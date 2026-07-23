//! **Single-Use Reply Block (SURB)** — the encrypted return path a client registers with a rendezvous relay so
//! the relay forwards an anonymous reply *without ever learning the client's coordinate* (audit §5 S1-H3,
//! `docs/design-surb.md`).
//!
//! A client cannot be its own reply rendezvous (only `t`-of-`(q+1)` line members are combiners, and every
//! coordinate reshuffles each epoch), so it engages a relay — which today learns `cookie → client_coord` in
//! cleartext and, colluding with the exit, re-links client ↔ target. The SURB closes that with a Sphinx/Loopix
//! **header–payload split**: the client pre-seals the *routing* (a [`crate::sealed`] onion whose innermost
//! layer delivers the client's coordinate to a **delivery node**), and the relay attaches only the *payload*.
//! So the node that learns the **cookie** (the relay) is a different node from the one that learns the
//! **coordinate** (the delivery node), and neither learns both.
//!
//! The reply block is masked once per return hop (a length-preserving XOR keyed by that hop's KEM session) so
//! the block is bitwise-unlinkable across hops; the client strips every mask with the keys it derived while
//! building the SURB. The block itself is already end-to-end encrypted (DIAULOS), so the masking is
//! unlinkability, not confidentiality.

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::{TRIPLE_WIRE_LEN, Triple, decode_triple, encode_triple};
use fanos_nyx::Circuit;
use fanos_pqcrypto::kem::CIPHERTEXT_LEN;
use fanos_pqcrypto::{HybridCiphertext, HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_primitives::hash::hash_xof;
use fanos_primitives::hash_labeled;
use fanos_wire::tessera;

use crate::sealed::{ONION_LEN, PeelOutcome, SealedError, build, peel};

/// The fixed reply-payload bucket a SURB carries. Constant on the wire so return hops cannot link a reply by
/// its size; a reply that would overflow it (plus a 2-byte length prefix) is refused, never truncated.
pub const SURB_PAYLOAD_LEN: usize = 4096;

/// Domain label for a hop's payload-mask key, derived from its KEM session.
const MASK_KEY_LABEL: &str = "FANOS-v1/surb-mask-key";
/// Domain label for the length-preserving keystream that masks the reply block.
const MASK_STREAM_LABEL: &str = "FANOS-v1/surb-mask-stream";

/// A single-use reply block: what a client registers with a rendezvous relay in place of its coordinate.
pub struct Surb {
    /// The first return hop — the only node the relay contacts.
    pub first_hop: Triple,
    /// The pre-sealed routing header (a [`crate::sealed`] onion delivering the client's coordinate to the
    /// delivery node). Opaque to the relay: exactly [`ONION_LEN`] bytes, indistinguishable from any forward
    /// onion.
    pub header: Vec<u8>,
}

/// The client's secret for opening a reply that returned via a [`Surb`] — the per-hop mask keys, in return
/// order. XOR-combining is order-independent, so the client strips every hop's mask regardless of arrival path.
pub struct SurbKeys {
    keys: Vec<[u8; 32]>,
}

/// The outcome of a return hop processing a SURB packet with [`process_surb_hop`].
pub enum SurbOutcome {
    /// Forward the re-masked packet to `next`.
    Forward {
        /// The next return hop.
        next: Triple,
        /// The `header ‖ block` packet to forward, still exactly `ONION_LEN + SURB_PAYLOAD_LEN` bytes.
        packet: Vec<u8>,
    },
    /// Deliver the (masked) reply block to the client at `coord` — only the delivery node reaches this.
    Deliver {
        /// The client's coordinate, revealed only here (sealed to the delivery node by the client).
        coord: Triple,
        /// The masked reply block; the client strips the masks with [`open_reply`].
        block: Vec<u8>,
    },
}

impl Surb {
    /// Canonical wire bytes — `first_hop(12) ‖ header(ONION_LEN)` — what a client carries in its `RdvRegister`
    /// so the relay can forward replies through the return path without learning the client's coordinate.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TRIPLE_WIRE_LEN + ONION_LEN);
        out.extend_from_slice(&encode_triple(self.first_hop));
        out.extend_from_slice(&self.header);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if the length is wrong or the coordinate malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != TRIPLE_WIRE_LEN + ONION_LEN {
            return None;
        }
        let first_hop = bytes.get(..TRIPLE_WIRE_LEN).and_then(decode_triple)?;
        let header = bytes.get(TRIPLE_WIRE_LEN..)?.to_vec();
        Some(Self { first_hop, header })
    }
}

/// A hop's payload-mask key, derived from its KEM session — the one value both the client (at build) and the
/// hop (on peel) can compute, and no one else can.
fn mask_key(session: &[u8; 32]) -> [u8; 32] {
    hash_labeled(MASK_KEY_LABEL, session)
}

/// XOR `block` in place with a length-preserving keystream from `key`.
fn apply_mask(block: &mut [u8], key: &[u8; 32]) {
    let mut keystream = alloc::vec![0u8; block.len()];
    hash_xof(MASK_STREAM_LABEL, key, &mut keystream);
    for (b, k) in block.iter_mut().zip(keystream.iter()) {
        *b ^= *k;
    }
}

/// Re-derive hop `k`'s (1-based) KEM session exactly as [`crate::sealed::build`] does, so the client knows every
/// hop's mask key without the secret keys. Deterministic in `seed` — `build` derives hop `k`'s randomness from
/// `seed ‖ (k as u32 be)` and uses it only for the encapsulation (the nonce comes from a separate hash), so
/// replaying that encapsulation reproduces the identical session.
fn hop_session(public: &HybridKemPublic, seed: &[u8], k: usize) -> Option<[u8; 32]> {
    let mut hop_seed = seed.to_vec();
    hop_seed.extend_from_slice(&(k as u32).to_be_bytes());
    let mut rng = SeedRng::from_seed(&hop_seed);
    public.encapsulate(&mut rng).map(|(_, session)| session)
}

/// Build a SURB over `return_circuit`, sealing hop `k` to `return_keys[k-1]` and delivering `client_coord` to
/// the last hop (the delivery node). Returns the SURB (registered with the relay) and the client's opening keys.
///
/// # Errors
/// [`SealedError::KeyMismatch`] if `return_keys.len() != return_circuit.hop_count()` or the circuit is empty;
/// [`SealedError::TooLong`] if the header would overflow the onion bucket; [`SealedError::NonContributory`] on a
/// malformed relay key.
pub fn build_surb<F: Field>(
    return_circuit: &Circuit<F>,
    return_keys: &[&HybridKemPublic],
    client_coord: Triple,
    seed: &[u8],
) -> Result<(Surb, SurbKeys), SealedError> {
    let hops = return_circuit.hop_count();
    if hops == 0 || return_keys.len() != hops {
        return Err(SealedError::KeyMismatch);
    }
    // The header is a standard sealed onion whose innermost payload is the client's coordinate — so the
    // delivery node, and only it, learns where to send.
    let header = build(return_circuit, return_keys, &encode_triple(client_coord), seed)?;
    // Re-derive each hop's session (deterministic in `seed`) → its mask key, in return order.
    let mut keys = Vec::with_capacity(hops);
    for (k, public) in return_keys.iter().enumerate() {
        let session = hop_session(public, seed, k + 1).ok_or(SealedError::NonContributory)?;
        keys.push(mask_key(&session));
    }
    let first_hop = return_circuit.relays().first().ok_or(SealedError::Malformed)?.coords();
    Ok((Surb { first_hop, header }, SurbKeys { keys }))
}

/// Attach `reply` to `surb`, producing the packet the relay sends to [`Surb::first_hop`]. The reply is
/// length-prefixed and padded to the fixed [`SURB_PAYLOAD_LEN`] bucket.
///
/// # Errors
/// [`SealedError::TooLong`] if `reply` (plus its 2-byte length prefix) exceeds [`SURB_PAYLOAD_LEN`].
pub fn inject_reply(surb: &Surb, reply: &[u8]) -> Result<Vec<u8>, SealedError> {
    let len = u16::try_from(reply.len()).map_err(|_| SealedError::TooLong)?;
    if reply.len() + 2 > SURB_PAYLOAD_LEN {
        return Err(SealedError::TooLong);
    }
    let mut block = Vec::with_capacity(SURB_PAYLOAD_LEN);
    block.extend_from_slice(&len.to_be_bytes());
    block.extend_from_slice(reply);
    block.resize(SURB_PAYLOAD_LEN, 0);
    let mut packet = Vec::with_capacity(ONION_LEN + SURB_PAYLOAD_LEN);
    packet.extend_from_slice(&surb.header);
    packet.extend_from_slice(&block);
    Ok(packet)
}

/// Process a SURB packet at a return hop with its `kem_secret`: peel the routing header and re-mask the reply
/// block. A transit hop returns [`SurbOutcome::Forward`]; the delivery node returns [`SurbOutcome::Deliver`]
/// with the client's coordinate — revealed nowhere else on the path.
///
/// # Errors
/// [`SealedError::Malformed`] on a wrong-size packet or a mis-encoded delivery coordinate; the peel errors
/// (KEM/AEAD) propagate for a packet not sealed to this hop.
pub fn process_surb_hop(packet: &[u8], kem_secret: &HybridKemSecret) -> Result<SurbOutcome, SealedError> {
    let header = packet.get(..ONION_LEN).ok_or(SealedError::Malformed)?;
    let block = packet.get(ONION_LEN..).ok_or(SealedError::Malformed)?;
    if block.len() != SURB_PAYLOAD_LEN {
        return Err(SealedError::Malformed);
    }
    // Derive this hop's mask key from the header's outer KEM layer — the same session `peel` reconstructs —
    // and re-mask the block (a redundant decapsulation, but it keeps this additive to the forward path).
    let kem_off = tessera::offset::KEM_CT;
    let kem_ct_bytes = header.get(kem_off..kem_off + CIPHERTEXT_LEN).ok_or(SealedError::Malformed)?;
    let kem_ct = HybridCiphertext::from_bytes(kem_ct_bytes).ok_or(SealedError::Kem)?;
    let session = kem_secret.decapsulate(&kem_ct).ok_or(SealedError::NonContributory)?;
    let mut block = block.to_vec();
    apply_mask(&mut block, &mask_key(&session));

    match peel(header, kem_secret)? {
        PeelOutcome::Forward { next, onion } => {
            let mut packet = onion;
            packet.extend_from_slice(&block);
            Ok(SurbOutcome::Forward { next, packet })
        }
        PeelOutcome::Deliver { payload, .. } => {
            let coord = decode_triple(&payload).ok_or(SealedError::Malformed)?;
            Ok(SurbOutcome::Deliver { coord, block })
        }
    }
}

/// Open a reply block delivered via a SURB: strip every hop's mask (order-independent XOR) with the client's
/// [`SurbKeys`] and remove the length padding, recovering the (still end-to-end-encrypted) reply.
///
/// # Errors
/// [`SealedError::Malformed`] on a wrong-size block or a length prefix that runs past the bucket.
pub fn open_reply(block: &[u8], keys: &SurbKeys) -> Result<Vec<u8>, SealedError> {
    if block.len() != SURB_PAYLOAD_LEN {
        return Err(SealedError::Malformed);
    }
    let mut block = block.to_vec();
    for key in &keys.keys {
        apply_mask(&mut block, key);
    }
    let len = usize::from(u16::from_be_bytes(
        block.get(..2).and_then(|b| b.try_into().ok()).ok_or(SealedError::Malformed)?,
    ));
    block.get(2..2 + len).map(<[u8]>::to_vec).ok_or(SealedError::Malformed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::F31;
    use fanos_geometry::Point;
    use fanos_nyx::build_circuit;

    /// Test relays: coordinate index → (secret, public), positional like the `sealed` tests.
    fn relays(n: usize, seed: u8) -> Vec<(HybridKemSecret, HybridKemPublic)> {
        (0..n).map(|i| HybridKemSecret::generate(&mut SeedRng::from_seed(&[seed, i as u8]))).collect()
    }

    #[test]
    fn a_reply_returns_through_the_surb_without_the_relay_learning_the_coordinate() {
        let client_coord = Point::<F31>::at(42).coords();
        let circuit = build_circuit(Point::<F31>::at(0), Point::<F31>::at(300), 3, b"surb-return").unwrap();
        let keypairs = relays(circuit.hop_count(), 7);
        let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();

        let (surb, keys) = build_surb(&circuit, &pubkeys, client_coord, b"surb-seed").unwrap();
        // The relay holds only the opaque header + the first hop — the client's coordinate appears NOWHERE in
        // what it attaches to and sends.
        assert_eq!(surb.header.len(), ONION_LEN, "the header is a constant-size onion");
        assert!(!surb.header.windows(12).any(|w| w == encode_triple(client_coord)), "the coordinate is not in the cleartext header");

        let reply = b"the service's end-to-end-encrypted response cell";
        let mut packet = inject_reply(&surb, reply).unwrap();
        assert!(!packet.windows(12).any(|w| w == encode_triple(client_coord)), "nor in the relay's outgoing packet");

        // Route through every return hop; only the delivery node yields the coordinate.
        let mut delivered = None;
        for (i, (secret, _)) in keypairs.iter().enumerate() {
            assert_eq!(packet.len(), ONION_LEN + SURB_PAYLOAD_LEN, "the packet stays constant-size across hops");
            match process_surb_hop(&packet, secret).unwrap() {
                SurbOutcome::Forward { packet: p, .. } => {
                    assert!(i < keypairs.len() - 1, "only transit hops forward");
                    packet = p;
                }
                SurbOutcome::Deliver { coord, block } => {
                    assert_eq!(i, keypairs.len() - 1, "delivery happens only at the last hop");
                    assert_eq!(coord, client_coord, "the delivery node — and only it — learns the coordinate");
                    delivered = Some(open_reply(&block, &keys).unwrap());
                }
            }
        }
        assert_eq!(delivered.as_deref(), Some(reply.as_slice()), "the client recovers the exact reply");
    }

    #[test]
    fn a_surb_round_trips_through_its_wire_form() {
        let circuit = build_circuit(Point::<F31>::at(3), Point::<F31>::at(77), 2, b"wire").unwrap();
        let keypairs = relays(circuit.hop_count(), 5);
        let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();
        let (surb, _keys) = build_surb(&circuit, &pubkeys, Point::<F31>::at(8).coords(), b"s").unwrap();
        let bytes = surb.to_bytes();
        let decoded = Surb::from_bytes(&bytes).expect("re-decodes");
        assert_eq!(decoded.first_hop, surb.first_hop);
        assert_eq!(decoded.header, surb.header);
        assert!(Surb::from_bytes(&bytes[..bytes.len() - 1]).is_none(), "a truncated SURB is refused");
    }

    #[test]
    fn each_hop_masks_the_block_so_it_is_unlinkable_across_the_wire() {
        let circuit = build_circuit(Point::<F31>::at(1), Point::<F31>::at(200), 2, b"mask-return").unwrap();
        let keypairs = relays(circuit.hop_count(), 9);
        let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();
        let (surb, _keys) = build_surb(&circuit, &pubkeys, Point::<F31>::at(5).coords(), b"s").unwrap();

        let packet = inject_reply(&surb, b"reply").unwrap();
        let block_in = &packet[ONION_LEN..];
        let SurbOutcome::Forward { packet: fwd, .. } = process_surb_hop(&packet, &keypairs[0].0).unwrap() else {
            panic!("first hop forwards");
        };
        let block_out = &fwd[ONION_LEN..];
        assert_ne!(block_in, block_out, "the reply block is re-masked at the hop — bitwise-unlinkable across it");
    }

    #[test]
    fn an_oversized_reply_is_refused_and_a_foreign_hop_cannot_peel() {
        let circuit = build_circuit(Point::<F31>::at(2), Point::<F31>::at(9), 2, b"reject").unwrap();
        let keypairs = relays(circuit.hop_count(), 3);
        let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();
        let (surb, _keys) = build_surb(&circuit, &pubkeys, Point::<F31>::at(6).coords(), b"s").unwrap();

        assert_eq!(inject_reply(&surb, &[0u8; SURB_PAYLOAD_LEN]), Err(SealedError::TooLong), "an over-bucket reply is refused");
        // A packet sealed to hop 0 does not peel under a foreign key.
        let packet = inject_reply(&surb, b"x").unwrap();
        let foreign = relays(1, 200);
        assert!(process_surb_hop(&packet, &foreign[0].0).is_err(), "a wrong-key hop cannot peel");
    }
}
