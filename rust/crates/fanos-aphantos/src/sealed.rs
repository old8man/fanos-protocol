//! The KEM-sealed onion — APHANTOS-Lite with real per-hop hybrid KEM (spec §L5, §5.7).
//!
//! Each hop's layer key is established by a **hybrid KEM encapsulation to that relay's public
//! key** (`X25519 ‖ ML-KEM-768`), not carried in the packet, so only the intended relay can
//! peel its layer. Layers are nested AEAD (ChaCha20-Poly1305) and the whole onion is a byte
//! string on the wire — the same code the simulator routes and a real transport would carry.
//!
//! The path-authenticator **holonomy travels inside the innermost (DELIVER) layer**, encrypted
//! end-to-end, so it is visible only to the endpoint. It is deliberately *not* a cleartext
//! header: a constant per-circuit tag at a fixed offset would be a perfect cross-hop correlator
//! (any two relays, or any observer of an un-encrypted hop, could link entry to exit by matching
//! it), collapsing the threshold `P_hop^L` endpoint-unlinkability to `1` (spec §5.4).
//!
//! The onion is **constant-size on the wire** ([`ONION_LEN`]): every hop's packet is padded to the
//! same fixed bucket, and the real layer length lives in an *encrypted* `len` field, so a passive
//! observer sees identically-sized packets at every hop and cannot link entry to exit by the
//! monotonically-shrinking size a naive nested onion would leak (spec §5.7 length-indistinguishability).
//! The padding is keystream-derived from the hop key, so it is indistinguishable from ciphertext and
//! shares no bytes hop-to-hop. (Residual, documented: the *processing* relay learns its own layer
//! length, hence approximately how much onion remains — full position-hiding is the Sphinx filler
//! construction; a passive network observer learns nothing.)
//!
//! ```text
//! onion = VERSION(1) ‖ kem_ct(1120) ‖ nonce(12) ‖ len_ct(18) ‖ body_ct(len) ‖ padding  → ONION_LEN
//! len_ct  = AEAD(len_key, nonce, u16 body_len)          — the real length, encrypted
//! body_ct = AEAD(body_key, nonce, cmd ‖ inner)          — the routing layer
//! cmd     = (DELIVER ‖ holonomy(32)) | (NEXT ‖ next_coord(12))
//! ```

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use fanos_crypto::hash::hash_xof;
use fanos_crypto::hash_labeled;
use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_nyx::{Circuit, circuit_holonomy};
use fanos_pqcrypto::kem::CIPHERTEXT_LEN;
use fanos_pqcrypto::{HybridCiphertext, HybridKemPublic, HybridKemSecret, SeedRng};

const VERSION: u8 = 1;
const CMD_DELIVER: u8 = 0;
const CMD_NEXT: u8 = 1;
const NONCE_LEN: usize = 12;
const HOLONOMY_LEN: usize = 32;
/// AEAD tag length (ChaCha20-Poly1305).
const TAG_LEN: usize = 16;
/// The encrypted `len` field: AEAD of a 2-byte big-endian body length.
const LEN_CT_LEN: usize = 2 + TAG_LEN;

/// The constant on-the-wire onion size (the padding bucket). Every hop's packet is exactly this
/// size, so a passive observer cannot distinguish packets — or link them across hops — by length.
/// Sized to hold the deepest supported circuit (≈4 hybrid-KEM layers plus a multi-KB payload); an
/// onion that would exceed it is rejected at [`build`] time rather than silently truncated.
pub const ONION_LEN: usize = 8192;

/// Byte offsets of the fixed cleartext header fields.
const OFF_KEM: usize = 1; // after VERSION
const OFF_NONCE: usize = OFF_KEM + CIPHERTEXT_LEN;
const OFF_LEN_CT: usize = OFF_NONCE + NONCE_LEN;
const OFF_BODY_CT: usize = OFF_LEN_CT + LEN_CT_LEN;

/// Errors from sealing or peeling an onion.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealedError {
    /// The onion bytes were malformed (bad length, version, or command).
    Malformed,
    /// A KEM ciphertext failed to parse.
    Kem,
    /// AEAD authentication failed (wrong relay / tampered layer).
    Aead,
    /// The circuit and relay-key list disagreed in length.
    KeyMismatch,
    /// The built onion would exceed the fixed [`ONION_LEN`] bucket (path too long / payload too big).
    TooLong,
}

/// The result of peeling one hop.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PeelOutcome {
    /// Forward the inner onion to the relay at `next`.
    Forward {
        /// The next relay's coordinate.
        next: Triple,
        /// The re-headed inner onion bytes.
        onion: Vec<u8>,
    },
    /// The payload reached its destination; the carried holonomy authenticator is returned.
    Deliver {
        /// The delivered payload.
        payload: Vec<u8>,
        /// The path-authenticator holonomy tag.
        holonomy: [u8; 32],
    },
}

fn hop_key(session: &[u8; 32]) -> [u8; 32] {
    hash_labeled("FANOS-v1/aphantos-hopkey", session)
}

/// The AEAD key for the encrypted `len` field — separate from the body key so both can safely share
/// the hop nonce (distinct keys, not a reused (key, nonce) pair).
fn len_key(session: &[u8; 32]) -> [u8; 32] {
    hash_labeled("FANOS-v1/aphantos-lenkey", session)
}

/// Extend `onion` to exactly [`ONION_LEN`] with keystream-derived filler (looks like ciphertext,
/// unlinkable to an observer without the hop key, and deterministic so the engine stays pure).
/// The receiver ignores the filler entirely — it reads the real length from the encrypted `len`.
fn pad_to_bucket(mut onion: Vec<u8>, session: &[u8; 32]) -> Result<Vec<u8>, SealedError> {
    if onion.len() > ONION_LEN {
        return Err(SealedError::TooLong);
    }
    let pad_len = ONION_LEN - onion.len();
    let mut pad = alloc::vec![0u8; pad_len];
    hash_xof("FANOS-v1/aphantos-pad", session, &mut pad);
    onion.extend_from_slice(&pad);
    Ok(onion)
}

fn aead_seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], pt: &[u8]) -> Result<Vec<u8>, SealedError> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| SealedError::Aead)?
        .encrypt(&Nonce::from(*nonce), pt)
        .map_err(|_| SealedError::Aead)
}

fn aead_open(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ct: &[u8]) -> Result<Vec<u8>, SealedError> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| SealedError::Aead)?
        .decrypt(&Nonce::from(*nonce), ct)
        .map_err(|_| SealedError::Aead)
}

fn coord_to_bytes(coord: Triple) -> [u8; 12] {
    let mut out = [0u8; 12];
    let (chunks, _) = out.as_chunks_mut::<4>();
    for (chunk, value) in chunks.iter_mut().zip(coord) {
        *chunk = value.to_be_bytes();
    }
    out
}

fn coord_from_bytes(bytes: &[u8]) -> Option<Triple> {
    let (chunks, _) = bytes.get(..12)?.as_chunks::<4>();
    Some([
        u32::from_be_bytes(*chunks.first()?),
        u32::from_be_bytes(*chunks.get(1)?),
        u32::from_be_bytes(*chunks.get(2)?),
    ])
}

/// A bounds-checked `buf[off .. off+len]`, or [`SealedError::Malformed`] if it runs past the end.
fn slice_at(buf: &[u8], off: usize, len: usize) -> Result<&[u8], SealedError> {
    let end = off.checked_add(len).ok_or(SealedError::Malformed)?;
    buf.get(off..end).ok_or(SealedError::Malformed)
}

/// Build a KEM-sealed onion for `circuit` carrying `payload`, sealing hop `k` to
/// `relay_keys[k-1]` (the public key of relay `r_k`). All randomness derives from `seed`.
///
/// `relay_keys.len()` must equal `circuit.hop_count()` (one key per peeling relay `r_1…r_L`).
pub fn build<F: Field>(
    circuit: &Circuit<F>,
    relay_keys: &[&HybridKemPublic],
    payload: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, SealedError> {
    let hops = circuit.hop_count();
    if relay_keys.len() != hops {
        return Err(SealedError::KeyMismatch);
    }
    let relays = circuit.relays();
    let holonomy = circuit_holonomy(circuit, &hash_labeled("FANOS-v1/aphantos-holoseed", seed));

    // `inner` is the *unpadded* nested onion built so far (innermost first); `outer_session` is the
    // outermost hop's key, used to pad the final packet to the bucket.
    let mut inner = payload.to_vec();
    let mut outer_session = [0u8; 32];
    for k in (1..=hops).rev() {
        let public = relay_keys.get(k - 1).ok_or(SealedError::KeyMismatch)?;
        // Per-hop deterministic randomness for encapsulation and the nonce.
        let mut hop_seed = seed.to_vec();
        hop_seed.extend_from_slice(&(k as u32).to_be_bytes());
        let mut rng = SeedRng::from_seed(&hop_seed);
        let (kem_ct, session) = public.encapsulate(&mut rng);
        outer_session = session;
        let nonce_full = hash_labeled("FANOS-v1/aphantos-nonce", &hop_seed);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_full.get(..NONCE_LEN).ok_or(SealedError::Malformed)?);

        // Routing body: forward to the next relay, or deliver. The holonomy authenticator rides
        // inside the innermost DELIVER layer (encrypted end-to-end), never as a cleartext header.
        let mut body = Vec::new();
        if k == hops {
            body.push(CMD_DELIVER);
            body.extend_from_slice(&holonomy);
        } else {
            body.push(CMD_NEXT);
            let next = relays.get(k + 1).ok_or(SealedError::Malformed)?;
            body.extend_from_slice(&coord_to_bytes(next.coords()));
        }
        body.extend_from_slice(&inner);

        let body_ct = aead_seal(&hop_key(&session), &nonce, &body)?;
        // The real body length, encrypted so it is not a cleartext size hint an observer can read.
        let len = u16::try_from(body_ct.len()).map_err(|_| SealedError::TooLong)?;
        let len_ct = aead_seal(&len_key(&session), &nonce, &len.to_be_bytes())?;

        // onion = VERSION ‖ kem_ct ‖ nonce ‖ len_ct ‖ body_ct  (unpadded; padded only at the top)
        let mut onion = Vec::with_capacity(OFF_BODY_CT + body_ct.len());
        onion.push(VERSION);
        onion.extend_from_slice(&kem_ct.to_bytes());
        onion.extend_from_slice(&nonce);
        onion.extend_from_slice(&len_ct);
        onion.extend_from_slice(&body_ct);
        inner = onion;
    }

    // Pad the outermost packet to the constant bucket (the receiver ignores the filler).
    pad_to_bucket(inner, &outer_session)
}

/// Peel the current hop of a sealed onion with a relay's KEM secret key (spec §5.7).
pub fn peel(onion: &[u8], kem_secret: &HybridKemSecret) -> Result<PeelOutcome, SealedError> {
    if onion.first().copied() != Some(VERSION) {
        return Err(SealedError::Malformed);
    }
    let kem_ct_bytes = onion
        .get(OFF_KEM..OFF_NONCE)
        .ok_or(SealedError::Malformed)?;
    let nonce_bytes = slice_at(onion, OFF_NONCE, NONCE_LEN)?;
    let len_ct = slice_at(onion, OFF_LEN_CT, LEN_CT_LEN)?;

    let kem_ct = HybridCiphertext::from_bytes(kem_ct_bytes).ok_or(SealedError::Kem)?;
    let session = kem_secret.decapsulate(&kem_ct);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);

    // Decrypt the length first (fixed-size, fixed-offset), then the exactly-`len` body ciphertext —
    // so the trailing bucket filler is never fed to the body AEAD.
    let len_pt = aead_open(&len_key(&session), &nonce, len_ct)?;
    let body_len = usize::from(u16::from_be_bytes(
        len_pt
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .ok_or(SealedError::Malformed)?,
    ));
    let body_ct = slice_at(onion, OFF_BODY_CT, body_len)?;
    let plaintext = aead_open(&hop_key(&session), &nonce, body_ct)?;

    let (&cmd, rest) = plaintext.split_first().ok_or(SealedError::Malformed)?;
    match cmd {
        CMD_DELIVER => {
            // Innermost layer: holonomy(32) ‖ payload — only the endpoint ever sees the tag.
            let holonomy_bytes = rest.get(..HOLONOMY_LEN).ok_or(SealedError::Malformed)?;
            let mut holonomy = [0u8; 32];
            holonomy.copy_from_slice(holonomy_bytes);
            let payload = rest
                .get(HOLONOMY_LEN..)
                .ok_or(SealedError::Malformed)?
                .to_vec();
            Ok(PeelOutcome::Deliver { payload, holonomy })
        }
        CMD_NEXT => {
            let next = coord_from_bytes(rest).ok_or(SealedError::Malformed)?;
            let inner = rest.get(12..).ok_or(SealedError::Malformed)?;
            // Re-head the inner onion for the next relay and re-pad to the constant bucket, so the
            // forwarded packet is the same size as the one we received — no cross-hop size link.
            let forwarded = pad_to_bucket(inner.to_vec(), &session)?;
            Ok(PeelOutcome::Forward {
                next,
                onion: forwarded,
            })
        }
        _ => Err(SealedError::Malformed),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::F31;
    use fanos_geometry::Point;
    use fanos_nyx::build_circuit;

    /// A tiny relay directory for the tests: coordinate → (secret, public).
    fn relays(n: usize, seed: u8) -> Vec<(HybridKemSecret, HybridKemPublic)> {
        (0..n)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[seed, i as u8]);
                HybridKemSecret::generate(&mut rng)
            })
            .collect()
    }

    #[test]
    fn onion_routes_through_every_relay() {
        let circuit =
            build_circuit(Point::<F31>::at(0), Point::<F31>::at(500), 3, b"circuit").unwrap();
        let keypairs = relays(circuit.hop_count(), 1);
        let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();

        let payload = b"anonymous hello";
        let mut onion = build(&circuit, &pubkeys, payload, b"onion-seed").unwrap();

        // Each hop is peeled only by the correct relay's secret key, and every packet on the wire is
        // exactly the constant bucket — a passive observer sees no size difference across hops.
        assert_eq!(
            onion.len(),
            ONION_LEN,
            "built onion is the fixed bucket size"
        );
        for (secret, _) in &keypairs {
            match peel(&onion, secret).unwrap() {
                PeelOutcome::Forward { onion: inner, .. } => {
                    assert_eq!(
                        inner.len(),
                        ONION_LEN,
                        "forwarded onion stays constant-size"
                    );
                    onion = inner;
                }
                PeelOutcome::Deliver { payload: got, .. } => {
                    assert_eq!(got, payload);
                    return;
                }
            }
        }
        panic!("onion never delivered");
    }

    #[test]
    fn an_oversized_onion_is_rejected_not_truncated() {
        // A payload that would overflow the fixed bucket is refused at build, never silently cut.
        let circuit = build_circuit(Point::<F31>::at(1), Point::<F31>::at(9), 2, b"big").unwrap();
        let keypairs = relays(circuit.hop_count(), 4);
        let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();
        let huge = alloc::vec![0xABu8; ONION_LEN];
        assert_eq!(
            build(&circuit, &pubkeys, &huge, b"s"),
            Err(SealedError::TooLong)
        );
    }

    #[test]
    fn the_holonomy_is_not_a_cleartext_cross_hop_correlator() {
        // Capture the on-wire bytes at every hop and confirm the path-authenticator holonomy
        // appears verbatim in NONE of them — it travels encrypted end-to-end, so colluding relays
        // (or an observer of an un-encrypted hop) cannot link entry to exit by matching a fixed tag.
        let circuit =
            build_circuit(Point::<F31>::at(3), Point::<F31>::at(700), 3, b"corr").unwrap();
        let keypairs = relays(circuit.hop_count(), 7);
        let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();
        let mut onion = build(&circuit, &pubkeys, b"secret payload", b"corr-seed").unwrap();

        let mut snapshots = alloc::vec![onion.clone()];
        let mut delivered = None;
        for (secret, _) in &keypairs {
            match peel(&onion, secret).unwrap() {
                PeelOutcome::Forward { onion: inner, .. } => {
                    onion = inner;
                    snapshots.push(onion.clone());
                }
                PeelOutcome::Deliver { holonomy, .. } => {
                    delivered = Some(holonomy);
                    break;
                }
            }
        }
        let holo = delivered.unwrap(); // onion delivered
        for (hop, snap) in snapshots.iter().enumerate() {
            assert!(
                !snap.windows(HOLONOMY_LEN).any(|w| w == holo),
                "holonomy tag leaks in cleartext at hop {hop}"
            );
        }
    }

    #[test]
    fn a_wrong_relay_cannot_peel() {
        let circuit = build_circuit(Point::<F31>::at(1), Point::<F31>::at(2), 2, b"c").unwrap();
        let keypairs = relays(circuit.hop_count(), 2);
        let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();
        let onion = build(&circuit, &pubkeys, b"x", b"s").unwrap();
        // The second relay's key cannot peel the first hop.
        assert_eq!(peel(&onion, &keypairs[1].0), Err(SealedError::Aead));
    }
}
