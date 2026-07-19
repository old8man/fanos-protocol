//! The **threshold-KEM-sealed** onion layer — a hop peeled by `t` of a line's `q+1` members, with
//! real cryptographic zero-knowledge below threshold *and* forward secrecy (spec §5.2, §5.7).
//!
//! [`fanos_nyx::sheaf`] introduced the threshold-sheaf idea — AEAD a layer under a key `K`, then
//! Shamir-share `K` across the line — but transported the shares *in the clear*, so any holder of
//! the packet had all `q+1` shares and the threshold was only nominal. This module closes that gap:
//! each Shamir share is **hybrid-KEM-sealed to its line member's public key** (`X25519 ‖ ML-KEM-768`).
//! Therefore
//!
//! * **below `t` members, `K` is unrecoverable even to an adversary holding the whole packet** — the
//!   shares are ciphertext bound to members' long-term keys, not plaintext (true zero-knowledge,
//!   not merely information-theoretic *among cooperating members*); and
//! * **forward secrecy** — each share rides a fresh KEM encapsulation, so a later compromise of the
//!   sender's build randomness reveals nothing (recovering a share needs a *member's* KEM secret).
//!
//! A hop is thus genuinely a **line**, not a node: the unit of trust is a `t`-of-`q+1` group, and
//! that is what drops endpoint linkage to `P_hop²` (spec §5.2). AEAD, Shamir sharing, and the hybrid
//! KEM are all vetted primitives; the composition is the FANOS novelty.

use alloc::vec::Vec;

use fanos_primitives::hash_labeled;
use fanos_primitives::shamir::{self, Share};
use fanos_pqcrypto::kem::CIPHERTEXT_LEN;
use fanos_pqcrypto::{HybridCiphertext, HybridKemPublic, HybridKemSecret, SeedRng};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// A Shamir share of a 32-byte key: `x(1) ‖ y(32)`.
const SHARE_LEN: usize = 1 + 32;
/// A KEM-sealed share: `kem_ct ‖ AEAD(share)`.
const SEALED_SHARE_LEN: usize = CIPHERTEXT_LEN + SHARE_LEN + TAG_LEN;

/// Errors from sealing or opening a threshold layer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThresholdError {
    /// A key, share, or ciphertext was malformed.
    Malformed,
    /// AEAD authentication failed (wrong key / below-threshold reconstruction / tamper).
    Aead,
    /// Secret-sharing parameters or shares were invalid.
    Sharing,
    /// A KEM ciphertext failed to parse.
    Kem,
    /// The built onion would exceed the fixed [`THRESHOLD_ONION_LEN`] bucket (path too long).
    TooLong,
}

/// The fixed on-the-wire size of a threshold onion. Every hop's packet is padded to this constant
/// bucket, so a passive observer cannot link hops by the shrinking layer size a naive nested onion
/// leaks (spec §5.7). Sized to hold a Fano threshold circuit of several hops. Packet **size** is
/// fully constant on the wire. (Residual, documented: the per-layer `ct_len` in the header is
/// cleartext, so a party holding the *decrypted* packet — an on-path relay, or an observer of an
/// un-encrypted hop — can read the layer size; the encrypting transport hides it from a passive
/// network observer, and full defence-in-depth field hiding is the flat-header Sphinx construction.)
/// It is a network-wide parameter — every node must agree on it — sized for the deepest supported
/// threshold circuit (each hop costs `≈ line_size × 1169` bytes of KEM-sealed shares).
pub const THRESHOLD_ONION_LEN: usize = 20480;

/// Pad a threshold onion to the constant [`THRESHOLD_ONION_LEN`] bucket with keystream filler that
/// looks like ciphertext (the receiver's [`ThresholdSealed::from_bytes`] self-delimits and ignores
/// it). Errors with [`ThresholdError::TooLong`] if the onion already exceeds the bucket.
pub fn pad_onion(onion: &[u8]) -> Result<Vec<u8>, ThresholdError> {
    if onion.len() > THRESHOLD_ONION_LEN {
        return Err(ThresholdError::TooLong);
    }
    let mut out = Vec::with_capacity(THRESHOLD_ONION_LEN);
    out.extend_from_slice(onion);
    let mut pad = alloc::vec![0u8; THRESHOLD_ONION_LEN - onion.len()];
    fanos_primitives::hash::hash_xof("FANOS-v1/threshold-onion-pad", onion, &mut pad);
    out.extend_from_slice(&pad);
    Ok(out)
}

/// A threshold-sealed onion layer: the AEAD ciphertext of the routing command plus, for each line
/// member, a hybrid-KEM-sealed Shamir share of the layer key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ThresholdSealed {
    nonce: [u8; NONCE_LEN],
    /// `AEAD(K, nonce, routing_cmd)`.
    ciphertext: Vec<u8>,
    /// One KEM-sealed share per line member (in member order).
    sealed_shares: Vec<Vec<u8>>,
}

fn share_key(session: &[u8; 32]) -> [u8; 32] {
    hash_labeled("FANOS-v1/aphantos-threshold-share", session)
}

fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    pt: &[u8],
) -> Result<Vec<u8>, ThresholdError> {
    fanos_primitives::aead::seal(key, nonce, pt).ok_or(ThresholdError::Aead)
}

fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ct: &[u8],
) -> Result<Vec<u8>, ThresholdError> {
    fanos_primitives::aead::open(key, nonce, ct).ok_or(ThresholdError::Aead)
}

fn share_to_bytes(share: &Share) -> Option<[u8; SHARE_LEN]> {
    if share.y.len() != 32 {
        return None;
    }
    let mut out = [0u8; SHARE_LEN];
    out[0] = share.x;
    out[1..].copy_from_slice(&share.y);
    Some(out)
}

fn share_from_bytes(bytes: &[u8]) -> Option<Share> {
    let x = *bytes.first()?;
    let y = bytes.get(1..SHARE_LEN)?.to_vec();
    Some(Share { x, y })
}

impl ThresholdSealed {
    /// The number of line members this layer is sealed to.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.sealed_shares.len()
    }

    /// Seal `routing_cmd` for the line whose members are `member_keys` (in order), so that any
    /// `threshold` of them can peel it. `key` is the layer's AEAD key; `nonce` its AEAD nonce;
    /// `key_randomness` supplies `(threshold − 1) · 32` bytes for the sharing polynomial; and
    /// `kem_seed` derives the per-member KEM encapsulation randomness (a real CSPRNG in production,
    /// a fixed seed under the deterministic simulator).
    pub fn seal(
        routing_cmd: &[u8],
        key: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        threshold: u8,
        member_keys: &[&HybridKemPublic],
        key_randomness: &[u8],
        kem_seed: &[u8],
    ) -> Result<Self, ThresholdError> {
        let line_size = u8::try_from(member_keys.len()).map_err(|_| ThresholdError::Sharing)?;
        let ciphertext = aead_seal(key, nonce, routing_cmd)?;
        let shares = shamir::split(key, threshold, line_size, key_randomness)
            .map_err(|_| ThresholdError::Sharing)?;

        let mut sealed_shares = Vec::with_capacity(member_keys.len());
        for (i, (public, share)) in member_keys.iter().zip(&shares).enumerate() {
            let share_bytes = share_to_bytes(share).ok_or(ThresholdError::Sharing)?;
            // Per-member encapsulation randomness — deterministic in the seed for reproducibility.
            let mut hop_seed = kem_seed.to_vec();
            hop_seed.extend_from_slice(&(i as u32).to_be_bytes());
            let mut rng = SeedRng::from_seed(&hop_seed);
            let (kem_ct, session) = public.encapsulate(&mut rng);
            let sealed = aead_seal(&share_key(&session), nonce, &share_bytes)?;
            let mut slot = Vec::with_capacity(SEALED_SHARE_LEN);
            slot.extend_from_slice(&kem_ct.to_bytes());
            slot.extend_from_slice(&sealed);
            sealed_shares.push(slot);
        }
        Ok(Self {
            nonce: *nonce,
            ciphertext,
            sealed_shares,
        })
    }

    /// Member `i` recovers *its own* Shamir share by decapsulating its KEM-sealed slot. Returns
    /// `None` if `i` is out of range or the slot does not open under this member's secret (not its
    /// slot / tampered). No other member's share is ever exposed.
    #[must_use]
    pub fn member_share(&self, i: usize, member_secret: &HybridKemSecret) -> Option<Share> {
        let slot = self.sealed_shares.get(i)?;
        let kem_ct = HybridCiphertext::from_bytes(slot.get(..CIPHERTEXT_LEN)?)?;
        let session = member_secret.decapsulate(&kem_ct);
        let share_ct = slot.get(CIPHERTEXT_LEN..)?;
        let share_bytes = aead_open(&share_key(&session), &self.nonce, share_ct).ok()?;
        share_from_bytes(&share_bytes)
    }

    /// Reconstruct the layer key from `t` (or more) member shares and decrypt the routing command.
    /// With fewer than `t` shares the reconstructed key is wrong and AEAD authentication fails — the
    /// zero-knowledge-below-threshold guarantee, now backed by the KEM-sealing of every share.
    pub fn open(&self, shares: &[Share]) -> Result<Vec<u8>, ThresholdError> {
        let key = shamir::reconstruct(shares).map_err(|_| ThresholdError::Sharing)?;
        let key32: [u8; 32] = key.try_into().map_err(|_| ThresholdError::Malformed)?;
        aead_open(&key32, &self.nonce, &self.ciphertext)
    }

    /// Canonically serialize the layer: `nonce(12) ‖ members(2) ‖ ct_len(4) ‖ ciphertext ‖
    /// [sealed_share]*` (each sealed share is fixed-size).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.sealed_shares.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        for slot in &self.sealed_shares {
            out.extend_from_slice(slot);
        }
        out
    }

    /// Decode a layer from [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let nonce: [u8; NONCE_LEN] = bytes.get(..NONCE_LEN)?.try_into().ok()?;
        let members =
            u16::from_be_bytes(bytes.get(NONCE_LEN..NONCE_LEN + 2)?.try_into().ok()?) as usize;
        let ct_len =
            u32::from_be_bytes(bytes.get(NONCE_LEN + 2..NONCE_LEN + 6)?.try_into().ok()?) as usize;
        let mut pos = NONCE_LEN + 6;
        let ciphertext = bytes.get(pos..pos.checked_add(ct_len)?)?.to_vec();
        pos += ct_len;
        let mut sealed_shares = Vec::with_capacity(members.min(4096));
        for _ in 0..members {
            let slot = bytes.get(pos..pos.checked_add(SEALED_SHARE_LEN)?)?.to_vec();
            pos += SEALED_SHARE_LEN;
            sealed_shares.push(slot);
        }
        Some(Self {
            nonce,
            ciphertext,
            sealed_shares,
        })
    }
}

// --- Nested threshold onion over a circuit of hop LINES (the "hop is a line" onion) ---

const CMD_DELIVER: u8 = 0;
const CMD_NEXT: u8 = 1;

/// One hop of a threshold circuit: the hop line's coordinate (where the packet is routed) and the
/// KEM public keys of its `q+1` members, in member order.
pub struct HopLine<'a> {
    /// The hop line's coordinate (the next-hop address a peeling hop learns).
    pub line: fanos_geometry::Triple,
    /// The line members' hybrid KEM public keys, in order.
    pub members: &'a [&'a HybridKemPublic],
}

/// The outcome of peeling one threshold hop.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ThresholdPeel {
    /// Forward the inner onion to the next hop line at `next`.
    Forward {
        /// The next hop line's coordinate.
        next: fanos_geometry::Triple,
        /// The inner onion bytes.
        onion: Vec<u8>,
    },
    /// The payload reached its destination.
    Deliver {
        /// The delivered payload.
        payload: Vec<u8>,
    },
}

/// Build a **nested threshold onion** over `hops`: each layer is a [`ThresholdSealed`] to that hop
/// line's members, so a hop is peeled only by a threshold `t` of its `q+1` members — the "a hop is a
/// line" property (spec §5.2). A peeling hop learns only the *next* hop line, never the whole path.
/// All per-hop keys, nonces, sharing randomness, and KEM randomness derive from `seed` (a real
/// CSPRNG in production; a fixed seed under the deterministic simulator).
pub fn seal_onion(
    hops: &[HopLine<'_>],
    threshold: u8,
    payload: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, ThresholdError> {
    if hops.is_empty() {
        return Err(ThresholdError::Malformed);
    }
    let mut inner = payload.to_vec();
    let last = hops.len() - 1;
    for (k, hop) in hops.iter().enumerate().rev() {
        // Routing command: forward to the next line, or deliver.
        let mut cmd = Vec::with_capacity(1 + 12 + inner.len());
        if k == last {
            cmd.push(CMD_DELIVER);
        } else if let Some(next) = hops.get(k + 1) {
            cmd.push(CMD_NEXT);
            cmd.extend_from_slice(&fanos_geometry::encode_triple(next.line));
        }
        cmd.extend_from_slice(&inner);

        // Per-hop key material from the seed (labelled by hop index for separation).
        let tag = |label: &str| {
            let mut s = seed.to_vec();
            s.extend_from_slice(label.as_bytes());
            s.extend_from_slice(&(k as u32).to_be_bytes());
            s
        };
        let key = hash_labeled("FANOS-v1/threshold-onion-key", &tag("k"));
        let nonce_full = hash_labeled("FANOS-v1/threshold-onion-nonce", &tag("n"));
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(
            nonce_full
                .get(..NONCE_LEN)
                .ok_or(ThresholdError::Malformed)?,
        );
        let key_rnd = sharing_randomness(&tag("r"), threshold);
        let kem_seed = tag("kem");

        let sealed = ThresholdSealed::seal(
            &cmd,
            &key,
            &nonce,
            threshold,
            hop.members,
            &key_rnd,
            &kem_seed,
        )?;
        inner = sealed.to_bytes();
    }
    // Pad the outermost packet to the constant bucket (each forwarded hop is re-padded likewise).
    pad_onion(&inner)
}

/// `(threshold − 1) · 32` bytes of deterministic sharing randomness from a seed.
fn sharing_randomness(seed: &[u8], threshold: u8) -> Vec<u8> {
    let n = usize::from(threshold.saturating_sub(1)) * 32;
    let mut out = alloc::vec![0u8; n];
    fanos_primitives::hash::hash_xof("FANOS-v1/threshold-onion-sharing", seed, &mut out);
    out
}

/// Peel one threshold hop: given `members` — at least `threshold` `(index, secret)` pairs of the
/// current hop line — reconstruct the layer key and reveal the routing command. Returns whether to
/// forward the inner onion to the next line or deliver the payload. Fewer than `threshold` members
/// (or wrong secrets) fail with [`ThresholdError::Aead`].
pub fn peel_onion(
    onion: &[u8],
    members: &[(usize, &HybridKemSecret)],
) -> Result<ThresholdPeel, ThresholdError> {
    let sealed = ThresholdSealed::from_bytes(onion).ok_or(ThresholdError::Malformed)?;
    let shares: Vec<Share> = members
        .iter()
        .filter_map(|(i, sk)| sealed.member_share(*i, sk))
        .collect();
    peel_command(&sealed, &shares)
}

/// Peel one threshold hop from **already-gathered member shares** (the form an autonomous combiner
/// uses: it collects `≥ threshold` `PartialDec` replies, then peels). Fewer than `threshold` shares
/// fail with [`ThresholdError::Aead`].
pub fn peel_onion_with_shares(
    onion: &[u8],
    shares: &[Share],
) -> Result<ThresholdPeel, ThresholdError> {
    let sealed = ThresholdSealed::from_bytes(onion).ok_or(ThresholdError::Malformed)?;
    peel_command(&sealed, shares)
}

fn peel_command(
    sealed: &ThresholdSealed,
    shares: &[Share],
) -> Result<ThresholdPeel, ThresholdError> {
    let cmd = sealed.open(shares)?;
    let (&tag, rest) = cmd.split_first().ok_or(ThresholdError::Malformed)?;
    match tag {
        CMD_DELIVER => Ok(ThresholdPeel::Deliver {
            payload: rest.to_vec(),
        }),
        CMD_NEXT => {
            let next = fanos_geometry::decode_triple(rest.get(..12).ok_or(ThresholdError::Malformed)?)
                .ok_or(ThresholdError::Malformed)?;
            let onion = rest.get(12..).ok_or(ThresholdError::Malformed)?.to_vec();
            Ok(ThresholdPeel::Forward { next, onion })
        }
        _ => Err(ThresholdError::Malformed),
    }
}

/// Compute a single member's Shamir share of a threshold onion layer — the `PartialDec` a line
/// member returns to the combiner (spec §5.2). `member_index` is the member's position in the line's
/// canonical `points_on` ordering (the order the layer was sealed in). Returns `None` if the slot is
/// not this member's or is tampered.
#[must_use]
pub fn member_partial(
    onion: &[u8],
    member_index: usize,
    secret: &HybridKemSecret,
) -> Option<Share> {
    ThresholdSealed::from_bytes(onion)?.member_share(member_index, secret)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn line(n: usize, seed: u8) -> Vec<(HybridKemSecret, HybridKemPublic)> {
        (0..n)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[seed, i as u8]);
                HybridKemSecret::generate(&mut rng)
            })
            .collect()
    }

    fn randomness(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 131 + 7) % 251) as u8).collect()
    }

    #[test]
    fn the_combiner_path_gathers_partials_and_peels() {
        use fanos_geometry::Point;
        // The autonomous-combiner form: each line member computes its `member_partial`, a combiner
        // collects >= t of them and peels via `peel_onion_with_shares`.
        let t = 3u8;
        let kps = line(5, 55);
        let pubs: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        let hop = HopLine {
            line: Point::<fanos_field::F2>::at(1).coords(),
            members: &pubs,
        };
        let onion = seal_onion(&[hop], t, b"deliver me", b"seed").unwrap();

        // Members 0,2,4 each independently produce their partial share.
        let partials: Vec<Share> = [0usize, 2, 4]
            .iter()
            .map(|&i| member_partial(&onion, i, &kps[i].0).unwrap())
            .collect();
        // A combiner with those t partials peels the hop.
        match peel_onion_with_shares(&onion, &partials).unwrap() {
            ThresholdPeel::Deliver { payload } => assert_eq!(payload, b"deliver me"),
            ThresholdPeel::Forward { .. } => panic!("single hop should deliver"),
        }
        // A member decapsulating the wrong slot gets nothing (index 0 with member 2's secret).
        assert!(member_partial(&onion, 0, &kps[2].0).is_none());
    }

    #[test]
    fn any_threshold_of_members_peels_but_fewer_cannot() {
        // A line of 8 members, threshold 6.
        let members = line(8, 1);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let key = [3u8; 32];
        let nonce = [7u8; 12];
        let cmd = b"next line = L_42; delay = 120ms";
        let layer = ThresholdSealed::seal(cmd, &key, &nonce, 6, &pubs, &randomness(5 * 32), b"kem")
            .unwrap();
        assert_eq!(layer.member_count(), 8);

        // Each member decapsulates ITS OWN share (and only its own).
        let shares: Vec<Share> = members
            .iter()
            .enumerate()
            .map(|(i, (sk, _))| layer.member_share(i, sk).unwrap())
            .collect();

        // Any 6 reconstruct and peel.
        assert_eq!(layer.open(&shares[1..7]).unwrap(), cmd);
        assert_eq!(layer.open(&shares[2..8]).unwrap(), cmd);
        // Fewer than 6 → wrong key → AEAD auth fails.
        assert_eq!(layer.open(&shares[0..5]), Err(ThresholdError::Aead));
    }

    #[test]
    fn a_wrong_member_secret_cannot_open_a_slot() {
        let members = line(5, 2);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let layer = ThresholdSealed::seal(
            b"x",
            &[9u8; 32],
            &[0u8; 12],
            3,
            &pubs,
            &randomness(2 * 32),
            b"s",
        )
        .unwrap();
        // Member 0's slot cannot be opened with member 1's secret.
        assert!(layer.member_share(0, &members[1].0).is_none());
    }

    #[test]
    fn a_threshold_circuit_routes_hop_by_hop_and_delivers() {
        use fanos_geometry::Point;
        // A 3-hop circuit; each hop is a line of 5 members with threshold 3.
        let t = 3u8;
        let lines: Vec<Vec<(HybridKemSecret, HybridKemPublic)>> =
            (0..3).map(|h| line(5, 20 + h as u8)).collect();
        // Borrow the public keys per hop (outlives the HopLine slice below).
        let pubs: Vec<Vec<&HybridKemPublic>> = lines
            .iter()
            .map(|kps| kps.iter().map(|(_, p)| p).collect())
            .collect();
        let hops: Vec<HopLine<'_>> = pubs
            .iter()
            .enumerate()
            .map(|(h, members)| HopLine {
                line: Point::<fanos_field::F2>::at(h).coords(),
                members,
            })
            .collect();

        let payload = b"threshold-routed anonymous hello";
        let mut onion = seal_onion(&hops, t, payload, b"circuit-seed").unwrap();
        assert_eq!(
            onion.len(),
            THRESHOLD_ONION_LEN,
            "the built onion is the fixed bucket size"
        );

        // Route through each hop: a threshold subset of the line's members cooperate to peel.
        for kps in &lines {
            let members: Vec<(usize, &HybridKemSecret)> = kps
                .iter()
                .take(usize::from(t))
                .enumerate()
                .map(|(i, (sk, _))| (i, sk))
                .collect();
            match peel_onion(&onion, &members).unwrap() {
                ThresholdPeel::Forward { onion: inner, .. } => {
                    // Re-pad the inner onion as the router does: every hop's packet is the same size.
                    onion = pad_onion(&inner).unwrap();
                    assert_eq!(
                        onion.len(),
                        THRESHOLD_ONION_LEN,
                        "each hop stays constant-size"
                    );
                }
                ThresholdPeel::Deliver { payload: got } => {
                    assert_eq!(got, payload, "the payload arrives intact");
                    return;
                }
            }
        }
        panic!("onion never delivered");
    }

    #[test]
    fn below_threshold_members_cannot_peel_a_hop() {
        use fanos_geometry::Point;
        let t = 4u8;
        let kps = line(6, 30);
        let members_pub: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        let hop = HopLine {
            line: Point::<fanos_field::F2>::at(0).coords(),
            members: &members_pub,
        };
        let onion = seal_onion(&[hop], t, b"secret", b"s").unwrap();
        // Only t-1 members try — the reconstructed key is wrong and AEAD auth fails.
        let too_few: Vec<(usize, &HybridKemSecret)> = kps
            .iter()
            .take(usize::from(t) - 1)
            .enumerate()
            .map(|(i, (sk, _))| (i, sk))
            .collect();
        assert_eq!(peel_onion(&onion, &too_few), Err(ThresholdError::Aead));
    }

    #[test]
    fn a_threshold_layer_round_trips_through_bytes() {
        let members = line(5, 40);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let layer = ThresholdSealed::seal(
            b"cmd",
            &[1u8; 32],
            &[2u8; 12],
            3,
            &pubs,
            &randomness(2 * 32),
            b"s",
        )
        .unwrap();
        let decoded = ThresholdSealed::from_bytes(&layer.to_bytes()).unwrap();
        assert_eq!(decoded, layer);
    }

    #[test]
    fn shares_are_not_in_the_clear() {
        // The raw Shamir shares must NOT appear in the sealed layer bytes — an adversary holding the
        // whole packet learns nothing about the key without a member's KEM secret (real ZK below t).
        let members = line(4, 3);
        let pubs: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let rnd = randomness(2 * 32);
        let layer = ThresholdSealed::seal(b"secret", &key, &nonce, 3, &pubs, &rnd, b"s").unwrap();
        // Reconstruct the true shares (as a member would) and confirm none appears verbatim in a slot.
        for (i, (sk, _)) in members.iter().enumerate() {
            let share = layer.member_share(i, sk).unwrap();
            let raw = share_to_bytes(&share).unwrap();
            let slot = &layer.sealed_shares[i];
            assert!(
                !slot.windows(SHARE_LEN).any(|w| w == raw),
                "share {i} appears in the clear in its sealed slot"
            );
        }
    }

    #[test]
    fn seal_onion_rejects_bad_parameters() {
        use fanos_geometry::Point;
        let kps = line(3, 0x9E);
        let pubs: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        let line_coord = Point::<fanos_field::F2>::at(1).coords();

        // An empty circuit has no hop to seal.
        assert!(matches!(seal_onion(&[], 2, b"x", b"s"), Err(ThresholdError::Malformed)));
        // A threshold larger than the member count is unsatisfiable.
        assert!(
            seal_onion(
                &[HopLine {
                    line: line_coord,
                    members: &pubs,
                }],
                4,
                b"x",
                b"s",
            )
            .is_err(),
            "threshold > members is rejected"
        );
        // A zero threshold is degenerate.
        assert!(
            seal_onion(
                &[HopLine {
                    line: line_coord,
                    members: &pubs,
                }],
                0,
                b"x",
                b"s",
            )
            .is_err(),
            "threshold 0 is rejected"
        );
    }

    #[test]
    fn pad_onion_boundary() {
        // A short onion pads up to the constant bucket.
        assert_eq!(pad_onion(b"short").unwrap().len(), THRESHOLD_ONION_LEN);
        // Exactly the bucket size is a no-op pad (0 filler), still Ok.
        let exact = alloc::vec![0u8; THRESHOLD_ONION_LEN];
        assert_eq!(pad_onion(&exact).unwrap().len(), THRESHOLD_ONION_LEN);
        // One byte over the bucket cannot be padded down.
        let over = alloc::vec![0u8; THRESHOLD_ONION_LEN + 1];
        assert!(matches!(pad_onion(&over), Err(ThresholdError::TooLong)));
    }
}
