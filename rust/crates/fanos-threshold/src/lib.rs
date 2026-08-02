//! The **threshold-KEM-sealed** onion layer — a hop peeled by `t` of a line's `q+1` members, with
//! real cryptographic zero-knowledge below threshold (spec §5.2, §5.7).
//!
//! `fanos_nyx::sheaf` introduced the threshold-sheaf idea — AEAD a layer under a key `K`, then
//! Shamir-share `K` across the line — but transported the shares *in the clear*, so any holder of
//! the packet had all `q+1` shares and the threshold was only nominal. This module closes that gap:
//! each Shamir share is **hybrid-KEM-sealed to its line member's public key** (`X25519 ‖ ML-KEM-768`).
//! Therefore
//!
//! * **below `t` members, `K` is unrecoverable even to an adversary holding the whole packet** — the
//!   shares are ciphertext bound to members' long-term keys, not plaintext (true zero-knowledge,
//!   not merely information-theoretic *among cooperating members*).
//!
//! A hop is thus genuinely a **line**, not a node: the unit of trust is a `t`-of-`q+1` group, and
//! that is what drops endpoint linkage to `P_hop²` (spec §5.2). AEAD, Shamir sharing, and the hybrid
//! KEM are all vetted primitives; the composition is the FANOS novelty.
//!
//! **Forward secrecy & nonce hygiene (audit correction).** Do **not** read "each share rides a fresh KEM
//! encapsulation" as forward secrecy against a *sender* compromise: the layer key `K`, the KEM ephemerals, and
//! the AEAD nonce are all derived deterministically from the per-onion **`seed`** (`seal_onion`), so the seed
//! is a *universal trapdoor* while it lives — recovering `K` from it needs **no** member secret. Two operational
//! requirements follow, and callers own them: (1) the per-onion `seed` MUST be a fresh CSPRNG draw and be
//! **zeroized right after sealing** (forward secrecy is *seed-deletion* secrecy); and (2) a `seed` MUST NEVER
//! repeat — the AEAD is a deterministic-nonce construction, so a repeated `(seed)` reuses a `(key, nonce)` pair
//! and is catastrophic (keystream + one-time-authenticator reuse). What the KEM sealing *does* buy is the
//! below-threshold zero-knowledge above (a packet-only adversary needs a member's KEM secret), **not** sender
//! forward secrecy.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

use fanos_pqcrypto::kem::CIPHERTEXT_LEN;
use fanos_pqcrypto::{HybridCiphertext, HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_primitives::hash_labeled;
use fanos_primitives::shamir::{self, Share};

pub const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// A Shamir share of a 32-byte key: `x(1) ‖ y(32)`.
pub const SHARE_LEN: usize = 1 + 32;
/// A KEM-sealed share: `kem_ct ‖ AEAD(share)`.
/// One KEM-sealed share slot: `kem_ciphertext ‖ AEAD(share)`. Fixed-size, which is what lets a fixed-slot onion
/// header compute its width from the plane's line size alone (`fanos_aphantos::slots::slot_len`).
pub const SEALED_SHARE_LEN: usize = CIPHERTEXT_LEN + SHARE_LEN + TAG_LEN;

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
    /// The hybrid KEM's X25519 leg produced a non-contributory (low-order-point) shared secret —
    /// a malformed or malicious member key (audit B5, defense-in-depth per X-Wing guidance).
    NonContributory,
    /// The delivered path-authenticator (holonomy) did not match the circuit the verifier expected —
    /// the payload reached the endpoint over a different circuit than was agreed (spec §5.4, S1-M1).
    HolonomyFail,
}

impl core::fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed key, share, or ciphertext",
            Self::Aead => "AEAD authentication failed (wrong key or below-threshold or tamper)",
            Self::Sharing => "invalid secret-sharing parameters or shares",
            Self::Kem => "KEM ciphertext failed to parse",
            Self::TooLong => "threshold onion exceeds the fixed length bucket",
            Self::NonContributory => "hybrid KEM X25519 leg was non-contributory (low-order key)",
            Self::HolonomyFail => "delivered path-authenticator did not match the expected circuit",
        })
    }
}

impl core::error::Error for ThresholdError {}

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
///
/// **Length-hiding is weaker here than in `crate::sealed` (audit Finding 4).** This padding is a
/// *public* deterministic function of the onion bytes (`hash_xof("…threshold-onion-pad", onion)`), and
/// the header's `ct_len`/`members` are cleartext — so a party that sees the *decrypted* onion bytes (an
/// on-path line member, or any observer of an un-encrypted hop) can read the exact layer length and even
/// recompute the padding, learning hop position. The sealed onion, by contrast, encrypts its length and
/// derives padding from a *secret* session key, so its length-indistinguishability is intrinsic. The
/// threshold onion's therefore relies **entirely on the encrypting transport (QUIC/TLS)** — it has no
/// defence-in-depth if that layer is stripped or downgraded. Callers that need parity must run it only
/// under transport encryption (as the FANOS node does).
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

/// A Shamir share's fixed-width encoding — published because the onion layer above packs shares into its own
/// frames and must agree byte-for-byte with what the seal reads back.
#[must_use]
pub fn share_to_bytes(share: &Share) -> Option<[u8; SHARE_LEN]> {
    if share.y().len() != 32 {
        return None;
    }
    let mut out = [0u8; SHARE_LEN];
    out[0] = share.x();
    out[1..].copy_from_slice(share.y());
    Some(out)
}

fn share_from_bytes(bytes: &[u8]) -> Option<Share> {
    let x = *bytes.first()?;
    let y = bytes.get(1..SHARE_LEN)?.to_vec();
    Some(Share::new(x, y))
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
            let (kem_ct, session) = public
                .encapsulate(&mut rng)
                .ok_or(ThresholdError::NonContributory)?;
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
        let session = member_secret.decapsulate(&kem_ct)?;
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


#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::SeedRng;

    /// Deterministic randomness of `n` bytes for the share split.
    fn randomness(n: usize) -> Vec<u8> {
        (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect()
    }

    #[test]
    fn below_threshold_a_packet_holder_learns_nothing() {
        // The property the construction exists for, and the one the transparent form could not offer: `t` members
        // reconstruct while `t - 1` learn nothing, holding the WHOLE packet — because each share is sealed to its member's
        // public key rather than carried beside the ciphertext.
        let mut rng = SeedRng::from_seed(b"threshold-seal-test");
        let members: Vec<_> = (0..5).map(|_| HybridKemSecret::generate(&mut rng)).collect();
        let publics: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();

        let sealed = ThresholdSealed::seal(
            b"routing command",
            &[3u8; 32],
            &[7u8; NONCE_LEN],
            3,
            &publics,
            &randomness(5 * 32),
            b"kem-seed",
        )
        .expect("sealing across five members");
        assert_eq!(sealed.member_count(), 5);

        let open = |who: &[usize]| {
            let shares: Vec<Share> = who.iter().filter_map(|&i| sealed.member_share(i, &members[i].0)).collect();
            sealed.open(&shares)
        };
        assert_eq!(open(&[0, 1, 2]).as_deref(), Ok(&b"routing command"[..]), "any t of n reconstruct");
        assert_eq!(open(&[4, 0, 3]).as_deref(), Ok(&b"routing command"[..]), "any t — not one privileged subset");
        assert!(open(&[0, 1]).is_err(), "t-1 learn nothing, and they hold the entire packet");
        assert!(open(&[]).is_err());
    }

    #[test]
    fn a_padded_onion_is_one_width_whatever_it_carries() {
        // Length is a side channel: a hop must not learn its position from the size of what it forwards.
        for payload in [0usize, 1, 100, 4096, THRESHOLD_ONION_LEN] {
            let padded = pad_onion(&alloc::vec![7u8; payload]).expect("within the fixed width");
            assert_eq!(padded.len(), THRESHOLD_ONION_LEN, "one width for every onion, including an exactly-full one");
        }
        assert!(
            pad_onion(&alloc::vec![0u8; THRESHOLD_ONION_LEN + 1]).is_err(),
            "over the width is refused, never truncated — truncation would corrupt an onion instead of rejecting it"
        );
    }

    #[test]
    fn a_sealed_layer_round_trips_through_its_encoding() {
        let mut rng = SeedRng::from_seed(b"roundtrip");
        let members: Vec<_> = (0..3).map(|_| HybridKemSecret::generate(&mut rng)).collect();
        let publics: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let sealed =
            ThresholdSealed::seal(b"cmd", &[1u8; 32], &[2u8; NONCE_LEN], 2, &publics, &randomness(3 * 32), b"seed")
                .expect("seal");
        let back = ThresholdSealed::from_bytes(&sealed.to_bytes()).expect("its own encoding decodes");
        let shares: Vec<Share> = (0..2).filter_map(|i| back.member_share(i, &members[i].0)).collect();
        assert_eq!(back.open(&shares).as_deref(), Ok(&b"cmd"[..]), "and still opens after the round trip");
        assert!(ThresholdSealed::from_bytes(&sealed.to_bytes()[..8]).is_none(), "a truncated encoding is refused");
    }

    #[test]
    fn shares_are_not_in_the_clear() {
        // What separates this from the transparent form it replaced: the raw Shamir shares must not appear in the sealed
        // bytes at all. An adversary holding the whole packet learns nothing about the key without a member's KEM secret —
        // real zero-knowledge below threshold, rather than a threshold that only holds if the shares were delivered
        // privately. Lives here rather than with the onion layer above because it inspects the seal's own slots.
        let mut rng = SeedRng::from_seed(b"clear-share-test");
        let members: Vec<_> = (0..4).map(|_| HybridKemSecret::generate(&mut rng)).collect();
        let publics: Vec<&HybridKemPublic> = members.iter().map(|(_, p)| p).collect();
        let sealed =
            ThresholdSealed::seal(b"secret", &[42u8; 32], &[1u8; NONCE_LEN], 3, &publics, &randomness(4 * 32), b"s")
                .expect("seal");

        for (i, (sk, _)) in members.iter().enumerate() {
            let share = sealed.member_share(i, sk).expect("a member recovers its own share");
            let raw = share_to_bytes(&share).expect("a share encodes");
            assert!(
                !sealed.sealed_shares[i].windows(SHARE_LEN).any(|w| w == raw),
                "share {i} appears in the clear in its own sealed slot"
            );
        }
    }
}
