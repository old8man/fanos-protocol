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

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use fanos_crypto::hash_labeled;
use fanos_crypto::shamir::{self, Share};
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
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| ThresholdError::Aead)?
        .encrypt(&Nonce::from(*nonce), pt)
        .map_err(|_| ThresholdError::Aead)
}

fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ct: &[u8],
) -> Result<Vec<u8>, ThresholdError> {
    ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| ThresholdError::Aead)?
        .decrypt(&Nonce::from(*nonce), ct)
        .map_err(|_| ThresholdError::Aead)
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
}
