//! Hybrid node-identity signatures (spec §7.1, §L0).
//!
//! A FANOS identity signs with a **hybrid** key — classical Ed25519 alongside post-quantum ML-DSA-65
//! (FIPS 204) — and a hybrid signature verifies iff *both* components verify, so forging one would
//! demand breaking a classical *and* a lattice assumption at once. Signing keys are derived
//! deterministically from a 32-byte seed and Ed25519 signing is deterministic, so identity keygen and
//! authentication are fully reproducible in the deterministic simulator — no ambient randomness.
//!
//! This module currently provides the classical (Ed25519) half; the post-quantum half and the hybrid
//! composition build on it. The vetted primitive is `ed25519-dalek` (no new hardness is invented — the
//! novelty is the composition, spec §L6).

use ed25519_dalek::Signer;

/// Ed25519 public-key length (bytes).
pub const ED25519_PK_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
/// Ed25519 signature length (bytes).
pub const ED25519_SIG_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// An Ed25519 signing key, derived deterministically from a 32-byte seed. Wraps
/// [`ed25519_dalek::SigningKey`]; the secret is zeroized on drop (the crate's `zeroize` feature).
pub struct Ed25519SigningKey(ed25519_dalek::SigningKey);

impl Ed25519SigningKey {
    /// Derive a signing key from a 32-byte seed. Deterministic: the same seed always yields the same
    /// key, so a node's identity is reproducible from its seed alone (spec §L0).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The public verifying key bytes to publish in the identity bundle.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; ED25519_PK_LEN] {
        self.0.verifying_key().to_bytes()
    }

    /// Sign `msg` (deterministic Ed25519, RFC 8032).
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; ED25519_SIG_LEN] {
        self.0.sign(msg).to_bytes()
    }
}

/// Verify an Ed25519 signature under a 32-byte public key. Uses strict verification (rejects
/// non-canonical / small-order keys, closing the malleability edge cases). Returns `false` — never
/// panics — on a malformed key or a bad signature.
#[must_use]
pub fn ed25519_verify(public: &[u8; ED25519_PK_LEN], msg: &[u8], sig: &[u8; ED25519_SIG_LEN]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(public) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature).is_ok()
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_round_trip_and_rejects_tampering() {
        let sk = Ed25519SigningKey::from_seed(&[7u8; 32]);
        let pk = sk.public_bytes();
        let msg = b"authenticate this announcement";
        let sig = sk.sign(msg);

        assert!(ed25519_verify(&pk, msg, &sig), "a valid signature verifies");
        assert!(!ed25519_verify(&pk, b"a different message", &sig), "a tampered message is rejected");

        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!ed25519_verify(&pk, msg, &bad), "a tampered signature is rejected");

        let other = Ed25519SigningKey::from_seed(&[9u8; 32]).public_bytes();
        assert!(!ed25519_verify(&other, msg, &sig), "the wrong public key is rejected");
    }

    #[test]
    fn keys_and_signatures_are_deterministic_from_the_seed() {
        let a = Ed25519SigningKey::from_seed(&[1u8; 32]);
        let b = Ed25519SigningKey::from_seed(&[1u8; 32]);
        assert_eq!(a.public_bytes(), b.public_bytes(), "same seed → same key");
        assert_eq!(a.sign(b"m"), b.sign(b"m"), "same seed → same signature (reproducible)");
        let c = Ed25519SigningKey::from_seed(&[2u8; 32]);
        assert_ne!(a.public_bytes(), c.public_bytes(), "different seed → different key");
    }
}
