//! Hybrid node-identity signatures (spec §7.1, §L0).
//!
//! A FANOS identity signs with a **hybrid** key — classical Ed25519 alongside post-quantum ML-DSA-65
//! (FIPS 204) — and a hybrid signature verifies iff *both* components verify, so forging one would
//! demand breaking a classical *and* a lattice assumption at once. Signing keys are derived
//! deterministically from a 32-byte seed and Ed25519 signing is deterministic, so identity keygen and
//! authentication are fully reproducible in the deterministic simulator — no ambient randomness.
//!
//! The vetted primitives are `ed25519-dalek` (classical) and `fips204` (ML-DSA-65, FIPS 204) — no new
//! hardness is invented; the novelty is the composition (spec §L6).

use alloc::vec::Vec;

use ed25519_dalek::Signer;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as _, Verifier as _};

use crate::hash::{hash_labeled, label};

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

// --- Post-quantum half: ML-DSA-65 (FIPS 204) ---------------------------------------------------

/// ML-DSA-65 public-key length (bytes) — FIPS 204.
pub const MLDSA65_PK_LEN: usize = ml_dsa_65::PK_LEN;
/// ML-DSA-65 signature length (bytes) — FIPS 204.
pub const MLDSA65_SIG_LEN: usize = ml_dsa_65::SIG_LEN;

/// An ML-DSA-65 signing key derived deterministically from a 32-byte seed (FIPS 204 `KeyGen` with
/// seed ξ). The public key bytes are cached for publication in the identity bundle.
pub struct MlDsa65SigningKey {
    secret: ml_dsa_65::PrivateKey,
    public: [u8; MLDSA65_PK_LEN],
}

impl MlDsa65SigningKey {
    /// Derive a signing key from a 32-byte seed (deterministic FIPS 204 keygen).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(seed);
        Self { secret: sk, public: pk.into_bytes() }
    }

    /// The public verifying key bytes.
    #[must_use]
    pub fn public_bytes(&self) -> [u8; MLDSA65_PK_LEN] {
        self.public
    }

    /// Sign `msg`. Uses **deterministic** ML-DSA (FIPS 204 with the hedging randomness fixed to zero) —
    /// a valid, secure signing mode that is reproducible in the deterministic simulator. Returns `None`
    /// only on the internal error path (never for a valid key and empty context), so callers propagate
    /// without unwrapping.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Option<[u8; MLDSA65_SIG_LEN]> {
        self.secret.try_sign_with_seed(&[0u8; 32], msg, &[]).ok()
    }
}

/// Verify an ML-DSA-65 signature under public-key bytes. Returns `false` — never panics — on a
/// malformed key or a bad signature.
#[must_use]
pub fn mldsa65_verify(public: &[u8; MLDSA65_PK_LEN], msg: &[u8], sig: &[u8; MLDSA65_SIG_LEN]) -> bool {
    let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(*public) else {
        return false;
    };
    pk.verify(msg, sig, &[])
}

// --- The hybrid composition --------------------------------------------------------------------

/// The length of a hybrid signature: `Ed25519(64) ‖ ML-DSA-65(3309)`.
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA65_SIG_LEN;

/// A node's hybrid signing key: an Ed25519 key and an ML-DSA-65 key, each derived — with domain
/// separation — from one 32-byte **identity seed** (spec §L0, §7.1). A node holds one seed; both keys
/// (and hence its whole identity) follow deterministically from it.
pub struct HybridSigningKey {
    ed25519: Ed25519SigningKey,
    mldsa65: MlDsa65SigningKey,
}

impl HybridSigningKey {
    /// Derive both component keys from one 32-byte identity seed (domain-separated per primitive, so the
    /// two sub-keys are independent even though they share an origin).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            ed25519: Ed25519SigningKey::from_seed(&hash_labeled(label::ID_ED25519, seed)),
            mldsa65: MlDsa65SigningKey::from_seed(&hash_labeled(label::ID_MLDSA65, seed)),
        }
    }

    /// The Ed25519 public key bytes.
    #[must_use]
    pub fn ed25519_public(&self) -> [u8; ED25519_PK_LEN] {
        self.ed25519.public_bytes()
    }

    /// The ML-DSA-65 public key bytes.
    #[must_use]
    pub fn mldsa65_public(&self) -> [u8; MLDSA65_PK_LEN] {
        self.mldsa65.public_bytes()
    }

    /// Sign `msg` under both primitives: `Ed25519(64) ‖ ML-DSA-65(3309)`. `None` only if ML-DSA signing
    /// hits its internal error path (never for a valid key).
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Option<Vec<u8>> {
        let mldsa = self.mldsa65.sign(msg)?;
        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&self.ed25519.sign(msg));
        out.extend_from_slice(&mldsa);
        Some(out)
    }
}

/// Verify a hybrid signature `Ed25519(64) ‖ ML-DSA-65(3309)` under both public keys. Valid **iff both**
/// components verify — an attacker must break a classical *and* a lattice assumption to forge one, and
/// a wrong length or either bad half is rejected without panicking.
#[must_use]
pub fn hybrid_verify(
    ed25519_public: &[u8; ED25519_PK_LEN],
    mldsa65_public: &[u8; MLDSA65_PK_LEN],
    msg: &[u8],
    sig: &[u8],
) -> bool {
    let Some(ed) = sig.get(..ED25519_SIG_LEN).and_then(|s| <[u8; ED25519_SIG_LEN]>::try_from(s).ok())
    else {
        return false;
    };
    let Some(mldsa) = sig
        .get(ED25519_SIG_LEN..HYBRID_SIG_LEN)
        .and_then(|s| <[u8; MLDSA65_SIG_LEN]>::try_from(s).ok())
    else {
        return false;
    };
    ed25519_verify(ed25519_public, msg, &ed) && mldsa65_verify(mldsa65_public, msg, &mldsa)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
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

    #[test]
    fn mldsa65_round_trip_and_rejects_tampering() {
        let sk = MlDsa65SigningKey::from_seed(&[3u8; 32]);
        let pk = sk.public_bytes();
        let msg = b"post-quantum authentication";
        let sig = sk.sign(msg).expect("signing with a valid key succeeds");
        assert!(mldsa65_verify(&pk, msg, &sig), "a valid ML-DSA signature verifies");
        assert!(!mldsa65_verify(&pk, b"a different message", &sig), "a tampered message is rejected");
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!mldsa65_verify(&pk, msg, &bad), "a tampered signature is rejected");
        let other = MlDsa65SigningKey::from_seed(&[4u8; 32]).public_bytes();
        assert!(!mldsa65_verify(&other, msg, &sig), "the wrong public key is rejected");
    }

    #[test]
    fn hybrid_signature_requires_both_halves() {
        let k = HybridSigningKey::from_seed(&[5u8; 32]);
        let ed = k.ed25519_public();
        let ml = k.mldsa65_public();
        let msg = b"bind coord and hier to identity";
        let sig = k.sign(msg).expect("hybrid signing succeeds");
        assert_eq!(sig.len(), HYBRID_SIG_LEN);
        assert!(hybrid_verify(&ed, &ml, msg, &sig), "a valid hybrid signature verifies");

        // Corrupt only the Ed25519 half → the whole hybrid must fail (both components required).
        let mut ed_broken = sig.clone();
        ed_broken[0] ^= 0x01;
        assert!(!hybrid_verify(&ed, &ml, msg, &ed_broken), "a broken classical half fails the hybrid");
        // Corrupt only the ML-DSA half → the whole hybrid must fail.
        let mut ml_broken = sig.clone();
        let last = ml_broken.len() - 1;
        ml_broken[last] ^= 0x01;
        assert!(!hybrid_verify(&ed, &ml, msg, &ml_broken), "a broken PQ half fails the hybrid");
        // A truncated signature is rejected, not indexed out of bounds.
        assert!(!hybrid_verify(&ed, &ml, msg, &sig[..HYBRID_SIG_LEN - 1]), "a short signature is rejected");
        // Either wrong public key fails.
        let other = HybridSigningKey::from_seed(&[6u8; 32]);
        assert!(!hybrid_verify(&other.ed25519_public(), &ml, msg, &sig), "wrong classical key fails");
        assert!(!hybrid_verify(&ed, &other.mldsa65_public(), msg, &sig), "wrong PQ key fails");
    }

    #[test]
    fn hybrid_is_deterministic_from_the_seed() {
        let a = HybridSigningKey::from_seed(&[8u8; 32]);
        let b = HybridSigningKey::from_seed(&[8u8; 32]);
        assert_eq!(a.ed25519_public(), b.ed25519_public(), "same seed → same classical key");
        assert_eq!(a.mldsa65_public(), b.mldsa65_public(), "same seed → same PQ key");
        assert_eq!(a.sign(b"m"), b.sign(b"m"), "reproducible hybrid signatures");
    }
}
