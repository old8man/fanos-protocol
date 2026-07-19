//! The hybrid signature `Ed25519 ‖ ML-DSA-65` (spec §L6).
//!
//! Both signatures are produced over the same message and *both* must verify. Forgery
//! therefore requires breaking Ed25519 **and** ML-DSA-65 — a classical + post-quantum hedge.
//! This binds a FANOS node's long-term identity and its coordinate proofs (spec §L0, §7.3).

use alloc::vec::Vec;

// Public-key (= verifying-key, for these schemes) lengths come from the one byte-model in
// `fanos_primitives::keys`, so the identity bundle layout has a single source of truth; the round-trip
// tests (encode → decode → verify) pin these to the real RustCrypto sizes.
use fanos_primitives::keys::{ED25519_PK_LEN as ED25519_VK_LEN, MLDSA65_PK_LEN as MLDSA65_VK_LEN};
use ed25519_dalek::{
    Signature as EdSignature, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    EncodedVerifyingKey, Generate, MlDsa65, Signature as MlSignature, SigningKey as MlSigningKey,
    VerifyingKey as MlVerifyingKey,
};
use rand_core::CryptoRng;

/// Ed25519 signature length (bytes).
const ED25519_SIG_LEN: usize = 64;
/// ML-DSA-65 signature length (bytes).
const MLDSA65_SIG_LEN: usize = 3309;
/// The serialized [`HybridSignature`] length: `Ed25519(64) ‖ ML-DSA-65(3309)`.
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA65_SIG_LEN;
/// The serialized [`HybridVerifier`] length: `Ed25519(32) ‖ ML-DSA-65(1952)`.
pub const HYBRID_VK_LEN: usize = ED25519_VK_LEN + MLDSA65_VK_LEN;

/// A hybrid signing (secret) key.
pub struct HybridSigSecret {
    ed25519: EdSigningKey,
    mldsa: MlSigningKey<MlDsa65>,
}

/// A hybrid verifying (public) key.
#[derive(Clone)]
pub struct HybridVerifier {
    ed25519: EdVerifyingKey,
    mldsa: MlVerifyingKey<MlDsa65>,
}

/// A hybrid signature: the Ed25519 and the ML-DSA-65 signatures.
pub struct HybridSignature {
    ed25519: EdSignature,
    mldsa: MlSignature<MlDsa65>,
}

impl HybridSigSecret {
    /// Generate a hybrid signing keypair from a CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> (Self, HybridVerifier) {
        let ed25519 = EdSigningKey::generate(rng);
        let mldsa = MlSigningKey::<MlDsa65>::generate_from_rng(rng);
        let verifier = HybridVerifier {
            ed25519: ed25519.verifying_key(),
            mldsa: mldsa.verifying_key(),
        };
        (Self { ed25519, mldsa }, verifier)
    }

    /// Sign a message with both primitives (spec §L6).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        HybridSignature {
            ed25519: self.ed25519.sign(message),
            mldsa: self.mldsa.sign(message),
        }
    }
}

impl HybridSignature {
    /// The canonical `Ed25519(64) ‖ ML-DSA-65(3309)` encoding, for transmitting or storing a
    /// signature (e.g. in a signed descriptor). Length is always [`HYBRID_SIG_LEN`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&self.ed25519.to_bytes());
        out.extend_from_slice(self.mldsa.encode().as_slice());
        out
    }

    /// Decode a hybrid signature from its canonical bytes, or `None` if the wrong length or a
    /// component fails to parse.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HYBRID_SIG_LEN {
            return None;
        }
        let ed: [u8; ED25519_SIG_LEN] = bytes.get(..ED25519_SIG_LEN)?.try_into().ok()?;
        let ed25519 = EdSignature::from_bytes(&ed);
        let mldsa = MlSignature::<MlDsa65>::try_from(bytes.get(ED25519_SIG_LEN..)?).ok()?;
        Some(Self { ed25519, mldsa })
    }
}

impl HybridVerifier {
    /// Verify a hybrid signature — **both** components must verify (spec §L6).
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> bool {
        self.ed25519.verify(message, &signature.ed25519).is_ok()
            && self.mldsa.verify(message, &signature.mldsa).is_ok()
    }

    /// The canonical public-key bytes `Ed25519(32) ‖ ML-DSA-65` for the node-ID hash (spec §L0).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_VK_LEN);
        out.extend_from_slice(self.ed25519.as_bytes());
        out.extend_from_slice(self.mldsa.encode().as_slice());
        out
    }

    /// Reconstruct a verifier from its canonical [`encode`](Self::encode) bytes, or `None` if the
    /// wrong length or a component is not a valid key. This lets a party that learns only the public
    /// key bytes (from a descriptor, a `.fanos` address binding, or a JOIN announcement) verify
    /// signatures under it.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HYBRID_VK_LEN {
            return None;
        }
        let ed: [u8; ED25519_VK_LEN] = bytes.get(..ED25519_VK_LEN)?.try_into().ok()?;
        let ed25519 = EdVerifyingKey::from_bytes(&ed).ok()?;
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(bytes.get(ED25519_VK_LEN..)?).ok()?;
        let mldsa = MlVerifyingKey::<MlDsa65>::decode(&enc);
        Some(Self { ed25519, mldsa })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::rng::SeedRng;

    #[test]
    fn sign_and_verify_round_trips() {
        let mut rng = SeedRng::from_seed(b"sig-test");
        let (secret, verifier) = HybridSigSecret::generate(&mut rng);
        let message = b"FANOS coordinate proof for epoch 42";
        let signature = secret.sign(message);
        assert!(verifier.verify(message, &signature));
    }

    #[test]
    fn a_tampered_message_fails() {
        let mut rng = SeedRng::from_seed(b"sig-test-2");
        let (secret, verifier) = HybridSigSecret::generate(&mut rng);
        let signature = secret.sign(b"original");
        assert!(!verifier.verify(b"tampered", &signature));
    }

    #[test]
    fn another_key_does_not_verify() {
        let mut rng = SeedRng::from_seed(b"sig-test-3");
        let (secret, _verifier) = HybridSigSecret::generate(&mut rng);
        let (_other_secret, other_verifier) = HybridSigSecret::generate(&mut rng);
        let signature = secret.sign(b"msg");
        assert!(!other_verifier.verify(b"msg", &signature));
    }

    #[test]
    fn signature_and_verifier_round_trip_through_bytes() {
        let mut rng = SeedRng::from_seed(b"sig-serde");
        let (secret, verifier) = HybridSigSecret::generate(&mut rng);
        let msg = b"a signed descriptor";
        let sig = secret.sign(msg);

        // A signature survives serialization and still verifies.
        let sig_bytes = sig.to_bytes();
        assert_eq!(sig_bytes.len(), HYBRID_SIG_LEN);
        let sig2 = HybridSignature::from_bytes(&sig_bytes).unwrap();
        assert!(verifier.verify(msg, &sig2));

        // A verifier reconstructed from only its public-key bytes verifies the same signature.
        let vk_bytes = verifier.encode();
        assert_eq!(vk_bytes.len(), HYBRID_VK_LEN);
        let verifier2 = HybridVerifier::decode(&vk_bytes).unwrap();
        assert!(verifier2.verify(msg, &sig2));

        // Wrong-length inputs are rejected.
        assert!(HybridSignature::from_bytes(&sig_bytes[..HYBRID_SIG_LEN - 1]).is_none());
        assert!(HybridVerifier::decode(&vk_bytes[..HYBRID_VK_LEN - 1]).is_none());
    }
}
