//! The hybrid signature `Ed25519 ‖ ML-DSA-65` (spec §L6).
//!
//! Both signatures are produced over the same message and *both* must verify. Forgery
//! therefore requires breaking Ed25519 **and** ML-DSA-65 — a classical + post-quantum hedge.
//! This binds a FANOS node's long-term identity and its coordinate proofs (spec §L0, §7.3).

use ed25519_dalek::{
    Signature as EdSignature, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    Generate, MlDsa65, Signature as MlSignature, SigningKey as MlSigningKey,
    VerifyingKey as MlVerifyingKey,
};
use rand_core::CryptoRng;

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
        let mut out = Vec::new();
        out.extend_from_slice(self.ed25519.as_bytes());
        out.extend_from_slice(self.mldsa.encode().as_slice());
        out
    }
}

#[cfg(test)]
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
}
