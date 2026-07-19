//! Node identity from the hybrid public keys (spec §L0, §7.1).
//!
//! A FANOS node's long-term identifier is the BLAKE3 hash of the canonical concatenation of
//! its hybrid signature and KEM public keys. This is the real, post-quantum realization of the
//! identity that [`fanos_primitives`](https://docs.rs/fanos-primitives) models as a placeholder.

use fanos_primitives::{hash_labeled, label};
use rand_core::CryptoRng;

use crate::kem::{HybridKemPublic, HybridKemSecret};
use crate::sig::{HybridSigSecret, HybridVerifier};

/// The 32-byte long-term node identifier — the canonical type from [`fanos_primitives`], re-exported
/// here so a consumer of the real hybrid identity names one `NodeId`, not two (they were identical
/// byte-for-byte; the duplicate is retired).
pub use fanos_primitives::NodeId;

/// A node's public identity: its hybrid signature and KEM public keys (spec §L0).
pub struct PublicIdentity {
    /// The hybrid signature verifier.
    pub signature: HybridVerifier,
    /// The hybrid KEM public key.
    pub kem: HybridKemPublic,
}

impl PublicIdentity {
    /// The long-term node identifier: domain-separated `BLAKE3` of the canonical public-key bundle
    /// `sig ‖ kem` (spec §L0), via the one canonical [`fanos_primitives::hash_labeled`] under the shared
    /// [`label::NODE_ID`] — the single source of truth, so this real identity and the byte-model in
    /// `fanos-primitives` cannot drift apart.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        let mut bundle = self.signature.encode();
        bundle.extend_from_slice(&self.kem.encode());
        NodeId(hash_labeled(label::NODE_ID, &bundle))
    }
}

/// A node's full identity — the secret signing and KEM keys plus the derived public identity.
pub struct Identity {
    /// The hybrid signing key.
    pub signing: HybridSigSecret,
    /// The hybrid KEM secret key.
    pub kem: HybridKemSecret,
    /// The derived public identity.
    pub public: PublicIdentity,
}

impl Identity {
    /// Generate a fresh node identity from a CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let (signing, sig_public) = HybridSigSecret::generate(rng);
        let (kem_secret, kem_public) = HybridKemSecret::generate(rng);
        Self {
            signing,
            kem: kem_secret,
            public: PublicIdentity {
                signature: sig_public,
                kem: kem_public,
            },
        }
    }

    /// This node's identifier.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.public.node_id()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::rng::SeedRng;

    #[test]
    fn node_id_is_deterministic_and_distinguishing() {
        let mut rng = SeedRng::from_seed(b"id-1");
        let a = Identity::generate(&mut rng);
        let b = Identity::generate(&mut rng);
        assert_eq!(a.node_id(), a.node_id());
        assert_ne!(a.node_id(), b.node_id());
    }

    #[test]
    fn a_node_can_sign_and_others_verify_with_its_public_identity() {
        // The identity flow: a node signs a coordinate proof; anyone verifies with its pubkey.
        let mut rng = SeedRng::from_seed(b"id-2");
        let node = Identity::generate(&mut rng);
        let proof_input = b"coord-proof:epoch=42";
        let signature = node.signing.sign(proof_input);
        assert!(node.public.signature.verify(proof_input, &signature));
    }

    #[test]
    fn node_id_matches_the_primitives_byte_model() {
        // Cross-crate parity (spec §L0): the real hybrid identity and the `fanos-primitives` byte-model
        // must derive the SAME node id from the SAME public bundle, or the two impls disagree on
        // addressing. Reconstruct the byte-model from the real identity's component keys and compare —
        // this pins the bundle layout `Ed25519 ‖ ML-DSA ‖ X25519 ‖ ML-KEM` and the hash rule together.
        use fanos_primitives::keys::{HybridPublicKey, KemPublicKey, SigPublicKey};

        let node = Identity::generate(&mut SeedRng::from_seed(b"id-parity"));
        let sig_bytes = node.public.signature.encode();
        let kem_bytes = node.public.kem.encode();
        // Split each hybrid public key into its (classical 32, PQ rest) components.
        let (ed, mldsa) = sig_bytes.split_at(32);
        let (x, mlkem) = kem_bytes.split_at(32);
        let model = HybridPublicKey {
            sig: SigPublicKey::new(ed.try_into().unwrap(), mldsa.to_vec()).unwrap(),
            kem: KemPublicKey::new(x.try_into().unwrap(), mlkem.to_vec()).unwrap(),
        };
        assert_eq!(node.node_id(), model.node_id(), "real identity and byte-model agree on the node id");
    }
}
