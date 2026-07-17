//! Node identity from the hybrid public keys (spec §L0, §7.1).
//!
//! A FANOS node's long-term identifier is the BLAKE3 hash of the canonical concatenation of
//! its hybrid signature and KEM public keys. This is the real, post-quantum realization of the
//! identity that [`fanos_crypto`](https://docs.rs/fanos-crypto) models as a placeholder.

use rand_core::CryptoRng;

use crate::kem::{HybridKemPublic, HybridKemSecret};
use crate::sig::{HybridSigSecret, HybridVerifier};

const NODE_ID_LABEL: &[u8] = b"FANOS-v1/node-id";

/// A 32-byte long-term node identifier.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// The identifier bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A node's public identity: its hybrid signature and KEM public keys (spec §L0).
pub struct PublicIdentity {
    /// The hybrid signature verifier.
    pub signature: HybridVerifier,
    /// The hybrid KEM public key.
    pub kem: HybridKemPublic,
}

impl PublicIdentity {
    /// The long-term node identifier: domain-separated `BLAKE3` of the canonical public-key
    /// bundle (spec §L0). This reproduces `fanos_crypto::hash_labeled(NODE_ID, sig ‖ kem)`
    /// **byte-for-byte** — including the `0x1f` unit separator after the label — so the placeholder
    /// identity in `fanos-crypto` and this real hybrid one agree on the same node ID (a
    /// cross-crate test in `tests/node_id_parity.rs` pins the two together).
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(NODE_ID_LABEL);
        hasher.update(&[0x1f]); // canonical unit separator — matches `hash_labeled`
        hasher.update(&self.signature.encode());
        hasher.update(&self.kem.encode());
        NodeId(*hasher.finalize().as_bytes())
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
    fn node_id_matches_the_canonical_fanos_crypto_rule() {
        // The real hybrid identity and the `fanos-crypto` placeholder must agree on the node ID,
        // or the two impls disagree on addressing (spec §L0). Pin them: the pqcrypto node_id equals
        // `hash_labeled(NODE_ID, sig ‖ kem)` byte-for-byte (this catches a missing/extra separator).
        let mut rng = SeedRng::from_seed(b"id-parity");
        let node = Identity::generate(&mut rng);
        let mut bundle = node.public.signature.encode();
        bundle.extend_from_slice(&node.public.kem.encode());
        let canonical = fanos_crypto::hash_labeled(fanos_crypto::label::NODE_ID, &bundle);
        assert_eq!(node.node_id().0, canonical);
    }
}
