//! A node's complete cryptographic identity (spec §L0, §7.1).
//!
//! An identity is the composition of the two hybrid keypairs — [signature](crate::sig) and
//! [KEM](crate::kem) — both derived deterministically from **one 32-byte seed**. From it follow, all
//! deterministically:
//!
//! * the **public bundle** `Ed25519 ‖ ML-DSA-65 ‖ X25519 ‖ ML-KEM-768` ([`HybridPublicKey`]) — the
//!   canonical identity bytes that authenticated membership and self-certifying addresses are keyed on;
//! * the 32-byte **node identifier** `H(bundle)` ([`NodeId`], spec §L0);
//! * the self-certifying **overlay address** `MapToPoint(bundle ‖ level)` ([`address_point`]).
//!
//! A node holds one seed; everything above is a pure function of it, so an identity is fully
//! reproducible in the deterministic simulator. This module is the single place the primitives are
//! composed — [`fanos_quic::identity`] binds the same bundle to a TLS certificate at the transport.

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::{HierAddr, Point, derive_address};

use crate::address::address_point;
use crate::kem::{self, HYBRID_KEM_PK_LEN, HYBRID_KEM_SS_LEN, HybridKemKey};
use crate::keys::{HybridPublicKey, KemPublicKey, NodeId, SigPublicKey};
use crate::sig::{self, HybridSigningKey};

// The data-model lengths in `keys` and the primitive lengths in `sig`/`kem` must agree, or composing a
// bundle from real keys would mis-size a component. Pin them equal at compile time.
const _: () = assert!(crate::keys::ED25519_PK_LEN == sig::ED25519_PK_LEN);
const _: () = assert!(crate::keys::MLDSA65_PK_LEN == sig::MLDSA65_PK_LEN);
const _: () = assert!(crate::keys::X25519_PK_LEN == kem::X25519_LEN);
const _: () = assert!(crate::keys::MLKEM768_PK_LEN == kem::MLKEM768_EK_LEN);

/// A node's secret identity: the hybrid signing and KEM keypairs, plus the cached public bundle, all
/// derived from one 32-byte seed. The secret halves never leave this type; only signatures, decapsulated
/// secrets, and the public bundle come out.
pub struct HybridIdentity {
    sig: HybridSigningKey,
    kem: HybridKemKey,
    public: HybridPublicKey,
    bundle: Vec<u8>,
}

impl HybridIdentity {
    /// Derive a complete identity from one 32-byte seed. Both keypairs domain-separate internally, so
    /// the four component keys are independent though they share one origin.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sig = HybridSigningKey::from_seed(seed);
        let kem = HybridKemKey::from_seed(seed);
        let public = HybridPublicKey {
            sig: SigPublicKey::from_parts(sig.ed25519_public(), sig.mldsa65_public()),
            kem: KemPublicKey::from_parts(kem.x25519_public(), kem.mlkem768_public()),
        };
        let bundle = public.encode();
        Self { sig, kem, public, bundle }
    }

    /// The public identity bundle.
    #[must_use]
    pub fn public(&self) -> &HybridPublicKey {
        &self.public
    }

    /// The canonical identity bytes (`public().encode()`): the pre-image the node's address and
    /// signed descriptors are keyed on. Publish these as the `id` in a membership announcement.
    #[must_use]
    pub fn identity_bytes(&self) -> &[u8] {
        &self.bundle
    }

    /// The 32-byte long-term node identifier `H(bundle)` (spec §L0).
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.public.node_id()
    }

    /// Sign `msg` with the hybrid signing key (`Ed25519 ‖ ML-DSA-65`). `None` only on the ML-DSA
    /// internal error path (never for this valid key).
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Option<Vec<u8>> {
        self.sig.sign(msg)
    }

    /// Decapsulate a hybrid ciphertext addressed to this identity's KEM key. `None` on a malformed
    /// ciphertext.
    #[must_use]
    pub fn decapsulate(&self, ct: &[u8]) -> Option<[u8; HYBRID_KEM_SS_LEN]> {
        self.kem.decapsulate(ct)
    }

    /// This identity's self-certifying point at descent `level` (spec §L1) — `MapToPoint(bundle ‖ level)`.
    #[must_use]
    pub fn address_point<F: Field>(&self, level: usize) -> Point<F> {
        address_point::<F>(&self.bundle, level)
    }

    /// The depth-1 (single-plane) overlay address of a node that does not collide.
    #[must_use]
    pub fn root_address<F: Field>(&self) -> HierAddr<F> {
        HierAddr::root(self.address_point::<F>(0))
    }

    /// The overlay address resolved by sub-cell descent (§L0/§L1): the shortest self-certifying path
    /// whose full address `occupied` reports free. `None` only under an astronomically improbable run
    /// of collisions ([`fanos_geometry::MAX_DEPTH`]).
    #[must_use]
    pub fn address<F: Field>(&self, occupied: impl Fn(&[Point<F>]) -> bool) -> Option<HierAddr<F>> {
        derive_address(|level| self.address_point::<F>(level), occupied)
    }
}

impl HybridPublicKey {
    /// Verify a hybrid signature (`Ed25519 ‖ ML-DSA-65`) under this public identity — valid iff *both*
    /// components verify. `false` (never a panic) on any malformed length or bad half.
    #[must_use]
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        let Ok(mldsa) = <[u8; sig::MLDSA65_PK_LEN]>::try_from(self.sig.mldsa65()) else {
            return false;
        };
        sig::hybrid_verify(&self.sig.ed25519(), &mldsa, msg, signature)
    }

    /// Encapsulate a fresh shared secret to this public identity's KEM key, deterministically from
    /// `seed`. Returns the ciphertext and the shared secret. `None` on an internal encapsulation error.
    #[must_use]
    pub fn encapsulate(&self, seed: &[u8]) -> Option<(Vec<u8>, [u8; HYBRID_KEM_SS_LEN])> {
        let mut kem_public = Vec::with_capacity(HYBRID_KEM_PK_LEN);
        kem_public.extend_from_slice(&self.kem.x25519());
        kem_public.extend_from_slice(self.kem.mlkem768());
        kem::hybrid_encapsulate(&kem_public, seed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::address::address_matches_identity;
    use fanos_field::F2;

    #[test]
    fn identity_bundle_round_trips_and_matches_the_public_key() {
        let id = HybridIdentity::from_seed(&[1u8; 32]);
        // The cached bundle equals the public key's own encoding, and decodes back to it.
        assert_eq!(id.identity_bytes(), id.public().encode());
        assert_eq!(
            HybridPublicKey::decode(id.identity_bytes()).as_ref(),
            Some(id.public()),
        );
        assert_eq!(id.identity_bytes().len(), HybridPublicKey::ENCODED_LEN);
    }

    #[test]
    fn node_id_is_deterministic_and_distinguishing() {
        let a = HybridIdentity::from_seed(&[2u8; 32]);
        let b = HybridIdentity::from_seed(&[2u8; 32]);
        let c = HybridIdentity::from_seed(&[3u8; 32]);
        assert_eq!(a.node_id(), b.node_id(), "same seed → same node id");
        assert_ne!(a.node_id(), c.node_id(), "different seed → different node id");
    }

    #[test]
    fn the_identity_signs_and_its_public_key_verifies() {
        let id = HybridIdentity::from_seed(&[4u8; 32]);
        let msg = b"membership descriptor";
        let sig = id.sign(msg).expect("sign");
        assert!(id.public().verify(msg, &sig), "the public identity verifies its own signature");
        assert!(!id.public().verify(b"tampered", &sig), "a wrong message is rejected");
        let other = HybridIdentity::from_seed(&[5u8; 32]);
        assert!(!other.public().verify(msg, &sig), "a different identity does not verify it");
    }

    #[test]
    fn the_identity_kem_round_trips_through_its_public_key() {
        let id = HybridIdentity::from_seed(&[6u8; 32]);
        let (ct, ss_sender) = id.public().encapsulate(b"encaps-seed").expect("encaps");
        let ss_recipient = id.decapsulate(&ct).expect("decaps");
        assert_eq!(ss_sender, ss_recipient, "the identity recovers the encapsulated secret");
        let other = HybridIdentity::from_seed(&[7u8; 32]);
        assert_ne!(other.decapsulate(&ct).unwrap(), ss_sender, "a different identity cannot");
    }

    #[test]
    fn the_address_is_self_certified_by_the_identity_bundle() {
        // The overlay's self-certification (`address_matches_identity`) accepts an address derived from
        // this identity's bundle — the single source of truth the whole membership stack keys on.
        let id = HybridIdentity::from_seed(&[8u8; 32]);
        let addr = id.root_address::<F2>();
        assert!(address_matches_identity::<F2>(id.identity_bytes(), &addr));
        // A deeper (descended) address also self-certifies against the same bundle.
        let deep = id.address::<F2>(|path| path.len() < 2).expect("descend on a forced collision");
        assert!(deep.depth() >= 2);
        assert!(address_matches_identity::<F2>(id.identity_bytes(), &deep));
    }

    #[test]
    fn decode_rejects_a_wrong_length_bundle() {
        let id = HybridIdentity::from_seed(&[9u8; 32]);
        let mut short = id.identity_bytes().to_vec();
        short.pop();
        assert!(HybridPublicKey::decode(&short).is_none(), "a truncated bundle is rejected");
        let mut long = id.identity_bytes().to_vec();
        long.push(0);
        assert!(HybridPublicKey::decode(&long).is_none(), "an oversized bundle is rejected");
    }
}
