//! Node identity from the hybrid public keys (spec §L0, §7.1).
//!
//! A FANOS node's long-term identifier is the BLAKE3 hash of the canonical concatenation of its hybrid
//! signature key, hybrid KEM key, and **coordinate-VRF** key. This is the real, post-quantum realization
//! of the identity that [`fanos_primitives`](https://docs.rs/fanos-primitives) models as a byte-bundle.
//! The VRF key is what makes the node's projective coordinate verifiable — `coord = MapToPoint(VRF(vrf_sk,
//! epoch ‖ beacon))` — and because it is in the bundle, the `NodeId` commits to it (see
//! `docs/design-coordinates.md`). All three keys derive from one CSPRNG draw, so an identity is one seed.

use fanos_primitives::{hash_labeled, label};
use fanos_vrf::{VrfOutput, VrfProof, VrfPublic, VrfSecret};
use rand_core::CryptoRng;

use crate::kem::{HybridCiphertext, HybridKemPublic, HybridKemSecret, SessionKey};
use crate::sig::{HybridSigSecret, HybridSignature, HybridVerifier};

/// The 32-byte long-term node identifier — the canonical type from [`fanos_primitives`], re-exported
/// here so a consumer of the real hybrid identity names one `NodeId`, not two (they were identical
/// byte-for-byte; the duplicate is retired).
pub use fanos_primitives::NodeId;

/// A node's public identity: its hybrid signature, KEM, and coordinate-VRF public keys (spec §L0).
///
/// The three keys are read as one canonical bundle ([`encode`](Self::encode)) — the only input the
/// [`NodeId`] commits to — so they are private with no individual accessor: a consumer names the whole
/// identity (its `encode`/`node_id`), never a lone component that could drift from the committed bundle.
pub struct PublicIdentity {
    /// The hybrid signature verifier.
    signature: HybridVerifier,
    /// The hybrid KEM public key.
    kem: HybridKemPublic,
    /// The coordinate-VRF public key — verifies this node's `HELLO` proof-of-coordinate.
    vrf: VrfPublic,
}

impl PublicIdentity {
    /// The canonical public-key **bundle** bytes `sig ‖ kem ‖ vrf` (spec §7.1) — the one input the
    /// [`NodeId`] and the ONOMA/CALYPSO address commitment are both computed from. The VRF public is
    /// appended last, matching [`fanos_primitives::keys::HybridPublicKey::encode`], so the identifier
    /// commits to the key that earns the node's verifiable coordinate. This is the single source of truth
    /// for the bundle layout — never re-concatenate the components by hand.
    #[must_use]
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        let mut bundle = self.signature.encode();
        bundle.extend_from_slice(&self.kem.encode());
        bundle.extend_from_slice(&self.vrf.to_bytes());
        bundle
    }

    /// The hybrid signature verifier — checks signatures this node produced with [`Identity::sign`].
    #[must_use]
    pub fn signature(&self) -> &HybridVerifier {
        &self.signature
    }

    /// The hybrid KEM public key — encapsulate to it to seal a message only this node can
    /// [`decapsulate`](Identity::decapsulate).
    #[must_use]
    pub fn kem(&self) -> &HybridKemPublic {
        &self.kem
    }

    /// The coordinate-VRF public key — verifies the proofs this node produces with
    /// [`Identity::vrf_prove`].
    #[must_use]
    pub fn vrf(&self) -> &VrfPublic {
        &self.vrf
    }

    /// The long-term node identifier: domain-separated `BLAKE3` of the canonical [`encode`](Self::encode)d
    /// bundle (spec §L0), via the one canonical [`fanos_primitives::hash_labeled`] under the shared
    /// [`label::NODE_ID`] — the single source of truth, so this real identity and the byte-model in
    /// `fanos-primitives` cannot drift apart.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId(hash_labeled(label::NODE_ID, &self.encode()))
    }
}

/// A node's full identity — the secret signing, KEM, and coordinate-VRF keys plus the derived public
/// identity (spec §7.1). This is the **transport-agnostic** identity: its secrets are reached only
/// through the three behaviours they authorise — [`sign`](Self::sign), [`decapsulate`](Self::decapsulate),
/// and [`vrf_prove`](Self::vrf_prove) — never as raw fields, so a caller cannot copy, log, serialize, or
/// `mem::take` a secret out from under its zeroize-on-drop.
///
/// The live QUIC transport realizes the *coordinate* VRF a second way — derived from the mutual-TLS
/// certificate so the identity self-authenticates over the wire (`fanos_node::NodeCredentials`,
/// `docs/design-coordinates.md`) — so in that wiring an `Identity`'s own `vrf_prove` is the primitive the
/// coordinate layer builds on rather than the on-wire path. Both commit to the same [`NodeId`] bundle.
pub struct Identity {
    /// The hybrid signing key — reached only via [`sign`](Self::sign).
    signing: HybridSigSecret,
    /// The hybrid KEM secret key — reached only via [`decapsulate`](Self::decapsulate).
    kem: HybridKemSecret,
    /// The coordinate-VRF secret key — reached only via [`vrf_prove`](Self::vrf_prove).
    vrf: VrfSecret,
    /// The derived public identity.
    public: PublicIdentity,
}

impl Identity {
    /// Generate a fresh node identity from a CSPRNG — the hybrid signature, KEM, and coordinate-VRF keys
    /// all drawn from the one source, so the identity is one seed (spec §L0).
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let (signing, sig_public) = HybridSigSecret::generate(rng);
        let (kem_secret, kem_public) = HybridKemSecret::generate(rng);
        // The coordinate-VRF key: a draw from the same CSPRNG. `from_seed` reduces into the scalar
        // field, so every draw yields a valid key (no error path — spec §L0 coordinate assignment).
        let mut vrf_seed = [0u8; 32];
        rng.fill_bytes(&mut vrf_seed);
        let vrf = VrfSecret::from_seed(vrf_seed);
        let vrf_public = vrf.public();
        Self {
            signing,
            kem: kem_secret,
            vrf,
            public: PublicIdentity {
                signature: sig_public,
                kem: kem_public,
                vrf: vrf_public,
            },
        }
    }

    /// This node's identifier.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.public.node_id()
    }

    /// This node's public identity — its published signature/KEM/VRF bundle (verify signatures,
    /// encapsulate to it, check its VRF proofs).
    #[must_use]
    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    /// Sign `message` with the node's hybrid signature secret (spec §7.1) — e.g. to authenticate a
    /// membership descriptor binding a transport to an overlay address. Verify with
    /// [`self.public()`](Self::public)'s verifier.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        self.signing.sign(message)
    }

    /// Decapsulate a hybrid ciphertext sealed to this node's KEM public key, yielding the 32-byte shared
    /// session key (spec §7.1 receive path). The matching public key is `self.public()`. `None` if the
    /// ciphertext's X25519 leg is non-contributory (audit B5 — see
    /// [`HybridKemSecret::decapsulate`](crate::kem::HybridKemSecret::decapsulate)).
    #[must_use]
    pub fn decapsulate(&self, ciphertext: &HybridCiphertext) -> Option<SessionKey> {
        self.kem.decapsulate(ciphertext)
    }

    /// Prove this node's VRF over `alpha`, returning the proof and the 64-byte output it commits to. The
    /// overlay coordinate is `MapToPoint` of a proof over `beacon_alpha(node_id, epoch, beacon)` (spec
    /// §L0); this is the transport-agnostic primitive that the coordinate layer forms `alpha` for. Verify
    /// with `self.public()`'s VRF key.
    #[must_use]
    pub fn vrf_prove(&self, alpha: &[u8]) -> (VrfProof, VrfOutput) {
        self.vrf.prove(alpha)
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
        let signature = node.sign(proof_input);
        assert!(node.public().signature().verify(proof_input, &signature));
    }

    #[test]
    fn a_ciphertext_sealed_to_a_nodes_kem_public_decapsulates_to_the_same_key() {
        // Receive path (spec §7.1): anyone encapsulates to the node's KEM public; only the node's
        // `decapsulate` recovers the shared key — proving the held KEM secret is live, not dead weight.
        let mut rng = SeedRng::from_seed(b"id-kem");
        let node = Identity::generate(&mut rng);
        let (ciphertext, sender_key) = node
            .public()
            .kem()
            .encapsulate(&mut rng)
            .unwrap();
        assert_eq!(
            node.decapsulate(&ciphertext),
            Some(sender_key),
            "the node recovers the sender's session key"
        );
        // A different node's secret must NOT recover it.
        let other = Identity::generate(&mut rng);
        assert_ne!(
            other.decapsulate(&ciphertext).unwrap(),
            sender_key
        );
    }

    #[test]
    fn a_nodes_vrf_proof_verifies_under_its_public_vrf_key() {
        // Coordinate-proof primitive (spec §L0): the node proves its VRF over some alpha; its public VRF
        // key verifies the proof and recovers the same committed output — the held VRF secret is live.
        let mut rng = SeedRng::from_seed(b"id-vrf");
        let node = Identity::generate(&mut rng);
        let alpha = b"beacon_alpha(node_id, epoch, beacon)";
        let (proof, output) = node.vrf_prove(alpha);
        assert_eq!(
            node.public().vrf().verify(alpha, &proof),
            Some(output),
            "the public VRF key verifies the proof and recovers its output"
        );
    }

    #[test]
    fn node_id_matches_the_primitives_byte_model() {
        // Cross-crate parity (spec §L0): the real hybrid identity and the `fanos-primitives` byte-model
        // must derive the SAME node id from the SAME public bundle, or the two impls disagree on
        // addressing. Reconstruct the byte-model from the real identity's component keys and compare —
        // this pins the bundle layout `Ed25519 ‖ ML-DSA ‖ X25519 ‖ ML-KEM ‖ VRF` and the hash rule.
        use fanos_primitives::keys::{HybridPublicKey, KemPublicKey, SigPublicKey};

        let node = Identity::generate(&mut SeedRng::from_seed(b"id-parity"));
        let sig_bytes = node.public().signature().encode();
        let kem_bytes = node.public().kem().encode();
        // Split each hybrid public key into its (classical 32, PQ rest) components.
        let (ed, mldsa) = sig_bytes.split_at(32);
        let (x, mlkem) = kem_bytes.split_at(32);
        let model = HybridPublicKey {
            sig: SigPublicKey::new(ed.try_into().unwrap(), mldsa.to_vec()).unwrap(),
            kem: KemPublicKey::new(x.try_into().unwrap(), mlkem.to_vec()).unwrap(),
            vrf: node.public().vrf().to_bytes(),
        };
        assert_eq!(
            node.node_id(),
            model.node_id(),
            "real identity and byte-model agree on the node id"
        );
    }
}
