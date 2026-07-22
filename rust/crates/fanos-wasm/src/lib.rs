//! # fanos-wasm — the FANOS client in the browser
//!
//! A WebAssembly client surface for FANOS's **self-organizing coordinate**: from a seed, a browser or mobile
//! node computes the Fano point the network assigns it for an epoch (`coord = MapToPoint(VRF(sk, id ‖ epoch ‖
//! beacon))`), and any peer verifies that placement locally — no directory, no authority, just arithmetic. This
//! is the concrete answer to the usability lesson of the honest landscape comparison (`docs/comparison.md`):
//! FANOS's *more principled* computed-coordinate self-organization is only worth its elegance if it is as
//! reachable as a zero-config web/mobile client, and this crate makes the core reachable from JavaScript.
//!
//! The whole FANOS crypto stack (curve25519 ECVRF, hybrid PQ) already cross-builds to `wasm32-unknown-unknown`;
//! this crate wraps the client-side operations. The **pure core** ([`Identity`], [`verify_point`]) is ordinary
//! Rust with native tests; the **`wasm` feature** adds a thin `#[wasm_bindgen]` layer (`FanosIdentity`,
//! `verifyPoint`) that a JS host drives, supplying WebSocket transport and the beacon. The client uses only the
//! deterministic, seed-based key derivation, so it needs no ambient RNG at call time.
//!
//! ```ignore
//! // In JS, after `wasm-pack build --features wasm`:
//! const id = new FanosIdentity(seed32);          // an identity from a 32-byte seed
//! const point = id.point(epoch, beacon32);       // the network's computed placement (0..6 on the base cell)
//! const proof = id.pointProof(epoch, beacon32);  // the proof a peer checks
//! verifyPoint(id.nodeId(), point, epoch, beacon32, id.vrfPublic(), proof); // === true
//! ```

#![forbid(unsafe_code)]

use fanos_field::F2;
use fanos_geometry::fano;
use fanos_primitives::{hash_labeled, BeaconSeed, Epoch, NodeId};
use fanos_vrf::{prove_coordinate, verify_coordinate, VrfProof, VrfPublic, VrfSecret, PROOF_LEN};

/// The domain label binding a client's self-certifying node id to its coordinate-VRF public key.
const ID_LABEL: &str = "FANOS-v1/wasm-node-id";

/// A FANOS client identity: a coordinate-VRF key and the self-certifying [`NodeId`] that commits it
/// (`node_id = H(vrf_public)`), so a peer that learns the node id can check any placement it claims.
pub struct Identity {
    vrf_secret: VrfSecret,
    node_id: NodeId,
}

impl Identity {
    /// Derive a client identity from a 32-byte seed. Deterministic and total — every seed yields a key. (A
    /// production client draws the seed from the platform CSPRNG once and persists it; the network then assigns
    /// this identity a fresh coordinate every epoch.)
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let vrf_secret = VrfSecret::from_seed(seed);
        let node_id = NodeId(hash_labeled(ID_LABEL, &vrf_secret.public().to_bytes()));
        Self { vrf_secret, node_id }
    }

    /// The 32-byte self-certifying node id.
    #[must_use]
    pub fn node_id(&self) -> [u8; 32] {
        self.node_id.0
    }

    /// The coordinate-VRF public key (a peer needs it to verify a placement; the node id commits it).
    #[must_use]
    pub fn vrf_public(&self) -> [u8; 32] {
        self.vrf_secret.public().to_bytes()
    }

    /// The **Fano point** `0..6` the network assigns this identity for `(epoch, beacon)` — computed from the VRF,
    /// not chosen, and un-aimable (the beacon is unbiasable). This is the node's position each epoch.
    #[must_use]
    pub fn point(&self, epoch: u64, beacon: [u8; 32]) -> u8 {
        let (coord, _) =
            prove_coordinate::<F2>(&self.vrf_secret, &self.node_id.0, Epoch::new(epoch), &BeaconSeed::new(beacon));
        coord.index() as u8
    }

    /// The proof that this identity earns its [`point`](Self::point) for `(epoch, beacon)` — a peer verifies it
    /// with [`verify_point`].
    #[must_use]
    pub fn point_proof(&self, epoch: u64, beacon: [u8; 32]) -> [u8; PROOF_LEN] {
        let (_, proof) =
            prove_coordinate::<F2>(&self.vrf_secret, &self.node_id.0, Epoch::new(epoch), &BeaconSeed::new(beacon));
        proof.to_bytes()
    }
}

/// Verify that a peer earns its claimed Fano `point` for `(epoch, beacon)` under `vrf_public`, and that its
/// `node_id` self-certifies that key (`node_id == H(vrf_public)`). This is the self-organizing admission a
/// client runs locally — a forged placement, a mismatched key, or the wrong beacon is rejected (spec §7.3
/// `BAD_COORD`) — with no directory and no trusted authority.
#[must_use]
pub fn verify_point(
    node_id: [u8; 32],
    point: u8,
    epoch: u64,
    beacon: [u8; 32],
    vrf_public: [u8; 32],
    proof: &[u8],
) -> bool {
    if usize::from(point) >= fano::N {
        return false;
    }
    // Self-certification: the node id must commit exactly this VRF public key.
    if node_id != hash_labeled(ID_LABEL, &vrf_public) {
        return false;
    }
    let Some(vp) = VrfPublic::from_bytes(vrf_public) else {
        return false;
    };
    let Ok(proof_bytes) = <[u8; PROOF_LEN]>::try_from(proof) else {
        return false;
    };
    let Some(pf) = VrfProof::from_bytes(proof_bytes) else {
        return false;
    };
    let coord = fano::point(usize::from(point));
    verify_coordinate::<F2>(&vp, &node_id, Epoch::new(epoch), &BeaconSeed::new(beacon), &coord, &pf)
}

// ── The JavaScript-facing layer (only under `--features wasm`) ──────────────────────────────────────────────
// `wasm_bindgen` exports these `pub` items to JS from a private module, which Rust flags as unreachable-pub.
#[cfg(feature = "wasm")]
#[allow(unreachable_pub)]
mod js {
    use super::{verify_point, Identity};
    use wasm_bindgen::prelude::*;

    /// A FANOS client identity, exposed to JavaScript.
    #[wasm_bindgen]
    pub struct FanosIdentity(Identity);

    fn seed32(bytes: &[u8], what: &str) -> Result<[u8; 32], JsError> {
        <[u8; 32]>::try_from(bytes).map_err(|_| JsError::new(&format!("{what} must be 32 bytes")))
    }

    #[wasm_bindgen]
    impl FanosIdentity {
        /// Build an identity from a 32-byte seed.
        #[wasm_bindgen(constructor)]
        pub fn new(seed: &[u8]) -> Result<FanosIdentity, JsError> {
            Ok(FanosIdentity(Identity::from_seed(seed32(seed, "seed")?)))
        }

        /// The 32-byte self-certifying node id.
        #[wasm_bindgen(js_name = nodeId)]
        pub fn node_id(&self) -> Vec<u8> {
            self.0.node_id().to_vec()
        }

        /// The coordinate-VRF public key.
        #[wasm_bindgen(js_name = vrfPublic)]
        pub fn vrf_public(&self) -> Vec<u8> {
            self.0.vrf_public().to_vec()
        }

        /// The Fano point `0..6` the network assigns this identity for `(epoch, beacon)`.
        pub fn point(&self, epoch: u64, beacon: &[u8]) -> Result<u8, JsError> {
            Ok(self.0.point(epoch, seed32(beacon, "beacon")?))
        }

        /// The proof that this identity earns that point.
        #[wasm_bindgen(js_name = pointProof)]
        pub fn point_proof(&self, epoch: u64, beacon: &[u8]) -> Result<Vec<u8>, JsError> {
            Ok(self.0.point_proof(epoch, seed32(beacon, "beacon")?).to_vec())
        }
    }

    /// Verify a peer's claimed placement locally (self-organizing admission).
    #[wasm_bindgen(js_name = verifyPoint)]
    #[must_use]
    pub fn verify_point_js(
        node_id: &[u8],
        point: u8,
        epoch: u64,
        beacon: &[u8],
        vrf_public: &[u8],
        proof: &[u8],
    ) -> bool {
        let (Ok(id), Ok(b), Ok(vp)) =
            (seed32(node_id, "node_id"), seed32(beacon, "beacon"), seed32(vrf_public, "vrf_public"))
        else {
            return false;
        };
        verify_point(id, point, epoch, b, vp, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEACON: [u8; 32] = [0x11; 32];

    #[test]
    fn a_client_computes_a_valid_verifiable_coordinate() {
        let id = Identity::from_seed([7u8; 32]);
        let point = id.point(3, BEACON);
        assert!(usize::from(point) < fano::N, "the point is a Fano point 0..6");
        let proof = id.point_proof(3, BEACON);
        // A peer verifies the placement locally from the public inputs — no authority.
        assert!(verify_point(id.node_id(), point, 3, BEACON, id.vrf_public(), &proof));
    }

    #[test]
    fn the_coordinate_reshuffles_each_epoch_and_is_unforgeable() {
        let id = Identity::from_seed([9u8; 32]);
        // A different epoch generally moves the point (a reshuffling, moving-target placement).
        let differ = (0..40u64).filter(|&e| id.point(e, BEACON) != id.point(e + 1, BEACON)).count();
        assert!(differ > 15, "the coordinate reshuffles across epochs, got {differ}/40 changes");
        // A wrong point, wrong beacon, wrong key, or a tampered node id is all rejected.
        let point = id.point(5, BEACON);
        let proof = id.point_proof(5, BEACON);
        assert!(verify_point(id.node_id(), point, 5, BEACON, id.vrf_public(), &proof));
        let other = (point + 1) % (fano::N as u8);
        assert!(!verify_point(id.node_id(), other, 5, BEACON, id.vrf_public(), &proof), "a wrong point is rejected");
        assert!(!verify_point(id.node_id(), point, 6, BEACON, id.vrf_public(), &proof), "a wrong epoch is rejected");
        assert!(!verify_point(id.node_id(), point, 5, [0x22; 32], id.vrf_public(), &proof), "a wrong beacon is rejected");
        // A node id that does not commit the presented VRF key is rejected (no key substitution).
        assert!(!verify_point([0xAB; 32], point, 5, BEACON, id.vrf_public(), &proof), "a non-committing id is rejected");
    }

    #[test]
    fn distinct_seeds_are_distinct_self_certifying_identities() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        assert_ne!(a.node_id(), b.node_id());
        assert_ne!(a.vrf_public(), b.vrf_public());
        // Each identity's node id commits its own key.
        assert!(verify_point(a.node_id(), a.point(0, BEACON), 0, BEACON, a.vrf_public(), &a.point_proof(0, BEACON)));
        // …and one identity cannot pass another's proof.
        assert!(!verify_point(a.node_id(), a.point(0, BEACON), 0, BEACON, b.vrf_public(), &a.point_proof(0, BEACON)));
    }
}
