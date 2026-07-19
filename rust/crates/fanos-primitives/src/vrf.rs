//! The VRF surface for epoch-bound coordinate assignment (spec §L0, §L3).
//!
//! A node's coordinate is `MapToPoint(VRF(pubkey, epoch))`: the VRF binds the coordinate to
//! the epoch (so it reshuffles when the beacon advances) and is verifiable and not cheaply
//! grindable. The production instantiation is **ECVRF-Edwards25519** (RFC 9381), which needs
//! elliptic-curve crypto and so lives in its own crate.
//!
//! This module exposes a *deterministic* coordinate derivation that binds `(bundle, epoch)` exactly
//! as production does, so no_std addressing is testable end to end. It has no keyed proof and so is
//! not unforgeable on its own. The **real, verifiable** VRF lives in
//! [`fanos-vrf`](https://docs.rs/fanos-vrf): a ristretto255 RFC 9381-style VRF whose
//! `prove_coordinate` / `verify_coordinate` give an unforgeable, self-certifying coordinate — a node
//! proves its epoch position from its key, checkable by anyone without the secret. Use that where the
//! anti-grinding guarantees of §3.2 must hold; this hash form is the no_std reference. (`fanos-vrf`'s
//! `VrfSecret`/`VrfPublic`/`VrfProof` are the concrete API; there is no generic `Vrf` trait — nothing
//! is written generically over "any VRF backend", so a trait would be an abstraction without a client.)

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::{Line, Point};

use crate::epoch::Epoch;
use crate::hash::{hash_labeled, label};
use crate::keys::NodeId;
use crate::maptopoint::{map_to_line, map_to_point};

/// The VRF input for coordinate assignment: the node's identity bound to an epoch.
///
/// The epoch occupies a fixed 4-byte big-endian tail (a KAT-pinned encoding — see
/// [`Epoch::low32_be_bytes`]); the full input is exactly `node(32) ‖ epoch_low32_be(4)`.
#[must_use]
pub fn coord_input(node: &NodeId, epoch: Epoch) -> [u8; 36] {
    let mut input = [0u8; 36];
    input[..32].copy_from_slice(&node.0);
    input[32..].copy_from_slice(&epoch.low32_be_bytes());
    input
}

/// Derive a node's cell coordinate deterministically from a VRF output (spec §L0):
/// `coord = MapToPoint(vrf_output)`.
#[must_use]
pub fn coordinate_from_vrf<F: Field>(vrf_output: &[u8; 32]) -> Point<F> {
    map_to_point::<F>(label::COORD, vrf_output)
}

/// Reference (non-VRF) coordinate derivation binding `(node, epoch)`, standing in for
/// `MapToPoint(VRF(pubkey, epoch))` until ECVRF is wired in. Deterministic and epoch-binding,
/// but **not** unforgeable — see the module note.
#[must_use]
pub fn coordinate_for<F: Field>(node: &NodeId, epoch: Epoch) -> Point<F> {
    let seed = hash_labeled(label::COORD, &coord_input(node, epoch));
    coordinate_from_vrf::<F>(&seed)
}

/// Derive a private rendezvous line from a shared secret and epoch (spec §5.6, §12.2):
/// `L_rdv = MapToLine(VRF(secret, epoch))`. Reference derivation, ECVRF in production.
#[must_use]
pub fn rendezvous_line<F: Field>(shared_secret: &[u8], epoch: Epoch) -> Line<F> {
    let mut input = Vec::with_capacity(shared_secret.len() + 4);
    input.extend_from_slice(shared_secret);
    input.extend_from_slice(&epoch.low32_be_bytes());
    map_to_line::<F>(label::RDV, &input)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::{F31, F256};
    use fanos_geometry::Point;

    #[test]
    fn coordinate_is_deterministic_per_epoch() {
        let node = NodeId([9u8; 32]);
        let c0 = coordinate_for::<F31>(&node, Epoch::ZERO);
        assert_eq!(c0, coordinate_for::<F31>(&node, Epoch::ZERO));
        // A genuine canonical point.
        assert_eq!(Point::<F31>::at(c0.index()), c0);
    }

    #[test]
    fn coordinate_reshuffles_across_epochs() {
        let node = NodeId([9u8; 32]);
        let c0 = coordinate_for::<F256>(&node, Epoch::ZERO);
        let c1 = coordinate_for::<F256>(&node, Epoch::new(1));
        // Overwhelmingly likely to differ (the epoch reshuffle, spec §L3).
        assert_ne!(c0, c1);
    }

    #[test]
    fn rendezvous_line_rotates_with_epoch() {
        let secret = b"shared-pake-output";
        let l0 = rendezvous_line::<F31>(secret, Epoch::ZERO);
        let l1 = rendezvous_line::<F31>(secret, Epoch::new(1));
        assert_ne!(l0, l1, "L_rdv rotates each epoch (spec §5.6)");
        // Both parties with the same secret+epoch derive the same line.
        assert_eq!(l0, rendezvous_line::<F31>(secret, Epoch::ZERO));
    }
}
