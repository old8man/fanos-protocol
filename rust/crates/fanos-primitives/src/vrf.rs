//! The VRF surface for epoch-bound coordinate assignment (spec §L0, §L3).
//!
//! A node's coordinate is `MapToPoint(VRF(pubkey, epoch))`: the VRF binds the coordinate to
//! the epoch (so it reshuffles when the beacon advances) and is verifiable and not cheaply
//! grindable. The production instantiation is **ECVRF-Edwards25519** (RFC 9381), which needs
//! elliptic-curve crypto and is therefore pluggable behind the [`Vrf`] trait.
//!
//! This module exposes the trait plus a *deterministic* coordinate derivation that binds
//! `(bundle, epoch)` exactly as production does, so no_std addressing is testable end to end. It
//! has no keyed proof and so is not unforgeable on its own. The **real, verifiable** VRF lives in
//! [`fanos-vrf`](https://docs.rs/fanos-vrf): a ristretto255 RFC 9381-style VRF whose
//! `prove_coordinate` / `verify_coordinate` give an unforgeable, self-certifying coordinate — a
//! node proves its epoch position from its key, checkable by anyone without the secret. Use that
//! where the anti-grinding guarantees of §3.2 must hold; this hash form is the no_std reference.

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::{Line, Point};

use crate::hash::{hash_labeled, label};
use crate::keys::NodeId;
use crate::maptopoint::{map_to_line, map_to_point};

/// A verifiable random function (spec §L6, ECVRF-Edwards25519 in production).
pub trait Vrf {
    /// The proof accompanying an output.
    type Proof;
    /// The secret key type.
    type SecretKey;
    /// The public key type.
    type PublicKey;

    /// Produce the VRF output and its proof for `input`.
    fn prove(sk: &Self::SecretKey, input: &[u8]) -> ([u8; 32], Self::Proof);
    /// Verify that `output` is the correct VRF value of `input` under `pk`.
    fn verify(pk: &Self::PublicKey, input: &[u8], output: &[u8; 32], proof: &Self::Proof) -> bool;
}

/// The VRF input for coordinate assignment: the node's identity bound to an epoch.
#[must_use]
pub fn coord_input(node: &NodeId, epoch: u32) -> [u8; 36] {
    let mut input = [0u8; 36];
    input[..32].copy_from_slice(&node.0);
    input[32..].copy_from_slice(&epoch.to_be_bytes());
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
pub fn coordinate_for<F: Field>(node: &NodeId, epoch: u32) -> Point<F> {
    let seed = hash_labeled(label::COORD, &coord_input(node, epoch));
    coordinate_from_vrf::<F>(&seed)
}

/// Derive a private rendezvous line from a shared secret and epoch (spec §5.6, §12.2):
/// `L_rdv = MapToLine(VRF(secret, epoch))`. Reference derivation, ECVRF in production.
#[must_use]
pub fn rendezvous_line<F: Field>(shared_secret: &[u8], epoch: u32) -> Line<F> {
    let mut input = Vec::with_capacity(shared_secret.len() + 4);
    input.extend_from_slice(shared_secret);
    input.extend_from_slice(&epoch.to_be_bytes());
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
        let c0 = coordinate_for::<F31>(&node, 0);
        assert_eq!(c0, coordinate_for::<F31>(&node, 0));
        // A genuine canonical point.
        assert_eq!(Point::<F31>::at(c0.index()), c0);
    }

    #[test]
    fn coordinate_reshuffles_across_epochs() {
        let node = NodeId([9u8; 32]);
        let c0 = coordinate_for::<F256>(&node, 0);
        let c1 = coordinate_for::<F256>(&node, 1);
        // Overwhelmingly likely to differ (the epoch reshuffle, spec §L3).
        assert_ne!(c0, c1);
    }

    #[test]
    fn rendezvous_line_rotates_with_epoch() {
        let secret = b"shared-pake-output";
        let l0 = rendezvous_line::<F31>(secret, 0);
        let l1 = rendezvous_line::<F31>(secret, 1);
        assert_ne!(l0, l1, "L_rdv rotates each epoch (spec §5.6)");
        // Both parties with the same secret+epoch derive the same line.
        assert_eq!(l0, rendezvous_line::<F31>(secret, 0));
    }
}
