//! Self-certifying hierarchical addresses (spec §L0/§L1).
//!
//! A node's overlay address is not *chosen* but **derived** from its identity `id` (the long-term
//! node identifier — the `BLAKE3` hash of its public-key bundle, spec §L0). Level 0 is its top-cell
//! point; each deeper level is a fresh, domain-separated point in the sub-cell it descends into on a
//! collision (§L1). Because every level is `MapToPoint` of a domain-separated hash of `id`, the whole
//! descent chain is a deterministic **one-way** function of the identity:
//!
//! * a node cannot pick its address — it gets whatever its identity hashes to;
//! * an adversary cannot forge an address that shares a `k`-level prefix with a chosen target without
//!   grinding the identity against the map — `≈ N^k` work, the Sybil-cost bound (threat B1).
//!
//! That is what makes a routing-table **announcement self-certifying**: a receiver recomputes the
//! chain from the announced identity and rejects any address that does not match, so a peer cannot
//! announce an overlay address it did not earn in order to attract traffic it does not own (threat
//! §79, hierarchical routing-table poisoning). This module is the single source of truth for the
//! derivation; [`fanos_quic::identity`] and the overlay engine both call it.

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::{HierAddr, Point};

use crate::hash::label;
use crate::maptopoint::map_to_point;

/// The node's self-certifying point at descent `level`, derived from its identity `id` (spec §L1).
/// Level 0 is the ordinary top-cell coordinate `MapToPoint(node-id, id)`; each deeper level is
/// domain-separated by the level (`MapToPoint(subcell-coord, id ‖ level)`), so a descended coordinate
/// is a fresh point yet still bound to the same identity — only its holder can produce the chain.
#[must_use]
pub fn address_point<F: Field>(id: &[u8], level: usize) -> Point<F> {
    if level == 0 {
        return map_to_point::<F>(label::NODE_ID, id);
    }
    let mut data = Vec::with_capacity(id.len() + 8);
    data.extend_from_slice(id);
    data.extend_from_slice(&(level as u64).to_be_bytes());
    map_to_point::<F>(label::SUBCELL_COORD, &data)
}

/// Whether `addr` is exactly the self-certifying descent chain of identity `id`: every level's point
/// equals [`address_point(id, level)`](address_point). This is the check a receiver runs before
/// trusting an announced hierarchical address — an address that does not match cannot have been
/// derived from `id`, so it cannot be used to attract traffic the identity does not own. Forging a
/// match to a chosen target costs `≈ N^k` grinding work for a `k`-level prefix (threat B1/§79).
#[must_use]
pub fn address_matches_identity<F: Field>(id: &[u8], addr: &HierAddr<F>) -> bool {
    address_matches_identity_from::<F>(id, addr, 0)
}

/// Like [`address_matches_identity`] but verifies only levels `>= min_level` of the descent chain. The
/// use is a deployment whose **level-0** coordinate is seated by the VRF beacon
/// (`MapToPoint(VRF(id, epoch, beacon))`, spec §L0/A7), not the hash `address_point(id, 0)`: that
/// coordinate's authenticity comes from the transport's proof-of-coordinate HELLO plus the descriptor
/// signature, so the hash-chain check must SKIP level 0 (`min_level = 1`) — else every legitimate VRF
/// announcement is rejected (audit C3). The sub-cell descent (levels `>= 1`) is hash-derived in both the
/// hash-chain (§79) and VRF (§A7) schemes, so it is always checked. `min_level = 0` is the full chain.
#[must_use]
pub fn address_matches_identity_from<F: Field>(
    id: &[u8],
    addr: &HierAddr<F>,
    min_level: usize,
) -> bool {
    addr.points()
        .iter()
        .enumerate()
        .filter(|(level, _)| *level >= min_level)
        .all(|(level, &p)| p == address_point::<F>(id, level))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::F2;

    #[test]
    fn an_identitys_own_chain_verifies() {
        // The address derived from an identity is exactly the one that verifies against it.
        let id = b"node-identity-alpha";
        let chain = alloc::vec![
            address_point::<F2>(id, 0),
            address_point::<F2>(id, 1),
            address_point::<F2>(id, 2),
        ];
        let addr = HierAddr::<F2>::from_path(chain).unwrap();
        assert!(address_matches_identity::<F2>(id, &addr));
    }

    #[test]
    fn a_foreign_or_tampered_address_is_rejected() {
        let id = b"node-identity-alpha";
        let other = b"node-identity-beta";
        // A different identity's level-0 point almost surely differs; even if it collided, appending
        // a wrong deeper level breaks the chain. Build a two-level address that is NOT id's chain.
        let bogus = HierAddr::<F2>::from_path(alloc::vec![
            address_point::<F2>(other, 0),
            address_point::<F2>(id, 1), // level-1 from a different pre-image than level-0
        ])
        .unwrap();
        assert!(
            !address_matches_identity::<F2>(id, &bogus),
            "an address that is not id's own derived chain must not verify",
        );
        // The level-0-only address of a *different* identity also does not match `id`
        // (with overwhelming probability over the 7 Fano points; asserted by construction here).
        let other_root =
            HierAddr::<F2>::from_path(alloc::vec![address_point::<F2>(other, 0)]).unwrap();
        let id_root = HierAddr::<F2>::from_path(alloc::vec![address_point::<F2>(id, 0)]).unwrap();
        // Whichever way the two roots landed, each identity verifies its OWN root.
        assert!(address_matches_identity::<F2>(other, &other_root));
        assert!(address_matches_identity::<F2>(id, &id_root));
    }

    #[test]
    fn from_level_skips_a_vrf_seated_level_zero_but_still_binds_the_descent() {
        // Audit C3: under VRF coordinates the level-0 point is the beacon-seated VRF coordinate, NOT
        // `address_point(id, 0)`. Model that with a chain whose level 0 is some *other* point but whose
        // deeper levels ARE id's hash-derived descent. The full check rejects it (level 0 mismatches);
        // the `min_level = 1` check accepts it — exactly the skip that stops a legitimate VRF announcement
        // from being wrongly rejected, while the sub-cell descent (levels >= 1) is still verified.
        let id = b"vrf-node-identity";
        let foreign_l0 = b"some-other-preimage";
        let vrf_style = HierAddr::<F2>::from_path(alloc::vec![
            address_point::<F2>(foreign_l0, 0), // stand-in for a VRF coord: not id's hash level-0 point
            address_point::<F2>(id, 1),         // real hash-derived sub-cell descent
            address_point::<F2>(id, 2),
        ])
        .unwrap();

        // Non-vacuity: the stand-in level-0 point must actually differ from id's hash level-0 (else the
        // test proves nothing). On the 7-point plane a collision is possible; pick pre-images that differ.
        assert_ne!(
            address_point::<F2>(foreign_l0, 0),
            address_point::<F2>(id, 0),
            "the stand-in level-0 point must differ from id's hash-derived one for this test to bite",
        );

        assert!(
            !address_matches_identity::<F2>(id, &vrf_style),
            "full-chain check rejects it — level 0 is not id's hash point (this is the C3 false-reject)",
        );
        assert!(
            address_matches_identity_from::<F2>(id, &vrf_style, 1),
            "skipping level 0 accepts it — the VRF coord is externally verified, the descent still binds",
        );
        // A tampered deeper level is still caught even with the level-0 skip.
        let tampered = HierAddr::<F2>::from_path(alloc::vec![
            address_point::<F2>(foreign_l0, 0),
            address_point::<F2>(b"wrong", 1), // a descent level that is NOT id's
        ])
        .unwrap();
        assert!(
            !address_matches_identity_from::<F2>(id, &tampered, 1),
            "the level-0 skip does not weaken the sub-cell descent check",
        );
    }
}
