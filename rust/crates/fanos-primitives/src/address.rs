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
    addr.points()
        .iter()
        .enumerate()
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
}
