//! L1 overlay routing: O(1) rendezvous, bridges, multipath, and content addressing.
//!
//! All of routing is algebra (spec §L1): to reach `u → v` both sides lie on the unique line
//! `L = u × v`, so rendezvous is a single field operation with **no search**; two buses meet
//! at the unique bridge node `L₁ × L₂`; a content key maps to a responsible point and its
//! replica lines. This module is the thin, named routing surface over [`fanos_geometry`].

use fanos_field::Field;
use fanos_geometry::{Line, Plane, Point};

use fanos_primitives::storage_point;

/// The **rendezvous line** `L = u × v` on which `u` and `v` can meet (spec §L1). Returns
/// `None` iff the two points are equal.
#[must_use]
pub fn rendezvous<F: Field>(u: &Point<F>, v: &Point<F>) -> Option<Line<F>> {
    u.join(v)
}

/// The **bridge** node `p = L₁ × L₂` between two buses — a deterministic, load-balanced
/// gateway (spec §L1). Returns `None` iff the two lines are equal.
#[must_use]
pub fn bridge<F: Field>(l1: &Line<F>, l2: &Line<F>) -> Option<Point<F>> {
    l1.meet(l2)
}

/// The `q + 1` near-disjoint paths available out of a node: its incident lines (spec §L2
/// multipath). Any two cells sharing a line get `q + 1` paths between them.
pub fn paths_out<F: Field>(node: &Point<F>) -> impl Iterator<Item = Line<F>> + Clone {
    Plane::<F>::lines_through(*node)
}

/// The point responsible for a content key: `target = MapToPoint(H_storage(key))` (spec §L4). Uses the
/// **storage** domain label, matching the running engine's `address_of` and the canonical conformance
/// vector (`conformance/vectors/services.json`) — NOT the `coord` (node-placement) domain. Keying this
/// on `label::COORD` was an audit bug (C7): a value stored by the engine (storage domain) and located by
/// this function (coord domain) hashed to *different* points, so the lookup silently missed. Delegates to
/// the single source of truth [`fanos_primitives::storage_point`], so the domain can never drift again.
#[must_use]
pub fn content_address<F: Field>(key: &[u8]) -> Point<F> {
    storage_point::<F>(key)
}

/// The `q + 1` replica lines that erasure-code a target point's data (spec §L4 projective
/// LRC): the lines through the target.
///
/// These lines are the store's **Maekawa quorums** (spec §L4, line-364 "quorum consistency [T]"): any two
/// distinct lines meet in exactly one point (the dual Steiner property, verified exhaustively by
/// `fanos_geometry`'s `dual_any_two_lines_intersect`), so a write-line `W` and a read-line `R` always
/// satisfy `W ∩ R ≠ ∅`. The overlay realizes the resulting linearisability *more strongly* than a bare
/// line-quorum: a write erasure-codes across **all** shard homes and a read fans out to **all** of them,
/// grouping by write-version and reconstructing the highest recoverable one — a full-set read that is a
/// superset of any line-quorum, so it trivially intersects every write while also giving LRC durability
/// (a bare 3-point line could not: `[7,3,4]` needs 4 shards to reconstruct). Strict *multi-writer*
/// linearisability (quorum locking) is deliberately not added: store keys are single-writer (a service
/// publishes its own descriptor, a node its own key), so last-writer-wins-by-version is the right,
/// lock-free consistency, verified by the `fanos-sim` storage suite.
pub fn replica_lines<F: Field>(target: &Point<F>) -> impl Iterator<Item = Line<F>> + Clone {
    Plane::<F>::lines_through(*target)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::{F7, F31};
    use fanos_geometry::Plane;
    use fanos_primitives::hash::label;
    use fanos_primitives::map_to_point;

    #[test]
    fn rendezvous_puts_both_endpoints_on_the_line() {
        let u = Point::<F7>::new([1, 2, 3]).unwrap();
        let v = Point::<F7>::new([3, 1, 4]).unwrap();
        let l = rendezvous(&u, &v).unwrap();
        assert!(u.is_on(&l) && v.is_on(&l));
        // Rendezvous is symmetric.
        assert_eq!(l, rendezvous(&v, &u).unwrap());
    }

    #[test]
    fn bridge_is_the_shared_gateway() {
        // Two lines through a common point bridge back to that point.
        let p = Point::<F7>::new([1, 0, 0]).unwrap();
        let mut lines = Plane::<F7>::lines_through(p);
        let l1 = lines.next().unwrap();
        let l2 = lines.next().unwrap();
        assert_eq!(bridge(&l1, &l2).unwrap(), p);
    }

    #[test]
    fn multipath_offers_q_plus_one_paths() {
        let node = Point::<F31>::new([1, 5, 9]).unwrap();
        assert_eq!(paths_out(&node).count() as u32, Plane::<F31>::LINE_SIZE);
    }

    #[test]
    fn content_key_has_q_plus_one_replica_lines() {
        let target = content_address::<F7>(b"my-resource-key");
        assert_eq!(
            replica_lines(&target).count() as u32,
            Plane::<F7>::LINE_SIZE
        );
        // Deterministic addressing.
        assert_eq!(target, content_address::<F7>(b"my-resource-key"));
    }

    #[test]
    fn content_address_uses_the_storage_domain_matching_the_engine() {
        // Audit C7: content addressing must resolve in the STORAGE domain (the engine's `address_of`
        // and the canonical conformance vector), NOT the COORD (node-placement) domain — else a stored
        // value and its lookup hash to different points and the read silently misses.
        let key = b"a-key";
        assert_eq!(
            content_address::<F31>(key),
            map_to_point::<F31>(label::STORAGE, key),
            "content address is in the storage domain"
        );
        assert_ne!(
            content_address::<F31>(key),
            map_to_point::<F31>(label::COORD, key),
            "and is NOT the (distinct) coord domain — the bug this guards against"
        );
    }
}
