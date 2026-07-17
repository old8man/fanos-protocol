//! L1 overlay routing: O(1) rendezvous, bridges, multipath, and content addressing.
//!
//! All of routing is algebra (spec §L1): to reach `u → v` both sides lie on the unique line
//! `L = u × v`, so rendezvous is a single field operation with **no search**; two buses meet
//! at the unique bridge node `L₁ × L₂`; a content key maps to a responsible point and its
//! replica lines. This module is the thin, named routing surface over [`fanos_geometry`].

use fanos_field::Field;
use fanos_geometry::{Line, Plane, Point};

use fanos_crypto::hash::label;
use fanos_crypto::map_to_point;

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

/// The point responsible for a content key: `target = MapToPoint(H(key))` (spec §L0/§L4).
#[must_use]
pub fn content_address<F: Field>(key: &[u8]) -> Point<F> {
    map_to_point::<F>(label::COORD, key)
}

/// The `q + 1` replica lines that erasure-code a target point's data (spec §L4 projective
/// LRC): the lines through the target.
pub fn replica_lines<F: Field>(target: &Point<F>) -> impl Iterator<Item = Line<F>> + Clone {
    Plane::<F>::lines_through(*target)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::{F7, F31};
    use fanos_geometry::Plane;

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
}
