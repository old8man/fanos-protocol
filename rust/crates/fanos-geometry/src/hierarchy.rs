//! Hierarchical addressing — the **recursion of cells** that scales FANOS past one plane (spec §L1).
//!
//! One projective plane `PG(2,q)` holds `N = q²+q+1` nodes; the collinearity graph is complete, so in a
//! single cell every node structurally sees every other. Internet scale comes from *nesting*: each point
//! of a coarse cell is itself the root of a finer cell, so a node's address is a **path of points** from
//! the top cell down. Depth `k` gives `≈ N^k` nodes with `O(k)` state and `O(k)` rendezvous depth
//! (Kademlia-class asymptotics), while every level keeps the projective guarantees — O(1) rendezvous per
//! level, guaranteed quorum intersection, the structural centrality cap.
//!
//! A node normally lives at depth 1 (a plain single-plane coordinate). It **descends** a level only on a
//! collision: two identities whose `MapToPoint(H(cert))` lands on the same point cannot both occupy it
//! (one would shadow the other and break routing, §L0), so the later arrival takes a coordinate in the
//! sub-cell rooted at that point — deterministically, from its own identity. This module is the pure
//! geometry of that scheme (addresses, descent, the recursive rendezvous meet); the per-level point
//! derivation (`MapToPoint`) and the occupancy oracle are injected by the caller, so the mechanism is
//! testable without any crypto or network.

use alloc::vec::Vec;

use fanos_field::Field;

use crate::plane::{Line, Point};

/// The maximum descent depth. Collisions at each level occur with probability `1/N`, so the address
/// depth of `M` nodes is `≈ log_N M` — a handful of levels covers any realistic network (`q=31, k=3`
/// ⇒ ~10⁹ nodes). The cap bounds per-node state and makes [`derive_address`] total: a run of `MAX_DEPTH`
/// consecutive collisions (probability `N^-MAX_DEPTH`) is astronomically unlikely and fails closed.
pub const MAX_DEPTH: usize = 8;

/// A hierarchical node address: a non-empty path of projective points, coarsest first. `path[0]` is the
/// node's point in the top cell; `path[i]` is its point in the sub-cell rooted at `path[i-1]`. Depth 1
/// is an ordinary single-plane coordinate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HierAddr<F: Field> {
    path: Vec<Point<F>>,
}

impl<F: Field> HierAddr<F> {
    /// A depth-1 address at the top-cell point `p`.
    #[must_use]
    pub fn root(p: Point<F>) -> Self {
        Self { path: alloc::vec![p] }
    }

    /// Build from a path of points (coarsest first). `None` if empty or deeper than [`MAX_DEPTH`].
    #[must_use]
    pub fn from_path(path: Vec<Point<F>>) -> Option<Self> {
        if path.is_empty() || path.len() > MAX_DEPTH {
            return None;
        }
        Some(Self { path })
    }

    /// The number of levels (≥ 1).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// The point at `level` (coarsest = 0), or `None` past the address's depth.
    #[must_use]
    pub fn point_at(&self, level: usize) -> Option<Point<F>> {
        self.path.get(level).copied()
    }

    /// The full point path, coarsest first.
    #[must_use]
    pub fn points(&self) -> &[Point<F>] {
        &self.path
    }

    /// This address with one more level appended (a descent into the sub-cell at its current tail).
    /// `None` if already at [`MAX_DEPTH`].
    #[must_use]
    pub fn descended(&self, sub: Point<F>) -> Option<Self> {
        if self.path.len() >= MAX_DEPTH {
            return None;
        }
        let mut path = self.path.clone();
        path.push(sub);
        Some(Self { path })
    }

    /// The number of leading levels this address shares with `other`.
    #[must_use]
    pub fn common_prefix(&self, other: &Self) -> usize {
        self.path
            .iter()
            .zip(other.path.iter())
            .take_while(|(a, b)| a == b)
            .count()
    }

    /// Whether `self`'s path is a prefix of `other`'s — i.e. `self` names an ancestor cell of `other`
    /// (or equals it). Reaching a descendant is a pure downward walk, not a cross-cell rendezvous.
    #[must_use]
    pub fn is_ancestor_of(&self, other: &Self) -> bool {
        self.path.len() <= other.path.len() && self.common_prefix(other) == self.path.len()
    }
}

/// Derive a node's address by **sub-cell descent**. At each level the node's candidate point is
/// `point(level)` (in production, `MapToPoint(H(cert ‖ level))`); the node keeps the shortest prefix
/// that `occupied` reports free. So a node that does not collide gets a depth-1 address, and one that
/// collides at the top takes a sub-cell coordinate derived from its own identity — never shadowing the
/// occupant. `None` only if [`MAX_DEPTH`] consecutive levels all collide (probability `N^-MAX_DEPTH`).
pub fn derive_address<F: Field>(
    point: impl Fn(usize) -> Point<F>,
    occupied: impl Fn(&[Point<F>]) -> bool,
) -> Option<HierAddr<F>> {
    let mut path: Vec<Point<F>> = Vec::with_capacity(MAX_DEPTH);
    for level in 0..MAX_DEPTH {
        path.push(point(level));
        if !occupied(&path) {
            return Some(HierAddr { path });
        }
    }
    None
}

/// The **rendezvous meet** of two addresses: the coarsest level at which they diverge and the unique
/// line to meet on there — the two points' join, the O(1) projective rendezvous (spec §L1), applied at
/// the first differing level of the recursion. `None` when one address is a prefix of the other (an
/// ancestor/descendant pair — reached by descent, with no cross-line meet).
#[must_use]
pub fn rendezvous<F: Field>(a: &HierAddr<F>, b: &HierAddr<F>) -> Option<(usize, Line<F>)> {
    a.path
        .iter()
        .zip(b.path.iter())
        .enumerate()
        .find(|(_, (pa, pb))| pa != pb)
        .and_then(|(level, (pa, pb))| pa.join(pb).map(|line| (level, line)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::F2;

    fn p(i: usize) -> Point<F2> {
        Point::<F2>::at(i)
    }

    #[test]
    fn a_non_colliding_node_stays_at_depth_one() {
        // Point 3 is free ⇒ the node keeps a plain single-plane address.
        let addr = derive_address(|_| p(3), |path| path != [p(3)]).unwrap();
        assert_eq!(addr.depth(), 1);
        assert_eq!(addr.point_at(0), Some(p(3)));
    }

    #[test]
    fn a_collision_descends_into_the_sub_cell() {
        // Point 3 is taken at the top; the newcomer's level-1 point is 5. It descends to [3,5].
        let occupied = |path: &[Point<F2>]| path == [p(3)]; // only the depth-1 [3] is occupied
        let level_point = |level: usize| if level == 0 { p(3) } else { p(5) };
        let addr = derive_address(level_point, occupied).unwrap();
        assert_eq!(addr.depth(), 2, "the colliding node descends one level");
        assert_eq!(addr.points(), &[p(3), p(5)]);
        // It does NOT shadow the occupant: its address differs from the depth-1 [3].
        assert_ne!(addr, HierAddr::root(p(3)));
    }

    #[test]
    fn distinct_identities_get_distinct_addresses_even_under_collision() {
        // Two nodes both derive point 2 at the top (a collision), but different sub-points.
        let occupant = HierAddr::root(p(2));
        let mut taken = alloc::vec![occupant.clone()];
        let is_taken = |path: &[Point<F2>], taken: &[HierAddr<F2>]| {
            taken.iter().any(|a| a.points() == path)
        };
        // Newcomer A: top 2 (taken) → sub 4.
        let a = derive_address(
            |l| if l == 0 { p(2) } else { p(4) },
            |path| is_taken(path, &taken),
        )
        .unwrap();
        taken.push(a.clone());
        // Newcomer B: top 2 (taken) → sub 4 (now taken by A) → sub-sub 1.
        let b = derive_address(
            |l| match l {
                0 => p(2),
                1 => p(4),
                _ => p(1),
            },
            |path| is_taken(path, &taken),
        )
        .unwrap();
        assert_ne!(a, b, "distinct identities never share an address");
        assert_ne!(a, occupant);
        assert_eq!(a.depth(), 2, "A took [2,4]");
        assert_eq!(b.depth(), 3, "B descended past A's [2,4] to [2,4,1]");
    }

    #[test]
    fn rendezvous_meets_on_the_join_line_at_the_first_divergence() {
        // Two depth-1 addresses meet on the line through their points (O(1), spec §L1).
        let a = HierAddr::root(p(1));
        let b = HierAddr::root(p(4));
        let (level, line) = rendezvous(&a, &b).unwrap();
        assert_eq!(level, 0);
        assert_eq!(line, p(1).join(&p(4)).unwrap());
    }

    #[test]
    fn rendezvous_descends_when_a_prefix_is_shared() {
        // [3,5] and [3,6] share the top cell 3; they meet inside it, at level 1, on 5×6.
        let a = HierAddr::from_path(alloc::vec![p(3), p(5)]).unwrap();
        let b = HierAddr::from_path(alloc::vec![p(3), p(6)]).unwrap();
        let (level, line) = rendezvous(&a, &b).unwrap();
        assert_eq!(level, 1, "they diverge one level down");
        assert_eq!(line, p(5).join(&p(6)).unwrap());
    }

    #[test]
    fn an_ancestor_has_no_cross_line_meet() {
        // [3] is an ancestor of [3,5]: reaching the descendant is a downward walk, not a rendezvous.
        let ancestor = HierAddr::root(p(3));
        let descendant = HierAddr::from_path(alloc::vec![p(3), p(5)]).unwrap();
        assert!(ancestor.is_ancestor_of(&descendant));
        assert_eq!(rendezvous(&ancestor, &descendant), None);
    }
}
