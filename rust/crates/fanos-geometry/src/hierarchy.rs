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

    /// The canonical wire bytes: `depth(1) ‖ depth × coord(12)` (each point's `[x:y:z]` big-endian).
    /// Compact and fixed-per-depth, so an address travels on the overlay wire like any coordinate.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.path.len() * 12);
        out.push(self.path.len() as u8);
        for p in &self.path {
            for w in p.coords() {
                out.extend_from_slice(&w.to_be_bytes());
            }
        }
        out
    }

    /// Decode the wire bytes written by [`encode`](Self::encode). `None` on a bad length, an
    /// out-of-range depth, or a non-canonical projective point (so a forged address cannot inject a
    /// bogus coordinate).
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&depth, rest) = bytes.split_first()?;
        let depth = depth as usize;
        if depth == 0 || depth > MAX_DEPTH || rest.len() != depth * 12 {
            return None;
        }
        let mut path = Vec::with_capacity(depth);
        let (coords, _) = rest.as_chunks::<12>();
        for coord in coords {
            let (quads, _) = coord.as_chunks::<4>();
            let mut w = [0u32; 3];
            for (slot, quad) in w.iter_mut().zip(quads) {
                *slot = u32::from_be_bytes(*quad);
            }
            path.push(Point::new(w)?);
        }
        Some(Self { path })
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

/// The greedy next hop toward `dst` from the node currently holding the message, given the addresses it
/// can reach this hop (`reachable` — its rendezvous-line members and cell peers): the reachable address
/// sharing the **longest** prefix with `dst`, provided that is strictly longer than what the current
/// holder `from` shares. Returns `None` when `from` already lies in `dst`'s cell (delivered) or nothing
/// reachable is closer. Repeating this delivers in `≤ dst.depth − commonPrefix(from,dst)` hops, because
/// the rendezvous guarantees `dst`'s next ancestor is reachable and each hop adds one shared level.
#[must_use]
pub fn next_hop<F: Field>(
    from: &HierAddr<F>,
    dst: &HierAddr<F>,
    reachable: &[HierAddr<F>],
) -> Option<HierAddr<F>> {
    let here = from.common_prefix(dst);
    if here == dst.depth() {
        return None; // already in the destination cell
    }
    reachable
        .iter()
        .filter(|n| n.common_prefix(dst) > here)
        .max_by_key(|n| n.common_prefix(dst))
        .cloned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
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
    fn rendezvous_is_symmetric_so_both_parties_meet_on_one_bus() {
        // The routing-agreement property: A→B and B→A resolve to the SAME level and the SAME line, so
        // both post to / listen on one bus (spec §L1). Without this, rendezvous routing could not meet.
        let a = HierAddr::from_path(alloc::vec![p(2), p(5)]).unwrap();
        let b = HierAddr::from_path(alloc::vec![p(2), p(6)]).unwrap();
        assert_eq!(rendezvous(&a, &b), rendezvous(&b, &a));
        let c = HierAddr::root(p(1));
        let d = HierAddr::from_path(alloc::vec![p(4), p(3)]).unwrap();
        assert_eq!(rendezvous(&c, &d), rendezvous(&d, &c));
    }

    #[test]
    fn rendezvous_routing_strictly_converges_toward_the_target() {
        // The routing-correctness core. H and D share level 0 and diverge at level 1. The rendezvous
        // meets on the line H[1]×D[1]; D's own point at that level lies ON that line, so a node in D's
        // sub-cell is reachable there — and it shares one MORE prefix level with D than H did. Repeating
        // this reaches D in ≤ D.depth hops (the O(k) rendezvous depth, spec §L1).
        let h = HierAddr::from_path(alloc::vec![p(2), p(5), p(1)]).unwrap();
        let d = HierAddr::from_path(alloc::vec![p(2), p(6), p(3)]).unwrap();
        let (level, line) = rendezvous(&h, &d).unwrap();
        assert_eq!(level, 1, "they diverge one level down");
        assert!(
            d.point_at(level).unwrap().is_on(&line),
            "D's divergence-level point is on the meeting bus — D's sub-cell is reachable there",
        );
        let reached = HierAddr::from_path(d.points()[..=level].to_vec()).unwrap();
        assert!(
            reached.common_prefix(&d) > h.common_prefix(&d),
            "each rendezvous hop shares one more prefix level with the target — strict convergence",
        );
    }

    #[test]
    fn recursive_rendezvous_delivers_across_a_multi_level_network() {
        // A prefix-closed network: each sub-cell has a root/gateway, so `dst`'s ancestor at every level
        // is present. A message walks the prefix chain — one rendezvous per level — and is delivered.
        let dst = HierAddr::from_path(alloc::vec![p(2), p(4), p(6)]).unwrap();
        let network = alloc::vec![
            HierAddr::root(p(1)),                                        // a far node, other top cell
            HierAddr::root(p(2)),                                        // dst's top-cell root  (cp 1)
            HierAddr::from_path(alloc::vec![p(2), p(4)]).unwrap(),       // dst's level-2 ancestor (cp 2)
            dst.clone(),                                                 // dst                    (cp 3)
        ];
        let mut current = HierAddr::root(p(1));
        let (mut hops, mut prev_cp) = (0usize, current.common_prefix(&dst));
        while current != dst {
            let cp = current.common_prefix(&dst);
            // The rendezvous from `current` reaches `dst`'s ancestor one level deeper — the members of
            // the meeting line share exactly `cp+1` levels with `dst`.
            let reachable: Vec<HierAddr<F2>> = network
                .iter()
                .filter(|n| n.common_prefix(&dst) == cp + 1)
                .cloned()
                .collect();
            let next = next_hop(&current, &dst, &reachable).expect("dst's next ancestor is reachable");
            assert!(next.common_prefix(&dst) > prev_cp, "strictly closer each hop");
            prev_cp = next.common_prefix(&dst);
            current = next;
            hops += 1;
            assert!(hops <= dst.depth(), "delivered within ≤ depth hops (O(k) rendezvous depth)");
        }
        assert_eq!(current, dst, "the message reached the destination across three cells");
        assert_eq!(hops, 3);
    }

    #[test]
    fn next_hop_is_none_once_in_the_destination_cell() {
        let dst = HierAddr::from_path(alloc::vec![p(2), p(4)]).unwrap();
        // A node already at dst's prefix (dst itself) has no closer hop.
        assert_eq!(next_hop(&dst, &dst, &[HierAddr::root(p(1))]), None);
    }

    #[test]
    fn address_wire_form_round_trips_and_rejects_junk() {
        for addr in [
            HierAddr::root(p(3)),
            HierAddr::from_path(alloc::vec![p(2), p(5)]).unwrap(),
            HierAddr::from_path(alloc::vec![p(0), p(6), p(1)]).unwrap(),
        ] {
            assert_eq!(HierAddr::<F2>::decode(&addr.encode()), Some(addr));
        }
        assert_eq!(HierAddr::<F2>::decode(&[]), None, "empty");
        assert_eq!(HierAddr::<F2>::decode(&[0]), None, "zero depth");
        assert_eq!(HierAddr::<F2>::decode(&[1, 0, 0, 0]), None, "truncated coord");
        assert_eq!(
            HierAddr::<F2>::decode(&[(MAX_DEPTH as u8) + 1]),
            None,
            "over-deep"
        );
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
