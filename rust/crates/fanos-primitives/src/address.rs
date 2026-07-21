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
use fanos_geometry::{HierAddr, Point, derive_address};

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

/// Derive a node's **live** hierarchical address by occupancy-driven descent (spec §L1, #95) — the
/// distributed, self-organizing counterpart to the static [`address_point`] chain. A node's level-0 point
/// is `own_point` (its live VRF transport coordinate under §A7, or its hash level-0 point); each deeper
/// level is the identity-hash sub-cell point [`address_point(own_id, level)`]. At each level, if a
/// **higher-priority already-seated member holds this exact position**, the node descends past it into its
/// own sub-cell point — priority being the strict total order on identity bytes (the numerically-smaller
/// `id` keeps the shallower seat). `seated` is the `(member_id, member_address)` set a node has learned
/// from `Announce`.
///
/// **Why this is conflict-free and needs no negotiation.** Every node runs the *same* pure function over
/// the *same* membership, and the priority is a strict total order, so of any set of identities contesting
/// a position exactly one — the minimum id — keeps it and the rest descend, recursively. No two nodes ever
/// converge on the same address; a non-colliding node keeps its depth-1 seat; and each deeper collision
/// requires an additional `id`-hash-point match (probability `≈ N^-level`), so the recursion terminates
/// well within [`HierAddr`]'s `MAX_DEPTH`. This is the missing *live* half of the hierarchy: `address_point`
/// gives the candidate chain, this resolves it against who is actually seated — so a cell of more than `N`
/// nodes self-organizes into sub-cells deterministically, the recursion-of-cells of §L1.
///
/// **Anti-eclipse.** Under VRF coordinates (§A7) `own_point` reshuffles every epoch, so which identities
/// share a level-0 point — hence the whole sub-cell membership — churns each epoch; an adversary cannot
/// pre-settle a deep position, and grinding a `k`-level prefix against a target still costs `≈ N^k`. The
/// deeper levels stay hash-derived (epoch-stable within a sub-cell), so no per-sub-cell beacon is needed.
#[must_use]
pub fn derive_hierarchical_address<F: Field>(
    own_id: &[u8],
    own_point: Point<F>,
    seated: &[(&[u8], HierAddr<F>)],
) -> HierAddr<F> {
    derive_address::<F>(
        |level| {
            if level == 0 {
                own_point
            } else {
                address_point::<F>(own_id, level)
            }
        },
        |path| {
            seated
                .iter()
                .any(|(mid, maddr)| *mid < own_id && maddr.points() == path)
        },
    )
    .unwrap_or_else(|| HierAddr::root(own_point))
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
    fn a_non_colliding_node_keeps_its_depth_one_seat() {
        let p = Point::<F2>::at(3);
        // No member is seated anywhere: the node keeps its own level-0 point.
        assert_eq!(
            derive_hierarchical_address::<F2>(b"solo", p, &[]),
            HierAddr::root(p),
        );
    }

    #[test]
    fn the_higher_priority_identity_keeps_the_seat_and_the_other_descends() {
        let p = Point::<F2>::at(2);
        let root = HierAddr::<F2>::root(p);
        // "aaa" < "bbb" numerically, so aaa has priority for the shallow seat.
        // bbb has learned aaa is seated at [p]; a higher-priority holder → bbb descends into its own point.
        let bbb = derive_hierarchical_address::<F2>(b"bbb", p, &[(b"aaa", root.clone())]);
        assert_eq!(
            bbb,
            root.descended(address_point::<F2>(b"bbb", 1)).unwrap(),
            "the lower-priority node descends into its own sub-cell point",
        );
        // aaa has (transiently) learned bbb at [p], but bbb does NOT outrank aaa → aaa keeps [p].
        let aaa = derive_hierarchical_address::<F2>(b"aaa", p, &[(b"bbb", root.clone())]);
        assert_eq!(aaa, root, "the higher-priority node keeps the shallow seat");
    }

    /// Converge a set of identities all contesting the same level-0 `point` to their fixed-point layout,
    /// by iterating the live derivation until no address changes (the distributed self-organization).
    fn converge(ids: &[&[u8]], point: Point<F2>) -> Vec<HierAddr<F2>> {
        let mut seats: Vec<HierAddr<F2>> = ids.iter().map(|_| HierAddr::root(point)).collect();
        for _ in 0..16 {
            let mut changed = false;
            for i in 0..ids.len() {
                let others: Vec<(&[u8], HierAddr<F2>)> = ids
                    .iter()
                    .zip(&seats)
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, (&id, a))| (id, a.clone()))
                    .collect();
                let a = derive_hierarchical_address::<F2>(ids[i], point, &others);
                if a != seats[i] {
                    seats[i] = a;
                    changed = true;
                }
            }
            if !changed {
                return seats;
            }
        }
        seats
    }

    #[test]
    fn a_cell_self_organizes_into_a_conflict_free_layout() {
        // Five identities all VRF'd to the same level-0 point (a sub-cell of five). Running the live
        // descent to convergence must give every node a DISTINCT address (no two collide), the
        // minimum-id node the shallow seat, and a bounded depth — the recursion-of-cells forming itself.
        let p = Point::<F2>::at(4);
        let ids: [&[u8]; 5] = [b"id-e", b"id-a", b"id-c", b"id-b", b"id-d"];
        let seats = converge(&ids, p);

        // No two nodes share an address.
        for i in 0..seats.len() {
            for j in (i + 1)..seats.len() {
                assert_ne!(seats[i], seats[j], "nodes {i} and {j} converged on the same address");
            }
        }
        // The minimum id ("id-a") holds the shallow seat [p]; everyone shares p as their level-0 point.
        let min_idx = ids.iter().enumerate().min_by_key(|(_, id)| **id).unwrap().0;
        assert_eq!(seats[min_idx], HierAddr::root(p), "the minimum-id node keeps the shallow seat");
        for (i, seat) in seats.iter().enumerate() {
            assert_eq!(seat.point_at(0), Some(p), "node {i} keeps the shared level-0 point");
            assert!(seat.depth() <= 3, "node {i} descent stays bounded (depth {})", seat.depth());
        }
    }

    #[test]
    fn the_layout_is_a_pure_function_of_membership_not_arrival_order() {
        // Determinism: converging the SAME identity set in a different presentation order yields the
        // identical layout — the self-organization has no race, so the cell is eventually consistent.
        let p = Point::<F2>::at(5);
        let a: [&[u8]; 4] = [b"w", b"x", b"y", b"z"];
        let b: [&[u8]; 4] = [b"z", b"y", b"x", b"w"];
        let sa = converge(&a, p);
        let sb = converge(&b, p);
        // Compare per-identity (reorder b's result back to a's order).
        for (i, id) in a.iter().enumerate() {
            let j = b.iter().position(|x| x == id).unwrap();
            assert_eq!(sa[i], sb[j], "identity {id:?} lands at the same address regardless of order");
        }
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
