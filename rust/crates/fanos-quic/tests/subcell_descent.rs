//! **Coordinate-collision relocation by sub-cell descent** (§L0/§L1). This exercises the *hierarchical
//! address* — the #79 self-certifying hash-chain `address_point(cert, level)` — which is a **distinct**
//! addressing scheme from a node's live VRF coordinate: the hierarchy address is a proof-free one-way
//! hash of the identity (so the no_std overlay verifies an announced address by recomputation), whereas
//! the live coordinate is the VRF `MapToPoint(VRF(sk, …))` proven in the handshake (A7). Two distinct
//! identities collide on one Fano point of the hash-chain address with probability `1/N`; they cannot
//! both occupy it, so the newcomer **descends** into the sub-cell rooted at that point, taking a deeper
//! point it derives from its *own* certificate (never the occupant's). Unifying the hierarchy under the
//! VRF (a VRF-seeded descent with proof-carrying #79 verification) is Level B — see
//! `docs/design-coordinates.md`; here we test the hash-chain descent mechanism on its own terms, so the
//! test grinds the hash-chain level-0 coordinate rather than the VRF one.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use fanos_field::F2;
use fanos_geometry::{HierAddr, Point, Triple};
use fanos_quic::{
    NodeCredentials, coordinate_at_level, coordinate_from_cert, hierarchical_coordinate,
};

/// Grind a genuine self-certifying identity whose **hash-chain level-0** coordinate
/// `coordinate_from_cert` is exactly `target` — the addressing scheme the hierarchy descent uses (the
/// harness `credentials_for_point` grinds the VRF coordinate instead, a different point). Tractable only
/// because `N = 7`.
fn grind_hash_point(target: Point<F2>) -> NodeCredentials {
    loop {
        let c = NodeCredentials::generate().expect("mint credentials");
        if coordinate_from_cert::<F2>(c.cert_der()) == target {
            return c;
        }
    }
}

/// The occupancy oracle over a set of taken hierarchical addresses (each a point path).
fn occupied(taken: &BTreeSet<Vec<Triple>>, path: &[Point<F2>]) -> bool {
    let key: Vec<Triple> = path.iter().map(Point::coords).collect();
    taken.contains(&key)
}

fn key_of(addr: &HierAddr<F2>) -> Vec<Triple> {
    addr.points().iter().map(Point::coords).collect()
}

#[test]
fn a_colliding_newcomer_descends_into_a_sub_cell_rather_than_shadowing() {
    // Grind two DISTINCT certificates that both hash to the same Fano point 3 — a real coordinate
    // collision (tractable only because N = 7; the whole point of the self-certifying design).
    let target = Point::<F2>::at(3);
    let occupant_cred = grind_hash_point(target);
    let newcomer_cred = loop {
        let c = grind_hash_point(target);
        if c.cert_der() != occupant_cred.cert_der() {
            break c; // a genuinely different identity on the same point
        }
    };

    let mut taken: BTreeSet<Vec<Triple>> = BTreeSet::new();

    // The occupant arrives first: no collision, a depth-1 address at point 3.
    let occupant = hierarchical_coordinate::<F2>(occupant_cred.cert_der(), |p| occupied(&taken, p))
        .expect("occupant address");
    assert_eq!(
        occupant.depth(),
        1,
        "the first arrival keeps a plain coordinate"
    );
    assert_eq!(occupant.point_at(0), Some(target));
    taken.insert(key_of(&occupant));

    // The newcomer collides at point 3 and must descend.
    let newcomer = hierarchical_coordinate::<F2>(newcomer_cred.cert_der(), |p| occupied(&taken, p))
        .expect("newcomer address");
    assert!(
        newcomer.depth() >= 2,
        "the colliding newcomer descends into a sub-cell"
    );
    assert_eq!(
        newcomer.point_at(0),
        Some(target),
        "it still roots at the collided top point"
    );
    assert_ne!(
        newcomer, occupant,
        "it does NOT shadow the occupant's binding"
    );

    // The descended point is the newcomer's own, earned from its certificate — not the occupant's.
    assert_eq!(
        newcomer.point_at(1),
        Some(coordinate_at_level::<F2>(newcomer_cred.cert_der(), 1)),
        "the sub-cell point is derived from the newcomer's cert",
    );
}

#[test]
fn level_zero_matches_the_ordinary_coordinate_and_levels_diverge() {
    let cred = grind_hash_point(Point::<F2>::at(5));
    // Level 0 is exactly the ordinary hash-chain self-certifying coordinate.
    assert_eq!(
        coordinate_at_level::<F2>(cred.cert_der(), 0),
        coordinate_from_cert::<F2>(cred.cert_der()),
    );
    // The descent chain is deterministic (same cert ⇒ same points) and the levels are independent
    // draws, so a node's own path does not trivially repeat one point.
    let l1 = coordinate_at_level::<F2>(cred.cert_der(), 1);
    let l2 = coordinate_at_level::<F2>(cred.cert_der(), 2);
    assert_eq!(
        l1,
        coordinate_at_level::<F2>(cred.cert_der(), 1),
        "deterministic per level"
    );
    // (l1 and l2 may coincide by chance at 1/N; assert only determinism, not distinctness, here.)
    let _ = l2;
}
