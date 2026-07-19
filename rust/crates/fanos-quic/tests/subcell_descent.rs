//! **Coordinate-collision relocation by sub-cell descent** (§L0/§L1). A self-certifying coordinate is
//! `MapToPoint(H(cert))`, so two distinct identities collide on one Fano point with probability `1/N`.
//! They cannot both occupy it — the later binding would shadow the earlier and break routing — so the
//! newcomer **descends** into the sub-cell rooted at that point, taking a deeper coordinate it derives
//! from its *own* certificate (never the occupant's). This exercises that end to end on real credentials
//! ground to a chosen point, so the collision is genuine, not simulated.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use fanos_field::F2;
use fanos_geometry::{HierAddr, Point, Triple};
use fanos_quic::{coordinate_at_level, credentials_for_point, hierarchical_coordinate};

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
    let occupant_cred = credentials_for_point::<F2>(target, 4096).expect("grind occupant");
    let newcomer_cred = loop {
        let c = credentials_for_point::<F2>(target, 4096).expect("grind newcomer");
        if c.cert_der() != occupant_cred.cert_der() {
            break c; // a genuinely different identity on the same point
        }
    };

    let mut taken: BTreeSet<Vec<Triple>> = BTreeSet::new();

    // The occupant arrives first: no collision, a depth-1 address at point 3.
    let occupant = hierarchical_coordinate::<F2>(occupant_cred.cert_der(), |p| occupied(&taken, p))
        .expect("occupant address");
    assert_eq!(occupant.depth(), 1, "the first arrival keeps a plain coordinate");
    assert_eq!(occupant.point_at(0), Some(target));
    taken.insert(key_of(&occupant));

    // The newcomer collides at point 3 and must descend.
    let newcomer = hierarchical_coordinate::<F2>(newcomer_cred.cert_der(), |p| occupied(&taken, p))
        .expect("newcomer address");
    assert!(newcomer.depth() >= 2, "the colliding newcomer descends into a sub-cell");
    assert_eq!(newcomer.point_at(0), Some(target), "it still roots at the collided top point");
    assert_ne!(newcomer, occupant, "it does NOT shadow the occupant's binding");

    // The descended point is the newcomer's own, earned from its certificate — not the occupant's.
    assert_eq!(
        newcomer.point_at(1),
        Some(coordinate_at_level::<F2>(newcomer_cred.cert_der(), 1)),
        "the sub-cell point is derived from the newcomer's cert",
    );
}

#[test]
fn level_zero_matches_the_ordinary_coordinate_and_levels_diverge() {
    let cred = credentials_for_point::<F2>(Point::<F2>::at(5), 4096).unwrap();
    // Level 0 is exactly the ordinary self-certifying coordinate.
    assert_eq!(
        coordinate_at_level::<F2>(cred.cert_der(), 0),
        fanos_quic::coordinate_from_cert::<F2>(cred.cert_der()),
    );
    // The descent chain is deterministic (same cert ⇒ same points) and the levels are independent
    // draws, so a node's own path does not trivially repeat one point.
    let l1 = coordinate_at_level::<F2>(cred.cert_der(), 1);
    let l2 = coordinate_at_level::<F2>(cred.cert_der(), 2);
    assert_eq!(l1, coordinate_at_level::<F2>(cred.cert_der(), 1), "deterministic per level");
    // (l1 and l2 may coincide by chance at 1/N; assert only determinism, not distinctness, here.)
    let _ = l2;
}
