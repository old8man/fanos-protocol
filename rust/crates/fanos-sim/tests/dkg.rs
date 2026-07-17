//! Networked distributed key generation over the simulated cell (spec §L6): real `DkgNode` engines
//! run a `t`-of-`n` DKG by exchanging Feldman dealings as `DkgDeal` frames, and **every honest node
//! converges on the same joint public key** — whose secret no node holds. The DKG *logic* is unit-
//! verified in `fanos-vrf::dkg`; here it runs end to end over the transport, as it would in a real
//! threshold-hosting bootstrap.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_field::F2;
use fanos_geometry::{Plane, Point, Triple};
use fanos_keygen::DkgNode;
use fanos_runtime::{Command, Duration, Notification};
use fanos_sim::Sim;

/// Spawn a cell of `DkgNode`s (one per Fano point), each with a distinct secret seed.
fn spawn_dkg_cell(sim: &mut Sim, threshold: usize) -> Vec<Triple> {
    let mut coords = Vec::new();
    for (i, point) in Plane::<F2>::points().enumerate() {
        let mut secret = [0u8; 32];
        secret[0] = i as u8;
        secret[1] = 0xD6;
        let node = DkgNode::<F2>::new(point, threshold, secret);
        coords.push(sim.add(Box::new(node)));
    }
    coords
}

#[test]
fn a_cell_runs_a_networked_dkg_and_agrees_on_the_joint_key() {
    let mut sim = Sim::new(0xD46);
    let _cell = spawn_dkg_cell(&mut sim, 4); // 4-of-7 threshold

    // Every node begins dealing; the dealings flood as DkgDeal frames.
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    // Collect each node's announced joint public key.
    let joint: Vec<(Triple, [u8; 32])> = sim
        .report()
        .notifications
        .iter()
        .filter_map(|o| match &o.note {
            Notification::DkgComplete(y) => Some((o.node, *y)),
            _ => None,
        })
        .collect();

    assert_eq!(
        joint.len(),
        7,
        "all seven nodes completed the DKG: {}",
        joint.len()
    );
    let first = joint[0].1;
    assert!(
        joint.iter().all(|(_, y)| *y == first),
        "all nodes agree on the joint public key"
    );
    // The joint key is a real, non-identity group element.
    assert_ne!(first, [0u8; 32]);
}

#[test]
fn dkg_is_reproducible_per_seed() {
    // Determinism: the same seeds yield the same joint key (the dealings are seeded).
    let run = || {
        let mut sim = Sim::new(5);
        let _cell = spawn_dkg_cell(&mut sim, 3);
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(2000));
        sim.report()
            .notifications
            .iter()
            .find_map(|o| match &o.note {
                Notification::DkgComplete(y) => Some(*y),
                _ => None,
            })
            .unwrap()
    };
    assert_eq!(run(), run());
    // Keep the Point import meaningful across refactors.
    let _ = Point::<F2>::at(0);
}
