//! Membership & beacon over the simulated cell (spec §7.8 JOIN, §L3 beacon): a joining node's info
//! (its public key) floods to every member — dynamic key distribution — and an epoch beacon reaches
//! monotone consensus cell-wide from a single trigger. Both are the running `OverlayNode` engine's
//! flood behaviour, the substrate onion routing and epoch-rotating rendezvous build on.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_field::F2;
use fanos_primitives::Epoch;
use fanos_runtime::{Command, Config, Duration, Notification};
use fanos_sim::{Sim, spawn_cell};

#[test]
fn a_joining_nodes_key_propagates_to_every_member() {
    let mut sim = Sim::new(1);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());

    sim.inject(
        cell[0],
        Command::Join {
            info: b"node0-public-key".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));

    // The six other cell members each learned node 0's announcement exactly once (the monotone
    // "only re-flood the unseen" guard makes the flood converge, not loop).
    let learned: Vec<_> = sim
        .report()
        .notifications
        .iter()
        .filter_map(|o| match &o.note {
            Notification::MemberJoined { coord, info } if *coord == cell[0] => {
                Some((o.node, info.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        learned.len(),
        6,
        "all six other members learned node 0: {learned:?}"
    );
    assert!(learned.iter().all(|(_, info)| info == b"node0-public-key"));
}

#[test]
fn the_epoch_beacon_reaches_monotone_consensus_from_one_trigger() {
    let mut sim = Sim::new(2);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());

    // Advance the beacon at a single node; it floods and every node adopts epoch 1 (adopt-max).
    sim.inject(cell[0], Command::AdvanceEpoch);
    sim.run_for(Duration::from_millis(500));

    let adopted = sim
        .report()
        .notifications
        .iter()
        .filter(|o| matches!(&o.note, Notification::EpochAdvanced(Epoch(1))))
        .count();
    assert_eq!(adopted, 7, "all seven nodes adopted epoch 1");

    // A second advance moves the whole cell to epoch 2; epoch 1 is never re-emitted (monotone).
    sim.inject(cell[3], Command::AdvanceEpoch);
    sim.run_for(Duration::from_millis(500));
    let at_two = sim
        .report()
        .notifications
        .iter()
        .filter(|o| matches!(&o.note, Notification::EpochAdvanced(Epoch(2))))
        .count();
    assert_eq!(at_two, 7, "all seven nodes advanced to epoch 2");
}
