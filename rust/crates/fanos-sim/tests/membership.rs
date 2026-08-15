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
fn the_epoch_beacon_reaches_monotone_consensus_from_a_quorum_of_triggers() {
    let mut sim = Sim::new(2);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());

    // **This test used to say `from_one_trigger`, and that contract is deliberately gone** (#351).
    //
    // `EpochAgree` carries a bare four-byte ordinal and used to be adopted `adopt-max`, so one node's
    // advance dragged the whole cell — which is precisely the defect: every other decision in FANOS
    // tolerates `f` faulty members and this one tolerated zero, at a price of `current + 2` expiring every
    // directory slot on every node it reached. The epoch a node adopts from gossip now needs
    // `corroboration_quorum` distinct members to have reached it.
    //
    // **Nothing in production depended on the old contract.** Each node runs its own wall-clock epoch driver
    // (`fanos_node::spawn_epoch_driver` — "the root tick that periodically issues `Command::AdvanceEpoch`"),
    // so no node needs another's trigger to move its own clock; gossip exists for *agreement* and catch-up,
    // not to drive time. Convergence on the newest epoch is unchanged — it now waits for `q` members to get
    // there first, which is the calibration, not a delay bolted on.
    //
    // The subject of this test is untouched: monotone cell-wide consensus, and epoch 1 never re-emitted.
    // Only its setup is raised to the rule it is testing under.
    let quorum = Config::default().corroboration_quorum;
    for &trigger in cell.iter().take(quorum) {
        sim.inject(trigger, Command::AdvanceEpoch);
    }
    sim.run_for(Duration::from_millis(500));

    let adopted = sim
        .report()
        .notifications
        .iter()
        .filter(|o| matches!(&o.note, Notification::EpochAdvanced(Epoch(1))))
        .count();
    assert_eq!(adopted, 7, "all seven nodes adopted epoch 1");

    // A second advance moves the whole cell to epoch 2; epoch 1 is never re-emitted (monotone). A quorum
    // again, for the same reason — and deliberately a DIFFERENT set of members, so a green here cannot come
    // from the first round's claimants still being counted: `on_epoch_changed` prunes claims the cell has
    // reached, and if it did not, this second advance would ride on spent votes.
    for &trigger in cell.iter().skip(3).take(quorum) {
        sim.inject(trigger, Command::AdvanceEpoch);
    }
    sim.run_for(Duration::from_millis(500));
    let at_two = sim
        .report()
        .notifications
        .iter()
        .filter(|o| matches!(&o.note, Notification::EpochAdvanced(Epoch(2))))
        .count();
    assert_eq!(at_two, 7, "all seven nodes advanced to epoch 2");
}

/// **What fraction of LEGITIMATE announcements does the self-certified check reject?** (#352 residual)
///
/// `require_self_certified_membership` defends against routing-table poisoning and ships off. The reason
/// recorded for leaving the default alone is that no measurement exists of what it would cost an honest
/// deployment — and `hier_poisoning.rs` cannot answer it, because it feeds the check a **hand-built** signed
/// descriptor. That proves the check accepts a correctly constructed announcement; it says nothing about
/// whether the announcement a real engine EMITS is one. Two different questions, and the second is the one a
/// default turns on.
///
/// So: the same cell, twice, differing only in the flag. The gap between the two rosters is the rejection
/// rate on honest traffic, measured rather than argued.
#[test]
fn the_self_certified_check_measured_against_what_a_real_cell_actually_announces() {
    // The observable is `MemberJoined`, the same one this file's other test reads: one per (node, peer) pair
    // a node accepted. Summed over the cell it is the number of learned edges — which is exactly what the
    // check can take away.
    fn learned_edges(require: bool) -> usize {
        let mut sim = Sim::new(7);
        let cell = spawn_cell::<F2>(
            &mut sim,
            Config { require_self_certified_membership: require, ..Config::default() },
        );
        for &c in &cell {
            sim.inject(c, Command::Join { info: b"key".to_vec() });
        }
        sim.run_for(Duration::from_millis(500));
        sim.report()
            .notifications
            .iter()
            .filter(|o| matches!(&o.note, Notification::MemberJoined { .. }))
            .count()
    }
    let b = learned_edges(false);
    let g = learned_edges(true);
    assert!(b > 0, "the ungated cell learned nothing — the measurement has no baseline");
    // Not `assert_eq!(g, b)`: this test's job is to REPORT the cost, and a number is only worth having if a
    // reader can see it. The assertion is the floor the decision needs — a check that rejects honest
    // announcements wholesale is not a default anyone would consider.
    println!("self-certified membership: ungated {b} learned edges, guarded {g} — rejected {} ({:.0}%)",
             b.saturating_sub(g), 100.0 * f64::from(u32::try_from(b.saturating_sub(g)).unwrap_or(0)) / f64::from(u32::try_from(b).unwrap_or(1)));
    // **Pinning zero, which is a defect and not a property to preserve.** The measured answer is that the
    // check refuses 100% of honest traffic, and the cause is known and narrow: the engine holds no signing
    // key by construction, so a deployment must install a signed descriptor through
    // `OverlayNode::with_signed_descriptor` — and in this whole tree that builder's only caller is a
    // simulator test. `hier_poisoning::a_deployed_identity_node_self_certifies_end_to_end` proves the check
    // ACCEPTS a properly signed announcement, so what is missing is the producer, not the check.
    //
    // Hence this reads `assert_eq!(g, 0)` rather than the `g > 0` a first draft asserted from the hypothesis.
    // It is a tripwire: the day production learns to sign its descriptor this fails, and the failure is the
    // notice to drop the "rejects EVERY peer today" warning from `NodeConfig::require_self_certified_membership`
    // and its `setup.rs` hint — a warning that outlives its cause is a lie the operator acts on.
    assert_eq!(
        g, 0,
        "the self-certified check no longer refuses every honest announcement (ungated {b} edges, guarded \
         {g}). If production now installs a signed descriptor, this measurement is stale: re-run it, then \
         remove the precondition warning from NodeConfig::require_self_certified_membership and \
         render_overlay_choices, and revisit whether the default should now be ON."
    );
}
