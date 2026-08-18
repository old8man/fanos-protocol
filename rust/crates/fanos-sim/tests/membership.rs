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
            Config {
                require_self_certified_membership: require,
                // **`vrf_coordinates: true`, because that is what `Node::start` sets** — and without it this
                // measures the wrong half. The check has two: the overlay address must be the identity's own
                // descent chain, and the descriptor must bind this transport coordinate. Under VRF
                // coordinates the first skips level 0 (the HELLO's proof-of-coordinate authenticates it
                // instead, audit C3); with the flag off it demands `address_point(id, 0) == coord`, which a
                // fixture seating nodes at `Point::at(i)` satisfies only by coincidence.
                //
                // Measured with it off, for the record: **42 ungated edges against 12 guarded, 71 % refused**
                // — two identities in seven happened to hash onto their own seat, and their announcements are
                // the ones that survived. That is a statement about the fixture's seating, not about the
                // check, and reading it as the latter is what this comment exists to prevent.
                vrf_coordinates: true,
                ..Config::default()
            },
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
    // **This asserted `g == 0` until 2026-08-18, and that was the honest reading at the time**: the engine
    // holds no signing key by construction, nothing in production installed a signed descriptor, and the
    // check therefore refused every honest announcement. It was written as a tripwire — *"the day production
    // learns to sign its descriptor this fails"* — and it did.
    //
    // What changed: `NodeCredentials::descriptor_identity` derives the hybrid identity from the certificate
    // key, `Command::Descriptor` carries a fresh signature at every reseat (the message binds the transport
    // coordinate, which the reshuffle re-draws), and `compose_engine` installs the genesis one — so the
    // simulator's cell now announces what a deployment announces, which is the whole point of spawning
    // through the composer.
    //
    // **The cost on honest traffic is zero, and that is the number the default was waiting for.** What it does
    // NOT settle: this measures the descriptor-signature half only. Level 0's authenticity comes from the
    // HELLO proof-of-coordinate, which this bus does not carry, and the address-binding half is vacuous at
    // depth 1 anyway (`at_depth_one_the_vrf_skip_makes_the_binding_vacuous_for_any_identity`). So the switch
    // costs nothing and buys the transport-hijack defence (§80) — not the poisoning defence (§79), which
    // arrives with the descent.
    assert_eq!(
        g, b,
        "the self-certified check must not refuse a single honest announcement now that production produces \
         the descriptor it verifies (ungated {b} edges, guarded {g}). A gap here is the producer disagreeing \
         with the verifier about the bytes — the two build `descriptor_message` from the same exported \
         function precisely so they cannot."
    );
    assert_eq!(b, 42, "seven nodes learning six peers each — the baseline the percentage above divides by");
}
