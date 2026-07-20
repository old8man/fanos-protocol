//! Byzantine-fault scenarios (spec §6.4): an adversary that forges health-view gossip or floods
//! garbage. The headline is the **quorum-corroborated liveness** fix — a single liar vouching for a
//! dead node cannot fool an honest node (it is outvoted), whereas the old any-witness rule could be
//! fooled by one liar. Frames are injected with [`Sim::inject_frame`], which stands in for a
//! malicious node genuinely emitting them (the transport authenticates the sender).

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_diakrisis::{Fault, Verdict};
use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{Sim, spawn_cell};
use fanos_wire::{FrameType, encode_frame};

/// A forged health-view gossip claiming Fano point `target` is fresh (age 0) and nothing else.
fn forged_liveness_for(target: usize) -> Vec<u8> {
    let mut body = vec![0xFFu8; 14]; // all points "never seen"…
    body[target * 2] = 0;
    body[target * 2 + 1] = 0; // …except `target`, claimed just-seen
    let mut frame = Vec::new();
    encode_frame(FrameType::DiagGossip.code(), &body, &mut frame);
    frame
}

/// Establish a cell (with the given quorum), crash node 5, and let honest nodes detect it.
fn cell_with_dead_node(quorum: usize) -> (Sim, Vec<[u32; 3]>) {
    let cfg = Config {
        corroboration_quorum: quorum,
        ..Config::default()
    };
    let mut sim = Sim::new(0xB17);
    let cell = spawn_cell::<F2>(&mut sim, cfg);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    sim.crash(cell[5]);
    sim.run_for(Duration::from_millis(3000));
    (sim, cell)
}

#[test]
fn a_single_liar_cannot_forge_liveness_under_quorum() {
    // Quorum 2: one Byzantine witness vouching for the dead node is outvoted, so node 0 still
    // localizes the crash.
    let (mut sim, cell) = cell_with_dead_node(2);
    // Node 1 (Byzantine) repeatedly tells node 0 that the dead node 5 is alive.
    for _ in 0..4 {
        sim.inject_frame(cell[1], cell[0], forged_liveness_for(5));
        sim.run_for(Duration::from_millis(200));
    }
    sim.inject(cell[0], Command::Diagnose);
    sim.settle();
    assert!(
        sim.report()
            .any_verdict(&Verdict::Localized(Fault::Single(5))),
        "the lie is outvoted; the crash is still localized"
    );
}

#[test]
fn the_old_any_witness_rule_would_be_fooled_by_one_liar() {
    // Quorum 1 (the loss-optimized, Byzantine-unsafe setting): a single liar suffices to keep the
    // dead node "alive" at node 0 — demonstrating exactly the weakness the quorum default fixes.
    let (mut sim, cell) = cell_with_dead_node(1);
    for _ in 0..4 {
        sim.inject_frame(cell[1], cell[0], forged_liveness_for(5));
        sim.run_for(Duration::from_millis(200));
    }
    sim.clear_report(); // read only this final round, not the reflex's running diagnosis (#122)
    sim.inject(cell[0], Command::Diagnose);
    sim.settle();
    // Node 0 was fooled: it does not localize node 5 as a single fault.
    assert!(
        !sim.report()
            .any_verdict(&Verdict::Localized(Fault::Single(5))),
        "with quorum 1 the single liar masks the crash"
    );
}

#[test]
fn byzantine_tolerance_is_exactly_quorum_minus_one_distinct_witnesses() {
    // The equivocation/Sybil boundary (spec §6.4, threat D4): quorum-corroborated liveness tolerates up
    // to `quorum − 1` DISTINCT witnesses lying in concert — the distinctness is what forces an attacker
    // to control that many separate line identities (each an owned coordinate, priced by the B1 Sybil
    // bound). We pin the boundary exactly: with quorum 3, TWO distinct liars are outvoted, but THREE
    // (= quorum) succeed. A single node repeating the same lie is one witness, not a majority — so this
    // is strictly the multi-identity (equivocating) case the single-liar tests don't cover.
    let liars_defeated = |n_liars: usize| -> bool {
        let (mut sim, cell) = cell_with_dead_node(3);
        // `n_liars` DISTINCT honest-looking neighbours (cells 1..=n_liars) each vouch that the dead
        // node 5 is alive. (Node 5 is the crash; nodes 1..=4 are live witnesses an attacker would have
        // to have seized to speak as.)
        for round in 0..4 {
            for liar in 1..=n_liars {
                sim.inject_frame(cell[liar], cell[0], forged_liveness_for(5));
            }
            let _ = round;
            sim.run_for(Duration::from_millis(200));
        }
        sim.clear_report(); // read only this final round, not the reflex's running diagnosis (#122)
        sim.inject(cell[0], Command::Diagnose);
        sim.settle();
        // "Defeated" = the crash is still localized despite the lie (the honest node was not fooled).
        sim.report()
            .any_verdict(&Verdict::Localized(Fault::Single(5)))
    };

    // quorum − 1 = 2 distinct liars: outvoted, crash localized.
    assert!(
        liars_defeated(2),
        "2 < quorum 3 distinct liars are outvoted — the crash is still seen"
    );
    // quorum = 3 distinct liars: they meet the corroboration bar, masking the crash — the exact point
    // the tolerance is exceeded. This is the calibrated floor: safety holds iff #liars < quorum.
    assert!(
        !liars_defeated(3),
        "3 = quorum distinct liars reach the bar and mask the crash"
    );
}

#[test]
fn garbage_frame_floods_do_not_disturb_a_healthy_cell() {
    // A Byzantine node floods malformed frames; honest nodes drop them (canonical decode failure)
    // and the cell stays healthy.
    let mut sim = Sim::new(0x6A6);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    for i in 0..50u8 {
        // Random-looking, non-canonical bytes from node 1 to node 0.
        sim.inject_frame(cell[1], cell[0], vec![0xDE, 0xAD, 0xBE, 0xEF, i]);
    }
    sim.run_for(Duration::from_millis(1000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();

    let last: Vec<_> = sim.report().verdicts().rev().take(7).collect();
    assert!(
        last.iter().all(|(_, v)| **v == Verdict::Healthy),
        "garbage flood is dropped; the cell stays healthy: {last:?}"
    );
}
