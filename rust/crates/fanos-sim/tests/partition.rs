//! **§6.5 segment/partition diagnosis (V14) — live on the real engine (#95/#106).**
//!
//! The partition-resistance theorem says no single line-kill disconnects a Fano cell; a real split needs a
//! lossy line-*cover*, and the tell-tale case is an **incipient** split: nodes still corroborated-alive while
//! the lines between two sides degrade. Liveness monitoring cannot see it (nobody is down); the loss-weighted
//! Fiedler `λ₂` can. This wires that sensor from the measured per-channel loss (the #106 grey substrate — an
//! INDEPENDENT signal, not the node-liveness mask), behind a persistence dwell so a recovery-loss transient
//! never false-fires. These tests drive it with the simulator's soft-partition affordance (a lossy, not
//! fully-cut, bisection) and confirm: a sustained lossy line-cover fires `Verdict::Partition` while nodes stay
//! alive, and honest crash/recover churn never does.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use fanos_diakrisis::Verdict;
use fanos_field::F2;
use fanos_geometry::fano;
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{Sim, spawn_cell};

#[test]
fn a_soft_partition_fires_the_partition_verdict_while_nodes_stay_alive() {
    // A lossy-but-not-cut bisection isolating one point: its `q+1` lines read lossy (cross-loss 0.6 >
    // LINE_CUT_LOSS) while it stays corroborated-alive (gossip still crosses ~40 %), so the loss-weighted
    // Fiedler disconnects and — after the persistence dwell — `Verdict::Partition` fires. Crucially the
    // PARTITION verdict (not a crash/Localized) fires: `diagnose` only checks `healthy_lines` in the all-alive
    // branch, so the verdict itself proves the node was alive — the signal liveness monitoring cannot see.
    let mut sim = Sim::new(0x_9A27);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000)); // establish liveness + a clean baseline loss

    let isolated = fano::point(4).coords();
    let rest: BTreeSet<[u32; 3]> = cell.iter().copied().filter(|&c| c != isolated).collect();
    sim.network_mut()
        .soft_partition([BTreeSet::from([isolated]), rest], 0.6);
    sim.run_for(Duration::from_millis(6000)); // loss-EWMA ramp + the persistence dwell

    assert!(
        sim.report().any_verdict(&Verdict::Partition),
        "a sustained lossy line-cover fires Verdict::Partition while the isolated node stays alive"
    );
}

#[test]
fn honest_churn_does_not_false_fire_the_partition_verdict() {
    // The persistence guard: a crash+recover churn — a recovered node's loss EWMA lags for a round or two while
    // it reads alive — must NOT produce a Partition. The transient does not survive the dwell.
    for seed in 0..4u64 {
        let mut sim = Sim::new(0x_C0FF ^ seed);
        let cell = spawn_cell::<F2>(&mut sim, Config::default());
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(2500));
        sim.crash(cell[2]);
        sim.run_for(Duration::from_millis(2500));
        sim.recover(cell[2]);
        sim.inject(cell[2], Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(5000));

        assert!(
            !sim.report().any_verdict(&Verdict::Partition),
            "seed {seed}: honest crash/recover churn must never false-fire Verdict::Partition"
        );
    }
}

#[test]
fn a_healthy_cell_never_reports_partition() {
    // Baseline: an intact cell (mild honest loss) is fully connected (λ₂ = 7) — no Partition ever.
    let net =
        fanos_sim::NetworkModel::new(Duration::from_millis(20), Duration::from_millis(8), 0.1);
    let mut sim = Sim::with_network(0x_11AC, net);
    let _cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(8000));
    assert!(
        !sim.report().any_verdict(&Verdict::Partition),
        "a healthy cell (one plane, no split) never reports a partition (partition-resistance)"
    );
}
