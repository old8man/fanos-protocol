//! Fleet-scale state inspection — the dashboard/CLI data contract.
//!
//! `Sim::fleet_snapshot` folds every node's published coherence frame (plus ground-truth liveness and
//! the run's metrics) into a `FleetSnapshot`. Two facts shape these tests:
//!
//! 1. The DIAKRISIS coherence self-model is **per base 7-node Fano cell** (`cell_liveness` senses a
//!    3-bit syndrome over exactly 7 points, gated on `self_index`), so a base `F2` cell reports a full
//!    self-model at every node, and crashes there actually move that model.
//! 2. The snapshot *machinery* is `O(N)` and topology-agnostic, so liveness/metrics inspection scales to
//!    a thousand nodes on a single plane — while coherence **at scale** is the job of a hierarchy of base
//!    cells (a separate simulator capability). These tests pin both the base-cell contract and the
//!    structural scaling, and document the boundary between them.

#![allow(clippy::indexing_slicing)]

use fanos_field::{F2, F31};
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{Sim, spawn_cell};

fn config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

/// Bring up the base 7-node Fano cell, run it to steady state, and hand back the sim + node coordinates.
fn steady_base_cell(seed: u64) -> (Sim, Vec<fanos_runtime::Triple>) {
    let mut sim = Sim::new(seed);
    let cell = spawn_cell::<F2>(&mut sim, config());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(1200)); // a couple of heartbeat windows → every node has published
    (sim, cell)
}

#[test]
fn fleet_snapshot_reports_a_healthy_base_cell() {
    let (sim, cell) = steady_base_cell(1);
    let snap = sim.fleet_snapshot();

    assert_eq!(snap.stats.total, cell.len());
    assert_eq!(snap.stats.total, 7, "F2 is the 7-point Fano cell");
    assert_eq!(snap.stats.alive, 7, "all nodes alive");
    assert_eq!(snap.stats.reporting, 7, "every node published its coherence self-model");
    assert_eq!(snap.stats.faulted, 0, "a quiet cell reports no faults");
    assert!(snap.stats.is_healthy(), "a settled cell is fleet-healthy: {:?}", snap.stats);
    assert!(snap.stats.mean_phi.is_finite() && snap.stats.mean_phi > 0.0, "Φ measured: {}", snap.stats.mean_phi);
    assert!(snap.stats.min_phi.is_finite());
    assert!(snap.stats.alarms.healthy == 7, "every node's alarm is Healthy: {:?}", snap.stats.alarms);
    for node in &snap.nodes {
        assert!(node.coherence.is_some(), "node {:?} carries a decoded self-model", node.coord);
        assert!(node.alive);
    }
    assert_eq!(snap.concerns().count(), 0, "nothing to flag in a healthy cell");
}

#[test]
fn crashes_move_the_base_cell_self_model_and_flag_concerns() {
    let (mut sim, cell) = steady_base_cell(42);
    // Crash two of the seven, let the survivors sense the loss past the liveness timeout.
    sim.crash(cell[2]);
    sim.crash(cell[5]);
    sim.run_for(Duration::from_millis(2500));
    let snap = sim.fleet_snapshot();

    assert_eq!(snap.stats.total, 7);
    assert_eq!(snap.stats.alive, 5, "two crashed");
    let dead: Vec<_> = snap.nodes.iter().filter(|n| !n.alive).map(|n| n.coord).collect();
    assert_eq!(dead.len(), 2);
    assert!(dead.contains(&cell[2]) && dead.contains(&cell[5]), "the crashed pair shows as not-alive");
    assert!(snap.concerns().count() >= 2, "at least the crashed nodes are flagged");
    // On a real base cell the loss moves the survivors' self-model: the fleet is no longer all-healthy.
    assert!(!snap.stats.is_healthy(), "losing 2 of 7 perturbs the cell's coherence: {:?}", snap.stats);
}

#[test]
fn structural_fleet_inspection_scales_to_a_thousand_nodes() {
    // F31 = 993 nodes on one plane. `refresh_telemetry` is a single O(N) Observe round (not the O(N²)
    // heartbeat fan-out), so a ~1000-node fleet is inspectable cheaply. Liveness/metrics/roster are exact
    // at this scale; the coherence self-model is per base cell (see module docs), so a single large plane
    // is not a coherent cell — coherence AT scale comes from a hierarchy of base cells (next capability).
    let mut sim = Sim::new(31);
    let cell = spawn_cell::<F31>(&mut sim, config());
    assert_eq!(cell.len(), 993, "F31 plane N = 31²+31+1");
    sim.refresh_telemetry();
    let snap = sim.fleet_snapshot();

    assert_eq!(snap.stats.total, 993);
    assert_eq!(snap.stats.alive, 993, "all nodes alive");
    assert_eq!(snap.nodes.len(), 993, "the full roster is inspectable");
    assert_eq!(snap.stats.reporting, 0, "a single large plane is not a base cell — no per-node self-model");
    // Crash-tracking still works at scale (liveness is topology-agnostic).
    sim.crash(cell[0]);
    let after = sim.fleet_snapshot();
    assert_eq!(after.stats.alive, 992);
    assert_eq!(after.concerns().count(), 1, "the crashed node is flagged among a thousand");
}

#[test]
fn a_fleet_snapshot_is_deterministic_per_seed() {
    // The snapshot is a pure read over a reproducible run, so the same seed yields identical fleet state
    // (a base cell, so the coherence means are real numbers that reproduce bit-for-bit — no NaN).
    let a = steady_base_cell(99).0.fleet_snapshot();
    let b = steady_base_cell(99).0.fleet_snapshot();
    assert_eq!(a.stats, b.stats, "cluster stats reproduce");
    assert_eq!(a.nodes, b.nodes, "every node's state reproduces");
    assert_eq!(a.metrics, b.metrics, "run metrics reproduce");
}
