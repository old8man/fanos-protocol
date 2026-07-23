//! The scale-out cluster — a federation of coherent base cells, exercised from one node to ten thousand.
//!
//! Unlike a single large plane (where the per-node self-model is absent — coherence is a base-cell
//! property), a `Cluster` of base cells reports a genuine coherence self-model at *every* node, at scale.
//! These scenarios pin: coherence at ~1000 nodes, smooth 1→N node scaling (partial last cell), isolated
//! per-cell experiments, determinism, and 10 000-node feasibility.

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use fanos_runtime::{Config, Duration};
use fanos_sim::Cluster;

fn config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

#[test]
fn a_cluster_of_cells_is_coherent_at_thousand_node_scale() {
    // 143 base cells = 1001 nodes — and, crucially, EVERY node reports its self-model (contrast the
    // single 993-node plane, where none do). This is coherence at scale, the way the network actually
    // scales: a recursion of small coherent cells.
    let mut cluster = Cluster::new(7, config(), 143);
    assert_eq!(cluster.cell_count(), 143);
    assert_eq!(cluster.node_count(), 1001);
    cluster.run_for(Duration::from_millis(1200));
    let snap = cluster.snapshot();

    assert_eq!(snap.totals.total, 1001);
    assert_eq!(snap.totals.alive, 1001);
    assert_eq!(snap.totals.reporting, 1001, "every node in every cell publishes a self-model");
    assert!(snap.totals.is_healthy(), "a fresh cluster is fleet-healthy: {:?}", snap.totals);
    assert!(snap.totals.mean_phi.is_finite() && snap.totals.mean_phi > 0.0);
    assert_eq!(snap.cell_count(), 143);
    assert_eq!(snap.troubled_cells().count(), 0, "nothing troubled in a healthy cluster");
}

#[test]
fn node_target_gives_smooth_one_to_n_scaling() {
    // The "one node, two nodes, three nodes …" progression: a single growing cell up to 7, then more.
    for n in [1usize, 2, 3, 7, 8, 15, 50, 1000] {
        let cluster = Cluster::with_node_target(1, config(), n);
        assert_eq!(cluster.node_count(), n, "cluster holds exactly {n} nodes");
        assert_eq!(cluster.cell_count(), n.div_ceil(7), "⌈{n}/7⌉ cells");
    }
}

#[test]
fn a_per_cell_experiment_is_isolated_to_its_cell() {
    let mut cluster = Cluster::new(3, config(), 20); // 140 nodes
    cluster.run_for(Duration::from_millis(1200));
    // Crash two nodes in cell 5 only.
    {
        let cell = cluster.cell_mut(5).expect("cell 5 exists");
        let coords: Vec<_> = cell.nodes().collect();
        cell.crash(coords[1]);
        cell.crash(coords[4]);
    }
    cluster.run_for(Duration::from_millis(2500));
    let snap = cluster.snapshot();

    assert_eq!(snap.totals.total, 140);
    assert_eq!(snap.totals.alive, 138, "exactly the two crashed nodes are gone");
    // Only cell 5 is troubled; every other cell stays clean (the fault did not leak across cells).
    let troubled: Vec<_> = snap.troubled_cells().map(|(i, _)| i).collect();
    assert_eq!(troubled, vec![5], "the perturbation is contained to cell 5");
    assert!(!snap.totals.is_healthy(), "the cluster total reflects the degraded cell");
}

#[test]
fn a_cluster_snapshot_is_deterministic_per_seed() {
    let a = {
        let mut c = Cluster::new(55, config(), 10);
        c.run_for(Duration::from_millis(1200));
        c.snapshot()
    };
    let b = {
        let mut c = Cluster::new(55, config(), 10);
        c.run_for(Duration::from_millis(1200));
        c.snapshot()
    };
    assert_eq!(a.totals, b.totals, "cluster totals reproduce");
    assert_eq!(a.metrics, b.metrics, "summed metrics reproduce");
    assert_eq!(a.cells.len(), b.cells.len());
}

#[test]
fn the_cluster_reaches_ten_thousand_nodes() {
    // ~1429 cells × 7 = 10 003 nodes. Built and inspected via the O(N) refresh path (no O(N²) heartbeat),
    // so ten thousand nodes stay tractable — the scale ceiling the single-plane sim could not reach.
    let mut cluster = Cluster::with_node_target(9, config(), 10_000);
    assert!(cluster.node_count() >= 10_000, "holds at least ten thousand nodes: {}", cluster.node_count());
    cluster.refresh_telemetry();
    let snap = cluster.snapshot();

    assert_eq!(snap.totals.total, cluster.node_count());
    assert!(snap.totals.total >= 10_000);
    assert_eq!(snap.totals.alive, snap.totals.total, "all alive");
    assert!(snap.totals.reporting >= 10_000, "every node inspectable at 10k scale: {}", snap.totals.reporting);
}
