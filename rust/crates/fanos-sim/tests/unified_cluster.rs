//! Coherence at scale on ONE connected topology — `UnifiedCluster` puts K coherent 7-node cells in a
//! single `Sim` (unlike the federated `Cluster`'s per-cell Sims), the unified-topology refactor made
//! operable. Every node reports a self-model, it stays cheap (each node pings only its six cell members),
//! and a fault is contained to its cell.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_field::F31;
use fanos_runtime::{Config, Duration};
use fanos_sim::UnifiedCluster;

fn config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

#[test]
fn many_coherent_cells_report_in_one_sim() {
    // 100 cells = 700 nodes, all embedded in one F31 plane / one Sim.
    let mut cluster = UnifiedCluster::new::<F31>(7, config(), 100);
    assert_eq!(cluster.cell_count(), 100);
    assert_eq!(cluster.node_count(), 700);
    cluster.run_for(Duration::from_millis(1500));
    let snap = cluster.snapshot();

    assert_eq!(snap.stats.total, 700);
    assert_eq!(snap.stats.reporting, 700, "every node in every embedded cell reports coherence");
    assert!(snap.stats.is_healthy(), "a settled unified cluster is healthy: {:?}", snap.stats);
    assert!(snap.stats.mean_phi.is_finite() && snap.stats.mean_phi > 0.0);
}

#[test]
fn a_fault_is_contained_to_its_cell() {
    let mut cluster = UnifiedCluster::new::<F31>(3, config(), 40); // 280 nodes
    cluster.run_for(Duration::from_millis(1200));
    // Crash one member of cell 5.
    let victim = cluster.cell(5).unwrap()[2];
    cluster.crash(victim);
    cluster.run_for(Duration::from_millis(2500));
    let snap = cluster.snapshot();

    assert_eq!(snap.stats.total, 280);
    assert_eq!(snap.stats.alive, 279, "exactly one member down");
    assert!(snap.concerns().any(|n| !n.alive), "the crashed member is flagged");
    // Containment: because each node pings only its six cell members, the fault touches at most cell 5's
    // seven nodes — never the other 39 cells. (No cross-cell coherence coupling in a single Sim.)
    assert!(snap.concerns().count() <= 7, "the fault is contained to one cell: {} concerns", snap.concerns().count());
}

#[test]
fn coherent_cells_also_route_across_each_other() {
    // The unification: the SAME cluster reports coherence AND routes cross-cell (both lenses, one topology).
    let mut cluster = UnifiedCluster::new::<F31>(5, config(), 12); // 84 nodes, 12 gateways
    cluster.run_for(Duration::from_millis(1200));

    // Coherence lens.
    let snap = cluster.snapshot();
    assert_eq!(snap.stats.reporting, 84, "every node reports coherence");
    assert!(snap.stats.is_healthy());

    // Routing lens — every ordered gateway pair reaches the other.
    let pairs: Vec<(usize, usize)> = (0..12)
        .flat_map(|i| (0..12).filter(move |&j| i != j).map(move |j| (i, j)))
        .collect();
    assert!(cluster.reachability(&pairs) > 0.999, "every cell's gateway routes to every other");
}

#[test]
fn scales_toward_a_thousand_nodes_via_the_o_n_refresh_path() {
    // 141 cells = 987 nodes on F31 (its ceiling). Linear in cells — each node pings only its 6 members.
    let mut cluster = UnifiedCluster::new::<F31>(9, config(), 141);
    assert_eq!(cluster.node_count(), 987);
    cluster.refresh_telemetry();
    let snap = cluster.snapshot();
    assert_eq!(snap.stats.reporting, 987, "~1000 coherent nodes on one connected topology");
    assert!(snap.stats.mean_phi.is_finite());
}
