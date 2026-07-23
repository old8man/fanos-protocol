//! Cluster-scale stress experiments — chaos-engineering the fleet and checking its homeostatic response.
//! Each experiment is deterministic (index-chosen targets), so these are permanent regression guards.

#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

use fanos_runtime::{Config, Duration};
use fanos_sim::Cluster;
use fanos_sim::stress::{Experiment, run_experiment};

fn config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

fn step() -> Duration {
    Duration::from_millis(700)
}

#[test]
fn mass_crash_degrades_the_fleet_and_is_contained_to_whole_cells() {
    // 20 cells = 140 nodes; crash 10% = 14 nodes = exactly two whole cells (cells filled first).
    let mut cluster = Cluster::new(1, config(), 20);
    cluster.run_for(Duration::from_millis(1200));
    let report = run_experiment(&mut cluster, Experiment::MassCrash { fraction: 0.1 }, 4, step());

    assert!(report.before.is_healthy(), "starts healthy");
    assert_eq!(report.after.alive, 126, "14 of 140 nodes crashed and stay down");
    assert_eq!(report.peak_troubled_cells, 2, "the outage is contained to the two crashed cells");
    assert!(!report.ended_healthy, "a mass crash without rejoin leaves the fleet degraded");
    // The other 18 cells are untouched — the fault did not spread.
    let snap = cluster.snapshot();
    assert_eq!(snap.totals.alive, 126);
    assert_eq!(snap.troubled_cells().count(), 2);
}

#[test]
fn rolling_churn_keeps_the_fleet_bounded_not_cascading() {
    // Continuous turnover on 30 cells (210 nodes): a few nodes down at any moment, never a cascade.
    let mut cluster = Cluster::new(2, config(), 30);
    cluster.run_for(Duration::from_millis(1200));
    let exp = Experiment::RollingChurn { per_tick: 3, grace: 3 };
    let report = run_experiment(&mut cluster, exp, 20, step());

    // Steady-state churn keeps most of the fleet alive (only ~grace×per_tick down at once, far from all).
    assert!(report.after.alive >= 210 - 3 * 3 * 2, "churn stays bounded: {} alive", report.after.alive);
    assert!(report.peak_troubled_cells < 30, "never all cells at once (no cascade): {}", report.peak_troubled_cells);
    assert!(report.min_mean_phi.is_finite(), "the fleet keeps reporting a self-model throughout");
}

#[test]
fn cascade_collapses_only_the_target_cell() {
    // 10 cells (70 nodes); crash one node of cell 0 per tick for 7 ticks → cell 0 fully collapses, alone.
    let mut cluster = Cluster::new(3, config(), 10);
    cluster.run_for(Duration::from_millis(1200));
    let report = run_experiment(&mut cluster, Experiment::Cascade { target: 0 }, 7, step());

    assert_eq!(report.after.alive, 63, "all 7 of cell 0 are down");
    assert_eq!(report.peak_troubled_cells, 1, "only the target cell is ever troubled");
    let troubled: Vec<_> = cluster.snapshot().troubled_cells().map(|(i, _)| i).collect();
    assert_eq!(troubled, vec![0], "exactly cell 0 collapsed");
}

#[test]
fn partition_degrades_cells_without_crashing_them_then_heals() {
    // 10 cells (70 nodes); bisect 30% (3 cells) at t=0, heal at t=5, run 14 ticks.
    let mut cluster = Cluster::new(4, config(), 10);
    cluster.run_for(Duration::from_millis(1200));
    let report = run_experiment(&mut cluster, Experiment::Partition { fraction: 0.3, hold: 5 }, 14, step());

    assert!(report.before.is_healthy(), "starts healthy");
    // No node is ever crashed — a partition cuts reachability, it does not kill nodes.
    assert_eq!(report.after.alive, 70, "every node stays alive throughout a partition");
    // The cut is detected: the three bisected cells degrade at the worst moment.
    assert!(report.peak_troubled_cells >= 3, "the 3 partitioned cells are detected as degraded: {}", report.peak_troubled_cells);
    // After the heal + settle, the fleet recovers to healthy (nodes re-sense their peers).
    assert!(report.ended_healthy, "the fleet recovers once the cut heals: {:?}", report.after);
}

#[test]
fn soft_partition_never_crashes_a_node_and_recovers() {
    // A lossy (incipient) bisection of 3 of 10 cells: nodes stay marginally reachable, so none is ever
    // crashed; after the cut heals the fleet returns healthy.
    let mut cluster = Cluster::new(6, config(), 10);
    cluster.run_for(Duration::from_millis(1200));
    let exp = Experiment::SoftPartition { fraction: 0.3, cross_loss: 0.92, hold: 5 };
    let report = run_experiment(&mut cluster, exp, 16, step());

    assert!(report.before.is_healthy(), "starts healthy");
    assert_eq!(report.after.alive, 70, "a lossy cut never kills a node");
    assert!(report.ended_healthy, "the fleet recovers once the lossy cut heals: {:?}", report.after);
}

#[test]
fn an_experiment_run_is_deterministic_per_seed() {
    let run = || {
        let mut c = Cluster::new(9, config(), 12);
        c.run_for(Duration::from_millis(1200));
        run_experiment(&mut c, Experiment::RollingChurn { per_tick: 2, grace: 2 }, 10, step())
    };
    let a = run();
    let b = run();
    assert_eq!(a.after.alive, b.after.alive, "outcome reproduces");
    assert_eq!(a.peak_troubled_cells, b.peak_troubled_cells);
    assert_eq!(a.before.alive, b.before.alive);
}

#[test]
fn experiment_names_round_trip() {
    for name in Experiment::NAMES {
        let exp = Experiment::from_name(name, 0.1, 140).expect("known experiment");
        assert_eq!(exp.name(), name, "{name} round-trips");
    }
    assert!(Experiment::from_name("nonsense", 0.1, 7).is_none());
}
