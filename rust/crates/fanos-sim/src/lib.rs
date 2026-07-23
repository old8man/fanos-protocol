//! # fanos-sim — the deterministic network simulator
//!
//! A single-process **driver** that runs the real [`fanos_runtime`] node engines with the
//! environment and transport swapped for deterministic, in-memory implementations (see
//! `docs/architecture.md`). Each node is genuinely independent — it only ever sees its own
//! local inputs — so a cell simulated here behaves as a cell of real nodes would, and the
//! same engine code ships to production over a real transport.
//!
//! What it buys us (why simulate): faithful fault modelling (crash, partition, churn),
//! byte-for-byte reproducibility per seed, adversary experiments, and regression gating of the
//! protocol's emergent properties — self-diagnosis, rendezvous, partition resistance — not
//! just its formulas.
//!
//! ```
//! use fanos_sim::{Sim, spawn_cell};
//! use fanos_runtime::{Command, Config, Duration};
//! use fanos_field::F2;
//!
//! let mut sim = Sim::new(0xFA);
//! let cell = spawn_cell::<F2>(&mut sim, Config::default());
//! sim.inject_all(&Command::StartHeartbeat);
//! sim.run_for(Duration::from_millis(2000));    // establish liveness
//! sim.crash(cell[5]);                           // a node dies
//! sim.run_for(Duration::from_millis(3000));     // heartbeats time out
//! sim.inject_all(&Command::Diagnose);
//! sim.settle();
//! // A surviving node localizes the crash by its 3-bit syndrome.
//! ```

mod cluster;
mod experiment;
mod fleet;
mod hierarchy;
mod metrics;
/// Cluster-scale stress experiments (`stress::Experiment`), namespaced to avoid clashing with the
/// param-sweep [`Experiment`](experiment::Experiment) harness.
pub mod stress;
mod network;
mod observatory;
mod rng;
mod sim;
mod trace;

pub use cluster::{CELL_SIZE, Cluster, ClusterSnapshot};
pub use experiment::{Experiment, Grid, Params, Row, Scenario};
pub use fleet::{AlarmCounts, ClusterStats, FleetSnapshot, NodeState, RegimeCounts};
pub use hierarchy::Hierarchy;
pub use metrics::{Metrics, Observed, Report};
pub use network::NetworkModel;
pub use observatory::{
    CascadeForecast, CoherenceReading, CriticalSlowingDown, HealthField, forecast_cascade,
    lag1_autocorrelation, read, windowed_variance,
};
pub use rng::Rng;
pub use sim::{FrameObs, Sim};
pub use trace::{Trace, fmt_coord};

use fanos_field::Field;
use fanos_geometry::Plane;
use fanos_runtime::{Config, OverlayNode, Triple};

/// Spawn a full cell `PG(2, q)`: an [`OverlayNode`] at every point. Returns the node
/// coordinates indexed by point index (so `cell[i]` is the node at point `i`).
pub fn spawn_cell<F: Field + 'static>(sim: &mut Sim, config: Config) -> Vec<Triple> {
    spawn_partial_cell::<F>(sim, config, Plane::<F>::N as usize)
}

/// Spawn the first `size` points of a cell `PG(2, q)` (clamped to the plane size) — a *partial* cell,
/// for modelling a cell that is still filling (the "1 node, 2 nodes, 3 nodes …" progression) or a
/// fractional last cell in a [`Cluster`](crate::Cluster). The absent points read as down to the members
/// present, exactly as a real under-provisioned cell would sense them.
pub fn spawn_partial_cell<F: Field + 'static>(sim: &mut Sim, config: Config, size: usize) -> Vec<Triple> {
    let size = size.min(Plane::<F>::N as usize);
    let mut coords = Vec::with_capacity(size);
    for point in Plane::<F>::points().take(size) {
        let node = OverlayNode::<F>::new(point, config);
        coords.push(sim.add(Box::new(node)));
    }
    coords
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod scenarios {
    //! Research scenarios — the protocol's networked behaviour, validated end to end.
    use super::*;
    use fanos_diakrisis::{Fault, Verdict};
    use fanos_field::F2;
    use fanos_runtime::{Command, Duration};
    use std::collections::BTreeSet;

    fn test_config() -> Config {
        Config {
            heartbeat: Duration::from_millis(500),
            liveness_timeout: Duration::from_millis(1600),
            ..Config::default()
        }
    }

    /// Bring a Fano cell to steady state (all nodes exchanging heartbeats).
    fn established_cell(seed: u64) -> (Sim, Vec<Triple>) {
        let mut sim = Sim::new(seed);
        let cell = spawn_cell::<F2>(&mut sim, test_config());
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(2000));
        (sim, cell)
    }

    #[test]
    fn healthy_cell_diagnoses_healthy() {
        let (mut sim, _cell) = established_cell(1);
        // Diagnosis is a continuous reflex now (audit #122), so the run has been diagnosing all along;
        // reset and read just this round to check the cell's *current* verdict.
        sim.clear_report();
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        // A healthy cell only ever diagnoses Healthy, and all 7 nodes report.
        let verdicts: Vec<_> = sim.report().verdicts().collect();
        assert!(verdicts.iter().all(|(_, v)| **v == Verdict::Healthy));
        let reporters: BTreeSet<_> = verdicts.iter().map(|(n, _)| *n).collect();
        assert_eq!(reporters.len(), 7, "every node reports a verdict");
    }

    #[test]
    fn single_crash_is_localized_by_syndrome() {
        let (mut sim, cell) = established_cell(2);
        sim.crash(cell[5]); // node at Fano index 5 dies
        sim.run_for(Duration::from_millis(3000)); // its heartbeats time out
        // Reset before the final round so the report reflects the post-crash cell, not the healthy
        // verdicts the (now-crashed) node emitted while the continuous reflex was still running (#122).
        sim.clear_report();
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        // Surviving nodes pin the culprit to index 5 via the 3-bit syndrome (spec §6.3).
        assert!(
            sim.report()
                .any_verdict(&Verdict::Localized(Fault::Single(5)))
        );
        // The dead node does not report (it is crashed — silent in this round).
        assert!(sim.report().verdicts().all(|(who, _)| who != cell[5]));
    }

    #[test]
    fn two_crashes_resolve_as_a_pair() {
        let (mut sim, cell) = established_cell(3);
        sim.crash(cell[1]);
        sim.crash(cell[4]);
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        // The 7-theme layer resolves two faults exactly (spec §6.3, V21).
        assert!(
            sim.report()
                .any_verdict(&Verdict::Localized(Fault::Pair(1, 4)))
        );
    }

    #[test]
    fn three_crashes_escalate() {
        let (mut sim, cell) = established_cell(4);
        for &i in &[0usize, 1, 2] {
            sim.crash(cell[i]);
        }
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        // Three faults saturate the single-cell decoder → escalate (spec §6.3 stratification).
        assert!(
            sim.report()
                .verdicts()
                .any(|(_, v)| matches!(v, Verdict::Escalate(_)))
        );
    }

    #[test]
    fn rendezvous_delivers_in_one_hop_under_latency() {
        let (mut sim, cell) = established_cell(5);
        let before = sim.report().metrics.payloads_delivered;
        sim.inject(
            cell[0],
            Command::Send {
                to: cell[20 % 7],
                payload: b"hello".to_vec(),
            },
        );
        sim.run_for(Duration::from_millis(500));
        let report = sim.report();
        // Exactly one payload delivered — O(1) rendezvous, single hop.
        assert_eq!(report.metrics.payloads_delivered, before + 1);
        let (recv, sender, bytes) = report.deliveries().next().unwrap();
        assert_eq!(recv, cell[20 % 7]);
        assert_eq!(sender, cell[0]);
        assert_eq!(bytes, b"hello");
        // The sender computed the rendezvous line and reported it.
        assert!(
            report
                .notifications
                .iter()
                .any(|o| matches!(o.note, fanos_runtime::Notification::RendezvousLine(_)))
        );
    }

    #[test]
    fn partition_is_flagged_as_a_systemic_event() {
        let (mut sim, cell) = established_cell(6);
        // Split the cell 4 | 3.
        let group_a: BTreeSet<Triple> = [cell[0], cell[1], cell[2], cell[3]].into_iter().collect();
        let group_b: BTreeSet<Triple> = [cell[4], cell[5], cell[6]].into_iter().collect();
        sim.network_mut().partition([group_a, group_b]);
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        // With ≥3 peers unreachable across the cut, nodes escalate — a partition/systemic event.
        assert!(
            sim.report()
                .verdicts()
                .any(|(_, v)| matches!(v, Verdict::Escalate(_)))
        );
    }

    #[test]
    fn healed_partition_returns_to_healthy() {
        let (mut sim, cell) = established_cell(7);
        let a: BTreeSet<Triple> = [cell[0], cell[1], cell[2], cell[3]].into_iter().collect();
        let b: BTreeSet<Triple> = [cell[4], cell[5], cell[6]].into_iter().collect();
        sim.network_mut().partition([a, b]);
        sim.run_for(Duration::from_millis(3000));
        // Heal and let liveness recover.
        sim.network_mut().heal();
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        // The last round of diagnoses is healthy again.
        let last_seven: Vec<_> = sim.report().verdicts().rev().take(7).collect();
        assert!(last_seven.iter().all(|(_, v)| **v == Verdict::Healthy));
    }

    #[test]
    fn runs_are_reproducible_per_seed() {
        // The determinism contract: identical seed + scenario ⇒ byte-identical counters.
        fn run(seed: u64) -> Metrics {
            let (mut sim, cell) = established_cell(seed);
            sim.crash(cell[3]);
            sim.run_for(Duration::from_millis(3000));
            sim.inject_all(&Command::Diagnose);
            sim.settle();
            sim.report().metrics.clone()
        }
        assert_eq!(run(42), run(42), "same seed must reproduce exactly");
        assert_eq!(run(7), run(7));
        // Note: with zero loss the *counts* are seed-independent (every heartbeat frame is
        // sent regardless of jitter); the seed governs timing/order, and — with loss — which
        // frames drop. The next test exercises that.
    }

    #[test]
    fn loss_makes_seeds_diverge_but_stay_reproducible() {
        // Under packet loss, different seeds drop different frames, yet each seed is exact.
        fn run(seed: u64) -> (u64, u64) {
            let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(10), 0.3);
            let mut sim = Sim::with_network(seed, net);
            let _cell = spawn_cell::<F2>(&mut sim, test_config());
            sim.inject_all(&Command::StartHeartbeat);
            sim.run_for(Duration::from_millis(4000));
            let m = &sim.report().metrics;
            (m.frames_dropped, m.frames_delivered)
        }
        assert_eq!(run(42), run(42), "loss is deterministic per seed");
        assert_ne!(run(42), run(99), "different seeds drop different frames");
    }
}
