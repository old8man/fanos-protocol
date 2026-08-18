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
//! use fanos_field::F2;
//! use fanos_runtime::{Command, Config, Duration};
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
/// param-sweep [`Experiment`] harness.
pub mod fabric;
pub mod observe;
pub mod stress;
mod unified;
mod network;
mod observatory;
mod rng;
mod sim;
mod trace;

pub use cluster::{CELL_SIZE, Cluster, ClusterSnapshot};
pub use experiment::{Experiment, Grid, Params, Row, Scenario};
pub use fleet::{AlarmCounts, ClusterStats, FleetSnapshot, NodeState, RegimeCounts};
pub use hierarchy::Hierarchy;
pub use unified::UnifiedCluster;
pub use metrics::{Metrics, Observed, Report};
// The transport's four-valued verdict and the two size helpers travel with the model: a scenario asserting
// on an oversize drop (#195) needs to name the cause, and one packing a frame to the limit needs the very
// ceiling production reads with.
pub use network::{Delivery, NetworkModel, wire_ceiling, wire_len_of};
pub use observatory::{
    CascadeForecast, CoherenceReading, CriticalSlowingDown, ForecastVerdict, HealthField,
    forecast_cascade, lag1_autocorrelation, read, windowed_variance,
};
pub use rng::Rng;
pub use sim::{FrameObs, Sim};
pub use trace::{Trace, fmt_coord};

use fanos_field::Field;
use fanos_node::composition::{CellComposition, compose_engine};
use fanos_geometry::Plane;
use fanos_runtime::{Config, Triple};

/// Spawn a full cell `PG(2, q)`: an [`OverlayNode`](fanos_runtime::OverlayNode) at every point. Returns the node
/// coordinates indexed by point index (so `cell[i]` is the node at point `i`).
pub fn spawn_cell<F: Field + 'static>(sim: &mut Sim, config: Config) -> Vec<Triple> {
    spawn_partial_cell::<F>(sim, config, Plane::<F>::N as usize)
}

/// Spawn the first `size` points of a cell `PG(2, q)` (clamped to the plane size) — a *partial* cell,
/// for modelling a cell that is still filling (the "1 node, 2 nodes, 3 nodes …" progression) or a
/// fractional last cell in a [`Cluster`]. The absent points read as down to the members
/// present, exactly as a real under-provisioned cell would sense them.
pub fn spawn_partial_cell<F: Field + 'static>(sim: &mut Sim, config: Config, size: usize) -> Vec<Triple> {
    spawn_composed_cell::<F>(sim, &CellComposition::overlay_only(config), size)
}

/// Spawn `size` points of a cell running **the engine a deployment would run**.
///
/// The fidelity seam, and the one the standing rule ("the simulator differs from production only in transport")
/// requires. Before this, [`spawn_cell`] built a bare `OverlayNode` while `Node::start` layered an admission
/// gate, a beacon, a mixnet router and a threshold service on top of one — so the instrument meant to find
/// composition defects was, by construction, blind to the layer they live in. Every defect the 2026-07-28
/// audit found was in that layer.
///
/// Both paths now call `fanos_node::composition::compose_engine`. There is one function, so they cannot drift:
/// a role added to the composition appears here on the same commit.
pub fn spawn_composed_cell<F: Field + 'static>(
    sim: &mut Sim,
    what: &CellComposition,
    size: usize,
) -> Vec<Triple> {
    let size = size.min(Plane::<F>::N as usize);
    let mut coords = Vec::with_capacity(size);
    for point in Plane::<F>::points().take(size) {
        coords.push(sim.add(compose_engine::<F>(point, what, Some(sim_descriptor::<F>(point)))));
    }
    coords
}

/// A simulated node's **§80 signed descriptor** for `point` — what `Node::start` produces from its
/// certificate key, reproduced here from the point itself.
///
/// **The fidelity seam, again, and it is the same one.** The rule is that the simulator differs from
/// production *only in transport*; a cell whose members announce **unsigned** descriptors differs in
/// membership too, and the difference is invisible until something verifies one. It was: the measurement
/// that decides whether `require_self_certified_membership` can be turned on reads the learned-edge count
/// of a cell spawned here, and with no descriptor it could only ever report that the check refuses
/// everything — which was true of production until the producer landed and is now true only of this
/// fixture.
///
/// A deterministic identity per point, because a simulated node has no certificate to derive one from and a
/// scenario must replay. Everything else is the production call: `fanos_node::composition::sign_descriptor`,
/// over `fanos_runtime::descriptor_message`, so the bytes are the ones the engine rebuilds to verify.
fn sim_descriptor<F: Field>(point: fanos_geometry::Point<F>) -> (Vec<u8>, Vec<u8>) {
    let mut seed = Vec::with_capacity(24);
    seed.extend_from_slice(b"fanos-sim/descriptor/");
    seed.extend_from_slice(&fanos_geometry::encode_triple(point.coords()));
    let (secret, verifier) =
        fanos_pqcrypto::HybridSigSecret::generate(&mut fanos_pqcrypto::SeedRng::from_seed(&seed));
    fanos_node::composition::sign_descriptor::<F>(&(verifier.encode(), secret), point)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod scenarios {
    //! Research scenarios — the protocol's networked behaviour, validated end to end.
    use super::*;
    use fanos_diakrisis::{Fault, Verdict};
    use fanos_field::F2;

    #[test]
    fn a_composed_cell_still_diagnoses_like_a_bare_one() {
        // A smoke test, and named as one after its first version claimed more. It asserts that composing extra
        // roles onto the overlay does not cost the reflex underneath — a real thing to check, and *not* a check
        // that the simulator composes like production: a bare overlay localizes this crash identically, so
        // substituting one for the other leaves this test green. Measured, by doing exactly that.
        //
        // The seam itself is a property of the source — both paths calling one function — so it is checked
        // there, by `fanos-cli/tests/composition_seam.rs`.
        let mut sim = Sim::new(0x5EED_C0DE);
        let what = CellComposition {
            admission: Some(4),
            ..CellComposition::overlay_only(Config::default())
        };
        let cell = spawn_composed_cell::<F2>(&mut sim, &what, 7);
        assert_eq!(cell.len(), 7, "a full Fano cell");

        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(2000));
        sim.crash(cell[5]);
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();

        // The composed cell still diagnoses: a node that prices admission has not lost its reflex, and it pins
        // the same culprit by the same 3-bit syndrome.
        assert!(
            sim.report().any_verdict(&Verdict::Localized(Fault::Single(5))),
            "a composed cell must still localize the crash — it is the same overlay underneath"
        );
    }
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
    /// A cut surfaces as an **escalation**, not as `Verdict::Partition` — and that is correct, not a gap.
    ///
    /// From either side a cut is a set of silent coordinates, which is exactly what a mass crash is. The two
    /// hand a node the identical `degraded` and `healthy_lines`
    /// (`fanos_diakrisis::tests::a_mass_crash_and_one_side_of_a_cut_are_the_same_observation`), so no
    /// single-node verdict can separate them. Escalating hands the decision to the parent, the only observer
    /// that sees both sides. Making this arm answer `Partition` instead was tried and reverted: it relabelled
    /// every three-node crash, so a cell that had lost three members stopped escalating for repair.
    fn a_cut_surfaces_as_an_escalation_because_one_node_cannot_tell_it_from_a_mass_crash() {
        let (mut sim, cell) = established_cell(6);
        // Split the cell 4 | 3.
        let group_a: BTreeSet<Triple> = [cell[0], cell[1], cell[2], cell[3]].into_iter().collect();
        let group_b: BTreeSet<Triple> = [cell[4], cell[5], cell[6]].into_iter().collect();
        sim.network_mut().partition([group_a, group_b]);
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        // With ≥3 peers unreachable across the cut, the decoder saturates and nodes escalate.
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
