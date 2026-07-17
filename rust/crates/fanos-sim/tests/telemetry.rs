//! End-to-end telemetry: every node's **mandatory** self-observation flows through the *real*
//! `OverlayNode` engine under the simulator (the monism — the same production code, a substituted
//! transport). Each diagnosis emits a `CoherenceFrame`; here we decode those frames off the wire and
//! assert the load-bearing 3-bit syndrome localizes the very fault the DIAKRISIS verdict does.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_diakrisis::{Fault, Verdict};
use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration, Notification};
use fanos_sim::{Sim, spawn_cell};
use fanos_telemetry::CoherenceFrame;

fn cfg() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

/// Every decoded `CoherenceFrame` in the run report, in order.
fn observed_frames(sim: &Sim) -> Vec<CoherenceFrame> {
    sim.report()
        .notifications
        .iter()
        .filter_map(|o| match &o.note {
            Notification::Observed(bytes) => CoherenceFrame::decode(bytes),
            _ => None,
        })
        .collect()
}

#[test]
fn a_healthy_cell_observes_itself_with_no_fault() {
    let mut sim = Sim::new(7);
    let _cell = spawn_cell::<F2>(&mut sim, cfg());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000)); // establish mutual liveness
    sim.inject_all(&Command::Diagnose);
    sim.settle();

    let frames = observed_frames(&sim);
    assert!(
        !frames.is_empty(),
        "diagnosis is not possible without observing"
    );
    assert!(sim.report().metrics.observations >= 1);
    // A fully-live cell: every frame's syndrome is 0 (healthy) and reads integrated.
    assert!(
        frames.iter().all(|f| !f.is_faulted()),
        "no fault localized in a healthy cell"
    );
    // All nodes agree on which cell they describe.
    let id = frames[0].cell_id;
    assert!(
        frames.iter().all(|f| f.cell_id == id),
        "one cell id across the cell"
    );
}

#[test]
fn observe_is_sense_only_no_verdict_no_healing() {
    let mut sim = Sim::new(11);
    let cell = spawn_cell::<F2>(&mut sim, cfg());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    sim.crash(cell[3]); // a real fault is present...
    sim.run_for(Duration::from_millis(3000));
    // ...but a passive monitor only *observes* — it must not diagnose or heal.
    sim.inject_all(&Command::Observe);
    sim.settle();

    assert!(
        sim.report().metrics.observations >= 1,
        "frames were emitted"
    );
    assert_eq!(
        sim.report().verdicts().count(),
        0,
        "Observe emits no verdict"
    );
    let m = &sim.report().metrics;
    assert_eq!(
        (
            m.reroutes,
            m.repairs,
            m.quarantines,
            m.escalations,
            m.decouples
        ),
        (0, 0, 0, 0, 0),
        "Observe triggers no healing action"
    );
    // The observation still carries the true syndrome (the crash is visible, just not acted on).
    let frames = observed_frames(&sim);
    assert!(frames.iter().any(CoherenceFrame::is_faulted));
}

#[test]
fn a_crash_is_localized_in_the_coherence_frame() {
    let mut sim = Sim::new(3);
    let cell = spawn_cell::<F2>(&mut sim, cfg());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    sim.crash(cell[5]);
    sim.run_for(Duration::from_millis(3000)); // node 5's heartbeats time out
    sim.inject_all(&Command::Diagnose);
    sim.settle();

    // The verdict localizes node 5 (the established, known-correct diagnosis).
    assert!(
        sim.report()
            .any_verdict(&Verdict::Localized(Fault::Single(5))),
        "verdict localizes the crash"
    );
    // And the mandatory coherence frame carries the same fault: at least one surviving node emits a
    // frame whose 3-bit syndrome is non-zero (the crash, localized), proving the telemetry plane and
    // the diagnosis agree.
    let frames = observed_frames(&sim);
    assert!(
        sim.report().metrics.observations >= 1,
        "frames were emitted"
    );
    assert!(
        frames.iter().any(CoherenceFrame::is_faulted),
        "a surviving node's syndrome localizes the fault"
    );
    // Every surviving node sees the same down node, so all faulted frames carry one non-zero
    // syndrome — the Fano/Hamming localizer of point 5 (the verdict above fixes that it *is* 5).
    let syndromes: Vec<u8> = frames
        .iter()
        .filter(|f| f.is_faulted())
        .map(|f| f.syndrome)
        .collect();
    let first = syndromes[0];
    assert!(
        first != 0 && syndromes.iter().all(|&s| s == first),
        "all faulted frames localize the same point"
    );
}
