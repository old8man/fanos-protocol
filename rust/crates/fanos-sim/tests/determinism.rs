//! The simulator's **determinism & replay contract**, stated at trace strength.
//!
//! `design-platform.md` §8 names the platform's load-bearing guarantee: `(seed, inputs) →
//! byte-identical run`. It is what makes "the devnet is production", incident forensics by replay, and
//! time-travel debugging real rather than aspirational — a bug seen once is reproducible forever from
//! its `(seed, ordered Inputs)`. The inline `sim` tests check the contract at *counter* granularity
//! (aggregate [`Metrics`](fanos_sim::Metrics)); this file checks the **strong** form: the full ordered
//! causal trace — every dispatched event and performed effect, including DIAKRISIS verdicts —
//! reproduces byte-for-byte.
//!
//! The distinction matters. Counter-equality can hold while event *order* diverges (two runs sending
//! the same frames in a different sequence tally identically); trace-equality cannot. So the trace is
//! the honest witness of the contract, and this test is the one a third-party protocol author cites
//! when they inherit `fanos replay`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{Metrics, NetworkModel, Sim, spawn_cell};

/// Heartbeat/liveness timings chosen so a crash times out and recovery re-establishes within the run.
fn contract_config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

/// One rich, RNG-driven scenario over a Fano cell — heartbeats under 30% packet loss, DHT store/read
/// from different members, a crash → liveness-timeout → recover churn, then a cell-wide diagnose. It
/// touches jitter/timing, content-addressed routing, liveness/healing, and DIAKRISIS, so the run
/// genuinely depends on the seed. Returns the full trace dump (the causal log the contract is stated
/// over) and the final metrics.
fn run_scenario(seed: u64) -> (String, Metrics) {
    let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(10), 0.3);
    let mut sim = Sim::with_network(seed, net);
    sim.enable_trace(true);
    let cell = spawn_cell::<F2>(&mut sim, contract_config());

    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(1500));

    // DHT traffic: store at one member, read at another (content-address routing + replication).
    sim.inject(
        cell[0],
        Command::Put {
            key: b"k/determinism".to_vec(),
            value: b"replay me".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));
    sim.inject(
        cell[3],
        Command::Get {
            key: b"k/determinism".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));

    // Churn: lose a node, let its heartbeats time out, then bring it back.
    sim.crash(cell[5]);
    sim.run_for(Duration::from_millis(2000));
    sim.recover(cell[5]);
    sim.run_for(Duration::from_millis(1000));

    // DIAKRISIS verdicts (recorded as notifications, so trace-identity ⇒ verdict-identity).
    sim.inject_all(&Command::Diagnose);
    sim.settle();

    (sim.trace().dump(), sim.report().metrics.clone())
}

/// The contract: identical seed + inputs reproduce the run **byte-for-byte** — the whole causal trace,
/// not merely the counters — so `fanos replay` reconstructs any incident bit-for-bit.
#[test]
fn a_run_is_byte_identical_to_its_replay() {
    let (trace_a, metrics_a) = run_scenario(42);
    let (trace_b, metrics_b) = run_scenario(42);

    assert!(
        !trace_a.is_empty(),
        "the scenario must record a non-trivial trace, or the contract is vacuous"
    );
    assert_eq!(
        trace_a, trace_b,
        "identical seed + inputs must reproduce the run byte-for-byte"
    );
    assert_eq!(
        metrics_a, metrics_b,
        "the final metrics reproduce exactly too"
    );
}

/// Non-vacuity: the seed genuinely drives the run. Under packet loss two seeds drop different frames,
/// so their traces must diverge — otherwise byte-identity above would be trivially true of everything.
#[test]
fn different_seeds_diverge_under_loss() {
    let (trace_42, _) = run_scenario(42);
    let (trace_99, _) = run_scenario(99);

    assert_ne!(
        trace_42, trace_99,
        "distinct seeds must produce distinct runs under loss"
    );
}

/// Replay is stable across many rounds, not just twice: a scenario re-run repeatedly stays pinned to
/// its first trace. This is the property `fanos replay` relies on — no drift, no accumulated state
/// leaking between fresh `Sim`s.
#[test]
fn replay_is_stable_across_rounds() {
    let (reference, _) = run_scenario(7);
    for round in 0..5 {
        let (again, _) = run_scenario(7);
        assert_eq!(
            reference, again,
            "round {round}: every replay of seed 7 matches the first"
        );
    }
}
