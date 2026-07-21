//! **Stochastic invariant harness** — Monte-Carlo adversarial coverage of the whole cell.
//!
//! The hand-written scenarios (`healing`, `byzantine`, `storage`, …) each pin *one* situation. This
//! file instead samples a *distribution* of adversarial situations — random loss, random fault sets at
//! random times, random DHT floods, random forged frames — and asserts the load-bearing **safety and
//! liveness invariants hold across the whole sample**. It is the maximal-coverage tier: every attack
//! surface from a single logical fault to a saturating cascade, swept by seed rather than enumerated by
//! hand.
//!
//! The platform's determinism contract (`determinism.rs`) is what makes this rigorous rather than
//! flaky: each scenario is *derived from its seed*, so a violated invariant is not a heisenbug — it is
//! a seed that reproduces the counterexample byte-for-byte, forever. The Monte-Carlo counts below are
//! therefore fixed numbers, not samples of a random variable: the suite passes or fails deterministically.
//!
//! Invariants (each swept over many seeds):
//!   I1  determinism            — a random adversarial scenario replays to identical metrics.
//!   I2  syndrome soundness     — self-diagnosis never blames a *live* node (clean channel).
//!   I3  saturation escalates   — ≥3 simultaneous faults escalate, never a confident mislocalization.
//!   I4  replicated availability— a stored value survives losing any minority of the cell.
//!   I5  malformed-input safety — forged/garbage frames never crash or wedge an honest node.
//!   I6  no spurious quarantine — loss and crashes alone never quarantine an honest node.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_diakrisis::{Fault, Verdict};
use fanos_field::F2;
use fanos_geometry::fano;
use fanos_runtime::{Command, Config, Duration, Triple};
use fanos_sim::{NetworkModel, Rng, Sim, spawn_cell};

/// Fano cell size.
const N: usize = fano::N; // 7

/// Monte-Carlo sample size per invariant. Large enough that random fault placement covers every
/// point and every small fault set many times; small enough that the whole file runs in well under a
/// second (virtual time).
const SAMPLES: u64 = 160;

/// Heartbeat/liveness timings under which an injected crash reliably times out within a run, matching
/// the hand-written scenarios so the two tiers agree on cell dynamics.
fn cell_config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

/// `k` distinct Fano point indices drawn from `0..N` (a random fault/crash set).
fn distinct_indices(rng: &mut Rng, k: usize) -> Vec<usize> {
    let mut pool: Vec<usize> = (0..N).collect();
    let mut out = Vec::with_capacity(k);
    for _ in 0..k.min(N) {
        let j = rng.below(pool.len() as u64) as usize;
        out.push(pool.swap_remove(j));
    }
    out
}

/// Bring a healthy cell to steady state at `seed` on a clean (lossless) channel.
fn clean_cell(seed: u64) -> (Sim, Vec<Triple>) {
    let mut sim = Sim::new(seed);
    let cell = spawn_cell::<F2>(&mut sim, cell_config());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    (sim, cell)
}

/// The Fano index of a coordinate in `cell` (its point number 0..7).
fn index_of(cell: &[Triple], coord: Triple) -> usize {
    cell.iter().position(|&c| c == coord).unwrap()
}

// ---------------------------------------------------------------------------------------------------
// I1 — Determinism across a distribution of adversarial scenarios.
// ---------------------------------------------------------------------------------------------------

/// Drive one *random* adversarial scenario (loss, timed crashes, DHT flood, forged frames) and return
/// its final metrics. Every random choice is drawn from `Rng::new(seed)` and the transport loss/jitter
/// is seeded by the same `seed`, so the whole run is a pure function of `seed`.
fn adversarial_metrics(seed: u64) -> fanos_sim::Metrics {
    let mut rng = Rng::new(seed);
    let loss = 0.4 * rng.unit();
    let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(10), loss);
    let mut sim = Sim::with_network(seed, net);
    let cell = spawn_cell::<F2>(&mut sim, cell_config());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(1500));

    // A random DHT flood.
    for _ in 0..=rng.below(6) {
        let who = cell[rng.below(N as u64) as usize];
        let key = rng.next_u64().to_be_bytes().to_vec();
        sim.inject(
            who,
            Command::Put {
                key: key.clone(),
                value: rng.next_u64().to_be_bytes().to_vec(),
            },
        );
        sim.inject(cell[rng.below(N as u64) as usize], Command::Get { key });
    }
    sim.run_for(Duration::from_millis(500));

    // Random timed crashes (bounded so the cell stays a cell).
    let crash_count = rng.below(3) as usize;
    for &i in &distinct_indices(&mut rng, crash_count) {
        sim.run_for(Duration::from_millis(200 + rng.below(600)));
        sim.crash(cell[i]);
    }

    // Random forged frames from random members (the Byzantine hook).
    for _ in 0..rng.below(8) {
        let len = rng.below(64) as usize;
        let frame: Vec<u8> = (0..len).map(|_| rng.below(256) as u8).collect();
        sim.inject_frame(
            cell[rng.below(N as u64) as usize],
            cell[rng.below(N as u64) as usize],
            frame,
        );
    }
    sim.run_for(Duration::from_millis(2500));
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    sim.report().metrics.clone()
}

#[test]
fn i1_determinism_holds_across_random_adversarial_scenarios() {
    // Breadth companion to determinism.rs (which proves trace-depth on one scenario): across a whole
    // distribution of adversarial scenarios, each seed replays to identical metrics.
    for seed in 0..SAMPLES {
        let a = adversarial_metrics(seed);
        let b = adversarial_metrics(seed);
        assert_eq!(
            a, b,
            "seed {seed}: an adversarial scenario must replay to identical metrics"
        );
    }
}

// ---------------------------------------------------------------------------------------------------
// I2 — Syndrome soundness: self-diagnosis never blames a live node.
// ---------------------------------------------------------------------------------------------------

/// The set of point indices a verdict *accuses*, if it is a node localization (else empty).
fn accused(verdict: &Verdict) -> Vec<usize> {
    match verdict {
        Verdict::Localized(Fault::Single(i)) => vec![*i],
        Verdict::Localized(Fault::Pair(i, j)) => vec![*i, *j],
        _ => Vec::new(),
    }
}

#[test]
fn i2_syndrome_never_blames_a_live_node() {
    // The critical safety property of self-diagnosis: on a clean channel, whatever a survivor
    // concludes, it never localizes a fault onto a node that is actually alive. Swept over random
    // crash sets of size 0..=2 (the sizes the single-cell decoder is meant to resolve exactly).
    for seed in 0..SAMPLES {
        let mut rng = Rng::new(seed);
        let k = rng.below(3) as usize; // 0, 1, or 2
        let crashed = distinct_indices(&mut rng, k);

        let (mut sim, cell) = clean_cell(seed);
        for &i in &crashed {
            sim.crash(cell[i]);
        }
        // Generous multiple of the liveness timeout so every crash is fully observed.
        sim.run_for(Duration::from_millis(4000));
        // Read only this final round; the continuous reflex (#122) has been diagnosing throughout, so a
        // since-crashed node's earlier verdicts would otherwise pollute the "crashed node is silent" check.
        sim.clear_report();
        sim.inject_all(&Command::Diagnose);
        sim.settle();

        let mut detected = false;
        for (who, verdict) in sim.report().verdicts() {
            // A crashed node does not report; only survivors' verdicts are checked.
            assert!(
                !crashed.contains(&index_of(&cell, who)),
                "seed {seed}: a crashed node reported a verdict"
            );
            for a in accused(verdict) {
                assert!(
                    crashed.contains(&a),
                    "seed {seed}: verdict {verdict:?} blames live point {a} (crashed = {crashed:?})"
                );
                detected = true;
            }
        }
        // Completeness (soft): a non-empty fault set is noticed by *someone* (localized or escalated),
        // never silently ignored.
        if !crashed.is_empty() {
            let noticed = detected
                || sim
                    .report()
                    .verdicts()
                    .any(|(_, v)| !matches!(v, Verdict::Healthy));
            assert!(
                noticed,
                "seed {seed}: crash set {crashed:?} went entirely unnoticed"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// I3 — Saturation: three or more simultaneous faults escalate, never a confident mislocalization.
// ---------------------------------------------------------------------------------------------------

#[test]
fn i3_three_or_more_faults_escalate() {
    // Beyond the single-cell decoder's resolving power (spec §6.3 stratification): a survivor must
    // escalate (or report a systemic/partition event) rather than confidently name the wrong pair.
    // Swept over random fault sets of size 3..=4.
    for seed in 0..SAMPLES {
        let mut rng = Rng::new(seed);
        let k = 3 + rng.below(2) as usize; // 3 or 4
        let crashed = distinct_indices(&mut rng, k);

        let (mut sim, cell) = clean_cell(seed);
        for &i in &crashed {
            sim.crash(cell[i]);
        }
        sim.run_for(Duration::from_millis(4000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();

        // Soundness still holds — no live node is ever accused …
        for (_, verdict) in sim.report().verdicts() {
            for a in accused(verdict) {
                assert!(
                    crashed.contains(&a),
                    "seed {seed}: saturating fault set {crashed:?} still blames live point {a}"
                );
            }
        }
        // … and the saturation is recognized: someone escalates or flags a systemic/partition event.
        let saturated = sim.report().verdicts().any(|(_, v)| {
            matches!(
                v,
                Verdict::Escalate(_) | Verdict::Partition | Verdict::Systemic
            )
        });
        assert!(
            saturated,
            "seed {seed}: {k} simultaneous faults must saturate the decoder into escalation"
        );
    }
}

// ---------------------------------------------------------------------------------------------------
// I4 — Replicated availability: a stored value survives losing any minority of the cell.
// ---------------------------------------------------------------------------------------------------

#[test]
fn i4_a_replicated_value_survives_random_node_loss() {
    // A Put replicates to every member (LRC, spec §L4). So after the fan-out settles, crashing any
    // set that leaves the reader alive still serves the value — swept over random keys, random writer,
    // random crash sets, random reader.
    for seed in 0..SAMPLES {
        let mut rng = Rng::new(seed);
        let (mut sim, cell) = clean_cell(seed);

        let key = rng.next_u64().to_be_bytes().to_vec();
        let value = rng.next_u64().to_be_bytes().to_vec();
        sim.inject(
            cell[rng.below(N as u64) as usize],
            Command::Put {
                key: key.clone(),
                value: value.clone(),
            },
        );
        sim.run_for(Duration::from_millis(1500)); // let replication reach every live member
        assert!(
            sim.report().metrics.stores >= 1,
            "seed {seed}: the put must be acknowledged before we test survival"
        );

        // Crash a random tolerable-loss set. The `[7,3,4]` projective LRC (§L4) recovers a value from ANY
        // ≤3 simultaneous point losses (K=3 of N=7 shards suffice), so crash up to 3, always leaving a
        // distinct reader alive. (A 4-loss survives too UNLESS it is a hyperoval stopping set; ≤3 is the
        // clean always-recoverable bound this invariant asserts — crashing 4+ would exceed the code's
        // designed tolerance and legitimately lose the value.)
        let crash_count = rng.below(4) as usize; // 0..=3, the LRC's always-recoverable loss count
        let crashed = distinct_indices(&mut rng, crash_count);
        for &i in &crashed {
            sim.crash(cell[i]);
        }
        let reader = (0..N).find(|i| !crashed.contains(i)).unwrap();
        sim.run_for(Duration::from_millis(500));

        sim.inject(cell[reader], Command::Get { key });
        sim.run_for(Duration::from_millis(1500));

        let got = sim.report().retrievals().last().map(|(_, _, v)| v);
        assert_eq!(
            got,
            Some(Some(&value[..])),
            "seed {seed}: value must survive crashing {crashed:?} (reader = point {reader})"
        );
    }
}

// ---------------------------------------------------------------------------------------------------
// I5 — Malformed-input safety: forged/garbage frames never crash or wedge an honest node.
// ---------------------------------------------------------------------------------------------------

#[test]
fn i5_forged_frames_never_crash_or_wedge_a_node() {
    // The logical attack surface: an authenticated peer emits arbitrary bytes. The validating decoders
    // must reject them without panicking and without corrupting state — proven by the cell remaining
    // *functional* (a legit put/get still works) after absorbing a heavy forged-frame flood.
    for seed in 0..SAMPLES {
        let mut rng = Rng::new(seed);
        let (mut sim, cell) = clean_cell(seed);

        // Flood random garbage frames between random members, interleaved with time.
        for _ in 0..(8 + rng.below(24)) {
            let len = rng.below(96) as usize;
            let frame: Vec<u8> = (0..len).map(|_| rng.below(256) as u8).collect();
            sim.inject_frame(
                cell[rng.below(N as u64) as usize],
                cell[rng.below(N as u64) as usize],
                frame,
            );
            if rng.chance(0.3) {
                sim.run_for(Duration::from_millis(50));
            }
        }
        sim.run_for(Duration::from_millis(500));

        // The node is not wedged: a legitimate store/read still completes end to end.
        let key = rng.next_u64().to_be_bytes().to_vec();
        let value = b"still-alive".to_vec();
        sim.inject(
            cell[rng.below(N as u64) as usize],
            Command::Put {
                key: key.clone(),
                value: value.clone(),
            },
        );
        sim.run_for(Duration::from_millis(1000));
        sim.inject(cell[rng.below(N as u64) as usize], Command::Get { key });
        sim.run_for(Duration::from_millis(1000));

        let got = sim.report().retrievals().last().map(|(_, _, v)| v);
        assert_eq!(
            got,
            Some(Some(&value[..])),
            "seed {seed}: an honest exchange must still succeed after a forged-frame flood"
        );
    }
}

// ---------------------------------------------------------------------------------------------------
// I6 — No spurious quarantine: loss and crashes alone never quarantine an honest node.
// ---------------------------------------------------------------------------------------------------

#[test]
fn i6_honest_nodes_are_never_spuriously_quarantined() {
    // Quarantine is the response to *Byzantine forgery*, not to loss or crash. Under heavy loss and
    // random crashes, but no forged frames, no honest node is ever quarantined — a false quarantine
    // would be a partition-inducing correctness bug.
    for seed in 0..SAMPLES {
        let mut rng = Rng::new(seed);
        let loss = 0.5 * rng.unit();
        let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(10), loss);
        let mut sim = Sim::with_network(seed, net);
        let cell = spawn_cell::<F2>(&mut sim, cell_config());
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(2000));

        let crash_count = rng.below(3) as usize;
        for &i in &distinct_indices(&mut rng, crash_count) {
            sim.crash(cell[i]);
        }
        sim.run_for(Duration::from_millis(4000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();

        assert_eq!(
            sim.report().metrics.quarantines,
            0,
            "seed {seed}: loss/crash alone must never quarantine an honest node"
        );
    }
}
