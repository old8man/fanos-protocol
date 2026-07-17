//! `catastrophe` — drive the cell through catastrophic regimes and print what the nodes do, so
//! the robustness boundaries are visible before they are codified as tests. This is the "operator
//! at the console" view: loss tolerance, churn convergence, and scale.
//!
//! Run: `cargo run -p fanos-sim --example catastrophe`
#![allow(clippy::print_stdout, clippy::indexing_slicing, clippy::unwrap_used)]

use fanos_diakrisis::Verdict;
use fanos_field::{F2, F7, F13};
use fanos_runtime::{Command, Config, Duration, Triple};
use fanos_sim::{NetworkModel, Sim, spawn_cell};

fn cfg() -> Config {
    Config::default()
}

/// How many false PeerDowns a *healthy* (no-crash) cell reports under a given loss rate — the
/// liveness layer's false-positive rate.
fn false_downs_under_loss(loss: f64, seed: u64) -> u64 {
    let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(10), loss);
    let mut sim = Sim::with_network(seed, net);
    let _cell = spawn_cell::<F2>(&mut sim, cfg());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(10_000)); // 20 heartbeat rounds
    sim.report().metrics.peer_downs
}

fn loss_sweep() {
    println!(
        "== Loss tolerance (healthy 7-cell, 20 heartbeat rounds, liveness_timeout=3.2 rounds) =="
    );
    println!("  loss   false PeerDowns (median of 5 seeds)");
    for pct in [0, 10, 20, 30, 40, 50, 60, 70, 80] {
        let loss = f64::from(pct) / 100.0;
        let mut counts: Vec<u64> = (0..5)
            .map(|s| false_downs_under_loss(loss, 100 + s))
            .collect();
        counts.sort_unstable();
        println!("  {:>3}%   {}", pct, counts[2]);
    }
    println!();
}

fn churn_storm() {
    println!("== Churn storm (repeated crash/recover), then settle ==");
    let mut sim = Sim::new(0xCEED);
    let cell = spawn_cell::<F2>(&mut sim, cfg());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    // 8 rounds of: crash one node, run, recover it (with re-bootstrap), run.
    for round in 0..8u64 {
        let victim = cell[(round as usize * 3 + 1) % 7];
        sim.crash(victim);
        sim.run_for(Duration::from_millis(1500));
        sim.recover(victim);
        sim.inject(victim, Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(1500));
    }
    sim.run_for(Duration::from_millis(3000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    let last: Vec<Verdict> = sim
        .report()
        .verdicts()
        .rev()
        .take(7)
        .map(|(_, v)| v.clone())
        .collect();
    let healthy = last.iter().filter(|v| **v == Verdict::Healthy).count();
    println!("  after 8 churn rounds: {healthy}/7 nodes diagnose Healthy");
    println!("  final verdicts: {last:?}\n");
}

fn scale_report<F: fanos_field::Field + 'static>(name: &str) {
    let mut sim = Sim::new(7);
    let cell = spawn_cell::<F>(&mut sim, cfg());
    let n = cell.len();
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(3000));
    // One rendezvous send between two far-apart points.
    let before = sim.report().metrics.payloads_delivered;
    sim.inject(
        cell[0],
        Command::Send {
            to: cell[n / 2],
            payload: b"scale".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));
    let delivered = sim.report().metrics.payloads_delivered - before;
    let frames = sim.report().metrics.frames_sent;
    println!(
        "  {name:>4}: {n:>3} nodes, {frames:>6} frames exchanged, rendezvous delivered={delivered}"
    );
}

fn scale() {
    println!("== Scale (establish liveness + one rendezvous) ==");
    scale_report::<F2>("q=2");
    scale_report::<F7>("q=7");
    scale_report::<F13>("q=13");
    println!();
}

/// Does a *true* crash still get detected + healed under loss? (Corroboration must not mask it.)
fn death_detection_under_loss() {
    println!("== True-death detection under loss (crash node 5, 15 s budget) ==");
    println!("  loss   detected+healed   detection latency");
    for pct in [0, 20, 40, 60, 70, 80] {
        let loss = f64::from(pct) / 100.0;
        let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(10), loss);
        let mut sim = Sim::with_network(0xD1E, net);
        let cell = spawn_cell::<F2>(&mut sim, cfg());
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(2000));
        let crash_at = sim.now().as_nanos();
        sim.crash(cell[5]);
        // Poll in 500 ms steps until node 0 reports node 5 down (or budget exhausted).
        let mut detected_at = None;
        for _ in 0..30 {
            sim.run_for(Duration::from_millis(500));
            let downs = sim.report().notifications.iter().any(
                |o| matches!(&o.note, fanos_runtime::Notification::PeerDown(p) if *p == cell[5]),
            );
            if downs {
                detected_at = Some(sim.now().as_nanos());
                break;
            }
        }
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        let healed = sim.report().any_repaired(cell[5]);
        let latency = detected_at.map_or("—    (>15s)".to_string(), |t| {
            format!("{:>5} ms", (t - crash_at) / 1_000_000)
        });
        println!(
            "  {:>3}%   {:<15}   {}",
            pct,
            if healed { "yes" } else { "no" },
            latency
        );
    }
    println!();
}

fn main() {
    println!("FANOS catastrophic-regime probe\n");
    loss_sweep();
    death_detection_under_loss();
    churn_storm();
    scale();
    let _ = (Triple::default(),); // keep the import honest across refactors
}
