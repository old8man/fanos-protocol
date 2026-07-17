//! `fanos-sim-demo` — a narrated run of the deterministic simulator.
//!
//! Spins up a real Fano cell of node engines, then walks through crash localization, a
//! two-fault case, a partition, rendezvous, and a reproducibility check — printing what the
//! nodes observe. The same engine code would run over a real transport.
#![allow(clippy::print_stdout, clippy::indexing_slicing, clippy::unwrap_used)]

use std::collections::BTreeSet;

use fanos_diakrisis::Verdict;
use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration, Triple};
use fanos_sim::{Sim, spawn_cell};

fn config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

fn established(seed: u64) -> (Sim, Vec<Triple>) {
    let mut sim = Sim::new(seed);
    let cell = spawn_cell::<F2>(&mut sim, config());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    (sim, cell)
}

fn verdicts_line(sim: &Sim) -> String {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for (_, v) in sim.report().verdicts() {
        *counts.entry(format!("{v:?}")).or_default() += 1;
    }
    counts
        .iter()
        .map(|(v, n)| format!("{n}×{v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn main() {
    println!("\nFANOS network simulator — real node engines, substituted transport\n");

    // 1. Crash localization — with a trace excerpt of the causal chain.
    {
        let mut sim = Sim::new(2);
        let cell = spawn_cell::<F2>(&mut sim, config());
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(2000));
        println!(" scenario 1 — crash localization (7-node Fano cell)");
        sim.enable_trace(true); // record from here on
        sim.crash(cell[5]);
        let dead = fanos_sim::fmt_coord(cell[5]);
        println!("   · node {dead} (Fano index 5) crashes at t=2s");
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        println!("   · verdicts: {}", verdicts_line(&sim));
        println!(
            "   · localized index 5: {}",
            sim.report()
                .any_verdict(&Verdict::Localized(fanos_diakrisis::Fault::Single(5)))
        );
        // Investigate the log: how one neighbour comes to declare the dead node down.
        println!("   · trace (a neighbour's view of the dead node, then a verdict):");
        let mut shown = 0;
        for line in sim.trace().lines() {
            let relevant =
                line.contains(&dead) || line.contains("PeerDown") || line.contains("Verdict");
            if relevant && shown < 8 {
                println!("       {line}");
                shown += 1;
            }
        }
    }

    // 2. Two-fault resolution.
    {
        let (mut sim, cell) = established(3);
        println!("\n scenario 2 — two simultaneous crashes (7-theme layer)");
        sim.crash(cell[1]);
        sim.crash(cell[4]);
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        println!(
            "   · crashed indices 1 and 4 → verdicts: {}",
            verdicts_line(&sim)
        );
    }

    // 3. Partition.
    {
        let (mut sim, cell) = established(6);
        println!("\n scenario 3 — network partition (4 | 3)");
        let a: BTreeSet<Triple> = [cell[0], cell[1], cell[2], cell[3]].into_iter().collect();
        let b: BTreeSet<Triple> = [cell[4], cell[5], cell[6]].into_iter().collect();
        sim.network_mut().partition([a, b]);
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        println!("   · verdicts across the cut: {}", verdicts_line(&sim));
        sim.network_mut().heal();
        sim.run_for(Duration::from_millis(3000));
        sim.inject_all(&Command::Diagnose);
        sim.settle();
        let healed: Vec<_> = sim.report().verdicts().rev().take(7).collect();
        println!(
            "   · after healing, last round healthy: {}",
            healed.iter().all(|(_, v)| **v == Verdict::Healthy)
        );
    }

    // 4. Rendezvous.
    {
        let (mut sim, cell) = established(5);
        println!("\n scenario 4 — O(1) rendezvous under latency");
        sim.inject(
            cell[0],
            Command::Send {
                to: cell[6],
                payload: b"hello".to_vec(),
            },
        );
        sim.run_for(Duration::from_millis(500));
        let m = &sim.report().metrics;
        println!(
            "   · one payload sent node0 → node6, delivered={} (single hop)",
            m.payloads_delivered
        );
    }

    // 5. Reproducibility.
    {
        println!("\n scenario 5 — determinism (same seed ⇒ identical run)");
        let run = |seed: u64| {
            let (mut sim, cell) = established(seed);
            sim.crash(cell[3]);
            sim.run_for(Duration::from_millis(3000));
            sim.report().metrics.frames_sent
        };
        println!(
            "   · seed 42 twice: {} == {} ({})",
            run(42),
            run(42),
            run(42) == run(42)
        );
    }

    println!(
        "\n  The engines above are the production sans-I/O node code; only the driver differs.\n"
    );
}
