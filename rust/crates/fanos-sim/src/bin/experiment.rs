//! `fanos-sim-experiment` — run a simulator scenario over a parameter grid and emit a CSV/JSON artifact
//! (audit S-P2). Turns a research question into a **command**, not a recompile:
//!
//! ```text
//! fanos-sim-experiment --scenario diakrisis-resilience \
//!     --param crashes=1,2,3 --seeds 8 --out resilience.csv
//! ```
//!
//! `--param name=v1,v2,…` (repeatable) defines the grid axes (their Cartesian product is the run set);
//! `--seeds N` repeats each point for seeds `0..N`; `--out FILE` writes the artifact (else stdout);
//! `--json` selects JSON over CSV. Each scenario is a deterministic `(params, seed) → metrics` over the real
//! node engines, so the artifact is reproducible. See `--help` for the scenario registry.

#![allow(clippy::print_stdout, clippy::print_stderr, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::process::ExitCode;

use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{Experiment, Grid, Params, Sim, spawn_cell};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") || args.is_empty() {
        print_help();
        return ExitCode::SUCCESS;
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fanos-sim-experiment: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let mut grid = Grid::new();
    let mut seeds = 1u64;
    let mut out: Option<String> = None;
    let mut json = false;
    let mut scenario_name = String::from("diakrisis-resilience");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--param" => {
                let spec = args.get(i + 1).ok_or("--param needs name=v1,v2,…")?;
                let (name, values) = spec.split_once('=').ok_or_else(|| format!("bad --param '{spec}'"))?;
                let vals: Vec<&str> = values.split(',').filter(|v| !v.is_empty()).collect();
                grid = grid.axis(name, &vals);
                i += 2;
            }
            "--seeds" => {
                seeds = args.get(i + 1).and_then(|s| s.parse().ok()).ok_or("--seeds needs a positive integer")?;
                i += 2;
            }
            "--out" => {
                out = Some(args.get(i + 1).ok_or("--out needs a file path")?.clone());
                i += 2;
            }
            "--scenario" => {
                scenario_name.clone_from(args.get(i + 1).ok_or("--scenario needs a name")?);
                i += 2;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            other => return Err(format!("unknown flag '{other}' (try --help)")),
        }
    }

    let rows = match scenario_name.as_str() {
        "diakrisis-resilience" => Experiment::new(grid, seeds).run(&diakrisis_resilience),
        other => return Err(format!("unknown scenario '{other}' (known: diakrisis-resilience)")),
    };
    let artifact = if json { Experiment::to_json(&rows) } else { Experiment::to_csv(&rows) };
    match out {
        Some(path) => std::fs::write(&path, artifact).map_err(|e| format!("writing {path}: {e}"))?,
        None => println!("{artifact}"),
    }
    Ok(())
}

/// **diakrisis-resilience** — how a Fano cell's self-healing response scales with the fault count. Parameter
/// `crashes` (default 1): the number of nodes crashed after liveness is established. Metrics: the reroutes,
/// repairs, and escalations the surviving cell produced diagnosing the loss (spec §6.3/§6.7).
fn diakrisis_resilience(params: &Params, seed: u64) -> BTreeMap<String, f64> {
    let crashes: usize = params.get("crashes").and_then(|s| s.parse().ok()).unwrap_or(1);
    let config = Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    };
    let mut sim = Sim::new(seed);
    let cell = spawn_cell::<F2>(&mut sim, config);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000)); // establish liveness
    for &node in cell.iter().take(crashes) {
        sim.crash(node);
    }
    // The loss times out and the cell's continuous DIAKRISIS reflex diagnoses + heals over this window; the
    // report accumulates the healing actions it took (do NOT clear it — that is where the metrics live).
    sim.run_for(Duration::from_millis(4000));
    let m = &sim.report().metrics;
    BTreeMap::from([
        ("reroutes".to_owned(), m.reroutes as f64),
        ("repairs".to_owned(), m.repairs as f64),
        ("escalations".to_owned(), m.escalations as f64),
    ])
}

fn print_help() {
    println!(
        "fanos-sim-experiment — run a scenario over a parameter grid, emit a CSV/JSON artifact\n\
         \n\
         USAGE:\n\
         \x20 fanos-sim-experiment --scenario NAME [--param k=v1,v2,…]… [--seeds N] [--out FILE] [--json]\n\
         \n\
         FLAGS:\n\
         \x20 --scenario NAME   the experiment to run (default: diakrisis-resilience)\n\
         \x20 --param k=v1,v2   a grid axis and its values (repeatable; runs = Cartesian product)\n\
         \x20 --seeds N         repeat each grid point for seeds 0..N (default 1)\n\
         \x20 --out FILE        write the artifact here (default: stdout)\n\
         \x20 --json            emit JSON instead of CSV\n\
         \n\
         SCENARIOS:\n\
         \x20 diakrisis-resilience  [--param crashes=1,2,3]  a cell's healing response vs the fault count;\n\
         \x20                       metrics: reroutes, repairs, escalations\n\
         \n\
         EXAMPLE:\n\
         \x20 fanos-sim-experiment --scenario diakrisis-resilience --param crashes=1,2,3 --seeds 8 --out r.csv"
    );
}
