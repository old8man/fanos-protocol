//! `fanos-lab` — the FANOS simulation console.
//!
//! A structured, productivity-first operator CLI over the scale-out simulator ([`fanos_sim::Cluster`]):
//! build a cluster of 1 → 10 000 nodes, run it, watch its state live in a terminal dashboard, drive
//! edge-case experiments, and check the architecture viability gate — all from one command surface.
//!
//! ```text
//! fanos-lab run   --nodes 1001 --run-ms 3000       # headless: run and print cluster state (--json too)
//! fanos-lab watch --nodes 350                       # live ratatui dashboard, with fault/heal controls
//! fanos-lab gate                                    # the ХОЛАРХ viability gate (V1–V4 + σ + ablations)
//! ```

use std::io;
use std::time::{Duration as StdDuration, Instant as StdInstant};

use clap::{Args, Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use fanos_field::{F7, F13, F31, Field};
use fanos_observatory::{ClusterDashboard, render_cluster};
use fanos_runtime::{Config, Duration};
use fanos_sim::stress::{Experiment, ExperimentReport, run_experiment};
use fanos_sim::{Cluster, ClusterSnapshot, Hierarchy, UnifiedCluster};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

/// The FANOS simulation lab — run, inspect, and stress a scale-out cluster.
#[derive(Parser)]
#[command(name = "fanos-lab", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build a cluster, run it, and print its state (headless; `--json` for machines).
    Run(RunArgs),
    /// Watch a running cluster live in a terminal dashboard (fault/heal/inspect controls).
    Watch(WatchArgs),
    /// Run a named stress experiment against a cluster and report the fleet's response.
    Experiment(ExperimentArgs),
    /// Sweep across scales (1 → 10 000 nodes), reporting state at each — optionally under an experiment.
    Sweep(SweepArgs),
    /// Cross-cell routing on a connected hierarchy: measure reachability, optionally under gateway crashes.
    Route(RouteArgs),
    /// The unified topology: K coherent cells in one Sim that BOTH report coherence AND route cross-cell.
    Unified(UnifiedArgs),
    /// List the available stress experiments.
    Scenarios,
    /// Check the ХОЛАРХ architecture viability gate (V1–V4, σ-panel, Ω4 ablations).
    Gate,
}

#[derive(Args)]
struct ExperimentArgs {
    /// Which experiment (see `fanos-lab scenarios`): mass-crash | churn | cascade.
    name: String,
    #[command(flatten)]
    shape: Shape,
    /// The experiment's intensity — crash fraction (mass-crash) or churn rate (churn); ignored by cascade.
    #[arg(long, default_value_t = 0.1)]
    fraction: f64,
    /// How many perturb-and-step ticks to run.
    #[arg(long, default_value_t = 12)]
    ticks: usize,
    /// Virtual milliseconds per tick.
    #[arg(long, default_value_t = 700)]
    step_ms: u64,
    /// Emit the report as JSON.
    #[arg(long)]
    json: bool,
}

/// Shared cluster-shape arguments.
#[derive(Args, Clone)]
struct Shape {
    /// Total node count. Up to 7 is a single growing cell (one node, two nodes, …); beyond that, more
    /// base cells (each a coherent 7-node Fano cell).
    #[arg(long, short, default_value_t = 7)]
    nodes: usize,
    /// RNG seed — the whole run is deterministic in it.
    #[arg(long, short, default_value_t = 1)]
    seed: u64,
}

#[derive(Args)]
struct RunArgs {
    #[command(flatten)]
    shape: Shape,
    /// Virtual milliseconds to run before snapshotting.
    #[arg(long, default_value_t = 2000)]
    run_ms: u64,
    /// Emit the cluster state as JSON instead of a human report.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct UnifiedArgs {
    /// Number of coherent 7-node cells (each a Fano cell embedded in one plane, with a routing gateway).
    #[arg(long, short, default_value_t = 20)]
    cells: usize,
    /// Crash this many gateways, then re-measure — showing the two lenses COUPLED (a gateway is also a
    /// coherence member, so its loss both degrades its cell and severs cross-cell routing to it).
    #[arg(long, default_value_t = 0)]
    crash: usize,
    /// RNG seed.
    #[arg(long, short, default_value_t = 1)]
    seed: u64,
    /// Emit JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RouteArgs {
    /// Number of gateways (top-cell / sub-cells).
    #[arg(long, short, default_value_t = 6)]
    gateways: usize,
    /// Descended nodes per sub-cell.
    #[arg(long, short, default_value_t = 6)]
    per_cell: usize,
    /// Crash this many gateways, then re-measure reachability (fault-containment demo).
    #[arg(long, default_value_t = 0)]
    crash: usize,
    /// Instead of a single crash, sweep 0..gateways failures and print the reachability curve.
    #[arg(long)]
    resilience: bool,
    /// RNG seed.
    #[arg(long, short, default_value_t = 1)]
    seed: u64,
    /// Emit JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct SweepArgs {
    /// RNG seed.
    #[arg(long, short, default_value_t = 1)]
    seed: u64,
    /// The largest scale to reach (the ladder is 7, 70, 700, 7000, 10003 nodes, capped here).
    #[arg(long, default_value_t = 10_003)]
    max_nodes: usize,
    /// Optionally run this experiment at every scale (see `fanos-lab scenarios`).
    #[arg(long)]
    experiment: Option<String>,
    /// Experiment intensity (crash fraction / churn rate).
    #[arg(long, default_value_t = 0.1)]
    fraction: f64,
}

#[derive(Args)]
struct WatchArgs {
    #[command(flatten)]
    shape: Shape,
    /// Virtual milliseconds to advance per real refresh tick.
    #[arg(long, default_value_t = 300)]
    step_ms: u64,
    /// Optionally drive a stress experiment live while watching (see `fanos-lab scenarios`).
    #[arg(long)]
    experiment: Option<String>,
    /// The live experiment's intensity — crash fraction (mass-crash) or churn rate (churn).
    #[arg(long, default_value_t = 0.05)]
    fraction: f64,
}

fn lab_config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

fn build_cluster(shape: &Shape) -> Cluster {
    Cluster::with_node_target(shape.seed, lab_config(), shape.nodes.max(1))
}

fn main() {
    match Cli::parse().command {
        Command::Run(args) => cmd_run(&args),
        Command::Experiment(args) => cmd_experiment(&args),
        Command::Sweep(args) => cmd_sweep(&args),
        Command::Route(args) => cmd_route(&args),
        Command::Unified(args) => cmd_unified(&args),
        Command::Scenarios => cmd_scenarios(),
        Command::Gate => cmd_gate(),
        Command::Watch(args) => {
            if let Err(err) = cmd_watch(&args) {
                eprintln!("fanos-lab watch: {err}");
                std::process::exit(1);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// experiment / scenarios
// ---------------------------------------------------------------------------------------------------

fn cmd_sweep(args: &SweepArgs) {
    // Full-cell scales (multiples of 7) so the sweep isolates the experiment's effect — a partial last
    // cell would itself read degraded once its absent members time out, muddying the reading.
    let ladder: Vec<usize> = [1usize, 10, 100, 1000, 1429]
        .into_iter()
        .map(|cells| cells * 7)
        .filter(|&n| n <= args.max_nodes)
        .collect();
    if let Some(name) = &args.experiment {
        println!("\nscale sweep under '{name}' (seed {}):", args.seed);
        println!("  {:>7} {:>6} {:>8} {:>10} {:>8} {:>6} {:>10}", "nodes", "cells", "alive", "reporting", "min Φ", "peak", "outcome");
        for n in ladder {
            let mut cluster = Cluster::with_node_target(args.seed, lab_config(), n);
            cluster.run_for(Duration::from_millis(1200));
            let Some(exp) = Experiment::from_name(name, args.fraction, cluster.node_count()) else {
                eprintln!("unknown experiment '{name}'. Try: {}", Experiment::NAMES.join(", "));
                std::process::exit(2);
            };
            let r = run_experiment(&mut cluster, exp, 12, Duration::from_millis(700));
            println!(
                "  {:>7} {:>6} {:>8} {:>10} {:>8.3} {:>6} {:>10}",
                r.after.total, cluster.cell_count(), r.after.alive, r.after.reporting,
                r.min_mean_phi, r.peak_troubled_cells,
                if r.ended_healthy { "recovered" } else { "degraded" },
            );
        }
    } else {
        println!("\nscale sweep (seed {}):", args.seed);
        println!("  {:>7} {:>6} {:>8} {:>10} {:>8} {:>8}", "nodes", "cells", "alive", "reporting", "mean Φ", "troubled");
        for n in ladder {
            let mut cluster = Cluster::with_node_target(args.seed, lab_config(), n);
            cluster.run_for(Duration::from_millis(1200));
            cluster.refresh_telemetry();
            let snap = cluster.snapshot();
            let s = &snap.totals;
            println!(
                "  {:>7} {:>6} {:>8} {:>10} {:>8.3} {:>8}",
                s.total, snap.cell_count(), s.alive, s.reporting, s.mean_phi, snap.troubled_cells().count(),
            );
        }
    }
    println!();
}

/// Both-lens metrics of a unified cluster at one moment.
struct UnifiedMetrics {
    total: usize,
    alive: usize,
    reporting: usize,
    healthy: bool,
    mean_phi: f64,
    reach: f64,
}

fn cmd_unified(args: &UnifiedArgs) {
    if args.cells < 2 {
        eprintln!("unified needs at least 2 cells");
        std::process::exit(2);
    }
    let nodes = args.cells * 7;
    // Pick the smallest plane that fits 7·cells nodes (F7=57, F13=183, F31=993 points).
    let (before, after) = if nodes <= 57 {
        unified_run::<F7>(args)
    } else if nodes <= 183 {
        unified_run::<F13>(args)
    } else if nodes <= 993 {
        unified_run::<F31>(args)
    } else {
        eprintln!("unified tops out at 141 cells (993 nodes on one plane); requested {nodes} nodes");
        std::process::exit(2);
    };
    if args.json {
        print!(
            "{{\"cells\":{},\"nodes\":{},\"reporting\":{},\"healthy\":{},\"mean_phi\":{:.6},\"reachability\":{:.6}",
            args.cells, before.total, before.reporting, before.healthy, before.mean_phi, before.reach,
        );
        if let Some(a) = &after {
            print!(",\"crashed_gateways\":{},\"after\":{{\"reporting\":{},\"healthy\":{},\"reachability\":{:.6}}}", args.crash.min(args.cells), a.reporting, a.healthy, a.reach);
        }
        println!("}}");
    } else {
        println!("\nunified topology — {} coherent cells × 7 = {} nodes, one Sim", args.cells, before.total);
        println!("  coherence lens  {}/{} nodes report a self-model · {} · mean Φ {:.3}", before.reporting, before.total, if before.healthy { "healthy" } else { "degraded" }, before.mean_phi);
        println!("  routing lens    {:.1}% of sampled cross-cell gateway routes delivered", before.reach * 100.0);
        if let Some(a) = &after {
            let k = args.crash.min(args.cells);
            println!("  — crash {k} gateway(s) (each also a coherence member) —");
            println!("  coherence lens  {}/{} alive · {} · mean Φ {:.3}  (the {k} cells that lost their gateway degrade)", a.alive, a.total, if a.healthy { "healthy" } else { "degraded" }, a.mean_phi);
            println!("  routing lens    {:.1}% reachable  (routes into the severed cells fail — the two lenses are coupled at the gateway)", a.reach * 100.0);
        } else {
            println!("  → both lenses on one connected topology.");
        }
        println!();
    }
}

fn unified_run<F: Field + 'static>(args: &UnifiedArgs) -> (UnifiedMetrics, Option<UnifiedMetrics>) {
    let mut cluster = UnifiedCluster::new::<F>(args.seed, lab_config(), args.cells);
    cluster.run_for(Duration::from_millis(1500));
    let before = measure_unified(&mut cluster, args.cells);
    let after = if args.crash > 0 {
        // Crash the LAST k gateways (cell 0 — the routing probe origin — survives).
        let k = args.crash.min(args.cells);
        for c in (args.cells - k)..args.cells {
            if let Some(gw) = cluster.gateway(c) {
                cluster.crash(gw);
            }
        }
        cluster.run_for(Duration::from_millis(2500)); // let the cells sense the loss
        Some(measure_unified(&mut cluster, args.cells))
    } else {
        None
    };
    (before, after)
}

fn measure_unified(cluster: &mut UnifiedCluster, cells: usize) -> UnifiedMetrics {
    cluster.refresh_telemetry();
    let snap = cluster.snapshot();
    // Route from cell 0 (which survives) to a bounded sample of other cells.
    let pairs: Vec<(usize, usize)> = (1..cells.min(20)).map(|j| (0, j)).collect();
    let reach = cluster.reachability(pairs.as_slice());
    UnifiedMetrics {
        total: snap.stats.total,
        alive: snap.stats.alive,
        reporting: snap.stats.reporting,
        healthy: snap.stats.is_healthy(),
        mean_phi: snap.stats.mean_phi,
        reach,
    }
}

fn cmd_route(args: &RouteArgs) {
    let total = args.gateways * (1 + args.per_cell);
    if total == 0 || args.gateways < 2 {
        eprintln!("route needs at least 2 gateways and 1 node per cell");
        std::process::exit(2);
    }
    if total > 993 {
        eprintln!("route tops out at 993 nodes (one transport plane); requested {total}");
        std::process::exit(2);
    }

    if args.resilience {
        // Reachability as gateways progressively fail — the containment curve.
        let curve = if total <= 57 {
            route_resilience::<F7>(args)
        } else if total <= 183 {
            route_resilience::<F13>(args)
        } else {
            route_resilience::<F31>(args)
        };
        println!("\nrouting resilience — {} gateways × {} = {total} nodes", args.gateways, args.per_cell);
        println!("  {:>8}  {:>13}", "crashed", "reachability");
        for (k, r) in curve {
            println!("  {k:>8}  {:>12.1}%", r * 100.0);
        }
        println!();
        return;
    }

    // Pick the smallest transport plane that fits (F7=57, F13=183, F31=993 points).
    let (before, after) = if total <= 57 {
        route_run::<F7>(args)
    } else if total <= 183 {
        route_run::<F13>(args)
    } else {
        route_run::<F31>(args)
    };
    let crashed = args.crash.min(args.gateways);
    if args.json {
        println!(
            "{{\"gateways\":{},\"per_cell\":{},\"nodes\":{},\"crashed_gateways\":{},\"reachability_before\":{before:.6},\"reachability_after\":{after:.6}}}",
            args.gateways, args.per_cell, total, crashed,
        );
    } else {
        println!("\nconnected hierarchy — {} gateways × {} = {total} nodes", args.gateways, args.per_cell);
        println!("  reachability       {:.1}%   (cross-cell routes delivered, up-and-over descent)", before * 100.0);
        if args.crash > 0 {
            println!("  crash {crashed} gateway(s)  {:.1}%   (routes into the severed sub-cells fail; the rest hold)", after * 100.0);
        }
        println!();
    }
}

fn route_run<F: Field + 'static>(args: &RouteArgs) -> (f64, f64) {
    let mut h = Hierarchy::<F>::two_level(args.seed, lab_config(), args.gateways, args.per_cell);
    let pairs = cross_cell_pairs(args.gateways, args.per_cell);
    let before = h.reachability(&pairs);
    for g in 0..args.crash.min(args.gateways) {
        if let Some(idx) = h.gateway(g) {
            h.crash(idx);
        }
    }
    let after = h.reachability(&pairs);
    (before, after)
}

fn route_resilience<F: Field + 'static>(args: &RouteArgs) -> Vec<(usize, f64)> {
    let pairs = cross_cell_pairs(args.gateways, args.per_cell);
    (0..args.gateways)
        .map(|k| {
            let mut h = Hierarchy::<F>::two_level(args.seed, lab_config(), args.gateways, args.per_cell);
            for g in 0..k {
                if let Some(idx) = h.gateway(g) {
                    h.crash(idx);
                }
            }
            (k, h.reachability(&pairs))
        })
        .collect()
}

/// Every ordered cross-cell pair — cell `i`'s first sub-node to cell `j`'s first sub-node (`i ≠ j`).
fn cross_cell_pairs(gateways: usize, per_cell: usize) -> Vec<(usize, usize)> {
    let first_sub = |g: usize| g * (1 + per_cell) + 1;
    let mut pairs = Vec::new();
    for i in 0..gateways {
        for j in 0..gateways {
            if i != j {
                pairs.push((first_sub(i), first_sub(j)));
            }
        }
    }
    pairs
}

fn cmd_scenarios() {
    println!("\nStress experiments (fanos-lab experiment <name>):");
    for name in Experiment::NAMES {
        // A representative instance just to read its one-line description.
        if let Some(exp) = Experiment::from_name(name, 0.1, 7) {
            println!("  {:<12} {}", name, exp.describe());
        }
    }
    println!();
}

fn cmd_experiment(args: &ExperimentArgs) {
    let mut cluster = build_cluster(&args.shape);
    cluster.run_for(Duration::from_millis(1200)); // settle to steady state before perturbing
    let Some(experiment) = Experiment::from_name(&args.name, args.fraction, cluster.node_count()) else {
        eprintln!("unknown experiment '{}'. Try: {}", args.name, Experiment::NAMES.join(", "));
        std::process::exit(2);
    };
    let report = run_experiment(&mut cluster, experiment, args.ticks, Duration::from_millis(args.step_ms));
    if args.json {
        println!("{}", experiment_json(&report));
    } else {
        print_experiment(&report);
    }
}

fn print_experiment(r: &ExperimentReport) {
    println!("\nexperiment '{}' — {} ticks", r.name, r.ticks);
    println!("  before      {}/{} alive · {}", r.before.alive, r.before.total, if r.before.is_healthy() { "healthy" } else { "degraded" });
    println!("  after       {}/{} alive · {}", r.after.alive, r.after.total, if r.after.is_healthy() { "healthy" } else { "degraded" });
    println!("  peak trouble {} cell(s) at the worst moment", r.peak_troubled_cells);
    println!("  diagnosed    up to {} node(s) diagnosed ({} of them a partition verdict)", r.peak_diagnosed, r.peak_partitioned);
    println!("  decouples    {} correlation-shed action(s) (the homeostat's flood response)", r.decouples);
    println!("  min mean Φ   {:.3}   (deepest coherence dip)", r.min_mean_phi);
    println!("  outcome      {}\n", if r.ended_healthy { "● recovered / never broke" } else { "● ended degraded" });
}

fn experiment_json(r: &ExperimentReport) -> String {
    let phi = if r.min_mean_phi.is_finite() { format!("{:.6}", r.min_mean_phi) } else { "null".to_string() };
    format!(
        "{{\"name\":\"{}\",\"ticks\":{},\"before_alive\":{},\"after_alive\":{},\"total\":{},\"peak_troubled_cells\":{},\"peak_diagnosed\":{},\"peak_partitioned\":{},\"decouples\":{},\"min_mean_phi\":{},\"ended_healthy\":{}}}",
        r.name, r.ticks, r.before.alive, r.after.alive, r.after.total, r.peak_troubled_cells, r.peak_diagnosed, r.peak_partitioned, r.decouples, phi, r.ended_healthy,
    )
}

// ---------------------------------------------------------------------------------------------------
// run — headless
// ---------------------------------------------------------------------------------------------------

fn cmd_run(args: &RunArgs) {
    let mut cluster = build_cluster(&args.shape);
    cluster.run_for(Duration::from_millis(args.run_ms));
    cluster.refresh_telemetry(); // a guaranteed-fresh self-model read regardless of the run duration
    let snap = cluster.snapshot();
    if args.json {
        println!("{}", cluster_json(&snap));
    } else {
        print_report(&snap);
    }
}

fn print_report(snap: &ClusterSnapshot) {
    let s = &snap.totals;
    let healthy = s.is_healthy() && s.alive == s.total;
    println!("\nFANOS cluster — {} nodes across {} cells   t={:.2}s", s.total, snap.cell_count(), snap.at_nanos as f64 / 1e9);
    println!("  verdict     {}", if healthy { "● HEALTHY" } else { "● DEGRADED" });
    println!("  alive       {}/{}", s.alive, s.total);
    println!("  reporting   {}/{}   (nodes publishing a coherence self-model)", s.reporting, s.total);
    println!("  mean Φ      {:.3}   min Φ {:.3}   mean P {:.3}   mean R {:.3}", s.mean_phi, s.min_phi, s.mean_purity, s.mean_reflection);
    println!("  regimes     aggregate {}  collective {}  over-coupled {}", s.regimes.aggregate, s.regimes.collective_subject, s.regimes.over_coupled);
    println!("  alarms      healthy {}  integration {}  structure {}", s.alarms.healthy, s.alarms.integration, s.alarms.structure);
    println!("  diagnosis   partitioned {}  diagnosed {}", s.partitioned, s.diagnosed);
    println!("  faulted {}  ready {}", s.faulted, s.ready);
    let m = &snap.metrics;
    println!("  traffic     frames {}  reroutes {}  repairs {}  quarantines {}  escalations {}", m.frames_delivered, m.reroutes, m.repairs, m.quarantines, m.escalations);
    let troubled: Vec<usize> = snap.troubled_cells().map(|(i, _)| i).collect();
    if troubled.is_empty() {
        println!("  troubled    none");
    } else {
        let shown: Vec<usize> = troubled.iter().take(24).copied().collect();
        let more = if troubled.len() > shown.len() { " …" } else { "" };
        println!("  troubled    {} cell(s): {shown:?}{more}", troubled.len());
    }
    println!();
}

fn cluster_json(snap: &ClusterSnapshot) -> String {
    let s = &snap.totals;
    let m = &snap.metrics;
    let num = |x: f64| if x.is_finite() { format!("{x:.6}") } else { "null".to_string() };
    format!(
        concat!(
            "{{\"at_nanos\":{},\"cells\":{},\"nodes\":{},\"alive\":{},\"reporting\":{},",
            "\"faulted\":{},\"ready\":{},\"mean_phi\":{},\"min_phi\":{},\"mean_purity\":{},",
            "\"mean_reflection\":{},\"regimes\":{{\"aggregate\":{},\"collective_subject\":{},",
            "\"over_coupled\":{}}},\"alarms\":{{\"healthy\":{},\"integration\":{},\"structure\":{}}},",
            "\"metrics\":{{\"frames_delivered\":{},\"reroutes\":{},\"repairs\":{},\"quarantines\":{},",
            "\"escalations\":{}}},\"troubled_cells\":{}}}"
        ),
        snap.at_nanos, snap.cell_count(), s.total, s.alive, s.reporting, s.faulted, s.ready,
        num(s.mean_phi), num(s.min_phi), num(s.mean_purity), num(s.mean_reflection),
        s.regimes.aggregate, s.regimes.collective_subject, s.regimes.over_coupled,
        s.alarms.healthy, s.alarms.integration, s.alarms.structure,
        m.frames_delivered, m.reroutes, m.repairs, m.quarantines, m.escalations,
        snap.troubled_cells().count(),
    )
}

// ---------------------------------------------------------------------------------------------------
// gate — the ХОЛАРХ viability panel
// ---------------------------------------------------------------------------------------------------

fn cmd_gate() {
    let panel = fanos_holarch::Panel::run();
    println!("{panel}");
    if !panel.all_pass() {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------------------------------
// watch — the live dashboard
// ---------------------------------------------------------------------------------------------------

fn cmd_watch(args: &WatchArgs) -> Result<(), Box<dyn std::error::Error>> {
    let mut cluster = build_cluster(&args.shape);
    // Resolve an optional live experiment (fail fast on a bad name, before touching the terminal).
    let experiment = args.experiment.as_deref().map(|name| {
        Experiment::from_name(name, args.fraction, cluster.node_count()).unwrap_or_else(|| {
            eprintln!("unknown experiment '{name}'. Try: {}", Experiment::NAMES.join(", "));
            std::process::exit(2);
        })
    });
    let label = match &experiment {
        Some(exp) => format!("seed {} · {}", args.shape.seed, exp.name()),
        None => format!("seed {}", args.shape.seed),
    };

    install_panic_hook();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    let result = watch_loop(&mut terminal, &mut cluster, &label, args.step_ms, experiment);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn watch_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    cluster: &mut Cluster,
    label: &str,
    step_ms: u64,
    experiment: Option<Experiment>,
) -> Result<(), Box<dyn std::error::Error>> {
    cluster.refresh_telemetry();
    let mut dash = ClusterDashboard::new(cluster.snapshot(), label.to_string());
    let tick = StdDuration::from_millis(150);
    let mut last = StdInstant::now();
    let mut exp_tick = 0usize; // advances only while the live experiment is running

    loop {
        terminal.draw(|f| render_cluster(f, &dash))?;

        let timeout = tick.saturating_sub(last.elapsed());
        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc if dash.selected().is_none() => dash.should_quit = true,
                KeyCode::Esc => dash.clear_selection(),
                KeyCode::Char('q') => dash.should_quit = true,
                KeyCode::Char(' ') => dash.toggle_pause(),
                KeyCode::Char('f') => fault_a_cell(cluster, &dash),
                KeyCode::Char('h') => heal_all(cluster),
                KeyCode::Char('t') => dash.select_next_troubled(),
                KeyCode::Left | KeyCode::Up => dash.select_delta(-1),
                KeyCode::Right | KeyCode::Down => dash.select_delta(1),
                _ => {}
            }
        }

        if last.elapsed() >= tick {
            if !dash.is_paused() {
                if let Some(exp) = experiment {
                    exp.perturb(cluster, exp_tick);
                    exp_tick += 1;
                }
                cluster.run_for(Duration::from_millis(step_ms));
            }
            cluster.refresh_telemetry();
            dash.update(cluster.snapshot());
            last = StdInstant::now();
        }
        if dash.should_quit {
            return Ok(());
        }
    }
}

/// Crash one alive node in the selected cell (or cell 0) — an operator-triggered fault to watch heal.
fn fault_a_cell(cluster: &mut Cluster, dash: &ClusterDashboard) {
    let target = dash.selected().unwrap_or(0);
    if let Some(cell) = cluster.cell_mut(target) {
        let victim = cell.fleet_snapshot().nodes.iter().find(|n| n.alive).map(|n| n.coord);
        if let Some(v) = victim {
            cell.crash(v);
        }
    }
}

/// Recover every crashed node across the whole cluster.
fn heal_all(cluster: &mut Cluster) {
    let mut i = 0;
    while let Some(cell) = cluster.cell_mut(i) {
        let dead: Vec<_> = cell.fleet_snapshot().nodes.iter().filter(|n| !n.alive).map(|n| n.coord).collect();
        for coord in dead {
            cell.recover(coord);
        }
        i += 1;
    }
}

/// Restore the terminal on panic, so a crash never leaves the shell in raw mode / the alt screen.
fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original(info);
    }));
}
