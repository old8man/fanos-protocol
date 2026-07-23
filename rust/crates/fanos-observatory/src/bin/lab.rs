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
use fanos_observatory::{ClusterDashboard, render_cluster};
use fanos_runtime::{Config, Duration};
use fanos_sim::{Cluster, ClusterSnapshot};
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
    /// Check the ХОЛАРХ architecture viability gate (V1–V4, σ-panel, Ω4 ablations).
    Gate,
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
struct WatchArgs {
    #[command(flatten)]
    shape: Shape,
    /// Virtual milliseconds to advance per real refresh tick.
    #[arg(long, default_value_t = 300)]
    step_ms: u64,
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
    let label = format!("seed {}", args.shape.seed);
    install_panic_hook();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    let result = watch_loop(&mut terminal, &mut cluster, &label, args.step_ms);
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
) -> Result<(), Box<dyn std::error::Error>> {
    cluster.refresh_telemetry();
    let mut dash = ClusterDashboard::new(cluster.snapshot(), label.to_string());
    let tick = StdDuration::from_millis(150);
    let mut last = StdInstant::now();

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
                KeyCode::Left | KeyCode::Up => dash.select_delta(-1),
                KeyCode::Right | KeyCode::Down => dash.select_delta(1),
                _ => {}
            }
        }

        if last.elapsed() >= tick {
            if !dash.is_paused() {
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
