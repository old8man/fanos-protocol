//! `fanos-monitor` — the terminal Coherence Observatory.
//!
//! With no arguments it opens the live TUI (a human operator drives a cell and watches its coherence
//! self-model respond). With `--json` it prints one [`CoherenceSnapshot`](fanos_telemetry::CoherenceSnapshot)
//! as canonical JSON and exits — the same self-model an agent or `fanos monitor --json | jq` consumes.

use std::io::{self, Write as _};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

#[cfg(feature = "sim")]
use fanos_observatory::LiveCellSource;
use fanos_observatory::{App, Control, RemoteNodeSource, ScenarioSource, SnapshotSource, ui};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    // The source is chosen once; both the TUI and `--json` read the same seam.
    let node = args.iter().position(|a| a == "--node").and_then(|i| args.get(i + 1)).cloned();
    let mut source = build_source(args.iter().any(|a| a == "--live"), node.as_deref());
    if args.iter().any(|a| a == "--json") {
        // One tick first, or a remote source emits its pre-read zeros — which read as a collapsed cell. The
        // simulated sources are ready at construction and a tick costs them one window; the remote one has
        // not spoken to anything yet, and printing that as JSON would be a lie an agent cannot see through.
        source.tick();
        // Refuse to print a snapshot that is not a reading. Measured on a real run: an unreached node folds
        // to `"alarm":"healthy","faulted":false"` — a monitor reporting the cell healthy *because* it could
        // not reach it. An agent consuming this JSON cannot see through that, so it must not be produced.
        if let Err(why) = source.reading() {
            eprintln!("fanos-monitor: no reading — {why}");
            std::process::exit(2);
        }
        let mut out = io::stdout().lock();
        writeln!(out, "{}", source.snapshot().to_json())?;
        return Ok(());
    }
    run_tui(source)
}

/// `--node DIR` watches a **deployed** node over its control socket; `--live` drives a real cell of production
/// `OverlayNode` engines under the simulator; the default is the self-contained `PurityDynamics` demo. All
/// three are the same [`SnapshotSource`] seam, which is what the trait was extracted for.
///
/// `--node` wins over `--live` when both are given: one names a real deployment and the other a simulation,
/// and silently preferring the simulation would show an operator a cell that is not theirs.
fn build_source(live: bool, node: Option<&str>) -> Box<dyn SnapshotSource> {
    if let Some(dir) = node {
        return Box::new(RemoteNodeSource::new(std::path::Path::new(dir)));
    }
    #[cfg(feature = "sim")]
    if live {
        return Box::new(LiveCellSource::new());
    }
    #[cfg(not(feature = "sim"))]
    if live {
        eprintln!(
            "--live was compiled out (built without the `sim` feature); using the scenario demo"
        );
    }
    Box::new(ScenarioSource::new())
}

fn print_help() {
    println!("fanos-monitor — the terminal Coherence Observatory\n");
    println!("  --node DIR   watch a DEPLOYED node, read over the control socket in its state directory");
    println!("USAGE:\n  fanos-monitor            open the TUI (demo PurityDynamics cell)");
    println!("  fanos-monitor --live     drive a live cell of real OverlayNode engines");
    println!("  fanos-monitor --json     print one CoherenceSnapshot as JSON (for agents)\n");
    println!(
        "TUI KEYS:\n  q/Esc quit · space pause · a attack · z relieve · f inject fault · h heal"
    );
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

fn run_tui(source: Box<dyn SnapshotSource>) -> Result<(), Box<dyn std::error::Error>> {
    install_panic_hook();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let result = event_loop(&mut terminal, source);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    source: Box<dyn SnapshotSource>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut app = App::new(source);
    let tick = Duration::from_millis(120);
    let mut last = Instant::now();

    loop {
        terminal.draw(|f| ui::render(f, &app))?;

        let timeout = tick.saturating_sub(last.elapsed());
        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => app.quit(),
                KeyCode::Char(' ') => app.toggle_pause(),
                KeyCode::Char('a') | KeyCode::Up => app.control(Control::Attack),
                KeyCode::Char('z') | KeyCode::Down => app.control(Control::Relieve),
                KeyCode::Char('f') => app.control(Control::InjectFault),
                KeyCode::Char('h') => app.control(Control::Heal),
                _ => {}
            }
        }
        if last.elapsed() >= tick {
            app.on_tick();
            last = Instant::now();
        }
        if app.should_quit {
            return Ok(());
        }
    }
}
