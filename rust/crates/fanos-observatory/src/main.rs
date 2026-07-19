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

use fanos_observatory::{App, Control, LiveCellSource, ScenarioSource, SnapshotSource, ui};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    // The source is chosen once; both the TUI and `--json` read the same seam.
    let source = build_source(args.iter().any(|a| a == "--live"));
    if args.iter().any(|a| a == "--json") {
        let mut out = io::stdout().lock();
        writeln!(out, "{}", source.snapshot().to_json())?;
        return Ok(());
    }
    run_tui(source)
}

/// `--live` drives a real cell of production `OverlayNode` engines; the default is the self-contained
/// `PurityDynamics` demo. Both are the same [`SnapshotSource`] seam — a remote telemetry feed adds a third.
fn build_source(live: bool) -> Box<dyn SnapshotSource> {
    if live {
        Box::new(LiveCellSource::new())
    } else {
        Box::new(ScenarioSource::new())
    }
}

fn print_help() {
    println!("fanos-monitor — the terminal Coherence Observatory\n");
    println!("USAGE:\n  fanos-monitor            open the TUI (demo PurityDynamics cell)");
    println!("  fanos-monitor --live     drive a live cell of real OverlayNode engines");
    println!("  fanos-monitor --json     print one CoherenceSnapshot as JSON (for agents)\n");
    println!("TUI KEYS:\n  q/Esc quit · space pause · a attack · z relieve · f inject fault · h heal");
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
