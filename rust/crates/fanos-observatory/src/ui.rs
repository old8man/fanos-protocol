//! Rendering the Coherence Observatory. Pure: `render(frame, app)` draws the whole panel from the
//! app's current snapshot, so it is unit-testable against a `TestBackend` with no real terminal.
//!
//! The layout is an instrument panel: a readiness header; the three vital-sign gauges `Φ/P/R` with
//! their theorem-fixed thresholds; the **coherence spectrum** (the one quantity `r` on its band axis
//! — aggregate | collective-subject | over-coupled); a `Φ` trend sparkline; the Fano syndrome map; the
//! derived vitals; and the live agent-facing JSON. Colour is semantic, not decoration.

// Layout splits index into a slice whose length equals the constraint count passed on the line above,
// so every `rows[k]` / `body[k]` here is statically in bounds — the panic path clippy warns about
// cannot occur for these fixed layouts.
#![allow(clippy::indexing_slicing)]

use fanos_telemetry::{
    AlarmLevel, CoherenceSnapshot, OVER_COUPLING, PURITY_FLOOR, R_STAR, REFLECTION_FLOOR, Regime,
};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Sparkline, Wrap};

use crate::app::App;

const READY: Color = Color::Green;
const WARN: Color = Color::Yellow;
const CRIT: Color = Color::Magenta;
const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;

/// Draw the whole observatory for `app`'s current snapshot.
pub fn render(f: &mut Frame<'_>, app: &App) {
    let snap = app.snapshot();
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(0),    // body
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    render_header(f, root[0], app, snap);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(root[1]);
    render_left(f, body[0], app, snap);
    render_right(f, body[1], app, snap);

    render_footer(f, root[2]);
}

fn render_header(f: &mut Frame<'_>, area: Rect, app: &App, snap: &CoherenceSnapshot) {
    let (ready_txt, ready_col) = if snap.ready {
        ("● READY", READY)
    } else {
        ("● NOT READY", CRIT)
    };
    let paused = if app.is_paused() { "  ⏸ PAUSED" } else { "" };
    let title = Line::from(vec![
        Span::styled("◇ FANOS Coherence Observatory", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(format!("   {}   ", app.source_label()), Style::default().fg(MUTED)),
        Span::styled(format!("epoch {}", snap.epoch), Style::default().fg(Color::Gray)),
        Span::styled(paused.to_string(), Style::default().fg(WARN)),
    ]);
    let verdict = Line::from(vec![Span::styled(
        format!(" {ready_txt} "),
        Style::default().fg(Color::Black).bg(ready_col).add_modifier(Modifier::BOLD),
    )])
    .alignment(Alignment::Right);

    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(MUTED));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(14)])
        .split(inner);
    f.render_widget(Paragraph::new(title), cols[0]);
    f.render_widget(Paragraph::new(verdict), cols[1]);
}

fn render_left(f: &mut Frame<'_>, area: Rect, app: &App, snap: &CoherenceSnapshot) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Φ
            Constraint::Length(3), // P
            Constraint::Length(3), // R
            Constraint::Length(4), // coherence spectrum
            Constraint::Min(3),    // Φ trend
        ])
        .split(area);

    // Φ ≥ 1 ⇒ one bound subject. Gauge maps Φ=2 to full; the theorem line is at half.
    gauge(
        f, rows[0], "Φ  integration",
        (snap.phi / 2.0).clamp(0.0, 1.0),
        format!("{:.3}   bound if ≥ 1", snap.phi),
        if snap.phi >= 1.0 { READY } else { WARN },
    );
    // P > 2/N ⇒ structured/viable.
    gauge(
        f, rows[1], "P  structure",
        snap.purity.clamp(0.0, 1.0),
        format!("{:.3}   viable if > 2/7 ({PURITY_FLOOR:.3})", snap.purity),
        if snap.purity > PURITY_FLOOR { READY } else { CRIT },
    );
    // R ≥ 1/3 ⇒ still self-observing (not over-coupled).
    gauge(
        f, rows[2], "R  reflection",
        snap.reflection.clamp(0.0, 1.0),
        format!("{:.3}   self-model if ≥ 1/3 ({REFLECTION_FLOOR:.3})", snap.reflection),
        if snap.reflection >= REFLECTION_FLOOR { READY } else { CRIT },
    );

    render_spectrum(f, rows[3], snap);
    render_trend(f, rows[4], app);
}

fn gauge(f: &mut Frame<'_>, area: Rect, title: &str, ratio: f64, label: String, col: Color) {
    let g = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(Span::styled(format!(" {title} "), Style::default().fg(Color::Gray))).border_style(Style::default().fg(MUTED)))
        .gauge_style(Style::default().fg(col))
        .ratio(ratio.clamp(0.0, 1.0))
        .label(Span::styled(label, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)));
    f.render_widget(g, area);
}

/// The coherence spectrum: the mean correlation `r` on its band axis. The bands are theorem-fixed —
/// `(0, r*]` aggregate (Φ<1), `(r*, 1/√3]` the healthy collective-subject window, `(1/√3, 1]`
/// over-coupled (R<1/3). A bright marker sits at the current `r`.
fn render_spectrum(f: &mut Frame<'_>, area: Rect, snap: &CoherenceSnapshot) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(" coherence spectrum  r ", Style::default().fg(Color::Gray)))
        .border_style(Style::default().fg(MUTED));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let w = inner.width.max(1) as usize;
    let marker = ((snap.mean_correlation.clamp(0.0, 1.0)) * (w.saturating_sub(1)) as f64).round() as usize;

    let mut band = Vec::with_capacity(w);
    for i in 0..w {
        let r = i as f64 / (w.max(2) - 1) as f64;
        let (ch, col) = if i == marker {
            ('▐', Color::White)
        } else if r <= R_STAR {
            ('▄', WARN)
        } else if r <= OVER_COUPLING {
            ('▄', ACCENT)
        } else {
            ('▄', CRIT)
        };
        band.push(Span::styled(ch.to_string(), Style::default().fg(col)));
    }
    let axis = Line::from(vec![
        Span::styled("0", Style::default().fg(MUTED)),
        Span::styled(format!("  r*={R_STAR:.2}  "), Style::default().fg(WARN)),
        Span::styled(format!("band  1/√3={OVER_COUPLING:.2}"), Style::default().fg(ACCENT)),
        Span::styled("  1", Style::default().fg(MUTED)),
    ]);
    let para = Paragraph::new(vec![Line::from(band), axis]);
    f.render_widget(para, inner);
}

fn render_trend(f: &mut Frame<'_>, area: Rect, app: &App) {
    let data: Vec<u64> = app.phi_history().iter().copied().collect();
    let spark = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title(Span::styled(" Φ trend ", Style::default().fg(Color::Gray))).border_style(Style::default().fg(MUTED)))
        .data(&data)
        .style(Style::default().fg(ACCENT));
    f.render_widget(spark, area);
}

fn render_right(f: &mut Frame<'_>, area: Rect, app: &App, snap: &CoherenceSnapshot) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // vitals
            Constraint::Length(4),  // syndrome map
            Constraint::Min(4),     // agent JSON
        ])
        .split(area);
    render_vitals(f, rows[0], app, snap);
    render_syndrome(f, rows[1], app.degraded(), snap.syndrome);
    render_json(f, rows[2], snap);
}

fn render_vitals(f: &mut Frame<'_>, area: Rect, app: &App, snap: &CoherenceSnapshot) {
    let (reg_col, reg_txt) = regime_label(snap.regime);
    let (al_col, al_txt) = alarm_label(snap.alarm);
    let band_note = if snap.mean_correlation <= R_STAR {
        Span::styled("below r* — not yet bound", Style::default().fg(WARN))
    } else if snap.mean_correlation <= OVER_COUPLING {
        Span::styled("in the collective-subject band", Style::default().fg(READY))
    } else {
        Span::styled("over-coupled — shed correlation", Style::default().fg(CRIT))
    };
    let cascade = if snap.cascade_lead >= 0 {
        Span::styled(format!("forecast in {} ticks", snap.cascade_lead), Style::default().fg(CRIT))
    } else {
        Span::styled("none", Style::default().fg(MUTED))
    };
    let pcol = if app.pressure() >= 1.0 { CRIT } else { WARN };
    let lines = vec![
        kv("mean r", &format!("{:.3}", snap.mean_correlation), ACCENT, Some(band_note)),
        kv("spectral Δ", &format!("{:.3}", snap.spectral_gap), Color::White, None),
        kv("stability r_stab", &format!("{:.3}", snap.stability_radius), Color::White, None),
        kv_span("regime", Span::styled(reg_txt, Style::default().fg(reg_col).add_modifier(Modifier::BOLD))),
        kv_span("alarm", Span::styled(al_txt, Style::default().fg(al_col).add_modifier(Modifier::BOLD))),
        kv("pressure a/a*", &format!("{:.0}%", app.pressure() * 100.0), pcol, None),
        kv_span("cascade", cascade),
        kv("heal_seq", &format!("{}", snap.heal_seq), Color::White, None),
    ];
    let block = Block::default().borders(Borders::ALL).title(Span::styled(" vital signs ", Style::default().fg(Color::Gray))).border_style(Style::default().fg(MUTED));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_syndrome(f: &mut Frame<'_>, area: Rect, degraded: u8, syndrome: u8) {
    let idx: Vec<Span<'_>> = (0..7)
        .map(|i| Span::styled(format!(" {i} "), Style::default().fg(MUTED)))
        .collect();
    let pts: Vec<Span<'_>> = (0..7)
        .map(|i| {
            if degraded & (1u8 << i) != 0 {
                Span::styled(" ✖ ", Style::default().fg(CRIT).add_modifier(Modifier::BOLD))
            } else {
                Span::styled(" ● ", Style::default().fg(READY))
            }
        })
        .collect();
    let title = format!(" Fano nodes  ·  syndrome 0b{syndrome:03b} ");
    let block = Block::default().borders(Borders::ALL).title(Span::styled(title, Style::default().fg(Color::Gray))).border_style(Style::default().fg(MUTED));
    f.render_widget(Paragraph::new(vec![Line::from(idx), Line::from(pts)]).block(block), area);
}

fn render_json(f: &mut Frame<'_>, area: Rect, snap: &CoherenceSnapshot) {
    let block = Block::default().borders(Borders::ALL).title(Span::styled(" agent snapshot · JSON ", Style::default().fg(Color::Gray))).border_style(Style::default().fg(MUTED));
    let para = Paragraph::new(Span::styled(snap.to_json(), Style::default().fg(Color::Gray)))
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn render_footer(f: &mut Frame<'_>, area: Rect) {
    let keys = Line::from(vec![
        Span::styled(" q ", Style::default().fg(Color::Black).bg(MUTED)),
        Span::styled(" quit   ", Style::default().fg(MUTED)),
        Span::styled(" space ", Style::default().fg(Color::Black).bg(MUTED)),
        Span::styled(" pause   ", Style::default().fg(MUTED)),
        Span::styled(" a ", Style::default().fg(Color::Black).bg(WARN)),
        Span::styled(" attack   ", Style::default().fg(MUTED)),
        Span::styled(" z ", Style::default().fg(Color::Black).bg(READY)),
        Span::styled(" relieve   ", Style::default().fg(MUTED)),
        Span::styled(" f ", Style::default().fg(Color::Black).bg(CRIT)),
        Span::styled(" fault   ", Style::default().fg(MUTED)),
        Span::styled(" h ", Style::default().fg(Color::Black).bg(ACCENT)),
        Span::styled(" heal ", Style::default().fg(MUTED)),
    ]);
    f.render_widget(Paragraph::new(keys), area);
}

// --- small helpers for the vitals rows ---

fn kv(key: &str, val: &str, col: Color, note: Option<Span<'static>>) -> Line<'static> {
    let mut spans = vec![
        Span::styled(format!("{key:<18}"), Style::default().fg(MUTED)),
        Span::styled(format!("{val:<9}"), Style::default().fg(col).add_modifier(Modifier::BOLD)),
    ];
    if let Some(n) = note {
        spans.push(n);
    }
    Line::from(spans)
}

fn kv_span(key: &str, val: Span<'static>) -> Line<'static> {
    Line::from(vec![Span::styled(format!("{key:<18}"), Style::default().fg(MUTED)), val])
}

const fn regime_label(r: Regime) -> (Color, &'static str) {
    match r {
        Regime::Aggregate => (WARN, "AGGREGATE"),
        Regime::CollectiveSubject => (READY, "COLLECTIVE SUBJECT"),
        Regime::OverCoupled => (CRIT, "OVER-COUPLED"),
    }
}

const fn alarm_label(a: AlarmLevel) -> (Color, &'static str) {
    match a {
        AlarmLevel::Healthy => (READY, "HEALTHY"),
        AlarmLevel::Integration => (WARN, "INTEGRATION"),
        AlarmLevel::Structure => (CRIT, "STRUCTURE"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::source::ScenarioSource;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// Render to an off-screen backend and return the flattened text of the buffer.
    fn rendered_text(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(96, 32)).unwrap();
        terminal.draw(|f| render(f, app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        buf.content().iter().map(ratatui::buffer::Cell::symbol).collect()
    }

    #[test]
    fn a_healthy_cell_renders_the_key_instruments() {
        let app = App::new(Box::new(ScenarioSource::new()));
        let text = rendered_text(&app);
        assert!(text.contains("Coherence Observatory"));
        assert!(text.contains("READY"));
        assert!(text.contains('Φ') && text.contains('P') && text.contains('R'));
        assert!(text.contains("COLLECTIVE SUBJECT"), "a fresh cell is a collective subject");
        assert!(text.contains("agent snapshot"), "the agent JSON panel is present");
        assert!(text.contains("\"ready\":true"), "the live JSON reflects readiness");
    }

    #[test]
    fn a_collapsed_cell_shows_not_ready() {
        let mut app = App::new(Box::new(ScenarioSource::new()));
        for _ in 0..20 {
            app.control(Control::Attack);
        }
        for _ in 0..5000 {
            app.on_tick();
        }
        let text = rendered_text(&app);
        assert!(text.contains("NOT READY"), "a cell driven past a* shows NOT READY");
    }

    use crate::source::Control;
}
