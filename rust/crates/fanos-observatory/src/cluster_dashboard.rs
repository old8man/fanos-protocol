//! The **cluster dashboard** — a scale-legible view of a whole federation of cells (`fanos-lab watch`).
//!
//! The single-cell [`ui`](crate::ui) panel renders one 7-node cell's instrument readout; this renders a
//! *cluster* of hundreds-to-thousands of nodes. At that scale you cannot show every node, so the view is
//! aggregate-first: cluster vitals (alive / reporting / mean Φ / healthy), the regime and alarm
//! distributions, the run metrics, and a **cell-health heatmap** — one cell per glyph, coloured by that
//! cell's worst state — so a single degraded cell among a thousand is visible at a glance. Optionally it
//! drills into one selected cell's seven nodes.
//!
//! Pure: [`render_cluster`] draws entirely from a [`ClusterDashboard`], so it is `TestBackend`-testable
//! with no real terminal (the same discipline as [`crate::ui`]).

#![allow(clippy::indexing_slicing)]

use std::collections::VecDeque;

use fanos_sim::{ClusterSnapshot, FleetSnapshot};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Sparkline, Wrap};

const READY: Color = Color::Green;
const WARN: Color = Color::Yellow;
const CRIT: Color = Color::Magenta;
const DEAD: Color = Color::Red;
const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;

/// How many recent mean-Φ samples the trend sparkline keeps.
const HISTORY: usize = 512;

/// The cluster dashboard's render state: the latest snapshot, a mean-Φ history, a caption, and which cell
/// (if any) is selected for drill-down. The event loop owns the [`Cluster`](fanos_sim::Cluster), steps it,
/// and feeds each new snapshot in via [`update`](ClusterDashboard::update).
pub struct ClusterDashboard {
    snapshot: ClusterSnapshot,
    phi_history: VecDeque<u64>,
    label: String,
    selected: Option<usize>,
    paused: bool,
    /// Set when the operator asks to quit.
    pub should_quit: bool,
}

impl ClusterDashboard {
    /// A new dashboard over an initial snapshot, captioned (e.g. `"seed 7"`).
    #[must_use]
    pub fn new(snapshot: ClusterSnapshot, label: impl Into<String>) -> Self {
        let mut dash = Self {
            snapshot,
            phi_history: VecDeque::with_capacity(HISTORY),
            label: label.into(),
            selected: None,
            paused: false,
            should_quit: false,
        };
        dash.record();
        dash
    }

    /// Replace the snapshot and extend the Φ trend.
    pub fn update(&mut self, snapshot: ClusterSnapshot) {
        self.snapshot = snapshot;
        self.record();
    }

    fn record(&mut self) {
        let phi = self.snapshot.totals.mean_phi;
        let sample = if phi.is_finite() { (phi * 1000.0).round().max(0.0) as u64 } else { 0 };
        if self.phi_history.len() == HISTORY {
            self.phi_history.pop_front();
        }
        self.phi_history.push_back(sample);
    }

    /// The current snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &ClusterSnapshot {
        &self.snapshot
    }

    /// Whether the feed is paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Toggle pause.
    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    /// The selected cell index, if any.
    #[must_use]
    pub fn selected(&self) -> Option<usize> {
        self.selected
    }

    /// Move the drill-down selection by `delta` (wrapping), or clear it if there are no cells.
    pub fn select_delta(&mut self, delta: isize) {
        let n = self.snapshot.cell_count();
        if n == 0 {
            self.selected = None;
            return;
        }
        let cur = self.selected.unwrap_or(0) as isize;
        self.selected = Some((cur + delta).rem_euclid(n as isize) as usize);
    }

    /// Clear the drill-down selection (back to the whole-cluster view).
    pub fn clear_selection(&mut self) {
        self.selected = None;
    }

    /// Select the next troubled cell after the current selection (wrapping) — fast triage when a handful
    /// of cells among thousands need attention. No-op if nothing is troubled.
    pub fn select_next_troubled(&mut self) {
        let n = self.snapshot.cell_count();
        if n == 0 {
            return;
        }
        let start = self.selected.map_or(0, |s| s + 1);
        for off in 0..n {
            let i = (start + off) % n;
            if self.snapshot.cells[i].concerns().next().is_some() {
                self.selected = Some(i);
                return;
            }
        }
    }
}

/// The health colour of a whole cell — the worst state any of its nodes is in.
fn cell_color(cell: &FleetSnapshot) -> Color {
    let s = &cell.stats;
    if s.alive < s.total {
        DEAD // a crashed member
    } else if s.faulted > 0 || s.alarms.structure > 0 {
        CRIT
    } else if s.alarms.integration > 0 {
        WARN
    } else {
        READY
    }
}

/// Draw the whole cluster dashboard.
pub fn render_cluster(f: &mut Frame<'_>, dash: &ClusterDashboard) {
    let snap = &dash.snapshot;
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(9), // vitals + distributions
            Constraint::Min(3),    // cell heatmap or drill-down
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    render_header(f, root[0], dash);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(root[1]);
    render_vitals(f, mid[0], dash);
    render_distributions(f, mid[1], snap);

    match dash.selected {
        Some(i) if i < snap.cells.len() => render_cell_detail(f, root[2], i, &snap.cells[i]),
        _ => render_heatmap(f, root[2], snap),
    }
    render_footer(f, root[3], dash);
}

fn render_header(f: &mut Frame<'_>, area: Rect, dash: &ClusterDashboard) {
    let snap = &dash.snapshot;
    let healthy = snap.totals.is_healthy() && snap.totals.alive == snap.totals.total;
    let (verdict_txt, verdict_col) = if healthy { (" ● HEALTHY ", READY) } else { (" ● DEGRADED ", CRIT) };
    let paused = if dash.paused { "  ⏸ PAUSED" } else { "" };
    let title = Line::from(vec![
        Span::styled("◇ FANOS Cluster Lab", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!(
                "   {} nodes · {} cells · {}   t={:.1}s",
                snap.totals.total,
                snap.cell_count(),
                dash.label,
                snap.at_nanos as f64 / 1e9,
            ),
            Style::default().fg(MUTED),
        ),
        Span::styled(paused.to_string(), Style::default().fg(WARN)),
    ]);
    let verdict = Line::from(vec![Span::styled(
        verdict_txt,
        Style::default().fg(Color::Black).bg(verdict_col).add_modifier(Modifier::BOLD),
    )])
    .alignment(Alignment::Right);

    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(MUTED));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(13)])
        .split(inner);
    f.render_widget(Paragraph::new(title), cols[0]);
    f.render_widget(Paragraph::new(verdict), cols[1]);
}

fn render_vitals(f: &mut Frame<'_>, area: Rect, dash: &ClusterDashboard) {
    let s = &dash.snapshot.totals;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // alive
            Constraint::Length(1), // reporting
            Constraint::Length(1), // mean Φ
            Constraint::Length(1), // healthy fraction
            Constraint::Length(1), // spacer
            Constraint::Min(1),    // Φ trend
        ])
        .split(area);

    let frac = |num: usize| if s.total == 0 { 0.0 } else { num as f64 / s.total as f64 };
    let healthy_nodes = s.alarms.healthy;
    line_gauge(f, rows[0], "alive    ", frac(s.alive), format!("{}/{}", s.alive, s.total), READY);
    line_gauge(f, rows[1], "reporting", frac(s.reporting), format!("{}/{}", s.reporting, s.total), ACCENT);
    let phi = if s.mean_phi.is_finite() { s.mean_phi } else { 0.0 };
    line_gauge(f, rows[2], "mean Φ   ", (phi / 2.0).clamp(0.0, 1.0), format!("{phi:.3}  (≥1)"), if phi >= 1.0 { READY } else { WARN });
    line_gauge(f, rows[3], "healthy  ", frac(healthy_nodes), format!("{healthy_nodes}/{}", s.total), if healthy_nodes == s.total { READY } else { WARN });

    let spark = Sparkline::default()
        .block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(MUTED)).title(
            Span::styled(" Φ trend ", Style::default().fg(Color::Gray)),
        ))
        .data(dash.phi_history.iter().copied().collect::<Vec<_>>())
        .style(Style::default().fg(ACCENT));
    f.render_widget(spark, rows[5]);
}

fn render_distributions(f: &mut Frame<'_>, area: Rect, snap: &ClusterSnapshot) {
    let s = &snap.totals;
    let m = &snap.metrics;
    let text = vec![
        Line::from(vec![
            Span::styled("regimes  ", Style::default().fg(Color::Gray)),
            Span::styled(format!("aggregate {}  ", s.regimes.aggregate), Style::default().fg(WARN)),
            Span::styled(format!("collective {}  ", s.regimes.collective_subject), Style::default().fg(READY)),
            Span::styled(format!("over-coupled {}", s.regimes.over_coupled), Style::default().fg(CRIT)),
        ]),
        Line::from(vec![
            Span::styled("alarms   ", Style::default().fg(Color::Gray)),
            Span::styled(format!("healthy {}  ", s.alarms.healthy), Style::default().fg(READY)),
            Span::styled(format!("integration {}  ", s.alarms.integration), Style::default().fg(WARN)),
            Span::styled(format!("structure {}", s.alarms.structure), Style::default().fg(CRIT)),
        ]),
        Line::from(vec![
            Span::styled("state    ", Style::default().fg(Color::Gray)),
            Span::styled(format!("faulted {}  ", s.faulted), Style::default().fg(if s.faulted > 0 { CRIT } else { MUTED })),
            Span::styled(format!("ready {}", s.ready), Style::default().fg(READY)),
        ]),
        Line::from(vec![
            Span::styled("traffic  ", Style::default().fg(Color::Gray)),
            Span::styled(format!("frames {}  ", m.frames_delivered), Style::default().fg(Color::Gray)),
            Span::styled(format!("reroutes {}  ", m.reroutes), Style::default().fg(if m.reroutes > 0 { WARN } else { MUTED })),
            Span::styled(format!("repairs {}  ", m.repairs), Style::default().fg(if m.repairs > 0 { WARN } else { MUTED })),
            Span::styled(format!("quarantines {}", m.quarantines), Style::default().fg(if m.quarantines > 0 { CRIT } else { MUTED })),
        ]),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED))
        .title(Span::styled(" distributions ", Style::default().fg(Color::Gray)));
    f.render_widget(Paragraph::new(text).block(block).wrap(Wrap { trim: true }), area);
}

fn render_heatmap(f: &mut Frame<'_>, area: Rect, snap: &ClusterSnapshot) {
    // One glyph per cell, coloured by the cell's worst state — a degraded cell among thousands pops out.
    let spans: Vec<Span<'_>> = snap
        .cells
        .iter()
        .map(|c| Span::styled("●", Style::default().fg(cell_color(c))))
        .collect();
    let title = format!(
        " cells: {} · healthy {} · warn {} · crit {} · dead {} ",
        snap.cell_count(),
        snap.cells.iter().filter(|c| cell_color(c) == READY).count(),
        snap.cells.iter().filter(|c| cell_color(c) == WARN).count(),
        snap.cells.iter().filter(|c| cell_color(c) == CRIT).count(),
        snap.cells.iter().filter(|c| cell_color(c) == DEAD).count(),
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED))
        .title(Span::styled(title, Style::default().fg(Color::Gray)));
    f.render_widget(Paragraph::new(Line::from(spans)).block(block).wrap(Wrap { trim: false }), area);
}

fn render_cell_detail(f: &mut Frame<'_>, area: Rect, index: usize, cell: &FleetSnapshot) {
    let mut lines = vec![Line::from(Span::styled(
        format!("cell {index} — {} nodes, {} alive", cell.stats.total, cell.stats.alive),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    ))];
    for node in &cell.nodes {
        let (mark, col) = if !node.alive {
            ("✗ down ", DEAD)
        } else if let Some(c) = &node.coherence {
            match c.alarm {
                fanos_telemetry::AlarmLevel::Healthy => ("● healthy", READY),
                fanos_telemetry::AlarmLevel::Integration => ("● warn   ", WARN),
                fanos_telemetry::AlarmLevel::Structure => ("● struct ", CRIT),
            }
        } else {
            ("· quiet  ", MUTED)
        };
        let phi = node.coherence.as_ref().map_or(f64::NAN, |c| c.phi);
        lines.push(Line::from(vec![
            Span::styled(format!("  {:?}  ", node.coord), Style::default().fg(Color::Gray)),
            Span::styled(mark, Style::default().fg(col)),
            Span::styled(format!("  Φ={phi:.3}"), Style::default().fg(MUTED)),
        ]));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(format!(" cell {index} (↑↓ change · esc back) "), Style::default().fg(Color::Gray)));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_footer(f: &mut Frame<'_>, area: Rect, dash: &ClusterDashboard) {
    let hint = if dash.selected.is_some() {
        " q quit · space pause · ↑↓ change cell · t next issue · esc back to cluster "
    } else {
        " q quit · space pause · f fault · h heal · ←→ inspect a cell · t next issue "
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(hint, Style::default().fg(MUTED)))).alignment(Alignment::Center),
        area,
    );
}

/// A one-line labelled gauge (`label [██████  ] value`).
fn line_gauge(f: &mut Frame<'_>, area: Rect, label: &str, ratio: f64, value: String, col: Color) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(10), Constraint::Min(8)])
        .split(area);
    f.render_widget(Paragraph::new(Span::styled(label.to_string(), Style::default().fg(Color::Gray))), cols[0]);
    let g = Gauge::default()
        .gauge_style(Style::default().fg(col))
        .ratio(ratio.clamp(0.0, 1.0))
        .label(Span::styled(value, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)));
    f.render_widget(g, cols[1]);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::redundant_closure_for_method_calls)]
mod tests {
    use fanos_runtime::{Config, Duration};
    use fanos_sim::Cluster;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

    fn dashboard(cells: usize) -> ClusterDashboard {
        let mut cluster = Cluster::new(1, Config::default(), cells);
        cluster.run_for(Duration::from_millis(1200));
        ClusterDashboard::new(cluster.snapshot(), "seed 1")
    }

    #[test]
    fn renders_a_cluster_without_panicking_and_shows_the_headline() {
        let dash = dashboard(20); // 140 nodes
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|f| render_cluster(f, &dash)).unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("FANOS Cluster Lab"), "header present");
        assert!(text.contains("140 nodes"), "node count shown: {text:.0}");
        assert!(text.contains("HEALTHY"), "a fresh cluster reads healthy");
    }

    #[test]
    fn drilling_into_a_cell_shows_its_nodes() {
        let mut dash = dashboard(5);
        dash.select_delta(1); // select cell 0 → then to 1
        assert_eq!(dash.selected(), Some(1));
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|f| render_cluster(f, &dash)).unwrap();
        assert!(buffer_text(&terminal).contains("cell 1"), "drill-down header present");
    }

    #[test]
    fn jump_to_next_troubled_finds_the_degraded_cell() {
        let mut cluster = Cluster::new(1, Config::default(), 8);
        cluster.run_for(Duration::from_millis(1200));
        // Crash a node in cell 3 — it immediately reads not-alive, so cell 3 is the only troubled one.
        let victim = cluster.cell(3).unwrap().nodes().next().unwrap();
        cluster.cell_mut(3).unwrap().crash(victim);
        let mut dash = ClusterDashboard::new(cluster.snapshot(), "t");
        dash.select_next_troubled();
        assert_eq!(dash.selected(), Some(3), "triage jumps straight to the troubled cell");
    }

    #[test]
    fn selection_wraps_and_clears() {
        let mut dash = dashboard(3);
        dash.select_delta(-1);
        assert_eq!(dash.selected(), Some(2), "−1 wraps to the last cell");
        dash.clear_selection();
        assert_eq!(dash.selected(), None);
    }

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }
}
