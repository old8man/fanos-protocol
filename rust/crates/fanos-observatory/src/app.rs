//! The observatory application state: the snapshot source, the latest snapshot, and a short history of
//! `Φ` for the trend sparkline. Pure and terminal-agnostic — the event loop in `main` drives it and
//! the [`ui`](crate::ui) renders it, so both are unit-testable without a real terminal.

use std::collections::VecDeque;

use fanos_telemetry::CoherenceSnapshot;

use crate::source::{Control, SnapshotSource};

/// How many recent `Φ` samples the trend sparkline keeps.
const HISTORY: usize = 512;

/// The observatory app: a source, its latest snapshot, a `Φ` history, and whether the feed is paused.
pub struct App {
    source: Box<dyn SnapshotSource>,
    snapshot: CoherenceSnapshot,
    /// `Φ × 1000` samples (integers for [`ratatui::widgets::Sparkline`]), oldest first.
    phi_history: VecDeque<u64>,
    paused: bool,
    /// Set when the operator asks to quit.
    pub should_quit: bool,
}

impl App {
    /// A new app over `source`, seeded with its current snapshot.
    #[must_use]
    pub fn new(source: Box<dyn SnapshotSource>) -> Self {
        let snapshot = source.snapshot();
        let mut app = Self {
            source,
            snapshot,
            phi_history: VecDeque::with_capacity(HISTORY),
            paused: false,
            should_quit: false,
        };
        app.record();
        app
    }

    /// The latest snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &CoherenceSnapshot {
        &self.snapshot
    }

    /// The source's header label.
    #[must_use]
    pub fn source_label(&self) -> &str {
        self.source.label()
    }

    /// The source's decoherence pressure (fraction of the survival bound).
    #[must_use]
    pub fn pressure(&self) -> f64 {
        self.source.pressure()
    }

    /// Whether the live feed is paused.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// The source's degraded-node bitmask (the full footprint for the operator node map).
    #[must_use]
    pub fn degraded(&self) -> u8 {
        self.source.degraded()
    }

    /// The `Φ` trend history (oldest first) for the sparkline.
    #[must_use]
    pub fn phi_history(&self) -> &VecDeque<u64> {
        &self.phi_history
    }

    /// One observation window: advance the source (unless paused) and refresh the snapshot + history.
    pub fn on_tick(&mut self) {
        if !self.paused {
            self.source.tick();
            self.refresh();
        }
    }

    /// Apply an operator control and refresh immediately (so an injected fault shows at once).
    pub fn control(&mut self, op: Control) {
        self.source.control(op);
        self.refresh();
    }

    /// Toggle the paused state.
    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    /// Request shutdown.
    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    fn refresh(&mut self) {
        self.snapshot = self.source.snapshot();
        self.record();
    }

    fn record(&mut self) {
        // Φ ranges ~[0, ~2] in the collective-subject regime; scale to milli-units, clamp for the widget.
        let phi = (self.snapshot.phi.max(0.0) * 1000.0).min(u64::from(u32::MAX) as f64) as u64;
        if self.phi_history.len() == HISTORY {
            self.phi_history.pop_front();
        }
        self.phi_history.push_back(phi);
    }
}
