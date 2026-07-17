//! The mandatory per-node self-observation loop.
//!
//! [`SelfObserver`] is the component every node embeds and drives **every observation window** — it is
//! not a plugin the operator can disable, because self-observation is load-bearing: it feeds
//! self-diagnosis, self-healing (the regenerator `ℛ`), and load balancing. The observer is pure
//! (sans-I/O): the driver hands it the freshly-sampled local vitals and the cell's collected per-node
//! signals; the observer records them into its local [`history`](crate::history) and folds the cell
//! into a [`CoherenceFrame`] to emit. Keeping it pure means the *same* observer runs identically
//! under the simulator and in production (the monism: one engine, two drivers).
//!
//! Two calls per window:
//! * [`observe_local`](SelfObserver::observe_local) — record this node's own vitals; returns the
//!   scalar `pressure` signal the node gossips to its cell.
//! * [`observe_cell`](SelfObserver::observe_cell) — fold the cell's collected signals (this node's
//!   plus its peers', from gossip) into a frame, record its scalars, and return it to publish.

use alloc::vec::Vec;

use fanos_diakrisis::coherence::CoherenceMatrix;

use crate::frame::{CellId, CoherenceFrame};
use crate::history::{HistoryConfig, MetricStore};
use crate::sysmetrics::SystemSample;

/// A node's mandatory self-observation state: its local history, healing counter, and cell identity.
#[derive(Clone, Debug)]
pub struct SelfObserver {
    cell_id: CellId,
    window_nanos: u64,
    history: MetricStore,
    heal_seq: u32,
}

impl SelfObserver {
    /// A new observer for the cell `cell_id`, keeping `window_nanos`-spaced history under `config`.
    #[must_use]
    pub fn new(cell_id: CellId, window_nanos: u64, config: HistoryConfig) -> Self {
        Self {
            cell_id,
            window_nanos: window_nanos.max(1),
            history: MetricStore::new(config),
            heal_seq: 0,
        }
    }

    /// Record this node's own vitals into local history and return its `pressure` — the single scalar
    /// signal the node contributes to the cell's coherence correlation (gossiped to peers).
    pub fn observe_local(&mut self, now_nanos: u64, sample: &SystemSample) -> f64 {
        self.history.record_sample(now_nanos, sample);
        sample.pressure()
    }

    /// Fold the cell's collected per-node `signals` (each a short recent window of a node's pressure)
    /// into a [`CoherenceFrame`], record its scalars into history, and return it to publish. The
    /// `degraded` bitmask (faulted points) becomes the syndrome; `gap` is the spectral gap `Δ`;
    /// `forecast` is the cascade lead (`-1` = none). `None` if a coherence matrix cannot be formed
    /// (too few signals) — the caller still gossips liveness, but there is no cell frame this window.
    pub fn observe_cell(
        &mut self,
        now_nanos: u64,
        signals: &[Vec<f64>],
        degraded: u8,
        gap: f64,
        forecast: i16,
    ) -> Option<CoherenceFrame> {
        let matrix = CoherenceMatrix::from_signals(signals)?;
        let epoch = now_nanos / self.window_nanos;
        let frame = CoherenceFrame::observe(
            self.cell_id,
            epoch,
            &matrix,
            degraded,
            gap,
            forecast,
            self.heal_seq,
        );
        self.history.record_frame(now_nanos, &frame);
        Some(frame)
    }

    /// Note that a healing action fired: bump and return the monotone `heal_seq` (the sparse healing
    /// event stream is keyed off this, so it costs nothing in steady state).
    pub fn note_healing(&mut self) -> u32 {
        self.heal_seq = self.heal_seq.wrapping_add(1);
        self.heal_seq
    }

    /// This node's local metric history (for a `--monitor` read or trend-based balancing).
    #[must_use]
    pub fn history(&self) -> &MetricStore {
        &self.history
    }

    /// The current healing-action counter.
    #[must_use]
    pub fn heal_seq(&self) -> u32 {
        self.heal_seq
    }

    /// The cell this observer watches.
    #[must_use]
    pub fn cell_id(&self) -> CellId {
        self.cell_id
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;
    use crate::history::MetricId;

    #[test]
    fn observe_local_records_and_returns_pressure() {
        let mut obs = SelfObserver::new(CellId([1; 16]), 1_000_000_000, HistoryConfig::compact());
        let sample = SystemSample {
            cpu_busy: 0.6,
            mem_used: 0.4,
            available: true,
            ..Default::default()
        };
        let pressure = obs.observe_local(0, &sample);
        // pressure = 0.5*0.6 + 0.3*0.4 + 0.2*0 = 0.42.
        assert!((pressure - 0.42).abs() < 1e-6);
        let cpu = obs
            .history()
            .series(MetricId::CPU)
            .unwrap()
            .latest()
            .unwrap()
            .last;
        assert!((cpu - 0.6).abs() < 1e-6, "recorded the CPU sample");
    }

    #[test]
    fn observe_cell_folds_signals_into_a_recorded_frame() {
        let mut obs = SelfObserver::new(CellId([2; 16]), 1_000_000_000, HistoryConfig::compact());
        // Seven nodes, each a short window of correlated-but-distinct pressure signals.
        let signals: Vec<Vec<f64>> = (0..7)
            .map(|k| {
                (0..8)
                    .map(|t| 0.3 + 0.1 * f64::from(t) + 0.01 * f64::from(k))
                    .collect()
            })
            .collect();
        let frame = obs
            .observe_cell(2_000_000_000, &signals, 0, 0.5, -1)
            .expect("a matrix forms from 7 signals");
        assert_eq!(frame.epoch, 2, "epoch = now / window");
        assert_eq!(frame.cell_id, CellId([2; 16]));
        // The frame's coherence scalars were recorded into history.
        assert!(obs.history().series(MetricId::PHI).is_some());
        assert!(
            obs.history()
                .series(MetricId::MEAN_R)
                .unwrap()
                .latest()
                .is_some()
        );
    }

    #[test]
    fn too_few_signals_yield_no_frame() {
        let mut obs = SelfObserver::new(CellId([3; 16]), 1_000_000_000, HistoryConfig::compact());
        assert!(obs.observe_cell(0, &[], 0, 0.0, -1).is_none());
    }

    #[test]
    fn healing_counter_is_monotone() {
        let mut obs = SelfObserver::new(CellId([4; 16]), 1_000_000_000, HistoryConfig::compact());
        assert_eq!(obs.heal_seq(), 0);
        assert_eq!(obs.note_healing(), 1);
        assert_eq!(obs.note_healing(), 2);
        assert_eq!(obs.heal_seq(), 2);
    }
}
