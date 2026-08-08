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
//! * [`observe_measured`](SelfObserver::observe_measured) — fold a measured matrix (this node's
//!   plus its peers', from gossip) into a frame, record its scalars, and return it to publish.


use fanos_diakrisis::coherence::CoherenceMatrix;

use crate::frame::{CellId, CoherenceFrame};
use crate::history::{HistoryConfig, MetricStore};
use crate::sysmetrics::SystemSample;

/// A node's mandatory self-observation state: its local history, healing counter, and cell identity.
#[derive(Clone, Debug)]
pub struct SelfObserver {
    cell_id: CellId,
    history: MetricStore,
    heal_seq: u32,
}

impl SelfObserver {
    /// A new observer for the cell `cell_id`, keeping bounded local history under `config`.
    #[must_use]
    /// **No window length.** The observer used to carry one, for the sole purpose of computing
    /// `epoch = now_nanos / window_nanos` inside `observe_cell` — which is the derivation audit A3 removed
    /// from `observe_liveness`, because under a real transport that quotient is each node's *local*
    /// elapsed time and two nodes stamp one window with different epochs. Deleting the dead path left the
    /// field unread, which is the tell: it existed only to serve the wrong epoch. Every fold now takes the
    /// cell's **agreed** epoch from its caller.
    pub fn new(cell_id: CellId, config: HistoryConfig) -> Self {
        Self {
            cell_id,
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

    /// Fold a **measured** coherence matrix into a [`CoherenceFrame`], record it, and return it to publish.
    ///
    /// This is the path a node with a full observation window takes, and it exists because the one beside it
    /// cannot carry what a real matrix knows. [`observe_liveness`](Self::observe_liveness) *synthesises* an
    /// equicorrelated matrix from a single scalar, and an equicorrelated matrix has
    /// `dispersion ≡ 0` and a flat diagonal **by construction** — so every second-dimension quantity in the
    /// frame was structurally zero on every production node, however concentrated the real cell was (#226).
    /// The frame's own `dispersion()` doc says a zero reading and a high one "want opposite operator
    /// responses"; only one of the two was reachable.
    ///
    /// `epoch` is the cell's **agreed** epoch, passed in for the same reason `observe_liveness` takes it and
    /// not `now_nanos / window_nanos`: under a real transport that quotient is each node's *local* elapsed
    /// time, so two nodes stamp one window with different epochs and any `(cell_id, epoch)` roll-up
    /// mis-buckets (audit A3). The `observe_cell` this replaced computed exactly that quotient — the defect
    /// A3 removed from the live sibling, still sitting in the one nothing called.
    pub fn observe_measured(
        &mut self,
        now_nanos: u64,
        epoch: u64,
        matrix: &CoherenceMatrix,
        degraded: u8,
        gap: f64,
        forecast: i16,
    ) -> CoherenceFrame {
        let frame = CoherenceFrame::observe(
            self.cell_id,
            epoch,
            matrix,
            degraded,
            gap,
            forecast,
            self.heal_seq,
            true, // a real matrix — measured by construction, which is what the bit is for (#154)
        );
        self.history.record_frame(now_nanos, &frame);
        frame
    }

    /// Fold a frame from a liveness-only view, when full per-node signal vectors are not (yet)
    /// gathered: model the cell as equicorrelated over its `alive_count` live nodes at the healthy
    /// correlation `correlation`, with the real `degraded` syndrome from missed heartbeats. This is
    /// the honest minimal self-observation a node can always produce — the 3-bit syndrome is exact;
    /// the coherence scalars are the model's (design-telemetry.md §2: the syndrome is load-bearing).
    /// Records the frame and returns it to publish.
    ///
    /// `measured` says where `correlation` came from and it is **not optional bookkeeping** (#154). The
    /// caller falls back to a configured constant when it has no observation window, and at the shipped
    /// `healthy_correlation = 0.45` that constant produces a frame reading healthy on every axis — `Φ =
    /// 1.215`, `P = 0.3164`, `R = 0.4514`, `r` inside the band — from a node that has measured nothing. The
    /// bit is what lets a reader tell that frame from a real one.
    #[allow(clippy::too_many_arguments)] // distinct scalar inputs to the fold; a params struct adds no clarity
    pub fn observe_liveness(
        &mut self,
        now_nanos: u64,
        epoch: u64,
        alive_count: usize,
        correlation: f64,
        measured: bool,
        degraded: u8,
        gap: f64,
        forecast: i16,
    ) -> CoherenceFrame {
        // The frame's `epoch` is the cell's **agreed** epoch (the adopt-max flooded beacon), supplied by
        // the caller — NOT `now_nanos / window`, which under a real transport is each node's *local*
        // elapsed time, so two nodes would stamp different epochs on the same window and any
        // `(cell_id, epoch)` cross-node roll-up would mis-bucket (audit A3). `now_nanos` still times the
        // local RRD history below.
        let matrix = CoherenceMatrix::equicorrelated(alive_count.max(1), correlation);
        let frame = CoherenceFrame::observe(
            self.cell_id,
            epoch,
            &matrix,
            degraded,
            gap,
            forecast,
            self.heal_seq,
            measured,
        );
        self.history.record_frame(now_nanos, &frame);
        frame
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::history::MetricId;

    #[test]
    fn observe_local_records_and_returns_pressure() {
        let mut obs = SelfObserver::new(CellId([1; 16]), HistoryConfig::compact());
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
    fn a_measured_matrix_reaches_the_frame_with_its_second_dimension_intact() {
        // The property #226 exists for: a frame folded from a REAL matrix carries what that matrix knows,
        // and in particular a non-zero dispersion — which the synthesised-equicorrelated path can never
        // produce, because an equicorrelated matrix has `dispersion ≡ 0` by construction.
        let mut obs = SelfObserver::new(CellId([7; 16]), HistoryConfig::compact());
        // A 4-of-7 clique with the other three uncoupled — the shape that actually reaches the
        // under-coupled band on a matrix a cell can HAVE. (A star cannot: positive semi-definiteness puts
        // `λ_min = 1 − c√6 ≥ 0`, so a star's hub correlation is capped at `1/√6`, and the strongest
        // admissible star reaches only `Φ = 0.4077`. `from_correlation` refuses the rest, which is how this
        // test found the constraint.) Here `Φ = 1.0971` with `dispersion = 0.1306` and a mean of `0.2286`,
        // below the floor: gate open, and open on INEQUALITY rather than on consistency.
        let n = 7;
        let mut c = vec![0.0; n * n];
        for i in 0..n {
            c[i * n + i] = 1.0;
            for j in 0..n {
                if i != j && i < 4 && j < 4 {
                    c[i * n + j] = 0.8;
                }
            }
        }
        let uneven = CoherenceMatrix::from_correlation(c, n).expect("a block matrix is PSD");
        let frame = obs.observe_measured(2_000_000_000, 3, &uneven, 0b0000_0010, 0.4, -1);
        assert!(
            frame.dispersion() > 0.13,
            "the cell's dispersion must survive the fold, got {}",
            frame.dispersion()
        );

        // And the contrast that makes the number mean something: the synthesised path, same cell size,
        // cannot report any dispersion at all.
        let flat = obs.observe_liveness(2_000_000_000, 3, 7, 0.45, true, 0, 0.4, -1);
        // Measured, both: the real cell folds to **0.13061224** — the analytic `0.1306` to the frame's
        // precision — and the synthesised one to **1.31e-8**, which is zero up to `f32` rounding of the
        // three scalars `dispersion()` reconstructs from. Ten million to one. The bound below is taken from
        // those two numbers rather than guessed, and it sits four orders above the residue and four below
        // the signal.
        assert!(
            flat.dispersion() < 1e-6,
            "the equicorrelated fold reads zero dispersion by construction — that is the defect #226 \
             names, and it is what every production frame reported: got {}",
            flat.dispersion()
        );
    }


    #[test]
    fn liveness_frame_carries_the_syndrome_and_is_recorded() {
        let mut obs = SelfObserver::new(CellId([5; 16]), HistoryConfig::compact());
        // 6 alive, point 0 faulted (bit 0 set), healthy correlation 0.5. The frame stamps the AGREED
        // epoch passed in (3), NOT now_nanos/window (which here would be 9) — so nodes at different local
        // clocks but the same beacon epoch agree on the frame epoch (audit A3).
        let frame = obs.observe_liveness(9_000_000_000, 3, 6, 0.5, true, 0b0000_0001, 0.4, -1);
        assert_eq!(
            frame.epoch, 3,
            "frame epoch is the agreed epoch, decoupled from the local clock"
        );
        assert!(frame.is_faulted(), "a real syndrome from the degraded mask");
        assert!(
            obs.history()
                .series(MetricId::PHI)
                .unwrap()
                .latest()
                .is_some()
        );
    }

    #[test]
    fn healing_counter_is_monotone() {
        let mut obs = SelfObserver::new(CellId([4; 16]), HistoryConfig::compact());
        assert_eq!(obs.heal_seq(), 0);
        assert_eq!(obs.note_healing(), 1);
        assert_eq!(obs.note_healing(), 2);
        assert_eq!(obs.heal_seq(), 2);
    }
}
