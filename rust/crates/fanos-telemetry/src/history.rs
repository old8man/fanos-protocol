//! Local time-series history — a configurable, bounded, multi-resolution metric store.
//!
//! Every node keeps a rolling local history of its vitals and coherence so an operator (or the node
//! itself, for trend-based balancing) can look back in time without a central collector. The design
//! is the proven round-robin-database (RRD) shape, chosen for *bounded memory with unbounded reach*:
//!
//! * **Tiers of decreasing resolution.** A [`Series`] holds several [`Tier`]s — e.g. 1 s buckets for
//!   the last hour, 1 min for the last day, 1 h for the last month. Recent history is fine-grained;
//!   old history is downsampled, never dropped wholesale. Total memory is fixed (the sum of tier
//!   capacities) regardless of how long the node runs.
//! * **Roll-up aggregation.** Each [`Bucket`] keeps `min/max/mean/last/count`, so downsampling loses
//!   no envelope information (a transient spike still shows as a `max`). A finalized fine bucket
//!   cascades up into the next coarser tier.
//! * **Programmable.** Metrics are keyed by an open [`MetricId`] space (well-known ids for the system
//!   and coherence signals; `≥ 1024` reserved for application overlays), so an overlay records its
//!   own series through the same store. Resolution/retention is a [`HistoryConfig`] knob.
//!
//! `O(1)` amortized [`record`](Series::record); range queries return the finest tier that covers the
//! window. Append-only and copy-cheap, so it is trivially snapshot-serializable for disk persistence.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::frame::CoherenceFrame;
use crate::sysmetrics::SystemSample;

/// One resolution-bucket: an aggregate of a scalar metric over a fixed time window.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Bucket {
    /// Window start (nanoseconds, aligned to the tier resolution).
    pub start_nanos: u64,
    /// Number of raw samples folded in.
    pub count: u32,
    /// Minimum value in the window.
    pub min: f64,
    /// Maximum value in the window.
    pub max: f64,
    /// Arithmetic mean of the window.
    pub mean: f64,
    /// The most recent value in the window.
    pub last: f64,
}

impl Bucket {
    fn new(start_nanos: u64, v: f64) -> Self {
        Self {
            start_nanos,
            count: 1,
            min: v,
            max: v,
            mean: v,
            last: v,
        }
    }

    fn from_bucket(start_nanos: u64, fine: &Self) -> Self {
        Self {
            start_nanos,
            ..*fine
        }
    }

    /// Fold one raw sample in (incremental mean, running min/max).
    fn add(&mut self, v: f64) {
        self.count = self.count.saturating_add(1);
        self.min = self.min.min(v);
        self.max = self.max.max(v);
        self.mean += (v - self.mean) / f64::from(self.count);
        self.last = v;
    }

    /// Fold a finer bucket in (count-weighted mean, envelope min/max) — the roll-up step.
    fn absorb(&mut self, fine: &Self) {
        let total = self.count.saturating_add(fine.count);
        if total > 0 {
            self.mean = (self.mean * f64::from(self.count) + fine.mean * f64::from(fine.count))
                / f64::from(total);
        }
        self.count = total;
        self.min = self.min.min(fine.min);
        self.max = self.max.max(fine.max);
        self.last = fine.last;
    }
}

/// One resolution level of a [`Series`]: a bounded ring of finalized buckets plus the in-progress one.
#[derive(Clone, Debug)]
pub struct Tier {
    resolution_nanos: u64,
    capacity: usize,
    finalized: VecDeque<Bucket>,
    current: Option<Bucket>,
}

impl Tier {
    fn new(resolution_nanos: u64, capacity: usize) -> Self {
        Self {
            resolution_nanos: resolution_nanos.max(1),
            capacity: capacity.max(1),
            finalized: VecDeque::new(),
            current: None,
        }
    }

    fn align(&self, t: u64) -> u64 {
        t - (t % self.resolution_nanos)
    }

    fn push(&mut self, b: Bucket) {
        if self.finalized.len() >= self.capacity {
            self.finalized.pop_front();
        }
        self.finalized.push_back(b);
    }

    /// Record a raw sample; returns the just-finalized bucket if this sample opened a new window.
    fn record(&mut self, now: u64, v: f64) -> Option<Bucket> {
        let start = self.align(now);
        match self.current {
            Some(ref mut b) if b.start_nanos == start => {
                b.add(v);
                None
            }
            _ => {
                let finalized = self.current.take();
                if let Some(f) = finalized {
                    self.push(f);
                }
                self.current = Some(Bucket::new(start, v));
                finalized
            }
        }
    }

    /// Roll a finalized finer bucket into this tier; returns any bucket this finalized in turn.
    fn absorb(&mut self, fine: &Bucket) -> Option<Bucket> {
        let start = self.align(fine.start_nanos);
        match self.current {
            Some(ref mut b) if b.start_nanos == start => {
                b.absorb(fine);
                None
            }
            _ => {
                let finalized = self.current.take();
                if let Some(f) = finalized {
                    self.push(f);
                }
                self.current = Some(Bucket::from_bucket(start, fine));
                finalized
            }
        }
    }

    /// This tier's buckets (finalized then the in-progress one) whose windows intersect `[from, to]`.
    fn range(&self, from: u64, to: u64) -> Vec<Bucket> {
        self.finalized
            .iter()
            .chain(self.current.iter())
            .filter(|b| b.start_nanos + self.resolution_nanos > from && b.start_nanos <= to)
            .copied()
            .collect()
    }

    /// The oldest window start this tier still holds (finalized front, else the current bucket).
    fn oldest(&self) -> Option<u64> {
        self.finalized
            .front()
            .or(self.current.as_ref())
            .map(|b| b.start_nanos)
    }
}

/// A single scalar metric over time at multiple resolutions (the RRD).
#[derive(Clone, Debug)]
pub struct Series {
    tiers: Vec<Tier>,
}

impl Series {
    /// A series with the given `(resolution_nanos, capacity)` tiers, finest first. An empty spec
    /// yields a single 1-second, 1-bucket tier (so a series is never degenerate).
    #[must_use]
    pub fn new(tiers: &[(u64, usize)]) -> Self {
        let tiers: Vec<Tier> = if tiers.is_empty() {
            alloc::vec![Tier::new(1_000_000_000, 1)]
        } else {
            tiers.iter().map(|&(r, c)| Tier::new(r, c)).collect()
        };
        Self { tiers }
    }

    /// Record a raw sample at `now_nanos`; the value cascades up through coarser tiers as fine
    /// buckets finalize. `O(tiers)` worst case, `O(1)` amortized.
    pub fn record(&mut self, now_nanos: u64, value: f64) {
        let mut carry = match self.tiers.first_mut() {
            Some(t0) => t0.record(now_nanos, value),
            None => return,
        };
        for tier in self.tiers.iter_mut().skip(1) {
            match carry {
                Some(fine) => carry = tier.absorb(&fine),
                None => break,
            }
        }
    }

    /// The best-resolution buckets covering `[from_nanos, to_nanos]`: the finest tier whose retained
    /// history reaches back to `from`, else the coarsest available.
    #[must_use]
    pub fn range(&self, from_nanos: u64, to_nanos: u64) -> Vec<Bucket> {
        for tier in &self.tiers {
            if tier.oldest().is_some_and(|o| o <= from_nanos) {
                return tier.range(from_nanos, to_nanos);
            }
        }
        self.tiers
            .last()
            .map_or_else(Vec::new, |t| t.range(from_nanos, to_nanos))
    }

    /// The most recent finalized-or-current bucket at the finest resolution.
    #[must_use]
    pub fn latest(&self) -> Option<Bucket> {
        let t0 = self.tiers.first()?;
        t0.current.or_else(|| t0.finalized.back().copied())
    }
}

/// A metric identifier — an open space so overlays add their own series. Well-known ids below;
/// application-defined metrics should use `>= APP_BASE`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct MetricId(pub u16);

impl MetricId {
    /// CPU busy fraction.
    pub const CPU: Self = Self(0);
    /// Memory used fraction.
    pub const MEM: Self = Self(1);
    /// Load average per core.
    pub const LOAD: Self = Self(2);
    /// Network bytes/s received.
    pub const NET_RX: Self = Self(3);
    /// Network bytes/s transmitted.
    pub const NET_TX: Self = Self(4);
    /// Disk bytes/s read.
    pub const DISK_READ: Self = Self(5);
    /// Disk bytes/s written.
    pub const DISK_WRITE: Self = Self(6);
    /// Coherence integration `Φ`.
    pub const PHI: Self = Self(7);
    /// Coherence structuredness `P`.
    pub const PURITY: Self = Self(8);
    /// Coherence reflection `R`.
    pub const REFLECTION: Self = Self(9);
    /// Mean inter-node correlation `r`.
    pub const MEAN_R: Self = Self(10);
    /// Spectral gap `Δ`.
    pub const GAP: Self = Self(11);
    /// First id reserved for application overlays.
    pub const APP_BASE: u16 = 1024;
}

/// The resolution/retention policy for a [`MetricStore`]'s series.
#[derive(Clone, Debug)]
pub struct HistoryConfig {
    /// `(resolution_nanos, capacity)` tiers, finest first.
    pub tiers: Vec<(u64, usize)>,
}

impl Default for HistoryConfig {
    /// 1 s × 1 h, 1 min × 1 day, 1 h × 30 days — ~5760 buckets/metric, a few hundred KB.
    fn default() -> Self {
        const S: u64 = 1_000_000_000;
        Self {
            tiers: alloc::vec![(S, 3600), (60 * S, 1440), (3600 * S, 720)],
        }
    }
}

impl HistoryConfig {
    /// A compact policy for memory-constrained nodes: 1 s × 5 min, 1 min × 2 h.
    #[must_use]
    pub fn compact() -> Self {
        const S: u64 = 1_000_000_000;
        Self {
            tiers: alloc::vec![(S, 300), (60 * S, 120)],
        }
    }
}

/// A node's local metric history: one [`Series`] per [`MetricId`], created lazily under one config.
#[derive(Clone, Debug)]
pub struct MetricStore {
    config: HistoryConfig,
    series: BTreeMap<MetricId, Series>,
}

impl MetricStore {
    /// A store whose series follow `config`.
    #[must_use]
    pub fn new(config: HistoryConfig) -> Self {
        Self {
            config,
            series: BTreeMap::new(),
        }
    }

    /// Record `value` for `id` at `now_nanos`, creating the series on first use.
    pub fn record(&mut self, id: MetricId, now_nanos: u64, value: f64) {
        self.series
            .entry(id)
            .or_insert_with(|| Series::new(&self.config.tiers))
            .record(now_nanos, value);
    }

    /// Fan a system sample out into its per-metric series.
    pub fn record_sample(&mut self, now_nanos: u64, s: &SystemSample) {
        self.record(MetricId::CPU, now_nanos, f64::from(s.cpu_busy));
        self.record(MetricId::MEM, now_nanos, f64::from(s.mem_used));
        self.record(MetricId::LOAD, now_nanos, f64::from(s.load_per_core));
        self.record(MetricId::NET_RX, now_nanos, s.net_rx_bps);
        self.record(MetricId::NET_TX, now_nanos, s.net_tx_bps);
        self.record(MetricId::DISK_READ, now_nanos, s.disk_read_bps);
        self.record(MetricId::DISK_WRITE, now_nanos, s.disk_write_bps);
    }

    /// Fan a coherence frame's scalars out into their per-metric series.
    pub fn record_frame(&mut self, now_nanos: u64, f: &CoherenceFrame) {
        self.record(MetricId::PHI, now_nanos, f64::from(f.phi));
        self.record(MetricId::PURITY, now_nanos, f64::from(f.purity));
        self.record(MetricId::REFLECTION, now_nanos, f64::from(f.reflection));
        self.record(MetricId::MEAN_R, now_nanos, f64::from(f.mean_r));
        self.record(MetricId::GAP, now_nanos, f64::from(f.gap));
    }

    /// The series for `id`, if any exists yet.
    #[must_use]
    pub fn series(&self, id: MetricId) -> Option<&Series> {
        self.series.get(&id)
    }

    /// The best-resolution buckets for `id` over `[from, to]` (empty if the metric is unknown).
    #[must_use]
    pub fn range(&self, id: MetricId, from_nanos: u64, to_nanos: u64) -> Vec<Bucket> {
        self.series
            .get(&id)
            .map_or_else(Vec::new, |s| s.range(from_nanos, to_nanos))
    }

    /// The metric ids that have at least one recorded sample.
    pub fn metrics(&self) -> impl Iterator<Item = MetricId> + '_ {
        self.series.keys().copied()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    #[test]
    fn bucket_aggregates_min_max_mean_last() {
        let mut b = Bucket::new(0, 2.0);
        b.add(4.0);
        b.add(6.0);
        assert_eq!((b.count, b.min, b.max, b.last), (3, 2.0, 6.0, 6.0));
        assert!((b.mean - 4.0).abs() < 1e-9);
    }

    #[test]
    fn a_finer_tier_rolls_up_into_a_coarser_one() {
        // 1 s fine, 10 s coarse.
        let mut series = Series::new(&[(S, 100), (10 * S, 100)]);
        // Ten 1-second samples with values 0..10 land in one 10-second coarse bucket.
        for i in 0..10u64 {
            series.record(i * S, i as f64);
        }
        // One more sample opens the next 1-s fine bucket, cascading value 9 up too.
        series.record(11 * S, 100.0);
        // The first 10-second coarse window (in progress) has rolled up all ten values 0..9.
        let coarse = series.tiers.get(1).unwrap();
        let first = coarse.current.unwrap();
        assert_eq!(first.start_nanos, 0);
        assert_eq!(first.count, 10);
        assert_eq!(first.min, 0.0);
        assert_eq!(first.max, 9.0, "envelope preserved through downsampling");
        assert!(
            (first.mean - 4.5).abs() < 1e-9,
            "count-weighted mean of 0..9"
        );
    }

    #[test]
    fn ring_is_bounded_and_drops_oldest() {
        let mut series = Series::new(&[(S, 3)]);
        for i in 0..10u64 {
            series.record(i * S, i as f64);
        }
        let all = series.range(0, 100 * S);
        // Capacity 3 finalized + 1 current = at most 4 retained; oldest windows dropped.
        assert!(all.len() <= 4, "bounded memory");
        assert_eq!(series.latest().unwrap().last, 9.0, "newest value retained");
    }

    #[test]
    fn range_picks_a_tier_that_reaches_back() {
        let mut series = Series::new(&[(S, 5), (10 * S, 100)]);
        for i in 0..60u64 {
            series.record(i * S, i as f64);
        }
        // The fine tier only retains ~5 s; a query reaching to 0 must fall back to the coarse tier.
        let deep = series.range(0, 60 * S);
        assert!(!deep.is_empty(), "coarse tier answers the deep query");
        assert!(
            deep.iter().any(|b| b.start_nanos == 0),
            "reaches back to t=0"
        );
    }

    #[test]
    fn store_fans_out_samples_and_frames() {
        let mut store = MetricStore::new(HistoryConfig::compact());
        let sample = SystemSample {
            cpu_busy: 0.5,
            mem_used: 0.25,
            available: true,
            ..Default::default()
        };
        store.record_sample(0, &sample);
        assert_eq!(
            store.series(MetricId::CPU).unwrap().latest().unwrap().last,
            0.5
        );
        assert_eq!(
            store.series(MetricId::MEM).unwrap().latest().unwrap().last,
            0.25
        );
        assert!(
            store.series(MetricId::PHI).is_none(),
            "no frame recorded yet"
        );

        let matrix = fanos_diakrisis::coherence::CoherenceMatrix::equicorrelated(7, 0.5);
        let frame = CoherenceFrame::observe(crate::CellId([0; 16]), 1, &matrix, 0, 0.5, -1, 0);
        store.record_frame(1_000, &frame);
        assert!(store.series(MetricId::PHI).unwrap().latest().unwrap().last > 1.0);
        // The 7 system metrics (cpu..disk_write) plus the 5 coherence scalars (phi..gap).
        assert_eq!(store.metrics().count(), 12);
    }
}
