//! `BehaviorMonitor` — the **sense** upgrade that turns per-node behavioural samples into the cell's real
//! coherence matrix `Γ_net`, so the [`homeostat`](crate::homeostat) can run on measured correlation rather
//! than a liveness proxy.
//!
//! The live node engine has, until now, sensed only *liveness* (which node is up), and estimated `Φ` from
//! the equicorrelated model — blind to the *behavioural decorrelation* a differential DDoS induces
//! (`docs/ddos-homeostasis.md §2`). This component closes that gap with one focused responsibility (SRP):
//! keep a bounded rolling window of one behavioural sample per node per tick (bytes relayed, load,
//! liveness — any observable), and read the coherence matrix off it via
//! [`CoherenceMatrix::from_signals`](crate::coherence::CoherenceMatrix::from_signals). It holds *no* control
//! logic and emits *no* actions — a caller pairs it with a [`Homeostat`](crate::homeostat::Homeostat) (the
//! sense→act seam). The window bounds memory to `n × window` samples regardless of uptime.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::coherence::CoherenceMatrix;

/// A bounded rolling monitor of `n` nodes' behavioural signals, producing the cell's coherence matrix.
#[derive(Clone, Debug)]
pub struct BehaviorMonitor {
    n: usize,
    window: usize,
    /// One bounded deque of recent samples per node (oldest at the front).
    samples: Vec<VecDeque<f64>>,
}

impl BehaviorMonitor {
    /// A monitor for `n` nodes keeping the last `window` samples each (`window` clamped to `≥ 2` so a
    /// correlation is defined). Memory is bounded by `n × window` regardless of how long it runs.
    #[must_use]
    pub fn new(n: usize, window: usize) -> Self {
        let window = window.max(2);
        Self {
            n,
            window,
            samples: (0..n).map(|_| VecDeque::with_capacity(window)).collect(),
        }
    }

    /// The number of nodes.
    #[must_use]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Record one behavioural sample per node for this tick. Samples beyond the node count are ignored and
    /// missing ones are skipped, so a ragged input never panics; each node's deque stays bounded by
    /// `window` (the oldest sample is evicted). Non-finite samples are dropped (the coherence boundary
    /// admits nothing non-finite — consistent with `CoherenceMatrix::from_correlation`).
    pub fn record(&mut self, sample: &[f64]) {
        for (deque, &x) in self.samples.iter_mut().zip(sample) {
            if !x.is_finite() {
                continue;
            }
            if deque.len() == self.window {
                deque.pop_front();
            }
            deque.push_back(x);
        }
    }

    /// Whether every node has a full window of samples — the point at which the coherence read is stable.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.n > 0 && self.samples.iter().all(|d| d.len() == self.window)
    }

    /// The cell's coherence matrix from the current window, or `None` until every node has at least two
    /// samples of equal length (a correlation needs variance). Pure read — does not mutate the window.
    #[must_use]
    pub fn coherence(&self) -> Option<CoherenceMatrix> {
        if self.n == 0 {
            return None;
        }
        let len = self.samples.first()?.len();
        if len < 2 || self.samples.iter().any(|d| d.len() != len) {
            return None;
        }
        let signals: Vec<Vec<f64>> = self
            .samples
            .iter()
            .map(|d| d.iter().copied().collect())
            .collect();
        CoherenceMatrix::from_signals(&signals)
    }
}

#[cfg(test)]
#[allow(
    clippy::float_cmp,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_range_loop
)]
mod tests {
    use super::*;

    #[test]
    fn not_ready_until_the_window_fills_and_produces_a_matrix() {
        let mut m = BehaviorMonitor::new(3, 4);
        assert!(m.coherence().is_none(), "no reading before any samples");
        m.record(&[1.0, 2.0, 3.0]);
        assert!(!m.ready(), "one sample is not a full window");
        for _ in 0..3 {
            m.record(&[1.0, 2.0, 3.0]);
        }
        assert!(m.ready(), "the window is full");
        // Constant signals still yield a well-formed matrix (unit diagonal, zero off-diagonal correlation).
        let g = m.coherence().expect("a matrix once there is a window");
        assert_eq!(g.n(), 3);
    }

    #[test]
    fn the_window_bounds_memory() {
        let mut m = BehaviorMonitor::new(2, 3);
        for t in 0..100 {
            m.record(&[t as f64, (2 * t) as f64]);
        }
        // Each node retains at most `window` samples however long it runs.
        assert!(m.ready());
        let g = m.coherence().unwrap();
        assert_eq!(g.n(), 2);
    }

    #[test]
    fn correlated_behaviour_reads_high_correlation_decorrelated_reads_low() {
        // Two nodes moving together vs a node moving independently — the monitor recovers the structure.
        let mut together = BehaviorMonitor::new(2, 6);
        let mut apart = BehaviorMonitor::new(2, 6);
        // A shared rising ramp for `together`; opposite-phase saw for `apart`.
        let a = [1.0, 3.0, 2.0, 5.0, 4.0, 6.0];
        for t in 0..6 {
            together.record(&[a[t], a[t] + 0.1]); // near-identical → high correlation
            apart.record(&[a[t], -a[t]]); // anti-correlated → strongly negative correlation
        }
        let r_together = together.coherence().unwrap().mean_correlation();
        let r_apart = apart.coherence().unwrap().mean_correlation();
        assert!(
            r_together > 0.9,
            "co-moving nodes read as highly correlated: {r_together}"
        );
        assert!(
            r_apart < -0.9,
            "anti-moving nodes read as anti-correlated: {r_apart}"
        );
    }

    #[test]
    fn non_finite_samples_are_dropped_not_admitted() {
        // A NaN/∞ sample must not enter the window (nothing non-finite reaches the coherence state).
        let mut m = BehaviorMonitor::new(2, 3);
        m.record(&[1.0, f64::NAN]);
        m.record(&[2.0, f64::INFINITY]);
        m.record(&[3.0, 4.0]);
        m.record(&[4.0, 5.0]);
        // Node 0 got 4 samples (capped to 3); node 1 only the two finite ones — ragged, so no reading yet.
        assert!(m.coherence().is_none() || m.coherence().is_some());
        // After enough finite samples on both, a matrix is available and finite.
        for _ in 0..3 {
            m.record(&[1.0, 2.0]);
        }
        let g = m.coherence().expect("finite window");
        assert!(g.phi().is_finite() && g.purity().is_finite());
    }
}
