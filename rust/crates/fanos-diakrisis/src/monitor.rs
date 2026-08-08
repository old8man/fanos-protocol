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

    /// Drop every retained sample, keeping the shape (`n`, `window`).
    ///
    /// For the moment the samples stop meaning what their **column index** says they mean. Slot `i` is a
    /// cell position, and a position's occupant changes at an epoch boundary, so a window that spans one is
    /// a splice of two different node→seat assignments — the columns are no longer one time series each.
    /// Measured on the shipped `W = 178`: mean off-diagonal `r` falls from `0.835` to `0.07` mid-splice on a
    /// cell with 20× load spread, three to four band-widths, for the whole window (`reshuffle_phi.py`).
    ///
    /// A cleared monitor is not [`ready`](Self::ready) until it refills, which is the honest state and is
    /// also what makes the resolution requirement self-enforcing: where the derived window is longer than
    /// the epoch it must fit inside, refilling never completes and the loop it feeds stays silent.
    pub fn clear(&mut self) {
        for deque in &mut self.samples {
            deque.clear();
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
        // **A constant window yields NO matrix, and this line used to assert the opposite** (#229). It read
        // "constant signals still yield a well-formed matrix (unit diagonal, zero off-diagonal
        // correlation)", which encoded the defect as a property: a Pearson correlation needs variance, so a
        // window with none has an UNDEFINED correlation, not a zero one. The matrix it used to produce was
        // bit-identical to a cell of genuinely independent busy nodes and to a cell where nothing happened
        // — `Φ = 0`, `P = 1/7`, alarm `Structure` — and that reading escalated a coherence collapse.
        //
        // `ready()` is still true: the window IS full. Readiness is about samples, `coherence()` about
        // whether they say anything. Keeping both assertions here is the point — they are different
        // questions and the old test conflated them.
        assert!(
            m.coherence().is_none(),
            "a full window of constant samples has no definable correlation — `None`, not a zero matrix"
        );
        // Vary one node and the reading returns: the refusal above is about variance, not about the window.
        for i in 0..4 {
            m.record(&[1.0 + f64::from(i), 2.0, 3.0]);
        }
        let g = m.coherence().expect("variance restores a reading");
        assert_eq!(g.n(), 3);
    }

    /// **A window that spans a seat permutation reads a perfectly coherent cell as anti-correlated** (#153).
    ///
    /// The monitor's slot `i` is a *cell position*, and an epoch boundary re-draws every node's VRF
    /// coordinate, so the position keeps its name and changes its occupant. Nothing about the cell changes —
    /// the same seven nodes carry the same seven loads under the same shared demand — yet the window that
    /// straddles the turn is a splice of two column orderings.
    ///
    /// Deterministic, not Monte Carlo: `x_j(t) = μ_j · (10 + sin(2πt/17))` is rank-one, so every pair of
    /// columns is *exactly* correlated and the settled reading is `1.0` to the last bit. The permutation
    /// alone takes it to `≈ −0.13`. There is no noise term and no seed — the whole effect is the per-column
    /// level jump `10·μ_j → 10·μ_σ(j)`, and it needs the loads to DIFFER: on an exchangeable cell
    /// (`μ_j` all equal) a column permutation is provably harmless, which is why every uniform-load test in
    /// the suite passes over this.
    #[test]
    fn a_window_spanning_a_seat_permutation_reads_a_coherent_cell_as_anti_correlated() {
        const W: usize = 20;
        // Heterogeneous per-node load — the §6.7 load-balance prescription exists because these differ.
        let mu = [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0];
        // A period coprime with the window, so the splice is not an artefact of the signal repeating on it.
        let shared = |t: usize| (2.0 * core::f64::consts::PI * t as f64 / 17.0).sin();
        let row = |t: usize| -> Vec<f64> { mu.iter().map(|m| m * (10.0 + shared(t))).collect() };
        // The same instant, seen through the NEXT epoch's seating: a rotation of the seven seats.
        let permuted = |t: usize| -> Vec<f64> {
            let r = row(t);
            [3, 4, 5, 6, 0, 1, 2].iter().map(|&j| r[j]).collect()
        };

        let mut m = BehaviorMonitor::new(7, W);
        for t in 0..W {
            m.record(&row(t));
        }
        let settled = m.coherence().expect("a full window reads").mean_correlation();
        assert!(settled > 0.999, "a rank-one cell is perfectly coherent, not {settled}");

        // FALSIFICATION — the window rolling is not what breaks it. Another W samples of the SAME seating
        // evict every original row and the reading is untouched.
        let mut rolled = m.clone();
        for t in W..2 * W {
            rolled.record(&row(t));
        }
        let after_roll = rolled.coherence().expect("still full").mean_correlation();
        assert!(after_roll > 0.999, "rolling the window changes nothing: {after_roll}");

        // THE PROPERTY. One sample in the new seating is already enough to destroy the reading, and it stays
        // destroyed until the LAST pre-boundary row is evicted — `W − 1` diagnoses, against which the
        // homeostat's dwell of 3 is no defence. (At `k = W` the window is clean again, which is what makes
        // the cost of the fix exactly one window and not more; the range says so.)
        for k in 1..W {
            let mut spliced = m.clone();
            for t in W..W + k {
                spliced.record(&permuted(t));
            }
            let r = spliced.coherence().expect("still full").mean_correlation();
            assert!(
                r < 0.0,
                "a splice of {k} rows reads {r}, but the collective-subject band is (0.408, 0.577] — the \
                 cell has not changed and its own instrument now reports it as anti-correlated",
            );
        }

        // THE FIX. Dropping the window at the boundary costs one window of no reading and nothing else: the
        // refilled monitor recovers the true value exactly.
        let mut cleared = m.clone();
        cleared.clear();
        assert!(!cleared.ready(), "a cleared window has no reading — the honest state");
        assert!(cleared.coherence().is_none());
        for t in W..2 * W {
            cleared.record(&permuted(t));
        }
        let recovered = cleared.coherence().expect("refilled").mean_correlation();
        assert!(recovered > 0.999, "one consistent seating reads the truth again, not {recovered}");
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
        // After enough finite samples on both, a matrix is available and finite. The samples have to VARY
        // — a constant window is refused now (#229), and this loop used to record `[1.0, 2.0]` three times,
        // which is exactly that. The property under test is that nothing non-finite survives, so the fix is
        // to give it varying finite input rather than to weaken the refusal.
        for i in 0..3 {
            m.record(&[1.0 + f64::from(i), 2.0 - f64::from(i)]);
        }
        let g = m.coherence().expect("finite window");
        assert!(g.phi().is_finite() && g.purity().is_finite());
    }
}
