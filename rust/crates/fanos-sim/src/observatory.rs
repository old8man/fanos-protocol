//! The coherence observatory: reconstruct `Γ_net` from behavioural signals and *forecast*.
//!
//! DIAKRISIS's global monitors read a cell's **behavioural correlation**, not its liveness (spec
//! §2.7, §6.5). This module is the simulator's window onto that plane: it turns per-node signal
//! windows into the coherence measures `Φ / P / R`, the leading-indicator [`Alarm`], and the
//! collective-subject [`CollectiveState`], and drives the corpus's headline operational claim —
//!
//! > the cascade-failure regime `r > r* = 1/√(N−1)` is detectable **a full regime ahead of any
//! > liveness alarm** (spec §2.7, V15): correlation rises *before* nodes actually fail.
//!
//! [`HealthField`] is a deterministic generator of that behaviour — a shared common mode (whose
//! weight is the cascade `progress`) plus idiosyncratic noise, so inter-node correlation climbs as
//! a cascade builds. [`forecast_cascade`] sweeps `progress` and measures the **lead time** between
//! the coherence warning and the first node failure: the forecast the user asked for.
//!
//! Note (leading indicator, V17): because `from_signals` yields a *correlation* matrix (unit
//! diagonal), `Γ = C/N` has a uniform diagonal, the equality case of V17 — so `Φ < 1` and
//! `P < 2/N` cross *together* here. The strict lead time lives in the *cascade* axis (`r` vs
//! liveness), which is what this observatory forecasts.

use std::collections::VecDeque;

use fanos_diakrisis::coherence::CoherenceMatrix;
use fanos_diakrisis::window::{Alarm, CollectiveState};

use crate::rng::Rng;

/// One reading of a cell's coherence health at a single sampling instant.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CoherenceReading {
    /// Integration `Φ = Σ_{i≠j}|γ_ij|² / Σ_i γ_ii²` (threshold `1`).
    pub phi: f64,
    /// Structuredness `P = Tr(Γ²)` (threshold `2/N`).
    pub purity: f64,
    /// Reflection `R = 1/(N·P)` (threshold `1/3`).
    pub reflection: f64,
    /// Mean off-diagonal correlation `r`.
    pub mean_correlation: f64,
    /// The leading-indicator alarm (spec §6.6, V17).
    pub alarm: Alarm,
    /// The collective-subject classification (spec §18.2, V19).
    pub collective: CollectiveState,
    /// Whether the cascade early-warning has fired (`r > r*`, spec §2.7).
    pub systemic: bool,
}

/// Read the coherence measures from `n` equal-length per-node behavioural signals. Returns `None`
/// if the signals are empty or ragged.
#[must_use]
pub fn read(signals: &[Vec<f64>]) -> Option<CoherenceReading> {
    let g = CoherenceMatrix::from_signals(signals)?;
    let m = g.measures(); // Φ, P, R from a single Frobenius pass rather than three
    Some(CoherenceReading {
        phi: m.phi,
        purity: m.purity,
        reflection: m.reflection,
        mean_correlation: g.mean_correlation(),
        alarm: g.alarm(),
        collective: g.collective_state(),
        systemic: g.is_systemic(),
    })
}

/// A deterministic generator of per-node behavioural signals under a shared stressor, for
/// coherence forecasting. Each node carries a common-mode loading `aᵢ`: at cascade `progress`,
/// its signal is `(1 − c)·idiosyncratic + c·shared` with `c = progress·aᵢ`, so the inter-node
/// correlation climbs from `≈0` (diversified) toward `1` (fully coupled) as the cascade builds.
#[derive(Clone, Debug)]
pub struct HealthField {
    loadings: Vec<f64>,
}

impl HealthField {
    /// A field of `n` nodes with identical common-mode loading.
    #[must_use]
    pub fn uniform(n: usize, loading: f64) -> Self {
        Self {
            loadings: vec![loading.clamp(0.0, 1.0); n],
        }
    }

    /// A field with an explicit per-node loading vector (heterogeneous coupling / fragility).
    #[must_use]
    pub fn heterogeneous(loadings: Vec<f64>) -> Self {
        Self {
            loadings: loadings.into_iter().map(|a| a.clamp(0.0, 1.0)).collect(),
        }
    }

    /// The number of nodes.
    #[must_use]
    pub fn n(&self) -> usize {
        self.loadings.len()
    }

    /// Generate a `window`-length behavioural signal for every node at cascade `progress`
    /// (clamped to `[0, 1]`). The shared common mode is one sequence drawn per call; each node
    /// mixes it in with weight `progress·loadingᵢ`.
    #[must_use]
    pub fn signals(&self, progress: f64, window: usize, rng: &mut Rng) -> Vec<Vec<f64>> {
        let p = progress.clamp(0.0, 1.0);
        let shared: Vec<f64> = (0..window).map(|_| rng.unit() - 0.5).collect();
        self.loadings
            .iter()
            .map(|&a| {
                let c = (p * a).clamp(0.0, 1.0);
                shared
                    .iter()
                    .map(|&s| {
                        let idiosyncratic = rng.unit() - 0.5;
                        (1.0 - c) * idiosyncratic + c * s
                    })
                    .collect()
            })
            .collect()
    }

    /// The mean health level of node `i` at `progress`: `1 − progress·loadingᵢ`. A node is
    /// considered failed once this falls below the viability threshold.
    #[must_use]
    pub fn health_level(&self, progress: f64, i: usize) -> f64 {
        1.0 - progress * self.loadings.get(i).copied().unwrap_or(0.0)
    }

    /// How many nodes are still viable (`health ≥ thresh`) at `progress`.
    #[must_use]
    pub fn live_count(&self, progress: f64, thresh: f64) -> usize {
        (0..self.n())
            .filter(|&i| self.health_level(progress, i) >= thresh)
            .count()
    }
}

/// The result of a cascade forecast sweep: the trajectory of readings and the two critical
/// milestones — when the coherence warning fired, and when nodes actually began to fail.
#[derive(Clone, Debug, Default)]
pub struct CascadeForecast {
    /// The cascade progress at which the systemic (`r > r*`) early-warning first fired.
    pub warn_progress: Option<f64>,
    /// The cascade progress at which the first node fell below the viability threshold.
    pub fail_progress: Option<f64>,
    /// The full sampled trajectory: `(progress, reading, live_count)`.
    pub trajectory: Vec<(f64, CoherenceReading, usize)>,
}

impl CascadeForecast {
    /// The forecast **lead time** (in cascade progress) between the coherence warning and the
    /// first failure. `Some(Δ > 0)` means the warning genuinely preceded collapse.
    #[must_use]
    pub fn lead(&self) -> Option<f64> {
        match (self.warn_progress, self.fail_progress) {
            (Some(w), Some(f)) => Some(f - w),
            _ => None,
        }
    }
}

/// Sweep a [`HealthField`] from `progress = 0` to `1` in `steps` steps, sampling a `window`-length
/// signal at each and reading its coherence. Records when the systemic early-warning first fired
/// and when the first node failed (`health < fail_thresh`) — the forecast lead time.
#[must_use]
pub fn forecast_cascade(
    field: &HealthField,
    steps: usize,
    window: usize,
    fail_thresh: f64,
    seed: u64,
) -> CascadeForecast {
    let mut rng = Rng::new(seed);
    let mut out = CascadeForecast::default();
    let steps = steps.max(1);
    for s in 0..=steps {
        let progress = s as f64 / steps as f64;
        let signals = field.signals(progress, window, &mut rng);
        let Some(reading) = read(&signals) else {
            continue;
        };
        let live = field.live_count(progress, fail_thresh);
        if reading.systemic && out.warn_progress.is_none() {
            out.warn_progress = Some(progress);
        }
        if live < field.n() && out.fail_progress.is_none() {
            out.fail_progress = Some(progress);
        }
        out.trajectory.push((progress, reading, live));
    }
    out
}

/// Population variance of a scalar window, `Var = (1/n) Σ (xᵢ − x̄)²`. Returns `0` for an empty
/// or constant series. The *second*, dynamical leading indicator (with [`lag1_autocorrelation`]):
/// near the coherence saddle-node the fluctuation variance rises (Scheffer et al., Nature 2009).
#[must_use]
pub fn windowed_variance(series: &[f64]) -> f64 {
    let n = series.len();
    if n == 0 {
        return 0.0;
    }
    let mean = series.iter().sum::<f64>() / n as f64;
    series.iter().map(|&x| (x - mean) * (x - mean)).sum::<f64>() / n as f64
}

/// Lag-1 autocorrelation `ρ₁ = Σ_i (xᵢ − x̄)(x_{i+1} − x̄) / Σ_i (xᵢ − x̄)²` — the standard AR(1)
/// early-warning estimator (Scheffer et al., Nature 2009). Ranges in `[−1, 1]`; returns `0` for a
/// series of fewer than two samples or one with zero variance. As a dynamical system approaches a
/// saddle-node its recovery eigenvalue → 0, so (Ornstein–Uhlenbeck theory) `ρ₁ → 1`: a value near
/// `1` is the critical-slowing-down signature that fires while the mean is still in-band.
#[must_use]
pub fn lag1_autocorrelation(series: &[f64]) -> f64 {
    let n = series.len();
    if n < 2 {
        return 0.0;
    }
    let mean = series.iter().sum::<f64>() / n as f64;
    let denom = series.iter().map(|&x| (x - mean) * (x - mean)).sum::<f64>();
    if denom <= 0.0 {
        return 0.0;
    }
    let numer = series
        .iter()
        .zip(series.iter().skip(1))
        .map(|(&a, &b)| (a - mean) * (b - mean))
        .sum::<f64>();
    numer / denom
}

/// A streaming **critical-slowing-down** detector over a scalar coherence series (`P` or `r`) — a
/// *second*, dynamical leading indicator complementing the threshold indicator `{P<2/N}⊂{Φ<1}`
/// (`docs/frontier-synthesis.md §4.3`). FANOS's loss of viability is a proven saddle-node
/// bifurcation (`fanos_diakrisis::dynamics`), so as a sustained attack approaches the empirical
/// threshold the recovery eigenvalue → 0 and — by Ornstein–Uhlenbeck theory — the state's lag-1
/// autocorrelation → 1 and its variance rises *before* the mean leaves the band.
///
/// It maintains a sliding window of the most recent samples and raises [`alarm`](Self::alarm) once
/// BOTH the windowed variance and the lag-1 autocorrelation exceed caller-supplied thresholds
/// (calibrated to a healthy baseline). It is **pure observation** — it holds no control authority
/// and cannot move the attractor, so it can never harm the proven envelope.
#[derive(Clone, Debug)]
pub struct CriticalSlowingDown {
    window: usize,
    var_threshold: f64,
    ar1_threshold: f64,
    samples: VecDeque<f64>,
}

impl CriticalSlowingDown {
    /// A detector over a sliding `window` of samples that fires when the windowed variance exceeds
    /// `var_threshold` AND the lag-1 autocorrelation exceeds `ar1_threshold`. `window` is clamped
    /// to `≥ 2` (the minimum for a lag-1 estimate).
    #[must_use]
    pub fn new(window: usize, var_threshold: f64, ar1_threshold: f64) -> Self {
        let window = window.max(2);
        Self {
            window,
            var_threshold,
            ar1_threshold,
            samples: VecDeque::with_capacity(window),
        }
    }

    /// Ingest one sample of the scalar series, evicting the oldest once the window is full.
    pub fn observe(&mut self, x: f64) {
        if self.samples.len() == self.window {
            self.samples.pop_front();
        }
        self.samples.push_back(x);
    }

    /// Whether the sliding window is full — statistics below are only meaningful once it is.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.samples.len() == self.window
    }

    /// The current windowed variance (see [`windowed_variance`]).
    #[must_use]
    pub fn variance(&self) -> f64 {
        windowed_variance(&self.window())
    }

    /// The current windowed lag-1 autocorrelation (see [`lag1_autocorrelation`]).
    #[must_use]
    pub fn lag1_autocorrelation(&self) -> f64 {
        lag1_autocorrelation(&self.window())
    }

    /// Whether the critical-slowing-down alarm is firing: the window is full AND both statistics
    /// are above their thresholds — the dynamical early-warning that a saddle-node is near.
    #[must_use]
    pub fn alarm(&self) -> bool {
        if !self.ready() {
            return false;
        }
        let w = self.window();
        windowed_variance(&w) > self.var_threshold && lag1_autocorrelation(&w) > self.ar1_threshold
    }

    /// The window contents in temporal order (oldest first) — `VecDeque` preserves insertion order,
    /// so this is the correctly-ordered series the two estimators consume.
    fn window(&self) -> Vec<f64> {
        self.samples.iter().copied().collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_diversified_field_never_enters_the_cascade_regime() {
        // Low common-mode loading: even fully "stressed", correlation stays below r*, so a local
        // failure cannot cascade (spec §2.7 resilient regime).
        let field = HealthField::uniform(7, 0.30);
        let forecast = forecast_cascade(&field, 40, 256, 0.30, 0xC0);
        assert!(forecast.warn_progress.is_none(), "must stay resilient");
        // Every reading is diversified: Φ < 1 and not systemic.
        assert!(
            forecast
                .trajectory
                .iter()
                .all(|(_, r, _)| r.phi < 1.0 && !r.systemic)
        );
    }

    #[test]
    fn a_coupled_field_enters_the_cascade_regime() {
        // Strong common mode drives correlation past r* → the systemic early-warning fires and Φ
        // climbs above 1 (over-integrated, the cascade regime).
        let field = HealthField::uniform(7, 1.0);
        let forecast = forecast_cascade(&field, 40, 256, 0.30, 0xC1);
        assert!(forecast.warn_progress.is_some(), "must detect the cascade");
        assert!(
            forecast.trajectory.last().unwrap().1.phi > 1.0,
            "fully coupled cell is over-integrated"
        );
    }

    #[test]
    fn the_cascade_is_forecast_before_any_node_fails() {
        // THE forecast: the coherence warning (r > r*) precedes the first liveness failure by a
        // positive lead time (spec §2.7, V15 — "detectable before any node has failed").
        let field = HealthField::uniform(7, 1.0);
        let forecast = forecast_cascade(&field, 50, 256, 0.30, 0xF00D);
        let warn = forecast.warn_progress.expect("warning fired");
        let fail = forecast.fail_progress.expect("nodes eventually fail");
        assert!(
            warn < fail,
            "warning at {warn} must precede first failure at {fail}"
        );
        assert!(
            forecast.lead().unwrap() > 0.1,
            "lead time should be sizeable"
        );
    }

    #[test]
    fn the_reading_tracks_the_collective_subject_window() {
        // As coupling rises the cell walks Aggregate → CollectiveSubject → OverCoupled (V19).
        let field = HealthField::uniform(7, 1.0);
        let forecast = forecast_cascade(&field, 60, 256, 0.30, 0x5EED);
        let states: Vec<CollectiveState> = forecast
            .trajectory
            .iter()
            .map(|(_, r, _)| r.collective)
            .collect();
        assert!(
            states.contains(&CollectiveState::Aggregate),
            "starts diffuse"
        );
        assert!(
            states.contains(&CollectiveState::OverCoupled),
            "ends over-coupled"
        );
    }
}
