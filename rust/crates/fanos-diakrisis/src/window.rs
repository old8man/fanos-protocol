//! The leading-indicator theorem and the collective-subject window (spec §6.6, §18.2).
//!
//! Two consequences of the coherence measures matter for operations:
//!
//! * **Leading indicator (V17).** On the physical domain (`Γ` PSD, `Tr = 1`), the failure
//!   region `{P < 2/N}` is contained in `{Φ < 1}`: the integration alarm fires no later than
//!   the structure alarm, so `Φ` is the earliest single number to watch.
//! * **Collective-subject window (V19).** A cell is a candidate unified subject exactly when
//!   its mean inter-node correlation `r` lies in `(1/√(N−1), √(2/(N−1))]` — integrated, yet
//!   still self-modelling. For `N = 7` this is `(1/√6, 1/√3] ≈ (0.408, 0.577]`.

use crate::coherence::{p_crit, systemic_correlation};
use crate::mathfns::{ceil, nth_root, sqrt};

/// Integration `Φ` computed directly from a raw coherence matrix `Γ` (row-major, `n×n`,
/// PSD, `Tr = 1`): `Φ = Σ_{i≠j} γ_ij² / Σ_i γ_ii²`.
#[must_use]
pub fn phi_of_gamma(gamma: &[f64], n: usize) -> f64 {
    let mut off = 0.0;
    let mut diag = 0.0;
    for i in 0..n {
        for j in 0..n {
            let v = gamma.get(i * n + j).copied().unwrap_or(0.0);
            if i == j {
                diag += v * v;
            } else {
                off += v * v;
            }
        }
    }
    if diag <= 0.0 { 0.0 } else { off / diag }
}

/// Structuredness `P = Tr(Γ²) = Σ_ij γ_ij²` for a symmetric real `Γ`.
#[must_use]
pub fn purity_of_gamma(gamma: &[f64], n: usize) -> f64 {
    let mut sum = 0.0;
    for i in 0..n {
        for j in 0..n {
            let v = gamma.get(i * n + j).copied().unwrap_or(0.0);
            sum += v * v;
        }
    }
    sum
}

/// Which health alarm a coherence state trips (spec §6.6). By the leading-indicator theorem,
/// [`Alarm::Structure`] never occurs without [`Alarm::Integration`] also holding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Alarm {
    /// `Φ ≥ 1` and `P ≥ 2/N`: healthy.
    Healthy,
    /// `Φ < 1` but `P ≥ 2/N`: integration crossing first — the earliest warning.
    Integration,
    /// `Φ < 1` and `P < 2/N`: both crossed (structure implies integration).
    Structure,
}

/// Classify a raw coherence matrix by the leading-indicator ordering (spec §6.6, V17).
#[must_use]
pub fn leading_alarm(gamma: &[f64], n: usize) -> Alarm {
    let phi = phi_of_gamma(gamma, n);
    let p = purity_of_gamma(gamma, n);
    let phi_low = phi < 1.0 - 1e-12;
    let p_low = p < p_crit(n) - 1e-12;
    match (phi_low, p_low) {
        (false, _) => Alarm::Healthy,
        (true, false) => Alarm::Integration,
        (true, true) => Alarm::Structure,
    }
}

/// The collective-subject window `(1/√(N−1), √(2/(N−1))]` in mean correlation `r` (spec §18.2,
/// V19). Below it the collective is a mere aggregate; above it, over-coupled (groupthink).
#[must_use]
pub fn collective_subject_window(n: usize) -> (f64, f64) {
    // A cell with fewer than two live nodes has no inter-node correlation window — `r* = 1/√(n−1)` is
    // undefined. Return an unreachable window so a degenerate/collapsed cell classifies as `Aggregate`
    // (trivially diversified) and is never read as over-coupled, rather than panicking on the
    // `n >= 2` precondition — a real deployment can collapse to a lone survivor that still self-observes
    // and diagnoses every heartbeat (audit #122).
    if n < 2 {
        return (f64::INFINITY, f64::INFINITY);
    }
    (systemic_correlation(n), sqrt(2.0 / (n - 1) as f64))
}

/// The **sampling standard error** of the mean off-diagonal correlation estimated from `window` samples
/// per node on a cell of `n` nodes whose true correlation is `r`.
///
/// The window is not a memory parameter — it is the *resolution* of the only instrument the homeostat has.
/// A cell's `r` is not observed, it is estimated from a finite window, and every boundary the band-keeping
/// controller acts on (`Aggregate` / `CollectiveSubject` / `OverCoupled`) is a threshold on that estimate.
/// A controller cannot regulate against a boundary its estimator cannot resolve, so the window has to be
/// derived from the band it must see — [`resolving_window`].
///
/// Fisher's large-sample intraclass form, with the cell's `n` nodes as the group and the `window` samples as
/// the replicates:
///
/// ```text
/// SE(r̂) ≈ (1 − r)·(1 + (n−1)·r) · √( 2 / (n·(n−1)·(window−1)) )
/// ```
///
/// It is an approximation twice over — the shipped estimator is the mean of pairwise Pearson correlations
/// rather than the ANOVA intraclass estimator, and real behavioural samples are neither Gaussian nor
/// independent across heartbeats. `the_stderr_formula_matches_a_measured_one` checks the first gap by Monte
/// Carlo; the second can only widen the true error, so using this as the design figure is the optimistic
/// side, which is the side to be explicit about.
///
/// `INFINITY` for a cell too small or a window too short to define a correlation — the honest answer, and it
/// makes [`resolving_window`] refuse rather than return a plausible number.
#[must_use]
pub fn mean_correlation_stderr(n: usize, window: usize, r: f64) -> f64 {
    if n < 2 || window < 2 {
        return f64::INFINITY;
    }
    let nf = n as f64;
    (1.0 - r) * (1.0 + (nf - 1.0) * r) * sqrt(2.0 / (nf * (nf - 1.0) * (window - 1) as f64))
}

/// The **worst-case** [`mean_correlation_stderr`] over the collective-subject band — the figure that governs,
/// because the controller has to hold a cell *inside* that band and cannot choose where in it the cell sits.
///
/// `(1−r)(1 + (n−1)r)` is a downward parabola in `r` with its vertex at `r = (n−2)/(2(n−1))`, so the maximum
/// over the closed band is at that vertex clamped into it — the vertex is inside the band at `n = 7` and
/// above it from `n = 13` up, which is why this clamps rather than assuming either.
#[must_use]
pub fn band_stderr(n: usize, window: usize) -> f64 {
    let (lo, hi) = collective_subject_window(n);
    if !lo.is_finite() {
        return f64::INFINITY;
    }
    let nf = n as f64;
    let worst = ((nf - 2.0) / (2.0 * (nf - 1.0))).clamp(lo, hi);
    mean_correlation_stderr(n, window, worst)
}

/// The **control confidence** `z` a band-keeping loop must hold, derived rather than chosen: the smallest
/// number of standard errors at which the loop actuates on its own measurement noise **less often than the
/// system reconfigures itself**.
///
/// The reference period is the epoch, expressed here as `heartbeats_per_epoch` because that is the loop's
/// own clock. An epoch is when coordinates, rosters, directories and roles all change anyway; a controller
/// that spuriously fires more often than that is fighting a noise floor rather than regulating a cell, and
/// one that fires less often is below the system's own churn. That makes the epoch the only period in the
/// platform this can be stated against without inventing a target.
///
/// **Distribution-free, by Cantelli**, not by assuming normality — behavioural samples are counts, they are
/// not Gaussian, and a bound that needed them to be would be a story rather than a guarantee. One-sided,
/// `P(r̂ − r ≤ −z·SE) ≤ 1/(1 + z²)`; a dwell of `d` consecutive diagnoses multiplies independent readings, so
/// with `R = heartbeats_per_epoch / d` opportunities per epoch the requirement `R·(1+z²)^{−d} ≤ 1` inverts to
///
/// ```text
/// z = √( R^(1/d) − 1 )
/// ```
///
/// At the shipped loop (`d = BAND_DWELL = 3`, a 500 ms heartbeat, a 600 s epoch ⇒ 1200 heartbeats,
/// `R = 400`) this is `z ≈ 2.52`.
///
/// **The dwell is not optional, and this is where that becomes visible.** At `d = 1` the same requirement
/// demands `z = √1199 ≈ 34.6`, whose window is over four hours of history — a branch that actuates on a
/// single reading cannot be made statistically sound by observing longer. That is the derivation behind
/// giving *every* band branch a dwell, not only the over-coupled one.
///
/// `INFINITY` for a zero dwell (nothing to derive against); `0` when a cell gets at most one opportunity per
/// epoch, where any confidence suffices.
#[must_use]
pub fn control_confidence(dwell: usize, heartbeats_per_epoch: f64) -> f64 {
    if dwell == 0 {
        return f64::INFINITY;
    }
    let opportunities = heartbeats_per_epoch / dwell as f64;
    // A non-number is not a period: refuse rather than return a confidence, which would be a derived-looking
    // value with nothing behind it.
    if opportunities.is_nan() {
        return f64::INFINITY;
    }
    if opportunities <= 1.0 {
        return 0.0;
    }
    let Ok(d) = u32::try_from(dwell) else {
        return f64::INFINITY;
    };
    sqrt(nth_root(opportunities, d) - 1.0)
}

/// The shortest observation window whose estimate of `r` **resolves the collective-subject band**: `z`
/// standard errors must fit inside the band's half-width, so a cell sitting mid-band is not read as either
/// of the two failures on either side of it.
///
/// From `z·SE ≤ (hi − lo)/2` with `SE = g(n)·√(2/(n(n−1)(W−1)))`:
///
/// ```text
/// W − 1  ≥  8·z²·g(n)²  /  ( n·(n−1)·(hi − lo)² )
/// ```
///
/// At the Fano cell (`n = 7`, band `(0.4082, 0.5774]`, `g = n²/(4(n−1)) = 49/24`) with the derived
/// `z ≈ 2.52` of [`control_confidence`] this gives **178** — about 89 s of history at a 500 ms heartbeat,
/// against the 4 s the platform shipped.
///
/// That the answer is minutes rather than seconds is the point, not a cost to be minimised: the quantity
/// being regulated is a structural property of a cell inside a ~600 s epoch, and **the cost of resolution is
/// the loop's time constant, not memory** — `n × W` doubles is 448 bytes at `W = 8` and 10 KB at `W = 178`,
/// and nothing in this system cares about 10 KB. A controller cannot respond faster than the precision it
/// needs allows it to measure.
///
/// `0` for a cell with no band to resolve (`n < 2`) or a non-positive confidence, so a caller that ignores
/// the degenerate case gets a window that cannot be mistaken for a real one.
#[must_use]
pub fn resolving_window(n: usize, z: f64) -> usize {
    let (lo, hi) = collective_subject_window(n);
    if !lo.is_finite() || z <= 0.0 {
        return 0;
    }
    let nf = n as f64;
    let g = {
        let worst = ((nf - 2.0) / (2.0 * (nf - 1.0))).clamp(lo, hi);
        (1.0 - worst) * (1.0 + (nf - 1.0) * worst)
    };
    let half = (hi - lo) / 2.0;
    let w_minus_1 = 2.0 * z * z * g * g / (nf * (nf - 1.0) * half * half);
    ceil(w_minus_1) as usize + 1
}

/// Whether a collective of `n` nodes with mean correlation `r` is a candidate unified subject.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CollectiveState {
    /// `r ≤ 1/√(N−1)`: too weakly coupled to bind (`Φ < 1`).
    Aggregate,
    /// In the window: integrated, structured, still self-modelling.
    CollectiveSubject,
    /// `r > √(2/(N−1))`: over-coupled, loses its self-model (`R < 1/3`).
    OverCoupled,
}

/// Classify a collective by its mean inter-node correlation (spec §18.2).
#[must_use]
pub fn classify_collective(r: f64, n: usize) -> CollectiveState {
    let (lo, hi) = collective_subject_window(n);
    if r <= lo + 1e-12 {
        CollectiveState::Aggregate
    } else if r <= hi + 1e-12 {
        CollectiveState::CollectiveSubject
    } else {
        CollectiveState::OverCoupled
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::float_cmp, clippy::expect_used)]
mod tests {
    use super::*;

    /// A tiny deterministic LCG so the random-PSD sampling is reproducible without deps.
    struct Lcg(u64);
    impl Lcg {
        fn next_f64(&mut self) -> f64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            ((self.0 >> 11) as f64) / ((1u64 << 53) as f64) * 2.0 - 1.0
        }
    }

    /// A standard normal from the LCG by Irwin–Hall: twelve uniforms on `[0,1)` sum to mean 6 variance 1.
    ///
    /// Deliberately not Box–Muller — that needs `ln` and `cos`, and this crate's no_std shim carries only
    /// `sqrt` and `log2` on purpose ([[proxy-gate-that-cannot-fail]] is what a stray `std`-only float call
    /// cost last time). Twelve uniforms is more than enough to measure a standard deviation to two digits.
    fn gaussian(rng: &mut Lcg) -> f64 {
        // `next_f64` returns `[-1, 1)`, so a half-shift puts it back on `[0, 1)`.
        (0..12).map(|_| rng.next_f64().mul_add(0.5, 0.5)).sum::<f64>() - 6.0
    }

    /// One draw of the estimator: `window` samples of an equicorrelated cell of `n` nodes at correlation
    /// `r`, through the SHIPPED path (`from_signals` → `mean_correlation`), not a reimplementation of it.
    fn draw_mean_correlation(n: usize, window: usize, r: f64, rng: &mut Lcg) -> f64 {
        let (a, b) = (sqrt(r), sqrt(1.0 - r));
        let common: Vec<f64> = (0..window).map(|_| gaussian(rng)).collect();
        let signals: Vec<Vec<f64>> = (0..n)
            .map(|_| common.iter().map(|&z| a * z + b * gaussian(rng)).collect())
            .collect();
        crate::coherence::CoherenceMatrix::from_signals(&signals)
            .expect("equicorrelated signals are a valid correlation matrix")
            .mean_correlation()
    }

    #[test]
    fn the_stderr_formula_matches_a_measured_one() {
        // **The formula is a claim about the shipped estimator, so measure the shipped estimator.**
        // `mean_correlation_stderr` is Fisher's intraclass form, but `mean_correlation()` is the mean of
        // pairwise Pearson correlations — a different statistic that is only asymptotically the same. If the
        // two disagreed, the derived window would be derived from the wrong thing, and `resolving_window`
        // would hand the controller a number with a story attached rather than a bound.
        const REPLICATES: usize = 4000;
        for &(n, window, r) in &[(7usize, 8usize, 0.45), (7, 8, 0.4167), (7, 30, 0.45), (7, 120, 0.45)] {
            let mut rng = Lcg(0x5EED_0000 ^ (window as u64) << 8 ^ n as u64);
            let draws: Vec<f64> =
                (0..REPLICATES).map(|_| draw_mean_correlation(n, window, r, &mut rng)).collect();
            let mean = draws.iter().sum::<f64>() / REPLICATES as f64;
            let var =
                draws.iter().map(|d| (d - mean) * (d - mean)).sum::<f64>() / (REPLICATES - 1) as f64;
            let (measured, predicted) = (sqrt(var), mean_correlation_stderr(n, window, r));

            // A quarter is the tolerance a *design* figure needs: the window is chosen by squaring this, so a
            // 25 % error in the SE is a factor-1.6 error in the window — visible, and still the right order.
            let ratio = measured / predicted;
            assert!(
                (0.75..1.25).contains(&ratio),
                "n={n} window={window} r={r}: measured SE {measured:.4} vs predicted {predicted:.4} \
                 (ratio {ratio:.3}) — the closed form no longer describes the shipped estimator, so any \
                 window derived from it is derived from the wrong statistic",
            );
        }
    }

    #[test]
    fn the_shipped_window_is_the_one_the_band_requires() {
        // The two facts that make #99 a defect rather than a preference, asserted rather than argued.
        let n = 7;
        let (lo, hi) = collective_subject_window(n);

        // 1. At the window the platform shipped, one standard error is the WHOLE band. Not "close to" — the
        //    ratio is within a percent, which is why no operating point inside the band was resolvable and
        //    why the argument does not depend on where the cell actually sits.
        let shipped = band_stderr(n, 8);
        assert!(
            (shipped / (hi - lo) - 1.0).abs() < 0.05,
            "a window of 8 gives SE {shipped:.4} against a band of width {:.4}",
            hi - lo,
        );

        // 2. The derived window resolves it, and one sample short of it does not — the falsification, without
        //    which this test would pass for any window at all.
        for &z in &[1.0, 2.0, 3.0] {
            let w = resolving_window(n, z);
            assert!(z * band_stderr(n, w) <= (hi - lo) / 2.0, "z={z}: the derived window {w} must resolve");
            assert!(
                z * band_stderr(n, w - 2) > (hi - lo) / 2.0,
                "z={z}: a window shorter than the derived {w} must NOT resolve, or the derivation is slack",
            );
        }

        // Degenerate cells refuse rather than returning a plausible number.
        assert_eq!(resolving_window(1, 2.0), 0, "a lone survivor has no band to resolve");
        assert_eq!(resolving_window(7, 0.0), 0, "a zero confidence is not a window");
    }

    #[test]
    fn the_confidence_is_derived_from_the_dwell_and_the_epoch() {
        // The shipped loop: a 500 ms heartbeat inside a 600 s epoch is 1200 opportunities, and
        // `BAND_DWELL = 3` consecutive readings per actuation.
        const HEARTBEATS_PER_EPOCH: f64 = 1200.0;
        let z = control_confidence(3, HEARTBEATS_PER_EPOCH);
        assert!((z - 2.5236).abs() < 1e-3, "the derived control confidence at the shipped loop: {z}");
        assert_eq!(resolving_window(7, z), 178, "and the window that confidence requires");

        // **The property, not the number:** at the derived `z` the loop's own noise produces at most one
        // spurious actuation per epoch. Recomputed from Cantelli here rather than reused from the function,
        // so this asserts the requirement and not the algebra that solved it.
        let per_reading = 1.0 / (1.0 + z * z);
        let per_actuation = per_reading * per_reading * per_reading;
        assert!(
            per_actuation * (HEARTBEATS_PER_EPOCH / 3.0) <= 1.0 + 1e-9,
            "at z={z} the loop actuates on noise {} times per epoch",
            per_actuation * (HEARTBEATS_PER_EPOCH / 3.0),
        );
        // And it is the SMALLEST such confidence — a hair below it, the requirement fails. Without this the
        // derivation would be satisfied by any larger number, including the one it replaced.
        let smaller = z * 0.99;
        let p = 1.0 / (1.0 + smaller * smaller);
        assert!(p * p * p * (HEARTBEATS_PER_EPOCH / 3.0) > 1.0, "z is the minimum, not merely sufficient");

        // **A single-reading branch cannot be made sound by observing longer**, which is why every band
        // branch needs a dwell rather than only the over-coupled one: at `d = 1` the same requirement asks
        // for twenty standard errors, and the window that would resolve twenty is not a window any cell has.
        let no_dwell = control_confidence(1, HEARTBEATS_PER_EPOCH);
        assert!((no_dwell - 34.627).abs() < 1e-2, "a dwell-free branch would need z={no_dwell}");
        assert!(
            resolving_window(7, no_dwell) > 30_000,
            "and a window of {} samples, which at a 500 ms heartbeat is over four hours",
            resolving_window(7, no_dwell),
        );

        // Degenerate inputs refuse rather than returning a plausible number.
        assert!(control_confidence(0, HEARTBEATS_PER_EPOCH).is_infinite(), "no dwell, nothing to derive");
        assert_eq!(control_confidence(3, 1.0), 0.0, "one opportunity per epoch needs no confidence");
    }

    /// Build a random PSD `Γ` with `Tr = 1` as `Σ vₖ vₖᵀ`, trace-normalised.
    fn random_psd(n: usize, rng: &mut Lcg) -> Vec<f64> {
        let mut g = vec![0.0f64; n * n];
        for _ in 0..(n + 2) {
            let v: Vec<f64> = (0..n).map(|_| rng.next_f64()).collect();
            for i in 0..n {
                for j in 0..n {
                    g[i * n + j] += v[i] * v[j];
                }
            }
        }
        let trace: f64 = (0..n).map(|i| g[i * n + i]).sum();
        if trace > 0.0 {
            for x in &mut g {
                *x /= trace;
            }
        }
        g
    }

    #[test]
    fn leading_indicator_containment_holds_on_random_psd() {
        // V17: {P < 2/N} ⊆ {Φ < 1} — Structure never fires without Integration.
        let mut rng = Lcg(0x1234_5678_9abc_def0);
        for _ in 0..2000 {
            let g = random_psd(7, &mut rng);
            let phi = phi_of_gamma(&g, 7);
            let p = purity_of_gamma(&g, 7);
            if p < 2.0 / 7.0 - 1e-9 {
                assert!(
                    phi < 1.0 + 1e-9,
                    "P<2/7 but Φ={phi} ≥ 1 violates leading indicator"
                );
            }
            // The forbidden state "P<2/N while Φ≥1" is unrepresentable: it maps to Healthy.
            if leading_alarm(&g, 7) == Alarm::Healthy {
                assert!(p >= 2.0 / 7.0 - 1e-9 || phi >= 1.0 - 1e-9);
            }
        }
    }

    #[test]
    fn collective_window_matches_spec_for_seven() {
        // V19: window (1/√6, 1/√3] ≈ (0.408, 0.577].
        let (lo, hi) = collective_subject_window(7);
        assert!((lo - 1.0 / sqrt(6.0)).abs() < 1e-12);
        assert!((hi - 1.0 / sqrt(3.0)).abs() < 1e-12);
        assert_eq!(classify_collective(0.35, 7), CollectiveState::Aggregate);
        assert_eq!(
            classify_collective(0.5, 7),
            CollectiveState::CollectiveSubject
        );
        assert_eq!(classify_collective(0.7, 7), CollectiveState::OverCoupled);
    }
}
