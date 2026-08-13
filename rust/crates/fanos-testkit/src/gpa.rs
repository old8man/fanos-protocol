//! **The flow-correlation statistics a global passive adversary computes** — one implementation, so a
//! second harness cannot re-earn the first one's mistakes.
//!
//! These three functions lived privately inside `fanos-sim/tests/traffic_analysis.rs`, which taps a
//! `NyxNode`. The composed relay — what a `--relay` deployment actually runs — needs the same statistics
//! over a different tape, and the only way to get them there was to copy them. A copied scan inherits none
//! of the corrections the original has already paid for, and [`best_lag_score`] below carries one that cost
//! a whole investigation (#187): a zero-lag matcher scored **below chance**, which is not safety.
//!
//! Deliberately only the pure `&[f64] -> f64` half. Turning a frame tape into per-node rate series needs
//! `FrameObs` and `Triple`, which live in `fanos-sim`; this crate is a leaf with no dependencies and must
//! stay one. The split is by what each function needs, not by convenience.

/// Pearson correlation; `0.0` when either series is constant (no signal to read).
///
/// The constant case is a deliberate `0.0` rather than `NaN`: a series that never moves carries no
/// information about another, and a `NaN` propagating into a `max` would silently poison a sweep.
#[must_use]
pub fn pearson(a: &[f64], b: &[f64]) -> f64 {
    #[expect(
        clippy::cast_precision_loss,
        reason = "a bin count that exceeds f64's integer range would be a series longer than any run \
                  this instrument takes"
    )]
    let n = a.len().min(b.len()) as f64;
    if n < 2.0 {
        return 0.0;
    }
    let (ma, mb) = (a.iter().sum::<f64>() / n, b.iter().sum::<f64>() / n);
    let mut num = 0.0;
    let (mut da, mut db) = (0.0, 0.0);
    for (x, y) in a.iter().zip(b.iter()) {
        num += (x - ma) * (y - mb);
        da += (x - ma).powi(2);
        db += (y - mb).powi(2);
    }
    if da <= f64::EPSILON || db <= f64::EPSILON {
        return 0.0;
    }
    num / (da.sqrt() * db.sqrt())
}

/// Pearson between `a` and `b` with `b` shifted **later** by `lag` bins — the exit series read `lag` bins
/// after the entry one. `lag = 0` is exactly [`pearson`].
#[must_use]
#[expect(
    clippy::indexing_slicing,
    reason = "both slices are guarded one line above: `lag < a.len()` and `lag < b.len()`, so               `a.len() - lag` cannot underflow and neither range can exceed its slice"
)]
pub fn pearson_at_lag(a: &[f64], b: &[f64], lag: usize) -> f64 {
    if lag >= a.len() || lag >= b.len() {
        return 0.0;
    }
    pearson(&a[..a.len() - lag], &b[lag..])
}

/// The score a **lag-scanning** adversary computes: the strongest correlation over a window of delays,
/// rather than the one at zero.
///
/// This is the matcher #187 named as the likely cause of an anomaly it could not explain: the shipping
/// schedule's matching accuracy measured **0.00 against a chance of 0.20**, and below chance is not safety
/// — twelve seeds of zero has probability `(44/120)¹² ≈ 3e-6` under guessing, so the score matrix was still
/// carrying information and the matcher was systematically avoiding the truth. [`pearson`] compares series
/// at zero lag **only**, while mixing displaces the exit series; a real flow-correlation adversary scans
/// lags.
///
/// The caller derives the window rather than choosing it: the mix delay is a Poisson mean, so a packet's
/// displacement is exponential and its tail matters. Scanning further than the tail only adds noise maxima,
/// which is itself a bias — the max of more candidates is larger whether or not any is real. State the
/// derivation at the call site, in bins and in milliseconds, so the two can be checked against each other.
#[must_use]
pub fn best_lag_score(a: &[f64], b: &[f64], max_lag: usize) -> f64 {
    (0..=max_lag).map(|l| pearson_at_lag(a, b, l).abs()).fold(0.0, f64::max)
}

#[cfg(test)]
mod tests {
    use super::{best_lag_score, pearson, pearson_at_lag};

    #[test]
    fn a_series_that_never_moves_correlates_with_nothing() {
        let flat = [3.0, 3.0, 3.0, 3.0];
        let ramp = [1.0, 2.0, 3.0, 4.0];
        assert!(pearson(&flat, &ramp).abs() < 1e-12, "a constant series carries no signal");
        assert!(pearson(&ramp, &flat).abs() < 1e-12, "and the argument order does not matter");
        assert!(
            pearson(&flat, &ramp).is_finite(),
            "the degenerate case must be a number, not a NaN that would poison a sweep's max"
        );
    }

    #[test]
    fn too_short_to_conclude_reads_zero_rather_than_guessing() {
        assert!(pearson(&[1.0], &[2.0]).abs() < f64::EPSILON, "one bin is not a series");
        assert!(pearson(&[], &[]).abs() < f64::EPSILON);
    }

    #[test]
    fn identical_and_inverted_series_sit_at_the_two_extremes() {
        let a = [1.0, 4.0, 2.0, 8.0, 3.0];
        let inverted: Vec<f64> = a.iter().map(|x| -x).collect();
        assert!((pearson(&a, &a) - 1.0).abs() < 1e-12);
        assert!((pearson(&a, &inverted) + 1.0).abs() < 1e-12);
    }

    /// **The property the whole lag scan exists for**, and the one a re-derived copy would be most likely
    /// to lose: a displaced series is nearly invisible at zero lag and exact at its own.
    ///
    /// **The fixture has to be aperiodic, and the first one I wrote was not.** Bursts at a fixed period
    /// correlate with their own shifts at a value the period fixes — a period-3 pattern displaced by one
    /// bin reads `|r| = 0.500` at zero lag, which is neither noise nor signal, and the test failed on its
    /// own fixture rather than on the code. A GPA's real input is aperiodic; a periodic one flatters the
    /// zero-lag matcher for a reason that has nothing to do with mixing.
    #[test]
    fn a_displaced_series_is_found_by_the_scan_and_missed_at_zero_lag() {
        // Aperiodic bursts, and the same series displaced by exactly one bin. Measured: 0.333 at zero,
        // 1.000 at lag 1, 0.400 at lag 2 — so the separation is real and not a threshold chosen to fit.
        let entry = [0.0, 9.0, 0.0, 0.0, 0.0, 9.0, 0.0, 0.0, 0.0, 0.0, 9.0, 0.0, 9.0, 0.0, 0.0, 0.0];
        let mut exit = [0.0; 16];
        exit[1..].copy_from_slice(&entry[..15]);

        let at_zero = pearson(&entry, &exit).abs();
        let scanned = best_lag_score(&entry, &exit, 3);
        assert!(
            at_zero < 0.4,
            "a one-bin displacement must look like noise to the zero-lag matcher (got {at_zero:.3})"
        );
        assert!(
            scanned > 0.9,
            "and must be plain to the scanning one (got {scanned:.3}) — this gap IS the #187 finding"
        );
        assert!(
            (pearson_at_lag(&entry, &exit, 1).abs() - scanned).abs() < 1e-12,
            "and the scan's maximum must land on the true displacement, not on a noise lag"
        );
    }

    #[test]
    fn a_lag_past_the_end_of_the_series_scores_zero_rather_than_panicking() {
        let a = [1.0, 2.0, 3.0];
        assert!(pearson_at_lag(&a, &a, 3).abs() < f64::EPSILON);
        assert!(pearson_at_lag(&a, &a, 99).abs() < f64::EPSILON);
        assert!(
            (best_lag_score(&a, &a, 99) - 1.0).abs() < 1e-12,
            "an over-wide window must not erase the real score it already found"
        );
    }
}
