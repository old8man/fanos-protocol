//! **Stochastic cascade prediction** — the early-warning detector characterized over an *ensemble*.
//!
//! `early_warning.rs` proves the critical-slowing-down (CSD) detector fires with a positive lead time
//! on *one* fixed cell parameterization. But a predictor is only trustworthy if it works across the
//! *distribution* of cells it will actually meet — different couplings, ideal purities, and noise. This
//! file models that distribution: it samples random cell parameterizations, drives each toward its own
//! saddle-node (a genuine, per-cell cascade), and measures the two numbers that define a predictor:
//!
//!   * **sensitivity** — of the random cascades that actually collapse, the fraction the detector warns
//!     about *before* the viability crossing `P = 2/7` (a positive lead time);
//!   * **specificity** — of random cells held comfortably sub-critical, the fraction that *falsely*
//!     alarm.
//!
//! A detector with high sensitivity but low specificity cries wolf; the two together are the honest
//! characterization the frontier synthesis (`docs/frontier-synthesis.md §4.3`) claims. Every scenario
//! is seed-derived, so the ensemble rates are fixed pass/fail numbers, not samples — the suite is a
//! deterministic regression gate on the predictor's operating point.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_diakrisis::dynamics::PurityDynamics;
use fanos_sim::{CriticalSlowingDown, Rng, lag1_autocorrelation, windowed_variance};

const N: usize = 7;
/// Integration step (kept fixed for numerical stability, as in `early_warning.rs`/`dynamics.rs`).
const DT: f64 = 0.05;
/// Steps to settle a fixed point; detector window; attack levels in the ramp; noise amplitude.
const WARMUP: usize = 3000;
const WINDOW: usize = 800;
const LEVELS: usize = 40;
const NOISE: f64 = 0.02;
/// Ensemble size. Every seed is a distinct random cell; the pass/fail rates below are over this set.
const ENSEMBLE: u64 = 64;

/// A random cell parameterization drawn from the physically sensible regime around the known-good
/// `early_warning.rs` point (`λ≈0.1, κ≈0.5, P_ideal≈0.9`) — wide enough to be a real distribution,
/// narrow enough that every draw has a well-defined saddle-node.
struct Params {
    lambda: f64,
    kappa: f64,
    p_ideal: f64,
}

fn sample_params(rng: &mut Rng) -> Params {
    Params {
        lambda: 0.08 + 0.07 * rng.unit(),  // [0.08, 0.15]
        kappa: 0.40 + 0.20 * rng.unit(),   // [0.40, 0.60]
        p_ideal: 0.85 + 0.10 * rng.unit(), // [0.85, 0.95]
    }
}

fn cell_at(p: &Params, purity: f64) -> PurityDynamics {
    PurityDynamics::new(p.lambda, p.kappa, p.p_ideal, DT, N, purity)
}

/// Settle deterministically (no noise) from the healthy start to the sustained-`attack` fixed point.
fn settle(p: &Params, attack: f64) -> PurityDynamics {
    let mut d = cell_at(p, p.p_ideal);
    for _ in 0..WARMUP {
        d.step(attack);
    }
    d
}

/// One noisy step: advance the deterministic dynamics under `attack`, then inject additive purity
/// `noise` (the Ornstein–Uhlenbeck form CSD theory assumes) by reconstructing at the perturbed purity.
fn advance(p: &Params, cell: PurityDynamics, attack: f64, noise: f64) -> PurityDynamics {
    let mut d = cell;
    cell_at(p, d.step(attack) + noise)
}

/// The survival threshold `a*` — the largest sustained attack whose settled fixed point stays viable
/// (binary search, the `dynamics.rs` idiom).
fn a_star(p: &Params) -> f64 {
    let hi0 = cell_at(p, p.p_ideal).survival_bound_gate_open() * 5.0;
    let (mut lo, mut hi) = (0.0, hi0);
    for _ in 0..40 {
        let mid = f64::midpoint(lo, hi);
        if settle(p, mid).viable() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    f64::midpoint(lo, hi)
}

/// Detector thresholds calibrated from this cell's own *healthy* baseline window (variance must rise
/// `6×` and lag-1 AR halfway to 1 — the `early_warning.rs` calibration, per cell).
fn baseline_thresholds(p: &Params, astar: f64, seed: u64) -> (f64, f64) {
    let a = 0.1 * astar;
    let mut d = settle(p, a);
    let mut rng = Rng::new(seed ^ 0xBA5E_u64);
    let w: Vec<f64> = (0..WINDOW)
        .map(|_| {
            d = advance(p, d, a, NOISE * (rng.unit() - 0.5));
            d.purity()
        })
        .collect();
    (
        windowed_variance(&w) * 6.0,
        f64::midpoint(lag1_autocorrelation(&w), 1.0),
    )
}

/// A noisy purity window collected from the cell *settled* at sustained `attack` — the quasi-stationary
/// fluctuations whose variance / lag-1 AR reveal critical slowing down (the `early_warning.rs` idiom).
fn noisy_window(p: &Params, attack: f64, seed: u64) -> Vec<f64> {
    let mut d = settle(p, attack);
    let mut rng = Rng::new(seed);
    (0..WINDOW)
        .map(|_| {
            d = advance(p, d, attack, NOISE * (rng.unit() - 0.5));
            d.purity()
        })
        .collect()
}

/// Ramp a random cell's sustained attack toward its saddle-node in discrete **settled** levels — the
/// regime where critical slowing down is observable (recovery slows *before* the mean leaves the band;
/// the collapse transient itself is too fast for any window). At each still-viable level, test whether
/// the detector's two statistics have crossed their thresholds; record the first such warning level and
/// the first level whose settled fixed point is non-viable (the collapse). Returns `None` if no genuine
/// collapse occurred (not a cascade sample), else `Some(true)` iff the warning preceded the collapse
/// (a positive lead time), `Some(false)` otherwise.
fn cascade_warned_first(p: &Params, astar: f64, seed: u64) -> Option<bool> {
    if astar <= 0.0 {
        return None;
    }
    let (var_thr, ar1_thr) = baseline_thresholds(p, astar, seed);
    let a_max = 1.15 * astar;
    let (mut warn_a, mut collapse_a) = (None, None);
    for k in 0..=LEVELS {
        let a = a_max * (k as f64 / LEVELS as f64);
        if settle(p, a).viable() {
            if warn_a.is_none() {
                let w = noisy_window(p, a, seed ^ (k as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                if windowed_variance(&w) > var_thr && lag1_autocorrelation(&w) > ar1_thr {
                    warn_a = Some(a); // the dynamical alarm, fired while still in-band
                }
            }
        } else {
            collapse_a = Some(a); // the first non-viable settled level: the saddle-node crossing
            break;
        }
    }
    // Only scenarios that actually reached collapse are sensitivity samples; positive lead ⇔ warned
    // strictly before the viability crossing.
    collapse_a.map(|ac| matches!(warn_a, Some(aw) if aw < ac))
}

/// Hold a random cell comfortably sub-critical under noise for a long run; `true` if the detector ever
/// (falsely) alarms.
fn stable_cell_false_alarms(p: &Params, astar: f64, seed: u64) -> bool {
    let (var_thr, ar1_thr) = baseline_thresholds(p, astar, seed);
    let mut rng = Rng::new(seed ^ 0xFA15_u64);
    let a_stable = (0.3 + 0.3 * rng.unit()) * astar; // random, well below a*
    let mut det = CriticalSlowingDown::new(WINDOW, var_thr, ar1_thr);
    let mut d = settle(p, a_stable);
    for _ in 0..(WINDOW * 3) {
        d = advance(p, d, a_stable, NOISE * (rng.unit() - 0.5));
        det.observe(d.purity());
        if det.alarm() {
            return true;
        }
    }
    false
}

#[test]
fn cascades_are_predicted_with_positive_lead_across_the_ensemble() {
    let (mut cascades, mut warned) = (0usize, 0usize);
    for s in 0..ENSEMBLE {
        let mut rng = Rng::new(s);
        let p = sample_params(&mut rng);
        let astar = a_star(&p);
        if let Some(ok) = cascade_warned_first(&p, astar, s) {
            cascades += 1;
            warned += usize::from(ok);
        }
    }
    // The ensemble must actually contain cascades to characterize.
    assert!(
        cascades >= (ENSEMBLE as usize) / 2,
        "too few genuine cascades to characterize ({cascades}/{ENSEMBLE})"
    );
    let rate = warned as f64 / cascades as f64;
    eprintln!("[cascade sensitivity] positive-lead warnings: {warned}/{cascades} = {rate:.3}");
    assert!(
        rate >= 0.80,
        "CSD must warn before collapse in ≥80% of random cascades (got {rate:.3}, {warned}/{cascades})"
    );
}

#[test]
fn stable_cells_rarely_false_alarm_across_the_ensemble() {
    let mut false_positives = 0usize;
    for s in 0..ENSEMBLE {
        let mut rng = Rng::new(s ^ 0x9999_u64);
        let p = sample_params(&mut rng);
        let astar = a_star(&p);
        if stable_cell_false_alarms(&p, astar, s) {
            false_positives += 1;
        }
    }
    let rate = false_positives as f64 / ENSEMBLE as f64;
    eprintln!("[cascade specificity] false alarms: {false_positives}/{ENSEMBLE} = {rate:.3}");
    assert!(
        rate <= 0.10,
        "a stable cell must false-alarm in ≤10% of random scenarios (got {rate:.3}, {false_positives}/{ENSEMBLE})"
    );
}

#[test]
fn the_cascade_ensemble_is_reproducible() {
    // The determinism contract at the ensemble level: the whole sensitivity sweep is a pure function
    // of the seeds, so its rate is a stable regression number, not a sample.
    fn sensitivity() -> (usize, usize) {
        let (mut c, mut w) = (0usize, 0usize);
        for s in 0..16u64 {
            let mut rng = Rng::new(s);
            let p = sample_params(&mut rng);
            let astar = a_star(&p);
            if let Some(ok) = cascade_warned_first(&p, astar, s) {
                c += 1;
                w += usize::from(ok);
            }
        }
        (c, w)
    }
    assert_eq!(
        sensitivity(),
        sensitivity(),
        "the ensemble replays identically"
    );
}
