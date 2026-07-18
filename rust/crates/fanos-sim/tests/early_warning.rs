//! Critical-slowing-down early-warning — a *second, dynamical* leading indicator (frontier
//! candidate 3, `docs/frontier-synthesis.md §4.3`).
//!
//! FANOS's loss of viability is a proven **saddle-node bifurcation**: in the reduced purity
//! dynamics (`fanos_diakrisis::dynamics::PurityDynamics`) a sustained DDoS decoherence `a` past an
//! empirical threshold `a*` closes the V-preservation gate and the cell spirals to heat death. Near
//! a saddle-node the recovery eigenvalue → 0, so (Ornstein–Uhlenbeck theory; Scheffer et al.,
//! Nature 2009) the state's **variance** and **lag-1 autocorrelation** rise *before* the mean leaves
//! the band. This drives a noisy `PurityDynamics` trajectory whose sustained attack ramps toward the
//! saddle-node and shows the [`CriticalSlowingDown`] detector fires with a **positive lead time**
//! before purity crosses the viability boundary `2/7` — mirroring the coherence observatory's
//! `CascadeForecast::lead()` idiom — while a stable in-band cell raises **no** false alarm.
//!
//! The detector is pure observation; this is a deterministic regression gate on its lead time.

// Test code over fixed windows, exact statistic values, and always-present sweep results: indexing,
// exact float compares (constant-series statistics are exactly `0`), and unwrap/expect read clearest.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp
)]

use fanos_diakrisis::dynamics::PurityDynamics;
use fanos_sim::{CriticalSlowingDown, lag1_autocorrelation, windowed_variance};

/// A deterministic centred noise source in `[-0.5, 0.5)` (a fixed LCG, as in `coherence_ddos.rs`, so
/// the trajectory is reproducible without touching the sim's RNG visibility).
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 11) as f64) / ((1u64 << 53) as f64) - 0.5
    }
}

const N: usize = 7;
const PCRIT: f64 = 2.0 / 7.0;
// One fixed cell parameterization (λ, κ, P_ideal, dt), in the gate-open regime like `dynamics.rs`.
const LAMBDA: f64 = 0.1;
const KAPPA: f64 = 0.5;
const P_IDEAL: f64 = 0.9;
const DT: f64 = 0.05;
// A collection window matching the observatory flood tests, a long clean warm-up to the fixed point,
// and a small additive purity-noise amplitude (effective ±NOISE/2 per step) so the fluctuations —
// hence variance/AR1 — are meaningful without perturbing the deterministic drift.
const WINDOW: usize = 4000;
const WARMUP: usize = 20_000;
const NOISE: f64 = 0.02;

/// The cell at purity `p0`, with the fixed module parameters.
fn base_cell(p0: f64) -> PurityDynamics {
    PurityDynamics::new(LAMBDA, KAPPA, P_IDEAL, DT, N, p0)
}

/// One noisy step: advance the deterministic `PurityDynamics` under sustained `attack`, then inject
/// additive purity `noise` (the Ornstein–Uhlenbeck form CSD theory assumes) by reconstructing the
/// cell at the perturbed purity. Uses only the public `PurityDynamics` API.
fn advance(cell: PurityDynamics, attack: f64, noise: f64) -> PurityDynamics {
    let mut d = cell;
    base_cell(d.step(attack) + noise)
}

/// Settle deterministically (no noise) from the healthy start to the sustained-`attack` fixed point.
fn settle_clean(attack: f64) -> PurityDynamics {
    let mut d = base_cell(P_IDEAL);
    for _ in 0..WARMUP {
        d.step(attack);
    }
    d
}

/// From an already-settled `cell`, collect a `WINDOW`-length purity trajectory under sustained
/// `attack` with reproducible additive noise (fresh LCG stream `seed`).
fn noisy_window_from(cell: PurityDynamics, attack: f64, seed: u64) -> Vec<f64> {
    let mut cell = cell;
    let mut lcg = Lcg(seed);
    (0..WINDOW)
        .map(|_| {
            cell = advance(cell, attack, NOISE * lcg.next());
            cell.purity()
        })
        .collect()
}

/// Settle, then collect a noisy purity window at sustained `attack`.
fn noisy_window(attack: f64, seed: u64) -> Vec<f64> {
    noisy_window_from(settle_clean(attack), attack, seed)
}

/// The true (simulated) survival threshold `a*`: the largest sustained attack whose settled fixed
/// point stays viable (binary search on the attack amplitude) — the `dynamics.rs` idiom.
fn empirical_threshold(hi0: f64) -> f64 {
    let (mut lo, mut hi) = (0.0, hi0);
    for _ in 0..50 {
        let mid = f64::midpoint(lo, hi);
        if settle_clean(mid).viable() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    f64::midpoint(lo, hi)
}

/// Variance and lag-1 AR thresholds derived from a *healthy* (quiet, in-band) baseline window:
/// fire only when variance rises `6×` above baseline and AR1 rises halfway from baseline to `1`.
fn baseline_thresholds(a_star: f64) -> (f64, f64) {
    let base = noisy_window(0.1 * a_star, 0xBA5E);
    let var0 = windowed_variance(&base);
    let ar1_0 = lag1_autocorrelation(&base);
    (var0 * 6.0, f64::midpoint(ar1_0, 1.0))
}

#[test]
fn critical_slowing_down_precedes_the_viability_crossing() {
    // Ramp the sustained attack toward the saddle-node; find the first level where the CSD detector
    // fires (variance AND lag-1 AR both cross their baseline-calibrated thresholds) and the first
    // level where the cell actually loses viability (settled P ≤ 2/7). CSD must fire strictly first.
    let a_star = empirical_threshold(base_cell(P_IDEAL).survival_bound_gate_open() * 5.0);
    assert!(a_star > 0.0, "a positive survival margin exists");
    let (var_thr, ar1_thr) = baseline_thresholds(a_star);

    let levels = 48usize;
    let a_max = 1.15 * a_star;
    let mut warn: Option<(f64, f64, f64)> = None; // (attack, variance, ar1) at first alarm
    let mut collapse: Option<f64> = None;
    for k in 0..=levels {
        let a = a_max * k as f64 / levels as f64;
        if settle_clean(a).viable() {
            if warn.is_none() {
                let seed = 0x5EED ^ (k as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                let w = noisy_window(a, seed);
                let (v, ac) = (windowed_variance(&w), lag1_autocorrelation(&w));
                if v > var_thr && ac > ar1_thr {
                    warn = Some((a, v, ac));
                }
            }
        } else {
            collapse = Some(a);
            break;
        }
    }

    let (warn_a, warn_var, warn_ar1) = warn.expect("the CSD alarm fires somewhere in the ramp");
    let collapse_a = collapse.expect("the ramp reaches the saddle-node");

    // THE early-warning: the dynamical alarm fires while the cell is still viable/in-band, strictly
    // before purity crosses 2/7 — a positive lead time, exactly like `CascadeForecast::lead()`.
    assert!(
        settle_clean(warn_a).viable() && settle_clean(warn_a).purity() > PCRIT,
        "the alarm fires while the mean purity is still in-band (P={:.4} > 2/7)",
        settle_clean(warn_a).purity()
    );
    let lead = collapse_a - warn_a;
    assert!(
        lead > 0.0,
        "CSD lead time must be positive: warned at a={warn_a:.4} but collapse at a={collapse_a:.4}"
    );

    // The rise is genuine critical slowing down, not a bare threshold artifact: both statistics are
    // far above their healthy baseline (variance ≫, autocorrelation → 1).
    let base = noisy_window(0.1 * a_star, 0xBA5E);
    assert!(
        warn_var > windowed_variance(&base) * 5.0,
        "variance has risen far above baseline at the alarm"
    );
    assert!(
        warn_ar1 > lag1_autocorrelation(&base) && warn_ar1 > 0.95,
        "lag-1 autocorrelation has risen toward 1 at the alarm (got {warn_ar1:.4})"
    );
}

#[test]
fn a_stable_in_band_cell_raises_no_false_alarm() {
    // The controlled counterpart: hold the SAME cell at a comfortably sub-critical sustained attack
    // (half the survival threshold). Streaming its noisy purity through the detector over a run
    // several windows long, the sliding window never trips — no critical slowing down, no alarm —
    // and the trajectory never approaches the viability boundary (no false positive).
    let a_star = empirical_threshold(base_cell(P_IDEAL).survival_bound_gate_open() * 5.0);
    let (var_thr, ar1_thr) = baseline_thresholds(a_star);

    let a_stable = 0.5 * a_star;
    let mut cell = settle_clean(a_stable);
    let mut lcg = Lcg(0x00C0_FFEE);
    let mut detector = CriticalSlowingDown::new(WINDOW, var_thr, ar1_thr);
    let mut alarms = 0usize;
    let mut min_p = 1.0f64;
    for _ in 0..(WINDOW * 3) {
        cell = advance(cell, a_stable, NOISE * lcg.next());
        let p = cell.purity();
        min_p = min_p.min(p);
        detector.observe(p);
        if detector.alarm() {
            alarms += 1;
        }
    }

    assert_eq!(
        alarms, 0,
        "a stable in-band trajectory must not raise a CSD alarm"
    );
    assert!(
        min_p > PCRIT,
        "the stable trajectory never approaches the viability boundary (min P={min_p:.4} > 2/7)"
    );
    assert!(detector.ready(), "the sliding window filled");
    assert!(
        detector.variance() < var_thr && detector.lag1_autocorrelation() < ar1_thr,
        "both statistics stay at their healthy baseline"
    );
}

#[test]
fn windowed_variance_matches_the_definition() {
    // Var = (1/n) Σ (xᵢ − x̄)²: zero for empty/single/constant series, 8/3 for {2,4,6}.
    assert_eq!(windowed_variance(&[]), 0.0);
    assert_eq!(windowed_variance(&[5.0]), 0.0);
    assert_eq!(windowed_variance(&[1.0, 1.0, 1.0]), 0.0);
    assert!((windowed_variance(&[2.0, 4.0, 6.0]) - 8.0 / 3.0).abs() < 1e-12);
}

#[test]
fn lag1_autocorrelation_matches_the_definition_and_signature() {
    // Guards: fewer than two samples, or zero variance, return 0.
    assert_eq!(lag1_autocorrelation(&[]), 0.0);
    assert_eq!(lag1_autocorrelation(&[7.0]), 0.0);
    assert_eq!(lag1_autocorrelation(&[3.0, 3.0, 3.0]), 0.0);
    // A length-5 linear ramp has ρ₁ = 0.4 exactly (hand computation).
    assert!((lag1_autocorrelation(&[1.0, 2.0, 3.0, 4.0, 5.0]) - 0.4).abs() < 1e-12);
    // A smooth (slowly varying) series → ρ₁ near 1: the critical-slowing-down signature.
    let ramp: Vec<f64> = (0..200).map(|i| i as f64).collect();
    assert!(lag1_autocorrelation(&ramp) > 0.95);
    // An anticorrelated (alternating) series → ρ₁ near −1.
    let alt: Vec<f64> = (0..200)
        .map(|i| if i % 2 == 0 { 1.0 } else { -1.0 })
        .collect();
    assert!(lag1_autocorrelation(&alt) < -0.9);
}

#[test]
fn the_noisy_trajectory_is_reproducible_per_seed() {
    // The determinism contract: identical seed reproduces the trajectory exactly; different seeds
    // diverge. (The detector's lead time is therefore a stable regression number.)
    let a = 0.4;
    assert_eq!(noisy_window(a, 0xD00D), noisy_window(a, 0xD00D));
    assert_ne!(noisy_window(a, 0x0001), noisy_window(a, 0x0002));
}
