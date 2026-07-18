//! # Threat model B1 — the Sybil cost of seizing a FANOS coordinate
//!
//! A FANOS node's network address is **self-certifying**: its coordinate is the
//! point of `PG(2, q)` obtained by hashing the node's certificate and mapping
//! the digest into the plane (spec §L0, §7.1),
//!
//! ```text
//!     coordinate = MapToPoint(H(cert)).
//! ```
//!
//! A node cannot pick its coordinate; it can only pick `cert` (its hybrid
//! public-key bundle / nonce), and every distinct `cert` yields a fresh,
//! unpredictable point. This file derives — and the tests below empirically
//! confirm against the *real* [`map_to_point`] — how much hash-grinding work an
//! adversary must spend to place Sybil nodes on the coordinates it *wants*: one
//! chosen point, or a threshold of a chosen line / cell.
//!
//! ## Modelling assumptions
//!
//! * **(M1) Uniform, independent targeting.** `H = BLAKE3` is modelled as a
//!   random oracle, so `H(cert)` is uniform on its output space and independent
//!   across distinct `cert`. [`map_to_point`] draws a uniform *non-zero* triple
//!   of `GF(q)` from the domain-separated XOF stream and canonicalises it;
//!   because every projective point has exactly `q − 1` non-zero representatives,
//!   the result is *exactly* uniform over the `N = q² + q + 1` points (spec
//!   §7.1). Hence each cert trial lands on a point `P ~ Uniform{0, …, N−1}`,
//!   i.i.d. across trials. The uniformity test below checks M1 directly (Pearson
//!   χ² + full coverage) over a prime cell `GF(13)` and a binary cell `GF(16)` —
//!   the two independent sampling paths (rejection sampling vs. bit masking)
//!   where a bias bug could hide.
//! * **(M2) Cost unit.** We count *hash evaluations*: one `MapToPoint(H(·))` per
//!   candidate `cert`. Any real per-admission cost (PoW difficulty, stake)
//!   multiplies these counts; the geometry fixes the *number of trials*, which is
//!   what we derive and measure.
//!
//! ## (a) Seizing one chosen point — the geometric law
//!
//! Under M1 a trial hits the target point `p*` with probability `ρ = 1/N`, so the
//! number of trials `T` to the first hit is geometric:
//!
//! ```text
//!     E[T]   = 1/ρ = N = q² + q + 1
//!     Var[T] = (1−ρ)/ρ² ≈ N²          P(T > k) = (1 − 1/N)^k ≈ e^{−k/N}.
//! ```
//!
//! Targeting a *specific* coordinate therefore costs `N` hashes in expectation —
//! and only *linearly* in the cell size, not cryptographically: the
//! self-certifying address bounds targeting resistance by `N`, nothing more.
//! (`q=2`: `N=7`; `q=7`: `N=57`; `q=31`: `N=993`; `q=127`: `N=16257`.) The
//! one-point test below measures `E[T]` for `q=7` and matches `N`.
//!
//! ## (b) Capturing a threshold — the coupon-collector law
//!
//! To occupy `t` *distinct* seats from a target set `S` of size `s` (a line:
//! `s = q+1`; a whole cell: `s = N`), the adversary grinds one stream and banks
//! any fresh target it lands on. With `j` seats already held, a trial banks a new
//! one with probability `(s − j)/N`, so that step is geometric with mean
//! `N/(s − j)` and, by linearity,
//!
//! ```text
//!     E[T_capture(s, t)] = Σ_{j=0}^{t−1} N/(s − j) = N · (H_s − H_{s−t}),
//! ```
//!
//! with `H_n = Σ_{i≤n} 1/i` the harmonic number. This *contains* (a) as the
//! `s = t = 1` case (`E = N`). Consequences:
//!
//! * **Whole line** (`t = s = q+1`): `E = N · H_{q+1} ≈ N·ln(q+1)`.
//! * **Whole cell** (`t = s = N`): `E = N · H_N ≈ N·(ln N + γ)` (full collector).
//! * **Cell majority** (`t = N/2`, `s = N`): `E = N·(H_N − H_{N/2}) ≈ N·ln 2
//!   ≈ 0.69·N` — capturing *any* half of a cell is **cheaper** than one chosen
//!   point, because early draws almost always land on fresh seats. Specificity,
//!   not breadth, is what costs.
//!
//! The threshold test below measures a `q=7` line (`s = 8`) at a majority `t = 5`
//! (`E = 57·(H_8−H_3) ≈ 50.4`) and full capture `t = 8` (`E = 57·H_8 ≈ 154.9`),
//! matching the law.
//!
//! ## Security reading
//!
//! The cost is `Θ(N·log)` hashes — polynomial, not exponential. Self-certifying
//! coordinates alone do **not** stop a resourced adversary from parking on a
//! chosen seat; they raise the bar to `~N` hashes *per seat* and force it paid
//! *per coordinate*. Sybil resistance must come from a per-admission cost (M2);
//! the geometry only sets the multiplier. That quantitative bound is the point.

#![allow(clippy::indexing_slicing)]

use std::collections::BTreeSet;

use fanos_crypto::{hash::label, map_to_point};
use fanos_field::{F7, F13, F16, Field};
use fanos_geometry::{Line, Plane};
use fanos_sim::Rng;

// Fixed, reproducible seeds — one per deterministic experiment.
const SEED_PRIME: u64 = 0x5B10_0001;
const SEED_BINARY: u64 = 0x5B10_0002;
const SEED_HIT: u64 = 0x5B10_0003;
const SEED_LINE: u64 = 0x5B10_0004;

/// Adversary runs averaged per cost measurement. The sample mean of a geometric
/// / coupon-collector time has standard error `≈ σ/√RUNS`; with `RUNS = 4000` and
/// `σ ≲ 1.3·mean`, that is `< 2 %` of the mean — comfortably inside `TOL`.
const RUNS: u32 = 4_000;
/// Relative tolerance between the measured mean and the analytic expectation:
/// `> 5σ` of the sample-mean error above, yet an order of magnitude tighter than
/// any wrong law (which would be off by ≥ 100 %).
const TOL: f64 = 0.08;
/// Per-run trial cap: a run needing this many hashes signals a broken map, not
/// bad luck (`P(run > CAP) ≈ e^{−CAP/N} ≈ 0` for every cell here).
const CAP: u64 = 100_000;

/// The self-certifying coordinate index of a certificate carrying `nonce`:
/// `MapToPoint(H(cert)).index() ∈ 0..N`. This *is* the adversary's unit of work —
/// one hash evaluation per candidate certificate (spec §L0, §7.1).
fn coordinate_index<F: Field>(nonce: u64) -> usize {
    map_to_point::<F>(label::COORD, &nonce.to_le_bytes()).index()
}

/// The `n`-th harmonic number `H_n = Σ_{i=1}^n 1/i` (`H_0 = 0`).
fn harmonic(n: u32) -> f64 {
    (1..=n).map(|i| 1.0 / f64::from(i)).sum()
}

/// Analytic expected hash trials to bank `t` distinct seats from a target set of
/// size `s`, each trial landing on a uniform point of the `n`-point cell
/// (coupon-collector, derivation §(b)): `Σ_{j=0}^{t−1} n/(s−j) = n·(H_s−H_{s−t})`.
fn expected_capture_trials(n: u32, s: u32, t: u32) -> f64 {
    assert!(t >= 1 && t <= s && s <= n, "need 1 ≤ t ≤ s ≤ n");
    let n = f64::from(n);
    (0..t).map(|j| n / f64::from(s - j)).sum()
}

/// Measure the mean grinding trials for an adversary to bank `threshold` distinct
/// coordinates from `targets`, over `RUNS` independent runs off one deterministic
/// stream. Every trial is counted — hits, misses, and duplicates — because each
/// is one hash the adversary paid.
fn mean_capture_trials<F: Field>(rng: &mut Rng, targets: &BTreeSet<usize>, threshold: usize) -> f64 {
    assert!(threshold <= targets.len(), "cannot bank more seats than exist");
    let mut total: u64 = 0;
    for _ in 0..RUNS {
        let mut held: BTreeSet<usize> = BTreeSet::new();
        let mut trials: u64 = 0;
        while held.len() < threshold {
            trials += 1;
            assert!(trials <= CAP, "grind exceeded CAP — map or derivation is broken");
            let idx = coordinate_index::<F>(rng.next_u64());
            if targets.contains(&idx) {
                held.insert(idx);
            }
        }
        total += trials;
    }
    total as f64 / f64::from(RUNS)
}

/// A Pearson goodness-of-fit summary of `MapToPoint`'s point distribution.
struct Uniformity {
    /// Pearson's `χ² = Σ (Oᵢ − E)²/E` over the `N` points.
    chi2: f64,
    /// Degrees of freedom, `N − 1`.
    dof: u32,
    /// Whether every one of the `N` points was hit at least once.
    full_coverage: bool,
    /// The largest single-bin deviation `maxᵢ |Oᵢ − E|`, in units of `√E`.
    max_dev_sigma: f64,
}

/// Bin `samples_per_bin · N` fresh coordinates by point index and score them
/// against the uniform null (assumption M1).
fn uniformity_of<F: Field>(rng: &mut Rng, samples_per_bin: u64) -> Uniformity {
    let n = Plane::<F>::N as usize;
    let total = samples_per_bin * n as u64;
    let mut counts = vec![0u64; n];
    for _ in 0..total {
        counts[coordinate_index::<F>(rng.next_u64())] += 1;
    }
    let expected = total as f64 / n as f64;
    let chi2: f64 = counts
        .iter()
        .map(|&o| {
            let d = o as f64 - expected;
            d * d / expected
        })
        .sum();
    let max_dev = counts
        .iter()
        .map(|&o| (o as f64 - expected).abs())
        .fold(0.0_f64, f64::max);
    Uniformity {
        chi2,
        dof: (n - 1) as u32,
        full_coverage: counts.iter().all(|&o| o > 0),
        max_dev_sigma: max_dev / expected.sqrt(),
    }
}

/// Assert a χ² summary is consistent with the uniform null. Under M1,
/// `χ² ~ χ²(dof)` (mean `dof`, variance `2·dof`); a biased map inflates it far
/// past the `dof + 6·√(2·dof)` gate, while a uniform one essentially never trips
/// it. The `8σ` worst-bin gate is a coarse independent guard on the same null.
fn assert_uniform(u: &Uniformity, field: &str) {
    let bound = f64::from(u.dof) + 6.0 * (2.0 * f64::from(u.dof)).sqrt();
    assert!(
        u.chi2 < bound,
        "{field}: χ²={:.1} exceeded 6σ gate {bound:.1} (dof={}) — MapToPoint is biased",
        u.chi2,
        u.dof
    );
    assert!(
        u.full_coverage,
        "{field}: some point was never hit — MapToPoint does not cover the cell"
    );
    assert!(
        u.max_dev_sigma < 8.0,
        "{field}: worst bin {:.2}σ off the mean — MapToPoint is biased",
        u.max_dev_sigma
    );
}

/// (M1) The whole cost model rests on `MapToPoint` being uniform over the `N`
/// points. Check it on both independent sampling paths: prime `GF(13)`
/// (rejection sampling) and binary `GF(16)` (bit masking).
#[test]
fn mapping_is_uniform_over_prime_and_binary_cells() {
    let mut rp = Rng::new(SEED_PRIME);
    let prime = uniformity_of::<F13>(&mut rp, 250);
    assert_uniform(&prime, "GF(13)");

    let mut rb = Rng::new(SEED_BINARY);
    let binary = uniformity_of::<F16>(&mut rb, 250);
    assert_uniform(&binary, "GF(16)");
}

/// (a) One chosen coordinate is geometric with `ρ = 1/N`, so `E[T] = N`.
#[test]
fn seizing_one_chosen_point_costs_n_hashes() {
    let n = Plane::<F7>::N; // 57
    let target: BTreeSet<usize> = BTreeSet::from([29]);

    // (a) is the s = t = 1 special case of the coupon-collector law (b).
    let analytic = f64::from(n);
    assert!((analytic - expected_capture_trials(n, 1, 1)).abs() < 1e-9);

    let mut rng = Rng::new(SEED_HIT);
    let measured = mean_capture_trials::<F7>(&mut rng, &target, 1);
    assert!(
        (measured - analytic).abs() <= TOL * analytic,
        "one-point grind: measured {measured:.2} vs analytic N = {analytic:.2}"
    );
}

/// (b) A chosen line of `PG(2, 7)` has `s = q+1 = 8` seats; capturing `t` of them
/// is coupon-collector, `E = N·(H_8 − H_{8−t})`. Checked at a majority and full.
#[test]
fn capturing_a_line_threshold_follows_the_coupon_collector_law() {
    let n = Plane::<F7>::N; // 57
    let line = Line::<F7>::at(0);
    let seats: BTreeSet<usize> = Plane::<F7>::points_on(line).map(|p| p.index()).collect();
    let s = (F7::Q + 1) as usize;
    assert_eq!(seats.len(), s, "a line carries exactly q+1 points");

    let mut rng = Rng::new(SEED_LINE);
    for &t in &[5u32, 8u32] {
        // Closed form and direct sum must agree (derivation self-check).
        let analytic = expected_capture_trials(n, s as u32, t);
        let closed = f64::from(n) * (harmonic(s as u32) - harmonic(s as u32 - t));
        assert!((analytic - closed).abs() < 1e-9, "H-form ≠ Σ-form at t={t}");

        let measured = mean_capture_trials::<F7>(&mut rng, &seats, t as usize);
        assert!(
            (measured - analytic).abs() <= TOL * analytic,
            "line capture t={t}: measured {measured:.2} vs analytic {analytic:.2}"
        );
    }
}
