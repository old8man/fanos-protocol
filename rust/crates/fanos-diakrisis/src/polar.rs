//! Polar rates and the fourteen free consistency alarms (spec §6.2, corpus T-226).
//!
//! On a Fano-wired cell the 21 pairwise decoherence/error rates are **not free**: they
//! collapse to 7 values indexed by the polar point (the mediator), so within each of the 7
//! polar classes the 3 rates coincide — **14 parameter-free linear identities**. This module
//! provides the polar partition, the forward rate model `r_ij = ρ_{π(i,j)}` with
//! `ρ_k = (G − T_k)/6`, its closed-form inverse (line tomography), and the sum-rule checker
//! that turns the identities into a free structural-anomaly detector.

// Dense fixed-size (7-node) numerical kernel: array indices are all bounded by the Fano
// enumeration 0..7, so slice indexing is safe by construction, and `(i,j)` matrix fills read
// most clearly as index loops.
#![allow(clippy::indexing_slicing, clippy::needless_range_loop)]

use alloc::vec::Vec;

use fanos_geometry::fano;

/// Number of nodes / lines / polar classes in a Fano cell.
pub const N: usize = 7;

/// The polar class of point `k`: the three pairs that complete the three lines through `k`
/// (spec §6.2). Every such pair has `k` as its mediator, and the seven classes partition all
/// 21 pairs.
#[must_use]
pub fn polar_class(k: usize) -> [(usize, usize); 3] {
    let mut out = [(0usize, 0usize); 3];
    let lines = fano::POINT_LINES[k];
    for (slot, &l) in out.iter_mut().zip(lines.iter()) {
        let pts = fano::LINE_POINTS[l as usize];
        // The two points of the line other than k.
        let mut others = [0usize; 2];
        let mut idx = 0;
        for &p in &pts {
            if p as usize != k {
                others[idx] = p as usize;
                idx += 1;
            }
        }
        *slot = (others[0], others[1]);
    }
    out
}

/// The forward polar rate model: from 7 per-line rates `γ`, produce the 21 pairwise rates
/// `r_ij = ρ_{π(i,j)}`, `ρ_k = (G − T_k)/6`, `T_k = Σ_{ℓ∋k} γ_ℓ`, `G = Σ γ` (corpus T-226).
/// Returned as a symmetric `7×7` matrix with zero diagonal.
#[must_use]
pub fn line_rates_to_pair_rates(gamma: [f64; N]) -> [[f64; N]; N] {
    let g: f64 = gamma.iter().sum();
    let mut t = [0.0f64; N];
    for (k, tk) in t.iter_mut().enumerate() {
        for &l in &fano::POINT_LINES[k] {
            *tk += gamma[l as usize];
        }
    }
    let rho = |k: usize| (g - t[k]) / 6.0;
    let mut r = [[0.0f64; N]; N];
    for i in 0..N {
        for j in 0..N {
            if i != j
                && let Some(k) = fano::mediator(i, j)
            {
                r[i][j] = rho(k);
            }
        }
    }
    r
}

/// Line tomography (spec §6.2(iii), corpus T-226): recover the 7 line rates `γ` from the 7
/// polar values `ρ`, in closed form `γ_p = 3(½ Σ_k ρ_k − Σ_{k∈ℓ_p} ρ_k)`.
#[must_use]
pub fn polar_values_to_line_rates(rho: [f64; N]) -> [f64; N] {
    let half_sum: f64 = 0.5 * rho.iter().sum::<f64>();
    let mut gamma = [0.0f64; N];
    for (p, gp) in gamma.iter_mut().enumerate() {
        let line_sum: f64 = fano::LINE_POINTS[p].iter().map(|&k| rho[k as usize]).sum();
        *gp = 3.0 * (half_sum - line_sum);
    }
    gamma
}

/// The seven polar values `ρ_k` extracted from a pairwise-rate matrix (one representative
/// rate per class). Used to run tomography backwards from measured rates.
#[must_use]
pub fn polar_values(rates: &[[f64; N]; N]) -> [f64; N] {
    let mut rho = [0.0f64; N];
    for (k, slot) in rho.iter_mut().enumerate() {
        let (a, b) = polar_class(k)[0];
        *slot = rates[a][b];
    }
    rho
}

/// Check the fourteen polar equalities against a measured `7×7` rate matrix. Returns the list
/// of polar points `k` whose class violates the identity beyond `tol` — an empty list means
/// the wiring is a clean Fano plane (spec §6.2 selector T-226(vi)).
#[must_use]
pub fn violated_classes(rates: &[[f64; N]; N], tol: f64) -> Vec<usize> {
    let mut violated = Vec::new();
    for k in 0..N {
        let [(a, b), (c, d), (e, f)] = polar_class(k);
        let (r0, r1, r2) = (rates[a][b], rates[c][d], rates[e][f]);
        // A non-finite rate is a violation, not a pass: `(NaN − r).abs() > tol` is false, so an
        // unguarded check would let a Byzantine node reporting NaN/±∞ rates satisfy every polar
        // identity and evade detection. The organism treats a non-finite observable as inconsistent.
        if !r0.is_finite()
            || !r1.is_finite()
            || !r2.is_finite()
            || (r0 - r1).abs() > tol
            || (r0 - r2).abs() > tol
        {
            violated.push(k);
        }
    }
    violated
}

/// Whether all fourteen polar sum-rules hold (no violated class).
#[must_use]
pub fn sum_rules_hold(rates: &[[f64; N]; N], tol: f64) -> bool {
    violated_classes(rates, tol).is_empty()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn violated_classes_flags_non_finite_rates() {
        // A uniform rate matrix satisfies every polar identity — no violations.
        let uniform = [[1.0f64; N]; N];
        assert!(violated_classes(&uniform, 1e-9).is_empty());
        // A single NaN rate must be reported as a violation, not silently satisfy the identity: an
        // unguarded (NaN − r).abs() > tol is false, which would let a Byzantine node evade the check
        // by reporting non-finite rates (D3).
        let mut poisoned = uniform;
        let (a, b) = polar_class(0)[0];
        poisoned[a][b] = f64::NAN;
        assert!(violated_classes(&poisoned, 1e-9).contains(&0));
        // ±∞ likewise.
        let mut inf = uniform;
        let (c, d) = polar_class(3)[0];
        inf[c][d] = f64::INFINITY;
        assert!(violated_classes(&inf, 1e-9).contains(&3));
    }

    #[test]
    fn polar_classes_partition_all_21_pairs() {
        use std::collections::HashSet;
        let mut pairs = HashSet::new();
        for k in 0..N {
            for (a, b) in polar_class(k) {
                let key = if a < b { (a, b) } else { (b, a) };
                assert!(pairs.insert(key), "pair {key:?} appears in two classes");
                // k is the mediator of the pair.
                assert_eq!(fano::mediator(a, b), Some(k));
            }
        }
        assert_eq!(pairs.len(), 21);
    }

    #[test]
    fn forward_model_satisfies_sum_rules() {
        // For any line rates, the produced pairwise rates satisfy the 14 identities.
        for seed in 0..20u32 {
            let gamma = std::array::from_fn(|i| ((seed * 7 + i as u32 * 3) % 11) as f64 + 0.5);
            let rates = line_rates_to_pair_rates(gamma);
            assert!(sum_rules_hold(&rates, 1e-9), "seed {seed}");
        }
    }

    #[test]
    fn tomography_round_trips() {
        // γ → (G,T,ρ) → γ recovers the line rates exactly (spec §6.2(iii)).
        let gamma = [1.0, 2.0, 3.5, 0.5, 4.0, 2.5, 1.5];
        let rates = line_rates_to_pair_rates(gamma);
        let rho = polar_values(&rates);
        let back = polar_values_to_line_rates(rho);
        for i in 0..N {
            assert!((gamma[i] - back[i]).abs() < 1e-9, "γ[{i}] mismatch");
        }
    }

    #[test]
    fn byzantine_forge_breaks_exactly_its_polar_class() {
        // A single forged rate violates only the polar class of that pair's mediator,
        // localizing the anomaly (spec §6.2).
        let gamma = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];
        let mut rates = line_rates_to_pair_rates(gamma);
        // Corrupt the (0,1) channel; its mediator is the violated class.
        let k = fano::mediator(0, 1).unwrap();
        rates[0][1] += 5.0;
        rates[1][0] += 5.0;
        let violated = violated_classes(&rates, 1e-9);
        assert_eq!(
            violated,
            std::vec![k],
            "only the mediator's class is flagged"
        );
    }
}
