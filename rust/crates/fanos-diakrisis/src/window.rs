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
use crate::mathfns::sqrt;

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
    (systemic_correlation(n), sqrt(2.0 / (n - 1) as f64))
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
#[allow(clippy::indexing_slicing, clippy::float_cmp)]
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
