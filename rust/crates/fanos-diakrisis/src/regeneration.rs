//! Regeneration dynamics: recovery *rate* and reintegration *time*, from the corpus master
//! equation and the exact spectral gap (spec §6.7; corpus `evolution.md`, `fano-fingerprint.md`
//! T-226(v)).
//!
//! Healing is not only *what* to repair (that is [`plan`](crate::plan)) but *how fast* the cell
//! comes back. The corpus fixes both from measurable quantities, so a cell forecasts its own
//! recovery rather than waiting a worst-case constant:
//!
//! * **Regeneration rate** `κ(Γ) = κ_bootstrap + κ₀·Coh_E(Γ)` (corpus `axiom-septicity.md`): the
//!   drift of the master term `R[Γ,E] = κ(Γ)·(ρ* − Γ)·g_V(P)` that pulls the state back to its
//!   self-model `ρ*`. The `κ_bootstrap` floor guarantees progress even from near-zero coherence.
//! * **Replacement channel** `φ_k = (1−k)·Γ + k·ρ*`, `k = 1 − R` (corpus Level-9): the more a
//!   cell reflects (`R = 1/(N·P)`), the *less* it must overwrite itself to reintegrate.
//! * **Reintegration cooldown** `τ ≥ 1/Δ`, exact gap `Δ = (G − max_k T_k)/6` (T-226(v)): the
//!   relaxation time of the slowest polar mode, read straight from the cell's 7 line rates.
//!
//! All three are theorems `[Т]` (rate law and gap) or the corpus convention `[О]` (the specific
//! `κ_bootstrap` scale); see [`crate::healing`] for the budget side (`Φ → Φ/9`, `R_th = 1/3`).

use fanos_geometry::fano;

use crate::healing::KAPPA_BOOTSTRAP;

/// Total line flux `G = Σ_p γ_p`: the sum of the cell's seven Fano-line rates (T-226).
#[must_use]
pub fn total_line_flux(line_rates: &[f64; fano::N]) -> f64 {
    line_rates.iter().sum()
}

/// Point flux `T_k = Σ_{lines ∋ k} γ_p`: the sum of the three line rates incident to point `k`
/// (T-226). Returns `0` for an out-of-range point.
#[must_use]
pub fn point_flux(line_rates: &[f64; fano::N], k: usize) -> f64 {
    let Some(lines) = fano::POINT_LINES.get(k) else {
        return 0.0;
    };
    lines
        .iter()
        .map(|&l| line_rates.get(l as usize).copied().unwrap_or(0.0))
        .sum()
}

/// The polar-class decay rate `ρ_k = (G − T_k)/6` (T-226(i)): the relaxation rate of the polar
/// coherences on axis `k`.
#[must_use]
pub fn polar_decay_rate(line_rates: &[f64; fano::N], k: usize) -> f64 {
    (total_line_flux(line_rates) - point_flux(line_rates, k)) / 6.0
}

/// The exact spectral gap `Δ = min_k ρ_k = (G − max_k T_k)/6` (T-226(v)): the slowest polar mode,
/// set by the strongest-flux axis. For uniform line rates `γ̄` this is `Δ = (2/3)·γ̄`.
#[must_use]
pub fn spectral_gap(line_rates: &[f64; fano::N]) -> f64 {
    let g = total_line_flux(line_rates);
    let max_t = (0..fano::N)
        .map(|k| point_flux(line_rates, k))
        .fold(f64::NEG_INFINITY, f64::max);
    (g - max_t) / 6.0
}

/// The reintegration cooldown `τ ≥ 1/Δ` read from the cell's current line rates (T-226(v)): the
/// time to relax the slowest polar mode after a repair. `∞` if the gap has closed (`Δ ≤ 0`).
#[must_use]
pub fn recovery_time(line_rates: &[f64; fano::N]) -> f64 {
    let delta = spectral_gap(line_rates);
    if delta <= 0.0 {
        f64::INFINITY
    } else {
        1.0 / delta
    }
}

/// The regeneration rate `κ(Γ) = κ_bootstrap + κ₀·Coh_E` (corpus `axiom-septicity.md`), given the
/// coupling `κ₀` and the environmental coherence `Coh_E ∈ [0, 1]`. The `κ_bootstrap` floor makes
/// this strictly positive even at `Coh_E = 0`, so recovery never stalls.
#[must_use]
pub fn regeneration_rate(kappa0: f64, coh_e: f64) -> f64 {
    KAPPA_BOOTSTRAP + kappa0 * coh_e.clamp(0.0, 1.0)
}

/// The replacement fraction `k = 1 − R` of the self-model channel `φ_k = (1−k)Γ + k·ρ*` (corpus
/// Level-9): how strongly a reintegrating cell overwrites itself toward its self-model. Higher
/// reflection `R` ⇒ smaller `k` ⇒ a lighter touch. Clamped to `[0, 1]`.
#[must_use]
pub fn replacement_fraction(reflection: f64) -> f64 {
    (1.0 - reflection).clamp(0.0, 1.0)
}

/// One step of the replacement channel on a scalar coherence: `(1−k)·current + k·target`
/// (corpus Level-9 `φ_k`). Applied element-wise, this relaxes `Γ` toward the self-model `ρ*`.
#[must_use]
pub fn regenerate_toward(current: f64, target: f64, k: f64) -> f64 {
    let k = k.clamp(0.0, 1.0);
    (1.0 - k) * current + k * target
}

#[cfg(test)]
#[allow(clippy::float_cmp, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn uniform_rates_give_the_two_thirds_gap() {
        // T-226(v): uniform line rates γ̄ ⇒ Δ = (2/3)·γ̄, τ = 1/Δ = 1.5/γ̄.
        let gamma_bar = 4.0;
        let rates = [gamma_bar; fano::N];
        assert!((spectral_gap(&rates) - 2.0 / 3.0 * gamma_bar).abs() < 1e-12);
        assert!((recovery_time(&rates) - 1.0 / (2.0 / 3.0 * gamma_bar)).abs() < 1e-12);
        // G = 7γ̄, each point flux T_k = 3γ̄ (three lines per point).
        assert!((total_line_flux(&rates) - 7.0 * gamma_bar).abs() < 1e-12);
        assert!((point_flux(&rates, 0) - 3.0 * gamma_bar).abs() < 1e-12);
    }

    #[test]
    fn gap_is_set_by_the_strongest_flux_axis() {
        // Make one point's three lines hotter: its T_k is largest, so it sets the (smaller) gap.
        let mut rates = [1.0; fano::N];
        for &l in &fano::POINT_LINES[0] {
            rates[l as usize] = 5.0;
        }
        let delta = spectral_gap(&rates);
        // Δ = (G − max_k T_k)/6, and max_k T_k = point_flux(0).
        let expected = (total_line_flux(&rates) - point_flux(&rates, 0)) / 6.0;
        assert!((delta - expected).abs() < 1e-12);
        assert_eq!(delta, polar_decay_rate(&rates, 0)); // the strongest axis is the slowest mode
    }

    #[test]
    fn regeneration_rate_has_a_positive_floor() {
        // κ_bootstrap > 0 guarantees progress even with zero environmental coherence.
        assert_eq!(regeneration_rate(2.0, 0.0), KAPPA_BOOTSTRAP);
        assert!(regeneration_rate(2.0, 1.0) > KAPPA_BOOTSTRAP);
    }

    #[test]
    fn more_reflection_means_a_lighter_replacement() {
        // k = 1 − R: a highly reflective cell (R→1) barely overwrites itself.
        assert!((replacement_fraction(1.0 / 3.0) - 2.0 / 3.0).abs() < 1e-12);
        assert!(replacement_fraction(0.9) < replacement_fraction(0.4));
        // The channel is a convex blend toward the self-model.
        assert!((regenerate_toward(0.0, 1.0, 0.25) - 0.25).abs() < 1e-12);
    }

    #[test]
    fn closed_gap_means_infinite_cooldown() {
        // If every line rate is zero the gap closes and reintegration cannot complete.
        assert_eq!(recovery_time(&[0.0; fano::N]), f64::INFINITY);
    }
}
