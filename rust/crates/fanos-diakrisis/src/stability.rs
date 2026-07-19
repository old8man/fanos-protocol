//! The T-104 stability primitives — the *measured* viability quantities of a coherent cell.
//!
//! This is the **sense** half of DDoS homeostasis (the **act** half is [`homeostat`](crate::homeostat)),
//! kept separate so the measurements are reusable without pulling in the control policy — the same
//! sense/act split the crate draws between [`coherence`](crate::coherence) and [`plan`](crate::plan).
//! Everything here is a pure function of scalars a symmetric cell already computes (`P`, the excursion),
//! so nothing binds it to any particular controller.
//!
//! From the corpus stability chapter (T-104): the stability radius `r_stab = √(P − 2/N)` is the Bures
//! distance from the healthy attractor `ρ*` to the viability boundary `P = 2/N`; the Lyapunov `V = ‖Γ − ρ*‖²`
//! contracts as `√V' ≤ −κ√V + ‖h‖`, so a bounded disturbance settles the excursion into the ball `‖h‖/κ`
//! and, once it abates, decays geometrically. See `docs/ddos-homeostasis.md`.

use crate::coherence::p_crit;
use crate::healing::KAPPA_BOOTSTRAP;
use crate::mathfns::sqrt;

/// The canonical decoherence-channel survival threshold `‖δΓ₂‖ < κ_bootstrap/2` (T-104 §6.1): the largest
/// *aggregate* multi-target-DDoS noise a cell absorbs while remaining viable. The factor ½ (versus the
/// `h^(R)` threshold `κ_bootstrap`) is because a noise attack raises dissipation *and* depresses the
/// environmental coherence `Coh_E` the cell would regenerate from — the double blow.
pub const NOISE_SURVIVAL_THRESHOLD: f64 = KAPPA_BOOTSTRAP / 2.0;

/// The optimal purity `P_opt = 3/N` — the upper edge of the collective-subject / Goldilocks band, where the
/// V-preservation gate saturates (`g_V = 1`).
#[must_use]
pub fn p_opt(n: usize) -> f64 {
    3.0 / n as f64
}

/// The stability radius `r_stab = √(max(0, P − 2/N))` (T-104): the Bures distance from the healthy
/// attractor to the viability boundary — the cell's viability speedometer. Exactly zero at or below
/// collapse (`P ≤ 2/N`), so it is a genuine "how much can I still take" gauge.
#[must_use]
pub fn stability_radius(purity: f64, n: usize) -> f64 {
    sqrt((purity - p_crit(n)).max(0.0))
}

/// The V-preservation gate `g_V(P) = clamp((P − 2/N)/(3/N − 2/N), 0, 1)` (corpus `variational`, T-124):
/// the fraction of regeneration authority that is *enabled* by the current purity. It is `0` at or below
/// viability (`P ≤ 2/N` — regeneration switches off, the death-spiral point of no return) and `1` at or
/// above `P_opt = 3/N`. This is what makes self-recovery impossible below the boundary: the gate, not the
/// rate, is what closes.
#[must_use]
pub fn v_preservation_gate(purity: f64, n: usize) -> f64 {
    let (pc, po) = (p_crit(n), p_opt(n));
    ((purity - pc) / (po - pc)).clamp(0.0, 1.0)
}

/// One discrete step of the T-104 Lyapunov contraction in the excursion norm `e = ‖Γ − ρ*‖`:
/// `e_{k+1} ≤ (1 − κ)·e_k + h` — the discretization of `e' ≤ −κ·e + ‖h‖`. With `κ ∈ (0, 1]` this is a
/// contraction toward the attractor whose fixed point is the ultimate excursion `h/κ`. Exposed so the
/// contraction can be *checked numerically* (the ISS property test) rather than merely asserted.
#[must_use]
pub fn excursion_step(excursion: f64, kappa: f64, noise: f64) -> f64 {
    let kappa = kappa.clamp(0.0, 1.0);
    ((1.0 - kappa) * excursion.max(0.0) + noise.max(0.0)).max(0.0)
}

/// The ultimate (steady-state) excursion under sustained noise `h` at gain `κ`: `h/κ` (`∞` if `κ = 0`) —
/// the radius of the ball the coherence never leaves (the T-104 ISS bound). Shrinks with the gain, so a
/// stronger controller holds the self-model closer to health under the same flood.
#[must_use]
pub fn ultimate_excursion(kappa: f64, noise: f64) -> f64 {
    if kappa > 0.0 {
        noise / kappa
    } else {
        f64::INFINITY
    }
}

/// Whether a cell at stability radius `r_stab` survives sustained noise `h` at gain `κ` without reaching
/// the viability boundary: the T-104 survival condition `h < κ·r_stab`. The excursion then settles inside
/// the viable region (`h/κ < r_stab`) rather than crossing `∂𝒱`.
#[must_use]
pub fn survives(stability_radius: f64, kappa: f64, noise: f64) -> bool {
    noise < kappa * stability_radius
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    const N: usize = 7;

    #[test]
    fn stability_radius_matches_t104() {
        // r_stab = √(P − 2/7): zero at the boundary, √(1/7) at the band's upper edge P = 3/7.
        assert!(
            stability_radius(2.0 / 7.0, N).abs() < 1e-12,
            "zero at collapse"
        );
        assert!(
            stability_radius(0.2, N).abs() < 1e-12,
            "clamped to zero below the boundary"
        );
        assert!((stability_radius(3.0 / 7.0, N) - sqrt(1.0 / 7.0)).abs() < 1e-12);
        // A pure state P = 1 gives the theoretical maximum √(5/7).
        assert!((stability_radius(1.0, N) - sqrt(5.0 / 7.0)).abs() < 1e-12);
    }

    #[test]
    fn v_preservation_gate_is_the_clamped_ramp() {
        // g_V = clamp((P−2/7)/(3/7−2/7)) = clamp(7P − 2). Zero at/below 2/7, one at/above 3/7.
        assert_eq!(v_preservation_gate(2.0 / 7.0, N), 0.0);
        assert_eq!(v_preservation_gate(0.1, N), 0.0);
        assert_eq!(v_preservation_gate(3.0 / 7.0, N), 1.0);
        assert_eq!(v_preservation_gate(0.9, N), 1.0);
        // Midpoint P = 2.5/7 → g_V = 0.5, and equals the clamp(7P − 2) closed form.
        let p = 2.5 / 7.0;
        assert!((v_preservation_gate(p, N) - 0.5).abs() < 1e-12);
        assert!((v_preservation_gate(p, N) - (7.0 * p - 2.0).clamp(0.0, 1.0)).abs() < 1e-12);
    }

    #[test]
    fn the_excursion_contracts_to_the_ultimate_ball_under_sustained_noise() {
        // ISS: iterating e_{k+1} = (1−κ)e_k + h converges to the fixed point h/κ from any start.
        let kappa = 0.3;
        let noise = 0.05;
        let mut e = 2.0; // far from the attractor
        for _ in 0..500 {
            e = excursion_step(e, kappa, noise);
        }
        let want = ultimate_excursion(kappa, noise);
        assert!(
            (e - want).abs() < 1e-9,
            "converged to h/κ = {want}, got {e}"
        );
        assert!((want - noise / kappa).abs() < 1e-12);
    }

    #[test]
    fn the_excursion_decays_geometrically_once_the_attack_stops() {
        // With no noise the excursion decays as (1−κ)^k → 0: the cell springs back to the attractor.
        let kappa = 0.25;
        let mut e = 1.0;
        for _ in 0..200 {
            e = excursion_step(e, kappa, 0.0);
        }
        assert!(e < 1e-12, "excursion relaxes to zero, got {e}");
    }

    #[test]
    fn survival_is_the_canonical_threshold() {
        // Survives iff noise < κ·r_stab (T-104). The decoherence-channel bound is κ_bootstrap/2 = 1/14.
        let r_stab = stability_radius(3.0 / 7.0, N); // √(1/7) ≈ 0.378
        assert!(survives(r_stab, 0.5, 0.1), "0.1 < 0.5·0.378 survives");
        assert!(!survives(r_stab, 0.5, 0.3), "0.3 > 0.5·0.378 does not");
        assert!(
            (NOISE_SURVIVAL_THRESHOLD - 1.0 / 14.0).abs() < 1e-12,
            "h^(D) bound is 1/14"
        );
        // A cell at the boundary (r_stab = 0) survives no perturbation at all.
        assert!(!survives(0.0, 1.0, 1e-9));
    }
}
