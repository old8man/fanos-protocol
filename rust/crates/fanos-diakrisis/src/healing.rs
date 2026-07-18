//! Self-healing budgets and the monitoring-overhead floor (spec §6.6–§6.8, V16/V18).
//!
//! Healing is geometric — reroute via the mediator, repair via the LRC, reintegrate under the
//! cell's own mixing — but it is not free. Each **coarse** cross-segment hop contracts the
//! cell's coherences by the Fano-channel factor `1/3`, hence integration `Φ` by `1/9`. That
//! sets a hard budget on how deep a reroute may go before the reintegrated cell would fall
//! below `Φ = 1`. Separately, the reflection threshold fixes a **floor** on self-observation:
//! a cell must spend at least a third of its cycles on introspection or it cannot hold a
//! faithful self-model.

/// The Fano-channel coherence contraction per coarse hop: off-diagonal `γ_ij → γ_ij/3`
/// (corpus, fano-channel Thm 2.1).
pub const COHERENCE_CONTRACTION: f64 = 1.0 / 3.0;

/// The Fano absorption / gap `α = 1 − 1/3 = 2/3` (corpus Thm 5.1a).
pub const FANO_ABSORPTION: f64 = 2.0 / 3.0;

/// Integration contraction per coarse hop: `Φ → Φ/9` (the coherence `×1/3` squared, V16).
pub const PHI_CONTRACTION: f64 = 1.0 / 9.0;

/// The bootstrap regeneration constant `κ_bootstrap = ω₀/N = ω₀/7`, in units of the base
/// frequency `ω₀` (so the stored value is `1/7`). It is the floor on minimal self-regeneration:
/// `κ_bootstrap > 0` guarantees regeneration in *every* state, breaking the circularity
/// "low coherence → low κ → no regeneration" (corpus `axiom-septicity.md`, `κ = κ_bootstrap +
/// κ₀·Coh_E`). Note this specific value is a **scale convention** `[O]` ("one tick per cycle
/// through all N=7 dimensions"), not itself a theorem; the septicity *theorem* is `P_crit = 2/N`.
pub const KAPPA_BOOTSTRAP: f64 = 1.0 / 7.0;

/// Integration remaining after routing a repair path across `d` coarse boundaries:
/// `Φ → Φ / 9^d` (spec §6.7, V16).
#[must_use]
pub fn phi_after_coarse_hops(phi: f64, d: u32) -> f64 {
    phi * crate::mathfns::powi(PHI_CONTRACTION, d)
}

/// The maximum number of coarse reroute hops before a cell starting at `phi` would drop below
/// the integration threshold `Φ = 1` (spec §6.7). Returns `0` if already below `1`.
#[must_use]
pub fn max_reroute_depth(phi: f64) -> u32 {
    // A non-finite Φ (NaN from a degenerate coherence matrix, or +∞) is not a routable integration
    // level: `∞ · PHI_CONTRACTION = ∞ ≥ 1` would spin this loop forever (a live-confirmed DoS if a
    // gossiped reading reaches here). Reject it, and cap the loop regardless as defence in depth — the
    // depth of any finite Φ is at most a few (Φ/9^d < 1), far below the cap.
    if !phi.is_finite() || phi < 1.0 {
        return 0;
    }
    let mut depth = 0;
    let mut current = phi;
    while current * PHI_CONTRACTION >= 1.0 && depth < MAX_REROUTE_DEPTH {
        current *= PHI_CONTRACTION;
        depth += 1;
    }
    depth
}

/// A hard ceiling on reroute depth: `Φ / 9^d < 1` for any physically-meaningful Φ within a handful of
/// hops, so this only ever bites a pathological (e.g. astronomically large but finite) input.
const MAX_REROUTE_DEPTH: u32 = 64;

/// The reintegration cooldown `τ ≈ 1/Δ` from the current rate-gap `Δ` (spec §6.7, T-226(v)).
/// A cell tightens this adaptively from its own line rates rather than using a worst-case
/// constant.
#[must_use]
pub fn reintegration_cooldown(rate_gap: f64) -> f64 {
    if rate_gap <= 0.0 {
        f64::INFINITY
    } else {
        1.0 / rate_gap
    }
}

/// The self-observation floor `R_th = 1/3` (spec §6.8): a cell must budget at least a third
/// of its cycles for diagnosis or it cannot hold a faithful self-model.
pub const SELF_OBSERVATION_FLOOR: f64 = 1.0 / 3.0;

/// Whether a purity `P` on an `N`-cell leaves the self-model trustworthy, i.e. `R = 1/(N·P) ≥
/// 1/3`, equivalently `P ≤ 3/N` (spec §6.8, V18).
#[must_use]
pub fn reflection_sufficient(purity: f64, n: usize) -> bool {
    let r = if purity <= 0.0 {
        f64::INFINITY
    } else {
        1.0 / (n as f64 * purity)
    };
    r >= SELF_OBSERVATION_FLOOR - 1e-12
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn max_reroute_depth_is_total_and_terminates_on_non_finite_phi() {
        // A well-behaved Φ gives a small finite depth (Φ/9^d < 1).
        assert_eq!(max_reroute_depth(0.5), 0);
        assert_eq!(max_reroute_depth(1.0), 0, "exactly 1 does not reroute");
        assert_eq!(max_reroute_depth(9.0), 1);
        assert_eq!(max_reroute_depth(82.0), 2);
        // Non-finite Φ must not spin the loop forever (the D1 DoS): +∞·(1/9)=∞≥1 would never exit.
        assert_eq!(max_reroute_depth(f64::INFINITY), 0);
        assert_eq!(max_reroute_depth(f64::NAN), 0);
        // Even an astronomically large finite Φ is capped, not unbounded.
        assert!(max_reroute_depth(f64::MAX) <= MAX_REROUTE_DEPTH);
    }

    #[test]
    fn coarse_hop_contracts_phi_by_one_ninth() {
        // V16: one coarse boundary costs Φ → Φ/9.
        assert!((phi_after_coarse_hops(9.0, 1) - 1.0).abs() < 1e-12);
        assert!((phi_after_coarse_hops(81.0, 2) - 1.0).abs() < 1e-12);
        assert!((PHI_CONTRACTION - COHERENCE_CONTRACTION * COHERENCE_CONTRACTION).abs() < 1e-15);
    }

    #[test]
    fn reroute_depth_budget() {
        // Starting at Φ=100, one hop → ~11.1 (≥1), two → ~1.23 (≥1), three → ~0.137 (<1).
        assert_eq!(max_reroute_depth(100.0), 2);
        assert_eq!(max_reroute_depth(9.0), 1);
        assert_eq!(max_reroute_depth(1.0), 0);
        assert_eq!(max_reroute_depth(0.5), 0);
    }

    #[test]
    fn reflection_floor_is_p_at_most_three_sevenths() {
        // V18: R ≥ 1/3 ⟺ P ≤ 3/7 on the 7-cell.
        assert!(reflection_sufficient(3.0 / 7.0, 7));
        assert!(reflection_sufficient(2.0 / 7.0, 7));
        assert!(!reflection_sufficient(3.0 / 7.0 + 0.01, 7));
    }
}
