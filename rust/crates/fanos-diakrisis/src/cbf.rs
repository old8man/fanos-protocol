//! A Control-Barrier-Function (CBF) safety seam for the coherence homeostat (frontier candidate 2).
//!
//! The homeostat's action authority is a *learnable* seam — a future SYNARC policy chooses the
//! regeneration control `κ`. To guarantee that **no** learned or adversarial choice can ever push the cell
//! out of viability, every proposed control is filtered through a **control barrier function** (Ames et
//! al., *Control Barrier Functions*, arXiv:1609.06408; Kolathaya–Ames, *ISSf-CBF*, arXiv:1803.03035).
//!
//! Take the barrier `h(P) = P − 2/N`, so the safe set `{h ≥ 0}` is exactly the viability region `𝒱`
//! (T-104). An action keeps the state in `𝒱` for all time iff it satisfies `ḣ + γ·h ≥ 0` (forward
//! invariance, `γ > 0`). For the reduced purity dynamics `dP/dτ = drift + control_gain·κ` (see
//! [`PurityDynamics::barrier_coeffs`](crate::dynamics::PurityDynamics::barrier_coeffs)) this is **one
//! linear inequality in the scalar `κ`**, so the CBF quadratic program `min‖κ − κ_prop‖² s.t. …` collapses
//! to a closed form: the minimal correction of the proposal that holds the barrier.
//!
//! Two facts make this the right envelope for the reflex/learnable seam (`synarc-node-architecture`):
//! * **It provably contains `{P ≥ 2/N}`.** Every proposal — including an adversary's `κ = 0` — is raised
//!   to the least `κ` that satisfies the barrier, so the cell never crosses `∂𝒱` while the CBF is
//!   feasible. A SYNARC policy is free *within* this envelope and safe *at its edge* — this is what makes
//!   the learnable layer unable to break safety, no matter what it learns.
//! * **It recovers escalation exactly.** At the boundary the V-gate `g_V(P) → 0`, so `control_gain → 0`
//!   and the minimal safe control → ∞: no admissible `κ` can hold the barrier, and the filter returns
//!   [`SafeControl::Escalate`] — precisely the corpus "point of no return without external help"
//!   (T-104 §5). The escalation boundary is thus **derived from feasibility**, not hand-set.

use crate::healing::KAPPA_BOOTSTRAP;

/// The default barrier-relaxation rate `γ` (the class-`K` gain in `ḣ + γ·h ≥ 0`): larger `γ` lets the
/// state ride closer to the boundary before the filter intervenes, smaller `γ` is more cautious. `1.0` is
/// a neutral, well-conditioned choice.
pub const DEFAULT_GAMMA: f64 = 1.0;

/// The outcome of filtering a proposed control through the viability CBF.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SafeControl {
    /// The control to apply — the least change to the proposal that holds the barrier. Forward-invariant:
    /// applying it never lets `P` cross `2/N`.
    Apply(f64),
    /// No admissible control can hold the barrier — the regeneration gate has closed (`P ≤ 2/N`) or the
    /// disturbance exceeds the control authority `u_max`. External help is required (escalate to parent).
    Escalate,
}

/// Filter a proposed control `u_prop` through the viability control barrier, given the barrier value
/// `h = P − 2/N`, the plant's affine coefficients `(drift, control_gain)` (from
/// [`PurityDynamics::barrier_coeffs`](crate::dynamics::PurityDynamics::barrier_coeffs)), the relaxation
/// rate `gamma`, and the admissible control range `[u_min, u_max]`.
///
/// Returns the minimal correction of `u_prop` satisfying `drift + control_gain·u + gamma·h ≥ 0`, clamped
/// to `[u_min, u_max]`, or [`SafeControl::Escalate`] when the constraint is infeasible on that range.
#[must_use]
pub fn cbf_filter(
    u_prop: f64,
    h: f64,
    drift: f64,
    control_gain: f64,
    gamma: f64,
    u_min: f64,
    u_max: f64,
) -> SafeControl {
    // At or below the boundary the barrier is already violated and self-control cannot recover (g_V = 0).
    if h <= 0.0 {
        return SafeControl::Escalate;
    }
    // The barrier constraint reads `control_gain·u ≥ −slack`, with `slack = drift + γ·h`.
    let slack = drift + gamma * h;
    if control_gain <= 0.0 {
        // Control cannot raise `ḣ` (gate closed, or the state is already at/above the ideal). Safe only if
        // the *uncontrolled* constraint already holds; otherwise no control helps → escalate.
        if slack >= 0.0 {
            SafeControl::Apply(u_prop.clamp(u_min, u_max))
        } else {
            SafeControl::Escalate
        }
    } else {
        let u_min_safe = -slack / control_gain; // the least control that satisfies the barrier
        if u_min_safe > u_max {
            SafeControl::Escalate // even maximal control cannot hold the barrier — disturbance too strong
        } else {
            // Raise the proposal to the safe minimum where needed, then clamp to the admissible range.
            SafeControl::Apply(u_prop.max(u_min_safe).clamp(u_min, u_max))
        }
    }
}

/// [`cbf_filter`] with the homeostat's standard control range `[κ_bootstrap, 1]` and [`DEFAULT_GAMMA`] —
/// the convenience the homeostat / SYNARC seam uses. Because the lower clamp is `κ_bootstrap`, the filtered
/// control is *never below* the guaranteed floor and rises above it exactly when the barrier demands, so it
/// is strictly stronger than the fixed `κ_bootstrap` clamp it supersedes.
#[must_use]
pub fn cbf_filter_default(u_prop: f64, h: f64, drift: f64, control_gain: f64) -> SafeControl {
    cbf_filter(u_prop, h, drift, control_gain, DEFAULT_GAMMA, KAPPA_BOOTSTRAP, 1.0)
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;
    use crate::dynamics::PurityDynamics;

    const N: usize = 7;

    #[test]
    fn the_filter_raises_an_unsafe_proposal_to_the_barrier_minimum() {
        // h=0.3, drift=−0.5, gain=0.6, γ=1 ⇒ slack=−0.2, u_min_safe=0.2/0.6≈0.333. An adversarial κ=0 is
        // raised to that minimum (which is above κ_bootstrap, so the clamp does not bind).
        match cbf_filter(0.0, 0.3, -0.5, 0.6, 1.0, KAPPA_BOOTSTRAP, 1.0) {
            SafeControl::Apply(u) => assert!((u - 1.0 / 3.0).abs() < 1e-6, "raised to u_min_safe, got {u}"),
            other => panic!("expected Apply, got {other:?}"),
        }
        // A proposal already above the minimum is left untouched (minimal invasion).
        match cbf_filter(0.8, 0.3, -0.5, 0.6, 1.0, KAPPA_BOOTSTRAP, 1.0) {
            SafeControl::Apply(u) => assert!((u - 0.8).abs() < 1e-12, "a safe proposal is unchanged"),
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn the_filter_escalates_when_the_barrier_is_infeasible() {
        // Gate nearly closed (tiny control_gain) ⇒ u_min_safe ≫ 1 ⇒ no admissible control holds it.
        assert_eq!(
            cbf_filter(0.5, 0.01, -0.4, 1e-6, 1.0, KAPPA_BOOTSTRAP, 1.0),
            SafeControl::Escalate,
            "a barrier only maximal-infinite control could hold escalates"
        );
        // At/below the boundary, escalate regardless of the proposal.
        assert_eq!(
            cbf_filter(1.0, 0.0, 0.0, 0.5, 1.0, KAPPA_BOOTSTRAP, 1.0),
            SafeControl::Escalate,
            "h ≤ 0 escalates"
        );
    }

    #[test]
    fn the_cbf_keeps_the_cell_viable_under_an_adversarial_zero_control() {
        // A malicious SYNARC proposes κ = 0 (let the cell die) every step. The CBF must keep P > 2/N at
        // EVERY step — it never crosses ∂𝒱 — and if it can no longer self-hold it escalates *while still
        // viable*, never after death.
        let mut d = PurityDynamics::new(0.1, 0.5, 0.9, 0.02, N, 0.6);
        let attack = 0.5;
        for _ in 0..20_000 {
            assert!(d.viable(), "P is above the boundary at the start of every controlled step");
            let (drift, gain) = d.barrier_coeffs(attack);
            match cbf_filter_default(0.0, d.barrier(), drift, gain) {
                SafeControl::Apply(u) => {
                    d.step_with_control(attack, u);
                }
                SafeControl::Escalate => {
                    assert!(d.viable(), "escalates while still viable — hands off before crossing");
                    return;
                }
            }
        }
        assert!(d.viable(), "the barrier was never crossed under adversarial control");
    }

    #[test]
    fn the_cbf_tolerates_a_stronger_attack_than_the_fixed_clamp() {
        // Same proposal (κ_bootstrap) both ways. A fixed κ_bootstrap clamp crosses the boundary at this
        // attack; the CBF raises κ toward the barrier minimum (up to 1) and never crosses it.
        let attack = 0.8;
        let make = || PurityDynamics::new(0.1, KAPPA_BOOTSTRAP, 0.9, 0.02, N, 0.9);

        let mut fixed = make();
        for _ in 0..20_000 {
            fixed.step(attack); // uses the fixed κ = κ_bootstrap
        }
        assert!(!fixed.viable(), "the fixed κ_bootstrap clamp crosses ∂𝒱 at this attack");

        let mut cbf = make();
        for _ in 0..20_000 {
            let (drift, gain) = cbf.barrier_coeffs(attack);
            match cbf_filter_default(KAPPA_BOOTSTRAP, cbf.barrier(), drift, gain) {
                SafeControl::Apply(u) => {
                    assert!(u >= KAPPA_BOOTSTRAP - 1e-12, "never drops below the guaranteed floor");
                    cbf.step_with_control(attack, u);
                }
                SafeControl::Escalate => break, // escalated while viable (asserted below)
            }
        }
        assert!(cbf.viable(), "the CBF holds viability where the fixed clamp died");
    }
}
