//! A deterministic reduced-master-equation simulator — the model-system that *validates* the
//! [`homeostat`](crate::homeostat) numerically (corpus `model-systems.md`, `stability.md §2,§5`).
//!
//! The full state is a `7×7` Lindblad flow; on the **equicorrelated stratum** it collapses to one scalar,
//! the purity `P` (V15), and the corpus stability results are stated in exactly that scalar. This module
//! integrates that scalar surrogate so the T-104 predictions become executable, deterministic checks:
//!
//! ```text
//! dP/dτ  =  −2·(λ + a)·(P − 1/N)        (dissipation: toward the max-mixed 1/N — "heat death")
//!           + 2·κ·g_V(P)·(P_ideal − P)   (regeneration ℛ: toward the ordered attractor — "matter")
//! ```
//!
//! * `λ` is the baseline dissipative **spectral gap** (`regeneration::spectral_gap`).
//! * `a ≥ 0` is the **DDoS decoherence** `h^(D)` this step — the disturbance that adds dissipation.
//! * `κ` is the regeneration rate (`≥ κ_bootstrap = 1/7`, T-59), gated by the V-preservation gate
//!   `g_V(P)` (`homeostat::v_preservation_gate`): below viability `P ≤ 2/N` the gate is `0`, regeneration
//!   switches off, and the dissipation runs unopposed — **the death spiral** (`stability.md §5`).
//!
//! Faithful on the equicorrelated stratum, a first-order reduction off it (see the honesty ledger in
//! `docs/ddos-homeostasis.md`). It is a *validation instrument*, not production control — the shipping
//! controller is [`homeostat::Homeostat`], which this simulator drives to confirm its guarantees.

use crate::coherence::p_crit;
use crate::stability::{stability_radius, v_preservation_gate};

/// The maximally-mixed purity `1/N` — the "heat-death" floor the dissipator relaxes toward.
#[must_use]
fn mixed_purity(n: usize) -> f64 {
    1.0 / n as f64
}

/// The reduced (scalar-purity) coherence dynamics of one cell under a decoherence disturbance.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct PurityDynamics {
    /// Baseline dissipation `λ` (the cell's dissipative spectral gap).
    lambda: f64,
    /// Regeneration rate `κ` (the homeostat's guaranteed authority, `≥ κ_bootstrap`).
    kappa: f64,
    /// The ordered attractor purity `P_ideal = Tr(ρ*²·φ(ρ*))` the regenerator pulls toward (T-98).
    p_ideal: f64,
    /// Integration step `dt` (in the line-rate time unit).
    dt: f64,
    /// Cell size `N`.
    n: usize,
    /// Current purity `P`, always in `[1/N, 1]`.
    p: f64,
}

impl PurityDynamics {
    /// A cell with dissipation `lambda`, regeneration rate `kappa`, attractor purity `p_ideal`, step `dt`,
    /// size `n`, starting at purity `p0`. Degenerate inputs are clamped to keep the flow well-posed.
    #[must_use]
    pub fn new(lambda: f64, kappa: f64, p_ideal: f64, dt: f64, n: usize, p0: f64) -> Self {
        let n = n.max(2);
        Self {
            lambda: lambda.max(0.0),
            kappa: kappa.max(0.0),
            p_ideal: p_ideal.clamp(mixed_purity(n), 1.0),
            dt: dt.clamp(1e-6, 1.0),
            n,
            p: p0.clamp(mixed_purity(n), 1.0),
        }
    }

    /// The current purity `P`.
    #[must_use]
    pub fn purity(self) -> f64 {
        self.p
    }

    /// The current stability radius `r_stab = √(P − 2/N)` (T-104) — the viability speedometer.
    #[must_use]
    pub fn r_stab(self) -> f64 {
        stability_radius(self.p, self.n)
    }

    /// Whether the cell is still viable (`P > 2/N`). At or below this the regeneration gate is closed.
    #[must_use]
    pub fn viable(self) -> bool {
        self.p > p_crit(self.n)
    }

    /// Advance one step under sustained DDoS decoherence `attack` (the `h^(D)` amplitude), returning the
    /// new purity. Regeneration is gated by `g_V(P)`, so once `P` crosses the viability boundary the pull
    /// toward health vanishes and only dissipation remains — the death spiral, faithfully reproduced.
    pub fn step(&mut self, attack: f64) -> f64 {
        let a = attack.max(0.0);
        let gate = v_preservation_gate(self.p, self.n);
        let dissipation = -2.0 * (self.lambda + a) * (self.p - mixed_purity(self.n));
        let regeneration = 2.0 * self.kappa * gate * (self.p_ideal - self.p);
        self.p = (self.p + self.dt * (dissipation + regeneration)).clamp(mixed_purity(self.n), 1.0);
        self.p
    }

    /// The analytic steady-state purity under a *sustained* attack `a`, in the `g_V = 1` regime
    /// (`P ≥ P_opt = 3/N`): `P_ss = ((λ+a)/N + κ·P_ideal) / (λ + a + κ)` — the T-98 balance, a
    /// `κ`-weighted average of the ideal `P_ideal` and the heat-death `1/N`.
    #[must_use]
    pub fn steady_state(self, attack: f64) -> f64 {
        let a = attack.max(0.0);
        let d = self.lambda + a;
        (d * mixed_purity(self.n) + self.kappa * self.p_ideal) / (d + self.kappa)
    }

    /// A **conservative upper bound** on the survival threshold: the largest sustained decoherence whose
    /// `g_V = 1` fixed point stays viable, `ā = N·κ·(P_ideal − 2/N) − λ` (from the balance above with the
    /// gate fully open). `0` if even a quiet cell cannot hold viability (`κ` too weak for `λ`).
    ///
    /// **This is an over-estimate, not the true boundary** — and the simulator is what reveals it. The
    /// V-preservation gate `g_V` *ramps* from `0` to `1` across `P ∈ (2/N, 3/N)`, so regeneration is weaker
    /// than `g_V = 1` exactly where the near-boundary fixed point lives. The real threshold is therefore
    /// **lower**, and the loss of viability is a **saddle-node bifurcation** (corpus `bifurcation.md`): the
    /// regeneration hump `κ·g_V(P)·(P_ideal − P)` must rise above the dissipation line `(λ+a)(P − 1/N)`, and
    /// it stops doing so at a tangency below `ā`. Use this as a necessary condition / conservative sizing
    /// bound; obtain the true threshold from [`step`](Self::step) (see the crate tests). Keeping the honest
    /// gap between the closed form and the simulated truth is the point.
    #[must_use]
    pub fn survival_bound_gate_open(self) -> f64 {
        (self.n as f64 * self.kappa * (self.p_ideal - p_crit(self.n)) - self.lambda).max(0.0)
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;
    use crate::healing::KAPPA_BOOTSTRAP;

    const N: usize = 7;

    fn settle(mut d: PurityDynamics, attack: f64, steps: usize) -> PurityDynamics {
        for _ in 0..steps {
            d.step(attack);
        }
        d
    }

    /// The true survival threshold found by simulation: the largest sustained attack the cell still
    /// survives (binary search on the attack amplitude). This is the honest boundary, not the closed form.
    fn empirical_threshold(base: PurityDynamics, hi0: f64) -> f64 {
        let (mut lo, mut hi) = (0.0, hi0);
        for _ in 0..50 {
            let mid = 0.5 * (lo + hi);
            if settle(base, mid, 20_000).viable() {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        0.5 * (lo + hi)
    }

    #[test]
    fn a_quiet_cell_settles_at_its_healthy_fixed_point() {
        // No attack, and the quiet fixed point P_ss(0) ≥ 3/7 (gate fully open) so the closed form is exact:
        // purity converges to the T-98 balance point, viable and in-band.
        let d = PurityDynamics::new(0.1, 0.5, 0.6, 0.05, N, 0.5);
        let settled = settle(d, 0.0, 5000);
        assert!(d.steady_state(0.0) >= 3.0 / 7.0, "this operating point is in the gate-open regime");
        assert!((settled.purity() - d.steady_state(0.0)).abs() < 1e-6, "converges to P_ss(0)");
        assert!(settled.viable(), "the quiet fixed point is viable");
        assert!(settled.r_stab() > 0.0);
    }

    #[test]
    fn survival_is_a_sharp_bifurcation_at_or_below_the_gate_open_bound() {
        // The simulator reveals the true picture: loss of viability is a *saddle-node bifurcation*, and the
        // true threshold sits at or below the g_V=1 closed-form over-estimate (the V-gate ramp weakens
        // regeneration near the boundary). We assert all three: sharp, positive, and ≤ the bound.
        let base = PurityDynamics::new(0.1, 0.5, 0.9, 0.02, N, 0.9);
        let bound = base.survival_bound_gate_open();
        assert!(bound > 0.0);

        // A huge sustained flood always spirals to heat death 1/N; a quiet cell always survives.
        let dead = settle(base, bound * 5.0, 20_000);
        assert!(!dead.viable() && (dead.purity() - 1.0 / N as f64).abs() < 1e-3, "spirals to 1/N");
        assert!(settle(base, 0.0, 20_000).viable());

        // The true (simulated) threshold exists, is positive, and does not exceed the closed-form bound.
        let a_star = empirical_threshold(base, bound * 5.0);
        assert!(a_star > 0.0, "a positive survival margin exists");
        assert!(a_star <= bound + 1e-6, "the true threshold is at or below the gate-open bound {bound}");

        // Sharp transition (bifurcation, not a gradual fade): a hair below survives, a hair above collapses.
        assert!(settle(base, a_star * 0.9, 20_000).viable(), "just below a* survives");
        assert!(!settle(base, a_star * 1.1, 20_000).viable(), "just above a* collapses");
    }

    #[test]
    fn the_controller_is_necessary_no_regeneration_always_dies() {
        // κ = 0 (regeneration off — controller absent): even with NO attack the dissipator drags purity to
        // the heat-death 1/N. This is the death spiral the homeostat's guaranteed κ_bootstrap prevents.
        let dead = settle(PurityDynamics::new(0.1, 0.0, 0.9, 0.05, N, 0.6), 0.0, 5000);
        assert!(!dead.viable(), "with no regeneration the cell collapses");
        assert!((dead.purity() - 1.0 / N as f64).abs() < 1e-3);

        // The same cell with only the GUARANTEED floor κ_bootstrap survives quiet and a positive attack —
        // the floor alone (no adaptive Coh_E) already yields a non-trivial survival margin (found by sim).
        let floored = PurityDynamics::new(0.02, KAPPA_BOOTSTRAP, 0.9, 0.05, N, 0.6);
        assert!(settle(floored, 0.0, 20_000).viable(), "κ_bootstrap holds a quiet cell viable");
        let a_star = empirical_threshold(floored, floored.survival_bound_gate_open() * 2.0);
        assert!(a_star > 0.0, "κ_bootstrap gives a positive survival margin, got {a_star}");
        assert!(settle(floored, a_star * 0.8, 20_000).viable());
    }

    #[test]
    fn the_cell_springs_back_exponentially_after_the_attack_stops() {
        // Drive the cell down with a heavy but survivable flood (0.8× the true simulated threshold), then
        // stop: purity returns monotonically to the quiet fixed point (T-104 exponential recovery).
        let base = PurityDynamics::new(0.1, 0.5, 0.9, 0.02, N, 0.9);
        let a = empirical_threshold(base, base.survival_bound_gate_open() * 5.0) * 0.8;
        let stressed = settle(base, a, 20_000);
        assert!(stressed.viable(), "survives the flood (below the true threshold)");
        assert!(stressed.purity() < base.steady_state(0.0), "but depressed below the quiet fixed point");

        // Attack stops; the recovery is monotone increasing and reaches the quiet fixed point.
        let mut d = stressed;
        let mut prev = d.purity();
        for _ in 0..50 {
            let now = d.step(0.0);
            assert!(now >= prev - 1e-12, "recovery is monotone");
            prev = now;
        }
        let recovered = settle(d, 0.0, 20_000);
        assert!((recovered.purity() - base.steady_state(0.0)).abs() < 1e-6, "returns to P_ss(0)");
    }

    #[test]
    fn a_stronger_gain_raises_the_survival_threshold() {
        // The homeostat's loop gain κ is its control authority: a larger κ tolerates a larger sustained
        // attack — both in the closed-form bound and (the real check) in the simulated true threshold.
        let weak = PurityDynamics::new(0.1, KAPPA_BOOTSTRAP, 0.9, 0.02, N, 0.6);
        let strong = PurityDynamics::new(0.1, 0.6, 0.9, 0.02, N, 0.6);
        assert!(strong.survival_bound_gate_open() > weak.survival_bound_gate_open());
        let weak_star = empirical_threshold(weak, weak.survival_bound_gate_open() * 2.0);
        let strong_star = empirical_threshold(strong, strong.survival_bound_gate_open() * 2.0);
        assert!(strong_star > weak_star, "stronger gain tolerates a larger attack: {weak_star} → {strong_star}");
    }
}
