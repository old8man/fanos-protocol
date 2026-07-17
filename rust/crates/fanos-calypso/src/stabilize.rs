//! Lindbladian DDoS stabilization for hidden-service admission (spec §12.5, grounded in §6.7).
//!
//! Tor has fought hidden-service DoS for years with bolt-on filters. FANOS is instead a
//! **self-observing dissipative system**: the rendezvous line's load is a mode of an open system
//! whose healthy operating point is a steady state `ρ*`, and a flood is a *perturbation* driving it
//! away. The natural, formally-grounded response is the one an open quantum system makes under a
//! Lindblad master equation `dρ/dt = −i[H,ρ] + Σ_k(L_k ρ L_k† − ½{L_k†L_k, ρ})`: the dissipative
//! (jump) terms relax the excited mode back toward `ρ*` at the dynamics' spectral gap `Δ`
//! (the same `Δ` that sets the DIAKRISIS reintegration time `τ = 1/Δ`, §6.7 / T-226(v)).
//!
//! [`LindbladLoadController`] is that relaxation, in its classical single-mode limit — a leaky
//! integrator. Let `xₙ ≥ 0` be the **excitation** (admission demand above the sustainable target).
//! Each window it **relaxes then is driven**:
//!
//! ```text
//! x_{n+1} = (1 − Δ)·xₙ + max(0, arrivedₙ − target)
//! ```
//!
//! and the required admission work is **super-linear** in the excitation,
//! `difficulty = floor + gain·(x/target)²`, capped at `ceil`. Two formal consequences, both tested:
//!
//! * **Stability (no runaway).** For any *bounded* arrival rate `arrived = C·target` the excitation
//!   converges geometrically to the finite fixed point `x* = (C−1)·target / Δ`; once the flood stops
//!   (`arrived = 0`) the excitation decays as `xₙ = (1−Δ)ⁿ x₀ → 0`, so difficulty relaxes back to the
//!   `floor`. The line always returns to `ρ*` — a spectral-gap argument, not a heuristic.
//! * **Attacker penalty (super-linear cost).** Because cost grows with `x²` and `x` grows linearly
//!   in the overload `C`, a flooder sustaining rate `C·target` pays per-request work `∝ C²`, hence
//!   **aggregate work `∝ C³`** — it diverges super-linearly in the attack intensity, while a
//!   cooperative client at the target pays the `floor`. Sustained flooding is thus self-defeating:
//!   the attacker's cost curve is steeper than its load curve.
//!
//! Malformed floods (invalid intros) are a *different* attack and are handled structurally: they
//! violate the line's free polar sum-rules and are localized and quarantined (spec §6.2, T-226) —
//! the same mechanism that catches a Byzantine liar. This controller governs *valid-but-excessive*
//! demand, where the only fair response is to price it.
//!
//! **`Δ` is derived, not tuned.** [`LindbladLoadController::from_line_rates`] computes the relaxation
//! rate from the cell's own dissipative **spectral gap** `Δ = (G − max_k T_k)/6` (T-226(v), the exact
//! gap `fanos_diakrisis::regeneration::spectral_gap` reads from the seven line rates), so admission
//! relaxation and the DIAKRISIS reintegration time `τ = 1/Δ` are two observables of **one** spectral
//! gap — the *derive-don't-tune* invariant, closed. [`Self::new`] with an explicit `Δ` remains for
//! tests and analytic sizing.

use fanos_diakrisis::regeneration::spectral_gap;
use fanos_geometry::fano;

/// The per-window dissipation derived from a cell's dissipative spectral gap `Δ_cont` over a window
/// of `dt_window` (in the same time unit as the line rates): the small-step discretization
/// `Δ_cont · dt_window` (the linearization of `1 − e^{−Δ_cont·dt}`), clamped to `(0, 1]`. Exposed for
/// transparency and testing; [`LindbladLoadController::from_line_rates`] uses it.
#[must_use]
pub fn dissipation_from_gap(line_rates: &[f64; fano::N], dt_window: f64) -> f64 {
    (spectral_gap(line_rates).max(0.0) * dt_window.max(0.0)).clamp(1e-3, 1.0)
}

/// A Lindbladian (leaky-integrator) admission controller: excitation relaxes at rate `Δ` while load
/// drives it up, and admission difficulty is a super-linear function of the excitation. Pure state
/// machine — the driver counts arrivals per window and calls [`observe_window`](Self::observe_window);
/// [`difficulty`](Self::difficulty) is what the line broadcasts and gates on.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct LindbladLoadController {
    excitation: f64,
    dissipation: f64,
    target: f64,
    floor: u32,
    ceil: u32,
    /// Excitation-ratio `x/target` at which difficulty reaches the ceiling (a "severe" overload).
    over_ceil: f64,
}

/// The default overload ratio (`x/target`) at which admission difficulty saturates at the ceiling —
/// i.e. difficulty hits `ceil` once excitation is `10 × target`, a severe sustained flood.
const DEFAULT_OVER_CEIL: f64 = 10.0;

impl LindbladLoadController {
    /// A controller with dissipation (spectral gap) `dissipation ∈ (0, 1]`, a sustainable
    /// `target` intros per window, and difficulty bounds `[floor, ceil]`. Difficulty reaches the
    /// ceiling once the excitation is [`DEFAULT_OVER_CEIL`]`× target`. Degenerate inputs are clamped.
    #[must_use]
    pub fn new(dissipation: f64, target: f64, floor: u32, ceil: u32) -> Self {
        let ceil = ceil.max(floor);
        Self {
            excitation: 0.0,
            dissipation: dissipation.clamp(1e-3, 1.0),
            target: target.max(1.0),
            floor,
            ceil,
            over_ceil: DEFAULT_OVER_CEIL,
        }
    }

    /// A controller whose relaxation rate is **derived from the cell's own dissipative spectral gap**
    /// (T-226(v)) rather than tuned: `Δ = (G − max_k T_k)/6` from the line's seven `line_rates`,
    /// discretized over `dt_window` (see [`dissipation_from_gap`]). This is the network-grounded
    /// constructor — the admission relaxation and the healing time `τ = 1/Δ` then share one gap. A
    /// cell whose flux concentrates on one axis (`max_k T_k` large relative to the total `G`) has a
    /// smaller `Δ`, slower relaxation, and a *larger* steady-state excitation, so a structurally
    /// stressed cell prices admission more conservatively — automatically, with no hand-tuning.
    #[must_use]
    pub fn from_line_rates(
        line_rates: &[f64; fano::N],
        dt_window: f64,
        target: f64,
        floor: u32,
        ceil: u32,
    ) -> Self {
        Self::new(
            dissipation_from_gap(line_rates, dt_window),
            target,
            floor,
            ceil,
        )
    }

    /// Fold in a completed window's `arrived` intro count: relax the excitation by the dissipation
    /// rate, then drive it by the demand above target (the Lindblad leaky-integrator step).
    pub fn observe_window(&mut self, arrived: f64) {
        let surplus = (arrived - self.target).max(0.0);
        self.excitation = (1.0 - self.dissipation) * self.excitation + surplus;
    }

    /// The current excitation `x` (admission demand above the sustainable target, relaxed).
    #[must_use]
    pub fn excitation(self) -> f64 {
        self.excitation
    }

    /// The admission difficulty to broadcast and require now: `floor + gain·(x/target)²`, capped at
    /// `ceil`. Super-linear in the excitation, so a flooder's per-request cost grows with the square
    /// of the overload.
    #[must_use]
    pub fn difficulty(self) -> u32 {
        let over = self.excitation / self.target;
        // Normalized quadratic: 0 at the target, 1 at `over_ceil × target`, capped.
        let frac = ((over / self.over_ceil) * (over / self.over_ceil)).clamp(0.0, 1.0);
        let raw = f64::from(self.floor) + f64::from(self.ceil - self.floor) * frac;
        let clamped = raw.clamp(f64::from(self.floor), f64::from(self.ceil));
        clamped as u32
    }

    /// The steady-state excitation the controller relaxes to under a *sustained* arrival rate of
    /// `overload · target` intros per window: `x* = (overload − 1)·target / Δ`. A closed form of the
    /// fixed point `x* = (1−Δ)x* + (overload−1)target`, exposed so an operator can size `Δ` and the
    /// bounds analytically.
    #[must_use]
    pub fn steady_state_excitation(&self, overload: f64) -> f64 {
        (overload - 1.0).max(0.0) * self.target / self.dissipation
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol * b.abs().max(1.0)
    }

    #[test]
    fn a_sustained_flood_converges_to_a_bounded_fixed_point() {
        // Δ = 0.25, target = 100, flood at 6× target → excitation → (6−1)·100/0.25 = 2000 (over = 20,
        // past the over_ceil of 10), so difficulty saturates at the ceiling.
        let mut c = LindbladLoadController::new(0.25, 100.0, 8, 24);
        for _ in 0..500 {
            c.observe_window(600.0);
        }
        assert!(
            approx(c.excitation(), c.steady_state_excitation(6.0), 1e-6),
            "excitation converges to the analytic fixed point, got {}",
            c.excitation()
        );
        assert_eq!(
            c.difficulty(),
            24,
            "a heavy sustained flood pins difficulty at the ceiling"
        );
    }

    #[test]
    fn the_line_relaxes_back_after_the_flood_stops() {
        let mut c = LindbladLoadController::new(0.25, 100.0, 8, 24);
        for _ in 0..200 {
            c.observe_window(500.0); // heavy flood
        }
        assert!(
            c.difficulty() > 8,
            "difficulty is elevated during the flood"
        );
        // Attack stops: excitation decays geometrically to 0, difficulty returns to the floor.
        for _ in 0..200 {
            c.observe_window(0.0);
        }
        assert!(
            approx(c.excitation(), 0.0, 1e-6),
            "excitation relaxes to zero"
        );
        assert_eq!(c.difficulty(), 8, "difficulty relaxes back to the floor");
    }

    #[test]
    fn a_cooperative_client_pays_the_floor() {
        // Load at or below target never excites the mode → floor difficulty throughout.
        let mut c = LindbladLoadController::new(0.3, 100.0, 6, 30);
        for _ in 0..100 {
            c.observe_window(90.0);
        }
        assert_eq!(c.excitation(), 0.0);
        assert_eq!(c.difficulty(), 6);
    }

    #[test]
    fn cost_is_super_linear_in_the_overload() {
        // Per-request difficulty grows with the SQUARE of the overload, so doubling the attack's
        // rate more than doubles its per-request cost above the floor — the attacker's cost curve
        // is steeper than its load curve.
        let floor = 4;
        let make = |overload: f64| {
            let mut c = LindbladLoadController::new(0.5, 100.0, floor, 100_000);
            let x = c.steady_state_excitation(overload);
            // Drive straight to the fixed point to read the difficulty there.
            for _ in 0..2000 {
                c.observe_window(overload * 100.0);
            }
            assert!((c.excitation() - x).abs() < 1.0);
            f64::from(c.difficulty() - floor)
        };
        let d2 = make(2.0);
        let d3 = make(3.0);
        // Excess cost scales as (overload−1)²: (3−1)²/(2−1)² = 4×.
        assert!(
            d3 > 3.5 * d2 && d3 < 4.5 * d2,
            "3× overload costs ~4× the excess of 2× overload: {d2} → {d3}"
        );
    }

    #[test]
    fn dissipation_is_derived_from_the_cell_spectral_gap_not_tuned() {
        // T-226(v): uniform line rates γ̄ ⇒ Δ = (2/3)·γ̄. Over a unit window the derived dissipation
        // is that exact gap (clamped) — the controller's relaxation is the CELL's own, not tuned.
        let gamma_bar = 0.9;
        let rates = [gamma_bar; fano::N];
        let d = dissipation_from_gap(&rates, 1.0);
        assert!(
            (d - (2.0 / 3.0) * gamma_bar).abs() < 1e-9,
            "Δ = (2/3)·γ̄, got {d}"
        );

        let c = LindbladLoadController::from_line_rates(&rates, 1.0, 100.0, 4, 24);
        // Steady state under a 2× flood uses the DERIVED Δ: x* = (2−1)·target/Δ = 100/Δ.
        assert!((c.steady_state_excitation(2.0) - 100.0 / d).abs() < 1e-6);

        // A cell with a SMALLER gap (slower dissipative dynamics) prices admission more
        // conservatively — larger steady-state excitation — automatically, no hand-tuning.
        let fast = LindbladLoadController::from_line_rates(&[0.9; fano::N], 1.0, 100.0, 4, 24); // Δ=0.6
        let slow = LindbladLoadController::from_line_rates(&[0.3; fano::N], 1.0, 100.0, 4, 24); // Δ=0.2
        assert!(slow.steady_state_excitation(2.0) > fast.steady_state_excitation(2.0));

        // A large gap saturates the discretized dissipation at 1.0 (immediate relaxation).
        assert!((dissipation_from_gap(&[2.0; fano::N], 1.0) - 1.0).abs() < 1e-12);
    }
}
