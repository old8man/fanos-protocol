//! **How small a cell may be — and why smaller is stronger.**
//!
//! "How many nodes does FANOS need?" was answered here for a long time by reading constants off the
//! implementation: the geometry admits `q ≥ 2` so a cell has seven points, consensus tolerates `f = ⌊(N−1)/3⌋`,
//! the erasure code is `[7,3,4]`. Those are true and they are not an *answer* — they are a list of things that
//! happen to be built. A number worth trusting has to fall out of the dynamics, and then be visible in a
//! simulation that was never told about it.
//!
//! It does. On the equicorrelated stratum (spec §2.7, V15) the two closed forms
//!
//! ```text
//! Φ(N, r) = (N − 1) r²          P(N, r) = (1 + (N − 1) r²) / N = (1 + Φ) / N
//! ```
//!
//! collapse every question about cell size onto one variable, and the answers are sharp.
//!
//! ## What follows
//!
//! **1. Viability and integration are the same condition.** `P > 2/N ⟺ 1 + Φ > 2 ⟺ Φ > 1`. The septicity
//! theorem `P_crit = 2/N` and the integration threshold `Φ_th = 1` are not two requirements a cell must meet
//! but one requirement written twice. See [`viability_is_integration`].
//!
//! **2. The collective-subject window does not depend on `N`.** Its edges in mean correlation do —
//! `(1/√(N−1), √(2/(N−1))]` — but in integration they are the constants `Φ ∈ (1, 2]`, equivalently
//! `P ∈ (2/N, 3/N]`. A cell grows by *diluting* correlation at exactly the rate that holds `Φ` still.
//!
//! **3. Robustness has a ceiling that falls as the cell grows.** The stability radius is
//! `r_stab = √(P − 2/N) = √((Φ − 1)/N)`, and `Φ ≤ 2` caps it at
//!
//! ```text
//! r_stab ≤ 1/√N
//! ```
//!
//! attained only at the top of the window. Since T-104 survives sustained noise `h` iff `h < κ·r_stab`, the
//! disturbance such a cell can absorb is at most `κ/√N` — and with `κ_bootstrap = ω₀/N` it falls as
//! `ω₀·N^(−3/2)`.
//!
//! **This inverts the intuition — and it is conditional, which the first version of this module failed to
//! say.** A larger *compliant* cell is not a sturdier one: the viable band in purity is `(2/N, 3/N]`, of width
//! `1/N`, so it narrows as the cell grows and there is less room between health and the boundary, not more.
//! Seven nodes is not a floor to grow out of; among admissible cells it is the **maximum** of `1/√N`.
//!
//! The condition is `Φ ≤ 2`, i.e. `P ≤ 3/N` — purity that *scales down* with the cell. Hold purity at an
//! absolute level instead and `r_stab = √(P − 2/N)` runs the **other way**, because the subtrahend `2/N`
//! shrinks: at `P = 0.75` the radius climbs from `0.699` at `N = 7` to `0.865` at `N = 993`, and integrating
//! the reduced dynamics there measures a critical attack that *grows* with the cell (`0.725` at `N = 7`,
//! `3.875` at `N = 21`). Both statements are true and they are not the same statement.
//!
//! Only the first describes a cell this platform would keep, and the reason is exact rather than stylistic:
//! `R = 1/(N·P)`, so the self-model floor `R ≥ 1/3` **is** `P ≤ 3/N`. A cell at absolute purity `0.75` has
//! `R = 0.19` on a Fano plane — over-coupled, no longer self-observing, and what the homeostat answers with
//! `Decouple`. See [`tests::the_falling_ceiling_holds_inside_the_band_and_reverses_outside_it`].
//!
//! **4. There is an absolute floor at `N = 3`,** below which no cell is viable for reasons that have nothing to
//! do with FANOS. The window in `r` is `(1/√(N−1), √(2/(N−1))]`, and at `N = 2` its lower edge is `1` — a
//! correlation cannot exceed that, so the window is empty. Two nodes cannot form a collective subject at any
//! coupling whatsoever. See [`MIN_VIABLE_CELL`].
//!
//! ## 5. The band has a setpoint, and it is not its midpoint
//!
//! [`crate::homeostat::Homeostat::control`] returns `Hold` for any correlation inside the collective-subject
//! window, i.e. for any `Φ ∈ (1, 2]`. Result 3 says robustness is not flat there: it varies **3.16×**, from
//! `r_stab = 0.120` at `Φ = 1.1` to `0.378` at `Φ = 2` on a Fano cell. A cell can sit a hair above the collapse
//! boundary, be told it is healthy, and absorb a third of the disturbance it could.
//!
//! The band has two opposite failures, so the robust point maximizes the *smaller* distance — and both
//! distances are available in one metric without inventing anything. `r_stab = √(P − 2/N)` is the Bures
//! distance to the lower boundary, which fixes `ds = dP/(2√(P − 2/N))`; integrating that up to `3/N` gives
//! `d_high = 1/√N − r_stab`. The two therefore **partition the constant `1/√N`**, and the max-min point is
//! where they are equal:
//!
//! ```text
//! r_stab* = 1/(2√N)      ⟺      Φ* = 5/4      ⟺      P* = (9/4)/N
//! ```
//!
//! **Φ = 3/2 is the midpoint and it is wrong** — strictly worse, because the metric is singular at the lower
//! boundary and equal distance in `Φ` is not equal distance in the geometry the theory uses. That is the whole
//! reason to derive it rather than pick it. See [`OPTIMAL_INTEGRATION`].
//!
//! Exposed, not enforced: teaching `control` to steer toward `Φ*` inside the band is a control-law change and
//! is gated on evidence, not on this derivation alone (`docs/open-tasks.md`).
//!
//! ## What this module is not
//!
//! It is not the deployment minimum. Coherence is one of four independent constraints — consensus wants
//! `N ≥ 3f+1`, the erasure code recovers any `≤3` losses on a Fano cell (failing on four exactly when they
//! form a hyperoval), and anonymity wants `N` *large*, since the flow-matching floor is `1/K` in the anonymity
//! set. Anonymity is the one that pulls the other way, and it pulls hard.
//!
//! Federation would resolve it — many small cells, the anonymity set taken at the union — **but the
//! implementation does not support that**: `fanos-aphantos` is parameterized by a single field throughout, so
//! an anonymous circuit cannot leave its cell. Raising `q` is currently the only lever, and it costs
//! robustness as `1/√N`. That argument belongs in `docs/deployment-minima.md`; what belongs here is the half
//! of it that is a theorem.

use crate::coherence::{p_crit, purity_equicorrelated};
use crate::mathfns::sqrt;

/// The smallest cell that can be a collective subject at **any** coupling: `N = 3`.
///
/// Not a FANOS constant. The collective-subject window in mean correlation is `(1/√(N−1), √(2/(N−1))]`, whose
/// lower edge reaches `1` at `N = 2` — and a correlation cannot exceed one, so the window is empty. A pair has
/// no coupling strength at which it integrates without over-coupling; the notion of a two-node collective is
/// not merely weak but unavailable.
///
/// Every other floor in the platform sits above this one, which is why it never binds in practice. It is worth
/// stating because it is the only one that comes from the mathematics rather than from a design choice.
pub const MIN_VIABLE_CELL: usize = 3;

/// The integration window a cell must hold to be a collective subject: `Φ ∈ (1, 2]`.
///
/// Half-open below, closed above, matching [`crate::window::collective_subject_window`]: at `Φ = 1` exactly the
/// cell sits *on* the viability boundary (`P = 2/N`, `r_stab = 0`) and is not viable; at `Φ = 2` it is at the
/// far edge of the window and maximally robust, over-coupling only strictly beyond.
///
/// The constants do not depend on `N`, which is the whole content: the window's edges in correlation move as
/// `N` grows, but only so as to hold this interval fixed.
pub const PHI_WINDOW: (f64, f64) = (1.0, 2.0);

/// The greatest stability radius an `N`-node cell can hold: `1/√N`.
///
/// From `r_stab = √((Φ − 1)/N)` maximized over the admissible window `Φ ≤ 2`. Decreasing in `N`, so this is
/// simultaneously the answer to "how robust can a cell of this size be" and the argument for keeping cells
/// small.
///
/// Returns `0` for a cell below [`MIN_VIABLE_CELL`], where no admissible `Φ` exists at all — rather than the
/// formula's value, which would be a positive number describing a state the cell cannot occupy.
#[must_use]
pub fn max_stability_radius(n: usize) -> f64 {
    if n < MIN_VIABLE_CELL {
        return 0.0;
    }
    1.0 / sqrt(n as f64)
}

/// The greatest sustained disturbance an `N`-node cell can absorb at healing gain `kappa`: `κ/√N`.
///
/// T-104 survival is `h < κ·r_stab`; substituting the ceiling from [`max_stability_radius`] gives the bound a
/// cell cannot exceed at any coupling. A cell operating below the top of the window absorbs strictly less, so
/// this is a *ceiling* on capability and not a rating — sizing against it assumes a perfectly-tuned cell.
#[must_use]
pub fn max_survivable_disturbance(n: usize, kappa: f64) -> f64 {
    kappa * max_stability_radius(n)
}

/// The integration a cell should be **held at**: `Φ* = 5/4`.
///
/// Derived, not chosen. The band has two opposite failures — collapse at `Φ = 1` and loss of the self-model
/// above `Φ = 2` — so the robust operating point maximizes the *smaller* of the two distances. The distances
/// have to be measured in one metric, and there is only one on offer: `r_stab = √(P − 2/N)` is the Bures
/// distance to the lower boundary, which fixes the line element
///
/// ```text
/// ds = dP / (2·√(P − 2/N))
/// ```
///
/// Integrating that from `P` up to the upper boundary `3/N` gives a closed form,
///
/// ```text
/// d_high = √(3/N − 2/N) − √(P − 2/N) = 1/√N − r_stab
/// ```
///
/// so the two distances sum to the constant `1/√N` and `max min(d_low, d_high)` lands where they are equal:
///
/// ```text
/// r_stab* = 1/(2√N)      ⟺      Φ* = 5/4      ⟺      P* = (9/4)/N
/// ```
///
/// **It is not the midpoint of the band.** `Φ = 3/2` would be, and it is wrong: the metric is singular at the
/// lower boundary, so equal distance in `Φ` is not equal distance in the geometry the theory actually uses.
/// A setpoint picked by eye would have landed there.
///
/// # What this is not
///
/// This is the max-min **distance** point, which is well defined and derived. It is *not* established as the
/// optimal place to run a cell, and two things stand in the way — both worth stating rather than glossing:
///
/// * **The lower boundary carries a second penalty that distance does not see.** By [`v_gate_of_integration`]
///   the V-preservation gate is `g_V = Φ − 1` inside the band, so approaching collapse also *throttles
///   regeneration*: at `Φ* = 5/4` healing runs at a quarter authority. A criterion that weighed the throttle
///   as well as the distance would bias the setpoint upward.
/// * **The upper failure has no implemented consequence at all.** Over-coupling is a statement about reflection
///   `R`, and nothing in this tree degrades with it. [`crate::dynamics::PurityDynamics::viable`] tests only
///   `P > 2/N`, so the reduced dynamics cannot fail upward; and the observation path does not depend on
///   correlation either — `fanos_telemetry`'s own note is that "the 3-bit syndrome is exact; the coherence
///   scalars are the model's", the syndrome coming from missed heartbeats. So fault localization is exactly as
///   good at `R = 0.19` as at `R = 0.5`.
///
///   The theory (V19) says a cell above the band loses its self-model, and [`crate::homeostat::Homeostat`]
///   acts on that by decoupling. But **no mechanism here gets worse when it happens**, which means the upper
///   boundary is currently defended without a demonstrated cost — and any max-min setpoint, this one included,
///   inherits that. The first step toward enforcing `Φ*` is therefore not a control experiment but a prior
///   question: *what concretely breaks when `R < 1/3` in this implementation?*
///
/// So: exposed, not enforced. [`crate::homeostat::Homeostat::control`] still returns `Hold` anywhere in the
/// band, and changing that is gated on evidence rather than on this derivation — see `docs/open-tasks.md`.
pub const OPTIMAL_INTEGRATION: f64 = 1.25;

/// The V-preservation gate expressed in the band's own coordinate: `g_V = Φ − 1`.
///
/// `g_V = clamp(N·P − 2, 0, 1)` and `P = (1 + Φ)/N`, so `N·P − 2 = Φ − 1`, which lies in `[0, 1]` exactly over
/// the band and needs no clamping there. Two consequences worth having in one place:
///
/// * `r_stab = √((Φ − 1)/N) = √(g_V/N)` — the stability radius **is** the square root of the regeneration
///   gate, scaled by the cell. Distance to death and authority to heal are one quantity, not two.
/// * A cell near collapse is doubly penalized: it has little room *and* little regeneration, which is the
///   "point of no return without external support" stated as an identity rather than a warning.
#[must_use]
pub fn v_gate_of_integration(phi: f64) -> f64 {
    (phi - 1.0).clamp(0.0, 1.0)
}

/// The purity an `N`-node cell should be held at: `P* = (9/4)/N`.
#[must_use]
pub fn optimal_purity(n: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }
    (1.0 + OPTIMAL_INTEGRATION) / n as f64
}

/// The mean correlation an `N`-node cell should be held at: `r* = √(Φ*/(N−1))`.
#[must_use]
pub fn optimal_correlation(n: usize) -> f64 {
    correlation_for_integration(n, OPTIMAL_INTEGRATION)
}

/// The distance, in the same metric as [`max_stability_radius`], from purity `p` **up** to the over-coupling
/// boundary `3/N`: `1/√N − r_stab`.
///
/// The counterpart to [`crate::stability::stability_radius`], which measures downward to collapse. Together
/// they partition the constant `1/√N`, which is why the band's robustness ceiling and its setpoint come from
/// the same statement.
#[must_use]
pub fn over_coupling_distance(purity: f64, n: usize) -> f64 {
    (max_stability_radius(n) - crate::stability::stability_radius(purity, n)).max(0.0)
}

/// The mean correlation an `N`-node cell must hold to reach integration `phi`: `r = √(Φ/(N−1))`.
///
/// The inverse of `Φ = (N−1)r²`, and the operational form: a cell is steered by its coupling, not by its
/// integration directly. Shows the dilution law plainly — holding `Φ` fixed while `N` grows requires
/// `r ∝ 1/√(N−1)`.
///
/// Returns `0` for `n < 2`, where no inter-node correlation exists to speak of.
#[must_use]
pub fn correlation_for_integration(n: usize, phi: f64) -> f64 {
    if n < 2 || phi <= 0.0 {
        return 0.0;
    }
    sqrt(phi / (n - 1) as f64)
}

/// Whether viability (`P > 2/N`) and integration (`Φ > 1`) agree for `n` nodes at correlation `r`.
///
/// The identity of result 1, evaluated rather than asserted, so a caller can check it against whatever purity
/// it actually measured. It holds identically on the equicorrelated stratum — and knowing *where* it stops
/// holding says what the alarms mean.
///
/// Off the stratum both quantities still come from one matrix: `Φ = off/diag` and `P = diag·(1 + Φ)`, writing
/// `diag = Σγ_ii²` and `off = Σ_{i≠j}γ_ij²`. Since a unit-trace `Γ` has `diag ≥ 1/N` by Cauchy–Schwarz,
/// `Φ > 1 ⟹ P > 2/N` **always** — integration implies viability on every ensemble, which is why
/// [`crate::window::Alarm::Structure`] never fires alone. The converse fails exactly when the diagonal is
/// heterogeneous, and that has a physical name: **coherence has concentrated onto a few nodes**. A cell whose
/// mass sits on one dominant member scores a high `Tr(Γ²)` and near-zero integration.
///
/// So [`crate::window::Alarm::Integration`] is not a weaker structural alarm. It is the platform's
/// **centralization detector**, and the only reading of it that is correct.
#[must_use]
pub fn viability_is_integration(n: usize, r: f64) -> bool {
    if n < 2 {
        return true;
    }
    let phi = (n - 1) as f64 * r * r;
    (purity_equicorrelated(n, r) > p_crit(n)) == (phi > 1.0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::float_cmp)]
mod tests {
    use super::*;
    use crate::coherence::{R_TH, phi_equicorrelated};
    use crate::stability::{stability_radius, survives};
    use crate::window::{Alarm, collective_subject_window, leading_alarm, phi_of_gamma, purity_of_gamma};

    /// The plane orders the platform supports, as node counts.
    const CELLS: [usize; 4] = [7, 21, 57, 993];

    #[test]
    fn viability_and_integration_are_one_condition_on_the_stratum() {
        // Result 1, swept rather than spot-checked: across every supported cell and the whole range of
        // correlation, `P > 2/N` and `Φ > 1` never disagree. Two thresholds from two chapters of the theory,
        // one condition.
        for n in CELLS {
            for i in 0..=1000 {
                let r = i as f64 / 1000.0;
                assert!(
                    viability_is_integration(n, r),
                    "N={n} r={r}: P>2/N and Φ>1 must agree on the equicorrelated stratum"
                );
            }
        }
    }

    #[test]
    fn the_collective_subject_window_is_phi_one_to_two_for_every_cell() {
        // Result 2. The window is defined in correlation and its edges move with `N`; mapped through
        // `Φ = (N−1)r²` they land on the same two numbers every time.
        for n in CELLS {
            let (lo, hi) = collective_subject_window(n);
            assert!(
                (phi_equicorrelated(n, lo) - PHI_WINDOW.0).abs() < 1e-9,
                "N={n}: the lower edge must be Φ=1, got {}",
                phi_equicorrelated(n, lo)
            );
            assert!(
                (phi_equicorrelated(n, hi) - PHI_WINDOW.1).abs() < 1e-9,
                "N={n}: the upper edge must be Φ=2, got {}",
                phi_equicorrelated(n, hi)
            );
        }
    }

    #[test]
    fn robustness_is_capped_at_one_over_root_n_and_the_cap_is_attained() {
        // Result 3, the load-bearing one. Nothing inside the window exceeds `1/√N`, and the top of the window
        // reaches it — so the bound is tight, not merely an upper estimate.
        for n in CELLS {
            let cap = max_stability_radius(n);
            let (lo, hi) = collective_subject_window(n);
            for i in 0..=500 {
                let r = lo + (hi - lo) * (i as f64 / 500.0);
                let radius = stability_radius(purity_equicorrelated(n, r), n);
                assert!(radius <= cap + 1e-12, "N={n} r={r}: r_stab={radius} exceeds the 1/√N cap {cap}");
            }
            let top = stability_radius(purity_equicorrelated(n, hi), n);
            assert!((top - cap).abs() < 1e-9, "N={n}: the window's top must attain 1/√N, got {top} vs {cap}");
        }
    }

    #[test]
    fn a_larger_cell_is_strictly_less_robust() {
        // The inversion of intuition, stated as an order. The viable band in purity is `(2/N, 3/N]`, of width
        // `1/N` — it narrows as the cell grows, so there is *less* room between health and the boundary in a
        // big plane than a small one. This is the argument for federating rather than enlarging.
        for pair in CELLS.windows(2) {
            let (small, large) = (pair[0], pair[1]);
            assert!(
                max_stability_radius(small) > max_stability_radius(large),
                "N={small} must be strictly more robust than N={large}"
            );
        }
        // And the Fano cell is the maximum over everything admissible, not merely over what is implemented.
        for n in MIN_VIABLE_CELL..7 {
            assert!(
                max_stability_radius(n) >= max_stability_radius(7),
                "N={n} would out-rank the Fano cell — the geometry, not coherence, is what forbids it"
            );
        }
    }

    #[test]
    fn two_nodes_cannot_form_a_collective_at_any_coupling() {
        // Result 4. The window's lower edge is `1/√(N−1)`, which at `N=2` is exactly 1 — and a correlation
        // cannot exceed one. Not "weakly coupled": unavailable.
        let (lo, _hi) = collective_subject_window(2);
        assert!(lo >= 1.0, "at N=2 the window must start at or above the maximum possible correlation");
        // Perfect correlation still fails, since the edge is open.
        assert!(phi_equicorrelated(2, 1.0) <= PHI_WINDOW.0, "even r=1 gives only Φ=1, which is the boundary");
        assert_eq!(max_stability_radius(2), 0.0, "a sub-viable cell has no stability radius to report");
        assert!(max_stability_radius(MIN_VIABLE_CELL) > 0.0, "three nodes do have one");
    }

    #[test]
    fn the_survivable_disturbance_falls_as_n_to_the_three_halves() {
        // The corollary, with `κ = ω₀/N` as the bootstrap constant defines it. Sizing a deployment against
        // absorbed disturbance therefore penalizes a big cell twice: once through κ and once through r_stab.
        let omega = 1.0;
        let mut previous = f64::INFINITY;
        for n in CELLS {
            let kappa = omega / n as f64;
            let h = max_survivable_disturbance(n, kappa);
            let predicted = omega * (n as f64).powf(-1.5);
            assert!((h - predicted).abs() < 1e-12, "N={n}: expected ω·N^-3/2 = {predicted}, got {h}");
            assert!(h < previous, "N={n}: absorbed disturbance must fall as the cell grows");
            previous = h;
        }
    }

    #[test]
    fn the_ceiling_agrees_with_the_t104_survival_test() {
        // The bound is derived from `survives`, so it must not merely track it — it must be the exact edge.
        // Just under the ceiling survives; just over does not.
        //
        // The radius here comes the **independent** way — window edge → purity → `stability_radius` — and not
        // from `max_stability_radius`. An earlier version took both from the same function and so agreed with
        // itself whatever the formula said: falsifying the ceiling to `1/N` left this test green. A test that
        // cannot fail is not evidence, and this one was the only check tying the derivation to T-104.
        for n in CELLS {
            let kappa = 0.5;
            let radius = stability_radius(purity_equicorrelated(n, collective_subject_window(n).1), n);
            let ceiling = max_survivable_disturbance(n, kappa);
            assert!((ceiling - kappa * radius).abs() < 1e-12, "N={n}: the derived ceiling must be κ·r_stab");
            assert!(survives(radius, kappa, ceiling * 0.999), "N={n}: just under the ceiling must survive");
            assert!(!survives(radius, kappa, ceiling * 1.001), "N={n}: just over it must not");
        }
    }

    #[test]
    fn the_integration_alarm_is_unreachable_on_the_stratum_and_detects_centralization_off_it() {
        // Result 1 has a consequence for diagnosis. On the equicorrelated stratum `Φ<1 ⟺ P<2/N`, so
        // `leading_alarm`'s `(φ_low, !p_low)` arm cannot be taken: a cell with uniform coupling never reports an
        // integration failure alone.
        for n in CELLS {
            // Both other arms must actually be visited, or "never Integration" would hold vacuously — a sweep
            // that only ever sees healthy cells proves nothing about an alarm it never approaches.
            let (mut healthy, mut structure) = (0u32, 0u32);
            for i in 0..=400 {
                let r = i as f64 / 400.0;
                let gamma = equicorrelated_gamma(n, r);
                match leading_alarm(&gamma, n) {
                    Alarm::Healthy => healthy += 1,
                    Alarm::Structure => structure += 1,
                    Alarm::Integration => {
                        panic!("N={n} r={r}: Integration must be unreachable under uniform coupling")
                    }
                }
            }
            assert!(healthy > 0 && structure > 0, "N={n}: the sweep must cross the boundary, not sit on one side");
        }
        // Off the stratum it is reachable, and what reaches it is *concentration*: put nearly all the coherence
        // mass on one node and leave everything uncorrelated. `Tr(Γ²)` is high — the cell looks structured — and
        // integration is nil. That is a centralized cell, and naming it an integration failure is right.
        let n = 7;
        let mut gamma = vec![0.0; n * n];
        gamma[0] = 0.9;
        for i in 1..n {
            gamma[i * n + i] = 0.1 / (n - 1) as f64;
        }
        assert!(purity_of_gamma(&gamma, n) > p_crit(n), "a concentrated cell scores high purity");
        assert!(phi_of_gamma(&gamma, n) < 1.0, "and no integration at all");
        assert_eq!(leading_alarm(&gamma, n), Alarm::Integration, "which is exactly the Integration alarm");

        // And the direction that holds on every ensemble, not just this one: integration implies viability,
        // since `diag ≥ 1/N` forces `P = diag·(1+Φ) > 2/N` whenever `Φ > 1`. So Structure never fires alone.
        for n in CELLS {
            for i in 0..=200 {
                let r = i as f64 / 200.0;
                let gamma = equicorrelated_gamma(n, r);
                if phi_of_gamma(&gamma, n) > 1.0 {
                    assert!(purity_of_gamma(&gamma, n) > p_crit(n), "N={n} r={r}: Φ>1 must force P>2/N");
                }
            }
        }
    }

    /// The equicorrelated coherence matrix `Γ = (1/N)(I + r(J − I))` — unit trace, the stratum the closed forms
    /// integrate over.
    fn equicorrelated_gamma(n: usize, r: f64) -> Vec<f64> {
        let mut gamma = vec![0.0; n * n];
        for i in 0..n {
            for j in 0..n {
                gamma[i * n + j] = if i == j { 1.0 / n as f64 } else { r / n as f64 };
            }
        }
        gamma
    }

    /// The largest sustained ODE attack a cell still survives, by bisection on the amplitude.
    fn critical_attack(base: crate::dynamics::PurityDynamics) -> f64 {
        let (mut lo, mut hi) = (0.0, 4.0);
        for _ in 0..60 {
            let mid = f64::midpoint(lo, hi);
            let mut d = base;
            for _ in 0..20_000 {
                d.step(mid);
            }
            if d.viable() { lo = mid } else { hi = mid }
        }
        f64::midpoint(lo, hi)
    }

    #[test]
    fn the_falling_ceiling_holds_inside_the_band_and_reverses_outside_it() {
        // The load-bearing qualification, and the one this module first stated without. `r_stab ≤ 1/√N` is a
        // consequence of `Φ ≤ 2`, i.e. of `P ≤ 3/N` — purity that *scales down* with the cell. Hold purity at
        // an absolute level instead and the same formula runs the other way, because `r_stab = √(P − 2/N)` and
        // the subtrahend shrinks. Both are true; only the first describes a cell the homeostat would keep.
        for pair in CELLS.windows(2) {
            let (small, large) = (pair[0], pair[1]);
            // Inside the band: each cell at the top of its own window.
            let inside_small = stability_radius(purity_equicorrelated(small, correlation_for_integration(small, 2.0)), small);
            let inside_large = stability_radius(purity_equicorrelated(large, correlation_for_integration(large, 2.0)), large);
            assert!(inside_small > inside_large, "in-band: N={small} must beat N={large}");
            // Outside it: the same absolute purity for both.
            let fixed = 0.75;
            assert!(
                stability_radius(fixed, small) < stability_radius(fixed, large),
                "at fixed absolute purity the order REVERSES — N={small} vs N={large}"
            );
        }
    }

    #[test]
    fn a_cell_at_fixed_absolute_purity_is_over_coupled_and_not_self_observing() {
        // Why the reversal above is not the operative case. `R = 1/(N·P)`, and the self-model floor is `1/3`,
        // so `R ≥ 1/3 ⟺ P ≤ 3/N` — exactly the top of the window. A cell sitting at an absolute purity of
        // 0.75 has `R = 0.19` on a Fano plane and has *lost its self-model*; the homeostat's answer to it is
        // `Decouple`, not `Hold`.
        //
        // This is worth pinning because the reduced-dynamics module's own tests operate there
        // (`PurityDynamics::new(0.1, 0.5, 0.9, …)` settles at `P ≈ 0.774`), so a measurement taken at that
        // operating point tests the over-coupled regime and not the band.
        for n in CELLS {
            let over = 0.75;
            let reflection = 1.0 / (n as f64 * over);
            assert!(reflection < 1.0 / 3.0, "N={n}: P=0.75 must be over-coupled");
            let top_of_band = 3.0 / n as f64;
            assert!(
                (1.0 / (n as f64 * top_of_band) - 1.0 / 3.0).abs() < 1e-12,
                "N={n}: the self-model floor R=1/3 is exactly P=3/N, the band's top"
            );
        }
    }

    #[test]
    fn the_ode_confirms_the_reversal_outside_the_band() {
        // The empirical counterpart, through an integrator that knows nothing of `minima`: at a fixed
        // absolute operating point the largest survivable sustained attack *grows* with the cell.
        // Measured: 0.725 at N=7, 3.875 at N=21. This is the regime the reversal above predicts, and it is
        // reported here so the qualification is not merely asserted.
        let small = critical_attack(crate::dynamics::PurityDynamics::new(0.1, 0.5, 0.9, 0.05, 7, 0.5));
        let large = critical_attack(crate::dynamics::PurityDynamics::new(0.1, 0.5, 0.9, 0.05, 21, 0.5));
        assert!(
            large > small,
            "outside the band a bigger cell absorbs MORE, not less: N=7 {small}, N=21 {large}"
        );
    }

    #[test]
    fn the_setpoint_maximizes_the_smaller_distance_and_is_not_the_midpoint() {
        // The derivation, checked by brute force rather than trusted. Sweep the band finely, evaluate
        // `min(d_low, d_high)` at each point, and confirm the argmax is `Φ* = 5/4`.
        for n in CELLS {
            let (mut best_phi, mut best) = (0.0, -1.0);
            for i in 1..=100_000u32 {
                let phi = 1.0 + f64::from(i) / 100_000.0; // (1, 2]
                let p = (1.0 + phi) / n as f64;
                let worst = stability_radius(p, n).min(over_coupling_distance(p, n));
                if worst > best {
                    best = worst;
                    best_phi = phi;
                }
            }
            assert!(
                (best_phi - OPTIMAL_INTEGRATION).abs() < 1e-3,
                "N={n}: the max-min setpoint is {best_phi}, expected {OPTIMAL_INTEGRATION}"
            );
            // And explicitly not the midpoint — the claim that makes this a derivation rather than a taste.
            let mid = f64::midpoint(PHI_WINDOW.0, PHI_WINDOW.1);
            let at_mid = {
                let p = (1.0 + mid) / n as f64;
                stability_radius(p, n).min(over_coupling_distance(p, n))
            };
            assert!(at_mid < best, "N={n}: the midpoint Φ=1.5 must be strictly worse than Φ*");
        }
    }

    #[test]
    fn the_regeneration_gate_is_the_excess_integration() {
        // `g_V = clamp(N·P − 2, 0, 1)` and `P = (1+Φ)/N`, so inside the band `g_V = Φ − 1` exactly — and
        // therefore `r_stab = √(g_V/N)`. Checked against the real gate, not re-derived from the same algebra.
        for n in CELLS {
            for i in 0..=1000u32 {
                let phi = 1.0 + f64::from(i) / 1000.0;
                let p = (1.0 + phi) / n as f64;
                let gate = crate::stability::v_preservation_gate(p, n);
                assert!(
                    (gate - v_gate_of_integration(phi)).abs() < 1e-12,
                    "N={n} Φ={phi}: g_V must equal Φ−1, got {gate}"
                );
                assert!(
                    (stability_radius(p, n) - sqrt(gate / n as f64)).abs() < 1e-12,
                    "N={n} Φ={phi}: r_stab must equal √(g_V/N)"
                );
            }
            // The cost the max-min setpoint pays, stated as a number: a quarter of full healing authority.
            assert!(
                (v_gate_of_integration(OPTIMAL_INTEGRATION) - 0.25).abs() < 1e-12,
                "the setpoint runs regeneration at quarter authority — the reason it is not claimed optimal"
            );
        }
    }

    #[test]
    fn the_reduced_dynamics_cannot_fail_upward() {
        // Why the setpoint cannot be validated by the ODE. `viable()` tests `P > 2/N` and nothing else, so an
        // arbitrarily over-coupled cell — one that has lost its self-model entirely — is reported viable. Any
        // experiment run there will prefer more integration without bound, which is not an answer to a
        // trade-off whose other side it does not represent.
        let over = crate::dynamics::PurityDynamics::new(0.1, 0.5, 0.99, 0.05, 7, 0.99);
        assert!(over.viable(), "a cell at P≈0.99 is 'viable' to the ODE …");
        // Read from the object rather than the literal, so this measures the cell the ODE actually built.
        let reflection = 1.0 / (7.0 * over.purity());
        assert!(reflection < R_TH, "… while its reflection {reflection} is far below the self-model floor {R_TH}");
    }

    #[test]
    fn the_two_distances_partition_the_robustness_ceiling() {
        // `d_low + d_high = 1/√N` identically across the band — the identity the setpoint rests on. If this
        // failed, the closed form for `d_high` would be wrong and `Φ*` with it.
        for n in CELLS {
            for i in 0..=1000u32 {
                let phi = 1.0 + f64::from(i) / 1000.0;
                let p = (1.0 + phi) / n as f64;
                let sum = stability_radius(p, n) + over_coupling_distance(p, n);
                assert!(
                    (sum - max_stability_radius(n)).abs() < 1e-12,
                    "N={n} Φ={phi}: the distances must sum to 1/√N, got {sum}"
                );
            }
        }
    }

    #[test]
    fn the_setpoint_is_consistent_across_its_three_forms() {
        // Φ*, P* and r* must describe one state, or a caller steering by correlation would aim somewhere the
        // caller reading purity does not.
        for n in CELLS {
            let p = optimal_purity(n);
            let r = optimal_correlation(n);
            assert!((phi_equicorrelated(n, r) - OPTIMAL_INTEGRATION).abs() < 1e-9, "N={n}: r* ↦ Φ*");
            assert!((purity_equicorrelated(n, r) - p).abs() < 1e-12, "N={n}: r* ↦ P*");
            assert!(
                (stability_radius(p, n) - 1.0 / (2.0 * sqrt(n as f64))).abs() < 1e-12,
                "N={n}: the setpoint sits at exactly half the robustness ceiling"
            );
            // It is inside the band the homeostat enforces, which it must be to be reachable by `Hold`.
            let (lo, hi) = collective_subject_window(n);
            assert!(r > lo && r <= hi, "N={n}: r*={r} must lie in ({lo}, {hi}]");
        }
    }

    #[test]
    fn the_dilution_law_inverts_the_integration_formula() {
        // `correlation_for_integration` is the operational direction — a cell is steered by coupling. It must
        // round-trip exactly, or the steering acts on a different quantity than the one being read.
        for n in CELLS {
            for phi in [1.0, 1.5, 2.0] {
                let r = correlation_for_integration(n, phi);
                assert!((phi_equicorrelated(n, r) - phi).abs() < 1e-9, "N={n} Φ={phi}: round-trip failed");
            }
            // Holding Φ fixed while N grows dilutes correlation as 1/√(N−1).
            assert!(
                correlation_for_integration(n, 2.0) < correlation_for_integration(MIN_VIABLE_CELL, 2.0),
                "N={n}: a bigger cell must need weaker coupling to hold the same integration"
            );
        }
    }
}
