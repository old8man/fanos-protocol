//! The coherence homeostat — the `h^(D)`-channel DDoS-stabilization controller (corpus T-104).
//!
//! [`plan`](crate::plan) reacts to a discrete fault [`Verdict`](crate::Verdict); this module governs the
//! *continuous* self-model under a sustained perturbation. A multi-target DDoS is the canonical
//! **decoherence (`h^(D)`) noise attack** on the cell's coherence matrix `Γ_net` (it destroys the cell's
//! own correlation structure — see `docs/ddos-homeostasis.md`), and the corpus stability theory gives the
//! response directly:
//!
//! * **Viability speedometer** — the stability radius `r_stab = √(P − 2/N)` (T-104): the Bures distance
//!   from the healthy attractor `ρ*` to the viability boundary `P = 2/N`. Zero at collapse.
//! * **Guaranteed return** — with Lyapunov `V = ‖Γ − ρ*‖²`, T-104 gives `√V' ≤ −κ√V + ‖h‖`, so the
//!   excursion contracts to the ball `‖h‖/κ` and, once the attack abates, decays as `(1−κ)` per step. The
//!   rate `κ ≥ κ_bootstrap = 1/7 > 0` in *every* state (T-59), so the pull toward health never vanishes.
//! * **Survival threshold** — a cell absorbs the flood and stays viable iff the aggregate noise obeys the
//!   canonical `‖δΓ₂‖ < κ_bootstrap/2 = 1/14` ([`NOISE_SURVIVAL_THRESHOLD`], T-104 §6.1).
//! * **Band-keeping control law** — act only *outside* the collective-subject band, and only in the
//!   direction that lowers `V`: [`BandControl::Decouple`] a common-mode over-coupling, [`BandControl::Bind`]
//!   a differential disintegration, [`BandControl::Escalate`] a collapse the cell cannot self-heal
//!   (`P ≤ 2/N`, where the V-preservation gate `g_V = 0` and external help is required).
//!
//! **Symmetric by design (no forced analogy).** FANOS's cell is `N` *exchangeable* Fano nodes, so this
//! homeostat uses only the *permutation-symmetric* invariants `Γ` admits — `P`, `Φ`, `R`, the mean
//! correlation `r`, and `r_stab`. The corpus's *asymmetric* seven-sector stress tensor `σ_sys` (A,S,D,L,E,
//! O,U) is defined for a **holon with distinct cognitive sectors** — a future SYNARC *agent*, not a symmetric
//! network cell — so it is deliberately **not** imposed on the peer nodes here. See `synarc-node-architecture`.
//!
//! **Self-sufficient, evolvable.** The law is a complete deterministic reflex today. The only policy input
//! is the loop gain `κ`, clamped to `[κ_bootstrap, 1]` — a future SYNARC module may tune it *within that
//! clamp* to reshape the approach to the attractor, but can never move the attractor, leave the band, or
//! break the T-104 contraction. Learning lives strictly inside the proven envelope.

use crate::coherence::p_crit;
use crate::healing::KAPPA_BOOTSTRAP;
use crate::mathfns::sqrt;
use crate::window::{CollectiveState, classify_collective, collective_subject_window};

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

/// One corrective decision of the coherence homeostat — the `act` phase for the continuous self-model.
/// Every non-[`Hold`](BandControl::Hold) action moves `Γ` toward `ρ*`, i.e. lowers the Lyapunov `V`.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum BandControl {
    /// In-band healthy subject (`r ∈ (r*, r_over]`, `Φ ≥ 1 ∧ R ≥ 1/3`): do nothing. Band-keeping never
    /// treats a healthy cell — shedding correlation from a legitimate subject is forbidden.
    Hold,
    /// Over-coupled (`r > r_over`, `R < 1/3` — a common-mode flood driving the cell into groupthink): shed
    /// synchronisation with `effort ∈ (0, 1]`. This *lowers* `Φ = (N−1)r²` and `r` back into the band and
    /// restores `R ≥ 1/3`. Effort is proportional to the over-excursion and capped so it never drives `r`
    /// below the band.
    Decouple {
        /// The fraction of excess correlation to shed this step.
        effort: f64,
    },
    /// Viable but disintegrating (`P > 2/N` yet `r < r*` — a differential flood pulling the cell toward a
    /// mere aggregate): regenerate toward `ρ*` / reroute onto co-linear survivors, with the given
    /// `authority = κ·g_V(P) ∈ [0, 1]`. The rate `κ ≥ κ_bootstrap` is guaranteed (T-59), gated by `g_V`.
    Bind {
        /// The effective regeneration authority this step (`κ·g_V`).
        authority: f64,
    },
    /// Collapsed (`P ≤ 2/N`): the V-preservation gate is `0`, self-recovery is impossible, and the cell
    /// hands the residue to its parent for external regeneration `h^(R)` (the corpus recovery protocol —
    /// "one cannot climb out of a fully-collapsed cell from inside it").
    Escalate,
}

/// The coherence homeostat: a deterministic band-keeping controller parameterised only by its loop gain.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Homeostat {
    /// Loop gain / guaranteed regeneration rate, clamped to `[κ_bootstrap, 1]`.
    kappa: f64,
}

impl Homeostat {
    /// A homeostat with loop gain `gain`, clamped to `[κ_bootstrap, 1]`: the lower clamp keeps the T-59
    /// authority floor, and the upper clamp keeps the discrete contraction stable (`1 − κ ≥ 0`).
    #[must_use]
    pub fn new(gain: f64) -> Self {
        Self {
            kappa: gain.clamp(KAPPA_BOOTSTRAP, 1.0),
        }
    }

    /// The conservative homeostat using only the guaranteed `κ_bootstrap = 1/7` authority — relying on no
    /// adaptive `Coh_E`, so it is valid in *every* state. The always-safe default.
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            kappa: KAPPA_BOOTSTRAP,
        }
    }

    /// The loop gain `κ` (already clamped to `[κ_bootstrap, 1]`).
    #[must_use]
    pub fn gain(self) -> f64 {
        self.kappa
    }

    /// The band-keeping control decision from the cell's purity `P` and mean inter-node correlation `r`
    /// (T-104 §6). Escalate if collapsed (`P ≤ 2/N`, gate closed); otherwise hold inside the band, decouple
    /// above it, or bind below it. This is gradient descent on `V = ‖Γ − ρ*‖²`: the action always points
    /// toward the attractor, so the closed loop inherits the T-104 contraction.
    ///
    /// Purity is checked *first* (the viability gate), then the direction is set by the correlation band —
    /// so the decision is correct even off the equicorrelated stratum, where `P` and `r` decouple.
    #[must_use]
    pub fn control(self, purity: f64, mean_r: f64, n: usize) -> BandControl {
        // Below viability the V-preservation gate is zero: no amount of rate `κ` regenerates, external help
        // is required (T-104 §5, the "point of no return without external support").
        if purity <= p_crit(n) {
            return BandControl::Escalate;
        }
        let (_, hi) = collective_subject_window(n);
        match classify_collective(mean_r, n) {
            CollectiveState::CollectiveSubject => BandControl::Hold,
            CollectiveState::OverCoupled => {
                // Proportional shed: effort ∝ over-excursion, scaled by gain, capped at 1 (cannot shed more
                // correlation than exists). Never negative, so it cannot push `r` below the band.
                let effort = (self.kappa * (mean_r - hi) / hi).clamp(0.0, 1.0);
                BandControl::Decouple { effort }
            }
            CollectiveState::Aggregate => {
                // Guaranteed rate κ ≥ κ_bootstrap (T-59), gated by g_V(P): near the boundary the gate is
                // small (regeneration is nearly off — faithful to the master equation), far above it the
                // full rate applies.
                let authority = (self.kappa * v_preservation_gate(purity, n)).clamp(0.0, 1.0);
                BandControl::Bind { authority }
            }
        }
    }
}

impl Default for Homeostat {
    /// The conservative homeostat (guaranteed `κ_bootstrap` authority).
    fn default() -> Self {
        Self::conservative()
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;
    use crate::coherence::{phi_equicorrelated, purity_equicorrelated};

    const N: usize = 7;

    #[test]
    fn stability_radius_matches_t104() {
        // r_stab = √(P − 2/7): zero at the boundary, √(1/7) at the band's upper edge P = 3/7.
        assert!(stability_radius(2.0 / 7.0, N).abs() < 1e-12, "zero at collapse");
        assert!(stability_radius(0.2, N).abs() < 1e-12, "clamped to zero below the boundary");
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
        assert!((e - want).abs() < 1e-9, "converged to h/κ = {want}, got {e}");
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
        assert!((NOISE_SURVIVAL_THRESHOLD - 1.0 / 14.0).abs() < 1e-12, "h^(D) bound is 1/14");
        // A cell at the boundary (r_stab = 0) survives no perturbation at all.
        assert!(!survives(0.0, 1.0, 1e-9));
    }

    #[test]
    fn a_healthy_in_band_cell_is_left_alone() {
        // r = 0.5 ∈ (1/√6, 1/√3]; equicorrelated P there is well above 3/7 → viable, in-band → Hold.
        let r = 0.5;
        let p = purity_equicorrelated(N, r);
        assert!(phi_equicorrelated(N, r) >= 1.0, "integrated");
        assert_eq!(Homeostat::conservative().control(p, r, N), BandControl::Hold);
    }

    #[test]
    fn a_common_mode_flood_decouples() {
        // r = 0.7 > 1/√3 ≈ 0.577: over-coupled (groupthink). Viable (equicorrelated P ≈ 0.56 > 2/7), so it
        // sheds correlation rather than escalating. Effort is positive and ≤ 1.
        let r = 0.7;
        let p = purity_equicorrelated(N, r);
        match Homeostat::new(0.5).control(p, r, N) {
            BandControl::Decouple { effort } => {
                assert!(effort > 0.0 && effort <= 1.0, "proportional shed effort, got {effort}");
            }
            other => panic!("expected Decouple, got {other:?}"),
        }
    }

    #[test]
    fn a_differential_disintegration_binds_when_still_viable() {
        // Off-stratum: purity still viable (P = 0.35 > 2/7) but mean correlation collapsed (r = 0.30 < r*).
        // The cell regenerates (Bind) with authority κ·g_V, bounded and positive.
        let p = 0.35;
        let r = 0.30;
        match Homeostat::new(0.5).control(p, r, N) {
            BandControl::Bind { authority } => {
                let want = 0.5 * v_preservation_gate(p, N);
                assert!((authority - want).abs() < 1e-12, "authority = κ·g_V");
                assert!(authority > 0.0 && authority <= 1.0);
            }
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[test]
    fn a_collapsed_cell_escalates_regardless_of_correlation() {
        // P ≤ 2/7 ⇒ g_V = 0 ⇒ no self-recovery ⇒ Escalate, whatever r is.
        assert_eq!(Homeostat::conservative().control(0.25, 0.5, N), BandControl::Escalate);
        assert_eq!(Homeostat::conservative().control(0.25, 0.05, N), BandControl::Escalate);
        assert_eq!(Homeostat::conservative().control(2.0 / 7.0, 0.5, N), BandControl::Escalate);
    }

    #[test]
    fn the_policy_gain_is_clamped_into_the_proven_envelope() {
        // A future SYNARC policy can only tune κ within [κ_bootstrap, 1] — never below the floor (would
        // lose the guaranteed authority) nor above 1 (would break the discrete contraction).
        assert_eq!(Homeostat::new(5.0).gain(), 1.0);
        assert_eq!(Homeostat::new(-1.0).gain(), KAPPA_BOOTSTRAP);
        assert_eq!(Homeostat::new(0.01).gain(), KAPPA_BOOTSTRAP);
        assert_eq!(Homeostat::conservative().gain(), KAPPA_BOOTSTRAP);
        assert_eq!(Homeostat::default().gain(), KAPPA_BOOTSTRAP);
    }
}
