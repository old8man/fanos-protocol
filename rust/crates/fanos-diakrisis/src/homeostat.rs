//! The coherence homeostat — the `h^(D)`-channel DDoS-stabilization controller (corpus T-104).
//!
//! This is the **act** half of DDoS homeostasis; the *measured* T-104 quantities it acts on live in
//! [`stability`](crate::stability) (the sense half). [`plan`](crate::plan) reacts to a discrete fault
//! [`Verdict`](crate::Verdict); this module governs the *continuous* self-model under a sustained
//! perturbation. A multi-target DDoS is the canonical **decoherence (`h^(D)`) noise attack** on the cell's
//! coherence matrix `Γ_net` (it destroys the cell's own correlation structure — see
//! `docs/ddos-homeostasis.md`), and the corpus stability theory gives the response directly:
//!
//! * **Guaranteed return.** With Lyapunov `V = ‖Γ − ρ*‖²`, T-104 gives `√V' ≤ −κ√V + ‖h‖`, so the excursion
//!   contracts to the ball `‖h‖/κ` and, once the attack abates, decays as `(1−κ)` per step. The rate
//!   `κ ≥ κ_bootstrap = 1/7 > 0` in *every* state (T-59), so the pull toward health never vanishes.
//! * **Survival threshold.** A cell absorbs the flood and stays viable iff the aggregate noise obeys the
//!   canonical `‖δΓ₂‖ < κ_bootstrap/2 = 1/14` (`stability::NOISE_SURVIVAL_THRESHOLD`).
//! * **Band-keeping control law.** Act only *outside* the collective-subject band, and only in the
//!   direction that lowers `V`: [`BandControl::Decouple`] a common-mode over-coupling, [`BandControl::Bind`]
//!   a differential disintegration, [`BandControl::Escalate`] a collapse the cell cannot self-heal
//!   (`P ≤ 2/N`, where the V-preservation gate `g_V = 0` and external help is required).
//!
//! **Symmetric by design (no forced analogy).** FANOS's cell is `N` *exchangeable* Fano nodes, so this
//! controller uses only the *permutation-symmetric* invariants `Γ` admits — `P`, `Φ`, `R`, the mean
//! correlation `r`. The corpus's *asymmetric* seven-sector stress tensor `σ_sys` (A,S,D,L,E,O,U) is defined
//! for a **holon with distinct cognitive sectors** — a future SYNARC *agent*, not a symmetric network cell —
//! so it is deliberately **not** imposed on the peer nodes here. See `synarc-node-architecture`.
//!
//! **Self-sufficient, evolvable.** The law is a complete deterministic reflex today. The only policy input
//! is the loop gain `κ`, clamped to `[κ_bootstrap, 1]` — a future SYNARC module may tune it *within that
//! clamp* to reshape the approach to the attractor, but can never move the attractor, leave the band, or
//! break the T-104 contraction. Learning lives strictly inside the proven envelope.

use crate::coherence::{R_TH, p_crit};
use crate::healing::KAPPA_BOOTSTRAP;
use crate::stability::v_preservation_gate;
use crate::window::{CollectiveState, classify_collective};

/// One corrective decision of the coherence homeostat — the `act` phase for the continuous self-model.
/// Every non-[`Hold`](BandControl::Hold) action moves `Γ` toward `ρ*`, i.e. lowers the Lyapunov `V`. The
/// controller *decides*; applying the action is the actuator's responsibility (dependency inversion — the
/// homeostat does not depend on how a decouple/reroute is carried out).
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
    ///
    /// **The band's edges come from `diagonal_purity` = `p = Σᵢ dᵢ²`, not from `n`** (UHM T-312/T-314). The
    /// two purities are different quantities and both are needed: `purity` is `P = Tr(Γ²)`, the viability
    /// gate, while `p` is the concentration of behavioural weight, which is what moves the phase line. They
    /// are related — `P = p·(1 + Φ)` — so one cannot substitute for the other. Passing `1.0 / n` recovers
    /// the flat-stratum behaviour exactly, which is what
    /// [`CoherenceMatrix::equicorrelated`](crate::CoherenceMatrix::equicorrelated) produces.
    #[must_use]
    pub fn control(self, purity: f64, mean_r: f64, diagonal_purity: f64, n: usize) -> BandControl {
        // **The two purities are not independent, and the signature cannot say so** (#272). `Measures`
        // computes `P = p·(1 + Φ)` with `Φ ≥ 0`, so `P ≥ p` always and `p = 0` forces `P = 0`. Taking them
        // as two free floats makes an impossible pair expressible, and this function would answer one
        // confidently: a zero diagonal beside a purity above the gate reaches the band's `(∞, ∞)`
        // fallthrough and prescribes `Bind` — more coupling for a cell with no carriers. Unreachable
        // through `Measures`, and stated here rather than trusted, because the caller is what changes.
        debug_assert!(
            purity + 1e-12 >= diagonal_purity && (diagonal_purity > 0.0 || purity <= 1e-12),
            "purity {purity} and diagonal purity {diagonal_purity} cannot both come from one matrix: \
             P = p·(1 + Φ) with Φ ≥ 0 (#272)"
        );
        // Below viability the V-preservation gate is zero: no amount of rate `κ` regenerates, external help
        // is required (T-104 §5, the "point of no return without external support").
        if purity <= p_crit(n) {
            return BandControl::Escalate;
        }
        // `R = 1/(N·P)` — the caller already carries `P`, so the self-model the upper edge is defined by
        // needs no new input, only naming (#275).
        let reflection = if purity > 0.0 { 1.0 / (n as f64 * purity) } else { 0.0 };
        match classify_collective(mean_r, diagonal_purity, reflection) {
            CollectiveState::CollectiveSubject => BandControl::Hold,
            CollectiveState::OverCoupled => {
                // **Proportional shed, on the same quantity the trigger reads** (#275). It used to be
                // `(mean_r − hi)/hi`, which was right only while the trigger was also `r > hi`: once the
                // trigger became the measured `R`, a cell can be over-coupled at `r < hi`, and that
                // expression goes negative and `clamp`s to a `Decouple { effort: 0 }` — a shed that sheds
                // nothing, fired on exactly the cells the change exists to catch. Trigger and effort have
                // to measure one thing.
                //
                // The excursion is how far the self-model has fallen below its floor, as a fraction of the
                // floor: zero at the edge, 1 when the self-model is gone entirely, monotone between. Scaled
                // by the gain and capped at 1 for the same reason as before — a shed cannot exceed what
                // exists.
                let excursion = (R_TH - reflection) / R_TH;
                let effort = (self.kappa * excursion).clamp(0.0, 1.0);
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

    /// A cell that is over-coupled **below** the `hi` edge must still be shed with real effort (#275).
    ///
    /// This is the coupling the #275 change could have broken instead of fixed. The trigger moved to the
    /// measured `R`, which admits cells at `r < hi`; the old shed law `κ(r − hi)/hi` goes negative there and
    /// `clamp`s to zero, so the homeostat would have answered `Decouple { effort: 0.0 }` — a shed that sheds
    /// nothing, on exactly the cells the change exists to catch. Two errors cancelling into a confident
    /// no-op is worse than the defect it replaced.
    ///
    /// The numbers are the measured ones from `tests/phase_edge.rs`, not invented: a Fano cell whose one
    /// line exchanges more than the rest reads `r = 0.5746` (edge `0.5774`), `P = 0.4452`, hence
    /// `R = 1/(7P) = 0.3209` and `Φ = P/p − 1 = 2.116`.
    #[test]
    fn a_cell_over_coupled_below_the_edge_is_shed_with_real_effort() {
        let (purity, mean_r, p, n) = (0.4452, 0.5746, 1.0 / 7.0, 7);
        let (_, hi) = crate::window::collective_subject_window_at(p);
        assert!(mean_r < hi, "the case is only interesting below the edge: r={mean_r}, hi={hi}");

        let out = Homeostat::default().control(purity, mean_r, p, n);
        let BandControl::Decouple { effort } = out else {
            panic!("a cell at R = {:.4} has lost its self-model and must be shed, got {out:?}", 1.0 / (7.0 * purity));
        };
        assert!(
            effort > 0.0,
            "the shed fired with zero effort — the trigger reads R and the law still reads r, so they \
             disagree on every cell between the crossing and the edge (#275)"
        );
    }

    /// **These cases live on the equicorrelated stratum, and that is now said rather than assumed.**
    ///
    /// Every closed form they check (`phi_equicorrelated`, `purity_equicorrelated`) is the `p = 1/N` case
    /// of the general law, so the diagonal they belong to is the flat one. Naming it here keeps the
    /// stratum an explicit input instead of a property the call signature quietly supplied — which is the
    /// shape UHM T-316 exists to forbid: a result proved on a stratum predicts nothing off it until
    /// measured off it.
    const FLAT: f64 = 1.0 / N as f64;
    use crate::coherence::{phi_at, purity_equicorrelated};

    const N: usize = 7;

    #[test]
    fn a_healthy_in_band_cell_is_left_alone() {
        // r = 0.5 ∈ (1/√6, 1/√3]; equicorrelated P there is well above 3/7 → viable, in-band → Hold.
        let r = 0.5;
        let p = purity_equicorrelated(N, r);
        assert!(phi_at(r, FLAT) >= 1.0, "integrated");
        assert_eq!(
            Homeostat::conservative().control(p, r, FLAT, N),
            BandControl::Hold
        );
    }

    #[test]
    fn a_common_mode_flood_decouples() {
        // r = 0.7 > 1/√3 ≈ 0.577: over-coupled (groupthink). Viable (equicorrelated P ≈ 0.56 > 2/7), so it
        // sheds correlation rather than escalating. Effort is positive and ≤ 1.
        let r = 0.7;
        let p = purity_equicorrelated(N, r);
        match Homeostat::new(0.5).control(p, r, FLAT, N) {
            BandControl::Decouple { effort } => {
                assert!(
                    effort > 0.0 && effort <= 1.0,
                    "proportional shed effort, got {effort}"
                );
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
        match Homeostat::new(0.5).control(p, r, FLAT, N) {
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
        assert_eq!(
            Homeostat::conservative().control(0.25, 0.5, FLAT, N),
            BandControl::Escalate
        );
        assert_eq!(
            Homeostat::conservative().control(0.25, 0.05, FLAT, N),
            BandControl::Escalate
        );
        assert_eq!(
            Homeostat::conservative().control(2.0 / 7.0, 0.5, FLAT, N),
            BandControl::Escalate
        );
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

    /// **A degenerate behavioural diagonal escalates — and the reason is algebra, not the band** (#272).
    ///
    /// `collective_subject_window_at` returns `(∞, ∞)` for `p ≤ 0`, which `classify_collective` reads as
    /// [`Aggregate`](crate::CollectiveState::Aggregate) — under-coupled — whose prescription is `Bind`, more
    /// coupling. That would be exactly the wrong direction for a cell with no carriers, so the question is
    /// whether anything reaches it.
    ///
    /// Nothing does, and the guarantee is not the ordering of the checks: `Measures` computes
    /// `purity = diag · (1 + Φ)`, so `diagonal_purity = 0` **forces** `purity = 0`, and the viability gate
    /// fires first for every consistent input. The band is never consulted with an infinite window.
    ///
    /// **The first version of this test proved the opposite by passing an impossible pair** — purity just
    /// above the gate beside a zero diagonal — and got `Bind { authority: 1e-9 }`. No matrix can produce
    /// that pair; the probe had built a state the constructor refuses, which is the trap this tree already
    /// has a note about. What survived is not a live defect but a contract gap, and it is guarded below.
    #[test]
    fn a_degenerate_diagonal_escalates_across_the_whole_correlation_range() {
        const N: usize = 7;
        for r in [0.0, 0.3, 0.577, 0.9, 1.0] {
            let verdict = Homeostat::conservative().control(0.0, r, 0.0, N);
            assert_eq!(
                verdict,
                BandControl::Escalate,
                "a cell with no behavioural carriers answered {verdict:?} at r = {r}. If that is `Bind`, \
                 the window's `(∞, ∞)` fallthrough read it as under-coupled and prescribed MORE coupling \
                 — the direction that empties it (#272)."
            );
        }
    }

    /// The two purities are **algebraically dependent**, and the signature lets a caller pass a pair that
    /// no matrix can produce (#272).
    ///
    /// `P = p·(1 + Φ)` with `Φ ≥ 0`, so `P ≥ p` always, and `p = 0` forces `P = 0`. `control` takes them as
    /// two free `f64`s, so an impossible pair is expressible — and it answers such a pair confidently,
    /// which is how the first version of the test above manufactured a defect that cannot occur. The
    /// `debug_assert` in `control` closes that: the contract is now stated where it is relied on rather
    /// than in a comment two modules away.
    #[test]
    #[should_panic(expected = "purity")]
    fn an_impossible_purity_pair_is_refused_rather_than_answered() {
        // Purity above the viability gate beside a vanished diagonal: `P ≥ p` is satisfied, but
        // `p = 0 ⟹ P = 0` is not, and this is exactly the pair that produced the phantom finding.
        let _ = Homeostat::conservative().control(p_crit(7) + 1e-9, 0.9, 0.0, 7);
    }
}
