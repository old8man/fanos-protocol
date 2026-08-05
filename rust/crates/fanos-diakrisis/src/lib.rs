//! # fanos-diakrisis — the self-diagnosis plane
//!
//! FANOS shines, APHANTOS hides, NYX conceals — **DIAKRISIS discerns.** This crate is the
//! reflexive plane (spec Part VI) by which a cell observes its own state, localizes what
//! broke, tells a crash from a lie from a partition, and heals — every diagnostic constant
//! fixed by a theorem, not tuned. It builds on [`fanos_code`]'s syndrome localizer and adds:
//!
//! * [`coherence`] — the coherence matrix `Γ_net` and its measures `Φ` / `P` / `R` (§2.7).
//! * [`polar`] — the 14 free polar sum-rule alarms and the rate model (§6.2, T-226).
//! * [`blindness`] — first-order blindness `Σ A(line) = J − I` (§2.8, V11).
//! * [`partition`] — the partition-resistance / Fiedler reading (§6.5, V14).
//! * [`healing`] — the `Φ×1/9` reroute budget and the `R_th = 1/3` floor (§6.7–§6.8).
//! * [`window`] — the leading-indicator theorem and the collective-subject window (§6.6, §18).
//! * [`plan`] — the **act** phase: a [`Verdict`] becomes a bounded [`plan::HealingPlan`] (§6.7, §6.9).
//! * [`regeneration`] — recovery *rate* `κ(Γ)` and reintegration *time* `τ = 1/Δ` (§6.7, T-226(v)).
//!
//! [`diagnose`] runs one round of the reflexive loop (§6.9): detect (structural + global),
//! localize (syndrome / themes), and classify into a [`Verdict`].
//!
//! Builds on `std` (hardware float math) or `no_std` + the `libm` feature; needs `alloc`.

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(portable_simd)]
#![forbid(unsafe_code)]

extern crate alloc;

mod mathfns;

pub mod blindness;
pub mod cbf;
pub mod coherence;
pub mod dynamics;
pub mod eig;
pub mod healing;
/// Parent-observes-child recursion — DIAKRISIS up the cell hierarchy (§L1, §6.5; #95).
pub mod hierarchy;
pub mod homeostat;
pub mod loadbalance;
pub mod minima;
pub mod monitor;
pub mod partition;
pub mod plan;
pub mod polar;
pub mod regeneration;
pub mod stability;
pub mod vitals;
pub mod window;

use alloc::vec::Vec;

pub use coherence::CoherenceMatrix;
pub use homeostat::{BandControl, Homeostat};
pub use plan::{HealingAction, HealingPlan, plan_healing};
pub use vitals::VitalSigns;
// Re-export the localization types from the code crate so callers have one diagnosis surface.
pub use fanos_code::{Fault, Sector, decode_themes, locate, syndrome3, theme_flags};

/// The default tolerance for the polar sum-rule equalities (spec §6.2).
pub const POLAR_TOLERANCE: f64 = 1e-9;

/// One round of health observation feeding the reflexive loop (spec §6.9 DIAGNOSE).
#[derive(Clone, Debug, Default)]
pub struct Observation {
    /// Binarized node health: bit `i` set ⇒ Fano point `i` is degraded past its viability
    /// threshold.
    pub degraded: u8,
    /// Optional `7×7` measured pairwise rate matrix for the structural (polar) check.
    pub pairwise_rates: Option<[[f64; 7]; 7]>,
    /// Optional coherence matrix for the global mean-correlation cascade monitor.
    pub coherence: Option<CoherenceMatrix>,
    /// Optional 7-bit mask of healthy lines for the connectivity (partition) check. A cell is
    /// partitioned only when it actually disconnects (Fiedler `λ₂ = 0`), *not* merely when it
    /// is weakly correlated — low correlation is the resilient/diversified regime (§2.7).
    pub healthy_lines: Option<u8>,
}

/// The verdict of a diagnostic round (spec §6.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// All checks clean and integrated.
    Healthy,
    /// One or two node faults localized by the syndrome / theme layers.
    Localized(Fault),
    /// Three or more simultaneous faults saturate the single-cell decoder; escalate to the
    /// parent cell (spec §6.3 stratification). Carries the observed line-theme flags.
    Escalate(u8),
    /// A structural anomaly (Byzantine health-report forgery): the listed polar classes
    /// violate the free sum-rules, narrowing the culprit to those mediators (spec §6.2).
    Structural(Vec<usize>),
    /// No single-node syndrome, but the cell has fragmented (`Φ < 1`) — a partition /
    /// systemic event (spec §6.5).
    Partition,
    /// Mean correlation has crossed the **over-coupling** bound `√(2/(N−1))` (`= 1/√3` for
    /// `N = 7`), so `R < 1/3`: the cell is over-integrated and losing self-observation. The
    /// response is to *shed* correlation back into the healthy collective-subject band (spec
    /// §18.2, §6.8). The earlier `r > r*` crossing is only a monitor alarm, not this verdict —
    /// the band `(r*, 1/√3]` is a desirable integrated subject, not a fault.
    Systemic,
}

/// Run one round of the DIAKRISIS reflexive loop (spec §6.9): detect, localize, classify.
///
/// Order follows the specification: the structural polar-rule alarm (which catches
/// equivocation invisible to pairwise monitoring) is checked first, then node localization,
/// then — if no node syndrome fires — the global integration / cascade monitors.
#[must_use]
pub fn diagnose(obs: &Observation) -> Verdict {
    // Detect (structural): the 14 free polar sum-rules. A stable violation is a Byzantine
    // forgery or mis-provisioned member, already narrowed to the violated polar classes.
    if let Some(rates) = &obs.pairwise_rates {
        let violated = polar::violated_classes(rates, POLAR_TOLERANCE);
        if !violated.is_empty() {
            return Verdict::Structural(violated);
        }
    }

    // Localize: the 21 → 7 → 3 → 1 pyramid on the binarized health vector.
    match locate(obs.degraded) {
        Fault::Healthy => {
            // No single-node fault. Consult the global monitors (spec §6.5). Only *over-coupling*
            // (r > 1/√3, R < 1/3) is an actionable systemic fault — the band (r*, 1/√3] is a
            // healthy, self-modelling collective subject that must NOT be decoupled (spec §18.2).
            // A partition is a genuine connectivity loss, not weak correlation.
            if obs
                .coherence
                .as_ref()
                .is_some_and(CoherenceMatrix::is_overcoupled)
            {
                return Verdict::Systemic;
            }
            if obs
                .healthy_lines
                .is_some_and(|lines| !partition::is_connected(lines))
            {
                return Verdict::Partition;
            }
            Verdict::Healthy
        }
        // Three or more faults saturate the single-cell decoder: escalate to the parent (spec §6.3).
        //
        // **This arm must not consult the partition sensor, and the reason is an impossibility rather than a
        // preference.** A cut, seen from one side, *is* a set of silent coordinates — and so is a mass crash.
        // A node holds only its own `degraded` and `healthy_lines`, and those are **equal** in the two
        // worlds: `a_mass_crash_and_one_side_of_a_cut_are_the_same_observation` builds both from their
        // causes and shows they coincide. No function of a single [`Observation`] can separate them, so any
        // arm that tries is choosing one label for both.
        //
        // It was tried (#114), on the true premise that the sensor is nearly unreachable while gated on
        // `degraded == 0` — it could then only fire for a cut so soft that every node still corroborated.
        // The fix consulted the sensor here, and relabelled **every three-node crash as `Partition`**, which
        // is worse than the gap: a cell that has lost three members stops escalating for repair. Measured
        // afterwards, not predicted — `three_crashes_escalate` reported `Partition` on all four survivors.
        //
        // The discrimination is real, but the evidence for it is **cross-node** and this function has none:
        // on a cut the far side is alive and holds the complementary view, while a crashed node holds
        // nothing. Only an observer that sees both sides can tell — which is precisely what escalating to
        // the parent cell is for, and why `Escalate` is the honest verdict rather than a weaker one. The
        // narrower rule of §6.5 is untouched: `Single` and `Pair` still fall through to `Localized`.
        Fault::Escalate(flags) => Verdict::Escalate(flags),
        fault => Verdict::Localized(fault),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn healthy_cell_reports_healthy() {
        let obs = Observation {
            degraded: 0,
            pairwise_rates: Some(polar::line_rates_to_pair_rates([1.0; 7])),
            coherence: Some(CoherenceMatrix::equicorrelated(7, 0.2)),
            healthy_lines: Some(0x7F),
        };
        assert_eq!(diagnose(&obs), Verdict::Healthy);
    }

    #[test]
    fn single_crash_is_localized_and_repairable() {
        // Inject one crash: DIAKRISIS localizes it, and the LRC repairs it.
        let node = 5;
        let obs = Observation {
            degraded: 1 << node,
            ..Default::default()
        };
        assert_eq!(diagnose(&obs), Verdict::Localized(Fault::Single(node)));
        assert!(fanos_code::is_recoverable_fano(1 << node));
        // Reroute target is the mediator of the failed node with any partner.
        assert!(fanos_geometry::fano::mediator(node, 0).is_some());
    }

    #[test]
    fn byzantine_forgery_is_caught_by_polar_rules() {
        // A node lies about one channel rate: pairwise-healthy but structurally inconsistent.
        let mut rates = polar::line_rates_to_pair_rates([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]);
        let k = fanos_geometry::fano::mediator(2, 3).unwrap();
        rates[2][3] += 10.0;
        rates[3][2] += 10.0;
        let obs = Observation {
            degraded: 0,
            pairwise_rates: Some(rates),
            ..Default::default()
        };
        assert_eq!(diagnose(&obs), Verdict::Structural(alloc::vec![k]));
    }

    #[test]
    fn over_coupling_decouples_but_a_healthy_collective_subject_does_not() {
        // In the collective-subject band (1/√6, 1/√3] the cell is integrated AND still
        // self-modelling (R ≥ 1/3) — a *desired* state, not a fault: diagnose leaves it Healthy
        // (spec §18.2). Decoupling a legitimately integrated subject would be self-defeating.
        let in_band = Observation {
            degraded: 0,
            coherence: Some(CoherenceMatrix::equicorrelated(7, 0.5)),
            healthy_lines: Some(0x7F),
            ..Default::default()
        };
        assert_eq!(diagnose(&in_band), Verdict::Healthy);
        // Only when over-coupled (r > 1/√3, R < 1/3) is shedding correlation warranted.
        let over_coupled = Observation {
            degraded: 0,
            coherence: Some(CoherenceMatrix::equicorrelated(7, 0.7)),
            ..Default::default()
        };
        assert_eq!(diagnose(&over_coupled), Verdict::Systemic);
    }

    #[test]
    fn actual_disconnection_reports_partition() {
        // Drop all three lines through point 0 → it is isolated → the cell partitions.
        let its_lines = fanos_geometry::fano::POINT_LINES[0];
        let mut healthy = 0x7Fu8;
        for &l in &its_lines {
            healthy &= !(1 << l);
        }
        let obs = Observation {
            degraded: 0,
            healthy_lines: Some(healthy),
            ..Default::default()
        };
        assert_eq!(diagnose(&obs), Verdict::Partition);
        // A merely diversified (weakly correlated) cell is NOT a partition.
        let resilient = Observation {
            degraded: 0,
            coherence: Some(CoherenceMatrix::equicorrelated(7, 0.2)),
            healthy_lines: Some(0x7F),
            ..Default::default()
        };
        assert_eq!(diagnose(&resilient), Verdict::Healthy);
    }

    /// A line is healthy to an observer exactly when it holds no coordinate that observer has gone silent on.
    fn healthy_lines_given_silent(silent: u8) -> u8 {
        let mut mask = 0u8;
        for l in 0..7 {
            if fanos_geometry::fano::INCIDENCE[l] & silent == 0 {
                mask |= 1 << l;
            }
        }
        mask
    }

    /// What a node observes when the points in `stopped` **crash**: it stops hearing from exactly those.
    fn observed_after_crashes(stopped: u8) -> Observation {
        Observation {
            degraded: stopped,
            healthy_lines: Some(healthy_lines_given_silent(stopped)),
            ..Default::default()
        }
    }

    /// What a node on the `mine` side of a **cut** observes: it stops hearing from everything across it.
    fn observed_across_a_cut(mine: u8) -> Observation {
        let far_side = !mine & 0x7F;
        Observation {
            degraded: far_side,
            healthy_lines: Some(healthy_lines_given_silent(far_side)),
            ..Default::default()
        }
    }

    /// **A mass crash and one side of a cut are the same observation** — so `diagnose` must not claim to
    /// tell them apart (#114).
    ///
    /// Two different worlds, built here from their two different causes: points 0, 1 and 2 crash, or the
    /// cell is cut `{0,1,2} | {3,4,5,6}` and this node sits on the larger side. A node holds only its own
    /// silence record and its line-health mask, and both worlds hand it the *identical* pair. Any function
    /// of a single [`Observation`] therefore returns the same verdict for both, and an arm that consults the
    /// partition sensor here does not gain a discrimination — it just relabels every mass crash.
    ///
    /// That is not hypothetical: it shipped, and stopped a three-crash cell from escalating for repair. The
    /// evidence that separates the two is **cross-node** (on a cut the far side is alive and holds the
    /// complementary view), which is what escalating to the parent exists to reach.
    #[test]
    fn a_mass_crash_and_one_side_of_a_cut_are_the_same_observation() {
        let crashed = observed_after_crashes(0b000_0111);
        let cut = observed_across_a_cut(0b111_1000);
        assert_eq!(crashed.degraded, cut.degraded, "the same three coordinates fall silent");
        assert_eq!(crashed.healthy_lines, cut.healthy_lines, "and the same lines survive");
        assert_eq!(diagnose(&crashed), diagnose(&cut), "so one node cannot return different verdicts");

        // The graph really is disconnected here — otherwise the arm this pins would never have been
        // reachable and the test would prove nothing about it.
        assert!(
            !partition::is_connected(crashed.healthy_lines.unwrap()),
            "the survivors' line graph must actually be cut, or the sensor is not being exercised"
        );
        // And the verdict is the honest one: saturated decoder, hand it up (spec §6.3).
        assert!(matches!(diagnose(&crashed), Verdict::Escalate(_)));
    }

    #[test]
    fn two_faults_localize_via_theme_layer() {
        let obs = Observation {
            degraded: (1 << 1) | (1 << 4),
            ..Default::default()
        };
        assert_eq!(diagnose(&obs), Verdict::Localized(Fault::Pair(1, 4)));
    }
}
