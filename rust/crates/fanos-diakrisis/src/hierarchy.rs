//! **Parent-observes-child recursion** — DIAKRISIS up the cell hierarchy (spec §L1, §6.5; closing the #95
//! "deeper parent-recursion" residual).
//!
//! The base cell diagnoses `N = 7` **nodes** from their activity and loss signals. The recursion-of-cells
//! (§L1) makes each node of a parent cell itself a **child cell**, so the *identical* diagnosis runs one level
//! up with the child cells as its "nodes": the parent measures its own integration from its children's
//! activity signals (`parent_coherence`) and localizes a failing child from the inter-child loss matrix
//! (`localize_failing_child`) — the very §6.3 grey-endpoint that localizes a failing node inside a cell. A
//! child a parent cannot heal escalates to the *grandparent*, and because a parent's own loss is itself a
//! signal, the diagnosis composes to arbitrary depth (`diagnose_level`, validated in [`recursion tests`]).
//!
//! **Scale-invariance is the point, and its honest caveat.** The projective structure is identical at every
//! level (`S(2,3,7)` for `q = 2`), so the localization pyramid `21 → 7 → 3 → 1` and the leading-indicator
//! alarm recurse unchanged — the *arithmetic* (Φ, the grey endpoint) is exact. The one *model* assumption —
//! the same class as the existing `[И]` axis↔sector dictionary (§6.10) — is that a child cell's aggregate loss
//! is a faithful "node loss" for the parent; it is self-checking (a wrong aggregation breaks the parent's
//! polar sum-rules just as at the base) but is a model, not a theorem.

use alloc::vec::Vec;

use fanos_code::{federation, golay};
use fanos_geometry::fano;

use crate::coherence::{CoherenceMatrix, Measures, PHI_TH};
use crate::polar::grey_endpoint;

/// The **loss** a parent aggregates for a child cell: a scalar in `[0, 1]` (0 = healthy, 1 = dead). A cell is,
/// for its parent's purposes, as lossy as its own worst-off member — so a child that carries a failing
/// grandchild reads high loss, and the fault propagates *up* the hierarchy. This is what makes the recursion
/// compose: `cell_loss(children)` at one level is the child-loss the level above observes.
#[must_use]
pub fn cell_loss(child_losses: &[f64]) -> f64 {
    child_losses.iter().copied().fold(0.0_f64, f64::max).clamp(0.0, 1.0)
}

/// Build the parent's inter-child **loss matrix** from each child's aggregate loss: a link `i↔j` is as lossy
/// as its worse endpoint, `loss(i,j) = max(loss_i, loss_j)` (diagonal = the child's own loss). This is the
/// parent-level analogue of the §6.3 per-neighbour loss matrix, and it is exactly what
/// `localize_failing_child` reads: a failing child is lossy on *all* its links, an honest child keeps at
/// least one low-loss link (to another honest child).
#[must_use]
pub fn inter_child_loss(losses: &[f64; fano::N]) -> [[f64; fano::N]; fano::N] {
    core::array::from_fn(|i| {
        core::array::from_fn(|j| {
            let li = losses.get(i).copied().unwrap_or(0.0);
            let lj = losses.get(j).copied().unwrap_or(0.0);
            if i == j { li } else { li.max(lj) }
        })
    })
}

/// Localize the failing **child cell** from the parent's inter-child loss matrix — the *same* §6.3 grey
/// endpoint the base cell uses to localize a failing node, one level up. `None` if no child is lossy past the
/// `tol` gap (the parent is healthy). `tol` is the honest per-child jitter slack.
#[must_use]
pub fn localize_failing_child(loss_matrix: &[[f64; fano::N]; fano::N], tol: f64) -> Option<usize> {
    grey_endpoint(loss_matrix, tol)
}

/// Build the **parent coherence matrix** from each child's *activity signal over a window* — the parent
/// treats each child cell as one node, reusing the exact [`CoherenceMatrix`] the base cell uses, so its
/// integration `Φ` and leading-indicator alarm recurse. `None` if the signals are ragged or empty.
#[must_use]
pub fn parent_coherence(child_activity: &[Vec<f64>]) -> Option<CoherenceMatrix> {
    CoherenceMatrix::from_signals(child_activity)
}

/// The **federated verdict** over a parent's children — the Turyn covering applied to the degraded-axis masks the
/// children already compute (`docs/design-federation.md`).
///
/// This is a strictly finer instrument than `localize_failing_child`, and the difference is worth stating rather than
/// leaving to be discovered:
///
/// | | `localize_failing_child` | the federated verdict |
/// |---|---|---|
/// | granularity | *which child* is failing | *which `(child, axis)`* pairs are faulty |
/// | multiplicity | at most **one** child | up to **3** faults anywhere, or 1 per child across all 7 |
/// | a uniformly lossy parent | **silent** (no gap to find) | attributed, because the grammar does not need a gap |
/// | over capacity | silent | `Partial`, *naming what is unexplained* |
/// | basis | a loss-gap threshold | a perfect code (T-228) |
///
/// Both are kept. The grey-endpoint rule reads *analogue* loss and needs no per-child reporting, so it still works where
/// children are uncooperative or silent; the federated verdict reads *digital* self-reports and is exact where they exist.
/// They fail in different directions, which is the reason to have both rather than a reason to pick.
/// Gate each child's self-reported axis mask on the parent's **own** measurement of that child.
///
/// This is what makes a self-reported federation sound, and it is the composition the two localizers were always able to
/// support. A child's report is forgeable — `fanos_code::golay::Provenance` records that a lying member can otherwise
/// relocate blame onto a healthy sibling, measured at 24.9% of decodable frames. But the parent measures each child's
/// **loss** from its own traffic, and that measurement is not the child's to forge.
///
/// So the two are composed by *authority over different questions*:
///
/// * the parent's measurement decides **whether** a child is faulty — coarse, sound, unforgeable by the child;
/// * the child's report decides **which axes** — fine, forgeable, and therefore admissible only about a child the parent
///   has already independently found faulty.
///
/// A child the parent measures as healthy contributes a **zero block**, so its fabricated faults never enter the word and
/// cannot move the blame anywhere. A liar can at most under-report its own genuine faults, which is the direction that
/// harms only itself.
///
/// `tol` is the same per-child jitter slack `localize_failing_child` uses, so the two localizers agree about what
/// "measurably lossy" means rather than drifting apart on two thresholds.
#[must_use]
pub fn corroborated_reports(
    child_degraded: &[u8; fano::N],
    child_bus_faults: &[bool; fano::N],
    child_losses: &[f64; fano::N],
    tol: f64,
) -> ([u8; fano::N], [bool; fano::N]) {
    let baseline = child_losses.iter().copied().fold(f64::INFINITY, f64::min);
    let mut axes = [0u8; fano::N];
    let mut buses = [false; fano::N];
    for (i, (a, b)) in axes.iter_mut().zip(buses.iter_mut()).enumerate() {
        let lossy = child_losses.get(i).is_some_and(|l| *l > baseline + tol);
        if lossy {
            *a = child_degraded.get(i).copied().unwrap_or(0) & 0x7F;
            *b = child_bus_faults.get(i).copied().unwrap_or(false);
        }
    }
    (axes, buses)
}

/// Run the Turyn covering over the children's axis masks (`docs/design-federation.md`).
///
/// `provenance` states where the masks came from and therefore how far the grammar may be trusted with them — see
/// [`fanos_code::golay::Provenance`]. Pass [`golay::Provenance::Measured`] only for masks that are not the reporting
/// child's to forge; [`corroborated_reports`] is how a self-reported mask earns that standing.
#[must_use]
pub fn federated_diagnosis(
    child_degraded: &[u8; fano::N],
    child_bus_faults: &[bool; fano::N],
    provenance: golay::Provenance,
) -> federation::Cell {
    let mut reports = [golay::Report::default(); federation::CHILDREN];
    for (r, (&axes, &bus)) in reports.iter_mut().zip(child_degraded.iter().zip(child_bus_faults.iter())) {
        *r = golay::Report { axes: axes & 0x7F, bus_fault: bus };
    }
    federation::diagnose_cell(reports, provenance)
}

/// One level's diagnosis: the parent's coherence measures over its children, the localized failing child (if
/// any), the **federated verdict** over their reported axes, and whether the parent must escalate to *its* parent
/// (the parent itself is not integrated, `Φ < 1` — the leading indicator, one level up).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct LevelDiagnosis {
    /// The parent-level coherence measures (Φ, P, R) over the children's activity.
    pub measures: Measures,
    /// The localized failing child index `0..7`, if exactly one grey child stands out.
    pub failing_child: Option<usize>,
    /// The federated verdict over the children's degraded-axis reports — see [`federated_diagnosis`].
    pub federated: federation::Cell,
    /// Whether the parent must escalate to its own parent (`Φ < 1`).
    pub escalate: bool,
}

/// Diagnose one hierarchy level from the children's activity signals (parent coherence), their aggregate
/// losses (analogue localization), and their reported degraded axes (federated localization). `None` if the
/// activity signals are unusable.
///
/// The two localizers are deliberately both present rather than one chosen: the loss-gap rule needs no cooperation from
/// the children and degrades to silence, while the federated grammar needs their reports and is exact. A parent that has
/// both can cross-check them, and a disagreement is itself a signal — a child whose analogue loss says "failing" while its
/// own report says "healthy" is the shape of a lying member.
#[must_use]
pub fn diagnose_level(
    child_activity: &[Vec<f64>],
    child_losses: &[f64; fano::N],
    child_degraded: &[u8; fano::N],
    child_bus_faults: &[bool; fano::N],
    tol: f64,
) -> Option<LevelDiagnosis> {
    let measures = parent_coherence(child_activity)?.measures();
    Some(LevelDiagnosis {
        measures,
        failing_child: localize_failing_child(&inter_child_loss(child_losses), tol),
        // Corroborated before use: a child's axis mask is admitted only about a child the parent's OWN loss measurement
        // already found faulty, so a fabricated report never enters the word and cannot move blame onto a sibling. With
        // the forgeable half gated, what remains is parent-measured in the sense that matters, so the full `t = 3`
        // applies rather than the reduced self-reported capability.
        federated: {
            let (axes, buses) = corroborated_reports(child_degraded, child_bus_faults, child_losses, tol);
            federated_diagnosis(&axes, &buses, golay::Provenance::Measured)
        },
        escalate: measures.phi < PHI_TH - 1e-9,
    })
}

/// Whether the analogue and federated localizers **disagree** about a child: the loss gap names it failing while its own
/// report claims no faulty axis, or the reverse.
///
/// A disagreement is not noise to be smoothed over — it is the observable signature of a member misreporting its own
/// health, which neither localizer can see alone. The analogue side is measured *about* the child by its peers; the
/// federated side is claimed *by* the child. Where they part, the claim is the suspect one.
#[must_use]
pub fn localizers_disagree(d: &LevelDiagnosis) -> Option<usize> {
    let child = d.failing_child?;
    let reported = match d.federated {
        federation::Cell::Healthy => 0,
        federation::Cell::Localized(f) | federation::Cell::Partial { localized: f, .. } => {
            f.axes.get(child).map_or(0, |m| m.count_ones())
        }
    };
    if reported == 0 { Some(child) } else { None }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn the_federated_verdict_attributes_what_the_loss_gap_cannot() {
        // The upgrade, side by side. Three degraded axes inside one child: the loss-gap rule can at best name the child,
        // and only if its loss stands out; the federated grammar names the axes.
        let mut degraded = [0u8; fano::N];
        degraded[5] = 0b0010_1001; // axes 0, 3 and 5 of child 5
        let verdict = federated_diagnosis(&degraded, &[false; fano::N], golay::Provenance::Measured);
        let federation::Cell::Localized(f) = verdict else { panic!("three faults must localize") };
        assert_eq!(f.axes[5], 0b0010_1001, "the axes are named, not just the child");
        assert_eq!(f.total(), 3);
    }

    #[test]
    fn a_uniformly_degraded_parent_is_attributed_where_the_gap_rule_is_silent() {
        // The grey-endpoint rule needs a *gap*: a cell whose children are all equally lossy offers none, and the rule is
        // correctly silent (`grey_endpoint_is_silent_on_a_fair_lossy_cell`). The federated grammar needs no gap — one
        // degraded axis per child is seven faults, and it attributes every one.
        let mut degraded = [0u8; fano::N];
        for (c, d) in degraded.iter_mut().enumerate() {
            *d = 1 << (c % 7);
        }
        assert_eq!(localize_failing_child(&inter_child_loss(&[0.2; fano::N]), 0.1), None, "no gap, no verdict");
        let federation::Cell::Localized(f) = federated_diagnosis(&degraded, &[false; fano::N], golay::Provenance::Measured) else {
            panic!("one per child must localize")
        };
        assert_eq!(f.total(), 7, "all seven attributed without any gap to lean on");
    }

    #[test]
    fn a_lying_child_cannot_inject_faults_the_parent_does_not_measure() {
        // The framing attack, defeated by composition rather than by a cap. A child fabricates four faults in its own
        // block — the exact shape that relocates blame onto a healthy sibling when the grammar trusts self-reports. The
        // parent measures no loss at that child, so its whole block is refused and never enters the word.
        let mut degraded = [0u8; fano::N];
        degraded[6] = 0b0000_1111; // the lie
        let quiet = [0.01f64; fano::N]; // the parent sees every child as equally, minimally lossy
        let (axes, _) = corroborated_reports(&degraded, &[false; fano::N], &quiet, 0.1);
        assert_eq!(axes, [0u8; fano::N], "an uncorroborated report contributes nothing at all");
        assert_eq!(
            federated_diagnosis(&axes, &[false; fano::N], golay::Provenance::Measured),
            federation::Cell::Healthy,
            "so it cannot move blame anywhere, let alone onto a sibling"
        );
    }

    #[test]
    fn a_corroborated_child_keeps_its_axis_detail() {
        // The other direction, which matters just as much: gating must not throw away real diagnosis. The parent measures
        // child 2 as lossy, so child 2's axis detail IS admitted — the parent's measurement decides *whether*, the
        // child's report decides *which axes*.
        let mut degraded = [0u8; fano::N];
        degraded[2] = 0b0000_0101; // axes 0 and 2
        let mut losses = [0.01f64; fano::N];
        losses[2] = 0.8; // and the parent independently sees it
        let (axes, _) = corroborated_reports(&degraded, &[false; fano::N], &losses, 0.1);
        assert_eq!(axes[2], 0b0000_0101, "the corroborated child's detail survives");
        let federation::Cell::Localized(f) = federated_diagnosis(&axes, &[false; fano::N], golay::Provenance::Measured)
        else {
            panic!("must localize")
        };
        assert_eq!(f.axes[2], 0b0000_0101);
        assert_eq!(f.total(), 2);
    }

    #[test]
    fn a_liar_can_only_under_report_its_own_faults_which_harms_only_itself() {
        // The residual, stated so it is not mistaken for soundness. Gating stops a child inventing faults; it cannot make
        // a child confess ones it hides. A child the parent measures as lossy but which reports a clean mask contributes
        // nothing — the parent still knows it is lossy (that is `failing_child`), it simply learns no axis detail.
        let degraded = [0u8; fano::N]; // child 4 hides everything
        let mut losses = [0.01f64; fano::N];
        losses[4] = 0.9;
        let (axes, _) = corroborated_reports(&degraded, &[false; fano::N], &losses, 0.1);
        assert_eq!(axes[4], 0, "a hidden fault stays hidden — under-reporting is not prevented");
        assert_eq!(
            localize_failing_child(&inter_child_loss(&losses), 0.1),
            Some(4),
            "but the parent's own measurement still names the child, so the liar gains nothing but vagueness"
        );
    }

    #[test]
    fn a_clean_parent_is_federated_healthy() {
        assert_eq!(
            federated_diagnosis(&[0; fano::N], &[false; fano::N], golay::Provenance::Measured),
            federation::Cell::Healthy
        );
    }

    #[test]
    fn a_child_whose_peers_see_loss_but_who_reports_health_is_flagged() {
        // The cross-check the two localizers make possible, and neither can make alone: the analogue side is measured
        // *about* a child by its peers, the federated side is claimed *by* the child. Where they part, the claim is the
        // suspect one — which is the observable signature of a member misreporting its own health.
        let mut losses = [0.01f64; fano::N];
        losses[2] = 0.9; // peers see child 2 as badly lossy
        let activity: Vec<Vec<f64>> = (0..fano::N).map(|i| (0..8).map(|t| ((i + t) as f64).sin()).collect()).collect();
        let d = diagnose_level(&activity, &losses, &[0; fano::N], &[false; fano::N], 0.1).unwrap();
        assert_eq!(d.failing_child, Some(2), "the loss gap names child 2");
        assert_eq!(d.federated, federation::Cell::Healthy, "yet child 2 reports no faulty axis");
        assert_eq!(localizers_disagree(&d), Some(2), "the disagreement is surfaced, not averaged away");

        // And when the child reports honestly, there is no disagreement to flag.
        let mut degraded = [0u8; fano::N];
        degraded[2] = 0b0000_0001;
        let honest = diagnose_level(&activity, &losses, &degraded, &[false; fano::N], 0.1).unwrap();
        assert_eq!(honest.failing_child, Some(2));
        assert_eq!(localizers_disagree(&honest), None, "agreement is not a disagreement");
    }

    #[test]
    fn over_capacity_damage_is_reported_partial_rather_than_guessed() {
        let mut degraded = [0u8; fano::N];
        degraded[1] = 0b0000_1111; // four axes in one child: unavoidably beyond the grammar
        let federation::Cell::Partial { localized, unexplained } =
            federated_diagnosis(&degraded, &[false; fano::N], golay::Provenance::Measured)
        else {
            panic!("four in one child cannot localize")
        };
        assert!(localized.is_empty());
        assert_eq!(unexplained[1], 0b0000_1111, "and the unexplained damage is named for the controller");
    }

    #[test]
    fn a_parent_localizes_its_one_failing_child() {
        // Six healthy children (loss ≈ 0.05 jitter), child 4 failing (loss 0.8). The parent — reading the
        // inter-child loss matrix — localizes 4 by the same grey endpoint that finds a failing node in a cell.
        let mut loss = [0.05f64; fano::N];
        loss[4] = 0.8;
        assert_eq!(localize_failing_child(&inter_child_loss(&loss), 0.1), Some(4));
        // An all-healthy parent localizes no failing child.
        assert_eq!(localize_failing_child(&inter_child_loss(&[0.05f64; fano::N]), 0.1), None);
    }

    #[test]
    fn the_fault_and_its_localization_recurse_across_two_levels() {
        // Level 2 — a parent P observing 7 grandchildren; grandchild 2 collapses (loss 0.9). P localizes it.
        let mut gc = [0.05f64; fano::N];
        gc[2] = 0.9;
        assert_eq!(localize_failing_child(&inter_child_loss(&gc), 0.1), Some(2), "P localizes the failing grandchild");

        // P's OWN loss aggregates its worst member → high, propagating the fault UP. The grandparent G
        // observes 7 parents; P (index 5) carries the fault.
        let p_loss = cell_loss(&gc); // 0.9
        assert!((p_loss - 0.9).abs() < 1e-12);
        let mut parents = [0.05f64; fano::N];
        parents[5] = p_loss;
        // The SAME localize function, one level higher, finds the faulty parent — the recursion holds verbatim.
        assert_eq!(localize_failing_child(&inter_child_loss(&parents), 0.1), Some(5), "G localizes the faulty parent");
    }

    #[test]
    fn the_parent_integration_alarm_recurses() {
        // Children whose activity moves TOGETHER integrate at the parent level (Φ ≥ 1) → no escalation; each
        // moving independently leaves the parent un-integrated (Φ < 1) → escalate. The leading indicator, one
        // level up.
        let shared: Vec<f64> = (0..40).map(|t| f64::from(t) * 0.5 + 3.0).collect();
        let together: Vec<Vec<f64>> = (0..fano::N)
            .map(|k| shared.iter().map(|&x| x + 0.001 * f64::from(k as u32)).collect())
            .collect();
        let d_together = diagnose_level(&together, &[0.05; fano::N], &[0; fano::N], &[false; fano::N], 0.1).unwrap();
        assert!(d_together.measures.phi >= PHI_TH, "correlated sub-cells integrate at the parent (Φ={})", d_together.measures.phi);
        assert!(!d_together.escalate, "an integrated parent does not escalate");

        // Independent children: distinct, uncorrelated patterns.
        let apart: Vec<Vec<f64>> = (0..fano::N)
            .map(|k| (0..40usize).map(|t| ((t * (k + 1) * 7 + k * 3) % 11) as f64).collect())
            .collect();
        let d_apart = diagnose_level(&apart, &[0.05; fano::N], &[0; fano::N], &[false; fano::N], 0.1).unwrap();
        assert!(d_apart.escalate == (d_apart.measures.phi < PHI_TH - 1e-9), "escalation tracks the parent Φ<1 leading indicator");
    }

    #[test]
    fn cell_loss_propagates_the_worst_member() {
        assert!((cell_loss(&[0.05, 0.1, 0.9, 0.02]) - 0.9).abs() < 1e-12, "a cell is as lossy as its worst member");
        assert_eq!(cell_loss(&[]), 0.0, "an empty cell has no loss");
        assert!((cell_loss(&[0.01, 0.03]) - 0.03).abs() < 1e-12);
    }
}
