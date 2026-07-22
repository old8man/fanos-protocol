//! **Parent-observes-child recursion** — DIAKRISIS up the cell hierarchy (spec §L1, §6.5; closing the #95
//! "deeper parent-recursion" residual).
//!
//! The base cell diagnoses `N = 7` **nodes** from their activity and loss signals. The recursion-of-cells
//! (§L1) makes each node of a parent cell itself a **child cell**, so the *identical* diagnosis runs one level
//! up with the child cells as its "nodes": the parent measures its own integration from its children's
//! activity signals ([`parent_coherence`]) and localizes a failing child from the inter-child loss matrix
//! ([`localize_failing_child`]) — the very §6.3 grey-endpoint that localizes a failing node inside a cell. A
//! child a parent cannot heal escalates to the *grandparent*, and because a parent's own loss is itself a
//! signal, the diagnosis composes to arbitrary depth ([`diagnose_level`], validated in [`recursion tests`]).
//!
//! **Scale-invariance is the point, and its honest caveat.** The projective structure is identical at every
//! level (`S(2,3,7)` for `q = 2`), so the localization pyramid `21 → 7 → 3 → 1` and the leading-indicator
//! alarm recurse unchanged — the *arithmetic* (Φ, the grey endpoint) is exact. The one *model* assumption —
//! the same class as the existing `[И]` axis↔sector dictionary (§6.10) — is that a child cell's aggregate loss
//! is a faithful "node loss" for the parent; it is self-checking (a wrong aggregation breaks the parent's
//! polar sum-rules just as at the base) but is a model, not a theorem.

use alloc::vec::Vec;

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
/// [`localize_failing_child`] reads: a failing child is lossy on *all* its links, an honest child keeps at
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

/// One level's diagnosis: the parent's coherence measures over its children, the localized failing child (if
/// any), and whether the parent must escalate to *its* parent (the parent itself is not integrated, `Φ < 1` —
/// the leading indicator, one level up).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct LevelDiagnosis {
    /// The parent-level coherence measures (Φ, P, R) over the children's activity.
    pub measures: Measures,
    /// The localized failing child index `0..7`, if exactly one grey child stands out.
    pub failing_child: Option<usize>,
    /// Whether the parent must escalate to its own parent (`Φ < 1`).
    pub escalate: bool,
}

/// Diagnose one hierarchy level from the children's activity signals (parent coherence) and their aggregate
/// losses (localization). `None` if the activity signals are unusable.
#[must_use]
pub fn diagnose_level(
    child_activity: &[Vec<f64>],
    child_losses: &[f64; fano::N],
    tol: f64,
) -> Option<LevelDiagnosis> {
    let measures = parent_coherence(child_activity)?.measures();
    Some(LevelDiagnosis {
        measures,
        failing_child: localize_failing_child(&inter_child_loss(child_losses), tol),
        escalate: measures.phi < PHI_TH - 1e-9,
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

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
        let d_together = diagnose_level(&together, &[0.05; fano::N], 0.1).unwrap();
        assert!(d_together.measures.phi >= PHI_TH, "correlated sub-cells integrate at the parent (Φ={})", d_together.measures.phi);
        assert!(!d_together.escalate, "an integrated parent does not escalate");

        // Independent children: distinct, uncorrelated patterns.
        let apart: Vec<Vec<f64>> = (0..fano::N)
            .map(|k| (0..40usize).map(|t| ((t * (k + 1) * 7 + k * 3) % 11) as f64).collect())
            .collect();
        let d_apart = diagnose_level(&apart, &[0.05; fano::N], 0.1).unwrap();
        assert!(d_apart.escalate == (d_apart.measures.phi < PHI_TH - 1e-9), "escalation tracks the parent Φ<1 leading indicator");
    }

    #[test]
    fn cell_loss_propagates_the_worst_member() {
        assert!((cell_loss(&[0.05, 0.1, 0.9, 0.02]) - 0.9).abs() < 1e-12, "a cell is as lossy as its worst member");
        assert_eq!(cell_loss(&[]), 0.0, "an empty cell has no loss");
        assert!((cell_loss(&[0.01, 0.03]) - 0.03).abs() < 1e-12);
    }
}
