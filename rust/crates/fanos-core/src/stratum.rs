//! Stratified self-diagnosis: the consumer of escalation (spec §6.3, §6.7).
//!
//! A Fano cell resolves any `≤ 2` faults itself and recovers any `≤ 3` crashes by peeling; a
//! larger residue — three Byzantine faults, or a hyperoval stopping-set — **escalates to the
//! parent cell** (spec §6.3 stratification). This module is where that escalation *lands*: a
//! [`ParentCell`] treats its seven child cells as the seven points of its own Fano cell and runs
//! the **same** reflexive loop one tier up. The recursion is exact — DIAKRISIS is self-similar —
//! and it is here that the healing theory's coarse-hop budget earns its keep: a reroute *around a
//! failed child cell* is a coarse boundary, costing integration `Φ → Φ/9` (spec §6.7, V16), so the
//! parent can only bridge as many child-cell failures as its own `Φ` affords ([`max_reroute_depth`]).
//!
//! A child reports up a [`ChildSummary`]; the parent aggregates the seven summaries into a
//! coarse degraded-mask, [`ParentCell::diagnose`]s it, and [`ParentCell::heal`]s it — reusing the
//! byte-for-byte cell-scale [`diagnose`] and [`plan_healing`]. Escalation is no longer a message
//! into the void: it is the input to the next stratum.

use alloc::vec::Vec;

use fanos_diakrisis::healing::max_reroute_depth;
use fanos_diakrisis::{HealingAction, HealingPlan, Observation, Verdict, diagnose, plan_healing};

/// The number of child cells a Fano parent supervises (its seven points).
pub const CHILDREN: usize = 7;

/// What a child cell reports to its parent after one reflexive round (spec §6.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ChildSummary {
    /// Whether the child exhausted its local recovery and handed a residue up.
    pub escalated: bool,
    /// The child's irrecoverable node-mask (its stopping set); `0` when healthy.
    pub residue: u8,
}

impl ChildSummary {
    /// A healthy child (self-contained; nothing escalated).
    #[must_use]
    pub const fn healthy() -> Self {
        Self {
            escalated: false,
            residue: 0,
        }
    }

    /// A child that escalated an irrecoverable `residue` (e.g. a hyperoval, spec §6.3/V20).
    #[must_use]
    pub const fn escalated(residue: u8) -> Self {
        Self {
            escalated: true,
            residue,
        }
    }
}

/// A parent cell: seven child cells viewed as the seven points of one Fano cell, diagnosed and
/// healed at the coarse tier (spec §6.3, §6.7).
#[derive(Clone, Copy, Debug)]
pub struct ParentCell {
    /// This parent node's own Fano index among its siblings (`0..7`).
    self_index: usize,
    /// The latest summary from each child cell (`None` = not yet reported).
    children: [Option<ChildSummary>; CHILDREN],
}

impl ParentCell {
    /// A parent cell whose own coarse index is `self_index`, with no child reports yet.
    #[must_use]
    pub fn new(self_index: usize) -> Self {
        Self {
            self_index,
            children: [None; CHILDREN],
        }
    }

    /// Record a child cell's summary (out-of-range indices are ignored).
    pub fn observe(&mut self, child: usize, summary: ChildSummary) {
        if let Some(slot) = self.children.get_mut(child) {
            *slot = Some(summary);
        }
    }

    /// The coarse degraded-mask: child cell `i` is a failed parent-point iff it escalated. A child
    /// that has not reported is presumed healthy (its own liveness would escalate if it were gone).
    #[must_use]
    pub fn degraded_mask(&self) -> u8 {
        let mut mask = 0u8;
        for (i, child) in self.children.iter().enumerate() {
            if child.is_some_and(|s| s.escalated) {
                mask |= 1u8 << i;
            }
        }
        mask
    }

    /// Diagnose at the coarse tier — the same reflexive verdict, over child cells (spec §6.3).
    #[must_use]
    pub fn diagnose(&self) -> Verdict {
        diagnose(&Observation {
            degraded: self.degraded_mask(),
            ..Default::default()
        })
    }

    /// The coarse healing plan: reroute around / regenerate failed child cells, bounded by the
    /// parent's integration budget `phi` (each coarse reroute costs `Φ → Φ/9`, spec §6.7).
    ///
    /// The budget is **enforced** here (not merely reported): at the parent tier every reroute is a
    /// coarse boundary, so when `Φ` cannot afford even one hop (`Φ < 9` ⇒ `coarse_budget = 0`,
    /// spec §6.7/V16), the parent does not install an unaffordable reroute — that would itself drive
    /// `Φ → Φ/9 < 1` and disintegrate it — but escalates the coarse residue to the grandparent.
    #[must_use]
    pub fn heal(&self, phi: f64) -> HealingPlan {
        let coarse = self.degraded_mask();
        let mut plan = plan_healing(&self.diagnose(), self.self_index, coarse, phi);
        if coarse != 0 && Self::coarse_budget(phi) == 0 && !plan.escalates() {
            plan.actions.clear();
            plan.actions.push(HealingAction::Escalate {
                unrecoverable: coarse,
            });
        }
        plan
    }

    /// The fine-grained failure footprint (blast radius) below this parent: the total leaf-node
    /// weight of every escalating child's residue (its internal stopping set). Where
    /// [`degraded_mask`](Self::degraded_mask) says *which* child cells failed, this says *how many
    /// leaf nodes* those failures cost — the detail a parent reports upward alongside a coarse
    /// escalation, which the coarse mask alone would discard (spec §6.3).
    #[must_use]
    pub fn residue_weight(&self) -> u32 {
        self.children
            .iter()
            .filter_map(|c| c.as_ref())
            .map(|s| s.residue.count_ones())
            .sum()
    }

    /// How many coarse child-cell reroutes the parent can afford at integration `phi`
    /// (`Φ → Φ/9` per hop, spec §6.7, V16).
    #[must_use]
    pub fn coarse_budget(phi: f64) -> u32 {
        max_reroute_depth(phi)
    }

    /// Whether the parent absorbed the escalation locally (healed without escalating further up).
    #[must_use]
    pub fn contains_escalation(&self, phi: f64) -> bool {
        !self.heal(phi).escalates()
    }

    /// The coarse reroutes the parent installs — `(failed child, via sibling child)` pairs.
    #[must_use]
    pub fn coarse_reroutes(&self, phi: f64) -> Vec<(usize, usize)> {
        self.heal(phi)
            .actions
            .into_iter()
            .filter_map(|a| match a {
                HealingAction::Reroute { around, via } => Some((around, via)),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_diakrisis::Fault;

    #[test]
    fn a_healthy_stratum_is_healthy() {
        let mut parent = ParentCell::new(0);
        for c in 1..7 {
            parent.observe(c, ChildSummary::healthy());
        }
        assert_eq!(parent.degraded_mask(), 0);
        assert_eq!(parent.diagnose(), Verdict::Healthy);
        assert!(parent.heal(100.0).is_empty());
    }

    #[test]
    fn one_escalating_child_is_localized_and_rerouted_at_the_parent() {
        // Child cell 5 handed up a hyperoval residue; the parent localizes it as a single coarse
        // fault and reroutes around it via the coarse mediator — escalation is *consumed*.
        let mut parent = ParentCell::new(0);
        parent.observe(5, ChildSummary::escalated(0b0001_0110));
        assert_eq!(parent.degraded_mask(), 1 << 5);
        assert_eq!(parent.diagnose(), Verdict::Localized(Fault::Single(5)));

        let plan = parent.heal(100.0);
        assert!(!plan.escalates(), "the parent absorbs it locally");
        let reroutes = parent.coarse_reroutes(100.0);
        assert!(
            reroutes.iter().any(|&(around, _)| around == 5),
            "parent reroutes coarse traffic around child cell 5"
        );
    }

    #[test]
    fn two_escalating_children_resolve_as_a_coarse_pair() {
        let mut parent = ParentCell::new(0);
        parent.observe(1, ChildSummary::escalated(0xFF));
        parent.observe(4, ChildSummary::escalated(0xFF));
        assert_eq!(parent.diagnose(), Verdict::Localized(Fault::Pair(1, 4)));
        assert!(
            parent.contains_escalation(100.0),
            "a coarse pair still heals locally"
        );
    }

    #[test]
    fn a_coarse_hyperoval_escalates_to_the_grandparent() {
        // Four child cells failing as a coarse hyperoval exhaust this tier too → escalate up again.
        let hyperoval = (0u8..=0x7F)
            .find(|&m| m.count_ones() == 4 && is_hyperoval(m))
            .unwrap();
        let mut parent = ParentCell::new((0..7).find(|i| hyperoval & (1 << i) == 0).unwrap());
        for i in 0..7 {
            if hyperoval & (1 << i) != 0 {
                parent.observe(i, ChildSummary::escalated(0xFF));
            }
        }
        assert!(
            parent.heal(100.0).escalates(),
            "a coarse hyperoval escalates to the next stratum"
        );
    }

    #[test]
    fn coarse_budget_follows_the_phi_over_nine_law() {
        // V16: Φ=100 affords 2 coarse child-cell reroutes; Φ=1 affords none.
        assert_eq!(ParentCell::coarse_budget(100.0), 2);
        assert_eq!(ParentCell::coarse_budget(1.0), 0);
    }

    #[test]
    fn a_parent_that_cannot_afford_a_coarse_hop_escalates_instead_of_rerouting() {
        // The budget is enforced, not just reported: the same single escalating child the parent
        // reroutes at Φ=100 must instead escalate at Φ=1, where a coarse hop (Φ→Φ/9) is unaffordable.
        let mut parent = ParentCell::new(0);
        parent.observe(5, ChildSummary::escalated(0b0001_0110));
        assert!(parent.contains_escalation(100.0), "affordable at Φ=100");
        assert!(
            !parent.contains_escalation(1.0),
            "unaffordable at Φ=1 → escalates upward"
        );
        assert!(parent.heal(1.0).escalates());
        assert!(
            parent.coarse_reroutes(1.0).is_empty(),
            "no unaffordable reroute is installed"
        );
    }

    #[test]
    fn residue_weight_reports_the_fine_grained_blast_radius() {
        // The coarse mask says children 1 and 4 failed; the fine residue says 3+1 = 4 leaf nodes.
        let mut parent = ParentCell::new(0);
        parent.observe(1, ChildSummary::escalated(0b0000_0111));
        parent.observe(4, ChildSummary::escalated(0b0001_0000));
        assert_eq!(parent.degraded_mask(), (1 << 1) | (1 << 4));
        assert_eq!(parent.residue_weight(), 4);
    }

    fn is_hyperoval(mask: u8) -> bool {
        if mask.count_ones() != 4 {
            return false;
        }
        for l in 0..7 {
            if let Some(&line) = fanos_geometry::fano::INCIDENCE.get(l)
                && line & mask == line
            {
                return false;
            }
        }
        true
    }
}
