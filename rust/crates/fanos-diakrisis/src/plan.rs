//! The active healing controller — the **act** phase of the reflexive loop (spec §6.9, §6.7).
//!
//! [`diagnose`](crate::diagnose) *senses*; this module *acts*. A [`Verdict`] plus the cell's own
//! measured integration `Φ` becomes a bounded [`HealingPlan`]: reroute around losses along the
//! locally-recoverable code, regenerate lost shards by peeling, quarantine a structurally
//! inconsistent member, pre-emptively decouple an incipient cascade, or — when the geometry says
//! recovery is impossible or the `Φ`-budget is spent — escalate to the parent cell.
//!
//! Every action is fixed by the geometry and the corpus healing theory, not tuned:
//!
//! * **Reroute** uses the projective LRC (spec §L4, V9): a lost node's data lives on all `q+1`
//!   lines through it, so the querying node reaches it through the co-linear survivor
//!   [`mediator`](fanos_geometry::fano::mediator)`(self, lost)` — one fine hop.
//! * **Repair** is the peeling decode (spec §6.3, V20): rebuild any node that is the unique loss
//!   on some line; iterate. It recovers any `≤ 3` losses and every non-hyperoval `4`-set.
//! * **Escalate** fires exactly on the stopping set (a hyperoval, V20) or when the reroute would
//!   exceed the `Φ → Φ/9` per-coarse-hop budget (spec §6.7, V16) — [`max_reroute_depth`].
//! * **Decouple** is the over-coupling response, distinct from the mere early-warning. On the
//!   equicorrelated stratum `Φ_net = 6r²` is *monotone increasing* in `r` (spec §2.7, V15); the
//!   corpus prescribes **band-keeping**: the collective-subject band `(1/√6, 1/√3]` is the healthy,
//!   self-modelling regime (V19), so nothing is shed while `r` stays inside it. Only once the cell
//!   crosses `1/√3` (`R < 1/3`, over-coupled / groupthink, §18.2) is correlation shed — this
//!   *lowers* `Φ` back into the band and restores `R ≥ 1/3`. The earlier `r > 1/√6` crossing is a
//!   monitor alarm (the observatory's cascade forecast), not a decouple action.
//! * **Quarantine + Escalate** is the corpus Byzantine response (spec §6.2, §6.4, §6.3): the
//!   violated polar class *localizes* the liar (the free sum-rules `r_ij = ρ_{π(i,j)}` hold iff
//!   the wiring is Fano, T-226(vi)); the cell locally distrusts that member and hands it to the
//!   parent for re-provisioning. Local distrust is an operational safeguard — the corpus does not
//!   prove that exclusion alone restores the sum-rules, so the authoritative fix is escalation.

use alloc::vec::Vec;

use fanos_code::peel_fano;
use fanos_geometry::fano;

use crate::healing::max_reroute_depth;
use crate::{Fault, Verdict};

/// One corrective action the cell takes to restore itself.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HealingAction {
    /// Route around a lost node: to reach `around`'s data, contact the co-linear survivor `via`
    /// (LRC availability, spec §L4). One fine hop, no parent involvement.
    Reroute {
        /// The lost node being routed around (Fano point index).
        around: usize,
        /// The co-linear survivor that co-hosts its data (`mediator(self, around)`).
        via: usize,
    },
    /// Regenerate a lost node's shard from a repair line on which it is the only loss (peeling
    /// decode, spec §6.3).
    Repair {
        /// The recovered node (Fano point index).
        node: usize,
        /// The line it was rebuilt from (the one line where it was the unique loss).
        from_line: usize,
    },
    /// Locally distrust a structurally inconsistent (Byzantine) member — the polar class whose
    /// free sum-rule it violated (spec §6.2 localizes it). An operational safeguard pending the
    /// authoritative parental re-provisioning ([`HealingAction::Escalate`], spec §6.4/§6.3).
    Quarantine {
        /// The implicated polar-class / mediator index.
        node: usize,
    },
    /// Shed excess inter-node correlation while every node is still live: the cell is
    /// **over-coupled** (`r > 1/√3`, `R < 1/3`, spec §18.2). Band-keeping back toward `(1/√6, 1/√3]`
    /// — this *lowers* `Φ = 6r²` (V15) out of the over-coupled regime and restores `R ≥ 1/3`, not
    /// raises it. (A cell merely inside the band is a healthy subject and is left untouched.)
    Decouple,
    /// Hand the residue to the parent cell: the listed nodes are an irrecoverable stopping set
    /// (a hyperoval, V20) or lie beyond the `Φ`-budget (spec §6.3 stratification, §6.7).
    Escalate {
        /// Bitmask of nodes the local cell cannot recover on its own.
        unrecoverable: u8,
    },
}

/// A bounded, ordered course of self-healing derived from one diagnostic round.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct HealingPlan {
    /// The corrective actions, in application order (repairs precede the reroutes they enable).
    pub actions: Vec<HealingAction>,
    /// The affordable reroute depth given the cell's current `Φ` (spec §6.7, V16): the number of
    /// coarse boundaries a repair path may cross before reintegration would push `Φ < 1`.
    pub budget_hops: u32,
}

impl HealingPlan {
    /// Whether the plan is a no-op (a healthy cell).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Whether the plan hands any residue to the parent cell.
    #[must_use]
    pub fn escalates(&self) -> bool {
        self.actions
            .iter()
            .any(|a| matches!(a, HealingAction::Escalate { .. }))
    }

    /// The mask of nodes this plan regenerates locally (the recovered set).
    #[must_use]
    pub fn repaired_mask(&self) -> u8 {
        self.actions.iter().fold(0u8, |m, a| match a {
            HealingAction::Repair { node, .. } => m | (1u8 << node),
            _ => m,
        })
    }
}

/// Turn a diagnostic [`Verdict`] into a bounded [`HealingPlan`] for the node at `self_index`,
/// given the current degraded-node mask and the cell's measured integration `phi`.
///
/// The plan is *local first*: it recovers everything the projective LRC can (peeling), reroutes
/// the querying node around each loss via the co-linear survivor, and escalates only the true
/// residue. This is why a cell can report `Escalate` (its 1-of-N decoder saturated at ≥3 faults)
/// yet still heal without the parent — the peeling code recovers where the syndrome decoder cannot.
#[must_use]
pub fn plan_healing(verdict: &Verdict, self_index: usize, degraded: u8, phi: f64) -> HealingPlan {
    let budget_hops = max_reroute_depth(phi);
    let mut actions = Vec::new();

    // The Healthy and unreachable-Localized arms share an empty body but are kept distinct for
    // clarity: `locate` only ever wraps Single/Pair, so the catch-all is defensive, not healthy.
    #[allow(clippy::match_same_arms)]
    match verdict {
        Verdict::Healthy => {}
        Verdict::Localized(Fault::Single(i)) => {
            repair_and_reroute(1u8 << i, self_index, &mut actions);
        }
        Verdict::Localized(Fault::Pair(i, j)) => {
            repair_and_reroute((1u8 << i) | (1u8 << j), self_index, &mut actions);
        }
        // `locate` only ever wraps Single/Pair in `Localized`; other faults are their own verdict.
        Verdict::Localized(_) => {}
        Verdict::Escalate(_) => {
            let lost = degraded & 0x7F;
            let stuck = peel_fano(lost); // the irrecoverable stopping set (0 if all peel)
            let peelable = lost & !stuck;
            repair_and_reroute(peelable, self_index, &mut actions);
            if stuck != 0 {
                actions.push(HealingAction::Escalate {
                    unrecoverable: stuck,
                });
            }
        }
        Verdict::Structural(classes) => {
            // Byzantine forgery: localize (distrust the violated polar classes) AND escalate to
            // the parent for re-provisioning (spec §6.4 + §6.3). Local distrust alone is not a
            // proven restoration of the Fano wiring, so the parent is the authoritative fix.
            let mut residue = 0u8;
            for &c in classes {
                actions.push(HealingAction::Quarantine { node: c });
                if c < fano::N {
                    residue |= 1u8 << c;
                }
            }
            if residue != 0 {
                actions.push(HealingAction::Escalate {
                    unrecoverable: residue,
                });
            }
        }
        Verdict::Partition => {
            // A real connectivity cut (Fiedler λ₂ = 0): no in-cell reroute bridges it. The
            // fragment operates degraded and hands the cut to the parent for cross-cell repair.
            actions.push(HealingAction::Escalate {
                unrecoverable: degraded & 0x7F,
            });
        }
        Verdict::Systemic => {
            // Over-coupled (r > 1/√3, R < 1/3): the cell has climbed past the collective-subject
            // band. Shed correlation to bring r back into (1/√6, 1/√3] and restore R ≥ 1/3 (§18.2).
            actions.push(HealingAction::Decouple);
        }
    }

    HealingPlan {
        actions,
        budget_hops,
    }
}

/// Peel `lost`, emitting a [`HealingAction::Repair`] for each node as it becomes the unique loss
/// on a line, followed by a [`HealingAction::Reroute`] for the querying node when a co-linear
/// survivor is available. Mirrors [`peel_fano`] exactly, so it repairs precisely the recoverable
/// set in a valid dependency order.
fn repair_and_reroute(mut lost: u8, self_index: usize, actions: &mut Vec<HealingAction>) {
    lost &= 0x7F;
    // The diagnosing node is alive by construction; never try to repair or reroute "self".
    if self_index < fano::N {
        lost &= !(1u8 << self_index);
    }
    loop {
        let mut progressed = false;
        for l in 0..fano::N {
            let Some(&line) = fano::INCIDENCE.get(l) else {
                continue;
            };
            let on = line & lost;
            if on.is_power_of_two() {
                let node = on.trailing_zeros() as usize;
                actions.push(HealingAction::Repair { node, from_line: l });
                // Reroute the querying node via the surviving co-linear point, if it lives.
                if let Some(via) = fano::mediator(self_index, node)
                    && (1u8 << via) & lost == 0
                {
                    actions.push(HealingAction::Reroute { around: node, via });
                }
                lost &= !on;
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::vec;

    fn actions_of(v: &Verdict, self_index: usize, degraded: u8) -> Vec<HealingAction> {
        plan_healing(v, self_index, degraded, 100.0).actions
    }

    #[test]
    fn healthy_plans_nothing() {
        assert!(plan_healing(&Verdict::Healthy, 0, 0, 100.0).is_empty());
    }

    #[test]
    fn single_loss_repairs_and_reroutes_via_the_mediator() {
        let acts = actions_of(&Verdict::Localized(Fault::Single(5)), 0, 1 << 5);
        // Exactly one repair of node 5, from one of its lines.
        assert!(
            acts.iter()
                .any(|a| matches!(a, HealingAction::Repair { node: 5, .. }))
        );
        // Rerouted around 5 via the co-linear survivor mediator(0,5).
        let via = fano::mediator(0, 5).unwrap();
        assert!(acts.contains(&HealingAction::Reroute { around: 5, via }));
    }

    #[test]
    fn pair_loss_repairs_both() {
        let acts = actions_of(
            &Verdict::Localized(Fault::Pair(1, 4)),
            0,
            (1 << 1) | (1 << 4),
        );
        let repaired = HealingPlan {
            actions: acts,
            budget_hops: 0,
        }
        .repaired_mask();
        assert_eq!(repaired, (1 << 1) | (1 << 4));
    }

    #[test]
    fn three_recoverable_losses_heal_locally_without_escalating() {
        // Three crashes make the syndrome decoder ESCALATE, yet the peeling LRC still recovers
        // them — the cell heals on its own. (0,1,2 are not a hyperoval.)
        let lost = (1 << 0) | (1 << 1) | (1 << 2);
        assert!(fanos_code::is_recoverable_fano(lost));
        let plan = plan_healing(&Verdict::Escalate(0), 3, lost, 100.0);
        assert_eq!(plan.repaired_mask(), lost, "all three regenerated locally");
        assert!(
            !plan.escalates(),
            "recoverable losses do not reach the parent"
        );
    }

    #[test]
    fn a_hyperoval_is_escalated_as_the_stopping_set() {
        // Find a hyperoval (4 points, no 3 collinear) and a self outside it.
        let mask = (0u8..=0x7F)
            .find(|&m| m.count_ones() == 4 && fanos_code::is_hyperoval_fano(m))
            .unwrap();
        let self_index = (0..7).find(|i| mask & (1 << i) == 0).unwrap();
        let plan = plan_healing(&Verdict::Escalate(0), self_index, mask, 100.0);
        assert!(plan.escalates());
        assert!(
            plan.actions.contains(&HealingAction::Escalate {
                unrecoverable: mask
            }),
            "the whole hyperoval is the irrecoverable residue"
        );
        assert_eq!(plan.repaired_mask(), 0, "nothing in a hyperoval peels");
    }

    #[test]
    fn structural_forgery_localizes_then_escalates() {
        // Corpus §6.4+§6.3: localize (distrust the polar class) AND escalate to the parent.
        let acts = actions_of(&Verdict::Structural(vec![6]), 0, 0);
        assert_eq!(
            acts,
            vec![
                HealingAction::Quarantine { node: 6 },
                HealingAction::Escalate {
                    unrecoverable: 1 << 6
                },
            ]
        );
    }

    #[test]
    fn systemic_early_warning_decouples_before_collapse() {
        let acts = actions_of(&Verdict::Systemic, 0, 0);
        assert_eq!(acts, vec![HealingAction::Decouple]);
    }

    #[test]
    fn partition_escalates_the_fragment() {
        let plan = plan_healing(&Verdict::Partition, 0, 1 << 2, 100.0);
        assert!(plan.escalates());
    }

    #[test]
    fn budget_tracks_the_phi_reroute_law() {
        // Φ=100 affords 2 coarse hops (100/9/9 ≈ 1.23 ≥ 1); Φ=1 affords none (spec §6.7).
        assert_eq!(plan_healing(&Verdict::Healthy, 0, 0, 100.0).budget_hops, 2);
        assert_eq!(plan_healing(&Verdict::Healthy, 0, 0, 1.0).budget_hops, 0);
    }
}
