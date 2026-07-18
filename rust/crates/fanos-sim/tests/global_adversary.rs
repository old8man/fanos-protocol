//! **G3 — total-control / global adversary: the blast radius is finite and local.**
//!
//! `network-threat-model.md` G3 answers a fraction-of-network (or fully global) adversary with a
//! *bounded blast radius*: per-cell ISS absorbs damage locally, and where a cell's budget is exceeded,
//! escalation carries the residue at most `⌊log₉Φ⌋` tiers before reintegration would push `Φ < 1`
//! (`ddos-homeostasis.md §7`, the `1/9` `PHI_CONTRACTION`, T-226/V16). The *analytic* form of that
//! bound — `max_reroute_depth(Φ) = ⌊log₉Φ⌋`, total and DoS-safe — is already proven in
//! `fanos-diakrisis` (`healing.rs`, `props.rs::healing_budget`). This file supplies the **empirical**
//! half the threat model asks for: on the real engine and the real stratum, an adversary's damage
//!
//!   1. stays **local** — it never drags an untouched node/cell unhealthy, and a tier only ever
//!      reroutes *around the attacked cells*, never the honest ones;
//!   2. is **contained within a finite number of tiers** — one for a within-decoder attack, one more
//!      when the decoder saturates, and no further; and
//!   3. respects the **`⌊log₉Φ⌋` budget gate** — a tier installs a coarse reroute only when its
//!      coherence can afford one (`Φ ≥ 9`), escalating rather than disintegrating itself below that.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_core::{ChildSummary, ParentCell};
use fanos_diakrisis::healing::max_reroute_depth;
use fanos_diakrisis::{Fault, HealingAction, Verdict};
use fanos_field::F2;
use fanos_geometry::fano;
use fanos_runtime::{Command, Config, Duration, Notification};
use fanos_sim::{Sim, spawn_cell};

/// A hyperoval point-mask (four points, no three collinear) — an irrecoverable stopping set (V20), the
/// smallest attack that forces a cell past its own decoder into escalation.
fn hyperoval() -> u8 {
    (0u8..=0x7F)
        .find(|&m| {
            m.count_ones() == 4
                && (0..7).all(|l| {
                    fano::INCIDENCE
                        .get(l)
                        .is_none_or(|&line| line & m != line)
                })
        })
        .unwrap()
}

/// Drive a **real** Fano cell on the simulator past its budget (an adversary crashing a hyperoval) and
/// harvest the coarse residue it hands up — genuine ground truth for the stratum tests below, not a
/// hand-authored mask.
fn real_escalation_residue(seed: u64) -> u8 {
    let mut sim = Sim::new(seed);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    let mask = hyperoval();
    for (i, &node) in cell.iter().enumerate() {
        if mask & (1 << i) != 0 {
            sim.crash(node);
        }
    }
    sim.run_for(Duration::from_millis(3000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();
    sim.report()
        .notifications
        .iter()
        .find_map(|o| match o.note {
            Notification::Escalated(m) => Some(m),
            _ => None,
        })
        .expect("a hyperoval-crashed cell escalates an irrecoverable residue")
}

/// The coarse residue a parent hands to its grandparent, if it escalated.
fn escalated_residue(parent: &ParentCell, phi: f64) -> Option<u8> {
    parent.heal(phi).actions.into_iter().find_map(|a| match a {
        HealingAction::Escalate { unrecoverable } => Some(unrecoverable),
        _ => None,
    })
}

/// A parent tier (self-index 0) over children `1..7`, with `attacked` children escalated by `residue`.
fn parent_under_attack(residue: u8, attacked: &[usize]) -> ParentCell {
    let mut parent = ParentCell::new(0);
    for c in 1..7 {
        if attacked.contains(&c) {
            parent.observe(c, ChildSummary::escalated(residue));
        } else {
            parent.observe(c, ChildSummary::healthy());
        }
    }
    parent
}

/// Point indices a verdict accuses (empty unless it is a node localization).
fn accused(verdict: &Verdict) -> Vec<usize> {
    match verdict {
        Verdict::Localized(Fault::Single(i)) => vec![*i],
        Verdict::Localized(Fault::Pair(i, j)) => vec![*i, *j],
        _ => Vec::new(),
    }
}

/// Per-cell locality: an attack is *attributed to exactly the nodes it seized* — the syndrome never
/// implicates an honest node. The damage is localizable and confined to the attacker's own footprint,
/// which is what lets the tier above (and the reroute) target only the attacked cells.
#[test]
fn an_attack_is_localized_to_exactly_the_seized_nodes() {
    let mut sim = Sim::new(0x600C);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    // The adversary seizes two of the seven nodes (within the single-cell decoder's power).
    sim.crash(cell[1]);
    sim.crash(cell[4]);
    sim.run_for(Duration::from_millis(3000));
    sim.inject_all(&Command::Diagnose);
    sim.settle();

    // The attacked pair is localized exactly …
    assert!(
        sim.report()
            .any_verdict(&Verdict::Localized(Fault::Pair(1, 4))),
        "the cell localizes exactly the two attacked nodes"
    );
    // … and no honest survivor is ever accused, for any verdict any survivor reported. An attacker
    // cannot make the cell blame a node it did not seize — the blast is confined to its own footprint.
    for (_, v) in sim.report().verdicts() {
        for a in accused(v) {
            assert!(a == 1 || a == 4, "an honest node {a} was accused (blast escaped its footprint)");
        }
    }
}

/// A bounded cross-cell adversary is absorbed at the parent tier (blast radius one tier), and the
/// containment is **local**: the tier reroutes only around the attacked cells, never the honest ones.
#[test]
fn a_bounded_adversary_is_contained_at_the_parent_and_stays_local() {
    let residue = real_escalation_residue(0x6001);
    let attacked = [2usize, 5];
    let phi = 100.0; // a healthy network; ⌊log₉100⌋ = 2 coarse hops afforded
    let parent = parent_under_attack(residue, &attacked);

    // Two escalating child cells are within the coarse decoder and the Φ budget → contained here.
    assert!(
        parent.contains_escalation(phi),
        "a two-cell adversary is absorbed at the parent (blast radius = 1 tier)"
    );
    // The diagnosis names exactly the attacked cells (no honest cell implicated).
    let mut named = accused(&parent.diagnose());
    named.sort_unstable();
    assert_eq!(named, attacked, "the parent localizes exactly the attacked cells");
    // Locality of the response: every reroute routes *around* an attacked cell, *via* an honest one —
    // an honest cell is never the casualty of someone else's attack.
    let reroutes = parent.coarse_reroutes(phi);
    assert!(!reroutes.is_empty(), "the parent installs coarse reroutes");
    for (around, via) in reroutes {
        assert!(attacked.contains(&around), "rerouted around an un-attacked cell {around}");
        assert!(!attacked.contains(&via), "rerouted via an attacked cell {via}");
    }
}

/// When the adversary drives a tier into an *irrecoverable* coarse stopping set (a hyperoval of child
/// cells — the peeling decoder cannot recover it either), the residue escalates **one** more tier,
/// where the grandparent contains it. The blast radius is two tiers and no further: still finite.
///
/// (A merely large-but-peelable coarse fault does NOT escalate — the peeling decoder recovers it in
/// place, spec §6.3 — so forcing escalation genuinely requires a stopping set, not just `≥3` cells.)
#[test]
fn an_irrecoverable_adversary_escalates_one_more_tier_but_no_further() {
    let residue = real_escalation_residue(0x6002);
    let hov = hyperoval(); // four attacked child cells, no three collinear: an irrecoverable residue
    let self_index = (0..7).find(|i| hov & (1 << i) == 0).expect("a point outside the hyperoval");
    let phi = 100.0;

    let mut parent = ParentCell::new(self_index);
    for c in 0..7 {
        if c == self_index {
            continue;
        }
        if hov & (1 << c) != 0 {
            parent.observe(c, ChildSummary::escalated(residue));
        } else {
            parent.observe(c, ChildSummary::healthy());
        }
    }

    assert!(
        matches!(parent.diagnose(), Verdict::Escalate(_)),
        "a hyperoval of attacked cells saturates the parent decoder"
    );
    assert!(
        !parent.contains_escalation(phi),
        "the parent cannot absorb an irrecoverable residue and escalates (blast radius grows to 2 tiers)"
    );

    // The grandparent tier consumes the parent's coarse residue and contains it — the ripple stops.
    let coarse = escalated_residue(&parent, phi).expect("the parent handed up a coarse residue");
    let mut grand = ParentCell::new(0);
    grand.observe(2, ChildSummary::escalated(coarse)); // this parent is one point of the grandparent
    for c in [1usize, 3, 4, 5, 6] {
        grand.observe(c, ChildSummary::healthy());
    }
    assert!(
        grand.contains_escalation(phi),
        "the grandparent absorbs the escalated residue — the blast radius is 2 tiers, bounded"
    );
}

/// The empirical boundary of the `⌊log₉Φ⌋` bound: a tier installs a coarse reroute only when its
/// coherence affords one (`Φ ≥ 9` ⟺ `coarse_budget ≥ 1` ⟺ `⌊log₉Φ⌋ ≥ 1`). Below that, even a single
/// attacked cell escalates — an unaffordable reroute would itself drive `Φ → Φ/9 < 1` and disintegrate
/// the tier. The plan's own `budget_hops` equals the analytic `max_reroute_depth(Φ)`.
#[test]
fn the_reroute_budget_gate_is_the_analytic_log9_bound() {
    let residue = real_escalation_residue(0x6003);
    let contains_at = |phi: f64| parent_under_attack(residue, &[3]).contains_escalation(phi);

    // Below Φ = 9 the budget is 0: a single-cell fault cannot be rerouted and escalates instead.
    assert_eq!(max_reroute_depth(8.9), 0, "⌊log₉ 8.9⌋ = 0");
    assert!(
        !contains_at(8.9),
        "below Φ=9 the parent cannot afford a reroute (budget 0) and escalates"
    );
    // At Φ = 9 the budget is 1: exactly one coarse hop is affordable, so the fault is contained.
    assert_eq!(max_reroute_depth(9.0), 1, "⌊log₉ 9⌋ = 1");
    assert!(
        contains_at(9.0),
        "at Φ=9 the parent can afford one coarse reroute and contains the fault"
    );

    // The plan reports its affordable depth as exactly the analytic bound, at several coherences.
    for &phi in &[1.0f64, 9.0, 82.0, 1000.0] {
        let plan = parent_under_attack(residue, &[3]).heal(phi);
        assert_eq!(
            plan.budget_hops,
            max_reroute_depth(phi),
            "the plan's affordable reroute depth is ⌊log₉Φ⌋ at Φ={phi}"
        );
    }
}
