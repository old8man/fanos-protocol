//! Stratified healing end to end: a child cell drives itself into an *irrecoverable* residue (a
//! hyperoval, spec §6.3/V20), escalates, and the **parent tier consumes that escalation** —
//! localizing the failed child cell and rerouting coarse traffic around it (spec §6.7). This is
//! the proof that `Escalate` is no longer "escalation into the void": it is the input to the next
//! stratum, using the byte-for-byte same reflexive loop one tier up.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_core::{ChildSummary, ParentCell};
use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration, Notification};
use fanos_sim::{Sim, spawn_cell};

/// Find a hyperoval point-mask (four points, no three collinear).
fn hyperoval() -> u8 {
    (0u8..=0x7F)
        .find(|&m| {
            m.count_ones() == 4
                && (0..7).all(|l| {
                    fanos_geometry::fano::INCIDENCE
                        .get(l)
                        .is_none_or(|&line| line & m != line)
                })
        })
        .unwrap()
}

#[test]
fn a_child_escalation_is_consumed_and_healed_by_the_parent_tier() {
    // 1. Drive a real child cell into a hyperoval crash → it escalates.
    let mut sim = Sim::new(0x511);
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
    sim.clear_report(); // read only this final round, not the reflex's running diagnosis (#122)
    sim.inject_all(&Command::Diagnose);
    sim.settle();

    // 2. Harvest the residue the child handed up.
    let residue = sim
        .report()
        .notifications
        .iter()
        .find_map(|o| match o.note {
            Notification::Escalated(m) => Some(m),
            _ => None,
        })
        .expect("the child cell escalated an irrecoverable residue");
    assert!(residue != 0, "a hyperoval is a non-empty stopping set");

    // 3. The parent tier consumes it: this child is one of the parent's seven points (index 3).
    let mut parent = ParentCell::new(0);
    parent.observe(3, ChildSummary::escalated(residue));
    // Sibling cells are healthy.
    for c in [1usize, 2, 4, 5, 6] {
        parent.observe(c, ChildSummary::healthy());
    }

    // 4. The parent localizes the failed child cell and reroutes coarse traffic around it.
    assert_eq!(
        parent.diagnose(),
        fanos_diakrisis::Verdict::Localized(fanos_diakrisis::Fault::Single(3)),
    );
    assert!(
        parent.contains_escalation(100.0),
        "the parent absorbs the child's residue"
    );
    let reroutes = parent.coarse_reroutes(100.0);
    assert!(
        reroutes.iter().any(|&(around, _)| around == 3),
        "the parent reroutes around the failed child cell: {reroutes:?}"
    );
}
