//! The parent tier on a UNIFIED topology: an embedded parent cell (seated at arbitrary coordinates via
//! `CellComposition::cell_members`) receives a child cell's escalation and runs the parent-stratum reflex —
//! folding the failed child into its `ParentCell` (self_index derived from its real members) and acting.
//! Before the cell_members refactor an embedded node had `self_index == None`, so `on_cell_escalate` bailed
//! immediately; now the whole parent stratum runs over a cell seated anywhere.
//!
//! Composed rather than hand-assembled (#180): the parent stratum is a claim about a CELL, and a cell the
//! simulator stands up must be the engine a deployment runs, not a bare overlay.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_field::F31;
use fanos_geometry::{Point, Triple};
use fanos_node::composition::{CellComposition, compose_engine};
use fanos_runtime::{Command, Config, Duration, Notification};
use fanos_sim::Sim;
use fanos_wire::{FrameType, encode_frame};

fn config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

/// Seven arbitrary F31 seats for the parent cell — none on the base points 0..6.
const PARENT: [usize; 7] = [7, 21, 55, 111, 300, 600, 950];

/// The `CellEscalate` body: `child_index(2, big-endian) ‖ residue ‖ ttl`.
///
/// **Two bytes, and this file is exactly the reason** (#110). It runs on `F31` — 993 points — where the old
/// one-byte index aliased any child above 255 onto a different, *valid* sibling that the receiver's bounds
/// check happily accepted. `usize` here rather than `u8` so a future case can name a child this plane really
/// has, instead of the helper quietly capping what the test is able to say.
fn cell_escalate_frame(child_index: usize, residue: u8, ttl: u8) -> Vec<u8> {
    let mut f = Vec::new();
    let idx = u16::try_from(child_index).expect("a child index fits the wire field").to_be_bytes();
    encode_frame(FrameType::CellEscalate.code(), &[idx[0], idx[1], residue, ttl], &mut f);
    f
}

#[test]
fn an_embedded_parent_runs_the_parent_stratum_reflex_on_a_child_escalation() {
    let members: [Triple; 7] = PARENT.map(|i| Point::<F31>::at(i).coords());
    let mut sim = Sim::new(1);
    let mut coords = Vec::new();
    let what = CellComposition { cell_members: Some(members), ..CellComposition::overlay_only(config()) };
    for &seat in &PARENT {
        coords.push(sim.add(compose_engine::<F31>(Point::<F31>::at(seat), &what, None)));
    }
    // Settle the parent cell to health so its members carry a real Φ (self_index is set from cell_members).
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(1500));
    sim.clear_report();

    // A child cell hanging off parent position 2 escalates an irrecoverable residue to parent member 0.
    sim.inject_frame(Point::<F31>::at(3).coords(), coords[0], cell_escalate_frame(2, 0b0000_0111, 4));
    sim.settle();

    // The embedded parent HANDLED it: it either absorbed (coarse reroute/repair around the failed child)
    // or, more typically at cell-scale Φ, escalated the residue onward. Either way the parent-stratum
    // reflex ran on a cell seated off the base points — impossible before (self_index would be None).
    let acted = sim.report().notifications.iter().any(|o| {
        o.node == coords[0]
            && matches!(
                &o.note,
                Notification::Escalated(_) | Notification::Rerouted { .. } | Notification::Repaired(_)
            )
    });
    assert!(acted, "the embedded parent processed the child escalation");

    // If it did install a coarse reroute or repair, the target is a REAL parent member (generalised via
    // cell_coord), never a stray base point 0..6.
    for o in &sim.report().notifications {
        match &o.note {
            Notification::Rerouted { around, via } => {
                assert!(members.contains(around) && members.contains(via), "coarse reroute uses real members");
            }
            Notification::Repaired(c) => {
                assert!(members.contains(c), "coarse repair marks a real member: {c:?}");
            }
            _ => {}
        }
    }
}
