//! The parent tier on a UNIFIED topology: an embedded parent cell (seated at arbitrary coordinates via
//! `with_cell_members`) receives a child cell's escalation and runs the parent-stratum reflex — folding
//! the failed child into its `ParentCell` (self_index derived from its real members) and acting. Before
//! the cell_members refactor an embedded node had `self_index == None`, so `on_cell_escalate` bailed
//! immediately; now the whole parent stratum runs over a cell seated anywhere.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_field::F31;
use fanos_geometry::{Point, Triple};
use fanos_runtime::{Command, Config, Duration, Notification, OverlayNode};
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

fn cell_escalate_frame(child_index: u8, residue: u8, ttl: u8) -> Vec<u8> {
    let mut f = Vec::new();
    encode_frame(FrameType::CellEscalate.code(), &[child_index, residue, ttl], &mut f);
    f
}

#[test]
fn an_embedded_parent_runs_the_parent_stratum_reflex_on_a_child_escalation() {
    let members: [Triple; 7] = PARENT.map(|i| Point::<F31>::at(i).coords());
    let mut sim = Sim::new(1);
    let mut coords = Vec::new();
    for &seat in &PARENT {
        coords.push(sim.add(Box::new(
            OverlayNode::<F31>::new(Point::<F31>::at(seat), config()).with_cell_members(members),
        )));
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
