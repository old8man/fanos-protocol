//! **A node that loses its point descends, and the cell learns where it went** (spec §L0/§L1).
//!
//! The walk and the descent answer the same event. `probe_walk` searches the drawn point's *line* — `q + 1`
//! points of one plane — and the descent is what that search becomes when the line is exhausted. Without it
//! a Fano cell tops out at seven members while `members_for_a_covered_plane(3) = 16` asks for sixteen, and
//! the overflow ends as two nodes bound to one point, which §L0 forbids.
//!
//! What this exercises is the half that has to work over a *cell*, not inside one engine: the proposal, the
//! adoption, and — the part that would silently have done nothing — the announce actually reaching peers.
//! `on_announce` is first-sight-only, and a descendant re-announces from the coordinate it already holds, so
//! under the plain rule every peer drops it as a repeat and the sub-cell address is never learned.
//!
//! The driver's half (which claim lost, and the descriptor signature) is not here: this is the sans-I/O
//! cell, and `Command::ProposeAddress` is exactly the seam where the driver states the one fact it owns.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_field::F2;
use fanos_geometry::fano;
use fanos_runtime::{Command, Config, Duration, Notification, OverlayNode};
use fanos_sim::Sim;

/// A node at Fano point `i` announcing under identity `id`.
fn node(i: usize, id: &[u8]) -> Box<OverlayNode<F2>> {
    Box::new(
        OverlayNode::<F2>::new(fano::point(i), Config::default()).with_identity(id.to_vec()),
    )
}

#[test]
fn a_descended_node_is_learned_by_the_cell_it_re_announces_into() {
    let ids: Vec<Vec<u8>> = (0u8..3).map(alloc_id).collect();
    let mut sim = Sim::new(0x5E_A7ED);
    let seats = [0usize, 2, 5];
    let nodes: Vec<[u32; 3]> =
        seats.iter().zip(&ids).map(|(&i, id)| sim.add(node(i, id))).collect();
    sim.inject_all(&Command::StartHeartbeat);
    // The announce is what carries an overlay address, and only a JOIN emits one.
    sim.inject_all(&Command::Join { info: vec![0xAB] });
    sim.run_for(Duration::from_millis(2000)); // everyone announces once, at depth 1

    // Non-vacuity, in two halves. The cell must already know this node — otherwise the announce below is
    // a first sight and proves nothing about the repeat guard — and it must not yet have been told about any
    // address *change*, or the assertion at the end could be reading the fixture's own setup.
    assert!(
        sim.report().notifications.iter().any(|o| matches!(
            &o.note, Notification::MemberJoined { coord, .. } if *coord == nodes[0]
        )),
        "the fixture is wrong: the cell has not learned the node whose address is about to move"
    );
    assert!(
        learned(&sim, nodes[0]).is_empty(),
        "an address change was reported before one happened — the assertion below would be vacuous"
    );

    // The driver would say this after `settle` came up empty on every point of the line.
    sim.inject(nodes[0], Command::ProposeAddress { contested: true });
    sim.run_for(Duration::from_millis(200));
    let path = sim
        .report()
        .notifications
        .iter()
        .find_map(|o| match &o.note {
            Notification::AddressProposed { path } if o.node == nodes[0] => Some(path.clone()),
            _ => None,
        })
        .expect("the engine must answer with an address");
    assert_eq!(path.len(), 2, "a beaten node is told a sub-cell under the point it wanted");
    assert_eq!(path[0], fano::point(seats[0]).coords(), "…and the sub-cell hangs under that point");
    assert_eq!(
        path[1],
        fanos_primitives::address_point::<F2>(&ids[0], 1).coords(),
        "…derived from its own identity, so no other node can predict or claim it"
    );

    sim.inject(nodes[0], Command::Descend { path: path.clone() });
    sim.run_for(Duration::from_millis(3000));

    assert!(
        learned(&sim, nodes[0]).contains(&path),
        "the descendant re-announced and nobody heard it — `on_announce`'s first-sight rule drops the \
         repeat, so the sub-cell address exists and is unroutable, which is exactly what the descent \
         exists to prevent"
    );
    // The transport coordinate is unchanged: a descendant is reached through an ancestor, not moved.
    assert!(
        sim.nodes().any(|c| c == nodes[0]),
        "the descent must not move the transport coordinate"
    );
}

/// 32 bytes that sort by `k` — enough of an identity for the tie-break, which is an order and not a key.
fn alloc_id(k: u8) -> Vec<u8> {
    vec![k; 32]
}

/// Every overlay address the cell has been told `coord` serves, newest last.
///
/// Read from `PeerAddressed` rather than from any engine's table, because that is the only place the fact
/// is observable — the descendant's transport coordinate does not move, so `MemberJoined` fires once at its
/// first sight and never again.
fn learned(sim: &Sim, coord: [u32; 3]) -> Vec<Vec<[u32; 3]>> {
    sim.report()
        .notifications
        .iter()
        .filter_map(|o| match &o.note {
            Notification::PeerAddressed { coord: c, path } if *c == coord => Some(path.clone()),
            _ => None,
        })
        .collect()
}
