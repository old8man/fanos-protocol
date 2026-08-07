//! The unified topology: ONE connected topology carrying BOTH lenses at once — coherent 7-node Fano
//! cells (via `CellComposition::cell_members`) that also route to each other across the overlay (via
//! `HierAddr`). Before the cell_members generalisation this was impossible: coherence existed only on the base
//! plane's points 0..6, so cells embedded elsewhere reported nothing. Now two cells seated at distinct F31
//! coordinates each run the full DIAKRISIS reflex AND exchange a cross-cell message on the same run.
//!
//! Composed, not hand-assembled (#180). This file is why the migration stalled: the gateway needs a
//! hierarchical PEER, `CellComposition` had no field for one, and so both this and the `cell_members` branch
//! of `compose_engine` stayed unreachable. `hier_peers` is that field.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_field::F31;
use fanos_geometry::{HierAddr, Point, Triple};
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

/// Two cells of seven, seated at distinct F31 points (cell 0 low, cell 1 high — none is a base point 0..6).
const CELL0: [usize; 7] = [3, 17, 42, 100, 250, 500, 900];
const CELL1: [usize; 7] = [5, 19, 44, 102, 252, 502, 902];

fn members(seats: [usize; 7]) -> [Triple; 7] {
    seats.map(|i| Point::<F31>::at(i).coords())
}

fn route_hier_frame(dst: &HierAddr<F31>) -> Vec<u8> {
    let mut body = dst.encode();
    body.extend_from_slice(b"unified");
    let mut frame = Vec::new();
    encode_frame(FrameType::RouteHier.code(), &body, &mut frame);
    frame
}

#[test]
fn two_coherent_cells_report_and_route_across_each_other() {
    let m0 = members(CELL0);
    let m1 = members(CELL1);
    // Overlay: cell 0's gateway is [P0] at transport CELL0[0]; cell 1's is [P1] at transport CELL1[0].
    let g0 = HierAddr::root(Point::<F31>::at(0));
    let g1 = HierAddr::root(Point::<F31>::at(1));
    let g0_tp = Point::<F31>::at(CELL0[0]).coords();
    let g1_tp = Point::<F31>::at(CELL1[0]).coords();

    let mut sim = Sim::new(1);
    // Both cells are COMPOSED, not hand-assembled (#180). The gateway differs from its cell-mates only in
    // carrying a hierarchical address and one peer, and `CellComposition` now expresses both — which is what
    // was missing when `cell_members` was added for these very scenarios and they could not move onto it.
    let member = |members: [Triple; 7]| CellComposition {
        cell_members: Some(members),
        ..CellComposition::overlay_only(config())
    };
    let gateway = |members: [Triple; 7], own: &HierAddr<F31>, peer: &HierAddr<F31>, peer_tp| CellComposition {
        hier_path: Some(own.points().iter().map(Point::coords).collect()),
        hier_peers: vec![(peer.points().iter().map(Point::coords).collect(), peer_tp)],
        ..member(members)
    };
    // Cell 0: seven coherent members; member 0 is also the routing gateway [P0] that knows [P1].
    for (idx, &seat) in CELL0.iter().enumerate() {
        let what =
            if idx == 0 { gateway(m0, &g0, &g1, g1_tp) } else { member(m0) };
        sim.add(compose_engine::<F31>(Point::<F31>::at(seat), &what));
    }
    // Cell 1: seven coherent members; member 0 is the gateway [P1] that knows [P0].
    for (idx, &seat) in CELL1.iter().enumerate() {
        let what =
            if idx == 0 { gateway(m1, &g1, &g0, g0_tp) } else { member(m1) };
        sim.add(compose_engine::<F31>(Point::<F31>::at(seat), &what));
    }

    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(1500));

    // Lens 1 — coherence: both embedded cells report a self-model at every node, and the fleet is healthy.
    let snap = sim.fleet_snapshot();
    assert_eq!(snap.stats.total, 14, "two cells of seven");
    assert_eq!(snap.stats.reporting, 14, "every node in both embedded cells reports coherence");
    assert!(snap.stats.is_healthy(), "both settled cells are healthy: {:?}", snap.stats);

    // Lens 2 — routing: a message from cell 0's gateway reaches cell 1's gateway across the overlay, on
    // the very same running topology.
    sim.inject_frame(g0_tp, g0_tp, route_hier_frame(&g1));
    sim.run_for(Duration::from_millis(2000));
    let delivered = sim.report().notifications.iter().any(|o| {
        o.node == g1_tp && matches!(&o.note, Notification::Delivered { payload, .. } if payload == b"unified")
    });
    assert!(delivered, "the cross-cell message reached cell 1's gateway — routing and coherence coexist");
}
