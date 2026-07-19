//! End-to-end **hierarchical routing** across cells, on the real discrete-event simulator (spec §L1).
//!
//! One projective plane holds `N = q²+q+1` nodes; Internet scale comes from *nesting* cells, so a
//! node's overlay address is a path of points (`HierAddr`) while its transport coordinate stays a flat
//! single point — a structured overlay over a flat transport, exactly as an onion address rides on IP.
//!
//! These tests wire three real `OverlayNode` engines with **distinct transport coordinates** but a
//! two-level overlay (`[1]`, `[2]`, `[2,5]`), seed each with the hierarchical routing table it would
//! learn from membership, and drive a `RouteHier` frame through the live sim. The message crosses the
//! top cell (`[1] → [2]`) and then *descends* into the sub-cell (`[2] → [2,5]`) — a genuine multi-hop
//! descent through physically-distinct sub-cell peers, delivered by the same greedy longest-prefix rule
//! (`fanos_geometry::next_hop`) the geometry layer proves converges in `≤ depth` hops. The second test
//! pins the fail-closed property: a routing hole (a missing descent peer) drops, never misroutes or loops.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_field::F2;
use fanos_geometry::{HierAddr, Point};
use fanos_runtime::{Command, Config, Duration, Notification, OverlayNode};
use fanos_sim::Sim;
use fanos_wire::{FrameType, encode_frame};

const PAYLOAD: &[u8] = b"multi-level-hello";

/// Build the `HierAddr(dst) ‖ payload` body inside a `RouteHier` wire frame — what a client hands the
/// entry relay to reach a multi-level destination.
fn route_hier_frame(dst: &HierAddr<F2>, payload: &[u8]) -> Vec<u8> {
    let mut body = dst.encode();
    body.extend_from_slice(payload);
    let mut frame = Vec::new();
    encode_frame(FrameType::RouteHier.code(), &body, &mut frame);
    frame
}

/// Every `Delivered` notification the run produced: `(delivering transport node, payload)`.
fn deliveries(sim: &Sim) -> Vec<(fanos_geometry::Triple, Vec<u8>)> {
    sim.report()
        .notifications
        .iter()
        .filter_map(|o| match &o.note {
            Notification::Delivered { payload, .. } => Some((o.node, payload.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn a_message_descends_two_levels_to_a_sub_cell_node() {
    let mut sim = Sim::new(0x0051_1E44);

    // Overlay addresses (what routing reads) and transport coordinates (what the sim keys on). At
    // depth 1 they coincide; the destination is a genuinely-deeper `[2,5]` seated on its own transport
    // point 5 — decoupled from the gateway's point 2, so both coexist as distinct sim nodes.
    let o_addr = HierAddr::root(Point::<F2>::at(1)); // origin/entry relay, top cell
    let g_addr = HierAddr::root(Point::<F2>::at(2)); // gateway: the sub-cell's root
    let d_addr = HierAddr::from_path(vec![Point::<F2>::at(2), Point::<F2>::at(5)]).unwrap(); // [2,5]

    let o_tp = Point::<F2>::at(1).coords();
    let g_tp = Point::<F2>::at(2).coords();
    let d_tp = Point::<F2>::at(5).coords();

    // The routing tables each node would learn from membership: the entry knows the gateway; the
    // gateway knows the way down to [2,5] and back to [1]; the destination knows its gateway.
    let origin = OverlayNode::<F2>::new(Point::<F2>::at(1), Config::default())
        .with_hier_address(o_addr.clone())
        .with_hier_peer(g_addr.clone(), g_tp);
    let gateway = OverlayNode::<F2>::new(Point::<F2>::at(2), Config::default())
        .with_hier_address(g_addr.clone())
        .with_hier_peer(d_addr.clone(), d_tp)
        .with_hier_peer(o_addr.clone(), o_tp);
    let dest = OverlayNode::<F2>::new(Point::<F2>::at(5), Config::default())
        .with_hier_address(d_addr.clone())
        .with_hier_peer(g_addr.clone(), g_tp);

    let o_id = sim.add(Box::new(origin));
    let g_id = sim.add(Box::new(gateway));
    let d_id = sim.add(Box::new(dest));
    assert_eq!(o_id, o_tp, "the sim keys a node by its transport coordinate");
    assert_ne!(g_id, d_id, "the gateway [2] and the sub-cell node [2,5] are distinct transport nodes");

    // A client hands the entry relay a RouteHier for [2,5]. The address travels unchanged; each hop
    // re-derives its own next step.
    let frame = route_hier_frame(&d_addr, PAYLOAD);
    sim.inject_frame(Point::<F2>::at(3).coords(), o_id, frame);
    sim.run_for(Duration::from_millis(5_000));

    let delivered = deliveries(&sim);
    assert_eq!(delivered.len(), 1, "exactly one delivery — no misroute, drop, or duplication");
    assert_eq!(delivered[0].0, d_id, "delivered at the depth-2 destination's own transport node");
    assert_eq!(delivered[0].1, PAYLOAD, "payload intact across the two-level descent");

    // Convergence: the top-cell hop plus the descent hop — two RouteHier relays, no more.
    assert_eq!(
        sim.report().metrics.frames_sent,
        2,
        "converges in exactly depth hops: [1]→[2] then [2]→[2,5]",
    );
}

#[test]
fn a_routing_hole_fails_closed_without_misdelivery_or_loop() {
    // Same topology, but the gateway never learned the way down to [2,5]. The descent has no next hop,
    // so the gateway drops the frame — it must not deliver to the wrong node, echo it back, or loop.
    let mut sim = Sim::new(0x0000_D20F);

    let o_addr = HierAddr::root(Point::<F2>::at(1));
    let g_addr = HierAddr::root(Point::<F2>::at(2));
    let d_addr = HierAddr::from_path(vec![Point::<F2>::at(2), Point::<F2>::at(5)]).unwrap();
    let o_tp = Point::<F2>::at(1).coords();
    let g_tp = Point::<F2>::at(2).coords();

    let origin = OverlayNode::<F2>::new(Point::<F2>::at(1), Config::default())
        .with_hier_address(o_addr.clone())
        .with_hier_peer(g_addr.clone(), g_tp);
    // The gateway knows only the way back up — not down to the sub-cell.
    let gateway = OverlayNode::<F2>::new(Point::<F2>::at(2), Config::default())
        .with_hier_address(g_addr.clone())
        .with_hier_peer(o_addr.clone(), o_tp);
    let dest = OverlayNode::<F2>::new(Point::<F2>::at(5), Config::default())
        .with_hier_address(d_addr.clone());

    let o_id = sim.add(Box::new(origin));
    let _g_id = sim.add(Box::new(gateway));
    let _d_id = sim.add(Box::new(dest));

    let frame = route_hier_frame(&d_addr, PAYLOAD);
    sim.inject_frame(Point::<F2>::at(3).coords(), o_id, frame);
    sim.run_for(Duration::from_millis(5_000));

    assert!(deliveries(&sim).is_empty(), "a routing hole fails closed — no delivery at all");
    assert_eq!(
        sim.report().metrics.frames_sent,
        1,
        "the entry forwards one hop to the gateway, which then drops — no echo, no loop",
    );
}

#[test]
fn join_announcements_auto_seed_the_hierarchical_routing_table() {
    // The self-organizing property: NO hand-seeded peer tables. Nodes JOIN, each flooding its overlay
    // address, and a hierarchical send to a DESCENDED sub-cell node is delivered — the routing table
    // populated itself from the announcements alone (§L1).
    //
    // The proof is made discriminating by seating the descended node's TRANSPORT coordinate (point 6)
    // away from its overlay leaf point (5): the geometric bootstrap fallback would forward toward
    // point 5 — where no node lives — and drop. Only a table *learned* from the JOIN announcement maps
    // `[2,5] → point 6`, so a successful delivery is proof the announcement seeded the table.
    let mut sim = Sim::new(0x00A2_5EED);

    let a_addr = HierAddr::root(Point::<F2>::at(1));
    let g_addr = HierAddr::root(Point::<F2>::at(2));
    let d_addr = HierAddr::from_path(vec![Point::<F2>::at(2), Point::<F2>::at(5)]).unwrap();

    // Built with overlay addresses but ZERO `with_hier_peer` calls — the tables start empty.
    let entry = OverlayNode::<F2>::new(Point::<F2>::at(1), Config::default())
        .with_hier_address(a_addr.clone());
    let gateway = OverlayNode::<F2>::new(Point::<F2>::at(2), Config::default())
        .with_hier_address(g_addr.clone());
    let dest = OverlayNode::<F2>::new(Point::<F2>::at(6), Config::default()) // transport 6, overlay [2,5]
        .with_hier_address(d_addr.clone());

    let a_id = sim.add(Box::new(entry));
    let _g_id = sim.add(Box::new(gateway));
    let d_id = sim.add(Box::new(dest));
    assert_ne!(d_id, Point::<F2>::at(5).coords(), "the descended node is NOT at its overlay leaf point");

    // Everyone joins: announcements flood, carrying each node's overlay address, and every receiver
    // seeds `(hier → transport coord)`.
    sim.inject_all(&Command::Join { info: b"keys".to_vec() });
    sim.run_for(Duration::from_millis(2_000));

    // Now originate a hierarchical send to the descended node. No peer table was ever hand-configured.
    let frame = route_hier_frame(&d_addr, PAYLOAD);
    sim.inject_frame(Point::<F2>::at(3).coords(), a_id, frame);
    sim.run_for(Duration::from_millis(2_000));

    let delivered = deliveries(&sim);
    assert!(
        delivered.iter().any(|(node, payload)| *node == d_id && payload == PAYLOAD),
        "the descended node [2,5] is reachable purely from its JOIN announcement (auto-seeded table)",
    );
}
