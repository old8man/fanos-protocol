//! Threat-model **B2 — eclipse resistance** (docs/network-threat-model.md §B2).
//!
//! ## The argument
//!
//! An eclipse attack isolates a victim by controlling *which peers it talks to*: surround it with
//! attacker-run neighbours and you mediate its entire view of the network. Against a DHT whose
//! routing table is **discovered** — learned from whichever peers happen to answer a lookup walk —
//! this is a classic attack: poison the walk and the victim adopts attacker peers as neighbours.
//!
//! FANOS deletes the attack surface *structurally*, not by hardening the discovery walk (there is
//! none). A node's cell neighbours are **derived** from its own projective coordinate.
//! `OverlayNode::<F>::new` (crates/fanos-runtime/src/overlay.rs) builds the peer set exactly once,
//! as
//!
//! ```text
//!     peers(coord) = ( ⋃_{L ∈ lines_through(coord)} points_on(L) ) \ {coord}
//! ```
//!
//! i.e. precisely the points **co-linear** with `coord`. By the Steiner property of `PG(2, q)` any
//! two distinct points lie on a unique common line, so inside a cell this set is *every other node*:
//! the neighbour / witness set is the whole cell, pinned by geometry. Crucially the set is
//! immutable after construction — in the whole engine `peers` is only ever *written* by the
//! `entry().or_insert` in `new`; every later access is a read or a liveness-timestamp update
//! (`last_seen`/`reported_down`), never a key insert or remove. Received frames touch only those
//! timestamps, the corroboration-witness map, and the **separate** discovered-membership view — not
//! the neighbour set. So an attacker who merely *talks to* a victim can neither add itself to, nor
//! evict a real node from, that victim's neighbour set.
//!
//! Coordinates are self-certifying: `coordinate = MapToPoint(H(cert))` (spec §L0). To *be* a
//! specific neighbour of the victim you must own that exact coordinate — and you cannot choose it,
//! it is the hash of your certificate.
//!
//! ## The reduction (stated precisely)
//!
//! To eclipse a victim `v` you must remove a true co-linear witness `w` from `v`'s corroborated view
//! (or substitute an attacker node for it). But:
//!
//! 1. `v`'s neighbour set is a pure function of `v`'s coordinate — no frame can change it
//!    (Property 1). So a witness cannot be *added* or *swapped*; only *silenced*.
//! 2. A witness stays alive in `v`'s view while a **quorum** of the *other* co-linear witnesses
//!    corroborate it (spec §6.4). Forged "peer-gone" gossip cannot subtract liveness — the health
//!    view only ever *adds* fresh observations, and `v` trusts its own eyes first — and cutting the
//!    direct `v↔w` link is routed around by the rest of the witness set (Property 2).
//!
//! Hence the *only* way to remove `w` from `v`'s view is to take `w`'s coordinate offline: crash or
//! **own** the node at that projective point. Owning it means presenting a certificate whose hash
//! maps to `w`'s point — coordinate seizure. Therefore
//!
//! ```text
//!     eclipse(v)  ⇒  control of v's co-linear coordinate set  ⇒  B1 coordinate-seizure cost.
//! ```
//!
//! Eclipse does not reduce to a cheap network-level trick; it is exactly as expensive as seizing the
//! victim's neighbourhood coordinate-by-coordinate — the B1 Sybil / coordinate cost. There is no
//! independent B2 weakness.
//!
//! ## What is validated on the simulator
//!
//! * **Property 1 — neighbour-determinism.**
//!   [`a_nodes_neighbours_are_exactly_the_colinear_points_of_its_coordinate`] asserts the running
//!   engine's neighbour set equals, node-for-node, the co-linear points of its coordinate computed
//!   independently from the plane (`PG(2, 2)` and `PG(2, 7)`).
//!   [`no_forged_frame_flood_can_add_or_remove_a_neighbour`] floods a node with the exact forged
//!   `Input::Message`s the sim's [`Sim::inject_frame`] delivers (false-topology announces, forged
//!   health-views, garbage, unsolicited control) and shows the neighbour set is byte-identical
//!   afterwards, while the *discovered* membership view is a distinct, writable map.
//! * **Property 2 — eclipse-attempt fails.**
//!   [`a_forged_frame_flood_does_not_eclipse_the_target_from_its_live_neighbours`] and
//!   [`a_targeted_link_cut_is_defeated_by_quorum_witness_corroboration`] run a full Fano cell and
//!   show the target is not deceived: its true co-linear witnesses stay live in its view via the
//!   quorum-witness path, under forged floods and a targeted link cut.
//!   [`severing_a_true_neighbour_requires_seizing_its_coordinate`] is the reduction made concrete:
//!   only crashing / owning the witness's coordinate severs it from the target.

#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

use std::collections::BTreeSet;

use fanos_diakrisis::{Fault, Verdict};
use fanos_field::{F2, F7, Field};
use fanos_geometry::{HierAddr, Plane, Point, Triple};
use fanos_runtime::{Command, Config, Duration, Engine, Input, Instant, OverlayNode};
use fanos_sim::{Report, Sim, spawn_cell};
use fanos_wire::{FrameType, encode_frame};

// --- forged-frame constructors: exactly the bytes an adversary puts on the wire (see byzantine.rs) ---

/// Encode a wire frame of `ty` with `body`.
fn frame(ty: FrameType, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(ty.code(), body, &mut out);
    out
}

/// A forged `Announce` claiming coordinate `coord` exists with attacker-chosen `info` — the
/// adversary asserting false topology / membership. Body layout is `coord(12) ‖ hier(1+depth×12) ‖
/// id_len(2) ‖ id ‖ sig_len(2) ‖ sig ‖ info` (spec §7.8, §L1, §80). The adversary announces
/// `hier = root(coord)` for a valid coordinate (a self-consistent depth-1 lie), or a placeholder
/// overlay address when the coordinate itself is the impossible-point being tested; `id` and `sig` are
/// empty (this cell does not require self-certified membership), so the receiver's coordinate check is
/// what decides.
fn forged_announce(coord: Triple, info: &[u8]) -> Vec<u8> {
    let hier =
        Point::<F2>::new(coord).map_or_else(|| HierAddr::root(Point::<F2>::at(0)), HierAddr::root);
    let hier_bytes = hier.encode();
    let mut body = Vec::with_capacity(12 + hier_bytes.len() + 2 + info.len());
    for word in coord {
        body.extend_from_slice(&word.to_be_bytes());
    }
    body.extend_from_slice(&hier_bytes);
    body.extend_from_slice(&0u16.to_be_bytes()); // id_len = 0 (self-certification off in this test)
    body.extend_from_slice(&0u16.to_be_bytes()); // sig_len = 0
    body.extend_from_slice(info);
    frame(FrameType::Announce, &body)
}

/// A forged `DiagGossip` health-view where every one of the 7 Fano points reads `byte`:
/// `0xFF` = "I can see no-one" (the strongest eclipse lie), `0x00` = "everyone is fresh".
fn forged_health_view(byte: u8) -> Vec<u8> {
    frame(FrameType::DiagGossip, &[byte; 14])
}

/// The co-linear neighbour set of `coord`, computed independently from the plane's incidence
/// geometry — the union of the points on every line through `coord`, minus `coord` itself. This is
/// the set `OverlayNode::new` derives; the tests assert the engine reproduces it exactly.
fn colinear_neighbours<F: Field>(coord: Point<F>) -> BTreeSet<Triple> {
    let mut set = BTreeSet::new();
    for line in Plane::<F>::lines_through(coord) {
        for member in Plane::<F>::points_on(line) {
            if member != coord {
                set.insert(member.coords());
            }
        }
    }
    set
}

/// Every verdict the node at `coord` reported over the run, newest last. A single `Diagnose`
/// produces exactly one, so callers assert against `vec![..]`.
fn verdicts_of(report: &Report, coord: Triple) -> Vec<Verdict> {
    report
        .verdicts()
        .filter(|(who, _)| *who == coord)
        .map(|(_, v)| v.clone())
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Property 1 — neighbour-determinism.
// ---------------------------------------------------------------------------------------------

/// A node's neighbour set is *exactly* the co-linear points of its coordinate — a deterministic
/// function of its own address, independent of any peer. We assert it directly from the plane, for
/// every node of the base Fano cell `PG(2, 2)` and of a larger cell `PG(2, 7)`.
fn assert_neighbours_are_colinear<F: Field>() {
    for coord in Plane::<F>::points() {
        let node = OverlayNode::<F>::new(coord, Config::default());
        let got: BTreeSet<Triple> = node.neighbours().collect();

        // (a) Derivation identity: the engine's peers equal the co-linear set built from incidence.
        assert_eq!(
            got,
            colinear_neighbours::<F>(coord),
            "neighbours are the co-linear points of the coordinate"
        );

        // (b) Independent characterization (Steiner): in a projective plane every *other* point is
        // co-linear with `coord`, so the neighbour set is the whole rest of the cell — nothing an
        // attacker can be "outside".
        let all_others: BTreeSet<Triple> = Plane::<F>::points()
            .map(|p| p.coords())
            .filter(|&c| c != coord.coords())
            .collect();
        assert_eq!(
            got, all_others,
            "the neighbour set is every other node of the cell"
        );

        // (c) Each neighbour genuinely shares a unique line with `coord`, proven from the geometry
        // primitives (join + incidence) rather than from the construction formula.
        for &n in &got {
            let peer = Point::<F>::new(n).unwrap();
            let line = coord.join(&peer).unwrap();
            assert!(
                coord.is_on(&line) && peer.is_on(&line),
                "the coordinate and its neighbour lie on a common line",
            );
        }
    }
}

#[test]
fn a_nodes_neighbours_are_exactly_the_colinear_points_of_its_coordinate() {
    assert_neighbours_are_colinear::<F2>(); // the base Fano cell (7 nodes)
    assert_neighbours_are_colinear::<F7>(); // a larger cell (57 nodes) — the property is generic
}

#[test]
fn no_forged_frame_flood_can_add_or_remove_a_neighbour() {
    // Driving `engine.step(now, Input::Message{ from, frame })` directly is byte-for-byte what the
    // sim's `inject_frame` delivers to an engine (sim.rs: Event::Deliver → step(Input::Message)),
    // and it is the only way to read the neighbour set back out (it is internal engine state). So we
    // flood the engine here and observe the invariant directly.
    let coord = Point::<F2>::at(0);
    let mut node = OverlayNode::<F2>::new(coord, Config::default());
    let before: BTreeSet<Triple> = node.neighbours().collect();

    // "from" an authenticated peer (the transport authenticates the sender — see byzantine.rs).
    let byz = Point::<F2>::at(1).coords();
    let seen_member = Point::<F2>::at(2).coords();

    // A grab-bag of forged frames claiming false topology / liveness, plus malformed bytes.
    let forged: Vec<Vec<u8>> = vec![
        forged_announce(seen_member, b"ATTACKER-KEYS"), // "member X has these (attacker) keys"
        forged_announce(Point::<F2>::at(4).coords(), b"ATTACKER-KEYS"),
        forged_announce([0, 0, 0], b"GHOST-NODE"), // the zero vector is not a projective point
        forged_announce([7, 7, 7], b"GHOST-NODE"), // out of range for GF(2): an impossible node
        forged_health_view(0xFF),                  // "your whole cell is gone"
        forged_health_view(0x00),                  // "your whole cell is fresh"
        vec![0xDE, 0xAD, 0xBE, 0xEF],              // garbage — canonical decode failure
        frame(FrameType::Route, b"flood"),         // unsolicited data relay
        frame(FrameType::Ping, &[]),               // unsolicited control
    ];

    let mut t = 1u64;
    for _ in 0..20 {
        for f in &forged {
            node.step(
                Instant(t),
                Input::Message {
                    from: byz,
                    frame: f.clone(),
                },
            );
            t += 1;
        }
    }

    // The DERIVED neighbour set is untouched: no forged frame added or removed a peer.
    let after: BTreeSet<Triple> = node.neighbours().collect();
    assert_eq!(
        after, before,
        "a forged frame flood cannot alter the neighbour set"
    );
    assert_eq!(
        after,
        colinear_neighbours::<F2>(coord),
        "the neighbour set is still exactly the co-linear points of the coordinate",
    );

    // The DISCOVERED membership view is a *distinct*, writable map — the adversary reached it — yet
    // the neighbour set above is invariant: adjacency is computed, not announced. And an impossible
    // coordinate is rejected outright, so no "ghost node" can even be recorded.
    let members: BTreeSet<Triple> = node.members().map(|(c, _)| c).collect();
    assert!(
        members.contains(&seen_member),
        "a forged announce can write the discovered membership view",
    );
    assert!(
        !members.contains(&[0, 0, 0]) && !members.contains(&[7, 7, 7]),
        "an impossible coordinate is never accepted as a member",
    );
    assert!(
        members.is_disjoint(&BTreeSet::from([[0u32, 0, 0], [7, 7, 7]])),
        "no ghost coordinate leaked into the view",
    );
}

// ---------------------------------------------------------------------------------------------
// Property 2 — an eclipse attempt fails; only coordinate seizure severs a witness.
// ---------------------------------------------------------------------------------------------

/// Bring a full Fano cell (7 nodes) to steady state with all nodes exchanging heartbeats.
fn established_fano_cell(seed: u64) -> (Sim, Vec<Triple>) {
    let mut sim = Sim::new(seed);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    (sim, cell)
}

#[test]
fn a_forged_frame_flood_does_not_eclipse_the_target_from_its_live_neighbours() {
    // The adversary floods the target with forged frames but crashes / owns no coordinate. Because
    // the target's six co-linear neighbours keep heartbeating and it trusts its own direct
    // observation, forged "your peers are gone" gossip cannot subtract their liveness.
    let (mut sim, cell) = established_fano_cell(0xEC1);
    let target = cell[0];

    for _ in 0..8 {
        sim.inject_frame(cell[1], target, forged_health_view(0xFF)); // "I can see no-one"
        sim.inject_frame(cell[2], target, forged_announce([0, 0, 0], b"GHOST")); // impossible node
        sim.inject_frame(cell[1], target, vec![0xDE, 0xAD, 0xBE, 0xEF]); // garbage
        sim.run_for(Duration::from_millis(200));
    }

    sim.inject(target, Command::Diagnose);
    sim.settle();
    assert_eq!(
        verdicts_of(sim.report(), target),
        vec![Verdict::Healthy],
        "the target still sees all six co-linear neighbours alive; forged frames cannot deceive it",
    );
}

#[test]
fn a_targeted_link_cut_is_defeated_by_quorum_witness_corroboration() {
    // The sharpest attack short of seizing a coordinate: cut the target's *direct* link to one
    // witness while it stays alive and heard by the rest of the cell, and reinforce with forged
    // "the witness is gone" gossip. The target loses its own view of the witness — yet the other
    // co-linear members corroborate its liveness (the quorum-witness path, spec §6.4), so the
    // eclipse fails.
    let (mut sim, cell) = established_fano_cell(0xEC2);
    let target = cell[0];
    let witness = cell[3];

    // A single-edge cut, realized by two OVERLAPPING reachability groups:
    //   A = cell \ {witness}  (holds target, not witness)
    //   B = cell \ {target}   (holds witness, not target)
    // reachable(a, b) ⇔ some group holds both ⇒ every pair reaches EXCEPT (target, witness).
    let group_a: BTreeSet<Triple> = cell.iter().copied().filter(|&c| c != witness).collect();
    let group_b: BTreeSet<Triple> = cell.iter().copied().filter(|&c| c != target).collect();
    sim.network_mut().partition([group_a, group_b]);

    // Well past the liveness timeout, so the target's own (now-severed) observation of the witness
    // goes stale and must rely on corroboration.
    for _ in 0..12 {
        sim.inject_frame(cell[1], target, forged_health_view(0xFF)); // "the witness is gone"
        sim.inject_frame(cell[1], target, vec![0xBA, 0xD0]); // garbage
        sim.run_for(Duration::from_millis(300));
    }

    sim.inject(target, Command::Diagnose);
    sim.settle();
    assert_eq!(
        verdicts_of(sim.report(), target),
        vec![Verdict::Healthy],
        "quorum-witness corroboration keeps the cut-off witness alive in the target's view",
    );
}

#[test]
fn severing_a_true_neighbour_requires_seizing_its_coordinate() {
    // The reduction, made concrete. Forged floods and a targeted link cut both FAIL above. The only
    // lever that removes a co-linear witness from the target's corroborated view is taking that
    // witness's COORDINATE offline — crashing (or owning) the node at that projective point. That is
    // coordinate seizure: the B1 cost, not a network-level trick.
    let (mut sim, cell) = established_fano_cell(0xEC3);
    let target = cell[0];

    sim.crash(cell[3]); // seize / kill the co-linear coordinate at Fano index 3
    sim.run_for(Duration::from_millis(3000)); // now no node hears it → no quorum can corroborate

    sim.inject(target, Command::Diagnose);
    sim.settle();
    assert_eq!(
        verdicts_of(sim.report(), target),
        vec![Verdict::Localized(Fault::Single(3))],
        "only removing the witness's coordinate severs it from the target — eclipse ⇒ B1 seizure",
    );
}
