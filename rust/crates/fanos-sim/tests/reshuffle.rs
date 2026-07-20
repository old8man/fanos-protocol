//! Per-epoch coordinate RESHUFFLE (spec §L3 "epoch reshuffle", §3.2; task #102). Each epoch a node
//! re-seats at a fresh VRF coordinate for anti-eclipse PLACEMENT, while storage stays anchored to the
//! epoch-stable content points `MapToPoint(H(k))` (§L4) — the "fixed points, flowing nodes" model. The
//! property that must hold, and the one audit C2 warned a naive reshuffle would break: **every stored key
//! stays retrievable across the reshuffle** (no data loss on rotation), and the DHT keeps routing in the
//! re-derived topology.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_field::F2;
use fanos_geometry::fano;
use fanos_runtime::{Command, Config, Duration, OverlayNode};
use fanos_sim::Sim;

/// Coordinate of Fano point `i`.
fn point(i: usize) -> [u32; 3] {
    fano::point(i).coords()
}

#[test]
fn every_stored_key_survives_an_epoch_reshuffle() {
    // A SPARSE cell — 3 of the 7 Fano points — so each node can reshuffle onto a fresh, currently
    // unoccupied point, exactly as an independent per-node VRF reshuffle does (the base cell never
    // lockstep-permutes). `after` is disjoint from `before`: every node vacates its old point.
    const N: usize = 20;
    let before = [0usize, 2, 5];
    let after = [1usize, 3, 6];

    let mut sim = Sim::new(0x9E_5117);
    let nodes: Vec<[u32; 3]> = before
        .iter()
        .map(|&i| sim.add(Box::new(OverlayNode::<F2>::new(fano::point(i), Config::default()))))
        .collect();
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000)); // establish liveness among the three occupants

    // Store a batch of keys; a Put replicates across the whole cell (LRC availability, §L4), so after this
    // settles every one of the three nodes holds every value.
    let keys: Vec<Vec<u8>> = (0..N).map(|k| format!("key-{k}").into_bytes()).collect();
    for (k, key) in keys.iter().enumerate() {
        sim.inject(
            nodes[0],
            Command::Put {
                key: key.clone(),
                value: format!("val-{k}").into_bytes(),
            },
        );
    }
    sim.run_for(Duration::from_millis(3000));

    // THE RESHUFFLE: each node re-seats at its new VRF coordinate (the driver would compute this from the
    // new epoch's beacon; here we inject it directly). The engine re-derives neighbours/index/address and
    // re-announces, keeping its epoch-stable store.
    for (slot, &new_i) in after.iter().enumerate() {
        sim.inject(nodes[slot], Command::Reseat { coord: point(new_i) });
    }
    sim.run_for(Duration::from_millis(6000)); // reshuffle propagates; liveness reconverges at new points

    // Non-vacuity: the cell genuinely MOVED — every old point is vacated, every new point is occupied.
    let live: Vec<[u32; 3]> = sim.nodes().collect();
    for &i in &after {
        assert!(live.contains(&point(i)), "a node reshuffled onto point {i}");
    }
    for &i in &before {
        assert!(!live.contains(&point(i)), "old point {i} was vacated by the reshuffle");
    }

    // SURVIVAL: every stored key is still retrievable after the reshuffle. Query from a node that moved
    // (originally point 2, now point 3); with the store preserved across the re-seat it answers from its
    // own replica, so no key was lost when the coordinate rotated (the C2 property).
    let getter = point(after[1]);
    for key in &keys {
        sim.inject(getter, Command::Get { key: key.clone() });
    }
    sim.run_for(Duration::from_millis(4000));
    let survived = sim
        .report()
        .retrievals()
        .filter(|(who, _, v)| *who == getter && v.is_some())
        .count();
    assert_eq!(
        survived, N,
        "every one of the {N} keys stays retrievable across the epoch reshuffle (got {survived})"
    );

    // The DHT still ROUTES in the re-derived topology: a fresh Put from one relocated node round-trips to a
    // Get on another, proving responsibility resolution + replication work at the new coordinates.
    sim.inject(
        point(after[0]),
        Command::Put {
            key: b"post-reshuffle".to_vec(),
            value: b"routed-in-the-new-topology".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(3000));
    sim.inject(
        point(after[2]),
        Command::Get {
            key: b"post-reshuffle".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(3000));
    let got = sim
        .report()
        .retrievals()
        .filter(|(who, _, _)| *who == point(after[2]))
        .last()
        .map(|(_, _, v)| v.map(<[u8]>::to_vec));
    assert_eq!(
        got,
        Some(Some(b"routed-in-the-new-topology".to_vec())),
        "the DHT resolves responsibility and replicates correctly in the reshuffled topology"
    );
}
