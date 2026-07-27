//! End-to-end DHT over a **full seven-node Fano (`F2`) cell on real QUIC**.
//!
//! `loopback.rs` exercises a pair and `self_certifying.rs` exercises identity; this is the whole
//! cell. Seven self-certifying nodes are pinned — by grinding credentials, see
//! [`fanos_quic::spawn_cell`] — to the seven Fano points `0..7`, sharing one directory, so
//! content-addressed routing, replication, and read-repair run over genuine mutual-TLS QUIC links.
//! This is the tier the deterministic simulator structurally cannot cover: real sockets, real
//! certificates, real concurrency. Because the Fano plane is fully connected (any two points share a
//! line), each node derives all six others as peers at construction — so a freshly assembled cell
//! replicates and read-repairs with no discovery walk.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_quic::spawn_cell;
use fanos_runtime::{Config, Engine, OverlayNode};

/// Build the overlay engine seated at `coord` — the same `OverlayNode` that ships, at a pinned point.
fn make_node(coord: Point<F2>) -> Box<dyn Engine + Send> {
    Box::new(OverlayNode::<F2>::new(coord, Config::default()))
}

/// The grind seats each of the seven nodes on a distinct Fano point — the cell is fully populated.
#[tokio::test]
async fn full_fano_cell_assembles_at_the_seven_points() {
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble cell");
    assert_eq!(cell.nodes.len(), 7, "a Fano cell has seven points");

    // Every canonical point 0..7 is occupied exactly once: the pin put each node where it was asked,
    // and every occupant is a genuine self-certifying node (its cert hashes to that very point).
    let mut coords: Vec<_> = cell
        .nodes
        .iter()
        .map(fanos_quic::NodeHandle::address)
        .collect();
    coords.sort_unstable();
    let mut want: Vec<_> = (0..7).map(|i| Point::<F2>::at(i).coords()).collect();
    want.sort_unstable();
    assert_eq!(
        coords, want,
        "the seven nodes occupy the seven distinct Fano points"
    );

    for n in cell.nodes {
        n.shutdown();
    }
}

/// A value stored at one node is read back at a **different** node — content-addressed routing,
/// replication, and read-repair over real QUIC, not a loopback pair.
#[tokio::test]
async fn dht_put_on_one_node_is_read_by_another_across_the_cell() {
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble cell");

    // Put from node 0, get from node 3. The key is content-addressed to whichever point is
    // responsible; the write is routed there over QUIC, replicated across the cell, and read back from
    // an origin that is (in general) neither the writer nor the primary. The routing is what is tested.
    let writer = cell.nodes[0].client();
    let reader = cell.nodes[3].client();
    let key = b"cell-e2e/key".to_vec();
    let value = b"stored across a real-QUIC Fano cell".to_vec();

    assert!(
        writer.put(key.clone(), value.clone()).await,
        "the responsible node acknowledged the store"
    );
    let got = reader.get(key).await;
    assert_eq!(
        got.as_deref(),
        Some(value.as_slice()),
        "the value read back at a different cell member equals what was written"
    );

    for n in cell.nodes {
        n.shutdown();
    }
}

/// The value survives the loss of a node: a `Put` replicates to every member (LRC availability, spec
/// §L4), so shutting one down still leaves every survivor able to serve the key.
#[tokio::test]
async fn a_stored_value_survives_losing_a_node() {
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble cell");

    let key = b"cell-e2e/durable".to_vec();
    let value = b"replicated, so one node may fall".to_vec();
    assert!(
        cell.nodes[1].client().put(key.clone(), value.clone()).await,
        "store acknowledged"
    );

    // Give the replication fan-out a moment to reach every member over QUIC, then drop node 1 (a
    // writer/replica). A read from an untouched survivor still returns the value.
    tokio::time::sleep(Duration::from_millis(200)).await;
    cell.nodes[1].shutdown();

    let survivor = cell.nodes[5].client();
    let got = survivor.get(key).await;
    assert_eq!(
        got.as_deref(),
        Some(value.as_slice()),
        "a survivor still serves the replicated value after a node is lost"
    );

    for n in cell.nodes {
        n.shutdown();
    }
}

/// A **large** App frame fanned out to every other cell point arrives at every one of them.
///
/// The property the DA path depends on and nothing asserted. `Command::Emit` is fire-and-forget — it reports only
/// whether the *local* input queue accepted the frame — so a frame lost anywhere past that point is silently gone, and
/// the only caller that noticed was a consensus cell that stopped finalizing.
///
/// Sized like a real DA shard of a shielded block: measured at **6203 bytes** on the live path, against 43 bytes for a
/// plain-transfer block. That two-orders-of-magnitude gap is why every small-payload suite passed while the shielded one
/// wedged, with validators holding their own dispersed shard and never obtaining a single one from a peer across 48 s of
/// retries. Both sizes are asserted here so a regression says which one broke.
#[tokio::test]
async fn a_large_app_frame_fans_out_to_every_cell_point() {
    use fanos_runtime::{Command, Notification};

    let cell = spawn_cell::<F2>(make_node).await.expect("assemble cell");
    let n = cell.nodes.len();

    for &bytes in &[43usize, 6203] {
        // A distinct payload per size, so a receiver can tell which fan-out it is seeing. `Emit` takes a *wire frame*,
        // not raw bytes — an unparseable frame is dropped on receipt, which is itself worth knowing.
        let body: Vec<u8> = (0..bytes).map(|i| u8::try_from((i + bytes) % 251).unwrap_or(0)).collect();
        let mut frame = Vec::new();
        fanos_wire::encode_frame(fanos_wire::FrameType::App.code(), &body, &mut frame);
        let mut streams: Vec<_> = cell.nodes.iter().map(|n| n.client().subscribe()).collect();
        for (i, node) in cell.nodes.iter().enumerate() {
            if i != 0 {
                assert!(
                    cell.nodes[0].client().command(Command::Emit { to: node.address(), frame: frame.clone() }),
                    "the local input queue accepted the {bytes}-byte frame for point {i}"
                );
            }
        }

        // Count arrivals with a generous ceiling: this asserts delivery, not latency.
        let mut arrived = 0;
        for (i, rx) in streams.iter_mut().enumerate() {
            if i == 0 {
                continue;
            }
            let got = tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    if let Ok(Notification::App { body: got, .. }) = rx.recv().await
                        && got == body
                    {
                        return;
                    }
                }
            })
            .await;
            if got.is_ok() {
                arrived += 1;
            }
        }
        assert_eq!(arrived, n - 1, "every one of the {} peers received the {bytes}-byte frame", n - 1);
    }

    for n in cell.nodes {
        n.shutdown();
    }
}

/// **Every ordered pair** of cell points can deliver to each other, not just outward from one node.
///
/// `a_large_app_frame_fans_out_to_every_cell_point` covers one sender. That cannot see a *directional* gap, and a
/// directional gap is exactly what the live DA symptom looks like: a validator requested shards from all six peers every
/// tick for 48 s and got none, while four other validators recovered the same block by answering each other. Peers that
/// demonstrably held and served their shard answered some requesters and not others.
///
/// `Command::Emit` resolves the destination coordinate through the sender's own directory, so what each node knows is
/// per-node state — and a missing entry drops the frame silently, with the sender's `command` still returning `true`.
/// Consensus hides that: votes are broadcast, so a quorum forms while one pair never talks.
#[tokio::test]
async fn every_ordered_pair_of_cell_points_can_deliver() {
    use fanos_runtime::{Command, Notification};

    let cell = spawn_cell::<F2>(make_node).await.expect("assemble cell");
    let n = cell.nodes.len();
    let coords: Vec<_> = cell.nodes.iter().map(fanos_quic::NodeHandle::address).collect();

    // A shielded block's DA shard is 6203 bytes on the live path; use that size, since it is the traffic that stalled.
    let mut streams: Vec<_> = cell.nodes.iter().map(|node| node.client().subscribe()).collect();
    for (from, node) in cell.nodes.iter().enumerate() {
        for (to, &coord) in coords.iter().enumerate() {
            if from == to {
                continue;
            }
            // The payload names its ordered pair, so a receiver can tell exactly which senders reached it.
            let mut body = vec![u8::try_from(from).unwrap_or(0), u8::try_from(to).unwrap_or(0)];
            body.resize(6203, 0x5A);
            let mut frame = Vec::new();
            fanos_wire::encode_frame(fanos_wire::FrameType::App.code(), &body, &mut frame);
            assert!(node.client().command(Command::Emit { to: coord, frame }), "point {from} queued its frame for {to}");
        }
    }

    // Collect what each node actually received and report every missing pair at once — one run names the whole gap
    // rather than failing on the first hole.
    let mut missing = Vec::new();
    for (to, rx) in streams.iter_mut().enumerate() {
        let mut seen = vec![false; n];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while tokio::time::Instant::now() < deadline
            && seen.iter().enumerate().filter(|&(i, _)| i != to).any(|(_, &s)| !s)
        {
            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
                Ok(Ok(Notification::App { body, .. })) if body.len() == 6203 => {
                    if let (Some(&f), Some(&t)) = (body.first(), body.get(1))
                        && usize::from(t) == to
                        && let Some(slot) = seen.get_mut(usize::from(f))
                    {
                        *slot = true;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => break,
            }
        }
        for (from, &got) in seen.iter().enumerate() {
            if from != to && !got {
                missing.push((from, to));
            }
        }
    }
    assert!(missing.is_empty(), "{} of {} ordered pairs never delivered: {missing:?}", missing.len(), n * (n - 1));

    for n in cell.nodes {
        n.shutdown();
    }
}
