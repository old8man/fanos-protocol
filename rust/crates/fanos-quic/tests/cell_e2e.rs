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
    let mut coords: Vec<_> = cell.nodes.iter().map(fanos_quic::NodeHandle::address).collect();
    coords.sort_unstable();
    let mut want: Vec<_> = (0..7).map(|i| Point::<F2>::at(i).coords()).collect();
    want.sort_unstable();
    assert_eq!(coords, want, "the seven nodes occupy the seven distinct Fano points");

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
