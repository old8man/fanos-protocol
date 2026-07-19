//! The **live mixnet directory** assembled over a real seven-node Fano cell on QUIC (audit #54, item 1).
//!
//! The anonymous profile seals each onion hop to the forward-secure onion keys of that hop's members
//! ([`fanos_node::mixdir`]). In a unit test those keys are handed in; here they are *discovered the way a
//! real client discovers them* — every relay advertises its per-epoch onion public into the overlay store
//! ([`publish_mix_key`] / [`spawn_mix_publisher`]), and a client resolves the current epoch's roster into a
//! [`MixDirectory`] ([`build_cell_mix_directory`]) with no central directory and no hand-built map. The
//! cell is genuine mutual-TLS QUIC (via [`fanos_quic::spawn_cell`]), the tier the deterministic simulator
//! cannot cover: real sockets, real replication, real concurrency.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_node::{
    EpochDriver, build_cell_mix_directory, cell_mix_coords, publish_mix_key, spawn_mix_publisher,
};
use fanos_quic::spawn_cell;
use fanos_rendezvous::Epoch;
use fanos_runtime::{Config, Engine, OverlayNode};

/// Build the overlay engine seated at `coord` — the same `OverlayNode` that ships, at a pinned point, so
/// the cell serves the L4 store the directory is published into and read from.
fn make_node(coord: Point<F2>) -> Box<dyn Engine + Send> {
    Box::new(OverlayNode::<F2>::new(coord, Config::default()))
}

/// A distinct, deterministic onion-ratchet genesis seed for the relay at roster index `i`.
fn onion_seed(i: usize) -> [u8; 32] {
    [0x54u8.wrapping_add(i as u8); 32]
}

/// The onion public the relay at `coord` (seeded `seed`) advertises for `epoch` — derived through the very
/// [`EpochDriver`] a live relay publishes with, so the test's expectation is the production key, not a
/// re-derivation by another path.
fn expected_public(coord: [u32; 3], seed: [u8; 32], epoch: Epoch) -> Vec<u8> {
    let mut driver = EpochDriver::new(coord, seed);
    driver.advance_to(epoch);
    driver.public().encode()
}

/// Seven relays each publish their genesis onion key; a client on a *different* node assembles the whole
/// live cell directory from the store, and every discovered key is exactly the key that relay will peel
/// with. A different epoch's directory is empty — the slots are epoch-tagged (forward secrecy, audit E4).
#[tokio::test]
async fn the_live_cell_directory_is_assembled_from_published_keys_over_real_quic() {
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble cell");
    let roster = cell_mix_coords::<F2>();
    let epoch = Epoch::ZERO;

    // Each relay advertises its own current onion public at its epoch-tagged slot — publishing from its
    // own node's client, exactly as a live relay would (the store routes the write to the responsible
    // node regardless of who issues it).
    for (i, &coord) in roster.iter().enumerate() {
        let public = expected_public(coord, onion_seed(i), epoch);
        assert!(
            publish_mix_key(
                &cell.nodes[i].client(),
                coord,
                epoch,
                &fanos_pqcrypto::kem::HybridKemPublic::decode(&public).unwrap(),
            )
            .await,
            "relay {i} advertised its onion key",
        );
    }

    // A client on node 0 discovers the whole live roster from the store — no hand-built directory.
    let reader = cell.nodes[0].client();
    let dir = build_cell_mix_directory::<F2>(&reader, epoch).await;
    assert_eq!(dir.len(), 7, "every live relay is discovered");
    for (i, &coord) in roster.iter().enumerate() {
        assert_eq!(
            dir.get(&coord)
                .map(fanos_pqcrypto::kem::HybridKemPublic::encode),
            Some(expected_public(coord, onion_seed(i), epoch)),
            "the discovered key for relay {i} is the key it will peel with",
        );
    }

    // Epoch-scoping: nothing was published for a later epoch, so its directory is empty — a client for
    // that epoch resolves a distinct slot and finds nobody, never a stale key from a past epoch.
    let future = build_cell_mix_directory::<F2>(&reader, Epoch::new(1)).await;
    assert_eq!(
        future.len(),
        0,
        "a different epoch's directory is independent"
    );

    for n in cell.nodes {
        n.shutdown();
    }
}

/// The directory is a **best-effort roster view**, not all-or-nothing: when only some relays have
/// published for an epoch, the client discovers exactly those and the silent ones are simply absent — a
/// down or not-yet-published relay degrades to a smaller mixnet, never a failed lookup.
#[tokio::test]
async fn the_live_directory_is_best_effort_absent_relays_are_simply_missing() {
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble cell");
    let roster = cell_mix_coords::<F2>();
    let epoch = Epoch::new(3);

    // Only the first five of the seven relays advertise for this epoch.
    let present = 5usize;
    for (i, &coord) in roster.iter().enumerate().take(present) {
        let public = expected_public(coord, onion_seed(i), epoch);
        assert!(
            publish_mix_key(
                &cell.nodes[i].client(),
                coord,
                epoch,
                &fanos_pqcrypto::kem::HybridKemPublic::decode(&public).unwrap(),
            )
            .await,
            "relay {i} advertised for epoch 3",
        );
    }

    let dir = build_cell_mix_directory::<F2>(&cell.nodes[6].client(), epoch).await;
    assert_eq!(
        dir.len(),
        present,
        "exactly the relays that published are discovered"
    );
    for (i, &coord) in roster.iter().enumerate() {
        if i < present {
            assert!(
                dir.get(&coord).is_some(),
                "present relay {i} is in the directory"
            );
        } else {
            assert!(
                dir.get(&coord).is_none(),
                "silent relay {i} is simply absent"
            );
        }
    }

    for n in cell.nodes {
        n.shutdown();
    }
}

/// [`spawn_mix_publisher`] closes the loop: spawned on each relay, it advertises the relay's genesis onion
/// key with no further prompting, so a client that only ever calls [`build_cell_mix_directory`] finds a
/// fully populated, live directory. (Beacon-driven republish is proven deterministically by the
/// `EpochDriver` unit tests; here we confirm the async task publishes over real QUIC.)
#[tokio::test]
async fn the_publisher_task_keeps_each_relays_key_live() {
    let cell = spawn_cell::<F2>(make_node).await.expect("assemble cell");
    let roster = cell_mix_coords::<F2>();
    let epoch = Epoch::ZERO;

    // Every relay runs its publisher task, seeded with the same onion seed its router would use.
    let mut publishers = Vec::new();
    for (i, &coord) in roster.iter().enumerate() {
        publishers.push(spawn_mix_publisher(
            cell.nodes[i].client(),
            coord,
            onion_seed(i),
        ));
    }

    // The publishers write asynchronously; poll the discovered directory until every relay's genesis key
    // has landed (bounded — a real store ack is fast over loopback QUIC), then assert the full roster.
    let reader = cell.nodes[0].client();
    let mut dir = build_cell_mix_directory::<F2>(&reader, epoch).await;
    for _ in 0..40 {
        if dir.len() == roster.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        dir = build_cell_mix_directory::<F2>(&reader, epoch).await;
    }
    assert_eq!(
        dir.len(),
        7,
        "every relay's publisher advertised its genesis key"
    );
    for (i, &coord) in roster.iter().enumerate() {
        assert_eq!(
            dir.get(&coord)
                .map(fanos_pqcrypto::kem::HybridKemPublic::encode),
            Some(expected_public(coord, onion_seed(i), epoch)),
            "the publisher for relay {i} advertised the key it will peel with",
        );
    }

    for p in publishers {
        p.abort();
    }
    for n in cell.nodes {
        n.shutdown();
    }
}
