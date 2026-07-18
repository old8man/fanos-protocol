//! End-to-end: anonymous NYX onion routing over the simulated network.
//!
//! Real `NyxNode` engines (the production code) route a KEM-sealed onion hop by hop across the
//! in-memory network. The payload reaches the destination while every relay sees only its own
//! next hop, and the receiver never learns the originator — anonymity demonstrated "as if in
//! production", on one host.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_aphantos::node::ANONYMOUS;
use fanos_aphantos::{Directory, NyxNode};
use fanos_field::F7;
use fanos_geometry::{Plane, Point, Triple};
use fanos_pqcrypto::{HybridKemSecret, SeedRng};
use fanos_runtime::{Command, Duration};
use fanos_sim::Sim;

/// Spawn a cell of `NyxNode`s, each with a KEM keypair and a shared membership directory.
fn spawn_nyx_cell(sim: &mut Sim, path_len: usize) -> Vec<Triple> {
    let points: Vec<Point<F7>> = Plane::<F7>::points().collect();

    // Every node gets a KEM keypair; the directory maps coordinates to public keys.
    let mut directory = Directory::new();
    let mut secrets = Vec::with_capacity(points.len());
    for (i, point) in points.iter().enumerate() {
        let mut rng = SeedRng::from_seed(&[0x5A, i as u8]);
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        directory.insert(point.coords(), public);
        secrets.push(secret);
    }

    let mut coords = Vec::with_capacity(points.len());
    for (i, (point, secret)) in points.iter().zip(secrets).enumerate() {
        let node = NyxNode::new(*point, secret, directory.clone(), [i as u8; 32], [0u8; 32], path_len);
        coords.push(sim.add(Box::new(node)));
    }
    coords
}

#[test]
fn anonymous_onion_is_delivered_across_the_cell() {
    let mut sim = Sim::new(1);
    let cell = spawn_nyx_cell(&mut sim, 3);

    // The source anonymously sends to the destination; the NyxNode builds a 3-hop onion.
    sim.inject(
        cell[0],
        Command::Send {
            to: cell[40],
            payload: b"the message is anonymous".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(2000));

    // The destination received exactly the payload, from an anonymous source.
    let deliveries: Vec<_> = sim.report().deliveries().collect();
    assert!(
        deliveries.iter().any(|(recv, from, bytes)| {
            *recv == cell[40] && *bytes == b"the message is anonymous" && *from == ANONYMOUS
        }),
        "payload should reach the destination anonymously; got {deliveries:?}"
    );

    // It traversed multiple relays (one framed onion per hop) — real onion routing.
    assert!(
        sim.report().metrics.frames_sent >= 3,
        "a 3-hop onion sends at least 3 frames, got {}",
        sim.report().metrics.frames_sent
    );
}

#[test]
fn onion_is_reproducible_per_seed() {
    let run = |seed: u64| {
        let mut sim = Sim::new(seed);
        let cell = spawn_nyx_cell(&mut sim, 3);
        sim.inject(
            cell[1],
            Command::Send {
                to: cell[20],
                payload: b"repro".to_vec(),
            },
        );
        sim.run_for(Duration::from_millis(2000));
        sim.report().metrics.clone()
    };
    assert_eq!(run(9), run(9));
}
