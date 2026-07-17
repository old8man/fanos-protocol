//! NYX mixnet driver behaviours over the simulated network (spec §L5): per-hop **Poisson mixing**
//! (a relayed onion is held for an exponential delay, so a batch leaves reordered — the anonymity
//! set) and **cover traffic** (a steady stream of indistinguishable cells, so a node's send pattern
//! is uniform regardless of real traffic). The onion crypto and routing are the same `NyxNode`
//! engine the other tests run; here we exercise its timing behaviour.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_aphantos::node::ANONYMOUS;
use fanos_aphantos::{Directory, NyxNode};
use fanos_field::F7;
use fanos_geometry::{Plane, Point, Triple};
use fanos_pqcrypto::{HybridKemSecret, SeedRng};
use fanos_runtime::{Command, Duration};
use fanos_sim::Sim;

/// Spawn a cell of `NyxNode`s, optionally with Poisson mixing + cover traffic enabled.
fn spawn_nyx_cell(
    sim: &mut Sim,
    path_len: usize,
    mix: Option<(Duration, Duration)>,
) -> Vec<Triple> {
    let points: Vec<Point<F7>> = Plane::<F7>::points().collect();
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
        let mut node = NyxNode::new(*point, secret, directory.clone(), [i as u8; 32], path_len);
        if let Some((mean_delay, cover_interval)) = mix {
            node = node.with_mixing(mean_delay, cover_interval);
        }
        coords.push(sim.add(Box::new(node)));
    }
    coords
}

#[test]
fn mixing_holds_each_hop_on_a_delay_timer_yet_still_delivers() {
    // With mixing on, every relayed hop is held on a mix-delay timer before forwarding — so timers
    // fire (they do not without mixing) — and the onion still reaches its destination anonymously.
    let mut sim = Sim::new(3);
    let cell = spawn_nyx_cell(
        &mut sim,
        3,
        Some((Duration::from_millis(200), Duration::from_millis(0))),
    );
    sim.inject(
        cell[0],
        Command::Send {
            to: cell[40],
            payload: b"mixed message".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(5000));

    let report = sim.report();
    assert!(
        report
            .deliveries()
            .any(|(recv, from, bytes)| recv == cell[40]
                && from == ANONYMOUS
                && bytes == b"mixed message"),
        "the mixed onion still arrives anonymously"
    );
    assert!(
        report.metrics.timers_fired >= 2,
        "each relayed hop armed a mix-delay timer (got {})",
        report.metrics.timers_fired
    );
}

#[test]
fn without_mixing_no_delay_timers_are_used() {
    // Contrast: a non-mixing cell forwards immediately and arms no mix timers.
    let mut sim = Sim::new(3);
    let cell = spawn_nyx_cell(&mut sim, 3, None);
    sim.inject(
        cell[0],
        Command::Send {
            to: cell[40],
            payload: b"unmixed".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(2000));
    assert_eq!(
        sim.report().metrics.timers_fired,
        0,
        "no mixing ⇒ no timers"
    );
}

#[test]
fn cover_traffic_emits_a_steady_stream_of_cover_cells() {
    // Every node runs cover traffic; over a window the network carries many cover cells, so an
    // observer cannot tell an idle node from a busy one (spec §L5, V8).
    let mut sim = Sim::new(7);
    sim.enable_trace(true);
    let _cell = spawn_nyx_cell(
        &mut sim,
        3,
        Some((Duration::from_millis(0), Duration::from_millis(300))),
    );
    sim.inject_all(&Command::StartHeartbeat); // begin cover emission
    sim.run_for(Duration::from_millis(6000));

    let cover_cells = sim.trace().grep("Cover").len();
    assert!(
        cover_cells > 20,
        "cover traffic should produce a steady stream, got {cover_cells}"
    );
}

#[test]
fn the_anonymity_set_grows_with_mixing_and_matches_the_theory() {
    // The mixing math the running node embodies: a higher arrival rate (relative to the mix rate μ)
    // yields a larger anonymity set and more entropy (spec §L5, V7).
    let mu = 10.0;
    let light = fanos_nyx::mixing::anonymity_entropy_bits(20.0, mu);
    let heavy = fanos_nyx::mixing::anonymity_entropy_bits(200.0, mu);
    assert!(
        light > 0.0 && heavy > light,
        "more traffic ⇒ more anonymity: {light} < {heavy}"
    );
}
