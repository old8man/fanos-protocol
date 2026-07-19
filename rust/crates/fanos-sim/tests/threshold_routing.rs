//! Threshold-onion routing end to end over the overlay (spec §5.2, §5.7): "a hop is a line". A
//! client seals a nested threshold onion over a circuit of hop *lines*; the `ThresholdRouter` nodes
//! then route it **autonomously** — each hop's combiner gathers a threshold `t` of partial
//! decryptions from the line's members through the overlay, peels, and forwards to the next line's
//! combiner, until delivery. No node peels a hop alone, and below `t` cooperating members a hop
//! cannot be peeled at all.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use fanos_aphantos::ThresholdRouter;
use fanos_aphantos::threshold::{HopLine, seal_onion};
use fanos_aphantos::threshold_router::{ANONYMOUS, combiner_for, launch_frame, line_member_coords};
use fanos_field::F2;
use fanos_geometry::{Line, Point, Triple};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, OnionKeyRatchet, SeedRng};
use fanos_rendezvous::Epoch;
use fanos_runtime::Duration;
use fanos_sim::Sim;

/// Spawn a `ThresholdRouter` at every Fano point (threshold `t`), returning the public-key directory
/// so the test can seal onions to the line members.
fn spawn_routers(sim: &mut Sim, t: usize) -> BTreeMap<Triple, HybridKemPublic> {
    spawn_routers_with(sim, t, Duration::from_millis(0))
}

/// As [`spawn_routers`], with a Poisson mixing mean delay on each router.
fn spawn_routers_with(
    sim: &mut Sim,
    t: usize,
    mean_delay: Duration,
) -> BTreeMap<Triple, HybridKemPublic> {
    let mut pubs = BTreeMap::new();
    for i in 0..7 {
        let point = Point::<F2>::at(i);
        let mut rng = SeedRng::from_seed(&[0xA0, i as u8]);
        let (secret, _identity) = HybridKemSecret::generate(&mut rng);
        // Seal onions to each relay's forward-secure ONION public (audit E4); the relay peels with the
        // onion secret from the same genesis seed.
        let mut onion_seed = [0xC5u8; 32];
        onion_seed[31] = i as u8;
        let onion_public = OnionKeyRatchet::new(onion_seed, Epoch::ZERO)
            .public()
            .clone();
        pubs.insert(point.coords(), onion_public);
        sim.add(Box::new(
            ThresholdRouter::<F2>::new(point, &secret, t, onion_seed).with_mixing(mean_delay),
        ));
    }
    pubs
}

/// Build a threshold onion over `hop_lines` carrying `payload`, threshold `t`, using the directory.
fn build_onion(
    hop_lines: &[Triple],
    t: u8,
    payload: &[u8],
    pubs: &BTreeMap<Triple, HybridKemPublic>,
) -> Vec<u8> {
    // Per hop, the member public keys in canonical `points_on` (seal) order.
    let member_vecs: Vec<Vec<&HybridKemPublic>> = hop_lines
        .iter()
        .map(|&line| {
            line_member_coords::<F2>(line)
                .iter()
                .map(|c| pubs.get(c).unwrap())
                .collect()
        })
        .collect();
    let hops: Vec<HopLine<'_>> = hop_lines
        .iter()
        .zip(&member_vecs)
        .map(|(&line, members)| HopLine { line, members })
        .collect();
    seal_onion(&hops, t, payload, b"threshold-route-seed").unwrap()
}

#[test]
fn a_threshold_onion_routes_autonomously_and_delivers() {
    let mut sim = Sim::new(0x7A1);
    let t = 2u8; // 2-of-3 per Fano line
    let pubs = spawn_routers(&mut sim, usize::from(t));

    // A 2-hop circuit over two distinct Fano lines.
    let hop_lines = vec![Line::<F2>::at(0).coords(), Line::<F2>::at(3).coords()];
    let payload = b"threshold-routed hello";
    let onion = build_onion(&hop_lines, t, payload, &pubs);

    // Launch: send the first-hop onion to the first line's combiner.
    let combiner = combiner_for::<F2>(hop_lines[0]).unwrap();
    let source = Point::<F2>::at(6).coords();
    sim.inject_frame(source, combiner, launch_frame(hop_lines[0], &onion));
    sim.run_for(Duration::from_millis(2000));

    // The payload is delivered (anonymously) at the last hop's combiner.
    let delivered = sim
        .report()
        .deliveries()
        .find(|(_, from, bytes)| *from == ANONYMOUS && *bytes == payload);
    assert!(
        delivered.is_some(),
        "the threshold onion routes through both line-hops and delivers the payload"
    );
}

#[test]
fn a_threshold_onion_still_delivers_with_poisson_mixing() {
    // With per-hop mixing enabled the onion is held for a sampled delay at each forward, reordering
    // the flow — but it still reaches the destination once the delays elapse.
    let mut sim = Sim::new(0x7A4);
    let t = 2u8;
    let pubs = spawn_routers_with(&mut sim, usize::from(t), Duration::from_millis(50));

    let hop_lines = vec![Line::<F2>::at(0).coords(), Line::<F2>::at(3).coords()];
    let payload = b"mixed threshold hello";
    let onion = build_onion(&hop_lines, t, payload, &pubs);

    let combiner = combiner_for::<F2>(hop_lines[0]).unwrap();
    sim.inject_frame(
        Point::<F2>::at(6).coords(),
        combiner,
        launch_frame(hop_lines[0], &onion),
    );
    sim.run_for(Duration::from_millis(4000)); // room for the sampled mix delays

    assert!(
        sim.report()
            .deliveries()
            .any(|(_, from, bytes)| from == ANONYMOUS && bytes == payload),
        "the mixed threshold onion still delivers once the mix delays elapse"
    );
}

#[test]
fn a_single_hop_threshold_onion_delivers() {
    let mut sim = Sim::new(0x7A2);
    let t = 2u8;
    let pubs = spawn_routers(&mut sim, usize::from(t));

    let hop_lines = vec![Line::<F2>::at(2).coords()];
    let payload = b"one hop, one line";
    let onion = build_onion(&hop_lines, t, payload, &pubs);

    let combiner = combiner_for::<F2>(hop_lines[0]).unwrap();
    sim.inject_frame(
        Point::<F2>::at(0).coords(),
        combiner,
        launch_frame(hop_lines[0], &onion),
    );
    sim.run_for(Duration::from_millis(1500));

    assert!(
        sim.report()
            .deliveries()
            .any(|(_, from, bytes)| from == ANONYMOUS && bytes == payload),
        "a single-line threshold hop delivers once its combiner gathers t partials"
    );
}

#[test]
fn below_threshold_the_hop_cannot_be_peeled_and_nothing_is_delivered() {
    // With only one live member per line but a threshold of 3, no combiner can ever gather enough
    // partials, so nothing is delivered — the line, not a node, is the unit of trust.
    let mut sim = Sim::new(0x7A3);
    let t = 3u8; // needs all 3 members of a Fano line
    let pubs = spawn_routers(&mut sim, usize::from(t));

    let hop_lines = vec![Line::<F2>::at(1).coords()];
    let payload = b"should never arrive";
    let onion = build_onion(&hop_lines, t, payload, &pubs);

    // Crash two of the three line members, leaving fewer than the threshold able to reply.
    let members = line_member_coords::<F2>(hop_lines[0]);
    sim.crash(members[1]);
    sim.crash(members[2]);

    let combiner = combiner_for::<F2>(hop_lines[0]).unwrap(); // members[0], still alive
    sim.inject_frame(
        Point::<F2>::at(4).coords(),
        combiner,
        launch_frame(hop_lines[0], &onion),
    );
    sim.run_for(Duration::from_millis(3000));

    assert!(
        !sim.report()
            .deliveries()
            .any(|(_, from, bytes)| from == ANONYMOUS && bytes == payload),
        "below threshold the hop cannot be peeled — nothing is delivered"
    );
}
