//! Threshold-hosted CALYPSO over the sim overlay through the **production** `ThresholdService` engine
//! (spec §12.3, audit #99) — the live-wired successor to the hand-rolled `ServiceMember` template in
//! `threshold_calypso.rs`. A service hosted `t`-of-`(q+1)` across its line: a client seals its intro to
//! the whole line (`SealedIntro`), the line's combiner gathers `>= t` PartialDecs over the real wire
//! frames (`RdvIntro`/`SvcShareReq`/`SvcPartial`) and surfaces the recovered request — no single host
//! ever reads an intro alone. The below-threshold run proves 0-knowledge: too few members, nothing served.
//!
//! Unlike `threshold_calypso.rs` (its own scaffolding engine), this drives `fanos_node::ThresholdService`
//! directly, so it also exercises the production concerns that template omitted: multiplexed concurrent
//! intros keyed by intro id, and replay suppression.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_calypso::hosting::{LineMember, SealedIntro, ServiceLine};
use fanos_field::F2;
use fanos_geometry::{Point, Triple};
use fanos_node::{ThresholdService, intro_frame};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_runtime::Duration;
use fanos_sim::Sim;
use fanos_wire::Wire;

/// The anonymous-source sentinel a surfaced request carries (the service never learns the deliverer).
const ANON: Triple = [0, 0, 0];

/// Spawn an `n`-member service-line (threshold `t`) as production `ThresholdService` engines at Fano
/// points `0..n`. Returns the line coordinates (in seal order) and the members' public keys.
fn spawn_line(sim: &mut Sim, n: usize, t: usize) -> (Vec<Triple>, Vec<HybridKemPublic>) {
    let mut line = Vec::new();
    let mut pubs = Vec::new();
    let mut secrets = Vec::new();
    for i in 0..n {
        let mut rng = SeedRng::from_seed(&[0xCA, i as u8]);
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        line.push(Point::<F2>::at(i).coords());
        pubs.push(public);
        secrets.push(secret);
    }
    for (i, secret) in secrets.into_iter().enumerate() {
        sim.add(Box::new(ThresholdService::new(line[i], secret, line.clone(), t)));
    }
    (line, pubs)
}

fn seal(pubs: &[HybridKemPublic], t: u8, payload: &[u8], seed: &[u8]) -> SealedIntro {
    let refs: Vec<&HybridKemPublic> = pubs.iter().collect();
    SealedIntro::seal(payload, t, &refs, seed).unwrap()
}

#[test]
fn a_threshold_of_the_line_serves_the_intro() {
    // 3-of-5 hosting: the client seals to the whole line and sends to the combiner (line[0]); the line
    // cooperates to threshold-decrypt and the combiner surfaces the request. No single host read it.
    let mut sim = Sim::new(0x9901);
    let (line, pubs) = spawn_line(&mut sim, 5, 3);
    let client = Point::<F2>::at(5).coords();
    let request = b"please serve my hidden content".to_vec();
    let intro = seal(&pubs, 3, &request, b"intro-seed-1");

    sim.inject_frame(client, line[0], intro_frame(&intro));
    sim.run_for(Duration::from_millis(2000));

    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == line[0] && from == ANON && bytes == request.as_slice()),
        "the line, cooperating at threshold, decrypted and surfaced the request"
    );
}

#[test]
fn any_surviving_threshold_subset_serves() {
    // The same 3-of-5 line with two specific members seized: {0,2,4} remain — exactly t=3, a different
    // quorum than "the first 3 to answer". Availability is not pinned to one fixed subset.
    let mut sim = Sim::new(0x9902);
    let (line, pubs) = spawn_line(&mut sim, 5, 3);
    let client = Point::<F2>::at(5).coords();
    let request = b"served by a different quorum".to_vec();
    let intro = seal(&pubs, 3, &request, b"intro-seed-2");

    sim.crash(line[1]);
    sim.crash(line[3]);
    sim.inject_frame(client, line[0], intro_frame(&intro));
    sim.run_for(Duration::from_millis(2000));

    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == line[0] && from == ANON && bytes == request.as_slice()),
        "the surviving {{0,2,4}} subset still serves"
    );
}

#[test]
fn below_threshold_seizure_serves_nothing() {
    // Only 2 of 5 reachable (below t=3): the combiner can never gather enough PartialDecs, and a
    // below-threshold share set reconstructs the WRONG AEAD key, so `open` fails — 0-knowledge, not a
    // mere timeout. Nothing is surfaced anywhere.
    let mut sim = Sim::new(0x9903);
    let (line, pubs) = spawn_line(&mut sim, 5, 3);
    let client = Point::<F2>::at(5).coords();
    let intro = seal(&pubs, 3, b"secret content nobody serves", b"intro-seed-3");

    sim.crash(line[1]);
    sim.crash(line[2]);
    sim.crash(line[3]);
    sim.inject_frame(client, line[0], intro_frame(&intro));
    sim.run_for(Duration::from_millis(2000));

    assert!(
        sim.report()
            .deliveries()
            .next()
            .is_none(),
        "below threshold, the line never decrypts and nothing is served"
    );
}

#[test]
fn concurrent_intros_are_multiplexed_by_id() {
    // The production engine tracks many intros at once (the template handled one): two distinct intros to
    // the same combiner are both threshold-decrypted and surfaced, keyed by their intro ids.
    let mut sim = Sim::new(0x9904);
    let (line, pubs) = spawn_line(&mut sim, 5, 3);
    let client = Point::<F2>::at(5).coords();
    let req_a = b"first concurrent request".to_vec();
    let req_b = b"second concurrent request".to_vec();
    let intro_a = seal(&pubs, 3, &req_a, b"intro-seed-a");
    let intro_b = seal(&pubs, 3, &req_b, b"intro-seed-b");

    sim.inject_frame(client, line[0], intro_frame(&intro_a));
    sim.inject_frame(client, line[0], intro_frame(&intro_b));
    sim.run_for(Duration::from_millis(2000));

    let served: Vec<Vec<u8>> = sim
        .report()
        .deliveries()
        .filter(|(recv, from, _)| *recv == line[0] && *from == ANON)
        .map(|(_, _, bytes)| bytes.to_vec())
        .collect();
    assert!(served.contains(&req_a), "the first concurrent intro was served");
    assert!(served.contains(&req_b), "the second concurrent intro was served");
}

#[test]
fn a_client_discovers_the_roster_and_seals_an_openable_intro() {
    // The full discovery -> seal -> serve loop: a client that holds only the line's published roster
    // (round-tripped through the wire, as it would be resolved from a descriptor) seals its intro to the
    // whole line via `ServiceLine::seal_intro`, sends it to the roster's combiner, and the line serves it.
    let mut sim = Sim::new(0x9906);
    let (line, pubs) = spawn_line(&mut sim, 5, 3);
    let client = Point::<F2>::at(5).coords();

    // Publish the roster (member keys + coordinates + threshold) and re-decode it client-side.
    let roster = ServiceLine {
        threshold: 3,
        members: pubs
            .iter()
            .zip(&line)
            .map(|(p, &coord)| LineMember {
                member_pubkey: p.encode(),
                coordinate: coord,
            })
            .collect(),
    };
    let resolved = ServiceLine::from_wire(&roster.to_wire()).unwrap();

    let request = b"served from a discovered roster".to_vec();
    let intro = resolved.seal_intro(&request, b"roster-live-seed").unwrap();
    let combiner = resolved.combiner().unwrap();
    assert_eq!(combiner, line[0]);

    sim.inject_frame(client, combiner, intro_frame(&intro));
    sim.run_for(Duration::from_millis(2000));

    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == combiner && from == ANON && bytes == request.as_slice()),
        "a client with only the roster reached and was served by the threshold line"
    );
}

#[test]
fn a_replayed_intro_is_served_at_most_once() {
    // Sending the same intro twice must not re-run the serve path: the engine remembers served ids.
    let mut sim = Sim::new(0x9905);
    let (line, pubs) = spawn_line(&mut sim, 5, 3);
    let client = Point::<F2>::at(5).coords();
    let request = b"replay me".to_vec();
    let intro = seal(&pubs, 3, &request, b"intro-seed-replay");

    sim.inject_frame(client, line[0], intro_frame(&intro));
    sim.run_for(Duration::from_millis(2000));
    // Replay the identical intro after the first was served.
    sim.inject_frame(client, line[0], intro_frame(&intro));
    sim.run_for(Duration::from_millis(2000));

    let serves = sim
        .report()
        .deliveries()
        .filter(|(recv, from, bytes)| {
            *recv == line[0] && *from == ANON && *bytes == request.as_slice()
        })
        .count();
    assert_eq!(serves, 1, "a replayed intro is served at most once");
}
