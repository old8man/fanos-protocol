//! Networked distributed key generation over the simulated cell (spec §L6): real `DkgNode` engines
//! run a `t`-of-`n` Feldman/Pedersen DKG **with a complaint round** by exchanging `DkgDeal` /
//! `DkgCommit` / `DkgComplaint` / `DkgJustify` frames, and **every honest node converges on the same
//! joint public key** — whose secret no node holds — even against an offline or a *Byzantine
//! equivocating* dealer. The DKG *logic* is unit-verified in `fanos-vrf::dkg`; here it runs end to
//! end over the transport, as it would in a real threshold-hosting bootstrap.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_field::F2;
use fanos_geometry::{Plane, Point, Triple};
use fanos_keygen::DkgNode;
use fanos_runtime::{Command, Duration, Notification};
use fanos_sim::Sim;
use fanos_vrf::dkg;
use fanos_vrf::vss::{DeterministicRng, VssCommitment, VssShare};
use fanos_wire::{FrameType, encode_frame};

/// Short phase deadlines so the two-phase (sharing + complaint) protocol settles fast under test.
const SHARING: Duration = Duration::from_millis(500);
const COMPLAINT: Duration = Duration::from_millis(500);
/// A run window comfortably past both phases.
const WINDOW: Duration = Duration::from_millis(1600);

fn secret_of(i: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = i as u8;
    s[1] = 0xD6;
    s
}

/// A distinct per-node session nonce (fresh per-DKG-instance entropy, audit B6). Deterministic here so
/// the simulation stays reproducible; a real deployment draws it from a CSPRNG each run.
fn nonce_of(i: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = i as u8;
    s[1] = 0x9E;
    s
}

/// Spawn a cell of `DkgNode`s (one per Fano point), each with a distinct secret seed.
fn spawn_dkg_cell(sim: &mut Sim, threshold: usize) -> Vec<Triple> {
    let mut coords = Vec::new();
    for (i, point) in Plane::<F2>::points().enumerate() {
        let node = DkgNode::<F2>::new(point, threshold, secret_of(i), nonce_of(i))
            .with_deadlines(SHARING, COMPLAINT);
        coords.push(sim.add(Box::new(node)));
    }
    coords
}

/// The joint keys each node announced (node coord → Y).
fn completions(sim: &Sim) -> Vec<(Triple, [u8; 32])> {
    sim.report()
        .notifications
        .iter()
        .filter_map(|o| match &o.note {
            Notification::DkgComplete(y) => Some((o.node, *y)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_cell_runs_a_networked_dkg_and_agrees_on_the_joint_key() {
    let mut sim = Sim::new(0xD46);
    let _cell = spawn_dkg_cell(&mut sim, 4); // 4-of-7 threshold
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(WINDOW);

    let joint = completions(&sim);
    assert_eq!(joint.len(), 7, "all seven nodes completed the DKG");
    let first = joint[0].1;
    assert!(
        joint.iter().all(|(_, y)| *y == first),
        "all nodes agree on the joint public key"
    );
    assert_ne!(first, [0u8; 32], "the joint key is a real group element");
}

#[test]
fn an_offline_dealer_does_not_stall_the_honest_majority() {
    // Liveness (spec §6.4): one dealer never deals; the other six still complete on the qualified
    // subset once the deadlines pass — the offline dealer is disqualified (nobody can justify it).
    let mut sim = Sim::new(0xD47);
    let cell = spawn_dkg_cell(&mut sim, 4);
    for &node in &cell[..6] {
        sim.inject(node, Command::StartHeartbeat);
    }
    sim.run_for(WINDOW);

    let joint = completions(&sim);
    assert_eq!(joint.len(), 6, "the six online dealers complete");
    let first = joint[0].1;
    assert!(
        joint.iter().all(|(_, y)| *y == first),
        "all honest nodes agree over the qualified subset"
    );
    assert_ne!(first, [0u8; 32]);
}

#[test]
fn below_threshold_participation_does_not_finalize() {
    // Safety boundary: three dealers under a 4-threshold form no qualified subset that reaches it.
    let mut sim = Sim::new(0xD48);
    let cell = spawn_dkg_cell(&mut sim, 4);
    for &node in &cell[..3] {
        sim.inject(node, Command::StartHeartbeat);
    }
    sim.run_for(WINDOW);
    assert_eq!(
        completions(&sim).len(),
        0,
        "three dealers cannot form a 4-key"
    );
}

#[test]
fn a_byzantine_equivocating_dealer_is_disqualified_and_honest_nodes_still_agree() {
    // The headline: dealer 7 (Byzantine) broadcasts a valid commitment and deals a VALID share to
    // some honest nodes but an INVALID share to another. Without the complaint round the qualified
    // set would split (some keep dealer 7, some drop it). With it, the victim complains, dealer 7
    // (an injector) never justifies, so *every* honest node disqualifies dealer 7 and they all
    // converge on the same key over the honest dealers {1..6}.
    let mut sim = Sim::new(0xD49);

    // Spawn six honest DkgNodes at points 0..5 (indices 1..6); point 6 (index 7) is the adversary.
    let points: Vec<Point<F2>> = Plane::<F2>::points().collect();
    let honest: Vec<Triple> = points[..6]
        .iter()
        .enumerate()
        .map(|(i, &p)| {
            let node = DkgNode::<F2>::new(p, 4, secret_of(i), nonce_of(i))
                .with_deadlines(SHARING, COMPLAINT);
            sim.add(Box::new(node))
        })
        .collect();
    let adversary = points[6].coords();

    // The adversary's dealing (index 7 addresses points 1..=7 as 1-based).
    let adv_secret = secret_of(0xB7);
    let mut rng = DeterministicRng::new(&adv_secret);
    let dealing = dkg::deal(&adv_secret, 4, 7, &mut rng).unwrap();
    let commitment = dealing.commitment().clone();

    // Broadcast a VALID commitment for dealer 7 to every honest node (they treat 7 as a candidate).
    for &h in &honest {
        sim.inject_frame(adversary, h, commit_frame(7, &commitment));
    }
    // Deal a VALID share to honest nodes 1..5, and an INVALID one to node 6 (the victim).
    for (i, &h) in honest.iter().enumerate() {
        let holder = (i + 1) as u8; // 1-based index of this honest node
        let share = if holder == 6 {
            corrupt_share_for(&dealing, 6) // wrong value for index 6 → fails verification
        } else {
            *dealing.share_for(holder).unwrap()
        };
        sim.inject_frame(adversary, h, deal_frame(&share, &commitment));
    }

    sim.inject_all(&Command::StartHeartbeat); // the six honest nodes begin dealing
    sim.run_for(WINDOW);

    let joint = completions(&sim);
    assert_eq!(
        joint.len(),
        6,
        "all six honest nodes complete despite the equivocating dealer"
    );
    let first = joint[0].1;
    assert!(
        joint.iter().all(|(_, y)| *y == first),
        "honest nodes agree on ONE key — the equivocation did not split the qualified set: {joint:?}"
    );
    assert_ne!(first, [0u8; 32]);
}

#[test]
fn dkg_is_reproducible_per_seed() {
    let run = || {
        let mut sim = Sim::new(5);
        let _cell = spawn_dkg_cell(&mut sim, 3);
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(WINDOW);
        completions(&sim).first().map(|(_, y)| *y).unwrap()
    };
    assert_eq!(run(), run());
}

// --- Adversary frame helpers (mirror the private keygen wire format) ---

fn commit_frame(dealer: u8, commitment: &VssCommitment) -> Vec<u8> {
    let mut body = vec![dealer];
    body.extend_from_slice(&commitment.to_bytes());
    let mut out = Vec::new();
    encode_frame(FrameType::DkgCommit.code(), &body, &mut out);
    out
}

fn deal_frame(share: &VssShare, commitment: &VssCommitment) -> Vec<u8> {
    let mut body = share.to_bytes().to_vec();
    body.extend_from_slice(&commitment.to_bytes());
    let mut out = Vec::new();
    encode_frame(FrameType::DkgDeal.code(), &body, &mut out);
    out
}

/// A share that *claims* holder `index` but carries a value that does not satisfy the commitment at
/// that index (here, the value legitimately dealt to `index-1`), so it fails Feldman verification.
fn corrupt_share_for(dealing: &dkg::Dealing, index: u8) -> VssShare {
    let wrong = dealing.share_for(index - 1).unwrap();
    let mut bytes = wrong.to_bytes();
    bytes[0] = index; // relabel: index = `index`, value = f(index-1) ≠ f(index)
    VssShare::from_bytes(&bytes).unwrap()
}
