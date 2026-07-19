//! E4∩E5 mix-relay end-to-end (#54): a cell of [`MixRelay`] composite engines runs the distributed
//! beacon **and** routes threshold onions — one engine per node. A single epoch tick converges the
//! beacon and rotates every relay's forward-secure onion key to the new epoch in lock-step; a client
//! then reaches the beacon-derived meeting line, sealed to the **new** epoch's keys, through the very
//! same relays. This is the whole E4∩E5 loop — unpredictable rendezvous (E5) over forward-secure,
//! epoch-rotated hops (E4) — proven in one composite node role.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_aphantos::ThresholdRouter;
use fanos_field::F2;
use fanos_geometry::{Line, Point};
use fanos_keygen::BeaconNode;
use fanos_node::MixRelay;
use fanos_pqcrypto::{HybridKemSecret, OnionKeyRatchet, SeedRng};
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, Epoch, MixDirectory, combiner_for, meeting_line, seal_forward,
};
use fanos_runtime::{Command, Duration, Notification};
use fanos_sim::Sim;
use fanos_vrf::vss::{DeterministicRng, VssCommitment, VssShare, deal};

const BEACON_T: usize = 4;
const ONION_T: u8 = 2;

/// The forward-secure onion-ratchet genesis for the relay at Fano point `i`.
fn onion_seed(i: usize) -> [u8; 32] {
    let mut s = [0xD0u8; 32];
    s[31] = i as u8;
    s
}

/// A `BEACON_T`-of-7 sharing (stands for a completed DKG — its networked realisation is proven in
/// fanos-keygen). Returns the anchors' shares and the group commitment.
fn beacon_group() -> (Vec<VssShare>, VssCommitment) {
    deal(
        &[0xB5; 32],
        BEACON_T,
        7,
        &mut DeterministicRng::new(b"mixrelay-cell"),
    )
    .unwrap()
}

#[test]
fn a_mixrelay_cell_beacons_rotates_and_rendezvouses() {
    let (shares, commitment) = beacon_group();
    let mut sim = Sim::new(0x54E0);

    // A cell of 7 MixRelays: each hosts a threshold router + a beacon anchor at one Fano point.
    for (i, &share) in shares.iter().enumerate() {
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xC0, i as u8]));
        let router = ThresholdRouter::<F2>::new(
            Point::at(i),
            &identity,
            usize::from(ONION_T),
            onion_seed(i),
        );
        let beacon = BeaconNode::<F2>::new(Point::at(i), Some(share), commitment.clone(), BEACON_T);
        sim.add(Box::new(MixRelay::new(router, beacon)));
    }

    // One epoch tick: the beacons flood partials, converge on epoch 1's seed, and — inside each composite
    // — every router rotates its onion key to epoch 1 in lock-step.
    sim.inject_all(&Command::AdvanceEpoch);
    sim.run_for(Duration::from_millis(2000));

    // Every relay's beacon adopted epoch 1 and the whole cell agreed on one seed.
    let readies: Vec<[u8; 32]> = sim
        .report()
        .notifications
        .iter()
        .filter_map(|o| match &o.note {
            Notification::BeaconReady { epoch, seed } if *epoch == Epoch::new(1) => Some(*seed),
            _ => None,
        })
        .collect();
    assert_eq!(readies.len(), 7, "every relay's beacon adopted epoch 1");
    let seed = readies[0];
    assert!(
        readies.iter().all(|&s| s == seed),
        "the cell agreed on one beacon seed"
    );

    // The epoch-1 onion directory: each router rotated to epoch 1, whose public is deterministic from the
    // relay's onion seed — a client for epoch 1 seals to these.
    let mut dir = MixDirectory::new();
    for i in 0..7 {
        let mut ratchet = OnionKeyRatchet::new(onion_seed(i), Epoch::ZERO);
        ratchet.advance_to(Epoch::new(1));
        dir.insert(Point::<F2>::at(i).coords(), ratchet.public().clone());
    }

    // A rendezvous on the beacon-derived meeting line, sealed to the epoch-1 keys, delivers through the
    // now-rotated relays — E5 line over E4-rotated hops, end to end.
    let bseed = BeaconSeed::from(seed);
    let meeting = meeting_line::<F2>(b"mixrelay-svc", Epoch::new(1), &bseed).coords();
    let hop = (0..7)
        .map(|i| Line::<F2>::at(i).coords())
        .find(|&l| l != meeting)
        .unwrap();
    let payload = b"through the mixrelay cell";
    let fwd = seal_forward::<F2>(&[hop, meeting], &dir, ONION_T, payload, b"mr-seed").unwrap();
    sim.inject_frame(Point::<F2>::at(6).coords(), fwd.combiner, fwd.frame);
    sim.run_for(Duration::from_millis(4000));

    let l_comb = combiner_for::<F2>(meeting).unwrap();
    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == l_comb && from == ANONYMOUS && bytes == payload),
        "an onion sealed to the epoch-1 beacon line delivered through the rotated MixRelay cell"
    );
}
