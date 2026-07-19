//! E4∩E5 end-to-end (#94): the **networked** `BeaconNode` cell produces each epoch's seed over the
//! simulated overlay, and that live seed drives a working anonymous rendezvous over the threshold-onion
//! mixnet — the epoch clock in action, not a hand-combined seed.
//!
//! This composes the two subsystems the driver bridges: the beacon cell (anchors flood partials, verify,
//! and converge on the epoch seed, announced via `Notification::BeaconReady`) and the CALYPSO/APHANTOS
//! rendezvous (client and service fold the seed into the meeting line and meet through `t`-of-`(q+1)`
//! onion hops). The beacon sharing is stood up with `vss::deal`; its networked DKG realisation and the
//! DKG→beacon composition are proven in `fanos-keygen`/`fanos-vrf`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_aphantos::ThresholdRouter;
use fanos_field::F2;
use fanos_geometry::{Line, Point};
use fanos_keygen::BeaconNode;
use fanos_pqcrypto::{HybridKemSecret, OnionKeyRatchet, SeedRng};
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, Epoch, MixDirectory, combiner_for, meeting_line, seal_forward,
};
use fanos_runtime::{Command, Duration, Notification};
use fanos_sim::Sim;
use fanos_vrf::beacon::{BeaconRound, partial_eval};
use fanos_vrf::vss::{DeterministicRng, VssCommitment, VssShare, deal};

/// Beacon threshold (`t`-of-7 anchors).
const BEACON_T: usize = 4;

/// A `BEACON_T`-of-7 sharing (stands for a completed DKG — its networked realisation is proven in
/// fanos-keygen). Returns the anchors' shares and the public group commitment.
fn beacon_group() -> (Vec<VssShare>, VssCommitment) {
    deal(
        &[0xBE; 32],
        BEACON_T,
        7,
        &mut DeterministicRng::new(b"e2e-beacon"),
    )
    .unwrap()
}

/// Run a `BeaconNode` cell for one epoch over the simulator, returning the `(epoch, seed)` the whole
/// cell agreed on — read from the `BeaconReady` notifications the engines emit.
fn produce_beacon_seed(shares: &[VssShare], commitment: &VssCommitment) -> (Epoch, [u8; 32]) {
    let mut sim = Sim::new(0xB2C0);
    for (i, share) in shares.iter().enumerate() {
        let node = BeaconNode::<F2>::new(Point::at(i), Some(*share), commitment.clone(), BEACON_T);
        sim.add(Box::new(node));
    }
    // One epoch tick to every anchor: they flood partials, assemble the round, and announce the seed.
    sim.inject_all(&Command::AdvanceEpoch);
    sim.run_for(Duration::from_millis(2000));

    let readies: Vec<(Epoch, [u8; 32])> = sim
        .report()
        .notifications
        .iter()
        .filter_map(|o| match &o.note {
            Notification::BeaconReady { epoch, seed } => Some((*epoch, *seed)),
            _ => None,
        })
        .collect();
    assert_eq!(readies.len(), 7, "every beacon node announced the epoch");
    let (e0, s0) = readies[0];
    assert!(
        readies.iter().all(|&(e, s)| e == e0 && s == s0),
        "the whole cell agreed on one beacon seed"
    );
    (e0, s0)
}

/// Spawn a Fano threshold-onion mixnet, returning the onion-key directory (as the rendezvous tests do).
fn spawn_mixnet(sim: &mut Sim, onion_t: usize) -> MixDirectory {
    let mut dir = MixDirectory::new();
    for i in 0..7 {
        let point = Point::<F2>::at(i);
        let mut rng = SeedRng::from_seed(&[0xB0, i as u8]);
        let (secret, _identity) = HybridKemSecret::generate(&mut rng);
        let mut onion_seed = [0xE7u8; 32];
        onion_seed[31] = i as u8;
        let onion_public = OnionKeyRatchet::new(onion_seed, Epoch::ZERO)
            .public()
            .clone();
        dir.insert(point.coords(), onion_public);
        sim.add(Box::new(ThresholdRouter::<F2>::new(
            point, &secret, onion_t, onion_seed,
        )));
    }
    dir
}

#[test]
fn the_beacon_node_cell_drives_a_working_rendezvous() {
    let (shares, commitment) = beacon_group();

    // 1) The networked beacon cell produces epoch 1's seed and every node agrees on it.
    let (epoch, seed) = produce_beacon_seed(&shares, &commitment);
    assert_eq!(epoch, Epoch::new(1));
    assert_ne!(seed, [0u8; 32]);

    // The engine's seed is exactly the canonical DVRF output (a direct combine of the same partials).
    let partials: Vec<_> = shares
        .iter()
        .take(BEACON_T)
        .map(|s| partial_eval(s, epoch))
        .collect();
    let canonical = BeaconRound::assemble(epoch, &partials, BEACON_T)
        .unwrap()
        .verify_and_seed(&commitment, BEACON_T)
        .unwrap();
    assert_eq!(
        seed, canonical,
        "the networked beacon matches the canonical DVRF output"
    );

    // 2) That live seed drives a real rendezvous: an onion to the beacon-derived meeting line delivers.
    let mut sim = Sim::new(0xB2D0);
    let onion_t = 2usize;
    let dir = spawn_mixnet(&mut sim, onion_t);
    let bseed = BeaconSeed::from(seed);
    let meeting = meeting_line::<F2>(b"e2e-service", epoch, &bseed).coords();
    let hop = (0..7)
        .map(|i| Line::<F2>::at(i).coords())
        .find(|&l| l != meeting)
        .unwrap();
    let payload = b"beacon-driven rendezvous";
    let fwd =
        seal_forward::<F2>(&[hop, meeting], &dir, onion_t as u8, payload, b"e2e-seed").unwrap();
    sim.inject_frame(Point::<F2>::at(6).coords(), fwd.combiner, fwd.frame);
    sim.run_for(Duration::from_millis(4000));

    let l_comb = combiner_for::<F2>(meeting).unwrap();
    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == l_comb && from == ANONYMOUS && bytes == payload),
        "an onion to the beacon-node-derived meeting line delivered anonymously"
    );
}
