//! E5 end-to-end: the distributed randomness beacon drives an **unpredictable** rendezvous (spec §5.6,
//! §L3; audit E5).
//!
//! A `t`-of-`n` group holds a DKG'd key (set up here with `vss::deal` — the DKG *realisation* of that
//! sharing is proven in `fanos-vrf`/`fanos-keygen`). Each epoch, `≥ t` members emit beacon partials that
//! anyone verifies against the group commitment and combines into the epoch's public seed. Client and
//! service both fold that seed into the meeting line ([`meeting_line`]) and rendezvous over the
//! threshold-onion mixnet — so:
//!
//! * the beacon-derived line is a *real* rendezvous point (an onion sealed to it delivers anonymously);
//! * a **future** epoch's line is uncomputable until that epoch's beacon is revealed (holding the
//!   current beacon reveals nothing about the next line — the defence against pre-positioning); and
//! * a **sub-threshold** coalition cannot form the beacon at all, so it cannot compute any line ahead.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_aphantos::ThresholdRouter;
use fanos_field::F2;
use fanos_geometry::{Line, Point};
use fanos_pqcrypto::{HybridKemSecret, OnionKeyRatchet, SeedRng};
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, Epoch, MixDirectory, combiner_for, meeting_line, seal_forward,
};
use fanos_runtime::Duration;
use fanos_sim::Sim;
use fanos_vrf::beacon::{BeaconRound, partial_eval};
use fanos_vrf::vss::{DeterministicRng, VssCommitment, VssShare, deal};

/// The service key both parties know (the rendezvous is computed from it, not published).
const SERVICE_PUBKEY: &[u8] = b"beacon-rendezvous-service";
/// Beacon threshold (`t`-of-7 anchors must cooperate to produce a seed).
const BEACON_T: usize = 4;

/// Spawn a Fano mixnet of threshold routers, returning the onion-key directory (as the other rendezvous
/// tests do — each relay advertises its forward-secure onion public, audit E4).
fn spawn_mixnet(sim: &mut Sim, onion_t: usize) -> MixDirectory {
    let mut dir = MixDirectory::new();
    for i in 0..7 {
        let point = Point::<F2>::at(i);
        let mut rng = SeedRng::from_seed(&[0xB0, i as u8]);
        let (secret, _identity) = HybridKemSecret::generate(&mut rng);
        let mut onion_seed = [0xE5u8; 32];
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

/// A `BEACON_T`-of-7 beacon group (a completed DKG, stood up here with a trusted deal — the networked
/// DKG that realises it is proven in `fanos-vrf`/`fanos-keygen`). Returns the members' shares and the
/// public group commitment their partials verify against.
fn beacon_group() -> (Vec<VssShare>, VssCommitment) {
    let mut secret = [0u8; 32];
    secret[0] = 0xBE;
    secret[1] = 0xAC;
    deal(
        &secret,
        BEACON_T,
        7,
        &mut DeterministicRng::new(b"e5-beacon-group"),
    )
    .unwrap()
}

/// The network's public beacon seed for `epoch`: `BEACON_T` members each emit a partial, which anyone
/// verifies against the group commitment and combines into the canonical seed.
fn beacon_seed(shares: &[VssShare], commitment: &VssCommitment, epoch: Epoch) -> BeaconSeed {
    let partials: Vec<_> = shares
        .iter()
        .take(BEACON_T)
        .map(|s| partial_eval(s, epoch))
        .collect();
    let round = BeaconRound::assemble(epoch, &partials, BEACON_T).unwrap();
    BeaconSeed::from(round.verify_and_seed(commitment, BEACON_T).unwrap())
}

#[test]
fn a_beacon_derived_meeting_line_delivers_over_the_mixnet() {
    let mut sim = Sim::new(0xE5D);
    let onion_t = 2usize; // 2-of-3 per Fano line (independent of the beacon threshold)
    let dir = spawn_mixnet(&mut sim, onion_t);
    let (shares, commitment) = beacon_group();

    // At epoch e the network's beacon fixes the seed; client and service both derive the same line.
    let epoch = Epoch::new(5);
    let seed = beacon_seed(&shares, &commitment, epoch);
    let meeting = meeting_line::<F2>(SERVICE_PUBKEY, epoch, &seed).coords();

    // Seal a 2-hop onion to the beacon-derived meeting line and launch it; it must deliver anonymously.
    let hop = (0..7)
        .map(|i| Line::<F2>::at(i).coords())
        .find(|&l| l != meeting)
        .unwrap();
    let payload = b"hello beacon rendezvous";
    let fwd =
        seal_forward::<F2>(&[hop, meeting], &dir, onion_t as u8, payload, b"e5-seed").unwrap();
    sim.inject_frame(Point::<F2>::at(6).coords(), fwd.combiner, fwd.frame);
    sim.run_for(Duration::from_millis(4000));

    let l_comb = combiner_for::<F2>(meeting).unwrap();
    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| recv == l_comb && from == ANONYMOUS && bytes == payload),
        "an onion sealed to the beacon-derived meeting line delivered anonymously"
    );
}

#[test]
fn a_future_epochs_line_is_unpredictable_without_that_epochs_beacon() {
    let (shares, commitment) = beacon_group();

    let seed_e = beacon_seed(&shares, &commitment, Epoch::new(9));
    let seed_e1 = beacon_seed(&shares, &commitment, Epoch::new(10));
    // The per-epoch seeds are independent DDH values (x·M(9) vs x·M(10)); one does not yield the next.
    assert_ne!(seed_e.as_bytes(), seed_e1.as_bytes());

    let line_e = meeting_line::<F2>(SERVICE_PUBKEY, Epoch::new(9), &seed_e).coords();
    let line_e1 = meeting_line::<F2>(SERVICE_PUBKEY, Epoch::new(10), &seed_e1).coords();
    // What an adversary holding *only* epoch 9's beacon would compute for epoch 10 (reusing the stale
    // seed) — it is not epoch 10's real line, so the current beacon reveals nothing about the next one.
    let stale_guess = meeting_line::<F2>(SERVICE_PUBKEY, Epoch::new(10), &seed_e).coords();

    assert_ne!(line_e, line_e1, "the meeting line rotates with the beacon");
    assert_ne!(
        stale_guess, line_e1,
        "epoch 9's beacon does not predict epoch 10's rendezvous line"
    );
}

#[test]
fn a_sub_threshold_coalition_cannot_form_the_beacon() {
    let (shares, commitment) = beacon_group();
    let epoch = Epoch::new(3);

    // BEACON_T − 1 partials cannot assemble a round — a coalition below threshold computes no seed, so it
    // cannot derive (nor pre-position on) any epoch's meeting line ahead of the honest anchors.
    let short: Vec<_> = shares
        .iter()
        .take(BEACON_T - 1)
        .map(|s| partial_eval(s, epoch))
        .collect();
    assert!(BeaconRound::assemble(epoch, &short, BEACON_T).is_none());

    // With the full threshold the round forms and yields a seed.
    let full: Vec<_> = shares
        .iter()
        .take(BEACON_T)
        .map(|s| partial_eval(s, epoch))
        .collect();
    assert!(
        BeaconRound::assemble(epoch, &full, BEACON_T)
            .unwrap()
            .verify_and_seed(&commitment, BEACON_T)
            .is_some()
    );
}
