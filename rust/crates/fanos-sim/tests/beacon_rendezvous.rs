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
use fanos_geometry::{Line, Point, Triple};
use fanos_pqcrypto::{HybridKemSecret, OnionKeyRatchet, SeedRng};
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, Epoch, MixDirectory, line_member_coords, meeting_line, seal_forward,
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

    // The launch and final gather are per-onion salted picks (#55), so the delivery surfaces at
    // whichever MEMBER of the meeting line gathered it — membership, not the canonical combiner,
    // is the invariant.
    let members = line_member_coords::<F2>(meeting);
    assert!(
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| members.contains(&recv) && from == ANONYMOUS && bytes == payload),
        "an onion sealed to the beacon-derived meeting line delivered anonymously at a line member"
    );
}

/// **A hidden service survives the epoch turn, and the line it was reached at stops working.**
///
/// The two properties beside it cover one epoch each: a beacon-derived line delivers *now*, and next epoch's
/// line is uncomputable *now*. Neither says what a testnet operator actually needs — that a service reachable
/// at epoch `e` is still reachable at `e + 1` with no out-of-band step, because both ends re-derive the line
/// from a beacon they each already verify.
///
/// It also asserts the half that makes the rotation worth having: the **old** line is no longer where the
/// service is. Without that, a scenario that never moved would pass, and the rotation would be decoration.
/// A client that cached `e`'s line and kept using it must find nobody, which is exactly the property that
/// makes a rendezvous point unlinkable across epochs.
///
/// Not a timing test: the epoch is advanced by deriving the next seed, the same way every node does when the
/// beacon lands. What is *not* covered here and needs a live fleet is the transport-level turn — connections,
/// directory re-keying, and the reshuffle running underneath a session in flight.
#[test]
fn a_service_reached_at_one_epoch_is_reached_at_the_next_and_not_at_the_old_line() {
    let mut sim = Sim::new(0xE5E);
    let onion_t = 2usize;
    let dir = spawn_mixnet(&mut sim, onion_t);
    let (shares, commitment) = beacon_group();

    let (before, after) = (Epoch::new(5), Epoch::new(6));
    let seed_before = beacon_seed(&shares, &commitment, before);
    let seed_after = beacon_seed(&shares, &commitment, after);
    let line_before = meeting_line::<F2>(SERVICE_PUBKEY, before, &seed_before).coords();
    let line_after = meeting_line::<F2>(SERVICE_PUBKEY, after, &seed_after).coords();
    assert_ne!(
        line_before, line_after,
        "the meeting line must move with the epoch, or there is nothing here to survive and nothing to \
         unlink — this is the premise the two deliveries below are measured against"
    );

    let deliver = |sim: &mut Sim, line: Triple, payload: &[u8]| {
        let hop = (0..7).map(|i| Line::<F2>::at(i).coords()).find(|&l| l != line).unwrap();
        let fwd = seal_forward::<F2>(&[hop, line], &dir, onion_t as u8, payload, b"e5-turn").unwrap();
        sim.inject_frame(Point::<F2>::at(6).coords(), fwd.combiner, fwd.frame);
        sim.run_for(Duration::from_millis(4000));
    };
    let arrived = |sim: &Sim, line: Triple, payload: &[u8]| {
        let members = line_member_coords::<F2>(line);
        sim.report()
            .deliveries()
            .any(|(recv, from, bytes)| members.contains(&recv) && from == ANONYMOUS && bytes == payload)
    };

    deliver(&mut sim, line_before, b"before the turn");
    assert!(arrived(&sim, line_before, b"before the turn"), "the service is reachable at its epoch's line");

    // The turn: nothing is re-negotiated, both ends simply fold the next beacon into the same derivation.
    deliver(&mut sim, line_after, b"after the turn");
    assert!(
        arrived(&sim, line_after, b"after the turn"),
        "the service must be reachable at the next epoch's line with no out-of-band step — a hidden service \
         that needs one has not survived the turn"
    );

    // And the old line is not where it is any more: a client holding `before`'s line reaches nobody with it.
    assert!(
        !arrived(&sim, line_before, b"after the turn"),
        "the payload sent to the NEW line surfaced at the OLD one, so the two lines share a member and this \
         scenario cannot tell a survived turn from a line that never moved"
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
