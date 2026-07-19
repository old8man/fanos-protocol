//! Boundary + adversarial coverage for the anonymous rendezvous, beyond the happy-path scenarios in
//! `anonymous_rendezvous.rs`:
//!
//! * **deeper circuits** — a 3-hop onion still delivers (the layering is not limited to two hops);
//! * **threshold extremes** — 1-of-`(q+1)` and `(q+1)`-of-`(q+1)` both deliver;
//! * **a starved hop** — when fewer than `t` of a hop's members are live, the onion cannot be peeled,
//!   so nothing is delivered and nothing panics (graceful degradation, not a silent wrong delivery);
//! * **a larger plane** — the whole flow works unchanged on PG(2,3) (13 points, lines of 4), proving
//!   nothing is hard-wired to the Fano plane;
//! * **epoch rotation** — the meeting line moves across epochs, and an onion for one epoch does not
//!   reach another epoch's rendezvous point.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_aphantos::ThresholdRouter;
use fanos_aphantos::threshold_router::line_member_coords;
use fanos_field::{F2, Field, GfP};
use fanos_geometry::{Line, Point, Triple};
use fanos_pqcrypto::{HybridKemSecret, OnionKeyRatchet, SeedRng};
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, MixDirectory, combiner_for, meeting_line, seal_forward,
};
use fanos_runtime::Duration;
use fanos_sim::Sim;

/// GF(3): the field of the next projective plane up from Fano, PG(2,3).
type F3 = GfP<3>;

/// A fixed live-epoch beacon seed for these derivation tests, held constant across epochs (the line
/// still rotates by epoch; the beacon's per-epoch variation is exercised in the beacon's own tests).
const BEACON: BeaconSeed = BeaconSeed::new([0x5B; 32]);

/// Spawn a `ThresholdRouter` at every point of PG(2,q) for field `F`, returning the members' key
/// directory. Every point's KEM key is recorded (so sealing always succeeds); a router is *omitted*
/// for any coordinate in `skip_routers`, which lets a test starve a hop below its threshold while the
/// onion is still sealed to the full membership.
fn spawn_plane<F: Field + 'static>(
    sim: &mut Sim,
    t: usize,
    skip_routers: &[Triple],
) -> MixDirectory {
    let q = <F as Field>::Q as usize;
    let n = q * q + q + 1;
    let mut dir = MixDirectory::new();
    for i in 0..n {
        let point = Point::<F>::at(i);
        let coord = point.coords();
        let mut rng = SeedRng::from_seed(&[0xB0, i as u8, q as u8]);
        let (secret, _identity) = HybridKemSecret::generate(&mut rng);
        // The directory carries each relay's forward-secure ONION public (audit E4); the relay peels
        // with the onion secret derived from the same genesis seed.
        let mut onion_seed = [0xA1u8; 32];
        onion_seed[30] = q as u8;
        onion_seed[31] = i as u8;
        let onion_public = OnionKeyRatchet::new(onion_seed, fanos_rendezvous::Epoch::ZERO)
            .public()
            .clone();
        dir.insert(coord, onion_public);
        if !skip_routers.contains(&coord) {
            sim.add(Box::new(ThresholdRouter::<F>::new(
                point, &secret, t, onion_seed,
            )));
        }
    }
    dir
}

/// Whether `payload` was delivered anonymously to `combiner` at any point in the run.
fn delivered_anonymously(sim: &Sim, combiner: Triple, payload: &[u8]) -> bool {
    sim.report()
        .deliveries()
        .any(|(recv, from, bytes)| recv == combiner && from == ANONYMOUS && bytes == payload)
}

#[test]
fn a_deeper_multi_hop_circuit_still_delivers() {
    let mut sim = Sim::new(0x3303);
    let t = 2usize;
    let dir = spawn_plane::<F2>(&mut sim, t, &[]);

    let meeting =
        meeting_line::<F2>(b"deep-svc", fanos_rendezvous::Epoch::new(2), &BEACON).coords();
    let others: Vec<Triple> = (0..7)
        .map(|i| Line::<F2>::at(i).coords())
        .filter(|&l| l != meeting)
        .collect();
    // Three hops before the destination — a strictly deeper onion than the 2-hop happy path.
    let circuit = [others[0], others[1], meeting];
    let payload = b"deep-client-hello";
    let fwd = seal_forward::<F2>(&circuit, &dir, t as u8, payload, b"deep-seed").unwrap();
    sim.inject_frame(Point::<F2>::at(6).coords(), fwd.combiner, fwd.frame);
    sim.run_for(Duration::from_millis(4000));

    let l_comb = combiner_for::<F2>(meeting).unwrap();
    assert!(
        delivered_anonymously(&sim, l_comb, payload),
        "a 3-hop onion still delivers anonymously to the meeting line"
    );
}

#[test]
fn threshold_extremes_still_deliver() {
    // 1-of-3 (any single member peels) and 3-of-3 (unanimity) on the Fano lines.
    for t in [1usize, 3usize] {
        let mut sim = Sim::new(0x7700 + t as u64);
        let dir = spawn_plane::<F2>(&mut sim, t, &[]);
        let meeting =
            meeting_line::<F2>(b"thr-svc", fanos_rendezvous::Epoch::new(1), &BEACON).coords();
        let hop = (0..7)
            .map(|i| Line::<F2>::at(i).coords())
            .find(|&l| l != meeting)
            .unwrap();
        let payload = b"threshold-hello";
        let fwd = seal_forward::<F2>(&[hop, meeting], &dir, t as u8, payload, b"thr-seed").unwrap();
        sim.inject_frame(Point::<F2>::at(6).coords(), fwd.combiner, fwd.frame);
        sim.run_for(Duration::from_millis(4000));

        let l_comb = combiner_for::<F2>(meeting).unwrap();
        assert!(
            delivered_anonymously(&sim, l_comb, payload),
            "threshold t={t} of q+1=3 delivers"
        );
    }
}

#[test]
fn a_hop_starved_below_threshold_does_not_deliver() {
    let mut sim = Sim::new(0xDEAD);
    let t = 2usize;
    let meeting =
        meeting_line::<F2>(b"starve-svc", fanos_rendezvous::Epoch::new(1), &BEACON).coords();
    // Keep the combiner (the onion's entry point) live but silence the other members, so the final hop
    // has only 1 < t=2 live members and can never be reconstructed.
    let members = line_member_coords::<F2>(meeting);
    let skip = &members[1..];
    let dir = spawn_plane::<F2>(&mut sim, t, skip);

    let payload = b"starved-hello";
    let fwd = seal_forward::<F2>(&[meeting], &dir, t as u8, payload, b"starve-seed").unwrap();
    sim.inject_frame(Point::<F2>::at(6).coords(), fwd.combiner, fwd.frame);
    sim.run_for(Duration::from_millis(4000));

    let l_comb = combiner_for::<F2>(meeting).unwrap();
    assert!(
        !delivered_anonymously(&sim, l_comb, payload),
        "a hop with fewer than t live members yields no anonymous delivery — and no panic"
    );
}

#[test]
fn rendezvous_generalises_to_a_larger_plane_pg_2_3() {
    let mut sim = Sim::new(0x1303);
    let t = 2usize;
    // PG(2,3): 13 points, 13 lines of 4 points each.
    let dir = spawn_plane::<F3>(&mut sim, t, &[]);

    let meeting = meeting_line::<F3>(b"f3-svc", fanos_rendezvous::Epoch::new(1), &BEACON).coords();
    let hop = (0..13)
        .map(|i| Line::<F3>::at(i).coords())
        .find(|&l| l != meeting)
        .unwrap();
    let payload = b"pg23-hello";
    let fwd = seal_forward::<F3>(&[hop, meeting], &dir, t as u8, payload, b"f3-seed").unwrap();
    sim.inject_frame(Point::<F3>::at(12).coords(), fwd.combiner, fwd.frame);
    sim.run_for(Duration::from_millis(5000));

    let l_comb = combiner_for::<F3>(meeting).unwrap();
    assert!(
        delivered_anonymously(&sim, l_comb, payload),
        "the anonymous rendezvous works unchanged on PG(2,3) — nothing is hard-wired to Fano"
    );
}

#[test]
fn the_meeting_line_rotates_across_epochs() {
    let key = b"rotating-service";
    // Over a span of epochs the meeting line takes several distinct values — no fixed rendezvous point.
    let distinct: std::collections::BTreeSet<Triple> = (0..20u32)
        .map(|e| meeting_line::<F2>(key, fanos_rendezvous::Epoch::new(e.into()), &BEACON).coords())
        .collect();
    assert!(
        distinct.len() > 1,
        "the meeting line must not be constant across epochs (rotation)"
    );

    // An onion sealed for epoch 5 reaches epoch 5's rendezvous, but not a *different* epoch's point.
    let mut sim = Sim::new(0xE0E0);
    let t = 2usize;
    let dir = spawn_plane::<F2>(&mut sim, t, &[]);
    let l5 = meeting_line::<F2>(key, fanos_rendezvous::Epoch::new(5), &BEACON).coords();
    let hop = (0..7)
        .map(|i| Line::<F2>::at(i).coords())
        .find(|&l| l != l5)
        .unwrap();
    let payload = b"epoch5-hello";
    let fwd = seal_forward::<F2>(&[hop, l5], &dir, t as u8, payload, b"epoch-seed").unwrap();
    sim.inject_frame(Point::<F2>::at(6).coords(), fwd.combiner, fwd.frame);
    sim.run_for(Duration::from_millis(4000));

    let c5 = combiner_for::<F2>(l5).unwrap();
    assert!(
        delivered_anonymously(&sim, c5, payload),
        "delivered at the epoch-5 rendezvous"
    );
    // Find some other epoch whose combiner differs from epoch 5's, and confirm this payload never
    // landed there — an epoch-5 onion does not reach a foreign epoch's listening point.
    if let Some(other_c) = (0..20u32)
        .map(|e| {
            combiner_for::<F2>(
                meeting_line::<F2>(key, fanos_rendezvous::Epoch::new(e.into()), &BEACON).coords(),
            )
            .unwrap()
        })
        .find(|&c| c != c5)
    {
        assert!(
            !delivered_anonymously(&sim, other_c, payload),
            "an epoch-5 onion does not reach a different epoch's rendezvous point"
        );
    }
}
