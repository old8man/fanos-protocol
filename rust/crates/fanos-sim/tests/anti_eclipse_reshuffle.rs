//! **B1/B2 multi-epoch — the anti-eclipse "no pre-settling" claim (spec §3.2 assumption 2, the load-bearing
//! one).** A node's coordinate is `MapToPoint(VRF(vrf_secret, id ‖ epoch ‖ beacon))`, so it reshuffles every
//! epoch on the *unpredictable* beacon. The security consequence that the whole anti-eclipse story rests on:
//! an adversary that grinds identities to seize a target's coordinate THIS epoch **cannot maintain** the
//! seat — next epoch it reshuffles to a random point, and the next beacon is not known in time to pre-grind.
//! `sybil_cost.rs` measures the single-epoch coupon-collector cost; this measures the *cross-epoch* property
//! the reshuffle adds — seat-retention collapses to chance, the placement stays uniform (no point is easier
//! to aim at), and seizing a chosen coordinate costs a full ~N regrind that must be re-paid every epoch.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_core::membership::Member;
use fanos_field::F7;
use fanos_geometry::Plane;
use fanos_primitives::{BeaconSeed, Epoch, NodeId};
use fanos_vrf::VrfSecret;

/// A distinct adversary identity `(vrf_secret, id)` seeded by `seed`.
fn identity(seed: u32) -> (VrfSecret, NodeId) {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&seed.to_le_bytes());
    (VrfSecret::from_seed(b), NodeId(b))
}

/// The Fano-plane point index (`0..N`) this identity lands on for `(epoch, beacon)`.
fn coord_index(sk: &VrfSecret, id: NodeId, epoch: Epoch, beacon: &BeaconSeed) -> usize {
    Member::<F7>::assign(sk, id, epoch, beacon).coord.index()
}

#[test]
fn a_grinded_seat_is_not_maintained_across_an_epoch_reshuffle() {
    // §3.2 assumption 2: the VRF binds the coordinate to the epoch's beacon, so the SAME identity lands at an
    // unpredictable new point next epoch. Seat-retention across an epoch boundary must therefore be ~chance
    // (1/N), NOT persistent — a grinded position is lost on every reshuffle, so it cannot be pre-settled.
    let n = Plane::<F7>::N as usize;
    let beacon0 = BeaconSeed::GENESIS;
    let beacon1 = BeaconSeed::new([0x9A; 32]); // the next epoch's (unpredictable) beacon
    let m = 600u32;
    let retained = (0..m)
        .filter(|&s| {
            let (sk, id) = identity(s);
            coord_index(&sk, id, Epoch::ZERO, &beacon0)
                == coord_index(&sk, id, Epoch::new(1), &beacon1)
        })
        .count();
    let retention = f64::from(u32::try_from(retained).unwrap()) / f64::from(m);
    let chance = 1.0 / n as f64;
    assert!(
        retention < chance * 3.0,
        "seat retention across a reshuffle must be ~chance (1/{n} = {chance:.4}), got {retention:.4} — a \
         grinded seat is not maintained"
    );
}

#[test]
fn the_coordinate_is_deterministic_per_epoch_but_reshuffles_between_epochs() {
    // Reproducible (so a peer can verify a claimed coordinate) yet moving (so it cannot be pre-aimed): the
    // same (id, epoch, beacon) always yields the same point; a different epoch + beacon yields a different
    // point for nearly every identity.
    let (sk, id) = identity(42);
    let b0 = BeaconSeed::GENESIS;
    let b1 = BeaconSeed::new([0x11; 32]);
    assert_eq!(
        coord_index(&sk, id, Epoch::ZERO, &b0),
        coord_index(&sk, id, Epoch::ZERO, &b0),
        "the coordinate is deterministic for a fixed (id, epoch, beacon)"
    );
    let m = 300u32;
    let moved = (0..m)
        .filter(|&s| {
            let (sk, id) = identity(s);
            coord_index(&sk, id, Epoch::ZERO, &b0) != coord_index(&sk, id, Epoch::new(1), &b1)
        })
        .count();
    assert!(
        f64::from(u32::try_from(moved).unwrap()) / f64::from(m) > 0.9,
        "the reshuffle moves nearly every node ({moved}/{m})"
    );
}

#[test]
fn placement_is_uniform_so_no_seat_is_easier_to_pre_aim() {
    // The reshuffled placement lands ~uniformly over the N points, so an adversary gains nothing by aiming at
    // a "popular" coordinate — there is none (χ² well under the 0.999 critical value for N−1 dof).
    let n = Plane::<F7>::N as usize;
    let beacon = BeaconSeed::new([0x33; 32]);
    let m = n * 30; // ~30 identities per point expected
    let mut counts = vec![0usize; n];
    for s in 0..u32::try_from(m).unwrap() {
        let (sk, id) = identity(s ^ 0xABCD);
        counts[coord_index(&sk, id, Epoch::new(2), &beacon)] += 1;
    }
    let expected = m as f64 / n as f64;
    let chi2: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();
    // 56 dof, 0.999 critical value ≈ 99.6 — a uniform placement stays comfortably under.
    assert!(
        chi2 < 100.0,
        "placement must be ~uniform (χ² {chi2:.1} over {} dof)",
        n - 1
    );
}

#[test]
fn seizing_a_chosen_coordinate_costs_a_full_epoch_regrind() {
    // The per-epoch cost the reshuffle forces: to land an identity on a CHOSEN point under a given beacon, the
    // adversary grinds ~N candidates (coupon, E[T] = N per seat). Averaged over many seizures so a lucky
    // early hit does not flake it. And — per the retention test — this cost is re-paid every epoch (a seat is
    // not held), so there is no amortization across epochs: pre-settling an eclipse is structurally denied.
    let n = Plane::<F7>::N as usize;
    let beacon = BeaconSeed::new([0x77; 32]);
    let seizures = 24usize;
    let mut total_tries = 0usize;
    let mut s = 0u32;
    for target in 0..seizures {
        let mut tries = 0usize;
        loop {
            s += 1;
            tries += 1;
            let (sk, id) = identity(s ^ 0xF00D);
            if coord_index(&sk, id, Epoch::new(3), &beacon) == target {
                break;
            }
            assert!(
                tries <= n * 80,
                "no landing after {tries} grinds — placement may be non-uniform"
            );
        }
        total_tries += tries;
    }
    let avg = total_tries as f64 / seizures as f64;
    assert!(
        avg > n as f64 * 0.4 && avg < n as f64 * 2.5,
        "seizing a chosen coordinate costs ~N grinds per epoch (avg {avg:.1}, N={n})"
    );
}
