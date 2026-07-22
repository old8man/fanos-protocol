//! Mass-destruction → heterogeneous recovery — the user's #1 scenario (audit §2). **Phase 0** builds the
//! simulator capability the audit's S-P0.0 says is missing: a cell standing on the *real* threshold-DVRF
//! epoch clock (`spawn_beacon_cell` + [`Sim::tick_epoch`]), so the **R-C1 beacon liveness cliff** becomes
//! observable — crash `n − t + 1` anchors and the epoch clock freezes, silently and (today) permanently.
//!
//! These scenarios pin the current, pre-fix behaviour: the clock advances while ≥ `t` anchors survive and
//! freezes the instant the live anchor set drops below `t`. Phase 1 (proactive verifiable resharing +
//! re-bootstrap + safe-stall) will turn that freeze into a survivable clock and flip the frozen assertion.

#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

mod common;

use common::spawn_beacon_cell;
use fanos_field::F2;
use fanos_keygen::BeaconNode;
use fanos_runtime::{Command, Config, Duration, Epoch};
use fanos_sim::Sim;

#[test]
fn the_epoch_clock_advances_while_a_threshold_of_anchors_survives() {
    // A full Fano cell on a 4-of-7 beacon; every node is an anchor.
    let mut sim = Sim::new(0x5C1A);
    let cell = spawn_beacon_cell::<F2>(&mut sim, Config::default(), 4, 7);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000)); // establish overlay liveness + let joiners pull-sync

    // With all 7 anchors live the epoch clock steps forward, tick by tick.
    assert_eq!(sim.tick_epoch(), Some(Epoch::new(1)), "the clock leaves genesis");
    assert_eq!(sim.tick_epoch(), Some(Epoch::new(2)), "and keeps advancing");

    // Lose exactly `n − t = 3` anchors: 4 remain, precisely the threshold. The round still assembles — this
    // is the whole point of a `t`-of-`n` beacon, and the boundary the fault model is built around.
    sim.crash(cell[0]);
    sim.crash(cell[1]);
    sim.crash(cell[2]);
    assert_eq!(
        sim.tick_epoch(),
        Some(Epoch::new(3)),
        "exactly t = 4 live anchors still assemble the DVRF round"
    );
}

#[test]
fn the_epoch_clock_freezes_below_threshold_the_r_c1_cliff() {
    // 4-of-7 again, but this time cross the `n − t + 1 = 4`-loss boundary.
    let mut sim = Sim::new(0xC11F);
    let cell = spawn_beacon_cell::<F2>(&mut sim, Config::default(), 4, 7);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    assert_eq!(sim.tick_epoch(), Some(Epoch::new(1)), "healthy: the clock starts");

    // Knock out 4 of the 7 anchors — one past the `n − t` tolerance, leaving only 3 < t = 4 live.
    for &i in &[0usize, 1, 2, 3] {
        sim.crash(cell[i]);
    }

    // R-C1: below threshold no round can assemble, so no node adopts a new epoch and no `BeaconReady` fires.
    // The epoch clock — and with it every coordinate reshuffle, onion-key rotation, rendezvous line and
    // HELLO proof that folds the seed — is frozen. There is no re-DKG or resharing anywhere to recover it.
    assert_eq!(
        sim.tick_epoch(),
        None,
        "below threshold the DVRF beacon cannot assemble a round — the clock stalls"
    );
    assert_eq!(
        sim.tick_epoch(),
        None,
        "and it stays frozen: the one-shot DKG left no path to reconstitute the anchor set (R-C1)"
    );
}

#[test]
fn proactive_resharing_survives_the_r_c1_cliff() {
    // The R-C1 fix, end to end: the SAME 4-of-7 cell and the SAME four-anchor loss that froze the clock above
    // is now survived — because the beacon proactively re-shared its key to the survivors BEFORE the loss.
    let mut sim = Sim::new(0x5EED);
    let cell = spawn_beacon_cell::<F2>(&mut sim, Config::default(), 4, 7);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    assert_eq!(sim.tick_epoch(), Some(Epoch::new(1)), "healthy: the clock starts");
    assert_eq!(sim.tick_epoch(), Some(Epoch::new(2)), "and advances");

    // PROACTIVELY reshare (generation 1) while all anchors are still up: move the beacon key to the four
    // survivors {points 3,4,5,6} = holder indices {4,5,6,7} at a NEW threshold t' = 3. A coordinator
    // broadcasts the trigger; it self-floods, so injecting it at one anchor reaches the cell.
    let contributors = [4u8, 5, 6, 7];
    let new_holders = [4u8, 5, 6, 7];
    let trigger = BeaconNode::<F2>::reshare_trigger(1, 3, &contributors, &new_holders);
    sim.inject_frame(cell[6], cell[6], trigger);
    sim.run_for(Duration::from_millis(3000)); // the reshare deals, floods, and is adopted cell-wide

    // Now cross the ORIGINAL n − t + 1 = 4-loss cliff: crash points {0,1,2,3}. Points 0,1,2 are now pure
    // consumers; point 3 was a survivor anchor — so exactly 3 anchors {points 4,5,6} remain, precisely the
    // new threshold. Where the un-reshared clock froze on this very loss, the reshared 3-of-4 beacon runs on.
    for &i in &[0usize, 1, 2, 3] {
        sim.crash(cell[i]);
    }
    assert_eq!(
        sim.tick_epoch(),
        Some(Epoch::new(3)),
        "the reshared 3-of-4 beacon assembles where the original 4-of-7 would have frozen"
    );
    assert_eq!(sim.tick_epoch(), Some(Epoch::new(4)), "and the epoch clock keeps advancing");
}
