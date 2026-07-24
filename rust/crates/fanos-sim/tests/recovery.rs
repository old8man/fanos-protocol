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
use fanos_runtime::{Command, Config, Duration, Epoch, Notification};
use fanos_sim::{Sim, spawn_cell};

/// A hyperoval point-mask — four Fano points, no three collinear: a stopping set the `[7,3,4]` erasure code
/// cannot recover (one past its ≤3-loss tolerance).
fn hyperoval() -> u8 {
    (0u8..=0x7F)
        .find(|&m| {
            m.count_ones() == 4
                && (0..7).all(|l| {
                    fanos_geometry::fano::INCIDENCE.get(l).is_none_or(|&line| line & m != line)
                })
        })
        .unwrap()
}

/// A storage cell config with a brisk heartbeat/liveness so a crash is corroborated-down within the test window.
fn storage_config() -> Config {
    Config {
        heartbeat: Duration::from_millis(500),
        liveness_timeout: Duration::from_millis(1600),
        ..Config::default()
    }
}

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
    // A reshare changes the threshold, so it must be authorized by the beacon's recovery authority (§2.1);
    // the operator/parent signs the trigger. spawn_beacon_cell configured the cell with this authority.
    let (authority_sk, _) = common::recovery_authority();
    let trigger = BeaconNode::<F2>::reshare_trigger(&authority_sk, 1, 3, &contributors, &new_holders);
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

#[test]
fn a_permanent_data_loss_is_accounted_not_silent_r_c3() {
    // Audit R-C3: past the erasure tolerance, a read used to return `Retrieved(None)` — byte-identical to a
    // never-stored miss. Now a held key whose live shard-homes can no longer reconstruct is ACCOUNTED: a
    // distinct DataLost signal + a durable ledger entry, so permanent loss is visible, not silent.
    let mut sim = Sim::new(0x105);
    let cell = spawn_cell::<F2>(&mut sim, storage_config());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000)); // establish liveness across the cell

    // Store a value: erasure-encoded into 7 shards, one per Fano point, replicated cell-wide.
    let key = b"treasured-key".to_vec();
    sim.inject(cell[0], Command::Put { key: key.clone(), value: b"the-only-copy".to_vec() });
    sim.run_for(Duration::from_millis(3000));

    // Catastrophe: crash a HYPEROVAL — four shard-homes forming a stopping set, one past the [7,3,4]
    // tolerance. The value is now genuinely unrecoverable.
    let mask = hyperoval();
    for (i, &node) in cell.iter().enumerate() {
        if mask & (1 << i) != 0 {
            sim.crash(node);
        }
    }
    sim.run_for(Duration::from_millis(4000)); // the survivors corroborate the four homes as down

    // A survivor — which holds its own shard, so it KNOWS the key was stored — reads it. The read fails, but
    // instead of a silent, ambiguous miss the node accounts the permanent loss.
    let survivor = cell[(0..7).find(|i| mask & (1 << i) == 0).unwrap()];
    sim.clear_report();
    sim.inject(survivor, Command::Get { key: key.clone() });
    sim.run_for(Duration::from_millis(4000)); // the read fans out, times out, and accounts the loss

    let report = sim.report();
    assert!(report.metrics.data_losses >= 1, "the unrecoverable held key is accounted a permanent loss");
    assert!(
        report.notifications.iter().any(|o| matches!(o.note, Notification::DataLost { .. })),
        "the loss is a distinct, visible DataLost signal — not a silent Retrieved(None)"
    );
}

#[test]
fn a_recoverable_loss_is_not_accounted_r_c3() {
    // The bracket: crash only THREE homes — within the [7,3,4] tolerance — and the value still reconstructs,
    // so NO loss is accounted. Loss is charged only past the code's real recovery boundary.
    let mut sim = Sim::new(0x106);
    let cell = spawn_cell::<F2>(&mut sim, storage_config());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));

    let key = b"resilient-key".to_vec();
    sim.inject(cell[0], Command::Put { key: key.clone(), value: b"survives".to_vec() });
    sim.run_for(Duration::from_millis(3000));

    for i in [1usize, 2, 4] {
        sim.crash(cell[i]);
    }
    sim.run_for(Duration::from_millis(4000));

    sim.clear_report();
    sim.inject(cell[0], Command::Get { key: key.clone() });
    sim.run_for(Duration::from_millis(4000));

    let report = sim.report();
    assert_eq!(report.metrics.data_losses, 0, "a ≤3-home loss is within tolerance — not accounted a loss");
    assert!(
        report.retrievals().any(|(_, _, v)| v.is_some()),
        "the value still reconstructs from the four surviving shards"
    );
}
