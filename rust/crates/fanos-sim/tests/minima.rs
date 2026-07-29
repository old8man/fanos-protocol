//! **The cell's operational floor, measured through the live stack.**
//!
//! `fanos_code::lrc` proves on paper that peeling the projective `[7,3,4]` code recovers any `≤3` losses and
//! fails on four exactly when they form a hyperoval. That is a statement about a decoder. This is the
//! statement about a *network*: a value dispersed across seven homes, members crashed, and the read issued
//! from a survivor over the ordinary path — store, lookup, gather, reconstruct.
//!
//! The two must agree, and the interesting direction is disagreement. A storage layer that quietly replicated
//! whole values would pass every decoder test and read back from one survivor; one that dispersed but never
//! gathered would fail at the first loss. Neither shows up in `lrc`'s own tests, because neither is about the
//! code.
//!
//! Every loss pattern is enumerated rather than sampled. The first version of the accompanying example crashed
//! a fixed prefix of the cell and reported the resulting single outcome as the cell's floor — which turned a
//! regime that succeeds for 80% of patterns into a hard boundary one node too high.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_code::lrc::is_hyperoval_fano;
use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{Sim, spawn_partial_cell};

/// How long each phase of a run is given to settle.
const PHASE: Duration = Duration::from_millis(3500);

/// Disperse a value across a full Fano cell, crash exactly the members in `lost`, and read it back from the
/// highest-indexed survivor. Returns whether the value came back.
fn reads_after_losses(lost: u8, seed: u64) -> bool {
    let mut sim = Sim::new(seed);
    let cell = spawn_partial_cell::<F2>(&mut sim, Config::default(), 7);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(PHASE);

    let key = b"minima-floor-key".to_vec();
    sim.inject(cell[0], Command::Put { key: key.clone(), value: vec![0x5Au8; 512] });
    sim.run_for(PHASE);

    for (i, point) in cell.iter().enumerate() {
        if lost & (1 << i) != 0 {
            sim.crash(*point);
        }
    }
    sim.run_for(PHASE);

    let Some(reader) = (0..7).rev().find(|i| lost & (1 << i) == 0).map(|i| cell[i]) else {
        return false;
    };
    sim.inject(reader, Command::Get { key });
    sim.run_for(PHASE);
    sim.settle();
    sim.report().metrics.retrieval_hits > 0
}

/// Every 7-bit mask with exactly `bits` bits set.
fn patterns(bits: u32) -> Vec<u8> {
    (0u8..=0x7F).filter(|m| m.count_ones() == bits).collect()
}

#[test]
fn three_losses_never_cost_a_read() {
    // The code's guarantee, run through the network. All 35 three-loss patterns, no exceptions — a *pattern*
    // claim, so sampling would not establish it.
    //
    // This is a positive control and cannot, alone, tell you the crashes are happening: a `reads_after_losses`
    // that crashed nobody would still pass here. The two tests below are the ones that detect that, and a
    // falsification run confirms they do.
    for (i, &mask) in patterns(3).iter().enumerate() {
        assert!(
            reads_after_losses(mask, 0x9E00 + i as u64),
            "losing {mask:#09b} (3 members) must leave the value readable"
        );
    }
}

#[test]
fn four_losses_cost_the_read_exactly_on_hyperovals() {
    // The sharp one, and the reason this test exists. Among four-member losses the irrecoverable patterns are
    // precisely the hyperovals — four points no three of which are collinear, so every line meets them in 0 or
    // 2 points and peeling never gets a single exposed loss to start from.
    //
    // This asserts the live stack's failure set *equals* the geometry's, in both directions: a hyperoval that
    // still read would mean the value was replicated somewhere it should not be, and a non-hyperoval that
    // failed would mean the gather is weaker than the decoder.
    let mut failures = 0;
    for (i, &mask) in patterns(4).iter().enumerate() {
        let read = reads_after_losses(mask, 0x9E00 + i as u64);
        let hyperoval = is_hyperoval_fano(mask);
        assert_eq!(
            read, !hyperoval,
            "losing {mask:#09b}: hyperoval={hyperoval} but the read {}",
            if read { "succeeded" } else { "failed" }
        );
        if !read {
            failures += 1;
        }
    }
    assert_eq!(failures, 7, "the Fano plane has exactly seven hyperovals, so exactly seven patterns fail");
}

#[test]
fn five_losses_are_past_the_floor() {
    // Two survivors cannot serve a read under any pattern — the operational floor, and the number a deployment
    // should be sized against.
    for (i, &mask) in patterns(5).iter().enumerate() {
        assert!(
            !reads_after_losses(mask, 0x9E00 + i as u64),
            "losing {mask:#09b} (5 members) must leave the value unreadable"
        );
    }
}
