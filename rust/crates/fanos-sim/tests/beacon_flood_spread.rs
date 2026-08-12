//! **`beacon flood spread < epoch period`** — the inequality PROTEUS's ±1 shape window rests on (#196).
//!
//! `ProteusShaper` accepts the shapes of epochs `{N−1, N, N+1}`. It needs the *future* one because epoch
//! advance is beacon-driven: at a turn one anchor rotates first, so its frames carry a shape its peer has
//! not adopted yet. A ±1 window covers that **only while the beacon reaches the whole cell inside one
//! epoch**. Should the spread ever exceed a period, the correct finding is not "widen the window" — it is
//! that the epoch period is too short for the cell's diameter, and widening would hide it.
//!
//! The inequality had been written down and never measured, for two separate reasons that were worth
//! separating: the notification log carried no timestamp (fixed — `Observed::at`), and `spawn_cell` runs
//! no beacon at all, so a first attempt measured **0 adopters of 57** and passed. This one stands up the
//! real `BeaconNode` cell, and asserts the SAMPLE before the STATISTIC so a vacuous run fails loudly
//! instead of reporting that the inequality holds.
//!
//! `measure_` by convention: reported, never gated — a number that moves with the machine must not be able
//! to redden a build. The coverage assertion is the exception and is deliberate: zero adopters is not a
//! slow machine, it is a broken harness.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_keygen::BeaconNode;
use fanos_primitives::BeaconSeed;
use fanos_vrf::vss::{DeterministicRng, VssCommitment, VssShare, deal};
use fanos_runtime::{Command, Config, Duration, Notification, Triple};
use fanos_sim::Sim;

/// `t`-of-7 anchors — the same sharing shape `beacon_node_e2e` proves a working rendezvous over.
const BEACON_T: usize = 5;

fn beacon_group() -> (Vec<VssShare>, VssCommitment) {
    deal(&[0xBE; 32], BEACON_T, 7, &mut DeterministicRng::new(b"flood-spread")).unwrap()
}

#[test]
fn measure_beacon_flood_spread_against_the_epoch_period() {
    let period_ms = Config::default().epoch_period.as_nanos() / 1_000_000;
    let (shares, commitment) = beacon_group();

    let mut sim = Sim::new(0xB2C0);
    for (i, share) in shares.iter().enumerate() {
        sim.add(Box::new(BeaconNode::<F2>::new(
            Point::at(i),
            Some(share.clone()),
            commitment.clone(),
            BEACON_T,
            BeaconSeed::GENESIS,
        )));
    }
    sim.inject_all(&Command::AdvanceEpoch);
    sim.run_for(Duration::from_millis(4000));

    // First adoption per anchor, in virtual milliseconds.
    let mut first: BTreeMap<Triple, u64> = BTreeMap::new();
    for o in &sim.report().notifications {
        if matches!(o.note, Notification::BeaconReady { .. }) {
            first.entry(o.node).or_insert_with(|| o.at.as_nanos() / 1_000_000);
        }
    }

    // **The sample, before the statistic.** `max − min` over an empty set is 0, and 0 is under every
    // bound — which is exactly how the previous attempt reported "the inequality holds" having measured
    // nothing at all. A spread is meaningless until the denominator is the whole cell.
    assert_eq!(
        first.len(),
        7,
        "every anchor must have adopted before a spread means anything — {} of 7 did, so this run measured \
         coverage, not speed (#196)",
        first.len()
    );

    let (lo, hi) = (first.values().min().unwrap(), first.values().max().unwrap());
    let spread = hi - lo;
    println!(
        "\nbeacon flood spread over 7 anchors: {spread} ms  (first {lo} ms, last {hi} ms)\n\
         epoch period: {period_ms} ms  →  spread is {:.6} of a period\n",
        spread as f64 / period_ms as f64
    );

    assert!(
        spread < period_ms,
        "MEASURED VIOLATION: the beacon takes {spread} ms to cross the cell against a {period_ms} ms \
         epoch. The ±1 shape window is NOT sufficient here, and widening it would hide the real finding: \
         the period is too short for this diameter (#196)"
    );
}
