//! The **live epoch clock** — the wall-clock driver that advances the beacon in a deployed node.
//!
//! The moving-target defence (VRF coordinate reshuffle, PROTEUS shape rotation, forward-secure onion-key
//! rotation) all hangs off `Notification::BeaconReady`, which fires only after a threshold beacon round
//! assembles, which happens only on `Command::AdvanceEpoch`. Until this was wired, nothing in the running
//! node issued that tick, so the beacon never advanced and the whole defence stayed pinned at genesis for
//! the node's entire life. `Node::start` now spawns `spawn_epoch_driver`, which issues the tick every
//! `epoch_period`.
//!
//! A single 1-of-1 beacon anchor exercises the full live chain — driver → `AdvanceEpoch` → partial →
//! threshold round → `BeaconReady` — without a multi-node cell (an anchor self-buffers its own partial, so
//! threshold 1 assembles immediately).

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::time::Duration;

use fanos_field::F2;
use fanos_node::{BeaconParams, Node, NodeConfig};
use fanos_runtime::Notification;
use fanos_vrf::vss::{DeterministicRng, deal};

#[tokio::test]
async fn the_live_epoch_clock_advances_the_beacon_across_epochs() {
    // A 1-of-1 beacon anchor: its own partial assembles the round.
    let (shares, commitment) =
        deal(&[0x7E; 32], 1, 1, &mut DeterministicRng::new(b"epoch-driver")).expect("deal a 1-of-1 beacon");
    let share = shares.into_iter().next().expect("a 1-of-1 sharing yields one share");
    let config = NodeConfig {
        listen: "127.0.0.1:0".parse().expect("loopback addr"),
        beacon: Some(BeaconParams {
            commitment,
            threshold: 1,
            share: Some(share),
        }),
        // A short period so the wall clock ticks several times within the test.
        epoch_period: Duration::from_millis(120),
        start_heartbeat: false,
        ..NodeConfig::default()
    };
    let mut node = Node::start::<F2>(config).await.expect("the node starts");

    // Before this fix nothing issued `AdvanceEpoch`, so `BeaconReady` would NEVER fire in a live node.
    // Assert the wall-clock driver advances the beacon across ≥ 2 DISTINCT epochs within the timeout —
    // proving the clock ticks repeatedly, not once.
    let epochs = tokio::time::timeout(Duration::from_secs(5), async {
        let mut seen = BTreeSet::new();
        loop {
            if let Some(Notification::BeaconReady { epoch, .. }) = node.next_notification().await {
                seen.insert(epoch.get());
                if seen.len() >= 2 {
                    return seen;
                }
            }
        }
    })
    .await
    .expect("the live epoch clock must advance the beacon within the timeout");

    assert!(
        epochs.iter().all(|&e| e >= 1),
        "beacon rounds fire only for advanced epochs (past genesis 0): {epochs:?}"
    );
    assert!(
        epochs.len() >= 2,
        "the wall-clock epoch driver must tick repeatedly, driving ≥ 2 distinct epochs: {epochs:?}"
    );

    node.shutdown();
}
