//! **A running node publishes its cell diagnosis** — the evidence half of #131/#129.
//!
//! Reputation used to be folded from `Notification::Liveness` into a carried map with `observe_reachable`,
//! and that function had **no production caller at all**: the score was a fresh `Reputation::new()` for the
//! life of every node, so the role assignment's reputation weighting was the identity function. The fix is
//! not to call the folder — a carried fold over a local measurement is what makes two honest nodes disagree
//! permanently — but to *publish* the measurement and recompute the score from a closed window
//! (`fanos_node::diagdir`, `fanos_core::roles::Reputation::from_published`).
//!
//! This is the falsification for the publish half, over real QUIC and the real driver chain: heartbeat →
//! `on_diagnose` → `Notification::Liveness` → role loop → `publish_diagnosis`. Every link is load-bearing and
//! each was absent before this task: `on_diagnose` raised no `Liveness` at all (only the operator-provoked
//! `Command::Observe` did), the role loop did not subscribe to it, and there was no directory to write to.
//! Break any one of them and the assertions below find no record.
//!
//! A single 1-of-1 beacon anchor drives it, for the same reason `epoch_clock.rs` uses one: an anchor
//! self-buffers its own partial, so a threshold round assembles without a multi-node cell, and the whole
//! epoch chain runs.
//!
//! Runtime: multi-threaded with four workers — a current-thread harness cannot see a parallelism defect at
//! all (#84).

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

use fanos_field::F2;
use fanos_node::diagdir::read_diagnosis_window;
use fanos_node::{BeaconParams, Node, NodeConfig};
use fanos_primitives::BeaconSeed;
use fanos_rendezvous::Epoch;
use fanos_runtime::Notification;
use fanos_vrf::vss::{DeterministicRng, deal};

/// How long to let the node run before looking. Generous rather than tuned: the assertion is about *whether*
/// a record exists, so a slow box should make this test slower, never red.
const RUN_FOR: Duration = Duration::from_secs(180);

/// How many closed epochs to collect before looking, and the whole set is then read.
///
/// **Not a window the test picks — every epoch it saw.** Asserting over a chosen slice would test the role
/// loop's cadence rather than the mechanism, which is how the first two versions of this test failed.
///
/// It must also comfortably exceed the first **heartbeat** — `HEARTBEAT_PERIOD` is 500 ms, three epochs here —
/// because the loop can only publish a reading it has, and the epochs before it legitimately have none.
const EPOCHS: usize = 2;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_running_node_publishes_the_cell_diagnosis_its_reputation_is_recomputed_from() {
    let (shares, commitment) =
        deal(&[0x5D; 32], 1, 1, &mut DeterministicRng::new(b"diagdir-anchor")).expect("deal a 1-of-1 beacon");
    let share = shares.into_iter().next().expect("a 1-of-1 sharing yields one share");
    let config = NodeConfig {
        listen: "127.0.0.1:0".parse().expect("loopback addr"),
        beacon: Some(BeaconParams {
            network_id: fanos_node::NetworkId::from_seed(b"diagdir-network"),
            commitment,
            threshold: 1,
            share: Some(share),
            authority: None,
        }),
        // **Longer than `ROSTER_REFRESH`, which is a protocol constraint and not a test knob.**
        //
        // Two measured reasons, both of which failed earlier drafts of this test. (1) A record is retained for
        // `DIAGNOSIS_SLOT_EPOCHS = REP_WINDOW = 7` epochs, and at a 150 ms epoch the loop published for one
        // epoch in eleven — every record expired before the next was written, so the window could never hold
        // more than one entry. (2) On an epoch turn the roster is *empty* until each node's capability
        // publisher republishes for the new epoch, and the loop declines to testify about an epoch whose
        // roster it is not yet in; the within-epoch `ROSTER_REFRESH` is what finds it there. An epoch shorter
        // than that refresh therefore never gets past the first, empty read.
        //
        // A deployment's epoch is minutes against a `ROSTER_REFRESH` of seconds, so both hold with room to
        // spare. This is the smallest period that reproduces that regime.
        epoch_period: fanos_node::role_loop::ROSTER_REFRESH * 2,
        // **Required, and it is the point.** The diagnosis is a heartbeat product: `on_diagnose` is what
        // senses the cell and raises the `Liveness` the role loop publishes. With the heartbeat off there is
        // no reading to publish, which is a different failure from "the publish is broken" — so it is turned
        // on explicitly here rather than inherited from a default that might change.
        start_heartbeat: true,
        ..NodeConfig::default()
    };
    let mut node = Node::start::<F2>(config).await.expect("the node starts");

    // Collect the closed epochs' seeds exactly as the role loop does: off `BeaconReady`, because the beacon
    // watch keeps no history and a record is bound against the seed of the epoch it was PUBLISHED in.
    let window = tokio::time::timeout(RUN_FOR, async {
        let mut seen: Vec<(Epoch, BeaconSeed)> = Vec::new();
        loop {
            if let Some(Notification::BeaconReady { epoch, seed, .. }) = node.next_notification().await {
                let entry = (epoch, BeaconSeed::new(seed));
                if !seen.contains(&entry) {
                    seen.push(entry);
                }
                if seen.len() >= EPOCHS {
                    return seen;
                }
            }
        }
    })
    .await
    .expect("the beacon advances through the epochs this test needs");

    // A within-epoch refresh past the last advance, so the loop has read a roster that has filled in and
    // published for it — the assignment that runs *on* the advance reads an empty roster by construction.
    tokio::time::sleep(fanos_node::role_loop::ROSTER_REFRESH * 2).await;

    // `true`: a deployed node has VRF coordinates, so its records are coordinate-BOUND and a reader that asks
    // for bare ones parses nothing. Reading with the wrong mode is indistinguishable from an empty directory
    // (`Read::found_or_absent` calls a failed binding a definite absence), which is exactly how this test
    // first failed — the reader's mode is as load-bearing as the writer's.
    let (records, view) = read_diagnosis_window::<F2>(&node.client(), &window, true).await;
    // `assert_eq!` on the count, not `assert!` on the flag: a failure here now says how many of the window's
    // reads were outstanding, which is the difference between a slow box and a cell that is not answering.
    assert_eq!(view.unresolved, 0, "every read of the diagnosis window concluded");
    assert!(
        !records.is_empty(),
        "a node ran {} epochs with its heartbeat on and published NO diagnosis — the chain from \
         `on_diagnose` to `publish_diagnosis` is broken somewhere, and the reputation it feeds is the \
         identity function again",
        window.len(),
    );

    // The record must describe the node that wrote it, and the seat to check is the one it held **in that
    // epoch** — `node.address()` is only today's, because a deployed cell re-draws every coordinate each
    // epoch. That is the whole reason the roster travels inside the record: reading these masks against the
    // current seating would attribute an old epoch's evidence to whoever sits there now.
    for record in &records {
        let seat = usize::from(record.publisher);
        assert!(
            record.roster[seat].is_some(),
            "the record names no identity at the publisher's own seat {seat}, so the masks it carries are \
             indexed against nothing a reader can attribute",
        );
        assert_ne!(
            record.responsive & (1u8 << seat),
            0,
            "the publisher did not mark ITSELF responsive, which `responsive_mask` guarantees — so the mask \
             in the record is not the one the engine measured",
        );
    }

    // And the records span the epochs, rather than one slot being rewritten: a directory that keyed every
    // epoch to the same address would give a reputation window one epoch deep however long it ran.
    let mut epochs: Vec<u64> = records.iter().map(|r| r.epoch).collect();
    epochs.sort_unstable();
    epochs.dedup();
    assert!(
        epochs.len() >= 2,
        "all {} records are for one epoch ({epochs:?}) — the slot is not epoch-keyed, so the window cannot \
         have a history to fold",
        records.len(),
    );

    node.shutdown().await;
}
