//! **The DKG has never run on a real socket** — until this file (§7 of `docs/testnet.md`).
//!
//! `DkgNode` is a sans-I/O `Engine` running Feldman/Pedersen with a GJKR complaint round, and
//! `fanos-sim/tests/dkg.rs` drives seven of them — including an equivocating dealer — to a common joint
//! key. That is the protocol logic. What had never happened is the thing a founding ceremony actually is:
//! seven separate processes, each holding a secret nobody else sees, agreeing over a network that can
//! reorder, delay and fragment.
//!
//! This is the platform's standing "libraries ahead, wiring behind" pattern at its most consequential site:
//! the DKG is the *only* thing standing between a testnet and a founder who briefly holds the whole beacon
//! secret, and it was one `Engine` away from a real transport the whole time. `spawn_cell` takes any
//! `Engine`, so the wiring is a constructor — but a constructor nobody had ever written, which is exactly
//! how a subsystem comes to be believed shipped.
//!
//! Tier T3 on `docs/design-testing.md`'s ladder: real mutual-TLS QUIC, real frames, real scheduling.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]


use fanos_field::F2;
use fanos_geometry::{Plane, Point};
use fanos_keygen::DkgNode;
use fanos_node::keygen::{DkgCeremony, OutcomeSlot};
use fanos_quic::spawn_cell;
use fanos_vrf::vss::verify_share;
use fanos_runtime::{Command, Duration as EngineDuration, Notification};

mod common;

/// The threshold a seven-seat cell is dealt at — the beacon's own `t`, not an arbitrary number: a Fano cell
/// tolerates `f = 2`, so a reconstruction quorum must exceed any tolerated coalition.
const THRESHOLD: usize = 4;

/// Each participant's secret is drawn locally and never transmitted whole; distinct per node, so a run that
/// accidentally shared one would produce an aggregate the shares cannot open.
fn secret_of(i: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = i as u8;
    s[1] = 0xD6;
    s
}

/// Fresh per-instance entropy binding this DKG run (audit B6), so a frame from one run cannot be replayed
/// into another. Deterministic here only so a failure is reproducible.
fn nonce_of(i: usize) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = i as u8;
    s[1] = 0x9E;
    s
}

/// Seven independent processes, seven secrets no one else holds, one joint key — over real QUIC.
///
/// **What this catches, measured rather than assumed.** Withholding one founder's `StartHeartbeat` fails it
/// on the timeout, so the collection loop and its bound are real. Giving one founder a *foreign session
/// nonce* does **not** fail it — and that is the protocol working, not the test being blind: the aggregate
/// is summed over the qualified set, so a dealer whose frames do not verify is disqualified and the other
/// six still agree, while the disqualified node lands on the same aggregate as everyone else. Agreement is
/// preserved under a bad dealer by design; what a bad dealer changes is *which* key, not whether there is
/// one. Byzantine-dealer behaviour is covered where it belongs, in `fanos-sim/tests/dkg.rs`, which can
/// inject forged frames this harness deliberately cannot.
///
/// The assertion that matters is **agreement**: every node must land on the *same* `Y`. A DKG that merely
/// completes proves nothing; one where two nodes finish on different aggregates has produced a beacon whose
/// partials will never combine, and the cell would discover that only when its epoch clock failed to advance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seven_founders_run_a_dkg_over_real_quic_and_agree_on_one_joint_key() {
    // One whole-cell fixture at a time: seven QUIC endpoints on one loopback and one scheduler.
    let _serial = common::serial_cell().await;

    let cell = spawn_cell::<F2>(|coord: Point<F2>| {
        let i = (0..Plane::<F2>::N as usize)
            .find(|&k| Point::<F2>::at(k) == coord)
            .expect("every spawned point is a plane point");
        // Generous phase deadlines: these are wall-clock on a loaded machine running real TLS handshakes,
        // where the simulator's are logical. Too tight and the complaint round closes before an honest
        // share arrives, which would look like a Byzantine dealer.
        Box::new(
            DkgNode::<F2>::new(coord, THRESHOLD, secret_of(i), nonce_of(i))
                .with_deadlines(EngineDuration::from_millis(6_000), EngineDuration::from_millis(6_000)),
        )
    })
    .await
    .expect("assemble cell");

    // Subscribe before starting, or a fast node's completion lands in the gap.
    let mut streams: Vec<_> = cell.nodes.iter().map(|n| n.client().subscribe()).collect();
    for node in &cell.nodes {
        assert!(node.command(Command::StartHeartbeat), "every founder begins dealing");
    }

    // Collect one `DkgComplete` per node, bounded — a DKG that does not converge must fail this test rather
    // than hang it.
    let mut joint: Vec<[u8; 32]> = Vec::new();
    for stream in &mut streams {
        let y = tokio::time::timeout(common::HANG_CEILING, async {
            loop {
                match stream.recv().await {
                    Ok(Notification::DkgComplete(y)) => return Some(y),
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                }
            }
        })
        .await
        .expect("a founder must reach DkgComplete within the window")
        .expect("the node must not shut down mid-ceremony");
        joint.push(y);
    }

    assert_eq!(joint.len(), 7, "all seven founders completed");
    let first = joint[0];
    assert!(
        joint.iter().all(|y| *y == first),
        "every founder must land on the SAME joint key — two aggregates means a beacon whose partials never \
         combine, and a cell that discovers it when its epoch clock fails to advance: {joint:?}"
    );
    // Not vacuous: an all-zero aggregate would satisfy agreement while being no group element at all.
    assert_ne!(first, [0u8; 32], "the joint key is a real group element, not a default");

    for n in cell.nodes {
        n.shutdown();
    }
}

/// **The ceremony's output reaches the file, and the share never touches a channel.**
///
/// The DKG agreeing is only half a founding: what an operator needs is a provisioning file, and the two
/// values that go in it — `final_share()` and `aggregate_commitment()` — live on the engine, which the
/// driver owns the moment it is spawned. The obvious route is to widen `Notification::DkgComplete`, and it
/// is the wrong one: that stream is a `broadcast` every subscriber receives, so a beacon share on it is
/// handed to every present and future reader of a telemetry channel.
///
/// `DkgCeremony` writes the outcome into a cell the ceremony already owns, at the one step it becomes true.
/// This asserts the whole chain a `fanos keygen` verb will stand on: every founder recovers an outcome, all
/// seven commitments are identical, **each founder's own share verifies against that shared commitment**,
/// and the result assembles into a `BeaconParams` that round-trips through the provisioning format.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_founder_recovers_its_share_and_the_cell_agrees_on_one_commitment() {
    let _serial = common::serial_cell().await;

    let slots: Vec<OutcomeSlot> = (0..7).map(|_| DkgCeremony::<F2>::slot()).collect();
    let cell = {
        let slots = slots.clone();
        spawn_cell::<F2>(move |coord: Point<F2>| {
            let i = (0..Plane::<F2>::N as usize)
                .find(|&k| Point::<F2>::at(k) == coord)
                .expect("every spawned point is a plane point");
            let node = DkgNode::<F2>::new(coord, THRESHOLD, secret_of(i), nonce_of(i))
                .with_deadlines(EngineDuration::from_millis(6_000), EngineDuration::from_millis(6_000));
            Box::new(DkgCeremony::new(node, slots[i].clone()))
        })
        .await
        .expect("assemble cell")
    };

    let mut streams: Vec<_> = cell.nodes.iter().map(|n| n.client().subscribe()).collect();
    for node in &cell.nodes {
        assert!(node.command(Command::StartHeartbeat), "every founder begins dealing");
    }
    for stream in &mut streams {
        tokio::time::timeout(common::HANG_CEILING, async {
            loop {
                match stream.recv().await {
                    Ok(Notification::DkgComplete(_)) => return Some(()),
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                }
            }
        })
        .await
        .expect("a founder must complete within the window")
        .expect("the node must not shut down mid-ceremony");
    }

    let outcomes: Vec<_> = slots
        .iter()
        .map(|s| s.lock().unwrap().clone().expect("a completed founder must have delivered its outcome"))
        .collect();
    assert_eq!(outcomes.len(), 7);

    let commitment = outcomes[0].commitment.to_bytes();
    for (i, o) in outcomes.iter().enumerate() {
        assert_eq!(
            o.commitment.to_bytes(),
            commitment,
            "founder {i} recovered a different commitment — the file it would write names another beacon"
        );
        // The half that makes the file usable rather than merely present: a share that does not verify
        // against the commitment beside it produces a node that floods partials nobody can combine.
        assert!(
            verify_share(&o.share, &o.commitment),
            "founder {i}'s own share must verify against the commitment it will write next to it"
        );
    }
    // Distinct shares — seven copies of one share would also satisfy everything above and would mean the
    // DKG had distributed nothing.
    let mut share_bytes: Vec<[u8; 33]> = outcomes.iter().map(|o| o.share.to_bytes()).collect();
    share_bytes.sort_unstable();
    share_bytes.dedup();
    assert_eq!(share_bytes.len(), 7, "each founder holds its OWN share, or nothing was distributed");

    // And it assembles into the provisioning file a founder actually writes.
    let params = fanos_node::config::BeaconParams {
        network_id: fanos_node::NetworkId::from_seed(b"ceremony-under-test"),
        commitment: outcomes[0].commitment.clone(),
        threshold: THRESHOLD,
        share: Some(outcomes[0].share.clone()),
        authority: None,
    };
    let back = fanos_node::config::BeaconParams::from_config_str(&params.to_config_string())
        .expect("a ceremony's output must round-trip through the provisioning format");
    assert_eq!(back.threshold, THRESHOLD);
    assert_eq!(back.commitment.to_bytes(), commitment);

    for n in cell.nodes {
        n.shutdown();
    }
}
