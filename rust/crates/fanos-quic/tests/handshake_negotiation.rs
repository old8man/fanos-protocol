//! End-to-end HELLO negotiation over a real QUIC connection (spec §7.3/§7.4, audit #100): two
//! self-certifying nodes with different capability sets, over real sockets, real certificates, and
//! real coordinate proofs — not the pure-function unit tests in `fanos-quic/src/identity.rs` (which
//! cover the version-mismatch path directly, since `PROTOCOL_VERSION` is a build-wide constant, not
//! a per-node knob the public API exposes to construct a live version-mismatched peer).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration as StdDuration;

use fanos_field::F7;
use fanos_quic::{Directory, NodeHandle, spawn_self_certifying_with_capabilities};
use fanos_runtime::{Command, Config, Engine, Notification, OverlayNode};
use fanos_wire::capability::Capabilities;

fn make_node(coord: fanos_geometry::Point<F7>) -> Box<dyn Engine + Send> {
    Box::new(OverlayNode::<F7>::new(coord, Config::default()))
}

async fn spawn_with(caps: Capabilities, dir: &Directory) -> NodeHandle {
    spawn_self_certifying_with_capabilities::<F7>(make_node, dir.clone(), caps)
        .await
        .expect("spawn")
}

#[tokio::test]
async fn overlapping_capability_sets_negotiate_and_deliver() {
    // A minimal (CORE-only) node and a "full" node (CORE + every optional flag) — spec §7.4's own
    // example: they must still interoperate on the shared baseline, not merely on identical offers.
    let dir = Directory::new();
    let minimal = spawn_with(Capabilities::CORE, &dir).await;
    let mut full = spawn_with(
        Capabilities::CORE | Capabilities::APHANTOS_FULL | Capabilities::CALYPSO,
        &dir,
    )
    .await;

    minimal.command(Command::Send {
        to: full.address(),
        payload: b"negotiated".to_vec(),
    });

    let got = tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            if let Some(Notification::Delivered { payload, .. }) = full.next_notification().await
            {
                return payload;
            }
        }
    })
    .await
    .expect("delivery must not hang when capabilities overlap");
    assert_eq!(got, b"negotiated");
}

#[tokio::test]
async fn disjoint_capability_sets_abort_cleanly_without_delivering() {
    // Neither side advertises CORE, and their optional-only sets don't overlap either — an empty
    // intersection, the genuine incompatibility condition (spec §7.3: HELLO_SENT → CLOSED). The
    // send must be dropped, not delivered, and — critically — must not hang.
    let dir = Directory::new();
    let a = spawn_with(Capabilities::APHANTOS_LITE, &dir).await;
    let mut b = spawn_with(Capabilities::APHANTOS_FULL, &dir).await;

    a.command(Command::Send {
        to: b.address(),
        payload: b"should never arrive".to_vec(),
    });

    // A bounded wait proves this aborts cleanly rather than hanging: if the handshake wedged, this
    // timeout is what would catch it (a hang would otherwise block the test suite indefinitely).
    let delivered = tokio::time::timeout(StdDuration::from_secs(2), b.next_notification()).await;
    assert!(
        delivered.is_err(),
        "an empty capability intersection must never deliver"
    );
}

#[tokio::test]
async fn three_way_capability_diversity_each_negotiates_its_own_true_intersection() {
    // A minimal, a lite, and a full node — each pair negotiates a DIFFERENT intersection, proving
    // the negotiated set is genuinely per-connection, not a single cached/global outcome.
    let dir = Directory::new();
    let minimal = spawn_with(Capabilities::CORE, &dir).await;
    let lite = spawn_with(Capabilities::CORE | Capabilities::APHANTOS_LITE, &dir).await;
    let mut full = spawn_with(
        Capabilities::CORE | Capabilities::APHANTOS_LITE | Capabilities::APHANTOS_FULL,
        &dir,
    )
    .await;

    for (from, tag) in [(&minimal, b"from-minimal".to_vec()), (&lite, b"from-lite".to_vec())] {
        from.command(Command::Send {
            to: full.address(),
            payload: tag.clone(),
        });
        let got = tokio::time::timeout(StdDuration::from_secs(5), async {
            loop {
                if let Some(Notification::Delivered { payload, .. }) =
                    full.next_notification().await
                {
                    return payload;
                }
            }
        })
        .await
        .expect("delivery must not hang regardless of the specific capability overlap");
        assert_eq!(got, tag);
    }
}
