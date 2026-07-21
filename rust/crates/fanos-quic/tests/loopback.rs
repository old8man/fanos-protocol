//! Real-QUIC loopback e2e: the *same* `OverlayNode` engine the simulator runs, driven here over a
//! real UDP + TLS 1.3 socket. If these pass, the sans-I/O boundary holds — production transport
//! and the deterministic simulator are two drivers of one engine.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration as StdDuration;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_quic::{Directory, NodeHandle, spawn};
use fanos_runtime::{Command, Config, Notification, OverlayNode, Triple};

/// A brisk liveness profile so this test runs in a couple of seconds, not the 500 ms production
/// cadence. `liveness_timeout` is kept a full 10 heartbeats wide (1000 ms) on purpose: this is a
/// *real-QUIC, real-wall-clock* test that shares the machine with the whole workspace, and a tighter
/// window (an earlier 350 ms) let CPU-starvation jitter delay B's pings past the deadline so A wrongly
/// declared a *live* peer dead — a load-sensitive flake. 1000 ms swamps that jitter while staying fast;
/// the quiet-window assertion below still spans more than one `liveness_timeout`, so it remains a real
/// check (parallel-safe real-QUIC tests, audit #56/#77).
fn brisk() -> Config {
    Config {
        heartbeat: fanos_runtime::Duration::from_millis(100),
        liveness_timeout: fanos_runtime::Duration::from_millis(1000),
        ..Config::default()
    }
}

async fn node(point: usize, dir: &Directory, cfg: Config) -> NodeHandle {
    let engine = OverlayNode::<F2>::new(Point::at(point), cfg);
    spawn(Box::new(engine), dir.clone())
        .await
        .expect("spawn node")
}

/// Await a `Delivered` payload from `want_from`, within `secs`.
async fn await_delivery(node: &mut NodeHandle, want_from: Triple, secs: u64) -> Vec<u8> {
    let deadline = tokio::time::timeout(StdDuration::from_secs(secs), async {
        loop {
            match node.next_notification().await {
                Some(Notification::Delivered { from, payload }) if from == want_from => {
                    return payload;
                }
                Some(_) => {}
                None => panic!("engine stopped before delivery"),
            }
        }
    });
    deadline.await.expect("delivery timed out")
}

#[tokio::test]
async fn application_payload_delivers_over_real_quic() {
    let dir = Directory::new();
    let a = node(0, &dir, Config::default()).await;
    let mut b = node(1, &dir, Config::default()).await;

    let payload = b"the same engine, a real socket".to_vec();
    assert!(a.command(Command::Send {
        to: b.address(),
        payload: payload.clone(),
    }));

    assert_eq!(await_delivery(&mut b, a.address(), 5).await, payload);
}

#[tokio::test]
async fn delivery_is_bidirectional_and_reuses_the_connection() {
    // A→B establishes the connection; B→A must ride it back (connection reuse), not deadlock.
    let dir = Directory::new();
    let mut a = node(0, &dir, Config::default()).await;
    let mut b = node(1, &dir, Config::default()).await;

    a.command(Command::Send {
        to: b.address(),
        payload: b"ping-app".to_vec(),
    });
    assert_eq!(await_delivery(&mut b, a.address(), 5).await, b"ping-app");

    b.command(Command::Send {
        to: a.address(),
        payload: b"pong-app".to_vec(),
    });
    assert_eq!(await_delivery(&mut a, b.address(), 5).await, b"pong-app");
}

#[tokio::test]
async fn a_node_learns_its_public_address_from_a_quorum_of_peers() {
    // NAT traversal #119, reflexive discovery: a node does not know the address remote peers reach it at.
    // Here A dials B and C; each, on accepting, reports back the source address it observes A arriving from
    // (an `ObservedAddr` frame). Once a quorum (2) of peers agree, A confirms its public address. Over
    // loopback there is no NAT, so that observed address is A's own endpoint — the mechanism is identical
    // under a real NAT, where it would instead be the NAT-mapped public endpoint.
    let dir = Directory::new();
    let a = node(0, &dir, Config::default()).await;
    let b = node(1, &dir, Config::default()).await;
    let c = node(2, &dir, Config::default()).await;

    assert_eq!(a.public_addr(), None, "A knows no public address before any peer reports one");

    // A dials both peers (triggering the connections whose accept-side sends the ObservedAddr back).
    a.command(Command::Send {
        to: b.address(),
        payload: b"hi-b".to_vec(),
    });
    a.command(Command::Send {
        to: c.address(),
        payload: b"hi-c".to_vec(),
    });

    let confirmed = tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            if let Some(addr) = a.public_addr() {
                return addr;
            }
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
    })
    .await
    .expect("A never confirmed a public address from a quorum of peers");

    assert_eq!(
        confirmed,
        a.local_addr(),
        "A's reflexive address is where its peers observe it (its own endpoint, over loopback)"
    );
    drop((b, c));
}

#[tokio::test]
async fn heartbeat_keeps_a_live_peer_up_then_detects_its_death() {
    // Full liveness loop over QUIC: ping → pong keeps B alive; killing B makes A report it down.
    let dir = Directory::new();
    let mut a = node(0, &dir, brisk()).await;
    let b = node(1, &dir, brisk()).await;

    a.command(Command::StartHeartbeat);
    b.command(Command::StartHeartbeat);

    // For ~1400 ms — comfortably longer than one `liveness_timeout` (1000 ms), so a broken liveness
    // that declared a live peer dead WOULD fire and be caught here — B keeps answering A's pings, so A
    // must NOT report B down. (A *will* report the never-present Fano neighbours 2..6 down — we only
    // care about B here.) The window exceeds the timeout to stay a real check; the timeout is wide
    // enough that load jitter cannot forge a false PeerDown.
    let quiet = tokio::time::timeout(StdDuration::from_millis(1400), async {
        loop {
            if let Some(Notification::PeerDown(p)) = a.next_notification().await
                && p == b.address()
            {
                return true; // wrongly declared a live peer dead
            }
        }
    });
    assert!(quiet.await.is_err(), "A declared a live peer dead");

    // Now kill B. Within a few liveness windows, A must report exactly B down. 5 s is a generous
    // margin over the 1000 ms `liveness_timeout`, robust even when the machine is loaded.
    b.shutdown();
    let detected = tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            if let Some(Notification::PeerDown(p)) = a.next_notification().await
                && p == b.address()
            {
                return true;
            }
        }
    });
    assert!(detected.await.is_ok(), "A never detected the dead peer");
}
