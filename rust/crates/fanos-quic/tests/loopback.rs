//! Real-QUIC loopback e2e: the *same* `OverlayNode` engine the simulator runs, driven here over a
//! real UDP + TLS 1.3 socket. If these pass, the sans-I/O boundary holds — production transport
//! and the deterministic simulator are two drivers of one engine.
//!
//! Runtime: multi-threaded with **four** workers — a current-thread harness cannot see a parallelism
//! defect at all (#84), and two workers see it only 3 times in 8 where four see it 8 of 8. Measured
//! against the reverted fix for #83; the table is in `fanos-quic/tests/store_acks.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration as StdDuration;

use fanos_field::{F2, Field};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_learns_its_public_address_only_once_the_fault_budget_agrees() {
    // NAT traversal #119, reflexive discovery: a node does not know the address remote peers reach it at.
    // A dials its peers; each, on accepting, reports back the source address it observes A arriving from (an
    // `ObservedAddr` frame), and A confirms its public address once a quorum agree. Over loopback there is no
    // NAT, so that observed address is A's own endpoint — the mechanism is identical under a real NAT, where
    // it would instead be the NAT-mapped public endpoint.
    //
    // **The quorum is the cell's fault budget, and the count is asserted rather than assumed.** A node's
    // public address is what it advertises and what a hub hands out to broker a hole-punch, so a coalition
    // that could carry the vote could move a node's address — which is why the quorum is `⌊(n−1)/3⌋ + 1`
    // (`fanos_quic::reflexive_quorum`) and not the 2 it once was. This test used to supply exactly two
    // observers and confirm; raising the quorum broke it, and the break went unseen because the change was
    // gated with `-p fanos-node` and this file is `-p fanos-quic`'s. So it now supplies one observer FEWER
    // than the quorum first, proves the address stays unconfirmed, and only then adds the last one.
    let quorum = fanos_quic::reflexive_quorum(F2::Q);
    let dir = Directory::new();
    let a = node(0, &dir, Config::default()).await;
    // One peer per observer, plus the last one held back — `quorum + 1` nodes in all, which the Fano cell's
    // seven points accommodate for any `q = 2` budget.
    let mut peers = Vec::new();
    for i in 1..=quorum {
        peers.push(node(i, &dir, Config::default()).await);
    }

    assert_eq!(a.public_addr(), None, "A knows no public address before any peer reports one");

    // Dial every peer but the last: one vote short of the quorum.
    for peer in peers.iter().take(quorum - 1) {
        a.command(Command::Send { to: peer.address(), payload: b"hi".to_vec() });
    }
    // Long enough for those reports to have landed — the next assertion is only meaningful if they did, so
    // it is checked against the *last* peer's arrival below rather than trusted to a sleep alone.
    tokio::time::sleep(StdDuration::from_millis(600)).await;
    assert_eq!(
        a.public_addr(),
        None,
        "{} observers is one short of the quorum of {quorum} — a sub-budget coalition must not set an \
         address the network will dial and a hub will hand out",
        quorum - 1,
    );

    // The last observer completes the quorum.
    let last = peers.last().expect("at least one peer");
    a.command(Command::Send { to: last.address(), payload: b"hi".to_vec() });
    let confirmed = tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            if let Some(addr) = a.public_addr() {
                return addr;
            }
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
    })
    .await
    .expect("A never confirmed a public address once a quorum of peers had reported one");

    assert_eq!(
        confirmed,
        a.local_addr(),
        "A's reflexive address is where its peers observe it (its own endpoint, over loopback)"
    );
    drop(peers);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
