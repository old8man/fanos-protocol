//! Real-QUIC **NAT hole-punch coordination** (#119): a common hub brokers a direct connection between
//! two peers that do not know each other's address.
//!
//! The scenario models two nodes behind NAT, each with a connection only to a shared hub. `reflexive.rs`
//! covers the STUN-like half (a node learning its own public address); this covers the brokering half —
//! the hub relaying each party's observed address to the other so they can dial simultaneously. Each node
//! here has its OWN directory, so A genuinely cannot reach B until the hub tells it where B is; and
//! because a quinn endpoint uses one socket for both accepting and dialing, the address the hub observes a
//! peer at is exactly that peer's listener, so the punched dial reaches it (over loopback the NAT is
//! absent, but the coordination mechanism exercised is identical to the deployed one).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::await_holding_lock)]

use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::Duration;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_quic::{Directory, NodeHandle, spawn};
use fanos_runtime::{Command, Config, Notification, OverlayNode, Triple};

/// Real-QUIC tests each bring up several loopback nodes; run them one at a time to avoid overloading the
/// transport (see `diaulos_quic.rs`).
static SERIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Bring up an overlay node at `point` on its own directory (default config, HELLO-mode transport).
async fn node(point: usize, dir: &Directory) -> NodeHandle {
    spawn(
        Box::new(OverlayNode::<F2>::new(Point::at(point), Config::default())),
        dir.clone(),
    )
    .await
    .expect("spawn node")
}

/// Await a `Delivered` payload from `want_from`, within `secs` — a barrier that also proves the sender's
/// connection reached this node (its accept path ran).
async fn await_delivery(node: &mut NodeHandle, want_from: Triple, secs: u64) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            match node.next_notification().await {
                Some(Notification::Delivered { from, payload }) if from == want_from => {
                    return payload;
                }
                Some(_) => {}
                None => panic!("engine stopped before delivery"),
            }
        }
    })
    .await
    .expect("delivery timed out")
}

/// Poll `dir` until it resolves `coord`, within `secs`. Returns whether it did.
async fn await_resolved(dir: &Directory, coord: Triple, secs: u64) -> bool {
    tokio::time::timeout(Duration::from_secs(secs), async {
        while dir.resolve(coord).is_none() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn a_hub_brokers_a_direct_hole_punched_connection() {
    let _serial = serial();
    // Three nodes, each on its OWN directory: A and B know only the hub H, never each other.
    let dir_a = Directory::new();
    let dir_b = Directory::new();
    let dir_h = Directory::new();
    let a = node(0, &dir_a).await;
    let mut b = node(1, &dir_b).await;
    let mut h = node(2, &dir_h).await;

    dir_a.insert(h.address(), h.local_addr());
    dir_b.insert(h.address(), h.local_addr());

    // Precondition: A has no address for B, so it cannot reach it directly.
    assert!(
        dir_a.resolve(b.address()).is_none(),
        "A must not know B's address up front — the hub is the only path"
    );

    // B dials the hub. When the hub delivers B's payload it has already accepted B's connection, so it now
    // holds B's observed public address — the material it will relay.
    b.command(Command::Send {
        to: h.address(),
        payload: b"hello-hub".to_vec(),
    });
    assert_eq!(
        await_delivery(&mut h, b.address(), 5).await,
        b"hello-hub",
        "the hub observed B (accepted its connection)"
    );

    // A asks the hub to broker a hole-punch to B. The hub tells each party where the other is; both dial,
    // and the direct connection forms.
    assert!(
        a.hole_punch(h.address(), b.address()),
        "the hole-punch request was queued"
    );

    // The brokering worked: A learned B's address from the hub's PunchTo, so overlay traffic to B now
    // resolves directly — no hub in the path.
    assert!(
        await_resolved(&dir_a, b.address(), 5).await,
        "A learned B's address via the hub's PunchTo"
    );

    // End-to-end proof over the punched path: an application payload from A reaches B.
    let payload = b"through the punched hole".to_vec();
    assert!(a.command(Command::Send {
        to: b.address(),
        payload: payload.clone(),
    }));
    assert_eq!(
        await_delivery(&mut b, a.address(), 5).await,
        payload,
        "B receives A's payload over the hole-punched connection"
    );

    a.shutdown();
    b.shutdown();
    h.shutdown();
}

#[tokio::test]
async fn a_hub_relays_between_peers_that_cannot_reach_each_other() {
    let _serial = serial();
    // Symmetric-NAT fallback: A and B can each reach a hub H but NOT each other (separate directories, no
    // cross-address, no hole-punch here). A's traffic to B is relayed transparently through H — and B's
    // reply routes back the same way, because the relay carries the origin (a bidirectional relay).
    let dir_a = Directory::new();
    let dir_b = Directory::new();
    let dir_h = Directory::new();
    let mut a = node(0, &dir_a).await;
    let mut b = node(1, &dir_b).await;
    let h = node(2, &dir_h).await;

    // A and B each know only the hub, and each opens a connection to it (a Send warms it): the hub then
    // holds a connection to both, and A/B each hold one to the hub to relay through.
    dir_a.insert(h.address(), h.local_addr());
    dir_b.insert(h.address(), h.local_addr());
    a.command(Command::Send {
        to: h.address(),
        payload: vec![0xAA],
    });
    b.command(Command::Send {
        to: h.address(),
        payload: vec![0xBB],
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Precondition: A and B have no path to each other — only the relay can carry it.
    assert!(
        dir_a.resolve(b.address()).is_none() && dir_b.resolve(a.address()).is_none(),
        "A and B must not know each other's address"
    );

    // A → B, relayed through H, delivered attributed to A (not the hub).
    let fwd = b"A to B through the relay hub".to_vec();
    a.command(Command::Send {
        to: b.address(),
        payload: fwd.clone(),
    });
    assert_eq!(
        await_delivery(&mut b, a.address(), 5).await,
        fwd,
        "B received A's message via the relay, attributed to A"
    );

    // B → A, relayed back the same way — the bidirectional property the origin tag buys.
    let rev = b"B back to A through the relay hub".to_vec();
    b.command(Command::Send {
        to: a.address(),
        payload: rev.clone(),
    });
    assert_eq!(
        await_delivery(&mut a, b.address(), 5).await,
        rev,
        "A received B's reply via the relay, attributed to B"
    );

    a.shutdown();
    b.shutdown();
    h.shutdown();
}
