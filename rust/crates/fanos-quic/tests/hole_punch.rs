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
//!
//! Runtime: multi-threaded with **four** workers — a current-thread harness cannot see a parallelism
//! defect at all (#84), and two workers see it only 3 times in 8 where four see it 8 of 8. Measured
//! against the reverted fix for #83; the table is in `fanos-quic/tests/store_acks.rs`.

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

/// The in-process half. The **machine-wide** half is `fanos_testkit::acquire_cell_fixture`, and it is what
/// this file's own comment was missing: "scoped to this file only — each `tests/*.rs` is its own binary" was
/// stated and then relied on anyway, while the resource being guarded — the loopback stack and the host
/// scheduler — is shared by every binary Cargo runs concurrently, in this crate and in `fanos-node`.
fn serial() -> (std::sync::MutexGuard<'static, ()>, fanos_testkit::CellFixture) {
    let machine = fanos_testkit::acquire_cell_fixture();
    (SERIAL.lock().unwrap_or_else(PoisonError::into_inner), machine)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hub_relays_between_peers_it_cannot_broker_a_punch_for() {
    let _serial = serial();
    // Symmetric-NAT fallback: A and B can each reach a hub H but NOT each other. A's traffic to B is relayed
    // transparently through H — and B's reply routes back the same way, because the relay carries the origin
    // (a bidirectional relay).
    //
    // **The hub must be unable to broker, or this stops testing the relay.** Since the send path now asks for
    // a hole-punch before settling into relaying, a hub that *could* broker would punch the pair through and
    // the relay would carry only the first frame — leaving the reverse leg proven over a direct connection
    // while the test still claimed the relay. So B never dials H: the hub *dials out* to B instead. It then
    // holds a live connection to B (relayable) but no entry in its hole-punch table, which is populated only
    // on the accept path — a real condition, not a contrivance, and exactly the "hub cannot describe this
    // peer's mapping to a third party" case the relay exists for.
    let dir_a = Directory::new();
    let dir_b = Directory::new();
    let dir_h = Directory::new();
    let mut a = node(0, &dir_a).await;
    let mut b = node(1, &dir_b).await;
    let h = node(2, &dir_h).await;

    dir_a.insert(h.address(), h.local_addr());
    dir_h.insert(b.address(), b.local_addr());
    a.command(Command::Send {
        to: h.address(),
        payload: vec![0xAA],
    });
    h.command(Command::Send {
        to: b.address(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relaying_peer_asks_its_hub_to_punch_instead_of_relaying_for_ever() {
    let _serial = serial();
    // **The wiring this file's first test never exercised.** `hole_punch` is a manual call, and until now it
    // had no caller anywhere but that test: the send path fell straight from "no direct route" to "relay
    // through a hub", so a NAT-to-NAT pair relayed *all* of its traffic through a third node for the life of
    // the session. The hub paid the bandwidth, and — this being an anonymity network — the hub also saw the
    // volume of the pair's traffic, since a `Relay` names its target and origin in the clear to the
    // forwarder while a punched connection names nothing.
    //
    // Here nobody calls `hole_punch`. A simply sends to B, and the punch must happen on its own.
    let dir_a = Directory::new();
    let dir_b = Directory::new();
    let dir_h = Directory::new();
    let a = node(0, &dir_a).await;
    let mut b = node(1, &dir_b).await;
    let mut h = node(2, &dir_h).await;

    dir_a.insert(h.address(), h.local_addr());
    dir_b.insert(h.address(), h.local_addr());

    // Both ends dial the hub, so it holds each one's observed address — the material it brokers with.
    b.command(Command::Send { to: h.address(), payload: b"b-warms-the-hub".to_vec() });
    assert_eq!(await_delivery(&mut h, b.address(), 5).await, b"b-warms-the-hub");
    a.command(Command::Send { to: h.address(), payload: b"a-warms-the-hub".to_vec() });
    assert_eq!(await_delivery(&mut h, a.address(), 5).await, b"a-warms-the-hub");

    assert!(
        dir_a.resolve(b.address()).is_none(),
        "A must have no address for B — the relay branch is the one under test",
    );

    // One ordinary application send. Its own frame rides the relay (a punch is asynchronous and traffic must
    // not wait on it), so B receives it either way — but the send ALSO asks the hub to broker.
    let payload = b"A to B, relayed now and punched next".to_vec();
    a.command(Command::Send { to: b.address(), payload: payload.clone() });
    assert_eq!(
        await_delivery(&mut b, a.address(), 5).await,
        payload,
        "the frame itself is relayed — the punch must not delay traffic",
    );

    // The property: without anyone calling `hole_punch`, A ends up holding B's address, so every subsequent
    // frame leaves the hub out of the path entirely.
    assert!(
        await_resolved(&dir_a, b.address(), 5).await,
        "an ordinary send over the relay must ask the hub to punch — otherwise the pair relays for ever",
    );

    let direct = b"and this one goes direct".to_vec();
    a.command(Command::Send { to: b.address(), payload: direct.clone() });
    assert_eq!(
        await_delivery(&mut b, a.address(), 5).await,
        direct,
        "traffic continues over the punched connection",
    );

    a.shutdown();
    b.shutdown();
    h.shutdown();
}
