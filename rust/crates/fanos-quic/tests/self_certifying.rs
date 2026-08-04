//! Self-certifying identity over real QUIC (mutual TLS). Each node's overlay coordinate is
//! `MapToPoint(H(cert))`; the mutual-TLS handshake proves the peer holds that certificate's key,
//! so the peer's coordinate is *authenticated by the handshake* — no HELLO, no directory-trust for
//! identity. An impostor at a resolved address (wrong cert → wrong coordinate) is rejected.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration as StdDuration;

use fanos_field::F7;
use fanos_geometry::{Point, Triple};
use fanos_quic::{
    Directory, NodeCredentials, NodeHandle, spawn_self_certifying, spawn_self_certifying_persistent,
};
use fanos_runtime::{Command, Config, Engine, Notification, OverlayNode};

fn make_node(coord: Point<F7>) -> Box<dyn Engine + Send> {
    Box::new(OverlayNode::<F7>::new(coord, Config::default()))
}

/// Spawn a self-certifying node whose cert-derived coordinate (`MapToPoint(H(cert))`) differs from
/// every one already in `taken`. A cell's members occupy **distinct** points, but two fresh
/// identities collide on the same point `1/N` of the time — retry until distinct, otherwise the
/// coordinate→node mapping is ambiguous and routing between the colliding pair breaks.
async fn spawn_distinct(dir: &Directory, taken: &[Triple]) -> NodeHandle {
    loop {
        let node = spawn_self_certifying::<F7>(make_node, dir.clone())
            .await
            .expect("spawn");
        if !taken.contains(&node.address()) {
            return node;
        }
        node.shutdown();
    }
}

#[tokio::test]
async fn cert_bound_identity_delivers_and_authenticates_the_sender() {
    // A *delivery* assertion, so it is guarded. Its two siblings here are not, deliberately: an impostor
    // being rejected and a coordinate surviving a restart are structural, and a starved box cannot make
    // either of them wrongly pass — guarding them would weaken a test for no reason.
    fanos_testkit::require_quiet_host("whether a cert-bound identity delivers and authenticates its sender");
    let dir = Directory::new();
    // A and B sit at their cert-derived coordinates (none was assigned), at distinct points.
    let a = spawn_distinct(&dir, &[]).await;
    let mut b = spawn_distinct(&dir, &[a.address()]).await;

    let payload = b"authenticated by my certificate".to_vec();
    a.command(Command::Send {
        to: b.address(),
        payload: payload.clone(),
    });

    let (from, got) = tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            if let Some(Notification::Delivered { from, payload }) = b.next_notification().await {
                return (from, payload);
            }
        }
    })
    .await
    .expect("delivery timed out");

    assert_eq!(got, payload);
    // The sender coordinate B sees is A's cert-derived coordinate — proven by A's client cert,
    // not merely claimed. B never read a HELLO.
    assert_eq!(from, a.address());
}

#[tokio::test]
async fn an_impostor_at_the_resolved_address_is_rejected() {
    let dir = Directory::new();
    let a = spawn_distinct(&dir, &[]).await;
    let mut b = spawn_distinct(&dir, &[a.address()]).await;
    let c = spawn_distinct(&dir, &[a.address(), b.address()]).await;

    // **Wait for B's binding to be PROVEN before testing that a proof cannot be overwritten.** `spawn_inner`
    // seeds an unranked entry and the reshuffle loop replaces it with the ranked one on a spawned task, so
    // "B has a proven claim" is not true the instant `spawn_distinct` returns — it is true a moment later.
    // Asserting through that window passed whenever the task happened to win the race and failed under load,
    // which is a property of the machine rather than of the rank rule.
    //
    // `claim_at` is the oracle that already answers this — `None` covers "free" and "occupied but unranked"
    // alike, which is exactly the distinction being waited on. A second accessor was written for it and
    // deleted: the architecture ratchet flagged it as public-and-uncalled, and it was right, because the
    // question already had an answer with a production caller (`Node::health`'s `probe_index`).
    tokio::time::timeout(StdDuration::from_secs(5), async {
        while dir.claim_at(b.address()).is_none() {
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("B's own coordinate claim must be seated before the arbitration rule can be tested");

    // A naive overwrite no longer poisons anything, and that is the rank rule working: B's binding was made *with* its
    // verified rank when B spawned, and an unranked write carries no evidence, so it cannot evict a proven claim
    // (`Directory::supersedes`). This assertion is the reason the test below has to reach for a realistic stale entry.
    dir.insert(b.address(), c.local_addr());
    assert_eq!(dir.resolve(b.address()), Some(b.local_addr()), "an unranked write must not evict a proven binding");

    // The realistic stale entry: B vacates its point (an epoch reshuffle does exactly this) and C is bound there
    // afterwards, so a send to B's *old* coordinate reaches C. Nothing about that is forgery — it is why the dialer must
    // still check the certificate against the coordinate it asked for.
    dir.remove(b.address());
    dir.insert(b.address(), c.local_addr());
    assert_eq!(dir.resolve(b.address()), Some(c.local_addr()), "a vacated point is free to rebind");

    // A dials "B" but reaches C, whose certificate certifies C's coordinate, not B's → A rejects
    // the connection and the frame is dropped. B receives nothing.
    a.command(Command::Send {
        to: b.address(),
        payload: b"should not arrive".to_vec(),
    });
    let delivered = tokio::time::timeout(StdDuration::from_secs(2), b.next_notification()).await;
    assert!(
        delivered.is_err(),
        "an impostor whose cert does not certify the dialed coordinate must be rejected"
    );
    let _ = c; // keep C alive for the duration
}

#[tokio::test]
async fn persistent_credentials_keep_the_same_coordinate_across_restarts() {
    // Mint an identity, persist it to bytes, and reload it (as an app would across a restart).
    let creds = NodeCredentials::generate().expect("generate credentials");
    let reloaded = NodeCredentials::from_bytes(&creds.to_bytes()).expect("reload credentials");

    let a = spawn_self_certifying_persistent::<F7>(&creds, make_node, Directory::new())
        .await
        .expect("spawn with credentials");
    let coord = a.address();
    a.shutdown();

    // A fresh node from the *same* persisted credentials occupies the *same* coordinate — a durable
    // overlay identity, not a new one each boot.
    let b = spawn_self_certifying_persistent::<F7>(&reloaded, make_node, Directory::new())
        .await
        .expect("spawn from reloaded credentials");
    assert_eq!(b.address(), coord, "coordinate is stable across restarts");
}
