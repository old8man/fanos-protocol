//! Self-certifying identity over real QUIC (mutual TLS). Each node's overlay coordinate is
//! `MapToPoint(H(cert))`; the mutual-TLS handshake proves the peer holds that certificate's key,
//! so the peer's coordinate is *authenticated by the handshake* — no HELLO, no directory-trust for
//! identity. An impostor at a resolved address (wrong cert → wrong coordinate) is rejected.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration as StdDuration;

use fanos_field::F7;
use fanos_geometry::Point;
use fanos_quic::{
    Directory, NodeCredentials, spawn_self_certifying, spawn_self_certifying_persistent,
};
use fanos_runtime::{Command, Config, Engine, Notification, OverlayNode};

fn make_node(coord: Point<F7>) -> Box<dyn Engine + Send> {
    Box::new(OverlayNode::<F7>::new(coord, Config::default()))
}

#[tokio::test]
async fn cert_bound_identity_delivers_and_authenticates_the_sender() {
    let dir = Directory::new();
    let a = spawn_self_certifying::<F7>(make_node, dir.clone())
        .await
        .expect("spawn A");
    let mut b = spawn_self_certifying::<F7>(make_node, dir.clone())
        .await
        .expect("spawn B");

    // A and B sit at their cert-derived coordinates (no coordinate was assigned).
    assert_ne!(a.address(), b.address());

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
    let a = spawn_self_certifying::<F7>(make_node, dir.clone())
        .await
        .expect("spawn A");
    let mut b = spawn_self_certifying::<F7>(make_node, dir.clone())
        .await
        .expect("spawn B");
    let c = spawn_self_certifying::<F7>(make_node, dir.clone())
        .await
        .expect("spawn C");

    // Poison the address book: B's coordinate now resolves to C's socket (a MITM / stale entry).
    dir.insert(b.address(), c.local_addr());

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
