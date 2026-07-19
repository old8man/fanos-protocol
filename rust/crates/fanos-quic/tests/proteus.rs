//! PROTEUS over a real socket: two nodes whose QUIC driver shapes every frame with a shared
//! community secret still deliver application traffic — the same `OverlayNode` engine, now behind
//! a polymorph transport that carries no static FANOS signature (spec §13.2). The shaping lives
//! entirely in the driver; the engine is byte-for-byte the one the simulator runs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration as StdDuration;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_quic::{Directory, spawn_shaped};
use fanos_runtime::{Command, Config, Notification, OverlayNode};

#[tokio::test]
async fn shaped_nodes_deliver_over_a_polymorph_transport() {
    let secret = b"community-transport-secret".to_vec();
    let epoch = fanos_proteus::Epoch::new(11);
    let dir = Directory::new();

    let a = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(0), Config::default())),
        dir.clone(),
        secret.clone(),
        epoch,
    )
    .await
    .expect("spawn shaped A");
    let mut b = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(1), Config::default())),
        dir.clone(),
        secret,
        epoch,
    )
    .await
    .expect("spawn shaped B");

    let payload = b"delivered through the polymorph".to_vec();
    a.command(Command::Send {
        to: b.address(),
        payload: payload.clone(),
    });

    let got = tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            if let Some(Notification::Delivered { from, payload }) = b.next_notification().await
                && from == a.address()
            {
                return payload;
            }
        }
    })
    .await
    .expect("delivery through the shaped transport timed out");
    assert_eq!(got, payload);
}
