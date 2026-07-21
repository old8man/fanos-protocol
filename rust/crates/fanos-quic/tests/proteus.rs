//! PROTEUS over a real socket: two nodes whose QUIC driver shapes every frame with a shared
//! community secret still deliver application traffic — the same `OverlayNode` engine, now behind
//! a polymorph transport that carries no static FANOS signature (spec §13.2). The shaping lives
//! entirely in the driver; the engine is byte-for-byte the one the simulator runs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration as StdDuration;

use std::sync::Arc;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_quic::{Directory, Morph, MorphCodec, ProteusConfig, spawn_shaped};
use fanos_runtime::{Command, Config, Notification, OverlayNode};

/// A trivial reversible pluggable codec standing in for a real cover-protocol transport (a real one tunnels
/// TLS/MASQUE/etc.): reverse the bytes and append a marker. Proves the SPI carries traffic over the wire.
#[derive(Debug)]
struct ReverseCodec;

impl MorphCodec for ReverseCodec {
    fn encode(&self, frame: &[u8], _seq: u64) -> Vec<u8> {
        let mut v: Vec<u8> = frame.iter().rev().copied().collect();
        v.push(0xC0);
        v
    }
    fn decode(&self, wire: &[u8]) -> Option<Vec<u8>> {
        let (&marker, body) = wire.split_last()?;
        (marker == 0xC0).then(|| body.iter().rev().copied().collect())
    }
}

/// Bring up two shaped nodes under `proteus`, send one payload A→B, and assert it is delivered through the
/// shaped transport within the timeout.
async fn deliver_under(proteus: ProteusConfig) {
    let epoch = fanos_proteus::Epoch::new(11);
    let dir = Directory::new();

    let a = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(0), Config::default())),
        dir.clone(),
        proteus.clone(),
        epoch,
    )
    .await
    .expect("spawn shaped A");
    let mut b = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(1), Config::default())),
        dir.clone(),
        proteus,
        epoch,
    )
    .await
    .expect("spawn shaped B");

    let payload = b"delivered through the shaped transport".to_vec();
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

#[tokio::test]
async fn shaped_nodes_deliver_over_a_polymorph_transport() {
    // The flagship codec: no static signature, no size/timing shaping (zero-cost default).
    deliver_under(ProteusConfig::polymorph(b"community-transport-secret".to_vec())).await;
}

#[tokio::test]
async fn shaped_nodes_deliver_under_a_timing_and_size_morph() {
    // A shaping morph (TLS-tunnel profile): every data frame is padded up into the MTU band AND paced by an
    // exponential inter-packet delay. Delivery must still round-trip — size padding is transparent to decode
    // and the pacing only delays. This exercises the driver's morph dispatch + `send_uni` pacing end to end.
    deliver_under(ProteusConfig::with_morph(
        b"community-transport-secret".to_vec(),
        Morph::TlsTunnel,
    ))
    .await;
}

#[tokio::test]
async fn shaped_nodes_deliver_under_a_pluggable_codec() {
    // The pluggable-transport SPI (§13.3): a custom `MorphCodec` fully replaces the built-in transform on the
    // wire, and two nodes running it still deliver application traffic end to end over a real socket.
    deliver_under(ProteusConfig::pluggable(
        b"community-transport-secret".to_vec(),
        Arc::new(ReverseCodec),
    ))
    .await;
}
