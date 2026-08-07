//! PROTEUS over a real socket: two nodes whose QUIC driver shapes every frame with a shared
//! community secret still deliver application traffic — the same `OverlayNode` engine, now behind
//! a polymorph transport that carries no static FANOS signature (spec §13.2). The shaping lives
//! entirely in the driver; the engine is byte-for-byte the one the simulator runs.
//!
//! Runtime: multi-threaded with **four** workers — a current-thread harness cannot see a parallelism
//! defect at all (#84), and two workers see it only 3 times in 8 where four see it 8 of 8. Measured
//! against the reverted fix for #83; the table is in `fanos-quic/tests/store_acks.rs`.

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

/// A frame packed to the wire authority's ceiling still arrives once shaped.
///
/// The defect this pins: `MAX_FRAME` bounded the sender's *frame* and the receiver's *wire*, and PROTEUS
/// sits between them growing every packet (`nonce ‖ junk ‖ len ‖ payload ‖ padding`, on by default). A
/// producer that filled its budget — a TAXIS block does, by design — therefore emitted something no peer
/// could read, `write_all` reported success, and nothing counted the loss.
///
/// The epoch is chosen **by measurement**, not picked: only a heavily-junked shape guarantees the wire
/// exceeds the frame cap, so searching for one makes this test hit the boundary on every run instead of on
/// whichever epochs happen to shape hard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_at_the_ceiling_survives_the_shaper() {
    let secret = b"ceiling-secret".to_vec();
    let (epoch, junk) = (0u64..100_000)
        .map(fanos_proteus::Epoch::new)
        .map(|e| (e, fanos_proteus::epoch_shape(&secret, e).junk_len()))
        .find(|&(_, junk)| junk > 1200)
        .expect("some epoch in 100k shapes with >1200 bytes of junk");

    // Sized so the wire provably exceeds the frame cap: the payload is `slack` below it, and shaping adds
    // at least `junk` — more than `slack` — before the envelope is even counted.
    let slack = 1024usize;
    assert!(junk > slack, "the chosen epoch must add more than the slack, got {junk}");
    let payload = vec![0x5A; fanos_wire::MAX_FRAME - slack];

    let dir = Directory::new();
    let cfg = || ProteusConfig::polymorph(secret.clone());
    let a = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(0), Config::default())),
        dir.clone(),
        cfg(),
        epoch,
    )
    .await
    .expect("spawn A");
    let mut b = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(1), Config::default())),
        dir.clone(),
        cfg(),
        epoch,
    )
    .await
    .expect("spawn B");

    a.command(Command::Send { to: b.address(), payload: payload.clone() });

    let got = tokio::time::timeout(StdDuration::from_secs(20), async {
        loop {
            if let Some(Notification::Delivered { from, payload }) = b.next_notification().await
                && from == a.address()
            {
                return payload;
            }
        }
    })
    .await
    .expect("a frame at the ceiling must arrive; before the wire got its own bound it never did");
    assert_eq!(got.len(), payload.len(), "the whole frame arrived, not a truncation");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shaped_nodes_deliver_over_a_polymorph_transport() {
    // The flagship codec: no static signature, no size/timing shaping (zero-cost default).
    deliver_under(ProteusConfig::polymorph(b"community-transport-secret".to_vec())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shaped_nodes_deliver_under_a_pluggable_codec() {
    // The pluggable-transport SPI (§13.3): a custom `MorphCodec` fully replaces the built-in transform on the
    // wire, and two nodes running it still deliver application traffic end to end over a real socket.
    deliver_under(ProteusConfig::pluggable(
        b"community-transport-secret".to_vec(),
        Arc::new(ReverseCodec),
    ).unwrap())
    .await;
}
