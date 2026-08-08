//! PROTEUS over a real socket: two nodes whose QUIC driver shapes every frame with a shared
//! community secret still deliver application traffic — the same `OverlayNode` engine, now behind
//! a polymorph transport (spec §13.2). The shaping lives entirely in the driver; the engine is
//! byte-for-byte the one the simulator runs.
//!
//! This file measures *delivery through the shaped path*. It does not measure what an off-path
//! observer sees, and the two are not the same question: the shaping starts at the QUIC stream, so
//! the connection still opens in plaintext. `probe_resistance.rs` measures that half.
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

/// Bytes that do not un-shape are counted, and counted as *that* — not as the other transport discard.
///
/// Before #191 this was a bare `continue` in `read_frames`. Two defects lived in that silence: #190's
/// ceiling mismatch (every full block dropped, `write_all` reporting success) and #196's epoch-turn
/// blackout. It is also exactly what an active censor probing a PROTEUS bridge produces — so an unprobed
/// bridge and one under systematic probing were observationally identical.
///
/// Driven by giving the two nodes **different community secrets**, which is the same condition a peer in
/// another epoch or a stranger creates: A's frames are well-formed and B cannot strip them.
///
/// The negative half is the point. A counter that rises on everything says nothing, so this asserts the
/// *other* transport station stays at zero — the frames are the right size, they are simply not ours.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bytes_that_do_not_unshape_are_counted_as_that_and_not_as_something_else() {
    let epoch = fanos_proteus::Epoch::new(3);
    let dir = Directory::new();
    let a = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(0), Config::default())),
        dir.clone(),
        ProteusConfig::polymorph(b"community-A".to_vec()),
        epoch,
    )
    .await
    .expect("spawn A");
    let b = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(1), Config::default())),
        dir.clone(),
        ProteusConfig::polymorph(b"community-B-different".to_vec()),
        epoch,
    )
    .await
    .expect("spawn B");

    let count = |h: &fanos_quic::NodeHandle, want: &str| -> u64 {
        h.client()
            .driver_stations()
            .iter()
            .filter(|o| o.station.name() == want)
            .map(|o| o.count)
            .sum()
    };
    assert_eq!(count(&b, "wire.foreign_datagram"), 0, "nothing has been refused before any traffic");

    for _ in 0..8 {
        a.command(Command::Send { to: b.address(), payload: b"unreadable to B".to_vec() });
    }
    // No delivery to await — that is the condition under test — so give the reads a bounded moment to run.
    tokio::time::sleep(StdDuration::from_secs(2)).await;

    assert!(
        count(&b, "wire.foreign_datagram") > 0,
        "B must count what it refused; a bridge under probing looked idle before this"
    );
    assert_eq!(
        count(&b, "wire.over_bound"),
        0,
        "and must not blame the size: these datagrams are well within the ceiling, they are simply not ours"
    );
    // The gate MOVED, and that is the finding this assertion carries (#232). Before the datagram envelope,
    // A's frames reached B's frame decoder and were refused there as `wire.unshaped`. Now A's very first
    // datagram — its QUIC Initial — is refused, so the two never share a connection and the frame layer
    // never sees anything. A counter left behind at the old gate would read zero for ever and be mistaken
    // for "no probing".
    assert_eq!(
        count(&b, "wire.unshaped"),
        0,
        "with the envelope on, a foreign community is refused a layer earlier and never reaches the frames"
    );
}
