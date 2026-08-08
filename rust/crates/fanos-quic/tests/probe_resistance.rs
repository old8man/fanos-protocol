//! **§13.5 probe-indistinguishability, measured against a live PROTEUS node.**
//!
//! The spec makes two claims about the obfuscated modes, and both are about the *first packet of a
//! connection* — the one place a morph never reaches today:
//!
//! * §13.3 — "the obfuscated modes carry the FANOS wire over a raw polymorphic UDP transport **with no
//!   QUIC/TLS handshake to fingerprint**."
//! * §13.5 — "without the correct `community_secret` the endpoint returns nothing decodable — the
//!   handshake is keyed, so **a prober sees an unresponsive UDP port** (obfs4-class)."
//!
//! What ships instead: `spawn_shaped` builds an ordinary `quinn` endpoint from `node_configs()` and
//! applies the polymorph codec at `shape_out`/`shape_in`, which are called only on QUIC **streams** —
//! strictly after the handshake. So the shaped envelope starts one layer too late: every FANOS
//! connection opens with a plaintext QUIC Initial carrying `alpn = fanos/1` and `sni = fanos.node`,
//! identical under every morph, and the endpoint answers strangers.
//!
//! This file measures the second claim, because it needs no crypto to falsify. An RFC 9000 server must
//! answer a long-header packet bearing an unsupported version with a **Version Negotiation** packet
//! (§6.1). An "unresponsive UDP port" cannot. The probe carries no community secret, no FANOS
//! credentials and no valid version — the weakest possible censor.
//!
//! The control is the point: the identical probe is also sent to a bound-but-silent UDP socket, so
//! "we heard something back" is a statement about the *node* and not about the harness. Without that
//! arm a passing assertion would only prove the socket works.

// Indexing is deliberate here: this file reads a wire format at fixed offsets (RFC 9000 §17.2.1), and a
// packet that is too short to index is a *failed measurement*, which must abort the test rather than be
// silently folded into a `None`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_quic::{Directory, ProteusConfig, spawn_shaped};
use fanos_runtime::{Config, OverlayNode};
use tokio::net::UdpSocket;

/// How long a prober waits for an answer. Generous: this is loopback, and the assertion that matters
/// (the silent control) is the one that spends the whole budget.
const PROBE_WAIT: Duration = Duration::from_secs(3);

/// A QUIC long-header packet with a **reserved** version (RFC 9000 §15: `0x?a?a?a?a` is permanently
/// unassigned and exists precisely to force version negotiation), padded to the 1200-byte
/// anti-amplification floor a server requires before it will answer.
///
/// Deliberately *not* a FANOS packet: it carries no community secret, no shaped envelope and no valid
/// version. Anything that answers it is answering a stranger.
fn version_negotiation_probe() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(1200);
    pkt.push(0xC0); // long header, fixed bit set
    pkt.extend_from_slice(&0x1a2a_3a4au32.to_be_bytes()); // reserved version — never supported
    pkt.push(8); // DCID length
    pkt.extend_from_slice(&[0x11; 8]);
    pkt.push(8); // SCID length
    pkt.extend_from_slice(&[0x22; 8]);
    pkt.resize(1200, 0);
    pkt
}

/// Send the probe to `target` and return the answer, or `None` if the target stayed silent.
async fn probe(target: std::net::SocketAddr) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind prober");
    sock.send_to(&version_negotiation_probe(), target)
        .await
        .expect("send probe");
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(PROBE_WAIT, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _from))) => {
            buf.truncate(n);
            Some(buf)
        }
        // A closed loopback port can surface as an ICMP-driven error rather than a timeout; both mean
        // "no QUIC server answered", which is what the control arm needs.
        Ok(Err(_)) | Err(_) => None,
    }
}

/// Whether `pkt` is a QUIC Version Negotiation packet: long header with an all-zero version field
/// (RFC 9000 §17.2.1). Only a QUIC server emits one.
fn is_version_negotiation(pkt: &[u8]) -> bool {
    pkt.len() >= 5 && pkt[0] & 0x80 != 0 && pkt[1..5] == [0, 0, 0, 0]
}

/// **A sealed node is silent to an unauthenticated prober; an unsealed one is not** (spec §13.5).
///
/// PROPERTY: the answer a stranger gets is now a *function of the morph*. Three arms, and all three are
/// needed — the interesting claim is a difference, and a difference needs both sides plus a floor.
///
/// 1. a bound, silent UDP socket — shows the harness can observe silence at all;
/// 2. a `Morph::Plain` node — shows the probe still works and native QUIC still answers, so arm 3's
///    silence is the envelope's doing and not a broken prober;
/// 3. a `Morph::Polymorph` node — the property.
///
/// Before the datagram envelope (#232) arm 3 answered with a Version Negotiation packet byte-identical to
/// arm 2's but for RFC 9000 §17.2.1's arbitrary low bits. That measurement is what this file was written
/// to record; this is the same measurement after the mechanism, which is why the `plain` arm stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealed_node_is_silent_where_an_unsealed_one_answers() {
    let epoch = fanos_proteus::Epoch::new(7);

    // Arm 1 — the floor.
    let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind silent");
    let silent_addr = silent.local_addr().expect("silent addr");
    assert!(
        probe(silent_addr).await.is_none(),
        "the floor must stay silent, or this test cannot distinguish anything",
    );

    // Arm 2 — native QUIC, no envelope. `plain` declines the envelope by design.
    let plain = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(1), Config::default())),
        Directory::new(),
        ProteusConfig::with_morph(b"community".to_vec(), fanos_quic::Morph::Plain),
        epoch,
    )
    .await
    .expect("spawn the plain node");
    let answer = probe(plain.local_addr()).await;
    let Some(answer) = answer else {
        panic!("the `plain` morph must still answer, or arm 3 proves nothing about the envelope");
    };
    assert!(
        is_version_negotiation(&answer),
        "and it answers as a QUIC server: {:02x?}",
        &answer[..answer.len().min(16)],
    );

    // Arm 3 — the flagship morph, sealed.
    let sealed = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(0), Config::default())),
        Directory::new(),
        ProteusConfig::polymorph(b"a-secret-the-prober-does-not-have".to_vec()),
        epoch,
    )
    .await
    .expect("spawn the sealed node");
    assert!(
        probe(sealed.local_addr()).await.is_none(),
        "a sealed endpoint must not answer a stranger — §13.5's unresponsive UDP port",
    );

    // …and the silence is *counted*, which is the other half. A drop this quiet is invisible on every
    // other surface a node has, so a bridge under enumeration would read as idle without this counter.
    let probes: u64 = sealed
        .client()
        .driver_stations()
        .iter()
        .filter(|o| o.station.name() == "wire.foreign_datagram")
        .map(|o| o.count)
        .sum();
    assert!(probes > 0, "the refusal must leave a trace; silence on the wire is not silence in the log");
}
