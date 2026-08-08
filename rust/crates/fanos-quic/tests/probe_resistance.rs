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

/// **A node running the flagship morph answers an unauthenticated prober** — §13.5 says it must not.
///
/// PROPERTY: an off-path observer with no community secret can tell a PROTEUS endpoint from an
/// unresponsive UDP port using one 1200-byte datagram and no cryptography.
///
/// The control arm (a bound, silent socket) is what makes the positive arm mean anything: it shows the
/// harness can observe silence, so the node's answer is the node's, not the loopback's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unauthenticated_prober_can_tell_a_proteus_node_from_a_silent_port() {
    let epoch = fanos_proteus::Epoch::new(7);
    let dir = Directory::new();
    let node = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(0), Config::default())),
        dir,
        ProteusConfig::polymorph(b"a-secret-the-prober-does-not-have".to_vec()),
        epoch,
    )
    .await
    .expect("spawn a shaped node");

    // The control first, so a harness fault fails here rather than masquerading as a clean result.
    let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind silent");
    let silent_addr = silent.local_addr().expect("silent addr");
    assert!(
        probe(silent_addr).await.is_none(),
        "the control must stay silent, or this test cannot distinguish anything",
    );

    let answer = probe(node.local_addr()).await;
    let Some(answer) = answer else {
        // The day this branch is taken, the finding is closed: keep the message pointing at what
        // changed rather than just failing.
        panic!(
            "the shaped node stayed silent — §13.5 now holds; delete this test's expectation and \
             record the mechanism that closed it",
        );
    };
    assert!(
        is_version_negotiation(&answer),
        "the answer is a QUIC Version Negotiation packet, i.e. the endpoint identified itself as a \
         QUIC server to a stranger: {:02x?}",
        &answer[..answer.len().min(16)],
    );
}

/// **The stranger's-eye view does not depend on the morph** — which is why rotating morphs cannot
/// answer a censor who works at this layer, and why the auto-fallback breaker (#231) reads a signal
/// its own control variable cannot move.
///
/// PROPERTY: two nodes differing in *both* inputs a deployment can turn — the community secret and the
/// morph — return byte-identical answers to the same probe. The morph is not an argument of this
/// observable.
///
/// The probe's connection IDs are fixed by [`version_negotiation_probe`], so a Version Negotiation
/// packet's only variable content (the echoed IDs) is held constant across the two nodes; any
/// remaining difference would have to come from the node.
///
/// Byte 0 is excluded, and the reason is in RFC 9000 §17.2.1: below the form bit its seven "Unused"
/// bits are set to an arbitrary value the client must ignore, and quinn randomizes them. Measured:
/// `0xC3` vs `0xE3` on the first run of this test, with **all 54 remaining bytes identical** — the
/// echoed IDs and, more to the point, the supported-version list `0a1a2a3a, 00000001,
/// ff00001d…ff000022`. That list is quinn 0.11's exact advertisement, and it is the same one under
/// both morphs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_answer_a_stranger_gets_is_the_same_under_every_morph() {
    let epoch = fanos_proteus::Epoch::new(7);

    let polymorph = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(0), Config::default())),
        Directory::new(),
        ProteusConfig::polymorph(b"community-A".to_vec()),
        epoch,
    )
    .await
    .expect("spawn the polymorph node");
    // `plain` is the other end of the morph axis: no codec at all. If anything a deployment configures
    // could change what a stranger sees, these two would differ.
    let plain = spawn_shaped(
        Box::new(OverlayNode::<F2>::new(Point::at(1), Config::default())),
        Directory::new(),
        ProteusConfig::with_morph(b"community-B-different".to_vec(), fanos_quic::Morph::Plain),
        epoch,
    )
    .await
    .expect("spawn the plain node");

    let a = probe(polymorph.local_addr()).await.expect("polymorph answered");
    let b = probe(plain.local_addr()).await.expect("plain answered");

    assert!(
        is_version_negotiation(&a) && is_version_negotiation(&b),
        "both arms must be QUIC answers, or the comparison below compares nothing",
    );
    assert_eq!(
        &a[1..],
        &b[1..],
        "the two nodes differ in community secret AND morph and still hand a stranger the same \
         bytes — the morph is not an input to what a censor sees first",
    );
    // Name the fingerprint rather than leaving it implicit in an equality: the supported-version list
    // is what a censor keys on, and it survives every morph rotation.
    assert!(
        a[5..].windows(4).any(|w| w == [0, 0, 0, 1]),
        "the answer advertises QUIC v1 in the clear: {:02x?}",
        &a[..a.len().min(32)],
    );
}
