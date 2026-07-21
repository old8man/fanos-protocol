//! Clearnet **exit relay** (roadmap §3, the `exit` role): a node that bridges anonymous overlay traffic to
//! the ordinary internet. A client dials the exit as a DIAULOS service, sends a target `host:port`, and the
//! exit opens a TCP connection there and splices bytes both ways — so the destination sees the exit's
//! address, not the client's. This is what lets FANOS reach services that are not themselves on the
//! overlay, the counterpart to a Tor exit node.
//!
//! The exit is transport-anonymous exactly to the degree the client's DIAULOS circuit is (direct or a
//! threshold-onion rendezvous route): the exit never learns who the client is, only the target it asked
//! for. An [`ExitPolicy`] bounds what the exit will relay to — an open relay to *any* port is an abuse
//! lever, so the operator restricts it (an empty allow-list means "any port", chosen explicitly).
//!
//! Wire framing on the DIAULOS stream: the client first sends `len(2 BE) ‖ host:port` (UTF-8), then relays
//! its connection's bytes; the exit splices those to the TCP target and the target's bytes back. The exit
//! is protocol-agnostic — it moves raw bytes, whatever the client and destination speak.
//!
//! **Session shape (current):** the underlying DIAULOS session completes and delivers the client's bytes
//! once the client half-closes its send side — the *request → response* shape (HTTP/1.0, DNS-over-TCP, and
//! any protocol where the client's request is bounded before it reads the reply). Fully-interactive
//! bidirectional streaming (the client sending and receiving with no half-close, as an HTTPS CONNECT
//! tunnel needs) additionally requires the reliable-stream layer to surface received bytes before the
//! peer's FIN — a DIAULOS-layer enhancement tracked separately, not a property of this relay, which is
//! already byte-transparent. The relay mechanism here is unchanged either way.

use std::io;
use std::sync::Arc;

use fanos_diaulos::{Coord, StaticKeypair};
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_quic::Client;
use rand_core::CryptoRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;

use crate::diaulos::{dial_service, serve};

/// Upper bound on the target header length (`host:port`) — bounds the read a malicious client can force
/// before it has connected anywhere.
const MAX_TARGET_LEN: usize = 256;

/// What clearnet targets an exit will relay to. A first cut gates on the destination **port** (the common
/// abuse lever — mail relays, scanning); an empty allow-list means any port, which the operator opts into
/// explicitly rather than by default.
#[derive(Clone, Default, Debug)]
pub struct ExitPolicy {
    allowed_ports: Vec<u16>,
}

impl ExitPolicy {
    /// An exit policy allowing exactly `allowed_ports` (empty = any port).
    #[must_use]
    pub fn new(allowed_ports: Vec<u16>) -> Self {
        Self { allowed_ports }
    }

    /// The conventional web policy: HTTP (80) and HTTPS (443) only.
    #[must_use]
    pub fn web() -> Self {
        Self::new(vec![80, 443])
    }

    /// Whether this policy permits relaying to `port`.
    #[must_use]
    pub fn allows_port(&self, port: u16) -> bool {
        self.allowed_ports.is_empty() || self.allowed_ports.contains(&port)
    }
}

/// Run a clearnet exit service on `client`'s node under the DIAULOS service identity `keypair`. Each client
/// that dials gets its own stream (see [`serve`]); the exit reads the requested target, checks `policy`,
/// dials TCP, and splices until either side closes. Returns immediately (spawns the demultiplexer).
pub fn serve_exit<R>(client: Client, keypair: StaticKeypair, rng: R, policy: ExitPolicy)
where
    R: CryptoRng + Send + 'static,
{
    let policy = Arc::new(policy);
    serve(client, keypair, rng, move |stream| {
        let policy = Arc::clone(&policy);
        async move {
            relay_one(stream, &policy).await;
        }
    });
}

/// Serve one exit session: read its target, enforce the policy, dial TCP, and splice both ways. Any error
/// (bad header, denied target, unreachable host) simply ends the session — the stream drops, closing it.
async fn relay_one(mut stream: DuplexStream, policy: &ExitPolicy) {
    let Some(target) = read_target(&mut stream).await else {
        return;
    };
    let Some((host, port)) = split_host_port(&target) else {
        return;
    };
    if !policy.allows_port(port) {
        return;
    }
    let Ok(mut tcp) = TcpStream::connect((host, port)).await else {
        return;
    };
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
}

/// Read the length-prefixed target header `len(2 BE) ‖ host:port` from the stream.
async fn read_target(stream: &mut DuplexStream) -> Option<String> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.ok()?;
    let len = usize::from(u16::from_be_bytes(len));
    if len == 0 || len > MAX_TARGET_LEN {
        return None;
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.ok()?;
    String::from_utf8(buf).ok()
}

/// Split a `host:port` target, taking the port after the LAST colon (so IPv6 literals like `[::1]:443` and
/// bare hostnames both parse). `None` if there is no port, the port is unparseable, or the host is empty.
fn split_host_port(target: &str) -> Option<(&str, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let port: u16 = port.parse().ok()?;
    (!host.is_empty()).then_some((host, port))
}

/// Client side: dial the exit at `(service, service_public)` and ask it to connect to `target`
/// (`host:port`), returning the spliceable stream. The caller then copies its local connection's payload
/// over the returned stream (the destination sees the exit, not the caller).
///
/// # Errors
/// An I/O error if `target` exceeds the header length bound or the initial write fails.
pub async fn dial_exit<R: CryptoRng>(
    client: Client,
    service: Coord,
    service_public: &HybridKemPublic,
    target: &str,
    rng: &mut R,
) -> io::Result<DuplexStream> {
    let bytes = target.as_bytes();
    let len = u16::try_from(bytes.len())
        .ok()
        .filter(|&n| usize::from(n) <= MAX_TARGET_LEN)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "exit target too long"))?;
    let mut stream = dial_service(client, service, service_public, rng);
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(bytes).await?;
    Ok(stream)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn policy_gates_on_port() {
        let web = ExitPolicy::web();
        assert!(web.allows_port(443) && web.allows_port(80));
        assert!(!web.allows_port(25), "SMTP is not in the web policy");
        assert!(ExitPolicy::default().allows_port(9999), "empty allow-list = any port");
    }

    #[test]
    fn splits_host_and_port() {
        assert_eq!(split_host_port("example.com:443"), Some(("example.com", 443)));
        assert_eq!(split_host_port("127.0.0.1:80"), Some(("127.0.0.1", 80)));
        assert_eq!(split_host_port("[::1]:8443"), Some(("::1", 8443)));
        assert_eq!(split_host_port("no-port"), None);
        assert_eq!(split_host_port(":443"), None, "empty host rejected");
        assert_eq!(split_host_port("host:not-a-port"), None);
    }
}
