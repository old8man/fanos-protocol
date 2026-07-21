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
//! is protocol-agnostic and fully interactive — it moves raw bytes both ways with no half-close required
//! (an HTTPS CONNECT tunnel works), whatever the client and destination speak.

use std::io;
use std::sync::Arc;

use fanos_diaulos::{Coord, StaticKeypair};
use fanos_field::Field;
use fanos_geometry::{Plane, Point};
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_quic::Client;
use fanos_rendezvous::Epoch;
use fanos_runtime::Notification;
use rand_core::CryptoRng;
use std::net::Ipv4Addr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::diaulos::{dial_service, serve};
use crate::resolve::RESOLVE_TIMEOUT;

/// Upper bound on the target header length (`host:port`) — bounds the read a malicious client can force
/// before it has connected anywhere.
const MAX_TARGET_LEN: usize = 256;

/// The maximum UDP datagram payload the exit tunnel carries (a `u16` length prefix bounds it; comfortably
/// above a jumbo DNS response).
pub const MAX_DATAGRAM_LEN: usize = 65535;

/// The transport an exit session relays: a TCP byte stream (the default) or UDP datagrams. Selected by an
/// optional scheme prefix on the target header (`udp:host:port`; a bare or `tcp:`-prefixed `host:port` is
/// TCP — backward-compatible with the original TCP-only exit).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Protocol {
    Tcp,
    Udp,
}

/// Parse an exit target header into `(protocol, host, port)`: a leading `udp:` selects UDP; a leading
/// `tcp:` or no scheme selects TCP. `None` if the `host:port` remainder is malformed.
fn parse_target(target: &str) -> Option<(Protocol, &str, u16)> {
    let (proto, rest) = match target.strip_prefix("udp:") {
        Some(rest) => (Protocol::Udp, rest),
        None => (Protocol::Tcp, target.strip_prefix("tcp:").unwrap_or(target)),
    };
    let (host, port) = split_host_port(rest)?;
    Some((proto, host, port))
}

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

/// Serve one exit session: read its target, enforce the policy, then splice it — a TCP byte stream or a
/// UDP datagram relay — until either side closes. Any error (bad header, denied target, unreachable host)
/// simply ends the session; the stream drops, closing it.
async fn relay_one(mut stream: DuplexStream, policy: &ExitPolicy) {
    let Some(target) = read_target(&mut stream).await else {
        return;
    };
    let Some((proto, host, port)) = parse_target(&target) else {
        return;
    };
    if !policy.allows_port(port) {
        return;
    }
    match proto {
        Protocol::Tcp => {
            let Ok(mut tcp) = TcpStream::connect((host, port)).await else {
                return;
            };
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        }
        Protocol::Udp => relay_udp(stream, host, port).await,
    }
}

/// Relay UDP datagrams for one exit session: bind an ephemeral socket **connected** to `(host, port)`, and
/// shuttle length-framed datagrams (`len(2 BE) ‖ payload`) between the session stream and that socket in
/// both directions until either closes. A connected socket keeps this a one-target tunnel (the UDP analog
/// of `CONNECT`) — the target sees the exit's address, never the client's. This serves DNS-over-FANOS (a
/// resolver at `udp:host:53`) and any single-destination UDP flow.
async fn relay_udp(stream: DuplexStream, host: &str, port: u16) {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
        return;
    };
    if socket.connect((host, port)).await.is_err() {
        return;
    }
    let socket = Arc::new(socket);
    let (mut reader, mut writer) = tokio::io::split(stream);

    // Session → target: each framed datagram off the stream is one UDP send.
    let up = {
        let socket = Arc::clone(&socket);
        async move {
            while let Some(payload) = read_datagram(&mut reader).await {
                if socket.send(&payload).await.is_err() {
                    break;
                }
            }
        }
    };
    // Target → session: each UDP datagram received is framed back onto the stream.
    let down = async move {
        let mut buf = vec![0u8; MAX_DATAGRAM_LEN];
        loop {
            let Ok(n) = socket.recv(&mut buf).await else {
                break;
            };
            if write_datagram(&mut writer, buf.get(..n).unwrap_or(&[]))
                .await
                .is_err()
            {
                break;
            }
        }
    };
    tokio::select! {
        () = up => {}
        () = down => {}
    }
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

/// Read one length-framed datagram (`len(2 BE) ‖ payload`) from a UDP-tunnel stream. `None` on EOF or a
/// short read; a zero length is a valid empty datagram.
pub async fn read_datagram<R: AsyncRead + Unpin>(reader: &mut R) -> Option<Vec<u8>> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).await.ok()?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    reader.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

/// Write one length-framed datagram (`len(2 BE) ‖ payload`) to a UDP-tunnel stream. Errors if `payload`
/// exceeds [`MAX_DATAGRAM_LEN`].
pub async fn write_datagram<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "datagram exceeds the tunnel frame size")
    })?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await
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

/// Client side: dial the exit and open a **UDP** tunnel to `(host, port)`. The returned stream carries
/// length-framed datagrams ([`write_datagram`] / [`read_datagram`]) — each frame written is one UDP send at
/// the exit, each frame read is one datagram the target sent back. Serves DNS-over-FANOS (`host:53`) and
/// any single-destination UDP; see [`dial_exit`] for the TCP form.
///
/// # Errors
/// An I/O error if the target header is too long or the initial write fails.
pub async fn dial_exit_udp<R: CryptoRng>(
    client: Client,
    service: Coord,
    service_public: &HybridKemPublic,
    host: &str,
    port: u16,
    rng: &mut R,
) -> io::Result<DuplexStream> {
    dial_exit(client, service, service_public, &format!("udp:{host}:{port}"), rng).await
}

// --- Exit discovery: exits advertise themselves through the overlay store (mirroring the mix directory),
// so a proxy finds one without a hand-configured descriptor. -----------------------------------------------

/// The overlay store slot an exit publishes its service public key at — domain-separated, keyed by the
/// exit's coordinate **and the epoch**. The epoch tag makes the directory *live*: an exit republishes each
/// epoch, so one that has gone away simply stops appearing (best-effort roster, as with the mix directory).
fn exit_key_slot(coord: Coord, epoch: Epoch) -> Vec<u8> {
    let mut key = b"FANOS-v1/exit-key/".to_vec();
    key.extend_from_slice(&fanos_geometry::encode_triple(coord));
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// Publish this exit's stable service public key for `epoch` at its coordinate slot, so a proxy resolving
/// exits for that epoch discovers it. `false` if the store rejected the write.
pub async fn publish_exit_key(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    public: &HybridKemPublic,
) -> bool {
    client.put(exit_key_slot(coord, epoch), public.encode()).await
}

/// Resolve the exit service key published by the node at `coord` for `epoch`, or `None` if none is
/// published, the lookup times out, or the stored bytes are not a valid key.
pub async fn resolve_exit_key(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
) -> Option<HybridKemPublic> {
    let bytes = tokio::time::timeout(RESOLVE_TIMEOUT, client.get(exit_key_slot(coord, epoch)))
        .await
        .ok()??;
    HybridKemPublic::decode(&bytes)
}

/// Assemble the **live** exit directory of the base cell of plane `F` for `epoch`: resolve every cell
/// point's published exit key and keep those currently answering — a best-effort roster of exits the proxy
/// can route clearnet traffic through (no central directory; the cell advertises itself through the store).
pub async fn build_cell_exit_directory<F: Field>(
    client: &Client,
    epoch: Epoch,
) -> Vec<(Coord, HybridKemPublic)> {
    let mut exits = Vec::new();
    for i in 0..Plane::<F>::N as usize {
        let coord = Point::<F>::at(i).coords();
        if let Some(public) = resolve_exit_key(client, coord, epoch).await {
            exits.push((coord, public));
        }
    }
    exits
}

/// Keep an exit **discoverable**: spawn the task that (re)publishes the exit at `coord` its stable service
/// public key each epoch, so [`build_cell_exit_directory`] always sees it while the node runs. Publishes
/// the genesis-epoch key at once, then follows the node's `BeaconReady` stream (the exit's identity is
/// seed-pinned, so the same key is refreshed at each new epoch's slot). Ends when the node shuts down.
#[must_use]
pub fn spawn_exit_publisher(client: Client, coord: Coord, public: HybridKemPublic) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut events = client.subscribe();
        let mut epoch = Epoch::ZERO;
        publish_exit_key(&client, coord, epoch, &public).await;
        loop {
            match events.recv().await {
                Ok(Notification::BeaconReady { epoch: reached, .. }) if reached > epoch => {
                    epoch = reached;
                    publish_exit_key(&client, coord, epoch, &public).await;
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
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
    fn exit_key_slots_are_distinct_and_domain_separated() {
        let a = exit_key_slot([1, 0, 0], Epoch::ZERO);
        assert!(a.starts_with(b"FANOS-v1/exit-key/"), "domain-separated slot");
        assert_ne!(a, exit_key_slot([0, 1, 0], Epoch::ZERO), "coord changes the slot");
        assert_ne!(a, exit_key_slot([1, 0, 0], Epoch::new(1)), "epoch changes the slot");
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

    #[test]
    fn parse_target_selects_the_protocol() {
        assert_eq!(parse_target("example.com:443"), Some((Protocol::Tcp, "example.com", 443)));
        assert_eq!(parse_target("tcp:example.com:80"), Some((Protocol::Tcp, "example.com", 80)));
        assert_eq!(parse_target("udp:9.9.9.9:53"), Some((Protocol::Udp, "9.9.9.9", 53)));
        assert_eq!(parse_target("udp:[::1]:53"), Some((Protocol::Udp, "::1", 53)));
        assert_eq!(parse_target("udp:no-port"), None, "a malformed udp target is rejected");
    }

    #[tokio::test]
    async fn the_udp_relay_tunnels_datagrams_to_a_target_and_back() {
        use std::time::Duration;

        // A UDP echo server: whatever it receives, it sends straight back to the sender.
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, src)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(buf.get(..n).unwrap_or(&[]), src).await;
            }
        });

        // The exit's UDP relay, connected to the echo server, over one half of an in-memory duplex.
        let (client, exit) = tokio::io::duplex(64 * 1024);
        let host = echo_addr.ip().to_string();
        let port = echo_addr.port();
        let relay = tokio::spawn(async move { relay_udp(exit, &host, port).await });

        let (mut rd, mut wr) = tokio::io::split(client);
        // Two distinct framed datagrams each round-trip through the exit and the echo server.
        for expected in [b"dns-query".as_slice(), b"a second datagram".as_slice()] {
            write_datagram(&mut wr, expected).await.unwrap();
            let echoed = tokio::time::timeout(Duration::from_secs(2), read_datagram(&mut rd))
                .await
                .expect("no timeout")
                .expect("a datagram comes back");
            assert_eq!(echoed, expected, "the UDP relay tunnels the datagram to the target and back");
        }

        drop(wr); // closing the tunnel ends the relay
        let _ = tokio::time::timeout(Duration::from_secs(2), relay).await;
    }
}
