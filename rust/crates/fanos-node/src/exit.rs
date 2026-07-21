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
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::diaulos::{dial_service, serve};
use crate::resolve::RESOLVE_TIMEOUT;

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
}
