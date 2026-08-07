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
use fanos_quic::{Client, CoordinateProver};
use fanos_rendezvous::{BeaconSeed, Epoch};
use fanos_vrf::{VrfProof, VrfPublic};

use crate::bound::Entitlement;
use rand_core::CryptoRng;
use std::net::Ipv4Addr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinHandle;

use crate::DIRECTORY_SLOT_EPOCHS;
use crate::role_loop::LoadGauge;
use crate::diaulos::{dial_service, serve};
use crate::resolve::STORE_TIMEOUT;

/// Upper bound on the target header length (`host:port`) — bounds the read a malicious client can force
/// before it has connected anywhere.
const MAX_TARGET_LEN: usize = 256;

/// The maximum UDP datagram payload the exit tunnel carries (a `u16` length prefix bounds it; comfortably
/// above a jumbo DNS response).
pub const MAX_DATAGRAM_LEN: usize = 65535;

/// Whether `addr` is a destination an exit may relay to: **globally routable, and nothing else** (#170).
///
/// The exit policy gated on the destination **port** and on nothing else, so a client could name any
/// address and the exit would dial it. With the *recommended* `ports = 80, 443` that includes
/// **`169.254.169.254:80`** — the AWS/GCP/Azure/OpenStack instance-metadata endpoint, which on IMDSv1
/// answers with the operator's temporary IAM credentials — and with the default empty allow-list ("any
/// port") it includes the operator's whole LAN and their own loopback on every port.
///
/// An anonymity network makes that strictly worse than an ordinary SSRF: the requester is unidentifiable by
/// construction, and the traffic leaves from the exit operator's address, so the abuse is attributed to
/// them. Every exit implementation is expected to have this control — Tor's default policy rejects these
/// ranges before any port rule.
///
/// **Deny by default.** The list is written out rather than deferred to `Ipv4Addr::is_global`, which is
/// unstable, and each entry names the RFC it comes from so the next reader can check it rather than trust
/// it. Anything not recognised as globally routable is refused: an exit that cannot classify a destination
/// must not dial it.
///
/// `realm` widens nothing but loopback; see [`Realm`] for why that hatch exists and why it is this narrow.
#[must_use]
/// Whether an exit may relay to `addr` under `realm` — the platform's shared dial policy (#171).
///
/// The rule this used to spell out inline now lives in `fanos_quic::dial_policy`, because the hole-punch is
/// its second consumer and needed a DIFFERENT realm: a peer behind NAT is legitimately on 10/8, while an exit
/// destination never may be. Two named policies, one module, each with its derivation — rather than two
/// copies of a list of RFC ranges that would drift.
fn is_relayable(addr: &std::net::IpAddr, realm: Realm) -> bool {
    fanos_quic::dial_policy::may_dial(addr, realm.policy())
}

/// Resolve `host:port` and return the first **relayable** address, or `None` if the name resolves to
/// nothing an exit may dial.
///
/// **The resolution happens here, once, and the caller connects to the returned `SocketAddr`** — never to
/// the name again. That is the whole point and it is easy to get wrong: `TcpStream::connect((host, port))`
/// resolves *inside* `connect`, so a filter applied to the host **string** is bypassed by a name that simply
/// resolves to a private address (`metadata.attacker.example → 169.254.169.254` — no rebinding required),
/// and a resolve-then-reconnect-by-name is bypassed by rebinding between the two lookups.
async fn resolve_relayable(host: &str, port: u16, realm: Realm) -> Option<std::net::SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await
        .ok()?
        .find(|addr| is_relayable(&addr.ip(), realm))
}

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

/// Which **addresses** an exit may dial, independent of the port rule.
///
/// This exists only because an in-process end-to-end test has to point the exit at an echo server it just
/// bound, and the only address it can bind on every CI host is loopback — the one address production must
/// refuse hardest. So the escape hatch is made explicit, named for what it is, and kept as narrow as the
/// fixture needs: [`Realm::AlsoLoopback`] relaxes loopback **and nothing else**. RFC 1918, CGNAT and
/// link-local — including `169.254.169.254` — stay refused in both realms, so the exemption provably cannot
/// re-open the hole #170 closed, and `the_metadata_endpoint_is_refused_in_every_realm` asserts exactly that.
///
/// It is a constructor argument rather than a builder method on purpose: a security default that a caller
/// must remember to switch on is a default that production ships without.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum Realm {
    /// Globally routable destinations only. The shipping rule, and the only value a configuration file or
    /// any other production path can produce.
    #[default]
    Global,
    /// Additionally permits loopback. **Test fixtures only** — an exit constructed this way will relay an
    /// anonymous client onto the operator's own host.
    AlsoLoopback,
}

impl Realm {
    /// The shared dial policy this realm selects (#171).
    ///
    /// Both map to a `Clearnet*` policy: an exit is never permitted the punch path's tolerance for private
    /// addresses, and this function is the one place that mapping is written.
    const fn policy(self) -> fanos_quic::dial_policy::Policy {
        match self {
            Self::Global => fanos_quic::dial_policy::Policy::Clearnet,
            Self::AlsoLoopback => fanos_quic::dial_policy::Policy::ClearnetOrLoopback,
        }
    }
}

/// What clearnet targets an exit will relay to: a destination **port** rule the operator writes (the common
/// abuse lever — mail relays, scanning; an empty allow-list means any port, opted into explicitly rather
/// than by default), and a destination **address** rule that is not the operator's to widen (#170).
#[derive(Clone, Default, Debug)]
pub struct ExitPolicy {
    allowed_ports: Vec<u16>,
    realm: Realm,
}

impl ExitPolicy {
    /// An exit policy allowing exactly `allowed_ports` (empty = any port), to globally routable addresses.
    #[must_use]
    pub fn new(allowed_ports: Vec<u16>) -> Self {
        Self { allowed_ports, realm: Realm::Global }
    }

    /// The conventional web policy: HTTP (80) and HTTPS (443) only.
    #[must_use]
    pub fn web() -> Self {
        Self::new(vec![80, 443])
    }

    /// The same policy, but also willing to dial loopback — **for end-to-end tests only**, see [`Realm`].
    ///
    /// Named to be unmistakable at the call site and kept honest by
    /// `the_loopback_exemption_is_reachable_only_from_a_test` in `fanos-cli/tests/architecture.rs`, which
    /// fails if any non-test file in the workspace calls it.
    #[must_use]
    pub fn also_permitting_loopback_for_tests(allowed_ports: Vec<u16>) -> Self {
        Self { allowed_ports, realm: Realm::AlsoLoopback }
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
/// `gauge` meters the role: each session counts as one unit of exit work in flight for as long as it is
/// spliced, which is what closes the role controller's loop for a role no engine can see. `None` runs unmetered
/// — the role then reports no sensor and the cell falls back to what nodes *offer*, which is the right
/// behaviour for a bare exit spawned outside a self-organizing node (the integration tests, an embedder).
pub fn serve_exit<R>(
    client: Client,
    keypair: StaticKeypair,
    rng: R,
    policy: ExitPolicy,
    gauge: Option<LoadGauge>,
) where
    R: CryptoRng + Send + 'static,
{
    let policy = Arc::new(policy);
    serve(client, keypair, rng, move |stream| {
        let policy = Arc::clone(&policy);
        // Taken before the session runs and dropped with the future, so every way a session can end — a clean
        // close, a rejected port, an unreachable host, a cancelled task — decrements it.
        let carried = gauge.as_ref().map(LoadGauge::in_flight);
        async move {
            relay_one(stream, &policy).await;
            drop(carried);
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
    // **Then the destination itself** (#170). The port is only half the question, and it was the only half
    // asked: `ports = 80, 443` — the policy the setup wizard writes, commented "a web-only exit" — permits
    // `169.254.169.254:80`, the cloud metadata endpoint. Resolved once here so the connect below cannot
    // re-resolve to something else; see `resolve_relayable`.
    let Some(dest) = resolve_relayable(host, port, policy.realm).await else {
        // Loud, because a refusal and a quiet exit look identical to an operator, and this particular
        // refusal is the signature of someone probing for the metadata endpoint from inside the anonymity
        // set. The target is logged; the client is unidentifiable by construction, which is the point of the
        // network and the reason the operator needs the other half.
        tracing::warn!(
            target = %target,
            "exit refused a non-relayable destination: it resolves to a loopback, private, link-local or \
             otherwise non-global address"
        );
        return;
    };
    match proto {
        Protocol::Tcp => {
            let Ok(mut tcp) = TcpStream::connect(dest).await else {
                return;
            };
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        }
        Protocol::Udp => relay_udp(stream, dest).await,
    }
}

/// Relay UDP datagrams for one exit session: bind an ephemeral socket **connected** to `(host, port)`, and
/// shuttle length-framed datagrams (`len(2 BE) ‖ payload`) between the session stream and that socket in
/// both directions until either closes. A connected socket keeps this a one-target tunnel (the UDP analog
/// of `CONNECT`) — the target sees the exit's address, never the client's. This serves DNS-over-FANOS (a
/// resolver at `udp:host:53`) and any single-destination UDP flow.
async fn relay_udp(stream: DuplexStream, dest: std::net::SocketAddr) {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await else {
        return;
    };
    // An already-resolved, already-filtered address (#170) — never a name, which `connect` would resolve
    // again and could resolve differently.
    if socket.connect(dest).await.is_err() {
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
    exit_send_target(dial_service(client, service, service_public, rng), target).await
}

/// Send the exit its destination `target` over an **already-established** session (the client→exit protocol:
/// `len(2, big-endian) ‖ target`). The session may be Direct *or* anonymous — the exit only ever learns the
/// target, never the client's coordinate — so the caller chooses the transport per the anonymity profile
/// (audit S1-C1: an anonymous profile routes this over the rendezvous, not a Direct by-coordinate dial).
pub async fn exit_send_target(mut stream: DuplexStream, target: &str) -> io::Result<DuplexStream> {
    let bytes = target.as_bytes();
    let len = u16::try_from(bytes.len())
        .ok()
        .filter(|&n| usize::from(n) <= MAX_TARGET_LEN)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "exit target too long"))?;
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

/// The bytes an exit key is stored as: the bare key, or the key inside the coordinate-bound
/// [`Entitlement`] envelope when this deployment can prove coordinates.
///
/// **A key directory that nobody signs is a key directory anyone can rewrite.** The store is
/// content-addressed, so this slot's key embeds a coordinate but nothing made the publisher own it: any
/// admitted member could overwrite another exit's published key. Traffic then seals to a key the honest node
/// at that coordinate cannot open — the transport is still coordinate-authenticated by HELLO, so it is
/// denial rather than interception, and total: with no exit discovered and none pinned, a proxy refuses
/// every clearnet target. One member takes down the cell's whole clearnet path, attributable to nobody.
///
/// The three sibling directories ([`crate::mixdir`], [`crate::capdir`], [`crate::loaddir`]) all carry this
/// envelope; this one did not. One encode, one decode, both on the production path, so a test that drives
/// them is testing what ships.
#[must_use]
fn exit_record(public: &HybridKemPublic, credential: Option<&(Vec<u8>, VrfPublic, VrfProof)>) -> Vec<u8> {
    let payload = public.encode();
    match credential {
        Some((id, vrf_public, proof)) => Entitlement::encode(id, vrf_public, proof, &payload),
        None => payload,
    }
}

/// The inverse of [`exit_record`]: the published key, or `None` if malformed or — when `beacon` is `Some` —
/// not bound to `coord` for `epoch`.
#[must_use]
fn open_exit_record<F: Field>(
    bytes: &[u8],
    coord: Coord,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<HybridKemPublic> {
    match beacon {
        Some(seed) => {
            let (_, payload) = Entitlement::open::<F>(bytes, coord, epoch, &seed)?;
            HybridKemPublic::decode(payload)
        }
        None => HybridKemPublic::decode(bytes),
    }
}

/// Publish this exit's stable service public key for `epoch` at its coordinate slot, so a proxy resolving
/// exits for that epoch discovers it. `false` if the store rejected the write.
///
/// `credential` is this node's coordinate proof for `epoch` — `Some` on any cell with VRF coordinates, and
/// the record is then bound so no other member can replace this exit's key. `None` emits the bare key a
/// pinned cell can produce, where no coordinate is provable.
pub async fn publish_exit_key(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    public: &HybridKemPublic,
    credential: Option<&(Vec<u8>, VrfPublic, VrfProof)>,
) -> bool {
    let landed = client
        .put_ephemeral(exit_key_slot(coord, epoch), exit_record(public, credential), DIRECTORY_SLOT_EPOCHS)
        .await;
    crate::note_publish(client, crate::Directory::ExitKey, epoch, landed)
}

/// Resolve the exit service key published by the node at `coord` for `epoch`, or `None` if none is
/// published, the lookup times out, the stored bytes are not a valid key, or — when `beacon` is `Some` —
/// the record is not bound to that coordinate.
pub async fn resolve_exit_key<F: Field>(
    client: &Client,
    coord: Coord,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Option<HybridKemPublic> {
    let bytes = tokio::time::timeout(STORE_TIMEOUT, client.get(exit_key_slot(coord, epoch)))
        .await
        .ok()??;
    open_exit_record::<F>(&bytes, coord, epoch, beacon)
}

/// Assemble the **live** exit directory of the base cell of plane `F` for `epoch`: resolve every cell
/// point's published exit key and keep those currently answering — a best-effort roster of exits the proxy
/// can route clearnet traffic through (no central directory; the cell advertises itself through the store).
/// `beacon` states whether this deployment can prove coordinates — `Some` on any cell with VRF
/// coordinates, and a record that is not bound to the point it sits at is then skipped rather than routed
/// through. Symmetric with the publisher's `credential`, and with the three sibling directories.
pub async fn build_cell_exit_directory<F: Field>(
    client: &Client,
    epoch: Epoch,
    beacon: Option<BeaconSeed>,
) -> Vec<(Coord, HybridKemPublic)> {
    let mut exits = Vec::new();
    for i in 0..Plane::<F>::N as usize {
        let coord = Point::<F>::at(i).coords();
        if let Some(public) = resolve_exit_key::<F>(client, coord, epoch, beacon).await {
            exits.push((coord, public));
        }
    }
    exits
}

/// Keep an exit **discoverable**: spawn the task that (re)publishes the exit at `coord` its stable service
/// public key each epoch, so [`build_cell_exit_directory`] always sees it while the node runs. Publishes
/// the genesis-epoch key at once, then follows the node's `BeaconReady` stream (the exit's identity is
/// seed-pinned, so the same key is refreshed at each new epoch's slot). Ends when the node shuts down.
/// Publishes at the node's **live** coordinate, re-read on every cycle rather than captured at spawn.
///
/// A coordinate moves — every epoch by the beacon reshuffle (spec §L3), and within an epoch when a better claim displaces
/// this node. A publisher that captured it kept writing to the point the node had *left*, so the cell's directory scan found
/// a descriptor at an unoccupied point and none at the occupied one. Measured as rosters frozen one short of the occupied
/// count (`[4, 4, 4, 1, 4]` with five points held) after live coordinate resolution started actually moving nodes.
#[must_use]
pub fn spawn_exit_publisher(
    client: Client,
    public: HybridKemPublic,
    prover: Option<CoordinateProver>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut beacons = client.beacons();
        let mut epoch = Epoch::ZERO;
        // This network's epoch-0 seed, not the constant (`docs/design-genesis.md`) — a record bound against
        // the wrong seed proves a coordinate this node does not occupy, so no reader can verify it.
        let mut seed = client.genesis();
        let publish = |epoch: Epoch, seed: BeaconSeed, public: &HybridKemPublic| {
            // Proven per write: the credential names an epoch, so one captured at spawn would verify only
            // in the epoch it was made.
            let credential = prover.as_ref().map(|prove| prove(epoch, &seed));
            let (client, public) = (client.clone(), public.clone());
            async move { publish_exit_key(&client, client.address(), epoch, &public, credential.as_ref()).await }
        };
        publish(epoch, seed, &public).await;
        // Latest-state, not the lossy notification stream: an exit missing from the directory for an epoch
        // is an exit no proxy can discover for that epoch, and the stream could drop the round (#86).
        while let Some((reached, s)) = crate::next_epoch(&mut beacons, epoch).await {
            epoch = reached;
            seed = s;
            publish(epoch, seed, &public).await;
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// **An exit key verifies only at a coordinate its publisher can prove.**
    ///
    /// A key directory nobody signs is a key directory anyone rewrites. Any admitted member could overwrite
    /// another exit's published key; traffic then seals to something the honest node at that coordinate
    /// cannot open, and since a proxy refuses every clearnet target when no exit is discovered, one member
    /// takes the cell's whole clearnet path down and nothing attributes it.
    ///
    /// Stated over the plane rather than at one forged point — a credential verifies exactly on the
    /// coordinates its VRF walk reaches — and driven through the same `exit_record` / `open_exit_record`
    /// the publisher and the directory use, so deleting the binding from either end fails this.
    /// **The exit refuses every destination it must not dial** (#170), and the list is the point.
    ///
    /// The policy gated on the port and on nothing else, so `ports = 80, 443` — the configuration the setup
    /// wizard writes, commented *"a web-only exit"* — permitted `169.254.169.254:80`, the cloud
    /// instance-metadata endpoint that answers with the operator's IAM credentials on IMDSv1. Each address
    /// below is a destination a client could name and the exit would have dialled.
    #[test]
    fn the_exit_refuses_every_destination_it_must_not_dial() {
        use std::net::IpAddr;
        let ip = |s: &str| s.parse::<IpAddr>().expect("a literal address");

        for (what, addr) in [
            ("the cloud metadata endpoint", "169.254.169.254"),
            ("loopback", "127.0.0.1"),
            ("another loopback", "127.7.7.7"),
            ("RFC1918 /8", "10.1.2.3"),
            ("RFC1918 /12", "172.20.0.1"),
            ("RFC1918 /16", "192.168.1.1"),
            ("CGNAT", "100.100.0.1"),
            ("this-network", "0.0.0.0"),
            ("benchmarking", "198.19.0.1"),
            ("documentation", "192.0.2.1"),
            ("reserved", "240.0.0.1"),
            ("broadcast", "255.255.255.255"),
            ("v6 loopback", "::1"),
            ("v6 unique-local", "fc00::1"),
            ("v6 link-local", "fe80::1"),
            ("v6 documentation", "2001:db8::1"),
            ("an IPv4-mapped loopback — the wrapper must not launder it", "::ffff:127.0.0.1"),
            ("an IPv4-mapped metadata endpoint", "::ffff:169.254.169.254"),
        ] {
            assert!(!is_relayable(&ip(addr), Realm::Global), "{what} ({addr}) must not be relayable");
        }

        // And the other direction, or the filter above is indistinguishable from a blanket deny — an exit
        // that refuses everything is not an exit.
        for (what, addr) in [
            ("a public v4 address", "93.184.216.34"),
            ("a public resolver", "9.9.9.9"),
            ("a public v6 address", "2606:4700:4700::1111"),
        ] {
            assert!(is_relayable(&ip(addr), Realm::Global), "{what} ({addr}) must still be relayable");
        }
    }

    /// A NAME that resolves to a refused address is refused — the half a string check cannot do.
    ///
    /// `TcpStream::connect((host, port))` resolves inside `connect`, so filtering the host *string* is
    /// bypassed by `metadata.attacker.example → 169.254.169.254` with no rebinding at all. `localhost` is the
    /// one name every host resolves to a refused address, so it is the portable way to assert the resolved
    /// address is what gets checked.
    #[tokio::test]
    async fn a_name_that_resolves_to_a_refused_address_is_refused() {
        assert!(
            resolve_relayable("localhost", 80, Realm::Global).await.is_none(),
            "a name resolving only to loopback yields no relayable address",
        );
        assert!(
            resolve_relayable("127.0.0.1", 80, Realm::Global).await.is_none(),
            "and so does the literal",
        );
    }

    /// The test-only realm relaxes loopback and **nothing else** — the exemption cannot re-open #170.
    ///
    /// This is the assertion that makes [`Realm::AlsoLoopback`] safe to exist. An escape hatch added so an
    /// end-to-end fixture can reach the echo server it just bound is a hatch someone will later widen "while
    /// they are in there", and the widening that matters is the metadata endpoint: it is the one address on
    /// this list that hands over credentials. So the two realms are asserted to differ on loopback and to
    /// agree on everything else. Delete the `is_loopback` guard's narrowness — make the arm return `true`
    /// unconditionally — and the second half of this test reds.
    #[test]
    fn the_metadata_endpoint_is_refused_in_every_realm() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().expect("a literal address");

        assert!(
            is_relayable(&ip("127.0.0.1"), Realm::AlsoLoopback),
            "the fixture realm exists precisely so loopback is dialable",
        );
        assert!(
            is_relayable(&ip("::1"), Realm::AlsoLoopback),
            "and v6 loopback with it — the fixture binds whichever the host gives it",
        );

        for (what, addr) in [
            ("the cloud metadata endpoint", "169.254.169.254"),
            ("the rest of link-local", "169.254.1.1"),
            ("an RFC 1918 LAN host", "192.168.1.1"),
            ("a 10/8 host", "10.0.0.1"),
            ("a CGNAT host", "100.64.0.1"),
            ("the unspecified address", "0.0.0.0"),
            ("a v6 unique-local host", "fc00::1"),
            ("an IPv4-mapped metadata endpoint", "::ffff:169.254.169.254"),
        ] {
            assert!(
                !is_relayable(&ip(addr), Realm::AlsoLoopback),
                "{what} ({addr}) must stay refused even in the fixture realm — the hatch is loopback only",
            );
        }
    }

    #[test]
    fn an_exit_key_verifies_only_at_a_coordinate_its_publisher_can_prove() {
        use fanos_field::F7;
        use fanos_pqcrypto::kem::HybridKemSecret;
        use fanos_pqcrypto::rng::SeedRng;
        use fanos_vrf::VrfSecret;

        let (epoch, beacon) = (Epoch::new(3), BeaconSeed::GENESIS);
        let sk = VrfSecret::from_seed([7u8; 32]);
        let id = b"exit-7".to_vec();
        let (_, proof) = fanos_vrf::prove_coordinate::<F7>(&sk, &id, epoch, &beacon);
        let (_, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"exit-key"));
        let record = exit_record(&public, Some(&(id.clone(), sk.public(), proof)));
        let output = fanos_vrf::coordinate_output(&sk.public(), &id, epoch, &beacon, &proof)
            .expect("the publisher's own credential yields its walk");

        let mut refused = 0;
        for i in 0..Plane::<F7>::N as usize {
            let p = Point::<F7>::at(i);
            let got = open_exit_record::<F7>(&record, p.coords(), epoch, Some(beacon));
            if fanos_vrf::probe_index_of::<F7>(&output, &p).is_some() {
                assert_eq!(
                    got.map(|k| k.encode()),
                    Some(public.encode()),
                    "a point on the publisher's own walk yields its key"
                );
            } else {
                assert!(got.is_none(), "a coordinate the publisher cannot prove is refused");
                refused += 1;
            }
        }
        // PG(2,7) holds 57 points and a line q + 1 = 8, so 49 are unreachable for this publisher — the same
        // arithmetic the capability and load directories state for their own bindings.
        assert_eq!(refused, 49, "the substitution is refused at 49 of the plane's 57 points");
    }

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
        // `relay_udp` now takes an already-resolved, already-filtered `SocketAddr` (#170) rather than a
        // name it would resolve itself — so this test hands it the echo server's address directly. Note the
        // echo server is on LOOPBACK, which `is_relayable` refuses: that is correct and is why this test
        // calls `relay_udp` rather than going through `relay_one`. The refusal itself is asserted in
        // `the_exit_refuses_every_destination_it_must_not_dial`.
        let (client, exit) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn(async move { relay_udp(exit, echo_addr).await });

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
