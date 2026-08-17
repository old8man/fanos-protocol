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
///
/// **One of these is allocated per live session, and until #254 no memory share named the product.** The
/// size itself is right — this is a raw UDP socket facing the internet, where the kernel really does
/// reassemble up to 65507 bytes, unlike the VPN's stack-fed buffer that #247 cut by 51× because the packets
/// it sized for could not exist. What was missing was the accounting, and
/// `tests::the_exit_datagram_buffers_fit_the_share_the_budget_grants_them` now holds the product under
/// `fanos_primitives::budget::EXIT_DATAGRAM_SHARE`. (Not an intra-doc link: rustdoc does not see
/// `#[cfg(test)]` items, so one would never resolve.)
pub const MAX_DATAGRAM_LEN: usize = 65535;

/// This node's share of memory for exit UDP receive buffers — **taken from
/// `fanos_primitives::budget`, not restated here** (#213's direction, #254's term).
///
/// `fanos-primitives` sits below every consumer, so the share is declared there where it can be summed with
/// its neighbours, and each owner imports it under its own name. Drift is deleted rather than detected.
pub const EXIT_DATAGRAM_MEMORY_BUDGET: usize = fanos_primitives::budget::EXIT_DATAGRAM_SHARE;

/// How many concurrent UDP sessions the exit's own share of memory buys: one
/// [`MAX_DATAGRAM_LEN`] receive buffer each.
///
/// **The exit's ceiling, derived from the exit's budget** — not a second use of a number derived for
/// something else. `fanos_diaulos::budget::MAX_SESSIONS` bounds *session queues*, a different quantity out of
/// a different share, and it happened to be the only cap in sight. Two quantities sharing one constant is
/// how a budget stops meaning anything, so this states the one that governs these buffers and
/// `tests::the_exit_datagram_buffers_fit_the_share_the_budget_grants_them` checks the two against each other.
pub const MAX_UDP_DATAGRAM_SESSIONS: usize = EXIT_DATAGRAM_MEMORY_BUDGET / MAX_DATAGRAM_LEN;

/// The product the share was never checked against, now checked by the compiler.
///
/// The division above stood alone: nothing multiplied the count back out, so a change to either factor could
/// have carried the datagram sessions past their share without a word. It is the third instance of that shape
/// found in one sweep — `MAX_PENDING`'s own doc calls it *"the assertion whose absence was the defect"*, and
/// the threshold router's two send queues were over their share by `251_829 B` for want of it. Here the
/// arithmetic happens to be safe (`256 × 65_535 = 16_776_960` against `16_777_216`), which is exactly why the
/// guard is worth adding while it costs nothing: an assertion that has never fired is the cheap half of one
/// that would have.
const _: () = assert!(
    MAX_UDP_DATAGRAM_SESSIONS * MAX_DATAGRAM_LEN <= EXIT_DATAGRAM_MEMORY_BUDGET,
    "the datagram sessions' worst case exceeds EXIT_DATAGRAM_SHARE — raise the share deliberately or lower a factor"
);

/// …and it is the **largest** count the share buys, so the number is derived rather than merely fitting —
/// without this the assertion above is satisfied by any small number and neither says the count was derived.
const _: () = assert!(
    (MAX_UDP_DATAGRAM_SESSIONS + 1) * MAX_DATAGRAM_LEN > EXIT_DATAGRAM_MEMORY_BUDGET,
    "MAX_UDP_DATAGRAM_SESSIONS is below what the share buys, so it was chosen rather than derived"
);

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

/// Why the exit declined a session — the sub-kind
/// [`Station::ExitRefused`](fanos_runtime::ports::stations::Station::ExitRefused) is counted under.
///
/// **The exit is the role whose refusals an operator is accountable for.** The traffic leaves from their
/// address and the requester is unidentifiable by construction, so "what is my exit turning away" is a
/// question only this node can answer, and it shipped answering none of it: one `warn!` on the destination
/// rule and silence everywhere else.
///
/// Named rather than aggregated because the three demand different actions. A malformed target is someone
/// speaking the wrong protocol at the service. A refused port is the operator's own allow-list working, and
/// its rate is how they learn whether the list is too narrow — or that someone is hunting for an open mail
/// relay. A refused destination has no benign reading at all: an anonymous client naming a link-local or
/// RFC 1918 address is probing for the cloud metadata endpoint from inside the anonymity set (#170).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitRefusal {
    /// The target header was unusable: absent, over `MAX_TARGET_LEN`, truncated, not UTF-8, or not
    /// `host:port`. **Not** a client that connected and said nothing — see `TargetRead::Silent`, which is
    /// deliberately not counted here, because a session ending before it began is ordinary and would bury
    /// the signal this name carries under it.
    TargetMalformed,
    /// [`ExitPolicy::allows_port`] refused the destination port.
    PortRefused,
    /// The destination is not globally routable, or resolves to nothing that is (#170).
    DestinationRefused,
}

/// `ExitRefusal::ALL` is complete, proven by the compiler. Same reasoning as [`crate::Gate`], and load-bearing
/// twice over here: the renderer resolves a tag to a name by enumerating this list, so a missing variant would
/// print as a bare integer to the one reader it exists for.
const _: () = assert!(
    ExitRefusal::ALL.len() == core::mem::variant_count::<ExitRefusal>(),
    "an ExitRefusal variant is missing from ExitRefusal::ALL, so its counter renders as an opaque number"
);

impl ExitRefusal {
    /// Every refusal reason, for a reader that enumerates rather than guesses.
    pub const ALL: &'static [Self] = &[Self::TargetMalformed, Self::PortRefused, Self::DestinationRefused];

    /// The discriminant carried in `Observation::tag`, written out for the same reason [`crate::Gate::tag`]
    /// is: variant order must not renumber an operator's counters.
    #[must_use]
    pub const fn tag(self) -> u64 {
        match self {
            Self::TargetMalformed => 0,
            Self::PortRefused => 1,
            Self::DestinationRefused => 2,
        }
    }

    /// The operator-facing name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TargetMalformed => "target_malformed",
            Self::PortRefused => "port_refused",
            Self::DestinationRefused => "destination_refused",
        }
    }
}

/// Record an exit refusal where an operator will see it — the counter carries the *reason*, the log line
/// carries the *target*.
///
/// The split is forced, not stylistic. A destination is a string an anonymous client chooses, so keying a
/// counter by it would be an attacker-minted key — the one thing the data-path plane's cardinality bound
/// forbids (`stations.rs` R2), and `record_tagged` would silently fold anything above `MAX_SKEW_TAG` anyway.
/// So the aggregate stays over a three-value enumeration and the specific target goes to the log, which is
/// where an operator investigating a *rise* in the counter will look next.
fn note_refusal(client: &Client, reason: ExitRefusal, target: &str) {
    client.record_station(
        fanos_runtime::ports::stations::Station::ExitRefused,
        Some(client.address()),
        Some(reason.tag()),
    );
    tracing::warn!(
        reason = reason.name(),
        target = %target,
        "exit refused a session; the client is unidentifiable by construction, which is the point of the \
         network and the reason the operator needs the other half"
    );
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
    // The same handle `serve` consumes, kept so each session can count its own refusals — the counters ride
    // the node's own data-path plane rather than a second surface nothing reads.
    let recorder = client.clone();
    serve(client, keypair, rng, move |stream| {
        let policy = Arc::clone(&policy);
        let recorder = recorder.clone();
        // Taken before the session runs and dropped with the future, so every way a session can end — a clean
        // close, a rejected port, an unreachable host, a cancelled task — decrements it.
        let carried = gauge.as_ref().map(LoadGauge::in_flight);
        async move {
            relay_one(stream, &policy, &recorder).await;
            drop(carried);
        }
    });
}

/// Serve one exit session: read its target, enforce the policy, then splice it — a TCP byte stream or a
/// UDP datagram relay — until either side closes.
///
/// **Every way this ends short is counted.** It shipped with one loud refusal (`#170`'s destination rule)
/// beside four silent ones, so an operator could see neither that their port policy was doing anything nor
/// that someone was probing it. `client` is the node's own handle and is what carries those counts to
/// `fanos data-path`; it is a parameter rather than an option because an observability seam a caller has to
/// remember to switch on is one production ships without.
async fn relay_one(mut stream: DuplexStream, policy: &ExitPolicy, client: &Client) {
    let target = match read_target(&mut stream).await {
        TargetRead::Got(target) => target,
        // Deliberately uncounted — see `TargetRead`. Nothing was asked for, so nothing was refused.
        TargetRead::Silent => return,
        TargetRead::Malformed => {
            note_refusal(client, ExitRefusal::TargetMalformed, "<unreadable header>");
            return;
        }
    };
    let Some((proto, host, port)) = parse_target(&target) else {
        note_refusal(client, ExitRefusal::TargetMalformed, &target);
        return;
    };
    if !policy.allows_port(port) {
        note_refusal(client, ExitRefusal::PortRefused, &target);
        return;
    }
    // **Then the destination itself** (#170). The port is only half the question, and it was the only half
    // asked: `ports = 80, 443` — the policy the setup wizard writes, commented "a web-only exit" — permits
    // `169.254.169.254:80`, the cloud metadata endpoint. Resolved once here so the connect below cannot
    // re-resolve to something else; see `resolve_relayable`.
    let Some(dest) = resolve_relayable(host, port, policy.realm).await else {
        note_refusal(client, ExitRefusal::DestinationRefused, &target);
        return;
    };
    match proto {
        Protocol::Tcp => {
            let Ok(mut tcp) = TcpStream::connect(dest).await else {
                // Not a refusal: this node agreed to relay and the destination did not answer. Ordinary one
                // at a time, and the whole diagnosis if it is the only thing this exit ever reports — an
                // operator whose upstream is gone otherwise sees a healthy node serving nobody.
                note_dial_failed(client, dest);
                return;
            };
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
        }
        Protocol::Udp => relay_udp(stream, dest, client).await,
    }
}

/// Record a destination this exit agreed to reach and could not.
fn note_dial_failed(client: &Client, dest: std::net::SocketAddr) {
    client.record_station(
        fanos_runtime::ports::stations::Station::ExitDialFailed,
        Some(client.address()),
        None,
    );
    tracing::debug!(
        %dest,
        "exit could not reach a permitted destination"
    );
}

/// Record that this node could not obtain a **local** socket — the failure that is the operator's own to fix.
///
/// `warn!` where a dial failure is `debug!`, and the asymmetry is the point: a destination that does not
/// answer is the internet's business and happens constantly, while a node that cannot open a socket is out
/// of file descriptors or ephemeral ports and will keep failing every session until someone raises
/// `LimitNOFILE`. Reporting the two at the same level would teach an operator to filter out the one that
/// matters.
fn note_socket_unavailable(client: &Client, what: &str, err: &io::Error) {
    client.record_station(
        fanos_runtime::ports::stations::Station::ExitSocketUnavailable,
        Some(client.address()),
        None,
    );
    tracing::warn!(
        operation = what,
        error = %err,
        "exit could not obtain a local socket — this node is out of descriptors or ephemeral ports, and is \
         serving no UDP session until that is fixed"
    );
}

/// Relay UDP datagrams for one exit session: bind an ephemeral socket **connected** to `(host, port)`, and
/// shuttle length-framed datagrams (`len(2 BE) ‖ payload`) between the session stream and that socket in
/// both directions until either closes. A connected socket keeps this a one-target tunnel (the UDP analog
/// of `CONNECT`) — the target sees the exit's address, never the client's. This serves DNS-over-FANOS (a
/// resolver at `udp:host:53`) and any single-destination UDP flow.
async fn relay_udp(stream: DuplexStream, dest: std::net::SocketAddr, client: &Client) {
    let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(socket) => socket,
        Err(e) => {
            note_socket_unavailable(client, "udp bind", &e);
            return;
        }
    };
    // An already-resolved, already-filtered address (#170) — never a name, which `connect` would resolve
    // again and could resolve differently.
    if let Err(e) = socket.connect(dest).await {
        // A connected UDP socket sends nothing, so this fails on a local condition — no route to that
        // family, an exhausted port table — which is why it joins the bind rather than the dial.
        note_socket_unavailable(client, "udp connect", &e);
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

/// The outcome of reading a session's target header — **three** states, because the two failures are not
/// the same event and folding them makes the interesting one unreadable.
///
/// A client that opens a session and sends nothing is ordinary: a circuit died, a proxy gave up. A client
/// that declares a 60 000-byte target, or sends bytes that are not UTF-8, is not speaking this protocol.
/// One `Option` returning `None` for both would have put the ordinary case into the counter that exists to
/// show the other, at a rate that buries it — the same three-state split #179 made for "alone on purpose"
/// versus "alone by accident".
enum TargetRead {
    /// A well-formed target header.
    Got(String),
    /// EOF before a single byte of the header — nothing was ever asked for.
    Silent,
    /// Bytes arrived and were not a target: a zero or over-`MAX_TARGET_LEN` length, a truncated body, or
    /// not UTF-8.
    Malformed,
}

/// Read the length-prefixed target header `len(2 BE) ‖ host:port` from the stream.
async fn read_target(stream: &mut DuplexStream) -> TargetRead {
    let mut len = [0u8; 2];
    // The one read whose failure is not a protocol violation: nothing has been claimed yet, so a closed
    // stream here is a session that ended before it began.
    if stream.read_exact(&mut len).await.is_err() {
        return TargetRead::Silent;
    }
    let len = usize::from(u16::from_be_bytes(len));
    if len == 0 || len > MAX_TARGET_LEN {
        return TargetRead::Malformed;
    }
    let mut buf = vec![0u8; len];
    if stream.read_exact(&mut buf).await.is_err() {
        return TargetRead::Malformed;
    }
    String::from_utf8(buf).map_or(TargetRead::Malformed, TargetRead::Got)
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
pub fn spawn_exit_publisher(
    client: Client,
    public: HybridKemPublic,
    prover: Option<CoordinateProver>,
    mut assigned: tokio::sync::watch::Receiver<crate::role_loop::Assignment>,
) -> JoinHandle<()> {
    // Supervised: this actor's death is a capability the node loses, and the counters that would
    // have shown it are written by the actor itself (#251).
    let supervised = client.clone();
    let task = tokio::spawn(async move {
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
        // **The genesis publication waits for the cell to speak, and does not skip on `NONE`.** At spawn the
        // assignment is `Assignment::NONE` — nothing decided yet, which is not the same as "not assigned" —
        // so testing it here would withhold the record of every exit until the first epoch boundary, and at
        // a 600 s period that is an exit no proxy can discover for ten minutes. `awaited` blocks until the
        // role loop's genesis assignment lands, after which the same rule as every later epoch applies.
        //
        // It is a wait and not a timeout: a node whose role loop never decides has nothing to advertise, and
        // saying so by silence is the honest answer rather than advertising an unassigned role anyway.
        while *assigned.borrow_and_update() == crate::role_loop::Assignment::NONE
            && assigned.changed().await.is_ok()
        {}
        if assigned.borrow().roles.has(fanos_core::roles::Role::Exit) {
            publish(epoch, seed, &public).await;
        }
        // Latest-state, not the lossy notification stream: an exit missing from the directory for an epoch
        // is an exit no proxy can discover for that epoch, and the stream could drop the round (#86).
        while let Some((reached, s)) = crate::next_epoch(&mut beacons, epoch).await {
            epoch = reached;
            seed = s;
            // **Withheld, not torn down — this is where the cell's assignment finally acts (audit R-H2).**
            // The node keeps running its exit: live sessions are untouched, the listener stays up, and
            // nothing is stopped. What changes is the *record*: a node the cell did not assign Exit this
            // epoch does not advertise one, so it drains gracefully as clients stop discovering it and it
            // resumes the moment the assignment includes it again.
            //
            // Read at the boundary rather than at spawn, because the assignment is a per-epoch decision and
            // a value captured once would be an offer wearing an assignment's name — which is exactly the
            // shape this closes: every activity advertisement was gated on `config.roles`, the OFFER, and
            // nothing consulted what the cell decided.
            // **Two different withholdings, and telling them apart is the whole reason for the tag.** The
            // publisher and the role loop both wake on the same beacon, so an assignment computed for an
            // earlier epoch is a race rather than a decision. Neither blocks: waiting for the loop to catch
            // up would hang this publisher on any epoch the loop legitimately declines to decide, and a
            // chosen timeout would be a number nobody derived. It publishes on a decision that includes it,
            // withholds otherwise, and says which case it was.

            // **Wait for the decision to reach this epoch, then act on it.** The publisher and the role
            // loop both wake on the same beacon and the publisher always wins the race — measured: gating on
            // `decided_for >= epoch` *without* waiting tagged every withholding on every node "stale", which
            // is a functional silence, not a decision. Waiting is what that attempt was missing.
            //
            // **And the wait is bounded by the protocol, not by a timer.** Any later assignment satisfies
            // `epoch(assignment) >= epoch`, so the loop skipping this epoch — which it may legitimately do
            // when the roster is incomplete — releases this wait at its next decision, and the record is
            // then written against a decision *newer* than the epoch it names, which is sound. The only
            // unbounded case is a loop that never decides again, and a node with no assignment has nothing
            // to advertise: silence is the honest answer there rather than a record backed by nothing.
            while assigned.borrow_and_update().epoch < epoch && assigned.changed().await.is_ok() {}
            let (decided_for, serves) = {
                let a = assigned.borrow();
                (a.epoch, a.roles.has(fanos_core::roles::Role::Exit))
            };
            if serves {
                publish(epoch, seed, &public).await;
            } else {
                let stale = u64::from(decided_for < epoch);
                client.record_station(
                    fanos_runtime::ports::stations::Station::ExitAdvertisementWithheld,
                    None,
                    Some(stale),
                );
            }
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::ExitPublisher, &supervised, task)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// **The exit's receive buffers fit the share the budget grants them (#254).**
    ///
    /// This is the join `fanos-primitives` cannot make. The share is declared there, below everything; the
    /// two factors live in `fanos-diaulos` and here; only a crate that sees all three can multiply. So the
    /// share is a *ceiling the budget grants* and this is the proof that the real cost is under it — the
    /// same arrangement `STORE_SHARE → MAX_STORE_ENTRIES` uses, and deliberately not a second copy of the
    /// product sitting in the budget module where it would drift.
    ///
    /// It fails in either direction, which is the point: raise `MAX_SESSIONS` or `MAX_DATAGRAM_LEN` and the
    /// exit outgrows its share; shrink the share and the same. Both are decisions to take against
    /// `budget::overcommit()`, which is already **109 MiB** over the recommendation.
    ///
    /// That figure has now been wrong here twice, in the same direction and for the same reason: this line
    /// copies a number the function computes. It said 61 while #254's proxy share had already taken it to
    /// 69, and 69 was passed when #294 named the threshold router's 40 MiB. Read `budget::overcommit()`;
    /// this sentence is a signpost, not the value.
    #[test]
    fn the_exit_datagram_buffers_fit_the_share_the_budget_grants_them() {
        let admitted = fanos_diaulos::budget::MAX_SESSIONS;
        assert!(
            admitted <= MAX_UDP_DATAGRAM_SESSIONS,
            "the session layer admits {admitted} sessions and this share buys receive buffers for only \
             {MAX_UDP_DATAGRAM_SESSIONS}, so {} of them would allocate past the budget — a share is not \
             advice, it is the term this node's sum is built from (#213, #254)",
            admitted - MAX_UDP_DATAGRAM_SESSIONS
        );

        // And the share is not wildly generous either. A ceiling with room for twice the sessions that can
        // exist would have the budget counting bytes no deployment will spend, which understates what is
        // left for everyone else — a budget wrong in the safe direction is still wrong.
        assert!(
            MAX_UDP_DATAGRAM_SESSIONS < 2 * admitted,
            "the share buys {MAX_UDP_DATAGRAM_SESSIONS} buffers for a layer that admits {admitted} sessions"
        );
    }

    /// One node on loopback, for the tests that need a real [`Client`] to record stations on and nothing
    /// else. A cell would be seven, and the exit's counters are entirely node-local.
    async fn spawn_one() -> fanos_quic::NodeHandle {
        fanos_quic::spawn(
            Box::new(fanos_runtime::OverlayNode::<fanos_field::F2>::new(
                Point::at(0),
                fanos_runtime::Config::default(),
            )),
            fanos_quic::Directory::new(),
        )
        .await
        .expect("spawn a node")
    }

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

    /// **Every way the exit declines is counted, distinguishably, and a session it serves is silent.**
    ///
    /// The exit shipped with one loud refusal — #170's destination rule, a `warn!` with no counter — beside
    /// four silent ones, so an operator could not tell a working port policy from a dead service, and could
    /// not see their exit being probed for the cloud metadata endpoint at all.
    ///
    /// Both halves are asserted, and the negative one is what makes the positive mean something: a counter
    /// that rises on every session says nothing about any of them. So the last case runs a *served* session
    /// end to end — bytes actually spliced through to an echo server and back — and asserts the plane did
    /// not move.
    ///
    /// The reasons are asserted **by tag**, not merely by station: folding "the port is not allowed" into
    /// "someone is naming a link-local address" is exactly the discrimination this exists to provide, and a
    /// test that only counted `exit.refused` would pass with the tags swapped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_way_the_exit_declines_is_counted_and_a_served_session_is_silent() {
        use std::time::Duration as StdDuration;

        use fanos_runtime::ports::stations::Station;
        use tokio::net::TcpListener;

        // One node, not a cell: the exit records on its own node's plane and needs no peers to do it, so a
        // cell fixture here would be measuring the harness.
        let node = spawn_one().await;
        let client = node.client();

        // Deltas, never absolutes: a live cell's own publishes share this plane, so an emptiness assertion
        // would be measuring the fixture rather than the exit.
        let count = |station: Station, tag: Option<u64>| {
            client
                .driver_stations()
                .iter()
                .filter(|o| o.station == station && (tag.is_none() || o.tag == tag))
                .map(|o| o.count)
                .sum::<u64>()
        };
        let refusals = |r: ExitRefusal| count(Station::ExitRefused, Some(r.tag()));

        // A port nobody is listening on: bound, addressed, released. The exit will resolve it (loopback is
        // dialable in the fixture realm) and the connect will be refused, which is the dial-failure case.
        let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap().local_addr().unwrap();

        // A TCP echo server, for the served session that must NOT move the plane.
        let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo.accept().await {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            }
        });

        // Drive one session against `relay_one` over an in-memory duplex, writing `header` verbatim so a
        // malformed header is expressible — `exit_send_target` would refuse to produce one.
        let session = |policy: ExitPolicy, header: Vec<u8>| {
            let client = client.clone();
            async move {
                let (mut mine, theirs) = tokio::io::duplex(64 * 1024);
                let relay = tokio::spawn(async move { relay_one(theirs, &policy, &client).await });
                if header.is_empty() {
                    drop(mine); // the client that connects and says nothing
                } else {
                    mine.write_all(&header).await.unwrap();
                    drop(mine);
                }
                let _ = tokio::time::timeout(StdDuration::from_secs(5), relay).await;
            }
        };
        // `len(2 BE) ‖ bytes`, the wire form the exit reads.
        let framed = |t: &str| {
            let mut v = u16::try_from(t.len()).unwrap().to_be_bytes().to_vec();
            v.extend_from_slice(t.as_bytes());
            v
        };
        let web = || ExitPolicy::web();
        let local = |port| ExitPolicy::also_permitting_loopback_for_tests(vec![port]);

        // 1. A client that says nothing. Ordinary — a circuit died — and deliberately NOT a refusal: it
        //    would outnumber every other reason and bury them.
        session(web(), Vec::new()).await;
        assert_eq!(count(Station::ExitRefused, None), 0, "a session that asked for nothing was refused nothing");

        // 2. A declared length of zero: bytes arrived, and they are not a target.
        session(web(), vec![0, 0]).await;
        assert_eq!(refusals(ExitRefusal::TargetMalformed), 1, "a zero-length target header is malformed");

        // 3. A header that is not `host:port` at all.
        session(web(), framed("this is not a target")).await;
        assert_eq!(refusals(ExitRefusal::TargetMalformed), 2, "and so is a target with no port");

        // 4. The operator's own allow-list. SMTP is the canonical abuse lever and the module doc names it;
        //    before this, an exit being hunted for an open mail relay looked exactly like an idle one.
        session(web(), framed("example.com:25")).await;
        assert_eq!(refusals(ExitRefusal::PortRefused), 1, "port 25 is outside the web policy");

        // 5. The #170 alarm. There is no benign reading of an anonymous client naming this address.
        session(web(), framed("169.254.169.254:80")).await;
        assert_eq!(
            refusals(ExitRefusal::DestinationRefused),
            1,
            "the cloud metadata endpoint is refused, and now says so where an operator can see it"
        );

        // 6. Permitted, resolvable, and nothing listening — this node agreed to relay and could not. A
        //    separate station because it is not a refusal, and because an exit reporting ONLY this has lost
        //    its upstream while still calling itself healthy.
        assert_eq!(count(Station::ExitDialFailed, None), 0);
        session(local(dead.port()), framed(&dead.to_string())).await;
        assert_eq!(count(Station::ExitDialFailed, None), 1, "a permitted destination that did not answer");
        assert_eq!(
            count(Station::ExitRefused, None),
            4,
            "and it is not filed as a refusal: this node did not decline anything"
        );

        // 7. **The negative half.** A session that is actually served, bytes spliced both ways, must leave
        //    the plane exactly where it was — otherwise every count above is just "a session happened".
        let before = client.driver_stations();
        let (mut mine, theirs) = tokio::io::duplex(64 * 1024);
        let (policy, recorder) = (local(echo_addr.port()), client.clone());
        let relay = tokio::spawn(async move { relay_one(theirs, &policy, &recorder).await });
        mine.write_all(&framed(&echo_addr.to_string())).await.unwrap();
        mine.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        tokio::time::timeout(StdDuration::from_secs(5), mine.read_exact(&mut back))
            .await
            .expect("the splice must carry bytes to the echo server and back")
            .expect("four bytes come back");
        assert_eq!(&back, b"ping", "the session was really served, not merely accepted");
        drop(mine);
        let _ = tokio::time::timeout(StdDuration::from_secs(5), relay).await;
        assert_eq!(client.driver_stations(), before, "a served session moves no station at all");
        node.shutdown();
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
        let node = spawn_one().await;
        let recorder = node.client();
        let (client, exit) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn(async move { relay_udp(exit, echo_addr, &recorder).await });

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
