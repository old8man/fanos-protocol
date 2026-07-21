//! The QUIC driver: the second realization of the sans-I/O environment ports.
//!
//! [`spawn`] wires one [`Engine`] to a real [`quinn`] endpoint. It never touches engine internals
//! — it only feeds the engine [`Input`]s and performs the [`Effect`]s it returns, the same
//! contract the simulator honours. Three cheap actors serialize the work:
//!
//! * the **engine actor** owns the `Box<dyn Engine>` and is the *only* task that touches it, so no
//!   locks are needed around engine state; it drains one input at a time and dispatches effects;
//! * the **transport loop** turns [`Effect::Send`] into a QUIC uni-stream, dialing and caching one
//!   connection per peer;
//! * the **accept loop** receives inbound connections and streams, tagging each frame with the
//!   peer coordinate learned from the connection HELLO.
//!
//! The clock is the one real-time seam: a driver *may* read the wall clock (the engine never can),
//! so virtual [`Instant`]s here are elapsed nanoseconds since the node started.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Instant as StdInstant;

use quinn::{Connection, Endpoint};
use tokio::sync::{Semaphore, broadcast, mpsc, oneshot};

use fanos_field::Field;
use fanos_geometry::{Point, TRIPLE_WIRE_LEN, Triple, decode_triple, encode_triple};
use fanos_primitives::{BeaconSeed, Epoch, storage_digest};
use fanos_proteus::ProteusShaper;
use fanos_runtime::{Command, Effect, Engine, Input, Instant, Notification, TimerToken};
use fanos_wire::capability::Capabilities;
use fanos_wire::error::encode_error;
use fanos_wire::{FrameType, ProtocolError, decode_frame, encode_frame};
use quinn::{ClientConfig, ServerConfig};

use crate::directory::Directory;
use crate::reflexive::{ReflexiveAddr, decode_addr, encode_addr};
use crate::identity::{
    HelloResult, hello_bytes, peer_cert_der, verifiable_coordinate, verify_hello,
};
use crate::tls::{NodeCredentials, TlsError, node_configs, node_configs_mutual_from};

/// Production transport tuning: a keep-alive so idle overlay links survive NAT/firewall timeouts,
/// and a bounded idle timeout so a dead peer's connection is reaped rather than lingering.
fn tuned_transport() -> Arc<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();
    if let Ok(idle) = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)) {
        tc.max_idle_timeout(Some(idle));
    }
    tc.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    Arc::new(tc)
}

/// An optional PROTEUS transport shaper, shared across a node's connections. When present, every
/// frame (including the identity HELLO) is polymorph-obfuscated on the wire (spec §13.2). Behind an
/// `RwLock` so the [`reshuffle_loop`] can **rotate** the shape when the beacon advances the epoch (§13.4,
/// V22 — the moving-target defence): sends take a read lock (shared, uncontended), the once-per-epoch
/// rotation a brief write lock. The inner `outbound`/`inbound` are `&self` (interior-mutable packet
/// counter), so concurrent sends never serialize on each other.
type Shaper = Option<Arc<RwLock<ProteusShaper>>>;

/// A self-certifying node's authenticated-identity handling (VRF-coordinate mode): the HELLO it
/// announces on a fresh connection — its negotiation parameters and `epoch ‖ coordinate ‖
/// proof-of-coordinate` (spec §7.3/§7.4) — and a verifier that checks a peer's HELLO against the
/// peer's authenticated certificate AND negotiates the session, yielding either the agreed
/// parameters or a protocol-incompatibility reason. Both are needed because a VRF coordinate is not
/// a function of the certificate alone: each side proves its coordinate and verifies the other's.
/// Verifies a peer's HELLO against its authenticated certificate and this node's own capabilities:
/// `(peer_cert_der, peer_hello) →` the negotiation outcome, or `None` to silently reject (bad proof).
type HelloVerifier = Arc<dyn Fn(&[u8], &[u8]) -> Option<HelloResult> + Send + Sync>;

#[derive(Clone)]
struct SelfCert {
    /// This node's own HELLO (its proof-of-coordinate for the current epoch). Behind a lock because the
    /// per-epoch reshuffle (`reshuffle_loop`, #102/L3) rewrites it when the beacon advances — every new
    /// connection then proves the node's *current* coordinate, not a stale genesis one. Read-cloned per
    /// connection (an `Arc` swap, no copy under the lock).
    hello: Arc<RwLock<Arc<Vec<u8>>>>,
    verify: HelloVerifier,
}

/// The identity mode. `None` ⇒ HELLO + directory-trust (unauthenticated coordinate); `Some(_)` ⇒
/// self-certifying, exchanging + verifying VRF proof-of-coordinate HELLOs.
type Identity = Option<SelfCert>;

/// Shape an outbound frame for the wire (identity when no shaper is configured). A poisoned lock (a panic
/// during a rotation) recovers the guard rather than fall back to plaintext — never leak an unshaped frame.
fn shape_out(shaper: &Shaper, frame: &[u8]) -> Vec<u8> {
    match shaper {
        Some(s) => s.read().unwrap_or_else(PoisonError::into_inner).outbound(frame),
        None => frame.to_vec(),
    }
}

/// Recover an inbound frame from the wire, or `None` if it wasn't shaped by our secret+epoch.
fn shape_in(shaper: &Shaper, wire: Vec<u8>) -> Option<Vec<u8>> {
    match shaper {
        Some(s) => s.read().unwrap_or_else(PoisonError::into_inner).inbound(&wire),
        None => Some(wire),
    }
}

/// Bytes of a HELLO: three little-endian `u32`s (a projective coordinate).
const HELLO_LEN: usize = TRIPLE_WIRE_LEN;
/// Per-frame receive cap. Onion/Tessera frames are far smaller; this only bounds abuse.
const MAX_FRAME: usize = 1 << 20;
/// Cap on **concurrent inbound connection-handler tasks** (audit C3): each accepted connection spawns a
/// task (HELLO exchange, then frame reads), so without a bound a peer opening connections in a loop grows
/// the task/handshake count without limit. The accept loop takes a permit per connection and holds it for
/// the task's life, so once this many are in flight, new accepts back-pressure (QUIC queues/rejects) until
/// one finishes. Generous next to a cell's `N-1` real neighbours; it only bounds abuse.
const MAX_INBOUND_CONNECTIONS: usize = 512;

/// Per-source-IP inbound cap (audit A6, #69). A single host can hold at most this many of the
/// [`MAX_INBOUND_CONNECTIONS`] slots, so monopolizing the accept path — a slowloris / connection-pinning
/// DoS — takes many distinct source IPs, which QUIC's address-validated handshake makes hard to spoof,
/// while still admitting the many nodes that can sit behind one shared NAT (a source may hold up to
/// `512/32 = 1/16` of the slots). The global cap alone is not enough: without this, one host mints 512
/// valid connections and pins every slot.
const MAX_INBOUND_PER_SOURCE: usize = 32;

/// How long a newly-accepted connection has to *establish and identify itself* (QUIC handshake + HELLO)
/// before it is dropped (audit A6, #69). A legitimate peer finishes in a few round trips; a connection
/// that stalls mid-handshake — holding a slot without ever proving a coordinate — is reclaimed rather than
/// pinned indefinitely. This is deliberately a **handshake** deadline, not an idle deadline on an
/// established link: an established connection may stay legitimately silent for a long time (it backs the
/// #119 reverse-reachability path), so it must never be reclaimed for inactivity.
const HELLO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// The bound on the engine's inbound `Input` queue. The per-connection frame readers feed this channel and
/// **await** when it is full, so a peer flooding frames is back-pressured through QUIC's own flow control
/// rather than growing this queue without limit (audit C2). The timer/command producers share it; commands
/// use a non-blocking `try_send` (dropped under a sustained flood, the caller sees `false`), timers await.
/// The outbound/notification channels stay unbounded — they are bounded *transitively*, since the engine
/// can only produce effects as fast as it drains this now-bounded input.
const INPUT_CAP: usize = 1024;

/// A coordinate → live connection cache. A `Connection` is a cheap handle (an `Arc` inside).
type ConnMap = Arc<Mutex<HashMap<Triple, Connection>>>;

/// Shared reflexive-address discovery state — peers' observations of this node's public address (#119).
type Reflexive = Arc<Mutex<ReflexiveAddr>>;

/// This node's record of the public source address each peer was observed dialing in from — the raw
/// material a **hub** needs to broker a hole-punch (#119). A node that accepts a connection sees the
/// dialer's NAT-mapped public endpoint (`conn.remote_address()`); remembering it, keyed by the dialer's
/// proven coordinate, lets this node later tell a third party where to reach that peer.
type PeerAddrs = Arc<Mutex<HashMap<Triple, SocketAddr>>>;

/// How many distinct peers must independently report the same observed address before this node trusts
/// it as its public address (see [`ReflexiveAddr`]). Two, so one lying/misconfigured peer cannot move it.
const REFLEXIVE_QUORUM: usize = 2;

/// An internal request from the engine actor to the transport loop.
struct SendRequest {
    to: Triple,
    frame: Vec<u8>,
}

/// The transport's shared context: everything the send and receive paths need besides the destination.
#[derive(Clone)]
struct Transport {
    endpoint: Endpoint,
    conns: ConnMap,
    input_tx: mpsc::Sender<Input>,
    shaper: Shaper,
    identity: Identity,
    me: Triple,
    reflexive: Reflexive,
    /// Public addresses this node has observed peers dialing in from — the hub's hole-punch table (#119).
    peer_addrs: PeerAddrs,
    /// The address book, so the receive path can register a peer's punched address and the send path can
    /// resolve a destination coordinate to a socket.
    directory: Directory,
}

/// How long a store `get`/`put` waits for its reply before giving up. A store request whose
/// responsible node is unreachable (down, or absent from a sparse cell) must fail, not hang the
/// caller's task forever (audit C1).
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long to wait for a dial to complete before abandoning it (#129). A peer that has gone away must
/// fail fast so it cannot stall the send loop behind it — the erasure store fans reads to every cell
/// point and a dead point's dial would otherwise block the live ones. A reachable peer's QUIC handshake
/// completes in a small fraction of this even under load.
const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// A running QUIC-backed node: the handle an application uses to drive it and hear from it.
///
/// Dropping the handle (or calling [`NodeHandle::shutdown`]) closes the endpoint and lets the
/// actors wind down.
pub struct NodeHandle {
    addr: Triple,
    local_addr: SocketAddr,
    input_tx: mpsc::Sender<Input>,
    ctrl_tx: mpsc::UnboundedSender<Control>,
    events_tx: broadcast::Sender<Notification>,
    events_rx: broadcast::Receiver<Notification>,
    endpoint: Endpoint,
    reflexive: Reflexive,
}

impl NodeHandle {
    /// This node's overlay coordinate.
    #[must_use]
    pub fn address(&self) -> Triple {
        self.addr
    }

    /// The UDP socket address the node is actually bound to (its directory entry).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// This node's **public (reflexive) address** as learned from peers — the address remote peers
    /// observe this node's connections arriving from, once at least [`REFLEXIVE_QUORUM`] of them agree
    /// (NAT traversal #119). `None` until enough peers have reported. Unlike [`local_addr`](Self::local_addr)
    /// (the possibly-private/wildcard bind), this is what the node should advertise to be reachable.
    #[must_use]
    pub fn public_addr(&self) -> Option<SocketAddr> {
        self.reflexive.lock().map_or(None, |r| r.confirmed())
    }

    /// Inject an application command (delivered to the engine as `Input::Command`). Returns
    /// `false` if the engine actor has stopped.
    pub fn command(&self, cmd: Command) -> bool {
        self.input_tx.try_send(Input::Command(cmd)).is_ok()
    }

    /// Request a NAT hole-punch to `target`, brokered by `via` (#119) — a hub both this node and `target`
    /// have a live connection to. Emits a `ConnectReq`; the hub, which observed each party's public
    /// address, replies to both ends with a `PunchTo`, and the two nodes dial each other simultaneously so
    /// their NAT mappings open. Once it succeeds the target's address is in this node's directory, so
    /// subsequent overlay traffic routes to it directly without the hub. Returns `false` if the engine
    /// actor has stopped. Best-effort: reachability then depends on the NATs actually admitting the punch.
    pub fn hole_punch(&self, via: Triple, target: Triple) -> bool {
        let mut frame = Vec::new();
        encode_frame(FrameType::ConnectReq.code(), &encode_triple(target), &mut frame);
        self.command(Command::Emit { to: via, frame })
    }

    /// Await the next application notification the engine emits, or `None` once it stops. Backed by a
    /// broadcast fan-out, so many observers can each read the full stream; a reader that falls behind
    /// skips the missed items rather than blocking the engine.
    pub async fn next_notification(&mut self) -> Option<Notification> {
        loop {
            match self.events_rx.recv().await {
                Ok(note) => return Some(note),
                Err(broadcast::error::RecvError::Lagged(_)) => {} // skip missed items, keep reading
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// A cloneable, **correlated** client for this node — the concurrency-safe surface. Many tasks
    /// share it to issue `get`/`put` and await *only their own* replies (correlated by the storage
    /// digest the engine echoes), send fire-and-forget commands, or `subscribe` to the event stream —
    /// none stealing another's notifications. A proxy or resolver uses this instead of the single
    /// `next_notification` stream.
    #[must_use]
    pub fn client(&self) -> Client {
        Client {
            addr: self.addr,
            input_tx: self.input_tx.clone(),
            ctrl_tx: self.ctrl_tx.clone(),
            events_tx: self.events_tx.clone(),
        }
    }

    /// Close the QUIC endpoint and stop serving. Idempotent.
    pub fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }

    /// A fresh receiver on the engine's notification broadcast — for an internal driver task (e.g. the
    /// per-epoch reshuffle loop) that follows the event stream without stealing from `next_notification`.
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Notification> {
        self.events_tx.subscribe()
    }
}

/// Pending `get` waiters, keyed by the storage digest the engine echoes (a Vec coalesces concurrent
/// gets of the same key onto one reply). Each carries its registration time so the router can evict a
/// waiter whose reply never comes, rather than leak its `oneshot::Sender` forever (audit C1).
type GetWaiters = HashMap<[u8; 32], Vec<(std::time::Instant, oneshot::Sender<Option<Vec<u8>>>)>>;
/// Pending `put` waiters, keyed by the storage digest — with the same registration-time eviction (C1).
/// The leak this closes is real: the engine emits `Stored` only on a local hit or a remote `Ack`, so a
/// put whose responsible node is down/absent/malicious never resolves, and without eviction its entry
/// (and `oneshot::Sender`) would live forever — repeated puts to unreachable keys grow the map unbounded.
type PutWaiters = HashMap<[u8; 32], Vec<(std::time::Instant, oneshot::Sender<()>)>>;

/// A control message from a [`Client`] to the router: register a waiter for a content-addressed
/// reply, keyed by the storage digest the engine will echo back.
enum Control {
    Get {
        digest: [u8; 32],
        reply: oneshot::Sender<Option<Vec<u8>>>,
    },
    Put {
        digest: [u8; 32],
        reply: oneshot::Sender<()>,
    },
}

/// A cloneable, correlated client for a node. Many tasks share it to issue content-addressed
/// requests (`get`/`put`) that await *only their own* answer — correlated by the storage digest the
/// engine echoes, so concurrent requests never cross — send fire-and-forget commands, or subscribe to
/// the notification stream. This is the concurrency-safe surface a SOCKS5 proxy or a `.fanos` resolver
/// builds on: the single-consumer `next_notification` bottleneck is gone.
#[derive(Clone)]
pub struct Client {
    addr: Triple,
    input_tx: mpsc::Sender<Input>,
    ctrl_tx: mpsc::UnboundedSender<Control>,
    events_tx: broadcast::Sender<Notification>,
}

impl Client {
    /// This node's overlay coordinate.
    #[must_use]
    pub fn address(&self) -> Triple {
        self.addr
    }

    /// Inject a fire-and-forget command (`Input::Command`). `false` once the engine has stopped.
    pub fn command(&self, cmd: Command) -> bool {
        self.input_tx.try_send(Input::Command(cmd)).is_ok()
    }

    /// Retrieve `key` from the L4 store, awaiting *this* request's answer (correlated by the storage
    /// digest, so concurrent `get`s never cross). `None` if no value is stored or the node stopped.
    pub async fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        let digest = storage_digest(&key);
        let (reply, rx) = oneshot::channel();
        // Register the waiter BEFORE issuing the Get, so a fast reply can never be missed.
        if self.ctrl_tx.send(Control::Get { digest, reply }).is_err() {
            return None;
        }
        if self
            .input_tx
            .try_send(Input::Command(Command::Get { key }))
            .is_err()
        {
            return None;
        }
        // Bound the wait: a key whose responsible node is unreachable (or absent from a sparse cell)
        // must resolve to `None`, never hang the caller forever (audit C1).
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(value)) => value,
            _ => None,
        }
    }

    /// Store `value` under `key`, awaiting the responsible node's acknowledgement. `false` if the
    /// node stopped before acking.
    pub async fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        let digest = storage_digest(&key);
        let (reply, rx) = oneshot::channel();
        if self.ctrl_tx.send(Control::Put { digest, reply }).is_err() {
            return false;
        }
        if self
            .input_tx
            .try_send(Input::Command(Command::Put { key, value }))
            .is_err()
        {
            return false;
        }
        // Bound the wait for the responsible node's ack; a timeout is reported as a failed store, not a
        // hang (audit C1).
        matches!(tokio::time::timeout(REQUEST_TIMEOUT, rx).await, Ok(Ok(())))
    }

    /// Subscribe to the full notification stream (Delivered, PeerDown, Verdict, healing events, …).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Notification> {
        self.events_tx.subscribe()
    }
}

/// The router actor: sole owner of the engine's notification stream. It resolves content-addressed
/// request/response correlation (many concurrent `get`/`put` each awaiting their own digest) and fans
/// every notification out to subscribers — so the single-consumer bottleneck is gone and no observer
/// steals another's reply. Single-writer-by-message: it alone touches the registry, mutated only via
/// `Control` (mirroring the engine actor's lock-free discipline).
async fn router_loop(
    mut notify_rx: mpsc::UnboundedReceiver<Notification>,
    mut ctrl_rx: mpsc::UnboundedReceiver<Control>,
    events_tx: broadcast::Sender<Notification>,
) {
    let mut gets: GetWaiters = HashMap::new();
    let mut puts: PutWaiters = HashMap::new();
    // Periodic waiter-map eviction (audit C1): a `get` is self-cleaning (the engine always concludes a
    // `Retrieved` via read-repair exhaustion), but a `put` to a node that never `Ack`s never resolves — so
    // sweep both maps, dropping any waiter whose receiver the client already abandoned (`is_closed`, the
    // common case once its `REQUEST_TIMEOUT` await fired) or that has outlived `REQUEST_TIMEOUT` (the reply
    // is not coming). Dropping the `oneshot::Sender` resolves the client to `None`/`false`. The map thus
    // stays bounded even under a flood of puts to unreachable keys.
    let mut sweep = tokio::time::interval(REQUEST_TIMEOUT);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            note = notify_rx.recv() => {
                let Some(note) = note else { break };
                match &note {
                    Notification::Retrieved { key, value } => {
                        if let Some(waiters) = gets.remove(key) {
                            for (_, tx) in waiters {
                                let _ = tx.send(value.clone());
                            }
                        }
                    }
                    Notification::Stored(key) => {
                        if let Some(waiters) = puts.remove(key) {
                            for (_, tx) in waiters {
                                let _ = tx.send(());
                            }
                        }
                    }
                    _ => {}
                }
                // Fan every notification out to subscribers (Err only if no receivers — ignored).
                let _ = events_tx.send(note);
            }
            ctrl = ctrl_rx.recv() => {
                let Some(ctrl) = ctrl else { break };
                let now = std::time::Instant::now();
                match ctrl {
                    Control::Get { digest, reply } => gets.entry(digest).or_default().push((now, reply)),
                    Control::Put { digest, reply } => puts.entry(digest).or_default().push((now, reply)),
                }
            }
            _ = sweep.tick() => {
                let now = std::time::Instant::now();
                evict_stale(&mut gets, now);
                evict_stale(&mut puts, now);
            }
        }
    }
}

/// Drop request waiters whose reply will never come (audit C1): the client already abandoned the receiver
/// (`is_closed` — the common case once its `REQUEST_TIMEOUT` await fired), or the waiter has outlived
/// `REQUEST_TIMEOUT` so no correlated notification is coming. Dropping the `oneshot::Sender` resolves any
/// still-live client to `None`/`false`; empty digest buckets are removed. Keeps the correlation maps
/// bounded regardless of how many requests target unreachable keys.
fn evict_stale<T>(
    map: &mut HashMap<[u8; 32], Vec<(std::time::Instant, oneshot::Sender<T>)>>,
    now: std::time::Instant,
) {
    map.retain(|_, waiters| {
        waiters.retain(|(at, tx)| !tx.is_closed() && now.duration_since(*at) < REQUEST_TIMEOUT);
        !waiters.is_empty()
    });
}

/// Errors that can occur bringing a node up.
#[derive(Debug)]
pub enum QuicError {
    /// TLS/QUIC configuration failed.
    Tls(TlsError),
    /// Binding the UDP socket or reading its address failed.
    Io(std::io::Error),
    /// Rejection sampling could not mint self-certifying credentials for a requested coordinate
    /// within the grind limit (see [`harness::credentials_for_point`](crate::credentials_for_point)).
    /// Impossible for a real Fano cell; signals an unreachable target or a mis-set limit.
    Grind,
}

impl core::fmt::Display for QuicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tls(e) => write!(f, "TLS setup: {e}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Grind => write!(
                f,
                "could not grind credentials for the requested coordinate"
            ),
        }
    }
}

impl std::error::Error for QuicError {}

impl From<TlsError> for QuicError {
    fn from(e: TlsError) -> Self {
        Self::Tls(e)
    }
}
impl From<std::io::Error> for QuicError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Bring up a node: bind a QUIC endpoint on loopback, register it in `directory`, and spawn the
/// three driver actors around `engine`. Returns a handle to command it and read its notifications.
///
/// The engine is moved in and thereafter touched only by its own actor task.
pub async fn spawn(
    engine: Box<dyn Engine + Send>,
    directory: Directory,
) -> Result<NodeHandle, QuicError> {
    let (server, client) = node_configs()?;
    spawn_inner(
        engine,
        directory,
        None,
        None,
        server,
        client,
        default_bind(),
    )
}

/// The default bind address for the test/loopback wrappers: an ephemeral port on localhost.
fn default_bind() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

/// Bring up a **self-certifying** node: its overlay coordinate is `MapToPoint(H(cert))`, bound to
/// its mutual-TLS certificate, so a peer authenticates the coordinate from the handshake — no
/// directory-trust for identity (the directory serves only address resolution). The engine is built
/// at the cert-derived coordinate by `make_engine`. Advertises the conservative
/// [`Capabilities::CORE`]-only baseline (spec §7.4): this generic entry point has no visibility
/// into which optional modules the caller wires up alongside the core engine, so it never overclaims
/// a feature it might not actually serve. A caller that knows its full module mix should use
/// [`spawn_self_certifying_with_capabilities`] instead.
pub async fn spawn_self_certifying<F: Field + 'static>(
    make_engine: impl FnOnce(Point<F>) -> Box<dyn Engine + Send>,
    directory: Directory,
) -> Result<NodeHandle, QuicError> {
    let creds = NodeCredentials::generate()?;
    let (server, client, _cert) = node_configs_mutual_from(&creds)?;
    self_certifying_inner::<F, _>(
        server,
        client,
        &creds,
        make_engine,
        directory,
        default_bind(),
        Capabilities::CORE,
        None,
    )
}

/// Like [`spawn_self_certifying`], but advertises an explicit capability set (spec §7.4) instead of
/// the conservative [`Capabilities::CORE`]-only default — for a deployment (or test) that knows
/// which optional feature families it actually serves alongside the core engine, so a peer can
/// negotiate the real intersection rather than always falling back to the baseline.
pub async fn spawn_self_certifying_with_capabilities<F: Field + 'static>(
    make_engine: impl FnOnce(Point<F>) -> Box<dyn Engine + Send>,
    directory: Directory,
    capabilities: Capabilities,
) -> Result<NodeHandle, QuicError> {
    let creds = NodeCredentials::generate()?;
    let (server, client, _cert) = node_configs_mutual_from(&creds)?;
    self_certifying_inner::<F, _>(
        server,
        client,
        &creds,
        make_engine,
        directory,
        default_bind(),
        capabilities,
        None,
    )
}

/// Like [`spawn_self_certifying`], but reuses persisted [`NodeCredentials`] so the node keeps the
/// **same coordinate across restarts** — a durable overlay identity.
pub async fn spawn_self_certifying_persistent<F: Field + 'static>(
    credentials: &NodeCredentials,
    make_engine: impl FnOnce(Point<F>) -> Box<dyn Engine + Send>,
    directory: Directory,
) -> Result<NodeHandle, QuicError> {
    let (server, client, _cert) = node_configs_mutual_from(credentials)?;
    self_certifying_inner::<F, _>(
        server,
        client,
        credentials,
        make_engine,
        directory,
        default_bind(),
        Capabilities::CORE,
        None,
    )
}

/// Like [`spawn_self_certifying_persistent`], but binds the QUIC endpoint to an explicit address
/// (e.g. `0.0.0.0:9000` for a publicly reachable node) instead of an ephemeral localhost port. This
/// is the production entry point a node binary uses; the coordinate stays cert-derived and stable.
/// `community_secret` enables PROTEUS (§13.4): when `Some`, every frame is polymorph-shaped with that shared
/// secret and the shape rotates each epoch; `None` is plaintext QUIC. Peers must share the secret to interop.
pub async fn spawn_self_certifying_persistent_on<F: Field + 'static>(
    bind: SocketAddr,
    credentials: &NodeCredentials,
    make_engine: impl FnOnce(Point<F>) -> Box<dyn Engine + Send>,
    directory: Directory,
    community_secret: Option<Vec<u8>>,
) -> Result<NodeHandle, QuicError> {
    let (server, client, _cert) = node_configs_mutual_from(credentials)?;
    self_certifying_inner::<F, _>(
        server,
        client,
        credentials,
        make_engine,
        directory,
        bind,
        Capabilities::CORE,
        community_secret,
    )
}

#[allow(clippy::too_many_arguments)]
fn self_certifying_inner<F: Field + 'static, M>(
    server: ServerConfig,
    client: ClientConfig,
    creds: &NodeCredentials,
    make_engine: M,
    directory: Directory,
    bind: SocketAddr,
    capabilities: Capabilities,
    community_secret: Option<Vec<u8>>,
) -> Result<NodeHandle, QuicError>
where
    M: FnOnce(Point<F>) -> Box<dyn Engine + Send>,
{
    // PROTEUS enablement (§13.4): with a community secret, wrap every frame in the beacon-rotating polymorph
    // shape so the transport carries no static FANOS signature and the shape moves each epoch. The shaper
    // starts at the genesis epoch and the `reshuffle_loop` rotates it as the beacon advances (below).
    let shaper: Shaper = community_secret
        .map(|secret| Arc::new(RwLock::new(ProteusShaper::new(secret, Epoch::ZERO))));
    // The node's verifiable coordinate for the genesis epoch: MapToPoint(VRF(vrf_sk, cert‖0‖GENESIS)),
    // with the proof it announces so peers can verify it (spec §L0/§7.3).
    let (coord, proof) = verifiable_coordinate::<F>(creds, Epoch::ZERO, &BeaconSeed::GENESIS);
    let engine = make_engine(coord);
    // The self-certifying identity is now LIVE across epochs (Level B, #102): the HELLO and the beacon the
    // verifier checks peers against both sit behind locks the `reshuffle_loop` rewrites when the beacon
    // advances. Cold-start values are the genesis coordinate; a node with no beacon simply never reshuffles.
    let hello_cell = Arc::new(RwLock::new(Arc::new(hello_bytes::<F>(
        Epoch::ZERO,
        coord.coords(),
        &proof,
        capabilities,
    ))));
    let beacon_cell = Arc::new(RwLock::new(BeaconSeed::GENESIS));
    let verify_beacon = beacon_cell.clone();
    let identity: Identity = Some(SelfCert {
        hello: hello_cell.clone(),
        verify: Arc::new(move |peer_cert: &[u8], peer_hello: &[u8]| {
            let beacon = *verify_beacon.read().ok()?; // poisoned ⇒ reject (None), never verify on a stale seed
            verify_hello::<F>(peer_cert, peer_hello, &beacon, capabilities)
        }),
    });
    let dir_for_reshuffle = directory.clone();
    let handle = spawn_inner(engine, directory, shaper.clone(), identity, server, client, bind)?;
    // Drive the per-epoch coordinate reshuffle off the live beacon (spec §L3, §3.2): on each `BeaconReady`
    // the loop re-derives this node's VRF coordinate for the new epoch, re-seats the engine, rebinds its
    // directory coordinate, and publishes the fresh HELLO + beacon so subsequent connections prove/verify
    // the current placement.
    let local_addr = handle.local_addr();
    tokio::spawn(reshuffle_loop::<F>(
        creds.clone(),
        capabilities,
        coord.coords(),
        local_addr,
        dir_for_reshuffle,
        hello_cell,
        beacon_cell,
        shaper,
        handle.subscribe(),
        handle.client(),
    ));
    Ok(handle)
}

/// The per-epoch coordinate reshuffle driver (spec §L3 "epoch reshuffle", §3.2; task #102). It follows the
/// engine's notification stream and, on each `BeaconReady { epoch, seed }`, re-derives this node's
/// verifiable coordinate `MapToPoint(VRF(vrf_sk, cert ‖ epoch ‖ seed))`, re-seats the overlay engine to it
/// (`Command::Reseat`), and republishes the node's HELLO + the beacon the peer-verifier checks against — so
/// the unpredictable placement rotation that defends against eclipse / path-prediction (the load-bearing
/// defence on the grindable q=2 base cell) is live end to end. Exits when the engine stops.
#[allow(clippy::too_many_arguments)]
async fn reshuffle_loop<F: Field>(
    creds: NodeCredentials,
    capabilities: Capabilities,
    genesis_coord: Triple,
    local_addr: SocketAddr,
    directory: Directory,
    hello: Arc<RwLock<Arc<Vec<u8>>>>,
    beacon: Arc<RwLock<BeaconSeed>>,
    shaper: Shaper,
    mut events: broadcast::Receiver<Notification>,
    client: Client,
) {
    let mut current = genesis_coord;
    loop {
        match events.recv().await {
            Ok(Notification::BeaconReady { epoch, seed }) => {
                // Rotate the PROTEUS wire shape to the new epoch FIRST (§13.4 moving target): the polymorphism
                // moves every epoch so a censor's classifier trained on the old shape is stale. Independent of
                // whether the VRF coordinate also moves below — the shape rotates on every beacon round. A
                // poisoned lock recovers the guard (the shape is still consistent) rather than skip the rotation.
                if let Some(s) = &shaper {
                    s.write()
                        .unwrap_or_else(PoisonError::into_inner)
                        .rotate(epoch);
                }
                let seed = BeaconSeed::new(seed);
                let (coord, proof) = verifiable_coordinate::<F>(&creds, epoch, &seed);
                let new_coord = coord.coords();
                if new_coord == current {
                    continue; // this epoch's VRF landed on the same point — nothing to move
                }
                // Re-seat the engine at the new coordinate; a dead engine (`false`) ends the loop.
                if !client.command(Command::Reseat { coord: new_coord }) {
                    break;
                }
                // Rebind the transport directory: bind the new point to our (unchanged) address and clear
                // the vacated one, so peers dial us at our current coordinate and no stale binding lingers.
                directory.insert(new_coord, local_addr);
                directory.remove(current);
                current = new_coord;
                // Publish the new HELLO + beacon so subsequent handshakes prove/verify at this epoch. Write
                // the beacon FIRST: a connection accepted between the two writes then verifies a peer against
                // the newer beacon while announcing the older coordinate — harmless (the peer re-syncs on an
                // epoch mismatch, §7.3), and never the reverse (verifying against a stale beacon). A poisoned
                // lock skips this rotation's publish; the next `BeaconReady` retries.
                if let Ok(mut b) = beacon.write() {
                    *b = seed;
                }
                if let Ok(mut h) = hello.write() {
                    *h = Arc::new(hello_bytes::<F>(
                        epoch,
                        coord.coords(),
                        &proof,
                        capabilities,
                    ));
                }
            }
            // Some other notification, or we fell behind the broadcast — keep following either way.
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => break, // engine stopped
        }
    }
}

/// Like [`spawn`], but every frame on the wire is PROTEUS-shaped with the shared `community_secret`
/// for `epoch` (spec §13.2): the transport carries no static FANOS signature, and a peer without
/// the secret cannot produce frames this node will accept. The engine is unchanged — shaping lives
/// entirely in the driver, below the sans-I/O boundary.
pub async fn spawn_shaped(
    engine: Box<dyn Engine + Send>,
    directory: Directory,
    community_secret: Vec<u8>,
    epoch: Epoch,
) -> Result<NodeHandle, QuicError> {
    let shaper = Arc::new(RwLock::new(ProteusShaper::new(community_secret, epoch)));
    let (server, client) = node_configs()?;
    spawn_inner(
        engine,
        directory,
        Some(shaper),
        None,
        server,
        client,
        default_bind(),
    )
}

/// Bind the endpoint and spawn the driver actors. Synchronous (only sets up channels and
/// `tokio::spawn`s tasks); the public wrappers stay `async` for API stability.
fn spawn_inner(
    engine: Box<dyn Engine + Send>,
    directory: Directory,
    shaper: Shaper,
    identity: Identity,
    mut server_cfg: ServerConfig,
    mut client_cfg: ClientConfig,
    bind: SocketAddr,
) -> Result<NodeHandle, QuicError> {
    let addr = engine.address();

    // Apply production transport tuning (keep-alive + idle timeout) to both directions.
    server_cfg.transport_config(tuned_transport());
    client_cfg.transport_config(tuned_transport());

    let mut endpoint = Endpoint::server(server_cfg, bind)?;
    endpoint.set_default_client_config(client_cfg);
    let local_addr = endpoint.local_addr()?;
    directory.insert(addr, local_addr);
    tracing::debug!(?addr, %local_addr, self_certifying = identity.is_some(), "fanos-quic node up");

    let (input_tx, input_rx) = mpsc::channel::<Input>(INPUT_CAP);
    let (send_tx, send_rx) = mpsc::unbounded_channel::<SendRequest>();
    let (notify_tx, notify_rx) = mpsc::unbounded_channel::<Notification>();
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<Control>();
    let (events_tx, events_rx) = broadcast::channel::<Notification>(4096);
    let conns: ConnMap = Arc::new(Mutex::new(HashMap::new()));
    let reflexive: Reflexive = Arc::new(Mutex::new(ReflexiveAddr::new(REFLEXIVE_QUORUM)));
    let peer_addrs: PeerAddrs = Arc::new(Mutex::new(HashMap::new()));

    // One shared context object drives both the accept/receive path and the send path.
    let transport = Transport {
        endpoint: endpoint.clone(),
        conns,
        input_tx: input_tx.clone(),
        shaper,
        identity,
        me: addr,
        reflexive: reflexive.clone(),
        peer_addrs,
        directory,
    };
    tokio::spawn(accept_loop(transport.clone()));
    tokio::spawn(transport_loop(transport, send_rx));
    tokio::spawn(engine_loop(
        engine,
        input_rx,
        input_tx.clone(),
        send_tx,
        notify_tx,
    ));
    // The router owns the notification stream: it correlates get/put replies and fans events out.
    tokio::spawn(router_loop(notify_rx, ctrl_rx, events_tx.clone()));

    Ok(NodeHandle {
        addr,
        local_addr,
        input_tx,
        ctrl_tx,
        events_tx,
        events_rx,
        endpoint,
        reflexive,
    })
}

/// The engine actor: the sole owner of the engine, dispatching its effects.
async fn engine_loop(
    mut engine: Box<dyn Engine + Send>,
    mut input_rx: mpsc::Receiver<Input>,
    input_tx: mpsc::Sender<Input>,
    send_tx: mpsc::UnboundedSender<SendRequest>,
    notify_tx: mpsc::UnboundedSender<Notification>,
) {
    let origin = StdInstant::now();
    while let Some(input) = input_rx.recv().await {
        let now = Instant(origin.elapsed().as_nanos() as u64);
        for effect in engine.step(now, input) {
            match effect {
                Effect::Send { to, frame } => {
                    let _ = send_tx.send(SendRequest { to, frame });
                }
                Effect::ArmTimer { token, after } => {
                    let tx = input_tx.clone();
                    let delay = std::time::Duration::from_nanos(after.as_nanos());
                    tokio::spawn(fire_timer(tx, token, delay));
                }
                Effect::Notify(note) => {
                    let _ = notify_tx.send(note);
                }
            }
        }
    }
}

/// Sleep for `delay`, then hand the engine its `Timer` input.
async fn fire_timer(tx: mpsc::Sender<Input>, token: TimerToken, delay: std::time::Duration) {
    tokio::time::sleep(delay).await;
    let _ = tx.send(Input::Timer(token)).await;
}

/// The transport dispatcher: routes each [`Effect::Send`] to a per-destination worker. One worker owns the
/// dial-once-then-drain sequence for a single peer, so sends to DIFFERENT peers proceed concurrently while a
/// slow or dead peer stalls only its own queue — never the sends to live peers. This is the #129 fix: a
/// read fans a `Lookup` to every cell point at once, and a single down shard-home must not block the
/// `Lookup`s to the survivors (which, by the erasure redundancy, suffice to reconstruct). Because there is
/// exactly one worker per coordinate, there is also exactly one in-flight dial per coordinate — the
/// duplicate-dial race a naive per-frame spawn would suffer cannot arise.
async fn transport_loop(t: Transport, mut send_rx: mpsc::UnboundedReceiver<SendRequest>) {
    let mut workers: HashMap<Triple, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
    while let Some(SendRequest { to, frame }) = send_rx.recv().await {
        // Reuse the peer's worker, or start one. Workers live for the dispatcher's lifetime (bounded by the
        // node's peer set, exactly like the connection cache), so no per-peer teardown race exists: the
        // channel a frame is handed to always has a live receiver draining it.
        let worker = workers.entry(to).or_insert_with(|| {
            let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
            tokio::spawn(peer_send_worker(t.clone(), to, rx));
            tx
        });
        let _ = worker.send(frame);
    }
}

/// A single peer's send worker: resolve the destination to a connection (dial once, then reuse the cached
/// connection), then write each queued frame as its own QUIC uni-stream, in order. Scoped to one peer so a
/// slow dial or a broken connection cannot delay any other peer's traffic (#129).
async fn peer_send_worker(t: Transport, to: Triple, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        // Resolve `to` to a live connection. If the directory knows an address, reuse-or-dial it; otherwise
        // fall back to a connection the peer already dialed IN on — a live cached connection *is*
        // reachability, so a peer we never learned an address for is still routable in reverse (#119).
        let direct = if let Some(addr) = t.directory.resolve(to) {
            get_or_connect(&t, to, addr).await
        } else {
            cached(&t.conns, to)
        };
        if let Some(conn) = direct {
            send_uni(&conn, &t.shaper, &frame).await;
        } else if let Some(hub) = pick_relay_hub(&t.conns, to) {
            // Symmetric-NAT relay fallback (#119): `to` is unreachable directly (no address, no cached
            // connection — the case a symmetric NAT leaves after even a hole-punch fails). Wrap the frame
            // (with ourselves as origin, so `to`'s reply routes back the same way) and ask a hub we CAN
            // reach to forward it, so any pair behind NAT still communicates. The hub forwards only to a
            // peer it already holds a connection to, so this reaches `to` iff some common node connects both
            // ends — exactly the topology the overlay's cell membership creates.
            send_uni(&hub, &t.shaper, &encode_relay(to, t.me, &frame)).await;
        } else {
            // Genuinely unroutable (no direct path and no hub): drop, counted + logged so it is observable.
            t.directory.note_unresolved_drop(to);
        }
    }
}

/// Write one frame as a single shaped uni-stream on `conn` (the shared send primitive).
async fn send_uni(conn: &Connection, shaper: &Shaper, frame: &[u8]) {
    if let Ok(mut stream) = conn.open_uni().await
        && stream.write_all(&shape_out(shaper, frame)).await.is_ok()
    {
        let _ = stream.finish();
    }
}

/// A live cached connection to any peer other than `exclude` — a hub to relay through when `exclude` is
/// not directly reachable (#119). `None` if this node has no other live connection to relay via.
fn pick_relay_hub(conns: &ConnMap, exclude: Triple) -> Option<Connection> {
    let map = conns.lock().ok()?;
    for (&peer, conn) in map.iter() {
        if peer != exclude && conn.close_reason().is_none() {
            return Some(conn.clone());
        }
    }
    None
}

/// Encode a [`Relay`](FrameType::Relay) frame asking a hub to forward `inner` to `target` on behalf of
/// `origin`: `target_coord(12B) ‖ origin_coord(12B) ‖ inner`. Carrying the origin lets the target attribute
/// the delivered frame to `origin` (not the hub), so its reply routes back the same way — a bidirectional
/// relay, not a one-shot forward. The origin is as trustworthy as the forwarding hub; the target's engine
/// validates the frame content regardless.
fn encode_relay(target: Triple, origin: Triple, inner: &[u8]) -> Vec<u8> {
    let mut body = encode_triple(target).to_vec();
    body.extend_from_slice(&encode_triple(origin));
    body.extend_from_slice(inner);
    let mut frame = Vec::new();
    encode_frame(FrameType::Relay.code(), &body, &mut frame);
    frame
}

/// Decode a [`Relay`](FrameType::Relay) body into `(target, origin, inner frame)`.
fn decode_relay(body: &[u8]) -> Option<(Triple, Triple, &[u8])> {
    let target = decode_triple(body.get(..TRIPLE_WIRE_LEN)?)?;
    let origin = decode_triple(body.get(TRIPLE_WIRE_LEN..2 * TRIPLE_WIRE_LEN)?)?;
    let inner = body.get(2 * TRIPLE_WIRE_LEN..)?;
    Some((target, origin, inner))
}

/// Reuse a cached connection to `to`, or dial one, establish identity (HELLO or self-certifying
/// cert check), and start reading frames the peer sends back on it.
async fn get_or_connect(t: &Transport, to: Triple, addr: SocketAddr) -> Option<Connection> {
    if let Some(conn) = cached(&t.conns, to) {
        return Some(conn);
    }
    // Bound the dial: a peer that has gone away (shut down, NAT-dropped) must fail FAST, not hang the send
    // loop for the full QUIC handshake timeout. That stall is the #129 availability bug — a `get`'s
    // `Lookup`s to live shard-homes were blocked behind a dead peer's dial, so the erasure shards never
    // gathered even though the redundancy tolerates the loss. A real peer answers in well under this.
    let connecting = t.endpoint.connect(addr, "fanos.node").ok()?;
    let conn = tokio::time::timeout(DIAL_TIMEOUT, connecting)
        .await
        .ok()?
        .ok()?;

    match &t.identity {
        // HELLO mode: announce our coordinate as the first uni-stream.
        None => {
            if let Ok(mut hello) = conn.open_uni().await {
                let _ = hello
                    .write_all(&shape_out(&t.shaper, &encode_triple(t.me)))
                    .await;
                let _ = hello.finish();
            }
        }
        // Self-certifying mode: exchange + negotiate HELLOs (spec §7.3/§7.4), then require the peer
        // to have proved the coordinate we dialed — otherwise the address resolved to an impostor
        // (or a negotiation-incompatible peer) and we drop it.
        Some(id) => {
            let peer = hello_exchange(&conn, &t.shaper, id).await;
            if peer != Some(to) {
                tracing::warn!(
                    ?to,
                    ?peer,
                    "peer did not prove the dialed coordinate (or negotiation failed); rejecting"
                );
                return None;
            }
        }
    }
    // Tell the peer the address we observe its connection arriving from — its reflexive/public address
    // for NAT traversal (#119) — on a spawned task, so this side-channel never delays the connection
    // becoming usable. Our own reflexive address arrives symmetrically on the peer's `ObservedAddr`.
    spawn_observed_addr(conn.clone(), t.shaper.clone());
    // The dialer knows the peer identity intrinsically (it chose `to`): tag replies with it.
    tokio::spawn(read_frames(conn.clone(), to, t.clone()));
    if let Ok(mut map) = t.conns.lock() {
        map.insert(to, conn.clone());
    }
    Some(conn)
}

/// A cached, still-open connection to `peer`, if any.
fn cached(conns: &ConnMap, peer: Triple) -> Option<Connection> {
    let map = conns.lock().ok()?;
    let conn = map.get(&peer)?;
    if conn.close_reason().is_none() {
        Some(conn.clone())
    } else {
        None
    }
}

/// Whether a new inbound connection from `ip` is admitted under the per-source cap
/// ([`MAX_INBOUND_PER_SOURCE`]), incrementing that source's live-connection count if so. Returns `false`
/// — without incrementing — when the source already holds the cap. Paired with [`SourceGuard`], which
/// decrements the count when the connection's handler ends.
fn admit_source(counts: &Mutex<HashMap<IpAddr, usize>>, ip: IpAddr) -> bool {
    let mut counts = counts.lock().unwrap_or_else(PoisonError::into_inner);
    let n = counts.entry(ip).or_insert(0);
    if *n >= MAX_INBOUND_PER_SOURCE {
        false
    } else {
        *n += 1;
        true
    }
}

/// Decrements a source IP's live inbound-connection count when its accept handler ends (RAII), so the
/// per-source cap tracks *live* connections rather than cumulative accepts. Removes the entry at zero, so
/// the table stays bounded by the number of currently-connected sources.
struct SourceGuard {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for SourceGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = counts.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

/// Resolve a peer's coordinate from a freshly-established connection: a proof-of-coordinate HELLO exchange
/// (self-certifying mode) or an unauthenticated HELLO read (directory-trust mode). `None` if the HELLO is
/// rejected (bad proof / incompatible negotiation) or unreadable.
async fn resolve_peer_hello(conn: &Connection, t: &Transport) -> Option<Triple> {
    match &t.identity {
        Some(id) => hello_exchange(conn, &t.shaper, id).await,
        None => read_hello(conn, &t.shaper).await,
    }
}

/// The accept loop: for each inbound connection, learn the peer identity from its HELLO and then serve its
/// frames — bounded globally ([`MAX_INBOUND_CONNECTIONS`]), per source ([`admit_source`]), and in handshake
/// time ([`HELLO_DEADLINE`]) so no peer can pin the accept path (audit A6/C3).
async fn accept_loop(t: Transport) {
    let inbound_slots = Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS));
    let per_source: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    while let Some(incoming) = t.endpoint.accept().await {
        // Per-source cap FIRST: the source IP is known before the handshake, so an over-cap connection is
        // refused without spending a global slot or a handshake — one host cannot monopolize accepts (A6).
        let src_ip = incoming.remote_address().ip();
        if !admit_source(&per_source, src_ip) {
            incoming.refuse();
            continue;
        }
        // Take a global connection slot; at the cap this awaits — back-pressuring accepts so a
        // connection-flood cannot spawn unbounded handler tasks (audit C3). `Err` only if the semaphore was
        // closed (only at shutdown), so a failure ends the loop; the per-source table drops with it.
        let Ok(permit) = inbound_slots.clone().acquire_owned().await else {
            break;
        };
        let t = t.clone();
        let source_guard = SourceGuard { counts: per_source.clone(), ip: src_ip };
        tokio::spawn(async move {
            let _permit = permit; // held for this handler's lifetime; released to free the global slot on return
            let _source_guard = source_guard; // decrements this source's live count when the handler ends
            // Establish + identify within the handshake deadline: a connection that stalls before proving a
            // coordinate is dropped, not held (audit A6). This is a HANDSHAKE deadline only — an established
            // link is never reclaimed for silence, since it may back the #119 reverse-reachability path.
            let established = tokio::time::timeout(HELLO_DEADLINE, async {
                let conn = incoming.await.ok()?;
                let from = resolve_peer_hello(&conn, &t).await?;
                Some((conn, from))
            })
            .await;
            let (conn, from) = match established {
                Ok(Some(pair)) => pair,
                Ok(None) => {
                    tracing::debug!(
                        "inbound HELLO rejected (bad proof or negotiation incompatible); dropping"
                    );
                    return;
                }
                Err(_) => {
                    tracing::debug!("inbound connection did not establish + HELLO within the deadline; dropping");
                    return;
                }
            };
            // Cache the connection keyed by the peer's coordinate. This is what makes a dialed-in peer
            // routable in reverse (#119): the transport reuses this live connection to originate traffic
            // back to `from`, even though we never learned its listen address (its HELLO/source address is
            // an ephemeral client port, not where it accepts). No directory entry is written — a live
            // connection *is* the reachability, and inventing a directory address from the source port
            // would be wrong (and, in a shared directory, would clobber the peer's real listen address).
            if let Ok(mut map) = t.conns.lock() {
                map.insert(from, conn.clone());
            }
            // Remember the public source address this peer dialed in from, keyed by its proven coordinate:
            // the hub's hole-punch table (#119). When a third party later asks us to broker a connection to
            // `from`, this is the address we hand it — the peer's NAT-mapped endpoint, which its NAT admits
            // a return packet to once the peer has itself punched outward.
            if let Ok(mut map) = t.peer_addrs.lock() {
                map.insert(from, conn.remote_address());
            }
            // Tell the dialing peer the source address we observe it at — its reflexive/public address
            // for NAT traversal (#119), the STUN-like feedback — on a spawned task so it never delays
            // reading this peer's frames (a blocking send here can stall a busy cell, worsening #129).
            spawn_observed_addr(conn.clone(), t.shaper.clone());
            // Subsequent uni-streams are this peer's frames.
            read_frames(conn, from, t).await;
        });
    }
}

/// Announce our HELLO (a pre-built [`FrameType::Hello`] frame: negotiation parameters ‖ `epoch` ‖
/// `coord` ‖ proof-of-coordinate) as a uni-stream, shaped like any frame.
async fn send_hello(conn: &Connection, shaper: &Shaper, hello: &[u8]) {
    if let Ok(mut stream) = conn.open_uni().await {
        let _ = stream.write_all(&shape_out(shaper, hello)).await;
        let _ = stream.finish();
    }
}

/// Fire-and-forget a reflexive-address report to `conn`'s peer (the source address we observe it at,
/// #119) on a spawned task, so this side-channel never blocks the connection's critical path — reading
/// the peer's frames or completing setup. A blocking send here can stall a busy cell (worsening #129).
fn spawn_observed_addr(conn: Connection, shaper: Shaper) {
    let observed = conn.remote_address();
    tokio::spawn(async move {
        send_framed(&conn, &shaper, FrameType::ObservedAddr, &encode_addr(observed)).await;
    });
}

/// Write one framed message as a fresh uni-stream, shaped like any frame — the shared send
/// primitive [`send_hello_ack`] and [`send_error`] build on (spec §7.2 framing).
async fn send_framed(conn: &Connection, shaper: &Shaper, ty: FrameType, body: &[u8]) {
    let mut frame = Vec::new();
    encode_frame(ty.code(), body, &mut frame);
    if let Ok(mut stream) = conn.open_uni().await {
        let _ = stream.write_all(&shape_out(shaper, &frame)).await;
        let _ = stream.finish();
    }
}

/// Send a `HELLO_ACK` (spec §7.3/§7.4) echoing the negotiated `version` and `capabilities`: body
/// `version(2 BE) ‖ capabilities(4 BE)` — the confirmation the state diagram enters `ESTABLISHED`
/// on. Fire-and-forget: each side computes the SAME deterministic negotiation independently from
/// the peer's HELLO, so establishing the session never blocks waiting to read the peer's ack back
/// (a peer that never sends one — e.g. a future build that dropped HelloAck — cannot wedge us).
async fn send_hello_ack(
    conn: &Connection,
    shaper: &Shaper,
    version: u16,
    capabilities: Capabilities,
) {
    let mut body = Vec::with_capacity(6);
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&capabilities.bits().to_be_bytes());
    send_framed(conn, shaper, FrameType::HelloAck, &body).await;
}

/// Send an `ERROR` frame (spec §7.5) reporting `err` with no reason text — the handshake's
/// incompatibility path (state diagram: `HELLO_SENT → CLOSED`). Best-effort: the connection is
/// being abandoned regardless of whether this write lands.
async fn send_error(conn: &Connection, shaper: &Shaper, err: ProtocolError) {
    let body = encode_error(err, b"");
    send_framed(conn, shaper, FrameType::Error, &body).await;
}

/// Read the peer's first uni-stream as its HELLO, verify its coordinate proof against the peer's
/// authenticated certificate, and negotiate the session — returning the raw [`HelloResult`] (or
/// `None` to drop the peer: canonical-decode failure or a bad proof). This is the authenticated-
/// identity step for a VRF coordinate — a proof for one certificate does not verify against
/// another, so no live challenge is needed (spec §7.3).
async fn read_verified_hello(
    conn: &Connection,
    shaper: &Shaper,
    verify: &HelloVerifier,
) -> Option<HelloResult> {
    let mut stream = conn.accept_uni().await.ok()?;
    let raw = stream.read_to_end(MAX_FRAME).await.ok()?;
    let hello = shape_in(shaper, raw)?;
    let cert = peer_cert_der(conn)?;
    verify(&cert, &hello)
}

/// The full self-certifying HELLO exchange on a fresh connection (spec §7.3/§7.4): announce our own
/// negotiation-bearing HELLO, then read + verify the peer's. On a successful negotiation, send a
/// `HELLO_ACK` echoing the agreed (version, capabilities) and return the peer's certified
/// coordinate. On a version or capability incompatibility, send an `ERROR` frame and abort
/// (`None`) instead of proceeding. A bad coordinate proof is unchanged: a silent drop (spec §L0 —
/// an impostor is never told exactly why its forged proof failed).
///
/// Both the dialer ([`get_or_connect`]) and the acceptor ([`accept_loop`]) call this same function:
/// each announces its own HELLO immediately (never waiting on the peer first), so there is no
/// ordering dependency between the two sides — symmetric, and it cannot deadlock.
async fn hello_exchange(conn: &Connection, shaper: &Shaper, id: &SelfCert) -> Option<Triple> {
    // Snapshot the current-epoch HELLO (an `Arc` clone) and drop the lock before awaiting, so a concurrent
    // reshuffle can rewrite it without blocking on this connection's I/O. A poisoned lock rejects the
    // handshake (`None`), matching the connection-map convention elsewhere in this driver.
    let hello = id.hello.read().ok()?.clone();
    send_hello(conn, shaper, &hello).await;
    match read_verified_hello(conn, shaper, &id.verify).await? {
        HelloResult::Established {
            coord,
            version,
            capabilities,
        } => {
            send_hello_ack(conn, shaper, version, capabilities).await;
            Some(coord)
        }
        HelloResult::Incompatible(err) => {
            tracing::warn!(
                ?err,
                "HELLO negotiation incompatible; sending ERROR and aborting"
            );
            send_error(conn, shaper, err).await;
            None
        }
    }
}

/// Read a connection's first uni-stream as the peer's HELLO (its coordinate), un-shaping first.
async fn read_hello(conn: &Connection, shaper: &Shaper) -> Option<Triple> {
    let mut stream = conn.accept_uni().await.ok()?;
    let raw = stream.read_to_end(MAX_FRAME).await.ok()?;
    let bytes = shape_in(shaper, raw)?;
    decode_triple(bytes.get(..HELLO_LEN)?)
}

/// Read every uni-stream on `conn` as one frame, un-shaping it, delivering `Input::Message`.
async fn read_frames(conn: Connection, from: Triple, t: Transport) {
    // `accept_uni` errors when the connection closes, ending the loop; a single malformed or
    // wrongly-shaped stream is skipped without sinking the connection.
    while let Ok(mut stream) = conn.accept_uni().await {
        let Ok(raw) = stream.read_to_end(MAX_FRAME).await else {
            continue;
        };
        let Some(frame) = shape_in(&t.shaper, raw) else {
            continue;
        };
        // Intercept transport-level signalling before the engine sees it — reflexive discovery and NAT
        // hole-punch brokering (#119) are the driver's concern, not overlay traffic. Everything is
        // attributed to `from`, the peer's cryptographically-proven coordinate.
        if let Ok((decoded, _)) = decode_frame(&frame) {
            match decoded.frame_type() {
                // A peer reporting the public address it observes us at — one vote toward our reflexive
                // address (a peer gets exactly one, keyed by its coordinate).
                Some(FrameType::ObservedAddr) => {
                    if let Some(addr) = decode_addr(decoded.body)
                        && let Ok(mut r) = t.reflexive.lock()
                    {
                        r.observe(from, addr);
                    }
                    continue;
                }
                // `from` asks us (a common hub) to broker a hole-punch to a third peer it cannot reach.
                Some(FrameType::ConnectReq) => {
                    broker_holepunch(&t, from, &conn, decoded.body).await;
                    continue;
                }
                // A hub tells us to dial a peer at its observed public address for a simultaneous open.
                Some(FrameType::PunchTo) => {
                    accept_holepunch(&t, decoded.body);
                    continue;
                }
                // A relayed frame (symmetric-NAT fallback, #119). If we are the target, deliver the inner
                // frame to our engine attributed to its ORIGIN (not the hop `from`), so a request's reply
                // routes back the same way. Otherwise we are the hub: forward the whole `Relay` on to the
                // target if we hold a live connection to it (our own peer, reachable in reverse). The inner
                // is a plain overlay frame the target's engine validates, so a hub only reaches its peers.
                Some(FrameType::Relay) => {
                    if let Some((target, origin, inner)) = decode_relay(decoded.body) {
                        if target == t.me {
                            // The inner is a plain (unshaped) overlay frame — it rode inside the shaped
                            // Relay wrapper, so hand it to the engine as-is, attributed to its origin.
                            if t.input_tx
                                .send(Input::Message { from: origin, frame: inner.to_vec() })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        } else if let Some(hub_conn) = cached(&t.conns, target) {
                            // We are the hub: pass the whole Relay on to the target (re-shaped for that hop).
                            send_uni(&hub_conn, &t.shaper, &frame).await;
                        }
                    }
                    continue;
                }
                _ => {}
            }
        }
        if t.input_tx.send(Input::Message { from, frame }).await.is_err() {
            break; // engine actor gone (or, while it drains a flood, back-pressured here — bounded)
        }
    }
    // The connection ended: drop this peer's reflexive vote so a departed observer stops propping up a
    // possibly-stale address.
    if let Ok(mut r) = t.reflexive.lock() {
        r.forget(from);
    }
}

/// Broker a hole-punch (#119). `requester` (reached on `req_conn`) asked us — a hub both parties have a
/// live connection to — to introduce it to `target` (the coordinate in `body`). We observed each party's
/// public address when it dialed in, so we tell **both** to dial the **other**: `target` learns where
/// `requester` is, `requester` learns where `target` is, and each dials at once. Each NAT then sees an
/// outbound packet before the peer's inbound arrives, so both mappings open and the direct connection
/// forms. We broker only what we can attribute — if we never observed the target, we cannot help.
async fn broker_holepunch(t: &Transport, requester: Triple, req_conn: &Connection, body: &[u8]) {
    let Some(target) = decode_triple(body) else {
        return;
    };
    let (target_addr, requester_addr) = match t.peer_addrs.lock() {
        Ok(map) => (map.get(&target).copied(), map.get(&requester).copied()),
        Err(_) => return,
    };
    let Some(target_addr) = target_addr else {
        return; // the target never dialed in to us — nothing to broker
    };
    // The requester is on this very connection, so its remote address is authoritative even if it also
    // dialed in earlier under a since-rebound mapping.
    let requester_addr = requester_addr.unwrap_or_else(|| req_conn.remote_address());
    // Tell the target to dial the requester (over our cached connection to the target)…
    if let Some(target_conn) = cached(&t.conns, target) {
        send_framed(
            &target_conn,
            &t.shaper,
            FrameType::PunchTo,
            &encode_punch(requester, requester_addr),
        )
        .await;
    }
    // …and tell the requester to dial the target (over the connection it reached us on).
    send_framed(
        req_conn,
        &t.shaper,
        FrameType::PunchTo,
        &encode_punch(target, target_addr),
    )
    .await;
}

/// Act on a hub's `PunchTo` (#119): learn where `peer` is and dial it at once, punching our NAT open for
/// the peer's simultaneous inbound. Recording the address in the directory also makes future overlay
/// sends to `peer` resolve directly, no longer needing the hub. The dial runs on a spawned task so a slow
/// or filtered punch never blocks this connection's frame loop.
fn accept_holepunch(t: &Transport, body: &[u8]) {
    let Some((peer, addr)) = decode_punch(body) else {
        return;
    };
    t.directory.insert(peer, addr);
    let t = t.clone();
    tokio::spawn(async move {
        let _ = get_or_connect(&t, peer, addr).await;
    });
}

/// Encode a [`PunchTo`](FrameType::PunchTo) body: `peer_coord(12B) ‖ family(1B) ‖ ip(4|16) ‖ port(2B BE)`.
fn encode_punch(peer: Triple, addr: SocketAddr) -> Vec<u8> {
    let mut out = encode_triple(peer).to_vec();
    out.extend_from_slice(&encode_addr(addr));
    out
}

/// Decode a [`PunchTo`](FrameType::PunchTo) body into `(peer coordinate, its public address)`.
fn decode_punch(body: &[u8]) -> Option<(Triple, SocketAddr)> {
    let peer = decode_triple(body.get(..TRIPLE_WIRE_LEN)?)?;
    let addr = decode_addr(body.get(TRIPLE_WIRE_LEN..)?)?;
    Some((peer, addr))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::F2;

    #[test]
    fn relay_frame_round_trips_target_origin_and_inner() {
        let (target, origin) = ([1, 2, 3], [4, 5, 6]);
        let inner = b"the inner overlay frame".as_slice();
        let relay = encode_relay(target, origin, inner);
        let (decoded, _) = decode_frame(&relay).expect("a well-formed frame");
        assert_eq!(decoded.frame_type(), Some(FrameType::Relay));
        assert_eq!(decode_relay(decoded.body), Some((target, origin, inner)));
        // A body too short for both coordinates is rejected, not mis-parsed.
        assert_eq!(decode_relay(&[0u8; 2 * TRIPLE_WIRE_LEN - 1]), None);
    }

    /// The per-source inbound cap (audit A6/#69): one host cannot pin more than
    /// [`MAX_INBOUND_PER_SOURCE`] slots, the cap is per-IP, and the RAII [`SourceGuard`] frees a slot when a
    /// handler ends — so the table tracks *live* connections and stays bounded.
    #[test]
    fn the_per_source_cap_bounds_one_ip_and_the_guard_frees_slots() {
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 7).into();
        let other: IpAddr = Ipv4Addr::new(198, 51, 100, 1).into();

        // One source is admitted up to the cap, then refused: a single host cannot pin more than the cap.
        for _ in 0..MAX_INBOUND_PER_SOURCE {
            assert!(admit_source(&counts, ip));
        }
        assert!(!admit_source(&counts, ip), "a source at the cap is refused");
        // The cap is per-IP: a different source is admitted independently.
        assert!(admit_source(&counts, other), "a different source is admitted independently");

        // A handler ending (SourceGuard drop) frees exactly one slot for that source, so it accepts again.
        drop(SourceGuard { counts: counts.clone(), ip });
        assert!(admit_source(&counts, ip), "a freed slot admits the next connection from that source");
        assert!(!admit_source(&counts, ip), "and the source is capped again");

        // The table stays bounded: draining a source to zero live connections forgets it entirely.
        for _ in 0..MAX_INBOUND_PER_SOURCE {
            drop(SourceGuard { counts: counts.clone(), ip });
        }
        let map = counts.lock().unwrap();
        assert!(!map.contains_key(&ip), "a source with no live connections is removed from the table");
        assert!(map.contains_key(&other), "the other source's live connection is still tracked");
    }

    /// The per-epoch reshuffle driver (#102): a `BeaconReady` re-derives this node's VRF coordinate for
    /// the new epoch, re-seats the engine to it, and rebinds its directory coordinate. Driven with a
    /// synthetic beacon so the outcome is deterministic: the new coordinate is exactly
    /// `verifiable_coordinate(creds, epoch, seed)`.
    #[tokio::test]
    async fn a_beacon_round_reshuffles_the_coordinate_and_rebinds_the_directory() {
        let creds = NodeCredentials::generate().expect("credentials");
        let genesis = verifiable_coordinate::<F2>(&creds, Epoch::ZERO, &BeaconSeed::GENESIS).0;
        let genesis_coord = genesis.coords();

        // The epoch-1 beacon and the coordinate it deterministically yields — what the loop must land on.
        // Choose a seed that ACTUALLY moves this (randomly-generated) node's coordinate: a fixed seed would
        // collide with genesis ~1/7 of the time (7 Fano points) and flake the precondition. Deterministic
        // given `creds` — the first byte-fill seed whose epoch-1 VRF coordinate differs from genesis.
        let epoch = Epoch::ZERO.next();
        let (seed, expected) = (0u8..=255)
            .map(|b| {
                let s = [b; 32];
                let coord = verifiable_coordinate::<F2>(&creds, epoch, &BeaconSeed::new(s))
                    .0
                    .coords();
                (s, coord)
            })
            .find(|(_, coord)| *coord != genesis_coord)
            .expect("some beacon seed moves the coordinate off genesis");

        // Shared cells + a directory pre-bound at the genesis coordinate.
        let hello = Arc::new(RwLock::new(Arc::new(vec![0u8]))); // sentinel: rewritten on reshuffle
        let beacon = Arc::new(RwLock::new(BeaconSeed::GENESIS));
        let directory = Directory::new();
        let local_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 40_000).into();
        directory.insert(genesis_coord, local_addr);

        // Channels: the loop's `Client` sends `Reseat` down `input_rx`; we push `BeaconReady` via `events`.
        let (input_tx, mut input_rx) = mpsc::channel::<Input>(8);
        let (ctrl_tx, _ctrl_rx) = mpsc::unbounded_channel::<Control>();
        let (events_tx, _events_rx0) = broadcast::channel::<Notification>(8);
        let client = Client {
            addr: genesis_coord,
            input_tx,
            ctrl_tx,
            events_tx: events_tx.clone(),
        };

        // A PROTEUS shaper started at genesis — the reshuffle must rotate its shape to the new epoch (§13.4).
        let shaper = Arc::new(RwLock::new(ProteusShaper::new(b"test-secret".to_vec(), Epoch::ZERO)));
        tokio::spawn(reshuffle_loop::<F2>(
            creds,
            Capabilities::CORE,
            genesis_coord,
            local_addr,
            directory.clone(),
            hello.clone(),
            beacon.clone(),
            Some(shaper.clone()),
            events_tx.subscribe(),
            client,
        ));

        events_tx
            .send(Notification::BeaconReady { epoch, seed })
            .expect("a subscriber (the loop) is listening");

        // The loop re-seats the engine: a `Reseat` command carrying the epoch-1 VRF coordinate.
        let cmd = tokio::time::timeout(std::time::Duration::from_secs(2), input_rx.recv())
            .await
            .expect("the reshuffle loop issued a command in time")
            .expect("the command channel is open");
        assert_eq!(
            cmd,
            Input::Command(Command::Reseat { coord: expected }),
            "the engine is re-seated at the epoch's VRF coordinate"
        );

        // The directory + published cells follow (the loop writes them right after the command). Poll
        // briefly: those writes happen on the loop's task, concurrent with ours.
        let rebound = await_until(|| {
            directory.resolve(expected) == Some(local_addr)
                && directory.resolve(genesis_coord).is_none()
        })
        .await;
        assert!(
            rebound,
            "the new coordinate is bound to our address and the vacated one is cleared"
        );
        assert_eq!(
            *beacon.read().unwrap(),
            BeaconSeed::new(seed),
            "the verifier's beacon advanced"
        );
        assert_ne!(
            **hello.read().unwrap(),
            vec![0u8],
            "the published HELLO was rewritten for the new coordinate"
        );
        assert_eq!(
            shaper.read().unwrap().epoch(),
            epoch,
            "the PROTEUS wire shape rotated to the new epoch (§13.4 moving target)"
        );
    }

    /// A beacon whose VRF lands the node back on its current point is a no-op: no re-seat command.
    #[tokio::test]
    async fn a_beacon_that_does_not_move_the_coordinate_is_a_noop() {
        let creds = NodeCredentials::generate().expect("credentials");
        let genesis = verifiable_coordinate::<F2>(&creds, Epoch::ZERO, &BeaconSeed::GENESIS).0;
        let genesis_coord = genesis.coords();

        let hello = Arc::new(RwLock::new(Arc::new(vec![0u8])));
        let beacon = Arc::new(RwLock::new(BeaconSeed::GENESIS));
        let directory = Directory::new();
        let local_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 40_001).into();

        let (input_tx, mut input_rx) = mpsc::channel::<Input>(8);
        let (ctrl_tx, _ctrl_rx) = mpsc::unbounded_channel::<Control>();
        let (events_tx, _rx0) = broadcast::channel::<Notification>(8);
        let client = Client {
            addr: genesis_coord,
            input_tx,
            ctrl_tx,
            events_tx: events_tx.clone(),
        };
        tokio::spawn(reshuffle_loop::<F2>(
            creds,
            Capabilities::CORE,
            genesis_coord,
            local_addr,
            directory,
            hello,
            beacon,
            None,
            events_tx.subscribe(),
            client,
        ));

        // Re-announce the GENESIS beacon at epoch 0 → the same coordinate → the loop must NOT re-seat.
        events_tx
            .send(Notification::BeaconReady {
                epoch: Epoch::ZERO,
                seed: *BeaconSeed::GENESIS.as_bytes(),
            })
            .expect("subscriber listening");
        let quiet =
            tokio::time::timeout(std::time::Duration::from_millis(300), input_rx.recv()).await;
        assert!(
            quiet.is_err(),
            "no re-seat command when the coordinate does not move"
        );
    }

    /// Poll `cond` up to ~2s, yielding between checks; returns whether it became true.
    async fn await_until(cond: impl Fn() -> bool) -> bool {
        for _ in 0..400 {
            if cond() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        false
    }

    #[test]
    fn evict_stale_drops_abandoned_and_expired_waiters_but_keeps_fresh_ones() {
        // Audit C1: the router's correlation maps must not leak waiters whose reply never comes. Use
        // forward timestamps only (Instant + Duration never underflows): register the "fresh" entries at
        // `later` and evaluate at `later`, and the "expired" entry at `t0` so it is `REQUEST_TIMEOUT + 1s`
        // old at evaluation.
        let t0 = std::time::Instant::now();
        let later = t0 + REQUEST_TIMEOUT + std::time::Duration::from_secs(1);
        let mut puts: PutWaiters = HashMap::new();

        // (a) fresh + live receiver → survives.
        let (tx_live, _rx_live) = oneshot::channel::<()>();
        puts.entry([1u8; 32]).or_default().push((later, tx_live));
        // (b) fresh timestamp but the client already dropped its receiver → evicted (is_closed).
        let (tx_abandoned, rx_abandoned) = oneshot::channel::<()>();
        drop(rx_abandoned);
        puts.entry([2u8; 32])
            .or_default()
            .push((later, tx_abandoned));
        // (c) receiver still held but the waiter has outlived REQUEST_TIMEOUT → evicted (age).
        let (tx_expired, mut rx_expired) = oneshot::channel::<()>();
        puts.entry([3u8; 32]).or_default().push((t0, tx_expired));

        evict_stale(&mut puts, later);

        assert!(
            puts.contains_key(&[1u8; 32]),
            "a fresh, still-awaited waiter survives"
        );
        assert!(
            !puts.contains_key(&[2u8; 32]),
            "a waiter whose receiver was abandoned is evicted"
        );
        assert!(
            !puts.contains_key(&[3u8; 32]),
            "a waiter older than REQUEST_TIMEOUT is evicted"
        );
        // Evicting (c) dropped its sender, so the client's receiver now resolves to Err → it sees `false`.
        assert!(
            matches!(
                rx_expired.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            ),
            "the expired client's receiver is closed by the eviction (it will observe a failed put)",
        );
    }
}
