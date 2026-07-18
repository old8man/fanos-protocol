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
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant as StdInstant;

use quinn::{Connection, Endpoint};
use tokio::sync::{broadcast, mpsc, oneshot};

use fanos_crypto::{hash_labeled, label};
use fanos_field::Field;
use fanos_geometry::{Point, Triple};
use fanos_proteus::ProteusShaper;
use fanos_runtime::{Command, Effect, Engine, Input, Instant, Notification, TimerToken};
use quinn::{ClientConfig, ServerConfig};

use crate::directory::Directory;
use crate::identity::{coordinate_from_cert, peer_cert_der};
use crate::tls::{
    NodeCredentials, TlsError, node_configs, node_configs_mutual, node_configs_mutual_from,
};

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
/// frame (including the identity HELLO) is polymorph-obfuscated on the wire (spec §13.2).
type Shaper = Option<Arc<ProteusShaper>>;

/// The identity mode. `None` ⇒ HELLO + directory-trust; `Some(f)` ⇒ self-certifying, where `f`
/// derives a peer's authenticated coordinate from its presented certificate DER.
type Identity = Option<Arc<dyn Fn(&[u8]) -> Option<Triple> + Send + Sync>>;

/// Shape an outbound frame for the wire (identity when no shaper is configured).
fn shape_out(shaper: &Shaper, frame: &[u8]) -> Vec<u8> {
    shaper
        .as_ref()
        .map_or_else(|| frame.to_vec(), |s| s.outbound(frame))
}

/// Recover an inbound frame from the wire, or `None` if it wasn't shaped by our secret+epoch.
fn shape_in(shaper: &Shaper, wire: Vec<u8>) -> Option<Vec<u8>> {
    match shaper {
        Some(s) => s.inbound(&wire),
        None => Some(wire),
    }
}

/// Bytes of a HELLO: three little-endian `u32`s (a projective coordinate).
const HELLO_LEN: usize = 12;
/// Per-frame receive cap. Onion/Tessera frames are far smaller; this only bounds abuse.
const MAX_FRAME: usize = 1 << 20;

/// The bound on the engine's inbound `Input` queue. The per-connection frame readers feed this channel and
/// **await** when it is full, so a peer flooding frames is back-pressured through QUIC's own flow control
/// rather than growing this queue without limit (audit C2). The timer/command producers share it; commands
/// use a non-blocking `try_send` (dropped under a sustained flood, the caller sees `false`), timers await.
/// The outbound/notification channels stay unbounded — they are bounded *transitively*, since the engine
/// can only produce effects as fast as it drains this now-bounded input.
const INPUT_CAP: usize = 1024;

/// A coordinate → live connection cache. A `Connection` is a cheap handle (an `Arc` inside).
type ConnMap = Arc<Mutex<HashMap<Triple, Connection>>>;

/// An internal request from the engine actor to the transport loop.
struct SendRequest {
    to: Triple,
    frame: Vec<u8>,
}

/// The transport's shared context: everything the send path needs besides the destination.
#[derive(Clone)]
struct Transport {
    endpoint: Endpoint,
    conns: ConnMap,
    input_tx: mpsc::Sender<Input>,
    shaper: Shaper,
    identity: Identity,
    me: Triple,
}

/// How long a store `get`/`put` waits for its reply before giving up. A store request whose
/// responsible node is unreachable (down, or absent from a sparse cell) must fail, not hang the
/// caller's task forever (audit C1).
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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

    /// Inject an application command (delivered to the engine as `Input::Command`). Returns
    /// `false` if the engine actor has stopped.
    pub fn command(&self, cmd: Command) -> bool {
        self.input_tx.try_send(Input::Command(cmd)).is_ok()
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
}

/// Pending `get` waiters, keyed by the storage digest the engine echoes (a Vec coalesces concurrent
/// gets of the same key onto one reply).
type GetWaiters = HashMap<[u8; 32], Vec<oneshot::Sender<Option<Vec<u8>>>>>;
/// Pending `put` waiters, keyed by the storage digest.
type PutWaiters = HashMap<[u8; 32], Vec<oneshot::Sender<()>>>;

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
        let digest = hash_labeled(label::STORAGE, &key);
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
        let digest = hash_labeled(label::STORAGE, &key);
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
    loop {
        tokio::select! {
            note = notify_rx.recv() => {
                let Some(note) = note else { break };
                match &note {
                    Notification::Retrieved { key, value } => {
                        if let Some(waiters) = gets.remove(key) {
                            for w in waiters {
                                let _ = w.send(value.clone());
                            }
                        }
                    }
                    Notification::Stored(key) => {
                        if let Some(waiters) = puts.remove(key) {
                            for w in waiters {
                                let _ = w.send(());
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
                match ctrl {
                    Control::Get { digest, reply } => gets.entry(digest).or_default().push(reply),
                    Control::Put { digest, reply } => puts.entry(digest).or_default().push(reply),
                }
            }
        }
    }
}

/// Errors that can occur bringing a node up.
#[derive(Debug)]
pub enum QuicError {
    /// TLS/QUIC configuration failed.
    Tls(TlsError),
    /// Binding the UDP socket or reading its address failed.
    Io(std::io::Error),
}

impl core::fmt::Display for QuicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tls(e) => write!(f, "TLS setup: {e}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
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
/// its mutual-TLS certificate, so a peer authenticates the coordinate from the handshake — no HELLO
/// and no directory-trust for identity (the directory serves only address resolution). The engine
/// is built at the cert-derived coordinate by `make_engine`.
pub async fn spawn_self_certifying<F: Field + 'static>(
    make_engine: impl FnOnce(Point<F>) -> Box<dyn Engine + Send>,
    directory: Directory,
) -> Result<NodeHandle, QuicError> {
    let (server, client, cert) = node_configs_mutual()?;
    self_certifying_inner::<F, _>(
        server,
        client,
        &cert,
        make_engine,
        directory,
        default_bind(),
    )
}

/// Like [`spawn_self_certifying`], but reuses persisted [`NodeCredentials`] so the node keeps the
/// **same coordinate across restarts** — a durable overlay identity.
pub async fn spawn_self_certifying_persistent<F: Field + 'static>(
    credentials: &NodeCredentials,
    make_engine: impl FnOnce(Point<F>) -> Box<dyn Engine + Send>,
    directory: Directory,
) -> Result<NodeHandle, QuicError> {
    let (server, client, cert) = node_configs_mutual_from(credentials)?;
    self_certifying_inner::<F, _>(
        server,
        client,
        &cert,
        make_engine,
        directory,
        default_bind(),
    )
}

/// Like [`spawn_self_certifying_persistent`], but binds the QUIC endpoint to an explicit address
/// (e.g. `0.0.0.0:9000` for a publicly reachable node) instead of an ephemeral localhost port. This
/// is the production entry point a node binary uses; the coordinate stays cert-derived and stable.
pub async fn spawn_self_certifying_persistent_on<F: Field + 'static>(
    bind: SocketAddr,
    credentials: &NodeCredentials,
    make_engine: impl FnOnce(Point<F>) -> Box<dyn Engine + Send>,
    directory: Directory,
) -> Result<NodeHandle, QuicError> {
    let (server, client, cert) = node_configs_mutual_from(credentials)?;
    self_certifying_inner::<F, _>(server, client, &cert, make_engine, directory, bind)
}

fn self_certifying_inner<F: Field + 'static, M>(
    server: ServerConfig,
    client: ClientConfig,
    cert: &rustls::pki_types::CertificateDer<'static>,
    make_engine: M,
    directory: Directory,
    bind: SocketAddr,
) -> Result<NodeHandle, QuicError>
where
    M: FnOnce(Point<F>) -> Box<dyn Engine + Send>,
{
    let engine = make_engine(coordinate_from_cert::<F>(cert.as_ref()));
    let derive: Identity = Some(Arc::new(|der: &[u8]| {
        Some(coordinate_from_cert::<F>(der).coords())
    }));
    spawn_inner(engine, directory, None, derive, server, client, bind)
}

/// Like [`spawn`], but every frame on the wire is PROTEUS-shaped with the shared `community_secret`
/// for `epoch` (spec §13.2): the transport carries no static FANOS signature, and a peer without
/// the secret cannot produce frames this node will accept. The engine is unchanged — shaping lives
/// entirely in the driver, below the sans-I/O boundary.
pub async fn spawn_shaped(
    engine: Box<dyn Engine + Send>,
    directory: Directory,
    community_secret: Vec<u8>,
    epoch: u32,
) -> Result<NodeHandle, QuicError> {
    let shaper = Arc::new(ProteusShaper::new(community_secret, epoch));
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

    tokio::spawn(accept_loop(
        endpoint.clone(),
        conns.clone(),
        input_tx.clone(),
        shaper.clone(),
        identity.clone(),
    ));
    let transport = Transport {
        endpoint: endpoint.clone(),
        conns,
        input_tx: input_tx.clone(),
        shaper,
        identity,
        me: addr,
    };
    tokio::spawn(transport_loop(transport, directory, send_rx));
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
async fn fire_timer(
    tx: mpsc::Sender<Input>,
    token: TimerToken,
    delay: std::time::Duration,
) {
    tokio::time::sleep(delay).await;
    let _ = tx.send(Input::Timer(token)).await;
}

/// The transport loop: performs `Effect::Send` by writing one QUIC uni-stream per frame.
async fn transport_loop(
    t: Transport,
    directory: Directory,
    mut send_rx: mpsc::UnboundedReceiver<SendRequest>,
) {
    while let Some(SendRequest { to, frame }) = send_rx.recv().await {
        // Unresolved coordinate → drop, exactly as the simulator drops to an unknown node — but count
        // and log it so the drop is observable, not silent (a symptom of a stale/colliding address).
        let Some(addr) = directory.resolve(to) else {
            directory.note_unresolved_drop(to);
            continue;
        };
        let Some(conn) = get_or_connect(&t, to, addr).await else {
            continue;
        };
        if let Ok(mut stream) = conn.open_uni().await
            && stream
                .write_all(&shape_out(&t.shaper, &frame))
                .await
                .is_ok()
        {
            let _ = stream.finish();
        }
    }
}

/// Reuse a cached connection to `to`, or dial one, establish identity (HELLO or self-certifying
/// cert check), and start reading frames the peer sends back on it.
async fn get_or_connect(t: &Transport, to: Triple, addr: SocketAddr) -> Option<Connection> {
    if let Some(conn) = cached(&t.conns, to) {
        return Some(conn);
    }
    let conn = t.endpoint.connect(addr, "fanos.node").ok()?.await.ok()?;

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
        // Self-certifying mode: the peer's certificate must certify the coordinate we dialed —
        // otherwise the address resolved to an impostor and we drop the connection.
        Some(derive) => {
            let peer = peer_cert_der(&conn).and_then(|der| derive(&der));
            if peer != Some(to) {
                tracing::warn!(
                    ?to,
                    ?peer,
                    "peer certificate does not certify the dialed coordinate; rejecting"
                );
                return None;
            }
        }
    }
    // The dialer knows the peer identity intrinsically (it chose `to`): tag replies with it.
    tokio::spawn(read_frames(
        conn.clone(),
        to,
        t.input_tx.clone(),
        t.shaper.clone(),
    ));
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

/// The accept loop: for each inbound connection, learn the peer identity from its HELLO and then
/// serve its frames.
async fn accept_loop(
    endpoint: Endpoint,
    conns: ConnMap,
    input_tx: mpsc::Sender<Input>,
    shaper: Shaper,
    identity: Identity,
) {
    while let Some(incoming) = endpoint.accept().await {
        let conns = conns.clone();
        let input_tx = input_tx.clone();
        let shaper = shaper.clone();
        let identity = identity.clone();
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else {
                return;
            };
            // Learn the peer's coordinate: from its certificate (self-certifying) or its HELLO.
            let from = if let Some(derive) = &identity {
                let Some(coord) = peer_cert_der(&conn).and_then(|der| derive(&der)) else {
                    tracing::debug!("inbound peer presented no certifiable identity; dropping");
                    return;
                };
                coord
            } else {
                let Some(coord) = read_hello(&conn, &shaper).await else {
                    return;
                };
                coord
            };
            if let Ok(mut map) = conns.lock() {
                map.insert(from, conn.clone());
            }
            // Subsequent uni-streams are this peer's frames.
            read_frames(conn, from, input_tx, shaper).await;
        });
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
async fn read_frames(
    conn: Connection,
    from: Triple,
    input_tx: mpsc::Sender<Input>,
    shaper: Shaper,
) {
    // `accept_uni` errors when the connection closes, ending the loop; a single malformed or
    // wrongly-shaped stream is skipped without sinking the connection.
    while let Ok(mut stream) = conn.accept_uni().await {
        let Ok(raw) = stream.read_to_end(MAX_FRAME).await else {
            continue;
        };
        let Some(frame) = shape_in(&shaper, raw) else {
            continue;
        };
        if input_tx.send(Input::Message { from, frame }).await.is_err() {
            break; // engine actor gone (or, while it drains a flood, back-pressured here — bounded)
        }
    }
}

/// Encode a coordinate as 12 little-endian bytes.
fn encode_triple(t: Triple) -> [u8; HELLO_LEN] {
    let mut out = [0u8; HELLO_LEN];
    out[0..4].copy_from_slice(&t[0].to_le_bytes());
    out[4..8].copy_from_slice(&t[1].to_le_bytes());
    out[8..12].copy_from_slice(&t[2].to_le_bytes());
    out
}

/// Decode a coordinate from exactly 12 little-endian bytes.
fn decode_triple(b: &[u8]) -> Option<Triple> {
    let bytes: [u8; HELLO_LEN] = b.try_into().ok()?;
    let x = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let y = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    let z = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    Some([x, y, z])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_codec_round_trips() {
        let t = [7u32, 0, 1];
        assert_eq!(decode_triple(&encode_triple(t)), Some(t));
    }

    #[test]
    fn short_hello_is_rejected() {
        assert_eq!(decode_triple(&[0u8; 4]), None);
    }
}
