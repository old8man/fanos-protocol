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

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Instant as StdInstant;

use quinn::{Connection, Endpoint};
use tokio::sync::{Semaphore, broadcast, mpsc, oneshot};

use fanos_field::Field;
use fanos_geometry::{Point, TRIPLE_WIRE_LEN, Triple, decode_triple, encode_triple};
use fanos_primitives::{BeaconSeed, Epoch, storage_digest};
use fanos_proteus::{Environment, Morph, MorphCodec, MorphController, ProteusShaper};
use fanos_runtime::{Command, Effect, Engine, Input, Instant, Notification, TimerToken};
use fanos_wire::capability::Capabilities;
use fanos_wire::error::encode_error;
use fanos_wire::{FrameType, ProtocolError, decode_frame, encode_frame};
use quinn::{ClientConfig, ServerConfig};

use crate::directory::Directory;
use crate::reflexive::{ReflexiveAddr, decode_addr, encode_addr};
use fanos_vrf::{CoordinateClaim, VrfProof, VrfPublic};

use crate::claims::{self, ClaimBook};
use crate::identity::{
    HelloResult, hello_bytes, hello_epoch, peer_cert_der, verifiable_coordinate_ranked, verify_hello,
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

/// The optional morph auto-fallback controller shared across a node's send path: when set, connection
/// outcomes are recorded into it ([`apply_outcome`]) and a trip rotates the shaper's morph (§13.7).
type MaybeController = Option<Arc<Mutex<MorphController>>>;

/// PROTEUS transport configuration (spec §13): the shared community `secret` every frame is shaped under,
/// the [`Morph`] selecting the codec and traffic-shaping profile (size + timing), and an optional
/// [`Environment`] enabling **morph auto-fallback** (§13.7 — rotate the morph on a connection-failure spike).
/// Peers must share the secret to interoperate; the morph and fallback are local wire-shaping choices.
#[derive(Clone)]
pub struct ProteusConfig {
    /// The shared community secret keying the beacon-rotating shape.
    pub secret: Vec<u8>,
    /// The obfuscation morph (defaults to the flagship [`Morph::Polymorph`]). When `environment` is set the
    /// starting morph is the environment's preferred morph instead; when `codec` is set the morph is
    /// [`Morph::Pluggable`].
    pub morph: Morph,
    /// The environment policy for morph auto-fallback (§13.7). `Some(env)` rotates through `env`'s morph
    /// chain when the current morph starts failing; `None` (the default) pins the fixed `morph`.
    pub environment: Option<Environment>,
    /// A pluggable-transport codec (the §13.3 SPI). `Some(codec)` runs the [`Morph::Pluggable`] morph with
    /// this custom codec instead of the built-in polymorph transform (and takes precedence over
    /// `environment`/`morph`); an embedder sets it programmatically — it has no config-file/CLI surface,
    /// since a codec is code, not configuration.
    pub codec: Option<Arc<dyn MorphCodec>>,
}

/// Redacted `Debug`: never render the community secret (secret hygiene, audit D) — the morph/env, and only
/// whether a pluggable codec is present.
impl std::fmt::Debug for ProteusConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProteusConfig")
            .field("secret", &"<redacted>")
            .field("morph", &self.morph)
            .field("environment", &self.environment)
            .field("codec", &self.codec.as_ref().map(|_| "<plugged>"))
            .finish()
    }
}

impl ProteusConfig {
    /// A config for the flagship [`Morph::Polymorph`] ("look like nothing") under `secret`, fixed morph.
    #[must_use]
    pub fn polymorph(secret: impl Into<Vec<u8>>) -> Self {
        Self { secret: secret.into(), morph: Morph::Polymorph, environment: None, codec: None }
    }

    /// A config under an explicit fixed `morph`.
    #[must_use]
    pub fn with_morph(secret: impl Into<Vec<u8>>, morph: Morph) -> Self {
        Self { secret: secret.into(), morph, environment: None, codec: None }
    }

    /// A config with **auto-fallback** under `environment`: the morph starts at the environment's preferred
    /// morph and rotates through its chain as morphs fail (§13.7).
    #[must_use]
    pub fn auto(secret: impl Into<Vec<u8>>, environment: Environment) -> Self {
        Self {
            secret: secret.into(),
            morph: environment.preferred_morph(),
            environment: Some(environment),
            codec: None,
        }
    }

    /// A config driven by a **pluggable** [`MorphCodec`] (the §13.3 SPI) instead of the built-in transform —
    /// the honest home for a real cover-protocol tunnel or a third-party morph.
    #[must_use]
    pub fn pluggable(secret: impl Into<Vec<u8>>, codec: Arc<dyn MorphCodec>) -> Self {
        Self { secret: secret.into(), morph: Morph::Pluggable, environment: None, codec: Some(codec) }
    }

    /// Build the shared shaper and (when auto-fallback is configured) its controller, seeded at `epoch`. A
    /// pluggable codec wins; else an environment starts the shaper at its preferred morph with a controller;
    /// else the fixed `morph` with no controller.
    fn build(self, epoch: Epoch) -> (Arc<RwLock<ProteusShaper>>, MaybeController) {
        if let Some(codec) = self.codec {
            let shaper = ProteusShaper::with_codec(self.secret, epoch, codec);
            return (Arc::new(RwLock::new(shaper)), None);
        }
        match self.environment {
            Some(env) => {
                let controller = MorphController::new(env);
                let shaper = ProteusShaper::with_morph(self.secret, epoch, controller.current());
                (Arc::new(RwLock::new(shaper)), Some(Arc::new(Mutex::new(controller))))
            }
            None => (
                Arc::new(RwLock::new(ProteusShaper::with_morph(self.secret, epoch, self.morph))),
                None,
            ),
        }
    }
}

/// Record a connection outcome into the auto-fallback controller (if any) and, when it trips a rotation,
/// install the new morph on the shaper — the live half of §13.7 morph auto-fallback. A no-op without a
/// controller (fixed morph). Extracted so the record→rotate→`set_morph` glue is unit-testable off the
/// network (a censored morph otherwise only manifests as slow connect timeouts).
fn apply_outcome(shaper: &Shaper, controller: &MaybeController, success: bool) {
    let Some(ctl) = controller else { return };
    let rotated = ctl.lock().unwrap_or_else(PoisonError::into_inner).record(success);
    if let (Some(morph), Some(s)) = (rotated, shaper) {
        s.write().unwrap_or_else(PoisonError::into_inner).set_morph(morph);
    }
}

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
    /// Prove this node's coordinate for an arbitrary `(epoch, beacon)`: identity bytes, VRF public, and proof.
    ///
    /// A **closure over the credentials**, so the secret never leaves this module while anything that must publish a
    /// coordinate-bound record (`fanos_node::mixdir`) can obtain the proof a reader will check. Handing out the VRF secret
    /// instead would put a signing key in every publisher and every fixture that spawns one.
    prove: CoordinateProver,
}

/// See `SelfCert::prove`: `(epoch, beacon) → (identity bytes, VRF public, proof)`.
pub type CoordinateProver = Arc<dyn Fn(Epoch, &BeaconSeed) -> (Vec<u8>, VrfPublic, VrfProof) + Send + Sync>;

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

/// Shape an outbound frame for the wire **and** its traffic-shaping pace: the [`std::time::Duration`] the
/// data path waits before transmitting (`ZERO` when no shaper is set or the morph does not time-shape). The
/// clock stays in the driver — the shaper only computes the delay — keeping PROTEUS below the sans-I/O
/// boundary. Used on the data path (`send_uni`); control frames keep the untimed [`shape_out`].
fn shape_out_timed(shaper: &Shaper, frame: &[u8]) -> (Vec<u8>, std::time::Duration) {
    match shaper {
        Some(s) => {
            let shaped = s.read().unwrap_or_else(PoisonError::into_inner).shape(frame);
            (shaped.wire, shaped.delay)
        }
        None => (frame.to_vec(), std::time::Duration::ZERO),
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
/// Per-frame receive cap — **re-exported from the wire authority, not defined here**.
///
/// This driver enforces the bound, but it does not own it: every producer of a frame anywhere in the
/// workspace is bound by the same number, and a copy per enforcer is a copy free to drift. It used to be a
/// private `const` here with a second `pub const` in `fanos-node`'s ANGELOS driver — see
/// [`fanos_wire::MAX_FRAME`] for what that cost.
use fanos_wire::MAX_FRAME;
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

/// How many distinct peers must independently report the same observed address before this node trusts it
/// as its public address (see [`ReflexiveAddr`]) — **derived from the plane's own fault budget.**
///
/// It used to be the constant `2`, "so one lying/misconfigured peer cannot move it". That defends against
/// ONE liar while every other bound in FANOS is sized to `f = ⌊(n−1)/3⌋`, which is **2** at the Fano base
/// cell. So two colluding peers sat *inside* the budget the platform explicitly promises to survive, and two
/// agreeing reports was exactly the quorum: an adversary within tolerance could set a node's belief about its
/// own public address — the address it advertises and a hub uses to broker a hole-punch (#119).
///
/// `f + 1` is the same pigeonhole every coalition bound here uses, so a tolerated adversary is one short of
/// forging agreement whatever the plane.
///
/// **The layer matters and was the real defect.** A quorum sized against the fault model belongs where the
/// fault model is known, and this crate is the transport: `Directory` holds *known peers*, not the cell's
/// point count, so sizing from it would have been an attacker-influenceable guess. The self-certifying entry
/// points are generic over `F`, so they compute this and hand it in; the field-less [`spawn`] keeps the base
/// cell's value because a bare engine has no plane to ask.
#[must_use]
pub const fn reflexive_quorum(q: u32) -> usize {
    let n = (q as usize) * (q as usize) + (q as usize) + 1;
    (n - 1) / 3 + 1
}

/// The base cell's reflexive quorum — what [`spawn`] uses, having no `F` to derive from.
const REFLEXIVE_QUORUM_FANO: usize = reflexive_quorum(2);

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
    /// Transport-level events the layers above must see — currently a peer proving it moved. The driver publishes here
    /// rather than routing through the engine because the event is about the *transport's* view of who is where, which the
    /// engine has no part in forming.
    events_tx: broadcast::Sender<Notification>,
    shaper: Shaper,
    /// Morph auto-fallback controller (§13.7), when a PROTEUS environment policy is configured; the send
    /// path records connection outcomes into it and rotates the shaper's morph on a trip.
    controller: MaybeController,
    identity: Identity,
    me: Triple,
    reflexive: Reflexive,
    /// Public addresses this node has observed peers dialing in from — the hub's hole-punch table (#119).
    peer_addrs: PeerAddrs,
    /// The address book, so the receive path can register a peer's punched address and the send path can
    /// resolve a destination coordinate to a socket.
    directory: Directory,
    /// Identity-keyed distrust, so a quarantine follows the peer rather than the point (audit R-M1).
    distrust: Arc<Distrust>,
    /// Coordinates with a hole-punch dial already in flight — the bound on what an unsolicited `PunchTo`
    /// can cost (see [`accept_holepunch`]). A *set of coordinates*, so the ceiling is the plane's own point
    /// count and no constant has to assert one.
    punching: Arc<Mutex<BTreeSet<Triple>>>,
}

/// How long a store `get`/`put` waits for its reply before giving up. A store request whose
/// responsible node is unreachable (down, or absent from a sparse cell) must fail, not hang the
/// caller's task forever (audit C1).
///
/// **It must stay strictly longer than `fanos_node::resolve::STORE_TIMEOUT`, and that ordering carries a
/// correctness property rather than a preference.** A `get` that gives up returns `None`, which callers read as
/// a *definite* "nothing is published here" — `Read::Absent`, which `resolve.rs` says "a caller may rely on".
/// A caller that wants to distinguish "did not conclude" from "definitely empty" therefore wraps this in its
/// own, **shorter** bound and treats the elapse as `Read::Unknown`.
///
/// Invert the two and that distinction silently disappears: this timeout would always fire first, every read
/// would return `None`, `Read::Unknown` would become unreachable, and an unreachable member would be reported
/// as one demanding nothing — with `Scan::complete()` returning `true` the whole time, so every consumer that
/// checks it would be checking a constant. Public so the ordering can be asserted rather than assumed.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
    /// Peer coordinate claims verified this epoch — the input coordinate resolution runs on. `None` for a node with no
    /// self-certifying identity, which never resolves and therefore has no book.
    ///
    /// **Not** a test for "this cell's coordinates are VRF-derived", though it reads like one. A harness can pin every
    /// coordinate while still giving each node a self-certifying identity, so this is `Some` and yet no node sits on a point
    /// it could prove. Deriving the coordinate-binding mode from this rejected every honest record in exactly that setup —
    /// the mode is a deployment property of the cell, known above this layer, and it is passed in (see
    /// `fanos_node::rendezvous_host::HostedService`), never inferred here.
    claims: Option<ClaimBook>,
    /// The self-certifying identity, for [`coordinate_prover`](Self::coordinate_prover). `None` under directory trust.
    identity: Identity,
    /// The node's **live** overlay coordinate.
    ///
    /// Shared and mutable because a coordinate moves: every epoch by the beacon reshuffle (spec §L3), and within an epoch
    /// when a better claim displaces this node from its point. It was a plain field set at spawn, so every layer above —
    /// `NodeHandle::address`, `Client::address`, `fanos_node::Node::health().address` — reported the *genesis* coordinate
    /// forever, from the first reshuffle onward. That is a defect in the shipped reshuffle, not only in probing: an
    /// operator surface that names a node's position must name where it actually is.
    addr: Arc<Mutex<Triple>>,
    local_addr: SocketAddr,
    input_tx: mpsc::Sender<Input>,
    ctrl_tx: mpsc::UnboundedSender<Control>,
    events_tx: broadcast::Sender<Notification>,
    events_rx: broadcast::Receiver<Notification>,
    endpoint: Endpoint,
    reflexive: Reflexive,
    /// The **network's genesis seed** — the value epoch-0 coordinates on this network are drawn against
    /// ([`Directory::genesis`]). Held here so every task spawned above the transport reads the network from
    /// one place instead of each reaching for the `BeaconSeed::GENESIS` constant, which is what made the
    /// publisher, the directory feeder and the role loop each independently wrong on a network that has a
    /// beacon (`docs/design-genesis.md` §5).
    genesis: BeaconSeed,
}

impl NodeHandle {
    /// This node's overlay coordinate, as of now.
    #[must_use]
    pub fn address(&self) -> Triple {
        *self.addr.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Attach the claim book a self-certifying node resolves against, so layers above can observe it.
    ///
    /// Set here rather than threaded through `spawn_inner` because the book belongs to the *identity* — a node without a
    /// self-certifying identity never resolves a coordinate and has nothing to record.
    #[must_use]
    fn with_claims(mut self, book: ClaimBook) -> Self {
        self.claims = Some(book);
        self
    }

    /// This node's coordinate prover, or `None` without a self-certifying identity.
    ///
    /// `NodeHandle` is deliberately not `Clone` — dropping it shuts the node down — so a background publisher cannot hold
    /// one. It holds this instead: a closure over the credentials, which is the point of the indirection.
    #[must_use]
    pub fn coordinate_prover(&self) -> Option<CoordinateProver> {
        self.identity.as_ref().map(|id| id.prove.clone())
    }

    /// How many peers' coordinate claims this node has verified this epoch, or `None` without a self-certifying identity.
    ///
    /// The observable that lets a scenario tell "it never heard of its rival" apart from "it heard and did not move" — two
    /// failures with the same symptom and different causes.
    #[must_use]
    pub fn verified_claims(&self) -> Option<usize> {
        self.claims.as_ref().map(ClaimBook::len)
    }

    /// The UDP socket address the node is actually bound to (its directory entry).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// This node's **public (reflexive) address** as learned from peers — the address remote peers
    /// observe this node's connections arriving from, once at least `REFLEXIVE_QUORUM` of them agree
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
        self.command(Command::Emit { to: via, frame: connect_req_frame(target) })
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
            addr: self.addr.clone(),
            input_tx: self.input_tx.clone(),
            ctrl_tx: self.ctrl_tx.clone(),
            events_tx: self.events_tx.clone(),
            genesis: self.genesis,
        }
    }

    /// The genesis seed of the network this node is on — see [`Client::genesis`].
    #[must_use]
    pub fn genesis(&self) -> BeaconSeed {
        self.genesis
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
    /// A request for the engine's durable state.
    ///
    /// Correlated by **arrival order** rather than by a digest, because a snapshot has no key: exactly one
    /// `Notification::Snapshot` answers each `Command::Snapshot`, in order, so the front of the queue is the
    /// asker. There is no fan-out at all — see the router's arm for why that matters.
    Snapshot {
        /// Where the durable bytes go.
        reply: oneshot::Sender<Vec<u8>>,
    },
}

/// A cloneable, correlated client for a node. Many tasks share it to issue content-addressed
/// requests (`get`/`put`) that await *only their own* answer — correlated by the storage digest the
/// engine echoes, so concurrent requests never cross — send fire-and-forget commands, or subscribe to
/// the notification stream. This is the concurrency-safe surface a SOCKS5 proxy or a `.fanos` resolver
/// builds on: the single-consumer `next_notification` bottleneck is gone.
#[derive(Clone)]
pub struct Client {
    /// The node's live coordinate — the same shared cell [`NodeHandle`] holds, not a copy of it.
    addr: Arc<Mutex<Triple>>,
    input_tx: mpsc::Sender<Input>,
    ctrl_tx: mpsc::UnboundedSender<Control>,
    events_tx: broadcast::Sender<Notification>,
    genesis: BeaconSeed,
}

impl Client {
    /// This node's overlay coordinate, as of now — the same shared cell [`NodeHandle::address`] reads.
    #[must_use]
    pub fn address(&self) -> Triple {
        *self.addr.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The **genesis seed of the network this node is on** — the beacon value epoch 0 is drawn against.
    ///
    /// Every task that starts before the first `BeaconReady` needs a seed for epoch 0: the mix-key publisher,
    /// the directory feeder a combiner reads, the capability publisher, the role loop. Each of them used to
    /// name `BeaconSeed::GENESIS` directly, which was right only while that constant *was* the network's
    /// seed. Once it is derived per network (`docs/design-genesis.md` §4) a producer on the constant and a
    /// verifier on the constant still agree with each other — and both disagree with the node's own seat, so
    /// the whole genesis epoch silently resolves nothing.
    ///
    /// Reading it from the client is what makes that unrepeatable: there is one seed per node, it arrives with
    /// the transport that already used it to seat this node, and a task added later gets it by asking rather
    /// than by remembering.
    #[must_use]
    pub fn genesis(&self) -> BeaconSeed {
        self.genesis
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

    /// This node's **durable state** as canonical bytes — what a persister writes to disk, and `None` if the
    /// node stopped or did not answer in time.
    ///
    /// Not a subscription. The answer goes to this caller alone, because a snapshot is the whole store and
    /// broadcasting it would clone it once per subscriber (see the router's `Notification::Snapshot` arm).
    pub async fn snapshot(&self) -> Option<Vec<u8>> {
        let (reply, rx) = oneshot::channel();
        if self.ctrl_tx.send(Control::Snapshot { reply }).is_err() {
            return None;
        }
        if self.input_tx.try_send(Input::Command(Command::Snapshot)).is_err() {
            return None;
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(bytes)) => Some(bytes),
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


    /// Store `value` under `key` as **soft state that expires after `epochs` further epoch advances** —
    /// what a directory slot is, as distinct from content ([`Command::PutEphemeral`]).
    ///
    /// Every `(coordinate, epoch)`-keyed directory publisher uses this: without it the store had no way to
    /// know a slot was dead, kept every one ever written, and — being fail-closed on admission — stopped a
    /// cell from publishing anything at all after about a day (`fanos-node/tests/store_lifetime.rs`).
    pub async fn put_ephemeral(&self, key: Vec<u8>, value: Vec<u8>, epochs: u32) -> bool {
        let digest = storage_digest(&key);
        let (reply, rx) = oneshot::channel();
        if self.ctrl_tx.send(Control::Put { digest, reply }).is_err() {
            return false;
        }
        if self
            .input_tx
            .try_send(Input::Command(Command::PutEphemeral { key, value, epochs }))
            .is_err()
        {
            return false;
        }
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
    seat: Arc<Mutex<Triple>>,
) {
    let mut gets: GetWaiters = HashMap::new();
    let mut puts: PutWaiters = HashMap::new();
    // Snapshot askers, in the order they asked, each stamped so the sweep below can drop it.
    //
    // **Stamped for the same reason the maps are, and it is not symmetry for its own sake.** A registration
    // whose `Input` never reaches the engine — `try_send` on a full channel — leaves an asker in this queue
    // that no answer will ever match. Order-correlated means the *next* answer goes to that orphan instead
    // of to whoever earned it: one dropped input silently mis-delivers every snapshot after it. The sweep
    // and the `is_closed` check on the way out make an orphan cost nothing beyond its own request.
    let mut snapshots: VecDeque<(std::time::Instant, oneshot::Sender<Vec<u8>>)> = VecDeque::new();
    // Periodic waiter-map eviction (audit C1): a `get` is self-cleaning (the engine always concludes a
    // `Retrieved` via read-repair exhaustion), but a `put` to a node that never `Ack`s never resolves — so
    // sweep both maps, dropping any waiter whose receiver the client already abandoned (`is_closed`, the
    // common case once its `REQUEST_TIMEOUT` await fired) or that has outlived `REQUEST_TIMEOUT` (the reply
    // is not coming). Dropping the `oneshot::Sender` resolves the client to `None`/`false`. The map thus
    // stays bounded even under a flood of puts to unreachable keys.
    let mut sweep = tokio::time::interval(REQUEST_TIMEOUT);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // **`biased`, and it is the correctness of every `get`/`put` rather than a preference.** A client
        // registers its waiter on `ctrl_rx` and *then* sends the input that makes the engine answer, so the
        // registration is always enqueued strictly first. An unbiased `select!` polls its branches in random
        // order, so whenever this task was busy while both arrived it could take the answer first, find no
        // waiter, drop it — and resolve the registration that arrived next iteration never. The client then
        // waited out `REQUEST_TIMEOUT` and reported a **failure for a write that had succeeded**.
        //
        // Measured at ~2 failures in 12 runs of the FFI round-trip, with a probe that fired on exactly the
        // failing runs (#83). Every directory publisher writes through `put_ephemeral`, so the same race told
        // nodes their own capability/load/onion-key publishes had failed; `get` has the identical shape and
        // could report a stored value absent.
        //
        // Biasing toward `ctrl_rx` restores the order the design already assumed. It cannot starve
        // notifications: a control message is one client call, is `O(1)` to record, and every client that
        // sends one then waits.
        tokio::select! {
            biased;
            ctrl = ctrl_rx.recv() => {
                let Some(ctrl) = ctrl else { break };
                let now = std::time::Instant::now();
                match ctrl {
                    Control::Get { digest, reply } => gets.entry(digest).or_default().push((now, reply)),
                    Control::Put { digest, reply } => puts.entry(digest).or_default().push((now, reply)),
                    Control::Snapshot { reply } => snapshots.push_back((now, reply)),
                }
            }
            note = notify_rx.recv() => {
                let Some(note) = note else { break };
                match &note {
                    // The engine is the only authority on where this node sits, and it has always said so — this
                    // notification existed with no consumer, which is why every layer above reported the coordinate it was
                    // *spawned* at, for the whole life of the node, however many times it reshuffled. Tracking it here
                    // rather than in whoever sent the `Reseat` is the point: recovery, the placement loop and a direct
                    // command are all sources, and each maintaining its own copy is how the stale one survived.
                    Notification::Reseated { new, .. } => {
                        *seat.lock().unwrap_or_else(PoisonError::into_inner) = *new;
                    }
                    // **Answers, not events, and they leave here rather than going on to the broadcast.**
                    // A `Retrieved`/`Stored` is the reply to one caller's `get`/`put`, correlated by digest;
                    // nothing subscribes to either, in any crate. Fanning them out cloned every read value —
                    // up to `MAX_VALUE_LEN` — once per subscriber, and a running node keeps twenty-one, all
                    // of which discarded it. That was not only waste: it was the dominant source of
                    // broadcast volume, and this channel drops messages when a subscriber falls behind, so
                    // it was buying nothing with the budget an epoch-driven publisher needs to not miss a
                    // `BeaconReady`. The `Snapshot` arm below is the same rule for the same reason.
                    Notification::Retrieved { key, value } => {
                        if let Some(waiters) = gets.remove(key) {
                            for (_, tx) in waiters {
                                let _ = tx.send(value.clone());
                            }
                        }
                        continue;
                    }
                    Notification::Stored(key) => {
                        if let Some(waiters) = puts.remove(key) {
                            for (_, tx) in waiters {
                                let _ = tx.send(());
                            }
                        }
                        continue;
                    }
                    // **Delivered to the one asker and never broadcast, and that is a memory bound rather
                    // than tidiness.** A snapshot is the whole store — up to `MAX_STORE_ENTRIES ×
                    // MAX_VALUE_LEN` — and `events_tx.send` hands a *clone* to every subscriber. A running
                    // node keeps eight or so (the mix and exit publishers, the role loop, the beacon
                    // tracker, the recovery watcher…), so fanning it out would allocate the entire store
                    // once per subscriber every snapshot period, from a store any peer can fill. It is a
                    // reply, not an event; nothing subscribes to it because nothing should.
                    Notification::Snapshot(_) => {
                        let Notification::Snapshot(bytes) = note else { unreachable!() };
                        // Skip askers that have already given up, so an abandoned request cannot consume the
                        // answer a live one is waiting for.
                        while let Some((_, tx)) = snapshots.pop_front() {
                            if !tx.is_closed() {
                                let _ = tx.send(bytes);
                                break;
                            }
                        }
                        continue;
                    }
                    _ => {}
                }
                // Fan every notification out to subscribers (Err only if no receivers — ignored).
                let _ = events_tx.send(note);
            }
            _ = sweep.tick() => {
                let now = std::time::Instant::now();
                evict_stale(&mut gets, now);
                evict_stale(&mut puts, now);
                snapshots
                    .retain(|(at, tx)| !tx.is_closed() && now.duration_since(*at) < REQUEST_TIMEOUT);
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
        None, // shaper
        None, // controller
        &None, // identity
        server,
        client,
        default_bind().into(),
        // No `F` here: a bare engine carries no plane to ask, so the base cell's budget stands. A caller
        // running a larger plane reaches the transport through `spawn_self_certifying*`, which derives it.
        REFLEXIVE_QUORUM_FANO,
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
        default_bind().into(),
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
        default_bind().into(),
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
        default_bind().into(),
        Capabilities::CORE,
        None,
    )
}

/// Like [`spawn_self_certifying_persistent`], but binds the QUIC endpoint to an explicit address
/// (e.g. `0.0.0.0:9000` for a publicly reachable node) instead of an ephemeral localhost port. This
/// is the production entry point a node binary uses; the coordinate stays cert-derived and stable.
/// `proteus` enables PROTEUS (§13.4): when `Some`, every frame is shaped with that shared secret under the
/// chosen morph and the shape rotates each epoch; `None` is plaintext QUIC. Peers must share the secret.
pub async fn spawn_self_certifying_persistent_on<F: Field + 'static>(
    bind: SocketAddr,
    credentials: &NodeCredentials,
    make_engine: impl FnOnce(Point<F>) -> Box<dyn Engine + Send>,
    directory: Directory,
    proteus: Option<ProteusConfig>,
) -> Result<NodeHandle, QuicError> {
    let (server, client, _cert) = node_configs_mutual_from(credentials)?;
    self_certifying_inner::<F, _>(
        server,
        client,
        credentials,
        make_engine,
        directory,
        bind.into(),
        Capabilities::CORE,
        proteus,
    )
}

/// Spawn a self-certifying persistent node over an arbitrary [`Fabric`] — the **transport-injection seam**.
///
/// Identical to [`spawn_self_certifying_persistent_on`] except that the caller supplies the datagram carrier. Pass
/// `Fabric::Udp(addr)` for production; pass `Fabric::Abstract(socket)` to run this node — real QUIC, real TLS, real
/// composition — over a modelled fabric. Nothing above the socket changes, which is what makes a simulation built on
/// it differ from a deployment in the transport and *only* the transport.
///
/// # Errors
/// [`QuicError`] if the credentials cannot be turned into a TLS configuration or the endpoint cannot be created.
pub fn spawn_self_certifying_persistent_over<F: Field + 'static>(
    fabric: Fabric,
    credentials: &NodeCredentials,
    make_engine: impl FnOnce(Point<F>) -> Box<dyn Engine + Send>,
    directory: Directory,
    proteus: Option<ProteusConfig>,
) -> Result<NodeHandle, QuicError> {
    let (server, client, _cert) = node_configs_mutual_from(credentials)?;
    self_certifying_inner::<F, _>(
        server,
        client,
        credentials,
        make_engine,
        directory,
        fabric,
        Capabilities::CORE,
        proteus,
    )
}

#[allow(clippy::too_many_arguments)]
fn self_certifying_inner<F: Field + 'static, M>(
    server: ServerConfig,
    client: ClientConfig,
    creds: &NodeCredentials,
    make_engine: M,
    directory: Directory,
    bind: Fabric,
    capabilities: Capabilities,
    proteus: Option<ProteusConfig>,
) -> Result<NodeHandle, QuicError>
where
    M: FnOnce(Point<F>) -> Box<dyn Engine + Send>,
{
    // PROTEUS enablement (§13.4): with a community secret, wrap every frame in the beacon-rotating shape (the
    // configured morph's codec + traffic-shaper) so the transport carries no static FANOS signature and the
    // shape moves each epoch. The shaper starts at the genesis epoch and the `reshuffle_loop` rotates it as
    // the beacon advances (below).
    let (shaper, controller): (Shaper, MaybeController) = match proteus {
        Some(cfg) => {
            let (s, c) = cfg.build(Epoch::ZERO);
            (Some(s), c)
        }
        None => (None, None),
    };
    // The node's verifiable coordinate for the genesis epoch: MapToPoint(VRF(vrf_sk, cert‖0‖GENESIS)),
    // with the proof it announces so peers can verify it (spec §L0/§7.3).
    // The node's own genesis seat, drawn against THIS NETWORK's seed rather than a constant every FANOS
    // deployment shares — see `Directory::for_network` and `docs/design-genesis.md`. The same value seeds the
    // `BeaconWindow` below, and it must be the same value: a node's seat and its peers' verification of that
    // seat are the two halves of one claim.
    let genesis_seed = directory.genesis();
    let (coord, proof, rank) = verifiable_coordinate_ranked::<F>(creds, Epoch::ZERO, &genesis_seed);
    let engine = make_engine(coord);
    // The self-certifying identity is now LIVE across epochs (Level B, #102): the HELLO and the beacon the
    // verifier checks peers against both sit behind locks the `reshuffle_loop` rewrites when the beacon
    // advances. Cold-start values are the genesis coordinate; a node with no beacon simply never reshuffles.
    let hello_cell = Arc::new(RwLock::new(Arc::new(hello_bytes::<F>(
        Epoch::ZERO,
        coord.coords(),
        &CoordinateClaim::direct(proof),
        capabilities,
    ))));
    let beacon_cell = Arc::new(RwLock::new(BeaconWindow::genesis(genesis_seed)));
    let verify_beacon = beacon_cell.clone();
    // Every peer whose claim this node verifies is remembered for the epoch, because coordinate resolution needs exactly
    // that: the best claim on each point of this node's own walk, and a witness for every step it advances
    // (`crate::claims`). The verifier closure is the only place holding a peer's certificate DER — the identity the
    // coordinate VRF binds to — so it is where the recording happens.
    let book = ClaimBook::new();
    let verify_book = book.clone();
    let prover_creds = creds.clone();
    let identity: Identity = Some(SelfCert {
        hello: hello_cell.clone(),
        prove: Arc::new(move |epoch, beacon| {
            let (_, proof) = crate::identity::verifiable_coordinate::<F>(&prover_creds, epoch, beacon);
            (prover_creds.cert_der().to_vec(), prover_creds.vrf_secret().public(), proof)
        }),
        verify: Arc::new(move |peer_cert: &[u8], peer_hello: &[u8]| {
            // Select the beacon for the epoch the peer proves — the current one, or a recent last-good epoch
            // within the accepted window (safe-stall, R-C1). Outside the window ⇒ reject; poisoned ⇒ reject.
            let epoch = hello_epoch(peer_hello)?;
            let beacon = {
                let window = verify_beacon.read().ok()?;
                window.beacon_for(epoch)?
            };
            let result = verify_hello::<F>(peer_cert, peer_hello, &beacon, capabilities)?;
            if let HelloResult::Established { peer, .. } = result {
                // Recorded only on success, so the book holds nothing a remote verifier would reject. A peer proving a
                // *past* epoch within the safe-stall window is deliberately not recorded: its claim is evidence about that
                // epoch's placement, and admitting it here would let a retired placement justify a displacement now.
                if epoch == verify_book.epoch() {
                    verify_book.record::<F>(peer_cert, peer.public, peer.proof, &peer.output);
                }
            }
            Some(result)
        }),
    });
    let dir_for_reshuffle = directory.clone();
    // Snapshot who holds our point **before** `spawn_inner` runs, because `spawn_inner` binds our coordinate to our own
    // address unranked — which overwrites the bootstrap seed. Reading it afterwards always answers "us", which is precisely
    // how the first attempt at this fix silently did nothing.
    let seeded_at_our_point = directory.resolve(coord.coords());
    let handle =
        spawn_inner(
            engine,
            directory,
            shaper.clone(),
            controller,
            &identity,
            server,
            client,
            bind,
            reflexive_quorum(F::Q),
        )?
            .with_claims(book.clone());
    // Re-bind our genesis point *with* its rank — unless someone else's address is already there.
    //
    // `spawn_inner` binds the coordinate before any rank is available to it, and an unranked self-binding is one any
    // newcomer displaces, which for our own point is the eviction the rank rule exists to prevent. But binding
    // *unconditionally* is what stopped coordinate resolution from ever happening. A node whose point is already held by a
    // bootstrap-seeded address overwrote that seed with its own ranked entry — the seed being unranked, it always won — and
    // in doing so **deleted its only route to the incumbent**. It then had no contender in its claim book, `settle_index`
    // saw nothing to move for, and both nodes sat at index 0 each believing it held the point. Measured:
    // `index [0, 0, 0, 0, 0, 0, 0]` on a draw with two contested points.
    //
    // So: if the point resolves to a *different* address, leave that binding alone. Being unbound is the honest state for a
    // contested node — it is what the arbitration would have produced anyway — and it keeps the one route by which this node
    // can ask the incumbent for its claim.
    let contender_at_our_point = seeded_at_our_point.filter(|addr| *addr != handle.local_addr());
    match contender_at_our_point {
        // Contested: restore the incumbent's binding, which `spawn_inner` just overwrote. Being unbound ourselves is the
        // honest state — it is what the arbitration would have produced — and it keeps the one route by which we can ask
        // the incumbent for its claim.
        Some(addr) => dir_for_reshuffle.insert(coord.coords(), addr),
        None => dir_for_reshuffle.insert_ranked(coord.coords(), handle.local_addr(), rank),
    }
    // Drive the per-epoch coordinate reshuffle off the live beacon (spec §L3, §3.2): on each `BeaconReady`
    // the loop re-derives this node's VRF coordinate for the new epoch, re-seats the engine, rebinds its
    // directory coordinate, and publishes the fresh HELLO + beacon so subsequent connections prove/verify
    // the current placement.
    let local_addr = handle.local_addr();
    tokio::spawn(reshuffle_loop::<F>(
        creds.clone(),
        Placement {
            coord: coord.coords(),
            output: rank,
            index: 0,
            epoch: Epoch::ZERO,
            // The seed this node's epoch-0 seat was actually drawn against, not the constant: the reshuffle
            // loop compares against it to decide whether a new beacon moves the coordinate at all.
            beacon: genesis_seed,
            joining: true,
        },
        Reseater {
            capabilities,
            local_addr,
            directory: dir_for_reshuffle,
            hello: hello_cell,
            client: handle.client(),
        },
        beacon_cell,
        book,
        shaper,
        handle.subscribe(),
        contender_at_our_point,
    ));
    Ok(handle)
}

/// A bounded window of recent epoch beacons behind the HELLO verifier. The coordinate proof binds to a
/// specific `(epoch, beacon)`; verifying only against the single newest beacon rejects a peer that proves the
/// current-minus-one epoch — a normal transition race, and precisely the deadlock a beacon *stall* would
/// otherwise cause (a lagging or recovering node can never present the frozen current epoch, so it is turned
/// away as `EPOCH_STALE` and the cell becomes unjoinable). Remembering the last few epochs' beacons lets such
/// a peer attach to the **last good epoch** instead (audit R-C1 safe-stall), while the bound stops a stale
/// proof from being accepted indefinitely.
struct BeaconWindow {
    recent: VecDeque<(Epoch, BeaconSeed)>,
}

impl BeaconWindow {
    /// Accept the current epoch plus this many previous epochs' beacons.
    const DEPTH: usize = 3;

    fn genesis(seed: BeaconSeed) -> Self {
        let mut recent = VecDeque::with_capacity(Self::DEPTH);
        recent.push_back((Epoch::ZERO, seed));
        Self { recent }
    }

    /// Record a newly-adopted epoch beacon, evicting the oldest beyond [`DEPTH`].
    fn adopt(&mut self, epoch: Epoch, beacon: BeaconSeed) {
        if self.recent.iter().any(|&(e, _)| e == epoch) {
            return;
        }
        self.recent.push_back((epoch, beacon));
        while self.recent.len() > Self::DEPTH {
            self.recent.pop_front();
        }
    }

    /// The beacon this window remembers for `epoch`, if it is still within the accepted window.
    fn beacon_for(&self, epoch: Epoch) -> Option<BeaconSeed> {
        self.recent.iter().find(|&&(e, _)| e == epoch).map(|&(_, b)| b)
    }
}

/// The per-epoch coordinate reshuffle driver (spec §L3 "epoch reshuffle", §3.2; task #102). It follows the
/// engine's notification stream and, on each `BeaconReady { epoch, seed }`, re-derives this node's
/// verifiable coordinate `MapToPoint(VRF(vrf_sk, cert ‖ epoch ‖ seed))`, re-seats the overlay engine to it
/// (`Command::Reseat`), and republishes the node's HELLO + the beacon the peer-verifier checks against — so
/// the unpredictable placement rotation that defends against eclipse / path-prediction (the load-bearing
/// defence on the grindable q=2 base cell) is live end to end. Exits when the engine stops.
/// Where this node currently sits, and the material to prove it.
///
/// Tracked as one value because the four move together: a placement is a `(coord, index)` pair justified by an `output`
/// that is only meaningful for its `(epoch, beacon)`. Splitting them into loop-local variables is how a re-seat ends up
/// publishing a claim for one epoch against the beacon of another.
struct Placement {
    coord: Triple,
    output: fanos_vrf::VrfOutput,
    index: u16,
    epoch: Epoch,
    beacon: BeaconSeed,
    /// Whether this node is still **joining** — it has not yet lived through an epoch boundary.
    ///
    /// This is what makes moving safe, and it is a sharper condition than a timer. Committee membership, shard placement
    /// and routing are all derived *at a boundary*, so a node that joined after the current one is in none of those sets:
    /// nothing above it has derived anything from its coordinate yet, and it may re-seat freely. The moment the first
    /// `BeaconReady` arrives, the cell commits to wherever it then sits, and it must stop.
    joining: bool,
}

/// The three surfaces a re-seat has to move together, in one value.
///
/// Grouped because they are never touched apart: a placement that reached the engine but not the directory, or the
/// directory but not the published HELLO, is a node peers cannot dial at a point it believes it holds.
struct Reseater {
    capabilities: Capabilities,
    local_addr: SocketAddr,
    directory: Directory,
    hello: Arc<RwLock<Arc<Vec<u8>>>>,
    client: Client,
}

impl Reseater {
    /// Re-seat the node at `index` on its own probe walk: engine, directory, HELLO.
    ///
    /// Returns `false` only if the engine is gone, which ends the loop. The order matters and is the one the epoch
    /// reshuffle has always used: seat the engine first, then rebind the directory (the new point bound *before* the old
    /// one is cleared, so there is no window in which the node is unroutable), then publish the HELLO.
    fn apply<F: Field>(&self, at: &mut Placement, index: u16, claim: &CoordinateClaim) -> bool {
        let point = fanos_vrf::probe_point::<F>(&at.output, index).coords();
        if !self.client.command(Command::Reseat { coord: point }) {
            return false;
        }
        // Bound with this epoch's rank AND the probed index: the arbitration order is the claim *pair*, so a table
        // recording only the rank would disagree with what every node's own `settle_index` concludes
        // (`Directory::supersedes`).
        self.directory.insert_claimed(point, self.local_addr, at.output, index);
        if point != at.coord {
            self.directory.remove(at.coord);
        }
        if let Ok(mut h) = self.hello.write() {
            *h = Arc::new(hello_bytes::<F>(at.epoch, point, claim, self.capabilities));
        }
        at.coord = point;
        at.index = index;
        true
    }
}

/// The per-epoch coordinate reshuffle **and live collision-resolution** driver (spec §L3 "epoch reshuffle", §3.2;
/// tasks #102 and the probe-index wiring).
///
/// Two triggers, one mechanism:
///
/// * **`BeaconReady`** — re-derive `MapToPoint(VRF(vrf_sk, cert ‖ epoch ‖ seed))` for the new epoch, clear the claim book
///   (a claim proves a placement for one epoch only), and re-seat. This is the unpredictable placement rotation that
///   defends against eclipse and path-prediction.
/// * **any other notification** — re-run [`claims::settle`] against the peers verified since the last check. A node learns
///   of a better claim to its own point only by meeting the peer that holds it, so the moment a peer set changes is exactly
///   the moment a settled index can become stale. There is no separate wake channel because there does not need to be:
///   this loop already sees every notification, and settling is `q + 1` map lookups against a pre-indexed book.
///
/// The index only ever advances within an epoch (`settle_index` is monotone in information), so a node never retracts a
/// point it has already announced — which is what makes acting on partial information safe.
///
/// Exits when the engine stops.
#[allow(clippy::too_many_arguments)]
async fn reshuffle_loop<F: Field>(
    creds: NodeCredentials,
    mut at: Placement,
    seat: Reseater,
    beacon: Arc<RwLock<BeaconWindow>>,
    book: ClaimBook,
    shaper: Shaper,
    mut events: broadcast::Receiver<Notification>,
    contested: Option<SocketAddr>,
) {
    book.adopt(at.epoch);
    // A contested point is only resolvable by learning the incumbent's *claim*, and dialing is by coordinate — so the one
    // pair that must meet is the pair coordinate-addressed introduction cannot introduce. Sending to our own point reaches
    // whoever the directory says holds it, which is exactly the incumbent: the HELLO exchange that follows records its
    // claim (`crate::claims`), which wakes this loop, which then settles onto a point it can prove.
    if let Some(addr) = contested {
        tracing::debug!(?addr, coord = ?at.coord, "our point is already held; asking its holder for its claim");
        seat.client.command(Command::Send { to: at.coord, payload: Vec::new() });
    }
    loop {
        // Why the loop woke. A local enum rather than a `Notification` variant: "a peer's claim was recorded" is this
        // loop's business, not something the engine has any reason to broadcast.
        enum Wake {
            /// The beacon advanced: re-derive for the new epoch.
            Beacon(Epoch, [u8; 32]),
            /// Something changed that could move the settled index — a new peer claim, or any engine notification.
            Resettle,
            /// The engine stopped.
            Stop,
        }
        // Either reason re-settles. A peer completing a handshake is as good a reason as a beacon advancing, and the engine
        // emits no notification for the former — without the book's own signal the loop would only ever move on a beacon.
        let wake = tokio::select! {
            event = events.recv() => match event {
                Ok(Notification::BeaconReady { epoch, seed }) => Wake::Beacon(epoch, seed),
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => Wake::Resettle,
                Err(broadcast::error::RecvError::Closed) => Wake::Stop,
            },
            () = book.changed() => Wake::Resettle,
        };
        match wake {
            Wake::Beacon(epoch, seed) => {
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
                let (_, proof, rank) = verifiable_coordinate_ranked::<F>(&creds, epoch, &seed);
                // Publish the beacon BEFORE the HELLO: a connection accepted between the two then verifies a peer
                // against the newer beacon while announcing the older coordinate — harmless (the peer re-syncs on an
                // epoch mismatch, §7.3), and never the reverse (verifying against a stale beacon). A poisoned lock
                // skips this rotation's publish; the next `BeaconReady` retries.
                if let Ok(mut b) = beacon.write() {
                    b.adopt(epoch, seed);
                }
                at.epoch = epoch;
                at.beacon = seed;
                at.output = rank;
                // The cell commits to placements at a boundary, so from here this node is established and holds its point
                // for the epoch. Everything below re-derives; nothing may move again until the settling window exists.
                at.joining = false;
                // The book's claims belong to the retired epoch; clearing it is what stops a peer's past placement from
                // justifying a displacement now. Settling immediately afterwards therefore lands at index 0 and moves
                // up again as this epoch's peers are met.
                book.adopt(epoch);
                let Some((index, claim)) = claims::settle::<F>(&book, &rank, proof) else {
                    continue; // every point of this epoch's line is better claimed — announce nothing
                };
                if fanos_vrf::probe_point::<F>(&rank, index).coords() == at.coord && index == at.index {
                    continue; // this epoch's VRF landed on the same point — nothing to move
                }
                if !seat.apply::<F>(&mut at, index, &claim) {
                    break;
                }
            }
            // A recorded claim moves this node **only while it is still joining** — before the first epoch boundary it
            // lives through. That is the increment `docs/design-coordinates.md` calls settle-on-join, and the safety
            // argument is structural rather than a timeout: committee membership, shard placement and every routing table
            // are derived at a *boundary*, so a node that joined after the current one is in none of those sets. Nothing
            // above it has derived anything from its coordinate, so re-seating invalidates nothing.
            //
            // An **established** node still does not move, and must not: it is in those sets, and moving mid-epoch leaves
            // the rest of the cell holding state for a position it has left. Fixing *that* case needs the settling window
            // (a bounded phase at the start of each epoch, before the layers above commit), which is designed and not yet
            // built. Whether moving an established node is in fact harmful is **unverified** rather than disproven — the
            // measurement that appeared to show it breaking consensus was a load artefact the baseline refuted — and "do
            // not move a node the cell has committed to" is the right default while that is open.
            Wake::Resettle if at.joining => {
                let (_, proof, _) = verifiable_coordinate_ranked::<F>(&creds, at.epoch, &at.beacon);
                let Some((index, claim)) = claims::settle::<F>(&book, &at.output, proof) else {
                    continue; // beaten on every point of the line; hold the current announcement rather than retract it
                };
                if index == at.index {
                    continue; // still the right seat
                }
                if !seat.apply::<F>(&mut at, index, &claim) {
                    break;
                }
            }
            Wake::Resettle => {}
            Wake::Stop => break,
        }
    }
}

/// Like [`spawn`], but every frame on the wire is PROTEUS-shaped by `proteus` for `epoch` (spec §13.2): the
/// transport carries no static FANOS signature, and a peer without the secret cannot produce frames this node
/// will accept. The engine is unchanged — shaping lives entirely in the driver, below the sans-I/O boundary.
pub async fn spawn_shaped(
    engine: Box<dyn Engine + Send>,
    directory: Directory,
    proteus: ProteusConfig,
    epoch: Epoch,
) -> Result<NodeHandle, QuicError> {
    let (shaper, controller) = proteus.build(epoch);
    let (server, client) = node_configs()?;
    spawn_inner(
        engine,
        directory,
        Some(shaper),
        controller,
        &None, // identity
        server,
        client,
        default_bind().into(),
        // No `F` here: a bare engine carries no plane to ask, so the base cell's budget stands. A caller
        // running a larger plane reaches the transport through `spawn_self_certifying*`, which derives it.
        REFLEXIVE_QUORUM_FANO,
    )
}

/// Where a node's QUIC endpoint gets its datagrams — **the transport seam**.
///
/// Production binds a real UDP socket. [`Fabric::Abstract`] hands quinn an
/// [`AsyncUdpSocket`](quinn::AsyncUdpSocket) instead, which is what lets a simulator run **real nodes** — real QUIC
/// state machine, real TLS, real node composition — over a modelled datagram fabric. Everything above the socket is
/// then byte-for-byte the production path, so the simulator differs from a deployment in the transport and *only* the
/// transport (`docs/design-testing.md` §5.1).
///
/// The distinction matters because the composition above this line is where wiring bugs live, and a simulator that
/// instantiates engines directly cannot see them.
pub enum Fabric {
    /// A real UDP socket bound at this address — production, and the T3/T4 test tiers.
    Udp(SocketAddr),
    /// An abstract socket supplied by the caller — the simulator's in-memory fabric.
    Abstract(Arc<dyn quinn::AsyncUdpSocket>),
}

impl From<SocketAddr> for Fabric {
    fn from(bind: SocketAddr) -> Self {
        Self::Udp(bind)
    }
}

impl core::fmt::Debug for Fabric {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Udp(addr) => f.debug_tuple("Udp").field(addr).finish(),
            Self::Abstract(_) => f.write_str("Abstract(<socket>)"),
        }
    }
}

/// Bind the endpoint and spawn the driver actors. Synchronous (only sets up channels and
/// `tokio::spawn`s tasks); the public wrappers stay `async` for API stability.
#[allow(clippy::too_many_arguments)]
fn spawn_inner(
    engine: Box<dyn Engine + Send>,
    directory: Directory,
    shaper: Shaper,
    controller: MaybeController,
    identity: &Identity,
    mut server_cfg: ServerConfig,
    mut client_cfg: ClientConfig,
    fabric: Fabric,
    reflexive_quorum: usize,
) -> Result<NodeHandle, QuicError> {
    let addr = engine.address();

    // Apply production transport tuning (keep-alive + idle timeout) to both directions.
    server_cfg.transport_config(tuned_transport());
    client_cfg.transport_config(tuned_transport());

    let mut endpoint = match fabric {
        Fabric::Udp(bind) => Endpoint::server(server_cfg, bind)?,
        // The same endpoint over a caller-supplied socket: identical QUIC/TLS configuration, only the datagram
        // carrier differs.
        Fabric::Abstract(socket) => Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_cfg),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?,
    };
    endpoint.set_default_client_config(client_cfg);
    let local_addr = endpoint.local_addr()?;
    directory.insert(addr, local_addr);
    // Read before the directory is moved into the transport: this is the network identity every task above
    // the transport asks the handle for, so it is captured once rather than re-derived.
    let genesis = directory.genesis();
    tracing::debug!(?addr, %local_addr, self_certifying = identity.is_some(), "fanos-quic node up");

    let (input_tx, input_rx) = mpsc::channel::<Input>(INPUT_CAP);
    let (send_tx, send_rx) = mpsc::unbounded_channel::<SendRequest>();
    let (notify_tx, notify_rx) = mpsc::unbounded_channel::<Notification>();
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<Control>();
    let (events_tx, events_rx) = broadcast::channel::<Notification>(4096);
    let conns: ConnMap = Arc::new(Mutex::new(HashMap::new()));
    let reflexive: Reflexive = Arc::new(Mutex::new(ReflexiveAddr::new(reflexive_quorum)));
    let peer_addrs: PeerAddrs = Arc::new(Mutex::new(HashMap::new()));
    // Identity-keyed distrust, shared between the engine loop (which sees verdicts) and the accept path (which sees who
    // is seated where) — audit R-M1.
    let distrust: Arc<Distrust> = Arc::new(Distrust::default());
    // The one live coordinate cell every handle and client above shares. A copy per layer is what let the reported
    // coordinate go stale at the first reshuffle.
    let seat = Arc::new(Mutex::new(addr));

    // One shared context object drives both the accept/receive path and the send path.
    let transport = Transport {
        endpoint: endpoint.clone(),
        conns,
        input_tx: input_tx.clone(),
        events_tx: events_tx.clone(),
        shaper,
        controller,
        identity: identity.clone(),
        me: addr,
        reflexive: reflexive.clone(),
        peer_addrs,
        directory,
        distrust: distrust.clone(),
        punching: Arc::new(Mutex::new(BTreeSet::new())),
    };
    tokio::spawn(announce_moves(transport.clone(), events_tx.subscribe()));
    tokio::spawn(accept_loop(transport.clone()));
    tokio::spawn(transport_loop(transport, send_rx));
    tokio::spawn(engine_loop(
        engine,
        input_rx,
        input_tx.clone(),
        send_tx,
        notify_tx,
        distrust,
    ));
    // The router owns the notification stream: it correlates get/put replies and fans events out.
    tokio::spawn(router_loop(notify_rx, ctrl_rx, events_tx.clone(), seat.clone()));

    Ok(NodeHandle {
        addr: seat,
        local_addr,
        input_tx,
        ctrl_tx,
        events_tx,
        events_rx,
        endpoint,
        reflexive,
        claims: None,
        identity: identity.clone(),
        // The same value this node was seated against — one network, one seed, read once here.
        genesis,
    })
}

/// The engine actor: the sole owner of the engine, dispatching its effects.
async fn engine_loop(
    mut engine: Box<dyn Engine + Send>,
    mut input_rx: mpsc::Receiver<Input>,
    input_tx: mpsc::Sender<Input>,
    send_tx: mpsc::UnboundedSender<SendRequest>,
    notify_tx: mpsc::UnboundedSender<Notification>,
    distrust: Arc<Distrust>,
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
                    // Audit R-M1: a verdict is about the *identity* seated at that coordinate, not about the point. The
                    // driver is the only component that knows which, so it banks it here — before the notification goes
                    // on, since a consumer may act on it.
                    if let Notification::Quarantined(coord) = note {
                        distrust.observe_verdict(coord);
                    }
                    let _ = notify_tx.send(note);
                }
            }
        }
    }
}

/// **Identity-keyed distrust** — the driver's half of audit R-M1.
///
/// The engine drops frames by coordinate, because that is all it routes on and it is crypto-free. But a coordinate is a
/// per-epoch VRF placement, so a tag left on one aliases the moment a node moves: a Byzantine identity sheds it by the
/// epoch turning, and an innocent identity landing on that point inherits it. The second is worse — a denial of service
/// against an honest node caused by nothing but the clock.
///
/// Identity lives here because this is where it is **authenticated**: the HELLO exchange verified
/// `coord = MapToPoint(VRF(sk, cert ‖ epoch ‖ beacon))` against the peer's certificate, so the driver — and only the
/// driver — knows which identity sits where. It therefore holds distrust by identity and keeps the engine's
/// coordinate-keyed view honest, re-issuing [`Command::Quarantine`] when a distrusted identity moves and
/// [`Command::Readmit`] when a coordinate's occupant changes.
#[derive(Default)]
struct Distrust {
    /// Identity → when it was quarantined. Keyed by a hash of the peer certificate, which is what the coordinate proof
    /// is bound to, so the key is exactly as unforgeable as the coordinate itself.
    by_identity: Mutex<HashMap<[u8; 32], StdInstant>>,
    /// Coordinate → the identity currently seated there, so a change of occupant is observable.
    seated: Mutex<HashMap<Triple, [u8; 32]>>,
}

/// A peer's stable identity: the hash of the certificate its coordinate proof is bound to.
fn identity_of(cert_der: &[u8]) -> [u8; 32] {
    fanos_primitives::hash::hash_labeled(fanos_primitives::hash::label::NODE_ID, cert_der)
}

impl Distrust {
    /// Record the engine's verdict against the *identity* seated at `coord`, so it survives the peer moving.
    ///
    /// A verdict about a coordinate nobody is seated at is dropped rather than stored: there is no identity to blame, and
    /// storing it keyed by the coordinate would reintroduce the aliasing this exists to remove.
    fn observe_verdict(&self, coord: Triple) {
        let Ok(seated) = self.seated.lock() else { return };
        let Some(&id) = seated.get(&coord) else { return };
        if let Ok(mut by_id) = self.by_identity.lock() {
            by_id.entry(id).or_insert_with(StdInstant::now);
        }
    }

    /// Seat `id` at `coord` and return the commands the engine needs to stay consistent.
    ///
    /// Two independent corrections, and both matter:
    /// * the coordinate's occupant **changed** ⇒ [`Command::Readmit`], so the arriving identity does not inherit a
    ///   verdict it never earned;
    /// * the arriving identity is **still distrusted** ⇒ [`Command::Quarantine`], so it cannot shed a verdict by moving.
    ///
    /// Both can fire at once — a distrusted identity moving onto a point vacated by another distrusted one — and the
    /// order matters: clear first, then re-apply, or the re-application is undone.
    fn seat(&self, coord: Triple, id: [u8; 32]) -> Vec<Command> {
        let mut cmds = Vec::new();
        let replaced = match self.seated.lock() {
            Ok(mut seated) => seated.insert(coord, id).is_some_and(|prev| prev != id),
            Err(_) => return cmds,
        };
        if replaced {
            cmds.push(Command::Readmit { coord });
        }
        let distrusted = match self.by_identity.lock() {
            Ok(mut by_id) => {
                // Expire on read against the *engine's* window, so the two halves never disagree about who is trusted.
                let ttl = std::time::Duration::from_nanos(fanos_runtime::QUARANTINE_TTL.as_nanos());
                by_id.retain(|_, since| since.elapsed() <= ttl);
                by_id.contains_key(&id)
            }
            Err(_) => false,
        };
        if distrusted {
            cmds.push(Command::Quarantine { coord });
        }
        cmds
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
    // Hubs already asked to broker a punch to `to` — see the relay branch below. Local to this worker, so
    // it needs no lock, and bounded by the plane's point count because a hub is a peer coordinate.
    let mut asked: BTreeSet<Triple> = BTreeSet::new();
    // The address whose dial already failed — see the reachability decision below. Per-peer, because this
    // worker is.
    let mut dead_addr: Option<SocketAddr> = None;
    while let Some(frame) = rx.recv().await {
        // Resolve `to` to a live connection. A live cached connection *is* reachability, so it is checked
        // first and a peer we never learned an address for is still routable in reverse (#119).
        //
        // **A dial that already failed is not waited for a second time.** After a hole-punch fails, the
        // hub's brokered address stays in the directory, so this used to call `get_or_connect` on every
        // frame — a fresh QUIC handshake awaited to `DIAL_TIMEOUT` before falling back to the relay that
        // was always going to carry it. Measured on the modelled-NAT harness: four frames to one
        // symmetric-NAT peer cost four full dials and 30 NAT-rejected datagrams, with the frame path
        // blocked for the timeout each time. The failures also feed `apply_outcome(false)` and so the
        // morph auto-fallback breaker (§13.7), which means an unreachable peer reads as a censored morph.
        //
        // The rule is the same one the `asked` guard below already derives: re-trying the same thing
        // cannot yield a different answer while the mappings hold, and a *different* address is genuinely
        // new information. So the first dial to an address is awaited exactly as before — the common path
        // is unchanged, and in particular a first frame to a reachable peer still goes direct rather than
        // being disclosed to a hub — and a repeat of a *failed* address is skipped rather than retried.
        //
        // **What recovers, with no timer anywhere.** A different address in the directory retries (the
        // condition below is on the address, not on "have we ever failed"). An inbound connection from the
        // peer is found by `cached` above, so reverse reachability needs no dial at all. And the epoch
        // reshuffle ends this state by construction: coordinates are redrawn per epoch, so `to` becomes a
        // new point, the dispatcher starts a new worker for it, and this cache is gone — its lifetime is
        // exactly one epoch without a constant being chosen for it. A background retry loop was written
        // first and deleted: at one dial per `DIAL_TIMEOUT` for as long as traffic flows it is a retry
        // timer wearing a derivation's clothes, and it re-creates a smaller copy of the amplification this
        // change exists to remove.
        let direct = match t.directory.resolve(to) {
            Some(addr) if dead_addr != Some(addr) => {
                let conn = get_or_connect(&t, to, addr).await;
                if conn.is_none() {
                    dead_addr = Some(addr);
                }
                conn
            }
            // Known-dead address, or none at all: whatever is already live, and no waiting.
            _ => cached(&t.conns, to),
        };
        if let Some(conn) = direct {
            send_uni(&conn, &t.shaper, &frame).await;
        } else if let Some((hub_coord, hub)) = pick_relay_hub(&t.conns, to) {
            // **Try to stop relaying before settling into it.** The relay below is the fallback for the case
            // a hole-punch cannot fix, but nothing in a running node ever *asked* for a punch — `hole_punch`
            // had no caller outside its own test — so every NAT-to-NAT pair relayed all of its traffic
            // through a third node, permanently. That is a bandwidth amplifier on the hub, and on an
            // anonymity network it also hands that hub a volume vantage on the pair: a `Relay` names its
            // `target` and `origin` in the clear to the forwarder, where a punched connection names nothing.
            //
            // **Once per hub, and the bound is derived rather than a retry interval.** Whether a punch
            // succeeds is a function of the two NATs and the broker that describes them; re-asking the same
            // broker about the same pair cannot yield a different answer while the mappings hold. A
            // *different* hub is genuinely new information — it observed a different mapping — so it gets its
            // own attempt. That needs no timer and no chosen period, and it is bounded by the peer count.
            if asked.insert(hub_coord) {
                send_uni(&hub, &t.shaper, &connect_req_frame(to)).await;
            }
            // Symmetric-NAT relay fallback (#119): `to` is unreachable directly (no address, no cached
            // connection — the case a symmetric NAT leaves after even a hole-punch fails). Wrap the frame
            // (with ourselves as origin, so `to`'s reply routes back the same way) and ask a hub we CAN
            // reach to forward it, so any pair behind NAT still communicates. The hub forwards only to a
            // peer it already holds a connection to, so this reaches `to` iff some common node connects both
            // ends — exactly the topology the overlay's cell membership creates. This frame relays either
            // way: a punch is asynchronous, and the traffic must not wait on it.
            send_uni(&hub, &t.shaper, &encode_relay(to, t.me, &frame)).await;
        } else {
            // Genuinely unroutable (no direct path and no hub): drop, counted + logged so it is observable.
            t.directory.note_unresolved_drop(to);
        }
    }
}

/// Write one frame as a single shaped uni-stream on `conn` (the shared send primitive). When the active
/// morph time-shapes (§13.3), the frame is paced by the shaper's per-packet delay first — the traffic-shaper
/// applied at the one point every data frame passes through.
async fn send_uni(conn: &Connection, shaper: &Shaper, frame: &[u8]) {
    let (wire, delay) = shape_out_timed(shaper, frame);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    if let Ok(mut stream) = conn.open_uni().await
        && stream.write_all(&wire).await.is_ok()
    {
        let _ = stream.finish();
    }
}

/// A live cached connection to any peer other than `exclude` — a hub to relay through when `exclude` is
/// not directly reachable (#119) — **with its coordinate**, which the caller needs to remember which hubs it
/// has already asked to broker a punch. `None` if this node has no other live connection to relay via.
fn pick_relay_hub(conns: &ConnMap, exclude: Triple) -> Option<(Triple, Connection)> {
    let map = conns.lock().ok()?;
    for (&peer, conn) in map.iter() {
        if peer != exclude && conn.close_reason().is_none() {
            return Some((peer, conn.clone()));
        }
    }
    None
}

/// A [`ConnectReq`](FrameType::ConnectReq) frame asking a hub to broker a hole-punch to `target`. One
/// builder, so the manual [`hole_punch`](Driver::hole_punch) call and the send path's automatic attempt can
/// never drift onto different encodings.
fn connect_req_frame(target: Triple) -> Vec<u8> {
    let mut frame = Vec::new();
    encode_frame(FrameType::ConnectReq.code(), &encode_triple(target), &mut frame);
    frame
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
    // A connect failure (the transport refused/timed out) feeds the morph auto-fallback breaker: a censored
    // morph manifests exactly as connects that never complete (§13.7). A completed handshake resets it — the
    // shaped transport is getting through, whatever the peer's identity check below concludes.
    let established = match t.endpoint.connect(addr, "fanos.node") {
        Ok(connecting) => tokio::time::timeout(DIAL_TIMEOUT, connecting)
            .await
            .ok()
            .and_then(Result::ok),
        Err(_) => None,
    };
    let Some(conn) = established else {
        apply_outcome(&t.shaper, &t.controller, false);
        return None;
    };
    apply_outcome(&t.shaper, &t.controller, true);

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
                // Audit R-M1: the HELLO exchange just proved this peer's coordinate against its certificate, so this is
                // the one moment the identity↔coordinate binding is known. Seat it, and issue whatever the engine needs
                // to stay consistent — clear a stale tag if the occupant changed, re-apply one if this identity is
                // still distrusted. Both can fire, and `seat` orders them so the re-application is not undone.
                if let Some(cert) = peer_cert_der(&conn) {
                    for cmd in t.distrust.seat(from, identity_of(&cert)) {
                        let _ = t.input_tx.send(Input::Command(cmd)).await;
                    }
                }
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
            // The claim material is recorded by the verifier closure itself (`spawn_self_certifying`), which is the only
            // place holding the peer's certificate DER — the identity the coordinate VRF binds to.
            peer: _,
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

/// Tell every live peer when this node moves, by re-sending its (already updated) `HELLO` on each open connection.
///
/// The other half of `read_frames`' `Hello` arm. A move is only useful if the peers this node already has hear about it:
/// they hold the connection filed under the coordinate proved at handshake time, and nothing else would ever correct it.
/// New connections were never the problem — they read the fresh HELLO anyway.
///
/// Driven off `Notification::Reseated` rather than from whoever issued the move, for the same reason the reported
/// coordinate is: the engine is the authority on where this node sits, and every mover — the placement loop, recovery, a
/// direct command — should be announced identically.
async fn announce_moves(t: Transport, mut events: broadcast::Receiver<Notification>) {
    loop {
        match events.recv().await {
            Ok(Notification::Reseated { .. }) => {
                let Some(hello) = t.identity.as_ref().and_then(|id| id.hello.read().ok().map(|h| h.clone())) else {
                    continue;
                };
                // Snapshot the peer set, then send outside the lock: a send awaits, and holding a `std::sync::Mutex`
                // across an await is how a transport deadlocks itself.
                let peers: Vec<Connection> = match t.conns.lock() {
                    Ok(map) => map.values().cloned().collect(),
                    Err(_) => continue,
                };
                for conn in peers {
                    send_hello(&conn, &t.shaper, &hello).await;
                }
            }
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// The peer's **new** coordinate from a mid-connection `HELLO`, if it verifies and actually differs from `known`.
///
/// `None` when there is no self-certifying identity to check against (a build that never verified coordinates cannot start
/// trusting them here), when the claim does not verify, or when the peer re-announced the point it already held.
fn verified_move(t: &Transport, conn: &Connection, frame: &[u8], known: Triple) -> Option<Triple> {
    let id = t.identity.as_ref()?;
    let cert = peer_cert_der(conn)?;
    match (id.verify)(&cert, frame)? {
        HelloResult::Established { coord, .. } => (coord != known).then_some(coord),
        HelloResult::Incompatible(_) => None,
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
    // Mutable because a peer may **move**: a coordinate is not fixed for the life of a connection (spec §L3 reshuffle, and
    // within an epoch when a better claim displaces the peer). A verified move re-keys this connection and re-attributes
    // every frame after it, so the peer stays reachable at the point it actually holds.
    let mut from = from;
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
                // A peer announcing that it **moved**: the same `HELLO` body, arriving mid-connection.
                //
                // Without this, a live connection stays filed under the coordinate the peer proved at handshake time and
                // nothing is filed under its new one — so a node that resolved a coordinate collision became unreachable to
                // the peers it already had. Measured before this existed: with placement fully resolved (`occupied = 5 of
                // 5`) roster convergence still froze at `[4, 4, 3, 4, 2]`.
                //
                // Re-keying is gated on **exactly the handshake's own check** (`SelfCert::verify` — a coordinate claim
                // proved against the peer's authenticated certificate), so a peer can only ever move *itself*, and only to
                // a point it can prove. Re-keying on an unverified announcement would be a coordinate-hijack primitive.
                //
                // The live connection is preserved rather than dropped, which is the design's own principle: a live
                // connection *is* the reachability, and the peer that accepted it may hold no listen address for us.
                Some(FrameType::Hello) => {
                    if let Some(moved) = verified_move(&t, &conn, &frame, from) {
                        tracing::debug!(?from, ?moved, "peer moved; re-keying its live connection");
                        if let Ok(mut map) = t.conns.lock() {
                            map.remove(&from);
                            map.insert(moved, conn.clone());
                        }
                        if let Ok(mut map) = t.peer_addrs.lock()
                            && let Some(addr) = map.remove(&from)
                        {
                            map.insert(moved, addr);
                        }
                        // Tell the layers above: the cell's coordinate composition changed without its peer *count*
                        // changing, so nothing else would prompt a re-derivation until the mover's own backoff expired.
                        let _ = t.events_tx.send(Notification::PeerMoved { old: from, new: moved });
                        from = moved;
                    }
                    continue;
                }
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

/// Act on a hub's `PunchTo` (#119): dial `peer` at once at the address the hub observed it at, punching
/// our NAT open for the peer's simultaneous inbound. The dial runs on a spawned task so a slow or filtered
/// punch never blocks this connection's frame loop.
///
/// # What this frame is allowed to cause, and why it is bounded
///
/// A `PunchTo` is **unsolicited on one side by construction**: the hub tells *both* parties to dial, and the
/// target never sent a `ConnectReq`. The simultaneous open needs that — each side's own outbound packet is
/// what opens its mapping for the other's — so "only act on a punch I asked for" would break the mechanism
/// on the side that did not ask. The receive path therefore cannot correlate, and must bound instead.
///
/// Before it did, this function took `(peer, addr)` off the frame, wrote the directory, and spawned a dial,
/// consulting neither the sender nor any cap. Any established peer — and the fault budget tolerates `f` of
/// them — could therefore point this node's QUIC Initials at **any address it named**, as many times as it
/// liked. That is an outward harm before it is a local one: a fleet of FANOS nodes becomes a reflector
/// aimed at a third party who never joined anything.
///
/// Two bounds, each derived rather than chosen:
///
/// * **No directory write until the identity is proven.** `get_or_connect` already refuses a peer that does
///   not prove the dialed coordinate, and caches the connection only on success — so the address is worth
///   recording exactly when that returns `Some`, and not a moment before. Writing first meant a single
///   peer's say-so replaced the address of any coordinate it named, which is the very write `#50` hardened
///   behind a quorum one frame along (`ObservedAddr`), left open here.
/// * **At most one outstanding punch dial per coordinate**, tracked as a set of coordinates rather than a
///   counter. That is the same rule the neighbouring guards derive — re-trying the same thing cannot yield
///   a different answer while the mappings hold — and it makes the ceiling fall out of the address space
///   instead of being asserted: a coordinate is a point of the plane, so at most `q² + q + 1` punches can
///   ever be in flight, whatever an attacker sends. A repeat while one is outstanding is dropped rather
///   than queued, because a punch is a *timing* operation and one held until a slot frees has already
///   missed the simultaneous open.
fn accept_holepunch(t: &Transport, body: &[u8]) {
    let Some((peer, addr)) = decode_punch(body) else {
        return;
    };
    // Claim the coordinate, or drop: a punch toward a peer we are already punching adds nothing, and
    // dropping it is what makes the in-flight count bounded by the plane rather than by the sender.
    let claimed = match t.punching.lock() {
        Ok(mut set) => set.insert(peer),
        Err(_) => false,
    };
    if !claimed {
        return;
    }
    let t = t.clone();
    tokio::spawn(async move {
        let reached = get_or_connect(&t, peer, addr).await.is_some();
        if reached {
            // Proven: whoever answered at that address proved the dialed coordinate. Only now is the
            // address worth recording, so subsequent overlay sends resolve directly and stop needing the
            // hub.
            t.directory.insert(peer, addr);
        }
        if let Ok(mut set) = t.punching.lock() {
            set.remove(&peer);
        }
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

/// A pass-through [`AsyncUdpSocket`](quinn::AsyncUdpSocket) over a tokio UDP socket — the identity fabric.
///
/// It exists to prove the [`Fabric::Abstract`] seam carries a *real* node: same QUIC, same TLS, same driver actors,
/// datagrams reaching the wire through an injected socket rather than one quinn bound itself. A simulator's fabric
/// replaces the body of these methods with a modelled carrier (latency, jitter, loss, partition); the seam it plugs
/// into is this one.
///
/// **Readiness is the whole difficulty.** `poll_recv` must register the caller's waker when it has nothing to hand
/// back — returning a bare `Poll::Pending` compiles, type-checks, and then silently never receives another datagram,
/// because nothing will ever wake the task. Hence `tokio::net::UdpSocket` rather than a raw one: its
/// `poll_recv_ready`/`poll_send_ready` do the reactor registration. Any simulated fabric owes the same contract to
/// whatever queue backs it.
#[cfg(test)]
#[derive(Debug)]
struct PassThroughFabric {
    socket: tokio::net::UdpSocket,
    /// Datagrams handed to this fabric by the node — the evidence that real node traffic crosses the seam.
    sent: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl PassThroughFabric {
    fn bound(addr: SocketAddr) -> std::io::Result<Arc<Self>> {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(Arc::new(Self {
            socket: tokio::net::UdpSocket::from_std(socket)?,
            sent: std::sync::atomic::AtomicUsize::new(0),
        }))
    }

    fn sent(&self) -> usize {
        self.sent.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
impl quinn::AsyncUdpSocket for PassThroughFabric {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(WritablePoller(self))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> std::io::Result<()> {
        self.sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.socket.try_send_to(transmit.contents, transmit.destination).map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let (Some(buf), Some(slot)) = (bufs.first_mut(), meta.first_mut()) else {
            return std::task::Poll::Ready(Ok(0));
        };
        loop {
            // Register interest *before* attempting the read, so a datagram arriving between the two still wakes us.
            std::task::ready!(self.socket.poll_recv_ready(cx))?;
            match self.socket.try_recv_from(buf) {
                Ok((len, addr)) => {
                    *slot = quinn::udp::RecvMeta { addr, len, stride: len, ecn: None, dst_ip: None };
                    return std::task::Poll::Ready(Ok(1));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {} // spurious readiness; re-register
                Err(e) => return std::task::Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

/// Writability half of the fabric's readiness contract — the same registration discipline as `poll_recv`.
#[cfg(test)]
#[derive(Debug)]
struct WritablePoller(Arc<PassThroughFabric>);

#[cfg(test)]
impl quinn::UdpPoller for WritablePoller {
    fn poll_writable(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.socket.poll_send_ready(cx)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::verifiable_coordinate;
    use fanos_field::F2;

    #[tokio::test]
    #[ignore = "heavy real-node fixture, superseded by fanos-sim's fabric suite — see the note above"]
    async fn the_fabric_seam_carries_real_node_traffic() {
        // The transport-injection seam (docs/design-testing.md §5.1): a node spawned over Fabric::Abstract is the
        // SAME node — same QUIC state machine, same TLS, same driver actors — with its datagrams flowing through a
        // caller-supplied socket. A simulator substitutes a modelled carrier at exactly this point, which is what
        // lets it run the real node COMPOSITION rather than bare engines.
        //
        // Proven by two fabric-injected nodes dialling each other: the assertion is that node traffic actually
        // crosses the injected sockets, which is the property a simulated fabric depends on.
        use fanos_runtime::{Config, OverlayNode};

        let directory = Directory::new();
        let mut fabrics = Vec::new();
        let mut handles = Vec::new();
        for _ in 0..2 {
            let credentials = NodeCredentials::generate().expect("credentials");
            let fabric = PassThroughFabric::bound(SocketAddr::from(([127, 0, 0, 1], 0))).expect("fabric binds");
            let handle = spawn_self_certifying_persistent_over::<F2>(
                Fabric::Abstract(fabric.clone()),
                &credentials,
                |point| Box::new(OverlayNode::<F2>::new(point, Config::default())),
                directory.clone(),
                None,
            )
            .expect("a node spawns over the injected fabric");
            assert!(handle.local_addr().port() > 0, "the injected socket is bound");
            assert_eq!(handle.client().address(), handle.address(), "the client addresses the same node");
            fabrics.push(fabric);
            handles.push(handle);
        }

        // Ask one to reach the other. Whether the overlay operation itself succeeds is not the point (a two-node
        // subset of a seven-point plane is not a whole cell); the point is that the attempt drives real QUIC
        // datagrams through the injected socket.
        //
        // `#[ignore]`d deliberately, and not because it is flaky in itself. This is the only test in this crate's lib
        // suite that stands up two full self-certifying nodes with real TLS, so on a contended host it starves against
        // the 32 light tests beside it and its own binary's neighbours: measured 0.11 s alone, 183 s (hitting its
        // ceiling) inside the full lib run. Widening the ceiling only lengthens the failure, and an in-process lock has
        // nothing to serialize against here — the competition is cross-binary.
        //
        // It is kept as an on-demand driver-level smoke test rather than deleted, but the property it asserts — real
        // node traffic crossing an injected `Fabric::Abstract` socket — is covered more thoroughly, and by the same
        // seam, by `fanos_sim::fabric`'s `real_nodes_exchange_traffic_over_the_modelled_carrier` and the composed-node
        // fleet tests beside it. An intermittently-red gate is worse than an explicitly-named exclusion
        // (`docs/design-testing.md` §5.3.6).
        //
        // A poll-until ceiling exists only to turn a hang into a failure, so it is sized for a *loaded* machine, not an
        // idle one: the healthy path exits in well under a second and pays nothing for the headroom, while a ceiling
        // tuned to the idle case is itself a defect — it converts machine contention into a false red. Measured: this
        // test missed a ~20 s ceiling under a full-workspace parallel run while passing in 1 s alone.
        // Written as poll-until-observed with a generous deadline rather than "wait N then assert" — the latter
        // passed alone and failed under concurrent test load, which is the flake shape §5 of docs/design-testing.md
        // records. The property is *that* traffic crosses the fabric, never how promptly.
        let dialer = handles.first().expect("two nodes").client();
        let dial = tokio::spawn(async move { dialer.get(b"fabric-seam/key".to_vec()).await });
        let mut crossed = 0;
        for _ in 0..1_800 {
            crossed = fabrics.iter().map(|f| f.sent()).sum::<usize>();
            if crossed > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        dial.abort();
        assert!(crossed > 0, "real node traffic crossed the injected fabric");

        for handle in handles {
            handle.shutdown();
        }
    }

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

    #[test]
    fn the_beacon_window_admits_recent_epochs_and_evicts_beyond_its_depth() {
        // Safe-stall (R-C1): the HELLO verifier remembers the last DEPTH epochs' beacons, so a peer proving a
        // recent last-good epoch is admitted (no EPOCH_STALE deadlock), while a truly stale epoch falls out.
        let mut w = BeaconWindow::genesis(BeaconSeed::GENESIS);
        assert_eq!(w.beacon_for(Epoch::ZERO), Some(BeaconSeed::GENESIS));

        let b1 = BeaconSeed::new([1; 32]);
        w.adopt(Epoch::new(1), b1);
        assert_eq!(w.beacon_for(Epoch::new(1)), Some(b1), "the current epoch verifies");
        assert_eq!(
            w.beacon_for(Epoch::ZERO),
            Some(BeaconSeed::GENESIS),
            "a peer one epoch behind still attaches to its last-good epoch"
        );

        // Advance past the window depth: the oldest epoch is evicted, so a stale proof cannot live forever.
        for e in 2..=(BeaconWindow::DEPTH as u64) {
            w.adopt(Epoch::new(e), BeaconSeed::new([e as u8; 32]));
        }
        assert_eq!(w.beacon_for(Epoch::ZERO), None, "an epoch beyond the window is no longer admitted");
        assert!(
            w.beacon_for(Epoch::new(BeaconWindow::DEPTH as u64)).is_some(),
            "the newest epoch is admitted"
        );
        assert_eq!(w.beacon_for(Epoch::new(999)), None, "an unseen epoch is rejected");

        // Re-adopting a known epoch is idempotent — no duplicate, no eviction churn.
        w.adopt(Epoch::new(BeaconWindow::DEPTH as u64), BeaconSeed::new([0xEE; 32]));
        assert_eq!(w.recent.len(), BeaconWindow::DEPTH);
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
        let (genesis, _, genesis_rank) =
            verifiable_coordinate_ranked::<F2>(&creds, Epoch::ZERO, &BeaconSeed::GENESIS);
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
        let beacon = Arc::new(RwLock::new(BeaconWindow::genesis(BeaconSeed::GENESIS)));
        let directory = Directory::new();
        let local_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 40_000).into();
        directory.insert(genesis_coord, local_addr);

        // Channels: the loop's `Client` sends `Reseat` down `input_rx`; we push `BeaconReady` via `events`.
        let (input_tx, mut input_rx) = mpsc::channel::<Input>(8);
        let (ctrl_tx, _ctrl_rx) = mpsc::unbounded_channel::<Control>();
        let (events_tx, _events_rx0) = broadcast::channel::<Notification>(8);
        let client = Client {
            addr: Arc::new(Mutex::new(genesis_coord)),
            input_tx,
            ctrl_tx,
            events_tx: events_tx.clone(),
            genesis: BeaconSeed::GENESIS,
        };

        // A PROTEUS shaper started at genesis — the reshuffle must rotate its shape to the new epoch (§13.4).
        let shaper = Arc::new(RwLock::new(ProteusShaper::new(b"test-secret".to_vec(), Epoch::ZERO)));
        tokio::spawn(reshuffle_loop::<F2>(
            creds,
            Placement {
                coord: genesis_coord,
                output: genesis_rank,
                index: 0,
                epoch: Epoch::ZERO,
                beacon: BeaconSeed::GENESIS,
                joining: true,
            },
            Reseater {
                capabilities: Capabilities::CORE,
                local_addr,
                directory: directory.clone(),
                hello: hello.clone(),
                client,
            },
            beacon.clone(),
            ClaimBook::new(),
            Some(shaper.clone()),
            events_tx.subscribe(),
            None,
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
            beacon.read().unwrap().beacon_for(epoch),
            Some(BeaconSeed::new(seed)),
            "the verifier's window advanced to the new epoch beacon"
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
        let (genesis, _, genesis_rank) =
            verifiable_coordinate_ranked::<F2>(&creds, Epoch::ZERO, &BeaconSeed::GENESIS);
        let genesis_coord = genesis.coords();

        let hello = Arc::new(RwLock::new(Arc::new(vec![0u8])));
        let beacon = Arc::new(RwLock::new(BeaconWindow::genesis(BeaconSeed::GENESIS)));
        let directory = Directory::new();
        let local_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 40_001).into();

        let (input_tx, mut input_rx) = mpsc::channel::<Input>(8);
        let (ctrl_tx, _ctrl_rx) = mpsc::unbounded_channel::<Control>();
        let (events_tx, _rx0) = broadcast::channel::<Notification>(8);
        let client = Client {
            addr: Arc::new(Mutex::new(genesis_coord)),
            input_tx,
            ctrl_tx,
            events_tx: events_tx.clone(),
            genesis: BeaconSeed::GENESIS,
        };
        tokio::spawn(reshuffle_loop::<F2>(
            creds,
            Placement {
                coord: genesis_coord,
                output: genesis_rank,
                index: 0,
                epoch: Epoch::ZERO,
                beacon: BeaconSeed::GENESIS,
                joining: true,
            },
            Reseater {
                capabilities: Capabilities::CORE,
                local_addr,
                directory,
                hello,
                client,
            },
            beacon,
            ClaimBook::new(),
            None,
            events_tx.subscribe(),
            None,
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

    #[test]
    fn distrust_follows_the_identity_and_is_not_inherited_by_the_next_occupant() {
        // Audit R-M1, both directions, on the pure half of the driver's logic.
        let d = Distrust::default();
        let p0: Triple = [1, 1, 0];
        let p1: Triple = [0, 1, 1];
        let byzantine = identity_of(b"cert-byzantine");
        let innocent = identity_of(b"cert-innocent");

        // The Byzantine peer is seated and then quarantined by the engine.
        assert!(d.seat(p0, byzantine).is_empty(), "a first seating needs no correction");
        d.observe_verdict(p0);

        // DIRECTION 1 — it reshuffles to a new point. Without this it would arrive clean, because the tag is on a point
        // it no longer occupies.
        assert_eq!(
            d.seat(p1, byzantine),
            vec![Command::Quarantine { coord: p1 }],
            "distrust follows the identity to its new coordinate"
        );

        // DIRECTION 2, the worse one — an innocent peer lands on the vacated point. It must arrive clean, and it must
        // NOT pick up its predecessor's verdict, which it never earned.
        assert_eq!(
            d.seat(p0, innocent),
            vec![Command::Readmit { coord: p0 }],
            "the arriving identity clears the stale tag rather than inheriting it"
        );

        // And an innocent peer that merely re-connects at its own point triggers nothing.
        assert!(d.seat(p0, innocent).is_empty(), "re-seating the same identity is not a change of occupant");
    }

    #[test]
    fn a_distrusted_identity_landing_on_a_vacated_point_both_clears_and_re_applies() {
        // Both corrections at once, and the order matters: clear first, then re-apply, or the re-application is undone
        // by the clear that follows it.
        let d = Distrust::default();
        let point: Triple = [1, 0, 1];
        let first = identity_of(b"cert-first");
        let second = identity_of(b"cert-second");
        let elsewhere: Triple = [0, 0, 1];

        d.seat(point, first);
        d.observe_verdict(point); // `first` is distrusted
        d.seat(elsewhere, second);
        d.observe_verdict(elsewhere); // so is `second`

        assert_eq!(
            d.seat(point, second),
            vec![Command::Readmit { coord: point }, Command::Quarantine { coord: point }],
            "clear the predecessor's tag, then re-apply the arriving identity's own"
        );
    }

    #[test]
    fn a_verdict_about_an_unoccupied_point_is_dropped_rather_than_stored() {
        // Storing it would have to be keyed by the coordinate, which is exactly the aliasing this removes. With no
        // identity to blame there is nothing to remember.
        let d = Distrust::default();
        let ghost: Triple = [1, 1, 1];
        d.observe_verdict(ghost);
        let arriving = identity_of(b"cert-arriving");
        assert!(d.seat(ghost, arriving).is_empty(), "an arrival inherits nothing from a verdict about nobody");
    }

    /// Poll `cond` up to ~30s, yielding between checks; returns whether it became true.
    ///
    /// The ceiling is deliberately far above the healthy path (which resolves in milliseconds): its only job is to turn
    /// a hang into a failure, and a ceiling sized for an idle machine turns parallel-run contention into a false red.
    async fn await_until(cond: impl Fn() -> bool) -> bool {
        for _ in 0..3_000 {
            if cond() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
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

    /// The live morph-auto-fallback glue (§13.7): a failure trip drives the controller, which rotates the
    /// real driver shaper's morph in place — verified off the network (the connect path calls this exact
    /// function; a censored morph would otherwise only surface as slow connect timeouts).
    #[test]
    fn apply_outcome_rotates_the_shaper_morph_on_a_failure_trip() {
        let shaper: Shaper = Some(Arc::new(RwLock::new(ProteusShaper::with_morph(
            b"s".to_vec(),
            Epoch::ZERO,
            Morph::Polymorph,
        ))));
        let controller: MaybeController = Some(Arc::new(Mutex::new(MorphController::with_trip(
            Environment::DeepCensorship,
            1,
        ))));
        let morph = || shaper.as_ref().unwrap().read().unwrap().morph();

        // A success is a breaker reset — the morph is unchanged.
        apply_outcome(&shaper, &controller, true);
        assert_eq!(morph(), Morph::Polymorph);
        // Each failure (trip = 1) walks the DeepCensorship chain, installing the new morph on the shaper.
        apply_outcome(&shaper, &controller, false);
        assert_eq!(morph(), Morph::Fronted, "Polymorph → Fronted");
        apply_outcome(&shaper, &controller, false);
        assert_eq!(morph(), Morph::Webrtc, "Fronted → Webrtc");
    }

    #[test]
    fn apply_outcome_is_a_noop_without_a_controller() {
        // Fixed-morph mode (no environment): outcomes are never recorded, the morph never changes.
        let shaper: Shaper = Some(Arc::new(RwLock::new(ProteusShaper::with_morph(
            b"s".to_vec(),
            Epoch::ZERO,
            Morph::Polymorph,
        ))));
        apply_outcome(&shaper, &None, false);
        assert_eq!(
            shaper.as_ref().unwrap().read().unwrap().morph(),
            Morph::Polymorph,
            "a fixed morph never rotates"
        );
    }
}
