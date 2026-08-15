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
use fanos_proteus::shaper::OpenedUnder;
use fanos_proteus::{Environment, Morph, MorphCodec, MorphController, ProteusShaper};
use fanos_runtime::ports::stations::{Observation, Station, Stations};
use fanos_runtime::ports::ReadOutcome;
use fanos_runtime::{Command, Effect, Engine, Input, Instant, Notification, TimerToken};
use fanos_wire::capability::Capabilities;
use fanos_wire::error::encode_error;
use fanos_wire::{FrameType, ProtocolError, decode_frame, encode_frame, varint};
use quinn::{ClientConfig, ServerConfig};

use crate::directory::{Directory, WriteOutcome};
use crate::reflexive::{ReflexiveAddr, decode_addr, encode_addr};
use fanos_vrf::{CoordinateClaim, VrfProof, VrfPublic};

use crate::claims::{self, ClaimBook};
use crate::identity::{
    HelloResult, hello_bytes, hello_coord, hello_epoch, peer_cert_der, verifiable_coordinate_ranked,
    verify_hello,
};
use crate::tls::{NodeCredentials, TlsError, node_configs, node_configs_mutual_from};

/// How many uni-streams one peer may have open on one connection at a time.
///
/// **Derived by enumerating this crate's own openers, not chosen.** Every stream FANOS opens is a
/// `conn.open_uni()`, and there are exactly four sites: [`send_uni`] (the data path), `send_hello`,
/// `send_framed` (HelloAck/Error), and the HELLO-mode announcement. Each writes one frame and finishes the
/// stream, and `peer_send_worker` awaits `send_uni` in a serial loop — so one peer's legitimate concurrency
/// is bounded by the number of *sites*, not by traffic.
///
/// quinn's default is **100**, which is not a FANOS number: it is a general-purpose default for protocols
/// that multiplex. Against a peer that simply opens streams and sends, every credited stream is memory this
/// node commits before the application has accepted it — `read_frames` accepts serially, so the other 99
/// fill their buffers while the first is read. The bound below is what the protocol actually needs.
///
/// The ratchet in `tests/` keeps this honest: adding a fifth `open_uni` site without raising this constant
/// is a change that would silently drop frames, so it must fail the build rather than the wire.
const MAX_PEER_UNI_STREAMS: u32 = 4;

/// How many **unconsumed frames** a peer that has stopped reading can pin on one inbound connection.
///
/// One frame rides one uni-stream, and `MAX_PEER_UNI_STREAMS` of them may be open at once, so a sender
/// facing a receiver that never reads gets exactly this many frames out before its next `open_uni` stalls
/// on the peer's stream limit. That stall is the back-pressure boundary — the sender waits, it is not told
/// no and nothing is lost. In bytes the same bound is `MAX_PEER_UNI_STREAMS × max_wire()`, which is what
/// `receive_window` is set to.
///
/// **Public because the simulator needs it and must not restate it (#246).** Its transport had no retention
/// axis at all — a message was delivered or lost, never held — so the whole class #245 belongs to (a
/// transport library buffering on our behalf, bounded only by its own default) was invisible by
/// construction. Modelling that needs this number, and a copy of it would drift from the transport config
/// above without anything failing.
#[must_use]
pub fn inbound_frame_capacity() -> usize {
    MAX_PEER_UNI_STREAMS as usize
}

/// Per-stream flow-control credit: exactly what a reader is willing to read.
///
/// [`max_wire`] is the largest byte string `read_frames` will accept (`MAX_FRAME` + relay wrapper + PROTEUS
/// overhead, every term derived in #190). A sender that exceeds it has its stream dropped by the reader, so
/// crediting more than this buys a peer buffer space for bytes this node has already decided to refuse.
///
/// quinn's default is 1.25 MB — close to this by coincidence rather than derivation. Tying the credit to the
/// reader's own ceiling makes the two move together: raise `MAX_FRAME` and the credit follows, with no second
/// place to remember.
fn max_stream_credit() -> u64 {
    max_wire() as u64
}

/// Production transport tuning.
///
/// Two liveness settings — a keep-alive so idle overlay links survive NAT/firewall timeouts, and a bounded
/// idle timeout so a dead peer's connection is reaped — **and four memory bounds**, which quinn's defaults
/// leave at values a peer chooses the cost of (#245).
///
/// **What the defaults cost, measured against the node's own 256 MiB recommendation.** quinn credits 100
/// uni-streams *and* 100 bidi-streams at 1.25 MB each, sets `receive_window` to `VarInt::MAX` (so the
/// connection-level sum is never capped), and reserves datagram buffers. That is ≈250 MB of receive credit
/// per connection, and `MAX_INBOUND_CONNECTIONS = 512` of them — three orders of magnitude past the budget,
/// committed before the application sees a byte.
///
/// **Bidirectional streams are set to zero because FANOS has none.** A scan of the whole workspace finds no
/// `open_bi` and no `accept_bi`: every frame rides a uni-stream. Crediting 100 bidi-streams is therefore
/// strictly worse than crediting uni ones — a stream the application never accepts is never drained either,
/// so its buffer is held for the life of the connection. Zero is not a tightening; it is the true number.
fn tuned_transport() -> Arc<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();
    if let Ok(idle) = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)) {
        tc.max_idle_timeout(Some(idle));
    }
    tc.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

    // The protocol opens uni-streams only; see `MAX_PEER_UNI_STREAMS` for the enumeration.
    tc.max_concurrent_uni_streams(MAX_PEER_UNI_STREAMS.into());
    tc.max_concurrent_bidi_streams(0u32.into());

    // Per-stream credit = what the reader will read; connection credit = the product, so the sum a peer can
    // pin is stated rather than unbounded. `VarInt::MAX` was the default and made the product meaningless.
    let per_stream = max_stream_credit();
    tc.stream_receive_window(per_stream.try_into().unwrap_or(quinn::VarInt::MAX));
    let per_conn = per_stream.saturating_mul(u64::from(MAX_PEER_UNI_STREAMS));
    tc.receive_window(per_conn.try_into().unwrap_or(quinn::VarInt::MAX));

    // The QUIC DATAGRAM extension is unused: `fanos_node::exit::read_datagram` is a length-prefixed helper
    // over a stream, not this. Reserving nothing for it removes ~2.25 MB per connection that no code path
    // can ever consume.
    tc.datagram_receive_buffer_size(None);
    tc.datagram_send_buffer_size(0);

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
    /// Community secrets accepted on **receive only**, for a rollover in progress (#13). Empty on a node
    /// that is not mid-rotation.
    ///
    /// Separate from [`secret`](Self::secret) rather than a list with the first entry privileged, because
    /// the two are different powers: `secret` is what this node **emits** under and therefore what every
    /// peer must already hold, while these are only what it will **read**. A rollover is exactly the period
    /// when those two sets differ, and collapsing them into one list would make "add the new secret" and
    /// "start emitting under it" the same edit — which is the change that takes a censored deployment dark.
    pub accept_secrets: Vec<Vec<u8>>,
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
            .field("accept_secrets", &self.accept_secrets.len())
            .finish()
    }
}

impl ProteusConfig {
    /// A config for the flagship [`Morph::Polymorph`] ("look like nothing") under `secret`, fixed morph.
    #[must_use]
    pub fn polymorph(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
            morph: Morph::Polymorph,
            environment: None,
            codec: None,
            accept_secrets: Vec::new(),
        }
    }

    /// A config under an explicit fixed `morph`.
    #[must_use]
    pub fn with_morph(secret: impl Into<Vec<u8>>, morph: Morph) -> Self {
        Self { secret: secret.into(), morph, environment: None, codec: None, accept_secrets: Vec::new() }
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
            accept_secrets: Vec::new(),
        }
    }

    /// A config driven by a **pluggable** [`MorphCodec`] (the §13.3 SPI) instead of the built-in transform —
    /// the honest home for a real cover-protocol tunnel or a third-party morph.
    ///
    /// `None` if the codec declares a [`max_overhead`](MorphCodec::max_overhead) above
    /// [`fanos_proteus::MAX_WIRE_OVERHEAD`] — the receiver's read bound is `MAX_FRAME` plus that overhead,
    /// so a codec growing a frame by more would make full-size frames undeliverable. Refused **here**,
    /// where the embedder hands the codec over, because past this point the loss is indistinguishable from
    /// packet loss and the sender still sees its writes succeed.
    #[must_use]
    pub fn pluggable(secret: impl Into<Vec<u8>>, codec: Arc<dyn MorphCodec>) -> Option<Self> {
        (codec.max_overhead() <= fanos_proteus::MAX_WIRE_OVERHEAD).then(|| Self {
            secret: secret.into(),
            morph: Morph::Pluggable,
            environment: None,
            codec: Some(codec),
            accept_secrets: Vec::new(),
        })
    }

    /// Build the shared shaper and (when auto-fallback is configured) its controller, seeded at `epoch`. A
    /// pluggable codec wins; else an environment starts the shaper at its preferred morph with a controller;
    /// else the fixed `morph` with no controller.
    fn build(self, epoch: Epoch) -> (Arc<RwLock<ProteusShaper>>, MaybeController) {
        // Installed in ONE place, on whichever shaper the branches below produce (#13). Installing per
        // branch would leave the next branch someone adds silently deaf to a rollover — the family-moved-
        // one-member-at-a-time shape this whole change exists to remove.
        let accept = self.accept_secrets.clone();
        let install = move |mut shaper: ProteusShaper| {
            for secret in accept {
                if !shaper.also_accept(secret) {
                    tracing::warn!(
                        max = fanos_proteus::shaper::MAX_ACCEPTED_SECRETS,
                        "more accepted community secrets configured than a rollover needs; the extra ones \
                         are IGNORED, so peers still on them cannot be read"
                    );
                }
            }
            shaper
        };
        if let Some(codec) = self.codec {
            // `ProteusConfig::pluggable` already refused an over-growing codec, so this is `Some`. The
            // branch exists because the type cannot carry that proof — and it says so out loud rather
            // than falling through onto a wire the peer is not expecting.
            if let Some(shaper) = ProteusShaper::with_codec(self.secret.clone(), epoch, codec) {
                return (Arc::new(RwLock::new(install(shaper))), None);
            }
            tracing::error!(
                max_wire_overhead = fanos_proteus::MAX_WIRE_OVERHEAD,
                "pluggable codec grows a frame by more than a receiver will read; refusing to install it"
            );
        }
        match self.environment {
            Some(env) => {
                // **No plugged codec here** (that branch returned above), so the controller is built
                // knowing it: the four cover-protocol morphs are dropped from its walk instead of being
                // rotated into and silently rendered as polymorph under a cover-protocol shaping profile
                // (#113). For `dpi-corporate`, `sni-filter` and `deep-censorship` that leaves a chain of
                // one, which is the true state and the operator's cue to plug a transport.
                let controller = MorphController::with_trip_and_codec(env, fanos_proteus::DEFAULT_TRIP, false);
                if !controller.has_fallback() {
                    tracing::warn!(
                        environment = env.name(),
                        morph = ?controller.current(),
                        "no morph fallback: this build honours one obfuscation mode in this environment, so \
                         a censor that learns it has no successor to defeat — plug a MorphCodec transport"
                    );
                }
                let shaper = ProteusShaper::with_morph(self.secret, epoch, controller.current());
                (Arc::new(RwLock::new(install(shaper))), Some(Arc::new(Mutex::new(controller))))
            }
            None => (
                Arc::new(RwLock::new(install(ProteusShaper::with_morph(self.secret, epoch, self.morph)))),
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
        // The controller only ever proposes a morph from its *effective* chain, so a refusal here would
        // mean the two disagree about what this build can honour — report it rather than continue on a
        // morph nobody chose (#113).
        if !s.write().unwrap_or_else(PoisonError::into_inner).set_morph(morph) {
            tracing::warn!(?morph, "morph rotation refused by the shaper — no codec for a cover protocol");
        }
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
type HelloVerifier = Arc<dyn Fn(&[u8], &[u8]) -> HelloVerdict + Send + Sync>;

/// Why a peer's HELLO was accepted or refused — **three answers, because two of them call for opposite
/// operator actions** (#236).
///
/// This used to be `Option<HelloResult>`, and the `None` merged a forgery with our own staleness. They are
/// not the same event: one says a peer is lying to us, the other says we are behind and cannot judge. A
/// single counter over both is the defect #109 named for POROS's gates — one name on two decisions.
pub(crate) enum HelloVerdict {
    /// The proof verified; the negotiation produced a result (established or incompatible).
    ///
    /// Boxed because [`HelloResult::Established`] carries the peer's certificate material and dwarfs the two
    /// refusal variants; without it every verdict on the stack would be sized for the success arm.
    Ok(Box<HelloResult>),
    /// The proof did **not** verify against a beacon this node holds — an impostor or a forgery. Actionable
    /// as an attack.
    BadProof,
    /// This node has **no beacon** for the epoch the peer proves, so it cannot judge the claim at all: we
    /// are behind, not under attack. A node that has just started holds only the genesis beacon, which makes
    /// this the first thing an operator sees when a join is failing — see #235.
    EpochUnknown,
}

#[derive(Clone)]
struct SelfCert {
    /// This node's own HELLO (its proof-of-coordinate for the current epoch). Behind a lock because the
    /// per-epoch reshuffle (`reshuffle_loop`, #102/L3) rewrites it when the beacon advances — every new
    /// connection then proves the node's *current* coordinate, not a stale genesis one. Read-cloned per
    /// connection (an `Arc` swap, no copy under the lock).
    hello: Arc<RwLock<Arc<Vec<u8>>>>,
    /// This node's own certificate DER — the identity a peer authenticates it by, and therefore the exact test
    /// for "is the party on the other end of this connection *us*?" (#350).
    ///
    /// **Not the address and not the coordinate**, and both alternatives were tried on paper first. The address
    /// is wrong because a node behind NAT is reached at one address and bound to another, so comparing them
    /// misses the very deployments that matter. The coordinate is wrong for a sharper reason: `reshuffle_loop`
    /// *deliberately* sends to this node's own point to resolve a contested one, and its own comment says why —
    /// "sending to our own point reaches whoever the directory says holds it, which is exactly the incumbent".
    /// A coordinate-keyed guard would refuse the one message that mechanism exists to send. The certificate has
    /// neither problem: it is unforgeable, NAT-independent, and it distinguishes *us* from *whoever else holds
    /// our point*, which is the distinction the collision actually turns on.
    ///
    /// Not behind a lock, unlike `hello`: the reshuffle rewrites where this node sits, never who it is.
    own_cert: Arc<Vec<u8>>,
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
fn shape_out_timed(
    shaper: &Shaper,
    under: Option<OpenedUnder>,
    frame: &[u8],
) -> (Vec<u8>, std::time::Duration) {
    match (shaper, under) {
        // A peer that is behind reads only the shape it reached us with, and that is true of *data* frames as
        // well as handshake ones (#234). The pin found this: the handshake completed and the first payload was
        // unreadable, because the data path has its own shaping call and it was not on the list. Pacing is
        // unaffected — the delay is a property of the morph, not of which shape sealed the bytes.
        (Some(s), Some(under)) => {
            let wire = s.read().unwrap_or_else(PoisonError::into_inner).outbound_under(frame, under);
            (wire, std::time::Duration::ZERO)
        }
        (Some(s), None) => {
            let shaped = s.read().unwrap_or_else(PoisonError::into_inner).shape(frame);
            (shaped.wire, shaped.delay)
        }
        (None, _) => (frame.to_vec(), std::time::Duration::ZERO),
    }
}

/// Recover an inbound frame from the wire with the shape that opened it, or `None` if it wasn't shaped by
/// our secret+epoch.
///
/// The second value says which secret and which epoch opened it — [`OpenedEpoch::Genesis`] exactly when the
/// sender does not know the live epoch yet (#234), and an [`OpenedSecret::Accepted`] when the sender is on a
/// community secret this node accepts but does not emit under (#13). A caller that will *reply* must carry it
/// to the reply. With no shaper configured there is one shape and it is the current one, which is what
/// [`OpenedUnder::CURRENT`] means here.
fn shape_in(shaper: &Shaper, wire: Vec<u8>) -> Option<(Vec<u8>, OpenedUnder)> {
    match shaper {
        Some(s) => s.read().unwrap_or_else(PoisonError::into_inner).inbound(&wire),
        None => Some((wire, OpenedUnder::CURRENT)),
    }
}


/// Shape an outbound frame **for a peer that may be behind on the epoch, the secret, or both** (#234, #13).
///
/// A joining node's accept window is `{0, 0, 1}`, so a frame shaped at the cell's live epoch is one it
/// cannot open; a node mid-secret-rollover holds a different secret entirely. This is asked at SEND time —
/// not derived from a frame we have read — because both sides emit their HELLO before reading one, and by
/// the time the arm is visible in an inbound frame the outbound one has already gone. The answer comes from
/// the datagram envelope, which saw the peer's shape one layer down and one round earlier.
fn shape_out_joining(shaper: &Shaper, under: Option<OpenedUnder>, frame: &[u8]) -> Vec<u8> {
    match (shaper, under) {
        (Some(s), Some(under)) => {
            s.read().unwrap_or_else(PoisonError::into_inner).outbound_under(frame, under)
        }
        (Some(s), None) => s.read().unwrap_or_else(PoisonError::into_inner).outbound(frame),
        (None, _) => frame.to_vec(),
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
/// How a verifier turns a peer's proven VRF output plus the coordinate it proved into that peer's **probe
/// index** — the first component of the arbitration order (`fanos_vrf::claim_beats`).
///
/// A function pointer rather than a type parameter, and that is the whole point (#249). The index IS
/// derivable from what a handshake recovers — `fanos_vrf::probe_index_of`'s own doc says a verifier "learns
/// how far along `p` sits for that peer **without being told**", which is what keeps
/// `verify_coordinate_claim` non-recursive. Nothing was ever missing from the wire. What was missing was the
/// TYPE at the site: walking the plane needs `F`, and `F` is monomorphised away at spawn, so by the time the
/// send loop holds a `Proven(actual)` there is no type left to walk with. Carrying the walk as a value
/// closes that without touching a frame, a proof, or a witness chain.
type ProbeIndex = fn(&fanos_vrf::VrfOutput, Triple) -> Option<u16>;

/// [`ProbeIndex`] for a concrete plane — monomorphised where `F` is still known and passed down as a value.
fn probe_index_on<F: Field>(output: &fanos_vrf::VrfOutput, coord: Triple) -> Option<u16> {
    let point = Point::<F>::new(coord)?;
    fanos_vrf::probe_index_of::<F>(output, &point)
}

/// Bytes a [`Relay`](FrameType::Relay) wrapper adds around an inner frame, **at the largest inner there
/// can be**.
///
/// Derived from `encode_frame`'s own shape — `varint(type) ‖ varint(body_len) ‖ body`, with
/// `body = target(12B) ‖ origin(12B) ‖ inner` — and evaluated at the biggest body, because the length
/// varint *widens with it*. Sizing this on an empty inner would understate it by two bytes, and an
/// understated ceiling is the same defect a little smaller.
fn relay_overhead() -> usize {
    let body = 2 * TRIPLE_WIRE_LEN + MAX_FRAME;
    varint::encoded_len(FrameType::Relay.code()) + varint::encoded_len(body as u64) + 2 * TRIPLE_WIRE_LEN
}

/// Per-stream receive cap on the **wire** — [`MAX_FRAME`] plus everything applied to it on the way out.
///
/// `MAX_FRAME` bounds a *frame*. A reader reads *wire*, and two transforms sit between them, each of which
/// only grows the bytes:
/// * the relay wrapper, when a peer is reached through a hub (`send_uni(hub, shaper, &encode_relay(..))` —
///   the wrapper goes on the frame, and the shaper then wraps *that*), and
/// * the PROTEUS polymorph transform, `nonce ‖ junk ‖ len ‖ payload ‖ padding`, which is **on by default**.
///
/// Bounding the read by the frame cap therefore drops exactly the frames a producer packed to that cap by
/// design — a full TAXIS block — while `write_all` reports success and nothing counts the loss. Different
/// quantities need different bounds, and each gap here is derived (from the encoder, and from the shape
/// parameter ranges) rather than chosen, so neither can silently reopen the hole.
///
/// **Public because a second reader exists, and it must not restate this (#195).** The simulator models the
/// receive path without a socket, so it needs the very number `read_to_end` is given. A copy over there
/// would agree with this one until either moved, and a simulator that silently disagrees with production is
/// worse than one that abstains — it reports a green run for a frame the real receiver drops. Anything
/// modelling, conformance-checking or documenting the read bound imports this function.
#[must_use]
pub fn max_wire() -> usize {
    MAX_FRAME + relay_overhead() + fanos_proteus::MAX_WIRE_OVERHEAD
}
/// Cap on **concurrent inbound connection-handler tasks** (audit C3): each accepted connection spawns a
/// task (HELLO exchange, then frame reads), so without a bound a peer opening connections in a loop grows
/// the task/handshake count without limit. The accept loop takes a permit per connection and holds it for
/// the task's life, so once this many are in flight, new accepts back-pressure (QUIC queues/rejects) until
/// one finishes. Generous next to a cell's `N-1` real neighbours; it only bounds abuse.
pub(crate) const MAX_INBOUND_CONNECTIONS: usize = 512;

/// The most **inbound receive credit** this node can have outstanding at once, across every connection.
///
/// `fanos_primitives::budget`'s table lists this term as *"inbound QUIC credit — **unnamed**"*, and says
/// "unnamed is not zero; it is unbounded". That was true when the table was written and stopped being true
/// when #245 landed: the per-connection window is no longer quinn's `VarInt::MAX` but
/// `MAX_PEER_UNI_STREAMS × max_wire()`, and the connection count is capped at
/// `MAX_INBOUND_CONNECTIONS` (`pub(crate)`, so this doc names it rather than linking it — a public item
/// may not link a private one, and rustdoc refuses). The product has been computable ever since, and nobody
/// went back to take it.
/// Exported so the sum can be taken where all three factors are visible, which is not inside
/// `fanos-primitives` — it sits below this crate and cannot see `MAX_FRAME` or the connection cap.
///
/// **It is deliberately not a `*_MEMORY_BUDGET` share, and the difference is not bookkeeping.** Every term
/// in that table is *steady*: the store holds its 128 MiB whenever it is full, and a full store is ordinary
/// operation. This is *contingent* — flow-control credit is a promise, and the bytes exist only for peers
/// that actually fill their windows and only until this node reads them. A node at rest holds ~none of it.
/// So it must not be added to `allocated()`, where it would report a permanent 2 GiB the node does not
/// occupy; it belongs to the difference between "beyond my design, throttle" and "definitely leaking, die",
/// which is exactly the `MemoryHigh`/`MemoryMax` split (#207).
///
/// It is large — **2.00 GiB**, against 320 MiB of named shares — and a peer chooses how much of it to use,
/// since filling a window is the sender's decision. An enforcement figure below it turns a flood the caps
/// were designed to survive into a kill.
///
/// **It is NOT the largest such term, and saying so here was wrong.** The first version of this doc called
/// it "by far the largest quantity in the node's memory picture" and "the one an adversary chooses the size
/// of". Enumerating the class one step further found the SOCKS5 UDP tunnel map:
/// `MAX_UDP_FLOWS × 2 directions × UDP_TUNNEL_BUFFER × 65535` is **8.6 GB per association**, and one tunnel
/// alone can hold the whole 8 MiB proxy share. A superlative is a claim about everything else, and this one
/// was made after summing only what happened to be named (#300).
#[must_use]
pub fn inbound_credit_ceiling() -> usize {
    MAX_INBOUND_CONNECTIONS
        .saturating_mul(MAX_PEER_UNI_STREAMS as usize)
        .saturating_mul(max_wire())
}

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
/// The notification channel stays unbounded and is bounded *transitively*: the router drains it at memory
/// speed, so the engine cannot outrun it for long.
///
/// **The same argument was made for the per-peer send queues and it does not hold there** — see
/// `MAX_PEER_SEND_QUEUE`. It bounds the engine's production *rate*, not the queue's *depth*, and a queue
/// whose consumer runs at zero grows without limit however slowly it is filled.
const INPUT_CAP: usize = 1024;

/// The most frames one peer's send queue may hold before this node stops making more (#89).
///
/// # Why it was unbounded, and why the reasoning failed
///
/// `INPUT_CAP`'s own comment used to cover this: "the outbound channels stay unbounded — they are bounded
/// transitively, since the engine can only produce effects as fast as it drains this now-bounded input."
/// That bounds the **rate**. The depth is `∫(rate − drain)`, and the drain here is *the peer's*, which can be
/// zero: `send_uni` awaits `open_uni` and `write_all`, so a peer that completes the handshake and simply
/// never reads — or advertises a minimal stream window — stalls the worker while this node keeps queueing.
/// No forged frame and no protocol violation; a socket that does not drain is enough. The traffic shaper is
/// the second, non-adversarial path to the same place: it *deliberately* paces sends, so even a healthy peer
/// has a bounded drain rate by design.
///
/// # The bound
///
/// `INPUT_CAP`, because that is exactly the depth the transitive argument was right about. Each input the
/// engine has accepted but not yet processed owes at most one frame per peer, so a legitimate backlog to one
/// peer cannot exceed the inbound queue's own capacity. Anything past it is not work this node was asked to
/// do — it is a peer that is not draining, and the answer to that is to stop making frames for it rather
/// than to buffer them.
///
/// Stated honestly: this converts an *unbounded* leak into a *bounded* one, and the bound is generous — a
/// queue full of maximum-size shard publishes is tens of megabytes. It is the engine's own accepted-work
/// limit rather than a comfortable number, which is the right trade for a cap whose job is to exist.
const MAX_PEER_SEND_QUEUE: usize = INPUT_CAP;

/// A coordinate → live connection cache. A `Connection` is a cheap handle (an `Arc` inside).
/// Live connections to each peer — **a list, not one** (#265).
///
/// It held exactly one, and every write was a blind overwrite, so a peer that opened a second connection
/// while the first worked cost the *acceptor* its only route home: the surplus is the dialer's to discard
/// and the acceptor's to depend on, and each side decides alone. Measured at
/// `conns.route_replaced = 5` on the run where the reverse send times out.
///
/// **The ceiling is not a new constant.** A coordinate is held by one node, and how many connections that
/// node can have open here is already bounded on the accept path by `MAX_INBOUND_PER_SOURCE` (per IP) under
/// `MAX_INBOUND_CONNECTIONS` (globally). Both are enforced before a handshake runs, so this list inherits
/// them; [`file_conn`] additionally drops closed entries on every write, so the steady state is the number
/// of connections the peer is actually keeping open.
///
/// **Why a list rather than "keep the older" or "keep the newer".** The acceptor cannot tell at accept time
/// whether a second connection is a doomed surplus or a migrated peer's only working path, so it keeps both
/// and defers the question to the reader below. What it must *not* do is discard one, which is what the old
/// single-slot map did — and discarding closed the route the answering peer had just filed (#264).
type ConnMap = Arc<Mutex<HashMap<Triple, Vec<Connection>>>>;

/// The one place the liveness rule is applied: drop closed connections to `peer` and hand back the
/// **newest** survivor. Every reader goes through this so "live" cannot come to mean two things in two
/// callers.
///
/// **Why the newest, derived — this is not a preference (#266).** Two causes put a second connection under
/// one coordinate, and they are the only two. *Surplus*: both sides dialed at once, both are live, and either
/// choice carries the frame. *Redial*: the peer lost its side (restart, NAT rebind, migration) and dialed
/// again, so the older entry is dead and the newer one is the only path. The newest is therefore never worse
/// and is sometimes the only correct answer, so it dominates — no measurement is needed to choose.
///
/// **Why the reader must choose at all, rather than trying each in turn.** Trying in turn needs a send whose
/// failure is observable, and QUIC does not give one here: a peer that vanished sends no `CONNECTION_CLOSE`,
/// so `close_reason()` stays `None` for the whole `max_idle_timeout`, `retain` keeps the corpse, `open_uni`
/// succeeds locally, and the write is buffered into silence. Nothing reports a failure to fall back *from*.
/// That lagging predicate is also why picking the oldest was actively harmful and not merely arbitrary: it
/// pinned every redial onto the dead entry for a full idle timeout, which is longer than most exchanges live.
fn live_conn(map: &mut HashMap<Triple, Vec<Connection>>, peer: Triple) -> (Option<Connection>, usize) {
    let Some(live) = map.get_mut(&peer) else {
        return (None, 0);
    };
    let before = live.len();
    live.retain(|c| c.close_reason().is_none());
    let pruned = before - live.len();
    if live.is_empty() {
        map.remove(&peer);
        return (None, pruned);
    }
    (live.last().cloned(), pruned)
}

/// File a connection under `peer`, pruning closed ones first. Returns how many live connections were
/// **already** held — zero on the ordinary path, and non-zero exactly when this one is surplus.
fn file_conn(map: &mut HashMap<Triple, Vec<Connection>>, peer: Triple, conn: Connection) -> usize {
    let live = map.entry(peer).or_default();
    live.retain(|c| c.close_reason().is_none());
    let held = live.len();
    if !live.iter().any(|c| c.stable_id() == conn.stable_id()) {
        live.push(conn);
    }
    held
}

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
    // `f + 1`, where `f` is the platform's Byzantine budget — IMPORTED, not restated. `fault_budget`'s own
    // doc says it best: "restating `(n − 1)/3` over there would work and is exactly the copy that drifts."
    // Both are `const fn`, so `REFLEXIVE_QUORUM_FANO` below stays a const item.
    //
    // This does not touch the layering argument above, which is about where `n` comes from (the plane
    // order, never the peer directory) and remains exactly as it was. That argument is about the INPUT;
    // this line is about the FORMULA, and only the formula had two homes.
    fanos_runtime::fault_budget(n) + 1
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
    /// The driver-side data-path plane (#191): discards that stop before the engine, so the engine cannot
    /// count them. Shared with the `NodeHandle`, whose `driver_stations` merges it into the answer to `Observe`.
    stations: Arc<Mutex<Stations>>,
    /// Which peers reached us under the genesis shape, shared with the datagram envelope that learns it.
    /// Read at SEND time by [`Transport::joining`] — see `proteus_socket::GenesisSpeakers` for why the
    /// answer has to arrive from one layer down (#234).
    joining: crate::proteus_socket::ReplyAddressing,
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
    /// Frames not made because a peer's send queue was at `MAX_PEER_SEND_QUEUE` (#89).
    ///
    /// Zero on a healthy node, and a non-zero value has exactly one meaning: some peer stopped draining and
    /// this node stopped making frames for it. Counted rather than logged-and-forgotten because that is the
    /// difference between an operator being able to test the hypothesis and having to guess.
    send_drops: Arc<std::sync::atomic::AtomicU64>,
    /// Coordinates with a hole-punch dial already in flight — the bound on what an unsolicited `PunchTo`
    /// can cost (see [`accept_holepunch`]). A *set of coordinates*, so the ceiling is the plane's own point
    /// count and no constant has to assert one.
    punching: Arc<Mutex<BTreeSet<Triple>>>,
    /// Coordinates a dialed-but-unjudgeable connection is already being held open for (#235) — the dial
    /// side's ceiling, deliberately the same shape as `punching` above. See [`spawn_restricted`].
    unjudged: Arc<Mutex<BTreeSet<Triple>>>,
    /// The plane's probe walk, carried as a value so the send path can RANK a peer it verified (#249).
    ///
    /// `None` is not a disabled check but an **absent mechanism** — the distinction `fanos_node::bound`
    /// draws with `Option<BeaconSeed>`. A pinned-coordinate deployment has no VRF walk at all, so a peer's
    /// verified claim genuinely has no index to derive and an unranked binding is the whole truth there.
    probe_index: Option<ProbeIndex>,
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
pub(crate) const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// The node's **current epoch and beacon seed**, as latest-state rather than as an event.
///
/// An epoch is state: a driver only ever wants the one that is current, and an intermediate epoch it missed
/// is already worthless. Carried on a `watch` for exactly that reason — the notification broadcast is lossy,
/// and a publisher that missed a `BeaconReady` never published for that epoch at all, leaving its directory
/// slot empty for a full period with nothing to say so (#86).
pub type Beacons = tokio::sync::watch::Receiver<Option<(Epoch, [u8; 32])>>;

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
    /// The **driver's own** data-path readings, merged into the engine's when `Observe` is answered.
    ///
    /// Some work stops on this side of the seam and the engine never learns of it: a directory publish whose
    /// ack times out is the case that mattered (#106). The contract already says what to do with two planes —
    /// "every composite that forwards `Observe` to more than one place owes the same fold"
    /// ([`fanos_runtime::ports::fold_data_path`]) — and a node is exactly such a composite once the driver
    /// observes anything at all. Shared, not copied, so every `Client` a publisher clones writes to the one
    /// plane an operator reads.
    stations: Arc<Mutex<Stations>>,
    local_addr: SocketAddr,
    input_tx: mpsc::Sender<Input>,
    ctrl_tx: mpsc::UnboundedSender<Control>,
    events_tx: broadcast::Sender<Notification>,
    events_rx: broadcast::Receiver<Notification>,
    /// The live epoch, as latest-state — see [`Beacons`].
    beacons: Beacons,
    /// Frames not made because a peer's send queue was full (#89) — shared with the transport.
    send_drops: Arc<std::sync::atomic::AtomicU64>,
    /// **This node was asked to stop** — the discriminator every supervisor reads (#257). See
    /// [`Client::is_stopping`] for why an actor's ending cannot be judged without it.
    stopping: Arc<std::sync::atomic::AtomicBool>,
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
    /// The shared data-path plane, for the driver's own supervisors (#251).
    ///
    /// `pub(crate)` and returning the `Arc` rather than a reading: a supervisor must record into the SAME
    /// plane `Observe` merges, long after this handle was built, so it needs the handle and not a snapshot.
    pub(crate) const fn stations_handle(&self) -> &Arc<Mutex<Stations>> {
        &self.stations
    }

    /// The shared "this node was asked to stop" flag, for a supervisor spawned after the handle exists
    /// (#257) — the reshuffle loop is the one such actor. Same reasoning as [`Self::stations_handle`]: the
    /// supervisor must read the flag at the moment its actor ends, so it needs the cell, not a reading.
    pub(crate) const fn stopping_handle(&self) -> &Arc<std::sync::atomic::AtomicBool> {
        &self.stopping
    }

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

    /// Frames this node **did not make** because a peer's send queue was at `MAX_PEER_SEND_QUEUE`.
    ///
    /// Zero on a healthy node. A non-zero value has one meaning and it is actionable: some peer stopped
    /// draining its connection, so this node stopped queueing for it rather than growing without limit
    /// (#89). Reported by `fanos status health`, because the alternative — a silent drop — is the property
    /// that makes a defect unfalsifiable.
    #[must_use]
    pub fn send_drops(&self) -> u64 {
        self.send_drops.load(std::sync::atomic::Ordering::Relaxed)
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
            stations: self.stations.clone(),
            input_tx: self.input_tx.clone(),
            ctrl_tx: self.ctrl_tx.clone(),
            events_tx: self.events_tx.clone(),
            beacons: self.beacons.clone(),
            genesis: self.genesis,
            stopping: Arc::clone(&self.stopping),
        }
    }

    /// The genesis seed of the network this node is on — see [`Client::genesis`].
    #[must_use]
    pub fn genesis(&self) -> BeaconSeed {
        self.genesis
    }

    /// Close the QUIC endpoint and stop serving. Idempotent.
    ///
    /// **The flag is raised before the endpoint closes, and the order is load-bearing** (#257):
    /// `accept_loop` ends the instant `Endpoint::accept()` answers `None`, so a supervisor that read the
    /// flag after the close would race the very ending it is trying to classify. Raised first, the ending is
    /// always judged against a `true`. `Release`/`Acquire` pair the store with those reads.
    pub fn shutdown(&self) {
        self.stopping.store(true, std::sync::atomic::Ordering::Release);
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
type GetWaiters = HashMap<[u8; 32], Vec<(std::time::Instant, oneshot::Sender<ReadOutcome>)>>;
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
        reply: oneshot::Sender<ReadOutcome>,
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
    /// The driver's data-path plane — the same shared cell [`NodeHandle`] holds.
    stations: Arc<Mutex<Stations>>,
    input_tx: mpsc::Sender<Input>,
    ctrl_tx: mpsc::UnboundedSender<Control>,
    events_tx: broadcast::Sender<Notification>,
    beacons: Beacons,
    genesis: BeaconSeed,
    /// Whether this node is on its way out — see [`Client::is_stopping`].
    stopping: Arc<std::sync::atomic::AtomicBool>,
}

impl Client {
    /// Record one **driver-side** discard on this node's data-path plane, at `line`, under `tag`.
    ///
    /// For work that stops before or after the engine, so the engine cannot count it. The engine's own plane
    /// is untouched; the two are merged when `Observe` is answered ([`Self::driver_stations`]).
    pub fn record_station(&self, station: Station, line: Option<Triple>, tag: Option<u64>) {
        self.stations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record_tagged(station, line, tag, 1);
    }

    /// This node's driver-side readings, to be folded into the engine's answer to `Observe`.
    #[must_use]
    pub fn driver_stations(&self) -> Vec<Observation> {
        self.stations.lock().unwrap_or_else(PoisonError::into_inner).observations()
    }

    /// **Is this node on its way out?** — the discriminator that makes an actor's ending readable (#257).
    ///
    /// A supervisor sees a task end and has to say whether that is an outage. It cannot: the same `Ok(())`
    /// arrives from a loop that fell out of its own accord and from one whose input was taken away because
    /// the node is stopping. `accept_loop` is the sharp case — it is written as
    /// `while let Some(i) = endpoint.accept().await`, and [`NodeHandle::shutdown`] closing the endpoint makes
    /// that `None`. So *every* orderly stop retires it, and a supervisor without this predicate files the
    /// shutdown as a death. One false alarm per stop is enough to make the true one unreadable: a publisher
    /// that really died at 03:00 sits in the record beside the stop at 09:00 with nothing to sort them by.
    ///
    /// Two ways a node goes away, and both count, because both are somebody's decision rather than a fault:
    ///
    /// * **the endpoint was closed** — [`NodeHandle::shutdown`], which is what the binary does on SIGTERM;
    /// * **the engine is gone** — every `Input` sender dropped, which is what an *embedder* does when it
    ///   drops its `Node` while the process keeps running (`fanos-ffi`, and every test). There the actors
    ///   really do run to completion with the supervisors still alive to misreport them, so this half is not
    ///   hypothetical — it is the deterministic case, where the first is only a race.
    ///
    /// A panic is deliberately **not** excused by either: a defect during shutdown is still a defect, and it
    /// is the one ending that says the code is wrong rather than that the operator asked.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(std::sync::atomic::Ordering::Acquire) || self.input_tx.is_closed()
    }

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
    /// digest, so concurrent `get`s never cross) — **and say which of the three things happened**.
    ///
    /// The three-state door (#215). `Absent` is a definite negative a caller may rely on; `Inconclusive` is
    /// not evidence of anything, and every way this call can fail to establish a fact produces it: the
    /// engine's own read timeout, its full read table, no peer to ask, this bound elapsing, or a stopped
    /// node. Before, all five and a real absence were one `None`, and callers that carefully distinguished
    /// them one layer up were reconstructing the difference from which timeout happened to win.
    pub async fn read(&self, key: Vec<u8>) -> ReadOutcome {
        let digest = storage_digest(&key);
        let (reply, rx) = oneshot::channel();
        // Register the waiter BEFORE issuing the Get, so a fast reply can never be missed.
        if self.ctrl_tx.send(Control::Get { digest, reply }).is_err() {
            return ReadOutcome::Inconclusive; // the node stopped — nothing was established
        }
        if self
            .input_tx
            .try_send(Input::Command(Command::Get { key }))
            .is_err()
        {
            return ReadOutcome::Inconclusive;
        }
        // Bound the wait: a key whose responsible node is unreachable (or absent from a sparse cell)
        // must resolve, never hang the caller forever (audit C1). An elapse here is a non-conclusion —
        // which is what this bound's ordering against `fanos_node::resolve::STORE_TIMEOUT` used to be the
        // only expression of.
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(outcome)) => outcome,
            _ => ReadOutcome::Inconclusive,
        }
    }

    /// **Sample a value's data availability** without downloading it (spec §L4.3) — the light-client check.
    ///
    /// Probes a few unpredictable Fano lines and concludes as soon as every sampled line is fully present.
    /// By the Steiner soundness in `fanos_code::da`, an unavailable value has at most one of the seven lines
    /// external, so `DA_SAMPLES = 3` distinct lines give certain detection.
    ///
    /// **This is the door that was never cut (#173).** `Command::SampleAvailability` has existed with the
    /// engine handling it end to end — sampling, probing, the timeout sweep, the notification — and no way
    /// for anything outside the engine to issue one. The only issuers in the tree were two simulator tests,
    /// so no shipped binary, no embedder through the C ABI, and no `fanos-vpn` could ask the question the
    /// mechanism exists to answer.
    ///
    /// The subscription is taken **before** the command is sent, for the reason `read` registers its waiter
    /// first: a sample that concludes locally (this node already holds enough shards) notifies immediately,
    /// and a subscription taken afterwards would miss it and then wait out the full timeout.
    ///
    /// [`Unavailable`](Sampled::Unavailable) is the engine's own conclusion and is deliberately conservative:
    /// it folds "a sampled line was missing" together with "the probe did not answer in time", because for
    /// data availability those must not be told apart in the caller's favour — a withheld value that reads as
    /// available is the failure this check exists to prevent. [`Inconclusive`](Sampled::Inconclusive) is
    /// strictly about *this call* failing to reach a conclusion at all.
    pub async fn sample_availability(&self, key: Vec<u8>) -> Sampled {
        let digest = storage_digest(&key);
        let mut events = self.subscribe();
        if !self.command(Command::SampleAvailability { key }) {
            return Sampled::Inconclusive; // the node stopped — nothing was established
        }
        let wait = async {
            loop {
                match events.recv().await {
                    Ok(Notification::Availability { key: k, available }) if k == digest => {
                        return if available { Sampled::Available } else { Sampled::Unavailable };
                    }
                    // Two different reasons, one behaviour: another sample's answer or an unrelated
                    // notification is simply not ours, and a lag *may* have dropped ours but may not have.
                    // Neither is a conclusion, so both keep waiting and let the bound below decide.
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return Sampled::Inconclusive,
                }
            }
        };
        tokio::time::timeout(REQUEST_TIMEOUT, wait).await.unwrap_or(Sampled::Inconclusive)
    }

    /// [`read`](Self::read), for the callers that genuinely treat both negatives alike.
    ///
    /// Kept because most call sites want the bytes and will retry regardless of why they are missing — a
    /// `.fanos` resolution, a snapshot probe. It is a **named lossy conversion**, so the sites that have
    /// decided the distinction does not matter to them are the ones that say `get`, and they can be found.
    pub async fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        self.read(key).await.found()
    }

    /// The live epoch as **latest-state**: a receiver that always yields the newest `(epoch, seed)` this node
    /// has seen, and never the fact that one went by while the reader was busy.
    ///
    /// Use this rather than `subscribe()` for anything driven by the epoch. The notification broadcast is
    /// lossy by design, and a driver that missed a `BeaconReady` on it simply never ran for that epoch —
    /// which for a `(coordinate, epoch)`-keyed publisher is a directory slot left empty for a full period,
    /// with nothing anywhere to say so (#86). A `watch` cannot express that failure: a reader that was
    /// descheduled through three epochs wakes on the third, which is the only one it wanted.
    ///
    /// `None` until the first round assembles, and on a node with no beacon clock, for ever.
    #[must_use]
    pub fn beacons(&self) -> Beacons {
        self.beacons.clone()
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

/// What a [`Client::sample_availability`] call established (spec §L4.3).
///
/// Three-valued for the reason every read on this client is: a call that did not conclude is not a negative,
/// and folding it into one would let an unreachable node read as a withheld value — or worse, the reverse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Sampled {
    /// Every sampled Fano line was fully present: the value's shards are retrievable.
    Available,
    /// The engine concluded the value is **not** confirmed available — a sampled line was incomplete, or its
    /// probes did not answer within the engine's own timeout. Conservative by design; see
    /// [`sample_availability`](Client::sample_availability).
    Unavailable,
    /// This call did not reach a conclusion: the node had stopped, or the wait elapsed. **Not** evidence of
    /// anything, and in particular not evidence that the value is unavailable.
    Inconclusive,
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
    beacon_tx: tokio::sync::watch::Sender<Option<(Epoch, [u8; 32])>>,
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
                    // **The epoch is republished as latest-state, and this is the only place that can do it
                    // losslessly.** This task owns `notify_rx`, an unbounded mpsc, so it never misses a
                    // round; every other consumer reads the *broadcast*, which drops messages for anyone who
                    // falls behind. A publisher that missed a `BeaconReady` never published for that epoch —
                    // a relay's onion key, an exit's key, a node's capability or load simply absent from the
                    // directory for a full period, self-healing at the next and invisible while it lasted.
                    //
                    // Monotone: a replayed or reordered older round is ignored, so a reader can treat the
                    // value as "the newest epoch this node has seen" without checking.
                    Notification::BeaconReady { epoch, seed } => {
                        let (epoch, seed) = (*epoch, *seed);
                        beacon_tx.send_if_modified(|live| match *live {
                            Some((seen, _)) if seen >= epoch => false,
                            _ => {
                                *live = Some((epoch, seed));
                                true
                            }
                        });
                    }
                    // **Answers, not events, and they leave here rather than going on to the broadcast.**
                    // A `Retrieved`/`Stored` is the reply to one caller's `get`/`put`, correlated by digest;
                    // nothing subscribes to either, in any crate. Fanning them out cloned every read value —
                    // up to `MAX_VALUE_LEN` — once per subscriber, and a running node keeps twenty-one, all
                    // of which discarded it. That was not only waste: it was the dominant source of
                    // broadcast volume, and this channel drops messages when a subscriber falls behind, so
                    // it was buying nothing with the budget an epoch-driven publisher needs to not miss a
                    // `BeaconReady`. The `Snapshot` arm below is the same rule for the same reason.
                    Notification::Retrieved { key, outcome } => {
                        if let Some(waiters) = gets.remove(key) {
                            for (_, tx) in waiters {
                                let _ = tx.send(outcome.clone());
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
    /// The engine's beacon and the directory disagree about which network this node is on.
    ///
    /// A node is provisioned onto a network twice — once as `BeaconParams` (which the beacon engine reads)
    /// and once as the directory the transport seats it in (`Directory::for_network`) — and nothing but this
    /// check makes those two agree. Disagreement is not a degraded mode: coordinates derive from the seed, so
    /// the node would seat itself in one network's coordinate space while running the other's epoch clock,
    /// and both halves would look healthy. Misprovisioning, so it refuses to start.
    GenesisMismatch {
        /// What the beacon engine was provisioned with.
        engine: BeaconSeed,
        /// What the directory the transport seats this node in carries.
        directory: BeaconSeed,
    },
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
            Self::GenesisMismatch { engine, directory } => {
                // Eight bytes, the repo's short-form for a 32-byte identifier (`config.rs`): enough to tell
                // two networks apart in a log, and the operator's actual fix is to reconcile `network_id`
                // between the beacon file and the node configuration, not to read a seed back.
                write!(f, "genesis seed mismatch: the beacon is provisioned for network ")?;
                for b in &engine.as_bytes()[..8] {
                    write!(f, "{b:02x}")?;
                }
                write!(f, " but the directory carries ")?;
                for b in &directory.as_bytes()[..8] {
                    write!(f, "{b:02x}")?;
                }
                write!(
                    f,
                    " — this node is misprovisioned and would seat itself in one network while clocking the other"
                )
            }
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
        // And the same absence answers #249: with no plane there is no probe walk, so a peer's verified
        // claim has no index to derive and an unranked binding is the whole truth here.
        None,
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
/// `capabilities` is an **argument, not a default** (#284). This entry point spawns the node a deployment
/// actually runs, so it is the one place where what the caller wired and what the HELLO announces are both in
/// scope; a `Capabilities::CORE` constant here made the whole §7.4 negotiation inert — the intersection
/// machinery complete and tested, its input never varying, so feature selection always degraded to baseline.
/// Derive the set from the modules composed (`RoleSet::advertised_capabilities`), never write it beside them.
///
/// [`Capabilities::CORE`] must be in the set: an empty intersection is the handshake's incompatibility
/// condition, so a caller that omits it refuses every peer.
pub fn spawn_self_certifying_persistent_over<F: Field + 'static>(
    fabric: Fabric,
    credentials: &NodeCredentials,
    make_engine: impl FnOnce(Point<F>) -> Box<dyn Engine + Send>,
    directory: Directory,
    capabilities: Capabilities,
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
        capabilities,
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
    // Every peer whose claim this node verifies is remembered for the epoch, because coordinate resolution needs exactly
    // that: the best claim on each point of this node's own walk, and a witness for every step it advances
    // (`crate::claims`). Owned here rather than inside the identity, because the reshuffle loop and `with_claims` read
    // the same book the verifier writes.
    let book = ClaimBook::new();
    let identity: Identity =
        Some(self_certifying_identity::<F>(creds, &hello_cell, &beacon_cell, &book, capabilities));
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
            reflexive_quorum(F::Q), Some(probe_index_on::<F>), // `F` lives here, nowhere downstream (#249)
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
        //
        // The one production write whose outcome is unconditionally discardable: the goal is that the point NOT resolve
        // to us, and all three outcomes reach it — `Superseded` means a peer's *ranked* claim landed since `spawn_inner`,
        // which is a better occupant than the unranked seed this line was putting back.
        Some(addr) => { let _ = dir_for_reshuffle.insert(coord.coords(), addr); }
        // Our own seat, with its rank. A refusal is a peer holding a better claim to the point this node derived, so
        // the node must walk on — which the reshuffle loop below does on the first `Wake::Resettle`.
        None => bind_own_seat(
            &dir_for_reshuffle,
            &handle.client().stations,
            coord.coords(),
            handle.local_addr(),
            Some(rank),
        ),
    }
    // Drive the per-epoch coordinate reshuffle off the live beacon (spec §L3, §3.2): on each `BeaconReady`
    // the loop re-derives this node's VRF coordinate for the new epoch, re-seats the engine, rebinds its
    // directory coordinate, and publishes the fresh HELLO + beacon so subsequent connections prove/verify
    // the current placement.
    let local_addr = handle.local_addr();
    supervise(DriverActor::Reshuffle, handle.stations_handle(), handle.stopping_handle(), tokio::spawn(reshuffle_loop::<F>(
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
    )));
    Ok(handle)
}

/// Build this node's self-certifying identity: what it proves about itself, what it accepts from a peer, and
/// the one byte-string that says the peer *is* this node.
///
/// **A seam, not a slice taken to satisfy a line count.** `self_certifying_inner` answers "how does a node come
/// up and take a seat"; this answers "how does a node prove and judge an identity". They change for different
/// reasons — a seating rule moves with the placement design, these three closures move with §7.3 — and only the
/// second half needs `creds`, which is why the credentials stop travelling past this call.
///
/// The verifier closure is the only place holding a peer's certificate DER — the identity the coordinate VRF
/// binds to — so it is where a claim is recorded into `book`.
///
/// Returns the [`SelfCert`] itself and not an [`Identity`]: the `Option` in that alias carries a *different*
/// question — self-certifying, or directory-trust — which is settled by the caller's choice of constructor and
/// never by anything here. Wrapping inside would have this function answer a question it is never asked.
fn self_certifying_identity<F: Field + 'static>(
    creds: &NodeCredentials,
    hello: &Arc<RwLock<Arc<Vec<u8>>>>,
    beacons: &Arc<RwLock<BeaconWindow>>,
    book: &ClaimBook,
    capabilities: Capabilities,
) -> SelfCert {
    let verify_beacon = beacons.clone();
    let verify_book = book.clone();
    let prover_creds = creds.clone();
    SelfCert {
        hello: hello.clone(),
        own_cert: Arc::new(creds.cert_der().to_vec()),
        prove: Arc::new(move |epoch, beacon| {
            let (_, proof) = crate::identity::verifiable_coordinate::<F>(&prover_creds, epoch, beacon);
            (prover_creds.cert_der().to_vec(), prover_creds.vrf_secret().public(), proof)
        }),
        verify: Arc::new(move |peer_cert: &[u8], peer_hello: &[u8]| {
            // Select the beacon for the epoch the peer proves — the current one, or a recent last-good epoch
            // within the accepted window (safe-stall, R-C1). **Outside the window is not a bad proof**: it is
            // this node admitting it cannot judge, and the two are reported apart (#236).
            let Some(epoch) = hello_epoch(peer_hello) else {
                return HelloVerdict::BadProof;
            };
            let beacon = match verify_beacon.read() {
                Ok(window) => window.beacon_for(epoch),
                // A poisoned window is a local fault, and a local fault is not the peer's forgery. Reported
                // as "cannot judge" for the same reason.
                Err(_) => None,
            };
            let Some(beacon) = beacon else {
                return HelloVerdict::EpochUnknown;
            };
            let Some(result) = verify_hello::<F>(peer_cert, peer_hello, &beacon, capabilities) else {
                return HelloVerdict::BadProof;
            };
            if let HelloResult::Established { peer, .. } = result {
                // Recorded only on success, so the book holds nothing a remote verifier would reject. A peer proving a
                // *past* epoch within the safe-stall window is deliberately not recorded: its claim is evidence about that
                // epoch's placement, and admitting it here would let a retired placement justify a displacement now.
                if epoch == verify_book.epoch() {
                    verify_book.record::<F>(peer_cert, peer.public, peer.proof, &peer.output);
                }
            }
            HelloVerdict::Ok(Box::new(result))
        }),
    }
}

/// A bounded window of recent epoch beacons behind the HELLO verifier. The coordinate proof binds to a
/// specific `(epoch, beacon)`; verifying only against the single newest beacon rejects a peer that proves the
/// current-minus-one epoch — a normal transition race, and precisely the deadlock a beacon *stall* would
/// otherwise cause (a lagging or recovering node can never present the frozen current epoch, so it is turned
/// away as `EPOCH_STALE` and the cell becomes unjoinable). Remembering the last few epochs' beacons lets such
/// a peer attach to the **last good epoch** instead (audit R-C1 safe-stall), while the bound stops a stale
/// proof from being accepted indefinitely.
struct BeaconWindow {
    /// The network's genesis seed, **retained for the life of the node and never evicted** — the verifier's
    /// half of the transport's permanent genesis door (#235). See [`beacon_for`](Self::beacon_for).
    genesis: BeaconSeed,
    recent: VecDeque<(Epoch, BeaconSeed)>,
}

impl BeaconWindow {
    /// How many epochs' beacons the window holds — the current one and `SHAPE_GRACE` before it.
    ///
    /// **Derived, and derived from the transport, because a verifier cannot usefully be wider than the wire
    /// that feeds it** (#261). It was `3` with no derivation at all, while both neighbouring "epochs of
    /// grace" constants carry careful ones and each says explicitly why it is its own number:
    /// `fanos_proteus::SHAPE_GRACE` bounds *beacon propagation*, `HOST_GRACE_EPOCHS` is pinned by the onion
    /// ratchet's retain window. This one is the propagation question again — a peer proving `N−1` is the
    /// transition race — so it is `SHAPE_GRACE`, not a third opinion about the same quantity.
    ///
    /// **What the old `3` bought: nothing.** The shapes a node can open are `{N−1, N, N+1}` plus the genesis
    /// shape (#234). A peer two epochs behind seals at `N−2`, which is in neither set, so for `N ≥ 3` its
    /// frame is never opened and its HELLO never reaches this window at all. The third slot was unreachable
    /// width that *read*, in the doc above, as tolerance for a lagging node.
    ///
    /// **And the safe-stall case in that doc is not served here — say so rather than imply it.** A node more
    /// than `SHAPE_GRACE` behind cannot get a frame across in either direction, so no width of this window
    /// reaches it; it has to re-learn the epoch, which is the §7.8 bootstrap (#235) and not a beacon cache.
    /// Widening this constant to "help" such a node is the shape that made `3` look reasonable.
    const DEPTH: usize = 1 + fanos_proteus::SHAPE_GRACE as usize;

    /// A window that has adopted nothing yet. Epoch zero is answered by the **pin**, not by an entry in
    /// `recent` — one seed in one place, so a rotation can never slide the network's own constant out from
    /// under the door that is supposed to be permanent.
    fn genesis(seed: BeaconSeed) -> Self {
        Self { genesis: seed, recent: VecDeque::with_capacity(Self::DEPTH) }
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

    /// The beacon this window remembers for `epoch` — an adopted one still inside the window, **or the
    /// pinned genesis seed, which never expires** (#235).
    ///
    /// **The pin is the verifier's half of a door the transport already holds open.** PROTEUS opens
    /// `{N−1, N, N+1}` *plus a permanent genesis shape* (#234), so a node that knows only epoch zero can
    /// always get a frame across to a rotated cell — by design, because that is how it announces itself. Its
    /// HELLO therefore arrives, is un-shaped, and then met a verifier whose newest two entries could not
    /// judge an epoch-zero proof: **the door led to a wall.** The cell answered `EpochUnknown`, dropped the
    /// connection, and the joining node was never seated. That is the measured mechanism behind #260's
    /// bimodal join — pass while `N ≤ 1`, dark for ever after.
    ///
    /// **Why this is not the widening #261 warned against.** That warning was about carrying *more adopted
    /// epochs*, which buys nothing: a peer at `N−2` cannot get a frame across at all, so no width reaches it.
    /// Genesis is the one epoch where the opposite holds — the transport singles it out and delivers it — and
    /// the seed is not a remembered rotation but a permanent network-wide constant derived from the network
    /// name (#98), which every member holds for the life of the node. Retaining a value that cannot go stale
    /// costs no staleness. The rule the two cases share: **a door is worth exactly as much as the narrowest
    /// stage behind it**, and here the verifier was the narrow one.
    ///
    /// **What it does not grant.** A coordinate is `MapToPoint(VRF(identity, epoch, beacon))`, so an
    /// epoch-zero proof still yields the one point that identity has always had at epoch zero — it cannot be
    /// steered, and the holder gets no *fresh* standing: `verify_book.record` is already gated on
    /// `epoch == book.epoch()`, so a genesis claim is judged and then deliberately not filed as evidence for
    /// any placement now. That guard was written for the safe-stall window and covers this unchanged.
    fn beacon_for(&self, epoch: Epoch) -> Option<BeaconSeed> {
        self.recent
            .iter()
            .find(|&&(e, _)| e == epoch)
            .map(|&(_, b)| b)
            .or_else(|| (epoch == Epoch::ZERO).then_some(self.genesis))
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
    /// Returns `false` only if the engine is gone, which ends the loop. A directory bind the arbitration rule
    /// **refuses** leaves all three surfaces untouched and returns `true`: the node stays exactly where it was, which is
    /// the only self-consistent answer available (see below).
    ///
    /// The order is: bind the directory, then seat the engine, then clear the old point, then publish the HELLO. The
    /// invariant the old ordering existed to protect — the new point bound *before* the old one is cleared, so there is
    /// no window in which the node is unroutable — is preserved, and the reason the bind moved to the front is that it
    /// is now the step that can **fail**. Seating the engine first and discovering afterwards that the point belongs to
    /// someone else left the node at a coordinate its own table routed elsewhere, and nothing said so. The mirror risk
    /// the reorder introduces — bind lands, engine is gone — happens only on the shutdown path, where the loop breaks
    /// immediately and the entry outlives the node by the length of one teardown.
    ///
    /// **What a refusal here means, and why it is not retried.** The walk settles against the *claim book*
    /// (`claims::settle`) and the refusal comes from the *directory* — two stores of one fact, each able to hold a claim
    /// the other has never seen. `WriteOutcome::Superseded` carries the incumbent's address, not its claim, so there is
    /// nothing to feed back into the book and re-settling would land on the same index and lose again. Holding the
    /// current placement is correct rather than a concession: the loop is event-driven, and the next `BeaconReady`
    /// re-derives everything from a fresh rank anyway.
    fn apply<F: Field>(&self, at: &mut Placement, index: u16, claim: &CoordinateClaim) -> bool {
        let point = fanos_vrf::probe_point::<F>(&at.output, index).coords();
        // Bound with this epoch's rank AND the probed index: the arbitration order is the claim *pair*, so a table
        // recording only the rank would disagree with what every node's own `settle_index` concludes
        // (`Directory::supersedes`).
        // Exhaustive, not `if let` (#260). A new outcome must be a compile error here: the variant that
        // was added — "we took the point from a live holder" — fell straight through the old `if let` and
        // was recorded nowhere, which is how a node could displace two incumbents and show an empty plane.
        match self.directory.insert_claimed(point, self.local_addr, at.output, index) {
            WriteOutcome::Displaced { evicted } => {
                self.client.record_station(Station::DirectoryPointTaken, Some(point), None);
                tracing::debug!(?point, index, ?evicted, "settled seat taken from its holder; it must walk on");
            }
            WriteOutcome::Bound | WriteOutcome::Unchanged => {}
            WriteOutcome::Superseded { keeping } => {
            self.client.record_station(Station::DirectorySeatSuperseded, Some(point), None);
            tracing::debug!(
                ?point,
                index,
                ?keeping,
                "the settled seat is held by a better claim the book has not seen; holding position"
            );
                return true;
            }
        }
        if !self.client.command(Command::Reseat { coord: point }) {
            return false;
        }
        if point != at.coord {
            // Compare-and-remove: the vacated point is cleared only while it still names THIS node. A better
            // claim may have taken it while this walk was deciding, and deleting that binding would make the
            // rightful occupant unroutable here until it announced again (#241).
            let _ = self.directory.remove_if(at.coord, self.local_addr);
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
                //
                // **Reported once, on the transition** (#260). "Free to re-seat" and "committed" are the two states the
                // whole coordinate-resolution argument turns on — `Wake::Resettle` moves one and refuses the other — and
                // until now neither was visible from outside this loop. Diagnosing a contested point without it means
                // guessing which side was even allowed to walk on, which is what cost this investigation three wrong
                // explanations. No line: the point is settled a few lines below and either `continue` can leave it where
                // it was, so a coordinate recorded here would be the one held *entering* the boundary — a value close
                // enough to the real answer to be read as it.
                if at.joining {
                    seat.client.record_station(Station::SeatCommitted, None, None);
                }
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
            // **The established node says so instead (#260).** Two rules, each sound alone, deadlock together:
            // `claim_beats` can decide the *seated* node lost, and the rule above forbids exactly that node to walk
            // on. Both then hold one point until the epoch turns. The loser is not uninformed — the winning claim is
            // in its own book, which is what woke this arm — it is **forbidden to act**, so a notification would have
            // fixed nothing. What was missing is that the state was invisible: measured on the two-node join probe,
            // the frozen side reported `collisions = 0` and looked healthy while the cell was split.
            Wake::Resettle => {
                if let Some(point) = book.outranked_at::<F>(&at.output, at.index) {
                    seat.client.record_station(Station::DirectorySeatOutranked, Some(point), None);
                    tracing::warn!(
                        ?point,
                        index = at.index,
                        "a peer proved a better claim to the point this node is seated on, and an established node \
                         must not move mid-epoch: both hold it until the next beacon re-derives placement"
                    );
                }
            }
            Wake::Stop => break,
        }
    }
}

/// Like [`spawn`], but every frame on the wire is PROTEUS-shaped by `proteus` for `epoch` (spec §13.2): a
/// peer without the secret cannot produce frames this node will accept. The engine is unchanged — shaping
/// lives entirely in the driver, below the sans-I/O boundary.
///
/// **Scope, and it is narrower than §13.3 asks for.** The shaping starts at the QUIC *stream*, so it covers
/// every frame and nothing before one. The connection itself still opens with a plaintext QUIC Initial
/// carrying the ALPN and SNI `tls::node_configs` installs, identical under every morph. Measured in
/// `tests/probe_resistance.rs`: a stranger with no community secret gets a Version Negotiation packet back,
/// and gets the *same* bytes from a `polymorph` node and a `plain` one. Until the envelope moves down to the
/// datagram, "carries no static FANOS signature" is true of the frames and false of the connection.
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
        // And the same absence answers #249: with no plane there is no probe walk, so a peer's verified
        // claim has no index to derive and an unranked binding is the whole truth here.
        None,
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

/// Bind this node's **own** coordinate in its address book, and say so when the arbitration rule refuses.
///
/// Shared by the two startup writes of a node's own seat, because a refusal means the same thing at each: a
/// *proven* claim already holds the point, so this node is missing from its own directory at the very
/// coordinate it is about to announce — every reflexive lookup then answers with someone else, and the settle
/// walk (`fanos_vrf::settle_index`) is what repairs it. Losing is the rule working; being unable to tell was
/// #241, so reporting is this helper's whole reason to exist.
///
/// `rank` is `None` where no coordinate proof exists yet (the pre-rank bind in [`spawn_inner`]). An unranked
/// write yields to any proven claim, which is exactly why the refusal is worth recording there.
fn bind_own_seat(
    directory: &Directory,
    stations: &Arc<Mutex<Stations>>,
    coord: Triple,
    addr: SocketAddr,
    rank: Option<fanos_vrf::VrfOutput>,
) {
    let outcome = match rank {
        Some(rank) => directory.insert_ranked(coord, addr, rank),
        None => directory.insert(coord, addr),
    };
    // Exhaustive for the reason at `apply` above (#260): the winning half of a collision is a fact about
    // the cell, and an `if let` on the losing one silently drops it.
    if let WriteOutcome::Displaced { evicted } = outcome {
        stations.lock().unwrap_or_else(PoisonError::into_inner).record_tagged(
            Station::DirectoryPointTaken,
            Some(coord),
            None,
            1,
        );
        tracing::debug!(?coord, ?evicted, "took the point from its holder; the evicted node must walk on");
    }
    if let WriteOutcome::Superseded { keeping } = outcome {
        stations.lock().unwrap_or_else(PoisonError::into_inner).record_tagged(
            Station::DirectorySeatSuperseded,
            Some(coord),
            None,
            1,
        );
        tracing::warn!(
            ?coord,
            ?keeping,
            own = ?addr,
            "a proven claim holds this node's own seat; it is absent from its own directory"
        );
    }
}

/// Which long-lived driver actor a [`Station::ActorDied`] observation is about (#251).
///
/// **Only the loops meant to outlive every request.** Per-connection, per-peer and per-timer tasks are
/// deliberately absent: their death is how they end, and counting it would bury the six whose death is a
/// node fault under thousands of ordinary completions. The discriminator is #244's — whether anyone has
/// another move — and it is what makes supervision affordable here and absurd per connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DriverActor {
    /// Re-derives this node's VRF coordinate each epoch. Dead: the node never reseats again.
    Reshuffle,
    /// Re-announces this node's moves. Dead: peers stop learning where it went.
    AnnounceMoves,
    /// Accepts inbound QUIC connections. Dead: the node answers nobody while still dialling out.
    Accept,
    /// Drains the send queue onto the wire. Dead: nothing this node produces ever leaves.
    Transport,
    /// Steps the engine over its inputs. Dead: the node stops thinking and keeps its sockets open.
    Engine,
    /// Correlates replies and fans events out. Dead: every `get`/`put` times out with no reason given.
    Router,
}

/// `DriverActor::ALL` is complete, proven by the compiler — same reasoning as `Station::ALL`.
const _: () = assert!(
    DriverActor::ALL.len() == core::mem::variant_count::<DriverActor>(),
    "a DriverActor variant is missing from ALL, so it is invisible to every reader that enumerates"
);

impl DriverActor {
    /// Every supervised actor, for a reader that enumerates rather than guesses.
    pub const ALL: &'static [Self] =
        &[Self::Reshuffle, Self::AnnounceMoves, Self::Accept, Self::Transport, Self::Engine, Self::Router];

    /// The discriminant carried in `Observation::tag`, written out so variant order never renumbers an
    /// operator's counters.
    #[must_use]
    pub const fn tag(self) -> u64 {
        match self {
            Self::Reshuffle => 0,
            Self::AnnounceMoves => 1,
            Self::Accept => 2,
            Self::Transport => 3,
            Self::Engine => 4,
            Self::Router => 5,
        }
    }

    /// The operator-facing name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Reshuffle => "reshuffle",
            Self::AnnounceMoves => "announce_moves",
            Self::Accept => "accept",
            Self::Transport => "transport",
            Self::Engine => "engine",
            Self::Router => "router",
        }
    }
}

/// Watch one long-lived actor and record its death where an operator can see it (#251).
///
/// A task nobody joins **cannot report its own death**: the handle is dropped, the runtime reaps it, and a
/// panic leaves only a line on stderr that no aggregate surface reads. Sixty-three actors shipped that way,
/// and `panic = "abort"` — which would at least have taken the process down loudly — is set on the
/// `maxperf` profile alone, which CI does not build. So a panic inside `accept_loop` removed this node's
/// ability to answer anyone while `health` went on saying it was fine: degraded and confident, the worst
/// shape an outage can take.
///
/// The cost is one task parked on a `JoinHandle` that wakes exactly once, ever.
///
/// ## An ending is only an outage if nobody asked for it
///
/// Three endings, kept apart in the line because the operator's next move differs — a panic is a defect, a
/// cancellation is an orderly stop, and a plain return is neither. But *which* of them is an alarm depends
/// on something the ending itself does not carry: whether the node is going away. `accept_loop` returns by
/// design the moment [`NodeHandle::shutdown`] closes the endpoint, so judged on the ending alone every
/// orderly stop of every node files an outage against `Accept` (#257). `stopping` is that missing half —
/// see [`Client::is_stopping`] for both ways a node goes away and why a panic is excused by neither.
///
/// Returns the **watcher's** handle, which callers drop — dropping a `JoinHandle` detaches, so it changes
/// nothing in production. A test can `await` it instead, which is the only way to assert that a supervisor
/// stayed *silent*: waiting on the actor proves the actor ended, not that the watcher has spoken.
fn supervise(
    actor: DriverActor,
    stations: &Arc<Mutex<Stations>>,
    stopping: &Arc<std::sync::atomic::AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
) -> tokio::task::JoinHandle<()> {
    let stations = Arc::clone(stations);
    let stopping = Arc::clone(stopping);
    tokio::spawn(async move {
        let ending = handle.await;
        let panicked = ending.as_ref().err().is_some_and(tokio::task::JoinError::is_panic);
        // Read the flag AFTER awaiting the ending: `shutdown` raises it before closing the endpoint, so an
        // actor that ended because of the stop always finds it already `true`.
        if !panicked && stopping.load(std::sync::atomic::Ordering::Acquire) {
            tracing::debug!(actor = actor.name(), "a driver actor retired because the node is stopping");
            return;
        }
        let how = match ending {
            Ok(()) => "returned, which these loops are not meant to do while the node runs",
            Err(e) if e.is_panic() => "PANICKED",
            Err(_) => "was cancelled",
        };
        tracing::error!(
            actor = actor.name(),
            how,
            "a long-lived driver actor stopped; this node has lost that capability and is still running"
        );
        stations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record_tagged(Station::ActorDied, None, Some(actor.tag()), 1);
    })
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
    // The plane's probe walk, or `None` for a pinned-coordinate deployment — see `Transport::probe_index`.
    probe_index: Option<ProbeIndex>,
) -> Result<NodeHandle, QuicError> {
    let addr = engine.address();

    // Apply production transport tuning (keep-alive + idle timeout) to both directions.
    server_cfg.transport_config(tuned_transport());
    client_cfg.transport_config(tuned_transport());

    // Both carriers go through one abstract socket so the PROTEUS envelope (§13.3/§13.5) can wrap either.
    // Production used to take `Endpoint::server`, which owns its socket and admits no decorator — the
    // reason the envelope had nowhere to live and the handshake shipped in plaintext.
    let carrier: Arc<dyn quinn::AsyncUdpSocket> = match fabric {
        Fabric::Udp(bind) => {
            use quinn::Runtime as _;
            let sock = std::net::UdpSocket::bind(bind)?;
            quinn::TokioRuntime.wrap_udp_socket(sock)?
        }
        Fabric::Abstract(socket) => socket,
    };
    // The driver-side data-path plane, created **here** rather than at the `NodeHandle` below so the
    // transport can share it (#191). It now has to exist even earlier than that: the datagram envelope is
    // the outermost gate, and a refusal there is invisible everywhere else by design (#232).
    let stations = Arc::new(Mutex::new(Stations::new()));
    // Learned by the envelope, acted on by the frame layer — see `proteus_socket::GenesisSpeakers` for why
    // it cannot live in either alone (#234).
    let joining = crate::proteus_socket::reply_addressing();
    let carrier = match &shaper {
        Some(s) => crate::proteus_socket::ProteusSocket::wrap(carrier, s, &stations, &joining),
        None => carrier,
    };
    let mut endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_cfg),
        carrier,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_cfg);
    let local_addr = endpoint.local_addr()?;
    // Unranked: no coordinate proof exists this early, and the caller rebinds with a rank immediately after.
    bind_own_seat(&directory, &stations, addr, local_addr, None);
    // Read before the directory is moved into the transport: this is the network identity every task above
    // the transport asks the handle for, so it is captured once rather than re-derived.
    let genesis = directory.genesis();
    // The node's two provisioning paths meet here and nowhere else. `BeaconParams` reaches the engine
    // (`composition.rs`), `Directory::for_network` reaches the transport (`node.rs`), and both happen to call
    // `genesis_seed(&network_id)` — an agreement held up by two independent call sites, which is not an
    // invariant, only a coincidence that has so far held. Fail closed: a seed disagreement is silent by
    // construction (coordinates derive from one value, the epoch clock from the other, and both halves report
    // healthy), so the only moment it can be caught is before the node exists.
    if let Some(engine_genesis) = engine.genesis_seed()
        && engine_genesis != genesis
    {
        return Err(QuicError::GenesisMismatch { engine: engine_genesis, directory: genesis });
    }
    tracing::debug!(?addr, %local_addr, self_certifying = identity.is_some(), "fanos-quic node up");

    let (input_tx, input_rx) = mpsc::channel::<Input>(INPUT_CAP);
    let (send_tx, send_rx) = mpsc::unbounded_channel::<SendRequest>();
    let (notify_tx, notify_rx) = mpsc::unbounded_channel::<Notification>();
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<Control>();
    let (events_tx, events_rx) = broadcast::channel::<Notification>(4096);
    // Latest-state for the epoch, fed by the router (the one lossless reader) — see [`Beacons`].
    let (beacon_tx, beacon_rx) = tokio::sync::watch::channel::<Option<(Epoch, [u8; 32])>>(None);
    let conns: ConnMap = Arc::new(Mutex::new(HashMap::new()));
    let reflexive: Reflexive = Arc::new(Mutex::new(ReflexiveAddr::new(reflexive_quorum)));
    let peer_addrs: PeerAddrs = Arc::new(Mutex::new(HashMap::new()));
    // Identity-keyed distrust, shared between the engine loop (which sees verdicts) and the accept path (which sees who
    // is seated where) — audit R-M1.
    let distrust: Arc<Distrust> = Arc::new(Distrust::default());
    // Shared with the handle, so `fanos status health` can report it (#89).
    let send_drops: Arc<std::sync::atomic::AtomicU64> = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // Shared with every supervisor, the handle and each `Client`: the one place that says whether an actor's
    // ending was asked for (#257). See [`Client::is_stopping`].
    let stopping: Arc<std::sync::atomic::AtomicBool> = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // The one live coordinate cell every handle and client above shares. A copy per layer is what let the reported
    // coordinate go stale at the first reshuffle.
    let seat = Arc::new(Mutex::new(addr));
    // `stations` is created above, before the carrier, because the PROTEUS envelope needs it. `Client::
    // record_station` and `driver_stations` already existed and already had production callers, but
    // `Transport` held no handle to the plane — so the three discards in `read_frames`, thirty lines from the
    // recorder, could not reach it and stayed uncounted (#191). One absent field is all that separated a
    // built facility from the place that needed it most.

    // One shared context object drives both the accept/receive path and the send path.
    let transport = Transport {
        stations: Arc::clone(&stations),
        joining: Arc::clone(&joining),
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
        send_drops: Arc::clone(&send_drops),
        punching: Arc::new(Mutex::new(BTreeSet::new())),
        unjudged: Arc::new(Mutex::new(BTreeSet::new())),
        probe_index,
    };
    supervise(DriverActor::AnnounceMoves, &stations, &stopping, tokio::spawn(announce_moves(transport.clone(), events_tx.subscribe())));
    supervise(DriverActor::Accept, &stations, &stopping, tokio::spawn(accept_loop(transport.clone())));
    supervise(DriverActor::Transport, &stations, &stopping, tokio::spawn(transport_loop(transport, send_rx)));
    supervise(DriverActor::Engine, &stations, &stopping, tokio::spawn(engine_loop(
        engine,
        input_rx,
        input_tx.clone(),
        send_tx,
        notify_tx,
        distrust,
    )));
    // The router owns the notification stream: it correlates get/put replies and fans events out.
    supervise(
        DriverActor::Router,
        &stations,
        &stopping,
        tokio::spawn(router_loop(notify_rx, ctrl_rx, events_tx.clone(), beacon_tx, seat.clone())),
    );

    Ok(NodeHandle {
        addr: seat,
        stations,
        stopping,
        local_addr,
        input_tx,
        ctrl_tx,
        events_tx,
        events_rx,
        beacons: beacon_rx,
        send_drops,
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
    let mut workers: HashMap<Triple, mpsc::Sender<Vec<u8>>> = HashMap::new();
    while let Some(SendRequest { to, frame }) = send_rx.recv().await {
        // Reuse the peer's worker, or start one. Workers live for the dispatcher's lifetime (bounded by the
        // node's peer set, exactly like the connection cache), so no per-peer teardown race exists: the
        // channel a frame is handed to always has a live receiver draining it.
        let worker = workers.entry(to).or_insert_with(|| {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(MAX_PEER_SEND_QUEUE);
            tokio::spawn(peer_send_worker(t.clone(), to, rx));
            tx
        });
        // **`try_send`, never `send`.** Awaiting here would let one stalled peer stop this dispatcher and
        // therefore every *other* peer's traffic — reintroducing the head-of-line blocking the per-peer
        // workers exist to remove (#129), and turning a memory leak into a total send outage. Over budget,
        // the frame is not made.
        //
        // Dropping is safe because every layer above recovers on its own: DIAULOS retransmits, a store read
        // re-fans to the shard homes, a directory slot is rewritten next epoch. It is **counted**, because a
        // silent drop is the property that makes a defect unfalsifiable — `fanos status health` reports it,
        // and a non-zero count is the operator's evidence that a peer is not draining.
        if worker.try_send(frame).is_err() {
            t.send_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// A single peer's send worker: resolve the destination to a connection (dial once, then reuse the cached
/// connection), then write each queued frame as its own QUIC uni-stream, in order. Scoped to one peer so a
/// slow dial or a broken connection cannot delay any other peer's traffic (#129).
async fn peer_send_worker(t: Transport, to: Triple, mut rx: mpsc::Receiver<Vec<u8>>) {
    // Hubs already asked to broker a punch to `to` — see the relay branch below. Local to this worker, so
    // it needs no lock, and bounded by the plane's point count because a hub is a peer coordinate.
    let mut asked: BTreeSet<Triple> = BTreeSet::new();
    // Configured entry addresses already dialed for this peer — the last rung's bound (#263). Local for the
    // same reason `asked` is, and bounded by the operator's own bootstrap list.
    let mut entries_tried: BTreeSet<SocketAddr> = BTreeSet::new();
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
            _ => cached(&t, to),
        };
        if let Some(conn) = direct {
            send_uni(&conn, &t.shaper, t.joining(&conn), &frame).await;
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
                send_uni(&hub, &t.shaper, t.joining(&hub), &connect_req_frame(to)).await;
            }
            // Symmetric-NAT relay fallback (#119): `to` is unreachable directly (no address, no cached
            // connection — the case a symmetric NAT leaves after even a hole-punch fails). Wrap the frame
            // (with ourselves as origin, so `to`'s reply routes back the same way) and ask a hub we CAN
            // reach to forward it, so any pair behind NAT still communicates. The hub forwards only to a
            // peer it already holds a connection to, so this reaches `to` iff some common node connects both
            // ends — exactly the topology the overlay's cell membership creates. This frame relays either
            // way: a punch is asynchronous, and the traffic must not wait on it.
            send_uni(&hub, &t.shaper, t.joining(&hub), &encode_relay(to, t.me, &frame)).await;
        } else if let Some(entry) = t.directory.entries().into_iter().find(|a| entries_tried.insert(*a)) {
            // **The last rung: a configured entry address** (#263). No direct path, no hub — which on a
            // small or freshly-partitioned cell is exactly where a node lands when its own lawful reseat
            // overwrote the one address it was given. The entry list is held outside the coordinate map
            // precisely so nothing can arbitrate it away; see `Directory::entries`.
            //
            // **Dialed with `to` even though the entry is probably not `to`.** The handshake settles who is
            // there: if the entry IS `to`'s current address the connection is filed under `to` and the next
            // frame goes direct, and if it is not, the peer is filed at the coordinate it PROVED and becomes
            // the hub this ladder's rung above can use. Both outcomes are the dialer's existing behaviour;
            // what had to change first was that neither of them threw the connection away (#264) and that a
            // surplus one no longer costs the answering peer its route (#265). This rung was red for three
            // passes on exactly those two defects.
            //
            // **Spawned, never awaited.** Awaiting put a full `DIAL_TIMEOUT` on the *drop* path — the one
            // path that must be fast, because it is reached when there is nothing to wait for. That is
            // #129's stall, and the comment on the direct dial above already says so. Recovery is also what
            // this rung *is*: this frame is dropped either way, and the dial buys the next one.
            t.record_station(Station::DirectoryEntryFallback, Some(to), None);
            let recover = t.clone();
            tokio::spawn(async move {
                let _ = get_or_connect(&recover, to, entry).await;
            });
            t.directory.note_unresolved_drop(to);
        } else {
            // Genuinely unroutable (no direct path, no hub, no untried entry): drop, counted + logged so it
            // is observable.
            t.directory.note_unresolved_drop(to);
        }
    }
}

/// Write one frame as a single shaped uni-stream on `conn` (the shared send primitive). When the active
/// morph time-shapes (§13.3), the frame is paced by the shaper's per-packet delay first — the traffic-shaper
/// applied at the one point every data frame passes through.
async fn send_uni(conn: &Connection, shaper: &Shaper, joining: Option<OpenedUnder>, frame: &[u8]) {
    let (wire, delay) = shape_out_timed(shaper, joining, frame);
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
    let mut map = conns.lock().ok()?;
    let peers: Vec<Triple> = map.keys().copied().filter(|&p| p != exclude).collect();
    peers.into_iter().find_map(|p| live_conn(&mut map, p).0.map(|c| (p, c)))
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
    if let Some(conn) = cached(t, to) {
        return Some(conn);
    }
    // Bound the dial: a peer that has gone away (shut down, NAT-dropped) must fail FAST, not hang the send
    // loop for the full QUIC handshake timeout. That stall is the #129 availability bug — a `get`'s
    // `Lookup`s to live shard-homes were blocked behind a dead peer's dial, so the erasure shards never
    // gathered even though the redundancy tolerates the loss. A real peer answers in well under this.
    // A connect failure (the transport refused/timed out) feeds the morph auto-fallback breaker. A completed
    // handshake does **not** reset it — see below.
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

    match &t.identity {
        // HELLO mode: announce our coordinate as the first uni-stream. No reply is awaited, so this mode has
        // no shaped round trip to read and the QUIC handshake is the only signal there is. Stated rather
        // than assumed: every shipped composition goes through `spawn_self_certifying_*` (the arm below);
        // this one is the simulator's and the tests'.
        None => {
            apply_outcome(&t.shaper, &t.controller, true);
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
            // **Bounded by the same deadline the accept side uses** (#233). The QUIC half above has
            // `DIAL_TIMEOUT`; this half had nothing, on the very loop that bound exists to protect, so a peer
            // that completed the handshake and then opened no stream wedged the send loop until QUIC's 30 s
            // idle timeout. The acceptor has always wrapped the whole handshake in `HELLO_DEADLINE`; the
            // dialer now does too, rather than inventing a second constant for one quantity.
            let handshake = tokio::time::timeout(HELLO_DEADLINE, hello_exchange(&conn, t, id))
                .await
                .unwrap_or(Handshake { peer: PeerIdentity::Rejected, round_trip: false, rank: None });
            // Nothing crossed the network, so nothing downstream may treat this as evidence about the network
            // (#350). Returning here — before `apply_outcome` — is the whole point: the breaker must not read a
            // loop-back as a cut morph. The frame is dropped rather than delivered, which is the honest outcome:
            // the addressee is a different node that currently shares our point, and it is unreachable BY
            // COORDINATE until one of us reseats. `reshuffle_loop` is already doing exactly that, driven by the
            // claim this connection would have recorded had it been a peer's.
            if matches!(handshake.peer, PeerIdentity::Ourself) {
                t.record_station(Station::TransportSelfConnection, Some(to), None);
                tracing::debug!(?to, "dialed our own coordinate; another node holds the point we drew");
                return None;
            }
            // **The breaker reads the shaped round trip, not the QUIC handshake** (#231). Shaping starts at
            // the stream, so the handshake completing says nothing about the morph — a censor that admits
            // the handshake and kills the data phase used to be recorded as a success, resetting the breaker
            // for ever in exactly the case the morph exists to answer. A refused proof still counts as a
            // success here: the bytes crossed, and we rejected their contents.
            apply_outcome(&t.shaper, &t.controller, handshake.round_trip);
            if !handshake.round_trip {
                // The breaker acts on this; the operator needs to *see* it. A rotation says only that
                // something tripped, while this says how often the shaped path is cut with the handshake let
                // through — the number that separates a lossy network from a filter.
                t.record_station(Station::TransportRoundTripLost, Some(to), None);
            }
            // **A peer that proved a DIFFERENT coordinate has moved; it has not lied** (#240). One message
            // and one `return None` used to cover both, and the two call for opposite responses:
            //
            // * `Some(actual)` — the HELLO verified. This address hosts `actual` and does not host `to`, so
            //   our directory entry is stale. Seats rotate every epoch by §L3, which makes this routine
            //   rather than exceptional, and **the correction arrives inside the rejection**: the peer just
            //   proved where it is. Throwing that away left the dial failing on every retry while the answer
            //   came back each time.
            // * `None` — nothing was proved: an impostor, or an epoch we cannot judge (already counted at
            //   `hello.epoch_unknown` / `hello.proof_rejected`). Unchanged: drop, and tell it nothing (§L0).
            //
            // The payload is NOT redirected to `actual`. A coordinate is the overlay identity, so delivering
            // it there would be a misdelivery, not a repair — this fixes the map and fails the send.
            let Handshake { peer: proven, rank, .. } = handshake;
            match proven {
                PeerIdentity::Proven(actual) if actual == to => {}
                PeerIdentity::Proven(actual) => {
                    // Sound by the same rule `spawn_punch` already follows: an address binding is recorded
                    // only for a coordinate that was *proved* at it, and this one was, over mutual TLS to an
                    // address we chose ourselves.
                    //
                    // **RANKED, and #249 needed no wire change to get there.** For a long time this wrote
                    // an unranked binding, and the comment here argued that "the index is the half a
                    // handshake cannot supply". That premise was false, and `fanos_vrf::probe_index_of`'s
                    // own doc says so: a verifier "learns how far along `p` sits for that peer **without
                    // being told**", which is exactly what keeps `verify_coordinate_claim` non-recursive.
                    // Nothing was missing from the frame. TWO things were dropped at TWO boundaries:
                    //
                    //  * the peer's VRF output — its rank — which `hello_exchange` had in hand and bound to
                    //    `peer: _`, now carried as `Handshake::rank`; and
                    //  * the plane type `F`, monomorphised away at spawn, now carried back as the value
                    //    `Transport::probe_index`.
                    //
                    // With both, the index is DERIVED here from what the handshake proved. It cannot be
                    // fabricated — given (output, point) it is determined — so the old fear of writing a
                    // false index 0 and beating a peer legitimately seated further along its walk does not
                    // arise: a wrong index is not expressible, only an absent one.
                    //
                    // The measured cost of the old rule was `route [1,1,1,1,1,1,1]`: every node reached
                    // exactly one point, its own, and the roster never agreed.
                    let outcome = match (t.probe_index, rank) {
                        (Some(index_of), Some(rank)) => match index_of(&rank, actual) {
                            Some(index) => t.directory.insert_claimed(actual, addr, rank, index),
                            // Proved a coordinate that is not on its own walk. Not our business to resolve —
                            // record reachability and let the claim book's arbitration judge the claim.
                            None => t.directory.insert(actual, addr),
                        },
                        // No plane (a pinned deployment) or no rank recovered: an unranked binding is the
                        // whole truth, exactly as before.
                        _ => t.directory.insert(actual, addr),
                    };
                    //
                    match outcome {
                        WriteOutcome::Superseded { keeping } => {
                            t.record_station(Station::DirectoryRouteSuperseded, Some(actual), None);
                            tracing::debug!(?actual, ?addr, ?keeping, "proved route not recorded; a better claim holds the point");
                        }
                        WriteOutcome::Displaced { evicted } => {
                            t.record_station(Station::DirectoryPointTaken, Some(actual), None);
                            tracing::debug!(?actual, ?addr, ?evicted, "proved route took the point from its holder");
                        }
                        WriteOutcome::Bound | WriteOutcome::Unchanged => {}
                    }
                    // Retract the stale binding only if it still names this address — a concurrent refresh
                    // may already have corrected it, and clobbering that would trade one stale entry for
                    // another. Read-then-write was the first form of this and had a window: a rebinding
                    // landing between the `resolve` and the `remove` was deleted by a decision taken before
                    // it existed. `remove_if` closes the pair inside one write lock (#241).
                    // **Recorded on the retraction, not before it** (#263). The station means "our entry
                    // sent this dial to the wrong node", and `remove_if` answers exactly that: it returns
                    // whether the directory really did name `addr` for `to`. The entry-address rung dials an
                    // address the directory never named, so the old unconditional record would have reported
                    // a stale entry that did not exist — a counter lying about the one thing it is for.
                    if t.directory.remove_if(to, addr) {
                        t.record_station(Station::DirectoryStaleCoordinate, Some(to), None);
                    }
                    // **The connection is KEPT, filed under the coordinate it proved** (#264). It used to be
                    // dropped here, with the reason "caching a connection that arrived through a *failed*
                    // dial is a new state for the connection map, and this change is about the directory".
                    // The second half is a statement of that change's scope, not a safety argument, and the
                    // first does not survive reading: the handshake **proved** this peer sits at `actual`, so
                    // a live authenticated connection to a proven coordinate is exactly what this map holds —
                    // it is what the accept path files for every inbound peer. The dial "failed" only in that
                    // it did not reach `to`, and the send still fails, which is #240's behaviour unchanged.
                    //
                    // **What dropping it cost, measured.** The peer that answered has already filed this
                    // connection under *our* coordinate as its route back to us (`accept_loop`, #119), and
                    // that write is unconditional — so it replaced whatever live connection it had for us.
                    // Discarding our end then closed the connection its map now points at, and its route to
                    // us was gone until something else re-established one. A coordinate move is routine (that
                    // is why #240 exists), so these throwaway dials are routine too. Keeping the connection
                    // removes them at the source, which is better than teaching the acceptor to defend
                    // against them: that defence costs a reconnect delay, this costs nothing.
                    //
                    // **Compare-and-insert under one lock**, never a blind overwrite — the very hazard above,
                    // one table over. If a live connection already holds `actual` it stays, and ours is the
                    // redundant one; the read-then-write form of this is the window #241 closed in the
                    // directory with `remove_if`.
                    let filed = match t.conns.lock() {
                        // Filed unconditionally now (#265): the list holds it beside whatever is already
                        // there, so there is nothing to compare against and nothing to evict. #264's
                        // compare-and-insert existed only because the map held one connection per peer.
                        Ok(mut map) => {
                            file_conn(&mut map, actual, conn.clone());
                            true
                        }
                        Err(_) => false,
                    };
                    if filed {
                        t.record_station(Station::DirectoryMovedPeerRetained, Some(actual), None);
                        tokio::spawn(read_frames(conn.clone(), actual, t.clone()));
                    }
                    // No `spawn_observed_addr` and no `peer_addrs` entry: both are about an address the peer
                    // dialed in *from*, and here we dialed out to a listen address the directory named. The
                    // binding worth recording was `actual → addr`, and the write above already made it.
                    tracing::debug!(?to, ?actual, filed, "dialed coordinate has moved; directory corrected");
                    return None;
                }
                // **We could not judge it, so we keep the connection and fail only the send** (#235). This
                // dial was to `to`, and nothing here proved the peer is `to` — so no directory write, no
                // connection-map entry, and the caller's frame is not delivered. What the connection *is*
                // good for is the one thing this node is missing: a beacon round, which authenticates
                // itself against the group commitment and needs no trusted sender. Dropping it instead is
                // what made §7.8's bootstrap unreachable — the pull-sync it defines has to run over a
                // connection, and this was the connection.
                PeerIdentity::Unjudged(u) => {
                    spawn_restricted(conn, u, t.clone());
                    return None;
                }
                PeerIdentity::Rejected => {
                    tracing::warn!(?to, "peer proved no coordinate (impostor or malformed claim); rejecting");
                    return None;
                }
                // Unreachable: the loop-back is answered above, before `apply_outcome`, precisely so it never
                // reaches the arms that write the directory and the connection map. Written out rather than
                // folded into a wildcard because a wildcard here would silently absorb the NEXT variant too,
                // and this match is where a mis-sorted identity costs a directory write.
                PeerIdentity::Ourself => return None,
            }
        }
    }
    // Tell the peer the address we observe its connection arriving from — its reflexive/public address
    // for NAT traversal (#119) — on a spawned task, so this side-channel never delays the connection
    // becoming usable. Our own reflexive address arrives symmetrically on the peer's `ObservedAddr`.
    spawn_observed_addr(conn.clone(), t.shaper.clone(), t.joining(&conn));
    // The dialer knows the peer identity intrinsically (it chose `to`): tag replies with it.
    tokio::spawn(read_frames(conn.clone(), to, t.clone()));
    if let Ok(mut map) = t.conns.lock() {
        file_conn(&mut map, to, conn.clone());
    }
    Some(conn)
}

/// A cached, still-open connection to `peer`, if any.
///
/// Takes the whole [`Transport`] rather than just the map so the pruning can be **reported** (#267).
/// `live_conn` hands back how many entries it dropped, and discarding that number is what left the
/// question "does this node ever observe the peer closing its surplus" unanswerable — the single most
/// consequential fact about a list whose other end has a different retention rule.
fn cached(t: &Transport, peer: Triple) -> Option<Connection> {
    let (conn, pruned, surplus) = {
        let mut map = t.conns.lock().ok()?;
        let surplus = map.get(&peer).is_some_and(|l| l.len() > 1);
        let (conn, pruned) = live_conn(&mut map, peer);
        (conn, pruned, surplus)
    };
    // Reported on every surplus read, **including the ones that prune nothing**. Recording only the
    // non-zero case makes absence mean two incompatible things — "read it, nothing was dead" and "never
    // read it" — and the measurement this was built for landed on exactly that ambiguity.
    if surplus {
        t.record_station(Station::ConnSurplusRead, Some(peer), Some(pruned as u64));
    }
    conn
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
async fn resolve_peer_hello(conn: &Connection, t: &Transport) -> PeerIdentity {
    match &t.identity {
        // The accept side wants the coordinate and nothing else. It deliberately does **not** feed the morph
        // breaker: an inbound exchange reports whether a *peer's* transport reached us, and the breaker
        // regulates whether ours reaches out. Rotating on someone else's reachability would let one peer
        // walk this node's morph chain.
        Some(id) => hello_exchange(conn, t, id).await.peer,
        None => read_hello(conn, t).await.map_or(PeerIdentity::Rejected, PeerIdentity::Proven),
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
                let from = match resolve_peer_hello(&conn, &t).await {
                    PeerIdentity::Proven(from) => from,
                    // **Kept, not dropped, and kept out of every table** (#235). Symmetric with the dial
                    // side: this peer proved an epoch we hold no beacon for, and the connection it arrived
                    // on is the one place that beacon can come from. Nothing below runs — no seat, no
                    // connection map, no hole-punch address — because all three are statements about a
                    // coordinate, and none was proved. Handed OUT of the deadline rather than served here:
                    // `HELLO_DEADLINE` bounds a handshake, and this connection's whole purpose is to
                    // outlive one.
                    PeerIdentity::Unjudged(u) => return Some((conn, PeerIdentity::Unjudged(u))),
                    PeerIdentity::Rejected => return None,
                    // Our own dial, arriving back at us (#350). Dropped rather than served: every table below is
                    // a statement about a *peer*, and this is not one. Deliberately not counted here — the dial
                    // side already recorded the same event at `transport.self_connection`, and counting both
                    // ends would double every occurrence of a single collision.
                    //
                    // **It says so itself rather than falling through to the arm below**, which announces "bad
                    // proof or negotiation incompatible" — true of a forgery and false of this. An operator
                    // reading that line for a placement collision is sent looking for an attacker.
                    PeerIdentity::Ourself => {
                        tracing::debug!("inbound connection is this node's own dial arriving back; dropping");
                        return None;
                    }
                };
                // Audit R-M1: the HELLO exchange just proved this peer's coordinate against its certificate, so this is
                // the one moment the identity↔coordinate binding is known. Seat it, and issue whatever the engine needs
                // to stay consistent — clear a stale tag if the occupant changed, re-apply one if this identity is
                // still distrusted. Both can fire, and `seat` orders them so the re-application is not undone.
                if let Some(cert) = peer_cert_der(&conn) {
                    for cmd in t.distrust.seat(from, identity_of(&cert)) {
                        let _ = t.input_tx.send(Input::Command(cmd)).await;
                    }
                }
                Some((conn, PeerIdentity::Proven(from)))
            })
            .await;
            let (conn, from) = match established {
                Ok(Some((conn, PeerIdentity::Proven(from)))) => (conn, from),
                // Unreachable for the same reason as its dial-side twin: the closure above answers `Ourself`
                // with `None`, so it never reaches here. Spelled out rather than wildcarded so that a future
                // identity variant has to be sorted deliberately instead of inheriting "drop it".
                Ok(Some((_, PeerIdentity::Ourself))) => return,
                // The restricted state runs **here**, inside the handler, so the inbound permit and the
                // per-source guard are held for its whole life — exactly as they are for `read_frames`.
                // Spawning it instead would free both the moment the handshake ended, and an unjudgeable
                // peer would then cost nothing to hold, which is the one thing every bound on this path
                // exists to prevent (audit A6/C3).
                Ok(Some((conn, PeerIdentity::Unjudged(u)))) => {
                    read_restricted(conn, u, t).await;
                    return;
                }
                // Unreachable by construction: the block above returns `None` rather than a `Rejected`.
                // Matched rather than `_`-ed so that adding a further identity state is a compile error here —
                // which is exactly what happened when `Ourself` arrived, and the arm above it is the answer.
                Ok(Some((_, PeerIdentity::Rejected)) | None) => {
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
            // **Observed, not changed** (#265). The write stays unconditional — five explanations for the
            // route loss have already been refuted, and changing behaviour on a sixth guess is how the last
            // three passes went. What was missing is that this eviction left no trace at all: `conns` is the
            // table reverse reachability depends on and it had no instrument, so "the route was replaced by
            // a connection about to close" and "there was never a route" were the same silence.
            //
            // Under one lock, so the observation cannot disagree with the write it describes.
            let already_held = match t.conns.lock() {
                Ok(mut map) => file_conn(&mut map, from, conn.clone()),
                Err(_) => 0,
            };
            if already_held > 0 {
                t.record_station(Station::ConnSurplusHeld, Some(from), None);
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
            spawn_observed_addr(conn.clone(), t.shaper.clone(), t.joining(&conn));
            // Subsequent uni-streams are this peer's frames.
            read_frames(conn, from, t).await;
        });
    }
}

/// Announce our HELLO (a pre-built [`FrameType::Hello`] frame: negotiation parameters ‖ `epoch` ‖
/// `coord` ‖ proof-of-coordinate) as a uni-stream, shaped like any frame.
async fn send_hello(conn: &Connection, shaper: &Shaper, joining: Option<OpenedUnder>, hello: &[u8]) {
    if let Ok(mut stream) = conn.open_uni().await {
        let _ = stream.write_all(&shape_out_joining(shaper, joining, hello)).await;
        let _ = stream.finish();
    }
}

/// Fire-and-forget a reflexive-address report to `conn`'s peer (the source address we observe it at,
/// #119) on a spawned task, so this side-channel never blocks the connection's critical path — reading
/// the peer's frames or completing setup. A blocking send here can stall a busy cell (worsening #129).
fn spawn_observed_addr(conn: Connection, shaper: Shaper, joining: Option<OpenedUnder>) {
    let observed = conn.remote_address();
    tokio::spawn(async move {
        send_framed(&conn, &shaper, joining, FrameType::ObservedAddr, &encode_addr(observed)).await;
    });
}

/// Write one framed message as a fresh uni-stream, shaped like any frame — the shared send
/// primitive [`send_hello_ack`] and [`send_error`] build on (spec §7.2 framing).
async fn send_framed(conn: &Connection, shaper: &Shaper, joining: Option<OpenedUnder>, ty: FrameType, body: &[u8]) {
    let mut frame = Vec::new();
    encode_frame(ty.code(), body, &mut frame);
    if let Ok(mut stream) = conn.open_uni().await {
        let _ = stream.write_all(&shape_out_joining(shaper, joining, &frame)).await;
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
    joining: Option<OpenedUnder>,
    version: u16,
    capabilities: Capabilities,
) {
    let mut body = Vec::with_capacity(6);
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&capabilities.bits().to_be_bytes());
    send_framed(conn, shaper, joining, FrameType::HelloAck, &body).await;
}

/// Send an `ERROR` frame (spec §7.5) reporting `err` with no reason text — the handshake's
/// incompatibility path (state diagram: `HELLO_SENT → CLOSED`). Best-effort: the connection is
/// being abandoned regardless of whether this write lands.
async fn send_error(conn: &Connection, shaper: &Shaper, joining: Option<OpenedUnder>, err: ProtocolError) {
    let body = encode_error(err, b"");
    send_framed(conn, shaper, joining, FrameType::Error, &body).await;
}

/// What a peer's first uni-stream produced — **three states, not two** (#231).
///
/// The split exists for one reason: only [`Silent`](Self::Silent) is a statement about the *transport*, and
/// the morph auto-fallback must not rotate on the other two. A refused proof means the shaped round trip
/// worked perfectly and we did not like what it carried; rotating the morph would answer a question nobody
/// asked, and — worse — a peer that can make us refuse could then drive our morph chain.
enum PeerHello {
    /// Nothing decodable came back: no stream, a read error, or bytes that did not un-shape. The shaped
    /// round trip did not complete, which is the only outcome here the morph controls.
    Silent,
    /// A HELLO arrived, decoded, and produced a negotiation result — established or incompatible.
    ///
    /// Boxed because [`HelloResult::Established`] carries the peer's certificate material and dwarfs the two
    /// unit variants; without it every `PeerHello` on the stack would be sized for the rare arm.
    Answered(Box<HelloResult>),
    /// A HELLO arrived and decoded, and we refused it. The transport worked; the identity did not.
    ///
    /// **Which of the two reasons it was is recorded where it is known**, at the two stations
    /// [`HelloProofRejected`](Station::HelloProofRejected) and
    /// [`HelloEpochUnknown`](Station::HelloEpochUnknown), rather than carried here (#236). The caller needs
    /// only "not a transport failure"; an operator needs the reason, and the operator's channel is the
    /// station plane.
    Refused,
    /// A HELLO arrived and decoded, and this node **cannot judge it**: it holds no beacon for the epoch the
    /// peer proves (#235). Split off from [`Refused`](Self::Refused) because the two call for opposite
    /// responses — a forged proof is a peer to be rid of, an unjudgeable epoch is *our* gap, and the
    /// connection carrying it is the only place the beacon that closes the gap can arrive from.
    /// Carries what the peer **claims**, unproven — a label for a connection that is in no routing table,
    /// never a routing or reply target. See [`hello_coord`](crate::identity::hello_coord).
    Unjudgeable(Triple),
}

/// Read the peer's first uni-stream as its HELLO, verify its coordinate proof against the peer's
/// authenticated certificate, and negotiate the session. This is the authenticated-identity step for a VRF
/// coordinate — a proof for one certificate does not verify against another, so no live challenge is needed
/// (spec §7.3).
async fn read_verified_hello(
    conn: &Connection,
    t: &Transport,
    verify: &HelloVerifier,
) -> PeerHello {
    let Ok(mut stream) = conn.accept_uni().await else {
        return PeerHello::Silent;
    };
    let Ok(raw) = stream.read_to_end(max_wire()).await else {
        return PeerHello::Silent;
    };
    // **The arm is available here and deliberately not acted on yet** (#234). Answering a genesis-shaped
    // HELLO in the genesis shape is right, but it is not sufficient and would look like a fix: both sides
    // `send_hello` BEFORE they read one, so the member's own HELLO is already on the wire — shaped at the
    // live epoch — by the time this line runs, and a joiner cannot read it. Closing that needs the arm
    // known at SEND time, which means sharing the datagram layer's `genesis_speakers` map with the driver.
    let Some((hello, _under)) = shape_in(&t.shaper, raw) else {
        t.record_station(Station::WireUnshaped, None, None);
        return PeerHello::Silent;
    };
    let Some(cert) = peer_cert_der(conn) else {
        // A QUIC peer with no certificate cannot have proved anything: that is a malformed claim, not a
        // beacon we are missing.
        t.record_station(Station::HelloProofRejected, None, None);
        return PeerHello::Refused;
    };
    match verify(&cert, &hello) {
        HelloVerdict::Ok(result) => PeerHello::Answered(result),
        HelloVerdict::BadProof => {
            t.record_station(Station::HelloProofRejected, None, None);
            PeerHello::Refused
        }
        HelloVerdict::EpochUnknown => {
            // Not keyed by line: the claim is unverified, so the coordinate it names is not yet a fact about
            // anyone — attaching it would let a stranger choose which line this node's counters accuse. The
            // claim IS carried in the arm below, for routing-free labelling only; the station stays blind.
            t.record_station(Station::HelloEpochUnknown, None, None);
            match hello_coord(&hello) {
                Some(claimed) => PeerHello::Unjudgeable(claimed),
                // A HELLO that passed `verify`'s own length checks but whose coordinate will not decode is
                // malformed, not unjudgeable — there is nothing to hold a connection open for.
                None => PeerHello::Refused,
            }
        }
    }
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
async fn hello_exchange(conn: &Connection, t: &Transport, id: &SelfCert) -> Handshake {
    // **Asked before the first byte, because after it there is nothing left to prevent** (#350). A peer
    // authenticated with our own certificate is us: the coordinate we dialed resolved to our own endpoint, which
    // happens exactly when another node has drawn the same point and the directory serves it to us. Everything
    // downstream would then be correct in isolation and wrong together — the HELLO verifies (it is ours), the
    // proven coordinate equals the one we dialed (it is ours), and the frame is handed to our own engine as
    // though a peer had sent it. Measured on forced collisions: 20 of 20 payloads delivered to the sender.
    //
    // Placed in `hello_exchange` rather than at either call site because BOTH sides need it and they need it for
    // the same reason — the dial side to stop a misdelivery, the accept side to stop serving a stranger that is
    // itself. One check, two paths; a per-site copy is the divergence this file has been bitten by before.
    if peer_cert_der(conn).is_some_and(|peer_cert| peer_cert.as_slice() == id.own_cert.as_slice()) {
        return Handshake { peer: PeerIdentity::Ourself, round_trip: false, rank: None };
    }
    // Snapshot the current-epoch HELLO (an `Arc` clone) and drop the lock before awaiting, so a concurrent
    // reshuffle can rewrite it without blocking on this connection's I/O. A poisoned lock rejects the
    // handshake, matching the connection-map convention elsewhere in this driver — and it is a *local*
    // fault, so it says nothing about the transport.
    let Ok(hello) = id.hello.read().map(|h| h.clone()) else {
        return Handshake { peer: PeerIdentity::Rejected, round_trip: false, rank: None };
    };
    // Asked BEFORE the first byte goes out, which is the whole point: by the time an inbound frame could
    // tell us, ours has already left in the wrong shape (#234).
    let joining = t.joining(conn);
    send_hello(conn, &t.shaper, joining, &hello).await;
    match read_verified_hello(conn, t, &id.verify).await {
        PeerHello::Answered(result) => match *result {
            HelloResult::Established {
                coord,
                version,
                capabilities,
                // The claim material is ALSO recorded by the verifier closure (`spawn_self_certifying`),
                // which is the only place holding the peer's certificate DER — the identity the coordinate
                // VRF binds to. That copy feeds the settle oracle; this one feeds the dial table, and until
                // #249 the second consumer simply had nothing (`peer: _`).
                peer,
            } => {
                send_hello_ack(conn, &t.shaper, joining, version, capabilities).await;
                Handshake { peer: PeerIdentity::Proven(coord), round_trip: true, rank: Some(peer.output) }
            }
            HelloResult::Incompatible(err) => {
                tracing::warn!(?err, "HELLO negotiation incompatible; sending ERROR and aborting");
                send_error(conn, &t.shaper, joining, err).await;
                // A version disagreement is proof the shaped bytes crossed intact — we read and parsed them.
                Handshake { peer: PeerIdentity::Rejected, round_trip: true, rank: None }
            }
        },
        // No `HELLO_ACK` and no `ERROR`: an ACK echoes *agreed* parameters, and nothing was agreed — we
        // could not read the peer's claim. An ERROR would be worse: it tells a stranger which of our gates
        // it hit (§L0), and this peer is very likely honest and simply ahead of us.
        PeerHello::Unjudgeable(u) => Handshake { peer: PeerIdentity::Unjudged(u), round_trip: true, rank: None },
        PeerHello::Refused => Handshake { peer: PeerIdentity::Rejected, round_trip: true, rank: None },
        PeerHello::Silent => Handshake { peer: PeerIdentity::Rejected, round_trip: false, rank: None },
    }
}

/// The outcome of a HELLO exchange, split along the line the two consumers actually need (#231).
///
/// `peer` answers "who is this?" — the connection is kept or dropped on it. `round_trip` answers a
/// different question, "did a shaped frame make it there and back?", and only the morph auto-fallback reads
/// it. Before this they were one `Option<Triple>`, so the breaker had nothing to read at this layer and was
/// fed the QUIC handshake instead — an event the morph cannot influence, since shaping starts above it.
struct Handshake {
    /// What the exchange settled about **who** the peer is.
    peer: PeerIdentity,
    /// The peer's proven VRF **output** — its rank — when the exchange recovered one (#249).
    ///
    /// It was always here and always discarded: `hello_exchange`'s `Established` arm binds `peer: _` with a
    /// comment saying the verifier closure records the claim material, which is true and is about a
    /// *different consumer* (the settle oracle's `ClaimBook`). The dial table needs it too, and dropping it
    /// at this boundary is half of why a verified peer could never become a ranked binding — the other half
    /// being that `F` is monomorphised away before the send loop, which [`Transport::probe_index`] carries
    /// back as a value.
    ///
    /// `None` on every non-`Proven` outcome, and on a `Proven` one reached by a path that never had it.
    rank: Option<fanos_vrf::VrfOutput>,
    /// Whether a shaped frame completed the round trip. **A refusal counts as `true`**: we decoded what the
    /// peer sent and rejected its contents, so the transport is not what failed.
    round_trip: bool,
}

/// What a completed exchange settled about **who** the peer is — three states, because "we do not know"
/// and "we know it is nobody" lead to opposite handling of the same live connection (#235).
enum PeerIdentity {
    /// A coordinate proved against the peer's authenticated certificate. The connection is routable.
    Proven(Triple),
    /// The peer named an epoch this node holds no beacon for, so nothing is proved *and nothing is
    /// disproved*. The connection is kept but stays out of every routing table — see [`read_restricted`].
    /// The `Triple` is the peer's unproven claim, carried only as a label.
    Unjudged(Triple),
    /// Nothing was established: a forged proof, an incompatible negotiation, a local fault, or silence.
    Rejected,
    /// The peer authenticated with **this node's own certificate**: the connection loops back to us (#350).
    ///
    /// A fourth answer rather than a fold into [`Rejected`](Self::Rejected), because the two demand opposite
    /// handling one line later. `Rejected` means the shaped path carried bytes and we disliked them, so it feeds
    /// `apply_outcome` and therefore the morph auto-fallback breaker. This means no bytes left the host at all,
    /// so feeding the breaker would manufacture evidence of censorship out of a placement collision — the
    /// "alarm that cannot know what normal is" this platform has paid for before. It is also the only refusal
    /// here that is not about a peer, which is why it is counted at its own station and not with the forgeries.
    Ourself,
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
                    Ok(map) => map.values().flatten().cloned().collect(),
                    Err(_) => continue,
                };
                for conn in peers {
                    send_hello(&conn, &t.shaper, t.joining(&conn), &hello).await;
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
    // The mid-connection move is counted at the same two gates as the initial HELLO (#236): a re-announced
    // coordinate this node cannot judge is the peer moving past our stale beacon, not the peer lying.
    match (id.verify)(&cert, frame) {
        HelloVerdict::Ok(result) => match *result {
            HelloResult::Established { coord, .. } => (coord != known).then_some(coord),
            HelloResult::Incompatible(_) => None,
        },
        HelloVerdict::BadProof => {
            t.record_station(Station::HelloProofRejected, Some(known), None);
            None
        }
        HelloVerdict::EpochUnknown => {
            t.record_station(Station::HelloEpochUnknown, Some(known), None);
            None
        }
    }
}

/// Whether a frame may cross from a peer whose coordinate is **unproven** (#235).
///
/// **The rule is read off the consumer, not chosen:** a frame whose handler uses `from` cannot be admitted
/// from a peer whose coordinate is a claim. Applying it to `BeaconNode::step`'s dispatch leaves exactly one
/// frame:
///
/// * `Beacon` → `on_round(f.body)`. `from` is **not read**. The round carries its own proof against the
///   group commitment, so a forged one is rejected by the same check that rejects a forged flood from a
///   proven peer. Admitted.
/// * `BeaconReq` → `on_beacon_req(from)`, where `from` is the **reply target**. From an unproven peer this
///   is both useless (it is not reachable at the coordinate it names, precisely because we filed nothing)
///   and a small reflection primitive — we would send to whoever really holds that point. Refused.
/// * `BeaconPartial` and the three reshare frames: a joining node has no share to contribute and no reshare
///   to trigger, so admitting them would widen the surface for nothing.
///
/// So this is **narrower than `is_beacon_frame`** on purpose, and the difference is not a copy that drifted:
/// that predicate answers "which engine owns this frame", this one answers "may a stranger send it".
fn admitted_unjudged(frame: &[u8]) -> bool {
    matches!(
        decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()),
        Some(FrameType::Beacon)
    )
}

/// Hold a connection whose peer this node **could not judge**, and read the one thing it can safely accept
/// from it: a beacon round (#235).
///
/// This is what makes §7.8's bootstrap reachable. The pull-sync it defines (`request_sync` → `on_beacon_req`
/// → a round) has to run over a connection, and until now the handshake dropped the only connection there
/// was — the joining node refused a cell it could not judge, and so never received the beacon that would
/// let it judge. A node needed to be a member to become one.
///
/// **There is deliberately no promotion path, and that is a simplification the design gained by reading.**
/// Once a round is adopted, `reshuffle_loop` re-derives this node's seat and rewrites its HELLO, and the
/// very next send dials a fresh connection that both sides *can* judge, gets cached, and proceeds as
/// normal. Promoting this connection in place would buy one connection setup and cost a re-verification
/// hook, a stored copy of the peer's HELLO, and a `select!` over `Connection::accept_uni` — which quinn
/// does not document as cancel-safe, and this is the authentication path.
///
/// The peer is told nothing and this node claims nothing: no directory write, no connection-map entry, no
/// hole-punch address, no seat, no distrust binding. `claimed` labels the frame for the engine and is
/// otherwise inert — the one frame admitted does not read it.
async fn read_restricted(conn: Connection, claimed: Triple, t: Transport) {
    t.record_station(Station::PeerUnjudged, None, None);
    while let Ok(mut stream) = conn.accept_uni().await {
        let Ok(raw) = stream.read_to_end(max_wire()).await else {
            t.record_station(Station::WireOverBound, None, None);
            continue;
        };
        let Some((frame, _under)) = shape_in(&t.shaper, raw) else {
            t.record_station(Station::WireUnshaped, None, None);
            continue;
        };
        if !admitted_unjudged(&frame) {
            // Counted, because "a peer we cannot judge is talking to us about something else" is the shape
            // an operator would want to see rising, and it is invisible everywhere else: this connection is
            // in no table, so no per-peer counter exists for it.
            //
            // **Tagged with the wire type code, which is what the tag field is for** (`Observation::tag`
            // says frame stations put it there) and which this site was throwing away. The bare count
            // cannot tell two very different worlds apart, and a measurement needed exactly that
            // distinction: a late-joining node's restricted channel carries **exactly 2** dropped frames on
            // every run where the join fails and 38–324 on every run where it succeeds (#267, 20 runs).
            //
            // With the tag the two are named: `HelloAck` and `ObservedAddr`, one each — the handshake's own
            // tail and nothing after it. That answer took six runs and could not have been reached from the
            // count, which is the argument for tagging every frame station rather than this one.
            // `None` when the bytes do not decode as a frame at all, which is a THIRD thing and must not
            // be folded into a type code: `admitted_unjudged` returns false for both "a well-formed frame
            // of the wrong type" and "not a frame", and only the tag can now tell them apart.
            let code = decode_frame(&frame).ok().map(|(f, _)| f.type_code);
            t.record_station(Station::RestrictedFrameDropped, None, code);
            continue;
        }
        // Counted BEFORE the send, and counted at all because the drop counter alone is one-sided: it says
        // how many frames were refused and never how many crossed, so "no round ever arrived" and "a round
        // arrived and was rejected downstream" read identically. The engine's own reject counters (#161)
        // pick the question up from here.
        t.record_station(Station::RestrictedFrameAdmitted, None, None);
        if t.input_tx.send(Input::Message { from: claimed, frame }).await.is_err() {
            break; // engine actor gone
        }
    }
}

/// Hold an unjudgeable connection open on the **dial** side, at most one per claimed coordinate.
///
/// The accept side awaits [`read_restricted`] under its own inbound permit, so it is already bounded by
/// `MAX_INBOUND_CONNECTIONS`. A dial has no permit, so it needs its own ceiling — and the shape is the one
/// `spawn_punch` already uses (#78): a **set of coordinates**, whose size is the plane's own point count
/// `q² + q + 1`. No constant has to be invented, and the fact that `claimed` is attacker-chosen cannot
/// widen it, because a `Triple` is a point and there are only that many.
///
/// It also closes a re-dial storm before it opens: nothing caches an unjudged connection, so without this
/// every send to the same coordinate would open another one — the #72 shape.
fn spawn_restricted(conn: Connection, claimed: Triple, t: Transport) {
    let admitted = match t.unjudged.lock() {
        Ok(mut held) => held.insert(claimed),
        // A poisoned set is a local fault; refusing is what every path here did before this existed.
        Err(_) => false,
    };
    if !admitted {
        // **Counted, because the peer pays for it and nothing else here says so** (#267). Dropping `conn`
        // closes it, so a peer that dialed and was answered has the answer shut under it — and the bound
        // that decides this is on THIS node's coordinate set, invisible from the other end. Its judged twin
        // `ConnSurplusHeld` records the opposite choice one layer up, and having both is what makes the
        // asymmetry a decision rather than an accident.
        t.record_station(Station::RestrictedSurplusDropped, Some(claimed), None);
        return;
    }
    tokio::spawn(async move {
        read_restricted(conn, claimed, t.clone()).await;
        if let Ok(mut held) = t.unjudged.lock() {
            held.remove(&claimed);
        }
    });
}

/// Read a connection's first uni-stream as the peer's HELLO (its coordinate), un-shaping first.
async fn read_hello(conn: &Connection, t: &Transport) -> Option<Triple> {
    let mut stream = conn.accept_uni().await.ok()?;
    let raw = stream.read_to_end(max_wire()).await.ok()?;
    // This mode sends no reply, so the arm has nowhere to be carried; `read_verified_hello` is the one
    // that answers, and it threads it (#234).
    let Some((bytes, _under)) = shape_in(&t.shaper, raw) else {
        // The HELLO path un-shapes too, and it fires FIRST: a peer on another epoch or another community
        // never reaches `read_frames`, so instrumenting only the steady-state path counts nothing for
        // exactly the peer an operator wants named. Found by the falsification, not by reading (#191).
        t.record_station(Station::WireUnshaped, None, None);
        return None;
    };
    decode_triple(bytes.get(..HELLO_LEN)?)
}

/// Read every uni-stream on `conn` as one frame, un-shaping it, delivering `Input::Message`.
impl Transport {
    /// Whether frames to this peer must go out under the genesis shape: it reached us not knowing the live
    /// epoch, and until the handshake ends it cannot read anything else (#234).
    fn joining(&self, conn: &Connection) -> Option<OpenedUnder> {
        crate::proteus_socket::addressing_for(&self.joining, conn.remote_address())
    }

    /// Record one driver-side discard on this node's data-path plane — the same plane `Client` records on
    /// and `NodeHandle::driver_stations` merges into the answer to `Observe`, reached through the `Arc` this
    /// struct now shares (#191).
    fn record_station(&self, station: Station, line: Option<Triple>, tag: Option<u64>) {
        self.stations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record_tagged(station, line, tag, 1);
    }
}

async fn read_frames(conn: Connection, from: Triple, t: Transport) {
    // Mutable because a peer may **move**: a coordinate is not fixed for the life of a connection (spec §L3 reshuffle, and
    // within an epoch when a better claim displaces the peer). A verified move re-keys this connection and re-attributes
    // every frame after it, so the peer stays reachable at the point it actually holds.
    let mut from = from;
    // `accept_uni` errors when the connection closes, ending the loop; a single malformed or
    // wrongly-shaped stream is skipped without sinking the connection.
    while let Ok(mut stream) = conn.accept_uni().await {
        // Both discards below were bare `continue`s. They are the two conditions an operator most needs and
        // could least see: #190 lived in the first for as long as the frame ceiling and the wire ceiling were
        // one constant, and #196's epoch-turn blackout lives in the second. Counted separately on purpose —
        // "a peer produces frames this build will not read" and "these bytes are not ours" call for opposite
        // responses, and one number cannot say which.
        let Ok(raw) = stream.read_to_end(max_wire()).await else {
            t.record_station(Station::WireOverBound, Some(from), None);
            continue;
        };
        // The steady loop: by the time a peer is framing here the handshake has completed, so it has
        // learned the live epoch and `_under` is `Current` or `Grace`. Named rather than dropped so the
        // next reader sees there is nothing to reply-shape on this path.
        let Some((frame, _under)) = shape_in(&t.shaper, raw) else {
            t.record_station(Station::WireUnshaped, Some(from), None);
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
                            // **Move every connection this peer holds here, not just the one that carried the
                            // announcement** (#271). The rule the old comment stated is right and unchanged —
                            // a peer takes ITS connections along, and anything else under the vacated point
                            // belongs to whoever still holds it — but the discriminator had to change. When
                            // the map held one connection per coordinate, "this connection only" *was* all of
                            // them. #265 made the value a list, so the peer's surplus stayed behind: measured
                            // at 6 left under the old point against 1 moved, with `keep_alive_interval = 10 s`
                            // pinging every one of them and #241's directory retraction guaranteeing nothing
                            // would ever address that point again to prune them.
                            //
                            // Identity is what separates "this peer's surplus" from "the next occupant's",
                            // and it is the same answer `Distrust::seat` already gives one field over: the
                            // verdict is keyed on the identity precisely so it survives a move. Read from the
                            // certificate each connection authenticated with, so nothing has to be stored.
                            let mine = peer_cert_der(&conn).map(|c| identity_of(&c));
                            let mut moving = Vec::new();
                            if let Some(old) = map.get_mut(&from) {
                                old.retain(|c| {
                                    // `None` for our own identity means the cert is unreadable, which is not
                                    // a licence to take everything: fall back to the single connection the
                                    // announcement arrived on, which is what this did before.
                                    let same = mine.is_some()
                                        && peer_cert_der(c).map(|d| identity_of(&d)) == mine;
                                    if same || c.stable_id() == conn.stable_id() {
                                        moving.push(c.clone());
                                        return false;
                                    }
                                    true
                                });
                                if old.is_empty() {
                                    map.remove(&from);
                                }
                            }
                            // **The announcing connection is filed even when the old key held nothing.**
                            // The previous code did this unconditionally and my first version did not, so a
                            // move whose old coordinate had no entry — the peer was never filed there, or was
                            // already re-keyed — silently filed nothing at all. The station caught it on the
                            // first run: `#0` appeared repeatedly, and a move that carries zero connections
                            // is a peer this node just stopped being able to reach.
                            if !moving.iter().any(|c| c.stable_id() == conn.stable_id()) {
                                moving.push(conn.clone());
                            }
                            let carried = moving.len();
                            for c in moving {
                                file_conn(&mut map, moved, c);
                            }
                            // Counted because the surplus is exactly what used to be lost, and a zero here
                            // after a move would mean the old point held nothing — a different world from
                            // "held six and moved six".
                            t.record_station(
                                Station::ConnMovedWithPeer,
                                Some(moved),
                                Some(carried as u64),
                            );
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
                        } else if let Some(hub_conn) = cached(&t, target) {
                            // We are the hub: pass the whole Relay on to the target (re-shaped for that hop).
                            send_uni(&hub_conn, &t.shaper, t.joining(&hub_conn), &frame).await;
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
    if let Some(target_conn) = cached(t, target) {
        send_framed(
            &target_conn,
            &t.shaper,
            t.joining(&target_conn),
            FrameType::PunchTo,
            &encode_punch(requester, requester_addr),
        )
        .await;
    }
    // …and tell the requester to dial the target (over the connection it reached us on).
    send_framed(
        req_conn,
        &t.shaper,
        t.joining(req_conn),
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
    // **Where, not just how many (#171).** The two bounds this function derives — no directory write before
    // the coordinate is proven, at most one outstanding punch per coordinate — limit the RATE at which a
    // tolerated peer can make this node emit QUIC Initials. Neither limits the TARGET, and the doc above
    // names the harm exactly: "a fleet of FANOS nodes becomes a reflector aimed at a third party who never
    // joined anything." Until this line, a peer could name `169.254.169.254`, the operator's LAN, or their
    // own loopback, and this node would dial it from the operator's IP.
    //
    // `Overlay`, not the exit's realm: a FANOS peer legitimately sits on 10/8 or 192.168/16, and NAT
    // traversal is what that topology needs. What is refused is an address that cannot BE a distinct peer.
    if !crate::dial_policy::may_dial(&addr.ip(), crate::dial_policy::Policy::Overlay) {
        return;
    }
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
            //
            // A refusal costs the whole punch. The hole is open and reachability is proved, but the route is
            // not in the table, so the very next overlay frame resolves the incumbent's address and goes back
            // through the relay — the #54 state, re-entered silently and for as long as the better-claimed
            // entry stands. Nothing here can override it (that is the arbitration rule, and an unranked
            // observation must not beat a proven claim), so what this site owes is the count.
            match t.directory.insert(peer, addr) {
                WriteOutcome::Superseded { keeping } => {
                    t.record_station(Station::DirectoryRouteSuperseded, Some(peer), None);
                    tracing::debug!(?peer, ?addr, ?keeping, "punched route refused by arbitration; traffic stays on the relay");
                }
                WriteOutcome::Displaced { evicted } => {
                    t.record_station(Station::DirectoryPointTaken, Some(peer), None);
                    tracing::debug!(?peer, ?addr, ?evicted, "punched route took the point from its holder");
                }
                WriteOutcome::Bound | WriteOutcome::Unchanged => {}
            }
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

    /// **A panicking actor is named on the data-path plane, and a clean one is silent (#251).**
    ///
    /// The defect this closes is not "the actor died" — it is that nobody could tell. Sixty-three actors
    /// shipped unjoined, and a task nobody joins cannot report its own death; `panic = "abort"` sits only on
    /// the `maxperf` profile, which CI does not build. So a panic inside `accept_loop` removed this node's
    /// ability to answer anyone while every other surface said it was fine.
    ///
    /// Both directions, because a supervisor that recorded unconditionally would pass the first half alone
    /// and turn every orderly shutdown into an alarm.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_actor_is_named_and_a_finished_one_is_not() {
        let stations = Arc::new(Mutex::new(Stations::new()));
        let running = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let count = |tag: u64| {
            stations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .observations()
                .iter()
                .filter(|o| o.station == Station::ActorDied && o.tag == Some(tag))
                .map(|o| o.count)
                .sum::<u64>()
        };

        // While the node is running, every ending is an alarm — including a plain return, because none of
        // these loops is meant to reach its end with the node still up.
        supervise(DriverActor::Accept, &stations, &running, tokio::spawn(async { panic!("the accept loop fell over") }));
        for _ in 0..200 {
            if count(DriverActor::Accept.tag()) > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            count(DriverActor::Accept.tag()),
            1,
            "a panicked actor must be named on the plane; without it the node is degraded and confident"
        );
        assert_eq!(
            count(DriverActor::Engine.tag()),
            0,
            "and only the one that died — a supervisor that tagged them all would say nothing useful"
        );
    }

    /// **A stopping node retires its actors; it does not lose them (#257).**
    ///
    /// `accept_loop` is `while let Some(i) = endpoint.accept().await`, and `shutdown` closes that endpoint —
    /// so a clean stop ends it *by design*. Judged on the ending alone, every orderly shutdown of every node
    /// files an outage against `Accept`, and the comment this test used to carry ("these loops never
    /// return") was the fossil of exactly that mistake.
    ///
    /// The second half is the one that keeps the excuse honest: a panic is a defect whether or not the
    /// operator asked for a stop, so `stopping` must not silence it. A predicate that returned early before
    /// looking at the ending would pass the first assertion and fail this one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retiring_actor_is_silent_but_a_panic_during_shutdown_is_not() {
        let stations = Arc::new(Mutex::new(Stations::new()));
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let count = |tag: u64| {
            stations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .observations()
                .iter()
                .filter(|o| o.station == Station::ActorDied && o.tag == Some(tag))
                .map(|o| o.count)
                .sum::<u64>()
        };

        // Await the WATCHER, not the actor: the actor ends immediately either way, and what is under test is
        // what the watcher does with that. Waiting on the actor would prove only that it ended, and the
        // silence assertion below would then be measuring a watcher that had not run yet — green for the
        // wrong reason.
        let watcher = supervise(DriverActor::Accept, &stations, &stopping, tokio::spawn(async {}));
        watcher.await.expect("the watcher must survive the actor it watches");
        supervise(DriverActor::Engine, &stations, &stopping, tokio::spawn(async { panic!("during shutdown") }));
        for _ in 0..200 {
            if count(DriverActor::Engine.tag()) > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        assert_eq!(
            count(DriverActor::Engine.tag()),
            1,
            "a panic is a defect even while stopping — excusing it would hide the one ending that says the \
             code is wrong rather than that the operator asked"
        );
        assert_eq!(
            count(DriverActor::Accept.tag()),
            0,
            "an actor that ended because the node is stopping must not be filed as an outage: one false \
             alarm per shutdown is what makes the true one unreadable"
        );
    }
    use super::*;
    use crate::identity::verifiable_coordinate;
    use fanos_field::F2;

    /// **An embedder that drops its `Node` is stopping too, and only the channel says so (#257).**
    ///
    /// The other half of [`Client::is_stopping`]. `shutdown` covers the binary, which closes the endpoint;
    /// a library user — `fanos-ffi`, and every test — instead drops the last handle while the process keeps
    /// running. The engine's receiver goes with it, the actors run to completion, and the supervisors are
    /// still alive to misreport them, so this is the *deterministic* case where the flag alone is only a
    /// race. Nothing was asked of the flag here: it stays `false` throughout, and the verdict comes from the
    /// closed channel.
    #[test]
    fn a_client_whose_engine_is_gone_reports_that_the_node_is_stopping() {
        let (input_tx, input_rx) = mpsc::channel::<Input>(8);
        let client = Client {
            addr: Arc::new(Mutex::new([1, 0, 1])),
            stations: Arc::new(Mutex::new(Stations::new())),
            input_tx,
            ctrl_tx: mpsc::unbounded_channel::<Control>().0,
            events_tx: broadcast::channel::<Notification>(8).0,
            beacons: tokio::sync::watch::channel(None).1,
            genesis: BeaconSeed::GENESIS,
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        assert!(
            !client.is_stopping(),
            "a running node must not read as stopping, or the predicate excuses every real death"
        );
        drop(input_rx); // the engine actor is gone — what dropping the last `Node` does
        assert!(
            client.is_stopping(),
            "an actor that ends because the engine went away ended for a reason somebody chose"
        );
    }

    /// The driver's plane records what the engine cannot see, and every `Client` clone writes to the one
    /// plane an operator reads (#106).
    ///
    /// The sharing is the load-bearing half. Each directory publisher holds its own `Client` clone, so a
    /// per-clone plane would give eight private counters and an `Observe` that reports whichever one the CLI
    /// happened to hold — which is indistinguishable from a healthy node.
    #[test]
    fn the_driver_plane_is_shared_across_client_clones_and_reads_back() {
        let (input_tx, _input_rx) = mpsc::channel::<Input>(8);
        let (ctrl_tx, _ctrl_rx) = mpsc::unbounded_channel::<Control>();
        let (events_tx, _events_rx) = broadcast::channel::<Notification>(8);
        let coord: Triple = [1, 0, 1];
        let client = Client {
            addr: Arc::new(Mutex::new(coord)),
            stations: Arc::new(Mutex::new(Stations::new())),
            input_tx,
            ctrl_tx,
            events_tx,
            beacons: tokio::sync::watch::channel(None).1,
            genesis: BeaconSeed::GENESIS,
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        // Silent until something stops. A plane that reports counts before any work failed would make
        // "nothing has fired" meaningless, which is the whole value of the verb.
        assert!(client.driver_stations().is_empty(), "a node that has dropped nothing reports nothing");

        // A publisher's clone records; the CLI's original reads it.
        let publisher = client.clone();
        publisher.record_station(Station::DirectoryPublishFailed, Some(coord), Some(3));
        publisher.record_station(Station::DirectoryPublishFailed, Some(coord), Some(3));
        publisher.record_station(Station::DirectoryPublishFailed, Some(coord), Some(5));

        let seen = client.driver_stations();
        assert_eq!(seen.len(), 2, "two directories failed, not two-or-three counts: {seen:?}");
        let by_tag: Vec<(Option<u64>, u64)> = seen.iter().map(|o| (o.tag, o.count)).collect();
        assert_eq!(by_tag, vec![(Some(3), 2), (Some(5), 1)], "counts accumulate per directory");
        assert!(
            seen.iter().all(|o| o.station == Station::DirectoryPublishFailed && o.line == Some(coord)),
            "and each names the coordinate that went missing"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
                // A transport test's node is a baseline node: CORE is what it means, said out loud (#284).
                Capabilities::CORE,
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
    fn the_relay_wrapper_never_outgrows_the_ceiling_that_allows_for_it() {
        // `max_wire()` is what a receiver will read, and it reserves `relay_overhead()` for this wrapper.
        // The wrapper is NOT a constant: `encode_frame` writes a varint length that widens with the body,
        // so the lengths below straddle every varint boundary up to the largest frame there can be. Sizing
        // the reservation on a small inner would pass a naive test and still drop full blocks.
        let declared = relay_overhead();
        for len in [0usize, 1, 62, 63, 64, 16_382, 16_383, 16_384, MAX_FRAME - 1, MAX_FRAME] {
            let inner = vec![0u8; len];
            let grown = encode_relay([0, 0, 0], [0, 0, 0], &inner).len() - len;
            assert!(
                grown <= declared,
                "inner {len}: the relay wrapper added {grown}, over the {declared} the wire ceiling \
                 reserves — a relayed full frame would be dropped by the peer's read bound"
            );
        }
        // And the reservation is not absurdly loose: at the largest inner it must be exact, or the ceiling
        // is carrying slack nobody derived.
        let at_max = encode_relay([0, 0, 0], [0, 0, 0], &vec![0u8; MAX_FRAME]).len() - MAX_FRAME;
        assert_eq!(at_max, declared, "the declared overhead must be the one the encoder actually adds");
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

    /// **Every epoch the verifier admits must be one the wire can deliver** (#261).
    ///
    /// A relation between two crates, which is why neither can state it alone: `BeaconWindow` decides whose
    /// HELLO is judged, `ProteusShaper` decides whose frame is opened, and a HELLO that cannot be opened is
    /// never judged. Asserting `DEPTH == 1 + SHAPE_GRACE` would be vacuous now that DEPTH is defined that
    /// way; this drives the actual shapers instead, so it fails if either side moves on its own.
    #[test]
    fn the_verifier_admits_no_epoch_the_wire_would_refuse() {
        const N: u64 = 8; // far enough that the genesis door is open and cannot mask a grace failure
        let secret = b"window-vs-wire".to_vec();
        let mut here = ProteusShaper::new(secret.clone(), Epoch::ZERO);
        here.rotate(Epoch::new(N));

        // The window admits `N` down to `N - (DEPTH - 1)`. Every one of those must cross the wire.
        for back in 0..BeaconWindow::DEPTH as u64 {
            let peer_epoch = N - back;
            let mut peer = ProteusShaper::new(secret.clone(), Epoch::ZERO);
            peer.rotate(Epoch::new(peer_epoch));
            let mut wire = peer.seal_datagram(b"hello-ish", &[7u8; fanos_proteus::NONCE_LEN]);
            assert!(
                here.open_datagram(&mut wire).is_some(),
                "the window admits epoch {peer_epoch} (N={N}, DEPTH={}), so the wire must carry it —                  otherwise that slot is width nobody can reach",
                BeaconWindow::DEPTH
            );
        }

        // And the first epoch OUTSIDE the window is one the wire refuses too, so the window is not the
        // narrower of the two gates either: neither side is silently deciding for the other.
        let outside = N - BeaconWindow::DEPTH as u64;
        let mut peer = ProteusShaper::new(secret, Epoch::ZERO);
        peer.rotate(Epoch::new(outside));
        let mut wire = peer.seal_datagram(b"hello-ish", &[7u8; fanos_proteus::NONCE_LEN]);
        assert!(
            here.open_datagram(&mut wire).is_none(),
            "epoch {outside} is outside the verification window, and the wire agrees — if the wire carried \
             it, the window would be the gate turning a reachable peer away"
        );
    }

    /// **The restricted set admits exactly the frames whose handler ignores `from`** (#235).
    ///
    /// Stated as the rule rather than as a list, because the list is a consequence: an unjudged peer's
    /// coordinate is a claim, so any handler that *uses* `from` would be acting on a stranger's choice.
    /// `Beacon` → `on_round(f.body)` does not read it; `BeaconReq` → `on_beacon_req(from)` uses it as the
    /// reply target. Those two are the whole discrimination, and they are checked here as a pair — checking
    /// only that `Beacon` passes would be satisfied by a function that admits everything.
    ///
    /// Falsified by widening `admitted_unjudged` to `is_beacon_frame`'s six types: the `BeaconReq` and
    /// `BeaconPartial` assertions redden. Narrowed to nothing, the first assertion reddens.
    #[test]
    fn an_unjudged_peer_may_send_only_what_no_handler_attributes_to_it() {
        let framed = |ty: FrameType, body: &[u8]| {
            let mut out = Vec::new();
            encode_frame(ty.code(), body, &mut out);
            out
        };
        assert!(
            admitted_unjudged(&framed(FrameType::Beacon, b"round-ish")),
            "a beacon round proves itself against the group commitment, so an unproven sender costs nothing"
        );
        assert!(
            !admitted_unjudged(&framed(FrameType::BeaconReq, b"")),
            "`on_beacon_req` sends the round TO `from`, so admitting this would let a stranger aim our \
             reply at a coordinate it merely named"
        );
        for other in [FrameType::BeaconPartial, FrameType::Hello, FrameType::Relay, FrameType::ObservedAddr] {
            assert!(
                !admitted_unjudged(&framed(other, b"x")),
                "{other:?} is not part of the §7.8 bootstrap and must not cross an unauthenticated connection"
            );
        }
        assert!(!admitted_unjudged(b"not-a-frame"), "an undecodable frame is not admitted by default");
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

        // Advance until epoch 1 has fallen out. **Epoch 1, not epoch 0** — this assertion used to be about
        // zero, and zero is now the one epoch that is deliberately never evicted (#235). A ROTATED epoch is
        // what the bound is about, so the test asks about one; keeping it on zero would have made the eviction
        // rule and the genesis pin contradict each other, and the pin would have been the one to go.
        let last = BeaconWindow::DEPTH as u64 + 1;
        for e in 2..=last {
            w.adopt(Epoch::new(e), BeaconSeed::new([e as u8; 32]));
        }
        assert_eq!(w.beacon_for(Epoch::new(1)), None, "a rotated epoch beyond the window is no longer admitted");
        assert!(w.beacon_for(Epoch::new(last)).is_some(), "the newest epoch is admitted");
        assert_eq!(w.beacon_for(Epoch::new(999)), None, "an unseen epoch is rejected");

        // Re-adopting a known epoch is idempotent — no duplicate, no eviction churn.
        w.adopt(Epoch::new(last), BeaconSeed::new([0xEE; 32]));
        assert_eq!(w.recent.len(), BeaconWindow::DEPTH);
    }

    /// **A door the transport holds open must have a verifier behind it** (#235).
    ///
    /// The mirror of [`the_verifier_admits_no_epoch_the_wire_would_refuse`]: that one caught a window wider
    /// than the wire, this one catches a wire wider than the window. Both gates are driven for real, because
    /// the relation is the claim — asserting `beacon_for(ZERO).is_some()` alone would pass against a verifier
    /// nothing could ever reach.
    ///
    /// Falsified in both directions. Drop the `or_else` pin from `beacon_for` and the second half reddens:
    /// the wire delivers a genesis frame that no verifier can judge. Remove the genesis arm from the shaper
    /// and the first half reddens instead, which is the honest outcome — with no genesis shape there is no
    /// door, and a pin behind a wall is the unreachable width #261 deleted.
    #[test]
    fn the_wire_opens_no_epoch_the_verifier_could_not_judge() {
        // Far past the window, so a surviving genesis answer cannot be an un-evicted `recent` entry.
        const N: u64 = 8;
        let mut here = ProteusShaper::new(b"genesis-door".to_vec(), Epoch::ZERO);
        here.rotate(Epoch::new(N));
        let mut window = BeaconWindow::genesis(BeaconSeed::GENESIS);
        for e in 1..=N {
            window.adopt(Epoch::new(e), BeaconSeed::new([e as u8; 32]));
        }

        // A node that knows only epoch zero seals under the genesis shape, and the rotated cell opens it.
        let joiner = ProteusShaper::new(b"genesis-door".to_vec(), Epoch::ZERO);
        let mut wire = joiner.seal_datagram(b"hello-ish", &[9u8; fanos_proteus::NONCE_LEN]);
        assert!(
            here.open_datagram(&mut wire).is_some(),
            "the transport keeps a permanent genesis door (#234), so a joining node's frame arrives at N={N}"
        );
        assert_eq!(
            window.beacon_for(Epoch::ZERO),
            Some(BeaconSeed::GENESIS),
            "and the verifier can judge what came through it — otherwise the door leads to a wall and the \
             joining node is refused at N >= {}, which is #260's dark half",
            BeaconWindow::DEPTH
        );
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
        let _ = directory.insert(genesis_coord, local_addr);

        // Channels: the loop's `Client` sends `Reseat` down `input_rx`; we push `BeaconReady` via `events`.
        let (input_tx, mut input_rx) = mpsc::channel::<Input>(8);
        let (ctrl_tx, _ctrl_rx) = mpsc::unbounded_channel::<Control>();
        let (events_tx, _events_rx0) = broadcast::channel::<Notification>(8);
        let client = Client {
            addr: Arc::new(Mutex::new(genesis_coord)),
            stations: Arc::new(Mutex::new(Stations::new())),
            input_tx,
            ctrl_tx,
            events_tx: events_tx.clone(),
            beacons: tokio::sync::watch::channel(None).1,
            genesis: BeaconSeed::GENESIS,
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
            stations: Arc::new(Mutex::new(Stations::new())),
            input_tx,
            ctrl_tx,
            events_tx: events_tx.clone(),
            beacons: tokio::sync::watch::channel(None).1,
            genesis: BeaconSeed::GENESIS,
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
        // **With a codec plugged**, so the cover-protocol morphs in the chain are real. Without one they are
        // not in the controller's walk at all (#113), and the second half of this test is what says so.
        let controller: MaybeController = Some(Arc::new(Mutex::new(
            MorphController::with_trip_and_codec(Environment::DeepCensorship, 1, true),
        )));
        let morph = || shaper.as_ref().unwrap().read().unwrap().morph();

        // A success is a breaker reset — the morph is unchanged.
        apply_outcome(&shaper, &controller, true);
        assert_eq!(morph(), Morph::Polymorph);
        // Each failure (trip = 1) walks the DeepCensorship chain. The shaper still refuses to *install* a
        // cover-protocol morph without its own codec — the two halves are separately guarded — so the
        // assertion here is on the controller's walk, which is what the fallback logic owns.
        apply_outcome(&shaper, &controller, false);
        assert_eq!(
            controller.as_ref().unwrap().lock().unwrap().current(),
            Morph::Fronted,
            "Polymorph → Fronted",
        );
        apply_outcome(&shaper, &controller, false);
        assert_eq!(
            controller.as_ref().unwrap().lock().unwrap().current(),
            Morph::Webrtc,
            "Fronted → Webrtc",
        );
    }

    /// **A stock build does not rotate at all, because it has nowhere to rotate to** (#113).
    ///
    /// This is the shape the fix exists for: the policy chain for `deep-censorship` names three morphs, two
    /// of which need a plugged `MorphCodec`. Rotating into them used to apply the polymorph codec under a
    /// cover-protocol shaping profile, so the node emitted the same codec three times while reporting that
    /// it was trying domain-fronting and WebRTC.
    #[test]
    fn a_stock_build_has_no_morph_fallback_and_stays_on_the_one_it_can_honour() {
        let shaper: Shaper = Some(Arc::new(RwLock::new(ProteusShaper::with_morph(
            b"s".to_vec(),
            Epoch::ZERO,
            Morph::Polymorph,
        ))));
        let ctl = MorphController::with_trip_and_codec(Environment::DeepCensorship, 1, false);
        assert!(!ctl.has_fallback(), "no codec ⇒ nowhere to go, and the driver logs exactly this");
        let controller: MaybeController = Some(Arc::new(Mutex::new(ctl)));
        let morph = || shaper.as_ref().unwrap().read().unwrap().morph();

        for _ in 0..4 {
            apply_outcome(&shaper, &controller, false);
            assert_eq!(morph(), Morph::Polymorph, "the wire transform never changes, and now nothing claims it did");
        }
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

    /// Bring up a censor: FANOS's own server config over a real sealed socket keyed by `secret`, which
    /// completes everything the transport asks for and then withholds the one shaped frame the exchange
    /// needs. Returns its address.
    ///
    /// `hold` picks which of the two censors this is, and the distinction is the whole reason there are two
    /// tests below: **holding** the connection open exercises the deadline, **closing** it exercises the
    /// classification. A test that conflated them would pass with either half of the fix reverted.
    fn silent_censor(secret: &[u8], hold: bool) -> SocketAddr {
        use quinn::Runtime as _;
        let creds = NodeCredentials::generate().expect("censor credentials");
        let (server, _client, _cert) = node_configs_mutual_from(&creds).expect("censor tls");
        let shaper = Arc::new(RwLock::new(ProteusShaper::with_morph(
            secret.to_vec(),
            Epoch::ZERO,
            Morph::Polymorph,
        )));
        let stations = Arc::new(Mutex::new(Stations::new()));
        let raw = std::net::UdpSocket::bind("127.0.0.1:0").expect("censor bind");
        let carrier = quinn::TokioRuntime.wrap_udp_socket(raw).expect("censor carrier");
        let carrier = crate::proteus_socket::ProteusSocket::wrap(
            carrier,
            &shaper,
            &stations,
            &crate::proteus_socket::reply_addressing(),
        );
        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server),
            carrier,
            Arc::new(quinn::TokioRuntime),
        )
        .expect("censor endpoint");
        let addr = endpoint.local_addr().expect("censor addr");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(incoming) = endpoint.accept().await {
                if let Ok(conn) = incoming.await
                    && hold
                {
                    held.push(conn);
                }
            }
        });
        addr
    }

    /// A shipped self-certifying dialer sharing `secret`, plus a directory pointing `target` at `addr`.
    fn dialer_pointed_at(secret: &[u8], addr: SocketAddr) -> (NodeHandle, Triple) {
        let dir = Directory::new();
        let creds = NodeCredentials::generate().expect("dialer credentials");
        let node = spawn_self_certifying_persistent_over::<F2>(
            Fabric::Udp("127.0.0.1:0".parse().unwrap()),
            &creds,
            |coord| {
                Box::new(fanos_runtime::OverlayNode::<F2>::new(
                    coord,
                    fanos_runtime::Config::default(),
                ))
            },
            dir.clone(),
            Capabilities::CORE,
            Some(ProteusConfig::polymorph(secret.to_vec())),
        )
        .expect("spawn the dialer");
        let target: Triple = if node.address() == [1, 0, 0] { [0, 1, 0] } else { [1, 0, 0] };
        let _ = dir.insert(target, addr);
        (node, target)
    }

    /// How many transport round trips this node has concluded lost.
    fn round_trips_lost(node: &NodeHandle) -> u64 {
        node.client()
            .driver_stations()
            .iter()
            .filter(|o| o.station.name() == "transport.round_trip_lost")
            .map(|o| o.count)
            .sum()
    }

    /// Poll `f` until it is non-zero, or give up after `ceiling`.
    async fn wait_nonzero(
        ceiling: std::time::Duration,
        mut f: impl FnMut() -> u64,
    ) -> Option<u64> {
        tokio::time::timeout(ceiling, async {
            loop {
                let n = f();
                if n > 0 {
                    return n;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .ok()
    }

    /// **#231 — a peer that completes the handshake and never speaks is a TRANSPORT failure.**
    ///
    /// PROPERTY: the outcome fed to the morph breaker comes from the shaped round trip, not from the QUIC
    /// handshake. Before this, `apply_outcome(true)` fired the moment `connect` returned, so a censor that
    /// admits the handshake and kills the data phase reset the breaker for ever — silent in exactly the case
    /// the morph exists to answer.
    ///
    /// The censor here **closes** the connection after the handshake, so the failure is reached by
    /// classification and not by any deadline: the assertion on elapsed time is what separates this test
    /// from the one below. Falsified by mapping `PeerHello::Silent` to `round_trip: true` — this test then
    /// fails, while the deadline test still passes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_handshake_without_a_shaped_round_trip_is_recorded_as_a_transport_failure() {
        let secret = b"round-trip-classification".to_vec();
        let addr = silent_censor(&secret, false);
        let (node, target) = dialer_pointed_at(&secret, addr);

        let started = std::time::Instant::now();
        node.command(Command::Send { to: target, payload: b"into the void".to_vec() });
        let lost = wait_nonzero(HELLO_DEADLINE, || round_trips_lost(&node))
            .await
            .expect("a peer that hangs up unspoken is a transport failure");

        assert!(lost > 0);
        assert!(
            started.elapsed() < HELLO_DEADLINE,
            "this must be reached by CLASSIFICATION, not by the deadline — took {:?}",
            started.elapsed(),
        );
    }

    /// **#233 — the caller's half of the handshake is bounded by the same deadline the acceptor uses.**
    ///
    /// PROPERTY: a peer that completes the QUIC handshake and then holds the connection open in silence is
    /// abandoned within `HELLO_DEADLINE`, not held to QUIC's 30 s idle timeout. The dial runs on the send
    /// loop, which is the very path `DIAL_TIMEOUT` exists to keep clear — and only its QUIC half was bounded.
    ///
    /// The ceiling sits between the two: above `HELLO_DEADLINE` (10 s) and well below the idle timeout
    /// (30 s), so a run that satisfies it is a statement about which bound fired. Falsified by removing the
    /// `timeout` wrapper — measured at 18 s and failing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_peer_that_holds_the_connection_silent_is_abandoned_at_the_handshake_deadline() {
        let secret = b"round-trip-deadline".to_vec();
        let addr = silent_censor(&secret, true);
        let (node, target) = dialer_pointed_at(&secret, addr);

        let started = std::time::Instant::now();
        node.command(Command::Send { to: target, payload: b"into the void".to_vec() });
        let ceiling = HELLO_DEADLINE + std::time::Duration::from_secs(8);
        let lost = wait_nonzero(ceiling, || round_trips_lost(&node))
            .await
            .expect("the held-open peer must be abandoned inside the handshake deadline");

        assert!(lost > 0);
        assert!(
            started.elapsed() < ceiling,
            "the dial concluded in {:?}, which must be under {:?} and nowhere near the 30 s idle timeout",
            started.elapsed(),
            ceiling,
        );
    }
    /// **Does the ACCEPTOR learn that the dialer dropped its handle?** The whole pruning rule rests on it.
    ///
    /// `live_conn` keeps an entry while `close_reason().is_none()`, so "the peer closed it" has to become
    /// visible here or the list is a graveyard. A measurement says it does not: a late-joining node closes
    /// six of its seven connections to a cell, and that cell reads the surplus list **3537 times and prunes
    /// zero** (#267). Either the closes never leave the dialer, or they never register on the acceptor, or
    /// the scenario differs from this one in some way worth naming — and only an experiment on the bare
    /// transport can say which.
    ///
    /// Deliberately minimal: two endpoints, one dial, drop the dialer's only handle, watch the accepted
    /// side. No FANOS layers, because the question is about quinn's contract and nothing above it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dropping_a_dialers_last_handle_is_visible_to_the_acceptor() {
        let creds = NodeCredentials::generate().expect("credentials");
        let (server, client, _cert) = node_configs_mutual_from(&creds).expect("tls");

        let accepted: Arc<Mutex<Vec<Connection>>> = Arc::new(Mutex::new(Vec::new()));
        let listener =
            Endpoint::server(server, "127.0.0.1:0".parse().expect("listen addr")).expect("listener");
        let addr = listener.local_addr().expect("listener addr");
        let sink = accepted.clone();
        tokio::spawn(async move {
            while let Some(incoming) = listener.accept().await {
                if let Ok(conn) = incoming.await
                    && let Ok(mut held) = sink.lock()
                {
                    held.push(conn);
                }
            }
        });

        let mut dialer =
            Endpoint::client("127.0.0.1:0".parse().expect("client addr")).expect("dialer");
        dialer.set_default_client_config(client);
        let conn = dialer.connect(addr, "fanos.node").expect("dial").await.expect("connection");

        // Wait for the acceptor to have it at all, so a `None` below cannot be "it never arrived".
        for _ in 0..200 {
            if accepted.lock().is_ok_and(|h| !h.is_empty()) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            accepted.lock().map_or(0, |h| h.len()),
            1,
            "the acceptor never saw the connection, so this measures a dial that did not land"
        );

        drop(conn); // the dialer's only handle — quinn closes the connection on the last drop

        let mut observed = None;
        for _ in 0..300 {
            observed = accepted.lock().ok().and_then(|h| h.first().and_then(Connection::close_reason));
            if observed.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            observed.is_some(),
            "three seconds after the dialer dropped its last handle, the acceptor still reports the \
             connection live. Then `close_reason().is_none()` is not a liveness test on this path, every \
             list `live_conn` prunes against is a graveyard, and the send picks a corpse for as long as the \
             peer stays away (#267)."
        );
    }

    /// Two connections proving one coordinate, and the reader must hand back the **newest** (#266).
    ///
    /// The property is not a preference: a second connection exists either because both sides dialed at
    /// once — in which case either carries the frame — or because the peer lost its side and dialed again,
    /// in which case the older one is a corpse and the newer is the only path. So the newest is never worse
    /// and is sometimes the only right answer. The second half pins the pruning that makes the first half
    /// safe: once a connection *is* known closed it must leave, or "newest" would mean "newest corpse".
    ///
    /// Falsified twice: `live.first()` (the shipped behaviour this task corrects) fails the newest
    /// assertion, and dropping the `retain` fails the survivor assertion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_connection_map_hands_back_the_newest_and_drops_the_closed() {
        let creds = NodeCredentials::generate().expect("credentials");
        let (server, client, _cert) = node_configs_mutual_from(&creds).expect("tls");

        let listener =
            Endpoint::server(server, "127.0.0.1:0".parse().expect("listen addr")).expect("listener");
        let addr = listener.local_addr().expect("listener addr");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(incoming) = listener.accept().await {
                if let Ok(conn) = incoming.await {
                    held.push(conn);
                }
            }
        });

        let mut dialer =
            Endpoint::client("127.0.0.1:0".parse().expect("client addr")).expect("dialer");
        dialer.set_default_client_config(client);
        let older = dialer
            .connect(addr, "fanos.node")
            .expect("dial the older")
            .await
            .expect("older connection");
        let newer = dialer
            .connect(addr, "fanos.node")
            .expect("dial the newer")
            .await
            .expect("newer connection");
        assert_ne!(
            older.stable_id(),
            newer.stable_id(),
            "the two dials collapsed onto one connection, so this test cannot tell the orders apart"
        );

        let peer: Triple = [1, 0, 1];
        let mut map: HashMap<Triple, Vec<Connection>> = HashMap::new();
        assert_eq!(file_conn(&mut map, peer, older.clone()), 0, "the first is not surplus");
        assert_eq!(file_conn(&mut map, peer, newer.clone()), 1, "the second arrives over one held");

        let picked = live_conn(&mut map, peer).0.expect("both are live, so one must come back");
        assert_eq!(
            picked.stable_id(),
            newer.stable_id(),
            "the reader handed back the OLDER connection. A peer that redialed because it lost its side is \
             then pinned to a corpse for a full idle timeout, because QUIC reports no failure to fall back \
             from — the send succeeds locally and the frame is buffered into silence (#266)."
        );

        newer.close(0u32.into(), b"gone");
        let survivor = live_conn(&mut map, peer).0.expect("the older one is still live");
        assert_eq!(
            survivor.stable_id(),
            older.stable_id(),
            "a closed connection was handed back: `newest` must mean the newest SURVIVOR, or the map \
             degrades into always returning the most recent corpse."
        );
    }
}

/// **#245: what one inbound connection may pin, as a number rather than a library default.**
///
/// The product is the claim. Per-stream credit × concurrent streams is what a peer makes this node hold
/// before the application has read a byte. quinn's defaults credited 100 uni **and** 100 bidi at 1.25 MB with
/// `receive_window = VarInt::MAX` — ≈250 MB per connection, times `MAX_INBOUND_CONNECTIONS = 512`, against a
/// node recommendation of 256 MiB. Three orders of magnitude, committed before a byte is seen.
///
/// Asserted as arithmetic rather than by reading the setters back: `TransportConfig` has no getters, and the
/// arithmetic is the thing that must stay true when either factor moves.
#[cfg(test)]
mod transport_bounds {
    use super::{MAX_PEER_UNI_STREAMS, max_stream_credit};
    use fanos_wire::MAX_FRAME;

    #[test]
    fn one_connection_pins_exactly_the_frames_it_is_allowed_to_send() {
        let per_stream = max_stream_credit();
        let per_conn = per_stream.saturating_mul(u64::from(MAX_PEER_UNI_STREAMS));

        // A full-size frame must fit, or a legitimate producer stalls its own stream.
        assert!(
            per_stream >= MAX_FRAME as u64,
            "per-stream credit {per_stream} is below MAX_FRAME {MAX_FRAME}: a full frame cannot arrive"
        );
        // …and the whole connection must stay within a few frames, not a few hundred.
        let ceiling = 8 * 1024 * 1024;
        assert!(
            per_conn < ceiling,
            "one connection may pin {per_conn} bytes, over the {ceiling}-byte sanity ceiling. The derivation \
             is `four openers × one frame each`; a jump means MAX_FRAME or the opener count moved and the \
             budget was not redone (#245, #213)."
        );
    }

}
