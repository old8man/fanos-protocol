//! `serve_anonymous` — host a DIAULOS service on the **anonymous** rendezvous path (the production form
//! of the hidden-service server, `design-anonymity-substrate.md` §3b).
//!
//! The Direct accept loop ([`crate::diaulos::serve`]) demultiplexes clients by their source **coordinate**
//! and replies `Command::Send { to: from }` — which reveals where each client is. The anonymous loop here
//! is its mirror: a client's request arrives as a threshold-peeled `Notification::Delivered { from:
//! ANONYMOUS, .. }` at the service's meeting combiner, carrying a [`RendezvousService`]-wrapped payload. The
//! loop [`ingest`](RendezvousService::ingest)s it — binding the per-session **cookie** to the client's own
//! NOSTOS dead-drop reply route, learning *nothing* about the client — drives that cookie's DIAULOS
//! `ServerSession`, and seals each response back through the recorded route
//! ([`seal_reply`](RendezvousService::seal_reply)), raw-emitted at its first combiner. Neither party ever
//! learns the other's coordinate.
//!
//! ## One shared session driver, one shared bound
//!
//! Each cookie's session is driven by the *same* `serve_over_channels` engine the Direct loop uses, so the
//! RFC 6298 retransmit clock (and its anti-livelock pacing) is inherited, not re-implemented — the reference
//! hand-rolled `poll_payloads`/`poll_new` split that a naive loop gets wrong lives inside that driver. The
//! one structural difference is the reply path: a session's outbound cells cannot be sealed inside its own
//! task, because sealing needs the single `RendezvousService` (its reply-route table and fresh per-onion
//! seeds). So every session funnels its outbound cells — tagged by cookie — to the central loop, which owns
//! the `RendezvousService` and does all sealing. The cookie→session map is `MAX_SESSIONS`-bounded and
//! idle-swept exactly like the Direct loop (audit A4), reusing `Session`/`evict_lru`, so a flood of
//! distinct cookies or a wedged handler cannot grow it without bound.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use fanos_aphantos::nostos::{ReplyKeys, select_drop_line};
use fanos_aphantos::slots;
use fanos_diaulos::StaticKeypair;
use fanos_field::F2;
use fanos_geometry::{Point, Triple};
use fanos_pqcrypto::HybridSigSecret;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_pqcrypto::rng::SeedRng;
use fanos_quic::Client;
use fanos_runtime::ports::stations::Station;
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, Epoch, HostRegister, MixDirectory, RendezvousService, SessionId,
    line_member_coords, meeting_lines, seal_host_register,
};
use fanos_runtime::{Command, Notification};
use fanos_session::{ChannelTransport, serve_over_channels_paced_observed};

use crate::mixdir::build_plane_mix_directory;
use crate::resolve::Coverage;
use rand_core::CryptoRng;
use tokio::io::DuplexStream;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::diaulos::{MAX_SESSIONS, SESSION_IDLE_TIMEOUT, SESSION_SWEEP_INTERVAL, Session, evict_lru};

/// How many recent epochs' dead-drop [`ReplyKeys`] the accept loop keeps — **derived from the window a
/// combiner will actually serve, not chosen.**
///
/// It was `3`, with the reasoning "enough to open across a boundary without unboundedly hoarding keys" — a
/// number picked to be comfortably large because nothing fixed it. Something does now.
///
/// A forwarded request is opened with the reply key carried in the *registration* the combiner matched, and a
/// combiner serves registrations from the current epoch plus [`HOST_GRACE_EPOCHS`](crate::rendezvous_relay)
/// (`rendezvous_relay::retire_stale_hosts`). So the oldest key that can ever open anything is exactly that
/// many epochs old, and `1 + grace` is both necessary and sufficient: one fewer and a request the combiner
/// legitimately served cannot be opened; one more is a secret held past every path that could use it.
///
/// The ring and the registration move together — `rotate_host` mints the key and registers in the same step,
/// and a skipped rotation lags both identically — so there is no case where the host's keys are older than
/// its own registration. That is what makes the bound tight rather than optimistic.
const MAX_REPLY_KEYS: usize = 1 + crate::rendezvous_relay::HOST_GRACE_EPOCHS as usize;

/// The measured cost of one [`RendezvousService::seal_reply`], rounded up (#248).
///
/// A threshold onion through the reply circuit, plus a hybrid-KEM seal to the client's reply key on the
/// NOSTOS path. `fanos_rendezvous`'s `measure_the_cost_of_sealing_one_reply` reads 509 us (legacy) and
/// 591 us (NOSTOS) in release on a quiet box; 600 is the larger of the two rounded up, which is the
/// conservative direction — a cost *under*-stated would let [`MAX_SEAL_QUEUE`] be too deep.
///
/// Microseconds as a plain integer rather than a `Duration`, so the bound below is a compile-time check.
const SEAL_REPLY_COST_US: u64 = 600;

/// How many outbound cells may wait to be sealed: **one per live session**.
///
/// Derived, not chosen. The loop seals one cell at a time, so the queue's only job is to let every session
/// that is behaving hand over a cell without waiting on a neighbour. One slot each does exactly that, and a
/// session wanting a *second* slot while its first is unsealed is producing faster than the host can seal —
/// which is the case backpressure exists for. Deeper buys nothing: the cell would still be sealed in the
/// same order, only later, and with the tail waiting longer.
///
/// Two consequences worth naming, both checked below:
/// * **Latency.** A cell at the back waits `MAX_SEAL_QUEUE × SEAL_REPLY_COST` ≈ 148 ms, comfortably inside
///   the platform's own `INITIAL_GATHER_DEADLINE` of 2 s — so a queued reply is not one the client's
///   threshold round has already given up on.
/// * **Memory.** `MAX_SEAL_QUEUE × (SessionId + CELL_LEN)` ≈ 266 KiB. Small enough that it needs no share
///   of its own in `fanos_primitives::budget` — stated so the next reader does not have to re-derive that
///   it was considered (#254's whole subject was costs nobody had added up).
const MAX_SEAL_QUEUE: usize = MAX_SESSIONS;

/// The tail of a full seal queue must still be inside the threshold round it belongs to. A deeper queue, or
/// a slower seal, is a reply the client stopped waiting for — and the failure would look like a dead host.
const _: () = assert!(
    (MAX_SEAL_QUEUE as u64) * SEAL_REPLY_COST_US
        < fanos_runtime::ports::gather::INITIAL_GATHER_DEADLINE.as_nanos() / 1_000,
    "a cell at the back of the seal queue waits past the gather deadline it is answering inside"
);

/// One epoch's rotating host material, pushed to a running [`serve_anonymous`] loop by the
/// `spawn_rendezvous_host` driver: the fresh dead-drop [`ReplyKeys`] (to open forwarded requests) and the
/// current mix directory (the members' onion keys the reply onions seal to, which rotate each epoch, E4).
pub struct HostEpoch {
    /// This epoch's dead-drop reply keypair — the secret half, kept to open forwarded requests.
    pub reply_keys: ReplyKeys,
    /// This epoch's mix directory, for sealing replies back to clients.
    pub directory: MixDirectory,
}

/// Open a forwarded request: try each dead-drop key in the ring (a request may be sealed to the current or a
/// recent epoch's key); if none opens it, it is a plaintext request delivered directly (this node *is* the
/// combiner) and is ingested raw. `ReplyKeys::open` authenticates, so a wrong key never yields a false body.
fn open_forwarded(ring: &[ReplyKeys], payload: Vec<u8>) -> Vec<u8> {
    for keys in ring {
        if let Some(opened) = keys.open(&payload) {
            return opened;
        }
    }
    payload
}

/// Ring the new epoch's dead-drop key (keeping the last [`MAX_REPLY_KEYS`]) and swap the reply directory; a
/// `None` update means the driver stopped, so keep serving with the last material. Kept out of the
/// `serve_anonymous` loop body so that stays within the pedantic line budget.
fn apply_epoch(
    ring: &mut Vec<ReplyKeys>,
    rservice: &mut RendezvousService<F2>,
    update: Option<HostEpoch>,
) {
    if let Some(HostEpoch { reply_keys, directory }) = update {
        ring.push(reply_keys);
        if ring.len() > MAX_REPLY_KEYS {
            ring.remove(0);
        }
        rservice.set_directory(directory);
    }
}

/// Await the next [`HostEpoch`] from the driver, or never resolve when no driver is attached — so the
/// `serve_anonymous` select can carry an optional epoch channel without a dedicated arm type.
async fn recv_epoch(updates: &mut Option<UnboundedReceiver<HostEpoch>>) -> Option<HostEpoch> {
    match updates.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Evict every session idle past [`SESSION_IDLE_TIMEOUT`], aborting its handler task (reclaiming a wedged
/// one). Extracted from the loop body to keep `serve_anonymous` within the pedantic line budget.
fn sweep_idle_sessions(sessions: &mut HashMap<SessionId, Session>) {
    let now = Instant::now();
    let idle: Vec<SessionId> = sessions
        .iter()
        .filter(|(_, s)| now.duration_since(s.last_active) >= SESSION_IDLE_TIMEOUT)
        .map(|(&cookie, _)| cookie)
        .collect();
    for cookie in idle {
        if let Some(session) = sessions.remove(&cookie) {
            session.task.abort();
        }
    }
}

/// Run a **multi-client, full-duplex** DIAULOS service on the *anonymous* path: each anonymous client that
/// reaches this node's meeting combiner gets its own session driven as an async [`DuplexStream`] and handed
/// to `handler` (which may read and write concurrently and stream both ways). A single service `keypair`
/// backs every session (shared, never copied); `rng` is the base entropy each session draws a fresh CSPRNG
/// from; `rservice` is the [`RendezvousService`] that records each cookie's reply route and seals responses
/// back through it. Spawns a background demultiplexer and returns immediately.
///
/// `rservice` must be built with the current-epoch mix directory + threshold (the keys the reply onions seal
/// to); a node re-arms it as the epoch rotates (the `spawn_rendezvous_host` node driver).
///
/// `reply_keys` is the host's NOSTOS dead-drop secret ring: when the service is hosted **off** its meeting
/// combiner (§3b) a forwarded request arrives as a dead-drop end-to-end sealed to it, so the loop opens each
/// delivery with it before ingesting. Pass **empty** when the service *is* its own combiner (requests arrive
/// as plaintext `Request`s — `open()` authenticates, so the empty ring just ingests raw). `epoch_updates`, if
/// present, is the channel the `spawn_rendezvous_host` driver pushes each epoch's fresh [`HostEpoch`] on: the
/// loop rings the new key (keeping the last `MAX_REPLY_KEYS`, so a request forwarded across the boundary
/// still opens) and swaps the reply directory. Pass `None` for a fixed single-epoch host (tests, at-combiner).
pub fn serve_anonymous<R, H, Fut>(
    client: Client,
    keypair: StaticKeypair,
    mut rng: R,
    mut rservice: RendezvousService<F2>,
    mut reply_keys: Vec<ReplyKeys>,
    mut epoch_updates: Option<UnboundedReceiver<HostEpoch>>,
    handler: H,
) where
    R: CryptoRng + Send + 'static,
    H: Fn(DuplexStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let handler = Arc::new(handler);
    // Share the service identity across all sessions — never copy the secret (audit A6).
    let keypair = Arc::new(keypair);
    tokio::spawn(async move {
        let mut deliveries = client.subscribe();
        let mut sessions: HashMap<SessionId, Session> = HashMap::new();
        // A session task signals its cookie here when its handler completes, so the demux reaps it.
        let (done_tx, mut done_rx) = unbounded_channel::<SessionId>();
        // Every session's outbound cells funnel here as `(cookie, cell)`; the loop — the sole owner of
        // `rservice` — seals each through that cookie's reply route and raw-emits it.
        let (seal_tx, mut seal_rx) = channel::<(SessionId, Vec<u8>)>(MAX_SEAL_QUEUE);
        let mut sweep = tokio::time::interval(SESSION_SWEEP_INTERVAL);
        loop {
            tokio::select! {
                event = deliveries.recv() => match event {
                    Ok(Notification::Delivered { from, payload }) if from == ANONYMOUS => {
                        // A forwarded request (§3b) arrives as a dead-drop end-to-end sealed to this host's
                        // reply key — open it (trying the recent-epoch ring); a direct request (this node IS
                        // the combiner) opens under no key and ingests as-is.
                        let request = open_forwarded(&reply_keys, payload);
                        // Ingest binds the cookie→reply-route and surfaces the inner DIAULOS bytes; a
                        // non-`Request` body (e.g. a stray dead-drop) yields `None` and is ignored.
                        let Some((cookie, inner)) = rservice.ingest(&request) else { continue };
                        // Reuse a live session, or spin up a fresh one on first contact / after the previous
                        // one finished. At the cap, evict the least-recently-active first (audit A4).
                        let live = sessions.get(&cookie).is_some_and(|s| !s.in_tx.is_closed());
                        if !live {
                            sessions.remove(&cookie);
                            if sessions.len() >= MAX_SESSIONS {
                                evict_lru(&mut sessions);
                            }
                            let mut seed = [0u8; 32];
                            rng.fill_bytes(&mut seed);
                            let (in_tx, task) = spawn_anonymous_session(
                                keypair.clone(),
                                SeedRng::from_seed(&seed),
                                cookie,
                                handler.clone(),
                                seal_tx.clone(),
                                done_tx.clone(),
                                client.clone(),
                            );
                            sessions.insert(cookie, Session { in_tx, task, last_active: Instant::now() });
                        }
                        if let Some(session) = sessions.get_mut(&cookie) {
                            session.accept(inner);
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                outbound = seal_rx.recv() => {
                    // Seal a session's outbound cell back through its client's recorded reply route (NOSTOS
                    // dead-drop) and raw-emit the onion at its first combiner. `Emit` (not `Send`) so a cell
                    // router forwards the onion as-is rather than wrapping it in a routed frame it cannot peel.
                    if let Some((cookie, cell)) = outbound
                        && let Some(fwd) = rservice.seal_reply(&cookie, &cell)
                    {
                        client.command(Command::Emit { to: fwd.combiner, frame: fwd.frame });
                    }
                }
                reaped = done_rx.recv() => {
                    // Reap a finished session, unless a reconnect already replaced it with a fresh (open) one.
                    if let Some(cookie) = reaped
                        && sessions.get(&cookie).is_some_and(|s| s.in_tx.is_closed())
                    {
                        sessions.remove(&cookie);
                    }
                }
                _ = sweep.tick() => sweep_idle_sessions(&mut sessions),
                // The host driver rotated the epoch: ring the new dead-drop key and swap the reply directory
                // (a no-op when no driver is attached — `recv_epoch` is then `pending` and never fires).
                update = recv_epoch(&mut epoch_updates) => {
                    apply_epoch(&mut reply_keys, &mut rservice, update);
                }
            }
        }
    });
}

/// The **request/response** convenience over [`serve_anonymous`] (the anonymous mirror of
/// [`serve_rpc`](crate::diaulos::serve_rpc)): read the request up to `max_request` bytes (the client
/// half-closes to end it), call `handler(&request)`, write the response, and close. Streaming or
/// full-duplex hidden services use [`serve_anonymous`] directly.
///
/// ## Why `max_request` is a positional argument and not a default (#194)
///
/// This convenience buffers a whole request in memory before the handler sees a byte, and the client that
/// sends it is **unauthenticated by construction** — anonymity is the point, so there is nobody to hold
/// responsible for a request that never ends. Before this the read was `read_to_end` with no bound at all,
/// and the doc said "read the whole request" without saying that "whole" had no ceiling.
///
/// It is mandatory and positional for the reason [`ExitPolicy`](crate::exit::ExitPolicy)'s loopback hatch is
/// (#170): a limit the caller may omit is a limit production ships without. There is deliberately **no
/// default constant** here, because the honest value depends on an accounting this crate cannot close for
/// the caller — see below.
///
/// ## What the caller is committing to, stated because it does not currently close
///
/// The host admits at most `MAX_SESSIONS` concurrent sessions (`fanos_diaulos::budget::MAX_SESSIONS`,
/// 246 at the shipping budget), so the worst case this buffer adds is
/// `max_request × MAX_SESSIONS`. That memory is **on top of** `fanos_diaulos::budget::SESSION_MEMORY_BUDGET`,
/// which is already spent in full: `MAX_SESSIONS` is *defined* as that budget divided by the transport
/// queues' per-session cost, with a const assert that the product does not exceed it. So there is no slice
/// left to derive a default from, and inventing one by halving a neighbour's share is exactly the mistake
/// `fanos_primitives::budget` exists to prevent. Pick `max_request` from what the *service* needs, and add
/// `max_request × MAX_SESSIONS` to the node's memory plan yourself.
pub fn serve_anonymous_rpc<R, H>(
    client: Client,
    keypair: StaticKeypair,
    rng: R,
    rservice: RendezvousService<F2>,
    reply_keys: Vec<ReplyKeys>,
    epoch_updates: Option<UnboundedReceiver<HostEpoch>>,
    rpc: RpcService<H>,
) where
    R: CryptoRng + Send + 'static,
    H: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    let RpcService { max_request, handler } = rpc;
    let handler = Arc::new(handler);
    let stations = client.clone();
    serve_anonymous(client, keypair, rng, rservice, reply_keys, epoch_updates, move |stream| {
        run_rpc(handler.clone(), stations.clone(), max_request, stream)
    });
}

/// A request/response hidden service: **what answers, and what it will spend answering**.
///
/// Grouped for the reason [`HostedService`] is, and the file's own history is the argument: threading these
/// individually reached the `too_many_arguments` ceiling, and a suppressed lint is a place a reviewer stops
/// reading. But the cohesion is real rather than a workaround — `max_request` exists *only* because
/// `handler` is fed a whole buffer, so a caller with one and not the other has said nothing complete. A
/// struct with no `Default` also makes the bound un-omittable, which is the point of #194.
pub struct RpcService<H> {
    /// The largest request body assembled before `handler` sees a byte. Read
    /// [`serve_anonymous_rpc`]'s doc before choosing it: the number commits the node to
    /// `max_request` × `fanos_diaulos::budget::MAX_SESSIONS` of memory that no existing budget accounts for.
    pub max_request: usize,
    /// Produces the response from the whole request.
    pub handler: H,
}

/// What reading one anonymous RPC request produced — three answers, because they call for three actions.
///
/// Folding `OverBound` into `Broken` would be the shape #109 keeps finding: a refusal the caller cannot
/// distinguish from a transport that died, so the one that an operator must act on is invisible. Folding it
/// into `Body` is worse — a truncated request served as a whole one.
#[derive(Debug, PartialEq, Eq)]
enum RequestRead {
    /// A complete request, within the bound.
    Body(Vec<u8>),
    /// The client sent more than the bound allows; nothing is served.
    OverBound,
    /// The transport failed before the request ended. Not the client's fault and not a refusal.
    Broken,
}

/// Read one request, refusing at `max_request` rather than growing to whatever arrives.
///
/// **Reads `max_request + 1`, not `max_request`.** Stopping exactly at the bound makes a request that *fits*
/// indistinguishable from one that was cut off there, and serving a silent prefix of what the client sent is
/// worse than refusing — neither side can tell. That one extra byte is the whole discriminator, and it is
/// the only byte ever read past the bound.
async fn read_bounded(stream: &mut DuplexStream, max_request: usize) -> RequestRead {
    use tokio::io::AsyncReadExt;
    let ceiling = u64::try_from(max_request).unwrap_or(u64::MAX).saturating_add(1);
    let mut request = Vec::new();
    if stream.take(ceiling).read_to_end(&mut request).await.is_err() {
        return RequestRead::Broken;
    }
    if request.len() > max_request {
        return RequestRead::OverBound;
    }
    RequestRead::Body(request)
}

/// Drive one anonymous session in **request/response** shape: read the request (bounded by `max_request`,
/// ended by the client half-closing), call `handler(&request)`, write the response, and close. Shared by the
/// `_rpc` conveniences so the adapter lives in exactly one place.
async fn run_rpc<H>(handler: Arc<H>, client: Client, max_request: usize, mut stream: DuplexStream)
where
    H: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    use tokio::io::AsyncWriteExt;
    let request = match read_bounded(&mut stream, max_request).await {
        RequestRead::Body(body) => body,
        RequestRead::OverBound => {
            // Counted, not merely dropped: an unauthenticated client can produce this at will, so a rise is
            // the one reading that separates "a service whose clients outgrew its bound" from "a service
            // being leaned on" — and an uncounted refusal is indistinguishable from silence (#109).
            client.record_station(Station::HostRequestOverBound, None, None);
            tracing::warn!(bound = max_request, "anonymous RPC request exceeds this host's bound; refusing");
            return;
        }
        RequestRead::Broken => return,
    };
    // **An empty request is an abandoned session, not a request.** A client that hedges across meeting points
    // drops the attempts that lose the race, which closes their transports — so the service reads EOF with
    // nothing in hand. Calling the handler there invents a request the client never sent: measured as one
    // dial incrementing a handler's count by three. Harmless for an echo, not harmless for application code
    // that counts, bills, rate-limits, or has any side effect at all, and the hedge means EVERY dial can
    // produce them rather than only failing ones.
    if request.is_empty() {
        return;
    }
    let response = handler(&request);
    let _ = stream.write_all(&response).await;
    let _ = stream.shutdown().await;
}

/// One hidden service's hosting parameters: **what** is hosted, and **under which coordinate regime**.
///
/// Grouped rather than passed positionally because the four travel together through every layer of the host driver, and
/// because `(Vec<u8>, u8, bool)` at a call site is three chances to get the order wrong silently.
pub struct HostedService {
    /// The service's static keypair — its anonymous identity, and what a client addresses it by.
    pub service: StaticKeypair,
    /// The service's **canonical published identity bundle** (`Ed25519 ‖ ML-DSA-65 ‖ X25519 ‖ ML-KEM-768`) — what
    /// a `.fanos` resolution yields, and the preimage of `service_tag`.
    ///
    /// **Its KEM half must be `service`'s public key**, and [`spawn_rendezvous_host`] refuses to run otherwise.
    /// The two are used for different things by the client — the KEM key LOCATES the service (it derives the
    /// meeting line) while the bundle AUTHORISES its route binding (it derives the tag) — so a bundle that named
    /// a different key would send clients to compute a tag for a service that lives somewhere else, and every
    /// dial would silently miss.
    pub identity: Vec<u8>,
    /// The signing secret whose public half is `identity`'s signing prefix: it signs each epoch's registration.
    ///
    /// Hosting **requires** a signing identity, and that is forced rather than chosen. The combiner authenticates
    /// a registration by recomputing the tag from the presented bundle and verifying a signature under it; a
    /// KEM-only bundle (`bundle_from_kem_public`, zero signing prefix) is reconstructible by anyone holding the
    /// public KEM key, so accepting one would authenticate nothing while appearing to.
    pub signer: HybridSigSecret,
    /// Seeds the dead-drop line selection and each epoch's reply key. Deterministic, so a restart re-derives both.
    pub host_secret: Vec<u8>,
    /// The rendezvous registration threshold: how many of the meeting line's points must hold a share.
    pub threshold: u8,
    /// Whether this cell's coordinates are **VRF-derived**, in which case each mix-key record must prove the slot's
    /// coordinate lies on its publisher's probe walk (S1-M3, `mixdir::parse_bound_record`).
    ///
    /// A deployment property of the cell, so it is stated by whoever configured it: [`crate::Node`] always sets
    /// `OverlayConfig::vrf_coordinates`, a pinned harness never does. It cannot be inferred from below — a pinned harness
    /// still gives its nodes self-certifying identities, so "has an identity" and "sits on a provable point" come apart, and
    /// reading the mode off the identity rejected every honest record in exactly that setup.
    ///
    /// `false` is an **absent mechanism**, not a disabled check: where coordinates are pinned, no publisher can produce such
    /// a proof and no reader can check one.
    pub vrf_coordinates: bool,
}

/// Spawn the production **hidden-service host** driver (§3b): host `service` anonymously so clients reach it
/// at its rotating meeting line even though this node is (in general) *not* that line's combiner. Each epoch
/// it rebuilds the cell mix directory, computes the meeting combiner and its own beacon-blinded dead-drop
/// line, draws a fresh dead-drop reply key, and **registers** an anonymous forward route at the combiner (an
/// onion, so no node learns this coordinate) — then hands the fresh `(key, directory)` to the
/// [`serve_anonymous`] accept loop it runs, which opens each forwarded request and hands the session's byte
/// stream to `handler` (a **full-duplex** handler — e.g. forward each session to a local port, the onion-
/// service model; [`spawn_rendezvous_host_rpc`] is the request/response convenience). Returns the epoch-loop
/// task; the accept loop runs as its own spawned task.
///
/// `coord` is this node's overlay coordinate (its dead-drop line passes through it); `host_secret` seeds the
/// dead-drop line selection and the per-epoch reply key (deterministic, so a restart re-derives them);
/// `initial` is the current `(epoch, beacon seed)` (e.g. `node.live_beacon()`), so the first registration
/// happens at startup rather than waiting for the next `BeaconReady`.
pub fn spawn_rendezvous_host<H, Fut>(
    client: Client,
    coord: Triple,
    hosted: HostedService,
    initial: (Epoch, [u8; 32]),
    handler: H,
) -> JoinHandle<()>
where
    H: Fn(DuplexStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let HostedService { service, identity, signer, host_secret, threshold, vrf_coordinates } = hosted;
    let service_public = service.public().clone();
    // **The bundle must name this very service.** A client makes two derivations from a service's identity and
    // they read different parts of it: the KEM half locates the service (the meeting line, and the handshake
    // encapsulates to it) while the whole bundle authorises its route binding. A bundle carrying someone else's
    // KEM key would send every client to compute a tag for a service that lives at another meeting line, and
    // every dial would miss — silently, since a tag that matches no registration simply falls through to local
    // delivery. Refusing to start says so once, loudly, instead.
    if fanos_diaulos::service_public_from_bundle(&identity).map(|k| k.encode()) != Some(service_public.encode()) {
        return tokio::spawn(async move {
            tracing::error!("hidden service refused to start: the identity bundle's KEM key is not this service's");
        });
    }
    let (epoch_tx, epoch_rx) = unbounded_channel::<HostEpoch>();
    // The accept loop opens forwarded dead-drops (its key ring fed per epoch) and hands each session to the
    // handler; it starts with an empty ring + directory, filled by the first rotation below.
    let rservice = RendezvousService::<F2>::new(MixDirectory::new(), threshold, &host_secret);
    serve_anonymous(
        client.clone(),
        service,
        SeedRng::from_seed(&host_secret),
        rservice,
        Vec::new(),
        Some(epoch_rx),
        handler,
    );
    let ctx = HostContext { service_public, host_secret, threshold, vrf_coordinates, identity, signer };
    tokio::spawn(async move {
        let mut beacons = client.beacons();
        let (mut epoch, mut seed) = initial;
        rotate_host(&client, coord, &ctx, epoch, seed, &epoch_tx).await;
        // Latest-state, not the lossy stream: a host that sleeps through an epoch keeps registering at the
        // meeting points of a period that has passed, so every client dialing it looks in the right place
        // and finds nothing — unreachable for the epoch, with no error on either side (#86).
        while let Some((reached, s)) = crate::next_epoch(&mut beacons, epoch).await {
            epoch = reached;
            seed = *s.as_bytes();
            rotate_host(&client, coord, &ctx, epoch, seed, &epoch_tx).await;
        }
    })
}

/// The **request/response** convenience over [`spawn_rendezvous_host`]: each anonymous session's request is
/// read up to `max_request` bytes, `handler(&request)` produces the response, and the session closes. A
/// streaming hidden service (forward each session to a local port) uses [`spawn_rendezvous_host`] directly.
///
/// [`RpcService::max_request`] carries the same obligation it does on [`serve_anonymous_rpc`], and for the
/// same reason: read that function's doc before choosing a number.
pub fn spawn_rendezvous_host_rpc<H>(
    client: Client,
    coord: Triple,
    hosted: HostedService,
    initial: (Epoch, [u8; 32]),
    rpc: RpcService<H>,
) -> JoinHandle<()>
where
    H: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    let RpcService { max_request, handler } = rpc;
    let handler = Arc::new(handler);
    let stations = client.clone();
    spawn_rendezvous_host(client, coord, hosted, initial, move |stream| {
        run_rpc(handler.clone(), stations.clone(), max_request, stream)
    })
}

/// Everything about the hosted service that every epoch's rotation needs, gathered once.
///
/// It exists because threading these individually had already reached nine parameters with a
/// `too_many_arguments` suppression, and the registration binding adds two more. A suppressed lint is a place a
/// reviewer stops reading, which is the wrong thing to have on the function that decides where a hidden service's
/// traffic goes.
struct HostContext {
    service_public: HybridKemPublic,
    host_secret: Vec<u8>,
    threshold: u8,
    /// See [`HostedService::vrf_coordinates`] — whether a mix-key record must prove the slot it sits at.
    vrf_coordinates: bool,
    identity: Vec<u8>,
    signer: HybridSigSecret,
}

/// Whether this epoch's mix directory is a sound basis for laying a hidden service's circuits.
///
/// **An incomplete read is treated exactly like an empty one**, and that is the whole point of carrying the
/// flag. Every construction downstream draws from the directory: `select_drop_line` skips a line whose members
/// are absent, `random_hops` picks only from what resolved, and `HostRegister::onion` refuses a hop it cannot
/// seal to. Under a partial view all three still *succeed*, over whichever lines answered.
///
/// Incomplete means a read **timed out**, not that a peer published nothing — an unpublished key is a definite
/// absence and routing around that node is correct, since it cannot be a hop. A timeout is not a fact about the
/// cell at all, so an adversary that can slow a chosen subset of store reads, far cheaper than compromising a
/// node, would otherwise steer this service's circuit placement. Registering over a subset an attacker shaped
/// is worse than not registering: the epoch is lost either way, and only one of the two hands the placement
/// over.
///
/// A named predicate rather than an inline `if`, so the rule can be asserted both ways — its two siblings in
/// the role loop (`setpoint_to_track`, `next_stable`) are pure for the same reason, and the branch it guards
/// is otherwise reachable only from a live cell whose store reads are being stalled.
#[must_use]
const fn may_register(resolved: usize, view: Coverage) -> bool {
    resolved > 0 && view.complete()
}

/// One epoch's host rotation: rebuild the directory, register the anonymous forward route at the current
/// meeting combiner, and push the fresh `(reply key, directory)` to the accept loop. A silent no-op if the
/// directory is not yet resolvable or a member key is missing — the next epoch (or the client's retransmits)
/// retries.
async fn rotate_host(
    client: &Client,
    coord: Triple,
    ctx: &HostContext,
    epoch: Epoch,
    seed: [u8; 32],
    epoch_tx: &UnboundedSender<HostEpoch>,
) {
    let HostContext { service_public, host_secret, threshold, vrf_coordinates, identity, signer } = ctx;
    let (threshold, vrf_coordinates) = (*threshold, *vrf_coordinates);
    // The same beacon this host derives its dead-drop line from, one line down.
    let beacon = BeaconSeed::new(seed);
    // The mix directory's binding mode is the cell's, so it is read from the client rather than configured here: a record
    // must prove its slot exactly where coordinates are VRF-derived (S1-M3, `mixdir::parse_bound_record`).
    let (dir, view) =
        build_plane_mix_directory::<F2>(client, epoch, vrf_coordinates.then_some(beacon)).await;
    if !may_register(dir.len(), view) {
        if !view.complete() {
            tracing::warn!(
                resolved = dir.len(),
                // The shortfall, not just its existence: one outstanding read on a busy cell is ordinary,
                // and six is the read-stalling attack this refusal exists for. Same warning either way
                // until the number is in it.
                unresolved = view.unresolved,
                "hidden service not registering this epoch: the cell's mix directory did not resolve in \
                 full, so any circuit drawn from it would be drawn from whichever lines answered rather \
                 than from the cell"
            );
        }
        return;
    }
    let Some(point) = Point::<F2>::new(coord) else { return };
    // The dead-drop line: beacon-blinded, through this node's own point — forwarded requests come home here.
    // Sealable against the epoch's directory, or `HostRegister::onion` below returns `None` and this
    // function silently returns — leaving the service unregistered for the whole epoch because one member of
    // one line happened to be absent. Choosing a usable line is the difference between a service that is
    // reachable and one that is quietly not there.
    let Some(drop_line) = select_drop_line(point, host_secret, epoch.get(), &seed, |l| {
        line_member_coords::<F2>(l.coords())
            .iter()
            .all(|m| dir.get(m).is_some())
    })
    .map(|l| l.coords()) else {
        // No line through this point can be sealed against this epoch's directory. Refuse the registration
        // and SAY so — the silence was half the defect (#163). This used to be indistinguishable from
        // success: `select_drop_line` returned an unusable line typed like a usable one, every circuit below
        // was laid around it, `onion` then returned `None`, and the function returned quietly. The service
        // was absent for the whole epoch and the failure surfaced as a CLIENT-side reachability fault.
        tracing::warn!(
            ?point,
            epoch = epoch.get(),
            "no sealable dead-drop line through this host's point — refusing to register for this epoch"
        );
        return;
    };
    // Every circuit below is laid AROUND `drop_line`, and around the meeting lines, for the reason
    // `rendezvous::route_leaks` states: no line may hold both a name for this host and a name for the service
    // it serves. Drawn from a per-epoch secret seed, so the paths are stable for the epoch the signed
    // registration names, unpredictable to anyone without `host_secret`, and fresh at every turn.
    let meetings = meeting_lines::<F2>(&service_public.encode(), epoch, &beacon);
    let mut avoid = meetings.clone();
    avoid.push(drop_line);
    // A fresh per-epoch dead-drop reply keypair (deterministic in secret+epoch), advertised in the
    // registration and handed to the accept loop to open forwarded requests.
    let (reply_keys, reply_pub) = ReplyKeys::generate(&epoch_seed(host_secret, epoch, b"reply"));
    // The route the combiner forwards requests along. It used to be `vec![drop_line]` — depth 0 — so the
    // member that peels a client request sealed it straight to this host's drop line, holding a service-name
    // and a host-name at once.
    //
    // `slots::MIN_REPLY_DEPTH` intermediates, and note that ONE would not have been enough here even though
    // it removes the depth-0 case: the launcher is a member of this service's meeting line, so it is itself
    // service-naming, and a hop learns BOTH its neighbours. A single intermediate would learn the launcher
    // (hence the service) and `drop_line` (hence this host, 1-of-(q+1)) — the same pair, one hop further out.
    let mut fwd_rng = SeedRng::from_seed(&epoch_seed(host_secret, epoch, b"fwd-circuit"));
    let mut forward_circuit =
        crate::rendezvous::random_hops::<F2, _>(slots::MIN_REPLY_DEPTH, &avoid, &dir, &mut fwd_rng);
    if forward_circuit.len() < slots::MIN_REPLY_DEPTH {
        // A plane too crowded to lay even one intermediate cannot host anonymously this epoch. Failing here
        // is the honest outcome: registering anyway would publish the drop line to every meeting member and
        // still call itself a hidden service.
        tracing::warn!(
            "hidden service not registering this epoch: no line is free to carry its forward circuit, so a \
             registration would hand the combiner this host's dead-drop line directly"
        );
        return;
    }
    forward_circuit.push(drop_line);
    let Some(reg) =
        HostRegister::onion(identity, signer, epoch, beacon.as_bytes(), reply_pub.encode(), forward_circuit, threshold)
    else {
        return;
    };
    // Register anonymously: seal the registration to the meeting line and raw-emit it at the combiner.
    // Register at EVERY meeting point, not one. A single meeting line put a whole epoch of this service's inbound
    // traffic behind one combiner, which cannot read it but can drop it — censorship by one node, and the beacon
    // is public so the placement is predictable an epoch ahead. `meeting_lines` yields `meeting_point_count(q)`
    // points with distinct combiners, so an adversary inside the tolerated fault budget cannot hold them all —
    // by pigeonhole on the small planes, and by the beacon's unpredictability on the large ones, where covering
    // a third of the network is not a cost the host can pay (`docs/design-rendezvous.md §6`).
    //
    // Additive by construction: meeting point 0 IS the single-point derivation, so a client still computing
    // `meeting_line` keeps finding this service there while the extra points are pure gain.
    //
    // Each registration is sealed under its own seed. They carry the same identity and route but different tags,
    // so a combiner that peels one cannot replay it to another meeting point.
    //
    // And each is emitted to EVERY member of its meeting line, not to one combiner (#55): a route binding is
    // state at whichever node peels the request, and client launches draw a per-onion member
    // (`combiner_for_salted`), so a member without the binding is a member that answers a client with silence.
    // The same sealed frame serves all `q + 1` — each member runs its own gather over the identical onion and
    // binds. This is what makes silencing a meeting point cost the adversary a `q + 2 − t` quorum of its line
    // rather than one node.
    for (i, meeting) in meetings.iter().copied().enumerate() {
        let seed = epoch_seed(host_secret, epoch, &[b"reg".as_slice(), &(i as u32).to_be_bytes()].concat());
        let mut rng = SeedRng::from_seed(&epoch_seed(
            host_secret,
            epoch,
            &[b"reg-circuit".as_slice(), &(i as u32).to_be_bytes()].concat(),
        ));
        let mut circuit =
            crate::rendezvous::random_hops::<F2, _>(slots::MIN_FORWARD_DEPTH, &avoid, &dir, &mut rng);
        if circuit.len() < slots::MIN_FORWARD_DEPTH {
            continue;
        }
        circuit.push(meeting);
        // ONE emission, at a salted member of the FIRST hop — not one per member of the meeting line. That
        // loop was the leak: `Input::Message` carries a transport-authenticated source coordinate, so every
        // member of every meeting line learned this host's address, which is precisely what a hidden service
        // must not publish. The fan-out now happens inside the onion, at the last hop
        // (`seal_host_register`'s dead-drop envelope), where a member of the meeting line does it on our
        // behalf and this coordinate never appears.
        if let Some(fwd) = seal_host_register::<F2>(&circuit, &dir, threshold, &reg, &seed) {
            client.command(Command::Emit { to: fwd.combiner, frame: fwd.frame });
        }
    }
    let _ = epoch_tx.send(HostEpoch { reply_keys, directory: dir });
}

/// A domain-separated per-epoch seed for the host's reply key / registration onion, so each epoch draws fresh
/// key material and the two uses never collide, yet a restart re-derives the same values.
fn epoch_seed(host_secret: &[u8], epoch: Epoch, domain: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(host_secret.len() + domain.len() + 8);
    s.extend_from_slice(host_secret);
    s.extend_from_slice(domain);
    s.extend_from_slice(&epoch.get().to_be_bytes());
    s
}

/// Spin up one anonymous session, keyed by `cookie`: a [`serve_over_channels`] DIAULOS server bridged so its
/// outbound cells are forwarded — tagged by `cookie` — to the central loop's `seal_tx` (which owns the
/// `RendezvousService` and seals them), with `handler` spawned over the resulting stream. When the handler
/// completes, `done_tx` is signalled so the demultiplexer reaps the session.
fn spawn_anonymous_session<H, Fut>(
    keypair: Arc<StaticKeypair>,
    rng: SeedRng,
    cookie: SessionId,
    handler: Arc<H>,
    seal_tx: Sender<(SessionId, Vec<u8>)>,
    done_tx: UnboundedSender<SessionId>,
    reporter: Client,
) -> (Sender<Vec<u8>>, JoinHandle<()>)
where
    H: Fn(DuplexStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (in_tx, in_rx) = channel::<Vec<u8>>(ChannelTransport::CAP);
    let (out_tx, mut out_rx) = channel::<Vec<u8>>(ChannelTransport::CAP);
    // Discards reported by this session reach the operator here (#276). **`line` is `None`, and that is the
    // design, not an omission**: on the anonymous path the host does not learn a client coordinate — the
    // whole point — so the station can say *what* was thrown away and never *by whom*. On the Direct path
    // the same station does carry the peer, and the difference between the two readings is itself the
    // profile's privacy claim made visible.
    let (ingest_tx, mut ingest_rx) = channel::<fanos_diaulos::Ingest>(crate::diaulos::INGEST_REPORTS);
    tokio::spawn(async move {
        while let Some(outcome) = ingest_rx.recv().await {
            reporter.record_station(
                Station::SessionIngestDropped,
                None,
                u64::try_from(outcome.index()).ok(),
            );
        }
    });
    // Outbound: this session's cells are funnelled to the central loop for sealing through its reply route.
    tokio::spawn(async move {
        while let Some(cell) = out_rx.recv().await {
            // `send().await`, not `try_send` — the queue is bounded now (#248) and a full one must apply
            // BACKPRESSURE rather than drop. This await blocks only this session's forwarder, which fills
            // its own bounded `out_rx`, which stalls its own DIAULOS server: a client producing faster than
            // the host can seal throttles ITSELF, and no cell is lost. Dropping here would have needed a
            // refusal outcome and would still have lost a reply the client is waiting for.
            //
            // It cannot deadlock: the loop drains `seal_rx` and never waits on this task.
            if seal_tx.send((cookie, cell)).await.is_err() {
                break; // the accept loop is gone; nothing left to seal through.
            }
        }
    });
    // Pace the server's retransmit clock to the mixnet's effective round trip — the SAME cadence the
    // client dials at ([`crate::rendezvous::RENDEZVOUS_TICK`]) — so replies do not flood the return path
    // faster than the per-hop threshold gathers can peel them (the anti-livelock discipline the reference
    // hand-rolled; here it is the shared paced session driver).
    let stream = serve_over_channels_paced_observed(
        keypair,
        rng,
        ChannelTransport {
            outbound: out_tx,
            inbound: in_rx,
        },
        crate::rendezvous::RENDEZVOUS_TICK,
        Some(ingest_tx),
    );
    let task = tokio::spawn(async move {
        handler(stream).await;
        let _ = done_tx.send(cookie);
    });
    (in_tx, task)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_aphantos::nostos::seal_to_receiver;

    /// The bound's three answers, at the boundary itself (#194).
    ///
    /// `max` and `max + 1` are the only pair that can distinguish a working bound from an off-by-one, and
    /// the `max` case is the one that matters most: a limit that refuses a request which *fits* is a service
    /// that looks broken to its own clients, and would be blamed on the network rather than on this line.
    #[tokio::test]
    async fn a_request_is_refused_at_one_byte_past_the_bound_and_served_at_the_bound() {
        const BOUND: usize = 64;
        for (len, want) in [
            (BOUND - 1, RequestRead::Body(vec![7u8; BOUND - 1])),
            (BOUND, RequestRead::Body(vec![7u8; BOUND])),
            (BOUND + 1, RequestRead::OverBound),
        ] {
            // Written and half-closed before the read, with a pipe wider than the largest case: no task, so
            // no reason for this to want a multi-threaded runtime (#201). The client's shutdown is what
            // ends the request, exactly as a real one does.
            let (mut host, mut client) = tokio::io::duplex(4 * BOUND);
            {
                use tokio::io::AsyncWriteExt;
                client.write_all(&vec![7u8; len]).await.unwrap();
                client.shutdown().await.unwrap();
            }
            let got = read_bounded(&mut host, BOUND).await;
            assert_eq!(got, want, "a {len}-byte request against a bound of {BOUND}");
        }
    }

    /// Both directions of the registration gate, which is the only way to tell a working refusal from one
    /// that never registers at all.
    #[test]
    fn a_hidden_service_registers_only_on_a_directory_that_fully_resolved() {
        let whole = Coverage { unresolved: 0 };
        assert!(may_register(7, whole), "a complete read of a populated cell is what registration is for");
        assert!(may_register(3, whole), "a cell where four members published nothing is still a KNOWN cell");
        assert!(!may_register(0, whole), "nothing to seal to");
        // The count is what separates these two from the pair above: same `resolved`, and the shortfall is
        // now stated rather than implied by a bare `false`.
        assert!(
            !may_register(7, Coverage { unresolved: 1 }),
            "a full-looking view with even one read outstanding is not a view of the cell"
        );
        assert!(!may_register(3, Coverage { unresolved: 4 }), "and neither is a partial one");
    }

    #[test]
    fn open_forwarded_tries_the_recent_epoch_ring() {
        // A request forwarded under epoch B is end-to-end sealed to B's dead-drop key; the host may have
        // already rotated, so B is not the ring's head — the ring must be TRIED, not just its newest key.
        let (a1, _) = ReplyKeys::generate(b"epoch-A");
        let (a2, _) = ReplyKeys::generate(b"epoch-A"); // same seed ⇒ same keys as a1
        let (b_keys, b_pub) = ReplyKeys::generate(b"epoch-B");
        let body = seal_to_receiver(&b_pub, b"a forwarded request", b"e2e-seed").unwrap();

        // Ring holds the previous (A) and current (B) epoch keys → B opens it.
        assert_eq!(open_forwarded(&[a1, b_keys], body.clone()), b"a forwarded request");
        // Only the wrong epoch (A) → cannot open, falls through to the raw bytes (a direct request would).
        assert_eq!(open_forwarded(&[a2], body.clone()), body);
        // An empty ring (the service IS its own combiner) always ingests raw.
        let plain = b"plaintext request at the combiner".to_vec();
        assert_eq!(open_forwarded(&[], plain.clone()), plain);
    }
}
