//! DIAULOS sessions over the node's overlay transport — the client dial and a service accept path.
//!
//! The base overlay moves datagrams by coordinate (`Command::Send` / `Notification::Delivered`); this
//! module rides a reliable, encrypted, hybrid-PQ [DIAULOS](fanos_diaulos) session on top, exposing it
//! as an async byte stream. [`NodeTransport`] adapts a node [`Client`] to the
//! [`OverlayTransport`] the async stream driver expects;
//! [`dial_service`] / [`FanosDialer`] are the client side (what a SOCKS5 proxy calls); [`serve`] is
//! the multi-client service accept loop. This is the **Direct** profile — the anonymous rendezvous is
//! a different transport under the identical stream.

use fanos_diaulos::service_public_from_bundle;
use fanos_diaulos::{ClientSession, Coord, StaticKeypair};
use fanos_field::F2;
use fanos_geometry::Triple;
use fanos_onoma::Epoch;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_pqcrypto::rng::SeedRng;
use fanos_proxy::{DialError, Dialer, Target, UdpDialer, UdpTunnel};
use fanos_quic::Client;
use fanos_rendezvous::{BeaconSeed, MixDirectory, meeting_lines};
use fanos_runtime::{Command, Notification};
use fanos_session::{
    ChannelTransport, GIVE_UP_ATTEMPTS, OverlayTransport, dial_over_transport, serve_over_channels,
};
use rand_core::CryptoRng;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::sync::broadcast;
use tokio::sync::oneshot;
use tokio::sync::mpsc::{Sender, UnboundedSender, channel, unbounded_channel};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Cap on the client sessions a service accept loop tracks concurrently. A client dialing the service is
/// not admission-gated (unlike overlay membership, §L3), so without a cap a flood of distinct source
/// coordinates — or handlers that never finish — would grow the peer map without bound (audit A4). At the
/// cap, the least-recently-active session is evicted (its handler aborted) to admit a new one.
pub(crate) const MAX_SESSIONS: usize = 1024;

/// A session that has **accepted** no datagram for this long is evicted — its inbound channel closed and
/// its handler task aborted — reclaiming a wedged or abandoned handler that never signals completion
/// (audit A4).
///
/// "Accepted", not "seen": a session whose handler has stopped draining its bounded queue rejects every
/// further datagram, so it ages out even while its peer keeps sending. Sweeping on arrival instead made
/// this timer un-trippable by exactly the wedged sessions it exists to reclaim (see [`Session::last_active`]).
///
/// This is the **backstop**, not the primary bound. A peer that stops answering is now abandoned by the
/// session driver itself (`fanos_session`'s RFC 1122 give-up rule), which ends the task and lets the
/// ordinary reap path free the slot; this sweep covers what that cannot see — a handler wedged against a
/// peer still sending.
pub(crate) const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// How often the accept loop sweeps for idle sessions to evict.
pub(crate) const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// One live client session in a service accept loop: the channel feeding it inbound datagrams, its
/// handler task (aborted on idle/cap eviction, so a wedged handler is reclaimed, not merely detached), and
/// its last-activity time (for idle and LRU eviction). Shared by the Direct [`serve`] loop (keyed by
/// client coordinate) and the anonymous [`crate::rendezvous_host::serve_anonymous`] loop (keyed by cookie).
pub(crate) struct Session {
    pub(crate) in_tx: Sender<Vec<u8>>,
    pub(crate) task: JoinHandle<()>,
    /// When this session last **accepted** a datagram — not when one last arrived for it.
    ///
    /// The distinction is the whole point: it is refreshed only by [`Session::accept`], on a successful
    /// `in_tx.try_send`, so a session whose handler has stopped draining its queue ages out even while
    /// its peer keeps sending. Refreshing on arrival made the field measure *traffic*, which meant the
    /// sweep could never fire on precisely the wedged sessions it exists to reclaim, and `evict_lru`
    /// would sacrifice healthy sessions to keep them.
    pub(crate) last_active: Instant,
}

impl Session {
    /// Offer `payload` to this session, returning whether it was taken.
    ///
    /// `try_send`, so a **full** queue drops the datagram (audit A4b — DIAULOS retransmits it) and a
    /// **closed** one reports failure for the caller's reap checks. The idle timer is refreshed **only on
    /// success**, which is what makes [`SESSION_IDLE_TIMEOUT`] a liveness bound rather than a traffic one.
    ///
    /// Both accept loops — Direct ([`serve`]) and anonymous
    /// ([`crate::rendezvous_host::serve_anonymous`]) — go through here, so the invariant has one
    /// definition instead of two copies free to drift apart.
    pub(crate) fn accept(&mut self, payload: Vec<u8>) -> bool {
        let taken = self.in_tx.try_send(payload).is_ok();
        if taken {
            self.last_active = Instant::now();
        }
        taken
    }
}

/// Evict the least-recently-active session (called when a session map is at [`MAX_SESSIONS`]), aborting its
/// handler task so a stuck session cannot hold a slot against a live client. Generic over the session key so
/// both accept loops (coordinate-keyed and cookie-keyed) share one bound.
pub(crate) fn evict_lru<K: Copy + Eq + std::hash::Hash>(peers: &mut HashMap<K, Session>) {
    let victim = peers
        .iter()
        .min_by_key(|(_, s)| s.last_active)
        .map(|(&coord, _)| coord);
    if let Some(coord) = victim
        && let Some(session) = peers.remove(&coord)
    {
        session.task.abort();
    }
}

/// An [`OverlayTransport`] over a node's [`Client`]: outbound payloads become `Command::Send`, and the
/// node's `Notification::Delivered` events become inbound datagrams.
pub struct NodeTransport {
    client: Client,
    deliveries: broadcast::Receiver<Notification>,
}

impl NodeTransport {
    /// Adapt `client` into a transport (subscribing to its delivery stream).
    #[must_use]
    pub fn new(client: Client) -> Self {
        let deliveries = client.subscribe();
        Self { client, deliveries }
    }
}

impl OverlayTransport for NodeTransport {
    fn send(&self, to: Coord, payload: Vec<u8>) {
        self.client.command(Command::Send { to, payload });
    }

    async fn recv(&mut self) -> Option<(Coord, Vec<u8>)> {
        loop {
            match self.deliveries.recv().await {
                Ok(Notification::Delivered { from, payload }) => return Some((from, payload)),
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// Dial a service by its overlay coordinate and static public key, returning an async byte stream
/// (the pipe a SOCKS5 client's TCP payload rides). The `rng` seeds the client's ephemeral handshake
/// keys — pass a cryptographically secure source in production.
#[must_use]
pub fn dial_service<R: CryptoRng>(
    client: Client,
    service: Coord,
    service_public: &HybridKemPublic,
    rng: &mut R,
) -> DuplexStream {
    let session = ClientSession::dial(service, service_public, rng);
    dial_over_transport(session, NodeTransport::new(client))
}

/// Run a **multi-client, full-duplex** DIAULOS service on `client`'s node: each client that dials gets its
/// own session driven as an async [`DuplexStream`] and handed to `handler`, which may read the request and
/// write the response **concurrently** and stream in both directions — not merely answer once. A single
/// service `keypair` (the identity) backs every client (cloned per session, so one hidden service serves
/// many); `rng` is the base entropy each client's session draws a fresh CSPRNG from. Spawns a background
/// demultiplexer and returns immediately.
///
/// The demultiplexer routes each `Notification::Delivered { from, .. }` to that client's session; a new
/// `from` — or one whose previous session finished — spins up a fresh session + `handler` task, and a
/// completed session is reaped, so the peer map holds only live clients (does not grow without bound).
pub fn serve<R, H, Fut>(client: Client, keypair: StaticKeypair, mut rng: R, handler: H)
where
    R: CryptoRng + Send + 'static,
    H: Fn(DuplexStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let handler = Arc::new(handler);
    // Share the service identity across all client sessions — never copy the secret (audit A6).
    let keypair = Arc::new(keypair);
    tokio::spawn(async move {
        let mut deliveries = client.subscribe();
        let mut peers: HashMap<Coord, Session> = HashMap::new();
        // A session task signals its client coordinate here when its handler completes, so the demux reaps
        // it. The map is also capped ([`MAX_SESSIONS`], LRU-evicted) and idle-swept, so neither a flood of
        // distinct client coordinates nor a wedged handler can grow it without bound (audit A4).
        let (done_tx, mut done_rx) = unbounded_channel::<Coord>();
        let mut sweep = tokio::time::interval(SESSION_SWEEP_INTERVAL);
        loop {
            tokio::select! {
                event = deliveries.recv() => match event {
                    Ok(Notification::Delivered { from, payload }) => {
                        // Reuse a live session, or spin up a fresh one — on first contact or when the
                        // previous one finished (its inbound channel closed), so a reconnecting client
                        // starts clean. At the cap, evict the least-recently-active session first.
                        let live = peers.get(&from).is_some_and(|s| !s.in_tx.is_closed());
                        if !live {
                            peers.remove(&from); // drop a finished/closed session before replacing it
                            if peers.len() >= MAX_SESSIONS {
                                evict_lru(&mut peers);
                            }
                            let mut seed = [0u8; 32];
                            rng.fill_bytes(&mut seed);
                            let (in_tx, task) = spawn_client_session(
                                client.clone(),
                                keypair.clone(),
                                SeedRng::from_seed(&seed),
                                from,
                                handler.clone(),
                                done_tx.clone(),
                            );
                            peers.insert(from, Session { in_tx, task, last_active: Instant::now() });
                        }
                        if let Some(session) = peers.get_mut(&from) {
                            session.accept(payload);
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                reaped = done_rx.recv() => {
                    // Reap a finished session, but only if a reconnect has not already replaced it with a
                    // fresh (still-open) one — a race-free drop keyed on the sender being closed.
                    if let Some(from) = reaped
                        && peers.get(&from).is_some_and(|s| s.in_tx.is_closed())
                    {
                        peers.remove(&from);
                    }
                }
                _ = sweep.tick() => {
                    // Evict sessions idle past the timeout: close their inbound channel and abort the
                    // handler task, reclaiming a wedged handler that never signalled completion.
                    let now = Instant::now();
                    let idle: Vec<Coord> = peers
                        .iter()
                        .filter(|(_, s)| now.duration_since(s.last_active) >= SESSION_IDLE_TIMEOUT)
                        .map(|(&coord, _)| coord)
                        .collect();
                    for coord in idle {
                        if let Some(session) = peers.remove(&coord) {
                            session.task.abort();
                        }
                    }
                }
            }
        }
    });
}

/// A convenience over [`serve`] for the common **request/response** shape: read the whole request (until
/// the client half-closes), call `handler(&request)`, write the response, and close. Full-duplex or
/// streaming services (which read and write concurrently) use [`serve`] directly.
pub fn serve_rpc<R, H>(client: Client, keypair: StaticKeypair, rng: R, handler: H)
where
    R: CryptoRng + Send + 'static,
    H: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    serve(client, keypair, rng, move |mut stream: DuplexStream| {
        let handler = handler.clone();
        async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut request = Vec::new();
            if stream.read_to_end(&mut request).await.is_ok() {
                let response = handler(&request);
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            }
        }
    });
}

/// Spin up one client's full-duplex session: a [`serve_over_channels`] driver bridged to the node
/// (outbound cells → `Command::Send { to: from }`; inbound is the returned channel the demultiplexer feeds
/// this client's deliveries into), with `handler` spawned over the resulting stream. When the handler
/// completes, `done_tx` is signalled so the demultiplexer reaps the session.
fn spawn_client_session<H, Fut>(
    client: Client,
    keypair: Arc<StaticKeypair>,
    rng: SeedRng,
    from: Coord,
    handler: Arc<H>,
    done_tx: UnboundedSender<Coord>,
) -> (Sender<Vec<u8>>, JoinHandle<()>)
where
    H: Fn(DuplexStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (in_tx, in_rx) = channel::<Vec<u8>>(ChannelTransport::CAP);
    let (out_tx, mut out_rx) = channel::<Vec<u8>>(ChannelTransport::CAP);
    // Outbound: this session's cells are addressed to the client coordinate over the node.
    tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            client.command(Command::Send { to: from, payload });
        }
    });
    let stream = serve_over_channels(
        keypair,
        rng,
        ChannelTransport {
            outbound: out_tx,
            inbound: in_rx,
        },
    );
    let task = tokio::spawn(async move {
        handler(stream).await;
        let _ = done_tx.send(from);
    });
    (in_tx, task)
}

/// Resolves a `.fanos` host to the service's overlay coordinate and its **canonical identity bundle** — the two
/// facts [`FanosDialer`] needs to dial it. A production impl reads the ONOMA descriptor (bundle + coordinate)
/// from the overlay; [`StaticResolver`] is a fixed map for simple deployments and tests.
///
/// **The bundle, not the KEM key it contains**, and the distinction is load-bearing: a dial needs *two*
/// derivations from the service's identity, and they read different parts of it. The KEM key LOCATES the service
/// — it derives the meeting line and the handshake encapsulates to it — while the whole bundle AUTHORISES its
/// route binding, since `service_tag` is a one-way image of it and the combiner recomputes that tag from the
/// registration's carried identity. Reducing to the KEM key here threw the second derivation's input away, so a
/// client computed a tag no host could ever register under.
pub trait ServiceResolver: Send + Sync {
    /// Resolve `host` (the full `.fanos` name) to `(coordinate, identity bundle)`, or `None` if it is unknown.
    fn resolve(&self, host: &str) -> impl Future<Output = Option<(Coord, Vec<u8>)>> + Send;
}

/// A fixed `host → (coordinate, key)` map.
#[derive(Default)]
pub struct StaticResolver {
    map: BTreeMap<String, (Coord, Vec<u8>)>,
}

impl StaticResolver {
    /// An empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a service (builder style).
    #[must_use]
    pub fn with(mut self, host: impl Into<String>, coord: Coord, identity: Vec<u8>) -> Self {
        self.map.insert(host.into(), (coord, identity));
        self
    }
}

impl ServiceResolver for StaticResolver {
    fn resolve(&self, host: &str) -> impl Future<Output = Option<(Coord, Vec<u8>)>> + Send {
        std::future::ready(self.map.get(host).cloned())
    }
}

/// A SOCKS5 [`Dialer`] that reaches `.fanos` services over DIAULOS: resolve the name to a coordinate
/// and static key, then dial a reliable, encrypted, hybrid-PQ session (an async byte stream) to it.
/// Each dial seeds a fresh CSPRNG from OS entropy for its ephemeral handshake keys, so forward
/// secrecy holds per connection.
///
/// A **clearnet** target (any non-`.fanos` name or IP) is reached through a configured **exit** node
/// ([`with_exit`](Self::with_exit)): the dialer opens an exit session (`dial_exit`) and hands it the
/// `host:port`, so the destination sees the exit rather than the client. Without an exit configured, a
/// clearnet target is `Unsupported` (a `.fanos`-only proxy).
pub struct FanosDialer<R: ServiceResolver> {
    client: Client,
    resolver: R,
    profile: Profile,
    /// The exit node (coordinate + service key) clearnet targets are routed through, if any.
    exit: Option<(Coord, Vec<u8>)>,
}

/// Parameters to draw a **fresh unlinkable** rendezvous route *per dial* — the general anonymous proxy
/// profile (spec §L5, #54). Each connection gets new random forward/reply hops drawn from the live mix
/// `directory`, so an observer cannot link successive dials by their shared path (the fixed-route
/// [`FanosDialer::anonymous`] reuses one path across dials and is linkable — a real proxy must use this).
pub struct AnonRouteParams {
    /// The live mixnet key directory (e.g. from [`build_cell_mix_directory`](crate::build_cell_mix_directory)).
    pub directory: MixDirectory,
    /// How many of each hop line's members must cooperate to peel an onion.
    pub threshold: u8,
    /// The rendezvous epoch (the meeting line and placement rotate with it).
    pub epoch: Epoch,
    /// The epoch's beacon seed (folds into the meeting-line derivation).
    pub beacon: BeaconSeed,
    /// `(forward, reply)` intermediate-hop depths for each freshly-drawn circuit.
    pub depths: (usize, usize),
}

/// The dialer's routing profile.
enum Profile {
    /// Direct: reach services by coordinate (fast, but reveals *where* each party is).
    Direct,
    /// Anonymous with **one fixed** rendezvous route reused across dials (the meeting line is still
    /// per-target). Simple, but successive dials share the same intermediate hops — an observer can LINK
    /// them; kept for the single-service test path.
    Fixed(crate::rendezvous::RendezvousRoute),
    /// Anonymous with a **fresh unlinkable** route drawn per dial from the live directory — the general
    /// proxy profile.
    Fresh(AnonRouteParams),
}

impl<R: ServiceResolver> FanosDialer<R> {
    /// A **Direct** dialer on `client`'s node resolving names through `resolver`: it reaches services
    /// by coordinate (fast, but reveals *where* each party is).
    #[must_use]
    pub fn new(client: Client, resolver: R) -> Self {
        Self {
            client,
            resolver,
            profile: Profile::Direct,
            exit: None,
        }
    }

    /// Route **clearnet** targets (non-`.fanos` names and IPs) through the exit node at `coord` with static
    /// key `public` — the dialer opens a `dial_exit` session and hands it the destination. Without this,
    /// clearnet targets are `Unsupported`.
    #[must_use]
    pub fn with_exit(mut self, coord: Coord, identity: Vec<u8>) -> Self {
        self.exit = Some((coord, identity));
        self
    }

    /// An **anonymous** dialer with a single fixed `route`: every dial rides threshold onions along it to
    /// the service's computed meeting line (per-target), hiding both parties' locations. Successive dials
    /// share the route's intermediate hops, so they are linkable — for a general proxy use
    /// [`anonymous_fresh`](Self::anonymous_fresh), which draws a new path per dial.
    #[must_use]
    pub fn anonymous(
        client: Client,
        resolver: R,
        route: crate::rendezvous::RendezvousRoute,
    ) -> Self {
        Self {
            client,
            resolver,
            profile: Profile::Fixed(route),
            exit: None,
        }
    }

    /// A **general anonymous** dialer that draws a **fresh, unlinkable** rendezvous route for *every* dial
    /// from `params`' live mix directory (spec §L5, #54): each connection gets new random forward/reply
    /// hops, so an observer cannot link a client's successive connections by their path — the property a
    /// real anonymity proxy needs. The per-target meeting line is derived from the resolved service key.
    #[must_use]
    pub fn anonymous_fresh(client: Client, resolver: R, params: AnonRouteParams) -> Self {
        Self {
            client,
            resolver,
            profile: Profile::Fresh(params),
            exit: None,
        }
    }

    /// Establish a DIAULOS session to a service (identified by `service_public`, located at `coord` for the
    /// Direct profile) via this dialer's anonymity profile. Shared by the TCP [`dial`](Self::dial) and UDP
    /// [`dial_udp`](Self::dial_udp) paths so **both** honour the profile — an anonymous profile never reaches a
    /// service (or the clearnet exit) by coordinate, which would leak the client's coordinate (audit S1-C1).
    async fn establish(
        &self,
        coord: Coord,
        identity: &[u8],
        rng: &mut SeedRng,
    ) -> Result<DuplexStream, DialError> {
        Ok(match &self.profile {
            Profile::Direct => {
                let public = service_public_from_bundle(identity).ok_or(DialError::Unreachable)?;
                dial_service(self.client.clone(), coord, &public, rng)
            }
            Profile::Fixed(route) => {
                let public = service_public_from_bundle(identity).ok_or(DialError::Unreachable)?;
                // A FIXED route can only be walked to meeting points it does not already pass through.
                // `RendezvousRoute::draw` lays forward hops that *avoid* their destination, so reusing one
                // route for a different meeting point can put that point in the middle of its own circuit —
                // a terminus the onion reaches and peels early, which is the "0 of 8 dials arriving" failure
                // this profile already carries a warning about. Such a point is unreachable *by this route*,
                // so it is not a candidate; the Fresh profile has no such restriction because it redraws.
                let meetings: Vec<Triple> =
                    meeting_lines::<F2>(&public.encode(), route.epoch, &route.beacon)
                        .into_iter()
                        .filter(|m| !route.forward_hops.contains(m) && !route.reply_circuit.contains(m))
                        .collect();
                self.walk_meeting_points(&meetings, rng, |meeting, rng| {
                    // A separate OS-entropy secret seeds each attempt's cookie + per-onion key material, so two
                    // attempts of one dial are no more linkable than two dials.
                    let secret = os_entropy_32()?;
                    crate::rendezvous::anonymous_dial(self.client.clone(), identity, route, meeting, &secret, rng)
                        .ok_or(DialError::Unreachable)
                })
                .await?
            }
            Profile::Fresh(params) => {
                // Derive the service's meeting points, DRAW A FRESH route per attempt (new random forward/reply
                // hops so this connection is unlinkable to the client's others), then ride the session over it.
                let public = service_public_from_bundle(identity).ok_or(DialError::Unreachable)?;
                let meetings = meeting_lines::<F2>(&public.encode(), params.epoch, &params.beacon);
                self.walk_meeting_points(&meetings, rng, |meeting, rng| {
                    // The route is drawn to the meeting point THIS attempt uses. They must agree: `draw` lays
                    // hops that avoid the destination, so a route drawn toward one meeting point and sealed to
                    // another is a circuit built for somewhere it is not going — measured as 0 of 8 dials
                    // arriving. Redrawing per attempt is required, not merely tidy.
                    let route = crate::rendezvous::RendezvousRoute::draw::<F2, _>(
                        params.directory.clone(),
                        params.threshold,
                        params.epoch,
                        params.beacon,
                        meeting,
                        params.depths,
                        rng,
                    );
                    let secret = os_entropy_32()?;
                    crate::rendezvous::anonymous_dial(self.client.clone(), identity, &route, meeting, &secret, rng)
                        .ok_or(DialError::Unreachable)
                })
                .await?
            }
        })
    }

    /// Try a service's meeting points **from a random start** until one's DIAULOS handshake completes.
    ///
    /// `meeting_lines` derives its count so that at least one meeting point is uncensored — by pigeonhole on
    /// the small planes, by the beacon's unpredictability on the large ones. Drawing *one* point and giving up
    /// converts that guarantee into a per-dial success of `1 − f/n ≈ 2/3` and makes every point past the first
    /// dead weight: the derivation proves a good element **exists**, and only a walk finds it
    /// (`docs/design-rendezvous.md §5`). Failure here is observable — the confirmation signal resolves `Err`
    /// when the session driver gives up — so this is a walk and not a re-draw.
    ///
    /// The **start is random**, which is the property the previous single pick was really protecting: two dials
    /// by one client must not share a first contact, or a node sitting at a meeting point can link them. A
    /// random start keeps each dial's first contact uniform while the walk supplies the coverage.
    ///
    /// **Hedged, not serial-with-a-deadline** — and that is a measured correction, not a preference. A serial
    /// walk has to decide "is this meeting point censored, or merely slow?", and over this mixnet that
    /// question has no cheap answer: twelve healthy handshakes through a live meeting point measured
    /// `0.26 · 1.14 · 1.15 · 2.24 · 2.53 · 3.01 · 3.02 · 3.03 · 3.14 · 3.58 · 6.69 · 14.86` seconds — a median
    /// near 3 s with a tail past 14. Any deadline short enough to be useful against a censor also abandons
    /// live paths, which is *worse* than not walking at all; the first attempt at this measured **7 of 12**
    /// arrivals against a single draw's 8.
    ///
    /// Hedging removes the question instead of answering it (Dean & Barroso, *The Tail at Scale*). Attempts
    /// are **added** at [`HEDGE_DELAY`] and never withdrawn, so the dial completes at the *minimum* over the
    /// points tried rather than at whichever one it happened to commit to. The asymmetry is what makes this
    /// safe: hedging too early costs an extra onion, while timing out too early costs the dial.
    ///
    /// The anonymity price is that a hedged dial tells two meeting points a dial happened rather than one.
    /// Neither learns who dialled or that the two are the same client, and the service key that selects them
    /// is public anyway — so this buys tail latency with traffic, not with linkability.
    async fn walk_meeting_points(
        &self,
        meetings: &[Triple],
        rng: &mut SeedRng,
        mut attempt: impl FnMut(Triple, &mut SeedRng) -> Result<(DuplexStream, oneshot::Receiver<()>), DialError>,
    ) -> Result<DuplexStream, DialError> {
        if meetings.is_empty() {
            return Err(DialError::Unreachable);
        }
        let mut pick = [0u8; 4];
        rng.fill(&mut pick);
        let start = u32::from_be_bytes(pick) as usize % meetings.len();

        // Each launched attempt reports its own outcome here: `Ok(idx)` established, `Err(idx)` gave up. A
        // channel rather than a future combinator keeps the streams owned by this frame — the winner is handed
        // back and the losers drop, and dropping a loser's stream is what tears its session driver down.
        let (tx, mut rx) = channel(meetings.len());
        let mut streams: Vec<Option<DuplexStream>> = Vec::with_capacity(meetings.len());
        let mut last = DialError::Unreachable;
        let mut in_flight = 0usize;

        for i in 0..meetings.len() {
            let Some(&meeting) = meetings.get((start + i) % meetings.len()) else { break };
            match attempt(meeting, rng) {
                Ok((stream, ready)) => {
                    let (idx, tx) = (streams.len(), tx.clone());
                    streams.push(Some(stream));
                    in_flight += 1;
                    tokio::spawn(async move {
                        let _ = tx.send(ready.await.map(|()| idx).map_err(|_| idx)).await;
                    });
                }
                Err(e) => {
                    last = e;
                    continue;
                }
            }
            // Wait for something to happen before adding another meeting point: an establishment ends the
            // dial, a give-up frees a slot immediately, and the hedge delay adds a slot speculatively — but
            // only while fewer than `MAX_IN_FLIGHT` attempts are outstanding.
            //
            // **The cap is the load brake, and it is not optional.** Hedging assumes slowness is *local* to a
            // path. Under host starvation it is not — every path is slow at once, so an uncapped hedge fires
            // on every dial and multiplies onion traffic by `m` precisely when the mixnet can least carry it.
            // Measured: with the machine at load 16, an uncapped hedge took the silenced arm to **0 of 12**
            // against a control of 10, a collapse an unhedged client would not have had. Capping at two keeps
            // the worst case at 2× and leaves the coverage intact, because a *failed* attempt frees its slot
            // at once — speculation is bounded, recovery is not.
            while in_flight >= MAX_IN_FLIGHT {
                match rx.recv().await {
                    Some(Ok(idx)) => {
                        return streams.get_mut(idx).and_then(Option::take).ok_or(DialError::Unreachable);
                    }
                    Some(Err(_)) => in_flight -= 1,
                    None => return Err(last),
                }
            }
            match tokio::time::timeout(HEDGE_DELAY, rx.recv()).await {
                Ok(Some(Ok(idx))) => {
                    return streams.get_mut(idx).and_then(Option::take).ok_or(DialError::Unreachable);
                }
                Ok(Some(Err(_))) => in_flight -= 1,
                Ok(None) => return Err(last),
                Err(_) => {} // the hedge delay elapsed: add the next meeting point
            }
        }

        // Every meeting point has been offered. `recv` now ends only once the last attempt's task has dropped
        // its sender — that is, once every session driver has given up — so the drivers' own give-up rule is
        // the overall deadline and there is no second timer that could disagree with it.
        drop(tx);
        loop {
            match rx.recv().await {
                Some(Ok(idx)) => {
                    return streams.get_mut(idx).and_then(Option::take).ok_or(DialError::Unreachable);
                }
                Some(Err(_)) => {} // that point gave up; the others are still trying
                None => return Err(last),
            }
        }
    }
}

/// How long the attempts already in flight are given before another meeting point is **added**.
///
/// Not a deadline: nothing is abandoned when it expires, so the cost of firing early is one extra onion and
/// never a lost dial. That asymmetry is what lets the value be set from the measured distribution rather than
/// argued from a worst case — the twelve healthy handshakes timed in [`FanosDialer::walk_meeting_points`] put
/// the median near 3 s, so `GIVE_UP_ATTEMPTS × RENDEZVOUS_TICK` = 15 × 250 ms = 3.75 s sits around the third
/// quartile: most dials never hedge, and the tail past 6 s gets a second path without waiting out the first.
///
/// It reuses the platform's existing "no answer by now is evidence" quantity ([`GIVE_UP_ATTEMPTS`], RFC 1122's
/// `R2`) rather than introducing a constant of its own. Under a *timeout* that quantity was the wrong one —
/// it abandoned live paths — but as a hedge trigger it is exactly the right shape: the point past which
/// another sample is worth its bandwidth.
const HEDGE_DELAY: Duration = crate::rendezvous::RENDEZVOUS_TICK.saturating_mul(GIVE_UP_ATTEMPTS);

/// How many of a service's meeting points a single dial may have in flight at once.
///
/// **A hedge without a cap is a congestion amplifier.** Hedging is sound when slowness is a property of the
/// *path* — then a second sample is cheap information. When slowness is a property of the *host*, every path
/// is slow together, every dial hedges, and the mixnet receives `m` times the onions at the moment it is
/// least able to peel them. That is not a hypothetical: measured at machine load 16, an uncapped hedge drove
/// the censored arm of `anonymous_quic`'s experiment to **0 of 12** against a control of 10 — worse than not
/// hedging at all, which is the signature of self-inflicted collapse.
///
/// Two is the smallest cap that keeps the mechanism: one live attempt plus one speculative alternative bounds
/// the traffic multiplier at 2× while a *failed* attempt frees its slot immediately, so coverage of all `m`
/// points is preserved — only the speculation is bounded, never the recovery.
const MAX_IN_FLIGHT: usize = 2;

/// 32 fresh bytes of OS entropy, mapped to a [`DialError`] on the (unexpected) failure of the OS source
/// — the one place a dial draws randomness for its ephemeral session material.
fn os_entropy_32() -> Result<[u8; 32], DialError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| DialError::Io(std::io::Error::other(format!("OS entropy failed: {e}"))))?;
    Ok(bytes)
}

impl<R: ServiceResolver> Dialer for FanosDialer<R> {
    type Stream = DuplexStream;

    async fn dial(&self, target: &Target) -> Result<DuplexStream, DialError> {
        // Resolve where to route, plus (for a clearnet target) the destination the exit must be handed. A
        // clearnet target rides the configured EXIT — but through the **same anonymity profile** as a `.fanos`
        // service (the exit is just a service, reached by its service key), so an anonymous profile never sends
        // clearnet by-coordinate Direct, which would leak the client's coordinate to the exit (audit S1-C1).
        let (coord, identity, exit_target): (Coord, Vec<u8>, Option<String>) = if target.is_fanos() {
            let host = target.host();
            let (coord, identity) = self.resolver.resolve(&host).await.ok_or(DialError::Unreachable)?;
            (coord, identity, None)
        } else {
            let Some((exit_coord, exit_public)) = &self.exit else {
                return Err(DialError::Unsupported(
                    "no exit configured — the FANOS dialer reaches only .fanos targets".to_owned(),
                ));
            };
            (*exit_coord, exit_public.clone(), Some(target.to_string()))
        };

        // A fresh CSPRNG seeded from OS entropy for this dial's ephemeral keys.
        let mut rng = SeedRng::from_seed(&os_entropy_32()?);

        // Establish the session per the anonymity profile (the exit is just a service, reached by its key).
        let stream = self.establish(coord, &identity, &mut rng).await?;

        // For a clearnet target, hand the exit its destination over the (Direct or anonymous) session it now
        // rides — the exit still learns only the target, never the client's coordinate.
        match exit_target {
            Some(t) => crate::exit::exit_send_target(stream, &t).await.map_err(DialError::Io),
            None => Ok(stream),
        }
    }
}

/// Slack (datagrams per direction) a UDP tunnel buffers before UDP's lossy drop kicks in — a few
/// in-flight datagrams smooth a burst without letting a stalled peer grow memory without bound.
const UDP_TUNNEL_BUFFER: usize = 64;

impl<R: ServiceResolver> UdpDialer for FanosDialer<R> {
    /// Open a UDP tunnel to a **clearnet** `target` through the configured exit — the datagram counterpart
    /// of [`dial`](Self::dial). The exit session is established through the **anonymity profile** (via
    /// ``establish``, same as the TCP path — audit S1-C1), then handed a `udp:host:port`
    /// target; datagrams ride it as length framing on the DIAULOS stream, pumped both ways into the
    /// [`UdpTunnel`]'s channels. A `.fanos` target is [`Unsupported`](DialError::Unsupported) (services are
    /// byte streams, not datagram endpoints); without an exit, so is any clearnet UDP target.
    async fn dial_udp(&self, target: &Target) -> Result<UdpTunnel, DialError> {
        if target.is_fanos() {
            return Err(DialError::Unsupported(
                ".fanos names are byte-stream services; UDP targets need a clearnet exit".to_owned(),
            ));
        }
        let Some((exit_coord, exit_public)) = &self.exit else {
            return Err(DialError::Unsupported(
                "no exit configured — the FANOS dialer relays UDP only through an exit".to_owned(),
            ));
        };
        let mut rng = SeedRng::from_seed(&os_entropy_32()?);
        // Route the exit session through the anonymity profile (audit S1-C1) — the datagram counterpart of the
        // TCP `dial`. Before this fix `dial_udp` reached the exit by COORDINATE (Direct only), so `proxy
        // --profile anonymous` leaked the client's coordinate to the exit on every SOCKS5 UDP datagram (DNS,
        // QUIC/HTTP-3, WebRTC). Establishing via the profile and then handing the exit its `udp:host:port`
        // target means an anonymous profile rides threshold onions to the exit's meeting line, never by-coord.
        let session = self.establish(*exit_coord, exit_public, &mut rng).await?;
        let stream = crate::exit::exit_send_target(session, &format!("udp:{}:{}", target.host(), target.port()))
            .await
            .map_err(DialError::Io)?;

        // Bridge the DIAULOS datagram stream to the tunnel's channels: outbound datagrams are length-framed
        // onto the stream, inbound frames are lifted back off it. Either direction closing ends both.
        let (tunnel, inbound_tx, mut outbound_rx) = UdpTunnel::pair(UDP_TUNNEL_BUFFER);
        tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let up = async move {
                while let Some(datagram) = outbound_rx.recv().await {
                    if crate::exit::write_datagram(&mut writer, &datagram).await.is_err() {
                        break;
                    }
                }
            };
            let down = async move {
                while let Some(datagram) = crate::exit::read_datagram(&mut reader).await {
                    if inbound_tx.send(datagram).await.is_err() {
                        break;
                    }
                }
            };
            tokio::select! {
                () = up => {}
                () = down => {}
            }
        });
        Ok(tunnel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session whose last activity was `age` ago (a still-live but idle handler task).
    fn idle_session(age: Duration) -> Session {
        let (in_tx, _in_rx) = channel::<Vec<u8>>(1);
        let task = tokio::spawn(std::future::pending::<()>());
        Session {
            in_tx,
            task,
            last_active: Instant::now() - age,
        }
    }

    #[tokio::test]
    async fn a_wedged_session_ages_out_even_while_its_peer_keeps_sending() {
        // The ghost-session sweep half. `last_active` must measure whether this session is still
        // CONSUMING, not whether datagrams keep arriving for it: a handler that has stopped draining
        // its bounded queue rejects everything further, and a timer refreshed by mere arrival could
        // never trip on precisely the wedged sessions it exists to reclaim — worse, since `evict_lru`
        // picks by the same field, the wedged one would look freshest and healthy sessions would be
        // shed to keep it.
        let (in_tx, in_rx) = channel::<Vec<u8>>(1); // capacity 1: one accepted, then wedged
        let mut wedged = Session {
            in_tx,
            task: tokio::spawn(std::future::pending::<()>()),
            last_active: Instant::now() - Duration::from_secs(3600),
        };
        // Nobody is draining `in_rx` — the wedged handler. The first datagram fits the queue and so is
        // genuinely accepted, which must refresh the timer.
        assert!(wedged.accept(b"first".to_vec()), "the empty queue takes one");
        let refreshed = wedged.last_active;
        assert!(
            Instant::now().duration_since(refreshed) < SESSION_IDLE_TIMEOUT,
            "an ACCEPTED datagram refreshes the idle timer"
        );
        // Now the queue is full. Every further datagram — a peer retransmitting forever, or an attacker
        // deliberately holding the slot — is dropped, and must NOT refresh the timer.
        for _ in 0..64 {
            assert!(!wedged.accept(b"more".to_vec()), "a full queue takes nothing");
        }
        assert_eq!(
            wedged.last_active, refreshed,
            "a peer that only keeps SENDING cannot hold a wedged session's slot open — the timer moved \
             only for the datagram that was actually taken"
        );
        drop(in_rx);
    }

    /// The cap-eviction victim is always the *least-recently-active* session — so a stalled/idle session
    /// is shed before a live client's, bounding the map (audit A4).
    #[tokio::test]
    async fn evict_lru_drops_the_least_recently_active_session() {
        let mut peers: HashMap<Coord, Session> = HashMap::new();
        peers.insert([1, 1, 1], idle_session(Duration::from_secs(1))); // newest
        peers.insert([2, 2, 2], idle_session(Duration::from_secs(30))); // oldest — the LRU victim
        peers.insert([3, 3, 3], idle_session(Duration::from_secs(5)));

        evict_lru(&mut peers);

        assert_eq!(peers.len(), 2, "exactly one session is evicted");
        assert!(
            !peers.contains_key(&[2, 2, 2]),
            "the least-recently-active session is the one evicted"
        );
        assert!(
            peers.contains_key(&[1, 1, 1]) && peers.contains_key(&[3, 3, 3]),
            "the more-recently-active sessions are kept"
        );
    }
}
