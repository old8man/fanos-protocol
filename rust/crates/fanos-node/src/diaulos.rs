//! DIAULOS sessions over the node's overlay transport — the client dial and a service accept path.
//!
//! The base overlay moves datagrams by coordinate (`Command::Send` / `Notification::Delivered`); this
//! module rides a reliable, encrypted, hybrid-PQ [DIAULOS](fanos_diaulos) session on top, exposing it
//! as an async byte stream. [`NodeTransport`] adapts a node [`Client`] to the
//! [`OverlayTransport`](fanos_session::OverlayTransport) the async stream driver expects;
//! [`dial_service`] / [`FanosDialer`] are the client side (what a SOCKS5 proxy calls); [`serve`] is
//! the multi-client service accept loop. This is the **Direct** profile — the anonymous rendezvous is
//! a different transport under the identical stream.

use fanos_diaulos::{ClientSession, Coord, StaticKeypair};
use fanos_field::F2;
use fanos_onoma::Epoch;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_pqcrypto::rng::SeedRng;
use fanos_proxy::{DialError, Dialer, Target, UdpDialer, UdpTunnel};
use fanos_quic::Client;
use fanos_rendezvous::{BeaconSeed, MixDirectory, meeting_line};
use fanos_runtime::{Command, Notification};
use fanos_session::{ChannelTransport, OverlayTransport, dial_over_transport, serve_over_channels};
use rand_core::CryptoRng;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Cap on the client sessions a service accept loop tracks concurrently. A client dialing the service is
/// not admission-gated (unlike overlay membership, §L3), so without a cap a flood of distinct source
/// coordinates — or handlers that never finish — would grow the peer map without bound (audit A4). At the
/// cap, the least-recently-active session is evicted (its handler aborted) to admit a new one.
const MAX_SESSIONS: usize = 1024;

/// A session with no traffic for this long is evicted — its inbound channel closed and its handler task
/// aborted — reclaiming a wedged or abandoned handler that never signals completion (audit A4).
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// How often the accept loop sweeps for idle sessions to evict.
const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// One live client session in the service accept loop: the channel feeding it inbound datagrams, its
/// handler task (aborted on idle/cap eviction, so a wedged handler is reclaimed, not merely detached), and
/// its last-activity time (for idle and LRU eviction).
struct Session {
    in_tx: UnboundedSender<Vec<u8>>,
    task: JoinHandle<()>,
    last_active: Instant,
}

/// Evict the least-recently-active session (called when the map is at [`MAX_SESSIONS`]), aborting its
/// handler task so a stuck session cannot hold a slot against a live client.
fn evict_lru(peers: &mut HashMap<Coord, Session>) {
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
                            session.last_active = Instant::now();
                            let _ = session.in_tx.send(payload);
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
) -> (UnboundedSender<Vec<u8>>, JoinHandle<()>)
where
    H: Fn(DuplexStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (in_tx, in_rx) = unbounded_channel::<Vec<u8>>();
    let (out_tx, mut out_rx) = unbounded_channel::<Vec<u8>>();
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

/// Resolves a `.fanos` host to the service's overlay coordinate and static KEM public key — the two
/// facts [`FanosDialer`] needs to dial it. A production impl reads the ONOMA descriptor (bundle +
/// coordinate) from the overlay; [`StaticResolver`] is a fixed map for simple deployments and tests.
pub trait ServiceResolver: Send + Sync {
    /// Resolve `host` (the full `.fanos` name), or `None` if it is unknown.
    fn resolve(&self, host: &str) -> impl Future<Output = Option<(Coord, HybridKemPublic)>> + Send;
}

/// A fixed `host → (coordinate, key)` map.
#[derive(Default)]
pub struct StaticResolver {
    map: BTreeMap<String, (Coord, HybridKemPublic)>,
}

impl StaticResolver {
    /// An empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a service (builder style).
    #[must_use]
    pub fn with(mut self, host: impl Into<String>, coord: Coord, public: HybridKemPublic) -> Self {
        self.map.insert(host.into(), (coord, public));
        self
    }
}

impl ServiceResolver for StaticResolver {
    fn resolve(&self, host: &str) -> impl Future<Output = Option<(Coord, HybridKemPublic)>> + Send {
        std::future::ready(self.map.get(host).cloned())
    }
}

/// A SOCKS5 [`Dialer`] that reaches `.fanos` services over DIAULOS: resolve the name to a coordinate
/// and static key, then dial a reliable, encrypted, hybrid-PQ session (an async byte stream) to it.
/// Each dial seeds a fresh CSPRNG from OS entropy for its ephemeral handshake keys, so forward
/// secrecy holds per connection.
///
/// A **clearnet** target (any non-`.fanos` name or IP) is reached through a configured **exit** node
/// ([`with_exit`](Self::with_exit)): the dialer opens an exit session ([`dial_exit`]) and hands it the
/// `host:port`, so the destination sees the exit rather than the client. Without an exit configured, a
/// clearnet target is `Unsupported` (a `.fanos`-only proxy).
pub struct FanosDialer<R: ServiceResolver> {
    client: Client,
    resolver: R,
    profile: Profile,
    /// The exit node (coordinate + service key) clearnet targets are routed through, if any.
    exit: Option<(Coord, HybridKemPublic)>,
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
    /// key `public` — the dialer opens a [`dial_exit`] session and hands it the destination. Without this,
    /// clearnet targets are `Unsupported`.
    #[must_use]
    pub fn with_exit(mut self, coord: Coord, public: HybridKemPublic) -> Self {
        self.exit = Some((coord, public));
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
}

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
        if !target.is_fanos() {
            // A clearnet target rides the configured exit (which sees the exit, not the client); without
            // one, this dialer is `.fanos`-only.
            let Some((exit_coord, exit_public)) = &self.exit else {
                return Err(DialError::Unsupported(
                    "no exit configured — the FANOS dialer reaches only .fanos targets".to_owned(),
                ));
            };
            let mut rng = SeedRng::from_seed(&os_entropy_32()?);
            return crate::exit::dial_exit(
                self.client.clone(),
                *exit_coord,
                exit_public,
                &target.to_string(),
                &mut rng,
            )
            .await
            .map_err(DialError::Io);
        }
        let host = target.host();
        let (coord, service_public) = self
            .resolver
            .resolve(&host)
            .await
            .ok_or(DialError::Unreachable)?;
        // A fresh CSPRNG seeded from OS entropy for this dial's ephemeral keys.
        let mut rng = SeedRng::from_seed(&os_entropy_32()?);
        match &self.profile {
            Profile::Direct => Ok(dial_service(
                self.client.clone(),
                coord,
                &service_public,
                &mut rng,
            )),
            Profile::Fixed(route) => {
                // A separate OS-entropy secret seeds this session's cookie + per-onion key material.
                let secret = os_entropy_32()?;
                Ok(crate::rendezvous::anonymous_dial(
                    self.client.clone(),
                    &service_public,
                    route,
                    &secret,
                    &mut rng,
                ))
            }
            Profile::Fresh(params) => {
                // The general anonymous profile: derive the service's per-target meeting line, DRAW A FRESH
                // route (new random forward/reply hops so this connection is unlinkable to the client's
                // others), then ride the DIAULOS session over it. `draw` and `anonymous_dial` re-derive the
                // same meeting line from the service key, so they agree.
                let meeting =
                    meeting_line::<F2>(&service_public.encode(), params.epoch, &params.beacon).coords();
                let route = crate::rendezvous::RendezvousRoute::draw::<F2, _>(
                    params.directory.clone(),
                    params.threshold,
                    params.epoch,
                    params.beacon,
                    meeting,
                    params.depths,
                    &mut rng,
                );
                let secret = os_entropy_32()?;
                Ok(crate::rendezvous::anonymous_dial(
                    self.client.clone(),
                    &service_public,
                    &route,
                    &secret,
                    &mut rng,
                ))
            }
        }
    }
}

/// Slack (datagrams per direction) a UDP tunnel buffers before UDP's lossy drop kicks in — a few
/// in-flight datagrams smooth a burst without letting a stalled peer grow memory without bound.
const UDP_TUNNEL_BUFFER: usize = 64;

impl<R: ServiceResolver> UdpDialer for FanosDialer<R> {
    /// Open a UDP tunnel to a **clearnet** `target` through the configured exit — the datagram counterpart
    /// of [`dial`](Self::dial). Datagrams ride an exit session ([`dial_exit_udp`](crate::exit::dial_exit_udp))
    /// as length framing on the DIAULOS stream, pumped both ways into the [`UdpTunnel`]'s channels. A
    /// `.fanos` target is [`Unsupported`](DialError::Unsupported) (services are byte streams, not datagram
    /// endpoints); without an exit, so is any clearnet UDP target.
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
        let stream = crate::exit::dial_exit_udp(
            self.client.clone(),
            *exit_coord,
            exit_public,
            &target.host(),
            target.port(),
            &mut rng,
        )
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
        let (in_tx, _in_rx) = unbounded_channel::<Vec<u8>>();
        let task = tokio::spawn(std::future::pending::<()>());
        Session {
            in_tx,
            task,
            last_active: Instant::now() - age,
        }
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
