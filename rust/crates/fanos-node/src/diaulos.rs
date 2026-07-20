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
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_pqcrypto::rng::SeedRng;
use fanos_proxy::{DialError, Dialer, Target};
use fanos_quic::Client;
use fanos_runtime::{Command, Notification};
use fanos_session::{ChannelTransport, OverlayTransport, dial_over_transport, serve_over_channels};
use rand_core::CryptoRng;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::Arc;
use tokio::io::DuplexStream;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

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
        let mut peers: HashMap<Coord, UnboundedSender<Vec<u8>>> = HashMap::new();
        // A session task signals its client coordinate here when its handler completes, so the demux reaps
        // it — bounding the map to live clients (a step toward the audit-A4 back-pressure hygiene).
        let (done_tx, mut done_rx) = unbounded_channel::<Coord>();
        loop {
            tokio::select! {
                event = deliveries.recv() => match event {
                    Ok(Notification::Delivered { from, payload }) => {
                        // Spin up a session on first contact, or if the previous one finished (its inbound
                        // channel closed), so a reconnecting client starts clean.
                        if peers.get(&from).is_none_or(UnboundedSender::is_closed) {
                            let mut seed = [0u8; 32];
                            rng.fill_bytes(&mut seed);
                            let in_tx = spawn_client_session(
                                client.clone(),
                                keypair.clone(),
                                SeedRng::from_seed(&seed),
                                from,
                                handler.clone(),
                                done_tx.clone(),
                            );
                            peers.insert(from, in_tx);
                        }
                        if let Some(tx) = peers.get(&from) {
                            let _ = tx.send(payload);
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                reaped = done_rx.recv() => {
                    // Reap a finished session, but only if a reconnect has not already replaced it with a
                    // fresh (still-open) one — a race-free drop keyed on the sender being closed.
                    if let Some(from) = reaped
                        && peers.get(&from).is_some_and(UnboundedSender::is_closed)
                    {
                        peers.remove(&from);
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
) -> UnboundedSender<Vec<u8>>
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
    tokio::spawn(async move {
        handler(stream).await;
        let _ = done_tx.send(from);
    });
    in_tx
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
/// secrecy holds per connection. Non-`.fanos` targets are `Unsupported`.
pub struct FanosDialer<R: ServiceResolver> {
    client: Client,
    resolver: R,
    /// The rendezvous route for the **anonymous** profile; `None` selects the Direct profile (dial by
    /// coordinate). When set, dials carry the same DIAULOS session over threshold onions instead, so
    /// neither party learns the other's location.
    anonymous: Option<crate::rendezvous::RendezvousRoute>,
}

impl<R: ServiceResolver> FanosDialer<R> {
    /// A **Direct** dialer on `client`'s node resolving names through `resolver`: it reaches services
    /// by coordinate (fast, but reveals *where* each party is).
    #[must_use]
    pub fn new(client: Client, resolver: R) -> Self {
        Self {
            client,
            resolver,
            anonymous: None,
        }
    }

    /// An **anonymous** dialer: every dial rides threshold onions along `route` to the service's
    /// computed meeting line, hiding both parties' locations. `route` supplies the mixnet directory,
    /// threshold, epoch, and the client's forward/reply circuits (the per-target meeting line is
    /// derived from the resolved service key at dial time).
    #[must_use]
    pub fn anonymous(
        client: Client,
        resolver: R,
        route: crate::rendezvous::RendezvousRoute,
    ) -> Self {
        Self {
            client,
            resolver,
            anonymous: Some(route),
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
            return Err(DialError::Unsupported(
                "the FANOS dialer reaches only .fanos targets".to_owned(),
            ));
        }
        let host = target.host();
        let (coord, service_public) = self
            .resolver
            .resolve(&host)
            .await
            .ok_or(DialError::Unreachable)?;
        // A fresh CSPRNG seeded from OS entropy for this dial's ephemeral keys.
        let mut rng = SeedRng::from_seed(&os_entropy_32()?);
        match &self.anonymous {
            None => Ok(dial_service(
                self.client.clone(),
                coord,
                &service_public,
                &mut rng,
            )),
            Some(route) => {
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
        }
    }
}
