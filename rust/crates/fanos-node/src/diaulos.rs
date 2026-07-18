//! DIAULOS sessions over the node's overlay transport — the client dial and a service accept path.
//!
//! The base overlay moves datagrams by coordinate (`Command::Send` / `Notification::Delivered`); this
//! module rides a reliable, encrypted, hybrid-PQ [DIAULOS](fanos_diaulos) session on top, exposing it
//! as an async byte stream. [`NodeTransport`] adapts a node [`Client`] to the
//! [`OverlayTransport`](fanos_session::OverlayTransport) the async stream driver expects;
//! [`dial_service`] / [`FanosDialer`] are the client side (what a SOCKS5 proxy calls); [`serve`] is
//! the multi-client service accept loop. This is the **Direct** profile — the anonymous rendezvous is
//! a different transport under the identical stream.

use fanos_diaulos::{ClientSession, Coord, ServerSession, StaticKeypair};
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_pqcrypto::rng::SeedRng;
use fanos_proxy::{DialError, Dialer, Target};
use fanos_quic::Client;
use fanos_runtime::{Command, Notification};
use fanos_session::{OverlayTransport, dial_over_transport};
use rand_core::CryptoRng;
use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::sync::broadcast;

/// The service accept loop's poll/retransmit tick.
const SERVE_TICK: Duration = Duration::from_millis(20);

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

/// One in-flight client session at the service, plus its primary stream and whether it was answered.
#[derive(Default)]
struct ClientState {
    session: ServerSession,
    primary: Option<u32>,
    answered: bool,
    /// The request bytes drained so far. Accumulated **incrementally** (not read only at FIN), so the
    /// receiver buffer keeps freeing and its `rwnd` recovers — otherwise a request larger than one recv
    /// window never `receiver_finished`s (buffer full ⇒ rwnd 0 ⇒ sender stalls) and the exchange
    /// deadlocks (audit #66 service-duplex; same fix the sans-I/O test service loop already carries).
    request: Vec<u8>,
}

/// Run a **multi-client** DIAULOS request/response service on `client`'s node: one [`ServerSession`]
/// per client coordinate, each answered with `handler(request)`, retiring a session once its exchange
/// completes both ways. A single service `keypair` (the identity) backs every client — passed by
/// reference, so no per-client key clone. Spawns a background task and returns immediately.
pub fn serve<R, H>(client: Client, keypair: StaticKeypair, mut rng: R, handler: H)
where
    R: CryptoRng + Send + 'static,
    H: Fn(&[u8]) -> Vec<u8> + Send + 'static,
{
    tokio::spawn(async move {
        let mut deliveries = client.subscribe();
        let mut sessions: BTreeMap<Coord, ClientState> = BTreeMap::new();
        let mut ticker = tokio::time::interval(SERVE_TICK);
        loop {
            let mut retire: Vec<Coord> = Vec::new();
            for (&peer, st) in &mut sessions {
                if st.primary.is_none() {
                    st.primary = st.session.primary();
                }
                if let Some(sid) = st.primary {
                    if !st.answered {
                        // Drain the delivered prefix EVERY tick (freeing the receiver window), and answer
                        // once the whole request has arrived — never blocking the first read on FIN.
                        st.request.extend_from_slice(&st.session.read(sid));
                        if st.session.receiver_finished(sid) {
                            let response = handler(&st.request);
                            st.session.write(sid, &response);
                            st.session.finish(sid);
                            st.answered = true;
                        }
                    }
                    if st.answered && st.session.is_stream_done(sid) {
                        retire.push(peer);
                    }
                }
            }
            // One emit per wake: the delivery arm below coalesces its whole ready batch before looping,
            // so this re-sends each session's window once per batch or tick, never once per datagram
            // (which would make the two sides amplify each other's retransmits without bound).
            for (&peer, st) in &mut sessions {
                for payload in st.session.poll_payloads() {
                    client.command(Command::Send { to: peer, payload });
                }
            }
            for peer in retire {
                sessions.remove(&peer);
            }
            tokio::select! {
                event = deliveries.recv() => match event {
                    Ok(Notification::Delivered { from, payload }) => {
                        sessions
                            .entry(from)
                            .or_default()
                            .session
                            .handle_payload(&keypair, &payload, &mut rng);
                        // Coalesce the rest of the ready batch, then emit once for all of them.
                        while let Ok(ev) = deliveries.try_recv() {
                            if let Notification::Delivered { from, payload } = ev {
                                sessions
                                    .entry(from)
                                    .or_default()
                                    .session
                                    .handle_payload(&keypair, &payload, &mut rng);
                            }
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                _ = ticker.tick() => {}
            }
        }
    });
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
    pub fn anonymous(client: Client, resolver: R, route: crate::rendezvous::RendezvousRoute) -> Self {
        Self {
            client,
            resolver,
            anonymous: Some(route),
        }
    }
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
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| DialError::Io(std::io::Error::other(format!("OS entropy failed: {e}"))))?;
        let mut rng = SeedRng::from_seed(&seed);
        match &self.anonymous {
            None => Ok(dial_service(
                self.client.clone(),
                coord,
                &service_public,
                &mut rng,
            )),
            Some(route) => {
                // A separate OS-entropy secret seeds this session's cookie + per-onion key material.
                let mut secret = [0u8; 32];
                getrandom::fill(&mut secret).map_err(|e| {
                    DialError::Io(std::io::Error::other(format!("OS entropy failed: {e}")))
                })?;
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
