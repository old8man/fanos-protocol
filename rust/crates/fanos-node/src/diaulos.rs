//! DIAULOS sessions over the node's overlay transport — the client dial and a service accept path.
//!
//! The base overlay moves datagrams by coordinate (`Command::Send` / `Notification::Delivered`); this
//! module rides a reliable, encrypted, hybrid-PQ [DIAULOS](fanos_diaulos) session on top, exposing it
//! as an async byte stream. [`NodeTransport`] adapts a node [`Client`] to the
//! [`OverlayTransport`](fanos_session::OverlayTransport) the async stream driver expects;
//! [`dial_service`] is the client side (what a SOCKS5 proxy calls); [`serve_one`] is a minimal
//! single-client service accept loop. This is the **Direct** profile — the anonymous rendezvous is a
//! different transport under the identical stream.

use fanos_diaulos::{ClientSession, Coord, ServerSession, StaticKeypair};
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_quic::Client;
use fanos_runtime::{Command, Notification};
use fanos_session::{OverlayTransport, dial_over_transport};
use rand_core::CryptoRng;
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

/// Serve a **single** client request/response over DIAULOS on `client`'s node, answering with
/// `handler(request)`. Spawns a background task bound to the first client that connects; returns
/// immediately. (A full multi-client hidden service is a follow-up — it needs the service identity
/// shared across sessions by reference rather than owned here.)
pub fn serve_one<R, H>(client: Client, keypair: StaticKeypair, mut rng: R, handler: H)
where
    R: CryptoRng + Send + 'static,
    H: Fn(&[u8]) -> Vec<u8> + Send + 'static,
{
    tokio::spawn(async move {
        let mut server = ServerSession::new(keypair);
        let mut deliveries = client.subscribe();
        let mut ticker = tokio::time::interval(SERVE_TICK);
        let mut peer: Option<Coord> = None;
        let mut answered = false;
        loop {
            if let Some(to) = peer {
                for payload in server.poll_payloads() {
                    client.command(Command::Send { to, payload });
                }
            }
            if let Some(sid) = server.primary()
                && !answered
                && server.receiver_finished(sid)
            {
                let response = handler(&server.read(sid));
                server.write(sid, &response);
                server.finish(sid);
                answered = true;
            }
            tokio::select! {
                event = deliveries.recv() => match event {
                    Ok(Notification::Delivered { from, payload }) => {
                        let bound = *peer.get_or_insert(from);
                        if bound == from {
                            server.handle_payload(&payload, &mut rng);
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
