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
//! Each cookie's session is driven by the *same* [`serve_over_channels`] engine the Direct loop uses, so the
//! RFC 6298 retransmit clock (and its anti-livelock pacing) is inherited, not re-implemented — the reference
//! hand-rolled `poll_payloads`/`poll_new` split that a naive loop gets wrong lives inside that driver. The
//! one structural difference is the reply path: a session's outbound cells cannot be sealed inside its own
//! task, because sealing needs the single `RendezvousService` (its reply-route table and fresh per-onion
//! seeds). So every session funnels its outbound cells — tagged by cookie — to the central loop, which owns
//! the `RendezvousService` and does all sealing. The cookie→session map is [`MAX_SESSIONS`]-bounded and
//! idle-swept exactly like the Direct loop (audit A4), reusing [`Session`]/[`evict_lru`], so a flood of
//! distinct cookies or a wedged handler cannot grow it without bound.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use fanos_aphantos::nostos::ReplyKeys;
use fanos_diaulos::StaticKeypair;
use fanos_field::F2;
use fanos_pqcrypto::rng::SeedRng;
use fanos_quic::Client;
use fanos_rendezvous::{ANONYMOUS, MixDirectory, RendezvousService, SessionId};
use fanos_runtime::{Command, Notification};
use fanos_session::{ChannelTransport, serve_over_channels_paced};
use rand_core::CryptoRng;
use tokio::io::DuplexStream;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::diaulos::{MAX_SESSIONS, SESSION_IDLE_TIMEOUT, SESSION_SWEEP_INTERVAL, Session, evict_lru};

/// How many recent epochs' dead-drop [`ReplyKeys`] the accept loop keeps. The meeting combiner, the
/// dead-drop line, and the reply key all rotate with the beacon each epoch (§3b); a request forwarded just
/// before a rotation is sealed to the *previous* epoch's key, so the loop tries the last few keys, not only
/// the newest — enough to open across a boundary without unboundedly hoarding keys.
const MAX_REPLY_KEYS: usize = 3;

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
/// loop rings the new key (keeping the last [`MAX_REPLY_KEYS`], so a request forwarded across the boundary
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
        let (seal_tx, mut seal_rx) = unbounded_channel::<(SessionId, Vec<u8>)>();
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
                            );
                            sessions.insert(cookie, Session { in_tx, task, last_active: Instant::now() });
                        }
                        if let Some(session) = sessions.get_mut(&cookie) {
                            session.last_active = Instant::now();
                            let _ = session.in_tx.send(inner);
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
/// [`serve_rpc`](crate::diaulos::serve_rpc)): read the whole request (until the client half-closes), call
/// `handler(&request)`, write the response, and close. Streaming or full-duplex hidden services use
/// [`serve_anonymous`] directly.
pub fn serve_anonymous_rpc<R, H>(
    client: Client,
    keypair: StaticKeypair,
    rng: R,
    rservice: RendezvousService<F2>,
    reply_keys: Vec<ReplyKeys>,
    epoch_updates: Option<UnboundedReceiver<HostEpoch>>,
    handler: H,
) where
    R: CryptoRng + Send + 'static,
    H: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let wrap = move |mut stream: DuplexStream| {
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
    };
    serve_anonymous(client, keypair, rng, rservice, reply_keys, epoch_updates, wrap);
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
    seal_tx: UnboundedSender<(SessionId, Vec<u8>)>,
    done_tx: UnboundedSender<SessionId>,
) -> (UnboundedSender<Vec<u8>>, JoinHandle<()>)
where
    H: Fn(DuplexStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (in_tx, in_rx) = unbounded_channel::<Vec<u8>>();
    let (out_tx, mut out_rx) = unbounded_channel::<Vec<u8>>();
    // Outbound: this session's cells are funnelled to the central loop for sealing through its reply route.
    tokio::spawn(async move {
        while let Some(cell) = out_rx.recv().await {
            if seal_tx.send((cookie, cell)).is_err() {
                break; // the accept loop is gone; nothing left to seal through.
            }
        }
    });
    // Pace the server's retransmit clock to the mixnet's effective round trip — the SAME cadence the
    // client dials at ([`crate::rendezvous::RENDEZVOUS_TICK`]) — so replies do not flood the return path
    // faster than the per-hop threshold gathers can peel them (the anti-livelock discipline the reference
    // hand-rolled; here it is the shared paced session driver).
    let stream = serve_over_channels_paced(
        keypair,
        rng,
        ChannelTransport {
            outbound: out_tx,
            inbound: in_rx,
        },
        crate::rendezvous::RENDEZVOUS_TICK,
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
