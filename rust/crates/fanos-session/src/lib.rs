//! # fanos-session — async DIAULOS byte streams
//!
//! Turns a sans-I/O [`ClientSession`] into a tokio
//! [`AsyncRead`](tokio::io::AsyncRead) + [`AsyncWrite`](tokio::io::AsyncWrite) stream — the object a
//! SOCKS5 proxy hands to `copy_bidirectional`, or any async caller treats as a socket. A background
//! task bridges the stream to a **datagram channel transport**: framed DIAULOS payloads flow out on
//! `outbound` and in on `inbound`, and the task retransmits on a tick so setup and delivery converge
//! over a lossy datagram path. The transport is deliberately abstract — the same driver runs whether
//! those channels are wired to the overlay's `Command::Send`/deliveries (Direct) or to an anonymous
//! rendezvous circuit — so this is the one async bridge every profile reuses.
//!
//! The application writes request bytes and reads the response through the returned stream; the
//! driver buffers writes made before the 1-RTT handshake completes and flushes them once the session
//! is live, so a proxy can pipe immediately without racing the handshake.

#![forbid(unsafe_code)]

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use fanos_diaulos::{ClientSession, Coord, ServerSession, StaticKeypair};
use rand_core::CryptoRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::sync::oneshot;

/// The internal duplex buffer between the app and the driver.
const DUPLEX_BUF: usize = 64 * 1024;
/// The driver's retransmission / keep-alive tick.
const TICK: Duration = Duration::from_millis(20);
/// How many app bytes the driver reads per wake.
const READ_CHUNK: usize = 16 * 1024;

/// A datagram channel transport: framed DIAULOS payloads to the peer (`outbound`) and from it
/// (`inbound`). A Direct driver wires these to overlay `Command::Send`/deliveries; an anonymous
/// driver wires them to a rendezvous circuit.
pub struct ChannelTransport {
    /// Framed payloads to send to the peer. Bounded ([`ChannelTransport::CAP`]).
    pub outbound: Sender<Vec<u8>>,
    /// Framed payloads received from the peer. Bounded ([`ChannelTransport::CAP`]) — the inbound
    /// sender is fed by peer deliveries (adversary-reachable), so an unbounded queue is a
    /// single-peer memory-exhaustion DoS (audit A4b).
    pub inbound: Receiver<Vec<u8>>,
}

impl ChannelTransport {
    /// Depth of both datagram queues. The inbound side is fed by peer deliveries, so it must be
    /// bounded (audit A4b); the outbound side is bounded for symmetry (the loopback wiring uses one
    /// channel as one peer's outbound and the other's inbound, so both halves share a kind). A full
    /// queue **drops** the datagram rather than blocking — DIAULOS retransmits unacked cells, so a
    /// bounded lossy queue is the correct memory bound (and mirrors the overlay's own lossy
    /// delivery). The depth sits far above a healthy in-flight window (SACK width 64), so it never
    /// sheds under honest load; the FIFO drop engages only under a peer flood.
    pub const CAP: usize = 1024;
}

/// Drive a dialed [`ClientSession`] as an async duplex byte stream over `transport`. Returns the
/// application side (an `AsyncRead + AsyncWrite`); a spawned task owns the session and the transport.
///
/// Must be called from within a tokio runtime (it spawns the driver task).
#[must_use]
pub fn stream_over_channels(session: ClientSession, transport: ChannelTransport) -> DuplexStream {
    stream_over_channels_paced(session, transport, TICK)
}

/// Like [`stream_over_channels`] but with an explicit retransmit/keep-alive `tick`. A high-latency
/// transport — e.g. a multi-hop threshold-onion rendezvous, whose effective round trip dwarfs the base
/// `TICK` — must pace retransmits to that round trip, or the driver floods datagrams faster than they
/// can be acknowledged and saturates the path. Coordinate-addressed (Direct) transports use the base
/// tick via [`stream_over_channels`].
#[must_use]
pub fn stream_over_channels_paced(
    session: ClientSession,
    transport: ChannelTransport,
    tick: Duration,
) -> DuplexStream {
    let (app_side, driver_side) = tokio::io::duplex(DUPLEX_BUF);
    tokio::spawn(drive(session, driver_side, transport, tick, None));
    app_side
}

/// Like [`stream_over_channels_paced`], but also hands back a **liveness signal**: a receiver that resolves
/// `Ok(())` the moment the DIAULOS handshake completes, and `Err(_)` if the driver gives up first.
///
/// A caller that can *choose another path* needs to know whether this one came up, and a bare
/// [`DuplexStream`] cannot tell it: a session whose far end never answers looks exactly like one whose peer
/// simply has nothing to say yet, until the give-up rule finally closes it minutes later. The anonymous dialer
/// walks a service's meeting points precisely because any single one may be censored, and the walk is only as
/// good as its ability to tell "this meeting point is dead" from "this meeting point is quiet".
///
/// Both outcomes come from the one channel with no extra state: the sender fires on establishment, and is
/// dropped unfired when the driver exits any other way — so `Err` *is* the give-up, not a separate report that
/// could disagree with it.
#[must_use]
pub fn stream_over_channels_confirmed(
    session: ClientSession,
    transport: ChannelTransport,
    tick: Duration,
) -> (DuplexStream, oneshot::Receiver<()>) {
    let (app_side, driver_side) = tokio::io::duplex(DUPLEX_BUF);
    let (ready_tx, ready_rx) = oneshot::channel();
    tokio::spawn(drive(session, driver_side, transport, tick, Some(ready_tx)));
    (app_side, ready_rx)
}

/// Drive the **accepting** side of a DIAULOS session — a service answering one client — as an async
/// duplex byte stream over `transport`, returning the application side: the `AsyncRead + AsyncWrite` a
/// service handler reads the request from and writes the response to. It is exactly symmetric with
/// [`stream_over_channels`] on the client and shares the same driver, so a service is **full-duplex** — it
/// may read and write concurrently and stream in both directions, not merely answer once. `keypair` is the
/// service's static identity (it completes each client's handshake); `rng` seeds the handshake response.
///
/// `keypair` is shared (`Arc`) so one service identity backs many concurrent client sessions without ever
/// copying the secret. Must be called from within a tokio runtime (it spawns the driver task).
#[must_use]
pub fn serve_over_channels<R: CryptoRng + Send + 'static>(
    keypair: Arc<StaticKeypair>,
    rng: R,
    transport: ChannelTransport,
) -> DuplexStream {
    serve_over_channels_paced(keypair, rng, transport, TICK)
}

/// Like [`serve_over_channels`] but with an explicit retransmit/keep-alive `tick` — a high-latency
/// transport (e.g. an anonymous rendezvous circuit) must pace retransmits to its round trip, exactly as
/// [`stream_over_channels_paced`] does on the client side.
#[must_use]
pub fn serve_over_channels_paced<R: CryptoRng + Send + 'static>(
    keypair: Arc<StaticKeypair>,
    rng: R,
    transport: ChannelTransport,
    tick: Duration,
) -> DuplexStream {
    let (app_side, driver_side) = tokio::io::duplex(DUPLEX_BUF);
    let server = ServerStream {
        server: ServerSession::new(),
        keypair,
        rng,
        stream_id: None,
    };
    tokio::spawn(drive(server, driver_side, transport, tick, None));
    app_side
}

/// A coordinate-addressed datagram transport — the base overlay as the async stream sees it: send a
/// framed payload to a coordinate (like `Command::Send`), and await `(from, payload)` deliveries. A
/// production impl wraps the node's client; a test impl uses channels. The anonymous rendezvous is a
/// different impl of the same trait.
pub trait OverlayTransport: Send + 'static {
    /// Send `payload` to coordinate `to` (fire-and-forget).
    fn send(&self, to: Coord, payload: Vec<u8>);
    /// Await the next delivery `(from, payload)`; `None` once the transport closes.
    fn recv(&mut self) -> impl Future<Output = Option<(Coord, Vec<u8>)>> + Send;
}

/// Dial a `ClientSession` over a coordinate-addressed [`OverlayTransport`], returning the async byte
/// stream. Outbound payloads are `send`-t to the session's peer coordinate; deliveries *from* that
/// coordinate feed the session (others are ignored). Must run inside a tokio runtime.
#[must_use]
pub fn dial_over_transport<T: OverlayTransport>(
    session: ClientSession,
    transport: T,
) -> DuplexStream {
    let peer = session.peer();
    let (out_tx, out_rx) = channel(ChannelTransport::CAP);
    let (in_tx, in_rx) = channel(ChannelTransport::CAP);
    tokio::spawn(bridge(transport, peer, out_rx, in_tx));
    stream_over_channels(
        session,
        ChannelTransport {
            outbound: out_tx,
            inbound: in_rx,
        },
    )
}

/// Offer a datagram to a bounded transport channel; returns `true` to keep the driver loop running.
/// A **full** channel *drops* the datagram — the peer's DIAULOS layer retransmits unacked cells, so a
/// queue that sheds under a flood is exactly the audit-A4b memory bound (and mirrors the overlay's own
/// lossy delivery). A **closed** channel means the far end is gone, so the loop should stop.
/// Outbound payloads discarded because the transport channel was full, process-wide — see [`offer`].
static DROPPED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// How many outbound payloads this process has discarded for a full transport channel.
///
/// A diagnostic, not a control: `offer` cannot block (its caller also drives the inbound half, so waiting on a
/// full outbound channel would deadlock the session), so it drops — and DIAULOS's selective repeat is what makes
/// that survivable. The counter exists because "survivable in principle" and "recovered within the caller's
/// patience" are different claims, and only one of them can be measured. A payload loss observed at the
/// application level is a *retransmission* question exactly when this number moved, and something else entirely
/// when it did not.
#[must_use]
pub fn dropped_payloads() -> u64 {
    DROPPED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Offer a payload to the transport. `false` only when the channel is **closed** — a *full* channel discards the
/// payload and still reports success, because the caller cannot wait (see [`dropped_payloads`]).
fn offer(tx: &Sender<Vec<u8>>, payload: Vec<u8>) -> bool {
    match tx.try_send(payload) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            DROPPED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            true
        }
        Err(TrySendError::Closed(_)) => false,
    }
}

/// Bridge the channel transport to a coordinate-addressed overlay: outbound payloads go to `peer`;
/// deliveries from `peer` come back in.
async fn bridge<T: OverlayTransport>(
    mut transport: T,
    peer: Coord,
    mut out_rx: Receiver<Vec<u8>>,
    in_tx: Sender<Vec<u8>>,
) {
    loop {
        tokio::select! {
            payload = out_rx.recv() => match payload {
                Some(p) => transport.send(peer, p),
                None => return,
            },
            delivery = transport.recv() => match delivery {
                Some((from, payload)) => {
                    if from == peer && !offer(&in_tx, payload) {
                        return;
                    }
                }
                None => return,
            },
        }
    }
}

/// The sans-I/O session surface the async byte-stream `drive` loop needs. **Both** the dialing
/// ([`ClientSession`]) and accepting ([`ServerSession`]) sides implement it, so one driver runs a
/// full-duplex stream in either direction — a service handler gets the same `AsyncRead + AsyncWrite` a
/// client's dial does, and the flow-control / retransmit logic lives in exactly one place.
trait SessionStream: Send + 'static {
    /// The handshake has completed, so `write`/`finish` take effect (buffer app writes until then).
    fn is_live(&self) -> bool;
    /// Queue application bytes to send to the peer.
    fn write(&mut self, data: &[u8]);
    /// Seal any buffered partial (sub-segment) write so it is sent promptly, rather than held until it
    /// fills a whole segment or the stream is `finish`ed — what interactive streaming needs.
    fn flush(&mut self);
    /// Take the application bytes received from the peer.
    fn read(&mut self) -> Vec<u8>;
    /// Signal end-of-stream (FIN) to the peer.
    fn finish(&mut self);
    /// The stream is complete both ways.
    fn is_done(&self) -> bool;
    /// The **peer** has finished writing (its whole side is received + FIN'd), so the app's read half can
    /// EOF while this side keeps writing — a half-close, so a full-duplex handler learns the request ended
    /// and can then stream its response.
    fn peer_write_finished(&self) -> bool;
    /// The datagram cells to transmit now: the whole due send window (first sends, fast-retransmits,
    /// and anything past its RTO), plus a fresh ack. Ticks the session's retransmit clock (RFC 6298) —
    /// call this **only** at the driver's fixed retransmit cadence (the `tick` timer), never
    /// reactively; see [`poll_new`](Self::poll_new) for the reactive counterpart.
    fn poll_payloads(&mut self) -> Vec<Vec<u8>>;
    /// The cells to transmit **reactively** — right after handling new inbound data or a fresh app
    /// write, so the peer is acked/answered promptly — without ticking the retransmit clock: only
    /// never-before-sent data plus a fresh ack, never a retransmission. Safe to call any number of
    /// times between ticks; see [`poll_payloads`](Self::poll_payloads)'s doc for why that safety matters
    /// (a caller that also ticks the clock reactively can race it ahead of real time under load — the
    /// mechanism behind the anonymous-session retransmit-storm livelock this split exists to prevent).
    fn poll_new(&mut self) -> Vec<Vec<u8>>;
    /// Fold a received datagram cell into the session.
    fn handle_payload(&mut self, payload: &[u8]);
    /// How many times the most-retransmitted unacknowledged segment has been resent — TCP's `R2`
    /// statistic (RFC 1122 §4.2.3.5), which is how `drive` tells a peer that is **gone** from one
    /// that is merely slow. Zero while handshaking and for a stream whose window is fully acked.
    fn stalled_attempts(&self) -> u32;
}

impl SessionStream for ClientSession {
    fn is_live(&self) -> bool {
        ClientSession::is_live(self)
    }
    fn write(&mut self, data: &[u8]) {
        ClientSession::write(self, data);
    }
    fn flush(&mut self) {
        ClientSession::flush(self);
    }
    fn read(&mut self) -> Vec<u8> {
        ClientSession::read(self)
    }
    fn finish(&mut self) {
        ClientSession::finish(self);
    }
    fn is_done(&self) -> bool {
        ClientSession::is_done(self)
    }
    fn peer_write_finished(&self) -> bool {
        ClientSession::receiver_finished(self)
    }
    fn poll_payloads(&mut self) -> Vec<Vec<u8>> {
        ClientSession::poll_payloads(self)
    }
    fn poll_new(&mut self) -> Vec<Vec<u8>> {
        ClientSession::poll_new(self)
    }
    fn handle_payload(&mut self, payload: &[u8]) {
        ClientSession::handle_payload(self, payload);
    }
    fn stalled_attempts(&self) -> u32 {
        ClientSession::stalled_attempts(self)
    }
}

/// The accepting side of a session as a single duplex stream: a [`ServerSession`] driven through its
/// **primary** stream, carrying the service keypair and a CSPRNG to complete the client's handshake. Once
/// the client's `ClientHello` is folded in, `primary()` names the stream and the driver runs it exactly
/// like a dialed one — so a service handler reads the request and writes the response through the same
/// async stream, concurrently (full duplex), not answer-once.
struct ServerStream<R: CryptoRng + Send + 'static> {
    server: ServerSession,
    keypair: Arc<StaticKeypair>,
    rng: R,
    stream_id: Option<u32>,
}

impl<R: CryptoRng + Send + 'static> SessionStream for ServerStream<R> {
    fn is_live(&self) -> bool {
        self.stream_id.is_some()
    }
    fn write(&mut self, data: &[u8]) {
        if let Some(sid) = self.stream_id {
            self.server.write(sid, data);
        }
    }
    fn flush(&mut self) {
        if let Some(sid) = self.stream_id {
            self.server.flush(sid);
        }
    }
    fn read(&mut self) -> Vec<u8> {
        self.stream_id
            .map(|sid| self.server.read(sid))
            .unwrap_or_default()
    }
    fn finish(&mut self) {
        if let Some(sid) = self.stream_id {
            self.server.finish(sid);
        }
    }
    fn is_done(&self) -> bool {
        self.stream_id
            .is_some_and(|sid| self.server.is_stream_done(sid))
    }
    fn peer_write_finished(&self) -> bool {
        self.stream_id
            .is_some_and(|sid| self.server.receiver_finished(sid))
    }
    fn poll_payloads(&mut self) -> Vec<Vec<u8>> {
        self.server.poll_payloads()
    }
    fn poll_new(&mut self) -> Vec<Vec<u8>> {
        self.server.poll_new()
    }
    fn handle_payload(&mut self, payload: &[u8]) {
        self.server
            .handle_payload(&self.keypair, payload, &mut self.rng);
        // Latch the primary stream id once the handshake opens it.
        if self.stream_id.is_none() {
            self.stream_id = self.server.primary();
        }
    }
    fn stalled_attempts(&self) -> u32 {
        self.server.stalled_attempts()
    }
}

/// **`R2` — the retransmit count at which a session abandons its peer** (RFC 1122 §4.2.3.5), and the
/// answer to "how long does a dead session live".
///
/// Without it, nothing in the platform ever gave up: `drive` returned only on `is_done()` or a closed
/// transport, and a peer that has vanished satisfies neither — so both ends retransmitted at the tick
/// cadence *forever*, holding a session slot, a task, and (on a service) a handler each. A dropped client
/// stream produced exactly that, and the host's idle sweep could not reclaim it because inbound
/// retransmits kept refreshing the very timer meant to trip.
///
/// **The value is derived from the wall-clock RFC 1122 requires, not chosen for feel.** RFC 1122 sets the
/// floor at "at least 100 seconds" before a connection may be abandoned. Attempt `k` waits an RTO that
/// doubles until it saturates at `RTO_BACKOFF_MULT · base_rto = 4 · base_rto`
/// (`fanos_stream`), so `n` attempts take at least `(1 + 2 + 4 + 4 + … ) · base_rto` ticks — from the
/// third attempt on, `4·base_rto` each. With `n = 15` that is `≥ (1 + 2 + 13·4) = 55` base RTOs. At the
/// anonymous path's own cadence (`RENDEZVOUS_TICK`, the mixnet's effective round trip) a base RTO is
/// `≥ RTO_MIN_TICKS = 1` tick, and the shipped tick is hundreds of milliseconds, so 55 base RTOs clears
/// 100 s with margin on the slowest transport and lands far above any real recovery on the fastest.
///
/// It is also exactly Linux's `net.ipv4.tcp_retries2` default, which is the same constant answering the
/// same question against decades of deployment — matching it is evidence, not coincidence.
///
/// **This bounds only a peer that never acknowledges.** Every ack resets the count for what it covers, and
/// a SACKed hole is excluded (`StreamSender::stalled_attempts`),
/// so a live-but-lossy peer is never abandoned — only an absent one.
pub const GIVE_UP_ATTEMPTS: u32 = 15;

/// **How long an unanswered *handshake* is pursued** before the dial is abandoned — the second half of
/// the give-up rule, and deliberately a different quantity from [`GIVE_UP_ATTEMPTS`].
///
/// It cannot share that threshold, and the reason is measurable rather than stylistic. A `ClientHello`
/// is retransmitted on **every** poll with no RTO backoff (`ClientSession::poll_payloads`), so an
/// attempt count here means "consecutive ticks", not "exponentially spaced attempts". At the anonymous
/// profile's cadence (`RENDEZVOUS_TICK`, 250 ms) fifteen ticks is 3.75 s — while the censorship
/// scenario in `fanos-node/tests/anonymous_quic.rs` deliberately grants each dial **12 s**, because a
/// dial that draws a silenced member legitimately loses that round trip and self-heals on the next
/// reseal. Reusing the data-phase count would therefore abandon dials the system is in the middle of
/// recovering — converting a survivable path into a dead one, which is precisely the class of defect
/// this work exists to remove.
///
/// So the bound is a **duration**, scaled by the driver's own tick, and its value is RFC 1122
/// §4.2.3.5's own answer to this exact question: the standard requires `R2` for a connection-*opening*
/// segment to correspond to at least **3 minutes** — far longer than for established data, precisely
/// because "nobody answered yet" is weaker evidence of absence than "nobody acknowledged what they
/// were already exchanging". At 250 ms that is 720 unanswered round trips, 60× the granted per-dial
/// patience, so it can only fire on a peer that genuinely is not there.
const HANDSHAKE_GIVE_UP: Duration = Duration::from_secs(180);

/// What the next emit should do, if anything. `Tick` runs the full clock-ticking retransmit sweep
/// ([`SessionStream::poll_payloads`]); `Reactive` sends only genuinely new information — first-sent
/// data and a fresh ack — via [`SessionStream::poll_new`], which never advances the session's RTO
/// clock. `Tick` is a strict superset of what `Reactive` would send (a first send is always "due" in
/// `poll_payloads` too), so accumulating triggers within one loop pass keeps the stronger of the two
/// rather than the most recent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Emit {
    None,
    Reactive,
    Tick,
}

impl Emit {
    /// Record that reactive work is ready, without downgrading an already-pending `Tick`.
    fn mark_reactive(&mut self) {
        if *self == Emit::None {
            *self = Emit::Reactive;
        }
    }
}

async fn drive<S: SessionStream>(
    mut session: S,
    driver_side: DuplexStream,
    transport: ChannelTransport,
    tick: Duration,
    // Fired once, the first time the session goes live; dropped unfired on every other exit, so a caller
    // awaiting it learns "established" from `Ok` and "gave up" from `Err` without a second channel to
    // contradict the first ([`stream_over_channels_confirmed`]).
    mut ready: Option<oneshot::Sender<()>>,
) {
    let ChannelTransport {
        outbound,
        mut inbound,
    } = transport;
    let (mut rd, mut wr) = tokio::io::split(driver_side);
    let mut ticker = tokio::time::interval(tick);
    let mut buf = vec![0u8; READ_CHUNK];
    let mut pending: Vec<u8> = Vec::new(); // app writes made before the session went live
    let mut app_eof = false; // the app closed its write side
    let mut finished = false; // we called session.finish()
    let mut read_eof = false; // we signaled EOF to the app's read half (the peer finished writing)
    // Consecutive retransmit ticks spent still handshaking. Counted only on the tick (never reactively),
    // so it measures elapsed round trips rather than traffic volume — the handshake half of the give-up
    // rule ([`HANDSHAKE_GIVE_UP`]), which the data half cannot cover because an unanswered `ClientHello`
    // opens no stream and so accumulates no `R2` at all.
    let mut handshake_ticks: u32 = 0;
    // Emit outbound cells on startup, when the app hands us new data, after draining a *batch* of
    // inbound datagrams, or on the retransmit tick — but only the tick runs the clock-ticking
    // `poll_payloads` sweep (retransmission included); every other trigger is `Reactive` and calls the
    // non-ticking `poll_new` instead (first-sent data plus a fresh ack, never a resend). This split is
    // load-bearing: `poll_payloads`'s RTO estimator is calibrated in *calls*, one logical tick each, on
    // the assumption of a fixed calling cadence (RFC 6298). Calling it reactively too — once per inbound
    // datagram, coalesced or not — races that clock ahead of real time in proportion to traffic volume:
    // over a high-latency transport, inbound traffic includes the peer's own retransmissions, so more
    // reactive calls means a *faster* clock means a *shorter* effective RTO, right when backoff should
    // be growing it — a mutual retransmission-storm feedback loop between the two ends (the anonymous
    // real-QUIC session livelock this split exists to prevent), not the bounded, converging backoff RFC
    // 6298 promises. Coalescing a batch of inbound datagrams into one reactive emit is still worthwhile
    // (one ack for N deliveries, not N), but coalescing alone cannot fix a *cross-side* alternation —
    // only keeping the clock tick-exclusive does.
    let mut emit = Emit::Tick; // startup: send the first cells (ClientHello / initial segments)

    loop {
        // Once live, flush any buffered pre-handshake writes and propagate the app's close.
        if session.is_live() {
            if let Some(tx) = ready.take() {
                let _ = tx.send(()); // the caller may have stopped caring; that is not this driver's problem
            }
            if !pending.is_empty() {
                session.write(&pending);
                session.flush(); // seal the buffered partial so it ships now, not only on close
                pending.clear();
                emit.mark_reactive();
            }
            if app_eof && !finished {
                session.finish();
                finished = true;
                emit.mark_reactive();
            }
        }
        let payloads = match emit {
            Emit::Tick => session.poll_payloads(),
            Emit::Reactive => session.poll_new(),
            Emit::None => Vec::new(),
        };
        emit = Emit::None;
        for payload in payloads {
            if !offer(&outbound, payload) {
                return; // the transport is gone
            }
        }
        let data = session.read();
        if !data.is_empty() && wr.write_all(&data).await.is_err() {
            return; // the app dropped its read side
        }
        // Half-close: once the peer has finished writing, signal EOF to the app's read half — so a
        // full-duplex handler learns the request ended and can then stream its response — but keep this
        // side's write half open until the app finishes and both directions complete.
        if !read_eof && session.peer_write_finished() {
            let _ = wr.shutdown().await;
            read_eof = true;
        }
        // Done, or **abandoned**. A peer is abandoned on either of two disjoint pieces of evidence,
        // because a session can die in either phase and neither test can see the other:
        //
        // * **established** — it has not acknowledged through `R2` retransmissions ([`GIVE_UP_ATTEMPTS`]);
        // * **handshaking** — it has not answered the `ClientHello` for [`HANDSHAKE_GIVE_UP`], which the
        //   first test cannot detect at all, since no stream exists yet to accumulate retransmissions on.
        //
        // Every exit shuts the app's read half down, so a handler sees EOF and returns, its task
        // completes, and the accept loop reaps the session through machinery that already exists — the
        // ghost session (immortal, retransmitting at the tick cadence, holding a slot) cannot form.
        let handshake_abandoned =
            u64::from(handshake_ticks).saturating_mul(tick.as_millis().try_into().unwrap_or(u64::MAX))
                >= HANDSHAKE_GIVE_UP.as_millis().try_into().unwrap_or(u64::MAX);
        if session.is_done()
            || session.stalled_attempts() >= GIVE_UP_ATTEMPTS
            || handshake_abandoned
        {
            if !read_eof {
                let _ = wr.shutdown().await;
            }
            return;
        }

        tokio::select! {
            biased;
            maybe = inbound.recv() => match maybe {
                Some(payload) => {
                    // Coalesce: absorb this delivery and every other one already queued, then emit once
                    // (the ack for the whole batch plus any newly-unblocked segments). A burst of N
                    // deliveries costs one emit, not N.
                    session.handle_payload(&payload);
                    while let Ok(more) = inbound.try_recv() {
                        session.handle_payload(&more);
                    }
                    emit = Emit::Reactive;
                }
                None => return, // peer transport closed
            },
            read = rd.read(&mut buf), if !app_eof => match read {
                Ok(0) => app_eof = true,
                Ok(n) => {
                    let chunk = buf.get(..n).unwrap_or(&[]);
                    if session.is_live() {
                        session.write(chunk);
                        session.flush(); // seal the partial so a sub-segment write ships now, not on close
                        emit = Emit::Reactive; // new app data to send now
                    } else {
                        pending.extend_from_slice(chunk);
                    }
                }
                Err(_) => return,
            },
            _ = ticker.tick() => {
                // One elapsed round trip. While still handshaking it counts toward abandoning the dial;
                // going live resets it, so a slow-but-answering peer is never penalised for the wait.
                handshake_ticks = if session.is_live() { 0 } else { handshake_ticks.saturating_add(1) };
                emit = Emit::Tick;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    /// **The give-up window must admit enough attempts to be evidence of absence — measured, not claimed.**
    ///
    /// `HANDSHAKE_GIVE_UP` is a *duration*, while the `ClientHello` resend backs off in *polls*
    /// (`fanos_diaulos`). So how much evidence the window actually buys depends on the caller's tick, and the
    /// two crates cannot see each other's number — which is exactly how a claim about their product drifts.
    ///
    /// It already had: the backoff's own doc said "~22 attempts inside a 180 s give-up", hand-computed and
    /// wrong. Driving the real session says **27** at the anonymous profile's 250 ms poll, and **286** at the
    /// Direct profile's 20 ms one. Both are ample — the point is that neither was known, and a tenfold spread
    /// between two live profiles is not something a reader should have to rediscover.
    #[test]
    fn the_handshake_give_up_admits_enough_attempts_at_every_profile_tick() {
        fn hellos_within(tick: Duration) -> usize {
            let mut rng = SeedRng::from_seed(b"give-up-evidence");
            let keypair = StaticKeypair::generate(&mut rng);
            let mut session = ClientSession::dial([1, 0, 0], keypair.public(), &mut rng);
            let polls = HANDSHAKE_GIVE_UP.as_millis() / tick.as_millis().max(1);
            (0..polls).filter(|_| !session.poll_payloads().is_empty()).count()
        }

        // The anonymous profile's cadence (`fanos_node::rendezvous::RENDEZVOUS_TICK`), and the Direct one.
        let anonymous = hellos_within(Duration::from_millis(250));
        let direct = hellos_within(TICK);

        // Enough to be evidence: a handful of unanswered attempts is a lost packet, dozens is an absence.
        assert!(anonymous >= 16, "the anonymous profile must get real evidence of absence, got {anonymous}");
        assert!(direct >= anonymous, "a faster tick cannot buy less evidence: {direct} vs {anonymous}");

        // And bounded: the backoff exists so an unanswered handshake is not a flood, so the fastest profile
        // must still be far below one attempt per poll.
        let polls_direct = HANDSHAKE_GIVE_UP.as_millis() / TICK.as_millis();
        assert!(
            (direct as u128) * 8 < polls_direct,
            "the backoff must keep attempts far under one per poll: {direct} sends in {polls_direct} polls"
        );
    }


    use super::*;
    use fanos_diaulos::{ServerSession, StaticKeypair};
    use fanos_pqcrypto::rng::SeedRng;
    // The mock overlay network ((Coord, payload)) is test scaffolding, not the bounded datagram
    // transport under test, so it stays on unbounded channels.
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

    /// A minimal async service loop: drive a `ServerSession` over the mirror channels and answer the
    /// request (uppercased) once fully received — the loopback peer for the async-stream test.
    async fn serve_uppercase(
        keypair: StaticKeypair,
        outbound: Sender<Vec<u8>>,
        mut inbound: Receiver<Vec<u8>>,
    ) {
        let mut server = ServerSession::new();
        let mut rng = SeedRng::from_seed(b"async-session-server");
        let mut ticker = tokio::time::interval(TICK);
        let mut answered = false;
        let mut request = Vec::new();
        loop {
            if let Some(sid) = server.primary() {
                // Drain available request bytes every round so `delivered` advances and the receive
                // window slides. A bounded receiver (C3/F1) stalls the sender once its buffer fills, so
                // waiting for `receiver_finished` before the first read would deadlock any request larger
                // than the window — the flow-control contract is "drain to make progress".
                request.extend_from_slice(&server.read(sid));
                if !answered && server.receiver_finished(sid) {
                    let resp: Vec<u8> = request.iter().map(u8::to_ascii_uppercase).collect();
                    server.write(sid, &resp);
                    server.finish(sid);
                    answered = true;
                }
            }
            // One emit per wake (below): the inbound arm coalesces its whole batch first, so this is
            // one emit per batch or tick — never one per datagram.
            for payload in server.poll_payloads() {
                if !offer(&outbound, payload) {
                    return;
                }
            }
            tokio::select! {
                maybe = inbound.recv() => match maybe {
                    Some(payload) => {
                        server.handle_payload(&keypair, &payload, &mut rng);
                        while let Ok(more) = inbound.try_recv() {
                            server.handle_payload(&keypair, &more, &mut rng);
                        }
                    }
                    None => return,
                },
                _ = ticker.tick() => {}
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn request_response_through_the_async_stream() {
        let mut rng = SeedRng::from_seed(b"async-session-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"async-session-client");
        // The coordinate is unused by the channel transport (it addresses the single peer).
        let client = ClientSession::dial([0, 1, 0], keypair.public(), &mut crng);

        let (c2s_tx, c2s_rx) = channel(ChannelTransport::CAP);
        let (s2c_tx, s2c_rx) = channel(ChannelTransport::CAP);
        let mut stream = stream_over_channels(
            client,
            ChannelTransport {
                outbound: c2s_tx,
                inbound: s2c_rx,
            },
        );
        tokio::spawn(serve_uppercase(keypair, s2c_tx, c2s_rx));

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            stream.write_all(b"hello async").await.unwrap();
            stream.shutdown().await.unwrap(); // signal end-of-request
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            resp
        })
        .await
        .expect("the async request/response completed in time");

        assert_eq!(
            result, b"HELLO ASYNC",
            "response arrived through the async DIAULOS stream"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_full_duplex_service_streams_both_ways() {
        // The service side is now a DuplexStream via `serve_over_channels`, not an answer-once loop. Prove
        // it: the handler **talks first** — it writes a banner before any request arrives — then
        // stream-echoes each chunk uppercased. A request/response-only service cannot send before it has
        // read the whole request; this one can, so both directions are independent (full duplex).
        let mut rng = SeedRng::from_seed(b"duplex-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"duplex-client");
        let client = ClientSession::dial([0, 1, 0], keypair.public(), &mut crng);

        let (c2s_tx, c2s_rx) = channel(ChannelTransport::CAP);
        let (s2c_tx, s2c_rx) = channel(ChannelTransport::CAP);
        let mut client_stream = stream_over_channels(
            client,
            ChannelTransport {
                outbound: c2s_tx,
                inbound: s2c_rx,
            },
        );
        let server_stream = serve_over_channels(
            Arc::new(keypair),
            SeedRng::from_seed(b"duplex-server"),
            ChannelTransport {
                outbound: s2c_tx,
                inbound: c2s_rx,
            },
        );

        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(server_stream);
            wr.write_all(b"BANNER:").await.unwrap(); // talk first — buffered until the handshake is live
            let mut buf = vec![0u8; 4096];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) => {
                        let _ = wr.shutdown().await;
                        break;
                    }
                    Ok(n) => {
                        let up: Vec<u8> =
                            buf.get(..n).unwrap_or(&[]).iter().map(u8::to_ascii_uppercase).collect();
                        if wr.write_all(&up).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let result = tokio::time::timeout(Duration::from_secs(10), async {
            client_stream.write_all(b"hi").await.unwrap();
            client_stream.shutdown().await.unwrap();
            let mut resp = Vec::new();
            client_stream.read_to_end(&mut resp).await.unwrap();
            resp
        })
        .await
        .expect("the full-duplex exchange completed in time");
        assert_eq!(
            result, b"BANNER:HI",
            "the service's unsolicited banner and the streamed echo both arrived"
        );
    }

    const CLIENT: Coord = [1, 0, 0];
    const SERVICE: Coord = [0, 1, 0];

    /// A channel-backed [`OverlayTransport`] for the test: sends go to the mock network; deliveries
    /// come back from it.
    struct MockTransport {
        to_net: UnboundedSender<(Coord, Vec<u8>)>,
        from_net: UnboundedReceiver<(Coord, Vec<u8>)>,
    }

    impl OverlayTransport for MockTransport {
        fn send(&self, to: Coord, payload: Vec<u8>) {
            let _ = self.to_net.send((to, payload));
        }
        async fn recv(&mut self) -> Option<(Coord, Vec<u8>)> {
            self.from_net.recv().await
        }
    }

    /// The mock service: drive a `ServerSession` over the network channels, tagging replies with the
    /// service coordinate so the client's transport accepts them, and answer the request uppercased.
    async fn mock_service(
        keypair: StaticKeypair,
        mut inbound: UnboundedReceiver<(Coord, Vec<u8>)>,
        outbound: UnboundedSender<(Coord, Vec<u8>)>,
    ) {
        let mut server = ServerSession::new();
        let mut rng = SeedRng::from_seed(b"mock-svc");
        let mut ticker = tokio::time::interval(TICK);
        let mut answered = false;
        let mut request = Vec::new();
        loop {
            if let Some(sid) = server.primary() {
                // Drain available request bytes every round so `delivered` advances and the receive
                // window slides. A bounded receiver (C3/F1) stalls the sender once its buffer fills, so
                // waiting for `receiver_finished` before the first read would deadlock any request larger
                // than the window — the flow-control contract is "drain to make progress".
                request.extend_from_slice(&server.read(sid));
                if !answered && server.receiver_finished(sid) {
                    let resp: Vec<u8> = request.iter().map(u8::to_ascii_uppercase).collect();
                    server.write(sid, &resp);
                    server.finish(sid);
                    answered = true;
                }
            }
            for payload in server.poll_payloads() {
                if outbound.send((SERVICE, payload)).is_err() {
                    return;
                }
            }
            tokio::select! {
                msg = inbound.recv() => match msg {
                    Some((_from, payload)) => {
                        server.handle_payload(&keypair, &payload, &mut rng);
                        while let Ok((_from, more)) = inbound.try_recv() {
                            server.handle_payload(&keypair, &more, &mut rng);
                        }
                    }
                    None => return,
                },
                _ = ticker.tick() => {}
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dial_over_a_coordinate_addressed_transport() {
        let mut rng = SeedRng::from_seed(b"mock-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"mock-client");
        let session = ClientSession::dial(SERVICE, keypair.public(), &mut crng);
        assert_eq!(session.peer(), SERVICE);

        // The mock *network* carries (Coord, payload) and is test scaffolding, not the bounded
        // datagram transport under test — keep it unbounded so it never sheds in the test harness.
        let (c2s_tx, c2s_rx) = unbounded_channel();
        let (s2c_tx, s2c_rx) = unbounded_channel();
        let transport = MockTransport {
            to_net: c2s_tx,
            from_net: s2c_rx,
        };
        tokio::spawn(mock_service(keypair, c2s_rx, s2c_tx));

        let mut stream = dial_over_transport(session, transport);
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            stream.write_all(b"dial me").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            resp
        })
        .await
        .expect("the dial completed in time");
        assert_eq!(
            result, b"DIAL ME",
            "the response arrived over the coordinate transport"
        );
        let _ = CLIENT; // documents the client coordinate in this scenario
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_large_payload_streams_through_the_async_stream() {
        // ~100 KB each way exercises the multi-cell path: the driver's READ_CHUNK loop, many
        // poll/handle rounds, the sliding window, and the retransmit tick — not just a single cell.
        let mut rng = SeedRng::from_seed(b"async-large-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"async-large-client");
        let client = ClientSession::dial([0, 1, 0], keypair.public(), &mut crng);

        let (c2s_tx, c2s_rx) = channel(ChannelTransport::CAP);
        let (s2c_tx, s2c_rx) = channel(ChannelTransport::CAP);
        let mut stream = stream_over_channels(
            client,
            ChannelTransport {
                outbound: c2s_tx,
                inbound: s2c_rx,
            },
        );
        tokio::spawn(serve_uppercase(keypair, s2c_tx, c2s_rx));

        let request: Vec<u8> = (0..100_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        let expected: Vec<u8> = request.iter().map(u8::to_ascii_uppercase).collect();
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            stream.write_all(&request).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            resp
        })
        .await
        .expect("the large transfer completed in time");
        assert_eq!(
            result, expected,
            "the whole payload streamed through, uppercased"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_empty_request_completes_cleanly() {
        // The app closes its write side without sending a byte. The driver still propagates the finish
        // (an empty FIN stream), the service answers empty, and the client reads a clean EOF — no hang.
        let mut rng = SeedRng::from_seed(b"async-empty-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"async-empty-client");
        let client = ClientSession::dial([0, 1, 0], keypair.public(), &mut crng);

        let (c2s_tx, c2s_rx) = channel(ChannelTransport::CAP);
        let (s2c_tx, s2c_rx) = channel(ChannelTransport::CAP);
        let mut stream = stream_over_channels(
            client,
            ChannelTransport {
                outbound: c2s_tx,
                inbound: s2c_rx,
            },
        );
        tokio::spawn(serve_uppercase(keypair, s2c_tx, c2s_rx));

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            stream.shutdown().await.unwrap(); // no write at all
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            resp
        })
        .await
        .expect("the empty request completed in time");
        assert!(
            result.is_empty(),
            "an empty request yields an empty response, cleanly"
        );
    }
    /// **A sub-segment write is never lost across the session + reliable-stream pair.** 200 rounds of the exact
    /// shape that fails elsewhere: dial, write 23 bytes, flush, read on the peer.
    ///
    /// It exists as the deterministic half of a live investigation. The C ABI's host test loses that payload about
    /// 2 runs in 10 — the client's write returns its full count, `offer` reports zero drops, and the host's read
    /// finds nothing within 5 s. A failure here would have indicted these two crates; 200 clean rounds indict what
    /// is *below* them instead, which is what makes this worth keeping rather than deleting: it is the boundary
    /// marker for the next investigation, and a regression that moves the fault up into these crates will trip it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sub_segment_write_is_never_lost_across_the_session_pair() {
        const ROUNDS: usize = 200;
        for round in 0..ROUNDS {
            let mut rng = SeedRng::from_seed(b"loss-key");
            let keypair = StaticKeypair::generate(&mut rng);
            let mut crng = SeedRng::from_seed(b"loss-client");
            let client = ClientSession::dial([0, 1, 0], keypair.public(), &mut crng);
            let (c2s_tx, c2s_rx) = channel(ChannelTransport::CAP);
            let (s2c_tx, s2c_rx) = channel(ChannelTransport::CAP);
            let mut client_stream = stream_over_channels(
                client,
                ChannelTransport { outbound: c2s_tx, inbound: s2c_rx },
            );
            let mut server_stream = serve_over_channels(
                Arc::new(keypair),
                SeedRng::from_seed(b"loss-server"),
                ChannelTransport { outbound: s2c_tx, inbound: c2s_rx },
            );
            // Exactly the shape the C ABI test uses: a sub-segment write, then the peer reads it.
            let msg = b"c-abi service host echo";
            client_stream.write_all(msg).await.unwrap();
            client_stream.flush().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(5), server_stream.read(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("round {round}: nothing arrived within 5 s"))
                .unwrap();
            assert_eq!(buf.get(..n), Some(&msg[..]), "round {round}: wrong payload");
        }
    }

    /// A peer that completes the handshake and then **goes silent while still holding the channels
    /// open** — the shape a vanished far end actually has on the wire. Dropping the channels instead
    /// would close the transport and end the session through an entirely different path, proving
    /// nothing about the give-up rule.
    async fn serve_then_vanish(
        keypair: StaticKeypair,
        outbound: Sender<Vec<u8>>,
        mut inbound: Receiver<Vec<u8>>,
    ) {
        let mut server = ServerSession::new();
        let mut rng = SeedRng::from_seed(b"vanishing-server");
        // Answer exactly the handshake: poll once per inbound datagram until the session is established,
        // then stop responding forever while keeping `outbound`/`inbound` alive.
        while server.primary().is_none() {
            match inbound.recv().await {
                Some(payload) => {
                    server.handle_payload(&keypair, &payload, &mut rng);
                    for out in server.poll_payloads() {
                        if !offer(&outbound, out) {
                            return;
                        }
                    }
                }
                None => return,
            }
        }
        // Vanish: hold both channel ends (so the transport stays open) and never answer again.
        std::future::pending::<()>().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_whose_peer_vanishes_ends_instead_of_retransmitting_forever() {
        // **The ghost session.** Before this, nothing in the platform ever gave up: `drive` returned only
        // on `is_done()` or a closed transport, and a peer that has stopped answering satisfies neither.
        // A dropped stream therefore left both ends retransmitting at the tick cadence *indefinitely*,
        // each holding a task — and on a service, a session slot and a handler with it.
        //
        // The property asserted is the one an operator cares about: **the session ENDS**. It is asserted
        // before any mechanism, so removing the give-up rule fails here rather than in some counter check
        // that would never be reached.
        //
        // The peer is modelled as answering the handshake and then going silent with the channels still
        // open, which is what a far end that has gone away looks like: cells keep going out, nothing
        // acknowledges them, and `R2` climbs exactly as it would in production.
        let mut rng = SeedRng::from_seed(b"ghost-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"ghost-client");
        let client = ClientSession::dial([0, 1, 0], keypair.public(), &mut crng);

        let (c2s_tx, c2s_rx) = channel(ChannelTransport::CAP);
        let (s2c_tx, s2c_rx) = channel(ChannelTransport::CAP);
        let mut stream = stream_over_channels_paced(
            client,
            ChannelTransport { outbound: c2s_tx, inbound: s2c_rx },
            TICK,
        );
        tokio::spawn(serve_then_vanish(keypair, s2c_tx, c2s_rx));

        // Write and close the write half — the shape a client takes when its caller goes away mid-flow.
        stream.write_all(b"anyone still there?").await.unwrap();
        stream.shutdown().await.unwrap();

        // The driver must hang up on its own. `read_to_end` returns only once `drive` shuts the read
        // half, which here cannot happen via `is_done()` (nothing is ever acked) — only via the give-up
        // rule. The bound is generous but finite: R2 = 15 backed-off attempts at a 20 ms tick is a few
        // seconds, and "forever" is what this is distinguishing it from.
        let mut sink = Vec::new();
        let ended = tokio::time::timeout(Duration::from_secs(60), stream.read_to_end(&mut sink)).await;
        assert!(
            ended.is_ok(),
            "a session whose peer stops answering must END, not retransmit forever — that is the ghost \
             session, and it holds a task (and on a service a session slot and a handler) for as long \
             as it lives"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_live_peer_is_never_abandoned_by_the_give_up_rule() {
        // The other half, and the one that makes the rule safe to have: the give-up threshold must be
        // reachable ONLY by a peer that has genuinely stopped acknowledging. A working request/response
        // — which retransmits under this crate's own pacing — must complete untouched.
        //
        // Without this, "make sessions mortal" could be satisfied by a rule that also kills live ones,
        // which would be a far worse defect than the ghost it replaced.
        let mut rng = SeedRng::from_seed(b"live-peer-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"live-peer-client");
        let client = ClientSession::dial([0, 1, 0], keypair.public(), &mut crng);

        let (c2s_tx, c2s_rx) = channel(ChannelTransport::CAP);
        let (s2c_tx, s2c_rx) = channel(ChannelTransport::CAP);
        let mut stream = stream_over_channels_paced(
            client,
            ChannelTransport { outbound: c2s_tx, inbound: s2c_rx },
            TICK,
        );
        tokio::spawn(serve_uppercase(keypair, s2c_tx, c2s_rx));

        let result = tokio::time::timeout(Duration::from_secs(10), async {
            stream.write_all(b"still here").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            resp
        })
        .await
        .expect("a live peer completes — the give-up rule must not fire on it");
        assert_eq!(result, b"STILL HERE", "and the answer is intact");
    }

}
