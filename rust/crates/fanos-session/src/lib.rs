//! # fanos-session — async DIAULOS byte streams
//!
//! Turns a sans-I/O [`ClientSession`](fanos_diaulos::ClientSession) into a tokio
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
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

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
    /// Framed payloads to send to the peer.
    pub outbound: UnboundedSender<Vec<u8>>,
    /// Framed payloads received from the peer.
    pub inbound: UnboundedReceiver<Vec<u8>>,
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
    tokio::spawn(drive(session, driver_side, transport, tick));
    app_side
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
    tokio::spawn(drive(server, driver_side, transport, tick));
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
    let (out_tx, out_rx) = unbounded_channel();
    let (in_tx, in_rx) = unbounded_channel();
    tokio::spawn(bridge(transport, peer, out_rx, in_tx));
    stream_over_channels(
        session,
        ChannelTransport {
            outbound: out_tx,
            inbound: in_rx,
        },
    )
}

/// Bridge the channel transport to a coordinate-addressed overlay: outbound payloads go to `peer`;
/// deliveries from `peer` come back in.
async fn bridge<T: OverlayTransport>(
    mut transport: T,
    peer: Coord,
    mut out_rx: UnboundedReceiver<Vec<u8>>,
    in_tx: UnboundedSender<Vec<u8>>,
) {
    loop {
        tokio::select! {
            payload = out_rx.recv() => match payload {
                Some(p) => transport.send(peer, p),
                None => return,
            },
            delivery = transport.recv() => match delivery {
                Some((from, payload)) => {
                    if from == peer && in_tx.send(payload).is_err() {
                        return;
                    }
                }
                None => return,
            },
        }
    }
}

/// The sans-I/O session surface the async byte-stream [`drive`] loop needs. **Both** the dialing
/// ([`ClientSession`]) and accepting ([`ServerSession`]) sides implement it, so one driver runs a
/// full-duplex stream in either direction — a service handler gets the same `AsyncRead + AsyncWrite` a
/// client's dial does, and the flow-control / retransmit logic lives in exactly one place.
trait SessionStream: Send + 'static {
    /// The handshake has completed, so `write`/`finish` take effect (buffer app writes until then).
    fn is_live(&self) -> bool;
    /// Queue application bytes to send to the peer.
    fn write(&mut self, data: &[u8]);
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
    /// The datagram cells to transmit now (the whole send window; re-sent each call).
    fn poll_payloads(&mut self) -> Vec<Vec<u8>>;
    /// Fold a received datagram cell into the session.
    fn handle_payload(&mut self, payload: &[u8]);
}

impl SessionStream for ClientSession {
    fn is_live(&self) -> bool {
        ClientSession::is_live(self)
    }
    fn write(&mut self, data: &[u8]) {
        ClientSession::write(self, data);
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
    fn handle_payload(&mut self, payload: &[u8]) {
        ClientSession::handle_payload(self, payload);
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
    fn handle_payload(&mut self, payload: &[u8]) {
        self.server
            .handle_payload(&self.keypair, payload, &mut self.rng);
        // Latch the primary stream id once the handshake opens it.
        if self.stream_id.is_none() {
            self.stream_id = self.server.primary();
        }
    }
}

async fn drive<S: SessionStream>(
    mut session: S,
    driver_side: DuplexStream,
    transport: ChannelTransport,
    tick: Duration,
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
    // Emit outbound cells only when the send state actually changes — on startup (the ClientHello),
    // when the app hands us new data, after draining a *batch* of inbound datagrams, or on the
    // retransmit tick. `poll_payloads` re-sends the whole window each call, so emitting on *every*
    // inbound datagram would make one side's window retransmit per ack while the peer acks per cell —
    // a mutual, runaway amplification over an unbounded channel. Coalescing the inbound (drain all that
    // are ready, then emit once) collapses that to one emit per batch, so throughput is bounded by the
    // round trip, not by the tick, with no feedback storm.
    let mut emit = true;

    loop {
        // Once live, flush any buffered pre-handshake writes and propagate the app's close.
        if session.is_live() {
            if !pending.is_empty() {
                session.write(&pending);
                pending.clear();
                emit = true;
            }
            if app_eof && !finished {
                session.finish();
                finished = true;
                emit = true;
            }
        }
        if emit {
            for payload in session.poll_payloads() {
                if outbound.send(payload).is_err() {
                    return; // the transport is gone
                }
            }
            emit = false;
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
        if session.is_done() {
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
                    emit = true;
                }
                None => return, // peer transport closed
            },
            read = rd.read(&mut buf), if !app_eof => match read {
                Ok(0) => app_eof = true,
                Ok(n) => {
                    let chunk = buf.get(..n).unwrap_or(&[]);
                    if session.is_live() {
                        session.write(chunk);
                        emit = true; // new app data to send now
                    } else {
                        pending.extend_from_slice(chunk);
                    }
                }
                Err(_) => return,
            },
            _ = ticker.tick() => emit = true,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_diaulos::{ServerSession, StaticKeypair};
    use fanos_pqcrypto::rng::SeedRng;

    /// A minimal async service loop: drive a `ServerSession` over the mirror channels and answer the
    /// request (uppercased) once fully received — the loopback peer for the async-stream test.
    async fn serve_uppercase(
        keypair: StaticKeypair,
        outbound: UnboundedSender<Vec<u8>>,
        mut inbound: UnboundedReceiver<Vec<u8>>,
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
                if outbound.send(payload).is_err() {
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

    #[tokio::test]
    async fn request_response_through_the_async_stream() {
        let mut rng = SeedRng::from_seed(b"async-session-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"async-session-client");
        // The coordinate is unused by the channel transport (it addresses the single peer).
        let client = ClientSession::dial([0, 1, 0], keypair.public(), &mut crng);

        let (c2s_tx, c2s_rx) = unbounded_channel();
        let (s2c_tx, s2c_rx) = unbounded_channel();
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

    #[tokio::test]
    async fn a_full_duplex_service_streams_both_ways() {
        // The service side is now a DuplexStream via `serve_over_channels`, not an answer-once loop. Prove
        // it: the handler **talks first** — it writes a banner before any request arrives — then
        // stream-echoes each chunk uppercased. A request/response-only service cannot send before it has
        // read the whole request; this one can, so both directions are independent (full duplex).
        let mut rng = SeedRng::from_seed(b"duplex-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"duplex-client");
        let client = ClientSession::dial([0, 1, 0], keypair.public(), &mut crng);

        let (c2s_tx, c2s_rx) = unbounded_channel();
        let (s2c_tx, s2c_rx) = unbounded_channel();
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

    #[tokio::test]
    async fn dial_over_a_coordinate_addressed_transport() {
        let mut rng = SeedRng::from_seed(b"mock-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"mock-client");
        let session = ClientSession::dial(SERVICE, keypair.public(), &mut crng);
        assert_eq!(session.peer(), SERVICE);

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

    #[tokio::test]
    async fn a_large_payload_streams_through_the_async_stream() {
        // ~100 KB each way exercises the multi-cell path: the driver's READ_CHUNK loop, many
        // poll/handle rounds, the sliding window, and the retransmit tick — not just a single cell.
        let mut rng = SeedRng::from_seed(b"async-large-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"async-large-client");
        let client = ClientSession::dial([0, 1, 0], keypair.public(), &mut crng);

        let (c2s_tx, c2s_rx) = unbounded_channel();
        let (s2c_tx, s2c_rx) = unbounded_channel();
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

    #[tokio::test]
    async fn an_empty_request_completes_cleanly() {
        // The app closes its write side without sending a byte. The driver still propagates the finish
        // (an empty FIN stream), the service answers empty, and the client reads a clean EOF — no hang.
        let mut rng = SeedRng::from_seed(b"async-empty-key");
        let keypair = StaticKeypair::generate(&mut rng);
        let mut crng = SeedRng::from_seed(b"async-empty-client");
        let client = ClientSession::dial([0, 1, 0], keypair.public(), &mut crng);

        let (c2s_tx, c2s_rx) = unbounded_channel();
        let (s2c_tx, s2c_rx) = unbounded_channel();
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
}
