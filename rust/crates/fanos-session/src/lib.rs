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
use std::time::Duration;

use fanos_diaulos::{ClientSession, Coord};
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
    let (app_side, driver_side) = tokio::io::duplex(DUPLEX_BUF);
    tokio::spawn(drive(session, driver_side, transport));
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

async fn drive(mut session: ClientSession, driver_side: DuplexStream, transport: ChannelTransport) {
    let ChannelTransport {
        outbound,
        mut inbound,
    } = transport;
    let (mut rd, mut wr) = tokio::io::split(driver_side);
    let mut ticker = tokio::time::interval(TICK);
    let mut buf = vec![0u8; READ_CHUNK];
    let mut pending: Vec<u8> = Vec::new(); // app writes made before the session went live
    let mut app_eof = false; // the app closed its write side
    let mut finished = false; // we called session.finish()

    loop {
        // Once live, flush any buffered pre-handshake writes and propagate the app's close.
        if session.is_live() {
            if !pending.is_empty() {
                session.write(&pending);
                pending.clear();
            }
            if app_eof && !finished {
                session.finish();
                finished = true;
            }
        }
        // Emit outbound datagrams and deliver any received bytes to the app.
        for payload in session.poll_payloads() {
            if outbound.send(payload).is_err() {
                return; // the transport is gone
            }
        }
        let data = session.read();
        if !data.is_empty() && wr.write_all(&data).await.is_err() {
            return; // the app dropped its read side
        }
        if session.is_done() {
            let _ = wr.shutdown().await;
            return;
        }

        tokio::select! {
            biased;
            maybe = inbound.recv() => match maybe {
                Some(payload) => session.handle_payload(&payload),
                None => return, // peer transport closed
            },
            read = rd.read(&mut buf), if !app_eof => match read {
                Ok(0) => app_eof = true,
                Ok(n) => {
                    let chunk = buf.get(..n).unwrap_or(&[]);
                    if session.is_live() {
                        session.write(chunk);
                    } else {
                        pending.extend_from_slice(chunk);
                    }
                }
                Err(_) => return,
            },
            _ = ticker.tick() => {}
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
        loop {
            for payload in server.poll_payloads() {
                if outbound.send(payload).is_err() {
                    return;
                }
            }
            if let Some(sid) = server.primary()
                && !answered
                && server.receiver_finished(sid)
            {
                let req = server.read(sid);
                let resp: Vec<u8> = req.iter().map(u8::to_ascii_uppercase).collect();
                server.write(sid, &resp);
                server.finish(sid);
                answered = true;
            }
            tokio::select! {
                maybe = inbound.recv() => match maybe {
                    Some(payload) => server.handle_payload(&keypair, &payload, &mut rng),
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
        let client = ClientSession::dial([0, 1, 0], &keypair.public, &mut crng);

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
        loop {
            for payload in server.poll_payloads() {
                if outbound.send((SERVICE, payload)).is_err() {
                    return;
                }
            }
            if let Some(sid) = server.primary()
                && !answered
                && server.receiver_finished(sid)
            {
                let req = server.read(sid);
                let resp: Vec<u8> = req.iter().map(u8::to_ascii_uppercase).collect();
                server.write(sid, &resp);
                server.finish(sid);
                answered = true;
            }
            tokio::select! {
                msg = inbound.recv() => match msg {
                    Some((_from, payload)) => server.handle_payload(&keypair, &payload, &mut rng),
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
        let session = ClientSession::dial(SERVICE, &keypair.public, &mut crng);
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
}
