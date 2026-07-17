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

use std::time::Duration;

use fanos_diaulos::ClientSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

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
    use tokio::sync::mpsc;

    /// A minimal async service loop: drive a `ServerSession` over the mirror channels and answer the
    /// request (uppercased) once fully received — the loopback peer for the async-stream test.
    async fn serve_uppercase(
        keypair: StaticKeypair,
        outbound: UnboundedSender<Vec<u8>>,
        mut inbound: UnboundedReceiver<Vec<u8>>,
    ) {
        let mut server = ServerSession::new(keypair);
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
                    Some(payload) => server.handle_payload(&payload, &mut rng),
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

        let (c2s_tx, c2s_rx) = mpsc::unbounded_channel();
        let (s2c_tx, s2c_rx) = mpsc::unbounded_channel();
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
}
