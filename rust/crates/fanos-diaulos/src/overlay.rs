//! Running a DIAULOS session over the base overlay's **datagram** transport.
//!
//! The overlay moves opaque application payloads between coordinates
//! (`fanos_runtime::Command::Send { to, payload }` out, a delivered `{ from, payload }` in). DIAULOS
//! rides *on top* of that: its handshake messages and its constant-size cells travel as those
//! payloads. This module is the thin, sans-I/O adapter that binds a [`Connection`] to that transport
//! — it **produces** [`Command::Send`]s and **consumes** deliveries, so the very same session logic
//! runs under the simulator and the real QUIC driver (the monism).
//!
//! Each payload is tag-framed so the two message kinds are told apart on one datagram channel:
//! `HELLO` carries a handshake message (the `ClientHello` / `ServerHello`, larger than a cell) and
//! `CELL` carries one sealed [`crate::cell`]. The client retransmits its `ClientHello` until it sees
//! a `ServerHello`; the service caches and resends its single `ServerHello` for each `ClientHello` it
//! sees (re-accepting would derive fresh keys), so setup converges over a lossy datagram path.
//!
//! This is the **Direct** profile (no anonymity): the client addresses the service by coordinate.
//! The anonymous *rendezvous* path (a threshold meeting that hides the linkage) carries the same
//! `HELLO`/`CELL` payloads over an onion instead of a bare coordinate — a later layer.

use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_runtime::Command;
use rand_core::CryptoRng;

use crate::conn::Connection;
use crate::handshake::StaticKeypair;
use crate::session::{self, Dialed, PendingDial};

/// An overlay coordinate (the base cell address a payload is sent to).
pub type Coord = [u32; 3];

const TAG_HELLO: u8 = 0x01;
const TAG_CELL: u8 = 0x02;

fn framed(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(tag);
    v.extend_from_slice(body);
    v
}

fn unframe(payload: &[u8]) -> Option<(u8, &[u8])> {
    payload.split_first().map(|(&tag, rest)| (tag, rest))
}

/// The client half of a DIAULOS session over the overlay: dial a service by coordinate, complete the
/// 1-RTT handshake over datagrams, then carry a byte stream on the primary stream.
pub struct ClientSession {
    service: Coord,
    state: ClientState,
}

enum ClientState {
    /// Awaiting the `ServerHello`; `hello` is retransmitted each poll until it arrives.
    Handshaking {
        pending: PendingDial,
        hello: Vec<u8>,
    },
    /// Established: a live connection with its primary stream.
    Live { dialed: Dialed },
    /// The `ServerHello` was malformed — the session cannot proceed.
    Failed,
}

impl ClientSession {
    /// Dial `service` (its coordinate) using its static public key. The `ClientHello` is produced now
    /// and sent by the first [`poll_transmit`](Self::poll_transmit).
    #[must_use]
    pub fn dial<R: CryptoRng>(
        service: Coord,
        service_public: &HybridKemPublic,
        rng: &mut R,
    ) -> Self {
        let (pending, hello) = session::dial(service_public, rng);
        Self {
            service,
            state: ClientState::Handshaking { pending, hello },
        }
    }

    /// Dial `service` from its resolved identity `bundle` (a `.fanos` resolution). `None` if the
    /// bundle is malformed.
    #[must_use]
    pub fn dial_bundle<R: CryptoRng>(service: Coord, bundle: &[u8], rng: &mut R) -> Option<Self> {
        let (pending, hello) = session::dial_bundle(bundle, rng)?;
        Some(Self {
            service,
            state: ClientState::Handshaking { pending, hello },
        })
    }

    /// The framed payloads to send to the peer now (transport-agnostic): the (retransmitted)
    /// `ClientHello` while handshaking, then one framed cell each once live. A transport turns each
    /// into a datagram — a `Command::Send` to a coordinate (Direct), an onion to the rendezvous line
    /// (anonymous), or a channel write (an async stream driver).
    pub fn poll_payloads(&mut self) -> Vec<Vec<u8>> {
        match &mut self.state {
            ClientState::Handshaking { hello, .. } => vec![framed(TAG_HELLO, hello)],
            ClientState::Live { dialed } => dialed
                .conn
                .outbound()
                .iter()
                .map(|cell| framed(TAG_CELL, cell))
                .collect(),
            ClientState::Failed => Vec::new(),
        }
    }

    /// The overlay commands to send now — [`poll_payloads`](Self::poll_payloads) addressed to the
    /// service coordinate (the Direct-profile transport).
    pub fn poll_transmit(&mut self) -> Vec<Command> {
        let to = self.service;
        self.poll_payloads()
            .into_iter()
            .map(|payload| Command::Send { to, payload })
            .collect()
    }

    /// Ingest a payload from the peer (the transport has already resolved addressing). A `ServerHello`
    /// completes the handshake; a cell feeds the live connection.
    pub fn handle_payload(&mut self, payload: &[u8]) {
        let Some((tag, body)) = unframe(payload) else {
            return;
        };
        match (&self.state, tag) {
            (ClientState::Handshaking { .. }, TAG_HELLO) => {
                let prev = core::mem::replace(&mut self.state, ClientState::Failed);
                if let ClientState::Handshaking { pending, .. } = prev
                    && let Some(dialed) = pending.establish(body)
                {
                    self.state = ClientState::Live { dialed };
                }
            }
            (ClientState::Live { .. }, TAG_CELL) => {
                if let ClientState::Live { dialed } = &mut self.state {
                    dialed.conn.on_cell(body);
                }
            }
            _ => {}
        }
    }

    /// Ingest an overlay delivery — [`handle_payload`](Self::handle_payload) gated on the sender being
    /// the dialed service coordinate (deliveries from elsewhere are ignored).
    pub fn handle_delivery(&mut self, from: Coord, payload: &[u8]) {
        if from == self.service {
            self.handle_payload(payload);
        }
    }

    /// Append request bytes to the primary stream (no-op until live).
    pub fn write(&mut self, bytes: &[u8]) {
        if let ClientState::Live { dialed } = &mut self.state {
            let primary = dialed.primary;
            dialed.conn.write(primary, bytes);
        }
    }

    /// Close the primary send side (no-op until live).
    pub fn finish(&mut self) {
        if let ClientState::Live { dialed } = &mut self.state {
            let primary = dialed.primary;
            dialed.conn.finish(primary);
        }
    }

    /// Drain response bytes received on the primary stream.
    pub fn read(&mut self) -> Vec<u8> {
        match &mut self.state {
            ClientState::Live { dialed } => {
                let primary = dialed.primary;
                dialed.conn.read(primary)
            }
            _ => Vec::new(),
        }
    }

    /// The service coordinate this session dials (its datagram destination).
    #[must_use]
    pub fn peer(&self) -> Coord {
        self.service
    }

    /// Whether the handshake has completed.
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self.state, ClientState::Live { .. })
    }

    /// Whether the primary stream is complete in both directions.
    #[must_use]
    pub fn is_done(&self) -> bool {
        match &self.state {
            ClientState::Live { dialed } => dialed.conn.is_stream_done(dialed.primary),
            _ => false,
        }
    }
}

/// The service half of one client's session: accept a dial and carry the session over the overlay
/// datagram transport. Bound to one client (the first that hellos). The service identity
/// ([`StaticKeypair`]) is **not** owned here — it is passed by reference at accept time, so one
/// identity backs many concurrent [`ServerSession`]s (a real multi-client hidden service).
#[derive(Default)]
pub struct ServerSession {
    client: Option<Coord>,
    conn: Option<Connection>,
    /// The cached `ServerHello`, resent for each `ClientHello` (never re-accepted).
    server_hello: Option<Vec<u8>>,
    /// Set when a `ClientHello` arrives, cleared when the `ServerHello` is (re)sent this poll.
    resend_hello: bool,
    primary: Option<u32>,
}

impl ServerSession {
    /// A fresh, unbound service-side session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The framed payloads to send to the client now (transport-agnostic): the (re)sent `ServerHello`
    /// if a `ClientHello` just arrived, plus one framed cell each once a connection exists.
    pub fn poll_payloads(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.resend_hello {
            if let Some(hello) = &self.server_hello {
                out.push(framed(TAG_HELLO, hello));
            }
            self.resend_hello = false;
        }
        if let Some(conn) = &mut self.conn {
            for cell in conn.outbound() {
                out.push(framed(TAG_CELL, &cell));
            }
        }
        out
    }

    /// The overlay commands to send now — [`poll_payloads`](Self::poll_payloads) addressed to the
    /// bound client coordinate (the Direct-profile transport). Empty until a client has hello'd.
    pub fn poll_transmit(&mut self) -> Vec<Command> {
        match self.client {
            Some(client) => self
                .poll_payloads()
                .into_iter()
                .map(|payload| Command::Send {
                    to: client,
                    payload,
                })
                .collect(),
            None => Vec::new(),
        }
    }

    /// Ingest a payload from the client (the transport has resolved addressing). The first
    /// `ClientHello` derives the session (`accept`, using the service `keypair`); a repeat re-arms the
    /// `ServerHello` resend (never re-accepting); a cell feeds the connection.
    pub fn handle_payload<R: CryptoRng>(
        &mut self,
        keypair: &StaticKeypair,
        payload: &[u8],
        rng: &mut R,
    ) {
        let Some((tag, body)) = unframe(payload) else {
            return;
        };
        match tag {
            TAG_HELLO => {
                if self.conn.is_none()
                    && let Some((conn, hello)) = session::accept(keypair, body, rng)
                {
                    self.conn = Some(conn);
                    self.server_hello = Some(hello);
                }
                if self.server_hello.is_some() {
                    self.resend_hello = true;
                }
            }
            TAG_CELL => {
                if let Some(conn) = &mut self.conn {
                    conn.on_cell(body);
                    if self.primary.is_none() {
                        self.primary = conn.accept();
                    }
                }
            }
            _ => {}
        }
    }

    /// Ingest an overlay delivery. Binds the client coordinate on the first accepted `ClientHello`;
    /// once bound, deliveries from any other coordinate are ignored.
    pub fn handle_delivery<R: CryptoRng>(
        &mut self,
        keypair: &StaticKeypair,
        from: Coord,
        payload: &[u8],
        rng: &mut R,
    ) {
        if let Some(client) = self.client
            && from != client
        {
            return;
        }
        self.handle_payload(keypair, payload, rng);
        if self.client.is_none() && self.conn.is_some() {
            self.client = Some(from);
        }
    }

    /// The client's primary stream, once its first cell has arrived.
    #[must_use]
    pub fn primary(&self) -> Option<u32> {
        self.primary
    }

    /// Drain bytes received on `stream_id`.
    pub fn read(&mut self, stream_id: u32) -> Vec<u8> {
        self.conn
            .as_mut()
            .map_or_else(Vec::new, |c| c.read(stream_id))
    }

    /// Append response bytes to `stream_id`.
    pub fn write(&mut self, stream_id: u32, bytes: &[u8]) {
        if let Some(conn) = &mut self.conn {
            conn.write(stream_id, bytes);
        }
    }

    /// Close the send side of `stream_id`.
    pub fn finish(&mut self, stream_id: u32) {
        if let Some(conn) = &mut self.conn {
            conn.finish(stream_id);
        }
    }

    /// Whether `stream_id`'s inbound half is fully received.
    #[must_use]
    pub fn receiver_finished(&self, stream_id: u32) -> bool {
        self.conn
            .as_ref()
            .is_some_and(|c| c.receiver_finished(stream_id))
    }

    /// Whether `stream_id` is complete in both directions (request received, response acknowledged) —
    /// a multi-client service uses this to retire a finished session.
    #[must_use]
    pub fn is_stream_done(&self, stream_id: u32) -> bool {
        self.conn
            .as_ref()
            .is_some_and(|c| c.is_stream_done(stream_id))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_pqcrypto::rng::SeedRng;
    use fanos_runtime::Command;

    const CLIENT: Coord = [1, 0, 0];
    const SERVICE: Coord = [0, 1, 0];

    /// Extract the `(to, payload)` datagrams from a batch of commands (all are `Send` here).
    fn datagrams(cmds: Vec<Command>) -> Vec<(Coord, Vec<u8>)> {
        cmds.into_iter()
            .map(|c| match c {
                Command::Send { to, payload } => (to, payload),
                _ => panic!("session emits only Send"),
            })
            .collect()
    }

    #[test]
    fn request_response_over_the_overlay_datagram_transport() {
        let mut rng = SeedRng::from_seed(b"diaulos-overlay");
        let service_kp = StaticKeypair::generate(&mut rng);
        let mut client = ClientSession::dial(SERVICE, &service_kp.public, &mut rng);
        let mut server = ServerSession::new();
        let mut srng = SeedRng::from_seed(b"diaulos-overlay-server");

        let request = b"GET /index HTTP/1.0\r\n\r\n".to_vec();
        let mut wrote_request = false;
        let mut answered = false;
        for _round in 0..40 {
            // client → service
            for (to, payload) in datagrams(client.poll_transmit()) {
                assert_eq!(to, SERVICE);
                server.handle_delivery(&service_kp, CLIENT, &payload, &mut srng);
            }
            // Once live, the client writes its request exactly once.
            if client.is_live() && !wrote_request {
                client.write(&request);
                client.finish();
                wrote_request = true;
            }
            // The service answers once the whole request has arrived on the primary stream.
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
            // service → client
            for (to, payload) in datagrams(server.poll_transmit()) {
                assert_eq!(to, CLIENT);
                client.handle_delivery(SERVICE, &payload);
            }
            if client.is_done() {
                break;
            }
        }
        let response = client.read();
        let expected: Vec<u8> = request.iter().map(u8::to_ascii_uppercase).collect();
        assert_eq!(
            response, expected,
            "the service's response arrived over the overlay"
        );
        assert!(client.is_live(), "the handshake completed over datagrams");
    }

    #[test]
    fn a_wrong_coordinate_delivery_is_ignored() {
        let mut rng = SeedRng::from_seed(b"diaulos-overlay-2");
        let kp = StaticKeypair::generate(&mut rng);
        let mut client = ClientSession::dial(SERVICE, &kp.public, &mut rng);
        // A hello "from" the wrong coordinate must not complete the handshake.
        client.handle_delivery([9, 9, 9], &framed(TAG_HELLO, b"junk"));
        assert!(!client.is_live());
    }
}
