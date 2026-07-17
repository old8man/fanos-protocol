//! Dialing and accepting a DIAULOS session — the handshake wrapped into a ready [`Connection`].
//!
//! This is the ergonomic entry point a proxy (SOCKS5 → `.fanos`) or a hidden service uses: one call
//! to start the 1-RTT handshake, one to finish it into a live connection with a primary stream
//! already opened. The handshake messages (`ClientHello`/`ServerHello`) and the connection's cells
//! are carried by the caller's transport — the rendezvous circuit — so this layer stays pure and
//! transport-agnostic, exactly like the rest of the sans-I/O core.
//!
//! Lifecycle:
//! ```text
//!   client: (pending, client_hello) = dial(service_public)
//!           ── client_hello ──▶  service: (conn, server_hello) = accept(keypair, client_hello)
//!           ◀── server_hello ──                    │ conn.accept() surfaces the client's stream
//!           Dialed { conn, primary } = pending.establish(server_hello)
//! ```

use fanos_pqcrypto::kem::HybridKemPublic;
use rand_core::CryptoRng;

use crate::conn::Connection;
use crate::handshake::{
    ClientHandshake, ServerHandshake, StaticKeypair, service_public_from_bundle,
};

/// A dial in flight: the `ClientHello` has been produced; hold this until the `ServerHello` arrives,
/// then [`establish`](PendingDial::establish) it.
pub struct PendingDial {
    handshake: ClientHandshake,
}

/// A client's established session: a live [`Connection`] and the primary stream opened on it.
pub struct Dialed {
    /// The multiplexed, end-to-end-encrypted connection.
    pub conn: Connection,
    /// The primary stream id (opened by the dial — write the request here, open more as needed).
    pub primary: u32,
}

/// Begin dialing a service by its static public key ([`HybridKemPublic`], from its ONOMA descriptor).
/// Returns the pending dial and the `ClientHello` bytes to deliver to the service (via the
/// rendezvous).
#[must_use]
pub fn dial<R: CryptoRng>(service_public: &HybridKemPublic, rng: &mut R) -> (PendingDial, Vec<u8>) {
    let (handshake, hello) = ClientHandshake::start(service_public, rng);
    (PendingDial { handshake }, hello)
}

/// Begin dialing straight from a service's canonical identity bundle (the `bundle` a `.fanos`
/// resolution yields) — [`service_public_from_bundle`] then [`dial`]. `None` if the bundle is
/// malformed. This is the one call a proxy makes after resolving a `.fanos` name.
#[must_use]
pub fn dial_bundle<R: CryptoRng>(bundle: &[u8], rng: &mut R) -> Option<(PendingDial, Vec<u8>)> {
    let service_public = service_public_from_bundle(bundle)?;
    Some(dial(&service_public, rng))
}

impl PendingDial {
    /// Finish the dial from the received `ServerHello`: derive keys, build the connection, and open
    /// the primary stream. `None` if the `ServerHello` is malformed.
    #[must_use]
    pub fn establish(self, server_hello: &[u8]) -> Option<Dialed> {
        let keys = self.handshake.finish(server_hello)?;
        let mut conn = keys.client_connection();
        let primary = conn.open_stream();
        Some(Dialed { conn, primary })
    }
}

/// Accept a dial on the service side: respond to a `ClientHello` with the service identity. Returns
/// the live [`Connection`] and the `ServerHello` bytes to send back, or `None` if the hello is
/// malformed. The client's primary stream surfaces via [`Connection::accept`] once its first cell
/// arrives.
#[must_use]
pub fn accept<R: CryptoRng>(
    keypair: &StaticKeypair,
    client_hello: &[u8],
    rng: &mut R,
) -> Option<(Connection, Vec<u8>)> {
    let (keys, server_hello) = ServerHandshake::respond(keypair, client_hello, rng)?;
    Some((keys.server_connection(), server_hello))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::rng::SeedRng;

    #[test]
    fn dial_accept_request_response_round_trip() {
        let mut rng = SeedRng::from_seed(b"diaulos-session");
        let service = StaticKeypair::generate(&mut rng);

        // Client dials; service accepts; client establishes — the 1-RTT handshake.
        let (pending, client_hello) = dial(&service.public, &mut rng);
        let (mut svc_conn, server_hello) =
            accept(&service, &client_hello, &mut rng).expect("valid client hello");
        let Dialed { mut conn, primary } = pending
            .establish(&server_hello)
            .expect("valid server hello");

        // Client sends a request on the primary stream; service echoes it back uppercased.
        let request = b"GET /index.html HTTP/1.1\r\n\r\n".to_vec();
        conn.write(primary, &request);
        conn.finish(primary);

        let mut svc_stream: Option<u32> = None;
        let mut got_request = Vec::new();
        let mut got_response = Vec::new();
        for _ in 0..20 {
            for cell in conn.outbound() {
                svc_conn.on_cell(&cell);
            }
            if svc_stream.is_none() {
                svc_stream = svc_conn.accept();
            }
            if let Some(sid) = svc_stream {
                got_request.extend_from_slice(&svc_conn.read(sid));
                if svc_conn.receiver_finished(sid) {
                    // Respond once we have the whole request.
                    let response: Vec<u8> =
                        got_request.iter().map(u8::to_ascii_uppercase).collect();
                    svc_conn.write(sid, &response);
                    svc_conn.finish(sid);
                }
            }
            for cell in svc_conn.outbound() {
                conn.on_cell(&cell);
            }
            got_response.extend_from_slice(&conn.read(primary));
            if conn.is_stream_done(primary) {
                break;
            }
        }
        got_response.extend_from_slice(&conn.read(primary));

        assert_eq!(
            svc_stream,
            Some(primary),
            "service's accepted stream is the primary"
        );
        assert_eq!(got_request, request, "service received the request");
        let expected: Vec<u8> = request.iter().map(u8::to_ascii_uppercase).collect();
        assert_eq!(got_response, expected, "client received the response");
    }

    #[test]
    fn establish_rejects_a_malformed_server_hello() {
        let mut rng = SeedRng::from_seed(b"diaulos-session-bad");
        let service = StaticKeypair::generate(&mut rng);
        let (pending, _hello) = dial(&service.public, &mut rng);
        assert!(pending.establish(&[0u8; 8]).is_none());
    }
}
