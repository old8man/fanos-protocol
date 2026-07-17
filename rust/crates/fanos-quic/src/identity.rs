//! Self-certifying identity: a node's overlay coordinate is bound to its TLS certificate.
//!
//! In the directory-trust model, a node claims a coordinate in a HELLO and the directory vouches
//! for the coordinate→address mapping. Self-certifying identity removes that trust: a node's
//! coordinate **is** `MapToPoint(H(cert))`, so the mutual-TLS handshake — which proves the peer
//! holds the certificate's private key — *authenticates the coordinate itself*. An impostor cannot
//! occupy a coordinate whose key it does not hold. The [`Directory`](crate::Directory) then serves
//! only address resolution (a hint for dialing), never identity.

use fanos_crypto::hash::label;
use fanos_crypto::map_to_point;
use fanos_field::Field;
use fanos_geometry::Point;
use quinn::Connection;
use rustls::pki_types::CertificateDer;

/// The self-certifying coordinate of a node from its certificate DER: `MapToPoint(H(cert))`.
#[must_use]
pub fn coordinate_from_cert<F: Field>(cert_der: &[u8]) -> Point<F> {
    map_to_point::<F>(label::NODE_ID, cert_der)
}

/// The peer's end-entity certificate DER from an established connection (its authenticated
/// identity), or `None` if the peer presented no certificate.
pub(crate) fn peer_cert_der(conn: &Connection) -> Option<Vec<u8>> {
    let identity = conn.peer_identity()?;
    let chain = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    chain.first().map(|cert| cert.as_ref().to_vec())
}
