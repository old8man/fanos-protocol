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
use fanos_geometry::{HierAddr, Point, derive_address};
use quinn::Connection;
use rustls::pki_types::CertificateDer;

/// The self-certifying coordinate of a node from its certificate DER: `MapToPoint(H(cert))`.
#[must_use]
pub fn coordinate_from_cert<F: Field>(cert_der: &[u8]) -> Point<F> {
    map_to_point::<F>(label::NODE_ID, cert_der)
}

/// The node's self-certifying point at descent `level` of the cell hierarchy (§L1). Level 0 is the
/// ordinary top-cell coordinate ([`coordinate_from_cert`]); each deeper level is a fresh, still
/// cert-bound point in the sub-cell, domain-separated by the level, so a node that collides can descend
/// to a coordinate it *earned* rather than shadow the occupant (§L0). Deterministic and unforgeable:
/// only the certificate's holder can produce its whole descent chain.
#[must_use]
pub fn coordinate_at_level<F: Field>(cert_der: &[u8], level: usize) -> Point<F> {
    if level == 0 {
        return coordinate_from_cert::<F>(cert_der);
    }
    let mut data = cert_der.to_vec();
    data.extend_from_slice(&(level as u64).to_be_bytes());
    map_to_point::<F>("FANOS-v1/subcell-coord", &data)
}

/// Resolve a node's **hierarchical address** by sub-cell descent (§L0/§L1): the shortest self-certifying
/// path whose full address `occupied` reports free. A node that does not collide gets a depth-1 address
/// equal to its ordinary coordinate; one that collides descends into a sub-cell it derives from its own
/// certificate. `None` only under an astronomically improbable run of collisions ([`MAX_DEPTH`]).
#[must_use]
pub fn hierarchical_coordinate<F: Field>(
    cert_der: &[u8],
    occupied: impl Fn(&[Point<F>]) -> bool,
) -> Option<HierAddr<F>> {
    derive_address(|level| coordinate_at_level::<F>(cert_der, level), occupied)
}

/// The peer's end-entity certificate DER from an established connection (its authenticated
/// identity), or `None` if the peer presented no certificate.
pub(crate) fn peer_cert_der(conn: &Connection) -> Option<Vec<u8>> {
    let identity = conn.peer_identity()?;
    let chain = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    chain.first().map(|cert| cert.as_ref().to_vec())
}
