//! Self-certifying identity: a node's overlay coordinate is bound to its TLS certificate.
//!
//! In the directory-trust model, a node claims a coordinate in a HELLO and the directory vouches
//! for the coordinate→address mapping. Self-certifying identity removes that trust: a node's
//! coordinate **is** `MapToPoint(H(cert))`, so the mutual-TLS handshake — which proves the peer
//! holds the certificate's private key — *authenticates the coordinate itself*. An impostor cannot
//! occupy a coordinate whose key it does not hold. The [`Directory`](crate::Directory) then serves
//! only address resolution (a hint for dialing), never identity.

use fanos_field::Field;
use fanos_geometry::{HierAddr, Point, Triple, decode_triple, derive_address, encode_triple};
use fanos_primitives::hash::label;
use fanos_primitives::{BeaconSeed, Epoch, map_to_point};
use fanos_vrf::{PROOF_LEN, VrfProof, VrfPublic, prove_coordinate, verify_coordinate};
use quinn::Connection;
use rustls::pki_types::CertificateDer;
use x509_parser::asn1_rs::{FromDer, Oid};
use x509_parser::certificate::X509Certificate;

use crate::tls::{FANOS_VRF_OID, NodeCredentials};

/// The byte length of a self-certifying HELLO: `epoch(8) ‖ coord(12) ‖ proof(80)`.
pub(crate) const HELLO_PROOF_LEN: usize = 8 + 12 + PROOF_LEN;

/// The self-certifying coordinate of a node from its certificate DER: `MapToPoint(H(cert))`.
#[must_use]
pub fn coordinate_from_cert<F: Field>(cert_der: &[u8]) -> Point<F> {
    map_to_point::<F>(label::NODE_ID, cert_der)
}

/// This node's **verifiable** coordinate for (`epoch`, `beacon`) and the proof that certifies it:
/// `MapToPoint(VRF(vrf_sk, cert_der ‖ epoch ‖ beacon))` (spec §L0/§L3). The node's own certificate DER is
/// the identity anchor the VRF binds to — and it commits the VRF public (embedded), so the proof cannot be
/// transplanted onto another certificate. Use [`BeaconSeed::GENESIS`] at cold start; the coordinate
/// reshuffles unpredictably as the beacon advances, so it cannot be pre-aimed (§3.2 assumptions 1–2).
#[must_use]
pub fn verifiable_coordinate<F: Field>(
    creds: &NodeCredentials,
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> (Point<F>, VrfProof) {
    prove_coordinate::<F>(&creds.vrf_secret(), creds.cert_der(), epoch, beacon)
}

/// The coordinate-VRF public key embedded in a certificate, or `None` if the certificate is unparsable or
/// carries no [`FANOS_VRF_OID`] extension. Read from a peer's *authenticated* certificate to check its
/// coordinate proof.
#[must_use]
pub fn vrf_public_from_cert(cert_der: &[u8]) -> Option<VrfPublic> {
    let want = Oid::from(FANOS_VRF_OID).ok()?;
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let ext = cert.extensions().iter().find(|e| e.oid == want)?;
    let bytes: [u8; 32] = ext.value.try_into().ok()?;
    VrfPublic::from_bytes(bytes)
}

/// Verify a peer's claimed `coord` for (`epoch`, `beacon`) against its authenticated certificate: extract
/// the VRF public embedded in `peer_cert_der`, then check `verify_coordinate` with the certificate DER as
/// the identity anchor. Because the coordinate is bound to *this* certificate, a valid proof for one
/// identity does not verify against another's certificate — so a peer cannot claim a coordinate it did not
/// earn. `false` if the certificate carries no VRF key or the proof does not check out (`BAD_COORD`).
#[must_use]
pub fn verify_peer_coordinate<F: Field>(
    peer_cert_der: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    coord: &Point<F>,
    proof: &VrfProof,
) -> bool {
    match vrf_public_from_cert(peer_cert_der) {
        Some(vrf_public) => {
            verify_coordinate::<F>(&vrf_public, peer_cert_der, epoch, beacon, coord, proof)
        }
        None => false,
    }
}

/// The node's self-certifying point at descent `level` of the cell hierarchy (§L1). Level 0 is the
/// ordinary top-cell coordinate ([`coordinate_from_cert`]); each deeper level is a fresh, still
/// cert-bound point in the sub-cell, domain-separated by the level, so a node that collides can descend
/// to a coordinate it *earned* rather than shadow the occupant (§L0). Deterministic and unforgeable:
/// only the certificate's holder can produce its whole descent chain. Delegates to the shared
/// derivation [`fanos_primitives::address_point`] (the single source of truth) with the certificate DER as
/// the node identity — so the overlay's announcement verifier recomputes byte-identical points.
#[must_use]
pub fn coordinate_at_level<F: Field>(cert_der: &[u8], level: usize) -> Point<F> {
    fanos_primitives::address_point::<F>(cert_der, level)
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

/// Encode a self-certifying HELLO — the announcement a node sends on a fresh connection to prove its
/// coordinate: `epoch(8 BE) ‖ coord(12) ‖ proof(80)`. The peer verifies it against this node's
/// authenticated certificate with [`verify_hello`].
#[must_use]
pub(crate) fn hello_bytes(epoch: Epoch, coord: Triple, proof: &VrfProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(HELLO_PROOF_LEN);
    out.extend_from_slice(&epoch.get().to_be_bytes());
    out.extend_from_slice(&encode_triple(coord));
    out.extend_from_slice(&proof.to_bytes());
    out
}

/// Parse a peer's HELLO and verify its coordinate proof against the peer's authenticated certificate
/// `peer_cert_der`, returning the **certified** coordinate or `None`. This is the authenticated identity
/// step for a VRF coordinate (spec §7.3): the proof binds the coordinate to *this* certificate, so a
/// replayed proof from another identity does not verify. `beacon` is the epoch's beacon seed
/// ([`BeaconSeed::GENESIS`] at cold start).
#[must_use]
pub(crate) fn verify_hello<F: Field>(
    peer_cert_der: &[u8],
    hello: &[u8],
    beacon: &BeaconSeed,
) -> Option<Triple> {
    if hello.len() != HELLO_PROOF_LEN {
        return None;
    }
    let epoch = Epoch::new(u64::from_be_bytes(hello.get(0..8)?.try_into().ok()?));
    let coord = decode_triple(hello.get(8..20)?)?;
    let proof = VrfProof::from_bytes(hello.get(20..HELLO_PROOF_LEN)?.try_into().ok()?)?;
    let point = Point::<F>::new(coord)?;
    verify_peer_coordinate::<F>(peer_cert_der, epoch, beacon, &point, &proof).then_some(coord)
}

/// The peer's end-entity certificate DER from an established connection (its authenticated
/// identity), or `None` if the peer presented no certificate.
pub(crate) fn peer_cert_der(conn: &Connection) -> Option<Vec<u8>> {
    let identity = conn.peer_identity()?;
    let chain = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    chain.first().map(|cert| cert.as_ref().to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::F2;

    #[test]
    fn vrf_coordinate_round_trips_and_binds_to_the_certificate() {
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(3);
        let beacon = BeaconSeed::new([0x2C; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);

        // The certificate embeds exactly the VRF public derived from the cert's private key.
        assert_eq!(
            vrf_public_from_cert(creds.cert_der()).unwrap().to_bytes(),
            creds.vrf_secret().public().to_bytes(),
            "the certificate embeds the node's coordinate-VRF public key"
        );
        // The node's own proof verifies against its own certificate.
        assert!(
            verify_peer_coordinate::<F2>(creds.cert_der(), epoch, &beacon, &coord, &proof),
            "a node's coordinate proof verifies against its own certificate"
        );
        // Epoch- and beacon-bound: a different epoch or beacon rejects the same proof.
        assert!(!verify_peer_coordinate::<F2>(
            creds.cert_der(),
            Epoch::new(4),
            &beacon,
            &coord,
            &proof
        ));
        assert!(!verify_peer_coordinate::<F2>(
            creds.cert_der(),
            epoch,
            &BeaconSeed::new([0x99; 32]),
            &coord,
            &proof
        ));
        // Binding / no impersonation: another node's certificate rejects this proof — a coordinate proof
        // cannot be transplanted onto a different identity, so the handshake needs no live challenge.
        let other = NodeCredentials::generate().unwrap();
        assert!(
            !verify_peer_coordinate::<F2>(other.cert_der(), epoch, &beacon, &coord, &proof),
            "a proof does not verify against another certificate"
        );
    }
}
