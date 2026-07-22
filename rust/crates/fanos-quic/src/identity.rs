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
use fanos_wire::capability::{Capabilities, PROTOCOL_VERSION, negotiate_version};
use fanos_wire::{FrameType, ProtocolError, decode_frame, encode_frame};
use quinn::Connection;
use rustls::pki_types::CertificateDer;
use x509_parser::asn1_rs::{FromDer, Oid};
use x509_parser::certificate::X509Certificate;

use crate::tls::{FANOS_VRF_OID, NodeCredentials};

/// The byte length of a self-certifying HELLO **frame body** (spec §7.3/§7.4):
/// `version(2) ‖ capabilities(4) ‖ field_q(4) ‖ epoch(8) ‖ coord(12) ‖ proof(80)`. The whole thing
/// is carried as the body of a [`FrameType::Hello`] frame (audit #100 — previously these bytes went
/// on the wire raw, with no version/capability negotiation and no frame envelope at all).
pub(crate) const HELLO_BODY_LEN: usize = 2 + 4 + 4 + 8 + 12 + PROOF_LEN;

/// The outcome of processing a peer's HELLO (spec §7.3/§7.4): either negotiation succeeded —
/// carrying the peer's certified coordinate and the AGREED (min version, intersected capability)
/// parameters both sides will operate at — or it failed for a specific protocol reason, which the
/// caller reports to the peer with an `ERROR` frame before aborting (spec state diagram:
/// `HELLO_SENT → CLOSED`). A bad coordinate **proof** is deliberately not a variant here: that
/// stays the unchanged silent drop (`None` from [`verify_hello`]) — an impostor is never told
/// exactly why its forged proof was rejected (spec §L0), whereas negotiation failure is an ordinary,
/// disclosable protocol condition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum HelloResult {
    /// Negotiation succeeded: the peer's certified coordinate and the agreed session parameters.
    Established {
        coord: Triple,
        version: u16,
        capabilities: Capabilities,
    },
    /// Negotiation failed (version too old, or an empty capability intersection) — the
    /// [`ProtocolError`] to report before aborting.
    Incompatible(ProtocolError),
}

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

/// Encode a self-certifying HELLO — the announcement a node sends on a fresh connection carrying
/// its negotiation parameters and its proof of coordinate (spec §7.3/§7.4): frame body
/// `version(2 BE) ‖ capabilities(4 BE) ‖ field_q(4 BE) ‖ epoch(8 BE) ‖ coord(12) ‖ proof(80)`,
/// wrapped as a [`FrameType::Hello`] frame. `field_q` is this node's plane order (`F::Q`) —
/// informational parity, not itself negotiated (an intersection is meaningless for a scalar order).
/// The peer verifies it — and negotiates against its own parameters — with [`verify_hello`].
#[must_use]
pub(crate) fn hello_bytes<F: Field>(
    epoch: Epoch,
    coord: Triple,
    proof: &VrfProof,
    capabilities: Capabilities,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(HELLO_BODY_LEN);
    body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&capabilities.bits().to_be_bytes());
    body.extend_from_slice(&F::Q.to_be_bytes());
    body.extend_from_slice(&epoch.get().to_be_bytes());
    body.extend_from_slice(&encode_triple(coord));
    body.extend_from_slice(&proof.to_bytes());
    let mut out = Vec::new();
    encode_frame(FrameType::Hello.code(), &body, &mut out);
    out
}

/// Parse a peer's HELLO, verify its coordinate proof against the peer's authenticated certificate
/// `peer_cert_der`, and negotiate the session parameters against `my_capabilities` (spec §7.3/§7.4).
///
/// The coordinate proof gate is unchanged from before negotiation existed: it binds the coordinate
/// to *this* certificate, so a replayed proof from another identity does not verify, and a bad
/// proof is a silent `None` (spec §L0 — an impostor is never told why). Only once the proof checks
/// out does negotiation run: `None` on a canonical-decode failure or a bad proof (silent drop, as
/// before); `Some(HelloResult::Incompatible(err))` on a version or capability mismatch (the caller
/// reports `err` and aborts); `Some(HelloResult::Established { .. })` otherwise.
///
/// `beacon` is the epoch's beacon seed ([`BeaconSeed::GENESIS`] at cold start).
#[must_use]
pub(crate) fn verify_hello<F: Field>(
    peer_cert_der: &[u8],
    hello: &[u8],
    beacon: &BeaconSeed,
    my_capabilities: Capabilities,
) -> Option<HelloResult> {
    let (frame, _) = decode_frame(hello).ok()?;
    if frame.frame_type() != Some(FrameType::Hello) {
        return None;
    }
    let body = frame.body;
    if body.len() != HELLO_BODY_LEN {
        return None;
    }
    let peer_version = u16::from_be_bytes(body.get(0..2)?.try_into().ok()?);
    let peer_capabilities =
        Capabilities::from_bits(u32::from_be_bytes(body.get(2..6)?.try_into().ok()?));
    // The peer's plane order is carried for informational parity; routing itself is decided by the
    // generic `F` this build is instantiated with, not by this value, so it is not gated here.
    let _peer_field_q = u32::from_be_bytes(body.get(6..10)?.try_into().ok()?);
    let epoch = Epoch::new(u64::from_be_bytes(body.get(10..18)?.try_into().ok()?));
    let coord = decode_triple(body.get(18..30)?)?;
    let proof = VrfProof::from_bytes(body.get(30..HELLO_BODY_LEN)?.try_into().ok()?)?;
    let point = Point::<F>::new(coord)?;
    if !verify_peer_coordinate::<F>(peer_cert_der, epoch, beacon, &point, &proof) {
        return None; // bad proof — silent drop, unchanged behaviour (spec §L0)
    }
    let Some(version) = negotiate_version(PROTOCOL_VERSION, peer_version) else {
        return Some(HelloResult::Incompatible(ProtocolError::Unsupported));
    };
    let capabilities = my_capabilities.intersect(peer_capabilities);
    if capabilities.is_empty() {
        return Some(HelloResult::Incompatible(ProtocolError::Unsupported));
    }
    Some(HelloResult::Established {
        coord,
        version,
        capabilities,
    })
}

/// Peek the epoch a HELLO proves its coordinate for, without verifying (the proof is bound to it). The
/// verifier uses this to select the matching epoch beacon from its accepted window — so a peer proving for
/// the current OR a recent last-good epoch is admitted rather than rejected as stale (audit R-C1 safe-stall).
/// `None` if the frame is not a well-formed HELLO.
#[must_use]
pub(crate) fn hello_epoch(hello: &[u8]) -> Option<Epoch> {
    let (frame, _) = decode_frame(hello).ok()?;
    if frame.frame_type() != Some(FrameType::Hello) {
        return None;
    }
    let body = frame.body;
    if body.len() != HELLO_BODY_LEN {
        return None;
    }
    Some(Epoch::new(u64::from_be_bytes(body.get(10..18)?.try_into().ok()?)))
}

/// The peer's end-entity certificate DER from an established connection (its authenticated
/// identity), or `None` if the peer presented no certificate.
pub(crate) fn peer_cert_der(conn: &Connection) -> Option<Vec<u8>> {
    let identity = conn.peer_identity()?;
    let chain = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    chain.first().map(|cert| cert.as_ref().to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::F2;

    /// Build a HELLO frame with an explicit `version` (unlike [`hello_bytes`], which always uses
    /// this build's [`PROTOCOL_VERSION`]) — the seam the version-incompatibility test needs to
    /// construct a peer that claims an older-than-supported version.
    fn hello_bytes_with_version<F: Field>(
        version: u16,
        epoch: Epoch,
        coord: Triple,
        proof: &VrfProof,
        capabilities: Capabilities,
    ) -> Vec<u8> {
        let mut body = Vec::with_capacity(HELLO_BODY_LEN);
        body.extend_from_slice(&version.to_be_bytes());
        body.extend_from_slice(&capabilities.bits().to_be_bytes());
        body.extend_from_slice(&F::Q.to_be_bytes());
        body.extend_from_slice(&epoch.get().to_be_bytes());
        body.extend_from_slice(&encode_triple(coord));
        body.extend_from_slice(&proof.to_bytes());
        let mut out = Vec::new();
        encode_frame(FrameType::Hello.code(), &body, &mut out);
        out
    }

    #[test]
    fn a_matching_hello_establishes_with_the_intersected_capabilities() {
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(1);
        let beacon = BeaconSeed::new([0x11; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);

        let sender_caps = Capabilities::CORE | Capabilities::APHANTOS_FULL | Capabilities::CALYPSO;
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &proof, sender_caps);

        // The receiver offers CORE + APHANTOS_FULL only (no CALYPSO) — the intersection drops it.
        let receiver_caps = Capabilities::CORE | Capabilities::APHANTOS_FULL;
        let result = verify_hello::<F2>(creds.cert_der(), &hello, &beacon, receiver_caps);
        assert_eq!(
            result,
            Some(HelloResult::Established {
                coord: coord.coords(),
                version: PROTOCOL_VERSION,
                capabilities: Capabilities::CORE | Capabilities::APHANTOS_FULL,
            }),
            "negotiates the true intersection, not either side's full offer"
        );
    }

    #[test]
    fn hello_epoch_reads_the_proven_epoch_for_the_safe_stall_window() {
        // The verifier peeks the epoch a HELLO proves so it can select that epoch's beacon from its accepted
        // window (safe-stall, R-C1) — a peer proving a recent last-good epoch is matched to the right beacon.
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(7);
        let beacon = BeaconSeed::new([0x77; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &proof, Capabilities::CORE);

        assert_eq!(hello_epoch(&hello), Some(epoch), "the proven epoch is recoverable without verifying");
        // Selecting that epoch's beacon, the proof verifies even after the cell has moved on — the essence of
        // safe-stall: an old-but-remembered epoch is admitted instead of being rejected as stale.
        assert!(
            matches!(
                verify_hello::<F2>(creds.cert_der(), &hello, &beacon, Capabilities::CORE),
                Some(HelloResult::Established { .. })
            ),
            "a proof for epoch 7 verifies against epoch 7's beacon"
        );
        assert_eq!(hello_epoch(b"not a hello frame"), None, "a non-HELLO yields no epoch");
    }

    #[test]
    fn a_minimal_peer_still_establishes_on_the_shared_core_baseline() {
        // Spec §7.4's own example: a DHT-only (CORE-only) peer interoperates with a full node — the
        // intersection is CORE, not empty, so this must NOT be Incompatible.
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(1);
        let beacon = BeaconSeed::new([0x12; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &proof, Capabilities::CORE);

        let full_node_caps =
            Capabilities::CORE | Capabilities::APHANTOS_FULL | Capabilities::CALYPSO;
        let result = verify_hello::<F2>(creds.cert_der(), &hello, &beacon, full_node_caps);
        assert_eq!(
            result,
            Some(HelloResult::Established {
                coord: coord.coords(),
                version: PROTOCOL_VERSION,
                capabilities: Capabilities::CORE,
            })
        );
    }

    #[test]
    fn disjoint_capabilities_are_reported_incompatible() {
        // Neither side advertises CORE nor anything the other offers — an empty intersection, the
        // genuine incompatibility condition (distinct from ordinary feature degradation).
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(1);
        let beacon = BeaconSeed::new([0x13; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &proof, Capabilities::APHANTOS_LITE);

        let result =
            verify_hello::<F2>(creds.cert_der(), &hello, &beacon, Capabilities::APHANTOS_FULL);
        assert_eq!(
            result,
            Some(HelloResult::Incompatible(ProtocolError::Unsupported))
        );
    }

    #[test]
    fn an_older_than_supported_version_is_reported_incompatible() {
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(1);
        let beacon = BeaconSeed::new([0x14; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);
        // Version 0 predates MIN_SUPPORTED_VERSION (1) — negotiate_version returns None.
        let hello =
            hello_bytes_with_version::<F2>(0, epoch, coord.coords(), &proof, Capabilities::CORE);

        let result = verify_hello::<F2>(creds.cert_der(), &hello, &beacon, Capabilities::CORE);
        assert_eq!(
            result,
            Some(HelloResult::Incompatible(ProtocolError::Unsupported)),
            "a too-old version is incompatible even though capabilities would have matched"
        );
    }

    #[test]
    fn a_bad_proof_is_still_a_silent_drop_not_an_incompatible_result() {
        // The pre-existing impostor-rejection behaviour is preserved exactly: a proof that does not
        // verify against the presented certificate yields `None`, never `Incompatible` — negotiation
        // is layered ON TOP of the proof check, never instead of it.
        let creds = NodeCredentials::generate().unwrap();
        let other = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(1);
        let beacon = BeaconSeed::new([0x15; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &proof, Capabilities::CORE);

        // Verify against a DIFFERENT certificate than the one the proof was produced for.
        let result = verify_hello::<F2>(other.cert_der(), &hello, &beacon, Capabilities::CORE);
        assert_eq!(result, None, "an impostor's HELLO is a silent drop");
    }

    #[test]
    fn a_short_or_wrongly_typed_frame_is_a_silent_drop() {
        let creds = NodeCredentials::generate().unwrap();
        let beacon = BeaconSeed::new([0x16; 32]);
        // Truncated body.
        let mut short = Vec::new();
        encode_frame(FrameType::Hello.code(), &[0u8; 10], &mut short);
        assert_eq!(
            verify_hello::<F2>(creds.cert_der(), &short, &beacon, Capabilities::CORE),
            None
        );
        // Right length, wrong frame type (e.g. a Ping).
        let mut wrong_type = Vec::new();
        encode_frame(FrameType::Ping.code(), &[0u8; HELLO_BODY_LEN], &mut wrong_type);
        assert_eq!(
            verify_hello::<F2>(creds.cert_der(), &wrong_type, &beacon, Capabilities::CORE),
            None
        );
    }

    #[test]
    fn a_real_hello_matches_the_documented_field_layout() {
        // Cross-checks a REAL `hello_bytes()` output (real cert, real VRF proof) against the same
        // byte layout `conformance/vectors/wire.json`'s `hello_handshake.hello` vector pins with an
        // opaque placeholder proof (fanos-wire has no VRF machinery to produce a real one). The KAT
        // fixes the field order/widths; this proves the actual encoder produces exactly that shape.
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(0x1122_3344_5566_7788);
        let beacon = BeaconSeed::new([0x17; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);
        let caps = Capabilities::CORE | Capabilities::CALYPSO;
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &proof, caps);

        let (frame, n) = decode_frame(&hello).unwrap();
        assert_eq!(n, hello.len(), "the frame consumes the whole buffer");
        assert_eq!(frame.frame_type(), Some(FrameType::Hello));
        let body = frame.body;
        assert_eq!(body.len(), HELLO_BODY_LEN);

        // version(2) ‖ capabilities(4) ‖ field_q(4) ‖ epoch(8) ‖ coord(12) ‖ proof(80), in that order.
        assert_eq!(
            u16::from_be_bytes(body[0..2].try_into().unwrap()),
            PROTOCOL_VERSION,
            "version at offset 0"
        );
        assert_eq!(
            u32::from_be_bytes(body[2..6].try_into().unwrap()),
            caps.bits(),
            "capabilities at offset 2"
        );
        assert_eq!(
            u32::from_be_bytes(body[6..10].try_into().unwrap()),
            F2::Q,
            "field_q at offset 6"
        );
        assert_eq!(
            u64::from_be_bytes(body[10..18].try_into().unwrap()),
            epoch.get(),
            "epoch at offset 10"
        );
        assert_eq!(
            decode_triple(&body[18..30]).unwrap(),
            coord.coords(),
            "coord at offset 18"
        );
        assert_eq!(
            body[30..HELLO_BODY_LEN].len(),
            PROOF_LEN,
            "proof at offset 30, PROOF_LEN bytes"
        );
    }

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
