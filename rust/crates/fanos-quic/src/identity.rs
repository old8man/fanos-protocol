//! Self-certifying identity: a node's overlay coordinate is bound to its TLS certificate.
//!
//! In the directory-trust model, a node claims a coordinate in a HELLO and the directory vouches
//! for the coordinate→address mapping. Self-certifying identity removes that trust: a node's
//! coordinate **is** `MapToPoint(H(cert))`, so the mutual-TLS handshake — which proves the peer
//! holds the certificate's private key — *authenticates the coordinate itself*. An impostor cannot
//! occupy a coordinate whose key it does not hold. The [`Directory`](crate::Directory) then serves
//! only address resolution (a hint for dialing), never identity.

use fanos_field::Field;
use fanos_geometry::{HierAddr, Point, TRIPLE_WIRE_LEN, Triple, decode_triple, derive_address, encode_triple};
use fanos_primitives::hash::label;
use fanos_primitives::{BeaconSeed, Epoch, map_to_point};
use fanos_vrf::{CoordinateClaim, PROOF_LEN, VrfProof, VrfPublic, prove_coordinate, verify_coordinate};
use fanos_wire::capability::{Capabilities, PROTOCOL_VERSION, negotiate_version};
use fanos_wire::{FrameType, ProtocolError, decode_frame, encode_frame};
use quinn::Connection;
use rustls::pki_types::CertificateDer;
use x509_parser::asn1_rs::{FromDer, Oid};
use x509_parser::certificate::X509Certificate;

use crate::tls::{FANOS_VRF_OID, NodeCredentials};

/// The fixed head of a self-certifying HELLO **frame body** (spec §7.3/§7.4):
/// `version(2) ‖ capabilities(4) ‖ field_q(4) ‖ epoch(8) ‖ listen_port(2) ‖ coord(12)`, followed by the
/// node's [`CoordinateClaim`]. The whole thing is carried as the body of a [`FrameType::Hello`] frame
/// (audit #100 — previously these bytes went on the wire raw, with no version/capability negotiation and no
/// frame envelope at all).
///
/// ## Why a port and not an address
///
/// The acceptor needs *somewhere to dial this peer back*, and before this field it had nothing: the source
/// address of an inbound connection is an ephemeral client port, so `accept_loop` deliberately wrote no
/// directory entry at all and reverse reachability rested entirely on the accepted connection staying open.
/// Measured consequence on a five-node fleet: `route [1, 2, 3, 4, 5]` — a staircase in *bootstrap order*,
/// because a node only ever learned an address by dialing out, and the node that dials nobody learns
/// nothing, permanently.
///
/// Carrying a full `SocketAddr` would answer that and open two holes this does not. A node bound to
/// `0.0.0.0` does not know which of its addresses to advertise, and — the sharper one — an advertised IP is
/// a claim about a *third party*: a peer could make every node it meets file a directory binding pointing at
/// a victim's address, which is a reflection primitive built out of the routing table. Pairing the peer's
/// **claimed port** with the **observed source IP** removes both: the IP is evidence this node collected
/// itself, so a lie can only redirect traffic to another port on the liar's own address.
///
/// `0` means "do not file me" — a node that dials out but accepts nothing.
pub(crate) const HELLO_HEAD_LEN: usize = 2 + 4 + 4 + 8 + 2 + 12;

/// The shortest legal HELLO body: the head plus an **uncontested** claim, `proof(80) ‖ index(2)`.
///
/// The claim is what replaced a bare proof here, and the uncontested case — every node that meets no coordinate collision
/// — costs exactly two bytes more than before, with the first 80 byte-identical. A displaced node additionally carries one
/// witness per skipped step, which is why the body is variable-length at all.
pub(crate) const HELLO_MIN_BODY_LEN: usize = HELLO_HEAD_LEN + PROOF_LEN + 2;

/// Byte offset of the advertised listen port within the body — after the epoch, **before** the coordinate,
/// so that `hello_coord`'s `HELLO_HEAD_LEN - TRIPLE_WIRE_LEN` keeps pointing at the triple.
const PORT_AT: usize = 2 + 4 + 4 + 8;

/// Byte offset of the claim's probe index within the body — a fixed position, so a verifier can bound the index
/// *before* decoding the variable-length witness list it implies. See [`verify_hello`].
const CLAIM_INDEX_AT: usize = HELLO_HEAD_LEN + PROOF_LEN;

/// The outcome of processing a peer's HELLO (spec §7.3/§7.4): either negotiation succeeded —
/// carrying the peer's certified coordinate and the AGREED (min version, intersected capability)
/// parameters both sides will operate at — or it failed for a specific protocol reason, which the
/// caller reports to the peer with an `ERROR` frame before aborting (spec state diagram:
/// `HELLO_SENT → CLOSED`). A bad coordinate **proof** is deliberately not a variant here: that
/// stays the unchanged silent drop (`None` from [`verify_hello`]) — an impostor is never told
/// exactly why its forged proof was rejected (spec §L0), whereas negotiation failure is an ordinary,
/// disclosable protocol condition.
///
/// Not comparable, since [`PeerClaimed`] is not: asserting on a whole result would mean asserting on a group element's
/// encoding, which is not what any caller or test is about. Match the variant and compare the fields that carry meaning.
// The `Established` variant is much larger than `Incompatible`, which is fine here and not worth a box: one of these is
// built per handshake and destructured immediately, never stored in a collection, so the size difference costs a stack
// move on a path that has just done a VRF verification.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum HelloResult {
    /// Negotiation succeeded: the peer's certified coordinate and the agreed session parameters.
    Established {
        coord: Triple,
        version: u16,
        capabilities: Capabilities,
        /// The peer's verified claim material — its VRF public, proof, output and the probe index it claims.
        ///
        /// Carried out of verification rather than recomputed by the caller: the output is the peer's rank *and* what
        /// places any point on its walk, so a caller that remembers peers (`crate::claims::ClaimBook`) would otherwise
        /// rebuild the VRF input and verify a second time — a second construction of that input being a second place for
        /// it to drift.
        peer: PeerClaimed,
        /// The port this peer **accepts** connections on, to be paired with the source IP this node observed
        /// (see [`HELLO_HEAD_LEN`]). `0` means it advertises none.
        listen_port: u16,
    },
    /// Negotiation failed (version too old, or an empty capability intersection) — the
    /// [`ProtocolError`] to report before aborting.
    Incompatible(ProtocolError),
}

/// A peer's verified coordinate claim, as [`verify_hello`] recovered it.
///
/// Not comparable: neither `VrfPublic` nor `VrfProof` implements `Eq` (equality on a group element is a question about
/// encodings, which `CoordinateClaim` answers explicitly where it needs to). Nothing here needs to compare two peers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerClaimed {
    /// The peer's VRF public key.
    pub public: VrfPublic,
    /// The proof that certified its coordinate this epoch.
    pub proof: VrfProof,
    /// The VRF output the proof yielded — the peer's rank.
    ///
    /// The output is what every comparison needs: a claim to a point is `(where the claimant's own walk reaches it, its
    /// rank)`, both functions of it.
    ///
    /// ⛔ This doc used to add *"so where the peer actually settled is not needed and is not carried — that is what keeps
    /// `verify_coordinate_claim` non-recursive"*. Where a peer settled **is** needed since 2026-08-21: a step is forced
    /// only by the node that *holds* the contested point, so a witness carries its own claim and checking one does
    /// unfold into the witness's chain. It is bounded rather than absent — a witness's settled index is strictly below
    /// its claimant's — and what that bought is the difference between 7.5 % and 97.5 % of `PG(2,4)` draws at `1.5 N`
    /// clearing the line-viability floor. This struct is unchanged: the settled index arrives in the peer's
    /// `CoordinateClaim`, beside the output rather than instead of it.
    pub output: fanos_vrf::VrfOutput,
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

/// As [`verifiable_coordinate`], but also returning this node's **rank** — needed to bind its directory entry so a
/// coordinate collision is arbitrated by an unforgeable value instead of by whoever connected last
/// (`Directory::insert_ranked`).
// Crate-internal: only the driver binds its own directory entry, and exposing a second coordinate-derivation entry point
// publicly would invite callers to pick the wrong one. The public surface stays `verifiable_coordinate`.
#[must_use]
pub(crate) fn verifiable_coordinate_ranked<F: Field>(
    creds: &NodeCredentials,
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> (Point<F>, VrfProof, fanos_vrf::VrfOutput) {
    fanos_vrf::prove_coordinate_ranked::<F>(&creds.vrf_secret(), creds.cert_der(), epoch, beacon)
}

/// The coordinate-VRF public key embedded in a certificate, or `None` if the certificate is unparsable or
/// carries no `FANOS_VRF_OID` extension. Read from a peer's *authenticated* certificate to check its
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
/// certificate. `None` only under an astronomically improbable run of collisions (`MAX_DEPTH`).
#[must_use]
pub fn hierarchical_coordinate<F: Field>(
    cert_der: &[u8],
    occupied: impl Fn(&[Point<F>]) -> bool,
) -> Option<HierAddr<F>> {
    derive_address(|level| coordinate_at_level::<F>(cert_der, level), occupied)
}

/// Encode a self-certifying HELLO — the announcement a node sends on a fresh connection carrying
/// its negotiation parameters and its **claim** to a coordinate (spec §7.3/§7.4): frame body
/// `version(2 BE) ‖ capabilities(4 BE) ‖ field_q(4 BE) ‖ epoch(8 BE) ‖ coord(12) ‖ claim`,
/// wrapped as a [`FrameType::Hello`] frame. `field_q` is this node's plane order (`F::Q`) —
/// informational parity, not itself negotiated (an intersection is meaningless for a scalar order).
/// The peer verifies it — and negotiates against its own parameters — with [`verify_hello`].
///
/// The claim is `proof(80) ‖ index(2) ‖ witness*`. It replaced a bare proof so a node **displaced from its preferred
/// point can announce where it went**: before this, the resolution machinery could tell a node it had to move but the wire
/// could only ever say index 0, so probing was reachable from the simulator and not from a deployment, and a cell still
/// seated only `O(q)` of its `q² + q + 1` points. An uncontested node — the overwhelming majority — pays two bytes.
#[must_use]
pub(crate) fn hello_bytes<F: Field>(
    epoch: Epoch,
    coord: Triple,
    claim: &CoordinateClaim,
    capabilities: Capabilities,
    listen_port: u16,
) -> Vec<u8> {
    let claim_bytes = claim.to_bytes();
    let mut body = Vec::with_capacity(HELLO_HEAD_LEN + claim_bytes.len());
    body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&capabilities.bits().to_be_bytes());
    body.extend_from_slice(&F::Q.to_be_bytes());
    body.extend_from_slice(&epoch.get().to_be_bytes());
    // Before the coordinate, not after it: `hello_coord` reads the triple at
    // `HELLO_HEAD_LEN - TRIPLE_WIRE_LEN`, so a field appended to the head would silently move what that
    // expression points at while still type-checking.
    debug_assert_eq!(body.len(), PORT_AT, "the port must sit at the offset the reader and patcher use");
    body.extend_from_slice(&listen_port.to_be_bytes());
    body.extend_from_slice(&encode_triple(coord));
    body.extend_from_slice(&claim_bytes);
    let mut out = Vec::new();
    encode_frame(FrameType::Hello.code(), &body, &mut out);
    out
}

/// Write the real listen port into an already-built HELLO frame.
///
/// **The ordering this exists for.** The HELLO is constructed before the endpoint is bound — it needs the
/// node's coordinate and VRF claim, which come from the credentials, while the port comes from the socket —
/// so at construction time there is no port to advertise and `hello_bytes` is called with `0`. `spawn_inner`
/// calls this the instant it has `endpoint.local_addr()`, which is also the only place the *ephemeral* case
/// is answerable at all: a node bound to port `0` learns its port from the OS and nowhere else, and that is
/// the ordinary case in the simulator and in any `bind 0` deployment.
///
/// Rewrites two bytes at a fixed offset rather than rebuilding the frame, because rebuilding would need the
/// claim material this layer does not hold. The offset is derived from the frame's own decode, so a change
/// to the header cannot leave this writing into the body.
///
/// Returns `false` if `hello` is not a well-formed HELLO frame — the caller keeps the unpatched bytes, which
/// advertise `0` and therefore ask peers not to file a directory entry: a missing route, never a wrong one.
pub(crate) fn set_hello_listen_port(hello: &mut [u8], port: u16) -> bool {
    let Ok((frame, _)) = decode_frame(hello) else {
        return false;
    };
    if frame.frame_type() != Some(FrameType::Hello) || frame.body.len() < HELLO_MIN_BODY_LEN {
        return false;
    }
    // The body's offset within the frame, taken from the decode rather than assumed: `body` is a slice of
    // `hello`, so the distance between their starts is exactly the header length.
    let header = frame.body.as_ptr() as usize - hello.as_ptr() as usize;
    let at = header + PORT_AT;
    let Some(slot) = hello.get_mut(at..at + 2) else {
        return false;
    };
    slot.copy_from_slice(&port.to_be_bytes());
    true
}

/// Parse a peer's HELLO, verify its coordinate proof against the peer's authenticated certificate
/// `peer_cert_der`, and negotiate the session parameters against `my_capabilities` (spec §7.3/§7.4).
///
/// The coordinate gate binds the coordinate to *this* certificate, so a replayed proof from another
/// identity does not verify, and a bad claim is a silent `None` (spec §L0 — an impostor is never told
/// why). Only once it checks out does negotiation run: `None` on a canonical-decode failure or a bad
/// claim (silent drop, as before); `Some(HelloResult::Incompatible(err))` on a version or capability
/// mismatch (the caller reports `err` and aborts); `Some(HelloResult::Established { .. })` otherwise.
///
/// ## The claim is bounded before it is decoded
///
/// A claim states a probe index and must carry exactly that many witnesses, each ~`2 + |cert| + 32 + 80` bytes. The index
/// is attacker-chosen and sits at a **fixed offset**, so it is read and bounded against `probe_bound::<F>()` *first* —
/// before the witness list it implies is decoded, and therefore before it can size an allocation. `CoordinateClaim::from_bytes`
/// would reject an out-of-range index too, but only after reserving for it, and `verify_coordinate_claim` only after that
/// again: the cheapest rejection is the one that never allocates.
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
    if body.len() < HELLO_MIN_BODY_LEN {
        return None;
    }
    let peer_version = u16::from_be_bytes(body.get(0..2)?.try_into().ok()?);
    let peer_capabilities =
        Capabilities::from_bits(u32::from_be_bytes(body.get(2..6)?.try_into().ok()?));
    // The peer's plane order is carried for informational parity; routing itself is decided by the
    // generic `F` this build is instantiated with, not by this value, so it is not gated here.
    let _peer_field_q = u32::from_be_bytes(body.get(6..10)?.try_into().ok()?);
    let epoch = Epoch::new(u64::from_be_bytes(body.get(10..18)?.try_into().ok()?));
    let listen_port = u16::from_be_bytes(body.get(PORT_AT..PORT_AT + 2)?.try_into().ok()?);
    let coord = decode_triple(body.get(HELLO_HEAD_LEN - TRIPLE_WIRE_LEN..HELLO_HEAD_LEN)?)?;
    // Bound the claimed index from its fixed offset, before the witness list it implies is decoded.
    let claimed_index = u16::from_be_bytes(body.get(CLAIM_INDEX_AT..CLAIM_INDEX_AT + 2)?.try_into().ok()?);
    if claimed_index >= fanos_vrf::probe_bound::<F>() {
        return None;
    }
    let claim = CoordinateClaim::from_bytes(body.get(HELLO_HEAD_LEN..)?)?;
    let point = Point::<F>::new(coord)?;
    let public = vrf_public_from_cert(peer_cert_der)?;
    let output = fanos_vrf::verify_coordinate_claim_output::<F>(
        &public,
        peer_cert_der,
        epoch,
        beacon,
        &point,
        &claim,
    )?; // bad claim — silent drop, unchanged behaviour (spec §L0)
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
        peer: PeerClaimed { public, proof: claim.proof, output },
        listen_port,
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
    if body.len() < HELLO_MIN_BODY_LEN {
        return None;
    }
    Some(Epoch::new(u64::from_be_bytes(body.get(10..18)?.try_into().ok()?)))
}

/// The **probe index** a HELLO claims, for labelling a refusal.
///
/// A claim at index `k` is required to carry exactly `k` witnesses
/// (`fanos_vrf::verify_coordinate_claim_output`), each one proving the point at the previous step is held by
/// a better claimant. So "the proof did not verify" has two very different meanings depending on this
/// number: at index 0 the peer's own VRF proof failed, and above it the *witness chain* did — which a node
/// can only assemble from a claim book that knows who beat it. Refusals that carry no index and refusals
/// that all sit at index 1 are different defects, and without this they render identically.
#[must_use]
pub(crate) fn hello_claim_index(hello: &[u8]) -> Option<u16> {
    let (frame, _) = decode_frame(hello).ok()?;
    if frame.frame_type() != Some(FrameType::Hello) {
        return None;
    }
    let body = frame.body;
    if body.len() < HELLO_MIN_BODY_LEN {
        return None;
    }
    Some(u16::from_be_bytes(body.get(CLAIM_INDEX_AT..CLAIM_INDEX_AT + 2)?.try_into().ok()?))
}

/// Peek the coordinate a HELLO *claims*, without verifying it. Paired with [`hello_epoch`], and read from
/// the same fixed head — the claim sits at `HELLO_HEAD_LEN - TRIPLE_WIRE_LEN`, right after the epoch.
///
/// **This is an unproven assertion by a stranger, and only one caller may treat it as anything at all**
/// (#235): the restricted state a connection sits in when this node cannot judge the peer's epoch, where it
/// serves as a *label* for a connection that is not in any routing table. It must never reach the directory,
/// the connection map, a station tag, or a reply target — attaching it to any of those is how a stranger
/// picks which line this node's instruments accuse or which member its replies are aimed at.
#[must_use]
pub(crate) fn hello_coord(hello: &[u8]) -> Option<Triple> {
    let (frame, _) = decode_frame(hello).ok()?;
    if frame.frame_type() != Some(FrameType::Hello) {
        return None;
    }
    let body = frame.body;
    if body.len() < HELLO_MIN_BODY_LEN {
        return None;
    }
    decode_triple(body.get(HELLO_HEAD_LEN - TRIPLE_WIRE_LEN..HELLO_HEAD_LEN)?)
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
        claim: &CoordinateClaim,
        capabilities: Capabilities,
    ) -> Vec<u8> {
        let mut body = Vec::with_capacity(HELLO_MIN_BODY_LEN);
        body.extend_from_slice(&version.to_be_bytes());
        body.extend_from_slice(&capabilities.bits().to_be_bytes());
        body.extend_from_slice(&F::Q.to_be_bytes());
        body.extend_from_slice(&epoch.get().to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // listen port — not what this seam is about
        body.extend_from_slice(&encode_triple(coord));
        body.extend_from_slice(&claim.to_bytes());
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
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &CoordinateClaim::direct(proof), sender_caps, 0);

        // The receiver offers CORE + APHANTOS_FULL only (no CALYPSO) — the intersection drops it.
        let receiver_caps = Capabilities::CORE | Capabilities::APHANTOS_FULL;
        let result = verify_hello::<F2>(creds.cert_der(), &hello, &beacon, receiver_caps);
        let Some(HelloResult::Established { coord: got, version, capabilities, .. }) = result else {
            unreachable!("a valid HELLO with an overlapping capability set establishes")
        };
        assert_eq!(
            (got, version, capabilities),
            (
                coord.coords(),
                PROTOCOL_VERSION,
                Capabilities::CORE | Capabilities::APHANTOS_FULL
            ),
            "negotiates the true intersection, not either side's full offer"
        );
    }

    /// **The port survives verification, and the patch reaches it after the socket is bound.**
    ///
    /// Two facts in one test, because they are one mechanism split across a lifetime: `hello_bytes` writes
    /// the port at a fixed offset before the coordinate, and `set_hello_listen_port` rewrites exactly those
    /// two bytes once `spawn_inner` knows what the OS gave it — the only source a `bind 0` node has.
    ///
    /// The coordinate is asserted on both sides of the patch on purpose. The port sits *before* the triple,
    /// so an off-by-one in the offset would corrupt the coordinate rather than the port, and a test that
    /// checked only the port would read the right number out of a broken frame.
    #[test]
    fn the_advertised_listen_port_survives_verification_and_the_bind_time_patch() {
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(3);
        let beacon = BeaconSeed::new([0x31; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);
        let claim = CoordinateClaim::direct(proof);

        // Built with a port, as `Reseater::apply` does — it holds `local_addr` and needs no patch.
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &claim, Capabilities::CORE, 4433);
        let Some(HelloResult::Established { coord: got, listen_port, .. }) =
            verify_hello::<F2>(creds.cert_der(), &hello, &beacon, Capabilities::CORE)
        else {
            unreachable!("a valid HELLO establishes")
        };
        assert_eq!((got, listen_port), (coord.coords(), 4433), "the port arrives with the coordinate intact");

        // Built without one, as `spawn_self_certifying` must — the endpoint does not exist yet — and patched
        // at bind time.
        let mut cold = hello_bytes::<F2>(epoch, coord.coords(), &claim, Capabilities::CORE, 0);
        let Some(HelloResult::Established { listen_port: none_yet, .. }) =
            verify_hello::<F2>(creds.cert_der(), &cold, &beacon, Capabilities::CORE)
        else {
            unreachable!("a valid HELLO establishes")
        };
        assert_eq!(none_yet, 0, "an unpatched HELLO advertises nothing — a missing route, never a wrong one");

        assert!(set_hello_listen_port(&mut cold, 51820), "a well-formed HELLO accepts the patch");
        let Some(HelloResult::Established { coord: after, listen_port: patched, .. }) =
            verify_hello::<F2>(creds.cert_der(), &cold, &beacon, Capabilities::CORE)
        else {
            unreachable!("the patch must not disturb the proof")
        };
        assert_eq!(
            (after, patched),
            (coord.coords(), 51820),
            "the patched port is read back and the coordinate after it is untouched"
        );

        // And it refuses what it cannot place: the caller then keeps bytes advertising `0`.
        assert!(!set_hello_listen_port(&mut [0u8; 4], 51820), "a frame that is not a HELLO is refused");
    }

    #[test]
    fn hello_epoch_reads_the_proven_epoch_for_the_safe_stall_window() {
        // The verifier peeks the epoch a HELLO proves so it can select that epoch's beacon from its accepted
        // window (safe-stall, R-C1) — a peer proving a recent last-good epoch is matched to the right beacon.
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(7);
        let beacon = BeaconSeed::new([0x77; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &CoordinateClaim::direct(proof), Capabilities::CORE, 0);

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
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &CoordinateClaim::direct(proof), Capabilities::CORE, 0);

        let full_node_caps =
            Capabilities::CORE | Capabilities::APHANTOS_FULL | Capabilities::CALYPSO;
        let result = verify_hello::<F2>(creds.cert_der(), &hello, &beacon, full_node_caps);
        let Some(HelloResult::Established { coord: got, version, capabilities, .. }) = result else {
            unreachable!("CORE always intersects")
        };
        assert_eq!((got, version, capabilities), (coord.coords(), PROTOCOL_VERSION, Capabilities::CORE));
    }

    #[test]
    fn disjoint_capabilities_are_reported_incompatible() {
        // Neither side advertises CORE nor anything the other offers — an empty intersection, the
        // genuine incompatibility condition (distinct from ordinary feature degradation).
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(1);
        let beacon = BeaconSeed::new([0x13; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &CoordinateClaim::direct(proof), Capabilities::APHANTOS_LITE, 0);

        let result =
            verify_hello::<F2>(creds.cert_der(), &hello, &beacon, Capabilities::APHANTOS_FULL);
        assert!(
            matches!(result, Some(HelloResult::Incompatible(ProtocolError::Unsupported))),
            "an empty capability intersection is a disclosable negotiation failure"
        );
    }

    #[test]
    fn an_older_than_supported_version_is_reported_incompatible() {
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(1);
        let beacon = BeaconSeed::new([0x14; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);
        // Version 0 predates MIN_SUPPORTED_VERSION (1) — negotiate_version returns None.
        let hello = hello_bytes_with_version::<F2>(
            0,
            epoch,
            coord.coords(),
            &CoordinateClaim::direct(proof),
            Capabilities::CORE,
        );

        let result = verify_hello::<F2>(creds.cert_der(), &hello, &beacon, Capabilities::CORE);
        assert!(
            matches!(result, Some(HelloResult::Incompatible(ProtocolError::Unsupported))),
            "a too-old version is incompatible even though capabilities would have matched"
        );
    }

    #[test]
    fn a_displaced_node_is_accepted_at_the_point_it_probed_to() {
        // The property this whole wire change exists for: before it, a node could *detect* that it had to move but the
        // HELLO could only ever say index 0, so a cell seated `O(q)` of its `q² + q + 1` points and the resolution
        // machinery was reachable from the simulator and not from a deployment.
        //
        // Two identities that draw the same preferred point; the worse-ranked one announces its NEXT probe point, carrying
        // the better-ranked one as the witness that forced it there.
        let epoch = Epoch::new(4);
        let beacon = BeaconSeed::new([0x21; 32]);
        let mut pool: Vec<NodeCredentials> = Vec::new();
        let mut pair = None;
        for _ in 0..400 {
            let fresh = NodeCredentials::generate().unwrap();
            let (_, _, rank) = verifiable_coordinate_ranked::<F2>(&fresh, epoch, &beacon);
            if let Some(i) = pool.iter().position(|c| {
                let (_, _, other) = verifiable_coordinate_ranked::<F2>(c, epoch, &beacon);
                fanos_vrf::probe_point::<F2>(&other, 0) == fanos_vrf::probe_point::<F2>(&rank, 0)
                    // Same preference, but NOT the same whole walk — a shared walk means the loser is beaten everywhere
                    // and has no seat at all (see `fanos_vrf::probe_point`'s residual note).
                    && fanos_vrf::probe_point::<F2>(&other, 1) != fanos_vrf::probe_point::<F2>(&rank, 1)
            }) {
                let held = pool.swap_remove(i);
                let (_, _, held_rank) = verifiable_coordinate_ranked::<F2>(&held, epoch, &beacon);
                pair = Some(if fanos_vrf::claim_beats((0, &held_rank), (0, &rank)) {
                    (fresh, held) // (loser, winner)
                } else {
                    (held, fresh)
                });
                break;
            }
            pool.push(fresh);
        }
        let Some((loser, winner)) = pair else {
            unreachable!("two of 400 identities collide on one of PG(2,2)'s seven points")
        };

        let (_, loser_proof, loser_rank) = verifiable_coordinate_ranked::<F2>(&loser, epoch, &beacon);
        let (_, winner_proof, _) = verifiable_coordinate_ranked::<F2>(&winner, epoch, &beacon);
        let displaced = fanos_vrf::probe_point::<F2>(&loser_rank, 1);
        let claim = CoordinateClaim {
            proof: loser_proof,
            index: 1,
            witnesses: vec![fanos_vrf::DisplacementWitness {
                id: winner.cert_der().to_vec(),
                public: vrf_public_from_cert(winner.cert_der()).unwrap(),
                // The winner is SEATED at its own preferred point, which is the one it displaced the loser from — so
                // its whole justification is the uncontested claim, and the witnessed HELLO is one `u16` longer than
                // it was before the rule changed.
                claim: CoordinateClaim::direct(winner_proof),
            }],
        };
        let hello = hello_bytes::<F2>(epoch, displaced.coords(), &claim, Capabilities::CORE, 0);
        assert!(
            hello.len() > HELLO_MIN_BODY_LEN,
            "a witnessed claim is longer than the uncontested body it extends"
        );
        let result = verify_hello::<F2>(loser.cert_der(), &hello, &beacon, Capabilities::CORE);
        let Some(HelloResult::Established { coord, .. }) = result else {
            unreachable!("a witnessed displacement must be accepted")
        };
        assert_eq!(coord, displaced.coords(), "and accepted at the PROBED point, not the preferred one");
        assert_ne!(
            coord,
            fanos_vrf::probe_point::<F2>(&loser_rank, 0).coords(),
            "the whole point: this is not the point its own draw preferred"
        );

        // The same claim announced at index 1 but WITHOUT its witness is refused — the wire carries the justification, not
        // just the number.
        let unwitnessed = CoordinateClaim { proof: loser_proof, index: 1, witnesses: Vec::new() };
        assert!(
            verify_hello::<F2>(
                loser.cert_der(),
                &hello_bytes::<F2>(epoch, displaced.coords(), &unwitnessed, Capabilities::CORE, 0),
                &beacon,
                Capabilities::CORE
            )
            .is_none(),
            "an unjustified index is a silent drop"
        );
        // And the uncontested claim still names the preferred point, unchanged from before this existed.
        let direct = CoordinateClaim::direct(loser_proof);
        let preferred = fanos_vrf::probe_point::<F2>(&loser_rank, 0);
        assert!(
            verify_hello::<F2>(
                loser.cert_der(),
                &hello_bytes::<F2>(epoch, preferred.coords(), &direct, Capabilities::CORE, 0),
                &beacon,
                Capabilities::CORE
            )
            .is_some(),
            "index 0 is exactly the claim that was already valid"
        );
    }

    #[test]
    fn an_out_of_range_probe_index_is_refused_before_the_witness_list_is_decoded() {
        // The claimed index is attacker-chosen and sits at a fixed offset, and each witness it implies is ~2 + |cert| + 112
        // bytes. Bounding it against `probe_bound::<F>()` first is what stops a `u16` on the wire from sizing an
        // allocation; `CoordinateClaim::from_bytes` would also reject it, but only after reserving for it.
        let creds = NodeCredentials::generate().unwrap();
        let epoch = Epoch::new(2);
        let beacon = BeaconSeed::new([0x22; 32]);
        let (coord, proof) = verifiable_coordinate::<F2>(&creds, epoch, &beacon);
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &CoordinateClaim::direct(proof), Capabilities::CORE, 0);
        assert!(verify_hello::<F2>(creds.cert_der(), &hello, &beacon, Capabilities::CORE).is_some());

        // `probe_bound::<F2>()` is q + 1 = 3, so 3 and above name a point some lower index already names.
        assert_eq!(fanos_vrf::probe_bound::<F2>(), 3);
        let (frame, _) = decode_frame(&hello).unwrap();
        for claimed in [3u16, 64, u16::MAX] {
            let mut body = frame.body.to_vec();
            let at = HELLO_HEAD_LEN + PROOF_LEN;
            body[at..at + 2].copy_from_slice(&claimed.to_be_bytes());
            let mut framed = Vec::new();
            encode_frame(FrameType::Hello.code(), &body, &mut framed);
            assert!(
                verify_hello::<F2>(creds.cert_der(), &framed, &beacon, Capabilities::CORE).is_none(),
                "index {claimed} is at or past the line's length and must be refused"
            );
        }
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
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &CoordinateClaim::direct(proof), Capabilities::CORE, 0);

        // Verify against a DIFFERENT certificate than the one the proof was produced for.
        let result = verify_hello::<F2>(other.cert_der(), &hello, &beacon, Capabilities::CORE);
        assert!(result.is_none(), "an impostor's HELLO is a silent drop");
    }

    #[test]
    fn a_short_or_wrongly_typed_frame_is_a_silent_drop() {
        let creds = NodeCredentials::generate().unwrap();
        let beacon = BeaconSeed::new([0x16; 32]);
        // Truncated body.
        let mut short = Vec::new();
        encode_frame(FrameType::Hello.code(), &[0u8; 10], &mut short);
        assert!(verify_hello::<F2>(creds.cert_der(), &short, &beacon, Capabilities::CORE).is_none());
        // Right length, wrong frame type (e.g. a Ping).
        let mut wrong_type = Vec::new();
        encode_frame(FrameType::Ping.code(), &[0u8; HELLO_MIN_BODY_LEN], &mut wrong_type);
        assert!(verify_hello::<F2>(creds.cert_der(), &wrong_type, &beacon, Capabilities::CORE).is_none());
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
        let hello = hello_bytes::<F2>(epoch, coord.coords(), &CoordinateClaim::direct(proof), caps, 0);

        let (frame, n) = decode_frame(&hello).unwrap();
        assert_eq!(n, hello.len(), "the frame consumes the whole buffer");
        assert_eq!(frame.frame_type(), Some(FrameType::Hello));
        let body = frame.body;
        assert_eq!(body.len(), HELLO_MIN_BODY_LEN, "an uncontested claim is the shortest legal body");

        // version(2) ‖ capabilities(4) ‖ field_q(4) ‖ epoch(8) ‖ listen_port(2) ‖ coord(12) ‖ proof(80) ‖
        // index(2), in that order.
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
            u16::from_be_bytes(body[18..20].try_into().unwrap()),
            0,
            "listen_port at offset 18 — before the coordinate, so `hello_coord`'s \
             `HELLO_HEAD_LEN - TRIPLE_WIRE_LEN` still names the triple"
        );
        assert_eq!(
            decode_triple(&body[20..32]).unwrap(),
            coord.coords(),
            "coord at offset 20"
        );
        assert_eq!(
            body[HELLO_HEAD_LEN..HELLO_HEAD_LEN + PROOF_LEN].len(),
            PROOF_LEN,
            "the claim's proof sits at HELLO_HEAD_LEN for PROOF_LEN bytes"
        );
        assert_eq!(
            u16::from_be_bytes(body[HELLO_HEAD_LEN + PROOF_LEN..].try_into().unwrap()),
            0,
            "and an uncontested node's index is the two bytes that follow"
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
