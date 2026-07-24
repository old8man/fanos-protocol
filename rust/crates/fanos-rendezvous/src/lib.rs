//! # fanos-rendezvous — anonymous meeting for DIAULOS
//!
//! A `.fanos` session normally rides the base overlay by coordinate (the Direct profile), which
//! reveals *where* each party is. The anonymous profile instead carries the very same DIAULOS
//! payloads (the `ClientHello`/`ServerHello` and the sealed cells) over **threshold onions**
//! ([`fanos_aphantos`], "a hop is a line") to a **computed meeting line** ([`meeting_line`], derived
//! by CALYPSO from the service key and the epoch — no lookup, rotates each epoch). Because aphantos
//! onions are forward-only, the two directions are two independent forward circuits that meet at
//! rendezvous lines:
//!
//! * client → service: an onion whose last hop is the service's meeting line;
//! * service → client: an onion whose last hop is a *client-chosen* reply rendezvous line, which the
//!   client names (as a [`Request`]'s `reply_circuit`) inside its first message.
//!
//! DIAULOS already encrypts the inner bytes end-to-end, so the reply route travels in the clear at
//! the meeting point without weakening confidentiality — the onion hides *where*, DIAULOS hides
//! *what*. So neither party learns the other's location: each is reachable only at a rotating
//! rendezvous line, through `t`-of-`(q+1)` threshold hops no single node can peel. This crate is the
//! sealing, meeting-line, and request-wrapper core; wiring it under a DIAULOS session is a thin layer.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use fanos_aphantos::threshold::{HopLine, seal_onion};
use fanos_aphantos::threshold_router::{launch_frame, line_member_coords};
pub use fanos_calypso::{BeaconSeed, Epoch};
use fanos_field::Field;
use fanos_geometry::{Line, Triple};
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_wire::Wire;

mod transport;
pub use transport::{RendezvousClient, RendezvousService, SessionId, session_reply_keypair};

/// The anonymous-source sentinel a threshold delivery carries (`from` in `Notification::Delivered`).
pub use fanos_aphantos::threshold_router::ANONYMOUS;
/// The combiner coordinate where an onion bound for `line` is finally delivered — the point a party
/// listens at to receive its rendezvous traffic.
pub use fanos_aphantos::threshold_router::combiner_for;

/// The rendezvous **meeting line** for a service: the client and the service each derive the *same*
/// line from the service's public key, the `epoch`, and the epoch's randomness `beacon`, with no lookup
/// or published record (CALYPSO). It rotates every epoch, so there is no fixed rendezvous point to
/// enumerate, block, or seize — and because it folds in the beacon (audit E5), a future epoch's line is
/// unpredictable in advance, so an adversary cannot pre-position on it.
#[must_use]
pub fn meeting_line<F: Field>(service_pubkey: &[u8], epoch: Epoch, beacon: &BeaconSeed) -> Line<F> {
    fanos_calypso::rendezvous::rendezvous_line::<F>(service_pubkey, epoch, beacon)
}

/// A directory of mixnet members' hybrid KEM public keys, keyed by overlay coordinate. Sealing an
/// onion seals each hop to the coordinates of that line's members named here.
#[derive(Clone, Default)]
pub struct MixDirectory {
    keys: BTreeMap<Triple, HybridKemPublic>,
}

impl MixDirectory {
    /// An empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `public` as the KEM key of the member at `coord`.
    pub fn insert(&mut self, coord: Triple, public: HybridKemPublic) {
        self.keys.insert(coord, public);
    }

    /// The KEM key of the member at `coord`, if known.
    #[must_use]
    pub fn get(&self, coord: &Triple) -> Option<&HybridKemPublic> {
        self.keys.get(coord)
    }

    /// Iterate the directory's `(coordinate, key)` entries — used to pick a delivery relay for a SURB reply
    /// block (audit §5 S1-H3).
    pub fn entries(&self) -> impl Iterator<Item = (&Triple, &HybridKemPublic)> {
        self.keys.iter()
    }

    /// The number of known members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the directory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The client's rendezvous **request wrapper**, the plaintext delivered at the service's meeting
/// line: the *reply circuit* the service routes responses back through (hop lines ending at the
/// client's own reply rendezvous line) and the inner DIAULOS bytes (a `ClientHello` or a cell). The
/// service seals its responses to `reply_circuit` (via [`seal_forward`]); the client listens at that
/// circuit's destination combiner. The onion already hides the path, and DIAULOS already encrypts the
/// inner bytes end-to-end, so this wrapper carries the return route in the clear at the meeting point
/// without weakening either property.
/// `#[derive(Wire)]` emits the canonical `cookie(16) ‖ reply_circuit(varint count ‖ Triple×12) ‖
/// payload(varint-prefixed) ‖ reply_pub(varint-prefixed)` (spec §7.1) — one derived codec for the
/// wrapper, replacing the hand-rolled `u8` hop-count + raw trailing payload.
#[derive(Clone, PartialEq, Eq, Debug, fanos_wire_derive::Wire)]
pub struct Request {
    /// A per-session cookie: the service demultiplexes concurrent clients by it and binds each to its
    /// reply circuit, so it need not learn who any client is.
    pub cookie: [u8; 16],
    /// The service's **host-registration tag** [`service_tag`], or all-zeros for none. When a hidden
    /// service is hosted off its meeting combiner (the general case — the combiner is key-derived, not
    /// the operator's coordinate), the node at the combiner routes this request to the host registered
    /// under this tag (`design-anonymity-substrate.md` §3b). All-zeros ⇒ deliver locally (the service is
    /// its own combiner, or the legacy/Direct path) — so this is additive and back-compatible.
    pub service_tag: [u8; 32],
    /// Hop lines to the client's reply rendezvous. For NOSTOS the **last** hop is the client's own
    /// **dead-drop line** (one of the `q+1` lines through the client's coordinate), so the client
    /// receives replies passively as a line member — the service never learns which member it is.
    pub reply_circuit: Vec<Triple>,
    /// The inner payload (a DIAULOS `ClientHello` or cell).
    pub payload: Vec<u8>,
    /// The client's **NOSTOS reply public key** (a serialized [`HybridKemPublic`]): the service
    /// end-to-end-seals its replies to it, so the dead-drop line's members — who route the reply —
    /// see only ciphertext and only the client decrypts. Empty on the legacy (pre-NOSTOS) path.
    pub reply_pub: Vec<u8>,
}

impl Request {
    /// The canonical wire bytes (the derived [`Wire`] codec).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.to_wire()
    }

    /// Decode a request wrapper; `None` if malformed, non-canonical, or carrying trailing bytes.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        Self::from_wire(bytes).ok()
    }
}

/// A sealed forward onion ready to launch: the coordinate to send it to and the wire frame.
pub struct Forward {
    /// The combiner coordinate of the first hop line — where the launch frame is sent.
    pub combiner: Triple,
    /// The launch frame (the onion wrapped for its first hop).
    pub frame: Vec<u8>,
}

/// Seal `payload` into a threshold onion routed through `circuit` — a sequence of hop lines whose
/// **last** is the destination (e.g. a [`meeting_line`]) — and return the [`Forward`] to launch it.
/// Each hop needs `threshold` of its `q+1` line members to peel; `directory` supplies their keys.
/// `seed` domain-separates this onion's per-hop key material — use fresh randomness per onion in
/// production. `None` if the circuit is empty, a member key is missing, or sealing fails.
#[must_use]
pub fn seal_forward<F: Field>(
    circuit: &[Triple],
    directory: &MixDirectory,
    threshold: u8,
    payload: &[u8],
    seed: &[u8],
) -> Option<Forward> {
    let first = *circuit.first()?;
    // Each hop line's member keys, in the canonical seal order the router expects.
    let member_vecs: Vec<Vec<&HybridKemPublic>> = circuit
        .iter()
        .map(|&line| {
            line_member_coords::<F>(line)
                .iter()
                .map(|coord| directory.get(coord))
                .collect::<Option<Vec<_>>>()
        })
        .collect::<Option<Vec<_>>>()?;
    let hops: Vec<HopLine<'_>> = circuit
        .iter()
        .zip(&member_vecs)
        .map(|(&line, members)| HopLine { line, members })
        .collect();
    let onion = seal_onion(&hops, threshold, payload, seed).ok()?;
    Some(Forward {
        combiner: combiner_for::<F>(first)?,
        frame: launch_frame(first, &onion),
    })
}

/// Seal a **NOSTOS reply** back through `circuit` — a threshold onion whose last hop is the client's
/// own dead-drop line. `payload` is first end-to-end-sealed to `reply_pub` (the client's NOSTOS reply
/// key) and wrapped in the dead-drop envelope, so the delivery line's combiner multicasts only
/// ciphertext to the line's `q+1` members and only the client decrypts. `e2e_seed` and `onion_seed`
/// MUST be independent fresh draws (the end-to-end nonce and every hop's key material derive from
/// them). `None` if the reply key is malformed, a member key is missing, or sealing fails.
#[must_use]
pub fn seal_nostos_reply<F: Field>(
    reply_pub: &[u8],
    circuit: &[Triple],
    directory: &MixDirectory,
    threshold: u8,
    payload: &[u8],
    e2e_seed: &[u8],
    onion_seed: &[u8],
) -> Option<Forward> {
    let public = HybridKemPublic::decode(reply_pub)?;
    let inner = fanos_aphantos::nostos::seal_to_receiver(&public, payload, e2e_seed).ok()?;
    let enveloped = fanos_aphantos::nostos::deaddrop_envelope(&inner);
    seal_forward::<F>(circuit, directory, threshold, &enveloped, onion_seed)
}

/// The **host-registration tag** for a service: `H("FANOS-v1/rdv-host" ‖ service_pubkey ‖ epoch)`. A
/// hidden service is reached at its [`meeting_line`], whose combiner is a function of the *service key*,
/// not of any node's (VRF-blinded, epoch-rotated) coordinate — so the operator hosting the service is,
/// save by luck, **not** the node at that combiner. The operator instead registers an anonymous forward
/// route there (`design-anonymity-substrate.md` §3b); this tag lets the combiner route each client
/// request to the right registered host when several services share one combiner (Fano has only four).
/// It rotates per epoch and is a one-way image of the public key, so it discloses no coordinate.
#[must_use]
pub fn service_tag(service_pubkey: &[u8], epoch: Epoch) -> [u8; 32] {
    let mut data = Vec::with_capacity(service_pubkey.len() + 4);
    data.extend_from_slice(service_pubkey);
    data.extend_from_slice(&epoch.low32_be_bytes());
    fanos_primitives::hash::hash_labeled(fanos_primitives::hash::label::RDV_HOST, &data)
}

/// The 4-byte marker that prefixes a [`HostRegister`] onion body, distinguishing a host registration
/// from a client [`Request`] when both peel out at a meeting combiner as anonymous deliveries. A
/// `Request` opens with a 16-byte CSPRNG cookie, so a collision with this constant is negligible; the
/// combiner nonetheless checks the marker *first* (both encoders are ours), making classification exact.
pub const HOST_REGISTER_TAG: &[u8; 4] = b"RHR1";

/// A hidden service's **anonymous host registration**, delivered to its [`meeting_line`]'s combiner each
/// epoch (`design-anonymity-substrate.md` §3b). The service is treated as a NOSTOS receiver: the combiner
/// learns only its dead-drop **line** (the last hop of `forward_circuit`), never its coordinate, and
/// forwards each matching client request to it as a NOSTOS onion.
///
/// The **bare-host fallback** — an operator that cannot peel a dead-drop (a pure-overlay egress) — sends
/// an empty `forward_circuit`, registering its plaintext coordinate for a direct forward instead; that
/// leaks the coordinate to the one combiner node (Tor's posture, no worse). The primary, coordinate-hiding
/// path carries a real `forward_circuit` + `reply_pub`.
/// `#[derive(Wire)]` emits `service_tag(32) ‖ reply_pub(varint-prefixed) ‖ forward_circuit(varint count ‖
/// Triple×12) ‖ coordinate(12)`.
#[derive(Clone, PartialEq, Eq, Debug, fanos_wire_derive::Wire)]
pub struct HostRegister {
    /// The [`service_tag`] the combiner routes matching client requests by.
    pub service_tag: [u8; 32],
    /// The service's **NOSTOS reply public key** (a serialized [`HybridKemPublic`]): the combiner
    /// end-to-end-seals each forwarded request to it, so the dead-drop line's members see only ciphertext
    /// and only the service decrypts. Empty on the bare-host fallback (direct forward to `coordinate`).
    pub reply_pub: Vec<u8>,
    /// Hop lines to the service's own **dead-drop line** (the last hop), through which the combiner
    /// forwards client requests as NOSTOS onions. Empty on the bare-host fallback.
    pub forward_circuit: Vec<Triple>,
    /// The bare-host fallback coordinate — used **only** when `forward_circuit` is empty (the combiner
    /// forwards by a direct `Send`, learning this coordinate). All-zeros on the primary onion path.
    pub coordinate: Triple,
}

impl HostRegister {
    /// The canonical wire bytes (the derived [`Wire`] codec).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.to_wire()
    }

    /// Decode a host registration; `None` if malformed, non-canonical, or carrying trailing bytes.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        Self::from_wire(bytes).ok()
    }
}

/// Seal a [`HostRegister`] into a threshold onion routed through `meeting_circuit` — hop lines whose
/// **last** is the service's [`meeting_line`] this epoch — so it peels out at the meeting combiner as an
/// anonymous delivery the combiner recognizes by [`HOST_REGISTER_TAG`]. The registration itself is an
/// onion, so the combiner never learns the operator's coordinate — only the dead-drop line inside
/// `register.forward_circuit`. `seed` domain-separates the onion's key material (fresh per registration).
/// `None` if the circuit is empty, a member key is missing, or sealing fails.
#[must_use]
pub fn seal_host_register<F: Field>(
    meeting_circuit: &[Triple],
    directory: &MixDirectory,
    threshold: u8,
    register: &HostRegister,
    seed: &[u8],
) -> Option<Forward> {
    let mut body = Vec::with_capacity(HOST_REGISTER_TAG.len() + 32);
    body.extend_from_slice(HOST_REGISTER_TAG);
    body.extend_from_slice(&register.encode());
    seal_forward::<F>(meeting_circuit, directory, threshold, &body, seed)
}

/// If `delivery` is a [`HOST_REGISTER_TAG`]-prefixed host registration, decode it; otherwise `None` (the
/// combiner then treats the delivery as a client [`Request`]). Used at a meeting combiner to classify each
/// anonymous delivery.
#[must_use]
pub fn parse_host_register(delivery: &[u8]) -> Option<HostRegister> {
    let body = delivery.strip_prefix(HOST_REGISTER_TAG.as_slice())?;
    HostRegister::decode(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wrapper_round_trips() {
        let req = Request {
            cookie: *b"session-cookie16",
            service_tag: [0x5B; 32],
            reply_circuit: vec![[1, 2, 3], [4, 5, 6]],
            payload: b"inner diaulos bytes".to_vec(),
            reply_pub: b"nostos-reply-public-key".to_vec(),
        };
        let wire = req.encode();
        assert_eq!(Request::decode(&wire), Some(req));
        // Too short to hold even the cookie.
        assert!(Request::decode(&[]).is_none());
        assert!(Request::decode(&[0; 15]).is_none());
        // A cookie but no service_tag is truncated (the fixed 16 + 32 header is incomplete).
        assert!(Request::decode(&[0; 16]).is_none());
        assert!(Request::decode(&[0; 47]).is_none());
        // The full 48-byte header but no reply_circuit hop-count varint is truncated.
        assert!(Request::decode(&[0; 48]).is_none());
    }

    #[test]
    fn request_wrapper_boundary_shapes() {
        // Empty reply circuit, payload, and reply key — the minimal wrapper: 16 cookie ‖ 32 tag ‖
        // varint(0)×3.
        let bare = Request {
            cookie: [0xAB; 16],
            service_tag: [0; 32],
            reply_circuit: vec![],
            payload: vec![],
            reply_pub: vec![],
        };
        let wire = bare.encode();
        assert_eq!(wire.len(), 16 + 32 + 3);
        assert_eq!(Request::decode(&wire), Some(bare));

        // A payload but no reply circuit (a follow-up cell that relies on the service's cookie binding).
        let follow = Request {
            cookie: [0xCD; 16],
            service_tag: [0x11; 32],
            reply_circuit: vec![],
            payload: b"cell-bytes".to_vec(),
            reply_pub: vec![],
        };
        assert_eq!(Request::decode(&follow.encode()), Some(follow));

        // The varint hop count lifts the old 255-hop `u8` ceiling (which silently truncated): a 300-hop
        // circuit round-trips exactly — `16 cookie ‖ 32 tag ‖ varint(300)=2 ‖ 300×12 triples ‖ varint(4)=1
        // ‖ 4 ‖ varint(0)`.
        let big = Request {
            cookie: [1; 16],
            service_tag: [0x22; 32],
            reply_circuit: (0..300u32)
                .map(|i| [i, i.wrapping_add(1), i.wrapping_add(2)])
                .collect(),
            payload: b"tail".to_vec(),
            reply_pub: vec![],
        };
        let wire = big.encode();
        assert_eq!(wire.len(), 16 + 32 + 2 + 300 * 12 + 1 + 4 + 1);
        assert_eq!(Request::decode(&wire), Some(big));
    }

    #[test]
    fn host_register_round_trips_and_parses_by_tag() {
        // The primary onion path: a real dead-drop forward circuit + NOSTOS reply key, all-zero coordinate.
        let reg = HostRegister {
            service_tag: [0x5B; 32],
            reply_pub: b"service-nostos-reply-key".to_vec(),
            forward_circuit: vec![[1, 2, 3], [4, 5, 6]],
            coordinate: [0, 0, 0],
        };
        assert_eq!(HostRegister::decode(&reg.encode()), Some(reg.clone()));

        // A tagged onion body parses back through the combiner's classifier; a bare `Request` does not.
        let mut body = Vec::new();
        body.extend_from_slice(HOST_REGISTER_TAG);
        body.extend_from_slice(&reg.encode());
        assert_eq!(parse_host_register(&body), Some(reg));
        let req = Request {
            cookie: [0xAB; 16],
            service_tag: [0; 32],
            reply_circuit: vec![],
            payload: b"a client request, not a registration".to_vec(),
            reply_pub: vec![],
        };
        assert!(
            parse_host_register(&req.encode()).is_none(),
            "a client Request is not misread as a host registration",
        );

        // The bare-host fallback: empty forward circuit + reply key, a real coordinate.
        let fallback = HostRegister {
            service_tag: [0x11; 32],
            reply_pub: vec![],
            forward_circuit: vec![],
            coordinate: [7, 8, 9],
        };
        assert_eq!(HostRegister::decode(&fallback.encode()), Some(fallback));
    }

    #[test]
    fn service_tag_is_one_way_epoch_rotating_and_service_specific() {
        let a = service_tag(b"svc-A", Epoch::new(5));
        // Deterministic in its inputs.
        assert_eq!(a, service_tag(b"svc-A", Epoch::new(5)));
        // Rotates per epoch, and separates distinct services — so co-located hosts never collide.
        assert_ne!(a, service_tag(b"svc-A", Epoch::new(6)), "the tag rotates per epoch");
        assert_ne!(a, service_tag(b"svc-B", Epoch::new(5)), "distinct services get distinct tags");
        // A real tag is never the all-zero "none" sentinel.
        assert_ne!(a, [0u8; 32]);
    }
}
