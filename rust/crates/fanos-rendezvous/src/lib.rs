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
pub use transport::{RendezvousClient, RendezvousService, SessionId};

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
/// payload(varint-prefixed)` (spec §7.1) — one derived codec for the wrapper, replacing the hand-rolled
/// `u8` hop-count + raw trailing payload.
#[derive(Clone, PartialEq, Eq, Debug, fanos_wire_derive::Wire)]
pub struct Request {
    /// A per-session cookie: the service demultiplexes concurrent clients by it and binds each to its
    /// reply circuit, so it need not learn who any client is.
    pub cookie: [u8; 16],
    /// Hop lines to the client's reply rendezvous (the last is where the client listens).
    pub reply_circuit: Vec<Triple>,
    /// The inner payload (a DIAULOS `ClientHello` or cell).
    pub payload: Vec<u8>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wrapper_round_trips() {
        let req = Request {
            cookie: *b"session-cookie16",
            reply_circuit: vec![[1, 2, 3], [4, 5, 6]],
            payload: b"inner diaulos bytes".to_vec(),
        };
        let wire = req.encode();
        assert_eq!(Request::decode(&wire), Some(req));
        // Too short to hold even the cookie.
        assert!(Request::decode(&[]).is_none());
        assert!(Request::decode(&[0; 15]).is_none());
        // A cookie but no hop-count byte is truncated.
        assert!(Request::decode(&[0; 16]).is_none());
        // A cookie but a truncated hop-line is rejected (16 cookie + count=2 + partial coord).
        assert!(
            Request::decode(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1
            ])
            .is_none()
        );
    }

    #[test]
    fn request_wrapper_boundary_shapes() {
        // Empty reply circuit and empty payload — the minimal wrapper: 16 cookie ‖ varint(0) ‖ varint(0).
        let bare = Request {
            cookie: [0xAB; 16],
            reply_circuit: vec![],
            payload: vec![],
        };
        let wire = bare.encode();
        assert_eq!(wire.len(), 18);
        assert_eq!(Request::decode(&wire), Some(bare));

        // A payload but no reply circuit (a follow-up cell that relies on the service's cookie binding).
        let follow = Request {
            cookie: [0xCD; 16],
            reply_circuit: vec![],
            payload: b"cell-bytes".to_vec(),
        };
        assert_eq!(Request::decode(&follow.encode()), Some(follow));

        // The varint hop count lifts the old 255-hop `u8` ceiling (which silently truncated): a 300-hop
        // circuit round-trips exactly — `16 cookie ‖ varint(300)=2 ‖ 300×12 triples ‖ varint(4)=1 ‖ 4`.
        let big = Request {
            cookie: [1; 16],
            reply_circuit: (0..300u32)
                .map(|i| [i, i.wrapping_add(1), i.wrapping_add(2)])
                .collect(),
            payload: b"tail".to_vec(),
        };
        let wire = big.encode();
        assert_eq!(wire.len(), 16 + 2 + 300 * 12 + 1 + 4);
        assert_eq!(Request::decode(&wire), Some(big));
    }
}
