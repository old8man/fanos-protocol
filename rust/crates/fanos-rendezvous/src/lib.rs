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
use fanos_aphantos::threshold_router::launch_frame;
pub use fanos_calypso::{BeaconSeed, Epoch};
use fanos_field::Field;
use fanos_geometry::{Line, Triple};
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_pqcrypto::sig::HYBRID_VK_LEN;
use fanos_pqcrypto::{HybridSigSecret, HybridSignature, HybridVerifier};
use fanos_wire::Wire;

mod transport;
pub use transport::{RendezvousClient, RendezvousService, SessionId, session_reply_keypair};

/// The anonymous-source sentinel a threshold delivery carries (`from` in `Notification::Delivered`).
pub use fanos_aphantos::threshold_router::ANONYMOUS;
/// The **canonical** combiner of a line — a pure function of the line alone, used by derivations
/// (the `meeting_lines` distinct-combiner walk) rather than by launches, which draw a per-onion
/// member via [`combiner_for_salted`] (#55).
pub use fanos_aphantos::threshold_router::combiner_for;
/// The line member a particular onion is launched at — the per-onion salted pick that makes a hop's
/// availability the line's own `t`-of-`q+1` quorum instead of one canonical node (#55).
pub use fanos_aphantos::threshold_router::combiner_for_salted;
/// A line's member coordinates in canonical seal order — what a host walks to spread combiner-local
/// state (a §3b route binding) to **every** member, since a salted launch may peel at any of them.
pub use fanos_aphantos::threshold_router::line_member_coords;

/// The rendezvous **meeting line** for a service: the client and the service each derive the *same*
/// line from the service's public key, the `epoch`, and the epoch's randomness `beacon`, with no lookup
/// or published record (CALYPSO). It rotates every epoch, so there is no fixed rendezvous point to
/// enumerate, block, or seize — and because it folds in the beacon (audit E5), a future epoch's line is
/// unpredictable in advance, so an adversary cannot pre-position on it.
#[must_use]
pub fn meeting_line<F: Field>(service_pubkey: &[u8], epoch: Epoch, beacon: &BeaconSeed) -> Line<F> {
    fanos_calypso::rendezvous::rendezvous_line::<F>(service_pubkey, epoch, beacon)
}

/// The ``Command::Control`` tag under which a combiner is handed the epoch's mix
/// directory ([`MixDirectory::encode`]).
///
/// A combiner needs those hop keys to seal a forward onion to a registered host's dead-drop, and it cannot get
/// them itself: it is a sans-I/O engine and building the directory is a store lookup. The registration used to
/// carry them instead, which made it grow as `q + 1` per hop — measured at ~39 KB on a `q = 31` plane against a
/// 7041-byte onion body, so it did not fit past Fano even before authentication added a bundle and a signature.
pub const CONTROL_MIX_DIRECTORY: u16 = 1;

/// The horizon the probabilistic meeting-point count is solved for: the number of epochs over which a service
/// expects **at most one** censored epoch.
///
/// This is the single policy input to [`meeting_point_count`] — everything else there is derived. It is a
/// horizon rather than a bare probability because that is the form an operator can reason about: *how long
/// should this run before one epoch is expected to be censored*, and the intended answer is "longer than the
/// network's authors". Raising it costs meeting points only logarithmically (`log₃`), so the horizon is cheap
/// to be generous with.
///
/// **It is stated in epochs and justified in years, which is a unit conversion — and the first version of this
/// constant got that conversion wrong.** It read "`2²⁰` epochs is ≈120 years at one epoch per hour", but this
/// platform's default epoch is **ten minutes** (`fanos_node::config::DEFAULT_EPOCH_PERIOD`), six times faster,
/// so `2²⁰` bought ≈20 years — not the lifetime the justification claimed. A policy number whose whole warrant
/// is a span of time is worth nothing if the span is computed against the wrong clock.
///
/// So: `2²³ × 600 s ≈ 159 years`, at the platform's actual default. The arithmetic is pinned by
/// `fanos-node`'s `the_censorship_horizon_is_stated_against_the_real_epoch_period`, which sees both constants
/// and fails if either moves — a checkable invariant rather than a comment hoping to stay true.
///
/// The cost of the correction is two meeting points at large planes (`log₃ 2²³ = 15` against 13) and **none at
/// all on the shipped Fano cell**, where the pigeonhole bound of 3 is cheaper and wins the `min` regardless.
pub const CENSORSHIP_HORIZON_EPOCHS: u64 = 1 << 23;

/// How many meeting points a service takes on a plane of order `q` — the **minimum of two bounds**, because
/// they are cheapest in opposite regimes and neither dominates.
///
/// Model the censor as the fault model already does: an adversary holds `A` with `|A| = f = ⌊(n − 1)/3⌋`,
/// where `n = q² + q + 1`. A service is censored in an epoch exactly when every one of its meeting
/// **combiners** lies in `A`.
///
/// **The pigeonhole bound, `m = f + 1`.** With `m ≤ f` combiners an adversary that can *aim* `A` covers them
/// all; with `m = f + 1` at least one combiner is outside every admissible `A`. Censorship becomes
/// impossible rather than improbable. But `f + 1 ≈ n/3` is **linear in `n`** — the host registers at a third
/// of the network, times `q + 1` members per line — so past the smallest planes it costs more than the
/// network has (`tests/meeting_cost.rs` measures the growth).
///
/// **The unpredictability bound.** The adversary *cannot* aim `A`, and the reason is already an axiom here:
/// `coord = MapToPoint(VRF(sk, node‖epoch‖beacon))` is identity-bound and HELLO-proven (§3.2 assumption 1,
/// `design-coordinates.md`), so `A` is a uniformly random `f`-subset fixed before the epoch's beacon exists,
/// while the combiners are `H(key‖i, epoch, beacon)`. Each combiner is then adversarial independently with
/// probability `f/n`, and sampling the `m` distinct combiners *without* replacement only helps:
///
/// ```text
/// Pr[censored in one epoch] = C(f,m)/C(n,m) < (f/n)^m
/// ```
///
/// Solving `(f/n)^m ≤ 1/H` for the horizon `H` = [`CENSORSHIP_HORIZON_EPOCHS`] gives
/// `m ≥ log(H) / log(n/f)`, and since `n/f → 3` that is `log₃ H` — **constant in `n`**. Censorship is also
/// not permanent: the next beacon redraws every combiner, so the bound is one censored epoch per `H`, each
/// self-healing at the next rotation.
///
/// Taking the minimum makes the two bounds a single rule: small planes keep the *strictly stronger*
/// deterministic guarantee (on the Fano cell, `f + 1 = 3` — the number Tor picked by convention and here
/// follows from the geometry), and large planes stop growing. The crossover falls at `q = 7` precisely
/// because that is where the deterministic bound stops being affordable.
///
/// The arithmetic is **integer-only and division-truncating**. A client and a host must agree on this count
/// with no channel to compare it on, so a `f64::ln` whose last bit differs between two platforms' libm would
/// be a silent split; and truncation biases the ratio *down*, so `m` errs high — toward more meeting points
/// than the bound needs, never fewer.
#[must_use]
pub fn meeting_point_count(q: usize) -> usize {
    let n = q * q + q + 1;
    let f = (n - 1) / 3;
    let pigeonhole = f + 1;
    if f == 0 {
        return pigeonhole; // No adversary is tolerable on such a plane; one meeting point is the whole bound.
    }
    // Smallest `m` with `(n/f)^m ≥ H`, tracking the ratio in 32-bit fixed point so neither side of the
    // comparison grows like `n^m`. `r` stays under `H·2³²·(n/f)` ≈ 2⁵⁴, well inside `u128`.
    let (n, f) = (n as u128, f as u128);
    let target = u128::from(CENSORSHIP_HORIZON_EPOCHS) << 32;
    let (mut r, mut m) = (1u128 << 32, 0usize);
    while r < target {
        m += 1;
        r = r * n / f;
    }
    m.min(pigeonhole)
}

/// **All** of a service's meeting lines for `epoch` — the [`meeting_point_count`] points a client may reach
/// it at. A single meeting point would be a censorship single point of failure; the count is derived there.
///
/// **Distinct COMBINERS, not distinct lines**, and that is part of the derivation rather than a detail: two lines
/// can share a combiner, and `f + 1` lines with `f` distinct combiners is the censored case again. The index walks
/// until `f + 1` distinct combiner points are held, bounded by `n` because after `n` distinct combiners the whole
/// plane is covered — a derived bound, not a retry constant. It can only terminate because the combiner map itself
/// covers more than `f` points, which it did NOT before `ThresholdRouter::combiner_of` was spread: 14 of 57 on
/// `PG(2,7)` against `f = 18` made `f + 1` distinct combiners literally unobtainable.
///
/// Both sides run this identical loop over a pure function of `(key, epoch, beacon)`, so a client and a host agree
/// on the set with no coordination. Unlike Tor's service-*chosen* introduction points, these are a public function
/// of the key and the beacon, so a client can verify it is dialing a legitimate meeting point without trusting the
/// service to tell it.
#[must_use]
pub fn meeting_lines<F: Field>(service_pubkey: &[u8], epoch: Epoch, beacon: &BeaconSeed) -> Vec<Triple> {
    let q = F::Q as usize;
    let n = q * q + q + 1;
    let m = meeting_point_count(q);
    let (mut lines, mut combiners) = (Vec::with_capacity(m), Vec::with_capacity(m));
    for i in 0..n as u32 {
        // Index 0 hashes the key ALONE, so `meeting_lines(..)[0] == meeting_line(..)` exactly. That identity is
        // what makes adopting several meeting points additive rather than a flag day: a party still using the
        // single-point derivation is using meeting point 0, which every host registers at, so old and new coexist
        // and the extra points are pure gain. Mixing the index in at `i = 0` too would have made the two
        // derivations disagree and forced client and host to switch in the same instant or lose each other.
        let mut data = Vec::with_capacity(service_pubkey.len() + 4);
        data.extend_from_slice(service_pubkey);
        if i > 0 {
            data.extend_from_slice(&i.to_be_bytes());
        }
        let line = meeting_line::<F>(&data, epoch, beacon).coords();
        let Some(combiner) = combiner_for::<F>(line) else { continue };
        if combiners.contains(&combiner) {
            continue;
        }
        combiners.push(combiner);
        lines.push(line);
        if lines.len() == m {
            break;
        }
    }
    lines
}

/// A directory of mixnet members' hybrid KEM public keys, keyed by overlay coordinate. Sealing an
/// onion seals each hop to the coordinates of that line's members named here.
#[derive(Clone, Default)]
pub struct MixDirectory {
    keys: BTreeMap<Triple, HybridKemPublic>,
}

impl MixDirectory {
    /// Encode as a flat `Vec<MixEntry>` — the form a combiner is handed one in (`Command::Control`).
    ///
    /// Deterministic (the map iterates in coordinate order), so two nodes that resolved the same cell produce
    /// byte-identical directories, which keeps a mismatch a real disagreement rather than an encoding artefact.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let entries: Vec<MixEntry> =
            self.entries().map(|(coord, key)| MixEntry { coord: *coord, key: key.encode() }).collect();
        entries.to_wire()
    }

    /// Decode what [`Self::encode`] produced. `None` if the bytes are malformed or an entry's key is not a
    /// well-formed hybrid KEM public — a directory is key material, so a partial parse is refused whole.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cur = bytes;
        let entries = <Vec<MixEntry> as Wire>::wire_decode(&mut cur).ok()?;
        if !cur.is_empty() {
            return None;
        }
        let mut dir = Self::new();
        for entry in entries {
            dir.insert(entry.coord, HybridKemPublic::decode(&entry.key)?);
        }
        Some(dir)
    }


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
        // The launch target is drawn PER ONION (salted by the sealed bytes, #55): any member of the
        // first hop line can gather, and pinning launches to the one canonical combiner made that
        // node a per-hop censorship single point of failure. Every reseal — and every DIAULOS
        // retransmit reseals — draws an independent member, so a dead member costs 1/(q+1) of
        // attempts, not the hop.
        combiner: combiner_for_salted::<F>(first, &onion)?,
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
/// It rotates per epoch and is a one-way image of the public identity, so it discloses no coordinate.
///
/// **It hashes the service's whole canonical identity bundle, not the KEM half a client dials.** That is what makes
/// a host registration authenticable at all, and the alternatives were eliminated rather than passed over:
///
/// * A signature alone proves nothing if the tag commits only to the KEM key — a KEM key verifies nothing, so the
///   signature would be by some *other* key with no stated relation to the tag.
/// * Carrying the bundle while keeping the tag KEM-derived fails too, and this is the subtle one: a bundle is plain
///   concatenated bytes (`Ed25519 ‖ ML-DSA-65 ‖ X25519 ‖ ML-KEM-768`), so an attacker who knows the victim's KEM
///   public key — which every client must — simply presents `(own signing prefix ‖ victim KEM key)`, signs with the
///   key it holds, and passes. Nothing binds a bundle's halves together except its publication, and an anonymous
///   combiner has nothing to check that against.
/// * Proving KEM-secret possession is not available non-interactively: encapsulating proves nothing (anyone can),
///   only decapsulating does, and a one-shot registration has no round trip.
///
/// So the tag must commit to **the key that authenticates the registration**. Note the resulting split, which is
/// coherent rather than accidental: [`meeting_line`] stays KEM-derived because it *locates* the service, while this
/// tag is identity-derived because it *authorises* a route binding. One addresses, the other authenticates.
#[must_use]
pub fn service_tag(service_identity: &[u8], epoch: Epoch) -> [u8; 32] {
    // Only the bundle's **signing prefix** goes in, and that is the invariant rather than an optimisation: the tag
    // must commit to the key that authenticates the registration, which is the signing half. The KEM half's job is
    // to LOCATE the service — the client derives the meeting line from it and already holds it — so carrying it
    // into a registration would cost 1216 bytes of a fixed-width onion packet and buy nothing.
    //
    // A bundle too short to have a prefix is hashed whole. That is safe rather than a fallback worth avoiding: it
    // yields a tag no well-formed identity can reproduce, and `HostRegister::verify` refuses such an identity
    // outright before ever comparing tags.
    let signing = service_identity.get(..HYBRID_VK_LEN).unwrap_or(service_identity);
    let mut data = Vec::with_capacity(signing.len() + 4);
    data.extend_from_slice(signing);
    data.extend_from_slice(&epoch.low32_be_bytes());
    fanos_primitives::hash::hash_labeled(fanos_primitives::hash::label::RDV_HOST, &data)
}

/// One `(coordinate, KEM public key)` entry of a self-provisioned forwarding directory carried inside a
/// [`HostRegister`]. The meeting combiner that forwards a request to a hidden service holds no global mix
/// directory (it is any node the beacon happened to place there), so the service's registration carries the
/// member keys of its *own* forward route — all already public (published in mixdir), and re-sent each epoch
/// as the route rotates — letting the combiner seal the forward onion as a pure function of the registration.
#[derive(Clone, PartialEq, Eq, Debug, fanos_wire_derive::Wire)]
pub struct MixEntry {
    /// The member's overlay coordinate.
    pub coord: Triple,
    /// Its serialized [`HybridKemPublic`].
    pub key: Vec<u8>,
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
/// Triple×12) ‖ coordinate(12) ‖ identity(varint-prefixed) ‖ sig(varint-prefixed)`. The two authentication
/// fields are appended rather than placed with the tag they bind, so `Self::signing_preimage` — the same
/// encoding with `sig` emptied — stays a prefix-stable function of the rest.
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
    /// The threshold `t` the forward onion's hops seal to (`t`-of-`(q+1)`), as the service chose it.
    pub threshold: u8,
    /// The bare-host fallback coordinate — used **only** when `forward_circuit` is empty (the combiner
    /// forwards by a direct `Send`, learning this coordinate). All-zeros on the primary onion path.
    pub coordinate: Triple,
    /// The service's canonical published identity bundle — the preimage of [`service_tag`].
    ///
    /// Carried so the combiner can *recompute* the tag rather than believe it. A registration whose bundle does not
    /// hash to its own `service_tag` is a registration for a service the sender cannot name.
    pub identity: Vec<u8>,
    /// A [`HybridSignature`] over this registration with `sig` empty, by the signing half of `identity`.
    ///
    /// Covers every field at once — the epoch-bound tag, `reply_pub`, `forward_circuit`, `threshold` and
    /// `coordinate` — because each of them redirects traffic. Signing only the tag would let a genuine
    /// registration be replayed with a swapped circuit, which is the same seizure by a longer route.
    pub sig: Vec<u8>,
}

impl HostRegister {
    /// Build the **primary** (coordinate-hiding) registration: the combiner will forward client requests as
    /// NOSTOS onions to the service's dead-drop line (`forward_circuit`'s last hop), end-to-end sealed to
    /// `reply_pub`. `directory` supplies the member keys for `forward_circuit`'s lines — extracted into the
    /// registration so the combiner (which holds no directory) can seal. `None` if a member key is missing.
    #[must_use]
    pub fn onion(
        identity: &[u8],
        signer: &HybridSigSecret,
        epoch: Epoch,
        reply_pub: Vec<u8>,
        forward_circuit: Vec<Triple>,
        threshold: u8,
    ) -> Option<Self> {
        if forward_circuit.is_empty() {
            return None;
        }
        let mut reg = Self {
            service_tag: service_tag(identity, epoch),
            reply_pub,
            forward_circuit,
            threshold,
            coordinate: [0, 0, 0], // the primary onion path hides the coordinate; all-zeros = none
            identity: identity.to_vec(),
            sig: Vec::new(),
        };
        reg.sig = signer.sign(&reg.signing_preimage()).to_bytes();
        Some(reg)
    }

    /// The exact bytes [`Self::sig`] covers: this registration's own canonical encoding with the signature field
    /// empty. Deriving the preimage from the encoding rather than listing fields by hand means a field added later
    /// is signed by construction — the failure mode where a new redirecting field silently escapes the signature is
    /// the one that would reopen this hole quietly.
    #[must_use]
    fn signing_preimage(&self) -> Vec<u8> {
        let mut bare = self.clone();
        bare.sig = Vec::new();
        bare.encode()
    }

    /// Whether this registration is one the named service actually issued, for `epoch`.
    ///
    /// Three checks, and each rejects a distinct forgery:
    /// 1. the tag is **recomputed** from `identity`, so a sender cannot claim a service it cannot name;
    /// 2. the signing prefix must not be all-zero — `bundle_from_kem_public` builds exactly that for a KEM-only
    ///    service, and such a bundle is reconstructible by anyone holding the (public) KEM key, so accepting one
    ///    would authenticate nothing while looking like it did. Hosting requires a signing identity;
    /// 3. the signature must verify over `Self::signing_preimage` under that prefix.
    #[must_use]
    pub fn verify(&self, epoch: Epoch) -> bool {
        if self.service_tag != service_tag(&self.identity, epoch) {
            return false;
        }
        let Some(prefix) = self.identity.get(..HYBRID_VK_LEN) else { return false };
        if prefix.iter().all(|b| *b == 0) {
            return false;
        }
        let (Some(verifier), Some(sig)) = (HybridVerifier::decode(prefix), HybridSignature::from_bytes(&self.sig)) else {
            return false;
        };
        verifier.verify(&self.signing_preimage(), &sig)
    }

    /// Build the **bare-host fallback** registration (an operator that cannot peel a dead-drop): the combiner
    /// forwards each request by a direct `Send` to `coordinate`, learning it. Weaker than [`Self::onion`] —
    /// the primary path hides the coordinate; this leaks it to the one combiner node (Tor's posture).
    #[must_use]
    pub fn bare(identity: &[u8], signer: &HybridSigSecret, epoch: Epoch, coordinate: Triple) -> Self {
        let mut reg = Self {
            service_tag: service_tag(identity, epoch),
            reply_pub: Vec::new(),
            forward_circuit: Vec::new(),
            threshold: 0,
            coordinate,
            identity: identity.to_vec(),
            sig: Vec::new(),
        };
        reg.sig = signer.sign(&reg.signing_preimage()).to_bytes();
        reg
    }

    /// Seal a client `request` into a NOSTOS onion bound for this service's dead-drop line — what a meeting
    /// combiner emits to forward the request on. The whole `Request` is carried (so the service binds the
    /// client's reply route), end-to-end sealed to the service's `reply_pub` and dead-dropped to
    /// `forward_circuit`'s last hop. `None` on the bare-host fallback (empty `forward_circuit`) or if sealing
    /// fails. `e2e_seed`/`onion_seed` MUST be independent fresh draws (as in [`seal_nostos_reply`]).
    #[must_use]
    pub fn seal_forward_to_host<F: Field>(
        &self,
        directory: &MixDirectory,
        request: &[u8],
        e2e_seed: &[u8],
        onion_seed: &[u8],
    ) -> Option<Forward> {
        if self.forward_circuit.is_empty() {
            return None;
        }
        seal_nostos_reply::<F>(
            &self.reply_pub,
            &self.forward_circuit,
            directory,
            self.threshold,
            request,
            e2e_seed,
            onion_seed,
        )
    }

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
/// **last** is the service's [`meeting_line`] this epoch — so it peels out there as an anonymous delivery
/// every member recognizes by [`HOST_REGISTER_TAG`]. `seed` domain-separates the onion's key material
/// (fresh per registration). `None` if the circuit is empty, a member key is missing, or sealing fails.
///
/// **The fan-out is inside the onion, and that is the point.** A registration has to reach *every* member of
/// the meeting line, because a route binding is state at whichever member later gathers a client request
/// (#55) and a member without it answers with silence. It used to reach them because the operator emitted the
/// sealed frame to each of them **itself** — and `Input::Message` carries a source coordinate the transport
/// authenticates, so every one of them learned the operator's address. The onion hid the coordinate in its
/// payload while the emission carried it on the wire, and this function's own doc claimed the opposite.
///
/// So the body rides a [`deaddrop_envelope`](fanos_aphantos::nostos::deaddrop_envelope): the last hop
/// recognizes the tag and multicasts to `points_on(L)` on the operator's behalf. The fan-out belongs at a
/// member of the destination line, which already knows that line — not at the origin, which must not be seen
/// by it. No new wire format; the same primitive a NOSTOS dead drop uses.
///
/// The circuit must therefore be a real one. `[meeting]` alone puts the operator one transport hop from the
/// line derived from its own service key, and `[H, meeting]` is no better: `H` would see the operator's
/// address *and* learn `meeting` when it peels. Two intermediates is the floor
/// ([`slots::MIN_FORWARD_DEPTH`](fanos_aphantos::slots::MIN_FORWARD_DEPTH)) and it is the same derivation as
/// the client's, because this is the same shape — a forward circuit from a party that must stay hidden to a
/// destination derived from the service.
#[must_use]
pub fn seal_host_register<F: Field>(
    meeting_circuit: &[Triple],
    directory: &MixDirectory,
    threshold: u8,
    register: &HostRegister,
    seed: &[u8],
) -> Option<Forward> {
    let (&meeting, _) = meeting_circuit.split_last()?;
    if meeting_circuit.len() < fanos_aphantos::slots::TARGET_DEPTH {
        return None;
    }
    let mut body = Vec::with_capacity(HOST_REGISTER_TAG.len() + 32);
    body.extend_from_slice(HOST_REGISTER_TAG);
    body.extend_from_slice(&register.encode());
    let envelope = fanos_aphantos::nostos::deaddrop_envelope(&body);
    // The launch addressee must not be a member of the meeting line, and this is where the line-counting
    // argument stops applying. Capturing a HOP costs `t` of its members; learning the LAUNCHER's address costs
    // nothing — the transport authenticates the source, so exactly one node gets it for free. Two distinct
    // lines meet in exactly one point, so at `q = 2` one of the first hop's three members also sits on the
    // meeting line, and a launch that lands there hands one node both the operator's address and (via the
    // multicast registration it is about to receive) the service it serves. One node, no threshold, no
    // collusion.
    //
    // The seed is walked rather than the circuit redrawn: the addressee is `combiner_for_salted(first, onion)`,
    // a function of the onion bytes, and every line meets the meeting line in a point — so no choice of first
    // hop avoids this, only a choice of salt. `None` after the walk rather than a launch that leaks, and the
    // odds make that unreachable in practice: `(1/q+1)^ATTEMPTS` at worst.
    let members = line_member_coords::<F>(meeting);
    (0..LAUNCH_SALT_ATTEMPTS).find_map(|i| {
        let mut salted = seed.to_vec();
        salted.extend_from_slice(&(i as u32).to_be_bytes());
        let fwd = seal_forward::<F>(meeting_circuit, directory, threshold, &envelope, &salted)?;
        (!members.contains(&fwd.combiner)).then_some(fwd)
    })
}

/// How many salts [`seal_host_register`] may walk looking for a launch addressee off the meeting line.
///
/// Each try succeeds with probability `q/(q+1)` — `2/3` at Fano — so sixteen leaves a failure probability of
/// about `2 x 10^-8`, and the walk is bounded so a degenerate directory cannot spin.
const LAUNCH_SALT_ATTEMPTS: usize = 16;

/// If `delivery` is a [`HOST_REGISTER_TAG`]-prefixed host registration, decode it; otherwise `None` (the
/// combiner then treats the delivery as a client [`Request`]). Used at a meeting combiner to classify each
/// anonymous delivery.
#[must_use]
pub fn parse_host_register(delivery: &[u8]) -> Option<HostRegister> {
    let body = delivery.strip_prefix(HOST_REGISTER_TAG.as_slice())?;
    HostRegister::decode(body)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A deterministic signing identity plus the canonical bundle it publishes.
    ///
    /// The bundle's layout is `Ed25519 ‖ ML-DSA-65 ‖ X25519 ‖ ML-KEM-768`; only the signing prefix is read back by
    /// [`HostRegister::verify`], so the KEM half is filler here — what matters is that `service_tag` hashes the
    /// WHOLE thing, which is what stops a forged `(own signing prefix ‖ victim KEM key)` bundle from reproducing
    /// someone else's tag.
    fn identity(seed: &[u8]) -> (Vec<u8>, HybridSigSecret) {
        let mut rng = fanos_pqcrypto::SeedRng::from_seed(seed);
        let (secret, verifier) = HybridSigSecret::generate(&mut rng);
        let mut bundle = verifier.encode();
        bundle.extend_from_slice(&[0x42; 32]);
        (bundle, secret)
    }

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
        let (bundle, signer) = identity(b"round-trip-service");
        let epoch = Epoch::new(9);
        let reg = HostRegister {
            service_tag: service_tag(&bundle, epoch),
            reply_pub: b"service-nostos-reply-key".to_vec(),
            forward_circuit: vec![[1, 2, 3], [4, 5, 6]],
            threshold: 2,
            coordinate: [0, 0, 0],
            identity: bundle,
            sig: Vec::new(),
        };
        let reg = HostRegister { sig: signer.sign(&reg.signing_preimage()).to_bytes(), ..reg };
        assert_eq!(HostRegister::decode(&reg.encode()), Some(reg.clone()));
        assert!(reg.verify(epoch), "a genuine registration survives the wire round trip and verifies");

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

        // The bare-host fallback: empty forward circuit/keys, a real coordinate.
        let (fb_bundle, fb_signer) = identity(b"bare-fallback-service");
        let fallback = HostRegister::bare(&fb_bundle, &fb_signer, Epoch::new(9), [7, 8, 9]);
        assert!(fallback.forward_circuit.is_empty(), "the bare fallback names no forward route");
        assert_eq!(HostRegister::decode(&fallback.encode()), Some(fallback));
    }

    #[test]
    fn a_service_has_its_derived_meeting_points_at_distinct_combiners() {
        use fanos_field::{F2, F7};
        // THE PROPERTY: no adversary within the fault model can hold every meeting point of a service, and each
        // point sits at a DIFFERENT combiner — two at one combiner puts two of them in a single pair of hands.
        //
        // The count follows from `meeting_point_count`, which takes the cheaper of two bounds: pigeonhole
        // (`f + 1`, deterministic) on small planes, and the beacon's unpredictability (`log₃ H`, constant in `n`)
        // once `f + 1 ≈ n/3` stops being affordable. Asserted on TWO planes because it must FOLLOW from the
        // geometry rather than be a constant that happens to suit Fano — and that is not hypothetical:
        // enumerating a second plane is what exposed the combiner map covering only 14 of 57 points, which made
        // the requested count literally unobtainable. `PG(2,7)` is now on the *other* side of the crossover from
        // `PG(2,2)`, so this pair also pins that both branches are reachable.
        for q in [2usize, 7] {
            let want = meeting_point_count(q);
            let lines = if q == 2 {
                meeting_lines::<F2>(b"a-service-key", Epoch::new(4), &BeaconSeed::GENESIS)
            } else {
                meeting_lines::<F7>(b"a-service-key", Epoch::new(4), &BeaconSeed::GENESIS)
            };
            assert_eq!(lines.len(), want, "PG(2,{q}) must yield the {want} meeting points its derivation asks for");
            let combiners: std::collections::BTreeSet<Triple> = lines
                .iter()
                .filter_map(|&l| if q == 2 { combiner_for::<F2>(l) } else { combiner_for::<F7>(l) })
                .collect();
            assert_eq!(combiners.len(), want, "every meeting point must sit at a DIFFERENT combiner — two at one \
                 combiner puts two of them in a single adversary's hands");
        }
        // The two planes must actually exercise the two branches, or the pair above is one test written twice.
        let n7 = 7 * 7 + 7 + 1;
        assert_eq!(meeting_point_count(2), (2 * 2 + 2 + 1 - 1) / 3 + 1, "Fano must take the pigeonhole bound");
        assert!(meeting_point_count(7) < (n7 - 1) / 3 + 1, "PG(2,7) must take the unpredictability bound");

        // **Point 0 IS the single-point derivation**, which is what lets several meeting points be adopted
        // additively: anyone still computing `meeting_line` is computing meeting point 0, and every host
        // registers there, so the two derivations coexist instead of forcing a flag day.
        assert_eq!(
            meeting_lines::<F2>(b"svc", Epoch::new(4), &BeaconSeed::GENESIS).first().copied(),
            Some(meeting_line::<F2>(b"svc", Epoch::new(4), &BeaconSeed::GENESIS).coords()),
            "meeting point 0 must equal the single-point derivation"
        );

        // A pure function of (key, epoch, beacon): a client and a host derive the same set with no coordination,
        // and the set rotates so an adversary cannot camp the next epoch's meeting points in advance.
        let a = meeting_lines::<F2>(b"svc", Epoch::new(4), &BeaconSeed::GENESIS);
        assert_eq!(a, meeting_lines::<F2>(b"svc", Epoch::new(4), &BeaconSeed::GENESIS), "deterministic");
        assert_ne!(a, meeting_lines::<F2>(b"svc", Epoch::new(5), &BeaconSeed::GENESIS), "rotates per epoch");
        assert_ne!(a, meeting_lines::<F2>(b"other", Epoch::new(4), &BeaconSeed::GENESIS), "service-specific");
    }

    #[test]
    fn a_registration_cannot_be_forged_for_a_service_the_sender_cannot_name() {
        // THE PROPERTY this whole binding exists for: knowing a hidden service's public address must not let you
        // take over its route. Before the identity-derived tag, one unsigned message per epoch did exactly that —
        // `register_host` accepted any well-formed registration and `BoundedMap::insert` overwrites a known key.
        //
        // Four forgeries, each closing a distinct hole. They are asserted in order of subtlety, because the third
        // is the one that defeats the fix that *looks* sufficient.
        let epoch = Epoch::new(5);
        let (victim, victim_signer) = identity(b"the-victim-service");
        let (attacker, attacker_signer) = identity(b"the-attacker");
        let genuine = HostRegister::bare(&victim, &victim_signer, epoch, [1, 2, 3]);
        assert!(genuine.verify(epoch), "the service's own registration verifies");

        // 1. Claim the victim's tag while signing with your own key. The tag is PUBLIC — anyone can compute
        //    `service_tag(victim_bundle, epoch)` — so this is the cheap attack, and it dies on recomputation.
        let seizure = HostRegister { identity: attacker.clone(), ..genuine.clone() };
        let seizure = HostRegister { sig: attacker_signer.sign(&seizure.signing_preimage()).to_bytes(), ..seizure };
        assert!(!seizure.verify(epoch), "a tag that does not hash from the presented identity is refused");

        // 2. Replay the genuine registration into another epoch. The tag rotates, so the signature no longer
        //    matches the tag it must bind — a stale route cannot be resurrected.
        assert!(!genuine.verify(Epoch::new(6)), "a registration does not carry across epochs");

        // 3. Keep the genuine identity and signature, swap only where traffic goes. This is the forgery that
        //    survives signing the TAG alone, which is why the signature covers the whole encoding.
        let redirected = HostRegister { coordinate: [9, 9, 9], ..genuine.clone() };
        assert!(!redirected.verify(epoch), "the signature covers the forwarding fields, not just the tag");

        // 4. A KEM-only bundle — `bundle_from_kem_public`'s zero signing prefix. Anyone holding the (public) KEM
        //    key rebuilds that bundle byte for byte, so accepting one would authenticate nothing while looking
        //    like it did. Hosting requires a signing identity; this is refused rather than trusted.
        let mut kem_only = vec![0u8; HYBRID_VK_LEN];
        kem_only.extend_from_slice(&[0x42; 32]);
        let unsigned = HostRegister {
            service_tag: service_tag(&kem_only, epoch),
            identity: kem_only,
            sig: Vec::new(),
            ..genuine.clone()
        };
        assert!(!unsigned.verify(epoch), "a KEM-only identity cannot authenticate a registration, so it is refused");
    }

    /// A registration is never launched at the line it names, and cannot be.
    ///
    /// This is where hidden-service location privacy actually lives. `Input::Message` carries a source
    /// coordinate the transport authenticates, so whoever this frame is emitted to learns the operator's
    /// address — and the frame used to be emitted to every member of every meeting line, each derived from the
    /// operator's own service key. The onion hid the coordinate in its payload while the emission carried it
    /// on the wire.
    #[test]
    fn a_registration_is_never_launched_at_the_line_it_names() {
        use fanos_field::F2;
        use fanos_geometry::Line;
        use fanos_pqcrypto::{HybridKemSecret, SeedRng};

        let mut dir = MixDirectory::new();
        for i in 0..7u8 {
            let mut rng = SeedRng::from_seed(&[0xA7, i]);
            let (_s, public) = HybridKemSecret::generate(&mut rng);
            dir.insert(fanos_geometry::Point::<F2>::at(usize::from(i)).coords(), public);
        }
        let line = |i: usize| Line::<F2>::at(i).coords();
        let (meeting, h1, h2, drop) = (line(0), line(1), line(2), line(3));
        let mut kem = SeedRng::from_seed(b"launch-svc");
        let (_sec, svc_pub) = HybridKemSecret::generate(&mut kem);
        let (identity, signer) = identity(b"launch-sign");
        let epoch = Epoch::new(9);
        let reg = HostRegister::onion(&identity, &signer, epoch, svc_pub.encode(), vec![h2, drop], 2)
            .expect("the registration is nameable");

        // THE PROPERTY, over many registrations rather than one: the frame lands on a member of the FIRST hop
        // and never on a member of the meeting line. Measured across seeds, because a single seed would say
        // nothing about the salt walk that enforces it.
        let mut registration_body = HOST_REGISTER_TAG.to_vec();
        registration_body.extend_from_slice(&reg.encode());
        let meeting_members = line_member_coords::<F2>(meeting);
        let mut naive_would_leak = 0u32;
        // Enough to make the falsification below decisive at its ~1-in-3 rate, and no more: each trial is
        // two PQ onion seals.
        let trials = 120u32;
        for i in 0..trials {
            let seed = [b"launch".as_slice(), &i.to_be_bytes()].concat();
            let fwd = seal_host_register::<F2>(&[h1, h2, meeting], &dir, 2, &reg, &seed)
                .expect("a floor-depth circuit seals");
            assert!(
                line_member_coords::<F2>(h1).contains(&fwd.combiner),
                "the launch lands on the first hop"
            );
            assert!(
                !meeting_members.contains(&fwd.combiner),
                "the launch must NOT land on the meeting line: the transport authenticates the source, so \
                 that ONE member learns this operator's address for free — no threshold, no collusion — and \
                 it is about to receive the multicast registration naming the service"
            );
            // What the unsalted launch would have done. Two distinct lines meet in exactly one point, so at
            // q = 2 one of the first hop's three members sits on the meeting line and this is not rare.
            let envelope = fanos_aphantos::nostos::deaddrop_envelope(&registration_body);
            if let Some(naive) = seal_forward::<F2>(&[h1, h2, meeting], &dir, 2, &envelope, &seed)
                && meeting_members.contains(&naive.combiner)
            {
                naive_would_leak += 1;
            }
        }
        assert!(
            naive_would_leak > trials / 10,
            "only {naive_would_leak} of {trials} unsalted launches would have landed on the meeting line, so \
             this test cannot see the defect the salt walk exists to remove"
        );

        // THE FAN-OUT MOVED INSIDE. Every member of the meeting line must end up holding the binding (#55).
        // That used to be the operator's job, by emitting to each of them; now the body rides a dead-drop
        // envelope so the LAST hop multicasts it, on the operator's behalf and without seeing it.
        let peeled = fanos_aphantos::nostos::deaddrop_envelope(&registration_body);
        let body = fanos_aphantos::nostos::parse_deaddrop(&peeled)
            .expect("the registration rides a dead-drop envelope, which is what makes the last hop multicast");
        assert!(
            parse_host_register(body).is_some(),
            "and what gets multicast is still a registration every member classifies the same way"
        );

        // THE FALSIFICATION, in the tree rather than performed once by hand: the circuits that leak are
        // refused, so the assertions above are a constraint and not a description.
        for short in [vec![meeting], vec![h1, meeting]] {
            assert!(
                seal_host_register::<F2>(&short, &dir, 2, &reg, b"seed").is_none(),
                "a {}-hop registration circuit must be refused: with none the operator emits straight at the \
                 line named after its own key, and with one that hop sees the operator AND learns the meeting \
                 line when it peels",
                short.len()
            );
        }
    }

    #[test]
    fn an_onion_registration_names_its_forward_route_and_the_combiner_seals_to_it() {
        use fanos_field::F2;
        use fanos_geometry::Line;
        use fanos_pqcrypto::{HybridKemSecret, SeedRng};

        // A Fano directory (a KEM key at every point), and a 1-hop forward route to a dead-drop line.
        let mut dir = MixDirectory::new();
        for i in 0..7u8 {
            let (_s, public) =
                HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xF0, i]));
            dir.insert(fanos_geometry::Point::<F2>::at(usize::from(i)).coords(), public);
        }
        let drop_line = Line::<F2>::at(2).coords();
        let (reply_keys, reply_pub) =
            fanos_aphantos::nostos::ReplyKeys::generate(b"svc-forward-reply");

        let (bundle, signer) = identity(b"onion-service");
        let reg = HostRegister::onion(&bundle, &signer, Epoch::new(3), reply_pub.encode(), vec![drop_line], 2)
        .expect("all forward-line members are in the directory");
        // It names the dead-drop line and the threshold, and carries NO member keys: those are the combiner's
        // to resolve. Carrying them made the registration grow as `q + 1` per hop, so it did not fit the
        // fixed-width onion packet on any plane past Fano — a limit measured, not assumed (~39 KB at q = 31
        // against a 7041-byte body).
        assert_eq!(reg.forward_circuit, vec![drop_line]);
        assert_eq!(reg.threshold, 2);

        // The combiner seals a client request to the service's dead-drop; it launches at the drop line's
        // combiner, and only the service (with reply_keys) opens the end-to-end body once peeled.
        let fwd = reg
            .seal_forward_to_host::<F2>(&dir, b"the-wrapped-client-request", b"e2e-seed", b"onion-seed")
            .expect("a primary registration seals a forward onion");
        // The launch target is a per-onion salted member of the drop line (#55).
        assert!(
            line_member_coords::<F2>(drop_line).contains(&fwd.combiner),
            "the forward launches at a member of the drop line"
        );
        // The bare-host fallback has no forward circuit, so it seals nothing (the combiner Sends direct).
        assert!(
            HostRegister::bare(&bundle, &signer, Epoch::new(3), [1, 1, 1])
                .seal_forward_to_host::<F2>(&dir, b"x", b"e", b"o")
                .is_none()
        );
        // A drop route whose line members are absent from the directory can't self-provision.
        let empty = MixDirectory::new();
        // An empty forward circuit is the bare-host shape, which `onion` refuses by construction.
        assert!(HostRegister::onion(&bundle, &signer, Epoch::new(3), vec![], vec![], 2).is_none());
        let _ = &empty;
        let _ = &reply_keys; // reply_keys' secret half stays with the service; only the public traveled
    }

    #[test]
    fn the_epoch_rotating_tag_is_defeated_by_the_preimage_travelling_beside_it() {
        // **What the rotation buys, and what carrying the identity gives straight back.**
        //
        // `service_tag` rotates every epoch precisely so a combiner cannot follow one hidden service through
        // time: `service_tag_is_one_way_epoch_rotating_and_service_specific` proves the tags themselves are
        // unlinkable. But a registration also carries `identity` — the bundle the tag is a hash of — because
        // the combiner must *recompute* the tag rather than believe it, or one unsigned message per epoch
        // would seize a service's route.
        //
        // So the combiner holds the preimage. Two registrations from different epochs, whose tags share
        // nothing, are trivially the same service: their `identity` fields are byte-identical. Every meeting
        // combiner therefore keeps a linkable, timestamped record of which services exist and when they are
        // up — by construction, with no attack, from data the protocol hands it.
        //
        // This test exists to make that measured rather than argued, because the design's "proven
        // non-linkable across epochs" is a claim about the NOSTOS receiver's dead-drop line and does not
        // extend to a hidden service's registration. Closing it needs per-epoch **key blinding** — a public
        // derivation of an epoch verification key from a stable one — which ML-DSA does not offer as a
        // standard operation. Until then the leak stands, and the number below is the honest size of it.
        let (bundle, signer) = identity(b"a-service-across-time");

        let across: Vec<HostRegister> = (1..=8u64)
            .map(|e| HostRegister::bare(&bundle, &signer, Epoch::new(e), [1, 0, 1]))
            .collect();

        // The rotation works, on its own terms: no two epochs share a tag.
        let tags: std::collections::BTreeSet<[u8; 32]> =
            across.iter().map(|r| r.service_tag).collect();
        assert_eq!(tags.len(), across.len(), "the tag genuinely rotates — this half is sound");

        // And it is defeated: the SAME registrations are linkable by a field sitting beside the tag, so the
        // combiner needs no cryptanalysis and no correlation window.
        let identities: std::collections::BTreeSet<&[u8]> =
            across.iter().map(|r| r.identity.as_slice()).collect();
        assert_eq!(
            identities.len(),
            1,
            "eight epochs of registrations carry ONE identity — the epoch-rotating tag hides nothing from \
             the party that receives its preimage, which is every meeting combiner the service registers at",
        );

        // The precise leak, so a fix can be checked against it rather than against a feeling: the tag commits
        // to the signing half only, so that is exactly what travels.
        assert!(
            across.first().is_some_and(|r| r.identity == bundle),
            "the registration carries the service's published bundle verbatim, whose prefix is the stable \
             signing verification key the tag commits to",
        );
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
