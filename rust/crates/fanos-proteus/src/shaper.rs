//! The transport-layer shaper — PROTEUS as a driver wrapper (spec §13.2, §13.4).
//!
//! A driver (the QUIC transport, the simulator) wraps every outbound frame through a
//! [`ProteusShaper`] and unwraps every inbound one. The engine is untouched: the shaper lives
//! entirely below the sans-I/O boundary, exactly where the wire signature lives. Two peers holding
//! the same community secret derive the same epoch shape and so strip each other's wrapping; an
//! observer sees only shaped bytes with no fixed signature, and the shape **rotates every epoch**
//! (§13.4), so a classifier trained on one epoch is stale the next.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use fanos_primitives::Epoch;
use fanos_primitives::hash::hash_xof;

use crate::codec::MorphCodec;
use crate::datagram::{open_in_place, seal};
use crate::morph::Morph;
use crate::obfuscate::{NONCE_LEN, deobfuscate, obfuscate};
use crate::profile::ShapingProfile;
use crate::shape::{ShapeParams, epoch_shape};

const NONCE_LABEL: &str = "FANOS-v1/proteus-packet-nonce";

/// A shaped outbound frame: the wire bytes, and the [`Duration`] the driver should pace before putting them
/// on the wire (the traffic-shaper's timing directive — `Duration::ZERO` for morphs that do not time-shape).
/// The clock lives in the driver, never here, so PROTEUS stays below the sans-I/O boundary.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Shaped {
    /// The wire bytes to transmit.
    pub wire: Vec<u8>,
    /// How long to wait before transmitting `wire` (traffic-shaping pace).
    pub delay: Duration,
}

/// A stateful per-connection shaper: the selected [`Morph`] and its traffic-shaping profile, the community
/// secret, the current epoch's shape, and a monotonic packet counter that diversifies each packet's junk,
/// size, and timing (interior-mutable, so the shaper can be shared `&self` behind an `Arc` across a
/// connection's concurrent sends).
pub struct ProteusShaper {
    secret: Vec<u8>,
    morph: Morph,
    profile: ShapingProfile,
    /// A pluggable codec (the `pluggable` morph, §13.3 SPI); when set it replaces the built-in polymorph
    /// transform in [`shape`](Self::shape)/[`inbound`](Self::inbound).
    codec: Option<Arc<dyn MorphCodec>>,
    epoch: Epoch,
    /// The shapes derived from [`secret`](Self::secret) — the **emitting** set. Everything this node puts on
    /// the wire uses `shapes.current`; the rest of the set is receive-only.
    shapes: ShapeSet,
    /// Additional community secrets accepted on **receive only**, each with its own full [`ShapeSet`]
    /// (#13). Empty on a node that is not mid-rotation, which is almost every node almost always.
    ///
    /// The secret is kept beside its shapes because [`rotate`](Self::rotate) has to re-derive them: a shape
    /// is `PRF(secret, epoch)`, so an accepted secret whose shapes were computed once would go dark at the
    /// very next epoch turn while looking perfectly configured.
    accepted: Vec<(Vec<u8>, ShapeSet)>,
    counter: AtomicU64,
}

/// The three shapes one community secret yields at one epoch: what this node emits with, the
/// [`SHAPE_GRACE`] neighbours it also accepts, and the immobile genesis rendezvous shape.
///
/// Extracted so the **secret** axis and the **epoch** axis compose instead of multiplying (#13). Before this
/// the three lived as three fields of the shaper, which made "one more secret" mean "three more fields, and
/// remember all three in `rotate`" — the shape of defect where a family gets moved one member at a time.
struct ShapeSet {
    /// This secret's shape at the current epoch.
    current: ShapeParams,
    /// The neighbouring epochs' shapes, accepted on receive only: `[previous, next]`. See [`SHAPE_GRACE`]
    /// for why both, and why the pair is cached rather than derived per frame.
    grace: [ShapeParams; 2],
    /// The **genesis** shape, accepted on receive only, and only once the epoch has moved far enough that
    /// [`grace`](Self::grace) no longer covers it. See [`OpenedEpoch::Genesis`] for the deadlock it breaks.
    ///
    /// Cached like the grace pair and for the same reason: it must cost one `deobfuscate` on a frame nobody
    /// recognises, never a hash, or an attacker sending garbage chooses this node's CPU bill.
    genesis: ShapeParams,
}

impl ShapeSet {
    /// Every shape `secret` yields at `epoch`.
    fn for_secret(secret: &[u8], epoch: Epoch) -> Self {
        Self {
            current: epoch_shape(secret, epoch),
            grace: grace_shapes(secret, epoch),
            genesis: epoch_shape(secret, Epoch::ZERO),
        }
    }

    /// Move the set to `epoch`.
    ///
    /// `genesis` is deliberately NOT re-derived: it is `epoch_shape(secret, 0)` by definition and does not
    /// move. That immobility is the whole reason it can serve as a rendezvous shape for a node that knows no
    /// epoch, and it is also its only cost — see [`OpenedEpoch::Genesis`].
    fn rotate(&mut self, secret: &[u8], epoch: Epoch) {
        self.current = epoch_shape(secret, epoch);
        self.grace = grace_shapes(secret, epoch);
    }

    /// Which arm of this set opens `wire` as a **frame**, if any. `beyond_grace` comes from the shaper
    /// because it is a property of the epoch, not of the secret.
    fn open_frame(&self, wire: &[u8], beyond_grace: bool) -> Option<(Vec<u8>, OpenedEpoch)> {
        // Current epoch first: in steady state — which is almost all of the time — the first attempt
        // succeeds and the grace shapes are never touched. See [`SHAPE_GRACE`] for why the other two exist
        // and why both sides are needed rather than only the past.
        if let Some(frame) = deobfuscate(&self.current, wire) {
            return Some((frame, OpenedEpoch::Current));
        }
        if let Some(frame) = deobfuscate(&self.grace[0], wire).or_else(|| deobfuscate(&self.grace[1], wire)) {
            return Some((frame, OpenedEpoch::Grace));
        }
        // Last, and only past the grace window: a peer that has not yet learned the epoch. Fourth in the
        // chain because it is the rarest, so the steady state never pays for it beyond the miss it was
        // already paying.
        if beyond_grace
            && let Some(frame) = deobfuscate(&self.genesis, wire)
        {
            return Some((frame, OpenedEpoch::Genesis));
        }
        None
    }

    /// The datagram twin of [`open_frame`](Self::open_frame), opening `buf` in place.
    ///
    /// A failed attempt leaves the buffer untouched (`open_in_place` verifies the tag before it writes),
    /// which is what makes trying the arms in sequence safe.
    fn open_datagram(&self, buf: &mut [u8], beyond_grace: bool) -> Option<(usize, OpenedEpoch)> {
        if let Some(len) = open_in_place(&self.current, buf) {
            return Some((len, OpenedEpoch::Current));
        }
        if let Some(len) = open_in_place(&self.grace[0], buf).or_else(|| open_in_place(&self.grace[1], buf)) {
            return Some((len, OpenedEpoch::Grace));
        }
        if beyond_grace
            && let Some(len) = open_in_place(&self.genesis, buf)
        {
            return Some((len, OpenedEpoch::Genesis));
        }
        None
    }

    /// The shape a reply addressed to `epoch` must use.
    fn shape_for(&self, epoch: OpenedEpoch) -> &ShapeParams {
        match epoch {
            // `Grace` replies in the CURRENT shape on purpose: the peer accepts its own grace window, and
            // the disagreement is self-correcting within the beacon's spread. Only `Genesis` is a shape the
            // peer cannot compute any other way.
            OpenedEpoch::Current | OpenedEpoch::Grace => &self.current,
            OpenedEpoch::Genesis => &self.genesis,
        }
    }
}

/// Which of a shaper's accepted shapes opened an inbound datagram: **which secret, and which epoch**.
///
/// **A pair rather than a flat enum, because the two lags are independent** (#13). A peer can be behind on
/// the epoch, behind on the community secret, or — a node joining during a rotation — both at once. Flattening
/// them would need one variant per combination and would make every caller enumerate a product it does not
/// reason about; the caller's actual question is "how do I address the reply", and that has two coordinates.
///
/// **Returned because a reply has to be readable by whoever asked**, and at the join that is not decidable
/// from the receiver's own state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpenedUnder {
    /// Which epoch's shape opened it.
    pub epoch: OpenedEpoch,
    /// Which community secret opened it.
    pub secret: OpenedSecret,
}

impl OpenedUnder {
    /// The steady state: this node's own secret, at this node's own epoch.
    pub const CURRENT: Self = Self { epoch: OpenedEpoch::Current, secret: OpenedSecret::Emitting };

    /// Whether the reply may go out the ordinary way — the emitting secret at the current epoch.
    ///
    /// Stated as one predicate so a caller cannot satisfy half of it. Answering a peer in the right epoch
    /// under the wrong secret is exactly as unreadable as the reverse, and a caller checking only the arm it
    /// happened to hear about is how the second axis would go dark unnoticed.
    #[must_use]
    pub fn needs_addressing(self) -> bool {
        self.epoch == OpenedEpoch::Genesis || self.secret != OpenedSecret::Emitting
    }
}

/// Which community secret opened an inbound datagram.
///
/// The **secret** axis of [`OpenedUnder`], and it exists so that a rotation's lag is *visible*: a cell part-way
/// through a secret rollover would otherwise look exactly like a cell that has finished one, and an operator
/// would have no way to know when it is safe to move to the next phase.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenedSecret {
    /// This node's own secret — the one it emits under, and the steady state.
    Emitting,
    /// One of the receive-only secrets, by index into the accepted list. **A reply MUST go out under the
    /// same one** ([`ProteusShaper::outbound_under`]): the peer that sent this does not hold the emitting
    /// secret yet, or no longer holds it, and either way cannot read anything shaped with it.
    Accepted(usize),
}

/// Which epoch's shape opened an inbound datagram.
///
/// The **epoch** axis of [`OpenedUnder`]. The epoch shape is `PRF(community secret, epoch)`, so a node holding
/// the secret can compute any epoch's shape and simply does not know which is current — a *search* problem,
/// not a cryptographic one. The two ends share exactly one epoch they can both name without talking, **zero**,
/// and that is what makes the join deadlock breakable at constant cost.
///
/// The deadlock, on `SHAPE_GRACE = 1`: a node joining a cell at epoch `N ≥ 2` emits the epoch-0 shape, which
/// is outside the cell's `{N−1, N, N+1}` window, and its own `{0, 1}` window rejects the cell's replies. Both
/// directions are dark, and nothing can teach either side the epoch because teaching requires a frame to
/// cross. To speak you must know the epoch; to learn it you must speak.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenedEpoch {
    /// This node's current epoch — the steady state, and the first attempt, so it is what almost every
    /// datagram costs.
    Current,
    /// A neighbouring epoch inside the [`SHAPE_GRACE`] window: the peer turned a moment before or after this
    /// node. Transient by construction and self-correcting, so a reply in the *current* shape still lands.
    Grace,
    /// The **genesis** shape, from a peer that has not yet learned the cell's epoch — reported only when the
    /// epoch has moved beyond the grace window, so at `epoch ≤ SHAPE_GRACE` this variant never occurs (the
    /// genesis shape is then already `Current` or `Grace`).
    ///
    /// A reply in the current shape would be unreadable, so the caller MUST seal it under
    /// [`seal_datagram_under`](ProteusShaper::seal_datagram_under) — the whole point of returning
    /// which shape opened the datagram.
    ///
    /// **The cost, stated where it is paid.** The genesis shape does not rotate, so for an observer who has
    /// somehow obtained the community secret it is a signature that stands for the life of the network,
    /// which is exactly the static signature §13.4 rotates the shape to remove. It is bounded to the join at
    /// both ends: the arriving node leaves it on its first `BeaconReady`, and the answering node stops using
    /// it for a peer as soon as that peer's datagrams open under the current shape. Against an observer
    /// *without* the secret nothing changes — the bytes are PRF output either way, and community membership
    /// is precisely what the secret certifies.
    Genesis,
}

/// How many epochs to either side of the current one a receiver still un-shapes (#196).
///
/// **Both sides, and that is the finding.** Epoch advance is driven by the beacon, not a clock
/// (`fanos_node::epoch_driver` waits on the beacon watch), so at a turn one peer rotates before the other
/// and the pair disagrees for the flood's spread across the cell. Take A rotating first:
///
/// | direction | sender shapes with | receiver holds | receiver needs |
/// |---|---|---|---|
/// | A → B | `N+1` | `N` | a **future** shape |
/// | B → A | `N` | `N+1` | a **past** shape |
///
/// A node cannot know whether it is the early one or the late one, so retaining only the past — the obvious
/// fix, and the one the onion ratchet's `DEFAULT_RETAIN` suggests — leaves whichever node rotated *first*
/// unreachable for the whole spread. Before this, both directions went dark and stayed dark until both ends
/// had turned.
///
/// **Deliberately its own constant, not the ratchet's.** `fanos-pqcrypto`'s retention bounds how long a
/// sealed onion stays peelable — a bound on *message flight time*. This bounds how long two peers may
/// disagree about the epoch — a bound on *beacon propagation*. They share a value today and would diverge on
/// a cell whose flooding is slow relative to its round trips, so tying them would be one constant standing
/// for two quantities.
///
/// **Emission is unaffected**: [`ProteusShaper::shape`] uses the current epoch alone, so the wire signature
/// still moves exactly once per epoch and a size/timing detector sees what it saw before. Widening happens
/// only on the receive side.
///
/// The window is **cached**, not derived per frame. Deriving on a miss would make every unrecognised frame
/// cost two `epoch_shape` hashes, which an attacker sending garbage controls; three `deobfuscate` attempts
/// on a cached window is constant work with nothing attacker-scaled in it.
pub const SHAPE_GRACE: u64 = 1;

/// How many receive-only community secrets a shaper will hold beside the one it emits under (#13).
///
/// **Derived from what a rollover needs, not chosen for comfort.** The three-phase rollover in
/// [`ProteusShaper::also_accept`] needs exactly one extra secret at a time: the incoming one during phase 1,
/// the outgoing one during phase 2. Two allows a second rollover to begin before the first has been tidied
/// away — an operator's realistic mistake rather than a design — and that is the whole justification.
///
/// It is a **bound**, not a target, and the reason it exists at all is the receive path: a frame nobody
/// recognises costs up to four `deobfuscate` attempts per installed secret, so an unbounded list would let a
/// configuration mistake multiply the CPU an attacker's garbage buys. The multiplier stays the operator's,
/// and it stays small.
pub const MAX_ACCEPTED_SECRETS: usize = 2;

/// Redacted `Debug`: never render the community secret (which now lives in a production node once PROTEUS is
/// enabled) — a `{:?}` on the driver's transport state must not leak it (secret hygiene, audit D).
impl core::fmt::Debug for ProteusShaper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProteusShaper")
            .field("secret", &"<redacted>")
            .field("morph", &self.morph)
            .field("epoch", &self.epoch)
            .field("accepted_secrets", &self.accepted.len())
            .finish_non_exhaustive()
    }
}

impl ProteusShaper {
    /// A shaper for `epoch`, keyed by the shared `community_secret`, using the flagship [`Morph::Polymorph`]
    /// ("look like nothing"). Use [`with_morph`](Self::with_morph) to select another morph.
    #[must_use]
    pub fn new(community_secret: impl Into<Vec<u8>>, epoch: Epoch) -> Self {
        Self::with_morph(community_secret, epoch, Morph::Polymorph)
    }

    /// A shaper for `epoch` under `morph`, keyed by the shared `community_secret`. The morph selects both the
    /// codec ([`Morph::Plain`] is identity; every other morph applies the polymorph codec) and the
    /// traffic-shaping [`ShapingProfile`] (size + timing).
    #[must_use]
    pub fn with_morph(community_secret: impl Into<Vec<u8>>, epoch: Epoch, morph: Morph) -> Self {
        let secret = community_secret.into();
        let shapes = ShapeSet::for_secret(&secret, epoch);
        Self {
            secret,
            morph,
            profile: ShapingProfile::for_morph(morph),
            codec: None,
            epoch,
            shapes,
            accepted: Vec::new(),
            counter: AtomicU64::new(0),
        }
    }

    /// Also accept `secret` on **receive**, without emitting under it — the phase-1 half of a community-secret
    /// rotation (#13). Returns `false`, changing nothing, past [`MAX_ACCEPTED_SECRETS`].
    ///
    /// # Why emission is not a parameter here
    ///
    /// A secret rotation is not an epoch rotation, and the difference decides the whole design. An epoch is
    /// driven by the beacon, so both ends converge on their own within the flood's spread and
    /// [`SHAPE_GRACE`] is a *derived* bound on that disagreement. A community secret is distributed **outside
    /// the protocol** — by whatever channel the operator uses — so the two ends never converge by themselves,
    /// and nothing in FANOS can bound how long the disagreement lasts.
    ///
    /// A node that switched emission to a new secret the moment it learned one would be unreadable to every
    /// peer that had not learned it yet, which in a censored deployment is the failure PROTEUS exists to
    /// prevent. So emission moves only when the operator says so, and a rollover is three deliberate phases:
    ///
    /// 1. every node **accepts** the new secret (this call). Nothing changes on the wire.
    /// 2. every node **emits** under the new one and accepts the old (swap the config's two keys).
    /// 3. every node **drops** the old.
    ///
    /// **There is therefore no overlap-window constant in this crate, and that absence is the derivation.**
    /// The window is the operator's pause between phases; no protocol quantity bounds it, so inventing a
    /// number here would be a constant standing for a decision the code cannot see. What the code owes
    /// instead is the *observable* that tells the operator a phase is complete: [`OpenedSecret`], reported by
    /// [`inbound`](Self::inbound) and [`open_datagram`](Self::open_datagram) on every datagram.
    pub fn also_accept(&mut self, secret: impl Into<Vec<u8>>) -> bool {
        if self.accepted.len() >= MAX_ACCEPTED_SECRETS {
            return false;
        }
        let secret = secret.into();
        let shapes = ShapeSet::for_secret(&secret, self.epoch);
        self.accepted.push((secret, shapes));
        true
    }

    /// How many receive-only secrets are installed — zero on a node that is not mid-rotation.
    #[must_use]
    pub fn accepted_secrets(&self) -> usize {
        self.accepted.len()
    }

    /// A shaper driven by a **pluggable** [`MorphCodec`] (§13.3 SPI) instead of the built-in codec — the
    /// [`Morph::Pluggable`] mode. The custom codec fully handles encode/decode; the size/timing profile is
    /// the (identity) `Pluggable` default, so the codec owns the wire. The community secret still seeds the
    /// epoch shape (so a codec MAY consult it), and the epoch still rotates via [`rotate`](Self::rotate).
    ///
    /// `None` if the codec declares a
    /// [`max_overhead`](crate::MorphCodec::max_overhead) above [`MAX_WIRE_OVERHEAD`]: a receiver's read
    /// bound is `MAX_FRAME + MAX_WIRE_OVERHEAD`, so such a codec would make full-size frames silently
    /// undeliverable. Refusing at installation is the only place the mismatch is *observable* — past this
    /// point the loss looks like a network drop, and the sender still sees its write succeed.
    ///
    /// [`MAX_WIRE_OVERHEAD`]: crate::MAX_WIRE_OVERHEAD
    #[must_use]
    pub fn with_codec(
        community_secret: impl Into<Vec<u8>>,
        epoch: Epoch,
        codec: Arc<dyn MorphCodec>,
    ) -> Option<Self> {
        if codec.max_overhead() > crate::MAX_WIRE_OVERHEAD {
            return None;
        }
        let secret = community_secret.into();
        let shapes = ShapeSet::for_secret(&secret, epoch);
        Some(Self {
            secret,
            morph: Morph::Pluggable,
            profile: ShapingProfile::for_morph(Morph::Pluggable),
            codec: Some(codec),
            epoch,
            shapes,
            accepted: Vec::new(),
            counter: AtomicU64::new(0),
        })
    }

    /// The active morph.
    #[must_use]
    pub fn morph(&self) -> Morph {
        self.morph
    }

    /// Switch to a different morph at runtime (the auto-fallback [`MorphController`](crate::MorphController)
    /// drives this, §13.7). The codec-using morphs (everything but [`Morph::Plain`]) share one wire codec, so
    /// switching *among* them changes only the size/timing profile — a peer keeps decoding with no
    /// renegotiation. Switching to or from `Plain` changes the codec itself and needs both ends to agree
    /// (§7.4 HELLO capability negotiation). The packet counter and epoch shape are unchanged.
    pub fn set_morph(&mut self, morph: Morph) -> bool {
        // **A cover-protocol morph without a plugged codec is refused, not approximated.** The "Parrot is
        // Dead" rule keeps the four tunnels out of the core, so honouring one needs a `MorphCodec`. Before
        // this, selecting `Fronted` applied the *polymorph* codec under a CDN-ish shaping profile: the
        // auto-fallback could walk `Polymorph → Fronted → Webrtc` emitting the same codec three times while
        // the operator's configuration said domain-fronting and WebRTC. Rotation defeats a size/timing
        // detector and cannot defeat a codec-level one, and nothing distinguished the two cases.
        //
        // Returns whether the morph was installed, so a caller that cares (the auto-fallback does) can tell
        // a real rotation from a request it cannot honour.
        if morph.requires_codec() {
            return false;
        }
        self.morph = morph;
        self.profile = ShapingProfile::for_morph(morph);
        // Switching to a built-in morph drops any pluggable codec: a shaper is either codec-driven or
        // built-in-morph-driven, never both.
        self.codec = None;
        true
    }

    /// Advance to a new epoch: the shape rotates, so the wire signature moves (§13.4, V22).
    ///
    /// The [`SHAPE_GRACE`] window moves with it, so a peer that has not yet turned — or has already turned —
    /// still un-shapes for the length of the beacon's spread.
    ///
    /// **Every accepted secret rotates too, and that is not housekeeping** (#13). A shape is
    /// `PRF(secret, epoch)`, so an accepted secret left at the epoch it was installed at would keep matching
    /// nothing from the very next turn onward — configured, listed, and deaf. The loop is what makes the
    /// secret axis and the epoch axis independent instead of accidentally coupled.
    pub fn rotate(&mut self, epoch: Epoch) {
        self.epoch = epoch;
        self.shapes.rotate(&self.secret, epoch);
        for (secret, shapes) in &mut self.accepted {
            shapes.rotate(secret, epoch);
        }
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Shape an outbound frame: the wire bytes **and** the timing directive (§13.3 — a morph is a codec *and*
    /// a traffic-shaper). Every morph but [`Morph::Plain`] applies the polymorph codec (junk-padded, no
    /// static signature, per-packet-diversified so even identical frames differ, §13.2–§13.4), then the
    /// morph's [`ShapingProfile`] pads the wire toward its size band and returns the inter-packet delay.
    /// `Plain` is identity with zero delay (the zero-overhead open-network path). Each call consumes one
    /// packet-counter value, seeding this packet's nonce, size, and timing.
    #[must_use]
    pub fn shape(&self, frame: &[u8]) -> Shaped {
        let seq = self.counter.fetch_add(1, Ordering::Relaxed);
        // A pluggable codec (the SPI, §13.3) replaces the built-in transform; the profile still applies (it
        // is the identity `Pluggable` default unless the codec's shaper set otherwise).
        let mut wire = match &self.codec {
            Some(codec) => codec.encode(frame, seq),
            None if self.morph == Morph::Plain => {
                return Shaped { wire: frame.to_vec(), delay: Duration::ZERO };
            }
            None => obfuscate(&self.shapes.current, frame, &self.packet_nonce(seq)),
        };
        self.profile.pad_to_target(&mut wire, &self.shapes.current.scramble_seed, seq);
        let delay = self.profile.packet_delay(&self.shapes.current.scramble_seed, seq);
        Shaped { wire, delay }
    }

    /// Wrap an outbound frame for the wire, discarding the timing directive — [`shape`](Self::shape) without
    /// the delay, for call sites (handshake/control frames) that do not pace.
    #[must_use]
    pub fn outbound(&self, frame: &[u8]) -> Vec<u8> {
        self.shape(frame).wire
    }

    /// Derive a random-looking per-packet nonce from the sequence counter — so the cleartext front
    /// of the wire is not an incrementing (fingerprintable) counter but PRF output.
    fn packet_nonce(&self, seq: u64) -> [u8; NONCE_LEN] {
        let mut material = self.shapes.current.scramble_seed.to_vec();
        material.extend_from_slice(&seq.to_be_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        hash_xof(NONCE_LABEL, &material, &mut nonce);
        nonce
    }

    /// Recover an inbound frame, or `None` if it was not shaped by the same secret and epoch —
    /// a peer without the community secret cannot produce a frame this shaper will accept. [`Morph::Plain`]
    /// is identity (the frame passed through unshaped). Size-shaping padding on the wire is transparent here:
    /// the codec's length field bounds the payload, so trailing pad is ignored.
    /// **Returns the arm as well as the bytes, and the caller must act on it** (#234). A frame that opened
    /// under [`OpenedEpoch::Genesis`] came from a peer that does not yet know the live epoch, so a reply
    /// shaped at the live epoch is one it cannot read — the handshake would connect and then go silent in
    /// one direction. `Current` and `Grace` are the same instruction to the caller (reply normally) and are
    /// kept distinct anyway, because "we are inside the grace window" is a different thing for an operator
    /// to see than "we are in step".
    #[must_use]
    pub fn inbound(&self, wire: &[u8]) -> Option<(Vec<u8>, OpenedUnder)> {
        if let Some(codec) = &self.codec {
            return codec.decode(wire).map(|f| (f, OpenedUnder::CURRENT));
        }
        if self.morph == Morph::Plain {
            return Some((wire.to_vec(), OpenedUnder::CURRENT));
        }
        let beyond = self.beyond_grace();
        // The emitting secret first, and its own current epoch first inside that: in steady state — which is
        // almost all of the time — the first attempt succeeds and nothing else is touched. Accepted secrets
        // come after for the same reason the genesis shape comes last: a cost paid only on a miss.
        if let Some((frame, epoch)) = self.shapes.open_frame(wire, beyond) {
            return Some((frame, OpenedUnder { epoch, secret: OpenedSecret::Emitting }));
        }
        for (i, (_, shapes)) in self.accepted.iter().enumerate() {
            if let Some((frame, epoch)) = shapes.open_frame(wire, beyond) {
                return Some((frame, OpenedUnder { epoch, secret: OpenedSecret::Accepted(i) }));
            }
        }
        None
    }

    /// Whether the genesis shape is a *distinct* fourth candidate rather than one already inside the
    /// `{epoch − 1, epoch, epoch + 1}` window.
    ///
    /// Below this threshold the genesis shape is `Current` or `Grace` and trying it again would be a wasted
    /// `deobfuscate` — and, worse, would report [`OpenedEpoch::Genesis`] for an ordinary peer, so a node at
    /// epoch 1 would answer the whole cell in the genesis shape and pin itself there.
    fn beyond_grace(&self) -> bool {
        self.epoch.get() > SHAPE_GRACE
    }

    /// Seal one **datagram** — the layer below the frame (spec §13.3/§13.5, see
    /// [`crate::datagram`]). `nonce` must not repeat for this epoch's shape; the caller draws it,
    /// because only the caller knows how many sockets share the community secret.
    ///
    /// The shaper owns both directions of the envelope for the same reason it owns the frame codec: the
    /// epoch shape and its grace window live here, so a datagram and a frame can never disagree about
    /// which epoch they are in.
    #[must_use]
    pub fn seal_datagram(&self, payload: &[u8], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
        seal(&self.shapes.current, payload, nonce)
    }

    /// Open one datagram in place, returning the plaintext length; `None` means "not from this
    /// community" and the caller drops it without replying.
    ///
    /// Tries the current shape, then the [`SHAPE_GRACE`] window, exactly as [`inbound`](Self::inbound)
    /// does — a peer that turned the epoch a moment before or after this node must still be able to
    /// *connect*, and at this layer a failure is not one lost frame but a dead handshake.
    ///
    /// A failed attempt leaves the buffer untouched (`open_in_place` verifies the tag before it writes),
    /// which is what makes trying three shapes in sequence safe.
    #[must_use]
    pub fn open_datagram(&self, buf: &mut [u8]) -> Option<(usize, OpenedUnder)> {
        let beyond = self.beyond_grace();
        if let Some((len, epoch)) = self.shapes.open_datagram(buf, beyond) {
            return Some((len, OpenedUnder { epoch, secret: OpenedSecret::Emitting }));
        }
        for (i, (_, shapes)) in self.accepted.iter().enumerate() {
            if let Some((len, epoch)) = shapes.open_datagram(buf, beyond) {
                return Some((len, OpenedUnder { epoch, secret: OpenedSecret::Accepted(i) }));
            }
        }
        None
    }

    /// Seal one datagram addressed the way `under` says — the reply half of
    /// [`open_datagram`](Self::open_datagram), and the only way an established node can answer a peer that is
    /// behind on the epoch, on the community secret, or (a node joining mid-rotation) on both.
    ///
    /// Separate from [`seal_datagram`](Self::seal_datagram) instead of a parameter on it, because the default
    /// must stay "my secret, my epoch": a shape argument on the hot path is a shape argument someone
    /// eventually passes `Epoch::ZERO` to by accident, and that is the static wire signature §13.4 exists to
    /// remove. Use it only for a peer this node has just *observed* on that shape, never speculatively.
    ///
    /// An `under` naming an accepted secret that has since been dropped falls back to the emitting set — the
    /// only safe answer, since the alternative is inventing a shape. The peer then cannot read the reply,
    /// which is the correct outcome: the operator ended the rollover phase, and this peer did not follow.
    #[must_use]
    pub fn seal_datagram_under(&self, payload: &[u8], nonce: &[u8; NONCE_LEN], under: OpenedUnder) -> Vec<u8> {
        seal(self.reply_shape(under), payload, nonce)
    }

    /// Wrap an outbound **frame** addressed the way `under` says — the frame-layer twin of
    /// [`seal_datagram_under`](Self::seal_datagram_under), for the same peer and the same reason.
    ///
    /// Both layers are needed, and that is not redundancy: the datagram envelope carries the QUIC packet and
    /// the frame codec carries what is inside it, each keyed independently on the shape. Fixing only the
    /// envelope gets a joining node's handshake through and then loses its first HELLO.
    #[must_use]
    pub fn outbound_under(&self, frame: &[u8], under: OpenedUnder) -> Vec<u8> {
        let seq = self.counter.fetch_add(1, Ordering::Relaxed);
        if self.morph == Morph::Plain {
            return frame.to_vec();
        }
        let shape = self.reply_shape(under);
        let mut nonce = [0u8; NONCE_LEN];
        let mut material = shape.scramble_seed.to_vec();
        material.extend_from_slice(&seq.to_be_bytes());
        hash_xof(NONCE_LABEL, &material, &mut nonce);
        let mut wire = obfuscate(shape, frame, &nonce);
        self.profile.pad_to_target(&mut wire, &shape.scramble_seed, seq);
        wire
    }

    /// The one shape both reply paths address with — resolved in a single place so the frame layer and the
    /// datagram layer can never disagree about which peer they are talking to.
    fn reply_shape(&self, under: OpenedUnder) -> &ShapeParams {
        let set = match under.secret {
            OpenedSecret::Emitting => &self.shapes,
            OpenedSecret::Accepted(i) => self.accepted.get(i).map_or(&self.shapes, |(_, s)| s),
        };
        set.shape_for(under.epoch)
    }
}

/// The shapes a receiver accepts besides the current one: `[epoch − SHAPE_GRACE, epoch + SHAPE_GRACE]`.
///
/// At genesis there is no earlier epoch, so the past slot repeats the current shape rather than inventing
/// `Epoch::ZERO − 1`. That costs one redundant `deobfuscate` on a node that has never rotated and keeps the
/// window a fixed-size array — no allocation, no branch on the receive path, and nothing for a `no_std`
/// build to special-case.
///
/// **Saturating at BOTH ends**, and the first version of this was not: it used `saturating_sub` for the past
/// and a bare `+` for the future, which panics at `Epoch(u64::MAX)`. `Epoch::next` is saturating for the same
/// reason and says so — a counter that wraps re-derives a *past* window, which is a replay hazard, not merely
/// an arithmetic one. Caught on the first run by `the_window_at_genesis_does_not_wrap_below_zero`, which was
/// written for the other end of the range.
fn grace_shapes(secret: &[u8], epoch: Epoch) -> [ShapeParams; 2] {
    let previous = Epoch::new(epoch.get().saturating_sub(SHAPE_GRACE));
    let following = Epoch::new(epoch.get().saturating_add(SHAPE_GRACE));
    [epoch_shape(secret, previous), epoch_shape(secret, following)]
}

#[cfg(test)]
// `expect_used` joins `unwrap_used` for the reason the sibling crates carry the pair: in a test the message
// IS the assertion — "an accepted secret must open" says what went wrong at the moment it does, where a bare
// `unwrap` would report a line number and nothing else.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    /// The bytes alone. Every assertion below predates [`ProteusShaper::inbound`] reporting its arm and is
    /// about *reachability*; the arm has its own tests, and folding it into each of these would add noise
    /// to claims that are not about it.
    fn opened(shaper: &ProteusShaper, wire: &[u8]) -> Option<Vec<u8>> {
        shaper.inbound(wire).map(|(frame, _)| frame)
    }

    use super::*;

    #[test]
    fn a_frame_round_trips_through_the_shaper() {
        let shaper = ProteusShaper::new(b"community".to_vec(), Epoch::new(5));
        let frame = b"a canonical FANOS wire frame";
        let wire = shaper.outbound(frame);
        assert_ne!(
            wire.as_slice(),
            frame,
            "the wire carries no raw frame bytes"
        );
        assert_eq!(opened(&shaper, &wire).unwrap(), frame);
    }

    #[test]
    fn two_peers_sharing_the_secret_interoperate() {
        let alice = ProteusShaper::new(b"s".to_vec(), Epoch::new(9));
        let bob = ProteusShaper::new(b"s".to_vec(), Epoch::new(9));
        let wire = alice.outbound(b"hi bob");
        assert_eq!(opened(&bob, &wire).unwrap(), b"hi bob");
    }

    /// **A community-secret rollover is reachable in BOTH directions, and a dropped secret in neither** (#13).
    ///
    /// The epoch-axis twin below is the model, and both of its obligations transfer:
    ///
    /// * **both directions**, because the two ends fail differently and a test of one certifies half a fix.
    ///   Here the asymmetry is sharper than the epoch's: the node that has *moved* emits under the new secret
    ///   and would be unreadable to everyone still on the old, which is why emission is not allowed to move
    ///   until every peer accepts. Phase 1 is asserted as the state where nothing on the wire has changed
    ///   yet — that is the property that makes the rollover safe, not an incidental one.
    /// * **the negative half**, because a window that accepts everything is not a window. A secret the
    ///   operator has dropped must stop opening, or phase 3 does nothing and the rotation is not one.
    ///
    /// The third assertion has no epoch-axis counterpart and is the reason [`OpenedSecret`] exists: the
    /// receiver must be able to *say* which secret opened a datagram. Without it a cell part-way through a
    /// rollover is indistinguishable from a cell that has finished one, and the operator has no signal for
    /// when phase 2 is safe — the rollover would be a leap in the dark rather than a procedure.
    #[test]
    fn a_secret_rollover_is_readable_both_ways_and_a_dropped_secret_is_not() {
        const OLD: &[u8] = b"the community secret in use";
        const NEW: &[u8] = b"the one being rolled out";

        // PHASE 1: this node accepts the new secret and still emits under the old.
        let mut moving = ProteusShaper::new(OLD.to_vec(), Epoch::new(4));
        assert!(moving.also_accept(NEW.to_vec()));
        let unmoved = ProteusShaper::new(OLD.to_vec(), Epoch::new(4));

        // Nothing on the wire changed: a peer that has heard nothing about the rollover still reads it.
        let out = moving.outbound(b"phase 1 emits under the old secret");
        assert_eq!(
            opened(&unmoved, &out).as_deref(),
            Some(b"phase 1 emits under the old secret".as_slice()),
            "accepting a secret must not move emission — a node that switched on learning a new secret \
             would go dark to every peer that had not learned it yet, which is the failure PROTEUS exists \
             to prevent"
        );

        // And the other direction: a peer already emitting under the NEW secret is readable here. This is
        // the leg that makes phase 2 survivable, and it is the one a naive "keep the old shape" misses.
        let ahead = ProteusShaper::new(NEW.to_vec(), Epoch::new(4));
        let from_ahead = ahead.outbound(b"phase 2 emits under the new secret");
        let (frame, under) = moving.inbound(&from_ahead).expect("an accepted secret must open");
        assert_eq!(frame, b"phase 2 emits under the new secret");

        // The observable, which is what tells an operator a phase is complete.
        assert_eq!(under.secret, OpenedSecret::Accepted(0), "the arm names WHICH secret opened it");
        assert_eq!(under.epoch, OpenedEpoch::Current, "and the two axes are read independently");
        assert!(under.needs_addressing(), "so the reply is addressed rather than sent the default way");

        // The reply goes back under that same secret, and the peer can read it. Without this the handshake
        // connects and then dies in one direction — the #235 asymmetry, one axis over.
        let reply = moving.outbound_under(b"answered under the secret that asked", under);
        assert_eq!(
            opened(&ahead, &reply).as_deref(),
            Some(b"answered under the secret that asked".as_slice()),
            "a reply must be readable by whoever asked, or the rollover breaks exactly the peers it is for"
        );

        // PHASE 3, the negative half: a shaper that never accepted NEW does not open its frames.
        assert!(
            opened(&unmoved, &from_ahead).is_none(),
            "a secret that was never accepted must not open — otherwise 'accepted' means nothing and \
             dropping one at the end of a rollover would change nothing"
        );
    }

    /// **An accepted secret rotates with the epoch, or it is deaf from the next turn onward** (#13).
    ///
    /// The trap the [`ShapeSet`] extraction exists to remove. A shape is `PRF(secret, epoch)`, so an accepted
    /// secret whose shapes were derived once at install time keeps matching nothing the moment the beacon
    /// advances — while remaining listed, configured, and reported as present. The failure is silent on every
    /// surface, which is why it is asserted rather than argued.
    ///
    /// **It takes TWO turns to see, and that is the finding** — my first version of this test rotated once
    /// and stayed green with the fix removed. A frozen set still holds `grace = [install − 1, install + 1]`,
    /// and `SHAPE_GRACE` is exactly 1, so the first turn lands inside the stale window and is absorbed. The
    /// defect is invisible for one epoch and total from the second: the worst possible shape, because a
    /// deployment would test a rollover across one turn, see it work, and lose the peer on the next.
    ///
    /// Falsified by dropping the `for (secret, shapes) in &mut self.accepted` loop from `rotate`: the
    /// TWO-turn assertion goes red while the one-turn assertion above it and the emitting secret both stay
    /// green — which is the discrimination, not merely a failure.
    #[test]
    fn rotating_the_epoch_moves_the_accepted_secrets_too() {
        const OLD: &[u8] = b"retiring";
        const NEW: &[u8] = b"incoming";
        let mut node = ProteusShaper::new(NEW.to_vec(), Epoch::new(7));
        assert!(node.also_accept(OLD.to_vec()));

        // Before any turn, the accepted peer is readable — the control, so what follows is about the turn
        // and not about the setup.
        let peer_old = ProteusShaper::new(OLD.to_vec(), Epoch::new(7));
        assert!(opened(&node, &peer_old.outbound(b"before")).is_some(), "the setup itself must work");

        // One turn: absorbed either way. Asserted so the two-turn assertion below cannot be mistaken for
        // "rotation breaks accepted secrets" — it is specifically the SECOND turn that escapes the window.
        node.rotate(Epoch::new(8));
        let peer_at_8 = ProteusShaper::new(OLD.to_vec(), Epoch::new(8));
        assert!(
            opened(&node, &peer_at_8.outbound(b"one turn")).is_some(),
            "one turn is inside a stale set's own grace window — this must hold with or without the fix"
        );

        // Two turns: outside every arm a frozen set has, including its immobile genesis shape.
        node.rotate(Epoch::new(9));
        let peer_at_9 = ProteusShaper::new(OLD.to_vec(), Epoch::new(9));
        assert!(
            opened(&node, &peer_at_9.outbound(b"two turns")).is_some(),
            "an accepted secret must follow the epoch — left where it was installed it goes deaf two turns \
             later while still looking perfectly configured, and nothing reports it"
        );

        // And the emitting secret is unaffected throughout, so the failure above is about the accepted one.
        let peer_new = ProteusShaper::new(NEW.to_vec(), Epoch::new(9));
        assert!(opened(&node, &peer_new.outbound(b"emitting")).is_some(), "the emitting secret still works");
        assert_eq!(node.accepted_secrets(), 1, "and the rollover state is reportable");
    }

    /// The bound is a bound: past [`MAX_ACCEPTED_SECRETS`] the shaper refuses and changes nothing.
    ///
    /// Refusing rather than evicting, because an evicted secret is a peer that silently stops being readable
    /// — the operator would see a successful call and a broken cell.
    #[test]
    fn accepting_more_secrets_than_a_rollover_needs_is_refused_not_evicted() {
        let mut node = ProteusShaper::new(b"emitting".to_vec(), Epoch::new(1));
        for i in 0..MAX_ACCEPTED_SECRETS {
            assert!(node.also_accept(alloc::format!("extra-{i}").into_bytes()), "up to the bound, accepted");
        }
        let first = ProteusShaper::new(b"extra-0".to_vec(), Epoch::new(1));
        assert!(!node.also_accept(b"one too many".to_vec()), "past the bound, refused");
        assert_eq!(node.accepted_secrets(), MAX_ACCEPTED_SECRETS, "and nothing was added");
        assert!(
            opened(&node, &first.outbound(b"still here")).is_some(),
            "nor evicted — an eviction would silently unreachable a peer the operator still expects to work"
        );
    }

    /// **A peer mid-rotation is reachable in BOTH directions, and two epochs apart in neither** (#196).
    ///
    /// The shaper held one shape and `rotate` overwrote it, so at every epoch turn the link went dark both
    /// ways until both ends had rotated — in exactly the censored deployments PROTEUS exists for.
    ///
    /// The A→B leg is the half a "retain the previous epoch" fix does not cover, and it is the one that
    /// matters: the node that rotates **first** is the unreachable one, and a test checking only the late
    /// peer's inbound would certify the half-fix as done. Both legs are asserted for that reason.
    ///
    /// The two-apart case is the negative half. A window that accepts everything is not a window: it would
    /// mean a stale peer could be shaped-for indefinitely, and the rotation would stop being a rotation.
    #[test]
    fn a_peer_one_epoch_behind_is_reachable_both_ways_and_two_epochs_behind_is_not() {
        let early = ProteusShaper::new(b"s".to_vec(), Epoch::new(10)); // rotated already
        let late = ProteusShaper::new(b"s".to_vec(), Epoch::new(9)); // beacon has not reached it

        // The half a backward-only retention misses: the EARLY node's frames reaching the late one.
        let forward = early.outbound(b"from the node that turned first");
        assert_eq!(
            opened(&late, &forward).as_deref(),
            Some(b"from the node that turned first".as_slice()),
            "a peer that has not yet rotated must still read the one that has — otherwise whichever node \
             turns first is unreachable for the whole beacon spread"
        );

        // And the half it does cover, which must not regress.
        let back = late.outbound(b"from the node still behind");
        assert_eq!(
            opened(&early, &back).as_deref(),
            Some(b"from the node still behind".as_slice()),
            "and the node that has rotated must still read the one that has not"
        );

        // Two epochs apart is outside the window, in both directions.
        let far = ProteusShaper::new(b"s".to_vec(), Epoch::new(12));
        assert!(
            opened(&far, &back).is_none() && opened(&late, &far.outbound(b"x")).is_none(),
            "the grace window is bounded: two epochs apart does not un-shape, or the rotation is not one"
        );
    }

    /// Genesis has no earlier epoch, and the window must not invent one.
    ///
    /// `Epoch::ZERO − 1` would wrap to `u64::MAX` and derive a shape from a window that will never exist,
    /// so a node that has never rotated would spend one of its three attempts on nonsense. Saturating makes
    /// the past slot repeat the present, which is redundant but correct.
    #[test]
    fn the_window_at_genesis_does_not_wrap_below_zero() {
        let genesis = ProteusShaper::new(b"s".to_vec(), Epoch::ZERO);
        let next = ProteusShaper::new(b"s".to_vec(), Epoch::new(1));
        assert_eq!(
            opened(&genesis, &next.outbound(b"forward from epoch 1")).as_deref(),
            Some(b"forward from epoch 1".as_slice()),
            "epoch 0 still accepts epoch 1 — the forward half is what a fresh node needs"
        );
        let wrapped = ProteusShaper::new(b"s".to_vec(), Epoch::new(u64::MAX));
        assert!(
            opened(&genesis, &wrapped.outbound(b"x")).is_none(),
            "and it does not accept the shape of `0 - 1` wrapped, which is what a bare subtraction would give"
        );
    }

    #[test]
    fn the_wire_signature_rotates_every_epoch() {
        let mut shaper = ProteusShaper::new(b"s".to_vec(), Epoch::ZERO);
        let w0 = shaper.outbound(b"same payload");
        shaper.rotate(Epoch::new(1));
        let w1 = shaper.outbound(b"same payload");
        assert_ne!(w0, w1, "the same frame shapes differently each epoch");
    }

    #[test]
    fn set_morph_swaps_the_profile_but_still_decodes() {
        // Rotating among the morphs a stock build can honour keeps a peer decoding: they share one codec,
        // so only the size/timing profile moves. **That sharing is also why a rotation into a
        // cover-protocol morph would be theatre** — it changes nothing a codec-level censor observes — which
        // is why `set_morph` now refuses those outright (#113) and this test uses `Plain`, a morph the core
        // really implements.
        let mut sender = ProteusShaper::new(b"s".to_vec(), Epoch::new(4));
        let receiver = ProteusShaper::new(b"s".to_vec(), Epoch::new(4));
        assert!(!sender.set_morph(Morph::MasqueH3), "a cover-protocol morph needs a plugged codec");
        assert_eq!(sender.morph(), Morph::Polymorph, "and the refusal leaves the honourable morph in place");

        let shaped = sender.shape(b"post-rotation frame");
        assert_eq!(
            opened(&receiver, &shaped.wire).as_deref(),
            Some(&b"post-rotation frame"[..]),
            "a peer on the same morph decodes — the codec is shared"
        );
    }

    /// A trivial reversible codec standing in for a real pluggable transport: reverse the bytes and append a
    /// marker. Enough to prove the SPI dispatches (a real codec tunnels a cover protocol).
    struct MockCodec;
    impl MorphCodec for MockCodec {
        fn encode(&self, frame: &[u8], _seq: u64) -> Vec<u8> {
            let mut v: Vec<u8> = frame.iter().rev().copied().collect();
            v.push(0xAB);
            v
        }
        fn decode(&self, wire: &[u8]) -> Option<Vec<u8>> {
            let (&marker, body) = wire.split_last()?;
            (marker == 0xAB).then(|| body.iter().rev().copied().collect())
        }
    }

    /// Declares more growth than a receiver's wire bound allows — the case the guard exists for.
    struct GreedyCodec;
    impl MorphCodec for GreedyCodec {
        fn encode(&self, frame: &[u8], _seq: u64) -> Vec<u8> {
            frame.to_vec()
        }
        fn decode(&self, wire: &[u8]) -> Option<Vec<u8>> {
            Some(wire.to_vec())
        }
        fn max_overhead(&self) -> usize {
            crate::MAX_WIRE_OVERHEAD + 1
        }
    }

    #[test]
    fn a_codec_that_outgrows_the_read_bound_is_refused() {
        // The property first: a codec declaring one byte more than the receiver will read is refused at
        // installation. Without this the failure is invisible — full-size frames vanish, the write
        // succeeds, and it is indistinguishable from packet loss.
        assert!(
            ProteusShaper::with_codec(b"s".to_vec(), Epoch::ZERO, Arc::new(GreedyCodec)).is_none(),
            "a codec growing frames past MAX_WIRE_OVERHEAD must not be installed"
        );
        // And the guard is not simply refusing everything: the same call with a conforming codec succeeds.
        assert!(
            ProteusShaper::with_codec(b"s".to_vec(), Epoch::ZERO, Arc::new(MockCodec)).is_some(),
            "a codec within the bound must still be accepted"
        );
    }

    #[test]
    fn a_pluggable_codec_replaces_the_builtin_transform() {
        let shaper = ProteusShaper::with_codec(b"s".to_vec(), Epoch::ZERO, Arc::new(MockCodec)).unwrap();
        assert_eq!(shaper.morph(), Morph::Pluggable);
        let shaped = shaper.shape(b"hello");
        assert!(shaped.wire.ends_with(&[0xAB]), "the custom codec produced the wire, not obfuscate");

        // A peer running the same codec recovers it; the built-in polymorph decode does NOT.
        let receiver = ProteusShaper::with_codec(b"s".to_vec(), Epoch::ZERO, Arc::new(MockCodec)).unwrap();
        assert_eq!(opened(&receiver, &shaped.wire).as_deref(), Some(&b"hello"[..]));
        let builtin = ProteusShaper::new(b"s".to_vec(), Epoch::ZERO);
        assert_ne!(opened(&builtin, &shaped.wire).as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn set_morph_off_pluggable_restores_the_builtin_codec() {
        let mut shaper = ProteusShaper::with_codec(b"s".to_vec(), Epoch::ZERO, Arc::new(MockCodec)).unwrap();
        shaper.set_morph(Morph::Polymorph);
        assert_eq!(shaper.morph(), Morph::Polymorph);
        // The built-in codec is back: a plain Polymorph shaper decodes the frame (the mock codec would not).
        let shaped = shaper.shape(b"builtin again");
        let rx = ProteusShaper::new(b"s".to_vec(), Epoch::ZERO);
        assert_eq!(opened(&rx, &shaped.wire).as_deref(), Some(&b"builtin again"[..]));
    }

    #[test]
    fn switching_to_plain_is_identity() {
        let mut shaper = ProteusShaper::new(b"s".to_vec(), Epoch::ZERO);
        shaper.set_morph(Morph::Plain);
        let frame = b"unshaped";
        let shaped = shaper.shape(frame);
        assert_eq!(shaped.wire, frame, "Plain passes the frame through unshaped");
        assert_eq!(opened(&shaper, frame).as_deref(), Some(&frame[..]));
    }

    #[test]
    fn the_wrong_secret_cannot_recover_the_frame() {
        let sender = ProteusShaper::new(b"real-secret".to_vec(), Epoch::new(3));
        let eavesdropper = ProteusShaper::new(b"guessed-secret".to_vec(), Epoch::new(3));
        let wire = sender.outbound(b"secret payload");
        // Different junk length ⇒ the recovered bytes are not the original frame.
        assert_ne!(
            opened(&eavesdropper, &wire).as_deref(),
            Some(&b"secret payload"[..])
        );
    }

    #[test]
    fn consecutive_packets_of_the_same_frame_differ_on_the_wire() {
        // Per-packet junk within a single epoch: two sends of the identical frame produce different
        // wire bytes (no fixed intra-epoch prefix / equal-frame linkability), yet both strip back.
        let shaper = ProteusShaper::new(b"community".to_vec(), Epoch::new(7));
        let frame = b"identical application frame";
        let w0 = shaper.outbound(frame);
        let w1 = shaper.outbound(frame);
        assert_ne!(
            w0, w1,
            "consecutive packets of one frame are not byte-identical"
        );
        // The receiver (fresh counter is irrelevant — it only skips fixed widths) recovers both.
        let rx = ProteusShaper::new(b"community".to_vec(), Epoch::new(7));
        assert_eq!(opened(&rx, &w0).unwrap(), frame);
        assert_eq!(opened(&rx, &w1).unwrap(), frame);
    }
}
