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
    /// The current epoch's shape — the **only** one this node emits with.
    shape: ShapeParams,
    /// The neighbouring epochs' shapes, accepted on receive only: `[previous, next]`. See
    /// [`SHAPE_GRACE`] for why both, and why the pair is cached rather than derived per frame.
    grace: [ShapeParams; 2],
    /// The **genesis** shape, accepted on receive only, and only once the epoch has moved far enough that
    /// [`grace`](Self::grace) no longer covers it. See [`OpenedUnder::Genesis`] for the deadlock it breaks.
    ///
    /// Cached like the grace pair and for the same reason: it must cost one `deobfuscate` on a frame nobody
    /// recognises, never a hash, or an attacker sending garbage chooses this node's CPU bill.
    genesis: ShapeParams,
    counter: AtomicU64,
}

/// Which of a shaper's accepted shapes opened an inbound datagram.
///
/// **Returned because a reply has to be readable by whoever asked**, and at the join that is not decidable
/// from the receiver's own epoch. The epoch shape is `PRF(community secret, epoch)`, so a node holding the
/// secret can compute any epoch's shape and simply does not know which is current — a *search* problem, not
/// a cryptographic one. The two ends share exactly one epoch they can both name without talking, **zero**,
/// and that is what makes the deadlock breakable at constant cost.
///
/// The deadlock, on `SHAPE_GRACE = 1`: a node joining a cell at epoch `N ≥ 2` emits the epoch-0 shape, which
/// is outside the cell's `{N−1, N, N+1}` window, and its own `{0, 1}` window rejects the cell's replies. Both
/// directions are dark, and nothing can teach either side the epoch because teaching requires a frame to
/// cross. To speak you must know the epoch; to learn it you must speak.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenedUnder {
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
    /// [`seal_datagram_at_genesis`](ProteusShaper::seal_datagram_at_genesis) — the whole point of returning
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

/// Redacted `Debug`: never render the community secret (which now lives in a production node once PROTEUS is
/// enabled) — a `{:?}` on the driver's transport state must not leak it (secret hygiene, audit D).
impl core::fmt::Debug for ProteusShaper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProteusShaper")
            .field("secret", &"<redacted>")
            .field("morph", &self.morph)
            .field("epoch", &self.epoch)
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
        let shape = epoch_shape(&secret, epoch);
        let grace = grace_shapes(&secret, epoch);
        let genesis = epoch_shape(&secret, Epoch::ZERO);
        Self {
            secret,
            morph,
            profile: ShapingProfile::for_morph(morph),
            codec: None,
            epoch,
            shape,
            grace,
            genesis,
            counter: AtomicU64::new(0),
        }
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
        let shape = epoch_shape(&secret, epoch);
        let grace = grace_shapes(&secret, epoch);
        let genesis = epoch_shape(&secret, Epoch::ZERO);
        Some(Self {
            secret,
            morph: Morph::Pluggable,
            profile: ShapingProfile::for_morph(Morph::Pluggable),
            codec: Some(codec),
            epoch,
            shape,
            grace,
            genesis,
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
    pub fn rotate(&mut self, epoch: Epoch) {
        self.epoch = epoch;
        self.shape = epoch_shape(&self.secret, epoch);
        self.grace = grace_shapes(&self.secret, epoch);
        // `genesis` is deliberately NOT re-derived: it is `epoch_shape(secret, 0)` by definition and does not
        // move. That immobility is the whole reason it can serve as a rendezvous shape for a node that knows
        // no epoch, and it is also its only cost — see [`OpenedUnder::Genesis`].
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
            None => obfuscate(&self.shape, frame, &self.packet_nonce(seq)),
        };
        self.profile.pad_to_target(&mut wire, &self.shape.scramble_seed, seq);
        let delay = self.profile.packet_delay(&self.shape.scramble_seed, seq);
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
        let mut material = self.shape.scramble_seed.to_vec();
        material.extend_from_slice(&seq.to_be_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        hash_xof(NONCE_LABEL, &material, &mut nonce);
        nonce
    }

    /// Recover an inbound frame, or `None` if it was not shaped by the same secret and epoch —
    /// a peer without the community secret cannot produce a frame this shaper will accept. [`Morph::Plain`]
    /// is identity (the frame passed through unshaped). Size-shaping padding on the wire is transparent here:
    /// the codec's length field bounds the payload, so trailing pad is ignored.
    #[must_use]
    pub fn inbound(&self, wire: &[u8]) -> Option<Vec<u8>> {
        if let Some(codec) = &self.codec {
            return codec.decode(wire);
        }
        if self.morph == Morph::Plain {
            return Some(wire.to_vec());
        }
        // Current epoch first: in steady state — which is almost all of the time — the first attempt
        // succeeds and the grace shapes are never touched. See [`SHAPE_GRACE`] for why the other two exist
        // and why both sides are needed rather than only the past.
        deobfuscate(&self.shape, wire)
            .or_else(|| deobfuscate(&self.grace[0], wire))
            .or_else(|| deobfuscate(&self.grace[1], wire))
            // Last, and only past the grace window: a peer that has not yet learned the epoch
            // ([`OpenedUnder::Genesis`]). Fourth in the chain because it is the rarest, so the steady state
            // never pays for it beyond the miss it was already paying.
            .or_else(|| self.beyond_grace().then(|| deobfuscate(&self.genesis, wire)).flatten())
    }

    /// Whether the genesis shape is a *distinct* fourth candidate rather than one already inside the
    /// `{epoch − 1, epoch, epoch + 1}` window.
    ///
    /// Below this threshold the genesis shape is `Current` or `Grace` and trying it again would be a wasted
    /// `deobfuscate` — and, worse, would report [`OpenedUnder::Genesis`] for an ordinary peer, so a node at
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
        seal(&self.shape, payload, nonce)
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
        if let Some(len) = open_in_place(&self.shape, buf) {
            return Some((len, OpenedUnder::Current));
        }
        if let Some(len) = open_in_place(&self.grace[0], buf).or_else(|| open_in_place(&self.grace[1], buf)) {
            return Some((len, OpenedUnder::Grace));
        }
        if self.beyond_grace()
            && let Some(len) = open_in_place(&self.genesis, buf)
        {
            return Some((len, OpenedUnder::Genesis));
        }
        None
    }

    /// Seal one datagram under the **genesis** shape rather than this node's current one — the reply half of
    /// [`OpenedUnder::Genesis`], and the only way an established node can answer a peer that has not yet
    /// learned the epoch.
    ///
    /// Separate from [`seal_datagram`](Self::seal_datagram) instead of a parameter on it, because the default
    /// must stay "the current epoch": a shape argument on the hot path is a shape argument someone eventually
    /// passes `Epoch::ZERO` to by accident, and that is the static wire signature §13.4 exists to remove.
    /// Use it only for a peer this node has just *observed* speaking genesis, never speculatively.
    #[must_use]
    pub fn seal_datagram_at_genesis(&self, payload: &[u8], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
        seal(&self.genesis, payload, nonce)
    }

    /// Wrap an outbound **frame** under the genesis shape — the frame-layer twin of
    /// [`seal_datagram_at_genesis`](Self::seal_datagram_at_genesis), for the same peer and the same reason.
    ///
    /// Both layers are needed, and that is not redundancy: the datagram envelope carries the QUIC packet and
    /// the frame codec carries what is inside it, each keyed independently on the epoch. Fixing only the
    /// envelope gets a joining node's handshake through and then loses its first HELLO.
    #[must_use]
    pub fn outbound_at_genesis(&self, frame: &[u8]) -> Vec<u8> {
        let seq = self.counter.fetch_add(1, Ordering::Relaxed);
        if self.morph == Morph::Plain {
            return frame.to_vec();
        }
        let mut nonce = [0u8; NONCE_LEN];
        let mut material = self.genesis.scramble_seed.to_vec();
        material.extend_from_slice(&seq.to_be_bytes());
        hash_xof(NONCE_LABEL, &material, &mut nonce);
        let mut wire = obfuscate(&self.genesis, frame, &nonce);
        self.profile.pad_to_target(&mut wire, &self.genesis.scramble_seed, seq);
        wire
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
#[allow(clippy::unwrap_used)]
mod tests {
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
        assert_eq!(shaper.inbound(&wire).unwrap(), frame);
    }

    #[test]
    fn two_peers_sharing_the_secret_interoperate() {
        let alice = ProteusShaper::new(b"s".to_vec(), Epoch::new(9));
        let bob = ProteusShaper::new(b"s".to_vec(), Epoch::new(9));
        let wire = alice.outbound(b"hi bob");
        assert_eq!(bob.inbound(&wire).unwrap(), b"hi bob");
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
            late.inbound(&forward).as_deref(),
            Some(b"from the node that turned first".as_slice()),
            "a peer that has not yet rotated must still read the one that has — otherwise whichever node \
             turns first is unreachable for the whole beacon spread"
        );

        // And the half it does cover, which must not regress.
        let back = late.outbound(b"from the node still behind");
        assert_eq!(
            early.inbound(&back).as_deref(),
            Some(b"from the node still behind".as_slice()),
            "and the node that has rotated must still read the one that has not"
        );

        // Two epochs apart is outside the window, in both directions.
        let far = ProteusShaper::new(b"s".to_vec(), Epoch::new(12));
        assert!(
            far.inbound(&back).is_none() && late.inbound(&far.outbound(b"x")).is_none(),
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
            genesis.inbound(&next.outbound(b"forward from epoch 1")).as_deref(),
            Some(b"forward from epoch 1".as_slice()),
            "epoch 0 still accepts epoch 1 — the forward half is what a fresh node needs"
        );
        let wrapped = ProteusShaper::new(b"s".to_vec(), Epoch::new(u64::MAX));
        assert!(
            genesis.inbound(&wrapped.outbound(b"x")).is_none(),
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
            receiver.inbound(&shaped.wire).as_deref(),
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
        assert_eq!(receiver.inbound(&shaped.wire).as_deref(), Some(&b"hello"[..]));
        let builtin = ProteusShaper::new(b"s".to_vec(), Epoch::ZERO);
        assert_ne!(builtin.inbound(&shaped.wire).as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn set_morph_off_pluggable_restores_the_builtin_codec() {
        let mut shaper = ProteusShaper::with_codec(b"s".to_vec(), Epoch::ZERO, Arc::new(MockCodec)).unwrap();
        shaper.set_morph(Morph::Polymorph);
        assert_eq!(shaper.morph(), Morph::Polymorph);
        // The built-in codec is back: a plain Polymorph shaper decodes the frame (the mock codec would not).
        let shaped = shaper.shape(b"builtin again");
        let rx = ProteusShaper::new(b"s".to_vec(), Epoch::ZERO);
        assert_eq!(rx.inbound(&shaped.wire).as_deref(), Some(&b"builtin again"[..]));
    }

    #[test]
    fn switching_to_plain_is_identity() {
        let mut shaper = ProteusShaper::new(b"s".to_vec(), Epoch::ZERO);
        shaper.set_morph(Morph::Plain);
        let frame = b"unshaped";
        let shaped = shaper.shape(frame);
        assert_eq!(shaped.wire, frame, "Plain passes the frame through unshaped");
        assert_eq!(shaper.inbound(frame).as_deref(), Some(&frame[..]));
    }

    #[test]
    fn the_wrong_secret_cannot_recover_the_frame() {
        let sender = ProteusShaper::new(b"real-secret".to_vec(), Epoch::new(3));
        let eavesdropper = ProteusShaper::new(b"guessed-secret".to_vec(), Epoch::new(3));
        let wire = sender.outbound(b"secret payload");
        // Different junk length ⇒ the recovered bytes are not the original frame.
        assert_ne!(
            eavesdropper.inbound(&wire).as_deref(),
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
        assert_eq!(rx.inbound(&w0).unwrap(), frame);
        assert_eq!(rx.inbound(&w1).unwrap(), frame);
    }
}
