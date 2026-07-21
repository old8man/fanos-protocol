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
    shape: ShapeParams,
    counter: AtomicU64,
}

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
        Self {
            secret,
            morph,
            profile: ShapingProfile::for_morph(morph),
            codec: None,
            epoch,
            shape,
            counter: AtomicU64::new(0),
        }
    }

    /// A shaper driven by a **pluggable** [`MorphCodec`] (§13.3 SPI) instead of the built-in codec — the
    /// [`Morph::Pluggable`] mode. The custom codec fully handles encode/decode; the size/timing profile is
    /// the (identity) `Pluggable` default, so the codec owns the wire. The community secret still seeds the
    /// epoch shape (so a codec MAY consult it), and the epoch still rotates via [`rotate`](Self::rotate).
    #[must_use]
    pub fn with_codec(
        community_secret: impl Into<Vec<u8>>,
        epoch: Epoch,
        codec: Arc<dyn MorphCodec>,
    ) -> Self {
        let secret = community_secret.into();
        let shape = epoch_shape(&secret, epoch);
        Self {
            secret,
            morph: Morph::Pluggable,
            profile: ShapingProfile::for_morph(Morph::Pluggable),
            codec: Some(codec),
            epoch,
            shape,
            counter: AtomicU64::new(0),
        }
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
    pub fn set_morph(&mut self, morph: Morph) {
        self.morph = morph;
        self.profile = ShapingProfile::for_morph(morph);
        // Switching to a built-in morph drops any pluggable codec: a shaper is either codec-driven or
        // built-in-morph-driven, never both.
        self.codec = None;
    }

    /// Advance to a new epoch: the shape rotates, so the wire signature moves (§13.4, V22).
    pub fn rotate(&mut self, epoch: Epoch) {
        self.epoch = epoch;
        self.shape = epoch_shape(&self.secret, epoch);
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
        deobfuscate(&self.shape, wire)
    }
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
        // Rotating among codec-using morphs (the auto-fallback path) keeps a peer decoding: a frame shaped
        // after a switch to the size+timing TLS morph still strips back under the original Polymorph shaper.
        let mut sender = ProteusShaper::new(b"s".to_vec(), Epoch::new(4));
        let receiver = ProteusShaper::new(b"s".to_vec(), Epoch::new(4));
        sender.set_morph(Morph::TlsTunnel);
        assert_eq!(sender.morph(), Morph::TlsTunnel);
        let shaped = sender.shape(b"post-rotation frame");
        assert!(shaped.wire.len() >= 1200, "the TLS profile pads into its size band");
        assert_eq!(
            receiver.inbound(&shaped.wire).as_deref(),
            Some(&b"post-rotation frame"[..]),
            "a peer on the old morph still decodes — the codec is shared"
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

    #[test]
    fn a_pluggable_codec_replaces_the_builtin_transform() {
        let shaper = ProteusShaper::with_codec(b"s".to_vec(), Epoch::ZERO, Arc::new(MockCodec));
        assert_eq!(shaper.morph(), Morph::Pluggable);
        let shaped = shaper.shape(b"hello");
        assert!(shaped.wire.ends_with(&[0xAB]), "the custom codec produced the wire, not obfuscate");

        // A peer running the same codec recovers it; the built-in polymorph decode does NOT.
        let receiver = ProteusShaper::with_codec(b"s".to_vec(), Epoch::ZERO, Arc::new(MockCodec));
        assert_eq!(receiver.inbound(&shaped.wire).as_deref(), Some(&b"hello"[..]));
        let builtin = ProteusShaper::new(b"s".to_vec(), Epoch::ZERO);
        assert_ne!(builtin.inbound(&shaped.wire).as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn set_morph_off_pluggable_restores_the_builtin_codec() {
        let mut shaper = ProteusShaper::with_codec(b"s".to_vec(), Epoch::ZERO, Arc::new(MockCodec));
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
