//! The transport-layer shaper — PROTEUS as a driver wrapper (spec §13.2, §13.4).
//!
//! A driver (the QUIC transport, the simulator) wraps every outbound frame through a
//! [`ProteusShaper`] and unwraps every inbound one. The engine is untouched: the shaper lives
//! entirely below the sans-I/O boundary, exactly where the wire signature lives. Two peers holding
//! the same community secret derive the same epoch shape and so strip each other's wrapping; an
//! observer sees only shaped bytes with no fixed signature, and the shape **rotates every epoch**
//! (§13.4), so a classifier trained on one epoch is stale the next.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use fanos_primitives::Epoch;
use fanos_primitives::hash::hash_xof;

use crate::obfuscate::{NONCE_LEN, deobfuscate, obfuscate};
use crate::shape::{ShapeParams, epoch_shape};

const NONCE_LABEL: &str = "FANOS-v1/proteus-packet-nonce";

/// A stateful per-connection shaper: the community secret, the current epoch's shape, and a
/// monotonic packet counter that diversifies each packet's junk (interior-mutable, so the shaper
/// can be shared `&self` behind an `Arc` across a connection's concurrent sends).
#[derive(Debug)]
pub struct ProteusShaper {
    secret: Vec<u8>,
    epoch: Epoch,
    shape: ShapeParams,
    counter: AtomicU64,
}

impl ProteusShaper {
    /// A shaper for `epoch`, keyed by the shared `community_secret`.
    #[must_use]
    pub fn new(community_secret: impl Into<Vec<u8>>, epoch: Epoch) -> Self {
        let secret = community_secret.into();
        let shape = epoch_shape(&secret, epoch);
        Self {
            secret,
            epoch,
            shape,
            counter: AtomicU64::new(0),
        }
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

    /// Wrap an outbound frame for the wire — junk-padded and shaped so it carries no static
    /// signature, with **per-packet** junk so even identical frames shape to different bytes
    /// (§13.2–§13.4). Each call consumes one packet-counter value, PRF'd into a random-looking
    /// nonce that seeds this packet's junk/padding keystream.
    #[must_use]
    pub fn outbound(&self, frame: &[u8]) -> Vec<u8> {
        let seq = self.counter.fetch_add(1, Ordering::Relaxed);
        obfuscate(&self.shape, frame, &self.packet_nonce(seq))
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
    /// a peer without the community secret cannot produce a frame this shaper will accept.
    #[must_use]
    pub fn inbound(&self, wire: &[u8]) -> Option<Vec<u8>> {
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
