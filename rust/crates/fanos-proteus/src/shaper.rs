//! The transport-layer shaper — PROTEUS as a driver wrapper (spec §13.2, §13.4).
//!
//! A driver (the QUIC transport, the simulator) wraps every outbound frame through a
//! [`ProteusShaper`] and unwraps every inbound one. The engine is untouched: the shaper lives
//! entirely below the sans-I/O boundary, exactly where the wire signature lives. Two peers holding
//! the same community secret derive the same epoch shape and so strip each other's wrapping; an
//! observer sees only shaped bytes with no fixed signature, and the shape **rotates every epoch**
//! (§13.4), so a classifier trained on one epoch is stale the next.

use alloc::vec::Vec;

use crate::obfuscate::{deobfuscate, obfuscate};
use crate::shape::{ShapeParams, epoch_shape};

/// A stateful per-connection shaper: the community secret plus the current epoch's shape.
#[derive(Clone, Debug)]
pub struct ProteusShaper {
    secret: Vec<u8>,
    epoch: u32,
    shape: ShapeParams,
}

impl ProteusShaper {
    /// A shaper for `epoch`, keyed by the shared `community_secret`.
    #[must_use]
    pub fn new(community_secret: impl Into<Vec<u8>>, epoch: u32) -> Self {
        let secret = community_secret.into();
        let shape = epoch_shape(&secret, epoch);
        Self {
            secret,
            epoch,
            shape,
        }
    }

    /// Advance to a new epoch: the shape rotates, so the wire signature moves (§13.4, V22).
    pub fn rotate(&mut self, epoch: u32) {
        self.epoch = epoch;
        self.shape = epoch_shape(&self.secret, epoch);
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Wrap an outbound frame for the wire — junk-padded and shaped so it carries no static
    /// signature (§13.2).
    #[must_use]
    pub fn outbound(&self, frame: &[u8]) -> Vec<u8> {
        obfuscate(&self.shape, frame)
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
        let shaper = ProteusShaper::new(b"community".to_vec(), 5);
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
        let alice = ProteusShaper::new(b"s".to_vec(), 9);
        let bob = ProteusShaper::new(b"s".to_vec(), 9);
        let wire = alice.outbound(b"hi bob");
        assert_eq!(bob.inbound(&wire).unwrap(), b"hi bob");
    }

    #[test]
    fn the_wire_signature_rotates_every_epoch() {
        let mut shaper = ProteusShaper::new(b"s".to_vec(), 0);
        let w0 = shaper.outbound(b"same payload");
        shaper.rotate(1);
        let w1 = shaper.outbound(b"same payload");
        assert_ne!(w0, w1, "the same frame shapes differently each epoch");
    }

    #[test]
    fn the_wrong_secret_cannot_recover_the_frame() {
        let sender = ProteusShaper::new(b"real-secret".to_vec(), 3);
        let eavesdropper = ProteusShaper::new(b"guessed-secret".to_vec(), 3);
        let wire = sender.outbound(b"secret payload");
        // Different junk length ⇒ the recovered bytes are not the original frame.
        assert_ne!(
            eavesdropper.inbound(&wire).as_deref(),
            Some(&b"secret payload"[..])
        );
    }
}
