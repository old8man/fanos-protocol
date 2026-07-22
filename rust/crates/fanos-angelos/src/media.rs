//! The **real-time media session** — the crypto under an ANGELOS voice/video call (`spec/platform.md` §6.2).
//!
//! Real-time media is a different regime from text: 50 packets/s per stream, loss and reordering are normal,
//! and you cannot ratchet per packet. So a media session keys every frame with a **per-call epoch key**
//! (agreed over the anonymous control plane) under an SRTP-like construction: each frame is independently
//! AEAD-sealed, sequence-numbered, and *loss-tolerant* — any frame opens on its own, out of order or after gaps.
//! Forward secrecy is provided **across epochs, not packets**: [`rekey`](MediaSession::rekey) advances the key
//! by a one-way step (a call rekeys periodically, or on a membership change), so a compromised key exposes only
//! the current epoch's frames. Voice, video, and data are just typed streams ([`MediaKind`]) over the session.

use alloc::vec::Vec;

use fanos_primitives::{aead, hash_labeled};

use crate::nonce;

/// Label deriving the epoch-0 media key from the call secret.
const EPOCH0_LABEL: &str = "FANOS-angelos-v1/media-epoch0";
/// Label advancing the media key to the next epoch.
const NEXT_EPOCH_LABEL: &str = "FANOS-angelos-v1/media-next-epoch";

/// The kind of media a frame carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MediaKind {
    /// An audio frame.
    Audio,
    /// A video frame.
    Video,
    /// An application data frame (e.g. screen-share control, file chunk).
    Data,
}

impl MediaKind {
    #[must_use]
    fn tag(self) -> u8 {
        match self {
            MediaKind::Audio => 0,
            MediaKind::Video => 1,
            MediaKind::Data => 2,
        }
    }

    #[must_use]
    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(MediaKind::Audio),
            1 => Some(MediaKind::Video),
            2 => Some(MediaKind::Data),
            _ => None,
        }
    }
}

/// A per-call media session keyed on the current epoch key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MediaSession {
    key: [u8; 32],
    epoch: u32,
    send_seq: u64,
}

impl MediaSession {
    /// Start a media session from the `call_secret` agreed over the control plane (its epoch-0 key).
    #[must_use]
    pub fn new(call_secret: &[u8; 32]) -> Self {
        Self { key: hash_labeled(EPOCH0_LABEL, call_secret), epoch: 0, send_seq: 0 }
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Advance to the next epoch (a periodic or membership-triggered rekey), giving forward secrecy across
    /// epochs. Both ends rekey in lock-step (coordinated over the control plane).
    pub fn rekey(&mut self) {
        self.key = hash_labeled(NEXT_EPOCH_LABEL, &self.key);
        self.epoch = self.epoch.saturating_add(1);
        self.send_seq = 0;
    }

    /// Seal one media frame: `epoch(4) ‖ seq(8) ‖ AEAD(kind ‖ payload)`. Frames are independently openable and
    /// loss-tolerant.
    #[must_use]
    pub fn seal_frame(&mut self, kind: MediaKind, payload: &[u8]) -> Vec<u8> {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.saturating_add(1);
        let mut inner = Vec::with_capacity(1 + payload.len());
        inner.push(kind.tag());
        inner.extend_from_slice(payload);
        let ciphertext = aead::seal(&self.key, &nonce(seq), &inner).unwrap_or_default();
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Open one media frame, returning `(sequence, kind, payload)`. `None` if malformed, from a different epoch
    /// (a stale frame after a rekey, dropped as real-time media should), or failing authentication. Stateless in
    /// the sequence — any frame of the current epoch opens, in any order, so loss and reordering are fine.
    #[must_use]
    pub fn open_frame(&self, sealed: &[u8]) -> Option<(u64, MediaKind, Vec<u8>)> {
        let epoch = u32::from_le_bytes(sealed.get(..4)?.try_into().ok()?);
        if epoch != self.epoch {
            return None;
        }
        let seq = u64::from_le_bytes(sealed.get(4..12)?.try_into().ok()?);
        let inner = aead::open(&self.key, &nonce(seq), sealed.get(12..)?)?;
        let (&tag, payload) = inner.split_first()?;
        Some((seq, MediaKind::from_tag(tag)?, payload.to_vec()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const CALL_SECRET: [u8; 32] = [0x33; 32];

    #[test]
    fn frames_seal_and_open_and_are_loss_tolerant() {
        let mut tx = MediaSession::new(&CALL_SECRET);
        let rx = MediaSession::new(&CALL_SECRET);
        let f0 = tx.seal_frame(MediaKind::Audio, b"audio0");
        let f1 = tx.seal_frame(MediaKind::Video, b"video1");
        let f2 = tx.seal_frame(MediaKind::Audio, b"audio2");
        // Open out of order and with a gap (frame 1 "lost") — real-time media tolerates it.
        assert_eq!(rx.open_frame(&f2), Some((2, MediaKind::Audio, b"audio2".to_vec())));
        assert_eq!(rx.open_frame(&f0), Some((0, MediaKind::Audio, b"audio0".to_vec())));
        assert_eq!(rx.open_frame(&f1), Some((1, MediaKind::Video, b"video1".to_vec())));
    }

    #[test]
    fn a_rekey_gives_forward_secrecy_across_epochs() {
        let mut tx = MediaSession::new(&CALL_SECRET);
        let mut rx = MediaSession::new(&CALL_SECRET);
        let old = tx.seal_frame(MediaKind::Audio, b"epoch0");
        assert_eq!(rx.open_frame(&old).map(|(_, _, p)| p), Some(b"epoch0".to_vec()));
        // Both rekey in lock-step.
        tx.rekey();
        rx.rekey();
        assert_eq!(tx.epoch(), 1);
        let new = tx.seal_frame(MediaKind::Audio, b"epoch1");
        assert_eq!(rx.open_frame(&new).map(|(_, _, p)| p), Some(b"epoch1".to_vec()));
        // A stale epoch-0 frame no longer opens (the old key is gone → forward secrecy).
        assert!(rx.open_frame(&old).is_none(), "a pre-rekey frame is dropped after the rekey");
    }

    #[test]
    fn a_wrong_call_secret_or_tamper_cannot_open() {
        let mut tx = MediaSession::new(&CALL_SECRET);
        let eve = MediaSession::new(&[0x99; 32]);
        let frame = tx.seal_frame(MediaKind::Video, b"secret call");
        assert!(eve.open_frame(&frame).is_none(), "the wrong call secret cannot open a frame");
        let rx = MediaSession::new(&CALL_SECRET);
        let mut bad = frame.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(rx.open_frame(&bad).is_none(), "a tampered frame is refused");
    }
}
