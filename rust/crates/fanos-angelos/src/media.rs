//! The **real-time media session** — the crypto under an ANGELOS voice/video call (`spec/platform.md` §6.2).
//!
//! Real-time media is a different regime from text: 50 packets/s per stream, loss and reordering are normal,
//! and you cannot ratchet per packet. So a media session keys every frame with a **per-call, per-direction
//! epoch key** (agreed over the anonymous control plane) under an SRTP-like construction: each frame is
//! independently AEAD-sealed, sequence-numbered, and *loss-tolerant* — any frame opens on its own, out of order
//! or after gaps. Forward secrecy is provided **across epochs, not packets**: [`rekey`](MediaSession::rekey)
//! advances the keys by a one-way step (a call rekeys periodically, or on a membership change), so a compromised
//! key exposes only the current epoch's frames.
//!
//! **Direction split (load-bearing).** The two ends derive *distinct* send keys from the shared call secret —
//! the caller seals under `H(…-caller, secret)`, the callee under `H(…-callee, secret)` — so the caller's frame
//! `seq=0` and the callee's frame `seq=0` never collide on a `(key, nonce)` pair. Sharing one key across both
//! directions (as an earlier version did) is a ChaCha20-Poly1305 nonce reuse — a two-time pad and a forgery — so
//! the split is not an optimization but a correctness requirement, exactly as the 1:1 [`crate::session`] splits
//! `a2b`/`b2a`. Voice, video, and data are just typed streams ([`MediaKind`]) over the session.

use alloc::vec::Vec;

use fanos_primitives::{aead, hash_labeled};
use zeroize::Zeroize;

use crate::nonce;

/// Label deriving the caller's epoch-0 media key from the call secret.
const CALLER_EPOCH0_LABEL: &str = "FANOS-angelos-v1/media-epoch0-caller";
/// Label deriving the callee's epoch-0 media key from the call secret.
const CALLEE_EPOCH0_LABEL: &str = "FANOS-angelos-v1/media-epoch0-callee";
/// Label advancing a media key to the next epoch.
const NEXT_EPOCH_LABEL: &str = "FANOS-angelos-v1/media-next-epoch";

/// Which end of the call this party is — it fixes which directional key is *send* and which is *receive*.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MediaRole {
    /// The party that initiated the call (its [`CallSignal::Invite`](crate::call::CallSignal::Invite) side).
    Caller,
    /// The party that accepted the call.
    Callee,
}

impl MediaRole {
    /// The epoch-0 key label for this role's *send* direction.
    #[must_use]
    fn send_label(self) -> &'static str {
        match self {
            MediaRole::Caller => CALLER_EPOCH0_LABEL,
            MediaRole::Callee => CALLEE_EPOCH0_LABEL,
        }
    }

    /// The epoch-0 key label for this role's *receive* direction (the peer's send label).
    #[must_use]
    fn recv_label(self) -> &'static str {
        match self {
            MediaRole::Caller => CALLEE_EPOCH0_LABEL,
            MediaRole::Callee => CALLER_EPOCH0_LABEL,
        }
    }
}

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

/// A per-call media session keyed on the current epoch's directional keys.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MediaSession {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    epoch: u32,
    send_seq: u64,
}

impl Drop for MediaSession {
    fn drop(&mut self) {
        // Audit AT-M1: wipe both directions' media keys on drop.
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

impl MediaSession {
    /// Start a media session from the `call_secret` agreed over the control plane and this party's `role`: the
    /// send key is this direction's epoch-0 key, the receive key the peer's — so the two ends' frames never share
    /// a `(key, nonce)`.
    #[must_use]
    pub fn new(call_secret: &[u8; 32], role: MediaRole) -> Self {
        Self {
            send_key: hash_labeled(role.send_label(), call_secret),
            recv_key: hash_labeled(role.recv_label(), call_secret),
            epoch: 0,
            send_seq: 0,
        }
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Advance to the next epoch (a periodic or membership-triggered rekey), giving forward secrecy across
    /// epochs. Both directional keys advance; both ends rekey in lock-step (coordinated over the control plane).
    pub fn rekey(&mut self) {
        self.send_key = hash_labeled(NEXT_EPOCH_LABEL, &self.send_key);
        self.recv_key = hash_labeled(NEXT_EPOCH_LABEL, &self.recv_key);
        self.epoch = self.epoch.saturating_add(1);
        self.send_seq = 0;
    }

    /// Seal one media frame under this party's *send* key: `epoch(4) ‖ seq(8) ‖ AEAD(kind ‖ payload)`. Frames are
    /// independently openable and loss-tolerant.
    #[must_use]
    pub fn seal_frame(&mut self, kind: MediaKind, payload: &[u8]) -> Vec<u8> {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.saturating_add(1);
        let mut inner = Vec::with_capacity(1 + payload.len());
        inner.push(kind.tag());
        inner.extend_from_slice(payload);
        let ciphertext = aead::seal(&self.send_key, &nonce(seq), &inner).unwrap_or_default();
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Open one media frame under the peer's send key (this party's *receive* key), returning
    /// `(sequence, kind, payload)`. `None` if malformed, from a different epoch (a stale frame after a rekey), or
    /// failing authentication. Stateless in the sequence — any frame of the current epoch opens, in any order, so
    /// loss and reordering are fine.
    #[must_use]
    pub fn open_frame(&self, sealed: &[u8]) -> Option<(u64, MediaKind, Vec<u8>)> {
        let epoch = u32::from_le_bytes(sealed.get(..4)?.try_into().ok()?);
        if epoch != self.epoch {
            return None;
        }
        let seq = u64::from_le_bytes(sealed.get(4..12)?.try_into().ok()?);
        let inner = aead::open(&self.recv_key, &nonce(seq), sealed.get(12..)?)?;
        let (&tag, payload) = inner.split_first()?;
        Some((seq, MediaKind::from_tag(tag)?, payload.to_vec()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const CALL_SECRET: [u8; 32] = [0x33; 32];

    /// A matched caller/callee media pair over the same call secret.
    fn pair() -> (MediaSession, MediaSession) {
        (MediaSession::new(&CALL_SECRET, MediaRole::Caller), MediaSession::new(&CALL_SECRET, MediaRole::Callee))
    }

    #[test]
    fn frames_seal_and_open_across_directions_and_are_loss_tolerant() {
        let (mut caller, callee) = pair();
        let f0 = caller.seal_frame(MediaKind::Audio, b"audio0");
        let f1 = caller.seal_frame(MediaKind::Video, b"video1");
        let f2 = caller.seal_frame(MediaKind::Audio, b"audio2");
        // The callee opens the caller's frames out of order and with a gap (frame 1 "lost").
        assert_eq!(callee.open_frame(&f2), Some((2, MediaKind::Audio, b"audio2".to_vec())));
        assert_eq!(callee.open_frame(&f0), Some((0, MediaKind::Audio, b"audio0".to_vec())));
        assert_eq!(callee.open_frame(&f1), Some((1, MediaKind::Video, b"video1".to_vec())));
    }

    #[test]
    fn the_two_directions_never_share_a_key_nonce_pair() {
        // Both parties seal their own seq=0 frame; the ciphertexts differ (distinct keys) and neither opens
        // under its own send key — the whole point of the direction split (no two-time pad).
        let (mut caller, mut callee) = pair();
        let c0 = caller.seal_frame(MediaKind::Audio, b"same");
        let d0 = callee.seal_frame(MediaKind::Audio, b"same");
        assert_ne!(c0, d0, "the same plaintext at seq 0 seals differently in each direction");
        // The callee opens the caller's frame (cross-direction), and cannot open its own (wrong key).
        assert_eq!(callee.open_frame(&c0).map(|(_, _, p)| p), Some(b"same".to_vec()));
        assert!(callee.open_frame(&d0).is_none(), "a party cannot open its own send frame (distinct directions)");
    }

    #[test]
    fn a_rekey_gives_forward_secrecy_across_epochs() {
        let (mut caller, mut callee) = pair();
        let old = caller.seal_frame(MediaKind::Audio, b"epoch0");
        assert_eq!(callee.open_frame(&old).map(|(_, _, p)| p), Some(b"epoch0".to_vec()));
        // Both rekey in lock-step.
        caller.rekey();
        callee.rekey();
        assert_eq!(caller.epoch(), 1);
        let new = caller.seal_frame(MediaKind::Audio, b"epoch1");
        assert_eq!(callee.open_frame(&new).map(|(_, _, p)| p), Some(b"epoch1".to_vec()));
        // A stale epoch-0 frame no longer opens (the old key is gone → forward secrecy).
        assert!(callee.open_frame(&old).is_none(), "a pre-rekey frame is dropped after the rekey");
    }

    #[test]
    fn a_wrong_call_secret_or_tamper_cannot_open() {
        let mut caller = MediaSession::new(&CALL_SECRET, MediaRole::Caller);
        let eve = MediaSession::new(&[0x99; 32], MediaRole::Callee);
        let frame = caller.seal_frame(MediaKind::Video, b"secret call");
        assert!(eve.open_frame(&frame).is_none(), "the wrong call secret cannot open a frame");
        let callee = MediaSession::new(&CALL_SECRET, MediaRole::Callee);
        let mut bad = frame.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(callee.open_frame(&bad).is_none(), "a tampered frame is refused");
    }
}
