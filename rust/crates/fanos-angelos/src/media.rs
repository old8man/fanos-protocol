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

/// How far a frame may be reordered behind the newest one and still be accepted — the replay window's width,
/// in frames.
///
/// **Derived, not picked, and the derivation is that width is free in one direction and costly in neither.**
/// Two facts about this construction fix it:
///
/// 1. *Widening never admits a replay.* Every sequence the window remembers is refused individually by the
///    bitmap, and [`MediaSession::is_replay`] refuses anything that has fallen off the back as well. So
///    forgetting causes **false rejects**, never admissions — the failure of a narrow window is a liveness
///    failure, and the failure of a wide one is nothing.
/// 2. *State cost is flat up to the machine word.* A bitmap of any width from 1 to 64 is one `u64`.
///
/// A quantity that is monotonically better up to a hard structural limit, at constant cost, should sit at
/// that limit. Hence the full word. RFC 3711 §3.3.2 mandating *at least* 64 for SRTP is corroboration that
/// this is the right order of magnitude for real paths — at 20 ms voice framing it is 1.28 s of reordering
/// tolerance — but it is not the reason, and a future `u128` bitmap would move the number without moving the
/// argument.
///
/// If a real path ever reorders past it, that is a *measurement* rather than a silent drop: see
/// [`MediaSession::reordered_past_window`].
const REPLAY_WINDOW: u64 = 64;

/// Where an arriving frame's sequence stands relative to the replay window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Freshness {
    /// Not seen this epoch, and inside what the window remembers — open it.
    Fresh,
    /// Already accepted. A replay, or a duplicate the path produced.
    AlreadySeen,
    /// Further behind than the window remembers, so it cannot be judged — refused, and counted, because this
    /// is the window being too narrow rather than anything the sender did.
    PastWindow,
}

/// A per-call media session keyed on the current epoch's directional keys.
pub struct MediaSession {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    epoch: u32,
    send_seq: u64,
    /// The highest sequence accepted this epoch, and a bitmap of which of the `REPLAY_WINDOW` frames below
    /// it have already been seen — bit `i` ⇔ `highest_seen − 1 − i`.
    ///
    /// Without this a captured frame re-opens for as long as its epoch is current (audit AT-H3). AEAD proves a
    /// frame was authentic *once*; only a replay window proves it has not been seen before, which is why SRTP
    /// mandates one and why the "stateless in the sequence, so reordering is fine" comment this replaces was
    /// describing a hazard as a feature.
    highest_seen: Option<u64>,
    seen_below: u64,
    /// Frames refused for arriving further behind than the window remembers.
    ///
    /// Counted because the alternative is a silent drop that looks exactly like packet loss, and the two call
    /// for opposite responses: loss is the network's, this is the window being too narrow for the path. A
    /// nonzero value here is the evidence that would justify a wider bitmap — which is how `REPLAY_WINDOW`
    /// should ever change, rather than by someone's judgement of what feels roomy.
    reordered_past_window: u64,
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
            highest_seen: None,
            seen_below: 0,
            reordered_past_window: 0,
        }
    }

    /// How many frames this session refused for arriving further behind than `REPLAY_WINDOW` remembers.
    ///
    /// Distinct from loss, and the distinction is the point: loss is the network's business, this is the
    /// window being too narrow for the path it is running on.
    #[must_use]
    pub fn reordered_past_window(&self) -> u64 {
        self.reordered_past_window
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
        // The window is per-epoch: sequences restart at 0, so carrying the old one forward would reject the
        // new epoch's first frames as ancient replays.
        self.highest_seen = None;
        self.seen_below = 0;
    }

    /// Seal one media frame under this party's *send* key: `epoch(4) ‖ seq(8) ‖ AEAD(kind ‖ payload)`. Frames are
    /// independently openable and loss-tolerant.
    /// `None` on the AEAD-setup error, unreachable for any payload this build produces. The sequence number
    /// is spent only once the frame exists (#338): a media session has no [`SendChain`] to hold that rule for
    /// it, so it is kept here by hand, and the reason is the same one — a number spent on nothing steps the
    /// peer's replay window past a frame that never existed.
    #[must_use]
    pub fn seal_frame(&mut self, kind: MediaKind, payload: &[u8]) -> Option<Vec<u8>> {
        let seq = self.send_seq;
        let mut inner = Vec::with_capacity(1 + payload.len());
        inner.push(kind.tag());
        inner.extend_from_slice(payload);
        let ciphertext = aead::seal(&self.send_key, &nonce(seq), &inner)?;
        // Commit only once the frame is built.
        self.send_seq = self.send_seq.saturating_add(1);
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&ciphertext);
        Some(out)
    }

    /// Open one media frame under the peer's send key (this party's *receive* key), returning
    /// `(sequence, kind, payload)`. `None` if malformed, from a different epoch (a stale frame after a rekey),
    /// failing authentication, or **replayed**.
    ///
    /// Loss and reordering are still fine — a frame within `REPLAY_WINDOW` of the newest one opens whatever
    /// order it arrives in. What no longer works is opening the *same* frame twice: AEAD proves a frame was
    /// authentic once, and only the window proves it has not been seen before (RFC 3711 §3.3.2, audit AT-H3).
    ///
    /// Takes `&mut self`, and that is the point — the previous signature was `&self`, which is precisely the
    /// type-level statement that no such check was happening.
    pub fn open_frame(&mut self, sealed: &[u8]) -> Option<(u64, MediaKind, Vec<u8>)> {
        let epoch = u32::from_le_bytes(sealed.get(..4)?.try_into().ok()?);
        if epoch != self.epoch {
            return None;
        }
        let seq = u64::from_le_bytes(sealed.get(4..12)?.try_into().ok()?);
        match self.classify(seq) {
            Freshness::Fresh => {}
            Freshness::AlreadySeen => return None,
            Freshness::PastWindow => {
                self.reordered_past_window = self.reordered_past_window.saturating_add(1);
                return None;
            }
        }
        // Authenticate BEFORE recording: a forged frame carrying an unseen sequence must not be able to burn
        // that slot and make the genuine frame behind it look like a replay.
        let inner = aead::open(&self.recv_key, &nonce(seq), sealed.get(12..)?)?;
        let (&tag, payload) = inner.split_first()?;
        let kind = MediaKind::from_tag(tag)?;
        self.record_seen(seq);
        Some((seq, kind, payload.to_vec()))
    }

    /// Where `seq` stands relative to what this epoch has already accepted.
    ///
    /// Three outcomes rather than a boolean, because two of them are refusals for *different reasons* and
    /// summing them would repeat the mistake this session keeps finding elsewhere: a replay is an attack or a
    /// duplicate, while past-the-window is the window being too narrow for the path.
    fn classify(&self, seq: u64) -> Freshness {
        let Some(highest) = self.highest_seen else {
            return Freshness::Fresh;
        };
        if seq > highest {
            return Freshness::Fresh;
        }
        match highest - seq {
            // The newest frame itself, arriving again.
            0 => Freshness::AlreadySeen,
            // Inside the window: the bitmap knows.
            d if d <= REPLAY_WINDOW => {
                if self.seen_below & (1u64 << (d - 1)) == 0 {
                    Freshness::Fresh
                } else {
                    Freshness::AlreadySeen
                }
            }
            // Off the back. Refused rather than admitted: the window is the only thing that remembers, so
            // admitting what it has forgotten would be a replay hole exactly as wide as an attacker cares to
            // make it by waiting.
            _ => Freshness::PastWindow,
        }
    }

    /// Record `seq` as accepted, sliding the window forward if it is the newest.
    fn record_seen(&mut self, seq: u64) {
        match self.highest_seen {
            Some(highest) if seq <= highest => {
                let d = highest - seq;
                if d <= REPLAY_WINDOW {
                    self.seen_below |= 1u64 << (d - 1);
                }
            }
            Some(highest) => {
                // Slide: everything previously in the window moves down by the advance, and the old highest
                // becomes a set bit. A jump past the window width clears it, which is correct — nothing that
                // old is acceptable any more.
                let advance = seq - highest;
                self.seen_below = if advance >= REPLAY_WINDOW {
                    0
                } else {
                    (self.seen_below << advance) | (1u64 << (advance - 1))
                };
                self.highest_seen = Some(seq);
            }
            None => self.highest_seen = Some(seq),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const CALL_SECRET: [u8; 32] = [0x33; 32];

    /// **A captured frame must not re-open** (audit AT-H3), while genuine reordering and loss still must.
    ///
    /// AEAD proves a frame was authentic *once*. Only a replay window proves it has not been seen before, and
    /// without one any recording of a call replays into it for as long as the epoch lasts — which is why SRTP
    /// mandates a window and why `open_frame` used to take `&self`, a signature that states at the type level
    /// that no such check happens.
    ///
    /// Asserted on all four behaviours together, because a window that only satisfies the first is a
    /// liveness regression dressed as a fix: replays refused, out-of-order accepted, loss survived, and a
    /// frame past the window refused *and counted* rather than silently dropped.
    #[test]
    fn a_captured_frame_cannot_be_replayed_but_reordering_still_works() {
        let (mut caller, mut callee) = pair();
        let frames: Vec<Vec<u8>> =
            (0..8).map(|i| caller.seal_frame(MediaKind::Audio, &[i as u8]).expect("a bounded plaintext always seals")).collect();

        // Out of order, with a gap: 3, 1, 0, 5 — all fresh, all open.
        for i in [3usize, 1, 0, 5] {
            assert!(callee.open_frame(&frames[i]).is_some(), "frame {i} is fresh and must open");
        }
        // Every one of them replayed is refused, including the newest (the bitmap's zero-distance case) and
        // one that arrived out of order (the bitmap's interior).
        for i in [5usize, 3, 1, 0] {
            assert!(callee.open_frame(&frames[i]).is_none(), "frame {i} is a replay and must be refused");
        }
        // Loss is survived: the frames skipped above still open when they turn up.
        for i in [2usize, 4, 6, 7] {
            assert!(callee.open_frame(&frames[i]).is_some(), "frame {i} was never seen and must open");
        }
        assert_eq!(callee.reordered_past_window(), 0, "nothing here was further back than the window");

        // A frame further behind than the window remembers is refused — and COUNTED, because that is the
        // window being too narrow for the path, not the network losing a packet, and the two ask for
        // different responses.
        let (mut far, mut rx) = pair();
        let ancient = far.seal_frame(MediaKind::Audio, b"first").expect("a bounded plaintext always seals");
        for _ in 0..(REPLAY_WINDOW + 8) {
            let f = far.seal_frame(MediaKind::Audio, b"filler").expect("a bounded plaintext always seals");
            assert!(rx.open_frame(&f).is_some(), "the live stream keeps opening");
        }
        assert!(rx.open_frame(&ancient).is_none(), "a frame off the back of the window is refused");
        assert_eq!(rx.reordered_past_window(), 1, "and is counted as the window being narrow, not as loss");

        // A rekey resets the window, or the new epoch's frame 0 would look like an ancient replay.
        let (mut a, mut b) = pair();
        let _ = b.open_frame(&a.seal_frame(MediaKind::Audio, b"pre").expect("a bounded plaintext always seals"));
        a.rekey();
        b.rekey();
        assert!(b.open_frame(&a.seal_frame(MediaKind::Audio, b"post").expect("a bounded plaintext always seals")).is_some(), "epoch 1 starts clean");
    }


    /// A matched caller/callee media pair over the same call secret.
    fn pair() -> (MediaSession, MediaSession) {
        (MediaSession::new(&CALL_SECRET, MediaRole::Caller), MediaSession::new(&CALL_SECRET, MediaRole::Callee))
    }

    /// **Every public sealer reports its failure** — a compile-time pin, and only that (#338).
    ///
    /// Coercing each to a function pointer makes the return type part of the crate's build: putting
    /// `-> Vec<u8>` back on any of the three stops compilation here. It exercises no failure path and is not
    /// evidence that one works — `chain::tests::a_refused_seal_does_not_burn_a_message_key` is.
    #[test]
    fn the_three_public_sealers_all_return_option() {
        let _: fn(&mut crate::session::Session, &[u8]) -> Option<Vec<u8>> = crate::session::Session::seal;
        let _: fn(&mut crate::group::GroupSession, &[u8]) -> Option<Vec<u8>> = crate::group::GroupSession::send;
        let _: fn(&mut MediaSession, MediaKind, &[u8]) -> Option<Vec<u8>> = MediaSession::seal_frame;
    }

    #[test]
    fn frames_seal_and_open_across_directions_and_are_loss_tolerant() {
        let (mut caller, mut callee) = pair();
        let f0 = caller.seal_frame(MediaKind::Audio, b"audio0").expect("a bounded plaintext always seals");
        let f1 = caller.seal_frame(MediaKind::Video, b"video1").expect("a bounded plaintext always seals");
        let f2 = caller.seal_frame(MediaKind::Audio, b"audio2").expect("a bounded plaintext always seals");
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
        let c0 = caller.seal_frame(MediaKind::Audio, b"same").expect("a bounded plaintext always seals");
        let d0 = callee.seal_frame(MediaKind::Audio, b"same").expect("a bounded plaintext always seals");
        assert_ne!(c0, d0, "the same plaintext at seq 0 seals differently in each direction");
        // The callee opens the caller's frame (cross-direction), and cannot open its own (wrong key).
        assert_eq!(callee.open_frame(&c0).map(|(_, _, p)| p), Some(b"same".to_vec()));
        assert!(callee.open_frame(&d0).is_none(), "a party cannot open its own send frame (distinct directions)");
    }

    #[test]
    fn a_rekey_gives_forward_secrecy_across_epochs() {
        let (mut caller, mut callee) = pair();
        let old = caller.seal_frame(MediaKind::Audio, b"epoch0").expect("a bounded plaintext always seals");
        assert_eq!(callee.open_frame(&old).map(|(_, _, p)| p), Some(b"epoch0".to_vec()));
        // Both rekey in lock-step.
        caller.rekey();
        callee.rekey();
        assert_eq!(caller.epoch(), 1);
        let new = caller.seal_frame(MediaKind::Audio, b"epoch1").expect("a bounded plaintext always seals");
        assert_eq!(callee.open_frame(&new).map(|(_, _, p)| p), Some(b"epoch1".to_vec()));
        // A stale epoch-0 frame no longer opens (the old key is gone → forward secrecy).
        assert!(callee.open_frame(&old).is_none(), "a pre-rekey frame is dropped after the rekey");
    }

    #[test]
    fn a_wrong_call_secret_or_tamper_cannot_open() {
        let mut caller = MediaSession::new(&CALL_SECRET, MediaRole::Caller);
        let mut eve = MediaSession::new(&[0x99; 32], MediaRole::Callee);
        let frame = caller.seal_frame(MediaKind::Video, b"secret call").expect("a bounded plaintext always seals");
        assert!(eve.open_frame(&frame).is_none(), "the wrong call secret cannot open a frame");
        let mut callee = MediaSession::new(&CALL_SECRET, MediaRole::Callee);
        let mut bad = frame.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(callee.open_frame(&bad).is_none(), "a tampered frame is refused");
    }
}
