//! **Call signaling** — how a voice/video call is set up over the secure content plane (`spec/platform.md`
//! §6.2). It is the SIP/SDP *offer–answer* re-derived on FANOS, with no server in the middle: the media key is
//! agreed inside the encrypted 1:1 [`crate::session`] (or a group session), then seeds the real-time
//! [`crate::media`] plane that rides the low-latency transport dial.
//!
//! A [`CallSignal`] is the plaintext of a [`crate::message::MessageKind::CallSignal`] message, so it inherits
//! that channel's end-to-end encryption and anonymity. The caller sends an **Invite** carrying a fresh media
//! secret (the call's epoch-0 key) and the offered media kinds; the callee answers **Accept** (or **Decline**),
//! and both seed an identical [`MediaSession`] from the secret — from then on, media frames flow directly on the
//! media plane. **Hangup** ends the call. Because the secret travels inside the already-encrypted session, the
//! media plane is bootstrapped without ever exposing its key to the network.

use alloc::vec::Vec;

use crate::media::{MediaRole, MediaSession};

/// The length of a call identifier.
pub const CALL_ID_LEN: usize = 16;

/// Offered-media bit flags (a call may carry any combination).
pub mod media_flags {
    /// The call offers audio.
    pub const AUDIO: u8 = 0b001;
    /// The call offers video.
    pub const VIDEO: u8 = 0b010;
    /// The call offers an application data stream (screen-share control, etc.).
    pub const DATA: u8 = 0b100;
}

/// A random per-call identifier, tying an invite to its accept/hangup.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CallId([u8; CALL_ID_LEN]);

impl CallId {
    /// A call id from 16 bytes (caller-supplied randomness — a CSPRNG in production).
    #[must_use]
    pub fn new(bytes: [u8; CALL_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CALL_ID_LEN] {
        &self.0
    }
}

/// A call-control message, carried as the content of a `CallSignal` message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CallSignal {
    /// Offer a call: the fresh media secret (the media session's epoch-0 key) and the offered media kinds.
    Invite {
        /// The call id.
        call: CallId,
        /// The media session's seed secret.
        media_secret: [u8; 32],
        /// The offered media, as [`media_flags`].
        media: u8,
    },
    /// Answer an invite affirmatively.
    Accept {
        /// The call id being accepted.
        call: CallId,
    },
    /// Answer an invite negatively.
    Decline {
        /// The call id being declined.
        call: CallId,
    },
    /// End a call.
    Hangup {
        /// The call id being ended.
        call: CallId,
    },
}

impl CallSignal {
    /// Start a call: from a fresh `call` id, a fresh `media_secret`, and the offered `media`, return the invite
    /// to send (sealed over the session) and the caller's local [`MediaSession`] seeded by the secret.
    #[must_use]
    pub fn invite(call: CallId, media_secret: [u8; 32], media: u8) -> (Self, MediaSession) {
        (Self::Invite { call, media_secret, media }, MediaSession::new(&media_secret, MediaRole::Caller))
    }

    /// Accept a received invite: return the accept to send and the callee's [`MediaSession`] — identical to the
    /// caller's, so media frames interoperate immediately. `None` if this is not an [`Invite`](Self::Invite).
    #[must_use]
    pub fn accept(&self) -> Option<(Self, MediaSession)> {
        match self {
            Self::Invite { call, media_secret, .. } => {
                Some((Self::Accept { call: *call }, MediaSession::new(media_secret, MediaRole::Callee)))
            }
            _ => None,
        }
    }

    /// The call this signal concerns.
    #[must_use]
    pub fn call(&self) -> CallId {
        match self {
            Self::Invite { call, .. } | Self::Accept { call } | Self::Decline { call } | Self::Hangup { call } => {
                *call
            }
        }
    }

    /// The wire tag.
    #[must_use]
    fn tag(&self) -> u8 {
        match self {
            Self::Invite { .. } => 0,
            Self::Accept { .. } => 1,
            Self::Decline { .. } => 2,
            Self::Hangup { .. } => 3,
        }
    }

    /// Canonical bytes: `tag(1) ‖ call(16)`, and for an invite `‖ media_secret(32) ‖ media(1)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + CALL_ID_LEN + 33);
        out.push(self.tag());
        out.extend_from_slice(self.call().as_bytes());
        if let Self::Invite { media_secret, media, .. } = self {
            out.extend_from_slice(media_secret);
            out.push(*media);
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed / truncated / over-long.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&tag, rest) = bytes.split_first()?;
        let call = CallId::new(rest.get(..CALL_ID_LEN)?.try_into().ok()?);
        let after = rest.get(CALL_ID_LEN..)?;
        match tag {
            0 => {
                let media_secret: [u8; 32] = after.get(..32)?.try_into().ok()?;
                let &media = after.get(32)?;
                if after.len() != 33 {
                    return None; // no trailing garbage
                }
                Some(Self::Invite { call, media_secret, media })
            }
            1..=3 if after.is_empty() => Some(match tag {
                1 => Self::Accept { call },
                2 => Self::Decline { call },
                _ => Self::Hangup { call },
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    use crate::media::MediaKind;

    const CALL: CallId = CallId([0x11; CALL_ID_LEN]);
    const SECRET: [u8; 32] = [0x77; 32];

    #[test]
    fn an_invite_and_accept_seed_matching_media_sessions() {
        // Caller offers audio+video.
        let (invite, mut caller_media) = CallSignal::invite(CALL, SECRET, media_flags::AUDIO | media_flags::VIDEO);
        // The invite travels sealed over the session; the callee decodes it and accepts.
        let received = CallSignal::from_bytes(&invite.to_bytes()).expect("decode");
        let (accept, callee_media) = received.accept().expect("accept an invite");
        assert_eq!(accept, CallSignal::Accept { call: CALL });
        // Both media sessions match: a frame sealed by the caller opens for the callee.
        let frame = caller_media.seal_frame(MediaKind::Audio, b"hello call");
        assert_eq!(
            callee_media.open_frame(&frame),
            Some((0, MediaKind::Audio, b"hello call".to_vec())),
            "the callee's media session interoperates with the caller's"
        );
    }

    #[test]
    fn only_an_invite_can_be_accepted() {
        assert!(CallSignal::Hangup { call: CALL }.accept().is_none());
        assert!(CallSignal::Accept { call: CALL }.accept().is_none());
    }

    #[test]
    fn signals_round_trip_and_reject_garbage() {
        for sig in [
            CallSignal::Invite { call: CALL, media_secret: SECRET, media: media_flags::AUDIO },
            CallSignal::Accept { call: CALL },
            CallSignal::Decline { call: CALL },
            CallSignal::Hangup { call: CALL },
        ] {
            let bytes = sig.to_bytes();
            assert_eq!(CallSignal::from_bytes(&bytes), Some(sig.clone()));
            assert_eq!(CallSignal::from_bytes(&bytes[..bytes.len() - 1]), None, "truncation rejected");
            assert_eq!(CallSignal::from_bytes(&[bytes.as_slice(), b"x"].concat()), None, "trailing garbage rejected");
        }
        assert_eq!(CallSignal::from_bytes(&[9u8, 0, 0]), None, "an unknown tag is rejected");
    }

    #[test]
    fn the_call_signal_wire_format_is_stable_a_known_answer() {
        // A fixed invite must encode to fixed bytes so every language's SDK agrees.
        let invite = CallSignal::Invite { call: CallId([0xAB; 16]), media_secret: [0xCD; 32], media: 0b011 };
        let bytes = invite.to_bytes();
        assert_eq!(bytes[0], 0, "tag Invite = 0");
        assert_eq!(&bytes[1..17], &[0xAB; 16], "call id");
        assert_eq!(&bytes[17..49], &[0xCD; 32], "media secret");
        assert_eq!(bytes[49], 0b011, "media flags = audio|video");
        assert_eq!(bytes.len(), 50);
    }
}
