//! TAXIS on the FANOS wire — the App-overlay framing (spec §7.2, `docs/design-taxis.md` §1).
//!
//! TAXIS is an application overlay, so its [`ConsensusMsg`]s ride inside the canonical
//! [`FrameType::App`](fanos_wire::FrameType::App) (`0x70`) frame — the length-skippable outer type the wire
//! protocol reserves for application overlays (the Kernel/Protocol split) — rather than claiming new
//! top-level frame codes. A node that does not run TAXIS skips the frame by its length; a node that does
//! hands the body to [`from_frame`]. This keeps `fanos-wire` the single frame-code authority (audit A1) with
//! no core change, while giving TAXIS a fully canonical, language-agnostic message encoding.

use alloc::vec::Vec;

use fanos_wire::{FrameType, decode_frame, encode_frame};

use crate::consensus::ConsensusMsg;

/// Wrap a consensus message in a canonical App-overlay frame (`type=App ‖ len ‖ body`), ready for the wire.
#[must_use]
pub fn to_frame(msg: &ConsensusMsg) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(FrameType::App.code(), &msg.to_bytes(), &mut out);
    out
}

/// Decode a consensus message from an App-overlay frame, or `None` if the bytes are not a well-formed App
/// frame carrying a valid [`ConsensusMsg`].
#[must_use]
pub fn from_frame(bytes: &[u8]) -> Option<ConsensusMsg> {
    let (frame, _consumed) = decode_frame(bytes).ok()?;
    if frame.frame_type() != Some(FrameType::App) {
        return None;
    }
    ConsensusMsg::from_bytes(frame.body)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use fanos_pqcrypto::{HybridSigSecret, SeedRng};
    use fanos_primitives::Epoch;

    use super::*;
    use crate::block::{Block, GENESIS_PARENT};
    use crate::consensus::RevealMsg;
    use crate::vote::{Phase, SignedVote, Vote};

    #[test]
    fn every_message_round_trips_through_an_app_frame() {
        // Propose (an empty block is enough to exercise the header + empty payload path).
        let block = Block::assemble(GENESIS_PARENT, 0, Epoch::new(1), 3, Vec::new());
        let propose = ConsensusMsg::Propose(block);
        assert_eq!(from_frame(&to_frame(&propose)), Some(propose));

        // Vote.
        let mut rng = SeedRng::from_seed(b"wire-vote");
        let (signer, _) = HybridSigSecret::generate(&mut rng);
        let vote = Vote { height: 7, round: 1, block_hash: [9u8; 32], phase: Phase::Commit, voter: 4 };
        let msg = ConsensusMsg::Vote(SignedVote::sign(vote, &signer));
        assert_eq!(from_frame(&to_frame(&msg)), Some(msg));

        // Reveal.
        let reveal = ConsensusMsg::Reveal(RevealMsg { commit: [5u8; 32], member: 2, share: vec![7u8; 33] });
        assert_eq!(from_frame(&to_frame(&reveal)), Some(reveal));
    }

    #[test]
    fn a_non_app_frame_or_garbage_is_rejected() {
        // A frame of a different type is not a TAXIS message.
        let mut other = Vec::new();
        encode_frame(FrameType::Ping.code(), b"x", &mut other);
        assert_eq!(from_frame(&other), None);
        // Pure garbage is rejected, not panicked on.
        assert_eq!(from_frame(&[0xFF, 0xFF, 0xFF]), None);
    }
}
