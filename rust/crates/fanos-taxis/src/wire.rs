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
use crate::tx::SealedTx;

/// App-overlay body kind: a consensus message (validator ↔ validator).
const KIND_CONSENSUS: u8 = 0x00;
/// App-overlay body kind: a client-submitted sealed transaction (client → validator, then gossiped).
const KIND_TX: u8 = 0x01;

/// A decoded TAXIS App-overlay message: either a **consensus** message between validators, or a submitted
/// **transaction** (a client sends it to a validator, which gossips it so every mempool holds it). A 1-byte
/// kind prefix on the App body keeps the two unambiguous while sharing the one `App` frame code — so TAXIS
/// still claims no new top-level frame code (audit A1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TaxisApp {
    /// A consensus message (Propose / Vote / Reveal / ExecVote / Sync …).
    Consensus(ConsensusMsg),
    /// A sealed transaction submitted to the mempool.
    Tx(SealedTx),
}

/// Wrap a consensus message in a canonical App-overlay frame (`type=App ‖ len ‖ KIND_CONSENSUS ‖ body`).
#[must_use]
pub fn to_frame(msg: &ConsensusMsg) -> Vec<u8> {
    app_frame(KIND_CONSENSUS, &msg.to_bytes())
}

/// Wrap a sealed transaction in a canonical App-overlay frame (`type=App ‖ len ‖ KIND_TX ‖ tx`) — the wire
/// form a client sends to submit a transaction, and a validator gossips to seed every mempool.
#[must_use]
pub fn tx_to_frame(tx: &SealedTx) -> Vec<u8> {
    app_frame(KIND_TX, &tx.to_bytes())
}

/// Encode `kind ‖ payload` as the body of an `App` frame.
fn app_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + payload.len());
    body.push(kind);
    body.extend_from_slice(payload);
    let mut out = Vec::new();
    encode_frame(FrameType::App.code(), &body, &mut out);
    out
}

/// Parse a TAXIS App-overlay **body** (already unwrapped from the `App` frame — e.g. a `Notification::App`
/// body) into its [`TaxisApp`] message, or `None` if the kind is unknown or the payload is malformed.
#[must_use]
pub fn parse_app_body(body: &[u8]) -> Option<TaxisApp> {
    let (kind, payload) = body.split_first()?;
    match *kind {
        KIND_CONSENSUS => ConsensusMsg::from_bytes(payload).map(TaxisApp::Consensus),
        KIND_TX => SealedTx::from_bytes(payload).map(TaxisApp::Tx),
        _ => None,
    }
}

/// Decode a TAXIS message from a full App-overlay **frame** (`type=App ‖ len ‖ body`), or `None` if the bytes
/// are not a well-formed `App` frame carrying a valid TAXIS body.
#[must_use]
pub fn from_frame(bytes: &[u8]) -> Option<TaxisApp> {
    let (frame, _consumed) = decode_frame(bytes).ok()?;
    if frame.frame_type() != Some(FrameType::App) {
        return None;
    }
    parse_app_body(frame.body)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use fanos_pqcrypto::kem::{HybridKemPublic, HybridKemSecret};
    use fanos_pqcrypto::{HybridSigSecret, SeedRng};
    use fanos_primitives::Epoch;

    use super::*;
    use crate::block::{Block, GENESIS_PARENT};
    use crate::consensus::RevealMsg;
    use crate::tx::Transaction;
    use crate::vote::{Phase, SignedVote, Vote};

    #[test]
    fn every_message_round_trips_through_an_app_frame() {
        // Propose (an empty block is enough to exercise the header + empty payload path).
        let block = Block::assemble(GENESIS_PARENT, 0, Epoch::new(1), 3, Vec::new());
        let propose = ConsensusMsg::Propose(block);
        assert_eq!(from_frame(&to_frame(&propose)), Some(TaxisApp::Consensus(propose)));

        // Vote.
        let mut rng = SeedRng::from_seed(b"wire-vote");
        let (signer, _) = HybridSigSecret::generate(&mut rng);
        let vote = Vote { height: 7, round: 1, block_hash: [9u8; 32], phase: Phase::Commit, voter: 4 };
        let msg = ConsensusMsg::Vote(SignedVote::sign(vote, &signer));
        assert_eq!(from_frame(&to_frame(&msg)), Some(TaxisApp::Consensus(msg)));

        // Reveal (authenticated — signed by the revealing member's key).
        let reveal =
            ConsensusMsg::Reveal(RevealMsg::signed([5u8; 32], 2, vec![7u8; 33], &signer));
        assert_eq!(from_frame(&to_frame(&reveal)), Some(TaxisApp::Consensus(reveal)));
    }

    #[test]
    fn a_sealed_transaction_round_trips_through_a_tx_app_frame() {
        // A submitted transaction rides the same App code under KIND_TX, distinct from a consensus message.
        let kps: Vec<(HybridKemSecret, HybridKemPublic)> =
            (0..3u8).map(|i| HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xAB, i]))).collect();
        let pubs: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        let tx = SealedTx::seal(&Transaction::new(b"pay-alice".to_vec()), Epoch::new(2), 0, &pubs, 2, b"seed")
            .unwrap();
        assert_eq!(from_frame(&tx_to_frame(&tx)), Some(TaxisApp::Tx(tx)));
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
