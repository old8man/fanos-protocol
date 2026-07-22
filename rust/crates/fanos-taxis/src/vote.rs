//! Signed votes and the quorum certificate (spec §10.1, `docs/design-taxis.md` §4).
//!
//! Consensus advances by collecting **votes**: each validator hybrid-PQ-signs `(phase, height, round,
//! block_hash)` (Ed25519 + ML-DSA-65, [`fanos_pqcrypto`]), and a set of `Q` distinct valid signatures over
//! the same tuple is a [`Certificate`] — a prepared certificate (`PREPARE` phase) locks a block, a commit
//! certificate (`COMMIT` phase) finalizes it. The signatures are what make the Byzantine model sound: a
//! validator cannot forge another's vote, so a forged or under-quorum certificate is rejected by
//! [`Certificate::verify`].
//!
//! The reference certificate carries the `Q` full signatures; a production deployment would compress them
//! with an aggregate/threshold signature — a noted optimization, orthogonal to safety.

use alloc::vec::Vec;

use fanos_pqcrypto::sig::HYBRID_SIG_LEN;
use fanos_pqcrypto::{HybridSigSecret, HybridSignature, HybridVerifier};

/// The two consensus voting phases.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// First round of votes; a `Q`-quorum forms a *prepared certificate* that locks the block.
    Prepare,
    /// Second round; a `Q`-quorum forms a *commit certificate* that finalizes the block.
    Commit,
}

impl Phase {
    /// The 1-byte code used in the canonical signing/wire encoding.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Prepare => 0,
            Self::Commit => 1,
        }
    }

    /// The phase for a code byte, or `None` if unknown (non-canonical).
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Prepare),
            1 => Some(Self::Commit),
            _ => None,
        }
    }
}

/// The fixed canonical byte width of a vote's signable content: `height(8) ‖ round(4) ‖ block_hash(32) ‖
/// phase(1) ‖ voter(1)`.
pub const VOTE_LEN: usize = 8 + 4 + 32 + 1 + 1;

/// The signable content of one vote: which validator votes, in which phase, for which block at which
/// `(height, round)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Vote {
    /// The block height being decided.
    pub height: u64,
    /// The consensus round within the height (advanced on proposer timeout).
    pub round: u32,
    /// The hash of the block being voted for.
    pub block_hash: [u8; 32],
    /// Which voting phase this vote belongs to.
    pub phase: Phase,
    /// The voting validator's index `0..n`.
    pub voter: u8,
}

impl Vote {
    /// The canonical bytes a validator signs (and that its signature is verified over). Fixed [`VOTE_LEN`].
    #[must_use]
    pub fn to_bytes(&self) -> [u8; VOTE_LEN] {
        let mut b = [0u8; VOTE_LEN];
        b[..8].copy_from_slice(&self.height.to_be_bytes());
        b[8..12].copy_from_slice(&self.round.to_be_bytes());
        b[12..44].copy_from_slice(&self.block_hash);
        b[44] = self.phase.code();
        b[45] = self.voter;
        b
    }

    /// Decode a vote from its canonical [`to_bytes`](Self::to_bytes), or `None` if malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; VOTE_LEN] = bytes.get(..VOTE_LEN)?.try_into().ok()?;
        Some(Self {
            height: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            round: u32::from_be_bytes(bytes[8..12].try_into().ok()?),
            block_hash: bytes[12..44].try_into().ok()?,
            phase: Phase::from_code(bytes[44])?,
            voter: bytes[45],
        })
    }
}

/// A vote plus its author's hybrid-PQ signature over [`Vote::to_bytes`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedVote {
    /// The vote content.
    pub vote: Vote,
    /// The `Ed25519(64) ‖ ML-DSA-65(3309)` signature bytes.
    sig: Vec<u8>,
}

impl SignedVote {
    /// Sign a vote with the validator's hybrid signing secret.
    #[must_use]
    pub fn sign(vote: Vote, signer: &HybridSigSecret) -> Self {
        let sig = signer.sign(&vote.to_bytes()).to_bytes();
        Self { vote, sig }
    }

    /// Whether the signature verifies under `verifier` (which must be the voter's verifying key). A malformed
    /// signature, or one under the wrong key, is `false`.
    #[must_use]
    pub fn verify(&self, verifier: &HybridVerifier) -> bool {
        let Some(sig) = HybridSignature::from_bytes(&self.sig) else {
            return false;
        };
        verifier.verify(&self.vote.to_bytes(), &sig)
    }

    /// Canonical bytes: `vote(46) ‖ signature(HYBRID_SIG_LEN)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VOTE_LEN + HYBRID_SIG_LEN);
        out.extend_from_slice(&self.vote.to_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode a signed vote from [`to_bytes`](Self::to_bytes), or `None` if the wrong length or malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != VOTE_LEN + HYBRID_SIG_LEN {
            return None;
        }
        let vote = Vote::from_bytes(bytes.get(..VOTE_LEN)?)?;
        let sig = bytes.get(VOTE_LEN..)?.to_vec();
        Some(Self { vote, sig })
    }
}

/// A quorum certificate: `Q` distinct validators' signatures agreeing on one `(phase, height, round,
/// block_hash)`. A `PREPARE` certificate locks a block; a `COMMIT` certificate finalizes it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Certificate {
    /// The phase all votes belong to.
    pub phase: Phase,
    /// The height being decided.
    pub height: u64,
    /// The round within the height.
    pub round: u32,
    /// The block hash the quorum agrees on.
    pub block_hash: [u8; 32],
    /// The `Q` (or more) distinct signed votes.
    pub votes: Vec<SignedVote>,
}

impl Certificate {
    /// Whether this is a valid quorum certificate: every vote agrees on this certificate's `(phase, height,
    /// round, block_hash)`, the voters are **distinct** and each in range, every signature verifies under
    /// its voter's key, and at least `quorum` votes are present. `verifiers[i]` is validator `i`'s key.
    ///
    /// This is the safety linchpin: because two `Q`-quorums share an honest validator
    /// ([`crate::CellParams::is_safe`]), and an honest validator signs at most one block per `(height,
    /// round, phase)`, two conflicting certificates for the same height can never both verify.
    #[must_use]
    pub fn verify(&self, quorum: usize, verifiers: &[HybridVerifier]) -> bool {
        let mut seen = alloc::vec![false; verifiers.len()];
        let mut count = 0usize;
        for sv in &self.votes {
            let v = &sv.vote;
            if v.phase != self.phase
                || v.height != self.height
                || v.round != self.round
                || v.block_hash != self.block_hash
            {
                return false; // a vote that does not match this certificate's claim
            }
            let idx = usize::from(v.voter);
            let Some(verifier) = verifiers.get(idx) else {
                return false; // voter index out of range
            };
            match seen.get_mut(idx) {
                Some(slot) if !*slot => *slot = true,
                _ => return false, // duplicate voter (double-count) or out of range
            }
            if !sv.verify(verifier) {
                return false; // bad / forged signature
            }
            count += 1;
        }
        count >= quorum
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::SeedRng;

    /// `n` validators' hybrid signing keypairs (secret, verifier) from a deterministic seed.
    fn validators(n: usize) -> (Vec<HybridSigSecret>, Vec<HybridVerifier>) {
        let mut secrets = Vec::new();
        let mut verifiers = Vec::new();
        for i in 0..n {
            let mut rng = SeedRng::from_seed(&[0xB0, i as u8]);
            let (s, v) = HybridSigSecret::generate(&mut rng);
            secrets.push(s);
            verifiers.push(v);
        }
        (secrets, verifiers)
    }

    fn cert_of(hash: [u8; 32], phase: Phase, voters: &[usize], secrets: &[HybridSigSecret]) -> Certificate {
        let votes = voters.iter().map(|&i| {
            let vote = Vote { height: 1, round: 0, block_hash: hash, phase, voter: i as u8 };
            SignedVote::sign(vote, &secrets[i])
        }).collect();
        Certificate { phase, height: 1, round: 0, block_hash: hash, votes }
    }

    #[test]
    fn a_quorum_of_honest_signatures_verifies() {
        let (secrets, verifiers) = validators(7);
        let cert = cert_of([1u8; 32], Phase::Commit, &[0, 1, 2, 3, 4], &secrets);
        assert!(cert.verify(5, &verifiers), "a 5-of-7 commit certificate verifies");
        // Below the Fano quorum (5) it is not a certificate.
        assert!(!cert.verify(6, &verifiers), "4... fewer than quorum is rejected at the higher bar");
    }

    #[test]
    fn a_signed_vote_round_trips_and_a_tampered_vote_fails() {
        let (secrets, verifiers) = validators(7);
        let vote = Vote { height: 9, round: 2, block_hash: [7u8; 32], phase: Phase::Prepare, voter: 3 };
        let sv = SignedVote::sign(vote, &secrets[3]);
        assert!(sv.verify(&verifiers[3]));
        // Round-trips through bytes.
        assert_eq!(SignedVote::from_bytes(&sv.to_bytes()).unwrap(), sv);
        // A different validator's key does not verify it.
        assert!(!sv.verify(&verifiers[4]));
        // A tampered vote body no longer matches the signature.
        let mut forged = sv.clone();
        forged.vote.block_hash[0] ^= 1;
        assert!(!forged.verify(&verifiers[3]));
    }

    #[test]
    fn a_duplicate_voter_cannot_pad_a_certificate() {
        // Byzantine safety: a certificate that lists the same voter 5 times must NOT count as a 5-quorum.
        let (secrets, verifiers) = validators(7);
        let cert = cert_of([2u8; 32], Phase::Commit, &[1, 1, 1, 1, 1], &secrets);
        assert!(!cert.verify(5, &verifiers), "duplicate voters are rejected (no double-counting)");
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        // A vote purportedly from validator 6 but signed by validator 0's key must fail.
        let (secrets, verifiers) = validators(7);
        let vote = Vote { height: 1, round: 0, block_hash: [3u8; 32], phase: Phase::Commit, voter: 6 };
        let forged = SignedVote::sign(vote, &secrets[0]); // wrong signer
        let cert = Certificate {
            phase: Phase::Commit, height: 1, round: 0, block_hash: [3u8; 32], votes: vec![forged],
        };
        assert!(!cert.verify(1, &verifiers), "a signature under the wrong key is rejected");
    }

    #[test]
    fn votes_for_a_different_block_do_not_form_this_certificate() {
        let (secrets, verifiers) = validators(7);
        // Certificate claims block A, but a vote is for block B.
        let mut cert = cert_of([0xAAu8; 32], Phase::Commit, &[0, 1, 2, 3, 4], &secrets);
        let stray = Vote { height: 1, round: 0, block_hash: [0xBBu8; 32], phase: Phase::Commit, voter: 5 };
        cert.votes.push(SignedVote::sign(stray, &secrets[5]));
        assert!(!cert.verify(5, &verifiers), "a vote for a different block invalidates the certificate");
    }
}
