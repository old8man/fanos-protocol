//! **Execution checkpoints** — making executed-state divergence a *consensus-detectable* fault, and giving
//! cross-cell proofs a canonical state root to verify against (`docs/design-taxis.md` §5.1, audit follow-up).
//!
//! TAXIS deliberately separates *ordering* from *execution*: a block's order is final the instant it gathers a
//! commit certificate, but its transactions are decrypted and applied only after the anti-MEV reveals arrive
//! (`crate::consensus`). Consensus therefore commits to the *order*, not the executed *state* — so, as an
//! independent review noted, a divergence in executed state (from a bug, or a residual reveal inconsistency)
//! would be a **silent fork**: the header chains agree while balances differ, and nothing catches it.
//!
//! This module closes that. When a validator finishes executing a height `h` (its block drained of reveals and
//! applied), it emits a hybrid-PQ-signed [`ExecVote`] `(h, state_root_h)`. Because honest validators execute the
//! same agreed order to the same deterministic state, their roots agree; a `Q`-quorum of matching votes is an
//! [`ExecCertificate`] — a portable proof of the cell's canonical executed state at `h`. A validator whose root
//! differs is in a minority its vote never joins, so the divergence is **visible** (and slashable via
//! [`ExecCertificate::conflicting`]) rather than silent. The certificate is exactly what a *destination* cell
//! checks when it verifies a *source* cell's cross-shard transaction (`crate::crosscell`).

use alloc::vec::Vec;

use fanos_pqcrypto::sig::HYBRID_SIG_LEN;
use fanos_pqcrypto::{HybridSigSecret, HybridSignature, HybridVerifier};

/// A validator's signed attestation that executing **the chain ending at `head`** through `height` yields
/// `state_root`.
///
/// `head` is signed, and that is load-bearing rather than incidental (finding T-H6, 2026-07-30). A state-sync response
/// carries the certified state *and* the block hash the receiver installs as its chain tip; while the attestation covered
/// only `(height, state_root)`, that tip was unauthenticated, so a Byzantine cell member could pair a **genuine**
/// certificate with an arbitrary hash. The victim would adopt a tip nobody holds: its own proposals carry a `parent` no
/// peer recognizes and every proposal it receives fails the linkage check, isolating an honest validator for the cost of
/// one message and no forged signature. In a Fano cell that takes effective participation to `4 < Q = 5` alongside the
/// two tolerated faults.
///
/// Binding the tip into the signature — rather than validating a wire field at the receiver — is what makes the
/// message's `head` field unnecessary and lets it be deleted. A check can be forgotten; a signed field cannot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExecVote {
    /// The executed height this attests to.
    pub height: u64,
    /// The state root after executing every finalized block up to and including `height`.
    pub state_root: [u8; 32],
    /// The hash of the block finalized at `height` — the chain tip this state belongs to.
    pub head: [u8; 32],
    /// The attesting validator's index.
    pub voter: u8,
    /// The hybrid-PQ signature over [`signable`](ExecVote::signable).
    sig: Vec<u8>,
}

impl ExecVote {
    /// The signed content: `height(8) ‖ state_root(32) ‖ head(32) ‖ voter(1)`.
    #[must_use]
    fn signable(height: u64, state_root: &[u8; 32], head: &[u8; 32], voter: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 32 + 1);
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(state_root);
        out.extend_from_slice(head);
        out.push(voter);
        out
    }

    /// Sign an execution attestation with the validator's hybrid signing key.
    #[must_use]
    pub fn sign(height: u64, state_root: [u8; 32], head: [u8; 32], voter: u8, signer: &HybridSigSecret) -> Self {
        let sig = signer.sign(&Self::signable(height, &state_root, &head, voter)).to_bytes();
        Self { height, state_root, head, voter, sig }
    }

    /// Whether the signature verifies under `verifier` (which must be `voter`'s key).
    #[must_use]
    pub fn verify(&self, verifier: &HybridVerifier) -> bool {
        let Some(sig) = HybridSignature::from_bytes(&self.sig) else {
            return false;
        };
        verifier.verify(&Self::signable(self.height, &self.state_root, &self.head, self.voter), &sig)
    }

    /// The fixed byte length of an execution attestation's [`to_bytes`](Self::to_bytes).
    pub const LEN: usize = 8 + 32 + 32 + 1 + HYBRID_SIG_LEN;

    /// Canonical bytes: `height(8) ‖ state_root(32) ‖ head(32) ‖ voter(1) ‖ signature`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.head);
        out.push(self.voter);
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if the wrong length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::LEN {
            return None;
        }
        let height = u64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
        let state_root = bytes.get(8..40)?.try_into().ok()?;
        let head = bytes.get(40..72)?.try_into().ok()?;
        let voter = *bytes.get(72)?;
        let sig = bytes.get(73..)?.to_vec();
        Some(Self { height, state_root, head, voter, sig })
    }
}

/// A `Q`-quorum of validators attesting the **same** `(height, state_root, head)` — a portable proof of a cell's
/// canonical executed state *and the chain tip it belongs to*, verifiable by anyone holding the cell's validator keys.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExecCertificate {
    /// The executed height.
    pub height: u64,
    /// The canonical state root the quorum agrees on.
    pub state_root: [u8; 32],
    /// The block hash finalized at `height` — quorum-attested, so a state-sync receiver installs a tip the cell agreed
    /// on rather than one its peer chose (T-H6).
    pub head: [u8; 32],
    /// The `Q` (or more) distinct attesting votes.
    pub votes: Vec<ExecVote>,
}

impl ExecCertificate {
    /// Whether this is a valid execution certificate: every vote agrees on this `(height, state_root, head)`, the
    /// voters are **distinct** and each in range, every signature verifies, and there are at least `quorum`.
    /// Because two `Q`-quorums share an honest validator and an honest validator attests one root per height,
    /// two certificates for the same height can never carry different roots — so a verified certificate names
    /// the *unique* canonical executed state.
    ///
    /// `head` is checked here and signed in every vote, so tampering with it invalidates the certificate rather than
    /// merely being caught by a downstream comparison someone could omit.
    #[must_use]
    pub fn verify(&self, quorum: usize, verifiers: &[HybridVerifier]) -> bool {
        self.verify_by(quorum, verifiers.len(), |i| verifiers.get(i))
    }

    /// [`verify`](Self::verify) over a committee that may have **holes** — `seats` is how many validator
    /// indices exist, and `key(i)` is seat `i`'s verifier when it is known.
    ///
    /// **Why a hole is not a rejection.** `Q` of `n` means a certificate is sound as soon as `Q` signatures
    /// check out; the other `n − Q` seats need not even have voted. A parent that has learned five of seven
    /// keys can therefore verify a five-vote certificate completely, and refusing it because two keys are
    /// missing would make the quorum's own tolerance unusable — which is what a dense `Vec<HybridVerifier>`
    /// forces, since it cannot express "seat 3 unknown" at all.
    ///
    /// So an in-range vote with no key **contributes nothing** rather than invalidating the certificate: it
    /// is a vote this reader cannot check, and an unchecked vote is not evidence. It still claims its seat,
    /// so a duplicate voter is caught exactly as before, and padding a certificate with unverifiable votes
    /// therefore buys an attacker nothing.
    ///
    /// Out of range is still a **rejection**, and the two are deliberately not merged: a voter index that
    /// names no seat of this committee is a malformed certificate, while a seat whose key this reader has not
    /// learned is a fact about the reader.
    #[must_use]
    pub fn verify_by<'a>(
        &self,
        quorum: usize,
        seats: usize,
        key: impl Fn(usize) -> Option<&'a HybridVerifier>,
    ) -> bool {
        let mut seen = alloc::vec![false; seats];
        let mut count = 0usize;
        for v in &self.votes {
            if v.height != self.height || v.state_root != self.state_root || v.head != self.head {
                return false;
            }
            let Some(slot) = seen.get_mut(usize::from(v.voter)) else {
                return false; // names no seat of this committee
            };
            if *slot {
                return false; // duplicate voter
            }
            *slot = true; // claimed even when unverifiable, so duplicates stay caught
            let Some(verifier) = key(usize::from(v.voter)) else {
                continue; // a seat whose key this reader has not learned
            };
            if !v.verify(verifier) {
                return false;
            }
            count += 1;
        }
        count >= quorum
    }

    /// Detect an execution **divergence**: given this certificate's canonical root and another validator's
    /// `vote` for the *same* height, returns `Some(voter)` if that vote attests a *different* root under a valid
    /// signature — proof that `voter` executed to a wrong state (a slashable fault). `None` if it agrees, is for
    /// another height, or does not verify.
    #[must_use]
    pub fn conflicting(&self, vote: &ExecVote, verifiers: &[HybridVerifier]) -> Option<u8> {
        if vote.height != self.height || vote.state_root == self.state_root {
            return None;
        }
        let verifier = verifiers.get(usize::from(vote.voter))?;
        vote.verify(verifier).then_some(vote.voter)
    }

    /// Canonical bytes: `height(8) ‖ state_root(32) ‖ head(32) ‖ vote_count(2) ‖ votes*` (each vote fixed-width
    /// [`ExecVote::LEN`]) — the portable form a cell publishes so a parent (or a cross-cell peer) can verify its
    /// finality over the overlay.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 32 + 2 + self.votes.len() * ExecVote::LEN);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.head);
        // **Safe, and the bound is the voter index rather than anything here** (#110). `verify` refuses a
        // repeated `voter` and refuses one outside the verifier list, so a certificate anyone accepts holds
        // at most one vote per validator — and `ExecVote::voter` is itself a `u8`, so that is at most 256,
        // an order below this field. Written down because an unexamined narrowing and an examined-safe one
        // look identical, and the neighbouring `CellEscalate` index with the same shape was NOT safe.
        out.extend_from_slice(&(self.votes.len() as u16).to_be_bytes());
        for v in &self.votes {
            out.extend_from_slice(&v.to_bytes());
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed. The recovered certificate still needs
    /// [`verify`](Self::verify) against the cell's committee keys before it is trusted.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let height = u64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
        let state_root = bytes.get(8..40)?.try_into().ok()?;
        let head = bytes.get(40..72)?.try_into().ok()?;
        let count = usize::from(u16::from_be_bytes(bytes.get(72..74)?.try_into().ok()?));
        let body = bytes.get(74..)?;
        if body.len() != count * ExecVote::LEN {
            return None;
        }
        let mut votes = Vec::with_capacity(count);
        for i in 0..count {
            let start = i * ExecVote::LEN;
            votes.push(ExecVote::from_bytes(body.get(start..start + ExecVote::LEN)?)?);
        }
        Some(Self { height, state_root, head, votes })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::{HybridSigSecret, SeedRng};

    /// The chain tip every fixture attests, so a tampered one is visibly different.
    const HEAD: [u8; 32] = [0xEE; 32];

    fn keys(n: usize) -> Vec<(HybridSigSecret, HybridVerifier)> {
        (0..n)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[0x5A, i as u8]);
                HybridSigSecret::generate(&mut rng)
            })
            .collect()
    }

    #[test]
    fn a_quorum_of_matching_attestations_certifies_the_state() {
        let ks = keys(7);
        let verifiers: Vec<HybridVerifier> = ks.iter().map(|(_, v)| v.clone()).collect();
        let root = [0x11; 32];
        let votes: Vec<ExecVote> = (0..5).map(|i| ExecVote::sign(9, root, HEAD, i as u8, &ks[i].0)).collect();
        let cert = ExecCertificate { height: 9, state_root: root, head: HEAD, votes };
        assert!(cert.verify(5, &verifiers), "5 matching signed attestations certify height 9's root");
        // Fewer than the quorum does not certify.
        let short = ExecCertificate { height: 9, state_root: root, head: HEAD, votes: cert.votes[..4].to_vec() };
        assert!(!short.verify(5, &verifiers));
    }

    #[test]
    fn a_certificate_whose_head_was_swapped_after_signing_is_rejected() {
        // Finding T-H6. The chain tip used to travel beside the certificate in `ConsensusMsg::SyncResp`, unsigned, and
        // `on_sync_resp` installed it as the receiver's head with no linkage check. A Byzantine cell member could
        // therefore take a GENUINE certificate — they are served and broadcast freely — pair it with any hash, and leave
        // an honest validator on a tip nobody holds: its proposals name a `parent` no peer recognizes and every proposal
        // it receives fails the linkage check. No forged signature, one message, and in a Fano cell it takes effective
        // participation to 4 < Q = 5 alongside the two tolerated faults.
        //
        // The head is now signed by every vote, so this is what "swapping it" costs. Note the vote signatures are left
        // untouched: only the certificate's own field moves, which is exactly the attack the old shape permitted.
        let ks = keys(7);
        let verifiers: Vec<HybridVerifier> = ks.iter().map(|(_, v)| v.clone()).collect();
        let root = [0x33; 32];
        let votes: Vec<ExecVote> = (0..5).map(|i| ExecVote::sign(4, root, HEAD, i as u8, &ks[i].0)).collect();
        let honest = ExecCertificate { head: HEAD, height: 4, state_root: root, votes: votes.clone() };
        assert!(honest.verify(5, &verifiers), "the untampered certificate is valid");

        let swapped = ExecCertificate { head: [0xAB; 32], height: 4, state_root: root, votes };
        assert!(!swapped.verify(5, &verifiers), "a head the quorum never attested invalidates the certificate");
    }

    #[test]
    fn two_validators_disagreeing_on_the_tip_cannot_be_pooled_into_one_quorum() {
        // The other half of binding the head: a certificate must not be assembled ACROSS tips. Five signatures exist
        // here and all verify, but they attest two different heads — so no group of them reaches the quorum, and
        // `try_form_checkpoint` groups by the `(root, head)` pair for the same reason.
        let ks = keys(7);
        let verifiers: Vec<HybridVerifier> = ks.iter().map(|(_, v)| v.clone()).collect();
        let root = [0x44; 32];
        let other = [0x99; 32];
        let mut votes: Vec<ExecVote> = (0..3).map(|i| ExecVote::sign(6, root, HEAD, i as u8, &ks[i].0)).collect();
        votes.extend((3..5).map(|i| ExecVote::sign(6, root, other, i as u8, &ks[i].0)));
        for (i, v) in votes.iter().enumerate() {
            assert!(v.verify(&verifiers[i]), "vote {i} is genuinely signed — the mix is honest disagreement");
        }
        let pooled = ExecCertificate { head: HEAD, height: 6, state_root: root, votes };
        assert!(!pooled.verify(5, &verifiers), "votes attesting different tips cannot be pooled into one quorum");
    }

    #[test]
    fn a_wrong_root_or_forged_vote_is_rejected() {
        let ks = keys(7);
        let verifiers: Vec<HybridVerifier> = ks.iter().map(|(_, v)| v.clone()).collect();
        let root = [0x22; 32];
        // One voter attests a different root — the certificate (which claims a single root) is not uniform.
        let mut votes: Vec<ExecVote> = (0..5).map(|i| ExecVote::sign(3, root, HEAD, i as u8, &ks[i].0)).collect();
        votes[4] = ExecVote::sign(3, [0xFF; 32], HEAD, 4, &ks[4].0);
        let cert = ExecCertificate { height: 3, state_root: root, head: HEAD, votes };
        assert!(!cert.verify(5, &verifiers), "a non-uniform-root set is not a certificate");
        // A vote signed by the wrong key is rejected.
        let forged = ExecVote::sign(3, root, HEAD, 0, &ks[6].0); // voter 0 signed by key 6
        assert!(!forged.verify(&verifiers[0]));
    }

    #[test]
    fn a_divergent_execution_is_detectable() {
        let ks = keys(7);
        let verifiers: Vec<HybridVerifier> = ks.iter().map(|(_, v)| v.clone()).collect();
        let canonical = [0x33; 32];
        let cert = ExecCertificate {
            head: HEAD,
            height: 12,
            state_root: canonical,
            votes: (0..5).map(|i| ExecVote::sign(12, canonical, HEAD, i as u8, &ks[i].0)).collect(),
        };
        assert!(cert.verify(5, &verifiers));
        // Validator 6 executed to a different root at the same height → detected + attributable (slashable).
        let bad = ExecVote::sign(12, [0xAB; 32], HEAD, 6, &ks[6].0);
        assert_eq!(cert.conflicting(&bad, &verifiers), Some(6));
        // An agreeing vote, a wrong-height vote, and an unsigned/forged vote are not flagged.
        let good = ExecVote::sign(12, canonical, HEAD, 6, &ks[6].0);
        assert_eq!(cert.conflicting(&good, &verifiers), None);
        let other_height = ExecVote::sign(11, [0xAB; 32], HEAD, 6, &ks[6].0);
        assert_eq!(cert.conflicting(&other_height, &verifiers), None);
    }

    #[test]
    fn an_exec_vote_round_trips_through_bytes() {
        let ks = keys(1);
        let v = ExecVote::sign(42, [0x7E; 32], HEAD, 0, &ks[0].0);
        assert_eq!(ExecVote::from_bytes(&v.to_bytes()), Some(v.clone()));
        assert!(v.verify(&ks[0].1));
    }

    #[test]
    fn an_exec_certificate_round_trips_and_still_verifies() {
        let ks = keys(7);
        let verifiers: Vec<HybridVerifier> = ks.iter().map(|(_, v)| v.clone()).collect();
        let root = [0x9A; 32];
        let votes: Vec<ExecVote> = (0..5).map(|i| ExecVote::sign(4, root, HEAD, i as u8, &ks[i].0)).collect();
        let cert = ExecCertificate { height: 4, state_root: root, head: HEAD, votes };
        let rt = ExecCertificate::from_bytes(&cert.to_bytes()).unwrap();
        assert_eq!(rt, cert, "the certificate round-trips through bytes");
        assert!(rt.verify(5, &verifiers), "a decoded certificate still verifies");
        assert!(ExecCertificate::from_bytes(&cert.to_bytes()[..30]).is_none(), "a truncated certificate is rejected");
    }
}
