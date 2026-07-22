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

/// A validator's signed attestation that executing the ledger through `height` yields `state_root`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExecVote {
    /// The executed height this attests to.
    pub height: u64,
    /// The state root after executing every finalized block up to and including `height`.
    pub state_root: [u8; 32],
    /// The attesting validator's index.
    pub voter: u8,
    /// The hybrid-PQ signature over [`signable`](ExecVote::signable).
    sig: Vec<u8>,
}

impl ExecVote {
    /// The signed content: `height(8) ‖ state_root(32) ‖ voter(1)`.
    #[must_use]
    fn signable(height: u64, state_root: &[u8; 32], voter: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 1);
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(state_root);
        out.push(voter);
        out
    }

    /// Sign an execution attestation with the validator's hybrid signing key.
    #[must_use]
    pub fn sign(height: u64, state_root: [u8; 32], voter: u8, signer: &HybridSigSecret) -> Self {
        let sig = signer.sign(&Self::signable(height, &state_root, voter)).to_bytes();
        Self { height, state_root, voter, sig }
    }

    /// Whether the signature verifies under `verifier` (which must be `voter`'s key).
    #[must_use]
    pub fn verify(&self, verifier: &HybridVerifier) -> bool {
        let Some(sig) = HybridSignature::from_bytes(&self.sig) else {
            return false;
        };
        verifier.verify(&Self::signable(self.height, &self.state_root, self.voter), &sig)
    }

    /// The fixed byte length of an execution attestation's [`to_bytes`](Self::to_bytes).
    pub const LEN: usize = 8 + 32 + 1 + HYBRID_SIG_LEN;

    /// Canonical bytes: `height(8) ‖ state_root(32) ‖ voter(1) ‖ signature`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 1 + HYBRID_SIG_LEN);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.state_root);
        out.push(self.voter);
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if the wrong length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 8 + 32 + 1 + HYBRID_SIG_LEN {
            return None;
        }
        let height = u64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
        let state_root = bytes.get(8..40)?.try_into().ok()?;
        let voter = *bytes.get(40)?;
        let sig = bytes.get(41..)?.to_vec();
        Some(Self { height, state_root, voter, sig })
    }
}

/// A `Q`-quorum of validators attesting the **same** `(height, state_root)` — a portable proof of a cell's
/// canonical executed state, verifiable by anyone holding the cell's validator keys.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExecCertificate {
    /// The executed height.
    pub height: u64,
    /// The canonical state root the quorum agrees on.
    pub state_root: [u8; 32],
    /// The `Q` (or more) distinct attesting votes.
    pub votes: Vec<ExecVote>,
}

impl ExecCertificate {
    /// Whether this is a valid execution certificate: every vote agrees on this `(height, state_root)`, the
    /// voters are **distinct** and each in range, every signature verifies, and there are at least `quorum`.
    /// Because two `Q`-quorums share an honest validator and an honest validator attests one root per height,
    /// two certificates for the same height can never carry different roots — so a verified certificate names
    /// the *unique* canonical executed state.
    #[must_use]
    pub fn verify(&self, quorum: usize, verifiers: &[HybridVerifier]) -> bool {
        let mut seen = alloc::vec![false; verifiers.len()];
        let mut count = 0usize;
        for v in &self.votes {
            if v.height != self.height || v.state_root != self.state_root {
                return false;
            }
            let Some(slot) = seen.get_mut(usize::from(v.voter)) else {
                return false;
            };
            if *slot {
                return false; // duplicate voter
            }
            let Some(verifier) = verifiers.get(usize::from(v.voter)) else {
                return false;
            };
            if !v.verify(verifier) {
                return false;
            }
            *slot = true;
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

    /// Canonical bytes: `height(8) ‖ state_root(32) ‖ vote_count(2) ‖ votes*` (each vote fixed-width
    /// [`ExecVote::LEN`]) — the portable form a cell publishes so a parent (or a cross-cell peer) can verify its
    /// finality over the overlay.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 2 + self.votes.len() * ExecVote::LEN);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.state_root);
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
        let count = usize::from(u16::from_be_bytes(bytes.get(40..42)?.try_into().ok()?));
        let body = bytes.get(42..)?;
        if body.len() != count * ExecVote::LEN {
            return None;
        }
        let mut votes = Vec::with_capacity(count);
        for i in 0..count {
            let start = i * ExecVote::LEN;
            votes.push(ExecVote::from_bytes(body.get(start..start + ExecVote::LEN)?)?);
        }
        Some(Self { height, state_root, votes })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::{HybridSigSecret, SeedRng};

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
        let votes: Vec<ExecVote> = (0..5).map(|i| ExecVote::sign(9, root, i as u8, &ks[i].0)).collect();
        let cert = ExecCertificate { height: 9, state_root: root, votes };
        assert!(cert.verify(5, &verifiers), "5 matching signed attestations certify height 9's root");
        // Fewer than the quorum does not certify.
        let short = ExecCertificate { height: 9, state_root: root, votes: cert.votes[..4].to_vec() };
        assert!(!short.verify(5, &verifiers));
    }

    #[test]
    fn a_wrong_root_or_forged_vote_is_rejected() {
        let ks = keys(7);
        let verifiers: Vec<HybridVerifier> = ks.iter().map(|(_, v)| v.clone()).collect();
        let root = [0x22; 32];
        // One voter attests a different root — the certificate (which claims a single root) is not uniform.
        let mut votes: Vec<ExecVote> = (0..5).map(|i| ExecVote::sign(3, root, i as u8, &ks[i].0)).collect();
        votes[4] = ExecVote::sign(3, [0xFF; 32], 4, &ks[4].0);
        let cert = ExecCertificate { height: 3, state_root: root, votes };
        assert!(!cert.verify(5, &verifiers), "a non-uniform-root set is not a certificate");
        // A vote signed by the wrong key is rejected.
        let forged = ExecVote::sign(3, root, 0, &ks[6].0); // voter 0 signed by key 6
        assert!(!forged.verify(&verifiers[0]));
    }

    #[test]
    fn a_divergent_execution_is_detectable() {
        let ks = keys(7);
        let verifiers: Vec<HybridVerifier> = ks.iter().map(|(_, v)| v.clone()).collect();
        let canonical = [0x33; 32];
        let cert = ExecCertificate {
            height: 12,
            state_root: canonical,
            votes: (0..5).map(|i| ExecVote::sign(12, canonical, i as u8, &ks[i].0)).collect(),
        };
        assert!(cert.verify(5, &verifiers));
        // Validator 6 executed to a different root at the same height → detected + attributable (slashable).
        let bad = ExecVote::sign(12, [0xAB; 32], 6, &ks[6].0);
        assert_eq!(cert.conflicting(&bad, &verifiers), Some(6));
        // An agreeing vote, a wrong-height vote, and an unsigned/forged vote are not flagged.
        let good = ExecVote::sign(12, canonical, 6, &ks[6].0);
        assert_eq!(cert.conflicting(&good, &verifiers), None);
        let other_height = ExecVote::sign(11, [0xAB; 32], 6, &ks[6].0);
        assert_eq!(cert.conflicting(&other_height, &verifiers), None);
    }

    #[test]
    fn an_exec_vote_round_trips_through_bytes() {
        let ks = keys(1);
        let v = ExecVote::sign(42, [0x7E; 32], 0, &ks[0].0);
        assert_eq!(ExecVote::from_bytes(&v.to_bytes()), Some(v.clone()));
        assert!(v.verify(&ks[0].1));
    }

    #[test]
    fn an_exec_certificate_round_trips_and_still_verifies() {
        let ks = keys(7);
        let verifiers: Vec<HybridVerifier> = ks.iter().map(|(_, v)| v.clone()).collect();
        let root = [0x9A; 32];
        let votes: Vec<ExecVote> = (0..5).map(|i| ExecVote::sign(4, root, i as u8, &ks[i].0)).collect();
        let cert = ExecCertificate { height: 4, state_root: root, votes };
        let rt = ExecCertificate::from_bytes(&cert.to_bytes()).unwrap();
        assert_eq!(rt, cert, "the certificate round-trips through bytes");
        assert!(rt.verify(5, &verifiers), "a decoded certificate still verifies");
        assert!(ExecCertificate::from_bytes(&cert.to_bytes()[..30]).is_none(), "a truncated certificate is rejected");
    }
}
