//! **Parent-attests-child finality** — L0 shared security across the recursion of cells
//! (`docs/design-self-organization.md` §6, spec §L1).
//!
//! FANOS's hierarchy is a recursion of projective cells: a parent cell observes its child cells the way a cell
//! observes its own nodes (`fanos-core::hierarchy` does this for *coherence* — the DIAKRISIS scale-invariance
//! that mirrors the UHM holarchy's T-72 fractal closure). This module is the *finality* twin: a parent cell
//! anchors its children's **executed state** by verifying their execution certificates, giving *shared security
//! without a separate relay chain* — the parent is the relay, using the same geometry.
//!
//! A child cell finalizes and executes its own TAXIS ledger and produces an
//! [`ExecCertificate`](crate::checkpoint::ExecCertificate): a `Q`-quorum attestation of its canonical state
//! root at a height. The parent, holding each child's committee keys, **verifies** that certificate (and,
//! optionally, samples the child's data availability) before recording it. Consequences:
//! - **Shared security.** Once the parent records a child's checkpoint, anyone who trusts the parent
//!   transitively trusts the child's finality — the child inherits the parent's assurance without the parent
//!   re-executing it. A child cell cannot present a finalized state its own committee did not certify.
//! - **Detectable child equivocation.** If a child committee ever certifies *two* different roots at one height
//!   (only possible if more than `f` of the child's validators equivocate), the parent sees the conflict
//!   ([`ChildRegistry::conflict`]) — a slashable child-committee fault surfaced one level up, exactly as a
//!   node's fault is surfaced to its cell.
//! - **Availability-gated.** The parent can require the child's payload be retrievable (the same projective-LRC
//!   DA sampling a validator runs in-cell) before anchoring it, so it never vouches for an unavailable state.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_code::lrc::is_recoverable_fano;
use fanos_pqcrypto::HybridVerifier;

use crate::checkpoint::ExecCertificate;

/// A child cell's identity as the parent knows it: its cell address, its committee's verifying keys, and the
/// quorum its certificates must meet.
#[derive(Clone)]
pub struct ChildCommittee {
    /// The child cell's address in the hierarchy.
    pub cell: u32,
    /// The child committee's validator verifying keys (index = validator index, as in the child's `ExecVote`).
    pub verifiers: Vec<HybridVerifier>,
    /// The child cell's Byzantine quorum `Q`.
    pub quorum: usize,
}

/// A parent cell's trust-minimized registry of its children's finalized checkpoints. It records, per child, the
/// latest **verified** execution certificate — the parent's authoritative view of each child's executed state.
#[derive(Default)]
pub struct ChildRegistry {
    committees: BTreeMap<u32, ChildCommittee>,
    attested: BTreeMap<u32, ExecCertificate>,
}

impl ChildRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self { committees: BTreeMap::new(), attested: BTreeMap::new() }
    }

    /// Register (or update) a child cell's committee — the parent learns whose certificates to trust for `cell`.
    pub fn register(&mut self, committee: ChildCommittee) {
        self.committees.insert(committee.cell, committee);
    }

    /// Verify and record a child's execution certificate. Returns the newly-attested `(height, state_root)` iff
    /// the certificate verifies under the child's registered committee **and strictly advances** that child's
    /// attested height (finality only moves forward). Rejects an unknown child, an invalid or sub-quorum
    /// certificate, or a stale/replayed height.
    pub fn attest(&mut self, cell: u32, cert: ExecCertificate) -> Option<(u64, [u8; 32])> {
        let committee = self.committees.get(&cell)?;
        if !cert.verify(committee.quorum, &committee.verifiers) {
            return None; // not a genuine Q-quorum of this child
        }
        if self.attested.get(&cell).is_some_and(|c| cert.height <= c.height) {
            return None; // finality does not regress
        }
        let anchor = (cert.height, cert.state_root);
        self.attested.insert(cell, cert);
        Some(anchor)
    }

    /// Verify + record a child certificate **only if its data is available** — the parent additionally checks
    /// the child block's DA sample: `present` is the child-shard availability bitmask (bit `p` set ⇒ point
    /// `p`'s shard is retrievable). An unavailable child payload (`!is_recoverable_fano`) is refused, so the
    /// parent never anchors a state whose data is withheld. Otherwise identical to [`attest`](Self::attest).
    pub fn attest_available(&mut self, cell: u32, cert: ExecCertificate, present: u8) -> Option<(u64, [u8; 32])> {
        let missing = (!present) & 0x7F;
        if !is_recoverable_fano(missing) {
            return None; // the child's data is unavailable — do not vouch for it
        }
        self.attest(cell, cert)
    }

    /// The latest certificate the parent has attested for `cell` (its authoritative view of the child's state).
    #[must_use]
    pub fn latest(&self, cell: u32) -> Option<&ExecCertificate> {
        self.attested.get(&cell)
    }

    /// Detect a **child equivocation**: a validly-signed child certificate that certifies a *different* root at
    /// the *same* height as one the parent already attested — proof the child committee forked (only possible if
    /// more than `f` child validators equivocated). Returns `(height, attested_root, conflicting_root)`, the
    /// evidence the parent escalates/slashes. `None` if the child is unknown, the certificate is invalid, it is
    /// for a different height, or it agrees.
    #[must_use]
    pub fn conflict(&self, cell: u32, cert: &ExecCertificate) -> Option<(u64, [u8; 32], [u8; 32])> {
        let committee = self.committees.get(&cell)?;
        let prior = self.attested.get(&cell)?;
        if cert.height != prior.height || cert.state_root == prior.state_root {
            return None;
        }
        if !cert.verify(committee.quorum, &committee.verifiers) {
            return None; // an unverified claim is not evidence
        }
        Some((cert.height, prior.state_root, cert.state_root))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::{HybridSigSecret, SeedRng};

    use crate::checkpoint::ExecVote;

    /// A child committee of 7 validators (secrets kept for signing test certificates).
    fn child(cell: u32, tag: u8) -> (Vec<HybridSigSecret>, ChildCommittee) {
        let ks: Vec<(HybridSigSecret, HybridVerifier)> = (0..7)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[tag, i as u8]);
                HybridSigSecret::generate(&mut rng)
            })
            .collect();
        let verifiers = ks.iter().map(|(_, v)| v.clone()).collect();
        (ks.into_iter().map(|(s, _)| s).collect(), ChildCommittee { cell, verifiers, quorum: 5 })
    }

    fn cert(height: u64, root: [u8; 32], secrets: &[HybridSigSecret], q: usize) -> ExecCertificate {
        let votes = (0..q).map(|i| ExecVote::sign(height, root, i as u8, &secrets[i])).collect();
        ExecCertificate { height, state_root: root, votes }
    }

    #[test]
    fn a_parent_anchors_a_verified_child_checkpoint() {
        let (secrets, committee) = child(2, 0x10);
        let mut reg = ChildRegistry::new();
        reg.register(committee);
        let c = cert(4, [0xAA; 32], &secrets, 5);
        assert_eq!(reg.attest(2, c), Some((4, [0xAA; 32])), "a valid Q-quorum child cert is anchored");
        assert_eq!(reg.latest(2).map(|c| c.height), Some(4));
        // Finality advances; a later height is anchored, an equal/earlier one is not.
        assert_eq!(reg.attest(2, cert(5, [0xBB; 32], &secrets, 5)), Some((5, [0xBB; 32])));
        assert_eq!(reg.attest(2, cert(5, [0xCC; 32], &secrets, 5)), None, "finality does not regress");
    }

    #[test]
    fn an_unknown_child_or_sub_quorum_or_forged_cert_is_refused() {
        let (secrets, committee) = child(2, 0x20);
        let mut reg = ChildRegistry::new();
        // Unknown child.
        assert_eq!(reg.attest(9, cert(1, [1; 32], &secrets, 5)), None);
        reg.register(committee);
        // Sub-quorum (4 < 5).
        assert_eq!(reg.attest(2, cert(1, [1; 32], &secrets, 4)), None);
        // A certificate signed by a DIFFERENT committee's keys is refused.
        let (other_secrets, _) = child(2, 0x99);
        assert_eq!(reg.attest(2, cert(1, [1; 32], &other_secrets, 5)), None);
    }

    #[test]
    fn availability_gates_the_anchor() {
        let (secrets, committee) = child(3, 0x30);
        let mut reg = ChildRegistry::new();
        reg.register(committee);
        let c = cert(1, [0x77; 32], &secrets, 5);
        // A hyperoval's worth of shards missing → unrecoverable → refused even with a valid certificate.
        let hyperoval = (0u8..=0x7F).find(|&m| !is_recoverable_fano(m)).unwrap();
        assert_eq!(reg.attest_available(3, c.clone(), (!hyperoval) & 0x7F), None, "unavailable child is not anchored");
        // Full availability → anchored.
        assert_eq!(reg.attest_available(3, c, 0x7F), Some((1, [0x77; 32])));
    }

    #[test]
    fn a_child_equivocation_is_detectable_evidence() {
        let (secrets, committee) = child(4, 0x40);
        let mut reg = ChildRegistry::new();
        reg.register(committee);
        reg.attest(4, cert(7, [0xA0; 32], &secrets, 5)).unwrap();
        // The child committee certifies a DIFFERENT root at the same height (>f equivocated) → parent has proof.
        let forked = cert(7, [0xB0; 32], &secrets, 5);
        assert_eq!(reg.conflict(4, &forked), Some((7, [0xA0; 32], [0xB0; 32])));
        // An agreeing cert, or one for another height, is not a conflict.
        assert_eq!(reg.conflict(4, &cert(7, [0xA0; 32], &secrets, 5)), None);
        assert_eq!(reg.conflict(4, &cert(8, [0xB0; 32], &secrets, 5)), None);
    }
}
