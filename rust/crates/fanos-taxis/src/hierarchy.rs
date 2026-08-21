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
//! [`ExecCertificate`]: a `Q`-quorum attestation of its canonical state
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
    /// The child cell's address in the hierarchy — the canonical bytes of a `fanos_geometry::CellPath`.
    ///
    /// ⛔ **This was a `u32` until 2026-08-21, and a flat integer cannot name a cell of a tree.** A cell is the
    /// sibling-set under one prefix (`docs/design-hierarchy-recursion.md`), so its identity is *(the parent's address,
    /// which Fano cell of the level below it)* — and the first half is a path. Keyed by an integer, a parent's child
    /// `0` and its grandchild `0` are one entry, which is a registry that silently merges two committees and then
    /// verifies a certificate against the wrong keys.
    ///
    /// Opaque bytes rather than a `CellPath<F>` because that would make this type generic over the plane for a field it
    /// only ever compares — `ChildRegistry` needs `Ord`, not geometry. `fanos_geometry::CellPath::encode` produces
    /// them and `decode` reads them back, so the meaning is one function call away and lives where the geometry does.
    pub cell: Vec<u8>,
    /// The child committee's validator verifying keys, **indexed by validator index** as in the child's
    /// `ExecVote`, with `None` for a seat this parent has not learned.
    ///
    /// **Sparse, because `Q` of `n` is a tolerance a dense list cannot express.** A parent assembles this
    /// from the child cell's per-seat directory records, and a seat that has not published yet is a fact
    /// about the parent's reading rather than about the child. With `Vec<HybridVerifier>` the only options
    /// were to refuse the whole committee — making a five-of-seven quorum unusable whenever two seats are
    /// quiet — or to pad it, which would silently renumber every vote after the hole onto somebody else's
    /// key. `ExecCertificate::verify_by` states what a hole means: an unchecked vote is not evidence, and it
    /// still claims its seat so duplicates stay caught.
    pub verifiers: Vec<Option<HybridVerifier>>,
    /// The child cell's Byzantine quorum `Q`.
    pub quorum: usize,
}

/// A parent cell's trust-minimized registry of its children's finalized checkpoints. It records, per child, the
/// latest **verified** execution certificate — the parent's authoritative view of each child's executed state.
#[derive(Default)]
pub struct ChildRegistry {
    committees: BTreeMap<Vec<u8>, ChildCommittee>,
    attested: BTreeMap<Vec<u8>, ExecCertificate>,
}

impl ChildRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self { committees: BTreeMap::new(), attested: BTreeMap::new() }
    }

    /// Register (or update) a child cell's committee — the parent learns whose certificates to trust for `cell`.
    pub fn register(&mut self, committee: ChildCommittee) {
        self.committees.insert(committee.cell.clone(), committee);
    }

    /// Verify and record a child's execution certificate, **without checking that its data is available**.
    ///
    /// Private, and that is the fix rather than an accident of scope. This and
    /// [`attest_available`](Self::attest_available) were both public, differing only in whether the parent
    /// refuses to vouch for a state whose data is withheld — and the one production path that anchors
    /// children (`fanos_node::crosscell_dir::attest_children`) called *this* one. The safe door existed, was
    /// documented as the protection, and no caller went through it. A security property offered as an
    /// alternative method is a property nobody gets.
    ///
    /// Returns the newly-attested `(height, state_root)` iff the certificate verifies under the child's
    /// registered committee **and strictly advances** that child's attested height (finality only moves
    /// forward). Rejects an unknown child, an invalid or sub-quorum certificate, or a stale/replayed height.
    fn attest(&mut self, cell: &[u8], cert: ExecCertificate) -> Option<(u64, [u8; 32])> {
        let committee = self.committees.get(cell)?;
        if !cert.verify_by(committee.quorum, committee.verifiers.len(), |i| {
            committee.verifiers.get(i).and_then(Option::as_ref)
        }) {
            return None; // not a genuine Q-quorum of this child
        }
        if self.attested.get(cell).is_some_and(|c| cert.height <= c.height) {
            return None; // finality does not regress
        }
        let anchor = (cert.height, cert.state_root);
        self.attested.insert(cell.to_vec(), cert);
        Some(anchor)
    }

    /// Verify + record a child certificate **only if its data is available** — the one way a parent anchors a
    /// child.
    ///
    /// `present` is the child-shard availability bitmask (bit `p` set ⇒ point `p`'s shard is retrievable). An
    /// unavailable child payload (`!is_recoverable_fano`) is refused, so the parent never anchors a state
    /// whose data is withheld.
    ///
    /// The mask is an argument the caller must produce, never a default: a parent that cannot establish a
    /// child's availability must anchor nothing, and passing `0` says "nothing is present" and refuses,
    /// which is the safe direction. Today nothing produces one — the §L4.3 sampler yields `available: bool`
    /// per store key, and no shipped binary issues even that (#173) — so this is where that gap becomes
    /// visible instead of being skipped.
    pub fn attest_available(&mut self, cell: &[u8], cert: ExecCertificate, present: u8) -> Option<(u64, [u8; 32])> {
        let missing = (!present) & 0x7F;
        if !is_recoverable_fano(missing) {
            return None; // the child's data is unavailable — do not vouch for it
        }
        self.attest(cell, cert)
    }

    /// The latest certificate the parent has attested for `cell` (its authoritative view of the child's state).
    #[must_use]
    pub fn latest(&self, cell: &[u8]) -> Option<&ExecCertificate> {
        self.attested.get(cell)
    }

    /// Detect a **child equivocation**: a validly-signed child certificate that certifies a *different* root at
    /// the *same* height as one the parent already attested — proof the child committee forked (only possible if
    /// more than `f` child validators equivocated). Returns `(height, attested_root, conflicting_root)`, the
    /// evidence the parent escalates/slashes. `None` if the child is unknown, the certificate is invalid, it is
    /// for a different height, or it agrees.
    #[must_use]
    pub fn conflict(&self, cell: &[u8], cert: &ExecCertificate) -> Option<(u64, [u8; 32], [u8; 32])> {
        let committee = self.committees.get(cell)?;
        let prior = self.attested.get(cell)?;
        if cert.height != prior.height || cert.state_root == prior.state_root {
            return None;
        }
        if !cert.verify_by(committee.quorum, committee.verifiers.len(), |i| {
            committee.verifiers.get(i).and_then(Option::as_ref)
        }) {
            return None; // an unverified claim is not evidence
        }
        Some((cert.height, prior.state_root, cert.state_root))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    /// Every Fano point's shard retrievable — what these tests assume unless they are about availability.
    const ALL_PRESENT: u8 = 0x7F;

    use super::*;
    use fanos_pqcrypto::{HybridSigSecret, SeedRng};

    use crate::checkpoint::ExecVote;

    /// The canonical name of the child cell hanging under the parent's point `k` — a real
    /// `fanos_geometry::CellPath`, not a stand-in integer, so these tests exercise the key the directory writes.
    ///
    /// At `q = 2` a level holds exactly one Fano cell, so what distinguishes two children is their *prefix*: the point
    /// of the parent they hang under. That is the case a `u32` key merged.
    fn name(k: usize) -> Vec<u8> {
        use fanos_field::F2;
        use fanos_geometry::{CellPath, HierAddr, Point};
        CellPath::<F2>::under(HierAddr::root(Point::at(k)), 0).expect("PG(2,2) holds one cell per level").encode()
    }

    /// A child committee of 7 validators (secrets kept for signing test certificates).
    fn child(cell: usize, tag: u8) -> (Vec<HybridSigSecret>, ChildCommittee) {
        let ks: Vec<(HybridSigSecret, HybridVerifier)> = (0..7)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[tag, i as u8]);
                HybridSigSecret::generate(&mut rng)
            })
            .collect();
        let verifiers = ks.iter().map(|(_, v)| Some(v.clone())).collect();
        (ks.into_iter().map(|(s, _)| s).collect(), ChildCommittee { cell: name(cell), verifiers, quorum: 5 })
    }

    fn cert(height: u64, root: [u8; 32], secrets: &[HybridSigSecret], q: usize) -> ExecCertificate {
        let votes = (0..q).map(|i| ExecVote::sign(height, root, [0xEE; 32], i as u8, &secrets[i])).collect();
        ExecCertificate { height, state_root: root, head: [0xEE; 32], votes }
    }

    /// **A hole in the committee costs the votes it cannot check, and nothing else.**
    ///
    /// `Q` of `n` is a tolerance, and a dense `Vec<HybridVerifier>` could not express the state a parent is
    /// actually in — five seats learned, two quiet. Refusing the whole committee there makes the quorum's own
    /// tolerance unusable; padding it would renumber every vote after the hole onto somebody else's key.
    ///
    /// Three cases, because the middle one is the point and the outer two are what make it safe.
    #[test]
    fn a_committee_with_holes_verifies_what_it_can_and_refuses_what_it_cannot() {
        let (secrets, committee) = child(3, 0x40);
        let c = cert(9, [0xAB; 32], &secrets, 5);
        let seats = committee.verifiers.len();

        assert!(
            c.verify_by(5, seats, |i| committee.verifiers.get(i).and_then(Option::as_ref)),
            "a full committee must verify a five-vote certificate, or the two cases below prove nothing"
        );

        // Two seats unknown, and neither of them signed: the five that did are all checkable.
        let mut quiet_seats = committee.verifiers.clone();
        quiet_seats[5] = None;
        quiet_seats[6] = None;
        assert!(
            c.verify_by(5, seats, |i| quiet_seats.get(i).and_then(Option::as_ref)),
            "five signatures verified against five known keys is a quorum; refusing here would make a \
             five-of-seven cell unratifiable whenever two of its seats are quiet"
        );

        // A seat that DID sign is unknown: that vote cannot be counted, and the quorum is one short.
        let mut missing_signer = committee.verifiers.clone();
        missing_signer[0] = None;
        assert!(
            !c.verify_by(5, seats, |i| missing_signer.get(i).and_then(Option::as_ref)),
            "an unchecked vote was counted toward the quorum — a parent would then ratify on a signature it \
             never verified, which is the whole thing a committee is for"
        );
    }

    #[test]
    fn a_parent_anchors_a_verified_child_checkpoint() {
        let (secrets, committee) = child(2, 0x10);
        let mut reg = ChildRegistry::new();
        reg.register(committee);
        let c = cert(4, [0xAA; 32], &secrets, 5);
        assert_eq!(reg.attest_available(&name(2), c, ALL_PRESENT), Some((4, [0xAA; 32])), "a valid Q-quorum child cert is anchored");
        assert_eq!(reg.latest(&name(2)).map(|c| c.height), Some(4));
        // Finality advances; a later height is anchored, an equal/earlier one is not.
        assert_eq!(reg.attest_available(&name(2), cert(5, [0xBB; 32], &secrets, 5), ALL_PRESENT), Some((5, [0xBB; 32])));
        assert_eq!(reg.attest_available(&name(2), cert(5, [0xCC; 32], &secrets, 5), ALL_PRESENT), None, "finality does not regress");
    }

    #[test]
    fn an_unknown_child_or_sub_quorum_or_forged_cert_is_refused() {
        let (secrets, committee) = child(2, 0x20);
        let mut reg = ChildRegistry::new();
        // Unknown child — a real cell of the plane that simply was never registered, since `name` builds an
        // address and `Point::at` refuses an index the plane does not have.
        assert_eq!(reg.attest_available(&name(6), cert(1, [1; 32], &secrets, 5), ALL_PRESENT), None);
        reg.register(committee);
        // Sub-quorum (4 < 5).
        assert_eq!(reg.attest_available(&name(2), cert(1, [1; 32], &secrets, 4), ALL_PRESENT), None);
        // A certificate signed by a DIFFERENT committee's keys is refused.
        let (other_secrets, _) = child(2, 0x99);
        assert_eq!(reg.attest_available(&name(2), cert(1, [1; 32], &other_secrets, 5), ALL_PRESENT), None);
    }

    #[test]
    fn availability_gates_the_anchor() {
        let (secrets, committee) = child(3, 0x30);
        let mut reg = ChildRegistry::new();
        reg.register(committee);
        let c = cert(1, [0x77; 32], &secrets, 5);
        // A hyperoval's worth of shards missing → unrecoverable → refused even with a valid certificate.
        let hyperoval = (0u8..=0x7F).find(|&m| !is_recoverable_fano(m)).unwrap();
        assert_eq!(reg.attest_available(&name(3), c.clone(), (!hyperoval) & 0x7F), None, "unavailable child is not anchored");
        // Full availability → anchored.
        assert_eq!(reg.attest_available(&name(3), c, ALL_PRESENT), Some((1, [0x77; 32])));
    }

    #[test]
    fn a_child_equivocation_is_detectable_evidence() {
        let (secrets, committee) = child(4, 0x40);
        let mut reg = ChildRegistry::new();
        reg.register(committee);
        reg.attest_available(&name(4), cert(7, [0xA0; 32], &secrets, 5), ALL_PRESENT).unwrap();
        // The child committee certifies a DIFFERENT root at the same height (>f equivocated) → parent has proof.
        let forked = cert(7, [0xB0; 32], &secrets, 5);
        assert_eq!(reg.conflict(&name(4), &forked), Some((7, [0xA0; 32], [0xB0; 32])));
        // An agreeing cert, or one for another height, is not a conflict.
        assert_eq!(reg.conflict(&name(4), &cert(7, [0xA0; 32], &secrets, 5)), None);
        assert_eq!(reg.conflict(&name(4), &cert(8, [0xB0; 32], &secrets, 5)), None);
    }
}
