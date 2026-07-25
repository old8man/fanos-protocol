//! The **per-input spend proof** — the top-level zero-knowledge relation for spending one shielded note, binding
//! every sub-proof over the *same* note. It composes the four built primitives so that a single hidden note `cm`,
//! its secret key `nsk`, its value node, and its value commitment `Cv` are shared across all of them:
//!
//! - **note-validity** ([`crate::ring_note`]) — `cm = hash(value_node, hash(hash(nsk, nsk), rho))`;
//! - **value-tie** ([`crate::ring_value_tie`]) — `value_node` encodes the amount in `Cv`;
//! - **untraceability** ([`crate::ring_untraceable`]) — `cm` is a tree member under the public root, and the public
//!   nullifier is its correct **position-bound** nullifier `nf = hash(nsk, hash(cm, pos))` at the very slot proven.
//!
//! The bindings are the soundness: the note-validity and value-tie proofs are verified against the **untraceability
//! leaf commitment** (`cm`) and its **nsk commitment**, and against one shared `value_node` commitment. So the note
//! whose amount is tied to `Cv` (hence balanced/ranged by [`crate::ring_confidential`]) is *exactly* the note
//! proven a tree member and nullified. Committed once, the shared randomness is derived so all sub-proofs agree.
//!
//! A whole shielded transaction is: a `prove_input` per input, a range proof per output, and one balance proof
//! ([`crate::ring_confidential`]) — the full `ShieldedProof` the ledger integration will wire.
//!
//! > **STATUS — [P]/[H], correctness-first.** A composition of the built, tested primitives; inherits their status
//! > and their `O(depth·ELL_H·LOG_BASE·REPETITIONS)` cost. Verified by an `#[ignore]`d test (`--ignored`) at real
//! > `bits = LOG_BASE`: a full input spend proves and verifies end to end.

use alloc::vec::Vec;

use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_hash::{HashNode, HashParams};
use crate::ring_membership::{NodeWitness, commit_node, node_r};
use crate::ring_note::{NoteProof, NoteScheme, prove_note, verify_note};
use crate::ring_nullifier::nullifier_of;
use crate::ring_untraceable::{UntraceableProof, position_of, prove_untraceable, verify_untraceable};
use crate::ring_value_tie::{ValueTieProof, prove_value_tie, verify_value_tie};

/// The domain-separated SIS hash instances a spend uses — the [`NoteScheme`] (how a note is built) plus the two
/// ledger-level hashes (the tree it lives in and the nullifier it reveals).
pub struct SpendScheme {
    /// How a note commitment is built from `(value, nsk, rho)`.
    pub note: NoteScheme,
    /// The note-commitment tree hash.
    pub tree_hp: HashParams,
    /// The slot hash `slot = hash(cm, pos_node)` — the note's position-bound identity.
    pub slot_hp: HashParams,
    /// The nullifier hash `nf = hash(nsk, slot)`.
    pub nf_hp: HashParams,
}

impl SpendScheme {
    /// The canonical spend hashes (domain-separated instances of the ring hash).
    #[must_use]
    pub fn standard() -> Self {
        Self {
            note: NoteScheme::standard(),
            tree_hp: HashParams::standard(),
            slot_hp: HashParams::from_seed(b"FANOS-obolos-v1/note-slot"),
            nf_hp: HashParams::from_seed(b"FANOS-obolos-v1/nullifier"),
        }
    }
}

/// A zero-knowledge proof of spending one input: valid note + value-tie + membership + nullifier, all over one note.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InputProof {
    value_coms: Vec<RingCommitment>, // the hidden value_node commitment, shared by note + value-tie
    note: NoteProof,
    value_tie: ValueTieProof,
    untraceable: UntraceableProof,
}

/// A sub-seed `base ‖ tag`.
fn sub(base: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut s = base.to_vec();
    s.extend_from_slice(tag);
    s
}

/// Prove the full spend of one input: the note `cm = hash(value_node, hash(hash(nsk, nsk), rho))` is a tree member
/// with the public root, its nullifier is the position-bound `nf = hash(nsk, hash(cm, pos))` at the slot the path
/// proves, and `value_node` encodes the amount in `cv`. `rho`
/// is the note's per-note uniqueness randomness (delivered to the spender with the note's opening). Returns the
/// note commitment `cm` (the leaf the caller hashes to the root) and the public nullifier `nf`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn prove_input(
    params: &RingParams,
    scheme: &SpendScheme,
    nsk: &HashNode,
    value_node: &HashNode,
    rho: &HashNode,
    cv: &RingCommitment,
    rv: &RingRandomness,
    siblings: &[HashNode],
    directions: &[u64],
    seed: &[u8],
) -> Option<(HashNode, HashNode, InputProof)> {
    // Shared commitment randomness: the untraceability proof derives cm_r / nsk_r identically from `seed`.
    let cm_r = node_r(seed, "/leaf", 0);
    let nsk_r = node_r(seed, "/nsk", 0);
    let value_r = node_r(seed, "/valnode", 0);

    // Note validity — computes cm = hash(value_node, hash(hash(nsk, nsk), rho)). Masking is domain-separated (/note).
    let nsk_w = NodeWitness { node: nsk, randomness: &nsk_r };
    let value_w = NodeWitness { node: value_node, randomness: &value_r };
    let (cm, note) = prove_note(params, &scheme.note, &nsk_w, &value_w, rho, &cm_r, &sub(seed, b"/note"))?;

    // Value-tie — value_node encodes cv's amount (/vtie masking).
    let value_tie = prove_value_tie(params, cv, rv, value_node, &value_r, &sub(seed, b"/vtie"))?;

    // Untraceability — membership of cm + its position-bound nullifier. Uses `seed` directly, so cm_r/nsk_r match
    // the note proof's.
    let untraceable = prove_untraceable(
        params,
        &scheme.tree_hp,
        &scheme.slot_hp,
        &scheme.nf_hp,
        &cm,
        nsk,
        siblings,
        directions,
        seed,
    )?;
    let nf = nullifier_of(&scheme.slot_hp, &scheme.nf_hp, nsk, &cm, position_of(directions));

    let value_coms = commit_node(params, value_node, &value_r);
    Some((cm, nf, InputProof { value_coms, note, value_tie, untraceable }))
}

/// Verify a [`prove_input`] proof against the public tree `root`, the input value commitment `cv`, and the public
/// nullifier `nf`.
#[must_use]
pub fn verify_input(
    params: &RingParams,
    scheme: &SpendScheme,
    root: &HashNode,
    cv: &RingCommitment,
    nf: &HashNode,
    proof: &InputProof,
) -> bool {
    // Membership + position-bound nullifier bind the note commitment `cm`, the key `nsk`, and the tree slot.
    verify_untraceable(params, &scheme.tree_hp, &scheme.slot_hp, &scheme.nf_hp, root, nf, &proof.untraceable)
        // The note is well-formed over the SAME cm, nsk (from untraceability) and value_node.
        && verify_note(
            params,
            &scheme.note,
            proof.untraceable.cm_commitment(),
            proof.untraceable.nsk_commitment(),
            &proof.value_coms,
            &proof.note,
        )
        // The value_node encodes the input's committed amount.
        && verify_value_tie(params, cv, &proof.value_coms, &proof.value_tie)
}

impl crate::ring_size::ProofSize for InputProof {
    fn ring_elements(&self) -> usize {
        self.value_coms.ring_elements() + self.note.ring_elements() + self.value_tie.ring_elements()
            + self.untraceable.ring_elements()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ring::Poly;
    use crate::ring_hash::{ELL_H, LOG_BASE};

    /// The digit-encoding value node for amount `v`.
    fn value_node(v: u64) -> HashNode {
        HashNode::from_limbs((0..ELL_H).map(|d| Poly::constant((v >> (LOG_BASE * d as u32)) & 0xFFFF)).collect())
    }

    #[test]
    #[ignore = "full input spend: note + membership + nullifier at bits=LOG_BASE — a few minutes; run with --ignored"]
    fn a_full_input_spend_proves_and_verifies() {
        let params = RingParams::standard();
        let scheme = SpendScheme::standard();
        let v = 12_345u64;
        let rv = RingRandomness::from_seed(b"in-rv");
        let cv = RingCommitment::commit(&params, v, &rv);
        let vn = value_node(v);
        let nsk = HashNode::from_bytes(b"in-nsk");
        let rho = HashNode::from_bytes(b"in-rho");
        let sib0 = HashNode::from_bytes(b"in-sib");
        let d0 = 0u64;
        let sibs = [sib0.clone()];
        let dirs = [d0];
        let (cm, nf, proof) =
            prove_input(&params, &scheme, &nsk, &vn, &rho, &cv, &rv, &sibs, &dirs, b"seed").expect("input spend");
        // The tree root cm hashes up to (matching what prove_input's membership computed).
        let root = {
            let (l, r) = if d0 == 1 { (sib0.clone(), cm.clone()) } else { (cm.clone(), sib0.clone()) };
            scheme.tree_hp.hash(&l, &r)
        };
        assert!(verify_input(&params, &scheme, &root, &cv, &nf, &proof), "a full input spend verifies");
        // A wrong value commitment (different amount) breaks the value-tie.
        let cv_wrong = RingCommitment::commit(&params, v + 1, &rv);
        assert!(!verify_input(&params, &scheme, &root, &cv_wrong, &nf, &proof), "a wrong amount is rejected");
    }
}
