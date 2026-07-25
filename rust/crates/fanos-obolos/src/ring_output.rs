//! The **output note-creation proof** — the soundness binding for a *created* output, and the mirror of the
//! per-input spend proof ([`crate::ring_input`]) on the output side. A shielded transaction appends one new tree
//! leaf per output (a note commitment `cm`) and publishes one value commitment `Cv` per output (a balance term).
//! This proof ties the two together in zero knowledge, closing a **self-inflation** gap that a value commitment
//! and an opaque leaf leave open on their own:
//!
//! > Without it, a sender could *balance* an output at a small amount (its `Cv`) while appending a leaf `cm` that
//! > encodes a **larger** amount — then later spend that leaf for the larger amount. Balance holds over the `Cv`s,
//! > so nothing catches it; value is conjured from the gap. (The transparent reference [`crate::tx`] checks each
//! > output `Cv` opens to a claimed amount but does not bind the appended leaf to it — the ring path closes this.)
//!
//! ## The relation
//!
//! An output note is `cm = hash(value_node, note_owner)` ([`crate::ring_note`]'s leaf form), where `note_owner` is
//! the recipient's **one-time note key** `hash_rho(tag, rho)` — computed by the sender from the recipient's owner
//! tag and the fresh `rho` it delivers with the note, and hidden on the ledger — and `value_node` encodes the
//! amount. With `cm` and `Cv` **public**, the proof shows, in zero knowledge over hidden `value_node`, `note_owner`:
//!
//! ```text
//! cm  = hash(value_node, note_owner)  (a public-output hash step — as the nullifier proof reveals nf)
//! value_node ↔ Cv                     (the value-tie: value_node encodes Cv's amount — crate::ring_value_tie)
//! value_node, note_owner short        (node-shortness, so the SIS hash relation is binding)
//! ```
//!
//! **Soundness.** The hash step binds `cm` to the committed `value_node`; the value-tie binds that same
//! `value_node` to `Cv`; shortness makes the SIS opening of `cm` unique. So the amount the recipient can later
//! extract from `cm` (its unique short `value_node`) is exactly the amount balanced in `Cv` — no inflation. The
//! proof deliberately does **not** constrain how `note_owner` is derived: the sender does not know the recipient's
//! `nsk`, and ownership is established by the recipient's *own* spend proof ([`crate::ring_note`], which proves the
//! full `nsk → tag → note_owner` chain) later; here `note_owner` need only be a short node so the leaf's opening is
//! well-defined. A sender who fixes it wrongly only makes its own output unspendable — never anyone else's, and
//! never any extra value.
//!
//! > **STATUS — [P]/[H], correctness-first.** A composition of the built, tested primitives (hash step +
//! > value-tie + node-shortness); inherits their status and cost — the shortness proofs dominate (`bits =
//! > LOG_BASE` in production). A fast unit test exercises the whole relation at `bits = 4`.

use alloc::vec::Vec;

use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_hash::{HashNode, HashParams, LOG_BASE};
use crate::ring_membership::{
    HashStepProof, NodeWitness, commit_node, node_r, prove_hash_step, prove_node_short, verify_hash_step,
    verify_node_short,
};
use crate::ring_shortness::ShortnessProof;
use crate::ring_value_tie::{ValueTieProof, prove_value_tie, verify_value_tie};

/// A zero-knowledge proof that a created output note is well-formed and its hidden amount matches its public value
/// commitment: `cm = hash(value_node, note_owner)` for short `value_node`, `note_owner`, with `value_node` encoding
/// `Cv`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutputProof {
    value_coms: Vec<RingCommitment>, // the hidden value_node (shared by the cm step and the value-tie)
    owner_coms: Vec<RingCommitment>, // the hidden one-time note key
    cm_step: HashStepProof,          // cm = hash(value_node, note_owner) — cm public
    cm_r: Vec<RingRandomness>,       // revealed, ties the committed cm output to the public leaf cm
    value_tie: ValueTieProof,        // value_node ↔ Cv
    value_short: Vec<ShortnessProof>,
    owner_short: Vec<ShortnessProof>,
}

/// A sub-seed `base ‖ tag`.
fn sub(seed: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut s = seed.to_vec();
    s.extend_from_slice(tag);
    s
}

/// Prove a created output: the note commitment `cm = note_hp.hash(value_node, note_owner)` (the new tree leaf) is
/// well-formed, `value_node` and `note_owner` are short (`< 2^bits`; `bits = LOG_BASE` for real nodes), and
/// `value_node` encodes the amount committed by the public value commitment `cv`. `note_owner` is the recipient's
/// **one-time note key** ([`crate::ring_note::NoteScheme::note_owner`], hidden on the ledger). Returns the leaf `cm`
/// (appended to the tree) and the proof.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn prove_output(
    params: &RingParams,
    note_hp: &HashParams,
    cv: &RingCommitment,
    rv: &RingRandomness,
    value_node: &HashNode,
    note_owner: &HashNode,
    bits: usize,
    seed: &[u8],
) -> Option<(HashNode, OutputProof)> {
    let value_r = node_r(seed, "/valnode", 0);
    let owner_r = node_r(seed, "/owner", 0);
    let cm_r = node_r(seed, "/cm", 0); // revealed, so the verifier reconstructs the public leaf's commitment

    let cm = note_hp.hash(value_node, note_owner);
    let value_w = NodeWitness { node: value_node, randomness: &value_r };
    let owner_w = NodeWitness { node: note_owner, randomness: &owner_r };
    let cm_w = NodeWitness { node: &cm, randomness: &cm_r };

    // cm = hash(value_node, note_owner) — value_node left, note_owner right (matching crate::ring_note, so the leaf
    // equals the one the recipient's own note proof reconstructs at spend time).
    let cm_step = prove_hash_step(params, note_hp, &value_w, &owner_w, &cm_w, &sub(seed, b"/cstep"))?;
    let value_tie = prove_value_tie(params, cv, rv, value_node, &value_r, &sub(seed, b"/vtie"))?;
    let value_short = prove_node_short(params, value_node, &value_r, bits, &sub(seed, b"/vshort"))?;
    let owner_short = prove_node_short(params, note_owner, &owner_r, bits, &sub(seed, b"/oshort"))?;

    let value_coms = commit_node(params, value_node, &value_r);
    let owner_coms = commit_node(params, note_owner, &owner_r);
    Some((cm, OutputProof { value_coms, owner_coms, cm_step, cm_r, value_tie, value_short, owner_short }))
}

/// Verify a [`prove_output`] proof against the public value commitment `cv` and the public note commitment `cm`
/// (the leaf appended to the tree). `bits` is the shortness bound the hidden nodes were proven under.
#[must_use]
pub fn verify_output(
    params: &RingParams,
    note_hp: &HashParams,
    cv: &RingCommitment,
    cm: &HashNode,
    bits: usize,
    proof: &OutputProof,
) -> bool {
    // Tie the committed cm output to the public leaf: C_cm = com(cm; cm_r).
    let cm_coms = commit_node(params, cm, &proof.cm_r);
    // cm = hash(value_node, note_owner); value_node ↔ Cv; both hidden nodes short; the leaf is a valid hash node.
    verify_hash_step(params, note_hp, &proof.value_coms, &proof.owner_coms, &cm_coms, &proof.cm_step)
        && verify_value_tie(params, cv, &proof.value_coms, &proof.value_tie)
        && verify_node_short(params, &proof.value_coms, bits, &proof.value_short)
        && verify_node_short(params, &proof.owner_coms, bits, &proof.owner_short)
        // The public leaf is itself a valid short hash output (digits < 2^LOG_BASE, independent of `bits`).
        && cm.limbs().iter().all(|l| l.coeffs().iter().all(|&c| c < (1u64 << LOG_BASE)))
}

impl crate::ring_size::ProofSize for OutputProof {
    fn ring_elements(&self) -> usize {
        self.value_coms.ring_elements() + self.owner_coms.ring_elements() + self.cm_step.ring_elements()
            + self.cm_r.ring_elements()
            + self.value_tie.ring_elements()
            + self.value_short.ring_elements()
            + self.owner_short.ring_elements()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::ring::{D, Poly};
    use crate::ring_hash::ELL_H;

    /// The digit-encoding value node of `v`: limb `d` is `⟨(v >> LOG_BASE·d) & 0xFFFF⟩` as a constant polynomial.
    fn value_node(v: u64) -> HashNode {
        HashNode::from_limbs((0..ELL_H).map(|d| Poly::constant((v >> (LOG_BASE * d as u32)) & 0xFFFF)).collect())
    }

    /// A small node whose limbs have coefficients `< 2^4` — a stand-in note key for the fast (`bits = 4`) test.
    fn small_node(base: u64) -> HashNode {
        let limbs: Vec<Poly> = (0..ELL_H)
            .map(|i| {
                let mut c = [0u64; D];
                c[0] = (base + i as u64) % 16;
                c[1] = (base + 2 * i as u64) % 16;
                Poly::from_u64(&c)
            })
            .collect();
        HashNode::from_limbs(limbs)
    }

    #[test]
    fn a_well_formed_output_proves_and_a_wrong_amount_is_rejected() {
        let params = RingParams::standard();
        let note_hp = HashParams::from_seed(b"FANOS-obolos-v1/note");
        let v = 5u64; // < 2^4, so its single value-node digit is short at bits = 4
        let rv = RingRandomness::from_seed(b"out-rv");
        let cv = RingCommitment::commit(&params, v, &rv);
        let vn = value_node(v); // [5, 0, 0, 0]
        let note_owner = small_node(7); // an artificial (short) one-time note key

        let (cm, proof) = prove_output(&params, &note_hp, &cv, &rv, &vn, &note_owner, 4, b"seed").expect("output");
        assert!(verify_output(&params, &note_hp, &cv, &cm, 4, &proof), "a well-formed output verifies");
        // The self-inflation guard: a value commitment to a DIFFERENT amount than the leaf encodes is rejected —
        // the value-tie relation Σ 2^{16d}·vn_d = value(Cv) is false, so the leaf cannot be balanced at v+1.
        let cv_wrong = RingCommitment::commit(&params, v + 1, &rv);
        assert!(
            !verify_output(&params, &note_hp, &cv_wrong, &cm, 4, &proof),
            "an output leaf cannot be balanced at an amount it does not encode"
        );
    }

    #[test]
    fn a_leaf_from_a_different_note_is_rejected() {
        // The hash-step binds the public leaf: a cm that is not hash(value_node, owner) for the committed nodes
        // has no accepting proof (the recipient could not spend it, and it cannot be conjured to pass here).
        let params = RingParams::standard();
        let note_hp = HashParams::from_seed(b"FANOS-obolos-v1/note");
        let v = 3u64;
        let rv = RingRandomness::from_seed(b"out-rv2");
        let cv = RingCommitment::commit(&params, v, &rv);
        let (cm, proof) = prove_output(&params, &note_hp, &cv, &rv, &value_node(v), &small_node(2), 4, b"seed")
            .expect("output");
        assert!(verify_output(&params, &note_hp, &cv, &cm, 4, &proof), "the true leaf verifies");
        let other = note_hp.hash(&value_node(v), &small_node(9)); // a leaf of a different (note-key) note
        assert!(!verify_output(&params, &note_hp, &cv, &other, 4, &proof), "a leaf of a different note is rejected");
    }
}
