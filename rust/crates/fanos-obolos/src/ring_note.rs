//! The **SIS note-validity proof** — the bridge that ties a note commitment `cm` to *both* the note's value and
//! its owner, in zero knowledge. This is what makes a shielded spend sound across the two privacy halves: the value
//! commitment that [`crate::ring_confidential`] proves balanced-and-in-range and the leaf `cm` that
//! [`crate::ring_untraceable`] proves a tree member (and nullifies) must be the *same note* — otherwise a spender
//! could balance one note's amount while spending another's.
//!
//! ## The ring-native note
//!
//! A note binds a **value node** (the amount, tied to the ring value commitment in the full integration) and an
//! **owner** derived from the secret nullifier key `nsk`, hashed into the leaf commitment with the SIS hash
//! ([`crate::ring_hash`], domain-separated instances):
//!
//! ```text
//! owner = hash_owner(nsk, nsk)          — the owner is a one-way function of nsk (ownership)
//! cm    = hash_note(value, owner)        — the note commitment / tree leaf (binds value ∧ owner)
//! ```
//!
//! Both are `R_q`-linear hash relations, so the proof is two [hash steps](crate::ring_membership::prove_hash_step)
//! plus node-shortness on `nsk`, `value`, and the intermediate `owner`. Knowing `nsk` is what lets the spender
//! reproduce `owner` (hence `cm`, hence the matching nullifier), so this proof *is* the ownership check; composed
//! with membership + nullifier over the same `cm`, and balance/range over the value, it is a complete shielded
//! spend.
//!
//! > **STATUS — [P]/[H], correctness-first.** A composition of the hash step + node-shortness; inherits their
//! > status and cost. The value-node ↔ ring-value-commitment encoding is the remaining integration detail (the
//! > note redesign). Verified by an `#[ignore]`d test (`--ignored`) at real `bits = LOG_BASE`: a well-formed note
//! > proves, and a `cm` not derived from the committed `(value, nsk)` is rejected.

use alloc::vec::Vec;

use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_hash::{HashNode, HashParams, LOG_BASE};
use crate::ring_membership::{
    HashStepProof, NodeWitness, commit_node, node_r, prove_hash_step, prove_node_short, verify_hash_step,
    verify_node_short,
};
use crate::ring_shortness::ShortnessProof;

/// A zero-knowledge proof that a note commitment `cm` is well-formed: `cm = hash(value, hash(nsk, nsk))`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NoteProof {
    owner_coms: Vec<RingCommitment>, // the hidden owner node
    owner_step: HashStepProof,       // owner = hash(nsk, nsk)
    cm_step: HashStepProof,          // cm = hash(value, owner)
    nsk_short: Vec<ShortnessProof>,
    value_short: Vec<ShortnessProof>,
    owner_short: Vec<ShortnessProof>,
}

/// A sub-seed `base ‖ tag`.
fn sub(seed: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut s = seed.to_vec();
    s.extend_from_slice(tag);
    s
}

/// Prove that the note commitment `cm = note_hp.hash(value, owner_hp.hash(nsk, nsk))` for the committed `nsk` and
/// `value`, where `cm` is committed under `cm_r` (shared with the membership proof). Returns the computed `cm`
/// (the tree leaf) and the proof.
#[must_use]
pub fn prove_note(
    params: &RingParams,
    owner_hp: &HashParams,
    note_hp: &HashParams,
    nsk: &NodeWitness<'_>,
    value: &NodeWitness<'_>,
    cm_r: &[RingRandomness],
    seed: &[u8],
) -> Option<(HashNode, NoteProof)> {
    let bits = LOG_BASE as usize;
    let owner = owner_hp.hash(nsk.node, nsk.node);
    let owner_r = node_r(seed, "/owner", 0);
    let owner_w = NodeWitness { node: &owner, randomness: &owner_r };

    let cm = note_hp.hash(value.node, &owner);
    let cm_w = NodeWitness { node: &cm, randomness: cm_r };

    let owner_step = prove_hash_step(params, owner_hp, nsk, nsk, &owner_w, &sub(seed, b"/ostep"))?;
    let cm_step = prove_hash_step(params, note_hp, value, &owner_w, &cm_w, &sub(seed, b"/cstep"))?;
    let nsk_short = prove_node_short(params, nsk.node, nsk.randomness, bits, &sub(seed, b"/nsk"))?;
    let value_short = prove_node_short(params, value.node, value.randomness, bits, &sub(seed, b"/val"))?;
    let owner_short = prove_node_short(params, &owner, &owner_r, bits, &sub(seed, b"/own"))?;

    let owner_coms = commit_node(params, &owner, &owner_r);
    Some((cm, NoteProof { owner_coms, owner_step, cm_step, nsk_short, value_short, owner_short }))
}

/// Verify a [`prove_note`] proof against the public commitments of `cm`, `nsk`, and `value`.
#[must_use]
pub fn verify_note(
    params: &RingParams,
    owner_hp: &HashParams,
    note_hp: &HashParams,
    cm_coms: &[RingCommitment],
    nsk_coms: &[RingCommitment],
    value_coms: &[RingCommitment],
    proof: &NoteProof,
) -> bool {
    let bits = LOG_BASE as usize;
    // owner = hash(nsk, nsk); cm = hash(value, owner).
    verify_hash_step(params, owner_hp, nsk_coms, nsk_coms, &proof.owner_coms, &proof.owner_step)
        && verify_hash_step(params, note_hp, value_coms, &proof.owner_coms, cm_coms, &proof.cm_step)
        && verify_node_short(params, nsk_coms, bits, &proof.nsk_short)
        && verify_node_short(params, value_coms, bits, &proof.value_short)
        && verify_node_short(params, &proof.owner_coms, bits, &proof.owner_short)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "two hash steps + node-shortness at bits=LOG_BASE=16 — a couple of minutes; run with --ignored"]
    fn a_well_formed_note_proves_and_a_mismatched_cm_is_rejected() {
        let params = RingParams::standard();
        let owner_hp = HashParams::from_seed(b"FANOS-obolos-v1/owner");
        let note_hp = HashParams::from_seed(b"FANOS-obolos-v1/note");
        let nsk = HashNode::from_bytes(b"note-nsk");
        let value = HashNode::from_bytes(b"note-value");
        let nsk_r = node_r(b"nsk-r", "/n", 0);
        let value_r = node_r(b"val-r", "/v", 0);
        let cm_r = node_r(b"cm-r", "/c", 0);
        let nsk_w = NodeWitness { node: &nsk, randomness: &nsk_r };
        let value_w = NodeWitness { node: &value, randomness: &value_r };

        let (cm, proof) = prove_note(&params, &owner_hp, &note_hp, &nsk_w, &value_w, &cm_r, b"seed").expect("note");
        let cm_coms = commit_node(&params, &cm, &cm_r);
        let nsk_coms = commit_node(&params, &nsk, &nsk_r);
        let value_coms = commit_node(&params, &value, &value_r);
        assert!(
            verify_note(&params, &owner_hp, &note_hp, &cm_coms, &nsk_coms, &value_coms, &proof),
            "a well-formed note verifies"
        );
        // A cm not derived from (value, nsk) — commit a different node — breaks the cm hash step.
        let other = HashNode::from_bytes(b"note-not-cm");
        let other_coms = commit_node(&params, &other, &cm_r);
        assert!(
            !verify_note(&params, &owner_hp, &note_hp, &other_coms, &nsk_coms, &value_coms, &proof),
            "a cm not derived from (value, nsk) is rejected"
        );
    }
}
