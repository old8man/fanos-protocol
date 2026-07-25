//! The **SIS note-validity proof** — the bridge that ties a note commitment `cm` to *both* the note's value and
//! its owner, in zero knowledge. This is what makes a shielded spend sound across the two privacy halves: the value
//! commitment that [`crate::ring_confidential`] proves balanced-and-in-range and the leaf `cm` that
//! [`crate::ring_untraceable`] proves a tree member (and nullifies) must be the *same note* — otherwise a spender
//! could balance one note's amount while spending another's.
//!
//! ## The ring-native note
//!
//! A note binds a **value node** (the amount, tied to the ring value commitment by [`crate::ring_value_tie`]) and a
//! **one-time note key** derived from the recipient's secret nullifier key `nsk` *and* a fresh per-note `rho`,
//! hashed into the leaf commitment with the SIS hash ([`crate::ring_hash`], domain-separated instances):
//!
//! ```text
//! tag        = hash_owner(nsk, nsk)      — the owner tag: a one-way function of nsk (ownership)
//! note_owner = hash_rho(tag, rho)        — the ONE-TIME note key: fresh per note (uniqueness ∧ unlinkability)
//! cm         = hash_note(value, note_owner)   — the note commitment / tree leaf
//! ```
//!
//! ### Why `rho` is load-bearing, not decoration
//!
//! Without it the leaf would be `hash(value, tag)` — deterministic in *(amount, recipient)* — so two payments of
//! the same amount to the same recipient would produce the **identical leaf**. Two failures follow, and `rho`
//! closes both (it is the ring-native form of the [`crate::note`] `rho`, and of the *one-time key* a stealth
//! address supplies):
//!
//! - **privacy**: leaf equality is public on the tree, so an observer would learn "these two outputs are the same
//!   amount to the same recipient" — from opaque commitments that are meant to leak nothing;
//! - **spendability**: an identical `cm` would give an identical nullifier, so the second note would be rejected as
//!   a double-spend — value silently destroyed. A fresh `rho` per note means honest notes never collide; the
//!   **position-bound** nullifier ([`crate::ring_nullifier`]) then removes the hazard entirely, since every tree
//!   slot is unique even if two leaves are not (audit O-M1 in ring form).
//!
//! All three relations are `R_q`-linear, so the proof is three [hash steps](crate::ring_membership::prove_hash_step)
//! plus node-shortness on `nsk`, `value`, `rho`, and the two intermediates. Knowing `nsk` *and* `rho` is what lets
//! the spender reproduce `note_owner` (hence `cm`, hence the matching nullifier) — so this proof *is* the ownership
//! check; `rho` reaches the recipient out of band with the note's opening (as [`crate::note_cipher`] delivers it).
//! Composed with membership + nullifier over the same `cm`, and balance/range over the value, it is a complete
//! shielded spend.
//!
//! > **STATUS — [P]/[H], correctness-first.** A composition of the hash step + node-shortness; inherits their
//! > status and cost. Verified by an `#[ignore]`d test (`--ignored`) at real `bits = LOG_BASE`: a well-formed note
//! > proves, and a `cm` not derived from the committed `(value, nsk, rho)` is rejected — plus a fast test that two
//! > notes differing only in `rho` yield **distinct** leaves (the uniqueness property above).

use alloc::vec::Vec;

use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_hash::{HashNode, HashParams, LOG_BASE};
use crate::ring_membership::{
    HashStepProof, NodeWitness, commit_node, node_r, prove_hash_step, prove_node_short, verify_hash_step,
    verify_node_short,
};
use crate::ring_shortness::ShortnessProof;

/// The domain-separated SIS hash instances a **note** is built from — the note's own scheme, which a spend
/// ([`crate::ring_input::SpendScheme`]) extends with the tree and nullifier hashes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NoteScheme {
    /// The owner-tag hash `tag = hash(nsk, nsk)`.
    pub owner_hp: HashParams,
    /// The one-time-key hash `note_owner = hash(tag, rho)`.
    pub rho_hp: HashParams,
    /// The note-commitment hash `cm = hash(value, note_owner)`.
    pub note_hp: HashParams,
}

impl NoteScheme {
    /// The canonical note hashes (domain-separated instances of the ring hash).
    #[must_use]
    pub fn standard() -> Self {
        Self {
            owner_hp: HashParams::from_seed(b"FANOS-obolos-v1/owner"),
            rho_hp: HashParams::from_seed(b"FANOS-obolos-v1/note-rho"),
            note_hp: HashParams::from_seed(b"FANOS-obolos-v1/note"),
        }
    }

    /// The **one-time note key** `note_owner = hash_rho(tag, rho)` a sender computes for a recipient's owner `tag`
    /// and the fresh `rho` it will deliver with the note — the value [`crate::ring_output`] binds into the leaf.
    #[must_use]
    pub fn note_owner(&self, tag: &HashNode, rho: &HashNode) -> HashNode {
        self.rho_hp.hash(tag, rho)
    }
}

/// A zero-knowledge proof that a note commitment `cm` is well-formed:
/// `cm = hash(value, hash(hash(nsk, nsk), rho))` — the value, the owner, and the note's uniqueness, all bound.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NoteProof {
    tag_coms: Vec<RingCommitment>,        // the hidden owner tag = hash(nsk, nsk)
    note_owner_coms: Vec<RingCommitment>, // the hidden one-time note key = hash(tag, rho)
    rho_coms: Vec<RingCommitment>,        // the hidden per-note uniqueness randomness
    tag_step: HashStepProof,              // tag = hash(nsk, nsk)
    owner_step: HashStepProof,            // note_owner = hash(tag, rho)
    cm_step: HashStepProof,               // cm = hash(value, note_owner)
    nsk_short: Vec<ShortnessProof>,
    value_short: Vec<ShortnessProof>,
    rho_short: Vec<ShortnessProof>,
    tag_short: Vec<ShortnessProof>,
    owner_short: Vec<ShortnessProof>,
}

/// A sub-seed `base ‖ tag`.
fn sub(seed: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut s = seed.to_vec();
    s.extend_from_slice(tag);
    s
}

/// Prove that the note commitment `cm = hash_note(value, hash_rho(hash_owner(nsk, nsk), rho))` for the committed
/// `nsk` and `value` and the note's `rho`, where `cm` is committed under `cm_r` (shared with the membership proof).
/// `rho` is a fully hidden witness (its commitment randomness is derived from `seed`), so it need only be a short
/// node. Returns the computed `cm` (the tree leaf) and the proof.
#[must_use]
pub fn prove_note(
    params: &RingParams,
    scheme: &NoteScheme,
    nsk: &NodeWitness<'_>,
    value: &NodeWitness<'_>,
    rho: &HashNode,
    cm_r: &[RingRandomness],
    seed: &[u8],
) -> Option<(HashNode, NoteProof)> {
    let bits = LOG_BASE as usize;
    // tag = hash(nsk, nsk) — ownership.
    let tag = scheme.owner_hp.hash(nsk.node, nsk.node);
    let tag_r = node_r(seed, "/tag", 0);
    let tag_w = NodeWitness { node: &tag, randomness: &tag_r };
    // note_owner = hash(tag, rho) — the one-time note key (uniqueness).
    let rho_r = node_r(seed, "/rho", 0);
    let rho_w = NodeWitness { node: rho, randomness: &rho_r };
    let note_owner = scheme.note_owner(&tag, rho);
    let owner_r = node_r(seed, "/owner", 0);
    let owner_w = NodeWitness { node: &note_owner, randomness: &owner_r };
    // cm = hash(value, note_owner) — the tree leaf.
    let cm = scheme.note_hp.hash(value.node, &note_owner);
    let cm_w = NodeWitness { node: &cm, randomness: cm_r };

    let tag_step = prove_hash_step(params, &scheme.owner_hp, nsk, nsk, &tag_w, &sub(seed, b"/tstep"))?;
    let owner_step = prove_hash_step(params, &scheme.rho_hp, &tag_w, &rho_w, &owner_w, &sub(seed, b"/ostep"))?;
    let cm_step = prove_hash_step(params, &scheme.note_hp, value, &owner_w, &cm_w, &sub(seed, b"/cstep"))?;
    let nsk_short = prove_node_short(params, nsk.node, nsk.randomness, bits, &sub(seed, b"/nsk"))?;
    let value_short = prove_node_short(params, value.node, value.randomness, bits, &sub(seed, b"/val"))?;
    let rho_short = prove_node_short(params, rho, &rho_r, bits, &sub(seed, b"/rhos"))?;
    let tag_short = prove_node_short(params, &tag, &tag_r, bits, &sub(seed, b"/tags"))?;
    let owner_short = prove_node_short(params, &note_owner, &owner_r, bits, &sub(seed, b"/own"))?;

    let proof = NoteProof {
        tag_coms: commit_node(params, &tag, &tag_r),
        note_owner_coms: commit_node(params, &note_owner, &owner_r),
        rho_coms: commit_node(params, rho, &rho_r),
        tag_step,
        owner_step,
        cm_step,
        nsk_short,
        value_short,
        rho_short,
        tag_short,
        owner_short,
    };
    Some((cm, proof))
}

/// Verify a [`prove_note`] proof against the public commitments of `cm`, `nsk`, and `value`. (`rho` and the two
/// intermediate nodes are hidden witnesses carried by the proof itself.)
#[must_use]
pub fn verify_note(
    params: &RingParams,
    scheme: &NoteScheme,
    cm_coms: &[RingCommitment],
    nsk_coms: &[RingCommitment],
    value_coms: &[RingCommitment],
    proof: &NoteProof,
) -> bool {
    let bits = LOG_BASE as usize;
    // tag = hash(nsk, nsk); note_owner = hash(tag, rho); cm = hash(value, note_owner).
    verify_hash_step(params, &scheme.owner_hp, nsk_coms, nsk_coms, &proof.tag_coms, &proof.tag_step)
        && verify_hash_step(
            params,
            &scheme.rho_hp,
            &proof.tag_coms,
            &proof.rho_coms,
            &proof.note_owner_coms,
            &proof.owner_step,
        )
        && verify_hash_step(params, &scheme.note_hp, value_coms, &proof.note_owner_coms, cm_coms, &proof.cm_step)
        && verify_node_short(params, nsk_coms, bits, &proof.nsk_short)
        && verify_node_short(params, value_coms, bits, &proof.value_short)
        && verify_node_short(params, &proof.rho_coms, bits, &proof.rho_short)
        && verify_node_short(params, &proof.tag_coms, bits, &proof.tag_short)
        && verify_node_short(params, &proof.note_owner_coms, bits, &proof.owner_short)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rho_makes_every_note_leaf_unique() {
        // The property `rho` exists for: two notes identical in amount AND recipient still get DISTINCT leaves.
        // Without it the leaf would be hash(value, tag) — equal for repeat payments — which both leaks the
        // repetition (leaf equality is public) and collides their nullifiers (destroying the second note).
        let scheme = NoteScheme::standard();
        let nsk = HashNode::from_bytes(b"uniq-nsk");
        let value = HashNode::from_bytes(b"uniq-value"); // the same amount…
        let tag = scheme.owner_hp.hash(&nsk, &nsk); // …to the same recipient
        let leaf = |rho: &HashNode| scheme.note_hp.hash(&value, &scheme.note_owner(&tag, rho));
        let (rho_a, rho_b) = (HashNode::from_bytes(b"rho-a"), HashNode::from_bytes(b"rho-b"));
        assert_ne!(leaf(&rho_a), leaf(&rho_b), "notes differing only in rho have distinct leaves");
        assert_eq!(leaf(&rho_a), leaf(&rho_a), "and the leaf is deterministic in (value, tag, rho)");
        // The one-time key itself is fresh per note — so nothing about the recipient repeats on the ledger.
        assert_ne!(scheme.note_owner(&tag, &rho_a), scheme.note_owner(&tag, &rho_b), "the note key is one-time");
        assert_ne!(scheme.note_owner(&tag, &rho_a), tag, "and it is never the bare owner tag");
    }

    #[test]
    #[ignore = "three hash steps + node-shortness at bits=LOG_BASE=16 — a couple of minutes; run with --ignored"]
    fn a_well_formed_note_proves_and_a_mismatched_cm_is_rejected() {
        let params = RingParams::standard();
        let scheme = NoteScheme::standard();
        let nsk = HashNode::from_bytes(b"note-nsk");
        let value = HashNode::from_bytes(b"note-value");
        let rho = HashNode::from_bytes(b"note-rho");
        let nsk_r = node_r(b"nsk-r", "/n", 0);
        let value_r = node_r(b"val-r", "/v", 0);
        let cm_r = node_r(b"cm-r", "/c", 0);
        let nsk_w = NodeWitness { node: &nsk, randomness: &nsk_r };
        let value_w = NodeWitness { node: &value, randomness: &value_r };

        let (cm, proof) = prove_note(&params, &scheme, &nsk_w, &value_w, &rho, &cm_r, b"seed").expect("note");
        let cm_coms = commit_node(&params, &cm, &cm_r);
        let nsk_coms = commit_node(&params, &nsk, &nsk_r);
        let value_coms = commit_node(&params, &value, &value_r);
        assert!(verify_note(&params, &scheme, &cm_coms, &nsk_coms, &value_coms, &proof), "a well-formed note verifies");
        // A cm not derived from (value, nsk, rho) — commit a different node — breaks the cm hash step.
        let other = HashNode::from_bytes(b"note-not-cm");
        let other_coms = commit_node(&params, &other, &cm_r);
        assert!(
            !verify_note(&params, &scheme, &other_coms, &nsk_coms, &value_coms, &proof),
            "a cm not derived from (value, nsk, rho) is rejected"
        );
    }
}
