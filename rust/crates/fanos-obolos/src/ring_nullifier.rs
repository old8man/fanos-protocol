//! The **zero-knowledge nullifier proof** — the untraceability spend authorisation. A spend reveals a public
//! **nullifier** `nf` (for double-spend detection) and must prove, in zero knowledge, that it is correctly derived
//! from the spender's secret nullifier key `nsk` and the note commitment `cm` it is spending — *without revealing
//! `nsk` or which `cm`*. Determinism (`nf = f(nsk, cm)`) makes a second spend of the same note produce the same
//! `nf`, so a double-spend is caught; the zero-knowledge derivation keeps the spend unlinkable to the note.
//!
//! In the transparent design `nf = H(nsk ‖ position ‖ cm)` with BLAKE3 — a ZK proof of that is a whole SNARK
//! circuit. The escape is the same as the tree hash: a **SIS-based** nullifier ([`crate::ring_hash`],
//! domain-separated instances) whose relations are `R_q`-**linear**. Because `nf` is *public*, the outer step is
//! precisely a [hash step](crate::ring_membership::prove_hash_step) with a **public output**:
//!
//! ```text
//! slot = hash_slot(cm, pos_node)   (the position-bound note identity — hidden)
//! nf   = hash_nf(nsk, slot)        (the public nullifier)
//! nsk, cm, pos_node, slot short    (node-shortness, so the relations are not forgeable)
//! ```
//!
//! The verifier ties the committed outer output to the public `nf` by a revealed randomness (as the path proof ties
//! its top node to the public root), checks both hash steps over the hidden nodes, and checks each is short. Knowing
//! `nsk` — the only way to produce a matching `nf` — is what authorises the spend (ownership); that `cm` embeds the
//! spender's `nsk`-derived owner is proven by [`crate::ring_note`].
//!
//! ## Why the position is bound in
//!
//! A nullifier of `(nsk, cm)` alone is a function of the note's *contents*, so two notes that happen to share a
//! commitment share a nullifier — and only one of them is ever spendable, the other silently rejected as a
//! double-spend. A fresh per-note `rho` ([`crate::ring_note`]) makes that impossible for an *honest* sender, but a
//! malicious one can deliberately reuse `rho` to grief a recipient. Binding the leaf's **tree position** removes the
//! hazard structurally: every tree slot is unique, so distinct leaves always nullify distinctly, whatever their
//! contents. (This is the ring form of [`crate::nullifier`]'s audit O-M1 property.)
//!
//! The position never becomes public: [`crate::ring_untraceable`] proves `Σ_d 2^{LOG_BASE·d}·pos_node_d = Σ_j 2ʲ·d_j`
//! against the membership path's **already-committed direction bits** — one [`crate::ring_linear`] relation over
//! commitments both halves share, so the slot the nullifier binds is exactly the slot the path proved.
//!
//! > **STATUS — \[P\]/\[H\], correctness-first.** A composition of two hash steps + node-shortness; inherits their
//! > status. Real nodes are `LOG_BASE`-bit short (so `bits = LOG_BASE`); the proof test uses small artificial nodes
//! > at `bits = 4` where it can — note that the intermediate `slot` is a *hash output*, so its bound is always the
//! > gadget base `LOG_BASE`, whatever the caller's `bits`. Verifies a correct nullifier proves, a wrong one is
//! > rejected, a **different position** is rejected, and that the same note at a different position nullifies
//! > differently.

use alloc::vec::Vec;

use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_hash::{ELL_H, HashNode, HashParams, LOG_BASE};
use crate::ring_membership::{
    HashStepProof, NodeWitness, commit_node, prove_hash_step, prove_node_short, verify_hash_step, verify_node_short,
};
use crate::ring_shortness::ShortnessProof;

/// A zero-knowledge proof that a public nullifier `nf = hash_nf(nsk, hash_slot(cm, pos_node))` for hidden short
/// `nsk`, `cm`, and the leaf's position — so the nullifier is bound to the note *and* to its tree slot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NullifierProof {
    slot_coms: Vec<RingCommitment>, // the hidden position-bound note identity
    pos_coms: Vec<RingCommitment>,  // the hidden position node (tied to the path's direction bits by the caller)
    slot_step: HashStepProof,       // slot = hash_slot(cm, pos_node)
    step: HashStepProof,            // nf = hash_nf(nsk, slot) — nf public
    nsk_short: Vec<ShortnessProof>,
    cm_short: Vec<ShortnessProof>,
    pos_short: Vec<ShortnessProof>,
    slot_short: Vec<ShortnessProof>,
    nf_r: Vec<RingRandomness>, // revealed, to tie the committed output to the public nf
}

impl NullifierProof {
    /// The commitments to the hidden **position node**. [`crate::ring_untraceable`] proves these recompose to the
    /// membership path's direction bits, so the slot this nullifier binds is the slot the path proved.
    #[must_use]
    pub fn position_commitment(&self) -> &[RingCommitment] {
        &self.pos_coms
    }
}

/// The **nullifier of a note at a tree position** — `hash_nf(nsk, hash_slot(cm, ⟨position⟩))`. The public value a
/// spend reveals, and what a verifier recomputes; the zero-knowledge proof attests this derivation without revealing
/// `nsk`, `cm`, or the position.
#[must_use]
pub fn nullifier_of(slot_hp: &HashParams, nf_hp: &HashParams, nsk: &HashNode, cm: &HashNode, position: u64) -> HashNode {
    nf_hp.hash(nsk, &slot_hp.hash(cm, &HashNode::from_u64_digits(position)))
}

/// Deterministic randomness for a node's `ELL_H` limbs, domain-separated by `tag`.
fn node_randomness(seed: &[u8], tag: &[u8]) -> Vec<RingRandomness> {
    (0..ELL_H)
        .map(|i| {
            let mut s = seed.to_vec();
            s.extend_from_slice(tag);
            s.extend_from_slice(&(i as u64).to_le_bytes());
            RingRandomness::from_seed(&s)
        })
        .collect()
}

/// The randomness committing the **position node**, derived from the proof seed. `pub(crate)` so the untraceability
/// composition can re-derive it and state the position-tie relation over the very same commitments this proof
/// publishes ([`NullifierProof::position_commitment`]).
#[must_use]
pub(crate) fn position_randomness(seed: &[u8]) -> Vec<RingRandomness> {
    node_randomness(seed, b"/pos")
}

/// A sub-seed `base ‖ tag`.
fn sub(seed: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut s = seed.to_vec();
    s.extend_from_slice(tag);
    s
}

/// Prove that the public nullifier `nf = nullifier_of(…, nsk, cm, position)` is correctly derived from the hidden
/// `nsk`, `cm`, and tree `position` (all `< 2^bits`; `bits = LOG_BASE` for real key/commitment nodes). The position
/// node's commitment randomness is derived from `seed`, and its commitments are exposed by
/// [`NullifierProof::position_commitment`] so the caller can tie them to the membership path's direction bits — which
/// is what makes the binding meaningful (otherwise a prover could pick any position).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn prove_nullifier(
    params: &RingParams,
    slot_hp: &HashParams,
    nf_hp: &HashParams,
    nsk: &NodeWitness<'_>,
    cm: &NodeWitness<'_>,
    position: u64,
    bits: usize,
    seed: &[u8],
) -> Option<NullifierProof> {
    // slot = hash_slot(cm, pos_node) — the position-bound note identity.
    let pos = HashNode::from_u64_digits(position);
    let pos_r = node_randomness(seed, b"/pos");
    let pos_w = NodeWitness { node: &pos, randomness: &pos_r };
    let slot = slot_hp.hash(cm.node, &pos);
    let slot_r = node_randomness(seed, b"/slot");
    let slot_w = NodeWitness { node: &slot, randomness: &slot_r };
    // nf = hash_nf(nsk, slot) — the public nullifier.
    let nf = nf_hp.hash(nsk.node, &slot);
    let nf_r = node_randomness(seed, b"/nf");
    let nf_w = NodeWitness { node: &nf, randomness: &nf_r };

    let slot_step = prove_hash_step(params, slot_hp, cm, &pos_w, &slot_w, &sub(seed, b"/sstep"))?;
    let step = prove_hash_step(params, nf_hp, nsk, &slot_w, &nf_w, &sub(seed, b"/step"))?;
    let nsk_short = prove_node_short(params, nsk.node, nsk.randomness, bits, &sub(seed, b"/nsk"))?;
    let cm_short = prove_node_short(params, cm.node, cm.randomness, bits, &sub(seed, b"/cm"))?;
    let pos_short = prove_node_short(params, &pos, &pos_r, bits, &sub(seed, b"/poss"))?;
    // `slot` is a **hash output**, so its bound is the gadget base — LOG_BASE, not the caller's `bits` (which
    // constrains only the caller-supplied nodes). Its shortness is what makes the outer hash step binding.
    let slot_short = prove_node_short(params, &slot, &slot_r, LOG_BASE as usize, &sub(seed, b"/slots"))?;

    Some(NullifierProof {
        slot_coms: commit_node(params, &slot, &slot_r),
        pos_coms: commit_node(params, &pos, &pos_r),
        slot_step,
        step,
        nsk_short,
        cm_short,
        pos_short,
        slot_short,
        nf_r,
    })
}

/// Verify a [`prove_nullifier`] proof against the public nullifier `nf` and the public commitments of `nsk`, `cm`.
/// The **position tie** is the caller's (it needs the membership path) — see
/// [`NullifierProof::position_commitment`]; without it this attests only that *some* position was used.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn verify_nullifier(
    params: &RingParams,
    slot_hp: &HashParams,
    nf_hp: &HashParams,
    nf: &HashNode,
    nsk_coms: &[RingCommitment],
    cm_coms: &[RingCommitment],
    bits: usize,
    proof: &NullifierProof,
) -> bool {
    // Tie the (committed) outer hash output to the public nullifier: C_nf = com(nf; nf_r).
    let c_nf = commit_node(params, nf, &proof.nf_r);
    // slot = hash(cm, pos); nf = hash(nsk, slot); every hidden node short.
    verify_hash_step(params, slot_hp, cm_coms, &proof.pos_coms, &proof.slot_coms, &proof.slot_step)
        && verify_hash_step(params, nf_hp, nsk_coms, &proof.slot_coms, &c_nf, &proof.step)
        && verify_node_short(params, nsk_coms, bits, &proof.nsk_short)
        && verify_node_short(params, cm_coms, bits, &proof.cm_short)
        && verify_node_short(params, &proof.pos_coms, bits, &proof.pos_short)
        // `slot` is a hash output: bounded by the gadget base, not the caller's `bits` (see prove_nullifier).
        && verify_node_short(params, &proof.slot_coms, LOG_BASE as usize, &proof.slot_short)
        // The public nf is itself a valid short hash output (digits < 2^LOG_BASE).
        && nf.limbs().iter().all(|l| l.coeffs().iter().all(|&c| c < (1u64 << LOG_BASE)))
}

impl crate::ring_size::ProofSize for NullifierProof {
    fn ring_elements(&self) -> usize {
        self.slot_coms.ring_elements() + self.pos_coms.ring_elements() + self.slot_step.ring_elements()
            + self.step.ring_elements()
            + self.nsk_short.ring_elements()
            + self.cm_short.ring_elements()
            + self.pos_short.ring_elements()
            + self.slot_short.ring_elements()
            + self.nf_r.ring_elements()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::ring::{D, Poly};

    /// A small node whose limbs have coefficients `< 2^4` (so `bits = 4` shortness is fast).
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
    fn the_same_note_at_a_different_position_nullifies_differently() {
        // The property position-binding exists for: even two *identical* notes (same cm, same key) nullify
        // distinctly, because their tree slots differ — so a colliding leaf can never lock another out.
        let slot_hp = HashParams::from_seed(b"FANOS-obolos-v1/slot-test");
        let nf_hp = HashParams::from_seed(b"FANOS-obolos-v1/nullifier-test");
        let (nsk, cm) = (small_node(3), small_node(7));
        let nf_at = |p: u64| nullifier_of(&slot_hp, &nf_hp, &nsk, &cm, p);
        assert_ne!(nf_at(0), nf_at(1), "the same note at two slots gives two nullifiers");
        assert_ne!(nf_at(5), nf_at(1 << 20), "distinct across digit boundaries too");
        assert_eq!(nf_at(7), nf_at(7), "and it is deterministic in (nsk, cm, position)");
        // Still keyed: without nsk the nullifier is unobtainable, so it stays unlinkable to the note.
        assert_ne!(nf_at(7), nullifier_of(&slot_hp, &nf_hp, &small_node(9), &cm, 7), "a different key differs");
    }

    #[test]
    #[ignore = "the intermediate slot is a hash output, so one shortness proof is at bits=LOG_BASE — ~2 min; \
                run with --ignored"]
    fn a_correct_nullifier_proves_and_a_wrong_one_is_rejected() {
        let params = RingParams::standard();
        let slot_hp = HashParams::from_seed(b"FANOS-obolos-v1/slot-test");
        let nf_hp = HashParams::from_seed(b"FANOS-obolos-v1/nullifier-test");
        let (nsk, cm) = (small_node(3), small_node(7));
        let nsk_r = node_randomness(b"nsk-seed", b"/r");
        let cm_r = node_randomness(b"cm-seed", b"/r");
        let nsk_w = NodeWitness { node: &nsk, randomness: &nsk_r };
        let cm_w = NodeWitness { node: &cm, randomness: &cm_r };
        let position = 5u64; // < 2^4, so the position node's single digit is short at bits = 4

        let nf = nullifier_of(&slot_hp, &nf_hp, &nsk, &cm, position); // the correct nullifier
        let proof = prove_nullifier(&params, &slot_hp, &nf_hp, &nsk_w, &cm_w, position, 4, b"seed").expect("nf");
        let nsk_coms = commit_node(&params, &nsk, &nsk_r);
        let cm_coms = commit_node(&params, &cm, &cm_r);
        assert!(
            verify_nullifier(&params, &slot_hp, &nf_hp, &nf, &nsk_coms, &cm_coms, 4, &proof),
            "a correctly derived nullifier verifies"
        );
        // The nullifier of the SAME note at a different slot is not this proof's output.
        let other_slot = nullifier_of(&slot_hp, &nf_hp, &nsk, &cm, position + 1);
        assert!(
            !verify_nullifier(&params, &slot_hp, &nf_hp, &other_slot, &nsk_coms, &cm_coms, 4, &proof),
            "a nullifier for a different position is rejected"
        );
        // A different nullifier (hash of the swapped inputs, A₀ ≠ A₁) is not this proof's output either.
        let wrong_nf = nf_hp.hash(&cm, &nsk);
        assert!(
            !verify_nullifier(&params, &slot_hp, &nf_hp, &wrong_nf, &nsk_coms, &cm_coms, 4, &proof),
            "a wrong nullifier is rejected"
        );
    }
}
