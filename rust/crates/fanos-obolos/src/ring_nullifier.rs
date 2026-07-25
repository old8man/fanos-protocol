//! The **zero-knowledge nullifier proof** — the untraceability spend authorisation. A spend reveals a public
//! **nullifier** `nf` (for double-spend detection) and must prove, in zero knowledge, that it is correctly derived
//! from the spender's secret nullifier key `nsk` and the note commitment `cm` it is spending — *without revealing
//! `nsk` or which `cm`*. Determinism (`nf = f(nsk, cm)`) makes a second spend of the same note produce the same
//! `nf`, so a double-spend is caught; the zero-knowledge derivation keeps the spend unlinkable to the note.
//!
//! In the transparent design `nf = H(nsk ‖ cm)` with BLAKE3 — a ZK proof of that is a whole SNARK circuit. The
//! escape is the same as the tree hash: a **SIS-based** nullifier `nf = hash(nsk, cm)` ([`crate::ring_hash`],
//! a domain-separated instance) whose relation is `R_q`-**linear**. Because `nf` is *public*, this is precisely a
//! [hash step](crate::ring_membership::prove_hash_step) with a **public output**:
//!
//! ```text
//! G(nf) = A₀·nsk + A₁·cm        (the linear hash relation, nf public)
//! nsk, cm short                 (node-shortness, so the relation is not forgeable)
//! ```
//!
//! The verifier ties the committed parent to the public `nf` by a revealed randomness (as the path proof ties its
//! top node to the public root), checks the hash step over the hidden `(nsk, cm)`, and checks both are short. Knowing
//! `nsk` — the only way to produce a matching `nf` — is what authorises the spend (ownership); the note-side tie
//! that `cm` embeds the spender's `nsk`-derived owner is the note redesign's job (the integration step).
//!
//! > **STATUS — [P]/[H], correctness-first.** A composition of the hash step + node-shortness; inherits their
//! > status. Real `nsk`/`cm` are `LOG_BASE`-bit short nodes (so `bits = LOG_BASE`); the test uses small artificial
//! > nodes at `bits = 4` to exercise the composition fast. Verifies a correct nullifier proves and a wrong one is
//! > rejected.

use alloc::vec::Vec;

use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_hash::{ELL_H, HashNode, HashParams, LOG_BASE};
use crate::ring_membership::{
    HashStepProof, NodeWitness, commit_node, prove_hash_step, prove_node_short, verify_hash_step, verify_node_short,
};
use crate::ring_shortness::ShortnessProof;

/// A zero-knowledge proof that a public nullifier `nf = hash(nsk, cm)` for hidden short `nsk`, `cm`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NullifierProof {
    step: HashStepProof,
    nsk_short: Vec<ShortnessProof>,
    cm_short: Vec<ShortnessProof>,
    nf_r: Vec<RingRandomness>, // revealed, to tie the committed output to the public nf
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

/// A sub-seed `base ‖ tag`.
fn sub(seed: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut s = seed.to_vec();
    s.extend_from_slice(tag);
    s
}

/// Prove that the public nullifier `nf = nf_hp.hash(nsk, cm)` is correctly derived from the hidden `nsk` and `cm`
/// (both `< 2^bits`; `bits = LOG_BASE` for real key/commitment nodes). The caller obtains `nf` as
/// `nf_hp.hash(nsk.node, cm.node)`.
#[must_use]
pub fn prove_nullifier(
    params: &RingParams,
    nf_hp: &HashParams,
    nsk: &NodeWitness<'_>,
    cm: &NodeWitness<'_>,
    bits: usize,
    seed: &[u8],
) -> Option<NullifierProof> {
    let nf = nf_hp.hash(nsk.node, cm.node);
    let nf_r = node_randomness(seed, b"/nf");
    let nf_w = NodeWitness { node: &nf, randomness: &nf_r };
    let step = prove_hash_step(params, nf_hp, nsk, cm, &nf_w, &sub(seed, b"/step"))?;
    let nsk_short = prove_node_short(params, nsk.node, nsk.randomness, bits, &sub(seed, b"/nsk"))?;
    let cm_short = prove_node_short(params, cm.node, cm.randomness, bits, &sub(seed, b"/cm"))?;
    Some(NullifierProof { step, nsk_short, cm_short, nf_r })
}

/// Verify a [`prove_nullifier`] proof against the public nullifier `nf` and the public commitments of `nsk`, `cm`.
#[must_use]
pub fn verify_nullifier(
    params: &RingParams,
    nf_hp: &HashParams,
    nf: &HashNode,
    nsk_coms: &[RingCommitment],
    cm_coms: &[RingCommitment],
    bits: usize,
    proof: &NullifierProof,
) -> bool {
    // Tie the (committed) hash output to the public nullifier: C_nf = com(nf; nf_r).
    let c_nf = commit_node(params, nf, &proof.nf_r);
    // The linear hash relation nf = hash(nsk, cm), and that nsk, cm are short.
    verify_hash_step(params, nf_hp, nsk_coms, cm_coms, &c_nf, &proof.step)
        && verify_node_short(params, nsk_coms, bits, &proof.nsk_short)
        && verify_node_short(params, cm_coms, bits, &proof.cm_short)
        // The public nf is itself a valid short hash output (digits < 2^LOG_BASE).
        && nf.limbs().iter().all(|l| l.coeffs().iter().all(|&c| c < (1u64 << LOG_BASE)))
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
    fn a_correct_nullifier_proves_and_a_wrong_one_is_rejected() {
        let params = RingParams::standard();
        let nf_hp = HashParams::from_seed(b"FANOS-obolos-v1/nullifier-test");
        let (nsk, cm) = (small_node(3), small_node(7));
        let nsk_r = node_randomness(b"nsk-seed", b"/r");
        let cm_r = node_randomness(b"cm-seed", b"/r");
        let nsk_w = NodeWitness { node: &nsk, randomness: &nsk_r };
        let cm_w = NodeWitness { node: &cm, randomness: &cm_r };

        let nf = nf_hp.hash(&nsk, &cm); // the correct nullifier
        let proof = prove_nullifier(&params, &nf_hp, &nsk_w, &cm_w, 4, b"seed").expect("nullifier");
        let nsk_coms = commit_node(&params, &nsk, &nsk_r);
        let cm_coms = commit_node(&params, &cm, &cm_r);
        assert!(
            verify_nullifier(&params, &nf_hp, &nf, &nsk_coms, &cm_coms, 4, &proof),
            "a correctly derived nullifier verifies"
        );
        // A different nullifier (hash of the swapped inputs, A₀ ≠ A₁) is not this proof's output.
        let wrong_nf = nf_hp.hash(&cm, &nsk);
        assert!(
            !verify_nullifier(&params, &nf_hp, &wrong_nf, &nsk_coms, &cm_coms, 4, &proof),
            "a wrong nullifier is rejected"
        );
    }
}
