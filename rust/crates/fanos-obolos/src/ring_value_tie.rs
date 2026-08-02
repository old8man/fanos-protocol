//! The **value-node ↔ value-commitment tie** — the last soundness linkage of a shielded spend. The note binds a
//! `value_node` (a SIS node, part of the leaf `cm` via [`crate::ring_note`]); the amount is *also* carried by a
//! ring value commitment `Cv = ring_commit(v; rv)` that [`crate::ring_confidential`] proves balanced and in range.
//! This proof shows the two carry the **same** `v`, so a spender cannot balance one amount while its note commits
//! another.
//!
//! ## Construction
//!
//! Encode the amount in the note as its base-`2^{LOG_BASE}` digits, one per node limb:
//! `value_node.limbs[d] = ⟨digit d of v⟩`, so `v = Σ_d 2^{LOG_BASE·d}·value_node.limbs[d]`. The value commitment is
//! `Cv = (t0, t1)` with `t0 = A₁·rv`, `t1 = ⟨a₂, rv⟩ + v`. Both are `R_q`-**linear** in the hidden `(rv, value_node)`
//! and the public `Cv`, so the tie is a bundle of [`crate::ring_linear`] relations:
//!
//! ```text
//! t0_k = Σ_j A₁_{kj}·rv_j            (K relations — binds rv to Cv)
//! t1   = Σ_j a₂_j·rv_j + Σ_d 2^{LOG_BASE·d}·value_node_d      (1 relation — binds v across Cv and the note)
//! ```
//!
//! `Cv`'s components enter as zero-randomness commitments (`Cv` is public); `rv` is committed once and reused
//! across all relations. Because these are linear (no shortness), the whole tie is **fast** — no `#[ignore]`.
//!
//! > **STATUS — \[P\]/\[H\], correctness-first.** Reduces to [`crate::ring_linear`]; inherits its status. Tests: a
//! > matching `value_node`/`Cv` proves; a `value_node` encoding a different amount than `Cv` is rejected.

use alloc::vec::Vec;

use crate::ring::Poly;
use crate::ring_commit::{ELL, RingCommitment, RingParams, RingRandomness};
use crate::ring_hash::{HashNode, digit_weights};
use crate::ring_linear::{LinearProof, prove_linear, verify_linear};
use crate::ring_membership::commit_node;

/// A zero-knowledge proof that a note's `value_node` and a value commitment `Cv` carry the same amount.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValueTieProof {
    rv_coms: Vec<RingCommitment>, // ELL commitments to Cv's randomness components
    t0_rels: Vec<LinearProof>,    // K relations: t0_k = Σ A₁_{kj} rv_j
    t1_rel: LinearProof,          // 1 relation: t1 = ⟨a₂, rv⟩ + Σ 2^{16d} value_node_d
}

/// `−1` as a constant ring element.
fn neg_one() -> Poly {
    Poly::zero().sub(&Poly::constant(1))
}

/// The `ELL`-vector of all-zero randomness — commits a *public* value (`Cv`'s components) with no hiding.
fn zero_r() -> RingRandomness {
    RingRandomness::from_components(alloc::vec![Poly::zero(); ELL])
}

/// A sub-seed `base ‖ tag ‖ index`.
fn sub(base: &[u8], tag: &[u8], index: usize) -> Vec<u8> {
    let mut s = base.to_vec();
    s.extend_from_slice(tag);
    s.extend_from_slice(&(index as u64).to_le_bytes());
    s
}

/// Prove that `value_node` encodes the amount committed by `cv = ring_commit(v; rv)`. `value_node.limbs[d]` must be
/// the `d`-th base-`2^{LOG_BASE}` digit of `v` (as a constant polynomial). `value_node_r` are the commitments'
/// randomness (shared with the note proof).
#[must_use]
pub fn prove_value_tie(
    params: &RingParams,
    cv: &RingCommitment,
    rv: &RingRandomness,
    value_node: &HashNode,
    value_node_r: &[RingRandomness],
    seed: &[u8],
) -> Option<ValueTieProof> {
    let z = zero_r();
    // Commit Cv's randomness components (reused across all relations).
    let rho: Vec<RingRandomness> =
        (0..ELL).map(|j| RingRandomness::from_seed(&sub(seed, b"/rho", j))).collect();
    let rv_coms: Vec<RingCommitment> = rv
        .components()
        .iter()
        .zip(&rho)
        .map(|(rvj, rj)| RingCommitment::commit_message(params, rvj, rj))
        .collect();

    // t0_k = Σ_j A₁_{kj} rv_j  ⇔  Σ_j A₁_{kj} rv_j − t0_k = 0.
    let mut t0_rels = Vec::with_capacity(cv.t0().len());
    for (k, t0k) in cv.t0().iter().enumerate() {
        let mut messages = rv.components().to_vec();
        messages.push(t0k.clone());
        let mut coeffs = params.a1_row(k).to_vec();
        coeffs.push(neg_one());
        let mut commitments = rv_coms.clone();
        commitments.push(RingCommitment::commit_message(params, t0k, &z));
        let mut randomness = rho.clone();
        randomness.push(z.clone());
        t0_rels.push(prove_linear(params, &commitments, &coeffs, &messages, &randomness, &sub(seed, b"/t0", k))?);
    }

    // t1 = Σ_j a₂_j rv_j + Σ_d 2^{16d} value_node_d  ⇔  Σ a₂_j rv_j + Σ 2^{16d} vn_d − t1 = 0.
    let t1 = cv.t1();
    let value_coms = commit_node(params, value_node, value_node_r);
    let mut messages = rv.components().to_vec();
    messages.extend(value_node.limbs().iter().cloned());
    messages.push(t1.clone());
    let mut coeffs = params.a2().to_vec();
    coeffs.extend(digit_weights());
    coeffs.push(neg_one());
    let mut commitments = rv_coms.clone();
    commitments.extend(value_coms);
    commitments.push(RingCommitment::commit_message(params, t1, &z));
    let mut randomness = rho;
    randomness.extend(value_node_r.iter().cloned());
    randomness.push(z);
    let t1_rel = prove_linear(params, &commitments, &coeffs, &messages, &randomness, &sub(seed, b"/t1", 0))?;

    Some(ValueTieProof { rv_coms, t0_rels, t1_rel })
}

/// Verify a [`prove_value_tie`] proof against the public `cv` and the note's `value_coms` (its `value_node`
/// limb commitments).
#[must_use]
pub fn verify_value_tie(
    params: &RingParams,
    cv: &RingCommitment,
    value_coms: &[RingCommitment],
    proof: &ValueTieProof,
) -> bool {
    let z = zero_r();
    if proof.t0_rels.len() != cv.t0().len() {
        return false;
    }
    for ((k, t0k), rel) in cv.t0().iter().enumerate().zip(&proof.t0_rels) {
        let mut coeffs = params.a1_row(k).to_vec();
        coeffs.push(neg_one());
        let mut commitments = proof.rv_coms.clone();
        commitments.push(RingCommitment::commit_message(params, t0k, &z));
        if !verify_linear(params, &commitments, &coeffs, rel) {
            return false;
        }
    }
    let mut coeffs = params.a2().to_vec();
    coeffs.extend(digit_weights());
    coeffs.push(neg_one());
    let mut commitments = proof.rv_coms.clone();
    commitments.extend(value_coms.iter().cloned());
    commitments.push(RingCommitment::commit_message(params, cv.t1(), &z));
    verify_linear(params, &commitments, &coeffs, &proof.t1_rel)
}

impl crate::ring_size::ProofSize for ValueTieProof {
    fn ring_elements(&self) -> usize {
        self.rv_coms.ring_elements() + self.t0_rels.ring_elements() + self.t1_rel.ring_elements()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ring_membership::node_r;

    /// The digit-encoding node of `v` — the canonical integer-into-node encoding.
    fn value_node(v: u64) -> HashNode {
        HashNode::from_u64_digits(v)
    }

    #[test]
    fn a_matching_value_node_and_commitment_tie() {
        let params = RingParams::standard();
        let v = 1_000_000u64;
        let rv = RingRandomness::from_seed(b"vt-rv");
        let cv = RingCommitment::commit(&params, v, &rv);
        let vn = value_node(v);
        let vn_r = node_r(b"vt-vnr", "/v", 0);
        let proof = prove_value_tie(&params, &cv, &rv, &vn, &vn_r, b"seed").expect("tie");
        let value_coms = commit_node(&params, &vn, &vn_r);
        assert!(verify_value_tie(&params, &cv, &value_coms, &proof), "value_node encodes Cv's amount");
    }

    #[test]
    fn a_value_node_of_a_different_amount_is_rejected() {
        // Cv commits v, but the value_node encodes v+1: the t1 relation Σ2^{16d}vn_d = v is false.
        let params = RingParams::standard();
        let v = 500_000u64;
        let rv = RingRandomness::from_seed(b"vt-rv2");
        let cv = RingCommitment::commit(&params, v, &rv);
        let vn = value_node(v + 1); // wrong amount
        let vn_r = node_r(b"vt-vnr2", "/v", 0);
        let proof = prove_value_tie(&params, &cv, &rv, &vn, &vn_r, b"seed").expect("proof emitted");
        let value_coms = commit_node(&params, &vn, &vn_r);
        assert!(!verify_value_tie(&params, &cv, &value_coms, &proof), "a mismatched amount is rejected");
    }
}
