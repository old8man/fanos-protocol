//! **Zero-knowledge Merkle membership** over the SIS tree — the untraceability proof a spend attaches to show its
//! note is a leaf under the public anchor *without revealing which leaf*. This module builds it bottom-up; the
//! first piece is the **hash step**: a zero-knowledge proof that committed nodes `(left, right, parent)` satisfy
//! `parent = hash(left, right)` ([`crate::ring_hash`]).
//!
//! Because the SIS hash relation is `R_q`-linear — `G(parent) = A₀·left + A₁·right`, i.e.
//! `A₀·left + A₁·right − G(parent) = 0` — a hash step is exactly one [`crate::ring_linear`] proof over the
//! concatenated limbs `left ‖ right ‖ parent` with the coefficients [`HashParams::step_coeffs`]. A full path
//! proof (the next increment) *chains* hash steps — the parent commitments of level `j` are the child commitments
//! of level `j+1` — up to the public root, with a conditional swap per level so the position stays hidden.
//!
//! > **SOUNDNESS SCOPE — the linear core.** This proves the *linear* hash relation in zero knowledge. A complete
//! > membership proof additionally needs each node proven **short** (limbs `< 2^{LOG_BASE}`) — otherwise a prover
//! > could satisfy the linear system with non-short "nodes" and forge a path. That shortness is a
//! > [`crate::ring_range_agg`] proof per limb; it is deferred because, unaggregated, it is `O(ELL_H·LOG_BASE)` per
//! > node — the **range-proof aggregation** is the prerequisite that makes the whole path proof practical. The
//! > linear step here is correct and composes with those shortness proofs once aggregated.
//!
//! > **STATUS — [P]/[H], correctness-first.** Tests verify a genuine hash step proves and verifies, and that a
//! > wrong parent (or swapped children) has no accepting proof.

use alloc::vec::Vec;

use crate::ring::Poly;
use crate::ring_binary::{BinaryProof, prove_binary, verify_binary};
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_hash::{HashNode, HashParams};
use crate::ring_linear::{LinearProof, prove_linear, verify_linear};
use crate::ring_product::{ProductProof, ProductWitness, prove_product, verify_product};

/// A node together with the randomness committing each of its limbs — the secret witness of one tree node.
pub struct NodeWitness<'a> {
    /// The node value.
    pub node: &'a HashNode,
    /// One randomness per limb (same length as the node's limbs).
    pub randomness: &'a [RingRandomness],
}

/// Commit each limb of `node` under the matching randomness — the public commitment of a tree node.
#[must_use]
pub fn commit_node(params: &RingParams, node: &HashNode, randomness: &[RingRandomness]) -> Vec<RingCommitment> {
    node.limbs()
        .iter()
        .zip(randomness)
        .map(|(limb, r)| RingCommitment::commit_message(params, limb, r))
        .collect()
}

/// A zero-knowledge proof of one hash step `parent = hash(left, right)` (its linear relation).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashStepProof(LinearProof);

/// The concatenated limb messages `left ‖ right ‖ parent`.
fn concat_messages(left: &HashNode, right: &HashNode, parent: &HashNode) -> Vec<Poly> {
    left.limbs().iter().chain(right.limbs()).chain(parent.limbs()).cloned().collect()
}

/// Prove, in zero knowledge, that the committed nodes satisfy `parent = hash(left, right)` — the SIS hash's linear
/// relation `A₀·left + A₁·right = G(parent)` over the concatenated limbs.
#[must_use]
pub fn prove_hash_step(
    params: &RingParams,
    hp: &HashParams,
    left: &NodeWitness<'_>,
    right: &NodeWitness<'_>,
    parent: &NodeWitness<'_>,
    seed: &[u8],
) -> Option<HashStepProof> {
    let messages = concat_messages(left.node, right.node, parent.node);
    let randomness: Vec<RingRandomness> =
        left.randomness.iter().chain(right.randomness).chain(parent.randomness).cloned().collect();
    let commitments: Vec<RingCommitment> =
        messages.iter().zip(&randomness).map(|(m, r)| RingCommitment::commit_message(params, m, r)).collect();
    prove_linear(params, &commitments, &hp.step_coeffs(), &messages, &randomness, seed).map(HashStepProof)
}

/// Verify a [`prove_hash_step`] proof against the public limb commitments of the three nodes (each a
/// [`commit_node`] output).
#[must_use]
pub fn verify_hash_step(
    params: &RingParams,
    hp: &HashParams,
    left: &[RingCommitment],
    right: &[RingCommitment],
    parent: &[RingCommitment],
    proof: &HashStepProof,
) -> bool {
    let commitments: Vec<RingCommitment> = left.iter().chain(right).chain(parent).cloned().collect();
    verify_linear(params, &commitments, &hp.step_coeffs(), &proof.0)
}

/// A zero-knowledge proof of one **position-hiding conditional swap**: that committed `left` is the correct
/// selection between `child` and `sibling` under a hidden bit `d` — `left = child + d·(sibling − child)` — with
/// `right = child + sibling − left` derived. This hides *which side* the spender's node sits on at a tree level,
/// so the path proof leaks no position (hence no note identity).
///
/// Per limb it is a [`ring_product`](crate::ring_product) proof `left_i − child_i = d·(sibling_i − child_i)` (with
/// `d` a constant polynomial, so the ring product is coefficient-wise scalar multiplication), plus a
/// [`ring_binary`](crate::ring_binary) proof that `d ∈ {0,1}`.
///
/// > **SOUNDNESS SCOPE.** `d` must act as a *scalar* (constant polynomial) consistently across limbs. A non-constant
/// > `d` turns `d·(sibling − child)` into a convolution whose result is generally *not short*, so the node
/// > **shortness** proofs (part of a complete path proof) reject it — this proof relies on that rather than proving
/// > `d` constant directly.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SwapProof {
    bit: BinaryProof,
    limbs: Vec<ProductProof>, // one per node limb
}

/// Prove the conditional swap: `left = child + d·(sibling − child)` with `d ∈ {0,1}` (a constant polynomial).
#[must_use]
pub fn prove_swap(
    params: &RingParams,
    child: &NodeWitness<'_>,
    sibling: &NodeWitness<'_>,
    left: &NodeWitness<'_>,
    d: &Poly,
    r_d: &RingRandomness,
    seed: &[u8],
) -> Option<SwapProof> {
    let mut bseed = seed.to_vec();
    bseed.extend_from_slice(b"/dbit");
    let bit = prove_binary(params, d, r_d, &bseed)?;

    let child_it = child.node.limbs().iter().zip(child.randomness);
    let sib_it = sibling.node.limbs().iter().zip(sibling.randomness);
    let left_it = left.node.limbs().iter().zip(left.randomness);
    let mut limbs = Vec::with_capacity(child.node.limbs().len());
    for (i, (((cl, cr), (sl, sr)), (ll, lr))) in child_it.zip(sib_it).zip(left_it).enumerate() {
        let y = sl.sub(cl); // sibling_i − child_i
        let z = ll.sub(cl); // left_i − child_i
        let ry = sr.sub(cr);
        let rz = lr.sub(cr);
        let witness = ProductWitness { x: d, rx: r_d, y: &y, ry: &ry, z: &z, rz: &rz };
        let mut pseed = seed.to_vec();
        pseed.extend_from_slice(b"/swap/");
        pseed.extend_from_slice(&(i as u64).to_le_bytes());
        limbs.push(prove_product(params, &witness, &pseed)?);
    }
    Some(SwapProof { bit, limbs })
}

/// Verify a [`prove_swap`] proof against the public limb commitments of the three nodes and the bit commitment.
#[must_use]
pub fn verify_swap(
    params: &RingParams,
    child: &[RingCommitment],
    sibling: &[RingCommitment],
    left: &[RingCommitment],
    d_com: &RingCommitment,
    proof: &SwapProof,
) -> bool {
    let n = child.len();
    if sibling.len() != n || left.len() != n || proof.limbs.len() != n {
        return false;
    }
    if !verify_binary(params, d_com, &proof.bit) {
        return false;
    }
    for (((cc, sc), lc), product) in child.iter().zip(sibling).zip(left).zip(&proof.limbs) {
        let cy = sc.sub(cc); // C_sibling_i − C_child_i
        let cz = lc.sub(cc); // C_left_i − C_child_i
        if !verify_product(params, d_com, &cy, &cz, product) {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ring_hash::ELL_H;

    /// Fresh ternary randomness for a node's `ELL_H` limbs.
    fn node_randomness(tag: &[u8]) -> Vec<RingRandomness> {
        (0..ELL_H)
            .map(|i| {
                let mut s = tag.to_vec();
                s.extend_from_slice(&(i as u64).to_le_bytes());
                RingRandomness::from_seed(&s)
            })
            .collect()
    }

    #[test]
    fn a_genuine_hash_step_proves_and_verifies() {
        let params = RingParams::standard();
        let hp = HashParams::standard();
        let (l, r) = (HashNode::from_bytes(b"child-l"), HashNode::from_bytes(b"child-r"));
        let parent = hp.hash(&l, &r);
        let (lr, rr, pr) = (node_randomness(b"lr"), node_randomness(b"rr"), node_randomness(b"pr"));
        let lw = NodeWitness { node: &l, randomness: &lr };
        let rw = NodeWitness { node: &r, randomness: &rr };
        let pw = NodeWitness { node: &parent, randomness: &pr };
        let proof = prove_hash_step(&params, &hp, &lw, &rw, &pw, b"seed").expect("genuine step");
        let (lc, rc, pc) = (
            commit_node(&params, &l, &lr),
            commit_node(&params, &r, &rr),
            commit_node(&params, &parent, &pr),
        );
        assert!(verify_hash_step(&params, &hp, &lc, &rc, &pc, &proof), "a real hash step verifies");
    }

    #[test]
    fn a_wrong_parent_has_no_accepting_proof() {
        let params = RingParams::standard();
        let hp = HashParams::standard();
        let (l, r) = (HashNode::from_bytes(b"c-l"), HashNode::from_bytes(b"c-r"));
        let wrong_parent = hp.hash(&r, &l); // hash of the swapped children ≠ hash(l, r)
        let (lr, rr, pr) = (node_randomness(b"lr2"), node_randomness(b"rr2"), node_randomness(b"pr2"));
        let lw = NodeWitness { node: &l, randomness: &lr };
        let rw = NodeWitness { node: &r, randomness: &rr };
        let pw = NodeWitness { node: &wrong_parent, randomness: &pr };
        let proof = prove_hash_step(&params, &hp, &lw, &rw, &pw, b"seed").expect("proof emitted");
        let (lc, rc, pc) = (
            commit_node(&params, &l, &lr),
            commit_node(&params, &r, &rr),
            commit_node(&params, &wrong_parent, &pr),
        );
        assert!(!verify_hash_step(&params, &hp, &lc, &rc, &pc, &proof), "hash(l,r) ≠ the committed parent");
    }

    #[test]
    fn a_conditional_swap_proves_for_both_directions() {
        let params = RingParams::standard();
        let child = HashNode::from_bytes(b"swap-child");
        let sib = HashNode::from_bytes(b"swap-sib");
        let (cr, sr) = (node_randomness(b"swap-cr"), node_randomness(b"swap-sr"));
        let child_coms = commit_node(&params, &child, &cr);
        let sib_coms = commit_node(&params, &sib, &sr);
        let cw = NodeWitness { node: &child, randomness: &cr };
        let sw = NodeWitness { node: &sib, randomness: &sr };
        // d = 0 ⇒ left = child.
        let (d0, rd0) = (Poly::constant(0), RingRandomness::from_seed(b"rd0"));
        let cd0 = RingCommitment::commit_message(&params, &d0, &rd0);
        let lw0 = NodeWitness { node: &child, randomness: &cr };
        let p0 = prove_swap(&params, &cw, &sw, &lw0, &d0, &rd0, b"s0").expect("d=0 swap");
        assert!(verify_swap(&params, &child_coms, &sib_coms, &child_coms, &cd0, &p0), "d=0: left = child");
        // d = 1 ⇒ left = sibling.
        let (d1, rd1) = (Poly::constant(1), RingRandomness::from_seed(b"rd1"));
        let cd1 = RingCommitment::commit_message(&params, &d1, &rd1);
        let lw1 = NodeWitness { node: &sib, randomness: &sr };
        let p1 = prove_swap(&params, &cw, &sw, &lw1, &d1, &rd1, b"s1").expect("d=1 swap");
        assert!(verify_swap(&params, &child_coms, &sib_coms, &sib_coms, &cd1, &p1), "d=1: left = sibling");
    }

    #[test]
    fn a_wrong_swap_is_rejected() {
        // Claim left = sibling while d = 0 (which requires left = child): the per-limb product proofs fail.
        let params = RingParams::standard();
        let child = HashNode::from_bytes(b"ws-child");
        let sib = HashNode::from_bytes(b"ws-sib");
        let (cr, sr) = (node_randomness(b"ws-cr"), node_randomness(b"ws-sr"));
        let child_coms = commit_node(&params, &child, &cr);
        let sib_coms = commit_node(&params, &sib, &sr);
        let cw = NodeWitness { node: &child, randomness: &cr };
        let sw = NodeWitness { node: &sib, randomness: &sr };
        let (d0, rd0) = (Poly::constant(0), RingRandomness::from_seed(b"ws-rd"));
        let cd0 = RingCommitment::commit_message(&params, &d0, &rd0);
        let lw = NodeWitness { node: &sib, randomness: &sr }; // wrong: left = sibling under d = 0
        let proof = prove_swap(&params, &cw, &sw, &lw, &d0, &rd0, b"ws").expect("proof emitted");
        assert!(!verify_swap(&params, &child_coms, &sib_coms, &sib_coms, &cd0, &proof), "d=0 with left=sib is wrong");
    }
}
