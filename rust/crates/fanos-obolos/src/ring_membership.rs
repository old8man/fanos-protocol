//! **Zero-knowledge Merkle membership** over the SIS tree — the untraceability proof a spend attaches to show its
//! note is a leaf under the public anchor *without revealing which leaf*. Built bottom-up from three parts:
//!
//! - **hash step** ([`prove_hash_step`]) — committed `(left, right, parent)` satisfy `parent = hash(left, right)`.
//!   The SIS hash relation is `R_q`-linear (`A₀·left + A₁·right − G(parent) = 0`), so a step is one
//!   [`crate::ring_linear`] proof over `left ‖ right ‖ parent` with coefficients `HashParams::step_coeffs`.
//! - **conditional swap** ([`prove_swap`]) — a hidden bit `d` selects `left = child + d·(sibling − child)`
//!   (`right` derived), so the path leaks no position. Per limb a [`crate::ring_product`] proof, plus `d` binary.
//! - **path** ([`prove_path`]) — *chains* swap + hash step up the tree (parent of level `j` = child of `j+1`),
//!   ties the top node to the public root, and keeps the leaf and every intermediate node hidden.
//!
//! > **SOUNDNESS SCOPE — the structural core.** These prove the *linear* hash relations and the swap selections and
//! > tie leaf → root. A complete proof additionally proves every node **short** (limbs `< 2^{LOG_BASE}`, a
//! > [`crate::ring_shortness`] proof per limb) — otherwise a prover could satisfy the linear system with non-short
//! > "nodes" and forge a path (and the swap's constant-`d` guarantee rests on shortness too). Shortness composes
//! > per node; it is `O(depth·ELL_H·LOG_BASE)` binarity proofs — deferred as the known cost of lattice ZK
//! > membership (recursive-SNARK compaction is future work).
//!
//! > **STATUS — \[P\]/\[H\], correctness-first.** Tests verify a genuine hash step, both swap directions, and a full
//! > leaf→root path; and that a wrong parent, a wrong swap, or a wrong root has no accepting proof.

use alloc::vec::Vec;

use crate::ring::Poly;
use crate::ring_binary::{BinaryProof, prove_binary, verify_binary};
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_hash::{HashNode, HashParams};
use crate::ring_linear::{LinearProof, prove_linear, verify_linear};
use crate::ring_product::{ProductProof, ProductWitness, prove_product, verify_product};
use crate::ring_shortness::{ShortnessProof, prove_short, verify_short};

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

/// Prove every limb of a committed node is **short** (`< 2^bits`) — i.e. the node is a valid SIS tree node. For
/// the tree hash use `bits = LOG_BASE`. One [`crate::ring_shortness`] proof per limb; attaching these to each node
/// of a [`PathProof`] is what completes membership soundness (a non-short node could otherwise satisfy the linear
/// hash relations and forge a path).
#[must_use]
pub fn prove_node_short(
    params: &RingParams,
    node: &HashNode,
    randomness: &[RingRandomness],
    bits: usize,
    seed: &[u8],
) -> Option<Vec<ShortnessProof>> {
    let mut proofs = Vec::with_capacity(node.limbs().len());
    for (i, (limb, r)) in node.limbs().iter().zip(randomness).enumerate() {
        let mut s = seed.to_vec();
        s.extend_from_slice(b"/short/");
        s.extend_from_slice(&(i as u64).to_le_bytes());
        proofs.push(prove_short(params, limb, r, bits, &s)?);
    }
    Some(proofs)
}

/// Verify a [`prove_node_short`] proof against a node's public limb commitments.
#[must_use]
pub fn verify_node_short(
    params: &RingParams,
    node: &[RingCommitment],
    bits: usize,
    proofs: &[ShortnessProof],
) -> bool {
    node.len() == proofs.len() && node.iter().zip(proofs).all(|(c, p)| verify_short(params, c, bits, p))
}

/// One level of a [`PathProof`]: the sibling and direction-bit commitments, the swapped `left` node's commitment,
/// the resulting parent node's commitment, and the swap + hash-step proofs.
#[derive(Clone, PartialEq, Eq, Debug)]
struct PathLevel {
    sibling: Vec<RingCommitment>,
    d_com: RingCommitment,
    left: Vec<RingCommitment>,
    node: Vec<RingCommitment>,
    swap: SwapProof,
    step: HashStepProof,
}

/// A zero-knowledge **Merkle membership** proof: a hidden leaf hashes up to the public root, position hidden.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PathProof {
    leaf: Vec<RingCommitment>,
    levels: Vec<PathLevel>,
    root_r: Vec<RingRandomness>, // the top node's randomness, revealed to tie it to the public root
}

/// Deterministic randomness for a node's `ELL_H` limbs, domain-separated by role and level. `pub(crate)` so the
/// untraceability composition ([`crate::ring_untraceable`]) can derive the *same* leaf randomness, sharing the note
/// commitment between the membership and nullifier proofs.
pub(crate) fn node_r(seed: &[u8], role: &str, level: usize) -> Vec<RingRandomness> {
    (0..crate::ring_hash::ELL_H)
        .map(|i| {
            let mut s = seed.to_vec();
            s.extend_from_slice(role.as_bytes());
            s.extend_from_slice(&(level as u64).to_le_bytes());
            s.extend_from_slice(&(i as u64).to_le_bytes());
            RingRandomness::from_seed(&s)
        })
        .collect()
}

/// The randomness committing the **direction bit** at `level`, derived from the path seed. `pub(crate)` so the
/// untraceability composition can re-derive it and prove a *position* relation over the very same `d_com`s the path
/// publishes ([`crate::ring_nullifier`] binds a nullifier to its tree slot that way).
pub(crate) fn dir_r(seed: &[u8], level: usize) -> RingRandomness {
    let mut s = seed.to_vec();
    s.extend_from_slice(b"/dir");
    s.extend_from_slice(&(level as u64).to_le_bytes());
    RingRandomness::from_seed(&s)
}

/// Component-wise `a + b − c` over three limb-randomness vectors — the derived `right = child + sibling − left`.
fn combine_r(a: &[RingRandomness], b: &[RingRandomness], c: &[RingRandomness]) -> Vec<RingRandomness> {
    a.iter().zip(b).zip(c).map(|((ai, bi), ci)| ai.add(bi).sub(ci)).collect()
}

/// The node value + randomness at each rung of the path: `[leaf, node_0, …, node_{depth-1}]` (the last is the
/// root). Deterministic from `seed` — [`prove_path_sound`] recomputes it to attach a shortness proof per node.
/// (It mirrors [`prove_path`]'s internal chain derivation; the two must stay in step.)
fn path_chain(
    hp: &HashParams,
    leaf: &HashNode,
    siblings: &[HashNode],
    directions: &[u64],
    seed: &[u8],
) -> Vec<(HashNode, Vec<RingRandomness>)> {
    let depth = siblings.len();
    let mut chain = Vec::with_capacity(depth + 1);
    chain.push((leaf.clone(), node_r(seed, "/leaf", 0)));
    let mut child = leaf.clone();
    for (j, (sibling, &d)) in siblings.iter().zip(directions).enumerate() {
        let (left, right) =
            if d == 1 { (sibling.clone(), child.clone()) } else { (child.clone(), sibling.clone()) };
        let node = hp.hash(&left, &right);
        let is_top = j == depth - 1;
        chain.push((node.clone(), node_r(seed, if is_top { "/root" } else { "/node" }, j)));
        child = node;
    }
    chain
}

/// Prove, in zero knowledge, that `leaf` is a member of a Merkle tree — hashing it up through `siblings` with
/// hidden `directions` (`0` = the running node is the left child, `1` = the right). The prover *computes* the top
/// node; [`verify_path`] ties it to the public root. The leaf and every intermediate node stay hidden, and the
/// position is hidden by the per-level conditional swap. `None` only on a sub-proof's rare masking exhaustion.
///
/// > **SOUNDNESS SCOPE — the structural core.** This chains the swap + hash-step relations and ties the top to the
/// > public root. A complete proof additionally proves every node **short** ([`crate::ring_shortness`] per limb) —
/// > without which non-short "nodes" could satisfy the linear relations and forge a path. Shortness composes per
/// > node (it is `O(depth·ELL_H·LOG_BASE)` binarity proofs — deferred as the known cost of lattice ZK membership).
#[must_use]
pub fn prove_path(
    params: &RingParams,
    hp: &HashParams,
    leaf: &HashNode,
    siblings: &[HashNode],
    directions: &[u64],
    seed: &[u8],
) -> Option<PathProof> {
    let depth = siblings.len();
    if directions.len() != depth || depth == 0 {
        return None;
    }
    let leaf_r = node_r(seed, "/leaf", 0);
    let leaf_coms = commit_node(params, leaf, &leaf_r);

    let mut child = leaf.clone();
    let mut child_r = leaf_r.clone();
    let mut levels = Vec::with_capacity(depth);
    let mut top_r = leaf_r;
    for (j, (sibling, &d)) in siblings.iter().zip(directions).enumerate() {
        let sib_r = node_r(seed, "/sib", j);
        let d_poly = Poly::constant(d);
        let d_r = dir_r(seed, j);

        // (left, right) = d ? (sibling, child) : (child, sibling); left committed fresh, right derived.
        let (left, right) = if d == 1 { (sibling.clone(), child.clone()) } else { (child.clone(), sibling.clone()) };
        let left_r = node_r(seed, "/left", j);
        let right_r = combine_r(&child_r, &sib_r, &left_r); // child_r + sib_r − left_r
        let node = hp.hash(&left, &right);
        let is_top = j == depth - 1;
        let nr = node_r(seed, if is_top { "/root" } else { "/node" }, j);

        let child_w = NodeWitness { node: &child, randomness: &child_r };
        let sib_w = NodeWitness { node: sibling, randomness: &sib_r };
        let left_w = NodeWitness { node: &left, randomness: &left_r };
        let right_w = NodeWitness { node: &right, randomness: &right_r };
        let node_w = NodeWitness { node: &node, randomness: &nr };
        let mut sw = seed.to_vec();
        sw.extend_from_slice(b"/sw");
        sw.extend_from_slice(&(j as u64).to_le_bytes());
        let swap = prove_swap(params, &child_w, &sib_w, &left_w, &d_poly, &d_r, &sw)?;
        let mut hs = seed.to_vec();
        hs.extend_from_slice(b"/hs");
        hs.extend_from_slice(&(j as u64).to_le_bytes());
        let step = prove_hash_step(params, hp, &left_w, &right_w, &node_w, &hs)?;

        levels.push(PathLevel {
            sibling: commit_node(params, sibling, &sib_r),
            d_com: RingCommitment::commit_message(params, &d_poly, &d_r),
            left: commit_node(params, &left, &left_r),
            node: commit_node(params, &node, &nr),
            swap,
            step,
        });
        child = node;
        child_r.clone_from(&nr);
        top_r = nr;
    }
    Some(PathProof { leaf: leaf_coms, levels, root_r: top_r })
}

/// Verify a [`prove_path`] proof that some hidden leaf is a member of the tree with the public `root`.
#[must_use]
pub fn verify_path(params: &RingParams, hp: &HashParams, root: &HashNode, proof: &PathProof) -> bool {
    if proof.levels.is_empty() {
        return false;
    }
    let mut child = proof.leaf.clone();
    for level in &proof.levels {
        // right = child + sibling − left (homomorphic).
        if level.sibling.len() != child.len() || level.left.len() != child.len() {
            return false;
        }
        let right: Vec<RingCommitment> = child
            .iter()
            .zip(&level.sibling)
            .zip(&level.left)
            .map(|((c, s), l)| c.add(s).sub(l))
            .collect();
        if !verify_swap(params, &child, &level.sibling, &level.left, &level.d_com, &level.swap) {
            return false;
        }
        if !verify_hash_step(params, hp, &level.left, &right, &level.node, &level.step) {
            return false;
        }
        child.clone_from(&level.node);
    }
    // Tie the top node to the public root: C_top = com(root; root_r).
    match proof.levels.last() {
        Some(top) => top.node == commit_node(params, root, &proof.root_r),
        None => false,
    }
}

/// A **fully sound** membership proof: the structural [`PathProof`] plus a shortness proof for every *hidden* node
/// (leaf, siblings, intermediate nodes), so no non-short "node" can satisfy the linear hash relations and forge a
/// path. The public root's shortness is checked directly. This is `O(depth·ELL_H·LOG_BASE·REPETITIONS)` binarity
/// proofs — the inherent cost of lattice ZK Merkle membership (recursive-SNARK compaction is future work).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SoundPathProof {
    path: PathProof,
    leaf_short: Vec<ShortnessProof>,         // ELL_H
    sibling_short: Vec<Vec<ShortnessProof>>, // depth × ELL_H
    node_short: Vec<Vec<ShortnessProof>>,    // (depth−1) intermediate nodes × ELL_H
}

impl SoundPathProof {
    /// The commitment to the membership **leaf** — the note commitment `cm`. The untraceability composition shares
    /// this with the nullifier proof, so a spend proves membership of *exactly* the note it nullifies.
    #[must_use]
    pub fn leaf_commitment(&self) -> &[RingCommitment] {
        &self.path.leaf
    }

    /// The commitments to the hidden **direction bits**, level 0 (the leaf's own side) upward. The bits *are* the
    /// leaf's tree index in binary — `position = Σ_j 2ʲ·d_j` — so these are exactly what a position-bound
    /// nullifier ties itself to ([`crate::ring_untraceable`]), without publishing the position. Each bit is already
    /// proven binary by its level's swap proof.
    #[must_use]
    pub fn direction_commitments(&self) -> Vec<RingCommitment> {
        self.path.levels.iter().map(|l| l.d_com.clone()).collect()
    }
}

/// A sub-seed `base ‖ tag ‖ index`.
fn tagged(base: &[u8], tag: &[u8], index: usize) -> Vec<u8> {
    let mut s = base.to_vec();
    s.extend_from_slice(tag);
    s.extend_from_slice(&(index as u64).to_le_bytes());
    s
}

/// Prove membership **soundly**: [`prove_path`] plus node-shortness (`bits = LOG_BASE`) on the leaf, every
/// sibling, and every intermediate node. The root is public, so its shortness is checked directly by
/// [`verify_path_sound`].
#[must_use]
pub fn prove_path_sound(
    params: &RingParams,
    hp: &HashParams,
    leaf: &HashNode,
    siblings: &[HashNode],
    directions: &[u64],
    seed: &[u8],
) -> Option<SoundPathProof> {
    let path = prove_path(params, hp, leaf, siblings, directions, seed)?;
    let depth = siblings.len();
    let bits = crate::ring_hash::LOG_BASE as usize;

    let leaf_short = prove_node_short(params, leaf, &node_r(seed, "/leaf", 0), bits, &tagged(seed, b"/lshort", 0))?;

    let mut sibling_short = Vec::with_capacity(depth);
    for (j, sibling) in siblings.iter().enumerate() {
        let sib_r = node_r(seed, "/sib", j);
        sibling_short.push(prove_node_short(params, sibling, &sib_r, bits, &tagged(seed, b"/sshort", j))?);
    }

    // Intermediate nodes node_0 … node_{depth−2} (skip node_{depth−1} = root, which is public).
    let chain = path_chain(hp, leaf, siblings, directions, seed);
    let mut node_short = Vec::with_capacity(depth.saturating_sub(1));
    for (j, (node, nr)) in chain.iter().skip(1).take(depth.saturating_sub(1)).enumerate() {
        node_short.push(prove_node_short(params, node, nr, bits, &tagged(seed, b"/nshort", j))?);
    }

    Some(SoundPathProof { path, leaf_short, sibling_short, node_short })
}

/// Verify a [`prove_path_sound`] proof: the structural path, every hidden node's shortness, and the public root's
/// shortness (its digits are `< 2^{LOG_BASE}`, checked directly).
#[must_use]
pub fn verify_path_sound(params: &RingParams, hp: &HashParams, root: &HashNode, proof: &SoundPathProof) -> bool {
    if !verify_path(params, hp, root, &proof.path) {
        return false;
    }
    let depth = proof.path.levels.len();
    let bits = crate::ring_hash::LOG_BASE as usize;
    if proof.sibling_short.len() != depth || proof.node_short.len() != depth.saturating_sub(1) {
        return false;
    }
    if !verify_node_short(params, &proof.path.leaf, bits, &proof.leaf_short) {
        return false;
    }
    for (level, ss) in proof.path.levels.iter().zip(&proof.sibling_short) {
        if !verify_node_short(params, &level.sibling, bits, ss) {
            return false;
        }
    }
    // Intermediate nodes: levels[0 .. depth−1].node = node_0 … node_{depth−2}.
    for (level, ns) in proof.path.levels.iter().take(depth.saturating_sub(1)).zip(&proof.node_short) {
        if !verify_node_short(params, &level.node, bits, ns) {
            return false;
        }
    }
    // The public root's limbs must be short (digits < 2^LOG_BASE).
    let bound = 1u64 << bits;
    root.limbs().iter().all(|limb| limb.coeffs().iter().all(|&c| c < bound))
}

impl crate::ring_size::ProofSize for HashStepProof {
    fn ring_elements(&self) -> usize {
        self.0.ring_elements()
    }
}

impl crate::ring_size::ProofSize for SwapProof {
    fn ring_elements(&self) -> usize {
        self.bit.ring_elements() + self.limbs.ring_elements()
    }
}

impl crate::ring_size::ProofSize for PathLevel {
    fn ring_elements(&self) -> usize {
        self.sibling.ring_elements() + self.d_com.ring_elements() + self.left.ring_elements()
            + self.node.ring_elements()
            + self.swap.ring_elements()
            + self.step.ring_elements()
    }
}

impl crate::ring_size::ProofSize for PathProof {
    fn ring_elements(&self) -> usize {
        self.leaf.ring_elements() + self.levels.ring_elements() + self.root_r.ring_elements()
    }
}

impl crate::ring_size::ProofSize for SoundPathProof {
    /// The structural path plus a shortness proof per hidden node — the second term is the stack's dominant cost
    /// (`docs/design-obolos-zk.md` §6): `2·depth + 1` nodes, each `ELL_H` limbs.
    fn ring_elements(&self) -> usize {
        self.path.ring_elements()
            + self.leaf_short.ring_elements()
            + self.sibling_short.iter().map(crate::ring_size::ProofSize::ring_elements).sum::<usize>()
            + self.node_short.iter().map(crate::ring_size::ProofSize::ring_elements).sum::<usize>()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ring::D;
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

    #[test]
    fn a_short_node_proves_and_a_non_short_limb_is_rejected() {
        let params = RingParams::standard();
        let small = |a: u64, b: u64| {
            let mut c = [0u64; D];
            c[0] = a;
            c[1] = b;
            Poly::from_u64(&c)
        };
        // A node whose limbs all have coefficients < 2^4 = 16 (a small `bits` keeps the shortness proof fast).
        let limbs: Vec<Poly> = (0..ELL_H).map(|i| small(3 + i as u64, 15 - i as u64)).collect();
        let node = HashNode::from_limbs(limbs);
        let nr = node_randomness(b"ns");
        let coms = commit_node(&params, &node, &nr);
        let proofs = prove_node_short(&params, &node, &nr, 4, b"seed").expect("short node");
        assert!(verify_node_short(&params, &coms, 4, &proofs), "a node with all-<16 limbs proves short");
        // A limb with a coefficient of 16 is not < 2^4: its shortness proof cannot verify.
        let bad: Vec<Poly> =
            (0..ELL_H).map(|i| if i == 0 { small(16, 0) } else { small(3 + i as u64, 15 - i as u64) }).collect();
        let bad_node = HashNode::from_limbs(bad);
        let bad_nr = node_randomness(b"ns-bad");
        let bad_coms = commit_node(&params, &bad_node, &bad_nr);
        let bad_proofs = prove_node_short(&params, &bad_node, &bad_nr, 4, b"seed").expect("emitted");
        assert!(!verify_node_short(&params, &bad_coms, 4, &bad_proofs), "a limb of 16 is not < 2^4");
    }

    /// The root a depth-2 path with the given leaf, siblings, and directions hashes to.
    fn tree_root(hp: &HashParams, leaf: &HashNode, sib0: &HashNode, sib1: &HashNode, d0: u64, d1: u64) -> HashNode {
        let (l0, r0) =
            if d0 == 1 { (sib0.clone(), leaf.clone()) } else { (leaf.clone(), sib0.clone()) };
        let node0 = hp.hash(&l0, &r0);
        let (l1, r1) =
            if d1 == 1 { (sib1.clone(), node0.clone()) } else { (node0.clone(), sib1.clone()) };
        hp.hash(&l1, &r1)
    }

    #[test]
    fn a_membership_path_proves_and_verifies() {
        let params = RingParams::standard();
        let hp = HashParams::standard();
        let leaf = HashNode::from_bytes(b"path-leaf");
        let sib0 = HashNode::from_bytes(b"path-sib0");
        let sib1 = HashNode::from_bytes(b"path-sib1");
        let (d0, d1) = (1u64, 0u64);
        let root = tree_root(&hp, &leaf, &sib0, &sib1, d0, d1);
        let sibs = [sib0, sib1];
        let dirs = [d0, d1];
        let proof = prove_path(&params, &hp, &leaf, &sibs, &dirs, b"seed").expect("membership path");
        assert!(verify_path(&params, &hp, &root, &proof), "a genuine leaf→root path verifies");
    }

    #[test]
    fn a_path_to_a_wrong_root_is_rejected() {
        let params = RingParams::standard();
        let hp = HashParams::standard();
        let leaf = HashNode::from_bytes(b"wr-leaf");
        let sib0 = HashNode::from_bytes(b"wr-sib0");
        let sib1 = HashNode::from_bytes(b"wr-sib1");
        let (d0, d1) = (0u64, 1u64);
        let root = tree_root(&hp, &leaf, &sib0, &sib1, d0, d1);
        let sibs = [sib0, sib1];
        let dirs = [d0, d1];
        let proof = prove_path(&params, &hp, &leaf, &sibs, &dirs, b"seed").expect("path");
        // The top-node tie is to the real root; a different anchor is rejected.
        let wrong_root = HashNode::from_bytes(b"wr-not-the-root");
        assert!(!verify_path(&params, &hp, &wrong_root, &proof), "a path does not verify against a wrong root");
        assert!(verify_path(&params, &hp, &root, &proof), "…but does against the real root");
    }

    #[test]
    #[ignore = "sound path proves shortness at bits=LOG_BASE=16 — ~minute of binarity proofs; run with --ignored"]
    fn a_sound_membership_path_proves_and_verifies() {
        // A fully sound depth-1 membership: the structural path plus node-shortness on the leaf and sibling
        // (the root, node_0, is public). Verifies every node is a genuine short SIS node — no forged path.
        let params = RingParams::standard();
        let hp = HashParams::standard();
        let leaf = HashNode::from_bytes(b"sp-leaf");
        let sib0 = HashNode::from_bytes(b"sp-sib0");
        let d0 = 1u64;
        let root = {
            let (l, r) = if d0 == 1 { (sib0.clone(), leaf.clone()) } else { (leaf.clone(), sib0.clone()) };
            hp.hash(&l, &r)
        };
        let sibs = [sib0];
        let dirs = [d0];
        let proof = prove_path_sound(&params, &hp, &leaf, &sibs, &dirs, b"seed").expect("sound path");
        assert!(verify_path_sound(&params, &hp, &root, &proof), "a fully sound depth-1 path verifies");
    }
}
