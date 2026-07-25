//! The **ring-native commitment tree** — a Merkle tree over the SIS hash ([`crate::ring_hash`]), the ledger
//! structure a shielded spend's membership proof ([`crate::ring_membership`]) is verified against. It is the
//! ring/SIS successor to the BLAKE3 [`crate::tree`]: leaves are note commitments (short nodes), internal nodes are
//! `hash(left, right)`, and it yields the **root** (the spend `anchor`) and the **authentication path** (siblings +
//! directions) that `prove_path_sound` hashes a leaf up to that root.
//!
//! This is a **reference** tree: it retains all leaves and recomputes the levels, so it is `O(2^depth)` and suited
//! to small depths / tests. A production tree keeps only the `O(depth)` frontier + per-note witnesses (as
//! [`crate::tree`] does); that is the drop-in optimisation, with the root/path outputs unchanged.
//!
//! > **STATUS — [P]/[H], correctness-first.** The tree and its auth paths are exact; the test checks that hashing a
//! > leaf up its auth path reproduces the root (so a membership proof against this tree/path is consistent). Wiring
//! > it into a ring-native shielded state (nullifier set + `apply`) is the next wiring step.

use alloc::vec::Vec;

use crate::ring::Poly;
use crate::ring_hash::{ELL_H, HashNode, HashParams};

/// A fixed-depth Merkle tree over the SIS hash. Leaves are note commitments; capacity is `2^depth`.
pub struct RingTree {
    hp: HashParams,
    leaves: Vec<HashNode>,
    depth: usize,
}

/// The canonical empty node — an all-zero short node — padding unfilled leaves and subtrees.
fn empty_node() -> HashNode {
    HashNode::from_limbs(alloc::vec![Poly::zero(); ELL_H])
}

impl RingTree {
    /// A new empty tree of the given `depth` (capacity `2^depth` leaves) under the canonical tree hash.
    #[must_use]
    pub fn new(depth: usize) -> Self {
        Self { hp: HashParams::standard(), leaves: Vec::new(), depth }
    }

    /// Append a leaf (a note commitment). Returns its index, or `None` if the tree is full.
    pub fn append(&mut self, leaf: HashNode) -> Option<usize> {
        if self.leaves.len() >= (1usize << self.depth) {
            return None;
        }
        let index = self.leaves.len();
        self.leaves.push(leaf);
        Some(index)
    }

    /// The tree levels bottom-up: `[leaves (padded), …, [root]]`. Index `[j][k]` is node `k` at height `j`.
    // Bottom level is padded to exactly `2^depth`, so every `chunks(2)` is a full pair and every index below is in
    // bounds by construction (the standard Merkle layout).
    #[allow(clippy::indexing_slicing)]
    fn levels(&self) -> Vec<Vec<HashNode>> {
        let width = 1usize << self.depth;
        let empty = empty_node();
        let mut level: Vec<HashNode> =
            self.leaves.iter().cloned().chain(core::iter::repeat(empty)).take(width).collect();
        let mut all = Vec::with_capacity(self.depth + 1);
        all.push(level.clone());
        for _ in 0..self.depth {
            level = level.chunks(2).map(|pair| self.hp.hash(&pair[0], &pair[1])).collect();
            all.push(level.clone());
        }
        all
    }

    /// The Merkle **root** — the spend anchor.
    #[must_use]
    pub fn root(&self) -> HashNode {
        self.levels().pop().and_then(|top| top.into_iter().next()).unwrap_or_else(empty_node)
    }

    /// The **authentication path** for leaf `index`: the sibling at each level and the direction bit
    /// (`0` = the running node is the left child, `1` = the right) — the witness a membership proof consumes.
    #[must_use]
    #[allow(clippy::indexing_slicing)] // sib_idx < level width at every height, by construction
    pub fn auth_path(&self, index: usize) -> (Vec<HashNode>, Vec<u64>) {
        let levels = self.levels();
        let mut siblings = Vec::with_capacity(self.depth);
        let mut directions = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in levels.iter().take(self.depth) {
            siblings.push(level[idx ^ 1].clone());
            directions.push((idx & 1) as u64);
            idx >>= 1;
        }
        (siblings, directions)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Hash `leaf` up an authentication path — the non-ZK check a membership proof mirrors in zero knowledge.
    fn hash_up(hp: &HashParams, leaf: &HashNode, siblings: &[HashNode], directions: &[u64]) -> HashNode {
        let mut node = leaf.clone();
        for (sib, &d) in siblings.iter().zip(directions) {
            let (l, r) = if d == 1 { (sib.clone(), node) } else { (node, sib.clone()) };
            node = hp.hash(&l, &r);
        }
        node
    }

    #[test]
    fn an_auth_path_hashes_a_leaf_up_to_the_root() {
        let mut tree = RingTree::new(3); // capacity 8
        let leaves: Vec<HashNode> = (0..5u8).map(|i| HashNode::from_bytes(&[b'l', i])).collect();
        let indices: Vec<usize> = leaves.iter().map(|l| tree.append(l.clone()).unwrap()).collect();
        let root = tree.root();
        // Every appended leaf's auth path reproduces the root.
        for (leaf, &idx) in leaves.iter().zip(&indices) {
            let (siblings, directions) = tree.auth_path(idx);
            assert_eq!(siblings.len(), 3, "one sibling per level");
            assert_eq!(&hash_up(&tree.hp, leaf, &siblings, &directions), &root, "leaf {idx} hashes to the root");
        }
    }

    #[test]
    fn a_full_tree_rejects_further_appends() {
        let mut tree = RingTree::new(2); // capacity 4
        for i in 0..4u8 {
            assert!(tree.append(HashNode::from_bytes(&[i])).is_some());
        }
        assert!(tree.append(HashNode::from_bytes(b"overflow")).is_none(), "the tree is full");
    }
}
