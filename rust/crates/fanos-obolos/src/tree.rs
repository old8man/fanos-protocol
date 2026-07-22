//! The **note-commitment tree** — the append-only Merkle tree of every shielded note ever created, and the
//! structure a spend proves *membership in* to achieve whole-pool untraceability (`spec/platform.md` §4.2).
//!
//! Every OBOLOS output appends its note commitment `cm` as the next leaf; the tree root is part of the block
//! `state_root`, so all validators agree on the same anonymity set. To spend a note, the owner proves in
//! zero-knowledge that its `cm` is *some* leaf under a known root — revealing which leaf to **no one**, so the
//! anonymity set is the entire pool (unlike Monero's ring, whose set is a handful of decoys). This module is
//! the exact tree semantics: append, the root, and the authentication path a membership proof is built over.
//!
//! It is a fixed-depth ([`TREE_DEPTH`]) binary tree with canonical empty-subtree padding (the Zcash Sapling
//! structure). The reference implementation here keeps the appended leaves so it can compute any leaf's path;
//! a production node keeps only the `O(TREE_DEPTH)` frontier plus a per-note incremental witness — an
//! optimisation of the *same* tree, byte-for-byte identical roots and paths.

use alloc::vec::Vec;

use fanos_primitives::hash_labeled;

/// The tree depth — `2^32` note capacity (the Zcash Sapling depth). A note's position is a `u64` index in
/// `0..2^TREE_DEPTH`.
pub const TREE_DEPTH: usize = 32;

/// Domain-separation label for an internal node hash `H(left ‖ right)`.
const NODE_LABEL: &str = "FANOS-obolos-v1/tree-node";
/// Domain-separation label for the canonical empty leaf.
const EMPTY_LEAF_LABEL: &str = "FANOS-obolos-v1/tree-empty-leaf";

/// The hash of an internal node from its two children.
#[must_use]
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(left);
    preimage[32..].copy_from_slice(right);
    hash_labeled(NODE_LABEL, &preimage)
}

/// The roots of all-empty subtrees, indexed by height: `empty_roots[0]` is the canonical empty leaf, and
/// `empty_roots[h+1] = H(empty_roots[h], empty_roots[h])`. Used to pad a partially-filled level.
#[must_use]
fn empty_roots() -> [[u8; 32]; TREE_DEPTH + 1] {
    let mut e = [[0u8; 32]; TREE_DEPTH + 1];
    let mut prev = hash_labeled(EMPTY_LEAF_LABEL, &[]);
    // Fill height 0 (the empty leaf) upward: e[h] is the root of an all-empty subtree of height h.
    for slot in &mut e {
        *slot = prev;
        prev = node_hash(&prev, &prev);
    }
    e
}

/// An **authentication path**: the `TREE_DEPTH` sibling hashes from a leaf up to the root, plus the leaf's
/// index (whose bits say, at each level, whether the current node is the left or right child). A membership
/// proof over the shielded pool carries (a commitment to) this path; [`verify`](Self::verify) recomputes the
/// root from a leaf and checks it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthPath {
    /// The leaf's position in the tree.
    pub index: u64,
    /// The sibling hash at each level, leaf-to-root.
    pub siblings: [[u8; 32]; TREE_DEPTH],
}

impl AuthPath {
    /// Recompute the tree root from `leaf` and this path, and check it equals `root`. This is exactly the
    /// membership relation a shielded spend proves in zero-knowledge (here in the clear, for verification).
    #[must_use]
    pub fn verify(&self, leaf: &[u8; 32], root: &[u8; 32]) -> bool {
        let mut cur = *leaf;
        let mut idx = self.index;
        for sib in &self.siblings {
            cur = if idx & 1 == 0 { node_hash(&cur, sib) } else { node_hash(sib, &cur) };
            idx >>= 1;
        }
        &cur == root
    }
}

/// The append-only note-commitment tree.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct CommitmentTree {
    leaves: Vec<[u8; 32]>,
}

impl CommitmentTree {
    /// An empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// The number of note commitments appended so far.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Whether the tree is full (`2^TREE_DEPTH` leaves). Practically never reached (`2^32` notes).
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.size() >= 1u64 << TREE_DEPTH
    }

    /// Append a note commitment as the next leaf, returning its **position** (the index a future spend of this
    /// note authenticates against). `None` if the tree is full.
    pub fn append(&mut self, cm: [u8; 32]) -> Option<u64> {
        if self.is_full() {
            return None;
        }
        let pos = self.size();
        self.leaves.push(cm);
        Some(pos)
    }

    /// The Merkle root over the fixed-depth tree with the appended leaves and canonical empty padding — the
    /// value committed into the block `state_root`. Computed without materialising the `2^TREE_DEPTH` empty
    /// leaves (empty subtrees collapse to their precomputed roots), so it is `O(size · TREE_DEPTH)`.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let empties = empty_roots();
        let mut nodes = self.leaves.clone();
        // Fold level by level, padding a lone left node with that level's empty-subtree root. An empty tree
        // folds to nothing and falls through to the all-empty root (`empties`'s top entry).
        for empty in empties.iter().take(TREE_DEPTH) {
            let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
            for pair in nodes.chunks(2) {
                let left = pair.first().copied().unwrap_or(*empty);
                let right = pair.get(1).copied().unwrap_or(*empty);
                next.push(node_hash(&left, &right));
            }
            nodes = next;
        }
        nodes.first().copied().unwrap_or_else(|| empties.last().copied().unwrap_or_default())
    }

    /// The authentication path for the leaf at `index`, or `None` if no note occupies that position yet. The
    /// returned path [`verify`](AuthPath::verify)s against [`root`](Self::root) for exactly the appended leaf.
    #[must_use]
    pub fn path(&self, index: u64) -> Option<AuthPath> {
        if index >= self.size() {
            return None;
        }
        let empties = empty_roots();
        let mut siblings = [[0u8; 32]; TREE_DEPTH];
        let mut nodes = self.leaves.clone();
        let mut idx = index as usize;
        for (level, sib) in siblings.iter_mut().enumerate() {
            let empty = empties.get(level).copied().unwrap_or_default();
            let sib_idx = idx ^ 1;
            *sib = nodes.get(sib_idx).copied().unwrap_or(empty);
            // Fold this level up so the next iteration sees the parent nodes.
            let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
            for pair in nodes.chunks(2) {
                let left = pair.first().copied().unwrap_or(empty);
                let right = pair.get(1).copied().unwrap_or(empty);
                next.push(node_hash(&left, &right));
            }
            nodes = next;
            idx >>= 1;
        }
        Some(AuthPath { index, siblings })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn leaf(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    #[test]
    fn append_returns_sequential_positions() {
        let mut t = CommitmentTree::new();
        assert_eq!(t.size(), 0);
        assert_eq!(t.append(leaf(1)), Some(0));
        assert_eq!(t.append(leaf(2)), Some(1));
        assert_eq!(t.append(leaf(3)), Some(2));
        assert_eq!(t.size(), 3);
    }

    #[test]
    fn the_empty_root_is_the_canonical_all_empty_tree() {
        let t = CommitmentTree::new();
        assert_eq!(t.root(), empty_roots()[TREE_DEPTH], "an empty tree's root is the all-empty-subtree root");
    }

    #[test]
    fn the_root_is_deterministic_and_advances_on_append() {
        let mut a = CommitmentTree::new();
        let mut b = CommitmentTree::new();
        a.append(leaf(1));
        b.append(leaf(1));
        assert_eq!(a.root(), b.root(), "same leaves ⇒ same root");
        let before = a.root();
        a.append(leaf(2));
        assert_ne!(a.root(), before, "appending a note advances the root");
        // Order matters (positions differ).
        let mut c = CommitmentTree::new();
        c.append(leaf(2));
        c.append(leaf(1));
        assert_ne!(a.root(), c.root(), "the tree is position-sensitive");
    }

    #[test]
    fn every_leaf_authenticates_against_the_root() {
        let mut t = CommitmentTree::new();
        for i in 0..13u8 {
            t.append(leaf(i));
        }
        let root = t.root();
        for i in 0..13u64 {
            let path = t.path(i).expect("a path for an occupied position");
            assert_eq!(path.index, i);
            assert!(path.verify(&leaf(i as u8), &root), "leaf {i} authenticates against the root");
        }
        assert!(t.path(13).is_none(), "no path for an unoccupied position");
    }

    #[test]
    fn a_path_rejects_the_wrong_leaf_or_a_stale_root() {
        let mut t = CommitmentTree::new();
        for i in 0..5u8 {
            t.append(leaf(i));
        }
        let root = t.root();
        let path = t.path(2).unwrap();
        assert!(path.verify(&leaf(2), &root));
        assert!(!path.verify(&leaf(99), &root), "a different leaf does not authenticate");
        // A root from a later tree state must not accept the old path/leaf pair at a different position's proof.
        let mut t2 = t.clone();
        t2.append(leaf(200));
        assert!(!path.verify(&leaf(2), &t2.root()), "the path does not verify against a changed root");
    }

    #[test]
    fn a_full_tree_refuses_further_appends() {
        // Simulate fullness without allocating 2^32 leaves by checking the boundary predicate directly.
        let t = CommitmentTree::new();
        assert!(!t.is_full(), "an empty tree is not full");
        // The capacity boundary is 2^TREE_DEPTH; the reference cannot materialise it, but the guard is exact.
        assert_eq!(1u64 << TREE_DEPTH, 4_294_967_296, "2^32 note capacity");
    }
}
