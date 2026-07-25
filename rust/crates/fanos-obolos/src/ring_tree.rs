//! The **ring-native commitment tree** — a Merkle tree over the SIS hash ([`crate::ring_hash`]), the ledger
//! structure a shielded spend's membership proof ([`crate::ring_membership`]) is verified against. It is the
//! ring/SIS successor to the BLAKE3 [`crate::tree`]: leaves are note commitments (short nodes), internal nodes are
//! `hash(left, right)`, and it yields the **root** (the spend `anchor`) and the **authentication path** (siblings +
//! directions) that `prove_path_sound` hashes a leaf up to that root.
//!
//! Like [`crate::tree`] it is a fixed-depth tree with **canonical empty-subtree padding**: `empty[0]` is the
//! all-zero leaf and `empty[h+1] = hash(empty[h], empty[h])`, so an unfilled sibling at height `h` is `empty[h]`.
//!
//! ## The frontier — why appending is `O(depth)`, not `O(leaves)`
//!
//! The consensus-critical operations are `append` and `root`: a validator runs them for every note of every block,
//! and the ledger records a new anchor each time. Recomputing the root from all leaves would make appending `O(n)`
//! and a block of `k` notes `O(n·k)` — quadratic growth in the pool, which no ledger can carry.
//!
//! So the tree maintains an **incremental frontier**: `pending[h]` holds the one complete subtree of height `h` that
//! is waiting for a right sibling. Appending carries upward exactly as binary addition carries — combine and ascend
//! while a slot is occupied, park and stop when it is free — so it is `O(depth)` worst case and `O(1)` amortised, and
//! `root` folds the frontier against the empty-subtree padding in `O(depth)`. Both are independent of the pool size,
//! so [`crate::tree::TREE_DEPTH`]-scale capacity is affordable.
//!
//! It remains a **reference** tree in one respect: it retains every leaf so it can produce *any* note's
//! `auth_path`, which is therefore `O(leaves)`. That is a wallet operation, not a consensus one. A production node
//! keeps a per-note incremental witness instead (as [`crate::tree`] does) — an optimisation of the *same* tree, with
//! byte-identical roots and paths.
//!
//! > **STATUS — [P]/[H], correctness-first.** The tree and its auth paths are exact; tests check that hashing a leaf
//! > up its auth path reproduces the root (so a membership proof against this tree/path is consistent), including at
//! > a partially-filled level where the padding is load-bearing; that the frontier root agrees with a from-scratch
//! > recomputation at every prefix length (the frontier's correctness proof, empirically); and that a realistic depth
//! > is affordable.

use alloc::vec::Vec;

use crate::ring::Poly;
use crate::ring_hash::{ELL_H, HashNode, HashParams};

/// A fixed-depth Merkle tree over the SIS hash. Leaves are note commitments; capacity is `2^depth`.
pub struct RingTree {
    hp: HashParams,
    leaves: Vec<HashNode>,
    depth: usize,
    /// `empty[h]` = the root of an all-empty subtree of height `h` — the canonical padding for an unfilled sibling
    /// at that height. Precomputed once (`depth + 1` hashes).
    empty: Vec<HashNode>,
    /// The **frontier**: `pending[h]` is the complete height-`h` subtree awaiting a right sibling, if any. This is
    /// what makes `append`/`root` `O(depth)` instead of `O(leaves)` — see the module docs.
    pending: Vec<Option<HashNode>>,
    /// The root of a *completely filled* tree. A full tree has no partially-filled subtree, so the frontier is
    /// empty and the final append's carry has no slot to park in — this holds it.
    full: Option<HashNode>,
}

/// The canonical empty **leaf** — an all-zero short node.
fn empty_leaf() -> HashNode {
    HashNode::from_limbs(alloc::vec![Poly::zero(); ELL_H])
}

impl RingTree {
    /// A new empty tree of the given `depth` (capacity `2^depth` leaves) under the canonical tree hash.
    #[must_use]
    pub fn new(depth: usize) -> Self {
        let hp = HashParams::standard();
        // empty[0] = the empty leaf; empty[h+1] = hash(empty[h], empty[h]).
        let mut empty = Vec::with_capacity(depth + 1);
        let mut node = empty_leaf();
        for _ in 0..=depth {
            empty.push(node.clone());
            node = hp.hash(&node, &node);
        }
        Self { hp, leaves: Vec::new(), depth, empty, pending: alloc::vec![None; depth], full: None }
    }

    /// The tree's capacity in leaves (`2^depth`, saturating — a realistic depth is affordable here, §module docs).
    #[must_use]
    pub fn capacity(&self) -> u64 {
        1u64.checked_shl(self.depth as u32).unwrap_or(u64::MAX)
    }

    /// The number of leaves appended so far.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Whether no leaf has been appended.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Append a leaf (a note commitment). Returns its index, or `None` if the tree is full.
    ///
    /// The frontier carries like binary addition: while height `h`'s slot is occupied, combine that parked left
    /// sibling with the ascending node and continue; at the first free slot, park and stop. `O(depth)` worst case,
    /// `O(1)` amortised — never `O(leaves)`.
    pub fn append(&mut self, leaf: HashNode) -> Option<u64> {
        if self.len() >= self.capacity() {
            return None;
        }
        let index = self.len();
        self.leaves.push(leaf.clone());
        let mut pending = core::mem::take(&mut self.pending);
        let mut carry = Some(leaf);
        for slot in &mut pending {
            let Some(node) = carry.take() else { break };
            match slot.take() {
                None => {
                    *slot = Some(node); // park as the left sibling at this height and stop carrying
                    break;
                }
                Some(left) => carry = Some(self.hp.hash(&left, &node)),
            }
        }
        self.pending = pending;
        // A carry surviving every height means this append filled the last leaf, so it *is* the complete root —
        // there is no higher slot to park it in. The capacity check makes that happen exactly once.
        if let Some(root) = carry {
            self.full = Some(root);
        }
        Some(index)
    }

    /// The empty-subtree root at height `h` — the padding for an unfilled sibling there.
    fn empty_at(&self, h: usize) -> HashNode {
        self.empty.get(h).cloned().unwrap_or_else(empty_leaf)
    }

    /// Fold one level of **occupied** nodes at height `h` into their parents, padding a missing right child with
    /// `empty[h]`. Only occupied nodes are hashed, so a level costs `O(occupied)` regardless of the tree's depth.
    fn fold(&self, level: &[HashNode], h: usize) -> Vec<HashNode> {
        level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => self.hp.hash(l, r),
                [l] => self.hp.hash(l, &self.empty_at(h)),
                _ => self.empty_at(h + 1), // unreachable: chunks(2) yields 1- or 2-element slices
            })
            .collect()
    }

    /// The Merkle **root** — the spend anchor. `O(depth)`: fold the frontier upward, padding each missing side with
    /// the canonical empty subtree. An empty tree's root is the all-empty subtree root at `depth`.
    #[must_use]
    pub fn root(&self) -> HashNode {
        if let Some(root) = &self.full {
            return root.clone(); // a completely filled tree keeps its root directly
        }
        // `acc` is the running right-hand accumulation. At each height, a parked left sibling takes the left slot and
        // `acc` (or the empty subtree) the right; with no parked node, `acc` becomes the left and pads on the right.
        let mut acc: Option<HashNode> = None;
        for h in 0..self.depth {
            let parked = self.pending.get(h).and_then(Option::as_ref);
            acc = match (parked, acc) {
                (Some(left), Some(right)) => Some(self.hp.hash(left, &right)),
                (Some(left), None) => Some(self.hp.hash(left, &self.empty_at(h))),
                (None, Some(left)) => Some(self.hp.hash(&left, &self.empty_at(h))),
                (None, None) => None,
            };
        }
        acc.unwrap_or_else(|| self.empty_at(self.depth))
    }

    /// The **authentication path** for leaf `index`: the sibling at each level and the direction bit
    /// (`0` = the running node is the left child, `1` = the right) — the witness a membership proof consumes. The
    /// direction bits are `index` in binary (low bit first), which is exactly what the position-bound nullifier
    /// ties itself to ([`crate::ring_untraceable::position_of`]).
    #[must_use]
    pub fn auth_path(&self, index: u64) -> (Vec<HashNode>, Vec<u64>) {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut directions = Vec::with_capacity(self.depth);
        let mut level = self.leaves.clone();
        let mut idx = index;
        for h in 0..self.depth {
            // The sibling is the occupied node at `idx ^ 1`, or the canonical empty subtree if that slot is unfilled.
            let sib = usize::try_from(idx ^ 1).ok().and_then(|i| level.get(i)).cloned();
            siblings.push(sib.unwrap_or_else(|| self.empty_at(h)));
            directions.push(idx & 1);
            level = self.fold(&level, h);
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
        // 5 leaves in a capacity-8 tree: levels are partially filled, so the empty-subtree padding is load-bearing
        // at every height — if it were wrong, some leaf's path would not reproduce the root.
        let mut tree = RingTree::new(3);
        let leaves: Vec<HashNode> = (0..5u8).map(|i| HashNode::from_bytes(&[b'l', i])).collect();
        let indices: Vec<u64> = leaves.iter().map(|l| tree.append(l.clone()).unwrap()).collect();
        let root = tree.root();
        for (leaf, &idx) in leaves.iter().zip(&indices) {
            let (siblings, directions) = tree.auth_path(idx);
            assert_eq!(siblings.len(), 3, "one sibling per level");
            assert_eq!(&hash_up(&tree.hp, leaf, &siblings, &directions), &root, "leaf {idx} hashes to the root");
            // The direction bits are the leaf index in binary — what the position-bound nullifier binds to.
            assert_eq!(crate::ring_untraceable::position_of(&directions), idx, "the directions spell the index");
        }
    }

    /// The root computed the naive way — fold every occupied level, padding with `empty[h]`. The frontier must agree
    /// with this at every prefix length; that agreement is the frontier's correctness check.
    fn naive_root(tree: &RingTree) -> HashNode {
        let mut level = tree.leaves.clone();
        if level.is_empty() {
            return tree.empty_at(tree.depth);
        }
        for h in 0..tree.depth {
            level = level
                .chunks(2)
                .map(|pair| match pair {
                    [l, r] => tree.hp.hash(l, r),
                    [l] => tree.hp.hash(l, &tree.empty_at(h)),
                    _ => unreachable!("chunks(2) yields 1- or 2-element slices"),
                })
                .collect();
        }
        level.into_iter().next().unwrap_or_else(|| tree.empty_at(tree.depth))
    }

    #[test]
    fn the_frontier_root_agrees_with_a_from_scratch_recomputation() {
        // The frontier is an O(depth) shortcut for an O(n) computation, so it must agree with the naive fold at
        // EVERY prefix length — including the empty tree and the completely full one (where the frontier is empty
        // and the root is carried directly).
        let mut tree = RingTree::new(3); // capacity 8, so this covers the full tree too
        assert_eq!(tree.root(), naive_root(&tree), "an empty tree");
        for i in 0..8u8 {
            tree.append(HashNode::from_bytes(&[b'f', i])).expect("append");
            assert_eq!(tree.root(), naive_root(&tree), "after {} leaves", i + 1);
        }
        assert_eq!(tree.len(), tree.capacity(), "the tree is now full");
        assert!(tree.pending.iter().all(Option::is_none), "a full tree has an empty frontier");
        assert!(tree.full.is_some(), "…and carries its root directly");
    }

    #[test]
    fn a_realistic_depth_is_affordable_and_padding_is_canonical() {
        // The property the empty-subtree padding buys: capacity 2^32 (the crate::tree depth) costs O(leaves+depth),
        // not O(2^depth). A tree this deep was previously unusable — levels() materialised every slot.
        let mut tree = RingTree::new(crate::tree::TREE_DEPTH);
        assert_eq!(tree.capacity(), 1u64 << 32, "full Sapling-scale capacity");
        let empty_root = tree.root(); // an empty deep tree still has a root, computed from the padding alone
        assert!(tree.is_empty());
        let leaf = HashNode::from_bytes(b"deep-leaf");
        assert_eq!(tree.append(leaf.clone()), Some(0));
        let root = tree.root();
        assert_ne!(root, empty_root, "appending a note advances the root");
        let (siblings, directions) = tree.auth_path(0);
        assert_eq!(siblings.len(), crate::tree::TREE_DEPTH, "one sibling per level, all padding above the leaf");
        assert_eq!(&hash_up(&tree.hp, &leaf, &siblings, &directions), &root, "the deep path reproduces the root");
        assert!(directions.iter().all(|&d| d == 0), "leaf 0 is the left child at every level");
    }

    #[test]
    fn a_full_tree_rejects_further_appends() {
        let mut tree = RingTree::new(2); // capacity 4
        for i in 0..4u8 {
            assert!(tree.append(HashNode::from_bytes(&[i])).is_some());
        }
        assert_eq!(tree.len(), tree.capacity());
        assert!(tree.append(HashNode::from_bytes(b"overflow")).is_none(), "the tree is full");
    }
}
