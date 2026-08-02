//! **One Merkle tree** for the whole platform — domain-separated, count-binding, and fixed-shape.
//!
//! Three divergent implementations existed before this module: `fanos-thesauros` (odd node *promoted*, `MerkleStep`
//! proofs), `fanos-taxis::crosscell` (odd tail *duplicated*, index-parity proofs), and `fanos-vrf::pqvrf` (perfect tree
//! only). Three odd-node rules, three proof formats, three sets of edge cases to get right — and the audit's standing
//! finding that a hash tree is exactly the kind of primitive a platform should own once.
//!
//! ## What this construction fixes, and what was actually at risk
//!
//! **The root binds the leaf count** (`root = H(ROOT ‖ count_be ‖ fold(leaves))`), which is what removes the
//! **CVE-2012-2459** ambiguity class outright rather than relying on a caller to bind the count externally. With
//! duplicate-the-odd-tail padding and no count in the root, `[a, b, c]` and `[a, b, c, c]` fold to the *same* root: one
//! commitment, two leaf sequences. Binding the count makes those two roots differ by construction, so the padding rule
//! stops being load-bearing.
//!
//! To be precise about severity, since overstating it would be worse than silence: in `crosscell` the ambiguity was **not
//! exploitable**. Leaves and internal nodes are domain-separated, so no internal node can be presented as a leaf; the
//! outbox root is bound into a quorum-certified `state_root`, so an attacker cannot choose it; and the only forgeable
//! variant is a *duplicate* of a message that genuinely was emitted, which the destination discards because it
//! de-duplicates by `(source_cell, nonce)`. What was genuinely wrong is narrower and fixed here:
//!
//! * **The proof length was unbounded.** `merkle_verify` folded however many siblings it was handed — a `u16` count on
//!   the wire, so 65 535 hashes per receipt from a ~2 MB message. `verify` instead *requires* exactly
//!   `height``(count)` siblings, so the work is bounded by the commitment itself and a wrong-shaped proof is rejected
//!   before any hashing.
//! * **The empty root was `[0u8; 32]`.** A certified empty outbox would have accepted any leaf whose hash was all-zeros —
//!   safe only because that is a preimage problem, which is not the kind of thing a commitment scheme should be resting
//!   on. `empty_root` is a domain-separated constant, and `verify` rejects `count == 0` outright: nothing is inside an
//!   empty tree, so there is no proof to check.
//!
//! ## Leaf hashing belongs to the caller
//!
//! This module hashes *already-hashed* leaves and owns only the internal-node and root labels. Each subsystem hashes its
//! own leaves under its own label (`leaf` is the helper), which keeps two properties: a leaf can never collide with an
//! internal node (different label), and a leaf of one subsystem can never be replayed as a leaf of another (different
//! label again). A single shared leaf label would silently give up the second.

use alloc::vec::Vec;

use crate::hash::{DIGEST_LEN, hash_labeled};

/// Label for an internal node — distinct from every caller's leaf label, which is what stops an internal node from being
/// presented as a leaf (the classic second-preimage attack on hash trees).
const NODE_LABEL: &str = "FANOS-v1/merkle-node";
/// Label for the count-binding root wrapper.
const ROOT_LABEL: &str = "FANOS-v1/merkle-root";
/// Label for the empty tree's root.
const EMPTY_LABEL: &str = "FANOS-v1/merkle-empty";

/// The largest leaf count this module commits to.
///
/// Bounded so a height always fits a `u8` and a proof always fits a small allocation: `2^32` leaves is 32 siblings, which
/// is already far past any use here (the largest caller is a block's cross-cell outbox). A count past this is refused
/// rather than truncated, because truncating a count silently would reintroduce exactly the ambiguity the count exists to
/// remove.
pub const MAX_LEAVES: u64 = 1 << 32;

/// Hash a leaf under the caller's own `domain`.
///
/// Use a label unique to the subsystem *and* the leaf type. Nothing forces this — a caller can hash its leaves however it
/// likes — but the guarantee that a leaf is neither an internal node nor another subsystem's leaf holds only if it does.
#[must_use]
pub fn leaf(domain: &str, bytes: &[u8]) -> [u8; DIGEST_LEN] {
    hash_labeled(domain, bytes)
}

/// The root of an empty tree — a domain-separated constant, deliberately not zeros.
#[must_use]
pub fn empty_root() -> [u8; DIGEST_LEN] {
    hash_labeled(EMPTY_LABEL, &[])
}

/// Hash two children into their parent.
#[must_use]
fn node(left: &[u8; DIGEST_LEN], right: &[u8; DIGEST_LEN]) -> [u8; DIGEST_LEN] {
    let mut buf = [0u8; DIGEST_LEN * 2];
    let (a, b) = buf.split_at_mut(DIGEST_LEN);
    a.copy_from_slice(left);
    b.copy_from_slice(right);
    hash_labeled(NODE_LABEL, &buf)
}

/// The number of sibling hashes a proof carries for a tree of `count` leaves: `ceil(log2(count))`, and `0` for a single
/// leaf (whose root is the leaf itself, wrapped).
///
/// This is the *exact* proof length `verify` demands, not an upper bound. A fixed shape per count is what turns a
/// malformed proof into a cheap rejection instead of a fold over attacker-chosen work.
#[must_use]
pub const fn height(count: u64) -> u32 {
    if count <= 1 {
        return 0;
    }
    // `ceil(log2(count))` for `count ≥ 2`: the bit width of `count - 1`, i.e. one more than its top bit's position.
    (count - 1).bit_width()
}

/// The Merkle root over `leaves`, binding the leaf count.
///
/// `None` if there are more than [`MAX_LEAVES`]. An empty sequence gives `empty_root`.
#[must_use]
pub fn root(leaves: &[[u8; DIGEST_LEN]]) -> Option<[u8; DIGEST_LEN]> {
    let count = u64::try_from(leaves.len()).ok()?;
    if count > MAX_LEAVES {
        return None;
    }
    if count == 0 {
        return Some(empty_root());
    }
    Some(wrap(count, fold(leaves)))
}

/// Bind the count to a bare fold. Two leaf sequences of different lengths cannot share a root, whatever the padding rule
/// does — which is the entire point of this wrapper.
#[must_use]
fn wrap(count: u64, bare: [u8; DIGEST_LEN]) -> [u8; DIGEST_LEN] {
    let mut buf = [0u8; 8 + DIGEST_LEN];
    let (c, b) = buf.split_at_mut(8);
    c.copy_from_slice(&count.to_be_bytes());
    b.copy_from_slice(&bare);
    hash_labeled(ROOT_LABEL, &buf)
}

/// Fold a non-empty leaf level to a single hash, duplicating an odd tail.
///
/// Duplication is safe here *because* the count is bound by [`wrap`]; on its own it is the CVE-2012-2459 shape. It is
/// preferred over promoting the odd node because it keeps the height a function of the count alone, which is what lets
/// `verify` demand an exact proof length.
#[must_use]
fn fold(leaves: &[[u8; DIGEST_LEN]]) -> [u8; DIGEST_LEN] {
    let mut level: Vec<[u8; DIGEST_LEN]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level.get(i).copied().unwrap_or_default();
            let right = level.get(i + 1).copied().unwrap_or(left);
            next.push(node(&left, &right));
            i += 2;
        }
        level = next;
    }
    level.first().copied().unwrap_or_else(empty_root)
}

/// The authentication path for the leaf at `index`: sibling hashes bottom-up, exactly `height` of them.
///
/// `None` if `index` is out of range or the tree is over-large.
#[must_use]
pub fn prove(leaves: &[[u8; DIGEST_LEN]], index: usize) -> Option<Vec<[u8; DIGEST_LEN]>> {
    let count = u64::try_from(leaves.len()).ok()?;
    if count > MAX_LEAVES || index >= leaves.len() {
        return None;
    }
    let mut path = Vec::with_capacity(height(count) as usize);
    let mut level: Vec<[u8; DIGEST_LEN]> = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        // The sibling, with the same duplicate-the-odd-tail rule `fold` applies: an unpaired node's sibling is itself.
        let sibling = if idx.is_multiple_of(2) {
            level.get(idx + 1).or_else(|| level.get(idx))
        } else {
            level.get(idx - 1)
        };
        path.push(sibling.copied().unwrap_or_else(empty_root));
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level.get(i).copied().unwrap_or_default();
            let right = level.get(i + 1).copied().unwrap_or(left);
            next.push(node(&left, &right));
            i += 2;
        }
        level = next;
        idx /= 2;
    }
    Some(path)
}

/// Whether `leaf` sits at `index` of a tree of `count` leaves whose root is `root`, under `siblings`.
///
/// Rejects, before hashing anything, every shape that cannot be a genuine opening: an empty tree (nothing is inside it),
/// an index past the count, and a proof whose length is not exactly `height``(count)`. That last check is what bounds
/// the work an unauthenticated peer can ask for — the previous per-subsystem verifiers folded however many siblings they
/// were handed.
#[must_use]
pub fn verify(
    leaf: [u8; DIGEST_LEN],
    index: u64,
    siblings: &[[u8; DIGEST_LEN]],
    root: &[u8; DIGEST_LEN],
    count: u64,
) -> bool {
    if count == 0 || count > MAX_LEAVES || index >= count {
        return false;
    }
    if u32::try_from(siblings.len()) != Ok(height(count)) {
        return false;
    }
    let mut acc = leaf;
    let mut idx = index;
    for sib in siblings {
        acc = if idx.is_multiple_of(2) { node(&acc, sib) } else { node(sib, &acc) };
        idx /= 2;
    }
    wrap(count, acc) == *root
}

#[cfg(test)]
// Test-local indexing into fixtures this module built itself, following the convention in `shamir`/`collections`: the
// bounds are visible at the call site, and `.get()` chains would obscure what each assertion is about.
#[allow(clippy::indexing_slicing)]
mod tests {
    use alloc::vec;

    use super::*;

    fn leaves(n: usize) -> Vec<[u8; DIGEST_LEN]> {
        (0..n).map(|i| leaf("FANOS-v1/test-leaf", &[u8::try_from(i).unwrap_or(0)])).collect()
    }

    #[test]
    fn every_leaf_of_every_size_opens_against_the_root() {
        for n in 1..=33usize {
            let ls = leaves(n);
            let Some(r) = root(&ls) else { unreachable!("{n} leaves is within MAX_LEAVES") };
            let count = n as u64;
            for (i, l) in ls.iter().enumerate() {
                let Some(p) = prove(&ls, i) else { unreachable!("index {i} is in range for {n}") };
                assert_eq!(p.len() as u32, height(count), "proof length must be the tree height at n={n}");
                assert!(verify(*l, i as u64, &p, &r, count), "leaf {i} of {n} must open");
            }
            assert!(prove(&ls, n).is_none(), "an out-of-range index has no proof");
        }
    }

    #[test]
    fn the_duplicate_tail_ambiguity_is_gone() {
        // THE defect this module exists to remove (CVE-2012-2459). Under duplicate-the-odd-tail padding the *bare* folds
        // of `[a, b, c]` and `[a, b, c, c]` are identical — one commitment for two different leaf sequences. Binding the
        // count separates them, so the padding rule stops carrying any security weight.
        let three = leaves(3);
        let mut four = three.clone();
        four.push(three[2]);
        assert_eq!(fold(&three), fold(&four), "the bare folds collide — this is the attack, unchanged");
        assert_ne!(root(&three), root(&four), "but the bound roots must not");

        // And the forged opening is rejected: the duplicate index does not exist at the real count.
        let Some(r) = root(&three) else { unreachable!() };
        let Some(p) = prove(&four, 3) else { unreachable!() };
        assert!(!verify(four[3], 3, &p, &r, 3), "an index past the committed count cannot open");
    }

    #[test]
    fn a_wrong_shaped_proof_is_rejected_before_any_hashing() {
        // The bound on attacker-chosen work: the previous verifiers folded however many siblings arrived (a `u16` count on
        // the wire ⇒ 65 535 hashes per receipt). The length is now part of what the commitment fixes.
        let ls = leaves(5);
        let Some(r) = root(&ls) else { unreachable!() };
        let Some(p) = prove(&ls, 0) else { unreachable!() };
        assert!(verify(ls[0], 0, &p, &r, 5), "the honest proof opens");

        let mut long = p.clone();
        long.push([7u8; DIGEST_LEN]);
        assert!(!verify(ls[0], 0, &long, &r, 5), "one sibling too many is refused");
        assert!(!verify(ls[0], 0, &p[..p.len() - 1], &r, 5), "one too few is refused");
        assert!(!verify(ls[0], 0, &vec![[0u8; DIGEST_LEN]; 65_535], &r, 5), "and a flood is refused, not folded");
    }

    #[test]
    fn an_empty_tree_has_a_domain_separated_root_that_opens_to_nothing() {
        // The old empty root was `[0u8; 32]`, so a certified empty outbox would accept any leaf hashing to all-zeros —
        // safe only by preimage resistance, which a commitment scheme should not be resting on.
        assert_ne!(empty_root(), [0u8; DIGEST_LEN], "the empty root must not be a value a leaf could take");
        assert_eq!(root(&[]), Some(empty_root()));
        assert!(!verify([0u8; DIGEST_LEN], 0, &[], &empty_root(), 0), "nothing is inside an empty tree");
        // Nor can the empty root be opened by claiming a non-zero count.
        assert!(!verify([0u8; DIGEST_LEN], 0, &[], &empty_root(), 1));
    }

    #[test]
    fn a_leaf_cannot_be_swapped_for_an_internal_node() {
        // Domain separation, stated as a test rather than a comment: an internal node's value is not a value any leaf
        // hashing can produce, so a two-leaf tree's root cannot be re-presented as a single leaf.
        let ls = leaves(2);
        let inner = node(&ls[0], &ls[1]);
        let Some(r) = root(&ls) else { unreachable!() };
        assert_ne!(inner, ls[0]);
        // The root of `[inner]` as a *leaf* differs from the root of `[a, b]`, though the bare folds agree by definition.
        assert_eq!(fold(&[inner]), fold(&ls), "the bare fold of one node equals the two-leaf fold");
        assert_ne!(root(&[inner]), Some(r), "but the counts differ, so the roots must too");
    }

    #[test]
    fn the_height_is_the_ceiling_of_the_log() {
        assert_eq!(height(0), 0);
        assert_eq!(height(1), 0, "a single leaf needs no siblings");
        assert_eq!(height(2), 1);
        assert_eq!(height(3), 2);
        assert_eq!(height(4), 2);
        assert_eq!(height(5), 3);
        assert_eq!(height(1 << 20), 20);
        assert_eq!(height((1 << 20) + 1), 21);
        assert_eq!(height(MAX_LEAVES), 32, "the bound keeps a height inside a u8");
    }

    #[test]
    fn an_over_large_tree_is_refused_rather_than_truncated() {
        // Not constructible in a test, so this pins the predicate instead: truncating a count would reintroduce exactly
        // the ambiguity the count exists to remove, so the answer is `None`/`false`, never a wrapped value.
        assert!(!verify([1u8; DIGEST_LEN], 0, &[], &[0u8; DIGEST_LEN], MAX_LEAVES + 1));
    }
}
