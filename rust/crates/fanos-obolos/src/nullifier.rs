//! **Nullifiers** — how OBOLOS makes a double-spend detectable while keeping the spent note untraceable.
//!
//! When a shielded note is spent, the spender reveals a **nullifier** — a pseudo-random tag derived from the
//! note's secret nullifier key, the note's **tree position**, and its commitment. Two properties, together, are
//! what let a public ledger enforce "spend once" over *private* notes (`spec/platform.md` §4.2):
//!
//! - **Deterministic** — the *same* note always yields the *same* nullifier, so spending it twice reveals the
//!   same tag and the second spend is rejected against the public [`NullifierSet`]. Double-spend is caught.
//! - **Unlinkable** — the nullifier is a keyed hash under the *secret* spending key `nsk`, so without `nsk`
//!   nobody can tell which note (which public commitment) a nullifier corresponds to, nor link two nullifiers
//!   of one owner. The note stays untraceable; only its *unspent-ness* is public.
//!
//! A shielded transaction's zero-knowledge proof (the frontier component, `spec/platform.md` §4.3) attests that
//! each revealed nullifier was computed correctly from a note the spender owns — so a nullifier can neither be
//! forged to frame an honest holder nor computed for a note one does not control.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use fanos_primitives::codec::{Reader, put_seq};
use fanos_primitives::hash_labeled;

/// Domain-separation label for nullifier derivation.
const NULLIFIER_LABEL: &str = "FANOS-obolos-v1/nullifier";
/// Domain-separation label for the nullifier-set commitment.
const NF_SET_ROOT_LABEL: &str = "FANOS-obolos-v1/nf-set-root";

/// A 32-byte nullifier — the public tag revealed when a note is spent.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Nullifier([u8; 32]);

impl Nullifier {
    /// Derive the nullifier of a note from its owner's secret nullifier key `nsk`, the note's tree `position`,
    /// and its commitment `cm`: `nf = H("…/nullifier", nsk ‖ position ‖ cm)`. Deterministic in
    /// `(nsk, position, cm)` (double-spend ⇒ repeated `nf`), a keyed hash under the secret `nsk` (unlinkable to
    /// the note without `nsk`), and — critically — **position-bound** (audit O-M1): every tree slot is unique,
    /// so two notes that happen to share a commitment (equal value/owner/auth/rho) still get *distinct*
    /// nullifiers and are both independently spendable, rather than one silently locking the other out.
    #[must_use]
    pub fn derive(nsk: &[u8; 32], position: u64, cm: &[u8; 32]) -> Self {
        let mut preimage = [0u8; 72];
        preimage[..32].copy_from_slice(nsk);
        preimage[32..40].copy_from_slice(&position.to_be_bytes());
        preimage[40..].copy_from_slice(cm);
        Self(hash_labeled(NULLIFIER_LABEL, &preimage))
    }

    /// The raw 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A nullifier from raw bytes (e.g. decoded off the wire).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// The public set of spent-note nullifiers — the ledger's double-spend guard.
///
/// A shielded spend is admitted only if every nullifier it reveals is **fresh** (unseen); the nullifiers are
/// then inserted. Because a note's nullifier is deterministic, re-spending it presents an already-present tag
/// and is rejected. The set is part of the executed state; [`root`](Self::root) commits to it for the block
/// `state_root`. (A production ledger may back this with an accumulator for succinct non-membership proofs; the
/// set here is the exact, canonical reference semantics.)
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct NullifierSet {
    seen: BTreeSet<[u8; 32]>,
}

impl NullifierSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self { seen: BTreeSet::new() }
    }

    /// Whether `nf` has already been spent.
    #[must_use]
    pub fn contains(&self, nf: &Nullifier) -> bool {
        self.seen.contains(&nf.0)
    }

    /// Insert `nf`, returning `true` if it was fresh (a valid spend) and `false` if it was already present
    /// (a **double-spend**, which the caller rejects). On `false` the set is unchanged.
    pub fn insert(&mut self, nf: Nullifier) -> bool {
        self.seen.insert(nf.0)
    }

    /// Whether **all** of `nullifiers` are fresh *and* pairwise-distinct — the precondition for admitting a
    /// spend that reveals several nullifiers at once, without mutating the set. A transaction that nullifies the
    /// same note twice within itself is as invalid as one that re-spends an already-seen note.
    #[must_use]
    pub fn all_fresh(&self, nullifiers: &[Nullifier]) -> bool {
        let mut within = BTreeSet::new();
        nullifiers.iter().all(|nf| !self.seen.contains(&nf.0) && within.insert(nf.0))
    }

    /// The number of spent notes recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether no note has been spent yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// A deterministic 32-byte commitment to the whole set, for the block `state_root`: the labeled hash of the
    /// nullifiers in canonical (sorted) order. Independent of insertion order, so every validator that spent the
    /// same set agrees on the same root.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(self.seen.len() * 32);
        for nf in &self.seen {
            buf.extend_from_slice(nf);
        }
        hash_labeled(NF_SET_ROOT_LABEL, &buf)
    }

    /// Canonical bytes for a state-sync snapshot ([`fanos_primitives::codec`]): the spent nullifiers in sorted
    /// order, so a restore reproduces the set and its [`root`](Self::root) exactly.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.seen.len() * 32);
        put_seq(&mut out, self.seen.len(), &self.seen, |o, nf| o.extend_from_slice(nf));
        out
    }

    /// Reconstruct a set from [`to_bytes`](Self::to_bytes), or `None` if malformed or truncated.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let seen = r.seq(32, Reader::array::<32>)?.into_iter().collect();
        r.finish()?;
        Some(Self { seen })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_nullifier_is_deterministic_in_the_note_and_key() {
        let nsk = [7u8; 32];
        let cm = [9u8; 32];
        assert_eq!(Nullifier::derive(&nsk, 0, &cm), Nullifier::derive(&nsk, 0, &cm), "same (nsk, cm) ⇒ same nullifier");
    }

    #[test]
    fn distinct_notes_or_keys_give_distinct_nullifiers() {
        let nsk = [7u8; 32];
        let cm = [9u8; 32];
        let base = Nullifier::derive(&nsk, 0, &cm);
        assert_ne!(base, Nullifier::derive(&[8u8; 32], 0, &cm), "a different spending key changes the nullifier");
        assert_ne!(base, Nullifier::derive(&nsk, 0, &[10u8; 32]), "a different note changes the nullifier");
        // Audit O-M1: the SAME key and commitment at a DIFFERENT tree position nullify distinctly, so two notes
        // that happen to collide on their commitment never share a nullifier (no silent spend-lock).
        assert_ne!(base, Nullifier::derive(&nsk, 1, &cm), "a different tree position changes the nullifier");
    }

    #[test]
    fn the_set_catches_a_double_spend() {
        let mut set = NullifierSet::new();
        let nf = Nullifier::derive(&[1u8; 32], 0, &[2u8; 32]);
        assert!(!set.contains(&nf));
        assert!(set.insert(nf), "a fresh nullifier is admitted");
        assert!(set.contains(&nf));
        assert!(!set.insert(nf), "re-spending the same note is rejected");
        assert_eq!(set.len(), 1, "the rejected double-spend did not grow the set");
    }

    #[test]
    fn all_fresh_rejects_seen_and_intra_transaction_repeats() {
        let mut set = NullifierSet::new();
        let a = Nullifier::derive(&[1u8; 32], 0, &[1u8; 32]);
        let b = Nullifier::derive(&[2u8; 32], 0, &[2u8; 32]);
        assert!(set.all_fresh(&[a, b]), "two distinct fresh nullifiers are admissible together");
        assert!(!set.all_fresh(&[a, a]), "a transaction cannot nullify the same note twice");
        set.insert(a);
        assert!(!set.all_fresh(&[a, b]), "an already-spent nullifier makes the batch inadmissible");
        assert!(set.all_fresh(&[b]), "the still-fresh one alone is fine");
    }

    #[test]
    fn the_set_root_is_order_independent_and_binds_the_contents() {
        let a = Nullifier::derive(&[1u8; 32], 0, &[1u8; 32]);
        let b = Nullifier::derive(&[2u8; 32], 0, &[2u8; 32]);
        let mut s1 = NullifierSet::new();
        s1.insert(a);
        s1.insert(b);
        let mut s2 = NullifierSet::new();
        s2.insert(b); // reverse insertion order
        s2.insert(a);
        assert_eq!(s1.root(), s2.root(), "the root is a function of the set, not the insertion order");
        let mut s3 = NullifierSet::new();
        s3.insert(a);
        assert_ne!(s1.root(), s3.root(), "a different set commits differently");
        assert_ne!(NullifierSet::new().root(), s3.root(), "the empty set differs from a non-empty one");
    }
}
