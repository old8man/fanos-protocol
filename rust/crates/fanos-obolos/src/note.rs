//! The **shielded note** — OBOLOS's unit of hidden value, and the two public objects it produces: its
//! commitment (the leaf appended to the [`crate::tree`]) and, when spent, its [`crate::nullifier::Nullifier`].
//!
//! A note binds an amount `value` (hidden by the value commitment), an `owner` one-time key (whoever knows the
//! secret spending key `nsk` with [`derive_owner_pk`]`(nsk) == owner` controls it), and per-note randomness
//! `rho` (so two notes of equal value to the same owner still differ). The note itself never appears on the
//! ledger; only its commitment (opaque) does, and — later — its nullifier (unlinkable). Recovering which note
//! a commitment or nullifier belongs to requires the owner's secret, which is the untraceability guarantee.

use alloc::vec::Vec;

use fanos_primitives::hash_labeled;

use crate::commit::{Commitment, Params, Randomness};
use crate::nullifier::Nullifier;

/// Domain-separation label for the one-time owner public key.
const OWNER_PK_LABEL: &str = "FANOS-obolos-v1/owner-pk";
/// Domain-separation label for the note commitment.
const NOTE_CM_LABEL: &str = "FANOS-obolos-v1/note-commitment";

/// The one-time **owner public key** derived from a secret spending key: `pk = H("owner-pk", nsk)`. A note is
/// controlled by whoever knows an `nsk` hashing to the note's `owner`. (The full stealth-address derivation —
/// where the sender computes a *fresh* per-payment owner key via ML-KEM so the recipient is unlinkable across
/// payments — composes on top in the next increment; this is its spend-authority core.)
#[must_use]
pub fn derive_owner_pk(nsk: &[u8; 32]) -> [u8; 32] {
    hash_labeled(OWNER_PK_LABEL, nsk)
}

/// A shielded note: a unit of hidden value held in the pool.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Note {
    /// The amount (hidden on the ledger by the value commitment).
    pub value: u64,
    /// The one-time owner key ([`derive_owner_pk`] of the holder's spending key).
    pub owner: [u8; 32],
    /// The randomness hiding the amount in the value commitment.
    pub value_r: Randomness,
    /// Per-note uniqueness randomness (so equal-value notes to one owner differ).
    pub rho: [u8; 32],
}

impl Note {
    /// A note of `value` to `owner`, with the given value-commitment randomness and per-note `rho`.
    #[must_use]
    pub fn new(value: u64, owner: [u8; 32], value_r: Randomness, rho: [u8; 32]) -> Self {
        Self { value, owner, value_r, rho }
    }

    /// The note's value commitment `com(value; value_r)` — the amount, hidden but homomorphically combinable.
    #[must_use]
    pub fn value_commitment(&self, params: &Params) -> Commitment {
        Commitment::commit(params, self.value, &self.value_r)
    }

    /// The **note commitment** — the opaque leaf appended to the commitment tree:
    /// `cm = H("note-commitment", value_commitment ‖ owner ‖ rho)`. Binding (fixes value, owner, rho) and
    /// hiding (reveals none of them). This is what the ledger stores and a spend proves membership of.
    #[must_use]
    pub fn commitment(&self, params: &Params) -> [u8; 32] {
        let vc = self.value_commitment(params).to_bytes();
        let mut buf = Vec::with_capacity(vc.len() + 64);
        buf.extend_from_slice(&vc);
        buf.extend_from_slice(&self.owner);
        buf.extend_from_slice(&self.rho);
        hash_labeled(NOTE_CM_LABEL, &buf)
    }

    /// The nullifier revealed when this note is spent, under the owner's secret spending key `nsk`.
    #[must_use]
    pub fn nullifier(&self, nsk: &[u8; 32], params: &Params) -> Nullifier {
        Nullifier::derive(nsk, &self.commitment(params))
    }

    /// Whether `nsk` is the secret spending key that controls this note.
    #[must_use]
    pub fn is_owned_by(&self, nsk: &[u8; 32]) -> bool {
        derive_owner_pk(nsk) == self.owner
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn note(value: u64, nsk: &[u8; 32], tag: &[u8]) -> Note {
        Note::new(value, derive_owner_pk(nsk), Randomness::from_seed(tag), [3u8; 32])
    }

    #[test]
    fn ownership_is_exactly_knowledge_of_the_spending_key() {
        let nsk = [1u8; 32];
        let n = note(100, &nsk, b"r");
        assert!(n.is_owned_by(&nsk), "the holder of nsk owns the note");
        assert!(!n.is_owned_by(&[2u8; 32]), "a different key does not own it");
    }

    #[test]
    fn the_commitment_binds_value_owner_and_rho() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let base = note(100, &nsk, b"r");
        let cm = base.commitment(&p);
        // A different amount, owner, or rho changes the commitment.
        let diff_value = Note { value: 101, ..base.clone() };
        assert_ne!(cm, diff_value.commitment(&p), "amount is bound");
        let diff_owner = Note { owner: derive_owner_pk(&[9u8; 32]), ..base.clone() };
        assert_ne!(cm, diff_owner.commitment(&p), "owner is bound");
        let diff_rho = Note { rho: [4u8; 32], ..base.clone() };
        assert_ne!(cm, diff_rho.commitment(&p), "rho is bound");
    }

    #[test]
    fn the_nullifier_is_the_owners_and_deterministic() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let n = note(100, &nsk, b"r");
        let nf = n.nullifier(&nsk, &p);
        assert_eq!(nf, n.nullifier(&nsk, &p), "deterministic");
        assert_eq!(nf, Nullifier::derive(&nsk, &n.commitment(&p)), "it is the nullifier of the note commitment");
    }
}
