//! The **shielded note** — OBOLOS's unit of hidden value, and the two public objects it produces: its
//! commitment (the leaf appended to the [`crate::tree`]) and, when spent, its [`crate::nullifier::Nullifier`].
//!
//! A note binds an amount `value` (hidden by the value commitment), the recipient's `owner` nullifier-key tag
//! (whoever knows `nsk` with [`derive_owner_pk`]`(nsk) == owner` can *recognize and nullify* it), the recipient's
//! spend-authorization commitment `auth` (whoever holds the matching spend-auth key can *authorize a spend* by
//! signing — audit §5.D-2, a key **separate** from `nsk`), and per-note randomness `rho`. The note itself never
//! appears on the ledger; only its commitment (opaque) does, and — later — its nullifier (unlinkable). The two
//! keys are split so that a spend, which reveals the nullifier key, does **not** thereby confer spend authority:
//! a broadcast transaction cannot be re-authorized (its `public_recipient` swapped) or re-spent by an observer.

use alloc::vec::Vec;

use fanos_pqcrypto::rng::SeedRng;
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier};
use fanos_primitives::hash_labeled;

use crate::commit::{Commitment, Params, Randomness};
use crate::nullifier::Nullifier;

/// Domain-separation label for the one-time owner public key.
const OWNER_PK_LABEL: &str = "FANOS-obolos-v1/owner-pk";
/// Domain-separation label for the note commitment.
const NOTE_CM_LABEL: &str = "FANOS-obolos-v1/note-commitment";
/// Domain-separation label for the spend-authorization key commitment (audit §5.D-2).
const AUTH_COMMIT_LABEL: &str = "FANOS-obolos-v1/spend-auth-commit";

/// The **nullifier-key public tag** derived from the secret nullifier key `nsk`: `owner = H("owner-pk", nsk)`.
/// A note's `owner` records this tag; the holder of `nsk` recognizes and can nullify the note. Spending
/// additionally requires the separate **spend-authorization** key (see [`derive_spend_auth`]) — `nsk` alone is
/// no longer spend authority (audit §5.D-2), it is only the nullifier key.
#[must_use]
pub fn derive_owner_pk(nsk: &[u8; 32]) -> [u8; 32] {
    hash_labeled(OWNER_PK_LABEL, nsk)
}

/// Derive a recipient's **spend-authorization keypair** `(ask, ak)` deterministically from a `seed` — the
/// hybrid PQ signing secret and its verifier. A spend is authorized by a signature under `ask` over the
/// transaction's sighash (binding every public field, including `public_recipient`); the secret `ask` is
/// **never revealed** by a spend, so a broadcast transaction cannot be re-authorized to a different recipient
/// or re-spent by an observer who learns the (revealed) nullifier key (audit §5.D-2).
#[must_use]
pub fn derive_spend_auth(seed: &[u8]) -> (HybridSigSecret, HybridVerifier) {
    HybridSigSecret::generate(&mut SeedRng::from_seed(seed))
}

/// The 32-byte **spend-auth commitment** bound into a note's [`auth`](Note::auth): `H("…/spend-auth-commit",
/// ak)`. A note records this; a spend reveals the full verifier `ak` (checked against it) and a signature the
/// note's spend-auth key must have produced.
#[must_use]
pub fn spend_auth_commit(ak: &HybridVerifier) -> [u8; 32] {
    hash_labeled(AUTH_COMMIT_LABEL, &ak.encode())
}

/// A shielded note: a unit of hidden value held in the pool.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Note {
    /// The amount (hidden on the ledger by the value commitment).
    pub value: u64,
    /// The nullifier-key tag ([`derive_owner_pk`] of the holder's nullifier key) — who can *recognize and
    /// nullify* the note.
    pub owner: [u8; 32],
    /// The **spend-authorization commitment** ([`spend_auth_commit`] of the holder's spend-auth verifier) — the
    /// key that must *sign* to authorize a spend (audit §5.D-2). Distinct from `owner`, so revealing the
    /// nullifier key at spend time does not confer spend authority.
    pub auth: [u8; 32],
    /// The randomness hiding the amount in the value commitment.
    pub value_r: Randomness,
    /// Per-note uniqueness randomness (so equal-value notes to one owner differ).
    pub rho: [u8; 32],
}

impl Note {
    /// A note of `value` to `(owner, auth)`, with the given value-commitment randomness and per-note `rho`.
    #[must_use]
    pub fn new(value: u64, owner: [u8; 32], auth: [u8; 32], value_r: Randomness, rho: [u8; 32]) -> Self {
        Self { value, owner, auth, value_r, rho }
    }

    /// The note's value commitment `com(value; value_r)` — the amount, hidden but homomorphically combinable.
    #[must_use]
    pub fn value_commitment(&self, params: &Params) -> Commitment {
        Commitment::commit(params, self.value, &self.value_r)
    }

    /// The **note commitment** — the opaque leaf appended to the commitment tree:
    /// `cm = H("note-commitment", value_commitment ‖ owner ‖ auth ‖ rho)`. Binding (fixes value, owner, the
    /// spend-auth key, and rho) and hiding (reveals none of them). This is what the ledger stores and a spend
    /// proves membership of; binding `auth` is what ties the spend-authorization signature to *this* note.
    #[must_use]
    pub fn commitment(&self, params: &Params) -> [u8; 32] {
        let vc = self.value_commitment(params).to_bytes();
        let mut buf = Vec::with_capacity(vc.len() + 96);
        buf.extend_from_slice(&vc);
        buf.extend_from_slice(&self.owner);
        buf.extend_from_slice(&self.auth);
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
        let (_ask, ak) = derive_spend_auth(nsk); // a test derives the auth key from the same seed
        Note::new(value, derive_owner_pk(nsk), spend_auth_commit(&ak), Randomness::from_seed(tag), [3u8; 32])
    }

    #[test]
    fn ownership_is_exactly_knowledge_of_the_nullifier_key() {
        let nsk = [1u8; 32];
        let n = note(100, &nsk, b"r");
        assert!(n.is_owned_by(&nsk), "the holder of nsk recognizes the note");
        assert!(!n.is_owned_by(&[2u8; 32]), "a different key does not");
    }

    #[test]
    fn the_commitment_binds_value_owner_auth_and_rho() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let base = note(100, &nsk, b"r");
        let cm = base.commitment(&p);
        // A different amount, owner, auth, or rho changes the commitment.
        let diff_value = Note { value: 101, ..base.clone() };
        assert_ne!(cm, diff_value.commitment(&p), "amount is bound");
        let diff_owner = Note { owner: derive_owner_pk(&[9u8; 32]), ..base.clone() };
        assert_ne!(cm, diff_owner.commitment(&p), "owner is bound");
        let diff_auth = Note { auth: [0x5A; 32], ..base.clone() };
        assert_ne!(cm, diff_auth.commitment(&p), "the spend-auth key is bound");
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
