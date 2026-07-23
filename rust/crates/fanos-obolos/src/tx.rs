//! The **shielded transaction**, the [`ShieldedProof`] interface (behind which the frontier post-quantum
//! zero-knowledge proof lives), and a fully-verified **transparent** reference proof.
//!
//! A shielded transfer spends some input notes and creates some output notes, revealing on the ledger only:
//! the tree `anchor` its inputs are proven against, one **nullifier** per input, one re-randomised **value
//! commitment** per input (the balance term), the **output note commitments** and their value commitments, and
//! the public **fee**. A single proof `π` attests the relation binding these — *without revealing which notes
//! were spent, who owns them, or any amount*:
//!
//! 1. **membership** — each input's note commitment is a leaf under `anchor` (whole-pool untraceability);
//! 2. **ownership + nullifier** — the spender knows each input's spending key, and its nullifier is correct;
//! 3. **value binding** — each input value commitment is a *freshly re-randomised* commitment to the spent
//!    note's amount — never the note's *creation* commitment, so a spend is unlinkable to the note that made it;
//! 4. **balance** — `Σ inputs = Σ outputs + fee + public_value` on the value commitments (confidential amounts);
//! 5. **range + bound** — every input *and* output amount, the fee, and the public value are in `[0, MAX_VALUE)`,
//!    and the number of value terms is bounded (`≤ MAX_NOTES_PER_TX`) so no homomorphic sum wraps modulo `q` — the
//!    two constraints that together make modular-wraparound inflation impossible.
//!
//! [`ShieldedProof`] is the seam. The production backend is a lattice/STARK zero-knowledge proof of exactly
//! this relation — the single frontier **[P]** component (`spec/platform.md` §4.3). The [`TransparentProof`]
//! here proves the *same relation in the clear* (revealing the witness), so the state machine
//! ([`crate::state`]) is verified end-to-end now, and the exact statement the ZK proof must attest is pinned in
//! code. It is not zero-knowledge — it is the accounting reference, the honest degraded-mode fallback, and the
//! oracle every adversarial scenario checks against.

use alloc::vec::Vec;

use fanos_pqcrypto::{HybridSignature, HybridVerifier};
use fanos_primitives::hash_labeled;

use crate::commit::{Commitment, MAX_NOTES_PER_TX, MAX_VALUE, Params, Randomness, sum, sum_randomness, verify_balance};
use crate::note::{Note, spend_auth_commit};
use crate::note_cipher::NoteCipher;
use crate::nullifier::Nullifier;
use crate::tree::AuthPath;

/// Domain-separation label for the transaction **sighash** — the message a spend-auth signature covers.
const SIGHASH_LABEL: &str = "FANOS-obolos-v1/tx-sighash";

/// A new note created by a transaction, as it appears on the ledger: the opaque note commitment (appended to
/// the tree) and its value commitment (a balance term). *(A note-ciphertext sealed to the recipient, so they
/// can detect and later spend the output, composes on top with stealth addresses — the next increment.)*
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutputNote {
    /// The note commitment appended to the tree.
    pub note_commitment: [u8; 32],
    /// The output amount's value commitment (hidden; a balance term).
    pub value_commitment: Commitment,
    /// The note's opening, sealed to the recipient for unlinkable delivery ([`crate::note_cipher`]), or `None`
    /// for an output the sender need not deliver (e.g. change to itself, which it can reconstruct). It is
    /// *data at rest* on the ledger — the consensus relation ([`ShieldedProof`]) does not depend on it, so its
    /// presence or contents can never affect a transaction's validity, only whether a recipient can find it.
    pub cipher: Option<NoteCipher>,
}

/// A shielded transaction — the public object ordered by consensus and applied to the [`crate::state`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShieldedTx {
    /// The commitment-tree root the inputs are proven to be members of.
    pub anchor: [u8; 32],
    /// One nullifier per spent input (double-spend guard; unlinkable to the note).
    pub nullifiers: Vec<Nullifier>,
    /// One value commitment per spent input (the balance term for the inputs).
    pub input_values: Vec<Commitment>,
    /// The created notes.
    pub outputs: Vec<OutputNote>,
    /// The public fee (paid to validators; a cleartext balance term).
    pub fee: u64,
    /// A **public output value** — an amount leaving the shielded pool to a transparent account (an *unshield*).
    /// `0` for a pure shielded transfer. Like the fee, it is a cleartext balance term: the proof enforces
    /// `Σ inputs = Σ shielded outputs + fee + public_value`, so value cannot be conjured on exit. The transparent
    /// crediting of [`public_recipient`](Self::public_recipient) is the enclosing ledger's job, not the pool's.
    pub public_value: u64,
    /// The transparent account credited with [`public_value`](Self::public_value) on an unshield (ignored when
    /// `public_value == 0`).
    pub public_recipient: [u8; 32],
    /// One **spend-authorization signature** per spent input (same order as [`nullifiers`](Self::nullifiers)),
    /// each a [`HybridSignature::to_bytes`] encoding over the transaction [`sighash`](Self::sighash) — which
    /// binds *every* public field, including `public_recipient`. A spend is authorized only by the note's
    /// spend-auth key, whose secret a spend never reveals, so a broadcast transaction can be neither redirected
    /// to a different `public_recipient` nor re-spent by an observer (audit §5.D-2). Public and backend-agnostic:
    /// the zero-knowledge backend keeps these on the transaction unchanged. Stored as bytes because
    /// [`HybridSignature`] is not `Eq`.
    pub spend_auths: Vec<Vec<u8>>,
}

impl ShieldedTx {
    /// The transaction **sighash**: a domain-separated hash of every public field **except** the
    /// [`spend_auths`](Self::spend_auths) themselves (which sign it). This is the message each spend-auth
    /// signature covers; changing any bound field — most importantly `public_recipient` on an unshield —
    /// changes the sighash and invalidates every signature, and the signer's secret is never revealed, so the
    /// binding cannot be reforged (audit §5.D-2).
    #[must_use]
    pub fn sighash(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.anchor);
        for nf in &self.nullifiers {
            buf.extend_from_slice(nf.as_bytes());
        }
        for c in &self.input_values {
            buf.extend_from_slice(&c.to_bytes());
        }
        for o in &self.outputs {
            buf.extend_from_slice(&o.note_commitment);
            buf.extend_from_slice(&o.value_commitment.to_bytes());
        }
        buf.extend_from_slice(&self.fee.to_be_bytes());
        buf.extend_from_slice(&self.public_value.to_be_bytes());
        buf.extend_from_slice(&self.public_recipient);
        hash_labeled(SIGHASH_LABEL, &buf)
    }
}

/// A proof that a [`ShieldedTx`] satisfies the shielded-transfer relation. The production implementation is a
/// post-quantum zero-knowledge proof (**[P]**, `spec/platform.md` §4.3); [`TransparentProof`] is the
/// fully-verified transparent reference.
pub trait ShieldedProof {
    /// Whether the transaction's relation holds (membership, ownership, nullifier correctness, value binding,
    /// balance, output range, and **randomness shortness** — every opening's commitment randomness is ternary,
    /// §3.2) with respect to `params`. The **freshness** of the nullifiers (no double-spend) is checked by the
    /// state machine against its nullifier set, not here.
    #[must_use]
    fn verify(&self, params: &Params, tx: &ShieldedTx) -> bool;
}

/// The opening of one spent input, revealed by a [`TransparentProof`]: the note, its authentication path to the
/// anchor, the secret spending key that authorises the spend, and the **fresh randomness** re-randomising the
/// input's value commitment.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InputOpening {
    /// The spent note.
    pub note: Note,
    /// Its authentication path to the transaction's anchor.
    pub path: AuthPath,
    /// The owner's secret **nullifier** key (recognizes + nullifies the note; NOT spend authority — §5.D-2).
    pub nsk: [u8; 32],
    /// The note's spend-auth **verifier** `ak` (public), as [`HybridVerifier::encode`] bytes: checked against
    /// the note's committed [`auth`](Note::auth), and the key each [`spend_auths`](ShieldedTx::spend_auths)
    /// signature must verify under. The matching secret `ask` is never revealed — that is what makes the spend
    /// non-malleable. Bytes because [`HybridVerifier`] is not `Eq`.
    pub ak: Vec<u8>,
    /// The randomness of the **re-randomised** input value commitment `com(value; value_r_in)` published on the
    /// public tx — distinct from the note's creation randomness `note.value_r`, so the spend's public
    /// `input_value` cannot be matched to the note's creation commitment (audit O-C2, the Zcash-Orchard pattern).
    pub value_r_in: Randomness,
}

/// The opening of one output, revealed by a [`TransparentProof`]: the amount and its commitment randomness (so
/// the verifier can check the range and the value-commitment binding in the clear).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutputOpening {
    /// The output amount.
    pub value: u64,
    /// Its value-commitment randomness.
    pub value_r: Randomness,
}

/// A **transparent** (non-zero-knowledge) proof: it reveals the whole witness and checks the shielded-transfer
/// relation in the clear. It proves exactly what the zero-knowledge backend must, so the state machine is
/// verified end-to-end — but it does *not* hide the witness, so it provides accounting soundness, not privacy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransparentProof {
    /// One opening per spent input (same order as [`ShieldedTx::nullifiers`] and `input_values`).
    pub inputs: Vec<InputOpening>,
    /// One opening per output (same order as [`ShieldedTx::outputs`]).
    pub outputs: Vec<OutputOpening>,
}

impl ShieldedProof for TransparentProof {
    fn verify(&self, params: &Params, tx: &ShieldedTx) -> bool {
        // Arities must line up across the public tx and the revealed witness — including one spend-auth
        // signature per input (audit §5.D-2).
        let n_in = tx.nullifiers.len();
        if self.inputs.len() != n_in || tx.input_values.len() != n_in || tx.spend_auths.len() != n_in {
            return false;
        }
        if self.outputs.len() != tx.outputs.len() {
            return false;
        }
        // Bound the number of value terms so the homomorphic balance sums cannot wrap modulo q (audit O-C1) —
        // and bound the two clear terms (fee, public_value) below MAX_VALUE, which the loops below enforce for
        // every input and output amount. Together these keep both sides of the balance law under q.
        if n_in + tx.outputs.len() > MAX_NOTES_PER_TX || tx.fee >= MAX_VALUE || tx.public_value >= MAX_VALUE {
            return false;
        }
        // §3.2: every revealed opening's randomness is part of the relation and MUST be ternary — the shortness
        // the commitment scheme assumes and the bound that keeps `A₁·r` from overflowing `i128` inside `commit`
        // (below). The wire decoder already rejects long randomness, so re-asserting it here makes the relation
        // explicit and closes any non-wire construction path before a long coefficient reaches the dot product.
        let short = |r: &Randomness| r.is_ternary();
        if !self.inputs.iter().all(|i| short(&i.value_r_in) && short(&i.note.value_r))
            || !self.outputs.iter().all(|o| short(&o.value_r))
        {
            return false;
        }

        // The message every spend-auth signature must cover — binds `public_recipient` and every other public
        // field, so the authorization is non-malleable (audit §5.D-2).
        let sighash = tx.sighash();
        // Per-input: membership under the anchor, nullifier-key recognition, correct nullifier, spend
        // AUTHORIZATION (the key committed in the note signed *this* transaction), range, value-commitment binding.
        for (((opening, nf), input_value), spend_auth) in
            self.inputs.iter().zip(&tx.nullifiers).zip(&tx.input_values).zip(&tx.spend_auths)
        {
            let cm = opening.note.commitment(params);
            if !opening.path.verify(&cm, &tx.anchor) {
                return false; // the note is not a member of the tree at this anchor
            }
            if !opening.note.is_owned_by(&opening.nsk) {
                return false; // the revealed nullifier key does not recognize the note
            }
            if &Nullifier::derive(&opening.nsk, &cm) != nf {
                return false; // the nullifier is not the note's (no forged/mismatched nullifier)
            }
            // §5.D-2: the revealed verifier `ak` must be the one committed in the note, AND it must have signed
            // THIS transaction's sighash. The secret `ask` is never revealed, so an attacker who copies the tx
            // cannot swap `public_recipient` (that changes the sighash, invalidating the signature) nor re-spend
            // the note (spending needs a fresh signature under `ask`). Revealing `nsk` no longer confers spend.
            let (Some(ak), Some(sig)) =
                (HybridVerifier::decode(&opening.ak), HybridSignature::from_bytes(spend_auth))
            else {
                return false; // a malformed verifier or signature encoding
            };
            if opening.note.auth != spend_auth_commit(&ak) {
                return false; // the revealed spend-auth verifier is not the one the note commits to
            }
            if !ak.verify(&sighash, &sig) {
                return false; // the spend-auth signature does not authorize this exact transaction
            }
            if opening.note.value >= MAX_VALUE {
                return false; // O-C1: an out-of-range INPUT could forge value via q-wraparound in the sum
            }
            // O-C2: the public input value commitment is a fresh re-randomisation com(value; value_r_in), bound
            // here to the spent note's amount — NOT the note's creation value_commitment, which would let anyone
            // match the spend to the note that created it.
            if &Commitment::commit(params, opening.note.value, &opening.value_r_in) != input_value {
                return false; // the re-randomised input value commitment does not commit to the note's amount
            }
        }

        // Per-output: range (no modular-wraparound "negative" value) and value-commitment binding.
        for (opening, output) in self.outputs.iter().zip(&tx.outputs) {
            if opening.value >= MAX_VALUE {
                return false; // out of range → could forge value via q-wraparound
            }
            if Commitment::commit(params, opening.value, &opening.value_r) != output.value_commitment {
                return false; // the output value commitment does not open to the claimed amount
            }
        }

        // Balance on the value commitments alone: Σ inputs = Σ outputs + fee. The balance randomness is
        // recomputed from the revealed openings (Σ input value_r_in − Σ output value_r), so it cannot be gamed.
        let input_r: Vec<Randomness> = self.inputs.iter().map(|i| i.value_r_in.clone()).collect();
        let output_r: Vec<Randomness> = self.outputs.iter().map(|o| o.value_r.clone()).collect();
        let balance_r = sum_randomness(&input_r).sub(&sum_randomness(&output_r));
        let output_values: Vec<Commitment> = tx.outputs.iter().map(|o| o.value_commitment.clone()).collect();
        // The clear balance term is the fee plus any public (unshielded) output — both leave the shielded value.
        verify_balance(params, &tx.input_values, &output_values, tx.fee.saturating_add(tx.public_value), &balance_r)
    }
}

/// The homomorphic sum of a transaction's declared input value commitments minus outputs minus fee — exposed
/// for scenario tooling that wants to inspect the balance term directly.
#[must_use]
pub fn balance_residual(tx: &ShieldedTx) -> Commitment {
    let outputs: Vec<Commitment> = tx.outputs.iter().map(|o| o.value_commitment.clone()).collect();
    sum(&tx.input_values).sub(&sum(&outputs)).sub(&Commitment::public_value(tx.fee))
}
