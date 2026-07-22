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

use crate::commit::{Commitment, MAX_NOTES_PER_TX, MAX_VALUE, Params, Randomness, sum, sum_randomness, verify_balance};
use crate::note::Note;
use crate::note_cipher::NoteCipher;
use crate::nullifier::Nullifier;
use crate::tree::AuthPath;

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
}

/// A proof that a [`ShieldedTx`] satisfies the shielded-transfer relation. The production implementation is a
/// post-quantum zero-knowledge proof (**[P]**, `spec/platform.md` §4.3); [`TransparentProof`] is the
/// fully-verified transparent reference.
pub trait ShieldedProof {
    /// Whether the transaction's relation holds (membership, ownership, nullifier correctness, value binding,
    /// balance, and output range) with respect to `params`. The **freshness** of the nullifiers (no
    /// double-spend) is checked by the state machine against its nullifier set, not here.
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
    /// The owner's secret spending key.
    pub nsk: [u8; 32],
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
        // Arities must line up across the public tx and the revealed witness.
        let n_in = tx.nullifiers.len();
        if self.inputs.len() != n_in || tx.input_values.len() != n_in {
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

        // Per-input: membership under the anchor, ownership, correct nullifier, range, and value-commitment binding.
        for ((opening, nf), input_value) in self.inputs.iter().zip(&tx.nullifiers).zip(&tx.input_values) {
            let cm = opening.note.commitment(params);
            if !opening.path.verify(&cm, &tx.anchor) {
                return false; // the note is not a member of the tree at this anchor
            }
            if !opening.note.is_owned_by(&opening.nsk) {
                return false; // the spend key does not control the note (no theft)
            }
            if &Nullifier::derive(&opening.nsk, &cm) != nf {
                return false; // the nullifier is not the note's (no forged/mismatched nullifier)
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
