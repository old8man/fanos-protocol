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
//! 3. **value binding** — each input value commitment commits to the spent note's amount;
//! 4. **balance** — `Σ inputs = Σ outputs + fee` on the value commitments (confidential amounts);
//! 5. **range** — every output amount is in `[0, MAX_VALUE)` (no modular-wraparound inflation).
//!
//! [`ShieldedProof`] is the seam. The production backend is a lattice/STARK zero-knowledge proof of exactly
//! this relation — the single frontier **[P]** component (`spec/platform.md` §4.3). The [`TransparentProof`]
//! here proves the *same relation in the clear* (revealing the witness), so the state machine
//! ([`crate::state`]) is verified end-to-end now, and the exact statement the ZK proof must attest is pinned in
//! code. It is not zero-knowledge — it is the accounting reference, the honest degraded-mode fallback, and the
//! oracle every adversarial scenario checks against.

use alloc::vec::Vec;

use crate::commit::{Commitment, MAX_VALUE, Params, Randomness, sum, sum_randomness, verify_balance};
use crate::note::Note;
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
    /// The public fee (paid to validators; the only cleartext amount).
    pub fee: u64,
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
/// anchor, and the secret spending key that authorises the spend.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InputOpening {
    /// The spent note.
    pub note: Note,
    /// Its authentication path to the transaction's anchor.
    pub path: AuthPath,
    /// The owner's secret spending key.
    pub nsk: [u8; 32],
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

        // Per-input: membership under the anchor, ownership, correct nullifier, and value-commitment binding.
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
            if &opening.note.value_commitment(params) != input_value {
                return false; // the input value commitment does not match the spent note's amount
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
        // recomputed from the revealed openings (Σ input_r − Σ output_r), so it cannot be gamed.
        let input_r: Vec<Randomness> = self.inputs.iter().map(|i| i.note.value_r.clone()).collect();
        let output_r: Vec<Randomness> = self.outputs.iter().map(|o| o.value_r.clone()).collect();
        let balance_r = sum_randomness(&input_r).sub(&sum_randomness(&output_r));
        let output_values: Vec<Commitment> = tx.outputs.iter().map(|o| o.value_commitment.clone()).collect();
        verify_balance(params, &tx.input_values, &output_values, tx.fee, &balance_r)
    }
}

/// The homomorphic sum of a transaction's declared input value commitments minus outputs minus fee — exposed
/// for scenario tooling that wants to inspect the balance term directly.
#[must_use]
pub fn balance_residual(tx: &ShieldedTx) -> Commitment {
    let outputs: Vec<Commitment> = tx.outputs.iter().map(|o| o.value_commitment.clone()).collect();
    sum(&tx.input_values).sub(&sum(&outputs)).sub(&Commitment::public_value(tx.fee))
}
