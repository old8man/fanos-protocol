//! The **transaction builder** — the wallet primitive that assembles a shielded transfer and its proof from
//! notes a holder controls. It is what a wallet calls to spend, and the ergonomic front door every
//! experiment/SecOps scenario ([`crate`] `tests/scenarios.rs`) uses to construct both honest and adversarial
//! transactions.
//!
//! For each spent input the builder derives the nullifier and the input value commitment; for each output it
//! derives the note and value commitments; and it packages the transparent witness (openings + paths) as the
//! [`TransparentProof`]. Swapping in the zero-knowledge backend (`spec/platform.md` §4.3) changes only the
//! proof object the builder returns — the transaction it builds is identical.

use alloc::vec::Vec;

use crate::commit::Params;
use crate::note::Note;
use crate::tree::AuthPath;
use crate::tx::{InputOpening, OutputNote, OutputOpening, ShieldedTx, TransparentProof};

/// One note being spent: the note, the secret spending key that authorises it, and its authentication path to
/// the transaction's anchor (obtained from [`crate::state::ShieldedState::path`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpendInput {
    /// The note to spend.
    pub note: Note,
    /// The owner's secret spending key.
    pub nsk: [u8; 32],
    /// The note's authentication path to `anchor`.
    pub path: AuthPath,
}

/// Build a shielded transfer of `inputs` into `outputs`, paying `fee`, proven against `anchor`, together with
/// the transparent proof of its correctness. The caller is responsible for value-conservation
/// (`Σ input.value = Σ output.value + fee`) and output ranges; an unbalanced or out-of-range set produces a
/// transaction whose proof will simply fail [`crate::tx::ShieldedProof::verify`] — which is precisely what a
/// scenario probing an inflation or wraparound attack wants to observe.
#[must_use]
pub fn build_transfer(
    params: &Params,
    anchor: [u8; 32],
    inputs: &[SpendInput],
    outputs: &[Note],
    fee: u64,
) -> (ShieldedTx, TransparentProof) {
    let nullifiers = inputs.iter().map(|i| i.note.nullifier(&i.nsk, params)).collect();
    let input_values = inputs.iter().map(|i| i.note.value_commitment(params)).collect();
    let output_notes: Vec<OutputNote> = outputs
        .iter()
        .map(|n| OutputNote { note_commitment: n.commitment(params), value_commitment: n.value_commitment(params) })
        .collect();
    let tx = ShieldedTx { anchor, nullifiers, input_values, outputs: output_notes, fee };

    let input_openings = inputs
        .iter()
        .map(|i| InputOpening { note: i.note.clone(), path: i.path.clone(), nsk: i.nsk })
        .collect();
    let output_openings =
        outputs.iter().map(|n| OutputOpening { value: n.value, value_r: n.value_r.clone() }).collect();
    let proof = TransparentProof { inputs: input_openings, outputs: output_openings };

    (tx, proof)
}
