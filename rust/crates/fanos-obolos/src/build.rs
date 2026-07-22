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

use crate::commit::{Commitment, Params, Randomness};
use crate::note::Note;
use crate::note_cipher::{Address, NoteCipher};
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
    // O-C2: each public input value commitment is a FRESH re-randomisation of the note's amount, so it cannot be
    // matched to the note's creation commitment. The randomness is derived per-input from spender-secret
    // material (production: a CSPRNG); it is revealed to the verifier in the input opening, never on the tx.
    let input_r: Vec<Randomness> = inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| {
            let mut seed = Vec::with_capacity(32 + 32 + 8);
            seed.extend_from_slice(&inp.nsk);
            seed.extend_from_slice(&inp.note.rho);
            seed.extend_from_slice(&(i as u64).to_le_bytes());
            Randomness::from_seed(&seed)
        })
        .collect();
    let input_values = inputs
        .iter()
        .zip(&input_r)
        .map(|(inp, r)| Commitment::commit(params, inp.note.value, r))
        .collect();
    let output_notes: Vec<OutputNote> = outputs
        .iter()
        .map(|n| OutputNote {
            note_commitment: n.commitment(params),
            value_commitment: n.value_commitment(params),
            cipher: None,
        })
        .collect();
    let tx =
        ShieldedTx { anchor, nullifiers, input_values, outputs: output_notes, fee, public_value: 0, public_recipient: [0u8; 32] };

    let input_openings = inputs
        .iter()
        .zip(input_r)
        .map(|(i, value_r_in)| InputOpening { note: i.note.clone(), path: i.path.clone(), nsk: i.nsk, value_r_in })
        .collect();
    let output_openings =
        outputs.iter().map(|n| OutputOpening { value: n.value, value_r: n.value_r.clone() }).collect();
    let proof = TransparentProof { inputs: input_openings, outputs: output_openings };

    (tx, proof)
}

/// Build an **unshield**: a shielded spend whose value partly (or wholly) *exits* the pool to a transparent
/// account. `public_value` leaves to `public_recipient`; any remainder stays shielded in `outputs`. The proof
/// enforces `Σ inputs = Σ shielded outputs + fee + public_value`, so value cannot be conjured on exit. The
/// transparent crediting of `public_recipient` is the enclosing ledger's responsibility (`fanos-dromos`).
#[must_use]
pub fn build_unshield(
    params: &Params,
    anchor: [u8; 32],
    inputs: &[SpendInput],
    outputs: &[Note],
    public_value: u64,
    public_recipient: [u8; 32],
    fee: u64,
) -> (ShieldedTx, TransparentProof) {
    let (mut tx, proof) = build_transfer(params, anchor, inputs, outputs, fee);
    tx.public_value = public_value;
    tx.public_recipient = public_recipient;
    (tx, proof)
}

/// Like [`build_transfer`], but each output is **delivered** to a recipient [`Address`]: its opening is sealed
/// as a [`NoteCipher`] so the recipient can find and spend it on-chain (unlinkable delivery, [`crate::note_cipher`]).
/// Each output's note must already be owned by its address (`note.owner == address.owner`); `cipher_seed` is the
/// per-output encapsulation randomness (production: a fresh CSPRNG; tests: a fixed seed, varied by output index).
/// The delivery cipher is ledger data-at-rest — it never affects the transaction's validity, only detectability.
#[must_use]
pub fn build_transfer_delivering(
    params: &Params,
    anchor: [u8; 32],
    inputs: &[SpendInput],
    outputs: &[(Note, Address)],
    fee: u64,
    cipher_seed: &[u8],
) -> (ShieldedTx, TransparentProof) {
    let notes: Vec<Note> = outputs.iter().map(|(n, _)| n.clone()).collect();
    let (mut tx, proof) = build_transfer(params, anchor, inputs, &notes, fee);
    for (i, (out, (note, address))) in tx.outputs.iter_mut().zip(outputs).enumerate() {
        let mut seed = cipher_seed.to_vec();
        seed.extend_from_slice(&(i as u64).to_le_bytes());
        out.cipher = NoteCipher::seal(address, note.value, &note.value_r, &note.rho, &seed);
    }
    (tx, proof)
}
