//! The **confidential-amount proof** — the amount-privacy half of a shielded transfer, composing the two ring-ZK
//! primitives this crate builds: a [range proof](crate::ring_range) per output and one [balance
//! proof](crate::ring_balance). Together they attest, in zero knowledge, that
//!
//! 1. **balance** — `Σ input values = Σ output values + fee` (no value is created), and
//! 2. **range** — every *output* amount is in `[0, 2^bits)`,
//!
//! which is exactly what makes confidential amounts *sound*: balance alone holds only modulo `q`, so without the
//! range bound an output could commit a value near `q` (a "negative" amount) and forge money; the range proof
//! rules that out (audit O-C1). **Input** amounts need no range proof here — every input is a re-randomised
//! commitment to a note that was itself created as a range-proven output, so their range holds by induction over
//! the pool's history (the note's membership + nullifier, the *untraceability* half, is proven separately).
//!
//! This is the ring-native successor to the amount checks the transparent [`crate::tx::TransparentProof`] does in
//! the clear (`Σin = Σout + fee` on revealed openings, `value < MAX_VALUE` per amount). Once the ledger's value
//! commitment migrates from the flat-vector [`crate::commit`] to [`crate::ring_commit`], this proof drops into the
//! shielded-transaction relation as the confidentiality component of `ConfidentialProof`, alongside the
//! untraceability proofs.
//!
//! > **STATUS — [P]/[H], correctness-first.** A composition of the underlying primitives; it inherits their
//! > status (parameters illustrative, not constant-time, range proof not yet aggregated). Tests verify a balanced
//! > in-range transfer proves and verifies, and that inflation or an out-of-range output has no accepting proof.

use alloc::vec::Vec;

use crate::ring_balance::{RingBalanceProof, prove_balance, verify_balance};
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_range::{RangeProof, prove_range, verify_range};

/// A shielded transfer's **secret** amount witness: each input's re-randomised value commitment opening, and each
/// output's amount with its commitment randomness.
pub struct AmountWitness<'a> {
    /// The commitment randomness of each input value commitment (the amounts themselves are not needed — balance
    /// only combines randomness, and input range holds by induction).
    pub input_r: &'a [RingRandomness],
    /// Each output amount.
    pub output_values: &'a [u64],
    /// Each output's value-commitment randomness (same order as [`output_values`](Self::output_values)).
    pub output_r: &'a [RingRandomness],
    /// The public fee (a cleartext balance term).
    pub fee: u64,
}

/// The zero-knowledge confidential-amount proof: a range proof per output plus the transfer's balance proof.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConfidentialAmountProof {
    output_ranges: Vec<RangeProof>,
    balance: RingBalanceProof,
}

/// Prove a shielded transfer's amounts are confidential *and* sound: every output is in `[0, 2^bits)` and
/// `Σ inputs = Σ outputs + fee`. `input_commitments` are the public re-randomised input value commitments (the
/// prover holds their randomness in `witness.input_r`). `None` only on a sub-proof's rare masking exhaustion.
#[must_use]
pub fn prove_amounts(
    params: &RingParams,
    input_commitments: &[RingCommitment],
    witness: &AmountWitness<'_>,
    bits: usize,
    seed: &[u8],
) -> Option<ConfidentialAmountProof> {
    // Re-derive the output value commitments the prover is committing to.
    let output_commitments: Vec<RingCommitment> = witness
        .output_values
        .iter()
        .zip(witness.output_r)
        .map(|(&v, r)| RingCommitment::commit_message(params, &crate::ring::Poly::constant(v), r))
        .collect();

    // A range proof per output, domain-separated by index.
    let mut output_ranges = Vec::with_capacity(witness.output_values.len());
    for (i, (&v, r)) in witness.output_values.iter().zip(witness.output_r).enumerate() {
        let mut s = Vec::with_capacity(seed.len() + 12);
        s.extend_from_slice(seed);
        s.extend_from_slice(b"/range/");
        s.extend_from_slice(&(i as u64).to_le_bytes());
        output_ranges.push(prove_range(params, v, r, bits, &s)?);
    }

    // One balance proof over inputs, outputs, and the fee.
    let mut bseed = Vec::with_capacity(seed.len() + 8);
    bseed.extend_from_slice(seed);
    bseed.extend_from_slice(b"/balance");
    let balance = prove_balance(
        params,
        input_commitments,
        &output_commitments,
        witness.fee,
        witness.input_r,
        witness.output_r,
        &bseed,
    )?;

    Some(ConfidentialAmountProof { output_ranges, balance })
}

/// Verify a [`prove_amounts`] proof against the public input and output value commitments and the fee.
#[must_use]
pub fn verify_amounts(
    params: &RingParams,
    input_commitments: &[RingCommitment],
    output_commitments: &[RingCommitment],
    fee: u64,
    proof: &ConfidentialAmountProof,
) -> bool {
    // One range proof per output, in order.
    if proof.output_ranges.len() != output_commitments.len() {
        return false;
    }
    for (range, com) in proof.output_ranges.iter().zip(output_commitments) {
        if !verify_range(params, com, range) {
            return false;
        }
    }
    // The transfer balances.
    verify_balance(params, input_commitments, output_commitments, fee, &proof.balance)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::ring::Poly;

    // A small range width keeps the (unaggregated) range proofs fast; the composition is identical at RANGE_BITS.
    const BITS: usize = 8;

    /// Commit `value` and return `(randomness, commitment)`.
    fn commit(params: &RingParams, value: u64, seed: &[u8]) -> (RingRandomness, RingCommitment) {
        let r = RingRandomness::from_seed(seed);
        let c = RingCommitment::commit_message(params, &Poly::constant(value), &r);
        (r, c)
    }

    #[test]
    fn a_balanced_in_range_transfer_proves_and_verifies() {
        // 200 in → 150 + 30 out + 20 fee = 200, all amounts < 256.
        let params = RingParams::standard();
        let (r_in, c_in) = commit(&params, 200, b"amt-in");
        let (r_o1, c_o1) = commit(&params, 150, b"amt-o1");
        let (r_o2, c_o2) = commit(&params, 30, b"amt-o2");
        let (inputs, outputs) = ([c_in], [c_o1, c_o2]);
        let (input_r, output_r, output_values) = ([r_in], [r_o1, r_o2], [150u64, 30]);
        let witness = AmountWitness { input_r: &input_r, output_values: &output_values, output_r: &output_r, fee: 20 };
        let proof = prove_amounts(&params, &inputs, &witness, BITS, b"seed").expect("valid transfer");
        assert!(verify_amounts(&params, &inputs, &outputs, 20, &proof), "the transfer verifies");
    }

    #[test]
    fn an_inflating_transfer_has_no_accepting_proof() {
        // Outputs + fee sum to 201, inputs to 200: balance fails.
        let params = RingParams::standard();
        let (r_in, c_in) = commit(&params, 200, b"inf-in");
        let (r_o1, c_o1) = commit(&params, 151, b"inf-o1");
        let (r_o2, c_o2) = commit(&params, 30, b"inf-o2");
        let (inputs, outputs) = ([c_in], [c_o1, c_o2]);
        let (input_r, output_r, output_values) = ([r_in], [r_o1, r_o2], [151u64, 30]);
        let witness = AmountWitness { input_r: &input_r, output_values: &output_values, output_r: &output_r, fee: 20 };
        let proof = prove_amounts(&params, &inputs, &witness, BITS, b"seed").expect("proof emitted");
        assert!(!verify_amounts(&params, &inputs, &outputs, 20, &proof), "inflation is rejected");
    }

    #[test]
    fn an_out_of_range_output_has_no_accepting_proof() {
        // Output 300 ≥ 256 = 2^8: its range proof cannot hold, even though balance is satisfiable (inputs = 300).
        let params = RingParams::standard();
        let (r_in, c_in) = commit(&params, 300, b"oor-in");
        let (r_o1, c_o1) = commit(&params, 300, b"oor-o1");
        let (inputs, outputs) = ([c_in], [c_o1]);
        let (input_r, output_r, output_values) = ([r_in], [r_o1], [300u64]);
        let witness = AmountWitness { input_r: &input_r, output_values: &output_values, output_r: &output_r, fee: 0 };
        let proof = prove_amounts(&params, &inputs, &witness, BITS, b"seed").expect("proof emitted");
        assert!(!verify_amounts(&params, &inputs, &outputs, 0, &proof), "an out-of-range output is rejected");
    }

    #[test]
    fn a_swapped_output_commitment_is_rejected() {
        let params = RingParams::standard();
        let (r_in, c_in) = commit(&params, 100, b"sw-in");
        let (r_o1, c_o1) = commit(&params, 80, b"sw-o1");
        let (inputs, _outputs) = ([c_in], [c_o1]);
        let (input_r, output_r, output_values) = ([r_in], [r_o1], [80u64]);
        let witness = AmountWitness { input_r: &input_r, output_values: &output_values, output_r: &output_r, fee: 20 };
        let proof = prove_amounts(&params, &inputs, &witness, BITS, b"seed").unwrap();
        // Verify against a different output commitment: both the range proof and balance are bound to c_o1.
        let (_r, c_other) = commit(&params, 80, b"different");
        assert!(!verify_amounts(&params, &inputs, &[c_other], 20, &proof), "the output commitment is bound in");
    }
}
