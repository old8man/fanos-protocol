//! The **confidential-amount proof** — the amount-privacy half of a shielded transfer, composing the two ring-ZK
//! primitives this crate builds: a [range proof](crate::ring_range_agg) per output and one [balance
//! proof](crate::ring_balance). Together they attest, in zero knowledge, that
//!
//! 1. **balance** — `Σ input values = Σ output values + fee` (no value is created), and
//! 2. **range** — every *output* amount is in `[0, MAX_VALUE)`,
//!
//! which is exactly what makes confidential amounts *sound*: balance alone holds only modulo `q`, so without the
//! range bound an output could commit a value near `q` (a "negative" amount) and forge money; the range proof
//! rules that out (audit O-C1). **Input** amounts need no range proof here — every input is a re-randomised
//! commitment to a note that was itself created as a range-proven output, so their range holds by induction over
//! the pool's history (the note's membership + nullifier, the *untraceability* half, is proven separately).
//!
//! Getting that right takes **three** bounds, not one — the range width must be the *verifier's* demand and not the
//! prover's claim, the cleartext fee must be bounded, and the number of value terms must be bounded. Each closes a
//! distinct modular-wraparound path; [`verify_amounts`] documents them, and each has a test that exhibits the
//! forging transaction it refuses.
//!
//! This is the ring-native successor to the amount checks the transparent [`crate::tx::TransparentProof`] does in
//! the clear (`Σin = Σout + fee` on revealed openings, `value < MAX_VALUE` per amount). Once the ledger's value
//! commitment migrates from the flat-vector [`crate::commit`] to [`crate::ring_commit`], this proof drops into the
//! shielded-transaction relation as the confidentiality component of `ConfidentialProof`, alongside the
//! untraceability proofs.
//!
//! > **STATUS — [P]/[H], correctness-first.** A composition of the underlying primitives; it inherits their status
//! > (parameters illustrative, not constant-time). Tests verify a balanced in-range transfer proves and verifies;
//! > that inflation, an out-of-range output, or a swapped commitment has no accepting proof; and that each of the
//! > three wraparound paths above is refused — the range-width test constructs the actual forging transaction and
//! > shows it is internally consistent, so that only the pinned width stands between it and the pool.

use alloc::vec::Vec;

use crate::ring_balance::{RingBalanceProof, prove_balance, verify_balance};
use crate::ring_commit::{MAX_NOTES_PER_TX, MAX_VALUE, RingCommitment, RingParams, RingRandomness};
use crate::ring_range_agg::{AggRangeProof, prove_range_agg, verify_range_agg};

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

/// The zero-knowledge confidential-amount proof: an aggregated range proof per output plus the transfer's balance
/// proof.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConfidentialAmountProof {
    output_ranges: Vec<AggRangeProof>,
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
        output_ranges.push(prove_range_agg(params, v, r, bits, &s)?);
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

/// Verify a [`prove_amounts`] proof against the public input and output value commitments and the fee, demanding
/// the range width `bits` (normally [`RANGE_BITS`] — consensus pins it; see below).
///
/// Three bounds together are what make the balance law sound over the integers rather than only modulo `q`
/// (audit O-C1). Each closes a distinct wraparound path, and dropping any one forges value:
///
/// - **the range width is the verifier's** — the proof carries its own width, so accepting that field would let the
///   prover choose the bound: four outputs each just under `2⁶²` sum to `q + ε ≡ ε`, balancing against an input worth
///   `ε` while being worth `≈2⁶⁴` in the pool;
/// - **the cleartext fee is bounded** — it has no range proof, so an unbounded `fee ≈ q` makes `Σin ≡ Σout + fee`
///   satisfiable with an output *larger* than its input (a "negative" fee), inflating by the difference;
/// - **the number of value terms is bounded** — even with every amount below `MAX_VALUE`, enough terms reach `q`;
///   [`MAX_NOTES_PER_TX`] is derived (`⌊q / MAX_VALUE⌋ − 2`) so no side of the law can.
///
/// Input amounts still need no range proof: every input is a re-randomised commitment to a note created as a
/// range-proven output, so their range holds by induction over the pool — *provided* issuance
/// ([`crate::ring_state::RingShieldedState::mint`]) respects `MAX_VALUE`, which is the monetary policy's duty.
#[must_use]
pub fn verify_amounts(
    params: &RingParams,
    input_commitments: &[RingCommitment],
    output_commitments: &[RingCommitment],
    fee: u64,
    bits: usize,
    proof: &ConfidentialAmountProof,
) -> bool {
    // Bound the cleartext fee and the number of value terms *first*, so neither side of the balance law can reach
    // `q` — and so an over-sized claim is refused before any expensive verification is attempted.
    if fee >= MAX_VALUE || input_commitments.len().saturating_add(output_commitments.len()) > MAX_NOTES_PER_TX {
        return false;
    }
    // One range proof per output, in order.
    if proof.output_ranges.len() != output_commitments.len() {
        return false;
    }
    for (range, com) in proof.output_ranges.iter().zip(output_commitments) {
        if !verify_range_agg(params, com, bits, range) {
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
    use crate::ring_commit::RANGE_BITS;

    // A small range width keeps the range proofs' packing cheap; the composition is identical at RANGE_BITS.
    const BITS: usize = 8;
    // The width a prover would pick to attempt wraparound inflation (the widest the proof system allows).
    const WIDE: usize = 62;

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
        assert!(verify_amounts(&params, &inputs, &outputs, 20, BITS, &proof), "the transfer verifies");
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
        assert!(!verify_amounts(&params, &inputs, &outputs, 20, BITS, &proof), "inflation is rejected");
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
        assert!(!verify_amounts(&params, &inputs, &outputs, 0, BITS, &proof), "an out-of-range output is rejected");
    }

    #[test]
    fn a_transfer_proves_and_verifies_at_the_protocol_range_width() {
        // The width consensus actually demands (`ring_tx` pins it), exercised directly: a balanced transfer with a
        // near-ceiling amount proves and verifies at RANGE_BITS. Because the range proof is *aggregated* its cost is
        // independent of the width, so the real ceiling is as cheap here as a toy one — which is what makes pinning
        // it free rather than a trade-off.
        let params = RingParams::standard();
        let big = MAX_VALUE - 1; // the largest legal amount
        let (r_in, c_in) = commit(&params, big, b"rb-in");
        let (r_o, c_o) = commit(&params, big - 7, b"rb-o");
        let (inputs, outputs) = ([c_in.clone()], [c_o]);
        let (input_r, output_r, output_values) = ([r_in], [r_o], [big - 7]);
        let witness = AmountWitness { input_r: &input_r, output_values: &output_values, output_r: &output_r, fee: 7 };
        let proof = prove_amounts(&params, &inputs, &witness, RANGE_BITS, b"rb").expect("proves at RANGE_BITS");
        assert!(verify_amounts(&params, &inputs, &outputs, 7, RANGE_BITS, &proof), "and verifies at RANGE_BITS");
        // MAX_VALUE itself is one too large: the reconstruction needs a 52nd bit, which the packing does not carry.
        let (r_over, c_over) = commit(&params, MAX_VALUE, b"rb-over");
        let over_values = [MAX_VALUE];
        let over_r = [r_over];
        let over = AmountWitness { input_r: &input_r, output_values: &over_values, output_r: &over_r, fee: 0 };
        let bad = prove_amounts(&params, core::slice::from_ref(&c_in), &over, RANGE_BITS, b"rb2").expect("emitted");
        assert!(
            !verify_amounts(&params, core::slice::from_ref(&c_in), &[c_over], 0, RANGE_BITS, &bad),
            "an amount at MAX_VALUE is out of range"
        );
    }

    #[test]
    fn a_prover_chosen_range_width_cannot_forge_value_by_wraparound() {
        // Audit O-C1, the attack the pinned range width closes. The range proof carries its own width, so a verifier
        // that trusted that field would let the PROVER choose the bound. At bits = 62, four outputs each just under
        // 2^62 sum to q + 100 ≡ 100 (mod q): they balance against an input worth 100 while being worth ≈2^64 in the
        // pool — value forged from nothing, with every individual check satisfied.
        let params = RingParams::standard();
        let big = (1u64 << WIDE) - 1;
        let mut values = alloc::vec![big; 3];
        // The fourth output makes the sum exactly q + 100, and is itself still < 2^62.
        values.push(crate::ring::Q.wrapping_add(100).wrapping_sub(big.wrapping_mul(3)));
        assert!(values.iter().all(|&v| v < (1u64 << WIDE)), "every output is within the wide range");
        assert_eq!(
            values.iter().fold(0u128, |a, &v| a + u128::from(v)),
            u128::from(crate::ring::Q) + 100,
            "…and they sum to q + 100, i.e. ≡ 100 (mod q)"
        );

        let (r_in, c_in) = commit(&params, 100, b"wrap-in");
        let (output_r, outputs): (Vec<_>, Vec<_>) = values
            .iter()
            .enumerate()
            .map(|(i, &v)| commit(&params, v, &alloc::format!("wrap-o{i}").into_bytes()))
            .unzip();
        let inputs = [c_in];
        let input_r = [r_in];
        let witness = AmountWitness { input_r: &input_r, output_values: &values, output_r: &output_r, fee: 0 };
        let proof = prove_amounts(&params, &inputs, &witness, WIDE, b"wrap").expect("the wide proof is emitted");

        // The attack is REAL: at the prover's own width the whole relation checks out — balance included.
        assert!(
            verify_amounts(&params, &inputs, &outputs, 0, WIDE, &proof),
            "the forging transaction is internally consistent — only the pinned width stops it"
        );
        // And it is refused at the protocol width, which is the only width consensus ever demands.
        assert!(
            !verify_amounts(&params, &inputs, &outputs, 0, RANGE_BITS, &proof),
            "a proof whose declared range width is not the protocol's is rejected"
        );
    }

    #[test]
    fn an_unbounded_fee_cannot_forge_value() {
        // The fee is a CLEARTEXT balance term with no range proof, so it must be bounded: with fee = q − 100,
        // Σin ≡ Σout + fee is satisfiable by an output *larger* than its input (a "negative" fee), inflating by 100.
        let params = RingParams::standard();
        let huge_fee = crate::ring::Q - 100;
        let (r_in, c_in) = commit(&params, 50, b"fee-in");
        let (r_o, c_o) = commit(&params, 150, b"fee-o"); // 150 out from a 50 input: 50 ≡ 150 + (q − 100) (mod q)
        let (inputs, outputs) = ([c_in], [c_o]);
        let (input_r, output_r, output_values) = ([r_in], [r_o], [150u64]);
        let witness =
            AmountWitness { input_r: &input_r, output_values: &output_values, output_r: &output_r, fee: huge_fee };
        let proof = prove_amounts(&params, &inputs, &witness, BITS, b"fee").expect("proof emitted");
        // Balance itself is satisfied modulo q — the bound is the only thing that refuses it.
        assert!(
            !verify_amounts(&params, &inputs, &outputs, huge_fee, BITS, &proof),
            "a fee at or above MAX_VALUE is rejected"
        );
        assert!(huge_fee >= MAX_VALUE, "…and that is precisely the bound being enforced");
    }

    #[test]
    fn the_note_count_bound_keeps_the_balance_sums_below_q() {
        // Even with every amount below MAX_VALUE, enough value terms reach q. MAX_NOTES_PER_TX is derived so they
        // cannot — check the derivation holds, then that the gate refuses an over-count (before any verification).
        assert!(
            u128::from(MAX_NOTES_PER_TX as u64) * u128::from(MAX_VALUE) < u128::from(crate::ring::Q),
            "MAX_NOTES_PER_TX · MAX_VALUE must stay below q, or a full transaction could wrap"
        );
        let params = RingParams::standard();
        let (r_in, c_in) = commit(&params, 10, b"cnt-in");
        let (r_o, c_o) = commit(&params, 10, b"cnt-o");
        let (input_r, output_r, output_values) = ([r_in], [r_o], [10u64]);
        let witness = AmountWitness { input_r: &input_r, output_values: &output_values, output_r: &output_r, fee: 0 };
        let proof = prove_amounts(&params, core::slice::from_ref(&c_in), &witness, BITS, b"cnt").expect("proof emitted");
        assert!(verify_amounts(&params, core::slice::from_ref(&c_in), core::slice::from_ref(&c_o), 0, BITS, &proof), "one-in/one-out is fine");
        // Claiming more value terms than the bound is refused outright.
        let too_many = alloc::vec![c_in; MAX_NOTES_PER_TX];
        assert!(
            !verify_amounts(&params, &too_many, &[c_o], 0, BITS, &proof),
            "a transaction with more value terms than MAX_NOTES_PER_TX is rejected"
        );
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
        assert!(!verify_amounts(&params, &inputs, &[c_other], 20, BITS, &proof), "the output commitment is bound in");
    }
}
