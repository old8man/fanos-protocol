//! The **zero-knowledge balance proof** for a shielded transfer over the ring-BDLOP commitment
//! ([`crate::ring_commit`]) — the confidentiality upgrade of the in-the-clear [`crate::ring_commit::verify_balance`].
//!
//! A transfer balances iff `Σ inputs = Σ outputs + fee`. On the additively-homomorphic commitments this is exactly
//! the statement that the **balance residual**
//!
//! ```text
//! diff = Σ input_commitments − Σ output_commitments − com(fee)
//! ```
//!
//! **opens to zero** — its amount cancels, leaving `diff = com(0; r_balance)` for the *balance randomness*
//! `r_balance = Σ r_in − Σ r_out`. The transparent check reveals `r_balance` and re-derives `diff`; that leaks a
//! quantity linear in the per-note randomness, a correlation an observer could exploit. Here we instead attach a
//! [`crate::ring_zk`] **opening-to-zero proof**: the prover proves *knowledge* of a short `r_balance` opening
//! `diff` to `0`, revealing nothing about it. The verifier recomputes `diff` from the public commitments and the
//! public fee — already on the transaction — and checks the proof.
//!
//! - **Soundness.** The commitment is binding, so a short opening of `diff` to `0` exists iff `diff` commits to
//!   `0`, i.e. iff `Σ v_in ≡ Σ v_out + fee (mod q)`. (Ruling out the modular *wrap* — an unbalanced transfer whose
//!   amounts are congruent mod `q` — is the job of the range proof and the `≤ MAX_NOTES_PER_TX` bound, the frontier
//!   [P] components, exactly as for the transparent proof.)
//! - **Zero-knowledge.** Inherited from the opening proof: the revealed `(challenge, z)` is simulatable from the
//!   public `diff` alone, so `r_balance` — and thus the per-note randomness linkage — stays hidden.
//!
//! The **norm regime** is not ternary: `r_balance` is a signed sum of up to `#notes` ternaries, so
//! `‖r_balance‖∞ ≤ #notes`. Both prover and verifier derive the same
//! [`OpeningParams::for_randomness_bound`]`(#notes)` from the public note count — no regime data rides on the wire.
//!
//! > **STATUS — [P]/[H], correctness-first (as the rest of the ring stack).** The construction is the security
//! > spec; the tests verify completeness (a balanced transfer proves and verifies), soundness (an inflating
//! > transfer has no accepting proof), fee/tamper rejection, and zero-knowledge re-randomisation — never
//! > bit-security.

use alloc::vec::Vec;

use crate::ring::Poly;
use crate::ring_commit::{ELL, RingCommitment, RingParams, RingRandomness, sum};
use crate::ring_zk::{OpeningParams, RingOpeningProof, prove_opening, verify_opening};

/// A zero-knowledge proof that a shielded transfer balances: an opening-to-zero proof of the balance residual.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingBalanceProof(RingOpeningProof);

/// The balance residual `Σ inputs − Σ outputs − com(fee)` — the commitment a balanced transfer opens to zero.
fn residual(inputs: &[RingCommitment], outputs: &[RingCommitment], fee: u64) -> RingCommitment {
    sum(inputs).sub(&sum(outputs)).sub(&RingCommitment::public_value(fee))
}

/// The norm regime for a balance opening: `r_balance` is a signed sum of `#notes` ternaries, so its infinity norm
/// is at most the note count. Both parties compute this from the (public) number of input and output commitments.
fn regime(n_inputs: usize, n_outputs: usize) -> OpeningParams {
    OpeningParams::for_randomness_bound((n_inputs + n_outputs) as i64)
}

/// The component-wise sum `Σ` of a set of randomnesses (the balance randomness combines these).
fn sum_components(rs: &[RingRandomness]) -> Vec<Poly> {
    rs.iter().fold(alloc::vec![Poly::zero(); ELL], |acc, r| {
        acc.iter().zip(r.components()).map(|(a, b)| a.add(b)).collect()
    })
}

/// Prove, in zero knowledge, that the transfer balances: `Σ inputs = Σ outputs + fee`. `input_r`/`output_r` are the
/// randomnesses of the respective public value commitments (the prover holds them). `None` only on the opening
/// proof's rare masking exhaustion. The caller is responsible for the `≤ MAX_NOTES_PER_TX` bound that keeps the
/// homomorphic sums from wrapping `q`.
#[must_use]
pub fn prove_balance(
    params: &RingParams,
    inputs: &[RingCommitment],
    outputs: &[RingCommitment],
    fee: u64,
    input_r: &[RingRandomness],
    output_r: &[RingRandomness],
    seed: &[u8],
) -> Option<RingBalanceProof> {
    let diff = residual(inputs, outputs, fee);
    // r_balance = Σ r_in − Σ r_out (component-wise). A balanced transfer makes `diff` open to 0 under it.
    let sum_in = sum_components(input_r);
    let sum_out = sum_components(output_r);
    let r_balance = RingRandomness::from_components(sum_in.iter().zip(&sum_out).map(|(a, b)| a.sub(b)).collect());
    let regime = regime(inputs.len(), outputs.len());
    prove_opening(params, &diff, 0, &r_balance, &regime, seed).map(RingBalanceProof)
}

/// Verify a [`prove_balance`] proof against the public commitments and fee (all already on the transaction).
#[must_use]
pub fn verify_balance(
    params: &RingParams,
    inputs: &[RingCommitment],
    outputs: &[RingCommitment],
    fee: u64,
    proof: &RingBalanceProof,
) -> bool {
    let diff = residual(inputs, outputs, fee);
    verify_opening(params, &diff, 0, &proof.0, &regime(inputs.len(), outputs.len()))
}

impl RingBalanceProof {
    /// Canonical bytes (the underlying opening proof).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Decode from [`to_bytes`](Self::to_bytes).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        RingOpeningProof::from_bytes(bytes).map(Self)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A 1000 → 700 + 250 + 50-fee transfer: three commitments and their randomnesses.
    fn transfer() -> (RingParams, Vec<RingCommitment>, Vec<RingCommitment>, u64, Vec<RingRandomness>, Vec<RingRandomness>)
    {
        let params = RingParams::standard();
        let r_in = RingRandomness::from_seed(b"bal-in");
        let r_o1 = RingRandomness::from_seed(b"bal-o1");
        let r_o2 = RingRandomness::from_seed(b"bal-o2");
        let inputs = alloc::vec![RingCommitment::commit(&params, 1000, &r_in)];
        let outputs = alloc::vec![
            RingCommitment::commit(&params, 700, &r_o1),
            RingCommitment::commit(&params, 250, &r_o2),
        ];
        (params, inputs, outputs, 50, alloc::vec![r_in], alloc::vec![r_o1, r_o2])
    }

    #[test]
    fn a_balanced_transfer_proves_and_verifies_without_revealing_the_randomness() {
        let (params, inputs, outputs, fee, in_r, out_r) = transfer();
        let proof = prove_balance(&params, &inputs, &outputs, fee, &in_r, &out_r, b"seed").expect("balances");
        assert!(verify_balance(&params, &inputs, &outputs, fee, &proof), "the balanced transfer verifies");
        // Zero-knowledge: a different seed gives a different (re-randomised) proof that still verifies — the proof
        // is not a deterministic function of the secret balance randomness.
        let proof2 = prove_balance(&params, &inputs, &outputs, fee, &in_r, &out_r, b"seed2").expect("balances");
        assert_ne!(proof.to_bytes(), proof2.to_bytes(), "re-randomised");
        assert!(verify_balance(&params, &inputs, &outputs, fee, &proof2));
    }

    #[test]
    fn an_inflating_transfer_has_no_accepting_proof() {
        // Claim fee 51 while the amounts sum to a 50 fee: the residual no longer opens to zero, so even the
        // honestly-computed balance randomness yields a proof the verifier rejects (and a verifier asked to check
        // the true fee against a proof built for a different fee also rejects).
        let (params, inputs, outputs, _fee, in_r, out_r) = transfer();
        let proof_51 = prove_balance(&params, &inputs, &outputs, 51, &in_r, &out_r, b"seed").expect("proof emitted");
        assert!(!verify_balance(&params, &inputs, &outputs, 51, &proof_51), "an inflated fee cannot be proven");
        // A proof built for the true fee does not certify a different claimed fee.
        let proof_50 = prove_balance(&params, &inputs, &outputs, 50, &in_r, &out_r, b"seed").expect("balances");
        assert!(!verify_balance(&params, &inputs, &outputs, 51, &proof_50), "the fee is bound into the residual");
    }

    #[test]
    fn a_tampered_output_set_is_rejected() {
        let (params, inputs, outputs, fee, in_r, out_r) = transfer();
        let proof = prove_balance(&params, &inputs, &outputs, fee, &in_r, &out_r, b"seed").unwrap();
        // Swap an output commitment for one to a different amount: the residual changes, the proof fails.
        let mut tampered = outputs.clone();
        tampered[0] = RingCommitment::commit(&params, 701, &RingRandomness::from_seed(b"bal-o1"));
        assert!(!verify_balance(&params, &inputs, &tampered, fee, &proof), "a changed output breaks the proof");
    }

    #[test]
    fn the_proof_round_trips_through_its_bytes() {
        let (params, inputs, outputs, fee, in_r, out_r) = transfer();
        let proof = prove_balance(&params, &inputs, &outputs, fee, &in_r, &out_r, b"seed").unwrap();
        let back = RingBalanceProof::from_bytes(&proof.to_bytes()).expect("round-trips");
        assert_eq!(back, proof);
        assert!(verify_balance(&params, &inputs, &outputs, fee, &back));
    }
}
