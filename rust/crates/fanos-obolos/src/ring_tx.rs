//! The **transaction-level shielded-spend proof** — the complete zero-knowledge relation for a whole shielded
//! transaction, and the top of the OBOLOS proof stack. It assembles the two composed halves:
//!
//! - one [per-input spend proof](crate::ring_input) per input — each proving the input note is valid, a tree
//!   member, correctly nullified, and its amount tied to its value commitment;
//! - the [confidential-amount proof](crate::ring_confidential) — a range proof per output and one balance proof,
//!   over the same input value commitments.
//!
//! Because the per-input proofs and the amount proof share each input's value commitment `Cv`, the transaction
//! that balances is exactly the one whose inputs are proven spendable — every privacy and soundness property of a
//! shielded transfer, in zero knowledge:
//!
//! | property | proven by |
//! |---|---|
//! | confidentiality (amounts hidden, sound) | balance + range over `Cv` |
//! | untraceability (which note) | membership + nullifier, per input |
//! | ownership | `nf` derivable only with `nsk`, per input |
//! | integrity (spend the note you balance) | shared `Cv` between input proof and balance |
//!
//! This is the statement the transparent [`crate::tx::TransparentProof`] proves in the clear — now in zero
//! knowledge. Wiring it as the ledger's `ShieldedProof` (migrating the value commitment and note model onto the
//! ring) is the remaining integration step.
//!
//! > **STATUS — [P]/[H], correctness-first.** A composition of the built, tested pieces; inherits their status and
//! > cost — a whole-transaction proof is minutes at real `bits` (aggregation / recursive-SNARK compaction is the
//! > perf frontier). Verified by an `#[ignore]`d test (`--ignored`): a 1-in/1-out shielded transfer proves and
//! > verifies end to end.

use alloc::vec::Vec;

use crate::ring::Poly;
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_confidential::{AmountWitness, ConfidentialAmountProof, prove_amounts, verify_amounts};
use crate::ring_hash::{ELL_H, HashNode, LOG_BASE};
use crate::ring_input::{InputProof, SpendScheme, prove_input, verify_input};

/// One spent input's secret witness.
pub struct TxInput {
    /// The spender's secret nullifier key.
    pub nsk: HashNode,
    /// The input amount.
    pub value: u64,
    /// The re-randomisation of the input's value commitment.
    pub rv: RingRandomness,
    /// The authentication path's siblings.
    pub siblings: Vec<HashNode>,
    /// The path directions (`0` = left child, `1` = right).
    pub directions: Vec<u64>,
}

/// One created output's secret witness.
pub struct TxOutput {
    /// The output amount.
    pub value: u64,
    /// The output value-commitment randomness.
    pub rv: RingRandomness,
}

/// A complete zero-knowledge shielded-transaction proof: a spend proof per input and the confidential amounts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShieldedTxProof {
    inputs: Vec<InputProof>,
    amounts: ConfidentialAmountProof,
}

/// A sub-seed `base ‖ tag ‖ index`.
fn sub(base: &[u8], tag: &[u8], index: usize) -> Vec<u8> {
    let mut s = base.to_vec();
    s.extend_from_slice(tag);
    s.extend_from_slice(&(index as u64).to_le_bytes());
    s
}

/// The digit-encoding value node for amount `v` (one base-`2^{LOG_BASE}` digit per limb).
fn value_node(v: u64) -> HashNode {
    HashNode::from_limbs((0..ELL_H).map(|d| Poly::constant((v >> (LOG_BASE * d as u32)) & 0xFFFF)).collect())
}

/// Prove a whole shielded transaction: each `input` is spent (valid note, tree member, nullified, amount-tied) and
/// the amounts balance with every output in `[0, 2^range_bits)`. The caller must ensure `Σ inputs = Σ outputs +
/// fee`. Returns the per-input note commitments `cm` (the leaves) and public nullifiers `nf`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn prove_shielded_tx(
    params: &RingParams,
    scheme: &SpendScheme,
    inputs: &[TxInput],
    outputs: &[TxOutput],
    fee: u64,
    range_bits: usize,
    seed: &[u8],
) -> Option<(Vec<HashNode>, Vec<HashNode>, ShieldedTxProof)> {
    let mut input_proofs = Vec::with_capacity(inputs.len());
    let mut cms = Vec::with_capacity(inputs.len());
    let mut nfs = Vec::with_capacity(inputs.len());
    let mut input_cvs = Vec::with_capacity(inputs.len());
    let mut input_r = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        let cv = RingCommitment::commit(params, inp.value, &inp.rv);
        let vn = value_node(inp.value);
        let (cm, nf, proof) = prove_input(
            params,
            scheme,
            &inp.nsk,
            &vn,
            &cv,
            &inp.rv,
            &inp.siblings,
            &inp.directions,
            &sub(seed, b"/in", i),
        )?;
        cms.push(cm);
        nfs.push(nf);
        input_proofs.push(proof);
        input_cvs.push(cv);
        input_r.push(inp.rv.clone());
    }

    let output_values: Vec<u64> = outputs.iter().map(|o| o.value).collect();
    let output_r: Vec<RingRandomness> = outputs.iter().map(|o| o.rv.clone()).collect();
    let witness = AmountWitness { input_r: &input_r, output_values: &output_values, output_r: &output_r, fee };
    let amounts = prove_amounts(params, &input_cvs, &witness, range_bits, &sub(seed, b"/amt", 0))?;

    Some((cms, nfs, ShieldedTxProof { inputs: input_proofs, amounts }))
}

/// Verify a [`prove_shielded_tx`] proof against the public transaction: the tree `root`, the input value
/// commitments and nullifiers, the output value commitments, and the fee.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn verify_shielded_tx(
    params: &RingParams,
    scheme: &SpendScheme,
    root: &HashNode,
    input_cvs: &[RingCommitment],
    nfs: &[HashNode],
    output_cvs: &[RingCommitment],
    fee: u64,
    proof: &ShieldedTxProof,
) -> bool {
    if proof.inputs.len() != input_cvs.len() || nfs.len() != input_cvs.len() {
        return false;
    }
    // Each input is a valid, member, nullified, amount-tied spend.
    for ((cv, nf), input_proof) in input_cvs.iter().zip(nfs).zip(&proof.inputs) {
        if !verify_input(params, scheme, root, cv, nf, input_proof) {
            return false;
        }
    }
    // The amounts balance, with every output in range — over the same input value commitments.
    verify_amounts(params, input_cvs, output_cvs, fee, &proof.amounts)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "whole-tx spend at real bits — several minutes; run with --ignored"]
    fn a_one_in_one_out_shielded_transfer_proves_and_verifies() {
        let params = RingParams::standard();
        let scheme = SpendScheme::standard();
        // 1000 in → 900 out + 100 fee.
        let (v_in, v_out, fee) = (1000u64, 900u64, 100u64);
        let rv_in = RingRandomness::from_seed(b"tx-rv-in");
        let rv_out = RingRandomness::from_seed(b"tx-rv-out");
        let nsk = HashNode::from_bytes(b"tx-nsk");
        let sib0 = HashNode::from_bytes(b"tx-sib");
        let input = TxInput { nsk, value: v_in, rv: rv_in.clone(), siblings: alloc::vec![sib0.clone()], directions: alloc::vec![0] };
        let output = TxOutput { value: v_out, rv: rv_out.clone() };

        let (cms, nfs, proof) =
            prove_shielded_tx(&params, &scheme, &[input], &[output], fee, 16, b"seed").expect("shielded tx");
        // Reconstruct the public transaction: the tree root, and the input/output value commitments.
        let cm = cms.first().unwrap();
        let root = scheme.tree_hp.hash(cm, &sib0); // d=0 ⇒ (cm, sib)
        let input_cvs = [RingCommitment::commit(&params, v_in, &rv_in)];
        let output_cvs = [RingCommitment::commit(&params, v_out, &rv_out)];
        assert!(
            verify_shielded_tx(&params, &scheme, &root, &input_cvs, &nfs, &output_cvs, fee, &proof),
            "a balanced 1-in/1-out shielded transfer verifies"
        );
        // Inflating the fee claim (101) breaks balance.
        assert!(
            !verify_shielded_tx(&params, &scheme, &root, &input_cvs, &nfs, &output_cvs, 101, &proof),
            "an inflated fee is rejected"
        );
    }
}
