//! The **transaction-level shielded-spend proof** — the complete zero-knowledge relation for a whole shielded
//! transaction, and the top of the OBOLOS proof stack. It assembles the two composed halves:
//!
//! - one [per-input spend proof](crate::ring_input) per input — each proving the input note is valid, a tree
//!   member, correctly nullified, and its amount tied to its value commitment;
//! - one [per-output note-creation proof](crate::ring_output) per output — each binding the created leaf `cm`
//!   (appended to the tree) to its output value commitment, so a created note cannot be worth more than the amount
//!   balanced for it (the output-side self-inflation guard);
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
//! | conservation (create only what you balance) | shared `Cv` between output proof and balance, per output |
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

use fanos_primitives::codec::{Reader, put_seq, put_u64};

use crate::ring::D;
use crate::ring_commit::{
    COMMITMENT_BYTES, MAX_NOTES_PER_TX, RANGE_BITS, RingCommitment, RingParams, RingRandomness,
};
use crate::ring_confidential::{AmountWitness, ConfidentialAmountProof, prove_amounts, verify_amounts};
use crate::ring_hash::{ELL_H, HashNode, LOG_BASE};
use crate::ring_input::{InputProof, SpendScheme, prove_input, verify_input};
use crate::ring_output::{OutputProof, prove_output, verify_output};

/// One spent input's secret witness.
pub struct TxInput {
    /// The spender's secret nullifier key.
    pub nsk: HashNode,
    /// The note's per-note uniqueness randomness (delivered with the note's opening when it was created) — with
    /// `nsk` it reproduces the note's one-time key, hence its leaf ([`crate::ring_note`]).
    pub rho: HashNode,
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
    /// The recipient's owner tag (`hash(nsk, nsk)` of the recipient's nullifier key), known to the sender from the
    /// recipient's address. The sender does **not** know the recipient's `nsk`, so the output proof binds the
    /// derived one-time key into `cm` without deriving it from `nsk` — ownership is established by the recipient's
    /// own spend proof later.
    pub owner_tag: HashNode,
    /// A **fresh per-note** `rho`, which with `owner_tag` forms the note's one-time key
    /// ([`crate::ring_note::NoteScheme::note_owner`]). It must be freshly sampled per output — that is what makes
    /// two payments of the same amount to the same recipient distinct leaves — and delivered to the recipient with
    /// the note's opening, since spending the note requires it.
    pub rho: HashNode,
}

/// A complete zero-knowledge shielded-transaction proof: a spend proof per input, a note-creation proof per
/// output, and the confidential amounts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShieldedTxProof {
    inputs: Vec<InputProof>,
    outputs: Vec<OutputProof>,
    amounts: ConfidentialAmountProof,
}

/// The public artifacts a proved shielded transaction emits, alongside the [`ShieldedTxProof`]: the input note
/// commitments (the spent leaves — the caller hashes each up its auth path to recover the anchor), the output note
/// commitments (the **new leaves** to append to the tree), and the public nullifiers. The value commitments and
/// fee are the caller's own public inputs; [`RingShieldedTx`] assembles all of it into the ledger object.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProvenTx {
    /// The spent inputs' note commitments (the leaves whose membership is proven).
    pub input_cms: Vec<HashNode>,
    /// The created outputs' note commitments (the leaves to append to the tree).
    pub output_cms: Vec<HashNode>,
    /// One public nullifier per spent input.
    pub nullifiers: Vec<HashNode>,
    /// The zero-knowledge proof binding it all.
    pub proof: ShieldedTxProof,
}

/// A **ring-native shielded transaction** — the public object consensus orders and [`crate::ring_state`] applies.
/// It is the ring successor to [`crate::tx::ShieldedTx`]: everything a validator needs, and *nothing* that would
/// identify a note, an owner, or an amount.
///
/// Note what is absent versus the BLAKE3 object: no spend-auth signatures. There, revealing the nullifier key at
/// spend time forced a separate signing key to keep a broadcast transaction from being re-authorised (audit §5.D-2).
/// Here `nsk` is *never revealed* — it stays inside the zero-knowledge proof — so the proof itself is the spend
/// authorization. Malleability protection for an unshield's public recipient still needs binding into the proof
/// statement when that path is ported; a pure shielded transfer has no such field.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingShieldedTx {
    /// The tree root the inputs are proven members of.
    pub anchor: HashNode,
    /// One public nullifier per spent input (double-spend guard; position-bound, so no note can lock another out).
    pub nullifiers: Vec<HashNode>,
    /// One re-randomised value commitment per spent input (the inputs' balance terms).
    pub input_cvs: Vec<RingCommitment>,
    /// One value commitment per created output (the outputs' balance terms).
    pub output_cvs: Vec<RingCommitment>,
    /// One note commitment per created output — the **new leaves** appended to the tree, each bound to its
    /// `output_cvs` entry by the output proof, so a created note is worth exactly what it balances.
    pub output_cms: Vec<HashNode>,
    /// The public fee (a cleartext balance term).
    pub fee: u64,
}

impl RingShieldedTx {
    /// Assemble the public transaction from a [`prove_shielded_tx`] result and the caller's public value
    /// commitments. `anchor` is the root the inputs' membership was proven against.
    #[must_use]
    pub fn new(
        anchor: HashNode,
        proven: &ProvenTx,
        input_cvs: Vec<RingCommitment>,
        output_cvs: Vec<RingCommitment>,
        fee: u64,
    ) -> Self {
        Self {
            anchor,
            nullifiers: proven.nullifiers.clone(),
            input_cvs,
            output_cvs,
            output_cms: proven.output_cms.clone(),
            fee,
        }
    }

    /// The transaction's canonical bytes — what consensus orders, gossips, and stores.
    ///
    /// Note the asymmetry this makes visible: the *public* object is small (~14 KiB for a 1-in/1-out transfer — nodes
    /// are `ELL_H·D·2` bytes via the short-digit encoding, commitments `(K+1)·D·8`), while its **proof** is hundreds of
    /// MiB (`docs/design-obolos-zk.md` §6). So the ledger object can cross a wire today; only the proof is gated on
    /// recursive compaction. Encoding them separately is what keeps that distinction honest.
    ///
    /// `None` if any node is not a valid short SIS node (which cannot happen for a well-formed transaction: every
    /// anchor and leaf is a hash output, and the nullifiers are checked short by the proof).
    #[must_use]
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.anchor.to_short_bytes()?);
        put_seq_nodes(&mut out, &self.nullifiers)?;
        put_seq(&mut out, self.input_cvs.len(), &self.input_cvs, |o, c| o.extend_from_slice(&c.to_bytes()));
        put_seq(&mut out, self.output_cvs.len(), &self.output_cvs, |o, c| o.extend_from_slice(&c.to_bytes()));
        put_seq_nodes(&mut out, &self.output_cms)?;
        put_u64(&mut out, self.fee);
        Some(out)
    }

    /// Decode a transaction from [`to_bytes`](Self::to_bytes). `None` if malformed, non-canonical (an unreduced
    /// coefficient), carrying trailing bytes, **arity-inconsistent** (a nullifier per input value commitment, a note
    /// commitment per output value commitment), or claiming more value terms than [`MAX_NOTES_PER_TX`] — the last
    /// being a decode bound, so a hostile message cannot force unbounded allocation before any check runs.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let anchor = HashNode::from_short_bytes(r.bytes(NODE_BYTES)?)?;
        let nullifiers = r.seq(NODE_BYTES, |rr| HashNode::from_short_bytes(rr.bytes(NODE_BYTES)?))?;
        let input_cvs = r.seq(COMMITMENT_BYTES, |rr| RingCommitment::from_bytes(rr.bytes(COMMITMENT_BYTES)?))?;
        let output_cvs = r.seq(COMMITMENT_BYTES, |rr| RingCommitment::from_bytes(rr.bytes(COMMITMENT_BYTES)?))?;
        let output_cms = r.seq(NODE_BYTES, |rr| HashNode::from_short_bytes(rr.bytes(NODE_BYTES)?))?;
        let fee = r.u64()?;
        r.finish()?;
        if nullifiers.len() != input_cvs.len() || output_cms.len() != output_cvs.len() {
            return None;
        }
        if input_cvs.len().saturating_add(output_cvs.len()) > MAX_NOTES_PER_TX {
            return None;
        }
        Some(Self { anchor, nullifiers, input_cvs, output_cvs, output_cms, fee })
    }

    /// Whether `proof` attests this transaction's relation — the stateless, expensive half of applying it. Reads no
    /// ledger state, so a block's proofs can be verified concurrently before the serial commit
    /// ([`crate::ring_state::RingShieldedState::apply_with_verdict`]).
    #[must_use]
    pub fn verify(&self, params: &RingParams, scheme: &SpendScheme, proof: &ShieldedTxProof) -> bool {
        verify_shielded_tx(
            params,
            scheme,
            &self.anchor,
            &self.input_cvs,
            &self.nullifiers,
            &self.output_cvs,
            &self.output_cms,
            self.fee,
            proof,
        )
    }
}

/// A node's canonical wire width ([`HashNode::to_short_bytes`]) — one `u16` digit per coefficient.
const NODE_BYTES: usize = ELL_H * D * 2;

/// Encode a length-prefixed run of nodes; `None` if any is not a valid short SIS node.
fn put_seq_nodes(out: &mut Vec<u8>, nodes: &[HashNode]) -> Option<()> {
    let mut encoded = Vec::with_capacity(nodes.len());
    for n in nodes {
        encoded.push(n.to_short_bytes()?);
    }
    put_seq(out, encoded.len(), &encoded, |o, e| o.extend_from_slice(e));
    Some(())
}

/// A sub-seed `base ‖ tag ‖ index`.
fn sub(base: &[u8], tag: &[u8], index: usize) -> Vec<u8> {
    let mut s = base.to_vec();
    s.extend_from_slice(tag);
    s.extend_from_slice(&(index as u64).to_le_bytes());
    s
}

/// Prove a whole shielded transaction: each `input` is spent (valid note, tree member, nullified, amount-tied),
/// each `output` creates a leaf bound to its value commitment, and the amounts balance with every output in
/// `[0, MAX_VALUE)`. The caller must ensure `Σ inputs = Σ outputs + fee`. Returns the [`ProvenTx`] public artifacts
/// (input/output note commitments, nullifiers) and the proof.
///
/// The range width is deliberately **not** a parameter: it is the protocol constant
/// [`RANGE_BITS`](crate::ring_commit::RANGE_BITS), so no call site — honest or otherwise — can widen the bound that
/// keeps the balance law from wrapping modulo `q` (audit O-C1). Because the range proof is *aggregated*, its cost is
/// independent of the width, so pinning it to the real ceiling is free.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn prove_shielded_tx(
    params: &RingParams,
    scheme: &SpendScheme,
    inputs: &[TxInput],
    outputs: &[TxOutput],
    fee: u64,
    seed: &[u8],
) -> Option<ProvenTx> {
    let mut input_proofs = Vec::with_capacity(inputs.len());
    let mut cms = Vec::with_capacity(inputs.len());
    let mut nfs = Vec::with_capacity(inputs.len());
    let mut input_cvs = Vec::with_capacity(inputs.len());
    let mut input_r = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        let cv = RingCommitment::commit(params, inp.value, &inp.rv);
        let vn = HashNode::from_u64_digits(inp.value);
        let (cm, nf, proof) = prove_input(
            params,
            scheme,
            &inp.nsk,
            &vn,
            &inp.rho,
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

    // Per output: prove the created leaf `cm = hash(value_node, note_owner)` is bound to its value commitment `Cv`,
    // so the note the recipient later spends is worth exactly the amount balanced here (the conservation guard).
    // The one-time key `note_owner = hash(owner_tag, rho)` is what makes each created leaf unique.
    let mut output_proofs = Vec::with_capacity(outputs.len());
    let mut output_cms = Vec::with_capacity(outputs.len());
    for (i, out) in outputs.iter().enumerate() {
        let cv = RingCommitment::commit(params, out.value, &out.rv);
        let vn = HashNode::from_u64_digits(out.value);
        let note_owner = scheme.note.note_owner(&out.owner_tag, &out.rho);
        let (cm, proof) = prove_output(
            params,
            &scheme.note.note_hp,
            &cv,
            &out.rv,
            &vn,
            &note_owner,
            LOG_BASE as usize,
            &sub(seed, b"/out", i),
        )?;
        output_cms.push(cm);
        output_proofs.push(proof);
    }

    let output_values: Vec<u64> = outputs.iter().map(|o| o.value).collect();
    let output_r: Vec<RingRandomness> = outputs.iter().map(|o| o.rv.clone()).collect();
    let witness = AmountWitness { input_r: &input_r, output_values: &output_values, output_r: &output_r, fee };
    let amounts = prove_amounts(params, &input_cvs, &witness, RANGE_BITS, &sub(seed, b"/amt", 0))?;

    let proof = ShieldedTxProof { inputs: input_proofs, outputs: output_proofs, amounts };
    Some(ProvenTx { input_cms: cms, output_cms, nullifiers: nfs, proof })
}

/// Verify a [`prove_shielded_tx`] proof against the public transaction: the tree `root`, the input value
/// commitments and nullifiers, the output value commitments and note commitments (the appended leaves), and the
/// fee.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn verify_shielded_tx(
    params: &RingParams,
    scheme: &SpendScheme,
    root: &HashNode,
    input_cvs: &[RingCommitment],
    nfs: &[HashNode],
    output_cvs: &[RingCommitment],
    output_cms: &[HashNode],
    fee: u64,
    proof: &ShieldedTxProof,
) -> bool {
    if proof.inputs.len() != input_cvs.len() || nfs.len() != input_cvs.len() {
        return false;
    }
    if proof.outputs.len() != output_cvs.len() || output_cms.len() != output_cvs.len() {
        return false;
    }
    // Each input is a valid, member, nullified, amount-tied spend.
    for ((cv, nf), input_proof) in input_cvs.iter().zip(nfs).zip(&proof.inputs) {
        if !verify_input(params, scheme, root, cv, nf, input_proof) {
            return false;
        }
    }
    // Each output leaf is bound to its value commitment — a created note is worth exactly what it balances.
    for ((cv, cm), output_proof) in output_cvs.iter().zip(output_cms).zip(&proof.outputs) {
        if !verify_output(params, &scheme.note.note_hp, cv, cm, LOG_BASE as usize, output_proof) {
            return false;
        }
    }
    // The amounts balance, with every output in range — over the same input value commitments.
    verify_amounts(params, input_cvs, output_cvs, fee, RANGE_BITS, &proof.amounts)
}

impl crate::ring_size::ProofSize for ShieldedTxProof {
    /// The whole cost of a shielded transfer: a spend proof per input, a creation proof per output, and the amounts.
    /// This is the number that decides whether the ring path can be wired as a live consensus relation
    /// (`docs/design-obolos-zk.md` §6) — per-input membership shortness dominates it entirely.
    fn ring_elements(&self) -> usize {
        self.inputs.ring_elements() + self.outputs.ring_elements() + self.amounts.ring_elements()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ring_size::ProofSize;

    /// A transaction with the given arity, built from distinct nodes and commitments (no proof needed — the codec is
    /// independent of the proof, which is exactly the separation being tested).
    fn sample_tx(n_in: usize, n_out: usize) -> RingShieldedTx {
        let params = RingParams::standard();
        let node = |tag: &[u8]| HashNode::from_bytes(tag);
        let com = |i: usize| {
            RingCommitment::commit(&params, 1000 + i as u64, &RingRandomness::from_seed(&[i as u8]))
        };
        RingShieldedTx {
            anchor: node(b"codec-anchor"),
            nullifiers: (0..n_in).map(|i| node(&[b'n', i as u8])).collect(),
            input_cvs: (0..n_in).map(com).collect(),
            output_cvs: (0..n_out).map(|i| com(i + 100)).collect(),
            output_cms: (0..n_out).map(|i| node(&[b'o', i as u8])).collect(),
            fee: 42,
        }
    }

    #[test]
    fn a_transaction_round_trips_canonically() {
        for (n_in, n_out) in [(1usize, 1usize), (0, 1), (1, 0), (3, 5)] {
            let tx = sample_tx(n_in, n_out);
            let bytes = tx.to_bytes().expect("a well-formed transaction encodes");
            assert_eq!(RingShieldedTx::from_bytes(&bytes).as_ref(), Some(&tx), "{n_in}-in/{n_out}-out round-trips");
            // One encoding only: trailing bytes and truncation are both refused.
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(RingShieldedTx::from_bytes(&trailing).is_none(), "trailing bytes are refused");
            let truncated = bytes.get(..bytes.len() - 1).expect("non-empty encoding");
            assert!(RingShieldedTx::from_bytes(truncated).is_none(), "truncation is refused");
        }
        // The size asymmetry that makes this codec worth having on its own: the public object is KiB, the proof is
        // hundreds of MiB (docs §6). Encoding them separately is what lets the ledger object cross a wire today.
        let bytes = sample_tx(1, 1).to_bytes().unwrap();
        assert!(bytes.len() < 20 * 1024, "a 1-in/1-out transaction is KiB-scale, not MiB ({} bytes)", bytes.len());
    }

    #[test]
    fn an_arity_inconsistent_encoding_is_refused() {
        let tx = sample_tx(1, 1);
        // Arity must line up: a nullifier per input value commitment, a note commitment per output value commitment.
        let mismatched = RingShieldedTx { nullifiers: Vec::new(), ..tx.clone() };
        let raw = mismatched.to_bytes().unwrap();
        assert!(RingShieldedTx::from_bytes(&raw).is_none(), "a missing nullifier is refused");
        let mismatched = RingShieldedTx { output_cms: Vec::new(), ..tx };
        let raw = mismatched.to_bytes().unwrap();
        assert!(RingShieldedTx::from_bytes(&raw).is_none(), "a missing output note commitment is refused");
    }

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
        let rho_in = HashNode::from_bytes(b"tx-rho-in");
        let sib0 = HashNode::from_bytes(b"tx-sib");
        let input = TxInput {
            nsk,
            rho: rho_in,
            value: v_in,
            rv: rv_in.clone(),
            siblings: alloc::vec![sib0.clone()],
            directions: alloc::vec![0],
        };
        // The output is created for a recipient whose owner tag is hash(nsk_out, nsk_out), with a fresh rho.
        let nsk_out = HashNode::from_bytes(b"tx-out-nsk");
        let owner_tag = scheme.note.owner_hp.hash(&nsk_out, &nsk_out);
        let output =
            TxOutput { value: v_out, rv: rv_out.clone(), owner_tag, rho: HashNode::from_bytes(b"tx-rho-out") };

        let ProvenTx { input_cms, output_cms, nullifiers, proof } =
            prove_shielded_tx(&params, &scheme, &[input], &[output], fee, b"seed").expect("shielded tx");
        // Reconstruct the public transaction: the tree root, and the input/output value commitments.
        let cm = input_cms.first().unwrap();
        let root = scheme.tree_hp.hash(cm, &sib0); // d=0 ⇒ (cm, sib)
        let input_cvs = [RingCommitment::commit(&params, v_in, &rv_in)];
        let output_cvs = [RingCommitment::commit(&params, v_out, &rv_out)];
        assert!(
            verify_shielded_tx(&params, &scheme, &root, &input_cvs, &nullifiers, &output_cvs, &output_cms, fee, &proof),
            "a balanced 1-in/1-out shielded transfer verifies"
        );
        // Inflating the fee claim (101) breaks balance.
        assert!(
            !verify_shielded_tx(&params, &scheme, &root, &input_cvs, &nullifiers, &output_cvs, &output_cms, 101, &proof),
            "an inflated fee is rejected"
        );

        // THE number that decides whether this path can be a live consensus relation (docs §6). Everything else in
        // the stack is measured analytically; this is the real object, at a depth-1 tree — the smallest possible.
        let proof_bytes = proof.encoded_bytes();
        let public = RingShieldedTx {
            anchor: root,
            nullifiers,
            input_cvs: input_cvs.to_vec(),
            output_cvs: output_cvs.to_vec(),
            output_cms,
            fee,
        };
        let tx_bytes = public.to_bytes().expect("the public transaction encodes").len();
        assert!(
            proof_bytes > 1000 * tx_bytes,
            "the proof dwarfs the public transaction by orders of magnitude ({proof_bytes} vs {tx_bytes} bytes)"
        );
        // A depth-1 spend — one sibling, the minimum a Merkle path can have — is already MiB-scale, so the ratio is
        // not an artefact of a deep tree: no tree depth makes this gossipable, which is why recursive compaction
        // gates the WIRING and not merely the scale.
        assert!(proof_bytes > 8 << 20, "even a depth-1 spend proof exceeds 8 MiB ({proof_bytes} bytes)");
    }
}
