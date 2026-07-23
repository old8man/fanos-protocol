//! The **shielded ledger state machine** — the commitment tree and the nullifier set, and the one operation
//! that mutates them: applying a verified shielded transaction. This is what a validator runs; it is a
//! `StateMachine` for TAXIS/DROMOS (the integration composes in a later increment), and it is the object every
//! adversarial scenario ([`crate`] tests, and the SecOps experiment suite) probes.
//!
//! Applying a transaction is a sequence of gates, each closing one attack, and it is **atomic** — on any
//! failure the state is left untouched:
//!
//! 1. **known anchor** — the tree root the inputs are proven against must be one the tree has actually had
//!    (a spend cannot cite a fabricated anchor);
//! 2. **fresh nullifiers** — every revealed nullifier must be unseen *and* distinct within the transaction
//!    (double-spend, including self-double-spend, is rejected);
//! 3. **valid proof** — the [`ShieldedProof`] must attest membership, ownership, correct nullifiers, value
//!    binding, balance, and output range (theft and inflation are rejected).
//!
//! Then the nullifiers are recorded and the output note commitments appended.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use fanos_primitives::codec::{Reader, put_seq};
use fanos_primitives::hash_labeled;

use crate::commit::Params;
use crate::nullifier::NullifierSet;
use crate::tree::{AuthPath, CommitmentTree, TREE_DEPTH};
use crate::tx::{ShieldedProof, ShieldedTx};

/// Domain-separation label for the shielded state commitment.
const STATE_ROOT_LABEL: &str = "FANOS-obolos-v1/state-root";

/// Domain-separation label for the anchor-set sub-commitment folded into the state root.
const ANCHOR_SET_ROOT_LABEL: &str = "FANOS-obolos-v1/anchor-set-root";

/// Why a shielded transaction was refused. Each variant names exactly one attack the gate closes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApplyError {
    /// The transaction cites a commitment-tree root that never existed (a fabricated anchor).
    UnknownAnchor,
    /// A nullifier is already spent, or the transaction reveals the same nullifier twice (double-spend).
    DoubleSpend,
    /// The proof does not attest the shielded-transfer relation (theft, inflation, bad membership, …).
    InvalidProof,
    /// The commitment tree cannot hold the transaction's outputs.
    CapacityExceeded,
}

/// The shielded ledger state: the note-commitment tree, the spent-nullifier set, and the set of anchors (every
/// root the tree has ever had — the valid membership references a spend may cite).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShieldedState {
    tree: CommitmentTree,
    nullifiers: NullifierSet,
    anchors: BTreeSet<[u8; 32]>,
}

impl Default for ShieldedState {
    fn default() -> Self {
        Self::new()
    }
}

impl ShieldedState {
    /// A fresh, empty shielded pool — the empty tree root is already a valid (empty) anchor.
    #[must_use]
    pub fn new() -> Self {
        let tree = CommitmentTree::new();
        let mut anchors = BTreeSet::new();
        anchors.insert(tree.root());
        Self { tree, nullifiers: NullifierSet::new(), anchors }
    }

    /// The current tree root — the anchor a fresh spend should cite.
    #[must_use]
    pub fn anchor(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// The number of notes ever created.
    #[must_use]
    pub fn note_count(&self) -> u64 {
        self.tree.size()
    }

    /// The number of notes spent so far.
    #[must_use]
    pub fn spent_count(&self) -> usize {
        self.nullifiers.len()
    }

    /// Whether `anchor` is a root the tree has actually had.
    #[must_use]
    pub fn is_valid_anchor(&self, anchor: &[u8; 32]) -> bool {
        self.anchors.contains(anchor)
    }

    /// The authentication path for the note at `position` against the *current* root — what a wallet needs to
    /// spend a note it holds. `None` if no note occupies that position.
    #[must_use]
    pub fn path(&self, position: u64) -> Option<AuthPath> {
        self.tree.path(position)
    }

    /// A binding commitment to the whole shielded state —
    /// `H(tree_root ‖ nullifier_set_root ‖ anchor_set_root)`, for inclusion in the block `state_root`.
    ///
    /// The **anchor set is folded in explicitly**. It is not derivable from the current tree — historical roots
    /// are overwritten as notes are appended — yet it decides which spends are valid (a spend must cite a past
    /// root). If the root omitted it, a state-sync peer could ship a correct tree + nullifiers with a *corrupted*
    /// anchor set, pass the certificate's root check, and thereafter accept/reject spends divergently — a silent
    /// fork. Folding it in makes the [`ExecCertificate`](../../fanos_taxis/checkpoint) cover the anchors too, so
    /// a mismatched snapshot is refused on adoption (audit §3.9).
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut buf = [0u8; 96];
        buf[..32].copy_from_slice(&self.tree.root());
        buf[32..64].copy_from_slice(&self.nullifiers.root());
        buf[64..].copy_from_slice(&self.anchor_set_root());
        hash_labeled(STATE_ROOT_LABEL, &buf)
    }

    /// A deterministic commitment to the anchor set (the labeled hash of every historical root, in canonical
    /// sorted order) — the third leg of [`root`](Self::root).
    fn anchor_set_root(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(self.anchors.len() * 32);
        for a in &self.anchors {
            buf.extend_from_slice(a);
        }
        hash_labeled(ANCHOR_SET_ROOT_LABEL, &buf)
    }

    /// Canonical bytes for a state-sync snapshot ([`fanos_primitives::codec`]): the tree, the nullifier set, and
    /// — critically — the **full anchor set**. The anchor set must be carried explicitly because it is not
    /// recomputable from the tree (see [`root`](Self::root)); a restore reproduces all three and hence the exact
    /// state root.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let tree = self.tree.to_bytes();
        let nullifiers = self.nullifiers.to_bytes();
        let mut out = Vec::with_capacity(8 + tree.len() + nullifiers.len() + 4 + self.anchors.len() * 32);
        fanos_primitives::codec::put_var_bytes(&mut out, &tree);
        fanos_primitives::codec::put_var_bytes(&mut out, &nullifiers);
        put_seq(&mut out, self.anchors.len(), &self.anchors, |o, a| o.extend_from_slice(a));
        out
    }

    /// Reconstruct a shielded state from [`to_bytes`](Self::to_bytes), or `None` if malformed / truncated /
    /// over-long. The anchor set is decoded explicitly (not re-derived), so historical-anchor spends remain valid
    /// after a state sync.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let tree = CommitmentTree::from_bytes(r.var_bytes()?)?;
        let nullifiers = NullifierSet::from_bytes(r.var_bytes()?)?;
        let anchors: BTreeSet<[u8; 32]> = r.seq(32, Reader::array::<32>)?.into_iter().collect();
        r.finish()?;
        Some(Self { tree, nullifiers, anchors })
    }

    /// **Issuance** — append a note commitment with *no* spend proof, creating value by a consensus rule (a
    /// genesis allocation or a block reward). Returns the note's tree position, or `None` if the tree is full.
    /// (A production chain gates minting by the consensus/monetary policy; here it is the value-creation seam.)
    pub fn mint(&mut self, note_commitment: [u8; 32]) -> Option<u64> {
        let pos = self.tree.append(note_commitment)?;
        self.anchors.insert(self.tree.root());
        Some(pos)
    }

    /// Apply a shielded transaction under `proof`. Atomic: returns `Ok(())` and mutates the state only if every
    /// gate passes; on any [`ApplyError`] the state is unchanged.
    pub fn apply<P: ShieldedProof>(
        &mut self,
        params: &Params,
        tx: &ShieldedTx,
        proof: &P,
    ) -> Result<(), ApplyError> {
        if !self.anchors.contains(&tx.anchor) {
            return Err(ApplyError::UnknownAnchor);
        }
        if !self.nullifiers.all_fresh(&tx.nullifiers) {
            return Err(ApplyError::DoubleSpend);
        }
        // Check capacity before any mutation so the append loop below cannot partially apply.
        if self.tree.size().saturating_add(tx.outputs.len() as u64) > (1u64 << TREE_DEPTH) {
            return Err(ApplyError::CapacityExceeded);
        }
        if !proof.verify(params, tx) {
            return Err(ApplyError::InvalidProof);
        }
        // Commit: record the nullifiers and append the output note commitments (capacity pre-checked).
        for nf in &tx.nullifiers {
            self.nullifiers.insert(*nf);
        }
        for out in &tx.outputs {
            let _ = self.tree.append(out.note_commitment);
        }
        self.anchors.insert(self.tree.root());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::commit::Randomness;
    use crate::note::{Note, derive_owner_pk};
    use crate::tx::{ShieldedTx, TransparentProof};

    /// A note of `value` owned by `nsk`, with deterministic randomness from `tag`.
    fn note(value: u64, nsk: &[u8; 32], tag: &[u8]) -> Note {
        Note::new(value, derive_owner_pk(nsk), Randomness::from_seed(tag), [tag.len() as u8; 32])
    }

    /// Mint `note` into `state` and return its position.
    fn mint(state: &mut ShieldedState, params: &Params, n: &Note) -> u64 {
        state.mint(n.commitment(params)).expect("mint")
    }

    /// Build a one-input, two-output transparent transfer of `input` (owned by `nsk`, at `position`) into notes
    /// `out_a` and `out_b`, paying `fee`, anchored at `anchor` with path `path`.
    #[allow(clippy::too_many_arguments)]
    fn transfer(
        params: &Params,
        anchor: [u8; 32],
        input: &Note,
        nsk: &[u8; 32],
        path: AuthPath,
        out_a: &Note,
        out_b: &Note,
        fee: u64,
    ) -> (ShieldedTx, TransparentProof) {
        // Delegate to the builder so the input value commitment is re-randomised the same way (audit O-C2).
        crate::build::build_transfer(
            params,
            anchor,
            &[crate::build::SpendInput { note: input.clone(), nsk: *nsk, path }],
            &[out_a.clone(), out_b.clone()],
            fee,
        )
    }

    #[test]
    fn a_minted_note_spends_to_outputs_and_the_state_advances() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let n0 = note(1000, &nsk, b"n0");
        let mut s = ShieldedState::new();
        let pos = mint(&mut s, &p, &n0);
        assert_eq!(s.note_count(), 1);

        let (out_a, out_b) = (note(600, &[2u8; 32], b"a"), note(400, &[3u8; 32], b"b"));
        let (tx, proof) = transfer(&p, s.anchor(), &n0, &nsk, s.path(pos).unwrap(), &out_a, &out_b, 0);
        assert_eq!(s.apply(&p, &tx, &proof), Ok(()), "a conserving, owned, in-range spend is accepted");
        assert_eq!(s.spent_count(), 1, "the input note is nullified");
        assert_eq!(s.note_count(), 3, "the two outputs are appended");
    }

    #[test]
    fn a_snapshot_round_trips_and_preserves_historical_anchors() {
        // The load-bearing state-sync property (audit §3.9): a restored shielded pool reproduces the exact state
        // root AND keeps every historical anchor. The anchor set is not recomputable from the tree, so it must
        // ride the snapshot explicitly, or a spend citing a valid past root would be wrongly rejected after a sync.
        let p = Params::standard();
        let mut s = ShieldedState::new();
        let n0 = note(1000, &[1u8; 32], b"n0");
        mint(&mut s, &p, &n0);
        let historical = s.anchor(); // the root while only n0 exists — a valid anchor a later spend may cite
        let n1 = note(500, &[2u8; 32], b"n1");
        mint(&mut s, &p, &n1); // the tree advances; `historical` is now a PAST root, overwritten inside the tree
        assert!(s.is_valid_anchor(&historical), "the past root is a valid anchor");
        assert_ne!(s.anchor(), historical, "and it is no longer the current root");

        // Round-trip through the snapshot.
        let bytes = s.to_bytes();
        let restored = ShieldedState::from_bytes(&bytes).expect("the snapshot restores");
        assert_eq!(restored, s, "the restored state is bit-identical");
        assert_eq!(restored.root(), s.root(), "and reproduces the exact state root");
        assert!(restored.is_valid_anchor(&historical), "critically, the historical anchor survives the sync");

        // The anchor set is genuinely bound by the root: dropping an anchor yields a DIFFERENT root, so a
        // corrupted-anchor snapshot cannot pass the certificate's root check (the safety argument for §3.9).
        let mut tampered = restored.clone();
        tampered.anchors.remove(&historical);
        assert_ne!(tampered.root(), s.root(), "dropping an anchor changes the root — a synced peer would reject it");
    }

    #[test]
    fn a_double_spend_is_rejected() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let n0 = note(1000, &nsk, b"n0");
        let mut s = ShieldedState::new();
        let pos = mint(&mut s, &p, &n0);
        let (out_a, out_b) = (note(600, &[2u8; 32], b"a"), note(400, &[3u8; 32], b"b"));
        let (tx, proof) = transfer(&p, s.anchor(), &n0, &nsk, s.path(pos).unwrap(), &out_a, &out_b, 0);
        assert_eq!(s.apply(&p, &tx, &proof), Ok(()));
        // Replaying the very same transaction re-reveals the nullifier → rejected, state unchanged.
        let before = s.clone();
        assert_eq!(s.apply(&p, &tx, &proof), Err(ApplyError::DoubleSpend));
        assert_eq!(s, before, "the rejected double-spend did not mutate the state");
    }

    #[test]
    fn an_inflating_transfer_is_rejected() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let n0 = note(1000, &nsk, b"n0");
        let mut s = ShieldedState::new();
        let pos = mint(&mut s, &p, &n0);
        // Outputs 600 + 500 = 1100 > input 1000 (fee 0): the balance law fails, so the proof does not verify.
        let (out_a, out_b) = (note(600, &[2u8; 32], b"a"), note(500, &[3u8; 32], b"b"));
        let (tx, proof) = transfer(&p, s.anchor(), &n0, &nsk, s.path(pos).unwrap(), &out_a, &out_b, 0);
        assert_eq!(s.apply(&p, &tx, &proof), Err(ApplyError::InvalidProof), "value cannot be created from nothing");
    }

    #[test]
    fn spending_a_note_you_do_not_own_is_rejected() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let n0 = note(1000, &nsk, b"n0");
        let mut s = ShieldedState::new();
        let pos = mint(&mut s, &p, &n0);
        // The thief tries to spend with the WRONG spending key.
        let thief = [9u8; 32];
        let (out_a, out_b) = (note(600, &[2u8; 32], b"a"), note(400, &[3u8; 32], b"b"));
        let (tx, proof) = transfer(&p, s.anchor(), &n0, &thief, s.path(pos).unwrap(), &out_a, &out_b, 0);
        assert_eq!(s.apply(&p, &tx, &proof), Err(ApplyError::InvalidProof), "a note cannot be spent without its key");
    }

    #[test]
    fn a_spend_against_a_fabricated_anchor_is_rejected() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let n0 = note(1000, &nsk, b"n0");
        let mut s = ShieldedState::new();
        let pos = mint(&mut s, &p, &n0);
        let (out_a, out_b) = (note(600, &[2u8; 32], b"a"), note(400, &[3u8; 32], b"b"));
        let (tx, proof) = transfer(&p, [0x42u8; 32], &n0, &nsk, s.path(pos).unwrap(), &out_a, &out_b, 0);
        assert_eq!(s.apply(&p, &tx, &proof), Err(ApplyError::UnknownAnchor), "a spend must cite a real tree root");
    }

    #[test]
    fn a_fee_is_part_of_the_balance_law() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let n0 = note(1000, &nsk, b"n0");
        let mut s = ShieldedState::new();
        let pos = mint(&mut s, &p, &n0);
        // Inputs 1000 = outputs 600 + 350 + fee 50.
        let (out_a, out_b) = (note(600, &[2u8; 32], b"a"), note(350, &[3u8; 32], b"b"));
        let (tx, proof) = transfer(&p, s.anchor(), &n0, &nsk, s.path(pos).unwrap(), &out_a, &out_b, 50);
        assert_eq!(s.apply(&p, &tx, &proof), Ok(()), "outputs + fee that conserve value are accepted");
        // The same outputs with the wrong fee (40) no longer balance.
        let mut s2 = ShieldedState::new();
        let pos2 = mint(&mut s2, &p, &n0);
        let (tx2, proof2) = transfer(&p, s2.anchor(), &n0, &nsk, s2.path(pos2).unwrap(), &out_a, &out_b, 40);
        assert_eq!(s2.apply(&p, &tx2, &proof2), Err(ApplyError::InvalidProof), "the fee must close the balance exactly");
    }

    #[test]
    fn the_state_root_binds_both_the_tree_and_the_nullifiers() {
        let p = Params::standard();
        let nsk = [1u8; 32];
        let n0 = note(1000, &nsk, b"n0");
        let mut s = ShieldedState::new();
        let empty_root = s.root();
        let pos = mint(&mut s, &p, &n0);
        assert_ne!(s.root(), empty_root, "minting a note changes the state root");
        let after_mint = s.root();
        let (out_a, out_b) = (note(600, &[2u8; 32], b"a"), note(400, &[3u8; 32], b"b"));
        let (tx, proof) = transfer(&p, s.anchor(), &n0, &nsk, s.path(pos).unwrap(), &out_a, &out_b, 0);
        s.apply(&p, &tx, &proof).unwrap();
        assert_ne!(s.root(), after_mint, "spending (nullifiers + new notes) changes the state root");
    }
}
