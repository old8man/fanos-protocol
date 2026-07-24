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

use alloc::collections::{BTreeSet, VecDeque};
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

/// The **rolling anchor window** (audit O-M2): the maximum number of recent tree roots kept valid to cite as
/// a spend's membership anchor. The set was previously insert-only — every historical root valid forever,
/// folded into the state root — so it grew without bound (state-bloat DoS). A spend must now cite a root from
/// the last `MAX_ANCHORS` state-advancing operations (Zcash's rolling-anchor design); the window is generous
/// enough that no honest, reasonably-fresh wallet is ever caught out, while bounding the set to 32 KiB. The
/// eviction is deterministic (FIFO over the append order all validators share), so it never forks the root.
const MAX_ANCHORS: usize = 1024;

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
    /// The valid membership anchors — the last [`MAX_ANCHORS`] tree roots (audit O-M2 rolling window). The set
    /// gives O(log n) validity checks and the canonical (sorted) fold into the state root; `anchor_order`
    /// carries the FIFO insertion order so the oldest can be evicted when the window overflows. Invariant:
    /// `anchors` holds exactly the roots in `anchor_order` (same length, no duplicates).
    anchors: BTreeSet<[u8; 32]>,
    anchor_order: VecDeque<[u8; 32]>,
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
        let mut state =
            Self { tree, nullifiers: NullifierSet::new(), anchors: BTreeSet::new(), anchor_order: VecDeque::new() };
        // The empty tree root is already a valid (empty) anchor.
        let root = state.tree.root();
        state.record_anchor(root);
        state
    }

    /// Record `root` as a valid anchor, maintaining the rolling window (audit O-M2). A genuinely new root takes
    /// a fresh window slot; if that overflows [`MAX_ANCHORS`], the **oldest** anchor is evicted FIFO. The tree is
    /// append-only, so every advancing operation yields a distinct root — the `is_new` guard is defensive.
    /// `anchor_order` and `anchors` stay in exact lockstep (enqueue-on-new, dequeue-on-evict), so the window is
    /// deterministic across every validator that applied the same operation sequence.
    fn record_anchor(&mut self, root: [u8; 32]) {
        if self.anchors.insert(root) {
            self.anchor_order.push_back(root);
            if self.anchors.len() > MAX_ANCHORS
                && let Some(oldest) = self.anchor_order.pop_front()
            {
                self.anchors.remove(&oldest);
            }
        }
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
        let mut out = Vec::with_capacity(8 + tree.len() + nullifiers.len() + 4 + self.anchor_order.len() * 32);
        fanos_primitives::codec::put_var_bytes(&mut out, &tree);
        fanos_primitives::codec::put_var_bytes(&mut out, &nullifiers);
        // Encode the anchors in FIFO **insertion order** (not the sorted set), so a restore rebuilds the exact
        // rolling window — the eviction order must survive the sync or two nodes' windows would diverge (O-M2).
        put_seq(&mut out, self.anchor_order.len(), &self.anchor_order, |o, a| o.extend_from_slice(a));
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
        // Decode the FIFO-ordered anchors and rebuild both views. Reject an over-window list (> MAX_ANCHORS): an
        // honest snapshot is always within the bound, and a tampered oversized set would fail the state-root
        // check anyway (the anchor set is folded into `root`), but rejecting early avoids restoring a bad window.
        let anchor_order: VecDeque<[u8; 32]> = r.seq(32, Reader::array::<32>)?.into();
        r.finish()?;
        if anchor_order.len() > MAX_ANCHORS {
            return None;
        }
        let anchors: BTreeSet<[u8; 32]> = anchor_order.iter().copied().collect();
        Some(Self { tree, nullifiers, anchors, anchor_order })
    }

    /// **Issuance** — append a note commitment with *no* spend proof, creating value by a consensus rule (a
    /// genesis allocation or a block reward). Returns the note's tree position, or `None` if the tree is full.
    /// (A production chain gates minting by the consensus/monetary policy; here it is the value-creation seam.)
    pub fn mint(&mut self, note_commitment: [u8; 32]) -> Option<u64> {
        let pos = self.tree.append(note_commitment)?;
        self.record_anchor(self.tree.root());
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
        // Single-transaction path: verify the proof inline, then commit. Block execution verifies proofs in
        // parallel up front (see [`verify_proof`](Self::verify_proof)) and commits via [`apply_with_verdict`].
        self.apply_with_verdict(tx, Self::verify_proof(params, tx, proof))
    }

    /// Whether `proof` attests `tx` under `params` — the shielded transfer's one stateless, expensive step (the
    /// zero-knowledge proof verification). It reads **no ledger state**, so a block's proofs can be verified
    /// concurrently before the serial commit; [`apply_with_verdict`](Self::apply_with_verdict) consumes the result.
    #[must_use]
    pub fn verify_proof<P: ShieldedProof>(params: &Params, tx: &ShieldedTx, proof: &P) -> bool {
        proof.verify(params, tx)
    }

    /// Commit a shielded transfer whose proof `verdict` is already known. The stateful half of
    /// [`apply`](Self::apply): the known-anchor, fresh-nullifier, and capacity checks in the same order, then —
    /// only if the proof held — recording the nullifiers and appending the output note commitments. Splitting the
    /// verdict out lets a block verify every proof in parallel, then commit serially in consensus order, with a
    /// result identical to `apply` — the proof verification reads no ledger state, so evaluating it earlier and
    /// off-thread cannot change the outcome.
    pub fn apply_with_verdict(&mut self, tx: &ShieldedTx, verdict: bool) -> Result<(), ApplyError> {
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
        if !verdict {
            return Err(ApplyError::InvalidProof);
        }
        // Commit: record the nullifiers and append the output note commitments (capacity pre-checked).
        for nf in &tx.nullifiers {
            self.nullifiers.insert(*nf);
        }
        for out in &tx.outputs {
            let _ = self.tree.append(out.note_commitment);
        }
        self.record_anchor(self.tree.root());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::commit::Randomness;
    use crate::note::{Note, derive_owner_pk, derive_spend_auth, spend_auth_commit};

    /// A test spend-auth seed, deterministically distinct from the nullifier key `nsk`.
    fn spend_seed_of(nsk: &[u8; 32]) -> [u8; 32] {
        let mut s = *nsk;
        s[0] ^= 0xA5;
        s
    }
    use crate::tx::{ShieldedTx, TransparentProof};

    /// A note of `value` owned by `nsk`, with deterministic randomness from `tag`.
    fn note(value: u64, nsk: &[u8; 32], tag: &[u8]) -> Note {
        let auth = spend_auth_commit(&derive_spend_auth(&spend_seed_of(nsk)).1);
        Note::new(value, derive_owner_pk(nsk), auth, Randomness::from_seed(tag), [tag.len() as u8; 32])
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
            &[crate::build::SpendInput { note: input.clone(), nsk: *nsk, spend_seed: spend_seed_of(nsk), path }],
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
    fn the_anchor_set_is_a_bounded_rolling_window() {
        // Audit O-M2: the anchor set was insert-only (unbounded state-bloat, folded into the state root). It is
        // now a rolling window of the last MAX_ANCHORS roots — minting past the window caps the set and evicts
        // (invalidates) the oldest anchors FIFO, so an ancient root can no longer be cited as a spend anchor.
        let p = Params::standard();
        let mut s = ShieldedState::new();
        let empty_root = s.anchor(); // the genesis (empty) anchor — the very first, so the first to be evicted
        assert!(s.is_valid_anchor(&empty_root));

        // Mint enough notes to overflow the window (each mint advances the tree → one new distinct anchor).
        for i in 0..(MAX_ANCHORS as u64 + 8) {
            let n = note(1, &[7u8; 32], &i.to_be_bytes());
            mint(&mut s, &p, &n);
        }
        assert_eq!(s.anchors.len(), MAX_ANCHORS, "the anchor set is capped at the window, not unbounded");
        assert_eq!(s.anchor_order.len(), s.anchors.len(), "the FIFO order stays in lockstep with the set");
        assert!(!s.is_valid_anchor(&empty_root), "the oldest anchor was evicted — it can no longer be cited");
        assert!(s.is_valid_anchor(&s.anchor()), "the current root is always a valid anchor");

        // The bounded window survives a snapshot round-trip exactly (eviction order preserved → same root).
        let restored = ShieldedState::from_bytes(&s.to_bytes()).expect("snapshot restores");
        assert_eq!(restored, s, "the windowed state is bit-identical after a sync");
        assert_eq!(restored.root(), s.root(), "and reproduces the exact state root");
        assert_eq!(restored.anchors.len(), MAX_ANCHORS, "the window bound survives the sync");
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
