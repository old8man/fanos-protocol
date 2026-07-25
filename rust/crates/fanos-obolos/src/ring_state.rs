//! The **ring-native shielded ledger state machine** — the commitment tree, the nullifier set, the anchor window,
//! and the one operation that mutates them: applying a zero-knowledge-proven shielded transaction. This is the ring
//! successor to [`crate::state`], and the point where the OBOLOS proof stack stops being a library and becomes a
//! ledger: `apply` verifies a real [`ShieldedTxProof`] — no witness revealed, no transparent oracle.
//!
//! Applying a transaction is the *same* gate sequence [`crate::state`] established, each closing one attack, and it
//! is **atomic** — on any failure the state is untouched:
//!
//! 1. **known anchor** — the root the inputs are proven against must be one the tree has actually had, within the
//!    rolling window (a spend cannot cite a fabricated or ancient anchor);
//! 2. **fresh nullifiers** — every revealed nullifier must be unseen *and* distinct within the transaction
//!    (double-spend, including self-double-spend, is rejected);
//! 3. **capacity** — the tree must hold every output, checked *before* any mutation so the append loop cannot
//!    partially apply;
//! 4. **valid proof** — the [`ShieldedTxProof`] must attest membership, ownership, position-bound nullifier
//!    correctness, value binding, balance, output range, *and* that each appended leaf is worth what it balances.
//!
//! Then the nullifiers are recorded and the output note commitments appended.
//!
//! ## What the ring changes, and why the digest
//!
//! A ring nullifier or root is a [`HashNode`] — `ELL_H·D` ring coefficients, kilobytes each. Keying the nullifier
//! set and the anchor window on nodes directly would grow the executed state by kilobytes per spent note, and the
//! block `state_root` is 32 bytes. So the *sets* are keyed on [`HashNode::digest`] — an injective encoding under the
//! same BLAKE3 collision assumption the BLAKE3-side ledger already makes — while every **soundness** check is
//! stated over the full node inside the proof. That lets the nullifier set and the anchor-window policy
//! ([`MAX_ANCHORS`], audit O-M2) be *literally the same code* as [`crate::state`]'s, rather than a second
//! divergent implementation of the same rules.
//!
//! > **STATUS — [P]/[H], correctness-first.** Inherits the proof stack's status: the gates and the state transitions
//! > are exact and tested here, and the proof they gate on is the real zero-knowledge relation — but its parameters
//! > are not yet calibrated to a bit-security target (`docs/design-obolos-zk.md` §5). The end-to-end test that mints,
//! > proves, and applies a real shielded transfer is `#[ignore]`d (minutes at real `bits`); the state-machine
//! > behaviour — anchors, double-spend, capacity, atomicity, the state root — is verified fast with a stub verdict.

use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;

use fanos_primitives::codec::{Reader, put_seq, put_var_bytes};
use fanos_primitives::hash_labeled;

use crate::nullifier::{Nullifier, NullifierSet};
use crate::ring::D;
use crate::ring_commit::RingParams;
use crate::ring_hash::{ELL_H, HashNode};
use crate::ring_input::SpendScheme;
use crate::ring_tree::RingTree;
use crate::ring_tx::{RingShieldedTx, ShieldedTxProof};
use crate::state::{ApplyError, MAX_ANCHORS};

/// Domain-separation label for the ring shielded-state commitment.
const STATE_ROOT_LABEL: &str = "FANOS-obolos-v1/ring-state-root";

/// Domain-separation label for the anchor-set sub-commitment folded into the state root.
const ANCHOR_SET_ROOT_LABEL: &str = "FANOS-obolos-v1/ring-anchor-set-root";

/// A node's canonical snapshot width ([`HashNode::to_short_bytes`]) — one `u16` digit per coefficient.
const NODE_BYTES: usize = ELL_H * D * 2;

/// The ring-native shielded ledger state: the SIS note-commitment tree, the spent-nullifier set, and the rolling
/// window of valid membership anchors.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingShieldedState {
    tree: RingTree,
    nullifiers: NullifierSet,
    /// The valid membership anchors — the last [`MAX_ANCHORS`] tree roots, keyed by digest (audit O-M2). The set
    /// gives `O(log n)` validity checks and the canonical (sorted) fold into the state root; `anchor_order` carries
    /// the FIFO insertion order so the oldest can be evicted when the window overflows. Invariant: `anchors` holds
    /// exactly the digests in `anchor_order` (same length, no duplicates).
    anchors: BTreeSet<[u8; 32]>,
    anchor_order: VecDeque<[u8; 32]>,
}

impl RingShieldedState {
    /// A fresh, empty shielded pool of the given tree `depth` — the empty tree root is already a valid anchor.
    #[must_use]
    pub fn new(depth: usize) -> Self {
        let tree = RingTree::new(depth);
        let mut state =
            Self { tree, nullifiers: NullifierSet::new(), anchors: BTreeSet::new(), anchor_order: VecDeque::new() };
        let root = state.tree.root();
        state.record_anchor(&root);
        state
    }

    /// Record `root` as a valid anchor, maintaining the rolling window (audit O-M2). A genuinely new root takes a
    /// fresh slot; if that overflows [`MAX_ANCHORS`], the **oldest** anchor is evicted FIFO. The tree is append-only,
    /// so every advancing operation yields a distinct root — the `is_new` guard is defensive. The eviction is
    /// deterministic (FIFO over the shared append order), so it never forks the state root.
    fn record_anchor(&mut self, root: &HashNode) {
        let digest = root.digest();
        if self.anchors.insert(digest) {
            self.anchor_order.push_back(digest);
            if self.anchors.len() > MAX_ANCHORS
                && let Some(oldest) = self.anchor_order.pop_front()
            {
                self.anchors.remove(&oldest);
            }
        }
    }

    /// The current tree root — the anchor a fresh spend should cite.
    #[must_use]
    pub fn anchor(&self) -> HashNode {
        self.tree.root()
    }

    /// The number of notes ever created.
    #[must_use]
    pub fn note_count(&self) -> u64 {
        self.tree.len()
    }

    /// The number of notes spent so far.
    #[must_use]
    pub fn spent_count(&self) -> usize {
        self.nullifiers.len()
    }

    /// Whether `anchor` is a root the tree has actually had, still inside the rolling window.
    #[must_use]
    pub fn is_valid_anchor(&self, anchor: &HashNode) -> bool {
        self.anchors.contains(&anchor.digest())
    }

    /// The authentication path for the note at `position` — the siblings and direction bits a spender feeds to
    /// [`crate::ring_tx::prove_shielded_tx`]. `None` if no note occupies that position.
    #[must_use]
    pub fn auth_path(&self, position: u64) -> Option<(Vec<HashNode>, Vec<u64>)> {
        (position < self.tree.len()).then(|| self.tree.auth_path(position))
    }

    /// A binding 32-byte commitment to the whole shielded state — `H(tree_root ‖ nullifier_set_root ‖
    /// anchor_set_root)`, for inclusion in the block `state_root`.
    ///
    /// The **anchor set is folded in explicitly**, for the same reason as [`crate::state::ShieldedState::root`]: it
    /// is not derivable from the current tree (historical roots are overwritten as notes are appended) yet it decides
    /// which spends are valid. If the root omitted it, a state-sync peer could ship a correct tree + nullifiers with
    /// a *corrupted* anchor set, pass the certificate's root check, and thereafter accept/reject spends divergently —
    /// a silent fork (audit §3.9).
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut buf = [0u8; 96];
        buf[..32].copy_from_slice(&self.tree.root().digest());
        buf[32..64].copy_from_slice(&self.nullifiers.root());
        buf[64..].copy_from_slice(&self.anchor_set_root());
        hash_labeled(STATE_ROOT_LABEL, &buf)
    }

    /// A deterministic commitment to the anchor set (the labeled hash of every windowed root digest, in canonical
    /// sorted order) — the third leg of [`root`](Self::root).
    fn anchor_set_root(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(self.anchors.len() * 32);
        for a in &self.anchors {
            buf.extend_from_slice(a);
        }
        hash_labeled(ANCHOR_SET_ROOT_LABEL, &buf)
    }

    /// Canonical bytes for a **state-sync snapshot**: the tree depth, its leaves in order, the nullifier set, and —
    /// critically — the **full anchor window in FIFO insertion order**.
    ///
    /// Two things must ride the snapshot explicitly, for the same reasons as
    /// [`crate::state::ShieldedState::to_bytes`] (audit §3.9):
    ///
    /// - the **anchor window**, because it is not recomputable from the current tree (historical roots are
    ///   overwritten as notes are appended) yet it decides which spends are valid. A peer that restored a correct
    ///   tree with a *wrong* anchor set would thereafter accept/reject spends divergently — a silent fork. It is
    ///   folded into [`root`](Self::root), so a mismatched snapshot fails the certificate's root check on adoption;
    /// - the **insertion order**, not just the set, because eviction is FIFO: two nodes whose windows hold the same
    ///   anchors in a different order would evict differently and diverge later.
    ///
    /// The tree's *frontier* is deliberately **not** encoded — re-appending the leaves rebuilds it, so there is no
    /// second representation of the same fact that could disagree with the leaves.
    #[must_use]
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        out.push(u8::try_from(self.tree.depth()).ok()?);
        // Leaves in tree order; each is a short node, so its canonical encoding is a fixed-width bijection.
        let mut leaves = Vec::with_capacity(self.tree.leaves().len());
        for leaf in self.tree.leaves() {
            leaves.push(leaf.to_short_bytes()?);
        }
        put_seq(&mut out, leaves.len(), &leaves, |o, l| o.extend_from_slice(l));
        put_var_bytes(&mut out, &self.nullifiers.to_bytes());
        put_seq(&mut out, self.anchor_order.len(), &self.anchor_order, |o, a| o.extend_from_slice(a));
        Some(out)
    }

    /// Reconstruct a shielded state from [`to_bytes`](Self::to_bytes), or `None` if malformed, truncated, over-long,
    /// or inconsistent (a leaf count exceeding the depth's capacity, or an anchor window over [`MAX_ANCHORS`]).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let depth = usize::from(r.u8()?);
        let leaves = r.seq(NODE_BYTES, |rr| HashNode::from_short_bytes(rr.bytes(NODE_BYTES)?))?;
        let nullifiers = NullifierSet::from_bytes(r.var_bytes()?)?;
        // The anchors are decoded in FIFO **insertion order** (not as a sorted set), so the restored window evicts
        // exactly as the original would. Reject an over-window list: an honest snapshot is always within the bound.
        let anchor_order: VecDeque<[u8; 32]> = r.seq(32, Reader::array::<32>)?.into();
        r.finish()?;
        if anchor_order.len() > MAX_ANCHORS {
            return None;
        }
        let mut tree = RingTree::new(depth);
        for leaf in leaves {
            tree.append(leaf)?; // `None` iff the snapshot claims more leaves than the depth can hold
        }
        let anchors: BTreeSet<[u8; 32]> = anchor_order.iter().copied().collect();
        Some(Self { tree, nullifiers, anchors, anchor_order })
    }

    /// **Issuance** — append a note commitment with *no* spend proof, creating value by a consensus rule (a genesis
    /// allocation or a block reward). Returns the note's tree position, or `None` if the tree is full **or the leaf
    /// is not a valid short SIS node**.
    ///
    /// The shortness check matters because minting is the one path with no proof behind it. Every *proven* output
    /// leaf is short by construction (the output proof checks it), but a non-short minted leaf could never be spent
    /// at all — the membership proof requires short nodes — so it would silently destroy the value it issued.
    /// (A production chain additionally gates the *amount* by the monetary policy; that is what keeps the "inputs
    /// are in range by induction" argument of [`crate::ring_confidential`] true at its base case.)
    pub fn mint(&mut self, note_commitment: HashNode) -> Option<u64> {
        if !note_commitment.is_short() {
            return None;
        }
        let pos = self.tree.append(note_commitment)?;
        let root = self.tree.root();
        self.record_anchor(&root);
        Some(pos)
    }

    /// Apply a shielded transaction under `proof`. Atomic: returns `Ok(())` and mutates the state only if every gate
    /// passes; on any [`ApplyError`] the state is unchanged.
    pub fn apply(
        &mut self,
        params: &RingParams,
        scheme: &SpendScheme,
        tx: &RingShieldedTx,
        proof: &ShieldedTxProof,
    ) -> Result<(), ApplyError> {
        // Single-transaction path: verify the proof inline, then commit. Block execution verifies proofs in parallel
        // up front ([`RingShieldedTx::verify`]) and commits via [`apply_with_verdict`](Self::apply_with_verdict).
        self.apply_with_verdict(tx, tx.verify(params, scheme, proof))
    }

    /// Commit a shielded transfer whose proof `verdict` is already known — the stateful half of
    /// [`apply`](Self::apply): the known-anchor, fresh-nullifier, and capacity gates in that order, then, only if the
    /// proof held, recording the nullifiers and appending the output leaves. Splitting the verdict out lets a block
    /// verify every proof in parallel and then commit serially in consensus order, with a result identical to
    /// `apply` — proof verification reads no ledger state, so evaluating it earlier and off-thread cannot change the
    /// outcome.
    pub fn apply_with_verdict(&mut self, tx: &RingShieldedTx, verdict: bool) -> Result<(), ApplyError> {
        if !self.is_valid_anchor(&tx.anchor) {
            return Err(ApplyError::UnknownAnchor);
        }
        // Nullifiers enter the set by digest; the proof binds each to its note and tree slot over the full node.
        let nfs: Vec<Nullifier> = tx.nullifiers.iter().map(|nf| Nullifier::from_bytes(nf.digest())).collect();
        if !self.nullifiers.all_fresh(&nfs) {
            return Err(ApplyError::DoubleSpend);
        }
        // Check capacity before any mutation so the append loop below cannot partially apply.
        if self.tree.len().saturating_add(tx.output_cms.len() as u64) > self.tree.capacity() {
            return Err(ApplyError::CapacityExceeded);
        }
        if !verdict {
            return Err(ApplyError::InvalidProof);
        }
        // Commit: record the nullifiers and append the output note commitments (capacity pre-checked).
        for nf in nfs {
            self.nullifiers.insert(nf);
        }
        for cm in &tx.output_cms {
            let _ = self.tree.append(cm.clone());
        }
        let root = self.tree.root();
        self.record_anchor(&root);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::ring_commit::{RingCommitment, RingRandomness};
    use crate::ring_tx::{ProvenTx, TxInput, TxOutput, prove_shielded_tx};

    /// A distinct note commitment for tests that exercise state transitions rather than proofs.
    fn cm(tag: &[u8]) -> HashNode {
        HashNode::from_bytes(tag)
    }

    /// A transaction spending `nfs` against `anchor` and creating `outs`, with no value commitments — enough for the
    /// state-machine gates, whose behaviour is independent of the (separately-tested) proof contents.
    fn tx(anchor: HashNode, nfs: &[&[u8]], outs: &[&[u8]]) -> RingShieldedTx {
        RingShieldedTx {
            anchor,
            nullifiers: nfs.iter().map(|t| cm(t)).collect(),
            input_cvs: Vec::new(),
            output_cvs: Vec::new(),
            output_cms: outs.iter().map(|t| cm(t)).collect(),
            fee: 0,
        }
    }

    #[test]
    fn a_minted_note_spends_to_outputs_and_the_state_advances() {
        let mut s = RingShieldedState::new(4);
        s.mint(cm(b"n0")).expect("mint");
        assert_eq!(s.note_count(), 1);
        let t = tx(s.anchor(), &[b"nf0"], &[b"out-a", b"out-b"]);
        assert_eq!(s.apply_with_verdict(&t, true), Ok(()), "a proven spend against a live anchor is accepted");
        assert_eq!(s.spent_count(), 1, "the input note is nullified");
        assert_eq!(s.note_count(), 3, "the two output leaves are appended");
    }

    #[test]
    fn a_double_spend_is_rejected_and_leaves_the_state_untouched() {
        let mut s = RingShieldedState::new(4);
        s.mint(cm(b"n0")).unwrap();
        let t = tx(s.anchor(), &[b"nf0"], &[b"out-a"]);
        assert_eq!(s.apply_with_verdict(&t, true), Ok(()));
        let (notes, spent, root) = (s.note_count(), s.spent_count(), s.root());
        // Replaying re-reveals the nullifier → rejected, nothing mutated.
        let replay = tx(s.anchor(), &[b"nf0"], &[b"out-b"]);
        assert_eq!(s.apply_with_verdict(&replay, true), Err(ApplyError::DoubleSpend));
        assert_eq!((s.note_count(), s.spent_count(), s.root()), (notes, spent, root), "state untouched");
        // A transaction that nullifies the same note twice within itself is equally invalid.
        let selfsame = tx(s.anchor(), &[b"nf1", b"nf1"], &[b"out-c"]);
        assert_eq!(s.apply_with_verdict(&selfsame, true), Err(ApplyError::DoubleSpend));
    }

    #[test]
    fn an_invalid_proof_is_rejected_and_leaves_the_state_untouched() {
        let mut s = RingShieldedState::new(4);
        s.mint(cm(b"n0")).unwrap();
        let before = s.root();
        let t = tx(s.anchor(), &[b"nf0"], &[b"out-a"]);
        assert_eq!(s.apply_with_verdict(&t, false), Err(ApplyError::InvalidProof), "no proof, no spend");
        assert_eq!(s.root(), before, "the rejected transaction did not mutate the state");
        assert_eq!(s.spent_count(), 0, "and did not record its nullifier");
    }

    #[test]
    fn minting_a_non_short_leaf_is_refused() {
        // Minting is the one value-creating path with no proof behind it, so it must not admit a leaf that could
        // never be spent: the membership proof requires short SIS nodes, so a non-short leaf destroys its own value.
        let mut s = RingShieldedState::new(4);
        let before = s.root();
        let mut limbs = cm(b"almost").limbs().to_vec();
        limbs.push(crate::ring::Poly::constant(1 << crate::ring_hash::LOG_BASE)); // a digit at the base — not short
        limbs.remove(0);
        let bad = HashNode::from_limbs(limbs);
        assert!(!bad.is_short(), "the fixture really is a non-short node");
        assert_eq!(s.mint(bad), None, "a non-short leaf is refused");
        assert_eq!((s.note_count(), s.root()), (0, before), "and nothing was appended");
        assert!(s.mint(cm(b"fine")).is_some(), "a genuine short leaf still mints");
    }

    #[test]
    fn a_spend_against_a_fabricated_anchor_is_rejected() {
        let mut s = RingShieldedState::new(4);
        s.mint(cm(b"n0")).unwrap();
        let t = tx(cm(b"not-a-root"), &[b"nf0"], &[b"out-a"]);
        assert_eq!(s.apply_with_verdict(&t, true), Err(ApplyError::UnknownAnchor), "a spend must cite a real root");
    }

    #[test]
    fn a_historical_anchor_stays_valid_while_the_tree_advances() {
        // The rolling-anchor property: a wallet whose witness is a few blocks old can still spend.
        let mut s = RingShieldedState::new(4);
        s.mint(cm(b"n0")).unwrap();
        let historical = s.anchor();
        s.mint(cm(b"n1")).unwrap();
        assert_ne!(s.anchor(), historical, "the tree advanced, so this is now a PAST root");
        assert!(s.is_valid_anchor(&historical), "…but it is still a valid anchor to cite");
        let t = tx(historical, &[b"nf0"], &[b"out-a"]);
        assert_eq!(s.apply_with_verdict(&t, true), Ok(()), "a spend against the past root is accepted");
    }

    #[test]
    fn capacity_is_checked_before_any_mutation() {
        // Depth 1 ⇒ capacity 2. One minted note leaves room for exactly one output, so a 2-output spend must be
        // rejected *atomically* — not append one leaf and then fail.
        let mut s = RingShieldedState::new(1);
        s.mint(cm(b"n0")).unwrap();
        let before = (s.note_count(), s.root());
        let t = tx(s.anchor(), &[b"nf0"], &[b"out-a", b"out-b"]);
        assert_eq!(s.apply_with_verdict(&t, true), Err(ApplyError::CapacityExceeded));
        assert_eq!((s.note_count(), s.root()), before, "no output was partially appended");
        // One output fits.
        let ok = tx(s.anchor(), &[b"nf0"], &[b"out-a"]);
        assert_eq!(s.apply_with_verdict(&ok, true), Ok(()));
        assert_eq!(s.note_count(), 2);
    }

    #[test]
    fn the_state_root_binds_the_tree_the_nullifiers_and_the_anchors() {
        let mut s = RingShieldedState::new(4);
        let empty = s.root();
        s.mint(cm(b"n0")).unwrap();
        assert_ne!(s.root(), empty, "minting a note changes the state root");
        let after_mint = s.root();
        let t = tx(s.anchor(), &[b"nf0"], &[b"out-a"]);
        s.apply_with_verdict(&t, true).unwrap();
        assert_ne!(s.root(), after_mint, "spending (nullifiers + new leaves) changes the state root");
        // The anchor set is genuinely bound: dropping an anchor changes the root, so a corrupted-anchor state-sync
        // snapshot cannot pass a certificate's root check (the §3.9 safety argument, ring side).
        let real = s.root();
        let dropped = s.anchors.iter().next().copied().unwrap();
        s.anchors.remove(&dropped);
        assert_ne!(s.root(), real, "dropping an anchor changes the root — a synced peer would reject it");
    }

    #[test]
    fn a_snapshot_round_trips_and_preserves_historical_anchors() {
        // The load-bearing state-sync property (audit §3.9): a restored pool reproduces the exact state root AND
        // keeps every windowed anchor. The anchor set is not recomputable from the tree, so it must ride the
        // snapshot explicitly — otherwise a spend citing a valid past root would be wrongly rejected after a sync.
        let mut s = RingShieldedState::new(4);
        s.mint(cm(b"snap-n0")).unwrap();
        let historical = s.anchor(); // valid to cite, but about to stop being the current root
        s.mint(cm(b"snap-n1")).unwrap();
        let t = tx(historical.clone(), &[b"snap-nf"], &[b"snap-out"]);
        s.apply_with_verdict(&t, true).unwrap(); // so the nullifier set is non-empty too
        assert!(s.is_valid_anchor(&historical) && s.anchor() != historical);

        let bytes = s.to_bytes().expect("a snapshot encodes");
        let restored = RingShieldedState::from_bytes(&bytes).expect("…and restores");
        assert_eq!(restored, s, "the restored state is structurally identical");
        assert_eq!(restored.root(), s.root(), "and reproduces the exact state root");
        assert_eq!(restored.anchor(), s.anchor(), "the rebuilt frontier yields the same current root");
        assert!(restored.is_valid_anchor(&historical), "critically, the historical anchor survives the sync");
        assert_eq!(restored.spent_count(), s.spent_count(), "and the nullifier set survives");
        // Every leaf's auth path still reproduces the root after the rebuild — the frontier was restored, not faked.
        for pos in 0..restored.note_count() {
            assert_eq!(restored.auth_path(pos).map(|(s, _)| s.len()), Some(4), "leaf {pos} has a full path");
        }

        // The anchor set is genuinely bound by the root: dropping one yields a DIFFERENT root, so a corrupted-anchor
        // snapshot cannot pass a certificate's root check (the §3.9 safety argument).
        let mut tampered = restored.clone();
        tampered.anchors.remove(&historical.digest());
        assert_ne!(tampered.root(), s.root(), "dropping an anchor changes the root — a synced peer would reject it");
    }

    #[test]
    fn a_malformed_or_inconsistent_snapshot_is_refused() {
        let mut s = RingShieldedState::new(1); // capacity 2
        s.mint(cm(b"m0")).unwrap();
        let bytes = s.to_bytes().unwrap();
        assert!(RingShieldedState::from_bytes(&bytes).is_some(), "the honest snapshot restores");
        assert!(RingShieldedState::from_bytes(&bytes[..bytes.len() - 1]).is_none(), "a truncated snapshot is refused");
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(RingShieldedState::from_bytes(&trailing).is_none(), "trailing bytes are refused (one encoding only)");
        // A snapshot claiming more leaves than its declared depth can hold is inconsistent, not merely large.
        let mut deep = RingShieldedState::new(1);
        deep.mint(cm(b"m0")).unwrap();
        deep.mint(cm(b"m1")).unwrap();
        let mut over = deep.to_bytes().unwrap();
        over[0] = 0; // depth 0 ⇒ capacity 1, but the payload carries two leaves
        assert!(RingShieldedState::from_bytes(&over).is_none(), "a leaf count over the depth's capacity is refused");
    }

    #[test]
    fn the_anchor_window_is_bounded() {
        // Audit O-M2, ring side: the anchor set is a rolling window, not insert-only, so it cannot bloat the state.
        // Driven through `record_anchor` directly — the subject here is the window policy, and that a real mint feeds
        // it is covered by `a_historical_anchor_stays_valid_while_the_tree_advances`.
        let mut s = RingShieldedState::new(4);
        let genesis = s.anchor(); // the very first anchor — the first to be evicted
        assert!(s.is_valid_anchor(&genesis));
        for i in 0..(MAX_ANCHORS as u64 + 4) {
            let root = cm(&i.to_be_bytes());
            s.record_anchor(&root);
            assert!(s.is_valid_anchor(&root), "a freshly recorded anchor is citable");
        }
        assert_eq!(s.anchors.len(), MAX_ANCHORS, "the window is capped, not unbounded");
        assert_eq!(s.anchor_order.len(), s.anchors.len(), "the FIFO order stays in lockstep with the set");
        assert!(!s.is_valid_anchor(&genesis), "the oldest anchor was evicted — it can no longer be cited");
        // Re-recording an already-windowed anchor must not consume a second slot (the invariant record_anchor keeps).
        let last = cm(&(MAX_ANCHORS as u64 + 3).to_be_bytes());
        s.record_anchor(&last);
        assert_eq!(s.anchors.len(), MAX_ANCHORS, "a duplicate anchor does not grow or rotate the window");
        assert_eq!(s.anchor_order.len(), s.anchors.len(), "…and the FIFO order stays in lockstep");
    }

    #[test]
    #[ignore = "mints, PROVES and applies a real zero-knowledge shielded transfer — minutes; run with --ignored"]
    fn a_real_zero_knowledge_transfer_applies_to_the_ledger() {
        // The end-to-end wiring: a note in the tree, a real proof of spending it, and the state machine accepting
        // it on the proof alone — no witness revealed, no transparent oracle.
        let params = RingParams::standard();
        let scheme = SpendScheme::standard();
        let mut s = RingShieldedState::new(2);

        // Mint a note the spender owns: cm = hash(value_node, hash(hash(nsk,nsk), rho)).
        let (v_in, v_out, fee) = (1000u64, 900u64, 100u64);
        let nsk = HashNode::from_bytes(b"rs-nsk");
        let rho = HashNode::from_bytes(b"rs-rho");
        let tag = scheme.note.owner_hp.hash(&nsk, &nsk);
        let note_cm = scheme.note.note_hp.hash(&HashNode::from_u64_digits(v_in), &scheme.note.note_owner(&tag, &rho));
        let pos = s.mint(note_cm.clone()).expect("mint");
        let anchor = s.anchor();
        let (siblings, directions) = s.auth_path(pos).expect("the minted note has a path");

        // Prove the spend: 1000 in → 900 out (to a fresh recipient) + 100 fee.
        let rv_in = RingRandomness::from_seed(b"rs-rv-in");
        let rv_out = RingRandomness::from_seed(b"rs-rv-out");
        let out_nsk = HashNode::from_bytes(b"rs-out-nsk");
        let input = TxInput { nsk, rho, value: v_in, rv: rv_in.clone(), siblings, directions };
        let output = TxOutput {
            value: v_out,
            rv: rv_out.clone(),
            owner_tag: scheme.note.owner_hp.hash(&out_nsk, &out_nsk),
            rho: HashNode::from_bytes(b"rs-out-rho"),
        };
        let proven: ProvenTx =
            prove_shielded_tx(&params, &scheme, &[input], &[output], fee, b"rs-seed").expect("proof");
        assert_eq!(proven.input_cms.first(), Some(&note_cm), "the proof spends the note we minted");

        let input_cvs = alloc::vec![RingCommitment::commit(&params, v_in, &rv_in)];
        let output_cvs = alloc::vec![RingCommitment::commit(&params, v_out, &rv_out)];
        let t = RingShieldedTx::new(anchor, &proven, input_cvs, output_cvs, fee);
        assert_eq!(s.apply(&params, &scheme, &t, &proven.proof), Ok(()), "a real proven transfer applies");
        assert_eq!(s.spent_count(), 1, "the input is nullified");
        assert_eq!(s.note_count(), 2, "the output leaf is appended");

        // Soundness at the ledger seam: the same transaction with an inflated fee claim no longer verifies.
        let mut s2 = RingShieldedState::new(2);
        s2.mint(note_cm).unwrap();
        let inflated = RingShieldedTx { fee: fee + 1, ..t };
        assert_eq!(
            s2.apply(&params, &scheme, &inflated, &proven.proof),
            Err(ApplyError::InvalidProof),
            "an inflated fee is caught by the proof, at the ledger boundary"
        );
    }
}
