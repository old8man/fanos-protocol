//! **Trust-minimized cross-cell messaging** — the L0 primitive that lets one projective cell act on another
//! cell's finalized state *without trusting a bridge node* (`docs/design-self-organization.md` §6,
//! `docs/design-taxis.md` §7).
//!
//! FANOS shards by geometry: each cell runs its own TAXIS ledger, and two cells' committees meet in a unique
//! Maekawa bridge point (`committee::cross_shard_bridge`). The bridge *routes* a cross-shard transaction, but a
//! destination cell must not have to *trust* it. This module supplies the proof it verifies instead.
//!
//! A cross-cell message is emitted as an execution side-effect in the *source* cell and accumulated into an
//! [`Outbox`], whose Merkle [`root`](Outbox::root) the source state machine folds into its `state_root`
//! ([`compose_state_root`]). The source cell's [`ExecCertificate`](crate::checkpoint::ExecCertificate) — a
//! `Q`-quorum attestation of that `state_root` at a height — therefore *also* certifies the outbox. A
//! [`CrossCellReceipt`] bundles the message, its Merkle inclusion proof, the `state_root` opening, and that
//! certificate; [`CrossCellReceipt::verify`] checks, against only the *source* cell's committee keys, that a
//! `Q`-quorum of the source cell certified a state whose outbox contains exactly this message. The destination
//! applies it on that proof alone — the bridge cannot forge, drop, or alter a cross-cell message, only relay
//! the receipt.

use alloc::vec::Vec;

use fanos_primitives::hash_labeled;

use crate::checkpoint::ExecCertificate;

const LEAF_LABEL: &str = "FANOS-v1/taxis-crossmsg-leaf";
const NODE_LABEL: &str = "FANOS-v1/taxis-merkle-node";
const STATE_LABEL: &str = "FANOS-v1/taxis-state-root";
/// The Merkle root of an empty outbox (a cell that emitted no cross-cell messages this height).
const EMPTY_ROOT: [u8; 32] = [0u8; 32];

/// A cross-cell message: an outbound payload from this cell to `dest_cell`, uniquely identified by `nonce`
/// (the destination de-duplicates by `(source_cell, nonce)` for replay protection).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CrossMsg {
    /// The destination cell identifier (its geometric address in the hierarchy).
    pub dest_cell: u32,
    /// A per-source monotonic nonce — the destination applies each `(source, nonce)` at most once.
    pub nonce: u64,
    /// The application payload the destination cell interprets.
    pub payload: Vec<u8>,
}

impl CrossMsg {
    /// A cross-cell message.
    #[must_use]
    pub fn new(dest_cell: u32, nonce: u64, payload: impl Into<Vec<u8>>) -> Self {
        Self { dest_cell, nonce, payload: payload.into() }
    }

    /// The message's Merkle leaf: `H(dest_cell ‖ nonce ‖ len ‖ payload)` — a binding commitment to the whole
    /// message (the length prefix makes the encoding unambiguous).
    #[must_use]
    pub fn leaf(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(4 + 8 + 8 + self.payload.len());
        buf.extend_from_slice(&self.dest_cell.to_be_bytes());
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        buf.extend_from_slice(&(self.payload.len() as u64).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        hash_labeled(LEAF_LABEL, &buf)
    }
}

/// Hash two Merkle children into their parent (domain-separated from leaves).
fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    hash_labeled(NODE_LABEL, &buf)
}

/// The Merkle root over `leaves`, padding each level's odd tail by duplicating the last node. Empty ⇒
/// [`EMPTY_ROOT`].
#[must_use]
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return EMPTY_ROOT;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level.get(i).copied().unwrap_or(EMPTY_ROOT);
            let right = level.get(i + 1).copied().unwrap_or(left); // duplicate-last on an odd tail
            next.push(node(&left, &right));
            i += 2;
        }
        level = next;
    }
    level.first().copied().unwrap_or(EMPTY_ROOT)
}

/// The Merkle authentication path (sibling hashes, bottom-up) for the leaf at `index`, or `None` if out of
/// range. The path length is the tree height; each step pairs with the sibling, duplicating the last node on an
/// odd tail exactly as [`merkle_root`] does.
#[must_use]
fn merkle_prove(leaves: &[[u8; 32]], index: usize) -> Option<Vec<[u8; 32]>> {
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        let sibling = if idx.is_multiple_of(2) {
            level.get(idx + 1).copied().unwrap_or_else(|| level.get(idx).copied().unwrap_or(EMPTY_ROOT))
        } else {
            level.get(idx - 1).copied().unwrap_or(EMPTY_ROOT)
        };
        path.push(sibling);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level.get(i).copied().unwrap_or(EMPTY_ROOT);
            let right = level.get(i + 1).copied().unwrap_or(left);
            next.push(node(&left, &right));
            i += 2;
        }
        level = next;
        idx /= 2;
    }
    Some(path)
}

/// Whether `leaf` at `index` authenticates against `root` under `proof` (the sibling path from
/// [`merkle_prove`]).
#[must_use]
fn merkle_verify(leaf: [u8; 32], index: usize, proof: &[[u8; 32]], root: &[u8; 32]) -> bool {
    let mut acc = leaf;
    let mut idx = index;
    for sib in proof {
        acc = if idx.is_multiple_of(2) { node(&acc, sib) } else { node(sib, &acc) };
        idx /= 2;
    }
    &acc == root
}

/// The `state_root` a **cross-cell-aware** state machine commits: `H(accounts_root ‖ outbox_root)` — binding
/// the ordinary application state *and* the height's cross-cell outbox under one root, so the execution
/// certificate over `state_root` certifies both. A plain state machine that emits no cross-cell messages can
/// use `outbox_root = ` [`empty_outbox_root`] and this reduces to committing the application state.
#[must_use]
pub fn compose_state_root(accounts_root: &[u8; 32], outbox_root: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(accounts_root);
    buf[32..].copy_from_slice(outbox_root);
    hash_labeled(STATE_LABEL, &buf)
}

/// The outbox root of a cell that emitted no cross-cell messages.
#[must_use]
pub fn empty_outbox_root() -> [u8; 32] {
    EMPTY_ROOT
}

/// The source cell's **outbox** for one executed height — the ordered cross-cell messages produced, committed
/// by their Merkle [`root`](Outbox::root).
#[derive(Clone, Default, Debug)]
pub struct Outbox {
    msgs: Vec<CrossMsg>,
}

impl Outbox {
    /// A fresh, empty outbox.
    #[must_use]
    pub fn new() -> Self {
        Self { msgs: Vec::new() }
    }

    /// Append an outbound message (in execution order).
    pub fn push(&mut self, msg: CrossMsg) {
        self.msgs.push(msg);
    }

    /// The number of messages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.msgs.len()
    }

    /// Whether the outbox is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }

    /// The Merkle root committing all messages (folded into `state_root` via [`compose_state_root`]).
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        merkle_root(&self.leaves())
    }

    fn leaves(&self) -> Vec<[u8; 32]> {
        self.msgs.iter().map(CrossMsg::leaf).collect()
    }

    /// Build the inclusion proof for the message at `index` (its Merkle path), or `None` if out of range.
    #[must_use]
    pub fn prove(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        merkle_prove(&self.leaves(), index)
    }

    /// Assemble a [`CrossCellReceipt`] for the message at `index`, given this cell's `accounts_root` and the
    /// source cell's execution certificate (which must certify `compose_state_root(accounts_root, self.root())`).
    #[must_use]
    pub fn receipt(&self, index: usize, accounts_root: [u8; 32], cert: ExecCertificate) -> Option<CrossCellReceipt> {
        let msg = self.msgs.get(index)?.clone();
        let proof = self.prove(index)?;
        Some(CrossCellReceipt { msg, index: index as u64, proof, accounts_root, outbox_root: self.root(), cert })
    }
}

/// A portable, self-verifying proof that a source cell *canonically emitted* a cross-cell message. Carries the
/// message, its Merkle inclusion proof, the `state_root` opening `(accounts_root, outbox_root)`, and the source
/// cell's execution certificate over that `state_root`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CrossCellReceipt {
    /// The certified cross-cell message.
    pub msg: CrossMsg,
    /// The message's index in the source outbox.
    pub index: u64,
    /// The Merkle authentication path into `outbox_root`.
    pub proof: Vec<[u8; 32]>,
    /// The source cell's application-state root (the other half of the `state_root` opening).
    pub accounts_root: [u8; 32],
    /// The source cell's outbox root (the message is proven to be in this).
    pub outbox_root: [u8; 32],
    /// The source cell's `Q`-quorum execution certificate over `compose_state_root(accounts_root, outbox_root)`.
    pub cert: ExecCertificate,
}

impl CrossCellReceipt {
    /// Verify against the **source** cell's committee: the execution certificate is a valid `Q`-quorum, its
    /// certified `state_root` opens to `(accounts_root, outbox_root)`, and `msg` is in `outbox_root` at `index`.
    /// Returns the certified message iff all three hold — the destination applies it on this proof alone,
    /// trusting no bridge. (Replay protection — applying each `(source, nonce)` once — is the destination state
    /// machine's responsibility; this proves *emission*, the destination enforces *once*.)
    #[must_use]
    pub fn verify(
        &self,
        source_verifiers: &[fanos_pqcrypto::HybridVerifier],
        quorum: usize,
    ) -> Option<&CrossMsg> {
        if !self.cert.verify(quorum, source_verifiers) {
            return None; // not a genuine Q-quorum of the source cell
        }
        if compose_state_root(&self.accounts_root, &self.outbox_root) != self.cert.state_root {
            return None; // the opening does not match the certified state root
        }
        let idx = usize::try_from(self.index).ok()?;
        merkle_verify(self.msg.leaf(), idx, &self.proof, &self.outbox_root).then_some(&self.msg)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};

    use crate::checkpoint::ExecVote;

    fn keys(n: usize) -> Vec<(HybridSigSecret, HybridVerifier)> {
        (0..n)
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[0xCC, i as u8]);
                HybridSigSecret::generate(&mut rng)
            })
            .collect()
    }

    /// A source cell that emitted `msgs`, certified by `q` of its validators; returns (verifiers, receipt for
    /// message `index`) — the exact bundle a destination cell receives from a bridge.
    fn certified_outbox(
        msgs: &[CrossMsg],
        accounts_root: [u8; 32],
        index: usize,
        q: usize,
    ) -> (Vec<HybridVerifier>, CrossCellReceipt) {
        let ks = keys(7);
        let verifiers: Vec<HybridVerifier> = ks.iter().map(|(_, v)| v.clone()).collect();
        let mut outbox = Outbox::new();
        for m in msgs {
            outbox.push(m.clone());
        }
        let state_root = compose_state_root(&accounts_root, &outbox.root());
        let votes: Vec<ExecVote> = (0..q).map(|i| ExecVote::sign(5, state_root, i as u8, &ks[i].0)).collect();
        let cert = ExecCertificate { height: 5, state_root, votes };
        let receipt = outbox.receipt(index, accounts_root, cert).unwrap();
        (verifiers, receipt)
    }

    #[test]
    fn a_certified_cross_cell_message_verifies_against_the_source_committee() {
        let msgs = [
            CrossMsg::new(2, 0, b"mint 10 to bob".to_vec()),
            CrossMsg::new(2, 1, b"mint 5 to carol".to_vec()),
            CrossMsg::new(3, 0, b"note".to_vec()),
        ];
        let (verifiers, receipt) = certified_outbox(&msgs, [0x11; 32], 1, 5);
        // The destination verifies with ONLY the source cell's keys + quorum — no bridge trust.
        assert_eq!(receipt.verify(&verifiers, 5), Some(&msgs[1]), "the emitted message is proven");
        assert_eq!(receipt.msg.dest_cell, 2);
    }

    #[test]
    fn a_forged_or_altered_message_is_rejected() {
        let msgs = [CrossMsg::new(2, 0, b"mint 10".to_vec()), CrossMsg::new(2, 1, b"mint 5".to_vec())];
        let (verifiers, mut receipt) = certified_outbox(&msgs, [0x22; 32], 0, 5);
        assert!(receipt.verify(&verifiers, 5).is_some());
        // Tamper the message: its leaf no longer matches the proven outbox root.
        receipt.msg.payload = b"mint 1000000".to_vec();
        assert!(receipt.verify(&verifiers, 5).is_none(), "an altered message fails Merkle inclusion");
    }

    #[test]
    fn a_message_not_in_the_certified_outbox_is_rejected() {
        // Certify an outbox of ONE message, then try to claim a DIFFERENT message under the same certificate.
        let real = [CrossMsg::new(2, 0, b"real".to_vec())];
        let (verifiers, receipt) = certified_outbox(&real, [0x33; 32], 0, 5);
        let mut forged = receipt.clone();
        forged.msg = CrossMsg::new(2, 9, b"never emitted".to_vec());
        assert!(forged.verify(&verifiers, 5).is_none(), "a message never emitted cannot be proven");
    }

    #[test]
    fn a_forged_state_root_opening_is_rejected() {
        let msgs = [CrossMsg::new(2, 0, b"x".to_vec())];
        let (verifiers, mut receipt) = certified_outbox(&msgs, [0x44; 32], 0, 5);
        // Swap in a different accounts_root — the opening no longer hashes to the certified state root.
        receipt.accounts_root = [0xFF; 32];
        assert!(receipt.verify(&verifiers, 5).is_none(), "the opening must match the certified state root");
    }

    #[test]
    fn a_sub_quorum_certificate_is_rejected() {
        let msgs = [CrossMsg::new(2, 0, b"x".to_vec())];
        // Only 4 validators attested, but the destination demands a 5-quorum.
        let (verifiers, receipt) = certified_outbox(&msgs, [0x55; 32], 0, 4);
        assert!(receipt.verify(&verifiers, 5).is_none(), "fewer than Q attestations does not certify");
        assert!(receipt.verify(&verifiers, 4).is_some(), "the matching quorum verifies");
    }

    #[test]
    fn merkle_paths_authenticate_at_every_position_and_size() {
        // Exhaustive small-tree check: every leaf of every outbox size 1..=9 proves against the root, and a
        // wrong index does not.
        for n in 1..=9usize {
            let leaves: Vec<[u8; 32]> = (0..n).map(|i| hash_labeled("t", &[i as u8])).collect();
            let root = merkle_root(&leaves);
            for i in 0..n {
                let proof = merkle_prove(&leaves, i).unwrap();
                assert!(merkle_verify(leaves[i], i, &proof, &root), "n={n} leaf {i} authenticates");
                if n > 1 {
                    let wrong = (i + 1) % n;
                    assert!(!merkle_verify(leaves[i], wrong, &proof, &root), "n={n} leaf {i} at wrong index fails");
                }
            }
            assert!(merkle_prove(&leaves, n).is_none(), "out-of-range index has no proof");
        }
    }
}
