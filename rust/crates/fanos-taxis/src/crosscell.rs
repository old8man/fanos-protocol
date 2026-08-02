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
//! ([`compose_state_root`]). The source cell's [`ExecCertificate`] — a
//! `Q`-quorum attestation of that `state_root` at a height — therefore *also* certifies the outbox. A
//! [`CrossCellReceipt`] bundles the message, its Merkle inclusion proof, the `state_root` opening, and that
//! certificate; [`CrossCellReceipt::verify`] checks, against only the *source* cell's committee keys, that a
//! `Q`-quorum of the source cell certified a state whose outbox contains exactly this message. The destination
//! applies it on that proof alone — the bridge cannot forge, drop, or alter a cross-cell message, only relay
//! the receipt.

use alloc::vec::Vec;

use fanos_primitives::{hash_labeled, merkle};

use crate::checkpoint::ExecCertificate;

/// This subsystem's own leaf label. Deliberately local: [`merkle`] owns the internal-node label, so a leaf of *this*
/// tree can be neither an internal node nor a leaf of any other subsystem's tree.
const LEAF_LABEL: &str = "FANOS-v1/taxis-crossmsg-leaf";
const STATE_LABEL: &str = "FANOS-v1/taxis-state-root";

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

    /// Canonical bytes: `dest_cell(4) ‖ nonce(8) ‖ payload_len(4) ‖ payload`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 8 + 4 + self.payload.len());
        out.extend_from_slice(&self.dest_cell.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), returning the message and the byte count consumed, or `None`
    /// if malformed. (The count lets a container decode a message followed by more fields.)
    #[must_use]
    pub fn from_prefix(bytes: &[u8]) -> Option<(Self, usize)> {
        let dest_cell = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?);
        let nonce = u64::from_be_bytes(bytes.get(4..12)?.try_into().ok()?);
        let plen = usize::try_from(u32::from_be_bytes(bytes.get(12..16)?.try_into().ok()?)).ok()?;
        let payload = bytes.get(16..16 + plen)?.to_vec();
        Some((Self { dest_cell, nonce, payload }, 16 + plen))
    }
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
///
/// A domain-separated constant rather than zeros (`fanos_primitives::merkle::empty_root`): the previous `[0u8; 32]` was a
/// value a leaf hash could in principle take, so a certified empty outbox rested on preimage resistance to refuse an
/// opening. `merkle::verify` now refuses `count == 0` outright — nothing is inside an empty tree.
#[must_use]
pub fn empty_outbox_root() -> [u8; 32] {
    merkle::empty_root()
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

    /// Canonical bytes of the whole outbox (its ordered messages) — the state-sync snapshot of the cross-cell
    /// state a `StateMachine::snapshot` folds in alongside its application state (via the shared codec).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        fanos_primitives::codec::put_seq(&mut out, self.msgs.len(), &self.msgs, |o, m| {
            fanos_primitives::codec::put_var_bytes(o, &m.to_bytes());
        });
        out
    }

    /// Reconstruct an outbox from [`to_bytes`](Self::to_bytes), or `None` if malformed / over-long.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = fanos_primitives::codec::Reader::new(bytes);
        // Each message is length-prefixed (≥ 4) around its ≥ 16-byte body.
        let msgs = r.seq(20, |r| CrossMsg::from_prefix(r.var_bytes()?).map(|(m, _)| m))?;
        r.finish()?;
        Some(Self { msgs })
    }

    /// The Merkle root committing all messages (folded into `state_root` via [`compose_state_root`]).
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        // An outbox past `merkle::MAX_LEAVES` (2^32 messages in one height) is not constructible — the block size bounds it
        // orders of magnitude below — and committing a *wrong* root would be worse than committing the empty one.
        merkle::root(&self.leaves()).unwrap_or_else(merkle::empty_root)
    }

    fn leaves(&self) -> Vec<[u8; 32]> {
        self.msgs.iter().map(CrossMsg::leaf).collect()
    }

    /// Build the inclusion proof for the message at `index` (its Merkle path), or `None` if out of range.
    #[must_use]
    pub fn prove(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        merkle::prove(&self.leaves(), index)
    }

    /// Assemble a [`CrossCellReceipt`] for the message at `index`, given this cell's `accounts_root` and the
    /// source cell's execution certificate (which must certify `compose_state_root(accounts_root, self.root())`).
    #[must_use]
    pub fn receipt(&self, index: usize, accounts_root: [u8; 32], cert: ExecCertificate) -> Option<CrossCellReceipt> {
        let msg = self.msgs.get(index)?.clone();
        let proof = self.prove(index)?;
        let count = u64::try_from(self.msgs.len()).ok()?;
        Some(CrossCellReceipt { msg, index: index as u64, count, proof, accounts_root, outbox_root: self.root(), cert })
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
    /// The number of messages in the source outbox.
    ///
    /// Part of the opening, not decoration: `outbox_root` binds the count
    /// (`fanos_primitives::merkle`), so a receipt must state it and `verify` refuses any count that does not
    /// reproduce the certified root. This is what removes the CVE-2012-2459 ambiguity — under the previous
    /// unbound scheme the *bare* folds of `[a, b, c]` and `[a, b, c, c]` were equal, so one commitment had two
    /// readings. It also fixes the proof length, bounding the work an unauthenticated peer can ask a verifier
    /// for.
    pub count: u64,
    /// The Merkle authentication path into `outbox_root`. Its length must be exactly
    /// `fanos_primitives::merkle::height(count)`.
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
        merkle::verify(self.msg.leaf(), self.index, &self.proof, &self.outbox_root, self.count)
            .then_some(&self.msg)
    }

    /// Canonical bytes: `msg ‖ index(8) ‖ leaf_count(8) ‖ proof_len(2) ‖ proof(32·len) ‖ accounts_root(32) ‖
    /// outbox_root(32) ‖ cert` — the portable form a source cell publishes to a destination cell's inbox.
    ///
    /// `proof_len` stays on the wire even though `leaf_count` determines it, so a malformed receipt fails to
    /// *decode* rather than being reassembled into a shape `verify` must then reject.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.msg.to_bytes();
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&(self.proof.len() as u16).to_be_bytes());
        for sib in &self.proof {
            out.extend_from_slice(sib);
        }
        out.extend_from_slice(&self.accounts_root);
        out.extend_from_slice(&self.outbox_root);
        out.extend_from_slice(&self.cert.to_bytes());
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if malformed. The recovered receipt still needs
    /// [`verify`](Self::verify) against the source cell's committee keys before it is applied.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (msg, mut off) = CrossMsg::from_prefix(bytes)?;
        let index = u64::from_be_bytes(bytes.get(off..off + 8)?.try_into().ok()?);
        off += 8;
        let count = u64::from_be_bytes(bytes.get(off..off + 8)?.try_into().ok()?);
        off += 8;
        let proof_len = u32::from(u16::from_be_bytes(bytes.get(off..off + 2)?.try_into().ok()?));
        off += 2;
        // The count fixes the proof length, so a disagreeing header is refused HERE — before the length is used to size an
        // allocation. Previously this reserved capacity straight from an attacker-chosen `u16` and then folded every
        // sibling it had been handed (65 535 hashes from a ~2 MB receipt).
        if proof_len != merkle::height(count) {
            return None;
        }
        let mut proof = Vec::with_capacity(proof_len as usize);
        for _ in 0..proof_len {
            proof.push(bytes.get(off..off + 32)?.try_into().ok()?);
            off += 32;
        }
        let accounts_root = bytes.get(off..off + 32)?.try_into().ok()?;
        off += 32;
        let outbox_root = bytes.get(off..off + 32)?.try_into().ok()?;
        off += 32;
        let cert = ExecCertificate::from_bytes(bytes.get(off..)?)?;
        Some(Self { msg, index, count, proof, accounts_root, outbox_root, cert })
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
        let votes: Vec<ExecVote> = (0..q).map(|i| ExecVote::sign(5, state_root, [0xEE; 32], i as u8, &ks[i].0)).collect();
        let cert = ExecCertificate { height: 5, state_root, head: [0xEE; 32], votes };
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
    fn a_receipt_round_trips_and_still_verifies() {
        let msgs = [CrossMsg::new(2, 0, b"mint 10 to bob".to_vec()), CrossMsg::new(3, 1, b"note".to_vec())];
        let (verifiers, receipt) = certified_outbox(&msgs, [0x66; 32], 1, 5);
        let rt = CrossCellReceipt::from_bytes(&receipt.to_bytes()).unwrap();
        assert_eq!(rt, receipt, "the receipt round-trips through bytes (message, proof, opening, certificate)");
        assert_eq!(rt.verify(&verifiers, 5), Some(&msgs[1]), "a decoded receipt still verifies against the source committee");
        assert!(CrossCellReceipt::from_bytes(&receipt.to_bytes()[..20]).is_none(), "a truncated receipt is rejected");
    }

    #[test]
    fn the_certified_leaf_count_is_part_of_the_opening() {
        // The generic tree properties (every leaf of every size opens; the duplicate-tail ambiguity; a wrong-shaped proof)
        // are exhaustively covered in `fanos_primitives::merkle`. What is specific to a receipt is that the COUNT is part
        // of what the source cell certified, so misstating it cannot open the certified root.
        let msgs = [
            CrossMsg::new(2, 0, b"a".to_vec()),
            CrossMsg::new(2, 1, b"b".to_vec()),
            CrossMsg::new(2, 2, b"c".to_vec()),
        ];
        let (verifiers, receipt) = certified_outbox(&msgs, [0x77; 32], 2, 5);
        assert!(receipt.verify(&verifiers, 5).is_some(), "the honest receipt verifies");

        // A count of 4 for a 3-message outbox is exactly the CVE-2012-2459 reading — under the previous unbound scheme the
        // bare folds of `[a, b, c]` and `[a, b, c, c]` were equal, so the same certified root had two readings.
        for wrong in [0u64, 2, 4, 8, u64::MAX] {
            let mut forged = receipt.clone();
            forged.count = wrong;
            assert!(forged.verify(&verifiers, 5).is_none(), "count {wrong} must not open a root committed at 3");
        }

        // And the duplicate index the old scheme admitted is refused outright: index 3 does not exist at count 3.
        let mut dup = receipt.clone();
        dup.index = 3;
        dup.count = 4;
        assert!(dup.verify(&verifiers, 5).is_none(), "the duplicated tail is not a fourth message");
    }

    #[test]
    fn a_receipt_whose_proof_length_disagrees_with_its_count_does_not_decode() {
        // The bound on attacker-chosen verifier work. Previously the proof length was an independent `u16` on the wire:
        // the decoder reserved capacity from it and the verifier folded every sibling handed over — 65 535 hashes from a
        // ~2 MB receipt. The count now fixes the length, and the mismatch is refused at decode time.
        let msgs = [CrossMsg::new(2, 0, b"a".to_vec()), CrossMsg::new(2, 1, b"b".to_vec())];
        let (verifiers, receipt) = certified_outbox(&msgs, [0x88; 32], 0, 5);
        let bytes = receipt.to_bytes();
        assert!(CrossCellReceipt::from_bytes(&bytes).is_some(), "the honest encoding decodes");

        // `msg ‖ index(8) ‖ count(8) ‖ proof_len(2) ‖ …` — overwrite the length header in place.
        let at = bytes.len() - (2 + 32 * receipt.proof.len() + 32 + 32 + receipt.cert.to_bytes().len());
        for claimed in [0u16, 2, 40, u16::MAX] {
            let mut tampered = bytes.clone();
            tampered[at..at + 2].copy_from_slice(&claimed.to_be_bytes());
            assert!(
                CrossCellReceipt::from_bytes(&tampered).is_none(),
                "proof_len {claimed} disagrees with height(2) = 1 and must be refused before allocating"
            );
        }
        // Sanity: the real length is what the count implies, so `verify` never sees a shape it must reject.
        assert_eq!(receipt.proof.len() as u32, merkle::height(receipt.count));
        assert!(receipt.verify(&verifiers, 5).is_some());
    }

    #[test]
    fn an_empty_outbox_root_is_domain_separated_and_opens_to_nothing() {
        // It was `[0u8; 32]`, a value a leaf hash could in principle take, so refusing an opening rested on preimage
        // resistance rather than on the scheme.
        assert_ne!(empty_outbox_root(), [0u8; 32], "the empty root must not be a value a leaf could take");
        assert_eq!(Outbox::new().root(), empty_outbox_root(), "an outbox with no messages commits the empty root");
        let msgs = [CrossMsg::new(2, 0, b"a".to_vec())];
        let (verifiers, receipt) = certified_outbox(&msgs, [0x99; 32], 0, 5);
        let mut empty = receipt.clone();
        empty.count = 0;
        empty.proof.clear();
        assert!(empty.verify(&verifiers, 5).is_none(), "nothing is inside an empty tree");
    }
}
