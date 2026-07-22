//! The block, its hash-linked header, and the data-availability (DA) commitment (spec §10.1,
//! `docs/design-taxis.md` §4, §6).
//!
//! A [`BlockHeader`] is the small, canonically-encoded, hash-linked object that validators **vote on**. It
//! commits to the ordered transaction set (`tx_root`) and to the erasure-coded payload (`da_commit`), so a
//! validator can verify a proposer's header against the payload it actually shipped — a proposer cannot
//! finalize a header describing a payload it withheld or altered.
//!
//! The payload — the ordered [`SealedTx`] ciphertexts — is erasure-coded with the **projective LRC**
//! (`[7,3,4]` on the Fano cell, [`fanos_code::erasure`]) across the cell's seven nodes. Availability is then
//! checked by **DA sampling along lines** ([`fanos_code::da`]): by the DA theorem an unavailable payload has
//! `≤ 1` external line, so two distinct line-samples detect any withheld block with certainty. That check
//! gates PREPARE (see [`crate::consensus`]).

use alloc::vec::Vec;

use fanos_code::erasure;
use fanos_primitives::{Epoch, hash_labeled};
use fanos_wire::Wire;
use fanos_wire_derive::Wire;

use crate::tx::{SealedTx, TxCommit};

const HEADER_LABEL: &str = "FANOS-v1/taxis-block-header";
const TX_ROOT_LABEL: &str = "FANOS-v1/taxis-tx-root";
const DA_COMMIT_LABEL: &str = "FANOS-v1/taxis-da-commit";

/// The all-zero hash naming "no parent" — the genesis link.
pub const GENESIS_PARENT: [u8; 32] = [0u8; 32];

/// A block header — the hash-linked, voted-on object (spec §10.1). Canonically [`Wire`]-encoded, so every
/// validator hashes the identical bytes and agrees on the block hash.
#[derive(Clone, PartialEq, Eq, Debug, Wire)]
pub struct BlockHeader {
    /// The parent block's [`hash`](Self::hash), or [`GENESIS_PARENT`] at height 0.
    pub parent: [u8; 32],
    /// The block height (0 = genesis).
    pub height: u64,
    /// The epoch this block was proposed in (fixes the beacon leader schedule and sealing committees).
    pub epoch: Epoch,
    /// The elected proposer's validator index `0..7` (`crate::committee::leader`).
    pub proposer: u8,
    /// A binding commitment to the **ordered** list of transaction commitments (`H(commit₀ ‖ commit₁ ‖ …)`).
    pub tx_root: [u8; 32],
    /// A binding commitment to the erasure-coded payload shards — what DA sampling verifies against.
    pub da_commit: [u8; 32],
}

impl BlockHeader {
    /// The block hash: a domain-separated hash of the canonical header encoding. This is the identifier
    /// votes are cast over and children link to.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        hash_labeled(HEADER_LABEL, &self.to_wire())
    }
}

/// A full block: the voted-on [`BlockHeader`] plus the ordered sealed-transaction payload it commits to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    /// The hash-linked, voted-on header.
    pub header: BlockHeader,
    /// The ordered anti-MEV sealed transactions (the DA-sampled payload).
    pub sealed_txs: Vec<SealedTx>,
}

impl Block {
    /// Assemble a block from an ordered `sealed_txs` list: derives `tx_root` and `da_commit` from the
    /// payload and links `parent`. The proposer builds this; a validator re-derives the two commitments to
    /// check the header ([`verify_structure`](Self::verify_structure)).
    #[must_use]
    pub fn assemble(
        parent: [u8; 32],
        height: u64,
        epoch: Epoch,
        proposer: u8,
        sealed_txs: Vec<SealedTx>,
    ) -> Self {
        let tx_root = tx_root(&commits_of(&sealed_txs));
        let da_commit = commit_shards(&erasure::encode(&encode_payload(&sealed_txs)));
        let header = BlockHeader { parent, height, epoch, proposer, tx_root, da_commit };
        Self { header, sealed_txs }
    }

    /// The block hash (its header's hash).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }

    /// Canonical bytes: the fixed-width [`Wire`] header followed by the length-prefixed sealed-tx payload.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.header.to_wire();
        out.extend_from_slice(&encode_payload(&self.sealed_txs));
        out
    }

    /// Decode a block from [`to_bytes`](Self::to_bytes), or `None` if malformed. The receiver still calls
    /// [`verify_structure`](Self::verify_structure) — decoding trusts the bytes, verification checks them.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut cur = bytes;
        let header = BlockHeader::wire_decode(&mut cur).ok()?;
        let sealed_txs = decode_payload(cur)?;
        Some(Self { header, sealed_txs })
    }

    /// The ordered transaction commitments — what the proposer ordered by (blind to contents).
    #[must_use]
    pub fn tx_commits(&self) -> Vec<TxCommit> {
        commits_of(&self.sealed_txs)
    }

    /// The canonical payload bytes that are erasure-coded for DA (the ordered sealed-tx ciphertexts).
    #[must_use]
    pub fn payload_bytes(&self) -> Vec<u8> {
        encode_payload(&self.sealed_txs)
    }

    /// The `N = 7` projective-LRC shards of the payload (one per cell node) — the DA-coded block data.
    #[must_use]
    pub fn da_shards(&self) -> [Vec<u8>; erasure::N] {
        erasure::encode(&self.payload_bytes())
    }

    /// Whether the header's `tx_root` and `da_commit` genuinely match the payload — a proposer cannot
    /// finalize a header that describes a different (or withheld) payload than the one it shipped.
    #[must_use]
    pub fn verify_structure(&self) -> bool {
        let tx_root_ok = self.header.tx_root == tx_root(&self.tx_commits());
        let da_ok = self.header.da_commit == commit_shards(&self.da_shards());
        tx_root_ok && da_ok
    }

    /// Reconstruct a block's payload from a **subset** of its shards (an erased point is `None`) and verify
    /// the result against the header's `da_commit`. Returns the recovered sealed transactions, or `None` if
    /// the shard set is unrecoverable (the payload is genuinely unavailable, spec §6.3/§L4.3) or the
    /// re-encoded shards do not match the committed `da_commit` (tampered / wrong block).
    ///
    /// This is the availability check a validator runs after sampling: a withholding proposer leaves too few
    /// shards present, reconstruction fails, and the validator withholds its PREPARE.
    #[must_use]
    pub fn reconstruct_payload(&self, shards: &[Option<Vec<u8>>; erasure::N]) -> Option<Vec<SealedTx>> {
        let payload = erasure::reconstruct(shards)?;
        // Re-encode the recovered payload and check it matches the committed shards (binds availability to
        // *this* block, not some other payload that happens to be recoverable).
        if commit_shards(&erasure::encode(&payload)) != self.header.da_commit {
            return None;
        }
        decode_payload(&payload)
    }
}

/// The ordered transaction commitments of a sealed-tx list.
fn commits_of(sealed: &[SealedTx]) -> Vec<TxCommit> {
    sealed.iter().map(SealedTx::commit).collect()
}

/// A binding commitment to an ordered commitment list: `H(commit₀ ‖ commit₁ ‖ …)`. A flat hash suffices for
/// consensus safety (validators hold the full block); a Merkle tree would additionally give light clients
/// succinct inclusion proofs — a noted extension, not needed for finality.
fn tx_root(commits: &[TxCommit]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(commits.len() * 32);
    for c in commits {
        buf.extend_from_slice(c);
    }
    hash_labeled(TX_ROOT_LABEL, &buf)
}

/// A binding commitment to all `N = 7` payload shards: `H(len₀ ‖ shard₀ ‖ len₁ ‖ shard₁ ‖ …)`. A validator
/// that downloads a shard set verifies it against this before trusting the recovered payload.
fn commit_shards(shards: &[Vec<u8>; erasure::N]) -> [u8; 32] {
    let mut buf = Vec::new();
    for shard in shards {
        buf.extend_from_slice(&(shard.len() as u32).to_be_bytes());
        buf.extend_from_slice(shard);
    }
    hash_labeled(DA_COMMIT_LABEL, &buf)
}

/// Canonically encode the ordered sealed transactions as the payload — the [`Wire`] form of a
/// `Vec<Vec<u8>>` of per-tx bytes, so it reuses the audited length-prefixed sequence codec.
fn encode_payload(sealed: &[SealedTx]) -> Vec<u8> {
    let framed: Vec<Vec<u8>> = sealed.iter().map(SealedTx::to_bytes).collect();
    framed.to_wire()
}

/// Decode a payload produced by [`encode_payload`] back into sealed transactions, or `None` if malformed.
fn decode_payload(payload: &[u8]) -> Option<Vec<SealedTx>> {
    let framed: Vec<Vec<u8>> = Vec::<Vec<u8>>::from_wire(payload).ok()?;
    framed.iter().map(|b| SealedTx::from_bytes(b)).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_code::lrc::is_recoverable_fano;
    use fanos_pqcrypto::SeedRng;
    use fanos_pqcrypto::kem::{HybridKemPublic, HybridKemSecret};

    use crate::tx::Transaction;

    fn sealed_tx(tag: &[u8], epoch: Epoch) -> SealedTx {
        let kps: Vec<(HybridKemSecret, HybridKemPublic)> = (0..3).map(|i| {
            let mut rng = SeedRng::from_seed(&[tag.first().copied().unwrap_or(0), i]);
            HybridKemSecret::generate(&mut rng)
        }).collect();
        let pubs: Vec<&HybridKemPublic> = kps.iter().map(|(_, p)| p).collect();
        SealedTx::seal(&Transaction::new(tag.to_vec()), epoch, 0, &pubs, 2, tag).unwrap()
    }

    fn sample_block() -> Block {
        let txs = vec![sealed_tx(b"tx-one", Epoch::new(3)), sealed_tx(b"tx-two", Epoch::new(3))];
        Block::assemble(GENESIS_PARENT, 1, Epoch::new(3), 4, txs)
    }

    #[test]
    fn a_block_verifies_its_own_structure_and_hashes_stably() {
        let block = sample_block();
        assert!(block.verify_structure(), "the header commitments match the payload");
        assert_eq!(block.hash(), block.header.hash());
        // The header round-trips through its canonical Wire encoding (so all validators hash the same bytes).
        let bytes = block.header.to_wire();
        assert_eq!(BlockHeader::from_wire(&bytes).unwrap(), block.header);
    }

    #[test]
    fn a_tampered_header_fails_structure_verification() {
        let mut block = sample_block();
        // A proposer that lies about its tx set (swaps tx_root) is caught.
        block.header.tx_root[0] ^= 0xFF;
        assert!(!block.verify_structure(), "a mismatched tx_root is rejected");
    }

    #[test]
    fn the_full_shard_set_reconstructs_the_exact_payload() {
        let block = sample_block();
        let shards = block.da_shards();
        let present: [Option<Vec<u8>>; erasure::N] = core::array::from_fn(|p| Some(shards[p].clone()));
        let recovered = block.reconstruct_payload(&present).expect("full shards reconstruct");
        assert_eq!(recovered, block.sealed_txs, "the exact sealed transactions are recovered");
    }

    #[test]
    fn an_available_payload_survives_up_to_three_lost_shards() {
        // §L4/V20: the projective LRC recovers any ≤3 crashes — DA holds with up to 3 nodes withholding.
        let block = sample_block();
        let shards = block.da_shards();
        for missing in 0u8..=0x7F {
            if missing.count_ones() > 3 {
                continue;
            }
            let present: [Option<Vec<u8>>; erasure::N] =
                core::array::from_fn(|p| if missing & (1 << p) == 0 { Some(shards[p].clone()) } else { None });
            assert!(is_recoverable_fano(missing));
            assert_eq!(
                block.reconstruct_payload(&present).as_deref(),
                Some(block.sealed_txs.as_slice()),
                "≤3 lost shards still reconstruct (missing {missing:#09b})"
            );
        }
    }

    #[test]
    fn a_withheld_payload_is_detected_as_unavailable() {
        // A hyperoval loss (4 nodes, no 3 collinear) is the minimal UNrecoverable pattern — a proposer
        // withholding it cannot have its block reconstructed, so honest validators withhold PREPARE.
        let block = sample_block();
        let shards = block.da_shards();
        // Points {1,2,4} ... build a genuine hyperoval mask via is_recoverable_fano == false.
        let hyperoval = (0u8..=0x7F).find(|&m| !is_recoverable_fano(m)).unwrap();
        let present: [Option<Vec<u8>>; erasure::N] =
            core::array::from_fn(|p| if hyperoval & (1 << p) == 0 { Some(shards[p].clone()) } else { None });
        assert!(block.reconstruct_payload(&present).is_none(), "an unavailable payload cannot be reconstructed");
    }
}
