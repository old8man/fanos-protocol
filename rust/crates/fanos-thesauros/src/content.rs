//! The **content model** — content-addressed objects over a position-bound BLAKE3 Merkle tree.
//!
//! An object's (already-encrypted) bytes are split into fixed-size [`LEAF`] leaves; each leaf is hashed
//! **with its index** (`H(label, index ‖ bytes)`), and a binary Merkle tree over those leaf hashes yields the
//! **content id** [`Cid`] = the root. The CID is content-addressed-by-value (fetch, recompute, verify — no
//! authority) *and* the commitment a proof of retrievability opens against. Objects larger than one [`CHUNK`]
//! are split into chunks, each with its own CID, and a [`Manifest`] lists them — a Merkle DAG. A lone odd node
//! at any tree level is promoted unchanged, so the scheme is defined for any leaf count.
//!
//! Position-binding is the load-bearing subtlety: because a leaf's hash includes its index, a valid Merkle
//! path for leaf *i* proves possession of *the bytes at position i*, not merely of *some* leaf — so a provider
//! cannot answer every audit challenge with one cached leaf and its path.

use alloc::vec::Vec;

use fanos_primitives::{hash_labeled, merkle};

/// The Merkle leaf size (bytes): the granularity a proof of retrievability samples.
pub const LEAF: usize = 4096;
/// The chunk size (bytes): objects larger than this are split into chunks under a [`Manifest`].
pub const CHUNK: usize = 262_144;

/// Domain label for a position-bound leaf hash. The internal-node label belongs to `fanos_primitives::merkle`, which
/// owns the tree — keeping this one local is what stops a thesauros leaf from being read as any other subsystem's.
const LEAF_LABEL: &str = "FANOS-v1/thesauros-leaf";

/// A **content id** — the Merkle root of an object, its address and its storage commitment.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Cid([u8; 32]);

impl Cid {
    /// A CID from its 32 raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A Merkle authentication path from a leaf to the root (leaf level first): one sibling hash per level.
///
/// Which side each sibling is on is **derived from the index**, not carried. Carrying it, as this did, gave a prover a
/// free choice the commitment never authorised: the verifier followed the prover's own flags, so the path's shape was
/// unconstrained by the position it claimed. Position-bound leaf hashing kept that sound, but a constraint available for
/// nothing should not be given away — and the same change lets [`verify_leaf`] demand an exact length, which is what
/// bounds the work an untrusted provider can ask a verifier to do.
pub type MerkleProof = Vec<[u8; 32]>;

/// The position-bound hash of the `index`-th leaf: `H(leaf, index_le(8) ‖ bytes)`.
#[must_use]
fn leaf_hash(index: usize, bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + bytes.len());
    buf.extend_from_slice(&(index as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
    hash_labeled(LEAF_LABEL, &buf)
}

/// The position-bound leaf hashes of a chunk (an empty chunk is one empty leaf).
#[must_use]
fn leaf_hashes(chunk: &[u8]) -> Vec<[u8; 32]> {
    if chunk.is_empty() {
        return alloc::vec![leaf_hash(0, &[])];
    }
    chunk.chunks(LEAF).enumerate().map(|(i, b)| leaf_hash(i, b)).collect()
}

/// The Merkle root over already-computed leaf hashes, via the platform's shared tree.
///
/// `fanos_primitives::merkle` binds the leaf count into the root, so a chunk id is no longer a value a bare leaf hash can
/// take — previously a one-leaf chunk's id *was* its leaf hash, putting ids and leaf hashes in one space. Position-bound
/// leaves ([`leaf_hash`]) still do their own job on top: a leaf cannot be replayed at another index.
#[must_use]
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    merkle::root(leaves).unwrap_or_else(merkle::empty_root)
}

/// The number of leaves in a chunk.
#[must_use]
pub fn leaf_count(chunk: &[u8]) -> usize {
    if chunk.is_empty() { 1 } else { chunk.len().div_ceil(LEAF) }
}

/// The `index`-th leaf slice of a chunk, if in range.
#[must_use]
pub fn leaf(chunk: &[u8], index: usize) -> Option<&[u8]> {
    if chunk.is_empty() {
        return if index == 0 { Some(&[]) } else { None };
    }
    chunk.chunks(LEAF).nth(index)
}

/// The content id of a single chunk (`≤ CHUNK` bytes).
#[must_use]
pub fn chunk_cid(chunk: &[u8]) -> Cid {
    Cid(merkle_root(&leaf_hashes(chunk)))
}

/// The Merkle authentication path proving the `index`-th leaf's membership, or `None` if out of range.
#[must_use]
pub fn merkle_proof(chunk: &[u8], index: usize) -> Option<MerkleProof> {
    merkle::prove(&leaf_hashes(chunk), index)
}

/// The leaf bytes and their Merkle path — a proof-of-retrievability response for one challenged index.
#[must_use]
pub fn prove_leaf(chunk: &[u8], index: usize) -> Option<(Vec<u8>, MerkleProof)> {
    let proof = merkle_proof(chunk, index)?;
    let bytes = leaf(chunk, index)?.to_vec();
    Some((bytes, proof))
}

/// Verify that `leaf_bytes` really is the `index`-th of the `leaves` leaves committed by `cid`, via `proof`.
///
/// Doubly bound. **Position**: the leaf hash folds its index, so a proof for one position cannot verify another's bytes.
/// **Shape**: `leaves` fixes both the root ([`chunk_cid`] binds the count) and the exact path length, so a proof of any
/// other length is refused before a single hash is computed. That second bound is the one an untrusted provider used to be
/// free of — `verify_leaf` folded however many steps it was handed, and the PoR wire format allowed 65 535 of them.
///
/// `leaves` must come from something the prover does not control: in the audit path it is derived from the *manifest's*
/// chunk length (`por::verify`), which the object's own commitment covers.
#[must_use]
pub fn verify_leaf(cid: &Cid, index: usize, leaf_bytes: &[u8], proof: &[[u8; 32]], leaves: usize) -> bool {
    let Ok(count) = u64::try_from(leaves) else { return false };
    let Ok(index) = u64::try_from(index) else { return false };
    merkle::verify(leaf_hash(index as usize, leaf_bytes), index, proof, cid.as_bytes(), count)
}

/// One chunk of an object in a [`Manifest`]: its content id and byte length.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChunkRef {
    /// The chunk's content id.
    pub cid: Cid,
    /// The chunk's length in bytes.
    pub len: u32,
}

/// A **manifest** — the ordered list of an object's chunks (a Merkle-DAG object in its own right).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Manifest {
    /// The object's chunks, in order.
    pub chunks: Vec<ChunkRef>,
}

impl Manifest {
    /// Build the manifest of an object by splitting it into [`CHUNK`]-sized chunks and addressing each.
    #[must_use]
    pub fn of(object: &[u8]) -> Self {
        let chunks = object
            .chunks(CHUNK)
            .map(|c| ChunkRef { cid: chunk_cid(c), len: u32::try_from(c.len()).unwrap_or(u32::MAX) })
            .collect();
        Self { chunks }
    }

    /// The object's total length in bytes.
    #[must_use]
    pub fn total_len(&self) -> u64 {
        self.chunks.iter().map(|c| u64::from(c.len)).sum()
    }

    /// Canonical bytes: `count(4, LE) ‖ [ cid(32) ‖ len(4, LE) ] × count`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.chunks.len() * 36);
        out.extend_from_slice(&u32::try_from(self.chunks.len()).unwrap_or(u32::MAX).to_le_bytes());
        for c in &self.chunks {
            out.extend_from_slice(c.cid.as_bytes());
            out.extend_from_slice(&c.len.to_le_bytes());
        }
        out
    }

    /// Decode from [`encode`](Self::encode), or `None` if malformed / truncated / over-long.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let count = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        let body = bytes.get(4..)?;
        if body.len() != count.checked_mul(36)? {
            return None;
        }
        let mut chunks = Vec::with_capacity(count);
        for entry in body.chunks(36) {
            let cid = Cid::new(entry.get(..32)?.try_into().ok()?);
            let len = u32::from_le_bytes(entry.get(32..36)?.try_into().ok()?);
            chunks.push(ChunkRef { cid, len });
        }
        Some(Self { chunks })
    }

    /// The manifest's own content id (it is stored as an ordinary object).
    #[must_use]
    pub fn cid(&self) -> Cid {
        chunk_cid(&self.encode())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_chunk_id_is_never_a_bare_leaf_hash() {
        // This used to assert the opposite — a one-leaf chunk's id WAS its leaf hash — which put ids and leaf hashes in
        // one value space. The shared tree binds the leaf count into the root, so the two are now distinguishable by
        // construction, and a leaf can no longer be presented as a whole object.
        let data = b"small object";
        assert_ne!(chunk_cid(data), Cid(leaf_hash(0, data)), "an id must not collide with the leaf it commits");
        assert_eq!(chunk_cid(data), Cid(merkle::root(&[leaf_hash(0, data)]).unwrap()), "it is the count-bound root");
    }

    #[test]
    fn an_untrusted_provers_path_length_is_fixed_by_the_authenticated_leaf_count() {
        // The bound that was missing: `verify_leaf` folded however many steps it was handed, and the PoR wire format
        // allowed 65 535 of them. The count comes from the manifest, which the prover does not control, so a path of any
        // other length is refused before a single hash.
        let data = alloc::vec![7u8; LEAF * 5 + 3];
        let cid = chunk_cid(&data);
        let n = leaf_count(&data);
        let (bytes, proof) = prove_leaf(&data, 2).expect("a leaf");
        assert!(verify_leaf(&cid, 2, &bytes, &proof, n), "the honest path verifies");
        assert_eq!(proof.len() as u32, merkle::height(n as u64), "and its length is what the count implies");

        let mut long = proof.clone();
        long.push([0u8; 32]);
        assert!(!verify_leaf(&cid, 2, &bytes, &long, n), "one step too many is refused");
        assert!(!verify_leaf(&cid, 2, &bytes, &proof[..proof.len() - 1], n), "one too few is refused");
        assert!(!verify_leaf(&cid, 2, &bytes, &alloc::vec![[0u8; 32]; 65_535], n), "a flood is refused, not folded");
        // Nor can the prover shift the count to make its own path the right shape.
        for wrong in [1usize, 2, 4, 8, 64] {
            assert!(!verify_leaf(&cid, 2, &bytes, &proof, wrong), "count {wrong} must not open a 6-leaf commitment");
        }
    }

    #[test]
    fn every_leaf_proves_and_a_wrong_index_or_byte_fails() {
        // A chunk spanning several leaves (odd count to exercise promotion).
        let data: Vec<u8> = (0..LEAF * 4 + 100).map(|i| i as u8).collect();
        let cid = chunk_cid(&data);
        let n = leaf_count(&data);
        assert_eq!(n, 5, "4 full leaves + a partial one");
        for i in 0..n {
            let (bytes, proof) = prove_leaf(&data, i).expect("a leaf");
            assert!(verify_leaf(&cid, i, &bytes, &proof, n), "leaf {i} verifies");
            // The right bytes at the WRONG index must not verify (position-binding).
            let wrong_index = (i + 1) % n;
            assert!(!verify_leaf(&cid, wrong_index, &bytes, &proof, n), "leaf {i} bytes do not verify as {wrong_index}");
            // A tampered byte must not verify.
            let mut bad = bytes.clone();
            if let Some(b) = bad.first_mut() {
                *b ^= 0xFF;
            }
            assert!(!verify_leaf(&cid, i, &bad, &proof, n), "tampered leaf {i} does not verify");
        }
        assert!(prove_leaf(&data, n).is_none(), "an out-of-range leaf has no proof");
    }

    #[test]
    fn the_cid_is_stable_a_known_answer() {
        // A fixed 2-leaf chunk must address to fixed bytes so every implementation agrees.
        let mut data = alloc::vec![0xABu8; LEAF];
        data.extend_from_slice(&[0xCD; 100]);
        let cid = chunk_cid(&data);
        // Root = the shared tree over the two position-bound leaves.
        let expect = merkle::root(&[leaf_hash(0, &data[..LEAF]), leaf_hash(1, &data[LEAF..])]).unwrap();
        assert_eq!(cid.as_bytes(), &expect);
    }

    #[test]
    fn a_manifest_round_trips_and_addresses_a_large_object() {
        let object: Vec<u8> = (0..CHUNK * 2 + 500).map(|i| (i * 7) as u8).collect();
        let manifest = Manifest::of(&object);
        assert_eq!(manifest.chunks.len(), 3, "2 full chunks + a partial one");
        assert_eq!(manifest.total_len(), object.len() as u64);
        // Each manifest entry addresses its actual chunk.
        for (i, chunk) in object.chunks(CHUNK).enumerate() {
            assert_eq!(manifest.chunks[i].cid, chunk_cid(chunk), "chunk {i} cid");
        }
        // Encoding round-trips and rejects corruption.
        let bytes = manifest.encode();
        assert_eq!(Manifest::decode(&bytes), Some(manifest.clone()));
        assert_eq!(Manifest::decode(&bytes[..bytes.len() - 1]), None, "truncation rejected");
        assert_eq!(Manifest::decode(&[bytes.as_slice(), b"x"].concat()), None, "trailing garbage rejected");
    }

    #[test]
    fn an_empty_object_has_a_defined_cid() {
        // One leaf (the empty one), and the id is the count-bound root of it rather than the bare leaf hash — so a chunk
        // id is no longer a value a leaf hash can take.
        assert_eq!(chunk_cid(&[]), Cid(merkle::root(&[leaf_hash(0, &[])]).unwrap()));
        assert_ne!(chunk_cid(&[]), Cid(leaf_hash(0, &[])), "an id and a leaf hash live in different spaces");
        let (bytes, proof) = prove_leaf(&[], 0).expect("the empty leaf");
        assert!(bytes.is_empty());
        assert!(verify_leaf(&chunk_cid(&[]), 0, &bytes, &proof, 1));
    }
}
