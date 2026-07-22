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

use fanos_primitives::hash_labeled;

/// The Merkle leaf size (bytes): the granularity a proof of retrievability samples.
pub const LEAF: usize = 4096;
/// The chunk size (bytes): objects larger than this are split into chunks under a [`Manifest`].
pub const CHUNK: usize = 262_144;

/// Domain label for a position-bound leaf hash.
const LEAF_LABEL: &str = "FANOS-v1/thesauros-leaf";
/// Domain label for an internal Merkle node hash.
const NODE_LABEL: &str = "FANOS-v1/thesauros-node";

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

/// One step of a Merkle authentication path: the sibling hash and which side it is on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MerkleStep {
    /// The sibling node's hash.
    pub sibling: [u8; 32],
    /// Whether the sibling is the *right* child (so this node is the left one).
    pub sibling_on_right: bool,
}

/// A Merkle authentication path from a leaf to the root (leaf level first).
pub type MerkleProof = Vec<MerkleStep>;

/// The position-bound hash of the `index`-th leaf: `H(leaf, index_le(8) ‖ bytes)`.
#[must_use]
fn leaf_hash(index: usize, bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + bytes.len());
    buf.extend_from_slice(&(index as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
    hash_labeled(LEAF_LABEL, &buf)
}

/// The hash of an internal node from its two children: `H(node, left ‖ right)`.
#[must_use]
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    let (l, r) = buf.split_at_mut(32);
    l.copy_from_slice(left);
    r.copy_from_slice(right);
    hash_labeled(NODE_LABEL, &buf)
}

/// The position-bound leaf hashes of a chunk (an empty chunk is one empty leaf).
#[must_use]
fn leaf_hashes(chunk: &[u8]) -> Vec<[u8; 32]> {
    if chunk.is_empty() {
        return alloc::vec![leaf_hash(0, &[])];
    }
    chunk.chunks(LEAF).enumerate().map(|(i, b)| leaf_hash(i, b)).collect()
}

/// Fold one Merkle level into the next, promoting a lone odd node unchanged.
#[must_use]
fn fold_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    for pair in level.chunks(2) {
        let node = match pair {
            [l, r] => node_hash(l, r),
            [l] => *l,
            _ => continue,
        };
        next.push(node);
    }
    next
}

/// The Merkle root over already-computed leaf hashes.
#[must_use]
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level = match leaves.first() {
        None => return leaf_hash(0, &[]),
        Some(_) if leaves.len() == 1 => return leaves.first().copied().unwrap_or_default(),
        Some(_) => leaves.to_vec(),
    };
    while level.len() > 1 {
        level = fold_level(&level);
    }
    level.first().copied().unwrap_or_default()
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
    let leaves = leaf_hashes(chunk);
    if index >= leaves.len() {
        return None;
    }
    let mut proof = MerkleProof::new();
    let mut level = leaves;
    let mut idx = index;
    while level.len() > 1 {
        if idx.is_multiple_of(2) {
            if let Some(sib) = level.get(idx + 1) {
                proof.push(MerkleStep { sibling: *sib, sibling_on_right: true });
            }
        } else if let Some(sib) = idx.checked_sub(1).and_then(|j| level.get(j)) {
            proof.push(MerkleStep { sibling: *sib, sibling_on_right: false });
        }
        level = fold_level(&level);
        idx /= 2;
    }
    Some(proof)
}

/// The leaf bytes and their Merkle path — a proof-of-retrievability response for one challenged index.
#[must_use]
pub fn prove_leaf(chunk: &[u8], index: usize) -> Option<(Vec<u8>, MerkleProof)> {
    let proof = merkle_proof(chunk, index)?;
    let bytes = leaf(chunk, index)?.to_vec();
    Some((bytes, proof))
}

/// Verify that `leaf_bytes` really is the `index`-th leaf of the object committed by `cid`, via `proof`.
/// Position-bound: the proof for a different index cannot verify these bytes.
#[must_use]
pub fn verify_leaf(cid: &Cid, index: usize, leaf_bytes: &[u8], proof: &MerkleProof) -> bool {
    let mut acc = leaf_hash(index, leaf_bytes);
    for step in proof {
        acc = if step.sibling_on_right { node_hash(&acc, &step.sibling) } else { node_hash(&step.sibling, &acc) };
    }
    &acc == cid.as_bytes()
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
    fn a_single_leaf_chunk_cid_is_its_leaf_hash() {
        let data = b"small object";
        assert_eq!(chunk_cid(data), Cid(leaf_hash(0, data)), "one leaf → the root is that leaf's hash");
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
            assert!(verify_leaf(&cid, i, &bytes, &proof), "leaf {i} verifies");
            // The right bytes at the WRONG index must not verify (position-binding).
            let wrong_index = (i + 1) % n;
            assert!(!verify_leaf(&cid, wrong_index, &bytes, &proof), "leaf {i} bytes do not verify as {wrong_index}");
            // A tampered byte must not verify.
            let mut bad = bytes.clone();
            if let Some(b) = bad.first_mut() {
                *b ^= 0xFF;
            }
            assert!(!verify_leaf(&cid, i, &bad, &proof), "tampered leaf {i} does not verify");
        }
        assert!(prove_leaf(&data, n).is_none(), "an out-of-range leaf has no proof");
    }

    #[test]
    fn the_cid_is_stable_a_known_answer() {
        // A fixed 2-leaf chunk must address to fixed bytes so every implementation agrees.
        let mut data = alloc::vec![0xABu8; LEAF];
        data.extend_from_slice(&[0xCD; 100]);
        let cid = chunk_cid(&data);
        // Root = node_hash(leaf0, leaf1) with position-bound leaves.
        let expect = node_hash(&leaf_hash(0, &data[..LEAF]), &leaf_hash(1, &data[LEAF..]));
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
        assert_eq!(chunk_cid(&[]), Cid(leaf_hash(0, &[])));
        let (bytes, proof) = prove_leaf(&[], 0).expect("the empty leaf");
        assert!(bytes.is_empty());
        assert!(verify_leaf(&chunk_cid(&[]), 0, &bytes, &proof));
    }
}
