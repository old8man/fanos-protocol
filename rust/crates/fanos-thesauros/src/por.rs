//! **Proof of retrievability** — the beacon-driven audit that a provider still holds a chunk it was paid to
//! hold (`docs/design-storage.md` §5). The public PQ-VRF beacon seeds an unpredictable set of leaf challenges;
//! the provider answers with those leaves and their Merkle paths against the committed [`Cid`]; anyone verifies
//! the paths. Deleting data is caught because the challenges are unpredictable and position-bound.
//!
//! **Derived soundness (no magic constant).** If a cheating provider retains only a fraction `ρ` of a chunk's
//! `m` leaves, each independent challenge lands on a retained leaf with probability `≤ ρ`, so it passes all `k`
//! with probability `≤ ρ^k`. To catch any provider missing at least a tolerated fraction `f_tol`
//! (`ρ ≤ 1 − f_tol`) with `λ` bits of audit-soundness, [`required_samples`] returns
//! `k ≥ λ·ln2 / (−ln(1 − f_tol))` — computed from the security parameters, not chosen. `k` is a deal parameter;
//! the runtime here only needs the agreed `k` to challenge and verify (so the core stays `no_std`; the
//! derivation is a `std` tooling helper). A chunk with `m < k` leaves is fully audited — it can only afford the
//! soundness its size permits, and the inherited erasure layer carries the rest of the durability.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use fanos_primitives::hash_labeled;

use crate::content::{Cid, MerkleProof, leaf_count, prove_leaf, verify_leaf};

/// Label deriving the per-audit challenge seed from the chunk id and the beacon.
const CHALLENGE_LABEL: &str = "FANOS-v1/thesauros-challenge";
/// Label drawing successive candidate indices from the seed.
const DRAW_LABEL: &str = "FANOS-v1/thesauros-draw";

/// The number of leaf challenges needed to catch a provider missing a fraction `f_tol` of leaves with
/// `lambda_bits` of audit-soundness: `⌈ λ·ln2 / (−ln(1 − f_tol)) ⌉`. A `std` tooling helper (uses `f64::ln`);
/// the resulting `k` is carried as a deal parameter into the `no_std` challenge/verify path. Returns
/// `usize::MAX` for a degenerate `f_tol ∉ (0, 1)`.
#[cfg(feature = "std")]
#[must_use]
pub fn required_samples(lambda_bits: u32, f_tol: f64) -> usize {
    if !(f_tol > 0.0 && f_tol < 1.0) {
        return usize::MAX;
    }
    let k = f64::from(lambda_bits) * core::f64::consts::LN_2 / -(1.0 - f_tol).ln();
    k.ceil() as usize
}

/// The seed for a chunk's audit at a given beacon value.
#[must_use]
fn challenge_seed(chunk: &Cid, beacon: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + beacon.len());
    buf.extend_from_slice(chunk.as_bytes());
    buf.extend_from_slice(beacon);
    hash_labeled(CHALLENGE_LABEL, &buf)
}

/// Draw the `counter`-th candidate leaf index in `[0, m)` from the seed.
#[must_use]
fn draw(seed: &[u8; 32], counter: u64, m: usize) -> usize {
    let mut buf = [0u8; 40];
    let (s, c) = buf.split_at_mut(32);
    s.copy_from_slice(seed);
    c.copy_from_slice(&counter.to_le_bytes());
    let h = hash_labeled(DRAW_LABEL, &buf);
    let word = u64::from_le_bytes(h.first_chunk::<8>().copied().unwrap_or_default());
    (word % m as u64) as usize
}

/// A hard cap on the leaf domain (and hence sample count) a single audit challenge allocates over (audit §3.3,
/// defense-in-depth). `open_deal` already bounds a deal's `size` so its leaf count is tiny (`≤ CHUNK/LEAF`);
/// clamping here means even a params-bypassing call can never reserve an unbounded `Vec` and OOM the audit path.
pub const MAX_AUDIT_LEAVES: usize = 1 << 20;

/// The set of leaf indices challenged for `chunk` at `beacon`, wanting `k` distinct samples out of `leaves`.
/// Publicly derivable, so the verifier recomputes it rather than trusting the prover. If `k ≥ leaves`, the whole
/// chunk is audited. Both `leaves` and `k` are clamped to [`MAX_AUDIT_LEAVES`] so the work is always bounded.
#[must_use]
pub fn challenge(chunk: &Cid, beacon: &[u8], k: usize, leaves: usize) -> Vec<usize> {
    // Defensive clamp (audit §3.3): the challenge is derived deterministically by both prover and verifier, so
    // clamping identically keeps them consistent while making the allocation unconditionally bounded.
    let leaves = leaves.min(MAX_AUDIT_LEAVES);
    let k = k.min(leaves);
    if leaves == 0 {
        return Vec::new();
    }
    if k >= leaves {
        return (0..leaves).collect();
    }
    let seed = challenge_seed(chunk, beacon);
    let mut chosen = BTreeSet::new();
    let mut counter = 0u64;
    while chosen.len() < k {
        chosen.insert(draw(&seed, counter, leaves));
        counter = counter.saturating_add(1);
    }
    chosen.into_iter().collect()
}

/// One challenged leaf's answer: its index, bytes, and Merkle path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LeafProof {
    /// The challenged leaf index.
    pub index: usize,
    /// The leaf bytes.
    pub bytes: Vec<u8>,
    /// The Merkle authentication path to the chunk's CID.
    pub path: MerkleProof,
}

/// Build the audit response for `chunk`: the leaf + path for each challenged index. `None` if any index is out
/// of range (the provider does not hold that leaf) — a provider missing challenged data cannot answer.
#[must_use]
pub fn prove(chunk: &[u8], indices: &[usize]) -> Option<Vec<LeafProof>> {
    indices
        .iter()
        .map(|&index| {
            let (bytes, path) = prove_leaf(chunk, index)?;
            Some(LeafProof { index, bytes, path })
        })
        .collect()
}

/// Verify an audit `response` against the committed `chunk` id. Recomputes the challenge from
/// `(chunk, beacon, k, leaves)` — so a provider cannot choose which leaves to answer — and checks the response
/// covers exactly those indices, each leaf verifying against the CID (position-bound). `true` iff the provider
/// demonstrably holds every challenged leaf.
#[must_use]
pub fn verify(chunk: &Cid, beacon: &[u8], k: usize, leaves: usize, response: &[LeafProof]) -> bool {
    let expected = challenge(chunk, beacon, k, leaves);
    if response.len() != expected.len() {
        return false;
    }
    // The response must be exactly the challenged indices, in canonical ascending order — so there is a *single*
    // valid byte encoding per (chunk, beacon), and a permuted/duplicated variant cannot pass as a distinct proof
    // (which, without this, lets a provider replay one proof of holding many times against one settlement).
    for (lp, &index) in response.iter().zip(&expected) {
        if lp.index != index || !verify_leaf(chunk, index, &lp.bytes, &lp.path) {
            return false;
        }
    }
    true
}

/// The number of leaves an object of `object_len` bytes exposes to the audit (its total leaf count across the
/// chunking), a convenience for computing per-chunk audits.
#[must_use]
pub fn chunk_leaf_count(chunk: &[u8]) -> usize {
    leaf_count(chunk)
}

/// Canonical bytes of one leaf proof: `index(4, LE) ‖ bytes_len(4, LE) ‖ bytes ‖ steps(2, LE) ‖
/// [ sibling(32) ‖ on_right(1) ] × steps`.
fn encode_leaf_proof(lp: &LeafProof, out: &mut Vec<u8>) {
    out.extend_from_slice(&u32::try_from(lp.index).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(&u32::try_from(lp.bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(&lp.bytes);
    out.extend_from_slice(&u16::try_from(lp.path.len()).unwrap_or(u16::MAX).to_le_bytes());
    for step in &lp.path {
        out.extend_from_slice(&step.sibling);
        out.push(u8::from(step.sibling_on_right));
    }
}

/// Canonical bytes of a full audit response: `count(4, LE) ‖ [ leaf proof ] × count`.
#[must_use]
pub fn encode_response(response: &[LeafProof]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(response.len()).unwrap_or(u32::MAX).to_le_bytes());
    for lp in response {
        encode_leaf_proof(lp, &mut out);
    }
    out
}

/// Decode one leaf proof from the front of `bytes`, returning it and the remaining bytes.
fn decode_leaf_proof(bytes: &[u8]) -> Option<(LeafProof, &[u8])> {
    let index = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    let blen = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?) as usize;
    let leaf_end = 8usize.checked_add(blen)?;
    let leaf_bytes = bytes.get(8..leaf_end)?.to_vec();
    let steps = u16::from_le_bytes(bytes.get(leaf_end..leaf_end + 2)?.try_into().ok()?) as usize;
    let mut path = MerkleProof::with_capacity(steps);
    let mut off = leaf_end.checked_add(2)?;
    for _ in 0..steps {
        let sibling = bytes.get(off..off + 32)?.try_into().ok()?;
        let flag = *bytes.get(off + 32)?;
        if flag > 1 {
            return None; // non-canonical boolean
        }
        path.push(crate::content::MerkleStep { sibling, sibling_on_right: flag == 1 });
        off = off.checked_add(33)?;
    }
    Some((LeafProof { index, bytes: leaf_bytes, path }, bytes.get(off..)?))
}

/// The fewest bytes any encoded leaf proof occupies — index (4) + empty leaf-bytes length prefix (4) +
/// zero-step path length prefix (2). Bounds `decode_response`'s pre-allocation against the actual buffer.
const MIN_LEAFPROOF_LEN: usize = 4 + 4 + 2;

/// Decode a full audit response from [`encode_response`], or `None` if malformed / truncated / over-long.
#[must_use]
pub fn decode_response(bytes: &[u8]) -> Option<Vec<LeafProof>> {
    let count = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    // Bound the pre-allocation against the bytes actually present (audit §3.3): a leaf proof is at least
    // MIN_LEAFPROOF_LEN bytes, so a `count` beyond what the remaining buffer could hold is a crafted over-count.
    // Reserving for it (`[0xFF; 4]` ⇒ ~4.3 billion) would OOM-abort every validator on the deterministic
    // block-execute path — a cell-wide halt. Mirrors the `count·stride ≤ body.len()` guard in `Manifest::decode`.
    if count > (bytes.len() - 4) / MIN_LEAFPROOF_LEN {
        return None;
    }
    let mut rest = bytes.get(4..)?;
    let mut response = Vec::with_capacity(count);
    for _ in 0..count {
        let (lp, tail) = decode_leaf_proof(rest)?;
        response.push(lp);
        rest = tail;
    }
    if !rest.is_empty() {
        return None; // no trailing garbage
    }
    Some(response)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    use crate::content::{LEAF, chunk_cid};

    /// A chunk of `n` leaves (each leaf distinct so a swap is detectable).
    fn chunk(n: usize) -> Vec<u8> {
        (0..n * LEAF).map(|i| (i / LEAF + 1) as u8).collect()
    }

    #[test]
    fn required_samples_matches_the_derived_table() {
        // The worked points from docs/design-storage.md §5.
        assert_eq!(required_samples(20, 0.10), 132);
        assert_eq!(required_samples(30, 0.10), 198);
        assert_eq!(required_samples(40, 0.10), 264);
        assert_eq!(required_samples(30, 0.01), 2070);
        assert_eq!(required_samples(30, 0.001), 20785);
        // Degenerate f_tol is refused.
        assert_eq!(required_samples(30, 0.0), usize::MAX);
        assert_eq!(required_samples(30, 1.0), usize::MAX);
    }

    #[test]
    fn an_honest_provider_passes_and_the_challenge_is_recomputable() {
        let data = chunk(16);
        let cid = chunk_cid(&data);
        let leaves = chunk_leaf_count(&data);
        let beacon = b"epoch-42-beacon";
        let k = 5;
        let indices = challenge(&cid, beacon, k, leaves);
        assert_eq!(indices.len(), k, "k distinct indices");
        // Recomputing the challenge is deterministic (the verifier does not trust the prover's index set).
        assert_eq!(challenge(&cid, beacon, k, leaves), indices);
        let response = prove(&data, &indices).expect("honest response");
        assert!(verify(&cid, beacon, k, leaves, &response), "an honest provider passes");
    }

    #[test]
    fn a_different_beacon_generally_challenges_different_leaves() {
        let data = chunk(64);
        let cid = chunk_cid(&data);
        let leaves = chunk_leaf_count(&data);
        let a = challenge(&cid, b"beacon-A", 8, leaves);
        let b = challenge(&cid, b"beacon-B", 8, leaves);
        assert_ne!(a, b, "the audit is unpredictable across beacons");
    }

    #[test]
    fn a_small_chunk_is_fully_audited() {
        let data = chunk(4);
        let cid = chunk_cid(&data);
        let leaves = chunk_leaf_count(&data);
        // k larger than the leaf count → every leaf is challenged.
        let indices = challenge(&cid, b"beacon", 1000, leaves);
        assert_eq!(indices, (0..leaves).collect::<Vec<_>>());
        assert!(verify(&cid, b"beacon", 1000, leaves, &prove(&data, &indices).unwrap()));
    }

    #[test]
    fn a_provider_missing_a_challenged_leaf_fails() {
        let full = chunk(16);
        let cid = chunk_cid(&full);
        let leaves = chunk_leaf_count(&full);
        let beacon = b"epoch";
        let k = 6;
        let indices = challenge(&cid, beacon, k, leaves);
        // The cheat holds only the first 8 leaves; any challenge to a higher leaf cannot be answered.
        let held = &full[..8 * LEAF];
        match prove(held, &indices) {
            None => {} // a challenged leaf is missing → cannot answer at all
            Some(resp) => assert!(!verify(&cid, beacon, k, leaves, &resp), "a partial answer does not verify"),
        }
    }

    #[test]
    fn an_audit_response_round_trips_on_the_wire() {
        let data = chunk(16);
        let cid = chunk_cid(&data);
        let indices = challenge(&cid, b"epoch", 5, 16);
        let response = prove(&data, &indices).unwrap();
        let bytes = encode_response(&response);
        assert_eq!(decode_response(&bytes).as_deref(), Some(response.as_slice()));
        // The decoded response still verifies (the codec is faithful).
        let decoded = decode_response(&bytes).unwrap();
        assert!(verify(&cid, b"epoch", 5, 16, &decoded));
        // Truncation and trailing garbage are rejected.
        assert_eq!(decode_response(&bytes[..bytes.len() - 1]), None, "truncation rejected");
        assert_eq!(decode_response(&[bytes.as_slice(), b"x"].concat()), None, "trailing garbage rejected");
    }

    #[test]
    fn a_swapped_leaf_fails_position_binding() {
        let data = chunk(16);
        let cid = chunk_cid(&data);
        let leaves = chunk_leaf_count(&data);
        let beacon = b"epoch";
        let indices = challenge(&cid, beacon, 4, leaves);
        let mut resp = prove(&data, &indices).unwrap();
        // Answer the first challenged index with a *different* held leaf's bytes+path.
        let victim = indices[0];
        let other = (victim + 1) % leaves;
        let (bytes, path) = prove_leaf(&data, other).unwrap();
        resp[0] = LeafProof { index: victim, bytes, path };
        assert!(!verify(&cid, beacon, 4, leaves, &resp), "a leaf answered at the wrong position is rejected");
    }

    #[test]
    fn decode_response_refuses_a_crafted_over_count() {
        // Audit §3.3: a 4-byte count claiming billions of leaf proofs must be refused BEFORE `with_capacity`,
        // so a crafted response cannot OOM-abort every validator on the deterministic prove path.
        let mut evil = u32::MAX.to_le_bytes().to_vec(); // claims ~4.3 billion leaf proofs …
        evil.extend_from_slice(&[0u8; 20]); // … in 20 bytes (room for ~2)
        assert_eq!(decode_response(&evil), None, "an over-count is refused, not pre-allocated");
        // A count with no proof bytes at all is likewise refused (bounded by the empty remainder).
        assert_eq!(decode_response(&1u32.to_le_bytes()), None);
    }

    #[test]
    fn challenge_work_is_bounded_regardless_of_params() {
        // Audit §3.3: an unbounded leaf domain / sample count cannot make `challenge` allocate without limit.
        let cid = chunk_cid(&chunk(1));
        let all = challenge(&cid, b"beacon", usize::MAX, usize::MAX);
        assert_eq!(all.len(), MAX_AUDIT_LEAVES, "the leaf domain is clamped to the cap");
        assert_eq!(challenge(&cid, b"beacon", 7, usize::MAX).len(), 7, "a modest k over a huge domain draws exactly k");
    }
}
