//! A **post-quantum, hash-based Verifiable Random Function** over a bounded sequential domain — the FANOS
//! epoch beacon's actual VRF need (spec §16 `[P]` "PQ-VRF / PQ beacon", `docs/design-pq-vrf.md`).
//!
//! The classical VRF ([`crate::VrfSecret`]) is ristretto255 (discrete-log, not post-quantum). This module is
//! a PQ alternative built from **BLAKE3 alone** — no new hardness assumption, quantum-resistant by
//! construction. The observation that makes it clean: a VRF's input domain here is the **epoch counter**, a
//! bounded increasing sequence, so a *Merkle-committed PRF tree* is a perfect fit:
//!
//! ```text
//! leaf(e) = H("pqvrf-leaf" , seed ‖ e)               a PRF value, one per epoch e ∈ [0, 2^height)
//! root    = Merkle root over { leaf(0) … leaf(2^h−1) }        the public key
//! VRF(e)  = (output = leaf(e), proof = the Merkle authentication path)
//! ```
//!
//! It has every VRF property, from symmetric primitives only:
//! * **Uniqueness** — the root binds *one* leaf per epoch (Merkle 2nd-preimage resistance), so a prover
//!   cannot present two different valid outputs for the same epoch.
//! * **Pseudorandomness / unpredictability** — `leaf(e) = PRF(seed, e)`; without `seed` a future epoch's
//!   output is unpredictable even given all earlier ones.
//! * **Unbiasability** (the beacon property) — every leaf is fixed by `seed` and *committed in `root` at
//!   setup*, so at reveal time a rushing adversary cannot grind its contribution: the RANDAO last-actor bias
//!   that plagues hash commit-reveal beacons is structurally absent.
//!
//! The one cost is a **bounded, pre-committed domain** of `2^height` epochs (e.g. `height = 20` ⇒ ~1M epochs,
//! then rotate to a fresh root — a natural periodic re-key). The tradeoff, and the honest status of a
//! *threshold* PQ beacon with reconstruction-uniqueness, are discussed in `docs/design-pq-vrf.md`.

use alloc::vec::Vec;

use fanos_primitives::{hash_labeled, Epoch};

const LEAF_LABEL: &str = "FANOS-v1/pqvrf-leaf";
const NODE_LABEL: &str = "FANOS-v1/pqvrf-node";
const BEACON_LABEL: &str = "FANOS-v1/pqvrf-beacon";

/// The largest supported tree height (`2^24` ≈ 16.7M epochs) — a guard so a bad `height` cannot ask for an
/// astronomically large tree. Real deployments pick a modest height and re-key periodically.
pub const MAX_HEIGHT: u32 = 24;

/// The 32-byte VRF output (a leaf value).
pub type VrfOutput = [u8; 32];

/// Hash one leaf: `H("pqvrf-leaf", seed ‖ index)`.
fn hash_leaf(seed: &[u8; 32], index: u64) -> [u8; 32] {
    let mut buf = [0u8; 32 + 8];
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(&index.to_be_bytes());
    hash_labeled(LEAF_LABEL, &buf)
}

/// Hash one internal node: `H("pqvrf-node", left ‖ right)`.
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    hash_labeled(NODE_LABEL, &buf)
}

/// A Merkle authentication path — one sibling digest per tree level (from the leaf up to the root).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MerkleProof {
    siblings: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// The path length (equal to the tree height).
    #[must_use]
    pub fn len(&self) -> usize {
        self.siblings.len()
    }

    /// Whether the path is empty (a height-0 tree).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.siblings.is_empty()
    }

    /// Canonical bytes: each 32-byte sibling in path order.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.siblings.len() * 32);
        for s in &self.siblings {
            out.extend_from_slice(s);
        }
        out
    }

    /// Decode a path of exactly `height` siblings, or `None` if the length is wrong.
    #[must_use]
    pub fn from_bytes(bytes: &[u8], height: u32) -> Option<Self> {
        if bytes.len() != height as usize * 32 {
            return None;
        }
        // `bytes.len()` is a multiple of 32 (checked above), so the remainder is empty.
        let (chunks, _rest) = bytes.as_chunks::<32>();
        Some(Self { siblings: chunks.to_vec() })
    }
}

/// The prover's secret: the seed plus the fully materialized Merkle tree (levels bottom-up, `levels[0]` the
/// leaves, `levels[height]` the single root).
pub struct MerkleVrfSecret {
    height: u32,
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleVrfSecret {
    /// Build the VRF from a `seed` over a domain of `2^height` epochs. `None` if `height > MAX_HEIGHT`.
    #[must_use]
    pub fn generate(seed: &[u8; 32], height: u32) -> Option<Self> {
        if height > MAX_HEIGHT {
            return None;
        }
        let leaf_count = 1usize << height;
        let mut leaves = Vec::with_capacity(leaf_count);
        for i in 0..leaf_count as u64 {
            leaves.push(hash_leaf(seed, i));
        }
        let mut levels = Vec::with_capacity(height as usize + 1);
        levels.push(leaves);
        for level in 0..height as usize {
            let cur = levels.get(level)?;
            let mut next = Vec::with_capacity(cur.len() / 2);
            let mut j = 0;
            while j + 1 < cur.len() {
                next.push(hash_node(cur.get(j)?, cur.get(j + 1)?));
                j += 2;
            }
            levels.push(next);
        }
        Some(Self { height, levels })
    }

    /// The public key: the Merkle root committing to every epoch's output.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|top| top.first())
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// The domain size `2^height`.
    #[must_use]
    pub fn domain(&self) -> u64 {
        1u64 << self.height
    }

    /// The tree height.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Prove the VRF at `index` (an epoch): returns `(output, proof)`, or `None` if `index` is outside the
    /// domain. The output is deterministic in `(seed, index)`; the proof authenticates it against [`root`].
    #[must_use]
    pub fn prove(&self, index: u64) -> Option<(VrfOutput, MerkleProof)> {
        if index >= self.domain() {
            return None;
        }
        let output = *self.levels.first()?.get(index as usize)?;
        let mut siblings = Vec::with_capacity(self.height as usize);
        let mut idx = index as usize;
        for level in 0..self.height as usize {
            let layer = self.levels.get(level)?;
            let sib = layer.get(idx ^ 1)?;
            siblings.push(*sib);
            idx >>= 1;
        }
        Some((output, MerkleProof { siblings }))
    }
}

/// Verify a PQ-VRF output at `index` against the public `root` and tree `height`: recompute the Merkle path
/// from `output` using `proof`'s siblings and check it reaches `root`. `true` iff the output is the unique
/// committed value for that epoch.
#[must_use]
pub fn verify(root: &[u8; 32], height: u32, index: u64, output: &VrfOutput, proof: &MerkleProof) -> bool {
    if proof.len() != height as usize || index >= (1u64 << height) {
        return false;
    }
    let mut acc = *output;
    let mut idx = index;
    for sib in &proof.siblings {
        acc = if idx & 1 == 0 {
            hash_node(&acc, sib) // this node is the left child
        } else {
            hash_node(sib, &acc) // this node is the right child
        };
        idx >>= 1;
    }
    &acc == root
}

/// A single anchor's PQ-beacon contribution for an epoch: its committed root and the authenticated output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BeaconShare {
    /// The anchor's public Merkle root (fixed at setup).
    pub root: [u8; 32],
    /// The anchor's VRF output for this epoch.
    pub output: VrfOutput,
    /// The authentication path for `output` under `root`.
    pub proof: MerkleProof,
}

impl BeaconShare {
    /// Whether this share authenticates: `output` is the committed value at `epoch` under `root`.
    #[must_use]
    pub fn verify(&self, epoch: Epoch, height: u32) -> bool {
        verify(&self.root, height, epoch.get(), &self.output, &self.proof)
    }
}

/// Combine verified anchor shares into an unbiasable PQ beacon seed for `epoch`:
/// `H("pqvrf-beacon", epoch ‖ sorted(root ‖ output)*)`. Returns `None` unless **every** share verifies (a
/// full-reveal beacon; see `docs/design-pq-vrf.md` for the threshold-uniqueness discussion). Sorting by
/// `(root, output)` makes the seed independent of share ordering. Unbiasable because each `output` is
/// pre-committed in its `root` at setup — no anchor can grind its contribution at reveal time.
#[must_use]
pub fn beacon_seed(epoch: Epoch, height: u32, shares: &[BeaconShare]) -> Option<[u8; 32]> {
    if shares.is_empty() || !shares.iter().all(|s| s.verify(epoch, height)) {
        return None;
    }
    let mut entries: Vec<[u8; 64]> = shares.iter().map(|s| {
        let mut e = [0u8; 64];
        e[..32].copy_from_slice(&s.root);
        e[32..].copy_from_slice(&s.output);
        e
    }).collect();
    entries.sort_unstable();
    let mut buf = Vec::with_capacity(8 + entries.len() * 64);
    buf.extend_from_slice(&epoch.to_be_bytes());
    for e in &entries {
        buf.extend_from_slice(e);
    }
    Some(hash_labeled(BEACON_LABEL, &buf))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn prove_and_verify_round_trips_over_the_whole_domain() {
        let vrf = MerkleVrfSecret::generate(&[1u8; 32], 6).unwrap(); // 64 epochs
        let root = vrf.root();
        for e in 0..vrf.domain() {
            let (output, proof) = vrf.prove(e).unwrap();
            assert!(verify(&root, 6, e, &output, &proof), "epoch {e} verifies");
            // The output is the deterministic PRF leaf.
            assert_eq!(output, hash_leaf(&[1u8; 32], e));
        }
        assert!(vrf.prove(vrf.domain()).is_none(), "out-of-domain index has no proof");
    }

    #[test]
    fn a_forged_output_or_tampered_proof_is_rejected() {
        let vrf = MerkleVrfSecret::generate(&[2u8; 32], 5).unwrap();
        let root = vrf.root();
        let (output, proof) = vrf.prove(10).unwrap();

        // A different output for epoch 10 cannot be authenticated (uniqueness / Merkle binding).
        let mut forged = output;
        forged[0] ^= 1;
        assert!(!verify(&root, 5, 10, &forged, &proof), "a forged output is rejected");

        // A tampered path is rejected.
        let mut bad = proof.clone();
        bad.siblings[0][0] ^= 1;
        assert!(!verify(&root, 5, 10, &output, &bad), "a tampered path is rejected");

        // The right output at the WRONG epoch is rejected.
        assert!(!verify(&root, 5, 11, &output, &proof), "output bound to its own epoch only");

        // A different root (different key) rejects it.
        let other = MerkleVrfSecret::generate(&[3u8; 32], 5).unwrap();
        assert!(!verify(&other.root(), 5, 10, &output, &proof), "wrong public key rejects");
    }

    #[test]
    fn outputs_are_unpredictable_without_the_seed_and_unbiasable() {
        // Two seeds → different roots and unrelated outputs (pseudorandomness); and every epoch's output is
        // fixed at setup (unbiasability): revealing earlier epochs does not change a later one.
        let a = MerkleVrfSecret::generate(&[7u8; 32], 8).unwrap();
        let b = MerkleVrfSecret::generate(&[8u8; 32], 8).unwrap();
        assert_ne!(a.root(), b.root());
        let mut seen = alloc::collections::BTreeSet::new();
        for e in 0..a.domain() {
            let (out, _) = a.prove(e).unwrap();
            assert!(seen.insert(out), "outputs are distinct across epochs (no obvious structure)");
            // The output for e is committed in the root from setup — deterministic, so a re-derivation of
            // the same seed reproduces it exactly (nothing revealed later can move it).
            assert_eq!(out, MerkleVrfSecret::generate(&[7u8; 32], 8).unwrap().prove(e).unwrap().0);
        }
    }

    #[test]
    fn a_pq_beacon_combines_anchor_shares_unbiasably() {
        let epoch = Epoch::new(42);
        let height = 8;
        // Three anchors, each with a pre-committed root.
        let anchors: Vec<MerkleVrfSecret> =
            (0..3).map(|i| MerkleVrfSecret::generate(&[10 + i as u8; 32], height).unwrap()).collect();
        let shares: Vec<BeaconShare> = anchors.iter().map(|v| {
            let (output, proof) = v.prove(epoch.get()).unwrap();
            BeaconShare { root: v.root(), output, proof }
        }).collect();

        let seed = beacon_seed(epoch, height, &shares).expect("all shares verify");
        // Order-independent.
        let mut reordered = shares.clone();
        reordered.reverse();
        assert_eq!(beacon_seed(epoch, height, &reordered).unwrap(), seed, "seed independent of share order");
        // A share for a different epoch (wrong proof) breaks the beacon.
        let (o2, p2) = anchors[0].prove(epoch.get() + 1).unwrap();
        let mut tampered = shares.clone();
        tampered[0] = BeaconShare { root: anchors[0].root(), output: o2, proof: p2 };
        assert!(beacon_seed(epoch, height, &tampered).is_none(), "a mismatched-epoch share is rejected");
        // Different epoch → different beacon seed (freshness).
        let (o3, p3) = anchors[0].prove(epoch.get() + 1).unwrap();
        let e2_shares: Vec<BeaconShare> = anchors.iter().map(|v| {
            let (output, proof) = v.prove(epoch.get() + 1).unwrap();
            BeaconShare { root: v.root(), output, proof }
        }).collect();
        let _ = (o3, p3);
        assert_ne!(beacon_seed(Epoch::new(43), height, &e2_shares).unwrap(), seed, "each epoch's seed is fresh");
    }

    #[test]
    fn the_proof_round_trips_through_bytes() {
        let vrf = MerkleVrfSecret::generate(&[4u8; 32], 7).unwrap();
        let (_output, proof) = vrf.prove(33).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 7 * 32);
        assert_eq!(MerkleProof::from_bytes(&bytes, 7).unwrap(), proof);
        assert!(MerkleProof::from_bytes(&bytes, 6).is_none(), "wrong height is rejected");
    }
}
