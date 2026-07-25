//! The **SIS-based, zero-knowledge-friendly Merkle hash** over the ring (`spec/platform.md` §4.2) — the
//! foundation for proving *whole-pool* membership (untraceability) in zero knowledge.
//!
//! OBOLOS's anonymity set is the entire commitment tree ([`crate::tree`]), so a spend must prove its note is a
//! leaf under the public anchor *without revealing which leaf* — a **zero-knowledge Merkle path**. With the
//! current BLAKE3 tree hash that is intractable (a ZK proof of a bit-mixing hash is a whole SNARK circuit). The
//! escape, used by every practical lattice membership proof (Libert–Ling–Nguyen–Wang), is a hash whose relation is
//! **linear over `R_q`**, so proving `parent = hash(left, right)` reduces to the opening/product arguments this
//! crate already builds ([`crate::ring_zk`], [`crate::ring_product`]).
//!
//! ## The compression function
//!
//! A node is a **short** vector `x ∈ R_q^ℓ` (coefficients in `[0, 2^{LOG_BASE})`). For public matrices
//! `A₀, A₁ ∈ R_q^{k×ℓ}` (a nothing-up-my-sleeve CRS),
//!
//! ```text
//! hash(l, r) = G⁻¹( A₀·l + A₁·r )      — the k-element linear image, then gadget-decomposed back to a short ℓ-vector
//! ```
//!
//! where `G⁻¹` is the **gadget decomposition**: each coefficient of the `k`-element image (a value `< q < 2^{64}`)
//! is split into its `DIGITS` base-`2^{LOG_BASE}` digits, yielding `ℓ = k·DIGITS` short polynomials. The map is a
//! bijection (`G` recomposes it), so the node stays short and re-hashable, and the tree compresses `2ℓ → ℓ`.
//!
//! - **Collision resistance ← Module-SIS.** `hash(l,r) = hash(l',r')` iff `A₀(l−l') + A₁(r−r') = 0` (decomposition
//!   is injective), i.e. `[A₀ | A₁]·(l−l', r−r') = 0` — a *short, nonzero* kernel element, a Module-SIS solution on
//!   `[A₀ | A₁]`. (No new assumption: the same lattice hardness the commitment uses.)
//! - **ZK-friendly.** The load-bearing identity `G(hash(l,r)) = A₀·l + A₁·r` is `R_q`-linear in the short witness
//!   `(l, r)`, so a path proof composes: at each level, an opening-style argument that the (secret) children map to
//!   the (secret) parent, chained to the public root — with the shortness of each node a range/binary sub-proof.
//!
//! > **STATUS — [P]/[H], correctness-first (as the rest of the ring stack).** Construction and the SIS reduction
//! > are the security spec; the dimensions `(k, ℓ)`, base, and `q` are illustrative, not yet calibrated to a
//! > bit-security target nor externally cryptanalysed; arithmetic is not constant-time. Tests verify the hash is
//! > deterministic, that decomposition round-trips, that nodes stay short and re-hashable, and — the load-bearing
//! > property the ZK path proof rests on — that `G(hash(l,r)) = A₀·l + A₁·r`. The zero-knowledge path proof itself
//! > is the next increment.

use alloc::vec::Vec;

use crate::ring::{D, Poly};

/// Base-2 logarithm of the gadget base. `q < 2^{64}`, so `DIGITS = 64/LOG_BASE` base-`2^{LOG_BASE}` digits
/// represent any coefficient. `16` gives 4 digits of a clean 16-bit range.
pub const LOG_BASE: u32 = 16;

/// The number of base-`2^{LOG_BASE}` digits per coefficient — `⌈64 / LOG_BASE⌉`.
pub const DIGITS: usize = 4;

/// The gadget base `2^{LOG_BASE}`; every node coefficient is a digit in `[0, BASE)`.
pub const BASE: u64 = 1 << LOG_BASE;

/// Module rank of the linear image (`SIS rows = K_H·D`). Illustrative — a calibration parameter.
pub const K_H: usize = 1;

/// Node width in ring elements: the gadget decomposition of a `K_H`-element image is `K_H·DIGITS` short polys.
pub const ELL_H: usize = K_H * DIGITS;

/// A tree node: a **short** vector of `ELL_H` ring elements (coefficients in `[0, BASE)`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashNode {
    limbs: Vec<Poly>, // ELL_H polynomials
}

impl HashNode {
    /// Whether every coefficient is a valid digit (`< BASE`) — the shortness the SIS reduction and the ZK path
    /// proof assume.
    #[must_use]
    pub fn is_short(&self) -> bool {
        self.limbs.len() == ELL_H && self.limbs.iter().all(|p| p.coeffs().iter().all(|&c| c < BASE))
    }

    /// The limb polynomials.
    #[must_use]
    pub fn limbs(&self) -> &[Poly] {
        &self.limbs
    }

    /// A node from explicit limb polynomials (must be `ELL_H` of them) — for assembling derived nodes and, in
    /// tests, small nodes whose shortness is fast to prove.
    #[must_use]
    #[allow(dead_code)] // consumed by tests now; the sound-path assembly constructs derived nodes with it
    pub(crate) fn from_limbs(limbs: Vec<Poly>) -> Self {
        debug_assert_eq!(limbs.len(), ELL_H, "a node has ELL_H limbs");
        Self { limbs }
    }

    /// Encode arbitrary bytes (e.g. a note commitment) as a short leaf node — the gadget decomposition of a
    /// uniform `K_H`-element image derived from the bytes, so the leaf is deterministic, short, and re-hashable.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let image: Vec<Poly> = (0..K_H)
            .map(|i| {
                let mut s = Vec::with_capacity(bytes.len() + 8);
                s.extend_from_slice(bytes);
                s.extend_from_slice(&(i as u64).to_le_bytes());
                Poly::uniform(&s)
            })
            .collect();
        decompose(&image)
    }
}

/// The public compression matrices `A₀, A₁ ∈ R_q^{K_H×ELL_H}` (row-major) — a shared nothing-up-my-sleeve CRS.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashParams {
    a0: Vec<Poly>, // K_H * ELL_H
    a1: Vec<Poly>, // K_H * ELL_H
}

impl HashParams {
    /// The canonical tree-hash parameters.
    #[must_use]
    pub fn standard() -> Self {
        Self::from_seed(b"FANOS-obolos-v1/ring-hash-crs")
    }

    /// Parameters derived deterministically from `seed`.
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        let matrix = |tag: &str| -> Vec<Poly> {
            (0..K_H * ELL_H)
                .map(|i| {
                    let mut s = Vec::with_capacity(seed.len() + tag.len() + 8);
                    s.extend_from_slice(seed);
                    s.extend_from_slice(tag.as_bytes());
                    s.extend_from_slice(&(i as u64).to_le_bytes());
                    Poly::uniform(&s)
                })
                .collect()
        };
        Self { a0: matrix("/A0"), a1: matrix("/A1") }
    }

    /// The linear image `A₀·l + A₁·r ∈ R_q^{K_H}` — the un-decomposed hash, and the value the ZK path proof's
    /// linear relation is stated over (`G(hash(l,r)) = this`).
    #[must_use]
    pub fn image(&self, l: &HashNode, r: &HashNode) -> Vec<Poly> {
        let mul_row = |a: &[Poly], x: &HashNode, row: usize| {
            a.iter()
                .skip(row * ELL_H)
                .take(ELL_H)
                .zip(x.limbs())
                .fold(Poly::zero(), |acc, (aij, xj)| acc.add(&aij.mul(xj)))
        };
        (0..K_H).map(|row| mul_row(&self.a0, l, row).add(&mul_row(&self.a1, r, row))).collect()
    }

    /// The **compression** `hash(l, r) = G⁻¹(A₀·l + A₁·r)` — a short, re-hashable parent node.
    #[must_use]
    pub fn hash(&self, l: &HashNode, r: &HashNode) -> HashNode {
        decompose(&self.image(l, r))
    }

    /// The coefficient vector of the hash's **linear relation** `A₀·l + A₁·r − G(parent) = 0`, laid out over the
    /// concatenated limbs `left ‖ right ‖ parent` — `[A₀ row, A₁ row, −gadget weights]`. A [`crate::ring_linear`]
    /// proof over the committed limbs with these coefficients is one zero-knowledge hash step
    /// ([`crate::ring_membership`]). (`K_H = 1`: a single output row.)
    #[must_use]
    pub(crate) fn step_coeffs(&self) -> Vec<Poly> {
        debug_assert_eq!(K_H, 1, "step_coeffs lays out a single output row");
        let mut coeffs = Vec::with_capacity(3 * ELL_H);
        coeffs.extend(self.a0.iter().cloned()); // A₀ (K_H·ELL_H limbs)
        coeffs.extend(self.a1.iter().cloned()); // A₁
        for d in 0..DIGITS {
            coeffs.push(Poly::zero().sub(&Poly::constant(1u64 << (LOG_BASE * (d as u32))))); // −2^{LOG_BASE·d}
        }
        coeffs
    }
}

/// The **gadget decomposition** `G⁻¹`: split each coefficient of the `K_H`-element `image` into its `DIGITS`
/// base-`2^{LOG_BASE}` digits, giving a short `ELL_H`-element node.
#[must_use]
fn decompose(image: &[Poly]) -> HashNode {
    let mut limbs = Vec::with_capacity(ELL_H);
    for component in image {
        for d in 0..DIGITS {
            let shift = LOG_BASE * (d as u32);
            let digit: Vec<u64> = component.coeffs().iter().map(|&c| (c >> shift) & (BASE - 1)).collect();
            limbs.push(Poly::from_u64(&to_array(&digit)));
        }
    }
    HashNode { limbs }
}

/// The **gadget recomposition** `G`: `Σ_d 2^{LOG_BASE·d}·digit_d`, the inverse of [`decompose`]. Because a node's
/// digits recompose to a value `< q`, this returns the exact `K_H`-element image. (Ring-multiplying by a constant
/// polynomial is coefficient-wise scalar multiplication, so this stays index-free.) The zero-knowledge path proof
/// (next increment) states its per-level linear relation `G(parent) = A₀·l + A₁·r` over this.
#[must_use]
#[allow(dead_code)] // consumed by tests now; the forthcoming ZK path proof recomposes G to state its relation
pub(crate) fn recompose(node: &HashNode) -> Vec<Poly> {
    node.limbs
        .chunks(DIGITS)
        .map(|digits| {
            digits.iter().enumerate().fold(Poly::zero(), |acc, (d, digit)| {
                let weight = Poly::constant(1u64 << (LOG_BASE * (d as u32)));
                acc.add(&weight.mul(digit))
            })
        })
        .collect()
}

/// Copy a length-`D` coefficient slice into the fixed array `Poly::from_u64` expects.
fn to_array(v: &[u64]) -> [u64; D] {
    let mut a = [0u64; D];
    a.copy_from_slice(v);
    a
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn node(seed: &[u8]) -> HashNode {
        HashNode::from_bytes(seed)
    }

    #[test]
    fn a_leaf_encoding_is_short_and_deterministic() {
        let a = node(b"leaf-1");
        assert!(a.is_short(), "a leaf node has digit-sized coefficients");
        assert_eq!(a, node(b"leaf-1"), "encoding is deterministic");
        assert_ne!(a, node(b"leaf-2"), "distinct inputs give distinct leaves");
    }

    #[test]
    fn decomposition_round_trips() {
        // G(G⁻¹(y)) = y for any image y (coefficients < q).
        let image = alloc::vec![Poly::uniform(b"img-0")];
        let node = decompose(&image);
        assert!(node.is_short(), "the decomposition is short");
        assert_eq!(recompose(&node), image, "recompose ∘ decompose = identity");
    }

    #[test]
    fn the_hash_is_deterministic_and_short() {
        let params = HashParams::standard();
        let (l, r) = (node(b"child-l"), node(b"child-r"));
        let parent = params.hash(&l, &r);
        assert!(parent.is_short(), "the parent is a short, re-hashable node");
        assert_eq!(parent, params.hash(&l, &r), "the hash is deterministic");
        // Order matters (A₀ ≠ A₁): hash(l,r) ≠ hash(r,l) in general.
        assert_ne!(parent, params.hash(&r, &l), "the hash is position-dependent");
    }

    #[test]
    fn the_hash_composes_up_a_tree() {
        // A parent is itself a valid input to the next level — the property a Merkle tree needs.
        let params = HashParams::standard();
        let (a, b, c, d) = (node(b"a"), node(b"b"), node(b"c"), node(b"d"));
        let left = params.hash(&a, &b);
        let right = params.hash(&c, &d);
        let root = params.hash(&left, &right);
        assert!(root.is_short() && left.is_short() && right.is_short(), "every level stays short");
    }

    #[test]
    fn the_linear_relation_underlying_the_zk_path_proof_holds() {
        // The load-bearing identity: G(hash(l,r)) = A₀·l + A₁·r. The ZK path proof states exactly this linear
        // relation over the secret short (l, r), so it must hold on the nose.
        let params = HashParams::standard();
        let (l, r) = (node(b"witness-l"), node(b"witness-r"));
        let parent = params.hash(&l, &r);
        assert_eq!(recompose(&parent), params.image(&l, &r), "G(hash(l,r)) = A₀·l + A₁·r");
    }
}
