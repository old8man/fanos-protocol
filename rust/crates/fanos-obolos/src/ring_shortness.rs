//! The **polynomial-shortness proof**: prove a committed polynomial `p` has `‖p‖∞ < 2^t` (every coefficient in
//! `[0, 2^t)`), in zero knowledge. This is what makes the untraceability hash step **sound** — a spend must prove
//! each tree node it uses is a genuine short SIS node ([`crate::ring_membership`]), otherwise the linear hash
//! relation is satisfiable with non-short "nodes" and a path can be forged.
//!
//! ## Construction — bit-planes + reconstruction
//!
//! Decompose `p` into its `t` **bit-planes** `p = Σ_{j<t} 2ʲ·p_j`, where `p_j` holds the `j`-th bit of every
//! coefficient of `p` (so each `p_j` is `{0,1}`-valued). Commit the planes and prove:
//!
//! 1. **binarity** — each `p_j` is `{0,1}`-valued ([`crate::ring_binary`]); and
//! 2. **reconstruction** — `p − Σ_{j<t} 2ʲ·p_j = 0` (a [`crate::ring_linear`] relation over `p` and the planes).
//!
//! Together: every coefficient of `p` equals `Σ_{j<t} 2ʲ·bit` with each `bit ∈ {0,1}`, i.e. lies in `[0, 2^t)`. A
//! non-short `p` (some coefficient `≥ 2^t`) cannot be decomposed into `t` binary planes that recompose to it, so no
//! accepting proof exists.
//!
//! > **STATUS — [P]/[H], correctness-first.** A composition of [`crate::ring_binary`] and [`crate::ring_linear`];
//! > it inherits their status. Size/time is `O(t)` binarity proofs plus one reconstruction — the untraceability
//! > hash step needs one of these per node limb. Tests verify a short polynomial proves, a non-short one is
//! > rejected, commitment binding, and re-randomisation.

use alloc::vec::Vec;

use crate::ring::{D, Poly};
use crate::ring_binary::{BinaryProof, prove_binary, verify_binary};
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_linear::{LinearProof, prove_linear, verify_linear};

/// A zero-knowledge proof that a committed polynomial has `‖·‖∞ < 2^t`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShortnessProof {
    bit_planes: Vec<RingCommitment>, // C_{p_j}, t commitments
    binary: Vec<BinaryProof>,        // each p_j is {0,1}-valued
    reconstruction: LinearProof,     // p = Σ 2ʲ p_j
}

impl crate::ring_size::ProofSize for ShortnessProof {
    /// `t` plane commitments + **`t` full binarity proofs** + one reconstruction over `t+1` messages.
    ///
    /// The middle term is the whole stack's dominant cost: a membership path needs one of these *per node limb*, so a
    /// depth-`d` spend pays `(2d+1) · ELL_H · t` binarity proofs. Aggregating the `t` binarity checks into a single
    /// relation — `Σ_j y^j·(p_j ∘ (p_j − 1)) = 0` for a challenge `y` — is the first compaction to reach for; a wider
    /// challenge (hence fewer repetitions) is the second.
    fn ring_elements(&self) -> usize {
        self.bit_planes.ring_elements() + self.binary.ring_elements() + self.reconstruction.ring_elements()
    }
}

/// The `j`-th bit-plane of `p`: coefficient `i` is the `j`-th bit of `p`'s coefficient `i`.
fn bit_plane(p: &Poly, j: usize) -> Poly {
    let mut coeffs = [0u64; D];
    for (slot, &c) in coeffs.iter_mut().zip(p.coeffs()) {
        *slot = (c >> j) & 1;
    }
    Poly::from_u64(&coeffs)
}

/// The reconstruction coefficients `[1, −2⁰, −2¹, …, −2^{t−1}]` over `[p, p_0, …, p_{t−1}]` (so the relation is
/// `p − Σ 2ʲ p_j = 0`).
fn recon_coeffs(t: usize) -> Vec<Poly> {
    let mut coeffs = Vec::with_capacity(t + 1);
    coeffs.push(Poly::constant(1));
    for j in 0..t {
        coeffs.push(Poly::zero().sub(&Poly::constant(1u64 << j)));
    }
    coeffs
}

/// Prove, in zero knowledge, that `com(p; r_p)` opens to a polynomial with `‖p‖∞ < 2^t`. `t ≤ 62`. `None` only on
/// a sub-proof's rare masking exhaustion.
#[must_use]
pub fn prove_short(
    params: &RingParams,
    p: &Poly,
    r_p: &RingRandomness,
    t: usize,
    seed: &[u8],
) -> Option<ShortnessProof> {
    debug_assert!(t <= 62, "2^t must fit in a coefficient");
    let c_p = RingCommitment::commit_message(params, p, r_p);
    // Bit-planes, each under fresh ternary randomness.
    let planes: Vec<Poly> = (0..t).map(|j| bit_plane(p, j)).collect();
    let plane_r: Vec<RingRandomness> = (0..t)
        .map(|j| {
            let mut s = seed.to_vec();
            s.extend_from_slice(b"/plane/");
            s.extend_from_slice(&(j as u64).to_le_bytes());
            RingRandomness::from_seed(&s)
        })
        .collect();
    let bit_planes: Vec<RingCommitment> =
        planes.iter().zip(&plane_r).map(|(pj, rj)| RingCommitment::commit_message(params, pj, rj)).collect();

    // Each plane is binary.
    let mut binary = Vec::with_capacity(t);
    for (j, (pj, rj)) in planes.iter().zip(&plane_r).enumerate() {
        let mut s = seed.to_vec();
        s.extend_from_slice(b"/bin/");
        s.extend_from_slice(&(j as u64).to_le_bytes());
        binary.push(prove_binary(params, pj, rj, &s)?);
    }

    // Reconstruction: p − Σ 2ʲ p_j = 0.
    let mut messages = Vec::with_capacity(t + 1);
    messages.push(p.clone());
    messages.extend(planes);
    let mut randomness = Vec::with_capacity(t + 1);
    randomness.push(r_p.clone());
    randomness.extend(plane_r);
    let mut commitments = Vec::with_capacity(t + 1);
    commitments.push(c_p);
    commitments.extend(bit_planes.iter().cloned());
    let mut rseed = seed.to_vec();
    rseed.extend_from_slice(b"/recon");
    let reconstruction = prove_linear(params, &commitments, &recon_coeffs(t), &messages, &randomness, &rseed)?;

    Some(ShortnessProof { bit_planes, binary, reconstruction })
}

/// Verify a [`prove_short`] proof that `c_p` opens to a polynomial with `‖·‖∞ < 2^t`.
#[must_use]
pub fn verify_short(params: &RingParams, c_p: &RingCommitment, t: usize, proof: &ShortnessProof) -> bool {
    if proof.bit_planes.len() != t || proof.binary.len() != t {
        return false;
    }
    // Each plane is {0,1}-valued.
    for (plane, bin) in proof.bit_planes.iter().zip(&proof.binary) {
        if !verify_binary(params, plane, bin) {
            return false;
        }
    }
    // And the planes recompose to the committed p.
    let mut commitments = Vec::with_capacity(t + 1);
    commitments.push(c_p.clone());
    commitments.extend(proof.bit_planes.iter().cloned());
    verify_linear(params, &commitments, &recon_coeffs(t), &proof.reconstruction)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // A small width keeps the O(t) binarity sub-proofs fast; the construction is identical at any t.
    const T: usize = 4; // ‖·‖∞ < 16

    /// A polynomial with the given coefficients (rest 0).
    fn poly(coeffs: &[u64]) -> Poly {
        let mut c = [0u64; D];
        c[..coeffs.len()].copy_from_slice(coeffs);
        Poly::from_u64(&c)
    }

    fn commit(params: &RingParams, p: &Poly, seed: &[u8]) -> (RingRandomness, RingCommitment) {
        let r = RingRandomness::from_seed(seed);
        let c = RingCommitment::commit_message(params, p, &r);
        (r, c)
    }

    #[test]
    fn a_short_polynomial_proves_and_verifies() {
        let params = RingParams::standard();
        let p = poly(&[0, 15, 7, 1, 12]); // all < 16
        let (r, c) = commit(&params, &p, b"short-happy");
        let proof = prove_short(&params, &p, &r, T, b"seed").expect("short");
        assert!(verify_short(&params, &c, T, &proof), "‖p‖∞ < 16 verifies");
    }

    #[test]
    fn the_boundary_polynomial_proves() {
        let params = RingParams::standard();
        let p = poly(&[15, 15, 15]); // exactly 2^4 − 1
        let (r, c) = commit(&params, &p, b"short-edge");
        let proof = prove_short(&params, &p, &r, T, b"seed").expect("boundary");
        assert!(verify_short(&params, &c, T, &proof));
    }

    #[test]
    fn a_non_short_polynomial_has_no_accepting_proof() {
        // A coefficient of 16 = 2^4 needs a 5th bit; its 4 bit-planes recompose to 0, so the reconstruction
        // against the real commitment (to 16) fails.
        let params = RingParams::standard();
        let p = poly(&[16]);
        let (r, c) = commit(&params, &p, b"short-bad");
        let proof = prove_short(&params, &p, &r, T, b"seed").expect("proof emitted");
        assert!(!verify_short(&params, &c, T, &proof), "a coefficient of 16 is not < 2^4");
    }

    #[test]
    fn a_proof_does_not_verify_against_a_different_commitment() {
        let params = RingParams::standard();
        let p = poly(&[5, 9]);
        let (r, _c) = commit(&params, &p, b"short-bind");
        let proof = prove_short(&params, &p, &r, T, b"seed").unwrap();
        let (_r2, other) = commit(&params, &p, b"other-randomness");
        assert!(!verify_short(&params, &other, T, &proof), "the commitment is bound in");
    }

    #[test]
    fn the_measured_size_matches_the_construction_and_exposes_the_dominant_term() {
        // The accounting is only worth trusting if it matches the construction exactly, so derive the expected count
        // from the constants and check the real proof against it — then state what it implies for a whole spend.
        use crate::ring_commit::{ELL, K};
        use crate::ring_hash::{ELL_H, LOG_BASE};
        use crate::ring_product::REPETITIONS;
        use crate::ring_size::{BYTES_PER_ELEMENT, ProofSize};

        let params = RingParams::standard();
        let p = poly(&[1, 2, 3]);
        let (r, _c) = commit(&params, &p, b"size-short");
        let proof = prove_short(&params, &p, &r, T, b"seed").expect("short");

        // A binarity round is 3 commitments + the revealed f + 2 openings; a linear round over n messages is
        // (n+1) commitments + n revealed + (n+1) openings. Shortness = T planes + T binarity + 1 reconstruction.
        let binary_one = REPETITIONS * (3 * (K + 1) + 1 + 2 * ELL);
        let n = T + 1; // the reconstruction relates p to its T planes
        let recon = REPETITIONS * ((n + 1) * (K + 1) + n + (n + 1) * ELL);
        let expected = T * (K + 1) + T * binary_one + recon;
        assert_eq!(proof.ring_elements(), expected, "the accounting matches the construction exactly");
        assert_eq!(proof.encoded_bytes(), expected * BYTES_PER_ELEMENT);

        // The dominant term, stated as a ratio rather than an adjective: the T binarity proofs are the bulk even at
        // this small T, and a real node uses T = LOG_BASE with ELL_H limbs.
        let binary_share = T * binary_one;
        assert!(
            binary_share * 2 > proof.ring_elements(),
            "the per-plane binarity proofs are over half of a shortness proof ({binary_share} of {})",
            proof.ring_elements()
        );
        // At the real width, one node's shortness is ELL_H limbs × LOG_BASE planes of binarity — the term any
        // compaction must attack. Kept as an assertion so the ratio cannot silently regress.
        let real_binary_per_node = ELL_H * (LOG_BASE as usize) * binary_one;
        assert!(
            real_binary_per_node * BYTES_PER_ELEMENT > 1 << 20,
            "one node's binarity alone exceeds a megabyte ({} bytes)",
            real_binary_per_node * BYTES_PER_ELEMENT
        );
    }

    #[test]
    fn the_proof_is_re_randomised() {
        let params = RingParams::standard();
        let p = poly(&[3, 14, 8]);
        let (r, c) = commit(&params, &p, b"short-zk");
        let p1 = prove_short(&params, &p, &r, T, b"seed-a").unwrap();
        let p2 = prove_short(&params, &p, &r, T, b"seed-b").unwrap();
        assert_ne!(p1, p2, "different seeds ⇒ different zero-knowledge proofs");
        assert!(verify_short(&params, &c, T, &p1) && verify_short(&params, &c, T, &p2));
    }
}
