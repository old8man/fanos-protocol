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
//! 1. **binarity** — every `p_j` is `{0,1}`-valued, in **one** aggregated proof ([`crate::ring_binary`]); and
//! 2. **reconstruction** — `p − Σ_{j<t} 2ʲ·p_j = 0`.
//!
//! Together: every coefficient of `p` equals `Σ_{j<t} 2ʲ·bit` with each `bit ∈ {0,1}`, i.e. lies in `[0, 2^t)`. A
//! non-short `p` (some coefficient `≥ 2^t`) cannot be decomposed into `t` binary planes that recompose to it, so no
//! accepting proof exists.
//!
//! ## The reconstruction is an opening-to-zero, not a linear proof
//!
//! Stating (2) with [`crate::ring_linear`] costs `t+1` masked messages and openings *per round* — that proof exists to
//! survive **huge** coefficients, where `Σ cᵢ·rᵢ` dwarfs `q` and cannot be revealed short. Here the coefficients are
//! `2ʲ ≤ 2^{t−1}`, so the blow-up it insures against never happens:
//!
//! ```text
//! C_p − Σ_j 2ʲ·C_{p_j}  =  com( p − Σ_j 2ʲ·p_j ;  r_p − Σ_j 2ʲ·r_j )
//! ```
//!
//! is a commitment the verifier forms *itself* by homomorphism, and its randomness has `‖·‖∞ ≤ 1 + 2^t − 1 = 2^t` —
//! short against `q = 2⁶⁴`. So the whole relation is: **that one difference opens to zero**, an
//! [opening-to-zero proof](crate::ring_zk) in the `for_randomness_bound(2^t)` regime, exactly as
//! [`crate::ring_balance`] treats the balance residual. That replaces ~2000 ring elements with ~6 (docs §6.1 rung 2),
//! and it is why `t` is capped at [`MAX_WIDTH`] here: the regime's masking is `2^{19+t}`, which must stay well below `q`.
//!
//! One property changes with the substitution and is worth stating, since this proof is the *foundation* of membership
//! soundness. [`crate::ring_zk`] has **relaxed** special-soundness: extraction yields `M·z̄ = c̄·u` for a challenge
//! difference `c̄`, which pins the residual's message to zero exactly when `c̄` is invertible. On this fully-splitting
//! ring a ternary `c̄` has essentially uniform NTT slots, so it is non-invertible only if some slot vanishes —
//! probability `≈ D/q = 2⁻⁵⁶`. The general linear proof reached the same conclusion via monomial challenges, whose
//! differences are *always* units; here it holds with overwhelming probability instead of certainty. That is the same
//! relaxation [`crate::ring_balance`] already rests on, and it is part of what the pending calibration must confirm.
//!
//! > **STATUS — [P]/[H], correctness-first.** A composition of [`crate::ring_binary`] and [`crate::ring_zk`]; it
//! > inherits their status. The untraceability hash step needs one of these per node limb, which makes it the stack's
//! > dominant cost (`docs/design-obolos-zk.md` §6). Tests verify a short polynomial proves, a non-short one is
//! > rejected, commitment binding, re-randomisation, and that the measured size matches the construction.

use alloc::vec::Vec;

use crate::ring::{D, Poly};
use crate::ring_binary::{AggBinaryProof, prove_binary_agg, verify_binary_agg};
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_zk::{OpeningParams, RingOpeningProof, prove_opening, verify_opening};

/// The largest bit-width this proof supports. The reconstruction's opening regime masks at `2^{19+t}`
/// ([`OpeningParams::for_randomness_bound`] of `2^t`), which must stay well below `q = 2⁶⁴`; at `t = 40` that is
/// `2⁵⁹`, and `t = 44` would already reach `2⁶³`. Every caller uses `t = LOG_BASE = 16`.
pub const MAX_WIDTH: usize = 40;

/// A zero-knowledge proof that a committed polynomial has `‖·‖∞ < 2^t`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShortnessProof {
    bit_planes: Vec<RingCommitment>,     // C_{p_j}, t commitments
    binary: AggBinaryProof,              // ONE proof that every p_j is {0,1}-valued
    reconstruction: RingOpeningProof,    // C_p − Σ 2ʲ·C_{p_j} opens to ZERO
}

impl crate::ring_size::ProofSize for ShortnessProof {
    /// `t` plane commitments + **one aggregated binarity proof** + one reconstruction over `t+1` messages.
    ///
    /// The middle term is the whole stack's dominant cost — a membership path needs one of these *per node limb*. It
    /// used to be `t` separate binarity proofs; aggregating them into the single relation
    /// `Σ_j y^j·(p_j ∘ (p_j − 1)) = 0` halved it (docs §6.1, rung 1). What remains there is irreducible at this level:
    /// each revealed plane still needs its own binding and mask.
    ///
    /// The reconstruction is now a *single* opening-to-zero (docs §6.1 rung 2) rather than a general linear proof over
    /// `t+1` messages — ~6 elements instead of ~2000 — so the aggregated binarity is once again the whole cost.
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

/// The homomorphic reconstruction residual `C_p − Σ_j 2ʲ·C_{p_j}` — a commitment to `p − Σ 2ʲ·p_j`, which the verifier
/// forms itself from public values. Scaling by the *constant* `2ʲ` is coefficient-wise, so the residual's randomness is
/// `r_p − Σ 2ʲ·r_j` with norm `≤ 2^t` (accounted for by the opening regime).
fn residual(c_p: &RingCommitment, planes: &[RingCommitment]) -> RingCommitment {
    planes
        .iter()
        .enumerate()
        .fold(c_p.clone(), |acc, (j, cj)| acc.sub(&cj.scale(&Poly::constant(1u64 << j))))
}

/// The opening regime of the reconstruction residual: its randomness is a signed combination bounded by `2^t`.
fn recon_regime(t: usize) -> OpeningParams {
    OpeningParams::for_randomness_bound(1i64 << t)
}

/// Prove, in zero knowledge, that `com(p; r_p)` opens to a polynomial with `‖p‖∞ < 2^t`. `None` if `t` is zero or
/// exceeds [`MAX_WIDTH`], or on a sub-proof's rare masking exhaustion.
#[must_use]
pub fn prove_short(
    params: &RingParams,
    p: &Poly,
    r_p: &RingRandomness,
    t: usize,
    seed: &[u8],
) -> Option<ShortnessProof> {
    if t == 0 || t > MAX_WIDTH {
        return None;
    }
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

    // Every plane is binary — ONE aggregated proof, not one per plane (the stack's dominant cost, docs §6.1).
    let mut bseed = seed.to_vec();
    bseed.extend_from_slice(b"/bin");
    let binary = prove_binary_agg(params, &planes, &plane_r, &bseed)?;

    // Reconstruction: the homomorphic residual C_p − Σ 2ʲ·C_{p_j} opens to ZERO under r_p − Σ 2ʲ·r_j.
    let diff_r = plane_r
        .iter()
        .enumerate()
        .fold(r_p.clone(), |acc, (j, rj)| acc.sub(&rj.scale(&Poly::constant(1u64 << j))));
    let mut rseed = seed.to_vec();
    rseed.extend_from_slice(b"/recon");
    let reconstruction =
        prove_opening(params, &residual(&c_p, &bit_planes), 0, &diff_r, &recon_regime(t), &rseed)?;

    Some(ShortnessProof { bit_planes, binary, reconstruction })
}

/// Verify a [`prove_short`] proof that `c_p` opens to a polynomial with `‖·‖∞ < 2^t`.
#[must_use]
pub fn verify_short(params: &RingParams, c_p: &RingCommitment, t: usize, proof: &ShortnessProof) -> bool {
    if t == 0 || t > MAX_WIDTH || proof.bit_planes.len() != t {
        return false;
    }
    // Every plane is {0,1}-valued, in one aggregated check.
    if !verify_binary_agg(params, &proof.bit_planes, &proof.binary) {
        return false;
    }
    // And the planes recompose to the committed p: the residual the verifier forms opens to zero.
    verify_opening(params, &residual(c_p, &proof.bit_planes), 0, &proof.reconstruction, &recon_regime(t))
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
        use crate::ring_range_agg::SCALAR_ROUNDS;
        use crate::ring_size::{BYTES_PER_ELEMENT, ProofSize};

        let params = RingParams::standard();
        let p = poly(&[1, 2, 3]);
        let (r, _c) = commit(&params, &p, b"size-short");
        let proof = prove_short(&params, &p, &r, T, b"seed").expect("short");

        // A binarity round is 3 commitments + the revealed f + 2 openings; a linear round over n messages is
        // (n+1) commitments + n revealed + (n+1) openings. Shortness = T planes + T binarity + 1 reconstruction.
        let separate = SCALAR_ROUNDS * (3 * (K + 1) + 1 + 2 * ELL); // what ONE plane used to cost
        let aggregated = SCALAR_ROUNDS * (T * (K + 1 + 1 + ELL) + 2 * (K + 1) + ELL); // all T planes, one proof
        let recon = 1 + ELL; // rung 2: ONE opening-to-zero (challenge + ELL responses), single-round
        let expected = T * (K + 1) + aggregated + recon;
        assert_eq!(proof.ring_elements(), expected, "the accounting matches the construction exactly");
        assert_eq!(proof.encoded_bytes(), expected * BYTES_PER_ELEMENT);

        // The aggregation's win, measured. The ratio approaches (3(K+1)+1+2ELL)/(K+1+1+ELL) ≈ 2.14× as the fixed
        // per-round overhead amortises: 1.67× at this test's small T, and ≥2× from the real width upward — so assert
        // the loose bound here and the exact one at t = LOG_BASE, which is what a spend actually pays.
        assert!(aggregated < T * separate, "aggregating is cheaper than one proof per plane ({aggregated} vs {})", T * separate);
        let real_t = LOG_BASE as usize;
        let real_agg = SCALAR_ROUNDS * (real_t * (K + 1 + 1 + ELL) + 2 * (K + 1) + ELL);
        assert!(
            real_agg * 2 <= real_t * separate,
            "at t = LOG_BASE the aggregation at least halves binarity ({real_agg} vs {})",
            real_t * separate
        );
        // Rung 2: the reconstruction, which after rung 1 had OVERTAKEN binarity as the larger part, is now negligible.
        // A general linear proof over T+1 messages would have cost REPETITIONS·((T+2)(K+1) + (T+1) + (T+2)ELL).
        let recon_as_linear = crate::ring_product::REPETITIONS * ((T + 2) * (K + 1) + (T + 1) + (T + 2) * ELL);
        assert!(
            recon * 100 < recon_as_linear,
            "the opening-to-zero reconstruction is orders of magnitude smaller ({recon} vs {recon_as_linear})"
        );
        assert!(recon * 10 < aggregated, "and it is now negligible beside the binarity it used to exceed");
        // Binarity is once again the whole of a shortness proof, and a real node pays ELL_H limbs at t = LOG_BASE — so
        // that is what the remaining rungs must attack. Asserted so the ratio cannot silently regress.
        let real_per_node = ELL_H
            * (LOG_BASE as usize * (K + 1)
                + SCALAR_ROUNDS * (LOG_BASE as usize * (K + 1 + 1 + ELL) + 2 * (K + 1) + ELL));
        assert!(
            real_per_node * BYTES_PER_ELEMENT > 1 << 20,
            "one node's shortness still exceeds a megabyte ({} bytes)",
            real_per_node * BYTES_PER_ELEMENT
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
