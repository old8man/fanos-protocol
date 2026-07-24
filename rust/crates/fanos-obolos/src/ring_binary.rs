//! The **binarity proof**: prove a committed polynomial `p` is `{0,1}`-valued (every coefficient a bit), in zero
//! knowledge. This is the reusable core of the **polynomial-shortness** proof ([`crate::ring_shortness`]) — a
//! value is short (`‖p‖∞ < 2^t`) iff its `t` bit-planes are each binary and recompose to it — which in turn makes
//! the untraceability hash step *sound* (nodes must be short, [`crate::ring_membership`]).
//!
//! The argument is the binarity half of the aggregated range proof ([`crate::ring_range_agg`]), lifted to an
//! arbitrary committed polynomial: for a small scalar challenge `x`, reveal the masked `f = x·p + a` and check
//!
//! ```text
//! opening:   com(f)        = x·C_p + C_a
//! binarity:  com(f ∘ (x−f)) = x·C_d + C_e     with  d = a∘(1−2p),  e = −a∘a
//! ```
//!
//! `f ∘ (x−f) = x²·(p∘(1−p)) + x·(a∘(1−2p)) − a∘a`; the check forces the `x²` term `p∘(1−p) = 0`, i.e. `p` binary.
//! A non-binary `p` survives only if `x` hits a root of a degree-2 identity (`≤ 2/2^{CHALLENGE_BITS}` per round →
//! `≈2⁻¹²⁸` over [`REPETITIONS`](crate::ring_product::REPETITIONS) rounds). Shares the challenge width, masking
//! bound, and `scalar_mul` with [`crate::ring_range_agg`].
//!
//! > **STATUS — [P]/[H], correctness-first.** Tests verify a binary polynomial proves, a non-binary one is
//! > rejected, commitment binding, and re-randomisation.

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

use crate::ring::Poly;
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_product::REPETITIONS;
use crate::ring_range_agg::{ACCEPT_SMALL, ACCEPT_WIDE, CHALLENGE_MOD, MASK_WIDE, scalar_mul};

/// A bound on resample attempts (the wide masking keeps rejection rare).
const MAX_ATTEMPTS: u32 = 32;

/// One round: the masking commitments and the revealed masked polynomial with its openings.
#[derive(Clone, PartialEq, Eq, Debug)]
struct BinaryRound {
    c_a: RingCommitment, // com(a)
    c_d: RingCommitment, // com(a∘(1−2p))
    c_e: RingCommitment, // com(−a∘a)
    f: Poly,             // x·p + a
    z_ba: RingRandomness,
    z_de: RingRandomness,
}

/// A zero-knowledge proof that a committed polynomial is `{0,1}`-valued.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BinaryProof {
    rounds: Vec<BinaryRound>,
}

/// Absorb a commitment into a Fiat–Shamir transcript.
fn absorb(buf: &mut Vec<u8>, c: &RingCommitment) {
    for p in c.t0().iter().chain(core::iter::once(c.t1())) {
        for &coeff in p.coeffs() {
            buf.extend_from_slice(&coeff.to_le_bytes());
        }
    }
}

/// The Fiat–Shamir seed: the statement `C_p` and every round's masking commitments.
fn challenge_seed<'a>(c_p: &RingCommitment, rounds: impl Iterator<Item = &'a BinaryRound>) -> [u8; 32] {
    let mut buf = Vec::new();
    absorb(&mut buf, c_p);
    for r in rounds {
        absorb(&mut buf, &r.c_a);
        absorb(&mut buf, &r.c_d);
        absorb(&mut buf, &r.c_e);
    }
    let mut seed = [0u8; 32];
    hash_xof("FANOS-obolos-v1/ring-binary-seed", &buf, &mut seed);
    seed
}

/// Round `k`'s scalar challenge `x ∈ [1, CHALLENGE_MOD]`.
fn round_challenge(seed: &[u8; 32], k: usize) -> u64 {
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(seed);
    input.extend_from_slice(&(k as u64).to_le_bytes());
    let mut out = [0u8; 8];
    hash_xof("FANOS-obolos-v1/ring-binary-challenge", &input, &mut out);
    (u64::from_le_bytes(out) % CHALLENGE_MOD) + 1
}

/// A domain-separated masking seed `base ‖ attempt ‖ k ‖ tag`.
fn mask_seed(base: &[u8], attempt: u32, k: usize, tag: u8) -> Vec<u8> {
    let mut s = Vec::with_capacity(base.len() + 14);
    s.extend_from_slice(base);
    s.extend_from_slice(&attempt.to_le_bytes());
    s.extend_from_slice(&(k as u64).to_le_bytes());
    s.push(tag);
    s
}

/// Prove, in zero knowledge, that `com(p; r_p)` opens to a `{0,1}`-valued polynomial.
#[must_use]
pub fn prove_binary(params: &RingParams, p: &Poly, r_p: &RingRandomness, seed: &[u8]) -> Option<BinaryProof> {
    let one_minus_2p = Poly::broadcast(1).sub(&p.add(p)); // 1 − 2p, coefficient-wise
    for attempt in 0..MAX_ATTEMPTS {
        struct Masking {
            a: Poly,
            r_a: RingRandomness,
            r_d: RingRandomness,
            r_e: RingRandomness,
        }
        let mut maskings = Vec::with_capacity(REPETITIONS);
        let mut rounds = Vec::with_capacity(REPETITIONS);
        for k in 0..REPETITIONS {
            let a = Poly::uniform(&mask_seed(seed, attempt, k, 0));
            let d = a.hadamard(&one_minus_2p);
            let e = Poly::zero().sub(&a.hadamard(&a)); // −a∘a
            let r_a = RingRandomness::from_uniform_bounded(&mask_seed(seed, attempt, k, 1), MASK_WIDE);
            let r_d = RingRandomness::from_seed(&mask_seed(seed, attempt, k, 2)); // ternary (fresh)
            let r_e = RingRandomness::from_seed(&mask_seed(seed, attempt, k, 3)); // ternary (fresh)
            rounds.push(BinaryRound {
                c_a: RingCommitment::commit_message(params, &a, &r_a),
                c_d: RingCommitment::commit_message(params, &d, &r_d),
                c_e: RingCommitment::commit_message(params, &e, &r_e),
                f: Poly::zero(),
                z_ba: r_a.clone(),
                z_de: r_d.clone(),
            });
            maskings.push(Masking { a, r_a, r_d, r_e });
        }
        let c_p = RingCommitment::commit_message(params, p, r_p);
        let seed_h = challenge_seed(&c_p, rounds.iter());

        let mut ok = true;
        for (k, (m, round)) in maskings.iter().zip(&mut rounds).enumerate() {
            let x = round_challenge(&seed_h, k);
            let cx = Poly::constant(x);
            round.f = scalar_mul(x, p).add(&m.a);
            round.z_ba = r_p.scale(&cx).add(&m.r_a);
            round.z_de = m.r_d.scale(&cx).add(&m.r_e);
            if !round.z_ba.infinity_norm_le(ACCEPT_WIDE) || !round.z_de.infinity_norm_le(ACCEPT_SMALL) {
                ok = false;
                break;
            }
        }
        if ok {
            return Some(BinaryProof { rounds });
        }
    }
    None
}

/// Verify a [`prove_binary`] proof that `c_p` opens to a `{0,1}`-valued polynomial.
#[must_use]
pub fn verify_binary(params: &RingParams, c_p: &RingCommitment, proof: &BinaryProof) -> bool {
    if proof.rounds.len() != REPETITIONS {
        return false;
    }
    let seed_h = challenge_seed(c_p, proof.rounds.iter());
    for (k, rd) in proof.rounds.iter().enumerate() {
        if !rd.z_ba.infinity_norm_le(ACCEPT_WIDE) || !rd.z_de.infinity_norm_le(ACCEPT_SMALL) {
            return false;
        }
        let x = round_challenge(&seed_h, k);
        let cx = Poly::constant(x);
        if RingCommitment::commit_message(params, &rd.f, &rd.z_ba) != c_p.scale(&cx).add(&rd.c_a) {
            return false;
        }
        let hadamard = rd.f.hadamard(&Poly::broadcast(x).sub(&rd.f));
        if RingCommitment::commit_message(params, &hadamard, &rd.z_de) != rd.c_d.scale(&cx).add(&rd.c_e) {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::ring::D;

    /// A `{0,1}`-valued polynomial from a byte pattern (bit `i` = bit of the pattern).
    fn binary_poly(pattern: u64) -> Poly {
        let mut coeffs = [0u64; D];
        for (i, slot) in coeffs.iter_mut().enumerate().take(64) {
            *slot = (pattern >> i) & 1;
        }
        Poly::from_u64(&coeffs)
    }

    fn commit(params: &RingParams, p: &Poly, seed: &[u8]) -> (RingRandomness, RingCommitment) {
        let r = RingRandomness::from_seed(seed);
        let c = RingCommitment::commit_message(params, p, &r);
        (r, c)
    }

    #[test]
    fn a_binary_polynomial_proves_and_verifies() {
        let params = RingParams::standard();
        let p = binary_poly(0xDEAD_BEEF_1234_5678);
        let (r, c) = commit(&params, &p, b"bin-happy");
        let proof = prove_binary(&params, &p, &r, b"seed").expect("binary");
        assert!(verify_binary(&params, &c, &proof), "a {{0,1}} polynomial verifies");
    }

    #[test]
    fn the_all_zero_and_all_one_polynomials_prove() {
        let params = RingParams::standard();
        for p in [Poly::zero(), Poly::broadcast(1)] {
            let (r, c) = commit(&params, &p, b"bin-edge");
            let proof = prove_binary(&params, &p, &r, b"seed").expect("edge binary");
            assert!(verify_binary(&params, &c, &proof));
        }
    }

    #[test]
    fn a_non_binary_polynomial_has_no_accepting_proof() {
        // A coefficient of 2 is not a bit: the x² term p∘(1−p) no longer vanishes.
        let params = RingParams::standard();
        let mut coeffs = [0u64; D];
        coeffs[0] = 2;
        let p = Poly::from_u64(&coeffs);
        let (r, c) = commit(&params, &p, b"bin-bad");
        let proof = prove_binary(&params, &p, &r, b"seed").expect("proof emitted");
        assert!(!verify_binary(&params, &c, &proof), "a coefficient of 2 is not binary");
    }

    #[test]
    fn a_proof_does_not_verify_against_a_different_commitment() {
        let params = RingParams::standard();
        let p = binary_poly(0b1011);
        let (r, _c) = commit(&params, &p, b"bin-bind");
        let proof = prove_binary(&params, &p, &r, b"seed").unwrap();
        let (_r2, other) = commit(&params, &p, b"other-randomness");
        assert!(!verify_binary(&params, &other, &proof), "the commitment is bound in");
    }

    #[test]
    fn the_proof_is_re_randomised() {
        let params = RingParams::standard();
        let p = binary_poly(0xFF00);
        let (r, c) = commit(&params, &p, b"bin-zk");
        let p1 = prove_binary(&params, &p, &r, b"seed-a").unwrap();
        let p2 = prove_binary(&params, &p, &r, b"seed-b").unwrap();
        assert_ne!(p1, p2, "different seeds ⇒ different zero-knowledge proofs");
        assert!(verify_binary(&params, &c, &p1) && verify_binary(&params, &c, &p2));
    }
}
