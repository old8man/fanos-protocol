//! The **aggregated range proof** — `v ∈ [0, 2^bits)` in zero knowledge with size *independent of the bit count*,
//! the practical successor to a per-bit range proof (`O(bits)` product proofs). This is what makes
//! confidential amounts *and* the untraceability shortness proofs affordable.
//!
//! ## Construction — a Bulletproofs-style argument in the lattice setting
//!
//! Pack the bits into **one** polynomial `b(X) = Σ bᵢ·Xⁱ` and commit `C_b = com(b)`. Two things must hold: every
//! coefficient is a bit (`b ∘ (b − 1) = 0`, coefficient-wise), and `Σ_{i<bits} 2ⁱ·bᵢ = v`. Both are proven with a
//! **small scalar challenge** `x` and a single revealed masked polynomial `f = x·b + a` (`a` uniform):
//!
//! ```text
//! binarity:        com(f ∘ (x − f)) = x·C_d + C_e     with  d = a∘(1−2b),  e = −a∘a
//! reconstruction:  com(⟨f, 2^vec⟩)  = x·C_v + C_w     with  w = ⟨a, 2^vec⟩
//! opening:         com(f)           = x·C_b + C_a
//! ```
//!
//! The trick that makes it a *lattice* proof: `x` is a small scalar (`< 2^{CHALLENGE_BITS}`), so `f ∘ (x − f)` is
//! a polynomial the **verifier computes** coefficient-wise from the revealed `f` — a Hadamard product, not a ring
//! product — and every opening `x·r + r_mask` stays short so binding holds. Expanding, `f∘(x−f) = x²·(b∘(1−b)) +
//! x·(a∘(1−2b)) − a∘a`; the binarity check forces the `x²` term to vanish, i.e. `b∘(1−b)=0`. A non-binary `b`
//! leaves a nonzero `x²` coefficient, so the degree-2 identity holds at a random `x` with probability `≤
//! 2/2^{CHALLENGE_BITS}` per round — driven to `≈2⁻¹²⁸` by [`REPETITIONS`](crate::ring_product::REPETITIONS) rounds
//! under one Fiat–Shamir seed. High coefficients of `b` (index `≥ bits`) are also forced binary but carry weight
//! `0` in `⟨·,2^vec⟩`, so they cannot affect `v`.
//!
//! Size: `C_b` plus `REPETITIONS` rounds of a handful of commitments and one polynomial — independent of `bits`.
//!
//! > **STATUS — [P]/[H], correctness-first.** Construction/soundness/ZK are the spec; `CHALLENGE_BITS`, the
//! > repetition count, and the masking bound are illustrative (calibration pending), not constant-time. Tests
//! > verify completeness, boundary values, out-of-range rejection, commitment binding, and re-randomisation.

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

use crate::ring::{D, Poly};
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_product::REPETITIONS;

/// Scalar challenge width: `x ∈ [1, 2^{CHALLENGE_BITS})`. Per-round soundness `≤ 2/2^{CHALLENGE_BITS} = 2⁻⁸`, so
/// `REPETITIONS = 16` rounds target `≈ 2⁻¹²⁸`. Illustrative.
const CHALLENGE_BITS: u32 = 9;

/// The challenge is drawn from `[1, CHALLENGE_MOD]` (nonzero — `x = 0` gives a vacuous round). Shared with the
/// binarity proof ([`crate::ring_binary`]).
pub(crate) const CHALLENGE_MOD: u64 = (1 << CHALLENGE_BITS) - 1;

/// **Wide** masking for the openings that hide *witness* randomness — sized so a whole proof accepts on the first
/// attempt with overwhelming probability. Shared with [`crate::ring_binary`].
///
/// The width is **derived, not chosen**. Rejection is per *coefficient*: an opening `x·r + r_mask` leaves the accept
/// region only if `r_mask` lands within `CHALLENGE_MOD` of the boundary, i.e. with probability `≈ CHALLENGE_MOD/B`.
/// A Fiat–Shamir transcript covers every round at once (that is what forbids per-round grinding), so **all** of a
/// proof's openings share a single accept event and the per-coefficient probability compounds over
/// `openings · ELL · D` coefficients. For the aggregated binarity proof an opening is revealed *per plane*, so that
/// count carries an extra factor of `t`:
///
/// ```text
/// P(accept) ≈ (1 − CHALLENGE_MOD/B)^(t · REPETITIONS · ELL · D)
/// ```
///
/// At `B = 2²⁵` that is 0.78 for `t = 1` but only **0.018** for `t = 16` and ~0 for `t = 64` — which is exactly how
/// the aggregation first failed: the mask had been sized for a single opening. `B = 2⁴⁰` gives `> 0.999` even at
/// `t = 64`, so no resampling is expected at any width the stack uses. The cost is a correspondingly larger
/// extractable-opening norm (`2⁴⁰`, still far below `q = 2⁶⁴`); like every parameter here that bound awaits
/// calibration, so the trade is recorded rather than hidden.
pub(crate) const MASK_WIDE: i64 = 1 << 40;

/// Accept region for a wide opening `x·r + r_mask`, hidden part `‖x·r‖∞ ≤ CHALLENGE_MOD`.
pub(crate) const ACCEPT_WIDE: i64 = MASK_WIDE - CHALLENGE_MOD as i64;

/// `z_de = x·r_d + r_e` hides only *fresh* ternary masking, so it is inherently small: `‖·‖∞ ≤ CHALLENGE_MOD + 1`.
/// No rejection is needed; the bound is a binding check.
pub(crate) const ACCEPT_SMALL: i64 = CHALLENGE_MOD as i64 + 1;

/// A bound on resample attempts (the wide masking keeps rejection rare).
const MAX_ATTEMPTS: u32 = 32;

/// One round: the masking commitments and the single revealed masked polynomial with its openings.
#[derive(Clone, PartialEq, Eq, Debug)]
struct AggRound {
    c_a: RingCommitment, // com(a)
    c_d: RingCommitment, // com(a∘(1−2b))
    c_e: RingCommitment, // com(−a∘a)
    c_w: RingCommitment, // com(⟨a, 2^vec⟩)
    f: Poly,             // x·b + a
    z_ba: RingRandomness,
    z_de: RingRandomness,
    z_w: RingRandomness,
}

/// An aggregated zero-knowledge range proof that a value commitment opens to some `v ∈ [0, 2^bits)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AggRangeProof {
    bits: usize,
    c_b: RingCommitment, // com(b), the packed bits — committed once
    rounds: Vec<AggRound>,
}

/// `x·p` coefficient-wise (a scalar-by-polynomial product): `broadcast(x) ∘ p`. Shared with the binarity proof.
pub(crate) fn scalar_mul(x: u64, p: &Poly) -> Poly {
    Poly::broadcast(x).hadamard(p)
}

/// Absorb a commitment into a Fiat–Shamir transcript.
fn absorb(buf: &mut Vec<u8>, c: &RingCommitment) {
    for p in c.t0().iter().chain(core::iter::once(c.t1())) {
        for &coeff in p.coeffs() {
            buf.extend_from_slice(&coeff.to_le_bytes());
        }
    }
}

/// The Fiat–Shamir seed: the value commitment, the bit commitment, and every round's masking commitments.
fn challenge_seed<'a>(
    v_com: &RingCommitment,
    c_b: &RingCommitment,
    rounds: impl Iterator<Item = &'a AggRound>,
) -> [u8; 32] {
    let mut buf = Vec::new();
    absorb(&mut buf, v_com);
    absorb(&mut buf, c_b);
    for r in rounds {
        absorb(&mut buf, &r.c_a);
        absorb(&mut buf, &r.c_d);
        absorb(&mut buf, &r.c_e);
        absorb(&mut buf, &r.c_w);
    }
    let mut seed = [0u8; 32];
    hash_xof("FANOS-obolos-v1/ring-range-agg-seed", &buf, &mut seed);
    seed
}

/// Round `k`'s scalar challenge `x ∈ [1, CHALLENGE_MOD]`.
fn round_challenge(seed: &[u8; 32], k: usize) -> u64 {
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(seed);
    input.extend_from_slice(&(k as u64).to_le_bytes());
    let mut out = [0u8; 8];
    hash_xof("FANOS-obolos-v1/ring-range-agg-challenge", &input, &mut out);
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

/// Prove, in zero knowledge, that `com(value; r_value)` opens to some `v ∈ [0, 2^bits)`. Returns `None` if
/// `bits > 62` (`2^bits` must fit in a coefficient) — a hard check, not a debug assertion, since a silently-accepted
/// oversized width is a soundness failure rather than a programming slip.
#[must_use]
pub fn prove_range_agg(
    params: &RingParams,
    value: u64,
    r_value: &RingRandomness,
    bits: usize,
    seed: &[u8],
) -> Option<AggRangeProof> {
    if bits > 62 {
        return None;
    }
    let v_com = RingCommitment::commit_message(params, &Poly::constant(value), r_value);
    // Pack the bits: b(X) = Σ_{i<bits} ((value>>i)&1)·Xⁱ.
    let mut b_coeffs = [0u64; D];
    for (i, slot) in b_coeffs.iter_mut().enumerate().take(bits) {
        *slot = (value >> i) & 1;
    }
    let b = Poly::from_u64(&b_coeffs);
    let one_minus_2b = Poly::broadcast(1).sub(&b.add(&b)); // 1 − 2b, coefficient-wise
    let mut bseed = seed.to_vec();
    bseed.extend_from_slice(b"/bits");
    let r_b = RingRandomness::from_seed(&bseed); // ternary
    let c_b = RingCommitment::commit_message(params, &b, &r_b);

    for attempt in 0..MAX_ATTEMPTS {
        // Sample every round's masking and commitments.
        struct Masking {
            a: Poly,
            r_a: RingRandomness,
            r_d: RingRandomness,
            r_e: RingRandomness,
            r_w: RingRandomness,
        }
        let mut maskings = Vec::with_capacity(REPETITIONS);
        let mut rounds = Vec::with_capacity(REPETITIONS);
        for k in 0..REPETITIONS {
            let a = Poly::uniform(&mask_seed(seed, attempt, k, 0));
            let d = a.hadamard(&one_minus_2b);
            let e = Poly::zero().sub(&a.hadamard(&a)); // −a∘a
            let w = a.inner_pow2(bits);
            let r_a = RingRandomness::from_uniform_bounded(&mask_seed(seed, attempt, k, 1), MASK_WIDE);
            let r_d = RingRandomness::from_seed(&mask_seed(seed, attempt, k, 2)); // ternary (fresh)
            let r_e = RingRandomness::from_seed(&mask_seed(seed, attempt, k, 3)); // ternary (fresh)
            let r_w = RingRandomness::from_uniform_bounded(&mask_seed(seed, attempt, k, 4), MASK_WIDE);
            rounds.push(AggRound {
                c_a: RingCommitment::commit_message(params, &a, &r_a),
                c_d: RingCommitment::commit_message(params, &d, &r_d),
                c_e: RingCommitment::commit_message(params, &e, &r_e),
                c_w: RingCommitment::commit_message(params, &Poly::constant(w), &r_w),
                f: Poly::zero(), // filled below
                z_ba: r_a.clone(),
                z_de: r_d.clone(),
                z_w: r_w.clone(),
            });
            maskings.push(Masking { a, r_a, r_d, r_e, r_w });
        }
        let seed_h = challenge_seed(&v_com, &c_b, rounds.iter());

        let mut ok = true;
        for (k, (m, round)) in maskings.iter().zip(&mut rounds).enumerate() {
            let x = round_challenge(&seed_h, k);
            let cx = Poly::constant(x);
            round.f = scalar_mul(x, &b).add(&m.a);
            round.z_ba = r_b.scale(&cx).add(&m.r_a);
            round.z_de = m.r_d.scale(&cx).add(&m.r_e);
            round.z_w = r_value.scale(&cx).add(&m.r_w);
            if !round.z_ba.infinity_norm_le(ACCEPT_WIDE)
                || !round.z_de.infinity_norm_le(ACCEPT_SMALL)
                || !round.z_w.infinity_norm_le(ACCEPT_WIDE)
            {
                ok = false;
                break;
            }
        }
        if ok {
            return Some(AggRangeProof { bits, c_b, rounds });
        }
    }
    None
}

/// Verify a [`prove_range_agg`] proof that `value_commitment` opens to some `v ∈ [0, 2^bits)`.
///
/// **`bits` is the verifier's demand, not the prover's claim** (audit O-C1). The proof carries its own width — the
/// reconstruction weights depend on it — but a verifier that simply *used* that field would let the prover choose
/// the bound, which forges value by modular wraparound (see [`crate::ring_commit::RANGE_BITS`]). So the declared
/// width must equal the width the caller demands, or the proof is refused.
#[must_use]
pub fn verify_range_agg(
    params: &RingParams,
    value_commitment: &RingCommitment,
    bits: usize,
    proof: &AggRangeProof,
) -> bool {
    if proof.bits != bits || proof.rounds.len() != REPETITIONS {
        return false;
    }
    let seed_h = challenge_seed(value_commitment, &proof.c_b, proof.rounds.iter());
    for (k, rd) in proof.rounds.iter().enumerate() {
        if !rd.z_ba.infinity_norm_le(ACCEPT_WIDE)
            || !rd.z_de.infinity_norm_le(ACCEPT_SMALL)
            || !rd.z_w.infinity_norm_le(ACCEPT_WIDE)
        {
            return false;
        }
        let x = round_challenge(&seed_h, k);
        let cx = Poly::constant(x);
        // Opening: com(f) = x·C_b + C_a.
        if RingCommitment::commit_message(params, &rd.f, &rd.z_ba) != proof.c_b.scale(&cx).add(&rd.c_a) {
            return false;
        }
        // Binarity: com(f ∘ (x − f)) = x·C_d + C_e. The verifier forms f∘(x−f) from the revealed f.
        let hadamard = rd.f.hadamard(&Poly::broadcast(x).sub(&rd.f));
        if RingCommitment::commit_message(params, &hadamard, &rd.z_de) != rd.c_d.scale(&cx).add(&rd.c_e) {
            return false;
        }
        // Reconstruction: com(⟨f, 2^vec⟩) = x·C_v + C_w.
        let recon = Poly::constant(rd.f.inner_pow2(proof.bits));
        if RingCommitment::commit_message(params, &recon, &rd.z_w) != value_commitment.scale(&cx).add(&rd.c_w) {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const BITS: usize = 16;

    fn commit(params: &RingParams, value: u64, seed: &[u8]) -> (RingRandomness, RingCommitment) {
        let r = RingRandomness::from_seed(seed);
        let c = RingCommitment::commit_message(params, &Poly::constant(value), &r);
        (r, c)
    }

    #[test]
    fn an_in_range_value_proves_and_verifies() {
        let params = RingParams::standard();
        let (r, c) = commit(&params, 40_000, b"agg-happy"); // < 2^16 = 65536
        let proof = prove_range_agg(&params, 40_000, &r, BITS, b"seed").expect("in range");
        assert!(verify_range_agg(&params, &c, 16, &proof), "40000 ∈ [0, 2^16) verifies");
    }

    #[test]
    fn boundary_values_prove() {
        let params = RingParams::standard();
        for v in [0u64, 1, (1 << BITS) - 1] {
            let (r, c) = commit(&params, v, &[b'a', v as u8, (v >> 8) as u8]);
            let proof = prove_range_agg(&params, v, &r, BITS, b"seed").expect("boundary");
            assert!(verify_range_agg(&params, &c, 16, &proof), "boundary {v} verifies");
        }
    }

    #[test]
    fn an_out_of_range_value_has_no_accepting_proof() {
        // 2^16 needs a 17th bit; decomposed into 16 bits it reconstructs to 0, not 2^16, so the reconstruction
        // check against the real C_v (= com 2^16) fails.
        let params = RingParams::standard();
        let (r, c) = commit(&params, 1 << BITS, b"agg-oob");
        let proof = prove_range_agg(&params, 1 << BITS, &r, BITS, b"seed").expect("proof emitted");
        assert!(!verify_range_agg(&params, &c, 16, &proof), "2^16 ∉ [0, 2^16) is rejected");
    }

    #[test]
    fn a_proof_does_not_verify_against_a_different_commitment() {
        let params = RingParams::standard();
        let (r, _c) = commit(&params, 1234, b"agg-bind");
        let proof = prove_range_agg(&params, 1234, &r, BITS, b"seed").unwrap();
        let (_r2, other) = commit(&params, 1234, b"other-randomness");
        assert!(!verify_range_agg(&params, &other, 16, &proof), "the value commitment is bound in");
    }

    #[test]
    fn the_proof_is_re_randomised() {
        let params = RingParams::standard();
        let (r, c) = commit(&params, 999, b"agg-zk");
        let p1 = prove_range_agg(&params, 999, &r, BITS, b"seed-a").unwrap();
        let p2 = prove_range_agg(&params, 999, &r, BITS, b"seed-b").unwrap();
        assert_ne!(p1, p2, "different seeds ⇒ different zero-knowledge proofs");
        assert!(verify_range_agg(&params, &c, 16, &p1) && verify_range_agg(&params, &c, 16, &p2));
    }
}
