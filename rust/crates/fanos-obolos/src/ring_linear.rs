//! The **zero-knowledge linear-relation proof**: given public commitments `Cᵢ = com(mᵢ; rᵢ)` and public ring
//! coefficients `cᵢ`, prove `Σᵢ cᵢ·mᵢ = 0` — *without revealing* the messages `mᵢ` or their randomness. This is
//! the workhorse the untraceability path proof rests on: the SIS hash relation `G(parent) = A₀·left + A₁·right`
//! ([`crate::ring_hash`]) is exactly such a linear relation (`A₀·left + A₁·right − G(parent) = 0`), with the
//! *huge* matrix entries `A₀, A₁` as coefficients.
//!
//! ## Why the coefficients can be huge
//!
//! A homomorphic `Σ cᵢ·Cᵢ` commits to `Σ cᵢ·mᵢ` under randomness `Σ cᵢ·rᵢ`, which — for coefficients as large as
//! uniform `R_q` matrix entries — dwarfs `q` and cannot be proven short. The escape (as in the range proof's
//! reconstruction): mask and reveal `zᵢ = γ·mᵢ + aᵢ` and check the relation **on the revealed messages** via the
//! aggregate `Σ cᵢ·zᵢ`. The coefficients hit only these public polynomials, never the randomness, so every
//! opening `r_{zᵢ} = γ·rᵢ + sᵢ` stays short (`γ` a monomial) and binding survives.
//!
//! ## Construction
//!
//! Each round commits per-message maskings `Aᵢ = com(aᵢ; sᵢ)` and one **aggregate** `A_agg = com(Σ cᵢ·aᵢ; s_agg)`
//! (`s_agg` short). For a monomial challenge `γ`, the prover reveals `zᵢ = γ·mᵢ + aᵢ`, the short openings
//! `r_{zᵢ}`, and `s_agg`. The verifier checks
//!
//! ```text
//! com(zᵢ; r_{zᵢ}) = γ·Cᵢ + Aᵢ   (binds zᵢ to Cᵢ)      and      com(Σ cᵢ·zᵢ; s_agg) = A_agg.
//! ```
//!
//! For an honest witness `Σ cᵢ·zᵢ = γ·(Σ cᵢ·mᵢ) + Σ cᵢ·aᵢ = Σ cᵢ·aᵢ`, so the aggregate check holds. A cheater
//! with `δ = Σ cᵢ·mᵢ ≠ 0` produces `Σ cᵢ·zᵢ = γ·δ + Σ cᵢ·aᵢ`, which matches the pre-committed `A_agg` only if `γ`
//! hits one specific monomial — probability `≤ 1/2D` per round, driven to `≈ 2⁻¹²⁸` by
//! [`REPETITIONS`] rounds under one Fiat–Shamir seed. Zero-knowledge: uniform
//! `aᵢ` hide `mᵢ` in `zᵢ`; the transcript is simulatable from `γ` alone (choose `zᵢ`, derive `Aᵢ`/`A_agg`).
//!
//! > **STATUS — \[P\]/\[H\], correctness-first.** Construction/soundness/ZK are the spec; parameters illustrative, not
//! > constant-time. Tests verify completeness, soundness (a false relation has no accepting proof), coefficient/
//! > commitment binding, and re-randomisation.

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

use crate::ring::{D, Poly};
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_product::{ACCEPT_LINEAR, MASK_BOUND, REPETITIONS};

/// A bound on resample attempts (rejection is rare — the masking is wide).
const MAX_ATTEMPTS: u32 = 32;

/// One round: per-message masking commitments, the aggregate masking commitment, and the masked responses.
#[derive(Clone, PartialEq, Eq, Debug)]
struct LinearRound {
    a_coms: Vec<RingCommitment>, // Aᵢ = com(aᵢ; sᵢ)
    a_agg: RingCommitment,       // A_agg = com(Σ cᵢ aᵢ; s_agg)
    z: Vec<Poly>,                // zᵢ = γ·mᵢ + aᵢ
    rz: Vec<RingRandomness>,     // r_{zᵢ} = γ·rᵢ + sᵢ
    s_agg: RingRandomness,       // the (short) randomness of A_agg, revealed
}

/// A zero-knowledge proof that public commitments satisfy `Σᵢ cᵢ·mᵢ = 0` under public coefficients `cᵢ`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinearProof {
    rounds: Vec<LinearRound>,
}

impl crate::ring_size::ProofSize for LinearRound {
    fn ring_elements(&self) -> usize {
        self.a_coms.ring_elements() + self.a_agg.ring_elements() + self.z.len() + self.rz.ring_elements()
            + self.s_agg.ring_elements()
    }
}

impl crate::ring_size::ProofSize for LinearProof {
    /// `REPETITIONS` rounds, each `(n+1)·(K+1)` commitment elements + `n` revealed messages + `(n+1)·ELL` openings —
    /// so a linear proof is linear in *both* the statement width `n` and the repetition count.
    fn ring_elements(&self) -> usize {
        self.rounds.ring_elements()
    }
}

/// The weighted sum `Σ cᵢ·zᵢ` in `R_q` — the aggregate the relation is checked on (revealed messages only).
fn weighted_sum(coeffs: &[Poly], terms: &[Poly]) -> Poly {
    coeffs.iter().zip(terms).fold(Poly::zero(), |acc, (c, z)| acc.add(&c.mul(z)))
}

/// Absorb a commitment into a Fiat–Shamir transcript.
fn absorb(buf: &mut Vec<u8>, c: &RingCommitment) {
    for p in c.t0().iter().chain(core::iter::once(c.t1())) {
        for &coeff in p.coeffs() {
            buf.extend_from_slice(&coeff.to_le_bytes());
        }
    }
}

/// The Fiat–Shamir seed: the statement (commitments + coefficients) and every round's masking commitments.
fn challenge_seed<'a>(
    commitments: &[RingCommitment],
    coeffs: &[Poly],
    aux: impl Iterator<Item = (&'a [RingCommitment], &'a RingCommitment)>,
) -> [u8; 32] {
    let mut buf = Vec::new();
    for c in commitments {
        absorb(&mut buf, c);
    }
    for c in coeffs {
        for &coeff in c.coeffs() {
            buf.extend_from_slice(&coeff.to_le_bytes());
        }
    }
    for (a_coms, a_agg) in aux {
        for a in a_coms {
            absorb(&mut buf, a);
        }
        absorb(&mut buf, a_agg);
    }
    let mut seed = [0u8; 32];
    hash_xof("FANOS-obolos-v1/ring-linear-seed", &buf, &mut seed);
    seed
}

/// Round `k`'s monomial challenge.
fn round_challenge(seed: &[u8; 32], k: usize) -> Poly {
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(seed);
    input.extend_from_slice(&(k as u64).to_le_bytes());
    let mut out = [0u8; 8];
    hash_xof("FANOS-obolos-v1/ring-linear-challenge", &input, &mut out);
    Poly::monomial((u64::from_le_bytes(out) % (2 * D as u64)) as usize)
}

/// A domain-separated masking seed `base ‖ attempt ‖ k ‖ tag`.
fn mask_seed(base: &[u8], attempt: u32, k: usize, tag: u32) -> Vec<u8> {
    let mut s = Vec::with_capacity(base.len() + 16);
    s.extend_from_slice(base);
    s.extend_from_slice(&attempt.to_le_bytes());
    s.extend_from_slice(&(k as u64).to_le_bytes());
    s.extend_from_slice(&tag.to_le_bytes());
    s
}

/// Prove, in zero knowledge, that `Σᵢ coeffs[i]·messages[i] = 0`, where `commitments[i] = com(messages[i];
/// randomness[i])`. All three slices share one length. `None` only on the rare masking exhaustion.
#[must_use]
pub fn prove_linear(
    params: &RingParams,
    commitments: &[RingCommitment],
    coeffs: &[Poly],
    messages: &[Poly],
    randomness: &[RingRandomness],
    seed: &[u8],
) -> Option<LinearProof> {
    let n = messages.len();
    for attempt in 0..MAX_ATTEMPTS {
        // Sample every round's maskings + commitments.
        struct Masking {
            a: Vec<Poly>,
            s: Vec<RingRandomness>,
            s_agg: RingRandomness,
        }
        let mut maskings = Vec::with_capacity(REPETITIONS);
        let mut auxes = Vec::with_capacity(REPETITIONS);
        for k in 0..REPETITIONS {
            let a: Vec<Poly> = (0..n).map(|i| Poly::uniform(&mask_seed(seed, attempt, k, i as u32))).collect();
            let s: Vec<RingRandomness> = (0..n)
                .map(|i| RingRandomness::from_uniform_bounded(&mask_seed(seed, attempt, k, (n + i) as u32), MASK_BOUND))
                .collect();
            let s_agg = RingRandomness::from_seed(&mask_seed(seed, attempt, k, (2 * n) as u32 + 1)); // ternary
            let a_agg_msg = weighted_sum(coeffs, &a);
            let a_coms: Vec<RingCommitment> =
                a.iter().zip(&s).map(|(ai, si)| RingCommitment::commit_message(params, ai, si)).collect();
            let a_agg = RingCommitment::commit_message(params, &a_agg_msg, &s_agg);
            auxes.push((a_coms, a_agg));
            maskings.push(Masking { a, s, s_agg });
        }
        let seed_h = challenge_seed(commitments, coeffs, auxes.iter().map(|(ac, ag)| (ac.as_slice(), ag)));

        let mut rounds = Vec::with_capacity(REPETITIONS);
        for (k, (m, (a_coms, a_agg))) in maskings.into_iter().zip(auxes).enumerate() {
            let g = round_challenge(&seed_h, k);
            let z: Vec<Poly> = messages.iter().zip(&m.a).map(|(msg, ai)| g.mul(msg).add(ai)).collect();
            let rz: Vec<RingRandomness> =
                randomness.iter().zip(&m.s).map(|(ri, si)| ri.scale(&g).add(si)).collect();
            if !rz.iter().all(|r| r.infinity_norm_le(ACCEPT_LINEAR)) {
                rounds.clear();
                break;
            }
            rounds.push(LinearRound { a_coms, a_agg, z, rz, s_agg: m.s_agg });
        }
        if rounds.len() == REPETITIONS {
            return Some(LinearProof { rounds });
        }
    }
    None
}

/// Verify a [`prove_linear`] proof that the public commitments satisfy `Σᵢ coeffs[i]·mᵢ = 0`.
#[must_use]
pub fn verify_linear(
    params: &RingParams,
    commitments: &[RingCommitment],
    coeffs: &[Poly],
    proof: &LinearProof,
) -> bool {
    let n = commitments.len();
    if proof.rounds.len() != REPETITIONS || coeffs.len() != n {
        return false;
    }
    let seed_h =
        challenge_seed(commitments, coeffs, proof.rounds.iter().map(|r| (r.a_coms.as_slice(), &r.a_agg)));
    for (k, rd) in proof.rounds.iter().enumerate() {
        if rd.a_coms.len() != n || rd.z.len() != n || rd.rz.len() != n {
            return false;
        }
        let g = round_challenge(&seed_h, k);
        // Bind each response to its commitment: com(zᵢ; r_{zᵢ}) = γ·Cᵢ + Aᵢ, with a short opening.
        for (((z, rz), c), a) in rd.z.iter().zip(&rd.rz).zip(commitments).zip(&rd.a_coms) {
            if !rz.infinity_norm_le(ACCEPT_LINEAR) {
                return false;
            }
            if RingCommitment::commit_message(params, z, rz) != c.scale(&g).add(a) {
                return false;
            }
        }
        // The relation, on the revealed messages: com(Σ cᵢ·zᵢ; s_agg) = A_agg with a short s_agg. For an honest
        // witness Σ cᵢ·zᵢ = Σ cᵢ·aᵢ (the γ·Σcᵢmᵢ term vanishes), matching the pre-committed aggregate.
        if !rd.s_agg.infinity_norm_le(ACCEPT_LINEAR) {
            return false;
        }
        let agg = weighted_sum(coeffs, &rd.z);
        if RingCommitment::commit_message(params, &agg, &rd.s_agg) != rd.a_agg {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Commit `messages` under fresh ternary randomness; return `(randomness, commitments)`.
    fn commit_all(params: &RingParams, messages: &[Poly], tag: &[u8]) -> (Vec<RingRandomness>, Vec<RingCommitment>) {
        let randomness: Vec<RingRandomness> = (0..messages.len())
            .map(|i| {
                let mut s = tag.to_vec();
                s.extend_from_slice(&(i as u64).to_le_bytes());
                RingRandomness::from_seed(&s)
            })
            .collect();
        let commitments =
            messages.iter().zip(&randomness).map(|(m, r)| RingCommitment::commit_message(params, m, r)).collect();
        (randomness, commitments)
    }

    #[test]
    fn a_true_linear_relation_proves_and_verifies() {
        // 3·m0 + 5·m1 − 1·m2 = 0 with m2 = 3·m0 + 5·m1. Coefficients include a "huge" uniform one to exercise the
        // no-blow-up property.
        let params = RingParams::standard();
        let m0 = Poly::constant(7);
        let m1 = Poly::constant(11);
        let big = Poly::uniform(b"huge-coeff"); // a full-range coefficient — the no-blow-up stress case
        let neg_one = Poly::zero().sub(&Poly::constant(1));
        // relation with coeffs [3, 5, big, -1] over messages [m0, m1, m0, m2]:
        //   3·m0 + 5·m1 + big·m0 − m2 = 0    ⇔    m2 = 3·m0 + 5·m1 + big·m0.
        let m2 = Poly::constant(3 * 7 + 5 * 11).add(&big.mul(&m0));
        let messages = [m0.clone(), m1, m0.clone(), m2];
        let coeffs = [Poly::constant(3), Poly::constant(5), big.clone(), neg_one];
        let (r, c) = commit_all(&params, &messages, b"lin-ok");
        let proof = prove_linear(&params, &c, &coeffs, &messages, &r, b"seed").expect("true relation");
        assert!(verify_linear(&params, &c, &coeffs, &proof), "the true linear relation verifies");
    }

    #[test]
    fn a_false_linear_relation_has_no_accepting_proof() {
        // 1·m0 + 1·m1 = 0 claimed, but m0 + m1 ≠ 0.
        let params = RingParams::standard();
        let messages = [Poly::constant(4), Poly::constant(9)]; // sum 13 ≠ 0
        let coeffs = [Poly::constant(1), Poly::constant(1)];
        let (r, c) = commit_all(&params, &messages, b"lin-bad");
        let proof = prove_linear(&params, &c, &coeffs, &messages, &r, b"seed").expect("proof emitted");
        assert!(!verify_linear(&params, &c, &coeffs, &proof), "a false relation cannot verify");
    }

    #[test]
    fn a_proof_is_bound_to_its_coefficients_and_commitments() {
        let params = RingParams::standard();
        let messages = [Poly::constant(6), Poly::constant(6)]; // m0 − m1 = 0
        let coeffs = [Poly::constant(1), Poly::constant(1).sub(&Poly::constant(2))]; // [1, -1]
        let (r, c) = commit_all(&params, &messages, b"lin-bind");
        let proof = prove_linear(&params, &c, &coeffs, &messages, &r, b"seed").unwrap();
        assert!(verify_linear(&params, &c, &coeffs, &proof), "m0 − m1 = 0 holds");
        // Different coefficients [1, 1]: the relation m0 + m1 = 12 ≠ 0, and the aggregate check fails.
        let other = [Poly::constant(1), Poly::constant(1)];
        assert!(!verify_linear(&params, &c, &other, &proof), "the coefficients are bound in");
        // A swapped commitment breaks the per-message binding.
        let (_r2, c2) = commit_all(&params, &[Poly::constant(6), Poly::constant(7)], b"lin-bind");
        assert!(!verify_linear(&params, &c2, &coeffs, &proof), "the commitments are bound in");
    }

    #[test]
    fn the_proof_is_re_randomised() {
        let params = RingParams::standard();
        let messages = [Poly::constant(8), Poly::constant(8)];
        let coeffs = [Poly::constant(1), Poly::constant(1).sub(&Poly::constant(2))];
        let (r, c) = commit_all(&params, &messages, b"lin-zk");
        let p1 = prove_linear(&params, &c, &coeffs, &messages, &r, b"seed-a").unwrap();
        let p2 = prove_linear(&params, &c, &coeffs, &messages, &r, b"seed-b").unwrap();
        assert_ne!(p1, p2, "different seeds ⇒ different zero-knowledge proofs");
        assert!(verify_linear(&params, &c, &coeffs, &p1) && verify_linear(&params, &c, &coeffs, &p2));
    }
}
