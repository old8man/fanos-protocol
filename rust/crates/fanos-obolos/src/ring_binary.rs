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
//! `≈2⁻¹²⁸` over [`SCALAR_ROUNDS`](crate::ring_range_agg::SCALAR_ROUNDS) rounds). Shares the challenge width, masking
//! bound, and `scalar_mul` with [`crate::ring_range_agg`].
//!
//! > **STATUS — [P]/[H], correctness-first.** Tests verify a binary polynomial proves, a non-binary one is
//! > rejected, commitment binding, and re-randomisation.

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

use crate::ring::Poly;
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_range_agg::{ACCEPT_SMALL, ACCEPT_WIDE, CHALLENGE_MOD, MASK_WIDE, SCALAR_ROUNDS, scalar_mul};

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

impl crate::ring_size::ProofSize for BinaryRound {
    fn ring_elements(&self) -> usize {
        self.c_a.ring_elements() + self.c_d.ring_elements() + self.c_e.ring_elements() + 1
            + self.z_ba.ring_elements()
            + self.z_de.ring_elements()
    }
}

impl crate::ring_size::ProofSize for BinaryProof {
    /// `SCALAR_ROUNDS` rounds of a fixed `3·(K+1) + 1 + 2·ELL` elements — constant per round, but the *count* of these
    /// proofs is what makes shortness expensive ([`crate::ring_shortness`] needs one per bit-plane).
    fn ring_elements(&self) -> usize {
        self.rounds.ring_elements()
    }
}

/// One round of the **aggregated** proof: a masking commitment per plane, the two aggregate masking commitments, and
/// the revealed masked planes with their openings.
#[derive(Clone, PartialEq, Eq, Debug)]
struct AggBinRound {
    c_a: Vec<RingCommitment>,  // com(a_j), one per plane
    c_d: RingCommitment,       // com(Σ_j y^j·(a_j∘(1−2p_j)))
    c_e: RingCommitment,       // com(−Σ_j y^j·(a_j∘a_j))
    f: Vec<Poly>,              // f_j = x·p_j + a_j
    z_ba: Vec<RingRandomness>, // x·r_{p_j} + r_{a_j}
    z_de: RingRandomness,      // x·r_D + r_E
}

/// A zero-knowledge proof that **every** polynomial in a committed family is `{0,1}`-valued — one proof for all of
/// them, rather than [`BinaryProof`] each.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AggBinaryProof {
    rounds: Vec<AggBinRound>,
}

impl crate::ring_size::ProofSize for AggBinRound {
    fn ring_elements(&self) -> usize {
        self.c_a.ring_elements() + self.c_d.ring_elements() + self.c_e.ring_elements() + self.f.len()
            + self.z_ba.ring_elements()
            + self.z_de.ring_elements()
    }
}

impl crate::ring_size::ProofSize for AggBinaryProof {
    /// `SCALAR_ROUNDS · (t·(K+1+1+ELL) + 2·(K+1) + ELL)` versus `t` separate proofs' `SCALAR_ROUNDS · t·(3(K+1)+1+2ELL)`.
    /// The per-plane `c_d, c_e, z_de` collapse into one triple; the per-plane `c_a, f, z_ba` are irreducible, because
    /// each revealed plane still needs its own binding and mask.
    fn ring_elements(&self) -> usize {
        self.rounds.ring_elements()
    }
}

/// `y^0 … y^{t−1}` in the field — the aggregation weights.
fn powers(y: u64, t: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(t);
    let mut acc = 1u64;
    for _ in 0..t {
        out.push(acc);
        acc = crate::ring::fmul(acc, y);
    }
    out
}

/// `Σ_j w_j · term(j)` coefficient-wise — the aggregate the binarity check is stated over.
fn weighted(weights: &[u64], mut term: impl FnMut(usize) -> Poly) -> Poly {
    weights.iter().enumerate().fold(Poly::zero(), |acc, (j, &w)| acc.add(&scalar_mul(w, &term(j))))
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

/// The aggregation seed — the statement (every plane commitment) and every round's per-plane masking commitments.
/// The `y` challenge must come **after** these and **before** `c_d`/`c_e`, which depend on `y`.
fn agg_seed_y(planes: &[RingCommitment], rounds: &[AggBinRound]) -> [u8; 32] {
    let mut buf = Vec::new();
    for c in planes {
        absorb(&mut buf, c);
    }
    for r in rounds {
        for a in &r.c_a {
            absorb(&mut buf, a);
        }
    }
    let mut seed = [0u8; 32];
    hash_xof("FANOS-obolos-v1/ring-binary-agg-y", &buf, &mut seed);
    seed
}

/// The evaluation seed — the aggregation seed plus every round's aggregate masking commitments.
fn agg_seed_x(seed_y: &[u8; 32], rounds: &[AggBinRound]) -> [u8; 32] {
    let mut buf = seed_y.to_vec();
    for r in rounds {
        absorb(&mut buf, &r.c_d);
        absorb(&mut buf, &r.c_e);
    }
    let mut seed = [0u8; 32];
    hash_xof("FANOS-obolos-v1/ring-binary-agg-x", &buf, &mut seed);
    seed
}

/// Round `k`'s **wide** aggregation challenge `y ∈ [1, q)`.
///
/// Unlike `x`, `y` may span the whole field: it never enters an opening that must stay short — it appears only inside
/// the prover's aggregate messages and in the verifier's own recomputation from revealed values. That is what keeps
/// the aggregation free: the extra soundness term is `(t−1)/q ≈ 2⁻⁶⁰` rather than `(t−1)/2^{CHALLENGE_BITS}`, so the
/// per-round error stays the `2/2^{CHALLENGE_BITS}` of the un-aggregated proof and `SCALAR_ROUNDS` still reaches `2⁻¹²⁸`.
fn round_y(seed: &[u8; 32], k: usize) -> u64 {
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(seed);
    input.extend_from_slice(&(k as u64).to_le_bytes());
    let mut out = [0u8; 8];
    hash_xof("FANOS-obolos-v1/ring-binary-agg-ychal", &input, &mut out);
    (u64::from_le_bytes(out) % (crate::ring::Q - 1)) + 1
}

/// Prove, in zero knowledge, that **every** `planes[j]` is `{0,1}`-valued — one proof for the whole family.
///
/// The aggregation: for a wide challenge `y` and the small challenge `x`, the revealed masked planes satisfy
///
/// ```text
/// Σ_j y^j·(f_j ∘ (x − f_j)) = x²·Σ_j y^j·(p_j∘(1−p_j)) + x·D + E
/// ```
///
/// with `D = Σ_j y^j·(a_j∘(1−2p_j))` and `E = −Σ_j y^j·(a_j∘a_j)` committed once. Checking that single identity forces
/// `Σ_j y^j·(p_j∘(1−p_j)) = 0`; a non-binary plane leaves a nonzero polynomial of degree `< t` in `y`, which a random
/// `y` annihilates only with probability `≤ (t−1)/q`. So `t` binarity statements cost one proof instead of `t`.
///
/// `None` if the inputs disagree in length, or on the rare masking exhaustion.
#[must_use]
pub fn prove_binary_agg(
    params: &RingParams,
    planes: &[Poly],
    plane_r: &[RingRandomness],
    seed: &[u8],
) -> Option<AggBinaryProof> {
    let t = planes.len();
    if t == 0 || plane_r.len() != t {
        return None;
    }
    let one_minus_2p: Vec<Poly> = planes.iter().map(|p| Poly::broadcast(1).sub(&p.add(p))).collect();
    let plane_coms: Vec<RingCommitment> =
        planes.iter().zip(plane_r).map(|(p, r)| RingCommitment::commit_message(params, p, r)).collect();

    for attempt in 0..MAX_ATTEMPTS {
        // Phase 1 — per-plane maskings and their commitments, which fix `y`.
        struct Masking {
            a: Vec<Poly>,
            r_a: Vec<RingRandomness>,
            r_d: RingRandomness,
            r_e: RingRandomness,
        }
        let mut maskings = Vec::with_capacity(SCALAR_ROUNDS);
        let mut rounds: Vec<AggBinRound> = Vec::with_capacity(SCALAR_ROUNDS);
        for k in 0..SCALAR_ROUNDS {
            let a: Vec<Poly> = (0..t).map(|j| Poly::uniform(&plane_seed(seed, attempt, k, 0, j))).collect();
            let r_a: Vec<RingRandomness> = (0..t)
                .map(|j| RingRandomness::from_uniform_bounded(&plane_seed(seed, attempt, k, 1, j), MASK_WIDE))
                .collect();
            let c_a = a.iter().zip(&r_a).map(|(aj, rj)| RingCommitment::commit_message(params, aj, rj)).collect();
            let zero = RingCommitment::commit_message(params, &Poly::zero(), &RingRandomness::from_seed(b"/init"));
            rounds.push(AggBinRound {
                c_a,
                c_d: zero.clone(),
                c_e: zero,
                f: Vec::new(),
                z_ba: Vec::new(),
                z_de: RingRandomness::from_seed(b"/init"),
            });
            maskings.push(Masking {
                a,
                r_a,
                r_d: RingRandomness::from_seed(&mask_seed(seed, attempt, k, 2)), // ternary (fresh)
                r_e: RingRandomness::from_seed(&mask_seed(seed, attempt, k, 3)), // ternary (fresh)
            });
        }

        // Phase 2 — `y` is now fixed, so the aggregate maskings can be committed.
        let seed_y = agg_seed_y(&plane_coms, &rounds);
        for (k, (m, round)) in maskings.iter().zip(&mut rounds).enumerate() {
            let w = powers(round_y(&seed_y, k), t);
            let d = weighted(&w, |j| match (m.a.get(j), one_minus_2p.get(j)) {
                (Some(aj), Some(oj)) => aj.hadamard(oj),
                _ => Poly::zero(),
            });
            let e = Poly::zero().sub(&weighted(&w, |j| m.a.get(j).map_or_else(Poly::zero, |aj| aj.hadamard(aj))));
            round.c_d = RingCommitment::commit_message(params, &d, &m.r_d);
            round.c_e = RingCommitment::commit_message(params, &e, &m.r_e);
        }

        // Phase 3 — `x` is fixed, so the masked planes and openings can be revealed.
        let seed_x = agg_seed_x(&seed_y, &rounds);
        let mut ok = true;
        for (k, (m, round)) in maskings.iter().zip(&mut rounds).enumerate() {
            let x = round_challenge(&seed_x, k);
            let cx = Poly::constant(x);
            round.f = planes.iter().zip(&m.a).map(|(p, aj)| scalar_mul(x, p).add(aj)).collect();
            round.z_ba = plane_r.iter().zip(&m.r_a).map(|(rp, ra)| rp.scale(&cx).add(ra)).collect();
            round.z_de = m.r_d.scale(&cx).add(&m.r_e);
            if !round.z_ba.iter().all(|z| z.infinity_norm_le(ACCEPT_WIDE))
                || !round.z_de.infinity_norm_le(ACCEPT_SMALL)
            {
                ok = false;
                break;
            }
        }
        if ok {
            return Some(AggBinaryProof { rounds });
        }
    }
    None
}

/// Verify a [`prove_binary_agg`] proof that every one of `plane_coms` opens to a `{0,1}`-valued polynomial.
#[must_use]
pub fn verify_binary_agg(params: &RingParams, plane_coms: &[RingCommitment], proof: &AggBinaryProof) -> bool {
    let t = plane_coms.len();
    if t == 0 || proof.rounds.len() != SCALAR_ROUNDS {
        return false;
    }
    let seed_y = agg_seed_y(plane_coms, &proof.rounds);
    let seed_x = agg_seed_x(&seed_y, &proof.rounds);
    for (k, rd) in proof.rounds.iter().enumerate() {
        if rd.c_a.len() != t || rd.f.len() != t || rd.z_ba.len() != t {
            return false;
        }
        if !rd.z_ba.iter().all(|z| z.infinity_norm_le(ACCEPT_WIDE)) || !rd.z_de.infinity_norm_le(ACCEPT_SMALL) {
            return false;
        }
        let x = round_challenge(&seed_x, k);
        let cx = Poly::constant(x);
        // Each revealed plane is bound to its commitment: com(f_j; z_ba_j) = x·C_{p_j} + C_{a_j}.
        for (((f, z), cp), ca) in rd.f.iter().zip(&rd.z_ba).zip(plane_coms).zip(&rd.c_a) {
            if RingCommitment::commit_message(params, f, z) != cp.scale(&cx).add(ca) {
                return false;
            }
        }
        // The single aggregated binarity identity, over the revealed planes the verifier already holds.
        let w = powers(round_y(&seed_y, k), t);
        let agg = weighted(&w, |j| {
            rd.f.get(j).map_or_else(Poly::zero, |f| f.hadamard(&Poly::broadcast(x).sub(f)))
        });
        if RingCommitment::commit_message(params, &agg, &rd.z_de) != rd.c_d.scale(&cx).add(&rd.c_e) {
            return false;
        }
    }
    true
}

/// A domain-separated masking seed for plane `j`: `base ‖ attempt ‖ k ‖ tag ‖ j`.
fn plane_seed(base: &[u8], attempt: u32, k: usize, tag: u8, j: usize) -> Vec<u8> {
    let mut s = mask_seed(base, attempt, k, tag);
    s.extend_from_slice(&(j as u64).to_le_bytes());
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
        let mut maskings = Vec::with_capacity(SCALAR_ROUNDS);
        let mut rounds = Vec::with_capacity(SCALAR_ROUNDS);
        for k in 0..SCALAR_ROUNDS {
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
    if proof.rounds.len() != SCALAR_ROUNDS {
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

    /// Commit a family of planes, returning `(randomness, commitments)`.
    fn commit_all(params: &RingParams, planes: &[Poly], tag: &[u8]) -> (Vec<RingRandomness>, Vec<RingCommitment>) {
        let r: Vec<RingRandomness> = (0..planes.len())
            .map(|j| {
                let mut s = tag.to_vec();
                s.extend_from_slice(&(j as u64).to_le_bytes());
                RingRandomness::from_seed(&s)
            })
            .collect();
        let c = planes.iter().zip(&r).map(|(p, rj)| RingCommitment::commit_message(params, p, rj)).collect();
        (r, c)
    }

    #[test]
    fn an_aggregated_proof_covers_a_whole_family_of_planes() {
        let params = RingParams::standard();
        let planes: Vec<Poly> = (0..8u64).map(|j| binary_poly(0x9E37_79B9_7F4A_7C15 ^ (j << 3))).collect();
        let (r, c) = commit_all(&params, &planes, b"agg-happy");
        let proof = prove_binary_agg(&params, &planes, &r, b"seed").expect("aggregated binarity");
        assert!(verify_binary_agg(&params, &c, &proof), "every plane is binary");
        // Arity is bound: a family of a different size cannot ride this proof.
        assert!(!verify_binary_agg(&params, &c[..7], &proof), "the plane count is bound in");
        assert!(!verify_binary_agg(&params, &[], &proof), "an empty family is refused");
    }

    #[test]
    fn one_non_binary_plane_among_many_is_caught() {
        // The property the y-aggregation must preserve: a single bad plane cannot hide behind its binary siblings.
        // Its p∘(1−p) is nonzero, so Σ_j y^j·(p_j∘(1−p_j)) is a nonzero degree-<t polynomial in y — which a random
        // wide y annihilates only with probability ≤ (t−1)/q.
        let params = RingParams::standard();
        for bad_at in [0usize, 3, 7] {
            let planes: Vec<Poly> = (0..8usize)
                .map(|j| {
                    if j == bad_at {
                        let mut coeffs = [0u64; D];
                        coeffs[5] = 2; // not a bit
                        Poly::from_u64(&coeffs)
                    } else {
                        binary_poly(0xABCD_1234 ^ (j as u64))
                    }
                })
                .collect();
            let (r, c) = commit_all(&params, &planes, b"agg-bad");
            let proof = prove_binary_agg(&params, &planes, &r, b"seed").expect("proof emitted");
            assert!(!verify_binary_agg(&params, &c, &proof), "a non-binary plane at index {bad_at} is caught");
        }
    }

    #[test]
    fn the_aggregated_proof_is_smaller_than_one_proof_per_plane() {
        // The first rung of the compaction ladder (docs §6.1), as a measurement rather than a claim: the per-plane
        // c_d/c_e/z_de collapse into a single triple, and the ratio must not silently regress.
        use crate::ring_size::ProofSize;
        let params = RingParams::standard();
        let planes: Vec<Poly> = (0..16u64).map(|j| binary_poly(0x5555_AAAA ^ j)).collect();
        let (r, c) = commit_all(&params, &planes, b"agg-size");
        let agg = prove_binary_agg(&params, &planes, &r, b"seed").expect("aggregated");
        assert!(verify_binary_agg(&params, &c, &agg), "the aggregated proof is valid");
        // The un-aggregated cost of the same statement: one proof per plane.
        let one = prove_binary(&params, &planes[0], &r[0], b"seed").expect("single");
        let separate = planes.len() * one.ring_elements();
        assert!(
            agg.ring_elements() * 2 <= separate,
            "aggregation halves the binarity cost ({} vs {separate} elements)",
            agg.ring_elements()
        );
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
