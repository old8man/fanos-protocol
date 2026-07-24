//! The **zero-knowledge product proof** over the ring-BDLOP commitment ([`crate::ring_commit`]): given public
//! commitments `X, Y, Z`, prove knowledge of openings with `z = x·y` — *without revealing* `x, y, z` or their
//! randomness. This is the quadratic gadget the **range proof** composes: a bit is binary iff `b·(b−1) = 0`, and
//! a non-negativity witness is a sum of squares `Σ xᵢ² = v` — both are product relations.
//!
//! ## Construction — the Baum–BDLOP product argument with monomial challenges
//!
//! Blind each factor with a uniform masking message (`b1, b2`) and reveal the masked openings
//! `z1 = γ·x + b1`, `z2 = γ·y + b2` for a challenge `γ`. The algebraic core is the polynomial identity in `γ`
//!
//! ```text
//! z1·z2 = γ²·(x·y) + γ·(x·b2 + y·b1) + b1·b2  =  γ²·z + γ·t + u        (t = x·b2 + y·b1,  u = b1·b2)
//! ```
//! which holds **iff `z = x·y`**. The prover commits `t, u` (and the maskings `b1, b2`) up front; the verifier,
//! after deriving `γ`, checks three homomorphic openings:
//!
//! ```text
//! com(z1; r_z1) = γ·X + B1      com(z2; r_z2) = γ·Y + B2      com(z1·z2; s) = γ²·Z + γ·T + U
//! ```
//! with `r_z1 = γ·r_x + r_b1`, `r_z2 = γ·r_y + r_b2`, `s = γ²·r_z + γ·r_t + r_u`.
//!
//! **The monomial challenge is what makes this a *lattice* proof.** `γ` is drawn from `{X^m : 0 ≤ m < 2D}`
//! ([`Poly::monomial`]): every element is short *and* every difference is a unit ([`crate::ring`]). Multiplying a
//! short randomness by a monomial only permutes/negates its coefficients, so the revealed openings `r_z1, r_z2, s`
//! stay **short** — binding survives — while the challenge space `2D` is large and the extractor can divide by a
//! challenge difference. Three accepting transcripts under distinct `γ` interpolate the degree-2 identity and
//! extract an opening with `z = x·y`; forging needs the quadratic `γ²(xy − z) + … = 0` to vanish at a random
//! monomial, probability `≤ 2/(2D)` per round, driven to `≈ 2⁻¹²⁸` by [`REPETITIONS`] parallel rounds (bound
//! together under one Fiat–Shamir seed so a cheater cannot grind rounds independently).
//!
//! **Zero-knowledge.** `b1, b2` uniform over `R_q` perfectly hide `x, y` in `z1, z2`; the wide masking randomness
//! (`r_b1, r_b2, r_u`, bound `2²⁰ ≫ 1`) hides the short `r_x, r_y, r_z, r_t` in the revealed openings via
//! rejection sampling — the accept region is witness-independent.
//!
//! > **STATUS — [P]/[H], correctness-first (as the rest of the ring stack).** Construction and the
//! > soundness/ZK arguments are the security spec; [`REPETITIONS`], the masking bound, and the monomial challenge
//! > distribution are illustrative, not yet calibrated to a bit-security target nor externally cryptanalysed;
//! > arithmetic is not constant-time. Tests verify completeness, soundness (a wrong product has no accepting
//! > proof), binding/tamper rejection, and zero-knowledge re-randomisation — never bit-security.

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

use crate::ring::{D, Poly};
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};

/// The wide masking bound `2²⁰` for the revealed randomness openings — far above the short (`≤ 2`) witness
/// randomness they hide, and far below `q`, so binding holds and rejection almost never fires. Shared with the
/// linear-relation proof ([`crate::ring_linear`]).
pub(crate) const MASK_BOUND: i64 = 1 << 20;

/// Accept region for a linear opening `r_z = γ·r + r_b`: the hidden part `‖γ·r‖∞ ≤ 1`, so `‖r_z‖∞ ≤ B − 1`.
pub(crate) const ACCEPT_LINEAR: i64 = MASK_BOUND - 1;

/// Accept region for the product opening `s = γ²·r_z + γ·r_t + r_u`: the hidden part `‖γ²r_z + γr_t‖∞ ≤ 2`.
const ACCEPT_PRODUCT: i64 = MASK_BOUND - 2;

/// Parallel repetitions. Per-round soundness error `≤ 2/(2D) = 2⁻⁸`; `16` rounds target `≈ 2⁻¹²⁸`. Illustrative —
/// exact calibration (and a larger single-round challenge set) is the deferred heavy-artillery step.
pub const REPETITIONS: usize = 16;

/// A bound on resample attempts (with the wide masking, completeness needs `≈ 1`).
const MAX_ATTEMPTS: u32 = 32;

/// The prover's secret witness: the three messages and their commitment randomness, with `z = x·y`.
pub struct ProductWitness<'a> {
    /// The first factor and its randomness.
    pub x: &'a Poly,
    /// The first factor's commitment randomness.
    pub rx: &'a RingRandomness,
    /// The second factor and its randomness.
    pub y: &'a Poly,
    /// The second factor's commitment randomness.
    pub ry: &'a RingRandomness,
    /// The product `x·y` and its randomness.
    pub z: &'a Poly,
    /// The product's commitment randomness.
    pub rz: &'a RingRandomness,
}

/// The up-front commitments of one round: the two masking messages and the two cross-terms.
#[derive(Clone, PartialEq, Eq, Debug)]
struct RoundAux {
    b1: RingCommitment,
    b2: RingCommitment,
    t: RingCommitment,
    u: RingCommitment,
}

/// One parallel round: its up-front commitments and its masked responses.
#[derive(Clone, PartialEq, Eq, Debug)]
struct ProductRound {
    aux: RoundAux,
    z1: Poly,
    z2: Poly,
    r_z1: RingRandomness,
    r_z2: RingRandomness,
    s: RingRandomness,
}

/// A zero-knowledge proof that public commitments `X, Y, Z` open to `x, y, z` with `z = x·y`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProductProof {
    rounds: Vec<ProductRound>,
}

/// Absorb a commitment's polynomials into the Fiat–Shamir transcript.
fn absorb(buf: &mut Vec<u8>, c: &RingCommitment) {
    for p in c.t0().iter().chain(core::iter::once(c.t1())) {
        for &coeff in p.coeffs() {
            buf.extend_from_slice(&coeff.to_le_bytes());
        }
    }
}

/// The Fiat–Shamir seed binding the statement and *all* rounds' up-front commitments (so a cheater cannot grind
/// one round at a time).
fn challenge_seed<'a>(
    x: &RingCommitment,
    y: &RingCommitment,
    z: &RingCommitment,
    aux: impl Iterator<Item = &'a RoundAux>,
) -> [u8; 32] {
    let mut buf = Vec::new();
    absorb(&mut buf, x);
    absorb(&mut buf, y);
    absorb(&mut buf, z);
    for a in aux {
        absorb(&mut buf, &a.b1);
        absorb(&mut buf, &a.b2);
        absorb(&mut buf, &a.t);
        absorb(&mut buf, &a.u);
    }
    let mut seed = [0u8; 32];
    hash_xof("FANOS-obolos-v1/ring-product-seed", &buf, &mut seed);
    seed
}

/// Round `k`'s monomial challenge `X^m`, `m = H(seed ‖ k) mod 2D`.
fn round_challenge(seed: &[u8; 32], k: usize) -> Poly {
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(seed);
    input.extend_from_slice(&(k as u64).to_le_bytes());
    let mut out = [0u8; 8];
    hash_xof("FANOS-obolos-v1/ring-product-challenge", &input, &mut out);
    let idx = (u64::from_le_bytes(out) % (2 * D as u64)) as usize;
    Poly::monomial(idx)
}

/// A domain-separated masking seed `base ‖ attempt ‖ k ‖ tag`.
fn mask_seed(base: &[u8], attempt: u32, k: usize, tag: u8) -> Vec<u8> {
    let mut s = Vec::with_capacity(base.len() + 13);
    s.extend_from_slice(base);
    s.extend_from_slice(&attempt.to_le_bytes());
    s.extend_from_slice(&(k as u64).to_le_bytes());
    s.push(tag);
    s
}

/// Prove, in zero knowledge, that `witness.z = witness.x · witness.y` (as committed under `params`). `seed` seeds
/// the re-randomised masking; `None` only on the rare masking exhaustion.
#[must_use]
pub fn prove_product(params: &RingParams, witness: &ProductWitness<'_>, seed: &[u8]) -> Option<ProductProof> {
    let (x, y, z) = (witness.x, witness.y, witness.z);
    let cx = RingCommitment::commit_message(params, x, witness.rx);
    let cy = RingCommitment::commit_message(params, y, witness.ry);
    let cz = RingCommitment::commit_message(params, z, witness.rz);

    for attempt in 0..MAX_ATTEMPTS {
        // Sample every round's masking and up-front commitments.
        let mut maskings = Vec::with_capacity(REPETITIONS);
        let mut auxes = Vec::with_capacity(REPETITIONS);
        for k in 0..REPETITIONS {
            let b1 = Poly::uniform(&mask_seed(seed, attempt, k, 0));
            let b2 = Poly::uniform(&mask_seed(seed, attempt, k, 1));
            let r_b1 = RingRandomness::from_uniform_bounded(&mask_seed(seed, attempt, k, 2), MASK_BOUND);
            let r_b2 = RingRandomness::from_uniform_bounded(&mask_seed(seed, attempt, k, 3), MASK_BOUND);
            let r_t = RingRandomness::from_seed(&mask_seed(seed, attempt, k, 4)); // ternary, so γ·r_t stays tiny
            let r_u = RingRandomness::from_uniform_bounded(&mask_seed(seed, attempt, k, 5), MASK_BOUND);
            let t = x.mul(&b2).add(&y.mul(&b1)); // x·b2 + y·b1
            let u = b1.mul(&b2);
            let aux = RoundAux {
                b1: RingCommitment::commit_message(params, &b1, &r_b1),
                b2: RingCommitment::commit_message(params, &b2, &r_b2),
                t: RingCommitment::commit_message(params, &t, &r_t),
                u: RingCommitment::commit_message(params, &u, &r_u),
            };
            maskings.push((b1, b2, r_b1, r_b2, r_t, r_u));
            auxes.push(aux);
        }

        let seed_h = challenge_seed(&cx, &cy, &cz, auxes.iter());
        // Compute the responses; restart the whole attempt if any round's opening lands out of the accept region.
        let mut rounds = Vec::with_capacity(REPETITIONS);
        for (k, ((b1, b2, r_b1, r_b2, r_t, r_u), aux)) in maskings.into_iter().zip(auxes).enumerate() {
            let g = round_challenge(&seed_h, k);
            let gg = g.mul(&g);
            let z1 = g.mul(x).add(&b1);
            let z2 = g.mul(y).add(&b2);
            let r_z1 = witness.rx.scale(&g).add(&r_b1);
            let r_z2 = witness.ry.scale(&g).add(&r_b2);
            let s = witness.rz.scale(&gg).add(&r_t.scale(&g)).add(&r_u);
            if !r_z1.infinity_norm_le(ACCEPT_LINEAR)
                || !r_z2.infinity_norm_le(ACCEPT_LINEAR)
                || !s.infinity_norm_le(ACCEPT_PRODUCT)
            {
                rounds.clear();
                break;
            }
            rounds.push(ProductRound { aux, z1, z2, r_z1, r_z2, s });
        }
        if rounds.len() == REPETITIONS {
            return Some(ProductProof { rounds });
        }
    }
    None
}

/// Verify a [`prove_product`] proof that the public commitments `x_com, y_com, z_com` open to a product relation
/// `z = x·y`.
#[must_use]
pub fn verify_product(
    params: &RingParams,
    x_com: &RingCommitment,
    y_com: &RingCommitment,
    z_com: &RingCommitment,
    proof: &ProductProof,
) -> bool {
    if proof.rounds.len() != REPETITIONS {
        return false;
    }
    let seed_h = challenge_seed(x_com, y_com, z_com, proof.rounds.iter().map(|r| &r.aux));
    for (k, rd) in proof.rounds.iter().enumerate() {
        // The revealed openings must be short (binding), else a long opening could satisfy the algebra vacuously.
        if !rd.r_z1.infinity_norm_le(ACCEPT_LINEAR)
            || !rd.r_z2.infinity_norm_le(ACCEPT_LINEAR)
            || !rd.s.infinity_norm_le(ACCEPT_PRODUCT)
        {
            return false;
        }
        let g = round_challenge(&seed_h, k);
        let gg = g.mul(&g);
        // Linear openings: com(z1) = γ·X + B1, com(z2) = γ·Y + B2.
        if RingCommitment::commit_message(params, &rd.z1, &rd.r_z1) != x_com.scale(&g).add(&rd.aux.b1) {
            return false;
        }
        if RingCommitment::commit_message(params, &rd.z2, &rd.r_z2) != y_com.scale(&g).add(&rd.aux.b2) {
            return false;
        }
        // The product identity: com(z1·z2) = γ²·Z + γ·T + U.
        let lhs = RingCommitment::commit_message(params, &rd.z1.mul(&rd.z2), &rd.s);
        let rhs = z_com.scale(&gg).add(&rd.aux.t.scale(&g)).add(&rd.aux.u);
        if lhs != rhs {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Commit `x, y, z=x·y` (constant-polynomial scalars) and return the commitments + a witness's parts.
    fn scalar_product(
        x: u64,
        y: u64,
    ) -> (RingParams, Poly, RingRandomness, Poly, RingRandomness, Poly, RingRandomness) {
        let params = RingParams::standard();
        let (px, py, pz) = (Poly::constant(x), Poly::constant(y), Poly::constant(x.wrapping_mul(y)));
        let rx = RingRandomness::from_seed(b"prod-rx");
        let ry = RingRandomness::from_seed(b"prod-ry");
        let rz = RingRandomness::from_seed(b"prod-rz");
        (params, px, rx, py, ry, pz, rz)
    }

    #[test]
    fn an_honest_product_proof_verifies() {
        let (params, x, rx, y, ry, z, rz) = scalar_product(6, 7); // 6·7 = 42
        let w = ProductWitness { x: &x, rx: &rx, y: &y, ry: &ry, z: &z, rz: &rz };
        let proof = prove_product(&params, &w, b"seed").expect("honest product proof");
        let cx = RingCommitment::commit_message(&params, &x, &rx);
        let cy = RingCommitment::commit_message(&params, &y, &ry);
        let cz = RingCommitment::commit_message(&params, &z, &rz);
        assert!(verify_product(&params, &cx, &cy, &cz, &proof), "6·7 = 42 verifies");
    }

    #[test]
    fn a_ring_product_proof_verifies() {
        // Not just scalars: a genuine polynomial product x·y in R_q.
        let params = RingParams::standard();
        let x = Poly::uniform(b"px");
        let y = Poly::uniform(b"py");
        let z = x.mul(&y);
        let (rx, ry, rz) = (
            RingRandomness::from_seed(b"rrx"),
            RingRandomness::from_seed(b"rry"),
            RingRandomness::from_seed(b"rrz"),
        );
        let w = ProductWitness { x: &x, rx: &rx, y: &y, ry: &ry, z: &z, rz: &rz };
        let proof = prove_product(&params, &w, b"seed").expect("honest");
        let cx = RingCommitment::commit_message(&params, &x, &rx);
        let cy = RingCommitment::commit_message(&params, &y, &ry);
        let cz = RingCommitment::commit_message(&params, &z, &rz);
        assert!(verify_product(&params, &cx, &cy, &cz, &proof), "a real ring product verifies");
    }

    #[test]
    fn a_wrong_product_has_no_accepting_proof() {
        // Commit z' = xy + 1 (not the product). The prover can still emit a proof, but it cannot verify against
        // the (correctly committed) false Z — and a prover who lies about z in the witness produces an internally
        // inconsistent transcript the verifier rejects.
        let (params, x, rx, y, ry, _z, rz) = scalar_product(6, 7);
        let z_bad = Poly::constant(43); // 6·7 + 1
        let w = ProductWitness { x: &x, rx: &rx, y: &y, ry: &ry, z: &z_bad, rz: &rz };
        let proof = prove_product(&params, &w, b"seed").expect("proof emitted");
        let cx = RingCommitment::commit_message(&params, &x, &rx);
        let cy = RingCommitment::commit_message(&params, &y, &ry);
        let cz_bad = RingCommitment::commit_message(&params, &z_bad, &rz);
        assert!(!verify_product(&params, &cx, &cy, &cz_bad, &proof), "z = xy+1 is not a product");
    }

    #[test]
    fn a_proof_does_not_verify_against_a_different_statement() {
        let (params, x, rx, y, ry, z, rz) = scalar_product(6, 7);
        let w = ProductWitness { x: &x, rx: &rx, y: &y, ry: &ry, z: &z, rz: &rz };
        let proof = prove_product(&params, &w, b"seed").unwrap();
        let cx = RingCommitment::commit_message(&params, &x, &rx);
        let cz = RingCommitment::commit_message(&params, &z, &rz);
        // Swap Y for a commitment to a different factor: the linear opening check fails.
        let cy_other = RingCommitment::commit_message(&params, &Poly::constant(8), &ry);
        assert!(!verify_product(&params, &cx, &cy_other, &cz, &proof), "the statement is bound in");
    }

    #[test]
    fn a_tampered_round_is_rejected() {
        let (params, x, rx, y, ry, z, rz) = scalar_product(9, 9); // 81
        let w = ProductWitness { x: &x, rx: &rx, y: &y, ry: &ry, z: &z, rz: &rz };
        let mut proof = prove_product(&params, &w, b"seed").unwrap();
        let cx = RingCommitment::commit_message(&params, &x, &rx);
        let cy = RingCommitment::commit_message(&params, &y, &ry);
        let cz = RingCommitment::commit_message(&params, &z, &rz);
        // Perturb one response coefficient: its opening no longer matches γ·X + B1.
        let mut c = proof.rounds[0].z1.coeffs().to_vec();
        c[0] = crate::ring::fadd(c[0], 1);
        proof.rounds[0].z1 = Poly::from_u64(&c.try_into().unwrap());
        assert!(!verify_product(&params, &cx, &cy, &cz, &proof), "a perturbed response fails");
    }

    #[test]
    fn the_proof_is_re_randomised_but_both_verify() {
        let (params, x, rx, y, ry, z, rz) = scalar_product(6, 7);
        let w = ProductWitness { x: &x, rx: &rx, y: &y, ry: &ry, z: &z, rz: &rz };
        let p1 = prove_product(&params, &w, b"seed-a").unwrap();
        let p2 = prove_product(&params, &w, b"seed-b").unwrap();
        assert_ne!(p1, p2, "different masking seeds ⇒ different (zero-knowledge) proofs");
        let cx = RingCommitment::commit_message(&params, &x, &rx);
        let cy = RingCommitment::commit_message(&params, &y, &ry);
        let cz = RingCommitment::commit_message(&params, &z, &rz);
        assert!(verify_product(&params, &cx, &cy, &cz, &p1));
        assert!(verify_product(&params, &cx, &cy, &cz, &p2));
    }
}
