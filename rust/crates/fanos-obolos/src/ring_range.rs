//! The **zero-knowledge range proof** over the ring-BDLOP commitment ([`crate::ring_commit`]): given a public
//! value commitment `C_v = com(v; r_v)`, prove `0 ≤ v < 2^bits` — *without revealing* `v`. This is the component
//! that makes confidential amounts **sound**: without it a transaction could commit a value near `q` that
//! represents a negative amount, satisfy the balance law modulo `q`, and forge money (audit O-C1). It composes
//! the [`crate::ring_product`] gadget with a linear reconstruction argument.
//!
//! ## Construction — bit decomposition, checked in zero knowledge
//!
//! Decompose `v = Σ_{i<bits} bᵢ·2ⁱ` and commit each bit `Cᵢ = com(bᵢ; rᵢ)`. Two things are proven:
//!
//! 1. **Binarity** — each `bᵢ ∈ {0,1}`, i.e. `bᵢ = bᵢ·bᵢ` (a value is idempotent iff it is `0` or `1`). This is
//!    exactly a [`ring_product`](crate::ring_product) proof with `x = y = z = bᵢ` against `Cᵢ`.
//! 2. **Reconstruction** — `Σ bᵢ·2ⁱ = v`, linking the bit commitments to `C_v`.
//!
//! Together they force `v = Σ bᵢ·2ⁱ` with every `bᵢ ∈ {0,1}` — precisely `v ∈ [0, 2^bits)`.
//!
//! ### The reconstruction argument, and why it fits `q`
//!
//! A homomorphic `Σ 2ⁱ·Cᵢ` would scale the randomness by `2ⁱ` — for `bits = 51` the opening randomness would
//! exceed `q`, so it cannot be proven short. Instead we mask and reveal `zᵢ = γ·bᵢ + aᵢ` (`aᵢ` uniform) and check
//! the reconstruction on the **revealed messages**: `Σ 2ⁱ·zᵢ = z_v` where `z_v = γ·v + a_v`, `a_v = Σ 2ⁱ·aᵢ`. The
//! `2ⁱ` weights touch only revealed polynomials — never the randomness — so each opening `r_{zᵢ} = γ·rᵢ + sᵢ`
//! stays short (`γ` a monomial), and binding holds. The commitment openings `com(zᵢ; r_{zᵢ}) = γ·Cᵢ + Aᵢ` bind
//! `zᵢ` to `Cᵢ`; a nonzero `Σ 2ⁱ·bᵢ − v` makes the linear-in-`γ` identity vanish only at a random monomial
//! (`≤ 1/2D` per round), driven to `≈ 2⁻¹²⁸` by [`REPETITIONS`](crate::ring_product::REPETITIONS) rounds.
//!
//! > **STATUS — [P]/[H], correctness-first.** Construction and soundness/ZK arguments are the security spec; the
//! > repetition count, masking bound, and challenge distribution are illustrative (calibration + audit pending),
//! > arithmetic is not constant-time. This proof is **not yet aggregated**: it is one product proof per bit plus a
//! > per-bit reconstruction round, so its size is `O(bits · REPETITIONS)` — correct and verifiable now, with
//! > batching the documented compactness optimisation. Tests verify completeness, soundness (an out-of-range value
//! > has no accepting proof), binding, and re-randomisation — never bit-security.

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

use crate::ring::{D, Poly};
use crate::ring_commit::{RingCommitment, RingParams, RingRandomness};
use crate::ring_product::{ACCEPT_LINEAR, MASK_BOUND, ProductProof, ProductWitness, REPETITIONS, prove_product, verify_product};

/// The range-proof width for an OBOLOS amount: `MAX_VALUE = 2⁵¹`, so a valid amount is a 51-bit non-negative
/// integer. Both parties agree on `bits` from context; the confidential-transaction layer passes this.
pub const RANGE_BITS: usize = 51;

/// A bound on resample attempts for the reconstruction argument (rejection is rare — the masking is wide).
const MAX_ATTEMPTS: u32 = 32;

/// `2ⁱ` as a constant ring element (`i < 63`).
fn pow2(i: usize) -> Poly {
    Poly::constant(1u64 << i)
}

/// The weighted sum `Σ 2ⁱ·termsᵢ` in `R_q` — the reconstruction combination, applied only to revealed messages.
fn weighted_sum(terms: &[Poly]) -> Poly {
    terms.iter().enumerate().fold(Poly::zero(), |acc, (i, t)| acc.add(&pow2(i).mul(t)))
}

/// Absorb a commitment into a Fiat–Shamir transcript.
fn absorb(buf: &mut Vec<u8>, c: &RingCommitment) {
    for p in c.t0().iter().chain(core::iter::once(c.t1())) {
        for &coeff in p.coeffs() {
            buf.extend_from_slice(&coeff.to_le_bytes());
        }
    }
}

/// A domain-separated masking seed `base ‖ attempt ‖ k ‖ tag`.
fn mask_seed(base: &[u8], attempt: u32, k: usize, tag: u16) -> Vec<u8> {
    let mut s = Vec::with_capacity(base.len() + 14);
    s.extend_from_slice(base);
    s.extend_from_slice(&attempt.to_le_bytes());
    s.extend_from_slice(&(k as u64).to_le_bytes());
    s.extend_from_slice(&tag.to_le_bytes());
    s
}

/// One reconstruction round: the masking commitments and the masked openings for every bit and for the value.
#[derive(Clone, PartialEq, Eq, Debug)]
struct ReconRound {
    a_bits: Vec<RingCommitment>, // Aᵢ = com(aᵢ)
    a_v: RingCommitment,         // A_v = com(Σ 2ⁱ aᵢ)
    z_bits: Vec<Poly>,           // zᵢ = γ·bᵢ + aᵢ
    z_v: Poly,                   // z_v = γ·v + a_v
    rz_bits: Vec<RingRandomness>,
    rz_v: RingRandomness,
}

/// The linear reconstruction proof that `Σ 2ⁱ·bᵢ = v`.
#[derive(Clone, PartialEq, Eq, Debug)]
struct ReconstructionProof {
    rounds: Vec<ReconRound>,
}

/// A zero-knowledge proof that a value commitment opens to some `v ∈ [0, 2^bits)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RangeProof {
    bits: usize,
    bit_commitments: Vec<RingCommitment>,
    binary_proofs: Vec<ProductProof>,
    reconstruction: ReconstructionProof,
}

/// The Fiat–Shamir seed for the reconstruction argument: the value commitment, the bit commitments, and every
/// round's masking commitments `(Aᵢ, A_v)`.
fn recon_seed<'a>(
    v_com: &RingCommitment,
    bit_coms: &[RingCommitment],
    aux: impl Iterator<Item = (&'a [RingCommitment], &'a RingCommitment)>,
) -> [u8; 32] {
    let mut buf = Vec::new();
    absorb(&mut buf, v_com);
    for c in bit_coms {
        absorb(&mut buf, c);
    }
    for (a_bits, a_v) in aux {
        for a in a_bits {
            absorb(&mut buf, a);
        }
        absorb(&mut buf, a_v);
    }
    let mut seed = [0u8; 32];
    hash_xof("FANOS-obolos-v1/ring-range-seed", &buf, &mut seed);
    seed
}

/// Round `k`'s monomial challenge.
fn round_challenge(seed: &[u8; 32], k: usize) -> Poly {
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(seed);
    input.extend_from_slice(&(k as u64).to_le_bytes());
    let mut out = [0u8; 8];
    hash_xof("FANOS-obolos-v1/ring-range-challenge", &input, &mut out);
    Poly::monomial((u64::from_le_bytes(out) % (2 * D as u64)) as usize)
}

/// Prove the reconstruction `Σ 2ⁱ·bᵢ = v`. `bit_msgs`/`r_bits` are the bit messages and randomness; `v`/`r_v` the
/// value's.
#[allow(clippy::too_many_arguments)]
fn prove_reconstruction(
    params: &RingParams,
    bit_msgs: &[Poly],
    r_bits: &[RingRandomness],
    bit_coms: &[RingCommitment],
    v: &Poly,
    r_v: &RingRandomness,
    v_com: &RingCommitment,
    seed: &[u8],
) -> Option<ReconstructionProof> {
    let n = bit_msgs.len();
    for attempt in 0..MAX_ATTEMPTS {
        // Sample every round's masking + commitments.
        struct Masking {
            a_bits: Vec<Poly>,
            a_v: Poly,
            s_bits: Vec<RingRandomness>,
            s_v: RingRandomness,
        }
        let mut maskings = Vec::with_capacity(REPETITIONS);
        let mut rounds_aux = Vec::with_capacity(REPETITIONS);
        for k in 0..REPETITIONS {
            let a_bits: Vec<Poly> =
                (0..n).map(|i| Poly::uniform(&mask_seed(seed, attempt, k, i as u16))).collect();
            let s_bits: Vec<RingRandomness> = (0..n)
                .map(|i| RingRandomness::from_uniform_bounded(&mask_seed(seed, attempt, k, (n + i) as u16), MASK_BOUND))
                .collect();
            let a_v = weighted_sum(&a_bits);
            let s_v = RingRandomness::from_uniform_bounded(&mask_seed(seed, attempt, k, (2 * n) as u16 + 1), MASK_BOUND);
            let a_bit_coms: Vec<RingCommitment> =
                a_bits.iter().zip(&s_bits).map(|(a, s)| RingCommitment::commit_message(params, a, s)).collect();
            let a_v_com = RingCommitment::commit_message(params, &a_v, &s_v);
            rounds_aux.push((a_bit_coms, a_v_com));
            maskings.push(Masking { a_bits, a_v, s_bits, s_v });
        }
        let seed_h = recon_seed(v_com, bit_coms, rounds_aux.iter().map(|(ab, av)| (ab.as_slice(), av)));

        let mut rounds = Vec::with_capacity(REPETITIONS);
        for (k, (m, (a_bit_coms, a_v_com))) in maskings.into_iter().zip(rounds_aux).enumerate() {
            let g = round_challenge(&seed_h, k);
            let z_bits: Vec<Poly> =
                bit_msgs.iter().zip(&m.a_bits).map(|(b, a)| g.mul(b).add(a)).collect();
            let z_v = g.mul(v).add(&m.a_v);
            let rz_bits: Vec<RingRandomness> =
                r_bits.iter().zip(&m.s_bits).map(|(r, s)| r.scale(&g).add(s)).collect();
            let rz_v = r_v.scale(&g).add(&m.s_v);
            let short = rz_bits.iter().all(|r| r.infinity_norm_le(ACCEPT_LINEAR)) && rz_v.infinity_norm_le(ACCEPT_LINEAR);
            if !short {
                rounds.clear();
                break;
            }
            rounds.push(ReconRound { a_bits: a_bit_coms, a_v: a_v_com, z_bits, z_v, rz_bits, rz_v });
        }
        if rounds.len() == REPETITIONS {
            return Some(ReconstructionProof { rounds });
        }
    }
    None
}

/// Verify a reconstruction proof against the public bit commitments and value commitment.
fn verify_reconstruction(
    params: &RingParams,
    bit_coms: &[RingCommitment],
    v_com: &RingCommitment,
    proof: &ReconstructionProof,
) -> bool {
    if proof.rounds.len() != REPETITIONS {
        return false;
    }
    let n = bit_coms.len();
    let seed_h = recon_seed(v_com, bit_coms, proof.rounds.iter().map(|r| (r.a_bits.as_slice(), &r.a_v)));
    for (k, rd) in proof.rounds.iter().enumerate() {
        if rd.a_bits.len() != n || rd.z_bits.len() != n || rd.rz_bits.len() != n {
            return false;
        }
        let g = round_challenge(&seed_h, k);
        // Each bit opening binds zᵢ to Cᵢ: com(zᵢ) = γ·Cᵢ + Aᵢ, with a short opening.
        for (((z, rz), c), a) in rd.z_bits.iter().zip(&rd.rz_bits).zip(bit_coms).zip(&rd.a_bits) {
            if !rz.infinity_norm_le(ACCEPT_LINEAR) {
                return false;
            }
            if RingCommitment::commit_message(params, z, rz) != c.scale(&g).add(a) {
                return false;
            }
        }
        // The value opening: com(z_v) = γ·C_v + A_v.
        if !rd.rz_v.infinity_norm_le(ACCEPT_LINEAR) {
            return false;
        }
        if RingCommitment::commit_message(params, &rd.z_v, &rd.rz_v) != v_com.scale(&g).add(&rd.a_v) {
            return false;
        }
        // The reconstruction, on the revealed messages: Σ 2ⁱ·zᵢ = z_v.
        if weighted_sum(&rd.z_bits) != rd.z_v {
            return false;
        }
    }
    true
}

/// Prove, in zero knowledge, that `value < 2^bits` (and `≥ 0`), against the commitment `com(value; r_value)`.
/// `None` only on the rare masking exhaustion of a sub-proof. `bits` must be `≤ 62` (so `2ⁱ` fits a coefficient).
#[must_use]
pub fn prove_range(
    params: &RingParams,
    value: u64,
    r_value: &RingRandomness,
    bits: usize,
    seed: &[u8],
) -> Option<RangeProof> {
    debug_assert!(bits <= 62, "2^bits must fit in a coefficient");
    let v_com = RingCommitment::commit_message(params, &Poly::constant(value), r_value);
    // Bit decomposition, each bit committed under its own ternary randomness.
    let bit_msgs: Vec<Poly> = (0..bits).map(|i| Poly::constant((value >> i) & 1)).collect();
    let r_bits: Vec<RingRandomness> = (0..bits)
        .map(|i| {
            let mut s = Vec::with_capacity(seed.len() + 8);
            s.extend_from_slice(seed);
            s.extend_from_slice(&(i as u64).to_le_bytes());
            RingRandomness::from_seed(&s)
        })
        .collect();
    let bit_commitments: Vec<RingCommitment> =
        bit_msgs.iter().zip(&r_bits).map(|(b, r)| RingCommitment::commit_message(params, b, r)).collect();

    // Binarity: bᵢ = bᵢ·bᵢ, one product proof per bit.
    let mut binary_proofs = Vec::with_capacity(bits);
    for (i, (b, r)) in bit_msgs.iter().zip(&r_bits).enumerate() {
        let witness = ProductWitness { x: b, rx: r, y: b, ry: r, z: b, rz: r };
        let mut bseed = Vec::with_capacity(seed.len() + 16);
        bseed.extend_from_slice(seed);
        bseed.extend_from_slice(b"/bin/");
        bseed.extend_from_slice(&(i as u64).to_le_bytes());
        binary_proofs.push(prove_product(params, &witness, &bseed)?);
    }

    // Reconstruction: Σ 2ⁱ·bᵢ = value.
    let mut rseed = Vec::with_capacity(seed.len() + 6);
    rseed.extend_from_slice(seed);
    rseed.extend_from_slice(b"/recon");
    let reconstruction = prove_reconstruction(
        params,
        &bit_msgs,
        &r_bits,
        &bit_commitments,
        &Poly::constant(value),
        r_value,
        &v_com,
        &rseed,
    )?;

    Some(RangeProof { bits, bit_commitments, binary_proofs, reconstruction })
}

/// Verify a [`prove_range`] proof that `value_commitment` opens to some `v ∈ [0, 2^bits)`.
#[must_use]
pub fn verify_range(params: &RingParams, value_commitment: &RingCommitment, proof: &RangeProof) -> bool {
    if proof.bit_commitments.len() != proof.bits || proof.binary_proofs.len() != proof.bits {
        return false;
    }
    // Every bit is binary: bᵢ = bᵢ·bᵢ.
    for (c, bin) in proof.bit_commitments.iter().zip(&proof.binary_proofs) {
        if !verify_product(params, c, c, c, bin) {
            return false;
        }
    }
    // And the bits reconstruct the committed value.
    verify_reconstruction(params, &proof.bit_commitments, value_commitment, &proof.reconstruction)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // A small width keeps the (unaggregated) proof fast; the construction is identical at RANGE_BITS.
    const TEST_BITS: usize = 6;

    fn value_commitment(params: &RingParams, value: u64, seed: &[u8]) -> (RingRandomness, RingCommitment) {
        let r = RingRandomness::from_seed(seed);
        let c = RingCommitment::commit_message(params, &Poly::constant(value), &r);
        (r, c)
    }

    #[test]
    fn an_in_range_value_proves_and_verifies() {
        let params = RingParams::standard();
        let (r, c) = value_commitment(&params, 45, b"range-happy"); // 45 < 64 = 2^6
        let proof = prove_range(&params, 45, &r, TEST_BITS, b"seed").expect("in range");
        assert!(verify_range(&params, &c, &proof), "45 ∈ [0, 64) verifies");
    }

    #[test]
    fn the_boundary_values_prove() {
        let params = RingParams::standard();
        for v in [0u64, 1, 63] {
            let (r, c) = value_commitment(&params, v, &[b'b', v as u8]);
            let proof = prove_range(&params, v, &r, TEST_BITS, b"seed").expect("boundary in range");
            assert!(verify_range(&params, &c, &proof), "boundary {v} verifies");
        }
    }

    #[test]
    fn an_out_of_range_value_has_no_accepting_proof() {
        // 64 = 2^6 needs a 7th bit. Decomposing it into 6 bits loses the high bit, so the 6-bit reconstruction
        // commits to 0, not 64 — the reconstruction proof cannot link the real C_v (=com 64) to those bits.
        let params = RingParams::standard();
        let (r, c) = value_commitment(&params, 64, b"range-oob");
        let proof = prove_range(&params, 64, &r, TEST_BITS, b"seed").expect("prover still emits");
        assert!(!verify_range(&params, &c, &proof), "64 ∉ [0, 64) is rejected");
    }

    #[test]
    fn a_proof_does_not_verify_against_a_different_commitment() {
        let params = RingParams::standard();
        let (r, _c) = value_commitment(&params, 20, b"range-bind");
        let proof = prove_range(&params, 20, &r, TEST_BITS, b"seed").unwrap();
        let (_r2, other) = value_commitment(&params, 20, b"different-randomness");
        assert!(!verify_range(&params, &other, &proof), "the value commitment is bound in");
    }

    #[test]
    fn a_tampered_bit_commitment_is_rejected() {
        let params = RingParams::standard();
        let (r, c) = value_commitment(&params, 30, b"range-tamper");
        let mut proof = prove_range(&params, 30, &r, TEST_BITS, b"seed").unwrap();
        // Replace a bit commitment with a commitment to 2 (not a bit): its binary proof no longer matches it.
        proof.bit_commitments[0] =
            RingCommitment::commit_message(&params, &Poly::constant(2), &RingRandomness::from_seed(b"x"));
        assert!(!verify_range(&params, &c, &proof), "a non-bit commitment fails its binary proof");
    }

    #[test]
    fn the_proof_is_re_randomised() {
        let params = RingParams::standard();
        let (r, c) = value_commitment(&params, 42 % (1 << TEST_BITS), b"range-zk");
        let p1 = prove_range(&params, 42 % (1 << TEST_BITS), &r, TEST_BITS, b"seed-a").unwrap();
        let p2 = prove_range(&params, 42 % (1 << TEST_BITS), &r, TEST_BITS, b"seed-b").unwrap();
        assert_ne!(p1, p2, "different seeds ⇒ different zero-knowledge proofs");
        assert!(verify_range(&params, &c, &p1) && verify_range(&params, &c, &p2));
    }
}
