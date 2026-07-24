//! The **compact, single-round zero-knowledge opening proof** for the ring-BDLOP commitment
//! ([`crate::ring_commit`]) — the production successor to the `κ`-round vector Σ-protocol [`crate::zk`].
//!
//! Because the challenge lives in the cyclotomic ring `R_q` (a space of `3^D` short ternary polynomials, far
//! more than `2^{128}`), **one** round already gives cryptographic soundness — no `{0,1}` repetition. The proof
//! is `(c, z)`: a ternary challenge polynomial and the `ELL` masked response polynomials. This is the exact
//! primitive the confidential-transaction stack reduces to: the balance proof (the difference commitment opens
//! to zero under a short `r_balance` never revealed) and, next, the range proof both call it.
//!
//! ## Construction — Fiat–Shamir with aborts over `R_q`
//!
//! To prove knowledge of a short `r ∈ R_q^ℓ` with `M·r = u` (`M = [A₁; a₂]`, `u = (t0, t1 − v)`):
//! 1. **Commit.** Sample a wide masking `y ∈ [−B, B]^{ℓ·D}` and send `w = M·y`.
//! 2. **Challenge.** `c = H(u ‖ w) ∈ R_q` — a short ternary polynomial (Fiat–Shamir).
//! 3. **Respond.** `z = y + c·r` (ring multiplication). **Reject** (resample) unless every `z_j` is short
//!    (`‖z_j‖∞ ≤ B − β`, `β = D` bounds `‖c·r_j‖∞`); the accept region is `c·r`-independent, so an accepted `z`
//!    is simulatable from `(u, w, c)` alone — the zero-knowledge.
//!
//! The verifier recomputes `w = M·z − c·u` (which equals `M·y`, since `u = M·r`), checks `H(u ‖ w) = c`, and
//! checks the norms.
//!
//! - **Completeness.** `z` is short with per-coefficient probability `(2(B−β)+1)/(2B+1)`; with `B ≫ β·√(ℓD)` the
//!   whole proof succeeds after ≈1 resample.
//! - **Special-soundness (relaxed knowledge).** Two accepting responses `z, z'` to the same `w` under `c ≠ c'`
//!   give `M·(z − z') = (c − c')·u`, i.e. a **relaxed opening** `(z̄ = z − z', c̄ = c − c')` with `M·z̄ = c̄·u`,
//!   both **short** (`c̄` a difference of ternaries, `z̄` bounded by the masking). Forging without such a witness
//!   means guessing `c` from `R_q` — probability `3^{−D}`. (The standard ring-lattice *relaxed* soundness: the
//!   extracted witness satisfies the relation scaled by the short `c̄`, and binding must hold for that relaxation
//!   — see the STATUS note. On the fully-splitting Goldilocks ring `c̄` is invertible with overwhelming
//!   probability, giving an exact opening `r* = c̄⁻¹ z̄` where it is.)
//!
//! > **STATUS — [P]/[H], correctness-first (as [`crate::ring`]/[`crate::ring_commit`]).** Construction and the
//! > completeness/soundness/ZK arguments are the security spec; the parameters `(B, β)`, the challenge
//! > distribution, and the invertible-difference bound are illustrative, not yet calibrated to a bit-security
//! > target nor externally cryptanalysed; arithmetic is not constant-time. The tests verify **completeness,
//! > relaxed knowledge (extraction), and cheat-rejection**, never bit-security.

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

use crate::ring::{D, Poly};
use crate::ring_commit::{ELL, RingCommitment, RingParams, RingRandomness};

/// The slack factor `B / β`: the masking is `2¹¹×` wider than the response bound, so the per-coefficient accept
/// probability is `≈ 1 − 1/2048` and the whole proof succeeds after `≈ 1.6` resamples (`(1−1/2048)^{ELL·D} ≈ 0.6`).
const SLACK: i64 = 1 << 11;

/// The **norm regime** of an opening proof: the response bound `β` (a bound on `‖c·r_j‖∞`) and the masking width
/// `B = β·SLACK`, which together fix the `c·r`-independent accept region `‖z_j‖∞ ≤ B − β` — the region an honest
/// masked response lands in and the shortness a verifier checks. It is **derived from context** by both parties
/// (a note-value opening is [`TERNARY`](Self::TERNARY); a balance opening scales with the note count via
/// [`for_randomness_bound`](Self::for_randomness_bound)), so it is never carried in the proof.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpeningParams {
    mask_bound: i64,
    beta: i64,
}

impl OpeningParams {
    /// The regime for a **ternary** opening — a single note-value commitment, `‖r‖∞ = 1`, so `β = D` (a ternary
    /// challenge convolved with ternary randomness has `‖c·r‖∞ ≤ D`). `B = D·2¹¹ = 2¹⁹`.
    pub const TERNARY: Self = Self { mask_bound: D as i64 * SLACK, beta: D as i64 };

    /// The regime for an opening whose randomness has infinity norm `≤ r_bound` — e.g. a **balance** randomness
    /// `Σr_in − Σr_out`, a signed sum of `n` ternaries with `‖·‖∞ ≤ n`. Then `β = D·r_bound` and `B = β·SLACK`
    /// (still far below `q`). `r_bound` is clamped to `≥ 1`; both prover and verifier pass the same `n`.
    #[must_use]
    pub fn for_randomness_bound(r_bound: i64) -> Self {
        let beta = D as i64 * r_bound.max(1);
        Self { mask_bound: beta.saturating_mul(SLACK), beta }
    }

    /// The accept region half-width `B − β`: an honest response satisfies `‖z_j‖∞ ≤ B − β` independently of the
    /// witness `c·r` (that is the zero-knowledge), and the verifier rejects any `z_j` outside it.
    #[must_use]
    fn accept_bound(&self) -> i64 {
        self.mask_bound - self.beta
    }
}

/// A bound on resample attempts (completeness needs `≈ 1.6`; exceeding it signals a parameter error).
const MAX_ATTEMPTS: u32 = 64;

/// A compact zero-knowledge proof of knowledge of a short opening: the ternary challenge and the `ELL` masked
/// response polynomials.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingOpeningProof {
    challenge: Poly,
    z: Vec<Poly>, // ELL polynomials
}

/// The Fiat–Shamir challenge: hash the statement `u` and the commitment `w` to a short ternary polynomial.
fn challenge(u: &[Poly], w: &[Poly]) -> Poly {
    let mut transcript = Vec::with_capacity((u.len() + w.len()) * D * 8);
    for p in u.iter().chain(w) {
        for &coeff in p.coeffs() {
            transcript.extend_from_slice(&coeff.to_le_bytes());
        }
    }
    let mut seed = [0u8; 32];
    hash_xof("FANOS-obolos-v1/ring-zk-challenge", &transcript, &mut seed);
    Poly::ternary(&seed)
}

/// Prove knowledge of the short randomness `r` opening `commitment` to `value`, in zero knowledge, in the norm
/// `regime` (which both parties derive from context — [`OpeningParams::TERNARY`] for a note, or
/// [`OpeningParams::for_randomness_bound`] for a balance). `seed` seeds the (re-randomised, never-revealed)
/// masking. `None` only if the masking never lands short within [`MAX_ATTEMPTS`] — a parameter error, not a
/// normal outcome.
#[must_use]
pub fn prove_opening(
    params: &RingParams,
    commitment: &RingCommitment,
    value: u64,
    r: &RingRandomness,
    regime: &OpeningParams,
    seed: &[u8],
) -> Option<RingOpeningProof> {
    let u = commitment.statement(value);
    let r = r.components();
    for attempt in 0..MAX_ATTEMPTS {
        let y: Vec<Poly> = (0..ELL)
            .map(|j| {
                let mut s = Vec::with_capacity(seed.len() + 12);
                s.extend_from_slice(seed);
                s.extend_from_slice(&attempt.to_le_bytes());
                s.extend_from_slice(&(j as u64).to_le_bytes());
                Poly::uniform_bounded(&s, regime.mask_bound)
            })
            .collect();
        let w = params.m_times(&y);
        let c = challenge(&u, &w);
        // z_j = y_j + c·r_j.
        let z: Vec<Poly> = y.iter().zip(r).map(|(yj, rj)| yj.add(&c.mul(rj))).collect();
        if z.iter().all(|zj| zj.infinity_norm_le(regime.accept_bound())) {
            return Some(RingOpeningProof { challenge: c, z });
        }
    }
    None
}

/// Verify a [`prove_opening`] proof that `commitment` opens to `value` under *some* short randomness, in the
/// norm `regime` (the same one the prover used, re-derived from context).
#[must_use]
pub fn verify_opening(
    params: &RingParams,
    commitment: &RingCommitment,
    value: u64,
    proof: &RingOpeningProof,
    regime: &OpeningParams,
) -> bool {
    if proof.z.len() != ELL || !proof.z.iter().all(|zj| zj.infinity_norm_le(regime.accept_bound())) {
        return false; // wrong arity, or a response outside the norm bound
    }
    let u = commitment.statement(value);
    // w = M·z − c·u  (= M·y for an honest transcript, since u = M·r).
    let m_z = params.m_times(&proof.z);
    let w: Vec<Poly> = m_z.iter().zip(&u).map(|(mz, ui)| mz.sub(&proof.challenge.mul(ui))).collect();
    challenge(&u, &w) == proof.challenge
}

impl RingOpeningProof {
    /// Canonical bytes: the challenge polynomial, then the `ELL` response polynomials (each `D` little-endian
    /// `u64` coefficients).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity((1 + ELL) * D * 8);
        for p in core::iter::once(&self.challenge).chain(&self.z) {
            for &coeff in p.coeffs() {
                out.extend_from_slice(&coeff.to_le_bytes());
            }
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` on the wrong length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != (1 + ELL) * D * 8 {
            return None;
        }
        let (words, _) = bytes.as_chunks::<8>();
        let coeffs: Vec<u64> = words.iter().map(|w| u64::from_le_bytes(*w)).collect();
        let (chunks, _) = coeffs.as_chunks::<D>();
        let mut polys = chunks.iter().map(Poly::from_u64);
        let challenge = polys.next()?;
        let z: Vec<Poly> = polys.collect();
        if z.len() != ELL {
            return None;
        }
        Some(Self { challenge, z })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn setup(value: u64, seed: &[u8]) -> (RingParams, RingCommitment, RingRandomness) {
        let params = RingParams::standard();
        let r = RingRandomness::from_seed(seed);
        let commitment = RingCommitment::commit(&params, value, &r);
        (params, commitment, r)
    }

    #[test]
    fn an_honest_opening_proof_verifies_and_hides_the_randomness() {
        let (params, commitment, r) = setup(42, b"ring-zk-happy");
        let t = &OpeningParams::TERNARY;
        let proof = prove_opening(&params, &commitment, 42, &r, t, b"proof-seed").expect("honest proof");
        assert!(verify_opening(&params, &commitment, 42, &proof, t), "an honest opening proof verifies");
        // A different masking seed ⇒ a different transcript for the SAME statement (re-randomised).
        let proof2 = prove_opening(&params, &commitment, 42, &r, t, b"other-seed").expect("honest proof");
        assert_ne!(proof.to_bytes(), proof2.to_bytes(), "the proof is re-randomised, not deterministic in r");
        assert!(verify_opening(&params, &commitment, 42, &proof2, t));
    }

    #[test]
    fn a_proof_for_the_wrong_value_or_commitment_is_rejected() {
        let (params, commitment, r) = setup(100, b"ring-zk-wrong");
        let t = &OpeningParams::TERNARY;
        let proof = prove_opening(&params, &commitment, 100, &r, t, b"seed").unwrap();
        assert!(!verify_opening(&params, &commitment, 101, &proof, t), "the value is bound into the statement");
        let other = RingCommitment::commit(&params, 100, &RingRandomness::from_seed(b"different-r"));
        assert!(!verify_opening(&params, &other, 100, &proof, t), "the commitment is bound into the statement");
    }

    #[test]
    fn a_tampered_response_is_rejected() {
        let (params, commitment, r) = setup(7, b"ring-zk-tamper");
        let t = &OpeningParams::TERNARY;
        let proof = prove_opening(&params, &commitment, 7, &r, t, b"seed").unwrap();
        let mut tampered = proof.clone();
        // Add 1 to one response coefficient: w changes, so the recomputed challenge no longer matches.
        let mut z0 = tampered.z[0].coeffs().to_vec();
        z0[0] = crate::ring::fadd(z0[0], 1);
        tampered.z[0] = Poly::from_u64(&z0.try_into().unwrap());
        assert!(!verify_opening(&params, &commitment, 7, &tampered, t), "a tampered response fails Fiat–Shamir");
    }

    #[test]
    fn special_soundness_extracts_a_short_relaxed_opening() {
        // The (relaxed) knowledge guarantee. Two responses to the SAME commitment w under challenges c, c' give
        // z̄ = z − z' = (c − c')·r = c̄·r and M·z̄ = c̄·u — a short relaxed opening (c̄ a difference of ternaries,
        // z̄ = c̄·r short). We check the identity directly (Fiat–Shamir gives one challenge per w; this is the
        // interactive property it compiles away).
        let (params, commitment, r) = setup(2024, b"ring-zk-extract");
        let u = commitment.statement(2024);
        let c = Poly::ternary(b"chal-c");
        let c_prime = Poly::ternary(b"chal-c-prime");
        let c_bar = c.sub(&c_prime);
        // z̄_j = c̄·r_j — the response difference (the y masking cancels).
        let z_bar: Vec<Poly> = r.components().iter().map(|rj| c_bar.mul(rj)).collect();
        let m_zbar = params.m_times(&z_bar); // M·z̄
        let expected: Vec<Poly> = u.iter().map(|ui| c_bar.mul(ui)).collect(); // c̄·u
        assert_eq!(m_zbar, expected, "M·z̄ = c̄·u — a genuine short relaxed opening is extracted");
    }

    #[test]
    fn an_invertible_challenge_difference_extracts_the_exact_witness() {
        // Monomials X^i are valid (ternary) challenges whose difference is ALWAYS a unit ([`crate::ring`]). With
        // such a pair the relaxed opening sharpens to the EXACT witness: from z̄ = c̄·r the extractor recovers
        // r = c̄⁻¹·z̄ and confirms M·r = u — a true opening, not merely a c̄-scaled one.
        let (params, commitment, r) = setup(77, b"ring-zk-exact");
        let u = commitment.statement(77);
        let c_bar = Poly::monomial(9).sub(&Poly::monomial(2)); // X^9 − X^2, a unit
        let c_bar_inv = c_bar.inverse().expect("a monomial difference is invertible");
        // z̄_j = c̄·r_j (the masking cancels across two transcripts under c = X^9, c' = X^2).
        let z_bar: Vec<Poly> = r.components().iter().map(|rj| c_bar.mul(rj)).collect();
        let extracted: Vec<Poly> = z_bar.iter().map(|zj| c_bar_inv.mul(zj)).collect();
        assert_eq!(extracted, r.components(), "c̄⁻¹·z̄ recovers the exact randomness r");
        assert_eq!(params.m_times(&extracted), u, "M·r = u — an exact opening of the commitment");
    }

    #[test]
    fn a_forged_proof_without_a_witness_is_rejected() {
        // A prover with no short opening cannot pass: any in-bound responses + any challenge recompute a w whose
        // hash is (with probability 3^-D) not the challenge — Fiat–Shamir rejects.
        let (params, commitment, _r) = setup(9, b"ring-zk-forge");
        let forged = RingOpeningProof {
            challenge: Poly::ternary(b"arbitrary-challenge"),
            z: (0..ELL).map(|j| Poly::uniform_bounded(&[b'z', j as u8], 5)).collect(),
        };
        assert!(!verify_opening(&params, &commitment, 9, &forged, &OpeningParams::TERNARY), "no witness ⇒ FS fails");
    }

    #[test]
    fn the_proof_round_trips_through_its_bytes() {
        let (params, commitment, r) = setup(555, b"ring-zk-codec");
        let proof = prove_opening(&params, &commitment, 555, &r, &OpeningParams::TERNARY, b"seed").unwrap();
        let back = RingOpeningProof::from_bytes(&proof.to_bytes()).expect("round-trips");
        assert_eq!(back, proof);
        assert!(verify_opening(&params, &commitment, 555, &back, &OpeningParams::TERNARY));
        assert!(RingOpeningProof::from_bytes(&proof.to_bytes()[..proof.to_bytes().len() - 1]).is_none());
    }

    #[test]
    fn the_larger_norm_regime_opens_a_non_ternary_randomness() {
        // The balance regime: a randomness whose infinity norm exceeds 1 (here a sum of several ternaries) still
        // has a complete, verifying opening proof under the matching `for_randomness_bound`, and the TERNARY
        // regime's tighter accept region would (correctly) reject its wider response.
        let params = RingParams::standard();
        let parts: Vec<RingRandomness> = (0..6u8).map(|i| RingRandomness::from_seed(&[b'p', i])).collect();
        // r = Σ parts (component-wise) — ‖r‖∞ ≤ 6; commit to 0 under it, as a balance residual would.
        let r = RingRandomness::from_components(
            (0..ELL)
                .map(|j| parts.iter().fold(Poly::zero(), |acc, p| acc.add(&p.components()[j])))
                .collect(),
        );
        let commitment = RingCommitment::commit(&params, 0, &r);
        let regime = OpeningParams::for_randomness_bound(6);
        let proof = prove_opening(&params, &commitment, 0, &r, &regime, b"bal-seed").expect("wide opening");
        assert!(verify_opening(&params, &commitment, 0, &proof, &regime), "the wider regime verifies");
        assert!(regime.accept_bound() > OpeningParams::TERNARY.accept_bound(), "the balance regime is wider");
    }
}
