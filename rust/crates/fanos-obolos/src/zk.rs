//! The **zero-knowledge engine** for OBOLOS — a lattice Σ-protocol proving *knowledge of a short opening* of a
//! value commitment without revealing it (`spec/platform.md` §4.3). This is the primitive the confidential-
//! transaction proofs are built from: the balance proof (the difference commitment opens to zero under a short
//! `r_balance` the prover never reveals) and, next, the range proof both reduce to "I know a short `r` with
//! `M·r = u`" for the shared commitment map `M = [A₁; a₂]`.
//!
//! ## Construction — Fiat–Shamir with aborts (Lyubashevsky)
//!
//! To prove knowledge of a short `r ∈ Z^L` with `M·r ≡ u (mod q)`, without leaking `r`, over `κ` parallel rounds:
//!
//! 1. **Commit.** For each round `i`, sample a *masking* `y_i ∈ [−B, B]^L` and send `w_i = M·y_i mod q`.
//! 2. **Challenge.** `c = H(u ‖ w_0 ‖ … ‖ w_{κ−1})` — one bit `c_i ∈ {0,1}` per round (Fiat–Shamir, non-interactive).
//! 3. **Respond.** `z_i = y_i + c_i·r`. **Reject** (resample everything) if any `z_i` coefficient leaves the safe
//!    region `[−(B−1), B−1]`; the acceptance region is exactly the intersection of the `c_i·r ∈ {−1,0,1}` shifts,
//!    so an accepted `z_i` is uniform there **independently of `r`** — that is the zero-knowledge (the transcript
//!    is simulatable from the public `(u, w_i, c_i)` alone).
//!
//! The proof is `(c, z_0..z_{κ−1})`; the verifier recomputes `w_i = M·z_i − c_i·u mod q` (which equals `M·y_i`
//! since `u = M·r`), checks `H(u ‖ w…) = c`, and checks every `‖z_i‖∞ ≤ B−1`.
//!
//! - **Completeness.** An honest prover's `z_i` lands in the safe region with per-round probability
//!   `((2B−1)/(2B+1))^L`; with `B ≫ L` the whole proof succeeds after ≈1 resample.
//! - **Special-soundness (knowledge).** Two accepting transcripts `(z_i, z_i')` that differ in `c_i` (so
//!   `c_i − c_i' = ±1`) yield `M·(z_i − z_i') = (c_i − c_i')·u`, i.e. `r* = ±(z_i − z_i')` is a preimage
//!   `M·r* = u` with `‖r*‖∞ ≤ 2(B−1)`. A cheating prover with no such preimage guesses each `c_i` with
//!   probability ½, so forges with probability `2^{−κ}`. (The extracted `r*` is short only up to the masking
//!   slack `2(B−1)`, the standard lattice-ZK gap: binding must hold at that norm, not just at ternary — the
//!   parameters must be calibrated for it, see the STATUS note.)
//!
//! > **STATUS — [P]/[H], calibration + audit pending (as [`crate::commit`]).** The *construction* is standard
//! > (Fiat–Shamir with aborts) and the completeness/soundness/ZK arguments above are the security spec; the
//! > concrete `(κ, B)` here are illustrative and **not yet calibrated to a bit-security target**, the masking is
//! > sampled with a negligible-but-nonzero modular bias, and arithmetic is not constant-time. This is a correct,
//! > tested *reference* of the right primitive (the vector-setting proof is deliberately uncompressed — a compact
//! > ring-BDLOP instantiation is the same future upgrade `commit` notes). The tests verify **completeness,
//! > knowledge (extraction), and that cheating proofs fail**, never bit-security.

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

use crate::commit::{Commitment, L, N, Params, Randomness, rem};

/// Soundness repetitions: a cheating prover forges with probability `2^{−KAPPA}` (one honest-verifier bit per
/// round). `128` targets 128-bit knowledge soundness.
pub const KAPPA: usize = 128;

/// The masking half-width `B`: each round's `y ∈ [−B, B]^L`. Chosen `≫ L` so the per-round abort probability is
/// tiny and the whole proof succeeds after ≈1 resample, while keeping `M·y` (`L` terms of `≈2⁶¹·B`) inside `i128`.
pub const MASK_BOUND: i64 = 1 << 16;

/// Domain-separation label for the Fiat–Shamir challenge hash.
const FS_LABEL: &str = "FANOS-obolos-v1/zk-opening-challenge";
/// Domain-separation label for deriving the per-round masking vectors from the prover's seed.
const MASK_LABEL: &str = "FANOS-obolos-v1/zk-opening-mask";
/// A bound on resample attempts — completeness needs ≈1, so exceeding this signals a parameter error, not a
/// normal event. The prover returns `None` rather than loop forever.
const MAX_ATTEMPTS: u32 = 64;

/// A zero-knowledge proof of knowledge of a short opening: the `κ`-bit challenge and the `κ` masked responses.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpeningProof {
    /// The `κ` challenge bits, packed (`KAPPA / 8` bytes).
    challenge: Vec<u8>,
    /// The `κ` response vectors, each `L` coefficients in `[−(B−1), B−1]`.
    z: Vec<Vec<i64>>,
}

/// The public statement bytes `u = (t0, t1 − value)` — the `N + 1` coefficients a short `r` maps to under `M`,
/// canonically encoded for the Fiat–Shamir transcript (little-endian `i64`).
fn statement(commitment: &Commitment, value: u64) -> Vec<i64> {
    // `commitment` opens to `value` under `r` iff `M·r = (t0, t1 − value)`.
    let mut u: Vec<i64> = commitment.t0_ref().to_vec();
    u.push(rem(i128::from(commitment.t1_of()) - i128::from(value)));
    u
}

/// The `i`-th challenge bit of a packed challenge.
#[inline]
fn bit(challenge: &[u8], i: usize) -> i64 {
    i64::from((challenge.get(i / 8).copied().unwrap_or(0) >> (i % 8)) & 1)
}

/// Fiat–Shamir: hash the statement and all round commitments to the `κ`-bit challenge.
fn fiat_shamir(u: &[i64], w: &[Vec<i64>]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity((u.len() + w.len() * (N + 1)) * 8);
    for &x in u {
        transcript.extend_from_slice(&x.to_le_bytes());
    }
    for wi in w {
        for &x in wi {
            transcript.extend_from_slice(&x.to_le_bytes());
        }
    }
    let mut out = alloc::vec![0u8; KAPPA / 8];
    hash_xof(FS_LABEL, &transcript, &mut out);
    out
}

/// Derive one round's masking vector `y ∈ [−B, B]^L` deterministically from the prover's `seed`, `attempt`, and
/// round index. Uses 4 bytes per coefficient reduced into `[−B, B]` (a negligible modular bias, tolerable for
/// the *masking* — it is re-randomised every attempt and never revealed; see the STATUS note).
fn mask(seed: &[u8], attempt: u32, round: usize) -> Vec<i64> {
    let mut input = Vec::with_capacity(seed.len() + 12);
    input.extend_from_slice(seed);
    input.extend_from_slice(&attempt.to_le_bytes());
    input.extend_from_slice(&(round as u64).to_le_bytes());
    let mut bytes = alloc::vec![0u8; L * 4];
    hash_xof(MASK_LABEL, &input, &mut bytes);
    let span = 2 * MASK_BOUND + 1;
    let (words, _) = bytes.as_chunks::<4>();
    words.iter().take(L).map(|c| i64::from(u32::from_le_bytes(*c)) % span - MASK_BOUND).collect()
}

/// Prove knowledge of the short randomness `r` opening `commitment` to `value`, without revealing `r`. `seed`
/// seeds the (re-randomised, never-revealed) masking; distinct seeds give distinct proofs of the same statement.
/// `None` only if the masking never lands in the safe region within [`MAX_ATTEMPTS`] — a parameter error, not a
/// normal outcome (completeness needs ≈1 attempt).
#[must_use]
pub fn prove_opening(params: &Params, commitment: &Commitment, value: u64, r: &Randomness, seed: &[u8]) -> Option<OpeningProof> {
    let u = statement(commitment, value);
    let r = r.coeffs_ref();
    for attempt in 0..MAX_ATTEMPTS {
        let y: Vec<Vec<i64>> = (0..KAPPA).map(|i| mask(seed, attempt, i)).collect();
        let w: Vec<Vec<i64>> = y.iter().map(|yi| params.m_times(yi)).collect();
        let challenge = fiat_shamir(&u, &w);
        let mut z = Vec::with_capacity(KAPPA);
        let mut ok = true;
        for (i, yi) in y.iter().enumerate() {
            let ci = bit(&challenge, i);
            let zi: Vec<i64> = yi.iter().zip(r).map(|(y, rr)| y + ci * rr).collect();
            // Reject unless every coefficient is in the r-independent safe region — the zero-knowledge gate.
            if zi.iter().any(|&c| c.abs() >= MASK_BOUND) {
                ok = false;
                break;
            }
            z.push(zi);
        }
        if ok {
            return Some(OpeningProof { challenge, z });
        }
    }
    None
}

/// Verify a [`prove_opening`] proof that `commitment` opens to `value` under *some* short randomness.
#[must_use]
pub fn verify_opening(params: &Params, commitment: &Commitment, value: u64, proof: &OpeningProof) -> bool {
    if proof.z.len() != KAPPA || proof.challenge.len() != KAPPA / 8 {
        return false;
    }
    let u = statement(commitment, value);
    let mut w = Vec::with_capacity(KAPPA);
    for (i, zi) in proof.z.iter().enumerate() {
        if zi.len() != L || zi.iter().any(|&c| c.abs() >= MASK_BOUND) {
            return false; // wrong shape, or a response outside the norm bound
        }
        // w_i = M·z_i − c_i·u mod q  (= M·y_i for an honest transcript, since u = M·r).
        let ci = bit(&proof.challenge, i);
        let mzi = params.m_times(zi);
        let wi: Vec<i64> =
            mzi.iter().zip(&u).map(|(&m, &uj)| rem(i128::from(m) - i128::from(ci) * i128::from(uj))).collect();
        w.push(wi);
    }
    // The Fiat–Shamir challenge must be exactly the one that binds these commitments.
    fiat_shamir(&u, &w) == proof.challenge
}

impl OpeningProof {
    /// Canonical bytes: the packed challenge, then `κ·L` little-endian `i64` responses.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KAPPA / 8 + KAPPA * L * 8);
        out.extend_from_slice(&self.challenge);
        for zi in &self.z {
            for &c in zi {
                out.extend_from_slice(&c.to_le_bytes());
            }
        }
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` on the wrong length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KAPPA / 8 + KAPPA * L * 8 {
            return None;
        }
        let challenge = bytes.get(..KAPPA / 8)?.to_vec();
        let (coeffs, _) = bytes.get(KAPPA / 8..)?.as_chunks::<8>();
        let (rows, _) = coeffs.as_chunks::<L>();
        let z: Vec<Vec<i64>> =
            rows.iter().map(|row| row.iter().map(|c| i64::from_le_bytes(*c)).collect()).collect();
        if z.len() != KAPPA {
            return None;
        }
        Some(Self { challenge, z })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn setup(value: u64, seed: &[u8]) -> (Params, Commitment, Randomness) {
        let params = Params::standard();
        let r = Randomness::from_seed(seed);
        let commitment = Commitment::commit(&params, value, &r);
        (params, commitment, r)
    }

    #[test]
    fn an_honest_opening_proof_verifies_and_hides_the_randomness() {
        let (params, commitment, r) = setup(42, b"zk-happy");
        let proof = prove_opening(&params, &commitment, 42, &r, b"proof-seed").expect("honest proof");
        assert!(verify_opening(&params, &commitment, 42, &proof), "an honest opening proof verifies");
        // Different masking seed ⇒ a different transcript for the SAME statement (the proof is randomised).
        let proof2 = prove_opening(&params, &commitment, 42, &r, b"other-seed").expect("honest proof");
        assert_ne!(proof.to_bytes(), proof2.to_bytes(), "the proof is re-randomised, not deterministic in the witness");
        assert!(verify_opening(&params, &commitment, 42, &proof2));
    }

    #[test]
    fn a_proof_for_the_wrong_value_or_commitment_is_rejected() {
        let (params, commitment, r) = setup(100, b"zk-wrong");
        let proof = prove_opening(&params, &commitment, 100, &r, b"seed").unwrap();
        // Right proof, wrong claimed value ⇒ the statement u = (t0, t1 − value) changes, Fiat–Shamir mismatches.
        assert!(!verify_opening(&params, &commitment, 101, &proof), "the value is bound into the statement");
        // Right proof, a different commitment ⇒ rejected.
        let other = Commitment::commit(&params, 100, &Randomness::from_seed(b"different-r"));
        assert!(!verify_opening(&params, &other, 100, &proof), "the commitment is bound into the statement");
    }

    #[test]
    fn a_tampered_response_is_rejected() {
        let (params, commitment, r) = setup(7, b"zk-tamper");
        let mut proof = prove_opening(&params, &commitment, 7, &r, b"seed").unwrap();
        // Flip one response coefficient: w_i changes, so the recomputed Fiat–Shamir challenge no longer matches.
        proof.z[0][0] += 1;
        assert!(!verify_opening(&params, &commitment, 7, &proof), "a tampered response fails Fiat–Shamir");
        // An out-of-bound response is rejected on the norm check alone.
        let mut huge = prove_opening(&params, &commitment, 7, &r, b"seed").unwrap();
        huge.z[1][2] = MASK_BOUND; // == bound ⇒ outside [−(B−1), B−1]
        assert!(!verify_opening(&params, &commitment, 7, &huge), "a response at/over the bound is rejected");
    }

    #[test]
    fn special_soundness_extracts_the_short_opening() {
        // The knowledge guarantee, empirically. Special-soundness rewinds ONE round to the SAME commitment
        // w = M·y and answers both challenges: c=0 gives z0 = y, c=1 gives z1 = y + r. Their difference is
        // exactly the witness, and M·(z1 − z0) = u — the extractor recovers a genuine short preimage. (This is
        // the interactive property Fiat–Shamir compiles away; two *independent* non-interactive proofs have
        // different w, so they cannot be subtracted — the extractor needs the shared first message.)
        let (params, commitment, r) = setup(2024, b"zk-extract");
        let u = statement(&commitment, 2024);
        let y = mask(b"round-mask", 0, 0);
        let z0 = y.clone(); // response to challenge bit 0
        let z1: Vec<i64> = y.iter().zip(r.coeffs_ref()).map(|(a, b)| a + b).collect(); // response to bit 1
        let r_star: Vec<i64> = z1.iter().zip(&z0).map(|(a, b)| a - b).collect();
        assert_eq!(r_star, r.coeffs_ref(), "z1 − z0 recovers exactly the witness r");
        let m = params.m_times(&r_star);
        assert!(m.iter().zip(&u).all(|(&mj, &uj)| rem(i128::from(mj)) == uj), "extractor: M·r* = u");
        assert!(r_star.iter().all(|&c| c.abs() <= 1), "the extracted opening is short (ternary here)");
    }

    #[test]
    fn a_forged_proof_without_a_witness_is_rejected() {
        // A prover who does not know a short opening cannot pass: pick arbitrary in-bound responses and any
        // challenge; the verifier recomputes w = M·z − c·u and hashes it, and that hash (with overwhelming
        // probability, 2^−128) is not the challenge in the proof — Fiat–Shamir rejects.
        let (params, commitment, _r) = setup(9, b"zk-forge");
        let mut bytes = alloc::vec![0u8; KAPPA / 8]; // an all-zero challenge
        for i in 0..KAPPA {
            for j in 0..L {
                bytes.extend_from_slice(&(((i * 7 + j * 3) % 11) as i64 - 5).to_le_bytes()); // arbitrary in-bound z
            }
        }
        let forged = OpeningProof::from_bytes(&bytes).expect("well-formed shape");
        assert!(!verify_opening(&params, &commitment, 9, &forged), "a witness-free proof fails Fiat–Shamir");
    }

    #[test]
    fn the_proof_round_trips_through_its_bytes() {
        let (params, commitment, r) = setup(555, b"zk-codec");
        let proof = prove_opening(&params, &commitment, 555, &r, b"seed").unwrap();
        let back = OpeningProof::from_bytes(&proof.to_bytes()).expect("round-trips");
        assert_eq!(back, proof);
        assert!(verify_opening(&params, &commitment, 555, &back));
        assert!(OpeningProof::from_bytes(&proof.to_bytes()[..proof.to_bytes().len() - 1]).is_none(), "truncation rejected");
    }
}
