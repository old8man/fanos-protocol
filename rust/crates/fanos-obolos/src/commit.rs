//! The **additively-homomorphic value commitment** — how OBOLOS hides amounts while keeping the ledger's
//! balance law checkable (`spec/platform.md` §4.1). A note's amount `v` is committed as `com(v; r)`, binding
//! (you cannot open it to a different amount) and hiding (the amount is invisible without `r`), and — the
//! load-bearing property — **additively homomorphic**: `com(v₁; r₁) + com(v₂; r₂) = com(v₁+v₂; r₁+r₂)`. That
//! is what lets a validator verify `Σ inputs = Σ outputs + fee` on the *commitments alone*, never seeing an
//! amount, so confidential transactions are sound.
//!
//! The construction is **BDLOP-style** (Baum–Damgård–Lyubashevsky–Oechsner–Peikert), the modern lattice
//! commitment: over `Z_q` with a public random matrix `A₁` and vector `a₂` (a nothing-up-my-sleeve common
//! reference string, [`Params::standard`]) and *short* (ternary) randomness `r`,
//!
//! ```text
//! com(v; r) = ( t0 = A₁·r mod q ,  t1 = ⟨a₂, r⟩ + v mod q )
//! ```
//!
//! - **Hiding** reduces to **decisional Module-LWE**: `(A₁·r, ⟨a₂, r⟩)` is pseudorandom for short `r`, so `t1`
//!   masks `v` — and because hiding is *computational* (not leftover-hash), short randomness suffices (no
//!   entropy blow-up).
//! - **Binding** reduces to **Module-SIS** on `A₁`: two openings `(v, r) ≠ (v', r')` with short `r, r'` give a
//!   short kernel vector `r − r'` of `A₁` (if `r ≠ r'`), else `v = v'`. Forging a second opening solves SIS.
//! - **Homomorphic** by construction: the two components are linear in `(v, r)`, so commitments add.
//!
//! > **STATUS — [P]/[H], calibration + audit pending (as `fanos-vrf::rlwe`).** The *construction* is standard
//! > and the *reductions* above are the security spec; the concrete parameters ([`Q`], [`N`], [`L`]) are
//! > illustrative and **not yet calibrated to a bit-security target, nor externally cryptanalysed**. Ternary
//! > sampling is not rejection-perfect and the modular reduction is `%` (not constant-time). This is a correct,
//! > tested *reference* of the right primitive — production needs calibrated `(N, L, q)`, a compact ring-BDLOP
//! > instantiation (the 2 KB commitment here is the honest uncompressed cost), and audit. The tests here verify
//! > **correctness** (homomorphism, opening, the balance identity), never security.

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

/// The modulus — the Mersenne prime `2⁶¹ − 1`. The message space is `Z_q`; amounts live in `0..MAX_VALUE`
/// with `MAX_VALUE ≪ q`, leaving ample room for homomorphic sums (a whole transaction's worth of inputs) to
/// not wrap modulo `q` — the precondition for the balance law to hold over the integers.
pub const Q: i128 = (1 << 61) - 1;

/// The Module-SIS/LWE dimension (rows of `A₁`, length of `t0`).
pub const N: usize = 128;

/// The randomness length (columns of `A₁`, length of `a₂` and of `r`). `L > N` gives `A₁` a high-dimensional
/// kernel, the regime where Module-SIS binding is hard.
pub const L: usize = 256;

/// The maximum representable amount (`2⁵¹`): a supply ceiling comfortably below `q` with room for the sums a
/// transaction's balance check forms. A range proof (the frontier ZK component) enforces `v < MAX_VALUE`.
pub const MAX_VALUE: u64 = 1 << 51;

/// The domain-separation seed for the canonical common reference string (the public `A₁`, `a₂`).
const CRS_LABEL: &str = "FANOS-obolos-v1/commit-crs";
/// The domain-separation label for deriving commitment randomness from a seed.
const RAND_LABEL: &str = "FANOS-obolos-v1/commit-rand";

/// Reduce a wide accumulator into the canonical range `[0, q)`.
#[inline]
#[must_use]
fn rem(x: i128) -> i64 {
    let r = ((x % Q) + Q) % Q;
    r as i64
}

/// The public parameters (common reference string): the random `A₁ ∈ Z_q^{N×L}` (row-major) and `a₂ ∈ Z_q^L`.
/// Deterministic from a seed, so every party shares the *same* public commitment key ([`standard`](Self::standard)).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Params {
    a1: Vec<i64>, // N * L, row-major
    a2: Vec<i64>, // L
}

impl Params {
    /// The canonical parameters — the common reference string every OBOLOS participant uses.
    #[must_use]
    pub fn standard() -> Self {
        Self::from_seed(b"FANOS-obolos-v1/standard-crs")
    }

    /// Parameters derived deterministically from `seed` (a nothing-up-my-sleeve public matrix; a tiny modular
    /// bias in these *public* values is harmless — they are not secret).
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut bytes = alloc::vec![0u8; (N * L + L) * 8];
        hash_xof(CRS_LABEL, seed, &mut bytes);
        let (words, _) = bytes.as_chunks::<8>();
        let uniform = |chunk: &[u8; 8]| -> i64 { rem(i128::from(u64::from_le_bytes(*chunk))) };
        let a1: Vec<i64> = words.iter().take(N * L).map(uniform).collect();
        let a2: Vec<i64> = words.iter().skip(N * L).take(L).map(uniform).collect();
        Self { a1, a2 }
    }
}

/// Short (ternary, `{−1, 0, 1}^L`) commitment randomness — the hiding secret of a commitment. Kept so the
/// owner can later open the note, and so a transaction can derive its balance randomness `Σr_in − Σr_out`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Randomness {
    coeffs: Vec<i64>, // L, each in {-1, 0, 1}
}

impl Randomness {
    /// Deterministic ternary randomness from `seed` (rejection-sampled to `{−1, 0, 1}` without the modulo bias
    /// of a raw byte).
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        // Draw generously and reject bytes ≥ 252 (= 84·3) so the remaining map uniformly to {0,1,2}.
        let mut coeffs = Vec::with_capacity(L);
        let mut round: u64 = 0;
        while coeffs.len() < L {
            let mut block = [0u8; 256];
            let mut salted = Vec::with_capacity(seed.len() + 8);
            salted.extend_from_slice(seed);
            salted.extend_from_slice(&round.to_le_bytes());
            hash_xof(RAND_LABEL, &salted, &mut block);
            for &b in &block {
                if coeffs.len() == L {
                    break;
                }
                if b < 252 {
                    coeffs.push(i64::from(b % 3) - 1);
                }
            }
            round += 1;
        }
        Self { coeffs }
    }

    /// The sum `r₁ + r₂` in **centered** (small-integer) representation — used to form a transaction's balance
    /// randomness `Σr_in − Σr_out`. Coefficients are kept small (not reduced mod `q`) — they stay bounded by
    /// the number of terms (a transaction's input+output count), which is exactly the shortness the frontier
    /// range proof bounds, and keeps `A₁·r` well within `i128` during commitment.
    #[must_use]
    pub(crate) fn add(&self, other: &Self) -> Self {
        let coeffs = self.coeffs.iter().zip(&other.coeffs).map(|(a, b)| a + b).collect();
        Self { coeffs }
    }

    /// The centered difference `r₁ − r₂` — the other half of a transaction's balance randomness.
    #[must_use]
    pub(crate) fn sub(&self, other: &Self) -> Self {
        let coeffs = self.coeffs.iter().zip(&other.coeffs).map(|(a, b)| a - b).collect();
        Self { coeffs }
    }
}

/// A value commitment `(t0, t1)` — hiding the amount, binding, and additively homomorphic.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Commitment {
    t0: Vec<i64>, // N
    t1: i64,
}

impl Commitment {
    /// Commit to `value` under randomness `r`: `(A₁·r, ⟨a₂, r⟩ + value) mod q`.
    #[must_use]
    pub fn commit(params: &Params, value: u64, r: &Randomness) -> Self {
        let (rows, _) = params.a1.as_chunks::<L>();
        let t0: Vec<i64> = rows
            .iter()
            .map(|row| rem(row.iter().zip(&r.coeffs).map(|(a, x)| i128::from(*a) * i128::from(*x)).sum()))
            .collect();
        let dot: i128 = params.a2.iter().zip(&r.coeffs).map(|(a, x)| i128::from(*a) * i128::from(*x)).sum();
        let t1 = rem(dot + i128::from(value));
        Self { t0, t1 }
    }

    /// The commitment to a **public** amount with zero randomness: `com(value; 0) = (0, value)`. The fee (a
    /// public quantity) enters the balance law through this.
    #[must_use]
    pub fn public_value(value: u64) -> Self {
        Self { t0: alloc::vec![0i64; N], t1: rem(i128::from(value)) }
    }

    /// The homomorphic sum `self + other = com(v_self + v_other; r_self + r_other)`.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let t0 = self.t0.iter().zip(&other.t0).map(|(a, b)| rem(i128::from(*a) + i128::from(*b))).collect();
        Self { t0, t1: rem(i128::from(self.t1) + i128::from(other.t1)) }
    }

    /// The homomorphic difference `self − other`.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        let t0 = self.t0.iter().zip(&other.t0).map(|(a, b)| rem(i128::from(*a) - i128::from(*b))).collect();
        Self { t0, t1: rem(i128::from(self.t1) - i128::from(other.t1)) }
    }

    /// Whether `(value, r)` is a valid opening of this commitment — the binding check.
    #[must_use]
    pub fn opens_to(&self, params: &Params, value: u64, r: &Randomness) -> bool {
        self == &Self::commit(params, value, r)
    }

    /// Canonical bytes: `t0` (`N` little-endian `i64`) followed by `t1`. Used to bind a value commitment into a
    /// note commitment and to carry it on the wire.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity((N + 1) * 8);
        for &x in &self.t0 {
            out.extend_from_slice(&x.to_le_bytes());
        }
        out.extend_from_slice(&self.t1.to_le_bytes());
        out
    }
}

/// The homomorphic sum of a list of commitments (`com(Σv; Σr)`), or the commitment to zero with zero
/// randomness for an empty list.
#[must_use]
pub fn sum(commitments: &[Commitment]) -> Commitment {
    commitments.iter().fold(Commitment::public_value(0), |acc, c| acc.add(c))
}

/// The homomorphic sum of a list of randomness values — a transaction's balance randomness is
/// `Σ r_inputs − Σ r_outputs`, which opens the balanced difference commitment to zero.
#[must_use]
pub fn sum_randomness(rs: &[Randomness]) -> Randomness {
    rs.iter().skip(1).fold(rs.first().cloned().unwrap_or_else(zero_randomness), |acc, r| acc.add(r))
}

/// The all-zero randomness (the opening of a public-value commitment).
#[must_use]
fn zero_randomness() -> Randomness {
    Randomness { coeffs: alloc::vec![0i64; L] }
}

/// Verify the **balance law** of a shielded transfer on the commitments alone (amounts never revealed):
/// `Σ input_commitments = Σ output_commitments + com(fee; 0) + com(0; r_balance)`, i.e. the difference
/// `Σin − Σout − com(fee)` opens to **zero** under `r_balance`. A production proof supplies `r_balance` in
/// zero-knowledge together with a proof that it is short; here it is checked in the clear.
///
/// Soundness: because the commitment is binding, a transaction whose amounts do *not* satisfy
/// `Σ v_in = Σ v_out + fee` cannot produce any `r_balance` opening the difference to zero — so it cannot
/// inflate the supply.
#[must_use]
pub fn verify_balance(
    params: &Params,
    inputs: &[Commitment],
    outputs: &[Commitment],
    fee: u64,
    r_balance: &Randomness,
) -> bool {
    let diff = sum(inputs).sub(&sum(outputs)).sub(&Commitment::public_value(fee));
    diff.opens_to(params, 0, r_balance)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn rand(tag: &[u8]) -> Randomness {
        Randomness::from_seed(tag)
    }

    #[test]
    fn randomness_is_ternary_and_full_length() {
        let r = rand(b"r1");
        assert_eq!(r.coeffs.len(), L);
        assert!(r.coeffs.iter().all(|&c| (-1..=1).contains(&c)), "randomness is ternary");
        // Deterministic.
        assert_eq!(r, rand(b"r1"));
        assert_ne!(r, rand(b"r2"), "a different seed gives different randomness");
    }

    #[test]
    fn the_commitment_is_additively_homomorphic() {
        let p = Params::standard();
        let (r1, r2) = (rand(b"a"), rand(b"b"));
        let (v1, v2) = (1_000u64, 2_500u64);
        let lhs = Commitment::commit(&p, v1, &r1).add(&Commitment::commit(&p, v2, &r2));
        let rhs = Commitment::commit(&p, v1 + v2, &r1.add(&r2));
        assert_eq!(lhs, rhs, "com(v1;r1) + com(v2;r2) = com(v1+v2; r1+r2)");
    }

    #[test]
    fn opening_binds_the_value_and_randomness() {
        let p = Params::standard();
        let r = rand(b"open");
        let c = Commitment::commit(&p, 42, &r);
        assert!(c.opens_to(&p, 42, &r), "the true opening verifies");
        assert!(!c.opens_to(&p, 43, &r), "a wrong amount does not open");
        assert!(!c.opens_to(&p, 42, &rand(b"other")), "wrong randomness does not open");
    }

    #[test]
    fn a_balanced_transfer_verifies_and_an_inflating_one_does_not() {
        let p = Params::standard();
        // Inputs 700 + 500 = 1200; outputs 900 + 250 = 1150; fee 50 → balances (1200 = 1150 + 50).
        let (ri0, ri1) = (rand(b"i0"), rand(b"i1"));
        let (ro0, ro1) = (rand(b"o0"), rand(b"o1"));
        let inputs = [Commitment::commit(&p, 700, &ri0), Commitment::commit(&p, 500, &ri1)];
        let outputs = [Commitment::commit(&p, 900, &ro0), Commitment::commit(&p, 250, &ro1)];
        let r_balance = sum_randomness(&[ri0.clone(), ri1.clone()]).add(&negate(&sum_randomness(&[ro0.clone(), ro1.clone()])));
        assert!(verify_balance(&p, &inputs, &outputs, 50, &r_balance), "a conserving transfer balances on commitments alone");
        // An inflating transfer (outputs 900 + 400, same inputs+fee) cannot balance under ANY provided opening.
        let bad_outputs = [Commitment::commit(&p, 900, &ro0), Commitment::commit(&p, 400, &ro1)];
        assert!(!verify_balance(&p, &inputs, &bad_outputs, 50, &r_balance), "an inflating transfer fails the balance law");
    }

    /// Coefficient-wise negation in centered form — the `−Σr_out` half of the balance randomness (test helper).
    fn negate(r: &Randomness) -> Randomness {
        Randomness { coeffs: r.coeffs.iter().map(|c| -c).collect() }
    }

    #[test]
    fn hiding_two_amounts_under_different_randomness_gives_different_commitments() {
        let p = Params::standard();
        // The same amount under different randomness commits differently (hiding is randomised).
        assert_ne!(Commitment::commit(&p, 5, &rand(b"h1")), Commitment::commit(&p, 5, &rand(b"h2")));
    }
}
