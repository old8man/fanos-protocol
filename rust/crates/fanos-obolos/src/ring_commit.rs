//! The compact **ring-BDLOP value commitment** (`spec/platform.md` §4.1) — the production successor to the flat
//! `Z_q`-vector [`crate::commit`]. Over the cyclotomic ring `R_q = Z_q[X]/(X^D + 1)` ([`crate::ring`]) a whole
//! Module-SIS/LWE commitment is a handful of ring elements, and — the real prize — its zero-knowledge proofs are
//! single-round with polynomial challenges (the large challenge space `R_q` gives negligible soundness error in
//! ONE shot), retiring the `κ`-round `{0,1}` blow-up of the vector-setting [`crate::zk`].
//!
//! An amount `v` is committed as
//!
//! ```text
//! t0 = A₁ · r        (K ring elements — the binding part, Module-SIS on A₁)
//! t1 = ⟨a₂, r⟩ + v   (1 ring element — the message part; v embedded as a constant polynomial)
//! ```
//!
//! with short (ternary) randomness `r ∈ R_q^ℓ`. It is:
//! - **Binding** ← Module-SIS on `[A₁; a₂] ∈ R_q^{(K+1)×ℓ}`: two openings with short `r ≠ r'` give a short kernel
//!   element, i.e. a Module-SIS solution.
//! - **Hiding** ← decisional Module-LWE: `(A₁·r, ⟨a₂,r⟩)` is pseudorandom for short `r`, masking `v`.
//! - **Additively homomorphic**: every component is `R_q`-linear in `(v, r)`, and because `v` lives in the
//!   *constant coefficient* with `q ≫ MAX_VALUE`, the message terms add as **integers** — so a validator checks
//!   `Σ v_in = Σ v_out + fee` on the commitments alone, exactly as the vector form did.
//!
//! > **STATUS — [P]/[H], calibration + audit pending (as [`crate::commit`] / [`crate::ring`]).** Construction and
//! > reductions are the security spec; the ranks `(K, ℓ)` and the ring `(D, q)` are illustrative, not yet
//! > calibrated to a bit-security target nor externally cryptanalysed. The tests verify **correctness**
//! > (homomorphism, opening, the balance identity), never security.

use alloc::vec::Vec;

use crate::ring::{Poly, Q};

/// Binding rows: `t0` is `K` ring elements (`K·D` Module-SIS rows).
pub const K: usize = 1;
/// Randomness rank: `r` is `ELL` ring elements (`ELL·D` Module-SIS columns).
pub const ELL: usize = 4;

/// The amount ceiling `2⁵¹` — comfortably below `q = 2⁶⁴ − 2³² + 1`, so a transaction's homomorphic sums stay in
/// a single coefficient without wrapping (a range proof enforces `v < MAX_VALUE`; see [`RANGE_BITS`]).
pub const MAX_VALUE: u64 = 1 << 51;

/// The **protocol range width** every shielded amount is proven to — `log₂(MAX_VALUE)`, so a range proof at this
/// width is exactly the statement `v < MAX_VALUE`.
///
/// This is a *constant*, not a parameter, and that is load-bearing (audit O-C1). The aggregated range proof
/// ([`crate::ring_range_agg`]) carries its width inside the proof object, so if a verifier trusted that field the
/// **prover** would choose the bound: with `bits = 62`, four outputs each just under `2⁶²` sum to `q + ε`, which is
/// `≡ ε (mod q)` — they balance against an input worth `ε` while being worth `≈2⁶⁴` in the pool. Consensus therefore
/// pins the width here rather than accepting a per-call argument, and the verifier rejects any proof whose declared
/// width differs. Together with [`MAX_NOTES_PER_TX`] and the same bound on the cleartext fee, no side of the balance
/// law can reach `q`.
pub const RANGE_BITS: usize = 51;

const _: () = assert!(MAX_VALUE == 1 << RANGE_BITS, "RANGE_BITS must be exactly log2(MAX_VALUE)");

/// The maximum value-bearing notes per transaction — **derived**, not chosen: every homomorphic sum must stay
/// below `q` over the integers or a wrap forges value (audit O-C1). `⌊q / MAX_VALUE⌋ − 2` with `q ≈ 2⁶⁴`,
/// `MAX_VALUE = 2⁵¹` leaves `≈ 8189`.
pub const MAX_NOTES_PER_TX: usize = ((Q / MAX_VALUE) - 2) as usize;

/// The public parameters (common reference string): the binding matrix `A₁ ∈ R_q^{K×ℓ}` (row-major) and the
/// message row `a₂ ∈ R_q^ℓ`. Deterministic from a seed — a nothing-up-my-sleeve public key every party shares.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingParams {
    a1: Vec<Poly>, // K * ELL, row-major
    a2: Vec<Poly>, // ELL
}

impl RingParams {
    /// The canonical parameters every OBOLOS participant uses.
    #[must_use]
    pub fn standard() -> Self {
        Self::from_seed(b"FANOS-obolos-v1/ring-commit-crs")
    }

    /// Parameters derived deterministically from `seed` (public; a tiny sampling bias in these public values is
    /// harmless — they are not secret).
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        let poly = |tag: &str, i: usize| {
            let mut s = Vec::with_capacity(seed.len() + tag.len() + 8);
            s.extend_from_slice(seed);
            s.extend_from_slice(tag.as_bytes());
            s.extend_from_slice(&(i as u64).to_le_bytes());
            Poly::uniform(&s)
        };
        let a1 = (0..K * ELL).map(|i| poly("/A1", i)).collect();
        let a2 = (0..ELL).map(|i| poly("/a2", i)).collect();
        Self { a1, a2 }
    }

    /// `A₁ · r` — the `K` binding ring elements. `r` must have length `ELL`.
    fn a1_times(&self, r: &[Poly]) -> Vec<Poly> {
        self.a1
            .chunks(ELL)
            .map(|row| row.iter().zip(r).fold(Poly::zero(), |acc, (a, rj)| acc.add(&a.mul(rj))))
            .collect()
    }

    /// `⟨a₂, r⟩` — the message-masking ring element.
    fn a2_dot(&self, r: &[Poly]) -> Poly {
        self.a2.iter().zip(r).fold(Poly::zero(), |acc, (a, rj)| acc.add(&a.mul(rj)))
    }

    /// `M·y = (A₁·y, ⟨a₂, y⟩)` — the `K + 1` ring elements the commitment and its zero-knowledge opening proof
    /// ([`crate::ring_zk`]) share, for an arbitrary `ELL`-vector `y` (the proof masks it wide, so `y` is NOT
    /// restricted to ternary).
    #[must_use]
    pub(crate) fn m_times(&self, y: &[Poly]) -> Vec<Poly> {
        let mut out = self.a1_times(y); // K
        out.push(self.a2_dot(y)); // + 1
        out
    }

    /// Row `k` of the binding matrix `A₁` (its `ELL` entries) — the value-tie proof ([`crate::ring_value_tie`])
    /// uses these as the public coefficients of the linear relation `t0_k = Σ_j A₁_{kj}·r_j`.
    #[must_use]
    pub(crate) fn a1_row(&self, k: usize) -> &[Poly] {
        self.a1.chunks(ELL).nth(k).unwrap_or(&[])
    }

    /// The message row `a₂` (its `ELL` entries) — the coefficients of `t1 = ⟨a₂, r⟩ + v`.
    #[must_use]
    pub(crate) fn a2(&self) -> &[Poly] {
        &self.a2
    }
}

/// Short (ternary) commitment randomness — an `ELL`-vector of ternary ring elements, the hiding secret.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingRandomness {
    r: Vec<Poly>, // ELL ternary polys
}

impl RingRandomness {
    /// Deterministic short randomness from `seed` (each ring element ternary, domain-separated by index).
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        let r = (0..ELL)
            .map(|j| {
                let mut s = Vec::with_capacity(seed.len() + 8);
                s.extend_from_slice(seed);
                s.extend_from_slice(&(j as u64).to_le_bytes());
                Poly::ternary(&s)
            })
            .collect();
        Self { r }
    }

    /// Whether every component is genuinely short ternary — the shortness binding/hiding assume.
    #[must_use]
    pub fn is_short(&self) -> bool {
        self.r.len() == ELL && self.r.iter().all(Poly::is_ternary)
    }

    /// The component ring elements (for the zero-knowledge opening proof).
    #[must_use]
    pub fn components(&self) -> &[Poly] {
        &self.r
    }

    /// A randomness from explicit component polynomials — the **balance** randomness `Σr_in − Σr_out` (a signed
    /// sum of ternaries: no longer ternary, but still short with `‖·‖∞ ≤ #notes`) is assembled this way for its
    /// zero-knowledge opening-to-zero proof ([`crate::ring_balance`]). Must have `ELL` components.
    #[must_use]
    pub(crate) fn from_components(r: Vec<Poly>) -> Self {
        debug_assert_eq!(r.len(), ELL, "a randomness has ELL components");
        Self { r }
    }

    /// **Wide masking** randomness — `ELL` uniformly-`bound`ed components, deterministic from `seed`. The product
    /// proof ([`crate::ring_product`]) blinds its revealed randomness openings with these (`bound ≫ 1`), so the
    /// short ternary randomness they carry stays hidden.
    #[must_use]
    pub(crate) fn from_uniform_bounded(seed: &[u8], bound: i64) -> Self {
        let r = (0..ELL)
            .map(|j| {
                let mut s = Vec::with_capacity(seed.len() + 8);
                s.extend_from_slice(seed);
                s.extend_from_slice(&(j as u64).to_le_bytes());
                Poly::uniform_bounded(&s, bound)
            })
            .collect();
        Self { r }
    }

    /// Scale by a ring element: `c·r` component-wise. With `c` a monomial the result stays short.
    #[must_use]
    pub(crate) fn scale(&self, c: &Poly) -> Self {
        Self { r: self.r.iter().map(|rj| c.mul(rj)).collect() }
    }

    /// Component-wise sum `r + other` (both `ELL` components).
    #[must_use]
    pub(crate) fn add(&self, other: &Self) -> Self {
        Self { r: self.r.iter().zip(&other.r).map(|(a, b)| a.add(b)).collect() }
    }

    /// Component-wise difference `r − other` — the randomness of a difference commitment `C_a − C_b`, which the
    /// conditional-swap proof ([`crate::ring_membership`]) opens as a product proof's factor.
    #[must_use]
    pub(crate) fn sub(&self, other: &Self) -> Self {
        Self { r: self.r.iter().zip(&other.r).map(|(a, b)| a.sub(b)).collect() }
    }

    /// Whether every component is within infinity-norm `bound` — the shortness a proof's masked randomness opening
    /// must satisfy.
    #[must_use]
    pub(crate) fn infinity_norm_le(&self, bound: i64) -> bool {
        self.r.iter().all(|p| p.infinity_norm_le(bound))
    }
}

/// A ring-BDLOP value commitment `(t0 ∈ R_q^K, t1 ∈ R_q)` — hiding the amount, binding, additively homomorphic.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RingCommitment {
    t0: Vec<Poly>, // K
    t1: Poly,
}

impl RingCommitment {
    /// Commit to `value` under short randomness `r`: `(A₁·r, ⟨a₂, r⟩ + value)`.
    #[must_use]
    pub fn commit(params: &RingParams, value: u64, r: &RingRandomness) -> Self {
        Self::commit_message(params, &Poly::constant(value), r)
    }

    /// Commit to a **full ring-element message** `msg` under short randomness `r`: `(A₁·r, ⟨a₂, r⟩ + msg)`. Value
    /// commitments embed the amount as a constant polynomial ([`commit`](Self::commit)); the product proof
    /// ([`crate::ring_product`]) commits general messages (masking terms and cross-products) this way.
    #[must_use]
    pub fn commit_message(params: &RingParams, msg: &Poly, r: &RingRandomness) -> Self {
        Self { t0: params.a1_times(&r.r), t1: params.a2_dot(&r.r).add(msg) }
    }

    /// Scale this commitment by a ring element `c`: `c·(t0, t1) = (c·t0, c·t1)` — a commitment to `c·msg` under
    /// `c·r`. With `c` a **monomial** (the challenge form), `c·r` stays short, so binding is preserved: the
    /// product proof's verifier forms `γ·X`, `γ²·Z`, `γ·T` this way.
    #[must_use]
    pub fn scale(&self, c: &Poly) -> Self {
        Self { t0: self.t0.iter().map(|p| c.mul(p)).collect(), t1: c.mul(&self.t1) }
    }

    /// The commitment to a **public** amount with zero randomness: `(0, value)`. The fee enters the balance law
    /// through this.
    #[must_use]
    pub fn public_value(value: u64) -> Self {
        Self { t0: alloc::vec![Poly::zero(); K], t1: Poly::constant(value) }
    }

    /// The homomorphic sum `self + other = com(v_self + v_other; r_self + r_other)`.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        Self {
            t0: self.t0.iter().zip(&other.t0).map(|(a, b)| a.add(b)).collect(),
            t1: self.t1.add(&other.t1),
        }
    }

    /// The homomorphic difference `self − other`.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        Self {
            t0: self.t0.iter().zip(&other.t0).map(|(a, b)| a.sub(b)).collect(),
            t1: self.t1.sub(&other.t1),
        }
    }

    /// Whether `(value, r)` is a valid opening of this commitment — the binding check.
    #[must_use]
    pub fn opens_to(&self, params: &RingParams, value: u64, r: &RingRandomness) -> bool {
        self == &Self::commit(params, value, r)
    }

    /// The opening-proof statement `u = (t0, t1 − value)` — the `K + 1` ring elements a short `r` maps to under
    /// `M`: `M·r = u` iff this commitment opens to `value` under `r`. The zero-knowledge proof proves knowledge
    /// of such a short `r` without revealing it ([`crate::ring_zk`]).
    #[must_use]
    pub(crate) fn statement(&self, value: u64) -> Vec<Poly> {
        let mut u = self.t0.clone();
        u.push(self.t1.sub(&Poly::constant(value)));
        u
    }

    /// The `t0` binding components (the zero-knowledge opening proof forms its statement from these).
    #[must_use]
    pub fn t0(&self) -> &[Poly] {
        &self.t0
    }

    /// The `t1` message component.
    #[must_use]
    pub fn t1(&self) -> &Poly {
        &self.t1
    }
}

impl crate::ring_size::ProofSize for RingCommitment {
    /// `t0 ∈ R_q^K` plus `t1 ∈ R_q`.
    fn ring_elements(&self) -> usize {
        self.t0.len() + 1
    }
}

impl crate::ring_size::ProofSize for RingRandomness {
    /// `ELL` ring elements.
    fn ring_elements(&self) -> usize {
        self.r.len()
    }
}

impl crate::ring_size::ProofSize for Poly {
    /// One ring element.
    fn ring_elements(&self) -> usize {
        1
    }
}

/// The homomorphic sum of a list of commitments, or the commitment to zero for an empty list.
#[must_use]
pub fn sum(commitments: &[RingCommitment]) -> RingCommitment {
    commitments.iter().fold(RingCommitment::public_value(0), |acc, c| acc.add(c))
}

/// Verify the **balance law** of a shielded transfer on the commitments alone (amounts never revealed):
/// `Σ inputs − Σ outputs − com(fee)` opens to **zero** under the balance randomness `r_balance`. Because the
/// commitment is binding, a transaction whose amounts do not satisfy `Σ v_in = Σ v_out + fee` cannot produce any
/// `r_balance` opening the difference to zero — so it cannot inflate the supply. A production proof supplies
/// `r_balance` in zero-knowledge (proving it short); here it is checked in the clear.
#[must_use]
pub fn verify_balance(
    params: &RingParams,
    inputs: &[RingCommitment],
    outputs: &[RingCommitment],
    fee: u64,
    r_balance: &RingRandomness,
) -> bool {
    let diff = sum(inputs).sub(&sum(outputs)).sub(&RingCommitment::public_value(fee));
    diff.opens_to(params, 0, r_balance)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::ring::fadd;

    #[test]
    fn a_commitment_opens_only_to_its_true_value_and_randomness() {
        let params = RingParams::standard();
        let r = RingRandomness::from_seed(b"open-r");
        assert!(r.is_short(), "the randomness is short ternary");
        let c = RingCommitment::commit(&params, 12345, &r);
        assert!(c.opens_to(&params, 12345, &r), "the true opening verifies");
        assert!(!c.opens_to(&params, 12346, &r), "a wrong value does not open it (binding)");
        assert!(!c.opens_to(&params, 12345, &RingRandomness::from_seed(b"other-r")), "wrong randomness fails");
    }

    #[test]
    fn the_commitment_is_additively_homomorphic() {
        // com(v1;r1) + com(v2;r2) opens to (v1+v2) under (r1+r2) — the property the balance law rests on.
        let params = RingParams::standard();
        let r1 = RingRandomness::from_seed(b"hom-r1");
        let r2 = RingRandomness::from_seed(b"hom-r2");
        let c = RingCommitment::commit(&params, 400, &r1).add(&RingCommitment::commit(&params, 600, &r2));
        // r1 + r2 (component-wise), and it opens to 1000.
        let r_sum = RingRandomness { r: r1.r.iter().zip(&r2.r).map(|(a, b)| a.add(b)).collect() };
        assert!(c.opens_to(&params, 1000, &r_sum), "the sum opens to v1+v2 under r1+r2");
        // The message added as an integer: t1's constant term is (v1+v2 masked); the sum of constants is exact.
        assert_eq!(fadd(400, 600), 1000, "amounts add as integers below q");
    }

    #[test]
    fn a_balanced_transfer_verifies_and_an_inflating_one_does_not() {
        // 1000 in → 700 out + 250 out + 50 fee = 1000. Balance randomness = Σr_in − Σr_out.
        let params = RingParams::standard();
        let r_in = RingRandomness::from_seed(b"bal-in");
        let (r_o1, r_o2) = (RingRandomness::from_seed(b"bal-o1"), RingRandomness::from_seed(b"bal-o2"));
        let input = RingCommitment::commit(&params, 1000, &r_in);
        let out1 = RingCommitment::commit(&params, 700, &r_o1);
        let out2 = RingCommitment::commit(&params, 250, &r_o2);
        // r_balance = r_in − r_o1 − r_o2 (centred small-int is fine; opens_to reconstructs the exact commitment).
        let sub = |a: &[Poly], b: &[Poly]| -> Vec<Poly> { a.iter().zip(b).map(|(x, y)| x.sub(y)).collect() };
        let r_bal = RingRandomness { r: sub(&sub(r_in.components(), r_o1.components()), r_o2.components()) };
        let (ins, outs) = ([input], [out1, out2]);
        assert!(verify_balance(&params, &ins, &outs, 50, &r_bal), "the balanced transfer verifies");
        // Inflate the fee claim to 51: the difference no longer opens to zero under this balance randomness.
        assert!(!verify_balance(&params, &ins, &outs, 51, &r_bal), "an inflating transfer is rejected");
    }
}
