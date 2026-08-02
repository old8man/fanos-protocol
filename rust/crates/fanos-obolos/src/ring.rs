//! The **power-of-two cyclotomic ring** `R_q = Z_q[X]/(X^D + 1)` — the algebraic substrate of the compact,
//! production-grade OBOLOS lattice commitment and its zero-knowledge proofs (`spec/platform.md` §4.1/§4.3).
//!
//! This is the modern, optimised replacement for the flat `Z_q`-vector [`crate::commit`]: a Module-SIS/LWE
//! commitment over `R_q` needs only a handful of ring elements (KB-scale) where the vector form needs thousands
//! (and its zero-knowledge proofs are single-round with polynomial challenges, not the κ-round `{0,1}` blow-up of
//! [`crate::zk`]). The ring is chosen for maximum performance:
//!
//! - **`q = 2⁶⁴ − 2³² + 1`, the Goldilocks prime** (Plonky2/STARK field). Its 2-adicity is `32` (`2³² | q − 1`),
//!   so a primitive `2D`-th root of unity exists for every `D ≤ 2³¹` — the **Number-Theoretic Transform (NTT)**
//!   turns ring multiplication into `O(D log D)` pointwise products. A product of two residues is `< q² < 2¹²⁸`,
//!   fitting `u128` exactly; and `q > 2⁶³` leaves a whole amount (`< 2⁵¹`) in a single coefficient so the
//!   homomorphic **integer** sum the balance law needs never wraps.
//! - **`D = 256`** (Kyber/Dilithium dimension) — the security/size sweet spot for a module lattice.
//!
//! > **STATUS — \[P\]/\[H\], correctness-first (as [`crate::commit`]).** The field and the negacyclic NTT are the
//! > standard, textbook-correct constructions; the tests below verify the ring axioms and that NTT-multiplication
//! > equals the schoolbook negacyclic convolution. What is deliberately *not yet* done, and lands as
//! > **verified drop-in optimisations with no behavioural change**: the fast Goldilocks reduction (here a plain
//! > `%`), merged-butterfly NTT with a precomputed twiddle table (here recomputed per call), and constant-time
//! > arithmetic. The module-lattice parameters `(D, module rank, noise)` are illustrative, not yet calibrated to
//! > a bit-security target nor externally cryptanalysed.

use alloc::vec::Vec;

use fanos_primitives::hash::hash_xof;

/// The Goldilocks prime `q = 2⁶⁴ − 2³² + 1`.
pub const Q: u64 = 0xFFFF_FFFF_0000_0001;

/// The ring degree — `R_q = Z_q[X]/(X^D + 1)`.
pub const D: usize = 256;

/// A primitive root (generator) of `Z_q^*`. `7` generates the Goldilocks multiplicative group.
const GENERATOR: u64 = 7;

/// `2⁶⁴ mod q = 2³² − 1` — the Goldilocks reduction constant (`ε`, where `q = 2⁶⁴ − ε`).
const EPSILON: u64 = 0xFFFF_FFFF;

/// Reduce a 128-bit value into the canonical `[0, q)` — the **fast Goldilocks reduction** (Plonky2), exploiting
/// `2⁶⁴ ≡ 2³² − 1` and `2⁹⁶ ≡ −1 (mod q)`: with `x = hi·2⁶⁴ + lo` and `hi = hi_hi·2³² + hi_lo`,
/// `x ≡ lo − hi_hi + hi_lo·ε`. Each `overflowing_{sub,add}` corrects a `2⁶⁴` wrap by `∓ε`; `hi_lo·ε < 2⁶⁴ − 2³³`
/// leaves headroom so no second carry occurs, and one conditional `− q` canonicalises. This replaces a plain `%`
/// with a few adds/shifts and is verified equal to it over the whole input range
/// ([`fast_reduction_equals_modulo`](self)).
#[inline]
#[must_use]
fn reduce(x: u128) -> u64 {
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    let hi_hi = hi >> 32; // bits 96..128 — 2⁹⁶ ≡ −1
    let hi_lo = hi & EPSILON; // bits 64..96 — 2⁶⁴ ≡ ε
    let (t0, borrow) = lo.overflowing_sub(hi_hi);
    let t0 = t0.wrapping_sub(EPSILON * u64::from(borrow)); // a 2⁶⁴ underflow ≡ +ε, so subtract ε back
    let (res, carry) = t0.overflowing_add(hi_lo * EPSILON);
    let res = res.wrapping_add(EPSILON * u64::from(carry)); // a 2⁶⁴ overflow dropped ε, so add it back
    if res >= Q { res - Q } else { res } // res ∈ [0, 2⁶⁴); q ≤ res < q + ε ⇒ one subtraction canonicalises
}

/// `a + b mod q`.
#[inline]
#[must_use]
pub fn fadd(a: u64, b: u64) -> u64 {
    reduce(u128::from(a) + u128::from(b))
}

/// `a − b mod q` (via `a + q − b`, so no `u64` underflow).
#[inline]
#[must_use]
pub fn fsub(a: u64, b: u64) -> u64 {
    reduce(u128::from(a) + u128::from(Q) - u128::from(b))
}

/// `a · b mod q`.
#[inline]
#[must_use]
pub fn fmul(a: u64, b: u64) -> u64 {
    reduce(u128::from(a) * u128::from(b))
}

/// `base^exp mod q` (square-and-multiply).
#[must_use]
pub fn fpow(base: u64, mut exp: u64) -> u64 {
    let mut result = 1u64;
    let mut b = reduce(u128::from(base));
    while exp > 0 {
        if exp & 1 == 1 {
            result = fmul(result, b);
        }
        b = fmul(b, b);
        exp >>= 1;
    }
    result
}

/// The multiplicative inverse `a⁻¹ mod q` (Fermat: `a^{q−2}`). `a` must be non-zero.
#[must_use]
pub fn finv(a: u64) -> u64 {
    fpow(a, Q - 2)
}

/// A primitive `2D`-th root of unity `ψ` (so `ψ^{2D} = 1`, `ψ^D = −1` = `q − 1`) — the twiddle base of the
/// **negacyclic** NTT for `X^D + 1`. `ψ = g^{(q−1)/2D}` for the group generator `g`.
#[must_use]
fn psi() -> u64 {
    fpow(GENERATOR, (Q - 1) / (2 * D as u64))
}

/// The bit-reversal permutation of `0..D` applied in place (Cooley–Tukey uses natural-in, bit-reversed-out).
fn bit_reverse(a: &mut [u64]) {
    let n = a.len();
    let bits = n.trailing_zeros();
    for i in 0..n {
        let j = (i as u32).reverse_bits() >> (32 - bits);
        if (i as u32) < j {
            a.swap(i, j as usize);
        }
    }
}

/// The forward negacyclic NTT of `a` (length `D`), in place. Pre-twists by powers of `ψ` (so the cyclic transform
/// that follows evaluates at the roots of `X^D + 1`), then runs an iterative Cooley–Tukey NTT with `ω = ψ²`, the
/// primitive `D`-th root. Twiddles are recomputed here (correctness-first; a precomputed table is the drop-in
/// optimisation).
// The butterfly indices `start + j` and `start + j + len/2` are provably `< n` by the power-of-two loop bounds
// (`start + len ≤ n`, `j < len/2`) — the standard iterative NTT access pattern.
#[allow(clippy::indexing_slicing)]
fn ntt(a: &mut [u64]) {
    let psi = psi();
    // Negacyclic pre-twist: a_i ← a_i · ψ^i.
    let mut p = 1u64;
    for x in a.iter_mut() {
        *x = fmul(*x, p);
        p = fmul(p, psi);
    }
    // Cyclic NTT with ω = ψ².
    let omega = fmul(psi, psi);
    let n = a.len();
    bit_reverse(a);
    let mut len = 2;
    while len <= n {
        // ω_len = ω^{n/len} — a primitive len-th root.
        let w_len = fpow(omega, (n / len) as u64);
        let mut start = 0;
        while start < n {
            let mut w = 1u64;
            for j in 0..len / 2 {
                let u = a[start + j];
                let v = fmul(a[start + j + len / 2], w);
                a[start + j] = fadd(u, v);
                a[start + j + len / 2] = fsub(u, v);
                w = fmul(w, w_len);
            }
            start += len;
        }
        len <<= 1;
    }
}

/// The inverse negacyclic NTT of `a` (length `D`), in place — the exact inverse of [`ntt`].
#[allow(clippy::indexing_slicing)] // same loop-bounded butterfly indices as `ntt`.
fn intt(a: &mut [u64]) {
    let psi = psi();
    let omega = fmul(psi, psi);
    let omega_inv = finv(omega);
    let n = a.len();
    bit_reverse(a);
    let mut len = 2;
    while len <= n {
        let w_len = fpow(omega_inv, (n / len) as u64);
        let mut start = 0;
        while start < n {
            let mut w = 1u64;
            for j in 0..len / 2 {
                let u = a[start + j];
                let v = fmul(a[start + j + len / 2], w);
                a[start + j] = fadd(u, v);
                a[start + j + len / 2] = fsub(u, v);
                w = fmul(w, w_len);
            }
            start += len;
        }
        len <<= 1;
    }
    // Scale by 1/n and undo the pre-twist: a_i ← a_i · n⁻¹ · ψ^{−i}.
    let n_inv = finv(n as u64);
    let psi_inv = finv(psi);
    let mut p = 1u64;
    for x in a.iter_mut() {
        *x = fmul(fmul(*x, n_inv), p);
        p = fmul(p, psi_inv);
    }
}

/// An element of `R_q = Z_q[X]/(X^D + 1)` — `D` coefficients in `[0, q)`, low degree first.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Poly {
    coeffs: Vec<u64>, // length D
}

impl Poly {
    /// The zero polynomial.
    #[must_use]
    pub fn zero() -> Self {
        Self { coeffs: alloc::vec![0u64; D] }
    }

    /// The constant polynomial `v` (used to embed a public amount in the message coefficient).
    #[must_use]
    pub fn constant(v: u64) -> Self {
        let mut coeffs = alloc::vec![0u64; D];
        if let Some(c0) = coeffs.first_mut() {
            *c0 = reduce(u128::from(v));
        }
        Self { coeffs }
    }

    /// The monomial `X^m ∈ R_q` for any `m` (taken mod `2D`). For `m mod 2D ≥ D` it is `−X^{(m mod 2D)−D}` (the
    /// negacyclic wrap `X^D = −1`). The set `{X^m : 0 ≤ m < 2D}` is the **challenge set** the range/product proofs
    /// use: every element is short (`‖·‖∞ = 1`) and — the load-bearing property for soundness extraction — every
    /// *difference* `X^i − X^j` (`i ≠ j mod 2D`) is a **unit**. That holds on this fully-splitting ring precisely
    /// because `2D` is a power of two, so `X^{i−j} − 1` shares no root with `X^D + 1`
    /// ([`monomial_challenge_differences_are_units`](self)).
    #[must_use]
    pub fn monomial(m: usize) -> Self {
        let mut coeffs = alloc::vec![0u64; D];
        let m = m % (2 * D);
        let (idx, val) = if m < D { (m, 1) } else { (m - D, Q - 1) };
        if let Some(c) = coeffs.get_mut(idx) {
            *c = val;
        }
        Self { coeffs }
    }

    /// The coefficient slice.
    #[must_use]
    pub fn coeffs(&self) -> &[u64] {
        &self.coeffs
    }

    /// The polynomial's canonical bytes: every coefficient as a little-endian `u64`, in order.
    ///
    /// A general element of `R_q` needs the full width — its coefficients are only bounded by `q`. Canonicity comes
    /// from the decoder ([`from_bytes`](Self::from_bytes)) rejecting any coefficient `≥ q`, so each polynomial has
    /// exactly one encoding and no two byte strings decode alike. (Elements that are *known* short — openings,
    /// ternary randomness — could pack far tighter; that is `docs/design-obolos-zk.md` §6.1 rung 4.)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(D * 8);
        for &c in self.coeffs() {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out
    }

    /// Decode a polynomial from [`to_bytes`](Self::to_bytes). `None` if the length is wrong or any coefficient is
    /// **not reduced** (`≥ q`) — an unreduced coefficient would give a second encoding of the same element.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != D * 8 {
            return None;
        }
        let mut coeffs = [0u64; D];
        for (slot, chunk) in coeffs.iter_mut().zip(bytes.as_chunks::<8>().0) {
            let v = u64::from_le_bytes(*chunk);
            if v >= Q {
                return None; // not canonical
            }
            *slot = v;
        }
        Some(Self::from_u64(&coeffs))
    }

    /// A ring element from `D` raw coefficients, each reduced into `[0, q)`. Reduction here is deliberate: callers
    /// build polynomials from arithmetic that may exceed `q`. Wire input goes through
    /// [`from_bytes`](Self::from_bytes) instead, which *rejects* unreduced coefficients rather than folding them, so
    /// the encoding stays canonical.
    #[must_use]
    pub fn from_u64(coeffs: &[u64; D]) -> Self {
        Self { coeffs: coeffs.iter().map(|&c| reduce(u128::from(c))).collect() }
    }

    /// The constant coefficient `c₀` (an embedded amount is read back here).
    #[must_use]
    pub fn constant_term(&self) -> u64 {
        self.coeffs.first().copied().unwrap_or(0)
    }

    /// A **uniform** ring element, derived deterministically from `seed` — the public matrix entries (CRS).
    #[must_use]
    pub fn uniform(seed: &[u8]) -> Self {
        let mut bytes = alloc::vec![0u8; D * 8];
        hash_xof("FANOS-obolos-v1/ring-uniform", seed, &mut bytes);
        let (words, _) = bytes.as_chunks::<8>();
        Self { coeffs: words.iter().take(D).map(|w| reduce(u128::from(u64::from_le_bytes(*w)))).collect() }
    }

    /// A **uniformly bounded** ring element with centred coefficients in `[−bound, bound]` (stored mod `q`),
    /// derived deterministically from `seed` — the masking `y` of the zero-knowledge opening proof
    /// ([`crate::ring_zk`]). Uses 8 bytes per coefficient reduced into the span (a negligible modular bias,
    /// tolerable for the re-randomised, never-revealed masking; the proof re-samples on rejection).
    #[must_use]
    pub fn uniform_bounded(seed: &[u8], bound: i64) -> Self {
        let span = (2 * bound + 1) as u64;
        let mut bytes = alloc::vec![0u8; D * 8];
        hash_xof("FANOS-obolos-v1/ring-mask", seed, &mut bytes);
        let (words, _) = bytes.as_chunks::<8>();
        let coeffs = words
            .iter()
            .take(D)
            .map(|w| {
                let v = (u64::from_le_bytes(*w) % span) as i64 - bound; // in [−bound, bound]
                if v < 0 { Q - v.unsigned_abs() } else { v as u64 }
            })
            .collect();
        Self { coeffs }
    }

    /// Whether every coefficient, **centred** into `(−q/2, q/2]`, has absolute value `≤ bound` — the shortness
    /// check the opening proof applies to its response `z` (a masked value stays small; a forged one wraps `q`).
    #[must_use]
    pub fn infinity_norm_le(&self, bound: i64) -> bool {
        let b = i128::from(bound);
        self.coeffs.iter().all(|&c| {
            let centered = if c > Q / 2 { i128::from(c) - i128::from(Q) } else { i128::from(c) };
            centered.abs() <= b
        })
    }

    /// A **short ternary** ring element `{−1, 0, 1}^D` (stored as `0`, `1`, `q−1`), the commitment randomness /
    /// challenge form. Rejection-sampled to `{0,1,2}` without modulo bias, then centred.
    #[must_use]
    pub fn ternary(seed: &[u8]) -> Self {
        let mut coeffs = Vec::with_capacity(D);
        let mut round: u64 = 0;
        while coeffs.len() < D {
            let mut block = [0u8; 256];
            let mut salted = Vec::with_capacity(seed.len() + 8);
            salted.extend_from_slice(seed);
            salted.extend_from_slice(&round.to_le_bytes());
            hash_xof("FANOS-obolos-v1/ring-ternary", &salted, &mut block);
            for &b in &block {
                if coeffs.len() == D {
                    break;
                }
                if b < 252 {
                    // 0,1,2 → 0, 1, q−1 (i.e. −1 centred).
                    coeffs.push(match b % 3 {
                        0 => 0,
                        1 => 1,
                        _ => Q - 1,
                    });
                }
            }
            round += 1;
        }
        Self { coeffs }
    }

    /// Whether this is genuinely short ternary (`{0, 1, q−1}` coefficients) — the shortness the commitment's
    /// Module-SIS binding / Module-LWE hiding assume.
    #[must_use]
    pub fn is_ternary(&self) -> bool {
        self.coeffs.len() == D && self.coeffs.iter().all(|&c| c == 0 || c == 1 || c == Q - 1)
    }

    /// `self + other` in `R_q`.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        Self { coeffs: self.coeffs.iter().zip(&other.coeffs).map(|(&a, &b)| fadd(a, b)).collect() }
    }

    /// `self − other` in `R_q`.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        Self { coeffs: self.coeffs.iter().zip(&other.coeffs).map(|(&a, &b)| fsub(a, b)).collect() }
    }

    /// `self · other` in `R_q = Z_q[X]/(X^D + 1)`, via the negacyclic NTT (`O(D log D)`).
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        let mut fa = self.coeffs.clone();
        let mut fb = other.coeffs.clone();
        ntt(&mut fa);
        ntt(&mut fb);
        let mut prod: Vec<u64> = fa.iter().zip(&fb).map(|(&a, &b)| fmul(a, b)).collect();
        intt(&mut prod);
        Self { coeffs: prod }
    }

    /// Whether this ring element is a **unit** (invertible) — true iff none of its `D` NTT slots vanish. On the
    /// fully-splitting Goldilocks ring `R_q ≅ (Z_q)^D` (slot-wise via the NTT), a product is a unit exactly when
    /// no slot is zero.
    #[must_use]
    pub fn is_invertible(&self) -> bool {
        let mut slots = self.coeffs.clone();
        ntt(&mut slots);
        slots.iter().all(|&s| s != 0)
    }

    /// The multiplicative inverse `a⁻¹` in `R_q`, or `None` if `a` is not a unit. Computed slot-wise in the NTT
    /// domain — `a⁻¹ = INTT((slotᵢ⁻¹)ᵢ)` — which is *exact* because the ring fully splits. The extractor of a
    /// range/product proof divides by an (always-invertible) challenge difference this way.
    #[must_use]
    pub fn inverse(&self) -> Option<Self> {
        let mut slots = self.coeffs.clone();
        ntt(&mut slots);
        if slots.contains(&0) {
            return None; // a zero slot ⇒ a zero divisor, not a unit
        }
        for s in &mut slots {
            *s = finv(*s);
        }
        intt(&mut slots);
        Some(Self { coeffs: slots })
    }

    /// The **coefficient-wise (Hadamard) product** `(a ∘ b)_i = a_i·b_i` — *not* the ring product. The aggregated
    /// range proof ([`crate::ring_range_agg`]) checks binarity through this: the verifier forms `f ∘ (x − f)` from
    /// the revealed masked bits `f` as a known polynomial.
    #[must_use]
    pub(crate) fn hadamard(&self, other: &Self) -> Self {
        Self { coeffs: self.coeffs.iter().zip(&other.coeffs).map(|(&a, &b)| fmul(a, b)).collect() }
    }

    /// The polynomial with **every** coefficient equal to the scalar `v` — the coefficient-wise broadcast used to
    /// form `x − f` (all `D` coefficients `x − f_i`), distinct from [`constant`](Self::constant) (only `c₀ = v`).
    #[must_use]
    pub(crate) fn broadcast(v: u64) -> Self {
        Self { coeffs: alloc::vec![reduce(u128::from(v)); D] }
    }

    /// The **weighted coefficient sum** `Σ_{i<bits} coeffᵢ·2ⁱ (mod q)` — the reconstruction inner product
    /// `⟨f, 2^vec⟩` that links the packed bits to the committed value. `bits ≤ 63`.
    #[must_use]
    pub(crate) fn inner_pow2(&self, bits: usize) -> u64 {
        self.coeffs.iter().take(bits).enumerate().fold(0u64, |acc, (i, &c)| fadd(acc, fmul(c, 1u64 << i)))
    }

    /// The negacyclic **schoolbook** product — the `O(D²)` reference [`mul`](Self::mul) is verified against.
    #[cfg(test)]
    #[must_use]
    #[allow(clippy::indexing_slicing)] // `k = i + j < 2D`, so `k` or `k − D` is a valid `0..D` index.
    fn mul_schoolbook(&self, other: &Self) -> Self {
        let mut out = alloc::vec![0u64; D];
        for (i, &a) in self.coeffs.iter().enumerate() {
            for (j, &b) in other.coeffs.iter().enumerate() {
                let term = fmul(a, b);
                let k = i + j;
                if k < D {
                    out[k] = fadd(out[k], term);
                } else {
                    // X^D = −1, so wrap with a sign flip.
                    out[k - D] = fsub(out[k - D], term);
                }
            }
        }
        Self { coeffs: out }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn fast_reduction_equals_modulo() {
        // The fast Goldilocks reduction must equal the plain modulo it replaces, over the WHOLE 128-bit input
        // range — a wrong reduction would silently corrupt every ring operation, so this is exhaustively checked.
        let reference = |x: u128| (x % (Q as u128)) as u64;
        // Edge cases: boundaries of q, the reduction limbs (2³², 2⁶⁴, 2⁹⁶), and every product of edge residues.
        let edges: [u128; 14] = [
            0, 1, 2, u128::from(EPSILON), u128::from(EPSILON) + 1, 1 << 32, 1 << 64, 1 << 96,
            u128::from(Q), u128::from(Q) - 1, u128::from(Q) + 1, 2 * u128::from(Q) - 1, u128::MAX,
            u128::MAX - u128::from(Q),
        ];
        for &x in &edges {
            assert_eq!(reduce(x), reference(x), "edge reduce({x})");
        }
        // Every product of two near-maximal field residues (the fmul worst cases) and their sums.
        let residues = [0u64, 1, 2, EPSILON, EPSILON + 1, 1 << 32, Q / 2, Q - 2, Q - 1];
        for &a in &residues {
            for &b in &residues {
                let prod = u128::from(a) * u128::from(b);
                assert_eq!(reduce(prod), reference(prod), "reduce({a}·{b})");
                let sum = u128::from(a) + u128::from(b);
                assert_eq!(reduce(sum), reference(sum), "reduce({a}+{b})");
            }
        }
        // A large deterministic random sweep (xorshift64), covering the full 128-bit range.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2_000_000u32 {
            let x = (u128::from(next()) << 64) | u128::from(next());
            assert_eq!(reduce(x), reference(x));
        }
    }

    #[test]
    fn the_field_is_a_field() {
        // Additive/multiplicative identities, inverses, and Fermat.
        assert_eq!(fadd(Q - 1, 1), 0, "q − 1 + 1 ≡ 0");
        assert_eq!(fsub(0, 1), Q - 1, "0 − 1 ≡ q − 1");
        assert_eq!(fmul(Q - 1, Q - 1), 1, "(−1)² ≡ 1");
        for &a in &[1u64, 2, 7, 12345, Q - 2, Q - 1, 0x1234_5678_9abc] {
            assert_eq!(fmul(a, finv(a)), 1, "a · a⁻¹ ≡ 1 for a = {a}");
        }
        // A product of two near-maximal residues stays correct through the u128 reduction.
        assert_eq!(fmul(Q - 1, Q - 2), fmul(Q - 2, Q - 1));
        assert_eq!(fmul(Q - 1, 2), Q - 2, "(−1)·2 ≡ −2 ≡ q − 2");
    }

    #[test]
    fn psi_is_a_primitive_2d_th_root_of_unity() {
        let psi = psi();
        assert_eq!(fpow(psi, 2 * D as u64), 1, "ψ^{{2D}} = 1");
        assert_eq!(fpow(psi, D as u64), Q - 1, "ψ^D = −1 (the negacyclic property)");
        assert_ne!(fpow(psi, 2), 1, "ψ is primitive (not a lower-order root)");
    }

    #[test]
    fn the_ntt_round_trips() {
        let a = Poly::uniform(b"ntt-roundtrip");
        let mut buf = a.coeffs.clone();
        ntt(&mut buf);
        intt(&mut buf);
        assert_eq!(buf, a.coeffs, "intt(ntt(a)) = a");
    }

    #[test]
    fn ntt_multiplication_equals_the_schoolbook_negacyclic_product() {
        // The load-bearing correctness property: fast NTT mul == the O(D²) reference, over several inputs.
        for i in 0..8u8 {
            let a = Poly::uniform(&[b'a', i]);
            let b = Poly::uniform(&[b'b', i]);
            assert_eq!(a.mul(&b), a.mul_schoolbook(&b), "NTT product matches schoolbook (seed {i})");
        }
        // X · X^{D−1} = X^D = −1 in this ring — the negacyclic wrap, checked concretely.
        let mut x = Poly::zero();
        x.coeffs[1] = 1; // X
        let mut top = Poly::zero();
        top.coeffs[D - 1] = 1; // X^{D−1}
        let prod = x.mul(&top);
        assert_eq!(prod.coeffs[0], Q - 1, "X · X^{{D−1}} = X^D = −1");
        assert!(prod.coeffs[1..].iter().all(|&c| c == 0), "…and nothing else");
    }

    #[test]
    fn the_ring_is_commutative_and_distributive() {
        let a = Poly::uniform(b"ring-a");
        let b = Poly::uniform(b"ring-b");
        let c = Poly::uniform(b"ring-c");
        assert_eq!(a.mul(&b), b.mul(&a), "commutative");
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)), "distributive over +");
        assert_eq!(a.add(&b).sub(&b), a, "additive inverse");
    }

    #[test]
    fn ring_inversion_is_exact_on_the_splitting_field() {
        // On the fully-splitting Goldilocks ring, NTT-domain slot inversion is exact.
        let a = Poly::uniform(b"invert-me");
        let a_inv = a.inverse().expect("a uniform element is almost surely a unit");
        assert_eq!(a.mul(&a_inv), Poly::constant(1), "a · a⁻¹ = 1");
        assert!(Poly::constant(1).is_invertible(), "1 is a unit");
        assert!(Poly::zero().inverse().is_none(), "0 is not a unit");
        // X^m is always a unit (its inverse is the negacyclic X^{2D−m}).
        assert!(Poly::monomial(5).is_invertible(), "a monomial is a unit");
        assert_eq!(Poly::monomial(5).mul(&Poly::monomial(5).inverse().unwrap()), Poly::constant(1));
    }

    #[test]
    fn monomial_challenge_differences_are_units() {
        // The load-bearing lemma for range/product-proof soundness: every difference X^i − X^j (i ≠ j mod 2D) is
        // invertible in R_q, so the extractor can divide by a challenge difference. Holds because 2D is a power of
        // two, so X^{i−j} − 1 shares no root with X^D + 1 even though the ring fully splits.
        for i in 0..10usize {
            for j in 0..10usize {
                let diff = Poly::monomial(i).sub(&Poly::monomial(j));
                if i == j {
                    assert!(!diff.is_invertible(), "X^i − X^i = 0 is not a unit");
                } else {
                    assert!(diff.is_invertible(), "X^{i} − X^{j} is a unit");
                    assert_eq!(diff.mul(&diff.inverse().unwrap()), Poly::constant(1), "and its inverse inverts");
                }
            }
        }
        // A far-apart pair, and the negacyclic-wrapped range m ≥ D (monomial(300) = −X^{44}).
        assert!(Poly::monomial(300).sub(&Poly::monomial(5)).is_invertible(), "wrapped monomials too");
        assert!(Poly::monomial(511).sub(&Poly::monomial(0)).is_invertible(), "the widest gap < 2D");
    }

    #[test]
    fn ternary_sampling_is_short_and_uniform_ish() {
        let t = Poly::ternary(b"ternary-seed");
        assert!(t.is_ternary(), "coefficients are in {{0, 1, q−1}}");
        // All three symbols appear (a sanity check that the centring maps 0/1/2 → 0/1/−1).
        assert!(t.coeffs.contains(&0));
        assert!(t.coeffs.contains(&1));
        assert!(t.coeffs.contains(&(Q - 1)));
        // A uniform element is (almost surely) not ternary.
        assert!(!Poly::uniform(b"not-ternary").is_ternary());
    }
}
