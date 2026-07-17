//! # fanos-field — finite-field arithmetic for FANOS
//!
//! Every FANOS address is a point of a finite projective plane `PG(2, q)`, and every
//! projective operation (the O(1) rendezvous `u × v`, incidence, the mediator map) is a
//! handful of field operations. This crate provides those field operations for the two
//! families the specification uses (spec §2.1):
//!
//! * **Binary extension fields `GF(2^m)`** — the *default binary profile*: addition is
//!   XOR, multiplication is carry-less, and the arithmetic is amenable to constant-time
//!   implementation on hardware down to microcontrollers (spec §11.5).
//! * **Prime fields `GF(p)`** — the *illustrative cells* `q ∈ {2, 7, 13, 31, 127}`.
//!
//! ## Design
//!
//! A field is a *type*, not a value: [`Gf2m`] and [`GfP`] are zero-sized markers carrying
//! their parameters as const generics, and [`Field`] exposes the operations as associated
//! functions. This makes every call monomorphize to straight-line code with no dynamic
//! dispatch and no per-call field object — the "zero-cost abstraction" the performance
//! target demands. Elements are represented canonically as a `u32`:
//!
//! * for `GF(2^m)`, the `m`-bit coefficient vector of a polynomial over `GF(2)`;
//! * for `GF(p)`, the residue in `0..p`.
//!
//! In both, `0` is the additive identity and `1` the multiplicative identity, so generic
//! code (e.g. the projective cross product) never needs to know which family it is over.
//!
//! The crate is `#![no_std]` and allocation-free.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod gf2m;
mod gfp;

pub use gf2m::{Gf2m, irreducible};
pub use gfp::{GfP, is_prime};

/// Which algebraic family a [`Field`] belongs to (spec §2.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum FieldKind {
    /// A binary extension field `GF(2^m)`: additive characteristic 2, XOR addition.
    Binary,
    /// A prime field `GF(p)`.
    Prime,
}

/// A finite field `GF(q)` exposed as compile-time operations over `u32` element codes.
///
/// Implementors are zero-sized types; all methods are associated functions so that a
/// generic algorithm over `F: Field` compiles to code specialized to that exact field
/// with no indirection. The canonical element encoding is:
///
/// * `GF(2^m)`: the low `m` bits are the polynomial coefficients; every `m`-bit value is a
///   valid element, so [`Field::Q`] `= 2^m` distinct codes.
/// * `GF(p)`: the residue `0..p`.
///
/// # Invariants
/// * Inputs to every operation must satisfy [`Field::in_range`]; outputs always do.
/// * [`Field::inv`] and [`Field::div`] require a non-zero divisor.
pub trait Field: Copy + core::fmt::Debug {
    /// The order `q` of the field (number of distinct elements).
    const Q: u32;
    /// The characteristic `p` (a prime); for `GF(2^m)` this is `2`.
    const P: u32;
    /// The extension degree `m`, so that `Q == P^M`. For `GF(p)`, `M == 1`.
    const M: u32;
    /// The algebraic family (used by the wire layer to pick the field-element width).
    const KIND: FieldKind;

    /// `a + b`.
    fn add(a: u32, b: u32) -> u32;
    /// `a − b`.
    fn sub(a: u32, b: u32) -> u32;
    /// `−a`, the additive inverse.
    fn neg(a: u32) -> u32;
    /// `a · b`.
    fn mul(a: u32, b: u32) -> u32;
    /// Reduce an arbitrary integer to a canonical field element (used by `MapToPoint`,
    /// spec §7.1). For `GF(2^m)` this keeps the low `m` bits; for `GF(p)` it is `x mod p`.
    fn reduce(x: u64) -> u32;

    /// The additive identity `0`.
    #[inline(always)]
    fn zero() -> u32 {
        0
    }
    /// The multiplicative identity `1`.
    #[inline(always)]
    fn one() -> u32 {
        1
    }
    /// Whether `a` is the additive identity.
    #[inline(always)]
    fn is_zero(a: u32) -> bool {
        a == 0
    }
    /// Whether `a` is a canonical element code (`a < q`).
    #[inline(always)]
    fn in_range(a: u32) -> bool {
        a < Self::Q
    }

    /// `base^e` by square-and-multiply. Works in any finite field.
    #[inline]
    fn pow(base: u32, mut e: u64) -> u32 {
        let mut acc = Self::one();
        let mut b = base;
        while e > 0 {
            if e & 1 == 1 {
                acc = Self::mul(acc, b);
            }
            b = Self::mul(b, b);
            e >>= 1;
        }
        acc
    }

    /// `a⁻¹`, the multiplicative inverse, via Fermat's little theorem `a^(q−2)`.
    ///
    /// # Panics (debug)
    /// If `a == 0`.
    #[inline]
    fn inv(a: u32) -> u32 {
        debug_assert!(a != 0, "multiplicative inverse of zero is undefined");
        Self::pow(a, Self::Q as u64 - 2)
    }

    /// `a / b == a · b⁻¹`. Requires `b != 0`.
    #[inline]
    fn div(a: u32, b: u32) -> u32 {
        Self::mul(a, Self::inv(b))
    }
}

/// `GF(2)` — the field of the base Fano cell `PG(2, 2)` (spec §2.2, §2.4).
pub type F2 = Gf2m<1>;
/// `GF(4)`.
pub type F4 = Gf2m<2>;
/// `GF(8)`.
pub type F8 = Gf2m<3>;
/// `GF(16)`.
pub type F16 = Gf2m<4>;
/// `GF(32)`.
pub type F32b = Gf2m<5>;
/// `GF(256)` — a byte-aligned binary cell for the embedded profile (spec §11.5).
pub type F256 = Gf2m<8>;

/// `GF(7)` — the primary illustrative prime cell of the test vectors (spec Appendix C).
pub type F7 = GfP<7>;
/// `GF(13)`.
pub type F13 = GfP<13>;
/// `GF(31)`.
pub type F31 = GfP<31>;
/// `GF(127)` — the large prime cell (`N = 16257`, spec §L1 scaling table).
pub type F127 = GfP<127>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise the full field axioms exhaustively for a small field `F`.
    fn check_axioms<F: Field>() {
        let q = F::Q;
        // Additive identity and inverse.
        for a in 0..q {
            assert_eq!(F::add(a, 0), a, "0 is additive identity");
            assert_eq!(F::add(a, F::neg(a)), 0, "additive inverse");
            assert_eq!(F::sub(a, a), 0, "self-subtraction");
            assert_eq!(F::mul(a, 0), 0, "0 absorbs");
            assert_eq!(F::mul(a, 1), a, "1 is multiplicative identity");
        }
        // Multiplicative inverse for every non-zero element.
        for a in 1..q {
            let ia = F::inv(a);
            assert_eq!(F::mul(a, ia), 1, "a·a⁻¹ = 1 in {:?} for a={a}", F::KIND);
            assert_eq!(F::div(a, a), 1, "a/a = 1");
        }
        // Commutativity, associativity, distributivity on all pairs/triples-lite.
        for a in 0..q {
            for b in 0..q {
                assert_eq!(F::add(a, b), F::add(b, a), "add commutes");
                assert_eq!(F::mul(a, b), F::mul(b, a), "mul commutes");
                assert_eq!(F::sub(F::add(a, b), b), a, "add/sub inverse");
                // distributivity a·(b+c) = a·b + a·c, sample c = (a^b) style third value
                let c = (a.wrapping_mul(2).wrapping_add(b + 1)) % q;
                let lhs = F::mul(a, F::add(b, c));
                let rhs = F::add(F::mul(a, b), F::mul(a, c));
                assert_eq!(lhs, rhs, "distributivity");
            }
        }
    }

    #[test]
    fn binary_fields_are_fields() {
        check_axioms::<F2>();
        check_axioms::<F4>();
        check_axioms::<F8>();
        check_axioms::<F16>();
        check_axioms::<F32b>();
        check_axioms::<F256>();
    }

    #[test]
    fn prime_fields_are_fields() {
        check_axioms::<F7>();
        check_axioms::<F13>();
        check_axioms::<F31>();
    }

    #[test]
    fn field_orders_match_spec() {
        assert_eq!(F2::Q, 2);
        assert_eq!(F256::Q, 256);
        assert_eq!(F7::Q, 7);
        assert_eq!(F127::Q, 127);
        assert_eq!(F2::KIND, FieldKind::Binary);
        assert_eq!(F7::KIND, FieldKind::Prime);
    }

    #[test]
    fn gf2_is_xor_and_and() {
        // In GF(2), addition is XOR and multiplication is AND.
        assert_eq!(F2::add(1, 1), 0);
        assert_eq!(F2::add(1, 0), 1);
        assert_eq!(F2::mul(1, 1), 1);
        assert_eq!(F2::mul(1, 0), 0);
        // The Fano mediator uses this: the third point of a line is the XOR of the other two.
        assert_eq!(F2::add(1, 1), F2::sub(1, 1));
    }

    #[test]
    fn known_prime_values() {
        // GF(7): 3·5 = 15 = 1 (mod 7); inverse of 3 is 5.
        assert_eq!(F7::mul(3, 5), 1);
        assert_eq!(F7::inv(3), 5);
        assert_eq!(F7::sub(2, 5), 4); // 2 - 5 = -3 = 4 (mod 7)
        assert_eq!(F7::neg(2), 5);
    }
}
