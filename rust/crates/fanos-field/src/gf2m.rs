//! Binary extension fields `GF(2^m)` (spec §2.1, default binary profile).

use crate::{Field, FieldKind};

/// The field `GF(2^M)`, elements packed as the low `M` bits of a `u32`.
///
/// Addition is XOR; multiplication is carry-less polynomial multiplication reduced modulo
/// a fixed irreducible polynomial of degree `M` (see [`irreducible`]). Supported degrees
/// are `1..=16` (orders `2..=65536`), which covers every cell size the specification uses
/// (`GF(2)` for the base Fano cell, byte-aligned `GF(256)` for embedded, up to `GF(2^16)`).
///
/// The reduction is the classic shift-and-reduce ("Russian-peasant") loop: correct,
/// branch-predictable, `const`-evaluable, and — because the inner step is data-independent
/// on the secret operand — a sound basis for a constant-time build. On targets with a
/// carry-less multiply instruction (`PMULL` on AArch64, `PCLMULQDQ` on x86-64) this loop is
/// the portable fallback; an accelerated path can replace [`Gf2m::clmul`] without changing
/// any caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Gf2m<const M: u32>;

/// A degree-`m` irreducible (in fact primitive) polynomial over `GF(2)`, encoded with its
/// leading `x^m` term, i.e. bit `m` is set. Returns `0` for unsupported degrees.
///
/// These are the standard low-weight primitive polynomials; primitivity is not required for
/// correctness of the arithmetic (any irreducible works) but keeps the door open for
/// log/antilog acceleration tables where element `x` generates the multiplicative group.
pub const fn irreducible(m: u32) -> u32 {
    match m {
        1 => 0b11,        // x + 1
        2 => 0b111,       // x^2 + x + 1
        3 => 0b1011,      // x^3 + x + 1
        4 => 0b1_0011,    // x^4 + x + 1
        5 => 0b10_0101,   // x^5 + x^2 + 1
        6 => 0b100_0011,  // x^6 + x + 1
        7 => 0b1000_0011, // x^7 + x + 1
        8 => 0x11D,       // x^8 + x^4 + x^3 + x^2 + 1
        9 => 0x211,       // x^9 + x^4 + 1
        10 => 0x409,      // x^10 + x^3 + 1
        11 => 0x805,      // x^11 + x^2 + 1
        12 => 0x1053,     // x^12 + x^6 + x^4 + x + 1
        13 => 0x201B,     // x^13 + x^4 + x^3 + x + 1
        14 => 0x4443,     // x^14 + x^10 + x^6 + x + 1
        15 => 0x8003,     // x^15 + x + 1
        16 => 0x1_100B,   // x^16 + x^12 + x^3 + x + 1
        _ => 0,
    }
}

impl<const M: u32> Gf2m<M> {
    /// The reduction polynomial (with its `x^m` term), fixed for this degree.
    const POLY: u32 = irreducible(M);
    /// A mask selecting the low `M` bits — the valid element range.
    const MASK: u32 = if M >= 32 { u32::MAX } else { (1u32 << M) - 1 };

    /// Carry-less multiply of two field elements, reduced modulo [`Self::POLY`].
    ///
    /// This is the single arithmetic kernel of the binary field; [`Field::mul`] delegates
    /// here. Kept `pub(crate)` and `const` so tables and tests can call it directly.
    #[inline]
    pub(crate) const fn clmul(a: u32, b: u32) -> u32 {
        const {
            assert!(
                M >= 1 && M <= 16 && irreducible(M) != 0,
                "fanos-field: GF(2^m) supports only degrees m in 1..=16",
            );
        }
        let mut a = a & Self::MASK;
        let mut b = b & Self::MASK;
        let mut acc = 0u32;
        let mut i = 0;
        while i < M {
            // Add a shifted copy of `a` for each set bit of `b` — **branchless**: a mask of all-ones (iff
            // the low bit is set) or all-zeros replaces the `if`, so this multiply runs in data-independent
            // time and leaks nothing about the operands. It is used on secret Shamir shares (audit B7).
            let add_mask = 0u32.wrapping_sub(b & 1);
            acc ^= a & add_mask;
            b >>= 1;
            // Multiply `a` by x, reducing by the field polynomial when the degree would reach `m` — also
            // branchless: XOR `POLY` under a mask derived from the top bit, never a conditional jump.
            let reduce_mask = 0u32.wrapping_sub((a >> (M - 1)) & 1);
            a = ((a << 1) ^ (Self::POLY & reduce_mask)) & Self::MASK;
            i += 1;
        }
        acc & Self::MASK
    }
}

impl<const M: u32> Field for Gf2m<M> {
    const Q: u32 = 1u32 << M;
    const P: u32 = 2;
    const M: u32 = M;
    const KIND: FieldKind = FieldKind::Binary;

    #[inline(always)]
    fn add(a: u32, b: u32) -> u32 {
        (a ^ b) & Self::MASK
    }
    #[inline(always)]
    fn sub(a: u32, b: u32) -> u32 {
        // In characteristic 2, subtraction is addition.
        (a ^ b) & Self::MASK
    }
    #[inline(always)]
    fn neg(a: u32) -> u32 {
        a & Self::MASK
    }
    #[inline(always)]
    fn mul(a: u32, b: u32) -> u32 {
        Self::clmul(a, b)
    }
    #[inline(always)]
    fn reduce(x: u64) -> u32 {
        (x as u32) & Self::MASK
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{F8, F16, F256};

    #[test]
    fn multiplication_is_associative_over_gf256() {
        // A stronger check than lib.rs's pairwise pass: full associativity on a sample grid.
        for a in (0..256).step_by(7) {
            for b in (0..256).step_by(5) {
                for c in (0..256).step_by(11) {
                    let l = F256::mul(F256::mul(a, b), c);
                    let r = F256::mul(a, F256::mul(b, c));
                    assert_eq!(l, r, "assoc fails at {a},{b},{c}");
                }
            }
        }
    }

    #[test]
    fn every_nonzero_has_unique_inverse() {
        for a in 1..F8::Q {
            let inv = F8::inv(a);
            assert_eq!(F8::mul(a, inv), 1);
        }
    }

    #[test]
    fn generator_x_has_full_order_when_primitive() {
        // For a primitive polynomial, element x=2 generates the whole multiplicative group:
        // its powers cycle with period q-1. Verify for GF(16).
        let mut seen = [false; 16];
        let mut cur = 1u32;
        for _ in 0..(F16::Q - 1) {
            assert!(!seen[cur as usize], "x is not primitive for GF(16)");
            seen[cur as usize] = true;
            cur = F16::mul(cur, 2);
        }
        assert_eq!(cur, 1, "x^(q-1) = 1");
    }
}

/// The constant-time experiment (spec §16, `docs/design-constant-time.md`): a deterministic proof that the
/// `GF(2^m)` inversion ladder performs a **secret-independent** number of field multiplications, so it leaks
/// nothing about the secret operand through timing. Non-flaky (an operation-count invariant, not a timing
/// measurement).
#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod ct_experiment {
    use core::cell::Cell;

    use crate::{Field, FieldKind, F256};

    std::thread_local! {
        /// Counts field multiplications performed by the [`Counting`] field.
        static MULS: Cell<u64> = const { Cell::new(0) };
    }

    /// A field that delegates to `GF(256)` but tallies every multiplication — an instrument to measure the
    /// inversion ladder's multiply-count, a deterministic proxy for constant-timeness.
    #[derive(Clone, Copy, Debug)]
    struct Counting;

    impl Field for Counting {
        const Q: u32 = F256::Q;
        const P: u32 = 2;
        const M: u32 = 8;
        const KIND: FieldKind = FieldKind::Binary;

        fn add(a: u32, b: u32) -> u32 {
            F256::add(a, b)
        }
        fn sub(a: u32, b: u32) -> u32 {
            F256::sub(a, b)
        }
        fn neg(a: u32) -> u32 {
            F256::neg(a)
        }
        fn mul(a: u32, b: u32) -> u32 {
            MULS.with(|c| c.set(c.get() + 1));
            F256::mul(a, b)
        }
        fn reduce(x: u64) -> u32 {
            F256::reduce(x)
        }
    }

    #[test]
    fn the_inversion_ladder_is_secret_independent() {
        let mut counts = Vec::with_capacity((F256::Q - 1) as usize);
        for a in 1..F256::Q {
            MULS.with(|c| c.set(0));
            let inv = Counting::inv(a);
            // The counting wrapper computes the genuine inverse (it exercises the real algorithm).
            assert_eq!(F256::mul(a, inv), 1, "the instrumented field still inverts a={a}");
            counts.push(MULS.with(Cell::get));
        }
        // The load-bearing constant-time property: EVERY one of the 255 secret inputs drives exactly the
        // same number of field multiplications, because the a^(q−2) square-and-multiply ladder branches only
        // on the PUBLIC exponent (q−2 = 254), never on the secret base `a`.
        let first = counts[0];
        assert!(counts.iter().all(|&c| c == first), "inv multiply-count varies with the secret: {counts:?}");
        // For e = 254 = 0b1111_1110 the fixed ladder is 8 squarings + 7 conditional multiplies = 15.
        assert_eq!(first, 15, "the secret-independent ladder performs the fixed 15 multiplications");
    }
}
