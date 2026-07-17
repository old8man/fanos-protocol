//! Prime fields `GF(p)` (spec §2.1, illustrative cells `q ∈ {2, 7, 13, 31, 127}`).

use crate::{Field, FieldKind};

/// The prime field `GF(MODULUS)` with elements represented as residues `0..MODULUS`.
///
/// `MODULUS` must be prime; this is asserted at compile time (post-monomorphization) the
/// first time the field is multiplied, so a mistaken `GfP<9>` fails to build rather than
/// silently computing in a non-field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct GfP<const MODULUS: u32>;

/// Trial-division primality test, `const` so it can gate field instantiation.
pub const fn is_prime(n: u32) -> bool {
    if n < 2 {
        return false;
    }
    if n.is_multiple_of(2) {
        return n == 2;
    }
    let mut i = 3u32;
    while i.saturating_mul(i) <= n {
        if n.is_multiple_of(i) {
            return false;
        }
        i += 2;
    }
    true
}

impl<const MODULUS: u32> GfP<MODULUS> {
    const _CHECK: () = assert!(
        is_prime(MODULUS),
        "fanos-field: GfP<MODULUS> requires a prime MODULUS",
    );
}

impl<const MODULUS: u32> Field for GfP<MODULUS> {
    const Q: u32 = MODULUS;
    const P: u32 = MODULUS;
    const M: u32 = 1;
    const KIND: FieldKind = FieldKind::Prime;

    #[inline(always)]
    fn add(a: u32, b: u32) -> u32 {
        // a, b < MODULUS, so the sum fits in u64 with no overflow and one conditional subtract.
        let s = a as u64 + b as u64;
        (if s >= MODULUS as u64 {
            s - MODULUS as u64
        } else {
            s
        }) as u32
    }
    #[inline(always)]
    fn sub(a: u32, b: u32) -> u32 {
        if a >= b { a - b } else { a + MODULUS - b }
    }
    #[inline(always)]
    fn neg(a: u32) -> u32 {
        if a == 0 { 0 } else { MODULUS - a }
    }
    #[inline(always)]
    fn mul(a: u32, b: u32) -> u32 {
        // Force the compile-time primality check to be evaluated for this monomorphization.
        let () = Self::_CHECK;
        ((a as u64 * b as u64) % MODULUS as u64) as u32
    }
    #[inline(always)]
    fn reduce(x: u64) -> u32 {
        (x % MODULUS as u64) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{F7, F13, F31, F127};

    #[test]
    fn primality_gate() {
        assert!(is_prime(2));
        assert!(is_prime(7));
        assert!(is_prime(127));
        assert!(!is_prime(1));
        assert!(!is_prime(9));
        assert!(!is_prime(21));
        assert!(!is_prime(0));
    }

    #[test]
    fn wilson_theorem_holds() {
        // Wilson: (p-1)! ≡ -1 (mod p) for prime p. A cross-check that mul/mod are correct.
        for &p_fact in &[
            check_wilson::<F7>(),
            check_wilson::<F13>(),
            check_wilson::<F31>(),
        ] {
            assert!(p_fact);
        }
    }

    fn check_wilson<F: Field>() -> bool {
        let mut acc = 1u32;
        for a in 1..F::Q - 1 {
            acc = F::mul(acc, a);
        }
        acc = F::mul(acc, F::Q - 1);
        F::add(acc, 1) == 0 // (p-1)! + 1 ≡ 0
    }

    #[test]
    fn inverses_via_fermat_match_bruteforce() {
        for a in 1..F127::Q {
            let inv = F127::inv(a);
            // brute-force search the inverse and compare
            let mut found = 0;
            for b in 1..F127::Q {
                if F127::mul(a, b) == 1 {
                    found = b;
                    break;
                }
            }
            assert_eq!(inv, found, "inverse mismatch for {a} in GF(127)");
        }
    }
}
