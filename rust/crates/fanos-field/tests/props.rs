//! Property-based tests: the field axioms must hold for *every* element, not just samples.
//!
//! These generate random elements of each field and assert the ring/field laws — the surest
//! way to reveal an arithmetic gap (a wrong reduction polynomial, an overflow, a bad inverse).

use fanos_field::{F2, F7, F13, F31, F127, F256, Field};
use proptest::prelude::*;

/// Emit the full field-axiom property suite for one field type.
macro_rules! field_axioms {
    ($name:ident, $F:ty) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            #[test]
            fn $name(
                a in 0..<$F>::Q,
                b in 0..<$F>::Q,
                c in 0..<$F>::Q,
            ) {
                // Commutativity.
                prop_assert_eq!(<$F>::add(a, b), <$F>::add(b, a));
                prop_assert_eq!(<$F>::mul(a, b), <$F>::mul(b, a));
                // Associativity.
                prop_assert_eq!(<$F>::add(<$F>::add(a, b), c), <$F>::add(a, <$F>::add(b, c)));
                prop_assert_eq!(<$F>::mul(<$F>::mul(a, b), c), <$F>::mul(a, <$F>::mul(b, c)));
                // Distributivity.
                prop_assert_eq!(
                    <$F>::mul(a, <$F>::add(b, c)),
                    <$F>::add(<$F>::mul(a, b), <$F>::mul(a, c))
                );
                // Identities.
                prop_assert_eq!(<$F>::add(a, 0), a);
                prop_assert_eq!(<$F>::mul(a, 1), a);
                prop_assert_eq!(<$F>::mul(a, 0), 0);
                // Additive inverse and subtraction.
                prop_assert_eq!(<$F>::add(a, <$F>::neg(a)), 0);
                prop_assert_eq!(<$F>::sub(<$F>::add(a, b), b), a);
                // Multiplicative inverse (non-zero) and division.
                if a != 0 {
                    prop_assert_eq!(<$F>::mul(a, <$F>::inv(a)), 1);
                    prop_assert_eq!(<$F>::div(b, a), <$F>::mul(b, <$F>::inv(a)));
                }
                // Outputs are always canonical (in range).
                prop_assert!(<$F>::in_range(<$F>::add(a, b)));
                prop_assert!(<$F>::in_range(<$F>::mul(a, b)));
                // reduce is idempotent on canonical elements.
                prop_assert_eq!(<$F>::reduce(u64::from(a)), a);
            }
        }
    };
}

field_axioms!(gf2, F2);
field_axioms!(gf7, F7);
field_axioms!(gf13, F13);
field_axioms!(gf31, F31);
field_axioms!(gf127, F127);
field_axioms!(gf256, F256);

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// `pow` agrees with repeated multiplication, and Fermat's little theorem holds.
    #[test]
    fn pow_and_fermat_gf127(a in 1..F127::Q, e in 0u64..40) {
        let mut acc = 1u32;
        for _ in 0..e {
            acc = F127::mul(acc, a);
        }
        prop_assert_eq!(F127::pow(a, e), acc);
        // a^(q-1) = 1 for non-zero a.
        prop_assert_eq!(F127::pow(a, u64::from(F127::Q) - 1), 1);
    }
}
