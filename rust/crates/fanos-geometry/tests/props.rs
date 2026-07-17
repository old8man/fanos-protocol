//! Property tests: the projective axioms must hold for *every* point/line pair.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_cmp
)]

use fanos_field::{F7, F31};
use fanos_geometry::element::is_canonical;
use fanos_geometry::{Line, Point, canonicalize};
use proptest::prelude::*;

const N7: usize = 57; // Plane::<F7>::N
const N31: usize = 993; // Plane::<F31>::N

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Steiner (points) and its dual (lines): any two distinct objects join/meet uniquely.
    #[test]
    fn steiner_and_dual(i in 0..N7, j in 0..N7) {
        let a = Point::<F7>::at(i);
        let b = Point::<F7>::at(j);
        if a == b {
            prop_assert!(a.join(&b).is_none(), "no unique line to self");
        } else {
            let l = a.join(&b).unwrap();
            prop_assert!(a.is_on(&l));
            prop_assert!(b.is_on(&l));
            prop_assert_eq!(l, b.join(&a).unwrap(), "join is symmetric/unique");
        }

        let la = Line::<F7>::at(i);
        let lb = Line::<F7>::at(j);
        if la != lb {
            let p = la.meet(&lb).unwrap();
            prop_assert!(la.contains(&p) && lb.contains(&p), "meet on both lines");
        }
    }

    /// Point/line indexing is a bijection with `0..N`.
    #[test]
    fn index_bijection(i in 0..N31) {
        prop_assert_eq!(Point::<F31>::at(i).index(), i);
        prop_assert_eq!(Line::<F31>::at(i).index(), i);
    }

    /// Two lines through a common point meet exactly at that point (the bridge property).
    #[test]
    fn bridge_recovers_the_common_point(i in 0..N7, j in 0..N7, k in 0..N7) {
        let (a, b, c) = (Point::<F7>::at(i), Point::<F7>::at(j), Point::<F7>::at(k));
        if a != b && a != c {
            let l1 = a.join(&b).unwrap();
            let l2 = a.join(&c).unwrap();
            if l1 != l2 {
                prop_assert_eq!(l1.meet(&l2).unwrap(), a);
            }
        }
    }

    /// Canonicalization is idempotent and produces canonical output for any non-zero triple.
    #[test]
    fn canonicalization_is_idempotent(x in 0..7u32, y in 0..7u32, z in 0..7u32) {
        if let Some(c) = canonicalize::<F7>([x, y, z]) {
            prop_assert!(is_canonical(c));
            prop_assert_eq!(canonicalize::<F7>(c), Some(c));
        }
    }

    /// The cross-product identity `(u × v) · u = 0`: the join always contains its operands.
    #[test]
    fn cross_product_annihilates_operands(i in 0..N31, j in 0..N31) {
        let a = Point::<F31>::at(i);
        let b = Point::<F31>::at(j);
        if a != b {
            let l = a.join(&b).unwrap();
            prop_assert!(a.is_on(&l) && b.is_on(&l));
        }
    }
}
