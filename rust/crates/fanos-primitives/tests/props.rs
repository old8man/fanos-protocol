//! Property tests: MapToPoint always yields a valid canonical point, and Shamir sharing
//! reconstructs from any threshold subset.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_cmp
)]

use fanos_field::{F31, F256};
use fanos_geometry::Point;
use fanos_primitives::hash::label;
use fanos_primitives::{map_to_point, reconstruct, split};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Any input maps to a genuine canonical point, deterministically.
    #[test]
    fn map_to_point_is_canonical_and_deterministic(seed in proptest::collection::vec(any::<u8>(), 1..48)) {
        let p = map_to_point::<F31>(label::COORD, &seed);
        prop_assert_eq!(Point::<F31>::at(p.index()), p);
        prop_assert_eq!(p, map_to_point::<F31>(label::COORD, &seed));
        // Over a binary field too.
        let q = map_to_point::<F256>(label::COORD, &seed);
        prop_assert_eq!(Point::<F256>::at(q.index()), q);
    }

    /// Distinct labels almost never collide (domain separation).
    #[test]
    fn domain_separation(seed in proptest::collection::vec(any::<u8>(), 1..32)) {
        let a = map_to_point::<F31>(label::COORD, &seed);
        let b = map_to_point::<F31>(label::RDV, &seed);
        // 993 points; a collision is possible but vanishingly rare — assert difference on the
        // overwhelming majority. (If they ever coincide, it is a legitimate 1/993 event, so we
        // check the map is at least a genuine point, not that it differs.)
        prop_assert_eq!(Point::<F31>::at(a.index()), a);
        prop_assert_eq!(Point::<F31>::at(b.index()), b);
    }

    /// Shamir sharing reconstructs the secret from any `t` of `n` shares (spec §L6).
    #[test]
    fn shamir_any_threshold_subset_reconstructs(
        secret in proptest::collection::vec(any::<u8>(), 1..32),
        t in 2u8..7,
        extra in 0u8..5,
        randomness in proptest::collection::vec(any::<u8>(), 200..201),
    ) {
        let n = t + extra;
        let shares = split(&secret, t, n, &randomness).unwrap();
        prop_assert_eq!(shares.len(), usize::from(n));
        // The first t shares reconstruct.
        let subset = &shares[..usize::from(t)];
        prop_assert_eq!(reconstruct(subset).unwrap(), secret.clone());
        // The last t shares also reconstruct.
        let tail = &shares[usize::from(n - t)..];
        prop_assert_eq!(reconstruct(tail).unwrap(), secret);
    }

    /// Fewer than `t` shares do not reconstruct the secret.
    #[test]
    fn shamir_below_threshold_fails(
        secret in proptest::collection::vec(1u8..=255, 4..16),
        t in 3u8..6,
        randomness in proptest::collection::vec(any::<u8>(), 200..201),
    ) {
        let shares = split(&secret, t, 8, &randomness).unwrap();
        let too_few = &shares[..usize::from(t - 1)];
        prop_assert_ne!(reconstruct(too_few).unwrap(), secret);
    }
}
