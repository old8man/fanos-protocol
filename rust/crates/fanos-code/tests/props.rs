//! Property tests: fault localization and LRC recovery over *every* fault pattern.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_cmp
)]

use fanos_code::erasure;
use fanos_code::syndrome::{Fault, index_of_address};
use fanos_code::{hamming, is_hyperoval_fano, is_recoverable_fano, locate, syndrome3, theme_flags};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The verdict of `locate` is always consistent with the fault count (spec §6.3 strata).
    #[test]
    fn verdict_matches_fault_count(mask in 0u8..128) {
        let count = mask.count_ones();
        match locate(mask) {
            Fault::Healthy => prop_assert_eq!(count, 0),
            Fault::Single(i) => {
                prop_assert_eq!(count, 1);
                prop_assert_eq!(mask, 1u8 << i);
            }
            Fault::Pair(a, b) => {
                prop_assert_eq!(count, 2);
                prop_assert_eq!(mask, (1u8 << a) | (1u8 << b));
            }
            Fault::Escalate(_) => prop_assert!(count >= 3),
        }
    }

    /// Any ≤3 crashes recover; among 4-sets exactly the hyperovals fail (V20).
    #[test]
    fn lrc_recovery_boundary(mask in 0u8..128) {
        match mask.count_ones() {
            0..=3 => prop_assert!(is_recoverable_fano(mask)),
            4 => prop_assert_eq!(is_recoverable_fano(mask), !is_hyperoval_fano(mask)),
            _ => {}
        }
    }

    /// A single fault's 3-bit syndrome equals its address, and its themes are its 3 lines.
    #[test]
    fn single_fault_syndrome_is_its_address(i in 0..7usize) {
        let addr = hamming::point_address(i);
        prop_assert_eq!(syndrome3(1u8 << i), addr);
        prop_assert_eq!(theme_flags(1u8 << i).count_ones(), 3);
        prop_assert_eq!(index_of_address(addr), Some(i));
    }

    /// The Hamming(7,4) syndrome is the XOR of set-bit addresses, for every word.
    #[test]
    fn hamming_syndrome_is_address_xor(word in 0u8..128) {
        let mut expect = 0u8;
        for i in 0..7 {
            if word & (1 << i) != 0 {
                expect ^= (i + 1) as u8;
            }
        }
        prop_assert_eq!(hamming::syndrome(word), expect);
    }

    /// Two distinct faults always flag 5 lines and are localized as that exact pair (V21).
    #[test]
    fn two_faults_localize_exactly(i in 0..7usize, j in 0..7usize) {
        prop_assume!(i != j);
        let mask = (1u8 << i) | (1u8 << j);
        prop_assert_eq!(theme_flags(mask).count_ones(), 5);
        let (lo, hi) = (i.min(j), i.max(j));
        prop_assert_eq!(locate(mask), Fault::Pair(lo, hi));
    }

    /// Erasure round-trip (spec §L4, V9/V20): for arbitrary payload bytes and lengths,
    /// `reconstruct` recovers the exact payload iff the erasure mask peel-recovers under
    /// `is_recoverable_fano` — complementing `erasure.rs`'s own fixed-payload exhaustive test
    /// with random payload content/length.
    #[test]
    fn erasure_round_trip_matches_recoverability(
        data in proptest::collection::vec(any::<u8>(), 0..40),
        mask in 0u8..128,
    ) {
        let shards = erasure::encode(&data);
        let mut input: [Option<Vec<u8>>; erasure::N] = core::array::from_fn(|_| None);
        for p in 0..erasure::N {
            if mask & (1 << p) == 0 {
                input[p] = Some(shards[p].clone());
            }
        }
        let got = erasure::reconstruct(&input);
        if is_recoverable_fano(mask) {
            prop_assert_eq!(got, Some(data));
        } else {
            prop_assert_eq!(got, None);
        }
    }
}
