//! Property tests: onion routing delivers any payload through any valid threshold circuit.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_cmp
)]

use fanos_field::F31;
use fanos_geometry::Point;
use fanos_nyx::{PeelResult, Tessera, build_circuit, security};
use proptest::prelude::*;

const N31: usize = 993;

fn seed32(bytes: &[u8]) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (slot, b) in s.iter_mut().zip(bytes) {
        *slot = *b;
    }
    s
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// A Tessera routed through its threshold circuit delivers the exact payload, with the
    /// holonomy carried intact across every hop.
    #[test]
    fn onion_delivers_any_payload(
        payload in proptest::collection::vec(any::<u8>(), 0..64),
        si in 0..N31,
        di in 0..N31,
        hops in 1usize..5,
        seed_bytes in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        prop_assume!(si != di);
        let Some(circuit) = build_circuit(Point::<F31>::at(si), Point::<F31>::at(di), hops, &seed_bytes)
        else {
            return Ok(()); // a rare relay collision; nothing to assert
        };
        let seed = seed32(&seed_bytes);
        let mut packet = Tessera::build(&circuit, &payload, 6, 8, &seed).unwrap();
        let holonomy = packet.holonomy();

        let delivered = loop {
            let shares: Vec<_> = packet.current_hop_shares().iter().take(6).cloned().collect();
            match packet.peel(&shares).unwrap() {
                PeelResult::Forward { packet: inner, .. } => {
                    prop_assert_eq!(inner.holonomy(), holonomy);
                    packet = inner;
                }
                PeelResult::Deliver { payload } => break payload,
            }
        };
        prop_assert_eq!(delivered, payload);
    }

    /// Any built circuit is a valid flag chain of the requested length, derived deterministically.
    #[test]
    fn circuit_is_a_valid_flag_chain(
        si in 0..N31,
        di in 0..N31,
        hops in 1usize..6,
        seed in proptest::collection::vec(any::<u8>(), 1..24),
    ) {
        prop_assume!(si != di);
        if let Some(c) = build_circuit(Point::<F31>::at(si), Point::<F31>::at(di), hops, &seed) {
            prop_assert!(c.is_valid_flag_chain());
            prop_assert_eq!(c.hop_count(), hops);
            let again = build_circuit(Point::<F31>::at(si), Point::<F31>::at(di), hops, &seed).unwrap();
            prop_assert_eq!(c.relays(), again.relays());
        }
    }

    /// The threshold security curve is monotone in the adversary fraction, and
    /// `P_link = P_hop²` exactly.
    #[test]
    fn security_curve_is_monotone(f1 in 0.0f64..0.5, f2 in 0.0f64..0.5) {
        let (lo, hi) = (f1.min(f2), f1.max(f2));
        let p_lo = security::hop_compromise(8, 6, lo);
        let p_hi = security::hop_compromise(8, 6, hi);
        prop_assert!(p_lo <= p_hi + 1e-12, "P_hop is non-decreasing in f");
        let p = security::hop_compromise(8, 6, hi);
        prop_assert!((security::endpoint_linkage(8, 6, hi) - p * p).abs() < 1e-12);
    }
}
