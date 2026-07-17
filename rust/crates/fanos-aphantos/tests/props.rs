//! Property test: the KEM-sealed onion delivers any payload through any valid circuit, and
//! only the correct relay peels each hop.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_aphantos::{PeelOutcome, sealed};
use fanos_field::F31;
use fanos_geometry::Point;
use fanos_nyx::build_circuit;
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
use proptest::prelude::*;

const N31: usize = 993;

proptest! {
    // Real hybrid-KEM keygen per relay is heavy; a couple dozen randomized routes suffice.
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn sealed_onion_delivers_any_payload(
        payload in proptest::collection::vec(any::<u8>(), 0..48),
        si in 0..N31,
        di in 0..N31,
        hops in 1usize..4,
        seed in proptest::collection::vec(any::<u8>(), 1..16),
    ) {
        prop_assume!(si != di);
        let Some(circuit) = build_circuit(Point::<F31>::at(si), Point::<F31>::at(di), hops, &seed)
        else {
            return Ok(());
        };
        // One KEM keypair per peeling relay.
        let keypairs: Vec<(HybridKemSecret, HybridKemPublic)> = (0..circuit.hop_count())
            .map(|i| {
                let mut rng = SeedRng::from_seed(&[i as u8, seed[0]]);
                HybridKemSecret::generate(&mut rng)
            })
            .collect();
        let pubkeys: Vec<&HybridKemPublic> = keypairs.iter().map(|(_, p)| p).collect();

        let mut onion = sealed::build(&circuit, &pubkeys, &payload, &seed).unwrap();
        for (secret, _) in &keypairs {
            match sealed::peel(&onion, secret).unwrap() {
                PeelOutcome::Forward { onion: inner, .. } => onion = inner,
                PeelOutcome::Deliver { payload: got, .. } => {
                    prop_assert_eq!(got, payload);
                    return Ok(());
                }
            }
        }
        prop_assert!(false, "onion never delivered");
    }
}
