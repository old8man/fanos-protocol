//! Property tests: self-certifying addresses and computed rendezvous over random services.

#![allow(clippy::unwrap_used)]

use fanos_calypso::{
    BeaconSeed, Epoch, HiddenService, ServiceAddress, client_meeting_line, pow, rendezvous_line,
};
use fanos_field::F31;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// An address always certifies its own key, and never a different one.
    #[test]
    fn address_self_certifies(
        pubkey in proptest::collection::vec(any::<u8>(), 1..64),
        other in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        let address = ServiceAddress::from_bundle(&pubkey);
        prop_assert!(address.verifies(&pubkey));
        if pubkey != other {
            prop_assert!(!address.verifies(&other));
        }
    }

    /// The rendezvous line is a deterministic public function; client and service agree, with
    /// no directory (spec §12.2).
    #[test]
    fn client_and_service_derive_the_same_line(
        pubkey in proptest::collection::vec(any::<u8>(), 1..48),
        epoch in 0u32..100_000,
        beacon_bytes in any::<[u8; 32]>(),
    ) {
        let epoch = Epoch::new(epoch.into());
        let beacon = BeaconSeed::new(beacon_bytes);
        let service = HiddenService::new(pubkey.clone());
        // All three derivations (client, service method, free function) agree for any beacon.
        let line = client_meeting_line::<F31>(service.address(), &pubkey, epoch, &beacon).unwrap();
        prop_assert_eq!(line, service.rendezvous_line::<F31>(epoch, &beacon));
        prop_assert_eq!(rendezvous_line::<F31>(&pubkey, epoch, &beacon), line);
    }

    /// A PoW solution verifies and also satisfies any lower difficulty.
    #[test]
    fn pow_solutions_verify(challenge in proptest::collection::vec(any::<u8>(), 0..32), difficulty in 0u32..12) {
        let nonce = pow::solve(&challenge, difficulty);
        prop_assert!(pow::verify(&challenge, nonce, difficulty));
        if difficulty > 0 {
            prop_assert!(pow::verify(&challenge, nonce, difficulty - 1));
        }
    }
}
