//! # fanos-calypso — anonymous hidden services (Part XII)
//!
//! A hidden service that is present but unlocatable, **without** the directory and
//! introduction-point infrastructure that are Tor's known deanonymization and DoS surface.
//! CALYPSO removes them: the meeting point is *computed, not published*, and a service may be
//! hosted by a **threshold group with no single physical location**.
//!
//! * [`address`] — self-certifying `.fanos` addresses (§12.1).
//! * [`rendezvous`] — the computed, per-epoch-rotating rendezvous line (§12.2).
//! * [`hosting`] — threshold hosting: no single host to raid (§12.3).
//! * [`pow`] — introduction proof-of-work for DoS resistance (§12.5).
//!
//! [`HiddenService`] ties the service side together; [`client_meeting_line`] is the client
//! side. Both derive the *same* rendezvous line with no lookup.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod balance;
pub mod descriptor;
pub mod hosting;
pub mod pow;
pub mod rendezvous;
pub mod stabilize;

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::Line;

pub use balance::{InstanceRef, MasterDescriptor, master_descriptor_key};
pub use rendezvous::rendezvous_line;

// A CALYPSO service address *is* an ONOMA address (the self-certifying `.fanos` name system):
// the post-quantum, bech32m, version-agile L-key. `ServiceAddress` is retained as the
// domain-meaningful alias used across the services code.
pub use fanos_onoma::Address;
pub use fanos_onoma::Address as ServiceAddress;
pub use fanos_primitives::{BeaconSeed, Epoch};

/// A hidden service — its public key and self-certifying address (spec Part XII).
pub struct HiddenService {
    pubkey: Vec<u8>,
    address: ServiceAddress,
}

impl HiddenService {
    /// Publish a service under its public-key bytes; the address is derived (self-certifying).
    #[must_use]
    pub fn new(pubkey: Vec<u8>) -> Self {
        let address = ServiceAddress::from_bundle(&pubkey);
        Self { pubkey, address }
    }

    /// The `.fanos` address.
    #[must_use]
    pub fn address(&self) -> &ServiceAddress {
        &self.address
    }

    /// The service's public-key bytes.
    #[must_use]
    pub fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    /// The service's rendezvous line for `epoch` under the epoch's randomness `beacon` (spec §12.2,
    /// audit E5).
    #[must_use]
    pub fn rendezvous_line<F: Field>(&self, epoch: Epoch, beacon: &BeaconSeed) -> Line<F> {
        rendezvous_line::<F>(&self.pubkey, epoch, beacon)
    }
}

/// The client side: given a `.fanos` address and the service's public key, verify the address
/// self-certifies the key and derive the same rendezvous line the service uses for `epoch` under its
/// randomness `beacon` (spec §12.2, audit E5). Returns `None` if the address does not certify the key.
#[must_use]
pub fn client_meeting_line<F: Field>(
    address: &ServiceAddress,
    service_pubkey: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> Option<Line<F>> {
    address
        .verifies(service_pubkey)
        .then(|| rendezvous_line::<F>(service_pubkey, epoch, beacon))
}

/// The L4 storage key under which a service publishes its contact descriptor for `epoch` under the
/// epoch's randomness `beacon` — the rendezvous realized over the distributed store (spec §12.2, audit
/// E5). Both the service and any client with the service's public key derive it identically; it rotates
/// every epoch *and* with the beacon, so a censor can neither pin a static location nor pre-compute the
/// next epoch's. The overlay hashes this to a responsible point (`MapToPoint`).
#[must_use]
pub fn descriptor_key(service_pubkey: &[u8], epoch: Epoch, beacon: &BeaconSeed) -> Vec<u8> {
    let mut key = Vec::with_capacity(service_pubkey.len() + 4 + 32);
    key.extend_from_slice(service_pubkey);
    key.extend_from_slice(&epoch.low32_be_bytes());
    key.extend_from_slice(beacon.as_bytes());
    key
}

/// The client's descriptor key, gated on the address self-certifying the key (spec §12.2). Returns
/// `None` for a forged public key — the client never contacts a service whose address it cannot
/// verify.
#[must_use]
pub fn client_descriptor_key(
    address: &ServiceAddress,
    service_pubkey: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> Option<Vec<u8>> {
    address
        .verifies(service_pubkey)
        .then(|| descriptor_key(service_pubkey, epoch, beacon))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    //! The end-to-end CALYPSO contact flow, without a directory.
    use super::*;
    use fanos_field::F31;

    /// A fixed non-genesis beacon seed standing for a live epoch's public beacon value.
    const BEACON: BeaconSeed = BeaconSeed::new([0xC1; 32]);

    #[test]
    fn client_and_service_meet_with_no_directory() {
        // The service publishes a self-certifying address.
        let service = HiddenService::new(b"service-hybrid-pubkey".to_vec());
        let address = *service.address();

        // A client that learns (address, pubkey) verifies the binding and computes the SAME
        // rendezvous line the service listens on — no HSDir lookup anywhere.
        let epoch = Epoch::new(42);
        let client_line = client_meeting_line::<F31>(&address, service.pubkey(), epoch, &BEACON)
            .expect("certifies");
        assert_eq!(client_line, service.rendezvous_line::<F31>(epoch, &BEACON));

        // A forged pubkey that does not match the address is rejected.
        assert!(client_meeting_line::<F31>(&address, b"forged", epoch, &BEACON).is_none());
    }

    #[test]
    fn the_meeting_point_moves_every_epoch() {
        let service = HiddenService::new(b"svc".to_vec());
        assert_ne!(
            service.rendezvous_line::<F31>(Epoch::new(100), &BEACON),
            service.rendezvous_line::<F31>(Epoch::new(101), &BEACON)
        );
    }

    #[test]
    fn full_flow_address_rendezvous_pow_threshold() {
        // Address + rendezvous + a PoW-gated intro + threshold hosting, composed.
        let service = HiddenService::new(b"whole-flow-key".to_vec());
        let line = service.rendezvous_line::<F31>(Epoch::new(7), &BEACON);
        assert!(line.coords()[0] <= 1); // canonical line

        // The client attaches a PoW to its intro cookie.
        let cookie = b"intro-cookie";
        let nonce = pow::solve(cookie, 12);
        assert!(pow::verify(cookie, nonce, 12));

        // The service is hosted 5-of-8; any 5 members serve, fewer learn nothing.
        let rnd: Vec<u8> = (0..4 * 16).map(|i| (i as u8).wrapping_mul(31)).collect();
        let shares = hosting::shard_service_key(b"service-secret!!", 5, 8, &rnd).unwrap();
        assert_eq!(
            hosting::recover_service_key(&shares[0..5]).unwrap(),
            b"service-secret!!"
        );
    }
}
