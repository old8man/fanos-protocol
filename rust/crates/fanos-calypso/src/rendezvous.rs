//! Computed rendezvous — no directory, rotates per epoch (spec §12.2).
//!
//! Client and service **independently derive** their meeting line from the service identity, the
//! epoch, and the epoch's randomness beacon:
//! `L_rdv = MapToLine(H("FANOS-v1/calypso" ‖ service_pubkey ‖ epoch ‖ beacon))`. Because it needs no
//! lookup there is **no HSDir to enumerate, block, or seize**; because it is keyed by the epoch it
//! **rotates every epoch**; and because it folds in the per-epoch **beacon** seed (audit E5), a future
//! epoch's line is **unpredictable in advance** — an adversary cannot pre-position on it. The beacon is
//! the distributed value from `fanos_vrf::beacon`; a bootstrap epoch may use [`BeaconSeed::GENESIS`]
//! until the first live round.

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::Line;
use fanos_primitives::hash::label;
use fanos_primitives::{BeaconSeed, Epoch, map_to_line};

/// The rendezvous line for a service at a given epoch (spec §12.2, audit E5). Both the client and the
/// service compute this — with no lookup — as `MapToLine(H(service_pubkey ‖ epoch ‖ beacon))`. The
/// per-epoch randomness `beacon` is what makes a *future* epoch's line unpredictable: without it the
/// line is a public function of the service key and epoch, so an adversary could compute every future
/// meeting line and pre-position on it. With it, the line is unknowable until the epoch's beacon is
/// revealed, yet still agreed by both parties once it is.
#[must_use]
pub fn rendezvous_line<F: Field>(
    service_pubkey: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
) -> Line<F> {
    let mut data = Vec::with_capacity(service_pubkey.len() + 4 + 32);
    data.extend_from_slice(service_pubkey);
    data.extend_from_slice(&epoch.low32_be_bytes());
    data.extend_from_slice(beacon.as_bytes());
    map_to_line::<F>(label::CALYPSO, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fanos_field::F31;

    /// A fixed non-genesis beacon seed for the derivation tests (a live epoch's public value).
    const BEACON: BeaconSeed = BeaconSeed::new([0x5B; 32]);

    #[test]
    fn both_parties_derive_the_same_line() {
        // The service and a client (holding the same pubkey + epoch + beacon) compute the same line.
        let pubkey = b"service-pubkey";
        let service_view = rendezvous_line::<F31>(pubkey, Epoch::new(7), &BEACON);
        let client_view = rendezvous_line::<F31>(pubkey, Epoch::new(7), &BEACON);
        assert_eq!(service_view, client_view);
    }

    #[test]
    fn the_line_rotates_every_epoch() {
        let pubkey = b"service-pubkey";
        let e0 = rendezvous_line::<F31>(pubkey, Epoch::new(0), &BEACON);
        let e1 = rendezvous_line::<F31>(pubkey, Epoch::new(1), &BEACON);
        assert_ne!(e0, e1, "no long-term target — L_rdv rotates per epoch");
    }

    #[test]
    fn the_line_depends_on_the_beacon() {
        // E5: for a fixed (pubkey, epoch), a different beacon seed yields a different line — so the line
        // for a future epoch is unknowable until that epoch's beacon is revealed.
        let pubkey = b"service-pubkey";
        let with_genesis = rendezvous_line::<F31>(pubkey, Epoch::new(7), &BeaconSeed::GENESIS);
        let with_live = rendezvous_line::<F31>(pubkey, Epoch::new(7), &BEACON);
        assert_ne!(
            with_genesis, with_live,
            "the meeting line folds in the epoch beacon (unpredictable-ahead)"
        );
    }

    #[test]
    fn distinct_services_meet_on_distinct_lines() {
        assert_ne!(
            rendezvous_line::<F31>(b"service-a", Epoch::new(3), &BEACON),
            rendezvous_line::<F31>(b"service-b", Epoch::new(3), &BEACON)
        );
    }

    #[test]
    fn derivation_is_total_at_the_epoch_and_pubkey_extremes() {
        // The derivation cannot fail, so exercise the input edges: the epoch counter's extremes and an
        // empty pubkey all yield stable, deterministic lines, and the extremes stay distinct.
        let pk = b"edge-service";
        assert_eq!(
            rendezvous_line::<F31>(pk, Epoch::new(u32::MAX as u64), &BEACON),
            rendezvous_line::<F31>(pk, Epoch::new(u32::MAX as u64), &BEACON),
            "u32::MAX epoch is deterministic"
        );
        assert_ne!(
            rendezvous_line::<F31>(pk, Epoch::new(0), &BEACON),
            rendezvous_line::<F31>(pk, Epoch::new(u32::MAX as u64), &BEACON),
            "the epoch counter's two extremes are distinct"
        );
        // An empty pubkey is a degenerate but valid input — still a stable line, no panic.
        assert_eq!(
            rendezvous_line::<F31>(&[], Epoch::new(5), &BEACON),
            rendezvous_line::<F31>(&[], Epoch::new(5), &BEACON)
        );
    }
}
