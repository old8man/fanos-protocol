//! Computed rendezvous — no directory, rotates per epoch (spec §12.2).
//!
//! Client and service **independently derive** their meeting line from the service identity
//! and the epoch: `L_rdv = MapToLine(VRF_beacon(H("FANOS-v1/calypso" ‖ service_pubkey), epoch))`.
//! Because it is a public function of the identity and epoch, there is **no HSDir to enumerate,
//! block, or seize**, and because it is keyed by the epoch it **rotates every epoch** — no
//! long-term target to surveil. (The reference build uses the deterministic epoch derivation
//! in place of the beacon VRF, marked `[C]` on the beacon as in the specification.)

use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::Line;
use fanos_primitives::hash::label;
use fanos_primitives::{Epoch, map_to_line};

/// The rendezvous line for a service at a given epoch (spec §12.2). Both the client and the
/// service compute this — with no lookup.
#[must_use]
pub fn rendezvous_line<F: Field>(service_pubkey: &[u8], epoch: Epoch) -> Line<F> {
    let mut data = Vec::with_capacity(service_pubkey.len() + 4);
    data.extend_from_slice(service_pubkey);
    data.extend_from_slice(&epoch.low32_be_bytes());
    map_to_line::<F>(label::CALYPSO, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fanos_field::F31;

    #[test]
    fn both_parties_derive_the_same_line() {
        // The service and a client (holding the same pubkey + epoch) compute the same line.
        let pubkey = b"service-pubkey";
        let service_view = rendezvous_line::<F31>(pubkey, Epoch::new(7));
        let client_view = rendezvous_line::<F31>(pubkey, Epoch::new(7));
        assert_eq!(service_view, client_view);
    }

    #[test]
    fn the_line_rotates_every_epoch() {
        let pubkey = b"service-pubkey";
        let e0 = rendezvous_line::<F31>(pubkey, Epoch::new(0));
        let e1 = rendezvous_line::<F31>(pubkey, Epoch::new(1));
        assert_ne!(e0, e1, "no long-term target — L_rdv rotates per epoch");
    }

    #[test]
    fn distinct_services_meet_on_distinct_lines() {
        assert_ne!(
            rendezvous_line::<F31>(b"service-a", Epoch::new(3)),
            rendezvous_line::<F31>(b"service-b", Epoch::new(3))
        );
    }

    #[test]
    fn derivation_is_total_at_the_epoch_and_pubkey_extremes() {
        // The derivation cannot fail, so exercise the input edges: the epoch counter's extremes and an
        // empty pubkey all yield stable, deterministic lines, and the extremes stay distinct.
        let pk = b"edge-service";
        assert_eq!(
            rendezvous_line::<F31>(pk, Epoch::new(u32::MAX as u64)),
            rendezvous_line::<F31>(pk, Epoch::new(u32::MAX as u64)),
            "u32::MAX epoch is deterministic"
        );
        assert_ne!(
            rendezvous_line::<F31>(pk, Epoch::new(0)),
            rendezvous_line::<F31>(pk, Epoch::new(u32::MAX as u64)),
            "the epoch counter's two extremes are distinct"
        );
        // An empty pubkey is a degenerate but valid input — still a stable line, no panic.
        assert_eq!(
            rendezvous_line::<F31>(&[], Epoch::new(5)),
            rendezvous_line::<F31>(&[], Epoch::new(5))
        );
    }
}
