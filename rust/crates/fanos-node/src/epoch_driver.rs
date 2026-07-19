//! The E4∩E5 epoch driver — rotate a mix-relay's forward-secure onion key off the randomness beacon.
//!
//! A mix-relay hosts a [`ThresholdRouter`](fanos_aphantos::ThresholdRouter) (spawned with an onion-ratchet
//! genesis `onion_seed`) and a [`BeaconNode`](fanos_keygen::BeaconNode). When the beacon adopts a new
//! epoch it emits [`Notification::BeaconReady`](fanos_runtime::Notification::BeaconReady); on that signal
//! the relay must, in lock-step:
//!
//! 1. **rotate** its forward-secure onion key one epoch (E4 — a recorded onion becomes unpeelable once
//!    the relay ratchets past its epoch), by issuing `Command::AdvanceEpoch` to the hosted router;
//! 2. **republish** its now-current onion public at the `(coord, epoch)` mixdir slot ([`publish_mix_key`](
//!    crate::publish_mix_key)), so a client building a circuit for the new epoch seals to a key the relay
//!    can still peel with; and
//! 3. fold the beacon **seed** into its rendezvous meeting line (E5) — the same seed every party adopts.
//!
//! [`EpochDriver`] is the pure, testable core of steps 1–2: it holds a ratchet parallel to the router's
//! (from the same `onion_seed`), so it computes the epoch's onion *public* to publish without reaching
//! into the spawned engine — both derive the identical key deterministically, so the driver publishes
//! exactly what the router will peel with. The async node loop is thin glue around it (see the example).

use fanos_diaulos::Coord;
use fanos_pqcrypto::OnionKeyRatchet;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_rendezvous::Epoch;

/// Drives a mix-relay's per-epoch onion-key rotation from the beacon (audit E4∩E5). Monotone: a stale or
/// replayed beacon epoch is ignored.
///
/// Usage — the async mix-relay node loop that ties the beacon, the router, and mixdir together:
/// ```ignore
/// let mut driver = EpochDriver::new(coord, onion_seed);
/// while let Some(note) = beacon.next_notification().await {
///     if let Notification::BeaconReady { epoch, seed } = note {
///         let steps = driver.advance_to(epoch);
///         for _ in 0..steps {
///             router.command(Command::AdvanceEpoch); // rotate the forward-secure onion key (E4)
///         }
///         if steps > 0 {
///             // republish so clients seal to the current epoch's key (E4 discovery)
///             publish_mix_key(&client, driver.coord(), driver.epoch(), driver.public()).await;
///         }
///         rendezvous_seed = BeaconSeed::from(seed); // fold into meeting_line (E5)
///     }
/// }
/// ```
pub struct EpochDriver {
    coord: Coord,
    ratchet: OnionKeyRatchet,
}

impl EpochDriver {
    /// A driver for the mix-relay at `coord` with onion-ratchet genesis `onion_seed` — the **same** seed
    /// the hosted [`ThresholdRouter`](fanos_aphantos::ThresholdRouter) was spawned with, so the two
    /// ratchets stay in lock-step. Starts at [`Epoch::ZERO`].
    #[must_use]
    pub fn new(coord: Coord, onion_seed: [u8; 32]) -> Self {
        Self {
            coord,
            ratchet: OnionKeyRatchet::new(onion_seed, Epoch::ZERO),
        }
    }

    /// This relay's coordinate — where its onion public is published.
    #[must_use]
    pub fn coord(&self) -> Coord {
        self.coord
    }

    /// The epoch the driver — and, in lock-step, the hosted router — is currently at.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.ratchet.epoch()
    }

    /// The current epoch's onion **public** key — what to (re)publish at the mixdir slot so clients seal
    /// to a key the router can still peel with.
    #[must_use]
    pub fn public(&self) -> &HybridKemPublic {
        self.ratchet.public()
    }

    /// Advance to the beacon's `epoch`, returning how many `Command::AdvanceEpoch` steps to issue to the
    /// hosted router so it rotates in lock-step — `0` if `epoch` is not newer (a stale or replayed beacon
    /// is ignored). After a non-zero return, [`public`](Self::public) is the new key to republish.
    pub fn advance_to(&mut self, epoch: Epoch) -> u64 {
        let from = self.ratchet.epoch().get();
        if self.ratchet.advance_to(epoch) {
            epoch.get().saturating_sub(from)
        } else {
            0
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_aphantos::ThresholdRouter;
    use fanos_field::F2;
    use fanos_geometry::Point;
    use fanos_pqcrypto::{HybridKemSecret, SeedRng};
    use fanos_runtime::{Command, Engine, Input, Instant};

    const SEED: [u8; 32] = [0xE4; 32];
    const COORD: Coord = [1, 2, 3];

    #[test]
    fn advancing_is_monotone_and_reports_the_router_step_count() {
        let mut driver = EpochDriver::new(COORD, SEED);
        assert_eq!(driver.epoch(), Epoch::ZERO);

        // 0 → 1 is one router step; the key rotated off genesis.
        let genesis_pub = driver.public().encode();
        assert_eq!(driver.advance_to(Epoch::new(1)), 1);
        assert_eq!(driver.epoch(), Epoch::new(1));
        assert_ne!(driver.public().encode(), genesis_pub);

        // A repeated or stale beacon is ignored — 0 steps, key unchanged.
        let e1_pub = driver.public().encode();
        assert_eq!(driver.advance_to(Epoch::new(1)), 0);
        assert_eq!(driver.advance_to(Epoch::new(0)), 0);
        assert_eq!(driver.public().encode(), e1_pub);

        // 1 → 3 is two router steps (a multi-epoch catch-up), and the key rotates again.
        assert_eq!(driver.advance_to(Epoch::new(3)), 2);
        assert_eq!(driver.epoch(), Epoch::new(3));
        assert_ne!(driver.public().encode(), e1_pub);
    }

    #[test]
    fn the_driver_publishes_exactly_the_key_the_router_peels_with() {
        // The whole point of the parallel ratchet: after the beacon advances, the key the driver
        // republishes must be the key the hosted router — advanced the reported number of steps — now
        // peels with. Drive both off the same onion seed and confirm they match at each epoch.
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"driver-identity"));
        let mut router = ThresholdRouter::<F2>::new(Point::<F2>::at(0), &identity, 2, SEED);
        let mut driver = EpochDriver::new(COORD, SEED);

        // Epoch 0: before any advance, the published key already matches the router's current key.
        assert_eq!(
            driver.public().encode(),
            router.onion_public().encode(),
            "genesis keys match"
        );

        for epoch in 1..=4u64 {
            let steps = driver.advance_to(Epoch::new(epoch));
            assert_eq!(steps, 1, "one beacon epoch ⇒ one router step");
            for _ in 0..steps {
                router.step(Instant(epoch), Input::Command(Command::AdvanceEpoch));
            }
            assert_eq!(router.onion_epoch(), Epoch::new(epoch));
            assert_eq!(
                driver.public().encode(),
                router.onion_public().encode(),
                "the driver republishes exactly the router's current onion key at epoch {epoch}"
            );
        }
    }
}
