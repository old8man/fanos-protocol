//! `MixRelay` — a complete mix-relay node as **one sans-I/O composite engine** (E4∩E5 unification).
//!
//! A mix-relay plays two roles at its coordinate: it **peels threshold-onion hops** (a
//! [`ThresholdRouter`]) and it **runs the distributed randomness beacon** (a [`BeaconNode`]). The
//! sans-I/O model spawns one engine per coordinate, so these could not be co-hosted — and the two are
//! *coupled*: when the beacon adopts a new epoch, the router must rotate its forward-secure onion key to
//! the same epoch (E4), or a client sealing to the new epoch's key would meet a relay still peeling with
//! the old one. `MixRelay` resolves this by **composing** the two into a single engine that routes each
//! input to the right sub-engine and, whenever the beacon announces a new epoch
//! ([`Notification::BeaconReady`]), drives the router's rotation internally — so the epoch clock is
//! defined once and both roles stay in lock-step. It is itself sans-I/O, so it runs unchanged under the
//! simulator and real QUIC, and a driver need only republish the (re-emitted) `BeaconReady`'s key at the
//! mixdir slot and fold its seed into the meeting line.
//!
//! Input routing is unambiguous: beacon control frames (`BeaconPartial`/`Beacon`) go to the beacon; the
//! router's raw internally-tagged onion traffic (tags `0`/`1`/`2`, which never collide with the beacon
//! frame codes `0x18`/`0x13`) and its timers go to the router; the external `AdvanceEpoch` tick drives
//! the *beacon* (which in turn rotates the router); every other command goes to the router.

use fanos_aphantos::ThresholdRouter;
use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_keygen::BeaconNode;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_runtime::{Command, Effect, Engine, Epoch, Input, Instant, Notification};
use fanos_wire::{FrameType, decode_frame};

use crate::rendezvous_relay::RendezvousRelay;

/// A mix-relay hosting a threshold-onion router and a distributed-beacon [`BeaconNode`] as one engine,
/// unifying the E4 onion-key rotation with the E5 beacon epoch (see the module docs). The router is
/// wrapped in a [`RendezvousRelay`] so the same coordinate also serves as a rendezvous point — forwarding
/// each anonymous reply it peels to the client that registered that session's cookie (audit #54, item 3),
/// which is what lets a general anonymous client receive replies without being a combiner itself. The
/// router and beacon MUST be constructed at the **same** coordinate.
pub struct MixRelay<F: Field> {
    relay: RendezvousRelay<F>,
    beacon: BeaconNode<F>,
}

impl<F: Field> MixRelay<F> {
    /// Compose a `router` and a `beacon` (both at this relay's coordinate) into one mix-relay engine. The
    /// router is wrapped in a [`RendezvousRelay`], so the relay also forwards cookie-tagged replies to
    /// registered clients.
    #[must_use]
    pub fn new(router: ThresholdRouter<F>, beacon: BeaconNode<F>) -> Self {
        Self {
            relay: RendezvousRelay::new(router),
            beacon,
        }
    }

    /// The current beacon seed — fold into `meeting_line` for the rendezvous this relay serves (E5).
    #[must_use]
    pub fn beacon_seed(&self) -> [u8; 32] {
        self.beacon.seed()
    }

    /// The current beacon epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.beacon.epoch()
    }

    /// The epoch the hosted router's forward-secure onion key is at. Invariant after every
    /// [`step`](Engine::step): it equals [`epoch`](Self::epoch) — the beacon and the router are locked.
    #[must_use]
    pub fn router_onion_epoch(&self) -> Epoch {
        self.relay.router().onion_epoch()
    }

    /// The router's current-epoch onion public — what a driver republishes at the `(coord, epoch)` mixdir
    /// slot so clients seal to a key the relay can still peel with (E4).
    #[must_use]
    pub fn onion_public(&self) -> &HybridKemPublic {
        self.relay.router().onion_public()
    }

    /// Whether `frame` is a beacon control frame (routed to the beacon; everything else is the router's
    /// raw-tagged onion traffic). The router's internal tags never encode to the beacon frame codes, so
    /// this classification is unambiguous.
    fn is_beacon_frame(frame: &[u8]) -> bool {
        matches!(
            decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()),
            Some(FrameType::BeaconPartial | FrameType::Beacon)
        )
    }

    /// After the beacon has stepped, rotate the router forward to the newest adopted beacon epoch (E4∩E5),
    /// appending the router's rotation effects. The `BeaconReady` notification is kept in `effects` so the
    /// node driver can republish the onion key and update its rendezvous seed.
    fn drive_router(&mut self, now: Instant, mut effects: Vec<Effect>) -> Vec<Effect> {
        let target = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Notify(Notification::BeaconReady { epoch, .. }) => Some(*epoch),
                _ => None,
            })
            .max();
        if let Some(epoch) = target {
            // Rotate the wrapped router directly (an epoch tick is not onion traffic, so it bypasses the
            // rendezvous-relay forwarding rule).
            while self.relay.router().onion_epoch() < epoch {
                let rotation = self
                    .relay
                    .router_mut()
                    .step(now, Input::Command(Command::AdvanceEpoch));
                effects.extend(rotation);
            }
        }
        effects
    }
}

impl<F: Field> Engine for MixRelay<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            Input::Message { .. } => {
                let is_beacon =
                    matches!(&input, Input::Message { frame, .. } if Self::is_beacon_frame(frame));
                if is_beacon {
                    let effects = self.beacon.step(now, input);
                    self.drive_router(now, effects)
                } else {
                    // Onion traffic and rendezvous registrations go to the wrapped relay (which peels
                    // hops and forwards cookie-tagged replies to registered clients).
                    self.relay.step(now, input)
                }
            }
            // The external epoch tick drives the BEACON; the beacon adopting an epoch rotates the router.
            Input::Command(Command::AdvanceEpoch) => {
                let effects = self.beacon.step(now, Input::Command(Command::AdvanceEpoch));
                self.drive_router(now, effects)
            }
            // Only the router arms timers (a firing gather timer may complete a peel → the relay forwards).
            Input::Timer(_) => self.relay.step(now, input),
            // StartHeartbeat (cover), Send (launch), and every other command go to the router.
            Input::Command(cmd) => self.relay.step(now, Input::Command(cmd)),
        }
    }

    fn address(&self) -> Triple {
        self.relay.address()
    }
}
