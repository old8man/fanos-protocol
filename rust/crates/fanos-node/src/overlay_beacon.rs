//! `OverlayBeaconNode` — the deployed node as **one sans-I/O composite engine**: an [`OverlayNode`]
//! (membership, liveness, L4 storage, DIAKRISIS healing) plus the distributed randomness
//! [`BeaconNode`], so a production node runs a **live epoch clock driven by the real threshold DVRF
//! beacon** instead of sitting pinned at genesis (§7.6, spec §L3).
//!
//! Why compose: the sans-I/O model spawns one engine per coordinate, and the two are *coupled* — the
//! overlay's epoch (which rotates coordinates, rendezvous meeting-lines, cover schedules and PROTEUS
//! shapes) must advance in lock-step with the beacon the whole cell agrees on. `OverlayBeaconNode`
//! resolves this exactly as [`MixRelay`](crate::mix_relay::MixRelay) does for the threshold router:
//! it routes each input to the right sub-engine and, whenever the beacon adopts a new epoch
//! ([`Notification::BeaconReady`]), drives the overlay forward to that same epoch — so the epoch clock
//! is defined **once**, by the beacon, and both roles stay locked.
//!
//! A deployed node needs no DKG to *consume* the beacon: a [`BeaconNode`] built with `share = None` is
//! a pure consumer that verifies and adopts the rounds the anchors flood (it only needs the group
//! commitment, a public genesis parameter). Anchors additionally hold a share and contribute partials.
//!
//! **Epoch agreement vs the beacon (audit #102).** `OverlayNode::on_advance_epoch` floods its own bare
//! 4-byte epoch ordinal as [`FrameType::EpochAgree`] — the cell's fallback epoch-number agreement when no
//! beacon is configured. Under a real beacon that gossip is *superseded*: the authoritative epoch clock is
//! the `BeaconNode`'s DVRF round. The two now travel on **distinct** frame codes (`EpochAgree` vs
//! `Beacon` — the one-frame-two-meanings collision that predated this is gone), so routing is
//! unambiguous: this composite (a) routes every inbound `BeaconPartial`/`Beacon` frame to the beacon, and
//! (b) **suppresses** the overlay's now-redundant `EpochAgree` floods emitted while we drive its epoch,
//! keeping the epoch bump and its `EpochAdvanced` notification. Folding the beacon *seed* into the
//! coordinate itself (the live per-epoch reshuffle) is the remaining overlay-side half of #102; this
//! engine is the substrate it builds on.

use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_keygen::BeaconNode;
use fanos_runtime::{Command, Effect, Engine, Epoch, Input, Instant, Notification, OverlayNode};
use fanos_wire::{FrameType, decode_frame};

/// A deployed node hosting an [`OverlayNode`] and a distributed-beacon [`BeaconNode`] as one engine,
/// driving the overlay's epoch clock from the real threshold DVRF beacon (see the module docs). Both
/// sub-engines MUST be constructed at the **same** coordinate.
pub struct OverlayBeaconNode<F: Field> {
    overlay: OverlayNode<F>,
    beacon: BeaconNode<F>,
}

impl<F: Field> OverlayBeaconNode<F> {
    /// Compose an `overlay` and a `beacon` (both at this node's coordinate) into one engine. Pass a
    /// beacon built with `share = Some(..)` to run as an anchor (contributes partials), or `None` to
    /// run as a pure consumer that only adopts the rounds anchors flood.
    #[must_use]
    pub fn new(overlay: OverlayNode<F>, beacon: BeaconNode<F>) -> Self {
        Self { overlay, beacon }
    }

    /// The current beacon epoch — the authoritative epoch clock both sub-engines track.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.beacon.epoch()
    }

    /// The current beacon seed — a driver folds this into the rendezvous `meeting_line` (E5) and the
    /// coordinate reshuffle (#102); every party that adopts the same round folds the same seed.
    #[must_use]
    pub fn beacon_seed(&self) -> [u8; 32] {
        self.beacon.seed()
    }

    /// The overlay's current epoch. Invariant after every [`step`](Engine::step): it equals
    /// [`epoch`](Self::epoch) — the beacon leads and the overlay is driven to match.
    #[must_use]
    pub fn overlay_epoch(&self) -> Epoch {
        self.overlay.epoch()
    }

    /// Whether `frame` is a beacon control frame (routed to the beacon; everything else on the wire is
    /// the overlay's). The overlay's own frames never carry the beacon frame codes, so this is
    /// unambiguous.
    fn is_beacon_frame(frame: &[u8]) -> bool {
        matches!(
            decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()),
            Some(FrameType::BeaconPartial | FrameType::Beacon)
        )
    }

    /// Whether `frame` is the overlay's own epoch-agreement gossip ([`FrameType::EpochAgree`]) — the
    /// flood the authoritative beacon round supersedes.
    fn is_epoch_agree_frame(frame: &[u8]) -> bool {
        matches!(
            decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()),
            Some(FrameType::EpochAgree)
        )
    }

    /// Drop the overlay's own `EpochAgree` floods from `effects` (redundant under the authoritative
    /// beacon round we are driving from), keeping every other effect — crucially the `EpochAdvanced`
    /// notification and any storage/liveness sends. See the module docs.
    fn strip_overlay_epoch_floods(effects: Vec<Effect>) -> Vec<Effect> {
        effects
            .into_iter()
            .filter(|e| match e {
                Effect::Send { frame, .. } => !Self::is_epoch_agree_frame(frame),
                _ => true,
            })
            .collect()
    }

    /// After the beacon has stepped, drive the overlay forward to the newest adopted beacon epoch
    /// (suppressing its redundant `EpochAgree` floods), appending the overlay's rotation effects. The `BeaconReady`
    /// notification is kept so the node driver can republish keys and fold the seed (E5 / #102).
    fn drive_overlay(&mut self, now: Instant, mut effects: Vec<Effect>) -> Vec<Effect> {
        let target = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Notify(Notification::BeaconReady { epoch, .. }) => Some(*epoch),
                _ => None,
            })
            .max();
        if let Some(epoch) = target {
            while self.overlay.epoch() < epoch {
                let bump = self
                    .overlay
                    .step(now, Input::Command(Command::AdvanceEpoch));
                effects.extend(Self::strip_overlay_epoch_floods(bump));
            }
        }
        effects
    }
}

impl<F: Field> Engine for OverlayBeaconNode<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            // Beacon control frames drive the beacon; adopting a new round drives the overlay's epoch.
            // Every other wire frame is the overlay's (membership, storage, liveness, healing).
            Input::Message { .. } => {
                let is_beacon = matches!(&input, Input::Message { frame, .. } if Self::is_beacon_frame(frame));
                if is_beacon {
                    let effects = self.beacon.step(now, input);
                    self.drive_overlay(now, effects)
                } else {
                    self.overlay.step(now, input)
                }
            }
            // The external epoch tick drives the BEACON (an anchor emits partials; a consumer is inert);
            // the beacon adopting an epoch drives the overlay.
            Input::Command(Command::AdvanceEpoch) => {
                let effects = self.beacon.step(now, Input::Command(Command::AdvanceEpoch));
                self.drive_overlay(now, effects)
            }
            // Startup goes to both: the overlay begins heartbeating; the beacon pulls a sync round so a
            // node that missed live rounds catches up (then drive the overlay to whatever it adopted).
            Input::Command(Command::StartHeartbeat) => {
                let mut effects = self.overlay.step(now, Input::Command(Command::StartHeartbeat));
                let synced = self
                    .beacon
                    .step(now, Input::Command(Command::StartHeartbeat));
                effects.extend(self.drive_overlay(now, synced));
                effects
            }
            // Only the overlay arms timers (the beacon is frame/tick-driven).
            Input::Timer(_) => self.overlay.step(now, input),
            // Send, Put, Get, Join, Diagnose, Observe, ... are all the overlay's.
            Input::Command(cmd) => self.overlay.step(now, Input::Command(cmd)),
        }
    }

    fn address(&self) -> Triple {
        self.overlay.address()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::F2;
    use fanos_geometry::Point;
    use fanos_runtime::Config as OverlayConfig;
    use fanos_vrf::vss::{DeterministicRng, VssCommitment, VssShare, deal};

    const T: usize = 4; // 4-of-7 beacon threshold (a full Fano cell of anchors, stands for a done DKG)

    // Deal the beacon key across the 7-node cell. A fixed secret + deterministic RNG keeps the test
    // reproducible; a real deployment deals from OS entropy via the anchors' one-time networked DKG.
    fn beacon_key() -> (Vec<VssShare>, VssCommitment) {
        deal(&[0xB5; 32], T, 7, &mut DeterministicRng::new(b"overlay-beacon-test")).unwrap()
    }

    // The test's router: map a flooded frame's destination coordinate back to its Fano-cell index.
    fn node_at(to: Triple) -> Option<usize> {
        (0..7).find(|&i| Point::<F2>::at(i).coords() == to)
    }

    #[test]
    fn a_cell_of_composites_drives_every_overlay_from_the_converged_beacon() {
        // A full Fano cell of composite nodes, each an anchor (overlay + a beacon share). Running one
        // beacon round among them must converge every beacon on epoch 1 AND drive every overlay to that
        // same epoch — the clock defined once by the beacon, both roles locked — with no overlay
        // EpochAgree flood escaping onto the wire (the beacon supersedes it).
        let (shares, commitment) = beacon_key();
        let mut cell: Vec<OverlayBeaconNode<F2>> = (0..7)
            .map(|i| {
                let overlay = OverlayNode::<F2>::new(Point::at(i), OverlayConfig::default());
                let beacon =
                    BeaconNode::<F2>::new(Point::at(i), Some(shares[i].clone()), commitment.clone(), T);
                OverlayBeaconNode::new(overlay, beacon)
            })
            .collect();
        for c in &cell {
            assert_eq!(c.overlay_epoch(), Epoch::ZERO, "every node starts pinned at genesis");
        }

        // kickoff: AdvanceEpoch drives each composite's beacon to flood its partial. The ONLY frames a
        // composite emits are the beacon's — the overlay's competing seedless Beacon flood is stripped.
        let mut bus: Vec<(usize, Vec<u8>)> = Vec::new();
        for c in &mut cell {
            for e in c.step(Instant(0), Input::Command(Command::AdvanceEpoch)) {
                if let Effect::Send { to, frame } = e {
                    assert!(
                        OverlayBeaconNode::<F2>::is_beacon_frame(&frame),
                        "a composite floods only beacon frames, never a seedless overlay Beacon"
                    );
                    if let Some(k) = node_at(to) {
                        bus.push((k, frame));
                    }
                }
            }
        }

        // run: deliver the bus until quiescent; the rounds assemble and each composite drives its own
        // overlay on the BeaconReady it adopts (re-busing only the beacon's onward sends).
        let mut clock = 0u64;
        while !bus.is_empty() {
            let (target, frame) = bus.remove(0);
            clock += 1;
            for e in cell[target].step(Instant(clock), Input::Message { from: [0, 0, 0], frame }) {
                if let Effect::Send { to, frame } = e
                    && let Some(k) = node_at(to)
                {
                    bus.push((k, frame));
                }
            }
        }

        // Every composite converged on the beacon's epoch 1, and locked its overlay to it.
        for c in &cell {
            assert_eq!(c.epoch(), Epoch::new(1), "the beacon converged on epoch 1");
            assert_eq!(
                c.overlay_epoch(),
                c.epoch(),
                "the overlay epoch is driven to the beacon epoch"
            );
        }
    }

    #[test]
    fn a_non_beacon_command_still_reaches_the_overlay() {
        // Sanity: composing the beacon must not swallow ordinary overlay traffic.
        let (_shares, commitment) = beacon_key();
        let coord = Point::<F2>::at(4);
        let overlay = OverlayNode::<F2>::new(coord, OverlayConfig::default());
        let beacon = BeaconNode::<F2>::new(coord, None, commitment, T);
        let mut node = OverlayBeaconNode::new(overlay, beacon);
        // StartHeartbeat must reach the overlay (it arms its heartbeat timer + pings).
        let effects = node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::ArmTimer { .. })),
            "the overlay's heartbeat timer is armed through the composite"
        );
    }
}
