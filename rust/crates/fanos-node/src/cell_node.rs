//! `CellNode` — the deployed node as a **full cell participant**: an [`OverlayBeaconNode`] (overlay +
//! the epoch-driving DVRF beacon) *plus* the anonymity mixnet role — a threshold-onion router wrapped in
//! a [`RendezvousRelay`], so the same coordinate that serves membership/storage/healing also **peels
//! rendezvous hops and forwards anonymous replies** (spec §L5, audit #54). This is what turns a cell of
//! nodes into a live mixnet: a client's [`build_cell_mix_directory`](crate::build_cell_mix_directory)
//! reads the onion keys these nodes publish, and draws its anonymous circuits over them.
//!
//! ## Why one engine
//!
//! The sans-I/O model spawns one engine per coordinate, so the three roles at a coordinate — overlay,
//! beacon, onion router — must be **composed**, not co-hosted. They are also *coupled*: the router's
//! forward-secure onion key must rotate to the very epoch the beacon adopts (E4∩E5), exactly as the
//! overlay's epoch does. [`OverlayBeaconNode`] already locks the overlay to the beacon; `CellNode` extends
//! that lock to the router — on every [`Notification::BeaconReady`] it drives the router's key forward to
//! the same epoch — so the epoch clock stays defined **once**, by the beacon, across all three roles.
//!
//! ## Frame routing
//!
//! Each inbound frame goes to exactly one sub-role, by frame type (the code spaces are disjoint by
//! construction):
//! * **onion traffic** (the router's raw internally-tagged frames — no [`FrameType`]) and
//!   [`RdvRegister`](FrameType::RdvRegister) → the rendezvous relay;
//! * everything else — every wire [`FrameType`], including the beacon's `Beacon`/`BeaconPartial` and the
//!   overlay's own frames (and [`RdvReply`](FrameType::RdvReply), which a *client* node surfaces) → the
//!   [`OverlayBeaconNode`], which itself splits beacon vs overlay.
//!
//! ## Timer namespacing
//!
//! Both the overlay and the router are timer-driven, and their token spaces would otherwise collide (the
//! overlay's sole `HEARTBEAT` is token `0`; the router's first gather-deadline token is also `0`). The
//! composite therefore **remaps** the overlay's heartbeat token onto a value the router provably never
//! uses — `(1 << 62) | 1`, which has bit 62 set (so it is neither a gather token, all `< 2^62`, nor the
//! `MIX_FLAG` tokens with bit 63 set) and is not the `COVER` token (exactly `1 << 62`). Router timer
//! tokens pass through untouched. Firing is then unambiguous: `OVERLAY_HEARTBEAT` → the overlay (unmapped
//! back to `0`), every other token → the router.

use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_runtime::{
    Command, Effect, Engine, Epoch, Input, Instant, Notification, TimerToken,
};
use fanos_wire::{FrameType, decode_frame};

use crate::overlay_beacon::OverlayBeaconNode;
use crate::rendezvous_relay::RendezvousRelay;
use fanos_aphantos::ThresholdRouter;

/// The overlay heartbeat's timer token as seen *outside* the composite. Chosen so the router (whose
/// tokens are gather ids `< 2^62`, `COVER = 1 << 62`, and `MIX_FLAG | id` with bit 63 set) never emits
/// it: bit 62 set rules out gather and `MIX_FLAG`, and the low bit rules out `COVER`. See the module docs.
const OVERLAY_HEARTBEAT: TimerToken = TimerToken((1 << 62) | 1);

/// The overlay's internal heartbeat token (`fanos_runtime`'s `HEARTBEAT`), which the composite remaps to
/// [`OVERLAY_HEARTBEAT`] on the way out and back on the way in.
const OVERLAY_HEARTBEAT_INNER: TimerToken = TimerToken(0);

/// A deployed **cell node**: an [`OverlayBeaconNode`] plus the mixnet router (a [`RendezvousRelay`] around
/// a [`ThresholdRouter`]) as one engine (see the module docs). All three sub-roles MUST be constructed at
/// the **same** coordinate. Compare [`MixRelay`](crate::mix_relay::MixRelay), which composes just the
/// router and beacon for a dedicated relay; `CellNode` is the full member that also runs the overlay.
pub struct CellNode<F: Field> {
    obn: OverlayBeaconNode<F>,
    relay: RendezvousRelay<F>,
}

impl<F: Field> CellNode<F> {
    /// Compose the deployed overlay+beacon node `obn` with the mixnet `router` (all at this node's
    /// coordinate) into one full cell participant. The router is wrapped in a [`RendezvousRelay`] so this
    /// coordinate also forwards cookie-tagged anonymous replies to registered clients.
    #[must_use]
    pub fn new(obn: OverlayBeaconNode<F>, router: ThresholdRouter<F>) -> Self {
        Self {
            obn,
            relay: RendezvousRelay::new(router),
        }
    }

    /// The authoritative epoch (the beacon's), which all three roles track.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.obn.epoch()
    }

    /// The current beacon seed — a driver folds this into the rendezvous `meeting_line` (E5) and the
    /// coordinate reshuffle (#102).
    #[must_use]
    pub fn beacon_seed(&self) -> [u8; 32] {
        self.obn.beacon_seed()
    }

    /// The router's current-epoch onion public — what a driver republishes at the `(coord, epoch)` mix-key
    /// slot so anonymous clients seal to a key this relay can still peel with (E4).
    #[must_use]
    pub fn onion_public(&self) -> &HybridKemPublic {
        self.relay.router().onion_public()
    }

    /// The epoch the router's forward-secure onion key is at. Invariant after every
    /// [`step`](Engine::step): it equals [`epoch`](Self::epoch) — the beacon leads, the router follows.
    #[must_use]
    pub fn router_onion_epoch(&self) -> Epoch {
        self.relay.router().onion_epoch()
    }

    /// Whether `frame` is onion traffic or a rendezvous registration — the rendezvous relay's inputs. Onion
    /// frames carry the router's raw internal tags (no wire [`FrameType`]); registrations are
    /// [`RdvRegister`](FrameType::RdvRegister). Everything else is a wire frame for the [`OverlayBeaconNode`].
    fn is_relay_frame(frame: &[u8]) -> bool {
        match decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()) {
            // A recognised wire frame is the relay's only if it is a rendezvous registration; every other
            // wire type (beacon, overlay, RdvReply) is the OverlayBeaconNode's.
            Some(ft) => ft == FrameType::RdvRegister,
            // Onion traffic carries the router's raw internal tags 0/1/2, which decode to no frame type.
            None => true,
        }
    }

    /// Rewrite the overlay's internal heartbeat token to the composite's [`OVERLAY_HEARTBEAT`] in an
    /// `ArmTimer` effect, so it never collides with a router token on the wire clock.
    fn remap_overlay_timer(effect: Effect) -> Effect {
        match effect {
            Effect::ArmTimer { token, after } if token == OVERLAY_HEARTBEAT_INNER => Effect::ArmTimer {
                token: OVERLAY_HEARTBEAT,
                after,
            },
            other => other,
        }
    }

    /// Run `obn` and remap its heartbeat `ArmTimer` tokens (see [`OVERLAY_HEARTBEAT`]). The beacon adopting
    /// a new epoch also drives the router's onion key forward to it, appending the router's rotation.
    fn step_obn(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let effects = self.obn.step(now, input);
        let target = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Notify(Notification::BeaconReady { epoch, .. }) => Some(*epoch),
                _ => None,
            })
            .max();
        let mut out: Vec<Effect> = effects.into_iter().map(Self::remap_overlay_timer).collect();
        if let Some(epoch) = target {
            // Lock the router's forward-secure onion key to the adopted beacon epoch (E4∩E5).
            while self.relay.router().onion_epoch() < epoch {
                let rotation = self
                    .relay
                    .router_mut()
                    .step(now, Input::Command(Command::AdvanceEpoch));
                out.extend(rotation);
            }
        }
        out
    }
}

impl<F: Field> Engine for CellNode<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            Input::Message { .. } => {
                let to_relay =
                    matches!(&input, Input::Message { frame, .. } if Self::is_relay_frame(frame));
                if to_relay {
                    self.relay.step(now, input)
                } else {
                    self.step_obn(now, input)
                }
            }
            // The overlay's remapped heartbeat fires: hand the overlay its own (inner) heartbeat token.
            Input::Timer(token) if token == OVERLAY_HEARTBEAT => {
                self.step_obn(now, Input::Timer(OVERLAY_HEARTBEAT_INNER))
            }
            // Every other timer token is the router's (gather deadline, mix release, or cover tick).
            Input::Timer(_) => self.relay.step(now, input),
            // StartHeartbeat drives the overlay+beacon composite AND starts the relay router's cover schedule
            // (audit S1-H1): otherwise cover only begins lazily on the router's first real forward, so the
            // silence→cover transition coincides with — and thereby reveals — the relay's first real traffic,
            // defeating the E1/E6 "uniform whether or not carrying real traffic" property. An idle or
            // line-member-only relay would emit zero cover at all. Starting cover here makes it proactive from
            // startup; the router's cover-tick timer routes back to the relay via the `Input::Timer(_)` arm.
            Input::Command(Command::StartHeartbeat) => {
                let mut out = self.step_obn(now, Input::Command(Command::StartHeartbeat));
                out.extend(self.relay.router_mut().step(now, Input::Command(Command::StartHeartbeat)));
                out
            }
            // Every other command drives the overlay+beacon composite: the epoch tick advances the beacon
            // (which `step_obn` then locks the router's onion key to) and arms the remapped overlay heartbeat;
            // Send/Put/Get/Join/Diagnose/Observe are the overlay's directly.
            Input::Command(_) => self.step_obn(now, input),
        }
    }

    fn address(&self) -> Triple {
        self.obn.address()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_aphantos::threshold::{HopLine, seal_onion};
    use fanos_aphantos::threshold_router::{launch_frame, line_member_coords};
    use fanos_field::F2;
    use fanos_geometry::{Line, Point};
    use fanos_pqcrypto::{HybridKemSecret, OnionKeyRatchet, SeedRng};
    use fanos_keygen::BeaconNode;
    use fanos_rendezvous::SessionId;
    use fanos_runtime::{Config as OverlayConfig, OverlayNode};
    use fanos_vrf::vss::{DeterministicRng, VssCommitment, VssShare, deal};

    const T: usize = 4; // 4-of-7 beacon threshold (a full Fano cell of anchors stands for a done DKG)

    fn beacon_key() -> (Vec<VssShare>, VssCommitment) {
        deal(&[0xC5; 32], T, 7, &mut DeterministicRng::new(b"cell-node-test")).unwrap()
    }

    fn cell_node(i: usize, shares: &[VssShare], commitment: &VssCommitment) -> CellNode<F2> {
        let coord = Point::<F2>::at(i);
        let overlay = OverlayNode::<F2>::new(coord, OverlayConfig::default());
        let beacon = BeaconNode::<F2>::new(coord, Some(shares[i].clone()), commitment.clone(), T);
        let obn = OverlayBeaconNode::new(overlay, beacon);
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xC5, i as u8]));
        let mut onion_seed = [0xC4u8; 32];
        onion_seed[31] = i as u8;
        let router = ThresholdRouter::<F2>::new(coord, &identity, 1, onion_seed);
        CellNode::new(obn, router)
    }

    #[test]
    fn startup_arms_the_overlay_heartbeat_under_the_remapped_token() {
        // StartHeartbeat must reach the overlay through the composite — and its heartbeat timer must be
        // armed under the REMAPPED token, so it never collides with a router timer.
        let (shares, commitment) = beacon_key();
        let mut node = cell_node(0, &shares, &commitment);
        let effects = node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::ArmTimer { token, .. } if *token == OVERLAY_HEARTBEAT
            )),
            "the overlay heartbeat is armed under the composite's remapped token"
        );
        assert!(
            !effects.iter().any(|e| matches!(
                e,
                Effect::ArmTimer { token, .. } if *token == OVERLAY_HEARTBEAT_INNER
            )),
            "the raw inner heartbeat token never escapes the composite"
        );
    }

    #[test]
    fn startup_starts_the_relay_cover_schedule_proactively() {
        use fanos_runtime::Duration;
        // Audit S1-H1: StartHeartbeat must ALSO start the relay's cover schedule — not lazily on the first real
        // forward — so cover runs from startup and the silence→cover transition never reveals the relay's first
        // real traffic.
        let (shares, commitment) = beacon_key();
        let coord = Point::<F2>::at(0);
        let overlay = OverlayNode::<F2>::new(coord, OverlayConfig::default());
        let beacon = BeaconNode::<F2>::new(coord, Some(shares[0].clone()), commitment.clone(), T);
        let obn = OverlayBeaconNode::new(overlay, beacon);
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xC5, 0]));
        let router =
            ThresholdRouter::<F2>::new(coord, &identity, 1, [0xC4; 32]).with_cover(Duration::from_millis(1000));
        let mut node = CellNode::new(obn, router);
        let effects = node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        // A router cover-tick timer (distinct from the overlay heartbeat) is armed at startup, before any real
        // traffic — cover is proactive. Without the fix the relay never sees StartHeartbeat and arms no cover.
        assert!(
            effects.iter().any(|e| matches!(e, Effect::ArmTimer { token, .. } if *token != OVERLAY_HEARTBEAT)),
            "startup arms the relay's cover-tick timer, so cover runs from startup"
        );
    }

    #[test]
    fn the_remapped_heartbeat_fires_the_overlay_not_the_router() {
        // Firing the remapped heartbeat token must reach the overlay (it re-arms its heartbeat), proving
        // the composite routes it back to the overlay rather than the router.
        let (shares, commitment) = beacon_key();
        let mut node = cell_node(1, &shares, &commitment);
        node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        let ticked = node.step(Instant(1_000_000_000), Input::Timer(OVERLAY_HEARTBEAT));
        assert!(
            ticked.iter().any(|e| matches!(
                e,
                Effect::ArmTimer { token, .. } if *token == OVERLAY_HEARTBEAT
            )),
            "the heartbeat re-arms — the composite delivered the tick to the overlay"
        );
    }

    #[test]
    fn a_cell_node_peels_a_rendezvous_hop_and_forwards_the_reply() {
        // The mixnet role end-to-end at one node: a non-combiner client registers its cookie, a reply
        // onion sealed to this node's line arrives, and the composite peels it (t = 1) and forwards the
        // cookie-tagged reply to the client — the overlay/beacon roles untouched.
        let (shares, commitment) = beacon_key();
        // Build the node at the combiner of line 0 so it is that line's rendezvous point.
        let line = Line::<F2>::at(0).coords();
        let members = line_member_coords::<F2>(line);
        let combiner_idx = Point::<F2>::new(members[0]).unwrap().index();
        let mut node = cell_node(combiner_idx, &shares, &commitment);

        let client: Triple = [0x0C, 0x0C, 0x0C];
        let cookie: SessionId = *b"cell-cookie-0001";
        node.step(
            Instant(0),
            Input::Message {
                from: client,
                frame: crate::rendezvous_relay::register_frame(cookie),
            },
        );

        // Seal a single-hop reply to this line, to the node's forward-secure onion public.
        let mut onion_seed = [0xC4u8; 32];
        onion_seed[31] = combiner_idx as u8;
        let onion_ratchet = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xEE, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xEE, 2]));
        let pubs = [onion_ratchet.public(), &p1, &p2];
        let mut payload = cookie.to_vec();
        payload.extend_from_slice(b"reply for the cell client");
        let onion = seal_onion(&[HopLine { line, members: &pubs }], 1, &payload, b"cell-seed").unwrap();

        let effects = node.step(
            Instant(1),
            Input::Message {
                from: [9, 9, 9],
                frame: launch_frame(line, &onion),
            },
        );
        let forwarded = effects.iter().find_map(|e| match e {
            Effect::Send { to, frame } if *to == client => Some(frame.clone()),
            _ => None,
        });
        let frame = forwarded.expect("the cell node forwarded the peeled reply to the registered client");
        let (decoded, _) = decode_frame(&frame).unwrap();
        assert_eq!(decoded.frame_type(), Some(FrameType::RdvReply));
        assert_eq!(decoded.body, payload.as_slice());
    }

    #[test]
    fn the_beacon_epoch_drives_the_router_onion_key() {
        // A full cell of composites runs one beacon round; every node's beacon adopts epoch 1 AND its
        // router's onion key is driven to epoch 1 in lock-step (E4∩E5), alongside the overlay.
        let (shares, commitment) = beacon_key();
        let mut cell: Vec<CellNode<F2>> = (0..7).map(|i| cell_node(i, &shares, &commitment)).collect();
        for c in &cell {
            assert_eq!(c.epoch(), Epoch::ZERO);
            assert_eq!(c.router_onion_epoch(), Epoch::ZERO);
        }

        let node_at = |to: Triple| (0..7).find(|&i| Point::<F2>::at(i).coords() == to);
        let mut bus: Vec<(usize, Vec<u8>)> = Vec::new();
        for c in &mut cell {
            for e in c.step(Instant(0), Input::Command(Command::AdvanceEpoch)) {
                if let Effect::Send { to, frame } = e
                    && let Some(k) = node_at(to)
                {
                    bus.push((k, frame));
                }
            }
        }
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
        for c in &cell {
            assert_eq!(c.epoch(), Epoch::new(1), "the beacon converged on epoch 1");
            assert_eq!(
                c.router_onion_epoch(),
                Epoch::new(1),
                "the router's onion key is driven to the beacon epoch in lock-step"
            );
        }
    }
}
