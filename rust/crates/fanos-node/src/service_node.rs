//! `ServiceNode` — a deployed node that also **hosts a threshold service** (spec §12.3, audit #99).
//!
//! A threshold-hosted CALYPSO service is served by a *line* of nodes, none of which can read a client's
//! intro alone: the client seals its request to the whole line ([`SealedIntro`](fanos_calypso::hosting::SealedIntro)),
//! and the line's combiner gathers `>= t` partial decryptions before the request surfaces. The per-member
//! logic is the [`ThresholdService`] engine. This composite lets a member run that role **alongside its
//! ordinary cell role** — overlay, beacon, and (optionally) the mixnet relay — at one coordinate, exactly
//! as [`CellNode`](crate::cell_node::CellNode) composes the relay with the overlay.
//!
//! ## Why one engine
//!
//! The sans-I/O model spawns one engine per coordinate, so a member that both participates in the cell and
//! hosts a service must **compose** the two, not co-host them. `ServiceNode` wraps an arbitrary `inner`
//! engine (a bare overlay, an [`OverlayBeaconNode`](crate::overlay_beacon::OverlayBeaconNode), or a full
//! [`CellNode`](crate::cell_node::CellNode)) together with a [`ThresholdService`], dispatching each input
//! to exactly one of them.
//!
//! ## Frame routing
//!
//! The three threshold-hosting wire types — [`RdvIntro`](FrameType::RdvIntro) (an intro to serve),
//! [`SvcShareReq`](FrameType::SvcShareReq) (a combiner asking a member for its partial), and
//! [`SvcPartial`](FrameType::SvcPartial) (a member's partial) — go to the [`ThresholdService`]; every other
//! input goes to `inner`. This takes precedence over the inner engine's own routing, so an `RdvIntro` is
//! served here rather than reaching the overlay. The intro reaches this coordinate like any frame — sent
//! directly by a client, or delivered anonymously to it as the target of a mixnet circuit — so the service
//! is anonymous exactly when the client's transport is, and the composite need not itself peel onions.
//!
//! ## Timer namespacing
//!
//! Both the inner engine and the service are timer-driven and both number their tokens from zero (the
//! overlay's heartbeat is `0`; the service's first gather deadline is `0`), so their spaces would collide
//! on the shared wire clock. The service's tokens are therefore remapped into a range the inner engine
//! provably never emits: bits 62 **and** 61 set with bit 63 clear (`SERVICE_FLAG`). That range is free of
//! every inner token — the overlay/beacon use only small values; a wrapped [`CellNode`] uses gather ids
//! `< 2^62`, `COVER = 1<<62`, the remapped overlay heartbeat `(1<<62)|1`, and `MIX_FLAG | id` (bit 63 set)
//! — none of which set bits 62 and 61 together with bit 63 clear. A fired token is dispatched by that tag:
//! `(token >> 61) == 0b011` → the service (unmapped back), everything else → the inner engine.

use fanos_geometry::Triple;
use fanos_runtime::{Effect, Engine, Input, Instant, TimerToken};
use fanos_wire::{FrameType, decode_frame};

use crate::threshold_service::ThresholdService;

/// The three-bit tag (bits 63,62,61) that marks a timer token as the service's: bit 63 clear, bits 62 and
/// 61 set. Chosen disjoint from every token an inner cell engine emits (see the module docs).
const SERVICE_TAG: u64 = 0b011;
/// The service-token flag: [`SERVICE_TAG`] shifted into the top three bits.
const SERVICE_FLAG: u64 = SERVICE_TAG << 61;
/// The low 61 bits carrying the service's own (inner) token beneath the flag.
const SERVICE_SEQ_MASK: u64 = (1 << 61) - 1;

/// A cell node that also hosts a threshold service: an arbitrary `inner` cell engine plus a
/// [`ThresholdService`], both at this node's coordinate, as one engine (see the module docs).
pub struct ServiceNode {
    inner: Box<dyn Engine + Send>,
    service: ThresholdService,
}

impl ServiceNode {
    /// Compose `inner` (the node's ordinary cell engine) with a threshold-service `service`, both at this
    /// coordinate, into one engine that hosts the service alongside the cell role.
    #[must_use]
    pub fn new(inner: Box<dyn Engine + Send>, service: ThresholdService) -> Self {
        Self { inner, service }
    }

    /// Whether `frame` is one of the threshold-hosting wire types the [`ThresholdService`] owns.
    fn is_service_frame(frame: &[u8]) -> bool {
        matches!(
            decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()),
            Some(FrameType::RdvIntro | FrameType::SvcShareReq | FrameType::SvcPartial)
        )
    }

    /// Remap the service's outbound timer tokens into the [`SERVICE_FLAG`] range so they never collide with
    /// an inner-engine token; every other effect passes through untouched.
    fn tag_service_effects(effects: Vec<Effect>) -> Vec<Effect> {
        effects
            .into_iter()
            .map(|e| match e {
                Effect::ArmTimer { token, after } => Effect::ArmTimer {
                    token: TimerToken(SERVICE_FLAG | (token.0 & SERVICE_SEQ_MASK)),
                    after,
                },
                other => other,
            })
            .collect()
    }
}

impl Engine for ServiceNode {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            // A threshold-hosting frame is the service's; every other frame is the inner engine's.
            Input::Message { .. } => {
                let to_service =
                    matches!(&input, Input::Message { frame, .. } if Self::is_service_frame(frame));
                if to_service {
                    Self::tag_service_effects(self.service.step(now, input))
                } else {
                    self.inner.step(now, input)
                }
            }
            // A service-tagged timer fires: hand the service its own (unmapped) token.
            Input::Timer(token) if (token.0 >> 61) == SERVICE_TAG => {
                let inner = Input::Timer(TimerToken(token.0 & SERVICE_SEQ_MASK));
                Self::tag_service_effects(self.service.step(now, inner))
            }
            // Every other timer is the inner engine's; and the service is purely frame/timer-driven, so
            // every command drives the inner cell engine too.
            Input::Timer(_) | Input::Command(_) => self.inner.step(now, input),
        }
    }

    fn address(&self) -> Triple {
        self.inner.address()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_calypso::hosting::SealedIntro;
    use fanos_field::F2;
    use fanos_geometry::Point;
    use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
    use fanos_runtime::{Command, Config as OverlayConfig, Notification, OverlayNode};

    use crate::intro_frame;

    /// A one-member (1-of-1) line so a single `ServiceNode` is its own combiner and serves an intro alone —
    /// enough to prove the composite dispatches the hosting frames to the service and the overlay frames to
    /// the inner engine.
    fn solo_service_node(seed: u8) -> (ServiceNode, HybridKemPublic) {
        let coord = Point::<F2>::at(0).coords();
        let (secret, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xCA, seed]));
        let overlay = OverlayNode::<F2>::new(Point::<F2>::at(0), OverlayConfig::default());
        let service = ThresholdService::new(coord, secret, vec![coord], 1);
        (ServiceNode::new(Box::new(overlay), service), public)
    }

    #[test]
    fn a_service_node_serves_an_intro_and_still_runs_the_overlay() {
        let (mut node, public) = solo_service_node(1);

        // An overlay command reaches the inner engine: StartHeartbeat arms the overlay's heartbeat timer.
        let started = node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        assert!(
            started
                .iter()
                .any(|e| matches!(e, Effect::ArmTimer { .. })),
            "the inner overlay armed its heartbeat — the composite delivered the command to it"
        );

        // A hosting frame reaches the service: a 1-of-1 line serves the sealed intro at once, surfacing the
        // recovered request as an anonymous delivery.
        let request = b"serve my hidden content".to_vec();
        let intro = SealedIntro::seal(&request, 1, &[&public], b"svc-node-seed").unwrap();
        let served = node.step(
            Instant(1),
            Input::Message {
                from: [7, 7, 7],
                frame: intro_frame(&intro),
            },
        );
        assert!(
            served.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Delivered { payload, .. }) if payload == &request
            )),
            "the composite routed the intro to the threshold service, which served it"
        );
    }

    #[test]
    fn a_service_gather_timer_is_tagged_and_routes_back_to_the_service() {
        // A 2-of-2 line cannot serve from the combiner alone, so the intro stays pending behind a gather
        // deadline — armed under the service tag, and firing it must reach the service (dropping the
        // pending gather), never the inner overlay.
        let coord = Point::<F2>::at(0).coords();
        let other = Point::<F2>::at(1).coords();
        let (secret, public0) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xCA, 10]));
        let (_s1, public1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xCA, 11]));
        let overlay = OverlayNode::<F2>::new(Point::<F2>::at(0), OverlayConfig::default());
        let service = ThresholdService::new(coord, secret, vec![coord, other], 2);
        let mut node = ServiceNode::new(Box::new(overlay), service);

        let intro = SealedIntro::seal(b"req", 2, &[&public0, &public1], b"seed2").unwrap();
        let effects = node.step(
            Instant(0),
            Input::Message {
                from: [7, 7, 7],
                frame: intro_frame(&intro),
            },
        );
        let armed = effects
            .iter()
            .find_map(|e| match e {
                Effect::ArmTimer { token, .. } => Some(*token),
                _ => None,
            })
            .expect("the pending gather armed a deadline timer");
        assert_eq!(
            armed.0 >> 61,
            SERVICE_TAG,
            "the gather deadline is armed under the service tag, disjoint from inner-engine tokens"
        );

        // Firing that tagged token reaches the service (the pending gather is dropped): a second identical
        // intro is then treated as fresh (accepted, re-arming a gather) rather than suppressed as pending.
        assert!(node.step(Instant(1), Input::Timer(armed)).is_empty());
        let refired = node.step(
            Instant(2),
            Input::Message {
                from: [7, 7, 7],
                frame: intro_frame(&intro),
            },
        );
        assert!(
            refired.iter().any(|e| matches!(e, Effect::ArmTimer { .. })),
            "after the deadline dropped the gather, the same intro is accepted anew — the tick reached the \
             service, not the overlay"
        );
    }
}
