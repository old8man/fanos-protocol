//! `IngressNode` — a deployed node that also **hosts POROS censorship-resistant ingress** (design
//! authority `docs/design-anonymity-substrate.md` §6).
//!
//! A community's ingress descriptor (its reachable entry peers) is threshold-hosted across an ingress
//! **line**: no member holds it whole, and a combiner gathers `>= t` descriptor shares before serving a
//! new node a bucket of entry peers ([`crate::poros`]). The per-member logic is the [`PorosHost`] engine.
//! This composite lets a line member run that role **alongside its ordinary cell role** — overlay, beacon,
//! and (optionally) the mixnet relay — at one coordinate, exactly as [`ServiceNode`](crate::service_node)
//! composes a threshold service and [`CellNode`](crate::cell_node) composes the relay.
//!
//! ## Why one engine
//!
//! The sans-I/O model spawns one engine per coordinate, so a member that both participates in the cell and
//! hosts ingress must **compose** the two, not co-host them. `IngressNode` wraps an arbitrary `inner` engine
//! (a bare overlay, an [`OverlayBeaconNode`](crate::overlay_beacon::OverlayBeaconNode), a full
//! [`CellNode`](crate::cell_node::CellNode), or even a [`ServiceNode`](crate::service_node::ServiceNode))
//! together with a [`PorosHost`], dispatching each input to exactly one of them.
//!
//! ## Frame routing
//!
//! The three POROS host wire types — [`PorosRequest`](FrameType::PorosRequest) (a new node's admission
//! request to the combiner), [`PorosShareReq`](FrameType::PorosShareReq) (a combiner asking a member for its
//! descriptor share), and [`PorosShare`](FrameType::PorosShare) (a member's share) — go to the [`PorosHost`];
//! every other input goes to `inner`. This takes precedence over the inner engine's routing. The
//! [`PorosResponse`](FrameType::PorosResponse) is delivered to the *requesting client*, never to a host, so
//! it is intentionally **not** routed here (an inner engine ignores it, as it would any unknown frame).
//!
//! ## Timer namespacing
//!
//! Both the inner engine and the host are timer-driven and both number their tokens from zero (the host's
//! first gather deadline is `0`), so their spaces would collide on the shared wire clock. The host's tokens
//! are remapped into a range provably free of every inner token — **and** of the [`ServiceNode`] token range,
//! so an ingress host may itself wrap a service node. The tag is bits 63 clear, 62 set, 61 clear, 60 set
//! (`0b0101`, [`INGRESS_FLAG`]): a wrapped [`CellNode`] uses gather ids `< 2^62` (bit 62 clear), `COVER =
//! 1<<62` and the overlay heartbeat `(1<<62)|1` (both bit 60 clear), and `MIX_FLAG | id` (bit 63 set); a
//! wrapped [`ServiceNode`] uses `0b011` (bit 61 set) — none match `0b0101`. A fired token is dispatched by
//! that tag: `(token >> 60) == 0b0101` → the host (unmapped back), everything else → the inner engine.

use fanos_geometry::Triple;
use fanos_runtime::{Effect, Engine, Input, Instant, TimerToken};
use fanos_wire::{FrameType, decode_frame};

use crate::poros::PorosHost;

/// The four-bit tag (bits 63,62,61,60) that marks a timer token as the ingress host's: bits 63 and 61 clear,
/// bits 62 and 60 set. Chosen disjoint from every token an inner cell engine or a [`ServiceNode`] emits (see
/// the module docs).
const INGRESS_TAG: u64 = 0b0101;
/// The ingress-token flag: [`INGRESS_TAG`] shifted into the top four bits.
const INGRESS_FLAG: u64 = INGRESS_TAG << 60;
/// The low 60 bits carrying the host's own (inner) token beneath the flag.
const INGRESS_SEQ_MASK: u64 = (1 << 60) - 1;

/// A cell node that also hosts POROS ingress: an arbitrary `inner` cell engine plus a [`PorosHost`], both at
/// this node's coordinate, as one engine (see the module docs).
pub struct IngressNode {
    inner: Box<dyn Engine + Send>,
    host: PorosHost,
}

impl IngressNode {
    /// Compose `inner` (the node's ordinary cell engine) with an ingress `host`, both at this coordinate, into
    /// one engine that hosts POROS ingress alongside the cell role.
    #[must_use]
    pub fn new(inner: Box<dyn Engine + Send>, host: PorosHost) -> Self {
        Self { inner, host }
    }

    /// Whether `frame` is one of the POROS host wire types the [`PorosHost`] owns (the combiner/member frames,
    /// not the client-bound [`PorosResponse`](FrameType::PorosResponse)).
    fn is_ingress_frame(frame: &[u8]) -> bool {
        matches!(
            decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()),
            Some(FrameType::PorosRequest | FrameType::PorosShareReq | FrameType::PorosShare)
        )
    }

    /// Remap the host's outbound timer tokens into the [`INGRESS_FLAG`] range so they never collide with an
    /// inner-engine token; every other effect passes through untouched.
    fn tag_host_effects(effects: Vec<Effect>) -> Vec<Effect> {
        effects
            .into_iter()
            .map(|e| match e {
                Effect::ArmTimer { token, after } => Effect::ArmTimer {
                    token: TimerToken(INGRESS_FLAG | (token.0 & INGRESS_SEQ_MASK)),
                    after,
                },
                other => other,
            })
            .collect()
    }
}

impl Engine for IngressNode {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        match input {
            // A POROS host frame is the host's; every other frame is the inner engine's.
            Input::Message { .. } => {
                let to_host =
                    matches!(&input, Input::Message { frame, .. } if Self::is_ingress_frame(frame));
                if to_host {
                    Self::tag_host_effects(self.host.step(now, input))
                } else {
                    self.inner.step(now, input)
                }
            }
            // An ingress-tagged timer fires: hand the host its own (unmapped) token.
            Input::Timer(token) if (token.0 >> 60) == INGRESS_TAG => {
                let inner = Input::Timer(TimerToken(token.0 & INGRESS_SEQ_MASK));
                Self::tag_host_effects(self.host.step(now, inner))
            }
            // Every other timer is the inner engine's; and the host is purely frame/timer-driven, so every
            // command drives the inner cell engine too.
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
    use std::net::SocketAddr;

    use fanos_field::F2;
    use fanos_geometry::Point;
    use fanos_rendezvous::{BeaconSeed, Epoch};
    use fanos_runtime::{Command, Config as OverlayConfig, OverlayNode};
    use fanos_wire::decode_frame;

    use super::*;
    use crate::config::Peer;
    use crate::poros::{IngressDescriptor, request_frame, shard_descriptor, solve_ingress_request};

    const COMMUNITY: &[u8] = b"ingress-community";
    const EPOCH: Epoch = Epoch::new(1);
    const DIFFICULTY: u32 = 4;

    fn descriptor(n: usize) -> IngressDescriptor {
        IngressDescriptor {
            peers: (0..n)
                .map(|i| Peer {
                    coord: Point::<F2>::at(i % 7).coords(),
                    addr: SocketAddr::from(([10, 0, 0, i as u8], 9000 + i as u16)),
                })
                .collect(),
        }
    }

    /// A solo (1-of-1) ingress line so a single `IngressNode` is its own combiner and serves a bucket alone —
    /// enough to prove the composite dispatches POROS frames to the host and overlay frames to the inner engine.
    fn solo_ingress_node(seed: u8) -> (IngressNode, BeaconSeed) {
        let coord = Point::<F2>::at(0).coords();
        let beacon = BeaconSeed::new([seed; 32]);
        let desc = descriptor(6);
        let randomness = vec![0x33u8; desc.to_bytes().len() + 8];
        let shares = shard_descriptor(&desc, 1, 1, &randomness).unwrap();
        let host = PorosHost::new(
            coord,
            shares[0].clone(),
            vec![coord],
            1,
            COMMUNITY.to_vec(),
            EPOCH,
            beacon,
            DIFFICULTY,
        );
        let overlay = OverlayNode::<F2>::new(Point::<F2>::at(0), OverlayConfig::default());
        (IngressNode::new(Box::new(overlay), host), beacon)
    }

    #[test]
    fn an_ingress_node_serves_a_request_and_still_runs_the_overlay() {
        let (mut node, beacon) = solo_ingress_node(0x21);

        // An overlay command reaches the inner engine: StartHeartbeat arms the overlay's heartbeat timer.
        let started = node.step(Instant(0), Input::Command(Command::StartHeartbeat));
        assert!(
            started.iter().any(|e| matches!(e, Effect::ArmTimer { .. })),
            "the inner overlay armed its heartbeat — the composite delivered the command to it"
        );

        // A POROS frame reaches the host: a 1-of-1 line serves the (valid-PoW) request at once, sending the
        // requester a PorosResponse bucket. The overlay never sees the ingress frame.
        let requester = Point::<F2>::at(3).coords();
        let req = solve_ingress_request(requester, COMMUNITY, EPOCH, &beacon, DIFFICULTY);
        let served = node.step(Instant(1), Input::Message { from: requester, frame: request_frame(&req) });
        assert!(
            served.iter().any(|e| matches!(
                e,
                Effect::Send { to, frame }
                    if *to == requester
                        && decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()) == Some(FrameType::PorosResponse)
            )),
            "the composite routed the request to the POROS host, which served a PorosResponse bucket"
        );
        // Any timer the host armed rode out under the ingress tag, disjoint from every inner-engine token.
        for e in &served {
            if let Effect::ArmTimer { token, .. } = e {
                assert_eq!(token.0 >> 60, INGRESS_TAG, "a host timer is ingress-tagged");
            }
        }
    }

    #[test]
    fn an_ingress_gather_timer_is_tagged_and_routes_back_to_the_host() {
        // A 2-of-2 line cannot serve from the combiner alone, so the request stays pending behind a gather
        // deadline — armed under the ingress tag, and firing it must reach the host (dropping the pending
        // gather), never the inner overlay.
        let coord = Point::<F2>::at(0).coords();
        let other = Point::<F2>::at(1).coords();
        let beacon = BeaconSeed::new([0x44; 32]);
        let desc = descriptor(6);
        let randomness = vec![0x9u8; desc.to_bytes().len() + 8];
        let shares = shard_descriptor(&desc, 2, 2, &randomness).unwrap();
        let host = PorosHost::new(
            coord,
            shares[0].clone(),
            vec![coord, other],
            2,
            COMMUNITY.to_vec(),
            EPOCH,
            beacon,
            DIFFICULTY,
        );
        let overlay = OverlayNode::<F2>::new(Point::<F2>::at(0), OverlayConfig::default());
        let mut node = IngressNode::new(Box::new(overlay), host);

        let requester = Point::<F2>::at(4).coords();
        let req = solve_ingress_request(requester, COMMUNITY, EPOCH, &beacon, DIFFICULTY);
        let effects = node.step(Instant(0), Input::Message { from: requester, frame: request_frame(&req) });
        let armed = effects
            .iter()
            .find_map(|e| match e {
                Effect::ArmTimer { token, .. } => Some(*token),
                _ => None,
            })
            .expect("the pending gather armed a deadline timer");
        assert_eq!(
            armed.0 >> 60,
            INGRESS_TAG,
            "the gather deadline is armed under the ingress tag, disjoint from inner-engine tokens"
        );

        // Firing that tagged token reaches the host (the pending gather is dropped): the same request is then
        // treated as fresh (accepted, re-arming a gather) rather than suppressed as a pending duplicate.
        assert!(node.step(Instant(1), Input::Timer(armed)).is_empty());
        let refired = node.step(Instant(2), Input::Message { from: requester, frame: request_frame(&req) });
        assert!(
            refired.iter().any(|e| matches!(e, Effect::ArmTimer { .. })),
            "after the deadline dropped the gather, the same request is accepted anew — the tick reached the \
             host, not the overlay"
        );
    }
}
