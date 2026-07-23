//! `RendezvousRelay` — a designated rendezvous point that relays clients' replies (audit #54, item 3).
//!
//! A client's reply circuit ends at a rendezvous **line**, whose *combiner* peels the reply onion and
//! delivers it. But only a strict subset of a plane's points are combiners (Fano: 4 of 7) *and* a node's
//! coordinate reshuffles every epoch, so a client cannot reliably be its own reply rendezvous — and an
//! external `.fanos` client (running only an overlay node, never a router) can never peel an onion at all.
//! It instead **engages a relay**: it registers its session cookie with a node sitting at a combiner (an
//! [`RdvRegister`](fanos_wire::FrameType::RdvRegister) frame carrying the 16-byte cookie), names that
//! relay's line as its reply circuit's last hop, and the relay forwards each anonymous reply it peels —
//! tagged by that cookie — to the client's real coordinate as an [`RdvReply`](fanos_wire::FrameType::RdvReply).
//! This is Tor's rendezvous-point model. In the **legacy** mode the relay learns the client's coordinate
//! (which the client chose) but never the service. That coordinate is the residual **S1-H3** leak: a relay
//! colluding with the exit re-links client ↔ target. So a client may instead register a **SURB** — a
//! [`Surb`](fanos_aphantos::surb::Surb) carried in the same `RdvRegister` — and the relay injects each reply
//! into that pre-sealed return path, learning only its first hop, never the coordinate. Both modes coexist
//! (backward-compatible); the SURB mode is the one that closes the correlator (`docs/design-surb.md`).
//!
//! **Shared by cookie.** One combiner relays for *many* clients at once: each reply carries the
//! [`RendezvousService`](fanos_rendezvous::RendezvousService)'s 16-byte session-cookie prefix
//! ([`seal_reply`](fanos_rendezvous::RendezvousService::seal_reply)), so the relay demultiplexes replies
//! to the right registered client with no per-client relay instance. A reply whose cookie matches no
//! registration passes through as a local anonymous delivery — which is exactly the *service's* own
//! meeting-line combiner (no client registers there), so a forward request still surfaces locally.
//!
//! [`RendezvousRelay`] composes a [`ThresholdRouter`] (which peels the reply hops) with the forwarding
//! rule, as one sans-I/O engine — so a relay is one spawnable engine, exactly like [`crate::MixRelay`]
//! (which composes this to make every cell relay a rendezvous point). It is *additive*: a client that
//! already sits at a combiner keeps listening there directly; nothing in the sealing path changes.

use std::collections::BTreeMap;

use fanos_aphantos::ThresholdRouter;
use fanos_aphantos::surb::{Surb, SurbOutcome, inject_reply};
use fanos_aphantos::threshold_router::ANONYMOUS;
use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_rendezvous::SessionId;
use fanos_runtime::{Effect, Engine, Input, Instant, Notification};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// How the relay forwards a session's anonymous replies once it peels one at its combiner.
enum Registration {
    /// Legacy (audit #54): forward the reply directly to this coordinate — the relay learns it (the S1-H3
    /// leak this exists to phase out). Registered by a bare-cookie `RdvRegister`.
    Coord(Triple),
    /// SURB (audit §5 S1-H3): inject the reply into this pre-sealed return path, so the relay learns only the
    /// first return hop, never the client's coordinate. Registered by a `RdvRegister` carrying a [`Surb`].
    /// Boxed so the enum stays small (a SURB holds a full-onion header).
    Reply(Box<Surb>),
}

/// A rendezvous relay: a [`ThresholdRouter`] plus a table of the clients whose anonymous replies it
/// forwards, keyed by each client's session cookie. Construct it at a **combiner** coordinate (the relay's
/// line's combiner).
pub struct RendezvousRelay<F: Field> {
    router: ThresholdRouter<F>,
    /// `cookie → how to forward its replies` — a peeled reply prefixed with `cookie` is either sent directly
    /// (legacy [`Coord`](Registration::Coord)) or injected into a SURB return path
    /// ([`Reply`](Registration::Reply)).
    registrations: BTreeMap<SessionId, Registration>,
}

impl<F: Field> RendezvousRelay<F> {
    /// A relay wrapping `router`. No client is registered until one sends an
    /// [`RdvRegister`](fanos_wire::FrameType::RdvRegister); until then the relay just routes.
    #[must_use]
    pub fn new(router: ThresholdRouter<F>) -> Self {
        Self {
            router,
            registrations: BTreeMap::new(),
        }
    }

    /// The coordinate registered for `cookie`, if any — only for a **legacy** coordinate registration; a SURB
    /// registration returns `None`, precisely because the relay does not learn the client's coordinate (S1-H3).
    #[must_use]
    pub fn client_for(&self, cookie: &SessionId) -> Option<Triple> {
        match self.registrations.get(cookie) {
            Some(Registration::Coord(coord)) => Some(*coord),
            _ => None,
        }
    }

    /// The number of client sessions currently registered.
    #[must_use]
    pub fn registrations(&self) -> usize {
        self.registrations.len()
    }

    /// A shared reference to the wrapped router (for a composite engine to read its onion-key state).
    #[must_use]
    pub fn router(&self) -> &ThresholdRouter<F> {
        &self.router
    }

    /// A mutable reference to the wrapped router (for a composite engine to drive its epoch rotation).
    pub fn router_mut(&mut self) -> &mut ThresholdRouter<F> {
        &mut self.router
    }

    /// Rewrite the router's effects: an anonymous delivery (a peeled reply) whose leading 16 bytes match a
    /// registered cookie becomes an [`RdvReply`](fanos_wire::FrameType::RdvReply) `Send` to that client's
    /// coordinate — so the reply reaches the client while the service that sealed it never learned that
    /// coordinate. A delivery with no matching registration passes through unchanged (a plain router, e.g.
    /// the service's own meeting-line combiner, or a client co-located at its combiner).
    fn relay_deliveries(&self, effects: Vec<Effect>) -> Vec<Effect> {
        if self.registrations.is_empty() {
            return effects;
        }
        effects
            .into_iter()
            .map(|e| match e {
                Effect::Notify(Notification::Delivered { from, payload })
                    if from == ANONYMOUS =>
                {
                    match payload
                        .get(..size_of::<SessionId>())
                        .and_then(|c| <SessionId>::try_from(c).ok())
                        .and_then(|cookie| self.registrations.get(&cookie))
                    {
                        // Legacy: send the reply straight to the registered coordinate (the relay knows it).
                        Some(Registration::Coord(client)) => {
                            Effect::Send { to: *client, frame: framed(FrameType::RdvReply, &payload) }
                        }
                        // SURB: inject the reply into the client's return path — the relay forwards to the
                        // first return hop, never learning the client's coordinate (S1-H3). A reply too large
                        // for the SURB bucket falls through to a local delivery rather than being dropped.
                        Some(Registration::Reply(surb)) => match inject_reply(surb, &payload) {
                            Ok(packet) => Effect::Send { to: surb.first_hop, frame: framed(FrameType::SurbPacket, &packet) },
                            Err(_) => Effect::Notify(Notification::Delivered { from, payload }),
                        },
                        None => Effect::Notify(Notification::Delivered { from, payload }),
                    }
                }
                other => other,
            })
            .collect()
    }

    /// Record a client's registration: a bare 16-byte cookie is the legacy coordinate registration (forward to
    /// the sender); a cookie followed by a [`Surb`] registers the SURB return path. A malformed body is ignored.
    fn register(&mut self, body: &[u8], from: Triple) {
        let Some((cookie_bytes, rest)) = body.split_at_checked(size_of::<SessionId>()) else {
            return;
        };
        let Ok(cookie) = <SessionId>::try_from(cookie_bytes) else {
            return;
        };
        let registration = if rest.is_empty() {
            Registration::Coord(from)
        } else if let Some(surb) = Surb::from_bytes(rest) {
            Registration::Reply(Box::new(surb))
        } else {
            return; // a present-but-malformed SURB is refused, never silently downgraded to a coordinate leak
        };
        self.registrations.insert(cookie, registration);
    }

    /// Route one hop of a SURB return packet: peel it with the router's onion secret, then re-emit it to the
    /// next return hop, or deliver the reply to the client — the only node on the path that learns the coord.
    fn route_surb(&self, packet: &[u8]) -> Vec<Effect> {
        match self.router.peel_surb(packet) {
            Some(SurbOutcome::Forward { next, packet }) => {
                vec![Effect::Send { to: next, frame: framed(FrameType::SurbPacket, &packet) }]
            }
            Some(SurbOutcome::Deliver { coord, block }) => {
                vec![Effect::Send { to: coord, frame: framed(FrameType::RdvReply, &block) }]
            }
            None => Vec::new(),
        }
    }
}

/// Encode `body` as a `frame_type` wire frame.
fn framed(frame_type: FrameType, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    encode_frame(frame_type.code(), body, &mut frame);
    frame
}

impl<F: Field> Engine for RendezvousRelay<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        if let Input::Message { from, frame } = &input
            && let Ok((decoded, _)) = decode_frame(frame)
        {
            match decoded.frame_type() {
                // A client registers a session cookie — legacy (bare cookie ⇒ forward to the sender) or SURB
                // (cookie ‖ Surb ⇒ forward through the pre-sealed return path, learning no coordinate).
                Some(FrameType::RdvRegister) => {
                    self.register(decoded.body, *from);
                    return Vec::new();
                }
                // A SURB return packet in transit: peel one hop and forward it onward, or deliver it.
                Some(FrameType::SurbPacket) => return self.route_surb(decoded.body),
                _ => {}
            }
        }
        // Everything else is onion traffic: route it, then forward any peeled reply to its client.
        let effects = self.router.step(now, input);
        self.relay_deliveries(effects)
    }

    fn address(&self) -> Triple {
        self.router.address()
    }
}

/// The frame a client sends to register with a rendezvous relay
/// ([`RdvRegister`](fanos_wire::FrameType::RdvRegister)). A bare `cookie` keeps the legacy path — the relay
/// forwards replies to the sender's coordinate. Passing a `surb` instead registers a SURB return path, so the
/// relay forwards through it and **never learns the client's coordinate** (audit §5 S1-H3).
#[must_use]
pub fn register_frame(cookie: SessionId, surb: Option<&Surb>) -> Vec<u8> {
    let mut body = cookie.to_vec();
    if let Some(surb) = surb {
        body.extend_from_slice(&surb.to_bytes());
    }
    framed(FrameType::RdvRegister, &body)
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
    use fanos_runtime::Epoch;

    #[test]
    fn a_relay_forwards_anonymous_replies_to_the_registered_client() {
        // The relay sits at a Fano line's combiner and peels the reply hop (t = 1). A non-combiner client
        // registers, then a reply onion sealed to that line arrives: the relay forwards the peeled reply
        // to the client's coordinate instead of surfacing a local anonymous delivery.
        let line = Line::<F2>::at(0).coords();
        let members = line_member_coords::<F2>(line);
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let onion_seed = [0x3D; 32];

        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"relay-id"));
        let mut relay = RendezvousRelay::new(ThresholdRouter::<F2>::new(
            combiner, &identity, 1, onion_seed,
        ));

        // A client at a non-combiner coordinate registers its session cookie with the relay.
        let client: Triple = [0x0C, 0x0C, 0x0C];
        let cookie: SessionId = *b"relay-cookie-001";
        relay.step(
            Instant(0),
            Input::Message {
                from: client,
                frame: register_frame(cookie, None),
            },
        );
        assert_eq!(
            relay.client_for(&cookie),
            Some(client),
            "the client is registered for its cookie"
        );

        // Seal a single-hop reply onion to the relay's line, sealed to the relay's forward-secure onion
        // public (the combiner is member 0; the other members never reply at t = 1). The service tags the
        // reply with the session cookie so the relay can demultiplex it.
        let relay_onion = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x3D, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x3D, 2]));
        let pubs = [relay_onion.public(), &p1, &p2];
        let mut payload = cookie.to_vec();
        payload.extend_from_slice(b"anonymous reply for the client");
        let onion = seal_onion(
            &[HopLine {
                line,
                members: &pubs,
            }],
            1,
            &payload,
            b"relay-seed",
        )
        .unwrap();

        // The reply arrives: the relay peels it (t = 1), matches the cookie, and forwards the full
        // cookie-tagged reply to the registered client wrapped in an RdvReply (the client strips the cookie).
        let effects = relay.step(
            Instant(1),
            Input::Message {
                from: [9, 9, 9],
                frame: launch_frame(line, &onion),
            },
        );
        let forwarded = effects
            .iter()
            .find_map(|e| match e {
                Effect::Send { to, frame } if *to == client => Some(frame.clone()),
                _ => None,
            })
            .expect("the relay forwards the peeled reply to the registered client");
        let (decoded, _) = decode_frame(&forwarded).unwrap();
        assert_eq!(decoded.frame_type(), Some(FrameType::RdvReply));
        assert_eq!(
            decoded.body,
            payload.as_slice(),
            "the full cookie-tagged reply is forwarded for the client to strip"
        );
        assert!(
            !effects.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Delivered { from, .. }) if *from == ANONYMOUS
            )),
            "the reply left for the client, not surfaced as a local anonymous delivery"
        );
    }

    #[test]
    fn one_shared_relay_demultiplexes_two_clients_by_cookie() {
        // The property a shared cell relay needs: two clients register distinct cookies at the SAME
        // combiner; each service reply, tagged by cookie, is forwarded to the correct client — no
        // per-client relay instance.
        let line = Line::<F2>::at(0).coords();
        let members = line_member_coords::<F2>(line);
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let onion_seed = [0x7Eu8; 32];
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"shared-relay"));
        let mut relay =
            RendezvousRelay::new(ThresholdRouter::<F2>::new(combiner, &identity, 1, onion_seed));

        let alice: Triple = [0x0A, 0x0A, 0x0A];
        let bob: Triple = [0x0B, 0x0B, 0x0B];
        let cookie_a: SessionId = *b"alice-cookie-000";
        let cookie_b: SessionId = *b"bob-cookie-00000";
        for (who, ck) in [(alice, cookie_a), (bob, cookie_b)] {
            relay.step(
                Instant(0),
                Input::Message {
                    from: who,
                    frame: register_frame(ck, None),
                },
            );
        }
        assert_eq!(relay.registrations(), 2, "both clients are registered");

        let relay_onion = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x7E, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x7E, 2]));
        let pubs = [relay_onion.public(), &p1, &p2];
        // Bob's reply, tagged with Bob's cookie, must reach Bob and not Alice.
        let mut payload = cookie_b.to_vec();
        payload.extend_from_slice(b"for bob only");
        let onion = seal_onion(
            &[HopLine {
                line,
                members: &pubs,
            }],
            1,
            &payload,
            b"shared-seed",
        )
        .unwrap();
        let effects = relay.step(
            Instant(1),
            Input::Message {
                from: [9, 9, 9],
                frame: launch_frame(line, &onion),
            },
        );
        let dests: Vec<Triple> = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Send { to, .. } => Some(*to),
                _ => None,
            })
            .collect();
        assert!(dests.contains(&bob), "the cookie-tagged reply reached Bob");
        assert!(
            !dests.contains(&alice),
            "it did not leak to the other registered client"
        );
    }

    #[test]
    fn without_a_registered_client_the_relay_is_a_plain_router() {
        // Before any registration, an anonymous delivery passes through unchanged — the relay is inert.
        let line = Line::<F2>::at(1).coords();
        let members = line_member_coords::<F2>(line);
        let combiner = Point::<F2>::new(members[0]).unwrap();
        let onion_seed = [0x4Du8; 32];
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"relay-id-2"));
        let mut relay = RendezvousRelay::new(ThresholdRouter::<F2>::new(
            combiner, &identity, 1, onion_seed,
        ));
        assert_eq!(relay.registrations(), 0);

        let relay_onion = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x4D, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x4D, 2]));
        let pubs = [relay_onion.public(), &p1, &p2];
        let payload = b"unrelayed reply";
        let onion = seal_onion(
            &[HopLine {
                line,
                members: &pubs,
            }],
            1,
            payload,
            b"relay-seed-2",
        )
        .unwrap();
        let effects = relay.step(
            Instant(1),
            Input::Message {
                from: [9, 9, 9],
                frame: launch_frame(line, &onion),
            },
        );
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Delivered { from, payload: p })
                    if *from == ANONYMOUS && p.as_slice() == payload.as_slice()
            )),
            "with no client, the anonymous delivery passes through unchanged"
        );
    }

    #[test]
    fn a_surb_registration_hides_the_coordinate_and_the_relay_routes_a_return_packet() {
        use fanos_aphantos::surb::{build_surb, open_reply};
        use fanos_nyx::build_circuit;
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"surb-relay"));
        let mut relay = RendezvousRelay::new(ThresholdRouter::<F2>::new(Point::<F2>::at(0), &identity, 1, [0x44; 32]));
        let circuit = build_circuit(Point::<F2>::at(1), Point::<F2>::at(3), 1, b"ret").unwrap();
        let client_coord = Point::<F2>::at(5).coords();

        // A SURB registration stores the return path but exposes NO coordinate (the S1-H3 property).
        let (_d, dpub) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"delivery"));
        let (surb, _keys) = build_surb(&circuit, &[&dpub], client_coord, b"reg").unwrap();
        let cookie = [0xAB; 16];
        relay.step(Instant(0), Input::Message { from: client_coord, frame: register_frame(cookie, Some(&surb)) });
        assert_eq!(relay.registrations(), 1, "the SURB session is registered");
        assert_eq!(relay.client_for(&cookie), None, "a SURB registration does not expose the client coordinate");

        // A SURB return packet whose delivery hop is sealed to THIS relay is peeled and delivered to the coord.
        let (surb2, keys2) = build_surb(&circuit, &[relay.router().onion_public()], client_coord, b"pkt").unwrap();
        let packet = inject_reply(&surb2, b"reply-payload").unwrap();
        let out = relay.step(Instant(1), Input::Message {
            from: Point::<F2>::at(2).coords(),
            frame: framed(FrameType::SurbPacket, &packet),
        });
        match out.as_slice() {
            [Effect::Send { to, frame }] => {
                assert_eq!(*to, client_coord, "the relay (delivery node) delivers to the client coordinate");
                let (decoded, _) = decode_frame(frame).unwrap();
                assert_eq!(decoded.frame_type(), Some(FrameType::RdvReply), "as an RdvReply");
                assert_eq!(open_reply(decoded.body, &keys2).unwrap(), b"reply-payload", "and the reply opens");
            }
            _ => panic!("the relay routes the SURB packet to delivery"),
        }
    }
}
