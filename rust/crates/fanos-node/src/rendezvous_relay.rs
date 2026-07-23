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
//! This is Tor's rendezvous-point model, and it is the **bare-proxy fallback**: the relay learns the
//! client's coordinate (which the client chose) but never the service. The stronger, primary path — where
//! the client's coordinate never leaves its node at all — is **NOSTOS** ([`fanos_aphantos::nostos`]): a
//! full cell-node client receives its replies as a member of its own beacon-blinded dead-drop line, needing
//! no relay and exposing no coordinate. This relay serves only the residual case of a client that cannot be
//! a line member. (It supersedes the earlier single-relay SURB, now retired.)
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

use std::collections::{BTreeMap, VecDeque};

use fanos_aphantos::ThresholdRouter;
use fanos_aphantos::threshold_router::ANONYMOUS;
use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_rendezvous::SessionId;
use fanos_runtime::{Effect, Engine, Input, Instant, Notification};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// A rendezvous relay: a [`ThresholdRouter`] plus a table of the clients whose anonymous replies it
/// forwards, keyed by each client's session cookie. Construct it at a **combiner** coordinate (the relay's
/// line's combiner).
pub struct RendezvousRelay<F: Field> {
    router: ThresholdRouter<F>,
    /// `cookie → client coordinate`: a peeled reply prefixed with `cookie` is forwarded straight to the
    /// registered coordinate as an [`RdvReply`](fanos_wire::FrameType::RdvReply). The relay learns that
    /// coordinate — the **bare-proxy fallback**; a full cell-node client uses NOSTOS instead and never
    /// registers here (its coordinate never leaves its node).
    registrations: BTreeMap<SessionId, Triple>,
    /// FIFO insertion order of `registrations`' cookies, so the map can be **bounded** (audit robustness B2):
    /// an `RdvRegister` carries an attacker-chosen 16-byte cookie, so an unbounded map is a single-peer remote
    /// OOM. At [`MAX_REGISTRATIONS`] the oldest registration is evicted — a bound, not a leak (an evicted client
    /// simply re-registers; the bare-proxy fallback is best-effort by design).
    reg_order: VecDeque<SessionId>,
}

/// The cap on concurrently-registered bare-proxy client sessions (audit robustness B2). Beyond it, the
/// oldest registration is evicted FIFO, so an attacker streaming distinct cookies cannot grow the map without
/// bound. Generous enough for any real relay's concurrent fallback clients.
const MAX_REGISTRATIONS: usize = 4096;

impl<F: Field> RendezvousRelay<F> {
    /// A relay wrapping `router`. No client is registered until one sends an
    /// [`RdvRegister`](fanos_wire::FrameType::RdvRegister); until then the relay just routes.
    #[must_use]
    pub fn new(router: ThresholdRouter<F>) -> Self {
        Self {
            router,
            registrations: BTreeMap::new(),
            reg_order: VecDeque::new(),
        }
    }

    /// The coordinate registered for `cookie` (the bare-proxy fallback), if any.
    #[must_use]
    pub fn client_for(&self, cookie: &SessionId) -> Option<Triple> {
        self.registrations.get(cookie).copied()
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
                        // Forward the reply straight to the registered coordinate (the bare-proxy fallback):
                        // the relay knows the client's coordinate but never the service.
                        Some(client) => {
                            Effect::Send { to: *client, frame: framed(FrameType::RdvReply, &payload) }
                        }
                        None => Effect::Notify(Notification::Delivered { from, payload }),
                    }
                }
                other => other,
            })
            .collect()
    }

    /// Record a client's registration: a 16-byte cookie binds this session to the sender's coordinate, so
    /// the relay forwards that session's replies there (the bare-proxy fallback). A body that is not exactly
    /// a 16-byte cookie (wrong length or trailing bytes) is ignored.
    fn register(&mut self, body: &[u8], from: Triple) {
        let Ok(cookie) = <SessionId>::try_from(body) else {
            return;
        };
        // A re-registration of a known cookie just refreshes its coordinate (no new slot, no order change); a
        // new cookie takes a fresh slot and pushes to the FIFO order. `reg_order` and `registrations` track
        // exactly the same set (a cookie is enqueued when inserted-as-new and dequeued when evicted), so on
        // overflow evicting the single oldest restores the bound (audit B2) — a bounded map, not a leak.
        if self.registrations.insert(cookie, from).is_none() {
            self.reg_order.push_back(cookie);
            if self.registrations.len() > MAX_REGISTRATIONS
                && let Some(oldest) = self.reg_order.pop_front()
            {
                self.registrations.remove(&oldest);
            }
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
            // A client registers a session cookie: the relay forwards that session's replies to the
            // sender's coordinate (the bare-proxy fallback).
            if decoded.frame_type() == Some(FrameType::RdvRegister) {
                self.register(decoded.body, *from);
                return Vec::new();
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
/// ([`RdvRegister`](fanos_wire::FrameType::RdvRegister)): a 16-byte `cookie` binds the session so the relay
/// forwards its replies to the sender's coordinate — the **bare-proxy fallback**, for a client that cannot
/// be a line member. A full cell-node client uses NOSTOS and never registers here.
#[must_use]
pub fn register_frame(cookie: SessionId) -> Vec<u8> {
    framed(FrameType::RdvRegister, &cookie)
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
    fn the_registration_map_is_bounded_against_a_cookie_flood() {
        // Audit B2: an RdvRegister carries an attacker-chosen 16-byte cookie, so an unbounded map is a
        // single-peer remote OOM. Streaming MAX_REGISTRATIONS + K distinct cookies must leave the map capped
        // at MAX_REGISTRATIONS (the oldest evicted FIFO), and a re-registration must not grow it.
        let line = Line::<F2>::at(0).coords();
        let combiner = Point::<F2>::new(line_member_coords::<F2>(line)[0]).unwrap();
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"flood-id"));
        let mut relay =
            RendezvousRelay::new(ThresholdRouter::<F2>::new(combiner, &identity, 1, [0x5D; 32]));

        let cookie_of = |i: u32| -> SessionId {
            let mut c = [0u8; 16];
            c[..4].copy_from_slice(&i.to_be_bytes());
            c
        };
        let overflow = 50u32;
        for i in 0..(MAX_REGISTRATIONS as u32 + overflow) {
            relay.step(Instant(0), Input::Message { from: [1, 2, 3], frame: register_frame(cookie_of(i)) });
        }
        assert_eq!(relay.registrations(), MAX_REGISTRATIONS, "the map is capped, not unbounded");
        // The oldest `overflow` cookies were evicted FIFO; the most recent are retained.
        assert!(relay.client_for(&cookie_of(0)).is_none(), "the oldest registration was evicted");
        assert_eq!(
            relay.client_for(&cookie_of(MAX_REGISTRATIONS as u32 + overflow - 1)),
            Some([1, 2, 3]),
            "the newest registration is retained",
        );
        // A re-registration of a still-present cookie refreshes its coordinate without growing the map.
        let recent = cookie_of(MAX_REGISTRATIONS as u32 + overflow - 1);
        relay.step(Instant(0), Input::Message { from: [7, 7, 7], frame: register_frame(recent) });
        assert_eq!(relay.registrations(), MAX_REGISTRATIONS, "a re-registration does not grow the bounded map");
        assert_eq!(relay.client_for(&recent), Some([7, 7, 7]), "but it does refresh the coordinate");
    }

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
                frame: register_frame(cookie),
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
                    frame: register_frame(ck),
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

}
