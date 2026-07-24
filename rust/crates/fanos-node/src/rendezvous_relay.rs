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
use fanos_primitives::hash::{hash_labeled, label};
use fanos_rendezvous::{HostRegister, Request, SessionId, parse_host_register};
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
    /// `service_tag → registration`: an anonymously-registered hidden service hosted **off** this combiner
    /// (`design-anonymity-substrate.md` §3b). When a client request whose `service_tag` matches peels out
    /// here, this relay re-seals it as a NOSTOS onion to the service's registered dead-drop line — so the
    /// service is reachable without this node (or anyone) learning its coordinate. Bounded like
    /// `registrations`.
    hosts: BTreeMap<[u8; 32], HostRegister>,
    /// FIFO insertion order of `hosts`' tags, bounding the map at [`MAX_HOSTS`] against a registration flood.
    host_order: VecDeque<[u8; 32]>,
    /// Per-node seed for the fresh onion/e2e seeds each host-forward draws; deterministic (derived from this
    /// relay's coordinate) so a sim reproduces exactly, distinct per node so two combiners never collide.
    forward_seed: [u8; 32],
    /// Monotonic counter domain-separating each forward's seed pair, so no two forwards reuse key material.
    forward_counter: u64,
}

/// The cap on concurrently-registered bare-proxy client sessions (audit robustness B2). Beyond it, the
/// oldest registration is evicted FIFO, so an attacker streaming distinct cookies cannot grow the map without
/// bound. Generous enough for any real relay's concurrent fallback clients.
const MAX_REGISTRATIONS: usize = 4096;

/// The cap on concurrently-registered hidden-service hosts (§3b). A `HostRegister` peels out as an
/// anonymous delivery, so — like the client registrations — an unbounded map would be a remote OOM; beyond
/// the cap the oldest host is evicted FIFO (it re-registers each epoch anyway). Generous for any real cell.
const MAX_HOSTS: usize = 4096;

impl<F: Field> RendezvousRelay<F> {
    /// A relay wrapping `router`. No client or host is registered until one sends an
    /// [`RdvRegister`](fanos_wire::FrameType::RdvRegister) / a §3b host registration; until then it just routes.
    #[must_use]
    pub fn new(router: ThresholdRouter<F>) -> Self {
        // Derive the host-forward seed from this relay's coordinate: deterministic (sim-reproducible) and
        // per-node distinct, with no new constructor parameter to thread through every caller.
        let forward_seed = hash_labeled(label::KDF, &encode_coord(router.address()));
        Self {
            router,
            registrations: BTreeMap::new(),
            reg_order: VecDeque::new(),
            hosts: BTreeMap::new(),
            host_order: VecDeque::new(),
            forward_seed,
            forward_counter: 0,
        }
    }

    /// The number of hidden-service hosts currently registered here.
    #[must_use]
    pub fn hosts(&self) -> usize {
        self.hosts.len()
    }

    /// Record a hidden service's anonymous host registration (§3b): bind its `service_tag` to the route the
    /// relay forwards matching client requests through. Only **primary** (coordinate-hiding) registrations
    /// are accepted — a non-empty `forward_circuit` with self-provisioned keys; a bare-host registration
    /// (direct-coordinate fallback) is ignored here (its forwarding is a separate, weaker path). Bounded FIFO.
    fn register_host(&mut self, reg: HostRegister) {
        if reg.forward_circuit.is_empty() || reg.forward_keys.is_empty() {
            return;
        }
        let tag = reg.service_tag;
        if self.hosts.insert(tag, reg).is_none() {
            self.host_order.push_back(tag);
            if self.hosts.len() > MAX_HOSTS
                && let Some(oldest) = self.host_order.pop_front()
            {
                self.hosts.remove(&oldest);
            }
        }
    }

    /// The next `(e2e_seed, onion_seed)` pair for a host-forward — two independent fresh draws (the NOSTOS
    /// end-to-end nonce and the onion key material must not share entropy), advancing the counter.
    fn next_forward_seeds(&mut self) -> ([u8; 32], [u8; 32]) {
        let n = self.forward_counter;
        self.forward_counter += 1;
        let mut data = [0u8; 40];
        data[..32].copy_from_slice(&self.forward_seed);
        data[32..].copy_from_slice(&n.to_be_bytes());
        let e2e = hash_labeled(label::KDF, &data);
        // A distinct second draw: flip the domain by appending a marker byte.
        let mut data2 = [0u8; 41];
        data2[..40].copy_from_slice(&data);
        data2[40] = 0x01;
        let onion = hash_labeled(label::KDF, &data2);
        (e2e, onion)
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

    /// Rewrite the router's effects, resolving each peeled anonymous delivery in priority order:
    /// 1. a **registered client's** cookie-tagged reply → an [`RdvReply`](fanos_wire::FrameType::RdvReply)
    ///    `Send` to that client (the bare-proxy fallback — the relay knows the *client*, never the service);
    /// 2. a **§3b host registration** → bind the hidden service's forward route (no effect emitted);
    /// 3. a **client request naming a registered host** → re-seal it as a NOSTOS onion to that host's
    ///    dead-drop line and `Send` it on — so the service is reachable though it is *not* this combiner and
    ///    this relay learns neither endpoint's coordinate;
    /// 4. anything else → pass through as a local anonymous delivery (the service *is* its own combiner, or an
    ///    unrelated onion). The rule is additive: with no clients and no hosts registered, every delivery
    ///    falls straight through and the relay is a plain router.
    fn process_deliveries(&mut self, effects: Vec<Effect>) -> Vec<Effect> {
        // Every anonymous delivery is inspected — no empty-map fast path: the *first* host registration
        // arrives while `hosts` is still empty, so skipping classification then would never bind it.
        let mut out = Vec::with_capacity(effects.len());
        for e in effects {
            match e {
                Effect::Notify(Notification::Delivered { from, payload }) if from == ANONYMOUS => {
                    out.extend(self.classify_anonymous(payload));
                }
                other => out.push(other),
            }
        }
        out
    }

    /// Resolve one peeled anonymous delivery to its effect(s) (see [`Self::process_deliveries`]).
    fn classify_anonymous(&mut self, payload: Vec<u8>) -> Vec<Effect> {
        // 1. A registered client's cookie-tagged reply → forward to that client.
        if let Some(client) = payload
            .get(..size_of::<SessionId>())
            .and_then(|c| <SessionId>::try_from(c).ok())
            .and_then(|cookie| self.registrations.get(&cookie))
        {
            return vec![Effect::Send { to: *client, frame: framed(FrameType::RdvReply, &payload) }];
        }
        // 2. A host registration → bind it (primary, coordinate-hiding registrations only).
        if let Some(reg) = parse_host_register(&payload) {
            self.register_host(reg);
            return Vec::new();
        }
        // 3. A client request naming a registered host → re-seal to that host's dead-drop and forward.
        if let Some(req) = Request::decode(&payload)
            && req.service_tag != [0u8; 32]
            && let Some(reg) = self.hosts.get(&req.service_tag).cloned()
        {
            let (e2e, onion) = self.next_forward_seeds();
            return match reg.seal_forward_to_host::<F>(&payload, &e2e, &onion) {
                Some(fwd) => vec![Effect::Send { to: fwd.combiner, frame: fwd.frame }],
                // A registered host whose route we cannot seal to: drop, don't surface locally (this node
                // is not the service — a local delivery would be answered by the wrong party).
                None => Vec::new(),
            };
        }
        // 4. Otherwise a local anonymous delivery (the service is its own combiner, or an unrelated onion).
        vec![Effect::Notify(Notification::Delivered { from: ANONYMOUS, payload })]
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

/// A coordinate's canonical bytes (three big-endian `u32`s), for deriving this relay's forward seed. Built
/// once at construction, so the small allocation is immaterial.
fn encode_coord(coord: Triple) -> Vec<u8> {
    coord.iter().flat_map(|c| c.to_be_bytes()).collect()
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
        // Everything else is onion traffic: route it, then resolve each peeled anonymous delivery (client
        // reply / host registration / request-for-a-registered-host / local).
        let effects = self.router.step(now, input);
        self.process_deliveries(effects)
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

    /// §3b: a hidden service registers **anonymously** at its meeting combiner, then a matching client
    /// request peeled there is re-sealed to the service's dead-drop line and forwarded on — not surfaced
    /// locally. The relay learns neither the service's coordinate (it registered by onion, naming only a
    /// line) nor the client's (the request names only its own dead-drop line).
    #[test]
    fn a_relay_forwards_a_request_to_an_anonymously_registered_host() {
        use fanos_pqcrypto::HybridKemSecret;
        use fanos_rendezvous::{HOST_REGISTER_TAG, MixDirectory, combiner_for, service_tag};

        // A KEM key at every Fano point, so any line's members can be sealed to (the host's forward route).
        let mut dir = MixDirectory::new();
        for i in 0..7u8 {
            let (_s, public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xD0, i]));
            dir.insert(Point::<F2>::at(usize::from(i)).coords(), public);
        }

        // The relay sits at line L's combiner (t = 1: the combiner is member 0).
        let l = Line::<F2>::at(0).coords();
        let combiner = Point::<F2>::new(line_member_coords::<F2>(l)[0]).unwrap();
        let onion_seed = [0xA5u8; 32];
        let (identity, _) = HybridKemSecret::generate(&mut SeedRng::from_seed(b"host-relay-id"));
        let mut relay =
            RendezvousRelay::new(ThresholdRouter::<F2>::new(combiner, &identity, 1, onion_seed));
        let relay_onion = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xA5, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0xA5, 2]));
        let pubs = [relay_onion.public(), &p1, &p2];
        // Seal a single-hop onion to L carrying `body`, peelable by the relay (member 0, t = 1).
        let seal_to_relay = |body: &[u8], seed: &[u8]| {
            let onion = seal_onion(&[HopLine { line: l, members: &pubs }], 1, body, seed).unwrap();
            launch_frame(l, &onion)
        };

        // The service's meeting tag and its dead-drop line L_O (a different line). It registers by onion.
        let tag = service_tag(b"a-hidden-service-key", Epoch::new(0));
        let drop_line = Line::<F2>::at(3).coords();
        let (_svc_keys, svc_reply_pub) =
            fanos_aphantos::nostos::ReplyKeys::generate(b"svc-deaddrop");
        let reg = HostRegister::onion::<F2>(tag, svc_reply_pub.encode(), vec![drop_line], &dir, 1)
            .expect("the dead-drop line's members are in the directory");
        let mut reg_body = HOST_REGISTER_TAG.to_vec();
        reg_body.extend_from_slice(&reg.encode());
        relay.step(Instant(0), Input::Message { from: [9, 9, 9], frame: seal_to_relay(&reg_body, b"reg") });
        assert_eq!(relay.hosts(), 1, "the anonymous host registration was bound by its tag");

        // A client request naming that service_tag, peeled at the relay, is forwarded to the dead-drop.
        let request = Request {
            cookie: *b"client-cookie-01",
            service_tag: tag,
            reply_circuit: vec![Line::<F2>::at(5).coords()],
            payload: b"a DIAULOS ClientHello".to_vec(),
            reply_pub: b"client-reply-key".to_vec(),
        }
        .encode();
        let effects =
            relay.step(Instant(1), Input::Message { from: [8, 8, 8], frame: seal_to_relay(&request, b"req") });
        let drop_combiner = combiner_for::<F2>(drop_line).unwrap();
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Send { to, .. } if *to == drop_combiner)),
            "the request is re-sealed and forwarded to the service's dead-drop line combiner",
        );
        assert!(
            !effects.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Delivered { from, .. }) if *from == ANONYMOUS
            )),
            "the request left for the host, not surfaced locally (this node is not the service)",
        );

        // A request for an UNregistered tag falls through to a local anonymous delivery (unchanged behaviour).
        let other = Request {
            cookie: *b"client-cookie-02",
            service_tag: service_tag(b"some-other-service", Epoch::new(0)),
            reply_circuit: vec![],
            payload: b"unrelated".to_vec(),
            reply_pub: vec![],
        }
        .encode();
        let effects =
            relay.step(Instant(2), Input::Message { from: [7, 7, 7], frame: seal_to_relay(&other, b"oth") });
        assert!(
            effects.iter().any(|e| matches!(
                e,
                Effect::Notify(Notification::Delivered { from, .. }) if *from == ANONYMOUS
            )),
            "a request for no registered host surfaces locally, as before",
        );
    }
}
