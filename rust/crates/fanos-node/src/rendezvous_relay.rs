//! `RendezvousRelay` — a designated rendezvous point that relays a client's replies (audit #54, item 3).
//!
//! A client's reply circuit ends at a rendezvous **line**, whose *combiner* peels the reply onion and
//! delivers it. But only a strict subset of a plane's points are combiners (Fano: 4 of 7), so a client
//! whose own coordinate is not a combiner — or which is not a cell member at all (an external `.fanos`
//! client) — cannot be its own reply rendezvous. It instead **engages a relay**: it registers with a
//! node sitting at a combiner (an [`RdvRegister`](fanos_wire::FrameType::RdvRegister) frame), names that
//! relay's line as its reply circuit's last hop, and the relay forwards each anonymous reply it peels to
//! the client's real coordinate. This is Tor's rendezvous-point model: the relay learns the client's
//! coordinate (which the client chose), but the **service never does** — it sealed only to the reply
//! line, so the client's location stays hidden from its peer.
//!
//! [`RendezvousRelay`] composes a [`ThresholdRouter`] (which peels the reply hops) with the forwarding
//! rule, as one sans-I/O engine — so a relay is one spawnable engine, exactly like [`crate::MixRelay`].
//! It is *additive*: a client that already sits at a combiner keeps listening there directly; nothing in
//! the sealing path or the existing rendezvous changes.

use fanos_aphantos::ThresholdRouter;
use fanos_aphantos::threshold_router::ANONYMOUS;
use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_runtime::{Effect, Engine, Input, Instant, Notification};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// A rendezvous relay: a [`ThresholdRouter`] plus the coordinate of the client whose anonymous replies it
/// forwards. Construct it at a **combiner** coordinate (the relay's line's combiner).
pub struct RendezvousRelay<F: Field> {
    router: ThresholdRouter<F>,
    client: Option<Triple>,
}

impl<F: Field> RendezvousRelay<F> {
    /// A relay wrapping `router`. No client is registered until one sends an
    /// [`RdvRegister`](fanos_wire::FrameType::RdvRegister); until then the relay just routes.
    #[must_use]
    pub fn new(router: ThresholdRouter<F>) -> Self {
        Self {
            router,
            client: None,
        }
    }

    /// The client currently registered to receive relayed replies, if any.
    #[must_use]
    pub fn client(&self) -> Option<Triple> {
        self.client
    }

    /// Rewrite the router's effects: an anonymous delivery (a peeled reply) becomes a `Send` to the
    /// registered client, so the reply reaches the coordinate the client registered while the service that
    /// sealed it never learned that coordinate. With no client registered the delivery passes through
    /// unchanged (the relay behaves as a plain router).
    fn relay_deliveries(&self, effects: Vec<Effect>) -> Vec<Effect> {
        let Some(client) = self.client else {
            return effects;
        };
        effects
            .into_iter()
            .map(|e| match e {
                Effect::Notify(Notification::Delivered { from, payload }) if from == ANONYMOUS => {
                    Effect::Send {
                        to: client,
                        frame: payload,
                    }
                }
                other => other,
            })
            .collect()
    }
}

impl<F: Field> Engine for RendezvousRelay<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        // A client registers its coordinate (the sender) to have its replies relayed here.
        if let Input::Message { from, frame } = &input
            && matches!(
                decode_frame(frame).ok().and_then(|(f, _)| f.frame_type()),
                Some(FrameType::RdvRegister)
            )
        {
            self.client = Some(*from);
            return Vec::new();
        }
        // Everything else is onion traffic: route it, then forward any peeled reply to the client.
        let effects = self.router.step(now, input);
        self.relay_deliveries(effects)
    }

    fn address(&self) -> Triple {
        self.router.address()
    }
}

/// The frame a client sends to register with a rendezvous relay. The frame carries no body — the relay
/// takes the sender's coordinate as the client to forward to.
#[must_use]
pub fn register_frame() -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(FrameType::RdvRegister.code(), &[], &mut out);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
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

        // A client at a non-combiner coordinate registers with the relay.
        let client: Triple = [0x0C, 0x0C, 0x0C];
        relay.step(
            Instant(0),
            Input::Message {
                from: client,
                frame: register_frame(),
            },
        );
        assert_eq!(relay.client(), Some(client), "the client is registered");

        // Seal a single-hop reply onion to the relay's line, sealed to the relay's forward-secure onion
        // public (the combiner is member 0; the other members never reply at t = 1).
        let relay_onion = OnionKeyRatchet::new(onion_seed, Epoch::ZERO);
        let (_d1, p1) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x3D, 1]));
        let (_d2, p2) = HybridKemSecret::generate(&mut SeedRng::from_seed(&[0x3D, 2]));
        let pubs = [relay_onion.public(), &p1, &p2];
        let payload = b"anonymous reply for the client";
        let onion = seal_onion(
            &[HopLine {
                line,
                members: &pubs,
            }],
            1,
            payload,
            b"relay-seed",
        )
        .unwrap();

        // The reply arrives: the relay peels it (t = 1) and forwards it to the registered client.
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
                Effect::Send { to, frame } if *to == client && frame.as_slice() == payload.as_slice()
            )),
            "the relay forwards the peeled reply to the registered client"
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
        assert_eq!(relay.client(), None);

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
