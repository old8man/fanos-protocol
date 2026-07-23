//! The **anonymous profile** — a DIAULOS session carried over threshold onions to a computed meeting
//! line, so neither party learns the other's location.
//!
//! It reuses the identical async stream machinery as the Direct profile ([`crate::diaulos`]): a
//! [`ClientSession`] driven as a byte stream over a [`ChannelTransport`]. The only difference is what
//! sits under those channels — here, the sans-I/O [`RendezvousClient`] seals each outbound DIAULOS
//! payload into a threshold onion ([`fanos_rendezvous`]) bound for the service's meeting line, and the
//! service's replies return as *anonymous* deliveries at the client's own reply rendezvous. The onion
//! hides *where*; DIAULOS still encrypts *what*.
//!
//! The overlay coupling is injected into [`rendezvous_bridge`] (a send closure + the node's delivery
//! stream), so the bridge's sealing/routing logic is unit-testable without a live node; [`dial_anonymous`]
//! wires it to a real [`Client`].

use fanos_aphantos::nostos::{ReplyKeys, select_drop_line};
use fanos_diaulos::{ClientSession, Coord};
use fanos_field::{F2, Field};
use fanos_geometry::{Line, Plane, Point};
use fanos_onoma::Epoch;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_quic::Client;
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, MixDirectory, RendezvousClient, combiner_for, meeting_line,
    session_reply_keypair,
};
use fanos_runtime::{Command, Notification};

use fanos_session::{ChannelTransport, stream_over_channels_paced};
use rand_core::{CryptoRng, Rng};
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// Bridge a DIAULOS session's datagram channels to the base overlay through a threshold-onion
/// rendezvous.
///
/// * outbound framed payloads (`app_out`) are sealed by `rclient` and launched at the first hop's
///   combiner via `send_frame`;
/// * anonymous deliveries from the overlay (`deliveries`) are surfaced verbatim to the session
///   (`app_in`); non-anonymous deliveries are ignored.
///
/// The overlay is injected (`send_frame` + `deliveries`) rather than referenced directly, so this core
/// carries no dependency on a live node and can be driven with in-memory doubles in tests. It runs
/// until the driver's channels or the delivery stream close.
async fn rendezvous_bridge<F, S>(
    mut rclient: RendezvousClient<F>,
    mut app_out: UnboundedReceiver<Vec<u8>>,
    app_in: UnboundedSender<Vec<u8>>,
    send_frame: S,
    mut deliveries: broadcast::Receiver<Notification>,
    reply_keys: ReplyKeys,
) where
    F: Field + Send + 'static,
    S: Fn(Coord, Vec<u8>) + Send + 'static,
{
    // The two directions are independent and each retransmits until the peer acks, so multiplexing
    // them in one `select!` lets whichever is busier starve the other (each side floods handshake
    // retransmits until the *other* direction completes them — a mutual starvation). Run them as two
    // concurrent halves on the one task instead: each progresses whenever its own input is ready.
    let inbound = async {
        loop {
            match deliveries.recv().await {
                Ok(Notification::Delivered { from, payload }) if from == ANONYMOUS => {
                    // NOSTOS: an anonymous delivery is a dead-drop landing on this session's own reply
                    // line — its body is end-to-end-sealed to our reply key. Open it; a body not for us
                    // (a co-member's dead-drop on the shared line, or cover traffic) does not open, so we
                    // skip it. The reply key is itself the demultiplexer, so there is no cookie to strip.
                    let Some(cell) = reply_keys.open(&payload) else {
                        continue;
                    };
                    if app_in.send(cell).is_err() {
                        break; // the stream driver is gone
                    }
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    let outbound = async {
        while let Some(payload) = app_out.recv().await {
            if let Some(fwd) = rclient.seal_send(&payload) {
                send_frame(fwd.combiner, fwd.frame);
            }
        }
    };
    tokio::join!(inbound, outbound);
}

/// Dial a service **anonymously**: drive `session` (a DIAULOS [`ClientSession`] whose peer is the
/// service's meeting-line coordinate) as an async byte stream whose cells ride threshold onions sealed
/// by `rclient`. Returns the application side of the stream; a spawned task owns the session and the
/// rendezvous bridge.
///
/// The reply comes home via NOSTOS: `rclient`'s reply circuit must terminate at one of this node's own
/// lines (a line through its coordinate), and `reply_keys` must be the matching
/// [`session_reply_keypair`](fanos_rendezvous::session_reply_keypair) half, so the service's dead-drop
/// replies — anonymous deliveries this node receives as a line member — open here. [`anonymous_dial`]
/// wires both. Must run inside a tokio runtime.
#[must_use]
pub fn dial_anonymous<F: Field + Send + 'static>(
    client: Client,
    session: ClientSession,
    rclient: RendezvousClient<F>,
    reply_keys: ReplyKeys,
) -> DuplexStream {
    let (out_tx, out_rx) = unbounded_channel();
    let (in_tx, in_rx) = unbounded_channel();
    let deliveries = client.subscribe();
    // NOSTOS: the client receives replies as a **member of its own reply line** — the dead-drop's
    // combiner multicasts each reply to that line's `q+1` members, and this node (a member, since the
    // line passes through its coordinate) surfaces it as an anonymous delivery. The bridge opens it with
    // `reply_keys`. There is no rendezvous-relay registration and no SURB: the client's coordinate never
    // leaves the node, and no relay ever learns which member of the line is the receiver.
    tokio::spawn(rendezvous_bridge(
        rclient,
        out_rx,
        in_tx,
        // Onion launches go out **raw** (`Emit`), not `Send` — the overlay would otherwise wrap them in a
        // routed `Route` frame the mixnet combiner cannot peel.
        move |to, frame| {
            client.command(Command::Emit { to, frame });
        },
        deliveries,
        reply_keys,
    ));
    stream_over_channels_paced(
        session,
        ChannelTransport {
            outbound: out_tx,
            inbound: in_rx,
        },
        RENDEZVOUS_TICK,
    )
}

/// Retransmit cadence for an anonymous session. A hop is a multi-round threshold gather over the
/// overlay, so the effective round trip is far larger than the Direct profile's base tick; pace
/// retransmits to it so the client does not flood onions faster than the mixnet can peel them.
const RENDEZVOUS_TICK: Duration = Duration::from_millis(250);

/// The circuit + mixnet parameters a client uses to reach a service anonymously. `forward_hops` and
/// `reply_circuit` are hop *lines* (a hop is a line); the meeting line is appended to the forward hops
/// by [`anonymous_dial`], and the reply circuit ends at the client's own rendezvous (see the
/// combiner-reachability note there).
pub struct RendezvousRoute {
    /// Intermediate hop lines before the service's meeting line.
    pub forward_hops: Vec<Coord>,
    /// Hop lines ending at the client's reply rendezvous, where the service's replies are delivered.
    pub reply_circuit: Vec<Coord>,
    /// The mixnet members' KEM keys the onions seal to.
    pub directory: MixDirectory,
    /// How many of each hop line's `q + 1` members must cooperate to peel it.
    pub threshold: u8,
    /// The rendezvous epoch — the meeting line rotates each epoch, so there is no fixed target.
    pub epoch: Epoch,
    /// The epoch's randomness-beacon seed, folded into the meeting-line derivation so a future epoch's
    /// line is unpredictable in advance (audit E5). The client obtains it via a `BEACON` sync; both
    /// parties must use the same epoch's seed to meet. [`BeaconSeed::GENESIS`] before the first round.
    pub beacon: BeaconSeed,
}

impl RendezvousRoute {
    /// Draw a **fresh** route for one anonymous dial (#54): random, distinct forward and reply hop lines —
    /// a new, unlinkable path each dial rather than a fixed route — with the client's reply rendezvous
    /// chosen to have a combiner distinct from the service's meeting line, so the service (listening at its
    /// own combiner) never also receives the client's reply traffic. `forward_depth`/`reply_depth` are the
    /// `depths` is `(forward, reply)` — the number of intermediate hops before the meeting line / before
    /// the reply rendezvous. `rng` MUST be a CSPRNG in production — the path's unpredictability is what
    /// unlinks successive dials.
    #[must_use]
    pub fn draw<F: Field, R: CryptoRng>(
        directory: MixDirectory,
        threshold: u8,
        epoch: Epoch,
        beacon: BeaconSeed,
        service_meeting: Coord,
        depths: (usize, usize),
        rng: &mut R,
    ) -> Self {
        let meeting_combiner = combiner_for::<F>(service_meeting);
        // The client's reply rendezvous: a random line distinct from the meeting line AND whose combiner is
        // a distinct, *live* relay present in the directory — that relay peels the reply and forwards it to
        // this client (audit #54, item 3), so it must be reachable to serve as the rendezvous point. Falls
        // back to the meeting line only on a degenerate plane that offers no such line.
        let reply_rendezvous = draw_line::<F, R>(rng, |l| {
            l != service_meeting
                && combiner_for::<F>(l)
                    .is_some_and(|c| Some(c) != meeting_combiner && directory.get(&c).is_some())
        })
        .unwrap_or(service_meeting);
        let forward_hops = random_hops::<F, R>(depths.0, &[service_meeting], rng);
        let mut reply_circuit =
            random_hops::<F, R>(depths.1, &[service_meeting, reply_rendezvous], rng);
        reply_circuit.push(reply_rendezvous);
        Self {
            forward_hops,
            reply_circuit,
            directory,
            threshold,
            epoch,
            beacon,
        }
    }
}

/// The bound on random-draw retries relative to the plane size — generous, so a valid draw is found with
/// overwhelming probability while the search can never run unbounded.
fn draw_budget<F: Field>() -> usize {
    (Plane::<F>::N as usize).saturating_mul(16).max(1)
}

/// Draw `count` distinct random hop lines, none in `avoid` and none repeated — a fresh set of hop lines
/// for one circuit. Bounded retries, so it always terminates (returning fewer than `count` only if the
/// plane cannot supply that many distinct non-avoided lines).
#[must_use]
pub fn random_hops<F: Field, R: Rng>(count: usize, avoid: &[Coord], rng: &mut R) -> Vec<Coord> {
    let n = Plane::<F>::N as usize;
    let mut chosen: Vec<Coord> = Vec::with_capacity(count);
    let mut attempts = 0usize;
    let budget = draw_budget::<F>().saturating_add(count.saturating_mul(n));
    while chosen.len() < count && attempts < budget {
        attempts += 1;
        let line = Line::<F>::at((rng.next_u32() as usize) % n.max(1)).coords();
        if !avoid.contains(&line) && !chosen.contains(&line) {
            chosen.push(line);
        }
    }
    chosen
}

/// Draw a single random line satisfying `ok`, or `None` after bounded retries.
fn draw_line<F: Field, R: Rng>(rng: &mut R, ok: impl Fn(Coord) -> bool) -> Option<Coord> {
    let n = Plane::<F>::N as usize;
    (0..draw_budget::<F>()).find_map(|_| {
        let line = Line::<F>::at((rng.next_u32() as usize) % n.max(1)).coords();
        ok(line).then_some(line)
    })
}

/// Dial a service **anonymously** by its static KEM public key — the anonymous analogue of
/// [`dial_service`](crate::diaulos::dial_service).
///
/// The client derives the service's meeting line for `route.epoch` from `service_public` (the very
/// line the service listens on, with no lookup), opens a DIAULOS session to it, and rides that session
/// over threshold onions through `route`'s circuit. `secret` seeds this session's cookie and its
/// per-onion key material — pass OS entropy in production. Returns the async byte stream; a background
/// task owns the session and the rendezvous bridge. Must run inside a tokio runtime.
///
/// As with [`dial_anonymous`], the node must be reachable at its reply rendezvous: `route.reply_circuit`
/// must end at a line whose combiner relays deliveries to this node.
#[must_use]
pub fn anonymous_dial<R: CryptoRng>(
    client: Client,
    service_public: &HybridKemPublic,
    route: &RendezvousRoute,
    secret: &[u8],
    rng: &mut R,
) -> DuplexStream {
    let meeting = meeting_line::<F2>(&service_public.encode(), route.epoch, &route.beacon).coords();
    let mut forward_circuit = route.forward_hops.clone();
    forward_circuit.push(meeting);
    // NOSTOS reply home: the terminus of the reply circuit is one of the client's OWN lines — a line
    // through its coordinate, beacon-blinded by the session secret so it is unpredictable and rotates
    // each epoch. The client receives the dead-drop there as a line member and no relay learns it. The
    // drawn intermediate reply hops are kept; only the terminus becomes the own line.
    let mut reply_circuit = route.reply_circuit.clone();
    if let Some(point) = Point::<F2>::new(client.address()) {
        let drop_line =
            select_drop_line(point, secret, route.epoch.get(), route.beacon.as_bytes()).coords();
        match reply_circuit.last_mut() {
            Some(last) => *last = drop_line,
            None => reply_circuit.push(drop_line),
        }
    }
    // The matching reply keypair — the client advertises the public half in every Request; this driver
    // keeps the secret half to open the dead-drop.
    let (reply_keys, reply_pub) = session_reply_keypair(secret);
    let rclient = RendezvousClient::<F2>::new(
        forward_circuit,
        reply_circuit,
        route.directory.clone(),
        route.threshold,
        secret,
        reply_pub,
    );
    let session = ClientSession::dial(meeting, service_public, rng);
    dial_anonymous(client, session, rclient, reply_keys)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use fanos_field::F2;
    use fanos_geometry::{Line, Point};
    use fanos_pqcrypto::{HybridKemSecret, SeedRng};
    use fanos_rendezvous::{MixDirectory, combiner_for, meeting_line};

    fn fano_directory() -> MixDirectory {
        let mut dir = MixDirectory::new();
        for i in 0..7u8 {
            let mut rng = SeedRng::from_seed(&[0x0E, i]);
            let (_secret, public) = HybridKemSecret::generate(&mut rng);
            dir.insert(Point::<F2>::at(usize::from(i)).coords(), public);
        }
        dir
    }

    /// A tiny deterministic SplitMix64 standing in for a CSPRNG in the route-draw test. rand_core 0.10 is
    /// fallible-first: implementing `TryRng` (with `Error = Infallible`) + the `TryCryptoRng` marker yields
    /// `Rng`/`RngCore`/`CryptoRng` by that crate's blanket impls.
    struct TestRng(u64);
    impl TestRng {
        fn step(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }
    impl rand_core::TryRng for TestRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.step() as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.step())
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                let bytes = self.step().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for TestRng {}

    #[test]
    fn drawn_routes_are_fresh_and_avoid_the_meeting_line() {
        let dir = fano_directory();
        let epoch = Epoch::new(1);
        let meeting = meeting_line::<F2>(b"draw-svc", epoch, &BeaconSeed::GENESIS).coords();
        let draw = |seed: u64| {
            RendezvousRoute::draw::<F2, _>(
                dir.clone(),
                2,
                epoch,
                BeaconSeed::GENESIS,
                meeting,
                (2, 2),
                &mut TestRng(seed),
            )
        };

        let r = draw(1);
        assert!(
            r.forward_hops.iter().all(|&h| h != meeting),
            "no forward hop is the meeting line"
        );
        assert!(
            r.forward_hops
                .iter()
                .enumerate()
                .all(|(i, &h)| !r.forward_hops[..i].contains(&h)),
            "forward hops are distinct"
        );
        let reply_rdv = *r.reply_circuit.last().unwrap();
        assert_ne!(
            combiner_for::<F2>(reply_rdv),
            combiner_for::<F2>(meeting),
            "the reply rendezvous does not collide with the meeting combiner"
        );

        // Fresh per dial: a different RNG state yields a different path (overwhelmingly likely).
        let r2 = draw(0x9999);
        assert!(
            r.forward_hops != r2.forward_hops || r.reply_circuit != r2.reply_circuit,
            "two draws produce different circuits"
        );
    }

    #[tokio::test]
    async fn the_bridge_seals_outbound_and_surfaces_only_anonymous_replies() {
        use fanos_aphantos::nostos::seal_to_receiver;
        let dir = fano_directory();
        let meeting =
            meeting_line::<F2>(b"anon-svc", Epoch::new(1), &BeaconSeed::new([0x0E; 32])).coords();
        let hop = (0..7)
            .map(|i| Line::<F2>::at(i).coords())
            .find(|&l| l != meeting)
            .unwrap();
        let rp = (0..7)
            .map(|i| Line::<F2>::at(i).coords())
            .find(|&l| l != hop)
            .unwrap();
        let secret = b"bridge-secret";
        let (reply_keys, reply_pub) = session_reply_keypair(secret);
        let rclient =
            RendezvousClient::<F2>::new(vec![hop, meeting], vec![rp], dir, 2, secret, reply_pub.clone());
        let expected_first_combiner = combiner_for::<F2>(hop).unwrap();

        let (out_tx, out_rx) = unbounded_channel();
        let (in_tx, mut in_rx) = unbounded_channel();
        let (sent_tx, mut sent_rx) = unbounded_channel::<(Coord, Vec<u8>)>();
        let (deliv_tx, deliv_rx) = broadcast::channel(16);

        tokio::spawn(rendezvous_bridge(
            rclient,
            out_rx,
            in_tx,
            move |to, frame| {
                let _ = sent_tx.send((to, frame));
            },
            deliv_rx,
            reply_keys,
        ));

        // Outbound: a framed DIAULOS payload is wrapped + sealed and launched at the first hop's
        // combiner — never forwarded in the clear.
        out_tx.send(b"diaulos-hello".to_vec()).unwrap();
        let (to, frame) = sent_rx.recv().await.unwrap();
        assert_eq!(
            to, expected_first_combiner,
            "the onion launches at the first hop's combiner"
        );
        assert_ne!(
            frame, b"diaulos-hello",
            "the payload was sealed, not forwarded verbatim"
        );
        assert!(!frame.is_empty());

        // A non-anonymous delivery is filtered; a dead-drop body sealed to a DIFFERENT session's reply
        // key does not open (the bridge skips it); only the body sealed to THIS session's reply key
        // surfaces its cell — so the non-anonymous and foreign deliveries were both dropped.
        deliv_tx
            .send(Notification::Delivered {
                from: [9, 9, 9],
                payload: b"noise".to_vec(),
            })
            .unwrap();
        let (_other, other_pub) = session_reply_keypair(b"a-different-session");
        let foreign = seal_to_receiver(
            &HybridKemPublic::decode(&other_pub).unwrap(),
            b"not for this session",
            b"foreign-seed",
        )
        .unwrap();
        deliv_tx
            .send(Notification::Delivered {
                from: ANONYMOUS,
                payload: foreign,
            })
            .unwrap();
        // The real reply: a dead-drop body end-to-end-sealed to this session's advertised reply key.
        let body = seal_to_receiver(
            &HybridKemPublic::decode(&reply_pub).unwrap(),
            b"reply",
            b"reply-seed",
        )
        .unwrap();
        deliv_tx
            .send(Notification::Delivered {
                from: ANONYMOUS,
                payload: body,
            })
            .unwrap();
        assert_eq!(
            in_rx.recv().await.unwrap(),
            b"reply",
            "only the reply sealed to this session's key opens and reaches the DIAULOS session"
        );
    }
}
