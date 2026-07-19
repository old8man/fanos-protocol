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

use fanos_diaulos::{ClientSession, Coord};
use fanos_field::{F2, Field};
use fanos_onoma::Epoch;
use fanos_pqcrypto::kem::HybridKemPublic;
use fanos_quic::Client;
use fanos_rendezvous::{ANONYMOUS, BeaconSeed, MixDirectory, RendezvousClient, meeting_line};
use fanos_runtime::{Command, Notification};
use fanos_session::{ChannelTransport, stream_over_channels_paced};
use rand_core::CryptoRng;
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
                    if app_in.send(payload).is_err() {
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
/// The node must be reachable at its reply rendezvous — `rclient`'s reply circuit must terminate at
/// this node's own coordinate, so the service's replies (anonymous deliveries to this node) arrive
/// here. Must run inside a tokio runtime.
#[must_use]
pub fn dial_anonymous<F: Field + Send + 'static>(
    client: Client,
    session: ClientSession,
    rclient: RendezvousClient<F>,
) -> DuplexStream {
    let (out_tx, out_rx) = unbounded_channel();
    let (in_tx, in_rx) = unbounded_channel();
    let deliveries = client.subscribe();
    tokio::spawn(rendezvous_bridge(
        rclient,
        out_rx,
        in_tx,
        move |to, payload| {
            client.command(Command::Send { to, payload });
        },
        deliveries,
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
    let rclient = RendezvousClient::<F2>::new(
        forward_circuit,
        route.reply_circuit.clone(),
        route.directory.clone(),
        route.threshold,
        secret,
    );
    let session = ClientSession::dial(meeting, service_public, rng);
    dial_anonymous(client, session, rclient)
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

    #[tokio::test]
    async fn the_bridge_seals_outbound_and_surfaces_only_anonymous_replies() {
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
        let rclient =
            RendezvousClient::<F2>::new(vec![hop, meeting], vec![rp], dir, 2, b"bridge-secret");
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

        // A non-anonymous delivery is filtered; the following anonymous one is surfaced verbatim. Since
        // the driver's next read is the anonymous reply, the non-anonymous delivery was indeed dropped.
        deliv_tx
            .send(Notification::Delivered {
                from: [9, 9, 9],
                payload: b"noise".to_vec(),
            })
            .unwrap();
        deliv_tx
            .send(Notification::Delivered {
                from: ANONYMOUS,
                payload: b"reply".to_vec(),
            })
            .unwrap();
        assert_eq!(
            in_rx.recv().await.unwrap(),
            b"reply",
            "only the anonymous reply reaches the session"
        );
    }
}
