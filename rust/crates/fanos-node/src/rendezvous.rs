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
use fanos_field::Field;
use fanos_quic::Client;
use fanos_rendezvous::{ANONYMOUS, RendezvousClient};
use fanos_runtime::{Command, Notification};
use fanos_session::{ChannelTransport, stream_over_channels};
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
    loop {
        tokio::select! {
            outbound = app_out.recv() => match outbound {
                Some(payload) => {
                    if let Some(fwd) = rclient.seal_send(&payload) {
                        send_frame(fwd.combiner, fwd.frame);
                    }
                }
                None => break, // the stream driver is gone
            },
            event = deliveries.recv() => match event {
                Ok(Notification::Delivered { from, payload }) if from == ANONYMOUS => {
                    if app_in.send(payload).is_err() {
                        break; // the stream driver is gone
                    }
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            },
        }
    }
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
    stream_over_channels(
        session,
        ChannelTransport {
            outbound: out_tx,
            inbound: in_rx,
        },
    )
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
        let meeting = meeting_line::<F2>(b"anon-svc", 1).coords();
        let hop = (0..7)
            .map(|i| Line::<F2>::at(i).coords())
            .find(|&l| l != meeting)
            .unwrap();
        let rp = (0..7)
            .map(|i| Line::<F2>::at(i).coords())
            .find(|&l| l != hop)
            .unwrap();
        let rclient = RendezvousClient::<F2>::new(
            vec![hop, meeting],
            vec![rp],
            dir,
            2,
            b"bridge-secret",
        );
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
        assert_ne!(frame, b"diaulos-hello", "the payload was sealed, not forwarded verbatim");
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
