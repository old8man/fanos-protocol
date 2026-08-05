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
//! The overlay coupling is injected into `rendezvous_bridge` (a send closure + the node's delivery
//! stream), so the bridge's sealing/routing logic is unit-testable without a live node; [`dial_anonymous`]
//! wires it to a real [`Client`].

use fanos_aphantos::nostos::{ReplyKeys, select_drop_line};
use fanos_aphantos::slots;
use fanos_diaulos::service_public_from_bundle;
use fanos_diaulos::{ClientSession, Coord};
use fanos_field::{F2, Field};
use fanos_geometry::{Line, Plane, Point, Triple};
use fanos_onoma::Epoch;
use fanos_quic::Client;
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, MixDirectory, RendezvousClient, service_tag, session_reply_keypair,
};
use fanos_runtime::{Command, Notification};

use fanos_session::{ChannelTransport, stream_over_channels_confirmed};
use rand_core::{CryptoRng, Rng};
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::sync::broadcast;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::sync::oneshot;

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
    mut app_out: Receiver<Vec<u8>>,
    app_in: Sender<Vec<u8>>,
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
            // The session driver going away must end this half **without waiting for a delivery**. Its only
            // other exit is `try_send` reporting `Closed`, which needs a reply to arrive and open — and an
            // abandoned attempt is precisely one that gets no reply, so it would spin on the node's broadcast
            // forever. That leaks a task per abandoned attempt, and the meeting-point walk creates one on
            // every dial that skips a censored point.
            let delivery = tokio::select! {
                () = app_in.closed() => break,
                d = deliveries.recv() => d,
            };
            match delivery {
                Ok(Notification::Delivered { from, payload }) if from == ANONYMOUS => {
                    // NOSTOS: an anonymous delivery is a dead-drop landing on this session's own reply
                    // line — its body is end-to-end-sealed to our reply key. Open it; a body not for us
                    // (a co-member's dead-drop on the shared line, or cover traffic) does not open, so we
                    // skip it. The reply key is itself the demultiplexer, so there is no cookie to strip.
                    let Some(cell) = reply_keys.open(&payload) else {
                        continue;
                    };
                    // A full inbound queue drops the reply (audit A4b) — DIAULOS retransmits it;
                    // a closed one means the stream driver is gone, so end the bridge.
                    if let Err(TrySendError::Closed(_)) = app_in.try_send(cell) {
                        break;
                    }
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    let outbound = async {
        while let Some(payload) = app_out.recv().await {
            match rclient.seal_send(&payload) {
                Some(fwd) => send_frame(fwd.combiner, fwd.frame),
                // **A seal failure is fatal to this session, not a dropped packet.** `seal_forward` fails
                // only for reasons fixed for the whole circuit — a hop line with a member absent from the
                // directory — so the next payload will fail identically and so will every one after it.
                // Dropping them silently is a session that moves zero bytes forever while looking healthy,
                // which is precisely the wedge the harness reports as REFUTED.
                //
                // Ending the bridge closes the transport, the driver gives up, and the dial's confirmation
                // signal resolves `Err` — so the hedged walk moves to another meeting point instead of
                // riding a circuit that can never carry anything.
                None => break,
            }
        }
    };
    tokio::join!(inbound, outbound);
}

/// Dial a service **anonymously**: drive `session` (a DIAULOS [`ClientSession`] whose peer is the
/// service's meeting-line coordinate) as an async byte stream whose cells ride threshold onions sealed
/// by `rclient`. Returns the application side of the stream **and a liveness signal**; a spawned task owns
/// the session and the rendezvous bridge.
///
/// The signal resolves `Ok(())` when the DIAULOS handshake completes through this meeting point and `Err(_)`
/// when the driver gives up on it. A caller choosing among a service's several meeting points has no other
/// way to tell a *censored* one from a merely *quiet* one — the stream itself stays open and silent either
/// way until the give-up rule fires minutes later — and without that distinction the meeting points past the
/// first are decorative (`docs/design-rendezvous.md §5`). A caller that will not walk may drop it.
///
/// The reply comes home via NOSTOS: `rclient`'s reply circuit must terminate at one of this node's own
/// lines (a line through its coordinate), and `reply_keys` must be the matching
/// [`session_reply_keypair`] half, so the service's dead-drop
/// replies — anonymous deliveries this node receives as a line member — open here. [`anonymous_dial`]
/// wires both. Must run inside a tokio runtime.
#[must_use]
pub fn dial_anonymous<F: Field + Send + 'static>(
    client: Client,
    session: ClientSession,
    rclient: RendezvousClient<F>,
    reply_keys: ReplyKeys,
) -> (DuplexStream, oneshot::Receiver<()>) {
    let (out_tx, out_rx) = channel(ChannelTransport::CAP);
    let (in_tx, in_rx) = channel(ChannelTransport::CAP);
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
    stream_over_channels_confirmed(
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
/// retransmits to it so the client does not flood onions faster than the mixnet can peel them. The
/// **service** side ([`crate::rendezvous_host::serve_anonymous`]) MUST pace to the same value, or its
/// replies flood the return path — the two halves share this one constant.
pub(crate) const RENDEZVOUS_TICK: Duration = Duration::from_millis(250);

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

#[derive(Clone)]
/// Parameters to draw a **fresh unlinkable** rendezvous route *per dial* — the general anonymous proxy
/// profile (spec §L5, #54). Each connection gets new random forward/reply hops drawn from the live mix
/// `directory`, so an observer cannot link successive dials by their shared path (the fixed-route
/// [`FanosDialer::anonymous`] reuses one path across dials and is linkable — a real proxy must use this).
pub struct AnonRouteParams {
    /// The live mixnet key directory (e.g. from [`build_cell_mix_directory`](crate::build_cell_mix_directory)).
    pub directory: MixDirectory,
    /// How many of each hop line's members must cooperate to peel an onion.
    pub threshold: u8,
    /// The rendezvous epoch (the meeting line and placement rotate with it).
    pub epoch: Epoch,
    /// The epoch's beacon seed (folds into the meeting-line derivation).
    pub beacon: BeaconSeed,
    /// `(forward, reply)` intermediate-hop depths for each freshly-drawn circuit.
    pub depths: (usize, usize),
}

impl RendezvousRoute {
    /// Draw a **fresh** route for one anonymous dial (#54): random, distinct forward and reply hop lines —
    /// a new, unlinkable path each dial rather than a fixed route — with the client's reply rendezvous
    /// chosen to have a combiner distinct from the service's meeting line, so the service (listening at its
    /// own combiner) never also receives the client's reply traffic. `forward_depth`/`reply_depth` are the
    /// `depths` is `(forward, reply)` — the number of intermediate hops before the meeting line / before
    /// the reply rendezvous. `rng` MUST be a CSPRNG in production — the path's unpredictability is what
    /// unlinks successive dials.
    ///
    /// `client_drop` is the session's NOSTOS drop line, and passing it is what makes the route **sound** rather
    /// than merely fresh: every hop is then laid around it, so no line can hold both a client-name and a
    /// service-name ([`route_leaks`]). Passing `None` draws an arbitrary reply rendezvous instead, which
    /// [`anonymous_dial`] will replace — and then that dial has to check, and refuse, what this could have
    /// avoided.
    #[must_use]
    pub fn draw<F: Field, R: CryptoRng>(
        params: &AnonRouteParams,
        service_meeting: Coord,
        client_drop: Option<Coord>,
        rng: &mut R,
    ) -> Self {
        let AnonRouteParams { directory, threshold, epoch, beacon, depths } = params.clone();
        // The client's reply rendezvous: a random line distinct from the meeting line — the service must not
        // receive the client's reply traffic as a delivery on its own line — and **sealable**: every member's
        // key present in the directory, because a reply onion seals to the whole line and its launch draws a
        // per-onion member (#55, `combiner_for_salted`), so no single member's liveness is the gate any more.
        // Falls back to the meeting line only on a degenerate plane that offers no such line.
        // The terminus is settled FIRST, and the order is the fix rather than a detail. The client's drop line
        // is *derived* from its own coordinate, so it has only `q + 1` candidates; the hops are *drawn*, from
        // `n`. Constrain the flexible side. Laying the hops first and patching the terminus afterwards — which
        // is what `anonymous_dial` used to do — put the drop line somewhere on the client's own forward circuit
        // on 43% of dials at `q = 2`, and on the hop that learns the meeting line on 15% of them.
        let terminus = client_drop.unwrap_or_else(|| {
            draw_line::<F, R>(rng, |l| l != service_meeting && line_is_sealable::<F>(l, &directory))
                .unwrap_or(service_meeting)
        });
        let forward_hops = random_hops::<F, R>(depths.0, &[service_meeting, terminus], &directory, rng);
        // `R_1` must differ from `H_1`: one is dialled by the client and the other from the service side, so a
        // single line holding both names the pair. Only the first forward hop is excluded — the middles name
        // nobody, and excluding them too would use six of Fano's seven lines and make the draw predictable.
        let mut reply_avoid = vec![service_meeting, terminus];
        reply_avoid.extend(forward_hops.first().copied());
        let mut reply_circuit = random_hops::<F, R>(depths.1, &reply_avoid, &directory, rng);
        reply_circuit.push(terminus);
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

/// Whether a line can carry a hop: **every** member's key is in `directory`, so an onion layer can be sealed
/// to the whole line.
///
/// One predicate, because there were two. The reply-rendezvous draw has always required this and
/// [`random_hops`], ten lines away, required nothing — the same decision under two rules. That is not a
/// tidiness point: [`fanos_rendezvous::seal_forward`] returns `None` if *any* member of *any* hop line is
/// missing, so a circuit laid through one unsealable line seals **nothing**, for the whole life of the
/// session, and the bridge used to drop each payload silently. Zero bytes moving forever is exactly the
/// wedge signature, and an unlucky draw was all it took.
#[must_use]
pub fn line_is_sealable<F: Field>(line: Coord, directory: &MixDirectory) -> bool {
    fanos_rendezvous::line_member_coords::<F>(line)
        .iter()
        .all(|m| directory.get(m).is_some())
}

/// The client's NOSTOS drop line for this session: the reply circuit's terminus, **derived** from the client's
/// own coordinate rather than drawn, so it has only `q + 1` candidates.
///
/// `forbidden` are lines it must not land on. `None` when every candidate is forbidden or unsealable — which is
/// a real outcome on a narrow plane and must be treated as one: [`fanos_aphantos::nostos::select_drop_line`]
/// falls back to an unusable line rather than failing, so the result is re-checked here and the fallback is
/// converted into the `None` it means.
#[must_use]
pub fn client_drop_line<F: Field>(
    client_address: Coord,
    secret: &[u8],
    epoch: Epoch,
    beacon: &BeaconSeed,
    directory: &MixDirectory,
    forbidden: &[Coord],
) -> Option<Coord> {
    let point = Point::<F>::new(client_address)?;
    let usable =
        |l: Line<F>| !forbidden.contains(&l.coords()) && line_is_sealable::<F>(l.coords(), directory);
    let line = select_drop_line::<F>(point, secret, epoch.get(), beacon.as_bytes(), &usable);
    usable(line).then(|| line.coords())
}

/// The line that would let one captured coalition name **both** endpoints of `forward_circuit` /
/// `reply_circuit`, or `None` if the route is sound.
///
/// The anonymity claim is arithmetic, and it is worth stating before the rule that follows from it: naming an
/// endpoint costs capturing a line — `t = ⌈2(q+1)/3⌉` of its `q + 1` members — and two **distinct** lines meet
/// in exactly one point, so naming both costs `2t − 1`. At Fano that is `3`, against a tolerated budget of
/// `f = 2`. The margin is one node, and it exists *only* while the two lines are two.
///
/// Which lines carry a name is not a matter of degree — it follows from who dials whom:
///
/// | line | names | how |
/// |---|---|---|
/// | `H_1` | the client | the client transmits to it, so it sees the address |
/// | `D` (reply terminus) | the client | its `q + 1` members include the client, which reads the dead drop there |
/// | `H_d` | the service | peeling its slot reveals the next hop, `M` |
/// | `M` | the service | it *is* the service's meeting line |
/// | `R_1` | the service | the reply is launched to it from the service side |
///
/// So the rule is one line: **no line may appear on both sides.** Everything between those positions is a
/// middle — it learns only the next hop, names nobody, and a middle-to-middle coincidence is harmless. Stating
/// the rule as "the circuits must be disjoint" would be wrong in the expensive direction: at `q = 2` there are
/// seven lines and a disjoint pair of depth-2 circuits plus a meeting line uses six of them, which makes the
/// draw nearly deterministic — and *a predictable circuit is a targetable one*.
///
/// Returns the offending line so the caller can say which, rather than that something was wrong.
#[must_use]
pub fn route_leaks(forward_circuit: &[Coord], reply_circuit: &[Coord], meeting: Coord) -> Option<Coord> {
    // A leg with no neutral middle leaks whatever its two ends name, because **a hop learns both of its
    // neighbours** — who sent to it (the transport authenticates the source) and where it forwards (peeling
    // reveals the next hop). One intermediate is therefore not "shallower", it is the *same* hop holding both
    // names with a hop's worth of ceremony around it. The table below cannot see this, because both names are
    // then carried by one line rather than by two that happen to coincide.
    if forward_circuit.len() < slots::MIN_FORWARD_DEPTH + 1 {
        return forward_circuit.first().copied().or(Some(meeting));
    }
    if reply_circuit.len() < slots::MIN_REPLY_DEPTH + 1 {
        return reply_circuit.first().copied().or(Some(meeting));
    }
    let names_client = [forward_circuit.first(), reply_circuit.last()];
    // `H_d` is the last INTERMEDIATE hop, i.e. the one before the meeting line the circuit ends at.
    let h_d = forward_circuit.len().checked_sub(2).and_then(|i| forward_circuit.get(i));
    let names_service = [h_d, Some(&meeting), reply_circuit.first()];
    names_client
        .into_iter()
        .flatten()
        .find(|c| names_service.iter().flatten().any(|s| s == c))
        .copied()
}

/// Draw `count` distinct random hop lines — none in `avoid`, none repeated, and every one **sealable**
/// against `directory` ([`line_is_sealable`]). Bounded retries, so it always terminates, returning fewer
/// than `count` only if the plane cannot supply that many.
///
/// Returning short is the honest outcome and the caller must treat it as one: a circuit with fewer hops than
/// asked for is shallower than the profile requested, which is a weaker anonymity set, not a failure to
/// route. It is still strictly better than the previous behaviour, which returned the full count including
/// lines nothing could be sealed to.
#[must_use]
pub fn random_hops<F: Field, R: Rng>(
    count: usize,
    avoid: &[Coord],
    directory: &MixDirectory,
    rng: &mut R,
) -> Vec<Coord> {
    let n = Plane::<F>::N as usize;
    let mut chosen: Vec<Coord> = Vec::with_capacity(count);
    let mut attempts = 0usize;
    let budget = draw_budget::<F>().saturating_add(count.saturating_mul(n));
    while chosen.len() < count && attempts < budget {
        attempts += 1;
        let line = Line::<F>::at((rng.next_u32() as usize) % n.max(1)).coords();
        if !avoid.contains(&line) && !chosen.contains(&line) && line_is_sealable::<F>(line, directory) {
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
    identity: &[u8],
    route: &RendezvousRoute,
    meeting: Triple,
    secret: &[u8],
    rng: &mut R,
) -> Option<(DuplexStream, oneshot::Receiver<()>)> {
    // Both derivations come from the one identity, so they cannot disagree: the KEM half LOCATES the service
    // (the meeting line, and the handshake encapsulates to it) while the whole bundle AUTHORISES its route
    // binding (`service_tag`, which the combiner recomputes from the registration's carried identity).
    // `None` is the single place a malformed bundle is rejected, so no caller re-derives and none can disagree.
    let service_public = &service_public_from_bundle(identity)?;
    // The meeting point is CHOSEN BY THE CALLER, not here, and that is a correctness constraint rather than
    // style: a route is drawn to avoid its own destination, so whoever draws the route must be the one who knows
    // which of the service's `f + 1` points it ends at. Picking here instead left the Fresh profile drawing
    // toward point 0 while this appended a different point — measured as 0 of 8 dials arriving once point 0's
    // combiner was silenced, i.e. the censorship spread not working at all.
    let mut forward_circuit = route.forward_hops.clone();
    forward_circuit.push(meeting);
    // NOSTOS reply home: the terminus of the reply circuit is one of the client's OWN lines — a line
    // through its coordinate, beacon-blinded by the session secret so it is unpredictable and rotates
    // each epoch. The client receives the dead-drop there as a line member and no relay learns it. The
    // drawn intermediate reply hops are kept; only the terminus becomes the own line.
    let mut reply_circuit = route.reply_circuit.clone();
    // The terminus must be one of the client's OWN lines — that is what lets it read the dead drop as a member,
    // and it is checkable here without re-deriving anything. When `draw` was given the drop line the circuit
    // already ends there and every hop was laid around it; when it was not (a FIXED route, drawn once and
    // reused across sessions) the terminus is still an arbitrary rendezvous and must be replaced now.
    //
    // Replacing it late is the weaker order and is only the fallback: by then the hops cannot move, so the drop
    // line has to dodge them out of its `q + 1` candidates and can fail. It used to be the ONLY order, and it
    // did not dodge at all — it overwrote a checked choice with an unchecked one, which the comment here
    // called "the sharpest form of the same defect `random_hops` had" while checking only sealability.
    let own_line = |l: &Coord| fanos_rendezvous::line_member_coords::<F2>(*l).contains(&client.address());
    if !reply_circuit.last().is_some_and(own_line) {
        let mut forbidden = vec![meeting];
        forbidden.extend(forward_circuit.iter().copied());
        forbidden.extend(reply_circuit.iter().rev().skip(1).copied());
        let drop_line = client_drop_line::<F2>(
            client.address(),
            secret,
            route.epoch,
            &route.beacon,
            &route.directory,
            &forbidden,
        )?;
        match reply_circuit.last_mut() {
            Some(last) => *last = drop_line,
            None => reply_circuit.push(drop_line),
        }
    }
    // The gate, and it is unconditional. Everything above is an attempt to make the sound route the one that
    // gets built; this is the refusal to dial when it is not. Both halves are needed — a check with no
    // construction behind it would fail 43% of dials, and a construction with no check would trust a caller.
    if let Some(line) = route_leaks(&forward_circuit, &reply_circuit, meeting) {
        tracing::warn!(
            ?line,
            forward = forward_circuit.len(),
            reply = reply_circuit.len(),
            "refusing an anonymous dial: one line of this route names both this node and the service — either \
             because two positions coincide, or because a leg is too short to have a middle and its single \
             hop holds both neighbours. Capturing that line alone costs `t` members, the tolerated budget at \
             Fano, where two distinct lines would cost `2t - 1` and exceed it."
        );
        return None;
    }
    // The matching reply keypair — the client advertises the public half in every Request; this driver
    // keeps the secret half to open the dead-drop.
    let (reply_keys, reply_pub) = session_reply_keypair(secret);
    // The service host-registration tag: if the service is hosted off its meeting combiner (the general
    // case), the node at the combiner routes this request to the host registered under this tag
    // (§3b). A service that is its own combiner ignores it (the delivery surfaces locally there).
    let tag = service_tag(identity, route.epoch);
    let rclient = RendezvousClient::<F2>::new(
        forward_circuit,
        reply_circuit,
        route.directory.clone(),
        route.threshold,
        secret,
        reply_pub,
        tag,
    );
    let session = ClientSession::dial(meeting, service_public, rng);
    Some(dial_anonymous(client, session, rclient, reply_keys))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    // The test's frame-capture sink carries (Coord, payload) and is scaffolding, not the bounded
    // datagram transport under test, so it stays on an unbounded channel.
    use tokio::sync::mpsc::unbounded_channel;
    use fanos_field::F2;
    use fanos_geometry::{Line, Point};
    use fanos_pqcrypto::{HybridKemSecret, SeedRng};
    use fanos_rendezvous::{MixDirectory, meeting_line};

    /// The shipped Fano parameters: `2`-of-`3` peeling at the production `(2, 2)` depths.
    fn fano_params(directory: MixDirectory, epoch: Epoch) -> AnonRouteParams {
        AnonRouteParams { directory, threshold: 2, epoch, beacon: BeaconSeed::GENESIS, depths: (2, 2) }
    }

    fn fano_directory() -> MixDirectory {
        let mut dir = MixDirectory::new();
        for i in 0..7u8 {
            let mut rng = SeedRng::from_seed(&[0x0E, i]);
            let (_secret, public) = HybridKemSecret::generate(&mut rng);
            dir.insert(Point::<F2>::at(usize::from(i)).coords(), public);
        }
        dir
    }

    /// A directory missing exactly one member's key — every line through that point becomes unsealable.
    fn fano_directory_without(missing: usize) -> MixDirectory {
        let mut dir = MixDirectory::new();
        for i in 0..7usize {
            if i == missing {
                continue;
            }
            let mut rng = SeedRng::from_seed(&[0x0E, u8::try_from(i).unwrap()]);
            let (_secret, public) = HybridKemSecret::generate(&mut rng);
            dir.insert(Point::<F2>::at(i).coords(), public);
        }
        dir
    }

    /// **A drawn circuit must be one the client can actually seal onto.**
    ///
    /// `seal_forward` needs every member of every hop line, and returns `None` if one is missing — for the
    /// whole circuit, on every call, for the life of the session. So a single unsealable hop is not a lossy
    /// hop, it is a session that sends nothing at all while looking established: the wedge signature.
    ///
    /// The draw used to permit exactly that. The reply rendezvous was checked for sealability and the
    /// intermediate hops, drawn ten lines away, were not.
    ///
    /// Asserted on the end-to-end property — the route SEALS — rather than on the predicate, so this cannot
    /// pass by agreeing with a reimplementation of the rule it is checking.
    #[test]
    #[allow(clippy::expect_used)]
    fn a_drawn_circuit_can_always_be_sealed() {
        for missing in 0..7usize {
            let dir = fano_directory_without(missing);
            let mut rng = TestRng(0xD1CE ^ missing as u64);
            // A meeting line that is itself sealable, since the client does not choose that one and a route
            // toward an unreachable service is a different question from a route laid through a dead hop.
            let meeting = (0..7)
                .map(|i| Line::<F2>::at(i).coords())
                .find(|&l| line_is_sealable::<F2>(l, &dir))
                .expect("a plane missing one point still has sealable lines");

            let route = RendezvousRoute::draw::<F2, _>(
                &fano_params(dir.clone(), Epoch::new(3)),
                meeting,
                None,
                &mut rng,
            );

            let mut forward = route.forward_hops.clone();
            forward.push(meeting);
            assert!(
                fanos_rendezvous::seal_forward::<F2>(&forward, &dir, 2, b"payload", b"seed").is_some(),
                "missing point {missing}: the forward circuit {forward:?} cannot be sealed, so this session \
                 would send nothing at all — forever, and silently"
            );
            assert!(
                fanos_rendezvous::seal_forward::<F2>(&route.reply_circuit, &dir, 2, b"reply", b"seed")
                    .is_some(),
                "missing point {missing}: the reply circuit {:?} cannot be sealed",
                route.reply_circuit
            );
        }
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

    /// Drawing the route AROUND the drop line removes every way one line can name both endpoints — and the
    /// same measurement on the old order shows the test can see the defect, so the first half is not vacuous.
    #[test]
    fn no_line_of_a_drawn_route_names_both_endpoints() {
        let dir = fano_directory();
        let epoch = Epoch::new(1);
        let trials = 2000u64;
        let (mut sound_leaks, mut legacy_leaks, mut sound_routes) = (0u32, 0u32, 0u32);
        for i in 0..trials {
            let meeting = meeting_line::<F2>(&i.to_le_bytes(), epoch, &BeaconSeed::GENESIS).coords();
            let client = Point::<F2>::at((i as usize) % 7).coords();
            let secret = [i as u8; 32];
            let drop = client_drop_line::<F2>(
                client, &secret, epoch, &BeaconSeed::GENESIS, &dir, &[meeting],
            );
            // The order under test: derive the terminus first, lay every hop around it.
            let sound = RendezvousRoute::draw::<F2, _>(
                &fano_params(dir.clone(), epoch),
                meeting,
                drop,
                &mut TestRng(i.wrapping_mul(0x9E37_79B9).wrapping_add(1)),
            );
            let mut fwd = sound.forward_hops.clone();
            fwd.push(meeting);
            if fwd.len() >= slots::TARGET_DEPTH {
                sound_routes += 1;
                if route_leaks(&fwd, &sound.reply_circuit, meeting).is_some() {
                    sound_leaks += 1;
                }
            }
            // The order that shipped: lay the hops blind, then overwrite the terminus with the drop line.
            let legacy = RendezvousRoute::draw::<F2, _>(
                &fano_params(dir.clone(), epoch),
                meeting,
                None,
                &mut TestRng(i.wrapping_mul(0x9E37_79B9).wrapping_add(1)),
            );
            let mut lfwd = legacy.forward_hops.clone();
            lfwd.push(meeting);
            let mut lreply = legacy.reply_circuit.clone();
            if let (Some(d), Some(last)) = (drop, lreply.last_mut()) {
                *last = d;
            }
            if route_leaks(&lfwd, &lreply, meeting).is_some() {
                legacy_leaks += 1;
            }
        }
        // The PROPERTY first, so a falsification that breaks the mechanism reaches this assertion.
        assert_eq!(
            sound_leaks, 0,
            "{sound_leaks} of {sound_routes} routes drawn around their own drop line still had a line naming \
             both endpoints — the whole 2t-1 argument rests on those two lines being two"
        );
        assert!(
            sound_routes > trials as u32 * 9 / 10,
            "only {sound_routes} of {trials} draws reached the minimum depth — a sound route must also be the \
             ordinary one, or the fix trades a leak for a liveness failure"
        );
        // And the falsification, kept in the tree rather than performed by hand once: the shipped order leaks
        // often enough that the assertion above is a real constraint.
        assert!(
            legacy_leaks > trials as u32 / 4,
            "the pre-fix order leaked on only {legacy_leaks} of {trials} draws, so this test cannot see the \
             defect it exists to pin"
        );
    }

    /// A circuit one hop short is refused rather than dialled, and the reason is that it is not a weaker
    /// setting: `H_1` and `H_d` become one line, so `t` members — the tolerated budget at Fano — name both ends.
    #[test]
    fn a_circuit_too_shallow_to_hide_either_endpoint_names_both() {
        let line = |i: usize| Line::<F2>::at(i).coords();
        let meeting = line(0);
        let (h1, h2, r1, r2, d) = (line(1), line(4), line(2), line(5), line(3));
        let sound_reply = [r1, r2, d];

        // FORWARD, depth 1: the circuit is [H_1, M], so the hop the client dials is the hop that learns M.
        let shallow = vec![h1, meeting];
        assert!(shallow.len() < slots::TARGET_DEPTH, "depth 1 is below the derived floor");
        assert_eq!(
            route_leaks(&shallow, &sound_reply, meeting),
            Some(h1),
            "at depth 1 the single intermediate is both the client's entry and the hop that learns the \
             meeting line, and the predicate must name it"
        );
        // Depth 0 is worse and must also be named: the client dials the meeting line itself.
        assert_eq!(route_leaks(&[meeting], &sound_reply, meeting), Some(meeting));

        // REPLY, depth 1, and this is the case a weaker derivation misses. `R_1` and `D` are DIFFERENT lines,
        // so no pair of positions coincides and the intersection test sees nothing — but a hop learns both of
        // its neighbours, so that single intermediate holds the service-side launcher and the client's drop
        // line at once. It is the same leak with a hop's worth of ceremony around it.
        let sound_forward = vec![h1, h2, meeting];
        assert_ne!(r1, d, "the two reply positions are distinct, so only the depth rule can catch this");
        assert_eq!(
            route_leaks(&sound_forward, &[r1, d], meeting),
            Some(r1),
            "one reply intermediate is not a shallower reply path, it is a hop holding both names"
        );

        // Both legs at their floor, same endpoints: sound. So each refusal above is about that leg's depth
        // rather than about the lines it was given.
        assert_eq!(route_leaks(&sound_forward, &sound_reply, meeting), None);
    }

    #[test]
    fn drawn_routes_are_fresh_and_avoid_the_meeting_line() {
        let dir = fano_directory();
        let epoch = Epoch::new(1);
        let meeting = meeting_line::<F2>(b"draw-svc", epoch, &BeaconSeed::GENESIS).coords();
        let draw = |seed: u64| {
            RendezvousRoute::draw::<F2, _>(
                &fano_params(dir.clone(), epoch),
                meeting,
                None,
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
            reply_rdv, meeting,
            "the reply rendezvous is not the meeting line — the service must not receive the \
             client's reply traffic as a delivery on its own line"
        );
        assert!(
            fanos_rendezvous::line_member_coords::<F2>(reply_rdv)
                .iter()
                .all(|m| fano_directory().get(m).is_some()),
            "the reply rendezvous is sealable: every member's key is in the directory"
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
        let rclient = RendezvousClient::<F2>::new(
            vec![hop, meeting],
            vec![rp],
            dir,
            2,
            secret,
            reply_pub.clone(),
            [0; 32],
        );
        // The launch target is a per-onion salted pick (#55), so the invariant is line MEMBERSHIP of
        // the first hop, not equality with the canonical combiner.
        let first_hop_members = fanos_rendezvous::line_member_coords::<F2>(hop);

        let (out_tx, out_rx) = channel(ChannelTransport::CAP);
        let (in_tx, mut in_rx) = channel(ChannelTransport::CAP);
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

        // Outbound: a framed DIAULOS payload is wrapped + sealed and launched at a member of the first
        // hop line (the per-onion salted pick, #55) — never forwarded in the clear.
        out_tx.send(b"diaulos-hello".to_vec()).await.unwrap();
        let (to, frame) = sent_rx.recv().await.unwrap();
        assert!(
            first_hop_members.contains(&to),
            "the onion launches at a member of its first hop line"
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
            &fanos_pqcrypto::kem::HybridKemPublic::decode(&other_pub).unwrap(),
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
            &fanos_pqcrypto::kem::HybridKemPublic::decode(&reply_pub).unwrap(),
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
