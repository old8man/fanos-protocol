//! Anonymous rendezvous end-to-end: DIAULOS payloads ride threshold onions (APHANTOS, "a hop is a
//! line", `t`-of-`(q+1)` — no single node peels a hop) to *computed* meeting lines (CALYPSO — client
//! and service derive the same line from the service key + epoch, no lookup, rotating each epoch), so
//! deliveries are anonymous (`from == ANONYMOUS`) and neither party learns the other's location.
//!
//! Three cases, building up: (1) the forward path — a real `ClientHello` reaches the service's meeting
//! line anonymously; (2) the bidirectional handshake — the service seals the `ServerHello` back along
//! the client's reply circuit to a client rendezvous, completing the 1-RTT into a live connection;
//! (3) a **full session** — handshake + a request/response, every cell wrapped and routed both ways,
//! completing end-to-end over the mixnet.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use fanos_aphantos::ThresholdRouter;
use fanos_field::F2;
use fanos_geometry::{Line, Point, Triple};
use fanos_pqcrypto::{HybridKemSecret, OnionKeyRatchet, SeedRng};
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, MixDirectory, RendezvousClient, RendezvousService, Request, SessionId,
    combiner_for, meeting_line, seal_forward,
};
use fanos_runtime::Duration;
use fanos_sim::Sim;

/// The epoch's public randomness beacon, shared by client and service so both derive the same meeting
/// line (audit E5). Fixed across these tests; the beacon's own per-epoch variation is tested elsewhere.
const BEACON: BeaconSeed = BeaconSeed::new([0x5E; 32]);

/// A relay's forward-secure onion-ratchet genesis seed (audit E4), distinct per Fano point. Fixed here
/// for the deterministic simulator; a real relay draws it from OS entropy.
fn onion_seed_for(i: u8) -> [u8; 32] {
    let mut s = [0xA0u8; 32];
    s[31] = i;
    s
}

/// Spawn a `ThresholdRouter` at every Fano point (the mixnet), returning the members' key directory.
fn spawn_mixnet(sim: &mut Sim, t: usize) -> MixDirectory {
    let mut dir = MixDirectory::new();
    for i in 0..7 {
        let point = Point::<F2>::at(i);
        let mut rng = SeedRng::from_seed(&[0xB0, i as u8]);
        let (secret, _identity) = HybridKemSecret::generate(&mut rng);
        // The mixnet directory carries each relay's forward-secure ONION public (audit E4), not its
        // long-term identity key: the client seals to it, and the relay peels with the matching onion
        // secret derived from the same genesis seed.
        let onion_seed = onion_seed_for(i as u8);
        let onion_public = OnionKeyRatchet::new(onion_seed, fanos_rendezvous::Epoch::ZERO)
            .public()
            .clone();
        dir.insert(point.coords(), onion_public);
        sim.add(Box::new(ThresholdRouter::<F2>::new(
            point, &secret, t, onion_seed,
        )));
    }
    dir
}

#[test]
fn a_diaulos_hello_reaches_the_meeting_line_anonymously() {
    let mut sim = Sim::new(0xBEEF);
    let t = 2u8; // 2-of-3 per Fano line
    let dir = spawn_mixnet(&mut sim, usize::from(t));

    // The service's rotating meeting line (client and service derive the identical one; no lookup).
    let mut srng = SeedRng::from_seed(b"rdv-service");
    let (_svc_secret, svc_public) = HybridKemSecret::generate(&mut srng);
    let epoch = fanos_rendezvous::Epoch::new(5);
    let meeting = meeting_line::<F2>(&svc_public.encode(), epoch, &BEACON).coords();

    // A 2-hop anonymous circuit: a first line distinct from the meeting line, then the meeting line.
    let first_hop = (0..7)
        .map(|i| Line::<F2>::at(i).coords())
        .find(|&l| l != meeting)
        .unwrap();
    let circuit = [first_hop, meeting];

    // A real DIAULOS ClientHello is the carried payload (the rendezvous moves the session's bytes).
    let mut dsvc = SeedRng::from_seed(b"rdv-diaulos-svc");
    let diaulos_service = fanos_diaulos::StaticKeypair::generate(&mut dsvc);
    let mut dcli = SeedRng::from_seed(b"rdv-diaulos-cli");
    let (_pending, client_hello) = fanos_diaulos::dial(diaulos_service.public(), &mut dcli);

    // Seal the onion toward the meeting line and launch it at the first hop's combiner.
    let fwd =
        seal_forward::<F2>(&circuit, &dir, t, &client_hello, b"rdv-seed").expect("sealed onion");
    let source = Point::<F2>::at(6).coords();
    sim.inject_frame(source, fwd.combiner, fwd.frame);
    sim.run_for(Duration::from_millis(3000));

    // Delivered anonymously at the meeting line's combiner — the service, listening there, receives
    // the ClientHello without the mixnet or itself learning who the client is.
    let delivered = sim
        .report()
        .deliveries()
        .find(|(_, from, bytes)| *from == ANONYMOUS && *bytes == client_hello.as_slice());
    assert!(
        delivered.is_some(),
        "the DIAULOS ClientHello reached the service's meeting line anonymously"
    );
}

#[test]
fn a_full_diaulos_handshake_completes_over_the_anonymous_bidirectional_path() {
    let mut sim = Sim::new(0xCAFE);
    let t = 2u8;
    let dir = spawn_mixnet(&mut sim, usize::from(t));

    // The service's DIAULOS identity fixes its meeting line L; the client picks a distinct reply
    // rendezvous line RP_c it will listen on.
    let mut skp = SeedRng::from_seed(b"rdv-bidi-svc");
    let service = fanos_diaulos::StaticKeypair::generate(&mut skp);
    let epoch = fanos_rendezvous::Epoch::new(9);
    let meeting = meeting_line::<F2>(&service.public().encode(), epoch, &BEACON).coords();
    let l_combiner = combiner_for::<F2>(meeting).unwrap();

    let lines: Vec<Triple> = (0..7).map(|i| Line::<F2>::at(i).coords()).collect();
    // The client's reply rendezvous line, listed in its reply circuit: distinct from the meeting line
    // *and* with a distinct combiner, so the service (listening at its own combiner) does not also
    // receive the client's reply traffic — two lines can share a combiner point, so avoid the collision.
    let rp_c = lines
        .iter()
        .copied()
        .find(|&l| l != meeting && combiner_for::<F2>(l) != Some(l_combiner))
        .unwrap();
    let hop_to_l = *lines.iter().find(|&&l| l != meeting).unwrap();
    let hop_to_rp = *lines.iter().find(|&&l| l != rp_c && l != meeting).unwrap();

    // Client dials (DIAULOS) and wraps its ClientHello with the reply circuit to RP_c.
    let mut crng = SeedRng::from_seed(b"rdv-bidi-cli");
    let (pending, client_hello) = fanos_diaulos::dial(service.public(), &mut crng);
    let reply_circuit = vec![hop_to_rp, rp_c];
    let request = Request {
        cookie: *b"bidi-cookie-0001",
        service_tag: [0; 32],
        reply_circuit: reply_circuit.clone(),
        payload: client_hello,
        reply_pub: vec![],
    }
    .encode();

    // → forward the request anonymously to the meeting line.
    let fwd = seal_forward::<F2>(&[hop_to_l, meeting], &dir, t, &request, b"seed-fwd").unwrap();
    sim.inject_frame(Point::<F2>::at(6).coords(), fwd.combiner, fwd.frame);
    sim.run_for(Duration::from_millis(3000));

    // Service (at L's combiner) receives it anonymously, decodes, and accepts the handshake.
    let req = {
        let (_, _, bytes) = sim
            .report()
            .deliveries()
            .find(|(recv, from, _)| *recv == l_combiner && *from == ANONYMOUS)
            .expect("request delivered anonymously to the meeting line");
        Request::decode(bytes).expect("valid request")
    };
    assert_eq!(
        req.reply_circuit, reply_circuit,
        "the reply route arrived intact"
    );
    let mut arng = SeedRng::from_seed(b"rdv-bidi-accept");
    let (_conn, server_hello) =
        fanos_diaulos::accept(&service, &req.payload, &mut arng).expect("service accepts");

    // ← seal the ServerHello back along the reply circuit to the client's rendezvous.
    let back =
        seal_forward::<F2>(&req.reply_circuit, &dir, t, &server_hello, b"seed-back").unwrap();
    sim.inject_frame(l_combiner, back.combiner, back.frame);
    sim.run_for(Duration::from_millis(3000));

    // Client (at RP_c's combiner) receives the ServerHello anonymously and completes the handshake.
    let rp_combiner = combiner_for::<F2>(rp_c).unwrap();
    let dialed = {
        let (_, _, bytes) = sim
            .report()
            .deliveries()
            .find(|(recv, from, _)| *recv == rp_combiner && *from == ANONYMOUS)
            .expect("server hello delivered anonymously to the client rendezvous");
        pending
            .establish(bytes)
            .expect("the 1-RTT handshake completed over the anonymous path")
    };
    // A live connection with its primary stream — the anonymous DIAULOS session is established.
    assert_eq!(dialed.primary, 0);
}

#[test]
fn a_full_diaulos_session_request_response_over_the_anonymous_path() {
    use fanos_diaulos::{ClientSession, ServerSession};

    let mut sim = Sim::new(0xABCD);
    let t = 2u8;
    let dir = spawn_mixnet(&mut sim, usize::from(t));

    let mut skp = SeedRng::from_seed(b"rdv-sess-svc");
    let service = fanos_diaulos::StaticKeypair::generate(&mut skp);
    let epoch = fanos_rendezvous::Epoch::new(3);
    let meeting = meeting_line::<F2>(&service.public().encode(), epoch, &BEACON).coords();
    let l_combiner = combiner_for::<F2>(meeting).unwrap();

    let lines: Vec<Triple> = (0..7).map(|i| Line::<F2>::at(i).coords()).collect();
    // The client's reply rendezvous must have a combiner *distinct* from the service's meeting line —
    // otherwise the service, listening at its combiner, would also receive the client's reply traffic
    // (two lines can share their combiner point). The client derives its reply line and picks one that
    // avoids the collision.
    let rp_c = lines
        .iter()
        .copied()
        .find(|&l| l != meeting && combiner_for::<F2>(l) != Some(l_combiner))
        .unwrap();
    let rp_combiner = combiner_for::<F2>(rp_c).unwrap();

    let hop_to_l = *lines.iter().find(|&&l| l != meeting).unwrap();
    let hop_to_rp = *lines.iter().find(|&&l| l != rp_c).unwrap();
    let source = Point::<F2>::at(6).coords();

    // The reusable rendezvous transport core carries the session: the client seals each DIAULOS payload
    // to the meeting line (naming its reply circuit + cookie), and the service demultiplexes by cookie
    // and seals replies back through the recorded circuit — no manual onion wrapping in the driver.
    let mut rclient = RendezvousClient::<F2>::new(
        vec![hop_to_l, meeting],
        vec![hop_to_rp, rp_c],
        dir.clone(),
        t,
        b"rdv-sess-cli-secret",
        vec![], // legacy cookie-tagged reply path (this manual driver reads at the reply combiner)
        [0; 32], // service is its own combiner in this test — no host-forwarding tag
    );
    let mut rservice = RendezvousService::<F2>::new(dir.clone(), t, b"rdv-sess-svc-secret");

    let mut crng = SeedRng::from_seed(b"rdv-sess-cli");
    let mut client = ClientSession::dial(meeting, service.public(), &mut crng);
    let mut server = ServerSession::new();
    let mut srng = SeedRng::from_seed(b"rdv-sess-accept");

    let request = b"anon GET /".to_vec();
    let (mut wrote, mut answered) = (false, false);
    let mut seen = 0usize;

    for _round in 0..40 {
        // client → service: seal each DIAULOS payload to the meeting line through the transport core.
        for payload in client.poll_payloads() {
            let fwd = rclient.seal_send(&payload).unwrap();
            sim.inject_frame(source, fwd.combiner, fwd.frame);
        }
        if client.is_live() && !wrote {
            client.write(&request);
            client.finish();
            wrote = true;
        }
        sim.run_for(Duration::from_millis(2000));
        drain(
            &sim,
            &mut seen,
            l_combiner,
            rp_combiner,
            &service,
            &mut server,
            &mut srng,
            &mut client,
            &mut rservice,
        );

        // service answers once the request has fully arrived.
        if let Some(sid) = server.primary()
            && !answered
            && server.receiver_finished(sid)
        {
            let got = server.read(sid);
            let mut resp = b"anon-200:".to_vec();
            resp.extend_from_slice(&got);
            server.write(sid, &resp);
            server.finish(sid);
            answered = true;
        }
        // service → client: seal each DIAULOS reply back through the client's circuit, keyed by cookie.
        for payload in server.poll_payloads() {
            let fwd = rservice.seal_reply(&rclient.cookie(), &payload).unwrap();
            sim.inject_frame(l_combiner, fwd.combiner, fwd.frame);
        }
        sim.run_for(Duration::from_millis(2000));
        drain(
            &sim,
            &mut seen,
            l_combiner,
            rp_combiner,
            &service,
            &mut server,
            &mut srng,
            &mut client,
            &mut rservice,
        );

        if client.is_done() {
            break;
        }
    }

    assert!(
        client.is_live(),
        "the anonymous handshake completed over the mixnet"
    );
    assert_eq!(
        client.read(),
        b"anon-200:anon GET /",
        "a full request/response completed end-to-end over the anonymous rendezvous"
    );
}

/// Drain newly-delivered anonymous onions through the rendezvous transport core: those at the
/// meeting-line combiner are `ingest`ed by the service (unwrapping the cookie + reply route) and fed to
/// the DIAULOS server; those at the client rendezvous feed the client.
#[allow(clippy::too_many_arguments)]
fn drain(
    sim: &Sim,
    seen: &mut usize,
    l_combiner: Triple,
    rp_combiner: Triple,
    keypair: &fanos_diaulos::StaticKeypair,
    server: &mut fanos_diaulos::ServerSession,
    srng: &mut SeedRng,
    client: &mut fanos_diaulos::ClientSession,
    rservice: &mut RendezvousService<F2>,
) {
    let new: Vec<(Triple, Vec<u8>)> = sim
        .report()
        .deliveries()
        .skip(*seen)
        .filter(|(_, from, _)| *from == ANONYMOUS)
        .map(|(recv, _, bytes)| (recv, bytes.to_vec()))
        .collect();
    *seen = sim.report().deliveries().count();
    for (recv, bytes) in new {
        if recv == l_combiner {
            // A client request arriving at the service's meeting line: the transport ingests it (binding
            // the cookie to its reply circuit) and surfaces the inner DIAULOS bytes for the server.
            if let Some((_cookie, payload)) = rservice.ingest(&bytes) {
                server.handle_payload(keypair, &payload, srng);
            }
        } else if recv == rp_combiner && let Some(cell) = bytes.get(16..) {
            // A service reply arriving at the client's rendezvous: strip the 16-byte session-cookie prefix
            // the service tags every reply with (a shared relay uses it to demultiplex clients), then feed
            // the client's DIAULOS session the cell.
            client.handle_payload(cell);
        }
    }
}

#[test]
fn one_service_demultiplexes_two_anonymous_clients_by_cookie() {
    use std::collections::BTreeMap;

    use fanos_diaulos::{ClientSession, ServerSession};

    let mut sim = Sim::new(0x5151);
    let t = 2u8;
    let dir = spawn_mixnet(&mut sim, usize::from(t));

    // One service, one meeting line — both clients aim at the same L, and the service tells them apart
    // *only* by the per-session cookie in each Request (never by identity or location).
    let mut skp = SeedRng::from_seed(b"rdv-mux-svc");
    let service = fanos_diaulos::StaticKeypair::generate(&mut skp);
    let epoch = fanos_rendezvous::Epoch::new(11);
    let meeting = meeting_line::<F2>(&service.public().encode(), epoch, &BEACON).coords();
    let l_combiner = combiner_for::<F2>(meeting).unwrap();

    let lines: Vec<Triple> = (0..7).map(|i| Line::<F2>::at(i).coords()).collect();
    let combiner = |l: Triple| combiner_for::<F2>(l).unwrap();
    // Two reply rendezvous lines whose combiners are distinct from L's and from each other, so the two
    // clients' return traffic never crosses (or lands on the service's own listening point).
    let rp_a = lines
        .iter()
        .copied()
        .find(|&l| combiner(l) != l_combiner)
        .unwrap();
    let rp_b = lines
        .iter()
        .copied()
        .find(|&l| combiner(l) != l_combiner && combiner(l) != combiner(rp_a))
        .unwrap();
    let (rp_a_comb, rp_b_comb) = (combiner(rp_a), combiner(rp_b));
    assert_ne!(
        rp_a_comb, rp_b_comb,
        "the two clients listen at distinct points"
    );

    let hop_to_l = *lines.iter().find(|&&l| l != meeting).unwrap();
    let hop_a = *lines.iter().find(|&&l| l != rp_a).unwrap();
    let hop_b = *lines.iter().find(|&&l| l != rp_b).unwrap();
    let source = Point::<F2>::at(6).coords();

    // Two independent client transports (distinct secrets → distinct cookies + reply rendezvous).
    let mut rc_a = RendezvousClient::<F2>::new(
        vec![hop_to_l, meeting],
        vec![hop_a, rp_a],
        dir.clone(),
        t,
        b"rdv-mux-cli-a",
        vec![], // legacy cookie-tagged reply path
        [0; 32],
    );
    let mut rc_b = RendezvousClient::<F2>::new(
        vec![hop_to_l, meeting],
        vec![hop_b, rp_b],
        dir.clone(),
        t,
        b"rdv-mux-cli-b",
        vec![], // legacy cookie-tagged reply path
        [0; 32],
    );
    let (cookie_a, cookie_b) = (rc_a.cookie(), rc_b.cookie());
    assert_ne!(
        cookie_a, cookie_b,
        "independent secrets yield distinct cookies"
    );

    // One service transport fronts both; DIAULOS server sessions are keyed by cookie.
    let mut rsvc = RendezvousService::<F2>::new(dir.clone(), t, b"rdv-mux-svc-secret");
    let mut servers: BTreeMap<SessionId, ServerSession> = BTreeMap::new();
    let mut answered: BTreeMap<SessionId, bool> = BTreeMap::new();
    let mut srng = SeedRng::from_seed(b"rdv-mux-accept");

    let mut client_a =
        ClientSession::dial(meeting, service.public(), &mut SeedRng::from_seed(b"ca"));
    let mut client_b =
        ClientSession::dial(meeting, service.public(), &mut SeedRng::from_seed(b"cb"));
    let (mut wrote_a, mut wrote_b) = (false, false);
    let mut seen = 0usize;

    for _round in 0..60 {
        // Both clients → service (each seals to L, tagged with its own cookie + reply route).
        for payload in client_a.poll_payloads() {
            let fwd = rc_a.seal_send(&payload).unwrap();
            sim.inject_frame(source, fwd.combiner, fwd.frame);
        }
        for payload in client_b.poll_payloads() {
            let fwd = rc_b.seal_send(&payload).unwrap();
            sim.inject_frame(source, fwd.combiner, fwd.frame);
        }
        if client_a.is_live() && !wrote_a {
            client_a.write(b"GET /a");
            client_a.finish();
            wrote_a = true;
        }
        if client_b.is_live() && !wrote_b {
            client_b.write(b"GET /b");
            client_b.finish();
            wrote_b = true;
        }

        for _half in 0..2 {
            sim.run_for(Duration::from_millis(2000));

            // Dispatch every new anonymous delivery by where it landed.
            let new: Vec<(Triple, Vec<u8>)> = sim
                .report()
                .deliveries()
                .skip(seen)
                .filter(|(_, from, _)| *from == ANONYMOUS)
                .map(|(recv, _, bytes)| (recv, bytes.to_vec()))
                .collect();
            seen = sim.report().deliveries().count();
            for (recv, bytes) in new {
                if recv == l_combiner {
                    if let Some((cookie, payload)) = rsvc.ingest(&bytes) {
                        servers
                            .entry(cookie)
                            .or_default()
                            .handle_payload(&service, &payload, &mut srng);
                    }
                } else if recv == rp_a_comb && let Some(cell) = bytes.get(16..) {
                    // Strip the 16-byte session-cookie prefix the service tags replies with, then feed A.
                    client_a.handle_payload(cell);
                } else if recv == rp_b_comb && let Some(cell) = bytes.get(16..) {
                    client_b.handle_payload(cell);
                }
            }

            // Each server answers its own client once that request has fully arrived, echoing the path.
            for (cookie, server) in &mut servers {
                if let Some(sid) = server.primary()
                    && !answered.get(cookie).copied().unwrap_or(false)
                    && server.receiver_finished(sid)
                {
                    let got = server.read(sid);
                    let mut resp = b"anon-200:".to_vec();
                    resp.extend_from_slice(&got);
                    server.write(sid, &resp);
                    server.finish(sid);
                    answered.insert(*cookie, true);
                }
                for payload in server.poll_payloads() {
                    if let Some(fwd) = rsvc.seal_reply(cookie, &payload) {
                        sim.inject_frame(l_combiner, fwd.combiner, fwd.frame);
                    }
                }
            }
        }

        if client_a.is_done() && client_b.is_done() {
            break;
        }
    }

    // Both anonymous sessions completed, each demultiplexed to its own reply — no cross-talk.
    assert!(
        client_a.is_live() && client_b.is_live(),
        "both sessions live"
    );
    assert_eq!(
        client_a.read(),
        b"anon-200:GET /a",
        "client A received exactly its own response"
    );
    assert_eq!(
        client_b.read(),
        b"anon-200:GET /b",
        "client B received exactly its own response"
    );
    assert_eq!(servers.len(), 2, "the service tracked two distinct cookies");
}
