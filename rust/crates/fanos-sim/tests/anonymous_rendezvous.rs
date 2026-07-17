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

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_aphantos::ThresholdRouter;
use fanos_field::F2;
use fanos_geometry::{Line, Point, Triple};
use fanos_pqcrypto::{HybridKemSecret, SeedRng};
use fanos_rendezvous::{
    ANONYMOUS, MixDirectory, Request, combiner_for, meeting_line, seal_forward,
};
use fanos_runtime::Duration;
use fanos_sim::Sim;

/// Spawn a `ThresholdRouter` at every Fano point (the mixnet), returning the members' key directory.
fn spawn_mixnet(sim: &mut Sim, t: usize) -> MixDirectory {
    let mut dir = MixDirectory::new();
    for i in 0..7 {
        let point = Point::<F2>::at(i);
        let mut rng = SeedRng::from_seed(&[0xB0, i as u8]);
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        dir.insert(point.coords(), public);
        sim.add(Box::new(ThresholdRouter::<F2>::new(point, secret, t)));
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
    let epoch = 5u32;
    let meeting = meeting_line::<F2>(&svc_public.encode(), epoch).coords();

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
    let (_pending, client_hello) = fanos_diaulos::dial(&diaulos_service.public, &mut dcli);

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
    let epoch = 9u32;
    let meeting = meeting_line::<F2>(&service.public.encode(), epoch).coords();
    let rp_c = meeting_line::<F2>(b"client-reply-rendezvous", epoch).coords();

    let lines: Vec<Triple> = (0..7).map(|i| Line::<F2>::at(i).coords()).collect();
    let hop_to_l = *lines.iter().find(|&&l| l != meeting).unwrap();
    let hop_to_rp = *lines.iter().find(|&&l| l != rp_c).unwrap();

    // Client dials (DIAULOS) and wraps its ClientHello with the reply circuit to RP_c.
    let mut crng = SeedRng::from_seed(b"rdv-bidi-cli");
    let (pending, client_hello) = fanos_diaulos::dial(&service.public, &mut crng);
    let reply_circuit = vec![hop_to_rp, rp_c];
    let request = Request {
        reply_circuit: reply_circuit.clone(),
        payload: client_hello,
    }
    .encode();

    // → forward the request anonymously to the meeting line.
    let fwd = seal_forward::<F2>(&[hop_to_l, meeting], &dir, t, &request, b"seed-fwd").unwrap();
    sim.inject_frame(Point::<F2>::at(6).coords(), fwd.combiner, fwd.frame);
    sim.run_for(Duration::from_millis(3000));

    // Service (at L's combiner) receives it anonymously, decodes, and accepts the handshake.
    let l_combiner = combiner_for::<F2>(meeting).unwrap();
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
    let epoch = 3u32;
    let meeting = meeting_line::<F2>(&service.public.encode(), epoch).coords();
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
    let reply_circuit = vec![hop_to_rp, rp_c];
    let source = Point::<F2>::at(6).coords();

    // The two session halves ride the anonymous transport via their payload-level API.
    let mut crng = SeedRng::from_seed(b"rdv-sess-cli");
    let mut client = ClientSession::dial(meeting, &service.public, &mut crng);
    let mut server = ServerSession::new();
    let mut srng = SeedRng::from_seed(b"rdv-sess-accept");

    let request = b"anon GET /".to_vec();
    let (mut wrote, mut answered) = (false, false);
    let mut seen = 0usize;
    let mut onion = 0u64; // a fresh per-onion seed (never reuse per-hop key material)

    let mut next_seed = || {
        onion += 1;
        onion.to_be_bytes().to_vec()
    };

    for _round in 0..40 {
        // client → service: wrap each payload with the reply circuit and seal to the meeting line.
        for payload in client.poll_payloads() {
            let req = Request {
                reply_circuit: reply_circuit.clone(),
                payload,
            }
            .encode();
            let fwd =
                seal_forward::<F2>(&[hop_to_l, meeting], &dir, t, &req, &next_seed()).unwrap();
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
        // service → client: seal each payload to the client's reply rendezvous.
        for payload in server.poll_payloads() {
            let fwd = seal_forward::<F2>(&reply_circuit, &dir, t, &payload, &next_seed()).unwrap();
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

/// Drain newly-delivered anonymous onions: those at the meeting-line combiner feed the service (after
/// unwrapping the Request), those at the client rendezvous feed the client.
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
            // A client request arriving at the service's meeting line: unwrap and feed the service.
            if let Some(req) = Request::decode(&bytes) {
                server.handle_payload(keypair, &req.payload, srng);
            }
        } else if recv == rp_combiner {
            // A service reply arriving at the client's rendezvous: feed the client.
            client.handle_payload(&bytes);
        }
    }
}
