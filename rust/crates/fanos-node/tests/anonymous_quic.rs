//! Anonymous rendezvous over **real QUIC**: a threshold-onion mixnet of QUIC nodes routes sealed
//! onions to a service's *computed* meeting line, delivered anonymously (`from == ANONYMOUS`). This is
//! the sim-proven flow (`fanos-sim/tests/anonymous_rendezvous.rs`) driven over a real UDP + TLS socket,
//! confirming the `ThresholdRouter` engine peels and forwards hops identically on the production
//! transport — the sans-I/O boundary holding once more.
//!
//! Two cases: the **forward path** (a client onion reaches the meeting line anonymously) and a **full
//! bidirectional session** (a complete DIAULOS handshake + request/response over the mixnet, both
//! directions). The full session works because the client and service pace their retransmits to the
//! mixnet's effective round trip (a hop is a multi-round threshold gather), rather than the Direct
//! profile's base tick — otherwise the onion flood saturates the per-hop gathers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration as StdDuration;

use fanos_aphantos::ThresholdRouter;
use fanos_diaulos::{ServerSession, StaticKeypair};
use fanos_field::F2;
use fanos_geometry::{Line, Point};
use fanos_node::{FanosDialer, RendezvousRoute, StaticResolver};
use fanos_proxy::{Dialer, Target};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_quic::{Directory, NodeHandle, spawn};
use fanos_rendezvous::{
    ANONYMOUS, MixDirectory, RendezvousService, SessionId, combiner_for, meeting_line, seal_forward,
};
use fanos_runtime::{Command, Effect, Engine, Input, Instant, Notification, Triple};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A minimal engine that injects a **raw** wire frame on command: `Command::Send { to, payload }` →
/// `Effect::Send { to, frame: payload }`, verbatim. Unlike `OverlayNode` (which wraps the payload in
/// its own routing frame), this delivers the launch frame to the entry combiner exactly as a client
/// would put it on the wire — the way a `.fanos` client originates an onion.
struct RawInjector {
    coord: Triple,
}

impl Engine for RawInjector {
    fn step(&mut self, _now: Instant, input: Input) -> Vec<Effect> {
        match input {
            Input::Command(Command::Send { to, payload }) => vec![Effect::Send { to, frame: payload }],
            _ => Vec::new(),
        }
    }
    fn address(&self) -> Triple {
        self.coord
    }
}

/// Spawn one QUIC node running a `ThresholdRouter` at Fano point `i`, returning its handle and KEM key.
async fn router(i: usize, dir: &Directory, t: usize) -> (NodeHandle, HybridKemPublic) {
    let mut rng = SeedRng::from_seed(&[0xA0, i as u8]);
    let (secret, public) = HybridKemSecret::generate(&mut rng);
    let engine = ThresholdRouter::<F2>::new(Point::<F2>::at(i), secret, t);
    let handle = spawn(Box::new(engine), dir.clone())
        .await
        .expect("spawn router");
    (handle, public)
}

/// Await an anonymous delivery of `want` on `node`, within `secs`.
async fn await_anonymous(node: &mut NodeHandle, want: &[u8], secs: u64) -> bool {
    tokio::time::timeout(StdDuration::from_secs(secs), async {
        loop {
            match node.next_notification().await {
                Some(Notification::Delivered { from, payload })
                    if from == ANONYMOUS && payload == want =>
                {
                    return true;
                }
                Some(_) => {}
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

#[tokio::test]
async fn an_onion_reaches_the_meeting_line_over_real_quic() {
    let dir = Directory::new();
    let t = 2usize; // 2-of-3 per Fano line

    // A Fano mixnet: 7 QUIC ThresholdRouter nodes at points 0..6, plus the members' KEM directory.
    let mut nodes: Vec<NodeHandle> = Vec::new();
    let mut mix = MixDirectory::new();
    for i in 0..7usize {
        let (handle, public) = router(i, &dir, t).await;
        mix.insert(Point::<F2>::at(i).coords(), public);
        nodes.push(handle);
    }

    // The service's rotating meeting line for this epoch, and a first hop distinct from it.
    let service_pubkey = b"anon-quic-service";
    let epoch = 4u32;
    let meeting = meeting_line::<F2>(service_pubkey, epoch).coords();
    let hop = (0..7)
        .map(|i| Line::<F2>::at(i).coords())
        .find(|&l| l != meeting)
        .unwrap();
    let l_combiner = combiner_for::<F2>(meeting).unwrap();
    let l_index = Point::<F2>::new(l_combiner).unwrap().index();

    // A client injector node (a non-mixnet coordinate) that puts the launch frame on the wire.
    let injector = spawn(
        Box::new(RawInjector {
            coord: [0xFF, 0xFF, 0xFF],
        }),
        dir.clone(),
    )
    .await
    .expect("spawn injector");

    // Seal a payload into a 2-hop onion and launch it at the first hop's combiner over QUIC.
    let payload = b"anon hello over quic".to_vec();
    let fwd = seal_forward::<F2>(&[hop, meeting], &mix, t as u8, &payload, b"quic-seed").unwrap();
    injector.command(Command::Send {
        to: fwd.combiner,
        payload: fwd.frame,
    });

    // The node sitting at the meeting line's combiner receives the payload anonymously — the mixnet
    // peeled both hops over the real socket, and no node (nor the endpoint) learned the source.
    assert!(
        await_anonymous(&mut nodes[l_index], &payload, 20).await,
        "the onion was delivered anonymously to the meeting line over QUIC"
    );
}

/// The service side of an anonymous session over its meeting-line node: ingest requests, drive a
/// DIAULOS `ServerSession`, and seal each reply back through the client's reply circuit — paced to the
/// mixnet round trip so replies do not flood the path.
async fn anonymous_service(
    keypair: StaticKeypair,
    mut node: NodeHandle,
    mut rservice: RendezvousService<F2>,
) {
    let mut server = ServerSession::new();
    let mut rng = SeedRng::from_seed(b"anon-quic-svc-accept");
    let mut cookie: Option<SessionId> = None;
    let mut answered = false;
    let mut ticker = tokio::time::interval(StdDuration::from_millis(250));
    loop {
        if let Some(sid) = server.primary()
            && !answered
            && server.receiver_finished(sid)
        {
            let got = server.read(sid);
            let mut resp = b"anon-quic-200:".to_vec();
            resp.extend_from_slice(&got);
            server.write(sid, &resp);
            server.finish(sid);
            answered = true;
        }
        if let Some(ck) = cookie {
            for payload in server.poll_payloads() {
                if let Some(fwd) = rservice.seal_reply(&ck, &payload) {
                    node.command(Command::Send {
                        to: fwd.combiner,
                        payload: fwd.frame,
                    });
                }
            }
        }
        tokio::select! {
            n = node.next_notification() => match n {
                Some(Notification::Delivered { from, payload }) if from == ANONYMOUS => {
                    if let Some((ck, inner)) = rservice.ingest(&payload) {
                        cookie = Some(ck);
                        server.handle_payload(&keypair, &inner, &mut rng);
                    }
                }
                Some(_) => {}
                None => return,
            },
            _ = ticker.tick() => {}
        }
    }
}

#[tokio::test]
async fn a_full_anonymous_session_completes_over_real_quic() {
    let dir = Directory::new();
    let t = 2usize;

    let mut nodes: Vec<Option<NodeHandle>> = Vec::new();
    let mut mix = MixDirectory::new();
    for i in 0..7usize {
        let (handle, public) = router(i, &dir, t).await;
        mix.insert(Point::<F2>::at(i).coords(), public);
        nodes.push(Some(handle));
    }

    let mut skp = SeedRng::from_seed(b"anon-quic-svc");
    let service = StaticKeypair::generate(&mut skp);
    let service_public = service.public.clone();
    let epoch = 5u32;
    let meeting = meeting_line::<F2>(&service_public.encode(), epoch).coords();
    let l_combiner = combiner_for::<F2>(meeting).unwrap();
    let l_index = Point::<F2>::new(l_combiner).unwrap().index();

    let lines: Vec<Triple> = (0..7).map(|i| Line::<F2>::at(i).coords()).collect();
    let rp = lines
        .iter()
        .copied()
        .find(|&l| l != meeting && combiner_for::<F2>(l) != Some(l_combiner))
        .unwrap();
    let rp_combiner = combiner_for::<F2>(rp).unwrap();
    let rp_index = Point::<F2>::new(rp_combiner).unwrap().index();
    let hop_to_l = *lines.iter().find(|&&l| l != meeting).unwrap();
    let hop_to_rp = *lines
        .iter()
        .find(|&&l| l != rp && l != meeting)
        .unwrap();

    let service_node = nodes[l_index].take().unwrap();
    let rservice = RendezvousService::<F2>::new(mix.clone(), t as u8, b"anon-quic-svc-secret");
    tokio::spawn(anonymous_service(service, service_node, rservice));

    let client_node = nodes[rp_index].take().unwrap();
    let route = RendezvousRoute {
        forward_hops: vec![hop_to_l],
        reply_circuit: vec![hop_to_rp, rp],
        directory: mix,
        threshold: t as u8,
        epoch,
    };
    // Dial through the production seam: a FanosDialer on the anonymous profile resolves the name to the
    // service key and rides the DIAULOS session over the mixnet (the coordinate is unused anonymously —
    // the meeting line comes from the key).
    let resolver = StaticResolver::new().with("anon.fanos", meeting, service_public);
    let dialer = FanosDialer::anonymous(client_node.client(), resolver, route);
    let mut stream = dialer
        .dial(&Target::Name("anon.fanos".to_owned(), 80))
        .await
        .expect("anonymous dial by name");

    let response = tokio::time::timeout(StdDuration::from_secs(40), async {
        stream.write_all(b"GET /anon").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        resp
    })
    .await
    .expect("the anonymous session completed in time");

    assert_eq!(
        response, b"anon-quic-200:GET /anon",
        "a full anonymous DIAULOS request/response completed over the real-QUIC mixnet"
    );
    drop(nodes);
    drop(client_node);
}
