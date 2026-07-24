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
use fanos_diaulos::StaticKeypair;
use fanos_field::F2;
use fanos_geometry::{Line, Point};
use fanos_keygen::BeaconNode;
use fanos_node::{
    AnonRouteParams, CellNode, FanosDialer, OverlayBeaconNode, RendezvousRoute, StaticResolver,
    serve_anonymous_rpc,
};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, OnionKeyRatchet, SeedRng};
use fanos_proxy::{Dialer, Target};
use fanos_quic::{Directory, NodeHandle, spawn};
use fanos_runtime::{Config as OverlayConfig, OverlayNode};
use fanos_vrf::vss::{DeterministicRng, VssCommitment, deal};
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, MixDirectory, RendezvousService, combiner_for, meeting_line, seal_forward,
};

/// The epoch's public randomness beacon, shared by the service (which listens on the derived meeting
/// line) and the client (which dials it) so both compute the same line (audit E5).
const TEST_BEACON: BeaconSeed = BeaconSeed::new([0x5E; 32]);
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
            Input::Command(Command::Send { to, payload }) => {
                vec![Effect::Send { to, frame: payload }]
            }
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
    let (secret, _identity) = HybridKemSecret::generate(&mut rng);
    // The directory advertises each relay's forward-secure ONION public (audit E4); the relay peels with
    // the onion secret derived from the same genesis seed. Fixed here for the test; OS entropy in prod.
    let mut onion_seed = [0xC4u8; 32];
    onion_seed[31] = i as u8;
    let onion_public = OnionKeyRatchet::new(onion_seed, fanos_rendezvous::Epoch::ZERO)
        .public()
        .clone();
    let engine = ThresholdRouter::<F2>::new(Point::<F2>::at(i), &secret, t, onion_seed);
    let handle = spawn(Box::new(engine), dir.clone())
        .await
        .expect("spawn router");
    (handle, onion_public)
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
    let epoch = fanos_rendezvous::Epoch::new(4);
    let meeting = meeting_line::<F2>(service_pubkey, epoch, &TEST_BEACON).coords();
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
    let service_public = service.public().clone();
    let epoch = fanos_rendezvous::Epoch::new(5);
    let meeting = meeting_line::<F2>(&service_public.encode(), epoch, &TEST_BEACON).coords();
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
    let hop_to_rp = *lines.iter().find(|&&l| l != rp && l != meeting).unwrap();

    let service_node = nodes[l_index].take().unwrap();
    let rservice = RendezvousService::<F2>::new(mix.clone(), t as u8, b"anon-quic-svc-secret");
    // The PRODUCTION src host driver — the same accept loop, no test fixture (§3b). It ingests each
    // anonymous request, drives the DIAULOS server, and seals the reply back through the client's route.
    serve_anonymous_rpc(
        service_node.client(),
        service,
        SeedRng::from_seed(b"anon-quic-svc-accept"),
        rservice,
        |req| {
            let mut resp = b"anon-quic-200:".to_vec();
            resp.extend_from_slice(req);
            resp
        },
    );

    let client_node = nodes[rp_index].take().unwrap();
    let route = RendezvousRoute {
        forward_hops: vec![hop_to_l],
        reply_circuit: vec![hop_to_rp, rp],
        directory: mix,
        threshold: t as u8,
        epoch,
        beacon: TEST_BEACON,
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

/// Spawn one QUIC [`CellNode`] at Fano point `i` — a **full cell participant**: overlay + a consumer
/// beacon (`commitment`, no share) + a threshold-onion mix router. Returns its handle and its published
/// onion key. This is the deployed node shape (unlike [`router`], a bare `ThresholdRouter`): it can peel
/// rendezvous hops *and* run the overlay that surfaces a forwarded `RdvReply`.
async fn spawn_composite(
    i: usize,
    dir: &Directory,
    onion_t: usize,
    commitment: &VssCommitment,
    beacon_t: usize,
) -> (NodeHandle, HybridKemPublic) {
    let coord = Point::<F2>::at(i);
    let mut rng = SeedRng::from_seed(&[0xD0, i as u8]);
    let (secret, _identity) = HybridKemSecret::generate(&mut rng);
    let mut onion_seed = [0xC4u8; 32];
    onion_seed[31] = i as u8;
    let onion_public = OnionKeyRatchet::new(onion_seed, fanos_rendezvous::Epoch::ZERO)
        .public()
        .clone();
    let overlay = OverlayNode::<F2>::new(coord, OverlayConfig::default());
    let beacon = BeaconNode::<F2>::new(coord, None, commitment.clone(), beacon_t);
    let router = ThresholdRouter::<F2>::new(coord, &secret, onion_t, onion_seed);
    let engine = CellNode::new(OverlayBeaconNode::new(overlay, beacon), router);
    let handle = spawn(Box::new(engine), dir.clone())
        .await
        .expect("spawn cell node");
    (handle, onion_public)
}

#[tokio::test]
async fn a_fresh_anonymous_session_completes_over_a_cell_of_composites() {
    // The full deployed shape: a Fano cell of `CellNode`s (each overlay + beacon + mix router), an
    // anonymous service on one, and a DIFFERENT cell node dialing it with a FRESH per-dial route via
    // `FanosDialer::anonymous_fresh`. Unlike the fixed-route test above, the client is a real overlay
    // node: it launches onions with `Command::Emit`, its reply returns through a rendezvous **relay** that
    // forwards an `RdvReply` to it (registered by cookie), and its overlay surfaces that as the anonymous
    // reply. This exercises the whole general anonymous-proxy stack end-to-end over real QUIC.
    let dir = Directory::new();
    let t = 2usize; // 2-of-3 per Fano line
    let beacon_t = 4usize; // 4-of-7 consumer beacon (commitment only; genesis epoch, no rotation)
    let (_shares, commitment) = deal(
        &[0xB7; 32],
        beacon_t,
        7,
        &mut DeterministicRng::new(b"anon-quic-cell"),
    )
    .unwrap();

    let mut nodes: Vec<Option<NodeHandle>> = Vec::new();
    let mut mix = MixDirectory::new();
    for i in 0..7usize {
        let (handle, public) = spawn_composite(i, &dir, t, &commitment, beacon_t).await;
        mix.insert(Point::<F2>::at(i).coords(), public);
        nodes.push(Some(handle));
    }

    // The service and its rotating meeting line (genesis epoch), and the cell node that hosts its combiner.
    let mut skp = SeedRng::from_seed(b"anon-cell-svc");
    let service = StaticKeypair::generate(&mut skp);
    let service_public = service.public().clone();
    let epoch = fanos_rendezvous::Epoch::ZERO;
    let meeting = meeting_line::<F2>(&service_public.encode(), epoch, &TEST_BEACON).coords();
    let l_combiner = combiner_for::<F2>(meeting).unwrap();
    let l_index = Point::<F2>::new(l_combiner).unwrap().index();

    let service_node = nodes[l_index].take().unwrap();
    let rservice = RendezvousService::<F2>::new(mix.clone(), t as u8, b"anon-cell-svc-secret");
    // The production src host driver (§3b), on the full deployed cell-of-composites shape.
    serve_anonymous_rpc(
        service_node.client(),
        service,
        SeedRng::from_seed(b"anon-cell-svc-accept"),
        rservice,
        |req| {
            let mut resp = b"anon-quic-200:".to_vec();
            resp.extend_from_slice(req);
            resp
        },
    );

    // A different cell node is the anonymous client. Its coordinate is not the service's combiner, so its
    // fresh reply rendezvous (drawn at random) is served by a relay that forwards the reply to it.
    let client_index = (0..7).find(|&i| i != l_index).unwrap();
    let client_node = nodes[client_index].take().unwrap();

    let params = AnonRouteParams {
        directory: mix,
        threshold: t as u8,
        epoch,
        beacon: TEST_BEACON,
        depths: (1, 1),
    };
    let resolver = StaticResolver::new().with("cell.fanos", meeting, service_public);
    let dialer = FanosDialer::anonymous_fresh(client_node.client(), resolver, params);
    let mut stream = dialer
        .dial(&Target::Name("cell.fanos".to_owned(), 80))
        .await
        .expect("fresh anonymous dial by name");

    let response = tokio::time::timeout(StdDuration::from_secs(45), async {
        stream.write_all(b"GET /cell").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        resp
    })
    .await
    .expect("the fresh anonymous session completed in time");

    assert_eq!(
        response, b"anon-quic-200:GET /cell",
        "a fresh unlinkable anonymous session completed end-to-end over a cell of composite nodes"
    );
    drop(nodes);
    drop(client_node);
}
