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

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::await_holding_lock)]

mod common;


use std::sync::{LazyLock, Mutex, PoisonError};

// Real-QUIC integration tests each bring up several loopback nodes; running them at once overloads the
// transport and stalls handshakes. Serialize them behind one blocking lock — the same guard `exit_quic.rs`,
// `diaulos_quic.rs` and `hole_punch.rs` already use, and the one file that had it missing.
//
// This was not a latent tidiness issue. CI ran eight of these concurrently on a two-core runner and four
// failed together, every one of them reporting that its runtime "was polled 0 times ... against 521 expected
// (0%)" — a starved host, not a broken system. The workflow has never once been green.
static SERIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

use fanos_aphantos::ThresholdRouter;

use fanos_aphantos::nostos::{ReplyKeys, select_drop_line};
use fanos_diaulos::{StaticKeypair, bundle_from_identity};
use fanos_field::F2;
use fanos_geometry::{Line, Point};
use fanos_keygen::BeaconNode;
use fanos_node::rendezvous_relay::RendezvousRelay;
use fanos_node::spawn_mix_directory_feeder;
use fanos_node::{
    AnonRouteParams, CellNode, FanosDialer, HostedService, OverlayBeaconNode, RendezvousRoute, StaticResolver,
    build_cell_mix_directory, serve_anonymous_rpc, spawn_mix_publisher, spawn_rendezvous_host_rpc,
};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, HybridSigSecret, OnionKeyRatchet, SeedRng};
use fanos_proxy::{Dialer, Target};
use fanos_quic::{Directory, NodeHandle, spawn};
use fanos_runtime::{Config as OverlayConfig, OverlayNode};
use fanos_vrf::vss::{DeterministicRng, VssCommitment, deal};
use fanos_rendezvous::CONTROL_MIX_DIRECTORY;
use fanos_rendezvous::{
    ANONYMOUS, BeaconSeed, HostRegister, MixDirectory, RendezvousService, combiner_for,
    line_member_coords, meeting_line, meeting_lines, seal_forward, seal_host_register,
};

/// The epoch's public randomness beacon, shared by the service (which listens on the derived meeting
/// line) and the client (which dials it) so both compute the same line (audit E5).
const TEST_BEACON: BeaconSeed = BeaconSeed::new([0x5E; 32]);
use fanos_runtime::{Command, Effect, Engine, Input, Instant, Notification, Triple};

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
    // Wrapped in a `RendezvousRelay`, **as a deployed node is**: `CellNode::new` composes exactly this
    // pairing, so a bare router here would be a fixture that cannot do what production does.
    //
    // It is not a detail. §3b off-combiner forwarding — a gathering member re-sealing a request to the
    // host's registered dead-drop — lives only in the relay, and a bare `ThresholdRouter` has no `hosts` map
    // at all. Since `a54d4aa` made the gathering member a per-onion salted draw, the member that peels a
    // request is usually NOT the one hosting the service, so without the relay the request is peeled,
    // surfaced locally on the wrong node, and silently dropped. Measured: the host at `[1,1,1]` while every
    // request landed on `[0,1,1]`, `[1,0,0]` or `[1,1,0]` — 2 passes in 10 runs, the odds of the draw.
    //
    // The simulator-fidelity rule this restores: a test node must differ from a production node in its
    // **transport** and nothing else. This one differed in its composition, which is the one difference
    // that hides a whole subsystem.
    let engine = RendezvousRelay::<F2>::new(ThresholdRouter::<F2>::new(
        Point::<F2>::at(i),
        &secret,
        t,
        onion_seed,
    ));
    let handle = spawn(Box::new(engine), dir.clone())
        .await
        .expect("spawn router");
    (handle, onion_public)
}

/// Await an anonymous delivery of `want` at **any member of `line`**, within the shared hang ceiling.
///
/// This replaced a single-node `await_anonymous(&mut nodes[l_index], …)`: which member gathers a given onion is
/// now the per-onion salted pick (#55), so there is no one node to await. The members are polled CONCURRENTLY,
/// and that is a correctness requirement rather than a nicety — a serial loop would spend the whole ceiling on
/// the first member and time out before ever reaching the one that received it. Racing them makes "some member
/// of the line got it" a single bounded wait, on the same total budget the one-node form used.
///
/// The ceiling is `common::HANG_CEILING` rather than a per-call `secs` argument, which removes the old
/// conflation: a caller passing `20` was not claiming the delivery takes 20 s, it was guessing how long to wait
/// before giving up.
async fn await_anonymous_on_line(nodes: &mut [NodeHandle], line: Triple, want: &[u8]) -> bool {
    let members = line_member_coords::<F2>(line);
    let mut waits: Vec<Option<_>> = nodes
        .iter_mut()
        .enumerate()
        .filter(|(i, _)| {
            members.iter().any(|&m| Point::<F2>::new(m).is_some_and(|p| p.index() == *i))
        })
        .map(|(_, node)| {
            Some(Box::pin(async move {
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
            }))
        })
        .collect();
    tokio::time::timeout(common::HANG_CEILING, async {
        // Poll every member's wait until one reports the delivery. `select_all` needs the `futures` crate,
        // which this crate does not carry for tests; a hand-rolled poll over the pinned futures keeps the
        // dependency surface unchanged and is exactly as concurrent. A finished wait is TAKEN OUT rather
        // than polled again — polling a completed future is undefined, and a member whose node has shut
        // down completes immediately with `false`.
        std::future::poll_fn(|cx| {
            let mut pending = false;
            for slot in &mut waits {
                let Some(wait) = slot.as_mut() else { continue };
                match wait.as_mut().poll(cx) {
                    std::task::Poll::Ready(true) => return std::task::Poll::Ready(true),
                    std::task::Poll::Ready(false) => *slot = None,
                    std::task::Poll::Pending => pending = true,
                }
            }
            // Every member's stream ended without the delivery: report it now rather than idling to the
            // ceiling — an exhausted race is an answer, not a hang.
            if pending { std::task::Poll::Pending } else { std::task::Poll::Ready(false) }
        })
        .await
    })
    .await
    .unwrap_or(false)
}

/// The signing half a hosted service needs, plus the full bundle it publishes.
///
/// Mirrors `hidden_service_identity` in the CLI: the combiner authenticates a route registration by recomputing
/// `service_tag` from the presented bundle and verifying a signature under its signing prefix, so a hosted service
/// must publish a bundle with a real one. A KEM-only bundle is reconstructible by anyone holding the public KEM
/// key and would authenticate nothing.
fn signing_half(kem: &HybridKemPublic, seed: &[u8]) -> (HybridSigSecret, Vec<u8>) {
    let mut rng = SeedRng::from_seed(seed);
    let (signer, verifier) = HybridSigSecret::generate(&mut rng);
    let bundle = bundle_from_identity(&verifier, kem);
    (signer, bundle)
}

#[tokio::test]
async fn an_onion_reaches_the_meeting_line_over_real_quic() {
    let _serial = serial();
    let _serial = common::serial_cell().await; // one whole-cell fixture at a time
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

    // A node ON the meeting line receives the payload anonymously — the mixnet peeled both hops over the
    // real socket, and no node (nor the endpoint) learned the source.
    //
    // *Which* member is decided by the per-onion salted pick (#55), so the assertion is over the line's
    // membership rather than its canonical combiner. Awaiting one predetermined node is what this test did
    // before, and it is precisely the assumption whose removal made a silenced node survivable.
    assert!(
        await_anonymous_on_line(&mut nodes, meeting, &payload).await,
        "the onion was delivered anonymously to a member of the meeting line over QUIC"
    );
}

#[tokio::test]
async fn a_full_anonymous_session_completes_over_real_quic() {
    let _serial = serial();
    let _serial = common::serial_cell().await; // one whole-cell fixture at a time
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
    let (signer, bundle) = signing_half(&service_public, b"anon-quic-service");
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
    // The service registers a forward route at EVERY meeting point, even though it happens to sit at one
    // combiner: a client now picks among the `f + 1` points, and a registration is what makes any of them able to
    // reach it. Being at a combiner stops being load-bearing — it becomes an accident of placement.
    let drop_line = select_drop_line(Point::<F2>::at(l_index), b"anon-quic-svc-secret", epoch.get(), TEST_BEACON.as_bytes())
        .coords();
    let (svc_reply_keys, svc_reply_pub) = ReplyKeys::generate(b"anon-quic-svc-secret");
    let reg = HostRegister::onion(&bundle, &signer, epoch, svc_reply_pub.encode(), vec![drop_line], t as u8)
        .expect("the dead-drop line is nameable");
    for (i, point) in meeting_lines::<F2>(&service_public.encode(), epoch, &TEST_BEACON).into_iter().enumerate() {
        let seed = [b"anon-quic-svc-secret".as_slice(), &(i as u32).to_be_bytes()].concat();
        if let Some(fwd) = seal_host_register::<F2>(&[point], &mix, t as u8, &reg, &seed) {
            service_node.client().command(Command::Emit { to: fwd.combiner, frame: fwd.frame });
        }
    }
    // Any node may be the combiner the client picks, and a combiner cannot seal a forward without the epoch's
    // mix directory — it is a sans-I/O engine and cannot resolve one itself.
    for n in nodes.iter().flatten() {
        n.client().command(Command::Control { tag: CONTROL_MIX_DIRECTORY, body: mix.encode() });
    }
    service_node.client().command(Command::Control { tag: CONTROL_MIX_DIRECTORY, body: mix.encode() });
    let rservice = RendezvousService::<F2>::new(mix.clone(), t as u8, b"anon-quic-svc-secret");
    // The PRODUCTION src host driver — the same accept loop, no test fixture (§3b). It ingests each
    // anonymous request, drives the DIAULOS server, and seals the reply back through the client's route.
    serve_anonymous_rpc(
        service_node.client(),
        service,
        SeedRng::from_seed(b"anon-quic-svc-accept"),
        rservice,
        vec![svc_reply_keys], // opens the dead-drops its own registration points at
        None,   // no epoch-rotation driver: a fixed single-epoch test
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
    let resolver = StaticResolver::new().with("anon.fanos", meeting, bundle.clone());
    let dialer = FanosDialer::anonymous(client_node.client(), resolver, route);
    let mut stream = dialer
        .dial(&Target::Name("anon.fanos".to_owned(), 80))
        .await
        .expect("anonymous dial by name");

    let response = common::exchange(&mut stream, b"GET /anon").await;

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
    let _serial = serial();
    let _serial = common::serial_cell().await; // one whole-cell fixture at a time
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
    let (signer, bundle) = signing_half(&service_public, b"anon-quic-service");
    let epoch = fanos_rendezvous::Epoch::ZERO;
    let meeting = meeting_line::<F2>(&service_public.encode(), epoch, &TEST_BEACON).coords();
    let l_combiner = combiner_for::<F2>(meeting).unwrap();
    let l_index = Point::<F2>::new(l_combiner).unwrap().index();

    let service_node = nodes[l_index].take().unwrap();
    // The service registers a forward route at EVERY meeting point, even though it happens to sit at one
    // combiner: a client now picks among the `f + 1` points, and a registration is what makes any of them able to
    // reach it. Being at a combiner stops being load-bearing — it becomes an accident of placement.
    let drop_line = select_drop_line(Point::<F2>::at(l_index), b"anon-cell-svc-secret", epoch.get(), TEST_BEACON.as_bytes())
        .coords();
    let (svc_reply_keys, svc_reply_pub) = ReplyKeys::generate(b"anon-cell-svc-secret");
    let reg = HostRegister::onion(&bundle, &signer, epoch, svc_reply_pub.encode(), vec![drop_line], t as u8)
        .expect("the dead-drop line is nameable");
    for (i, point) in meeting_lines::<F2>(&service_public.encode(), epoch, &TEST_BEACON).into_iter().enumerate() {
        let seed = [b"anon-cell-svc-secret".as_slice(), &(i as u32).to_be_bytes()].concat();
        if let Some(fwd) = seal_host_register::<F2>(&[point], &mix, t as u8, &reg, &seed) {
            service_node.client().command(Command::Emit { to: fwd.combiner, frame: fwd.frame });
        }
    }
    // Every node may be the combiner the client picks, and a combiner cannot seal a forward without the epoch's
    // mix directory — it is a sans-I/O engine and cannot resolve one itself.
    for n in nodes.iter().flatten() {
        n.client().command(Command::Control { tag: CONTROL_MIX_DIRECTORY, body: mix.encode() });
    }
    service_node.client().command(Command::Control { tag: CONTROL_MIX_DIRECTORY, body: mix.encode() });
    let rservice = RendezvousService::<F2>::new(mix.clone(), t as u8, b"anon-cell-svc-secret");
    // The production src host driver (§3b), on the full deployed cell-of-composites shape.
    serve_anonymous_rpc(
        service_node.client(),
        service,
        SeedRng::from_seed(b"anon-cell-svc-accept"),
        rservice,
        vec![svc_reply_keys], // opens the dead-drops its own registration points at
        None,   // no epoch-rotation driver: a fixed single-epoch test
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
        directory: mix.clone(),
        threshold: t as u8,
        epoch,
        beacon: TEST_BEACON,
        depths: (1, 1),
    };
    let resolver = StaticResolver::new().with("cell.fanos", meeting, bundle.clone());
    let dialer = FanosDialer::anonymous_fresh(client_node.client(), resolver, params);
    let mut stream = dialer
        .dial(&Target::Name("cell.fanos".to_owned(), 80))
        .await
        .expect("fresh anonymous dial by name");

    let response = common::exchange(&mut stream, b"GET /cell").await;

    assert_eq!(
        response, b"anon-quic-200:GET /cell",
        "a fresh unlinkable anonymous session completed end-to-end over a cell of composite nodes"
    );
    drop(nodes);
    drop(client_node);
}

/// Register `reg` anonymously at **every member of every** meeting line of `service_public` this epoch.
///
/// At every meeting point, because the client picks among them — registering at one leaves the other `m − 1`
/// unable to reach this host, which is the very spread the `f + 1` points exist to provide. And at every MEMBER
/// of each point (#55), because a client launch draws a per-onion member (`combiner_for_salted`): a member
/// without the binding is a member that answers a client with silence. One sealed frame serves all `q + 1` —
/// each member runs its own gather over the identical onion and binds. Each point's registration is sealed under
/// its own seed, so a member that peels one cannot replay it to another point.
fn register_at_every_meeting_member(
    host: &NodeHandle,
    service_public: &HybridKemPublic,
    epoch: fanos_rendezvous::Epoch,
    mix: &MixDirectory,
    threshold: u8,
    reg: &HostRegister,
) {
    for (i, point) in meeting_lines::<F2>(&service_public.encode(), epoch, &TEST_BEACON).into_iter().enumerate() {
        let seed = [b"off-combiner-reg".as_slice(), &(i as u32).to_be_bytes()].concat();
        let fwd = seal_host_register::<F2>(&[point], mix, threshold, reg, &seed).unwrap();
        for member in line_member_coords::<F2>(point) {
            host.client().command(Command::Emit { to: member, frame: fwd.frame.clone() });
        }
    }
}

/// Block until **every member of every** meeting line has bound `expect`'s forward route.
///
/// Waiting on the binding rather than on a duration is the difference between a test and a coin flip: a member
/// silently drops a request whose tag it has not bound yet, and the client then waits forever for a reply that
/// was never forwarded. Every member, not just the canonical combiner, because a client's launch draws a
/// per-onion member (#55) and may peel anywhere on the line — dialing before the spread completed measured as
/// 0 of 8 arrivals, which reads exactly like "the spread does not work" and is in fact "the spread had not
/// finished". A node lying on two meeting lines binds once per line, and is therefore awaited twice.
async fn await_every_meeting_member_binds(
    nodes: &mut [Option<NodeHandle>],
    host: &mut NodeHandle,
    host_index: usize,
    points: &[Triple],
    expect: [u8; 32],
) {
    for &point in points {
        for member in line_member_coords::<F2>(point) {
            let mi = Point::<F2>::new(member).unwrap().index();
            let node = if mi == host_index {
                &mut *host
            } else {
                nodes[mi].as_mut().unwrap_or_else(|| panic!("meeting-line member node {mi} is held"))
            };
            assert_eq!(
                common::host_registered(node).await,
                expect,
                "meeting-line member {member:?} must bind this service's forward route"
            );
        }
    }
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "two properties in one fixture; see the split note inside")]
async fn a_service_hosted_off_its_meeting_combiner_is_reached_via_forwarding() {
    let _serial = serial();
    let _serial = common::serial_cell().await; // one whole-cell fixture at a time
    // The §3b general case — no cheat: the service operator is NOT the node at its meeting combiner (it
    // cannot choose its VRF coordinate). It registers an anonymous forward route (its own dead-drop line)
    // with the combiner by onion; the combiner re-seals each client request to that dead-drop; the operator
    // opens it and serves. Neither the combiner nor anyone learns the operator's coordinate.
    let dir = Directory::new();
    let t = 2usize;
    let beacon_t = 4usize;
    let (_shares, commitment) =
        deal(&[0xB8; 32], beacon_t, 7, &mut DeterministicRng::new(b"anon-offcombiner")).unwrap();

    let mut nodes: Vec<Option<NodeHandle>> = Vec::new();
    let mut mix = MixDirectory::new();
    for i in 0..7usize {
        let (handle, public) = spawn_composite(i, &dir, t, &commitment, beacon_t).await;
        mix.insert(Point::<F2>::at(i).coords(), public);
        nodes.push(Some(handle));
    }

    let mut skp = SeedRng::from_seed(b"off-combiner-svc");
    let service = StaticKeypair::generate(&mut skp);
    let service_public = service.public().clone();
    let (signer, bundle) = signing_half(&service_public, b"anon-quic-service");
    let epoch = fanos_rendezvous::Epoch::ZERO;
    let meeting = meeting_line::<F2>(&service_public.encode(), epoch, &TEST_BEACON).coords();
    let m_combiner = combiner_for::<F2>(meeting).unwrap();
    let m_index = Point::<F2>::new(m_combiner).unwrap().index();

    // The operator hosts on a node that is NOT the meeting combiner — the realistic case.
    let host_index = (0..7).find(|&i| i != m_index).unwrap();
    let host_point = Point::<F2>::at(host_index);
    // Its dead-drop line (beacon-blinded, through its own point): where forwarded requests come home.
    let drop_line =
        select_drop_line(host_point, b"off-combiner-host", epoch.get(), TEST_BEACON.as_bytes()).coords();
    let (host_reply_keys, host_reply_pub) = ReplyKeys::generate(b"off-combiner-host");
    // The primary, coordinate-hiding registration: a 1-hop forward route to the dead-drop line, signed under the
    // service's published identity so the combiner can check the binding rather than believe it.
    let reg = HostRegister::onion(&bundle, &signer, epoch, host_reply_pub.encode(), vec![drop_line], t as u8)
        .expect("the dead-drop line's members are in the mix directory");

    // The combiner is handed the epoch's mix directory — the hop keys it seals the forward onion with. It cannot
    // resolve them itself (a sans-I/O engine cannot do a store lookup), and the registration no longer carries
    // them: carrying `q + 1` keys per hop made it grow with the plane and overflow the fixed-width onion packet.
    // A `Control` command is local by construction, so this is key material from in-process, never off the wire.
    for n in nodes.iter().flatten() {
        n.client().command(Command::Control { tag: CONTROL_MIX_DIRECTORY, body: mix.encode() });
    }

    let mut host_node = nodes[host_index].take().unwrap();
    register_at_every_meeting_member(&host_node, &service_public, epoch, &mix, t as u8, &reg);

    // The operator serves anonymously, opening each forwarded dead-drop with its reply key.
    let rservice = RendezvousService::<F2>::new(mix.clone(), t as u8, b"off-combiner-svc-secret");
    serve_anonymous_rpc(
        host_node.client(),
        service,
        SeedRng::from_seed(b"off-combiner-svc-accept"),
        rservice,
        vec![host_reply_keys], // the off-combiner host opens forwarded dead-drops with this key
        None,                  // fixed genesis epoch — no rotation driver
        |req| {
            let mut resp = b"anon-quic-200:".to_vec();
            resp.extend_from_slice(req);
            resp
        },
    );
    await_every_meeting_member_binds(
        &mut nodes,
        &mut host_node,
        host_index,
        &meeting_lines::<F2>(&service_public.encode(), epoch, &TEST_BEACON),
        reg.service_tag,
    )
    .await;

    // A third node dials by name — it neither is the combiner nor knows where the service is.
    let client_index = (0..7).find(|&i| i != m_index && i != host_index).unwrap();
    let client_node = nodes[client_index].take().unwrap();
    let params = AnonRouteParams {
        directory: mix.clone(),
        threshold: t as u8,
        epoch,
        beacon: TEST_BEACON,
        depths: (1, 1),
    };
    let resolver = StaticResolver::new().with("off.fanos", meeting, bundle.clone());
    let dialer = FanosDialer::anonymous_fresh(client_node.client(), resolver, params);
    let mut stream = dialer
        .dial(&Target::Name("off.fanos".to_owned(), 80))
        .await
        .expect("anonymous dial to an off-combiner service");

    let response = common::exchange(&mut stream, b"GET /off").await;

    assert_eq!(
        response, b"anon-quic-200:GET /off",
        "a service hosted off its meeting combiner was reached end-to-end via combiner forwarding",
    );

    // === CENSORSHIP: meeting point 0's combiner goes silent, and the service stays reachable. ===
    //
    // ⚠️ **Two properties share this test's name, and they fail independently.** Everything above is plain
    // reachability (no node silenced); everything below is reachability *under censorship*. Measured, some
    // failing runs never reach this line — they refute the assertion above — while others reach it and count
    // 0 of 8. Debugging them as one failure is why this resisted three rounds of hypotheses, each refuted:
    // a mix-directory race (a 750 ms pre-dial delay does not fix it), unlucky per-attempt draws (arithmetic:
    // 0-of-8 has probability ≈ 2.3e-8 against an observed ~1 in 3), and a stale first session held open
    // across the loop (retiring it changes nothing).
    //
    // Splitting them into two `#[tokio::test]`s needs the fixture — seven nodes, a beacon, a host, a mix
    // directory — extracted into a shared builder first. That is the next step and it is a real one: until
    // then neither half has its own name or its own rate.
    //
    // This is what `f + 1` meeting points exist for: with one, a single node held a whole epoch of this service's
    // inbound traffic and could drop it; with `f + 1`, an adversary inside the tolerated fault budget cannot hold
    // them all. Two things this test had to learn the hard way, both worth keeping:
    //
    // * **`shutdown()`, not `drop`.** Dropping the handle leaves the node running, and the first version of this
    //   test PASSED its own falsification with m collapsed to 1 — the combiner it claimed to have silenced was
    //   still answering. A test that disables nothing proves nothing.
    // * **A silenced combiner does not refuse, it swallows.** `dial` still succeeds (it only seals and emits) and
    //   the exchange then wedges forever, so each attempt needs its own deadline. That is the censorship property
    //   showing through rather than test hygiene: the only failure signal is a clock, which is exactly the signal
    //   the adversary controls — and why docs §6.2 rejected client-walks-the-points as the PRIMARY mechanism.
    //
    // ⚠️ **The paragraph below is contradicted by arithmetic and is kept only as the record of a refuted
    // explanation.** On the Fano plane the silenced node is one of three members of one of three meeting
    // points, so a single attempt avoids it with probability 1 − (1/3)(1/3) ≈ 0.889, making 0 of 8 arrivals
    // ≈ 2.3e-8 — one run in forty million. It was observed roughly **one run in three**. Whatever makes a
    // failing run fail is therefore shared across all eight attempts, not drawn per attempt.
    //
    // Two further measured facts: on failing runs the whole forward path is provably healthy (four distinct
    // combiners receive the request, each reports the host known, the host ingests it, the reply is sealed,
    // and the client opens it — 314 sealed / 44 opened in one such run); and some failing runs never reach
    // this loop at all, panicking at the *earlier* end-to-end assertion. This test name covers at least two
    // distinct failures.
    //
    // SOME ATTEMPTS MAY STILL MISS THEIR DEADLINE UNDER LOAD, and that is the expected shape, not a flake:
    // `anonymous_dial` does not retry a whole dial, but every DIAULOS retransmit reseals a fresh onion whose
    // launch and per-hop gatherers are drawn anew (`combiner_for_salted`, #55) — so a dial that touches the
    // silenced node simply loses that attempt's round trip and self-heals on the next reseal, bounded by the
    // per-attempt deadline. The property is "remains reachable", not "every dial completes in time". Do not
    // "fix" a marginal count by looping until green.
    nodes[m_index].take().expect("the combiner node is still held").shutdown();
    let dialer = FanosDialer::anonymous_fresh(
        client_node.client(),
        StaticResolver::new().with("off.fanos", meeting, bundle.clone()),
        AnonRouteParams { directory: mix.clone(), threshold: t as u8, epoch, beacon: TEST_BEACON, depths: (1, 1) },
    );
    // **Stop at the first arrival.** The property is "the service remains reachable through another of its
    // f + 1 points" — one arrival proves it; the remaining attempts prove nothing further and each can cost a
    // full `FROZEN_SPAN`. Running all eight regardless made the worst case 8 × 48 s ≈ 6.4 minutes of pure
    // timeout, which is how this test came to look like a hang rather than a failure (measured: a 399 s run).
    //
    // Attempts remain bounded at 8 so a genuinely unreachable service still terminates and still refutes.
    let mut reached = 0;
    for _ in 0..8 {
        if reached > 0 {
            break;
        }
        let Ok(mut s) = dialer.dial(&Target::Name("off.fanos".to_owned(), 80)).await else { continue };
        // Bounded by the harness's own **derived** span, not a hand-picked number. `exchange` already runs
        // under `within_span`, whose budget is `FROZEN_SPAN` (= `ROUND_TIMEOUT_MAX × 2`, 48 s). Wrapping it in
        // a shorter 12 s killed every attempt before the thing that judges it could reach a verdict — so the
        // loop counted 0 of 8 arrivals while the round trip was demonstrably completing underneath: measured,
        // 314 replies sealed by the host and 44 opened by the client during a single failing run.
        //
        // The outer bound is kept (a dial that truly hangs must not consume the whole loop) but set to the
        // same derived quantity, so it can only ever fire *after* the inner harness has spoken.
        let attempt =
            tokio::time::timeout(common::FROZEN_SPAN, common::exchange(&mut s, b"GET /off")).await;
        if attempt.as_deref() == Ok(b"anon-quic-200:GET /off".as_slice()) {
            reached += 1;
        }
    }
    assert!(
        reached > 0,
        "with meeting point 0's combiner silent the service must still be reachable through another of its \
         f + 1 points — 0 of 8 dials arrived, which is what a SINGLE meeting point would give",
    );
    drop(nodes);
    drop((host_node, client_node));
}

#[tokio::test]
async fn the_spawn_rendezvous_host_driver_serves_a_dialer_over_real_quic() {
    let _serial = serial();
    let _serial = common::serial_cell().await; // one whole-cell fixture at a time
    // The full operator driver (§3b): `spawn_rendezvous_host` builds the cell directory, registers an
    // anonymous forward route each epoch, and runs the accept loop — no manual registration. Proves the
    // driver glue over real QUIC end-to-end.
    let dir = Directory::new();
    let t = 2usize;
    let beacon_t = 4usize;
    let (_shares, commitment) =
        deal(&[0xB9; 32], beacon_t, 7, &mut DeterministicRng::new(b"anon-driver")).unwrap();

    let mut nodes: Vec<Option<NodeHandle>> = Vec::new();
    let mut mix = MixDirectory::new();
    for i in 0..7usize {
        let (handle, public) = spawn_composite(i, &dir, t, &commitment, beacon_t).await;
        mix.insert(Point::<F2>::at(i).coords(), public);
        nodes.push(Some(handle));
    }
    // Publish each node's mix key (same onion seed its router uses), so the host driver's
    // `build_cell_mix_directory` resolves the whole cell.
    let mut publishers = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let mut onion_seed = [0xC4u8; 32];
        onion_seed[31] = i as u8;
        let n = node.as_ref().unwrap();
        // This mixnet is PINNED (`spawn_pinned`), so no publisher here can prove its coordinate and no reader can check
        // one: `None` on both ends. The host driver below is told the same, and that symmetry is the whole design — the
        // binding exists exactly where VRF coordinates do (S1-M3, `mixdir::parse_bound_record`).
        publishers.push(spawn_mix_publisher(n.client(), onion_seed, n.coordinate_prover()));
        // The combiner half of the same role: a cell node PUBLISHES its onion key so others can seal to it, and
        // CONSUMES the cell's directory so it can seal a forward onion for a host registered off its combiner.
        // `Node::start` spawns the pair together for exactly this reason (`spawn_mix_export`).
        publishers.push(spawn_mix_directory_feeder::<F2>(n.client(), n.coordinate_prover().is_some()));
    }
    // Wait for the mix keys to be readable, not for a duration: the host driver below builds its directory from this
    // store, and an empty read makes it register a route through nothing.
    common::converge("every cell mix key is published", || async {
        let dir = build_cell_mix_directory::<F2>(&nodes[0].as_ref().unwrap().client(), fanos_rendezvous::Epoch::ZERO, None).await;
        (dir.len() == 7, format!("mix keys readable: {}", dir.len()))
    })
    .await;

    let mut skp = SeedRng::from_seed(b"driver-svc");
    let service = StaticKeypair::generate(&mut skp);
    let service_public = service.public().clone();
    let (signer, bundle) = signing_half(&service_public, b"anon-quic-service");
    let epoch = fanos_rendezvous::Epoch::ZERO;
    let meeting = meeting_line::<F2>(&service_public.encode(), epoch, &TEST_BEACON).coords();
    let m_index = Point::<F2>::new(combiner_for::<F2>(meeting).unwrap()).unwrap().index();

    // Host on a node that is NOT the meeting combiner; the driver registers it anonymously.
    let host_index = (0..7).find(|&i| i != m_index).unwrap();
    let host = nodes[host_index].take().unwrap();
    let _driver = spawn_rendezvous_host_rpc(
        host.client(),
        Point::<F2>::at(host_index).coords(),
        // Pinned coordinates: no mix-key record in this cell can prove its slot, and none is asked to.
        HostedService {
            service,
            identity: bundle.clone(),
            signer,
            host_secret: b"driver-host-secret".to_vec(),
            threshold: t as u8,
            vrf_coordinates: false,
        },
        (epoch, [0x5E; 32]), // the genesis (epoch, beacon-seed) — TEST_BEACON's bytes
        |req| {
            let mut resp = b"anon-quic-200:".to_vec();
            resp.extend_from_slice(req);
            resp
        },
    );
    // Same observable as the manual case: the driver's registration has actually bound at the combiner.
    common::host_registered(nodes[m_index].as_mut().expect("the combiner node is still held")).await;

    let client_index = (0..7).find(|&i| i != m_index && i != host_index).unwrap();
    let client_node = nodes[client_index].take().unwrap();
    let params = AnonRouteParams {
        directory: mix,
        threshold: t as u8,
        epoch,
        beacon: TEST_BEACON,
        depths: (1, 1),
    };
    let resolver = StaticResolver::new().with("driver.fanos", meeting, bundle.clone());
    let dialer = FanosDialer::anonymous_fresh(client_node.client(), resolver, params);
    let mut stream = dialer
        .dial(&Target::Name("driver.fanos".to_owned(), 80))
        .await
        .expect("anonymous dial to a driver-hosted service");
    let response = common::exchange(&mut stream, b"GET /driver").await;
    assert_eq!(
        response, b"anon-quic-200:GET /driver",
        "the spawn_rendezvous_host driver registered + served an off-combiner client end-to-end",
    );
    drop(nodes);
    drop((host, client_node, publishers));
}
