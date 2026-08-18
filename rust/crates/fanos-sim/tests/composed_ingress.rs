//! **The ingress role a deployment actually runs** — the OUTERMOST branch of `compose_engine`.
//!
//! `ingress_node.rs` already unit-tests the composite's dispatch: a POROS frame reaches the host, a command
//! reaches the inner engine. What it cannot test is the branch that BUILDS that composite. `composition.rs:273`
//! turns an `IngressParams` into a `PorosHost` — regenerating the KEM secret from a seed, pinning epoch 0 and
//! **this network's** genesis seed rather than the constant — and wraps the whole cell engine in it. Nothing
//! stood that up (#180): `ingress: Some(..)` appeared nowhere in this crate, so the wiring from a provisioning
//! record to a running host was checked at neither end.
//!
//! A newcomer derives a community's ingress line from `(community, epoch, beacon)`. If `compose_engine` seated
//! the host on a different seed than `Node::start` gives it, the host would serve a line nobody looks at — and
//! that failure is silent, which is why it is exercised over a real cell here rather than argued about.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use fanos_field::F2;
use fanos_geometry::{Plane, Point, Triple};
use fanos_node::composition::{CellComposition, compose_engine};
use fanos_node::config::IngressParams;
use fanos_node::{
    BeaconSeed, Epoch, IngressDescriptor, Peer, request_frame, shard_descriptor, solve_ingress_request,
};
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::Sim;
use fanos_wire::{FrameType, encode_frame};
use std::net::SocketAddr;

/// The community whose ingress line this cell hosts. Secret material in production; a literal here because the
/// requester must derive the same line, which is the whole point of the enumeration-resistance argument.
const COMMUNITY: &[u8] = b"composed-ingress-community";
/// Low enough that the test's requester solves it immediately; the PoW rate-limiter is exercised for its
/// dispatch, not for its cost (`sybil.rs` is explicit that a sequential proof bounds rate, never total).
const DIFFICULTY: u32 = 4;
/// A solo (1-of-1) line, so one composed node is its own combiner and serves a bucket alone. The threshold
/// protocol itself is covered by `poros.rs`; what is under test here is the composition around it.
const THRESHOLD: usize = 1;

/// The entry peers the line hands a newcomer.
fn descriptor() -> IngressDescriptor {
    IngressDescriptor {
        peers: (0..6)
            .map(|i| Peer {
                coord: Point::<F2>::at(i).coords(),
                addr: SocketAddr::from(([10, 0, 0, i as u8], 9000 + i as u16)),
            })
            .collect(),
    }
}

/// A plain overlay `Route` frame — the traffic an `IngressNode` must pass DOWN rather than answer.
fn route_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    encode_frame(FrameType::Route.code(), payload, &mut f);
    f
}

/// A whole Fano cell in which point 0 additionally hosts a 1-of-1 ingress line.
///
/// `hosting` switches the ingress role off for the control and changes nothing else — same seven engines,
/// same dealing, same `Sim` seed.
fn spawn_ingress_cell(sim: &mut Sim, hosting: bool) -> Triple {
    let host_coord = Point::<F2>::at(0).coords();
    let desc = descriptor();
    let randomness = vec![0x33u8; desc.to_bytes().len() + 8];
    let dealt = shard_descriptor(&desc, THRESHOLD as u8, 1, &randomness).expect("a 1-of-1 dealing");

    for point in Plane::<F2>::points() {
        let mut what = CellComposition::overlay_only(Config {
            heartbeat: Duration::from_millis(500),
            liveness_timeout: Duration::from_millis(1600),
            ..Config::default()
        });
        if hosting && point.coords() == host_coord {
            what.ingress = Some(IngressParams {
                community: COMMUNITY.to_vec(),
                share: dealt.shares[0].clone(),
                binding: dealt.binding.clone(),
                line: vec![host_coord],
                threshold: THRESHOLD,
                difficulty: DIFFICULTY,
                kem_seed: [0x1Du8; 32],
            });
        }
        sim.add(compose_engine::<F2>(point, &what, None));
    }
    host_coord
}

/// Run one world: a Fano cell with or without the ingress role, given the same ordinary frame and the same
/// newcomer request at the same simulated instants. Returns `(the ordinary frame landed, frames on the wire)`.
///
/// Both worlds in one helper because the observable is a DIFFERENCE. Counting the hosting run's frames alone
/// does not work and the control proved it: a settled cell emits heartbeats throughout the window, so
/// `frames_sent` rises whether or not anyone answered. That first version would have passed with no host at
/// all — the control is the only reason it was caught ([[falsify-every-new-test]]).
fn run_world(hosting: bool) -> (bool, u64) {
    let ordinary = b"ordinary overlay traffic".to_vec();
    let requester = Point::<F2>::at(3).coords();

    let mut sim = Sim::new(0x1D6E);
    let host = spawn_ingress_cell(&mut sim, hosting);
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(1500));

    sim.inject_frame(requester, host, route_frame(&ordinary));
    sim.run_for(Duration::from_millis(500));
    let carried = sim
        .report()
        .deliveries()
        .any(|(recv, from, bytes)| recv == host && from == requester && bytes == ordinary.as_slice());

    let req =
        solve_ingress_request(requester, COMMUNITY, Epoch::new(0), &BeaconSeed::GENESIS, DIFFICULTY);
    sim.inject_frame(requester, host, request_frame(&req));
    sim.run_for(Duration::from_millis(1000));
    (carried, sim.report().metrics.frames_sent)
}

/// Both sides of the outermost dispatch, as the difference between two otherwise identical worlds.
#[test]
fn a_composed_ingress_host_answers_a_newcomer_and_still_carries_the_cells_traffic() {
    let (carried_with, sent_with) = run_world(true);
    let (carried_without, sent_without) = run_world(false);

    // SIDE ONE — the cell engine underneath is reached in BOTH worlds. The `IngressNode` is composed
    // outermost, so every frame the cell handles passes through it; a wrapper that answered frames itself
    // would silence the node it wraps, and this is the assertion that would catch it.
    assert!(carried_with, "the outermost wrapper must pass a non-POROS frame to the engine it wraps");
    assert!(
        carried_without,
        "and the control carries it too — the two worlds differ in the ingress role ALONE, so a difference \
         here would mean the comparison below is measuring something other than the host"
    );

    // SIDE TWO — the POROS request is answered, and only in the world that has a host. The requester derives
    // its proof against the network's genesis seed, which is what `compose_engine` seats the host on
    // (`what.genesis_seed()`); a host pinned to a different seed answers nothing, silently.
    assert!(
        sent_with > sent_without,
        "a valid ingress request must make the composed host emit a response the identical roleless cell does \
         not send (with {sent_with} vs without {sent_without}) — equal counts mean the POROS frame reached no \
         host, so `ingress: Some(..)` built one that is not there"
    );
}
