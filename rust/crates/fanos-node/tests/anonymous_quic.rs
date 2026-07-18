//! Anonymous rendezvous over **real QUIC**: a threshold-onion mixnet of QUIC nodes routes a sealed
//! onion to a service's *computed* meeting line, delivered anonymously (`from == ANONYMOUS`). This is
//! the sim-proven flow (`fanos-sim/tests/anonymous_rendezvous.rs`) driven over a real UDP + TLS socket,
//! confirming the `ThresholdRouter` engine peels and forwards hops identically on the production
//! transport — the sans-I/O boundary holding once more.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration as StdDuration;

use fanos_aphantos::ThresholdRouter;
use fanos_field::F2;
use fanos_geometry::{Line, Point};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_quic::{Directory, NodeHandle, spawn};
use fanos_rendezvous::{ANONYMOUS, MixDirectory, combiner_for, meeting_line, seal_forward};
use fanos_runtime::{Command, Effect, Engine, Input, Instant, Notification, Triple};

/// A minimal engine that injects a **raw** wire frame on command: `Command::Send { to, payload }` →
/// `Effect::Send { to, frame: payload }`, verbatim. Unlike `OverlayNode` (which wraps the payload in
/// its own routing frame) or `ThresholdRouter` (which ignores commands), this delivers the launch
/// frame to the entry combiner exactly as a client would put it on the wire.
struct RawInjector {
    coord: Triple,
}

impl Engine for RawInjector {
    fn step(&mut self, _now: Instant, input: Input) -> Vec<Effect> {
        match input {
            Input::Command(Command::Send { to, payload }) => {
                alloc_effect_send(to, payload)
            }
            _ => Vec::new(),
        }
    }
    fn address(&self) -> Triple {
        self.coord
    }
}

fn alloc_effect_send(to: Triple, frame: Vec<u8>) -> Vec<Effect> {
    vec![Effect::Send { to, frame }]
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
    let entry: Triple = fwd.combiner;
    injector.command(Command::Send {
        to: entry,
        payload: fwd.frame,
    });

    // The node sitting at the meeting line's combiner receives the payload anonymously — the mixnet
    // peeled both hops over the real socket, and no node (nor the endpoint) learned the source.
    assert!(
        await_anonymous(&mut nodes[l_index], &payload, 20).await,
        "the onion was delivered anonymously to the meeting line over QUIC"
    );
}
