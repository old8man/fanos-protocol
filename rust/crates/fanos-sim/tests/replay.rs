//! **C9 — onion-cell replay path-confirmation over the RUNNING mixnet.** An on-path (or global) adversary
//! captures a forwarded onion cell and re-injects it to the relay that received it, hoping the relay
//! re-processes it and confirms — by timing — that it is on the circuit. FANOS's per-relay replay cache
//! (`sealed::replay_tag`) drops a cell it has already seen. Proven crate-locally
//! (`aphantos/tests/replay_attack.rs`); here it is driven over the real routed `NyxNode` mixnet — a
//! replayed cell produces no second delivery, while a distinct onion still routes.
//!
//! Mirrors the engine-wrapper idiom of `tagging.rs`, but the wrapper only *records* forwarded cells (so a
//! real captured onion can be replayed via `Sim::inject_frame`) — it never tampers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::{Arc, Mutex};

use fanos_aphantos::node::ANONYMOUS;
use fanos_aphantos::{Directory, NyxNode};
use fanos_field::F7;
use fanos_geometry::{Plane, Point, Triple};
use fanos_pqcrypto::{HybridKemSecret, SeedRng};
use fanos_runtime::{Command, Duration, Effect, Engine, Input, Instant};
use fanos_sim::Sim;
use fanos_wire::{FrameType, decode_frame};

const CLIENT: usize = 0;
const SERVICE: usize = 40;

/// A log of captured forwarded onion cells: `(from = the recording relay, to = the next hop, frame)`.
type ForwardLog = Arc<Mutex<Vec<(Triple, Triple, Vec<u8>)>>>;

/// A relay that records every onion (`Tessera`) cell it forwards — `(from = self, to, frame)` — so a test
/// can replay a genuine captured cell. Its own routing is the honest `NyxNode`.
struct RecordingRelay {
    node: NyxNode<F7>,
    log: ForwardLog,
}

impl Engine for RecordingRelay {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let effects = self.node.step(now, input);
        let me = self.node.address();
        for effect in &effects {
            if let Effect::Send { to, frame } = effect
                && is_tessera(frame)
            {
                self.log.lock().unwrap().push((me, *to, frame.clone()));
            }
        }
        effects
    }
    fn address(&self) -> Triple {
        self.node.address()
    }
}

fn is_tessera(frame: &[u8]) -> bool {
    decode_frame(frame).map(|(f, _)| f.frame_type()) == Ok(Some(FrameType::Tessera))
}

/// Spawn a `PG(2,7)` cell of `NyxNode`s; interior relays record their forwards, the client/service are
/// honest endpoints.
fn spawn_cell(sim: &mut Sim, log: &ForwardLog) -> Vec<Triple> {
    let points: Vec<Point<F7>> = Plane::<F7>::points().collect();
    let mut directory = Directory::new();
    let mut secrets = Vec::with_capacity(points.len());
    for (i, point) in points.iter().enumerate() {
        let mut rng = SeedRng::from_seed(&[0x5A, i as u8]);
        let (secret, public) = HybridKemSecret::generate(&mut rng);
        directory.insert(point.coords(), public);
        secrets.push(secret);
    }
    let mut coords = Vec::with_capacity(points.len());
    for (i, (point, secret)) in points.iter().zip(secrets).enumerate() {
        let node = NyxNode::new(*point, secret, directory.clone(), [i as u8; 32], [0u8; 32], 3);
        let engine: Box<dyn Engine> = if i == CLIENT || i == SERVICE {
            Box::new(node)
        } else {
            Box::new(RecordingRelay { node, log: log.clone() })
        };
        coords.push(sim.add(engine));
    }
    coords
}

fn delivered(sim: &Sim, service: Triple, payload: &[u8]) -> bool {
    sim.report()
        .deliveries()
        .any(|(recv, from, bytes)| recv == service && from == ANONYMOUS && bytes == payload)
}

#[test]
fn a_replayed_onion_cell_is_dropped_over_the_running_mixnet() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut sim = Sim::new(0x00C9);
    let cell = spawn_cell(&mut sim, &log);

    // Route a real onion: it delivers once, and interior relays record their forwards.
    let payload = b"confirm-me".to_vec();
    sim.inject(
        cell[CLIENT],
        Command::Send {
            to: cell[SERVICE],
            payload: payload.clone(),
        },
    );
    sim.run_for(Duration::from_millis(4000));
    assert!(delivered(&sim, cell[SERVICE], &payload), "the onion delivers once (control)");

    // Capture one genuine forwarded onion cell (a relay → its next hop).
    let (from, to, frame) = log
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("an interior relay forwarded an onion cell");
    assert!(is_tessera(&frame), "the captured cell is a real onion");

    // Replay it to the hop that already received it: that hop's replay cache must drop it, so no second
    // delivery follows — the adversary learns nothing about the circuit from the re-injection.
    sim.clear_report();
    sim.inject_frame(from, to, frame);
    sim.run_for(Duration::from_millis(4000));
    assert!(
        !delivered(&sim, cell[SERVICE], &payload),
        "the replayed onion is dropped by the per-relay replay cache — no path confirmation"
    );

    // Control: a DISTINCT onion still routes and delivers — the relays are live, the drop was replay-specific.
    let fresh = b"a fresh onion".to_vec();
    sim.inject(
        cell[CLIENT],
        Command::Send {
            to: cell[SERVICE],
            payload: fresh.clone(),
        },
    );
    sim.run_for(Duration::from_millis(4000));
    assert!(
        delivered(&sim, cell[SERVICE], &fresh),
        "a distinct onion still delivers — the relays remain live"
    );
}
