//! **C8 — active tagging / tamper-and-trace over the RUNNING mixnet.** A relay on a circuit flips bits in
//! a forwarded onion cell hoping to *mark* the flow and recognise it downstream (linking the circuit's in
//! and out sides). FANOS's per-hop ChaCha20-Poly1305 AEAD must defeat this: any tamper fails the tag at
//! the very next hop and the cell is dropped, so a tagged flow never completes — the marker never travels.
//!
//! This was proven crate-locally (`aphantos/tests/onion_tamper.rs`: 0 surviving tags over every core
//! byte-flip); here it is driven over the real routed `NyxNode` mixnet. A control run delivers the onion;
//! with every interior relay tampering each cell it forwards, the onion is AEAD-rejected downstream and
//! never reaches the destination. Mirrors the engine-wrapper idiom of `byzantine_equivocation.rs`.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fanos_aphantos::node::ANONYMOUS;
use fanos_aphantos::{Directory, NyxNode};
use fanos_field::F7;
use fanos_geometry::{Plane, Point, Triple};
use fanos_pqcrypto::{HybridKemSecret, SeedRng};
use fanos_runtime::{Command, Duration, Effect, Engine, Input, Instant};
use fanos_sim::Sim;
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// The client (originator) and service (destination) Fano points — kept honest so the tampering is
/// genuinely a *relay* corrupting a *forwarded* cell, not the endpoints.
const CLIENT: usize = 0;
const SERVICE: usize = 40;

/// A relay that flips a byte in every onion (`Tessera`) cell it forwards — an active tag-and-trace
/// attacker. Its own logic is the honest `NyxNode`; only the outbound onion frame is corrupted.
struct TaggingRelay {
    node: NyxNode<F7>,
    tagged: Arc<AtomicUsize>,
}

impl Engine for TaggingRelay {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let tagged = &self.tagged;
        self.node.step(now, input).into_iter().map(|e| tag_onion(e, tagged)).collect()
    }
    fn address(&self) -> Triple {
        self.node.address()
    }
}

/// If `effect` is an outbound `Tessera` onion, flip a byte deep in its body (an AEAD-protected layer);
/// every other effect passes through. Counts each tag so the test proves the attack really happened.
fn tag_onion(effect: Effect, tagged: &Arc<AtomicUsize>) -> Effect {
    let Effect::Send { to, frame } = &effect else {
        return effect;
    };
    let Ok((f, _)) = decode_frame(frame) else {
        return effect;
    };
    if f.frame_type() != Some(FrameType::Tessera) {
        return effect;
    }
    let mut body = f.body.to_vec();
    // Flip bytes near the FRONT of the onion: the body begins with the AEAD ciphertext (authenticated),
    // while the constant-size Sphinx padding — the only unauthenticated bytes — is the TAIL and is
    // regenerated per hop, so a tail flip is erased. A front flip fails the next hop's Poly1305 tag.
    let mut hit = false;
    for off in [2usize, 4, 6, 8, 10] {
        if let Some(b) = body.get_mut(off) {
            *b ^= 0xFF;
            hit = true;
        }
    }
    if !hit {
        return effect;
    }
    tagged.fetch_add(1, Ordering::Relaxed);
    let mut out = Vec::new();
    encode_frame(FrameType::Tessera.code(), &body, &mut out);
    Effect::Send { to: *to, frame: out }
}

/// Spawn a `PG(2,7)` cell of `NyxNode`s. With `tagger` set, every interior relay (not the client or
/// service) is wrapped as a [`TaggingRelay`]; otherwise the cell is all-honest. Deterministic secrets and
/// seeds, so the honest and tagging runs route the *same* circuit — an apples-to-apples comparison.
fn spawn_cell(sim: &mut Sim, path_len: usize, tagger: Option<&Arc<AtomicUsize>>) -> Vec<Triple> {
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
        let node = NyxNode::new(*point, secret, directory.clone(), [i as u8; 32], [0u8; 32], path_len);
        let engine: Box<dyn Engine> = match tagger {
            Some(counter) if i != CLIENT && i != SERVICE => {
                Box::new(TaggingRelay { node, tagged: counter.clone() })
            }
            _ => Box::new(node),
        };
        coords.push(sim.add(engine));
    }
    coords
}

/// Whether `service` received `payload` anonymously this run.
fn delivered(sim: &Sim, service: Triple, payload: &[u8]) -> bool {
    sim.report()
        .deliveries()
        .any(|(recv, from, bytes)| recv == service && from == ANONYMOUS && bytes == payload)
}

#[test]
fn per_hop_aead_drops_a_tagged_onion_so_tagging_cannot_trace_a_flow() {
    let payload = b"trace-me".to_vec();

    // Control: an all-honest mixnet routes and delivers the onion.
    let mut honest = Sim::new(0x7A6);
    let cell = spawn_cell(&mut honest, 3, None);
    honest.inject(cell[CLIENT], Command::Send { to: cell[SERVICE], payload: payload.clone() });
    honest.run_for(Duration::from_millis(4000));
    assert!(
        delivered(&honest, cell[SERVICE], &payload),
        "control: an honest mixnet delivers the onion (else the attack test proves nothing)"
    );

    // Attack: every interior relay tags (flips a byte of) each onion it forwards. The tampered cell fails
    // the next hop's per-hop AEAD and is dropped, so the marker never travels and nothing reaches the
    // service — tagging cannot link the circuit's in and out sides.
    let tagged = Arc::new(AtomicUsize::new(0));
    let mut sim = Sim::new(0x7A6);
    let cell = spawn_cell(&mut sim, 3, Some(&tagged));
    sim.inject(cell[CLIENT], Command::Send { to: cell[SERVICE], payload: payload.clone() });
    sim.run_for(Duration::from_millis(4000));

    assert!(
        tagged.load(Ordering::Relaxed) >= 1,
        "an interior relay must actually have tampered ≥1 forwarded onion"
    );
    assert!(
        !delivered(&sim, cell[SERVICE], &payload),
        "the tampered onion is AEAD-rejected downstream and never reaches the service"
    );
}
