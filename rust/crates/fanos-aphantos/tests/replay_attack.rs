//! **Replay path-confirmation attack** — and the bounded replay cache that defeats it.
//!
//! An onion cell is deterministic: a relay that peels it produces the same next-hop forward every
//! time. So an on-path or nearby adversary can *capture* a cell in flight and **re-inject** it at a
//! suspected relay; if that relay forwards the same cell onward again, the adversary has confirmed the
//! relay lies on the flow's path — a classic path-confirmation / replay-trace attack (the reason Sphinx
//! and Tor carry a per-relay replay cache, and rotate relay keys). Because FANOS relays hold long-term
//! KEM keys today (audit E4), a captured cell would otherwise stay replayable indefinitely.
//!
//! The defense (`NyxNode` replay cache, keyed on [`sealed::replay_tag`]): a relay remembers a compact
//! tag of every cell it has forwarded and silently drops any recurrence, so a replay yields **no**
//! second forward and the adversary learns nothing. The cache is bounded (FIFO eviction) so a flood of
//! distinct cells cannot exhaust memory.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_aphantos::sealed::{self, ONION_LEN};
use fanos_aphantos::{Directory, NyxNode};
use fanos_field::F31;
use fanos_geometry::Point;
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, SeedRng};
use fanos_runtime::{Effect, Engine, Input, Instant};
use fanos_wire::{FrameType, encode_frame};

/// A KEM keypair from a fixed seed.
fn keypair(seed: &[u8]) -> (HybridKemSecret, HybridKemPublic) {
    let mut rng = SeedRng::from_seed(seed);
    HybridKemSecret::generate(&mut rng)
}

/// Wrap a sealed onion in the Tessera wire frame a relay receives.
fn tessera_frame(onion: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(FrameType::Tessera.code(), onion, &mut out);
    out
}

/// A 2-hop onion (first hop sealed to `relay`, second delivering to `dest`), built with `build_seed`.
fn onion(relay: &HybridKemPublic, dest: &HybridKemPublic, build_seed: &[u8]) -> Vec<u8> {
    let circuit =
        fanos_nyx::build_circuit(Point::<F31>::at(1), Point::<F31>::at(9), 2, b"replay").unwrap();
    let onion = sealed::build(&circuit, &[relay, dest], b"anonymous payload", build_seed).unwrap();
    assert_eq!(onion.len(), ONION_LEN, "a sealed cell is the constant bucket");
    onion
}

/// How many `Send` effects a step produced (a forwarded cell).
fn forwards(effects: &[Effect]) -> usize {
    effects
        .iter()
        .filter(|e| matches!(e, Effect::Send { .. }))
        .count()
}

/// The attack: capture a cell, re-inject it at the relay, and watch for a repeated forward that would
/// confirm the relay is on the path. The replay cache drops it — the confirmation channel is closed.
#[test]
fn a_replayed_cell_is_dropped_not_re_forwarded() {
    let (secret_r, public_r) = keypair(b"relay-R");
    let (_secret_d, public_d) = keypair(b"dest-D");
    let frame = tessera_frame(&onion(&public_r, &public_d, b"seed"));

    let mut relay = NyxNode::new(
        Point::<F31>::at(3),
        secret_r,
        Directory::new(),
        [1u8; 32],
        [0u8; 32],
        2,
    );
    let from = Point::<F31>::at(0).coords();

    // First receipt: the relay peels its hop and forwards to the next hop.
    let first = relay.step(Instant::default(), Input::Message { from, frame: frame.clone() });
    assert_eq!(forwards(&first), 1, "the relay forwards a fresh cell once");

    // Re-injection (the attack): the same captured cell must NOT be forwarded a second time.
    let replay = relay.step(Instant::default(), Input::Message { from, frame: frame.clone() });
    assert_eq!(
        forwards(&replay),
        0,
        "a replayed cell must be dropped — no repeated forward to confirm the path"
    );

    // The tag is remembered, not consumed: further replays stay dropped.
    let again = relay.step(Instant::default(), Input::Message { from, frame });
    assert_eq!(forwards(&again), 0, "further replays stay dropped");
}

/// The cache drops only true replays: two DISTINCT cells (fresh encapsulations → distinct tags) are
/// each forwarded, so genuine traffic is never suppressed as a false replay.
#[test]
fn distinct_cells_are_each_forwarded() {
    let (secret_r, public_r) = keypair(b"relay-R2");
    let (_sd, public_d) = keypair(b"dest-D2");
    let mut relay = NyxNode::new(
        Point::<F31>::at(3),
        secret_r,
        Directory::new(),
        [2u8; 32],
        [0u8; 32],
        2,
    );
    let from = Point::<F31>::at(0).coords();

    let onion_a = onion(&public_r, &public_d, b"seed-a");
    let onion_b = onion(&public_r, &public_d, b"seed-b");
    assert_ne!(
        sealed::replay_tag(&onion_a),
        sealed::replay_tag(&onion_b),
        "distinct cells (different encapsulation) carry distinct replay tags"
    );

    let fa = relay.step(
        Instant::default(),
        Input::Message { from, frame: tessera_frame(&onion_a) },
    );
    let fb = relay.step(
        Instant::default(),
        Input::Message { from, frame: tessera_frame(&onion_b) },
    );
    assert_eq!(forwards(&fa), 1, "the first distinct cell is forwarded");
    assert_eq!(forwards(&fb), 1, "the second distinct cell is forwarded, not dropped as a replay");
}
