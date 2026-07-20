//! **L3.3 — the Sybil admission gate defeats a joiner with no per-admission cost.**
//!
//! `sybil_cost.rs` (this same test suite) derives that self-certifying coordinates alone bound a
//! grinding adversary only *polynomially*: capturing even a cell **majority** by coordinate
//! grinding costs just `Θ(N·log N)` hashes (its own doc-comment, lines 78-84 — "Sybil resistance
//! must come from a per-admission cost; the geometry only sets the multiplier"). Until now the
//! live engine had no such cost at all: `Command::Join` simply floods an announce, and every
//! `on_announce` accepted it (`fanos-runtime/src/overlay.rs`). This exercises the fix on the real
//! engine — not a formula: a peer announcing without a valid PoW proof is rejected (never added
//! to `members`, and told `SYBIL_REJECT`, spec §7.5 code 202), while a peer presenting a solved
//! proof is admitted exactly as before.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fanos_core::PowAdmission;
use fanos_field::{F2, Field};
use fanos_geometry::Point;
use fanos_runtime::overlay::admission_challenge;
use fanos_runtime::{
    Command, Config, Duration, Effect, Engine, Epoch, Input, Instant, Notification, OverlayNode,
    Triple,
};
use fanos_sim::Sim;
use fanos_wire::{FrameType, ProtocolError, decode_frame};

/// A modest difficulty: real work (not a no-op), cheap enough that `cargo test` solves it in
/// microseconds. The gate's *correctness*, not the PoW's real-world cost calibration, is what
/// this file exercises (`fanos_core::admission`'s own tests already cover the hashcash primitive).
const DIFFICULTY: u32 = 8;

/// Two Fano-cell (`q=2`, `N=7`) points are always direct peers — `OverlayNode::new` derives every
/// other point as a peer on the base cell (`overlay.rs`'s own
/// `node_derives_all_cell_neighbours_algebraically` test confirms all 6) — so a receiver at point
/// 0 and a joiner at point 1 need no relay: one hop suffices.
const RECEIVER_POINT: usize = 0;
const JOINER_POINT: usize = 1;

/// Wraps a real `OverlayNode`, transparently passing every effect through while recording the
/// two outcomes this file distinguishes: did it ever notify `MemberJoined`, and did it ever send
/// a `SYBIL_REJECT` error. Unlike `withholding.rs`'s `ByzantineWithholder`, this **observes**
/// rather than tampers — the node under test behaves exactly as the live engine does.
struct AdmissionObserver<F: Field> {
    node: OverlayNode<F>,
    joined: Arc<AtomicUsize>,
    sybil_rejected: Arc<AtomicUsize>,
}

impl<F: Field> Engine for AdmissionObserver<F> {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let effects = self.node.step(now, input);
        for effect in &effects {
            match effect {
                Effect::Notify(Notification::MemberJoined { .. }) => {
                    self.joined.fetch_add(1, Ordering::Relaxed);
                }
                Effect::Send { frame, .. } if is_sybil_reject(frame) => {
                    self.sybil_rejected.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
        effects
    }

    fn address(&self) -> Triple {
        self.node.address()
    }
}

/// Whether `frame` is an `Error` frame carrying exactly the `SYBIL_REJECT` code: a frame-type
/// check, then the body's leading 8 bytes, big-endian, are the `ProtocolError` code
/// (`fanos-runtime/src/overlay.rs`'s `ErrorBody`/`encode_error` — `code(8B BE) ‖ reason`; a
/// `#[derive(Wire)]` `u64` field is a fixed-width big-endian integer, not a varint — see that
/// struct's doc comment).
fn is_sybil_reject(frame: &[u8]) -> bool {
    let Ok((f, _)) = decode_frame(frame) else {
        return false;
    };
    if f.frame_type() != Some(FrameType::Error) {
        return false;
    }
    let Some(code_bytes) = f.body.get(..8).and_then(|b| <[u8; 8]>::try_from(b).ok()) else {
        return false;
    };
    u64::from_be_bytes(code_bytes) == ProtocolError::SybilReject.code()
}

/// Spawn an admission-observed receiver at [`RECEIVER_POINT`] and `joiner` at [`JOINER_POINT`],
/// returning `(sim, joiner_coord, joined, sybil_rejected)` — the receiver's own coordinate is
/// never needed by a caller, only its observed counters. The receiver always carries a
/// [`PowAdmission`] policy at [`DIFFICULTY`]: harmless when `receiver_config.require_admission`
/// is `false` (the gate is skipped entirely — see `admission_is_opt_in_a_default_config_admits_
/// without_any_proof`), and required for the gate to do anything but fail closed when it's `true`.
fn spawn_pair(
    seed: u64,
    receiver_config: Config,
    joiner: OverlayNode<F2>,
) -> (Sim, Triple, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let mut sim = Sim::new(seed);
    let joined = Arc::new(AtomicUsize::new(0));
    let sybil_rejected = Arc::new(AtomicUsize::new(0));
    let receiver = OverlayNode::<F2>::new(Point::at(RECEIVER_POINT), receiver_config)
        .with_admission_policy(Box::new(PowAdmission::new(DIFFICULTY)));
    sim.add(Box::new(AdmissionObserver {
        node: receiver,
        joined: joined.clone(),
        sybil_rejected: sybil_rejected.clone(),
    }));
    let joiner_coord = sim.add(Box::new(joiner));
    (sim, joiner_coord, joined, sybil_rejected)
}

#[test]
fn a_joiner_without_a_valid_pow_proof_is_rejected_and_told_sybil_reject() {
    let receiver_config = Config {
        require_admission: true,
        ..Config::default()
    };
    // No `.with_admission_proof(..)`: the joiner presents no proof at all (the empty default) —
    // the shape of an adversary that has not paid the admission cost. A joiner never needs its
    // own `admission_policy` (that's for *verifying* others, spec §L3) — only the receiver does.
    let joiner = OverlayNode::<F2>::new(Point::at(JOINER_POINT), Config::default());
    let (mut sim, joiner_coord, joined, sybil_rejected) = spawn_pair(1, receiver_config, joiner);

    sim.inject(
        joiner_coord,
        Command::Join {
            info: b"sybil".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));

    assert_eq!(
        joined.load(Ordering::Relaxed),
        0,
        "no MemberJoined — a proof-less joiner is never admitted"
    );
    assert!(
        sybil_rejected.load(Ordering::Relaxed) >= 1,
        "the receiver sent at least one SYBIL_REJECT — the rejection is genuine, not vacuous"
    );

    // Control: a retried proof-less join is rejected again, not silently admitted the second
    // time — proving the first attempt truly never entered `members` (an already-admitted
    // member's *repeat* announce is dropped without a re-flood or a re-reject, per
    // `announce_validates_coords_and_never_overwrites_a_member` in overlay.rs; seeing a SECOND
    // reject here rules out that this was instead a silent, harmless duplicate-admit).
    sim.inject(
        joiner_coord,
        Command::Join {
            info: b"sybil-retry".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));
    assert!(
        sybil_rejected.load(Ordering::Relaxed) >= 2,
        "a retried proof-less join is rejected again — it was never admitted the first time"
    );
}

#[test]
fn a_joiner_with_a_valid_pow_proof_is_admitted_normally() {
    let receiver_config = Config {
        require_admission: true,
        ..Config::default()
    };
    let joiner_coord = Point::<F2>::at(JOINER_POINT).coords();
    // Solve the SAME challenge `on_announce` will re-derive: (the joiner's own coordinate, epoch
    // 0 — neither node advances the epoch in this test).
    let proof =
        PowAdmission::new(DIFFICULTY).solve(&admission_challenge(joiner_coord, Epoch::ZERO));
    let joiner = OverlayNode::<F2>::new(Point::at(JOINER_POINT), Config::default())
        .with_admission_proof(proof);
    let (mut sim, joiner_coord, joined, sybil_rejected) = spawn_pair(2, receiver_config, joiner);

    sim.inject(
        joiner_coord,
        Command::Join {
            info: b"honest".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));

    assert!(
        joined.load(Ordering::Relaxed) >= 1,
        "a joiner with a valid PoW proof is admitted (MemberJoined fires)"
    );
    assert_eq!(
        sybil_rejected.load(Ordering::Relaxed),
        0,
        "a valid proof is never told SYBIL_REJECT"
    );
}

#[test]
fn admission_is_opt_in_a_default_config_admits_without_any_proof() {
    // Backward compatibility: `require_admission` defaults to `false`, so an ordinary Join with
    // no proof at all — every existing test's shape — still admits normally.
    let joiner = OverlayNode::<F2>::new(Point::at(JOINER_POINT), Config::default());
    let (mut sim, joiner_coord, joined, sybil_rejected) = spawn_pair(3, Config::default(), joiner);

    sim.inject(
        joiner_coord,
        Command::Join {
            info: b"legacy".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(500));

    assert!(
        joined.load(Ordering::Relaxed) >= 1,
        "with admission not required, a proof-less join still admits (default behaviour unchanged)"
    );
    assert_eq!(sybil_rejected.load(Ordering::Relaxed), 0);
}
