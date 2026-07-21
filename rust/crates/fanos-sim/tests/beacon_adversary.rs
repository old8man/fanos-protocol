//! **Beacon integrity under an active anchor adversary (B1/E5).** The epoch beacon is the root of
//! unpredictability — coordinates, rendezvous lines, and PROTEUS bridges all fold its seed — so an anchor
//! that forges or withholds its threshold partial is the most fundamental attack surface. The primitive's
//! guarantees are unit-proven (`fanos-vrf::beacon`: a wrong partial fails its DLEQ; `σ = x·M` is
//! subset-independent, so nothing to grind). This drives them over the **running** beacon cell: a live
//! `BeaconNode` anchor is wrapped to (a) broadcast a partial with a **biased `σ`** — an attempt to steer
//! the output — or (b) stay **silent**. In both cases the honest majority must converge on exactly the
//! seed an all-honest cell produces.
//!
//! Mirrors the engine-wrapper idiom of `byzantine_equivocation.rs`: a real node with exactly its outbound
//! beacon frames intercepted, not its own logic changed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_keygen::BeaconNode;
use fanos_runtime::{Command, Duration, Effect, Engine, Input, Instant, Notification, Triple};
use fanos_sim::Sim;
use fanos_vrf::vss::{DeterministicRng, VssCommitment, VssShare, deal};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// Beacon threshold (`t`-of-7 anchors), matching `beacon_node_e2e.rs`.
const BEACON_T: usize = 4;

/// A `BEACON_T`-of-7 sharing standing for a completed DKG (its networked realisation is proven in
/// fanos-keygen). Deterministic, so every cell below shares the same group key.
fn beacon_group() -> (Vec<VssShare>, VssCommitment) {
    deal(&[0xBE; 32], BEACON_T, 7, &mut DeterministicRng::new(b"e2e-beacon")).unwrap()
}

/// The single seed a cell agreed on this run (from the `BeaconReady` notifications), or `None` if the
/// announcing nodes disagreed — the property the adversary must not be able to break.
fn agreed_seed(sim: &Sim) -> Option<[u8; 32]> {
    let seeds: BTreeSet<[u8; 32]> = sim
        .report()
        .notifications
        .iter()
        .filter_map(|o| match &o.note {
            Notification::BeaconReady { seed, .. } => Some(*seed),
            _ => None,
        })
        .collect();
    match seeds.len() {
        1 => seeds.into_iter().next(),
        _ => None,
    }
}

/// Run a beacon cell built by `make` (a per-index engine factory) for one epoch and return the seed the
/// cell agreed on.
fn run_cell(seed: u64, make: impl Fn(usize, &VssShare, &VssCommitment) -> Box<dyn Engine>) -> Option<[u8; 32]> {
    let (shares, commitment) = beacon_group();
    let mut sim = Sim::new(seed);
    for (i, share) in shares.iter().enumerate() {
        sim.add(make(i, share, &commitment));
    }
    sim.inject_all(&Command::AdvanceEpoch);
    sim.run_for(Duration::from_millis(2000));
    agreed_seed(&sim)
}

/// An honest anchor engine.
fn honest(i: usize, share: &VssShare, commitment: &VssCommitment) -> Box<dyn Engine> {
    Box::new(BeaconNode::<F2>::new(Point::at(i), Some(share.clone()), commitment.clone(), BEACON_T))
}

/// The all-honest reference seed the adversarial cells must reproduce.
fn reference_seed() -> [u8; 32] {
    run_cell(0xB2C0, honest).expect("an all-honest cell agrees on a seed")
}

// ---- Adversary 1: a forging anchor (biased σ) ------------------------------------------------------

/// A live anchor that corrupts its own outbound `BeaconPartial` — a byte inside `σ`, so it broadcasts a
/// *biased* beacon value while its DLEQ proof still commits to the real one. `verify_partial` must reject
/// it before it reaches any combiner.
struct ForgingAnchor {
    node: BeaconNode<F2>,
    forged: Arc<AtomicUsize>,
}

impl Engine for ForgingAnchor {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let forged = &self.forged;
        self.node.step(now, input).into_iter().map(|e| forge_partial(e, forged)).collect()
    }
    fn address(&self) -> Triple {
        self.node.address()
    }
}

/// If `effect` is an outbound `BeaconPartial`, flip a byte inside its `σ` field (frame body layout
/// `epoch(8) ‖ index(1) ‖ σ(32) ‖ challenge(32) ‖ response(32)`, so `σ` starts at offset 9). Everything
/// else passes through. Counts each forgery so the test proves the attack actually happened.
fn forge_partial(effect: Effect, forged: &Arc<AtomicUsize>) -> Effect {
    let Effect::Send { to, frame } = &effect else {
        return effect;
    };
    let Ok((f, _)) = decode_frame(frame) else {
        return effect;
    };
    if f.frame_type() != Some(FrameType::BeaconPartial) {
        return effect;
    }
    let mut body = f.body.to_vec();
    let Some(b) = body.get_mut(20) else {
        return effect; // offset 20 ∈ σ (9..41)
    };
    *b ^= 0xFF;
    forged.fetch_add(1, Ordering::Relaxed);
    let mut out = Vec::new();
    encode_frame(FrameType::BeaconPartial.code(), &body, &mut out);
    Effect::Send { to: *to, frame: out }
}

// ---- Adversary 2: a silent anchor (withholds) ------------------------------------------------------

/// A live anchor that contributes **nothing** to the beacon — it drops both its `BeaconPartial` and any
/// `Beacon` round it would flood, modelling a crashed/lazy/withholding anchor. The remaining anchors must
/// still reach threshold and agree.
struct SilentAnchor {
    node: BeaconNode<F2>,
    dropped: Arc<AtomicUsize>,
}

impl Engine for SilentAnchor {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let dropped = &self.dropped;
        self.node.step(now, input).into_iter().filter(|e| !is_beacon_frame(e, dropped)).collect()
    }
    fn address(&self) -> Triple {
        self.node.address()
    }
}

/// Whether `effect` is an outbound beacon contribution (a `BeaconPartial` or a flooded `Beacon` round);
/// counts each so the test proves the anchor really was silent.
fn is_beacon_frame(effect: &Effect, dropped: &Arc<AtomicUsize>) -> bool {
    let Effect::Send { frame, .. } = effect else {
        return false;
    };
    let Ok((f, _)) = decode_frame(frame) else {
        return false;
    };
    if matches!(f.frame_type(), Some(FrameType::BeaconPartial | FrameType::Beacon)) {
        dropped.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}

// ---- Tests -----------------------------------------------------------------------------------------

#[test]
fn a_forged_partial_cannot_bias_the_beacon() {
    let reference = reference_seed();
    let forged = Arc::new(AtomicUsize::new(0));
    let liar = 3usize;
    let counter = forged.clone();
    let seed = run_cell(0xB2C0, move |i, share, commitment| {
        if i == liar {
            Box::new(ForgingAnchor {
                node: BeaconNode::<F2>::new(Point::at(i), Some(share.clone()), commitment.clone(), BEACON_T),
                forged: counter.clone(),
            })
        } else {
            honest(i, share, commitment)
        }
    });

    assert!(
        forged.load(Ordering::Relaxed) >= 1,
        "the forger must actually have corrupted ≥1 partial (else the test proves nothing)"
    );
    let seed = seed.expect("the honest majority still agrees on ONE seed despite the biased partial");
    assert_eq!(
        seed, reference,
        "a forged/biased partial is DLEQ-rejected and cannot steer the output — same seed as all-honest"
    );
}

#[test]
fn a_silent_anchor_does_not_block_the_beacon() {
    let reference = reference_seed();
    let dropped = Arc::new(AtomicUsize::new(0));
    let absent = 5usize;
    let counter = dropped.clone();
    let seed = run_cell(0xB2C0, move |i, share, commitment| {
        if i == absent {
            Box::new(SilentAnchor {
                node: BeaconNode::<F2>::new(Point::at(i), Some(share.clone()), commitment.clone(), BEACON_T),
                dropped: counter.clone(),
            })
        } else {
            honest(i, share, commitment)
        }
    });

    assert!(
        dropped.load(Ordering::Relaxed) >= 1,
        "the silent anchor must actually have withheld ≥1 beacon frame"
    );
    let seed = seed.expect("the remaining anchors still reach threshold and agree");
    assert_eq!(
        seed, reference,
        "a missing anchor does not change the output — threshold liveness + subset-independence (σ = x·M)"
    );
}
