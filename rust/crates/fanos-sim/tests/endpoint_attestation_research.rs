//! **§6.4 endpoint cross-attestation — simulator research harness (#106).**
//!
//! The §6.4 closure (catch a *consistent* liar the mediator model cannot) is a complex mechanism, so per
//! the simulation-driven directive it is RESEARCHED here — not derived-then-wired. This file builds the
//! high-level research affordance the search needs: a **configurable Byzantine gossiper** that forges its
//! own outbound `DiagGossip` health-view to a chosen false liveness view, and a **recorder** that captures
//! every node's actually-gossiped view. From those captured views a candidate detection rule can be
//! evaluated offline against the two metrics that decide it — the FALSE-POSITIVE rate on honest churn and
//! the DETECTION rate on the attack — so the optimal rule is *found*, not guessed. (The naive rule —
//! majority-vote the polar vectors `ρ` reconstructed from raw views — was reverted precisely because
//! honest nodes' asymmetric views make it false-positive; see the gap-map memory.)
//!
//! This module lands the affordance + its self-test; the FP/detection sweep and the rule search build on it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::{Arc, Mutex};

use fanos_field::F2;
use fanos_geometry::fano;
use fanos_runtime::{Command, Config, Duration, Effect, Engine, Input, Instant, OverlayNode, Triple};
use fanos_sim::Sim;
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// A node's claimed liveness view: the 7 per-point ages it gossips (`u16::MAX` = "I do not see this
/// point"). This IS the raw material of the §6.4 endpoint cross-attestation — what a node *asserts* about
/// who is alive, honest or forged.
type ClaimedView = [u16; 7];

/// The freshest health-view each node has gossiped, keyed by its coordinate — the research instrument's
/// capture buffer. Shared so a wrapper on every node writes into it and the test reads it after a run.
type ViewLog = Arc<Mutex<std::collections::BTreeMap<Triple, ClaimedView>>>;

/// Decode a `DiagGossip` body (7 little-endian `u16` ages) into a [`ClaimedView`]; `None` if it is not a
/// well-formed health-view.
fn decode_view(body: &[u8]) -> Option<ClaimedView> {
    if body.len() < 14 {
        return None;
    }
    Some(core::array::from_fn(|i| {
        u16::from_le_bytes([body[i * 2], body[i * 2 + 1]])
    }))
}

/// Encode a [`ClaimedView`] back into a `DiagGossip` frame body.
fn encode_view(view: &ClaimedView) -> Vec<u8> {
    let mut body = Vec::with_capacity(14);
    for age in view {
        body.extend_from_slice(&age.to_le_bytes());
    }
    body
}

/// The research adversary: a fully-live real [`OverlayNode`] whose only deviation is that each outbound
/// `DiagGossip` health-view is rewritten by a **policy** into a chosen false view. Everything else — pings,
/// pongs, `DiagAttest`, storage, routing — is honest, so the forgery is a pure liveness *lie*, exactly the
/// input the §6.4 endpoint check must adjudicate. The policy is `Fn(honest_view) -> forged_view`, so a
/// scenario can express any lie (claim a live node down, claim a dead node up, see nobody, …).
struct ByzantineGossiper {
    node: OverlayNode<F2>,
    policy: Arc<dyn Fn(ClaimedView) -> ClaimedView + Send + Sync>,
    forged: Arc<std::sync::atomic::AtomicUsize>,
}

impl Engine for ByzantineGossiper {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let effects = self.node.step(now, input);
        effects
            .into_iter()
            .map(|e| self.forge_gossip(e))
            .collect()
    }

    fn address(&self) -> Triple {
        self.node.address()
    }
}

impl ByzantineGossiper {
    fn forge_gossip(&self, effect: Effect) -> Effect {
        let Effect::Send { to, frame } = &effect else {
            return effect;
        };
        let Ok((f, _)) = decode_frame(frame) else {
            return effect;
        };
        if f.frame_type() != Some(FrameType::DiagGossip) {
            return effect;
        }
        let Some(view) = decode_view(f.body) else {
            return effect;
        };
        let forged_view = (self.policy)(view);
        self.forged.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut out = Vec::new();
        encode_frame(FrameType::DiagGossip.code(), &encode_view(&forged_view), &mut out);
        Effect::Send { to: *to, frame: out }
    }
}

/// A transparent wrapper that RECORDS every `DiagGossip` view its inner engine emits into a shared
/// [`ViewLog`] — the research instrument's capture point — then passes the effect through unchanged. Wrapped
/// around BOTH honest nodes and the adversary, so the log holds each node's actually-gossiped (honest or
/// forged) claimed view, the raw data a candidate detection rule is evaluated on.
struct Recorder {
    inner: Box<dyn Engine>,
    log: ViewLog,
}

impl Engine for Recorder {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let effects = self.inner.step(now, input);
        let me = self.inner.address();
        for e in &effects {
            if let Effect::Send { frame, .. } = e
                && let Ok((f, _)) = decode_frame(frame)
                && f.frame_type() == Some(FrameType::DiagGossip)
                && let Some(view) = decode_view(f.body)
            {
                self.log.lock().unwrap().insert(me, view);
            }
        }
        effects
    }

    fn address(&self) -> Triple {
        self.inner.address()
    }
}

/// The Fano point index of a coordinate (`0..7`).
fn point_index(coord: Triple) -> usize {
    (0..7).find(|&i| fano::point(i).coords() == coord).unwrap()
}

#[test]
fn the_byzantine_gossiper_affordance_forges_the_health_view_it_gossips() {
    // Validate the research instrument itself: a `ByzantineGossiper` configured to always claim point 5 is
    // DOWN (age → u16::MAX) actually gossips that lie — the recorder captures a forged view whose slot 5 is
    // u16::MAX — while it stays otherwise live. Without a working affordance, no §6.4 research is trustworthy.
    let log: ViewLog = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let forged = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let liar = 3usize;
    let policy: Arc<dyn Fn(ClaimedView) -> ClaimedView + Send + Sync> = Arc::new(|mut v: ClaimedView| {
        v[5] = u16::MAX; // "I do not see point 5" — a liveness lie about a node that is in fact alive
        v
    });

    let mut sim = Sim::new(0x6E_D400);
    for i in 0..7usize {
        let inner: Box<dyn Engine> = if i == liar {
            Box::new(ByzantineGossiper {
                node: OverlayNode::<F2>::new(fano::point(i), Config::default()),
                policy: policy.clone(),
                forged: forged.clone(),
            })
        } else {
            Box::new(OverlayNode::<F2>::new(fano::point(i), Config::default()))
        };
        sim.add(Box::new(Recorder { inner, log: log.clone() }));
    }
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(3000)); // several gossip rounds

    let captured = log.lock().unwrap();
    // The adversary genuinely emitted forged gossip during the run (not a vacuous pass).
    assert!(
        forged.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "the gossiper forged at least one health-view"
    );
    // The liar's OWN captured view carries the lie: it claims not to see point 5.
    let liar_view = captured
        .iter()
        .find(|(c, _)| point_index(**c) == liar)
        .map(|(_, v)| *v)
        .expect("the liar's gossip was recorded");
    assert_eq!(
        liar_view[5],
        u16::MAX,
        "the forged view asserts point 5 is unseen (the configured lie)"
    );
    // An honest node's captured view does NOT carry the lie — it sees point 5 (a fresh, finite age), so the
    // affordance forges ONLY the adversary, giving a clean honest/forged contrast for the rule search.
    let honest_view = captured
        .iter()
        .find(|(c, _)| point_index(**c) != liar)
        .map(|(_, v)| *v)
        .expect("an honest node's gossip was recorded");
    assert!(
        honest_view[5] != u16::MAX,
        "an honest node still sees point 5 — only the adversary forges"
    );
}
