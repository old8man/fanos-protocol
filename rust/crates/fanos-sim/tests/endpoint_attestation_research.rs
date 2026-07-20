//! **§6.4 endpoint cross-attestation — simulator research harness (#106).**
//!
//! The §6.4 closure (catch the *colluding* liars the plain corroboration quorum cannot) is a complex
//! mechanism, so per the simulation-driven directive it is RESEARCHED here — not derived-then-wired. This
//! file builds the high-level research affordances the search needs — a **configurable Byzantine gossiper**
//! that forges its own outbound `DiagGossip` health-view, and a **recorder** that captures every node's
//! actually-gossiped view as a time series — then *measures* candidate detection rules against the two
//! metrics that decide them: the FALSE-POSITIVE rate on honest churn+loss and the DETECTION rate on the
//! attack. The optimal rule is thereby *found on the instrument*, not guessed.
//!
//! **What the instrument reveals (the load-bearing finding).** The naive rule — reconstruct the polar
//! degradation vector `ρ` from raw views and majority-vote — false-positives (it was reverted for exactly
//! this) because `ρ` is a *symmetric magnitude*: it collapses two fundamentally different claims a node can
//! make about a peer `k`:
//!   - **VOUCH** (`age(k) < τ`): a positive, checkable assertion — "I received a fresh pong from `k`." A node's
//!     reported age is *monotone between real pongs* ([`OverlayNode::health_view`] reads `peers[k].last_seen`,
//!     set only by a genuine `Pong`), so an honest node **cannot fabricate freshness** for a node it did not
//!     hear from.
//!   - **DENY** (`age(k) ≥ τ` or `u16::MAX`): the *absence* of an assertion — honest under any lost ping or cut
//!     link, regardless of `k`'s true state.
//!
//! So the only *soundly attributable* lie is a **VOUCH that a firm consensus denies** — keeping a dead node
//! believed-alive to suppress its healing (the third-order fault the plain quorum, which merely *counts*
//! vouchers and so is defeated by `quorum` colluders, cannot catch). The reverse (DENY a live node) is
//! indistinguishable from honest link failure — and already inert, since every node trusts its *own* direct
//! observation over any gossip. This module lands the affordances + the sweep that *verifies* this rule beats
//! the naive one (0 false positives on churn, full detection of colluders), and pins its two parameters
//! (persistence window `W`, firm-consensus threshold `q`). The verified rule is then wired on the diakrisis
//! side as `polar`'s directional fabrication detector.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_range_loop
)]

use std::sync::{Arc, Mutex};

use fanos_field::F2;
use fanos_geometry::fano;
use fanos_runtime::{
    Command, Config, Duration, Effect, Engine, Input, Instant, Notification, OverlayNode, Triple,
};
use fanos_sim::{NetworkModel, Sim};
use fanos_wire::{FrameType, decode_frame, encode_frame};

/// The Fano cell size.
const N: usize = 7;

/// A node's claimed liveness view: the 7 per-point ages it gossips, in milliseconds (`u16::MAX` = "I have no
/// fresh observation of this point"). This IS the raw material of the §6.4 endpoint cross-attestation — what a
/// node *asserts* about who is alive, honest or forged. Byte-for-byte the body of a real `DiagGossip` frame
/// (see [`OverlayNode::health_view`]).
type ClaimedView = [u16; N];

/// A single recorded gossip emission: `(sim-time in ns, emitter coordinate, the view it gossiped)`. The log is
/// time-ordered (the sim dispatches events in nondecreasing time), so any snapshot is a forward scan.
type ViewEvent = (u64, Triple, ClaimedView);

/// The research instrument's capture buffer: every `DiagGossip` view every node emitted, in time order.
/// Shared so a wrapper on each node appends to it and the analysis reads it after a run.
type ViewLog = Arc<Mutex<Vec<ViewEvent>>>;

/// A per-round fresh/stale matrix reconstructed from captured gossip: `fresh[i][k]` = observer `i` gossiped a
/// *fresh* (`age < τ`) view of point `k`; `present[i]` = `i` had gossiped at all by that time. This is the
/// domain the detection rules operate on.
type FreshMatrix = ([[bool; N]; N], [bool; N]);

/// Decode a `DiagGossip` body (7 little-endian `u16` ages) into a [`ClaimedView`]; `None` if malformed.
fn decode_view(body: &[u8]) -> Option<ClaimedView> {
    if body.len() < N * 2 {
        return None;
    }
    Some(core::array::from_fn(|i| {
        u16::from_le_bytes([body[i * 2], body[i * 2 + 1]])
    }))
}

/// Encode a [`ClaimedView`] back into a `DiagGossip` frame body.
fn encode_view(view: &ClaimedView) -> Vec<u8> {
    let mut body = Vec::with_capacity(N * 2);
    for age in view {
        body.extend_from_slice(&age.to_le_bytes());
    }
    body
}

/// The research adversary: a fully-live real [`OverlayNode`] whose only deviation is that each outbound
/// `DiagGossip` health-view is rewritten by a **policy** into a chosen false view. Everything else — pings,
/// pongs, `DiagAttest`, storage, routing — is honest, so the forgery is a pure liveness *lie*, exactly the
/// input the §6.4 endpoint check must adjudicate. The policy is `Fn(honest_view) -> forged_view`, so a
/// scenario can express any lie (vouch for a dead node, deny a live one, see nobody, …).
struct ByzantineGossiper {
    node: OverlayNode<F2>,
    policy: Arc<dyn Fn(ClaimedView) -> ClaimedView + Send + Sync>,
    forged: Arc<std::sync::atomic::AtomicUsize>,
}

impl Engine for ByzantineGossiper {
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect> {
        let effects = self.node.step(now, input);
        effects.into_iter().map(|e| self.forge_gossip(e)).collect()
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
        self.forged
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut out = Vec::new();
        encode_frame(
            FrameType::DiagGossip.code(),
            &encode_view(&forged_view),
            &mut out,
        );
        Effect::Send {
            to: *to,
            frame: out,
        }
    }
}

/// A **vouch-fabrication** policy: always claim point `k` seen 1 ms ago (`age → 1`), so the adversary keeps a
/// (crashed) `k` believed-alive — the dangerous lie the plain quorum cannot catch beyond `quorum−1` colluders.
fn vouch_fresh(k: usize) -> Arc<dyn Fn(ClaimedView) -> ClaimedView + Send + Sync> {
    Arc::new(move |mut v: ClaimedView| {
        v[k] = 1;
        v
    })
}

/// A **denial** policy: always claim point `k` unseen (`age → u16::MAX`), the honest-omission-shaped lie that
/// the endpoint check must (soundly) *abstain* on — it is indistinguishable from a cut link and already inert.
fn deny_point(k: usize) -> Arc<dyn Fn(ClaimedView) -> ClaimedView + Send + Sync> {
    Arc::new(move |mut v: ClaimedView| {
        v[k] = u16::MAX;
        v
    })
}

/// A transparent wrapper that RECORDS every `DiagGossip` view its inner engine emits into a shared time-ordered
/// [`ViewLog`] — the research instrument's capture point — then passes the effect through unchanged. Wrapped
/// around BOTH honest nodes and adversaries, so the log holds each node's actually-gossiped (honest or forged)
/// claimed view, the raw data a candidate rule is evaluated on.
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
                self.log.lock().unwrap().push((now.as_nanos(), me, view));
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
    (0..N).find(|&i| fano::point(i).coords() == coord).unwrap()
}

/// The protocol's own staleness window τ (`liveness_timeout`), in ms — a peer unheard-from longer than this is
/// degraded ([`Config`]). The fresh/stale split uses THIS, never a magic threshold.
fn tau_ms() -> u16 {
    (Config::default().liveness_timeout.as_nanos() / 1_000_000).min(u64::from(u16::MAX)) as u16
}

/// The freshest view each node had gossiped as of `t_ns`, indexed by Fano point (`None` = not yet gossiped).
fn snapshot_at(log: &[ViewEvent], t_ns: u64) -> [Option<ClaimedView>; N] {
    let mut snap: [Option<ClaimedView>; N] = [None; N];
    for &(ts, emitter, view) in log {
        if ts <= t_ns {
            snap[point_index(emitter)] = Some(view);
        }
    }
    snap
}

/// Reduce a snapshot to the fresh/stale matrix the detection rules read: `fresh[i][k]` iff `i` gossiped
/// `age(k) < τ`. `u16::MAX` (unseen) is stale by construction.
fn fresh_matrix(snap: &[Option<ClaimedView>; N], tau: u16) -> FreshMatrix {
    let mut fresh = [[false; N]; N];
    let mut present = [false; N];
    for i in 0..N {
        if let Some(view) = snap[i] {
            present[i] = true;
            for k in 0..N {
                fresh[i][k] = view[k] < tau;
            }
        }
    }
    (fresh, present)
}

/// Sample the run at `count` snapshots spaced `step_ms` apart, ending at `end_ns` — the persistence window the
/// windowed rule reasons over.
fn window(
    log: &[ViewEvent],
    end_ns: u64,
    count: usize,
    step_ms: u64,
    tau: u16,
) -> Vec<FreshMatrix> {
    let step_ns = step_ms * 1_000_000;
    (0..count)
        .rev()
        .map(|back| {
            let t = end_ns.saturating_sub(back as u64 * step_ns);
            fresh_matrix(&snapshot_at(log, t), tau)
        })
        .collect()
}

/// **Rule NAIVE** (the reverted approach, distilled): on a single snapshot, flag `i` if for some subject `k` its
/// fresh/stale bit contradicts the *strict majority* of the other present nodes — in **either** direction. This
/// is the symmetric ρ-majority: it treats an honest DENY (lost ping / cut link) as a lie, so it false-positives
/// on churn. Kept as the baseline the sound rule must beat.
fn naive_flags(m: &FreshMatrix) -> Vec<usize> {
    let (fresh, present) = m;
    let mut flagged = Vec::new();
    for i in 0..N {
        if !present[i] {
            continue;
        }
        for k in 0..N {
            if k == i {
                continue;
            }
            let mut agree = 0i32;
            let mut disagree = 0i32;
            for j in 0..N {
                if j == i || j == k || !present[j] {
                    continue;
                }
                if fresh[j][k] == fresh[i][k] {
                    agree += 1;
                } else {
                    disagree += 1;
                }
            }
            if disagree > agree {
                flagged.push(i);
                break;
            }
        }
    }
    flagged
}

/// **Rule FABRICATION** (the found rule): flag `i` iff there is a subject `k` such that, *persistently across
/// the whole window*, `i` VOUCHES `k` fresh while a FIRM consensus (`≥ q` of the other present nodes) reports
/// `k` STALE. Only this VOUCH-vs-firm-STALE direction is judged — the sound, monotone-freshness-grounded
/// asymmetry. Persistence filters churn transients; firmness `q` tolerates up to `q−1` colluders on the honest
/// side of the count while still catching any minority of fabricators the plain quorum lets through.
fn fabrication_flags(win: &[FreshMatrix], q: usize) -> Vec<usize> {
    let mut flagged = Vec::new();
    for i in 0..N {
        let caught = (0..N).filter(|&k| k != i).any(|k| {
            win.iter().all(|(fresh, present)| {
                if !present[i] || !fresh[i][k] {
                    return false; // `i` must persistently vouch `k` fresh
                }
                let firm_stale = (0..N)
                    .filter(|&j| j != i && j != k && present[j] && !fresh[j][k])
                    .count();
                firm_stale >= q
            })
        });
        if caught {
            flagged.push(i);
        }
    }
    flagged
}

/// Build a 7-node Fano cell of [`Recorder`]-wrapped engines; `byz[i] = Some(policy)` makes point `i` a
/// [`ByzantineGossiper`] with that policy, `None` an honest [`OverlayNode`]. Returns the sim, the log, and the
/// shared forgery counter.
#[allow(clippy::type_complexity)]
fn build_cell(
    seed: u64,
    net: NetworkModel,
    byz: &[Option<Arc<dyn Fn(ClaimedView) -> ClaimedView + Send + Sync>>; N],
) -> (Sim, ViewLog, Arc<std::sync::atomic::AtomicUsize>) {
    let log: ViewLog = Arc::new(Mutex::new(Vec::new()));
    let forged = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut sim = Sim::with_network(seed, net);
    for i in 0..N {
        let inner: Box<dyn Engine> = match &byz[i] {
            Some(policy) => Box::new(ByzantineGossiper {
                node: OverlayNode::<F2>::new(fano::point(i), Config::default()),
                policy: policy.clone(),
                forged: forged.clone(),
            }),
            None => Box::new(OverlayNode::<F2>::new(fano::point(i), Config::default())),
        };
        sim.add(Box::new(Recorder {
            inner,
            log: log.clone(),
        }));
    }
    sim.inject_all(&Command::StartHeartbeat);
    (sim, log, forged)
}

const NONE_POLICY: Option<Arc<dyn Fn(ClaimedView) -> ClaimedView + Send + Sync>> = None;

// ---------------------------------------------------------------------------------------------------------
// Affordance self-test — validate the instrument before trusting any measurement taken with it.
// ---------------------------------------------------------------------------------------------------------

#[test]
fn the_byzantine_gossiper_affordance_forges_the_health_view_it_gossips() {
    // A `ByzantineGossiper` configured to always claim point 5 DOWN actually gossips that lie — the recorder
    // captures a forged view whose slot 5 is u16::MAX — while honest nodes still see point 5. Without a working
    // affordance, no §6.4 measurement is trustworthy.
    let liar = 3usize;
    let mut byz = [NONE_POLICY; N];
    byz[liar] = Some(deny_point(5));
    let net = NetworkModel::new(Duration::from_millis(10), Duration::from_millis(2), 0.0);
    let (mut sim, log, forged) = build_cell(0x6E_D400, net, &byz);
    sim.run_for(Duration::from_millis(3000));

    let log = log.lock().unwrap();
    assert!(
        forged.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "the gossiper forged at least one health-view"
    );
    let end = log.iter().map(|&(t, ..)| t).max().unwrap();
    let snap = snapshot_at(&log, end);
    assert_eq!(
        snap[liar].unwrap()[5],
        u16::MAX,
        "the forged view asserts point 5 is unseen (the configured lie)"
    );
    let honest = (0..N).find(|&i| i != liar && snap[i].is_some()).unwrap();
    assert!(
        snap[honest].unwrap()[5] != u16::MAX,
        "an honest node still sees point 5 — only the adversary forges"
    );
}

// ---------------------------------------------------------------------------------------------------------
// The FP/detection sweep — measure both rules on honest churn+loss and on the collusion attack.
// ---------------------------------------------------------------------------------------------------------

/// Persistence window and firmness pinned by this sweep (see the module finding): 5 snapshots × 400 ms spans
/// 2 s > τ, so a crash transient (nodes staling within one heartbeat of each other) cannot persist across it;
/// `q = 3` is a firm majority of the honest remainder that still catches any colluder minority.
const W: usize = 5;
const STEP_MS: u64 = 400;
const Q_FIRM: usize = 3;

/// **FALSE-POSITIVE metric.** Seven honest nodes under heavy loss (25 %) *and* a crash+recover churn of one
/// node. The sound fabrication rule must flag NOBODY across a seed sweep — an honest node cannot manufacture a
/// fresh age it did not earn — while the naive symmetric rule is shown to false-positive on the same data,
/// which is exactly why it was rejected.
#[test]
fn fabrication_rule_has_zero_false_positives_on_honest_churn() {
    let tau = tau_ms();
    let mut naive_ever_fired = false;
    for seed in 0..16u64 {
        let byz = [NONE_POLICY; N];
        let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(8), 0.25);
        let (mut sim, log, _) = build_cell(0x_A11CE ^ seed, net, &byz);
        // Honest churn: a node crashes for a spell and rejoins — every honest node stales on it *together*
        // (symmetric), so no single node stays fresh while a firm quorum is stale.
        sim.run_for(Duration::from_millis(2500));
        sim.crash(fano::point(2).coords());
        sim.run_for(Duration::from_millis(2500));
        sim.recover(fano::point(2).coords());
        sim.run_for(Duration::from_millis(4000));

        let log = log.lock().unwrap();
        let end = log.iter().map(|&(t, ..)| t).max().unwrap();
        let win = window(&log, end, W, STEP_MS, tau);
        let flagged = fabrication_flags(&win, Q_FIRM);
        assert!(
            flagged.is_empty(),
            "seed {seed}: the fabrication rule must not flag any honest node, got {flagged:?}"
        );
        // Record whether the naive rule would have mis-fired on this same honest data.
        if !naive_flags(win.last().unwrap()).is_empty() {
            naive_ever_fired = true;
        }
    }
    assert!(
        naive_ever_fired,
        "the naive symmetric rule false-positives on honest churn+loss (the reason it was rejected)"
    );
}

/// **DETECTION metric.** A dead node kept alive by *colluding* vouch-fabricators that exceed the corroboration
/// quorum (`quorum = 2`, so 2 colluders defeat the plain count). The fabrication rule catches every colluder
/// across a seed sweep — they persistently vouch a node a firm honest consensus reports stale.
#[test]
fn fabrication_rule_detects_colluding_vouch_liars() {
    let tau = tau_ms();
    let dead = 6usize; // the node the colluders keep "alive"
    let liars = [1usize, 4usize]; // two colluders — one more than the quorum tolerates
    for seed in 0..8u64 {
        let mut byz = [NONE_POLICY; N];
        for &l in &liars {
            byz[l] = Some(vouch_fresh(dead));
        }
        let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(8), 0.1);
        let (mut sim, log, forged) = build_cell(0x_DEAD ^ seed, net, &byz);
        sim.run_for(Duration::from_millis(3000));
        sim.crash(fano::point(dead).coords()); // the node truly dies; honest ages on it now grow past τ
        sim.run_for(Duration::from_millis(6000));

        assert!(forged.load(std::sync::atomic::Ordering::Relaxed) > 0);
        let log = log.lock().unwrap();
        let end = log.iter().map(|&(t, ..)| t).max().unwrap();
        let win = window(&log, end, W, STEP_MS, tau);
        let mut flagged = fabrication_flags(&win, Q_FIRM);
        flagged.sort_unstable();
        assert_eq!(
            flagged,
            liars.to_vec(),
            "seed {seed}: exactly the two colluding vouch-fabricators are caught"
        );
    }
}

/// **DIRECTIONALITY (soundness) metric.** The dual attack — colluders DENYing a *live* node — must be *abstained
/// on*: it is indistinguishable from honest link failure and already inert (every node trusts its own direct
/// observation). The fabrication rule flags nobody here; catching this direction would mean quarantining honest
/// nodes that merely have a bad link, which must never ship.
#[test]
fn fabrication_rule_abstains_on_deny_liars() {
    let tau = tau_ms();
    let victim = 6usize; // a fully-live node the liars falsely deny
    let liars = [1usize, 4usize];
    for seed in 0..8u64 {
        let mut byz = [NONE_POLICY; N];
        for &l in &liars {
            byz[l] = Some(deny_point(victim));
        }
        let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(8), 0.1);
        let (mut sim, log, forged) = build_cell(0x_FEED ^ seed, net, &byz);
        sim.run_for(Duration::from_millis(9000)); // victim stays alive throughout

        assert!(forged.load(std::sync::atomic::Ordering::Relaxed) > 0);
        let log = log.lock().unwrap();
        let end = log.iter().map(|&(t, ..)| t).max().unwrap();
        let win = window(&log, end, W, STEP_MS, tau);
        let flagged = fabrication_flags(&win, Q_FIRM);
        assert!(
            flagged.is_empty(),
            "seed {seed}: denying a live node is honest-omission-shaped — the rule must abstain, got {flagged:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------------------
// End-to-end: the found rule WIRED into the production engine (polar::fabricators_by_persistent_freshness
// driven from the live `witnessed` substrate in OverlayNode::on_diagnose). The sim exercises the real reflex.
// ---------------------------------------------------------------------------------------------------------

/// The offline sweep found the rule; here the REAL engine runs it. Two colluders keep a crashed node
/// believed-alive by vouching it fresh (exceeding `corroboration_quorum = 2`); every honest node's live §6.4
/// endpoint attestation localizes and QUARANTINES both — and never an honest node. This is full cohesion: the
/// verified primitive actuated through the production `OverlayNode`, not just in isolation.
#[test]
fn the_wired_engine_quarantines_colluding_vouch_fabricators() {
    let dead = 6usize;
    let liars = [1usize, 4usize]; // two colluders — one more than the quorum tolerates
    for seed in 0..4u64 {
        let mut byz = [NONE_POLICY; N];
        for &l in &liars {
            byz[l] = Some(vouch_fresh(dead));
        }
        let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(8), 0.05);
        let (mut sim, _log, _forged) = build_cell(0x_C0FFEE ^ seed, net, &byz);
        sim.run_for(Duration::from_millis(3000));
        sim.crash(fano::point(dead).coords()); // the node truly dies; the colluders alone keep it "alive"
        sim.run_for(Duration::from_millis(9000));

        let honest: Vec<Triple> = (0..N)
            .filter(|i| *i != dead && !liars.contains(i))
            .map(|i| fano::point(i).coords())
            .collect();

        // Both colluders are quarantined by at least one honest judge (the detection the plain quorum misses).
        for &l in &liars {
            let lc = fano::point(l).coords();
            let caught = sim.report().notifications.iter().any(|o| {
                honest.contains(&o.node)
                    && matches!(&o.note, Notification::Quarantined(c) if *c == lc)
            });
            assert!(
                caught,
                "seed {seed}: colluder {l} must be quarantined by an honest node"
            );
        }
        // The invariant that must never break: no honest node is quarantined, by ANY observer.
        let honest_hit = sim
            .report()
            .notifications
            .iter()
            .find_map(|o| match &o.note {
                Notification::Quarantined(c) if honest.contains(c) => Some((o.node, *c)),
                _ => None,
            });
        assert!(
            honest_hit.is_none(),
            "seed {seed}: an honest node was quarantined: {honest_hit:?}"
        );
    }
}

/// The live false-positive guard: seven honest nodes under heavy loss (25 %) + a crash/recover churn produce
/// NO quarantine at all — the wired detector never mistakes honest omission (a lost ping / a real death
/// everyone agrees on) for fabrication. This is the property whose *naive* violation reverted the first wiring.
#[test]
fn the_wired_engine_never_quarantines_under_honest_churn() {
    for seed in 0..8u64 {
        let byz = [NONE_POLICY; N];
        let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(8), 0.25);
        let (mut sim, _log, _forged) = build_cell(0x_B0BA ^ seed, net, &byz);
        sim.run_for(Duration::from_millis(2500));
        sim.crash(fano::point(2).coords());
        sim.run_for(Duration::from_millis(2500));
        sim.recover(fano::point(2).coords());
        sim.run_for(Duration::from_millis(4000));

        let quarantines: Vec<Triple> = sim
            .report()
            .notifications
            .iter()
            .filter_map(|o| match &o.note {
                Notification::Quarantined(c) => Some(*c),
                _ => None,
            })
            .collect();
        assert!(
            quarantines.is_empty(),
            "seed {seed}: honest churn must never quarantine, got {quarantines:?}"
        );
    }
}
