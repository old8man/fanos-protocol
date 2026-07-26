//! Threshold-onion routing end to end over the overlay (spec §5.2, §5.7): "a hop is a line". A
//! client seals a nested threshold onion over a circuit of hop *lines*; the `ThresholdRouter` nodes
//! then route it **autonomously** — each hop's combiner gathers a threshold `t` of partial
//! decryptions from the line's members through the overlay, peels, and forwards to the next line's
//! combiner, until delivery. No node peels a hop alone, and below `t` cooperating members a hop
//! cannot be peeled at all.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::collections as alloc_set;

use fanos_aphantos::ThresholdRouter;
use fanos_aphantos::threshold::{HopLine, seal_onion};
use fanos_aphantos::threshold_router::{ANONYMOUS, combiner_for, launch_frame, line_member_coords};
use fanos_field::{F2, F7};
use fanos_geometry::{Line, Plane, Point, Triple};
use fanos_pqcrypto::{HybridKemPublic, HybridKemSecret, OnionKeyRatchet, SeedRng};
use fanos_rendezvous::Epoch;
use fanos_runtime::{Command, Duration};
use fanos_sim::Sim;

/// Spawn a `ThresholdRouter` at every Fano point (threshold `t`), returning the public-key directory
/// so the test can seal onions to the line members.
fn spawn_routers(sim: &mut Sim, t: usize) -> BTreeMap<Triple, HybridKemPublic> {
    spawn_routers_with(sim, t, Duration::from_millis(0))
}

/// As [`spawn_routers`], with a Poisson mixing mean delay on each router.
fn spawn_routers_with(
    sim: &mut Sim,
    t: usize,
    mean_delay: Duration,
) -> BTreeMap<Triple, HybridKemPublic> {
    let mut pubs = BTreeMap::new();
    for i in 0..7 {
        let point = Point::<F2>::at(i);
        let mut rng = SeedRng::from_seed(&[0xA0, i as u8]);
        let (secret, _identity) = HybridKemSecret::generate(&mut rng);
        // Seal onions to each relay's forward-secure ONION public (audit E4); the relay peels with the
        // onion secret from the same genesis seed.
        let mut onion_seed = [0xC5u8; 32];
        onion_seed[31] = i as u8;
        let onion_public = OnionKeyRatchet::new(onion_seed, Epoch::ZERO)
            .public()
            .clone();
        pubs.insert(point.coords(), onion_public);
        sim.add(Box::new(
            ThresholdRouter::<F2>::new(point, &secret, t, onion_seed).with_mixing(mean_delay),
        ));
    }
    pubs
}

/// Build a threshold onion over `hop_lines` carrying `payload`, threshold `t`, using the directory.
fn build_onion(
    hop_lines: &[Triple],
    t: u8,
    payload: &[u8],
    pubs: &BTreeMap<Triple, HybridKemPublic>,
) -> Vec<u8> {
    // Per hop, the member public keys in canonical `points_on` (seal) order.
    let member_vecs: Vec<Vec<&HybridKemPublic>> = hop_lines
        .iter()
        .map(|&line| {
            line_member_coords::<F2>(line)
                .iter()
                .map(|c| pubs.get(c).unwrap())
                .collect()
        })
        .collect();
    let hops: Vec<HopLine<'_>> = hop_lines
        .iter()
        .zip(&member_vecs)
        .map(|(&line, members)| HopLine { line, members })
        .collect();
    seal_onion(&hops, t, payload, b"threshold-route-seed").unwrap()
}

#[test]
fn a_threshold_onion_routes_autonomously_and_delivers() {
    let mut sim = Sim::new(0x7A1);
    let t = 2u8; // 2-of-3 per Fano line
    let pubs = spawn_routers(&mut sim, usize::from(t));

    // A 2-hop circuit over two distinct Fano lines.
    let hop_lines = vec![Line::<F2>::at(0).coords(), Line::<F2>::at(3).coords()];
    let payload = b"threshold-routed hello";
    let onion = build_onion(&hop_lines, t, payload, &pubs);

    // Launch: send the first-hop onion to the first line's combiner.
    let combiner = combiner_for::<F2>(hop_lines[0]).unwrap();
    let source = Point::<F2>::at(6).coords();
    sim.inject_frame(source, combiner, launch_frame(hop_lines[0], &onion));
    sim.run_for(Duration::from_millis(2000));

    // The payload is delivered (anonymously) at the last hop's combiner.
    let delivered = sim
        .report()
        .deliveries()
        .find(|(_, from, bytes)| *from == ANONYMOUS && *bytes == payload);
    assert!(
        delivered.is_some(),
        "the threshold onion routes through both line-hops and delivers the payload"
    );
}

#[test]
fn a_threshold_onion_still_delivers_with_poisson_mixing() {
    // With per-hop mixing enabled the onion is held for a sampled delay at each forward, reordering
    // the flow — but it still reaches the destination once the delays elapse.
    let mut sim = Sim::new(0x7A4);
    let t = 2u8;
    let pubs = spawn_routers_with(&mut sim, usize::from(t), Duration::from_millis(50));

    let hop_lines = vec![Line::<F2>::at(0).coords(), Line::<F2>::at(3).coords()];
    let payload = b"mixed threshold hello";
    let onion = build_onion(&hop_lines, t, payload, &pubs);

    let combiner = combiner_for::<F2>(hop_lines[0]).unwrap();
    sim.inject_frame(
        Point::<F2>::at(6).coords(),
        combiner,
        launch_frame(hop_lines[0], &onion),
    );
    sim.run_for(Duration::from_millis(4000)); // room for the sampled mix delays

    assert!(
        sim.report()
            .deliveries()
            .any(|(_, from, bytes)| from == ANONYMOUS && bytes == payload),
        "the mixed threshold onion still delivers once the mix delays elapse"
    );
}

#[test]
fn a_single_hop_threshold_onion_delivers() {
    let mut sim = Sim::new(0x7A2);
    let t = 2u8;
    let pubs = spawn_routers(&mut sim, usize::from(t));

    let hop_lines = vec![Line::<F2>::at(2).coords()];
    let payload = b"one hop, one line";
    let onion = build_onion(&hop_lines, t, payload, &pubs);

    let combiner = combiner_for::<F2>(hop_lines[0]).unwrap();
    sim.inject_frame(
        Point::<F2>::at(0).coords(),
        combiner,
        launch_frame(hop_lines[0], &onion),
    );
    sim.run_for(Duration::from_millis(1500));

    assert!(
        sim.report()
            .deliveries()
            .any(|(_, from, bytes)| from == ANONYMOUS && bytes == payload),
        "a single-line threshold hop delivers once its combiner gathers t partials"
    );
}

#[test]
fn below_threshold_the_hop_cannot_be_peeled_and_nothing_is_delivered() {
    // With only one live member per line but a threshold of 3, no combiner can ever gather enough
    // partials, so nothing is delivered — the line, not a node, is the unit of trust.
    let mut sim = Sim::new(0x7A3);
    let t = 3u8; // needs all 3 members of a Fano line
    let pubs = spawn_routers(&mut sim, usize::from(t));

    let hop_lines = vec![Line::<F2>::at(1).coords()];
    let payload = b"should never arrive";
    let onion = build_onion(&hop_lines, t, payload, &pubs);

    // Crash two of the three line members, leaving fewer than the threshold able to reply.
    let members = line_member_coords::<F2>(hop_lines[0]);
    sim.crash(members[1]);
    sim.crash(members[2]);

    let combiner = combiner_for::<F2>(hop_lines[0]).unwrap(); // members[0], still alive
    sim.inject_frame(
        Point::<F2>::at(4).coords(),
        combiner,
        launch_frame(hop_lines[0], &onion),
    );
    sim.run_for(Duration::from_millis(3000));

    assert!(
        !sim.report()
            .deliveries()
            .any(|(_, from, bytes)| from == ANONYMOUS && bytes == payload),
        "below threshold the hop cannot be peeled — nothing is delivered"
    );
}

/// **The GPA timing channel on the SHIPPING engine.**
///
/// `traffic_analysis.rs` measures this on `NyxNode` — the *Lite* profile. But `fanos_node`'s `DEFAULT_MIX_DELAY` /
/// `DEFAULT_COVER_INTERVAL` feed **`ThresholdRouter`**, the Full profile the node actually builds, and audit E6 records
/// that the two differ on exactly this mechanism: constant-rate displacement was done on `ThresholdRouter` while "the Lite
/// `NyxNode` path remains additive". So the flagship "strong against a GPA" claim had a timing measurement on the *weaker*
/// engine and none on the shipping one.
///
/// ## ⚠️ THE METRIC BELOW IS INVALID — kept as a worked counter-example
///
/// It reports `r = 0.975` for the shipping configuration against `1.000` undefended, which reads as "no defence". **It is
/// not a valid test**, for two reasons that took three revisions to see:
///
/// 1. **It penalises conservation.** A relay neither drops nor manufactures real cells, so over a window much longer than
///    the mix delay, cells-out must equal cells-in. Maximising the correlation over the adversary's bin width therefore
///    drives it toward 1 for *any* finite delay. An **ideal** independent-exponential mix at mean 50 ms also leaves
///    `r ≈ 0.71` at 100 ms bins — so the number measures the mean and the conservation law, not the implementation.
/// 2. **One flow is an anonymity set of one.** This harness pushes a single flow through the cell and asks whether it is
///    visible. It necessarily is. Anonymity is whether an adversary can *match* inputs to outputs among **concurrent**
///    flows; a one-flow experiment deletes the confusion that cover and mixing exist to create.
///
/// The valid experiment is a **linkability** measurement over several simultaneous flows — how much better than chance the
/// adversary matches them — and it has **not** been run. This is left in place, `#[ignore]`d and labelled, because a
/// deleted mistake teaches nothing and someone will otherwise re-derive the same metric and reach the same wrong
/// conclusion. The generalisable rule: **a metric an ideal implementation also fails is measuring the physics, not the
/// implementation** — check the ideal reference before reporting a defect.
#[test]
#[ignore = "INVALID METRIC — kept as a worked counter-example, see the note above. Run with --ignored --nocapture"]
fn measure_gpa_timing_on_the_shipping_router() {
    const SPAN_MS: u64 = 10_000;
    const MIN_BINS: u64 = 30;

    let run = |mix: Duration, cover: Duration| -> f64 {
        let mut sim = Sim::new(0x9C1);
        let mut pubs = BTreeMap::new();
        for i in 0..7 {
            let point = Point::<F2>::at(i);
            let mut rng = SeedRng::from_seed(&[0xA0, i as u8]);
            let (secret, _identity) = HybridKemSecret::generate(&mut rng);
            let mut onion_seed = [0xC5u8; 32];
            onion_seed[31] = i as u8;
            pubs.insert(point.coords(), OnionKeyRatchet::new(onion_seed, Epoch::ZERO).public().clone());
            let mut r = ThresholdRouter::<F2>::new(point, &secret, 2, onion_seed).with_mixing(mix);
            if cover.as_nanos() > 0 {
                r = r.with_cover(cover);
            }
            sim.add(Box::new(r));
        }
        if cover.as_nanos() > 0 {
            sim.inject_all(&Command::StartHeartbeat);
        }
        sim.observe_frames();

        // A bursty flow through the cell — bursts are what a timing attack keys on.
        let hop_lines: Vec<Triple> = vec![Line::<F2>::at(0).coords(), Line::<F2>::at(1).coords()];
        for round in 0..8u64 {
            for _ in 0..5 {
                let onion = build_onion(&hop_lines, 2, b"burst", &pubs);
                let Some(entry) = combiner_for::<F2>(hop_lines[0]) else { continue };
                sim.inject(entry, Command::Emit { to: entry, frame: launch_frame(hop_lines[0], &onion) });
            }
            sim.run_for(Duration::from_millis(if round % 2 == 0 { 100 } else { 900 }));
        }
        sim.run_for(Duration::from_millis(2_000));

        let obs = sim.observed_frames();
        let mut worst = 0.0f64;
        for bin in [25u64, 50, 100, 250, 500].into_iter().filter(|b| SPAN_MS / b >= MIN_BINS) {
            let span = obs.iter().map(|o| o.t_ms).max().unwrap_or(0) / bin + 1;
            // EXCLUDE the entry combiner: it is the injection point, and `Command::Emit` is a RAW launch that bypasses
            // the constant-rate outbox by design (it is the client's launch primitive, not a relay forward). Its
            // emissions therefore track the injection schedule by construction — including it measures my own test
            // harness, not the defence. `traffic_analysis.rs` excludes endpoints for the same reason: endpoint exposure
            // is the acknowledged §8.1 residual (`P_link = P_hop²`), and cover defends the INTERIOR hops.
            let entry = combiner_for::<F2>(hop_lines[0]);
            for i in 0..7 {
                let relay = Point::<F2>::at(i).coords();
                if Some(relay) == entry {
                    continue;
                }
                let mut ins = vec![0f64; span as usize];
                let mut outs = vec![0f64; span as usize];
                for o in obs {
                    let b = (o.t_ms / bin) as usize;
                    if o.to == relay && let Some(v) = ins.get_mut(b) { *v += 1.0 }
                    if o.from == relay && let Some(v) = outs.get_mut(b) { *v += 1.0 }
                }
                worst = worst.max(pearson(&ins, &outs).abs());
            }
        }
        worst
    };

    // Sanity FIRST: is cover actually emitting in this harness? A schedule that emits nothing would read as
    // "undefended" at any parameter, and reporting that as a finding about the defence would be measuring my own setup.
    let volume = |mix: Duration, cover: Duration| -> usize {
        let mut sim = Sim::new(0x9C2);
        for i in 0..7 {
            let point = Point::<F2>::at(i);
            let mut rng = SeedRng::from_seed(&[0xA0, i as u8]);
            let (secret, _identity) = HybridKemSecret::generate(&mut rng);
            let mut onion_seed = [0xC5u8; 32];
            onion_seed[31] = i as u8;
            let mut r = ThresholdRouter::<F2>::new(point, &secret, 2, onion_seed).with_mixing(mix);
            if cover.as_nanos() > 0 {
                r = r.with_cover(cover);
            }
            sim.add(Box::new(r));
        }
        if cover.as_nanos() > 0 {
            sim.inject_all(&Command::StartHeartbeat);
        }
        sim.observe_frames();
        sim.run_for(Duration::from_millis(SPAN_MS));
        sim.observed_frames().len()
    };
    let idle_bare = volume(Duration::from_millis(0), Duration::from_millis(0));
    let idle_cover = volume(Duration::from_millis(50), Duration::from_millis(1_000));
    println!("idle frames over {SPAN_MS} ms — no cover {idle_bare}, cover 1000ms {idle_cover}");
    assert!(
        idle_cover > idle_bare + 20,
        "cover must genuinely emit in this harness, else the correlation below measures an undefended relay at any \
         parameter (bare {idle_bare}, with cover {idle_cover})"
    );

    println!("ThresholdRouter (the SHIPPING engine) — GPA in/out rate correlation:");
    println!("  no defence                       r = {:.3}", run(Duration::from_millis(0), Duration::from_millis(0)));
    println!("  SHIPPING (mix 50ms, cover 1000ms) r = {:.3}", run(Duration::from_millis(50), Duration::from_millis(1_000)));
    println!("  aggressive (mix 120ms, cover 150ms) r = {:.3}", run(Duration::from_millis(120), Duration::from_millis(150)));
}

/// Pearson correlation; `0.0` when either series is constant.
fn pearson(a: &[f64], b: &[f64]) -> f64 {
    let n = a.len().min(b.len()) as f64;
    if n < 2.0 {
        return 0.0;
    }
    let (ma, mb) = (a.iter().sum::<f64>() / n, b.iter().sum::<f64>() / n);
    let mut num = 0.0;
    let (mut da, mut db) = (0.0, 0.0);
    for (x, y) in a.iter().zip(b.iter()) {
        num += (x - ma) * (y - mb);
        da += (x - ma).powi(2);
        db += (y - mb).powi(2);
    }
    if da <= f64::EPSILON || db <= f64::EPSILON {
        return 0.0;
    }
    num / (da.sqrt() * db.sqrt())
}

// ── Linkability on the SHIPPING engine ──────────────────────────────────────────────────────────────────────────────
//
// The named follow-up from `traffic_analysis.rs`, which measured the valid metric on `NyxNode` (Lite) for want of a
// large-enough router harness. `ThresholdRouter` is generic over the field, so `PG(2,7)` gives the same 57 points and the
// same room for five concurrent flows — and this is the engine `fanos_node` actually builds.

/// A `PG(2,7)` cell of `ThresholdRouter`s with the given schedule, plus the onion-public directory.
fn spawn_f7_routers(
    sim: &mut Sim,
    mix: Duration,
    cover: Duration,
) -> BTreeMap<Triple, HybridKemPublic> {
    let mut pubs = BTreeMap::new();
    let n = Plane::<F7>::points().count();
    for i in 0..n {
        let point = Point::<F7>::at(i);
        let mut rng = SeedRng::from_seed(&[0xB7, i as u8]);
        let (secret, _identity) = HybridKemSecret::generate(&mut rng);
        let mut onion_seed = [0xD7u8; 32];
        onion_seed[31] = i as u8;
        pubs.insert(point.coords(), OnionKeyRatchet::new(onion_seed, Epoch::ZERO).public().clone());
        let mut r = ThresholdRouter::<F7>::new(point, &secret, 2, onion_seed).with_mixing(mix);
        if cover.as_nanos() > 0 {
            r = r.with_cover(cover);
        }
        sim.add(Box::new(r));
    }
    pubs
}

/// Seal an onion over `PG(2,7)` hop lines.
fn build_onion_f7(hop_lines: &[Triple], t: u8, payload: &[u8], pubs: &BTreeMap<Triple, HybridKemPublic>) -> Vec<u8> {
    let member_vecs: Vec<Vec<&HybridKemPublic>> = hop_lines
        .iter()
        .map(|&line| line_member_coords::<F7>(line).iter().filter_map(|c| pubs.get(c)).collect())
        .collect();
    let hops: Vec<HopLine<'_>> = hop_lines
        .iter()
        .zip(&member_vecs)
        .map(|(&line, members)| HopLine { line, members })
        .collect();
    seal_onion(&hops, t, payload, b"f7-linkability-seed").unwrap()
}

/// The adversary's flow-matching accuracy over `K` concurrent circuits on the shipping engine, averaged over seeds.
fn linkability_shipping(mix: Duration, cover: Duration, runs: u64) -> (f64, f64) {
    const K: usize = 5;
    const BIN_MS: u64 = 200;
    const SPAN_MS: u64 = 8_000;
    let mut total = 0.0;
    for seed in 0..runs {
        let mut sim = Sim::new(0xF71 + seed);
        let pubs = spawn_f7_routers(&mut sim, mix, cover);
        if cover.as_nanos() > 0 {
            sim.inject_all(&Command::StartHeartbeat);
        }
        sim.observe_frames();

        // K circuits whose entry AND exit combiners are all DISTINCT. Taking lines by index does not give this: any two
        // lines of a projective plane meet in exactly one point, so line-derived combiners collide — measured, the naive
        // choice gave 10 endpoint slots over only 7 distinct points, with one circuit's entry being another's exit. That
        // makes matching meaningless and produced a 0.00 accuracy even undefended, which is how the harness announced it
        // was broken rather than the engine.
        let mut used: alloc_set::BTreeSet<Triple> = alloc_set::BTreeSet::new();
        let mut lines: Vec<Triple> = Vec::new();
        for i in 0..Plane::<F7>::points().count() {
            let line = Line::<F7>::at(i).coords();
            if let Some(c) = combiner_for::<F7>(line)
                && used.insert(c)
            {
                lines.push(line);
            }
            if lines.len() == 2 * K {
                break;
            }
        }
        assert!(lines.len() == 2 * K, "need {} lines with distinct combiners, found {}", 2 * K, lines.len());
        let circuits: Vec<(Triple, Triple)> =
            (0..K).filter_map(|i| Some((*lines.get(i)?, *lines.get(i + K)?))).collect();
        let mut round = 0u64;
        let mut t = 0u64;
        while t < SPAN_MS {
            for (i, (entry_line, exit_line)) in circuits.iter().enumerate() {
                if round.is_multiple_of(i as u64 + 1)
                    && let Some(entry) = combiner_for::<F7>(*entry_line)
                {
                    let onion = build_onion_f7(&[*entry_line, *exit_line], 2, b"flow", &pubs);
                    sim.inject(entry, Command::Emit { to: entry, frame: launch_frame(*entry_line, &onion) });
                }
            }
            sim.run_for(Duration::from_millis(200));
            t += 200;
            round += 1;
        }
        sim.run_for(Duration::from_millis(2_000));

        // Score (entry combiner emissions) against (exit combiner receipts) — the endpoints of each circuit.
        let obs = sim.observed_frames();
        let bins = (SPAN_MS / BIN_MS) as usize + 12;
        let series = |node: Triple, out: bool| -> Vec<f64> {
            let mut v = vec![0f64; bins];
            for o in obs.iter().filter(|o| if out { o.from == node } else { o.to == node }) {
                if let Some(sl) = v.get_mut((o.t_ms / BIN_MS) as usize) {
                    *sl += 1.0;
                }
            }
            v
        };
        let ins: Vec<Vec<f64>> = circuits
            .iter()
            .filter_map(|(e, _)| combiner_for::<F7>(*e).map(|c| series(c, true)))
            .collect();
        let outs: Vec<Vec<f64>> = circuits
            .iter()
            .filter_map(|(_, x)| combiner_for::<F7>(*x).map(|c| series(c, false)))
            .collect();
        let mut pairs: Vec<(f64, usize, usize)> = Vec::new();
        for (i, a) in ins.iter().enumerate() {
            for (j, b) in outs.iter().enumerate() {
                pairs.push((pearson(a, b).abs(), i, j));
            }
        }
        pairs.sort_by(|a, b| b.0.total_cmp(&a.0));
        let (mut ti, mut tj) = ([false; K], [false; K]);
        let mut correct = 0usize;
        for (_, i, j) in pairs {
            if !ti[i] && !tj[j] {
                ti[i] = true;
                tj[j] = true;
                if i == j {
                    correct += 1;
                }
            }
        }
        total += correct as f64 / K as f64;
    }
    (total / runs as f64, 1.0 / K as f64)
}

/// Confirm the knee with enough seeds to change a shipping default on.
///
/// With `K = 5` each mis-matched circuit moves the mean by `0.2/runs`, so 8 runs resolve to 0.025 — fine for locating a
/// knee, not enough to justify moving a security constant. This re-measures the two candidate points at 24 runs.
#[test]
#[ignore = "confirmation, not an assertion — run with --ignored --nocapture"]
fn confirm_the_knee_with_enough_seeds_to_move_a_default() {
    for (name, mix, cover) in [("current default 50/1000", 50u64, 1_000u64), ("candidate     120/500", 120, 500)] {
        let (a, chance) = linkability_shipping(Duration::from_millis(mix), Duration::from_millis(cover), 24);
        println!("  {name} -> matching accuracy {a:.3}  (chance {chance:.2})");
    }
}

/// Where is the KNEE of the anonymity/cost curve on the shipping engine?
///
/// The defaults sit at 0.33 against a 0.20 floor and a heavy schedule reaches chance — but heavy costs 10× the cover
/// bandwidth and 10× the added latency. If an intermediate schedule reaches chance, the default is simply mis-set; if the
/// curve is smooth all the way, it is a genuine trade and belongs to the operator. Measuring rather than assuming which.
#[test]
#[ignore = "sweep, not an assertion — run with --ignored --nocapture"]
fn sweep_the_shipping_engine_for_the_anonymity_cost_knee() {
    println!("ThresholdRouter, PG(2,7), 5 circuits, chance 0.20 — mix/cover -> matching accuracy:");
    for (mix, cover) in [(50u64, 1_000u64), (120, 500), (120, 300), (250, 300), (250, 150), (500, 150), (500, 100)] {
        let (a, _) = linkability_shipping(Duration::from_millis(mix), Duration::from_millis(cover), 8);
        // Relative cost against the defaults: cover bandwidth scales as 1000/cover, latency as mix/50.
        let bw = 1_000.0 / cover as f64;
        let lat = mix as f64 / 50.0;
        println!("  mix {mix:>4} / cover {cover:>5} -> {a:.2}   (cover bandwidth ×{bw:.1}, added latency ×{lat:.1})");
    }
}

#[test]
#[ignore = "measurement, not an assertion — run with --ignored --nocapture"]
fn measure_linkability_on_the_shipping_engine() {
    let (undefended, chance) = linkability_shipping(Duration::from_millis(0), Duration::from_millis(0), 8);
    let (shipped, _) = linkability_shipping(Duration::from_millis(50), Duration::from_millis(1_000), 8);
    let (heavy, _) = linkability_shipping(Duration::from_millis(500), Duration::from_millis(100), 8);
    // Diagnose FIRST, and keep it: an undefended baseline at or below chance means the harness carried nothing, and the
    // adversary cannot match circuits that never traversed. This check is what caught the endpoint collision that made the
    // first version of this measurement read 0.00 — i.e. perfect anonymity — when in fact nothing was being measured.
    {
        let mut sim = Sim::new(0xF7D);
        let pubs = spawn_f7_routers(&mut sim, Duration::from_millis(0), Duration::from_millis(0));
        sim.observe_frames();
        let entry_line = Line::<F7>::at(0).coords();
        let exit_line = Line::<F7>::at(5).coords();
        let entry = combiner_for::<F7>(entry_line);
        let exit = combiner_for::<F7>(exit_line);
        let onion = build_onion_f7(&[entry_line, exit_line], 2, b"probe", &pubs);
        if let Some(e) = entry {
            sim.inject(e, Command::Emit { to: e, frame: launch_frame(entry_line, &onion) });
        }
        sim.run_for(Duration::from_millis(3_000));
        let obs = sim.observed_frames();
        let at_exit = obs.iter().filter(|o| Some(o.to) == exit).count();
        println!(
            "harness check — total frames {}, frames reaching the exit combiner {} (entry {:?}, exit {:?})",
            obs.len(),
            at_exit,
            entry,
            exit
        );
    }

    println!("ThresholdRouter (SHIPPING engine), PG(2,7), 5 circuits, chance {chance:.2}:");
    println!("  no defence                        {undefended:.2}");
    println!("  SHIPPING (mix 50ms, cover 1000ms) {shipped:.2}");
    println!("  heavy    (mix 500ms, cover 100ms) {heavy:.2}");
    assert!(
        undefended > chance + 0.3,
        "the undefended baseline must be attackable, or this measures nothing (got {undefended:.2}, chance {chance:.2})"
    );
    assert!(shipped < undefended - 0.3, "the shipping schedule must materially reduce matching (got {shipped:.2})");
    assert!(heavy <= shipped, "a heavier schedule must not be worse (heavy {heavy:.2}, shipping {shipped:.2})");
}
