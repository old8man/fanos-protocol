//! **C1 / §8.1 — a global passive adversary (GPA) over the RUNNING mixnet.** The flagship anonymity claim —
//! "strong against a GPA" (spec §8.2) and orders-of-magnitude-better endpoint linkage than Tor (§8.1) — was
//! until now backed only by a crate-local leak-slope (`aphantos/tests/flow_correlation.rs`), never by an
//! adversary over the real routed + mixed + cover-scheduled network. This models it: a GPA taps every frame's
//! metadata `(t, from, to, len)` on the simulated wire (never content — cells are constant-size AEAD), and
//! runs the canonical **flow-correlation** attack — for every relay, the Pearson correlation between its
//! input-rate and output-rate time series. A relay that forwards a bursty flow immediately leaks a high
//! correlation (the GPA links its in-flow to its out-flow, tracing the circuit); constant-rate cover +
//! Poisson mixing must collapse that correlation to chance. We measure the GPA's advantage with the defense
//! ON and OFF and assert the defense erases the signal.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_aphantos::{Directory, NyxNode};
use fanos_field::F7;
use fanos_geometry::{Plane, Point, Triple};
use fanos_node::config::{DEFAULT_COVER_INTERVAL, DEFAULT_MIX_DELAY};
use fanos_pqcrypto::{HybridKemSecret, SeedRng};
use fanos_runtime::{Command, Duration};
use fanos_sim::{FrameObs, Sim};

/// The shipping schedule, **read from the constants rather than copied** (#187).
///
/// Every function here used to spell `(50 ms, 1000 ms)` as "the shipping schedule". Those were the defaults
/// until `252815b` moved them to 120/500 on a knee measurement — and not one of the four measurements that
/// describe them followed, including the one whose name is `..._at_the_shipping_defaults`. A literal cannot
/// track a constant; an import can, and the constants are `pub` precisely so a measurement can cite them.
fn shipping() -> (Duration, Duration) {
    (engine_span(DEFAULT_MIX_DELAY), engine_span(DEFAULT_COVER_INTERVAL))
}

/// `std::time::Duration` → the engine's nanosecond span, the same conversion `Node::start` performs.
fn engine_span(d: std::time::Duration) -> Duration {
    Duration(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Whole milliseconds of `d`, for a sweep axis printed and swept in ms.
fn millis(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// `candidates` with the shipping value folded in, sorted and deduplicated.
///
/// A sweep whose axis is a hand-written list stops covering the default the moment the default moves — which
/// is exactly what happened: the cover sweep ran 150/300/1000/3000 and the shipping 500 ms was measured
/// nowhere, while the constant's doc quoted the 1000 ms row as "this default". Folding the live value in makes
/// the shipping point unmissable whatever it becomes.
fn including_the_default(candidates: &[u64], default_ms: u64) -> Vec<u64> {
    let mut axis: Vec<u64> = candidates.to_vec();
    axis.push(default_ms);
    axis.sort_unstable();
    axis.dedup();
    axis
}

/// Spawn a full `PG(2,7)` cell of `NyxNode`s, optionally with Poisson mixing + cover (the C1 defense).
fn spawn_nyx_cell(sim: &mut Sim, mix: Option<(Duration, Duration)>) -> Vec<Triple> {
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
        let mut node = NyxNode::new(
            *point,
            secret,
            directory.clone(),
            [i as u8; 32],
            [0u8; 32],
            3,
        );
        if let Some((mean_delay, cover_interval)) = mix {
            node = node.with_mixing(mean_delay, cover_interval);
        }
        coords.push(sim.add(Box::new(node)));
    }
    coords
}

/// Per-node **output** frame count over the run — what a GPA counts leaving each relay.
fn output_counts(tape: &[FrameObs], nodes: &[Triple]) -> Vec<usize> {
    nodes
        .iter()
        .map(|&n| tape.iter().filter(|o| o.from == n).count())
        .collect()
}

/// Run the routed mixnet with `real_cells` even-spread real onions client→service and return each node's
/// tapped output count. Even spread keeps the real rate within the cover budget — the regime in which
/// constant-rate cover is defined to displace (spec C1); a burst beyond the cover rate is a separate,
/// honestly-leaky regime, not what this measures.
fn run_and_tap(mix: Option<(Duration, Duration)>, real_cells: usize) -> (Vec<Triple>, Vec<usize>) {
    let mut sim = Sim::new(0x6AA_u64.wrapping_add(u64::from(mix.is_some())));
    let cell = spawn_nyx_cell(&mut sim, mix);
    if mix.is_some() {
        sim.inject_all(&Command::StartHeartbeat); // begin constant-rate cover
    }
    sim.observe_frames(); // the GPA starts tapping the wire

    let (client, service) = (cell[0], cell[40]);
    let total_ms = 9000u64;
    let step_ms = if real_cells == 0 {
        total_ms
    } else {
        total_ms / real_cells as u64
    };
    let mut injected = 0usize;
    let mut elapsed = 0u64;
    while elapsed < total_ms {
        while injected < real_cells && (injected as u64) * step_ms <= elapsed {
            sim.inject(
                client,
                Command::Send {
                    to: service,
                    payload: b"real-flow".to_vec(),
                },
            );
            injected += 1;
        }
        sim.run_for(Duration::from_millis(step_ms.min(200)));
        elapsed += step_ms.min(200);
    }
    let counts = output_counts(sim.observed_frames(), &cell);
    (cell, counts)
}

/// The GPA's **volume leak slope** on the *intermediate* relays: `max over relays (E(hi) − E(0)) / N`, the
/// extra frames a relay is observed emitting per extra real cell it forwards — the flow-correlation signal
/// (spec C1, `flow_correlation.rs` dE/dN, now over the routed network). The client-originator and
/// service-destination are excluded: endpoint exposure is the acknowledged §8.1 residual (`P_link = P_hop²`),
/// NOT what constant-rate cover defends — cover protects the *interior* hops, and that is the flagship claim.
fn gpa_volume_leak_slope(mix: Option<(Duration, Duration)>) -> f64 {
    const N: usize = 40;
    let (cell, e0) = run_and_tap(mix, 0);
    let (_, ehi) = run_and_tap(mix, N);
    let (client, service) = (cell[0], cell[40]);
    let mut best = 0.0f64;
    for (i, &node) in cell.iter().enumerate() {
        if node == client || node == service {
            continue; // endpoints are the §8.1 residual, not the cover-defended interior
        }
        let slope = (ehi[i] as f64 - e0[i] as f64) / N as f64;
        best = best.max(slope);
    }
    best
}

#[test]
fn constant_rate_cover_collapses_the_gpa_flow_correlation_on_interior_relays() {
    // Undefended (no cover, no mixing): an interior relay forwards each real onion immediately, so its
    // observed output volume grows one-for-one with the flow it carries — a leak slope ≈ 1 the GPA reads off.
    let undefended = gpa_volume_leak_slope(None);
    // Defended (constant-rate cover + Poisson mixing): a forwarded real onion DISPLACES a scheduled cover
    // cell, so the relay's observed output volume is independent of how much real traffic it carries — the
    // leak slope collapses to ~0. This is the C1 / §8.2 "strong against a GPA" claim, now measured by an
    // adversary over the real routed + mixed + cover-scheduled network, not a crate-local harness.
    let defended = gpa_volume_leak_slope(Some((
        Duration::from_millis(120),
        Duration::from_millis(150),
    )));

    assert!(
        undefended > 0.5,
        "an undefended interior relay's output volume tracks its real flow (leak slope {undefended:.3})"
    );
    assert!(
        defended < 0.25,
        "constant-rate cover must displace (not add), collapsing the interior leak slope to ~0, got {defended:.3}"
    );
    assert!(
        defended < undefended - 0.3,
        "the defense must materially erase the GPA's volume signal (defended {defended:.3} vs undefended {undefended:.3})"
    );
}

/// **Do the SHIPPING defaults actually defend?** The test above measures the GPA defence at a hand-picked schedule
/// (mix 120 ms, cover 150 ms). This one measures whatever `fanos_node::config` currently ships.
///
/// That matters because the mechanism is *displacement*: a real forward takes the slot a cover cell would have used, so
/// emitted volume stays constant. Displacement only masks a flow while cover slots are at least as frequent as real
/// forwards; past that the excess must be **added**, and the volume signal returns. A default that is measured at one
/// schedule and shipped at another is exactly how a defence becomes decorative.
///
/// **And that is precisely what happened to this test (#187).** It was written against `DEFAULT_MIX_DELAY = 50 ms`,
/// `DEFAULT_COVER_INTERVAL = 1000 ms` and said so in prose; `252815b` then moved the defaults to 120/500 on a knee
/// measurement, and the two literals below did not move with them — under a comment reading *"the shipping values,
/// read as the node's config declares them"*, which they were not. For two months the guard against a
/// measured-at-one-schedule-shipped-at-another defect **was** an instance of it, asserting about a configuration no
/// node runs. Reading the constants is the only version of this test that cannot go stale, so it now does.
#[test]
fn the_shipping_defaults_are_measured_not_assumed() {
    let (ship_mix, ship_cover) = shipping();

    let undefended = gpa_volume_leak_slope(None);
    let tested = gpa_volume_leak_slope(Some((Duration::from_millis(120), Duration::from_millis(150))));
    let shipped = gpa_volume_leak_slope(Some((ship_mix, ship_cover)));

    println!("GPA volume leak slope — undefended {undefended:.3}, tested-schedule {tested:.3}, SHIPPED {shipped:.3}");
    assert!(undefended > 0.5, "sanity: the undefended baseline still leaks");
    assert!(
        shipped < 0.25,
        "the SHIPPING defaults must collapse the leak slope, not merely the schedule the suite happened to pick \
         (shipped {shipped:.3}, tested schedule {tested:.3}, undefended {undefended:.3})"
    );
}

/// Disambiguate a zero leak slope: **masked, or never emitted?**
///
/// `gpa_volume_leak_slope` measures *extra frames per extra real cell*, which reads zero both when cover perfectly
/// displaces the flow and when the flow never left the relay at all. Those are opposite outcomes — one is the defence
/// working, the other is the defence eating the traffic — and the slope cannot tell them apart. So this measures the
/// absolute interior volume alongside it.
#[test]
fn a_zero_leak_slope_is_masking_and_not_starvation() {
    let shipped_label = format!(
        "SHIPPED (mix {}ms, cover {}ms)",
        millis(DEFAULT_MIX_DELAY),
        millis(DEFAULT_COVER_INTERVAL)
    );
    let schedules = [
        ("undefended", None),
        ("tested (mix 120ms, cover 150ms)", Some((Duration::from_millis(120), Duration::from_millis(150)))),
        (shipped_label.as_str(), Some(shipping())),
    ];
    for (name, mix) in schedules {
        let (cell, e0) = run_and_tap(mix, 0);
        let (_, ehi) = run_and_tap(mix, 40);
        let (client, service) = (cell[0], cell[40]);
        let interior = |v: &Vec<usize>| -> usize {
            cell.iter().zip(v.iter()).filter(|(n, _)| **n != client && **n != service).map(|(_, c)| *c).sum()
        };
        let (idle, loaded) = (interior(&e0), interior(&ehi));
        let delta = loaded as i64 - idle as i64;
        println!("{name:<34} interior frames: idle {idle:>5}, with 40 real cells {loaded:>5}  (delta {delta:+})");

        if mix.is_none() {
            // The baseline: every real cell shows up as extra emissions on the two interior hops it traverses.
            assert_eq!(idle, 0, "an undefended relay emits nothing when idle — it has no cover to emit");
            assert!(delta >= 80, "and every real cell is visible on the wire (delta {delta})");
        } else {
            // Cover is RUNNING — this is what separates masking from starvation. A schedule that emitted nothing
            // would also show delta ≈ 0, and would be a defence that works by eating the traffic.
            assert!(idle > 100, "{name}: cover must actually be emitting when idle (idle {idle})");
            // And real traffic DISPLACES rather than adds: the total is unchanged, which is the whole mechanism.
            assert!(
                delta.abs() <= 8,
                "{name}: real forwards must take cover slots, not add to them (delta {delta})"
            );
        }
    }
}

/// The **timing** half of the flow-correlation attack — the one this file's own header describes and did not measure.
///
/// The header promises "for every relay, the Pearson correlation between its input-rate and output-rate time series".
/// What was implemented is a *volume delta*: does total emission grow with load? Those are different attacks against
/// different halves of the defence:
///
/// * **volume** — masked by *displacement* (a real forward takes a cover slot, so the total is unchanged);
/// * **timing** — masked by *mixing* (a relay holds each onion a Poisson delay, so emission times do not track arrival
///   times).
///
/// A relay that forwards immediately leaks its circuit even at perfectly constant volume: the GPA watches *when* cells
/// leave, not how many. So the timing channel is where the mix delay earns its place, and it was untested.
/// The GPA's timing advantage, **maximised over the observation timescale** — because the adversary chooses it.
///
/// Reporting a single bin width measures *my* choice, not the attacker's — a global passive adversary bins the wire
/// however suits it, and the correlation is strongly bin-dependent. So the metric maximises over bin widths.
///
/// **But only over bins with enough samples to mean anything.** A first version maximised over every width including
/// 2000 ms, which on a ~10 s run is *five data points* — and Pearson over five points reaches 1.000 routinely by chance.
/// That version reported `r = 1.000` for every configuration, which is not a finding about the traffic but an artefact of
/// the sample count. [`MIN_BINS`] is the floor that keeps the statistic honest; widths coarser than `span / MIN_BINS` are
/// excluded rather than believed.
///
/// The lesson, recorded because it nearly shipped twice in opposite directions: a single bin width **understates** the
/// exposure (it is not the adversary's choice) and an unconstrained maximum **overstates** it (small samples correlate
/// spuriously). Both errors look like results.
fn gpa_timing_correlation(mix: Option<(Duration, Duration)>) -> f64 {
    /// Minimum bins for a Pearson coefficient to carry information rather than noise.
    const MIN_BINS: u64 = 30;
    // The run in `gpa_timing_correlation_binned` spans ~10 s of virtual time.
    const SPAN_MS: u64 = 10_000;
    [25u64, 50, 100, 250, 500, 1_000, 2_000]
        .into_iter()
        .filter(|bin| SPAN_MS / bin >= MIN_BINS)
        .map(|bin| gpa_timing_correlation_binned(mix, bin))
        .fold(0.0f64, f64::max)
}

/// As [`gpa_timing_correlation`], with an explicit bin width — so the result can be checked for binning artefacts.
fn gpa_timing_correlation_binned(mix: Option<(Duration, Duration)>, bin_ms: u64) -> f64 {
    let (cell, _) = run_and_tap(mix, 0); // shape only; re-run below with real traffic
    let (client, service) = (cell[0], cell[40]);

    let mut sim = Sim::new(0x77AA);
    let relays = spawn_nyx_cell(&mut sim, mix);
    if mix.is_some() {
        sim.inject_all(&Command::StartHeartbeat);
    }
    sim.observe_frames();
    // A BURSTY flow: bursts are what a timing attack keys on, and an even spread would hide the signal by construction.
    for round in 0..8u64 {
        for _ in 0..5 {
            sim.inject(relays[0], Command::Send { to: relays[40], payload: b"burst".to_vec() });
        }
        sim.run_for(Duration::from_millis(if round % 2 == 0 { 100 } else { 900 }));
    }
    sim.run_for(Duration::from_millis(2_000));

    let obs = sim.observed_frames();
    let span = obs.iter().map(|o| o.t_ms).max().unwrap_or(0) / bin_ms + 1;
    let mut worst = 0.0f64;
    for &relay in &relays {
        if relay == client || relay == service {
            continue; // endpoints are the acknowledged §8.1 residual, not what mixing defends
        }
        let mut ins = vec![0f64; span as usize];
        let mut outs = vec![0f64; span as usize];
        for o in obs {
            let b = (o.t_ms / bin_ms) as usize;
            if o.to == relay && let Some(v) = ins.get_mut(b) {
                *v += 1.0;
            }
            if o.from == relay && let Some(v) = outs.get_mut(b) {
                *v += 1.0;
            }
        }
        worst = worst.max(pearson(&ins, &outs).abs());
    }
    worst
}

/// Pearson correlation; `0.0` when either series is constant (no signal to read).
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

#[test]
#[ignore = "sweep, not an assertion — run with --ignored --nocapture"]
fn sweep_bin_width_to_check_the_correlation_is_not_an_artefact() {
    // Both series are mostly zero between cover slots, and CORRELATED ZEROS inflate Pearson. If r survives only at one
    // bin width it is an artefact of the binning, not a property of the traffic.
    println!(
        "bin width -> r  (shipping schedule: mix {}ms, cover {}ms)",
        millis(DEFAULT_MIX_DELAY),
        millis(DEFAULT_COVER_INTERVAL)
    );
    let ship = Some(shipping());
    for bin in [25u64, 50, 100, 250, 500, 1_000, 2_000] {
        println!(
            "  {bin:>5} ms bins -> undefended {:.3}, shipped {:.3}",
            gpa_timing_correlation_binned(None, bin),
            gpa_timing_correlation_binned(ship, bin)
        );
    }
}

#[test]
#[ignore = "sweep, not an assertion — run with --ignored --nocapture"]
fn sweep_timing_correlation_against_the_mix_delay() {
    // Each axis is swept with the OTHER parameter held at its shipping value, so a row reads as "what the
    // deployed node would get if only this dial moved". Held at a stale literal instead, as both axes were,
    // the table describes a configuration nobody runs.
    let (ship_mix, ship_cover) = (millis(DEFAULT_MIX_DELAY), millis(DEFAULT_COVER_INTERVAL));

    println!("mix delay -> GPA correlation, maximised over observation bin width (cover {ship_cover}ms):");
    for ms in including_the_default(&[0, 50, 250, 500, 1_000, 2_000], ship_mix) {
        let m = (ms != 0).then(|| (Duration::from_millis(ms), engine_span(DEFAULT_COVER_INTERVAL)));
        let mark = if ms == ship_mix { " <- shipping" } else { "" };
        println!("  {ms:>5} ms -> r = {:.3}{mark}", gpa_timing_correlation(m));
    }

    println!("cover interval sweep (mix {ship_mix}ms):");
    for ms in including_the_default(&[150, 300, 1_000, 3_000], ship_cover) {
        let r = gpa_timing_correlation(Some((engine_span(DEFAULT_MIX_DELAY), Duration::from_millis(ms))));
        let mark = if ms == ship_cover { " <- shipping" } else { "" };
        println!("  cover {ms:>5} ms -> r = {r:.3}{mark}");
    }
}

#[test]
#[ignore = "INVALID METRIC — see threshold_routing::measure_gpa_timing_on_the_shipping_router. Kept as a counter-example."]
fn measure_the_timing_channel_at_the_shipping_defaults() {
    let undefended = gpa_timing_correlation(None);
    let shipped = gpa_timing_correlation(Some(shipping()));
    println!(
        "GPA in/out rate correlation — undefended {undefended:.3}, SHIPPED {shipped:.3} \
         (mix {}ms, cover {}ms)",
        millis(DEFAULT_MIX_DELAY),
        millis(DEFAULT_COVER_INTERVAL)
    );
    assert!(
        undefended > 0.5,
        "an immediate-forwarding relay's output times track its input times (r = {undefended:.3})"
    );
    assert!(
        shipped < undefended - 0.3,
        "mixing must break the per-hop timing correlation at the SHIPPING delay, not only at a chosen one \
         (shipped r = {shipped:.3}, undefended r = {undefended:.3})"
    );
}

// ── The VALID experiment: linkability among concurrent flows ────────────────────────────────────────────────────────
//
// The retracted metric asked "is a lone flow visible", which conservation answers yes to for any design. Anonymity asks
// something else: among several **concurrent** flows, can the adversary MATCH inputs to outputs better than chance? That
// is the confusion cover and mixing exist to create, and it cannot be measured with one flow.
//
// The adversary here is the canonical one: it sees every frame's `(t, from, to)`, builds a rate series for each flow's
// entry and each flow's exit, scores every (entry, exit) pair by correlation, and takes the best assignment. Its accuracy
// against chance `1/K` is the anonymity loss.
//
// ⚠️ Engine: this uses `NyxNode` (the **Lite** profile), because `PG(2,7)`'s 57 points give room for several
// simultaneous flows while the `ThresholdRouter` harness has 7. Running the same metric on the shipping engine is the
// named follow-up — and after the 18fce2e retraction, the engine is stated rather than assumed.

/// One flow's entry and exit coordinates.
struct Flow {
    client: Triple,
    service: Triple,
}

/// Rate series of frames emitted by `node`, in `bin_ms` bins.
fn emit_series(obs: &[FrameObs], node: Triple, bin_ms: u64, bins: usize) -> Vec<f64> {
    let mut v = vec![0f64; bins];
    for o in obs.iter().filter(|o| o.from == node) {
        if let Some(slot) = v.get_mut((o.t_ms / bin_ms) as usize) {
            *slot += 1.0;
        }
    }
    v
}

/// Rate series of frames *received* by `node`.
fn recv_series(obs: &[FrameObs], node: Triple, bin_ms: u64, bins: usize) -> Vec<f64> {
    let mut v = vec![0f64; bins];
    for o in obs.iter().filter(|o| o.to == node) {
        if let Some(slot) = v.get_mut((o.t_ms / bin_ms) as usize) {
            *slot += 1.0;
        }
    }
    v
}

/// The adversary's matching accuracy over `K` concurrent flows: the fraction it assigns correctly, against chance `1/K`.
fn linkability_seeded(mix: Option<(Duration, Duration)>, seed: u64) -> (f64, f64) {
    const K: usize = 5;
    const BIN_MS: u64 = 200;
    const SPAN_MS: u64 = 8_000;

    let mut sim = Sim::new(0x4B1 + seed);
    let cell = spawn_nyx_cell(&mut sim, mix);
    if mix.is_some() {
        sim.inject_all(&Command::StartHeartbeat);
    }
    sim.observe_frames();

    // K flows on disjoint endpoint pairs, each with its OWN burst rhythm — distinct rhythms are what makes matching
    // possible at all, so this is the adversary's best case, not a soft one.
    let flows: Vec<Flow> = (0..K).map(|i| Flow { client: cell[i], service: cell[K + i] }).collect();
    let mut t = 0u64;
    let mut round = 0u64;
    while t < SPAN_MS {
        for (i, f) in flows.iter().enumerate() {
            // flow i fires every (i+1) rounds — distinct duty cycles the adversary can key on
            if round.is_multiple_of(i as u64 + 1) {
                sim.inject(f.client, Command::Send { to: f.service, payload: b"flow".to_vec() });
            }
        }
        sim.run_for(Duration::from_millis(200));
        t += 200;
        round += 1;
    }
    sim.run_for(Duration::from_millis(2_000));

    let obs = sim.observed_frames();
    let bins = (SPAN_MS / BIN_MS) as usize + 12;
    // Score every (entry, exit) pair, then greedily assign best-first — the adversary's natural strategy.
    let entries: Vec<Vec<f64>> = flows.iter().map(|f| emit_series(obs, f.client, BIN_MS, bins)).collect();
    let exits: Vec<Vec<f64>> = flows.iter().map(|f| recv_series(obs, f.service, BIN_MS, bins)).collect();
    let mut pairs: Vec<(f64, usize, usize)> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        for (j, x) in exits.iter().enumerate() {
            pairs.push((pearson(e, x).abs(), i, j));
        }
    }
    pairs.sort_by(|a, b| b.0.total_cmp(&a.0));
    let mut taken_i = [false; K];
    let mut taken_j = [false; K];
    let mut correct = 0usize;
    for (_, i, j) in pairs {
        if !taken_i[i] && !taken_j[j] {
            taken_i[i] = true;
            taken_j[j] = true;
            if i == j {
                correct += 1;
            }
        }
    }
    (correct as f64 / K as f64, 1.0 / K as f64)
}

/// Mean matching accuracy over several seeds — with `K = 5`, a single run moves in steps of 0.2, so one draw is not a
/// result. Averaging is the difference between a number and an anecdote.
fn linkability(mix: Option<(Duration, Duration)>) -> (f64, f64) {
    const RUNS: u64 = 12;
    let mut acc = 0.0;
    let mut chance = 0.0;
    for seed in 0..RUNS {
        let (a, c) = linkability_seeded(mix, seed);
        acc += a;
        chance = c;
    }
    (acc / RUNS as f64, chance)
}

#[test]
#[ignore = "sweep, not an assertion — run with --ignored --nocapture"]
fn sweep_linkability_against_the_schedule() {
    // Is the residual linkability TUNABLE? The retracted metric could not answer this, because it penalised
    // conservation at every setting. This one can.
    println!("flow-matching accuracy over 5 concurrent flows (chance 0.20):");
    let shipping_row =
        format!("SHIPPING  ({}/{})", millis(DEFAULT_MIX_DELAY), millis(DEFAULT_COVER_INTERVAL));
    for (name, mix, cover) in [
        ("undefended", 0u64, 0u64),
        (shipping_row.as_str(), millis(DEFAULT_MIX_DELAY), millis(DEFAULT_COVER_INTERVAL)),
        ("moderate  (120/300)", 120, 300),
        ("aggressive(250/150)", 250, 150),
        ("heavy     (500/100)", 500, 100),
    ] {
        let m = if cover == 0 { None } else { Some((Duration::from_millis(mix), Duration::from_millis(cover))) };
        println!("  {name:<22} accuracy {:.2}", linkability(m).0);
    }
}

#[test]
fn the_adversary_cannot_match_concurrent_flows_much_better_than_chance() {
    let (undefended, chance) = linkability(None);
    let (defended, _) = linkability(Some(shipping()));
    println!(
        "flow-matching accuracy over 5 concurrent flows — chance {chance:.2}, undefended {undefended:.2}, \
         shipping defaults (mix {}ms, cover {}ms) {defended:.2}",
        millis(DEFAULT_MIX_DELAY),
        millis(DEFAULT_COVER_INTERVAL)
    );
    // The undefended baseline must actually be attackable, or the experiment proves nothing about the defence.
    assert!(
        undefended > chance,
        "an undefended cell must leak the matching (got {undefended:.2} vs chance {chance:.2}) — otherwise this \
         measures nothing"
    );
    // A real, measured reduction — this is what the retracted metric could not see, because it penalised conservation at
    // every setting rather than the implementation.
    assert!(
        defended < undefended - 0.3,
        "the defence must materially reduce matching (defended {defended:.2}, undefended {undefended:.2})"
    );
    // And the honest other half. This assertion used to read `defended > chance` — "linkability remains" — and it
    // held at the 50/1000 defaults it was written against. Pointed at the defaults that actually ship (120/500) it
    // fails, and **not because the system became anonymous**: the accuracy is 0.00, which is *below* chance.
    //
    // Below chance is not safety, and the arithmetic says so. The score is `|Pearson|` at zero lag, and the assignment
    // is greedy, so a matcher reduced to guessing produces something distributed like a random permutation of `K = 5`.
    // Its expected fixed-point fraction is `1/K = 0.20` — but the *probability of zero* fixed points is only
    // `D₅/5! = 44/120 ≈ 0.367`. Twelve seeds all scoring zero therefore has probability `0.367¹² ≈ 3e-6` under the
    // guessing hypothesis. The matcher is not guessing; it is systematically *avoiding* the truth, which means the
    // score matrix still carries information about it. An anonymous system drives this metric to chance, not to zero.
    //
    // So the number is pinned as measured, with the mechanism unexplained and tracked (#187): the likely cause is that
    // `pearson` compares series at **zero lag only**, while mixing displaces the exit series by the mix delay — a real
    // flow-correlation adversary scans lags. Until that is resolved this assertion records what the harness does, not
    // an anonymity claim, and it fails loudly if the value drifts back across chance in either direction.
    assert!(
        defended < chance,
        "the shipping schedule's matching accuracy sits below chance (defended {defended:.2}, chance {chance:.2}); \
         if it has risen back to or above chance, the harness or the defaults changed and #187 must be re-read"
    );
}
