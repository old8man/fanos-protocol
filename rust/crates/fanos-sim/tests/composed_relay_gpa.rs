//! **The flow-correlation attack against the relay a `--relay` deployment actually runs** (#181 step 2).
//!
//! `traffic_analysis.rs` runs this attack over a bare `NyxNode`. The figure `DEFAULT_COVER_INTERVAL`'s doc
//! records — `r = 0.975` — is for the shipping `ThresholdRouter`. Neither is the composed cell, which is
//! what `compose_engine`'s relay branch builds and what a deployment starts. #181 forbids changing
//! `forward_send`'s precedence before that cell has been measured, and this is the measurement.
//!
//! # What can be measured today, and why it is not the pair #181 asked for
//!
//! #181's step 2 says "compare `r` with cover-only against cover+delay". **The shipping code cannot express
//! cover+delay**: `forward_send` queues a cell for the next cover slot *or* holds it for a sampled delay,
//! never both, which is the mutual exclusivity the task is about. Running that pair on today's code would
//! measure the same branch twice and report a difference of zero as if it meant something.
//!
//! So the three arms here are the three the code CAN express, and they answer the question the change hangs
//! on just as well:
//!
//! * **undefended** — no cover, no delay. The control. If this is not high the harness is not seeing the
//!   flow at all, and every other number is noise about nothing.
//! * **cover only** — the shipping precedence, `DEFAULT_COVER_INTERVAL` with the delay never reached.
//! * **delay only** — cover off, `DEFAULT_MIX_DELAY` applied per cell. This is the arm that decides the
//!   change: composing two defences is worth its latency only if the second one does something on its own.
//!   If delay-only sits at the undefended figure, the remedy `DEFAULT_COVER_INTERVAL`'s doc names is the
//!   wrong instrument and the gap needs a different one (a bounded-latency drain, or slots that do not
//!   skip) — which is a finding, not a failure.
//!
//! The adversary is the lag-scanning one (#187), through `fanos_testkit::gpa`, because a zero-lag matcher
//! reads mixing as absence of signal and scores *below chance*.
//!
//! # What it drives, and the two ways this file first measured nothing
//!
//! The probe is a **sealed two-hop onion** through `ThresholdRouter::forward_send`, built the way
//! `composed_relay.rs` builds one, with a separate seal per send — one frame re-injected would be a replay
//! and #296 taught the router to refuse those.
//!
//! It did not start that way, and both wrong turns are asserted against below rather than merely fixed:
//!
//! 1. It first drove `Command::Send`, an overlay send that never enters `forward_send`. The tape came back
//!    byte-identical with and without a 120 ms delay, and `delay buys 0.000` would have shipped as a
//!    property of the relay. #134's shape, one subsystem over.
//! 2. The control that caught it then used `(frame count, last timestamp)` — a proxy that cannot see ten
//!    frames displaced by 120 ms among 4972. Summing every timestamp can: `29 630 002 -> 29 635 851`.
//!
//! `the_mix_delay_engages_and_displaces_the_tape_without_dropping_a_frame` now pins all of it, so a future
//! change that silently detaches this harness from the forwarding path fails loudly instead of reading zero.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::cast_precision_loss
)]

mod common;

use common::{emit_series, recv_series, spawn_composed_relay_cell};
use fanos_field::F2;
use fanos_geometry::{Line, Point};
use fanos_node::config::{DEFAULT_COVER_INTERVAL, DEFAULT_MIX_DELAY};
use fanos_pqcrypto::OnionKeyRatchet;
use fanos_rendezvous::{BeaconSeed, Epoch, MixDirectory, meeting_line, seal_forward};
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::Sim;
use fanos_testkit::gpa::best_lag_score;

/// The Fano onion threshold `mix_threshold(3) = 2` — the value `compose_engine` hands its router. Stated
/// rather than imported for the reason `composed_relay.rs` states it: a change to the derivation should show
/// up as a forward that fails to seal, not as this file silently sealing to whatever the code now does.
const ONION_T: u8 = 2;

/// One seed for every arm: the three differ in the DEFENCE and in nothing else, which is the whole point
/// ([[discrimination-needs-differing-inputs]] read the other way — the inputs must be identical).
const SEED: u64 = 0x9E1D_C0DE;

/// The observation window. The BIN is a parameter and deliberately not a constant.
///
/// **A bin wider than the defence cannot see it.** The first version of this harness used the 200 ms bin
/// `traffic_analysis.rs` settled on, against a `DEFAULT_MIX_DELAY` of 120 ms — so a cell displaced by the
/// full mean landed in the same bin it started in, and the measurement reported `delay buys 0.000` as a
/// fact about the relay when it was a fact about the ruler. A borrowed number counts another object.
const WINDOW_MS: u64 = 12_000;

/// The driving step, FIXED so every arm and every bin width sees the same traffic — across the sweep only
/// the ruler changes, never the thing being measured.
const STEP_MS: u64 = 20;

/// Bin widths to sweep, spanning both sides of `DEFAULT_MIX_DELAY` (120 ms) and `DEFAULT_COVER_INTERVAL`
/// (500 ms). A defence that only appears at one bin is an artefact of that bin; one that appears across the
/// sweep is a property of the relay.
const BIN_SWEEP_MS: [u64; 5] = [20, 50, 100, 250, 500];

/// The lag window, derived rather than chosen: the mix delay is a Poisson MEAN, so a cell's displacement is
/// exponential and its tail matters. `DEFAULT_MIX_DELAY` at a 200 ms bin, covered to five means, is the
/// window past which a wider scan only collects noise maxima — and the max of more candidates is larger
/// whether or not any is real.
fn max_lag_bins(bin_ms: u64) -> usize {
    let mean_ms = DEFAULT_MIX_DELAY.as_millis() as u64;
    ((5 * mean_ms) / bin_ms).max(1) as usize
}

fn span(d: std::time::Duration) -> Duration {
    Duration::from_millis(d.as_millis() as u64)
}

/// The GPA's best score over every node in the cell: for each, how well its OUTPUT rate series is predicted
/// by its INPUT one, scanning lags. Taking the max is the adversary's own choice — it attacks the relay that
/// leaks most, not an average one.
fn worst_relay_correlation(cover: Duration, mix: Duration, bin_ms: u64) -> f64 {
    tape_and_correlation(cover, mix, bin_ms).1
}

/// The same run, also returning the tape's shape so a caller can check the setting ENGAGED.
fn tape_and_correlation(cover: Duration, mix: Duration, bin_ms: u64) -> ((usize, u64), f64) {
    tape_and_correlation_with(cover, mix, bin_ms, true)
}

/// The same run with the overlay heartbeat as a parameter — see
/// `the_figures_above_are_dominated_by_the_overlay_heartbeat_not_by_the_relay`.
fn tape_and_correlation_with(
    cover: Duration,
    mix: Duration,
    bin_ms: u64,
    heartbeat: bool,
) -> ((usize, u64), f64) {
    tape_correlation_cargo(cover, mix, bin_ms, heartbeat, true)
}

/// The same run with the relay's cargo as a parameter — the control that decides whether any of these
/// figures are about the relay at all.
fn tape_correlation_cargo(
    cover: Duration,
    mix: Duration,
    bin_ms: u64,
    heartbeat: bool,
    cargo: bool,
) -> ((usize, u64), f64) {
    tape_correlation_full(cover, mix, bin_ms, heartbeat, cargo, 0)
}

/// …and with the heartbeat **stagger** as a parameter. `0` is `inject_all` — seven nodes on one clock, which
/// no deployment does; anything else starts each node's liveness at its own offset.
fn tape_correlation_full(
    cover: Duration,
    mix: Duration,
    bin_ms: u64,
    heartbeat: bool,
    cargo: bool,
    stagger_ms: u64,
) -> ((usize, u64), f64) {
    tape_correlation_dense(cover, mix, bin_ms, heartbeat, cargo, stagger_ms, 1)
}

/// …and with the traffic density as a parameter. See `drive_n`.
#[allow(clippy::too_many_arguments)]
fn tape_correlation_dense(
    cover: Duration,
    mix: Duration,
    bin_ms: u64,
    heartbeat: bool,
    cargo: bool,
    stagger_ms: u64,
    repeats: usize,
) -> ((usize, u64), f64) {
    let mut sim = Sim::new(SEED);
    let cell = spawn_composed_relay_cell::<F2>(&mut sim, Config::default(), cover, mix, true);
    if heartbeat {
        if stagger_ms == 0 {
            sim.inject_all(&Command::StartHeartbeat); // arms the cover schedule where there is one
        } else {
            for (i, &n) in cell.iter().enumerate() {
                sim.inject(n, Command::StartHeartbeat);
                if i + 1 < cell.len() {
                    sim.run_for(Duration::from_millis(stagger_ms));
                }
            }
        }
    }
    sim.observe_frames(); // the GPA starts tapping

    if cargo {
        drive_n(&mut sim, repeats);
    } else {
        // The same simulated span with nothing forwarded, so the tape differs in exactly one thing.
        let mut now = 0u64;
        while now < WINDOW_MS {
            sim.run_for(Duration::from_millis(STEP_MS));
            now += STEP_MS;
        }
    }

    let tape = sim.observed_frames();
    let bins = (WINDOW_MS / bin_ms) as usize;
    let lag = max_lag_bins(bin_ms);
    let r = cell
        .iter()
        .map(|&n| {
            let ins = recv_series(tape, n, bin_ms, bins);
            let outs = emit_series(tape, n, bin_ms, bins);
            best_lag_score(&ins, &outs, lag)
        })
        .fold(0.0, f64::max);
    let shape = (tape.len(), tape.iter().map(|o| o.t_ms).sum::<u64>());
    (shape, r)
}

/// The traffic every arm and every extra test drives — one definition, so no two of them can differ in the
/// load while claiming to differ only in the defence.
fn drive(sim: &mut Sim) {
    drive_n(sim, 1);
}

/// The same traffic repeated at `repeats` offsets — one definition still, so no two arms can differ in the
/// load. Density matters because a Pearson over a series that is 95% zeros is measuring coincidence among a
/// handful of events, not a rate relationship.
fn drive_n(sim: &mut Sim, repeats: usize) {
    // **Sealed onions through the router, not overlay sends.** The first version of this harness drove
    // `Command::Send`, which never enters `ThresholdRouter::forward_send` — the control below caught it.
    // This is the shape `composed_relay.rs` uses: an epoch-0 `MixDirectory` over the seeds
    // `spawn_composed_relay_cell` gives each relay, a two-hop circuit, and a frame injected on the wire.
    let mut dir = MixDirectory::new();
    for i in 0..7usize {
        let ratchet = OnionKeyRatchet::new([u8::try_from(i).unwrap(); 32], Epoch::ZERO);
        dir.insert(Point::<F2>::at(i).coords(), ratchet.public().clone());
    }
    let meeting = meeting_line::<F2>(b"gpa-probe-svc", Epoch::ZERO, &BeaconSeed::GENESIS).coords();
    let hop = (0..7)
        .map(|i| Line::<F2>::at(i).coords())
        .find(|&l| l != meeting)
        .expect("a second line");
    let entry = Point::<F2>::at(6).coords();

    // An APERIODIC send pattern, within the cover budget. Both properties are load-bearing: a periodic one
    // correlates with its own shifts at a value the period fixes (measured — see `fanos_testkit::gpa`), and
    // a burst beyond the cover rate is a separately, honestly leaky regime that constant-rate cover never
    // claimed to hide.
    //
    // Each send is a SEPARATE seal. Re-injecting one frame would be a replay, and #296 taught the shipping
    // router to refuse those — the second onward would vanish at the anti-replay gate and the flow would be
    // one cell long.
    let base = [400u64, 1400, 1600, 3200, 5000, 5200, 5400, 8000, 9800, 10_000];
    let mut send_at_ms: Vec<u64> = Vec::new();
    for k in 0..repeats {
        let k = k as u64;
        for b in base {
            send_at_ms.push(b + k * 130 + (k % 3) * 37);
        }
    }
    send_at_ms.sort_unstable();
    let mut sent = 0usize;
    let mut now = 0u64;
    while now < WINDOW_MS {
        while sent < send_at_ms.len() && send_at_ms[sent] <= now {
            let seed = [b'g', b'p', b'a', u8::try_from(sent & 0xFF).unwrap()];
            let fwd = seal_forward::<F2>(&[hop, meeting], &dir, ONION_T, b"gpa-probe", &seed)
                .expect("the circuit seals");
            sim.inject_frame(entry, fwd.combiner, fwd.frame.clone());
            sent += 1;
        }
        sim.run_for(Duration::from_millis(STEP_MS));
        now += STEP_MS;
    }
}

/// **The mixing branch engages, and it DISPLACES rather than drops** — asserted before any figure below is
/// allowed to mean anything.
///
/// This control has been wrong twice, and both are worth keeping because each was a different way to
/// mis-measure the same thing:
///
/// 1. The harness first drove `Command::Send`, an overlay send that never enters
///    `ThresholdRouter::forward_send`. The tape came back byte-identical with and without a 120 ms mean
///    delay, and `delay buys 0.000` would have been published as a property of the relay. Same shape as
///    #134, where `deaddrop_multicast` did not call `forward_send` and both defences were bypassed for a
///    whole class of traffic. Fixed by sealing real onions through the router.
/// 2. The observable was then `(frame count, last timestamp)`, which cannot see ten frames displaced by
///    120 ms among 4972 — a proxy insensitive to exactly the effect it was hired to detect. Fixed by summing
///    every timestamp.
///
/// Measured with both fixes: 4972 frames either way, and the timestamp sum moves 29 630 002 → 29 635 851.
/// Nothing is lost; 5.8 s of aggregate displacement is added. That is a mixing delay doing its job.
#[test]
fn the_mix_delay_engages_and_displaces_the_tape_without_dropping_a_frame() {
    let ((count_plain, sum_plain), _) = tape_and_correlation(Duration(0), Duration(0), 100);
    let ((count_mixed, sum_mixed), _) = tape_and_correlation(Duration(0), span(DEFAULT_MIX_DELAY), 100);

    assert_ne!(
        sum_plain, sum_mixed,
        "the tape carries the same total timing with and without a {DEFAULT_MIX_DELAY:?} mean delay — the \
         mixing branch did not run, and every figure this file reports about it would be about nothing"
    );
    assert!(
        sum_mixed > sum_plain,
        "mixing moved the tape EARLIER ({sum_plain} -> {sum_mixed}), which a delay cannot do — a negative \
         displacement means the two arms are not the same experiment"
    );
    assert_eq!(
        count_plain, count_mixed,
        "the delay changed how many frames exist ({count_plain} -> {count_mixed}); it is meant to hold \
         cells, not to lose or duplicate them, and a count that moves makes the correlation figures \
         incomparable between arms"
    );
}

/// **Why the delay buys nothing, measured rather than argued.**
///
/// `DEFAULT_COVER_INTERVAL`'s log now carries an explanation for the zero: the relay emits one cell out per
/// cell in, so the two rate series meet at *some* displacement however the send times are jittered, and a
/// lag-scanning adversary is invariant to jitter by construction. That was reasoning. This measures it.
///
/// If the claim holds, a relay carrying the flow moves the same TOTAL either way — the delay changes when
/// cells leave, never how many — and the per-bin series are a permutation in time of one another rather
/// than two different signals. If instead the totals differ, the explanation in that doc is wrong and the
/// zero has some other cause, which would be worth more than the measurement that produced it.
#[test]
fn the_relay_emits_what_it_receives_which_is_why_jitter_cannot_help() {
    let bin = 100u64;
    let bins = (WINDOW_MS / bin) as usize;

    let totals = |mix: Duration| -> (f64, f64) {
        let mut sim = Sim::new(SEED);
        let cell = spawn_composed_relay_cell::<F2>(&mut sim, Config::default(), Duration(0), mix, true);
        drive(&mut sim);
        let tape = sim.observed_frames();
        cell.iter()
            .map(|&n| {
                let i: f64 = recv_series(tape, n, bin, bins).iter().sum();
                let o: f64 = emit_series(tape, n, bin, bins).iter().sum();
                (i, o)
            })
            .fold((0.0, 0.0), |(a, b), (i, o)| (a + i, b + o))
    };

    let (in_plain, out_plain) = totals(Duration(0));
    let (in_mixed, out_mixed) = totals(span(DEFAULT_MIX_DELAY));

    assert!(
        (in_plain - in_mixed).abs() < f64::EPSILON && (out_plain - out_mixed).abs() < f64::EPSILON,
        "the mixing delay changed the TOTALS ({in_plain}/{out_plain} -> {in_mixed}/{out_mixed}), so it does \
         more than displace and the explanation written into DEFAULT_COVER_INTERVAL's log is wrong"
    );
    assert!(
        (in_plain - out_plain).abs() / in_plain.max(1.0) < 0.05,
        "a relay cell emits {out_plain} for {in_plain} received — if those diverge, the output rate is NOT \
         a permutation of the input rate and something other than one-in-one-out explains the correlation"
    );
}

/// The three-arm measurement itself. `#[ignore]`d because it stands three cells up and runs 12 s of
/// simulated time each; the control above is what the gate runs.
///
/// Run: `cargo test -p fanos-sim --test composed_relay_gpa -- --ignored --nocapture`
#[test]
#[ignore = "measurement: three composed cells, 12 s of simulated time each"]
fn measure_the_gpa_correlation_on_the_composed_relay() {
    println!(
        "\n  GPA flow correlation on a composed relay cell's OVERLAY path, swept across bin widths\n  \
         (cover {DEFAULT_COVER_INTERVAL:?}, delay {DEFAULT_MIX_DELAY:?}; delay-only is a control that reads \
         zero because `forward_send` is not on this path)\n"
    );
    println!("    bin    lags   undefended   cover-only   delay-only   cover buys   delay buys");
    println!("    -----  -----  -----------  -----------  -----------  -----------  ----------");
    for bin in BIN_SWEEP_MS {
        let undefended = worst_relay_correlation(Duration(0), Duration(0), bin);
        let cover_only = worst_relay_correlation(span(DEFAULT_COVER_INTERVAL), Duration(0), bin);
        let delay_only = worst_relay_correlation(Duration(0), span(DEFAULT_MIX_DELAY), bin);
        let lags = max_lag_bins(bin);
        let cover_buys = undefended - cover_only;
        let delay_buys = undefended - delay_only;
        println!(
            "    {bin:>3}ms  {lags:>5}  {undefended:>11.3}  {cover_only:>11.3}  {delay_only:>11.3}  \
             {cover_buys:>11.3}  {delay_buys:>10.3}"
        );
    }
    println!();
}

/// **The figures this file records are dominated by the overlay heartbeat, and the cover's own contribution
/// is ~50× larger than they say.**
///
/// This file's header names two ways it once measured nothing — driving a command that never entered
/// `forward_send`, and an observable blind to a 120 ms displacement. This is a third, and it survived both
/// fixes because it is not about the *mechanism* being driven but about what else is on the tape.
///
/// `Command::StartHeartbeat` is injected to arm the cover schedule. It also starts overlay liveness, and
/// that traffic is not a rounding error: **4972 frames with it, 100 without**, on identical relay load. A
/// GPA correlating a relay's in-rate against its out-rate over that tape is correlating the heartbeat with
/// itself, and the relay's cargo is ~7% of what it sees.
///
/// Measured on the same drive, `bin = 100 ms`:
///
/// ```text
///                  undefended   cover-only   cover buys
///   with heartbeat      1.0000       0.9976       0.0024
///   without             1.0000       0.7585       0.2415
/// ```
///
/// The gap is what matters, not the second column's exact value: at five times this drive's density the
/// same pair reads `0.0019` and `0.1093`, because a busier relay leaves the cover less idle to fill. Both
/// densities put the ratio near two orders of magnitude, which is why the assertion below is a ratio and
/// not a pinned figure.
///
/// **This does not overturn the operational reading**, and that matters: `start_heartbeat` defaults to
/// `true`, so a deployed relay's tape really is heartbeat-dominated and a GPA really does see `r ≈ 1`. What
/// it overturns is the **attribution**, and the design item that was selected from it. `DEFAULT_COVER_INTERVAL`'s
/// entry concludes from `cover buys 0.002–0.007` that "the current schedule does not" decouple the output
/// count from the input, and proposes replacing it with cover that fills every slot. The schedule already
/// fills every slot — `forward_send` queues to `outbox` and one cell leaves per tick, real or keystream, and
/// `covering` is never cleared once set. On the traffic it governs it buys `0.24` here and `0.11` at five
/// times the density, not `0.002`. What re-correlates the
/// relay is a mechanism no mixnet defence touches, because it is membership liveness rather than relayed
/// cargo.
///
/// So the open item is not "replace the cover schedule". It is that a cell-wide periodic broadcast is
/// visible to the same adversary, and it is outside the plane the relay defends. Left as a measurement and
/// not a prescription, in this file's own tradition: what a GPA infers from an unsynchronised deployment's
/// heartbeats is a separate experiment — the perfect periodicity here is partly `inject_all` starting seven
/// nodes on one clock, which production does not do.
#[test]
fn the_figures_above_are_dominated_by_the_overlay_heartbeat_not_by_the_relay() {
    const BIN: u64 = 100;
    let ((frames_hb, _), plain_hb) = tape_and_correlation_with(Duration(0), Duration(0), BIN, true);
    let ((frames_no, _), plain_no) = tape_and_correlation_with(Duration(0), Duration(0), BIN, false);
    let ((_, _), cover_hb) = tape_and_correlation_with(span(DEFAULT_COVER_INTERVAL), Duration(0), BIN, true);
    let ((_, _), cover_no) = tape_and_correlation_with(span(DEFAULT_COVER_INTERVAL), Duration(0), BIN, false);
    let buys_hb = plain_hb - cover_hb;
    let buys_no = plain_no - cover_no;
    println!(
        "tape: {frames_hb} frames with heartbeat, {frames_no} without\n  \
         with heartbeat: undefended {plain_hb:.4} cover-only {cover_hb:.4} buys {buys_hb:.4}\n  \
         without:        undefended {plain_no:.4} cover-only {cover_no:.4} buys {buys_no:.4}"
    );
    // The attribution itself: the heartbeat is the tape, not a contribution to it.
    assert!(
        frames_hb > 5 * frames_no,
        "the claim is that the heartbeat DOMINATES; it carried {frames_hb} against {frames_no}"
    );
    // And the consequence: the cover's measured effect is an order of magnitude larger once the series is
    // not something else's. A `>` on the difference rather than a pinned figure — the point is the gap.
    assert!(
        buys_no > 10.0 * buys_hb,
        "cover buys {buys_no:.4} on relay traffic against {buys_hb:.4} on the heartbeat-dominated tape; if \
         these have converged the attribution above is stale and the entry at DEFAULT_COVER_INTERVAL needs \
         re-reading"
    );
}

/// **The control that settles it: the figure is unchanged when the relay carries nothing.**
///
/// The test above shows the heartbeat dominates the tape. Dominance still leaves room for the relay to
/// contribute something, and "dominated by" is a weaker claim than the measurement supports. This runs the
/// identical span with the drive removed — no sealed onions, no forwarding, nothing through `forward_send`
/// — and then re-runs it at **ten times the cargo**, because one dose cannot tell a small real effect from
/// a tolerance fitted to one sighting of it.
///
/// # The tolerance is measured now, and the first one was chosen
///
/// The original guard was `|Δ| < 0.01`, picked because the two staggered arms then read `−0.0038` and
/// `−0.0067`. That is a constant fitted to a single sample of a noisy statistic, and 146 commits of overlay
/// work later the same arms read `+0.0045` and `−0.0112`: the property held, the fitted line did not, and
/// the suite went red for a figure that had moved by one part in seventy. [[the-guard-becomes-the-defect]].
///
/// What replaces it has no free parameter. Deleting a fraction `f` of the observations cannot move a
/// *normalized second moment* of them by more than `f`, to first order — so the guard is
///
/// ```text
///   |r(with cargo) − r(without)|  ≤  cargo frames / tape frames
/// ```
///
/// with both sides measured in this same run. It tightens by itself as the heartbeat's share of the tape
/// grows, which is the direction a guard should move.
///
/// # The dose sweep behind it
///
/// Measured 2026-08-21, `BIN = 100 ms`, one run per cell (the sim is deterministic — three runs, one inside
/// a fully loaded workspace sweep, returned byte-identical figures):
///
/// ```text
///                      cargo    tape       f          r           Δ      Δ/f
///   synchronised
///     quiet                0    4872              1.000000
///     ×1                 100    4972    0.020     1.000000    0.000000   0.00
///     ×10                995    5867    0.170     1.000000    0.000000   0.00
///     ×80               2833    7705    0.368     1.000000    0.000000   0.00
///   staggered  71 ms
///     quiet                0    4886              0.747573
///     ×1                 100    4986    0.020     0.752080   +0.004507   0.22
///     ×10               1000    5886    0.170     0.695416   −0.052157   0.31
///     ×80               2823    7709    0.366     0.773762   +0.026189   0.07
///   staggered 149 ms
///     quiet                0    4931              0.754543
///     ×1                 100    5031    0.020     0.743389   −0.011154   0.56
///     ×10                995    5926    0.168     0.748066   −0.006477   0.04
///     ×80               2823    7754    0.364     0.781607   +0.027064   0.07
/// ```
///
/// `Δ/f` never reaches `1` and does not grow with the dose — quadrupling the cargo from `×20` to `×80`
/// *lowers* it. The tightest reading is `0.56`, at the shipping dose, so the guard sits `1.8×` above the
/// worst measurement rather than on top of it. The sweep runs `×1` and `×10`; `×80` is recorded here
/// because it is the evidence that the bound is the right *shape* and not another fitted number.
///
/// # Falsified, and it fires on the property it is about
///
/// `drive`'s send pattern is *deliberately aperiodic* — its own comment says so, and until now nothing
/// checked it. Replacing the ten aperiodic send times with ten evenly spaced ones, **same 100 frames of
/// 4986, same 2 % dose**, moves the 71 ms arm from `0.7476` to `0.8020`: `0.0544`, or **2.71 f**, and this
/// guard fails at its own assertion with the message above. Aperiodic cargo at the same dose reads `0.56 f`.
///
/// So the bound is not merely arithmetic that happens to hold — it discriminates on exactly the thing that
/// distinguishes a perturbation from a leak, which is whether the deleted frames carried correlated
/// structure. The old `|Δ| < 0.01` would have caught this too, but by a fitted number rather than by the
/// property, and it had already begun failing on figures that carried no structure at all.
///
/// # The synchronised arm is not the weak case, it is the strongest one
///
/// At a synchronised start the two arms return **the same float** — bit for bit, asserted as such — and
/// they keep returning it at every dose up to `2833 of 7705 frames`, **37 % of the tape**. An observable
/// that does not move when 37 % of its input is deleted is not measuring that input, and saying so needs no
/// tolerance at all.
///
/// **Note the sign.** Without cargo `r` goes *up* at the shipping dose. The relay's traffic is a small
/// aperiodic perturbation on a periodic signal's self-correlation, so its only effect on this observable is
/// to *decorrelate* it slightly — the opposite direction from a leak. The sign is also not stable across
/// arms (`+0.0045` at 71 ms against `−0.0112` at 149 ms), which is what an effect indistinguishable from
/// zero looks like and what a leak never looks like. Any reading of these figures as "the relay leaks" has
/// the sign backwards as well as the subject wrong.
///
/// **What the residual is.** `fanos_testkit::gpa`'s own doc warns that a periodic signal correlates with its
/// own shifts at a value the period fixes, which is why `drive` is deliberately aperiodic. The heartbeat is
/// perfectly periodic and it is 98% of the tape, so a lag-scanning adversary whose window spans the period
/// locks onto it. Synchronised starts push that to exactly `1.0000`; staggering the starts drops it to
/// `≈ 0.75`, which is the periodicity floor rather than anything causal — and `0.75` is high enough that the
/// residual would read as a leak to anyone who did not run this control.
#[test]
fn the_gpa_figure_does_not_move_when_the_relay_carries_nothing() {
    const BIN: u64 = 100;
    // The shipping drive, and ten times it. See the doc: one dose cannot separate a bounded response from
    // a fitted tolerance, and the ratio `Δ/f` is only a dose-response statement if there are two doses.
    const DOSES: [usize; 2] = [1, 10];
    for (label, stagger) in [("synchronised", 0u64), ("staggered 71 ms", 71), ("staggered 149 ms", 149)] {
        let ((quiet_frames, _), no_cargo) =
            tape_correlation_full(Duration(0), Duration(0), BIN, true, false, stagger);
        for dose in DOSES {
            let ((frames, _), with_cargo) =
                tape_correlation_dense(Duration(0), Duration(0), BIN, true, true, stagger, dose);
            let cargo = frames.saturating_sub(quiet_frames);
            let share = cargo as f64 / frames as f64;
            let moved = (with_cargo - no_cargo).abs();
            println!(
                "{label} x{dose}: cargo {cargo} of {frames} (f {share:.4}), r {with_cargo:.6} vs \
                 {no_cargo:.6}, moved {moved:.6} = {:.2} f",
                moved / share
            );
            assert!(
                moved <= share,
                "{label} x{dose}: deleting {cargo} of {frames} frames — a fraction {share:.4} of the tape \
                 — moved this figure by {moved:.6}, MORE than the fraction deleted. A normalized second \
                 moment cannot do that unless the deleted frames carried the correlation, so the relay's \
                 traffic now reaches this observable and every figure in DEFAULT_COVER_INTERVAL's entry \
                 can be re-read as being about the relay."
            );
            if stagger == 0 {
                // Bit-for-bit, deliberately: at a synchronised start the heartbeat saturates the figure at
                // 1.0, and the two arms do not merely agree to some tolerance — they return the same float.
                // A comparison on the bits says that without inviting a lint about comparing floats.
                assert_eq!(
                    with_cargo.to_bits(),
                    no_cargo.to_bits(),
                    "a synchronised start saturates this figure; {cargo} cargo frames of {frames} changed \
                     it from {no_cargo:.6} to {with_cargo:.6}, so it is no longer saturated and the \
                     staggered arms' periodicity floor needs re-deriving"
                );
            }
        }
    }
}

/// **The measurement #181 actually asked for, on a tape that is the relay's own — and the mix delay is not
/// the dead branch this file recorded.**
///
/// The two tests above establish that the figures in `DEFAULT_COVER_INTERVAL`'s entry describe the overlay
/// heartbeat and are unchanged when the relay carries nothing. That leaves the question the entry exists to
/// answer *open*: on its own traffic, does either defence do anything?
///
/// Measured with the heartbeat off, so the tape is cargo, at bins finer and coarser than the `120 ms` mean:
///
/// ```text
///   bin    undefended   cover-only   delay-only   cover buys   delay buys
///    20ms      0.8518       0.6256       0.6110       0.2262       0.2408
///    50ms      0.8243       0.7381       0.7109       0.0862       0.1135
///   100ms      0.8789       0.8186       0.8519       0.0603       0.0270
///   250ms      0.9592       0.9414       0.9523       0.0178       0.0069
///   500ms      0.9742       0.9664       0.9876       0.0079      −0.0134
/// ```
///
/// Every row is printed by the test below over this file's own `BIN_SWEEP_MS`, so the table cannot drift
/// from what runs.
///
/// **At fifteen repeats of the drive, and that is a correction of this test's own first version.** It read
/// its figures off the single-pass drive: 100 frames across seven nodes and twelve seconds, five non-empty
/// bins per node, and one node reporting `r = 1.0000` from three aligned events. A Pearson over a series
/// that is 95% zeros measures coincidence. The conclusion survived the denser sample — at 20 ms the delay
/// buys `0.2408` against the cover's `0.2262`, slightly *more* rather than less — but the first sample could
/// not have supported it, which is why the tape size is now asserted.
///
/// **`delay buys 0.000` was the ruler, not the delay.** At a `250 ms` bin a `120 ms` mean displacement moves
/// nothing across bin boundaries and the column reads zero — which is exactly the figure the old table
/// reported at *every* width, because on a heartbeat-dominated tape the relay's displacement was invisible
/// at any resolution. At `20 ms` the delay buys `0.2263`, within a hair of what the cover buys, and the
/// result is stable across traffic density: at 5× and 15× the same drive the pair reads
/// `(0.267, 0.252)` and `(0.226, 0.241)`.
///
/// So #181's decision criterion — *"composing two defences is worth its latency only if the second one does
/// something on its own"* — is met, and the conclusion recorded against it was drawn from an instrument that
/// could not see either defence. This does not by itself say the two should be composed: `forward_send`
/// still cannot express cover+delay, and what latency the pair costs is a separate measurement. It says the
/// branch is live.
#[test]
fn on_its_own_traffic_the_mix_delay_buys_as_much_as_the_cover() {
    // A bin finer than the mean displacement, or the ruler decides the answer — this file's own rule,
    // applied to the arm it was never applied to.
    const FINE: u64 = 20;
    // **Density, because a Pearson over a series that is 95% zeros measures coincidence.** The file's own
    // drive puts 100 frames on a heartbeat-free tape across seven nodes and twelve seconds — five non-empty
    // bins per node, and one of them read `r = 1.0000` off three aligned events. Fifteen repeats of the same
    // aperiodic pattern is ~1500 frames, and the figures below are stable against 5 repeats (see the doc).
    const REPEATS: usize = 15;
    // The whole sweep is printed, not just the row the claim rests on: the same ruler discipline this file
    // applies to the cover, and it is what shows `delay buys` decaying to zero as the bin passes the mean.
    println!("clean tape (heartbeat off), by bin width:");
    println!("  bin    undefended   cover-only   delay-only   cover buys   delay buys");
    let mut fine = (0.0, 0.0, 0.0);
    let mut frames = 0usize;
    for bin in BIN_SWEEP_MS {
        let ((f, _), p) = tape_correlation_dense(Duration(0), Duration(0), bin, false, true, 0, REPEATS);
        let c = tape_correlation_dense(span(DEFAULT_COVER_INTERVAL), Duration(0), bin, false, true, 0, REPEATS).1;
        let d = tape_correlation_dense(Duration(0), span(DEFAULT_MIX_DELAY), bin, false, true, 0, REPEATS).1;
        println!("{bin:5}ms      {p:.4}       {c:.4}       {d:.4}       {:.4}       {:.4}", p - c, p - d);
        if bin == FINE {
            fine = (p, c, d);
            frames = f;
        }
    }
    let (plain, cover, delay) = fine;
    // The sample, asserted before the statistic: the thin version of this test computed its figures over a
    // tape of 100 frames and would have kept doing so silently.
    assert!(
        frames > 1_000,
        "a Pearson needs a series that is not mostly zeros: the undefended tape carried {frames} frames"
    );
    assert!(plain > 0.8, "the undefended control must leak, or nothing below means anything: {plain:.4}");
    assert!(
        plain - delay > 0.15,
        "the mix delay must do something ON ITS OWN at a bin finer than its mean — the old table's \
         `delay buys 0.000` was measured on a tape the relay barely touched. Got {:.4}",
        plain - delay
    );
    // Stated as a comparison rather than two pinned figures: the claim that overturns the record is that the
    // delay is in the same class as the cover, not that it hits a particular number.
    assert!(
        (plain - delay) > 0.5 * (plain - cover),
        "the delay must be in the same class as the cover, not an order below it: delay buys {:.4}, cover \
         buys {:.4}",
        plain - delay,
        plain - cover
    );
}

