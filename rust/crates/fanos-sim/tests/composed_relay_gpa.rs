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
//! # SCOPE, and it is narrower than the title
//!
//! **This drives overlay `Send`s, which never enter `ThresholdRouter::forward_send`** — see
//! `a_plain_overlay_send_never_reaches_the_relays_mixing_branch`, which asserts exactly that after the first
//! version of this file nearly reported a mixing figure the mixing branch had not produced. What is
//! measured here is therefore the GPA's read on a composed relay cell's **overlay** traffic: real, never
//! measured before, and not the forwarding path.
//!
//! Finishing #181 step 2 needs the probe to be a sealed onion — `seal_forward` over a `meeting_line`, the
//! way `composed_relay.rs` builds one — so the cells actually traverse the router. Until then the
//! `delay-only` column below is a control that reads zero for a known reason, not a verdict on the delay.
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
    let mut sim = Sim::new(SEED);
    let cell = spawn_composed_relay_cell::<F2>(&mut sim, Config::default(), cover, mix, true);
    sim.inject_all(&Command::StartHeartbeat); // arms the cover schedule where there is one
    sim.observe_frames(); // the GPA starts tapping

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
    let send_at_ms = [400u64, 1400, 1600, 3200, 5000, 5200, 5400, 8000, 9800, 10_000];
    let mut sent = 0usize;
    let mut now = 0u64;
    while now < WINDOW_MS {
        while sent < send_at_ms.len() && send_at_ms[sent] <= now {
            let seed = [b'g', b'p', b'a', u8::try_from(sent).unwrap()];
            let fwd = seal_forward::<F2>(&[hop, meeting], &dir, ONION_T, b"gpa-probe", &seed)
                .expect("the circuit seals");
            sim.inject_frame(entry, fwd.combiner, fwd.frame.clone());
            sent += 1;
        }
        sim.run_for(Duration::from_millis(STEP_MS));
        now += STEP_MS;
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
    // The SUM of every timestamp, not the count and the last one: a proxy that cannot see ten frames
    // displaced by 120 ms among 4882 would report "the branch did not run" for a branch that did.
    let shape = (tape.len(), tape.iter().map(|o| o.t_ms).sum::<u64>());
    (shape, r)
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
