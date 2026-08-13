//! `forecast` — drive the coherence observatory through a building cascade and print the
//! trajectory, so the leading-indicator forecast is visible: the systemic warning (`r > r*`)
//! fires a measurable lead time *before* the first node fails (spec §2.7, V15).
//!
//! Run: `cargo run -p fanos-sim --example forecast`
#![allow(clippy::print_stdout, clippy::indexing_slicing, clippy::float_cmp)]

use fanos_diakrisis::window::Alarm;
use fanos_sim::{ForecastVerdict, HealthField, forecast_cascade};

fn main() {
    let n = 7;
    let field = HealthField::uniform(n, 1.0);
    let fail_thresh = 0.30;
    let forecast = forecast_cascade(&field, 40, 512, fail_thresh, 0xF0_1234);

    println!(
        "Cascade forecast on a {n}-node cell (r* = 1/√6 ≈ 0.408, fail below health {fail_thresh}):\n"
    );
    println!("  progress    r     Φ      P     alarm        systemic  live");
    println!("  --------  -----  -----  -----  -----------  --------  ----");
    for (progress, r, live) in &forecast.trajectory {
        let alarm = match r.alarm {
            Alarm::Healthy => "Healthy",
            Alarm::Integration => "Integration",
            Alarm::Structure => "Structure",
        };
        let warn = if *progress == forecast.warn_progress.unwrap_or(-1.0) {
            "  <-- CASCADE WARNING"
        } else if *progress == forecast.fail_progress.unwrap_or(-1.0) {
            "  <-- FIRST FAILURE"
        } else {
            ""
        };
        println!(
            "   {:5.2}    {:5.3}  {:5.2}  {:5.3}  {:<11}  {:^8}  {:>3}{}",
            progress,
            r.mean_correlation,
            r.phi,
            r.purity,
            alarm,
            if r.systemic { "YES" } else { "-" },
            live,
            warn
        );
    }

    println!();
    // One line per world, and the two that contradict V15 leave through a non-zero exit. The gate
    // runs this example as a phase, so before this it reported `ok` on a sweep where the leading
    // indicator had missed the cascade outright — and printed "resilient regime" while it did.
    //
    // Note that this sweep is NOT the one the unit test pins. `the_cascade_is_forecast_before_any
    // _node_fails` uses 50 steps / window 256 / seed 0xF00D; this uses 40 / 512 / 0xF0_1234. That
    // is the point of running it at all: a second sample of the same claim, at a different point
    // in the parameter space, taken on every gate run. A second sample whose verdict is discarded
    // is not a second sample.
    let verdict = forecast.verdict();
    match verdict {
        ForecastVerdict::Forecast { lead } => {
            let (w, f) = (forecast.warn_progress, forecast.fail_progress);
            println!(
                "Cascade early-warning at progress {:.2}; first node failed at {:.2}.",
                w.unwrap_or(f64::NAN),
                f.unwrap_or(f64::NAN)
            );
            println!(
                "FORECAST LEAD TIME = {lead:.2} of the cascade — collapse was called before it happened."
            );
        }
        ForecastVerdict::NoCascade => {
            println!("No cascade detected: no node fell below the threshold and no warning fired.");
        }
        ForecastVerdict::WarnedWithoutFailure { warn } => {
            println!(
                "Warning fired at progress {warn:.2} and no node ever failed — an alarm this sweep \
                 could not confirm, not a quiet run."
            );
        }
        ForecastVerdict::MissedTheCascade { fail } => {
            println!(
                "V15 VIOLATED: a node failed at progress {fail:.2} and the systemic warning never \
                 fired. The leading indicator was blind to a real cascade."
            );
        }
        ForecastVerdict::WarnedTooLate { lag } => {
            println!(
                "V15 VIOLATED: the warning arrived {lag:.2} of the cascade AFTER the first failure. \
                 A leading indicator that trails is not one."
            );
        }
    }

    if verdict.violates_v15() {
        std::process::exit(1);
    }
}
