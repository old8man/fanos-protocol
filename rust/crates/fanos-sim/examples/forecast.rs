//! `forecast` — drive the coherence observatory through a building cascade and print the
//! trajectory, so the leading-indicator forecast is visible: the systemic warning (`r > r*`)
//! fires a measurable lead time *before* the first node fails (spec §2.7, V15).
//!
//! Run: `cargo run -p fanos-sim --example forecast`
#![allow(clippy::print_stdout, clippy::indexing_slicing, clippy::float_cmp)]

use fanos_diakrisis::window::Alarm;
use fanos_sim::{HealthField, forecast_cascade};

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
    match (
        forecast.warn_progress,
        forecast.fail_progress,
        forecast.lead(),
    ) {
        (Some(w), Some(f), Some(lead)) => {
            println!("Cascade early-warning at progress {w:.2}; first node failed at {f:.2}.");
            println!(
                "FORECAST LEAD TIME = {lead:.2} of the cascade — collapse was called before it happened."
            );
        }
        _ => println!("No cascade detected (resilient regime)."),
    }
}
