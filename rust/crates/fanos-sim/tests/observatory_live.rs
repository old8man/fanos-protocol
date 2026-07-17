//! The coherence observatory, driven by a **live** crash-cascade rather than the synthetic
//! `HealthField`. We sample ground-truth liveness of a running cell over time into one behavioural
//! signal per node and read `Γ_net` off it. The claim under test: the observatory discriminates a
//! *correlated* collapse (nodes failing together — a real cascade) from *independent* churn (nodes
//! failing at unrelated times) on real run data. A synchronized collapse pushes the mean correlation
//! across `r* = 1/√6` (systemic); scattered churn stays diversified below it.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss
)]

use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration};
use fanos_sim::{Sim, read, spawn_cell};

/// Run a 7-cell, crash `victims` on the given per-victim sample schedule, and sample ground-truth
/// liveness every tick into one signal per node. Returns the observatory reading over the window.
fn cascade_reading(
    seed: u64,
    schedule: &[(usize, usize)],
    samples: usize,
) -> fanos_sim::CoherenceReading {
    let mut sim = Sim::new(seed);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(1500));

    let mut signals: Vec<Vec<f64>> = vec![Vec::with_capacity(samples); cell.len()];
    for tick in 0..samples {
        for &(victim, at) in schedule {
            if at == tick {
                sim.crash(cell[victim]);
            }
        }
        sim.run_for(Duration::from_millis(200));
        for (i, v) in sim.liveness_snapshot(&cell).into_iter().enumerate() {
            signals[i].push(v);
        }
    }
    read(&signals).unwrap()
}

#[test]
fn a_correlated_collapse_reads_systemic_but_independent_churn_does_not() {
    let samples = 24;
    // Correlated: six of seven nodes fail in one tight burst (a real cascade).
    let burst: Vec<(usize, usize)> = (0..6).map(|v| (v, 12)).collect();
    let correlated = cascade_reading(0xCA5, &burst, samples);

    // Independent: the same six failures, scattered across the window (incidental churn).
    let spread: Vec<(usize, usize)> = (0..6).map(|v| (v, 3 + v * 3)).collect();
    let independent = cascade_reading(0xCA5, &spread, samples);

    assert!(
        correlated.mean_correlation > independent.mean_correlation,
        "a synchronized collapse is read as more coherent than scattered churn: {:.3} vs {:.3}",
        correlated.mean_correlation,
        independent.mean_correlation
    );
    assert!(
        correlated.systemic,
        "the correlated collapse crosses r*: r = {:.3}",
        correlated.mean_correlation
    );
    assert!(
        !independent.systemic,
        "scattered churn stays diversified below r*: r = {:.3}",
        independent.mean_correlation
    );
}
