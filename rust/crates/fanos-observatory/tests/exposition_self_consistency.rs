//! Can one scrape of the exposition contradict itself? (#277)
//!
//! # The question
//!
//! A [`CoherenceFrame`] carries the cell's regime as a **verdict bit**, set at the source by
//! `CoherenceMatrix::collective_state()` — the general law, which reads the cell's own diagonal for the
//! lower band edge and its **measured** reflection for the upper one (#219, #275). The observatory renders
//! that verdict as `fanos_coherence_regime` and folds it into `fanos_diakrisis_verdict`.
//!
//! Beside those two lines it also emits `fanos_coherence_cascade_alarm` and
//! `fanos_coherence_over_coupling_alarm`, and those were **re-derived at the consumer** by comparing the
//! frame's `mean_r` against `R_STAR = 1/√6` and `OVER_COUPLING = 1/√3`. Both constants are the *flat*
//! closed forms `1/√(N−1)` and `√(2/(N−1))` frozen at `N = 7`: they answer the same question as the
//! regime, on the equicorrelated stratum only.
//!
//! So one scrape carries two answers to one question, computed by two different laws. Off the stratum
//! they part — and an operator's alerting rule reads the *gauge*, while the dashboard reads the
//! *verdict*.
//!
//! # Why the cell here is deliberately lopsided
//!
//! On the equicorrelated stratum the question is not askable: there `Φ = r²(1−p)/p` at `p = 1/N` reduces
//! to the flat form, the two laws are the same line, and any cell would agree. This test therefore builds
//! the shape FANOS actually has — three nodes of one Fano line exchanging heavily while the other four
//! exchange lightly — through [`CoherenceMatrix::from_signals`], so every sweep point is a real
//! correlation matrix and no state is unreachable. It is the same construction as
//! `fanos-diakrisis/tests/phase_edge.rs`, which asks the *classifier* the question this file asks the
//! *exposition*.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use fanos_diakrisis::coherence::CoherenceMatrix;
use fanos_diakrisis::window::CollectiveState;
use fanos_observatory::{HealthSummary, render_openmetrics};
use fanos_telemetry::{CellId, CoherenceFrame, CoherenceSnapshot, OVER_COUPLING, R_STAR, Regime};

/// Cell size: the Fano plane's node count.
const N: usize = 7;
/// Samples per node — far above the noise floor of the effects being separated.
const T: usize = 8192;

/// A deterministic pseudo-signal: the sweep must give the same answer on every machine, and a seeded LCG
/// is the whole requirement (no cryptographic property is used or claimed).
fn noise(seed: u64, len: usize) -> Vec<f64> {
    let mut s = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..len)
        .map(|_| {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            f64::from((s >> 32) as u32) / f64::from(u32::MAX) * 2.0 - 1.0
        })
        .collect()
}

/// The cell at exchange strength `lambda`, off the equicorrelated stratum: one Fano line at full weight,
/// the remaining four at 0.7 of it.
fn cell_at(lambda: f64) -> CoherenceMatrix {
    let shared = noise(0x00C0_FFEE, T);
    let weights = [1.0, 1.0, 1.0, 0.7, 0.7, 0.7, 0.7];
    let signals: Vec<Vec<f64>> = (0..N)
        .map(|i| {
            let own = noise(0x5EED + i as u64, T);
            let w = lambda * weights[i];
            own.iter()
                .zip(&shared)
                .map(|(&o, &s)| (1.0 - w) * o + w * s)
                .collect()
        })
        .collect();
    CoherenceMatrix::from_signals(&signals).expect("real signals give a PSD correlation matrix")
}

/// The first sweep point the general law calls `OverCoupled` while the mean correlation is still **below**
/// the flat over-coupling edge — the cell on which the two laws disagree.
///
/// Returned rather than asserted-on inline so the discriminator's existence is proved before anything is
/// concluded from it: a sweep that never produced such a point would make every assertion below vacuous.
fn a_cell_the_two_laws_disagree_about() -> Option<CoherenceMatrix> {
    (0..=400).find_map(|k| {
        let g = cell_at(f64::from(k) / 400.0);
        (g.collective_state() == CollectiveState::OverCoupled
            && g.mean_correlation() < OVER_COUPLING)
            .then_some(g)
    })
}

/// The exposition must not answer one question two ways. A cell the frame's own verdict calls
/// over-coupled must not scrape as an un-alarmed cell.
#[test]
fn one_scrape_must_not_contradict_itself_about_the_regime() {
    let g = a_cell_the_two_laws_disagree_about()
        .expect("the sweep must reach a cell the flat edge and the general law disagree about, or \
                 nothing below is a test");
    let m = g.measures();
    let r = g.mean_correlation();
    println!(
        "the disagreeing cell: r={r:.4} (flat edge {OVER_COUPLING:.4}), Φ={:.4}, P={:.4}, R={:.4}, \
         regime={:?}",
        m.phi,
        m.purity,
        m.reflection,
        g.collective_state()
    );

    let frame = CoherenceFrame::observe(CellId([0x11; 16]), 42, &g, 0, 0.5, -1, 0, true);
    let snap = CoherenceSnapshot::from_frame(&frame);
    assert_eq!(
        snap.regime,
        Regime::OverCoupled,
        "the frame must carry the general law's verdict, or this test is measuring the wrong thing"
    );

    let text = render_openmetrics(&snap);
    let value = |name: &str| -> f64 {
        text.lines()
            .find(|l| l.starts_with(&format!("{name}{{")))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("no sample line for {name} in:\n{text}"))
    };

    // The property: the alarm gauge and the regime the same scrape publishes are one answer. An operator
    // whose alerting rule reads the gauge and whose dashboard reads the verdict must not see a healthy
    // cell and a systemic one at the same instant.
    assert!(
        (value("fanos_coherence_over_coupling_alarm") - 1.0).abs() < 1e-12,
        "this scrape publishes `fanos_coherence_regime{{state=\"over_coupled\"}} 1` and \
         `fanos_diakrisis_verdict{{state=\"systemic\"}} 1`, while \
         `fanos_coherence_over_coupling_alarm` reads {} — the gauge re-derives the regime from \
         `mean_r >= 1/√3`, which is the FLAT edge at N = 7, and this cell is at r = {r:.4} with a \
         measured R = {:.4} < 1/3. The response to over-coupling is to shed correlation, and the line \
         that would trigger it is the silent one (#277)",
        value("fanos_coherence_over_coupling_alarm"),
        m.reflection,
    );

    // The same defect one edge down: `Aggregate` is exactly "below the lower band edge", and the cascade
    // gauge answers it from the flat `r*` instead of the regime that is already in the frame.
    assert!(
        (value("fanos_coherence_cascade_alarm") - 1.0).abs() < 1e-12,
        "the cell is past the lower band edge (regime = {:?}, not Aggregate) while \
         `fanos_coherence_cascade_alarm` reads {} — the same flat-proxy re-derivation, at r* = 1/√6",
        snap.regime,
        value("fanos_coherence_cascade_alarm"),
    );

    // `HealthSummary` is the `/healthz` face of the same snapshot and carried the same re-derivation.
    let health = HealthSummary::from_snapshot(&snap);
    assert!(
        health.cascade_alarm,
        "the compact health summary — the shape an alerting rule reads without parsing the metrics \
         text — disagrees with the verdict it is derived from: regime={:?}, cascade_alarm={}",
        snap.regime, health.cascade_alarm,
    );
}

/// The flat edges must stay *reachable* as documentation of where the stratum's lines are — this pins
/// that they are the numbers they claim to be, so a reader who sees them in a doc knows what they mean
/// and a future edit cannot quietly redefine them into a live threshold again.
#[test]
fn the_flat_edges_are_the_stratum_constants_they_claim_to_be() {
    assert!((R_STAR - 1.0 / 6.0_f64.sqrt()).abs() < 1e-12, "r* = 1/√6 at N = 7");
    assert!(
        (OVER_COUPLING - 1.0 / 3.0_f64.sqrt()).abs() < 1e-12,
        "the over-coupling edge = √(2/6) = 1/√3 at N = 7"
    );
    // And they are the flat window's two edges, which is the claim that makes them stratum-bound: the
    // general `collective_subject_window_at(p)` reproduces them at, and only at, a flat diagonal.
    let (lo, hi) = fanos_diakrisis::window::collective_subject_window_at(1.0 / N as f64);
    assert!((lo - R_STAR).abs() < 1e-12, "the general lower edge at p = 1/N is r*");
    assert!(
        (hi - OVER_COUPLING).abs() < 1e-12,
        "the general upper edge at p = 1/N is 1/√3"
    );
}
