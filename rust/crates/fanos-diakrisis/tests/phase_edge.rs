//! Does the collective's aliveness fall in a **step** where the coupling that gates it grows smoothly?
//! (#275, UHM `1ea2b27`)
//!
//! # The question the theory forced
//!
//! UHM swept exchange strength across a colony of seven while measuring *two* quantities — coupling (mean
//! pairwise Bures distance) and aliveness — and found they move differently: *"coupling grows smoothly,
//! aliveness falls in a step. A colony a third closer is still all conscious; one half closer — none."*
//! Its own honesty frame is "engineering results on a seven-dimensional reference implementation", which
//! is the Fano cell's dimension, so T-316's stratum rule does not discount the transfer.
//!
//! FANOS measures **one**. `classify_collective` decided all three collective states by comparing the
//! smooth scalar `r` against a band. If aliveness steps somewhere the band does not mark, the classifier
//! reports a healthy collective subject that is already dead — the shape of #184 and #99.
//!
//! # Why the experiment must leave the equicorrelated stratum
//!
//! On that stratum the question is not askable: `Φ`, `P` and `R` are bijections of each other (#101), so
//! aliveness is a deterministic function of `r` and the band edge `r_over = √(2/(N−1))` is *derived* to sit
//! exactly where `R = 1/3`. The two agree by construction, and a test there could only ever confirm.
//!
//! So the cell here is deliberately **off** the stratum, in the shape FANOS actually has: three nodes of one
//! Fano line exchanging heavily while the other four exchange lightly. Every matrix comes from
//! [`CoherenceMatrix::from_signals`] — a correlation matrix of real signals is positive semi-definite by
//! construction, so no sweep point is an unreachable state ([[a-probe-must-admit-only-reachable-states]]).

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use fanos_diakrisis::coherence::{CoherenceMatrix, PHI_TH, R_TH};
use fanos_diakrisis::window::CollectiveState;

/// Cell size: the Fano plane's node count, and the size UHM's colony was measured at.
const N: usize = 7;
/// Samples per node. Large enough that the estimator's noise is far below the effects being separated.
const T: usize = 8192;

/// A deterministic, reproducible pseudo-signal — the sweep must give the same answer on every machine, and
/// a seeded LCG is the whole requirement (no cryptographic property is used or claimed).
fn noise(seed: u64, len: usize) -> Vec<f64> {
    let mut s = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..len)
        .map(|_| {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            // Top 32 bits are the well-mixed ones in an LCG; map to (-1, 1).
            f64::from((s >> 32) as u32) / f64::from(u32::MAX) * 2.0 - 1.0
        })
        .collect()
}

/// The cell at exchange strength `lambda`, off the equicorrelated stratum.
///
/// Each node holds its own signal mixed with the cell's shared one at its **own** weight: the first three
/// (one Fano line) at full weight, the remaining four at 0.7 of it — mild enough that the sweep still
/// carries the cell through the whole band, asymmetric enough that  is a summary rather than a
/// description. That asymmetry is the whole point —
/// it is what makes `r` a summary rather than a description, and it is the shape a real cell has, where a
/// line carries traffic the rest of the plane does not.
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

/// One sweep point: what the classifier says, and whether the cell is actually alive.
///
/// Read straight off the matrix. This used to fold through `VitalSigns`, a summary at this layer that
/// claimed to be the canonical one and was constructed by nobody in production; it was deleted with #277,
/// and the reason is visible right here — its `ready` was `Φ ≥ 1 ∧ R ≥ 1/3` with no third conjunct,
/// because *provenance is not a property of a matrix*. `integrated` and `self_modelling` below are those
/// two numeric conjuncts, kept apart and named, which is all this sweep ever needed from it.
struct Point {
    lambda: f64,
    r: f64,
    phi: f64,
    reflection: f64,
    integrated: bool,
    self_modelling: bool,
    collective: CollectiveState,
}

fn sweep() -> Vec<Point> {
    (0..=60)
        .map(|k| {
            let lambda = f64::from(k) / 60.0;
            let g = cell_at(lambda);
            let m = g.measures();
            Point {
                lambda,
                r: g.mean_correlation(),
                phi: m.phi,
                reflection: m.reflection,
                integrated: m.phi >= PHI_TH - 1e-9,
                self_modelling: m.reflection >= R_TH - 1e-9,
                collective: g.collective_state(),
            }
        })
        .collect()
}

/// The classifier's verdict and the cell's aliveness must change at the same place, or one of them is
/// describing a cell that is not there.
#[test]
fn the_band_must_mark_the_place_where_the_cell_stops_being_alive() {
    let points = sweep();

    // The coupling axis must actually move, or the sweep proves nothing about either quantity.
    let (r_lo, r_hi) = (points[0].r, points[points.len() - 1].r);
    assert!(
        r_hi - r_lo > 0.5,
        "the sweep moved coupling from {r_lo:.4} to {r_hi:.4} — too little to separate a smooth rise from \
         a step, so no verdict below would mean anything"
    );

    for p in &points {
        println!(
            "λ={:.3}  r={:.4}  Φ={:.4}  R={:.4}  integrated={}  self_modelling={}  {:?}",
            p.lambda, p.r, p.phi, p.reflection, p.integrated, p.self_modelling, p.collective
        );
    }

    // The LOWER disagreement is not asserted here, and deliberately so: `classify_collective`'s own doc
    // names `Φ > 1` with the mean below the floor as the *under-coupled band*, a used feature. Reading
    // that as a defect would be indicting a function without reading it.
    //
    // The UPPER edge is a different animal, and no doc claims it. `is_overcoupled` defines itself as
    // "`r > √(2/(N−1))`, **equivalently** `R < 1/3`" — an equivalence that holds on the equicorrelated
    // stratum and breaks off it. When it breaks, the cell has lost the self-model the threshold exists to
    // protect while the classifier still reports a healthy collective subject, and `Decouple` — whose
    // trigger this is — does not fire.
    let late: Vec<&Point> = points
        .iter()
        .filter(|p| p.reflection < R_TH - 1e-9 && p.collective != CollectiveState::OverCoupled)
        .collect();

    assert!(
        late.is_empty(),
        "{} sweep point(s) have lost the self-model (R < 1/3) while still classified as a healthy \
         collective subject — worst at λ={:.3}: r={:.4} sits below the band edge, but the measured R is \
         {:.4} and Φ is {:.4}, past the Φ = 2 the edge was solved at. The band is a two-parameter law \
         (r, p) read on a three-parameter cell; off-diagonal dispersion raises the real Φ above what the \
         law predicts from r, so the `Decouple` trigger arrives late — and only ever late, never early \
         (#275, UHM 1ea2b27)",
        late.len(),
        late[0].lambda,
        late[0].r,
        late[0].reflection,
        late[0].phi,
    );
}
