//! What does the ε-private export cost in *accuracy*, separately from what it costs in noise? (#222)
//!
//! # The question
//!
//! [`CoherenceFrame::privatize`] releases one scalar — the Laplace-noised mean correlation — and then
//! **re-derives everything else from it**: `Φ`, `P`, `R`, the regime, the alarm and the integrated bit all
//! come from `CoherenceMatrix::equicorrelated(CELL_N, r̃)`. That is sound privacy engineering: one release,
//! and every other field is post-processing, so the whole frame is ε-DP for the price of one.
//!
//! It also means **every frame that leaves a cell describes a flat cell**, whatever the real one looks
//! like. Those are two different costs riding in one mechanism, and only the first has ever been stated:
//!
//! - the **noise** cost, bounded by ε and derived (`Δr = 1/21`);
//! - the **model** cost — substituting an equicorrelated cell for the measured one — which is not a
//!   function of ε at all and does not shrink as ε grows.
//!
//! # How the two are separated
//!
//! By taking ε enormous. At `ε = 10^9` the Laplace scale is `Δr/ε ≈ 5·10⁻¹¹`, far below anything that
//! moves a verdict, so whatever difference survives is the **model** alone. A test that used a realistic ε
//! could not tell the two apart, and would have measured the wrong thing
//! ([[discrimination-needs-differing-inputs]]).
//!
//! The cell is deliberately off the equicorrelated stratum, in the shape FANOS has: three nodes of one Fano
//! line exchanging heavily while the other four exchange lightly. Every matrix comes from
//! [`CoherenceMatrix::from_signals`], so it is a real correlation matrix and no state is unreachable.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use core::convert::Infallible;

use fanos_diakrisis::coherence::CoherenceMatrix;
use fanos_telemetry::{AlarmLevel, CellId, CoherenceFrame, PrivacyBudget, R_SENSITIVITY, Regime};
use rand_core::TryRng;

const N: usize = 7;
const T: usize = 8192;

/// A deterministic pseudo-signal — the answer must not move between machines.
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

/// The cell at exchange strength `lambda`, off the stratum: one Fano line at full weight, four at 0.7.
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

/// A generator that returns one fixed word. `laplace` is `b·(E₁ − E₂)` with both exponentials drawn from
/// this same constant, so the two cancel and the noise is **exactly zero** — not merely small. That is
/// what isolates the model error: nothing in the difference below can be attributed to the draw. The huge
/// ε is belt-and-braces, so the reading holds even if the cancellation ever stops being exact.
struct Still;
impl TryRng for Still {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0x5EED_5EED)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0x5EED_5EED_5EED_5EED)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(0x5E);
        Ok(())
    }
}

/// The measured magnitude of the model cost, pinned so the number the docs quote stays true.
///
/// This is a **characterisation**, not a bug report. Re-deriving from one release is what buys the ε-DP
/// guarantee for the price of a single Laplace draw, and there is no free alternative: the regime is a
/// function of the peers' behaviour, so carrying it truthfully is a second release with a second
/// sensitivity nobody has derived. What was missing is that the trade was never *stated*, so a consumer —
/// `Census` above all, which asks "is my cell sick, or the network?" off exactly these frames — had no way
/// to know the verdict it reads describes a cell that does not exist.
///
/// If someone later releases the diagonal purity with its own sensitivity, this goes red and the doc it
/// guards must move with it.
#[test]
fn the_export_substitutes_a_flat_cell_and_that_costs_a_whole_regime() {
    // Find a cell the substitution changes. Proving such a cell exists comes FIRST — a sweep that never
    // produced one would make the assertion below vacuous.
    let mut disagreement = None;
    for k in 0..=400 {
        let g = cell_at(f64::from(k) / 400.0);
        let exact = CoherenceFrame::observe(CellId([7; 16]), 3, &g, 0, 0.0, -1, 0, true);
        let exported = exact.privatize(PrivacyBudget::new(1e9), &mut Still);
        if exact.regime() != exported.regime() {
            disagreement = Some((g, exact, exported));
            break;
        }
    }

    let Some((g, exact, exported)) = disagreement else {
        panic!(
            "no sweep point changed regime under export. Either the export stopped substituting a flat \
             cell — in which case the cost this test characterises is gone and every doc quoting it must \
             be corrected — or the sweep never left the stratum, which would make the reading vacuous. \
             Check `cell_at` before concluding the former (#222)"
        );
    };

    let m = g.measures();
    println!(
        "measured cell: r={:.4}  Φ={:.4}  P={:.4}  R={:.4}  p={:.4}  regime={:?}",
        g.mean_correlation(),
        m.phi,
        m.purity,
        m.reflection,
        g.diagonal_purity(),
        g.collective_state()
    );
    println!(
        "exported frame: r={:.4}  Φ={:.4}  P={:.4}  R={:.4}  regime={:?}  alarm={:?}",
        exported.mean_r,
        exported.phi,
        exported.purity,
        exported.reflection,
        exported.regime(),
        exported.alarm()
    );

    // The mean correlation must survive intact, or the difference below is noise after all rather than the
    // model — this is the control that makes the reading a measurement.
    assert!(
        (f64::from(exact.mean_r) - f64::from(exported.mean_r)).abs() < 1e-6,
        "at ε = 1e9 the release must be effectively exact (Δr = {R_SENSITIVITY}); r went {} → {}",
        exact.mean_r,
        exported.mean_r
    );

    // The cell is barely off the stratum — `p = 0.1432` against a flat `1/7 = 0.1429`, two parts in a
    // thousand — and the verdict still flips. The work is done by the third parameter neither the flat form
    // nor `Φ = r²(1−p)/p` carries: off-diagonal **dispersion**, which raises the true `Φ` above what any
    // function of `(r, p)` predicts. `phi_at(0.5613, 0.1432) = 1.885`, essentially the flat `1.8905`, while
    // the cell measures `2.0092`. So this is not "a concentrated cell reads differently"; it is "any cell
    // whose pairwise couplings are not all equal reads differently", which is every real cell.
    assert_eq!(
        (exact.regime(), exported.regime()),
        (Regime::OverCoupled, Regime::CollectiveSubject),
        "the measured cost changed. The docs quote this exact flip — a cell the reflex calls over-coupled \
         exports as a healthy collective subject — and if the pair has moved, `privatize`'s doc, the dp \
         module header and docs/design-telemetry.md §DP are all now wrong (#222)"
    );
    assert_eq!(
        exported.alarm(),
        AlarmLevel::Healthy,
        "the exported alarm is Healthy here — worth pinning, because `Census` reads `alarm()`, not \
         `regime()`, so this is the field that decides the network-wide verdict"
    );

    // And the size of it, so the doc can quote a number rather than an adjective.
    let (true_phi, flat_phi) = (f64::from(exact.phi), f64::from(exported.phi));
    println!(
        "model cost at this cell: Φ {true_phi:.4} → {flat_phi:.4} ({:+.1}%), R {:.4} → {:.4}, and R \
         crosses the 1/3 self-model floor in the wrong direction",
        (flat_phi - true_phi) / true_phi * 100.0,
        exact.reflection,
        exported.reflection,
    );
    assert!(
        f64::from(exact.reflection) < 1.0 / 3.0 && f64::from(exported.reflection) >= 1.0 / 3.0,
        "the flip must be the self-model floor being crossed, not some other coincidence: measured R = \
         {}, exported R = {}",
        exact.reflection,
        exported.reflection
    );
}

/// **Would releasing the diagonal purity close it?** (#278, step 3 before step 1.)
///
/// The obvious fix for the cost above is to release `p` alongside `r` with its own derived sensitivity, so
/// the re-derivation has the second parameter. Deriving `Δp` is real work, and the task that proposes it
/// carries an explicit warning: *measure whether the second parameter helps before deriving its Δ.* This
/// is that measurement, and it is cheap — no sensitivity, no privacy, no noise. It asks one question:
/// **given `(r, p)` exactly, how often does the re-derived regime still differ from the cell's own?**
///
/// Three verdicts per sweep point:
/// 1. the cell's own, from the full matrix;
/// 2. the **flat** re-derivation, `equicorrelated(7, r)` — what `privatize` does today;
/// 3. the **two-parameter** re-derivation, `Φ = r²(1−p)/p`, `P = p(1+Φ)`, `R = 1/(NP)` — what releasing
///    `p` would buy, evaluated at the *exact* `p`, which is the most generous version of the proposal.
///
/// If (3) is no better than (2), the proposal is answering the wrong question and the honest fix is
/// different: stop shipping verdict bits a consumer will read as the cell's own.
#[test]
fn releasing_the_diagonal_purity_is_measured_before_its_sensitivity_is_derived() {
    let n = N as f64;
    let (mut flat_wrong, mut two_wrong, mut both_wrong, mut points) = (0usize, 0usize, 0usize, 0usize);
    let mut first_two_param_miss = None;

    for k in 0..=400 {
        let g = cell_at(f64::from(k) / 400.0);
        let (r, p) = (g.mean_correlation(), g.diagonal_purity());
        let truth = g.collective_state();

        // (2) the flat model, exactly as `privatize` builds it.
        let flat = CoherenceMatrix::equicorrelated(N, r).collective_state();

        // (3) the two-parameter model at the exact p — the proposal's best case.
        let phi2 = fanos_diakrisis::coherence::phi_at(r, p);
        let purity2 = p * (1.0 + phi2);
        let reflection2 = if purity2 > 0.0 { 1.0 / (n * purity2) } else { 0.0 };
        let two = fanos_diakrisis::window::classify_collective(r, p, reflection2);

        points += 1;
        let (f_bad, t_bad) = (flat != truth, two != truth);
        flat_wrong += usize::from(f_bad);
        two_wrong += usize::from(t_bad);
        both_wrong += usize::from(f_bad && t_bad);
        if t_bad && first_two_param_miss.is_none() {
            first_two_param_miss = Some((r, p, g.measures().phi, phi2, truth, two));
        }
    }

    println!(
        "over {points} sweep points: the FLAT re-derivation misses the regime {flat_wrong} times; the \
         TWO-PARAMETER one at the exact p misses it {two_wrong} times ({both_wrong} of those are the same \
         points)"
    );
    if let Some((r, p, phi_true, phi_two, truth, two)) = first_two_param_miss {
        println!(
            "first two-parameter miss: r={r:.4} p={p:.4} — the cell measures Φ={phi_true:.4}, the law \
             gives Φ={phi_two:.4} ({:+.1}%), so {truth:?} reads as {two:?}",
            (phi_two - phi_true) / phi_true * 100.0
        );
    }

    // The sweep must exercise the flat failure, or the comparison has no baseline.
    assert!(
        flat_wrong > 0,
        "the flat model got every point right on this sweep, so there is nothing for the second parameter \
         to improve and this measurement is vacuous"
    );

    // THE FINDING. If the second parameter closed it, this would be zero and #278 would be worth its
    // derivation. It is not: `Φ = r²(1−p)/p` is still a two-parameter law read on a cell whose off-diagonal
    // DISPERSION is a third, and dispersion is what raises the true Φ above what any function of (r, p)
    // predicts.
    assert!(
        two_wrong > 0,
        "the two-parameter re-derivation got every point right — releasing `p` WOULD close the export's \
         model cost, so #278's derivation of Δp is worth doing and this assertion must be inverted"
    );
}
