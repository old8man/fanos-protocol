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
    cell_shaped(lambda, 1.0, 0.7)
}

/// The same construction with the two weights exposed, so a sweep can cover cells of differing
/// **dispersion** rather than one shape at differing strength.
///
/// `line_w == rest_w` puts the cell back on the equicorrelated stratum, which is the control the sweep
/// needs: on the stratum the export is exact by construction, so any flip found there would be a bug in the
/// harness rather than a reading about the model.
fn cell_shaped(lambda: f64, line_w: f64, rest_w: f64) -> CoherenceMatrix {
    let shared = noise(0x00C0_FFEE, T);
    let weights = [line_w, line_w, line_w, rest_w, rest_w, rest_w, rest_w];
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
        (Some(Regime::OverCoupled), Some(Regime::CollectiveSubject)),
        "the measured cost changed. The docs quote this exact flip — a cell the reflex calls over-coupled \
         exports as a healthy collective subject — and if the pair has moved, `privatize`'s doc, the dp \
         module header and docs/design-telemetry.md §DP are all now wrong (#222)"
    );
    assert_eq!(
        exported.alarm(),
        Some(AlarmLevel::Healthy),
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

/// A deterministic LCG, so the miss counts below are the same on every machine. Numerical recipes'
/// constants; quality is irrelevant here — what is measured is how a verdict moves under Laplace noise of
/// a given scale, not the noise's own statistics.
struct Lcg(u64);
impl TryRng for Lcg {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok((self.try_next_u64()? >> 32) as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        Ok(self.0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let w = self.try_next_u64()?.to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&w[..n]);
        }
        Ok(())
    }
}

/// Laplace(0, b) from two uniforms, matching `dp::laplace`'s `b·(E₁ − E₂)` shape.
fn laplace(b: f64, rng: &mut Lcg) -> f64 {
    let mut e = || {
        let u = (rng.try_next_u64().unwrap_or(1) >> 11) as f64 / (1u64 << 53) as f64;
        -(1.0 - u).max(f64::MIN_POSITIVE).ln()
    };
    b * (e() - e())
}

/// **#278 branch (a), decided by an upper bound instead of a derivation.**
///
/// The open question is whether releasing three statistics — `r`, the diagonal purity `p`, and the
/// off-diagonal dispersion `v`, since the verdict is a function of exactly `(N, r, p, v)` — beats today's
/// single release. It costs the ε budget split three ways, so each statistic carries **three times** the
/// noise. The task says explicitly: do not start by deriving `Δp` and `Δv`; measure first, because the
/// last proposal here ("just release `p`") was refuted by a measurement after being written down as the
/// answer.
///
/// This is that measurement, and it is shaped so the derivation is not needed at all. Branch (a) is given
/// its **best possible case**:
///
/// * today's arm: `r` noised at `Δr/ε` — the real `privatize`, full budget — then the flat model;
/// * branch (a)'s arm: `r` noised at `Δr/(ε/3)` — the honest three-way split — but `p` and `v` **exact**,
///   with *zero* noise, which is better than any `Δp`/`Δv` derivation could ever deliver.
///
/// If the bounded arm does not beat today's, no sensitivity derivation can make branch (a) win, because
/// the derivation can only add noise to an arm that is already losing. That closes the branch with an
/// argument rather than with work — and if it *does* win, the margin is the budget for deriving the two
/// sensitivities, which is the number the task asks for.
#[test]
fn splitting_the_budget_three_ways_is_bounded_before_any_sensitivity_is_derived() {
    const EPSILON: f64 = 1.0;
    const DRAWS: usize = 200;
    let n = N as f64;
    let mut rng = Lcg(0x0D15_EA5E_0BAD_C0DE);

    let (mut today_wrong, mut split_wrong, mut trials) = (0usize, 0usize, 0usize);

    for k in 0..=400 {
        let g = cell_at(f64::from(k) / 400.0);
        let (r, p, v) = (g.mean_correlation(), g.diagonal_purity(), g.dispersion());
        let truth = g.collective_state();

        for _ in 0..DRAWS {
            trials += 1;

            // TODAY: the whole ε on `r`, then the flat re-derivation `privatize` performs.
            let r_today = (r + laplace(R_SENSITIVITY / EPSILON, &mut rng)).clamp(-1.0 / (n - 1.0), 1.0);
            if CoherenceMatrix::equicorrelated(N, r_today).collective_state() != truth {
                today_wrong += 1;
            }

            // BRANCH (a), BOUNDED: a third of ε on `r`, and `p`/`v` for free. The law is the exact one the
            // verdict is a function of — `Φ = (N−1)(r² + v)`, `P = p(1 + Φ)`, `R = 1/(N·P)` — so nothing
            // here is a model error. Only the tripled noise on `r` is.
            let r_split =
                (r + laplace(R_SENSITIVITY / (EPSILON / 3.0), &mut rng)).clamp(-1.0 / (n - 1.0), 1.0);
            let phi3 = (n - 1.0) * (r_split * r_split + v);
            let purity3 = p * (1.0 + phi3);
            let reflection3 = if purity3 > 0.0 { 1.0 / (n * purity3) } else { 0.0 };
            if fanos_diakrisis::window::classify_collective(r_split, p, reflection3) != truth {
                split_wrong += 1;
            }
        }
    }

    let today_rate = today_wrong as f64 / trials as f64;
    let split_rate = split_wrong as f64 / trials as f64;
    println!(
        "over {trials} trials at ε={EPSILON}: TODAY (whole ε on r, flat model) misses the regime \
         {today_wrong} times ({:.2}%); BRANCH (a) BOUNDED (ε/3 on r, exact p and v, exact law) misses it \
         {split_wrong} times ({:.2}%)",
        today_rate * 100.0,
        split_rate * 100.0,
    );

    // The measurement must be able to see a miss at all, or the comparison is between two zeros.
    assert!(
        today_wrong > 0,
        "today's arm was right on every trial, so this sweep cannot compare anything — the noise scale or \
         the sweep is wrong, not the finding",
    );

    // **THE FINDING, and it went the other way from the proposal.** Branch (a) loses badly — 16.77 %
    // against 6.53 % at ε = 1 — with `p` and `v` handed to it exactly and for free. The model error this
    // whole task is about (substituting a flat cell) costs 5 regime misses over 401 points at zero noise;
    // tripling the noise on `r` costs about 2.6× more than that. The single release is not merely the
    // convenient design, it is the more accurate one, and now by a number.
    //
    // Since deriving `Δp` and `Δv` can only ADD noise to the arm that is already losing, no sensitivity
    // derivation can reverse this. Branch (a) is closed by a bound rather than by work — which is exactly
    // what the task asked for when it said to measure before deriving.
    //
    // The assertion pins the MEASURED direction. If a future change flips it — a different verdict
    // boundary, a plane order where the model error grows, a tighter `Δr` — this reddens, and #278's
    // branch (a) has to be re-opened with the new number in hand rather than from the old intuition.
    assert!(
        split_rate > today_rate,
        "branch (a) now BEATS today's export ({:.2}% vs {:.2}%), which the bound above said it could not. \
         Something that changes the balance has changed: re-open #278 branch (a), derive Δp and Δv, and \
         re-run this with the real noise on all three statistics — the margin here is the budget for that \
         work.",
        split_rate * 100.0,
        today_rate * 100.0,
    );

    // And the margin is stated, not merely ordered: a factor, so a future reader can see whether a change
    // moved it a little or inverted it.
    println!(
        "branch (a)'s best possible case is {:.1}× worse than today's export — the noise cost of splitting \
         ε dominates the model cost it was meant to remove",
        split_rate / today_rate,
    );
}

/// How bad a level is, as a number that can be compared — a local copy of the fold `Census` uses.
///
/// Deliberately a copy rather than an import: `fanos-telemetry` does not depend on `fanos-node`, and the
/// point of the sweep below is to characterise the *frame*, not that one consumer's arithmetic.
fn severity(level: AlarmLevel) -> u8 {
    match level {
        AlarmLevel::Healthy => 0,
        AlarmLevel::Integration => 1,
        AlarmLevel::Structure => 2,
    }
}

/// Can the export **hide** a real alarm, or only invent a false one? (#278 branch (b))
///
/// This is the question that decides whether the model cost is a defect in the code or a defect in the
/// documentation. `Census` — the one production consumer of these frames — folds `alarm()` from every
/// published frame into a per-cell worst level and answers "is my cell sick, or the network?" off it. The
/// frames it reads are all privatized, so every level in that answer is the flat model's, never a cell's
/// own.
///
/// Two directions, and they are not equally bad:
///
/// - **Invented** (`exported` worse than `exact`): a cell that is fine is published as alarmed. Costly and
///   noisy, but it errs the way the rest of the census errs — toward looking, not toward comfort.
/// - **Hidden** (`exported` better than `exact`): a cell in real trouble publishes as healthy, and the
///   operator's only cell-level instrument goes quiet exactly when it should not. That is a silent
///   failure, and if it exists the export cannot keep shipping a verdict at all.
///
/// The sweep covers shapes as well as strengths, because the model error is driven by off-diagonal
/// **dispersion**: `Φ_true = (N−1)(r² + v)` against the flat `Φ_flat = (N−1)r²`. One shape at many `λ`
/// would measure a line through the space, not the space.
#[test]
fn measure_whether_the_export_can_hide_a_real_alarm_or_only_invent_one() {
    let mut hidden: Vec<(f64, f64, f64, AlarmLevel, AlarmLevel)> = Vec::new();
    let mut invented: Vec<(f64, f64, f64, AlarmLevel, AlarmLevel)> = Vec::new();
    let mut agreed = 0usize;
    let mut on_stratum_flips = 0usize;
    let mut alarmed_exact = 0usize;

    for &line_w in &[1.0_f64, 0.9, 0.8, 0.6, 0.4, 0.2] {
        for &rest_w in &[1.0_f64, 0.7, 0.5, 0.3, 0.1, 0.0] {
            for k in 0..=100 {
                let lambda = f64::from(k) / 100.0;
                let g = cell_shaped(lambda, line_w, rest_w);
                let exact = CoherenceFrame::observe(CellId([7; 16]), 3, &g, 0, 0.0, -1, 0, true);
                let exported = exact.privatize(PrivacyBudget::new(1e9), &mut Still);
                // Unwrapped, and legitimately: both frames were produced by THIS build — `observe` encodes
                // the exact one and `privatize` re-encodes it — so an encoding neither can read back would
                // be a defect in this crate rather than a peer speaking a newer dialect. The sweep is about
                // the export's error direction, and swallowing an unreadable frame here would silently
                // shrink the denominator it reports.
                let (a, b) = (
                    exact.alarm().expect("this build encoded the exact frame"),
                    exported.alarm().expect("privatize re-encodes into the same vocabulary"),
                );
                if severity(a) > 0 {
                    alarmed_exact += 1;
                }
                if a == b {
                    agreed += 1;
                    continue;
                }
                // On the stratum (`line_w == rest_w`) the export rebuilds the very cell it measured, so a
                // flip there is the harness lying, not the model. Counted, and asserted zero below.
                if (line_w - rest_w).abs() < 1e-12 {
                    on_stratum_flips += 1;
                }
                let row = (lambda, line_w, rest_w, a, b);
                if severity(b) < severity(a) {
                    hidden.push(row);
                } else {
                    invented.push(row);
                }
            }
        }
    }

    let total = agreed + hidden.len() + invented.len();
    println!(
        "swept {total} cells: {agreed} agree, {} invent an alarm, {} hide one; {alarmed_exact} of the \
         cells are genuinely alarmed",
        invented.len(),
        hidden.len(),
    );

    // Controls first, or neither count means anything.
    assert!(
        alarmed_exact > 0,
        "not one cell in the sweep is alarmed in its EXACT reading, so 'the export never hides an alarm' \
         would be true of an empty set. Widen the sweep — the alarm needs Φ < 1, which needs low λ"
    );
    assert_eq!(
        on_stratum_flips, 0,
        "the export disagreed with the exact frame on an EQUICORRELATED cell, where it rebuilds the same \
         matrix it measured. That is a harness or `privatize` bug, not a model cost, and every number \
         below is suspect until it is explained"
    );

    for (lambda, lw, rw, a, b) in hidden.iter().take(8) {
        println!("  HIDDEN  λ={lambda:.2} line={lw:.1} rest={rw:.1}: exact {a:?} → exported {b:?}");
    }
    for (lambda, lw, rw, a, b) in invented.iter().take(8) {
        println!("  INVENT  λ={lambda:.2} line={lw:.1} rest={rw:.1}: exact {a:?} → exported {b:?}");
    }

    // **This is the load-bearing half, so it is an assertion and not a printout.** `Census`'s whole argument
    // for still shipping a published alarm at all — see its doc in `fanos-node/src/telemetry_dir.rs` — is
    // that the export errs the way the rest of that type errs, toward looking rather than toward comfort. A
    // single hidden alarm falsifies that argument: it would mean a cell below viability can publish as
    // healthy, and the census would have to stop reporting a foreign cell's level rather than merely
    // labelling it.
    assert!(
        hidden.is_empty(),
        "the ε-private export HID {} real alarm(s) — e.g. {:?}. `Census` documents the opposite direction \
         as measured fact and reports foreign cells' published levels on the strength of it. Re-open #278 \
         branch (b): the question is no longer 'whose verdict is this' but 'may a foreign cell's level be \
         reported at all'",
        hidden.len(),
        hidden.first(),
    );
    assert!(
        !invented.is_empty(),
        "no cell in the sweep had an alarm invented either, so this test now measures nothing. Either the \
         export stopped substituting a flat cell — in which case the 2.8% figure quoted in `Census`'s doc \
         and in `privatize`'s is stale — or the sweep no longer crosses the alarm boundary"
    );
}
