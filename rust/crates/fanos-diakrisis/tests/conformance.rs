//! **The DIAKRISIS constants this crate ships are the ones `conformance/vectors/diakrisis.json` specifies.**
//!
//! The vector was written and then nothing compared it to the code (#160). That matters more here than for
//! most vectors, because these are not encoding details: `systemic_correlation_r_star_7` is the lower edge of
//! the collective-subject band the homeostat regulates the cell into, and the band's width is what #99 derived
//! the observation window from. A drift between the vector and the constant moves the band silently, and the
//! window, the hysteresis and the escalation threshold move with it.
//!
//! Every scalar is checked against the **closed form** rather than against a transcription of the decimal.
//! `p_crit = 2/N` and `r_star = 1/sqrt(N-1)` are stated in the vector's own `general_forms`, so comparing the
//! decimal to `2.0 / 7.0` pins the derivation; comparing it to a copied literal would pin only that two humans
//! typed the same digits.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use fanos_diakrisis::coherence::{PHI_TH, R_TH, phi_at, purity_equicorrelated};
use fanos_diakrisis::minima::{OPTIMAL_INTEGRATION, max_stability_radius, optimal_purity};
use fanos_diakrisis::partition::{N, algebraic_connectivity};
use fanos_diakrisis::stability::{stability_radius, stability_radius_exact};

/// Tolerance for a value that survives at most a handful of IEEE-754 operations.
///
/// Not a round number chosen to make the test pass: every quantity here is one divide, one square root or one
/// multiply-add away from an exact rational, so the accumulated error is a few ULPs of a number near 1 — well
/// under 1e-15. Anything that fails at 1e-12 is a real disagreement, not rounding.
const EPS: f64 = 1e-12;

/// The vector, read from the repo root (`CARGO_MANIFEST_DIR` is `rust/crates/fanos-diakrisis`).
///
/// Read as text and scanned for `"key": <number>`, the same way `fanos-telemetry/tests/conformance.rs` does
/// it — a JSON dependency for four scalars would be the only reason this crate needed one.
fn vector() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../conformance/vectors/diakrisis.json");
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// The number `key` maps to — the first occurrence whose value PARSES AS A NUMBER.
///
/// The scan has to skip non-numeric matches because this vector states several quantities twice: once as the
/// closed form (`"phi": "(N - 1) * r^2"`) and once as a value at the critical point (`"phi": 1.0`). Taking
/// the first match blindly would read the formula string and fail to parse it, which cost one debugging
/// round here.
///
/// Panics when no numeric occurrence exists, rather than defaulting — a renamed field must break the test,
/// not quietly stop being checked.
fn num(text: &str, key: &str) -> f64 {
    let needle = format!("\"{key}\":");
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(&needle) {
        let after = from + rel + needle.len();
        let rest = &text[after..];
        let end = rest.find([',', '\n', '}']).unwrap_or(rest.len());
        if let Ok(v) = rest[..end].trim().parse::<f64>() {
            return v;
        }
        from = after;
    }
    panic!("diakrisis.json has no numeric value for key `{key}`")
}

#[test]
fn the_shipped_thresholds_are_the_ones_the_vector_specifies() {
    let v = &vector();

    assert_eq!(N, 7, "the vector is written for the base 7-cell");

    let phi_th = num(v, "phi_th");
    assert!((PHI_TH - phi_th).abs() < EPS, "PHI_TH = {PHI_TH}, vector says {phi_th}");

    let r_th = num(v, "r_th");
    assert!((R_TH - r_th).abs() < EPS, "R_TH = {R_TH}, vector says {r_th}");

    // `general_forms.p_crit = "2 / N"` — check the decimal against the form, not against a copy of itself.
    let p_crit = num(v, "p_crit_7");
    let p_crit_form = 2.0 / N as f64;
    assert!(
        (p_crit - p_crit_form).abs() < EPS,
        "p_crit_7 = {p_crit} but the vector's own general form 2/N gives {p_crit_form}"
    );

    // `general_forms.r_star = "1 / sqrt(N - 1)"`.
    let r_star = num(v, "systemic_correlation_r_star_7");
    let r_star_form = 1.0 / ((N - 1) as f64).sqrt();
    assert!(
        (r_star - r_star_form).abs() < EPS,
        "r_star_7 = {r_star} but 1/sqrt(N-1) gives {r_star_form}"
    );
}

#[test]
fn the_equicorrelated_closed_forms_reproduce_the_vectors_critical_point() {
    let v = &vector();
    let r = num(v, "r");
    let want_phi = num(v, "phi");
    let want_purity = num(v, "purity");
    let want_reflection = num(v, "reflection");

    let phi = phi_at(r, 1.0 / N as f64);
    let purity = purity_equicorrelated(N, r);
    let reflection = 1.0 / (N as f64 * purity);

    assert!((phi - want_phi).abs() < EPS, "Φ({N}, {r}) = {phi}, vector says {want_phi}");
    assert!((purity - want_purity).abs() < EPS, "P({N}, {r}) = {purity}, vector says {want_purity}");
    assert!(
        (reflection - want_reflection).abs() < EPS,
        "R = 1/(N·P) = {reflection}, vector says {want_reflection}"
    );

    // `equicorrelated_stratum.identity`: "Phi = N * P - 1". Checked at the critical point AND away from it,
    // because at r* it degenerates to 1 = 7·(2/7) − 1 and would hold for a wrong formula by coincidence.
    for probe in [0.0, 0.1, r, 0.5, 0.9] {
        let p = purity_equicorrelated(N, probe);
        let f = phi_at(probe, 1.0 / N as f64);
        assert!(
            (f - (N as f64 * p - 1.0)).abs() < EPS,
            "at r={probe}: Φ={f} but N·P−1={}", N as f64 * p - 1.0
        );
    }
}

#[test]
fn the_collective_subject_band_is_the_vectors_half_open_interval() {
    let v = &vector();
    let n = num(v, "n") as usize;
    let lower = num(v, "lower_exclusive");
    let upper = num(v, "upper_inclusive");
    assert_eq!(n, N, "the window is specified for the 7-cell");

    // The lower edge is r* — the same number as the systemic-correlation threshold, and the test says so
    // rather than repeating the decimal: if the two ever diverge, the band and the threshold have parted.
    let r_star = num(v, "systemic_correlation_r_star_7");
    assert!((lower - r_star).abs() < EPS, "the band's lower edge {lower} is not r* = {r_star}");

    // Φ at the edges: exclusive lower means Φ > 1 strictly inside, inclusive upper means Φ ≤ 2 at the top.
    assert!(
        (phi_at(lower, 1.0 / N as f64) - PHI_TH).abs() < EPS,
        "at the lower edge Φ must equal the threshold exactly — that is what makes it the edge"
    );
    assert!(
        (phi_at(upper, 1.0 / N as f64) - 2.0).abs() < EPS,
        "at the upper edge Φ must equal 2 — the R = 1/3 boundary, Φ ≤ 2 ⟺ R ≥ R_TH"
    );
    assert!(upper > lower, "a half-open interval with a positive width");
}

#[test]
fn the_partition_sensor_reproduces_the_vectors_fiedler_values() {
    let v = &vector();
    let full = num(v, "full_cell_lambda2");
    let one_down = num(v, "one_line_down_lambda2");

    // All seven Fano lines healthy → the complete-graph value; one line down → the vector's degraded value.
    let all_healthy = 0x7F;
    assert!(
        (algebraic_connectivity(all_healthy) - full).abs() < 1e-9,
        "λ₂(full cell) = {}, vector says {full}", algebraic_connectivity(all_healthy)
    );
    let one_line_down = 0x7F & !1;
    assert!(
        (algebraic_connectivity(one_line_down) - one_down).abs() < 1e-9,
        "λ₂(one line down) = {}, vector says {one_down}", algebraic_connectivity(one_line_down)
    );
    assert!(one_down < full, "losing a line must lower the connectivity, or the sensor senses nothing");
}

/// The stability radius — the quantity that was wrong for months and had no vector until #188.
///
/// It is the input to the DDoS shed law, it derived the band setpoint, and it is what the observatory
/// dashboard and the `fanos_coherence_stability_radius` gauge serve. It was refuted **toward danger** —
/// `√(P − 2/N)` overstates the margin by up to 81.7× at the viability wall — and none of the nine vectors
/// would have said so, because none of them mentioned it. Nine less-consequential quantities did.
///
/// Checked against the vector's own stated closed forms, never against a transcribed decimal.
#[test]
fn both_stability_radius_forms_reproduce_the_vector() {
    let v = &vector();
    let phi_star = num(v, "phi_star");
    let purity = |phi: f64| (phi + 1.0) / N as f64;

    // The runtime form the homeostat steers on.
    assert!((stability_radius(purity(1.1), N) - num(v, "runtime_at_phi_1_1")).abs() < 1e-9, "runtime @ Φ=1.1");
    assert!((stability_radius(purity(phi_star), N) - num(v, "runtime_at_phi_star")).abs() < 1e-9, "runtime @ Φ*");
    assert!((max_stability_radius(N) - num(v, "runtime_at_phi_2_ceiling")).abs() < 1e-9, "runtime ceiling");

    // The exact form the report serves. A single test for both is deliberate: they are a PAIR, and a change
    // that silently collapsed one onto the other would pass two separate tests and fail this one.
    assert!((stability_radius_exact(purity(1.1), N) - num(v, "exact_at_phi_1_1")).abs() < 1e-9, "exact @ Φ=1.1");
    assert!((stability_radius_exact(purity(phi_star), N) - num(v, "exact_at_phi_star")).abs() < 1e-9, "exact @ Φ*");
    assert!(
        (stability_radius_exact(3.0 / N as f64, N) - num(v, "exact_at_phi_2_ceiling")).abs() < 1e-9,
        "exact ceiling"
    );
    assert!(
        stability_radius_exact(3.0 / N as f64, N) > max_stability_radius(N),
        "the two forms must stay distinct — the runtime one is an approximation of the exact one, not an alias"
    );
}

/// The root, which is the invariant the rest of the correction rests on.
///
/// Both the refuted surd and the corrected law are zero on exactly `P ≤ 2/N`. That is *why* every claim
/// reading only the root — the fault-count table, the tolerated fault fraction — survived T-104 untouched
/// while every claim about the curve's shape had to be redone. Pinning it makes that argument checkable
/// instead of a sentence in a document.
///
/// **This test is expected to PASS under the refuted law, and that is the point.** Falsified by swapping
/// `stability_radius` back to `√(P − 2/N)`: the three shape-dependent tests in this file fail and this one
/// does not — which is the root-vs-shape distinction demonstrated rather than asserted. A future reader
/// falsifying this file should not read that pass as a vacuous assertion; the discriminating tests are its
/// three siblings.
#[test]
fn the_radius_vanishes_exactly_on_the_viability_shell() {
    let v = &vector();
    let p_crit = 2.0 / N as f64;
    for &(p, what) in &[(p_crit, "at the shell"), (p_crit - 0.01, "below it"), (p_crit - 0.2, "far below")] {
        assert!((stability_radius(p, N) - num(v, "at_p_crit")).abs() < EPS, "runtime {what}");
        assert!((stability_radius_exact(p, N) - num(v, "below_p_crit")).abs() < EPS, "exact {what}");
    }
    // And strictly positive immediately above it, or "zero" would be uninformative.
    assert!(stability_radius(p_crit + 1e-6, N) > 0.0, "positive just above the shell");
    assert!(stability_radius_exact(p_crit + 1e-6, N) > 0.0, "positive just above the shell (exact)");
}

/// The setpoint, pinned by the property that DEFINES it rather than by its digits.
///
/// `Φ*` is the max-min point: the band has two opposite failures, so the robust point maximises the smaller
/// distance, and equalising them gives `√Φ* = (1 + √2)/2`. The scale `K/√N` cancels in that balance, so the
/// answer is the same on every plane — a claim worth checking rather than restating, since it is what lets a
/// single constant serve all four dispatchable plane orders.
#[test]
fn the_setpoint_equalises_the_two_band_distances_on_every_plane() {
    let v = &vector();
    assert!((OPTIMAL_INTEGRATION - num(v, "phi_star")).abs() < EPS, "Φ* matches the vector");
    assert!((optimal_purity(N) - num(v, "purity_star_7")).abs() < EPS, "P* matches the vector");

    for n in [7usize, 13, 21, 57, 993] {
        let r = |phi: f64| stability_radius((phi + 1.0) / n as f64, n);
        let (down, up) = (r(OPTIMAL_INTEGRATION) - r(1.0), r(2.0) - r(OPTIMAL_INTEGRATION));
        assert!((down - up).abs() < 1e-12, "N={n}: the setpoint must equalise the distances, {down} vs {up}");
    }
}

/// The **negative** vector: what the law is not.
///
/// Pinning only the right answer does not stop anyone re-deriving the wrong one, and this exact surd shipped
/// for months. The vector records it, and this checks the two facts that make it dangerous: it overstates at
/// the wall, and — the part that makes "just rescale the old numbers" wrong — it does **not** err in one
/// direction. The laws cross between `N = 57` and `N = 993`.
#[test]
fn the_refuted_surd_is_pinned_as_a_counter_example() {
    let v = &vector();
    let refuted = |p: f64, n: usize| (p - 2.0 / n as f64).max(0.0).sqrt();

    assert!((refuted(3.0 / 7.0, 7) - num(v, "ceiling_at_7")).abs() < 1e-9, "the surd's Fano ceiling");
    // Overstates near the wall, by a lot.
    let near_wall = 2.0 / 7.0 + 1e-4;
    assert!(
        refuted(near_wall, 7) > stability_radius(near_wall, 7) * 20.0,
        "the surd must overstate the margin near the wall by an order of magnitude or more"
    );
    // …and yet UNDERSTATES on a wide plane. Both directions, or the "not uniformly wrong" claim is decoration.
    assert!(refuted(3.0 / 7.0, 7) > max_stability_radius(7), "overstates the ceiling at N = 7");
    assert!(refuted(3.0 / 993.0, 993) < max_stability_radius(993), "UNDERSTATES the ceiling at N = 993");
}
