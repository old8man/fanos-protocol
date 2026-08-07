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

use fanos_diakrisis::coherence::{PHI_TH, R_TH, phi_equicorrelated, purity_equicorrelated};
use fanos_diakrisis::partition::{N, algebraic_connectivity};

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

    let phi = phi_equicorrelated(N, r);
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
        let f = phi_equicorrelated(N, probe);
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
        (phi_equicorrelated(N, lower) - PHI_TH).abs() < EPS,
        "at the lower edge Φ must equal the threshold exactly — that is what makes it the edge"
    );
    assert!(
        (phi_equicorrelated(N, upper) - 2.0).abs() < EPS,
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
