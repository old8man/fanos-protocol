//! The operator-facing **coherence snapshot** — a cell's vital signs, for humans *and* agents.
//!
//! A [`CoherenceFrame`] is the compact on-wire cell-aggregate observation. This folds it into a stable,
//! documented snapshot enriched with the *derived* operator quantities — the stability radius, the
//! theorem-fixed band thresholds, and a **readiness** verdict — and renders it as canonical JSON for
//! `fanos monitor --json` / OpenTelemetry / an agent consuming it programmatically. The bands are fixed
//! by theorems, not tuned: read *coherence*, not CPU. Readiness is `Φ ≥ 1 ∧ R ≥ 1/3` — a cell that is
//! one bound subject *and* still self-observing — which is the honest liveness gate a Kubernetes probe
//! or an SLO should read, in place of a hand-picked latency.

use alloc::string::String;
use core::fmt::Write as _;

use fanos_diakrisis::minima::OPTIMAL_INTEGRATION;
use fanos_diakrisis::stability::stability_radius;

use crate::frame::{AlarmLevel, CellId, CoherenceFrame, Regime};

/// The Fano cell size `N = 7` (the DIAKRISIS observation unit, spec §6).
pub const CELL_N: usize = 7;

/// The largest supported plane, `PG(2,31)` — the ceiling on a recovered node count.
///
/// Present because the previous estimate clamped to [`CELL_N`], which silently capped every reading from a
/// cell larger than Fano at seven.
pub const MAX_CELL_N: usize = 993;

/// Integration threshold: a cell is one bound subject iff `Φ ≥ 1` (spec §6, V11).
pub const PHI_THRESHOLD: f64 = 1.0;
/// Purity floor `P_crit = 2/N` — the viability boundary (T-104).
pub const PURITY_FLOOR: f64 = 2.0 / CELL_N as f64;
/// Reflection floor: self-observation holds iff `R ≥ 1/3` (V19).
pub const REFLECTION_FLOOR: f64 = 1.0 / 3.0;
/// Cascade early-warning line `r* = 1/√6 ≈ 0.4082` — the onset of the systemic/cascade regime (§2.7).
pub const R_STAR: f64 = 0.408_248_290_463_863;
/// Over-coupling bound `1/√3 ≈ 0.5774` — above this the cell loses its self-model (`R < 1/3`, V19).
pub const OVER_COUPLING: f64 = 0.577_350_269_189_626;

// The collective-subject band is the half-open interval `(r*, 1/√3]`, so its endpoints must be
// ordered. A compile-time guarantee (stronger than a runtime test): if the published constants were
// ever mistyped out of order, the crate would fail to build.
const _: () = assert!(R_STAR < OVER_COUPLING);

/// A cell's vital signs at one observation window, enriched for an operator.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CoherenceSnapshot {
    /// The cell this observes.
    pub cell_id: CellId,
    /// The agreed epoch of the observation.
    pub epoch: u64,
    /// Integration `Φ = 6r²` — is the cell one bound subject (`Φ ≥ 1`)? (the ECG.)
    pub phi: f64,
    /// Structuredness `P = Tr(Γ²)` — viable while `P > 2/N`.
    pub purity: f64,
    /// Reflection `R = 1/(N·P)` — self-observation holds while `R ≥ 1/3`.
    pub reflection: f64,
    /// Mean off-diagonal correlation `r` — compare against `r*` and the over-coupling bound.
    pub mean_correlation: f64,
    /// Polar spectral gap `Δ` (T-226(v)) — the healing-rate / density signal.
    pub spectral_gap: f64,
    /// Stability radius `r_stab = √(max(0, P − 2/N))` (T-104) — the viability speedometer.
    pub stability_radius: f64,
    /// The collective-subject band classification.
    pub regime: Regime,
    /// The leading-indicator alarm level.
    pub alarm: AlarmLevel,
    /// Whether a node fault is localized (`syndrome ≠ 0`).
    pub faulted: bool,
    /// The 3-bit fault syndrome (which points are degraded).
    pub syndrome: u8,
    /// Cascade forecast: ticks of lead time before a predicted cascade, or `-1` for none.
    pub cascade_lead: i16,
    /// The monotone self-healing action counter (a sparse healing timeline).
    pub heal_seq: u32,
    /// Readiness: `Φ ≥ 1 ∧ R ≥ 1/3` — bound *and* self-observing. The theorem-grounded liveness gate.
    pub ready: bool,
    /// The cell's alive-node count, recovered **exactly** as `N = 1/(R·P)`.
    ///
    /// Since `P = Tr(Γ²) = frob/n²` and `R = 1/(N·P) = n/frob`, their product is `1/n` on *any* coherence
    /// matrix. The compact 3-bit syndrome deliberately carries no count (Minimal Self-Observation Overhead
    /// theorem), and this recovers it from the measures already on the wire — no stratum assumption and no
    /// widening of the frame.
    ///
    /// It replaces an inversion of the equicorrelated identity `Φ = (N−1)·r²`, which was exact only for the
    /// liveness-only fold, approximate for frames built from measured per-node signals, undefined at `r ≈ 0`
    /// (a fully decorrelated cell — the *diversified* regime, not a fault), and clamped to [`CELL_N`], so a
    /// `PG(2,31)` cell reported at most seven alive nodes out of 993.
    ///
    /// Falls back to the binary syndrome signal only when `P = 0`, which means an unreadable matrix rather
    /// than any state a cell can be in.
    pub alive_nodes: u32,
    /// How far the cell sits from its **robust operating point**: `Φ − Φ*`, where `Φ* = 5/4`.
    ///
    /// Negative means under-coupled — nearer the collapse boundary than it needs to be; positive means nearer
    /// over-coupling. Zero is the point that maximizes the smaller of the two distances
    /// (`fanos_diakrisis::minima::OPTIMAL_INTEGRATION`, derived from the metric `r_stab` itself implies).
    ///
    /// **Why an operator needs it.** The band is `Φ ∈ (1, 2]` and [`Regime`] reports only *which* band the cell
    /// is in, so a cell at `Φ = 1.05` reads as a healthy collective subject, the homeostat correctly answers
    /// `Hold`, and nothing anywhere says its stability radius is a *third* of what the same cell could hold
    /// (`0.120` against `0.378` on a Fano plane). This is the number that says so.
    ///
    /// It reports; it does not steer. Teaching the homeostat to drive toward `Φ*` is a control-law change and
    /// is gated separately (`docs/open-tasks.md`).
    pub setpoint_offset: f64,
}

impl CoherenceSnapshot {
    /// Fold a [`CoherenceFrame`] into the operator snapshot, deriving `r_stab`, `alive_nodes`, and the
    /// readiness verdict.
    #[must_use]
    pub fn from_frame(frame: &CoherenceFrame) -> Self {
        let phi = f64::from(frame.phi);
        let purity = f64::from(frame.purity);
        let reflection = f64::from(frame.reflection);
        let mean_correlation = f64::from(frame.mean_r);
        let faulted = frame.is_faulted();
        // Recovered exactly from the frame's own measures, and used for *both* the node count and the
        // stability radius — `r_stab = √(P − 2/N)` was previously computed against a hard-coded seven, which
        // made the operator's headroom reading wrong on every cell that is not `PG(2,2)`.
        let alive = recover_cell_size(purity, reflection, faulted);
        Self {
            cell_id: frame.cell_id,
            epoch: frame.epoch,
            phi,
            purity,
            reflection,
            mean_correlation,
            spectral_gap: f64::from(frame.gap),
            stability_radius: stability_radius(purity, alive.max(1) as usize),
            regime: frame.regime(),
            alarm: frame.alarm(),
            faulted,
            syndrome: frame.syndrome,
            cascade_lead: frame.forecast,
            heal_seq: frame.heal_seq,
            ready: phi >= PHI_THRESHOLD && reflection >= REFLECTION_FLOOR,
            alive_nodes: alive,
            setpoint_offset: phi - OPTIMAL_INTEGRATION,
        }
    }

    /// Whether the cell is a healthy, self-observing subject (`Φ ≥ 1 ∧ R ≥ 1/3`) — the readiness /
    /// liveness gate an operator (human or agent) should probe, grounded in the theorems, not a latency.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// Whether a cascade is forecast (a non-negative lead time).
    #[must_use]
    pub fn cascade_imminent(&self) -> bool {
        self.cascade_lead >= 0
    }

    /// Canonical JSON — a flat, stable object for `fanos monitor --json` / OTLP / agent consumption.
    /// Field order and shape are fixed (KAT-pinned); non-finite scalars render as `null`.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push('{');
        s.push_str("\"cell_id\":\"");
        for b in self.cell_id.0 {
            let _ = write!(s, "{b:02x}");
        }
        s.push_str("\",");
        let _ = write!(s, "\"epoch\":{},", self.epoch);
        push_num(&mut s, "phi", self.phi);
        push_num(&mut s, "purity", self.purity);
        push_num(&mut s, "reflection", self.reflection);
        push_num(&mut s, "mean_correlation", self.mean_correlation);
        push_num(&mut s, "spectral_gap", self.spectral_gap);
        push_num(&mut s, "stability_radius", self.stability_radius);
        let _ = write!(s, "\"regime\":\"{}\",", self.regime.as_str());
        let _ = write!(s, "\"alarm\":\"{}\",", self.alarm.as_str());
        let _ = write!(s, "\"faulted\":{},", self.faulted);
        let _ = write!(s, "\"syndrome\":{},", self.syndrome);
        let _ = write!(s, "\"cascade_lead\":{},", self.cascade_lead);
        let _ = write!(s, "\"heal_seq\":{},", self.heal_seq);
        let _ = write!(s, "\"ready\":{},", self.ready);
        // Appended after the pre-existing fields (never inserted earlier): the doc-promised field
        // order of everything before it stays byte-identical for an existing consumer, and a fixed
        // terminal-width renderer (ui.rs) that only has room to show up through "ready" is unaffected.
        let _ = write!(s, "\"alive_nodes\":{},", self.alive_nodes);
        push_num_last(&mut s, "setpoint_offset", self.setpoint_offset);
        s.push('}');
        s
    }
}

/// [`push_num`] without the trailing comma, for the last field of the object.
fn push_num_last(s: &mut String, key: &str, v: f64) {
    if v.is_finite() {
        let _ = write!(s, "\"{key}\":{v}");
    } else {
        let _ = write!(s, "\"{key}\":null");
    }
}

/// Write `"key":<number>,` — a finite `f64` as a JSON number, non-finite as `null` (JSON has no NaN).
fn push_num(s: &mut String, key: &str, v: f64) {
    if v.is_finite() {
        let _ = write!(s, "\"{key}\":{v},");
    } else {
        let _ = write!(s, "\"{key}\":null,");
    }
}

/// Recover the cell's node count from the frame **exactly**: `N = 1/(R·P)`.
///
/// The measures are `P = Tr(Γ²) = frob/n²` and `R = 1/(N·P) = n/frob`, so their product is `1/n` on *any*
/// coherence matrix. No stratum assumption, no degeneracy, no division by a quantity that legitimately
/// approaches zero.
///
/// This replaces an inversion of the equicorrelated identity `Φ = (N−1)·r²`, which had three defects the exact
/// form does not:
///
/// * it held only on the equicorrelated stratum, and was documented as "approximate" elsewhere;
/// * it divided by `r²`, so a fully decorrelated cell — the *diversified* regime, not a fault — could not be
///   inverted at all and fell back to a binary syndrome guess;
/// * it clamped the result to `CELL_N`, so on `PG(2,31)` it reported at most 7 alive nodes out of 993.
///
/// `faulted` is retained only for the genuinely degenerate case `P = 0`, which means an empty or unreadable
/// matrix rather than any cell state.
fn recover_cell_size(purity: f64, reflection: f64, faulted: bool) -> u32 {
    let product = reflection * purity;
    let inverted = 1.0 / product;
    if product > 1e-12 && inverted.is_finite() {
        // No `f64::round()` in core-only no_std (it needs libm, and this crate's own `libm` feature only wires
        // the backend through to fanos-diakrisis, not to bare f64 methods here). Clamp to non-negative first,
        // then the classic round-to-nearest-via-truncation trick: adding 0.5 before the truncating cast rounds
        // correctly for any non-negative input.
        //
        // The upper clamp is the largest supported plane, not `CELL_N` — a `PG(2,31)` cell has 993 points and
        // clamping it to seven was the defect this replaced.
        let clamped = inverted.clamp(0.0, MAX_CELL_N as f64);
        (clamped + 0.5) as u32
    } else if faulted {
        (CELL_N - 1) as u32
    } else {
        CELL_N as u32
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;
    use fanos_diakrisis::coherence::CoherenceMatrix;

    /// A frame from an equicorrelated cell at correlation `r` over `alive` nodes.
    fn frame(r: f64) -> CoherenceFrame {
        let matrix = CoherenceMatrix::equicorrelated(7, r);
        CoherenceFrame::observe(CellId([0xAB; 16]), 9, &matrix, 0, 0.5, -1, 3)
    }

    #[test]
    fn readiness_is_phi_ge_1_and_r_ge_one_third() {
        // A healthy collective subject (r in the band) is integrated (Φ≥1) and self-observing (R≥1/3).
        let healthy = CoherenceSnapshot::from_frame(&frame(0.5));
        assert!(healthy.phi >= PHI_THRESHOLD, "Φ={} ≥ 1", healthy.phi);
        assert!(
            healthy.reflection >= REFLECTION_FLOOR,
            "R={} ≥ 1/3",
            healthy.reflection
        );
        assert!(healthy.is_ready(), "a healthy collective subject is ready");

        // A weakly-coupled aggregate (r small) is NOT integrated (Φ<1) → not ready.
        let aggregate = CoherenceSnapshot::from_frame(&frame(0.05));
        assert!(aggregate.phi < PHI_THRESHOLD, "Φ={} < 1", aggregate.phi);
        assert!(
            !aggregate.is_ready(),
            "an unintegrated aggregate is not ready"
        );
    }

    #[test]
    fn stability_radius_matches_the_theorem() {
        // r_stab = √(max(0, P − 2/7)); at the boundary purity it is 0.
        let snap = CoherenceSnapshot::from_frame(&frame(0.5));
        let expect = (snap.purity - PURITY_FLOOR).max(0.0).sqrt();
        assert!((snap.stability_radius - expect).abs() < 1e-9);
    }

    #[test]
    fn band_thresholds_match_their_closed_forms() {
        // The operator bands are theorem-fixed, not tuned — verify the published constants.
        assert!((R_STAR - 1.0 / 6.0_f64.sqrt()).abs() < 1e-12, "r* = 1/√6");
        assert!(
            (OVER_COUPLING - 1.0 / 3.0_f64.sqrt()).abs() < 1e-12,
            "over-coupling = 1/√3"
        );
        assert!(
            (PURITY_FLOOR - 2.0 / 7.0).abs() < 1e-12,
            "P_crit = 2/N = 2/7"
        );
        assert!(
            (REFLECTION_FLOOR - 1.0 / 3.0).abs() < 1e-12,
            "R floor = 1/3"
        );
        // The band ordering `r* < 1/√3` is now a compile-time `const _` assertion above.
    }

    #[test]
    fn json_is_a_stable_flat_object() {
        let snap = CoherenceSnapshot::from_frame(&frame(0.5));
        let json = snap.to_json();
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\"cell_id\":\"abababababababababababababababab\""));
        assert!(json.contains("\"epoch\":9,"));
        assert!(json.contains("\"regime\":\""));
        assert!(json.contains("\"alive_nodes\":"));
        assert!(json.contains("\"ready\":"));
        // No non-finite scalar leaked as an invalid JSON token.
        assert!(!json.contains("NaN") && !json.contains("inf"));
    }

    #[test]
    fn alive_nodes_is_exact_for_the_equicorrelated_liveness_fold() {
        // frame(r) builds CoherenceMatrix::equicorrelated(7, r) — exactly the shape
        // observe_liveness produces from a live alive_count — so Φ=(N−1)r² inverts back to N=7
        // exactly, for any nonzero r, healthy or weakly correlated alike.
        for r in [0.05, 0.3, 0.5, 0.7] {
            let snap = CoherenceSnapshot::from_frame(&frame(r));
            assert_eq!(snap.alive_nodes, 7, "r={r}");
        }
    }

    #[test]
    fn alive_nodes_tracks_a_smaller_live_count() {
        // Mirrors SelfObserver::observe_liveness with 2 nodes down (5 alive): the matrix really is
        // 5×5 equicorrelated, so the inversion recovers 5, not the fixed CELL_N=7.
        let matrix = CoherenceMatrix::equicorrelated(5, 0.45);
        let f = CoherenceFrame::observe(CellId([0xCD; 16]), 1, &matrix, 0b0001_1000, 0.3, -1, 0);
        let snap = CoherenceSnapshot::from_frame(&f);
        assert_eq!(snap.alive_nodes, 5);
    }

    #[test]
    fn a_fully_decorrelated_cell_is_still_counted_exactly() {
        // `r = 0` is the diversified/resilient regime, not a fault — and it is precisely where the old
        // inversion of `Φ = (N−1)r²` divided by zero and had to guess from the binary syndrome. `N = 1/(R·P)`
        // has no such hole: a decorrelated cell has `Γ = I/n`, so `P = 1/n`, `R = 1`, and the product is `1/n`
        // exactly as for any other correlation.
        let healthy = CoherenceSnapshot::from_frame(&frame(0.0));
        assert_eq!(healthy.alive_nodes, 7, "a decorrelated 7-cell is seven nodes, not a syndrome guess");

        // And a localized fault does not change the count, because the count is measured rather than inferred
        // from the fault bit. The old code returned `CELL_N − 1` here purely because it could not divide.
        let matrix = CoherenceMatrix::equicorrelated(7, 0.0);
        let faulted_frame = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0b0000_0001, 0.0, -1, 0);
        let faulted = CoherenceSnapshot::from_frame(&faulted_frame);
        assert!(faulted.faulted);
        assert_eq!(faulted.alive_nodes, 7, "the matrix still describes seven nodes");
    }

    #[test]
    fn the_setpoint_offset_says_which_way_the_cell_is_off_and_by_how_much() {
        // The band reports only *which* band, so a cell just above the collapse boundary reads healthy. This
        // field is what distinguishes "in the band" from "where in the band", which is a 3.16× difference in
        // stability radius on a Fano plane.
        //
        // Φ = 6r² on a 7-cell, so r = √(Φ/6): pick correlations that land the cell below, at, and above Φ*.
        let below = CoherenceSnapshot::from_frame(&frame((1.05f64 / 6.0).sqrt()));
        let at = CoherenceSnapshot::from_frame(&frame((1.25f64 / 6.0).sqrt()));
        let above = CoherenceSnapshot::from_frame(&frame((1.90f64 / 6.0).sqrt()));

        assert!(below.setpoint_offset < -0.1, "under-coupled reads negative: {}", below.setpoint_offset);
        assert!(at.setpoint_offset.abs() < 0.01, "at Φ* it reads ~zero: {}", at.setpoint_offset);
        assert!(above.setpoint_offset > 0.5, "toward over-coupling reads positive: {}", above.setpoint_offset);

        // All three are inside the band, so `Regime` cannot tell them apart — which is the whole reason this
        // field exists. Assert that, or the test would pass on a field nobody needs.
        assert_eq!(below.regime, at.regime, "the regime is identical across a 3× robustness difference");
        assert_eq!(at.regime, above.regime);
    }

    #[test]
    fn the_json_prefix_stays_byte_identical_when_a_field_is_appended() {
        // Appending must not renumber: an existing consumer reading up to `alive_nodes` must see exactly the
        // bytes it saw before, which is the discipline `alive_nodes` itself followed.
        let json = CoherenceSnapshot::from_frame(&frame(0.5)).to_json();
        let (prefix, tail) = json.split_once(",\"setpoint_offset\":").expect("appended last, with a comma");
        assert!(prefix.starts_with('{'), "the prefix is the whole object minus the new field");
        assert!(prefix.contains("\"alive_nodes\":"), "and it still ends with the previously-last field");
        assert!(tail.ends_with('}'), "the new field closes the object");
        assert!(!prefix.contains("setpoint_offset"), "the field appears exactly once, at the end");
    }

    #[test]
    fn the_count_is_exact_for_every_supported_plane() {
        // The defect this replaced clamped to `CELL_N`, so a `PG(2,31)` cell reported seven alive nodes out of
        // 993 — and the stability radius `√(P − 2/N)` was computed against the wrong `N` with it.
        for n in [7usize, 21, 57, 993] {
            for r in [0.0, 0.05, 0.3] {
                let matrix = CoherenceMatrix::equicorrelated(n, r);
                let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0, 0.0, -1, 0);
                let snap = CoherenceSnapshot::from_frame(&f);
                assert_eq!(snap.alive_nodes as usize, n, "N={n} r={r}: the count must be exact");
                // …and the radius must follow the recovered N, not a constant.
                let expected = stability_radius(snap.purity, n);
                assert!(
                    (snap.stability_radius - expected).abs() < 1e-9,
                    "N={n} r={r}: r_stab must use the recovered N (got {}, want {expected})",
                    snap.stability_radius
                );
            }
        }
    }

    #[test]
    fn alive_nodes_is_always_within_the_physical_cell_bound() {
        // Whatever r/Φ combination a (possibly adversarial or degenerate) frame carries, the derived
        // count must never exceed the cell size or go negative — it is clamped, not merely "usually"
        // in range.
        for r in [-0.9, -0.1, 0.0, 1e-7, 0.408, 0.577, 0.9, 1.0] {
            let matrix = CoherenceMatrix::equicorrelated(7, r);
            let f = CoherenceFrame::observe(CellId([0; 16]), 1, &matrix, 0, 0.0, -1, 0);
            let snap = CoherenceSnapshot::from_frame(&f);
            assert!(snap.alive_nodes <= MAX_CELL_N as u32, "r={r}");
        }
    }
}
