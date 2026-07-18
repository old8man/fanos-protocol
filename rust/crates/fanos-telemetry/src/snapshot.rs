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

use fanos_diakrisis::stability::stability_radius;

use crate::frame::{AlarmLevel, CellId, CoherenceFrame, Regime};

/// The Fano cell size `N = 7` (the DIAKRISIS observation unit, spec §6).
pub const CELL_N: usize = 7;

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
}

impl CoherenceSnapshot {
    /// Fold a [`CoherenceFrame`] into the operator snapshot, deriving `r_stab` and the readiness verdict.
    #[must_use]
    pub fn from_frame(frame: &CoherenceFrame) -> Self {
        let phi = f64::from(frame.phi);
        let purity = f64::from(frame.purity);
        let reflection = f64::from(frame.reflection);
        Self {
            cell_id: frame.cell_id,
            epoch: frame.epoch,
            phi,
            purity,
            reflection,
            mean_correlation: f64::from(frame.mean_r),
            spectral_gap: f64::from(frame.gap),
            stability_radius: stability_radius(purity, CELL_N),
            regime: frame.regime(),
            alarm: frame.alarm(),
            faulted: frame.is_faulted(),
            syndrome: frame.syndrome,
            cascade_lead: frame.forecast,
            heal_seq: frame.heal_seq,
            ready: phi >= PHI_THRESHOLD && reflection >= REFLECTION_FLOOR,
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
        let _ = write!(s, "\"regime\":\"{}\",", regime_name(self.regime));
        let _ = write!(s, "\"alarm\":\"{}\",", alarm_name(self.alarm));
        let _ = write!(s, "\"faulted\":{},", self.faulted);
        let _ = write!(s, "\"syndrome\":{},", self.syndrome);
        let _ = write!(s, "\"cascade_lead\":{},", self.cascade_lead);
        let _ = write!(s, "\"heal_seq\":{},", self.heal_seq);
        let _ = write!(s, "\"ready\":{}", self.ready);
        s.push('}');
        s
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

const fn regime_name(r: Regime) -> &'static str {
    match r {
        Regime::Aggregate => "aggregate",
        Regime::CollectiveSubject => "collective_subject",
        Regime::OverCoupled => "over_coupled",
    }
}

const fn alarm_name(a: AlarmLevel) -> &'static str {
    match a {
        AlarmLevel::Healthy => "healthy",
        AlarmLevel::Integration => "integration",
        AlarmLevel::Structure => "structure",
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
        assert!(healthy.reflection >= REFLECTION_FLOOR, "R={} ≥ 1/3", healthy.reflection);
        assert!(healthy.is_ready(), "a healthy collective subject is ready");

        // A weakly-coupled aggregate (r small) is NOT integrated (Φ<1) → not ready.
        let aggregate = CoherenceSnapshot::from_frame(&frame(0.05));
        assert!(aggregate.phi < PHI_THRESHOLD, "Φ={} < 1", aggregate.phi);
        assert!(!aggregate.is_ready(), "an unintegrated aggregate is not ready");
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
        assert!((OVER_COUPLING - 1.0 / 3.0_f64.sqrt()).abs() < 1e-12, "over-coupling = 1/√3");
        assert!((PURITY_FLOOR - 2.0 / 7.0).abs() < 1e-12, "P_crit = 2/N = 2/7");
        assert!((REFLECTION_FLOOR - 1.0 / 3.0).abs() < 1e-12, "R floor = 1/3");
        assert!(R_STAR < OVER_COUPLING, "the collective-subject band is (r*, 1/√3]");
    }

    #[test]
    fn json_is_a_stable_flat_object() {
        let snap = CoherenceSnapshot::from_frame(&frame(0.5));
        let json = snap.to_json();
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\"cell_id\":\"abababababababababababababababab\""));
        assert!(json.contains("\"epoch\":9,"));
        assert!(json.contains("\"regime\":\""));
        assert!(json.contains("\"ready\":"));
        // No non-finite scalar leaked as an invalid JSON token.
        assert!(!json.contains("NaN") && !json.contains("inf"));
    }
}
