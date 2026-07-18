//! `VitalSigns` — the operator-facing snapshot of a cell's coherence self-model, for **humans and
//! agents** alike.
//!
//! An operator (a person watching a panel, or an agent making a decision) should read *coherence*, not CPU
//! (`docs/coherent-cybernetics.md §5`). This is the one canonical, stable summary of a cell's health: the
//! three measures, where the mean correlation sits relative to the theorem-fixed band edges, the stability
//! radius (the viability speedometer, T-104), the collective-subject classification, the leading-indicator
//! alarm, and the single readiness verdict `Φ ≥ 1 ∧ R ≥ 1/3`. Every field is a plain number or a small enum,
//! so it renders directly on a dashboard *and* deserializes into an agent's decision — one summary, both
//! audiences. It carries no control logic (SRP): it *describes*, the [`homeostat`](crate::homeostat) *acts*.

use crate::coherence::{CoherenceMatrix, PHI_TH, R_TH};
use crate::stability::stability_radius;
use crate::window::{Alarm, CollectiveState, collective_subject_window};

/// A complete, theorem-grounded snapshot of a cell's coherence self-model at one instant.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct VitalSigns {
    /// Cell size `N`.
    pub n: usize,
    /// Integration `Φ` — cross-node binding (threshold `1`).
    pub phi: f64,
    /// Structuredness `P = Tr(Γ²)` — distance from a formless mesh (critical `2/N`).
    pub purity: f64,
    /// Reflection `R = 1/(N·P)` — self-model sufficiency (threshold `1/3`).
    pub reflection: f64,
    /// Mean inter-node correlation `r`.
    pub mean_correlation: f64,
    /// The systemic / "fever line" `r* = 1/√(N−1)`: the lower edge of the collective-subject band.
    pub systemic_threshold: f64,
    /// The over-coupling edge `√(2/(N−1))`: above it the cell loses its self-model (`R < 1/3`).
    pub over_coupling_threshold: f64,
    /// Stability radius `r_stab = √(P − 2/N)` (T-104) — how large a perturbation the cell still survives.
    pub stability_radius: f64,
    /// The collective-subject classification (`Aggregate` / `CollectiveSubject` / `OverCoupled`).
    pub collective: CollectiveState,
    /// The leading-indicator alarm (`Healthy` / `Integration` / `Structure`).
    pub alarm: Alarm,
    /// The readiness verdict `Φ ≥ 1 ∧ R ≥ 1/3` — the corpus L2 viability gate. This is what a
    /// Kubernetes/systemd readiness probe (or an agent's go/no-go) reads, grounded in a proof rather than a
    /// hand-picked latency threshold.
    pub ready: bool,
}

impl VitalSigns {
    /// Read the vital signs off a cell's coherence matrix in a single pass over its measures.
    #[must_use]
    pub fn of(g: &CoherenceMatrix) -> Self {
        let n = g.n();
        let m = g.measures();
        // The band edges: `collective_subject_window` returns exactly `(r* = systemic_correlation, r_over)`.
        let (systemic_threshold, over_coupling_threshold) = collective_subject_window(n);
        VitalSigns {
            n,
            phi: m.phi,
            purity: m.purity,
            reflection: m.reflection,
            mean_correlation: g.mean_correlation(),
            systemic_threshold,
            over_coupling_threshold,
            stability_radius: stability_radius(m.purity, n),
            collective: g.collective_state(),
            alarm: g.alarm(),
            // Readiness: integrated AND still self-modelling (small tolerance at the thresholds).
            ready: m.phi >= PHI_TH - 1e-9 && m.reflection >= R_TH - 1e-9,
        }
    }

    /// Whether the mean correlation is inside the healthy collective-subject band `(r*, r_over]`.
    #[must_use]
    pub fn in_band(&self) -> bool {
        matches!(self.collective, CollectiveState::CollectiveSubject)
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn a_healthy_in_band_cell_reads_ready_and_in_band() {
        // r = 0.5 is inside (1/√6, 1/√3] for N=7 → integrated (Φ≥1) and self-modelling (R≥1/3).
        let g = CoherenceMatrix::equicorrelated(7, 0.5);
        let v = VitalSigns::of(&g);
        assert!(v.ready, "an in-band cell is ready");
        assert!(v.in_band());
        assert_eq!(v.collective, CollectiveState::CollectiveSubject);
        assert!(v.stability_radius > 0.0);
        // Thresholds are the theorem-fixed band edges.
        assert!((v.systemic_threshold - 1.0 / 6.0f64.sqrt()).abs() < 1e-12);
        assert!((v.over_coupling_threshold - 1.0 / 3.0f64.sqrt()).abs() < 1e-12);
    }

    #[test]
    fn a_weakly_correlated_cell_is_not_ready() {
        // r = 0.2 < r* → an aggregate, Φ < 1, not integrated → not ready.
        let g = CoherenceMatrix::equicorrelated(7, 0.2);
        let v = VitalSigns::of(&g);
        assert!(!v.ready, "an unintegrated aggregate is not ready");
        assert_eq!(v.collective, CollectiveState::Aggregate);
        assert!(v.phi < 1.0);
    }

    #[test]
    fn an_over_coupled_cell_is_not_ready() {
        // r = 0.7 > r_over → over-coupled, R < 1/3, lost self-model → not ready despite high integration.
        let g = CoherenceMatrix::equicorrelated(7, 0.7);
        let v = VitalSigns::of(&g);
        assert!(v.phi >= 1.0, "it is (over-)integrated");
        assert!(v.reflection < 1.0 / 3.0, "but has lost its self-model");
        assert!(!v.ready, "over-coupling fails the readiness gate");
        assert_eq!(v.collective, CollectiveState::OverCoupled);
    }

    #[test]
    fn the_snapshot_fields_match_the_underlying_measures() {
        let g = CoherenceMatrix::equicorrelated(7, 0.45);
        let v = VitalSigns::of(&g);
        let m = g.measures();
        assert_eq!(v.phi, m.phi);
        assert_eq!(v.purity, m.purity);
        assert_eq!(v.reflection, m.reflection);
        assert_eq!(v.mean_correlation, g.mean_correlation());
        assert_eq!(v.n, 7);
    }
}
