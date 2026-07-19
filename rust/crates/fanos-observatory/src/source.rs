//! The snapshot source seam — where the observatory's data comes from.
//!
//! [`SnapshotSource`] is the single abstraction the UI depends on (the sans-I/O "one observatory, many
//! sources" analogue). Today the shipped source is [`ScenarioSource`]: a genuine DIAKRISIS
//! `PurityDynamics` cell the operator drives with decoherence pressure, producing real
//! [`CoherenceFrame`]s and hence real [`CoherenceSnapshot`]s — so the panel shows the production
//! self-model, not a mock. A live source (a node's telemetry stream / OTLP subscription) implements the
//! same trait and drops straight in.

use fanos_diakrisis::coherence::CoherenceMatrix;
use fanos_diakrisis::dynamics::PurityDynamics;
use fanos_diakrisis::regeneration::spectral_gap;
use fanos_geometry::fano;
use fanos_telemetry::{CellId, CoherenceFrame, CoherenceSnapshot};

/// An operator control the observatory can apply to its source. A live source may map these onto real
/// admin actions (shed load, quarantine, trigger `ℛ`) or ignore them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// Raise the decoherence pressure — a DDoS / load surge on the cell.
    Attack,
    /// Relieve pressure.
    Relieve,
    /// Inject a node fault (light the next point in the 3-bit syndrome).
    InjectFault,
    /// Heal: clear the syndrome and shed pressure — the regenerator `ℛ`.
    Heal,
}

/// A source of coherence snapshots — the seam a live node-telemetry feed slots into. The UI depends
/// only on this, never on where the vitals come from.
pub trait SnapshotSource {
    /// Advance one observation window.
    fn tick(&mut self);
    /// The latest snapshot (the production [`CoherenceSnapshot`], folded from a real frame).
    fn snapshot(&self) -> CoherenceSnapshot;
    /// Apply an operator [`Control`].
    fn control(&mut self, op: Control);
    /// A short human label for the source, shown in the header.
    fn label(&self) -> &str;
    /// The current decoherence pressure as a fraction of the cell's survival bound `a*` (the load
    /// gauge). `≥ 1.0` means past the saddle-node.
    fn pressure(&self) -> f64;
    /// The degraded-node bitmask over the seven Fano points (bit `i` = point `i` is down). The compact
    /// [`snapshot`](Self::snapshot) carries only the 3-bit Hamming *syndrome*; this exposes the full
    /// footprint for the operator's node map. A live source reads it from the same liveness view.
    fn degraded(&self) -> u8;
}

/// A self-contained demo source: a real `PurityDynamics` cell driven by an operator-controlled attack.
pub struct ScenarioSource {
    cell: PurityDynamics,
    attack: f64,
    /// The survival bound `a*` scale, so `pressure()` and the attack step are in meaningful units.
    a_star: f64,
    degraded: u8,
    heal_seq: u32,
    epoch: u64,
}

impl ScenarioSource {
    /// A fresh healthy cell resting in the **collective-subject band**: `P_ideal ≈ 0.36` maps to a mean
    /// correlation `r ≈ 0.50 ∈ (1/√6, 1/√3]`, so Φ ≈ 1.5 ≥ 1 and R ≈ 0.40 ≥ 1/3 (a bound, self-observing
    /// subject). Decoherence pressure drives `P` down toward the viability floor `2/N` — the DDoS
    /// collapse the observatory shows.
    #[must_use]
    pub fn new() -> Self {
        let cell = PurityDynamics::new(0.1, 0.5, 0.36, 0.05, 7, 0.36);
        // The gate-open survival-bound scale (a positive reference for the attack units).
        let a_star = (cell.survival_bound_gate_open() * 2.0).max(1e-3);
        Self {
            cell,
            attack: 0.0,
            a_star,
            degraded: 0,
            heal_seq: 0,
            epoch: 0,
        }
    }
}

impl Default for ScenarioSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotSource for ScenarioSource {
    fn tick(&mut self) {
        self.cell.step(self.attack);
        self.epoch = self.epoch.wrapping_add(1);
    }

    fn control(&mut self, op: Control) {
        let step = self.a_star * 0.12;
        match op {
            Control::Attack => self.attack = (self.attack + step).min(self.a_star * 1.6),
            Control::Relieve => self.attack = (self.attack - step).max(0.0),
            Control::InjectFault => {
                for i in 0..fano::N {
                    if self.degraded & (1u8 << i) == 0 {
                        self.degraded |= 1u8 << i;
                        break;
                    }
                }
            }
            Control::Heal => {
                self.degraded = 0;
                self.attack *= 0.4;
                self.heal_seq = self.heal_seq.wrapping_add(1);
            }
        }
    }

    fn snapshot(&self) -> CoherenceSnapshot {
        let purity = self.cell.purity();
        // Recover the mean correlation from the purity of an equicorrelated cell: P = (1 + 6r²)/7.
        let r = (((7.0 * purity - 1.0) / 6.0).max(0.0)).sqrt();
        let matrix = CoherenceMatrix::equicorrelated(fano::N, r);
        // The real polar spectral gap Δ over the Fano lines, given the degraded points (T-226(v)).
        let mut line_rates = [0.0f64; fano::N];
        for (rate, points) in line_rates.iter_mut().zip(fano::LINE_POINTS.iter()) {
            *rate = points
                .iter()
                .filter(|&&p| self.degraded & (1u8 << p) == 0)
                .count() as f64;
        }
        let gap = spectral_gap(&line_rates);
        let frame = CoherenceFrame::observe(
            CellId([0x0F; 16]),
            self.epoch,
            &matrix,
            self.degraded,
            gap,
            -1,
            self.heal_seq,
        );
        CoherenceSnapshot::from_frame(&frame)
    }

    // The trait ties the label to `&self` (a live source may return a stored, dynamic label); this
    // impl happens to return a literal, which clippy would prefer as `&'static`.
    #[allow(clippy::unnecessary_literal_bound)]
    fn label(&self) -> &str {
        "demo · PurityDynamics cell (N=7)"
    }

    fn pressure(&self) -> f64 {
        self.attack / self.a_star
    }

    fn degraded(&self) -> u8 {
        self.degraded
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_cell_is_ready_and_healthy() {
        let src = ScenarioSource::new();
        let snap = src.snapshot();
        assert!(
            snap.is_ready(),
            "a fresh gate-open cell is a bound, self-observing subject"
        );
        assert!(snap.phi >= 1.0, "Φ ≥ 1");
        assert_eq!(snap.syndrome, 0, "no faults");
    }

    #[test]
    fn sustained_attack_drives_the_cell_out_of_readiness() {
        let mut src = ScenarioSource::new();
        for _ in 0..20 {
            src.control(Control::Attack);
        }
        assert!(
            src.pressure() > 1.0,
            "the operator pushed past the survival bound"
        );
        for _ in 0..5000 {
            src.tick();
        }
        let snap = src.snapshot();
        assert!(
            !snap.is_ready(),
            "a cell held past a* loses viability (not ready)"
        );
    }

    #[test]
    fn injecting_faults_lights_the_syndrome_and_healing_clears_it() {
        let mut src = ScenarioSource::new();
        src.control(Control::InjectFault);
        src.control(Control::InjectFault);
        let snap = src.snapshot();
        assert_eq!(src.degraded().count_ones(), 2, "two nodes degraded");
        assert!(snap.faulted, "the 3-bit syndrome is non-zero");
        src.control(Control::Heal);
        let healed = src.snapshot();
        assert_eq!(src.degraded(), 0, "healing cleared the degraded set");
        assert!(!healed.faulted, "and the syndrome is clean");
        assert!(
            healed.heal_seq > snap.heal_seq,
            "the healing counter advanced"
        );
    }
}
