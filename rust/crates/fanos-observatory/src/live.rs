//! A **live** snapshot source: a real cell of production `OverlayNode` engines running under the
//! deterministic simulator. This is the "devnet is production" seam — the same engine that ships,
//! observed live. Heartbeats, liveness detection, and the DIAKRISIS syndrome are all real; the operator
//! crashes and recovers actual nodes and watches the cell's own coherence respond (including the real
//! detection latency — a freshly crashed node reads healthy until its heartbeats time out).
//!
//! A remote source — subscribing to a running node's telemetry stream (encoded [`CoherenceFrame`]s over
//! a socket / OTLP) — implements the same [`SnapshotSource`] trait and drops in behind this one.

use fanos_diakrisis::coherence::CoherenceMatrix;
use fanos_diakrisis::regeneration::spectral_gap;
use fanos_field::F2;
use fanos_geometry::fano;
use fanos_runtime::{Command, Config, Duration, Triple};
use fanos_sim::{Sim, spawn_cell};
use fanos_telemetry::{CellId, CoherenceFrame, CoherenceSnapshot};

use crate::source::{Control, SnapshotSource};

/// The heartbeat / observation window.
const HEARTBEAT_MS: u64 = 500;
/// One `tick` advances the cell by one observation window.
const WINDOW_MS: u64 = 500;
/// The healthy collective-subject correlation of a live, fully-integrated cell.
const HEALTHY_R: f64 = 0.5;
/// A node whose liveness has fallen below this is treated as degraded.
const LIVE_THRESHOLD: f64 = 0.5;

/// A live cell of seven `OverlayNode` engines under `fanos-sim`.
pub struct LiveCellSource {
    sim: Sim,
    cell: Vec<Triple>,
    epoch: u64,
    heal_seq: u32,
}

impl LiveCellSource {
    /// Bring up a Fano cell, start its heartbeats, and let it reach steady state.
    #[must_use]
    pub fn new() -> Self {
        let mut sim = Sim::new(0x0B5E_1234_C0DE_F00D);
        let config = Config {
            heartbeat: Duration::from_millis(HEARTBEAT_MS),
            liveness_timeout: Duration::from_millis(HEARTBEAT_MS * 3),
            ..Config::default()
        };
        let cell = spawn_cell::<F2>(&mut sim, config);
        sim.inject_all(&Command::StartHeartbeat);
        sim.run_for(Duration::from_millis(HEARTBEAT_MS * 4)); // settle to steady liveness
        Self {
            sim,
            cell,
            epoch: 0,
            heal_seq: 0,
        }
    }

    /// The cell's *own* current view: the degraded bitmask (heartbeat-timed-out nodes) and the alive
    /// count. Read from real liveness, so a just-crashed node still reads healthy until it times out.
    fn view(&self) -> (u8, usize) {
        let live = self.sim.liveness_snapshot(&self.cell);
        let mut degraded = 0u8;
        let mut alive = 0usize;
        for (i, &l) in live.iter().enumerate().take(fano::N) {
            if l >= LIVE_THRESHOLD {
                alive += 1;
            } else {
                degraded |= 1u8 << i;
            }
        }
        (degraded, alive)
    }
}

impl Default for LiveCellSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SnapshotSource for LiveCellSource {
    fn tick(&mut self) {
        self.sim.run_for(Duration::from_millis(WINDOW_MS));
        self.epoch = self.epoch.wrapping_add(1);
    }

    fn control(&mut self, op: Control) {
        let (degraded, _) = self.view();
        match op {
            Control::Attack | Control::InjectFault => {
                // Crash the lowest-index still-live node — a real node failure.
                if let Some((_, &node)) = self
                    .cell
                    .iter()
                    .enumerate()
                    .find(|&(i, _)| degraded & (1u8 << i) == 0)
                {
                    self.sim.crash(node);
                }
            }
            Control::Relieve => {
                // Recover the lowest-index crashed node.
                if let Some((_, &node)) = self
                    .cell
                    .iter()
                    .enumerate()
                    .find(|&(i, _)| degraded & (1u8 << i) != 0)
                {
                    self.sim.recover(node);
                }
            }
            Control::Heal => {
                for &node in &self.cell {
                    self.sim.recover(node);
                }
                self.heal_seq = self.heal_seq.wrapping_add(1);
            }
        }
    }

    fn snapshot(&self) -> CoherenceSnapshot {
        let (degraded, alive) = self.view();
        // The cell modelled as equicorrelated over its live members (the production liveness fold,
        // `SelfObserver::observe_liveness`): fewer live nodes ⇒ lower Φ ⇒ eventual loss of readiness.
        let matrix = CoherenceMatrix::equicorrelated(alive.max(2), HEALTHY_R);
        let mut line_rates = [0.0f64; fano::N];
        for (rate, points) in line_rates.iter_mut().zip(fano::LINE_POINTS.iter()) {
            *rate = points
                .iter()
                .filter(|&&p| degraded & (1u8 << p) == 0)
                .count() as f64;
        }
        let gap = spectral_gap(&line_rates);
        let frame = CoherenceFrame::observe(
            CellId([0xC1; 16]),
            self.epoch,
            &matrix,
            degraded,
            gap,
            -1,
            self.heal_seq,
        );
        CoherenceSnapshot::from_frame(&frame)
    }

    #[allow(clippy::unnecessary_literal_bound)] // the trait ties the label to &self; this impl is a literal
    fn label(&self) -> &str {
        "live · fanos-sim F2 cell · 7 OverlayNode engines"
    }

    fn pressure(&self) -> f64 {
        f64::from(self.view().0.count_ones()) / fano::N as f64
    }

    fn degraded(&self) -> u8 {
        self.view().0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_live_cell_is_ready() {
        let src = LiveCellSource::new();
        let snap = src.snapshot();
        assert_eq!(src.degraded(), 0, "a settled cell has no timed-out nodes");
        assert!(snap.is_ready(), "seven live nodes are a bound, self-observing subject");
    }

    #[test]
    fn crashing_a_majority_eventually_shows_degradation_and_loss_of_readiness() {
        let mut src = LiveCellSource::new();
        // Crash four of the seven nodes.
        for _ in 0..4 {
            src.control(Control::Attack);
        }
        // Advance several windows so the heartbeat timeouts register the failures.
        for _ in 0..8 {
            src.tick();
        }
        let snap = src.snapshot();
        assert!(src.degraded().count_ones() >= 3, "the crashed nodes time out and show degraded");
        assert!(!snap.is_ready(), "a cell that lost its majority is no longer ready");

        // Healing recovers every node; after settling the cell is ready again.
        src.control(Control::Heal);
        for _ in 0..8 {
            src.tick();
        }
        assert!(src.snapshot().is_ready(), "healing restores the live cell to readiness");
    }
}
