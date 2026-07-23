//! Cluster-scale **stress experiments** — chaos-engineering the fleet and measuring its response.
//!
//! The 50+ single-cell scenarios in `tests/` pin named adversarial *properties* (sybil, eclipse,
//! byzantine, …) on one cell. This module is the complementary axis: parametric perturbations of a whole
//! [`Cluster`](crate::Cluster) — crash a fraction of it, churn it continuously, cascade one cell to
//! collapse — run for a horizon, with the fleet's homeostatic response captured as an
//! [`ExperimentReport`]. Deterministic: every target is chosen by index, never a clock or RNG, so a run
//! reproduces exactly (the determinism contract, lifted to the fleet). This is the substrate behind
//! `fanos-lab experiment` and the live dashboard's fault controls.

use std::collections::BTreeSet;

use fanos_runtime::Duration;

use crate::cluster::Cluster;
use crate::fleet::ClusterStats;

/// A parametric perturbation applied to a [`Cluster`] over a run.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Experiment {
    /// A one-shot mass failure at `t = 0`: crash a `fraction` of the fleet's nodes, whole cells first
    /// (so the heatmap shows a block of failures), then leave it — the fleet does not resurrect nodes,
    /// so this measures the *degradation* a correlated outage inflicts and how it is contained per cell.
    MassCrash {
        /// Fraction of nodes to crash, in `[0, 1]`.
        fraction: f64,
    },
    /// Steady-state **churn**: every tick, crash `per_tick` fresh nodes and recover the ones crashed
    /// `grace` ticks ago — a rolling turnover that never stops. Measures whether the fleet's coherence
    /// stays bounded under continuous, uncorrelated failure (it should — churn is diversified, not a
    /// cascade).
    RollingChurn {
        /// How many nodes to crash (and later recover) each tick.
        per_tick: usize,
        /// How many ticks a crashed node stays down before it recovers.
        grace: usize,
    },
    /// A **cascade** in one cell: crash one more of cell `target`'s nodes each tick, until it collapses.
    /// Measures the point at which a single cell's self-model crosses the viability thresholds.
    Cascade {
        /// The cell to collapse.
        target: usize,
    },
    /// A **network partition**: bisect a `fraction` of cells (a 4|3 cut) at `t = 0`, then **heal** the cut
    /// at `t = hold`. The nodes are never crashed — they stay alive but cannot reach across the cut, so the
    /// self-model senses missing peers and the cell degrades (partition detection, B4); after the heal it
    /// re-senses its peers and recovers. Measures detection *and* recovery, at scale.
    Partition {
        /// Fraction of cells to bisect, in `[0, 1]`.
        fraction: f64,
        /// The tick at which the partition heals.
        hold: usize,
    },
    /// A **soft** (incipient) partition (§6.5): bisect a `fraction` of cells with a *lossy* cut — messages
    /// crossing are dropped with `cross_loss`, not fully cut — then heal at `t = hold`. The far side stays
    /// marginally reachable, so simple liveness barely notices; the degradation is subtler than a hard cut,
    /// which is exactly the regime the loss-weighted Fiedler sensor exists to catch. Measures graceful
    /// degradation under a lossy split and recovery.
    SoftPartition {
        /// Fraction of cells to softly bisect, in `[0, 1]`.
        fraction: f64,
        /// The probability a message crossing the cut is dropped, in `[0, 1]`.
        cross_loss: f64,
        /// The tick at which the soft partition heals.
        hold: usize,
    },
}

impl Experiment {
    /// The canonical name (the `fanos-lab experiment <name>` selector).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Experiment::MassCrash { .. } => "mass-crash",
            Experiment::RollingChurn { .. } => "churn",
            Experiment::Cascade { .. } => "cascade",
            Experiment::Partition { .. } => "partition",
            Experiment::SoftPartition { .. } => "soft-partition",
        }
    }

    /// A one-line description.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Experiment::MassCrash { .. } => "one-shot: crash a fraction of the fleet (whole cells first)",
            Experiment::RollingChurn { .. } => "continuous: crash and later recover a few nodes each tick",
            Experiment::Cascade { .. } => "crash one more node of a target cell each tick until it collapses",
            Experiment::Partition { .. } => "bisect a fraction of cells (nodes stay up), then heal — detect + recover",
            Experiment::SoftPartition { .. } => "lossy (incipient) bisection of a fraction of cells, then heal",
        }
    }

    /// The names of every built-in experiment (for `fanos-lab scenarios`).
    pub const NAMES: [&'static str; 5] =
        ["mass-crash", "churn", "cascade", "partition", "soft-partition"];

    /// Build an experiment from its name and a `fraction` parameter (reused as the churn rate; ignored
    /// by cascade). `None` for an unknown name.
    #[must_use]
    pub fn from_name(name: &str, fraction: f64, total_nodes: usize) -> Option<Self> {
        match name {
            "mass-crash" => Some(Experiment::MassCrash { fraction }),
            "churn" => Some(Experiment::RollingChurn {
                per_tick: ((fraction * total_nodes as f64).round() as usize).max(1),
                grace: 3,
            }),
            "cascade" => Some(Experiment::Cascade { target: 0 }),
            "partition" => Some(Experiment::Partition { fraction, hold: 5 }),
            "soft-partition" => Some(Experiment::SoftPartition { fraction, cross_loss: 0.92, hold: 5 }),
            _ => None,
        }
    }

    /// Apply this experiment's perturbation for tick `t` (0-based), before the cluster is stepped.
    pub fn perturb(self, cluster: &mut Cluster, t: usize) {
        match self {
            Experiment::MassCrash { fraction } => {
                if t == 0 {
                    let target = (fraction * cluster.node_count() as f64).round() as usize;
                    crash_first_alive(cluster, target);
                }
            }
            Experiment::RollingChurn { per_tick, grace } => {
                // Crash `per_tick` nodes at a rolling offset, and recover the batch from `grace` ticks ago.
                crash_batch(cluster, t, per_tick);
                if t >= grace {
                    recover_batch(cluster, t - grace, per_tick);
                }
            }
            Experiment::Cascade { target } => {
                if let Some(cell) = cluster.cell_mut(target)
                    && let Some(coord) =
                        cell.fleet_snapshot().nodes.iter().find(|n| n.alive).map(|n| n.coord)
                {
                    cell.crash(coord);
                }
            }
            Experiment::Partition { fraction, hold } => {
                let n = ((fraction * cluster.cell_count() as f64).round() as usize).max(1);
                if t == 0 {
                    for ci in 0..n {
                        if let Some(cell) = cluster.cell_mut(ci) {
                            let coords: Vec<_> = cell.nodes().collect();
                            let (left, right) = coords.split_at(coords.len() / 2);
                            let a: BTreeSet<_> = left.iter().copied().collect();
                            let b: BTreeSet<_> = right.iter().copied().collect();
                            cell.network_mut().partition([a, b]);
                        }
                    }
                } else if t == hold {
                    for ci in 0..n {
                        if let Some(cell) = cluster.cell_mut(ci) {
                            cell.network_mut().partition(core::iter::empty()); // heal the cut
                        }
                    }
                }
            }
            Experiment::SoftPartition { fraction, cross_loss, hold } => {
                let n = ((fraction * cluster.cell_count() as f64).round() as usize).max(1);
                if t == 0 {
                    for ci in 0..n {
                        if let Some(cell) = cluster.cell_mut(ci) {
                            let coords: Vec<_> = cell.nodes().collect();
                            let (left, right) = coords.split_at(coords.len() / 2);
                            let a: BTreeSet<_> = left.iter().copied().collect();
                            let b: BTreeSet<_> = right.iter().copied().collect();
                            cell.network_mut().soft_partition([a, b], cross_loss);
                        }
                    }
                } else if t == hold {
                    for ci in 0..n {
                        if let Some(cell) = cluster.cell_mut(ci) {
                            cell.network_mut().heal(); // clear the lossy cut
                        }
                    }
                }
            }
        }
    }
}

/// Crash the first `count` currently-alive nodes, whole cells first.
fn crash_first_alive(cluster: &mut Cluster, count: usize) {
    let mut remaining = count;
    let mut ci = 0;
    while remaining > 0 {
        let Some(cell) = cluster.cell_mut(ci) else { break };
        let alive: Vec<_> = cell.fleet_snapshot().nodes.iter().filter(|n| n.alive).map(|n| n.coord).collect();
        for coord in alive {
            if remaining == 0 {
                break;
            }
            cell.crash(coord);
            remaining -= 1;
        }
        ci += 1;
    }
}

/// Crash `per_tick` nodes selected by a tick-derived global offset (deterministic, spread across cells).
fn crash_batch(cluster: &mut Cluster, tick: usize, per_tick: usize) {
    let total = cluster.node_count().max(1);
    for k in 0..per_tick {
        let global = (tick.wrapping_mul(per_tick).wrapping_add(k)) % total;
        if let Some((ci, coord)) = nth_node(cluster, global)
            && let Some(cell) = cluster.cell_mut(ci)
        {
            cell.crash(coord);
        }
    }
}

/// Recover the same batch [`crash_batch`] crashed at `tick`.
fn recover_batch(cluster: &mut Cluster, tick: usize, per_tick: usize) {
    let total = cluster.node_count().max(1);
    for k in 0..per_tick {
        let global = (tick.wrapping_mul(per_tick).wrapping_add(k)) % total;
        if let Some((ci, coord)) = nth_node(cluster, global)
            && let Some(cell) = cluster.cell_mut(ci)
        {
            cell.recover(coord);
        }
    }
}

/// The `(cell_index, coordinate)` of the `global`-th node in cell-major order.
fn nth_node(cluster: &Cluster, global: usize) -> Option<(usize, fanos_runtime::Triple)> {
    let mut seen = 0;
    let mut ci = 0;
    while let Some(cell) = cluster.cell(ci) {
        let n = cell.node_count();
        if global < seen + n {
            let coord = cell.nodes().nth(global - seen)?;
            return Some((ci, coord));
        }
        seen += n;
        ci += 1;
    }
    None
}

/// The outcome of a stress run: the fleet before and after, the worst point reached, and whether it
/// ended healthy.
#[derive(Clone, Debug)]
pub struct ExperimentReport {
    /// The experiment's name.
    pub name: &'static str,
    /// Ticks run.
    pub ticks: usize,
    /// Cluster stats before the perturbation.
    pub before: ClusterStats,
    /// Cluster stats after the run.
    pub after: ClusterStats,
    /// The most cells troubled at any single tick (the worst moment).
    pub peak_troubled_cells: usize,
    /// The most nodes carrying any non-healthy diagnostic verdict at any single tick — the diagnosis
    /// signal (localized faults, escalations, partitions, …), distinct from the coherence dip.
    pub peak_diagnosed: usize,
    /// The most nodes that reached a **partition** verdict specifically at any single tick — a systemic
    /// (non-localizable) split registers here even while every node stays alive.
    pub peak_partitioned: usize,
    /// The lowest fleet mean-Φ observed across the run (the deepest coherence dip; `NaN` if never reported).
    pub min_mean_phi: f64,
    /// Whether the fleet ended fully alive and healthy (recovered / never broke).
    pub ended_healthy: bool,
}

/// Run `experiment` on `cluster` for `ticks` steps of `step` virtual time each, returning the response.
#[must_use]
pub fn run_experiment(
    cluster: &mut Cluster,
    experiment: Experiment,
    ticks: usize,
    step: Duration,
) -> ExperimentReport {
    cluster.refresh_telemetry();
    let before = cluster.snapshot().totals;
    let mut peak_troubled = 0;
    let mut peak_diagnosed = 0;
    let mut peak_partitioned = 0;
    let mut min_phi = f64::INFINITY;

    for t in 0..ticks {
        experiment.perturb(cluster, t);
        cluster.run_for(step);
        cluster.refresh_telemetry();
        let snap = cluster.snapshot();
        peak_troubled = peak_troubled.max(snap.troubled_cells().count());
        peak_diagnosed = peak_diagnosed.max(snap.totals.diagnosed);
        peak_partitioned = peak_partitioned.max(snap.totals.partitioned);
        if snap.totals.mean_phi.is_finite() {
            min_phi = min_phi.min(snap.totals.mean_phi);
        }
    }

    let after = cluster.snapshot().totals;
    ExperimentReport {
        name: experiment.name(),
        ticks,
        before,
        after,
        peak_troubled_cells: peak_troubled,
        peak_diagnosed,
        peak_partitioned,
        min_mean_phi: if min_phi.is_finite() { min_phi } else { f64::NAN },
        ended_healthy: after.is_healthy() && after.alive == after.total,
    }
}
