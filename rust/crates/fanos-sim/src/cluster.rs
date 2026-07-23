//! The scale-out cluster — a federation of base cells (spec §L1: the network is a *recursion of cells*).
//!
//! The DIAKRISIS self-model is per base 7-node Fano cell (`cell_liveness` senses a 3-bit syndrome over
//! the 7 points), so *genuine coherence at scale* means many cells, not one large plane. [`Cluster`]
//! federates independent base cells — each a real, coherent, deterministically-seeded `F2` cell — into
//! one addressable fleet: step them together, snapshot them together (a [`ClusterSnapshot`] of per-cell
//! [`FleetSnapshot`]s plus a cross-cell [`ClusterStats`] total), and reach into any cell for a targeted
//! experiment (crash / inject / partition). This reaches 10 000 nodes (~1429 cells) because every cell
//! stays a cheap 7-node discrete-event sim — the `O(N²)` heartbeat is bounded to `N = 7` *inside* a cell,
//! never across the fleet. Cross-cell routing is a separate capability (a hierarchy message bus); this is
//! the state-inspection and per-cell-experiment substrate the operator dashboard renders.

use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration};

use crate::fleet::{ClusterStats, FleetSnapshot};
use crate::metrics::Metrics;
use crate::sim::Sim;
use crate::spawn_partial_cell;

/// The number of points in a base Fano cell — the coherent unit the fleet is built from.
pub const CELL_SIZE: usize = 7;

/// A federation of base cells presented as one fleet. Cells are independent coherence domains (as in the
/// real recursion-of-cells), so the cluster scales by *count of cells*, each cheap.
pub struct Cluster {
    cells: Vec<Sim>,
    config: Config,
    seed: u64,
}

impl Cluster {
    /// A cluster of `cell_count` full base cells, each seeded deterministically from `seed` and already
    /// heartbeating.
    #[must_use]
    pub fn new(seed: u64, config: Config, cell_count: usize) -> Self {
        let mut cluster = Self { cells: Vec::with_capacity(cell_count), config, seed };
        for _ in 0..cell_count {
            cluster.push_cell(CELL_SIZE);
        }
        cluster
    }

    /// A cluster sized to hold at least `node_target` nodes: `⌈node_target / 7⌉` cells, the last one
    /// partial when `node_target` is not a multiple of 7. So `1..=7` is a single growing cell (the "one
    /// node, two nodes, three nodes …" progression), `8..=14` is one full cell plus a partial, and so on.
    #[must_use]
    pub fn with_node_target(seed: u64, config: Config, node_target: usize) -> Self {
        let mut cluster = Self { cells: Vec::new(), config, seed };
        let full = node_target / CELL_SIZE;
        let remainder = node_target % CELL_SIZE;
        for _ in 0..full {
            cluster.push_cell(CELL_SIZE);
        }
        if remainder > 0 {
            cluster.push_cell(remainder);
        }
        cluster
    }

    /// Append one cell of `size` members (deterministically seeded off its index) and start its heartbeat.
    fn push_cell(&mut self, size: usize) {
        let mut sim = Sim::new(self.seed.wrapping_add(self.cells.len() as u64));
        let _ = spawn_partial_cell::<F2>(&mut sim, self.config, size);
        sim.inject_all(&Command::StartHeartbeat);
        self.cells.push(sim);
    }

    /// The number of cells.
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// The total number of nodes across every cell.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.cells.iter().map(Sim::node_count).sum()
    }

    /// Borrow cell `i` (to read its state).
    #[must_use]
    pub fn cell(&self, i: usize) -> Option<&Sim> {
        self.cells.get(i)
    }

    /// Borrow cell `i` mutably — to run a targeted experiment on it (crash/inject/partition).
    pub fn cell_mut(&mut self, i: usize) -> Option<&mut Sim> {
        self.cells.get_mut(i)
    }

    /// Advance every cell by `dur`.
    pub fn run_for(&mut self, dur: Duration) {
        for cell in &mut self.cells {
            cell.run_for(dur);
        }
    }

    /// Force a fresh sense-only telemetry round in every cell (the `O(N)` inspection path at scale).
    pub fn refresh_telemetry(&mut self) {
        for cell in &mut self.cells {
            cell.refresh_telemetry();
        }
    }

    /// A whole-cluster snapshot: every cell's [`FleetSnapshot`], the cross-cell [`ClusterStats`] total,
    /// and the summed metrics. `O(total nodes)`.
    #[must_use]
    pub fn snapshot(&self) -> ClusterSnapshot {
        let cells: Vec<FleetSnapshot> = self.cells.iter().map(Sim::fleet_snapshot).collect();
        let totals = ClusterStats::from_nodes(cells.iter().flat_map(|c| &c.nodes));
        let mut metrics = Metrics::default();
        let mut at_nanos = 0;
        for cell in &cells {
            metrics.merge(&cell.metrics);
            at_nanos = at_nanos.max(cell.at_nanos);
        }
        ClusterSnapshot { at_nanos, totals, metrics, cells }
    }
}

/// A whole-cluster snapshot: per-cell fleet state, plus the cross-cell rollup and summed metrics.
#[derive(Clone, Debug)]
pub struct ClusterSnapshot {
    /// The latest virtual time across the cells (nanoseconds).
    pub at_nanos: u64,
    /// The cross-cell rollup (counts over every node in the cluster).
    pub totals: ClusterStats,
    /// The summed run metrics across every cell.
    pub metrics: Metrics,
    /// Each cell's own fleet snapshot, in cell order.
    pub cells: Vec<FleetSnapshot>,
}

impl ClusterSnapshot {
    /// The number of cells.
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// The cells that warrant attention (any node in them is a concern), with their index — the drill-down
    /// list a dashboard shows when the cluster is too large to render node-by-node.
    pub fn troubled_cells(&self) -> impl Iterator<Item = (usize, &FleetSnapshot)> {
        self.cells.iter().enumerate().filter(|(_, c)| c.concerns().next().is_some())
    }
}
