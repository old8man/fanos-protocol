//! The **unified cluster** — K coherent 7-node Fano cells embedded in ONE transport plane / ONE `Sim`,
//! each running the full DIAKRISIS reflex via `OverlayNode::with_cell_members` (the unified-topology
//! refactor). Distinct from the federated [`Cluster`](crate::Cluster), which puts each cell in its OWN
//! `Sim`: here every cell shares one event queue, so cells *can* route to one another (the routing lens
//! composes) — yet coherence still scales linearly, because each node pings only its six cell members
//! (`peers` = the cell), never the whole plane, so there is no `O(N²)` fan-out across the fleet.

use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_runtime::{Command, Config, OverlayNode};

use crate::fleet::FleetSnapshot;
use crate::sim::Sim;

/// The seven-point Fano cell size.
const CELL: usize = 7;

/// A cluster of coherent Fano cells on one transport plane `F`. Reaches `⌊(q²+q+1)/7⌋` cells (e.g. 141 on
/// `F31` = 987 nodes) — enough to demonstrate coherence at scale on a single connected topology.
pub struct UnifiedCluster {
    sim: Sim,
    /// Each cell's seven member coordinates, in position order.
    cells: Vec<[Triple; CELL]>,
}

impl UnifiedCluster {
    /// Build `cell_count` coherent 7-node cells on the transport plane `F`, each node told its cell, then
    /// start their heartbeats. (The plane `F` is a construction-time choice; the cluster itself is not
    /// parameterised by it, since it holds only flat coordinates.)
    ///
    /// # Panics
    /// If `7 · cell_count` exceeds the transport plane's point count.
    #[must_use]
    pub fn new<F: Field + 'static>(seed: u64, config: Config, cell_count: usize) -> Self {
        let plane_n = Plane::<F>::N as usize;
        assert!(cell_count * CELL <= plane_n, "{cell_count} cells exceed the {plane_n}-point plane");

        let mut sim = Sim::new(seed);
        let mut cells = Vec::with_capacity(cell_count);
        let mut next = 0usize; // next distinct transport point index
        for _ in 0..cell_count {
            let points: [Point<F>; CELL] = core::array::from_fn(|_| {
                let p = Point::<F>::at(next);
                next += 1;
                p
            });
            let members: [Triple; CELL] = points.map(|p| p.coords());
            for &point in &points {
                sim.add(Box::new(OverlayNode::<F>::new(point, config).with_cell_members(members)));
            }
            cells.push(members);
        }
        sim.inject_all(&Command::StartHeartbeat);
        Self { sim, cells }
    }

    /// The number of cells.
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// The total number of nodes (`7 · cells`).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.cells.len() * CELL
    }

    /// Cell `c`'s member coordinates.
    #[must_use]
    pub fn cell(&self, c: usize) -> Option<&[Triple; CELL]> {
        self.cells.get(c)
    }

    /// Advance every cell by `dur`.
    pub fn run_for(&mut self, dur: fanos_runtime::Duration) {
        self.sim.run_for(dur);
    }

    /// A guaranteed-fresh telemetry read across the whole cluster.
    pub fn refresh_telemetry(&mut self) {
        self.sim.refresh_telemetry();
    }

    /// Crash one node (by coordinate) — e.g. a member of a chosen cell.
    pub fn crash(&mut self, coord: Triple) {
        self.sim.crash(coord);
    }

    /// The whole-cluster coherence snapshot (every cell's nodes report a self-model, all in one `Sim`).
    #[must_use]
    pub fn snapshot(&self) -> FleetSnapshot {
        self.sim.fleet_snapshot()
    }

    /// Mutable access to the underlying `Sim` — to inject cross-cell routing frames or faults.
    pub fn sim_mut(&mut self) -> &mut Sim {
        &mut self.sim
    }
}
