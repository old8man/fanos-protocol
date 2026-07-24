//! The **unified cluster** — K coherent 7-node Fano cells embedded in ONE transport plane / ONE `Sim`,
//! each running the full DIAKRISIS reflex via `OverlayNode::with_cell_members` (the unified-topology
//! refactor), and each fronted by a **gateway** that routes to every other cell over the overlay. So one
//! topology carries BOTH lenses at once: coherence at every node (each pings only its six cell members,
//! so it scales linearly — no `O(N²)` plane fan-out) AND cross-cell routing between the gateways.

use fanos_field::Field;
use fanos_geometry::{HierAddr, Plane, Point, Triple};
use fanos_runtime::{Command, Config, Duration, Notification, OverlayNode};
use fanos_wire::{FrameType, encode_frame};

use crate::fleet::FleetSnapshot;
use crate::sim::Sim;

/// The seven-point Fano cell size.
const CELL: usize = 7;
/// The payload a cross-cell routing probe carries.
const PROBE: &[u8] = b"unified-route";

/// A cluster of coherent Fano cells on one transport plane, connected by gateway routing.
pub struct UnifiedCluster {
    sim: Sim,
    /// Each cell's seven member coordinates (position 0 is the gateway).
    cells: Vec<[Triple; CELL]>,
    /// Each cell's gateway `HierAddr`, pre-encoded at construction so a routing probe needs no field type.
    gateway_addrs: Vec<Vec<u8>>,
}

impl UnifiedCluster {
    /// Build `cell_count` coherent 7-node cells on the transport plane `F`, each node told its cell, each
    /// cell's member 0 a gateway that knows every other gateway (overlay root `[P_c]` → its transport), and
    /// start their heartbeats.
    ///
    /// # Panics
    /// If `7 · cell_count` exceeds the transport plane's point count.
    #[must_use]
    pub fn new<F: Field + 'static>(seed: u64, config: Config, cell_count: usize) -> Self {
        let plane_n = Plane::<F>::N as usize;
        assert!(cell_count * CELL <= plane_n, "{cell_count} cells exceed the {plane_n}-point plane");

        // Layout: cell c's members are transport points 7c..7c+6 (member 0 = its gateway); its overlay
        // gateway address is the root [P_c].
        let member_point = |c: usize, j: usize| Point::<F>::at(c * CELL + j);
        let gw_root = |c: usize| HierAddr::root(Point::<F>::at(c));
        let gw_transport = |c: usize| member_point(c, 0).coords();

        let mut sim = Sim::new(seed);
        let mut cells = Vec::with_capacity(cell_count);
        let mut gateway_addrs = Vec::with_capacity(cell_count);
        for c in 0..cell_count {
            let members: [Triple; CELL] = core::array::from_fn(|j| member_point(c, j).coords());
            for j in 0..CELL {
                let mut node = OverlayNode::<F>::new(member_point(c, j), config).with_cell_members(members);
                if j == 0 {
                    // The gateway: an overlay root that knows every cell's gateway, so cells route to one another.
                    node = node.with_hier_address(gw_root(c));
                    for k in 0..cell_count {
                        node = node.with_hier_peer(gw_root(k), gw_transport(k));
                    }
                }
                sim.add(Box::new(node));
            }
            cells.push(members);
            gateway_addrs.push(gw_root(c).encode());
        }
        sim.inject_all(&Command::StartHeartbeat);
        Self { sim, cells, gateway_addrs }
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

    /// Cell `c`'s member coordinates (position 0 is its gateway).
    #[must_use]
    pub fn cell(&self, c: usize) -> Option<&[Triple; CELL]> {
        self.cells.get(c)
    }

    /// Cell `c`'s gateway transport coordinate.
    #[must_use]
    pub fn gateway(&self, c: usize) -> Option<Triple> {
        self.cells.get(c).map(|m| m[0])
    }

    /// Advance every cell by `dur`.
    pub fn run_for(&mut self, dur: Duration) {
        self.sim.run_for(dur);
    }

    /// A guaranteed-fresh telemetry read across the whole cluster.
    pub fn refresh_telemetry(&mut self) {
        self.sim.refresh_telemetry();
    }

    /// Crash one node (by coordinate).
    pub fn crash(&mut self, coord: Triple) {
        self.sim.crash(coord);
    }

    /// The whole-cluster coherence snapshot (every cell's nodes report a self-model, all in one `Sim`).
    #[must_use]
    pub fn snapshot(&self) -> FleetSnapshot {
        self.sim.fleet_snapshot()
    }

    /// Whether cell `from`'s gateway routes a message to cell `to`'s gateway across the overlay.
    /// Report-isolated, so the result reflects only this probe.
    pub fn routes(&mut self, from: usize, to: usize) -> bool {
        let (Some(src), Some(dst_gw)) = (self.gateway(from), self.gateway(to)) else { return false };
        let Some(dst_addr) = self.gateway_addrs.get(to) else { return false };
        let mut body = dst_addr.clone();
        body.extend_from_slice(PROBE);
        let mut frame = Vec::new();
        encode_frame(FrameType::RouteHier.code(), &body, &mut frame);

        self.sim.clear_report();
        self.sim.inject_frame(src, src, frame);
        self.sim.run_for(Duration::from_millis(2_000));
        self.sim.report().notifications.iter().any(|o| {
            o.node == dst_gw
                && matches!(&o.note, Notification::Delivered { payload, .. } if payload == PROBE)
        })
    }

    /// The fraction of the given `(from, to)` cell pairs whose gateways reach each other.
    pub fn reachability(&mut self, pairs: &[(usize, usize)]) -> f64 {
        if pairs.is_empty() {
            return 1.0;
        }
        let ok = pairs.iter().filter(|&&(a, b)| self.routes(a, b)).count();
        ok as f64 / pairs.len() as f64
    }

    /// Mutable access to the underlying `Sim` — to inject cross-cell routing frames or faults.
    pub fn sim_mut(&mut self) -> &mut Sim {
        &mut self.sim
    }
}
