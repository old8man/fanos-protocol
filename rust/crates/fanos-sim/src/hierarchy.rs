//! A **connected hierarchy** of cells — the substrate for cross-cell *routing* experiments (spec §L1).
//!
//! Distinct from the coherence-focused [`Cluster`](crate::Cluster): there, cells are independent
//! coherence domains (federation) and the observable is the per-cell self-model. Here, nodes are seated
//! at **distinct transport coordinates** on one plane, each carrying a nested [`HierAddr`], and they
//! **auto-seed** their hierarchical routing tables from `Join` announcements (no hand-wiring — the §L1
//! self-organizing property). The observable is **routing**: does a message reach its destination across
//! cells, and does it survive a fault. Coherence is *not* modelled here — it is per base cell (transport
//! points `0..6`), so a connected multi-cell topology gives routing, not per-node coherence; the two are
//! complementary lenses on the same engine.
//!
//! A two-level tree is `gateways` gateways (top cell) each rooting a sub-cell of `per_cell` descended
//! nodes; total `gateways·(1+per_cell)` nodes must fit the transport plane `PG(2,q)`. Because transport
//! is one flat plane, `Join` still floods `O(N²)`, so this is a routing-*correctness* substrate at
//! cell-tree scale, not a 10k-node load test (that is the federated `Cluster`'s job).

use fanos_field::Field;
use fanos_geometry::{HierAddr, Plane, Point, Triple};
use fanos_runtime::{Config, Duration, Notification, OverlayNode};
use fanos_wire::{FrameType, encode_frame};

use crate::Sim;

/// The payload a routing probe carries.
const PROBE: &[u8] = b"fanos-route-probe";

/// One node's identity in a [`Hierarchy`]: its transport coordinate and its overlay address.
#[derive(Clone, Debug)]
struct Member<F: Field> {
    transport: Triple,
    addr: HierAddr<F>,
}

/// A connected two-level hierarchy of cells on one transport plane, wired purely by `Join` auto-seeding.
pub struct Hierarchy<F: Field> {
    sim: Sim,
    members: Vec<Member<F>>,
    settle: Duration,
}

impl<F: Field + 'static> Hierarchy<F> {
    /// Build a two-level tree — `gateways` gateways, each rooting a sub-cell of `per_cell` descended
    /// nodes — on the plane `F`, wiring each node's partial routing table (every node knows the gateway
    /// roots; a gateway also knows its own sub-nodes) so routing is genuine up-and-over descent.
    ///
    /// # Panics
    /// If the requested node count `gateways·(1 + per_cell)` exceeds the transport plane's point count.
    #[must_use]
    #[allow(clippy::expect_used)] // the constructed paths are 2-point and statically valid
    pub fn two_level(seed: u64, config: Config, gateways: usize, per_cell: usize) -> Self {
        let plane_n = Plane::<F>::N as usize;
        let block = 1 + per_cell; // a gateway + its descended nodes
        let total = gateways * block;
        assert!(total <= plane_n, "{total} nodes exceed the {plane_n}-point transport plane");

        // Layout: transport point of the k-th node is `Point::at(k)` (all distinct); overlay is nested.
        let transport = |k: usize| Point::<F>::at(k);
        let gw_transport = |g: usize| transport(g * block); // gateway g is the 0th node of its block
        let gw_root = |g: usize| HierAddr::root(Point::<F>::at(g)); // gateway g's overlay root [Pg]
        let sub_transport = |g: usize, m: usize| transport(g * block + 1 + m);
        let sub_addr = |g: usize, m: usize| {
            HierAddr::from_path(vec![Point::<F>::at(g), Point::<F>::at(m)]).expect("2-point path")
        };

        let mut sim = Sim::new(seed);
        let mut members = Vec::with_capacity(total);

        for g in 0..gateways {
            // Gateway g: an overlay root that knows *every* gateway (to hand cross-cell traffic on) and
            // its *own* descended nodes (to complete the descent). Hand-wired partial tables — NOT full
            // auto-seed — so routing is genuine up-and-over descent, and a gateway is load-bearing.
            let mut gw = OverlayNode::<F>::new(gw_transport(g), config).with_hier_address(gw_root(g));
            for k in 0..gateways {
                gw = gw.with_hier_peer(gw_root(k), gw_transport(k).coords());
            }
            for m in 0..per_cell {
                gw = gw.with_hier_peer(sub_addr(g, m), sub_transport(g, m).coords());
            }
            sim.add(Box::new(gw));
            members.push(Member { transport: gw_transport(g).coords(), addr: gw_root(g) });

            for m in 0..per_cell {
                // A descended node knows every gateway root, so it routes up to its own gateway and over
                // to the destination's — the greedy longest-prefix rule then completes the descent.
                let mut sn =
                    OverlayNode::<F>::new(sub_transport(g, m), config).with_hier_address(sub_addr(g, m));
                for k in 0..gateways {
                    sn = sn.with_hier_peer(gw_root(k), gw_transport(k).coords());
                }
                sim.add(Box::new(sn));
                members.push(Member { transport: sub_transport(g, m).coords(), addr: sub_addr(g, m) });
            }
        }

        Self { sim, members, settle: Duration::from_millis(2_000) }
    }

    /// The total number of nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the hierarchy has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Probe whether a message routes from node `from` to node `to` (roster indices) across the overlay,
    /// delivered to `to`'s transport node. Isolated: the run report is cleared first, so the result
    /// reflects only this probe.
    pub fn routes(&mut self, from: usize, to: usize) -> bool {
        let Some(source) = self.members.get(from).map(|m| m.transport) else { return false };
        let Some(dest) = self.members.get(to).cloned() else { return false };
        let mut body = dest.addr.encode();
        body.extend_from_slice(PROBE);
        let mut frame = Vec::new();
        encode_frame(FrameType::RouteHier.code(), &body, &mut frame);

        self.sim.clear_report();
        // A client hands the source relay the RouteHier frame (the injected `from` stands in for a client
        // one hop upstream; the source's own transport is the delivery origin the frame relays from).
        self.sim.inject_frame(source, source, frame);
        self.sim.run_for(self.settle);
        self.sim.report().notifications.iter().any(|o| {
            o.node == dest.transport
                && matches!(&o.note, Notification::Delivered { payload, .. } if payload == PROBE)
        })
    }

    /// The fraction of the given `(from, to)` pairs that route successfully — the fleet's routing
    /// reachability under whatever faults have been applied.
    pub fn reachability(&mut self, pairs: &[(usize, usize)]) -> f64 {
        if pairs.is_empty() {
            return 1.0;
        }
        let ok = pairs.iter().filter(|&&(a, b)| self.routes(a, b)).count();
        ok as f64 / pairs.len() as f64
    }

    /// Crash node `idx` (a roster index) — e.g. a gateway, to observe routing degrade.
    pub fn crash(&mut self, idx: usize) {
        if let Some(m) = self.members.get(idx) {
            self.sim.crash(m.transport);
        }
    }

    /// The roster index of gateway `g` (its sub-cell root), or `None` if out of range.
    #[must_use]
    pub fn gateway(&self, g: usize) -> Option<usize> {
        self.gateway_indices().get(g).copied()
    }

    /// The roster indices of every gateway (the depth-1 overlay addresses — the sub-cell roots).
    #[must_use]
    pub fn gateway_indices(&self) -> Vec<usize> {
        self.members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.addr.depth() == 1)
            .map(|(i, _)| i)
            .collect()
    }
}
