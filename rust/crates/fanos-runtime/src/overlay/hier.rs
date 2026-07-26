//! **Hierarchical addressing, routing and escalation** for [`OverlayNode`] (spec §L1) — split out of the facade's impl
//! (task 7a).
//!
//! A child module rather than a sibling, and the direction of Rust's privacy rule is why. A child reaches its parent's
//! private items, so these methods keep touching `OverlayNode`'s fields directly — no field visibility widened at all,
//! where the earlier slices had to make five `pub(crate)` to extract whole *types*.
//!
//! The rule does **not** run both ways, which the first attempt at this split assumed: a parent cannot see a *child's*
//! private items, so the four methods the facade dispatches to here (`on_route_hier`, `on_cell_escalate`,
//! `escalate_to_parent`, `escalate_up`) are `pub(super)`. That is the honest cost, and it is a narrower one than the
//! sibling case — `pub(super)` names exactly one module, while `pub(crate)` names the whole crate.
//!
//! What lives here: the node's own hierarchical address, the sub-cell peer table it learns from announcements, next-hop
//! resolution down the hierarchy, and escalation *up* to a parent cell when a level cannot resolve locally.

use alloc::vec::Vec;

use fanos_core::{ChildSummary, ParentCell};
use fanos_field::Field;
use fanos_geometry::{HierAddr, Plane, Point, Triple};
use fanos_wire::FrameType;

use super::{ESCALATE_TTL, OverlayNode, encode};
use crate::ports::{Effect, Notification};
use crate::router::HierRoute;

impl<F: Field> OverlayNode<F> {
    /// Seat this node at an overlay hierarchical address (builder), decoupled from its transport `coord`.
    /// A depth-1 node keeps the default `root(coord)`; a node that descended into a sub-cell (§L0), or a
    /// deployment that assigns transport addresses independently of overlay position, seats a deeper or
    /// different address here. Only the (type-guaranteed non-empty) address is needed — routing reads
    /// `hier`, transport reads `coord`, and the two need not coincide past depth 1 (a flat transport
    /// underlaying a structured overlay).
    #[must_use]
    pub fn with_hier_address(mut self, hier: HierAddr<F>) -> Self {
        self.router.address = hier;
        self
    }

    /// This node's hierarchical address (§L1).
    #[must_use]
    pub fn hier_address(&self) -> &HierAddr<F> {
        &self.router.address
    }

    /// Register a hierarchical peer reachable in one hop — the transport coordinate that reaches it and
    /// the overlay [`HierAddr`] it serves — replacing any existing address for that coordinate. This *is*
    /// the hierarchical routing table: `RouteHier` frames are forwarded greedily over it. A single-plane
    /// node needs none (transport ≡ overlay); a deployment or the membership layer seeds it for depth > 1.
    pub fn learn_hier_peer(&mut self, addr: HierAddr<F>, transport: Triple) {
        self.router.learn_peer(addr, transport);
    }

    /// Builder form of [`learn_hier_peer`](Self::learn_hier_peer).
    #[must_use]
    pub fn with_hier_peer(mut self, addr: HierAddr<F>, transport: Triple) -> Self {
        self.learn_hier_peer(addr, transport);
        self
    }

    /// The next-hop transport coordinate toward `dst`, or `None` if this node delivers `dst` locally or
    /// has no route to it. A thin accessor over [`Router::route`] for drivers and tests.
    #[must_use]
    pub fn hier_next_hop(&self, dst: &HierAddr<F>) -> Option<Triple> {
        match self.router.route(dst) {
            HierRoute::Forward(next) => Some(next),
            HierRoute::Deliver | HierRoute::Drop => None,
        }
    }

    /// Originate a hierarchical send to `dst`: deliver locally if we are its cell, else emit a
    /// `RouteHier` frame (`HierAddr(dst) ‖ payload`) toward the next hop — the driver entry a client
    /// uses to reach a multi-level destination (the single-plane [`on_send`](Self::on_send) is unchanged).
    pub fn send_hier(&mut self, dst: &HierAddr<F>, payload: &[u8]) -> Vec<Effect> {
        self.healer.record_origination();
        match self.router.route(dst) {
            HierRoute::Deliver => alloc::vec![Effect::Notify(Notification::Delivered {
                from: self.coord.coords(),
                payload: payload.to_vec(),
            })],
            HierRoute::Forward(next) => {
                let mut body = dst.encode();
                body.extend_from_slice(payload);
                alloc::vec![self.routed_send(next, encode(FrameType::RouteHier, &body))]
            }
            HierRoute::Drop => Vec::new(),
        }
    }

    /// Handle an incoming `RouteHier` frame (`HierAddr(dst) ‖ payload`): deliver if we are in the
    /// destination cell, else forward one cell closer (see [`Router::route`]). The
    /// destination address travels unchanged, so every hop re-derives its own next step.
    pub(super) fn on_route_hier(&mut self, from: Triple, body: &[u8]) -> Vec<Effect> {
        let Some(&depth) = body.first() else {
            return Vec::new();
        };
        let addr_len = 1 + usize::from(depth) * 12;
        let Some(dst) = body.get(..addr_len).and_then(HierAddr::<F>::decode) else {
            return Vec::new();
        };
        let payload = body.get(addr_len..).unwrap_or(&[]);
        match self.router.route(&dst) {
            HierRoute::Deliver => {
                self.healer.record_relay(from);
                alloc::vec![Effect::Notify(Notification::Delivered {
                    from,
                    payload: payload.to_vec(),
                })]
            }
            HierRoute::Forward(next) => {
                alloc::vec![self.routed_send(next, encode(FrameType::RouteHier, body))]
            }
            HierRoute::Drop => Vec::new(),
        }
    }

    /// Hand this cell's irrecoverable `residue` up to the **parent stratum** (audit R-C2): send a
    /// [`CellEscalate`](FrameType::CellEscalate) to each member of the parent cell — the cells that are this
    /// node's siblings one level up — so a sibling folds the failure into its [`ParentCell`] reflex and
    /// coarse-reroutes around this (failed) child cell. A depth-1 (top-stratum) cell has no parent, so its
    /// escalation is terminal (external help) and this is a no-op.
    pub(super) fn escalate_to_parent(&mut self, residue: u8) -> Vec<Effect> {
        self.escalate_up(residue, ESCALATE_TTL)
    }

    /// The bounded escalation step: route the residue to the parent cell's sibling members, decrementing `ttl`
    /// each stratum so the upward recursion terminates (the HOLARCH depth ceiling).
    pub(super) fn escalate_up(&mut self, residue: u8, ttl: u8) -> Vec<Effect> {
        // The child cell's point in the parent (the address's second-to-last level) and the parent cell's own
        // prefix (empty at depth 2 → the top cell). Extracted as owned values so the router is free below.
        let (child_index, prefix): (usize, Vec<Point<F>>) = {
            let addr = &self.router.address;
            let depth = addr.depth();
            if depth < 2 {
                return Vec::new(); // top stratum: no parent to escalate to
            }
            let Some(child_point) = addr.point_at(depth - 2) else {
                return Vec::new();
            };
            let prefix = addr.points().get(..depth - 2).map(<[Point<F>]>::to_vec).unwrap_or_default();
            (child_point.index(), prefix)
        };
        // Resolve each sibling's next-hop transport coordinate — the parent-prefix descended into each OTHER
        // point (a direct base-point send at depth 2; a `RouteHier` hop deeper).
        let mut targets: Vec<Triple> = Vec::new();
        for i in 0..Plane::<F>::N as usize {
            let sib = Point::<F>::at(i);
            if sib.index() == child_index {
                continue; // skip the failed child itself
            }
            let mut path = prefix.clone();
            path.push(sib);
            if let Some(sib_addr) = HierAddr::from_path(path)
                && let HierRoute::Forward(next) = self.router.route(&sib_addr)
                && next != self.coord.coords()
            {
                targets.push(next); // never escalate to ourselves
            }
        }
        let frame = encode(FrameType::CellEscalate, &[child_index as u8, residue, ttl]);
        targets.into_iter().map(|to| self.routed_send(to, frame.clone())).collect()
    }

    /// A received [`CellEscalate`](FrameType::CellEscalate): fold the failed child cell into this node's
    /// parent-tier [`ParentCell`] reflex, spend the coarse `⌊log₉Φ⌋` reroute budget, and act — install coarse
    /// reroutes around the failed child if the parent absorbs it, else hand the aggregate up to the
    /// grandparent (bounded by `ttl`), else emit a terminal `Escalated` (external help). This is the DIAKRISIS
    /// decoder recursing one stratum up: a child cell is one "node" of the parent Fano cell (§6.3, R-C2).
    pub(super) fn on_cell_escalate(&mut self, body: &[u8]) -> Vec<Effect> {
        let &[child_index, residue, ttl] = body else {
            return Vec::new();
        };
        let Some(self_index) = self.self_index else {
            return Vec::new(); // off the base cell — the coarse index geometry does not apply
        };
        if usize::from(child_index) >= Plane::<F>::N as usize || usize::from(child_index) == self_index {
            return Vec::new(); // a nonsensical child, or ourselves
        }
        let phi = self.healer.last_phi();
        let parent = self.parent_cell.get_or_insert_with(|| ParentCell::new(self_index));
        parent.observe(usize::from(child_index), ChildSummary::escalated(residue));
        let parent = *parent; // Copy out — end the mutable borrow of `self` before escalating further

        let mut effects = Vec::new();
        if parent.contains_escalation(phi) {
            // The parent absorbs it: install the coarse reroutes (failed child → via a co-linear sibling) and
            // mark the child repaired at the coarse tier.
            for (around, via) in parent.coarse_reroutes(phi) {
                // Parent positions → the parent cell's real member coordinates (base cell: Point::at).
                effects.push(Effect::Notify(Notification::Rerouted {
                    around: self.cell_coord(around),
                    via: self.cell_coord(via),
                }));
            }
            effects.push(Effect::Notify(Notification::Repaired(self.cell_coord(usize::from(child_index)))));
        } else {
            // The parent tier cannot absorb within its own Φ-budget: hand the AGGREGATE coarse residue up to
            // the grandparent if there is one (bounded), else terminal — external help required.
            let aggregate = parent.degraded_mask();
            let up = if ttl > 0 { self.escalate_up(aggregate, ttl - 1) } else { Vec::new() };
            if up.is_empty() {
                effects.push(Effect::Notify(Notification::Escalated(aggregate)));
            } else {
                effects.extend(up);
            }
        }
        effects
    }
}
