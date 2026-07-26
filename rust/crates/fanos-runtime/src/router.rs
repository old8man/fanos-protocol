//! The overlay's **routing table and peer liveness view**, split out of `overlay.rs` (task 7a).
//!
//! `Router` answers "who is the next hop", over both the flat plane and the hierarchy (`HierRoute`), and holds the
//! per-peer heartbeat state (`Peer`) that liveness is derived from. It is deliberately generic over `F`: a next hop is a
//! question about the plane's geometry.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_field::Field;
use fanos_geometry::{HierAddr, Point, Triple, next_hop};

use crate::ports::Instant;
/// What we know about a cell neighbour.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Peer {
    pub(crate) last_seen: Option<Instant>,
    pub(crate) reported_down: bool,
    /// EWMA of this channel's per-round **loss** (spec §6.3 grey detection): each heartbeat samples whether
    /// last round's `Ping` was answered (0) or not (1) and folds it at [`LOSS_EWMA_ALPHA`]. A grey neighbour —
    /// heartbeat-present but dropping a fraction of its `Pong`s — settles at an elevated loss while an honest
    /// one stays near the network floor; gossiped as `DiagLoss` and localized by `polar::grey_endpoint`.
    pub(crate) loss: f64,
    /// Whether this round's `Ping` is still outstanding (no `Pong` seen since it was sent) — the per-round
    /// loss sample the heartbeat folds into [`loss`](Self::loss).
    pub(crate) awaiting_pong: bool,
}

/// The forwarding decision for a `RouteHier` frame at a node (see [`Router::route`]).
pub(crate) enum HierRoute {
    /// This node is in the destination cell — deliver the payload locally.
    Deliver,
    /// Forward to this transport coordinate, one hop closer to the destination.
    Forward(Triple),
    /// Not the destination and no known peer is closer — drop (a routing hole).
    Drop,
}

/// The hierarchical-routing concern factored out of [`OverlayNode`] (audit #125 decompose): this node's
/// own overlay address plus its learned longest-prefix routing table, and the pure `RouteHier` forwarding
/// decision over them. Transport — the physical `coord` — stays on the facade: a flat transport underlays
/// this structured overlay and the two need not coincide past depth 1. This owns the addressing state and
/// the routing decision; the facade orchestrates the frame flow (an `Announce` carries the address out,
/// `on_announce` seeds a learned peer from one received).
pub(crate) struct Router<F: Field> {
    /// This node's hierarchical address (§L1). Defaults to the depth-1 `root(coord)` — the ordinary
    /// single-plane case — and is deepened only when the node descends into a sub-cell on a collision
    /// (§L0). It governs hierarchical (`RouteHier`) forwarding; single-plane routing is unchanged.
    pub(crate) address: HierAddr<F>,
    /// Learned hierarchical routing table: **transport coordinate → the overlay [`HierAddr`] reachable
    /// there**. Empty on a single-plane node (transport ≡ overlay); populated as the node learns sub-cell
    /// gateways and siblings (a deployment seed, or a JOIN/Announce). `RouteHier` forwarding is greedy
    /// longest-prefix over the addresses ([`next_hop`]), then resolved back to the transport coordinate to
    /// send on — this is what lets a node route *through* cells it is not a member of, and it decouples the
    /// node's transport coordinate (`coord`) from its overlay address (`address`), as a flat transport
    /// underlays a structured overlay. **Keyed by transport coordinate** (one overlay address per physical
    /// endpoint), so — exactly like [`OverlayNode::members`] — it is bounded by the plane size `N`: a peer
    /// cannot grow it without limit by announcing many forged addresses (audit C1/C2 DoS class). Like
    /// `members` it is an attacker-*writable* discovered view; safety does not rest on its integrity —
    /// delivery is decided by this node's own cert-bound `address`, so a poisoned entry can only misroute
    /// or blackhole (a bounded DoS), never impersonate a destination. Cert-verifying an announced address
    /// against its coordinate (poisoning resistance) is the QUIC-layer follow-up.
    pub(crate) peers: BTreeMap<Triple, HierAddr<F>>,
}

impl<F: Field> Router<F> {
    /// Seat this node at its default depth-1 overlay address `root(coord)`, with an empty routing table.
    /// A deployment that descends into a sub-cell or assigns overlay position independently of transport
    /// re-seats the address afterwards ([`OverlayNode::with_hier_address`]).
    pub(crate) fn new(coord: Point<F>) -> Self {
        Self {
            address: HierAddr::root(coord),
            peers: BTreeMap::new(),
        }
    }

    /// Register a hierarchical peer reachable in one hop — the transport coordinate that reaches it and the
    /// overlay [`HierAddr`] it serves — replacing any existing address for that coordinate. This *is* the
    /// hierarchical routing table: `RouteHier` frames are forwarded greedily over it. A single-plane node
    /// needs none (transport ≡ overlay); a deployment or the membership layer seeds it for depth > 1.
    pub(crate) fn learn_peer(&mut self, addr: HierAddr<F>, transport: Triple) {
        self.peers.insert(transport, addr);
    }

    /// Resolve the forwarding decision for hierarchical destination `dst` (§L1). If this node is already
    /// in `dst`'s cell it delivers. Otherwise, with **learned peers**, it routes greedily by longest
    /// shared prefix ([`next_hop`]) and resolves the chosen overlay address to its transport coordinate —
    /// the physical hop one level closer, so forwarding converges in `≤ dst.depth − commonPrefix` hops. A
    /// node with **no learned peers** (the bootstrap origin, or a single populated plane) targets `dst`'s
    /// own point at the divergence level directly. No closer peer and not the destination ⇒ drop (hole).
    pub(crate) fn route(&self, dst: &HierAddr<F>) -> HierRoute {
        if self.address.common_prefix(dst) == dst.depth() {
            return HierRoute::Deliver;
        }
        if !self.peers.is_empty() {
            let reachable: Vec<HierAddr<F>> = self.peers.values().cloned().collect();
            return match next_hop(&self.address, dst, &reachable) {
                Some(next) => self
                    .peers
                    .iter()
                    .find(|(_, a)| **a == next)
                    .map_or(HierRoute::Drop, |(t, _)| HierRoute::Forward(*t)),
                None => HierRoute::Drop,
            };
        }
        dst.point_at(self.address.common_prefix(dst))
            .map_or(HierRoute::Drop, |p| HierRoute::Forward(p.coords()))
    }
}
