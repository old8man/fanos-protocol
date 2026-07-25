//! The **live self-organizing role loop** — the driver that runs a node's [`RoleController`] over the real
//! overlay each beacon round (task A2; the sans-I/O controller is `fanos_core::roles`).
//!
//! Each epoch the loop reads the cell's authenticated capability directory ([`crate::capdir`]), steps the
//! controller (the UHM-grounded Lyapunov-descent demand rebalance + role assignment), extracts *this* node's
//! assigned roles, and publishes them on a `watch` channel the node acts on. The setpoint — how much of each
//! role the cell wants — is supplied on another `watch` channel a load sensor drives (task A3); until that is
//! wired the node holds a fixed target.
//!
//! Composition with [`crate::capdir`]: a node runs *two* tasks — [`crate::capdir::spawn_capability_publisher`]
//! keeps its own advertisement live, and [`spawn_role_loop`] reads the whole roster and computes its
//! assignment. Because every node steps an identical controller over the same agreed inputs (authenticated
//! capabilities, the shared beacon, the agreed setpoint), the cell reaches the same assignment with no
//! coordination — the deterministic self-organization proven in `fanos-core/tests/self_organization.rs`, now
//! over the live directory.

use core::time::Duration;

use fanos_core::roles::{Capability, Demand, Reputation, RoleController, RoleSet};
use fanos_diaulos::Coord;
use fanos_field::Field;
use fanos_primitives::{BeaconSeed, Epoch, NodeId};
use fanos_quic::Client;
use fanos_runtime::Notification;
use fanos_vrf::VrfSecret;
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::JoinHandle;

use crate::capdir::{build_capability_directory, spawn_capability_publisher};
use crate::loaddir::{build_cell_setpoint, spawn_load_publisher};

/// This node's assignment for an epoch, **with the roster it was computed over**.
///
/// The roster is not decoration. The assignment is only *cell-agreed* when every member stepped the controller over
/// the same live set — the property [`spawn_role_loop`]'s determinism rests on. A node's own capability and load slots
/// are **local** store reads, so a node that can reach nobody still resolves itself, computes a perfectly valid
/// assignment over a roster of one, and cannot tell the difference. Measured on the composed-node fleet: at 90% loss,
/// four datagrams delivered in total, every member reported a complete assignment
/// (`docs/design-testing.md` §5.3).
///
/// Carrying the roster makes that visible instead of implicit. There is deliberately **no quorum threshold** here — a
/// fresh or genuinely small cell must still be able to start — so the judgement is left to the caller, with
/// [`is_solitary`](Self::is_solitary) covering the one case that needs no policy at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Assignment {
    /// The roles the cell assigned this node.
    pub roles: RoleSet,
    /// How many authenticated cell members the assignment was computed over, including this node. `0` before the
    /// first assignment.
    pub roster: usize,
    /// The epoch it was computed for.
    pub epoch: Epoch,
}

impl Assignment {
    /// The empty assignment, before the first one is computed.
    pub const NONE: Self = Self { roles: RoleSet::EMPTY, roster: 0, epoch: Epoch::ZERO };

    /// Whether this node saw **no other member** — so the assignment is its own guess, not the cell's decision.
    ///
    /// Threshold-free on purpose: `roster ≤ 1` needs no policy to interpret. A subsystem whose safety depends on
    /// cell-wide agreement should decline to act on a solitary assignment; [`crate::rendezvous_host`] coverage is the
    /// motivating case, since a rendezvous line's membership *is* the anonymity set a hidden service hides in, and
    /// over-estimating it is a privacy claim the cell cannot back.
    #[must_use]
    pub fn is_solitary(self) -> bool {
        self.roster <= 1
    }
}

/// A node's **sans-I/O** live role controller: it holds the epoch-persistent [`RoleController`] state and, for a
/// given epoch's authenticated member set, beacon, and setpoint, produces *this* node's assigned [`RoleSet`].
/// The async loop below is a thin driver over it, so the identical logic runs under the simulator and a live
/// node.
pub struct LiveRoleController {
    node_id: NodeId,
    controller: RoleController,
    reputation: Reputation,
}

impl LiveRoleController {
    /// Build a live controller for `node_id` over the demand controller `controller`, with a fresh reputation
    /// (every node fully trusted until observed).
    #[must_use]
    pub fn new(node_id: NodeId, controller: RoleController) -> Self {
        Self { node_id, controller, reputation: Reputation::new() }
    }

    /// The controller's current demand (its internal state).
    #[must_use]
    pub fn demand(&self) -> Demand {
        self.controller.demand()
    }

    /// Record whether a node served its assigned role last epoch, from the cell's (agreed) coherence
    /// self-diagnosis — a non-performer's effective weight decays, so the next assignment prefers performers
    /// (task A4). A node the cell corroborates as **unreachable** (`reachable = false`) is excused rather than
    /// slashed (audit R-H2): an outage from a mass failure must not cost a node its role on return. Because
    /// every node feeds the same agreed diagnosis *and* reachability (spec §6.4 witnessed liveness), the
    /// reputation is identical cell-wide and the assignment stays deterministic.
    pub fn observe(&mut self, node: NodeId, performed: bool, reachable: bool) {
        self.reputation.observe_reachable(node, performed, reachable);
    }

    /// One epoch: apply reputation to the members' weights, rebalance the demand toward `setpoint`, assign
    /// roles, and return *this* node's assigned roles for `(epoch, beacon)`. Deterministic given the same
    /// inputs (including the agreed reputation) on every node.
    pub fn step(
        &mut self,
        members: &[(NodeId, Capability)],
        epoch: Epoch,
        beacon: &BeaconSeed,
        setpoint: Demand,
    ) -> Assignment {
        let weighted = self.reputation.adjust(members);
        let report = self.controller.step(&weighted, epoch, beacon, setpoint);
        let roles = report.roles.get(&self.node_id).copied().unwrap_or(RoleSet::EMPTY);
        Assignment { roles, roster: members.len(), epoch }
    }
}

/// Spawn the live role loop for a node on plane `F`. Returns the task handle and a `watch` receiver that
/// carries this node's currently-assigned [`RoleSet`] — the node subscribes to it and starts/stops serving
/// each role as the assignment rotates. `capacity` is the per-node capacity per role, from which the loop
/// derives the cell-agreed setpoint out of the live load directory ([`crate::loaddir`]) each epoch. The loop
/// assigns once immediately (the genesis epoch) and then on every real [`Notification::BeaconReady`]; it ends
/// when the notification stream closes. Must run inside a tokio runtime.
#[must_use]
pub fn spawn_role_loop<F: Field>(
    client: Client,
    node_id: NodeId,
    controller: RoleController,
    capacity: Demand,
    ready: (oneshot::Receiver<()>, oneshot::Receiver<()>),
) -> (JoinHandle<()>, watch::Receiver<Assignment>) {
    let (roles_tx, roles_rx) = watch::channel(Assignment::NONE);
    let handle = tokio::spawn(async move {
        let mut live = LiveRoleController::new(node_id, controller);
        let mut events = client.subscribe();
        let mut cur = Epoch::ZERO;
        genesis_assign::<F>(&client, &mut live, capacity, ready, &roles_tx).await;
        loop {
            match events.recv().await {
                Ok(Notification::BeaconReady { epoch, seed }) if epoch > cur => {
                    cur = epoch;
                    assign_epoch::<F>(&client, &mut live, epoch, &BeaconSeed::new(seed), capacity, &roles_tx).await;
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    (handle, roles_rx)
}

/// How long the genesis assignment waits for this node's own publishes to land before giving up and leaving the
/// first assignment to the beacon. Bounded so a node whose store is unreachable does not hang its role loop.
const GENESIS_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// The **genesis assignment**, before any beacon round.
///
/// It cannot simply run once. The capability publisher writes this node's own advertisement from a *sibling task*, so
/// a single attempt races it and can assign over a roster that does not yet contain the node itself — and on a cell
/// whose beacon clock has not started, nothing would ever revisit that. (The same race applies to every peer's
/// publish, which is why a node booting first always sees a thin directory.)
///
/// So it waits for **both** of this node's own publishes to signal — its capability advertisement *and* its load
/// report. Both are needed and for different reasons: the capability decides who is *eligible*, while the load decides
/// the *setpoint*, and a setpoint of zero correctly assigns nobody. Waiting on only one produced an empty assignment
/// that read like a controller fault and was actually a missing input.
///
/// The publishers *signal* rather than the loop polling the directory. Polling looks equivalent and is not: each poll
/// costs a full cell-wide scan bounded by [`RESOLVE_TIMEOUT`](crate::resolve), so a retry loop cannot converge
/// promptly, and a node's first epoch would silently serve nothing.
async fn genesis_assign<F: Field>(
    client: &Client,
    live: &mut LiveRoleController,
    capacity: Demand,
    ready: (oneshot::Receiver<()>, oneshot::Receiver<()>),
    roles_tx: &watch::Sender<Assignment>,
) {
    let (capability_ready, load_ready) = ready;
    let both = async {
        let _ = capability_ready.await;
        let _ = load_ready.await;
    };
    if tokio::time::timeout(GENESIS_READY_TIMEOUT, both).await.is_err() {
        return; // the store is not answering; the beacon's first round will assign instead
    }
    assign_epoch::<F>(client, live, Epoch::ZERO, &BeaconSeed::GENESIS, capacity, roles_tx).await;
}

/// One epoch of the loop: read the live authenticated capability directory *and* the cell-agreed setpoint (from
/// the live load directory), step the controller, publish this node's roles. `send` only fails if every
/// receiver has dropped (the node is shutting down) — ignored.
async fn assign_epoch<F: Field>(
    client: &Client,
    live: &mut LiveRoleController,
    epoch: Epoch,
    beacon: &BeaconSeed,
    capacity: Demand,
    roles_tx: &watch::Sender<Assignment>,
) {
    let members = build_capability_directory::<F>(client, epoch).await;
    let setpoint = build_cell_setpoint::<F>(client, epoch, capacity).await;
    let roles = live.step(&members, epoch, beacon, setpoint);
    let _ = roles_tx.send(roles);
}

/// The running self-organizing subsystem of a node: the three background tasks (capability publisher, load
/// publisher, role loop) and the `watch` receiver carrying this node's currently-assigned roles.
pub struct SelfOrganization {
    /// Keeps the node's capability advertisement live each epoch.
    pub capability_publisher: JoinHandle<()>,
    /// Keeps the node's load report live each epoch.
    pub load_publisher: JoinHandle<()>,
    /// Runs the assignment each epoch.
    pub role_loop: JoinHandle<()>,
    /// This node's currently-assigned roles — the node subscribes and actuates its role behaviors from it.
    pub assigned: watch::Receiver<Assignment>,
}

/// A node's inputs to the self-organizing subsystem: its identity (`node_id`, `vrf_secret`), the `capability`
/// it offers, its per-node `capacity` per role, and the demand `controller` (initial demand/floor/gain).
pub struct SelfOrgConfig {
    /// The node's identity.
    pub node_id: NodeId,
    /// The node's coordinate-VRF secret (signs its capability advertisement).
    pub vrf_secret: VrfSecret,
    /// The roles the node offers and its capacity weight.
    pub capability: Capability,
    /// The per-node capacity per role (the load one node absorbs) — the setpoint denominator.
    pub capacity: Demand,
    /// The demand controller (its initial demand, floor, and loop gain).
    pub controller: RoleController,
}

/// Spawn a node's **entire self-organizing subsystem** on plane `F` — the single call `Node::start` makes to
/// join the live role loop. It advertises the node's offered capability, reports its observed load
/// (`load_source`), and runs its role loop, so the cell assigns and rotates the node's roles each epoch with no
/// further input. The caller actuates the returned [`SelfOrganization::assigned`] roles (starting/stopping each
/// behavior as the assignment changes). Must run inside a tokio runtime.
#[must_use]
pub fn spawn_self_organization<F: Field>(
    client: Client,
    coord: Coord,
    config: SelfOrgConfig,
    load_source: impl Fn() -> Demand + Send + 'static,
) -> SelfOrganization {
    let SelfOrgConfig { node_id, vrf_secret, capability, capacity, controller } = config;
    let (capability_publisher, capability_ready) =
        spawn_capability_publisher(client.clone(), coord, node_id, vrf_secret, capability);
    let (load_publisher, load_ready) = spawn_load_publisher(client.clone(), coord, load_source);
    let (role_loop, assigned) =
        spawn_role_loop::<F>(client, node_id, controller, capacity, (capability_ready, load_ready));
    SelfOrganization { capability_publisher, load_publisher, role_loop, assigned }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fanos_core::roles::{Capability, Role, RoleSet};

    fn node(i: u8) -> NodeId {
        NodeId([i; 32])
    }

    #[test]
    fn the_live_controller_assigns_this_nodes_roles_and_tracks_the_setpoint() {
        // A 5-node relay-capable cell; every node runs its own live controller over the same members, and the
        // slices sum to the cell-wide assignment — each reports exactly its own share.
        let members: Vec<(NodeId, Capability)> =
            (0..5).map(|i| (node(i), Capability::new(RoleSet::of(&[Role::Relay]), 4))).collect();
        let beacon = BeaconSeed::new([0x33; 32]);
        let setpoint = Demand::per_role(|r| if r == Role::Relay { 3 } else { 0 });
        let ctrl = || {
            RoleController::new(
                Demand::per_role(|r| u16::from(r == Role::Relay)),
                Demand::per_role(|r| u16::from(r == Role::Relay)),
                7, // κ = 1: jump straight to the setpoint
            )
        };
        let mut active = 0;
        let mut demand_after = 0;
        for i in 0..5u8 {
            let mut live = LiveRoleController::new(node(i), ctrl());
            if live.step(&members, Epoch::new(1), &beacon, setpoint).roles.has(Role::Relay) {
                active += 1;
            }
            demand_after = live.demand().of(Role::Relay);
        }
        assert_eq!(active, 3, "the cell assigns exactly the demanded 3 relays across its members");
        assert_eq!(demand_after, 3, "each controller tracked the setpoint");
    }
}
