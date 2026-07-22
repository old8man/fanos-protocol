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

use fanos_core::roles::{Capability, Demand, Reputation, RoleController, RoleSet};
use fanos_field::Field;
use fanos_primitives::{BeaconSeed, Epoch, NodeId};
use fanos_quic::Client;
use fanos_runtime::Notification;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

use crate::capdir::build_capability_directory;
use crate::loaddir::build_cell_setpoint;

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
    /// (task A4). Because every node feeds the same agreed diagnosis, the reputation is identical cell-wide and
    /// the assignment stays deterministic.
    pub fn observe(&mut self, node: NodeId, performed: bool) {
        self.reputation.observe(node, performed);
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
    ) -> RoleSet {
        let weighted = self.reputation.adjust(members);
        let report = self.controller.step(&weighted, epoch, beacon, setpoint);
        report.roles.get(&self.node_id).copied().unwrap_or(RoleSet::EMPTY)
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
) -> (JoinHandle<()>, watch::Receiver<RoleSet>) {
    let (roles_tx, roles_rx) = watch::channel(RoleSet::EMPTY);
    let handle = tokio::spawn(async move {
        let mut live = LiveRoleController::new(node_id, controller);
        let mut events = client.subscribe();
        let mut cur = Epoch::ZERO;
        // Genesis-epoch assignment (before the first beacon) over whoever has published at genesis.
        assign_epoch::<F>(&client, &mut live, Epoch::ZERO, &BeaconSeed::GENESIS, capacity, &roles_tx).await;
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

/// One epoch of the loop: read the live authenticated capability directory *and* the cell-agreed setpoint (from
/// the live load directory), step the controller, publish this node's roles. `send` only fails if every
/// receiver has dropped (the node is shutting down) — ignored.
async fn assign_epoch<F: Field>(
    client: &Client,
    live: &mut LiveRoleController,
    epoch: Epoch,
    beacon: &BeaconSeed,
    capacity: Demand,
    roles_tx: &watch::Sender<RoleSet>,
) {
    let members = build_capability_directory::<F>(client, epoch).await;
    let setpoint = build_cell_setpoint::<F>(client, epoch, capacity).await;
    let roles = live.step(&members, epoch, beacon, setpoint);
    let _ = roles_tx.send(roles);
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
        let setpoint = Demand { relay: 3, ..Default::default() };
        let ctrl = || {
            RoleController::new(
                Demand { relay: 1, ..Default::default() },
                Demand { relay: 1, ..Default::default() },
                7, // κ = 1: jump straight to the setpoint
            )
        };
        let mut active = 0;
        let mut demand_after = 0;
        for i in 0..5u8 {
            let mut live = LiveRoleController::new(node(i), ctrl());
            if live.step(&members, Epoch::new(1), &beacon, setpoint).has(Role::Relay) {
                active += 1;
            }
            demand_after = live.demand().relay;
        }
        assert_eq!(active, 3, "the cell assigns exactly the demanded 3 relays across its members");
        assert_eq!(demand_after, 3, "each controller tracked the setpoint");
    }
}
