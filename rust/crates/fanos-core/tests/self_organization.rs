//! End-to-end simulation of the **self-organizing role loop** over a projective cell (`docs/design-self-
//! organization.md`). Every node runs its *own* [`RoleController`] on the *same* agreed inputs (signed
//! capabilities, the epoch beacon, the telemetry-derived setpoint), so the cell reaches the **same** role
//! assignment with no coordination — deterministic self-organization — while the demand tracks a changing load
//! by the UHM-grounded Lyapunov descent, roles rotate each epoch, and a shortfall escalates to the parent cell.
//!
//! The load-bearing design point this exercises: role assignment is deterministic *because* its inputs are
//! agreed. Capabilities are signed and advertised; the beacon is unbiasable and shared; the setpoint is derived
//! from a telemetry figure the cell agrees on (a consensus-committed or gossip-agreed aggregate). Given those,
//! each node's controller stays in lockstep with every other's — the cell decides *who does what* without a
//! leader, and any node can verify a peer's roles.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use fanos_core::roles::{
    assigned, AssignReport, Capability, Demand, Role, RoleController, RoleSet, GAIN_BOOTSTRAP_SEVENTHS,
};
use fanos_primitives::{BeaconSeed, Epoch, NodeId};

const BEACON: BeaconSeed = BeaconSeed::new([0x2E; 32]);

fn node(i: u8) -> NodeId {
    NodeId([i; 32])
}

/// A heterogeneous 13-node cell (a `q = 3` cell, `N = q²+q+1 = 13`): 8 relay-capable nodes of mixed capacity,
/// 6 storage-capable, and a scarce 3 exit-capable — with deliberate multi-role overlap.
fn heterogeneous_cell() -> Vec<(NodeId, Capability)> {
    (0..13u8)
        .map(|i| {
            let mut roles = Vec::new();
            if i < 8 {
                roles.push(Role::Relay);
            }
            if (3..9).contains(&i) {
                roles.push(Role::Storage);
            }
            if i >= 10 {
                roles.push(Role::Exit);
            }
            // Capacity weight varies across the cell (some nodes are fatter pipes than others).
            let weight = 1 + u16::from(i % 4) * 4;
            (node(i), Capability::new(RoleSet::of(&roles), weight))
        })
        .collect()
}

/// The relay **setpoint trajectory** — the *absolute* number of active relays the telemetry says the load
/// wants each epoch (a driver computes this as `⌈observed_load / per_node_capacity⌉`). It ramps up past the
/// 8-relay supply (congestion + deficit), holds, then relaxes back to slack — the disturbance the homeostat
/// must track.
const RELAY_WANT: [u16; 24] = [2, 3, 4, 6, 8, 10, 12, 12, 12, 11, 10, 8, 7, 6, 5, 4, 3, 2, 2, 2, 3, 4, 5, 5];

/// Wrap the driver's desired relay count into a per-role setpoint (storage held steady at 4).
fn setpoint(relay_want: u16) -> Demand {
    Demand { relay: relay_want, storage: 4, ..Demand::default() }
}

#[test]
fn a_cell_self_organizes_roles_in_lockstep_over_epochs() {
    let members = heterogeneous_cell();
    let relay_supply = Demand::supply(&members).relay; // 8 relay-capable nodes

    // Every node runs an identical controller — same initial demand, floor, and gain (κ = 3/7).
    let start = Demand { relay: 2, storage: 4, ..Demand::default() };
    let floor = Demand { relay: 1, storage: 1, ..Demand::default() };
    let mut controllers: Vec<RoleController> = (0..13).map(|_| RoleController::new(start, floor, 3)).collect();

    let mut relay_active_union: BTreeSet<u8> = BTreeSet::new();
    let mut demand_trace: Vec<u16> = Vec::new();
    let mut peak_deficit = 0u16;

    for (e, &want) in RELAY_WANT.iter().enumerate() {
        let sp = setpoint(want);
        // Each node steps its own controller on the identical agreed inputs.
        let reports: Vec<AssignReport> =
            controllers.iter_mut().map(|c| c.step(&members, Epoch::new(e as u64), &BEACON, sp)).collect();

        // (1) LOCKSTEP: every node computed the byte-identical assignment — role consensus, no coordination.
        for r in &reports[1..] {
            assert_eq!(r.roles, reports[0].roles, "epoch {e}: all nodes must agree on the assignment");
        }
        let report = &reports[0];

        // (2) CAPABILITY-HONESTY: no node is ever assigned a role it did not offer, and any node's roles are
        //     independently verifiable via `assigned`.
        for (id, cap) in &members {
            let got = report.roles.get(id).copied().unwrap_or(RoleSet::EMPTY);
            for role in Role::ALL {
                // Assigned ⇒ offered (a node is never given a role it cannot serve).
                assert!(!got.has(role) || cap.offered.has(role), "epoch {e}: {:?} got an un-offered role", id.0[0]);
            }
            assert_eq!(got, assigned(id, &members, Epoch::new(e as u64), &BEACON, controllers[0].demand()));
        }

        // Record dynamics: which nodes are active relays (for rotation), the demand (for convergence), the peak
        // deficit (for escalation).
        for (id, r) in &report.roles {
            if r.has(Role::Relay) {
                relay_active_union.insert(id.0[0]);
            }
        }
        demand_trace.push(controllers[0].demand().relay);
        peak_deficit = peak_deficit.max(report.deficit.relay);
    }

    // (3) HOMEOSTATIC CONVERGENCE: the demand rose while the cell was congested and relaxed when it went slack —
    //     it tracked the load, not a fixed provisioning.
    let peak = *demand_trace.iter().max().unwrap();
    assert!(peak >= relay_supply, "demand climbed to at least the supply ceiling under congestion ({peak} vs {relay_supply})");
    assert!(*demand_trace.last().unwrap() < peak, "demand relaxed once the load fell ({} < {peak})", demand_trace.last().unwrap());

    // (4) ROTATION (moving target + load spreading): across epochs the relay role rotated over most of the
    //     eligible pool — no fixed set monopolizes it.
    assert!(relay_active_union.len() >= 6, "the relay role rotated across the eligible pool, saw {} nodes", relay_active_union.len());
    assert!(relay_active_union.iter().all(|&n| n < 8), "only relay-capable nodes (0..8) were ever active relays");

    // (5) DEFICIT: at peak load the demand exceeded the 8-relay supply, surfacing an escalation signal.
    assert!(peak_deficit > 0, "peak congestion demanded more relays than the cell has — a deficit is escalated");
}

#[test]
fn a_deficit_escalates_to_the_parent_cell() {
    // The holarchic loop (UHM T-148 recovery): when a child cell cannot self-provision a role, the shortfall
    // rises to the parent, whose own controller provisions extra capacity to lend down.
    let members = heterogeneous_cell();
    let start = Demand { relay: 2, ..Demand::default() };
    let floor = Demand { relay: 1, ..Demand::default() };
    let mut child = RoleController::new(start, floor, 7); // κ = 1: jump to setpoint, so the deficit appears fast
    // The parent provisions a spare pool; its setpoint absorbs whatever deficit the child reports.
    let mut parent = RoleController::new(Demand { relay: 0, ..Demand::default() }, Demand::default(), 7);

    let mut parent_saw_escalation = false;
    // Sustained congestion far above the child's 8-relay supply.
    for e in 0..8u64 {
        let child_report = child.step(&members, Epoch::new(e), &BEACON, Demand { relay: 14, ..Demand::default() });
        // The parent's setpoint for this role is the child's unmet demand — it provisions to cover the gap.
        let parent_report =
            parent.step(&members, Epoch::new(e), &BEACON, Demand { relay: child_report.deficit.relay, ..Demand::default() });
        if child_report.deficit.relay > 0 {
            parent_saw_escalation = true;
            // The parent's demand grows toward the child's deficit — the overflow path is engaged.
            assert!(parent.demand().relay > 0, "epoch {e}: the parent provisions against the child's deficit");
        }
        let _ = parent_report;
    }
    assert!(parent_saw_escalation, "sustained congestion beyond the child's supply must escalate a deficit");
    assert!(parent.demand().relay >= 6, "the parent provisioned the child's ~6-relay shortfall, got {}", parent.demand().relay);
}

#[test]
fn the_minimum_gain_still_converges_the_cell() {
    // Even at the UHM viability floor κ_bootstrap = 1/7 (the slowest admissible loop gain), the cell's demand
    // still converges to a stable provisioning under a fixed load — the pull toward the setpoint never vanishes.
    let members = heterogeneous_cell();
    let mut ctrl = RoleController::new(Demand { relay: 1, ..Demand::default() }, Demand { relay: 1, ..Demand::default() }, GAIN_BOOTSTRAP_SEVENTHS);
    // A steady load wanting 6 relays (≤ supply): the slow controller must still reach and hold it.
    for e in 0..80u64 {
        ctrl.step(&members, Epoch::new(e), &BEACON, Demand { relay: 6, ..Demand::default() });
    }
    assert_eq!(ctrl.demand().relay, 6, "at κ_bootstrap the demand still converges to the setpoint");
}
