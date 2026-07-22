//! **Self-organizing role assignment** — the network assigns each node its *function*, the way the VRF
//! assigns its *position* (spec §L3; `docs/design-self-organization.md`).
//!
//! A node's coordinate is already computed, not chosen ([`crate::membership::Member::assign`]): it is
//! `MapToPoint(VRF(sk, id ‖ epoch ‖ beacon))`, so *where* a node sits is decided by the network, verifiably and
//! unpredictably. This module extends the same principle to *what a node does*. Today a node hand-declares a
//! [role set] on the command line; that is the one piece of the topology a human still wires. Here the human
//! wires only **capability** — what a node *can* do (relay, store, host, exit) and how much (`weight`, a
//! capacity class) — and the network **assigns** the active roles for the epoch as a deterministic function of
//! (the signed capabilities, the epoch beacon, the cell's demand). This is *controlled freedom*: a node offers
//! what it can; the cell decides what it does; no node can forge a role it lacks, monopolize a role, or aim
//! itself at one — exactly the guarantees the coordinate VRF already gives placement.
//!
//! **The assignment (`assign`).** For each role `ρ` with demand `Dρ`, the eligible nodes are those whose
//! capability offers `ρ`. Each eligible node draws a **priority key** = the minimum of `weight` beacon-bound
//! tickets `H(beacon ‖ epoch ‖ ρ ‖ id ‖ t)`, `t ∈ 0..weight`; the `Dρ` nodes with the **smallest** keys are
//! assigned `ρ`. Properties, all provable:
//! - **Deterministic & verifiable.** The inputs are public (signed capabilities, the beacon, the demand), so
//!   every node computes the *same* assignment for *every* node, with no coordination, and any node can verify
//!   another's claimed roles ([`assigned`]). A role claimed without capability, or outside the top-`Dρ`, is
//!   rejected — the same unforgeability the coordinate proof gives placement.
//! - **Capability-weighted.** A node's key is the minimum of `weight` i.i.d. uniforms, whose distribution
//!   `P(min ≤ x) = 1 − (1 − x)^weight` **stochastically decreases in `weight`** — so higher-capacity nodes are
//!   preferentially selected for scarce roles, while equal-weight nodes are selected uniformly at random (fair
//!   rotation). This is weighted reservoir selection, not an ad-hoc threshold; the exact-proportional
//!   Efraimidis–Spirakis key is a documented refinement (`docs/design-self-organization.md` §3).
//! - **Rotating (moving target + load spreading).** The beacon enters every ticket, so the assignment
//!   reshuffles each epoch: no node holds a role forever (load is spread over time and the role set is a moving
//!   target), and — because the beacon is unbiasable — a node cannot grind its identity to capture a chosen
//!   role, exactly as it cannot grind a chosen coordinate.
//! - **Self-balancing.** `Dρ` is not fixed: [`Demand::rebalance`] is a proportional controller that raises a
//!   role's demand when the cell's telemetry shows it under-served and lowers it when over-served, clamped to
//!   the eligible supply — the same homeostatic shape as the DDoS dissipation controller. When demand exceeds
//!   eligible supply the cell is genuinely under-provisioned and escalates to its parent
//!   ([`crate::hierarchy`]); the deficit is reported by [`assign_report`], never silently dropped.
//!
//! [role set]: crate::roles::RoleSet

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fanos_primitives::{hash_labeled, BeaconSeed, Epoch, NodeId};

/// The functional roles a cell provides. Extensible; the four base roles mirror the node's advertised
/// capability set (relay traffic, store L4 shards, host CALYPSO services, bridge to the clear net).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Role {
    /// Relays application traffic for others (onion hops).
    Relay,
    /// Stores L4 erasure-coded shards for the cell.
    Storage,
    /// Hosts hidden services (CALYPSO).
    Service,
    /// Bridges to the clear net (an exit).
    Exit,
}

impl Role {
    /// Every role, in canonical order — the iteration order of an assignment.
    pub const ALL: [Role; 4] = [Role::Relay, Role::Storage, Role::Service, Role::Exit];

    /// The 1-byte domain tag mixed into the ticket hash (distinct per role).
    #[must_use]
    fn tag(self) -> u8 {
        match self {
            Role::Relay => 0,
            Role::Storage => 1,
            Role::Service => 2,
            Role::Exit => 3,
        }
    }
}

/// A set of roles — a compact bit set over [`Role`].
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct RoleSet(u8);

impl RoleSet {
    /// The empty set.
    pub const EMPTY: RoleSet = RoleSet(0);

    /// A set from an explicit list of roles.
    #[must_use]
    pub fn of(roles: &[Role]) -> Self {
        let mut s = Self::EMPTY;
        for &r in roles {
            s.insert(r);
        }
        s
    }

    /// Add a role.
    pub fn insert(&mut self, r: Role) {
        self.0 |= 1 << r.tag();
    }

    /// Whether the set contains `r`.
    #[must_use]
    pub fn has(self, r: Role) -> bool {
        self.0 & (1 << r.tag()) != 0
    }

    /// Whether any role is present.
    #[must_use]
    pub fn any(self) -> bool {
        self.0 != 0
    }

    /// The number of roles in the set.
    #[must_use]
    pub fn count(self) -> u32 {
        self.0.count_ones()
    }

    /// The one-byte wire encoding (bit `Role::tag()` set iff the role is present).
    #[must_use]
    pub fn bits(self) -> u8 {
        self.0
    }
}

/// The maximum capacity weight — bounds the ticket loop and the influence any single node's self-declared
/// capacity can claim (a node cannot buy unbounded priority by inflating its weight).
pub const MAX_WEIGHT: u16 = 64;

/// A node's **capability declaration**: which roles it can serve and its capacity class per the node's signed
/// descriptor. `weight` is clamped to `1..=MAX_WEIGHT` (an offered role always gets at least one ticket; no
/// node claims more than [`MAX_WEIGHT`] tickets). Only capabilities the node actually possesses should be
/// declared — a node assigned a role it cannot serve fails to perform, which the cell's self-diagnosis detects
/// and answers by slashing its weight (the reputation loop, `docs/design-self-organization.md` §4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capability {
    /// The roles this node offers to serve.
    pub offered: RoleSet,
    /// Capacity class (bandwidth / storage / uptime), clamped to `1..=MAX_WEIGHT`.
    pub weight: u16,
}

impl Capability {
    /// A capability offering `roles` at capacity `weight` (clamped to `1..=MAX_WEIGHT`).
    #[must_use]
    pub fn new(roles: RoleSet, weight: u16) -> Self {
        Self { offered: roles, weight: weight.clamp(1, MAX_WEIGHT) }
    }

    /// The effective ticket count (clamped weight).
    #[must_use]
    fn tickets(self) -> u16 {
        self.weight.clamp(1, MAX_WEIGHT)
    }
}

/// Per-role **demand**: how many active nodes the cell wants serving each role this epoch. Structural roles
/// (consensus validation, the beacon keyper line) are fixed by the geometry and are *not* assigned here — this
/// governs the elastic roles a cell provisions to taste.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Demand {
    /// Wanted active relays.
    pub relay: u16,
    /// Wanted active storage nodes.
    pub storage: u16,
    /// Wanted active service hosts.
    pub service: u16,
    /// Wanted active exits.
    pub exit: u16,
}

impl Demand {
    /// The demand for one role.
    #[must_use]
    pub fn of(self, role: Role) -> u16 {
        match role {
            Role::Relay => self.relay,
            Role::Storage => self.storage,
            Role::Service => self.service,
            Role::Exit => self.exit,
        }
    }

    /// **Homeostatic rebalance** (self-balancing) — a proportional controller. `served[ρ]` is the load ratio
    /// the cell's telemetry observed last epoch, in tenths (`10` = at capacity, `>10` = congested, `<10` =
    /// slack); `eligible[ρ]` is how many nodes *can* serve `ρ` (the supply ceiling). Demand rises toward the
    /// supply ceiling when a role is congested and relaxes toward a floor when it is slack, by the proportional
    /// step `Dρ' = clamp(round(Dρ · served/10), floor, eligible)`. This mirrors the DDoS dissipation law: a
    /// bounded, monotone response to a measured deficit, never an unbounded or oscillating one.
    #[must_use]
    pub fn rebalance(self, served: Demand, eligible: Demand, floor: Demand) -> Demand {
        let step = |d: u16, load: u16, elig: u16, fl: u16| -> u16 {
            let scaled = (u32::from(d) * u32::from(load.max(1)) + 5) / 10; // round(d · load/10)
            (scaled as u16).clamp(fl.min(elig), elig)
        };
        Demand {
            relay: step(self.relay, served.relay, eligible.relay, floor.relay),
            storage: step(self.storage, served.storage, eligible.storage, floor.storage),
            service: step(self.service, served.service, eligible.service, floor.service),
            exit: step(self.exit, served.exit, eligible.exit, floor.exit),
        }
    }
}

/// The node's beacon-bound **priority key** for a role: the minimum over its `tickets` of
/// `H(role ‖ epoch ‖ beacon ‖ id ‖ t)`. Smaller is higher priority. Returning the minimum of `weight` i.i.d.
/// draws is what makes selection probability increase with capacity while staying uniform among equals.
fn priority_key(role: Role, id: &NodeId, cap: Capability, epoch: Epoch, beacon: &BeaconSeed) -> [u8; 32] {
    let mut best = [0xFFu8; 32];
    for t in 0..cap.tickets() {
        let mut buf = Vec::with_capacity(1 + 8 + 32 + 32 + 2);
        buf.push(role.tag());
        buf.extend_from_slice(&epoch.to_be_bytes());
        buf.extend_from_slice(beacon.as_bytes());
        buf.extend_from_slice(&id.0);
        buf.extend_from_slice(&t.to_be_bytes());
        let h = hash_labeled("FANOS-v1/role-ticket", &buf);
        if h < best {
            best = h;
        }
    }
    best
}

/// The set of nodes assigned role `role`, in selection order (best priority first) — the top-`demand` eligible
/// nodes by [`priority_key`], ties broken by `id` for determinism.
fn select(
    role: Role,
    members: &[(NodeId, Capability)],
    epoch: Epoch,
    beacon: &BeaconSeed,
    demand: u16,
) -> Vec<NodeId> {
    let mut ranked: Vec<([u8; 32], NodeId)> = members
        .iter()
        .filter(|(_, cap)| cap.offered.has(role))
        .map(|(id, cap)| (priority_key(role, id, *cap, epoch, beacon), *id))
        .collect();
    // Smallest key first; the id is a total-order tie-break so the result is fully deterministic.
    ranked.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1 .0.cmp(&b.1 .0)));
    ranked.into_iter().take(usize::from(demand)).map(|(_, id)| id).collect()
}

/// **Assign active roles** to a cell's members for `(epoch, beacon)` under `demand`. Returns each node's
/// assigned [`RoleSet`] (a node may hold several roles at once). Deterministic and verifiable: any party with
/// the same public inputs reproduces this map exactly, and [`assigned`] recomputes one node's roles for
/// verification. Nodes that were assigned nothing are omitted from the map.
#[must_use]
pub fn assign(
    members: &[(NodeId, Capability)],
    epoch: Epoch,
    beacon: &BeaconSeed,
    demand: Demand,
) -> BTreeMap<NodeId, RoleSet> {
    let mut out: BTreeMap<NodeId, RoleSet> = BTreeMap::new();
    for role in Role::ALL {
        for id in select(role, members, epoch, beacon, demand.of(role)) {
            out.entry(id).or_default().insert(role);
        }
    }
    out
}

/// The roles **one** node is assigned for `(epoch, beacon, demand)` — the verification path. A verifier checks
/// a peer's claimed role set by recomputing exactly this from the public capabilities and the beacon; a claim
/// that exceeds it (a role the node has no capability for, or is not in the top-`Dρ` of) is rejected.
#[must_use]
pub fn assigned(
    id: &NodeId,
    members: &[(NodeId, Capability)],
    epoch: Epoch,
    beacon: &BeaconSeed,
    demand: Demand,
) -> RoleSet {
    let mut roles = RoleSet::EMPTY;
    for role in Role::ALL {
        if select(role, members, epoch, beacon, demand.of(role)).contains(id) {
            roles.insert(role);
        }
    }
    roles
}

/// A cell's assignment together with its **provisioning deficit** — for every role, how many active nodes the
/// demand fell short of (because too few members offered it). A positive deficit is the signal the cell
/// escalates to its parent ([`crate::hierarchy`]); it is reported, never silently swallowed.
#[derive(Clone, Debug)]
pub struct AssignReport {
    /// Each node's assigned roles.
    pub roles: BTreeMap<NodeId, RoleSet>,
    /// Unmet demand per role (`max(0, demand − eligible_supply)`).
    pub deficit: Demand,
}

/// [`assign`], plus the per-role deficit where demand exceeded the eligible supply (the escalation signal).
#[must_use]
pub fn assign_report(
    members: &[(NodeId, Capability)],
    epoch: Epoch,
    beacon: &BeaconSeed,
    demand: Demand,
) -> AssignReport {
    let supply = |role: Role| members.iter().filter(|(_, c)| c.offered.has(role)).count() as u16;
    let short = |role: Role| demand.of(role).saturating_sub(supply(role));
    AssignReport {
        roles: assign(members, epoch, beacon, demand),
        deficit: Demand {
            relay: short(Role::Relay),
            storage: short(Role::Storage),
            service: short(Role::Service),
            exit: short(Role::Exit),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn node(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn cell(n: u8, roles: &[Role], weight: u16) -> Vec<(NodeId, Capability)> {
        (0..n).map(|i| (node(i), Capability::new(RoleSet::of(roles), weight))).collect()
    }

    const B: BeaconSeed = BeaconSeed::GENESIS;
    const E: Epoch = Epoch::new(3);

    #[test]
    fn assignment_is_deterministic_and_verifiable() {
        let members = cell(7, &[Role::Relay, Role::Storage], 4);
        let d = Demand { relay: 3, storage: 4, service: 0, exit: 0 };
        let a = assign(&members, E, &B, d);
        // Recomputable byte-for-byte.
        assert_eq!(a, assign(&members, E, &B, d));
        // Each node's map entry equals its independently-verified role set (the verification path).
        for (id, _) in &members {
            let claimed = a.get(id).copied().unwrap_or(RoleSet::EMPTY);
            assert_eq!(claimed, assigned(id, &members, E, &B, d), "node {:?} verifies", id.0[0]);
        }
    }

    #[test]
    fn demand_is_filled_exactly_when_supply_suffices() {
        let members = cell(7, &[Role::Relay], 4);
        let d = Demand { relay: 3, ..Default::default() };
        let a = assign(&members, E, &B, d);
        let relays = a.values().filter(|r| r.has(Role::Relay)).count();
        assert_eq!(relays, 3, "exactly the demanded number of relays are active");
        // No node is assigned a role it did not offer.
        for r in a.values() {
            assert!(!r.has(Role::Storage) && !r.has(Role::Exit) && !r.has(Role::Service));
        }
    }

    #[test]
    fn only_capable_nodes_are_eligible() {
        // Three exit-capable nodes among seven; demand 5 exits can only fill 3 — the rest is a reported deficit.
        let mut members = cell(7, &[Role::Relay], 4);
        for m in members.iter_mut().take(3) {
            m.1 = Capability::new(RoleSet::of(&[Role::Relay, Role::Exit]), 4);
        }
        let d = Demand { relay: 2, exit: 5, ..Default::default() };
        let report = assign_report(&members, E, &B, d);
        let exits = report.roles.values().filter(|r| r.has(Role::Exit)).count();
        assert_eq!(exits, 3, "only the 3 exit-capable nodes can be assigned exit");
        assert_eq!(report.deficit.exit, 2, "the 2 unfillable exits are a reported deficit (escalation signal)");
    }

    #[test]
    fn higher_capacity_nodes_are_preferentially_selected() {
        // One heavyweight node vs many lightweight; over many epochs the heavyweight is selected far more often
        // for a scarce (demand-1) role — capability-weighting, not a coin flip.
        let mut members = cell(12, &[Role::Relay], 1);
        members[0].1 = Capability::new(RoleSet::of(&[Role::Relay]), MAX_WEIGHT);
        let d = Demand { relay: 1, ..Default::default() };
        let mut heavy = 0u32;
        let trials = 400u64;
        for e in 0..trials {
            let a = assign(&members, Epoch::new(e), &B, d);
            if a.get(&node(0)).is_some_and(|r| r.has(Role::Relay)) {
                heavy += 1;
            }
        }
        // Uniform among 12 would be ~33 wins; the heavyweight should dominate a scarce slot.
        assert!(heavy > 150, "the high-capacity node should win the scarce role far above uniform, got {heavy}/400");
    }

    #[test]
    fn equal_weight_nodes_rotate_fairly_across_epochs() {
        // With equal weights the scarce role rotates over epochs — no node monopolizes it (moving target +
        // load spreading), and the assignment is unpredictable before the beacon (anti-grinding).
        let members = cell(7, &[Role::Relay], 4);
        let d = Demand { relay: 1, ..Default::default() };
        let mut winners = alloc::collections::BTreeSet::new();
        for e in 0..40u64 {
            let a = assign(&members, Epoch::new(e), &B, d);
            for (id, r) in &a {
                if r.has(Role::Relay) {
                    winners.insert(id.0[0]);
                }
            }
        }
        assert!(winners.len() >= 5, "the role should rotate across most of the cell, saw {} winners", winners.len());
    }

    #[test]
    fn a_node_can_hold_several_roles_at_once() {
        // A capable, high-weight node naturally accumulates multiple roles when demand is high relative to supply.
        let members = cell(4, &[Role::Relay, Role::Storage, Role::Service, Role::Exit], 8);
        let d = Demand { relay: 4, storage: 4, service: 4, exit: 4 };
        let a = assign(&members, E, &B, d);
        assert!(a.values().any(|r| r.count() >= 2), "at least one node holds multiple roles simultaneously");
        // With demand == supply on every role, every node serves every role it offered.
        for r in a.values() {
            assert_eq!(r.count(), 4);
        }
    }

    #[test]
    fn rebalance_raises_congested_and_relaxes_slack_demand() {
        let d = Demand { relay: 4, storage: 4, ..Default::default() };
        let eligible = Demand { relay: 10, storage: 10, service: 10, exit: 10 };
        let floor = Demand { relay: 1, storage: 1, service: 1, exit: 1 };
        // Relay congested (load 20 = 2× capacity) → demand rises; storage slack (load 5) → demand falls.
        let served = Demand { relay: 20, storage: 5, ..Default::default() };
        let next = d.rebalance(served, eligible, floor);
        assert!(next.relay > d.relay, "a congested role's demand rises ({} → {})", d.relay, next.relay);
        assert!(next.storage < d.storage, "a slack role's demand relaxes ({} → {})", d.storage, next.storage);
        // Never exceeds the eligible supply, never below the floor.
        assert!(next.relay <= eligible.relay && next.storage >= floor.storage);
    }
}
