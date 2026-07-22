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
use fanos_vrf::{VrfProof, VrfPublic, VrfSecret, PROOF_LEN};

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

    /// Reconstruct a set from its [`bits`](Self::bits) encoding (unknown high bits are ignored).
    #[must_use]
    pub fn from_bits(bits: u8) -> Self {
        Self(bits & ((1 << Role::ALL.len()) - 1))
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

/// A node's **signed capability advertisement** for an epoch — the authenticated input the role assignment
/// consumes. It is signed with the node's **coordinate-VRF key**: the same key that earns the node its
/// coordinate (`membership::Member::assign`) also attests what it can do, so one self-certifying identity
/// binds both *where* a node is and *what* it offers, and a peer authenticates the declaration (a node cannot
/// forge another's capabilities). A VRF proof over the capability bytes is an unforgeable signature on them.
///
/// A node may still over-declare its *own* `weight`; that is caught not here but by the performance-reputation
/// loop (`docs/design-self-organization.md` §4/§5): an assignee that cannot serve its role shows up as a
/// coherence deficit and has its effective weight slashed. Signing binds the declaration to the identity;
/// reputation prices honesty.
#[derive(Clone, Debug)]
pub struct CapabilityDescriptor {
    /// The advertising node's identity.
    pub node_id: NodeId,
    /// The epoch this advertisement is valid for (it is re-issued each epoch, like the coordinate).
    pub epoch: Epoch,
    /// The advertised capability (offered roles + capacity weight).
    pub capability: Capability,
    /// The VRF-proof signature over [`signable`](CapabilityDescriptor::signable).
    proof: VrfProof,
}

impl CapabilityDescriptor {
    /// The signed content: `node_id(32) ‖ epoch(8) ‖ offered(1) ‖ weight(2)`.
    #[must_use]
    fn signable(node_id: &NodeId, epoch: Epoch, capability: Capability) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 8 + 1 + 2);
        buf.extend_from_slice(&node_id.0);
        buf.extend_from_slice(&epoch.to_be_bytes());
        buf.push(capability.offered.bits());
        buf.extend_from_slice(&capability.weight.to_be_bytes());
        buf
    }

    /// Sign a capability advertisement with the node's coordinate-VRF secret.
    #[must_use]
    pub fn sign(node_id: NodeId, epoch: Epoch, capability: Capability, vrf_secret: &VrfSecret) -> Self {
        let (proof, _) = vrf_secret.prove(&Self::signable(&node_id, epoch, capability));
        Self { node_id, epoch, capability, proof }
    }

    /// Whether the advertisement is authentic under `vrf_public` (which must be the node's coordinate-VRF key,
    /// the one its identity commits). A forged or tampered advertisement is rejected.
    #[must_use]
    pub fn verify(&self, vrf_public: &VrfPublic) -> bool {
        vrf_public.verify(&Self::signable(&self.node_id, self.epoch, self.capability), &self.proof).is_some()
    }

    /// Canonical wire bytes: `node_id(32) ‖ epoch(8) ‖ offered(1) ‖ weight(2) ‖ proof(PROOF_LEN)` — the form a
    /// node publishes to the overlay store each epoch (its coordinate slot), for peers to read and verify.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 8 + 1 + 2 + PROOF_LEN);
        out.extend_from_slice(&self.node_id.0);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.push(self.capability.offered.bits());
        out.extend_from_slice(&self.capability.weight.to_be_bytes());
        out.extend_from_slice(&self.proof.to_bytes());
        out
    }

    /// Decode from [`to_bytes`](Self::to_bytes), or `None` if the wrong length or a malformed proof. The
    /// recovered descriptor still needs [`verify`](Self::verify) against the node's VRF key before it is trusted.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 + 8 + 1 + 2 + PROOF_LEN {
            return None;
        }
        let node_id = NodeId(bytes.get(..32)?.try_into().ok()?);
        let epoch = Epoch::from_be_bytes(bytes.get(32..40)?.try_into().ok()?);
        let offered = RoleSet::from_bits(*bytes.get(40)?);
        let weight = u16::from_be_bytes(bytes.get(41..43)?.try_into().ok()?);
        let proof = VrfProof::from_bytes(bytes.get(43..)?.try_into().ok()?)?;
        Some(Self { node_id, epoch, capability: Capability::new(offered, weight), proof })
    }
}

/// Gather **verified** capability advertisements for `epoch` into the `members` list [`assign`] consumes. Each
/// descriptor is paired with the advertising node's VRF public key (from its identity), and only those that are
/// for this epoch and pass [`CapabilityDescriptor::verify`] are admitted — so the assignment runs over an
/// authenticated capability set, and a forged or stale advertisement cannot steer it.
#[must_use]
pub fn verified_members<'a>(
    descriptors: impl IntoIterator<Item = (&'a CapabilityDescriptor, &'a VrfPublic)>,
    epoch: Epoch,
) -> Vec<(NodeId, Capability)> {
    descriptors
        .into_iter()
        .filter_map(|(d, pk)| (d.epoch == epoch && d.verify(pk)).then_some((d.node_id, d.capability)))
        .collect()
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

    /// The per-role **eligible supply** — how many members can serve each role (the demand ceiling).
    #[must_use]
    pub fn supply(members: &[(NodeId, Capability)]) -> Demand {
        let count = |role: Role| members.iter().filter(|(_, c)| c.offered.has(role)).count() as u16;
        Demand {
            relay: count(Role::Relay),
            storage: count(Role::Storage),
            service: count(Role::Service),
            exit: count(Role::Exit),
        }
    }

    /// **Homeostatic rebalance** (self-balancing) — a **Lyapunov-descent** proportional controller, grounded in
    /// the UHM viability dynamics (T-101 minimax under the T-104 ISS envelope; the same shape as the DDoS
    /// dissipation homeostat). It steps the current demand toward a `setpoint` — the *desired* active count the
    /// driver derives from telemetry (e.g. `⌈observed_load / per_node_capacity⌉`, the demand that would bring
    /// each role to capacity). `gain_seventh` sets the loop gain `κ = gain_seventh/7`, **clamped to `[1, 7]` so
    /// `κ ∈ [κ_bootstrap = 1/7, 1]`** — the UHM bound under which the pull toward the setpoint never vanishes and
    /// never overshoots.
    ///
    /// The step is `D'ρ = Dρ + κ·(setpointρ − Dρ)` (rounded to at least ±1 of progress when `Dρ ≠ setpointρ`,
    /// and never past it since `κ ≤ 1`), then floored at `floorρ`. Because the step lands strictly between `Dρ`
    /// and the setpoint, the error `V = (Dρ − setpointρ)²` **contracts by `(1 − κ)²` per step** — a strict
    /// Lyapunov descent to the setpoint (mirroring `fanos_diakrisis::stability::excursion_step`); with a moving
    /// setpoint (changing load) it is the ISS envelope `√V' ≤ (1−κ)√V + ‖drift‖`. The demand is *not* capped at
    /// the eligible supply — a setpoint above supply is a real, unmet want, surfaced as the deficit
    /// ([`assign_report`]) the cell escalates to its parent.
    #[must_use]
    pub fn rebalance(self, setpoint: Demand, floor: Demand, gain_seventh: u8) -> Demand {
        let k = i64::from(gain_seventh.clamp(1, 7)); // κ = k/7 ∈ [1/7, 1]
        let step = |d: u16, target: u16, fl: u16| -> u16 {
            let target = i64::from(target);
            let d = i64::from(d);
            // Proportional step κ(setpoint−D); rounds to at least ±1 of progress when D ≠ setpoint (κ ≤ 1 ⇒ no
            // overshoot).
            let mut delta = k * (target - d) / 7;
            if delta == 0 && target != d {
                delta = if target > d { 1 } else { -1 };
            }
            let next = (d + delta).clamp(0, i64::from(u16::MAX)) as u16;
            next.max(fl)
        };
        Demand {
            relay: step(self.relay, setpoint.relay, floor.relay),
            storage: step(self.storage, setpoint.storage, floor.storage),
            service: step(self.service, setpoint.service, floor.service),
            exit: step(self.exit, setpoint.exit, floor.exit),
        }
    }
}

impl Demand {
    /// Add `units` of load to one role (saturating).
    fn add_role(&mut self, role: Role, units: u16) {
        let slot = match role {
            Role::Relay => &mut self.relay,
            Role::Storage => &mut self.storage,
            Role::Service => &mut self.service,
            Role::Exit => &mut self.exit,
        };
        *slot = slot.saturating_add(units);
    }

    /// Per-role saturating sum with `other`.
    #[must_use]
    fn saturating_sum(self, other: Demand) -> Demand {
        Demand {
            relay: self.relay.saturating_add(other.relay),
            storage: self.storage.saturating_add(other.storage),
            service: self.service.saturating_add(other.service),
            exit: self.exit.saturating_add(other.exit),
        }
    }
}

/// The demand **setpoint** implied by an observed `load` against a per-node `capacity`: per role, the number
/// of active nodes that would bring it to capacity, `⌈loadρ / capacityρ⌉` (capacity clamped to `≥ 1`). This is
/// the target the [`RoleController`]'s Lyapunov rebalance tracks.
#[must_use]
pub fn setpoint_from(load: Demand, capacity: Demand) -> Demand {
    let ceil_div = |l: u16, c: u16| -> u16 { l.div_ceil(c.max(1)) };
    Demand {
        relay: ceil_div(load.relay, capacity.relay),
        storage: ceil_div(load.storage, capacity.storage),
        service: ceil_div(load.service, capacity.service),
        exit: ceil_div(load.exit, capacity.exit),
    }
}

/// The **cell-agreed setpoint** from every node's observed load: sum the per-node loads (the same summed value
/// on every node, since each reads the same advertised loads — the design's agreed-input requirement), then
/// [`setpoint_from`] the total against the per-node `capacity`. This is what a driver feeds the controller so
/// the whole cell tracks the *same* target and its assignment stays deterministic.
#[must_use]
pub fn cell_setpoint(node_loads: &[Demand], capacity: Demand) -> Demand {
    let total = node_loads.iter().copied().fold(Demand::default(), Demand::saturating_sum);
    setpoint_from(total, capacity)
}

/// A node's **per-role load meter**: it records how much each role was exercised over a window and reports the
/// observed load (for cell-wide aggregation) and the local setpoint. Sans-I/O — a driver records events on it
/// and reads its load each epoch; the cell agrees on the aggregate via [`cell_setpoint`].
#[derive(Clone, Debug)]
pub struct LoadMeter {
    load: Demand,
    capacity: Demand,
}

impl LoadMeter {
    /// A meter with the given per-node `capacity` per role and zero observed load.
    #[must_use]
    pub fn new(capacity: Demand) -> Self {
        Self { load: Demand::default(), capacity }
    }

    /// Record `units` of load exercised on `role` this window (saturating).
    pub fn record(&mut self, role: Role, units: u16) {
        self.load.add_role(role, units);
    }

    /// The load observed this window (the value a node advertises for cell-wide aggregation).
    #[must_use]
    pub fn observed_load(&self) -> Demand {
        self.load
    }

    /// This node's *local* setpoint from its own observed load (before cell aggregation).
    #[must_use]
    pub fn local_setpoint(&self) -> Demand {
        setpoint_from(self.load, self.capacity)
    }

    /// Clear the observed load for the next window.
    pub fn reset(&mut self) {
        self.load = Demand::default();
    }
}

/// Reputation fixed-point scale: a score of [`REP_SCALE`] is full (declared weight honored in full).
pub const REP_SCALE: u16 = 256;
/// Reputation floor: a persistently-non-performing node keeps `REP_FLOOR/REP_SCALE` of its declared weight —
/// never fully excluded (it may recover, and exclusion would be a censorship lever), only de-prioritized.
pub const REP_FLOOR: u16 = REP_SCALE / 8;

/// A per-node **performance reputation** — the third bound on the "controlled freedom" of the self-organizing
/// loop (`docs/design-self-organization.md` §5): a node declares capability freely, but an assignee that does
/// not actually *serve* its role has its effective capacity weight decayed, so the assignment prefers nodes
/// that perform. This prices the one freedom the signature and PoW cannot — over-declaring one's *own* weight.
///
/// The performance signal is an **agreed** one: it comes from the cell's coherence self-diagnosis
/// (`fanos-diakrisis`) — a non-performing node shows as reduced coupling on its lines — which every node reads
/// identically, so the reputation is the same on every node and the assignment stays deterministic. The model
/// here is sans-I/O: it consumes performed/failed observations and produces a weight multiplier.
#[derive(Clone, Debug, Default)]
pub struct Reputation {
    scores: BTreeMap<NodeId, u16>,
}

impl Reputation {
    /// A fresh reputation (every node starts at full [`REP_SCALE`] until observed).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A node's current score (unseen nodes are trusted at full [`REP_SCALE`]).
    #[must_use]
    pub fn score(&self, node: &NodeId) -> u16 {
        self.scores.get(node).copied().unwrap_or(REP_SCALE)
    }

    /// Record whether `node` served its assigned role this window. A success recovers the score additively
    /// (by `REP_SCALE/8`, capped at full); a failure decays it multiplicatively (halved, floored at
    /// [`REP_FLOOR`]) — fast to punish, slow to trust, the standard reputation asymmetry.
    pub fn observe(&mut self, node: NodeId, performed: bool) {
        let cur = self.score(&node);
        let next = if performed {
            cur.saturating_add(REP_SCALE / 8).min(REP_SCALE)
        } else {
            (cur / 2).max(REP_FLOOR)
        };
        self.scores.insert(node, next);
    }

    /// A node's **reputation-adjusted weight**: `declared × score / REP_SCALE`, clamped to `≥ 1` (a node in
    /// good standing keeps its full declared weight; a failing one is de-weighted toward the floor).
    #[must_use]
    pub fn effective_weight(&self, node: &NodeId, declared: u16) -> u16 {
        ((u32::from(declared) * u32::from(self.score(node)) / u32::from(REP_SCALE)) as u16).max(1)
    }

    /// Apply reputation to a member set for the assignment: each capability keeps its offered roles but its
    /// weight becomes the [`effective_weight`](Self::effective_weight). Feed the result to [`assign`] /
    /// [`RoleController::step`] so reputation shapes who wins scarce roles.
    #[must_use]
    pub fn adjust(&self, members: &[(NodeId, Capability)]) -> Vec<(NodeId, Capability)> {
        members
            .iter()
            .map(|(id, cap)| (*id, Capability::new(cap.offered, self.effective_weight(id, cap.weight))))
            .collect()
    }
}

/// The UHM viability gain floor `κ_bootstrap = 1/7`, expressed in sevenths as `1` — the smallest loop gain the
/// [`RoleController`] uses, under which the pull toward the demand setpoint never vanishes (T-59/T-104).
pub const GAIN_BOOTSTRAP_SEVENTHS: u8 = 1;

/// A **sans-I/O self-organizing role controller** — one per cell. Each epoch it rebalances its demand from the
/// observed per-role load (the homeostatic, Lyapunov-descent [`Demand::rebalance`]) and re-assigns roles over
/// the cell's current members ([`assign_report`]). It touches no clock, socket, or RNG — a driver feeds it the
/// members, the beacon, and the load telemetry each beacon round, exactly like every other FANOS engine, so the
/// identical controller runs under the simulator and a live node.
#[derive(Clone, Debug)]
pub struct RoleController {
    demand: Demand,
    floor: Demand,
    gain_seventh: u8,
}

impl RoleController {
    /// A controller starting at `initial` demand, never dropping a role below `floor`, with loop gain
    /// `κ = gain_seventh/7` (clamped to `[1/7, 1]`).
    #[must_use]
    pub fn new(initial: Demand, floor: Demand, gain_seventh: u8) -> Self {
        Self { demand: initial, floor, gain_seventh: gain_seventh.clamp(1, 7) }
    }

    /// The controller's current demand (its internal state).
    #[must_use]
    pub fn demand(&self) -> Demand {
        self.demand
    }

    /// One epoch of the loop: step the demand toward the telemetry-derived `setpoint` (the Lyapunov-descent
    /// [`Demand::rebalance`]), then assign roles over `members` for `(epoch, beacon)`. Returns the
    /// [`AssignReport`] — each node's roles (`min(demand, eligible)` filled) plus the per-role deficit the cell
    /// escalates to its parent when the demand exceeds the eligible supply. Pure, deterministic, sans-I/O.
    pub fn step(
        &mut self,
        members: &[(NodeId, Capability)],
        epoch: Epoch,
        beacon: &BeaconSeed,
        setpoint: Demand,
    ) -> AssignReport {
        self.demand = self.demand.rebalance(setpoint, self.floor, self.gain_seventh);
        assign_report(members, epoch, beacon, self.demand)
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
    fn rebalance_steps_toward_the_setpoint() {
        let d = Demand { relay: 4, storage: 4, ..Default::default() };
        let floor = Demand { relay: 1, storage: 1, service: 1, exit: 1 };
        // Want more relays, fewer storage: at κ = 1 the demand jumps straight to the setpoint.
        let setpoint = Demand { relay: 9, storage: 2, ..Default::default() };
        let next = d.rebalance(setpoint, floor, 7);
        assert_eq!(next.relay, 9, "κ=1 reaches the raised setpoint");
        assert_eq!(next.storage, 2, "κ=1 reaches the lowered setpoint");
        assert!(next.storage >= floor.storage, "never below the floor");
    }

    #[test]
    fn the_demand_controller_is_a_lyapunov_contraction() {
        // Under a FIXED setpoint, the error V = (D − setpoint)² must strictly decrease every step and converge
        // to the setpoint — the T-104 ISS contraction the UHM viability theory requires (κ = k/7 ∈ [1/7, 1]).
        let floor = Demand::default();
        for k in [GAIN_BOOTSTRAP_SEVENTHS, 3, 7] {
            let target = 50u16;
            for &start in &[2u16, 400] {
                // Approach the same setpoint from below and from above — both must contract monotonically.
                let mut d = Demand { relay: start, ..Default::default() };
                let setpoint = Demand { relay: target, ..Default::default() };
                let mut prev_err = u64::MAX;
                for _ in 0..256 {
                    d = d.rebalance(setpoint, floor, k);
                    let err = u64::from(d.relay.abs_diff(target)).pow(2);
                    assert!(err <= prev_err, "κ={k}/7 from {start}: Lyapunov error must not increase ({prev_err}→{err})");
                    prev_err = err;
                }
                assert_eq!(d.relay, target, "κ={k}/7 from {start}: converges to the setpoint, no overshoot");
            }
        }
    }

    #[test]
    fn the_role_controller_runs_the_live_loop() {
        // The sans-I/O controller: each epoch it steps demand toward the telemetry setpoint and re-assigns
        // roles. It converges its demand, assigns min(demand, supply), and escalates a genuine shortfall.
        let members = cell(10, &[Role::Relay], 4); // 10 relay-capable nodes
        let mut ctrl = RoleController::new(
            Demand { relay: 2, ..Default::default() },
            Demand { relay: 1, ..Default::default() },
            3, // κ = 3/7
        );
        // The driver's setpoint: the load wants 6 relays (≤ supply). Demand converges up to 6, assigns 6.
        let setpoint = Demand { relay: 6, ..Default::default() };
        let mut last = ctrl.demand().relay;
        for e in 0..40u64 {
            let report = ctrl.step(&members, Epoch::new(e), &B, setpoint);
            let active = report.roles.values().filter(|r| r.has(Role::Relay)).count();
            assert_eq!(active as u16, ctrl.demand().relay.min(10), "assigns min(demand, supply)");
            assert!(ctrl.demand().relay >= last, "demand rises monotonically toward the setpoint");
            assert_eq!(report.deficit.relay, 0, "supply covers this setpoint — no deficit");
            last = ctrl.demand().relay;
        }
        assert_eq!(ctrl.demand().relay, 6, "the controller settles at the setpoint");
        // A setpoint BEYOND the eligible supply: demand climbs past supply, assigns all 10, escalates the rest.
        let mut hungry = RoleController::new(Demand { relay: 8, ..Default::default() }, Demand::default(), 7);
        let report = hungry.step(&members, Epoch::new(0), &B, Demand { relay: 15, ..Default::default() });
        assert_eq!(report.roles.values().filter(|r| r.has(Role::Relay)).count(), 10, "assigns all it can");
        assert_eq!(report.deficit.relay, 5, "the 5 relays it wants but cannot fill are escalated to the parent");
    }

    #[test]
    fn a_signed_capability_advertisement_authenticates_the_assignment_input() {
        let sk = VrfSecret::from_seed([0x4A; 32]);
        let pk = sk.public();
        let cap = Capability::new(RoleSet::of(&[Role::Relay, Role::Storage]), 6);
        let desc = CapabilityDescriptor::sign(node(1), E, cap, &sk);
        // Authentic under the node's own key.
        assert!(desc.verify(&pk), "an honestly-signed advertisement verifies");
        // Rejected under a different key (a node cannot forge another's capabilities).
        assert!(!desc.verify(&VrfSecret::from_seed([0x99; 32]).public()), "a wrong key is rejected");
        // Tampering the declared capability breaks the signature.
        let mut tampered = desc.clone();
        tampered.capability = Capability::new(RoleSet::of(&[Role::Relay, Role::Storage, Role::Exit]), 63);
        assert!(!tampered.verify(&pk), "an altered capability is rejected");
        // The wire round-trip preserves an authentic, verifiable descriptor (the overlay-store form).
        let rt = CapabilityDescriptor::from_bytes(&desc.to_bytes()).unwrap();
        assert!(rt.verify(&pk), "a decoded descriptor still verifies");
        assert_eq!((rt.node_id, rt.epoch, rt.capability), (desc.node_id, desc.epoch, desc.capability));
        assert!(CapabilityDescriptor::from_bytes(&desc.to_bytes()[..40]).is_none(), "a truncated descriptor is rejected");
    }

    #[test]
    fn verified_members_admits_only_authentic_current_epoch_advertisements() {
        let sk0 = VrfSecret::from_seed([1; 32]);
        let sk1 = VrfSecret::from_seed([2; 32]);
        let (pk0, pk1) = (sk0.public(), sk1.public());
        let good = CapabilityDescriptor::sign(node(0), E, Capability::new(RoleSet::of(&[Role::Relay]), 4), &sk0);
        let stale = CapabilityDescriptor::sign(node(1), Epoch::new(99), Capability::new(RoleSet::of(&[Role::Exit]), 4), &sk1);
        // `good` is admitted; `stale` (wrong epoch) is dropped; a descriptor checked under the wrong key is dropped.
        let members = verified_members([(&good, &pk0), (&stale, &pk1)], E);
        assert_eq!(members.len(), 1, "only the current-epoch, authentic advertisement is admitted");
        assert_eq!(members[0].0, node(0));
        // The same descriptors, but `good` paired with the WRONG key, admits nothing valid for node 0.
        let none = verified_members([(&good, &pk1)], E);
        assert!(none.is_empty(), "a descriptor checked under the wrong key is not admitted");
    }

    #[test]
    fn the_load_meter_derives_a_setpoint_and_the_cell_agrees_on_the_aggregate() {
        let capacity = Demand { relay: 10, storage: 5, ..Default::default() };
        let mut m = LoadMeter::new(capacity);
        m.record(Role::Relay, 20);
        m.record(Role::Relay, 5); // 25 relay-units observed
        m.record(Role::Storage, 3);
        assert_eq!(m.observed_load(), Demand { relay: 25, storage: 3, ..Default::default() });
        // Local setpoint: ⌈25/10⌉ = 3 relays, ⌈3/5⌉ = 1 storage.
        assert_eq!(m.local_setpoint(), Demand { relay: 3, storage: 1, ..Default::default() });
        // The whole cell agrees on the aggregate: sum every node's observed load, then ⌈total / capacity⌉.
        let loads = [
            Demand { relay: 25, storage: 3, ..Default::default() },
            Demand { relay: 40, ..Default::default() },
            Demand { relay: 15, storage: 7, ..Default::default() },
        ];
        // relay total 80 → ⌈80/10⌉ = 8; storage total 10 → ⌈10/5⌉ = 2.
        assert_eq!(cell_setpoint(&loads, capacity), Demand { relay: 8, storage: 2, ..Default::default() });
        // reset clears the window for the next epoch.
        m.reset();
        assert_eq!(m.observed_load(), Demand::default());
    }

    #[test]
    fn reputation_decays_a_non_performer_and_shapes_the_assignment() {
        let mut rep = Reputation::new();
        let bad = node(0);
        assert_eq!(rep.score(&bad), REP_SCALE, "an unseen node is trusted at full");
        assert_eq!(rep.effective_weight(&bad, 64), 64);
        // Repeated failure decays fast (halving) to the floor, never to zero (it may recover).
        for _ in 0..8 {
            rep.observe(bad, false);
        }
        assert_eq!(rep.score(&bad), REP_FLOOR, "a persistent non-performer decays to the floor");
        assert_eq!(rep.effective_weight(&bad, 64), 64 * REP_FLOOR / REP_SCALE, "its effective weight is de-weighted");
        // Success recovers, slowly (additive).
        let before = rep.score(&bad);
        rep.observe(bad, true);
        assert!(rep.score(&bad) > before, "success recovers");
        // adjust() de-weights the failing node so the assignment favors performers.
        let members = vec![
            (bad, Capability::new(RoleSet::of(&[Role::Relay]), 64)),
            (node(1), Capability::new(RoleSet::of(&[Role::Relay]), 64)),
        ];
        let adjusted = rep.adjust(&members);
        let bad_w = adjusted.iter().find(|(id, _)| *id == bad).unwrap().1.weight;
        let good_w = adjusted.iter().find(|(id, _)| *id == node(1)).unwrap().1.weight;
        assert!(bad_w < good_w, "the non-performer is de-weighted vs a full-trust peer");
        // Over many epochs the full-trust node wins a scarce role far more than the de-weighted failer.
        let mut good_wins = 0u32;
        for e in 0..200u64 {
            let a = assign(&adjusted, Epoch::new(e), &B, Demand { relay: 1, ..Default::default() });
            if a.get(&node(1)).is_some_and(|r| r.has(Role::Relay)) {
                good_wins += 1;
            }
        }
        assert!(good_wins > 130, "the full-trust node wins the scarce role far more often, got {good_wins}/200");
    }
}
