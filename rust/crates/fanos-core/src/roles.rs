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

/// The functional roles a cell provides. Extensible; the base roles mirror the node's advertised capability set
/// (relay traffic, store L4 shards, host CALYPSO services, bridge to the clear net, and host the anonymous
/// rendezvous line an unlinkable receiver comes home on).
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
    /// Serves as a member of an anonymous **rendezvous line** — the NOSTOS receiver-anonymity substrate
    /// (`docs/design-anonymity-substrate.md` §3/§3b). A hosting node is one point of the `q+1` on a line, so the
    /// hidden service's anonymity set *is* the line's membership; the cell therefore needs enough of the line
    /// occupied for a receiver to be reachable at all, and enough for the threshold peel (`t`-of-`q+1`) to have
    /// a below-threshold guarantee worth having.
    ///
    /// This is why hosting must be an assignable role rather than a hand-started daemon: coverage of the line is
    /// a *cell* property, so the same deterministic controller that provisions relays and exits has to provision
    /// it, or the anonymity set is whatever operators happened to configure.
    Rendezvous,
    /// Serves as a member of a community's **POROS ingress line** — the censorship-resistant bootstrap
    /// entry (`docs/design-anonymity-substrate.md` §6). A member holds one threshold share of the
    /// community's ingress descriptor and, with `t` of its line, serves a new node a bucket of entry peers.
    ///
    /// Assignable for the same reason [`Rendezvous`](Self::Rendezvous) is: the seize-`< t`-reveals-nothing
    /// guarantee is a property of *how much of the line is occupied*, not of any one host, so a cell whose
    /// ingress line runs below threshold cannot admit anyone — and a cell that lets operators self-select
    /// gets whatever coverage they happened to configure. The same controller that provisions relays and
    /// rendezvous points has to provision this.
    Ingress,
}

impl Role {
    /// Every role, in canonical order — the iteration order of an assignment.
    pub const ALL: [Role; 6] =
        [Role::Relay, Role::Storage, Role::Service, Role::Exit, Role::Rendezvous, Role::Ingress];

    /// The number of roles — the width of a per-role array ([`Demand`]).
    pub const COUNT: usize = Role::ALL.len();

    /// Whether this role's **measured load is produced only by nodes assigned to it** — the property that
    /// decides whether zero demand is a stable state or an absorbing one.
    ///
    /// The setpoint loop is closed: assignment → work performed → load measured → assignment. For a role where
    /// that last arrow depends on the first, retiring the role destroys the very signal that would justify
    /// reinstating it, and zero becomes a trap the cell cannot climb out of. So the classification is not
    /// taxonomy — it is read off the loop topology, one role at a time, by asking *what produces this sensor's
    /// signal*:
    ///
    /// - [`Relay`](Self::Relay) — **no**. Its sensor counts frames this node *originated*. A node originates
    ///   traffic whether or not the cell assigned it the relay role, so the signal outlives the assignment.
    /// - [`Storage`](Self::Storage) — **no**. The DHT store is structural: a value lands on its responsible
    ///   content point by geometry, with nobody assigned, so held keys stay observable.
    /// - [`Service`](Self::Service), [`Exit`](Self::Exit), [`Rendezvous`](Self::Rendezvous) — **yes**. A node
    ///   only serves, exits, or gathers when the assignment says so. Nobody assigned means no registrations, no
    ///   flows and no gathers, so the load reads zero forever and the role never returns.
    ///
    /// A self-gated role therefore needs a viability floor on its setpoint — see
    /// [`Demand::with_viability_floor`]. A new role must answer this question, which is why it lives on the enum
    /// rather than in the driver that happens to need it today.
    #[must_use]
    pub const fn load_is_self_gated(self) -> bool {
        match self {
            Role::Relay | Role::Storage => false,
            Role::Service | Role::Exit | Role::Rendezvous | Role::Ingress => true,
        }
    }

    /// This role's index into a per-role array, in [`Role::ALL`] order.
    #[must_use]
    pub const fn index(self) -> usize {
        self.tag() as usize
    }

    /// The 1-byte domain tag mixed into the ticket hash (distinct per role).
    #[must_use]
    const fn tag(self) -> u8 {
        match self {
            Role::Relay => 0,
            Role::Storage => 1,
            Role::Service => 2,
            Role::Exit => 3,
            Role::Rendezvous => 4,
            Role::Ingress => 5,
        }
    }
}

// [`Demand`] indexes a `[u16; Role::COUNT]` by [`Role::index`], so every role's index must be a distinct, in-bounds
// slot and must agree with the `Role::ALL` order that per-role iteration uses. Checked at compile time, which is what
// makes the indexing in `Demand` provably panic-free rather than merely believed to be.
#[allow(clippy::indexing_slicing)] // const-evaluated: `i < Role::COUNT == Role::ALL.len()`
const _: () = {
    let mut i = 0;
    while i < Role::COUNT {
        assert!(Role::ALL[i].index() == i, "Role::ALL order must match Role::index()");
        i += 1;
    }
};

/// A set of roles — a compact bit set over [`Role`].
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct RoleSet(u8);

impl RoleSet {
    /// The bit each role occupies — exposed so a peer-facing encoding (the JOIN role bitfield in `fanos-node`) can
    /// *prove* it agrees with this bitset rather than restating the layout and hoping.
    pub const BIT_RELAY: u8 = 1 << 0;
    /// The storage-role bit; see [`BIT_RELAY`](Self::BIT_RELAY).
    pub const BIT_STORAGE: u8 = 1 << 1;
    /// The service-role bit; see [`BIT_RELAY`](Self::BIT_RELAY).
    pub const BIT_SERVICE: u8 = 1 << 2;
    /// The exit-role bit; see [`BIT_RELAY`](Self::BIT_RELAY).
    pub const BIT_EXIT: u8 = 1 << 3;
    /// The rendezvous-role bit; see [`BIT_RELAY`](Self::BIT_RELAY).
    pub const BIT_RENDEZVOUS: u8 = 1 << 4;
    /// The ingress-role bit; see [`BIT_RELAY`](Self::BIT_RELAY).
    pub const BIT_INGRESS: u8 = 1 << 5;

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
/// declared — a node assigned a role it cannot serve fails to perform, which the cell's self-diagnosis detects.
///
/// **The answer to that detection is not yet wired, and this said it was.** [`Reputation`] is built and
/// unit-proven, and [`Reputation::observe_reachable`] has no production caller: `assign_epoch` steps the
/// controller and never observes, so every score sits at [`REP_SCALE`] and [`Reputation::adjust`] is the
/// identity. `docs/design-self-organization.md` §5 already lists this as outstanding ("the performance-slash
/// reputation feedback ... is specified, not yet closed in code"); the sentence here claimed otherwise, which
/// is the more dangerous direction for a record to disagree in.
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
/// It is indexed **by role** rather than holding a field per role. That is not cosmetic: every operation here is
/// per-role and identical across roles (supply, rebalance, sum, setpoint, deficit), so named fields forced six
/// parallel enumerations that all had to be edited in lockstep to add a role — the kind of structure that makes an
/// extension point *look* extensible while charging for every use of it. Indexed by [`Role::ALL`], adding a role is
/// the enum variant and nothing else.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Demand {
    /// Wanted active nodes per role, indexed by [`Role::index`].
    counts: [u16; Role::COUNT],
}

// Every index below is `Role::index()`, proven `< Role::COUNT` and `ALL`-consistent by the const assertion above.
#[allow(clippy::indexing_slicing)]
impl Demand {
    /// A demand from an explicit per-role array, in [`Role::ALL`] order.
    #[must_use]
    pub const fn from_counts(counts: [u16; Role::COUNT]) -> Self {
        Self { counts }
    }

    /// The demand built by evaluating `f` for each role — the shape every per-role construction below takes.
    #[must_use]
    pub fn per_role(mut f: impl FnMut(Role) -> u16) -> Self {
        let mut counts = [0u16; Role::COUNT];
        for role in Role::ALL {
            counts[role.index()] = f(role);
        }
        Self { counts }
    }

    /// The demand for one role.
    #[must_use]
    pub fn of(self, role: Role) -> u16 {
        self.counts[role.index()]
    }

    /// Set the demand for one role.
    pub fn set(&mut self, role: Role, units: u16) {
        self.counts[role.index()] = units;
    }

    /// The per-role **eligible supply** — how many members can serve each role (the demand ceiling).
    #[must_use]
    pub fn supply(members: &[(NodeId, Capability)]) -> Demand {
        // A count of cell members, so it is bounded by the plane: `q² + q + 1` = 993 at the widest supported
        // order, two orders below the field (#110).
        Demand::per_role(|role| members.iter().filter(|(_, c)| c.offered.has(role)).count() as u16)
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
        Demand::per_role(|role| step(self.of(role), setpoint.of(role), floor.of(role)))
    }

    /// This setpoint raised to the **viability floor**: at least one node for every self-gated role somebody can
    /// serve.
    ///
    /// The floor is `1`, and it is derived rather than chosen. A role whose observed load is produced only by
    /// nodes assigned to it ([`Role::load_is_self_gated`]) loses observability the instant the cell retires it —
    /// no assignment means no work means no load means no assignment, an absorbing state. One retained server is
    /// the minimum that keeps the role's load observable, i.e. the persistent excitation the closed loop needs to
    /// notice demand returning. Not a tunable: below it the loop is blind, above it the measurement already
    /// speaks for itself.
    ///
    /// `supply` is the per-role **eligible supply** ([`Demand::supply`]) and conditions the floor, because
    /// flooring a role *nobody offers* would manufacture a want no member can meet — and a setpoint above supply
    /// is deliberately not capped but surfaced as a deficit the cell escalates to its parent, so a phantom floor
    /// would escalate forever.
    ///
    /// Applied where the **cell total** is known, never per node: if every member floored its own contribution
    /// the cell would provision one server per member instead of one per cell.
    #[must_use]
    pub fn with_viability_floor(self, supply: Demand) -> Demand {
        Demand::per_role(|role| {
            let needs_floor = role.load_is_self_gated() && supply.of(role) > 0;
            self.of(role).max(u16::from(needs_floor))
        })
    }
}

/// The `Command::Control` tag carrying a **load reading** to the sub-engine that assembles the load report.
///
/// A composite reaches that engine's `observe_load` seam directly when it holds it as a concrete type. When the
/// inner engine is behind a `dyn Engine` the type system cannot reach it, and this is the route: the same seam,
/// addressed by message. `Control` is the right carrier and not merely a convenient one — it is local by
/// construction, entering only through the node handle, so a peer cannot inject a load reading and talk a cell
/// into provisioning for work nobody asked for.
///
/// (The tag space is documented as per-sub-engine but is matched flatly by the composites that route it, so a
/// value must be distinct across all of them, not just within one.)
pub const CONTROL_LOAD_READING: u16 = 2;

/// Encode a load reading for [`CONTROL_LOAD_READING`]: the role index, then the load, big-endian.
#[must_use]
pub fn encode_load_reading(role: Role, load: u16) -> [u8; 3] {
    let [hi, lo] = load.to_be_bytes();
    // `Role::index()` is `< Role::COUNT`, which the const assertion above pins well inside a byte.
    [role.index() as u8, hi, lo]
}

/// Decode a [`CONTROL_LOAD_READING`] body, or `None` if it is not one — a malformed body is dropped, never
/// guessed at, since a wrong role index would credit the reading to the wrong role.
#[must_use]
pub fn decode_load_reading(body: &[u8]) -> Option<(Role, u16)> {
    let [index, hi, lo] = *body.first_chunk::<3>()?;
    let role = *Role::ALL.get(usize::from(index))?;
    Some((role, u16::from_be_bytes([hi, lo])))
}

/// Per-role **measured load**, where a role with no sensor is `None` — the raw observation a driver turns into
/// a [`Demand`] setpoint.
///
/// This exists because the two are not the same kind of number and a single `[u16; Role::COUNT]` cannot say so.
/// A [`Demand`] is a *decision* — every role has one, and zero means "want none". A reading is an *observation*,
/// and a role this node cannot see has no observation at all, which is different from observing nothing. Folding
/// the two into one array forced the driver to infer absence from the value, so it read every zero as "no
/// sensor" and substituted a fallback: a role that genuinely fell idle had its true reading thrown away at
/// exactly the moment the controller should have shrunk it.
///
/// So the sensor is total over roles and partial over readings, and the substitution happens once, where the
/// fallback policy lives, instead of everywhere a zero appears.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RoleReading {
    /// Measured load per role, indexed by [`Role::index`]; `None` where this node has no sensor.
    readings: [Option<u16>; Role::COUNT],
}

// Every index below is `Role::index()`, proven `< Role::COUNT` and `ALL`-consistent by the const assertion above.
#[allow(clippy::indexing_slicing)]
impl RoleReading {
    /// A reading with no sensor for any role — every role absent.
    #[must_use]
    pub const fn blind() -> Self {
        Self { readings: [None; Role::COUNT] }
    }

    /// A reading built by evaluating `f` for each role.
    #[must_use]
    pub fn per_role(mut f: impl FnMut(Role) -> Option<u16>) -> Self {
        let mut readings = [None; Role::COUNT];
        for role in Role::ALL {
            readings[role.index()] = f(role);
        }
        Self { readings }
    }

    /// This reading with `role` measured at `load`. Chainable, so a caller composes exactly the sensors it has.
    #[must_use]
    pub fn measuring(mut self, role: Role, load: u16) -> Self {
        self.readings[role.index()] = Some(load);
        self
    }

    /// This reading with `role` measured at `load`, saturating a `usize` count into the wire width.
    ///
    /// The saturation is deliberate and not a lossy shortcut: the reading feeds `⌈load / capacity⌉`, so any count
    /// at or above `u16::MAX` already demands more nodes than a cell can hold, and the setpoint is clamped by
    /// eligible supply downstream regardless. Wrapping, by contrast, would report a colossal load as a tiny one.
    #[must_use]
    pub fn counting(self, role: Role, count: usize) -> Self {
        self.measuring(role, u16::try_from(count).unwrap_or(u16::MAX))
    }

    /// The measured load for one role, or `None` if this node has no sensor for it.
    #[must_use]
    pub fn of(self, role: Role) -> Option<u16> {
        self.readings[role.index()]
    }

    /// The raw per-role array, in [`Role::ALL`] order — the form the sans-I/O contract carries.
    #[must_use]
    pub const fn into_array(self) -> [Option<u16>; Role::COUNT] {
        self.readings
    }

    /// A reading from the contract's per-role array, in [`Role::ALL`] order.
    #[must_use]
    pub const fn from_array(readings: [Option<u16>; Role::COUNT]) -> Self {
        Self { readings }
    }

    /// This node's **published load contribution**, in work units — what [`cell_setpoint`] sums and then divides
    /// by capacity, once.
    ///
    /// **In work units, not nodes, and that is the fix.** The driver used to divide here as well
    /// (`⌈load / capacity⌉`) and publish the quotient, which `cell_setpoint` then divided by capacity again.
    /// Capacity came out twice. It was invisible only because the shipped per-node capacity is `1`, where both
    /// divisions are the identity — so the error was waiting for the first role to be given a real capacity
    /// class, which is exactly what the capacity-weight constant anticipates.
    ///
    /// The fallback for a role with **no sensor** is stated in the same units, and stating it that way makes it
    /// exact rather than approximately right: an offered-but-unsensed role publishes `capacity`, i.e. the node
    /// presumes itself *at capacity*. The cell total is then `N_offering × capacity` and the setpoint comes back
    /// as precisely `N_offering` — "everyone who offers it, serves it" — at **any** capacity. Publishing a bare
    /// `1` reproduced that only at capacity 1 and silently under-provisioned above it.
    #[must_use]
    pub fn to_load(self, capacity: Demand, offered: RoleSet) -> Demand {
        Demand::per_role(|role| {
            self.of(role).unwrap_or(if offered.has(role) { capacity.of(role) } else { 0 })
        })
    }
}

impl Demand {
    /// Add `units` of load to one role (saturating).
    #[allow(clippy::indexing_slicing)] // `Role::index()`, bounded by the const assertion above
    fn add_role(&mut self, role: Role, units: u16) {
        let slot = &mut self.counts[role.index()];
        *slot = slot.saturating_add(units);
    }

    /// Per-role saturating sum with `other`.
    #[must_use]
    fn saturating_sum(self, other: Demand) -> Demand {
        Demand::per_role(|role| self.of(role).saturating_add(other.of(role)))
    }
}

/// The demand **setpoint** implied by an observed `load` against a per-node `capacity`: per role, the number
/// of active nodes that would bring it to capacity, `⌈loadρ / capacityρ⌉` (capacity clamped to `≥ 1`). This is
/// the target the [`RoleController`]'s Lyapunov rebalance tracks.
#[must_use]
pub fn setpoint_from(load: Demand, capacity: Demand) -> Demand {
    Demand::per_role(|role| load.of(role).div_ceil(capacity.of(role).max(1)))
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
/// How much one good window recovers: the single free parameter of the reputation law.
///
/// It sets the recovery time — `REP_SCALE/REP_RECOVER - 1` good windows from the floor back to full, seven at
/// the shipped value — and, through [`REP_FLOOR`], everything else.
pub const REP_RECOVER: u16 = REP_SCALE / 8;

/// Reputation floor: a persistently-non-performing node keeps `REP_FLOOR/REP_SCALE` of its declared weight —
/// never fully excluded (it may recover, and exclusion would be a censorship lever), only de-prioritized.
///
/// **Derived, not chosen: it is the alternating shirker's fixed point.** With additive recovery `r` and
/// multiplicative halving on failure, a node that serves every other window settles at
/// `x = (x + r)/2`, i.e. `x = r` — exactly, for every `r`, and it is checked as such
/// (`the_floor_is_the_alternating_shirkers_fixed_point`). So setting `REP_FLOOR = REP_RECOVER` states the
/// property the floor is for: **a node that shirks half the time is worth the floor and no more**, and one
/// that shirks less is worth strictly more. A floor *below* the fixed point would be unreachable and so
/// decorative; a floor *above* it would pay an alternator more than its behaviour earns.
///
/// It used to be an independent `REP_SCALE / 8` beside a recovery step of `REP_SCALE / 8` — the same number
/// twice, with no statement that they must be the same number. They must.
pub const REP_FLOOR: u16 = REP_RECOVER;

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
            cur.saturating_add(REP_RECOVER).min(REP_SCALE)
        } else {
            (cur / 2).max(REP_FLOOR)
        };
        self.scores.insert(node, next);
    }

    /// Record a node's role performance this window, **excusing a corroborated-down node** (audit R-H2). A
    /// node the cell corroborates as unreachable (`reachable = false`) is neither rewarded nor slashed: it is
    /// not punished for an outage outside its control, so a node knocked offline by a mass failure does not
    /// decay toward the floor and forfeit its role on return. A reachable node is scored exactly as
    /// [`observe`](Self::observe).
    ///
    /// This is the churn-safety the mass-recovery scenario needs: reputation must track *shirking* (reachable
    /// but not serving), never *outage* (down through no fault of its own). The reachability corroboration
    /// (spec §6.4 witnessed liveness) is the cell-agreed signal separating the two, so every node excuses the
    /// identical set and the assignment stays deterministic.
    pub fn observe_reachable(&mut self, node: NodeId, performed: bool, reachable: bool) {
        if reachable {
            self.observe(node, performed);
        }
        // A corroborated-down node is excused: its score is held — neither decayed (it is not shirking) nor
        // recovered (it is not serving) — so an outage is invisible to reputation, exactly as it must be.
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
    ///
    /// **Also the moment the table is trimmed to the roster** ([`retain_members`](Self::retain_members)),
    /// because it is the one call that is handed the membership.
    #[must_use]
    pub fn adjust(&mut self, members: &[(NodeId, Capability)]) -> Vec<(NodeId, Capability)> {
        self.retain_members(members);
        members
            .iter()
            .map(|(id, cap)| (*id, Capability::new(cap.offered, self.effective_weight(id, cap.weight))))
            .collect()
    }

    /// Drop the scores of nodes that are no longer members.
    ///
    /// `scores` had `get` and `insert` and nothing else — a node observed once kept its score for the life of
    /// the process, so the table grew with every identity the cell ever saw rather than with the cell. Ask of
    /// any accumulating map what removes from it; here the answer was nothing.
    ///
    /// Dropping is also the *correct* semantics, not merely the bounded one. A returning node is scored from
    /// [`REP_SCALE`] like any unseen one, and that is the same rule the reachability excuse already encodes:
    /// reputation prices **shirking while reachable**, and a node that was absent was not shirking. Carrying a
    /// stale score across a departure would punish an outage the corroboration exists to forgive.
    ///
    /// Determinism is preserved because every node runs this over the same agreed membership, in the same
    /// call, before the same assignment.
    fn retain_members(&mut self, members: &[(NodeId, Capability)]) {
        self.scores.retain(|id, _| members.iter().any(|(m, _)| m == id));
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
        deficit: Demand::per_role(short),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {

    /// The floor is not a second constant: it is where an alternating shirker lands.
    ///
    /// With additive recovery `r` and a halving on failure, `x -> (x + r)/2` has the fixed point `x = r`. So a
    /// node that serves every other window is worth exactly the floor — no more, which would overpay it, and
    /// no less, which would make the floor unreachable and therefore decorative. Checked by running the law
    /// rather than by re-deriving it, because the code uses integer division and the algebra does not.
    #[test]
    fn the_floor_is_the_alternating_shirkers_fixed_point() {
        let node = NodeId([9u8; 32]);
        let mut rep = Reputation::new();
        for _ in 0..64 {
            rep.observe(node, true);
            rep.observe(node, false);
        }
        assert_eq!(
            rep.score(&node),
            REP_FLOOR,
            "a node serving every other window settles exactly at the floor"
        );
        assert_eq!(REP_FLOOR, REP_RECOVER, "and the floor IS the recovery step, which is why it settles there");

        // Serving MORE than half is worth strictly more than the floor — otherwise the floor would be a
        // ceiling on everyone who ever failed, and the law would not price behaviour at all.
        let better = NodeId([8u8; 32]);
        let mut rep = Reputation::new();
        for _ in 0..64 {
            rep.observe(better, true);
            rep.observe(better, true);
            rep.observe(better, false);
        }
        assert!(
            rep.score(&better) > REP_FLOOR,
            "two-in-three is worth more than the floor ({} vs {REP_FLOOR})",
            rep.score(&better)
        );
    }

    /// A departed node's score does not outlive its membership.
    #[test]
    fn a_score_is_dropped_when_the_node_leaves_the_roster() {
        let (stayed, left) = (NodeId([1u8; 32]), NodeId([2u8; 32]));
        let mut rep = Reputation::new();
        rep.observe(stayed, false);
        rep.observe(left, false);
        assert!(rep.score(&left) < REP_SCALE, "the leaver was scored down while a member");

        let roster = [(stayed, Capability::new(RoleSet::EMPTY, 10))];
        let _ = rep.adjust(&roster);
        assert!(rep.score(&stayed) < REP_SCALE, "a member keeps its score across the assignment");
        assert_eq!(
            rep.score(&left),
            REP_SCALE,
            "a node off the roster is forgotten, so a returning one is scored fresh like any unseen node — \
             reputation prices shirking while reachable, and an absent node was not shirking"
        );
    }
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
    fn a_gain_below_one_makes_the_assignment_depend_on_when_a_node_joined() {
        // **κ = 1 is load-bearing for cell agreement, not merely a tracking choice**, and the constant's own
        // doc does not know it: it says a telemetry-driven sensor "should lower it so the Lyapunov descent
        // smooths real load jitter". Lowering it buys smoothing by making the demand a function of the node's
        // whole history — and `demand` is per-node state, while the assignment is derived from it. Two members
        // that have stepped a different number of epochs then assign different roles from the *same* agreed
        // setpoint, which is precisely the determinism the design rests on.
        //
        // At κ = 1 the step is `D' = D + (s − D) = s`: one step erases the history, so a node that joined this
        // epoch and one that has run for fifty agree immediately. That is what makes it safe today.
        let setpoint = Demand::per_role(|r| if r == Role::Relay { 6 } else { 0 });
        let floor = Demand::default();
        let incumbent_start = Demand::per_role(|r| if r == Role::Relay { 6 } else { 0 });
        let joiner_start = Demand::default();

        // κ = 1: histories differ, one step, agreement.
        let incumbent = incumbent_start.rebalance(setpoint, floor, 7);
        let joiner = joiner_start.rebalance(setpoint, floor, 7);
        assert_eq!(
            incumbent, joiner,
            "at κ = 1 one step erases the history, so a late joiner agrees with an incumbent immediately"
        );

        // κ = 1/7: the same two histories disagree, and the disagreement is *transient* — which is exactly why
        // it is easy to miss. It lasts while the joiner climbs to the setpoint, and the cell is split for
        // every epoch of that climb.
        let members: Vec<(NodeId, Capability)> =
            (0..6).map(|i| (node(i), Capability::new(RoleSet::of(&[Role::Relay]), 4))).collect();
        let beacon = BeaconSeed::new([0x5A; 32]);
        let epoch = Epoch::new(9);
        let assigned_by = |demand: Demand| assign_report(&members, epoch, &beacon, demand).roles;

        let mut incumbent = incumbent_start;
        let mut joiner = joiner_start;
        let mut split_epochs = 0;
        for _ in 0..40 {
            incumbent = incumbent.rebalance(setpoint, floor, 1);
            joiner = joiner.rebalance(setpoint, floor, 1);
            if assigned_by(incumbent) != assigned_by(joiner) {
                split_epochs += 1;
            }
        }
        assert!(
            split_epochs > 0,
            "the premise: below κ = 1 the demand is a function of history, so two members that have stepped a \
             different number of times assign differently from the SAME agreed setpoint"
        );
        // Stated as a number because the number is the cost: at κ = 1/7 a joiner needs this many epochs before
        // the cell agrees with it about who serves what, and an epoch is `DEFAULT_EPOCH_PERIOD`.
        assert!(
            split_epochs >= 5,
            "the split is not a single-epoch artifact — it lasted {split_epochs} epochs"
        );

        // And it does heal: the divergence is transient, not permanent, which is what makes it survivable at
        // all and also what makes it easy to miss in a test that only looks at the end state. This assertion
        // exists because the first draft of this test compared the two AFTER convergence and proved nothing.
        assert_eq!(
            assigned_by(incumbent),
            assigned_by(joiner),
            "the histories converge eventually — the cost is the transient, not a permanent fork"
        );
    }

    #[test]
    fn assignment_is_deterministic_and_verifiable() {
        let members = cell(7, &[Role::Relay, Role::Storage], 4);
        let d = Demand::from_counts([3, 4, 0, 0, 0, 0]);
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
        let d = Demand::from_counts([3, 0, 0, 0, 0, 0]);
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
        let d = Demand::from_counts([2, 0, 0, 5, 0, 0]);
        let report = assign_report(&members, E, &B, d);
        let exits = report.roles.values().filter(|r| r.has(Role::Exit)).count();
        assert_eq!(exits, 3, "only the 3 exit-capable nodes can be assigned exit");
        assert_eq!(
            report.deficit.of(Role::Exit),
            2,
            "the 2 unfillable exits are a reported deficit (escalation signal)"
        );
    }

    #[test]
    fn higher_capacity_nodes_are_preferentially_selected() {
        // One heavyweight node vs many lightweight; over many epochs the heavyweight is selected far more often
        // for a scarce (demand-1) role — capability-weighting, not a coin flip.
        let mut members = cell(12, &[Role::Relay], 1);
        members[0].1 = Capability::new(RoleSet::of(&[Role::Relay]), MAX_WEIGHT);
        let d = Demand::from_counts([1, 0, 0, 0, 0, 0]);
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
        let d = Demand::from_counts([1, 0, 0, 0, 0, 0]);
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
        let d = Demand::from_counts([4, 4, 4, 4, 0, 0]);
        let a = assign(&members, E, &B, d);
        assert!(a.values().any(|r| r.count() >= 2), "at least one node holds multiple roles simultaneously");
        // With demand == supply on every role, every node serves every role it offered.
        for r in a.values() {
            assert_eq!(r.count(), 4);
        }
    }

    #[test]
    fn rebalance_steps_toward_the_setpoint() {
        let d = Demand::from_counts([4, 4, 0, 0, 0, 0]);
        let floor = Demand::from_counts([1, 1, 1, 1, 0, 0]);
        // Want more relays, fewer storage: at κ = 1 the demand jumps straight to the setpoint.
        let setpoint = Demand::from_counts([9, 2, 0, 0, 0, 0]);
        let next = d.rebalance(setpoint, floor, 7);
        assert_eq!(next.of(Role::Relay), 9, "κ=1 reaches the raised setpoint");
        assert_eq!(next.of(Role::Storage), 2, "κ=1 reaches the lowered setpoint");
        assert!(next.of(Role::Storage) >= floor.of(Role::Storage), "never below the floor");
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
                let mut d = Demand::per_role(|r| if r == Role::Relay { start } else { 0 });
                let setpoint = Demand::per_role(|r| if r == Role::Relay { target } else { 0 });
                let mut prev_err = u64::MAX;
                for _ in 0..256 {
                    d = d.rebalance(setpoint, floor, k);
                    let err = u64::from(d.of(Role::Relay).abs_diff(target)).pow(2);
                    assert!(err <= prev_err, "κ={k}/7 from {start}: Lyapunov error must not increase ({prev_err}→{err})");
                    prev_err = err;
                }
                assert_eq!(d.of(Role::Relay), target, "κ={k}/7 from {start}: converges to the setpoint, no overshoot");
            }
        }
    }

    #[test]
    fn the_role_controller_runs_the_live_loop() {
        // The sans-I/O controller: each epoch it steps demand toward the telemetry setpoint and re-assigns
        // roles. It converges its demand, assigns min(demand, supply), and escalates a genuine shortfall.
        let members = cell(10, &[Role::Relay], 4); // 10 relay-capable nodes
        let mut ctrl = RoleController::new(
            Demand::from_counts([2, 0, 0, 0, 0, 0]),
            Demand::from_counts([1, 0, 0, 0, 0, 0]),
            3, // κ = 3/7
        );
        // The driver's setpoint: the load wants 6 relays (≤ supply). Demand converges up to 6, assigns 6.
        let setpoint = Demand::from_counts([6, 0, 0, 0, 0, 0]);
        let mut last = ctrl.demand().of(Role::Relay);
        for e in 0..40u64 {
            let report = ctrl.step(&members, Epoch::new(e), &B, setpoint);
            let active = report.roles.values().filter(|r| r.has(Role::Relay)).count();
            assert_eq!(active as u16, ctrl.demand().of(Role::Relay).min(10), "assigns min(demand, supply)");
            assert!(ctrl.demand().of(Role::Relay) >= last, "demand rises monotonically toward the setpoint");
            assert_eq!(report.deficit.of(Role::Relay), 0, "supply covers this setpoint — no deficit");
            last = ctrl.demand().of(Role::Relay);
        }
        assert_eq!(ctrl.demand().of(Role::Relay), 6, "the controller settles at the setpoint");
        // A setpoint BEYOND the eligible supply: demand climbs past supply, assigns all 10, escalates the rest.
        let mut hungry = RoleController::new(Demand::from_counts([8, 0, 0, 0, 0, 0]), Demand::default(), 7);
        let report = hungry.step(&members, Epoch::new(0), &B, Demand::from_counts([15, 0, 0, 0, 0, 0]));
        assert_eq!(report.roles.values().filter(|r| r.has(Role::Relay)).count(), 10, "assigns all it can");
        assert_eq!(report.deficit.of(Role::Relay), 5, "the 5 relays it wants but cannot fill are escalated to the parent");
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
        let capacity = Demand::from_counts([10, 5, 0, 0, 0, 0]);
        let mut m = LoadMeter::new(capacity);
        m.record(Role::Relay, 20);
        m.record(Role::Relay, 5); // 25 relay-units observed
        m.record(Role::Storage, 3);
        assert_eq!(m.observed_load(), Demand::from_counts([25, 3, 0, 0, 0, 0]));
        // Local setpoint: ⌈25/10⌉ = 3 relays, ⌈3/5⌉ = 1 storage.
        assert_eq!(m.local_setpoint(), Demand::from_counts([3, 1, 0, 0, 0, 0]));
        // The whole cell agrees on the aggregate: sum every node's observed load, then ⌈total / capacity⌉.
        let loads = [
            Demand::from_counts([25, 3, 0, 0, 0, 0]),
            Demand::from_counts([40, 0, 0, 0, 0, 0]),
            Demand::from_counts([15, 7, 0, 0, 0, 0]),
        ];
        // relay total 80 → ⌈80/10⌉ = 8; storage total 10 → ⌈10/5⌉ = 2.
        assert_eq!(cell_setpoint(&loads, capacity), Demand::from_counts([8, 2, 0, 0, 0, 0]));
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
            let a = assign(&adjusted, Epoch::new(e), &B, Demand::from_counts([1, 0, 0, 0, 0, 0]));
            if a.get(&node(1)).is_some_and(|r| r.has(Role::Relay)) {
                good_wins += 1;
            }
        }
        assert!(good_wins > 130, "the full-trust node wins the scarce role far more often, got {good_wins}/200");
    }

    #[test]
    fn a_corroborated_down_node_is_excused_not_slashed() {
        // Audit R-H2: a node knocked offline by a mass failure must not be punished for the outage — else it
        // decays to the floor and forfeits its role on return, the exact self-organization failure under
        // churn. Non-performance while corroborated-DOWN is excused; while REACHABLE (shirking) it decays.
        let (offline, shirker) = (node(9), node(8));
        let mut rep = Reputation::new();
        // Many windows of non-performance while corroborated down: excused — the score never moves.
        for _ in 0..8 {
            rep.observe_reachable(offline, false, false);
        }
        assert_eq!(rep.score(&offline), REP_SCALE, "an outage is invisible to reputation");
        // The identical non-performance while reachable is slashed to the floor (it is genuinely shirking).
        for _ in 0..8 {
            rep.observe_reachable(shirker, false, true);
        }
        assert_eq!(rep.score(&shirker), REP_FLOOR, "a reachable non-performer is slashed as before");
        // The returned node that serves recovers exactly as usual — the excuse changed nothing but the outage.
        rep.observe_reachable(offline, true, true);
        assert_eq!(rep.score(&offline), REP_SCALE, "serving keeps full standing");
    }

    #[test]
    fn the_role_set_is_extensible_without_touching_the_per_role_machinery() {
        // Role::Rendezvous was added for the NOSTOS receiver-anonymity substrate, and the point of the indexed
        // `Demand` is that adding it required only the enum variant. Assert the properties that makes true, so a
        // future role cannot silently half-land: every role has a distinct in-bounds slot, `per_role` reaches all of
        // them, and the supply/demand plumbing sees the new one.
        assert_eq!(Role::ALL.len(), Role::COUNT);
        let mut seen = [false; Role::COUNT];
        for role in Role::ALL {
            assert!(role.index() < Role::COUNT, "{role:?} indexes in bounds");
            assert!(!seen[role.index()], "{role:?} has a distinct slot");
            seen[role.index()] = true;
        }
        assert!(seen.iter().all(|&s| s), "every slot is claimed by exactly one role");

        // `per_role` is the single construction point, so it must reach every role — including the newest.
        let d = Demand::per_role(|r| r.index() as u16 + 1);
        for role in Role::ALL {
            assert_eq!(d.of(role), role.index() as u16 + 1, "per_role reaches {role:?}");
        }

        // A node offering ONLY the new role counts toward its supply and nothing else's — i.e. the role is real to
        // the assignment machinery, not just present in the enum.
        let members = [(node(1), Capability::new(RoleSet::of(&[Role::Rendezvous]), 4))];
        let supply = Demand::supply(&members);
        assert_eq!(supply.of(Role::Rendezvous), 1, "the rendezvous host is eligible supply");
        assert_eq!(supply.of(Role::Relay), 0, "and is not counted as anything else");
        // …and the assignment actually gives it out when the cell demands it.
        let want = Demand::per_role(|r| u16::from(r == Role::Rendezvous));
        let assigned = assign(&members, Epoch::new(1), &BeaconSeed::new([9u8; 32]), want);
        assert!(
            assigned.get(&node(1)).is_some_and(|r| r.has(Role::Rendezvous)),
            "the only rendezvous-capable node is assigned the role"
        );
    }
}
