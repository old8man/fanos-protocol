//! The **live self-organizing role loop** — the driver that runs a node's [`RoleController`] over the real
//! overlay each beacon round (task A2; the sans-I/O controller is `fanos_core::roles`).
//!
//! Each epoch the loop reads the cell's authenticated capability directory ([`crate::capdir`]), steps the
//! controller (the UHM-grounded Lyapunov-descent demand rebalance + role assignment), extracts *this* node's
//! assigned roles, and publishes them on a `watch` channel the node acts on. The setpoint — how much of each
//! role the cell wants — is a **cell aggregate over measured load**: [`spawn_self_organization`] runs a load
//! publisher beside the capability publisher, each node advertises its own observed per-role load at its
//! coordinate slot ([`crate::loaddir`]), and every node sums the roster so all derive the *same* setpoint,
//! which is what keeps the assignment deterministic.
//!
//! **This comment used to say "until that is wired the node holds a fixed target". It is wired** — and the
//! stale sentence was read by a later reader as evidence the loop was open, and copied into a design document
//! before anyone checked the code. The residual is narrower and worth stating exactly, so the next reader does
//! not have to re-derive it: `HealerNode::load_report` measures **2 of the 5 roles first-hand** (relay from
//! forwarding activity, storage from shards held) and reports the other three as **absent** — `None`, not a
//! fabricated zero. `LoadSensor::setpoint` substitutes this node's own offer for an absent role, deliberately,
//! since a demand of zero would retire a role the moment nobody could see it; so for a role with no sensor,
//! supply stands in for demand.
//!
//! That fallback used to fire on any **zero**, which is a different and wrong rule: it discarded the true
//! reading of a role that had legitimately gone idle, at exactly the moment the controller should have shrunk
//! it, and it bound the two roles that *are* measured. `Notification::LoadReport` now carries
//! `[Option<u16>; Role::COUNT]` so absence is a value rather than a guess.
//!
//! **All five roles are sensed**, by three routes that differ only in what can see the work:
//!
//! | role | measured | reported by |
//! |---|---|---|
//! | relay | frames originated | the overlay's healer, first-hand |
//! | storage | keys held | the overlay's healer, first-hand |
//! | rendezvous | registrations + hosted services | `CellNode`, calling `observe_load` on a concrete inner engine |
//! | service | intros being gathered | `ServiceNode`, addressing the same seam by `Control` through a `dyn Engine` |
//! | exit | flows in flight | a driver-side [`LoadGauge`] — the work is async tasks, which no engine can count |
//!
//! Four of the five are **levels**, not rates: what the node is carrying *now*, which is the quantity the
//! per-node capacity is defined against and which needs no observation window to be comparable. Only relay is a
//! rate, because origination is what the sensor it reuses already counted.
//!
//! A role still reads unsensed where its driver is not running — a bare exit spawned outside a self-organizing
//! node passes no gauge — and there the offer stands in, which is what a fallback is for.
//!
//! Composition with [`crate::capdir`]: a node runs *two* tasks — [`crate::capdir::spawn_capability_publisher`]
//! keeps its own advertisement live, and [`spawn_role_loop`] reads the whole roster and computes its
//! assignment. Because every node steps an identical controller over the same agreed inputs (authenticated
//! capabilities, the shared beacon, the agreed setpoint), the cell reaches the same assignment with no
//! coordination — the deterministic self-organization proven in `fanos-core/tests/self_organization.rs`, now
//! over the live directory.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use std::sync::Arc;

use fanos_core::roles::{
    Capability, Demand, REP_WINDOW, Reputation, Role, RoleController, RoleReading, RoleSet,
};
use fanos_field::Field;
use fanos_geometry::Plane;
use fanos_primitives::{BeaconSeed, Epoch, NodeId};
use fanos_quic::{Client, CoordinateProver};
use fanos_runtime::Notification;
use fanos_vrf::VrfSecret;
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::JoinHandle;

use crate::capdir::{Seating, build_capability_directory, spawn_capability_publisher};
use crate::resolve::Coverage;
use crate::diagdir::{publish_diagnosis, read_diagnosis_window};
use crate::loaddir::{build_cell_setpoint, spawn_load_publisher};

/// The load one node is taken to absorb per role — the setpoint denominator, applied **once**, cell-wide, in
/// `cell_setpoint`. An unsensed offered role publishes `capacity` as its load, so "everyone who offers it,
/// serves it" holds for those whatever this value is.
///
/// # This value is wrong now, and `1` is why
///
/// `1` was right while every role was unsensed: each offering node published one node's worth, the setpoint
/// came back equal to the eligible supply, and the identity above was the whole behaviour. Making the sensors
/// live (`5fa70ea`) changed what a *sensed* role publishes — its **measured load**, counted in keys held and
/// frames originated — while leaving the denominator at 1. So the setpoint is now
///
/// ```text
///   ⌈Σ (keys held + frames originated) / 1⌉   nodes
/// ```
///
/// which reads an event count as a node count. Where it still applies, demand exceeds the eligible supply
/// permanently, `assign_report` fills `min(demand, eligible)` so **every offering node receives every role it
/// offered**, and the controller can no longer express anything about that role: the assignment it produces
/// is the one a node would reach with no controller at all. Measured on a fleet when it applied to all six:
/// `transitions = 0` across a whole observation window, which is what made role-assignment churn
/// undetectable (`c77120a`).
///
/// **"Where it still applies" is now two roles, not six, and this paragraph used to illustrate it with the
/// first one to leave.** Storage — "a cell holding a hundred keys asks for a hundred storage nodes" — was the
/// first capacity derived from a real admission bound, and Rendezvous, Service and Exit followed. Relay and
/// Ingress are what remain, for reasons that are not the same: Relay's sensor is a rate measured against a
/// level, and Ingress has an admission bound with no sensor to divide into it. An example drawn from a role
/// that has since been fixed is worse than no example, because it reads as evidence that nothing has moved.
///
/// The permanent deficit that saturation implies **is read now, and only half of what reads it exists**.
/// `note_deficit` is called from the epoch step and records `Station::RoleUnderProvisioned`, so a shortfall
/// reaches this node's operator. What `docs/design-roles.md` describes and the tree still lacks is the
/// **parent-cell escalation**: `Escalation` has no `Deficit` variant, so a cell that cannot staff a role
/// tells its operator and no other cell.
///
/// This paragraph used to say the deficit had no production caller at all, and used that as the reason the
/// escalation was safe to leave unwired. Both halves of that have moved: four of the six roles now have a
/// derived capacity, so their deficits are real rather than artefacts of a placeholder denominator — see
/// `the_last_two_capacities_and_the_parent_escalation_are_still_open`, which fires when the last two get
/// theirs.
///
/// Correcting it is a **measurement**, not a new constant: capacity must be in the load's own units — how
/// many keys, or frames, one node absorbs per observation window — which is a throughput figure
/// `fanos-bench` can produce. Setting it by taste would replace one wrong number with another.
pub(crate) const ROLE_CAPACITY_PER_NODE: u16 = 1;

/// **How many keys one node absorbs — and the one role whose capacity is a derivation rather than a
/// placeholder.**
///
/// The storage load a node reports is `store.entries.len()` (`overlay/mod.rs`), so capacity in those units is
/// "how many entries one node will hold", and the node itself already answers that: `MAX_STORE_ENTRIES` is
/// the bound its own admission rule enforces, past which it refuses a new digest outright. Reading capacity
/// off anything else would be reading a number the node does not obey.
///
/// It became a *usable* figure only once the store started reclaiming. While six directories minted a slot
/// per epoch and nothing removed one, `entries.len()` climbed on a wall clock toward the cap regardless of
/// how much content the cell actually held — so this ratio measured uptime, not demand
/// (`fanos-node/tests/store_lifetime.rs`). With soft state reclaimed, what is left in `entries` is content
/// plus a constant directory footprint, which is the thing worth provisioning against.
///
/// Saturated `u16` because `Demand` is `u16`-valued and `MAX_STORE_ENTRIES` fits; if the cap ever grew past
/// `u16::MAX` the clamp would understate capacity, which errs toward over-provisioning storage — the safe
/// direction, and one the deficit escalation would surface rather than hide.
#[allow(clippy::cast_possible_truncation)]
const STORAGE_CAPACITY_PER_NODE: u16 =
    if fanos_runtime::MAX_STORE_ENTRIES > u16::MAX as usize { u16::MAX } else { fanos_runtime::MAX_STORE_ENTRIES as u16 };

/// The per-role capacity vector, built once so the load publisher and the setpoint aggregation cannot disagree
/// about the denominator — the divergence that would reintroduce a double division without any type noticing.
///
/// **Per role, because capacity is not one number.** Each role's load is measured in its own units, so its
/// capacity has to be too.
///
/// ## The rule, which storage established and four roles now follow
///
/// > **Capacity is the bound the node's own admission rule already enforces on the very number the sensor
/// > reports.**
///
/// Not a measurement to be commissioned and not a number to be chosen: the node is *already* refusing work
/// past some point, and reading capacity off anything else would be reading a figure the node does not obey.
/// Four of the six roles have both halves — a level-valued sensor and an enforced cap on that same level —
/// and the match of units is what makes the ratio meaningful rather than merely arithmetic:
///
/// | role | the sensor reports | the node enforces |
/// |---|---|---|
/// | storage | `store.entries.len()` | [`MAX_STORE_ENTRIES`](fanos_runtime::MAX_STORE_ENTRIES) at admission |
/// | rendezvous | `registrations() + hosts()` | those two `BoundedMap`s' caps |
/// | service | `service.pending()` | `max_pending`, checked before accepting an intro |
/// | exit | flows in flight | `MAX_SESSIONS`, LRU-evicted by the session demux |
///
/// The two residuals are residual for **different reasons**, and collapsing them would lose the distinction
/// that says what each still needs:
///
/// * **Relay** has a sensor and no matching bound. Its load is *frames originated* — a rate — while every cap
///   in reach is a level, so no admission rule answers "how many frames per window". That one is a genuine
///   throughput measurement, which is `fanos-bench`'s job.
/// * **Ingress** has a bound (POROS's own pending cap) and no sensor. A denominator over a numerator nobody
///   reports is not a ratio, so the bound is unusable until the role is measured.
///
/// Both keep [`ROLE_CAPACITY_PER_NODE`] and its stated defect. Replacing one wrong number with another by
/// taste is the thing this whole subsystem exists not to do.
///
/// ## Why these read protocol constants and never a node's configuration
///
/// Capacity is a **cell-wide denominator**: every node divides the same summed load by it, and the assignment
/// is only deterministic while they all use the same value. A node that locally lowers its own `max_pending`
/// therefore does not lower the cell's model of it — it simply under-serves relative to that model, which
/// surfaces as a deficit rather than as a silent disagreement. That is the correct direction, and it is why
/// this reads the constants rather than any live configuration.
#[must_use]
pub(crate) fn role_capacity() -> Demand {
    Demand::per_role(|role| {
        debug_assert_eq!(
            capacity_is_derived(role),
            !matches!(role, Role::Relay | Role::Ingress),
            "`capacity_is_derived` must name exactly the roles this match derives, or `note_deficit` \
             reports on a fabricated number (or stays silent about a real one)"
        );
        match role {
            Role::Storage => STORAGE_CAPACITY_PER_NODE,
            Role::Rendezvous => saturating_cap(
                crate::rendezvous_relay::MAX_REGISTRATIONS + crate::rendezvous_relay::MAX_HOSTS,
            ),
            Role::Service => saturating_cap(crate::threshold_service::DEFAULT_MAX_PENDING),
            Role::Exit => saturating_cap(crate::diaulos::MAX_SESSIONS),
            Role::Relay | Role::Ingress => ROLE_CAPACITY_PER_NODE,
        }
    })
}

/// Whether this role's capacity is **derived** from a bound its subsystem enforces, rather than still being
/// the [`ROLE_CAPACITY_PER_NODE`] placeholder.
///
/// Named because two different things read it and must not drift apart: `role_capacity` decides the
/// denominator, and `note_deficit` decides whether the resulting shortfall is worth an operator's attention.
/// A placeholder capacity makes the demand exceed eligible supply on any active cell, so its "deficit" is an
/// artefact of the denominator and reporting it would fire on every epoch for ever — and a station that fires
/// every epoch is not a signal, which is the same reason the deficit went unreported before the capacities
/// were derived at all.
const fn capacity_is_derived(role: Role) -> bool {
    matches!(role, Role::Storage | Role::Rendezvous | Role::Service | Role::Exit)
}

/// An admission bound in [`Demand`]'s `u16` units.
///
/// Saturating rather than truncating, and the direction matters: a cap past `u16::MAX` clamps to a *smaller*
/// capacity, which over-provisions the role. Over-provisioning is visible and safe; the truncated alternative
/// wraps to a tiny capacity and demands a hundred nodes for one node's work.
const fn saturating_cap(bound: usize) -> u16 {
    if bound > u16::MAX as usize { u16::MAX } else { bound as u16 }
}

/// The latest per-role load this node **measured**, shared between the engine's notification stream and the role
/// loop's setpoint closure.
///
/// Shared atomics rather than a channel because the two run on different clocks — the engine samples once per
/// observation window, the loop asks whenever an epoch turns — and only the most recent value matters. A channel
/// would either buffer readings nobody will read or put back-pressure on the engine's notification fan-out.
///
/// One `AtomicU32` per role holds an `Option<u16>` as **`0` = no reading, `v + 1` = `Some(v)`**. That encoding is
/// not a trick to save a word. The array's initial state *is* "nothing reported yet", which is genuinely absent,
/// and an encoding whose zero meant `Some(0)` would have the loop read a node that has not yet observed as a node
/// measuring no demand — the same conflation the `Option` in `Notification::LoadReport` exists to remove. Getting
/// it backwards here would reintroduce the defect one layer down, where no type would catch it.
///
/// # A frozen reading is worse than an absent one, and the array cannot tell them apart
///
/// The slots have two independent writers. Engine-measured roles are written by the feeder task
/// ([`spawn_load_sensor`]); driver-side roles are written by their own task through a [`LoadGauge`]. When the
/// **feeder** dies, the engine slots keep decoding to their last value — a plausible, measured-looking number
/// that has stopped tracking anything, which this node then publishes as its load and the whole cell divides
/// by. An `AtomicU32` has no way to say "nobody is writing me any more", so the level lies (#251).
///
/// `feeding` is that missing half: a `watch::Receiver` whose sender belongs to whoever writes through
/// [`Self::record`]. With the writer gone, an engine-fed slot reads **absent** rather than stale — and absent
/// is a state the consumer already handles, by standing the offer in for the role
/// ([`RoleReading::to_load`]). That errs toward "this node is at capacity", so the cell provisions more nodes
/// for the role instead of piling work onto one whose reported load stopped moving.
///
/// `gauged` is why the rule is per slot and not per sensor. Blanket-absenting on a dead feeder would erase a
/// live gauge's reading, which is precisely the failure [`Self::record`] refuses a `None` to avoid.
pub(crate) struct LoadSensor {
    /// Latest reading per role, indexed by `Role::index`, in the encoding above.
    latest: [AtomicU32; Role::COUNT],
    /// Bit `Role::index` set once a [`LoadGauge`] is opened for that role: its writer is the role's own task,
    /// not the feeder, so the feeder's death says nothing about it.
    gauged: AtomicU32,
    /// Alive while whoever calls [`Self::record`] still exists — see the type doc.
    feeding: watch::Receiver<()>,
}

// Every index below is `Role::index()`, which `fanos_core::roles` proves `< Role::COUNT`.
#[allow(clippy::indexing_slicing)]
impl LoadSensor {
    /// A sensor with nothing reported yet — every role absent — **and the token its feeder must hold**.
    ///
    /// Two values, so the writer cannot forget: whoever calls [`Self::record`] keeps the `Sender`, and when
    /// that owner is gone the engine-fed slots stop claiming to be measured. A caller that drops it
    /// immediately is declaring it will never feed this sensor, which is the truth for a gauge-only node.
    fn new() -> (Self, watch::Sender<()>) {
        let (tx, feeding) = watch::channel(());
        (Self { latest: core::array::from_fn(|_| AtomicU32::new(0)), gauged: AtomicU32::new(0), feeding }, tx)
    }

    /// Record a load report from the engine: latest-wins for a role the engine **measured**, and no-op for one
    /// it reports as absent.
    ///
    /// A `None` must not clear the slot, and that is not a convenience — it is what lets the two report paths
    /// coexist. The engine reports `None` for every role it has no sensor for, which is exactly the set a
    /// driver-side [`LoadGauge`] fills; storing the `None` would erase the gauge's reading on every observation
    /// and the three roles would silently fall back to the offer forever, looking wired.
    fn record(&self, reported: RoleReading) {
        for role in Role::ALL {
            if let Some(v) = reported.of(role) {
                self.slot(role).store(u32::from(v) + 1, Ordering::Relaxed);
            }
        }
    }

    /// Open a **driver-side gauge** for `role` — for work an async task performs, which no engine can count.
    ///
    /// Opening it declares the role *sensed* at a load of zero, which is the truth at that moment: the task is
    /// running and carrying nothing yet. From then on the role is measured, so the offer no longer stands in for
    /// it, and a genuinely idle exit or service reaches the controller as the zero it is.
    ///
    /// The gauge counts work **in flight** rather than work completed. That is the quantity `capacity` is
    /// defined against — "the load one node absorbs" — and it needs no observation window to be meaningful,
    /// where a completion rate would have to be reconciled with whatever window the engine's own counters use.
    /// **One open gauge per role.** Cloning is the supported way to share it (every clone addresses the same
    /// slot); opening a second, independent one would give the role two tokens, and the first to drop would
    /// mark it unsensed while the other driver is still running. A `debug_assert` makes that a loud test
    /// failure instead of a silent under-report, because production has exactly one opener per role.
    pub(crate) fn gauge(self: &Arc<Self>, role: Role) -> LoadGauge {
        debug_assert!(
            self.gauged.load(Ordering::Relaxed) & (1u32 << role.index()) == 0,
            "a second gauge for a role already gauged: the first to drop would unsense a running driver"
        );
        // Some(0): sensed, carrying nothing. `fetch_add`/`fetch_sub` then work directly on the encoding.
        self.slot(role).store(1, Ordering::Relaxed);
        // This slot's writer is the caller's task from here on, so the feeder's fate does not decide it.
        self.gauged.fetch_or(1u32 << role.index(), Ordering::Relaxed);
        LoadGauge { token: Arc::new(GaugeToken { sensor: Arc::clone(self), role }) }
    }

    /// This role's slot.
    fn slot(&self, role: Role) -> &AtomicU32 {
        &self.latest[role.index()]
    }

    /// The most recent reading, as the role vocabulary the setpoint is derived in.
    pub(crate) fn reading(&self) -> RoleReading {
        // Asked once, not per role: `has_changed` is a load on the shared channel state, and every slot is
        // judged against the same instant — two readings taken either side of the feeder's death would be a
        // reading of two different sensors.
        let feeding = self.feeding.has_changed().is_ok();
        let gauged = self.gauged.load(Ordering::Relaxed);
        RoleReading::per_role(|role| {
            // Engine-fed and nobody is feeding: absent, which is TRUE, where the last value merely looks it.
            if !feeding && gauged & (1u32 << role.index()) == 0 {
                return None;
            }
            let raw = self.latest[role.index()].load(Ordering::Relaxed);
            // `0` is absent; anything else decodes to `raw - 1`, which fits `u16` because `record` is the only
            // writer and it only ever stores `u16 + 1`.
            raw.checked_sub(1).map(|v| u16::try_from(v).unwrap_or(u16::MAX))
        })
    }

    /// This node's **published load contribution**, in work units — the value the cell sums and divides by
    /// capacity exactly once, in `cell_setpoint`.
    ///
    /// The fallback for a role with no sensor is stated once, in `RoleReading::to_load`, and it fires on
    /// **absence** — not on a zero. That distinction is the whole point: substituting the offer for every zero
    /// threw away the true reading of a role that legitimately went idle, at exactly the moment the controller
    /// should have shrunk it. Standing supply in for demand is right for a role nobody can see and wrong for one
    /// that reported nothing to do.
    pub(crate) fn load(&self, offered: RoleSet, capacity: Demand) -> Demand {
        self.reading().to_load(capacity, offered)
    }
}

/// A driver-side load gauge for one role: the count of work units this node is **carrying right now**.
///
/// Held by the task that performs the role's work — the clearnet exit, the hosted service — for a role no engine
/// can see. Cheap to clone; every clone addresses the same slot.
#[derive(Clone)]
pub struct LoadGauge {
    token: Arc<GaugeToken>,
}

/// **The role's driver is running** — held jointly by every [`LoadGauge`] clone and every live [`LoadGuard`],
/// and dropped when the last of them is gone (#258).
///
/// Without it a dead driver is indistinguishable from an idle one. [`LoadGuard`]'s `Drop` correctly releases
/// each unit of work however the flow ends, so a task that dies takes its guards with it and the slot falls to
/// `Some(0)` — "running, carrying nothing", which is exactly the reading that earns a role *more* work. The
/// distinction the sensor's encoding already draws is between measured and absent, so a driver that stopped
/// must return its slot to absent and let the offer stand in, the same conservative direction the feeder's
/// death takes ([`LoadSensor`]).
///
/// Guards hold it too, not just gauges: while a flow is still in flight the role is being served, whatever
/// became of the handle that started it, and the two drop orders must give the same answer.
struct GaugeToken {
    sensor: Arc<LoadSensor>,
    role: Role,
}

impl Drop for GaugeToken {
    fn drop(&mut self) {
        // Clear the marker first: from here the slot is the feeder's business again, and it has none.
        self.sensor.gauged.fetch_and(!(1u32 << self.role.index()), Ordering::Relaxed);
        self.sensor.slot(self.role).store(0, Ordering::Relaxed); // 0 is absent, not `Some(0)`
    }
}

impl LoadGauge {
    /// Count one unit of this role's work as in flight until the returned guard drops.
    ///
    /// A guard rather than a matched decrement call, because the flows this counts end in every way a Rust task
    /// can end — a clean close, a policy rejection, an unreachable host, a cancelled task — and a decrement that
    /// has to be *reached* would be skipped by most of them. A load that only ever rises reads as a permanently
    /// saturated node, so the controller would keep provisioning for work that finished long ago.
    #[must_use]
    pub fn in_flight(&self) -> LoadGuard {
        self.token.sensor.slot(self.token.role).fetch_add(1, Ordering::Relaxed);
        LoadGuard { token: Arc::clone(&self.token) }
    }
}

/// One unit of in-flight work; the gauge falls when this drops. See [`LoadGauge::in_flight`].
pub struct LoadGuard {
    token: Arc<GaugeToken>,
}

impl Drop for LoadGuard {
    fn drop(&mut self) {
        // Saturating: the slot is `Some(n)` encoded as `n + 1`, so it must never fall below 1 — that would
        // decode as "no sensor" and hand the role back to the offer fallback while the driver is still running.
        // Handing it back is [`GaugeToken`]'s job, and only once nothing is left to run.
        let slot = self.token.sensor.slot(self.token.role);
        let _ = slot.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1).max(1)));
    }
}

/// Subscribe to the engine's load reports and keep the latest, returning the shared sensor.
///
/// The task ends when the engine's notification stream closes, i.e. on node shutdown. A `Lagged` receiver is
/// ignored rather than treated as an error: the sensor is a *latest-value* register, so dropped intermediate
/// reports cost nothing — the next observation refreshes it in full.
pub(crate) fn spawn_load_sensor(client: &Client) -> Arc<LoadSensor> {
    let (sensor, feeding) = LoadSensor::new();
    let sensor = Arc::new(sensor);
    let sink = Arc::clone(&sensor);
    let mut reports = client.subscribe();
    // Supervised (#251): the sensor's readings are atomics with no channel behind them, so a dead feeder
    // leaves every role's load frozen at its last value — measured-looking and stale, which the controller
    // then divides by. The station is what makes that visible; the frozen READING is still a level nobody
    // can tell has stopped, and that is tracked separately.
    let supervised = client.clone();
    let task = tokio::spawn(async move {
        // Moved in, never sent on: its DROP is the signal. However this task ends — a panic, a cancellation,
        // the stream closing — the engine-fed slots stop claiming to be measured from that moment.
        let _feeding = feeding;
        loop {
            match reports.recv().await {
                Ok(Notification::LoadReport { per_role }) => sink.record(RoleReading::from_array(per_role)),
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::LoadSensor, &supervised, task);
    sensor
}

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
    /// Whether the directory scans behind [`roster`](Self::roster) were **complete** (#289).
    ///
    /// The count alone cannot be judged, and that is not a nicety. When two nodes report different rosters
    /// there are two worlds needing opposite responses: both scans complete and genuinely disagreeing means
    /// the cell is deciding on an input its members do not share (the #130 shape); one scan incomplete means
    /// a race that the next epoch settles, and there is no defect at all. Without this the two are one
    /// number and an observer must guess.
    ///
    /// It was computed all along — `assign_epoch` returns `caps_complete && load_complete` and the refresh
    /// tick feeds it to the backoff — so this adds no measurement, only a READER. A value that steers
    /// control and reaches no observer is the shape this tree keeps finding.
    pub complete: bool,
}

impl Assignment {
    /// The empty assignment, before the first one is computed.
    pub const NONE: Self = Self { roles: RoleSet::EMPTY, roster: 0, epoch: Epoch::ZERO, complete: false };

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

    /// Whether `other` is the **same assignment** — `(roles, roster, epoch)`, deliberately *not* `complete`.
    ///
    /// An assignment's identity is what the cell decided. [`complete`](Self::complete) is a property of the
    /// *read that produced it* — the reader's luck — and folding it into the comparison makes "the same
    /// assignment, read worse" count as a different assignment.
    ///
    /// **That was a live defect (#293), and it cost the thing the refresh loop exists to protect.** The loop
    /// scores a repeat as evidence and relaxes its scan period on accumulated evidence. With derived equality:
    /// a node at `A{R,7,E}` with `stable = 2` hits one timed-out read, gets the identical `A{R,7,E}` back with
    /// `complete: false`, and the comparison calls it a change — so the baseline is replaced. The very next
    /// *successful* read then returns `A{R,7,E}` with `complete: true`, differs from the poisoned baseline
    /// again, and is scored as "a complete change", which voids everything accumulated. Roles, roster and
    /// epoch never moved across all three steps.
    ///
    /// `next_stable` was written precisely so an inconclusive scan is "not a change, and not a reset" — its
    /// own test says so — and this comparison upstream was denying it the chance. Completeness still gates
    /// stability, once, where it belongs: as `next_stable`'s third argument.
    ///
    /// Derived `PartialEq` stays exact and is left alone. A `PartialEq` that silently ignores a field is a
    /// trap for the next reader, and it would disarm the destructuring guard (#193) that makes a newly added
    /// field a compile error.
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        self.roles.bits() == other.roles.bits()
            && self.roster == other.roster
            && self.epoch == other.epoch
    }
}

/// A node's **sans-I/O** live role controller: it holds the epoch-persistent [`RoleController`] state and, for a
/// given epoch's authenticated member set, beacon, and setpoint, produces *this* node's assigned [`RoleSet`].
/// The async loop below is a thin driver over it, so the identical logic runs under the simulator and a live
/// node.
pub struct LiveRoleController {
    node_id: NodeId,
    /// Held for its `floor` and `gain` — its **carried demand is deliberately not read**, see [`Self::step`].
    controller: RoleController,
    /// The last setpoint this node read **completely**, which is what a scan that did not conclude falls back
    /// to. A published value, not an accumulator: see [`Self::step`] for why that distinction is the whole
    /// point.
    ///
    /// `None` until the first complete read, and that is the whole of #250. The fallback's safety argument is
    /// "hold what the cell agreed", which requires there to *be* something the cell agreed; a `Demand::default()`
    /// in this field is not a quiet setpoint but the absence of one, and holding it is a claim the cell never
    /// made. On a 20 ms link every genesis load scan times out, so a two-valued field held zero for as long as
    /// that lasted and the whole cell assigned `RoleSet::EMPTY` — the freeze [`setpoint_to_track`]'s own doc
    /// calls "what makes the two-valued version of this rule a bug", reached by a different road.
    last_agreed: Option<Demand>,
    /// Per-role shortfall from the last [`step`](LiveRoleController::step) — see
    /// [`deficit`](LiveRoleController::deficit).
    last_deficit: Demand,
    reputation: Reputation,
}

impl LiveRoleController {
    /// Build a live controller for `node_id` over the demand controller `controller`, with a fresh reputation
    /// (every node fully trusted until observed).
    #[must_use]
    pub fn new(node_id: NodeId, controller: RoleController) -> Self {
        Self {
            node_id,
            controller,
            last_agreed: None,
            last_deficit: Demand::default(),
            reputation: Reputation::new(),
        }
    }

    /// The demand this node would assign from right now — a function of [`last_agreed`](Self::last_agreed),
    /// not of anything carried.
    #[must_use]
    pub fn demand(&self) -> Demand {
        self.demand_for(self.last_agreed.unwrap_or_default())
    }

    /// The last **complete** setpoint read, which a partial scan holds rather than acting on its own
    /// understated view — or `None` if no scan has ever concluded, in which case there is nothing to hold.
    #[must_use]
    pub fn last_agreed(&self) -> Option<Demand> {
        self.last_agreed
    }

    /// The demand implied by `setpoint` alone — replayed from the controller's floor, with no carried state,
    /// so two nodes reading the same setpoint assign from the same demand whatever their histories.
    fn demand_for(&self, setpoint: Demand) -> Demand {
        RoleController::demand_from_setpoints(
            self.controller.floor(),
            self.controller.gain_seventh(),
            &[setpoint],
        )
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

    /// One epoch: apply reputation to the members' weights, derive the demand **from `setpoint` alone**,
    /// assign roles, and return *this* node's assigned roles for `(epoch, beacon)`.
    ///
    /// ## Why this does not call [`RoleController::step`]
    ///
    /// `step` folds the setpoint into a carried demand, making the assignment a function of this node's
    /// *history* — and every node then takes its roles out of the report *it* computed, so a cell can
    /// under-provision a role with no node able to see it. [`RoleController::demand_from_setpoints`] is the
    /// same law replayed from the shared `floor`, which is the one starting value every node agrees on.
    ///
    /// **At the shipped `ROLE_GAIN_SEVENTH = 7` this is numerically identical**, because `κ = 1` reaches the
    /// setpoint in one step and the carry is already vacuous. That is exactly the reason to change it: cell
    /// agreement was resting on the *value of a tuning constant*, so damping the loop — the obvious response
    /// to role churn — would have reintroduced a permanent per-node divergence with no test failing. The
    /// agreement now holds at every gain, and the constant is free to be tuned for what it is for.
    ///
    /// ## The window is one epoch, and that is forced rather than chosen
    ///
    /// A window of `W` closed setpoints would need `W` readable closed epochs.
    /// `DIRECTORY_SLOT_EPOCHS` is `1` — derived from the onion ratchet's
    /// `DEFAULT_RETAIN`, i.e. the grace a lagging *reader* needs — so at epoch `e` the only closed load
    /// directory that still exists is `e − 1`. Smoothing over more history is not a trade-off available here;
    /// it is unreadable. Raising the retention to buy a window would couple two derivations that answer
    /// different questions, and the retention's own doc records that larger buys nothing and costs linearly.
    ///
    /// Losing the smoothing costs less than it appears, and for a reason specific to this mechanism: the
    /// assignment is a **fresh beacon lottery every epoch** (`priority_key` hashes the epoch and the seed), so
    /// *which* nodes serve is fully re-drawn regardless. Damping the count buys no stability that the
    /// consumer preserves.
    pub fn step(
        &mut self,
        members: &[(NodeId, Capability)],
        epoch: Epoch,
        beacon: &BeaconSeed,
        setpoint: Demand,
        // Whether the scans that produced `members` were complete — see `Assignment::complete`.
        complete: bool,
    ) -> Assignment {
        self.last_agreed = Some(setpoint);
        let weighted = self.reputation.adjust(members);
        let report = fanos_core::roles::assign_report(&weighted, epoch, beacon, self.demand_for(setpoint));
        self.last_deficit = report.deficit;
        let roles = report.roles.get(&self.node_id).copied().unwrap_or(RoleSet::EMPTY);
        Assignment { roles, roster: members.len(), epoch, complete }
    }

    /// This node's own identity — what a published record must name for this node to be in it.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Adopt a reputation **recomputed from published records** ([`Reputation::from_published`]).
    ///
    /// Replaces rather than folds, and that is the whole point: the score is a function of the closed record
    /// set, so two nodes that read the same records hold the same score whatever their local views were. A
    /// caller must only install a score computed over a window every node can read — see `assign_epoch`.
    pub fn adopt_reputation(&mut self, reputation: Reputation) {
        self.reputation = reputation;
    }

    /// Per role, how many nodes the cell's demand fell short of its eligible supply at the last
    /// [`step`](Self::step) — `AssignReport::deficit`, which used to be computed and dropped.
    ///
    /// **Reportable only now that capacity means something.** Under the placeholder capacity the demand
    /// exceeded supply on every active cell, so this was a fabrication on every epoch and surfacing it would
    /// have been pure noise; the saturation is exactly what made dropping it harmless. With four roles'
    /// capacities read off their own admission bounds the number says what it claims, and for a
    /// [`Role::covers_a_threshold_line`] role a positive value means the guarantee is not currently met.
    #[must_use]
    pub fn deficit(&self) -> Demand {
        self.last_deficit
    }
}

/// The newest epoch whose load directory is **closed** — final on every node that can read it — together with
/// the beacon seed its coordinate credentials verify against.
#[derive(Clone, Copy)]
struct ClosedEpoch {
    epoch: Epoch,
    seed: BeaconSeed,
}

impl ClosedEpoch {
    /// The `(epoch, seed)` to read the setpoint from when assigning for `assigning_for`, or `None` when this
    /// node holds no closed epoch it may read — in which case it must **hold**, never fall back to the live
    /// directory, which is the one input that cannot be agreed.
    ///
    /// Two rejections, and the first is the one that would be silent.
    ///
    /// * **Too old.** A record published for epoch `e` is pruned during `e + 2`, so anything older than
    ///   `assigning_for − 1` returns nothing — and `read_load` calls a missing record a definite `Absent`
    ///   rather than an unknown (deliberately, so one forged record cannot void a scan). An expired directory
    ///   therefore reads as a **complete** scan of a cell carrying no load at all, and every role is retired
    ///   at once. The staleness has to be rejected here because the reader cannot see it.
    /// * **Never held.** A node that booted mid-run never saw the previous epoch's seed, so on a VRF cell it
    ///   cannot verify that epoch's credentials. It waits one epoch. This is not a regression against reading
    ///   the live directory: such a node has not published its own load report for `e − 1` either.
    ///
    /// `assigning_for == self.epoch` is the genesis case and the *only* live read the loop performs: at epoch
    /// zero there is no earlier directory to close. It is corrected at the first beacon advance, and it cannot
    /// accumulate, because the demand is recomputed from scratch every epoch.
    fn readable_for(self, assigning_for: Epoch) -> Option<(Epoch, BeaconSeed)> {
        (self.epoch == assigning_for || self.epoch.next() == assigning_for)
            .then_some((self.epoch, self.seed))
    }
}

/// What an assignment is computed against: the **live** epoch and its seed, and the newest **closed** load
/// directory. Carried as one value so the two can never be passed separately and drift — the whole change
/// behind [`ClosedEpoch`] is that these are different epochs on purpose.
#[derive(Clone, Copy)]
struct AssignAt<'a> {
    /// The epoch being assigned for. The membership directory and the role lottery both read it live: who is
    /// present must be current, and a stale roster is a wrong answer for exactly one epoch.
    epoch: Epoch,
    /// That epoch's beacon seed — the lottery's randomness and the membership credentials' binding.
    beacon: BeaconSeed,
    /// Where the setpoint comes from. Not the live epoch, because a cell-wide count every node must agree on
    /// cannot be computed from a directory members are still writing to.
    closed: ClosedEpoch,
    /// This node's coordinate proof, present exactly where the cell's coordinates are VRF-derived, so a roster
    /// record must prove the slot it sits at (`crate::bound`). `Some` IS the mode.
    prover: Option<&'a CoordinateProver>,
    /// What this node's heartbeat last sensed about its cell — `(epoch, degraded, responsive)` from
    /// `Notification::Liveness`, which is what it publishes as that epoch's diagnosis. The epoch travels with
    /// it because a reading is only interpretable against the seating of the epoch it was taken in.
    sensed: Option<(Epoch, u8, u8)>,
    /// The closed epochs whose seeds this node still holds, newest last — the reputation window. Beside
    /// `closed` rather than derived from it because the two are different lengths on purpose: the setpoint
    /// reads one closed epoch (the load directory's whole retention), the reputation reads `REP_WINDOW`.
    window: &'a [(Epoch, BeaconSeed)],
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
    peers: impl Fn() -> usize + Send + 'static,
    // See `assign_epoch`: `Some` exactly where a roster record must prove the coordinate it sits at.
    prover: Option<CoordinateProver>,
) -> (JoinHandle<()>, watch::Receiver<Assignment>) {
    let (roles_tx, roles_rx) = watch::channel(Assignment::NONE);
    // Supervised (#251): `Node::assigned` reads this watch, so a dead controller leaves the node reporting
    // roles it is no longer maintaining and the cell counting it as covering them.
    let supervised = client.clone();
    let handle = tokio::spawn(async move {
        let mut live = LiveRoleController::new(node_id, controller);
        let mut events = client.subscribe();
        let mut beacons = client.beacons();
        let mut cur = Epoch::ZERO;
        let mut seed = client.genesis();
        let mut closed = ClosedEpoch { epoch: Epoch::ZERO, seed };
        // What this node currently senses about its cell, on a `watch` rather than read off this loop's own
        // event arm.
        //
        // **It has to be latest-state, and the reason is measured.** This loop's `select!` re-derives the
        // assignment whenever the beacon is ahead, and a re-derivation costs up to one `STORE_TIMEOUT` of
        // directory reads; while it runs, the event arm is not polled. On a cell whose epoch period is shorter
        // than an assignment the epoch arm is therefore ready every time round and the event arm starves — in
        // the harness that found this, the whole run delivered TWO notifications to it, so a `sensed` folded
        // from the stream stayed `None` for ever and nothing was ever published. The same shape as #86: a
        // current *value* must not travel on a lossy event channel, because the consumer only needs the
        // newest and the channel's job is to deliver every one.
        let sensed_rx = spawn_liveness_watch(&client);
        // The closed epochs whose seeds this node still holds, newest last, capped at the reputation window —
        // a record is bound against the seed of the epoch it was PUBLISHED in, and the beacon watch keeps no
        // history, so this ring is the only place those seeds survive. Bounded by `REP_WINDOW` because the law
        // folds no more than that and a longer ring would retain seeds nothing can use.
        let mut window: std::collections::VecDeque<(Epoch, BeaconSeed)> = std::collections::VecDeque::new();
        genesis_assign::<F>(&client, &mut live, capacity, ready, prover.as_ref(), &roles_tx).await;
        // The refresh is a fixed-point iteration over the roster, so it is polled at a rate proportional to how fast it
        // is still moving: back off geometrically while the assignment is unchanged, snap back to the floor the moment
        // it moves. Converged cells therefore stop paying for it (a fixed 5 s scan forever is two cell-wide directory
        // reads per node per tick, indefinitely), while a cell that is still discovering — or has just lost a member —
        // is re-checked at the discovery timescale. Bounded above by ROSTER_REFRESH_MAX, below by ROSTER_REFRESH.
        let mut backoff = ROSTER_REFRESH;
        let mut settled = Assignment::NONE;
        let mut stable = 0u32;
        let mut refresh = tokio::time::interval(backoff);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        refresh.tick().await; // the first tick is immediate; the genesis assignment just ran
        loop {
            tokio::select! {
                // **The epoch is latest-state; a move is an event.** A missed `BeaconReady` on the lossy
                // notification stream meant this loop never assigned for that epoch at all — every node of
                // the cell running the previous epoch's assignment while the lottery had already
                // re-randomised, for a full period, with nothing to say so (#86). There is no "current move"
                // to converge on, so those stay on the stream below, where a dropped one costs a delayed
                // re-derivation rather than a skipped one.
                advanced = crate::next_epoch(&mut beacons, cur) => {
                    let Some((epoch, s)) = advanced else { break };
                    // The epoch being left is now final, and this is the only place its seed is still held —
                    // the beacon watch keeps no history. A multi-epoch jump leaves `closed` more than one
                    // behind, which `readable_for` then refuses; that is the intended outcome, since the
                    // skipped directory has expired.
                    closed = ClosedEpoch { epoch: cur, seed };
                    // The epoch just left joins the reputation window, in order, oldest evicted. Pushed here
                    // and nowhere else, for the same reason `closed` is: this is the last moment the seed
                    // exists anywhere in the process.
                    window.push_back((cur, seed));
                    while window.len() > REP_WINDOW as usize {
                        window.pop_front();
                    }
                    cur = epoch;
                    seed = s;
                    let ring: Vec<(Epoch, BeaconSeed)> = window.iter().copied().collect();
                    // Read out of the borrow before the await: a `watch` guard is not `Send`.
                    let sensed = *sensed_rx.borrow();
                    settled =
                        assign_epoch::<F>(&client, &mut live, AssignAt { epoch: cur, beacon: seed, closed, prover: prover.as_ref(), sensed, window: &ring }, capacity, &roles_tx)
                            .await;
                    // An epoch advance re-randomises the lottery, so the assignment is expected to move: re-arm the
                    // fallback at the floor rather than letting a stale backoff carry over into the new epoch.
                    stable = 0;
                    backoff = ROSTER_REFRESH;
                    refresh = tokio::time::interval_at(tokio::time::Instant::now() + backoff, backoff);
                    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                }
                event = events.recv() => match event {
                    // A coordinate moved — this node's own (`Reseated`) or a peer's (`PeerMoved`). Either changes the
                    // cell's composition, so the assignment is expected to move and the loop must re-derive at the FLOOR
                    // rather than on whatever backoff it had reached.
                    //
                    // Nothing else would prompt it. The loop's one signal for "my view is behind" is `roster < peers()`,
                    // and a peer moving changes the composition without changing the peer *count* — so that gate reads
                    // false and the node relaxes while its roster is short by the mover. Measured before this arm existed:
                    // `[4, 5, 3, 3, 4]` with all five points held, placement fully resolved, one reader caught up and the
                    // rest waiting out a backoff.
                    // This node moved (`Reseated`), or a peer we hold a connection to moved (`PeerMoved`). Either changes
                    // the cell's coordinate composition, so the assignment is *expected* to move and any relaxation this
                    // loop had reached should be undone.
                    //
                    // `MemberJoined` — a coordinate entering the membership view from a flooded `Announce`, which is the one
                    // signal that reaches a node that never met the mover — is **deliberately NOT here**, and that is a
                    // measured decision rather than an oversight. Adding it made convergence worse in both forms tried:
                    // scanning inline gave 0 of 3 (rosters collapsing to `[2, 2, 2, 4, 2]`), and re-arming the interval gave
                    // 1 of 4 (`[2, 2, 1, 3, 2]`). The reason is the one §5.3.5 already records: `MemberJoined` fires once per
                    // newly-learned member, so acting on it holds every node at the refresh floor throughout discovery, and
                    // the steady-state scan then competes with the critical path until a seven-node cell fails to converge
                    // at all. More scanning cannot be the fix when scanning is what starves convergence.
                    //
                    // So the residual stands, with a sharper shape: a node that never met a mover must end up with a correct
                    // roster **without** scanning more — the flood should update its view directly, rather than prompt it to
                    // go and look.
                    Ok(Notification::Reseated { .. } | Notification::PeerMoved { .. }) => {
                        // Undo relaxation only. Not inline (a scan costs up to one `STORE_TIMEOUT`), and not by re-arming
                        // at the floor when already there — a fresh `interval_at(now + backoff, …)` pushes the next tick a
                        // full period out, so "re-arm" would *delay* the soonest available look.
                        stable = 0;
                        if backoff > ROSTER_REFRESH {
                            backoff = ROSTER_REFRESH;
                            refresh = tokio::time::interval_at(tokio::time::Instant::now() + backoff, backoff);
                            refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                        }
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                // Re-assign at the *current* epoch as the roster fills in. Without this the loop's only trigger is a
                // beacon advance, so a cell whose beacon has stalled — or has not started — keeps the provisional
                // genesis assignment forever. Measured: rosters frozen at [1, 1, 2] for 60 s on a perfect carrier,
                // epoch never leaving 0 (`docs/design-testing.md` §5.3).
                //
                // Determinism survives because the inputs are still agreed: same epoch, same beacon, and a roster that
                // only converges *upward* toward the true live set. Two nodes that have discovered the same members
                // compute the same assignment, exactly as on a beacon advance — the refresh adds no new randomness, it
                // just stops the cell being stuck with a startup-race view of itself.
                _ = refresh.tick() => {
                    let ring: Vec<(Epoch, BeaconSeed)> = window.iter().copied().collect();
                    let sensed = *sensed_rx.borrow();
                    let now =
                        assign_epoch::<F>(&client, &mut live, AssignAt { epoch: cur, beacon: seed, closed, prover: prover.as_ref(), sensed, window: &ring }, capacity, &roles_tx)
                            .await;
                    if now.same_as(&settled) {
                        stable = next_stable(stable, true, now.complete);
                        // Local stability is *not* evidence of the global fixed point, and conflating the two is the
                        // same error one level up. A solitary assignment is the one value that cannot distinguish "the
                        // cell really is just me" from "I have not discovered anyone yet" — so a node holding one has no
                        // grounds to relax, however many identical samples it has seen. Measured with this gate absent:
                        // a fleet reached [1, 1, 2], one node backed off 5→10→20→40 s while still at a roster of one,
                        // and the cell then sat at [2, 1, 2] indefinitely (`docs/design-testing.md` §5.3.2).
                        // The refresh exists to close one specific gap: the directory-derived roster lagging true
                        // membership. The transport's own peer table is a *lower bound* on that membership which owes
                        // nothing to the overlay store, so the gap is directly observable — and when it is not observed,
                        // there is no evidence of work to do.
                        //
                        //   roster <  peers()  → the directory view is demonstrably BEHIND the transport view. Positive
                        //                        evidence of incompleteness: stay at the floor and keep looking.
                        //   otherwise          → no observable gap. Relax; a beacon advance or a peer appearing will
                        //                        bring the loop back to the floor on its own.
                        //
                        // This replaced a `!is_solitary()` special case, which only covered the roster == 1 instance of
                        // the same condition. Measured consequence of relaxing too little: the refresh's steady-state
                        // scan competes with the node's critical path, and under machine contention a seven-node
                        // real-QUIC consensus cell then fails to converge *at all* — not slowly, at any ceiling
                        // (`docs/design-testing.md` §5.3.5). Steady-state cost must be zero, not a trickle.
                        // A repeat is only evidence when the reads behind it CONCLUDED. A scan whose members timed out
                        // understates the roster in exactly the way a genuine absence does, so two partial scans agree with
                        // each other while both disagree with the cell — and relaxing on that agreement is what left a
                        // frozen roster with nothing to indicate why. `complete` is the distinction that was missing.
                        if may_relax(stable, now.roster, peers(), now.complete) {
                            backoff = (backoff * 2).min(ROSTER_REFRESH_MAX);
                        }
                    } else {
                        settled = now;
                        stable = next_stable(stable, false, now.complete);
                        backoff = ROSTER_REFRESH;
                    }
                    refresh = tokio::time::interval_at(tokio::time::Instant::now() + backoff, backoff);
                    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                }
            }
        }
    });
    (crate::supervise::supervise(crate::supervise::NodeActor::RoleController, &supervised, handle), roles_rx)
}

/// How often the role loop re-assigns at the **current** epoch, so a roster that was incomplete at startup converges.
///
/// The loop's only other trigger is a beacon advance. That is insufficient on its own: role assignment is a
/// *homeostatic* function, and tying it exclusively to the beacon freezes it precisely when a cell most needs to
/// adapt — a stalled beacon (audit §4 R-C1's whole subject) would otherwise pin every node to whatever partial view
/// its startup race produced.
///
/// The period is **derived from the work it schedules**, not chosen: one assignment costs up to one
/// `STORE_TIMEOUT` (the two directory scans run concurrently), so a 3× period bounds the refresh at a **1/3 duty
/// cycle**. Anything near 1× and the scans overlap — the node is then permanently scanning the cell, which measurably
/// destabilised timing-sensitive real-socket tests running alongside it and would be a traffic beacon in production.
pub const ROSTER_REFRESH: Duration = Duration::from_secs(3 * crate::resolve::STORE_TIMEOUT.as_secs());

/// The ceiling the refresh backs off to, **derived** as one [`DEFAULT_EPOCH_PERIOD`](crate::config::DEFAULT_EPOCH_PERIOD).
///
/// Past one epoch the refresh has no work left that the beacon path would not do anyway: a live beacon re-assigns on
/// advance, so the refresh is *strictly* the fallback for a beacon that has stalled. Capping there keeps the fallback's
/// worst-case detection latency equal to the guarantee the beacon path already offers, at a cost that decays to nothing.
const ROSTER_REFRESH_MAX: Duration = crate::config::DEFAULT_EPOCH_PERIOD;

/// Consecutive unchanged assignments required before the refresh cadence is allowed to relax.
///
/// One sample cannot tell a *converged* iteration from one that has **not started moving yet** — and conflating them is
/// not a cosmetic error: backing off during discovery delays the agreement the refresh exists to reach. Measured with
/// naive one-sample backoff, a fleet that converges at 15 s on an idle machine failed to converge inside 60 s under
/// concurrent load, because the cadence relaxed 5→10→20→40 s while the roster was still filling underneath it.
///
/// Detecting a fixed point needs at least two identical successive iterates; a third is margin against a transient that
/// happens to repeat. Below this count the cadence stays pinned at [`ROSTER_REFRESH`], so discovery is never slowed.
const STABLE_BEFORE_BACKOFF: u32 = 3;

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
/// costs a full cell-wide scan bounded by [`STORE_TIMEOUT`](crate::resolve), so a retry loop cannot converge
/// promptly, and a node's first epoch would silently serve nothing.
async fn genesis_assign<F: Field>(
    client: &Client,
    live: &mut LiveRoleController,
    capacity: Demand,
    ready: (oneshot::Receiver<()>, oneshot::Receiver<()>),
    // See `assign_epoch`: `Some` exactly where a roster record must prove the coordinate it sits at.
    prover: Option<&CoordinateProver>,
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
    // The roster is read at epoch 0 against this network's genesis seed: the records it must verify were
    // published against that seed, so the constant would reject every one of them.
    //
    // Epoch zero is the one epoch with no closed predecessor, so the setpoint here is a live read — declared
    // as such rather than hidden, and corrected at the first beacon advance.
    let closed = ClosedEpoch { epoch: Epoch::ZERO, seed: client.genesis() };
    // No sensed reading and no closed epochs yet: at genesis this node has not run a heartbeat's diagnosis
    // and there is no earlier epoch to have closed, so it publishes nothing and keeps its fresh reputation —
    // which is the same value a recompute over an empty record set would give.
    let at = AssignAt {
        epoch: Epoch::ZERO,
        beacon: client.genesis(),
        closed,
        prover,
        sensed: None,
        window: &[],
    };
    assign_epoch::<F>(client, live, at, capacity, roles_tx).await;
}

/// One epoch of the loop: read the live authenticated capability directory *and* the cell-agreed setpoint (from
/// the live load directory), step the controller, publish this node's roles. `send` only fails if every
/// receiver has dropped (the node is shutting down) — ignored.
/// How many consecutive **complete** repeats of the assignment this node has now seen — the evidence half, kept apart from
/// the retry cadence ([`may_relax`]).
///
/// Three cases, and the middle one is the whole reason this is a named function rather than an inline `+= 1`:
///
/// * the answer **changed** ⇒ 0. Whatever was accumulating is void.
/// * the scan was **incomplete** ⇒ unchanged. Two partial views agreeing with each other say nothing about the cell, so
///   this must not accumulate — but neither should it destroy evidence gathered when the reads *did* conclude.
/// * a **complete repeat** ⇒ one more. The only case that is evidence of anything.
///
/// Extracted because the property "a node that cannot read never comes to believe its assignment is settled" had no guard:
/// reintroducing the defect (accumulate on any repeat) left all 101 tests green.
const fn next_stable(stable: u32, repeated: bool, complete: bool) -> u32 {
    if !complete {
        stable
    } else if repeated {
        stable.saturating_add(1)
    } else {
        0
    }
}

/// Whether the refresh may lengthen its period — i.e. whether looking again *soon* would be wasted effort.
///
/// This is deliberately **not** the same question as "is the assignment settled", and conflating the two is what the
/// `complete` flag exposed. There are two unrelated reasons a node has nothing useful to gain from scanning sooner:
///
/// * **It is settled.** `stable >= STABLE_BEFORE_BACKOFF` (one identical answer is not a pattern) *and* `roster >= peers`
///   — the transport's peer table is a lower bound the overlay store owes nothing to, so a roster below it is
///   *demonstrably* behind (`docs/design-testing.md` §5.3.2, measured as a cell stuck at `[2, 1, 2]`).
/// * **It cannot read.** `!complete`: the scan's reads timed out. Scanning *harder* cannot fix a store that is not
///   answering, and it adds exactly the load that stopped it answering — §5.3.5 measured a seven-node cell failing to
///   converge at all under that regime. An inconclusive read is a congestion signal, and the response to congestion is to
///   retry less often, not more.
///
/// The soundness half lives at the call site rather than here: `stable` only accumulates on a **complete** repeat, so a
/// node that cannot read never comes to *believe* its assignment is settled, however long it backs off. It slows down
/// without deciding anything — and recovers on its own, since the first complete scan that finds more members changes the
/// assignment and resets the period to the floor.
const fn may_relax(stable: u32, roster: usize, peers: usize, complete: bool) -> bool {
    !complete || (stable >= STABLE_BEFORE_BACKOFF && roster >= peers)
}

/// The setpoint to step toward this epoch: the freshly-read one when the scan concluded, else the demand
/// already held.
///
/// **A partial read may hold the demand; it may never move it.** `Read::Unknown` is documented as "not a
/// negative, and not evidence of anything", and `build_cell_setpoint`'s own doc says a member whose report did
/// not resolve "contributes zero exactly as a genuine absence does, so the setpoint is *understated* by a
/// partial read". Both were true and the caller stepped the controller on that understated value anyway — so a
/// timed-out read looked exactly like a member reporting no demand, the role shrank, and the next epoch's
/// successful read grew it back. Pure measurement noise driving role churn, which is churn in the anonymity
/// set, and with κ = 1 the assignment tracks it in a single step.
///
/// Safe on a small or bootstrapping cell precisely because the read is three-valued: an empty coordinate is a
/// definite `Absent` and does not count as unknown, so a solitary node's six empty slots still read *complete*
/// and the demand is free to move. Holding would otherwise freeze a young cell at zero for ever — which is what
/// makes the two-valued version of this rule a bug and the three-valued one a fix.
///
/// The viability floor rides with the fresh branch, where the supply it must be conditioned on was just read;
/// a held setpoint already carries the floor applied when it was last set.
///
/// **There is a third case, and it is the one that shipped broken (#250): nothing has ever been agreed.**
/// The safety argument above is "hold what the cell agreed", and it silently assumes such a value exists. It
/// does not at genesis, where `held` is `Demand::default()` — the *absence* of a setpoint written as a number.
/// Holding that is not conservative, it is a claim the cell never made, and it is self-sustaining: a demand of
/// zero assigns no roles, and a cell with no roles publishes no load, so the next scan has nothing to conclude
/// with either. Measured: five nodes, a 20 ms link, every genesis load scan timing out, and all five holding
/// zero for a full minute — the freeze this doc calls "what makes the two-valued version of this rule a bug",
/// arrived at from the other side. The paragraph above rules it out for *empty* slots, which read as a definite
/// `Absent`; it does not rule it out for slots whose read never returned.
///
/// So when there is nothing to hold, the understated read is floored instead. That is not a fallback invented
/// here — the viability floor is exactly the mechanism for "this cell must be able to function", it is
/// conditioned on the supply just read, and applying it to a zero read yields the geometry's own minimum
/// (`line_threshold` for a threshold-line role, one for a self-gated one) rather than nothing at all. The
/// churn argument does not apply either: there is no prior value to churn away from.
///
/// Returns the arm taken alongside the demand, because a non-conclusion that nothing reports is how this cost
/// a minute of silence across five nodes.
///
/// **`held` is a published setpoint, not an accumulator, and that is what makes holding safe.** Two nodes
/// holding different ones — one read epoch `e − 1`, the other's scan timed out and it still holds `e − 2` —
/// disagree only until both complete a scan of the same closed epoch. Nothing compounds, because the demand
/// is recomputed from the floor every epoch rather than stepped from where it was. Under the carried demand
/// this same fallback was the one path by which a momentary read failure became permanent.
fn setpoint_to_track(
    read: Demand,
    complete: bool,
    held: Option<Demand>,
    supply: Demand,
    line_size: usize,
) -> (Demand, Option<crate::SetpointHold>) {
    match (complete, held) {
        (true, _) => (read.with_viability_floor(supply, line_size), None),
        (false, Some(agreed)) => (agreed, Some(crate::SetpointHold::Held)),
        (false, None) => (
            read.with_viability_floor(supply, line_size),
            Some(crate::SetpointHold::Floored),
        ),
    }
}

/// The node's **latest** cell reading, on a `watch` — `(degraded, responsive)` from the heartbeat's
/// `Notification::Liveness`, or `None` until the first one lands.
///
/// A task of its own, doing nothing but forwarding, for one reason: the role loop cannot afford to be the
/// consumer. Its `select!` spends up to a `STORE_TIMEOUT` inside each re-derivation, and on a cell whose epoch
/// period is shorter than that the epoch arm is ready every time round, so the event arm is polled almost
/// never — measured at **two** notifications delivered across a whole run, with the reading consequently never
/// set and no diagnosis ever published. A dedicated forwarder is always at its `recv`, and a `watch` keeps only
/// the newest value, which is exactly what a *current reading* means. Ends when the notification stream closes.
#[must_use]
fn spawn_liveness_watch(client: &Client) -> watch::Receiver<Option<(Epoch, u8, u8)>> {
    let (tx, rx) = watch::channel(None);
    let mut events = client.subscribe();
    // Supervised (#251): the controller reads this watch every epoch, and a dead watcher freezes it — the
    // controller then keeps deciding against a snapshot of the cell that stopped advancing.
    let supervised = client.clone();
    let task = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(Notification::Liveness { epoch, degraded, responsive, .. }) => {
                    // A send with no receivers is not an error here: the role loop holding the only receiver
                    // has ended, and this task ends with it on the next stream close.
                    let _ = tx.send(Some((epoch, degraded, responsive)));
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    crate::supervise::supervise(crate::supervise::NodeActor::LivenessWatch, &supervised, task);
    rx
}

/// Publish this node's view of `epoch`, then recompute the reputation from the closed `window` — the two
/// halves of "a cell-wide decision reads closed published epochs, never this node's live measurement".
///
/// ## The publish
///
/// `sensed` is the `(degraded, responsive)` pair the engine raises every heartbeat, and `seating` is who sat
/// where in `epoch` as the capability scan just found them. A record is written for the epoch it is measured
/// in, at the coordinate held during it, bound against its own seed — the same discipline as the load report,
/// and for the same reason: a record published for an epoch this node has already left names a coordinate it
/// no longer occupies, so no reader can verify it.
///
/// Skipped when the capability scan was incomplete. A partial seating names fewer seats than the cell has, and
/// the empty ones are indistinguishable from "nobody there" to every reader — so an incomplete scan would
/// publish a *claim* that members were absent, which is the accusation this whole mechanism exists to make
/// carefully.
///
/// ## The recompute, and why the window must be full
///
/// [`Reputation::from_published`] is a pure function of the record set, so two nodes reading the same closed
/// epochs get the same score however their local views differed. That only holds if they read the SAME
/// epochs: a node folding a shorter window sees fewer accusations and weights a bad node higher, which forks
/// the assignment exactly as the carried accumulator did. So the score is adopted only from a window that is
/// both **full width** (`REP_WINDOW` closed epochs) and **completely read** — otherwise the previous score
/// stands.
///
/// **The residual this leaves, stated rather than hidden.** A node that booted mid-run holds fewer than
/// `REP_WINDOW` past seeds, cannot verify those epochs' bindings, and therefore holds a neutral reputation
/// while its established peers hold a recomputed one. The two disagree for at most `REP_WINDOW` epochs and
/// then converge for good, and the disagreement is bounded by what reputation can do (it only ever *reduces*
/// a weight, from the full standing a fresh score already gives). It is the same trade `ClosedEpoch::readable_for`
/// already makes at width one for the setpoint. Removing it needs the epoch seeds to be recoverable by a node
/// that was absent, which is a beacon-history question, not a role-loop one.
async fn refresh_reputation<F: Field>(
    client: &Client,
    live: &mut LiveRoleController,
    at: AssignAt<'_>,
    seating: &Seating,
    seating_complete: bool,
) {
    let AssignAt { epoch, beacon, prover, sensed, window, .. } = at;
    // Publish only a reading taken in the epoch being published for, against the seating of that same epoch.
    // A reading from an earlier epoch was measured at an earlier *seating* — the node itself sat elsewhere —
    // so pairing it with today's roster attributes every bit to the wrong node. Skipping is the honest
    // outcome: the next heartbeat produces a current one, and an epoch with no record is an epoch with no
    // evidence, which the quorum already handles.
    //
    // And only when this node's own IDENTITY is in that seating. `seating_complete` means no read timed out,
    // not that anyone answered: on an epoch turn the capability publisher and this loop are separate tasks, so
    // the roster is read before this node's advertisement for the epoch has landed. A record that cannot name
    // its own author is weak evidence — every bit it carries about itself maps to an empty seat and is
    // silently discarded — so the honest rule is not to testify about an epoch whose roster this node has not
    // yet joined. It costs one epoch of evidence; the next refresh supplies another.
    //
    // **By identity, not by `client.address()`.** The first draft asked whether this node's *current* point
    // was occupied, and it was wrong for the reason this whole task is about: the advertisement sits at the
    // coordinate held when it was published, and a reseat moves the node away from it within the epoch. That
    // draft was false on essentially every assignment, and reading the seat number instead of the name is
    // exactly the confusion `DiagnosisRecord::roster` exists to remove.
    let seated_here = seating.iter().flatten().any(|id| *id == live.node_id());
    if let (Some((sensed_at, degraded, responsive)), true) = (sensed, seating_complete && seated_here)
        && sensed_at == epoch
    {
        // Proven per write, never once at spawn: the credential names an epoch, so one made at startup would
        // verify only in the epoch it was made — the same reason every other publisher re-proves.
        let credential = prover.map(|prove| prove(epoch, &beacon));
        publish_diagnosis(
            client,
            client.address(),
            epoch,
            degraded,
            responsive,
            seating,
            credential.as_ref(),
        )
        .await;
    }
    if window.len() < REP_WINDOW as usize {
        return; // not yet a window every node can be reading the same way
    }
    let (records, window_view) = read_diagnosis_window::<F>(client, window, prover.is_some()).await;
    if !window_view.complete() {
        return; // a partial read is a per-node record set, which is the divergence being removed
    }
    let Some(latest) = window.iter().map(|(e, _)| e.get()).max() else {
        return;
    };
    // The **corroboration quorum**, not a local choice: a diagnosis record is a claim about others, and the
    // liveness layer already asks the same question with the same answer (`f + 1` at Fano). Reading it from
    // the geometry rather than restating it means the two can never drift apart.
    let quorum = fanos_runtime::corroboration_quorum(Plane::<F>::N as usize);
    live.adopt_reputation(Reputation::from_published(&records, latest, quorum));
}

/// Recompute and publish the assignment for `epoch`, reporting whether the directory reads it rests on were **complete**.
///
/// The second value is the one that was missing. A read that timed out was indistinguishable from a member that published
/// nothing, so an assignment computed over a partial view looked exactly like one computed over the whole cell — and two
/// such in a row read as "settled", which grew the refresh backoff and left the cell frozen short of its own membership.
/// Only a *complete* view is evidence of anything.
async fn assign_epoch<F: Field>(
    client: &Client,
    live: &mut LiveRoleController,
    at: AssignAt<'_>,
    capacity: Demand,
    roles_tx: &watch::Sender<Assignment>,
) -> Assignment {
    let vrf = at.prover.is_some();
    // The two directories are independent reads, so they are scanned concurrently rather than back to back: an
    // assignment's worst-case latency is one STORE_TIMEOUT, not two. That halving is what lets the refresh period
    // below stay short enough to converge while keeping its duty cycle bounded.
    let AssignAt { epoch, beacon, closed, .. } = at;
    let ((members, seating, caps_view), (setpoint, load_view)) = tokio::join!(
        build_capability_directory::<F>(client, epoch, vrf.then_some(beacon)),
        async {
            match closed.readable_for(epoch) {
                // Verified against the seed of the epoch the records were PUBLISHED in, not the current one:
                // a credential names its epoch, so the live seed rejects every closed record.
                Some((e, s)) => build_cell_setpoint::<F>(client, e, capacity, vrf.then_some(s)).await,
                // No readable closed epoch, so no scan ran at all. The shortfall is the whole cell — every
                // slot this scan would have read, none of which concluded — which is the honest count and
                // not a stand-in: `Coverage` has no `Default` precisely so that "nothing resolved" cannot be
                // written as a zero that reads as "everything did". The `Demand` beside it is unused, as the
                // caller holds on an incomplete view.
                None => (Demand::default(), Coverage { unresolved: Plane::<F>::N as usize }),
            }
        }
    );
    // Publish what this node sensed about the epoch it is IN, against the seating it just read, and recompute
    // the reputation from the closed window. Both are here rather than in a publisher task of their own for
    // one reason: the record's roster must be the seating the assignment used, and this is the only place
    // that holds it. A second reader would produce a second seating and the two could disagree.
    refresh_reputation::<F>(client, live, at, &seating, caps_view.complete()).await;
    // The plane's own line size, so the threshold-line roles are floored at `t`-of-`(q+1)` for THIS plane
    // rather than at the base cell's three — the ceiling-computed-on-Fano defect (#122), one subsystem over.
    let (setpoint, hold) = setpoint_to_track(
        setpoint,
        load_view.complete(),
        live.last_agreed(),
        Demand::supply(&members),
        Plane::<F>::LINE_SIZE as usize,
    );
    // A demand that did not advance is a decision, and an unreported decision is how #250 stayed invisible for
    // a minute across five nodes: the roster kept moving, the assignments kept being published, and every one
    // of them was computed from a setpoint nobody had agreed to.
    if let Some(hold) = hold {
        client.record_station(
            fanos_runtime::ports::stations::Station::SetpointHeld,
            Some(client.address()),
            Some(hold.tag()),
        );
    }
    // **A node that is not in the roster it just read may not speak for the cell** (#146).
    //
    // A capability record lives at `cap_slot(coord, epoch)`, so at the instant an epoch opens every slot is
    // empty until each node republishes for it — locally one write, for a peer a round trip. The loop wakes on
    // the same `BeaconReady` and reads that directory, and `caps_complete` says **true**, because an absent
    // record is a *definite* absence (deliberately, so one forged record cannot void a scan). "Complete" means
    // "no read timed out", never "the cell answered". So without this guard the loop assigns over an empty
    // roster, `assign_report` returns nothing for this node, and the `watch` every actuator reads goes to
    // `RoleSet::EMPTY` until the next within-epoch refresh.
    //
    // **Measured, on a three-node cell over real QUIC** (`tests/role_roster.rs`): a node published a roster of
    // 0 while its own address book held 2 peers. Every node turns at the same instant, so a threshold role's
    // line drops below `t` cell-wide together — and it is invisible, because the reads all "concluded".
    //
    // The predicate is self-referential on purpose, and it is the same one the diagnosis publish uses one
    // function over: **can I find my own advertisement for this epoch?** It needs no peer count and cannot
    // false-positive — a node whose own local write is not yet visible has definitely read a directory that
    // does not exist yet — while `members.len() < peers()` would hold forever on a cell where some peer
    // legitimately never publishes a capability. Genesis is unaffected: `genesis_assign` waits on
    // `capability_ready` before it assigns at all.
    //
    // Holding means: publish nothing, step nothing, and report **incomplete** — which is already the signal
    // that keeps the refresh at its floor, so the next look comes soon rather than after a backoff.
    if !members.iter().any(|(id, _)| *id == live.node_id()) {
        return withhold(client, roles_tx, members.len());
    }
    // **`members.len() < peers()` is deliberately NOT a second hold condition, and that was a close call.**
    //
    // It is tempting: the loop already uses that comparison to decide whether to keep *looking*, so using it
    // to decide whether to *speak* looks like the same evidence one step earlier. It is not. `peers()` is the
    // address book, which holds every coordinate this node has merely *heard of* through flooded announces —
    // including nodes that offer no roles and will never publish a capability at all. A roster smaller than
    // it is therefore not evidence that the directory is behind, and a hold on that condition would freeze
    // the assignment for as long as such a peer is known. Bounding the hold to once per epoch was tried, and
    // an ad-hoc bound to contain a condition that should not have fired is the wrong shape.
    //
    // What motivated it was a sampled `(roster 1, peers 2)`, and that reading does not support it either:
    // the roster was computed inside this function at one instant and the peer count read from outside at a
    // later one, so the address book had grown in between. The sound version of that measurement is taken
    // *here*, where both values are read together, and it has not been taken. See #151.
    // The completeness the caller already computed travels WITH the count it qualifies, instead of being
    // consumed for backoff and then dropped (#289).
    //
    // Reduced to a bool HERE rather than carried further: both consumers below can only branch on it, and a
    // count handed to something that can only branch is the mirror of the defect #291 fixed — a number that
    // reaches no reader. The builders carry `Coverage` because the information exists there; each consumer
    // reduces it at its own decision, and the one that *reports* (`bin/fanos.rs`) is the one that does not.
    let settled = caps_view.complete() && load_view.complete();
    let roles = live.step(&members, epoch, &beacon, setpoint, settled);
    note_deficit(client, epoch, live.deficit());
    let _ = roles_tx.send(roles);
    // The `Assignment` alone: it already carries `complete` (#289), and returning the bool beside it made one
    // quantity travel under two names — which is how the comparison above came to fold it in (#293).
    roles
}

/// Keep the previously published assignment, and **say so**: the same value, `complete = false`, and one
/// [`AssignmentWithheld`](fanos_runtime::ports::stations::Station::AssignmentWithheld) tagged with the roster
/// the scan produced.
///
/// The station is not decoration. Holding is a *deliberate non-action*, and a loop that silently keeps
/// returning the same answer is indistinguishable from a converged one — the exact ambiguity the
/// `complete`/`repeated` split in `next_stable` exists to remove one level up. It is also the only
/// deterministic observable of this mechanism: the window it guards is tens of milliseconds on loopback, so a
/// test sampling the published assignment catches it by luck, while the counter is exact.
///
/// `complete = false` rather than `true` because that is already the signal that keeps the refresh at its
/// floor — a withheld assignment must be re-derived soon, not backed off from.
fn withhold(
    client: &Client,
    roles_tx: &watch::Sender<Assignment>,
    roster: usize,
) -> Assignment {
    client.record_station(
        fanos_runtime::ports::stations::Station::AssignmentWithheld,
        Some(client.address()),
        Some(roster as u64),
    );
    // `complete: false` ON the assignment, not beside it. It used to be `(*roles_tx.borrow(), false)` — the
    // doc above promised "the same value, `complete = false`" and delivered it in the tuple element the
    // callers discarded, while the `Assignment` itself kept whatever completeness the last published one had.
    // The two halves of one return actively disagreed (#293).
    Assignment { complete: false, ..*roles_tx.borrow() }
}

/// Record a provisioning shortfall where an operator will see it — one
/// [`RoleUnderProvisioned`](fanos_runtime::ports::stations::Station::RoleUnderProvisioned) per role that came
/// up short, tagged with the role.
///
/// **The counterpart to `note_publish`, and installed for the same reason.** A deficit was computed on every
/// assignment and dropped on every assignment, so a cell that could not staff a role looked exactly like one
/// that could. What changed is that the number is now true: under the placeholder capacity every active cell
/// ran a permanent fabricated deficit, and a station firing on every epoch is not a signal.
///
/// Per role rather than aggregated, because the consequence is not the same everywhere — one relay short is a
/// throughput matter, while one point short on a rendezvous line means the `t`-of-`(q+1)` guarantee that role
/// exists to provide is not being met at all. One count cannot say which.
///
/// This is the **local** signal. Escalating to the parent cell, which `docs/design-roles.md` describes, needs
/// the hierarchy path and is deliberately not invented here: a half-wired escalation would be worse than a
/// stated gap.
fn note_deficit(client: &Client, epoch: Epoch, deficit: Demand) {
    for role in Role::ALL {
        let short = deficit.of(role);
        // A shortfall is only evidence where the denominator is. Relay and Ingress still divide by the
        // placeholder, so their demand exceeds supply on any active cell by construction — reporting that
        // would put a permanent warning in front of an operator and teach them to ignore the station, which
        // is worse than the silence this replaced. `the_last_two_capacities_and_the_parent_escalation_are_
        // still_open` is the tripwire that says so when they gain a real capacity.
        if short == 0 || !capacity_is_derived(role) {
            continue;
        }
        client.record_station(
            fanos_runtime::ports::stations::Station::RoleUnderProvisioned,
            Some(client.address()),
            Some(role.index() as u64),
        );
        tracing::warn!(
            role = ?role,
            short,
            epoch = ?epoch,
            "the cell wants more nodes in this role than any member offered"
        );
    }
}

/// Whether the role controller is still deciding, or the assignment a reader takes is **frozen** (#251).
///
/// [`SelfOrganization::assigned`] is a level: a value a reader polls, maintained by exactly one task. When
/// that task dies the level does not go absent — `borrow()` keeps returning whatever it last said, which on a
/// working node is a *healthy* assignment. So the node goes on reporting roles it has stopped being told to
/// hold, the cell counts them covered, and every surface agrees. The upgrade from silence to a level is what
/// created that: an absent signal a reader can detect became a confident wrong one.
///
/// One mechanism covers both ways the controller can end, which is why there is no orderly-exit message to
/// send: the `watch::Sender` is owned by the role-loop task alone, so a panic, a cancellation and a clean
/// return all drop it, and `has_changed()` answers `Err` from then on.
///
/// Two states, not three: unlike [`crate::durable::Durability`] there is no *not configured* case — every
/// node builds a `SelfOrganization`, because a node that offers nothing still has to be told it was assigned
/// nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RoleStanding {
    /// The controller is running, so the assignment is its current decision.
    Deciding,
    /// The controller has **stopped**. The assignment is frozen at its last value: this node still runs those
    /// role behaviours, but nothing is checking whether the cell still wants them there.
    Stopped,
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

impl SelfOrganization {
    /// Whether [`Self::assigned`] is still being decided — see [`RoleStanding`].
    ///
    /// `has_changed()` answers `Err` exactly when every sender is gone, and the only sender is inside the
    /// role-loop task. So this asks "is the writer alive?" rather than "has the value moved lately?", which
    /// matters because a correct assignment on a settled cell does not move for epochs at a time.
    #[must_use]
    pub fn standing(&self) -> RoleStanding {
        if self.assigned.has_changed().is_err() { RoleStanding::Stopped } else { RoleStanding::Deciding }
    }
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
    /// This node's coordinate prover, which **states the cell's coordinate regime** — see [`crate::bound`].
    ///
    /// `Some` ⇒ VRF-derived coordinates: the node publishes a capability advertisement bound to the coordinate it sits at,
    /// and its roster reads verify the same binding on everyone else's. `None` ⇒ a pinned cell, where no publisher can
    /// produce such a proof and no reader can check one.
    ///
    /// It is *this node's* prover but the *cell's* regime, and that is sound because the regime is a property of the
    /// deployment: every node in a cell is configured the same way, so "I can prove my coordinate" and "my peers can prove
    /// theirs" are the same fact. Obtained from [`fanos_quic::NodeHandle::coordinate_prover`].
    pub prover: Option<CoordinateProver>,
}

/// Spawn a node's **entire self-organizing subsystem** on plane `F` — the single call `Node::start` makes to
/// join the live role loop. It advertises the node's offered capability, reports its observed load
/// (`load_source`), and runs its role loop, so the cell assigns and rotates the node's roles each epoch with no
/// further input. The caller actuates the returned [`SelfOrganization::assigned`] roles (starting/stopping each
/// behavior as the assignment changes). Must run inside a tokio runtime.
#[must_use]
pub fn spawn_self_organization<F: Field>(
    client: Client,
    config: SelfOrgConfig,
    load_source: impl Fn() -> Demand + Send + 'static,
    peers: impl Fn() -> usize + Send + 'static,
) -> SelfOrganization {
    let SelfOrgConfig { node_id, vrf_secret, capability, capacity, controller, prover } = config;
    let (capability_publisher, capability_ready) =
        spawn_capability_publisher(client.clone(), node_id, vrf_secret, capability, prover.clone());
    let (load_publisher, load_ready) = spawn_load_publisher(client.clone(), load_source, prover.clone());
    let (role_loop, assigned) =
        spawn_role_loop::<F>(client, node_id, controller, capacity, (capability_ready, load_ready), peers, prover);
    SelfOrganization { capability_publisher, load_publisher, role_loop, assigned }
}

#[cfg(test)]
mod tests {
    /// **A dead driver is not an idle driver (#258).**
    ///
    /// [`LoadGuard`]'s `Drop` releases each unit of work however the flow ends, which is right for a flow and
    /// creates the question for the role: when the *task* dies, all its guards fall and the slot reads
    /// `Some(0)` — "running, carrying nothing". That is the reading the controller rewards with more work, so
    /// a dead exit attracts exactly the traffic it cannot serve.
    ///
    /// Three cases, because the wrong fix is easy in two directions: absenting on an idle gauge would throw
    /// away the true reading of a role that legitimately went quiet, and absenting on the first clone's drop
    /// would unsense a driver that is still running through another.
    #[test]
    fn a_dropped_driver_unsenses_its_role_while_an_idle_one_stays_measured() {
        use super::{LoadSensor, Role};

        let (sensor, _feeding) = LoadSensor::new();
        let sensor = Arc::new(sensor);
        let gauge = sensor.gauge(Role::Exit);

        assert_eq!(
            sensor.reading().of(Role::Exit),
            Some(0),
            "an idle driver is measured at zero — unsensing it here is how a quiet exit loses its true reading"
        );

        let shared = gauge.clone();
        drop(gauge);
        assert_eq!(
            sensor.reading().of(Role::Exit),
            Some(0),
            "one clone going does not stop the role: every clone addresses the same slot, and another holds it"
        );

        let flow = shared.in_flight();
        drop(shared);
        assert_eq!(
            sensor.reading().of(Role::Exit),
            Some(1),
            "a flow still in flight IS the role being served, whatever became of the handle that started it"
        );

        drop(flow); // the last holder — the driver is gone
        assert_eq!(
            sensor.reading().of(Role::Exit),
            None,
            "with nothing left to run, the role is unsensed and the offer stands in — `Some(0)` here would \
             advertise a dead exit as an idle one, which is what the controller gives more work to"
        );
    }

    /// **A load reading with nobody feeding it reads absent, not stale — and only where that is true (#251).**
    ///
    /// The engine slots are a level with one writer. When the feeder dies they keep decoding to their last
    /// value, so this node publishes a measured-looking load that stopped tracking anything and the whole
    /// cell divides by it. Absent is the honest answer, and it is one the consumer already has a rule for:
    /// the offer stands in, which errs toward "this node is full" rather than toward piling work on it.
    ///
    /// The second half is what makes it a per-slot rule. Blanket-absenting on a dead feeder would erase a
    /// live gauge's reading — the exact failure `record` refuses a `None` to avoid, reintroduced one layer
    /// up. A gauge's writer is the role's own task and knows nothing about the feeder's fate.
    #[test]
    fn a_dead_feeder_absents_the_engine_slots_and_leaves_a_live_gauge_alone() {
        use super::{LoadSensor, Role};

        let (sensor, feeding) = LoadSensor::new();
        let sensor = Arc::new(sensor);
        sensor.record(RoleReading::blind().measuring(Role::Relay, 7));
        let gauge = sensor.gauge(Role::Exit);
        let _flow = gauge.in_flight();

        assert_eq!(sensor.reading().of(Role::Relay), Some(7), "a fed slot reads what was fed");
        assert_eq!(sensor.reading().of(Role::Exit), Some(1), "and the gauge reads what it carries");

        drop(feeding); // the feeder task is gone — panicked, cancelled, or simply ended

        assert_eq!(
            sensor.reading().of(Role::Relay),
            None,
            "with nobody feeding it, 7 is a fossil: reporting it makes the cell divide by a number that \
             stopped moving, and absent is the state the consumer already knows how to be careful about"
        );
        assert_eq!(
            sensor.reading().of(Role::Exit),
            Some(1),
            "the gauge's writer is the exit's own task, so the feeder's death says nothing about it — \
             absenting this too is the `record`-must-not-store-None defect, one layer up"
        );
    }

    /// **A role controller that died stops claiming it is deciding (#251).**
    ///
    /// The level's writer is one task. While it lives, `assigned` is the cell's current decision; when it
    /// dies, `borrow()` does not go absent — it keeps handing back the last decision, which on a working node
    /// is a perfectly healthy assignment. So the node reports roles nothing is maintaining, the cell counts
    /// them covered, and no epoch corrects it.
    ///
    /// Both directions, because a predicate that answered `Stopped` unconditionally would close the defect
    /// and make the reading useless — and because a `watch` with an unread value must still read `Deciding`:
    /// the question is whether the WRITER is alive, not whether the value moved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_role_controller_that_died_stops_claiming_it_is_deciding() {
        use super::{Assignment, Epoch, RoleSet, RoleStanding, SelfOrganization, watch};

        let (tx, rx) = watch::channel(Assignment::NONE);
        let org = SelfOrganization {
            capability_publisher: tokio::spawn(async {}),
            load_publisher: tokio::spawn(async {}),
            role_loop: tokio::spawn(async {}),
            assigned: rx,
        };
        assert_eq!(
            org.standing(),
            RoleStanding::Deciding,
            "a live controller must read as deciding, or the reading says nothing about anything"
        );

        // An unread new value is still a live controller — a settled cell reassigns nothing for epochs.
        let _ = tx.send(Assignment { roles: RoleSet::EMPTY, roster: 5, epoch: Epoch(1), complete: true });
        assert_eq!(org.standing(), RoleStanding::Deciding, "an unread update is not a dead writer");

        drop(tx); // what a panic, a cancellation and a clean return all do
        assert_eq!(
            org.standing(),
            RoleStanding::Stopped,
            "with its only writer gone the assignment is a fossil, and saying so is the whole point"
        );
        assert_eq!(
            *org.assigned.borrow(),
            Assignment { roles: RoleSet::EMPTY, roster: 5, epoch: Epoch(1), complete: true },
            "and the frozen value is STILL readable — that is exactly why it needs the state beside it"
        );
    }

    /// **A tripwire on a defect that is deliberately unfixed, because fixing half of it is worse than
    /// neither half.**
    ///
    /// `ROLE_CAPACITY_PER_NODE` is `1`, which reads an *event* count as a *node* count. **Storage is out of
    /// its scope as of 2026-08-04** — its capacity is now derived from `MAX_STORE_ENTRIES`, the bound the
    /// node's own admission rule enforces on the very number it reports — and **Rendezvous, Service and Exit
    /// followed it**, each from its own admission bound. Two roles still carry the placeholder, Relay and
    /// Ingress, for different reasons: Relay's sensor is a rate against a level, and Ingress has a bound with
    /// no sensor to divide. For those two, demand exceeds eligible supply on any active cell, `assign_report`
    /// fills `min(demand, eligible)`, every offering node gets the role it offered, and the controller
    /// expresses nothing about them.
    ///
    /// That residual saturation is **no longer harmless by accident, because the deficit is read**:
    /// `note_deficit` records `Station::RoleUnderProvisioned` from the epoch step, so for Relay and Ingress it
    /// reports a shortfall that is still an artefact of the denominator. What remains absent is the
    /// **parent-cell escalation** — `Escalation` has no `Deficit` variant — which is a hierarchy-transport
    /// gap, not an oversight.
    ///
    /// So the two must move together, and this test is one half of saying so; the other is
    /// `the_last_two_capacities_and_the_parent_escalation_are_still_open`, which fires when Relay and Ingress
    /// stop being placeholders — exactly when someone needs to be told about the escalation.
    #[test]
    fn storage_capacity_is_the_bound_the_node_actually_enforces() {
        // The one role whose capacity is derived rather than placed. Its load is `store.entries.len()`, so
        // its capacity is the bound the node's own admission rule enforces on that number — read from
        // `MAX_STORE_ENTRIES` rather than restated, because a copy would drift the moment the cap moved and
        // nothing would notice: the assignment would simply provision the wrong number of storage nodes.
        assert_eq!(
            usize::from(role_capacity().of(Role::Storage)),
            fanos_runtime::MAX_STORE_ENTRIES,
            "storage capacity must equal the store's own admission bound",
        );
        assert!(
            role_capacity().of(Role::Storage) > role_capacity().of(Role::Relay),
            "and it must actually differ from the placeholder the unmeasured roles still carry — if these \
             ever coincide, capacity has silently become one number again",
        );
    }

    /// Every derived capacity is **the bound its own subsystem enforces**, read from that subsystem rather
    /// than restated here.
    ///
    /// A copy would drift the instant a cap moved, and nothing would notice: the assignment would simply
    /// provision the wrong number of nodes for that role, which is not a failure any test asserts directly.
    /// So the assertion is an identity against the source of truth, and the *only* thing it pins is that the
    /// two remain the same number.
    #[test]
    fn each_derived_capacity_is_its_subsystems_own_admission_bound() {
        let cap = role_capacity();
        assert_eq!(
            usize::from(cap.of(Role::Rendezvous)),
            crate::rendezvous_relay::MAX_REGISTRATIONS + crate::rendezvous_relay::MAX_HOSTS,
            "the combiner reports registrations + hosts, so its capacity is the sum of those two caps"
        );
        assert_eq!(
            usize::from(cap.of(Role::Service)),
            crate::threshold_service::DEFAULT_MAX_PENDING,
            "the service reports intros being gathered, and refuses past max_pending"
        );
        assert_eq!(
            usize::from(cap.of(Role::Exit)),
            crate::diaulos::MAX_SESSIONS,
            "an exit reports flows in flight, and the session demux caps concurrent sessions"
        );

        // The two that are still placeholders, and the distinction between them is the point: each names what
        // it is waiting for. Collapsing them into "unmeasured" loses that.
        assert_eq!(
            cap.of(Role::Relay),
            ROLE_CAPACITY_PER_NODE,
            "relay's sensor is a RATE and every cap in reach is a level — it needs a throughput measurement"
        );
        assert_eq!(
            cap.of(Role::Ingress),
            ROLE_CAPACITY_PER_NODE,
            "ingress HAS a bound and no sensor — a denominator over a numerator nobody reports is not a ratio"
        );
    }

    /// A shortfall is reported only where the denominator that produced it is real.
    ///
    /// The two halves have to name the same roles: `role_capacity` decides which capacities are derived, and
    /// `note_deficit` decides which shortfalls reach an operator. If they drift, the node either warns every
    /// epoch about a number that is an artefact of the placeholder — teaching an operator to ignore the
    /// station, which is worse than the silence this replaced — or goes quiet about a real one.
    #[test]
    fn only_a_derived_capacity_may_report_a_shortfall() {
        let cap = role_capacity();
        for role in Role::ALL {
            let derived = cap.of(role) != ROLE_CAPACITY_PER_NODE;
            assert_eq!(
                capacity_is_derived(role),
                derived,
                "{role:?}: `capacity_is_derived` and the capacity vector disagree, so the deficit report is \
                 either noise or missing"
            );
        }
        // Named literally, so flipping the classification cannot move both sides together and pass.
        assert!(!capacity_is_derived(Role::Relay), "relay divides by the placeholder — its deficit is an artefact");
        assert!(!capacity_is_derived(Role::Ingress), "ingress has no sensor at all — same");
        assert!(capacity_is_derived(Role::Exit), "exit divides by MAX_SESSIONS, so its shortfall is real");
    }

    /// **A tripwire on the half of the capacity work that is still open.**
    ///
    /// Four roles now divide by their own admission bound. Two do not, for the two different reasons the test
    /// above pins, and while `ROLE_CAPACITY_PER_NODE` is still `1` those two saturate: their demand exceeds
    /// eligible supply on any active cell, so every offering node gets them and the controller expresses
    /// nothing about them.
    ///
    /// The second half — the one this exists to hand on — is that a real capacity makes
    /// `AssignReport::deficit` mean something. That is now recorded locally (`note_deficit` →
    /// `Station::RoleUnderProvisioned`), so a shortfall is no longer silently dropped. What is still absent is
    /// the **parent-cell escalation** `docs/design-roles.md` describes: a cell that cannot staff a role tells
    /// its operator and not its parent. That is a hierarchy-transport gap, deliberately not faked here.
    #[test]
    fn the_last_two_capacities_and_the_parent_escalation_are_still_open() {
        assert_eq!(
            ROLE_CAPACITY_PER_NODE, 1,
            "Relay and Ingress capacity are no longer the placeholder — good, but read this first.\n\
             \n\
             `1` reads an event count as a node count, so those two roles saturate the assignment and the\n\
             controller cannot express anything about them. Their deficits are therefore FABRICATED, and\n\
             `note_deficit` will be reporting a shortfall for them on every epoch.\n\
             \n\
             When you give them a real capacity, check that the reported deficit becomes true rather than\n\
             merely quieter — and note that the parent-cell escalation is still unwired, so a genuine\n\
             shortfall reaches an operator and no other cell."
        );
    }


    use super::*;
    use fanos_core::roles::{Capability, Role, RoleSet, cell_setpoint};
    use fanos_geometry::fano;

    /// The threshold floor a line of `m` points imposes, in `Demand`'s units — the same conversion
    /// `with_viability_floor` performs, so a test cannot pin a number the production path would not produce.
    fn line_floor(m: usize) -> u16 {
        u16::try_from(fanos_geometry::line_threshold(m)).unwrap_or(u16::MAX)
    }

    fn node(i: u8) -> NodeId {
        NodeId([i; 32])
    }

    #[test]
    fn a_read_that_did_not_conclude_holds_the_demand_instead_of_shrinking_it() {
        // The noise source that made the assignment flap. A member whose load slot timed out contributes zero
        // exactly as a genuine absence does, so the aggregate is understated — and the controller stepped on
        // it. With κ = 1 that is a one-step retirement of a role nobody stopped needing, undone the next epoch
        // by a read that happened to succeed. Churn in the anonymity set, driven by the measurement.
        let supply = Demand::per_role(|_| 3);
        let held = Demand::per_role(|r| if r == Role::Relay { 5 } else { 0 });
        let understated = Demand::default();

        assert_eq!(
            setpoint_to_track(understated, false, Some(held), supply, fano::LINE_SIZE),
            (held, Some(crate::SetpointHold::Held)),
            "a read that did not conclude is not evidence that demand fell — hold, and say so"
        );

        // A read that DID conclude moves the demand, including downward. That direction has to keep working:
        // believing a measured zero is the whole point of the sensor work, and a rule that never shrank a role
        // would trade one defect for its mirror image.
        let measured_zero = Demand::default();
        let (moved, reported) = setpoint_to_track(measured_zero, true, Some(held), supply, fano::LINE_SIZE);
        assert_eq!(moved.of(Role::Relay), 0, "a COMPLETE read of zero relay demand must shrink the role");
        assert_eq!(reported, None, "a scan that concluded is the normal case and must not raise a station");

        // …and the floor rides with the fresh branch. Rendezvous is floored at the LINE THRESHOLD, not at one:
        // its guarantee is `t`-of-`(q+1)` occupancy, so a single point is not a thin anonymity set but none.
        assert_eq!(
            moved.of(Role::Rendezvous),
            line_floor(fano::LINE_SIZE),
            "the freshly-read setpoint is floored, and for a threshold-line role the floor is t-of-(q+1)"
        );
        assert_eq!(moved.of(Role::Exit), 1, "a role that is merely self-gated keeps the observability floor of 1");

        // A young cell must not freeze. Its empty coordinates are definite absences, not unknowns, so the scan
        // reads complete and the demand is free to move from zero — which is what makes holding safe at all.
        let fresh = Demand::per_role(|r| if r == Role::Storage { 4 } else { 0 });
        assert_eq!(
            setpoint_to_track(fresh, true, None, supply, fano::LINE_SIZE).0.of(Role::Storage),
            4,
            "a bootstrapping cell whose reads conclude tracks its first real setpoint"
        );
    }

    /// **Nothing to hold is not a demand of zero** (#250).
    ///
    /// The third case, and the one that shipped broken. `held` was a `Demand`, so "the cell agreed on nothing
    /// yet" and "the cell agreed on nothing" were the same value — and the fallback held the second reading of
    /// it. On a 20 ms link every genesis load scan times out, so five nodes held a demand of zero for a full
    /// minute, assigned `RoleSet::EMPTY`, published no load, and thereby guaranteed the next scan had nothing
    /// to conclude with either. Self-sustaining, and silent.
    ///
    /// Falsified by reverting the arm to `held.unwrap_or_default()`: this test then reports a relay demand of
    /// 0 against the floor's 1, and a rendezvous demand of 0 against `t`.
    #[test]
    fn a_cell_that_has_agreed_nothing_yet_is_floored_rather_than_frozen_at_zero() {
        let supply = Demand::per_role(|_| 3);
        // What the timed-out scan produces: every member's slot unresolved, so the aggregate is a zero that is
        // not evidence of anything — exactly the value the two-valued fallback then held forever.
        let (tracked, reported) =
            setpoint_to_track(Demand::default(), false, None, supply, fano::LINE_SIZE);

        assert_eq!(
            reported,
            Some(crate::SetpointHold::Floored),
            "the arm an operator needs distinguished: this cell has never completed a cell-wide load read"
        );
        assert_eq!(
            tracked.of(Role::Rendezvous),
            line_floor(fano::LINE_SIZE),
            "a threshold-line role is floored at t-of-(q+1) — the geometry's own minimum, not zero"
        );
        assert_eq!(tracked.of(Role::Exit), 1, "a self-gated role keeps the floor of 1");

        // The floor is conditioned on supply, and that condition survives: a role nobody offers stays at zero
        // rather than being provisioned into existence by a scan that failed.
        let unoffered = Demand::per_role(|r| u16::from(r != Role::Rendezvous) * 3);
        assert_eq!(
            setpoint_to_track(Demand::default(), false, None, unoffered, fano::LINE_SIZE)
                .0
                .of(Role::Rendezvous),
            0,
            "flooring must not invent demand for a role the cell has no supply for"
        );
    }

    #[test]
    fn a_role_that_measured_no_demand_is_believed_and_one_with_no_sensor_falls_back() {
        // The defect this pins. `Notification::LoadReport` carried a bare `[u16; 5]`, so "this role has no
        // sensor" and "this role measured zero" were the same value, and the driver told them apart by
        // guessing: **any** zero was replaced by the node's own offer. That is right for a role nobody can see
        // and wrong for one that reported nothing to do — the controller could never learn demand had fallen to
        // zero, precisely when it should be shrinking the role. It bound the two roles that *are* measured,
        // relay and storage: a cell could not conclude "nobody here needs relays".
        let offered = RoleSet::of(&[Role::Relay, Role::Storage, Role::Service]);
        let cap = role_capacity();
        // The feeder's token, held for the test's lifetime: the TEST is the feeder here.
        let (sensor, _feeding) = LoadSensor::new();

        // Nothing reported yet is genuinely absent — the array's initial state must not read as `Some(0)`.
        assert_eq!(sensor.reading(), RoleReading::blind(), "an unreported sensor holds no reading");

        // Now a report: relay measured **zero**, storage measured work, service has no sensor at all.
        sensor.record(RoleReading::blind().measuring(Role::Relay, 0).measuring(Role::Storage, 5));
        let published = sensor.load(offered, cap);
        assert_eq!(published.of(Role::Relay), 0, "a measured idle relay publishes zero work");
        assert_eq!(published.of(Role::Storage), 5, "a measured load publishes as work units");
        assert_eq!(
            published.of(Role::Service),
            cap.of(Role::Service),
            "an unsensed offered role presumes itself at capacity — supply standing in for demand"
        );
        assert_eq!(published.of(Role::Exit), 0, "an unoffered, unsensed role publishes nothing");

        // What the cell concludes from seven such nodes. This is the assertion that could not be made before:
        // the setpoint reaches zero, so the controller can actually shrink the role.
        let want = cell_setpoint(&[published; 7], cap);
        assert_eq!(
            want.of(Role::Relay),
            0,
            "a cell where every node measured no relay demand must want no relays; the offer-for-any-zero rule \
             reported 7 here and the role could never shrink"
        );
        // **Seven nodes holding five keys each need one storage node, not thirty-five, and that is the fix
        // working.** This read `35` while capacity was the placeholder `1` — a cell of seven asking for
        // thirty-five storage nodes because it holds thirty-five keys, an *event* count read as a *node*
        // count, and the saturation that made every assignment unanimous. Divided by the bound the node
        // actually enforces on that number, the same load is one node's worth of work, which is a figure a
        // controller can act on.
        assert_eq!(
            want.of(Role::Storage),
            1,
            "thirty-five keys against a per-node capacity of {} is ONE storage node's worth of work — \
             asking for thirty-five was reading held keys as needed nodes",
            cap.of(Role::Storage),
        );
        assert_eq!(want.of(Role::Service), 7, "everyone who offers an unsensed role serves it");
    }

    #[test]
    fn the_setpoint_divides_by_capacity_exactly_once() {
        // At the shipped capacity of 1 a single division and a double one are both the identity, which is the
        // only reason the double one survived: the driver published `⌈load / capacity⌉` and `cell_setpoint`
        // divided the sum by capacity again. At capacity 4 they diverge, and the cell under-provisions.
        let cap = Demand::per_role(|_| 4);
        let offered = RoleSet::of(&[Role::Relay, Role::Service]);
        // The feeder's token, held for the test's lifetime: the TEST is the feeder here.
        let (sensor, _feeding) = LoadSensor::new();
        sensor.record(RoleReading::blind().measuring(Role::Relay, 8));

        let published = sensor.load(offered, cap);
        assert_eq!(published.of(Role::Relay), 8, "a node publishes work units, not nodes");

        let want = cell_setpoint(&[published, published], cap);
        // 16 units of relay work at 4 units per node. Dividing twice gave ⌈⌈8/4⌉ + ⌈8/4⌉ / 4⌉ = 1 — a quarter
        // of the relays the cell needs.
        assert_eq!(want.of(Role::Relay), 4, "16 units of work at 4 per node needs 4 relays");
        assert_eq!(
            want.of(Role::Service),
            2,
            "the unsensed fallback stays exact away from capacity 1: both nodes offer it, so both serve it"
        );
    }

    #[test]
    fn a_self_gated_role_keeps_one_server_and_a_role_nobody_offers_gets_no_phantom_floor() {
        // Zero demand is absorbing for a role whose load only assigned nodes produce: nobody serving means no
        // registrations, no flows and no gathers, so the load reads zero forever and the role never returns.
        // The floor is the minimum that keeps the signal observable — and it must be conditioned on supply,
        // since a setpoint above supply is surfaced as a deficit the cell escalates to its parent.
        let measured_nothing = Demand::default();
        let everyone_offers = Demand::per_role(|_| 3);

        // Named per role rather than compared against `load_is_self_gated()`. Asserting agreement between the
        // floor and the classification is a tautology — flipping the classification moves both sides together
        // and the test still passes, which is exactly what happened when this was first written. What must be
        // pinned is *which roles are which*, and that only a literal can say.
        let floored = measured_nothing.with_viability_floor(everyone_offers, fano::LINE_SIZE);
        assert_eq!(floored.of(Role::Service), 1, "nobody serving means no service to measure");
        assert_eq!(floored.of(Role::Exit), 1, "nobody exiting means no flows to measure");

        // **The two floors are different questions, and this is where they part.** Observability is satisfied
        // by one server; a threshold line is not. `t`-of-`(q+1)` is what a rendezvous line's anonymity set and
        // POROS's seize-below-`t` guarantee both rest on, so one occupied point does not weaken the property —
        // it inverts it, handing a single node what the threshold exists to split.
        let t = line_floor(fano::LINE_SIZE);
        assert_eq!(t, 2, "PG(2,2): a 3-point line acts at 2, and the floor must be that same t");
        assert_eq!(floored.of(Role::Rendezvous), t, "a meeting line below t cannot peel at all");
        assert_eq!(floored.of(Role::Ingress), t, "and POROS's ingress line is the same property");
        assert!(
            floored.of(Role::Rendezvous) > floored.of(Role::Exit),
            "if these ever coincide the threshold floor has silently become the observability one"
        );

        // The floor tracks the PLANE, not the base cell — the ceiling-computed-on-Fano defect (#122) one
        // subsystem over. On a wider plane a line is wider and so is the quorum that must occupy it.
        let wide = measured_nothing.with_viability_floor(everyone_offers, 8);
        assert_eq!(
            wide.of(Role::Rendezvous),
            line_floor(8),
            "q=7: an 8-point line needs 6 occupied, not the Fano plane's 2"
        );
        assert_eq!(
            floored.of(Role::Relay),
            0,
            "relay load is originated traffic, which a node produces unassigned — no floor needed"
        );
        assert_eq!(
            floored.of(Role::Storage),
            0,
            "the store is structural, so held keys stay observable with nobody assigned — no floor needed"
        );

        // Nobody can serve any role: no floor anywhere, or the cell escalates a want no member can meet.
        assert_eq!(
            measured_nothing.with_viability_floor(Demand::default(), fano::LINE_SIZE),
            Demand::default(),
            "a role nobody offers must not be floored into a permanent phantom deficit"
        );

        // The floor never overrides a real measurement.
        let busy = Demand::per_role(|_| 9);
        assert_eq!(busy.with_viability_floor(everyone_offers, fano::LINE_SIZE), busy, "a floor raises, it does not clamp");
    }

    #[test]
    fn the_sensor_round_trips_every_reading_it_can_be_handed() {
        // The `0 = absent, v + 1 = Some(v)` encoding is the one place a `Some(0)` could silently become a
        // `None` again, one layer below where the type would catch it.
        // The feeder's token, held for the test's lifetime: the TEST is the feeder here.
        let (sensor, _feeding) = LoadSensor::new();
        let sent = RoleReading::blind()
            .measuring(Role::Relay, 0)
            .measuring(Role::Storage, 1)
            .measuring(Role::Exit, u16::MAX);
        sensor.record(sent);
        assert_eq!(sensor.reading(), sent, "every reading survives the shared-atomic encoding");

        // A later report that says nothing must change nothing: the engine reports `None` for every role it
        // cannot see on *every* observation, and those are exactly the roles a driver gauge fills.
        sensor.record(RoleReading::blind());
        assert_eq!(sensor.reading(), sent, "an absent reading does not erase a present one");
    }

    #[test]
    fn a_driver_gauge_measures_a_role_no_engine_can_see() {
        // Exit and service work happens in async tasks, so no engine counts it and the report carries `None`.
        // A gauge is how that role becomes measured — and opening one must survive the engine's next report,
        // which will say `None` for it again.
        // The token stays held: this fixture feeds Relay through `record` below, so it IS the feeder.
        let (sensor, _feeding) = LoadSensor::new();
        let sensor = Arc::new(sensor);
        assert_eq!(sensor.reading().of(Role::Exit), None, "unsensed before the role's task starts");

        let gauge = sensor.gauge(Role::Exit);
        assert_eq!(
            sensor.reading().of(Role::Exit),
            Some(0),
            "a running exit that is carrying nothing measured zero — it is not unsensed"
        );

        let first = gauge.in_flight();
        let second = gauge.in_flight();
        assert_eq!(sensor.reading().of(Role::Exit), Some(2), "two flows in flight");

        // The engine's report says `None` for exit on every observation; it must not erase the gauge.
        sensor.record(RoleReading::blind().measuring(Role::Relay, 4));
        assert_eq!(sensor.reading().of(Role::Exit), Some(2), "an engine report does not clobber a gauge");
        assert_eq!(sensor.reading().of(Role::Relay), Some(4), "and still lands its own readings");

        drop(first);
        assert_eq!(sensor.reading().of(Role::Exit), Some(1), "a finished flow stops being carried");
        drop(second);
        assert_eq!(
            sensor.reading().of(Role::Exit),
            Some(0),
            "an idle exit reads zero — and stays sensed, so the offer does not stand back in for it"
        );
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
            if live.step(&members, Epoch::new(1), &beacon, setpoint, true).roles.has(Role::Relay) {
                active += 1;
            }
            demand_after = live.demand().of(Role::Relay);
        }
        assert_eq!(active, 3, "the cell assigns exactly the demanded 3 relays across its members");
        assert_eq!(demand_after, 3, "each controller tracked the setpoint");
    }

    /// Two nodes that have lived through different pasts must assign the same roles from the same closed epoch.
    ///
    /// **This property is invisible at the shipped gain, which is why it survived.** `ROLE_GAIN_SEVENTH = 7`
    /// is `κ = 1`, so the carried demand reaches the setpoint in one step and is already history-free — the
    /// test passes with or without the fix. The divergence appears at `κ = 1/7`, and the consequence is worth
    /// stating plainly: cell agreement was resting on the *value of a tuning constant*, so damping the loop —
    /// the obvious response to role churn — would have reintroduced a permanent, unobservable disagreement.
    /// So the gain is what this varies.
    #[test]
    fn two_nodes_with_different_histories_assign_the_same_roles() {
        const GAIN: u8 = fanos_core::roles::GAIN_BOOTSTRAP_SEVENTHS; // κ = 1/7
        let members: Vec<(NodeId, Capability)> =
            (0..7).map(|i| (node(i), Capability::new(RoleSet::of(&[Role::Relay]), 4))).collect();
        let beacon = BeaconSeed::new([0x5a; 32]);
        let sp = |n: u16| Demand::per_role(|r| if r == Role::Relay { n } else { 0 });

        // How many of the cell's seven nodes take the relay role at epoch 6, after living through `history`.
        // Counted cell-wide rather than at one node: the count is what the disagreement is *about*, and a
        // single node can land on the same side of two different cutoffs by luck of the lottery.
        let assigned = |history: &[(u64, u16)]| -> usize {
            (0..7u8)
                .filter(|&i| {
                    let mut live = LiveRoleController::new(
                        node(i),
                        RoleController::new(Demand::default(), Demand::default(), GAIN),
                    );
                    for &(e, n) in history {
                        live.step(&members, Epoch::new(e), &beacon, sp(n), true);
                    }
                    live.step(&members, Epoch::new(6), &beacon, sp(5), true).roles.has(Role::Relay)
                })
                .count()
        };

        // THE PROPERTY. A cell whose load has been swinging, against a node that just restarted.
        let veteran = assigned(&[(1, 40), (2, 3), (3, 40), (4, 3), (5, 40)]);
        let restarted = assigned(&[]);
        assert_eq!(
            veteran, restarted,
            "the same closed epoch must produce the same cell-wide assignment on both nodes; carried, the \
             swinging history leaves a demand of 11 against the fresh node's 1, so the cell provisions 7 \
             relays or 1 depending on which node you ask — and every node's own report looks self-consistent"
        );

        // The mechanism, asserted after the property so that reverting `step` to the carried controller fails
        // on the property and not merely here.
        assert_eq!(
            restarted, 1,
            "and the agreed value is the floor replayed over that one setpoint: κ=1/7 of the way to 5 rounds \
             to zero, so the forced ±1 step gives 1"
        );
    }

    /// A closed epoch older than the directory's own lifetime must be refused, because the reader cannot tell.
    #[test]
    fn a_closed_epoch_older_than_the_directorys_lifetime_is_refused() {
        let seed = BeaconSeed::new([0x11; 32]);
        let at = |e: u64| ClosedEpoch { epoch: Epoch::new(e), seed };

        // THE PROPERTY. `read_load` calls a missing record a definite `Absent` rather than an `Unknown` — on
        // purpose, so one forged record cannot void a scan. The cost is that an *expired* directory reads as a
        // COMPLETE scan of a cell carrying no load at all, and the loop retires every role on evidence that
        // does not exist. Nothing downstream can catch this; it has to be refused here.
        assert!(at(5).readable_for(Epoch::new(7)).is_none(), "two epochs back is already pruned");
        assert!(
            at(0).readable_for(Epoch::new(500)).is_none(),
            "a node that booted mid-run holds no readable closed epoch, and must wait rather than read an \
             empty directory as a cell with no work"
        );

        // The two it must accept: the one closed epoch, and genesis, which has no predecessor to close.
        assert_eq!(at(5).readable_for(Epoch::new(6)).map(|(e, _)| e), Some(Epoch::new(5)));
        assert_eq!(at(0).readable_for(Epoch::ZERO).map(|(e, _)| e), Some(Epoch::ZERO));

        // The bound is the slot's lifetime, not a number chosen here: a record published in `e` expires at
        // `e + DIRECTORY_SLOT_EPOCHS`. Raising the retention to buy a wider smoothing window has to come back
        // through this assertion.
        assert_eq!(crate::DIRECTORY_SLOT_EPOCHS, 1, "one closed epoch is readable, so the window is one");
    }

    #[test]
    fn the_refresh_lengthens_only_when_looking_sooner_would_be_wasted() {
        // Two unrelated reasons to scan less often, pinned apart because conflating them is what left a cell frozen short
        // of its own membership: the answer is settled, or the store is not answering. Each was measured the hard way.
        const OK: u32 = STABLE_BEFORE_BACKOFF;

        assert!(may_relax(OK, 5, 5, true), "settled, not behind, and the reads concluded: relax");

        // One identical answer is not a pattern.
        assert!(!may_relax(0, 5, 5, true));
        assert!(!may_relax(OK - 1, 5, 5, true), "just short of the threshold still holds at the floor");

        // The transport's peer table is a lower bound the overlay store owes nothing to, so a roster below it is
        // DEMONSTRABLY behind — positive evidence of work left to do (§5.3.2, measured as a cell stuck at [2, 1, 2]).
        assert!(!may_relax(OK, 4, 5, true), "roster below the transport's own peer count");
        assert!(may_relax(OK, 6, 5, true), "a roster ABOVE it is not evidence of being behind");

        // An incomplete scan lengthens the period, and that is the RIGHT direction: a store that is not answering is not
        // fixed by asking it more often, and asking more often is what stopped it answering (§5.3.5). The soundness half is
        // at the call site — `stable` only accumulates on a complete repeat — so backing off here never turns into
        // believing a partial answer.
        assert!(may_relax(0, 0, 9, false), "cannot read ⇒ retry less often, regardless of how it looks");
        assert!(may_relax(OK, 5, 5, false), "and completeness is checked before stability, not after it");
    }

    #[test]
    fn a_read_that_did_not_conclude_is_not_an_absence() {
        // The primitive underneath it. `Absent` is actionable — the slot is empty, or its contents failed to authenticate.
        // `Unknown` is not information at all, and collapsing the two is what made a partial scan indistinguishable from a
        // small cell.
        use crate::resolve::{Read, Scan};

        assert_eq!(Read::found_or_absent(Some(7)), Read::Found(7), "a completed read that found something");
        assert_eq!(Read::found_or_absent(None::<u8>), Read::Absent, "a completed read that found nothing is DEFINITE");
        assert_ne!(Read::Absent, Read::Unknown::<u8>, "the distinction the old `Option` could not express");

        let whole = Scan { found: alloc_pairs(&[1, 2]), unknown: 0 };
        assert!(whole.complete(), "every read concluded");
        let partial = Scan { found: alloc_pairs(&[1]), unknown: 1 };
        assert!(!partial.complete(), "one inconclusive read makes the whole view partial");
    }

    /// Fixture: `(coord, value)` pairs for a `Scan`, coordinates being irrelevant to what is asserted.
    fn alloc_pairs(values: &[u8]) -> Vec<(fanos_diaulos::Coord, u8)> {
        values.iter().map(|&v| ([1, 0, 0], v)).collect()
    }

    #[test]
    fn one_timed_out_read_must_not_void_evidence_a_motionless_assignment_earned() {
        // #293, replayed as the refresh loop replays it: `same_as` picks the branch, `next_stable` scores it.
        // Both are production's, composed in production's order — a hand-rolled copy of the loop would pin my
        // reading of it rather than the loop.
        let at = |complete| Assignment {
            roles: RoleSet::EMPTY,
            roster: 7,
            epoch: Epoch::new(4),
            complete,
        };
        let step = |settled: Assignment, now: Assignment, stable: u32| {
            if now.same_as(&settled) {
                (settled, next_stable(stable, true, now.complete))
            } else {
                (now, next_stable(stable, false, now.complete))
            }
        };

        // Roles, roster and epoch never move across all three reads. Only the reader's luck does.
        let (mut settled, mut stable) = (at(true), 2u32);
        (settled, stable) = step(settled, at(true), stable);
        assert_eq!(stable, 3, "a complete repeat is evidence");
        (settled, stable) = step(settled, at(false), stable);
        assert_eq!(stable, 3, "one timed-out read is not a change, so it neither adds nor voids");
        (settled, stable) = step(settled, at(true), stable);
        assert_eq!(
            stable, 4,
            "and the next successful read continues the run. With `complete` inside the comparison the \
             timed-out read replaced the baseline, this recovery then differed from it too, and the run was \
             scored as `a complete change` — 4 became 0, not 3 (#293)"
        );

        // The other direction, and the one that must NOT be weakened: a real change still voids.
        let moved = Assignment { roster: 6, ..at(true) };
        let (_, after) = step(settled, moved, stable);
        assert_eq!(after, 0, "a genuine change on a complete read still resets the evidence");
    }

    #[test]
    fn evidence_of_a_settled_assignment_accumulates_only_on_a_complete_repeat() {
        // The soundness half, and it had no guard until this: reintroducing "accumulate on any repeat" left all 101 tests
        // green. A node that cannot read must never come to *believe* its assignment is settled, however long it waits.
        assert_eq!(next_stable(2, true, true), 3, "a complete repeat is evidence");
        assert_eq!(next_stable(2, false, true), 0, "a complete change voids what was accumulating");

        // The case the whole chain led to: two partial views agreeing with each other are not evidence about the cell.
        assert_eq!(next_stable(2, true, false), 2, "an incomplete repeat accumulates NOTHING");
        for n in 0..STABLE_BEFORE_BACKOFF + 5 {
            assert_eq!(next_stable(n, true, false), n, "however many times it repeats: {n}");
        }
        // ...and it does not destroy evidence gathered while the reads did conclude, either.
        assert_eq!(next_stable(2, false, false), 2, "an inconclusive scan is not a change, and not a reset");

        // Composed with the cadence rule: unable to read ⇒ slow down, but never cross the settled threshold by doing so.
        let mut stable = 0;
        for _ in 0..20 {
            stable = next_stable(stable, true, false);
        }
        assert!(stable < STABLE_BEFORE_BACKOFF, "twenty unreadable scans must not add up to a settled answer");
        assert!(may_relax(stable, 0, 9, false), "though the node does back off, which is the congestion response");
    }
}
