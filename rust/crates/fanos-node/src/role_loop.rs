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
//! fabricated zero. [`LoadSensor::setpoint`] substitutes this node's own offer for an absent role, deliberately,
//! since a demand of zero would retire a role the moment nobody could see it; so for a role with no sensor,
//! supply stands in for demand.
//!
//! That fallback used to fire on any **zero**, which is a different and wrong rule: it discarded the true
//! reading of a role that had legitimately gone idle, at exactly the moment the controller should have shrunk
//! it, and it bound the two roles that *are* measured. `Notification::LoadReport` now carries
//! `[Option<u16>; Role::COUNT]` so absence is a value rather than a guess, and a sibling engine fills the
//! missing three through `OverlayNode::observe_load` — the seam `docs/design-observability.md` §7 describes.
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

use fanos_core::roles::{Capability, Demand, Reputation, Role, RoleController, RoleReading, RoleSet};
use fanos_field::Field;
use fanos_primitives::{BeaconSeed, Epoch, NodeId};
use fanos_quic::{Client, CoordinateProver};
use fanos_runtime::Notification;
use fanos_vrf::VrfSecret;
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::JoinHandle;

use crate::capdir::{build_capability_directory, spawn_capability_publisher};
use crate::loaddir::{build_cell_setpoint, spawn_load_publisher};

/// The load one node is taken to absorb per role — the setpoint denominator, applied **once**, cell-wide, in
/// `cell_setpoint`. `1` is the right default before telemetry can substantiate a real capacity class, and it is
/// deliberately *not* what makes "everyone who offers it, serves it" hold: an unsensed offered role publishes
/// `capacity` as its load, so that identity survives any value here.
pub(crate) const ROLE_CAPACITY_PER_NODE: u16 = 1;

/// The per-role capacity vector, built once so the load publisher and the setpoint aggregation cannot disagree
/// about the denominator — the divergence that would reintroduce a double division without any type noticing.
#[must_use]
pub(crate) fn role_capacity() -> Demand {
    Demand::per_role(|_| ROLE_CAPACITY_PER_NODE)
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
pub(crate) struct LoadSensor {
    /// Latest reading per role, indexed by `Role::index`, in the encoding above.
    latest: [AtomicU32; Role::COUNT],
}

// Every index below is `Role::index()`, which `fanos_core::roles` proves `< Role::COUNT`.
#[allow(clippy::indexing_slicing)]
impl LoadSensor {
    /// A sensor with nothing reported yet — every role absent.
    fn new() -> Self {
        Self { latest: core::array::from_fn(|_| AtomicU32::new(0)) }
    }

    /// Record a load report from the engine, latest-wins.
    fn record(&self, per_role: [Option<u16>; Role::COUNT]) {
        for (slot, reading) in self.latest.iter().zip(per_role) {
            slot.store(reading.map_or(0, |v| u32::from(v) + 1), Ordering::Relaxed);
        }
    }

    /// The most recent reading, as the role vocabulary the setpoint is derived in.
    pub(crate) fn reading(&self) -> RoleReading {
        RoleReading::per_role(|role| {
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

/// Subscribe to the engine's load reports and keep the latest, returning the shared sensor.
///
/// The task ends when the engine's notification stream closes, i.e. on node shutdown. A `Lagged` receiver is
/// ignored rather than treated as an error: the sensor is a *latest-value* register, so dropped intermediate
/// reports cost nothing — the next observation refreshes it in full.
pub(crate) fn spawn_load_sensor(client: &Client) -> Arc<LoadSensor> {
    let sensor = Arc::new(LoadSensor::new());
    let sink = Arc::clone(&sensor);
    let mut reports = client.subscribe();
    tokio::spawn(async move {
        loop {
            match reports.recv().await {
                Ok(Notification::LoadReport { per_role }) => sink.record(per_role),
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
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
    peers: impl Fn() -> usize + Send + 'static,
    // See `assign_epoch`: whether a roster record must prove the coordinate it sits at.
    vrf: bool,
) -> (JoinHandle<()>, watch::Receiver<Assignment>) {
    let (roles_tx, roles_rx) = watch::channel(Assignment::NONE);
    let handle = tokio::spawn(async move {
        let mut live = LiveRoleController::new(node_id, controller);
        let mut events = client.subscribe();
        let mut cur = Epoch::ZERO;
        let mut seed = BeaconSeed::GENESIS;
        genesis_assign::<F>(&client, &mut live, capacity, ready, vrf, &roles_tx).await;
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
                event = events.recv() => match event {
                    Ok(Notification::BeaconReady { epoch, seed: s }) if epoch > cur => {
                        cur = epoch;
                        seed = BeaconSeed::new(s);
                        (settled, _) = assign_epoch::<F>(&client, &mut live, cur, &seed, capacity, vrf, &roles_tx).await;
                        // An epoch advance re-randomises the lottery, so the assignment is expected to move: re-arm the
                        // fallback at the floor rather than letting a stale backoff carry over into the new epoch.
                        stable = 0;
                        backoff = ROSTER_REFRESH;
                        refresh = tokio::time::interval_at(tokio::time::Instant::now() + backoff, backoff);
                        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    }
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
                    let (now, complete) = assign_epoch::<F>(&client, &mut live, cur, &seed, capacity, vrf, &roles_tx).await;
                    if now == settled {
                        stable = next_stable(stable, true, complete);
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
                        if may_relax(stable, now.roster, peers(), complete) {
                            backoff = (backoff * 2).min(ROSTER_REFRESH_MAX);
                        }
                    } else {
                        settled = now;
                        stable = next_stable(stable, false, complete);
                        backoff = ROSTER_REFRESH;
                    }
                    refresh = tokio::time::interval_at(tokio::time::Instant::now() + backoff, backoff);
                    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                }
            }
        }
    });
    (handle, roles_rx)
}

/// How often the role loop re-assigns at the **current** epoch, so a roster that was incomplete at startup converges.
///
/// The loop's only other trigger is a beacon advance. That is insufficient on its own: role assignment is a
/// *homeostatic* function, and tying it exclusively to the beacon freezes it precisely when a cell most needs to
/// adapt — a stalled beacon (audit §4 R-C1's whole subject) would otherwise pin every node to whatever partial view
/// its startup race produced.
///
/// The period is **derived from the work it schedules**, not chosen: one assignment costs up to one
/// [`STORE_TIMEOUT`] (the two directory scans run concurrently), so a 3× period bounds the refresh at a **1/3 duty
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
    // See `assign_epoch`: whether a roster record must prove the coordinate it sits at.
    vrf: bool,
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
    assign_epoch::<F>(client, live, Epoch::ZERO, &BeaconSeed::GENESIS, capacity, vrf, roles_tx).await;
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

/// Recompute and publish the assignment for `epoch`, reporting whether the directory reads it rests on were **complete**.
///
/// The second value is the one that was missing. A read that timed out was indistinguishable from a member that published
/// nothing, so an assignment computed over a partial view looked exactly like one computed over the whole cell — and two
/// such in a row read as "settled", which grew the refresh backoff and left the cell frozen short of its own membership.
/// Only a *complete* view is evidence of anything.
async fn assign_epoch<F: Field>(
    client: &Client,
    live: &mut LiveRoleController,
    epoch: Epoch,
    beacon: &BeaconSeed,
    capacity: Demand,
    // Whether this cell's coordinates are VRF-derived, so a roster record must prove the slot it sits at (`crate::bound`).
    vrf: bool,
    roles_tx: &watch::Sender<Assignment>,
) -> (Assignment, bool) {
    // The two directories are independent reads, so they are scanned concurrently rather than back to back: an
    // assignment's worst-case latency is one STORE_TIMEOUT, not two. That halving is what lets the refresh period
    // below stay short enough to converge while keeping its duty cycle bounded.
    let ((members, caps_complete), (setpoint, load_complete)) = tokio::join!(
        build_capability_directory::<F>(client, epoch, vrf.then_some(*beacon)),
        build_cell_setpoint::<F>(client, epoch, capacity)
    );
    // The viability floor is applied **here**, after the join, because this is the only place that sees both the
    // cell-wide setpoint and the eligible supply it must be conditioned on. Determinism is preserved: `members`
    // is the same authenticated capability directory on every node, so every node floors identically.
    let setpoint = setpoint.with_viability_floor(Demand::supply(&members));
    let roles = live.step(&members, epoch, beacon, setpoint);
    let _ = roles_tx.send(roles);
    (roles, caps_complete && load_complete)
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
    let (load_publisher, load_ready) = spawn_load_publisher(client.clone(), load_source);
    let (role_loop, assigned) =
        spawn_role_loop::<F>(client, node_id, controller, capacity, (capability_ready, load_ready), peers, prover.is_some());
    SelfOrganization { capability_publisher, load_publisher, role_loop, assigned }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fanos_core::roles::{Capability, Role, RoleSet, cell_setpoint};

    fn node(i: u8) -> NodeId {
        NodeId([i; 32])
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
        let sensor = LoadSensor::new();

        // Nothing reported yet is genuinely absent — the array's initial state must not read as `Some(0)`.
        assert_eq!(sensor.reading(), RoleReading::blind(), "an unreported sensor holds no reading");

        // Now a report: relay measured **zero**, storage measured work, service has no sensor at all.
        sensor.record(
            RoleReading::blind().measuring(Role::Relay, 0).measuring(Role::Storage, 5).into_array(),
        );
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
        assert_eq!(want.of(Role::Storage), 35, "measured storage work aggregates");
        assert_eq!(want.of(Role::Service), 7, "everyone who offers an unsensed role serves it");
    }

    #[test]
    fn the_setpoint_divides_by_capacity_exactly_once() {
        // At the shipped capacity of 1 a single division and a double one are both the identity, which is the
        // only reason the double one survived: the driver published `⌈load / capacity⌉` and `cell_setpoint`
        // divided the sum by capacity again. At capacity 4 they diverge, and the cell under-provisions.
        let cap = Demand::per_role(|_| 4);
        let offered = RoleSet::of(&[Role::Relay, Role::Service]);
        let sensor = LoadSensor::new();
        sensor.record(RoleReading::blind().measuring(Role::Relay, 8).into_array());

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
        let floored = measured_nothing.with_viability_floor(everyone_offers);
        assert_eq!(floored.of(Role::Service), 1, "nobody serving means no service to measure");
        assert_eq!(floored.of(Role::Exit), 1, "nobody exiting means no flows to measure");
        assert_eq!(floored.of(Role::Rendezvous), 1, "nobody gathering means no gathers to measure");
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
            measured_nothing.with_viability_floor(Demand::default()),
            Demand::default(),
            "a role nobody offers must not be floored into a permanent phantom deficit"
        );

        // The floor never overrides a real measurement.
        let busy = Demand::per_role(|_| 9);
        assert_eq!(busy.with_viability_floor(everyone_offers), busy, "a floor raises, it does not clamp");
    }

    #[test]
    fn the_sensor_round_trips_every_reading_it_can_be_handed() {
        // The `0 = absent, v + 1 = Some(v)` encoding is the one place a `Some(0)` could silently become a
        // `None` again, one layer below where the type would catch it.
        let sensor = LoadSensor::new();
        let sent = RoleReading::blind()
            .measuring(Role::Relay, 0)
            .measuring(Role::Storage, 1)
            .measuring(Role::Exit, u16::MAX);
        sensor.record(sent.into_array());
        assert_eq!(sensor.reading(), sent, "every reading survives the shared-atomic encoding");

        // Latest wins, including a later report that drops a role back to absent.
        sensor.record(RoleReading::blind().into_array());
        assert_eq!(sensor.reading(), RoleReading::blind(), "a later blind report clears the register");
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
