//! The discrete-event simulator: the driver that steps real node engines over virtual time.
//!
//! It owns the three environment ports (a virtual clock, the [`NetworkModel`] transport, and a
//! seeded [`Rng`]) and turns each engine [`Effect`] into future [`Input`]s. Nodes never share
//! state; the only coupling is messages routed through the network model — exactly as on a
//! real fleet.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap};

use fanos_runtime::{Command, Effect, Engine, Epoch, Input, Instant, Notification, TimerToken, Triple};
use fanos_wire::decode_frame;

use fanos_telemetry::{CoherenceFrame, CoherenceSnapshot};

use crate::fleet::{FleetSnapshot, NodeState};
use crate::metrics::{Observed, Report};
use crate::network::NetworkModel;
use crate::rng::Rng;
use crate::trace::{Trace, fmt_coord};

/// The settle window [`Sim::tick_epoch`] allows one beacon round to propagate and assemble, in ms. A DVRF
/// round is ~2 broadcast hops; the default network is 20 ms + ≤10 ms jitter, so 2 s is ample (it matches the
/// proven `beacon_node_e2e` idiom) while staying short enough that no realistic round is silently missed.
const EPOCH_SETTLE_MS: u64 = 2000;

/// A short human-readable name for a wire frame (its type), for the trace.
fn frame_name(frame: &[u8]) -> String {
    match decode_frame(frame) {
        Ok((f, _)) => match f.frame_type() {
            Some(ty) => format!("{ty:?}"),
            None => format!("type#{:#x}", f.type_code),
        },
        Err(_) => "malformed".to_owned(),
    }
}

/// A short name for an application command, for the trace.
fn cmd_name(cmd: &Command) -> &'static str {
    match cmd {
        Command::StartHeartbeat => "StartHeartbeat",
        Command::Send { .. } => "Send",
        Command::Emit { .. } => "Emit",
        Command::Diagnose => "Diagnose",
        Command::Observe => "Observe",
        Command::Put { .. } => "Put",
        Command::Get { .. } => "Get",
        Command::SampleAvailability { .. } => "SampleAvailability",
        Command::Join { .. } => "Join",
        Command::AdvanceEpoch => "AdvanceEpoch",
        Command::Reseat { .. } => "Reseat",
    }
}

/// A concise description of a notification, for the trace.
fn note_desc(note: &Notification) -> String {
    match note {
        Notification::Delivered { from, .. } => format!("Delivered from {}", fmt_coord(*from)),
        Notification::App { from, .. } => format!("App from {}", fmt_coord(*from)),
        Notification::RendezvousLine(l) => format!("RendezvousLine {}", fmt_coord(*l)),
        Notification::PeerDown(p) => format!("PeerDown {}", fmt_coord(*p)),
        Notification::Verdict(v) => format!("Verdict {v:?}"),
        Notification::Rerouted { around, via } => {
            format!("Rerouted {}→via {}", fmt_coord(*around), fmt_coord(*via))
        }
        Notification::Repaired(c) => format!("Repaired {}", fmt_coord(*c)),
        Notification::Quarantined(c) => format!("Quarantined {}", fmt_coord(*c)),
        Notification::Grey(c) => format!("Grey {}", fmt_coord(*c)),
        Notification::Escalated(mask) => format!("Escalated {mask:#09b}"),
        Notification::Decoupled => "Decoupled".to_owned(),
        Notification::Bound => "Bound".to_owned(),
        Notification::Stored(k) => format!("Stored {}", short_digest(k)),
        Notification::Retrieved { key, value } => format!(
            "Retrieved {} ({})",
            short_digest(key),
            value.as_ref().map_or("miss", |_| "hit")
        ),
        Notification::DataLost { key, epoch } => {
            format!("DataLost {} @{epoch}", short_digest(key))
        }
        Notification::Availability { key, available } => format!(
            "Availability {} ({})",
            short_digest(key),
            if *available {
                "available"
            } else {
                "unavailable"
            }
        ),
        Notification::MemberJoined { coord, .. } => format!("MemberJoined {}", fmt_coord(*coord)),
        Notification::EpochAdvanced(e) => format!("EpochAdvanced {e}"),
        Notification::DkgComplete(y) => format!("DkgComplete {}", short_digest(y)),
        Notification::BeaconReady { epoch, seed } => {
            format!("BeaconReady {epoch} {}", short_digest(seed))
        }
        Notification::Reseated { old, new } => {
            format!("Reseated {}→{}", fmt_coord(*old), fmt_coord(*new))
        }
        Notification::Rebalance { loads } => format!("Rebalance {loads:?}"),
        Notification::Observed(bytes) => format!("Observed {}B", bytes.len()),
    }
}

/// A short hex prefix of a 32-byte key digest, for the trace.
fn short_digest(d: &[u8; 32]) -> String {
    let a = d.first().copied().unwrap_or(0);
    let b = d.get(1).copied().unwrap_or(0);
    format!("{a:02x}{b:02x}…")
}

/// Milliseconds of a `Duration`, for the trace.
fn ms(d: fanos_runtime::Duration) -> u64 {
    d.as_nanos() / 1_000_000
}

/// A scheduled event and its total-order key `(time, seq)`.
struct Scheduled {
    time: Instant,
    seq: u64,
    event: Event,
}

enum Event {
    Deliver {
        to: Triple,
        from: Triple,
        frame: Vec<u8>,
    },
    Timer {
        node: Triple,
        token: TimerToken,
    },
    Command {
        node: Triple,
        cmd: Command,
    },
}

// A min-heap by (time, seq): earliest time first, ties broken by insertion order.
impl Ord for Scheduled {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse so BinaryHeap (a max-heap) yields the earliest event.
        other
            .time
            .cmp(&self.time)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for Scheduled {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for Scheduled {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time && self.seq == other.seq
    }
}
impl Eq for Scheduled {}

/// A node's liveness in the simulation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    Alive,
    Crashed,
}

struct Slot {
    engine: Box<dyn Engine>,
    status: Status,
}

/// One frame as a **global passive adversary** (GPA) observes it on the wire: when, between whom, and how
/// big — never the (encrypted) content. This is exactly a traffic-analysis adversary's observable, so a test
/// can drive the real routed/mixed/cover network and then evaluate what a GPA could infer from the metadata
/// alone (spec §8.1 endpoint correlation, C1 flow correlation). Recorded only when [`Sim::observe_frames`] is on.
#[derive(Clone, Copy, Debug)]
pub struct FrameObs {
    /// Delivery time, in milliseconds of virtual time.
    pub t_ms: u64,
    /// The sending coordinate (the transport authenticates it, so a GPA sees it).
    pub from: Triple,
    /// The receiving coordinate.
    pub to: Triple,
    /// The frame size in bytes (constant-size cells hide the payload length; a GPA still sees the count).
    pub len: usize,
}

/// The simulator. Add engines, inject commands, inject faults, run the clock, read the report.
pub struct Sim {
    clock: Instant,
    seq: u64,
    queue: BinaryHeap<Scheduled>,
    nodes: BTreeMap<Triple, Slot>,
    net: NetworkModel,
    rng: Rng,
    report: Report,
    trace: Trace,
    /// The global passive observer's tape (frame metadata), when [`observe_frames`](Sim::observe_frames) is on.
    frame_tap: Option<Vec<FrameObs>>,
    /// The latest coherence frame each node published (`Notification::Observed`), banked for `O(N)`
    /// fleet snapshots ([`fleet_snapshot`](Sim::fleet_snapshot)). Updated on every emission; read-only
    /// with respect to the run, so it never perturbs the determinism contract.
    latest_observed: BTreeMap<Triple, Vec<u8>>,
}

impl Sim {
    /// A new simulator with a default network, seeded for reproducibility.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self::with_network(seed, NetworkModel::default())
    }

    /// A new simulator with an explicit network model.
    #[must_use]
    pub fn with_network(seed: u64, net: NetworkModel) -> Self {
        Self {
            clock: Instant::default(),
            seq: 0,
            queue: BinaryHeap::new(),
            nodes: BTreeMap::new(),
            net,
            rng: Rng::new(seed),
            report: Report::default(),
            trace: Trace::new(),
            frame_tap: None,
            latest_observed: BTreeMap::new(),
        }
    }

    /// Turn the event trace on or off (off by default; see [`Sim::trace`]).
    pub fn enable_trace(&mut self, on: bool) {
        self.trace.enable(on);
    }

    /// Enable the **global passive observer**: from now on every delivered frame's metadata `(t, from, to,
    /// len)` is recorded on a tape a traffic-analysis adversary could read ([`observed_frames`](Sim::observed_frames)).
    /// The affordance for modeling a GPA over the running network (spec §8.1, C1) — the adversary sees only
    /// metadata, never the encrypted content.
    pub fn observe_frames(&mut self) {
        self.frame_tap.get_or_insert_with(Vec::new);
    }

    /// The global passive observer's tape (empty unless [`observe_frames`](Sim::observe_frames) was enabled).
    #[must_use]
    pub fn observed_frames(&self) -> &[FrameObs] {
        self.frame_tap.as_deref().unwrap_or(&[])
    }

    /// The recorded event trace — the inspectable log of the run.
    #[must_use]
    pub fn trace(&self) -> &Trace {
        &self.trace
    }

    fn log(&mut self, line: impl Into<String>) {
        let t = self.clock.as_nanos();
        self.trace.record(t, line);
    }

    /// The current virtual time.
    #[must_use]
    pub fn now(&self) -> Instant {
        self.clock
    }

    /// Mutable access to the network model (to impose or heal partitions, change latency).
    pub fn network_mut(&mut self) -> &mut NetworkModel {
        &mut self.net
    }

    /// Add a node engine; returns its coordinate (address).
    pub fn add(&mut self, engine: Box<dyn Engine>) -> Triple {
        let addr = engine.address();
        self.nodes.insert(
            addr,
            Slot {
                engine,
                status: Status::Alive,
            },
        );
        addr
    }

    /// The coordinates of all nodes.
    pub fn nodes(&self) -> impl Iterator<Item = Triple> + '_ {
        self.nodes.keys().copied()
    }

    /// Crash a node: it stops processing inputs and emitting effects (spec §3.3 crash/churn).
    pub fn crash(&mut self, node: Triple) {
        if let Some(slot) = self.nodes.get_mut(&node) {
            slot.status = Status::Crashed;
        }
    }

    /// Recover a crashed node (its engine state is retained — churn rejoin).
    pub fn recover(&mut self, node: Triple) {
        if let Some(slot) = self.nodes.get_mut(&node) {
            slot.status = Status::Alive;
        }
    }

    /// Whether a node is currently alive.
    #[must_use]
    pub fn is_alive(&self, node: Triple) -> bool {
        self.nodes
            .get(&node)
            .is_some_and(|s| s.status == Status::Alive)
    }

    /// A ground-truth liveness snapshot of `nodes` (`1.0` alive, `0.0` crashed), for feeding the
    /// coherence observatory from a *live* run. Sampled over time it yields one behavioural signal
    /// per node whose correlation the observatory reads: a synchronized (correlated) collapse pushes
    /// the mean correlation across `r*`, while independent churn stays diversified below it — so the
    /// observatory discriminates a genuine cascade from incidental churn on real data, not just the
    /// synthetic [`HealthField`](crate::HealthField).
    #[must_use]
    pub fn liveness_snapshot(&self, nodes: &[Triple]) -> Vec<f64> {
        nodes
            .iter()
            .map(|&n| f64::from(u8::from(self.is_alive(n))))
            .collect()
    }

    /// A whole-fleet state snapshot — every node's coordinate, liveness, and latest coherence self-model,
    /// plus the cluster rollup and the run's cumulative metrics. This is the data contract the operator
    /// dashboard and CLI read; it is a pure `O(N)` read over frames the nodes have already published (the
    /// reflex emits one every heartbeat since #122), so it never advances the clock. For a guaranteed-fresh
    /// read, call [`refresh_telemetry`](Sim::refresh_telemetry) first.
    #[must_use]
    pub fn fleet_snapshot(&self) -> FleetSnapshot {
        let nodes = self
            .nodes
            .iter()
            .map(|(&coord, slot)| {
                let coherence = self
                    .latest_observed
                    .get(&coord)
                    .and_then(|b| CoherenceFrame::decode(b))
                    .map(|f| CoherenceSnapshot::from_frame(&f));
                NodeState { coord, alive: slot.status == Status::Alive, coherence }
            })
            .collect();
        FleetSnapshot::from_nodes(self.clock.as_nanos(), nodes, self.report.metrics.clone())
    }

    /// Force every live node to publish a fresh coherence frame now (a sense-only
    /// [`Command::Observe`](fanos_runtime::Command::Observe) — no healing side effects), so the next
    /// [`fleet_snapshot`](Sim::fleet_snapshot) reflects the current instant rather than the last heartbeat.
    /// Drains at the current instant without advancing virtual time.
    pub fn refresh_telemetry(&mut self) {
        self.inject_all(&Command::Observe);
        self.settle();
    }

    /// Inject an application command into `node` at the current time.
    pub fn inject(&mut self, node: Triple, cmd: Command) {
        self.schedule(self.clock, Event::Command { node, cmd });
    }

    /// Inject a command into every node.
    pub fn inject_all(&mut self, cmd: &Command) {
        for node in self.nodes.keys().copied().collect::<Vec<_>>() {
            self.inject(node, cmd.clone());
        }
    }

    /// Deliver a raw wire `frame` to `to` as if sent by `from` — the Byzantine / adversary hook.
    /// Models a malicious node crafting an arbitrary (possibly forged or malformed) frame; the
    /// transport authenticates `from`, so this stands in for that node genuinely emitting it.
    pub fn inject_frame(&mut self, from: Triple, to: Triple, frame: Vec<u8>) {
        self.schedule(self.clock, Event::Deliver { to, from, frame });
    }

    fn schedule(&mut self, time: Instant, event: Event) {
        self.queue.push(Scheduled {
            time,
            seq: self.seq,
            event,
        });
        self.seq += 1;
    }

    /// Run until the event queue is empty or the deadline is reached.
    pub fn run_until(&mut self, deadline: Instant) {
        while let Some(next) = self.queue.peek() {
            if next.time > deadline {
                break;
            }
            let Some(scheduled) = self.queue.pop() else {
                break;
            };
            self.clock = scheduled.time;
            self.dispatch(scheduled.event);
        }
        self.clock = deadline.max(self.clock);
    }

    /// Advance the clock by `dur`, processing all events in that window.
    pub fn run_for(&mut self, dur: fanos_runtime::Duration) {
        self.run_until(self.clock.saturating_add(dur));
    }

    /// Process every event scheduled at the current instant (draining same-time cascades)
    /// without advancing the clock into the future.
    ///
    /// This is the safe way to flush injected commands — whose effects (notifications) are
    /// immediate — while perpetual timers such as heartbeats remain in the future. Running
    /// "until the queue is empty" is intentionally *not* offered: with periodic timers the
    /// queue is never empty, so such a call would never return.
    pub fn settle(&mut self) {
        self.run_until(self.clock);
    }

    /// Drive one beacon epoch across the whole cell and report the newest epoch it adopted.
    ///
    /// Ticks `Command::AdvanceEpoch` into every node — an anchor floods its DVRF partial, a threshold `t` of
    /// distinct partials assembles the round, and each node announces [`Notification::BeaconReady`] — then
    /// settles the round. Returns the newest epoch **any** node adopted this tick, or `None` if no round
    /// assembled: the beacon stalled because fewer than `t` anchors are live.
    ///
    /// Unlike injecting a `Command::Reseat` directly (which fakes the reshuffle), this drives the *real*
    /// `beacon → BeaconReady → reshuffle` epoch clock over `OverlayBeaconNode`s, so a scenario can crash an
    /// anchor batch and observe the clock freeze at the `n − t + 1` loss cliff (audit R-C1 / sim S-P0.0).
    #[must_use]
    pub fn tick_epoch(&mut self) -> Option<Epoch> {
        let seen = self.report.notifications.len();
        self.inject_all(&Command::AdvanceEpoch);
        self.run_for(fanos_runtime::Duration::from_millis(EPOCH_SETTLE_MS));
        self.report
            .notifications
            .iter()
            .skip(seen)
            .filter_map(|o| match o.note {
                Notification::BeaconReady { epoch, .. } => Some(epoch),
                _ => None,
            })
            .max()
    }

    fn dispatch(&mut self, event: Event) {
        match event {
            Event::Deliver { to, from, frame } => {
                let name = frame_name(&frame);
                if self.is_alive(to) {
                    self.report.metrics.frames_delivered += 1;
                    // Feed the global passive observer's tape (metadata only — a GPA never sees content).
                    if let Some(tap) = self.frame_tap.as_mut() {
                        tap.push(FrameObs {
                            t_ms: self.clock.as_nanos() / 1_000_000,
                            from,
                            to,
                            len: frame.len(),
                        });
                    }
                    self.log(format!(
                        "deliver {name} {}→{}",
                        fmt_coord(from),
                        fmt_coord(to)
                    ));
                    self.step(to, Input::Message { from, frame });
                } else {
                    self.report.metrics.frames_dropped += 1;
                    self.log(format!(
                        "drop[dead] {name} {}→{}",
                        fmt_coord(from),
                        fmt_coord(to)
                    ));
                }
            }
            Event::Timer { node, token } => {
                if self.is_alive(node) {
                    self.report.metrics.timers_fired += 1;
                    self.log(format!("timer {} #{}", fmt_coord(node), token.0));
                    self.step(node, Input::Timer(token));
                }
            }
            Event::Command { node, cmd } => {
                if self.is_alive(node) {
                    self.log(format!("cmd {} {}", fmt_coord(node), cmd_name(&cmd)));
                    self.step(node, Input::Command(cmd));
                }
            }
        }
    }

    fn step(&mut self, node: Triple, input: Input) {
        // Take the engine out to avoid borrowing self mutably twice, then run it.
        let Some(mut slot) = self.nodes.remove(&node) else {
            return;
        };
        let effects = slot.engine.step(self.clock, input);
        // Re-key by the engine's *current* address: a per-epoch reshuffle (`Command::Reseat`) moves a node
        // to a new coordinate, and frames must continue to route to it. A no-op for every ordinary step
        // (the address is unchanged). A reshuffle targets an independently-VRF'd point, so the sim — which
        // models one occupant per coordinate — moves the node to a currently-unoccupied coordinate; its
        // effects are attributed to the new address, matching the coordinate its re-announce carries.
        let addr = slot.engine.address();
        self.nodes.insert(addr, slot);
        self.apply(addr, effects);
    }

    fn apply(&mut self, node: Triple, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Send { to, frame } => {
                    self.report.metrics.frames_sent += 1;
                    let name = frame_name(&frame);
                    if let Some(d) = self.net.delay(node, to, &mut self.rng) {
                        let at = self.clock.saturating_add(d);
                        self.log(format!(
                            "send {name} {}→{} +{}ms",
                            fmt_coord(node),
                            fmt_coord(to),
                            ms(d)
                        ));
                        self.schedule(
                            at,
                            Event::Deliver {
                                to,
                                from: node,
                                frame,
                            },
                        );
                    } else {
                        self.report.metrics.frames_dropped += 1;
                        self.log(format!(
                            "drop[net] {name} {}→{}",
                            fmt_coord(node),
                            fmt_coord(to)
                        ));
                    }
                }
                Effect::ArmTimer { token, after } => {
                    let at = self.clock.saturating_add(after);
                    self.log(format!(
                        "arm {} #{} +{}ms",
                        fmt_coord(node),
                        token.0,
                        ms(after)
                    ));
                    self.schedule(at, Event::Timer { node, token });
                }
                Effect::Notify(note) => {
                    let m = &mut self.report.metrics;
                    match &note {
                        Notification::Delivered { .. } => m.payloads_delivered += 1,
                        Notification::PeerDown(_) => m.peer_downs += 1,
                        Notification::Rerouted { .. } => m.reroutes += 1,
                        Notification::Repaired(_) => m.repairs += 1,
                        Notification::Quarantined(_) => m.quarantines += 1,
                        Notification::Escalated(_) => m.escalations += 1,
                        Notification::Decoupled => m.decouples += 1,
                        Notification::Stored(_) => m.stores += 1,
                        Notification::Retrieved { value: Some(_), .. } => m.retrieval_hits += 1,
                        Notification::Retrieved { value: None, .. } => m.retrieval_misses += 1,
                        Notification::DataLost { .. } => m.data_losses += 1,
                        Notification::Observed(_) => m.observations += 1,
                        _ => {}
                    }
                    // Bank this node's latest coherence frame for O(1) fleet snapshots (the `m` borrow
                    // above has ended, so this second field is free to touch).
                    if let Notification::Observed(bytes) = &note {
                        self.latest_observed.insert(node, bytes.clone());
                    }
                    self.log(format!("notify {} {}", fmt_coord(node), note_desc(&note)));
                    self.report.notifications.push(Observed { node, note });
                }
            }
        }
    }

    /// The run report (counters + notifications).
    #[must_use]
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// Clear the accumulated report (counters + notifications). DIAKRISIS diagnosis is now a self-driving
    /// reflex on every heartbeat (audit #122), so a run accumulates verdicts/healing continuously; call
    /// this after staging a scenario to read only what happens from this point on — e.g. reset, then a
    /// final `inject_all(&Command::Diagnose)` + `settle()`, so the report reflects the cell's *current*
    /// diagnosis rather than its whole history (including a since-crashed node's earlier healthy verdicts).
    pub fn clear_report(&mut self) {
        self.report = Report::default();
    }
}
