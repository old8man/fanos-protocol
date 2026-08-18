//! The discrete-event simulator: the driver that steps real node engines over virtual time.
//!
//! It owns the three environment ports (a virtual clock, the [`NetworkModel`] transport, and a
//! seeded [`Rng`]) and turns each engine [`Effect`] into future [`Input`]s. Nodes never share
//! state; the only coupling is messages routed through the network model — exactly as on a
//! real fleet.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};

use fanos_runtime::ports::stations::GatherHealth;

use crate::network::Delivery;
use fanos_runtime::ports::ReadOutcome;
use fanos_runtime::{
    AdmissionOutcome, Command, Effect, Engine, Epoch, Escalation, Input, Instant, Notification,
    TimerToken, Triple,
};
use fanos_wire::decode_frame;

use fanos_diakrisis::Verdict;
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
        Command::Broadcast { .. } => "Broadcast",
        Command::Diagnose => "Diagnose",
        Command::Control { .. } => "Control",
        Command::Observe => "Observe",
        Command::Snapshot => "Snapshot",
        Command::Put { .. } => "Put",
        Command::PutEphemeral { .. } => "PutEphemeral",
        Command::Get { .. } => "Get",
        Command::SampleAvailability { .. } => "SampleAvailability",
        Command::Join { .. } => "Join",
        Command::AdvanceEpoch => "AdvanceEpoch",
        Command::Reseat { .. } => "Reseat",
        Command::Descriptor { .. } => "Descriptor",
        Command::Quarantine { .. } => "Quarantine",
        Command::Readmit { .. } => "Readmit",
    }
}

/// A concise description of a notification, for the trace.
/// The one-word form of a read's verdict, for the trace line.
///
/// Split out of `note_desc` because three arms of a `match` inside a `format!` inside a forty-arm `match`
/// is where a function stops being readable — and because the three words are the distinction #215 exists to
/// make, so they deserve a name rather than being buried in a formatting expression.
fn read_word(outcome: &ReadOutcome) -> &'static str {
    match outcome {
        ReadOutcome::Found(_) => "hit",
        ReadOutcome::Absent => "miss",
        ReadOutcome::Inconclusive => "inconclusive",
    }
}

/// What the node did about an admission refusal, for the trace line.
///
/// Split out for the same reason [`read_word`] was: a four-arm `match` inside a forty-arm `match` is where a
/// function stops being readable, and the split the words carry is the one #199 exists to make. Two of the
/// four are marked DEAD END in the text, because a scenario reading a trace needs to see at a glance that
/// the run is not going to resolve itself — the number alone reads like progress.
fn admission_desc(outcome: &AdmissionOutcome) -> String {
    match outcome {
        AdmissionOutcome::Repaid { bits } => format!("AdmissionRefused (re-minted at {bits} bits)"),
        AdmissionOutcome::AlreadySufficient { paid, asked } => {
            format!("AdmissionRefused (already pays {paid} >= {asked} asked)")
        }
        AdmissionOutcome::AboveCeiling { asked, ceiling } => {
            format!("AdmissionRefused (DEAD END: {asked} asked, ceiling {ceiling}, spent nothing)")
        }
        AdmissionOutcome::NoGuidance => "AdmissionRefused (DEAD END: no price given)".to_owned(),
    }
}

fn note_desc(note: &Notification) -> String {
    match note {
        Notification::Delivered { from, .. } => format!("Delivered from {}", fmt_coord(*from)),
        Notification::App { from, .. } => format!("App from {}", fmt_coord(*from)),
        Notification::RendezvousLine(l) => format!("RendezvousLine {}", fmt_coord(*l)),
        Notification::HostRegistered { service_tag } => {
            format!("HostRegistered {}", short_digest(service_tag))
        }
        Notification::PeerDown(p) => format!("PeerDown {}", fmt_coord(*p)),
        // The length, not the bytes: a durable snapshot is the whole store and a trace that inlined it would
        // be unreadable, while the size is the quantity a scenario about persistence actually watches.
        Notification::Snapshot(bytes) => format!("Snapshot {} bytes", bytes.len()),
        // The footprint as points, not as a number: `degraded=20` makes a reader do binary in their head,
        // and the whole reason this rides beside the syndrome is that a reader needs the SET.
        Notification::Liveness { degraded, alive, .. } => {
            let down: Vec<String> =
                (0..8).filter(|i| degraded & (1u8 << i) != 0).map(|i| i.to_string()).collect();
            if down.is_empty() {
                format!("Liveness alive={alive} all points fresh")
            } else {
                format!("Liveness alive={alive} down=[{}]", down.join(" "))
            }
        }
        // The data-path plane: only the stations that actually fired, since a line printing every station at
        // zero buries the two that moved — which is the failure mode the plane exists to end, not repeat.
        Notification::DataPath { stations, gather } => {
            let hit: Vec<String> = stations
                .iter()
                .filter(|o| o.count > 0)
                .map(|o| match o.line {
                    Some([x, y, z]) => format!("{}@{x}:{y}:{z}={}", o.station.name(), o.count),
                    None => format!("{}={}", o.station.name(), o.count),
                })
                .collect();
            let clock = match gather {
                GatherHealth::Measured { srtt, var } => format!(
                    "gather srtt={}ms var={}ms",
                    srtt.as_nanos() / 1_000_000,
                    var.as_nanos() / 1_000_000
                ),
                GatherHealth::Unmeasured => "gather=unmeasured".to_owned(),
                GatherHealth::NoGatherPath => "gather=n/a".to_owned(),
            };
            format!("DataPath [{}] {clock}", hit.join(" "))
        }
        // Rendered as `-` for a role with no sensor and the number for one with a reading, because `Some(0)`
        // and `None` are the distinction the report exists to carry and `{:?}` buries it in six words of noise.
        Notification::LoadReport { per_role } => {
            let cells: Vec<String> =
                per_role.iter().map(|r| r.map_or_else(|| "-".to_owned(), |v| v.to_string())).collect();
            format!("LoadReport [{}]", cells.join(" "))
        }
        Notification::EpochFloor { millis } => match millis {
            Some(ms) => format!("EpochFloor {ms}ms"),
            None => "EpochFloor (no sustainable cadence)".to_owned(),
        },
        Notification::AdmissionRefused { outcome } => admission_desc(outcome),
        Notification::Verdict(v) => format!("Verdict {v:?}"),
        Notification::Rerouted { around, via } => {
            format!("Rerouted {}→via {}", fmt_coord(*around), fmt_coord(*via))
        }
        Notification::Repaired(c) => format!("Repaired {}", fmt_coord(*c)),
        Notification::Quarantined(c) => format!("Quarantined {}", fmt_coord(*c)),
        Notification::Grey(c) => format!("Grey {}", fmt_coord(*c)),
        Notification::Escalated(Escalation::Faults(mask)) => format!("Escalated {mask:#09b}"),
        Notification::Escalated(Escalation::CoherenceCollapse) => "Escalated coherence-collapse".to_string(),
        Notification::Escalated(Escalation::UnsupportedCritical { type_code, from }) => {
            format!("Escalated unsupported-critical {type_code:#04x} from {}", fmt_coord(*from))
        }
        Notification::Escalated(Escalation::BeaconShareMismatch) => {
            "Escalated beacon-share-mismatch".to_owned()
        }
        Notification::Decoupled => "Decoupled".to_owned(),
        Notification::Bound => "Bound".to_owned(),
        Notification::Stored(k) => format!("Stored {}", short_digest(k)),
        Notification::Retrieved { key, outcome } => {
            format!("Retrieved {} ({})", short_digest(key), read_word(outcome))
        }
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
        Notification::DkgDiverged { agreed, heard } => {
            format!("DkgDiverged agreed={agreed} heard={heard}")
        }
        Notification::BeaconReady { epoch, seed } => {
            format!("BeaconReady {epoch} {}", short_digest(seed))
        }
        Notification::Reseated { old, new } => {
            format!("Reseated {}→{}", fmt_coord(*old), fmt_coord(*new))
        }
        Notification::PeerMoved { old, new } => {
            format!("PeerMoved {}→{}", fmt_coord(*old), fmt_coord(*new))
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
    /// The latest DIAKRISIS diagnostic verdict each node reached (`Notification::Verdict`), banked the
    /// same way — the diagnosis layer, distinct from the coherence frame.
    latest_verdict: BTreeMap<Triple, Verdict>,
    /// Nodes that have **stopped reading** — see [`stop_consuming`](Sim::stop_consuming). Frames addressed
    /// to one of these do not vanish: the transport holds them, which is the ninth axis (#246).
    not_consuming: BTreeSet<Triple>,
    /// Per-destination held frames, oldest first. Bounded by [`fanos_quic::inbound_frame_capacity`]; a
    /// sender that fills it is refused rather than buffered further, which is where production's writer
    /// would block instead.
    held: BTreeMap<Triple, VecDeque<(Triple, Vec<u8>)>>,
    /// Hand-back slot for [`hold_for_deaf_receiver`](Sim::hold_for_deaf_receiver) — see its doc.
    pending_frame: Option<Vec<u8>>,
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
            latest_verdict: BTreeMap::new(),
            not_consuming: BTreeSet::new(),
            held: BTreeMap::new(),
            pending_frame: None,
        }
    }

    /// **Stop `node` reading** — the ninth transport axis (#246).
    ///
    /// The sim's transport had four axes (latency, jitter, loss, partition) and a message was either
    /// delivered or lost; nothing could WAIT. That made the whole class #245 belongs to invisible by
    /// construction — a transport library buffering on our behalf, bounded only by its own default — and a
    /// run that could not find it read as "clean" rather than "not measured".
    ///
    /// A node that has stopped reading is **not** partitioned and **not** down: frames addressed to it are
    /// held, up to [`fanos_quic::inbound_frame_capacity`], and arrive when it resumes. Those three states
    /// are genuinely different and production tells them apart, so the sim must too.
    pub fn stop_consuming(&mut self, node: Triple) {
        self.not_consuming.insert(node);
    }

    /// Resume reading, delivering everything held for `node` in arrival order at the current clock.
    ///
    /// Ordered, because the transport is per-stream ordered and a reader that catches up sees its backlog
    /// as it was sent — reordering here would fabricate a defect the wire cannot produce.
    pub fn resume_consuming(&mut self, node: Triple) {
        self.not_consuming.remove(&node);
        let backlog = self.held.remove(&node).unwrap_or_default();
        for (from, frame) in backlog {
            self.schedule(self.clock, Event::Deliver { to: node, from, frame });
        }
    }

    /// How many frames the transport is holding for `node` right now — the observable the axis exists for.
    #[must_use]
    pub fn held_for(&self, node: Triple) -> usize {
        self.held.get(&node).map_or(0, VecDeque::len)
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

    /// The number of nodes (alive or crashed) in the sim.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
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
                let verdict = self.latest_verdict.get(&coord).cloned();
                NodeState { coord, alive: slot.status == Status::Alive, coherence, verdict }
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


    /// Hold a frame for a receiver that has **stopped reading**, or refuse it at the capacity boundary.
    ///
    /// `true` means this frame's fate is settled here and the network model must not be consulted. When it
    /// returns `false` the frame is handed back through `pending_frame` — an owned `Vec<u8>` cannot be
    /// returned by reference and cloning every frame to keep a tidy signature would tax every ordinary send
    /// for a branch that fires only in a retention scenario.
    fn hold_for_deaf_receiver(&mut self, from: Triple, to: Triple, name: &str, frame: Vec<u8>) -> bool {
        if !self.not_consuming.contains(&to) {
            self.pending_frame = Some(frame);
            return false;
        }
        let capacity = fanos_quic::inbound_frame_capacity();
        let queue = self.held.entry(to).or_default();
        let room = queue.len() < capacity;
        if room {
            queue.push_back((from, frame));
        }
        let depth = queue.len();
        if room {
            self.report.metrics.frames_withheld += 1;
            self.log(format!(
                "hold {name} {}→{} ({depth}/{capacity})",
                fmt_coord(from),
                fmt_coord(to)
            ));
        } else {
            // The back-pressure boundary. **What the sim cannot model, stated rather than hidden:**
            // production's sender BLOCKS here — its next `open_uni` waits on the peer's stream limit — and a
            // sans-I/O engine emitting fire-and-forget `Send` effects has no way to wait. So the frame is
            // refused and counted, which gets the arithmetic right (nothing more is pinned) and the timing
            // wrong (the sender carries on instead of stalling). A scenario about throughput under a stalled
            // reader must read `frames_backpressured`, not the delivery count.
            self.report.metrics.frames_backpressured += 1;
            self.log(format!("backpressure {name} {}→{} (holding {depth})", fmt_coord(from), fmt_coord(to)));
        }
        true
    }

    fn apply(&mut self, node: Triple, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                // **A flood is every peer this tier can reach, which here is the whole membership.** The
                // abstract network has no connection table — that is the one thing this simulator models
                // differently from production, and it is exactly the difference the fidelity rule permits —
                // so "the connections I hold" becomes "every other node in the cell". Expanded into per-peer
                // sends rather than delivered specially, so loss, delay, oversize and backpressure apply per
                // link precisely as they do to addressed traffic; a flood that bypassed the network model
                // would make every scenario read it as free.
                Effect::Flood { frame } => {
                    let peers: Vec<Triple> = self.nodes.keys().copied().filter(|&c| c != node).collect();
                    for to in peers {
                        self.apply(node, std::vec![Effect::Send { to, frame: frame.clone() }]);
                    }
                }
                Effect::Send { to, frame } => {
                    self.report.metrics.frames_sent += 1;
                    let name = frame_name(&frame);
                    // Retention (#246) is asked BEFORE the network verdict, and the order is the claim: a
                    // receiver that has stopped reading is not a lossy link, so letting an `rng.chance`
                    // delete a frame production would have HELD reports loss where the truth is backlog.
                    if self.hold_for_deaf_receiver(node, to, &name, frame) {
                        continue;
                    }
                    let Some(frame) = self.pending_frame.take() else { continue };
                    let wire = crate::network::wire_len_of(frame.len());
                    match self.net.deliver(node, to, wire, &mut self.rng) {
                        Delivery::After(d) => {
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
                        }
                        // **Counted apart from loss, and this is the point of the axis (#195).** An oversize
                        // frame is not bad luck: production's reader discards it on every run while
                        // `write_all` reports success, so a scenario that saw it inside `frames_dropped`
                        // would read a deterministic protocol defect as a lossy network.
                        Delivery::Oversize { wire_len, ceiling } => {
                            self.report.metrics.frames_oversize += 1;
                            self.log(format!(
                                "drop[oversize] {name} {}→{} wire={wire_len} ceiling={ceiling}",
                                fmt_coord(node),
                                fmt_coord(to)
                            ));
                        }
                        Delivery::Lost | Delivery::Partitioned => {
                            self.report.metrics.frames_dropped += 1;
                            self.log(format!(
                                "drop[net] {name} {}→{}",
                                fmt_coord(node),
                                fmt_coord(to)
                            ));
                        }
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
                        // Three counters, because the instrument must be able to SEE the distinction
                        // production now draws (#215). A run whose reads all end inconclusive and one whose
                        // reads all find nothing look identical under two counters, and only the first is a
                        // fault of the cell rather than of the workload.
                        Notification::Retrieved { outcome: ReadOutcome::Found(_), .. } => m.retrieval_hits += 1,
                        Notification::Retrieved { outcome: ReadOutcome::Absent, .. } => m.retrieval_misses += 1,
                        Notification::Retrieved { outcome: ReadOutcome::Inconclusive, .. } => {
                            m.retrieval_inconclusive += 1;
                        }
                        Notification::DataLost { .. } => m.data_losses += 1,
                        Notification::Observed(_) => m.observations += 1,
                        _ => {}
                    }
                    // Bank this node's latest coherence frame + diagnostic verdict for O(1) fleet
                    // snapshots (the `m` borrow above has ended, so these fields are free to touch).
                    match &note {
                        Notification::Observed(bytes) => {
                            self.latest_observed.insert(node, bytes.clone());
                        }
                        Notification::Verdict(v) => {
                            self.latest_verdict.insert(node, v.clone());
                        }
                        _ => {}
                    }
                    self.log(format!("notify {} {}", fmt_coord(node), note_desc(&note)));
                    self.report.notifications.push(Observed { node, at: self.clock, note });
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
