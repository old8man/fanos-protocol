//! Fleet-scale state inspection — the cross-node aggregation the operator dashboard and CLI read.
//!
//! The [`Engine`](fanos_ports::Engine) trait is deliberately minimal (`step` + `address`), so a node's
//! internals are not queryable. But every node already *emits* its coherence self-model each telemetry
//! window as a `Notification::Observed(CoherenceFrame)` (the reflex runs every heartbeat since audit
//! #122, and [`Command::Observe`](fanos_ports::Command::Observe) forces one on demand). [`Sim`] banks the
//! latest such frame per node, and [`Sim::fleet_snapshot`] folds those — with ground-truth liveness and
//! the run's aggregate [`Metrics`] — into a [`FleetSnapshot`]: one [`NodeState`] per node plus the
//! cluster [`ClusterStats`]. This is the data contract the ratatui dashboard renders, and it scales from
//! one node to a whole hierarchy because banking is `O(1)` per emission and the snapshot is `O(N)`.
//!
//! [`Sim`]: crate::Sim
//! [`Sim::fleet_snapshot`]: crate::Sim::fleet_snapshot

use fanos_runtime::Triple;
use fanos_telemetry::{AlarmLevel, CoherenceSnapshot, Regime};

use crate::metrics::Metrics;

/// One node's observable state: its coordinate, ground-truth liveness, and latest coherence self-model
/// (absent until the node has published its first telemetry window).
#[derive(Clone, Debug, PartialEq)]
pub struct NodeState {
    /// The node's overlay coordinate.
    pub coord: Triple,
    /// Ground-truth liveness (the sim knows it; a real fleet infers it from heartbeats).
    pub alive: bool,
    /// The node's most recent coherence snapshot, if it has published one.
    pub coherence: Option<CoherenceSnapshot>,
}

impl NodeState {
    /// This node's integration Φ, if known.
    #[must_use]
    pub fn phi(&self) -> Option<f64> {
        self.coherence.as_ref().map(|c| c.phi)
    }

    /// Whether this node warrants operator attention — crashed, or reporting a fault or a non-healthy
    /// alarm. The dashboard's "concerns" list is exactly these.
    #[must_use]
    pub fn is_concern(&self) -> bool {
        !self.alive
            || self
                .coherence
                .as_ref()
                .is_some_and(|c| c.faulted || c.alarm != AlarmLevel::Healthy)
    }
}

/// Per-regime node counts (the coherence-band distribution across the fleet).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RegimeCounts {
    /// `Regime::Aggregate` — too weakly coupled to bind (`Φ < 1`).
    pub aggregate: usize,
    /// `Regime::CollectiveSubject` — the healthy, self-modelling window.
    pub collective_subject: usize,
    /// `Regime::OverCoupled` — over-coupled, losing the self-model (`R < 1/3`).
    pub over_coupled: usize,
}

impl RegimeCounts {
    fn tally(&mut self, r: Regime) {
        match r {
            Regime::Aggregate => self.aggregate += 1,
            Regime::CollectiveSubject => self.collective_subject += 1,
            Regime::OverCoupled => self.over_coupled += 1,
        }
    }
}

/// Per-alarm node counts (the health-severity distribution across the fleet).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AlarmCounts {
    /// `AlarmLevel::Healthy`.
    pub healthy: usize,
    /// `AlarmLevel::Integration` — the earliest warning (`Φ < 1`).
    pub integration: usize,
    /// `AlarmLevel::Structure` — degraded (`Φ < 1` and `P < 2/N`).
    pub structure: usize,
}

impl AlarmCounts {
    fn tally(&mut self, a: AlarmLevel) {
        match a {
            AlarmLevel::Healthy => self.healthy += 1,
            AlarmLevel::Integration => self.integration += 1,
            AlarmLevel::Structure => self.structure += 1,
        }
    }
}

/// The cluster-level rollup a dashboard shows above the per-node detail. Coherence means are taken over
/// *reporting* nodes only (those that have published a window); `NaN` when none have.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ClusterStats {
    /// Total nodes in the fleet.
    pub total: usize,
    /// How many are alive.
    pub alive: usize,
    /// How many have published a coherence snapshot.
    pub reporting: usize,
    /// How many are reporting a fault.
    pub faulted: usize,
    /// How many are `ready` (booted, integrated, healthy).
    pub ready: usize,
    /// Mean integration Φ over reporting nodes.
    pub mean_phi: f64,
    /// Minimum Φ over reporting nodes — the worst-integrated node in the fleet.
    pub min_phi: f64,
    /// Mean purity P over reporting nodes.
    pub mean_purity: f64,
    /// Mean reflection R over reporting nodes.
    pub mean_reflection: f64,
    /// The coherence-band distribution over reporting nodes.
    pub regimes: RegimeCounts,
    /// The alarm-level distribution over reporting nodes.
    pub alarms: AlarmCounts,
}

impl Default for ClusterStats {
    fn default() -> Self {
        Self {
            total: 0,
            alive: 0,
            reporting: 0,
            faulted: 0,
            ready: 0,
            mean_phi: f64::NAN,
            min_phi: f64::NAN,
            mean_purity: f64::NAN,
            mean_reflection: f64::NAN,
            regimes: RegimeCounts::default(),
            alarms: AlarmCounts::default(),
        }
    }
}

impl ClusterStats {
    /// Roll a set of node states up into cluster statistics. Works over one cell's nodes or a whole
    /// federation's — coordinate collisions across cells are irrelevant here (this counts, it does not
    /// key). Coherence means are over *reporting* nodes; `NaN` when none report.
    #[must_use]
    pub fn from_nodes<'a>(nodes: impl IntoIterator<Item = &'a NodeState>) -> Self {
        let mut stats = ClusterStats::default();
        let (mut sum_phi, mut sum_p, mut sum_r) = (0.0, 0.0, 0.0);
        let mut min_phi = f64::INFINITY;
        for node in nodes {
            stats.total += 1;
            if node.alive {
                stats.alive += 1;
            }
            if let Some(c) = &node.coherence {
                stats.reporting += 1;
                if c.faulted {
                    stats.faulted += 1;
                }
                if c.ready {
                    stats.ready += 1;
                }
                sum_phi += c.phi;
                sum_p += c.purity;
                sum_r += c.reflection;
                min_phi = min_phi.min(c.phi);
                stats.regimes.tally(c.regime);
                stats.alarms.tally(c.alarm);
            }
        }
        if stats.reporting > 0 {
            let n = stats.reporting as f64;
            stats.mean_phi = sum_phi / n;
            stats.mean_purity = sum_p / n;
            stats.mean_reflection = sum_r / n;
            stats.min_phi = min_phi;
        }
        stats
    }

    /// The fraction of the fleet that is alive (`0.0` for an empty fleet).
    #[must_use]
    pub fn alive_fraction(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.alive as f64 / self.total as f64
        }
    }

    /// Whether the fleet as a whole is healthy: every reporting node integrated (`Φ ≥ 1`, no
    /// `Structure`/`Integration` alarm) and none faulted.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.faulted == 0 && self.alarms.integration == 0 && self.alarms.structure == 0
    }
}

/// A whole-fleet snapshot: the cluster rollup, every node's state (ordered by coordinate), and the run's
/// cumulative [`Metrics`]. Cheap to take (`O(N)`), so a dashboard can poll it every frame.
#[derive(Clone, Debug)]
pub struct FleetSnapshot {
    /// Virtual time (nanoseconds) at which the snapshot was taken.
    pub at_nanos: u64,
    /// The cluster-level rollup.
    pub stats: ClusterStats,
    /// Every node's state, ordered by coordinate.
    pub nodes: Vec<NodeState>,
    /// The run's cumulative metrics (frames sent/delivered/dropped, reroutes, repairs, …).
    pub metrics: Metrics,
}

impl FleetSnapshot {
    /// Build the rollup from the per-node states. Kept here (not in `Sim`) so it is unit-testable on
    /// synthetic node lists and reused by any future non-`Sim` fleet source.
    #[must_use]
    pub fn from_nodes(at_nanos: u64, nodes: Vec<NodeState>, metrics: Metrics) -> Self {
        let stats = ClusterStats::from_nodes(&nodes);
        Self { at_nanos, stats, nodes, metrics }
    }

    /// The nodes that warrant operator attention (crashed or alarming), for a dashboard's focus list.
    pub fn concerns(&self) -> impl Iterator<Item = &NodeState> {
        self.nodes.iter().filter(|n| n.is_concern())
    }
}
