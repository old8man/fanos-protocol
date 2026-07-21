//! The in-memory transport port: latency, loss, and partition models.
//!
//! This substitutes the network. A `Send` effect becomes a delayed `Deliver` input (or is
//! dropped) according to this model — the engine is unchanged whether it runs here or over
//! real UDP.
//!
//! The transport *port* is one method — [`NetworkModel::delay`] `(from, to, rng) -> Option<Duration>`
//! (`None` = dropped). Today one model implements it, and it already spans the adversarial network
//! surface the tests need: independent loss, latency + jitter, and hard partitions. A `Transport`
//! trait over `delay` should be extracted the moment a *second* model exists to be its client (e.g. a
//! trace-driven replay or an asymmetric-partition adversary) — not before, or it is an abstraction
//! with no consumer (cf. the deleted `fanos_primitives::vrf::Vrf`).

use std::collections::BTreeSet;

use fanos_runtime::{Duration, Triple};

use crate::rng::Rng;

/// Latency / loss / partition parameters of the simulated network.
#[derive(Clone, Debug)]
pub struct NetworkModel {
    /// Minimum one-way delivery delay.
    pub base_latency: Duration,
    /// Additional uniform random delay in `[0, jitter)`.
    pub jitter: Duration,
    /// Independent per-message drop probability.
    pub loss: f64,
    /// If non-empty, a complete partition of nodes into groups that can only reach within.
    partitions: Vec<BTreeSet<Triple>>,
    /// A **soft** partition (§6.5 incipient-split research): messages *crossing* between these groups are
    /// dropped with probability [`cross_loss`](Self::cross_loss) instead of hard-cut, so the far side stays
    /// (marginally) reachable and corroborated-alive while the crossing lines read lossy — the exact regime
    /// the loss-weighted Fiedler partition sensor must catch that liveness monitoring cannot.
    soft_partitions: Vec<BTreeSet<Triple>>,
    /// Extra drop probability applied to a message crossing [`soft_partitions`](Self::soft_partitions).
    cross_loss: f64,
}

impl Default for NetworkModel {
    fn default() -> Self {
        Self {
            base_latency: Duration::from_millis(20),
            jitter: Duration::from_millis(10),
            loss: 0.0,
            partitions: Vec::new(),
            soft_partitions: Vec::new(),
            cross_loss: 0.0,
        }
    }
}

impl NetworkModel {
    /// A model with the given base latency, jitter, and loss, fully connected.
    #[must_use]
    pub fn new(base_latency: Duration, jitter: Duration, loss: f64) -> Self {
        Self {
            base_latency,
            jitter,
            loss,
            partitions: Vec::new(),
            soft_partitions: Vec::new(),
            cross_loss: 0.0,
        }
    }

    /// Whether `from` can currently reach `to` (same partition group; self always reachable).
    #[must_use]
    pub fn reachable(&self, from: Triple, to: Triple) -> bool {
        if from == to || self.partitions.is_empty() {
            return true;
        }
        self.partitions
            .iter()
            .any(|group| group.contains(&from) && group.contains(&to))
    }

    /// The delivery delay for a message, or `None` if it is dropped (loss or partition).
    #[must_use]
    pub fn delay(&self, from: Triple, to: Triple, rng: &mut Rng) -> Option<Duration> {
        if !self.reachable(from, to) {
            return None;
        }
        if self.loss > 0.0 && rng.chance(self.loss) {
            return None;
        }
        // A soft partition: a message crossing between two soft groups is dropped with `cross_loss` — a lossy
        // but not fully-cut bisection (§6.5 incipient split).
        if self.cross_loss > 0.0 && self.crosses_soft(from, to) && rng.chance(self.cross_loss) {
            return None;
        }
        let jitter = (rng.unit() * self.jitter.as_nanos() as f64) as u64;
        Some(Duration(
            self.base_latency.as_nanos().saturating_add(jitter),
        ))
    }

    /// Impose a partition: `groups` should cover the participating nodes.
    pub fn partition<I>(&mut self, groups: I)
    where
        I: IntoIterator<Item = BTreeSet<Triple>>,
    {
        self.partitions = groups.into_iter().collect();
    }

    /// Impose a **soft** partition (§6.5): messages crossing between `groups` are dropped with probability
    /// `cross_loss` (a lossy, not fully-cut, bisection), while intra-group traffic is unaffected. Models an
    /// incipient split — the far side stays marginally reachable/alive while the crossing lines read lossy.
    pub fn soft_partition<I>(&mut self, groups: I, cross_loss: f64)
    where
        I: IntoIterator<Item = BTreeSet<Triple>>,
    {
        self.soft_partitions = groups.into_iter().collect();
        self.cross_loss = cross_loss;
    }

    /// Whether `from` and `to` lie in different soft-partition groups (so a message between them crosses).
    fn crosses_soft(&self, from: Triple, to: Triple) -> bool {
        if from == to || self.soft_partitions.is_empty() {
            return false;
        }
        let group_of = |n: Triple| self.soft_partitions.iter().position(|g| g.contains(&n));
        match (group_of(from), group_of(to)) {
            (Some(a), Some(b)) => a != b,
            _ => false, // a node in no soft group is unaffected
        }
    }

    /// Heal any partition (fully connect), hard or soft.
    pub fn heal(&mut self) {
        self.partitions.clear();
        self.soft_partitions.clear();
        self.cross_loss = 0.0;
    }

    /// Whether the network is currently partitioned.
    #[must_use]
    pub fn is_partitioned(&self) -> bool {
        !self.partitions.is_empty()
    }
}
