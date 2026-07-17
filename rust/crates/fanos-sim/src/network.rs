//! The in-memory transport port: latency, loss, and partition models.
//!
//! This substitutes the network. A `Send` effect becomes a delayed `Deliver` input (or is
//! dropped) according to this model — the engine is unchanged whether it runs here or over
//! real UDP.

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
}

impl Default for NetworkModel {
    fn default() -> Self {
        Self {
            base_latency: Duration::from_millis(20),
            jitter: Duration::from_millis(10),
            loss: 0.0,
            partitions: Vec::new(),
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

    /// Heal any partition (fully connect).
    pub fn heal(&mut self) {
        self.partitions.clear();
    }

    /// Whether the network is currently partitioned.
    #[must_use]
    pub fn is_partitioned(&self) -> bool {
        !self.partitions.is_empty()
    }
}
