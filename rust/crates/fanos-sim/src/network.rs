//! The in-memory transport port: latency, loss, partition, **size** and **retention**.
//!
//! ## The axes, and why the list is worth keeping honest
//!
//! For a long time there were three — latency+jitter, loss, partition — and the module said so as if that
//! were the adversarial surface. It was the surface *the tests then needed*, which is a different claim, and
//! two whole defect classes turned out to live in the gap:
//!
//! | axis | asks | added by |
//! |---|---|---|
//! | latency + jitter | how long | original |
//! | loss | does it arrive | original |
//! | partition (hard, soft) | can these two reach each other | original |
//! | **size** | is this frame too big for a real reader | #195 |
//! | **retention** | how many unread frames does the transport hold for us | #246 (in [`crate::Sim`], which owns the queue) |
//!
//! The last two are stated together because they were found the same way and are still confused for one
//! another: size is about the BYTES of one message, retention about the NUMBER of unconsumed ones. Different
//! mechanisms, different fixes, and each hid a CRITICAL that no run of the old model could express (#190,
//! #245). Both take their bound from production — [`fanos_quic::max_wire`] and
//! [`fanos_quic::inbound_frame_capacity`] — rather than restating it.
//!
//! **The standing rule this serves:** the sim differs from production *only* in transport, and it is also
//! the instrument that must pin every defect class. Those two only hold together if the transport models
//! every way transport can fail. A class the model cannot express turns a run that misses it into
//! "clean" rather than "not measured", which is the more dangerous of the two readings.
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

/// What became of one frame handed to the transport.
///
/// Named causes rather than `Option`, so a scenario can assert *why* — see [`NetworkModel::deliver`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[must_use]
pub enum Delivery {
    /// Arrives at the destination after this delay.
    After(Duration),
    /// Sender and receiver are in different hard-partition groups: nothing crosses, ever, until the cut heals.
    Partitioned,
    /// An independent loss draw, or the soft-partition crossing draw — the frame is gone and a retry may work.
    Lost,
    /// The wire form exceeds what a production reader will accept, so a real receiver discards the stream and
    /// the sender's write still reports success (#190). Deterministic: a retry of the same frame fails again.
    Oversize {
        /// The bytes this frame would occupy on the wire.
        wire_len: usize,
        /// [`fanos_quic::max_wire`] — the number `read_to_end` is given in production.
        ceiling: usize,
    },
}

/// The wire bytes a frame of `frame_len` occupies once production's transforms are applied.
///
/// The sim **accounts** for the growth without performing it: obfuscating here would buy nothing (nobody
/// inspects these bytes) while costing every scenario the CPU. What must be identical is the arithmetic, so
/// the one term that grows a frame on every path is taken from the crate that owns it. The relay wrapper is
/// deliberately *not* added: when a frame travels through a hub the engine has already emitted it
/// relay-encoded, so its bytes are in `frame_len` — adding the wrapper here would charge it twice and make
/// the sim refuse frames production accepts.
#[must_use]
pub fn wire_len_of(frame_len: usize) -> usize {
    frame_len + fanos_proteus::MAX_WIRE_OVERHEAD
}

/// The largest wire form a production reader accepts — **imported, never restated** (#195).
///
/// [`fanos_quic::max_wire`] is `MAX_FRAME + relay_overhead() + MAX_WIRE_OVERHEAD`, every term derived in
/// #190. A literal here would track it only until one of them moved, and a simulator that silently disagrees
/// with production is worse than one with no size axis at all: it would report a green run for a frame the
/// real receiver drops.
#[must_use]
pub fn wire_ceiling() -> usize {
    fanos_quic::max_wire()
}

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

    /// What the transport does with one frame — **four outcomes, because there are four causes**.
    ///
    /// This replaced an `Option<Duration>` whose `None` meant "loss *or* partition", a collapse that was
    /// harmless only while those were the sole causes. Adding the size axis (#195) to that shape would have
    /// buried an oversize drop in the same silence — which is precisely the defect #190 was: a frame the
    /// sender believed it had sent, discarded with nothing to read afterwards. A scenario must be able to
    /// assert on the cause, not infer it from an absence.
    pub fn deliver(&self, from: Triple, to: Triple, wire_len: usize, rng: &mut Rng) -> Delivery {
        if !self.reachable(from, to) {
            return Delivery::Partitioned;
        }
        // **The size axis, and it comes first among the random causes on purpose**: it is deterministic. A
        // frame too big for a production reader is dropped on *every* run, and letting an earlier `rng.chance`
        // draw claim it would make a certain failure look intermittent.
        let ceiling = wire_ceiling();
        if wire_len > ceiling {
            return Delivery::Oversize { wire_len, ceiling };
        }
        if self.loss > 0.0 && rng.chance(self.loss) {
            return Delivery::Lost;
        }
        // A soft partition: a message crossing between two soft groups is dropped with `cross_loss` — a lossy
        // but not fully-cut bisection (§6.5 incipient split).
        if self.cross_loss > 0.0 && self.crosses_soft(from, to) && rng.chance(self.cross_loss) {
            return Delivery::Lost;
        }
        let jitter = (rng.unit() * self.jitter.as_nanos() as f64) as u64;
        Delivery::After(Duration(
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
