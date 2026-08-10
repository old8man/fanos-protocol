//! **A long-lived node actor that dies says so** (#251).
//!
//! Sixty-three production `tokio::spawn`s, zero `JoinError` checks anywhere in the tree, and
//! `panic = "abort"` set only on the `maxperf` profile — which CI does not build. A task nobody joins
//! cannot report its own death.
//!
//! ## Holding the handle was never the fix
//!
//! Fifteen files store the returned `JoinHandle` in a `_`-prefixed field, which reads like ownership and is
//! not: tokio's own documentation says a dropped `JoinHandle` **detaches** the task, which "continues
//! running in the background and its return value is lost". So those fields accomplish nothing at all —
//! they neither abort on drop nor report anything. A scan that counted them as supervision (an earlier pass
//! of #251 did) is counting a proxy.
//!
//! ## Why the publishers are the sharp case, not merely the silent one
//!
//! #106 made a *failed directory write* visible: `Station::DirectoryPublishFailed`, tagged by directory.
//! That counter is incremented by the publisher. So when the publisher **dies**, the counter stops rising —
//! and a flat failure counter is exactly what a healthy node looks like. The node is not quiet about the
//! outage; it is *reassuring* about it. That is the same shape as `Durability` reporting `Persisting` after
//! its task panicked ([[a-level-makes-its-reporter-a-liar]]), one layer up: an observable whose only writer
//! is the thing that died.
//!
//! ## What is supervised, and what is deliberately not
//!
//! Only actors whose death is a **capability the node has lost**. Per-connection, per-session and
//! per-request tasks are absent on purpose: their death is how they end, and counting thousands of ordinary
//! completions is how an alarm stops being read. The discriminator is #244's — whether anyone else has a
//! move. A dying session handler is observed by its own peer through a closed stream; nobody observes a
//! dying publisher.
//!
//! The cost is one task parked on a `JoinHandle` that wakes exactly once, ever.

use std::sync::Arc;

use fanos_quic::Client;
use fanos_runtime::ports::stations::Station;
use tokio::task::JoinHandle;
use tracing::{debug, error};

/// Which long-lived node actor a [`Station::ActorDied`] observation is about.
///
/// Separate from `fanos_quic::DriverActor`, which names the six transport loops, because the two crates
/// own different actors and neither can see the other's list. They share the station and are told apart by
/// the tag's range — see [`NodeActor::tag`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeActor {
    /// Publishes this node's onion key each epoch. Dead: no circuit can be sealed through this relay again.
    MixPublisher,
    /// Feeds the local mix directory from the cell's published records. Dead: this node's view freezes and
    /// it seals to keys that have since rotated.
    MixFeeder,
    /// Publishes this node's capability advertisement. Dead: the cell stops assigning it roles.
    CapabilityPublisher,
    /// Publishes this node's measured load. Dead: the cell's role controller divides by a stale number.
    LoadPublisher,
    /// Publishes the ε-private coherence frame. Dead: the census stops seeing this node and reads it as
    /// silent, which is the reading reserved for a node that is actually down.
    CoherencePublisher,
    /// Rotates this node's POROS ingress share. Dead: the line stops rotating and forward secrecy stops
    /// advancing, with nothing refusing anything.
    IngressRotation,
    /// Publishes this node's exit key. Dead: clients keep sealing to a key this node will rotate past.
    ExitPublisher,
    /// Publishes this node's cross-cell health record. Dead: the parent cell stops seeing it.
    HealthPublisher,
    /// Feeds the per-role load sensor from the engine's reports. Dead: every reading freezes at its last
    /// value and the role controller divides by a number that stopped moving — while looking measured.
    LoadSensor,
    /// Drives role assignment each epoch. Dead: `Node::assigned` freezes, so this node reports roles it is
    /// no longer maintaining and the cell counts it as covering them.
    RoleController,
    /// Watches cell liveness for the role controller. Dead: the controller keeps deciding against a
    /// snapshot of the cell that has stopped advancing.
    LivenessWatch,
    /// Steps the TAXIS consensus engine. Dead: this validator falls out of the chain in silence, and the
    /// cell loses one member of its fault budget without anyone being told.
    TaxisEngine,
    /// Issues the wall-clock `AdvanceEpoch` tick. Dead: **nothing** advances the epoch, so the VRF
    /// coordinate, the PROTEUS wire shape and the forward-secure onion keys all stay pinned at genesis for
    /// the node's entire life — the whole moving-target defence off, with every surface reporting healthy.
    EpochDriver,
    /// Re-floods this node's coordinate after a move. Dead: a peer this node is not connected to never
    /// learns where it went, and since that peer holds no address it never dials — permanently.
    MoveAnnouncer,
    /// Watches for a frozen beacon and escalates to the recovery authority. Dead: the cell's only automatic
    /// path out of a stall is gone, so a frozen cell stays frozen (#88) with no one deciding not to act.
    RecoveryTrigger,
}

/// `NodeActor::ALL` is complete, proven by the compiler — same reasoning as `Station::ALL`.
const _: () = assert!(
    NodeActor::ALL.len() == core::mem::variant_count::<NodeActor>(),
    "a NodeActor variant is missing from ALL, so it is invisible to every reader that enumerates"
);

/// The first tag this crate's actors use, leaving the low range to `fanos_quic::DriverActor`.
///
/// **One station, two vocabularies, and the ranges must not overlap** — an operator reading
/// `driver.actor_died tag 3` must get one answer, not two. Disjointness is asserted in
/// `admin::tests::the_two_actor_vocabularies_do_not_collide`, because a comment claiming it would be exactly
/// the kind of promise this codebase keeps finding unkept.
pub const NODE_ACTOR_TAG_BASE: u64 = 64;

/// Every node-actor tag must stay inside the plane's taggable range, or `record_tagged` folds it into the
/// untagged bucket and the vocabulary this module exists to provide is silently discarded — the exact
/// failure `PeerRefused`'s doc records paying for with the wire codes.
///
/// A `const` assert on the HIGHEST tag, not on the base: the base is the part that reads safe, and the
/// highest is the part that can breach.
const _: () = assert!(
    NODE_ACTOR_TAG_BASE + (NodeActor::ALL.len() as u64) <= fanos_runtime::ports::stations::MAX_SKEW_TAG,
    "a node actor's tag is above MAX_SKEW_TAG, so the plane will fold it into the untagged bucket"
);

impl NodeActor {
    /// Every supervised node actor, for a reader that enumerates rather than guesses.
    pub const ALL: &'static [Self] = &[
        Self::MixPublisher,
        Self::MixFeeder,
        Self::CapabilityPublisher,
        Self::LoadPublisher,
        Self::CoherencePublisher,
        Self::IngressRotation,
        Self::ExitPublisher,
        Self::HealthPublisher,
        Self::LoadSensor,
        Self::RoleController,
        Self::LivenessWatch,
        Self::TaxisEngine,
        Self::EpochDriver,
        Self::MoveAnnouncer,
        Self::RecoveryTrigger,
    ];

    /// The discriminant carried in `Observation::tag`, written out so variant order never renumbers an
    /// operator's counters, and offset by [`NODE_ACTOR_TAG_BASE`] so it cannot be read as a driver actor.
    #[must_use]
    pub const fn tag(self) -> u64 {
        NODE_ACTOR_TAG_BASE
            + match self {
                Self::MixPublisher => 0,
                Self::MixFeeder => 1,
                Self::CapabilityPublisher => 2,
                Self::LoadPublisher => 3,
                Self::CoherencePublisher => 4,
                Self::IngressRotation => 5,
                Self::ExitPublisher => 6,
                Self::HealthPublisher => 7,
                Self::LoadSensor => 8,
                Self::RoleController => 9,
                Self::LivenessWatch => 10,
                Self::TaxisEngine => 11,
                Self::EpochDriver => 12,
                Self::MoveAnnouncer => 13,
                Self::RecoveryTrigger => 14,
            }
    }

    /// The operator-facing name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MixPublisher => "mix_publisher",
            Self::MixFeeder => "mix_feeder",
            Self::CapabilityPublisher => "capability_publisher",
            Self::LoadPublisher => "load_publisher",
            Self::CoherencePublisher => "coherence_publisher",
            Self::IngressRotation => "ingress_rotation",
            Self::ExitPublisher => "exit_publisher",
            Self::HealthPublisher => "health_publisher",
            Self::LoadSensor => "load_sensor",
            Self::RoleController => "role_controller",
            Self::LivenessWatch => "liveness_watch",
            Self::TaxisEngine => "taxis_engine",
            Self::EpochDriver => "epoch_driver",
            Self::MoveAnnouncer => "move_announcer",
            Self::RecoveryTrigger => "recovery_trigger",
        }
    }
}

/// Watch `actor` and record its death on the data-path plane, returning a handle to the watcher.
///
/// The returned handle is the **watcher's**, not the actor's, and that is safe precisely because holding
/// either accomplishes nothing: dropping a `JoinHandle` detaches. Callers that stored the actor's handle in
/// a `_`-prefixed field can store this one instead with no change in behaviour.
///
/// Three endings, kept apart in the log line because the operator's next move differs — a panic is a defect,
/// a cancellation is an orderly stop, and a plain return from a loop that should not return is neither. One
/// station for all three: the counter is the alarm, the line says which of them rang it.
///
/// ## Only if nobody asked for it
///
/// Every actor here ends when the node does: the publishers hang on `next_epoch`, whose `watch` sender lives
/// inside the engine, so dropping the last `Client` retires all twelve at once. Judged on the ending alone
/// that is twelve outages per orderly stop, and one false alarm per stop is enough to bury the true one — a
/// publisher that really died at 03:00 sits in the record beside the stop at 09:00 with nothing to sort them
/// by (#257). [`Client::is_stopping`] is the missing half. A panic is excused by neither of its two ways: a
/// defect during shutdown is still a defect.
pub fn supervise(actor: NodeActor, client: &Client, task: JoinHandle<()>) -> JoinHandle<()> {
    let client = Arc::new(client.clone());
    tokio::spawn(async move {
        let ending = task.await;
        let panicked = ending.as_ref().err().is_some_and(tokio::task::JoinError::is_panic);
        if !panicked && client.is_stopping() {
            debug!(actor = actor.name(), "a node actor retired because the node is stopping");
            return;
        }
        let how = match ending {
            Ok(()) => "returned, which this actor is not meant to do while the node runs",
            Err(e) if e.is_panic() => "PANICKED",
            Err(_) => "was cancelled",
        };
        error!(
            actor = actor.name(),
            how,
            "a long-lived node actor stopped; this node has lost that capability and is still running, and \
             the counters that would have shown it are written by the actor that died"
        );
        client.record_station(Station::ActorDied, Some(client.address()), Some(actor.tag()));
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// **A panicking node actor is named on the plane, and only that one (#251).**
    ///
    /// The defect is not that the actor died — it is that the only observable an operator watches for this
    /// class, #106's `DirectoryPublishFailed`, is written *by the actor*. A dead publisher stops failing, so
    /// the counter goes flat, which is what a healthy node looks like.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_node_actor_is_named_and_the_others_are_not() {
        let node = fanos_quic::spawn(
            Box::new(fanos_runtime::OverlayNode::<fanos_field::F2>::new(
                fanos_geometry::Point::at(0),
                fanos_runtime::Config::default(),
            )),
            fanos_quic::Directory::new(),
        )
        .await
        .expect("a node on loopback");
        let client = node.client();

        let count = |tag: u64| {
            client
                .driver_stations()
                .iter()
                .filter(|o| o.station == Station::ActorDied && o.tag == Some(tag))
                .map(|o| o.count)
                .sum::<u64>()
        };

        let watcher = supervise(
            NodeActor::MixPublisher,
            &client,
            tokio::spawn(async { panic!("the mix publisher fell over") }),
        );
        watcher.await.expect("the watcher itself must not die with the actor it watches");

        assert_eq!(
            count(NodeActor::MixPublisher.tag()),
            1,
            "a dead publisher must be named; #106's counter goes FLAT when it dies, which reads healthy"
        );
        assert_eq!(
            count(NodeActor::LoadPublisher.tag()),
            0,
            "and only the one that died — naming them all would say nothing an operator can act on"
        );
    }

    /// **A stopping node retires its actors; it does not lose them (#257).**
    ///
    /// Every actor here ends when the node does — the publishers hang on the beacon `watch`, whose sender
    /// lives inside the engine — so judged on the ending alone an orderly stop files twelve outages. One
    /// false alarm per stop is enough to bury the true one: a publisher that really died at 03:00 would sit
    /// in the record beside the stop at 09:00 with nothing to sort them by.
    ///
    /// Driven through the real [`fanos_quic::NodeHandle::shutdown`], so the *ordering* is under test too and
    /// not just the predicate: the flag is raised before the endpoint closes, and a version that raised it
    /// after would leave this racing the ending it is meant to classify.
    ///
    /// What this does **not** cover is `is_stopping`'s other half — an embedder dropping its `Node` while
    /// the runtime lives, which closes the engine's input instead of the endpoint. That half cannot be
    /// staged from here, because reading the plane afterwards requires holding a `Client`, and holding one
    /// is exactly what keeps the engine alive. It is covered in `fanos-quic`, next to the channel it reads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retiring_actor_is_silent_but_a_panic_during_shutdown_is_not() {
        let node = fanos_quic::spawn(
            Box::new(fanos_runtime::OverlayNode::<fanos_field::F2>::new(
                fanos_geometry::Point::at(0),
                fanos_runtime::Config::default(),
            )),
            fanos_quic::Directory::new(),
        )
        .await
        .expect("a node on loopback");
        let client = node.client();
        let count = |tag: u64| {
            client
                .driver_stations()
                .iter()
                .filter(|o| o.station == Station::ActorDied && o.tag == Some(tag))
                .map(|o| o.count)
                .sum::<u64>()
        };

        node.shutdown();
        assert!(client.is_stopping(), "shutdown must be visible to a supervisor, or the rest proves nothing");

        // Await the WATCHER, not the actor: waiting on the actor would prove only that it ended, leaving the
        // silence below to be read off a watcher that had not run yet — green for the wrong reason.
        supervise(NodeActor::MixPublisher, &client, tokio::spawn(async {}))
            .await
            .expect("the watcher must survive the actor it watches");
        supervise(NodeActor::LoadPublisher, &client, tokio::spawn(async { panic!("during shutdown") }))
            .await
            .expect("the watcher must survive the actor it watches");

        assert_eq!(
            count(NodeActor::MixPublisher.tag()),
            0,
            "an actor that ended because the node is stopping must not be filed as an outage: one false \
             alarm per shutdown is how the one true alarm becomes unreadable"
        );
        assert_eq!(
            count(NodeActor::LoadPublisher.tag()),
            1,
            "a panic is a defect even while stopping — excusing it would hide the one ending that says the \
             code is wrong rather than that the operator asked"
        );
    }
}
