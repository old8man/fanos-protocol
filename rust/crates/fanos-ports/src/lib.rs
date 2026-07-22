//! The environment ports: virtual time, and the `Input`/`Effect` contract (see
//! `docs/architecture.md`).
//!
//! These are the *only* channel between a node engine and the world. The engine never calls a
//! clock, socket, or RNG — it receives [`Input`]s and returns [`Effect`]s, and a driver (the
//! simulator, or a real network stack) performs them. Addresses on the wire are the raw
//! projective coordinate triple, the field-agnostic form the transport routes on.
//!
//! This is the sans-I/O **contract**, extracted to its own leaf crate (audit #73/#125) so a driver or a
//! sibling engine can depend on the vocabulary — `Command`/`Input`/`Effect`/`Notification`/`Engine` — without
//! linking the concrete `OverlayNode` engine and its whole subsystem stack. Re-exported as
//! `fanos_runtime::ports` for source compatibility.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

// Re-export the coordinate + epoch vocabulary the contract is written in, so a driver or sibling engine
// speaks them through the contract crate without depending on geometry/primitives directly.
pub use fanos_geometry::Triple;
pub use fanos_primitives::Epoch;

/// A monotonic instant in nanoseconds since the run's origin. Virtual — never the wall clock.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
pub struct Instant(pub u64);

/// A span in nanoseconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
pub struct Duration(pub u64);

impl Instant {
    /// Nanoseconds since origin.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }
    /// This instant advanced by `d` (saturating).
    #[must_use]
    pub const fn saturating_add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(d.0))
    }
    /// The span from `earlier` to `self` (saturating at zero).
    #[must_use]
    pub const fn since(self, earlier: Self) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }
}

impl Duration {
    /// A span of `ms` milliseconds.
    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms.saturating_mul(1_000_000))
    }
    /// A span of `us` microseconds.
    #[must_use]
    pub const fn from_micros(us: u64) -> Self {
        Self(us.saturating_mul(1_000))
    }
    /// Nanoseconds.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }
}

/// A timer identifier the engine chooses and the driver echoes back on expiry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct TimerToken(pub u64);

/// An application-level command handed to a node (the app → engine direction).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Command {
    /// Begin periodic liveness heartbeats.
    StartHeartbeat,
    /// Send an application payload to the peer at coordinate `to` (spec §L1 rendezvous).
    Send {
        /// Destination coordinate.
        to: Triple,
        /// Application payload.
        payload: Vec<u8>,
    },
    /// Put a **verbatim** frame on the wire to coordinate `to`, with no overlay framing — the raw-emit
    /// primitive an anonymous client uses to launch a threshold onion at a mixnet combiner or to register
    /// with a rendezvous relay (an `RdvRegister` frame). Unlike [`Send`](Self::Send), which the overlay
    /// wraps in a routed `Route` frame, this leaves `frame` untouched, so the receiving mix/rendezvous
    /// engine sees the exact bytes the client sealed. (A dedicated router node overloads `Send` for this; a
    /// node that also runs the overlay needs the two kept distinct.)
    Emit {
        /// Destination coordinate.
        to: Triple,
        /// The exact frame bytes to put on the wire.
        frame: Vec<u8>,
    },
    /// Run one round of local self-diagnosis and report the verdict (spec §6.9).
    Diagnose,
    /// Emit the cell's current coherence self-observation **without acting** — a sense-only read for
    /// a passive monitor (`fanos_telemetry`), which must not trigger the healing side-effects a full
    /// `Diagnose` does. Produces a `Notification::Observed` (docs/design-telemetry.md §4).
    Observe,
    /// Store `value` in the cell's DHT under `key` (spec §L4). The responsible node is
    /// `MapToPoint(H(key))`; the value is replicated across the cell for LRC availability.
    Put {
        /// The application key (hashed to its storage address).
        key: Vec<u8>,
        /// The value to store.
        value: Vec<u8>,
    },
    /// Retrieve the value stored under `key` from the cell's DHT (spec §L4).
    Get {
        /// The application key.
        key: Vec<u8>,
    },
    /// **Data-availability sample** `key` (spec §L4.3): probe a few unpredictable Fano *lines* to confirm
    /// the value's erasure shards are present, without downloading it — a cheap availability check for a
    /// light client. Produces a [`Notification::Availability`]. By the Steiner soundness (`fanos_code::da`)
    /// two distinct passing line-samples certify availability against any withholding adversary.
    SampleAvailability {
        /// The application key to sample.
        key: Vec<u8>,
    },
    /// Announce this node's presence and `info` (e.g. its public key) to the cell; the
    /// announcement floods so every member learns it (spec §7.8 JOIN).
    Join {
        /// Opaque membership info (a public-key bundle, capabilities) to distribute.
        info: Vec<u8>,
    },
    /// Advance the epoch beacon; the new epoch floods the cell (adopt-max), rotating epoch-derived
    /// rendezvous and shapes (spec §L3 beacon).
    AdvanceEpoch,
    /// Re-seat this node at a new VRF coordinate for the per-epoch reshuffle (spec §L3 "epoch reshuffle",
    /// §3.2): the driver computes `coord = MapToPoint(VRF(sk, node‖epoch‖beacon))` for the new epoch (the
    /// engine is crypto-free and cannot) and hands it here. The engine re-derives its cell neighbours /
    /// index / hierarchical address for `coord`, re-announces, and keeps its (epoch-stable, content-keyed)
    /// store — a placement move, not a data migration (spec §L4: fixed points, flowing nodes). The unpre-
    /// dictable reshuffle is the load-bearing anti-eclipse / anti-path-prediction defence (§3.2 assump. 2).
    Reseat {
        /// The node's new VRF-derived coordinate for the current epoch.
        coord: Triple,
    },
}

/// An input delivered to the engine — the only things it reacts to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
    /// A wire frame arrived from the peer at coordinate `from`.
    Message {
        /// Source coordinate (the transport authenticates this).
        from: Triple,
        /// The canonical wire frame bytes.
        frame: Vec<u8>,
    },
    /// A previously-armed timer fired.
    Timer(TimerToken),
    /// An application command.
    Command(Command),
}

/// An effect the engine asks the driver to perform — the only things it can cause.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Effect {
    /// Transmit a wire frame to the peer at coordinate `to`.
    Send {
        /// Destination coordinate.
        to: Triple,
        /// The canonical wire frame bytes.
        frame: Vec<u8>,
    },
    /// Arm a timer to fire after `after`.
    ArmTimer {
        /// Token echoed back on expiry.
        token: TimerToken,
        /// Delay from now.
        after: Duration,
    },
    /// Notify the application of an event.
    Notify(Notification),
}

/// An application-level notification (the engine → app direction).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Notification {
    /// An application payload was delivered from `from`.
    Delivered {
        /// Source coordinate.
        from: Triple,
        /// The payload.
        payload: Vec<u8>,
    },
    /// An **App-overlay** frame (`FrameType::App`, `0x7*`, spec §7.2) arrived from `from` — the receive path
    /// for an application protocol layered on the overlay (e.g. the TAXIS consensus engine driven as a side-car
    /// task). Distinct from [`Delivered`](Self::Delivered), which is a `Route` payload: an `App` body is the raw
    /// application frame (`fanos_taxis::wire`), dispatched to the app engine rather than surfaced as user data.
    App {
        /// Source coordinate (the sending validator's overlay coordinate).
        from: Triple,
        /// The raw application-frame body.
        body: Vec<u8>,
    },
    /// The rendezvous line computed for a send (for observation, spec §L1).
    RendezvousLine(Triple),
    /// A peer was observed to go down (heartbeat timeout).
    PeerDown(Triple),
    /// A local diagnosis verdict (spec §6.9).
    Verdict(fanos_diakrisis::Verdict),
    /// A mandatory self-observation: the node's encoded `CoherenceFrame` for this window
    /// (`fanos_telemetry`), carrying the 3-bit Fano/Hamming syndrome and the cell's coherence
    /// scalars. Emitted every diagnosis; decode with `fanos_telemetry::CoherenceFrame::decode`. The
    /// wire bytes (not the struct) are carried so this stays a plain, `Eq` payload — the same bytes a
    /// node gossips or publishes (docs/design-telemetry.md).
    Observed(Vec<u8>),
    /// Self-healing: traffic for the (down) node `around` is now served by the co-linear
    /// survivor `via` — the projective LRC reroute (spec §L4, §6.7).
    Rerouted {
        /// The down node being routed around.
        around: Triple,
        /// The surviving co-linear node now serving its data.
        via: Triple,
    },
    /// Self-healing: the down node's shard was regenerated by peeling (spec §6.3, V20).
    Repaired(Triple),
    /// Self-healing: a structurally inconsistent (Byzantine) member was excluded (spec §6.2).
    Quarantined(Triple),
    /// Diagnosis: a **grey** member (spec §6.3) — heartbeat-present but lossy/slow on *all* its channels —
    /// was localized from the polar minimum-incident reading of the cell's measured per-channel loss. Grey is
    /// degradation, not a lie, so it is *reported* for observability (and left to higher-layer rerouting),
    /// never quarantined — a possibly-honest slow node must not be punished.
    Grey(Triple),
    /// Self-healing: the local cell could not recover the listed Fano nodes (a hyperoval stopping
    /// set, or beyond the `Φ`-budget) and escalated them to the parent cell (spec §6.3, §6.7).
    Escalated(u8),
    /// Self-healing: the cascade early-warning fired while every node was still live; the cell
    /// pre-emptively shed correlation to restore headroom (spec §2.7, §6.5).
    Decoupled,
    /// Self-healing: after shedding, the cell's behavioural coherence fell back to the collective-subject
    /// band, so the node re-integrated (undid its decoupling) — the homeostat's `Bind` band control.
    Bound,
    /// A DHT `Put` was acknowledged by the responsible node (spec §L4); carries the key digest.
    Stored([u8; 32]),
    /// A DHT `Get` completed (spec §L4): the value if found, else `None`; carries the key digest.
    Retrieved {
        /// The 32-byte key digest.
        key: [u8; 32],
        /// The retrieved value, or `None` if the cell held no value for the key.
        value: Option<Vec<u8>>,
    },
    /// A DHT value was determined **permanently unrecoverable** (audit R-C3). A node that holds a shard of
    /// `key` — so the value provably WAS stored — gathered every available shard from the cell and the
    /// present set is a stopping set: more shard-homes than the `[7,3,4]` erasure code tolerates (`> 3`
    /// points, or a hyperoval) have been lost. Distinct from a `Retrieved { value: None }` miss (transient,
    /// or a never-stored key): this is durable, accounted loss, recorded in the node's loss ledger at `epoch`
    /// so it is visible rather than silent. A hierarchical cross-cell reconstruction path (R-C3 full) would
    /// consume this to attempt a parent-tier repair.
    DataLost {
        /// The 32-byte digest of the lost key.
        key: [u8; 32],
        /// The epoch at which the loss was accounted.
        epoch: Epoch,
    },
    /// A [`Command::SampleAvailability`] completed (spec §L4.3): whether the sampled Fano lines were all
    /// present. `available = true` certifies the value is retrievable (Steiner soundness, `fanos_code::da`);
    /// `false` means a sampled line was incomplete — inconclusive, retry or fall back to a full read.
    Availability {
        /// The 32-byte key digest sampled.
        key: [u8; 32],
        /// Whether every sampled line's shards were present.
        available: bool,
    },
    /// A cell member announced itself (spec §7.8 JOIN): its coordinate and info (e.g. public key).
    MemberJoined {
        /// The joining member's coordinate.
        coord: Triple,
        /// Its announced info.
        info: Vec<u8>,
    },
    /// The epoch beacon advanced to this value (spec §L3).
    EpochAdvanced(Epoch),
    /// A distributed key generation completed (spec §L6): the 32-byte joint public key the cell
    /// agreed on, whose secret no single node holds.
    DkgComplete([u8; 32]),
    /// The distributed randomness **beacon** produced (or adopted) an epoch's public seed (spec §L3,
    /// audit E5): a threshold of anchors' partials combined and verified. The `seed` is public and
    /// unpredictable-until-now; a driver folds it into the rendezvous meeting line and advances the
    /// epoch (rotating the E4 onion keys). Distinct from [`EpochAdvanced`](Self::EpochAdvanced), which
    /// is the bare epoch counter — this carries the verified randomness.
    BeaconReady {
        /// The epoch this seed is the beacon for.
        epoch: Epoch,
        /// The 32-byte public beacon seed.
        seed: [u8; 32],
    },
    /// This node re-seated its coordinate for the per-epoch reshuffle (in response to
    /// [`Command::Reseat`], spec §L3): it moved from `old` to `new`. A driver rebuilds its HELLO
    /// proof-of-coordinate for the new coordinate, and the simulator re-keys the node at its new address so
    /// frames continue to route to it. Storage is untouched (content addressing is epoch-stable, §L4).
    Reseated {
        /// The coordinate the node held before the reshuffle.
        old: Triple,
        /// The coordinate the node holds after the reshuffle.
        new: Triple,
    },
    /// The **differential-DDoS load-balance prescription** (spec §6.7): on entering the homeostat's
    /// under-coupled (`Aggregate`/`Bind`) band — the regime a load hotspot induces by decorrelating the cell
    /// — the node publishes the projective load state it sensed. `loads[i]` is point `i`'s measured relay
    /// load (the node observes ALL `N` points because its `q+1` lines cover the plane, `Aut(PG(2,q))`
    /// 2-transitivity). The **derived** response is `fanos_diakrisis::loadbalance::balance_exact(loads)` —
    /// the exact uniform mean `Σloads/N` at every point in one step (the two-eigenvalue projective diffusion,
    /// contraction `λ₂ = q/(q+1)²`), which dissolves the hotspot into the whole cell with no local extremum.
    /// A load balancer / routing layer applies that redistribution; the engine, being sans-I/O, prescribes.
    Rebalance {
        /// The measured per-point relay load over the base Fano cell (index = canonical point index).
        loads: [u32; 7],
    },
}

/// The sans-I/O node engine: a pure state machine over virtual time.
///
/// A driver calls [`Engine::step`] with the current instant and one input, and performs the
/// returned effects. The engine holds no handles to time, transport, or randomness.
pub trait Engine {
    /// Advance the engine by processing one input at `now`, returning the effects to perform.
    fn step(&mut self, now: Instant, input: Input) -> Vec<Effect>;

    /// This node's own coordinate (its overlay address).
    fn address(&self) -> Triple;
}
