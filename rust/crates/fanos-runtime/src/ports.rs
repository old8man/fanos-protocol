//! The environment ports: virtual time, and the `Input`/`Effect` contract (see
//! `docs/architecture.md`).
//!
//! These are the *only* channel between a node engine and the world. The engine never calls a
//! clock, socket, or RNG — it receives [`Input`]s and returns [`Effect`]s, and a driver (the
//! simulator, or a real network stack) performs them. Addresses on the wire are the raw
//! projective coordinate triple, the field-agnostic form the transport routes on.

use alloc::vec::Vec;

use fanos_geometry::Triple;
use fanos_primitives::Epoch;

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
    /// Announce this node's presence and `info` (e.g. its public key) to the cell; the
    /// announcement floods so every member learns it (spec §7.8 JOIN).
    Join {
        /// Opaque membership info (a public-key bundle, capabilities) to distribute.
        info: Vec<u8>,
    },
    /// Advance the epoch beacon; the new epoch floods the cell (adopt-max), rotating epoch-derived
    /// rendezvous and shapes (spec §L3 beacon).
    AdvanceEpoch,
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
