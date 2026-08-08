//! # fanos-runtime — the sans-I/O node engine
//!
//! The FANOS node as a **pure state machine**: it reacts to [`Input`]s (a received frame, a
//! fired timer, an application command) and returns [`Effect`]s (send a frame, arm a timer,
//! notify the app), touching no clock, socket, or RNG. A *driver* — the simulator today
//! ([`fanos-sim`](https://docs.rs/fanos-sim)), a real QUIC stack later — supplies the
//! environment and performs the effects. The same engine runs under both, so what the
//! simulator exercises is exactly what ships (see `docs/architecture.md`).
//!
//! * [`ports`] — the environment contract: [`Instant`], [`Input`], [`Effect`], [`Engine`].
//! * [`overlay`] — [`OverlayNode`], the base node: liveness, rendezvous, DIAKRISIS diagnosis.
//! * [`stream`] — reliable ordered byte-streams; re-exported from the transport-agnostic leaf crate
//!   [`fanos-stream`](fanos_stream), which carries no engine dependency (audit #73).

// `variant_count` backs the compile-time completeness assertion on `ReadRefusal::ALL`: a refusal rule
// added without a tag would print as a bare number to an operator, which is the failure #209 exists to
// prevent. A build error is the only place that can catch it.
#![feature(variant_count)]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

/// Every `encode_*`/`parse_*` for the overlay's wire bodies — see [`frames`].
mod frames;
/// The DIAKRISIS self-healing reflex, split out of [`overlay`] — see [`healer`].
mod healer;
/// The cell's membership view and admission gate — see [`membership`].
mod membership;
/// Next-hop routing and per-peer liveness — see [`router`].
mod router;
/// The local content store and in-flight request state — see [`store`].
mod store;
pub use store::snapshot_is_readable;
pub mod overlay;

// The sans-I/O contract now lives in the leaf crate `fanos-ports` (audit #73/#125); re-exported here as
// `ports` so existing `fanos_runtime::ports::*` and the crate-root re-exports below keep resolving.
pub use fanos_ports as ports;

// The reliable-stream layer now lives in the transport-agnostic leaf crate `fanos-stream` (audit #73);
// re-exported here as `stream` so existing `fanos_runtime::stream::*` paths keep resolving.
pub use fanos_stream as stream;

pub use overlay::{
    Config, MAX_PENDING_GETS, MAX_STORE_ENTRIES, MAX_VALUE_LEN, OverlayNode, QUARANTINE_TTL,
    READ_ACCUMULATOR_BYTES, READ_MEMORY_CEILING, READ_PEER_SHARD_QUOTA, ReadRefusal,
    corroboration_quorum,
};
pub use ports::{Command, Duration, Effect, Engine, Escalation, Input, Instant, Notification, TimerToken};

// Re-export the wire address type so drivers and apps speak the same coordinates.
pub use fanos_geometry::Triple;
// Re-export the protocol epoch — core engine vocabulary (`EpochAdvanced`, `BeaconReady`), so drivers
// and sibling engines (e.g. the beacon) speak it without reaching past the runtime.
pub use fanos_primitives::Epoch;
