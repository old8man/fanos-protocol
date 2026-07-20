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

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod overlay;

// The sans-I/O contract now lives in the leaf crate `fanos-ports` (audit #73/#125); re-exported here as
// `ports` so existing `fanos_runtime::ports::*` and the crate-root re-exports below keep resolving.
pub use fanos_ports as ports;

// The reliable-stream layer now lives in the transport-agnostic leaf crate `fanos-stream` (audit #73);
// re-exported here as `stream` so existing `fanos_runtime::stream::*` paths keep resolving.
pub use fanos_stream as stream;

pub use overlay::{Config, OverlayNode};
pub use ports::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};

// Re-export the wire address type so drivers and apps speak the same coordinates.
pub use fanos_geometry::Triple;
// Re-export the protocol epoch — core engine vocabulary (`EpochAdvanced`, `BeaconReady`), so drivers
// and sibling engines (e.g. the beacon) speak it without reaching past the runtime.
pub use fanos_primitives::Epoch;
