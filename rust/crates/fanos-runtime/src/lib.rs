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

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod overlay;
pub mod ports;
pub mod stream;

pub use overlay::{Config, OverlayNode};
pub use ports::{Command, Duration, Effect, Engine, Input, Instant, Notification, TimerToken};

// Re-export the wire address type so drivers and apps speak the same coordinates.
pub use fanos_geometry::Triple;
