//! # fanos-quic — the production transport driver
//!
//! FANOS is **sans-I/O**: a node is a pure state machine (`fanos-runtime`) that reacts to `Input`s
//! and returns `Effect`s, touching no clock, socket, or RNG. A *driver* supplies the environment.
//! `fanos-sim` is the deterministic in-process driver used to test the protocol; **this crate is
//! the second driver**, running the *same* engine over a real UDP + QUIC (TLS 1.3) socket. The
//! byte-for-byte engine the simulator exercises is what ships here — that equivalence is the whole
//! point of the architecture (`docs/architecture.md`).
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use fanos_quic::{spawn, Directory};
//! use fanos_runtime::{Config, OverlayNode, Command};
//! use fanos_geometry::Point;
//! use fanos_field::F2;
//!
//! let dir = Directory::new();
//! let a = spawn(Box::new(OverlayNode::<F2>::new(Point::at(0), Config::default())), dir.clone()).await?;
//! let mut b = spawn(Box::new(OverlayNode::<F2>::new(Point::at(1), Config::default())), dir.clone()).await?;
//! a.command(Command::Send { to: b.address(), payload: b"hi".to_vec() });
//! let note = b.next_notification().await; // Delivered { from: a, payload: "hi" }
//! # Ok(()) }
//! ```
//!
//! Overlay identity is the projective coordinate, bound to a network address by the [`Directory`]
//! (the DHT's job in production). TLS gives every link confidentiality and integrity; it does not
//! authenticate a hostname — the self-signed per-node certificate exists only to key the channel.

#![forbid(unsafe_code)]

mod directory;
mod driver;
mod harness;
mod identity;
mod reflexive;
mod tls;

pub use directory::Directory;
pub use reflexive::ReflexiveAddr;
pub use driver::{
    Client, NodeHandle, ProteusConfig, QuicError, spawn, spawn_self_certifying,
    spawn_self_certifying_persistent, spawn_self_certifying_persistent_on,
    spawn_self_certifying_with_capabilities, spawn_shaped,
};
pub use fanos_proteus::{Environment, Morph};
pub use harness::{Cell, DEFAULT_GRIND_LIMIT, credentials_for_point, spawn_cell, spawn_pinned};
pub use identity::{
    coordinate_at_level, coordinate_from_cert, hierarchical_coordinate, verifiable_coordinate,
    verify_peer_coordinate, vrf_public_from_cert,
};
pub use tls::{NodeCredentials, TlsError};
