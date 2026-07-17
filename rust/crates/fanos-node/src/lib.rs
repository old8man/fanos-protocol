//! # fanos-node — the FANOS node
//!
//! The unified node that the `fanos` binary runs (roadmap Phase 1). FANOS is **sans-I/O**: the
//! protocol logic is a pure engine (`fanos-runtime`) driven by a swappable driver. This crate is
//! the **supervisor** that binds a persistent, self-certifying identity, a bootstrap address book,
//! and the engine composition to the production QUIC driver (`fanos-quic`) — the same engine the
//! simulator exercises, now over a real socket.
//!
//! * [`config`] — [`NodeConfig`]: listen address, identity path, bootstrap peers, roles.
//! * [`identity`] — the durable, self-certifying identity (coordinate = `MapToPoint(H(cert))`).
//! * [`node`] — [`Node`]: start, control, health, shutdown.
//!
//! Phase 1 runs the overlay engine (membership, liveness, L4 storage, DIAKRISIS healing). Relay,
//! service, and exit engines — and the SOCKS5/DNS proxy and VPN surfaces — compose on top in later
//! phases (`docs/design.md` §5).

#![forbid(unsafe_code)]

pub mod config;
pub mod diaulos;
pub mod error;
pub mod identity;
pub mod node;
pub mod resolve;

pub use config::{NodeConfig, Peer, RoleSet};
pub use diaulos::{NodeTransport, dial_service, serve_one};
pub use error::NodeError;
pub use node::{Health, Node};
pub use resolve::ResolvedService;
