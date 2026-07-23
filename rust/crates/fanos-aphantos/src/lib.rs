//! # fanos-aphantos — the running anonymity node (APHANTOS / NYX)
//!
//! This crate turns the NYX onion primitives ([`fanos_nyx`]) and the real post-quantum crypto
//! ([`fanos_pqcrypto`]) into a **routable node**: a [`sealed`] onion whose per-hop keys are
//! established by a hybrid KEM to each relay, and a sans-I/O [`NyxNode`] engine that builds,
//! peels, and forwards it. Because the node is an [`Engine`](fanos_ports::Engine), the exact
//! same code runs under the simulator and a real transport (see `docs/architecture.md`).

#![forbid(unsafe_code)]

extern crate alloc;

pub mod node;
pub mod sealed;
pub mod surb;
pub mod threshold;
pub mod threshold_router;

pub use node::{Directory, NyxNode};
pub use sealed::{PeelOutcome, SealedError};
pub use threshold::{ThresholdError, ThresholdSealed};
pub use threshold_router::ThresholdRouter;
