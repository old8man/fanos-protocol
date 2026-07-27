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
pub mod nostos;
pub mod sealed;
pub mod slots;
pub mod threshold_onion;

/// The threshold construction as one surface, over two crates.
///
/// The **seal** — Shamir shares each sealed to a member's KEM public key — is now its own low-layer crate
/// ([`fanos_threshold`]), because sealing needs only the KEM, while routing an onion over hop *lines*
/// ([`threshold_onion`]) needs the plane's geometry and NYX's holonomy ratchet. That split removed the one bad edge in an
/// otherwise clean layer DAG: `fanos-taxis` needs `ThresholdSealed` and nothing else, and was reaching through the onion
/// router to get it.
///
/// This facade keeps both halves reachable by one path, so the split is a dependency change rather than a churn of every
/// caller — which is the whole of what it was for.
pub mod threshold {
    pub use fanos_threshold::*;

    pub use crate::threshold_onion::*;
}
pub mod threshold_router;

pub use node::{Directory, NyxNode};
pub use nostos::{ReplyKeys, seal_reply, seal_to_receiver, select_drop_line};
pub use sealed::{PeelOutcome, SealedError};
pub use fanos_threshold::{ThresholdError, ThresholdSealed};
pub use threshold_router::ThresholdRouter;
