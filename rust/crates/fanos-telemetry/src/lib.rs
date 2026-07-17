//! # fanos-telemetry — mandatory, provably-minimal per-node self-observation
//!
//! Every FANOS node observes itself **every window** — this is not optional. Self-observation is the
//! sensory half of the organism: it feeds self-diagnosis, self-healing (the regenerator `ℛ`), and
//! load optimization/balancing (`docs/design-telemetry.md`, `docs/coherent-cybernetics.md`). The
//! design's central guarantee is that this costs almost nothing: the **Minimal Self-Observation
//! Overhead theorem** shows the on-wire self-scan is `Θ(log N / N)` bits per node per window — a
//! constant, independent of network size — because a Fano cell *is* a Hamming(7,4) perfect code and
//! its 3-bit syndrome is the entropy-, coding-, and sightedness-floor all at once.
//!
//! This crate is the sans-I/O core of that plane:
//!
//! * [`frame`] — the [`CoherenceFrame`](frame::CoherenceFrame): the minimal sufficient statistic for
//!   a cell's health at a window (3-bit syndrome + coherence scalars), with a canonical KAT-pinned
//!   encoding. The load-bearing signal is 3 bits; the fold *is* the anonymization.
//!
//! Subsequent modules (system-metric acquisition, the local time-series history, the mandatory
//! per-node observer loop, distributed collection, and the monitor WebSocket) build on this atom.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod frame;

pub use frame::{AlarmLevel, CellId, CoherenceFrame, FRAME_LEN, Regime};
