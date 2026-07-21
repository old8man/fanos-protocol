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
//!   encoding. The load-bearing signal is 3 bits. The fold *minimizes* data (per-node raw signals stay
//!   local), but is **not** anonymization — the frame still names the faulted point and the cell's exact
//!   health, so an internal frame must never be exported raw (audit C7).
//! * [`dp`] — the **differentially-private export boundary** (audit C7): [`CoherenceFrame::privatize`]
//!   Laplace-noises the cell's sufficient statistic at the derived sensitivity `Δr = 1/21`, re-derives
//!   the scalars/verdict by post-processing, and withholds the exact syndrome — an ε-DP frame safe to
//!   share, while the full-resolution frame stays internal for self-healing.
//! * [`sysmetrics`] — platform-optimal acquisition of a node's raw vitals (CPU/memory/disk/network),
//!   the sensory input whose [`pressure`](sysmetrics::SystemSample::pressure) becomes each node's
//!   scalar in the cell correlation. Pure, tested parsers plus a cached-handle Linux `/proc` probe.
//!
//! Subsequent modules (the local time-series history, the mandatory per-node observer loop,
//! distributed collection, and the monitor WebSocket) build on these.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

// The DP export boundary (audit C7) rebuilds the equicorrelated coherence matrix (needs `alloc`) and
// samples Laplace noise (needs a float `ln` — `std` or `libm`).
#[cfg(all(feature = "alloc", any(feature = "std", feature = "libm")))]
pub mod dp;
pub mod frame;
pub mod history;
pub mod observer;
#[cfg(feature = "std")]
pub mod persist;
pub mod snapshot;
pub mod sysmetrics;

#[cfg(all(feature = "alloc", any(feature = "std", feature = "libm")))]
pub use dp::{PrivacyBudget, R_SENSITIVITY};
pub use frame::{AlarmLevel, CellId, CoherenceFrame, FRAME_LEN, Regime};
pub use history::{Bucket, HistoryConfig, MetricId, MetricStore, Series};
pub use observer::SelfObserver;
pub use snapshot::{
    CELL_N, CoherenceSnapshot, OVER_COUPLING, PHI_THRESHOLD, PURITY_FLOOR, R_STAR, REFLECTION_FLOOR,
};
pub use sysmetrics::{CpuTimes, NullProbe, SystemProbe, SystemSample};
