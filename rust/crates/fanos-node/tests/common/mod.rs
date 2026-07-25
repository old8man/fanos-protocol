//! Shared scaffolding for the real-socket integration tests.
//!
//! ## Why a single hang ceiling replaced fourteen hand-picked numbers
//!
//! These suites stand up real QUIC nodes on real sockets, then wait for a condition. Each wait carried its own
//! hand-tuned ceiling — 10 s, 15 s, 20 s, 30 s, 40 s, 45 s, 50 s, 60 s — and every one of them was **two different
//! quantities collapsed into one number**:
//!
//! 1. *how long this operation is expected to take* — a latency claim, worth asserting explicitly if it matters;
//! 2. *how long before we conclude it will never finish* — a liveness backstop, whose only job is to turn a hang into a
//!    failure rather than a stuck test run.
//!
//! Sizing (2) as though it were (1) is a defect, not a tuning choice: it converts **machine contention into a false
//! red**. Measured on this workspace — `cargo test --workspace` fails one random real-socket test per run, a different
//! one each time (`fanos-ffi`, the DROMOS QUIC cell, the rendezvous-host driver, the `fanos-quic` fabric seam), while
//! every one of them passes in seconds when run alone. A baseline run with the role-loop refresh disabled failed too, so
//! this is not one subsystem's load: it is the suite competing with itself for one machine, and it made the verification
//! gate itself unreliable (see `docs/design-testing.md` §5.3.3).
//!
//! So (2) becomes one constant, sized for a *loaded* machine, and the healthy path pays nothing for the headroom because
//! it exits as soon as its condition holds. A test that genuinely needs to pin latency asserts it **separately and
//! explicitly** — that keeps the claim visible instead of hiding it inside a timeout argument.

// `unreachable_pub` fires because each integration-test binary includes this module privately: within one binary the
// item is unreachable from outside, yet it must be `pub` to be visible across the `mod common;` boundary at all. The
// alternative — duplicating the constant into five test files — is the exact defect this module removes.
#![allow(unreachable_pub)]

use std::time::Duration;

/// The liveness backstop for any real-socket wait: long enough that machine contention cannot trip it, short enough that
/// a genuine hang still fails the run rather than wedging it.
///
/// This is deliberately **not** a latency budget. Assert latency explicitly where it matters.
pub const HANG_CEILING: Duration = Duration::from_secs(240);
