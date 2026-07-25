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

// Both lints here are artifacts of how Cargo compiles a shared test module: this file is built *separately into every*
// integration-test binary, and each binary uses only the part it needs.
//
// `unreachable_pub` — within one binary the item is unreachable from outside, yet it must be `pub` to cross the
// `mod common;` boundary at all. `dead_code` — a suite that needs the hang ceiling but not the fixture lock (or vice
// versa) leaves the other genuinely unused *in that binary*, which is correct, not a defect. The alternative to both is
// duplicating these into five test files, which is the exact defect this module removes.
#![allow(unreachable_pub, dead_code)]

use std::sync::LazyLock;
use std::time::Duration;

use tokio::sync::{Mutex, MutexGuard};

/// The liveness backstop for any real-socket wait: long enough that machine contention cannot trip it, short enough that
/// a genuine hang still fails the run rather than wedging it.
///
/// This is deliberately **not** a latency budget. Assert latency explicitly where it matters.
pub const HANG_CEILING: Duration = Duration::from_secs(240);

/// Serializes tests that stand up a **whole real-QUIC cell**.
///
/// `cargo test` runs the tests within a binary concurrently, so two cell fixtures in one file mean two seven-node QUIC
/// cells — fourteen real endpoints — competing for one loopback and one scheduler. Measured: each DROMOS QUIC test
/// passes alone in ~4–27 s and both fail at *any* ceiling when run together on a busy host. That is not a timing budget
/// to widen; it is a fixture that must not run twice at once.
///
/// The convention already existed (`fanos-ffi`'s `SERIAL`, whose comment names this exact failure mode) but lived only
/// in that crate, so each suite either rediscovered it or — as here — silently did without. It belongs next to
/// [`HANG_CEILING`]: both are about not mistaking host contention for a defect.
///
/// Hold the guard for the test's whole body; it is released on drop.
///
/// This is `tokio`'s mutex rather than `std`'s, because the guard is necessarily held across the `await`s that drive the
/// cell: a `std::sync::MutexGuard` blocks the worker thread it is parked on, so a test waiting for its turn would stall
/// a runtime thread instead of yielding it. (`fanos-ffi`'s equivalent uses `std`, correctly — its tests are synchronous.)
/// Tokio's mutex also has no poisoning, which removes the need to launder a panicking test's poison into every sibling.
static CELL_FIXTURE: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Acquire the whole-cell fixture lock, yielding until it is free.
pub async fn serial_cell() -> MutexGuard<'static, ()> {
    CELL_FIXTURE.lock().await
}
