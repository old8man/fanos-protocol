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
//!
//! ## The third quantity, and why the ceiling alone hid a real defect for 240 s at a time
//!
//! There is a state (2) cannot express: **the system has stopped changing.** A wait that ends at the ceiling reports
//! "did not finish in time", which reads as *slow* — so a cell that reached a wrong fixed point in three seconds was
//! diagnosed as contention and given more headroom, twice, while `HANG_CEILING` dutifully burned 240 s per test to
//! rediscover the same frozen state. The measured case: six of seven validators executed a private transfer and the
//! seventh sat at genesis height forever, unchanged from the 3-second mark onward.
//!
//! [`converge`] adds the missing verdict, the same three-valued discipline `fanos_sim::fabric::Settled` uses:
//! **Reached** (the condition held), **Refuted** (the observation has not changed for [`FROZEN_SPAN`] — report it now,
//! with the frozen trace, because more waiting cannot help), or **Inconclusive** (the ceiling, which stays as the
//! backstop for a system still visibly making progress). A measurement that did not finish is not a result; a
//! measurement that stopped moving is.

// Both lints here are artifacts of how Cargo compiles a shared test module: this file is built *separately into every*
// integration-test binary, and each binary uses only the part it needs.
//
// `unreachable_pub` — within one binary the item is unreachable from outside, yet it must be `pub` to cross the
// `mod common;` boundary at all. `dead_code` — a suite that needs the hang ceiling but not the fixture lock (or vice
// versa) leaves the other genuinely unused *in that binary*, which is correct, not a defect. The alternative to both is
// duplicating these into five test files, which is the exact defect this module removes.
#![allow(unreachable_pub, dead_code)]

use std::future::Future;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fanos_quic::NodeHandle;
use fanos_runtime::Notification;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, MutexGuard};
use tokio::time::Instant;

/// The liveness backstop for any real-socket wait: long enough that machine contention cannot trip it, short enough that
/// a genuine hang still fails the run rather than wedging it.
///
/// This is deliberately **not** a latency budget. Assert latency explicitly where it matters.
pub const HANG_CEILING: Duration = Duration::from_secs(240);

/// How long an observation must sit **unchanged** before it is a refutation rather than an unfinished wait.
///
/// Derived, not chosen: twice [`fanos_node::taxis_driver::ROUND_TIMEOUT_MAX`], the longest quiet period consensus can
/// legitimately produce. A driver between round attempts shows no state change for just under one round timeout, so one
/// period cannot distinguish "between attempts" from "stopped" — two can. (The same argument, and the same factor of two,
/// as `fanos_sim::fabric::FROZEN_SPAN` over the roster-refresh period; it was derived as a single period there first and
/// the simulator refuted it.)
///
/// At 48 s this is a fifth of [`HANG_CEILING`], so a wedged cell fails five times sooner *and* says why, while a cell
/// still making progress keeps the full ceiling.
pub const FROZEN_SPAN: Duration = fanos_node::taxis_driver::ROUND_TIMEOUT_MAX.saturating_mul(2);

/// How often [`converge`] samples. One driver tick, so a state change cannot hide between polls.
const POLL: Duration = Duration::from_millis(150);

/// Poll `observe` until the system reaches the condition, stops changing, or runs out of ceiling.
///
/// `observe` returns `(reached, trace)`: whether the condition holds, and a rendering of the observed state used **only**
/// to detect that it has stopped changing and to report it. Two states are "the same" when their traces are equal, so the
/// trace must contain everything the condition depends on — a trace that omits part of the state makes a moving system
/// look frozen.
///
/// Panics with the frozen trace on refutation, or with the last trace at the ceiling. The distinction is in the message,
/// because the two demand opposite responses: a frozen system needs a bug fixed, a slow one needs headroom.
pub async fn converge<F, Fut>(what: &str, mut observe: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = (bool, String)>,
{
    let started = Instant::now();
    let mut last = String::new();
    let mut last_change = Instant::now();
    loop {
        let (reached, trace) = observe().await;
        if reached {
            return;
        }
        if trace != last {
            last = trace;
            last_change = Instant::now();
        }
        let now = Instant::now();
        assert!(
            now.duration_since(last_change) <= FROZEN_SPAN,
            "{what}: REFUTED — the observed state has not changed for {:?} (a fixed point, not a slow one). \
             Frozen at: {last}",
            now.duration_since(last_change)
        );
        assert!(
            now.duration_since(started) <= HANG_CEILING,
            "{what}: INCONCLUSIVE — still changing at the {HANG_CEILING:?} ceiling, so this is latency rather than a \
             wedge. Last seen: {last}"
        );
        tokio::time::sleep(POLL).await;
    }
}

/// Complete a request/response exchange over a real stream, bounded by **progress** rather than by elapsed time.
///
/// [`HANG_CEILING`] measures elapsed time, and a descheduled process spends elapsed time without being given any — so a
/// flat `timeout(HANG_CEILING, ..)` wrapped around a whole exchange cannot separate a wedged session from a starved
/// machine, and raises the same panic for both. Measured on `anonymous_quic`, 2026-07-27: **2.69 s** alone; **143.4 s**
/// with the host oversubscribed 2× — a **53× dilation** that leaves only 1.7× of the ceiling unspent; and four of five
/// tests tripping the ceiling outright during a full workspace run. That is precisely the failure [`HANG_CEILING`]'s own
/// contract claims it cannot have, so the contract is quantitatively false, not merely optimistic.
///
/// Bytes are the observable a total-elapsed bound lacks, so the bound here is [`FROZEN_SPAN`] **since the last byte
/// moved**: a transfer that keeps delivering keeps resetting the window and still finishes, while one that stops is
/// reported in one span instead of burning the whole ceiling to say "too slow". The ceiling remains as the outer
/// backstop for the case progress cannot rule out — a transfer that trickles forever without ever stopping.
///
/// It would be convenient if contention merely *slowed* a transfer, so that any stall meant a defect. Measured at 3× and
/// 4× oversubscription, it does not: these exchanges deliver **zero** bytes for the whole window. That is why a stalled
/// window is not a verdict by itself, and why [`DELIVERED`] exists — the discriminator is whether anything *else* in the
/// process moved during the same window.
///
/// This is the same three-valued discipline as [`converge`], applied where the observable is a byte count rather than a
/// polled state.
pub async fn exchange<S>(stream: &mut S, request: &[u8]) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    within_span(async {
        stream.write_all(request).await.expect("the request is written to the stream");
        stream.shutdown().await.expect("the request half closes");
    })
    .await
    .expect("REFUTED — the request neither wrote nor half-closed within one span of granted time");

    let started = Instant::now();
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match read_within_span(stream, &mut chunk, response.len()).await {
            0 => return response,
            n => response.extend_from_slice(chunk.get(..n).expect("a read never exceeds the buffer it filled")),
        }
        assert!(
            started.elapsed() <= HANG_CEILING,
            "INCONCLUSIVE — still receiving at the {HANG_CEILING:?} ceiling ({} bytes so far), so this is a trickle \
             rather than a wedge",
            response.len()
        );
    }
}

/// Round-trip `sent` through a stream that **stays open**, bounded by progress exactly as [`exchange`] is.
///
/// Distinct from [`exchange`] because the request half is deliberately not closed: these suites use the echo to prove
/// bytes flow *before* either side finishes, which is what caught the DIAULOS flush-on-write defect (a sub-segment write
/// that was never shipped until close). Closing the stream would delete the very property under test.
pub async fn echo<S>(stream: &mut S, sent: &[u8]) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    within_span(stream.write_all(sent))
        .await
        .expect("REFUTED — the payload did not write within one span of granted time")
        .expect("the payload is written to the stream");

    let started = Instant::now();
    let mut received = vec![0u8; sent.len()];
    let mut filled = 0;
    while filled < sent.len() {
        let rest = received.get_mut(filled..).expect("`filled` never passes the buffer it counts");
        match read_within_span(stream, rest, filled).await {
            0 => panic!("REFUTED — the stream closed after {filled} of {} echoed bytes", sent.len()),
            n => filled += n,
        }
        assert!(
            started.elapsed() <= HANG_CEILING,
            "INCONCLUSIVE — still echoing at the {HANG_CEILING:?} ceiling ({filled} of {} bytes), so this is a trickle \
             rather than a wedge",
            sent.len()
        );
    }
    received
}

/// Bytes delivered to *any* progress-bounded wait anywhere in this process.
///
/// This is the discriminator a single flow cannot supply on its own. "No bytes arrived here" has two readings — this
/// session is wedged, or the host never scheduled the work — and they demand opposite responses. Whether this process
/// has *ever* delivered a byte separates them from the experiment already running, with no threshold: if it has, the
/// host demonstrably moves data and the fault is specific to this session; if it never has, the run produced no
/// evidence about the system at all.
///
/// Its limit, stated because an instrument that overstates itself is the defect it exists to prevent: a host that
/// starves only *after* some traffic has flowed will be read as a wedge. Both regimes measured here come out right —
/// nothing ever moves at 3–4× oversubscription, and a lone stalled flow after a healthy one is a wedge — but a run that
/// degrades midway can still mislead. The counter deliberately compares against *ever*, not against a window snapshot:
/// the window form was refuted by its own probe, since a stalled flow with no concurrent traffic reported "nothing
/// moved" on a completely idle host.
static DELIVERED: AtomicU64 = AtomicU64::new(0);

/// One read bounded by [`FROZEN_SPAN`] of granted time. Returns the byte count (0 at end of stream).
async fn read_within_span<S>(stream: &mut S, into: &mut [u8], so_far: usize) -> usize
where
    S: AsyncRead + Unpin,
{
    let read = within_span(stream.read(into))
        .await
        .unwrap_or_else(|| {
            let moved = DELIVERED.load(Ordering::Relaxed);
            assert!(
                moved > 0,
                "INCONCLUSIVE — no byte moved in {FROZEN_SPAN:?} of granted time after {so_far} bytes, and no flow in \
                 this process has ever moved one: the host may simply not have scheduled the work, so this run says \
                 nothing about the system. Re-run it alone; if it passes, the host was the variable."
            );
            panic!(
                "REFUTED — no byte moved in {FROZEN_SPAN:?} of granted time after {so_far} bytes, though this process \
                 has delivered {moved} bytes on other flows: the host can move data, so this session is wedged."
            )
        })
        .expect("the stream is readable");
    DELIVERED.fetch_add(read as u64, Ordering::Relaxed);
    read
}

/// Drive `work` to completion within [`FROZEN_SPAN`] of **granted** time; `None` if the budget drained first.
///
/// The span is charged one [`POLL`] per tick this task actually got to run, **not** by wall clock, and that distinction
/// is the whole point. A descheduled process spends wall clock without being given any, so a wall-clock window shrinks
/// precisely when the host is least able to make progress — which is how the first version of this helper came to report
/// `REFUTED — a stalled transfer` for a session that was merely starved (measured at 3× and 4× host oversubscription,
/// against 5 of 5 passing in 3.4 s idle). Reporting a wedge that is not there is worse than the "too slow" verdict it
/// replaced: it sends the reader hunting a defect the machine invented.
///
/// Charging by granted time is the right denomination — everything here shares one runtime, and a host that never
/// schedules the task never drains the budget, which is correct, because it has produced no evidence either way. But it
/// is **not** by itself a defence against starvation, and measurement is what says so: at 4× oversubscription this loop
/// stretched a 48 s window to only 79 s of wall clock (1.66×), against a work dilation nearer 53× on the same host.
/// Timers are precisely the thing that keeps running when the worker threads cannot, so a timer-derived budget barely
/// compensates. Separating starvation from a wedge is [`DELIVERED`]'s job, not this one's.
///
/// `work` is pinned and polled across ticks rather than re-created, so a future that is not cancel-safe — a stream read
/// mid-segment — cannot lose what it already consumed to the sampling.
async fn within_span<F: Future>(work: F) -> Option<F::Output> {
    tokio::pin!(work);
    let mut granted = Duration::ZERO;
    loop {
        tokio::select! {
            done = &mut work => return Some(done),
            () = tokio::time::sleep(POLL) => granted += POLL,
        }
        if granted >= FROZEN_SPAN {
            return None;
        }
    }
}

/// Wait until `node`'s rendezvous relay binds a §3b host registration, and return the tag it bound.
///
/// The observable that replaced a 500 ms sleep captioned "let the registration reach and bind at the combiner". A
/// registration carries no acknowledgement by design, so a test that dials before the binding exists sends a request the
/// combiner silently drops — and the client then waits for a reply that will never come, indistinguishable from a wedge.
/// That guess was the actual cause of the only two `anonymous_quic` tests that ever failed under load: both are the
/// combiner-forwarded ones, both were the only tests carrying a fixed sleep, and the three without one never failed.
///
/// Bounded the same way as the other waits here: by whether notifications keep arriving, not by wall clock.
pub async fn host_registered(node: &mut NodeHandle) -> [u8; 32] {
    loop {
        let Some(note) = within_span(node.next_notification()).await else {
            panic!(
                "REFUTED — no notification of any kind in {FROZEN_SPAN:?} of granted time while waiting for a host \
                 registration to bind"
            )
        };
        match note {
            Some(Notification::HostRegistered { service_tag }) => return service_tag,
            Some(_) => {}
            None => panic!("the relay node shut down before a host registration bound"),
        }
    }
}

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
