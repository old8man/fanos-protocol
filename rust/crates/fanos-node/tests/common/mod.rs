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
use std::num::NonZeroUsize;
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
///
/// ## The frozen span is counted in observations, not in wall clock
///
/// A wall-clock window shrinks precisely when the host is least able to make progress, so it refutes a starved system as
/// confidently as a wedged one. Measured on the HERMES cell suite: it converges in 48 s at load average 57, and at load
/// average 83 reported `REFUTED — a fixed point, not a slow one` about a cell that was never scheduled at all.
///
/// The budget is therefore charged one [`POLL`] per *completed observation*, so a span is `FROZEN_SPAN / POLL` samples
/// rather than a duration. This is not the same trick as charging by timer ticks — that was tried one layer down and
/// stretched a 48 s window to only 79 s at 4× oversubscription, because timers are exactly what keeps running when the
/// worker threads cannot. An observation is *real work the host must schedule*: it wakes seven validators and awaits their
/// snapshots. When the host slows that down tenfold, the window stretches tenfold with it, automatically and with no
/// tuning factor.
///
/// The verdict also carries the evidence a reader needs to second-guess it: how many observations completed inside the
/// frozen window, and the slowest one. A cell standing still while its nodes answer 320 snapshot rounds promptly is a
/// wedge; one whose observations have themselves blown out to seconds is a starved host, and the message says which
/// without pretending to a threshold that separates them.
pub async fn converge<F, Fut>(what: &str, mut observe: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = (bool, String)>,
{
    let started = Instant::now();
    let mut last = String::new();
    let mut granted = Duration::ZERO;
    let mut samples = 0u32;
    let mut slowest = Duration::ZERO;
    loop {
        let sampled_at = Instant::now();
        let (reached, trace) = observe().await;
        let took = sampled_at.elapsed();
        if reached {
            // **Report the converged state, not just the fact of converging.** A run that only says "reached" makes the
            // outcome the sole observable, and the outcome is the one thing a fix must not be judged by: a scenario can
            // go green because the defect was fixed or because that run was lucky. Twice in the round-split
            // investigation the question was "what does a *passing* cell look like here", and the answer had to be
            // guessed. Visible under `--nocapture`, where it costs a line and settles it.
            println!("{what}: reached in {:?}. Converged to: {trace}", started.elapsed());
            return;
        }
        if trace != last {
            last = trace;
            granted = Duration::ZERO;
            samples = 0;
            slowest = Duration::ZERO;
        }
        samples += 1;
        slowest = slowest.max(took);
        assert!(
            granted < FROZEN_SPAN,
            "{what}: REFUTED — the observed state has not changed across {samples} observations (a fixed point, not a \
             slow one). The slowest of them took {slowest:?}, so judge for yourself whether this host was answering. \
             Frozen at: {last}"
        );
        assert!(
            started.elapsed() <= HANG_CEILING,
            "{what}: INCONCLUSIVE — still changing at the {HANG_CEILING:?} ceiling, so this is latency rather than a \
             wedge. Last seen: {last}"
        );
        granted += POLL;
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

/// Wakeups of a task that does nothing but wake — the discriminator `DELIVERED` cannot supply.
///
/// "No bytes moved" has two readings that demand opposite responses: this session is wedged, or the runtime was
/// never scheduled to work on it. [`DELIVERED`] separates them by asking whether any *other flow* ever moved a
/// byte, and its own doc names the limit that leaves — a host that starves only after some traffic has flowed
/// reads as a wedge. That limit was hit twice in one workspace run, on tests that pass alone in under two seconds.
///
/// This asks a question with no such gap: **was this runtime running at all while the window drained?** The task
/// sleeps one [`POLL`] and increments, so its count rises only when the executor actually polls it. Timers alone
/// are not enough — they keep firing on a contended host precisely when the workers cannot run, which is why
/// charging by timer ticks under-stretched the window (measured: 48 s to 79 s at 4× oversubscription).
///
/// No threshold is chosen because the expectation is arithmetic: a window of `w` contains `w / POLL` wakeups if
/// the executor was polling us. The ratio is reported either way, so a reader can second-guess the verdict.
static HEARTBEAT: AtomicU64 = AtomicU64::new(0);

/// Start the heartbeat once per test binary, and return its current count. Idempotent.
fn heartbeat() -> u64 {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        tokio::spawn(async {
            loop {
                tokio::time::sleep(POLL).await;
                HEARTBEAT.fetch_add(1, Ordering::Relaxed);
            }
        });
    });
    HEARTBEAT.load(Ordering::Relaxed)
}

/// One read bounded by [`FROZEN_SPAN`] of granted time. Returns the byte count (0 at end of stream).
async fn read_within_span<S>(stream: &mut S, into: &mut [u8], so_far: usize) -> usize
where
    S: AsyncRead + Unpin,
{
    let beats_before = heartbeat();
    let opened = Instant::now();
    let read = within_span(stream.read(into))
        .await
        .unwrap_or_else(|| {
            let moved = DELIVERED.load(Ordering::Relaxed);
            let beats = HEARTBEAT.load(Ordering::Relaxed).saturating_sub(beats_before);
            let elapsed = opened.elapsed();
            let expected = (elapsed.as_secs_f64() / POLL.as_secs_f64()).max(1.0);
            #[allow(clippy::cast_precision_loss)]
            let ran = beats as f64 / expected;
            let evidence = format!(
                "the runtime was polled {beats} times in {elapsed:?} against {expected:.0} expected ({:.0}% of what \
                 it should have been), and this process has delivered {moved} bytes on other flows",
                ran * 100.0
            );
            // **`ran` decides, alone.** `moved` is the older proxy this heartbeat was introduced to replace —
            // its doc above names the gap it leaves — and requiring *both* re-imported that gap in the other
            // direction: `moved` counts bytes on OTHER flows, so a test run on its own has none by
            // construction, and every solo failure was labelled INCONCLUSIVE even at 98% polling, where the
            // runtime is demonstrably healthy and the honest verdict is a refutation.
            //
            // The message made that worse by advising "re-run it alone; if it passes, the host was the
            // variable" — routing the reader into the single case the conjunction could not judge. Three real
            // failures wore the inconclusive label for weeks because of it.
            //
            // `moved` stays in the evidence string, where it is informative, and out of the verdict, where it
            // was only ever a weaker way of asking what `ran` answers directly.
            assert!(
                ran > 0.5,
                "INCONCLUSIVE — no byte moved in {FROZEN_SPAN:?} of granted time after {so_far} bytes. {evidence}. \
                 This runtime was not scheduled enough to judge — so the run says nothing about the system. \
                 Re-run it on an idle host; if the poll ratio rises and it still moves nothing, it is wedged."
            );
            panic!(
                "REFUTED — no byte moved in {FROZEN_SPAN:?} of granted time after {so_far} bytes. {evidence} — so \
                 the runtime WAS running and this session still moved nothing: it is wedged."
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
    let charge = POLL.mul_f64(cpu_share());
    loop {
        tokio::select! {
            done = &mut work => return Some(done),
            () = tokio::time::sleep(POLL) => granted += charge,
        }
        if granted >= FROZEN_SPAN {
            return None;
        }
    }
}

/// The share of one CPU a runnable task can expect right now, in `(0, 1]`.
///
/// Charging the budget a full [`POLL`] per timer tick assumed a tick *is* the opportunity to make progress. It is
/// not, and this module's own [`converge`] doc already records the measurement: charging by timer ticks "stretched
/// a 48 s window to only 79 s at 4× oversubscription, because timers are exactly what keeps running when the
/// worker threads cannot". `converge` was given a better denominator; the layer below it was left as it was, and
/// that is the layer `read_within_span` uses — which is how two sub-two-second tests came to be reported
/// `REFUTED — this session is wedged` during a contended workspace run (they pass alone in 1.47 s and 0.87 s).
///
/// The factor is derived rather than chosen, from processor sharing: with `L` runnable tasks contending for `C`
/// cores each receives `C/L` of a core once `L > C`, and all of one below that. So the window stretches by exactly
/// the contention factor, and on an unloaded host the factor is exactly `1` — which is the property that matters
/// most, because it means **this cannot make a genuine wedge harder to see on a quiet machine: there it changes
/// nothing at all.**
///
/// Load average rather than this process's CPU time, deliberately: process CPU cannot separate "starved" from
/// "idle because wedged" — a wedged session consumes nothing either way, so a budget charged by it would stall on
/// the very case it exists to report. Load measures the *host's* contention, which is what actually differs.
///
/// Read once per span rather than per tick, and through the OS's own tool rather than FFI (`unsafe_code` is
/// denied workspace-wide, and a test harness is not the place to make an exception). A failed read falls back to
/// `1.0`, which is exactly the old behaviour and therefore cannot widen a window by accident.
///
/// **Known limit, measured the hard way: the one-minute load average LAGS.** It describes the minute just past,
/// not the moment, so on a machine whose contention is decaying this over-stretches the window and on one ramping
/// up it under-stretches. The cost of getting this wrong is asymmetric and in the safe direction — over-stretching
/// delays a verdict, under-stretching is the false REFUTED this replaced — but it is a real bound on the
/// correction. It also makes load average a poor *experimental* control: an attempt to measure the dilation curve
/// at three load levels produced 258 s at "load 12" and 3 s at "load 16", because the first ran while the machine
/// was still draining a previous experiment the one-minute average had not caught up with. The independent
/// variable was never actually controlled. A shorter-horizon measure (run-queue depth sampled directly) would fix
/// both, and is the obvious next step if this correction ever needs to be tighter.
/// The fraction of a core this process can expect right now — `1.0` on an idle host, falling as the host is
/// oversubscribed. Exported so a diagnostic can refuse to draw conclusions from a starved run.
///
/// A timing experiment on a loaded box measures the box. This harness already knows that, and encodes it in
/// the `INCONCLUSIVE` branch of its budgeted exchange; a diagnostic that reads station counters by hand
/// bypasses that machinery entirely and can spend hours attributing contention to the system under test.
#[must_use]
pub fn host_cpu_share() -> f64 {
    cpu_share()
}

/// The share below which a real-QUIC **liveness** assertion cannot tell a starved machine from a defect.
///
/// Derived from what the number means rather than chosen: `share_at` returns `cores / load`, so 0.5 is the
/// point at which this process can expect half a core — i.e. every deadline in the test is competing with an
/// equal amount of foreign work, and a missed one is at least as likely to be the box as the system.
pub const QUIET_ENOUGH: f64 = 0.5;

/// Refuse to conclude from a starved run, for an assertion whose subject is **liveness within a deadline**.
///
/// Call it immediately before such an assertion. On a quiet host it does nothing; on a loaded one it fails
/// with a message naming the machine, so the run is reported as unmeasurable rather than as a defect.
///
/// **Why this fails rather than skips.** A skip is silent, and a test that quietly skips under load is a test
/// that stops running exactly when the suite is busiest — which is most of the time. Failing converts a
/// *false defect report* into a *true environment report*: the run still goes red, but it goes red for the
/// reason it actually had.
///
/// **Why only liveness assertions.** A structural property — a forgery refused, a codec round-tripping, a
/// quorum arithmetic — does not depend on how fast the box is, and guarding it would weaken a test for no
/// reason. This is for the ones that count arrivals or wait on a deadline.
///
/// The cost of not having this is measured: #38 and #41 each sat open for weeks as suspected defects and
/// both were contention; three more real-QUIC tests produced false failures in a single day
/// (`handshake_negotiation`, `self_certifying`, `the_service_survives_one_meeting_point_going_silent`), each
/// passing 3/3 in isolation on a quiet box.
pub fn require_quiet_host(what: &str) {
    // **Re-measured, not sampled once, because load is bursty.** The first version read the average at one
    // instant and declined on it, so a co-tenant's link step — thirty seconds inside a run that takes five
    // minutes — decided the verdict for the whole test. Seen live: a run declined at cpu share 0.50, exactly
    // at the threshold, while the box was on its way back to idle.
    //
    // Waiting is honest in a way that lowering the threshold is not: a host that is busy *now* may not be in
    // twenty seconds, and the property under test does not change while we wait. A host that is busy for the
    // whole window genuinely cannot measure this, and then it still declines.
    let mut share = host_cpu_share();
    for _ in 0..QUIET_RETRIES {
        if share >= QUIET_ENOUGH {
            return;
        }
        std::thread::sleep(QUIET_RETRY_WAIT);
        share = host_cpu_share();
    }
    assert!(
        share >= QUIET_ENOUGH,
        "INCONCLUSIVE (cpu share {share:.2} < {QUIET_ENOUGH} after {QUIET_RETRIES} re-measurements over \
         {}s): this run cannot measure {what} — a starved host and a defect look the same here. Re-run with \
         nothing else on the box; do not read this as a failure of the property.",
        QUIET_RETRIES * QUIET_RETRY_WAIT.as_secs() as u32,
    );
}

/// How many times to re-measure before declining.
///
/// The load average this reads is a **one-minute** average, so successive samples inside a minute are not
/// independent — the number of retries has to span more than that window to see a different world. Six
/// samples twenty seconds apart cover two minutes, which is two full averaging windows.
const QUIET_RETRIES: u32 = 6;
/// How long to wait between re-measurements — see [`QUIET_RETRIES`].
const QUIET_RETRY_WAIT: Duration = Duration::from_secs(20);

fn cpu_share() -> f64 {
    let cores = f64::from(u32::try_from(std::thread::available_parallelism().map_or(1, NonZeroUsize::get)).unwrap_or(1));
    share_at(read_load_average().unwrap_or(0.0), cores)
}

/// The derivation itself, separated from the host it reads — so the tests exercise **this** function rather than a
/// copy of it that can drift, and so they do not depend on the load the machine happens to be under.
fn share_at(load: f64, cores: f64) -> f64 {
    if load <= cores { 1.0 } else { cores / load }
}

/// The 1-minute load average, or `None` if this host does not offer one the way we know how to ask.
fn read_load_average() -> Option<f64> {
    if let Ok(text) = std::fs::read_to_string("/proc/loadavg") {
        return text.split_whitespace().next()?.parse().ok();
    }
    let out = std::process::Command::new("sysctl").args(["-n", "vm.loadavg"]).output().ok()?;
    // `{ 1.23 4.56 7.89 }`
    String::from_utf8_lossy(&out.stdout).split_whitespace().nth(1)?.parse().ok()
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

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn an_unloaded_host_charges_exactly_what_it_always_did() {
        // The property that makes this change safe to make at all: on a quiet machine the factor is exactly 1, so
        // a genuine wedge is reported in the same window as before. A "fix" for false positives that also widens
        // the quiet-machine window would have bought load-tolerance with blindness, which is the worse trade.
        let cores = f64::from(u32::try_from(std::thread::available_parallelism().map_or(1, NonZeroUsize::get)).unwrap_or(1));
        // Exactly 1.0, not approximately: the whole safety argument is that a quiet machine behaves as before.
        assert!((share_at(0.0, cores) - 1.0).abs() < f64::EPSILON, "an idle host must charge the full poll");
        assert!((share_at(cores, cores) - 1.0).abs() < f64::EPSILON, "and so must one loaded to exactly its cores");
    }

    #[test]
    fn oversubscription_stretches_the_window_by_exactly_the_contention_factor() {
        // Processor sharing, asserted as the identity it is rather than as a range: at `k`x oversubscription a
        // runnable task gets `1/k` of a core, so the window must last `k`x longer. No tuning factor anywhere.
        let cores = 16.0;
        for k in [2.0, 3.0, 4.0, 10.0] {
            let share = share_at(cores * k, cores);
            assert!(
                (share - 1.0 / k).abs() < 1e-9,
                "at {k}x oversubscription a task expects 1/{k} of a core, got {share}"
            );
        }
    }

    #[test]
    fn the_charge_is_never_zero_so_a_wedge_is_always_eventually_reported() {
        // The failure mode of any contention-aware budget: at extreme load the charge could round to nothing and
        // the window would never close, converting every wedge into a hang. Bounded below by construction.
        let share = share_at(1e9, 16.0);
        assert!(share > 0.0, "the charge must stay positive at any load, got {share}");
        assert!(POLL.mul_f64(share) > Duration::ZERO, "…and must survive the conversion back to a Duration");
    }
}
