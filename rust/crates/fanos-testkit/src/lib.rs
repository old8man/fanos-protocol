//! **How loaded this host is, and when a timing test must decline to conclude.**
//!
//! A timing experiment on a loaded box measures the box. Two long-open FANOS findings — the anonymous-dial
//! "wedge" and the gather deadline — sat open for weeks as suspected defects and were both contention; three
//! more real-QUIC tests produced false failures in a single day, each passing 3/3 in isolation.
//!
//! So the durable fix is in the instrument: a liveness assertion that cannot be measured **fails as
//! `INCONCLUSIVE`**, which converts a false defect report into a true environment report. The run still goes
//! red, but for the reason it actually had.
//!
//! This lived in `fanos-node`'s `tests/common`, where exactly one test called it and `fanos-quic` — which
//! holds two of the three known load-sensitive tests — could not reach it at all. A guard that the paths
//! needing it most cannot call is the same shape as a guard those paths simply do not call (#87).

use std::num::NonZeroUsize;
use std::time::Duration;

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

/// Decline to conclude when the host is too busy for a **liveness** measurement to mean anything.
///
/// Call at the top of any test that counts arrivals or waits on a deadline. Failing is deliberate and is the
/// point: a test that quietly passes on a starved box certifies whatever it was meant to catch.
///
/// **Why only liveness assertions.** A structural property — a forgery refused, a codec round-tripping, a
/// quorum arithmetic — does not depend on how fast the box is, and guarding it would weaken a test for no
/// reason.
///
/// # Panics
///
/// Panics — as `INCONCLUSIVE`, which is the whole mechanism — when the host stays below [`QUIET_ENOUGH`] for
/// the full re-measurement window.
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
        QUIET_RETRIES * u32::try_from(QUIET_RETRY_WAIT.as_secs()).unwrap_or(u32::MAX),
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

/// The share as a plain number — what a budgeted poll multiplies by.
#[must_use]
pub fn cpu_share() -> f64 {
    let cores = f64::from(u32::try_from(std::thread::available_parallelism().map_or(1, NonZeroUsize::get)).unwrap_or(1));
    share_at(read_load_average().unwrap_or(0.0), cores)
}

/// The derivation itself, separated from the host it reads — so the tests exercise **this** function rather than a
/// copy of it that can drift, and so they do not depend on the load the machine happens to be under.
#[must_use]
pub fn share_at(load: f64, cores: f64) -> f64 {
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


/// How long a whole-cell fixture lockfile may sit before it is presumed abandoned and stolen.
///
/// **Derived, not chosen: it must exceed the longest a fixture can legitimately be held**, which is whatever
/// hang ceiling the slowest suite waits under — `fanos-node`'s `HANG_CEILING` is 240 s and a test asserts the
/// relationship rather than trusting two constants to stay ordered. A bound any shorter steals a live
/// holder's lock and reintroduces exactly the concurrency it exists to prevent; longer only delays recovery
/// from a `^C`.
///
/// Without a steal at all, one killed run would wedge every whole-cell test on the machine forever — a worse
/// instrument than the flakiness this replaces.
pub const FIXTURE_STALE_AFTER: Duration = Duration::from_secs(240);

/// The **machine-wide** whole-cell fixture lock: held while a test stands up a seven-node QUIC cell.
///
/// ## Why machine-wide, and not per-binary or per-crate
///
/// Every suite had its own `static SERIAL: LazyLock<Mutex<()>>`, and each guarded, in its own words, "the
/// transport" — the loopback stack and the host scheduler, which are **machine-wide**. A `static` is
/// process-local; `tests/*.rs` is one binary each; Cargo runs binaries, and crates, concurrently. So six
/// mutexes guarded a resource none of them could see, and `real_nat.rs`'s comment even said so out loud —
/// *"Scoped to this file only — each `tests/*.rs` is its own binary"* — without following it to the
/// conclusion. A guard is only as wide as the narrowest thing that can observe it.
///
/// Measured: a TAXIS test that passes alone in 6.3 s failed inside its own crate's full run once two more
/// seven-node cells joined the suite, at a host load indistinguishable from the run where it passed.
///
/// A file in the machine's temp directory is the one thing every one of those processes can see. Two
/// checkouts on one host genuinely do contend for the same CPU and the same loopback, so sharing the lock
/// between them is correct rather than incidental.
///
/// ## Blocking, and why that is safe here
///
/// Acquisition blocks the calling thread. Each `#[tokio::test]` builds its **own** runtime, and each suite's
/// in-process mutex already admits at most one waiter per binary, so the thread parked here belongs to a
/// runtime with nothing else to run. The returned guard is inert (a path), so holding it across `await`s is
/// fine and it stays `Send`.
pub struct CellFixture {
    path: std::path::PathBuf,
}

impl Drop for CellFixture {
    /// Releases on drop, including while unwinding from a failed assertion. A hard kill is what
    /// [`FIXTURE_STALE_AFTER`] covers.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Acquire the machine-wide whole-cell fixture lock, blocking until it is free.
#[must_use]
pub fn acquire_cell_fixture() -> CellFixture {
    let path = std::env::temp_dir().join("fanos-cell-fixture.lock");
    loop {
        let held = std::fs::OpenOptions::new().write(true).create_new(true).open(&path);
        match held {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .is_ok_and(|t| t.elapsed().unwrap_or_default() > FIXTURE_STALE_AFTER);
                if stale {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            // Acquired — or a temp directory this host will not let us write, which is not a suite's problem
            // to diagnose: fall through to the in-process guard rather than failing every whole-cell test.
            Ok(_) | Err(_) => return CellFixture { path },
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation, exercised through the shipped function rather than a copy of it.
    #[test]
    fn an_idle_host_gets_a_whole_core_and_a_loaded_one_gets_its_share() {
        assert!((share_at(0.0, 8.0) - 1.0).abs() < f64::EPSILON, "idle: a whole core");
        assert!((share_at(8.0, 8.0) - 1.0).abs() < f64::EPSILON, "exactly saturated is still a whole core");
        assert!((share_at(16.0, 8.0) - 0.5).abs() < f64::EPSILON, "twice oversubscribed: half a core");
        assert!(share_at(80.0, 8.0) < QUIET_ENOUGH, "ten times over is well below the threshold");
    }

    /// The threshold is the point at which foreign work equals this process's own — stated so a future
    /// change to it has to disagree with the derivation rather than with a number.
    #[test]
    fn the_quiet_threshold_is_where_contention_equals_this_process() {
        assert!((share_at(2.0, 1.0) - QUIET_ENOUGH).abs() < f64::EPSILON);
    }

    /// It must read *something* on this host, or the guard is decoration.
    #[test]
    fn the_host_load_is_actually_readable_here() {
        let share = host_cpu_share();
        assert!(share > 0.0 && share <= 1.0, "a share outside (0, 1] means the reader is broken: {share}");
    }
}
