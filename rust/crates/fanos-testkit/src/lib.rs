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

pub mod corpus;

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

/// # Reading a Rust source the way a guard must: shipping code only
///
/// **This lives here because it was copied (#252).** Seven places across five test files each carried their
/// own `src.split("#[cfg(test)]").next()` — and every one of them shared the same defect: it assumes a test
/// module is the last thing in a file. Thirteen files in this tree declare something at top level below one,
/// and in three of them it is shipping code (`fanos-field`'s `pub trait Field`, `fanos-node`'s
/// `pub struct NodeResolver` and `pub struct Census`). Each copy was therefore examining a subset and
/// reporting `ok`.
///
/// A guard that reads less than it claims cannot be caught by its own result, so the slice belongs in one
/// place where it can be tested directly — which is what the unit tests below do, in both directions.
pub mod source {
    /// The part of a source file that ships: everything **except** the `#[cfg(test)]` blocks.
    ///
    /// A call that exists only in a crate's own test module is not wiring — that is exactly how a built-and-unused
    /// capability looks reachable.
    ///
    /// **This used to cut the file at the first `#[cfg(test)]` and keep the head (#252).** That reading assumes a
    /// test module is the last thing in a file, which is a convention this tree does not actually hold: thirteen
    /// files declare something at top level below one, and in four of them it is shipping code —
    /// `fanos-field`'s `pub trait Field` and `pub type F2`, `fanos-node`'s `pub struct NodeResolver` and its
    /// `pub struct Census`. Every guard here reads through this function, so all of them had been silently
    /// examining a subset. Worse, the blindness was **placement-dependent**: a guard could be disarmed by moving
    /// a test module above the code it guards, which is how #245's `open_uni` ratchet came to pass while
    /// counting zero openers.
    ///
    /// So it now removes each attributed block by brace balance and keeps everything else. Braces inside string
    /// literals, char literals and comments are skipped, because a `"{"` in a test's assertion message would
    /// otherwise close the block early and readmit the rest of the file as production.
    pub fn production_part(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        let mut at = 0usize;
        for (start, end) in test_block_ranges(src) {
            out.push_str(&src[at..start]);
            at = end;
        }
        out.push_str(&src[at..]);
        out
    }

    /// The byte ranges every `#[cfg(test)]` item occupies — the single place the rule lives, so the slice and
    /// the line-numbered view cannot disagree.
    ///
    /// Ranges are disjoint and in order, and start at the beginning of the attribute's own line so the cut
    /// does not leave its indentation behind.
    #[must_use]
    pub fn test_block_ranges(src: &str) -> Vec<(usize, usize)> {
        const ATTR: &str = "#[cfg(test)]";
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0usize;
        while let Some(rel) = src[i..].find(ATTR) {
            let at = i + rel;
            let after = at + ATTR.len();
            let line_start = src[..at].rfind('\n').map_or(0, |n| n + 1);
            // Indentation is allowed — `#[cfg(test)] pub(crate) fn …_for_test` inside an `impl` is a test
            // helper and must not count as shipping code — but the attribute has to be the whole of what
            // precedes it on its line. Otherwise it is this very string appearing inside another scanner.
            if !src[line_start..at].trim().is_empty() || !item_follows(&src[after..]) {
                i = after;
                continue;
            }
            match block_end(bytes, at) {
                Some(end) => {
                    out.push((line_start, end));
                    i = end;
                }
                // Unbalanced or bodyless: keep the text and move past the attribute. Truncating the rest of
                // the file here is what the old slice did, and it is the defect (#252) — a scan that examines
                // less still reports `ok`, so the safe direction is to examine more.
                None => i = after,
            }
        }
        out
    }

    /// Whether an item **with a body** starts here, after any further attributes and doc lines.
    ///
    /// A `#[cfg(test)]` can also decorate a struct field or a `use`, and those have no block to balance: the
    /// brace scan would run on and swallow an unrelated one further down the file.
    fn item_follows(tail: &str) -> bool {
        // Attributes can span lines, and in this tree they usually do: `#[cfg(test)]` is followed by a
        // multi-line `#[allow(clippy::…, …)]` on 300-odd modules. Skipping only lines that START with `#[`
        // stops at the first continuation line, decides "no item here", and readmits the whole test module
        // as shipping code — which is how two test constants (`monitor.rs`'s `W`, `history.rs`'s `S`) were
        // reported as unexplained production values the first time this ran.
        let mut depth = 0i32;
        for line in tail.lines() {
            let t = line.trim();
            if depth > 0 {
                depth += i32::try_from(t.matches('[').count()).unwrap_or(0);
                depth -= i32::try_from(t.matches(']').count()).unwrap_or(0);
                continue;
            }
            if t.is_empty() || t.starts_with("//") {
                continue;
            }
            if t.starts_with("#[") {
                depth = i32::try_from(t.matches('[').count()).unwrap_or(0)
                    - i32::try_from(t.matches(']').count()).unwrap_or(0);
                continue;
            }
            let t = t
                .strip_prefix("pub(crate) ")
                .or_else(|| t.strip_prefix("pub(super) "))
                .or_else(|| t.strip_prefix("pub "))
                .unwrap_or(t);
            return ["mod ", "fn ", "async fn ", "unsafe fn ", "const fn ", "impl", "struct ", "enum ", "trait "]
                .iter()
                .any(|k| t.starts_with(k));
        }
        false
    }

    /// The 1-indexed lines of `src` that ship, paired with their text — [`production_part`] for callers that
    /// must report **where** something is.
    ///
    /// Slicing the text and then numbering the result gives line numbers that do not exist in the file, which
    /// is worse than no number at all: it sends a reader to the wrong place with full confidence.
    #[must_use]
    pub fn shipping_lines(src: &str) -> Vec<(usize, &str)> {
        let cuts = test_block_ranges(src);
        let mut out = Vec::new();
        let mut at = 0usize;
        for (n, line) in src.lines().enumerate() {
            if !cuts.iter().any(|&(a, b)| at >= a && at < b) {
                out.push((n + 1, line));
            }
            at += line.len() + 1;
        }
        out
    }

    /// Byte index just past the `{ … }` that follows `from`, skipping braces inside strings, chars and comments.
    ///
    /// `None` if there is no brace, or the file ends before it balances — a truncated read is a reason to stop,
    /// not to assume the rest is production.
    fn block_end(bytes: &[u8], from: usize) -> Option<usize> {
        let mut i = bytes.get(from..)?.iter().position(|&b| b == b'{')? + from;
        let (mut depth, mut in_str, mut in_char, mut in_line, mut in_block, mut esc) = (0i32, false, false, false, false, false);
        while let Some(&b) = bytes.get(i) {
            let next = bytes.get(i + 1).copied();
            if in_line {
                if b == b'\n' {
                    in_line = false;
                }
            } else if in_block {
                if b == b'*' && next == Some(b'/') {
                    in_block = false;
                    i += 1;
                }
            } else if in_str || in_char {
                if esc {
                    esc = false;
                } else if b == b'\\' {
                    esc = true;
                } else if (in_str && b == b'"') || (in_char && b == b'\'') {
                    in_str = false;
                    in_char = false;
                }
            } else {
                match b {
                    b'/' if next == Some(b'/') => in_line = true,
                    b'/' if next == Some(b'*') => in_block = true,
                    b'"' => in_str = true,
                    // A lifetime (`'a`) is not a char literal: a char is at most one escape plus a closing quote.
                    b'\'' if bytes.get(i + 2) == Some(&b'\'') || bytes.get(i + 1) == Some(&b'\\') => in_char = true,
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(i + 1);
                        }
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        None
    }

    /// [`production_part`] with whole-line comments removed — the text a **call scan** may read.
    ///
    /// **Comments are not code, and the unwired-capability scan used to count them** (#227). `calls` accepts a
    /// name followed by an opening paren, which is ordinary English punctuation: a doc line reading "the cascade
    /// `lead` (`-1` = none)" registered as a call to `lead()`. Measured across the workspace, **83 public
    /// functions were "wired" by nothing but a word in prose** — among them `loadbalance::balance_exact`, whose
    /// only real caller is a test and whose apparent one was the healer comment *describing* the §6.7 response
    /// that does not exist (#139), and `dispersion`, the second-dimension discriminator no production reader
    /// consumes (#225/#226). The blindness was biased toward the load-bearing: the more consequential a
    /// function, the likelier a neighbouring comment names it.
    ///
    /// **Separate from [`production_part`] rather than replacing it, and that is the point.** The literal-seed
    /// guard reads the same files looking for a `literal-seed-ok:` marker — which *is* a comment — so the two
    /// scans want opposite things from the same text. One helper serving both would have silently disarmed
    /// #203's marker lookback the moment this one started stripping.
    ///
    /// Whole lines only (`//`, `///`, `//!`), where prose lives. A trailing comment after code is left alone
    /// deliberately: cutting at `//` would corrupt any string literal containing it.
    pub fn code_only(src: &str) -> String {
        production_part(src)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// **The slice itself, falsified in both directions** — the guard set is only as wide as this function.
        ///
        /// It is a self-test rather than a corpus check because the failure #252 describes is invisible in the
        /// corpus: a scan that silently examines less still reports `ok`. Each case here is a shape the tree
        /// actually contains.
        #[test]
        fn the_production_slice_drops_test_blocks_and_keeps_what_follows_them() {
            // 1. Shipping code BELOW a test module is production. This is the whole of #252: four files
            //    (`fanos-field`, `fanos-node`'s resolve.rs and telemetry_dir.rs) declare exactly this shape.
            let src = "pub fn head() {}\n#[cfg(test)]\nmod tests {\n    fn hidden() {}\n}\npub fn tail() {}\n";
            let kept = production_part(src);
            assert!(kept.contains("head"), "code above a test module is production");
            assert!(kept.contains("tail"), "code BELOW a test module is production too — the #252 defect");
            assert!(!kept.contains("hidden"), "code inside the test module is not");

            // 2. A second test module after the first is still dropped, and so is a third.
            let src = "#[cfg(test)]\nmod a {\n    fn x() {}\n}\npub fn mid() {}\n#[cfg(test)]\nmod b {\n    fn y() {}\n}\n";
            let kept = production_part(src);
            assert!(kept.contains("mid"), "code between two test modules is production");
            assert!(!kept.contains("fn x") && !kept.contains("fn y"), "both test modules are dropped");

            // 3. A brace inside a test's assertion message must not close the block early. Before the brace-aware
            //    scan this readmitted the rest of the file as production — the failure mode that turns a guard into
            //    a source of false findings rather than a blind one.
            let src = "#[cfg(test)]\nmod t {\n    fn f() { panic!(\"unbalanced { here\"); }\n}\npub fn after() {}\n";
            let kept = production_part(src);
            assert!(!kept.contains("panic!"), "a `{{` in a string literal does not end the test block");
            assert!(kept.contains("after"), "and the code after it is still reached");

            // 4. `#[cfg(test)]` on an item that is not a module (a single test fn) is dropped by the same rule.
            let src = "#[cfg(test)]\nfn only_a_test() { let _ = 1; }\npub fn real() {}\n";
            let kept = production_part(src);
            assert!(!kept.contains("only_a_test") && kept.contains("real"));

            // 5. An INDENTED `#[cfg(test)]` on a struct FIELD has no block to balance. Cutting here is what made
            //    the first version of this fix worse than the defect: `block_end` found no brace and the function
            //    returned early, discarding the rest of the file.
            let src = "pub struct S {\n    #[cfg(test)]\n    pub probe: u8,\n    pub real: u8,\n}\n";
            assert!(production_part(src).contains("pub real"), "a cfg'd FIELD does not cut the struct");

            // 5b. A MULTI-LINE attribute between `#[cfg(test)]` and the module. Three hundred modules in this
        //     tree have exactly this shape, and missing it readmits every one of them as production.
        let src = "#[cfg(test)]\n#[allow(\n    clippy::unwrap_used,\n    clippy::expect_used\n)]\nmod tests {\n    const W: usize = 20;\n}\npub fn after() {}\n";
        let kept = production_part(src);
        assert!(!kept.contains("const W"), "a multi-line attribute does not hide the test module");
        assert!(kept.contains("after"), "and the code below it is still production");

        // 6. An indented `#[cfg(test)]` on a test HELPER inside an `impl` is dropped — five such helpers exist
            //    (`stress_for_test`, `admission_proof_for_test`, …) and counting them as shipping code would make
            //    the unwired-capability scan report functions no binary can reach.
            let src = "impl S {\n    #[cfg(test)]\n    pub(crate) fn probe_for_test(&self) {}\n    pub fn real(&self) {}\n}\n";
            let kept = production_part(src);
            assert!(!kept.contains("probe_for_test"), "a cfg'd helper inside an impl is a test");
            assert!(kept.contains("fn real"), "and its neighbours survive");

            // 7. The attribute appearing INSIDE another scanner's source — `src.split("#[cfg(test)]")` — is text,
            //    not an attribute. Seven such lines exist across five test files, and treating one as a block
            //    boundary would cut a guard's own file in half.
            let src = "pub fn scan(s: &str) {\n    let _ = s.split(\"#[cfg(test)]\").next();\n}\npub fn after() {}\n";
            let kept = production_part(src);
            assert!(kept.contains("fn scan") && kept.contains("after"), "a quoted attribute is not a block");
        }

    }

}
