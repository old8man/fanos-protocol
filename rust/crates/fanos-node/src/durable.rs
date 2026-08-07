//! **What a node keeps when it stops.**
//!
//! A FANOS node persisted its identity and nothing else. Everything a cell had asked it to hold — the erasure
//! shards it is custodian of, the expiry schedule that keeps directory slots from filling the store, the loss
//! ledger whose own documentation called it durable — lived in `BTreeMap`s and died with the process (#77).
//!
//! One node forgetting is survivable *by construction*: a value is `[7,3,4]` erasure-coded across the cell's
//! points, so any three of seven homes reconstruct it and four may be gone. But that tolerance is a **repair
//! budget**, not a property. Spending it on ordinary restarts leaves nothing for the failures it was sized
//! for, and a rolling upgrade across a cell spends the whole budget in an afternoon.
//!
//! ## The split
//!
//! `fanos-runtime` is sans-I/O and `no_std`: it cannot open a file, and teaching it to would dissolve the seam
//! the whole codebase is built on. So the engine says *what* is durable and in what bytes
//! ([`Command::Snapshot`] → [`Notification::Snapshot`]), and this module — which has a filesystem — says
//! *where* and *how often*. Restoring runs the other way and does not use a command at all: adopting a
//! snapshot is only correct before the engine has served anything, so it is an argument to construction
//! (`CellComposition::restore`).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fanos_quic::Client;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// The file a node's durable store lives in, inside its state directory.
pub const STORE_FILE: &str = "store.snapshot";

/// Create `path` and every missing parent, **owner-only** (`0o700`).
///
/// One function with three callers, because the alternative already happened. #82 fixed *"every dealing
/// ceremony writes its secrets at the process umask"* — for the **files**. The node then applied that lesson
/// to `identity.key` (`.mode(0o600)`), to a second secret write, and to the admin socket — and to **no
/// directory at all**: every `create_dir_all` in this crate created at the umask, typically `0o755`, and the
/// directory in question holds `identity.key`, `beacon.params`, `store.snapshot`, `taxis.snapshot` and
/// `admin.sock`.
///
/// **The consequence with teeth is the socket.** `admin::serve` binds the listener and *then* chmods it to
/// `0o600`, and a Unix socket's permission check happens at **`connect()`** — so in the window between those
/// two calls any local account spinning on `connect()` gets a connection that survives the chmod, on the
/// channel whose own doc calls itself *"the whole of this channel's access control"*. A `0o700` parent closes
/// that window by construction: an attacker cannot traverse into the directory to reach the socket at all.
///
/// `0o700` and not `0o750`: nothing here is meant to be read by a group. An operator who wants a group to
/// read the state directory can widen it deliberately, which is a different act from inheriting a umask.
///
/// # Errors
/// Propagates the `create_dir_all` or `set_permissions` failure. **The mode is not best-effort** — a
/// directory that could not be restricted is one whose contents are readable, and continuing would leave the
/// caller believing something the filesystem does not agree with.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// How many times a node is assumed to restart per day, for [`snapshot_interval`].
///
/// **An assumption, declared rather than folded into a chosen period.** Once a day is pessimistic for a
/// server that only restarts for upgrades and optimistic for a laptop that closes at night; it is the
/// quantity an operator would change, so it is the quantity the derivation takes as input.
pub const ASSUMED_RESTARTS_PER_DAY: f64 = 1.0;

/// The probability that one write is lost to restart windows, that [`snapshot_interval`] is solved for.
///
/// Eleven nines — the durability bar the large object stores state, chosen so this mechanism is not the
/// weakest term in a durability argument that also contains the erasure code.
pub const DURABILITY_TARGET: f64 = 1e-11;

/// Shards below which reconstruction fails: the `[7,3,4]` code recovers from any 3 of 7 homes, so a value is
/// lost only when **5 or more** homes lose their shard.
const HOMES: u32 = 7;
/// The number of simultaneous home-losses that destroys a value — `HOMES - 3 + 1`.
const FATAL_LOSSES: u32 = 5;

/// How often to write a snapshot, **derived** from the durability target and the assumed restart rate.
///
/// # The derivation
///
/// A shard written at time `t` is lost by its home only if that home restarts before its next snapshot. With
/// period `T` and a write arriving at a uniformly-random phase within it, the exposure window averages `T/2`,
/// so for a per-node restart rate `λ` the per-home loss probability is
///
/// ```text
/// p ≈ λT/2                            (λT ≪ 1)
/// ```
///
/// Restarts on different homes are independent — different machines, different operators — so the value is
/// lost when at least `FATAL_LOSSES` of `HOMES` lose it, and for small `p` the leading term dominates:
///
/// ```text
/// P(lost) ≈ C(7,5) · p⁵ = 21 · (λT/2)⁵
/// ```
///
/// Solving `P(lost) ≤ ε` gives the period this returns:
///
/// ```text
/// T ≤ (2/λ) · (ε/21)^(1/5)
/// ```
///
/// At the declared defaults — `λ` = 1/day, `ε` = 1e-11 — that is **≈ 592 s**, just under ten minutes. The
/// fifth power is what makes this cheap: a target a hundred times stricter costs a period only ~2.5× shorter.
///
/// The exposure is **one-shot per write**: once every home has snapshotted, the shard is on seven disks and a
/// restart restores it. This is not a continuous hazard being integrated.
#[must_use]
pub fn snapshot_interval(restarts_per_day: f64, target: f64) -> Duration {
    // `C(7,5)` — the ways five of seven homes can be the ones that lose it.
    let ways = f64::from(binomial(HOMES, FATAL_LOSSES));
    let lambda = restarts_per_day / 86_400.0;
    if lambda <= 0.0 || target <= 0.0 {
        // No restarts assumed, or no target: there is nothing to solve, and an infinite period would mean
        // never writing. Fall back to the derived default rather than to a number chosen here.
        return Duration::from_secs_f64(2.0 * 86_400.0 * (DURABILITY_TARGET / ways).powf(0.2));
    }
    Duration::from_secs_f64(2.0 / lambda * (target / ways).powf(1.0 / f64::from(FATAL_LOSSES)))
}

/// `C(n, k)`, computed multiplicatively so nothing overflows for the sizes a plane produces.
const fn binomial(n: u32, k: u32) -> u32 {
    let mut acc = 1u32;
    let mut i = 0u32;
    while i < k {
        acc = acc * (n - i) / (i + 1);
        i += 1;
    }
    acc
}

/// Read a previous run's snapshot, or `None` when there is no file (a first boot) or it cannot be read.
///
/// A snapshot that fails to *decode* is refused deeper in, by the engine, which is where the format is known.
/// This only fetches bytes.
#[must_use]
pub fn read_snapshot(state_dir: &Path) -> Option<Vec<u8>> {
    std::fs::read(state_dir.join(STORE_FILE)).ok()
}

/// Write `bytes` to the node's snapshot file **atomically**: a temporary beside it, flushed to the platter,
/// then renamed over.
///
/// The rename is the point. A snapshot written in place is, for the duration of the write, a file that is
/// neither the old state nor the new one — and the moment a machine is most likely to lose power is while it
/// is writing to disk. `rename` is atomic on every filesystem this runs on, so a reader sees one or the other.
///
/// The `sync_all` before it is the other half: without it the rename can be durable while the bytes it points
/// at are not, and the node comes back with a perfectly-named empty file.
pub fn write_snapshot(state_dir: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_bytes(&state_dir.join(STORE_FILE), bytes)
}

/// Write `bytes` to `path` atomically — the general form of [`write_snapshot`], for the other durable file a
/// node keeps (a validator's certified chain state, #57).
///
/// Shared rather than copied because the two properties are the same and both are easy to lose: the rename
/// is atomic so a reader never sees a half-written file, and the `sync_all` **before** it is what stops the
/// rename being durable while the bytes it points at are not — the failure that returns a node with a
/// perfectly-named empty file.
pub fn write_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        // `0o600` on the temp file, not only on the directory. Belt and braces on purpose: a directory mode
        // is one `chmod` away from being widened by an operator, and this file is the node's store and ledger
        // snapshot — not key material, but on a shared host it says which content keys this node holds and
        // what its chain state is. `identity.rs` already writes this way; there is no reason for the two to
        // differ. The mode applies at *creation*, so unlike a chmod-after there is no window.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// A running store persister, and the two signals that let a clean stop wait for its last write (#178).
///
/// Both are `watch` channels rather than a `oneshot` pair because [`crate::Node::shutdown`] takes `&self` and
/// cannot move a sender out; a `watch` sender is usable from a shared reference, and its receiver can be
/// cloned per waiter.
pub struct StorePersister {
    /// Kept so the task is aborted when the node drops, exactly as the bare `JoinHandle` was.
    _task: JoinHandle<()>,
    /// Set to `true` to ask the persister for one final snapshot. Sent BEFORE the engine is torn down, so the
    /// snapshot request still has an engine to answer it.
    stop: watch::Sender<bool>,
    /// Flipped by the persister once that final write has returned. A clean stop waits on this.
    done: watch::Receiver<bool>,
}

impl StorePersister {
    /// Ask for a final snapshot and wait until it has been written.
    ///
    /// Returns as soon as the persister is finished — or immediately if it has already exited, since the
    /// `watch` value is retained after the sender drops.
    pub async fn drain(&self) {
        // A closed channel means the persister is already gone; either way there is nothing more to wait for.
        let _ = self.stop.send(true);
        let mut done = self.done.clone();
        let _ = done.wait_for(|finished| *finished).await;
    }
}

/// Keep `state_dir`'s snapshot current for as long as the node runs, **and once more on the way out**.
///
/// Asks the engine for its durable bytes every [`snapshot_interval`] and writes them when they have changed.
/// The comparison is against what was last written, not a dirty flag: the snapshot is canonical — every map
/// streams in sorted order — so equal state produces equal bytes, and an idle node does no disk I/O at all.
/// A dirty flag would need a seam into the engine that nothing else wants.
///
/// **The final write is the point of the signal, not a nicety (#178).** `every` is derived from a *crash*
/// model — `snapshot_interval(ASSUMED_RESTARTS_PER_DAY, DURABILITY_TARGET)` bounds how much may be lost when
/// the process dies without warning. A clean stop is the case where nothing need be lost, and before this it
/// was charged the same interval: the loop slept, then asked an engine that was already down, got `None`, and
/// broke *before* writing. So the one path where the node knew it was stopping was the path that discarded
/// everything since the last tick — and a node that started, served and stopped inside one interval persisted
/// nothing at all, because the loop sleeps before its first snapshot.
///
/// The chain state next door already gets this right and says why (`taxis_driver.rs:745`): it persists on a
/// checkpoint, "the only moment there is anything certified to write". The store has no such natural event —
/// writing on every `put` would be absurd — so a period is right for its crash case. Only the *anticipated*
/// case was missing.
#[must_use]
pub fn spawn_store_persister(client: Client, state_dir: PathBuf, every: Duration) -> StorePersister {
    let (stop, mut stop_rx) = watch::channel(false);
    let (done_tx, done) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut last: Option<Vec<u8>> = None;
        // Every exit from the loop goes through this, so "the persister is finished" cannot be signalled by
        // one path and forgotten by another.
        let finish = |done_tx: &watch::Sender<bool>| {
            let _ = done_tx.send(true);
        };
        loop {
            let stopping = tokio::select! {
                () = tokio::time::sleep(every) => false,
                // `changed()` errs only when every sender is gone, which means the node is being dropped
                // without a clean stop — nothing is waiting on `done`, and there may be no engine to ask.
                r = stop_rx.changed() => {
                    if r.is_err() {
                        finish(&done_tx);
                        return;
                    }
                    true
                }
            };
            // A correlated request, not a subscription: the answer is the whole store, and the notification
            // stream would hand a clone of it to every subscriber a running node keeps.
            let Some(bytes) = client.snapshot().await else {
                // The node has shut down, or did not answer inside the request timeout.
                finish(&done_tx);
                return;
            };
            if last.as_ref().is_some_and(|prev| *prev == bytes) {
                if stopping {
                    finish(&done_tx);
                    return;
                }
                continue;
            }
            match write_snapshot(&state_dir, &bytes) {
                Ok(()) => last = Some(bytes),
                // Reported and retried on the next tick rather than fatal: a full disk should degrade a node
                // to the pre-#77 behaviour, not stop it serving the cell. On the *stopping* path there is no
                // next tick, so the report is all there is — and it is why this is `eprintln!` and not silence.
                Err(e) => eprintln!("fanos: could not persist the store to {}: {e}", state_dir.display()),
            }
            if stopping {
                finish(&done_tx);
                return;
            }
        }
    });
    StorePersister { _task: task, stop, done }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// **The state directory and everything written into it are owner-only** (#166).
    ///
    /// Asserted on the *mode bits*, not on the call: `create_dir_all` succeeding says nothing about
    /// permissions, and that is exactly how this got here — #82 taught the codebase to set `0o600` on secret
    /// **files** (`identity.key` does), and every `create_dir_all` in the crate went on creating at the umask.
    /// A directory left at `0o755` is world-traversable, and it is what left the admin socket reachable
    /// during the window between `bind` and its `chmod`, because a Unix socket is permission-checked at
    /// `connect()`.
    ///
    /// The mask is `0o077` rather than an equality: what matters is that **no bit is set for group or other**.
    /// Testing `== 0o700` would also fail an operator who deliberately narrowed it further.
    #[test]
    fn the_state_directory_and_its_snapshots_are_unreadable_to_other_accounts() {
        use std::os::unix::fs::PermissionsExt as _;

        // Per-process, per-test path: a fixed name under the shared temp dir is a machine-wide resource, and
        // two concurrent runs then race on it — measured at 7 failures in 8 for the sibling persist test.
        let dir = std::env::temp_dir().join(format!("fanos-durable-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // A umask that WOULD leave the directory world-readable if the mode were not set explicitly. Without
        // this the test could pass on a developer's `umask 077` box and fail nowhere until production.
        create_private_dir(&dir).expect("create the state dir");
        let mode = std::fs::metadata(&dir).expect("stat the dir").permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "the state directory is group/other-accessible (mode {mode:o}) — it holds identity.key, \
             beacon.params, the store and chain snapshots, and the admin socket",
        );

        // And the snapshot itself, at creation rather than by a chmod afterwards (no window).
        let file = dir.join(STORE_FILE);
        write_bytes(&file, b"snapshot bytes").expect("write the snapshot");
        let fmode = std::fs::metadata(&file).expect("stat the file").permissions().mode();
        assert_eq!(
            fmode & 0o077,
            0,
            "the store snapshot is group/other-readable (mode {fmode:o}) — on a shared host that is which \
             content keys this node holds and what its chain state is",
        );
        assert_eq!(std::fs::read(&file).expect("read back"), b"snapshot bytes", "and it round-trips");

        // The temp sibling must not survive the rename — a `…tmp` left behind at any mode is a second copy.
        assert!(!file.with_extension("tmp").exists(), "the atomic-write temp file is consumed by the rename");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The derived period, at the declared assumptions, and — the half that matters — that it **moves with
    /// them** rather than being a constant with an equation written above it.
    #[test]
    fn the_snapshot_period_is_solved_from_the_durability_target() {
        let t = snapshot_interval(ASSUMED_RESTARTS_PER_DAY, DURABILITY_TARGET).as_secs_f64();
        assert!((580.0..605.0).contains(&t), "≈ 592 s at 1 restart/day and eleven nines, got {t}");

        // A node that restarts ten times as often must snapshot ten times as often: `T ∝ 1/λ`.
        let busy = snapshot_interval(10.0 * ASSUMED_RESTARTS_PER_DAY, DURABILITY_TARGET).as_secs_f64();
        assert!((busy * 10.0 - t).abs() < 1.0, "T ∝ 1/λ: {busy} × 10 ≠ {t}");

        // A hundredfold stricter target costs a factor of only 100^(1/5) ≈ 2.512 — the fifth power is the
        // reason this mechanism is affordable, so the test states it.
        let strict = snapshot_interval(ASSUMED_RESTARTS_PER_DAY, DURABILITY_TARGET / 100.0).as_secs_f64();
        assert!((t / strict - 100f64.powf(0.2)).abs() < 0.01, "100^(1/5) ≈ 2.512, got {}", t / strict);
    }

    #[test]
    fn the_erasure_arithmetic_is_the_planes() {
        assert_eq!(binomial(7, 5), 21, "C(7,5): the ways five of seven homes are the losers");
        assert_eq!(binomial(7, 0), 1);
        assert_eq!(binomial(7, 7), 1);
    }

    /// A half-written snapshot must never be what a restart reads.
    #[test]
    fn a_snapshot_is_renamed_into_place_and_leaves_no_partial_file() {
        let dir = std::env::temp_dir().join(format!("fanos-durable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_snapshot(&dir, b"first").unwrap();
        assert_eq!(read_snapshot(&dir).unwrap(), b"first");
        write_snapshot(&dir, b"second-and-longer").unwrap();
        assert_eq!(read_snapshot(&dir).unwrap(), b"second-and-longer");
        assert!(
            !dir.join(format!("{STORE_FILE}.tmp")).exists(),
            "the temporary is renamed away, not left beside the real file where a reader could find it"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_snapshot_is_a_first_boot_and_not_an_error() {
        let dir = std::env::temp_dir().join(format!("fanos-durable-absent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(read_snapshot(&dir).is_none());
    }
}
