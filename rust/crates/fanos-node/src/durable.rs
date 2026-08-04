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
use tokio::task::JoinHandle;

/// The file a node's durable store lives in, inside its state directory.
pub const STORE_FILE: &str = "store.snapshot";

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
    std::fs::create_dir_all(state_dir)?;
    let final_path = state_dir.join(STORE_FILE);
    let tmp = state_dir.join(format!("{STORE_FILE}.tmp"));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &final_path)
}

/// Keep `state_dir`'s snapshot current for as long as the node runs.
///
/// Asks the engine for its durable bytes every [`snapshot_interval`] and writes them when they have changed.
/// The comparison is against what was last written, not a dirty flag: the snapshot is canonical — every map
/// streams in sorted order — so equal state produces equal bytes, and an idle node does no disk I/O at all.
/// A dirty flag would need a seam into the engine that nothing else wants.
///
/// Ends when the node does.
#[must_use]
pub fn spawn_store_persister(client: Client, state_dir: PathBuf, every: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut last: Option<Vec<u8>> = None;
        loop {
            tokio::time::sleep(every).await;
            // A correlated request, not a subscription: the answer is the whole store, and the notification
            // stream would hand a clone of it to every subscriber a running node keeps.
            let Some(bytes) = client.snapshot().await else {
                break; // the node has shut down, or did not answer inside the request timeout
            };
            if last.as_ref().is_some_and(|prev| *prev == bytes) {
                continue;
            }
            match write_snapshot(&state_dir, &bytes) {
                Ok(()) => last = Some(bytes),
                // Reported and retried on the next tick rather than fatal: a full disk should degrade a node
                // to the pre-#77 behaviour, not stop it serving the cell.
                Err(e) => eprintln!("fanos: could not persist the store to {}: {e}", state_dir.display()),
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
