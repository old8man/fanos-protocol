//! Durable local history — atomically snapshot the [`MetricStore`](crate::history::MetricStore) to
//! disk so a node's telemetry survives a restart. The snapshot format is the versioned, self-
//! describing one from [`MetricStore::snapshot`](crate::history::MetricStore::snapshot); this module
//! is just the (std-only) file plumbing, kept minimal and crash-safe.

use std::io::Write;
use std::path::Path;

use crate::history::MetricStore;

/// Atomically persist `store` to `path`: write to a sibling temp file, `fsync`, then rename over the
/// target, so a crash mid-write never corrupts the existing snapshot.
///
/// # Errors
/// Propagates any filesystem error (create, write, sync, or rename).
pub fn save(store: &MetricStore, path: &Path) -> std::io::Result<()> {
    let bytes = store.snapshot();
    let tmp = path.with_extension("fts.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Load a snapshot from `path`. `Ok(None)` if the file is absent *or* the snapshot is corrupt (the
/// caller then starts with fresh history); `Err` only on an actual I/O error.
///
/// # Errors
/// Propagates a filesystem read error other than "not found".
pub fn load(path: &Path) -> std::io::Result<Option<MetricStore>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(MetricStore::restore(&bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::history::{HistoryConfig, MetricId};

    #[test]
    fn save_then_load_round_trips_through_a_file() {
        const S: u64 = 1_000_000_000;
        let mut store = MetricStore::new(HistoryConfig::compact());
        for i in 0..40u64 {
            store.record(
                MetricId::CPU,
                i * S,
                f64::from(u32::try_from(i % 10).unwrap()) / 10.0,
            );
        }
        store.record(MetricId::PHI, 0, 1.5);

        // A unique temp path in the OS temp dir (no external deps).
        let mut path = std::env::temp_dir();
        path.push("fanos-telemetry-persist-test.fts");
        let _ = std::fs::remove_file(&path);

        // Missing file → Ok(None).
        assert!(load(&path).unwrap().is_none());

        save(&store, &path).expect("save");
        let back = load(&path).expect("load io").expect("valid snapshot");
        assert_eq!(back.metrics().count(), store.metrics().count());
        assert_eq!(
            back.range(MetricId::CPU, 0, 100 * S),
            store.range(MetricId::CPU, 0, 100 * S),
            "history restored byte-identically"
        );
        let _ = std::fs::remove_file(&path);
    }
}
