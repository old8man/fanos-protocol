//! **A node that is told to stop writes what it holds before it goes (#178).**
//!
//! The store persister runs on a period derived from a *crash* model — how much may be lost when the process
//! dies without warning. A clean stop is the case where nothing need be lost, and it was charged the same
//! bound: `shutdown()` closed the endpoint, the persister's next `snapshot()` returned `None`, and it exited
//! *before* writing. Everything stored since the last tick went with it, on the one path where the node knew
//! it was stopping. A node that started, served and stopped inside one interval persisted nothing at all,
//! because the loop sleeps before its first snapshot.
//!
//! The interval here is the real derived one — `snapshot_interval(ASSUMED_RESTARTS_PER_DAY,
//! DURABILITY_TARGET)`, minutes long — and these tests run in under a second. So **no periodic tick can fire
//! during them**: any snapshot on disk was written by the shutdown path, which is the only way to attribute
//! the observation to the mechanism under test rather than to luck with a timer.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fanos_field::F2;
use fanos_node::{Node, NodeConfig};

/// A directory of this test's own, removed when it drops.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("fanos-cleanstop-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(state: Option<PathBuf>) -> NodeConfig {
    NodeConfig {
        listen: "127.0.0.1:0".parse::<SocketAddr>().expect("loopback addr"),
        // No beacon and no heartbeat: this is about the store and the exit path, and a running clock would
        // only add traffic that could mask a missing write.
        epoch_period: Duration::from_secs(3600),
        start_heartbeat: false,
        state_path: state,
        ..NodeConfig::default()
    }
}

/// The snapshot file the persister writes, if it exists.
fn snapshot_on_disk(dir: &Path) -> Option<Vec<u8>> {
    std::fs::read(dir.join(fanos_node::durable::STORE_FILE)).ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_stop_writes_the_store_and_a_restart_reads_it_back() {
    let scratch = Scratch::new("roundtrip");
    let key = b"the-key".to_vec();
    let value = b"stored well inside one snapshot interval".to_vec();

    let node = Node::start::<F2>(config(Some(scratch.path().to_path_buf()))).await.expect("node starts");
    assert!(node.client().put(key.clone(), value.clone()).await, "the put is accepted");

    // Nothing on disk yet: the periodic tick is minutes away, so this pins that what follows came from the
    // shutdown path. Without it the test would pass on a build that never had a shutdown write at all.
    assert!(
        snapshot_on_disk(scratch.path()).is_none(),
        "no periodic tick can have fired this early — if a snapshot exists already, the interval is not what \
         this test assumes and the attribution below is worthless"
    );

    node.shutdown().await;
    let written = snapshot_on_disk(scratch.path()).expect("the clean stop wrote the store");
    assert!(!written.is_empty(), "and wrote something, not an empty file");

    // The round trip through the production restore path: a fresh node on the same directory holds the value.
    let restarted = Node::start::<F2>(config(Some(scratch.path().to_path_buf()))).await.expect("restart");
    let got = restarted.client().get(key).await;
    assert_eq!(
        got.as_deref(),
        Some(value.as_slice()),
        "a node that stopped cleanly comes back holding what it held — this is the whole property"
    );
    restarted.shutdown().await;
}

/// The negative half, and the reason the positive one means something.
///
/// A node that stored nothing must still write on a clean stop — a canonical empty snapshot. Without this,
/// the test above passes against a build whose shutdown write fires only when there is data, which is a
/// different and weaker property; and it is the assertion that fails if the drain is skipped entirely,
/// because then the file is absent rather than empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_stop_with_nothing_stored_still_writes_a_snapshot() {
    let scratch = Scratch::new("empty");
    let node = Node::start::<F2>(config(Some(scratch.path().to_path_buf()))).await.expect("node starts");
    node.shutdown().await;

    let written = snapshot_on_disk(scratch.path());
    assert!(
        written.is_some(),
        "the drain must run whether or not anything was stored — a write conditioned on having data is a \
         weaker property than the one this change claims, and indistinguishable from no drain at all here"
    );

    // And it restores to empty rather than to garbage.
    let restarted = Node::start::<F2>(config(Some(scratch.path().to_path_buf()))).await.expect("restart");
    assert_eq!(restarted.client().get(b"never-stored".to_vec()).await, None, "restores empty, not corrupt");
    restarted.shutdown().await;
}

/// A node with no state directory must not be slowed or broken by the drain it does not have.
///
/// The `Option` is a legitimate configuration — a test, a proxy-only client — and `shutdown` became async for
/// the sake of nodes that DO persist. This pins that the other kind still stops, which is the regression a
/// `wait_for` on a channel nobody sends to would produce: a hang, not a failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_keeps_nothing_still_stops() {
    let node = Node::start::<F2>(config(None)).await.expect("node starts");
    tokio::time::timeout(fanos_testkit::LIVENESS_BACKSTOP, node.shutdown())
        .await
        .expect("a node with no persister must not wait on one");
}
