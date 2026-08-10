//! **A node that cannot persist keeps serving — and says so, as a state rather than a stream (#200).**
//!
//! The persister already degraded correctly: a failed write is reported and retried on the next tick, so a
//! full disk drops the node to the pre-#77 behaviour instead of stopping it serving the cell. What it did
//! not do was leave the fact anywhere a reader could find it. The report was one `eprintln!` per tick and
//! nothing else, so "I am running without durable state" existed only as lines in a stream: an operator who
//! attached later, ran `fanos status health`, or scraped the data-path plane saw a node indistinguishable
//! from a healthy one. It is the [[state-carried-as-an-event]] shape on the one condition whose whole
//! consequence is discovered at the *next* restart.
//!
//! Both readers are asserted here, because they answer different questions and one cannot cover the other:
//!
//! * `Durability` is a **level** — is this node durable *now* — which is what an operator wants at the
//!   console during an incident, and which a late reader still gets.
//! * `Station::SnapshotWriteFailed` is a **count** — has this disk been failing — which the level cannot
//!   answer, because a run of failures that has ended leaves no trace in it by design.
//!
//! ## How the failure is injected, and why not with permissions
//!
//! The state directory is **replaced by a regular file** between the two phases. `create_dir_all` returns an
//! error when the path exists and is not a directory, and that is true for `root` as well — where a `chmod
//! 0o500` is simply ignored, so a permission-based injection would turn this test into one that silently
//! passes in any container that runs as root. Same reasoning as
//! [[a-silent-guard-is-not-evidence]]: the injection has to be one whose failure to bite is visible.
//!
//! ## The interval is this test's, and the function is production's
//!
//! `spawn_store_persister` takes its period as an argument; a deployment passes the derived
//! `snapshot_interval(ASSUMED_RESTARTS_PER_DAY, DURABILITY_TARGET)`, which is minutes long. Passing a short
//! one here changes *when* the loop runs and nothing about what it does — every line under test is the
//! shipped one. The `Failing` state is unreachable through `Node` inside a test for exactly that reason, so
//! the `Health` half below covers the two states a node can be *started* in, and this half covers the
//! transition.

#![allow(clippy::expect_used, clippy::unwrap_used)]

/// The persister tick every test here drives, so the derived budgets below are about the same clock.
const TICK: Duration = Duration::from_millis(20);
/// For waits on the persister's own loop, which turns on `TICK` — generous by two orders of magnitude, so
/// a loaded box does not turn a logic assertion into a timing one.
const QUICK: Duration = Duration::from_secs(10);

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fanos_field::F2;
use fanos_node::durable::{Durability, PersistFailure, spawn_store_persister};
use fanos_node::{Node, NodeConfig};
use fanos_runtime::ports::stations::Station;

/// A directory of this test's own, removed when it drops.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("fanos-durable-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch root");
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

/// A node that keeps nothing of its own, so the only persister touching a state directory is this test's.
fn config() -> NodeConfig {
    NodeConfig {
        listen: "127.0.0.1:0".parse::<SocketAddr>().expect("loopback addr"),
        epoch_period: Duration::from_secs(3600),
        start_heartbeat: false,
        state_path: None,
        ..NodeConfig::default()
    }
}

/// Poll until `f` holds, or give up after `label`'s worth of waiting.
///
/// A bound rather than a fixed sleep: the persister's tick is 20 ms, so a sleep long enough to be safe on a
/// loaded machine would be most of this test's runtime on an idle one — and a sleep *just* long enough is
/// the load-sensitive shape #159 keeps producing.
async fn until(label: &str, budget: Duration, mut f: impl FnMut() -> bool) {
    const STEP: Duration = Duration::from_millis(25);
    let mut waited = Duration::ZERO;
    while waited < budget {
        if f() {
            return;
        }
        tokio::time::sleep(STEP).await;
        waited += STEP;
    }
    panic!("{label} did not happen within {budget:?}");
}


/// **The property: the persister's verdict tracks the disk, in both directions, and the failure is counted.**
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_persister_that_cannot_write_reports_it_as_a_level_and_counts_it_as_an_event() {
    let scratch = Scratch::new("transition");
    let state = scratch.path().join("state");

    let node = Node::start::<F2>(config()).await.expect("node starts");
    let client = node.client();
    let persister = spawn_store_persister(client.clone(), state.clone(), TICK);

    let failures = |kind: PersistFailure| {
        client
            .driver_stations()
            .iter()
            .filter(|o| o.station == Station::SnapshotWriteFailed && o.tag == Some(kind.tag()))
            .map(|o| o.count)
            .sum::<u64>()
    };

    // --- Phase one: a writable directory. ---
    //
    // A `put` first, so the snapshot has changed and the tick actually writes: the loop compares against
    // what it last wrote and skips an unchanged store, which means a test that stored nothing would observe
    // a persister that never touched the disk at all and could not tell that from a working one.
    assert!(client.put(b"first".to_vec(), b"before the disk goes".to_vec()).await, "the put is accepted");
    until("the first snapshot", QUICK, || state.join(fanos_node::durable::STORE_FILE).exists()).await;

    assert_eq!(
        persister.state(),
        Durability::Persisting,
        "a persister whose writes are landing must say so — the success path reports its state too, or \
         `Failing` is the only observable and its absence means nothing"
    );
    assert_eq!(failures(PersistFailure::Periodic), 0, "nothing has failed yet");
    assert_eq!(failures(PersistFailure::Final), 0, "and nothing has stopped yet");

    // --- Phase two: the directory becomes un-creatable. ---
    std::fs::remove_dir_all(&state).expect("remove the state directory");
    std::fs::write(&state, b"not a directory").expect("put a file where the directory was");

    // Change the store again, or the tick has nothing to write and the failure never happens.
    assert!(client.put(b"second".to_vec(), b"after the disk goes".to_vec()).await, "the put is accepted");

    until("the persister to notice", QUICK, || matches!(persister.state(), Durability::Failing { .. }))
        .await;
    let Durability::Failing { consecutive } = persister.state() else {
        unreachable!("the wait above only returns on Failing")
    };
    assert!(consecutive >= 1, "a failure run is at least one long, not zero");

    // The count, which is the half the level cannot carry.
    assert!(
        failures(PersistFailure::Periodic) >= 1,
        "a failed periodic write must move the data-path plane — the level alone cannot answer whether this \
         disk has been failing all week"
    );
    assert_eq!(
        failures(PersistFailure::Final),
        0,
        "and it must be tagged as the retryable one: `final` is a strictly worse event (no next tick, so \
         the window is lost) and folding them together discards exactly that"
    );

    // --- Phase three: the disk comes back. The level must follow it down as well as up. ---
    //
    // Without this the level is indistinguishable from a latch, and a node that recovered would keep
    // reporting an emergency until it was restarted — which is the failure mode of every alarm that is
    // easier to set than to clear.
    std::fs::remove_file(&state).expect("take the file away again");
    assert!(client.put(b"third".to_vec(), b"after the disk returns".to_vec()).await, "the put is accepted");
    until("the persister to recover", QUICK, || persister.state() == Durability::Persisting).await;

    node.shutdown().await;
}

/// **A dead persister stops claiming it is persisting (#251).**
///
/// The level is published through a `watch` whose sender the persister task owns, and `borrow()` on a
/// channel with no senders keeps returning the last value. So a persister that panicked while `Persisting`
/// left every reader — `Health`, `fanos status health`, an operator mid-incident — being told `durable: yes`
/// for the rest of the node's life. #200 made the write failure visible and in the same stroke gave the
/// task's *death* a comfortable place to hide: the one state that reads best.
///
/// This is why the fix is in the type and not in a supervisor task. A dropped sender IS the fact that needs
/// reporting; a third party watching the handle would be a second thing to keep in sync with the first.
///
/// **What this test does NOT show.** `Durability::Stopped` is produced by two mechanisms — the task sends it
/// on the way out, and `state()` also reports it when the channel has no senders left. Removing *either*
/// leaves this test green, because after `drain` returns the task is usually far enough along for the second
/// to cover the first. So this pins the orderly path and nothing more; the panic path has no coverage here,
/// since nothing outside `durable` can make the persister task panic. Both mechanisms are kept on an
/// argument from the code, and the module says so rather than letting a green suite imply otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_persister_that_died_stops_claiming_it_is_persisting() {
    let scratch = Scratch::new("stopped");
    let state = scratch.path().join("state");

    let node = Node::start::<F2>(config()).await.expect("node starts");
    let client = node.client();
    let persister = spawn_store_persister(client.clone(), state.clone(), TICK);

    // Alive and writing, so the reading below is a CHANGE and not the initial value.
    assert!(client.put(b"k".to_vec(), b"v".to_vec()).await, "the put is accepted");
    until("the first snapshot", QUICK, || state.join(fanos_node::durable::STORE_FILE).exists()).await;
    assert_eq!(persister.state(), Durability::Persisting, "alive and landing writes");

    // End the persister through its own clean-stop path and WAIT for it: `drain` asks for a final snapshot
    // and returns once the task has written it and finished, so the sender is dropped by the time this
    // returns. Deterministic, and the same ending a panic produces as far as the channel is concerned.
    //
    // The first version of this test used `node.shutdown()` and waited for the state to change. It never
    // did, at 10 s and again at 20 s — which refuted the assumption behind it: shutting the node down does
    // not stop a persister someone else spawned against its client. Waiting longer would have hidden that;
    // the number is what said the mechanism was wrong ([[measure-the-mechanism-not-the-story]]).
    persister.drain().await;
    assert_eq!(
        persister.state(),
        Durability::Stopped,
        "a persister whose task has ended must not keep reporting the state it held when it died"
    );
    assert_ne!(persister.state(), Durability::Persisting, "and specifically not the one that reads best");
}

/// **The two states a node can be started in, through `Node` and its own `Health` — the production reader.**
///
/// The transition above exercises the persister directly. This one proves the value reaches the surface an
/// operator actually queries, and that the two *quiet* states are distinguishable there: a node with no
/// state directory is a legitimate deployment needing no action, and before #200 it was as silent as a node
/// whose writes were failing. Equally silent is the same as equal, to a reader.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_separates_a_node_that_keeps_nothing_from_one_that_is_keeping_it() {
    let keeps_nothing = Node::start::<F2>(config()).await.expect("node starts");
    assert_eq!(
        keeps_nothing.health().durable,
        Durability::NotConfigured,
        "a node with no state directory must say `NotConfigured`, never `Persisting` — the operator's next \
         action differs and nothing else on the surface tells them apart"
    );
    keeps_nothing.shutdown().await;

    let scratch = Scratch::new("health");
    let keeping = Node::start::<F2>(NodeConfig {
        state_path: Some(scratch.path().to_path_buf()),
        ..config()
    })
    .await
    .expect("node starts");
    assert_eq!(
        keeping.health().durable,
        Durability::Persisting,
        "and a node with one, whose writes have not failed, must say `Persisting`"
    );
    keeping.shutdown().await;
}
