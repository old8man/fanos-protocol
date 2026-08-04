//! **A store write that succeeded must never be reported to its caller as a failure.**
//!
//! `Client::put` registers its waiter by sending `Control::Put{digest, reply}`, *then* sends the input that
//! makes the engine answer, then awaits the oneshot. The router consumed both channels in one `tokio::select!`
//! — which polls its branches in **random order**. Whenever the router was mid-iteration while both a
//! registration and its answering `Notification::Stored` were queued, it could take the answer first, find no
//! waiter, and drop it; the registration arriving next iteration was then never resolved, and the client
//! waited out `REQUEST_TIMEOUT` and returned `false` for a write that had landed (#83).
//!
//! Not a test-only concern. Every `(coordinate, epoch)` directory publisher in the tree writes through
//! `put_ephemeral`, so a node could believe its own capability, load or onion-key publish had failed; `get`
//! has the identical shape, so a stored value could report absent.
//!
//! The fix is an ordering one — `biased;`, so the registration channel is always drained first — and this
//! test is shaped to catch its removal: **concurrency is what makes the race reachable**, because a router
//! with a backlog is a router that can pick the wrong branch. Sequential puts on an idle router mostly wake
//! on the registration and would pass either way.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_quic::{Directory, spawn};
use fanos_runtime::{Config, OverlayNode};

/// How many writes are in flight at once.
///
/// **Every number here was measured against the reverted fix, and three plausible shapes caught nothing.**
/// The race needs an answer and a registration queued at the router *simultaneously*, which is a scheduling
/// coincidence rather than something a test can ask for — so the shape had to be found rather than reasoned
/// out. Detection over runs with `biased;` removed:
///
/// | shape | caught |
/// |---|---|
/// | 64, 8 waves of 8, current-thread | 0 of 6 |
/// | 64, one burst, current-thread | 3 of 5 |
/// | 512, one burst, current-thread | 0 of 8 |
/// | 64, one burst, **multi-thread** | 6 of 8 |
/// | 256, one burst, multi-thread, **2 workers** | 3 of 8 |
/// | **256, one burst, multi-thread, 4 workers** | **8 of 8** |
///
/// Two things the table says that intuition did not. **Waves are worse than a burst**, because awaiting each
/// wave leaves the router idle between them and an idle router wakes on the registration it was given first.
/// And on a current-thread runtime **a bigger burst is worse**, because all the spawned tasks are polled
/// before the engine task runs even once, so every registration is enqueued before any answer exists — which
/// is exactly the order the fix guarantees, arrived at by accident. Only real parallelism puts the router,
/// the engine and the clients on separate threads, and only then does burst size help.
const CONCURRENT_WRITES: usize = 256;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_accepted_write_is_acknowledged_to_the_caller_that_made_it() {
    let dir = Directory::new();
    let engine = OverlayNode::<F2>::new(Point::at(0), Config::default());
    let handle = spawn(Box::new(engine), dir).await.expect("spawn the node");
    let client = handle.client();

    // A lone node is the nearest-occupied home for all seven shard points, so each write completes locally
    // and the answer comes back immediately — which is precisely the timing that made the race reachable.
    let writes: Vec<_> = (0..CONCURRENT_WRITES)
        .map(|i| {
            let client = client.clone();
            tokio::spawn(async move {
                let key = format!("store-ack-{i}").into_bytes();
                (i, client.put(key, alloc_value(i)).await)
            })
        })
        .collect();

    let mut refused = Vec::new();
    for w in writes {
        let (i, accepted) = w.await.expect("the write task");
        if !accepted {
            refused.push(i);
        }
    }

    assert!(
        refused.is_empty(),
        "{} of {CONCURRENT_WRITES} writes were reported as failures. A `put` that reaches the engine and is \
         stored must resolve its caller's waiter: the registration is sent strictly before the input that \
         produces the answer, so the router has to drain registrations first or it drops answers on the \
         floor. Refused: {refused:?}",
        refused.len(),
    );
}

/// A value distinct per write, so no two share a digest and each needs its own acknowledgement.
fn alloc_value(i: usize) -> Vec<u8> {
    format!("value-{i}").into_bytes()
}

/// The read side has the same shape, so it gets the same guarantee: a value this node holds must be
/// retrievable while the router is busy, not only while it is idle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_stored_value_is_retrievable_while_the_router_is_busy() {
    let dir = Directory::new();
    let engine = OverlayNode::<F2>::new(Point::at(0), Config::default());
    let handle = spawn(Box::new(engine), dir).await.expect("spawn the node");
    let client = handle.client();

    for i in 0..CONCURRENT_WRITES {
        assert!(
            client.put(format!("read-back-{i}").into_bytes(), alloc_value(i)).await,
            "write {i} must be accepted before the read half can mean anything"
        );
    }

    let reads: Vec<_> = (0..CONCURRENT_WRITES)
        .map(|i| {
            let client = client.clone();
            tokio::spawn(async move {
                (i, client.get(format!("read-back-{i}").into_bytes()).await)
            })
        })
        .collect();

    let mut missing = Vec::new();
    for r in reads {
        let (i, got) = r.await.expect("the read task");
        if got.as_deref() != Some(alloc_value(i).as_slice()) {
            missing.push(i);
        }
    }

    assert!(
        missing.is_empty(),
        "{} of {CONCURRENT_WRITES} stored values read back wrong or absent — a `Retrieved` answer was \
         dropped before its waiter was registered. Missing: {missing:?}",
        missing.len(),
    );
}
