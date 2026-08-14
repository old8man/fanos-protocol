//! **The wedge report must discriminate, not merely print** (#182).
//!
//! `host_registered` spends [`common::FROZEN_SPAN`] and then panics `REFUTED — no notification of any kind`.
//! That sentence is true of three different systems: a member that is not being scheduled at all, a member
//! that is running and has received nothing, and a member that received the registration and refused it.
//! Those call for opposite next steps, and the panic printed the same words for all three.
//!
//! The instrument that separates them already existed — `OffCombiner::autopsy`, a **private** method whose
//! only caller is `#[ignore]`d. So the diagnosis lived in the twin nobody runs. It is now
//! [`common::data_path_report`], and the REFUTED path calls it on both ends of the registration.
//!
//! **This file exists because a report is not evidence until it has been shown to say two different things.**
//! An instrument asserted only where it succeeds is indistinguishable from one that always prints the same
//! string. Producing the second direction took three attempts, and the first two were refuted by measurement
//! rather than by argument — both are recorded at the assertions below, because each is a fact about this
//! platform that the next reader would otherwise have to rediscover:
//!
//! 1. `NodeHandle::shutdown()` — REFUTED. The driver answered `Observe` in ~3.6 ms for the whole 240 s
//!    ceiling. `shutdown` closes the QUIC endpoint and raises the stopping flag; the engine actor keeps
//!    servicing LOCAL commands, which is *right* — a draining node still has readings to give, and a
//!    sense-only verb is what an operator should still get. "Stopped" and "not scheduling" are different.
//! 2. `drop(node)` — REFUTED, in 3.5 ms. `Client` owns an `input_tx`, so **the probe itself keeps the
//!    engine's receiver open**. "The engine is gone" is unreachable from any test still holding the client it
//!    would ask with; that state belongs to `Client::is_stopping`'s unit test, which drops the receiver
//!    directly.
//! 3. Taking the node's **runtime** away — which is what a wedge actually is: the task exists, its channel is
//!    open, and nothing runs it.
//!
//! Two runtimes, therefore, and a plain `#[test]`: the probe must keep being scheduled while the node stops
//! being scheduled, and `#[tokio::test]` gives only one scheduler to stop.
//!
//! It stands up ONE node rather than a cell: nothing here is about the anonymous path, and taking the
//! whole-cell fixture lock to prove a two-valued property would make this the slowest test of a claim that
//! needs no cell at all.

#![allow(clippy::expect_used)]

use std::time::Duration;

use fanos_field::F2;
use fanos_node::{Node, NodeConfig};
// The harness measures granted time on tokio's clock, not the std one; the two are distinct types and the
// compiler is what said so.
use tokio::time::Instant;

mod common;

/// **The same subject, one layer down: a drained budget must not always accuse the code** (#343).
///
/// The read half of this harness already split a drained budget three ways — INCONCLUSIVE when the runtime
/// was not polled enough to judge, REFUTED when it demonstrably WAS running and still made no progress. Its
/// two siblings, the write and half-close in `exchange` and the write in `echo`, said only `REFUTED`. That is
/// a claim about the CODE, made on a host that may never have scheduled them, and `within_span`'s own doc
/// calls that the dangerous direction: it "sends the reader hunting a defect the machine invented".
///
/// The verdict is now one function. This drives it to both of its outcomes, because a three-valued verdict
/// asserted at one value is a two-valued one with extra words.
#[test]
fn a_drained_budget_accuses_the_code_only_when_the_runtime_was_actually_running() {
    // A runtime is needed for the heartbeat task itself; `block_on` keeps the assertions outside it, so the
    // panic each direction raises is caught here rather than unwinding through the executor.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("the runtime builds");

    // DIRECTION 1 — a window in which this task was NEVER polled. `beats_before` is read at the same instant
    // the window opens, so no heartbeat can have landed inside it: the ratio is 0 and the honest verdict is
    // that the run says nothing at all about the system.
    let starved = std::panic::catch_unwind(|| {
        let beats = rt.block_on(async { common::heartbeat() });
        common::drained_budget(beats, Instant::now(), "nothing was attempted");
    })
    .expect_err("a drained budget always diverges");
    let starved = message(&starved);
    assert!(
        starved.contains("INCONCLUSIVE"),
        "a window the runtime never ran in cannot convict the code: {starved}"
    );

    // DIRECTION 2 — the same call after the heartbeat has demonstrably been polled across the window. Without
    // this the assertion above is satisfied by a verdict that says INCONCLUSIVE unconditionally, which is the
    // failure mode this replaced in the other direction.
    let wedged = std::panic::catch_unwind(|| {
        let opened = Instant::now();
        let beats = rt.block_on(async {
            let before = common::heartbeat();
            // Long enough that the heartbeat's own POLL cadence fills the window; the ratio is computed
            // against elapsed time, so sleeping ON the runtime is what makes `ran` rise.
            tokio::time::sleep(Duration::from_millis(600)).await;
            before
        });
        common::drained_budget(beats, opened, "nothing moved");
    })
    .expect_err("a drained budget always diverges");
    let wedged = message(&wedged);
    assert!(
        wedged.contains("REFUTED"),
        "a runtime that was demonstrably polled and still made no progress IS the verdict this exists to \
         reach: {wedged}"
    );
}

/// The panic payload as text — `panic!` and a failed `assert!` both arrive as `String` here.
fn message(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_else(|| "<non-string panic payload>".to_owned())
}

/// **One verdict, not three** — a ratchet over the harness's own source (#343).
///
/// The defect this closes was not a wrong message; it was the same decision made in three places and kept in
/// step in only one. A future wait that drains its budget and calls `.expect("REFUTED …")` would re-open it
/// silently, so the rule is mechanical: a *drained budget* — `within_span` answering `None` — leaves through
/// [`common::drained_budget`] and nowhere else.
///
/// `panic!("REFUTED …")` is deliberately still allowed: the stream-closed cases in `exchange` and `echo` are
/// **definite events**, not silence, and a host that never scheduled them cannot produce one. Widening this
/// to every `REFUTED` would forbid the honest ones and teach the next reader to disable the guard.
#[test]
fn every_drained_budget_in_the_harness_leaves_through_one_verdict() {
    let source = include_str!("common/mod.rs");
    // The scan must be able to SEE the shape it forbids, or it passes vacuously for ever.
    let needle = format!(".expect({}REFUTED", '"');
    assert!(
        source.contains("fn drained_budget("),
        "the shared verdict is gone from the harness — move this guard with it, or it now checks nothing"
    );
    let offenders: Vec<&str> = source.lines().filter(|l| l.contains(&needle)).collect();
    assert!(
        offenders.is_empty(),
        "a drained budget is reported outside `drained_budget`, so it can only ever say REFUTED — on a host \
         that may not have scheduled it at all: {offenders:?}"
    );
}

#[test]
fn the_data_path_probe_tells_a_scheduling_node_from_one_that_is_not() {
    let node_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("the node's own runtime builds");
    let probe_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("the prober's runtime builds");

    let (node, client) = node_rt.block_on(async {
        let node = Node::start::<F2>(NodeConfig {
            listen: "127.0.0.1:0".parse().expect("loopback addr"),
            // No beacon and no heartbeat: this asks whether the driver answers its own sense-only verb, and
            // a node with an epoch clock ticking would answer for reasons unrelated to the question.
            epoch_period: Duration::from_secs(3600),
            start_heartbeat: false,
            ..NodeConfig::default()
        })
        .await
        .expect("the node starts");
        let client = node.client();
        (node, client)
    });

    // DIRECTION 1 — a node being scheduled answers, and the report SAYS SO with a measured elapsed time.
    // The elapsed figure is the point: the version this replaced thresholded a chosen 4 s, so "busy" and
    // "wedged" printed identically on either side of a number nobody derived.
    let live = probe_rt.block_on(common::data_path_report(&client));
    // Printed, not only asserted: this file's subject IS what the report says, and an assertion that admits
    // more than one wording (below) would otherwise leave the reader guessing which one held.
    println!("scheduled:     {live}");
    assert!(
        live.starts_with("answered in"),
        "a scheduled node must answer `Observe`, the sense-only read a passive monitor may issue — got: \
         {live}"
    );
    // The control on the control: a fresh node has received nothing, so this must be the "saw nothing"
    // reading rather than a station list. If it ever carries counts, the two readings the REFUTED path
    // distinguishes have stopped being distinguishable on a node that has done nothing.
    assert!(
        live.contains("(every station zero)"),
        "a node that has taken no traffic must report every station zero, not an empty tail that reads as \
         truncated output — got: {live}"
    );

    // DIRECTION 2 — the wedge itself: the driver's task still exists and its channel is still open, and
    // nothing is running it. `shutdown_timeout` blocks until the tasks are dropped, so this is a state and
    // not a race; `drop(node)` afterwards is only tidiness, since the handle no longer drives anything.
    node_rt.shutdown_timeout(Duration::from_secs(5));
    let wedged = probe_rt.block_on(common::data_path_report(&client));
    drop(node);
    println!("not scheduled: {wedged}");
    assert!(
        !wedged.starts_with("answered in"),
        "a node nothing is scheduling must not read as one that answered: {wedged}"
    );
    // Either non-answer is correct and they are different facts, so both are named rather than collapsed:
    // the actors may already have been dropped (closing the input channel, which `command` reports at once)
    // or still be sitting un-polled (no answer within the span). What must never happen is a THIRD outcome.
    assert!(
        wedged.contains("the engine is gone") || wedged.contains("no DataPath answer"),
        "and it must say WHICH silence this is — a refused command is knowable at once, where a wedge costs \
         a whole span to establish: {wedged}"
    );
}
