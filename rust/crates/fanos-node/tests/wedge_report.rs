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

mod common;

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
