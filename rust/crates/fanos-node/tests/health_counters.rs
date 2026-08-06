//! **Every detector `Health` carries must be readable from both sides** (#149).
//!
//! Three counters were correct, deterministic, and had **no production reader at all** — and in each case the
//! code's own comment said something read it. `Directory::collisions` was documented as *"surfaced here so a
//! node can react (relocate) instead of silently shadowing a peer"*; `Directory::unresolved_drops` as *"shared
//! across clones, so a node's health surface can read it"*. Neither reached `Health`, which by then carried ten
//! other fields — two of them (`verified_claims`, `probe_index`) added by the very investigation these two
//! counters belong to.
//!
//! A counter asserted only at zero is indistinguishable from a field that is always zero, so each is checked in
//! **both** directions: quiet on a fresh node, and moving once the condition is forced. That is the whole
//! difference between an instrument and a decoration.
//!
//! The forcing is done against the `Directory` the node exposes, not by simulating the network condition:
//! `bind` and `note_unresolved_drop` are where the transport raises these, and reaching them through real
//! traffic would test QUIC rather than the health surface. What this pins is the *wiring* — that the number
//! the directory holds is the number `Health` reports — which is exactly what was missing.

#![allow(clippy::expect_used)]

use std::net::SocketAddr;
use std::time::Duration;

use fanos_field::F2;
use fanos_node::{Node, NodeConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nodes_health_reports_the_directory_counters_it_is_documented_to_report() {
    let config = NodeConfig {
        listen: "127.0.0.1:0".parse().expect("loopback addr"),
        epoch_period: Duration::from_secs(3600), // no beacon here; keep the clock out of the way
        start_heartbeat: false,
        ..NodeConfig::default()
    };
    let node = Node::start::<F2>(config).await.expect("the node starts");

    // Quiet to begin with — otherwise a nonzero reading below proves nothing about the condition.
    let before = node.health();
    assert_eq!(before.collisions, 0, "a fresh node has seen no coordinate collision");
    assert_eq!(before.unresolved_drops, 0, "and has dropped nothing for want of an address");

    // Force a genuine collision: two DISTINCT addresses claiming one point, which is what `bind` counts.
    let coord = [1, 0, 1];
    let a: SocketAddr = "127.0.0.1:9001".parse().expect("addr");
    let b: SocketAddr = "127.0.0.1:9002".parse().expect("addr");
    node.directory().insert(coord, a);
    node.directory().insert(coord, b);
    // And a drop for an unresolvable destination.
    node.directory().note_unresolved_drop([0, 1, 1]);

    let after = node.health();
    assert_eq!(
        after.collisions, 1,
        "the health surface did not report the collision the directory counted — the counter's own doc says a \
         node reacts to this by relocating, and a node that cannot read it cannot react",
    );
    assert_eq!(
        after.unresolved_drops, 1,
        "the health surface did not report the unresolved drop — indistinguishable from a quiet cell, which \
         is the opposite diagnosis",
    );
    // Same coordinate, same address is a re-bind, not a collision: a counter that also counted those would
    // read nonzero on every healthy node and mean nothing.
    node.directory().insert(coord, b);
    assert_eq!(node.health().collisions, 1, "a repeat of the SAME binding is not a collision");

    node.shutdown();
}
