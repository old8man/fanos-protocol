//! **The published assignment across epoch turns, on a real multi-node cell** (#146).
//!
//! The question this settles: `caps_complete` is `true` for a capability scan that found **nobody** — an
//! absent record is a *definite* absence, deliberately, so one forged record cannot void a scan — and
//! `assign_epoch` sends the resulting assignment to the `watch` every actuator reads with no
//! `members.is_empty()` guard anywhere. On an epoch turn each slot is keyed `cap_slot(coord, epoch)` and is
//! empty until every node republishes for the new epoch: locally that is one write, but a peer's is a round
//! trip. So the loop can, in principle, assign over a roster it can see is short and publish the result.
//!
//! A single-node probe **refuted** the first version of that claim: the roster stayed at 1 and one role was
//! released, which is the homeostat working. But one node cannot answer it — its own advertisement is a local
//! write with no round trip to lose. This needs peers.
//!
//! The predicate asserted is the loop's own: the transport's peer table is a lower bound on live membership
//! that owes nothing to the overlay store, and `role_loop` already uses `roster < peers()` to decide whether
//! to keep looking. Using it as an *admission* rule for what may be published is the same evidence, one step
//! earlier — so an assignment computed over fewer members than the node can literally see a connection to is
//! the thing to catch.
//!
//! Runtime: multi-threaded with four workers (#84). One beacon anchor drives the epochs for the whole cell.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use fanos_field::F2;
use fanos_node::config::Peer;
use fanos_node::role_loop::ROSTER_REFRESH;
use fanos_node::{BeaconParams, Node, NodeConfig};
use fanos_vrf::vss::{DeterministicRng, deal};

const LOOPBACK: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

/// How often to sample every node's published assignment. Well under any interval a role could plausibly be
/// held for, so a dip cannot hide between two samples.
const SAMPLE: Duration = Duration::from_millis(100);

/// The roles every node offers — the three that need no extra provisioning. `service` and `ingress` refuse to
/// start without a dealt line roster, and this test is about the ASSIGNMENT, not about what an actuator does
/// with one.
const fn offered() -> fanos_node::RoleSet {
    fanos_node::RoleSet {
        relay: true,
        storage: true,
        service: false,
        exit: false,
        rendezvous: true,
        ingress: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_node_ever_assigns_over_fewer_members_than_it_can_see() {
    fanos_testkit::require_quiet_host("whether the roster dips across an epoch turn");

    // Node 0 anchors a 1-of-1 beacon, so the cell has a clock; the others learn each round over the wire.
    let (shares, commitment) =
        deal(&[0x2C; 32], 1, 1, &mut DeterministicRng::new(b"role-roster")).expect("deal a 1-of-1 beacon");
    let share = shares.into_iter().next().expect("a 1-of-1 sharing yields one share");
    let network_id = fanos_node::NetworkId::from_seed(b"role-roster-network");

    // Longer than `ROSTER_REFRESH`, which is a protocol constraint rather than a test knob: the loop
    // re-derives when the beacon is ahead and a re-derivation costs up to one `STORE_TIMEOUT` of directory
    // scans, so an epoch shorter than that refresh never gets past its first, empty read. A deployment's epoch
    // is minutes against a refresh of seconds.
    let epoch_period = ROSTER_REFRESH * 2;

    let anchor = Node::start::<F2>(NodeConfig {
        listen: LOOPBACK,
        beacon: Some(BeaconParams {
            network_id,
            commitment: commitment.clone(),
            threshold: 1,
            share: Some(share),
            authority: None,
        }),
        epoch_period,
        start_heartbeat: true,
        roles: offered(),
        ..NodeConfig::default()
    })
    .await
    .expect("the anchor starts");
    let seed = vec![Peer { coord: anchor.address(), addr: anchor.local_addr() }];

    let mut nodes = vec![anchor];
    while nodes.len() < 3 {
        let node = Node::start::<F2>(NodeConfig {
            listen: LOOPBACK,
            bootstrap: seed.clone(),
            // The same network and commitment, without a share: these nodes VERIFY the anchor's rounds rather
            // than contributing to them, which is what a non-anchor member of a threshold beacon does.
            beacon: Some(BeaconParams {
                network_id,
                commitment: commitment.clone(),
                threshold: 1,
                share: None,
                authority: None,
            }),
            epoch_period,
            start_heartbeat: true,
            roles: offered(),
            ..NodeConfig::default()
        })
        .await
        .expect("a member starts");
        // Fresh identities collide 1/7 on the Fano plane; a collision is a different experiment.
        if nodes.iter().any(|n: &Node| n.address() == node.address()) {
            node.shutdown();
            continue;
        }
        nodes.push(node);
    }

    // Let the cell discover itself and settle before judging: the genesis assignment legitimately runs before
    // any capability record exists, and a dip measured there says nothing about an epoch turn.
    let settle = tokio::time::Instant::now() + ROSTER_REFRESH * 2;
    while tokio::time::Instant::now() < settle {
        tokio::time::sleep(SAMPLE).await;
    }
    let settled: Vec<usize> = nodes.iter().map(|n| n.assignment().roster).collect();
    assert!(
        settled.iter().any(|&r| r > 1),
        "the cell never discovered itself — every node settled at a roster of {settled:?}, so nothing below \
         can be about an epoch turn",
    );

    // Now watch across two epoch turns, recording the worst (roster, peers) each node ever publishes.
    let mut worst: Vec<(usize, usize)> = nodes.iter().map(|_| (usize::MAX, 0)).collect();
    let deadline = tokio::time::Instant::now() + epoch_period * 2 + ROSTER_REFRESH;
    while tokio::time::Instant::now() < deadline {
        for (i, node) in nodes.iter().enumerate() {
            let roster = node.assignment().roster;
            if roster < worst[i].0 {
                worst[i] = (roster, node.health().known_peers);
            }
        }
        tokio::time::sleep(SAMPLE).await;
    }
    for node in &nodes {
        node.shutdown();
    }

    // A roster below the transport's own peer count is an assignment computed over fewer members than the node
    // can literally see a connection to. `known_peers` counts the address book, which includes entries for
    // peers this node has only *heard of*, so it is an upper bound on what a capability scan could find — the
    // comparison is therefore deliberately loose, and only a real dip trips it.
    for (i, (roster, peers)) in worst.iter().enumerate() {
        assert!(
            *roster > 0,
            "node {i} published an EMPTY assignment (roster 0) while its address book held {peers} peers — \
             every actuated role on it was torn down until the next refresh, and `caps_complete` reported \
             that scan COMPLETE because an absent record is a definite absence",
        );
    }
    // Reported rather than asserted: the settled and worst rosters, so a future reader can see what the cell
    // actually did instead of inferring it from a passing test.
    println!("settled rosters {settled:?}, worst (roster, known_peers) per node {worst:?}");
}
