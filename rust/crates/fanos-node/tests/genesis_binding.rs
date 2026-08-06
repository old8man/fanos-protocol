//! **A node is provisioned onto a network twice, and nothing made the two agree** (#141).
//!
//! `genesis_seed(&network_id)` is read at two independent sites: `composition.rs` hands it to the
//! `BeaconNode`, and `node.rs` hands it to `Directory::for_network`. Both derive from the same
//! `BeaconParams::network_id`, so in the shipping configuration they agree — but by *coincidence of two call
//! sites*, which is not an invariant. Until this test there was nothing that would notice if one of them
//! drifted, and drift here is silent by construction: coordinates derive from the seed while the epoch clock
//! runs off the beacon's own, so a split node reports healthy on both halves while sitting in one network's
//! coordinate space and clocking the other's.
//!
//! Worse, it had already happened. `BeaconNode::new` used to start at `[0u8; 32]` and call that "the genesis
//! seed" — true until #98 made the seed `H("FANOS-v1/genesis-beacon" ‖ network_id)` so two deployments would
//! not share every genesis coordinate. After that change a node held two epoch-0 beacons and nothing read
//! them together.
//!
//! The two tests below are the two halves `falsify-every-new-test` asks for: the **property** (the production
//! path agrees, asserted through the real `NodeConfig`), then the **mechanism** (a disagreement is refused,
//! asserted by constructing one the config cannot express).

#![allow(clippy::expect_used)]

use std::time::Duration;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_keygen::BeaconNode;
use fanos_node::{BeaconParams, NetworkId, Node, NodeConfig, OverlayBeaconNode, genesis_seed};
use fanos_quic::{Directory, QuicError};
use fanos_runtime::{Config as OverlayConfig, OverlayNode};
use fanos_vrf::vss::{DeterministicRng, deal};

/// The property: a node built the ordinary way — one `network_id`, both halves derived from it — comes up.
///
/// This is the assertion that pins production, and it can only pass because `spawn_inner` now compares the
/// two. If either call site is ever changed to derive its seed from something else, this test stops the
/// build; before it, the node would have started and been silently split.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_whose_beacon_and_directory_share_a_network_starts() {
    let (shares, commitment) = deal(&[0x9A; 32], 1, 1, &mut DeterministicRng::new(b"genesis-binding"))
        .expect("deal a 1-of-1 beacon");
    let share = shares.into_iter().next().expect("a 1-of-1 sharing yields one share");
    let config = NodeConfig {
        listen: "127.0.0.1:0".parse().expect("loopback addr"),
        beacon: Some(BeaconParams {
            network_id: NetworkId::from_seed(b"genesis-binding-network"),
            commitment,
            threshold: 1,
            share: Some(share),
            authority: None,
        }),
        epoch_period: Duration::from_secs(3600),
        start_heartbeat: false,
        ..NodeConfig::default()
    };

    let node = Node::start::<F2>(config).await.expect("a consistently-provisioned node must start");
    node.shutdown();
}

/// The mechanism: two networks in one node is refused, and named.
///
/// The disagreement has to be built by hand, because `NodeConfig` carries exactly one `network_id` and
/// therefore cannot express it — which is the right shape (the config is the narrow door) and also the reason
/// the defect survived: the only way to reach the split state was through the constructor default, and a
/// default is invisible at every call site that accepts it. `BeaconNode::new` now takes the seed as an
/// argument for that reason, and this asserts the driver checks it rather than trusting the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_provisioned_onto_two_networks_refuses_to_start() {
    let (shares, commitment) = deal(&[0x9A; 32], 1, 1, &mut DeterministicRng::new(b"genesis-binding"))
        .expect("deal a 1-of-1 beacon");
    let share = shares.into_iter().next().expect("a 1-of-1 sharing yields one share");

    let mine = genesis_seed(&NetworkId::from_seed(b"the-network-i-was-dealt-into"));
    let theirs = genesis_seed(&NetworkId::from_seed(b"some-other-network"));
    assert_ne!(mine, theirs, "two distinct network names must derive distinct genesis seeds");

    let coord = Point::<F2>::at(0);
    let overlay = OverlayNode::<F2>::new(coord, OverlayConfig::default());
    let beacon = BeaconNode::<F2>::new(coord, Some(share), commitment, 1, mine);
    let engine = OverlayBeaconNode::new(overlay, beacon);

    // The transport seats this node in a directory bound to a *different* network.
    let directory = Directory::new().for_network(theirs);

    let err = fanos_quic::spawn(Box::new(engine), directory)
        .await
        .err()
        .expect("a node provisioned onto two networks must not come up");

    match err {
        QuicError::GenesisMismatch { engine, directory } => {
            assert_eq!(engine, mine, "the error must name the seed the BEACON carries");
            assert_eq!(directory, theirs, "the error must name the seed the DIRECTORY carries");
            // An operator has to be able to tell the two apart in a log; a message that reported only
            // "mismatch" would leave them diffing two files to learn which half is wrong.
            let rendered = format!("{}", QuicError::GenesisMismatch { engine, directory });
            assert!(rendered.contains("misprovisioned"), "the message must say what is wrong: {rendered}");
            assert!(
                rendered.contains(&hex8(engine.as_bytes())),
                "the message must carry the beacon's seed: {rendered}"
            );
            assert!(
                rendered.contains(&hex8(directory.as_bytes())),
                "the message must carry the directory's seed: {rendered}"
            );
        }
        other => panic!("expected a genesis mismatch, got {other:?}"),
    }
}

/// The repo's short form for a 32-byte identifier — the first eight bytes, as `config.rs` renders them.
fn hex8(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for b in &bytes[..8] {
        let _ = write!(s, "{b:02x}");
    }
    s
}
