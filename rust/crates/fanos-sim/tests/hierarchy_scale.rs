//! Cross-cell routing on a connected two-level `Hierarchy` (spec §L1) — the routing lens on the engine,
//! complementary to the coherence-focused `Cluster`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_field::F7;
use fanos_runtime::{Config, Duration};
use fanos_sim::Hierarchy;

fn config() -> Config {
    Config { heartbeat: Duration::from_millis(500), ..Config::default() }
}

/// Roster index of gateway `g`'s sub-node `m` (block size `1 + per_cell`).
fn sub(g: usize, m: usize, per_cell: usize) -> usize {
    g * (1 + per_cell) + 1 + m
}

#[test]
fn a_connected_hierarchy_routes_across_every_sub_cell() {
    // 3 gateways × 4 descended nodes = 15 nodes; wired purely by Join auto-seeding.
    let mut h = Hierarchy::<F7>::two_level(0x00C0_FFEE, config(), 3, 4);
    assert_eq!(h.len(), 15);
    assert_eq!(h.gateway_indices(), vec![0, 5, 10], "the three sub-cell roots");

    // Every cross-cell pair (a sub-node of one cell → a sub-node of another) is reachable.
    let pairs = vec![
        (sub(0, 0, 4), sub(1, 0, 4)),
        (sub(1, 1, 4), sub(2, 2, 4)),
        (sub(2, 0, 4), sub(0, 3, 4)),
        (sub(0, 1, 4), sub(2, 1, 4)),
    ];
    assert!(h.reachability(&pairs) > 0.999, "every cross-cell route is delivered");
}

#[test]
fn crashing_a_gateway_makes_its_sub_cell_unreachable() {
    let mut h = Hierarchy::<F7>::two_level(0x0000_BEEF, config(), 3, 4);
    // Baseline: a node in cell 0 reaches a node in cell 1.
    assert!(h.routes(sub(0, 0, 4), sub(1, 2, 4)), "cell 1 reachable before the crash");
    assert!(h.routes(sub(0, 0, 4), sub(2, 1, 4)), "cell 2 reachable before the crash");

    // Crash gateway 1 (its sub-cell's only overlay root).
    let gw1 = h.gateway(1).unwrap();
    h.crash(gw1);

    // Its sub-cell is now unreachable via the overlay; the other cells are untouched.
    assert!(!h.routes(sub(0, 0, 4), sub(1, 2, 4)), "cell 1 severed once its gateway is down");
    assert!(h.routes(sub(0, 0, 4), sub(2, 1, 4)), "cell 2 unaffected — the fault is contained");
}
