//! Shared helpers for the mass-destruction → heterogeneous-recovery scenarios (audit §2: R-C1..R-H2,
//! sim backlog S-P0.0). Kept in `tests/common` so every recovery scenario file drives one real epoch clock.

#![allow(dead_code, unreachable_pub, clippy::indexing_slicing, clippy::unwrap_used)]

use fanos_field::Field;
use fanos_geometry::Plane;
use fanos_keygen::BeaconNode;
use fanos_node::OverlayBeaconNode;
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};
use fanos_runtime::{Config, OverlayNode, Triple};
use fanos_sim::Sim;
use fanos_vrf::vss::{DeterministicRng, deal};

/// Spawn a full Fano cell `PG(2, q)` of [`OverlayBeaconNode`] composites that share one `threshold`-of-`N`
/// beacon key: the first `anchors` points hold a DVRF share (and contribute partials each epoch), the rest
/// are pure consumers (they verify and adopt the rounds anchors flood, but never contribute). Returns the
/// node coordinates by point index, so `cell[i]` is the node at Fano point `i`.
///
/// Unlike [`fanos_sim::spawn_cell`] (bare overlays pinned at genesis), this cell runs the **real threshold
/// DVRF epoch clock**, so [`Sim::tick_epoch`] drives the genuine `beacon → BeaconReady → reshuffle` loop and
/// a scenario can crash an anchor batch to observe the clock stall at the `n − t + 1` cliff (audit R-C1).
///
/// The sharing is dealt deterministically (a fixed secret + seeded RNG) so runs are reproducible; a real
/// deployment deals from OS entropy through the anchors' one-time networked DKG.
pub fn spawn_beacon_cell<F: Field + 'static>(
    sim: &mut Sim,
    config: Config,
    threshold: usize,
    anchors: usize,
) -> Vec<Triple> {
    let n = Plane::<F>::N as usize;
    let (shares, commitment) = deal(
        &[0xB5; 32],
        threshold,
        n,
        &mut DeterministicRng::new(b"fanos-sim/recovery/beacon-cell"),
    )
    .unwrap();
    let (_, authority_vk) = recovery_authority();
    let mut coords = Vec::with_capacity(n);
    for (i, point) in Plane::<F>::points().enumerate() {
        let overlay = OverlayNode::<F>::new(point, config);
        let share = (i < anchors).then(|| shares[i].clone());
        let beacon = BeaconNode::<F>::new(point, share, commitment.clone(), threshold)
            .with_recovery_authority(authority_vk.clone());
        coords.push(sim.add(Box::new(OverlayBeaconNode::new(overlay, beacon))));
    }
    coords
}

/// The sim's fixed recovery authority (a parent/operator trust root). [`spawn_beacon_cell`] configures every
/// beacon with its verifier, so a scenario can drive an AUTHENTICATED reshare (audit §2.1) by signing the
/// trigger with the secret this returns.
pub fn recovery_authority() -> (HybridSigSecret, HybridVerifier) {
    HybridSigSecret::generate(&mut SeedRng::from_seed(b"fanos-sim/recovery/authority"))
}
