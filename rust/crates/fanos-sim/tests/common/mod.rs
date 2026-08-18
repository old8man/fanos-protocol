//! Shared helpers for the mass-destruction → heterogeneous-recovery scenarios (audit §2: R-C1..R-H2,
//! sim backlog S-P0.0). Kept in `tests/common` so every recovery scenario file drives one real epoch clock.

#![allow(dead_code, unreachable_pub, clippy::indexing_slicing, clippy::unwrap_used)]

use fanos_keygen::recovery::RecoveryAuthoritySet;
use fanos_field::Field;
use fanos_geometry::{Line, Plane};
use fanos_keygen::BeaconNode;
use fanos_node::composition::{CellComposition, compose_engine};
use fanos_node::{BeaconParams, OverlayBeaconNode};
use fanos_pqcrypto::{HybridSigSecret, HybridVerifier, SeedRng};
use fanos_runtime::{Config, OverlayNode, Triple};
use fanos_sim::Sim;
use fanos_vrf::vss::{DeterministicRng, deal};
use fanos_primitives::BeaconSeed;

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
        let beacon = BeaconNode::<F>::new(point, share, commitment.clone(), threshold, BeaconSeed::GENESIS)
            .with_recovery_authority(RecoveryAuthoritySet::new(vec![authority_vk.clone()]).unwrap());
        coords.push(sim.add(Box::new(OverlayBeaconNode::new(overlay, beacon))));
    }
    coords
}

/// The same cell, assembled the way **production assembles it** — through
/// [`fanos_node::composition::compose_engine`] from a [`CellComposition`], rather than by hand.
///
/// [`spawn_beacon_cell`] builds `OverlayBeaconNode` directly, which is the drift the composition seam exists
/// to prevent: it can configure things production cannot, and it did — `with_recovery_authority` had no caller
/// outside this file, so every shipped beacon ran without a trust root and could never reshare. That is now a
/// `BeaconParams` field, and this helper is what proves the wire carries it: a reshare succeeds here **only
/// if** `compose_engine` passed the authority through to the `BeaconNode`.
///
/// `with_authority = false` is the falsification, kept as a callable configuration rather than a comment: the
/// same cell, the same signed trigger, refused.
pub fn spawn_composed_beacon_cell<F: Field + 'static>(
    sim: &mut Sim,
    config: Config,
    threshold: usize,
    anchors: usize,
    with_authority: bool,
) -> Vec<Triple> {
    let n = Plane::<F>::N as usize;
    // The same deterministic sharing as `spawn_beacon_cell`, so a scenario can compare the two assemblies
    // directly rather than wondering whether the key material differed.
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
        let what = CellComposition {
            beacon: Some(BeaconParams {
                network_id: fanos_node::NetworkId::from_seed(b"test-network"),
                commitment: commitment.clone(),
                threshold,
                share: (i < anchors).then(|| shares[i].clone()),
                authority: with_authority.then(|| RecoveryAuthoritySet::new(vec![authority_vk.clone()]).unwrap()),
            }),
            ..CellComposition::overlay_only(config)
        };
        coords.push(sim.add(compose_engine::<F>(point, &what, None)));
    }
    coords
}

/// A composed **relay** cell: beacon + mixnet router, the roles a production `--relay` node runs.
///
/// `relay = false` builds the identical cell *without* the router — same beacon, same config, same seeds — so
/// a scenario can isolate what the router contributes. That control is not decoration: the first version of
/// the cover test compared this cell against a bare `spawn_cell`, which differs in the **beacon** too, and
/// stayed green when the relay was switched off. It measured the wrong difference.
///
/// The relay branch of `compose_engine` had no scenario at all — `CellComposition { relay: true }` appeared
/// nowhere in this crate, `mixnet.rs` builds a bare `NyxNode` and `mix_relay.rs` hand-assembles a composite —
/// so the one thing a shipped relay actually is went unexercised, including the hop threshold it seals onions
/// at. A beacon is required and not incidental: the onion key rotates against the cell epoch, so
/// `compose_engine` builds no router without one.
/// `mix` is the **Poisson mixing** mean delay (`CellComposition::mix_mean_delay`). It is a parameter and not a
/// constant because it was the last composition field with no scenario at any value: every relay the simulator
/// ever stood up mixed with `Duration(0)`, i.e. forwarded instantly, while `NodeConfig`'s own default asserts
/// `mix_mean_delay > 0` ("Poisson mixing is on by default", `config.rs:1346`). The sim and a stock deployment
/// therefore disagreed on whether the timing defence was running at all (#180).
pub fn spawn_composed_relay_cell<F: Field + 'static>(
    sim: &mut Sim,
    config: Config,
    cover: fanos_runtime::Duration,
    mix: fanos_runtime::Duration,
    relay: bool,
) -> Vec<Triple> {
    spawn_composed_cell::<F>(sim, config, cover, mix, relay, false)
}

/// The same cell, with the **outer service layer** optionally composed over it.
///
/// `compose_engine` wraps five layers — overlay, beacon, `CellNode` (the router), `ServiceNode`,
/// `IngressNode` — and each outer one namespaces *its own* timer tokens while passing the inner engine's
/// through untouched. That pass-through is what keeps a relay's cover schedule alive on a node that also
/// hosts a service, and the wizard's default role set turns both on. One parameter here rather than a second
/// fixture, so the two arms cannot differ in anything but the layer under test.
pub fn spawn_composed_cell<F: Field + 'static>(
    sim: &mut Sim,
    config: Config,
    cover: fanos_runtime::Duration,
    mix: fanos_runtime::Duration,
    relay: bool,
    service: bool,
) -> Vec<Triple> {
    let n = Plane::<F>::N as usize;
    let (shares, commitment) =
        deal(&[0xB5; 32], 2, n, &mut DeterministicRng::new(b"fanos-sim/relay/beacon-cell")).unwrap();
    let mut coords = Vec::with_capacity(n);
    for (i, point) in Plane::<F>::points().enumerate() {
        let mut what = CellComposition::overlay_only(config);
        what.beacon = Some(BeaconParams {
            network_id: fanos_node::NetworkId::from_seed(b"test-network"),
            commitment: commitment.clone(),
            threshold: 2,
            share: Some(shares[i].clone()),
            authority: None,
        });
        what.relay = relay;
        what.cover_interval = cover;
        what.mix_mean_delay = mix;
        // Distinct per node: a relay's onion and router keys are its own, and seeding them identically would
        // make every hop of a circuit peelable by the same secret.
        if service {
            // Every node composes the layer; three of the seven are members of this line and four are not,
            // which `ThresholdService::new` handles by `position` returning `None`. Membership is not the
            // point — wrapping is.
            let line: Vec<Triple> = Plane::<F>::points_on(Line::<F>::at(0)).map(|p| p.coords()).collect();
            what.service = Some(([7u8; 32], line, 2, None));
        }
        what.onion_seed = [i as u8; 32];
        what.kem_seed = [0x80 ^ i as u8; 32];
        coords.push(sim.add(compose_engine::<F>(point, &what, None)));
    }
    coords
}

/// The sim's fixed recovery authority (a parent/operator trust root). [`spawn_beacon_cell`] configures every
/// beacon with its verifier, so a scenario can drive an AUTHENTICATED reshare (audit §2.1) by signing the
/// trigger with the secret this returns.
pub fn recovery_authority() -> (HybridSigSecret, HybridVerifier) {
    HybridSigSecret::generate(&mut SeedRng::from_seed(b"fanos-sim/recovery/authority"))
}

/// Rate series of frames **emitted** by `node`, in `bin_ms` bins — one half of what a GPA correlates.
///
/// Here rather than in either harness because two now need it: `traffic_analysis.rs` over a `NyxNode` and
/// `composed_relay_gpa.rs` over the relay a `--relay` deployment actually runs. The statistics that consume
/// these series live in `fanos_testkit::gpa`; these two stay here because they need `FrameObs` and `Triple`,
/// which that leaf crate cannot see.
pub fn emit_series(obs: &[fanos_sim::FrameObs], node: Triple, bin_ms: u64, bins: usize) -> Vec<f64> {
    let mut v = vec![0f64; bins];
    for o in obs.iter().filter(|o| o.from == node) {
        if let Some(slot) = v.get_mut((o.t_ms / bin_ms) as usize) {
            *slot += 1.0;
        }
    }
    v
}

/// Rate series of frames **received** by `node` — the other half. See [`emit_series`].
pub fn recv_series(obs: &[fanos_sim::FrameObs], node: Triple, bin_ms: u64, bins: usize) -> Vec<f64> {
    let mut v = vec![0f64; bins];
    for o in obs.iter().filter(|o| o.to == node) {
        if let Some(slot) = v.get_mut((o.t_ms / bin_ms) as usize) {
            *slot += 1.0;
        }
    }
    v
}
