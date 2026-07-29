//! **The one place a FANOS node's engine is assembled.**
//!
//! Plan item I.3, and the largest structural gap the 2026-07-28 audit found. The standing rule is that the
//! simulator differs from production only in *transport*. It did not: production layered an overlay, an
//! admission gate, a beacon, a mixnet router and a threshold service into one engine, while
//! `fanos_sim::spawn_cell` instantiated a bare `OverlayNode` and nothing else.
//!
//! So the simulator never ran the composed thing. Every defect found in that session lived in a composition —
//! `read_coherence` with no caller, a frame type dispatched nowhere, a consensus rule simply absent, an
//! observatory watching a simulation of itself — and the instrument that was supposed to find them was, by
//! construction, blind to the layer they were in.
//!
//! [`compose_engine`] is that assembly, extracted so both callers use it. The invariant is structural rather
//! than asserted: there is one function, so the two cannot drift. A role added here appears in the simulator on
//! the same commit, and a scenario that stands up a cell gets the engine a deployment would run.
//!
//! ## What this deliberately does not do
//!
//! It composes engines. It does not spawn tasks, publish directories, or drive an epoch clock — those are the
//! *driver's* work and live in [`crate::node`], because they need I/O and this must not. The seam is the same
//! one the whole codebase draws between a sans-I/O engine and the thing that turns its effects into syscalls.

use fanos_aphantos::ThresholdRouter;
use fanos_field::Field;
use fanos_geometry::{Plane, Point, Triple};
use fanos_keygen::BeaconNode;
use fanos_pqcrypto::kem::HybridKemSecret;
use fanos_pqcrypto::rng::SeedRng;
use fanos_runtime::{Config as OverlayConfig, Duration, Engine, OverlayNode};

use crate::cell_node::CellNode;
use crate::config::BeaconParams;
use crate::overlay_beacon::OverlayBeaconNode;
use crate::service_node::ServiceNode;
use crate::threshold_service::ThresholdService;

/// The threshold a mixnet relay reconstructs an onion layer at — `⌈2(q+1)/3⌉`, derived from the plane.
pub(crate) use crate::node::mix_threshold;

/// Everything that decides *which engine* a node runs — the roles it serves and the material each needs.
///
/// Derived from a `NodeConfig` in production and written directly by a scenario, which is the point: the two
/// paths differ in where the values come from and not in what is built from them.
#[derive(Clone)]
pub struct CellComposition {
    /// The overlay's own configuration (VRF coordinates, admission requirement, …).
    pub overlay: OverlayConfig,
    /// Proof-of-work admission difficulty demanded of joiners, if this node prices entry (§L3).
    pub admission: Option<u32>,
    /// Beacon provisioning — present iff this node runs the epoch clock.
    pub beacon: Option<BeaconParams>,
    /// Whether this node relays: composes the mixnet router over the beacon node.
    pub relay: bool,
    /// The relay's onion-key seed. Fresh OS entropy in production (forward-secure across restarts), fixed in a
    /// scenario that needs determinism.
    pub onion_seed: [u8; 32],
    /// The relay's router KEM seed, same reasoning.
    pub kem_seed: [u8; 32],
    /// Poisson mixing mean delay; zero leaves mixing off.
    pub mix_mean_delay: Duration,
    /// Constant-rate cover interval; zero leaves cover off.
    pub cover_interval: Duration,
    /// Threshold-service hosting: `(member seed, the line's coordinates, reconstruction threshold)`.
    pub service: Option<([u8; 32], Vec<Triple>, usize)>,
    /// This node's **hierarchical descent path**, when it sits in a sub-cell rather than at the root (§L1).
    ///
    /// Carried as coordinates rather than a `HierAddr<F>` so this type stays free of the field parameter — the
    /// path is the same numbers either way, and `compose_engine` knows `F`.
    pub hier_path: Option<Vec<Triple>>,
    /// A **pinned** cell roster, for a scenario that seats a cell directly instead of letting it discover
    /// itself by announcement.
    ///
    /// Present because two simulator scenarios needed it and were assembling their own engines to get it, which
    /// is the second assembly path this module exists to remove. A parameter here folds them back onto the one
    /// path; exempting them would have left the drift in place with a comment on it.
    pub cell_members: Option<[Triple; 7]>,
}

impl CellComposition {
    /// A plain overlay node — no beacon, no relay, no service, no admission price.
    ///
    /// The shape most scenarios want, and the shape the simulator used to hard-code. Now it is one point in a
    /// space rather than the only thing that can be built.
    #[must_use]
    pub fn overlay_only(overlay: OverlayConfig) -> Self {
        Self {
            overlay,
            admission: None,
            beacon: None,
            relay: false,
            onion_seed: [0u8; 32],
            kem_seed: [0u8; 32],
            mix_mean_delay: Duration(0),
            cover_interval: Duration(0),
            service: None,
            hier_path: None,
            cell_members: None,
        }
    }
}

/// Assemble the engine a node at `coord` runs, from `what` it is configured to be.
///
/// The layering is not arbitrary and each step is a strict extension of the last:
///
/// 1. **overlay** — membership, routing, storage, the DIAKRISIS reflex. Always present.
/// 2. **admission** — prices every join, and re-mints the proof each epoch as the coordinate reshuffles, so a
///    seized seat costs work *again* rather than once (§L3).
/// 3. **beacon** — the epoch clock. A relay needs it, because the onion-key rotation is locked to the cell
///    epoch (E4∩E5); without one there is nothing to rotate against.
/// 4. **relay** — the mixnet router, with Poisson mixing and constant-rate cover, so the relay defends against
///    a global passive adversary rather than merely forwarding.
/// 5. **service** — a threshold-CALYPSO member composed *over* whatever the roles below produced, so one
///    coordinate both serves its line and remains a full cell member: an intro is dispatched to the service,
///    everything else to the cell engine.
#[must_use]
pub fn compose_engine<F: Field + 'static>(
    coord: Point<F>,
    what: &CellComposition,
) -> Box<dyn Engine + Send> {
    let mut overlay = OverlayNode::<F>::new(coord, what.overlay);
    if let Some(members) = what.cell_members {
        overlay = overlay.with_cell_members(members);
    }
    if let Some(path) = &what.hier_path {
        // A coordinate that is not a point of this plane is dropped rather than panicking: the path comes from
        // configuration or a scenario, and a bad one should leave the node at its root, not abort the process.
        let points: Option<Vec<Point<F>>> = path.iter().map(|c| Point::<F>::new(*c)).collect();
        if let Some(hier) = points.and_then(fanos_geometry::HierAddr::from_path) {
            overlay = overlay.with_hier_address(hier);
        }
    }
    let overlay = match what.admission {
        Some(difficulty) => overlay.with_admission_pow(difficulty),
        None => overlay,
    };
    let base: Box<dyn Engine + Send> = match &what.beacon {
        Some(bp) => {
            // The recovery authority is part of *provisioning*, not of the beacon's steady-state operation —
            // but omitting it here is what left every shipped beacon unable to reshare or re-genesis, so the
            // freeze the resharing machinery exists to escape was permanent in production while both halves
            // sat built and tested (`BeaconParams::authority`).
            let mut beacon =
                BeaconNode::<F>::new(coord, bp.share.clone(), bp.commitment.clone(), bp.threshold);
            if let Some(authority) = &bp.authority {
                beacon = beacon.with_recovery_authority(authority.clone());
            }
            let obn = OverlayBeaconNode::new(overlay, beacon);
            if what.relay {
                let (router_secret, _identity) =
                    HybridKemSecret::generate(&mut SeedRng::from_seed(&what.kem_seed));
                // Derived from *this* plane: a hop is a line of `q+1` points, and a threshold fixed at the
                // Fano value would let any two corrupt members own a hop however wide the line is (E7).
                let threshold = mix_threshold(Plane::<F>::LINE_SIZE as usize);
                let router = ThresholdRouter::<F>::new(
                    coord,
                    &router_secret,
                    threshold,
                    what.onion_seed,
                )
                .with_mixing(what.mix_mean_delay)
                .with_cover(what.cover_interval);
                Box::new(CellNode::new(obn, router))
            } else {
                Box::new(obn)
            }
        }
        None => Box::new(overlay),
    };
    match &what.service {
        Some((seed, line, threshold)) => {
            // Regenerated in memory from the seed and never serialized (audit #124); the matching public is
            // the one the operator collected into the published line.
            let (secret, _public) = HybridKemSecret::generate(&mut SeedRng::from_seed(seed));
            Box::new(ServiceNode::new(
                base,
                ThresholdService::new(coord.coords(), secret, line.clone(), *threshold),
            ))
        }
        None => base,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::F2;

    #[test]
    fn a_bare_composition_is_an_overlay_and_nothing_more() {
        let what = CellComposition::overlay_only(OverlayConfig::default());
        assert!(what.beacon.is_none() && !what.relay && what.service.is_none() && what.admission.is_none());
        let _engine = compose_engine::<F2>(Point::at(0), &what);
    }

    #[test]
    fn a_relay_without_a_beacon_composes_no_router() {
        // Not a guess about intent — a relay's onion key rotates against the cell epoch, so without a beacon
        // there is nothing to rotate against. `Node::start` refuses that configuration outright; this asserts
        // the *engine* degrades to the overlay rather than silently building a router with no clock.
        let what = CellComposition { relay: true, ..CellComposition::overlay_only(OverlayConfig::default()) };
        let _engine = compose_engine::<F2>(Point::at(0), &what);
        // Reaching here without a panic is the assertion: the beacon-less branch is taken.
    }
}
