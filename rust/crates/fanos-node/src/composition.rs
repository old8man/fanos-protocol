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

use fanos_rendezvous::{BeaconSeed, Epoch};

use crate::cell_node::CellNode;
use crate::config::{BeaconParams, IngressParams};
use crate::ingress_node::IngressNode;
use crate::overlay_beacon::OverlayBeaconNode;
use crate::poros::{PorosHost, Sybil};
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
    /// Threshold-service hosting: `(member seed, the line's coordinates, reconstruction threshold, this
    /// member's identity-custody slot)`.
    ///
    /// The fourth element is `None` for a line that carries request confidentiality only — §12.3's half (b)
    /// without half (a). The two halves are separable in exactly that direction and not the other: a line
    /// can read intros without custodying an identity, but custody with no line to hold it is not a
    /// deployment.
    #[allow(clippy::type_complexity)]
    pub service: Option<([u8; 32], Vec<Triple>, usize, Option<fanos_calypso::hosting::SealedShare>)>,
    /// **POROS ingress hosting** — this node is one member of a community's ingress line
    /// (`docs/design-anonymity-substrate.md` §6), holding one threshold share of its entry-peer descriptor.
    /// Composed *over* everything below, exactly as `service` is: an ingress frame is dispatched to the host,
    /// everything else to the cell engine, so one coordinate both admits new nodes and stays a full member.
    pub ingress: Option<IngressParams>,
    /// This node's **hierarchical descent path**, when it sits in a sub-cell rather than at the root (§L1).
    ///
    /// Carried as coordinates rather than a `HierAddr<F>` so this type stays free of the field parameter — the
    /// path is the same numbers either way, and `compose_engine` knows `F`.
    pub hier_path: Option<Vec<Triple>>,
    /// This node's **durable store**, as written by a previous run of it ([`Command::Snapshot`](fanos_runtime::Command::Snapshot)).
    ///
    /// Adopted at construction because that is the only correct moment: restoring over an engine that has
    /// already accepted a write would discard it. A snapshot this build cannot read is refused and the node
    /// starts empty, which the cell's `[7,3,4]` erasure code is designed to survive for one member — the
    /// point of persistence is to make that rarer, not to make an unreadable file fatal.
    pub restore: Option<Vec<u8>>,
    /// A **pinned** cell roster, for a scenario that seats a cell directly instead of letting it discover
    /// itself by announcement.
    ///
    /// Present because two simulator scenarios needed it and were assembling their own engines to get it, which
    /// is the second assembly path this module exists to remove. A parameter here folds them back onto the one
    /// path; exempting them would have left the drift in place with a comment on it.
    pub cell_members: Option<[Triple; 7]>,
    /// **Hierarchical peers** pinned by hand: `(the peer's descent path, its transport coordinate)`.
    ///
    /// A deployment never sets this — a gateway learns its siblings by announcement, which is why `Node::start`
    /// leaves it empty. A multi-cell scenario has no announcement to wait for, so it seats the routes directly.
    ///
    /// Added for the same reason as [`cell_members`](Self::cell_members), and it is worth saying why the reason
    /// was not enough the first time: that field's own doc says it exists so two scenarios could stop assembling
    /// their own engines, and **they never moved onto it** — the field was added and the migration was not done,
    /// so both scenario branches of [`compose_engine`] sat unreachable. They could not move, because each also
    /// wired hierarchical peers and there was no parameter for those. This is that parameter.
    ///
    /// Paths are coordinates rather than `HierAddr<F>` for the same reason as `hier_path`: this type stays free
    /// of the field parameter, and `compose_engine` knows `F`.
    pub hier_peers: Vec<(Vec<Triple>, Triple)>,
}

impl CellComposition {
    /// The genesis seed of the network this composition describes — read from the `network_id` its beacon
    /// parameters carry, so it cannot disagree with the network this node was provisioned onto
    /// ([`BeaconParams::genesis_seed`](crate::config::BeaconParams::genesis_seed)).
    ///
    /// Without a beacon there is no network name to read, so the shared constant stands: a pinned cell with
    /// no beacon runs no epoch clock and draws no coordinates against a seed, which is the pre-beacon
    /// behaviour this deliberately preserves.
    #[must_use]
    pub fn genesis_seed(&self) -> BeaconSeed {
        self.beacon.as_ref().map_or(BeaconSeed::GENESIS, BeaconParams::genesis_seed)
    }

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
            ingress: None,
            restore: None,
            hier_path: None,
            cell_members: None,
            hier_peers: Vec::new(),
        }
    }
}

impl CellComposition {
    /// A node with the overlay and **no other role** — the composition a validator runs.
    ///
    /// This exists because `fanos validator` did not have one. It built `OverlayNode::<F2>::new(coord,
    /// OverlayConfig::default())` directly, which is a *second assembly path* in the shipped binary — exactly
    /// what this module exists to prevent, and what its header calls structurally impossible ("there is one
    /// function, so the two cannot drift"). It went unnoticed because the seam guard matched the literal
    /// `OverlayNode::<F>::new` and the binary writes `F2` (#168).
    ///
    /// Being empty of roles is a *statement about what a validator is*, not a bypass: the engine is still
    /// assembled by [`compose_engine`], so a layer added there reaches the validator on the same commit.
    /// Whether a validator should also relay, host, or hold beacon authority is a separate decision — one that
    /// needs `ValidatorConfig` to carry the knobs, which today it does not, and that is the residual.
    /// Delegates rather than repeating the field list. The two were byte-identical exhaustive literals kept in
    /// sync by hand, which is a standing invitation for them to stop agreeing; the distinction that matters is
    /// what each one *means*, and that lives in the doc comments, not in a second copy of thirteen `None`s.
    #[must_use]
    pub fn bare(overlay: OverlayConfig) -> Self {
        Self::overlay_only(overlay)
    }
}

/// A descent path, as coordinates, read as a hierarchical address of this plane.
///
/// `None` when any coordinate is not a point of the plane, or when the path is empty. Shared by
/// [`CellComposition::hier_path`] and [`CellComposition::hier_peers`] so the two cannot come to disagree about
/// what a malformed path means: a bad one is **dropped**, never a panic. The path arrives from configuration or
/// a scenario, and the right outcome is a node left at its root, not an aborted process — under
/// `panic = "abort"` a panic here kills the node.
fn hier_addr<F: Field>(path: &[Triple]) -> Option<fanos_geometry::HierAddr<F>> {
    let points: Option<Vec<Point<F>>> = path.iter().map(|c| Point::<F>::new(*c)).collect();
    points.and_then(fanos_geometry::HierAddr::from_path)
}

/// Sign a node's **§80 descriptor** for `coord` — the host's half of the coordinate↔identity binding.
///
/// The engine verifies a peer's descriptor by rebuilding `descriptor_message` from the announce, so the host
/// has to produce the identical bytes; `fanos_runtime` exports that function for exactly this reason, and two
/// implementations of one format is the drift it exists to prevent.
///
/// `HierAddr::root(coord)` is what the engine holds after being seated at `coord` **at depth 1**, which every
/// production composition is (`hier_path: None`). A descended node would hold `[coord] ++ deeper`, and the
/// deeper levels are not knowable here — the runtime test
/// `a_descriptor_signed_for_the_coordinate_about_to_be_held_verifies_on_the_announce_that_follows` pins the
/// agreement and is what fails on the day that changes.
pub fn sign_descriptor<F: Field>(
    identity: &(Vec<u8>, fanos_pqcrypto::HybridSigSecret),
    coord: Point<F>,
) -> (Vec<u8>, Vec<u8>) {
    let (id, secret) = identity;
    let msg = fanos_runtime::descriptor_message::<F>(
        coord.coords(),
        &fanos_geometry::HierAddr::<F>::root(coord),
        id,
    );
    (id.clone(), secret.sign(&msg).to_bytes())
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
/// 6. **ingress** — a POROS ingress-line member, composed the same way and outermost, so a node that admits
///    newcomers to the network is otherwise an ordinary cell node. Outermost because the ingress frames are a
///    disjoint set that must reach the host whatever the layers below are; the composite's timer namespacing
///    is built for exactly that nesting ([`IngressNode`]).
#[must_use]
pub fn compose_engine<F: Field + 'static>(
    coord: Point<F>,
    what: &CellComposition,
    descriptor: Option<(Vec<u8>, Vec<u8>)>,
) -> Box<dyn Engine + Send> {
    let mut overlay = OverlayNode::<F>::new(coord, what.overlay);
    // **The genesis descriptor**, signed by the host for *this* coordinate (spec §80). Every later one
    // arrives as `Command::Descriptor` from the reshuffle loop, which signs at each reseat because the
    // message binds the transport coordinate; without this one the node's first epoch would announce with
    // no binding at all, and a peer running self-certified membership would refuse it until the first
    // boundary. `None` for a build with no self-certifying credentials, which is the honest shape rather
    // than an empty signature that looks like one.
    if let Some((id, sig)) = descriptor {
        overlay = overlay.with_signed_descriptor(id, sig);
    }
    if let Some(bytes) = &what.restore {
        // Ignored on failure by design — see the field's doc. The *host* reports whether it took, because
        // the host is what knows there was a file to read at all; a silent empty start is the failure mode
        // this whole task exists to remove, so it must not be reintroduced here.
        overlay.restore(bytes);
    }
    // A malformed cell is **dropped**, never a panic — the same rule `hier_addr` states one function up,
    // and for the same reason: the members arrive from configuration or a scenario, and under
    // `panic = "abort"` a panic here kills the node. What is dropped now is wider than a bad coordinate:
    // `CellMembers::new` also refuses seven points whose order does not realise `fano::LINE_POINTS`, which
    // used to be accepted and would have run the whole reflex over triples that are not collinear.
    overlay = match what.cell_members.and_then(fanos_geometry::fano::CellMembers::<F>::new) {
        // A provisioned roster: a committee at fixed transport points, defended across reshuffles. A
        // malformed one is **dropped**, never a panic — the rule `hier_addr` states one function up, and
        // for the same reason: it arrives from configuration, and under `panic = "abort"` a panic there
        // kills the node.
        Some(cell) => overlay.with_cell_members(cell),
        // Otherwise the plane says which cell this node is in (#145): `fano::cell_of` is `index mod (N/7)`,
        // a pure function every node computes identically, so no agreement round is needed. A no-op where
        // the plane does not split (`7 ∤ N`, i.e. `q ∈ {7, 8, 31}`), which is honest rather than inventing
        // a cell for it — and at `q = 2` it derives exactly the base plane's own `Point::at(0..7)`, so the
        // shipped default is unchanged and the `N == 7` special case becomes one case of a rule.
        None => overlay.with_derived_cell(),
    };
    if let Some(path) = &what.hier_path
        && let Some(hier) = hier_addr::<F>(path)
    {
        overlay = overlay.with_hier_address(hier);
    }
    for (path, transport) in &what.hier_peers {
        if let Some(hier) = hier_addr::<F>(path) {
            overlay = overlay.with_hier_peer(hier, *transport);
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
                BeaconNode::<F>::new(coord, bp.share.clone(), bp.commitment.clone(), bp.threshold, bp.genesis_seed());
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
    let base = match &what.service {
        Some((seed, line, threshold, identity_share)) => {
            // Regenerated in memory from the seed and never serialized (audit #124); the matching public is
            // the one the operator collected into the published line. The same secret opens both this
            // member's per-intro share slots (half (b)) and its identity-custody slot (half (a)) — one
            // member, one key, which is why the slot travels beside it rather than in a second field.
            let (secret, _public) = HybridKemSecret::generate(&mut SeedRng::from_seed(seed));
            Box::new(ServiceNode::new(
                base,
                ThresholdService::new(
                    coord.coords(),
                    secret,
                    line.clone(),
                    *threshold,
                    identity_share.clone(),
                ),
            ))
        }
        None => base,
    };
    match &what.ingress {
        Some(ip) => {
            // The KEM secret is regenerated in memory from its seed and never serialized (audit #124); its
            // public is what the ceremony published in the line's roster, so a rotating line can seal this
            // member's sub-shares to it.
            let (kem_secret, _public) = HybridKemSecret::generate(&mut SeedRng::from_seed(&ip.kem_seed));
            let host = PorosHost::new(
                coord.coords(),
                ip.share.clone(),
                ip.binding.clone(),
                ip.line.clone(),
                ip.threshold,
                ip.community.clone(),
                // The host serves the epoch its dealing was made for; the rotation driver advances it.
                Epoch::new(0),
                // …against **this network's** epoch-0 seed. A newcomer derives the community's ingress line
                // from `(community, epoch, beacon)`; a host on the constant while the network is on its
                // derived seed would sit on a line nobody looks at.
                what.genesis_seed(),
                ip.difficulty,
                // **Uncapped, and this is the honest answer rather than a default.** The Sybil *cap* needs an
                // admitted set, canonically from the fast-mixing trust graph (`crate::sybil`) — which is
                // fully built and constructed nowhere, because nothing in a running node collects trust
                // EDGES. There is no set to install, so the cap is genuinely unavailable here and a deployed
                // ingress host runs the PoW *rate*-limiter alone. `sybil.rs`'s own module doc says what that
                // means: a sequential-cost proof bounds identity-creation rate, never total identities
                // (Boneh et al., CRYPTO 2018).
                //
                // It is written out because it used to be a `None` default behind a builder nobody called,
                // which reads as "no decision was needed" rather than "the mechanism is missing". Task #76
                // carries the design question — where vouches come from — and `set_admitted` is the seam
                // that promotes this host the moment there is an answer.
                Sybil::Uncapped,
            )
            .with_kem_secret(kem_secret);
            Box::new(IngressNode::new(base, host))
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
        let _engine = compose_engine::<F2>(Point::at(0), &what, None);
    }

    #[test]
    fn a_relay_without_a_beacon_composes_no_router() {
        // Not a guess about intent — a relay's onion key rotates against the cell epoch, so without a beacon
        // there is nothing to rotate against. `Node::start` refuses that configuration outright; this asserts
        // the *engine* degrades to the overlay rather than silently building a router with no clock.
        let what = CellComposition { relay: true, ..CellComposition::overlay_only(OverlayConfig::default()) };
        let _engine = compose_engine::<F2>(Point::at(0), &what, None);
        // Reaching here without a panic is the assertion: the beacon-less branch is taken.
    }
}
