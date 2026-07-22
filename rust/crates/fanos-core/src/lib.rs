//! # fanos-core — the overlay core and public API
//!
//! This crate integrates the layers into the surface an application uses (spec §11.2). It is
//! the *computational* core — addressing, rendezvous, quorums, storage placement, hierarchy,
//! and self-diagnosis — everything that is algebra rather than I/O. The transport (QUIC),
//! privacy (NYX), and service (CALYPSO) layers plug in above it; here every operation is
//! deterministic and testable without a network.
//!
//! * [`routing`] — O(1) rendezvous, bridges, multipath, content addressing (§L1/§L4).
//! * [`quorum`] — Maekawa quorums with guaranteed intersection (§L4).
//! * [`membership`] — coordinates and the structural centrality cap (§L0/§L3, V3).
//! * [`admission`] — pluggable Sybil admission (PoW today; stake/WoT next), the per-join cost
//!   the structural cap alone does not provide (§L3).
//! * [`hierarchy`] — scale by a recursion of cells (§L1, V4).
//!
//! [`Node`] ties them together: an identity, its epoch coordinate, its quorums, and a
//! [`diagnose`] health hook.
//!
//! ## Relationship to the shipping engine (`fanos-runtime`)
//!
//! There are two node types in this workspace, on purpose — this is a layering, not accidental
//! duplication (audit #127):
//!
//! * **`fanos_core::Node`** (here) is the **network-free algebraic reference**: every operation is a
//!   deterministic function of coordinates, testable without a clock or a socket. It is what the CLI
//!   (`fanos-cli`) drives to demonstrate the protocol, what `fanos-sim` borrows hierarchy/admission types
//!   from, and where the protocol's math (rendezvous, quorum intersection, centrality, descent) is stated
//!   most directly.
//! * **`fanos_runtime::OverlayNode`** is the **shipping sans-I/O engine** — the same math re-expressed as a
//!   `step(now, Input) -> Vec<Effect>` state machine the QUIC driver and the simulator both run (it is what
//!   the production `fanos` node binary uses).
//!
//! They do **not** drift on the load-bearing derivations, because both delegate to the *single sources of
//! truth* rather than re-deriving: content addressing is [`fanos_primitives::storage_point`]
//! ([`routing::content_address`] — the C7-unified storage domain, pinned by
//! `content_address_uses_the_storage_domain_matching_the_engine`), and the epoch coordinate is
//! [`fanos_vrf::prove_coordinate`] ([`membership::Member::assign`]) — the very functions the engine calls.
//! So the reference and the engine agree by construction on where data lives and where a node sits; what
//! differs is only the *shape* (pure functions vs. an effectful step loop). The `admission::AdmissionPolicy`
//! trait is shared **into** the engine (`fanos-runtime` depends on it), so the Sybil gate is one
//! implementation, not two. A future convergence could retire `fanos_core::Node` in favour of driving the
//! CLI on the shipping engine, but it is not required for correctness and is not a source of divergence.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod admission;
pub mod hierarchy;
pub mod membership;
pub mod quorum;
pub mod roles;
pub mod routing;
pub mod stratum;

// Re-export the stack's core types so an application depends on `fanos-core` alone.
pub use fanos_diakrisis::{Observation, Verdict, diagnose};
pub use fanos_field::Field;
pub use fanos_geometry::{Line, Plane, Point};
pub use fanos_primitives::{BeaconSeed, Epoch, HybridPublicKey, NodeId};
pub use fanos_vrf::{VrfProof, VrfPublic, VrfSecret};

pub use admission::{AdmissionPolicy, PowAdmission};
pub use hierarchy::Hierarchy;
pub use membership::Member;
pub use quorum::Quorum;
pub use stratum::{ChildSummary, ParentCell};

use fanos_geometry::fano;

/// A FANOS participant in a cell `PG(2, q)`: an identity, its epoch coordinate, and the
/// derived overlay structure (spec §3.1, §11.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Node<F: Field> {
    member: Member<F>,
}

impl<F: Field> Node<F> {
    /// Join the cell: derive this node's **verifiable** coordinate for (`epoch`, `beacon`) from its VRF
    /// secret — `coord = MapToPoint(VRF(vrf_secret, id ‖ epoch ‖ beacon))` (spec §7.8 JOIN steps 3–4).
    /// `vrf_secret` is the key committed in `id`'s identity bundle; `beacon` is the epoch's beacon seed
    /// ([`BeaconSeed::GENESIS`] before the first round), so the placement reshuffles unpredictably and is
    /// unforgeable (§3.2 assumptions 1–2).
    #[must_use]
    pub fn open(vrf_secret: &VrfSecret, id: NodeId, epoch: Epoch, beacon: &BeaconSeed) -> Self {
        Self {
            member: Member::assign(vrf_secret, id, epoch, beacon),
        }
    }

    /// This node's projective coordinate (its overlay address).
    #[must_use]
    pub fn coordinate(&self) -> Point<F> {
        self.member.coord
    }

    /// This node's identity.
    #[must_use]
    pub fn id(&self) -> NodeId {
        self.member.id
    }

    /// The rendezvous line to reach `peer` — a single field operation (spec §L1).
    #[must_use]
    pub fn rendezvous_with(&self, peer: &Point<F>) -> Option<Line<F>> {
        routing::rendezvous(&self.coordinate(), peer)
    }

    /// This node's `q + 1` quorums (the lines it belongs to).
    pub fn quorums(&self) -> impl Iterator<Item = Quorum<F>> + Clone {
        self.member.lines().map(Quorum::new)
    }
}

impl Node<fanos_field::F2> {
    /// Run one DIAKRISIS diagnostic round on this node's Fano cell (spec §6.9). Available on
    /// the base cell, where the self-diagnosis plane operates.
    #[must_use]
    pub fn health(observation: &Observation) -> Verdict {
        diagnose(observation)
    }

    /// The mediator (deterministic reroute target) for a failed link to another cell node
    /// (spec §6.7): the third point of their common line.
    #[must_use]
    pub fn reroute_via(from: usize, to: usize) -> Option<usize> {
        fano::mediator(from, to)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::{F2, F31};

    #[test]
    fn two_nodes_share_a_rendezvous_line() {
        // The end-to-end overlay flow: two identities → verifiable coordinates → a shared meeting line.
        let alice = Node::<F31>::open(
            &VrfSecret::from_seed([1u8; 32]),
            NodeId([1u8; 32]),
            Epoch::new(5),
            &BeaconSeed::GENESIS,
        );
        let bob = Node::<F31>::open(
            &VrfSecret::from_seed([2u8; 32]),
            NodeId([2u8; 32]),
            Epoch::new(5),
            &BeaconSeed::GENESIS,
        );
        let line = alice.rendezvous_with(&bob.coordinate()).unwrap();
        assert!(alice.coordinate().is_on(&line));
        assert!(bob.coordinate().is_on(&line));
        // Bob computes the same line to Alice — no coordination needed.
        assert_eq!(line, bob.rendezvous_with(&alice.coordinate()).unwrap());
    }

    #[test]
    fn a_node_has_q_plus_one_quorums_that_all_intersect() {
        let node = Node::<F31>::open(
            &VrfSecret::from_seed([3u8; 32]),
            NodeId([3u8; 32]),
            Epoch::ZERO,
            &BeaconSeed::GENESIS,
        );
        let quorums: Vec<_> = node.quorums().collect();
        assert_eq!(quorums.len(), 32);
        // Every pair of the node's quorums intersects (Maekawa); the node itself is common.
        for q in &quorums {
            assert!(q.members().any(|p| p == node.coordinate()));
        }
    }

    #[test]
    fn base_cell_node_can_self_diagnose_and_reroute() {
        // A single crash is localized, and the reroute target is the mediator.
        let obs = Observation {
            degraded: 1 << 4,
            ..Default::default()
        };
        assert!(matches!(
            Node::<F2>::health(&obs),
            Verdict::Localized(fanos_diakrisis::Fault::Single(4))
        ));
        assert!(Node::<F2>::reroute_via(4, 0).is_some());
    }
}
