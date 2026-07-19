//! End-to-end integration properties over the public `fanos-core` API.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_cmp
)]

use fanos_core::{BeaconSeed, Epoch, Hierarchy, Line, Node, NodeId, Plane, Quorum, VrfSecret};
use fanos_field::F31;
use proptest::prelude::*;

const N31: usize = 993;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Any two distinct identities derive coordinates that share a computable rendezvous line,
    /// symmetric from either side — the O(1) meeting guarantee (spec §L1).
    #[test]
    fn two_identities_share_a_rendezvous_line(a in 0u8..=255, b in 0u8..=255, epoch in 0u32..4096) {
        prop_assume!(a != b);
        let alice = Node::<F31>::open(&VrfSecret::from_seed([a; 32]), NodeId([a; 32]), Epoch::new(epoch.into()), &BeaconSeed::GENESIS);
        let bob = Node::<F31>::open(&VrfSecret::from_seed([b; 32]), NodeId([b; 32]), Epoch::new(epoch.into()), &BeaconSeed::GENESIS);
        if alice.coordinate() != bob.coordinate() {
            let line = alice.rendezvous_with(&bob.coordinate()).unwrap();
            prop_assert!(alice.coordinate().is_on(&line));
            prop_assert!(bob.coordinate().is_on(&line));
            prop_assert_eq!(line, bob.rendezvous_with(&alice.coordinate()).unwrap());
        }
    }

    /// Any two distinct quorums intersect in exactly one shared node (Maekawa, spec §L4).
    #[test]
    fn quorums_always_intersect(i in 0..N31, j in 0..N31) {
        prop_assume!(i != j);
        let qa = Quorum::new(Line::<F31>::at(i));
        let qb = Quorum::new(Line::<F31>::at(j));
        let node = qa.intersection(&qb).unwrap();
        prop_assert!(qa.members().any(|p| p == node));
        prop_assert!(qb.members().any(|p| p == node));
    }

    /// Every node sits on exactly `q+1` lines regardless of identity — the centrality cap,
    /// so a Sybil gains nothing (spec §L3, V3).
    #[test]
    fn centrality_is_uniform(seed in 0u8..=255, epoch in 0u32..1000) {
        let node = Node::<F31>::open(&VrfSecret::from_seed([seed; 32]), NodeId([seed; 32]), Epoch::new(epoch.into()), &BeaconSeed::GENESIS);
        prop_assert_eq!(node.quorums().count() as u32, Plane::<F31>::LINE_SIZE);
    }

    /// The hierarchy scale formulas hold for any cell size and depth (spec §L1, V4).
    #[test]
    fn hierarchy_scale(q in 2u32..50, k in 1u32..4) {
        let h = Hierarchy::new(q, k);
        let cell = u128::from(q) * u128::from(q) + u128::from(q) + 1;
        prop_assert_eq!(h.cell_size(), cell);
        prop_assert_eq!(h.total_nodes(), cell.pow(k));
        prop_assert_eq!(h.routing_state(), u128::from(k) * cell);
        prop_assert_eq!(h.rendezvous_depth(), k);
    }
}
