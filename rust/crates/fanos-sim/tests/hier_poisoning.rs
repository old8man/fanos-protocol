//! Threat **§79 — hierarchical routing-table poisoning** (docs/network-threat-model.md).
//!
//! ## The attack
//!
//! The overlay learns its hierarchical routing table from flooded `Announce`s (each carrying the
//! announcer's overlay [`HierAddr`]). A malicious node with a legitimate transport endpoint can try to
//! **attract** a popular destination's `RouteHier` traffic by announcing an overlay address that shares
//! a long prefix with that target: greedy longest-prefix forwarding would then hand the target's
//! traffic to the attacker (to blackhole or delay it). Delivery itself is never impersonated — a frame
//! for `T` is delivered only by the node whose own cert-bound address *is* `T` — so the damage is a
//! bounded denial/interception, but it is still worth pricing out.
//!
//! ## The defence — self-certifying addresses (§L0/§L1)
//!
//! An address is not chosen but **derived** from the node's identity: `hier[level] =
//! MapToPoint(·, id ‖ level)` ([`fanos_crypto::address_point`]). Under self-certified membership the
//! receiver recomputes the chain from the announced identity and rejects any address that does not
//! match, so an attacker can only announce an address it *earned*. Producing one that shares a
//! `k`-level prefix with a chosen target means grinding the identity against the map — `≈ N^k` work,
//! `N = q²+q+1` per cell (the Sybil-cost bound, threat B1). This file pins both halves: the live engine
//! rejects a poisoned announce, and the forging cost is measured against the `N^k` wall.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_crypto::{address_matches_identity, address_point};
use fanos_field::{Field, F7};
use fanos_geometry::{HierAddr, Point, Triple};
use fanos_runtime::{Config, Engine, Input, Instant, OverlayNode};
use fanos_wire::{FrameType, encode_frame};

/// Build an `Announce` wire frame `coord(12) ‖ hier ‖ id_len(2) ‖ id ‖ info` (the overlay's format).
fn announce_frame<F: Field>(coord: Triple, hier: &HierAddr<F>, id: &[u8], info: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for w in coord {
        body.extend_from_slice(&w.to_be_bytes());
    }
    body.extend_from_slice(&hier.encode());
    body.extend_from_slice(&(u16::try_from(id.len()).unwrap()).to_be_bytes());
    body.extend_from_slice(id);
    body.extend_from_slice(info);
    let mut frame = Vec::new();
    encode_frame(FrameType::Announce.code(), &body, &mut frame);
    frame
}

/// The self-certifying descent chain of `id` to `depth` levels.
fn derived_address<F: Field>(id: &[u8], depth: usize) -> HierAddr<F> {
    HierAddr::from_path((0..depth).map(|l| address_point::<F>(id, l)).collect()).unwrap()
}

#[test]
fn self_certified_membership_rejects_a_poisoned_address() {
    // A node running self-certified membership seeds only addresses that match the announcer's
    // identity — an honest peer's derived address is accepted, a poisoning peer's stolen target
    // address is dropped whole (no `members`, no routing-table entry).
    let cfg = Config { require_self_certified_membership: true, ..Config::default() };
    let mut v = OverlayNode::<F7>::new(Point::at(0), cfg);
    let now = Instant::default();
    let from = Point::<F7>::at(1).coords();

    // Honest peer H: a descended (depth-2) address that is exactly its identity's chain.
    let id_h = b"honest-peer-identity";
    let h_addr = derived_address::<F7>(id_h, 2);
    assert!(address_matches_identity::<F7>(id_h, &h_addr), "H's address is its own derived chain");
    let h_coord = Point::<F7>::at(5).coords();
    v.step(now, Input::Message { from, frame: announce_frame::<F7>(h_coord, &h_addr, id_h, b"keys-H") });
    assert!(v.members().any(|(c, _)| c == h_coord), "an honest self-certified announce is accepted");
    assert_eq!(v.hier_next_hop(&h_addr), Some(h_coord), "and seeds the hierarchical routing table");

    // Poisoning peer A: announces a *target's* address T that A did not derive from its own identity.
    let id_a = b"attacker-identity";
    let t_addr = derived_address::<F7>(b"popular-target-identity", 2);
    assert!(!address_matches_identity::<F7>(id_a, &t_addr), "A did not earn T's address");
    let a_coord = Point::<F7>::at(9).coords();
    v.step(now, Input::Message { from, frame: announce_frame::<F7>(a_coord, &t_addr, id_a, b"keys-A") });
    assert!(!v.members().any(|(c, _)| c == a_coord), "the poisoned announce is dropped whole");
    assert_ne!(v.hier_next_hop(&t_addr), Some(a_coord), "A cannot attract T's traffic to its endpoint");
}

#[test]
fn without_the_gate_a_poisoned_address_is_trusted() {
    // The calibration baseline: with self-certification OFF (the default), the same poisoning announce
    // IS trusted — the attacker's endpoint is seeded as the way to the target's address, in one try.
    let mut v = OverlayNode::<F7>::new(Point::at(0), Config::default());
    let now = Instant::default();
    let from = Point::<F7>::at(1).coords();
    let t_addr = derived_address::<F7>(b"popular-target-identity", 2);
    let a_coord = Point::<F7>::at(9).coords();
    v.step(now, Input::Message {
        from,
        frame: announce_frame::<F7>(a_coord, &t_addr, b"attacker-identity", b"keys-A"),
    });
    assert_eq!(
        v.hier_next_hop(&t_addr),
        Some(a_coord),
        "without the gate the attacker attracts the target's traffic for free (one announce)",
    );
}

#[test]
fn forging_an_address_near_a_target_costs_exponential_grinding() {
    // With N = 57 points per cell (q = 7), pricing out the forge: over a fixed grinding budget an
    // attacker's best *self-certifying* address (its own derived chain) cannot reproduce the target's
    // address, and near-matches obey the N^k wall. Deterministic — the identities are fixed.
    const BUDGET: usize = 3000; // < N² = 3249, so even a 2-level match should not occur
    let target = derived_address::<F7>(b"popular-destination-identity", 3);

    let mut best_cp = 0usize;
    let (mut ge2, mut ge3) = (0usize, 0usize);
    for i in 0..BUDGET {
        let mut id = b"attacker/".to_vec();
        id.extend_from_slice(&(i as u64).to_be_bytes());
        let chain = derived_address::<F7>(&id, 3);
        // The attacker's own chain always self-certifies — it just is not near the target.
        assert!(address_matches_identity::<F7>(&id, &chain));
        let cp = target.common_prefix(&chain);
        best_cp = best_cp.max(cp);
        if cp >= 2 {
            ge2 += 1;
        }
        if cp >= 3 {
            ge3 += 1;
        }
    }
    // No full forge: the attacker never reproduces the target's 3-level address (P ≈ 1/N³ ≈ 5e-6 per
    // try ⇒ essentially never in budget). This is what makes interception *near* the target infeasible.
    assert_eq!(ge3, 0, "a full-prefix forge must not appear within budget (got {ge3})");
    assert!(best_cp < target.depth(), "no attacker identity reproduced the target address");
    // Two-level near-matches obey the ~BUDGET/N² floor (≈ 0.9 expected) — a handful at most, nowhere
    // near enough to out-prefix an honest depth-2 ancestor on the path to the target.
    assert!(ge2 <= 8, "≥2-level near-forgeries stay at the N² wall (got {ge2})");
    // Contrast with the ungated cost: announcing the target verbatim is a *single* try at full match.
    assert_eq!(
        target.common_prefix(&target),
        target.depth(),
        "ungated, a verbatim announce is an instant full-prefix match — the gate raises this to >N² work",
    );
}
