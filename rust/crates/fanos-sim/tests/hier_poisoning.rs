//! Threat **§79/§80 — hierarchical routing-table poisoning** (docs/network-threat-model.md).
//!
//! The overlay learns its hierarchical routing table from flooded `Announce`s. Two poisoning vectors:
//!
//! * **Attraction (§79)** — announce an overlay address that shares a long prefix with a popular
//!   target, so greedy longest-prefix forwarding hands you its traffic. Defeated by *self-certifying
//!   addresses*: an address is `MapToPoint(·, id ‖ level)`, so forging one near a target costs `≈ N^k`
//!   identity grinding (the Sybil-cost wall, B1).
//! * **Transport hijack (§80)** — replay a victim's real (self-certified) address but announce it at
//!   *your own* transport coordinate, so its traffic is routed to you. Defeated by a *signed
//!   descriptor*: the identity signs `coord ‖ hier ‖ id` with its hybrid key, so an attacker cannot
//!   bind the victim's address to a different coordinate without the victim's private key.
//!
//! Under `require_self_certified_membership` a receiver checks *both*. This file pins the live-engine
//! enforcement of each, the ungated baselines, and the `N^k` forging cost.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_crypto::{HybridSigningKey, address_matches_identity, address_point};
use fanos_field::{F7, Field};
use fanos_geometry::{HierAddr, Point, Triple};
use fanos_runtime::overlay::descriptor_message;
use fanos_runtime::{Config, Engine, Input, Instant, OverlayNode};
use fanos_wire::{FrameType, encode_frame};

/// Build an `Announce` wire frame `coord ‖ hier ‖ id_len(2) ‖ id ‖ sig_len(2) ‖ sig ‖ info`.
fn announce_frame<F: Field>(
    coord: Triple,
    hier: &HierAddr<F>,
    id: &[u8],
    sig: &[u8],
    info: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    for w in coord {
        body.extend_from_slice(&w.to_be_bytes());
    }
    body.extend_from_slice(&hier.encode());
    body.extend_from_slice(&(u16::try_from(id.len()).unwrap()).to_be_bytes());
    body.extend_from_slice(id);
    body.extend_from_slice(&(u16::try_from(sig.len()).unwrap()).to_be_bytes());
    body.extend_from_slice(sig);
    body.extend_from_slice(info);
    let mut frame = Vec::new();
    encode_frame(FrameType::Announce.code(), &body, &mut frame);
    frame
}

/// The self-certifying descent chain of `id` to `depth` levels.
fn derived_address<F: Field>(id: &[u8], depth: usize) -> HierAddr<F> {
    HierAddr::from_path((0..depth).map(|l| address_point::<F>(id, l)).collect()).unwrap()
}

/// A complete signed descriptor for a node: identity bundle, its derived overlay address, and a hybrid
/// signature binding `transport` to that address. `(id, hier, sig)`.
fn signed_descriptor(seed: &[u8; 32], transport: Triple, depth: usize) -> (Vec<u8>, HierAddr<F7>, Vec<u8>) {
    let key = HybridSigningKey::from_seed(seed);
    let mut id = key.ed25519_public().to_vec();
    id.extend_from_slice(&key.mldsa65_public());
    let hier = derived_address::<F7>(&id, depth);
    let sig = key.sign(&descriptor_message::<F7>(transport, &hier, &id)).expect("hybrid sign");
    (id, hier, sig)
}

fn self_certified_cell() -> Config {
    Config { require_self_certified_membership: true, ..Config::default() }
}

#[test]
fn self_certified_membership_accepts_a_signed_descriptor_and_rejects_a_poisoned_address() {
    let mut v = OverlayNode::<F7>::new(Point::at(0), self_certified_cell());
    let now = Instant::default();
    let from = Point::<F7>::at(1).coords();

    // Honest peer H: a real signed descriptor (depth-2 address derived from its identity).
    let h_coord = Point::<F7>::at(5).coords();
    let (h_id, h_addr, h_sig) = signed_descriptor(&[1u8; 32], h_coord, 2);
    v.step(now, Input::Message { from, frame: announce_frame(h_coord, &h_addr, &h_id, &h_sig, b"keys-H") });
    assert!(v.members().any(|(c, _)| c == h_coord), "a valid signed descriptor is accepted");
    assert_eq!(v.hier_next_hop(&h_addr), Some(h_coord), "and seeds the hierarchical routing table");

    // Address poisoning: A announces a target's address it did not derive, signed under A's own id.
    let a_coord = Point::<F7>::at(9).coords();
    let (a_id, _, _) = signed_descriptor(&[2u8; 32], a_coord, 2);
    let (_, t_addr, _) = signed_descriptor(&[3u8; 32], Point::<F7>::at(11).coords(), 2);
    let a_key = HybridSigningKey::from_seed(&[2u8; 32]);
    let a_sig = a_key.sign(&descriptor_message::<F7>(a_coord, &t_addr, &a_id)).unwrap(); // valid sig, wrong address
    v.step(now, Input::Message { from, frame: announce_frame(a_coord, &t_addr, &a_id, &a_sig, b"keys-A") });
    assert!(!v.members().any(|(c, _)| c == a_coord), "an address A did not derive is rejected");
    assert_ne!(v.hier_next_hop(&t_addr), Some(a_coord), "A cannot attract T's address to its endpoint");
}

#[test]
fn a_signed_descriptor_blocks_the_transport_hijack() {
    // The attacker replays the VICTIM's real (id, hier, sig) but swaps in its own transport coordinate.
    // The signature covers the victim's coordinate, so it fails for the attacker's — the hijack is dropped.
    let cfg = self_certified_cell();
    let now = Instant::default();
    let from = Point::<F7>::at(1).coords();

    let victim_coord = Point::<F7>::at(5).coords();
    let (id, addr, sig) = signed_descriptor(&[7u8; 32], victim_coord, 2);

    // The genuine descriptor (at the victim's own coordinate) is accepted.
    let mut good = OverlayNode::<F7>::new(Point::at(0), cfg);
    good.step(now, Input::Message { from, frame: announce_frame(victim_coord, &addr, &id, &sig, b"k") });
    assert_eq!(good.hier_next_hop(&addr), Some(victim_coord), "the genuine signed descriptor is accepted");

    // The hijack: identical (id, addr, sig), announced at the ATTACKER's coordinate.
    let attacker_coord = Point::<F7>::at(9).coords();
    let mut v = OverlayNode::<F7>::new(Point::at(0), cfg);
    v.step(now, Input::Message { from, frame: announce_frame(attacker_coord, &addr, &id, &sig, b"k") });
    assert!(!v.members().any(|(c, _)| c == attacker_coord), "the hijack announce is rejected");
    assert_ne!(v.hier_next_hop(&addr), Some(attacker_coord), "the victim's address is NOT routed to the attacker");
}

#[test]
fn without_the_gate_a_transport_hijack_succeeds() {
    // Baseline: with self-certification OFF (the default), the hijack IS trusted — the victim's address
    // is seeded at the attacker's coordinate in one announce. This is exactly what the gate closes.
    let mut v = OverlayNode::<F7>::new(Point::at(0), Config::default());
    let now = Instant::default();
    let from = Point::<F7>::at(1).coords();
    let (id, addr, sig) = signed_descriptor(&[7u8; 32], Point::<F7>::at(5).coords(), 2);
    let attacker_coord = Point::<F7>::at(9).coords();
    v.step(now, Input::Message { from, frame: announce_frame(attacker_coord, &addr, &id, &sig, b"k") });
    assert_eq!(
        v.hier_next_hop(&addr),
        Some(attacker_coord),
        "ungated, the attacker attracts the victim's traffic for free (one announce)",
    );
}

#[test]
fn forging_an_address_near_a_target_costs_exponential_grinding() {
    // With N = 57 points per cell (q = 7), pricing out the attraction forge: over a fixed grinding
    // budget an attacker's best self-certifying address (its own derived chain) cannot reproduce the
    // target's address, and near-matches obey the N^k wall. Deterministic — the identities are fixed.
    const BUDGET: usize = 3000; // < N² = 3249, so even a 2-level match should not occur
    let target = derived_address::<F7>(b"popular-destination-identity", 3);

    let mut best_cp = 0usize;
    let (mut ge2, mut ge3) = (0usize, 0usize);
    for i in 0..BUDGET {
        let mut id = b"attacker/".to_vec();
        id.extend_from_slice(&(i as u64).to_be_bytes());
        let chain = derived_address::<F7>(&id, 3);
        assert!(address_matches_identity::<F7>(&id, &chain), "an attacker's own chain self-certifies");
        let cp = target.common_prefix(&chain);
        best_cp = best_cp.max(cp);
        if cp >= 2 {
            ge2 += 1;
        }
        if cp >= 3 {
            ge3 += 1;
        }
    }
    assert_eq!(ge3, 0, "a full-prefix forge must not appear within budget (got {ge3})");
    assert!(best_cp < target.depth(), "no attacker identity reproduced the target address");
    assert!(ge2 <= 8, "≥2-level near-forgeries stay at the N² wall (got {ge2})");
    assert_eq!(
        target.common_prefix(&target),
        target.depth(),
        "ungated, a verbatim announce is an instant full-prefix match — the gate raises this to >N² work",
    );
}
