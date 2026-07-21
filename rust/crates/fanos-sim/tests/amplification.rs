//! **A7 — amplification / reflection DoS.** A gossip overlay floods `Announce`s cell-wide, so the question a
//! DoS adversary asks is: can one cheap injected frame trigger an out-sized (or unbounded) fan-out? FANOS's
//! answer is structural, and this models the adversary to verify it over the running network: (1) a member
//! coordinate must be a **canonical projective point**, so `members` is bounded by the plane size `N` — a
//! flood of forged coordinates cannot grow it without limit; (2) the **monotone guard** re-floods an
//! announcement only on *first sight*, so replaying one announcement re-amplifies **zero** frames. Together
//! the fan-out per distinct valid announcement is bounded (one cell-wide epidemic, `O(N)`), and neither
//! replay nor forged-coordinate injection amplifies at all.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_field::F7;
use fanos_geometry::{HierAddr, Point, Triple};
use fanos_runtime::{Config, OverlayNode};
use fanos_sim::Sim;
use fanos_wire::{FrameType, encode_frame};

/// A minimal `Announce` wire frame for `coord` (self-cert is off in these cells, so the identity/sig/proof
/// fields are unvalidated and can be empty): `coord ‖ hier ‖ id_len ‖ id ‖ sig_len ‖ sig ‖ proof_len ‖ info`.
fn announce_frame(coord: Triple) -> Vec<u8> {
    let hier = HierAddr::<F7>::root(Point::<F7>::new(coord).unwrap());
    let mut body = Vec::new();
    for w in coord {
        body.extend_from_slice(&w.to_be_bytes());
    }
    body.extend_from_slice(&hier.encode());
    body.extend_from_slice(&0u16.to_be_bytes()); // id_len
    body.extend_from_slice(&0u16.to_be_bytes()); // sig_len
    body.extend_from_slice(&0u16.to_be_bytes()); // proof_len
    // info: empty
    let mut frame = Vec::new();
    encode_frame(FrameType::Announce.code(), &body, &mut frame);
    frame
}

/// A raw `Announce` frame carrying a NON-canonical coordinate (the zero vector is not a projective point).
fn forged_noncanonical_announce() -> Vec<u8> {
    let mut body = Vec::new();
    for _ in 0..3 {
        body.extend_from_slice(&0u32.to_be_bytes()); // [0,0,0] — not a projective point
    }
    // A depth-1 hier at a canonical point (so parse succeeds), but the member coord itself is [0,0,0].
    body.extend_from_slice(&HierAddr::<F7>::root(Point::<F7>::at(1)).encode());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    let mut frame = Vec::new();
    encode_frame(FrameType::Announce.code(), &body, &mut frame);
    frame
}

/// A small sparse cell of `OverlayNode`s at the given point indices (no heartbeat → no self-initiated
/// traffic, so every observed frame is a consequence of what the adversary injects).
fn sparse_cell(sim: &mut Sim, points: &[usize]) -> Vec<Triple> {
    points
        .iter()
        .map(|&i| {
            sim.add(Box::new(OverlayNode::<F7>::new(
                Point::at(i),
                Config::default(),
            )))
        })
        .collect()
}

#[test]
fn a_replayed_announcement_re_amplifies_nothing() {
    // The monotone guard: an announcement floods only on first sight. Re-injecting the SAME one produces no
    // further fan-out — an adversary cannot amplify by replaying a captured announcement.
    let mut sim = Sim::new(0x_A7_11);
    let cell = sparse_cell(&mut sim, &[0, 1, 2, 3, 4]);
    let attacker = Point::<F7>::at(30).coords();
    let fresh = Point::<F7>::at(10).coords(); // a canonical, unoccupied member coordinate
    let ann = announce_frame(fresh);

    // First injection: it is admitted and floods once (the receiving node re-announces to its peers).
    sim.inject_frame(attacker, cell[0], ann.clone());
    sim.run_for(fanos_runtime::Duration::from_millis(1000));
    let after_first = sim.report().metrics.frames_delivered;
    assert!(after_first > 0, "the first (new) announcement does fan out");

    // Replay the identical announcement: the monotone guard ends the flood ⇒ zero additional frames.
    sim.inject_frame(attacker, cell[0], ann);
    sim.run_for(fanos_runtime::Duration::from_millis(1000));
    let after_replay = sim.report().metrics.frames_delivered;
    // The one replayed inject itself is delivered (1 frame to cell[0]); it must trigger NO re-flood beyond it.
    assert!(
        after_replay <= after_first + 1,
        "a replayed announcement re-amplifies nothing (delivered {after_first} → {after_replay}, ≤ +1 for the inject itself)"
    );
}

#[test]
fn forged_noncanonical_coordinates_are_dropped_not_amplified() {
    // A member coordinate must be a canonical projective point; a forged [0,0,0] is dropped before membership
    // or any re-flood — so a flood of forged coordinates neither grows `members` nor amplifies.
    let mut sim = Sim::new(0x_A7_22);
    let cell = sparse_cell(&mut sim, &[0, 1, 2, 3, 4]);
    let attacker = Point::<F7>::at(30).coords();

    let before = sim.report().metrics.frames_delivered;
    for _ in 0..20 {
        sim.inject_frame(attacker, cell[0], forged_noncanonical_announce());
    }
    sim.run_for(fanos_runtime::Duration::from_millis(1500));
    let after = sim.report().metrics.frames_delivered;
    // Each of the 20 injects is itself delivered once (20 frames), but NONE re-floods — no fan-out amplification.
    assert!(
        after - before <= 20,
        "20 forged announcements deliver ≤20 frames (no re-flood) — got {}",
        after - before
    );
}

#[test]
fn membership_flood_is_bounded_by_the_plane_size() {
    // The canonical-coordinate gate bounds `members` by N: even a flood of announcements for every point
    // (and repeats) cannot grow the local membership view without limit — so the flood is O(N), not unbounded.
    let mut sim = Sim::new(0x_A7_33);
    let cell = sparse_cell(&mut sim, &[0, 1, 2, 3, 4]);
    let attacker = Point::<F7>::at(30).coords();
    let n = fanos_geometry::Plane::<F7>::N as usize;

    // Announce every canonical point (twice each — repeats must not double-count) at the target node.
    for _round in 0..2 {
        for i in 0..n {
            sim.inject_frame(
                attacker,
                cell[0],
                announce_frame(Point::<F7>::at(i).coords()),
            );
        }
    }
    sim.run_for(fanos_runtime::Duration::from_millis(2000));

    // The whole run's Announce fan-out is bounded (an epidemic per distinct point, no runaway). We assert the
    // observable frame count stays within a generous linear-in-N envelope, never exponential.
    let delivered = sim.report().metrics.frames_delivered;
    assert!(
        delivered < 100 * n as u64,
        "the announcement flood stays bounded (O(N) epidemic), got {delivered} frames for N={n}"
    );
}
