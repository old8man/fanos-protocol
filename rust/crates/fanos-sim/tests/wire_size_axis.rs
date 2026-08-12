//! The transport's **size axis** (#195) — the eighth simulator blindness, closed.
//!
//! Before this, `NetworkModel` decided delivery from `(from, to, rng)` alone: latency, loss, partition. A
//! frame of *any* size arrived intact, so the whole class #190 belongs to — a producer packing past what a
//! reader will accept — could not be expressed by any scenario, however adversarial. Not a missing scenario:
//! a missing observable.
//!
//! What makes the axis honest is that its ceiling is **imported**. [`fanos_sim::wire_ceiling`] forwards
//! `fanos_quic::max_wire()`, the very number `read_to_end` is given in production. A literal here would
//! track production until one of them moved, and a simulator that silently disagrees is worse than one with
//! no size axis at all — it reports a green run for a frame the real receiver drops.
//!
//! Both directions are pinned below, because a size check has two ways to be wrong and only one of them is
//! the one people look for: refusing too little (the blindness) and refusing too much (a sim that fails
//! traffic production carries, which would send someone hunting a defect that does not exist).

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration, Triple};
use fanos_sim::{Delivery, NetworkModel, Sim, spawn_cell, wire_ceiling, wire_len_of};

/// A settled 7-node cell — the standard fixture; nothing here depends on its topology beyond two live nodes.
fn settled() -> (Sim, Vec<Triple>) {
    let mut sim = Sim::new(7);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    (sim, cell)
}

#[test]
fn the_ceiling_is_productions_own_and_not_a_copy_of_it() {
    // The whole value of the axis rests on this identity. If it ever fails, the sim has acquired its own
    // opinion about the wire — which is the failure this test exists to make loud rather than subtle.
    assert_eq!(
        wire_ceiling(),
        fanos_quic::max_wire(),
        "the sim's ceiling IS the number production reads with; a copy would drift silently"
    );
    // And the growth term is proteus's, applied once. An empty frame still costs the transform's worst case,
    // which is what a receiver must budget for.
    assert_eq!(wire_len_of(0), fanos_proteus::MAX_WIRE_OVERHEAD);
    assert_eq!(wire_len_of(100), 100 + fanos_proteus::MAX_WIRE_OVERHEAD);
}

#[test]
fn the_axis_refuses_above_the_ceiling_and_admits_at_it() {
    let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(0), 0.0);
    let mut rng = fanos_sim::Rng::new(1);
    let (a, b) = ([1u32, 0, 0], [0u32, 1, 0]);
    let ceiling = wire_ceiling();

    // Exactly at the ceiling is DELIVERED. This is the direction a careless size check gets wrong, and
    // getting it wrong costs more than the blindness did: production packs frames to its budget on purpose
    // (a full TAXIS block), so a sim refusing them would fail runs production completes.
    assert!(
        matches!(net.deliver(a, b, ceiling, &mut rng), Delivery::After(_)),
        "a wire form exactly at the ceiling is what a producer is entitled to send"
    );
    // One byte past it is refused, and the verdict CARRIES BOTH NUMBERS — a reader of a failing scenario
    // needs to know by how much, not merely that.
    match net.deliver(a, b, ceiling + 1, &mut rng) {
        Delivery::Oversize { wire_len, ceiling: c } => {
            assert_eq!(wire_len, ceiling + 1);
            assert_eq!(c, ceiling);
        }
        other => panic!("one byte past the ceiling must be refused for SIZE, got {other:?}"),
    }
}

#[test]
fn an_oversize_frame_is_refused_for_size_and_never_as_loss() {
    // The distinction is the point of the axis, not a nicety. An oversize frame fails identically on every
    // run because a producer and a reader disagree about a bound; a lost one is the network being itself and
    // a retry may work. Folded into one counter, the first reads as the second and nobody investigates.
    //
    // A hard partition is checked FIRST in `deliver`, so this uses a fully-connected model: the question is
    // whether size beats the random causes, and it must, because it is the deterministic one.
    let net = NetworkModel::new(Duration::from_millis(20), Duration::from_millis(0), 1.0); // total loss
    let mut rng = fanos_sim::Rng::new(2);
    let (a, b) = ([1u32, 0, 0], [0u32, 1, 0]);
    assert!(
        matches!(net.deliver(a, b, wire_ceiling() + 1, &mut rng), Delivery::Oversize { .. }),
        "with loss at 1.0 the frame would be lost anyway — but a CERTAIN failure must not be reported as \
         an unlucky one, or a scenario reads a protocol defect as a flaky link"
    );
}

#[test]
fn ordinary_traffic_crosses_the_new_axis_untouched() {
    // The control for the whole change, and the one that would have caught it had the ceiling been wrong:
    // a settled cell exchanging a real payload must deliver, with the oversize counter flat at zero.
    // Falsified by hand while writing this (#195): cutting `wire_ceiling()` to a few hundred bytes turns
    // `frames_oversize` from 0 to the whole run's traffic and `payloads_delivered` to 0 — so a green result
    // here is a statement about the axis, not about the axis being asleep.
    let (mut sim, cell) = settled();
    let before = sim.report().metrics.payloads_delivered;
    sim.inject(cell[0], Command::Send { to: cell[3], payload: b"ordinary".to_vec() });
    sim.run_for(Duration::from_millis(1000));

    let m = &sim.report().metrics;
    assert_eq!(
        m.frames_oversize, 0,
        "no honest frame in a settled cell approaches a 1 MiB ceiling; a non-zero count here means the \
         sim has started refusing traffic production carries"
    );
    assert_eq!(m.payloads_delivered, before + 1, "and the payload still arrives");
}
