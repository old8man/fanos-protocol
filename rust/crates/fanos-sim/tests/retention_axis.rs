//! The transport's **retention axis** (#246) — the ninth simulator blindness, closed.
//!
//! The model had four axes — latency, jitter, loss, partition — and a message was either delivered or lost.
//! **Nothing could wait.** So the whole class #245 belongs to was inexpressible: a transport library
//! buffering on our behalf, bounded only by its own default. That class had just produced a CRITICAL (100
//! uni-streams × 1.25 MB = ~124 MB pinned by one inbound connection against a 256 MiB node budget) and no
//! simulator run could have found it, because in the model there was nothing to accumulate in.
//!
//! Retention is a different mechanism from #195's size axis and needs a different fix: that one is about
//! how many BYTES one message occupies, this one about how many UNCONSUMED messages the transport holds
//! for us. The capacity is production's own — [`fanos_quic::inbound_frame_capacity`], derived from
//! `MAX_PEER_UNI_STREAMS`, because one frame rides one uni-stream and the sender's next `open_uni` stalls
//! once that many are unread.
//!
//! Three states that used to be one: a peer that is **not reading**, a peer that is **partitioned**, and a
//! peer that is **down**. Production distinguishes them and now so does the sim.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_field::F2;
use fanos_runtime::{Command, Config, Duration, Triple};
use fanos_sim::{Sim, spawn_cell};

fn settled() -> (Sim, Vec<Triple>) {
    let mut sim = Sim::new(11);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    (sim, cell)
}

#[test]
fn a_receiver_that_stops_reading_accumulates_up_to_productions_capacity_then_back_pressures() {
    let (mut sim, cell) = settled();
    let capacity = fanos_quic::inbound_frame_capacity();
    let deaf = cell[3];

    sim.stop_consuming(deaf);
    let (held0, with0, bp0) = (
        sim.held_for(deaf),
        sim.report().metrics.frames_withheld,
        sim.report().metrics.frames_backpressured,
    );
    assert_eq!(held0, 0, "nothing is held before anyone sends to the deaf node");

    // Twice the capacity, so the boundary is crossed rather than merely approached — a test that stops AT
    // the capacity would pass whether or not the refusal arm exists.
    for i in 0..capacity * 2 {
        sim.inject(cell[0], Command::Send { to: deaf, payload: vec![b'x'; 8 + i] });
        sim.run_for(Duration::from_millis(200));
    }

    let m = sim.report().metrics.clone();
    assert_eq!(
        sim.held_for(deaf),
        capacity,
        "the hold fills to exactly production's inbound frame capacity and no further"
    );
    assert!(
        m.frames_withheld > with0,
        "frames toward a deaf peer are HELD — neither delivered nor lost, the fate the model could not \
         express before"
    );
    assert!(
        m.frames_backpressured > bp0,
        "and past the capacity the sender is refused, which is where production's writer would block"
    );

    // Resuming delivers the backlog rather than discarding it — the difference between a slow reader and a
    // lossy link, which is the whole distinction this axis exists to draw.
    sim.resume_consuming(deaf);
    sim.run_for(Duration::from_millis(500));
    assert_eq!(sim.held_for(deaf), 0, "the backlog drains when the reader returns");
}

#[test]
fn a_reading_receiver_accumulates_nothing() {
    // The falsification of the test above, and the one that matters: without it, that test would pass just
    // as well if the counter tracked ordinary traffic instead of retention. Same cell, same sends, nobody
    // deafened — the two counters must stay at zero throughout.
    let (mut sim, cell) = settled();
    for i in 0..fanos_quic::inbound_frame_capacity() * 2 {
        sim.inject(cell[0], Command::Send { to: cell[3], payload: vec![b'x'; 8 + i] });
        sim.run_for(Duration::from_millis(200));
    }
    let m = sim.report().metrics.clone();
    assert_eq!(m.frames_withheld, 0, "a reading peer holds nothing");
    assert_eq!(m.frames_backpressured, 0, "and nothing is refused");
    assert_eq!(sim.held_for(cell[3]), 0);
}

#[test]
fn a_held_frame_is_counted_as_held_and_never_as_a_drop() {
    // Three states the old model collapsed into "the message did not arrive": not reading, partitioned,
    // down. The discriminator is not HOW MANY frames pile up — my first version asserted exactly one and
    // measured four, because a settled cell's own heartbeats fill a deaf peer's hold without anyone calling
    // `Send` (worth knowing on its own: capacity is 4 frames, so a deaf peer back-pressures almost at once).
    // The discriminator is WHERE the count lands. Same traffic, two counters, and only one of them moves.
    let (mut sim, cell) = settled();
    let deaf = cell[2];
    let dropped_before = sim.report().metrics.frames_dropped;

    sim.stop_consuming(deaf);
    sim.inject(cell[0], Command::Send { to: deaf, payload: b"held".to_vec() });
    sim.run_for(Duration::from_millis(300));

    let m = sim.report().metrics.clone();
    assert!(sim.held_for(deaf) > 0, "a deaf peer's frames are being held");
    assert!(m.frames_withheld > 0, "and they land in the retention counter");
    assert_eq!(
        m.frames_dropped, dropped_before,
        "and NOT in the drop counter — the network is lossless here, the peer simply is not reading, and \
         conflating the two is what made a backlog read as a lossy link"
    );
}
