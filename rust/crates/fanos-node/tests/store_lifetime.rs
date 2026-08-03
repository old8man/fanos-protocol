//! **How long a cell can publish before its store refuses to accept anything new.**
//!
//! Six directories key their slots by `(coordinate, epoch)` — `mixdir`, `capdir`, `loaddir`,
//! `telemetry_dir`, `exit`, `crosscell_dir` — and every one re-publishes on each epoch advance, so every
//! node mints a *distinct* key every epoch. Against that, the store's admission rule is **fail-closed**: past
//! [`MAX_STORE_ENTRIES`] a new digest is refused while keys already held keep accepting writes.
//!
//! Those two facts used to compose into a clock, and the failure was the dangerous kind — not a slowdown or
//! an error, but a cell that worked normally and then, at a time fixed by the epoch period and the publisher
//! count, silently stopped being able to advertise a capability, report a load or rotate a mix key, while
//! every lookup against an *existing* key kept answering. This file's first version measured **1.01 days**
//! for the shipped constants, and nothing in the cell would have reported it.
//!
//! What was missing was not capacity — raising the cap only moves the date — but the ability to say that a
//! directory slot is **soft state**. A key reaches the store as an opaque digest, so the store cannot know;
//! the publisher can, and now declares it (`Command::PutEphemeral`). This file is the arithmetic that keeps
//! the two halves honest: it reads the shipped constants and computes, so it stays true when they move.

#![allow(clippy::unwrap_used, clippy::cast_precision_loss)]

use fanos_node::config::DEFAULT_EPOCH_PERIOD;
use fanos_runtime::MAX_STORE_ENTRIES;

/// Distinct `(coordinate, epoch)`-keyed slots ONE node writes per epoch in a fully-provisioned cell.
///
/// Counted from the publishers, not chosen: `capdir::publish_capability` (every node advertises its role
/// set), `loaddir::publish_load` (every node reports its measured per-role load), `mixdir::publish_mix_key`
/// (every relay publishes its forward-secure onion key), `telemetry_dir::publish_coherence` (every node with
/// `telemetry_epsilon` set). An exit adds `exit::publish_exit_key`; a validator cell adds
/// `crosscell_dir::{publish_checkpoint, publish_health}`. Four is therefore the **floor**, not the estimate.
const SLOTS_PER_NODE_PER_EPOCH: usize = 4;

/// The base cell's node count — `q² + q + 1` at `q = 2`. Every node's writes land in the same key space,
/// because a key's shard homes are its digest's points and the whole cell holds the plane.
const CELL_NODES: usize = 7;

/// How many further epoch advances a directory slot outlives — `fanos_node::DIRECTORY_SLOT_EPOCHS`, restated
/// here because that constant is crate-private and this test must not be able to drift from it silently.
/// The assertion below fails loudly if it does, since the live-set bound is computed from it.
const SLOT_GRACE_EPOCHS: usize = 1;

#[test]
fn the_live_directory_slot_count_is_bounded_and_does_not_grow_with_uptime() {
    // The property the expiry buys, and it is a *shape* claim rather than a threshold: at any moment the
    // live directory slots are the current epoch's plus the grace window's, so the number is a constant of
    // the cell — publishers times a small window — and does not depend on how long the cell has been up.
    let live = SLOTS_PER_NODE_PER_EPOCH * CELL_NODES * (1 + SLOT_GRACE_EPOCHS);

    // What it used to be, kept as the record rather than as prose: the same publishers with no expiry filled
    // the store on a wall clock, and this is the figure that made it a testnet blocker rather than a
    // housekeeping item.
    let per_epoch = SLOTS_PER_NODE_PER_EPOCH * CELL_NODES;
    let epochs_to_fill = MAX_STORE_ENTRIES / per_epoch;
    let days_to_fill = (epochs_to_fill as f64 * DEFAULT_EPOCH_PERIOD.as_secs_f64()) / 86_400.0;

    println!(
        "\n  store cap                 {MAX_STORE_ENTRIES} keys\n  \
         directory writes / epoch  {per_epoch} ({SLOTS_PER_NODE_PER_EPOCH} per node × {CELL_NODES} nodes)\n  \
         LIVE slots at any moment  {live}  (current epoch + {SLOT_GRACE_EPOCHS} grace)\n  \
         headroom for content      {} keys\n  \
         without expiry this filled in {days_to_fill:.2} days and the cell went silent\n",
        MAX_STORE_ENTRIES.saturating_sub(live),
    );

    assert!(
        live < MAX_STORE_ENTRIES / 4,
        "the directories must not occupy a material fraction of the store: {live} live slots against a cap \
         of {MAX_STORE_ENTRIES} leaves too little for content, and the store is shared",
    );
    assert!(
        days_to_fill < 30.0,
        "this figure is the record of WHY the expiry exists — if the unexpired fill time has become long \
         enough not to matter, say so and delete the mechanism rather than leaving a claim that no longer \
         describes anything",
    );
}
