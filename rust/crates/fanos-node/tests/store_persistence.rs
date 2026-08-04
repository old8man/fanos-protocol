//! **A node comes back holding what it held.**
//!
//! Until now it did not. A FANOS node persisted its identity and nothing else, so every erasure shard the
//! cell had made it custodian of, the expiry schedule, and the loss ledger whose own doc called it durable
//! all died with the process (#77). The cell survived that — `[7,3,4]` reconstructs from three of seven
//! homes — but survival by spending the repair budget on ordinary reboots is not durability, and a rolling
//! restart spends the whole budget at once.
//!
//! Driven through the **production path** end to end: `Command::Put` to write, `Command::Snapshot` to
//! extract, the real `durable::write_snapshot`/`read_snapshot` pair on a real directory, and
//! `compose_engine` — the one place a node's engine is assembled — to restore. Nothing here reaches into a
//! private field, so deleting the wiring anywhere along that chain fails the test rather than passing it on
//! a private back door.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_node::composition::{CellComposition, compose_engine};
use fanos_runtime::{
    Command, Config as OverlayConfig, Effect, Engine, Input, Instant, Notification,
};

/// A directory of this test's own, removed when it drops.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("fanos-persist-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A node's engine, optionally adopting a previous run's snapshot — assembled the way a deployment is.
fn engine(restore: Option<Vec<u8>>) -> Box<dyn Engine + Send> {
    let what = CellComposition { restore, ..CellComposition::overlay_only(OverlayConfig::default()) };
    compose_engine::<F2>(Point::<F2>::at(0), &what)
}

/// Ask the engine what it holds, through the same command a persister uses.
fn snapshot(node: &mut dyn Engine, at: u64) -> Vec<u8> {
    node.step(Instant(at), Input::Command(Command::Snapshot))
        .into_iter()
        .find_map(|e| match e {
            Effect::Notify(Notification::Snapshot(bytes)) => Some(bytes),
            _ => None,
        })
        .expect("Command::Snapshot must answer with Notification::Snapshot")
}

/// Store `value` under `key`. A lone node is the nearest-occupied home for every one of the seven shard
/// points, so all seven land locally — which is exactly the custody a restart used to drop.
fn put(node: &mut dyn Engine, at: u64, key: &[u8], value: &[u8]) {
    node.step(Instant(at), Input::Command(Command::Put { key: key.to_vec(), value: value.to_vec() }));
}

/// **The property: what a node held before a restart, it holds after one.**
///
/// Stated as byte equality of the two snapshots, which is stronger than "some shards came back" and only
/// meaningful because the encoding is canonical — every map streams in sorted order, so equal state is equal
/// bytes. The falsification is in the same test and it is the point: an engine composed *without* the
/// snapshot must come back with a **different** store, so a `restore` that silently did nothing could not
/// pass this by accident.
#[test]
fn a_node_that_restarts_holds_what_it_held() {
    let dir = Scratch::new("restart");

    let mut before = engine(None);
    let empty = snapshot(&mut *before, 1);
    put(&mut *before, 2, b"contract.wasm", b"the value a cell asked this node to keep");
    put(&mut *before, 3, b"another-key", &[7u8; 512]);
    let held = snapshot(&mut *before, 4);
    assert_ne!(held, empty, "the writes must have left something to persist");

    // Through the real file, at the real path, with the real atomic write.
    fanos_node::durable::write_snapshot(dir.path(), &held).expect("write the snapshot");
    let read_back = fanos_node::durable::read_snapshot(dir.path()).expect("read it back");
    assert_eq!(read_back, held, "the file is the bytes the engine produced");

    let mut after = engine(Some(read_back));
    assert_eq!(
        snapshot(&mut *after, 5),
        held,
        "a restarted node must hold exactly what it held: same shards, same versions, same expiry, same \
         loss ledger"
    );

    // The falsification, in the same test so it cannot rot separately: without the snapshot the very same
    // composition comes back empty. If `restore` were a no-op, this assertion and the one above could not
    // both hold.
    let mut cold = engine(None);
    assert_eq!(
        snapshot(&mut *cold, 6),
        empty,
        "a node composed without a snapshot must start empty — otherwise the assertion above proves nothing"
    );
}

/// A snapshot is a **file**, so it is provisioning, and provisioning is the surface that gets audited last.
///
/// Every way the bytes can be wrong has to be a refusal that leaves the node empty rather than a partial
/// adoption: a node that half-loads a store silently claims custody of shards it does not have, and a member
/// that lies about custody is worse for the cell than one that starts clean.
#[test]
fn a_snapshot_that_is_not_ours_is_refused_whole() {
    let mut source = engine(None);
    put(&mut *source, 1, b"key", b"value");
    let good = snapshot(&mut *source, 2);
    let empty = snapshot(&mut *engine(None), 1);

    let mut truncated = good.clone();
    truncated.truncate(good.len() - 1);

    let mut flipped = good.clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 0x01;

    let mut trailing = good.clone();
    trailing.push(0);

    let mut wrong_version = good.clone();
    wrong_version[0] = wrong_version[0].wrapping_add(1);

    for (what, bytes) in [
        ("truncated mid-write", truncated),
        ("one flipped bit", flipped),
        ("trailing garbage", trailing),
        ("a format version this build does not know", wrong_version),
        ("empty", Vec::new()),
        ("shorter than the checksum", alloc_short()),
    ] {
        let mut node = engine(Some(bytes));
        assert_eq!(
            snapshot(&mut *node, 3),
            empty,
            "{what}: must be refused whole and leave the store empty, never partially adopted"
        );
    }

    // And the good one still works, so the loop above is refusing bad bytes rather than everything.
    let mut node = engine(Some(good.clone()));
    assert_eq!(snapshot(&mut *node, 3), good, "a valid snapshot is still adopted");
}

/// Bytes too short to even carry the checksum — the degenerate truncation.
fn alloc_short() -> Vec<u8> {
    vec![0u8; 8]
}

/// **Restoring over a node that has already served would discard what it served.**
///
/// A live node adopting a snapshot silently replaces the shards it has accepted since it started. The refusal
/// makes the caller's mistake visible at startup, which is where an ordering bug of this shape belongs — the
/// alternative is data that quietly disappears.
#[test]
fn a_snapshot_cannot_be_adopted_by_a_node_that_has_already_stored_something() {
    let mut original = engine(None);
    put(&mut *original, 1, b"from-the-snapshot", b"old");
    let snap = snapshot(&mut *original, 2);

    // The same engine type, but this one has already accepted a write of its own.
    let mut live = fanos_runtime::OverlayNode::<F2>::new(Point::<F2>::at(0), OverlayConfig::default());
    live.step(Instant(1), Input::Command(Command::Put { key: b"live".to_vec(), value: b"new".to_vec() }));
    let own = snapshot(&mut live, 2);
    assert_ne!(
        own,
        snapshot(&mut *engine(None), 2),
        "the live node must actually hold something, or the refusal below proves nothing"
    );

    assert!(!live.restore(&snap), "a node that has stored something must refuse a snapshot");
    assert_eq!(snapshot(&mut live, 3), own, "and must still hold its own write, not the snapshot's");
}

/// The store's own DoS caps apply to a file exactly as they apply to the network.
///
/// `MAX_STORE_ENTRIES` and `MAX_VALUE_LEN` bound what a *peer* can make this node hold. A restore path that
/// did not re-check them would let a crafted file do what no peer can — so the check is not a duplicate, it
/// is the same rule applied at the second door.
#[test]
fn a_crafted_snapshot_cannot_exceed_the_caps_the_network_is_held_to() {
    let empty = snapshot(&mut *engine(None), 1);

    // One entry whose shard is longer than any value the store accepts. Hand-built, because no engine will
    // produce one — which is the situation the check exists for.
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_le_bytes()); // format version
    body.extend_from_slice(&0u64.to_le_bytes()); // seq
    body.extend_from_slice(&1u32.to_le_bytes()); // one entry
    body.extend_from_slice(&[9u8; 32]); //          its digest
    body.extend_from_slice(&1u32.to_le_bytes()); // one shard
    body.push(0); //                                at point 0
    body.extend_from_slice(&0u64.to_le_bytes()); // version
    let oversized = vec![0u8; 65_537]; //           MAX_VALUE_LEN + 1
    body.extend_from_slice(&u32::try_from(oversized.len()).unwrap().to_le_bytes());
    body.extend_from_slice(&oversized);
    body.extend_from_slice(&0u32.to_le_bytes()); // no expiry
    body.extend_from_slice(&0u32.to_le_bytes()); // no losses
    let tag = fanos_primitives::hash::hash_labeled("FANOS-v1/store-snapshot", &body);
    body.extend_from_slice(&tag);

    let mut node = engine(Some(body));
    assert_eq!(
        snapshot(&mut *node, 2),
        empty,
        "a shard over MAX_VALUE_LEN must be refused on the way in from disk, exactly as it is on the way in \
         from a peer"
    );
}

/// The **side maps** need the cap as much as the held shards do, and for a while only the shards had it.
///
/// `expiry` and `loss_ledger` are documented as subsets of the held keys — but that is an invariant of the
/// code that *writes* a snapshot, and the premise of reading one is that it may not have come from that code.
/// A file with no entries at all and a few million expiry records is an allocation no peer can ask for.
#[test]
fn a_crafted_snapshot_cannot_amplify_through_the_side_maps() {
    let empty = snapshot(&mut *engine(None), 1);
    // One more than the store's key cap, in the cheapest map: 40 bytes each, and no shards at all.
    let over = fanos_runtime::MAX_STORE_ENTRIES + 1;

    for (which, expiry_count, loss_count) in
        [("expiry", over, 0usize), ("loss ledger", 0usize, over)]
    {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes()); // format version
        body.extend_from_slice(&0u64.to_le_bytes()); // seq
        body.extend_from_slice(&0u32.to_le_bytes()); // no entries
        for count in [expiry_count, loss_count] {
            body.extend_from_slice(&u32::try_from(count).unwrap().to_le_bytes());
            for i in 0..count {
                let mut digest = [0u8; 32];
                digest[..8].copy_from_slice(&(i as u64).to_le_bytes());
                body.extend_from_slice(&digest);
                body.extend_from_slice(&0u64.to_le_bytes());
            }
        }
        let tag = fanos_primitives::hash::hash_labeled("FANOS-v1/store-snapshot", &body);
        body.extend_from_slice(&tag);

        let mut node = engine(Some(body));
        assert_eq!(
            snapshot(&mut *node, 2),
            empty,
            "a {which} over MAX_STORE_ENTRIES must be refused: capping only the held shards leaves the side \
             maps bounded by nothing but the file's length"
        );
    }
}
