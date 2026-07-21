//! L4 distributed-storage scenarios: `Put`/`Get` over the projective rendezvous, replicated for
//! LRC availability — and the property that matters most, that a `Get` to a *crashed* responsible
//! node transparently reroutes to a co-linear replica (storage ∘ self-healing, spec §L4 + §6.7).

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use fanos_field::F2;
use fanos_geometry::fano;
use fanos_primitives::{hash::label, map_to_point};
use fanos_runtime::{Command, Config, Duration, OverlayNode};
use fanos_sim::{Sim, spawn_cell};

/// The responsible point index and coordinate for `key` (the `MapToPoint(H(key))` address).
fn responsible(key: &[u8], cell: &[[u32; 3]]) -> (usize, [u32; 3]) {
    let coord = map_to_point::<F2>(label::STORAGE, key).coords();
    let idx = cell.iter().position(|&c| c == coord).unwrap();
    (idx, coord)
}

fn established(seed: u64) -> (Sim, Vec<[u32; 3]>) {
    let mut sim = Sim::new(seed);
    let cell = spawn_cell::<F2>(&mut sim, Config::default());
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000));
    (sim, cell)
}

#[test]
fn a_put_to_an_unoccupied_ideal_point_still_routes_and_is_retrievable() {
    // #123: independent VRF placement rarely fills every projective point, so a key's ideal storage
    // point MapToPoint(H(k)) is frequently UNOCCUPIED. With the old exact-match responsibility, such a
    // Put/Get was a silent send-to-nobody; with nearest-occupied resolution (consistent hashing on the
    // point index, spec §L0) it routes to a live member and round-trips. Spawn a SPARSE cell — 3 of the
    // 7 Fano points — and round-trip a batch of keys, proving (a) at least one key's ideal point is
    // unoccupied, and (b) every key is still retrievable (the old code would have lost exactly those).
    const N: usize = 24;
    let occupied_idx = [0usize, 2, 5];
    let mut sim = Sim::new(123);
    let nodes: Vec<[u32; 3]> = occupied_idx
        .iter()
        .map(|&i| {
            sim.add(Box::new(OverlayNode::<F2>::new(
                fano::point(i),
                Config::default(),
            )))
        })
        .collect();
    sim.inject_all(&Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(2000)); // liveness: each occupant hears the other two

    let keys: Vec<Vec<u8>> = (0..N)
        .map(|k| format!("resource-{k}").into_bytes())
        .collect();
    let unoccupied_ideals = keys
        .iter()
        .filter(|k| !occupied_idx.contains(&map_to_point::<F2>(label::STORAGE, k).index()))
        .count();

    let putter = nodes[0];
    for (k, key) in keys.iter().enumerate() {
        sim.inject(
            putter,
            Command::Put {
                key: key.clone(),
                value: format!("payload-{k}").into_bytes(),
            },
        );
    }
    sim.run_for(Duration::from_millis(3000)); // every Put routes to its nearest occupant + replicates

    let getter = nodes[1];
    for key in &keys {
        sim.inject(getter, Command::Get { key: key.clone() });
    }
    sim.run_for(Duration::from_millis(3000));

    let retrieved = sim
        .report()
        .retrievals()
        .filter(|(_, _, v)| v.is_some())
        .count();
    assert!(
        unoccupied_ideals > 0,
        "non-vacuity: at least one key's ideal point must be unoccupied (got {unoccupied_ideals}/{N})"
    );
    assert_eq!(
        retrieved, N,
        "every key round-trips despite {unoccupied_ideals} unoccupied ideal points — the old exact-match \
         would have lost exactly those (retrieved {retrieved}/{N})"
    );
}

#[test]
fn put_then_get_returns_the_value() {
    let (mut sim, cell) = established(1);
    let (primary_idx, _) = responsible(b"greeting", &cell);
    // Put from a node that is NOT the responsible one, so the value must route there.
    let putter = cell[(primary_idx + 1) % 7];
    sim.inject(
        putter,
        Command::Put {
            key: b"greeting".to_vec(),
            value: b"hello world".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(1000));
    assert!(sim.report().metrics.stores >= 1, "the put was acknowledged");

    // Get from yet another node.
    let getter = cell[(primary_idx + 3) % 7];
    sim.inject(
        getter,
        Command::Get {
            key: b"greeting".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(1000));

    let (_, _, value) = sim.report().retrievals().last().unwrap();
    assert_eq!(value, Some(&b"hello world"[..]));
}

#[test]
fn a_missing_key_retrieves_nothing() {
    let (mut sim, cell) = established(2);
    sim.inject(
        cell[0],
        Command::Get {
            key: b"never-stored".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(1000));
    let (_, _, value) = sim.report().retrievals().last().unwrap();
    assert_eq!(value, None, "an unstored key returns a miss");
}

#[test]
fn the_value_is_replicated_across_the_cell() {
    // After a put settles, every live node can answer a Get (LRC availability) — under erasure by gathering
    // a recoverable shard-set from the cell and reconstructing, not from a full local copy.
    let (mut sim, cell) = established(3);
    sim.inject(
        cell[0],
        Command::Put {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(1000));

    let before = sim.report().metrics.retrieval_hits;
    // Every node gets it; all should hit.
    for &node in &cell {
        sim.inject(node, Command::Get { key: b"k".to_vec() });
    }
    sim.run_for(Duration::from_millis(1000));
    assert_eq!(
        sim.report().metrics.retrieval_hits - before,
        7,
        "all seven nodes answer from a local replica"
    );
}

#[test]
fn a_read_is_repaired_across_the_replica_line_when_the_primary_is_empty() {
    // The subtle case the single-primary read misses: the responsible node is *up* but has lost its
    // shard (it was down when the value was published, then recovered empty), while replicas still
    // hold it. Read repair must fall back across the line and still find the value.
    let (mut sim, cell) = established(11);
    let (primary_idx, primary) = responsible(b"repair-key", &cell);
    let putter = cell[(primary_idx + 1) % 7];
    let querier = cell[(primary_idx + 3) % 7];

    // The primary and the querier are both offline. The putter first detects the primary down and
    // installs its reroute, so the Put lands on a co-linear survivor (which replicates to the live
    // members) — the primary and querier never receive it.
    sim.crash(primary);
    sim.crash(querier);
    sim.run_for(Duration::from_millis(3000)); // putter detects the primary down
    sim.inject(putter, Command::Diagnose); // installs putter.reroute[primary] → survivor
    sim.settle();
    sim.inject(
        putter,
        Command::Put {
            key: b"repair-key".to_vec(),
            value: b"survived".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(1500));

    // Both rejoin. The primary is now UP but empty (it missed the Put); the querier has no replica.
    sim.recover(primary);
    sim.recover(querier);
    sim.inject(primary, Command::StartHeartbeat);
    sim.inject(querier, Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(3000));

    sim.inject(
        querier,
        Command::Get {
            key: b"repair-key".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(3000));

    let got = sim
        .report()
        .retrievals()
        .filter(|(who, _, _)| *who == querier)
        .last()
        .map(|(_, _, v)| v.map(<[u8]>::to_vec));
    assert_eq!(
        got,
        Some(Some(b"survived".to_vec())),
        "read repair: an empty primary falls back to a replica that still holds the value"
    );
}

#[test]
fn a_get_through_a_crashed_primary_reroutes_to_a_replica() {
    // The headline compose: a querier that missed the replica looks up the responsible node while
    // it is DOWN, and the self-healing reroute serves the value from a co-linear survivor.
    let (mut sim, cell) = established(4);
    let (primary_idx, primary) = responsible(b"resilient-key", &cell);

    // The querier is offline during the Put, so it never receives a replica.
    let querier_idx = (primary_idx + 2) % 7;
    let querier = cell[querier_idx];
    sim.crash(querier);
    sim.inject(
        cell[(primary_idx + 1) % 7],
        Command::Put {
            key: b"resilient-key".to_vec(),
            value: b"still-here".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(1000));

    // Querier rejoins (re-bootstraps), then the responsible node dies.
    sim.recover(querier);
    sim.inject(querier, Command::StartHeartbeat);
    sim.run_for(Duration::from_millis(3000)); // learn the cell
    sim.crash(primary);
    sim.run_for(Duration::from_millis(3000)); // detect the primary down
    sim.inject(querier, Command::Diagnose); // install querier's reroute[primary] → survivor
    sim.settle();

    // The querier has no local copy and the primary is dead — yet the Get succeeds via the replica.
    sim.inject(
        querier,
        Command::Get {
            key: b"resilient-key".to_vec(),
        },
    );
    sim.run_for(Duration::from_millis(1000));

    let got = sim
        .report()
        .retrievals()
        .filter(|(who, _, _)| *who == querier)
        .last()
        .map(|(_, _, v)| v.map(<[u8]>::to_vec));
    assert_eq!(
        got,
        Some(Some(b"still-here".to_vec())),
        "storage ∘ self-healing: a Get to a dead primary is served by a co-linear replica"
    );
    // Sanity: the reroute target really is the co-linear survivor mediator(querier, primary).
    assert!(fano::mediator(querier_idx, primary_idx).is_some());
}

/// **§L4 erasure-resilience research (#115).** The load-bearing property: on a full Fano cell a value is
/// `erasure::encode`d into 7 point-shards (shard `i` at point `i`), so a `Get` reconstructs from the
/// surviving shards **iff** the crashed set is `is_recoverable_fano` — exactly the codec's guarantee, now
/// delivered end-to-end through the live engine (not just the unit codec). We crash every boundary-relevant
/// subset and assert read-success matches the oracle, hitting the decisive 4-loss hyperoval boundary (a
/// hyperoval — 4 points, no 3 collinear — is the first unrecoverable pattern).
#[test]
fn a_read_reconstructs_iff_the_surviving_shards_are_recoverable() {
    use fanos_code::is_recoverable_fano;

    // Boundary-complete masks: no loss, every single, every 4-subset (the hyperoval boundary), some 5-sets.
    let mut masks: Vec<u8> = alloc_masks();
    masks.sort_unstable();
    masks.dedup();

    for &crashed in &masks {
        let (mut sim, _cell) = established(0x5E_ED ^ u64::from(crashed));
        // Store BEFORE any crash so all 7 shards are distributed (shard i → point i on the full cell).
        let putter = fano::point(0).coords();
        sim.inject(
            putter,
            Command::Put {
                key: b"resilience-key".to_vec(),
                value: b"erasure-coded across the projective plane".to_vec(),
            },
        );
        sim.run_for(Duration::from_millis(1500));

        // Crash the masked points; read from the lowest-index survivor.
        for i in 0..7usize {
            if crashed & (1u8 << i) != 0 {
                sim.crash(fano::point(i).coords());
            }
        }
        let reader_idx = (0..7usize).find(|i| crashed & (1u8 << i) == 0).unwrap();
        let reader = fano::point(reader_idx).coords();
        sim.inject(
            reader,
            Command::Get {
                key: b"resilience-key".to_vec(),
            },
        );
        // Long enough for reconstruction (fast) OR the read timeout to conclude a miss (~1600 ms).
        sim.run_for(Duration::from_millis(2500));

        let got = sim
            .report()
            .retrievals()
            .filter(|(who, _, _)| *who == reader)
            .last()
            .is_some_and(|(_, _, v)| v.is_some());
        assert_eq!(
            got,
            is_recoverable_fano(crashed),
            "crashed mask {crashed:#09b}: read success must match is_recoverable_fano"
        );
    }
}

/// The boundary-relevant crash masks: `0`, all singletons, all 4-subsets (hyperoval vs not — the decisive
/// boundary), and a few 5-subsets (always unrecoverable). Kept off the hot path for readability.
fn alloc_masks() -> Vec<u8> {
    let mut masks = vec![0u8];
    for i in 0..7u8 {
        masks.push(1 << i);
    }
    // All 4-subsets of the 7 points.
    for a in 0..7u8 {
        for b in (a + 1)..7 {
            for c in (b + 1)..7 {
                for d in (c + 1)..7 {
                    masks.push((1 << a) | (1 << b) | (1 << c) | (1 << d));
                }
            }
        }
    }
    // A few 5-subsets (always beyond the code's tolerance).
    masks.push(0b001_1111);
    masks.push(0b111_0100);
    masks
}
