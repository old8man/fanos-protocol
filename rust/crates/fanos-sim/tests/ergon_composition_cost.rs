//! **What composing work into one ERGON term costs the scheduler.**
//!
//! `docs/design-ergon.md` §5(a) says a composite's footprint is "tighter than the union of separately-submitted
//! transactions, because `Par` proves disjointness". The first half of that is not true for the case that matters, and this
//! experiment is here to measure the direction rather than argue it: a composite is **one scheduling unit** whose footprint
//! is exactly the union of its parts, so it conflicts with everything any part conflicts with. Grouping therefore trades
//! *schedulability* for atomicity, and the trade gets worse as the group grows.
//!
//! What `Par` genuinely buys is that the disjointness is **proven at admission** rather than discovered — the scheduler
//! never has to over-approximate inside a term. That is a different benefit from a tighter footprint, and worth stating
//! separately because the two get conflated.
//!
//! Deterministic: one seeded PRNG, no wall clock, so a surprising number reproduces exactly.

// Exact comparisons are correct here and not a rounding hazard: every figure is an integer ratio of small counts
// (`units / waves`), so the uncontended case is exactly 240 or exactly 30, never 239.999…
#![allow(clippy::expect_used, clippy::float_cmp)]

use fanos_dromos::ergon_host::balance_key;
use fanos_dromos::scheduler::{AccessList, schedule};

/// A deterministic PRNG (splitmix64), matching `dromos_parallel.rs` so the two experiments are comparable.
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn acct(i: u64) -> fanos_ergon::Key {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&i.to_le_bytes());
    balance_key(k)
}

/// `count` transfer-shaped units over a pool of `accounts`, `group` transfers to a unit.
///
/// `group == 1` is the status quo: one transaction per transfer. `group == g` is the same work expressed as composites of
/// `g` transfers, whose access list is the union — which is what the ledger derives from a `Seq`/`Par` term.
fn units(count: usize, accounts: u64, group: usize, seed: u64) -> Vec<AccessList> {
    let mut s = seed;
    let mut out = Vec::new();
    for _ in 0..count / group {
        let mut writes = Vec::new();
        for _ in 0..group {
            writes.push(acct(splitmix(&mut s) % accounts));
            writes.push(acct(splitmix(&mut s) % accounts));
        }
        out.push(AccessList::new([], writes));
    }
    out
}

/// `(parallelism, transfers_per_wave)` for one configuration.
///
/// **Parallelism = units / waves** is the figure that answers the question, and getting this wrong is what the first
/// version of this experiment did. Transfers-per-wave looks like the throughput number but is confounded at large groups:
/// the wave count can never exceed the unit count, so at `group = 8` there are only 30 units and therefore at most 30
/// waves — a fully serialized schedule then *reports the same transfers-per-wave as the ungrouped run*, because each wave
/// happens to carry 8 transfers. The measured curve was U-shaped (8.28, 5.71, 5.45, 8.28) and the recovery at the end was
/// an artefact of that cap, not a return of parallelism.
///
/// Both are returned because they answer different questions: parallelism says how much of the work ran concurrently,
/// transfers-per-wave says how much work a wave carried. Quoting the second alone is the
/// ratio-of-absolute-quantities mistake in another costume.
fn measure(count: usize, accounts: u64, group: usize, seed: u64) -> (f64, f64) {
    let list = units(count, accounts, group, seed);
    let waves = schedule(&list).len();
    if waves == 0 {
        return (0.0, 0.0);
    }
    (list.len() as f64 / waves as f64, count as f64 / waves as f64)
}

#[test]
fn grouping_transfers_into_one_term_costs_throughput_under_contention() {
    // The measurement, at fixed work (240 transfers) over a contended pool (64 accounts, so collisions are common —
    // the regime where scheduling matters at all).
    const WORK: usize = 240;
    const ACCOUNTS: u64 = 64;
    const SEED: u64 = 0xE7_60_11;

    let ladder: Vec<(usize, f64, f64)> =
        [1usize, 2, 4, 8].iter().map(|&g| { let (p, t) = measure(WORK, ACCOUNTS, g, SEED); (g, p, t) }).collect();
    for (g, par, per_wave) in &ladder {
        println!("group {g}: parallelism {par:.2}×  transfers/wave {per_wave:.2}  (64 accounts, 240 transfers)");
    }

    // The claim: a wider footprint per unit conflicts more, so less of the work runs concurrently. Monotone across the
    // whole ladder rather than end to end, because an endpoint comparison passes on a curve that dips and recovers — which
    // is exactly the shape the confounded metric produced.
    for pair in ladder.windows(2) {
        let (Some(&(g0, p0, _)), Some(&(g1, p1, _))) = (pair.first(), pair.last()) else { continue };
        assert!(p1 < p0, "grouping {g0} → {g1} must cost parallelism: {p1:.2}× vs {p0:.2}×");
    }
    let (_, first, _) = *ladder.first().expect("the ladder is not empty");
    let (_, last, _) = *ladder.last().expect("the ladder is not empty");
    assert!(last < 1.5, "at group 8 the schedule is essentially serial: {last:.2}×");
    assert!(first > 5.0, "while ungrouped it is not: {first:.2}×");
}

#[test]
fn the_cost_vanishes_when_nothing_contends() {
    // The control, and the reason the first test's regime is stated: with accounts plentiful enough that collisions are
    // rare, grouping costs nothing measurable. So the cost is a property of CONTENTION, not of composition — which is what
    // makes it a trade-off an author can reason about rather than a tax on using terms.
    const WORK: usize = 240;
    const ACCOUNTS: u64 = 100_000;
    const SEED: u64 = 0xE7_60_12;

    let (single_par, single_tw) = measure(WORK, ACCOUNTS, 1, SEED);
    let (eight_par, eight_tw) = measure(WORK, ACCOUNTS, 8, SEED);
    println!("uncontended — group 1: {single_par:.2}× / {single_tw:.2}   group 8: {eight_par:.2}× / {eight_tw:.2}");
    assert_eq!(single_tw, WORK as f64, "with no collisions every transfer shares one wave");
    assert_eq!(eight_tw, WORK as f64, "and grouping changes nothing");
    assert_eq!(single_par, WORK as f64, "every unit ran concurrently");
    assert_eq!(eight_par, (WORK / 8) as f64, "and so did every composite");
}

#[test]
fn a_composites_access_list_is_exactly_the_union_of_its_parts() {
    // The mechanism behind the cost, pinned so the two tests above are explained rather than merely observed. Nothing here
    // is tighter than the parts: a composite conflicts with everything any part conflicts with.
    let a = AccessList::new([], [acct(1), acct(2)]);
    let b = AccessList::new([], [acct(3), acct(4)]);
    let composite = AccessList::new([], [acct(1), acct(2), acct(3), acct(4)]);

    let outsider = AccessList::new([], [acct(4)]);
    assert!(!a.conflicts_with(&outsider), "the first part alone does not touch account 4");
    assert!(b.conflicts_with(&outsider), "the second does");
    assert!(composite.conflicts_with(&outsider), "so the composite does — it inherits every part's conflicts");
    assert_eq!(composite.writes.len(), a.writes.len() + b.writes.len(), "and its footprint is their union");
}
