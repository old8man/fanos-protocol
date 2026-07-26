#![allow(clippy::indexing_slicing, clippy::print_stdout, clippy::too_many_lines)]
//! Adversarial probe: can a node be FORCED to move to a point it cannot PROVE it may occupy?
//!
//! This is the measurement that retired the original resolution rule, kept runnable as its evidence. That rule paired two
//! predicates derived independently: `settle_index` advanced past a point **held** by a better-ranked node, while
//! `displacement_is_forced` accepted only a witness that **preferred** the point. A holder displaced *onto* `p` does not
//! prefer `p`, so it pushed the claimant off without supplying the witness the claimant needed — and the doc asserted the
//! price was occupancy alone.
//!
//! Compares that rule against the shipping one over settled populations, on provability, injectivity, and the index choice
//! left to an attacker:
//!
//! * **held/prefers** — the retired pair, spelled out locally since the library no longer offers it.
//! * **lexicographic claim** — what ships: a node's claim to `p` is `(index at which its own walk reaches p, rank)`,
//!   ordered lexicographically, and it settles at the first point no one claims better. Both halves read the *same*
//!   predicate, so provability is structural rather than hoped for.
fn main() {
    use fanos_field::{F2, F4, F7, Field};
    use fanos_geometry::{Plane, Point};
    use fanos_primitives::{BeaconSeed, Epoch};
    use fanos_vrf::{
        VrfOutput, VrfSecret, claim_beats, outranks, probe_bound, probe_index_of, probe_point, prove_coordinate_ranked,
        settle_index,
    };

    let epoch = Epoch::new(9);
    let beacon = BeaconSeed::GENESIS;

    macro_rules! run {
        ($F:ty, $name:expr, $n:expr, $trials:expr) => {{
            let (mut a_unprov, mut a_coll, mut a_seat) = (0u64, 0u64, 0u64);
            let (mut b_unprov, mut b_coll, mut b_seat) = (0u64, 0u64, 0u64);
            // The security-relevant quantity: a node can prove any index up to its first UNBEATEN one and none beyond, so
            // the choice a rule leaves an attacker is exactly that prefix's width.
            let (mut a_width, mut a_wmax, mut b_width, mut b_wmax) = (0u64, 0u16, 0u64, 0u16);
            for trial in 0..$trials {
                let ids: Vec<Vec<u8>> = (0..$n).map(|i| format!("node-{}-{}", trial, i).into_bytes()).collect();
                let ranks: Vec<VrfOutput> = ids
                    .iter()
                    .enumerate()
                    .map(|(i, id)| {
                        let mut seed = [0u8; 32];
                        seed[..8].copy_from_slice(&((trial * 1000 + i) as u64).to_le_bytes());
                        prove_coordinate_ranked::<$F>(&VrfSecret::from_seed(seed), id, epoch, &beacon).2
                    })
                    .collect();

                // ---- Rule A: the shipping pair. Iterate to a fixed point with FULL occupancy visible, the best case for
                // the claimant, so anything stuck here is stuck in the live path too.
                let mut at: Vec<Option<u16>> = vec![Some(0); $n];
                for _round in 0..64 {
                    let mut moved = false;
                    for i in 0..$n {
                        // The RETIRED rule, kept here as the evidence for why it was retired: advance past a point HELD by
                        // a better-ranked node. The library no longer offers it, so it is spelled out.
                        let occupant = |p: &Point<$F>| -> Option<VrfOutput> {
                            (0..$n).filter(|&j| j != i).find_map(|j| {
                                at[j].and_then(|k| (probe_point::<$F>(&ranks[j], k) == *p).then(|| ranks[j].clone()))
                            })
                        };
                        let next = (0..probe_bound::<$F>()).find(|&k| {
                            match occupant(&probe_point::<$F>(&ranks[i], k)) {
                                None => true,
                                Some(held) => !outranks(&held, &ranks[i]),
                            }
                        });
                        if next != at[i] {
                            at[i] = next;
                            moved = true;
                        }
                    }
                    if !moved {
                        break;
                    }
                }
                for i in 0..$n {
                    let Some(k) = at[i] else { continue };
                    a_seat += 1;
                    let p = probe_point::<$F>(&ranks[i], k);
                    if (0..$n).any(|j| j != i && at[j].is_some_and(|kj| probe_point::<$F>(&ranks[j], kj) == p)) {
                        a_coll += 1;
                    }
                    // Provable iff every skipped index has a better-RANKED node PREFERRING it.
                    let provable = (0..k).all(|j| {
                        let pj = probe_point::<$F>(&ranks[i], j);
                        (0..$n).any(|w| {
                            w != i && outranks(&ranks[w], &ranks[i]) && probe_point::<$F>(&ranks[w], 0) == pj
                        })
                    });
                    if !provable {
                        a_unprov += 1;
                    }
                    // A's beaten predicate: a better-ranked node prefers the point.
                    let a_beaten = |j: u16| {
                        let pj = probe_point::<$F>(&ranks[i], j);
                        (0..$n).any(|w| {
                            w != i && outranks(&ranks[w], &ranks[i]) && probe_point::<$F>(&ranks[w], 0) == pj
                        })
                    };
                    let m = (0..probe_bound::<$F>()).find(|&j| !a_beaten(j)).unwrap_or(probe_bound::<$F>());
                    a_width += u64::from(m) + 1;
                    a_wmax = a_wmax.max(m + 1);
                }

                // ---- Rule B: the SHIPPING rule, exercised through the library rather than re-implemented here — a
                // measurement of a local copy would not be a measurement of what runs. One-shot: a claim to `p` does not
                // depend on where anyone settled, so there is no iteration and no arrival-order dependence.
                let best = |i: usize, p: &Point<$F>| -> Option<(u16, VrfOutput)> {
                    (0..$n)
                        .filter(|&w| w != i)
                        .filter_map(|w| probe_index_of::<$F>(&ranks[w], p).map(|k| (k, ranks[w])))
                        .reduce(|a, b| if claim_beats((b.0, &b.1), (a.0, &a.1)) { b } else { a })
                };
                let beaten = |i: usize, p: &Point<$F>| -> bool {
                    match (best(i, p), probe_index_of::<$F>(&ranks[i], p)) {
                        (Some((kw, ow)), Some(km)) => claim_beats((kw, &ow), (km, &ranks[i])),
                        _ => false,
                    }
                };
                let bat: Vec<Option<u16>> =
                    (0..$n).map(|i| settle_index::<$F>(&ranks[i], |p| best(i, p))).collect();
                for i in 0..$n {
                    let Some(k) = bat[i] else { continue };
                    b_seat += 1;
                    let p = probe_point::<$F>(&ranks[i], k);
                    if (0..$n).any(|j| j != i && bat[j].is_some_and(|kj| probe_point::<$F>(&ranks[j], kj) == p)) {
                        b_coll += 1;
                    }
                    // Provable iff every skipped index is claimed better by SOMEONE — the same predicate that moved it.
                    if !(0..k).all(|j| beaten(i, &probe_point::<$F>(&ranks[i], j))) {
                        b_unprov += 1;
                    }
                    b_width += u64::from(k) + 1;
                    b_wmax = b_wmax.max(k + 1);
                }
            }
            let cap = ($n as u64) * ($trials as u64);
            println!(
                "{:>8}  P={:<4} n={:<3} bound={:<3}\n           held/prefers : seated {:>5}/{:<5} unprovable {:>4}  colliding {:>4}  choice mean {:.2} max {}\n           lexicographic: seated {:>5}/{:<5} unprovable {:>4}  colliding {:>4}  choice mean {:.2} max {}",
                $name,
                <$F as Field>::Q * <$F as Field>::Q + <$F as Field>::Q + 1,
                $n, probe_bound::<$F>(),
                a_seat, cap, a_unprov, a_coll, a_width as f64 / a_seat.max(1) as f64, a_wmax,
                b_seat, cap, b_unprov, b_coll, b_width as f64 / b_seat.max(1) as f64, b_wmax,
            );
            let _ = Plane::<$F>::N;
        }};
    }

    println!("Two resolution rules, on provability and injectivity\n");
    run!(F2, "PG(2,2)", 5usize, 200usize);
    run!(F4, "PG(2,4)", 12usize, 200usize);
    run!(F7, "PG(2,7)", 30usize, 100usize);
}
