//! **What a seat costs to prove if the phantom yield is removed** — the last objection to the rule change,
//! priced.
//!
//! `line_confinement_coverage.rs` measures what the phantom yield costs in occupancy (`PG(2,4)` at `1.5 N`:
//! 7.5 % of draws clearing the viability floor against 97.5 % without it) and
//! `partial_knowledge_placement.rs` refutes the regression that was supposed to make the change unsafe. One
//! objection survived both, and it was the one stated in the code rather than measured:
//!
//! > a deferred-acceptance seat is a fixed point of the **whole** claim set, so it is checkable only by a
//! > verifier holding that set, where `settle_index` needs at most `q + 1` witnesses and nothing else.
//!
//! That is **wrong by a bounded factor**, and the bound is small on the planes that ship. This file computes
//! it exactly rather than arguing it.
//!
//! # Why the recursion terminates, and at what depth
//!
//! Under deferred acceptance a node `X` sitting at index `k` was rejected at each `p_j`, `j < k`, which
//! means `p_j`'s final holder `Y` **beats** `X` there: `claim_beats((k_Y, Y), (j, X))`, so `k_Y ≤ j < k`.
//! A witness's own settled index is therefore **strictly below** the claimant's, and a certificate is a
//! *tree* rather than a chain, of depth at most `k`. Its size obeys `T(k) ≤ k + Σ_{j<k} T(j)`, i.e.
//! `T(k) ≤ 2^k − 1`, and `k ≤ q` because a node that is rejected at every point of its line is not seated
//! at all. So:
//!
//! ```text
//!   plane      walk length   settle_index worst case   deferred worst case
//!   PG(2,2)         3               2 witnesses            3 claims
//!   PG(2,4)         5               4                     15
//!   PG(2,7)         8               7                    127
//! ```
//!
//! The worst case is not the cost, because most nodes sit at index 0 and carry no witnesses at all. The
//! measurement below is the distribution.
//!
//! # Result, 2026-08-21 — the objection does not survive: the change costs 0.005 witnesses per seat
//!
//! Witness objects a seated node must carry, at complete knowledge:
//!
//! ```text
//!   plane      n    walk    settle_index          deferred          seats carrying
//!                           mean     max        mean     max         nothing
//!   PG(2,2)     7     3     0.311      2       0.316      3           77.4 %
//!   PG(2,2)    16     3     0.104      2       0.104      3           91.4 %
//!   PG(2,2)    28     3     0.015      2       0.015      2           98.6 %
//!   PG(2,4)    21     5     0.520      4       0.554      8           72.8 %
//!   PG(2,4)    31     5     0.357      4       0.377      8           79.4 %
//!   PG(2,4)    84     5     0.020      3       0.020      3           98.2 %
//! ```
//!
//! **On the shipped plane at one node per point the mean goes from `0.311` to `0.316`** — one extra witness
//! object per two hundred seats — and the worst case from 2 to 3. At the sizing constant the two means are
//! equal to three decimals. `PG(2,4)` is the same story one plane up: `0.520 → 0.554`, worst case 4 → 8,
//! and the measured worst case is well inside the `2^k − 1` bound (15 at `k = 4`) because the tree
//! deduplicates and most witnesses sit at index 0 themselves.
//!
//! **Three quarters to ninety-nine per cent of seated nodes carry nothing at all.** A node at index 0 has no
//! skipped index to justify, under either rule, and at every load most nodes are at index 0 — which is also
//! why the mean is far below the worst case and why the worst case is the wrong number to design against.
//!
//! ⛔ **This refutes the last of the three objections to removing the phantom yield**, all three of them
//! stated in this tree's own code on 2026-08-21 and all three measured the same day:
//!
//! 1. *"it is worth nothing on a partial view"* — refuted: `PG(2,4)` at half the claims seen goes 9.3 % →
//!    40.3 % (`partial_knowledge_placement.rs`).
//! 2. *"a node can be told to move backwards"* — refuted: zero backward moves in twelve configurations,
//!    ≈ 30 000 draws, and Gale–Shapley's comparative static says it must be zero.
//! 3. *"checkable only by a verifier holding the whole claim set"* — refuted here. The certificate is a
//!    **bounded tree**, not the set: a witness's settled index is strictly below the claimant's, so the
//!    recursion terminates at depth `k ≤ q` and costs `2^k − 1` claims at worst and `0.005` more than
//!    today's flat list on average.
//!
//! What is left as a genuine price is the one thing that is not about proving a seat: **about a fifth more
//! doubly-held points while views disagree**, measured in `partial_knowledge_placement.rs`. That is a
//! transient of partial knowledge — both rules reach zero conflicts at complete knowledge — and it is what
//! a live measurement of the change would have to watch.
//!
//! Run: `cargo run -p fanos-vrf --example deferred_certificate_size --release`
// An example indexes its own fixed-size population by construction — the same allowance its two neighbours
// carry, and for the same reason.
#![allow(clippy::indexing_slicing)]

use fanos_geometry::Triple;
use fanos_vrf::{VrfOutput, claim_beats};
use std::collections::{BTreeMap, BTreeSet};

/// The deferred-acceptance assignment at complete knowledge: `point → (index, node)`.
///
/// The same Gale–Shapley `line_confinement_coverage.rs` runs, returned whole rather than counted, because a
/// certificate is built out of *who holds what* and not out of how many points are held.
fn assignment(walks: &[Vec<Triple>], ranks: &[VrfOutput]) -> BTreeMap<Triple, (u16, usize)> {
    let mut held: BTreeMap<Triple, (u16, usize)> = BTreeMap::new();
    let mut next: Vec<usize> = vec![0; walks.len()];
    let mut free: Vec<usize> = (0..walks.len()).collect();
    while let Some(i) = free.pop() {
        while next[i] < walks[i].len() {
            let k = next[i];
            next[i] += 1;
            let p = walks[i][k];
            let k = u16::try_from(k).unwrap_or(u16::MAX);
            match held.get(&p).copied() {
                None => {
                    held.insert(p, (k, i));
                    break;
                }
                Some((ck, ci)) => {
                    if claim_beats((k, &ranks[i]), (ck, &ranks[ci])) {
                        held.insert(p, (k, i));
                        free.push(ci);
                        break;
                    }
                }
            }
        }
    }
    held
}

/// The distinct claims a deferred-acceptance seat's certificate must carry, for the node seated at index
/// `seat` on `walks[i]`.
///
/// Every skipped index `j < seat` is justified by the **final holder** of `walks[i][j]` — which is what
/// makes this different from `settle_index`, where the justifier need only *want* the point. That holder's
/// own seat is justified the same way, so the walk down is a DAG and the count is of **distinct** nodes: a
/// witness reached twice is carried once.
fn certificate(
    i: usize,
    seat: u16,
    walks: &[Vec<Triple>],
    held: &BTreeMap<Triple, (u16, usize)>,
) -> BTreeSet<usize> {
    let mut carried = BTreeSet::new();
    let mut stack = vec![(i, seat)];
    while let Some((node, k)) = stack.pop() {
        for skipped in walks[node].iter().take(usize::from(k)) {
            let Some(&(wk, w)) = held.get(skipped) else {
                continue; // unreachable at complete knowledge; a skipped point is a held point
            };
            if carried.insert(w) {
                stack.push((w, wk));
            }
        }
    }
    carried
}

fn main() {
    use fanos_field::{F2, F4, Field};
    use fanos_primitives::{BeaconSeed, Epoch};
    use fanos_vrf::{VrfSecret, probe_point, prove_coordinate_ranked};

    let epoch = Epoch::new(9);
    let beacon = BeaconSeed::GENESIS;

    macro_rules! run {
        ($F:ty, $name:expr, $n:expr, $trials:expr) => {{
            let len = <$F as Field>::Q as usize + 1;
            let (mut seated, mut ship_sum, mut ship_max) = (0u64, 0u64, 0usize);
            let (mut def_sum, mut def_max, mut def_zero) = (0u64, 0usize, 0u64);
            for trial in 0..$trials {
                let ranks: Vec<VrfOutput> = (0..$n)
                    .map(|i| {
                        let mut seed = [0u8; 32];
                        seed[..8].copy_from_slice(&((trial * 1000 + i) as u64).to_le_bytes());
                        let sk = VrfSecret::from_seed(seed);
                        let id = format!("node-{}-{}", trial, i).into_bytes();
                        let (_, _, out) = prove_coordinate_ranked::<$F>(&sk, &id, epoch, &beacon);
                        out
                    })
                    .collect();
                let walks: Vec<Vec<Triple>> = (0..$n)
                    .map(|i| (0..len).map(|k| probe_point::<$F>(&ranks[i], k as u16).coords()).collect())
                    .collect();
                let held = assignment(&walks, &ranks);
                for (_, &(k, i)) in &held {
                    let cert = certificate(i, k, &walks, &held);
                    seated += 1;
                    // `settle_index`'s certificate is one witness per skipped index, flat: exactly `k`.
                    ship_sum += u64::from(k);
                    ship_max = ship_max.max(usize::from(k));
                    def_sum += cert.len() as u64;
                    def_max = def_max.max(cert.len());
                    def_zero += u64::from(cert.is_empty());
                }
            }
            let s = seated as f64;
            println!(
                "{:>9} n={:<3} walk={:<2} | seated {:>6} | settle_index mean {:.3} max {} | deferred mean \
                 {:.3} max {} | carry nothing {:>5.1}%",
                $name,
                $n,
                len,
                seated,
                ship_sum as f64 / s,
                ship_max,
                def_sum as f64 / s,
                def_max,
                100.0 * def_zero as f64 / s,
            );
        }};
    }

    println!("What a seat costs to prove — witness objects per seated node, complete knowledge\n");
    run!(F2, "PG(2,2)", 7, 4000);
    run!(F2, "PG(2,2)", 16, 2000);
    run!(F2, "PG(2,2)", 28, 1000);
    run!(F4, "PG(2,4)", 21, 400);
    run!(F4, "PG(2,4)", 31, 400);
    run!(F4, "PG(2,4)", 84, 200);
}
