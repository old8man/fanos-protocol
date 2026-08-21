//! **Can line-confined probing cover the plane at all?** — the ceiling the live cell is measured against.
//!
//! `fanos_sim`'s `measure_whether_the_shipped_fano_plane_stays_packed_across_a_boundary` reads a `PG(2,2)`
//! cell **below its line-viability floor in 25 % of samples** at the sized load, and three separate
//! candidate causes have been measured and refuted: knowledge (the claim book is complete at genesis and
//! refills every epoch), permission (a contested seat is no longer committed), and time (three times the
//! epoch's margin over the walk buys nothing).
//!
//! What has not been tested is the **geometry**. `probe_point` confines a node to the `q + 1` points of one
//! line through its preferred point — 3 of 7 on the Fano plane — and its own doc records that a plane-wide
//! walk was built, measured and reverted for a stated security reason (*"it would reopen the steering
//! primitive line restriction exists to remove"*). So a draw can leave a point that **no contender can
//! reach**, whatever the mechanism does.
//!
//! This is that question with the cell taken out of it: every rule below runs at complete knowledge, in one
//! shot. `settle_index` is order-independent given the contending claims, so its column is not a simulation
//! of a protocol run — it is the **fixed point** such a run converges to, and therefore the ceiling **of
//! that rule**. A live cell cannot beat it; the distance between the live cell and it is what *mechanism*
//! can buy, and the distance between it and the two columns beside it is what a *different rule* would.
//!
//! That distinction is the whole correction of 2026-08-21. The first version of this file had only the
//! first column and read its ceiling as the geometry's; the geometry is now measured beside it and is
//! nowhere near.
//!
//! ## Result, 2026-08-21 — line confinement is NOT the binding constraint; the arbitration rule is
//!
//! The first version of this example measured one rule and called its ceiling "the geometry". It is not.
//! Three rules now run on **the same draws and the same shipping walks**, so the columns are differences of
//! one thing at a time:
//!
//! * **SHIPPING** — `settle_index` at complete knowledge, exactly as before.
//! * **DEFERRED** — the same walks and the same `claim_beats` order, with one change: a point is held only
//!   by a node that actually *proposes* to it, so a node already seated at an earlier index stops blocking
//!   points further down its own walk. This is Gale–Shapley, and by the Rural Hospitals theorem every
//!   stable matching of these preferences has this size, so it is a property of the preferences and not of
//!   the proposal order.
//! * **CEILING** — a bipartite maximum matching over the same admissible sets, with no arbitration at all.
//!   What line confinement *alone* permits. Nothing can beat it.
//!
//! ```text
//!   plane      load          SHIPPING          DEFERRED           CEILING
//!   PG(2,2)    n=7  (1.0N)   5.16   32.7 %     5.98   80.5 %      6.82   99.1 %
//!   PG(2,2)    n=10 (1.5N)   5.95   74.5 %     6.76   99.2 %      6.97  100.0 %
//!   PG(2,2)    n=14 (2N)     6.47   93.8 %     6.97  100.0 %      7.00  100.0 %
//!   PG(2,2)    n=16 (const)  6.62   96.6 %     6.99  100.0 %      7.00  100.0 %
//!   PG(2,4)    n=21 (1.0N)  15.53    0.0 %    18.52   14.2 %     20.91   99.5 %
//!   PG(2,4)    n=31 (1.5N)  18.03    7.5 %    20.71   97.5 %     21.00  100.0 %
//!   PG(2,4)    n=42 (2N)    19.46   51.8 %    20.98  100.0 %     21.00  100.0 %
//!   PG(2,4)    n=84 (const) 20.81   98.0 %    21.00  100.0 %     21.00  100.0 %
//! ```
//!
//! **The geometry almost never binds.** At one node per point the ceiling clears the viability floor in
//! **99.1 %** of Fano draws and **99.5 %** of `PG(2,4)` draws. A draw that leaves a point no contender can
//! reach — the thing this example was built to look for — is a **1-in-100** event, not the explanation for
//! anything.
//!
//! **What binds is the phantom yield.** `settle_index` honours a contender's claim to `p` whether or not
//! that contender ends up on `p`; a node seated at index 0 still displaces everyone from the two points
//! further along its own walk. Removing exactly that — nothing else, same order, same walks — moves
//! `PG(2,4)` at `1.5 N` from **7.5 % to 97.5 %**, and Fano at one node per point from **32.7 % to 80.5 %**.
//!
//! ⛔ **This supersedes the conclusion the file carried until 2026-08-21**, which read *"the running
//! mechanism is at its geometric limit, so the below-floor share is not a defect in placement"*. The first
//! half is true and the second does not follow: the live cell is at **this rule's** limit, and that limit is
//! far below the geometry's. Knowledge, permission and time were each measured and refuted — correctly —
//! and the conclusion drawn from what was left named the wrong survivor.
//!
//! **What it costs a deployment.** `members_for_a_covered_plane` returns `84` for `PG(2,4)` — four times the
//! plane, with 75 % of members holding no seat — and the row above says `31` would do under deferred
//! acceptance. The phantom yield is therefore worth about **2.7× a cell's membership**, which is the price
//! of the property it buys: `settle_index` is verifiable without recursion, because the predicate that moves
//! a node never asks where anyone else *ended up*. That price was recorded on `settle_index` as **0.8 %**,
//! measured at `PG(2,7)` load `0.53`, and it is not the price at the loads a deployment actually runs.
//!
//! **What removing it would require, and why it is not a small change.** Deferred acceptance is a fixed
//! point of the whole claim set, so a node's seat is checkable only by someone holding that set — which is
//! precisely what cell-wide claim propagation delivers, and which today reaches only direct connection
//! partners. The two are one work item, not two. And `settle_index`'s *monotone in information* property
//! does not survive: under this rule a node that learns of a new peer can be told to move **backwards**,
//! where today it only ever advances to a position it can prove. That regression is unmeasured, and this
//! example measures the complete-knowledge fixed point only — it says what the change is worth, not that
//! the change is safe.
//!
//! **And the required load is not a constant multiple of `N`.** Coverage at a fixed multiple *falls* as the
//! plane grows (74.5 % against 7.5 % at the same `1.5 N` under the shipping rule), which is the
//! coupon-collector shape: covering `N − d` of `N` points costs about `N·(H(N) − H(d))` draws, and that is
//! `≈ 1.6 N` on Fano against `≈ 2.6 N` on `PG(2,4)`. A single ratio cannot serve both planes. Note that this
//! is a statement about the shipping rule: under deferred acceptance `1.5 N` clears both planes.
//!
//! **The preferred-only column stays** for the reason it was added: it is the tree's likely method for the
//! table this example refuted, it over-reports by counting seats nobody holds, and it reads *lower* than the
//! shipping rule anyway.
//!
//! Run: `cargo run -p fanos-vrf --example line_confinement_coverage --release`
// An example indexes its own fixed-size population by construction — the same allowance
// `unprovable_displacement.rs` carries, and for the same reason: every index here is a loop bound over a
// vector built one line above it.
#![allow(clippy::indexing_slicing)]

use fanos_geometry::Triple;
use fanos_vrf::{VrfOutput, claim_beats};
use std::collections::{BTreeMap, HashMap, HashSet};

/// One augmenting step of Kuhn's algorithm: try to seat node `i` on some point of `adj[i]`, displacing the
/// node already there if *it* can be re-seated. Standard bipartite maximum matching; the plane is 7 or 21
/// points so the cubic worst case is irrelevant and Hopcroft–Karp would only be harder to read.
///
/// This is the **only** rule here that is not the shipping one, and deliberately so: it is what line
/// confinement alone permits, with no arbitration at all — an oracle that sees every draw at once and
/// assigns seats to maximise occupancy. Nothing can beat it, so the distance from it is the whole of what
/// *any* placement mechanism could still buy.
/// **Deferred acceptance** over the shipping walks and the shipping order — the one rule change this file
/// exists to price. A point is held only by a node that actually *proposes* to it, so a node already seated
/// at an earlier index stops blocking the points further down its own walk (the *phantom yield*). The
/// point's preference is `claim_beats`, unchanged, and the proposer's is its walk order, unchanged.
///
/// Gale–Shapley terminates because each node proposes to each of its `q + 1` points at most once. By the
/// Rural Hospitals theorem every stable matching of these preferences seats the same number of nodes, so the
/// figure is a property of the draw and not of the order this loop happens to pop `free` in.
fn deferred_acceptance(walks: &[Vec<Triple>], ranks: &[VrfOutput]) -> usize {
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
    held.len()
}

/// **The geometric ceiling**: a bipartite maximum matching over the same admissible sets, with no
/// arbitration rule at all — what line confinement *alone* permits.
fn maximum_matching(walks: &[Vec<Triple>]) -> usize {
    let mut matched: HashMap<Triple, usize> = HashMap::new();
    for i in 0..walks.len() {
        augment(i, walks, &mut HashSet::new(), &mut matched);
    }
    matched.len()
}

fn augment(i: usize, adj: &[Vec<Triple>], seen: &mut HashSet<Triple>, matched: &mut HashMap<Triple, usize>) -> bool {
    for &p in &adj[i] {
        if !seen.insert(p) {
            continue;
        }
        let taken = matched.get(&p).copied();
        let free = match taken {
            None => true,
            Some(j) => augment(j, adj, seen, matched),
        };
        if free {
            matched.insert(p, i);
            return true;
        }
    }
    false
}

fn main() {
    use fanos_field::{F2, F4, Field};
    use fanos_geometry::{Plane, Point, points_serving_every_line};
    use fanos_primitives::{BeaconSeed, Epoch};
    use fanos_vrf::{VrfSecret, probe_index_of, probe_point, prove_coordinate_ranked, settle_index};

    let epoch = Epoch::new(9);
    let beacon = BeaconSeed::GENESIS;

    macro_rules! run {
        ($F:ty, $name:expr, $n:expr, $trials:expr) => {{
            let floor = points_serving_every_line(<$F as Field>::Q as usize + 1);
            let (mut cleared, mut pts_total, mut unseated) = (0u64, 0u64, 0u64);
            let (mut pref_cleared, mut pref_total) = (0u64, 0u64);
            let (mut stable_cleared, mut stable_pts) = (0u64, 0u64);
            let (mut max_cleared, mut max_pts) = (0u64, 0u64);
            for trial in 0..$trials {
                // The same draw the neighbouring example uses: a distinct secret and identity per node, so
                // the outputs are real VRF outputs rather than sampled points — the walk's line and stride
                // are derived from them, and a model that skipped that would be measuring a different
                // mechanism.
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
                // The library's own contender oracle and arbitration — a local copy would not be a
                // measurement of what runs.
                let best = |i: usize, p: &Point<$F>| -> Option<(u16, VrfOutput)> {
                    (0..$n)
                        .filter(|&w| w != i)
                        .filter_map(|w| probe_index_of::<$F>(&ranks[w], p).map(|k| (k, ranks[w])))
                        .reduce(|a, b| if claim_beats((b.0, &b.1), (a.0, &a.1)) { b } else { a })
                };
                let seats: Vec<Option<u16>> =
                    (0..$n).map(|i| settle_index::<$F>(&ranks[i], |p| best(i, p))).collect();
                let occupied: HashSet<_> = (0..$n)
                    .filter_map(|i| seats[i].map(|k| probe_point::<$F>(&ranks[i], k).coords()))
                    .collect();
                // **The same count made the way that over-reports it**, carried beside the real one because
                // a number this far from the tree's own table needs the table's likely method beside it. An
                // unseated node still *has* a preferred point; folding that in counts a seat nobody holds,
                // which is the exact mistake `fanos_sim::fabric`'s sizing measurement records having made on
                // its first run ("distinct + unbound > n, which is the arithmetic saying so").
                let preferred: HashSet<_> =
                    (0..$n).map(|i| probe_point::<$F>(&ranks[i], 0).coords()).collect();
                // ---- the two REFERENCE rules, on this same draw ----
                //
                // The walks first, since both need them and both must read the SHIPPING walk rather than a
                // model of it: `probe_point` is the function under study, not a stand-in for it.
                let len = <$F as Field>::Q as usize + 1;
                let walks: Vec<Vec<Triple>> = (0..$n)
                    .map(|i| (0..len).map(|k| probe_point::<$F>(&ranks[i], k as u16).coords()).collect())
                    .collect();
                let deferred = deferred_acceptance(&walks, &ranks);
                stable_pts += deferred as u64;
                if deferred >= floor {
                    stable_cleared += 1;
                }
                let ceiling = maximum_matching(&walks);
                max_pts += ceiling as u64;
                if ceiling >= floor {
                    max_cleared += 1;
                }

                unseated += seats.iter().filter(|s| s.is_none()).count() as u64;
                pts_total += occupied.len() as u64;
                pref_total += preferred.len() as u64;
                if occupied.len() >= floor {
                    cleared += 1;
                }
                if preferred.len() >= floor {
                    pref_cleared += 1;
                }
            }
            println!(
                "{:>9} n={:<3} N={:<3} floor={:<3} | SHIPPING {:>5.2} pts {:>5.1}% | DEFERRED {:>5.2} pts \
                 {:>5.1}% | CEILING {:>5.2} pts {:>5.1}% | preferred-only {:>5.2} {:>5.1}% | unseated {:.2}",
                $name,
                $n,
                Plane::<$F>::N,
                floor,
                pts_total as f64 / $trials as f64,
                100.0 * cleared as f64 / $trials as f64,
                stable_pts as f64 / $trials as f64,
                100.0 * stable_cleared as f64 / $trials as f64,
                max_pts as f64 / $trials as f64,
                100.0 * max_cleared as f64 / $trials as f64,
                pref_total as f64 / $trials as f64,
                100.0 * pref_cleared as f64 / $trials as f64,
                unseated as f64 / $trials as f64
            );
        }};
    }

    println!("Line-confined probing at complete knowledge — the ceiling, not a run\n");
    // `N`, `1.5N` (the shipped sizing constant), `2N`, `3N`, `4N` — the curve rather than a point, because
    // the constant this is checked against is a *choice of load factor* and only a curve can price one.
    run!(F2, "PG(2,2)", 7, 4000);
    run!(F2, "PG(2,2)", 10, 4000);
    run!(F2, "PG(2,2)", 14, 4000);
    // The constant itself, so the row a deployment is sized against is in the table rather than inferred
    // from its neighbours — and so the price in unseated members is stated where the recommendation is.
    run!(F2, "PG(2,2)", 16, 4000);
    run!(F2, "PG(2,2)", 21, 4000);
    run!(F2, "PG(2,2)", 28, 2000);
    run!(F4, "PG(2,4)", 21, 400);
    run!(F4, "PG(2,4)", 31, 400);
    run!(F4, "PG(2,4)", 42, 400);
    run!(F4, "PG(2,4)", 63, 200);
    run!(F4, "PG(2,4)", 84, 200);
}
