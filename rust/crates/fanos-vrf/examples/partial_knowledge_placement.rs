//! **What the two placement rules do when a node cannot see every claim** — the half
//! `line_confinement_coverage.rs` deliberately does not measure.
//!
//! That example runs both rules at *complete* knowledge and prices the difference: removing the phantom
//! yield takes `PG(2,4)` at `1.5 N` from 7.5 % to 97.5 % of draws clearing the line-viability floor. It also
//! says, twice, that the figure is not a licence to change the rule — because `settle_index` has a property
//! deferred acceptance does not, and a complete-knowledge measurement cannot see it:
//!
//! > **Monotone in information.** A node that has seen fewer peers may settle too early and later advance —
//! > a convergence question, not a correctness one, since every intermediate position is one it can prove.
//!
//! A live cell is never at complete knowledge. `fano-unpacks-below-its-own-floor` measured the claim book at
//! **3.0 of 6 peers** at `n = 7` and 6.0 of 9 at `n = 10` — so `φ ≈ 0.5` is not a pessimistic corner, it is
//! the reading. This example is that regime, for both rules, on the same draws and the same walks.
//!
//! # What is measured, and why these three
//!
//! Each node sees a uniformly random **symmetric** subset of the others (claims arrive over direct
//! connections, and a connection is two-way), then settles on its own view alone.
//!
//! * **occupied** — distinct points actually taken. The quantity the floor is read against.
//! * **conflicts** — points taken by two or more nodes. Both rules are injective at complete knowledge;
//!   under a partial view either can seat two nodes on one point, and that is a correctness hazard rather
//!   than a coverage one ([[two-bound-nodes-on-one-point]] is the live version of it).
//! * **backward moves** — nodes whose settled index is *lower* on the full view than on the partial one.
//!   For `settle_index` this must be **zero**, by the monotonicity above; the column is therefore also the
//!   harness's own check, and a non-zero SHIPPING entry would mean this file is measuring something else.
//!
//! # Result, 2026-08-21 — the regression this was built to find does not exist
//!
//! ```text
//!                        SHIPPING                              DEFERRED
//!   plane   n   phi   occ  clears  confl  back  fwd     occ  clears  confl  back   fwd
//!   PG(2,2)  7  0.25  4.86  20.0%   1.61  0.00  1.97   4.99   24.6%   1.71  0.00   2.05
//!   PG(2,2)  7  0.50  5.03  26.5%   1.20  0.00  1.41   5.33   41.0%   1.40  0.00   1.57
//!   PG(2,2)  7  0.75  5.11  30.4%   0.64  0.00  0.73   5.66   60.5%   0.84  0.00   0.88
//!   PG(2,2)  7  1.00  5.16  32.7%   0.00  0.00  0.00   5.98   80.5%   0.00  0.00   0.00
//!   PG(2,2) 16  0.25  6.62  96.5%   4.67  0.00  7.31   6.77   99.0%   5.16  0.00   8.58
//!   PG(2,2) 16  0.50  6.63  97.2%   3.36  0.00  4.17   6.89   99.7%   4.19  0.00   5.53
//!   PG(2,2) 16  0.75  6.61  96.3%   1.59  0.00  1.70   6.92  100.0%   2.08  0.00   2.27
//!   PG(2,2) 16  1.00  6.60  96.3%   0.00  0.00  0.00   6.99  100.0%   0.00  0.00   0.00
//!   PG(2,4) 31  0.25 17.49   6.0%   9.03  0.00 12.81  17.80    9.3%   9.59  0.00  13.68
//!   PG(2,4) 31  0.50 17.93   9.3%   6.82  0.00  8.51  19.12   40.3%   8.82  0.00  11.26
//!   PG(2,4) 31  0.75 17.99   9.3%   3.37  0.00  3.85  19.96   75.0%   5.30  0.00   6.06
//!   PG(2,4) 31  1.00 18.02   7.7%   0.00  0.00  0.00  20.71   97.7%   0.00  0.00   0.00
//! ```
//!
//! The `φ = 1.00` rows reproduce `line_confinement_coverage.rs` to the decimal, which is the control that
//! these are the same draws. It has already earned its keep: the first draft passed `φ` as a `u8`, `1.00`
//! wrapped to `0`, and the control row read "nobody sees anybody" instead of matching.
//!
//! ## ⛔ `backward` is zero in every row, and that refutes a claim made earlier the same day
//!
//! `line_confinement_coverage.rs`, `fanos_vrf::settle_index`'s own doc and `docs/testnet.md` §1 all said
//! that deferred acceptance gives up *monotone in information* — that a node learning of a new peer could be
//! told to move **backwards**. It cannot. `fwd` reaches **13.68 nodes per trial**, so the extra knowledge
//! plainly moves people; `back` is **0.00** in all twelve rows, both rules, ≈ 30 000 trials.
//!
//! And it is not luck. Gale–Shapley's own comparative static says so: adding an agent to the **proposing**
//! side weakly worsens every other proposer's outcome in the proposer-optimal stable matching. A node's
//! preference order *is* its walk order, so "weakly worse" is "at the same index or further along" —
//! exactly the property `settle_index` was credited with as a distinguishing one. It is not distinguishing.
//! Two derivations, one number: the theorem and the twelve rows.
//!
//! ## What the rule change does cost, measured
//!
//! **Conflicted points, by about a fifth.** At `φ = 0.5`: `1.40` against `1.20` on Fano, `8.82` against
//! `6.82` on `PG(2,4)`. The mechanism is not subtle — deferred acceptance seats *more* nodes on a partial
//! view, and a node seated on a stale view is a node that can be seated on someone else's point
//! ([[two-bound-nodes-on-one-point]]). Both rules go to zero conflicts at `φ = 1`, so this is a cost of
//! partial knowledge and not of the rule, but the rule pays more of it.
//!
//! **Verification.** Unchanged by this file and still the real obstacle: a deferred-acceptance seat is a
//! fixed point of the whole claim set, so it is checkable by recomputation from that set and not from a
//! witness chain. `settle_index` needs at most `q + 1` witnesses and nothing else.
//!
//! ## The row that decides what to build first
//!
//! Read `SHIPPING clears` down the `PG(2,4)` block: **6.0 %, 9.3 %, 9.3 %, 7.7 %**. Quadrupling what a node
//! knows buys three points and then gives one back. Read `DEFERRED` beside it: **9.3 %, 40.3 %, 75.0 %,
//! 97.7 %**. Cell-wide claim propagation — the open item this analysis started from — is worth almost
//! nothing under the rule that ships and almost everything under the rule beside it, because the phantom
//! yield converts each new claim into a fresh reason to move rather than a seat. The two are one work item
//! and this is the row that says so.
//!
//! Run: `cargo run -p fanos-vrf --example partial_knowledge_placement --release`
// An example indexes its own fixed-size population by construction — the same allowance
// `line_confinement_coverage.rs` carries, and for the same reason.
#![allow(clippy::indexing_slicing)]

use fanos_geometry::Triple;
use fanos_vrf::{VrfOutput, claim_beats, probe_index_of, probe_point, settle_index};
use std::collections::BTreeMap;

/// A deterministic bit for the pair `(i, j)`, `i < j` — whether these two nodes can see each other's claim.
///
/// Derived from a hash rather than an RNG so a row of this table is reproducible on its own, and symmetric
/// by construction because the caller orders the pair. `φ` is expressed in 1/256ths, which is finer than any
/// claim this file makes — and the parameter is a `u16` because the interesting end of the range is `256`,
/// "everyone", which does not fit in the `u8` the digest byte is compared against. It fitted in the first
/// draft, wrapped to zero, and turned the `φ = 1.00` control into "nobody sees anybody". The control caught
/// it: that row is supposed to reproduce `line_confinement_coverage.rs` and did not.
fn visible(trial: usize, i: usize, j: usize, phi_256: u16) -> bool {
    let (a, b) = if i < j { (i, j) } else { (j, i) };
    let mut msg = [0u8; 24];
    msg[..8].copy_from_slice(&(trial as u64).to_le_bytes());
    msg[8..16].copy_from_slice(&(a as u64).to_le_bytes());
    msg[16..].copy_from_slice(&(b as u64).to_le_bytes());
    let d = fanos_primitives::hash::hash_labeled("FANOS/example/visibility", &msg);
    u16::from(d[0]) < phi_256
}

/// `settle_index` over a restricted contender set — the shipping rule, exactly, with the oracle narrowed to
/// what node `i` can see. Narrowing the oracle rather than the rule is the whole point: the rule is not
/// being modelled here, it is being called.
fn shipping_seat<F: fanos_field::Field>(i: usize, ranks: &[VrfOutput], seen: &[Vec<usize>]) -> Option<u16> {
    settle_index::<F>(&ranks[i], |p| {
        seen[i]
            .iter()
            .filter_map(|&w| probe_index_of::<F>(&ranks[w], p).map(|k| (k, ranks[w])))
            .reduce(|a, b| if claim_beats((b.0, &b.1), (a.0, &a.1)) { b } else { a })
    })
}

/// Deferred acceptance over the sub-instance node `i` can see, returning **`i`'s own** seat index.
///
/// A node running this rule must compute the whole assignment of its view and then read its own row out of
/// it — which is the operational difference from `settle_index` and the reason the rule needs the claim
/// *set*, not a claim at a time.
fn deferred_seat(i: usize, walks: &[Vec<Triple>], ranks: &[VrfOutput], seen: &[Vec<usize>]) -> Option<u16> {
    let party: Vec<usize> = core::iter::once(i).chain(seen[i].iter().copied()).collect();
    let mut held: BTreeMap<Triple, (u16, usize)> = BTreeMap::new();
    let mut next: BTreeMap<usize, usize> = party.iter().map(|&w| (w, 0)).collect();
    let mut free: Vec<usize> = party.clone();
    while let Some(w) = free.pop() {
        while next[&w] < walks[w].len() {
            let k = next[&w];
            next.insert(w, k + 1);
            let p = walks[w][k];
            let k = u16::try_from(k).unwrap_or(u16::MAX);
            match held.get(&p).copied() {
                None => {
                    held.insert(p, (k, w));
                    break;
                }
                Some((ck, cw)) => {
                    if claim_beats((k, &ranks[w]), (ck, &ranks[cw])) {
                        held.insert(p, (k, w));
                        free.push(cw);
                        break;
                    }
                }
            }
        }
    }
    held.values().find_map(|&(k, w)| (w == i).then_some(k))
}

/// Occupied points, conflicted points, and unseated nodes for one assignment.
fn tally(seats: &[Option<u16>], walks: &[Vec<Triple>]) -> (usize, usize, usize) {
    let mut on: BTreeMap<Triple, usize> = BTreeMap::new();
    let mut unseated = 0;
    for (i, seat) in seats.iter().enumerate() {
        match seat {
            Some(k) => *on.entry(walks[i][usize::from(*k)]).or_default() += 1,
            None => unseated += 1,
        }
    }
    (on.len(), on.values().filter(|&&c| c > 1).count(), unseated)
}

fn main() {
    use fanos_field::{F2, F4, Field};
    use fanos_geometry::points_serving_every_line;
    use fanos_primitives::{BeaconSeed, Epoch};
    use fanos_vrf::{VrfSecret, prove_coordinate_ranked};

    let epoch = Epoch::new(9);
    let beacon = BeaconSeed::GENESIS;

    macro_rules! run {
        ($F:ty, $name:expr, $n:expr, $phi:expr, $trials:expr) => {{
            let floor = points_serving_every_line(<$F as Field>::Q as usize + 1);
            let len = <$F as Field>::Q as usize + 1;
            let mut acc = [[0u64; 5]; 2]; // [rule][occupied, cleared, conflicts, backward, forward]
            for trial in 0..$trials {
                // The same draw `line_confinement_coverage.rs` uses, so the two files' rows are comparable.
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
                let phi_256 = ((($phi) * 256.0) as u32).min(256) as u16;
                let seen: Vec<Vec<usize>> = (0..$n)
                    .map(|i| (0..$n).filter(|&j| j != i && visible(trial, i, j, phi_256)).collect())
                    .collect();
                let all: Vec<Vec<usize>> = (0..$n).map(|i| (0..$n).filter(|&j| j != i).collect()).collect();

                let part: [Vec<Option<u16>>; 2] = [
                    (0..$n).map(|i| shipping_seat::<$F>(i, &ranks, &seen)).collect(),
                    (0..$n).map(|i| deferred_seat(i, &walks, &ranks, &seen)).collect(),
                ];
                let full: [Vec<Option<u16>>; 2] = [
                    (0..$n).map(|i| shipping_seat::<$F>(i, &ranks, &all)).collect(),
                    (0..$n).map(|i| deferred_seat(i, &walks, &ranks, &all)).collect(),
                ];
                for r in 0..2 {
                    let (occ, conf, _) = tally(&part[r], &walks);
                    acc[r][0] += occ as u64;
                    acc[r][1] += u64::from(occ >= floor);
                    acc[r][2] += conf as u64;
                    // A node moves BACKWARD when knowing more puts it EARLIER in its own walk. Unseated
                    // counts as past the end of the walk, so gaining a seat is a backward move too — and it
                    // is the same event: a position the node had already left is handed back to it.
                    let moves = |cmp: fn(usize, usize) -> bool| {
                        (0..$n)
                            .filter(|&i| {
                                let p = part[r][i].map_or(usize::MAX, usize::from);
                                let f = full[r][i].map_or(usize::MAX, usize::from);
                                cmp(f, p)
                            })
                            .count() as u64
                    };
                    acc[r][3] += moves(|f, p| f < p);
                    // Counted beside it so `backward 0.00` cannot be read as "the view changes nothing":
                    // these are the nodes the extra knowledge DID move, all of them the other way.
                    acc[r][4] += moves(|f, p| f > p);
                }
            }
            let t = $trials as f64;
            println!(
                "{:>9} n={:<3} phi={:<4.2} | SHIPPING occ {:>5.2} clears {:>5.1}% conflict {:>4.2} back \
                 {:>4.2} fwd {:>4.2} | DEFERRED occ {:>5.2} clears {:>5.1}% conflict {:>4.2} back {:>4.2} \
                 fwd {:>4.2}",
                $name,
                $n,
                $phi,
                acc[0][0] as f64 / t,
                100.0 * acc[0][1] as f64 / t,
                acc[0][2] as f64 / t,
                acc[0][3] as f64 / t,
                acc[0][4] as f64 / t,
                acc[1][0] as f64 / t,
                100.0 * acc[1][1] as f64 / t,
                acc[1][2] as f64 / t,
                acc[1][3] as f64 / t,
                acc[1][4] as f64 / t,
            );
        }};
    }

    println!("Placement on a partial view — the regime a live cell is actually in\n");
    // `φ = 0.5` is the measured claim book (3.0 of 6 peers at n = 7); 0.25 and 0.75 bracket it and 1.0
    // reproduces `line_confinement_coverage.rs`, which is the cross-check that these are the same draws.
    for phi in [0.25, 0.50, 0.75, 1.00] {
        run!(F2, "PG(2,2)", 7, phi, 4000);
    }
    for phi in [0.25, 0.50, 0.75, 1.00] {
        run!(F2, "PG(2,2)", 16, phi, 2000);
    }
    for phi in [0.25, 0.50, 0.75, 1.00] {
        run!(F4, "PG(2,4)", 31, phi, 300);
    }
}
