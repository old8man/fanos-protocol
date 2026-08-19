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
//! This is that question with the cell taken out of it: the shipping arbitration, at complete knowledge, in
//! one shot. `settle_index` is order-independent given the contending claims, so this is not a simulation of
//! a protocol run — it is the **fixed point** such a run converges to, and therefore the ceiling. A live cell
//! cannot beat it; the distance between the two is what mechanism can still buy.
//!
//! ## Result, 2026-08-19 — the live cell is already AT this ceiling, and the tree's sizing table is not
//!
//! | load | `PG(2,2)` clears the floor | unseated | `PG(2,4)` | unseated |
//! |---|---|---|---|---|
//! | `1.0 N` | 32.7 % | 1.8 of 7 | 0.0 % | 5.5 of 21 |
//! | `1.5 N` — what the constant used to be | 74.5 % | 4.1 of 10 | 7.5 % | 13.0 of 31 |
//! | `2 N` | 93.8 % | 7.5 of 14 | 51.8 % | 22.5 of 42 |
//! | **the constant** (16 / 84) | **96.6 %** | **9.4 of 16** | **98.0 %** | **63.2 of 84** |
//! | `3 N` | 99.4 % | 14.2 of 21 | 90.5 % | 42.6 of 63 |
//!
//! **The `unseated` column is the price and it is severe.** At the load a deployment is sized to,
//! **59 %** of a Fano cell's members hold no seat at any given moment, and **75 %** of a `PG(2,4)` cell's.
//! They are not idle by accident: they are the draw's spare candidates, and what they buy is the coverage
//! column beside them. But production sets `hier_path: None` everywhere, so there is no sub-cell for them to
//! be in — they are simply unaddressable. `addressing-capacity-is-not-serving-capacity` put this at "about a
//! third"; measured at the corrected sizing it is well over half.
//!
//! **Two things follow, and the first closes an investigation.** `fanos_sim`'s live cell reads **75 %** at
//! `1.5 N` on `PG(2,2)`; the ceiling here is **74.5 %**. The running mechanism is at its geometric limit, so
//! the below-floor share is not a defect in placement — knowledge, permission and time were each measured
//! and refuted, and this is what was left.
//!
//! **The second is that `members_for_a_covered_plane`'s own table does not reproduce.** It records 99.7 %
//! and 99.2 % at `1.5 N` for these two planes against the 74.5 % and 7.5 % measured here through the
//! shipping arbitration. One candidate explanation was tested and **refuted**: counting each node's
//! *preferred* point rather than its settled one — the mistake `fanos_sim::fabric`'s sizing measurement
//! records making — gives *lower* coverage (50.5 % at `1.5 N`), not higher. The table's method is not
//! reproducible from its description, and two independent measurements agree with each other against it.
//!
//! **And the required load is not a constant multiple of `N`.** Coverage at a fixed multiple *falls* as the
//! plane grows (74.5 % against 7.5 % at the same `1.5 N`), which is the coupon-collector shape: covering
//! `N − d` of `N` points costs about `N·(H(N) − H(d))` draws, and that is `≈ 1.6 N` on Fano against
//! `≈ 2.6 N` on `PG(2,4)`. A single ratio cannot serve both planes.
//!
//! Run: `cargo run -p fanos-vrf --example line_confinement_coverage --release`
// An example indexes its own fixed-size population by construction — the same allowance
// `unprovable_displacement.rs` carries, and for the same reason: every index here is a loop bound over a
// vector built one line above it.
#![allow(clippy::indexing_slicing)]

fn main() {
    use fanos_field::{F2, F4, Field};
    use fanos_geometry::{Plane, Point, points_serving_every_line};
    use fanos_primitives::{BeaconSeed, Epoch};
    use fanos_vrf::{
        VrfOutput, VrfSecret, claim_beats, probe_index_of, probe_point, prove_coordinate_ranked, settle_index,
    };
    use std::collections::HashSet;

    let epoch = Epoch::new(9);
    let beacon = BeaconSeed::GENESIS;

    macro_rules! run {
        ($F:ty, $name:expr, $n:expr, $trials:expr) => {{
            let floor = points_serving_every_line(<$F as Field>::Q as usize + 1);
            let (mut cleared, mut pts_total, mut unseated) = (0u64, 0u64, 0u64);
            let (mut pref_cleared, mut pref_total) = (0u64, 0u64);
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
                "{:>9} n={:<3} N={:<3} floor={:<3}  SETTLED points {:>5.2} clears {:>5.1}%   \
                 preferred-only {:>5.2} clears {:>5.1}%   unseated/trial {:.2}",
                $name,
                $n,
                Plane::<$F>::N,
                floor,
                pts_total as f64 / $trials as f64,
                100.0 * cleared as f64 / $trials as f64,
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
