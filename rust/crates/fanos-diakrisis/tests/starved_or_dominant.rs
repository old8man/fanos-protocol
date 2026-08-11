//! Can the cell tell a **starved** node from a **dominant** one? (UHM `bccc3d7`, "Two diseases, one dose")
//!
//! # The question the theory forced
//!
//! UHM's second wave separates two illnesses that had been one: *deprivation* and *mismatch*. Its stress
//! syndrome — parity of channel tensions — detects mismatch and **stays silent on consented hunger**: a
//! body that has fully accepted poor food produces no tension. What wakes the organ instead is a
//! *dietary* detector, "a chronically starved **diagonal**", and the cure it prescribes is addressed:
//! the syndrome names the hungry **axis** and one specialised donor feeds it (`1ea2b27`, #139 condition 4).
//!
//! FANOS's diagonal is [`CoherenceMatrix`]'s activity-share vector `d` — per-node behavioural variance,
//! normalised. Every public reading of it is [`CoherenceMatrix::diagonal_purity`], the scalar
//! `p = Σᵢ dᵢ²`. A scalar cannot carry an address, and this file asks the sharper question: does it even
//! carry the *illness*?
//!
//! `p` rises when weight concentrates — and weight concentrates in **both** diseases. One node starving
//! raises it, and one node dominating raises it. Those two want opposite treatments: feed the first,
//! decouple the second. So the question is whether FANOS's instrument set can separate them at all.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use fanos_diakrisis::coherence::CoherenceMatrix;

/// The Fano cell.
const N: usize = 7;
/// Samples per node — far above the estimator noise of the effects being separated.
const T: usize = 16384;

/// A deterministic pseudo-signal; the answer must not move between machines.
fn noise(seed: u64, len: usize) -> Vec<f64> {
    let mut s = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..len)
        .map(|_| {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            f64::from((s >> 32) as u32) / f64::from(u32::MAX) * 2.0 - 1.0
        })
        .collect()
}

/// A cell where every node shares one common mode at `lambda`, but node 0's signal is scaled by `amp`.
///
/// Scaling amplitude moves node 0's **variance**, which is exactly what `from_signals` turns into its
/// activity share — and it leaves every *correlation* untouched, because Pearson divides the scale out.
/// So `amp < 1` is a starved node and `amp > 1` a dominant one, on an otherwise identical cell. That is
/// the control: the two worlds differ in the diagonal and in nothing else.
fn cell_with_node0_amplitude(lambda: f64, amp: f64) -> CoherenceMatrix {
    let shared = noise(0x00C0_FFEE, T);
    let signals: Vec<Vec<f64>> = (0..N)
        .map(|i| {
            let own = noise(0x5EED + i as u64, T);
            let scale = if i == 0 { amp } else { 1.0 };
            own.iter()
                .zip(&shared)
                .map(|(&o, &s)| scale * ((1.0 - lambda) * o + lambda * s))
                .collect()
        })
        .collect();
    CoherenceMatrix::from_signals(&signals).expect("real signals give a PSD correlation matrix")
}

/// Every scalar FANOS publishes about a cell, gathered so the two worlds can be compared field by field.
fn readings(g: &CoherenceMatrix) -> [f64; 5] {
    let m = g.measures();
    [
        m.phi,
        m.purity,
        m.reflection,
        g.mean_correlation(),
        g.diagonal_purity(),
    ]
}

/// **The finding.** A starved node and a dominant node can present the same `p`, and when they do, every
/// public reading agrees — while the correct response is opposite.
#[test]
fn a_starved_node_and_a_dominant_one_can_be_indistinguishable_to_every_published_scalar() {
    let lambda = 0.45;
    let starved = cell_with_node0_amplitude(lambda, 0.30);

    // Find the dominant amplitude that lands on the SAME diagonal purity. Both diseases raise `p`, so the
    // curve is folded about the uniform point: there are two amplitudes per `p`, one below 1 and one above.
    // Above 1 it is monotone, so this bisects rather than scanning — 40 evaluations instead of 4000, and
    // the first version's grid was both slow and unable to land inside its own tolerance.
    let target = starved.diagonal_purity();
    let (mut lo, mut hi) = (1.0_f64, 12.0_f64);
    assert!(
        cell_with_node0_amplitude(lambda, hi).diagonal_purity() > target,
        "the bracket must straddle the target, or the bisection converges on its own endpoint"
    );
    for _ in 0..40 {
        let mid = f64::midpoint(lo, hi);
        if cell_with_node0_amplitude(lambda, mid).diagonal_purity() < target {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let dominant = cell_with_node0_amplitude(lambda, f64::midpoint(lo, hi));

    // The match must be far tighter than the tolerance the readings are compared at, or "they agree" would
    // be a statement about the search rather than about the cells.
    let p_gap = (dominant.diagonal_purity() - target).abs();
    assert!(
        p_gap < 1e-6,
        "the matched pair is only within {p_gap:.2e} on p; every agreement below would be inside the \
         search's own error"
    );

    let (a, b) = (readings(&starved), readings(&dominant));
    let names = ["Φ", "P", "R", "r", "p"];
    for (i, name) in names.iter().enumerate() {
        println!("{name:>2}: starved {:.6}   dominant {:.6}", a[i], b[i]);
    }
    println!(
        "verdicts: starved {:?}/{:?}   dominant {:?}/{:?}",
        starved.collective_state(),
        starved.alarm(),
        dominant.collective_state(),
        dominant.alarm()
    );

    // THE CONTROL, and it has to be a measurement rather than an appeal to construction: the two worlds
    // must genuinely be different worlds, or "indistinguishable" is trivially true of one cell compared
    // with itself. Writing this is what forced `activity_shares` to exist — the first draft asserted the
    // difference in a `println!` because the vector was private, which is exactly the hole this file is
    // about ([[instrument-both-directions]]).
    let uniform = 1.0 / N as f64;
    let (hungry, shortfall) = starved.starved_axis().expect("a 7-node cell has an axis");
    let (fat, excess) = dominant.dominant_axis().expect("a 7-node cell has an axis");
    println!(
        "the difference nothing COULD see until now: uniform share is {uniform:.4}; the starved cell's \
         hungriest axis is node {hungry} at {:.4} (short by {shortfall:.4}), the dominant cell's fattest \
         is node {fat} at {:.4} (over by {excess:.4})",
        starved.activity_shares()[hungry],
        dominant.activity_shares()[fat],
    );
    assert_eq!(
        (hungry, fat),
        (0, 0),
        "both cells were built by moving node 0, so node 0 must be the extreme in each — if not, the \
         fixture is not doing what it claims and nothing below follows"
    );
    assert!(
        shortfall > 0.05 && excess > 0.05,
        "the two cells must differ WIDELY on the diagonal for their agreement elsewhere to mean anything: \
         shortfall {shortfall:.4}, excess {excess:.4}, against a uniform share of {uniform:.4}"
    );
    // And the deviations point in opposite directions, which is the whole finding: one cell needs feeding
    // and the other needs decoupling.
    assert!(
        starved.activity_shares()[0] < uniform && dominant.activity_shares()[0] > uniform,
        "the pair must straddle uniform — starved {:.4}, dominant {:.4}",
        starved.activity_shares()[0],
        dominant.activity_shares()[0]
    );

    // THE PROPERTY. Every scalar the platform publishes agrees to within estimator noise, so no consumer
    // of the coherence self-model — the homeostat, the healer, the frame, the exposition — can tell
    // "someone is starving" from "someone is swallowing the cell".
    for (i, name) in names.iter().enumerate() {
        assert!(
            (a[i] - b[i]).abs() < 5e-3,
            "{name} differs between the starved and dominant cells ({:.6} vs {:.6}), so it IS a \
             discriminator and this finding is wrong as stated — check which reading separates them \
             before concluding the instrument set is blind",
            a[i],
            b[i]
        );
    }
    assert_eq!(
        (starved.collective_state(), starved.alarm()),
        (dominant.collective_state(), dominant.alarm()),
        "the two verdicts differ, so the classifier separates the diseases after all"
    );
}
