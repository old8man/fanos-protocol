//! **`beacon flood spread < epoch period`** — the inequality PROTEUS's ±1 shape window rests on (#196, #288).
//!
//! `ProteusShaper` accepts the shapes of epochs `{N−1, N, N+1}`. It needs the *future* one because epoch
//! advance is beacon-driven: at a turn one anchor rotates first, so its frames carry a shape its peer has
//! not adopted yet. A ±1 window covers that **only while the beacon reaches the whole cell inside one
//! epoch**. Should the spread ever exceed a period, the correct finding is not "widen the window" — it is
//! that the epoch period is too short for the cell's diameter, and widening would hide it.
//!
//! The inequality had been written down and never measured, for two separate reasons that were worth
//! separating: the notification log carried no timestamp (fixed — `Observed::at`), and `spawn_cell` runs
//! no beacon at all, so a first attempt measured **0 adopters of 57** and passed. This one stands up the
//! real `BeaconNode` cell, and asserts the SAMPLE before the STATISTIC so a vacuous run fails loudly
//! instead of reporting that the inequality holds.
//!
//! ## Why two plane orders, and why they must share one threshold rule (#288)
//!
//! The first version measured Fano alone and reported 5 ms. That is a number about `PG(2,2)` and its seven
//! points — it says nothing about whether the spread is a property of the *plane* or of the smallest plane
//! there is. The claim under test is an inequality against the epoch
//! period, and the period does not grow with `q`, so the only honest form is a second anchor far enough
//! away to show the trend. `q = 7` gives 57 points, an eight-fold cell.
//!
//! **The threshold must be one rule across both, or this compares rules and not planes.** `BeaconReady`
//! fires when an anchor has `t` verified partials, so `t` sets *when* adoption happens; a Fano anchor at a
//! hand-picked 5 against a `q = 7` anchor at some other hand-picked number would differ for reasons that
//! have nothing to do with the flood. So both take `2f + 1` with `f` imported from
//! [`fanos_runtime::fault_budget`] — the platform's own Byzantine budget, not a local restatement of
//! `(n − 1)/3`. The previous `BEACON_T = 5` was borrowed from a sibling test's sharing shape; at `n = 7`
//! the rule reproduces it exactly, so the Fano figure stays comparable with what was measured before.
//!
//! ## What it measured, and why the shape is not a surprise once the geometry is stated
//!
//! ```text
//! q=2  n= 7  t= 5   spread 5 ms  (first 22, last 27)
//! q=7  n=57  t=37   spread 3 ms  (first 24, last 27)
//! cell grew x8.14, spread grew x0.60
//! ```
//!
//! The cell grew eight-fold and the spread did **not**. That is the projective plane doing the thing it was
//! chosen for: in `PG(2, q)` every two points lie on exactly one common line, so a node's line-mates are
//! *every other node in the cell*, at every `q`. The overlay is diameter-1 by construction, and a flood is
//! therefore one hop wide however many points there are. The spread is bounded by hop latency, not by `n`.
//!
//! So the honest reading of #288's premise: 5 ms was indeed a Fano number, and the thing it was feared to be
//! hiding — growth with the plane — is absent for a structural reason rather than by luck. What the second
//! anchor buys is that the reason is now *measured* and not merely argued.
//!
//! Two things this does **not** claim. The drop from 5 ms to 3 ms is 2 ms on a virtual clock across two
//! sample points, which is not a trend; the load-bearing observation is that 8.14× the cell did not produce
//! anything near 8× the spread. And the later *first* adoption at `q = 7` (24 ms against 22 ms) is what a
//! larger `t` should cost — 37 partials to wait for instead of 5 — but that mechanism is untested here and
//! is stated as an expectation, not a finding.
//!
//! `measure_` by convention: reported, never gated — a number that moves with the machine must not be able
//! to redden a build. The coverage assertion is the exception and is deliberate: zero adopters is not a
//! slow machine, it is a broken harness.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use fanos_field::{F2, F7, Field};
use fanos_geometry::{Plane, Point};
use fanos_keygen::BeaconNode;
use fanos_primitives::BeaconSeed;
use fanos_vrf::vss::{DeterministicRng, deal};
use fanos_runtime::{Command, Config, Duration, Notification, Triple, fault_budget};
use fanos_sim::Sim;

/// The reconstruction threshold for a cell of `n`: `2f + 1`, the standard Byzantine reconstruction size
/// over the platform's own budget. One rule for every plane order — see the module header for why that is
/// the load-bearing part and not a tidiness preference.
fn beacon_threshold(n: usize) -> usize {
    2 * fault_budget(n) + 1
}

/// First-adoption time per anchor, in virtual milliseconds, over a live `BeaconNode` cell on plane `F`.
///
/// Returns the map rather than the spread so the caller can assert coverage against `Plane::<F>::N` before
/// reducing it to a statistic — `max − min` over a short map is a number, and a wrong one.
fn first_adoptions<F: Field + 'static>(seed: u64, run_for: Duration) -> BTreeMap<Triple, u64> {
    let n = Plane::<F>::N as usize;
    let t = beacon_threshold(n);
    let (shares, commitment) = deal(&[0xBE; 32], t, n, &mut DeterministicRng::new(b"flood-spread")).unwrap();

    let mut sim = Sim::new(seed);
    for (i, share) in shares.iter().enumerate() {
        sim.add(Box::new(BeaconNode::<F>::new(
            Point::at(i),
            Some(share.clone()),
            commitment.clone(),
            t,
            BeaconSeed::GENESIS,
        )));
    }
    sim.inject_all(&Command::AdvanceEpoch);
    sim.run_for(run_for);

    let mut first: BTreeMap<Triple, u64> = BTreeMap::new();
    for o in &sim.report().notifications {
        if matches!(o.note, Notification::BeaconReady { .. }) {
            first.entry(o.node).or_insert_with(|| o.at.as_nanos() / 1_000_000);
        }
    }
    first
}

/// Reduce a coverage-checked adoption map to `(spread, first, last)`, panicking loudly if the sample is
/// short of the whole cell.
///
/// **The sample, before the statistic.** `max − min` over an empty set is 0, and 0 is under every bound —
/// which is exactly how the first attempt reported "the inequality holds" having measured nothing at all.
fn spread_of(first: &BTreeMap<Triple, u64>, n: usize, label: &str) -> (u64, u64, u64) {
    assert_eq!(
        first.len(),
        n,
        "{label}: every anchor must have adopted before a spread means anything — {} of {n} did, so this \
         run measured coverage, not speed (#196)",
        first.len()
    );
    let (lo, hi) = (*first.values().min().unwrap(), *first.values().max().unwrap());
    (hi - lo, lo, hi)
}

#[test]
fn measure_beacon_flood_spread_against_the_epoch_period() {
    let period_ms = Config::default().epoch_period.as_nanos() / 1_000_000;

    let fano_n = Plane::<F2>::N as usize;
    let fano = first_adoptions::<F2>(0xB2C0, Duration::from_millis(4000));
    let (fano_spread, fano_lo, fano_hi) = spread_of(&fano, fano_n, "q=2");

    // A cell eight times the size gets proportionally more virtual time to finish flooding: the ceiling is
    // a harness bound, not the quantity being measured, and one too tight would show up as a coverage
    // failure above rather than as a quietly shorter spread.
    let big_n = Plane::<F7>::N as usize;
    let big = first_adoptions::<F7>(0xB2C7, Duration::from_millis(32_000));
    let (big_spread, big_lo, big_hi) = spread_of(&big, big_n, "q=7");

    println!(
        "\nbeacon flood spread, one threshold rule (2f+1) across both planes:\n\
         \x20 q=2  n={fano_n:>2}  t={:>2}   spread {fano_spread:>5} ms  (first {fano_lo}, last {fano_hi})  \
         = {:.6} of a period\n\
         \x20 q=7  n={big_n:>2}  t={:>2}   spread {big_spread:>5} ms  (first {big_lo}, last {big_hi})  \
         = {:.6} of a period\n\
         \x20 cell grew x{:.2}, spread grew x{:.2}\n\
         \x20 epoch period: {period_ms} ms\n",
        beacon_threshold(fano_n),
        fano_spread as f64 / period_ms as f64,
        beacon_threshold(big_n),
        big_spread as f64 / period_ms as f64,
        big_n as f64 / fano_n as f64,
        if fano_spread == 0 { f64::INFINITY } else { big_spread as f64 / fano_spread as f64 },
    );

    for (label, n, spread) in [("q=2", fano_n, fano_spread), ("q=7", big_n, big_spread)] {
        assert!(
            spread < period_ms,
            "MEASURED VIOLATION at {label} (n={n}): the beacon takes {spread} ms to cross the cell against \
             a {period_ms} ms epoch. The ±1 shape window is NOT sufficient here, and widening it would hide \
             the real finding: the period is too short for this diameter (#196)"
        );
    }
}
