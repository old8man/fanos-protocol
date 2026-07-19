//! **C6 — guard-discovery / entry-enumeration unlinkability.**
//!
//! `network-threat-model.md` C6: FANOS has no public bridge/guard list. A party's entry point is its
//! *rendezvous line* `L = MapToLine(H("FANOS-v1/calypso" ‖ identity ‖ epoch))` (`calypso::rendezvous`),
//! which both ends derive with no lookup — the client's own reply rendezvous (where it is reachable,
//! i.e. its entry set) is derived the same way from its identity. The `rendezvous` unit tests already
//! pin determinism, per-epoch rotation, and per-identity separation. This file adds the **quantitative
//! adversarial properties** that make the entry set genuinely un-enumerable and unlinkable:
//!
//!   1. the entry lines cover the *whole* line space ~uniformly — there is no small guard set to
//!      enumerate or block;
//!   2. an adversary who does not know the identity guesses its entry line no better than `1/N`;
//!   3. entry lines are unpredictable across epochs — a line at epoch `e` reveals nothing about the
//!      same identity's line at `e+1`, so appearances cannot be linked and there is no long-term target;
//!   4. a near-miss identity (one bit different) yields an unrelated line — you cannot approximate a
//!      target's entry from a similar known one.
//!
//! Over `PG(2,7)` (`N = 57` lines): small enough for meaningful per-bucket occupancy, large enough for
//! the statistics to bite. Every identity is a fixed function of a counter, so the measured rates are
//! deterministic pass/fail numbers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use fanos_calypso::{Epoch, rendezvous_line};
use fanos_field::F7;
use fanos_geometry::{Plane, Triple};

/// Number of lines in `PG(2,7)`: `q² + q + 1 = 57`.
const N: usize = Plane::<F7>::N as usize;

/// A distinct pseudo-identity (a would-be pubkey) for counter `i`.
fn identity(i: u32) -> [u8; 4] {
    i.to_be_bytes()
}

/// The entry (rendezvous) line an identity uses at `epoch`, as a comparable bucket key.
fn entry_line(id: &[u8], epoch: u32) -> Triple {
    rendezvous_line::<F7>(id, Epoch::new(epoch.into())).coords()
}

/// Histogram of entry lines over identities `0..count` at `epoch`.
fn histogram(count: u32, epoch: u32) -> BTreeMap<Triple, usize> {
    let mut h = BTreeMap::new();
    for i in 0..count {
        *h.entry(entry_line(&identity(i), epoch)).or_insert(0) += 1;
    }
    h
}

/// The entry lines cover the whole line space with no clustering: an adversary sees no small set of
/// guards to enumerate or block — the entry set is the *entire* geometry, spread ~uniformly.
#[test]
fn entry_lines_cover_the_whole_space_uniformly() {
    let per_bucket = 80usize;
    let m = (N * per_bucket) as u32;
    let h = histogram(m, 0);

    // Every one of the N lines is used — there is no unreachable region and no small guard subset.
    assert_eq!(
        h.len(),
        N,
        "entry lines must cover all {N} lines (got {})",
        h.len()
    );

    // ~Uniform: a chi-square goodness-of-fit far below the tail. E[χ²] ≈ N-1 = 56 under uniformity;
    // the bound is generous (a good hash sits near 56), but a *biased* derivation with a hot/cold
    // region would blow past it.
    let exp = f64::from(m) / N as f64;
    let chi2: f64 = h
        .values()
        .map(|&o| {
            let d = o as f64 - exp;
            d * d / exp
        })
        .sum();
    eprintln!(
        "[C6 uniformity] N={N} m={m} exp={exp:.1} chi2={chi2:.1} maxload={}",
        h.values().max().copied().unwrap_or(0)
    );
    assert!(
        chi2 < 2.0 * N as f64,
        "entry-line distribution is not uniform (chi2={chi2:.1})"
    );
}

/// Without the identity, the entry line is unguessable beyond chance: the most-used line's frequency
/// is within a small factor of the uniform `1/N`, so the adversary's guessing advantage ≈ `1/N`.
#[test]
fn an_adversary_cannot_guess_an_entry_line_better_than_uniform() {
    let per_bucket = 80usize;
    let m = (N * per_bucket) as u32;
    let h = histogram(m, 0);

    let max_load = h.values().max().copied().unwrap_or(0);
    let max_freq = max_load as f64 / f64::from(m);
    let uniform = 1.0 / N as f64;
    eprintln!(
        "[C6 guessing] max_freq={max_freq:.4} uniform={uniform:.4} ratio={:.2}",
        max_freq / uniform
    );
    // The best line an adversary could guess is used at most ~2× the uniform rate — the min-entropy of
    // the entry line stays near log2(N), so guessing succeeds with probability ≈ 1/N.
    assert!(
        max_freq < 2.0 * uniform,
        "an entry line is over-represented (max_freq={max_freq:.4} ≫ 1/N={uniform:.4})"
    );
}

/// Entry lines are unpredictable across epochs: almost every identity moves to a different line at the
/// next epoch (no long-term target), and the line at `e+1` is uncorrelated with the line at `e` — so an
/// adversary cannot link an identity's appearances or extrapolate its future entry.
#[test]
fn entry_lines_are_unpredictable_across_epochs() {
    let m = (N * 40) as u32;

    // Rotation: the fraction of identities whose entry line changes from epoch e to e+1 is ≈ 1 − 1/N.
    let rotated = (0..m)
        .filter(|&i| entry_line(&identity(i), 0) != entry_line(&identity(i), 1))
        .count();
    let rotate_rate = rotated as f64 / f64::from(m);
    eprintln!(
        "[C6 rotation] rate={rotate_rate:.4}  (ideal {:.4})",
        1.0 - 1.0 / N as f64
    );
    assert!(
        rotate_rate > 0.95,
        "entry lines must rotate per epoch (rate={rotate_rate:.4})"
    );

    // No cross-epoch correlation: the count of identities whose e+1 line equals *some other* identity's
    // e line stays at the chance level — knowing epoch e's occupancy does not predict epoch e+1's. We
    // check the simplest linkage: for identities colliding on one line at epoch e, their epoch-(e+1)
    // lines are spread, not concentrated (max onward-load near the uniform expectation).
    let mut by_e0: BTreeMap<Triple, Vec<u32>> = BTreeMap::new();
    for i in 0..m {
        by_e0
            .entry(entry_line(&identity(i), 0))
            .or_default()
            .push(i);
    }
    // Take the most populated epoch-0 line and see where its members land at epoch 1.
    let group = by_e0.values().max_by_key(|v| v.len()).unwrap();
    let mut onward: BTreeMap<Triple, usize> = BTreeMap::new();
    for &i in group {
        *onward.entry(entry_line(&identity(i), 1)).or_insert(0) += 1;
    }
    let onward_max = onward.values().max().copied().unwrap_or(0);
    eprintln!(
        "[C6 no-correlation] group={} onward_distinct={} onward_max={onward_max}",
        group.len(),
        onward.len()
    );
    // If epoch-1 lines were correlated with epoch-0, this group would re-concentrate; instead it
    // scatters — the onward max-load is a small fraction of the group.
    assert!(
        onward_max <= (group.len() / 2).max(2),
        "epoch e+1 lines re-concentrate from an epoch e group — appearances are linkable"
    );
}

/// A near-miss identity (one bit flipped) lands on an unrelated entry line: an adversary cannot
/// approximate a target's entry point from a *similar* known identity (avalanche).
#[test]
fn a_near_miss_identity_reveals_nothing() {
    let m = 2000u32;
    let changed = (0..m)
        .filter(|&i| {
            let base = identity(i);
            let mut flipped = base;
            flipped[0] ^= 0x01; // flip one bit of the identity
            entry_line(&base, 3) != entry_line(&flipped, 3)
        })
        .count();
    let rate = changed as f64 / f64::from(m);
    eprintln!(
        "[C6 avalanche] one-bit-flip changes the line at rate {rate:.4}  (ideal {:.4})",
        1.0 - 1.0 / N as f64
    );
    assert!(
        rate > 0.95,
        "a one-bit identity change must give an unrelated line (rate={rate:.4})"
    );
}
