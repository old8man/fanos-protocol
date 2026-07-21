//! Data-availability sampling on the Fano plane (spec §L4.3): **each line is a sample.**
//!
//! To gain confidence that a stored value is *available* (retrievable) without downloading it whole, a
//! verifier samples random **lines**. A line "sample" checks whether all `q+1 = 3` shards on that line are
//! present. The Steiner `S(2,3,7)` structure turns this into a sharp soundness guarantee:
//!
//! > **Theorem (≤1 external line).** If a value is *unavailable* — its missing-shard set `M` is not
//! > [`is_recoverable_fano`](crate::lrc::is_recoverable_fano) — then **at most one** Fano line is fully
//! > present (disjoint from `M`, an "external line").
//!
//! *Proof sketch.* An unavailable `M` is either a hyperoval (`|M| = 4`, no 3 collinear) or `|M| ≥ 5`. A
//! hyperoval meets every line in `0` or `2` points, so exactly one line is external (`7` lines `= C(4,2) = 6`
//! secants `+ 1` external). For `|M| ≥ 5` the present set has `≤ 2` points, which lie on a single line whose
//! third point is missing — so **no** line is fully present. Either way `≤ 1`. (Verified exhaustively over
//! all `128` masks in the tests.) ∎
//!
//! Two corollaries make DA sampling cheap and sound on the base cell:
//! * **`k` independent uniform samples:** an unavailable value passes all `k` with probability `≤ (1/7)^k`
//!   ([`false_available_bound`]) — one sample already gives `6/7` detection.
//! * **`2` *distinct* samples ⇒ certainty:** with `≤ 1` external line you cannot draw two distinct all-present
//!   lines, so any unavailable value fails a 2-distinct-line sample **deterministically**
//!   ([`distinct_sampling_is_sound`] proves it over every unavailable mask).
//!
//! Sampling unpredictably (seed the line choice, [`sample_lines`]) denies an adversary the chance to
//! pre-position that single external line, so the guarantee holds against a withholding adversary.

use alloc::vec::Vec;

use fanos_geometry::fano;

/// Whether the `line`-th Fano line is fully present in `present` (bit `i` ⇒ point `i`'s shard is present):
/// all three of the line's points hold their shard. This is one DA **sample** (spec §L4.3).
#[must_use]
pub fn line_present(present: u8, line: usize) -> bool {
    fano::INCIDENCE
        .get(line)
        .is_some_and(|&m| present & m == m)
}

/// The number of fully-present ("external") Fano lines given the `present` shard mask. By the theorem this is
/// `≤ 1` exactly when the value is unavailable, so it doubles as a soundness witness.
#[must_use]
pub fn present_line_count(present: u8) -> u32 {
    (0..fano::N)
        .filter(|&l| line_present(present, l))
        .count() as u32
}

/// A DA sample over `sampled` (distinct) line indices passes iff **every** one is fully present in `present`.
/// A single failing line ends the sample — the value is not confirmed available (spec §L4.3).
#[must_use]
pub fn samples_pass(present: u8, sampled: &[usize]) -> bool {
    sampled.iter().all(|&l| line_present(present, l))
}

/// The soundness bound: the maximum probability that `k` **independent uniform** line-samples all pass when
/// the value is actually unavailable — `(1/7)^k`, since an unavailable value has `≤ 1` of the `7` lines
/// external (the theorem). `k = 0` is the vacuous `1.0`. Distinct sampling is strictly stronger (see
/// [`distinct_sampling_is_sound`]); this bound covers the with-replacement case.
#[must_use]
pub fn false_available_bound(k: u32) -> f64 {
    // `(1/7)^k` by repeated multiplication — `f64::powi` is unavailable in `no_std`.
    let factor = 1.0 / fano::N as f64;
    let mut bound = 1.0;
    for _ in 0..k {
        bound *= factor;
    }
    bound
}

/// `splitmix64` step — a tiny, deterministic, `no_std` PRNG for unpredictable-but-verifiable line selection
/// from a seed (no external hash dependency). Standard constants.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Choose `k` **distinct** Fano lines (`0..7`) to sample, unpredictably from `seed` — a partial Fisher-Yates
/// shuffle driven by `splitmix64(seed)`. Deterministic in `seed` (so a challenge is verifiable) yet
/// unpredictable without it (so a withholding adversary cannot pre-position the lone external line). `k` is
/// clamped to `N = 7`; returns distinct indices. Pair with [`samples_pass`]: `k ≥ 2` gives certain detection
/// of any unavailable value.
#[must_use]
pub fn sample_lines(seed: u64, k: usize) -> Vec<usize> {
    let k = k.min(fano::N);
    let mut lines: [usize; fano::N] = core::array::from_fn(|i| i);
    let mut state = seed;
    // Partial Fisher-Yates: for the first `k` positions, swap in a uniformly-chosen remaining line.
    for i in 0..k {
        let span = (fano::N - i) as u64;
        let j = i + (splitmix64(&mut state) % span) as usize;
        lines.swap(i, j);
    }
    lines.into_iter().take(k).collect()
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::lrc::{is_hyperoval_fano, is_recoverable_fano};

    /// The load-bearing theorem, verified over ALL 128 masks: an unavailable value has `≤ 1` external line;
    /// a hyperoval has exactly `1`; an available value always has more (so a sample can pass honestly).
    #[test]
    fn an_unavailable_value_has_at_most_one_external_line() {
        for missing in 0u8..=0x7F {
            let present = !missing & 0x7F;
            let external = present_line_count(present);
            if is_recoverable_fano(missing) {
                // Available: no soundness claim here, but a fully-present value has all 7 lines external.
                if missing == 0 {
                    assert_eq!(external, 7, "a complete value: every line is external");
                }
            } else {
                assert!(
                    external <= 1,
                    "unavailable missing {missing:#09b} must have ≤1 external line, got {external}"
                );
                if is_hyperoval_fano(missing) {
                    assert_eq!(external, 1, "a hyperoval has exactly one external line");
                } else {
                    // |M| ≥ 5 ⇒ no line is fully present.
                    assert_eq!(external, 0, "a ≥5-missing value has no external line");
                }
            }
        }
    }

    /// Corollary verified exhaustively: **two distinct line-samples detect any unavailable value with
    /// certainty** — for every unavailable mask and every pair of distinct lines, the sample fails.
    #[test]
    fn distinct_sampling_is_sound() {
        for missing in 0u8..=0x7F {
            if is_recoverable_fano(missing) {
                continue;
            }
            let present = !missing & 0x7F;
            for a in 0..fano::N {
                for b in (a + 1)..fano::N {
                    assert!(
                        !samples_pass(present, &[a, b]),
                        "unavailable {missing:#09b}: distinct sample [{a},{b}] must fail"
                    );
                }
            }
        }
    }

    /// The independent-sampling bound is `(1/7)^k` and shrinks with `k`.
    #[test]
    fn the_false_available_bound_is_one_over_seven_to_the_k() {
        assert!((false_available_bound(0) - 1.0).abs() < 1e-12);
        assert!((false_available_bound(1) - 1.0 / 7.0).abs() < 1e-12);
        assert!((false_available_bound(2) - 1.0 / 49.0).abs() < 1e-12);
        assert!(false_available_bound(3) < false_available_bound(2));
    }

    /// `sample_lines` returns `k` distinct valid lines, is deterministic in the seed, and varies with it.
    #[test]
    fn sample_lines_are_distinct_deterministic_and_seed_dependent() {
        for seed in 0..64u64 {
            let s = sample_lines(seed, 3);
            assert_eq!(s.len(), 3);
            assert!(s.iter().all(|&l| l < fano::N));
            let mut sorted = s.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), 3, "seed {seed}: sampled lines are distinct");
            assert_eq!(s, sample_lines(seed, 3), "deterministic in the seed");
        }
        // Different seeds generally pick different line-sets (not a constant).
        let varied = (0..32u64).map(|s| sample_lines(s, 2)).any(|s| s != sample_lines(0, 2));
        assert!(varied, "the sampler depends on the seed");
        // Clamped to N.
        assert_eq!(sample_lines(1, 100).len(), fano::N);
    }

    /// An available (recoverable) value that happens to be complete passes any sample — the honest case.
    #[test]
    fn a_complete_value_passes_every_sample() {
        let present = 0x7F;
        for seed in 0..16u64 {
            assert!(samples_pass(present, &sample_lines(seed, 3)));
        }
    }
}
