//! The projective locally-recoverable code (spec §L4, §6.3 note, V9/V20).
//!
//! A point's data is erasure-coded across its `q+1` lines, so a lost node is rebuilt from
//! **any one** of its lines (locality `q`, availability `q+1`, redundancy `(q+1)/q → 1`).
//! Recovery of several simultaneous losses is a **peeling** decode: repeatedly rebuild any
//! node that is the only loss on some line, which frees that line's other members and may
//! expose new single-loss lines. On the Fano cell this recovers any `≤ 3` crashes and most
//! 4-node losses; it fails first exactly on a **hyperoval** — 4 points no 3 collinear.

use fanos_geometry::fano;

/// Locality `r`: the number of surviving nodes read to repair one loss (spec §L4).
#[inline]
#[must_use]
pub const fn locality(q: u32) -> u32 {
    q
}

/// Availability: the number of independent repair groups (lines) per node, `q + 1`.
#[inline]
#[must_use]
pub const fn availability(q: u32) -> u32 {
    q + 1
}

/// Storage redundancy `(q+1)/q`, which tends to `1` as `q` grows (spec §2.4, V9). For
/// `q = 31` this is `1.032`.
#[inline]
#[must_use]
pub fn redundancy(q: u32) -> f64 {
    (f64::from(q) + 1.0) / f64::from(q)
}

/// Peel-decode a set of lost Fano nodes (bit `i` ⇒ point `i` crashed). Returns the mask of
/// nodes that remain **unrecoverable** — the stopping set — which is `0` iff every loss was
/// repaired (spec §6.3, §6.7).
#[must_use]
pub fn peel_fano(mut lost: u8) -> u8 {
    lost &= 0x7F;
    loop {
        let mut progressed = false;
        for l in 0..fano::N {
            let Some(&line_mask) = fano::INCIDENCE.get(l) else {
                continue;
            };
            let lost_on_line = line_mask & lost;
            if lost_on_line.is_power_of_two() {
                // Exactly one loss on this line: rebuild it from the line's other members.
                lost &= !lost_on_line;
                progressed = true;
            }
        }
        if !progressed {
            return lost;
        }
    }
}

/// Whether every lost Fano node can be recovered by peeling.
#[inline]
#[must_use]
pub fn is_recoverable_fano(lost: u8) -> bool {
    peel_fano(lost) == 0
}

/// Whether a 4-point Fano set is a **hyperoval**: four points, no three collinear (spec
/// §6.3 note, V20). These are precisely the minimal patterns the peeling decoder cannot
/// repair — every line meets a hyperoval in `0` or `2` points, so no line ever exposes a
/// single loss.
#[must_use]
pub fn is_hyperoval_fano(mask: u8) -> bool {
    let mask = mask & 0x7F;
    if mask.count_ones() != 4 {
        return false;
    }
    // No line lies entirely inside the set (that would be three collinear points).
    for l in 0..fano::N {
        if let Some(&line_mask) = fano::INCIDENCE.get(l)
            && line_mask & mask == line_mask
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn lrc_parameters_match_spec() {
        // V9: locality q, availability q+1, redundancy (q+1)/q → 1.032 at q=31.
        assert_eq!(locality(31), 31);
        assert_eq!(availability(31), 32);
        assert!((redundancy(31) - 1.032_258).abs() < 1e-5);
        assert!(
            redundancy(127) < redundancy(31),
            "redundancy → 1 as q grows"
        );
    }

    #[test]
    fn any_up_to_three_crashes_recover() {
        // V20: peeling recovers any ≤3 simultaneous crashes on the Fano cell.
        for mask in 0u8..=0x7F {
            if mask.count_ones() <= 3 {
                assert!(
                    is_recoverable_fano(mask),
                    "mask {mask:#09b} with ≤3 losses must recover"
                );
            }
        }
    }

    #[test]
    fn peeling_fails_exactly_on_hyperovals() {
        // V20: among 4-node losses, the irrecoverable ones are exactly the hyperovals.
        let mut hyperovals = 0;
        for mask in 0u8..=0x7F {
            if mask.count_ones() == 4 {
                let recoverable = is_recoverable_fano(mask);
                let hyperoval = is_hyperoval_fano(mask);
                assert_eq!(
                    recoverable, !hyperoval,
                    "4-set {mask:#09b}: recoverable={recoverable}, hyperoval={hyperoval}"
                );
                if hyperoval {
                    hyperovals += 1;
                    // A stuck hyperoval peels to itself (no progress at all).
                    assert_eq!(peel_fano(mask), mask);
                }
            }
        }
        // PG(2,2) has exactly 7 hyperovals.
        assert_eq!(hyperovals, 7);
    }

    #[test]
    fn spec_hyperoval_example_is_a_hyperoval() {
        // spec cites A,S,L,U (addresses 1,2,4,7) as the densest failure configuration.
        use crate::syndrome::index_of_address;
        let mut mask = 0u8;
        for a in [1u8, 2, 4, 7] {
            mask |= 1 << index_of_address(a).unwrap();
        }
        assert!(is_hyperoval_fano(mask));
        assert!(!is_recoverable_fano(mask));
    }
}
