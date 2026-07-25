//! **The tower ladder** — the *vertical* reading of the same Golay grammar (UHM **T-232**).
//!
//! [`crate::federation`] diagnoses a parent cell's seven *siblings* — growth sideways. A hierarchy also grows *upward*, and
//! a tower's diagnostic load is not just its floors:
//!
//! > "A coupling can be alive or broken, and a grammar that cannot see coupling faults does not certify the **tower**, only
//! > its floors."
//!
//! So an `m`-level tower carries `m` seven-axis cells **plus the `m − 1` couplings between adjacent levels**:
//!
//! ```text
//! U(m) = 7m + (m − 1) = 8m − 1
//! ```
//!
//! ## The ladder selects three, again, and for a third reason
//!
//! Running the van Lint–Tietäväinen classification along `U(m)` (T-232):
//!
//! | height `m` | units `U = 8m−1` | perfect grammar | canonical? | strength |
//! |---|---|---|---|---|
//! | 1 | 7 | Hamming = Fano | **yes** (Theorem Σ) | `t = 1` |
//! | 2 | 15 | Hamming-type | **no** — Vasil'ev rivals | `t = 1` |
//! | 3 | **23** | **Golay** | **yes** (Pless) | **`t = 3`** |
//! | 4 | 31 | Hamming-type | no | `t = 1` |
//! | 5, 6, 7 | 39, 47, 55 | **none at any order** | — | — |
//! | 8 | 63 | Hamming-type | no | `t = 1` |
//!
//! A perfect *single*-fault grammar exists iff `m` is a power of two (`8m − 1 = 2^r − 1`), and a perfect *multi*-fault
//! grammar exists **iff `m = 3`** — because `8m − 1 = 23` has exactly one solution and the Golay code is the only perfect
//! binary code with `t ≥ 2`. So `m = 3` is the unique height whose *full* load — axes **and** couplings — carries a
//! canonical perfect grammar beyond single faults.
//!
//! That is the platform's composition ceiling arrived at a **third** time, independently: the purity ladder gives
//! `P_crit^[4] = 54/35 > 1` (`fanos_ergon::D_MAX`), the horizontal federation gives it by sphere packing over three members
//! ([`crate::golay`]), and the tower ladder gives it by sphere packing over three *floors plus their couplings*. Three
//! derivations, one number.
//!
//! ## Why the vertical reading is the cleaner one
//!
//! `23 = 3·7 + 2` — three cells plus **two** couplings. Where the horizontal federation reaches the perfect `[23,12,7]` by
//! *puncturing* one bus coordinate, the 3-tower already has exactly 23 units and needs no puncture at all. The vertical
//! tower is the native home of the perfect code, and the two readings carry **literally the same grammar**.
//!
//! This module makes that concrete rather than decorative: the couplings *are* two of the three bus coordinates of
//! [`crate::golay`]'s block layout. Block `m` holds level `m`'s seven axes plus one bus coordinate, and those three buses
//! are `coupling(0↔1)`, `coupling(1↔2)`, and the tower's own parity attestation. So `3·7 + 2 = 23` natural units sit inside
//! the same 24-coordinate word the horizontal federation uses, and **one decoder serves both readings**.
//!
//! ## Perfection has a cost, and FANOS pays the other way [D]
//!
//! The 24th coordinate is retained deliberately, and the reason is worth stating because it cuts against the elegance.
//! Perfection means the radius-3 balls *tile* the cube: every raw profile has exactly one diagnosis, no profile is
//! undiagnosable. That is mathematically the strongest form of diagnosability — and operationally it means the code **can
//! never say "I don't know"**. Past three faults a perfect code answers confidently and wrongly.
//!
//! A confident wrong verdict acted on by a self-healing controller is the exact failure mode this whole line of work exists
//! to remove (see [`crate::golay`]'s note on the lone cell at two faults). So FANOS keeps the extension: the same `t = 3`,
//! and the ability to return [`Tower::Ambiguous`] instead of a fiction. T-232's "no puncture needed" is a statement about
//! the coordinate *count* matching exactly, and it stands; FANOS **adds** a parity coordinate rather than puncturing one,
//! for the opposite reason and to the same benefit.

use crate::golay::{self, Report, Word};

/// Levels of the canonical tower — **three**, and selected by the ladder rather than chosen.
pub const HEIGHT: u32 = 3;
/// Couplings in a tower of [`HEIGHT`] levels: one between each adjacent pair.
pub const COUPLINGS: usize = (HEIGHT - 1) as usize;

/// The diagnostic load of an `m`-level tower: `7m` axes plus `m − 1` couplings.
///
/// `None` for `m = 0` (a tower with no floors has no load) or on overflow.
#[must_use]
pub const fn units(m: u32) -> Option<u32> {
    if m == 0 {
        return None;
    }
    match m.checked_mul(8) {
        Some(u) => Some(u - 1),
        None => None,
    }
}

/// The perfect grammar available at a tower height, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grammar {
    /// No perfect grammar of any order exists at this height.
    None,
    /// A perfect single-fault (Hamming-type) grammar. `canonical` is true only at `m = 1`: from `U = 15` upward
    /// Vasil'ev's nonlinear perfect codes are rivals, so the grammar exists but is not canonically unique.
    SingleFault {
        /// Whether the grammar is canonically unique at this height.
        canonical: bool,
    },
    /// The Golay grammar: `t = 3`, canonical, and available at exactly one height.
    Golay,
}

/// The grammar at height `m`, by the T-232 ladder.
///
/// Derived rather than tabulated: a perfect single-fault grammar needs `8m − 1 = 2^r − 1`, i.e. `m` a power of two; a
/// perfect multi-fault grammar needs `8m − 1 = 23`, i.e. `m = 3`, since the Golay code is the only perfect binary code with
/// `t ≥ 2`.
#[must_use]
pub const fn grammar(m: u32) -> Grammar {
    // A height with no load (m = 0) and a height whose load fits no perfect code both answer `None`; they are one arm
    // because the reason differs but the grammar does not.
    match units(m) {
        Some(23) => Grammar::Golay,
        // `U + 1 = 2^r` ⟺ `m` is a power of two, since `U + 1 = 8m`.
        Some(u) if (u + 1).is_power_of_two() => Grammar::SingleFault { canonical: m == 1 },
        Some(_) | None => Grammar::None,
    }
}

/// A level's observation: which of its seven axes look faulty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Level {
    /// Bit `j` set ⟺ axis `j` of this level looks faulty. Low seven bits only.
    pub axes: u8,
}

impl Level {
    /// A level reporting the given faulty axes.
    #[must_use]
    pub const fn new(axes: u8) -> Self { Self { axes: axes & 0x7F } }
}

/// A localized unit of a tower — the thing a verdict names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    /// Axis `axis` of level `level`.
    Axis {
        /// The tower level, `0` = the deepest.
        level: usize,
        /// The axis within that level.
        axis: usize,
    },
    /// The coupling between levels `below` and `below + 1`.
    Coupling {
        /// The lower of the two levels the coupling joins.
        below: usize,
    },
    /// The tower's own parity coordinate — a damaged *attestation* rather than damaged structure. Observed, never computed
    /// (see [`word`]).
    Parity,
}

/// What a tower concluded about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tower {
    /// No level or coupling reports a fault.
    Healthy,
    /// Up to `golay::T` faults across axes **and couplings**, localized exactly.
    Localized {
        /// The localized units, in the order the grammar reports them.
        units: [Option<Unit>; golay::T],
    },
    /// Four or more faults: detected and not localizable. See the module note on why this verdict is kept.
    Ambiguous,
}

/// Map a tower unit onto its coordinate in the 24-bit word.
///
/// Block `m` carries level `m`'s axes in bits 0..6 and one bus coordinate in bit 7; the three buses are
/// `coupling(0↔1)`, `coupling(1↔2)`, and the derived tower parity. This is what makes T-232's "the two readings carry the
/// same grammar" a fact about the code rather than a remark: the couplings *are* bus coordinates.
const fn block_of(level: usize) -> usize { level }

/// Assemble the tower's 24-bit word from its levels, its couplings, and its parity coordinate.
///
/// ## `parity_fault` is observed, never computed — and this is the second time that mattered
///
/// The obvious move is to *derive* the parity coordinate: set it so the word comes out even, since a healthy tower's word
/// is even. That is wrong, and wrong in exactly the way `golay::Report`'s bus was wrong the first time: **parity is a
/// property of the codeword, not of the error.** Deriving it turns a weight-3 error into a weight-4 word, pushing a
/// correctable pattern past `t = 3` and answering [`Tower::Ambiguous`] for precisely the case the grammar exists to handle
/// — measured, by the exhaustive triple test failing on three axes in one level.
///
/// The healthy tower's word is all-zero, and an odd-weight *received* word is a detectable state rather than something to be
/// closed by construction. So the parity coordinate is an input like any other: `false` when the attestation is intact.
///
/// Having made the identical mistake at two different coordinates, the rule is worth stating flatly: in this code a parity
/// or bus coordinate is **always** an observation and **never** a function of the other observations.
#[must_use]
#[allow(clippy::indexing_slicing)] // fixed-size arrays, constant indices
pub fn word(levels: [Level; HEIGHT as usize], couplings: [bool; COUPLINGS], parity_fault: bool) -> Word {
    let mut blocks = [0u8; golay::MEMBERS];
    for (i, l) in levels.iter().enumerate() {
        blocks[block_of(i)] = l.axes & 0x7F;
    }
    for (i, broken) in couplings.iter().enumerate() {
        if *broken {
            blocks[block_of(i)] |= 1 << golay::AXES;
        }
    }
    if parity_fault {
        blocks[golay::MEMBERS - 1] |= 1 << golay::AXES;
    }
    Word::from_blocks([blocks[0], blocks[1], blocks[2]])
}

/// Diagnose a tower: up to `golay::T` faults across its axes **and its couplings**, localized exactly.
///
/// The coupling coordinates are what make this certify the tower rather than only its floors. A broken link between two
/// levels is a first-class fault here, indistinguishable in treatment from a faulty axis — which is the point of pricing
/// the tower at `8m − 1` rather than `7m`.
#[must_use]
#[allow(clippy::indexing_slicing)] // fixed-size arrays, constant indices
pub fn diagnose(
    levels: [Level; HEIGHT as usize],
    couplings: [bool; COUPLINGS],
    parity_fault: bool,
) -> Tower {
    let w = word(levels, couplings, parity_fault);
    let Some(faults) = golay::locate(w) else { return Tower::Ambiguous };
    if faults.is_empty() {
        return Tower::Healthy;
    }
    let mut units = [None; golay::T];
    for (slot, &bit) in units.iter_mut().zip(faults.bits()) {
        let block = golay::MEMBERS - 1 - usize::from(bit) / golay::BLOCK;
        let within = usize::from(bit) % golay::BLOCK;
        *slot = Some(if within == golay::AXES {
            if block < COUPLINGS { Unit::Coupling { below: block } } else { Unit::Parity }
        } else {
            Unit::Axis { level: block, axis: within }
        });
    }
    Tower::Localized { units }
}

/// The tower's three-level report as three [`Report`]s, for callers that want to feed the horizontal machinery directly.
///
/// Exposed to make the shared-grammar claim usable rather than only true: a tower and a federation differ in what their
/// coordinates *mean*, never in the code that decodes them.
#[must_use]
#[allow(clippy::indexing_slicing)] // fixed-size arrays, constant indices
pub fn as_reports(
    levels: [Level; HEIGHT as usize],
    couplings: [bool; COUPLINGS],
    parity_fault: bool,
) -> [Report; golay::MEMBERS] {
    let blocks = word(levels, couplings, parity_fault).blocks();
    [
        Report { axes: blocks[0] & 0x7F, bus_fault: blocks[0] >> golay::AXES & 1 == 1 },
        Report { axes: blocks[1] & 0x7F, bus_fault: blocks[1] >> golay::AXES & 1 == 1 },
        Report { axes: blocks[2] & 0x7F, bus_fault: blocks[2] >> golay::AXES & 1 == 1 },
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use alloc::format;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn the_load_is_axes_plus_couplings_not_axes_alone() {
        // U(m) = 7m + (m−1) = 8m − 1. The (m−1) is the whole point: a grammar blind to coupling faults certifies the
        // floors, not the tower.
        for m in 1u32..64 {
            let u = units(m).unwrap();
            assert_eq!(u, 8 * m - 1);
            assert_eq!(u, 7 * m + (m - 1), "axes plus couplings");
        }
        assert_eq!(units(0), None, "a tower with no floors has no load");
        assert_eq!(units(u32::MAX), None, "and overflow is refused rather than wrapped");
    }

    #[test]
    fn the_ladder_selects_three_for_multi_fault_and_powers_of_two_for_single() {
        // T-232 recomputed rather than tabulated.
        assert_eq!(grammar(1), Grammar::SingleFault { canonical: true }, "U=7: Hamming = Fano, canonical");
        assert_eq!(grammar(2), Grammar::SingleFault { canonical: false }, "U=15: Vasil'ev rivals destroy the canon");
        assert_eq!(grammar(3), Grammar::Golay, "U=23: the unique canonical multi-fault rung");
        assert_eq!(grammar(4), Grammar::SingleFault { canonical: false }, "U=31");
        for m in 5u32..=7 {
            assert_eq!(grammar(m), Grammar::None, "U={} admits no perfect grammar at any order", 8 * m - 1);
        }
        assert_eq!(grammar(8), Grammar::SingleFault { canonical: false }, "U=63");
        assert_eq!(grammar(0), Grammar::None);

        // The multi-fault rung is unique across the whole ladder — checked far past any plausible height.
        let golay_heights: Vec<u32> = (1u32..4096).filter(|&m| grammar(m) == Grammar::Golay).collect();
        assert_eq!(golay_heights, vec![3], "8m − 1 = 23 has exactly one solution");

        // And single-fault heights are exactly the powers of two.
        for m in 1u32..4096 {
            let single = matches!(grammar(m), Grammar::SingleFault { .. });
            assert_eq!(single, m.is_power_of_two() && m != 3, "height {m}");
        }
    }

    #[test]
    fn the_couplings_are_bus_coordinates_so_one_decoder_serves_both_readings() {
        // The concrete form of "the two readings carry the same grammar": a tower's couplings occupy two of the three bus
        // coordinates of the horizontal block layout, and the third is the derived tower parity. 3·7 + 2 = 23 natural units
        // inside the same 24-coordinate word.
        assert_eq!(HEIGHT as usize * golay::AXES + COUPLINGS, 23, "the tower's natural load");
        assert_eq!(golay::N, 24, "and it sits inside the one word the federation uses");
        assert_eq!(COUPLINGS + 1, golay::MEMBERS, "two couplings plus one parity = three buses");

        // A healthy tower is the zero word.
        let w = word([Level::new(0); HEIGHT as usize], [false; COUPLINGS], false);
        assert_eq!(w.0, 0);
        assert!(w.is_codeword());
    }

    #[test]
    fn a_healthy_tower_is_healthy() {
        assert_eq!(diagnose([Level::new(0); HEIGHT as usize], [false; COUPLINGS], false), Tower::Healthy);
    }

    #[test]
    fn a_broken_coupling_is_localized_as_a_coupling_not_as_an_axis() {
        // The capability the 7m accounting cannot express at all.
        for below in 0..COUPLINGS {
            let mut couplings = [false; COUPLINGS];
            couplings[below] = true;
            let Tower::Localized { units } = diagnose([Level::new(0); HEIGHT as usize], couplings, false) else {
                panic!("a single coupling fault must localize")
            };
            let named: Vec<Unit> = units.into_iter().flatten().collect();
            assert!(
                named.contains(&Unit::Coupling { below }),
                "coupling {below} must be named as a coupling, got {named:?}"
            );
        }
    }

    #[test]
    fn any_three_faults_across_axes_and_couplings_are_localized() {
        // Exhaustive over the tower's 23 natural units: 21 axes plus 2 couplings, all C(23,3) = 1771 triples. Each must be
        // localized exactly, and each named as the right kind of unit.
        let mut coords: Vec<Unit> = Vec::new();
        for level in 0..HEIGHT as usize {
            for axis in 0..golay::AXES {
                coords.push(Unit::Axis { level, axis });
            }
        }
        for below in 0..COUPLINGS {
            coords.push(Unit::Coupling { below });
        }
        assert_eq!(coords.len(), 23, "21 axes + 2 couplings");

        let mut checked = 0usize;
        for i in 0..coords.len() {
            for j in (i + 1)..coords.len() {
                for k in (j + 1)..coords.len() {
                    let want = [coords[i], coords[j], coords[k]];
                    let mut levels = [Level::new(0); HEIGHT as usize];
                    let mut couplings = [false; COUPLINGS];
                    for u in want {
                        match u {
                            Unit::Axis { level, axis } => levels[level].axes |= 1 << axis,
                            Unit::Coupling { below } => couplings[below] = true,
                            Unit::Parity => unreachable!("parity is derived, never an input"),
                        }
                    }
                    let Tower::Localized { units } = diagnose(levels, couplings, false) else {
                        panic!("three faults must localize: {want:?}")
                    };
                    let mut got: Vec<Unit> = units.into_iter().flatten().collect();
                    let mut want_sorted = want.to_vec();
                    want_sorted.sort_by_key(|u| format!("{u:?}"));
                    got.sort_by_key(|u| format!("{u:?}"));
                    assert_eq!(got, want_sorted, "exact attribution for {want:?}");
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 1771, "all C(23,3) triples — and 1771 is the punctured code's weight-3 ball");
    }

    #[test]
    fn four_faults_are_ambiguous_rather_than_a_confident_fiction() {
        // Why the 24th coordinate is retained: a *perfect* [23,12,7] tiles the cube, so it always answers — and past three
        // faults it answers wrongly. A controller acting on that is the failure mode this work exists to remove.
        let mut levels = [Level::new(0); HEIGHT as usize];
        levels[0].axes = 0b0000_0111;
        levels[1].axes = 0b0000_0001;
        assert_eq!(diagnose(levels, [false; COUPLINGS], false), Tower::Ambiguous, "detected, and not invented");
    }

    #[test]
    fn a_tower_decodes_through_the_same_reports_the_federation_uses() {
        // The shared grammar made usable: a tower's word is three Reports, decodable by the horizontal machinery.
        let mut levels = [Level::new(0); HEIGHT as usize];
        levels[2].axes = 0b0000_0100;
        let reports = as_reports(levels, [true, false], false);
        assert_eq!(golay::diagnose(reports, golay::Provenance::Measured), match golay::locate(word(levels, [true, false], false)) {
            Some(f) if f.is_empty() => golay::Verdict::Healthy,
            Some(f) => golay::Verdict::Localized(f),
            None => golay::Verdict::Ambiguous,
        }, "one decoder, two meanings for its coordinates");
    }
}
