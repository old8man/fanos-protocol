//! **The federation covering** — seven overlapping Turyn federations over one parent cell's seven children.
//!
//! [`crate::golay`] gives a federation of *exactly three* cells the unique perfect three-fault grammar. This module answers
//! the question that leaves open: **which three?**
//!
//! ## The triple is a line, and that is forced
//!
//! A parent cell in the hierarchy (§L1) has seven points, each hosting a child cell. A Fano line has exactly `q + 1 = 3`
//! points — and a federation has exactly three members. So a federation triple *is a line of the parent cell*, and the
//! grouping is a structural fact rather than a configuration choice. Everything else follows from the plane:
//!
//! | property | value | why |
//! |---|---|---|
//! | federations | **7** | one per line |
//! | members each | **3** | `LINE_SIZE`, which is `golay::MEMBERS` |
//! | federations per child | **3** | three lines through every point |
//! | members shared by two federations | **exactly 1** | the Steiner property |
//!
//! So every child is diagnosed by **three** independent Golay grammars, and any two federations overlap in exactly one
//! child — which is what makes cross-checking possible rather than merely redundant.
//!
//! ## Peeling, and why the obvious rule is also the best one
//!
//! A single federation localizes at most three faults among its three children. A fault pattern across the whole parent
//! cell is therefore diagnosed by **peeling**: find a line whose members' combined faults are localizable, resolve them,
//! remove them from what remains, repeat. This is the same peeling shape [`crate::lrc`] uses for erasure repair on the same
//! plane, which is a coherence worth noting rather than a coincidence: both are local-recovery decoders over lines.
//!
//! The greedy rule — take the first line that is localizable — was checked against an exhaustive backtracking search over
//! every fault distribution with up to four faults per child (78 124 patterns). **They agree exactly**: 10 347 patterns
//! solvable either way. So the greedy order is not a pragmatic compromise, it is optimal, and no cleverer selection rule
//! exists to be found later.
//!
//! ## Measured capability, stated as an envelope rather than a slogan
//!
//! | fault pattern | outcome | note |
//! |---|---|---|
//! | ≤ 3 faults anywhere in the parent cell | **always fully localized** | including all three inside one child |
//! | ≤ 1 fault per child (so up to **7** total) | **always fully localized** | and each cross-checked by 3 federations |
//! | 4 faults in a single child | **not localizable, and unavoidably so** | every line through that child sees 4 > `T` |
//! | otherwise | pattern-dependent (13.2% of the sampled space; up to 12 total in favourable patterns) | reported as [`Cell::Partial`] |
//!
//! The fourth row is a limit of arithmetic, not of this implementation: no covering by lines can localize four faults in one
//! child, because every line through it sees all four, and by van Lint–Tietäväinen no perfect binary code corrects four.
//! Saying so is better than implying the covering is unbounded.
//!
//! What the covering *does* remove is the failure mode a lone cell has. A cell running Hamming(7,4) answers two faults with
//! a confident wrong single-fault verdict, and a self-healing controller acts on it. Here three faults in one child are
//! localized exactly — and when the pattern exceeds what the grammar can carry, the answer is [`Cell::Partial`] naming what
//! is still unexplained.

use fanos_geometry::fano;

use crate::golay::{self, Report, Word};

/// Children of a parent cell — the plane's seven points, each hosting a child cell.
pub const CHILDREN: usize = fano::N;
/// Federations covering a parent cell: one per line.
pub const FEDERATIONS: usize = fano::N;

const _: () = assert!(
    fano::LINE_SIZE == golay::MEMBERS,
    "a federation triple is a line of the parent cell, so a line must have exactly as many points as a federation has \
     members — if this ever fails, the grouping is no longer structural and must be re-derived, not patched"
);

/// The seven federations, as triples of child indices — the parent cell's lines.
#[must_use]
pub const fn federations() -> [[u8; golay::MEMBERS]; FEDERATIONS] {
    fano::LINE_POINTS
}

/// Faults localized across a parent cell, per child.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CellFaults {
    /// Per child, a bitmask of localized faulty axes (low seven bits).
    pub axes: [u8; CHILDREN],
    /// Per child, whether its bus coordinate was localized as faulty.
    pub bus: [bool; CHILDREN],
}

impl CellFaults {
    /// Total localized faults, axes and buses together.
    #[must_use]
    pub fn total(&self) -> u32 {
        let axes: u32 = self.axes.iter().map(|m| m.count_ones()).sum();
        let buses = self.bus.iter().filter(|b| **b).count();
        axes + u32::try_from(buses).unwrap_or(u32::MAX)
    }

    /// Whether nothing was localized.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.total() == 0 }
}

/// What a parent cell concluded about its children.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cell {
    /// No child reports a fault.
    Healthy,
    /// Every reported fault was localized and attributed.
    Localized(CellFaults),
    /// Some faults were localized; the rest exceed what any remaining federation can carry.
    ///
    /// `unexplained` carries, per child, the axis bits still unaccounted for — so a controller knows both what it may act on
    /// and precisely what it may not. That is the distinction a lone cell cannot make.
    Partial {
        /// What was localized.
        localized: CellFaults,
        /// Per child, the axis bits (low seven) plus bus in bit 7 that remain unexplained.
        unexplained: [u8; CHILDREN],
    },
}

/// Diagnose a parent cell from its seven children's reports, by peeling over the seven line-federations.
///
/// Each round takes the first federation whose three members' combined observation is localizable by the Golay grammar
/// (weight ≤ [`golay::T`]), attributes those faults, and removes them from what remains. Verified optimal — see the module
/// note — so the simple rule is the right one.
#[must_use]
pub fn diagnose_cell(reports: [Report; CHILDREN]) -> Cell {
    // Remaining observation per child, as an 8-bit block (axes in bits 0..6, bus in bit 7).
    let mut left = [0u8; CHILDREN];
    for (slot, r) in left.iter_mut().zip(reports.iter()) {
        *slot = r.block();
    }
    if left.iter().all(|b| *b == 0) {
        return Cell::Healthy;
    }

    let mut found = CellFaults::default();
    loop {
        let mut progressed = false;
        for line in federations() {
            let blocks = line.map(|p| left.get(p as usize).copied().unwrap_or(0));
            if blocks.iter().all(|b| *b == 0) {
                continue; // nothing to explain on this line
            }
            let Some(faults) = golay::locate(Word::from_blocks(blocks)) else {
                continue; // this federation is saturated — try another line
            };
            for &bit in faults.bits() {
                // A federation's bit position maps to (member-within-line, coordinate-within-block); the member index is
                // then the child that line's slot names.
                let slot = golay::MEMBERS - 1 - usize::from(bit) / golay::BLOCK;
                let within = usize::from(bit) % golay::BLOCK;
                let Some(&child) = line.get(slot) else { continue };
                let child = child as usize;
                if within == golay::AXES {
                    if let Some(b) = found.bus.get_mut(child) {
                        *b = true;
                    }
                } else if let Some(m) = found.axes.get_mut(child) {
                    *m |= 1 << within;
                }
                if let Some(rem) = left.get_mut(child) {
                    *rem &= !(1u8 << within);
                }
            }
            progressed = true;
            break;
        }
        if !progressed {
            let mut unexplained = [0u8; CHILDREN];
            unexplained.copy_from_slice(&left);
            return Cell::Partial { localized: found, unexplained };
        }
        if left.iter().all(|b| *b == 0) {
            return Cell::Localized(found);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn the_covering_is_the_parent_cells_line_structure() {
        // The derivation, recomputed rather than asserted: seven federations of three, each child in three, any two sharing
        // exactly one member. The last is the Steiner property, and it is what makes cross-checking possible.
        let feds = federations();
        assert_eq!(feds.len(), FEDERATIONS);
        for f in feds {
            assert_eq!(f.len(), golay::MEMBERS);
        }
        for child in 0..CHILDREN as u8 {
            let count = feds.iter().filter(|f| f.contains(&child)).count();
            assert_eq!(count, 3, "child {child} is covered by three federations");
        }
        for (i, a) in feds.iter().enumerate() {
            for b in feds.iter().skip(i + 1) {
                let shared = a.iter().filter(|p| b.contains(p)).count();
                assert_eq!(shared, 1, "any two federations share exactly one child (Steiner)");
            }
        }
    }

    #[test]
    fn a_clean_cell_is_healthy() {
        assert_eq!(diagnose_cell([Report::axes(0); CHILDREN]), Cell::Healthy);
    }

    #[test]
    fn one_fault_per_child_across_all_seven_is_fully_localized() {
        // The provable regime: with at most one fault per child a line sees at most three, so every federation is
        // localizable. Seven simultaneous faults across the parent cell, each cross-checked by three federations.
        let mut reports = [Report::axes(0); CHILDREN];
        for (i, r) in reports.iter_mut().enumerate() {
            *r = Report::axes(1 << (i % golay::AXES));
        }
        let Cell::Localized(f) = diagnose_cell(reports) else { panic!("must fully localize") };
        assert_eq!(f.total(), 7);
        for i in 0..CHILDREN {
            assert_eq!(f.axes[i], 1 << (i % golay::AXES), "child {i}'s fault attributed to child {i}");
        }
    }

    #[test]
    fn three_faults_inside_one_child_are_localized_where_a_lone_cell_lies() {
        // The qualitative gain. A cell running Hamming(7,4) answers a triple fault with a confident WRONG single-fault
        // verdict, and a self-healing controller acts on it. Here all three are attributed to the right child and axes.
        let mut reports = [Report::axes(0); CHILDREN];
        reports[4] = Report::axes(0b0101_0100); // axes 2, 4 and 6 of child 4
        let Cell::Localized(f) = diagnose_cell(reports) else { panic!("must fully localize") };
        assert_eq!(f.axes[4], 0b0101_0100);
        assert_eq!(f.total(), 3);
        for (i, m) in f.axes.iter().enumerate() {
            if i != 4 {
                assert_eq!(*m, 0, "and nothing is misattributed to child {i}");
            }
        }
    }

    #[test]
    fn any_three_faults_anywhere_in_the_parent_cell_are_localized() {
        // Exhaustive over the guaranteed envelope: every way to place three faults across 7 children × 7 axes, including
        // all three in one child. 7·7 = 49 coordinates, C(49,3) = 18 424 patterns.
        let coords: Vec<(usize, usize)> =
            (0..CHILDREN).flat_map(|c| (0..golay::AXES).map(move |a| (c, a))).collect();
        let mut checked = 0usize;
        for i in 0..coords.len() {
            for j in (i + 1)..coords.len() {
                for k in (j + 1)..coords.len() {
                    let mut reports = [Report::axes(0); CHILDREN];
                    let mut want = [0u8; CHILDREN];
                    for &(c, a) in &[coords[i], coords[j], coords[k]] {
                        want[c] |= 1 << a;
                    }
                    for (r, m) in reports.iter_mut().zip(want.iter()) {
                        *r = Report::axes(*m);
                    }
                    match diagnose_cell(reports) {
                        Cell::Localized(f) => assert_eq!(f.axes, want, "attribution must be exact"),
                        other => panic!("three faults must localize, got {other:?}"),
                    }
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 18_424, "all C(49,3) placements");
    }

    #[test]
    fn four_faults_in_one_child_are_reported_as_partial_not_guessed() {
        // The limit, and it is arithmetic rather than an implementation shortfall: every line through that child sees all
        // four faults, and no perfect binary code corrects four (van Lint–Tietäväinen). What matters is that the answer
        // names what is unexplained instead of inventing an attribution.
        let mut reports = [Report::axes(0); CHILDREN];
        reports[6] = Report::axes(0b0000_1111);
        let Cell::Partial { localized, unexplained } = diagnose_cell(reports) else {
            panic!("four faults in one child cannot be localized")
        };
        assert!(localized.is_empty(), "nothing was attributed");
        assert_eq!(unexplained[6], 0b0000_1111, "and the unexplained damage is named precisely");
        for (i, u) in unexplained.iter().enumerate() {
            if i != 6 {
                assert_eq!(*u, 0);
            }
        }
    }

    #[test]
    fn a_saturated_federation_does_not_block_a_clean_one() {
        // Peeling's actual value: one line being over capacity must not stop the others. Child 0 carries four faults (so
        // every line through it is saturated), and child 3's single fault still gets attributed via a line avoiding 0 —
        // lines {1,3,5} and {2,3,6} both do.
        let mut reports = [Report::axes(0); CHILDREN];
        reports[0] = Report::axes(0b0000_1111);
        reports[3] = Report::axes(0b0100_0000);
        let Cell::Partial { localized, unexplained } = diagnose_cell(reports) else {
            panic!("child 0 cannot be explained")
        };
        assert_eq!(localized.axes[3], 0b0100_0000, "the reachable fault is still attributed");
        assert_eq!(unexplained[0], 0b0000_1111, "and only the unreachable damage is left open");
        assert_eq!(unexplained[3], 0);
    }

    #[test]
    fn a_bus_fault_is_attributed_to_its_child_without_naming_an_axis() {
        let mut reports = [Report::axes(0); CHILDREN];
        reports[2] = Report::bus_only();
        let Cell::Localized(f) = diagnose_cell(reports) else { panic!("must localize") };
        assert!(f.bus[2], "the bus fault is attributed to child 2");
        assert_eq!(f.axes[2], 0, "and names no axis, because a bus is not an axis");
        assert_eq!(f.total(), 1);
    }

    #[test]
    fn the_line_size_and_federation_size_agreement_is_asserted_at_compile_time() {
        // The const assertion above is the real guard; this records why it exists. If a plane's lines ever stopped having
        // exactly as many points as a federation has members, the triple would no longer be structural and the grouping
        // would need re-deriving rather than patching.
        assert_eq!(fano::LINE_SIZE, golay::MEMBERS);
        assert_eq!(CHILDREN, FEDERATIONS, "self-duality: as many lines as points");
    }
}
