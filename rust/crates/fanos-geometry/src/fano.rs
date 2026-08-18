//! The base Fano cell `PG(2, 2)` with compile-time incidence tables (spec §2.2, §2.4).
//!
//! The `q = 2` cell (`N = 7`) is where DIAKRISIS runs (spec §6): seven nodes, seven lines,
//! the Hamming(7,4) / Steane structure, the mediator map. Because it is tiny and fixed, its
//! entire incidence structure is precomputed **at compile time** into `const` tables using
//! raw `GF(2)` arithmetic (addition = XOR, multiplication = AND) — so every Fano query is a
//! table lookup with no runtime field arithmetic at all. The tables are cross-checked
//! against the generic [`Plane`](crate::Plane)`<F2>` in the test suite, giving two
//! independent derivations that must agree.

use fanos_field::{F2, Field};

use crate::element::Triple;
use crate::plane::{Line, Point};

/// The number of points (and lines) of the Fano plane.
pub const N: usize = 7;
/// Points per line (and lines per point): `q + 1 = 3`.
pub const LINE_SIZE: usize = 3;

/// Canonical coordinates of point/line index `i` (`q = 2` enumeration, see [`Point::index`]).
const fn coords_at(i: usize) -> Triple {
    if i < 4 {
        [1, (i / 2) as u32, (i % 2) as u32]
    } else if i < 6 {
        [0, 1, (i - 4) as u32]
    } else {
        [0, 0, 1]
    }
}

/// The canonical index of a `GF(2)` coordinate triple (inverse of [`coords_at`]).
const fn index_of(c: Triple) -> usize {
    match c {
        [1, y, z] => (y as usize) * 2 + z as usize,
        [0, 1, z] => 4 + z as usize,
        _ => 6,
    }
}

/// Incidence over `GF(2)`: `p · l = (px∧lx) ⊕ (py∧ly) ⊕ (pz∧lz) = 0`.
const fn incident_gf2(p: Triple, l: Triple) -> bool {
    ((p[0] & l[0]) ^ (p[1] & l[1]) ^ (p[2] & l[2])) & 1 == 0
}

#[allow(clippy::indexing_slicing)] // const table builders index by construction-bounded counters
const fn build_point_coords() -> [Triple; N] {
    let mut a = [[0u32; 3]; N];
    let mut i = 0;
    while i < N {
        a[i] = coords_at(i);
        i += 1;
    }
    a
}

#[allow(clippy::indexing_slicing)]
const fn build_line_points() -> [[u8; LINE_SIZE]; N] {
    let mut out = [[0u8; LINE_SIZE]; N];
    let mut l = 0;
    while l < N {
        let lc = coords_at(l);
        let mut found = [0u8; LINE_SIZE];
        let mut count = 0;
        let mut p = 0;
        while p < N {
            if incident_gf2(coords_at(p), lc) {
                found[count] = p as u8;
                count += 1;
            }
            p += 1;
        }
        assert!(count == LINE_SIZE, "every Fano line has exactly 3 points");
        out[l] = found;
        l += 1;
    }
    out
}

#[allow(clippy::indexing_slicing)]
const fn build_incidence() -> [u8; N] {
    let mut inc = [0u8; N];
    let mut l = 0;
    while l < N {
        let lc = coords_at(l);
        let mut p = 0;
        while p < N {
            if incident_gf2(coords_at(p), lc) {
                inc[l] |= 1 << p;
            }
            p += 1;
        }
        l += 1;
    }
    inc
}

#[allow(clippy::indexing_slicing)]
const fn build_mediator() -> [[i8; N]; N] {
    let mut m = [[-1i8; N]; N];
    let mut i = 0;
    while i < N {
        let ci = coords_at(i);
        let mut j = 0;
        while j < N {
            if i != j {
                let cj = coords_at(j);
                // Over GF(2) the third point of a line is the XOR of the other two.
                let third = [ci[0] ^ cj[0], ci[1] ^ cj[1], ci[2] ^ cj[2]];
                m[i][j] = index_of(third) as i8;
            }
            j += 1;
        }
        i += 1;
    }
    m
}

/// Canonical coordinates of each Fano point, indexed `0..7`.
pub const POINT_COORDS: [Triple; N] = build_point_coords();

/// The three point-indices lying on each line, indexed by line `0..7`.
pub const LINE_POINTS: [[u8; LINE_SIZE]; N] = build_line_points();

/// The three line-indices through each point, indexed by point `0..7`.
///
/// Equal to [`LINE_POINTS`] by self-duality: point `p` is on line `l` iff point `l` is on
/// line `p`, so the incidence relation is a symmetric `7×7` table.
pub const POINT_LINES: [[u8; LINE_SIZE]; N] = LINE_POINTS;

/// Bitmask of points on each line: bit `p` of `INCIDENCE[l]` is set iff point `p` is on
/// line `l`. Each entry has exactly three bits set (spec §2.2).
pub const INCIDENCE: [u8; N] = build_incidence();

/// The mediator map `k*(i, j)`: the third point of the line through points `i` and `j`
/// (spec §2.5). `MEDIATOR[i][j]` is that point's index, or `-1` when `i == j`.
///
/// This is the corpus **polar point** `π(i,j)`, and it is the deterministic reroute target
/// (spec §6.7): when the direct channel `(i, j)` fails, traffic falls back through `k*` with
/// no routing tables.
pub const MEDIATOR: [[i8; N]; N] = build_mediator();

/// The mediator (third collinear point) of two distinct Fano points.
///
/// Returns `None` if `i == j` or either index is out of range.
#[must_use]
pub fn mediator(i: usize, j: usize) -> Option<usize> {
    if i >= N || j >= N || i == j {
        return None;
    }
    // Safe indexing: bounds checked above.
    let m = MEDIATOR.get(i)?.get(j)?;
    if *m < 0 { None } else { Some(*m as usize) }
}

/// The typed [`Point`]`<F2>` for a Fano index `0..7`.
///
/// # Panics
/// If `i >= 7`.
#[must_use]
pub fn point(i: usize) -> Point<F2> {
    Point::at(i)
}

/// The typed [`Line`]`<F2>` for a Fano index `0..7`.
///
/// # Panics
/// If `i >= 7`.
#[must_use]
pub fn line(i: usize) -> Line<F2> {
    Line::at(i)
}

/// Seven **distinct** points of `PG(2, q)`, in the canonical position order the incidence tables index.
///
/// `OverlayNode::with_cell_members` accepts a roster and lets everything above it — `polar_class`,
/// `theme_flags`, `cell_liveness`, `grey_rate_matrix` — read [`LINE_POINTS`] on the *index* of a member.
/// Constructing this value is what makes "seven distinct points of this plane" a checked fact instead of
/// a caller's promise, in the shape `fanos_taxis::CellParams` took when its fields went private: a
/// validator a caller can forget is one that will be absent in production.
///
/// # What this deliberately does **not** require, and why the stronger rule is wrong
///
/// I first had it demand that the members **realise** the tables — that `members[l₀..l₂]` be collinear in
/// the transport plane for each of the seven triples — reasoning that otherwise `polar_class` names pairs
/// with no line between them. That is over-strict, and three existing tests failed on it before the
/// reasoning was re-checked:
///
/// * the cell's Fano structure is a **combinatorial labelling of seven members**, not a geometric claim
///   about their coordinates. `polar_class` groups the 21 pairs into 7 classes; `mediator_attestation`
///   computes from a `degraded` mask over *indices*; `grey_rate_matrix` is built from per-peer loss on
///   **direct** connections. The T-226 identities hold by construction of the rate formula.
/// * **nothing routes along a cell line.** Threshold gathers use transport lines from `Plane<F>`;
///   `cell_coord` only *names* a member. So a cell line is never a path that must exist.
/// * and the rule would have been unsatisfiable where the tree actually uses it: an embedded cell on
///   `PG(2,7)` or `PG(2,31)` — both shipped fixtures — cannot be a Fano subplane at all, because a
///   subplane needs `GF(2) ⊆ GF(q)` and both orders are odd primes.
///
/// What the members *must* agree on is the index→member mapping, and that is a **distributed** property
/// no local constructor can check. This type checks what is local: they are points, and they are seven.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellMembers<F: Field> {
    members: [Triple; N],
    plane: core::marker::PhantomData<fn() -> F>,
}

impl<F: Field> CellMembers<F> {
    /// `None` unless every coordinate is a point of `PG(2, q)` and all seven are **distinct** — a repeated
    /// coordinate would make two roster positions the same node, so the reflex would attribute one
    /// member's readings to two seats and its own consistency check could never see it.
    #[must_use]
    pub fn new(members: [Triple; N]) -> Option<Self> {
        let mut points = [Point::<F>::at(0); N];
        for (slot, &coords) in points.iter_mut().zip(members.iter()) {
            *slot = Point::<F>::new(coords)?;
        }
        for (i, a) in points.iter().enumerate() {
            if points.iter().skip(i + 1).any(|b| a == b) {
                return None;
            }
        }
        Some(Self { members, plane: core::marker::PhantomData })
    }

    /// The member coordinates, in the order the incidence tables index them.
    #[must_use]
    pub const fn coords(&self) -> [Triple; N] {
        self.members
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// **What the constructor refuses, and what it deliberately accepts.**
    ///
    /// It refuses a repeated coordinate — two roster positions holding one node — and a triple that is not
    /// a point of the plane. It **accepts** seven points that do not realise the incidence tables, because
    /// the cell's Fano structure is a labelling of members rather than a geometric claim about them; see
    /// the type's doc for why the stronger rule is wrong and which shipped fixtures it would have broken.
    /// Both directions are asserted, because a constructor that refused everything would pass a one-sided
    /// test.
    #[test]
    fn a_roster_is_seven_distinct_points_and_need_not_realise_the_tables() {
        let good: [Triple; N] = core::array::from_fn(|i| Point::<F2>::at(i).coords());
        assert!(CellMembers::<F2>::new(good).is_some(), "the base cell must validate");

        let mut duplicated = good;
        duplicated[6] = duplicated[0];
        assert!(CellMembers::<F2>::new(duplicated).is_none(), "a repeated member is not a roster");

        let mut off_plane = good;
        off_plane[3] = [0, 0, 0];
        assert!(CellMembers::<F2>::new(off_plane).is_none(), "the zero triple is not a point");

        // Accepted on purpose: a transposition breaks the tables' incidence and is still a valid roster.
        let mut swapped = good;
        swapped.swap(1, 2);
        assert!(
            CellMembers::<F2>::new(swapped).is_some(),
            "the order is a labelling the cell must agree on, not a geometry this constructor can check"
        );

        // And the case that made the stronger rule untenable: seven arbitrary points of an ODD-order
        // plane, which can never be a Fano subplane (a subplane needs `GF(2) ⊆ GF(q)`), yet is exactly
        // what the shipped embedded-cell fixtures use.
        let arbitrary: [Triple; N] =
            core::array::from_fn(|i| Point::<fanos_field::F7>::at(i * 5 + 2).coords());
        assert!(
            CellMembers::<fanos_field::F7>::new(arbitrary).is_some(),
            "an embedded roster on PG(2,7) is legitimate and no subplane exists there"
        );
    }

    /// The accessor returns what was accepted, so a caller cannot be handed a different cell than it
    /// validated.
    #[test]
    fn the_accepted_order_is_what_comes_back() {
        let good: [Triple; N] = core::array::from_fn(|i| Point::<F2>::at(i).coords());
        assert_eq!(CellMembers::<F2>::new(good).unwrap().coords(), good);
    }
}
