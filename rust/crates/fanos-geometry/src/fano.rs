//! The base Fano cell `PG(2, 2)` with compile-time incidence tables (spec §2.2, §2.4).
//!
//! The `q = 2` cell (`N = 7`) is where DIAKRISIS runs (spec §6): seven nodes, seven lines,
//! the Hamming(7,4) / Steane structure, the mediator map. Because it is tiny and fixed, its
//! entire incidence structure is precomputed **at compile time** into `const` tables using
//! raw `GF(2)` arithmetic (addition = XOR, multiplication = AND) — so every Fano query is a
//! table lookup with no runtime field arithmetic at all. The tables are cross-checked
//! against the generic [`Plane`](crate::Plane)`<F2>` in the test suite, giving two
//! independent derivations that must agree.

use fanos_field::F2;

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
