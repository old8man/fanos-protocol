//! # fanos-geometry — the finite projective plane `PG(2, q)`
//!
//! FANOS addresses nodes as **points** of a finite projective plane and organises them into
//! **lines** (quorums / multicast buses). This crate provides that plane, generic over the
//! [`Field`](fanos_field::Field), and the three load-bearing operations of the specification
//! (§2.2):
//!
//! * **Rendezvous** — the line through two points is their cross product `u × v`. A single
//!   field operation, no search: [`Point::join`].
//! * **Bridge** — two lines meet in the single point `L₁ × L₂`: [`Line::meet`].
//! * **Incidence** — a point lies on a line iff their dot product vanishes: [`Point::is_on`].
//!
//! From these follow the **Steiner property** (any two points lie on a unique common line)
//! and its dual (any two lines meet in a unique point — the Maekawa quorum-intersection
//! guarantee), both exercised in the test suite.
//!
//! The base cell `PG(2, 2)` (the Fano plane) has a dedicated [`fano`] module whose incidence
//! and mediator tables are computed at compile time.
//!
//! The crate is `#![no_std]`; the `alloc`/`std` features currently only gate downstream
//! conveniences and are off the arithmetic path.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod element;
pub mod fano;
pub mod hierarchy;
mod flag;
mod plane;

pub use element::{
    TRIPLE_WIRE_LEN, Triple, canonicalize, cross, decode_triple, dot, encode_triple,
};
pub use flag::Flag;
pub use hierarchy::{HierAddr, MAX_DEPTH, derive_address, next_hop, rendezvous};
pub use plane::{Line, Plane, Point, pgl3_order};

// Re-export the field crate so downstream users get a matched version.
pub use fanos_field::{self, Field};

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::{F2, F7, F13, F31};

    /// V1: plane parameters `N = q²+q+1`, `q+1` per line, and `|PGL(3,q)|` (spec §2.1, §2.3).
    #[test]
    fn plane_parameters_match_spec() {
        assert_eq!(Plane::<F2>::N, 7);
        assert_eq!(Plane::<F2>::LINE_SIZE, 3);
        assert_eq!(Plane::<F7>::N, 57);
        assert_eq!(Plane::<F7>::LINE_SIZE, 8);
        assert_eq!(Plane::<F13>::N, 183);
        assert_eq!(Plane::<F31>::N, 993);

        // |PGL(3,q)| collineation-group orders (spec §2.1 table).
        assert_eq!(pgl3_order(2), 168);
        assert_eq!(pgl3_order(7), 5_630_688);
        assert_eq!(pgl3_order(13), 810_534_816);
        assert_eq!(pgl3_order(31), 851_974_934_400);
    }

    /// V2 + Appendix C: the cross-product test vectors in `PG(2, 7)`.
    #[test]
    fn cross_product_known_answers() {
        let u = Point::<F7>::new([1, 0, 0]).unwrap();
        let v = Point::<F7>::new([0, 1, 0]).unwrap();
        let w = Point::<F7>::new([1, 2, 3]).unwrap();

        // [1:0:0] × [0:1:0] = [0:0:1], and both points lie on it.
        let luv = u.join(&v).unwrap();
        assert_eq!(luv.coords(), [0, 0, 1]);
        assert!(u.is_on(&luv) && v.is_on(&luv));

        // The bridge of L(u,v) and L(u,w) recovers u = [1:0:0].
        let luw = u.join(&w).unwrap();
        let bridge = luv.meet(&luw).unwrap();
        assert_eq!(bridge, u);
        assert_eq!(bridge.coords(), [1, 0, 0]);
    }

    /// The Steiner property: any two distinct points lie on exactly one common line, and
    /// equal points have no unique join.
    #[test]
    fn steiner_unique_line_through_two_points() {
        for a in Plane::<F7>::points() {
            assert!(a.join(&a).is_none(), "a point has no unique line to itself");
            for b in Plane::<F7>::points() {
                if a == b {
                    continue;
                }
                let l = a.join(&b).expect("distinct points join");
                assert!(a.is_on(&l) && b.is_on(&l), "both endpoints incident");
                // Uniqueness: join is symmetric as a projective line.
                assert_eq!(l, b.join(&a).unwrap());
            }
        }
    }

    /// The dual Steiner property (Maekawa): any two distinct lines meet in exactly one point.
    #[test]
    fn dual_any_two_lines_intersect() {
        for a in Plane::<F7>::lines() {
            for b in Plane::<F7>::lines() {
                if a == b {
                    continue;
                }
                let p = a.meet(&b).expect("distinct lines meet");
                assert!(a.contains(&p) && b.contains(&p), "meet lies on both");
            }
        }
    }

    /// Point/line indexing is a bijection with `0..N`.
    #[test]
    fn index_is_a_bijection() {
        let n = Plane::<F13>::N as usize;
        let mut seen = alloc_seen(n);
        for (i, slot) in seen.iter_mut().enumerate() {
            let p = Point::<F13>::at(i);
            assert_eq!(p.index(), i, "at∘index round-trips");
            *slot = true;
        }
        assert!(seen.iter().all(|&b| b), "every index hit exactly once");
    }

    // Small heap-free "seen" set for the bijection test (std available under cfg(test)).
    fn alloc_seen(n: usize) -> Vec<bool> {
        vec![false; n]
    }

    /// Regularity (spec §2.1): every point is on exactly `q+1` lines and every line has
    /// exactly `q+1` points.
    #[test]
    fn plane_is_regular() {
        for p in Plane::<F7>::points() {
            let deg = Plane::<F7>::lines_through(p).count();
            assert_eq!(deg as u32, Plane::<F7>::LINE_SIZE);
        }
        for l in Plane::<F7>::lines() {
            let size = Plane::<F7>::points_on(l).count();
            assert_eq!(size as u32, Plane::<F7>::LINE_SIZE);
        }
    }

    /// Cross-check: the compile-time Fano tables agree with the generic `Plane<F2>`.
    #[test]
    fn fano_tables_match_generic_plane() {
        // Coordinates.
        for i in 0..fano::N {
            assert_eq!(fano::POINT_COORDS[i], Point::<F2>::at(i).coords());
        }
        // Line membership.
        for l in 0..fano::N {
            let line = Line::<F2>::at(l);
            let mut generic: Vec<usize> = Plane::<F2>::points_on(line).map(|p| p.index()).collect();
            generic.sort_unstable();
            let mut tabled: Vec<usize> = fano::LINE_POINTS[l].iter().map(|&x| x as usize).collect();
            tabled.sort_unstable();
            assert_eq!(generic, tabled, "line {l} membership");
        }
    }

    /// The mediator `k*(i,j)` is the third point of the line through `i` and `j`, distinct
    /// from both, and equal to the XOR of their coordinates (spec §2.5, §6.7).
    #[test]
    fn mediator_is_the_third_collinear_point() {
        for i in 0..fano::N {
            for j in 0..fano::N {
                if i == j {
                    assert_eq!(fano::mediator(i, j), None);
                    continue;
                }
                let k = fano::mediator(i, j).expect("distinct points have a mediator");
                assert_ne!(k, i);
                assert_ne!(k, j);
                let pi = Point::<F2>::at(i);
                let pj = Point::<F2>::at(j);
                let pk = Point::<F2>::at(k);
                let line = pi.join(&pj).unwrap();
                assert!(pk.is_on(&line), "mediator lies on the pair's line");
                // Over GF(2), the third point is the coordinate XOR.
                let ci = pi.coords();
                let cj = pj.coords();
                assert_eq!(pk.coords(), [ci[0] ^ cj[0], ci[1] ^ cj[1], ci[2] ^ cj[2]]);
            }
        }
    }

    /// Every Fano line has three points and every point is on three lines (regularity of
    /// the const tables).
    #[test]
    fn fano_tables_are_regular() {
        for l in 0..fano::N {
            assert_eq!(fano::INCIDENCE[l].count_ones(), 3);
        }
        // Each point index appears in exactly three lines.
        let mut appearances = [0u32; fano::N];
        for line in &fano::LINE_POINTS {
            for &p in line {
                appearances[p as usize] += 1;
            }
        }
        assert!(appearances.iter().all(|&c| c == 3));
    }
}
