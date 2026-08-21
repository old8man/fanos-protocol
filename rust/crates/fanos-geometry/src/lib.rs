//! # fanos-geometry — the finite projective plane `PG(2, q)`
//!
//! FANOS addresses nodes as **points** of a finite projective plane and organises them into
//! **lines** (quorums / multicast buses). This crate provides that plane, generic over the
//! [`Field`], and the three load-bearing operations of the specification
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
//! The crate is `#![no_std]` and its arithmetic core (points, lines, incidence, mediator tables)
//! needs no allocator. The `alloc` feature gates the heap-backed [`hierarchy`] module — its
//! `HierAddr` is a `Vec`-of-points path — so a pure `--no-default-features` build stays allocator-free.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod element;
pub mod fano;
mod flag;
/// The recursive cell hierarchy (spec §L1). Heap-backed (`HierAddr` is a `Vec` path), so it is
/// gated behind the `alloc` feature — a pure `--no-default-features` build excludes it.
#[cfg(feature = "alloc")]
pub mod hierarchy;
mod plane;
/// The cell's Byzantine fault tolerance — see the module doc for why a consensus
/// quantity is hosted by the crate that owns the cell size.
pub mod tolerance;

pub use tolerance::fault_budget;

pub use element::{
    TRIPLE_WIRE_LEN, Triple, canonicalize, cross, decode_triple, dot, encode_triple,
};
pub use flag::Flag;
#[cfg(feature = "alloc")]
pub use hierarchy::{HierAddr, MAX_DEPTH, derive_address, next_hop, rendezvous};
pub use plane::{Line, Plane, Point, pgl3_order};

/// **How many of a line's `m` points must agree for the line to act** — `t = ⌈2m/3⌉`.
///
/// A line is FANOS's unit of collective action: a mixnet hop peels when `t` of its members do, a rendezvous
/// line serves when `t` of it is occupied, a threshold-hosted descriptor opens at `t` shares. All of them
/// want the same number, and for the same reason — a subset of `m` points carries about `m/3` corrupt in
/// expectation, and `⌈2m/3⌉` is the threshold that preserves the Fano margin at every `m`. At `m = 3` it is
/// `2`, which is what the base cell has always used.
///
/// It lives here, beside the plane, because it is a statement about a **line** rather than about any one
/// subsystem — and because the alternative is each subsystem restating it. `fanos_node::node::mix_threshold`
/// is this function under the mixnet's name, keeping that module's hop-capture derivation where a reader of
/// the mixnet will find it.
///
/// A degenerate line still needs someone to act, hence the floor of one: a quorum of nobody is not a quorum.
#[must_use]
pub const fn line_threshold(line_size: usize) -> usize {
    let t = (2 * line_size).div_ceil(3);
    if t == 0 { 1 } else { t }
}

/// The plane's point count from its line size: `N = q²+q+1` with `q = m − 1`, i.e. `m² − m + 1`.
///
/// Named because two laws below need the plane's size while holding only a line's, and re-deriving `q` at
/// each site is how the two would come to disagree.
#[must_use]
pub const fn plane_points(line_size: usize) -> usize {
    line_size * line_size - line_size + 1
}

/// **How many points of the plane must serve a role before EVERY line carries its
/// [`line_threshold`]** — the count a per-line guarantee costs when the servers are chosen without
/// reference to lines.
///
/// # Why a count of `t` is not this number
///
/// `line_threshold(m) = t` is a statement about **one line**: `t` of its `m` points must act. A cell's
/// role demand, though, is a **count of nodes in the plane**, and `roles::select` fills it by ranking a
/// beacon hash — no line enters that decision. So `t` nodes assigned cell-wide land on a *given* line
/// with the probability of a hypergeometric draw, which on the base cell is
///
/// ```text
///   P(a given line carries t) = C(3,2)/C(7,2) = 3/21 = 0.143
/// ```
///
/// — six lines in seven unusable — and at `q = 7` it is `C(8,6)/C(57,6) ≈ 9·10⁻⁷`. A floor of `t` does
/// not weaken the guarantee it exists to protect; it **inverts** it, in exactly the way that floor's own
/// doc warns about one level down.
///
/// # The derivation
///
/// A line fails when more than `m − t` of its points are withheld. Any `m − t + 1` points **may be
/// collinear** — in a projective plane collinearity is a property of the draw, not of the count — so a
/// count can guarantee the property only by keeping the withheld set at or below that bound:
///
/// ```text
///   floor(m) = N − (m − t),      N = m² − m + 1,   t = ⌈2m/3⌉
/// ```
///
/// `6` of `7` on the base cell; `55` of `57` at `q = 7`.
///
/// # What that says about the role assignment, and it is the point
///
/// The withholding budget `m − t` **is the per-line fault budget the threshold already buys**. So for a
/// role whose work arrives at a *derived* line — a mixnet hop, a service's meeting line, a community's
/// ingress line — the assignment cannot be a rationing device: the work lands where the geometry puts it
/// and provisioning a different node moves none of it. It is an **exclusion** device, and the number of
/// exclusions it may spend is precisely the redundancy the threshold pays for. Asking for `t` nodes was
/// reading a per-line quorum as a cell-wide budget.
#[must_use]
pub const fn points_serving_every_line(line_size: usize) -> usize {
    plane_points(line_size) - (line_size - line_threshold(line_size))
}

/// **How many of the plane's lines actually reach `t` — the exact answer where
/// [`points_serving_every_line`] gives only the threshold at which it is guaranteed.**
///
/// The floor answers *"how many points make EVERY line servable, whatever the draw"*. Below it the count
/// alone says nothing: on `PG(2,4)` five occupied points leave **zero** servable lines in 91.6 % of
/// placements and exactly one in the other 8.4 % (exhaustive over all `C(21,5)`), so `5 of 20` and
/// `19 of 20` are the same sentence about a cell that can complete no threshold operation anywhere and a
/// cell one point short of perfect. This distinguishes them, and it is a **measurement, not a probability**:
/// the caller holds the occupancy, so the answer is exact.
///
/// The distinction earns its place because it was needed and missing. A five-node fixture on `PG(2,4)`
/// (`M/N = 0.24`) raised `gather.expired` 15–30 times per node per minute and `role.under_provisioned` on
/// all six roles, and both were read as flakiness for as long as the only available statement was "below
/// floor". Zero servable lines says the same thing in a form that cannot be misread: **every gather the
/// cell draws must expire, because no line it could draw holds `t` members.**
///
/// **Sizing lives in [`members_for_a_covered_plane`] and is deliberately not restated here.** A cell is
/// sized in *nodes* while a plane is counted in *points*, they are not the same number, and the ratio is
/// not 1 — but the figures that say by how much belong in one place.
///
/// ⛔ This paragraph used to carry its own copy: *"`M = N` clears the floor 87 % on `PG(2,2)` and 25 % on
/// `PG(2,4)`, `M ≈ 1.5·N` ~99 % on both."* Every one of those numbers is from the table refuted on
/// 2026-08-19, and the refutation's own note said the last surviving copy was in `role_loop`'s
/// under-provisioning report. It was not: it was here, two functions above the correction, in the doc an
/// operator reads *first* because it is the function that names the floor. The shipping enumeration reads
/// `1.0 N` → **32.7 % / 0.0 %** and `1.5 N` → **74.5 % / 7.5 %** — so the old copy would have sized a
/// `PG(2,4)` testnet at `1.5 N` against a real 7.5 % chance of being able to carry a single anonymous hop.
///
/// A number quoted in two places is a number that will diverge; the link is the fix, not a corrected copy.
#[must_use]
pub fn servable_lines<F: Field>(occupied: impl Fn(Point<F>) -> bool) -> usize {
    let t = line_threshold(Plane::<F>::LINE_SIZE as usize);
    Plane::<F>::lines()
        .filter(|&line| Plane::<F>::points_on(line).filter(|&p| occupied(p)).count() >= t)
        .count()
}

/// **How many NODES a cell wants before its plane is covered** — the sizing constant a deployment needs and
/// nothing states.
///
/// A plane is counted in points; a cell is sized in members; and they are not the same number, because
/// members contend for points. Each node draws a coordinate and, when it is taken, walks the `q + 1` points
/// of one line through it (`fanos_vrf::probe_walk`) — so the occupancy a cell reaches is strictly below its
/// membership, and the shortfall grows with load.
///
/// ⛔ **This returned `3·N/2` until 2026-08-19, on a table that does not reproduce.** The doc recorded
/// *"1.5 → 99.7 % on `PG(2,2)`, 99.2 % on `PG(2,4)`"*. Enumerated through the **shipping** arbitration —
/// `settle_index` at complete knowledge, which is order-independent and therefore the fixed point a run
/// converges to — the same load reads **74.5 %** and **7.5 %**
/// (`fanos-vrf/examples/line_confinement_coverage.rs`), and a live cell reads 75 % beside it. One candidate
/// explanation for the gap was tested and refuted: counting each node's *preferred* point instead of its
/// settled one gives *lower* coverage, not higher. The old table's method is not recoverable from its
/// description; two independent measurements agree against it.
///
/// | load | `PG(2,2)` clears the floor | `PG(2,4)` |
/// |---|---|---|
/// | `1.0 N` | 32.7 % | 0.0 % |
/// | `1.5 N` (what this used to return) | 74.5 % | 7.5 % |
/// | `2 N` | 93.8 % | 51.8 % |
/// | `3 N` | 99.4 % | 90.5 % |
/// | `4 N` | 99.9 % | 98.0 % |
///
/// **And the load is not a constant multiple of `N` at all** — coverage at a *fixed* ratio falls as the
/// plane grows (74.5 % against 7.5 % at the same 1.5), so no single ratio can serve two planes. What the
/// numbers follow is the coupon-collector shape: line-confined draws must cover `N − d` of `N` points,
/// where `d` is what the viability floor may leave empty, and that costs about `N·(H(N) − H(d))` draws.
///
/// ⛔ **And the load this table prices is a property of the arbitration, not of the plane.** Measured
/// 2026-08-21 on the same draws and the same walks, with one change — a contender blocks a point only when
/// it actually takes that point (`fanos-vrf/examples/line_confinement_coverage.rs`):
///
/// | load | shipping `PG(2,2)` | deferred | shipping `PG(2,4)` | deferred |
/// |---|---|---|---|---|
/// | `1.0 N` | 32.7 % | **80.5 %** | 0.0 % | **14.2 %** |
/// | `1.5 N` | 74.5 % | **99.2 %** | 7.5 % | **97.5 %** |
/// | the constant | 96.6 % | 100 % | 98.0 % | 100 % |
///
/// A maximum matching over the same admissible sets clears the floor in **99.1 %** and **99.5 %** of draws
/// at `1.0 N`, so line confinement is almost never what leaves a point empty. **This constant exists to buy
/// back the phantom yield** — a contender that displaces a node from a point it will not occupy — and that
/// is worth stating where the number is read, because it is the difference between "the plane needs this
/// many nodes" and "this rule does". The rule is the one that ships, so the constant stands; see
/// `fanos_vrf::settle_index` for what the property costs and what giving it up would require.
///
/// So the `3/2` was the right factor applied to the wrong base. It is kept — as **confidence over the
/// expectation** rather than slack over the point count — and it lands both planes where a deployment wants
/// them: `PG(2,2)` at **16** members (between the measured 93.8 % and 99.4 %) and `PG(2,4)` at **84**, which
/// is exactly the 98 % row. A cell asking "how many members before my lines work" is asking for a load it
/// will usually clear at, and that is the one choice in here — stated, so it can be revisited against the
/// table above rather than re-derived.
///
/// **What the surplus costs, since it is most of the cell.** At this load **59 %** of a Fano cell's members
/// and **75 %** of a `PG(2,4)` cell's hold no seat at any given moment — 9.4 of 16 and 63.2 of 84, measured
/// by the same enumeration. They are the draw's spare candidates and the coverage above is what they buy;
/// but production sets `hier_path: None` everywhere, so there is no sub-cell for them to be in and they are
/// unaddressable while they wait. A deployment reading this number is being told to run a cell most of which
/// cannot serve, which is the strongest argument in the tree for wiring the descent.
///
/// `servable_lines` remains the exact question a running cell should ask about *itself*; this is the demand
/// figure a deployment is sized against.
#[must_use]
pub const fn members_for_a_covered_plane(line_size: usize) -> usize {
    let n = plane_points(line_size);
    // The points the viability floor may leave empty — `N − points_serving_every_line(m)`.
    let spare = line_size / 3;
    // `N · (H(N) − H(spare))`, summed in integers with rounding: the expected number of line-confined draws
    // before every point but `spare` of them is held.
    let (mut k, mut draws) = (spare + 1, 0);
    while k <= n {
        draws += (n + k / 2) / k;
        k += 1;
    }
    draws * 3 / 2
}

// Re-export the field crate so downstream users get a matched version.
pub use fanos_field::{self, Field};

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::{F2, F7, F13, F31};

    /// **`points_serving_every_line` is EXACT, proved by exhausting every placement on the base cell.**
    ///
    /// The claim is not "this many is enough" but "this many is the first count that is enough, whatever the
    /// draw" — and on `PG(2,2)` that is checkable in full: all `2⁷` subsets, all 7 lines. A sampled check
    /// could not distinguish an exact bound from a conservative one, and a conservative floor here would be
    /// a real cost (it is a demand the cell escalates as a deficit when supply falls short).
    ///
    /// What the exhaustion shows, and why the shipped floor of `t = 2` was not merely low: at `D = 4` a whole
    /// line can still be **empty**, and only at `D = 6` does every line carry its quorum.
    /// **The floor and the measurement agree, and the measurement is the sharper of the two.**
    ///
    /// Exhaustive over every subset of `PG(2,2)`'s seven points, and it pins three separate facts:
    ///
    /// * at the floor (`6`) **every** placement serves all seven lines — the floor's own claim, restated as a
    ///   count rather than a predicate;
    /// * one point below it (`5`) **every** placement serves exactly six — a single value, not a range, so
    ///   the last line is lost to the geometry and no draw or reseating recovers it;
    /// * below that the count spreads (`4` gives four or six), which is exactly the regime where
    ///   `points_serving_every_line` alone cannot answer and this can.
    ///
    /// `F7` then checks the same shape on a plane large enough that "all lines" and "the floor" are not
    /// adjacent numbers: `57` points, `d = m − t = 2`, so the floor is `55`.
    /// **The sizing constant is above the floor it exists to reach, at every order** — the one property
    /// that makes `members_for_a_covered_plane` an answer rather than a ratio.
    ///
    /// A cell of that many members must be able, in principle, to occupy `points_serving_every_line` of its
    /// plane; a recommendation below its own floor would be worse than none. Checked on every order the
    /// tree instantiates and on the two it merely defines, because the relation is a coupon-collector sum
    /// against `N − ⌊(q+1)/3⌋` and those grow differently — the sum grows like `N ln N`, so the margin over
    /// the floor *widens* with the plane rather than staying a ratio, which is the property the old `3N/2`
    /// did not have and the reason it read 7.5 % on `PG(2,4)`.
    #[test]
    fn the_sizing_constant_clears_the_floor_it_exists_to_reach() {
        for line_size in 3..=40usize {
            let (n, floor, want) = (
                plane_points(line_size),
                points_serving_every_line(line_size),
                members_for_a_covered_plane(line_size),
            );
            assert!(
                want >= floor,
                "a cell of {want} members cannot be expected to occupy {floor} of {n} points on a plane \
                 with {line_size}-point lines — the recommendation would sit below its own viability floor"
            );
            // And it is a *surplus*, not a coincidence of rounding: the excess over the plane is what fills
            // the last points, and it must exist at every order rather than only at large ones.
            assert!(want > n, "sizing at or below the point count is what makes M = N clear the floor 25% \
                 of the time on PG(2,4); the constant exists to say so");
        }
        // The two orders the base tier uses, spelled out so a reader sees the numbers rather than the rule
        // — and pinned by **what they were measured to buy**, not by the arithmetic that produced them.
        // `fanos-vrf/examples/line_confinement_coverage.rs` enumerates the shipping arbitration at complete
        // knowledge: 16 on `PG(2,2)` sits between the 93.8 % of `2N` and the 99.4 % of `3N`, and 84 on
        // `PG(2,4)` is exactly its 98 % row. These read 10 and 31 until 2026-08-19, which the same
        // enumeration prices at **74.5 %** and **7.5 %**.
        assert_eq!((plane_points(3), members_for_a_covered_plane(3)), (7, 16), "PG(2,2): 7 points, 16 nodes");
        assert_eq!((plane_points(5), members_for_a_covered_plane(5)), (21, 84), "PG(2,4): 21 points, 84 nodes");
    }

    #[test]
    fn servable_lines_is_exact_where_the_floor_is_only_a_threshold() {
        let n = Plane::<F2>::N as usize;
        let mut by_size: alloc::collections::BTreeMap<usize, alloc::collections::BTreeSet<usize>> =
            alloc::collections::BTreeMap::new();
        for mask in 0u32..(1 << n) {
            let occupied = |p: Point<F2>| mask & (1 << p.index()) != 0;
            by_size
                .entry(mask.count_ones() as usize)
                .or_default()
                .insert(servable_lines::<F2>(occupied));
        }
        let floor = points_serving_every_line(Plane::<F2>::LINE_SIZE as usize);
        assert_eq!(floor, 6, "the base cell's coverage floor");
        assert_eq!(
            by_size.get(&floor),
            Some(&alloc::collections::BTreeSet::from([7usize])),
            "at the floor EVERY placement must serve every line — that is what the floor asserts, and a \
             single value here is what makes it a floor rather than an average"
        );
        assert_eq!(
            by_size.get(&(floor - 1)),
            Some(&alloc::collections::BTreeSet::from([6usize])),
            "one point below it, every placement serves exactly six of seven: the missing line is forced by \
             the geometry, so no draw and no reseating can recover it"
        );
        assert!(
            by_size.get(&4).is_some_and(|v| v.len() > 1),
            "and further down the count spreads, which is the regime the floor cannot describe and this can"
        );

        // The same shape one plane up, where the floor and full coverage are two points apart.
        let big = points_serving_every_line(Plane::<F7>::LINE_SIZE as usize);
        assert_eq!((Plane::<F7>::N as usize, big), (57, 55), "PG(2,7): 57 points, d = m - t = 2");
        assert_eq!(
            servable_lines::<F7>(|_| true),
            57,
            "a full plane serves every line, and there are as many lines as points"
        );
        assert_eq!(servable_lines::<F7>(|_| false), 0, "an empty plane serves none");
    }

    #[test]
    fn the_coverage_floor_is_the_first_count_that_survives_every_placement() {
        let lines: Vec<Vec<usize>> = Plane::<F2>::lines()
            .map(|l| Plane::<F2>::points_on(l).map(|p| p.index()).collect())
            .collect();
        assert_eq!(lines.len(), 7, "the base cell has seven lines, and this walks all of them");

        let t = line_threshold(Plane::<F2>::LINE_SIZE as usize);
        // For each size, the WORST placement: the fewest points any line ends up carrying.
        let worst = |d: u32| -> usize {
            (0..1u32 << 7)
                .filter(|mask| mask.count_ones() == d)
                .map(|mask| {
                    lines
                        .iter()
                        .map(|l| l.iter().filter(|&&p| mask >> p & 1 == 1).count())
                        .min()
                        .unwrap_or(0)
                })
                .min()
                .unwrap_or(0)
        };

        let floor = points_serving_every_line(Plane::<F2>::LINE_SIZE as usize);
        assert_eq!(floor, 6, "N − (m − t) = 7 − 1 on the base cell");
        assert!(worst(floor as u32) >= t, "at the floor, no placement can starve a line");
        assert!(
            worst(floor as u32 - 1) < t,
            "and one below it, some placement does — so the floor is exact, not conservative"
        );
        // The shipped floor used to be `t` itself. Stated as its own consequence rather than as a smaller
        // number: at that count a line can be reached by NOBODY.
        assert_eq!(worst(t as u32), 0, "a demand of t leaves some line with zero of its points serving");
        assert_eq!(worst(4), 0, "and so does four of seven — the empty line survives past half the cell");
    }

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

    /// **Two corrupt points can never own both ends of a circuit** — the mixnet's end-to-end guarantee, and a
    /// fact about the plane rather than about any threshold tuning.
    ///
    /// A MIX hop is a *line*, peeled by a threshold of its `q+1 = 3` members (`MIX_THRESHOLD = 2`), so a hop
    /// falls when two of its points are corrupt. Two points lie on exactly one line, so **at most one line is
    /// ever captured while at most two points are corrupt** — and one line cannot be both the first and the
    /// last hop. Since only first-and-last correlation deanonymizes (a captured middle hop learns which relays
    /// flank it, not the client or the destination), end-to-end deanonymization is *impossible* inside the
    /// Byzantine tolerance `f = ⌊(n−1)/3⌋ = 2`.
    ///
    /// Enumerated rather than argued, because the argument was got wrong twice (`docs/audit.md` E7): a Chernoff
    /// bound over the same quantity gave 3.9 %, by assuming an independence between hops that an incidence
    /// structure does not have. **And the guarantee does not generalize** — it rests on `f = t = 2`, an accident
    /// of the smallest plane, which is why the second half of this test pins the boundary rather than the
    /// property alone.
    #[test]
    fn two_corrupt_points_can_never_capture_two_distinct_lines() {
        /// Lines holding at least `t` corrupt points — a captured hop.
        fn captured(corrupt: u8, t: u32) -> Vec<usize> {
            (0..fano::N).filter(|&l| (fano::INCIDENCE[l] & corrupt).count_ones() >= t).collect()
        }

        for corrupt in 0u8..=0x7F {
            if corrupt.count_ones() > 2 {
                continue;
            }
            assert!(
                captured(corrupt, 2).len() <= 1,
                "corrupt {corrupt:#09b} captured {} lines — two points lie on exactly one line, so at most one \
                 hop can fall and first-and-last correlation must be impossible",
                captured(corrupt, 2).len()
            );
        }

        // The bound is *tight*, not vacuous: three corrupt points capture three lines when they are not
        // collinear — which is where end-to-end correlation becomes possible, and exactly where consensus
        // halts, since `f = 2`. Without this half the test would pass on a plane where nothing is ever
        // captured at all.
        assert!(
            (0u8..=0x7F).filter(|c| c.count_ones() == 3).any(|c| captured(c, 2).len() == 3),
            "at three corrupt points the guarantee must break, or it proves nothing"
        );
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
