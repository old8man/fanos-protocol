//! **What names a cell** — the identity every cross-cell directory, committee and diagnosis is keyed by.
//!
//! A cell is a *sibling-set*: the nodes whose addresses share one prefix
//! (`docs/design-hierarchy-recursion.md`, decided 2026-08-18). Addressing builds a trie of **nodes**
//! ([`crate::hierarchy::derive_address`]), so the cell at prefix `P` is the set of nodes at `P ++ [s]` over the points
//! `s`, and its **parent** is the single node holding `P` itself. The base cell — `P` empty — is the plane's own
//! occupants, which is the case that ships.
//!
//! ## The arithmetic that made this look unanswerable, and where it actually lands
//!
//! `fanos_code::federation::CHILDREN` is `7`, while a plane holds [`fano::cells_in`] cells — **1** at `q = 2`, **3** at
//! `q = 4`, **39** at `q = 16`. Read as *"a parent has seven child cells"* that is a contradiction at every order but
//! two, and it is what `crosscell_dir`'s module doc recorded as a design step nobody could take: *"at `q = 16` there are
//! 39 and nothing says which seven"*.
//!
//! The seven are **seats, not cells**. A parent at address `P` has one child cell per Fano cell of the level below it —
//! `cells_in::<F>()` of them — and *each* child cell has exactly `fano::N = 7` seats. So the covering runs once per child
//! cell over its seven seats: once at `q = 2`, three times at `q = 4`, thirty-nine times at `q = 16`. Nothing has to pick
//! seven of anything, and `diagnose_level`'s `[f64; 7]` is the shape of one child cell rather than of a whole level.
//!
//! ## Why enumeration needs no directory
//!
//! A parent's children are `P ++ [s]` for the seven points `s` of the child cell ([`CellPath::member_address`]). That is
//! a pure function of the parent's own address and the plane, so a parent can name every child it must attest **before**
//! any of them has published anything — which is what `crosscell_dir::attest_children` was missing when it had no
//! caller. What a directory supplies is the *contents* of those slots, never which slots exist.
//!
//! ## The identity a hash of this closes (#167)
//!
//! `fanos_runtime`'s `cell_id` folds the genesis seed and the plane's canonical points, and its own doc states the
//! residual: *"two cells of the same deployment still collide, because the runtime has no identity above the base cell
//! to fold in"*. [`CellPath::encode`] **is** that identity, and it distinguishes both directions a bare `cell: u32`
//! cannot: two cells at the same level (different `base`) and two cells at the same `base` under different parents.

use alloc::vec::Vec;

use fanos_field::Field;

use crate::fano::{self, CellMembers};
use crate::hierarchy::{HierAddr, MAX_DEPTH};
use crate::plane::Point;

/// The identity of one **cell**: the sibling-set under a prefix, narrowed to one Fano cell of that level's plane.
///
/// `parent` is the address of the node the cell hangs under — `None` for the base cell, whose members are the plane's
/// own occupants. `base` says *which* of the level's [`fano::cells_in`] cells, and is what a member computes with
/// [`fano::cell_of`] from the point it sits on. At `q = 2` there is one cell per level, so `base` is always `0` and a
/// cell is exactly its prefix.
#[derive(Clone)]
pub struct CellPath<F: Field> {
    parent: Option<HierAddr<F>>,
    base: usize,
}

// `PartialEq`/`Eq`/`Debug` keyed on the fields only, mirroring `HierAddr` and `Point`, so `F` needs no bounds: a
// `CellPath<F>` is comparable and printable for every field. The directories compare generic cell paths to decide
// whether two records describe one cell, where `F` is bounded only by `Field`.
impl<F: Field> PartialEq for CellPath<F> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.base == other.base && self.parent == other.parent
    }
}
impl<F: Field> Eq for CellPath<F> {}
impl<F: Field> core::fmt::Debug for CellPath<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CellPath").field("parent", &self.parent).field("base", &self.base).finish()
    }
}

impl<F: Field> CellPath<F> {
    /// The `base`-th cell of the **plane itself** — the case a single-cell deployment runs.
    ///
    /// `None` when the plane does not split into Fano cells (`7 ∤ N`, so `q ∈ {7, 8, 31}` among the dispatchable
    /// orders) or when `base` is not one of them: a cell that cannot exist must not be nameable, or a directory would
    /// key records by an address no member can ever claim.
    #[must_use]
    pub fn base_cell(base: usize) -> Option<Self> {
        (base < fano::cells_in::<F>()?).then_some(Self { parent: None, base })
    }

    /// The `base`-th child cell of the node addressed `parent`.
    ///
    /// `None` on the same conditions as [`base_cell`](Self::base_cell), and additionally when `parent` already sits at
    /// [`MAX_DEPTH`] — a cell one level below it would have no addressable members.
    #[must_use]
    pub fn under(parent: HierAddr<F>, base: usize) -> Option<Self> {
        if parent.depth() >= MAX_DEPTH {
            return None;
        }
        (base < fano::cells_in::<F>()?).then_some(Self { parent: Some(parent), base })
    }

    /// The cell a node at `addr` is a **member** of: the siblings it shares a prefix with.
    ///
    /// Its seat is the last point of its address and its cell is that point's [`fano::cell_of`], so this is derivable
    /// from what every node already holds — no agreement, no lookup, the same property that makes `cell_of` an answer
    /// to #145 one level down.
    #[must_use]
    pub fn of_member(addr: &HierAddr<F>) -> Option<Self> {
        let (seat, prefix) = addr.points().split_last()?;
        let base = fano::cell_of::<F>(*seat)?;
        let parent = if prefix.is_empty() { None } else { HierAddr::from_path(prefix.to_vec()) };
        if !prefix.is_empty() && parent.is_none() {
            return None; // a prefix that is not itself a valid address names no parent
        }
        Some(Self { parent, base })
    }

    /// The address of the node that **parents** this cell, or `None` for the base cell, which has no parent inside the
    /// deployment.
    #[must_use]
    pub fn parent_address(&self) -> Option<&HierAddr<F>> {
        self.parent.as_ref()
    }

    /// Which Fano cell of its level this is, in `0..fano::cells_in::<F>()`.
    #[must_use]
    pub fn base(&self) -> usize {
        self.base
    }

    /// How deep the cell's **members** sit: `1` for the base cell, one more than the parent's depth otherwise.
    #[must_use]
    pub fn level(&self) -> usize {
        self.parent.as_ref().map_or(1, |p| p.depth() + 1)
    }

    /// The seven points a member of this cell may sit on, in the canonical order every member derives identically.
    #[must_use]
    pub fn seats(&self) -> Option<CellMembers<F>> {
        fano::cell_members_of::<F>(self.base)
    }

    /// The full address of the member at `seat` — the parent's path with that seat's point appended.
    ///
    /// This is the enumeration a parent needs: its children are exactly `member_address(0..fano::N)`, computable before
    /// any of them has spoken.
    #[must_use]
    pub fn member_address(&self, seat: usize) -> Option<HierAddr<F>> {
        let point = Point::<F>::new(*self.seats()?.coords().get(seat)?)?;
        match &self.parent {
            None => Some(HierAddr::root(point)),
            Some(parent) => parent.descended(point),
        }
    }

    /// Every child cell of the node addressed `parent` — one per Fano cell of the level below it.
    ///
    /// The counterpart of [`member_address`](Self::member_address) one level up: together they say a parent's children
    /// are `cells_in × fano::N` addresses, all derived and none negotiated.
    #[must_use]
    pub fn children_of(parent: &HierAddr<F>) -> Vec<Self> {
        let Some(cells) = fano::cells_in::<F>() else { return Vec::new() };
        (0..cells).filter_map(|base| Self::under(parent.clone(), base)).collect()
    }

    /// The canonical bytes a directory slot, a committee record and `cell_id` are keyed by:
    /// `depth(1) ‖ depth × coord(12) ‖ base(4)`, with `depth = 0` for the base cell.
    ///
    /// Depth-first so the encoding is self-delimiting, and `base` last so that reading a slot key does not require
    /// knowing the plane order. Injective in both coordinates: a different prefix and a different `base` each change
    /// the bytes, which is exactly what #167 needs and what a bare `cell: u32` could not express.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = match &self.parent {
            None => alloc::vec![0u8],
            Some(parent) => parent.encode(),
        };
        out.extend_from_slice(&(self.base as u32).to_be_bytes());
        out
    }

    /// Decode [`encode`](Self::encode). `None` on a bad length, a depth past [`MAX_DEPTH`], a non-canonical point, or a
    /// `base` that is not a cell of this plane — the last one because a decoder that accepts an impossible cell hands
    /// its caller a key no member can ever claim.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (addr_bytes, base_bytes) = bytes.split_at_checked(bytes.len().checked_sub(4)?)?;
        let base = u32::from_be_bytes(base_bytes.try_into().ok()?) as usize;
        match addr_bytes {
            [0] => Self::base_cell(base),
            _ => Self::under(HierAddr::decode(addr_bytes)?, base),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;
    use fanos_field::{F2, F4, F7};

    fn p4(i: usize) -> Point<F4> {
        Point::<F4>::at(i)
    }

    /// **Siblings name the same cell, and the naming is a pure function of the seat.**
    ///
    /// `PG(2,4)` splits into three cells, so this can tell "same cell" from "same plane" — the distinction a
    /// `q = 2` fixture cannot make, and the one every cross-cell directory slot turns on.
    ///
    /// Falsified by keying the cell on the point instead of on `cell_of(point)`: points 0 and 3 are members of one
    /// cell and would then name two.
    #[test]
    fn siblings_name_one_cell_and_a_neighbour_names_another() {
        let (mine, sibling, other) = (
            CellPath::of_member(&HierAddr::root(p4(0))).unwrap(),
            CellPath::of_member(&HierAddr::root(p4(3))).unwrap(),
            CellPath::of_member(&HierAddr::root(p4(1))).unwrap(),
        );
        assert_eq!(mine, sibling, "points 0 and 3 are members of cell 0 of PG(2,4)");
        assert_ne!(mine, other, "point 1 is a member of cell 1 and must not share cell 0's identity");
        assert_eq!((mine.base(), mine.level()), (0, 1));
    }

    /// **Two cells of one deployment no longer share an identity (#167).**
    ///
    /// `fanos_runtime`'s `cell_id` folds the genesis seed and the plane's canonical points, and its own doc records
    /// what is left: *"two cells of the same deployment still collide, because the runtime has no identity above the
    /// base cell to fold in"*. This is that identity, and it separates both directions a `cell: u32` cannot — the same
    /// index under two parents, and two indices at one level.
    ///
    /// Falsified by dropping the prefix from [`CellPath::encode`]: the first assertion goes green-to-red immediately,
    /// because a base cell and a sub-cell would then encode identically.
    #[test]
    fn a_prefix_separates_cells_a_flat_index_would_merge() {
        let base = CellPath::<F4>::base_cell(0).unwrap();
        let under_a = CellPath::under(HierAddr::root(p4(2)), 0).unwrap();
        let under_b = CellPath::under(HierAddr::root(p4(5)), 0).unwrap();
        let deeper = CellPath::under(HierAddr::root(p4(2)).descended(p4(5)).unwrap(), 0).unwrap();
        let names: BTreeSet<_> = [&base, &under_a, &under_b, &deeper].iter().map(|c| c.encode()).collect();
        assert_eq!(names.len(), 4, "four distinct cells, and each must have its own name");
        assert_ne!(base.encode(), under_a.encode(), "a base cell and a child cell with the same index");
        assert_ne!(under_a.encode(), under_b.encode(), "the same index under two different parents");
    }

    /// **A parent enumerates its children with no directory at all** — which is what `attest_children` was missing.
    ///
    /// The addresses are derived from the parent's own address and the plane: `cells_in` child cells, seven seats
    /// each, every one distinct, and each seat's own [`CellPath::of_member`] agrees with the cell it was enumerated
    /// from. That last assertion is the one that matters — it is the property that lets a parent and a child agree on
    /// which slot to write without ever exchanging the answer.
    #[test]
    fn a_parent_names_every_child_before_any_of_them_speaks() {
        let parent = HierAddr::root(p4(2));
        let children = CellPath::children_of(&parent);
        assert_eq!(children.len(), fano::cells_in::<F4>().unwrap(), "one child cell per Fano cell of the level");
        let mut seen = BTreeSet::new();
        for cell in &children {
            for seat in 0..fano::N {
                let addr = cell.member_address(seat).expect("a seat of an existing cell has an address");
                assert_eq!(addr.depth(), 2, "a child of a depth-1 parent sits at depth 2");
                assert!(parent.is_ancestor_of(&addr), "a child address must extend its parent's");
                assert_eq!(
                    CellPath::of_member(&addr).as_ref(),
                    Some(cell),
                    "the seat's own reading of its cell disagrees with the parent's enumeration of it"
                );
                assert!(seen.insert(addr.encode()), "two seats resolved to one address");
            }
        }
        assert_eq!(seen.len(), fano::cells_in::<F4>().unwrap() * fano::N, "21 children on PG(2,4)");
    }

    /// The wire form round-trips, and it round-trips at depth — a decoder that dropped levels would still pass a
    /// depth-1 fixture, which is why this walks down to `MAX_DEPTH`.
    #[test]
    fn the_encoding_round_trips_at_every_depth() {
        let mut addr = HierAddr::root(p4(1));
        for depth in 1..MAX_DEPTH {
            for base in 0..fano::cells_in::<F4>().unwrap() {
                let cell = CellPath::under(addr.clone(), base).unwrap();
                let bytes = cell.encode();
                assert_eq!(CellPath::<F4>::decode(&bytes).as_ref(), Some(&cell), "depth {depth}, base {base}");
                assert!(CellPath::<F4>::decode(&bytes[..bytes.len() - 1]).is_none(), "a truncated key must not decode");
            }
            addr = addr.descended(p4(depth % 21)).expect("MAX_DEPTH not reached");
        }
        let base = CellPath::<F2>::base_cell(0).unwrap();
        assert_eq!(CellPath::<F2>::decode(&base.encode()).as_ref(), Some(&base), "the base cell has a wire form too");
    }

    /// **A cell that cannot exist is not nameable.** `PG(2,7)` has 57 points and `7 ∤ 57`, so it holds no Fano cell —
    /// and a directory keyed by a name no member can ever claim is a directory of records nobody will ever read.
    ///
    /// The decoder is checked as well as the constructor, because the two are separate doors into the same type and a
    /// key arrives from the network through the second one.
    #[test]
    fn a_plane_that_holds_no_cell_names_none() {
        assert!(fano::cells_in::<F7>().is_none(), "PG(2,7) does not split into Fano cells");
        assert!(CellPath::<F7>::base_cell(0).is_none());
        assert!(CellPath::<F7>::under(HierAddr::root(Point::<F7>::at(0)), 0).is_none());
        assert!(CellPath::<F7>::of_member(&HierAddr::root(Point::<F7>::at(0))).is_none());
        // And an out-of-range index on a plane that *does* split, from both doors.
        assert!(CellPath::<F4>::base_cell(3).is_none(), "PG(2,4) has cells 0..3");
        let mut forged = CellPath::<F4>::base_cell(0).unwrap().encode();
        let n = forged.len();
        forged[n - 1] = 9;
        assert!(CellPath::<F4>::decode(&forged).is_none(), "a decoded base index must be checked, not trusted");
    }
}
