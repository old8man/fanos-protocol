//! The cell's **Byzantine fault tolerance** — how many of `n` nodes may be arbitrarily faulty.
//!
//! # Why this quantity lives in the geometry crate, and the tension that decision carries
//!
//! `f = ⌊(n − 1)/3⌋` is a **consensus** assumption — the classical Byzantine bound — and *not* a
//! theorem of incidence geometry. Nothing about a projective plane implies dividing by three. It is
//! hosted here for a structural reason that is worth stating plainly, because a reader who finds a
//! consensus constant in a geometry crate is right to be suspicious:
//!
//! * six crates need it — `taxis`, `rendezvous`, `aphantos`, `runtime`, `quic`, `node`;
//! * their common ancestors are exactly `field`, `geometry`, `pqcrypto`, `primitives`, `wire`;
//! * `field` is algebra, `pqcrypto` and `wire` are cryptography and encoding, and `primitives`
//!   already spends the word *budget* on the node's **memory** accounting — so a second meaning
//!   there would be a homonym, which is the defect class this move exists to avoid;
//! * which leaves this crate, and it is not a leftover: it **owns `n` itself**
//!   ([`Plane::N`](crate::Plane) `= q² + q + 1`), the sole argument the budget is a function of.
//!
//! So: geometry supplies `n`, consensus supplies the `/3`, and this module is where the two meet.
//!
//! # What it replaced
//!
//! Two production sites restated the formula and **could not import it**: `rendezvous`'s meeting
//! point count and `taxis`'s plane parameters. Neither crate depends on `fanos-runtime` — where the
//! canon lived — and neither should, because that is a higher layer. The duplication was therefore
//! not laziness but a layering fact, and the fix had to be a move rather than an import. (Measured
//! by reading each site: six further matches for the same arithmetic are all inside `#[test]`
//! functions, checked by opening the enclosing `fn` rather than by position relative to a
//! `#[cfg(test)]` marker — a positional filter has silently misclassified production code here
//! before.)
//!
//! `fanos_runtime::overlay::fault_budget`'s own doc had already named the risk — *"restating
//! `(n − 1)/3` over there would work and is exactly the copy that drifts"* — while two copies of
//! exactly that sat in the tree.

/// The Byzantine fault budget of a cell of `n` nodes: `f = ⌊(n − 1)/3⌋`.
///
/// Saturating rather than panicking at `n = 0`: a degenerate cell has no tolerance, and answering
/// `0` is both the arithmetic truth and the fail-safe direction — a caller sizing a quorum from it
/// demands *more* corroboration, never less.
///
/// # Examples
///
/// ```
/// use fanos_geometry::fault_budget;
/// assert_eq!(fault_budget(7), 2, "the Fano cell tolerates two");
/// assert_eq!(fault_budget(0), 0, "and a degenerate one tolerates none");
/// ```
#[must_use]
pub const fn fault_budget(n: usize) -> usize {
    n.saturating_sub(1) / 3
}

#[cfg(test)]
mod tests {
    use super::fault_budget;

    /// **The budget at every plane order the platform ships**, pinned as a table rather than as a
    /// re-statement of the formula.
    ///
    /// A test that computes `(n-1)/3` and compares it to `fault_budget(n)` would pass for any
    /// function of that shape, including a wrong one — it would be the formula checking itself. The
    /// values here are worked out by hand from `n = q² + q + 1`, so a change to the rule has to
    /// disagree with an independently-derived number to go unnoticed.
    #[test]
    fn the_budget_is_pinned_by_value_at_every_shipped_plane_order() {
        // q,  n = q²+q+1,  f = ⌊(n−1)/3⌋
        for &(q, n, f) in &[
            (2usize, 7usize, 2usize),   // Fano — the base cell
            (3, 13, 4),
            (4, 21, 6),
            (5, 31, 10),
            (7, 57, 18),
            (8, 73, 24),
            (9, 91, 30),
        ] {
            assert_eq!(q * q + q + 1, n, "the table's own n must be q²+q+1 for q={q}");
            assert_eq!(fault_budget(n), f, "budget at q={q} (n={n})");
        }
    }

    /// The degenerate end, where an off-by-one would be invisible on a real cell.
    ///
    /// `n ≤ 3` tolerates nobody: the classical bound needs `n ≥ 3f + 1`, so the first cell that can
    /// tolerate one fault has four members. Pinned because `n.saturating_sub(1) / 3` and a
    /// hypothetical `n / 3` agree on every plane order above and differ at exactly `n = 3`.
    #[test]
    fn no_cell_of_three_or_fewer_tolerates_anyone() {
        assert_eq!(fault_budget(0), 0);
        assert_eq!(fault_budget(1), 0);
        assert_eq!(fault_budget(2), 0);
        assert_eq!(fault_budget(3), 0, "n/3 would answer 1 here — the discriminator");
        assert_eq!(fault_budget(4), 1, "n ≥ 3f+1 with f = 1");
    }
}
