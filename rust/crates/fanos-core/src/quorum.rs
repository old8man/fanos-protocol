//! Maekawa quorums: lines as intersecting voting sets (spec §L4, §2.2).
//!
//! A line is a quorum of `q + 1 ≈ √N` nodes, and **any two lines intersect in exactly one
//! point** (the dual Steiner property). This is Maekawa's classic `O(√N)` mutual-exclusion
//! result, which FANOS reuses for consensus and replication: a write to quorum-line `W` and a
//! read from quorum-line `R` are guaranteed to share a node (`W ∩ R ≠ ∅`), so reads see the
//! latest write with no separate coordinator.

use fanos_field::Field;
use fanos_geometry::{Line, Plane, Point};

/// A quorum — a line and, on demand, its `q + 1` member points (spec §L4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Quorum<F: Field> {
    line: Line<F>,
}

impl<F: Field> Quorum<F> {
    /// Wrap a line as a quorum.
    #[must_use]
    pub fn new(line: Line<F>) -> Self {
        Self { line }
    }

    /// The underlying line.
    #[must_use]
    pub fn line(&self) -> Line<F> {
        self.line
    }

    /// The quorum size `q + 1`.
    #[must_use]
    pub fn size() -> u32 {
        Plane::<F>::LINE_SIZE
    }

    /// The quorum's `q + 1` member points.
    pub fn members(&self) -> impl Iterator<Item = Point<F>> + Clone {
        Plane::<F>::points_on(self.line)
    }

    /// The guaranteed non-empty intersection with another quorum (Maekawa): the unique node
    /// both contain. Returns `None` only if the two quorums are the same line.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Option<Point<F>> {
        self.line.meet(&other.line)
    }
}

/// The intersection node of a write-quorum and a read-quorum — always exists for distinct
/// quorums, guaranteeing read-your-writes freshness (spec §L4).
#[must_use]
pub fn write_read_witness<F: Field>(write: &Quorum<F>, read: &Quorum<F>) -> Option<Point<F>> {
    write.intersection(read)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::F13;

    #[test]
    fn quorum_size_is_q_plus_one() {
        assert_eq!(Quorum::<F13>::size(), 14);
    }

    #[test]
    fn any_two_quorums_intersect_in_one_node() {
        // Exhaustive Maekawa check on the q=13 cell.
        for a in Plane::<F13>::lines() {
            for b in Plane::<F13>::lines() {
                if a == b {
                    continue;
                }
                let qa = Quorum::new(a);
                let qb = Quorum::new(b);
                let node = qa.intersection(&qb).expect("distinct quorums intersect");
                // The witness is a member of both.
                assert!(a.contains(&node) && b.contains(&node));
            }
        }
    }

    #[test]
    fn write_read_always_share_a_node() {
        let w = Quorum::new(Line::<F13>::at(3));
        let r = Quorum::new(Line::<F13>::at(50));
        let witness = write_read_witness(&w, &r).unwrap();
        assert!(w.members().any(|p| p == witness));
        assert!(r.members().any(|p| p == witness));
    }
}
