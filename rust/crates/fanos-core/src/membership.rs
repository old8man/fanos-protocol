//! L0/L3 membership: node coordinates and the structural centrality cap (spec §L0, §L3, V3).
//!
//! A node's cell coordinate is a VRF of its identity and the epoch, so it reshuffles each
//! epoch and cannot be pre-aimed. Crucially, every node lies on **exactly `q + 1` of the `N`
//! lines** — a fixed fraction `(q+1)/N` — so *centrality cannot be bought*: a Sybil node gets
//! no more lines than anyone else, and to eclipse a node an adversary must control all `q+1`
//! of its lines at once.

use fanos_field::Field;
use fanos_geometry::{Line, Plane, Point};

use fanos_crypto::NodeId;
use fanos_crypto::coordinate_for;

/// A cell member: its long-term identity and its epoch-bound coordinate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Member<F: Field> {
    /// The long-term node identifier (spec §L0).
    pub id: NodeId,
    /// The projective coordinate for the current epoch.
    pub coord: Point<F>,
    /// The epoch this coordinate was derived for.
    pub epoch: u32,
}

impl<F: Field> Member<F> {
    /// Assign a member's coordinate for `epoch` (reference VRF derivation, spec §L0).
    #[must_use]
    pub fn assign(id: NodeId, epoch: u32) -> Self {
        Self {
            id,
            coord: coordinate_for::<F>(&id, epoch),
            epoch,
        }
    }

    /// The `q + 1` lines this member belongs to (its quorums / buses).
    pub fn lines(&self) -> impl Iterator<Item = Line<F>> + Clone {
        Plane::<F>::lines_through(self.coord)
    }
}

/// The number of lines through every node: `q + 1` (spec §L3). This is the structural
/// centrality — identical for every node, Sybil or not.
#[must_use]
pub fn lines_per_node<F: Field>() -> u32 {
    Plane::<F>::LINE_SIZE
}

/// The centrality cap `(q+1)/N` — the fixed fraction of lines any node touches (spec §L3, V3).
/// For `q = 31` this is `3.22%`.
#[must_use]
pub fn centrality_fraction(q: u32) -> f64 {
    let n = q * q + q + 1;
    f64::from(q + 1) / f64::from(n)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_field::{F7, F31};

    #[test]
    fn centrality_is_capped_and_uniform() {
        // V3: centrality (q+1)/N; q=31 → 3.22%.
        assert!((centrality_fraction(31) - 0.032_225).abs() < 1e-5);
        // Every node on the q=7 cell touches exactly q+1 = 8 lines — no exceptions.
        for p in Plane::<F7>::points() {
            assert_eq!(Plane::<F7>::lines_through(p).count() as u32, 8);
        }
    }

    #[test]
    fn member_coordinate_is_epoch_bound() {
        let id = NodeId([5u8; 32]);
        let m0 = Member::<F31>::assign(id, 0);
        let m1 = Member::<F31>::assign(id, 1);
        assert_eq!(m0.epoch, 0);
        assert_ne!(m0.coord, m1.coord, "epoch reshuffle moves the coordinate");
        assert_eq!(m0.lines().count() as u32, lines_per_node::<F31>());
    }

    #[test]
    fn sybil_gains_no_extra_centrality() {
        // Many identities all land on exactly q+1 lines — mass does not buy centrality.
        for seed in 0u8..20 {
            let m = Member::<F31>::assign(NodeId([seed; 32]), 0);
            assert_eq!(m.lines().count() as u32, 32);
        }
    }
}
