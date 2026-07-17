//! Scale via a hierarchy of cells (spec §L1, V4).
//!
//! One plane holds `N = q²+q+1` nodes; internet scale comes from a **recursion of cells** — a
//! cell is a "point" of the parent cell. Routing state and rendezvous depth are then
//! `O(log n)`, like Kademlia, but with FANOS's constant-factor wins (deterministic 1-message
//! rendezvous per level, quorum intersection, centrality cap, free multipath, LRC storage).
//! This module computes the scale figures the specification tabulates (V4).

/// Parameters of a cell hierarchy: the per-cell field order `q` and the number of levels `k`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hierarchy {
    /// The per-cell field order `q`.
    pub q: u32,
    /// The number of hierarchy levels `k`.
    pub levels: u32,
}

impl Hierarchy {
    /// Construct a hierarchy of `levels` cells, each `PG(2, q)`.
    #[must_use]
    pub fn new(q: u32, levels: u32) -> Self {
        Self { q, levels }
    }

    /// The size of a single cell, `N = q²+q+1`.
    #[must_use]
    pub fn cell_size(&self) -> u128 {
        let q = u128::from(self.q);
        q * q + q + 1
    }

    /// Total addressable nodes, `N^k`.
    #[must_use]
    pub fn total_nodes(&self) -> u128 {
        self.cell_size().pow(self.levels)
    }

    /// Approximate per-node routing state, `k · N` (spec §L1, V4).
    #[must_use]
    pub fn routing_state(&self) -> u128 {
        u128::from(self.levels) * self.cell_size()
    }

    /// Rendezvous depth: one algebraic step per level, `k`.
    #[must_use]
    pub fn rendezvous_depth(&self) -> u32 {
        self.levels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_scale_table() {
        // spec §L1 V4 table, reproduced exactly.
        let a = Hierarchy::new(31, 2);
        assert_eq!(a.cell_size(), 993);
        assert_eq!(a.total_nodes(), 986_049);
        assert_eq!(a.routing_state(), 1_986);
        assert_eq!(a.rendezvous_depth(), 2);

        let b = Hierarchy::new(31, 3);
        assert_eq!(b.total_nodes(), 979_146_657);
        assert_eq!(b.routing_state(), 2_979);

        let c = Hierarchy::new(127, 2);
        assert_eq!(c.cell_size(), 16_257);
        assert_eq!(c.total_nodes(), 264_290_049);
        assert_eq!(c.routing_state(), 32_514);

        let d = Hierarchy::new(127, 3);
        assert_eq!(d.total_nodes(), 4_296_563_326_593);
        assert_eq!(d.routing_state(), 48_771);
        assert_eq!(d.rendezvous_depth(), 3);
    }

    #[test]
    fn a_three_level_q31_hierarchy_reaches_a_billion() {
        // The headline claim: ~10⁹ nodes at depth 3 with ~3000 routing state.
        let h = Hierarchy::new(31, 3);
        assert!(h.total_nodes() > 900_000_000);
        assert!(h.routing_state() < 3_000);
    }
}
