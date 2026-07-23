//! # Fast-mixing trust-graph Sybil admission — the **cap** that anchors POROS's rate-limiter.
//!
//! The POROS proof-of-work ([`crate::poros`]) is a *rate-limiter*, not a Sybil cap (Boneh et al.
//! *CRYPTO 2018*: a sequential-cost proof bounds identity-creation *rate*, never *total* identities).
//! A true cap requires anchoring admission to a **scarce resource**; the strongest non-personhood one
//! is a **fast-mixing trust graph** (design authority §6; the audit's flagged requirement, and the open
//! residual of proof T5). This module supplies that anchor.
//!
//! ## The mechanism — trust as a random walk (SybilGuard / Whānau family)
//!
//! Trust flows from a small set of trusted **anchors** by a `w`-step random walk on the undirected
//! trust graph (an edge = a real-world vouch). The math the whole defense rests on:
//!
//! * In the **honest region**, which is assumed *fast-mixing* (a well-connected social graph has
//!   mixing time `w = Θ(log n)`), the walk reaches its **stationary distribution** `π(v) = deg(v)/2m`
//!   after `w` steps: every honest node gets trust proportional to its degree.
//! * A **Sybil region** can attach to the honest region only through the `g` **attack edges** its
//!   human dupes are willing to create. That cut has tiny **conductance**, so a random walk *escapes*
//!   into the Sybil region with probability `≈ g/2m` per step — the Sybils collectively absorb only
//!   `O(g·w)` of the trust mass no matter how many of them there are. Their per-node trust is therefore
//!   **exponentially below** the honest stationary share, and admitting on "trust ≥ a fraction of the
//!   stationary share" caps the admitted Sybils at **`O(g)`**, independent of `n` — the cap PoW cannot
//!   give.
//!
//! The walk is computed **exactly** (the full `w`-step distribution, not a sampled walk), so admission
//! is deterministic and reproducible — no CSPRNG, sans-I/O-friendly. This is the conductance-bounded
//! foundation; SybilLimit's tail-intersection + balance conditions tighten the bound to `O(log n)` per
//! attack edge and are a further increment. Compose this **cap** with FANOS's holonic-coherence
//! **rate-limiter/expulsion** layer (which shrinks the effective insider budget `t`, à la Salmon's
//! trust-tiering) for the full POROS Sybil defense.

use std::collections::{BTreeMap, BTreeSet};

/// A node identity in the trust graph (an overlay-independent handle; the caller maps it to a
/// coordinate/credential).
pub type NodeId = u32;

/// An undirected **trust graph**: an edge `{a, b}` is a mutual real-world vouch. Sybil resistance comes
/// from the *sparsity of the honest↔Sybil cut*, never from the count of Sybil-internal edges.
#[derive(Clone, Default, Debug)]
pub struct TrustGraph {
    adj: BTreeMap<NodeId, BTreeSet<NodeId>>,
}

impl TrustGraph {
    /// An empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the undirected trust edge `{a, b}` (a mutual vouch). Self-loops are ignored; a repeated edge
    /// is idempotent.
    pub fn add_edge(&mut self, a: NodeId, b: NodeId) {
        if a == b {
            return;
        }
        self.adj.entry(a).or_default().insert(b);
        self.adj.entry(b).or_default().insert(a);
    }

    /// The neighbours (vouchers) of `node`.
    pub fn neighbors(&self, node: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.adj.get(&node).into_iter().flatten().copied()
    }

    /// The degree of `node`.
    #[must_use]
    pub fn degree(&self, node: NodeId) -> usize {
        self.adj.get(&node).map_or(0, BTreeSet::len)
    }

    /// The number of nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.adj.len()
    }

    /// Whether the graph is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.adj.is_empty()
    }

    /// Twice the edge count `2m = Σ deg(v)` — the normalizer of the stationary distribution.
    #[must_use]
    fn total_degree(&self) -> usize {
        self.adj.values().map(BTreeSet::len).sum()
    }

    /// The exact **`steps`-step random-walk trust distribution** seeded at the trusted `anchor`:
    /// `p_0 = δ_anchor`, `p_{k+1}(v) = Σ_{u∼v} p_k(u)/deg(u)`. Trust that mixes into the honest region;
    /// a Sybil region behind a sparse cut receives only `O(g·steps)` of it in total.
    #[must_use]
    pub fn trust_distribution(&self, anchor: NodeId, steps: usize) -> BTreeMap<NodeId, f64> {
        let mut p: BTreeMap<NodeId, f64> = BTreeMap::new();
        p.insert(anchor, 1.0);
        for _ in 0..steps {
            let mut next: BTreeMap<NodeId, f64> = BTreeMap::new();
            for (&u, &mass) in &p {
                let deg = self.degree(u);
                if deg == 0 {
                    continue; // dangling trust: a degree-0 node cannot forward its mass
                }
                let share = mass / deg as f64;
                for v in self.neighbors(u) {
                    *next.entry(v).or_insert(0.0) += share;
                }
            }
            p = next;
        }
        p
    }

    /// A node's **trust ratio** — its `steps`-step walk mass measured against the honest stationary
    /// share `deg/2m`. Honest nodes in the well-mixed region converge to `≈ 1`; Sybils behind a sparse
    /// attack cut stay far below. `0.0` for an isolated or unknown node.
    #[must_use]
    pub fn trust_ratio(&self, anchor: NodeId, suspect: NodeId, steps: usize) -> f64 {
        let two_m = self.total_degree();
        let deg = self.degree(suspect);
        if deg == 0 || two_m == 0 {
            return 0.0;
        }
        let mass = self.trust_distribution(anchor, steps).get(&suspect).copied().unwrap_or(0.0);
        // stationary reference π(v) = deg/2m; ratio = mass / π(v).
        mass * two_m as f64 / deg as f64
    }

    /// **Admit** `suspect` iff its [`trust_ratio`](Self::trust_ratio) reaches `threshold` (a fraction of
    /// the honest stationary share, e.g. `0.3`). This is the Sybil **cap**: honest suspects pass; a
    /// Sybil region behind `g` attack edges yields at most `O(g)` admissions regardless of its size.
    #[must_use]
    pub fn admits(&self, anchor: NodeId, suspect: NodeId, steps: usize, threshold: f64) -> bool {
        self.trust_ratio(anchor, suspect, steps) >= threshold
    }

    /// The subset of `candidates` this anchor admits at `threshold` — the concrete Sybil-capped
    /// admission set (computed from one shared distribution, so it is `O(candidates)` after the walk).
    #[must_use]
    pub fn admitted<I>(&self, anchor: NodeId, candidates: I, steps: usize, threshold: f64) -> Vec<NodeId>
    where
        I: IntoIterator<Item = NodeId>,
    {
        let total = self.total_degree();
        if total == 0 {
            return Vec::new();
        }
        let two_m = total as f64;
        let dist = self.trust_distribution(anchor, steps);
        candidates
            .into_iter()
            .filter(|&c| {
                let deg = self.degree(c);
                deg > 0 && dist.get(&c).copied().unwrap_or(0.0) * two_m / deg as f64 >= threshold
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::*;

    /// A synthetic world: a fast-mixing honest region (a complete graph on `0..h`) with a Sybil region
    /// (a complete graph on `h..h+s`) attached by exactly `g` attack edges. This is the standard Sybil-
    /// defense benchmark: the defense must rest on the *sparse cut*, not the Sybil count.
    fn honest_plus_sybils(h: u32, s: u32, g: u32) -> TrustGraph {
        let mut g_ = TrustGraph::new();
        // Honest region: complete (definitively fast-mixing).
        for a in 0..h {
            for b in (a + 1)..h {
                g_.add_edge(a, b);
            }
        }
        // Sybil region: complete among themselves (many internal edges — which must NOT help them).
        for a in h..(h + s) {
            for b in (a + 1)..(h + s) {
                g_.add_edge(a, b);
            }
        }
        // Attack edges: g edges from distinct honest nodes to distinct Sybils.
        for i in 0..g {
            g_.add_edge(i, h + i);
        }
        g_
    }

    #[test]
    fn honest_nodes_mix_to_the_stationary_share() {
        // In the honest complete region, every honest node's trust ratio converges to ≈ 1 (the
        // stationary distribution deg/2m), regardless of the anchor.
        let g = honest_plus_sybils(12, 30, 2);
        for v in 0..12u32 {
            let ratio = g.trust_ratio(0, v, 16);
            assert!(ratio > 0.6, "honest node {v} should mix to near its stationary share, got {ratio}");
        }
    }

    #[test]
    fn the_sybil_region_is_capped_at_o_of_the_attack_cut() {
        // The whole point: NO MATTER how many Sybils there are (here 60), behind a sparse cut (g=3)
        // only O(g) of them clear the trust threshold — the count PoW alone can never bound.
        let h = 15u32;
        let s = 60u32;
        let g_edges = 3u32;
        let graph = honest_plus_sybils(h, s, g_edges);
        let sybils: Vec<NodeId> = (h..(h + s)).collect();
        let admitted = graph.admitted(0, sybils.clone(), 16, 0.3);
        assert!(
            admitted.len() <= (g_edges as usize) * 2,
            "admitted Sybils ({}) must be O(attack edges={g_edges}), not O(Sybil count={s})",
            admitted.len(),
        );
        // Meanwhile every honest node is admitted — the cap does not starve legitimate users.
        let honest: Vec<NodeId> = (0..h).collect();
        assert_eq!(
            graph.admitted(0, honest.clone(), 16, 0.3).len(),
            honest.len(),
            "all honest nodes clear the threshold",
        );
    }

    #[test]
    fn adding_more_sybils_behind_the_same_cut_does_not_admit_more() {
        // Sybil-cost independence of n: doubling the Sybil count behind the SAME attack cut admits no
        // more of them — the defining property of a real cap (vs a rate-limiter, where more identities
        // buy more admissions).
        let admitted = |s: u32| honest_plus_sybils(15, s, 2).admitted(0, 15..(15 + s), 16, 0.3).len();
        let few = admitted(20);
        let many = admitted(200);
        assert!(many <= few + 2, "10x the Sybils admits no more ({few} vs {many}) — a cap, not a rate");
    }

    #[test]
    fn a_disconnected_or_unknown_node_gets_no_trust() {
        let mut graph = TrustGraph::new();
        graph.add_edge(0, 1);
        graph.add_edge(1, 2);
        // A node with no path from the anchor (or unknown) has zero trust and is never admitted.
        assert_eq!(graph.trust_ratio(0, 99, 8), 0.0);
        assert!(!graph.admits(0, 99, 8, 0.1));
        // An isolated component the anchor cannot reach gets no mass.
        graph.add_edge(50, 51);
        assert_eq!(graph.trust_ratio(0, 50, 8), 0.0);
    }
}
