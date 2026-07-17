//! Segment / partition diagnosis via algebraic connectivity (spec §6.5, V14).
//!
//! The health-weighted collinearity graph puts an edge of weight "number of healthy lines
//! through the pair" between each pair of nodes. On the Fano cell every pair lies on exactly
//! one line, so a full healthy cell is `K₇` (Fiedler value `λ₂ = 7`); dropping one line
//! removes a triangle of edges, leaving `λ₂ = 4` — still comfortably connected. This is the
//! **partition-resistance theorem**: no single line-kill disconnects a cell; isolating a node
//! needs all `q+1` of its lines.

#![allow(clippy::indexing_slicing)] // fixed 7×7 kernel, indices bounded by the Fano enumeration

use alloc::vec;
use alloc::vec::Vec;

use fanos_geometry::fano;

use crate::eig::fiedler_value;

/// Number of Fano nodes.
pub const N: usize = 7;

/// The index of the unique Fano line through points `i` and `j` (`i != j`).
#[must_use]
fn line_through(i: usize, j: usize) -> Option<usize> {
    (0..N).find(|&l| {
        let m = fano::INCIDENCE[l];
        m & (1 << i) != 0 && m & (1 << j) != 0
    })
}

/// The graph Laplacian `L = D − W` of the health-weighted collinearity graph, where
/// `healthy_lines` is a 7-bit mask (bit `l` set ⇒ line `l` is healthy). A pair contributes an
/// edge iff the line through it is healthy.
#[must_use]
pub fn health_weighted_laplacian(healthy_lines: u8) -> Vec<f64> {
    let mut l = vec![0.0f64; N * N];
    for i in 0..N {
        for j in (i + 1)..N {
            let healthy = line_through(i, j).is_some_and(|line| healthy_lines & (1 << line) != 0);
            if healthy {
                l[i * N + j] -= 1.0;
                l[j * N + i] -= 1.0;
                l[i * N + i] += 1.0;
                l[j * N + j] += 1.0;
            }
        }
    }
    l
}

/// The algebraic connectivity (Fiedler value `λ₂`) of the cell with the given healthy lines.
/// `> 0` iff connected (spec §6.5).
#[must_use]
pub fn algebraic_connectivity(healthy_lines: u8) -> f64 {
    fiedler_value(&health_weighted_laplacian(healthy_lines), N)
}

/// Whether the cell is still connected (not partitioned) with the given healthy lines.
#[must_use]
pub fn is_connected(healthy_lines: u8) -> bool {
    algebraic_connectivity(healthy_lines) > 1e-9
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn full_cell_and_one_line_down_match_spec() {
        // V14: full cell λ₂ = 7; one line down λ₂ = 4.
        let full = algebraic_connectivity(0x7F);
        assert!((full - 7.0).abs() < 1e-6, "full cell λ₂ = 7, got {full}");
        let one_down = algebraic_connectivity(0x7F & !(1 << 0));
        assert!(
            (one_down - 4.0).abs() < 1e-6,
            "one line down λ₂ = 4, got {one_down}"
        );
    }

    #[test]
    fn no_single_line_kill_partitions() {
        // Partition-resistance: removing any one line leaves the cell connected.
        for l in 0..N {
            let healthy = 0x7F & !(1 << l);
            assert!(
                is_connected(healthy),
                "removing line {l} must not partition"
            );
        }
    }

    #[test]
    fn isolating_a_node_needs_all_its_lines() {
        // Anti-eclipse: a node is isolated only when all 3 of its lines are down.
        let point = 0usize;
        let its_lines: Vec<usize> = fano::POINT_LINES[point]
            .iter()
            .map(|&l| l as usize)
            .collect();
        // Drop two of its lines — still connected.
        let mut healthy = 0x7Fu8;
        healthy &= !(1 << its_lines[0]);
        healthy &= !(1 << its_lines[1]);
        assert!(is_connected(healthy), "two lines down: still connected");
        // Drop the third — the node is isolated, so the graph disconnects (λ₂ = 0).
        healthy &= !(1 << its_lines[2]);
        assert!(
            !is_connected(healthy),
            "all three lines down: node isolated"
        );
    }
}
