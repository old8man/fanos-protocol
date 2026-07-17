//! First-order blindness: why a heartbeat mesh cannot see the structure (spec §2.8, V11).
//!
//! Summing the adjacency matrices of the seven Fano lines gives exactly `J − I` — the
//! complete graph `K₇`, spectrum `{6, (−1)⁶}`. Any equal-weight pairwise statistic is
//! therefore a function of `J − I` alone: **indistinguishable from unstructured full
//! connectivity**. This is the formal reason DIAKRISIS must diagnose on triples, not pairs.

#![allow(clippy::indexing_slicing)] // fixed 7×7 kernel, indices bounded by the Fano enumeration

use alloc::vec;
use alloc::vec::Vec;

use fanos_geometry::fano;

use crate::eig::eigenvalues_symmetric;

/// Number of Fano nodes.
pub const N: usize = 7;

/// The sum of the seven Fano line-adjacency matrices, as a row-major `7×7` matrix. Each
/// off-diagonal pair, lying on exactly one line (Steiner `λ=1`), is hit exactly once.
#[must_use]
pub fn line_adjacency_sum() -> Vec<f64> {
    let mut a = vec![0.0f64; N * N];
    for line in &fano::LINE_POINTS {
        for (bi, &b) in line.iter().enumerate() {
            for &c in line.iter().skip(bi + 1) {
                let (b, c) = (b as usize, c as usize);
                a[b * N + c] += 1.0;
                a[c * N + b] += 1.0;
            }
        }
    }
    a
}

/// The matrix `J − I` (all-ones minus identity) as a row-major `7×7` matrix.
#[must_use]
pub fn j_minus_i() -> Vec<f64> {
    let mut a = vec![1.0f64; N * N];
    for i in 0..N {
        a[i * N + i] = 0.0;
    }
    a
}

/// Whether the summed line adjacency equals `J − I` — the content of first-order blindness.
#[must_use]
pub fn is_fano_blind() -> bool {
    let sum = line_adjacency_sum();
    let ji = j_minus_i();
    sum.iter().zip(&ji).all(|(a, b)| (a - b).abs() < 1e-12)
}

/// The spectrum of the summed line adjacency, sorted ascending: `[−1, −1, −1, −1, −1, −1, 6]`.
#[must_use]
pub fn blindness_spectrum() -> Vec<f64> {
    eigenvalues_symmetric(&line_adjacency_sum(), N)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn line_sum_is_j_minus_i_with_k7_spectrum() {
        // V11: Σ A(line_p) = J − I, spectrum {6, −1×6}.
        assert!(is_fano_blind());
        let spec = blindness_spectrum();
        assert_eq!(spec.len(), 7);
        for &lambda in spec.iter().take(6) {
            assert!(
                (lambda + 1.0).abs() < 1e-9,
                "six eigenvalues at −1, got {lambda}"
            );
        }
        assert!(
            (spec[6] - 6.0).abs() < 1e-9,
            "one eigenvalue at 6, got {}",
            spec[6]
        );
    }

    #[test]
    fn every_pair_covered_exactly_once() {
        // The defining Steiner property behind J − I: each off-diagonal entry is exactly 1.
        let sum = line_adjacency_sum();
        for i in 0..N {
            for j in 0..N {
                let expected = f64::from(u8::from(i != j));
                assert!((sum[i * N + j] - expected).abs() < 1e-12);
            }
        }
    }
}
