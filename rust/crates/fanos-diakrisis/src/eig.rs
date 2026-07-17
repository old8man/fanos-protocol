//! A compact symmetric eigenvalue solver (cyclic Jacobi rotations).
//!
//! DIAKRISIS needs the spectrum of two small symmetric matrices: the sum of the seven Fano
//! line-adjacencies (to exhibit first-order blindness, spec §2.8) and the health-weighted
//! graph Laplacian (for the partition/Fiedler reading, spec §6.5). Both are tiny (`7×7`),
//! so the classical Jacobi method — quadratically convergent, dependency-free, and exact for
//! symmetric input — is the right tool. Matrices are row-major `n×n` slices.

use alloc::vec::Vec;

use crate::mathfns::sqrt;

/// The eigenvalues of a symmetric `n×n` matrix (row-major), sorted ascending.
///
/// # Panics
/// If `mat.len() != n*n`.
#[must_use]
#[allow(clippy::indexing_slicing)] // dense numerical kernel; indices are loop-bounded by n
pub fn eigenvalues_symmetric(mat: &[f64], n: usize) -> Vec<f64> {
    assert_eq!(mat.len(), n * n, "matrix must be n*n");
    if n == 0 {
        return Vec::new();
    }
    let mut a = mat.to_vec();
    let idx = |i: usize, j: usize| i * n + j;

    // Cyclic Jacobi sweeps until the off-diagonal Frobenius norm is negligible.
    for _sweep in 0..100 {
        let mut off = 0.0;
        for p in 0..n {
            for q in (p + 1)..n {
                off += a[idx(p, q)] * a[idx(p, q)];
            }
        }
        if off <= 1e-30 {
            break;
        }
        for p in 0..n {
            for q in (p + 1)..n {
                let apq = a[idx(p, q)];
                if apq == 0.0 {
                    continue;
                }
                let app = a[idx(p, p)];
                let aqq = a[idx(q, q)];
                // Rotation angle that zeros the (p,q) entry.
                let theta = (aqq - app) / (2.0 * apq);
                let t = theta.signum() / (theta.abs() + sqrt(theta * theta + 1.0));
                let c = 1.0 / sqrt(t * t + 1.0);
                let s = t * c;
                // Apply the Givens rotation on both sides (columns then rows).
                for k in 0..n {
                    let akp = a[idx(k, p)];
                    let akq = a[idx(k, q)];
                    a[idx(k, p)] = c * akp - s * akq;
                    a[idx(k, q)] = s * akp + c * akq;
                }
                for k in 0..n {
                    let apk = a[idx(p, k)];
                    let aqk = a[idx(q, k)];
                    a[idx(p, k)] = c * apk - s * aqk;
                    a[idx(q, k)] = s * apk + c * aqk;
                }
            }
        }
    }

    let mut eigs: Vec<f64> = (0..n).map(|i| a[idx(i, i)]).collect();
    eigs.sort_by(|x, y| x.partial_cmp(y).unwrap_or(core::cmp::Ordering::Equal));
    eigs
}

/// The **algebraic connectivity** (Fiedler value): the second-smallest eigenvalue of a
/// graph Laplacian. `> 0` iff the graph is connected (spec §6.5). Returns `0` for `n < 2`.
#[must_use]
pub fn fiedler_value(laplacian: &[f64], n: usize) -> f64 {
    if n < 2 {
        return 0.0;
    }
    let eigs = eigenvalues_symmetric(laplacian, n);
    eigs.get(1).copied().unwrap_or(0.0)
}
