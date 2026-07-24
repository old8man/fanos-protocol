//! A compact symmetric eigenvalue solver (cyclic Jacobi rotations).
//!
//! DIAKRISIS needs the spectrum of two small symmetric matrices: the sum of the seven Fano
//! line-adjacencies (to exhibit first-order blindness, spec §2.8) and the health-weighted
//! graph Laplacian (for the partition/Fiedler reading, spec §6.5). Both are tiny (`7×7`),
//! so the classical Jacobi method — quadratically convergent, dependency-free, and exact for
//! symmetric input — is the right tool. Matrices are row-major `n×n` slices.

use alloc::vec::Vec;

use crate::mathfns::sqrt;

/// The eigenvalues of a symmetric `n×n` matrix (row-major), sorted ascending — or `None` if
/// the input is unusable.
///
/// Returns `None` when either (a) any entry is non-finite — a `NaN` survives the `apq == 0.0`
/// skip below and would otherwise be returned as a silent `NaN`/`±∞` eigenvalue that reads
/// downstream as a spurious partition or a poisoned spectrum — or (b) the cyclic-Jacobi
/// iteration fails to drive the off-diagonal mass below a Frobenius-relative tolerance within
/// the sweep budget (the explicit *did-not-converge* signal, so a caller never mistakes an
/// unreduced diagonal for a real spectrum).
///
/// # Panics
/// If `mat.len() != n*n`.
#[must_use]
#[allow(clippy::indexing_slicing)] // dense numerical kernel; indices are loop-bounded by n
pub fn eigenvalues_symmetric(mat: &[f64], n: usize) -> Option<Vec<f64>> {
    assert_eq!(mat.len(), n * n, "matrix must be n*n");
    if n == 0 {
        return Some(Vec::new());
    }
    if mat.iter().any(|x| !x.is_finite()) {
        return None;
    }
    let mut a = mat.to_vec();
    let idx = |i: usize, j: usize| i * n + j;

    // The Frobenius norm is invariant under the orthogonal Jacobi similarity, so the
    // off-diagonal mass is judged against the (constant) total mass: convergence is
    // `off ≤ (ε·‖A‖_F)²`, scale-invariant — unlike the old absolute `1e-30`, which a
    // large-normed matrix could never reach (silently returning an unreduced diagonal).
    let scale: f64 = a.iter().map(|x| x * x).sum();
    let tol = 1e-26 * scale;

    // Cyclic Jacobi sweeps until the off-diagonal Frobenius mass is negligible relative to ‖A‖_F.
    let mut converged = false;
    for _sweep in 0..100 {
        let mut off = 0.0;
        for p in 0..n {
            for q in (p + 1)..n {
                off += a[idx(p, q)] * a[idx(p, q)];
            }
        }
        if off <= tol {
            converged = true;
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

    if !converged {
        return None;
    }
    let mut eigs: Vec<f64> = (0..n).map(|i| a[idx(i, i)]).collect();
    eigs.sort_by(|x, y| x.partial_cmp(y).unwrap_or(core::cmp::Ordering::Equal));
    Some(eigs)
}

/// The **algebraic connectivity** (Fiedler value): the second-smallest eigenvalue of a
/// graph Laplacian. `> 0` iff the graph is connected (spec §6.5). Returns `0` for `n < 2`.
#[must_use]
pub fn fiedler_value(laplacian: &[f64], n: usize) -> f64 {
    if n < 2 {
        return 0.0;
    }
    // A non-finite or non-converged Laplacian yields no trustworthy spectrum, so fail safe to
    // `0` (read as "not connected" ⇒ a partition is flagged rather than silently missed). The
    // shipped caller builds the Laplacian from a finite `u8` line-mask, so this is a
    // library-surface guard, not a live path.
    match eigenvalues_symmetric(laplacian, n) {
        Some(eigs) => eigs.get(1).copied().unwrap_or(0.0),
        None => 0.0,
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    #[test]
    fn a_diagonal_matrix_returns_its_diagonal_sorted() {
        let m = [3.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 2.0];
        let eigs = eigenvalues_symmetric(&m, 3).expect("finite, converges");
        assert_eq!(eigs.len(), 3);
        assert!((eigs[0] - 1.0).abs() < 1e-12);
        assert!((eigs[1] - 2.0).abs() < 1e-12);
        assert!((eigs[2] - 3.0).abs() < 1e-12);
    }

    #[test]
    fn a_known_2x2_symmetric_matrix_has_the_exact_spectrum() {
        // [[2,1],[1,2]] → eigenvalues {1, 3}.
        let eigs = eigenvalues_symmetric(&[2.0, 1.0, 1.0, 2.0], 2).expect("converges");
        assert!((eigs[0] - 1.0).abs() < 1e-12, "min {}", eigs[0]);
        assert!((eigs[1] - 3.0).abs() < 1e-12, "max {}", eigs[1]);
    }

    #[test]
    fn a_large_normed_matrix_still_converges_scale_invariantly() {
        // The old absolute `1e-30` threshold is unreachable at this scale, so the solver would
        // have returned an unreduced diagonal; the Frobenius-relative test converges to the
        // exact {s, 3s} spectrum.
        let s = 1e10;
        let eigs = eigenvalues_symmetric(&[2.0 * s, s, s, 2.0 * s], 2).expect("converges");
        assert!((eigs[0] - s).abs() < 1e-3 * s, "min {}", eigs[0]);
        assert!((eigs[1] - 3.0 * s).abs() < 1e-3 * s, "max {}", eigs[1]);
    }

    #[test]
    fn a_non_finite_entry_is_rejected_rather_than_silently_propagated() {
        assert!(eigenvalues_symmetric(&[f64::NAN, 0.0, 0.0, 1.0], 2).is_none());
        assert!(eigenvalues_symmetric(&[1.0, f64::INFINITY, f64::INFINITY, 1.0], 2).is_none());
    }

    #[test]
    fn fiedler_value_fails_safe_to_zero_on_a_non_finite_laplacian() {
        // n ≥ 2 but poisoned input ⇒ 0.0 (treated as disconnected), never a propagated NaN.
        assert_eq!(fiedler_value(&[f64::NAN, 0.0, 0.0, 0.0], 2), 0.0);
    }
}
