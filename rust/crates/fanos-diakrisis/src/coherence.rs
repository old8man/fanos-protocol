//! The network coherence matrix `Γ_net` and its scalar health measures (spec §2.7).
//!
//! A live cell of `N` nodes carries a behavioural correlation matrix `C` (symmetric, unit
//! diagonal); its trace-normalised form `Γ_net = C / N` is a bona-fide coherence matrix
//! (`Tr Γ = 1`) and inherits the corpus's three invariants:
//!
//! * **Integration** `Φ = Σ_{i≠j}|γ_ij|² / Σ_i γ_ii²` — cross-node binding; threshold `1`.
//! * **Structuredness** `P = Tr(Γ²)` (purity) — distance from a formless mesh; `P_crit = 2/N`.
//! * **Reflection** `R = 1/(N·P)` — self-model sufficiency; threshold `1/3`.
//!
//! Because `C` has unit diagonal, every measure reduces to the Frobenius sum-of-squares of
//! `C`, which is computed with a `portable_simd` kernel (scalar-verified) so large monitor
//! cells stay cheap. No `Γ` is ever materialised.

use alloc::vec;
use alloc::vec::Vec;
use core::simd::f64x8;
use core::simd::num::SimdFloat;

use crate::mathfns::sqrt;

/// The systemic-correlation threshold `r* = 1/√(N−1)` (spec §2.7). At the mean off-diagonal
/// correlation `r*`, integration and structure thresholds coincide; above it the cell is in
/// the cascade-failure regime. For `N = 7` this is `1/√6 ≈ 0.408`.
#[must_use]
pub fn systemic_correlation(n: usize) -> f64 {
    debug_assert!(n >= 2);
    1.0 / sqrt((n - 1) as f64)
}

/// The structure critical value `P_crit = 2/N` (spec §2.7).
#[must_use]
pub fn p_crit(n: usize) -> f64 {
    2.0 / n as f64
}

/// The reflection threshold `R_th = 1/3` (spec §6.8), independent of `N`.
pub const R_TH: f64 = 1.0 / 3.0;
/// The integration threshold `Φ_th = 1` (spec §2.7).
pub const PHI_TH: f64 = 1.0;

/// The three coherence measures read together in one pass (see [`CoherenceMatrix::measures`]).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Measures {
    /// Integration `Φ` (threshold `1`).
    pub phi: f64,
    /// Structuredness `P = Tr(Γ²)` (threshold `2/N`).
    pub purity: f64,
    /// Reflection `R = 1/(N·P)` (threshold `1/3`).
    pub reflection: f64,
}

/// Sum of squares of all entries of a slice (the Frobenius norm squared), via `portable_simd`.
#[must_use]
pub fn frobenius_sq(values: &[f64]) -> f64 {
    let (prefix, middle, suffix) = values.as_simd::<8>();
    let mut acc = f64x8::splat(0.0);
    for &v in middle {
        acc += v * v;
    }
    let mut total = acc.reduce_sum();
    for &x in prefix.iter().chain(suffix) {
        total += x * x;
    }
    total
}

/// Scalar reference for [`frobenius_sq`] (used to verify the SIMD kernel).
#[must_use]
pub fn frobenius_sq_scalar(values: &[f64]) -> f64 {
    values.iter().map(|&x| x * x).sum()
}

/// A cell's behavioural correlation matrix `C` (row-major, `n×n`, symmetric, unit diagonal).
#[derive(Clone, Debug)]
pub struct CoherenceMatrix {
    n: usize,
    /// The correlation matrix `C`; `Γ_net = C / n`.
    c: Vec<f64>,
}

impl CoherenceMatrix {
    /// Wrap a correlation matrix. Returns `None` unless it is `n×n`, symmetric to tolerance,
    /// and has unit diagonal.
    #[must_use]
    pub fn from_correlation(c: Vec<f64>, n: usize) -> Option<Self> {
        if n == 0 || c.len() != n * n {
            return None;
        }
        // Reject any non-finite entry up front. NaN/±∞ silently pass the tolerance checks below (every
        // comparison with NaN is false), so an unguarded matrix would admit a poisoned self-model —
        // and a single non-finite entry propagates to Φ, which then hangs the reroute-depth loop and
        // evades the Byzantine polar check. This is the boundary of the organism's self-observation:
        // nothing non-finite enters the coherence state.
        if c.iter().any(|x| !x.is_finite()) {
            return None;
        }
        for i in 0..n {
            if (c.get(i * n + i)? - 1.0).abs() > 1e-9 {
                return None;
            }
            for j in (i + 1)..n {
                if (c.get(i * n + j)? - c.get(j * n + i)?).abs() > 1e-9 {
                    return None;
                }
            }
        }
        Some(Self { n, c })
    }

    /// Build the correlation matrix from `n` per-node activity signals of equal length
    /// (bytes relayed, liveness, load — any observable, spec §2.7). Constant signals
    /// correlate as the identity in their row/column.
    #[must_use]
    pub fn from_signals(signals: &[Vec<f64>]) -> Option<Self> {
        let n = signals.len();
        if n == 0 {
            return None;
        }
        let len = signals.first()?.len();
        if len == 0 || signals.iter().any(|s| s.len() != len) {
            return None;
        }
        // Per-signal mean and standard deviation.
        let mut mean = vec![0.0; n];
        let mut std = vec![0.0; n];
        for (i, s) in signals.iter().enumerate() {
            let m = s.iter().sum::<f64>() / len as f64;
            let var = s.iter().map(|&x| (x - m) * (x - m)).sum::<f64>() / len as f64;
            *mean.get_mut(i)? = m;
            *std.get_mut(i)? = sqrt(var);
        }
        let mut c = vec![0.0; n * n];
        for i in 0..n {
            *c.get_mut(i * n + i)? = 1.0;
            for j in (i + 1)..n {
                let (si, sj) = (signals.get(i)?, signals.get(j)?);
                let (mi, mj) = (*mean.get(i)?, *mean.get(j)?);
                let cov = si
                    .iter()
                    .zip(sj)
                    .map(|(&a, &b)| (a - mi) * (b - mj))
                    .sum::<f64>()
                    / len as f64;
                let denom = std.get(i)? * std.get(j)?;
                let corr = if denom > 1e-12 { cov / denom } else { 0.0 };
                *c.get_mut(i * n + j)? = corr;
                *c.get_mut(j * n + i)? = corr;
            }
        }
        Some(Self { n, c })
    }

    /// An equicorrelated cell: unit diagonal, every off-diagonal equal to `r` (spec §2.7).
    #[must_use]
    pub fn equicorrelated(n: usize, r: f64) -> Self {
        let mut c = vec![r; n * n];
        for i in 0..n {
            if let Some(slot) = c.get_mut(i * n + i) {
                *slot = 1.0;
            }
        }
        Self { n, c }
    }

    /// The number of nodes `N`.
    #[must_use]
    pub fn n(&self) -> usize {
        self.n
    }

    /// All three scalar measures (`Φ`, `P`, `R`) from a **single** Frobenius pass over `C`.
    ///
    /// Because `Γ = C/n` with unit-diagonal `C`, every measure reduces to `frob = Σ C_ij²`:
    /// `P = frob/n²`, `Φ = (frob − n)/n` (`= Σ_{i≠j}γ_ij² ÷ Σ_i γ_ii²`), and `R = 1/(N·P) = n/frob`.
    /// Prefer this to calling [`phi`](Self::phi)/[`purity`](Self::purity)/[`reflection`](Self::reflection)
    /// separately — each of those repeats the same O(n²) SIMD pass.
    #[must_use]
    pub fn measures(&self) -> Measures {
        let nf = self.n as f64;
        if nf <= 0.0 {
            return Measures {
                phi: 0.0,
                purity: 0.0,
                reflection: 0.0,
            };
        }
        let frob = frobenius_sq(&self.c); // Σ C_ij², computed once
        let purity = frob / (nf * nf); // Tr(Γ²)
        Measures {
            phi: (frob - nf) / nf, // Σ_{i≠j}γ_ij² / Σ_i γ_ii²
            purity,
            reflection: if purity > 0.0 {
                1.0 / (nf * purity)
            } else {
                0.0
            },
        }
    }

    /// Integration `Φ = Σ_{i≠j}|γ_ij|² / Σ_i γ_ii²` (spec §2.7). `Φ ≥ 1` ⇒ integrated.
    #[must_use]
    pub fn phi(&self) -> f64 {
        self.measures().phi
    }

    /// Structuredness `P = Tr(Γ²)` (purity). `P > 2/N` ⇒ structured (spec §2.7).
    #[must_use]
    pub fn purity(&self) -> f64 {
        self.measures().purity
    }

    /// Reflection `R = 1/(N·P)` (spec §2.7, §6.8). `R ≥ 1/3` ⇒ self-modelling.
    #[must_use]
    pub fn reflection(&self) -> f64 {
        self.measures().reflection
    }

    /// The mean off-diagonal correlation `r` (used for the cascade early-warning, §2.7).
    #[must_use]
    pub fn mean_correlation(&self) -> f64 {
        let n = self.n;
        if n < 2 {
            return 0.0;
        }
        let mut sum = 0.0;
        for i in 0..n {
            for j in (i + 1)..n {
                sum += self.c.get(i * n + j).copied().unwrap_or(0.0);
            }
        }
        sum / (n * (n - 1) / 2) as f64
    }

    /// Node `q`'s **coupling energy** `s_q = Σ_{j≠q} C_qj²` — the sum of its squared off-diagonal
    /// correlations, i.e. how much of the cell's integration `q` accounts for. `0` for an out-of-range `q`.
    /// The cell average is exactly `Φ` (each `C_ij²` appears in both `s_i` and `s_j`, so `Σ_q s_q = N·Φ`).
    #[must_use]
    pub fn coupling_energy(&self, q: usize) -> f64 {
        if q >= self.n {
            return 0.0;
        }
        let mut s = 0.0;
        for j in 0..self.n {
            if j != q {
                let v = self.c.get(q * self.n + j).copied().unwrap_or(0.0);
                s += v * v;
            }
        }
        s
    }

    /// The cell integration **after quarantining node `q`** — closed form (the D6 quarantine theorem,
    /// `docs/design-quarantine-theorem.md`): `Φ' = (N·Φ − 2·s_q)/(N−1)`, where `s_q` is `q`'s
    /// [`coupling_energy`](Self::coupling_energy). `None` if `N < 2` (nothing left to bind after removing a
    /// node). Excising `q` and recomputing [`phi`](Self::phi) yields the identical value (cross-checked in
    /// the tests) — this form is O(N) rather than O(N²) and needs no reallocation.
    #[must_use]
    pub fn phi_after_quarantine(&self, q: usize) -> Option<f64> {
        if self.n < 2 || q >= self.n {
            return None;
        }
        let nf = self.n as f64;
        Some((nf * self.phi() - 2.0 * self.coupling_energy(q)) / (nf - 1.0))
    }

    /// Whether quarantining node `q` **strictly lowers** the cell integration `Φ` — the D6 quarantine
    /// theorem's exact condition `s_q > Φ/2`: quarantine is a valid Φ-reducing healing step iff the node's
    /// coupling energy exceeds half the cell integration (a structurally-inconsistent / Byzantine node,
    /// which injects spurious high correlation, satisfies this; an under-coupled silent node does not, and
    /// quarantining it would *raise* Φ — the theorem forbids that). `false` for a degenerate cell.
    #[must_use]
    pub fn quarantine_lowers_phi(&self, q: usize) -> bool {
        if self.n < 2 || q >= self.n {
            return false;
        }
        self.coupling_energy(q) > self.phi() / 2.0
    }

    /// The `(N−1)×(N−1)` correlation matrix with node `q`'s row and column excised — the cell **after**
    /// quarantining `q`. `None` if `q` is out of range or the result would be empty. Used to realize the
    /// quarantine and to cross-validate [`phi_after_quarantine`](Self::phi_after_quarantine) against a full
    /// recompute.
    #[must_use]
    pub fn excise(&self, q: usize) -> Option<Self> {
        if q >= self.n || self.n <= 1 {
            return None;
        }
        let m = self.n - 1;
        let mut c = vec![0.0; m * m];
        let mut ri = 0;
        for i in 0..self.n {
            if i == q {
                continue;
            }
            let mut cj = 0;
            for j in 0..self.n {
                if j == q {
                    continue;
                }
                *c.get_mut(ri * m + cj)? = self.c.get(i * self.n + j).copied().unwrap_or(0.0);
                cj += 1;
            }
            ri += 1;
        }
        Some(Self { n: m, c })
    }

    /// Whether the cell is integrated (`Φ ≥ 1`).
    #[must_use]
    pub fn is_integrated(&self) -> bool {
        self.phi() >= PHI_TH - 1e-9
    }

    /// Whether the cell is in the systemic / cascade regime (`r > r*`), detectable a regime
    /// ahead of any liveness alarm (spec §2.7, §6.5). This is the **early-warning monitor**
    /// (the leading indicator the observatory forecasts on) — it is *not* itself a healing
    /// trigger, because the band `(r*, 1/√3]` is a healthy collective subject (see
    /// [`is_overcoupled`](Self::is_overcoupled)).
    #[must_use]
    pub fn is_systemic(&self) -> bool {
        // A degenerate (<2-node) cell has no inter-node correlation — `r*` is undefined and it is
        // never systemic (audit #122: a collapsed cell must be readable, not a panic).
        self.n >= 2 && self.mean_correlation() > systemic_correlation(self.n) + 1e-12
    }

    /// Whether the cell is **over-coupled** (`r > √(2/(N−1))`, equivalently `R < 1/3`):
    /// integration has climbed past the collective-subject band and the cell is losing its
    /// self-model (spec §18.2, §6.8). This — not the mere early-warning [`is_systemic`](Self::is_systemic)
    /// — is the actionable *decouple* trigger: shedding correlation is warranted only once the
    /// cell leaves the healthy band, never while it is a legitimately integrated subject.
    #[must_use]
    pub fn is_overcoupled(&self) -> bool {
        matches!(
            self.collective_state(),
            crate::window::CollectiveState::OverCoupled
        )
    }

    /// Which leading-indicator alarm this cell trips (spec §6.6, V17): `Healthy`, `Integration`
    /// (`Φ < 1` only — the earliest single-number warning), or `Structure` (`Φ < 1` and
    /// `P < 2/N`). By the leading-indicator theorem `Structure` never fires without `Integration`.
    #[must_use]
    pub fn alarm(&self) -> crate::window::Alarm {
        let m = self.measures(); // one Frobenius pass for both thresholds
        let phi_low = m.phi < PHI_TH - 1e-12;
        let p_low = m.purity < p_crit(self.n) - 1e-12;
        match (phi_low, p_low) {
            (false, _) => crate::window::Alarm::Healthy,
            (true, false) => crate::window::Alarm::Integration,
            (true, true) => crate::window::Alarm::Structure,
        }
    }

    /// The collective-subject classification from the mean correlation (spec §18.2, V19):
    /// `Aggregate` (too weak to bind), `CollectiveSubject` (in the band), or `OverCoupled`.
    #[must_use]
    pub fn collective_state(&self) -> crate::window::CollectiveState {
        crate::window::classify_collective(self.mean_correlation(), self.n)
    }
}

// --- Equicorrelated closed forms (spec §2.7, V15) ---

/// Closed-form integration on the equicorrelated stratum: `Φ = (N−1) r²`.
#[must_use]
pub fn phi_equicorrelated(n: usize, r: f64) -> f64 {
    (n - 1) as f64 * r * r
}

/// Closed-form purity on the equicorrelated stratum: `P = (1 + (N−1) r²) / N`.
#[must_use]
pub fn purity_equicorrelated(n: usize, r: f64) -> f64 {
    (1.0 + (n - 1) as f64 * r * r) / n as f64
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn from_correlation_rejects_non_finite_entries() {
        // A valid 2×2 correlation matrix is accepted.
        assert!(CoherenceMatrix::from_correlation(vec![1.0, 0.3, 0.3, 1.0], 2).is_some());
        // NaN or ±∞ anywhere is rejected — they would silently pass the tolerance checks (every
        // comparison with NaN is false) and poison the self-model (D2).
        assert!(CoherenceMatrix::from_correlation(vec![1.0, f64::NAN, f64::NAN, 1.0], 2).is_none());
        assert!(CoherenceMatrix::from_correlation(vec![f64::INFINITY, 0.0, 0.0, 1.0], 2).is_none());
        assert!(
            CoherenceMatrix::from_correlation(vec![1.0, 0.3, 0.3, f64::NEG_INFINITY], 2).is_none()
        );
    }

    #[test]
    fn simd_frobenius_matches_scalar() {
        let data: Vec<f64> = (0..137).map(|i| (i as f64) * 0.013 - 0.7).collect();
        assert!((frobenius_sq(&data) - frobenius_sq_scalar(&data)).abs() < 1e-9);
    }

    #[test]
    fn measures_match_equicorrelated_closed_forms() {
        // V15: matrix measures agree with the closed forms on the equicorrelated stratum.
        for &r in &[0.0, 0.1, 0.3, 0.408, 0.5, 0.7] {
            let g = CoherenceMatrix::equicorrelated(7, r);
            assert!(
                (g.phi() - phi_equicorrelated(7, r)).abs() < 1e-9,
                "Φ at r={r}"
            );
            assert!(
                (g.purity() - purity_equicorrelated(7, r)).abs() < 1e-9,
                "P at r={r}"
            );
            // Φ = N·P − 1 identity.
            assert!((g.phi() - (7.0 * g.purity() - 1.0)).abs() < 1e-9);
        }
    }

    #[test]
    fn critical_correlation_couples_thresholds() {
        // V15: Φ=1 ⟺ P=2/7 ⟺ r=1/√6, all at the single critical mean correlation.
        let rstar = systemic_correlation(7);
        assert!((rstar - 1.0 / sqrt(6.0)).abs() < 1e-12);
        let g = CoherenceMatrix::equicorrelated(7, rstar);
        assert!((g.phi() - 1.0).abs() < 1e-9, "Φ(r*) = 1");
        assert!((g.purity() - 2.0 / 7.0).abs() < 1e-9, "P(r*) = 2/7");
        assert!((g.reflection() - 0.5).abs() < 1e-9, "R(r*) = 1/2");
    }

    #[test]
    fn correlation_from_signals_is_well_formed() {
        // Two anti-correlated signals and one independent-ish; diagonal must be 1.
        let a = vec![1.0, 2.0, 3.0, 4.0];
        let b = vec![4.0, 3.0, 2.0, 1.0];
        let c = vec![1.0, 0.0, 1.0, 0.0];
        let g = CoherenceMatrix::from_signals(&[a, b, c]).unwrap();
        assert_eq!(g.n(), 3);
        assert!((g.c[0] - 1.0).abs() < 1e-12);
        assert!((g.c[1] + 1.0).abs() < 1e-9, "a,b perfectly anti-correlated");
    }

    #[test]
    fn systemic_regime_detected_above_threshold() {
        let below = CoherenceMatrix::equicorrelated(7, 0.35);
        let above = CoherenceMatrix::equicorrelated(7, 0.45);
        assert!(!below.is_systemic());
        assert!(above.is_systemic());
    }
}

/// The **D6 quarantine-theorem experiment** (`docs/design-quarantine-theorem.md`): a deterministic
/// simulation that the closed-form `Φ' = (N·Φ − 2·s_q)/(N−1)` matches a full recompute, that the condition
/// `s_q > Φ/2` predicts the sign of `Φ'−Φ` exactly, and that a Byzantine (over-coupled) node is quarantinable
/// while a silent (under-coupled) node is not (quarantining it would raise Φ).
#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod quarantine_experiment {
    use alloc::vec;

    use super::CoherenceMatrix;

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A correlation value in `[-0.9, 0.9]`.
    fn rand_corr(state: &mut u64) -> f64 {
        let u = (splitmix(state) >> 11) as f64 / (1u64 << 53) as f64; // [0, 1)
        u * 1.8 - 0.9
    }

    /// A random symmetric, unit-diagonal `n×n` correlation matrix.
    fn random_matrix(seed: u64, n: usize) -> CoherenceMatrix {
        let mut s = seed;
        let mut c = vec![0.0; n * n];
        for i in 0..n {
            c[i * n + i] = 1.0;
            for j in (i + 1)..n {
                let v = rand_corr(&mut s);
                c[i * n + j] = v;
                c[j * n + i] = v;
            }
        }
        CoherenceMatrix::from_correlation(c, n).unwrap()
    }

    #[test]
    fn the_closed_form_equals_the_full_recompute() {
        for seed in 0..300u64 {
            let n = 3 + (seed % 6) as usize; // 3..=8
            let m = random_matrix(seed, n);
            for q in 0..n {
                let closed = m.phi_after_quarantine(q).unwrap();
                let recompute = m.excise(q).unwrap().phi();
                assert!(
                    (closed - recompute).abs() < 1e-9,
                    "seed {seed} q {q}: closed-form Φ' {closed} ≠ recompute {recompute}"
                );
            }
        }
    }

    #[test]
    fn the_condition_predicts_the_sign_of_the_change_exactly() {
        for seed in 0..500u64 {
            let n = 3 + (seed % 6) as usize;
            let m = random_matrix(seed ^ 0xABCD, n);
            let phi = m.phi();
            for q in 0..n {
                let phi_after = m.excise(q).unwrap().phi();
                if (phi_after - phi).abs() < 1e-9 {
                    continue; // the exact boundary s_q = Φ/2 — neither strictly wins
                }
                assert_eq!(
                    m.quarantine_lowers_phi(q),
                    phi_after < phi,
                    "seed {seed} q {q}: predicted {} but Φ {phi} → {phi_after}",
                    m.quarantine_lowers_phi(q)
                );
            }
        }
    }

    #[test]
    fn a_byzantine_node_is_quarantinable_and_a_silent_node_is_not() {
        let n = 7;
        // A "Byzantine" node 0: spuriously highly coupled to everyone (others only weakly correlated).
        let mut c = vec![0.1; n * n];
        for i in 0..n {
            c[i * n + i] = 1.0;
        }
        for j in 1..n {
            c[j] = 0.9; // row 0
            c[j * n] = 0.9; // column 0
        }
        let byz = CoherenceMatrix::from_correlation(c, n).unwrap();
        assert!(byz.coupling_energy(0) > byz.phi() / 2.0, "the Byzantine node's coupling exceeds Φ/2");
        assert!(byz.quarantine_lowers_phi(0), "quarantining the Byzantine node lowers Φ");
        assert!(byz.phi_after_quarantine(0).unwrap() < byz.phi(), "Φ strictly drops");

        // A "silent" node 0: uncorrelated with everyone, while the rest are moderately coupled.
        let mut c2 = vec![0.5; n * n];
        for i in 0..n {
            c2[i * n + i] = 1.0;
        }
        for j in 1..n {
            c2[j] = 0.0;
            c2[j * n] = 0.0;
        }
        let silent = CoherenceMatrix::from_correlation(c2, n).unwrap();
        assert!(silent.coupling_energy(0) < silent.phi() / 2.0, "the silent node's coupling is below Φ/2");
        assert!(!silent.quarantine_lowers_phi(0), "quarantining a silent node is forbidden — it would raise Φ");
        assert!(silent.phi_after_quarantine(0).unwrap() > silent.phi(), "removing the silent node concentrates coupling");
    }
}
