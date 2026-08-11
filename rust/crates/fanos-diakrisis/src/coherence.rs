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
//!
//! # The three measures are one number, and the second dimension is dispersion
//!
//! [`CoherenceMatrix::from_correlation`] enforces an **exact** unit diagonal, so `Σ_i γ_ii² = 1/N` is
//! pinned. Writing `s = Σ_ij C_ij²`:
//!
//! ```text
//! Φ = s/N − 1        P = s/N²        R = N/s
//! ```
//!
//! — all three strictly monotone in the one scalar `s`, hence **bijections of one another**:
//! `P = (1 + Φ)/N` and `R = 1/(1 + Φ)`. The thresholds coincide accordingly: `Φ ≥ 1 ⟺ P > 2/N`, and
//! `R ≥ 1/3 ⟺ Φ ≤ 2`, so the whole scalar verdict this crate produces is **`Φ ∈ (1, 2]`**, stated in three
//! vocabularies here and three more in [`crate::window`].
//!
//! This is *stronger* than the equicorrelated result in [`crate::minima::viability_is_integration`], and
//! deliberately so. That function's doc reasons about a general trace-1 `Γ`, where `Σγ_ii² ≥ 1/N` is an
//! inequality: there `Φ > 1 ⟹ P > 2/N` one way only, and the converse fails when coherence **concentrates
//! onto a few nodes** — which is what makes `Alarm::Integration` a centralization detector. A correlation
//! matrix sits exactly on the boundary of that inequality, so on the matrices a running node builds, the
//! implication closes and the detector has nothing left to detect. Normalising every node's activity to
//! unit variance is what throws the concentration away.
//!
//! **Closed (#104), and the fix is the same formula rather than a new one.** A [`CoherenceMatrix`] now
//! carries the **activity shares** `d_i = var_i / Σ var_j` beside the correlation, so `γ_ij = √(d_i d_j)·c_ij`
//! and the diagonal is `d` rather than `1/N`. Then `Σγ_ii² = Σd_i²`, `Φ = Σ_{i≠j}d_i d_j c_ij² / Σd_i²` and
//! `P = Σd_i²·(1 + Φ)` — which collapse to the previous expressions **exactly** at `d_i = 1/N`. A cell whose
//! members are equally active therefore reads precisely as it did before; the numbers differ only where the
//! old ones were blind, which is where one node carries the cell's behaviour. `Alarm::Integration` is now
//! reachable from `from_signals`, and only from a genuinely concentrated cell.
//!
//! What remains genuinely two-dimensional is the gap between the off-diagonals' **RMS** `q` (which `Φ`
//! reads, `Φ = (N−1)q²`) and their **mean** `m` (which [`crate::window::classify_collective`] reads). By
//! Cauchy–Schwarz `m² ≤ q²`, with equality exactly on the equicorrelated stratum, so
//! [`Measures::dispersion`] `v = q² − m²` is the second coordinate. It is not a curiosity: the
//! under-coupled `Bind` band is `q > lo ≥ m`, which is *unreachable at `v = 0`* — the band exists only for
//! a cell that couples **unevenly**, which is precisely a load hotspot, and precisely what the §6.7
//! rebalance answers.

use alloc::vec;
use alloc::vec::Vec;
use core::simd::f64x8;
use core::simd::num::SimdFloat;

use fanos_geometry::fano;

use crate::eig::eigenvalues_symmetric;
use crate::mathfns::sqrt;

/// The systemic-correlation threshold `r* = 1/√(N−1)` (spec §2.7) **at a flat diagonal**. At the mean
/// off-diagonal correlation `r*`, integration and structure thresholds coincide; above it the cell is in
/// the cascade-failure regime. For `N = 7` this is `1/√6 ≈ 0.408`.
///
/// **The flatness is a second condition, and the stratum's name carries only the first** (UHM T-312/T-314).
/// The general phase line is [`systemic_correlation_at`]; this is that function at `p = 1/N`, and the
/// identity is asserted rather than asserted-about. Kept as the `N`-form because the CLI reports it and a
/// conformance vector pins it, and because a deployment that keeps node weights balanced *is* on the flat
/// stratum — but nothing here should read `0.408` off a cell whose diagonal it has not looked at.
#[must_use]
pub fn systemic_correlation(n: usize) -> f64 {
    debug_assert!(n >= 2);
    1.0 / sqrt((n - 1) as f64)
}

/// The phase line `r* = √(p/(1−p))` at a stated diagonal purity `p = Σᵢ dᵢ²` — the correlation at which
/// `Φ` crosses 1, in general rather than on the flat stratum (UHM T-312).
///
/// **It rises as the weights concentrate**: a lopsided cell needs *more* correlation to go systemic, not
/// less, so a monitor reading the flat `1/√(N−1)` off one calls it a collective subject before it is. At a
/// node carrying 30 % of the behavioural variance the true line is `0.455` against the flat `0.408`, and a
/// cell measured at `r = 0.45` there has `Φ = 0.977` — an aggregate, read as a subject.
///
/// `p` outside `(0, 1)` has no phase line: `p = 0` is an empty cell and `p = 1` is one node carrying
/// everything, where there is no inter-node correlation to speak of. Both return infinity, which classifies
/// as [`Aggregate`](crate::window::CollectiveState::Aggregate) — the same fail-safe
/// [`collective_subject_window`](crate::window::collective_subject_window) takes for `n < 2`.
#[must_use]
pub fn systemic_correlation_at(p: f64) -> f64 {
    if p <= 0.0 || p >= 1.0 {
        return f64::INFINITY;
    }
    sqrt(p / (1.0 - p))
}

/// Integration at a stated correlation and diagonal purity: `Φ = r²·(1−p)/p` (UHM T-312).
///
/// **The only integration law in the crate.** It replaced `phi_equicorrelated(n, r) = (N−1)r²`, which was
/// this at `p = 1/N` — and having the special case as its own function let a caller evaluate a stratum
/// result without naming the stratum (UHM T-316). The two differ exactly when the diagonal is not flat, and
/// that difference is what [`CoherenceMatrix::measures`] has been computing correctly all along while the
/// *classifiers* assumed it away.
#[must_use]
pub fn phi_at(r: f64, p: f64) -> f64 {
    if p <= 0.0 || p >= 1.0 {
        return 0.0;
    }
    r * r * (1.0 - p) / p
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

/// The coherence measures read together (see [`CoherenceMatrix::measures`]).
///
/// **`phi`, `purity` and `reflection` carry one degree of freedom between them**, not three — see the
/// module documentation. [`dispersion`](Self::dispersion) is the second, and it is the one the
/// under-coupled band actually turns on.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Measures {
    /// Integration `Φ` (threshold `1`).
    pub phi: f64,
    /// Structuredness `P = Tr(Γ²)` (threshold `2/N`). A bijection of `phi`: `P = (1 + Φ)/N`.
    pub purity: f64,
    /// Reflection `R = 1/(N·P)` (threshold `1/3`). Also a bijection of `phi`: `R = 1/(1 + Φ)`.
    pub reflection: f64,
    /// **Pairwise dispersion** `v = q² − m²` — the variance of the off-diagonal correlations, where `q` is
    /// their RMS (`Φ = (N−1)q²`) and `m` their mean (what `classify_collective` reads).
    ///
    /// The genuinely independent second dimension. Zero exactly on the equicorrelated stratum, and strictly
    /// positive whenever the cell couples unevenly — which is the load-hotspot signature the §6.7 response
    /// answers, and the only way `BandControl::Bind` is reachable at all.
    pub dispersion: f64,
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
    /// The correlation matrix `C`.
    c: Vec<f64>,
    /// **Activity shares** `d_i = var_i / Σ var_j`, summing to 1 — the diagonal of the unit-trace `Γ`.
    ///
    /// `Γ_net = C / n` holds only when every node contributes the same variance. In general
    /// `γ_ij = √(d_i d_j)·c_ij`, and the diagonal is `d`, not `1/n`. Carrying it is what makes
    /// [`crate::window::Alarm::Integration`] reachable at all: that alarm reads `Φ < 1` with `P ≥ 2/N`,
    /// which the `d_i = 1/n` idealisation makes **identically empty** (`P = (1+Φ)/N` forces
    /// `P ≥ 2/N ⟺ Φ ≥ 1`). A detector the docs call the platform's earliest warning could not fire.
    ///
    /// Uniform shares reproduce the old numbers exactly, so this is the completion of the same formula
    /// rather than a redefinition — it differs only where the old one was blind.
    d: Vec<f64>,
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
        // A correlation entry obeys |c_ij| ≤ 1 (Cauchy–Schwarz on the underlying signals); a
        // magnitude above 1 is not a correlation at all and would inflate the Frobenius sum —
        // and thus Φ — without bound. The unit diagonal is checked exactly just below.
        if c.iter().any(|x| x.abs() > 1.0 + 1e-9) {
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
        // A genuine correlation matrix is positive semidefinite. |c_ij| ≤ 1 is necessary but not
        // sufficient for n ≥ 3 (e.g. every off-diagonal = −0.9 is symmetric, unit-diagonal, and
        // in range yet has a negative eigenvalue), so reject any matrix whose least eigenvalue is
        // negative beyond a few-ulp floor: an indefinite "self-model" produces a finite but
        // meaningless Φ that can invert the V17 leading-indicator ordering and misfire Decouple/
        // Systemic. The spectrum is exact for symmetric input; the solver already rejects the
        // non-finite inputs excluded above, so `?` here is belt-and-braces. Eigenvalues sum to
        // Tr = n, so a floor of −1e-9·n absorbs Jacobi rounding without admitting real negatives.
        let eigs = eigenvalues_symmetric(&c, n)?;
        if eigs.first().is_some_and(|&min| min < -1e-9 * n as f64) {
            return None;
        }
        // A caller-supplied correlation matrix carries no variances, so activity is taken as uniform — the
        // classical `Γ = C/n`. That is the honest default rather than an assumption: a matrix handed in
        // without the signals behind it has no concentration to read.
        let d = vec![1.0 / n.max(1) as f64; n];
        Some(Self { n, c, d })
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
        // Activity shares from the same variances the correlation just divided out. A cell where one node
        // carries most of the behavioural variance has a concentrated diagonal, which is exactly the
        // centralization `Alarm::Integration` names — and exactly what normalising to unit variance throws
        // away. A cell with no variance anywhere (every node idle) has no shares to speak of, so it falls
        // back to uniform rather than to zeros, which would make every measure `NaN`.
        let total: f64 = std.iter().map(|s| s * s).sum();
        if total <= 1e-12 {
            // **No variance anywhere is not a measurement of zero correlation** (#229). The old fallback
            // returned a uniform diagonal here, and the resulting matrix was BIT-IDENTICAL to a cell of
            // genuinely independent busy nodes: `Φ = 0`, `P = 1/7`, `p = 1/7`, `r = 0`, `v = 0`, alarm
            // `Structure`. Three distinguishable conditions — real distributed work, total silence, and a
            // steady unchanging load — all read as the platform's most severe coherence alarm, from the one
            // input that could have separated them and was then discarded.
            //
            // `None` is the honest answer and it already has a consumer: `BehaviorMonitor::coherence`
            // propagates it, and `Healer::emit_observation` then takes the synthesised path, which stamps
            // the frame `measured = false`. That bit exists for exactly this distinction (#154) — it was
            // introduced for "no window yet" and the case one step over, "a full window with nothing in
            // it", slipped past it. Same guard, same reason, the twin that was left unguarded.
            //
            // A cell that is merely *quiet* is not collapsed. A cell that is quiet and reports collapse
            // sends its parent an escalation about nothing.
            return None;
        }
        let d: Vec<f64> = std.iter().map(|s| s * s / total).collect();
        Some(Self { n, c, d })
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
        // Equicorrelated names the *correlation* stratum; uniform activity is what makes it the classical
        // `Γ = C/n`, and it is what every existing caller of this constructor means.
        let d = vec![1.0 / n.max(1) as f64; n];
        Self { n, c, d }
    }

    /// The number of nodes `N`.
    #[must_use]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Every scalar measure from **two** O(n²) passes over `C` — a Frobenius one and a plain sum.
    ///
    /// Because `Γ = C/n` with unit-diagonal `C`, `Φ`, `P` and `R` all reduce to `frob = Σ C_ij²`:
    /// `P = frob/n²`, `Φ = (frob − n)/n` (`= Σ_{i≠j}γ_ij² ÷ Σ_i γ_ii²`), and `R = 1/(N·P) = n/frob` — which
    /// is exactly why they are bijections of one another and why one pass used to be enough. The second
    /// pass is the off-diagonal **mean**, and the gap between it and the RMS is
    /// [`dispersion`](Measures::dispersion), the only quantity here that `frob` does not already determine.
    /// Prefer this to calling [`phi`](Self::phi)/[`purity`](Self::purity)/[`reflection`](Self::reflection)
    /// separately — each of those repeats the same O(n²) SIMD pass.
    #[must_use]
    pub fn measures(&self) -> Measures {
        let nf = self.n as f64;
        if nf <= 0.0 {
            return Measures { phi: 0.0, purity: 0.0, reflection: 0.0, dispersion: 0.0 };
        }
        // `γ_ij = √(d_i d_j)·c_ij`, so `Σ_{i≠j}γ_ij² = Σ_{i≠j} d_i d_j c_ij²` and `Σ_i γ_ii² = Σ d_i²`.
        // At uniform `d_i = 1/n` these collapse to `(Σ C_ij² − n)/n` and `1/n` — the previous expressions,
        // exactly — so a cell whose nodes are equally active reads precisely as it did before.
        let diag: f64 = self.d.iter().map(|x| x * x).sum();
        let mut off = 0.0;
        for i in 0..self.n {
            for j in 0..self.n {
                if i != j
                    && let (Some(&di), Some(&dj), Some(&cij)) =
                        (self.d.get(i), self.d.get(j), self.c.get(i * self.n + j))
                {
                    off += di * dj * cij * cij;
                }
            }
        }
        let phi = if diag > 0.0 { off / diag } else { 0.0 };
        let purity = diag * (1.0 + phi); // Tr(Γ²) = Σd_i² + Σ_{i≠j}γ_ij²
        Measures {
            phi,
            purity,
            reflection: if purity > 0.0 {
                1.0 / (nf * purity)
            } else {
                0.0
            },
            // `Φ = (n−1)·q²` gives the RMS of the off-diagonals; the mean is the second pass. Clamped at
            // zero because Cauchy–Schwarz makes `m² ≤ q²` exact, so a negative here would be rounding.
            dispersion: if self.n >= 2 {
                let m = self.mean_correlation();
                (phi / (nf - 1.0) - m * m).max(0.0)
            } else {
                0.0
            },
        }
    }

    /// **Pairwise dispersion** `v = q² − m²`: the variance of the off-diagonal correlations.
    ///
    /// The second degree of freedom in the self-model, and the one that decides which *under*-coupled
    /// answer a cell gets. See [`Measures::dispersion`] and the module documentation.
    #[must_use]
    pub fn dispersion(&self) -> f64 {
        self.measures().dispersion
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
    /// theorem's exact condition `s_q > Φ/2`: excising a node whose coupling energy exceeds half the cell
    /// integration reduces Φ, and excising an under-coupled one *raises* it. `false` for a degenerate cell.
    ///
    /// # It has no caller, and that is correct (#156)
    ///
    /// This is the gate for a **coherence-motivated** excision — one chosen *in order to move Φ*. FANOS has
    /// none. Every quarantine it emits is a **security** action: the `Verdict::Structural` arm of
    /// `plan_healing` (a polar sum-rule violation — proven equivocation), the vouch-fabricator detector, and
    /// the driver's identity-keyed `Command::Quarantine` (audit R-M1).
    ///
    /// **Do not install it on those.** `s_q` is read from the measured *relay-activity* correlation matrix
    /// while a `Verdict::Structural` is read from the *polar attestation* sum rules — independent inputs — so
    /// a member that equivocates while relaying little traffic is simultaneously caught and under-coupled,
    /// and this predicate would spare it. An adversary evading exile by doing *less* work.
    ///
    /// Kept `pub` rather than hidden behind `cfg(test)` because it is the correct gate for the excision that
    /// does not exist yet, and the theorem it implements is proven and validated
    /// (`docs/design-quarantine-theorem.md`, `quarantine_experiment`). When that excision is built, gate it
    /// here and say at the call site that the security quarantines are deliberately outside D6.
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
        // Dropping a node redistributes its activity share over the survivors — renormalised, not discarded,
        // or the remaining cell would read as though it had lost the variance rather than the member.
        let kept: Vec<f64> = (0..self.n).filter(|&i| i != q).filter_map(|i| self.d.get(i).copied()).collect();
        let total: f64 = kept.iter().sum();
        let d = if total > 1e-12 {
            kept.iter().map(|x| x / total).collect()
        } else {
            vec![1.0 / m.max(1) as f64; m]
        };
        Some(Self { n: m, c, d })
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
        //
        // Against **this cell's own** phase line, not the flat-stratum one (UHM T-312/T-314): the diagonal
        // is right here in `self.d`, and reading `1/√(N−1)` off a concentrated cell calls it systemic
        // early.
        self.n >= 2 && self.mean_correlation() > systemic_correlation_at(self.diagonal_purity()) + 1e-12
    }

    /// Whether the cell is **over-coupled** — past its own band's upper edge with `R < 1/3`:
    /// integration has climbed past the collective-subject band and the cell is losing its
    /// self-model (spec §18.2, §6.8).
    ///
    /// This doc used to read *"`r > √(2/(N−1))`, **equivalently** `R < 1/3`"*. Those two are one line on
    /// the equicorrelated stratum and two different lines off it, and #275 moved the code to the second
    /// while leaving the sentence claiming they are the same. Measured on a Fano cell whose one line
    /// exchanged more than the rest: `r = 0.5746` against a flat edge of `0.5774`, with `R = 0.3209` — over
    /// -coupled, and below the edge the old sentence names. The word *equivalently* on a threshold is a
    /// theorem with scope conditions, and this one's scope is a flat diagonal.
    ///
    /// This — not the mere early-warning [`is_systemic`](Self::is_systemic)
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

    /// The **purity of the diagonal**, `p = Σᵢ dᵢ²` — the cell's concentration of behavioural weight.
    ///
    /// Flat activity gives `1/N`; one node carrying everything gives `1`. It is the second condition every
    /// "equicorrelated" closed form needs and the one that name does not carry (UHM T-312/T-314), and until
    /// now it had no name at all: it was a local called `diag` inside [`measures`](Self::measures), so no
    /// caller — not even inside this crate — could pass it to a classifier. That is why
    /// [`collective_state`](Self::collective_state) was comparing against the flat threshold on a cell whose
    /// diagonal this very struct had measured as concentrated.
    ///
    /// It is also the first of the four instrument families the state carries (UHM T-317) to get a reader
    /// here; the pairwise moduli are still private.
    #[must_use]
    pub fn diagonal_purity(&self) -> f64 {
        self.d.iter().map(|x| x * x).sum()
    }

    /// The **pairwise coupling** `c_ij` between two nodes, or `None` if either index is off the cell.
    ///
    /// The third instrument family (UHM T-317): `C(7,2) = 21` numbers on a Fano cell, of which the verdict
    /// keeps two summaries — [`mean_correlation`](Self::mean_correlation) and
    /// [`dispersion`](Self::dispersion). Both are symmetric functions, so neither can say *which* pair is
    /// coupled, and a summary is what the verdict is *for*. This is the reading underneath them.
    ///
    /// `c_ii = 1` exactly, by [`from_correlation`](Self::from_correlation)'s construction.
    #[must_use]
    pub fn pairwise(&self, i: usize, j: usize) -> Option<f64> {
        (i < self.n && j < self.n).then(|| self.c.get(i * self.n + j).copied())?
    }

    /// The **holonomy of a closed triple**, `c_ij · c_jk · c_ki` — the fourth instrument family (T-306).
    ///
    /// # What this is, and what it deliberately is not
    ///
    /// UHM's holonomy is `arg(γ_ij γ_jk γ_ki)` on a **complex** state, where the argument is a genuine
    /// phase taking a continuum of values. FANOS's substrate is a *real* correlation matrix, so that
    /// argument can only be `0` or `π` and the whole of the phase information UHM's `γ` carries is **not
    /// present here at all**. Borrowing the name without saying so would be claiming an instrument this
    /// platform does not have.
    ///
    /// What survives the restriction is exactly the part that matters for T-311: the **sign**. A negative
    /// product means the triple is **frustrated** — no assignment of "these two move together" is
    /// consistent around the loop — and `Φ` cannot see it, because `Φ` sums `c_ij²` and squares the sign
    /// away (#221). The magnitude `|c_ij c_jk c_ki|` says how strongly the loop is closed, so the reading
    /// is a signed strength rather than a bit.
    ///
    /// `None` if any index is off the cell, or if the three are not distinct — a "triple" with a repeated
    /// point is not a loop, and returning `c_ij²·1` for it would be a number with no meaning.
    #[must_use]
    pub fn triple_holonomy(&self, i: usize, j: usize, k: usize) -> Option<f64> {
        if i == j || j == k || i == k {
            return None;
        }
        Some(self.pairwise(i, j)? * self.pairwise(j, k)? * self.pairwise(k, i)?)
    }

    /// The seven Fano line holonomies, indexed by line — or `None` on any cell that is not `PG(2,2)`.
    ///
    /// A Fano line is three points, so it is exactly a closed triple, and the plane's seven lines are the
    /// seven loops the geometry itself names. See [`triple_holonomy`](Self::triple_holonomy) for what the
    /// number is and, more importantly, what it is not.
    ///
    /// **These seven do not span the cell's loops.** The cycle space of `K₇` has dimension
    /// `E − V + 1 = 21 − 7 + 1 = 15`; the seven lines span a proper subspace of it, and the remainder is
    /// dark to this reading — triangles the plane does not draw. `the_fano_lines_leave_exactly_eight_loop_dimensions_dark`
    /// computes both ranks rather than quoting them.
    #[must_use]
    pub fn line_holonomies(&self) -> Option<[f64; fano::N]> {
        if self.n != fano::N {
            return None;
        }
        let mut out = [0.0; fano::N];
        for (slot, points) in out.iter_mut().zip(fano::LINE_POINTS.iter()) {
            *slot = self.triple_holonomy(
                usize::from(points[0]),
                usize::from(points[1]),
                usize::from(points[2]),
            )?;
        }
        Some(out)
    }

    /// Bitmask of the Fano lines whose holonomy is **negative** — the frustrated loops (`0` on any cell
    /// that is not `PG(2,2)`, which is also the honest answer: no line is known to be frustrated).
    ///
    /// A tolerance is deliberately absent. The sign of a product of three measured correlations is a
    /// discrete fact about the estimate, and a "nearly zero" holonomy is a loop that is barely closed
    /// either way — the magnitude in [`line_holonomies`](Self::line_holonomies) is where that lives, and
    /// folding it into the mask would hide it.
    #[must_use]
    pub fn frustrated_lines(&self) -> u8 {
        self.line_holonomies().map_or(0, |h| {
            h.iter()
                .enumerate()
                .filter(|&(_, &v)| v < 0.0)
                .fold(0u8, |mask, (l, _)| mask | (1u8 << l))
        })
    }

    /// The per-node **activity shares** `d` — each node's share of the cell's behavioural variance,
    /// summing to 1.
    ///
    /// Until now the only public reading of the diagonal was [`diagonal_purity`](Self::diagonal_purity),
    /// the scalar `p = Σᵢ dᵢ²`, and **a scalar folds two opposite illnesses together**. Weight concentrates
    /// when one node is *starving* and when one node is *swallowing the cell*; `p` rises either way. A
    /// matched pair is in `tests/starved_or_dominant.rs`: node 0 at 0.30 amplitude and node 0 dominant,
    /// with `r` and `p` equal to six decimals, `Φ`, `P`, `R` agreeing to `3e-3`, and the same
    /// `CollectiveState` and `Alarm`. Every scalar the platform publishes says the two cells are the same
    /// cell, and the correct responses are opposite: feed the first, decouple the second.
    ///
    /// This is the vector those two diseases differ in, and it is the numerator of the **address** a cure
    /// needs — UHM `1ea2b27` measured that blind cell-wide exchange monotonically dilutes everyone and past
    /// a threshold collapses the colony, while naming the hungry axis and drawing from one specialised
    /// donor passes every threshold (#139, condition 4).
    ///
    /// **Cell-local only.** This must not widen the exported frame: `design-telemetry.md` §1.2.2 is that
    /// anything finer than the cell aggregate is *both* blind and forbidden, and the ε-DP floor releases
    /// one scalar. The surface that may read it is the node's own — local, unprivatized, and by §3 R4
    /// costing no anonymity.
    #[must_use]
    pub fn activity_shares(&self) -> &[f64] {
        &self.d
    }

    /// The **hungry axis**: the node furthest *below* an equal share, and its shortfall `1/n − dᵢ`.
    ///
    /// `None` for a degenerate cell (`n < 2`), where there is no axis to name. The shortfall is reported
    /// rather than the raw share so a caller compares against zero rather than re-deriving `1/n`, and so
    /// the two readings ([`starved_axis`](Self::starved_axis) and
    /// [`dominant_axis`](Self::dominant_axis)) are on one scale with opposite signs of the same quantity.
    ///
    /// It always names *someone*: on a perfectly uniform cell the shortfall is `0`, which is the honest
    /// answer — an axis exists, it is simply not hungry. A caller that wants "is anyone starving" must
    /// compare the shortfall against a threshold it derives, and this deliberately does not choose one:
    /// UHM's dose result says the cure has a *therapeutic window* (below it nothing heals, above it the
    /// coherence being served is destroyed), so the trigger and the dose belong to the executor that has
    /// measured that window, not to the sensor (`bccc3d7`, #139 condition 1).
    #[must_use]
    pub fn starved_axis(&self) -> Option<(usize, f64)> {
        self.extreme_axis(true)
    }

    /// The **dominant axis**: the node furthest *above* an equal share, and its excess `dᵢ − 1/n`.
    ///
    /// The mirror of [`starved_axis`](Self::starved_axis), and the reason both exist: `p` cannot tell them
    /// apart, and they call for opposite treatments.
    #[must_use]
    pub fn dominant_axis(&self) -> Option<(usize, f64)> {
        self.extreme_axis(false)
    }

    /// The node whose share deviates furthest from uniform in the requested direction, with the magnitude
    /// of that deviation. Ties go to the lowest index, so the answer is deterministic across a cell whose
    /// seats a rotation may permute.
    fn extreme_axis(&self, below: bool) -> Option<(usize, f64)> {
        if self.n < 2 {
            return None;
        }
        let uniform = 1.0 / self.n as f64;
        let mut best = (0usize, f64::NEG_INFINITY);
        for (i, &share) in self.d.iter().enumerate() {
            let deviation = if below { uniform - share } else { share - uniform };
            if deviation > best.1 {
                best = (i, deviation);
            }
        }
        Some(best)
    }

    /// The collective-subject classification from the mean correlation (spec §18.2, V19):
    /// `Aggregate` (too weak to bind), `CollectiveSubject` (in the band), or `OverCoupled`.
    ///
    /// Classified against **this cell's own** window for the lower edge, and against its **measured**
    /// self-model for the upper one.
    ///
    /// The lower edge is [`diagonal_purity`](Self::diagonal_purity)'s window (#219): on the flat stratum it
    /// is exactly the old reading, off it the old one was optimistic, and the direction matters — it called
    /// an aggregate a subject, never the reverse.
    ///
    /// **The upper edge cannot be a prediction, because the equivalence it rested on is a stratum result**
    /// (#275, UHM `1ea2b27`). [`is_overcoupled`](Self::is_overcoupled) defines over-coupling as
    /// "`r > √(2/(N−1))`, *equivalently* `R < 1/3`" — the two agree exactly where `Φ = r²(1−p)/p` is the
    /// whole story, which is the equicorrelated stratum. Off it a third parameter enters: the *dispersion*
    /// of the off-diagonals raises the real `Φ` above what that two-parameter law predicts from `r`, so the
    /// cell loses its self-model while `r` is still inside the band. Measured on a Fano cell whose one line
    /// exchanges more than the rest: at `r = 0.5746` — below the `0.5774` edge — the cell reads `R = 0.3209`
    /// and `Φ = 2.1065`, already past the `Φ = 2` the edge was solved at, and the old test called it a
    /// healthy collective subject. The error is one-directional: dispersion only ever raises `Φ`, so the
    /// prediction is only ever **late**, and late is the side where `Decouple` does not fire.
    ///
    /// So the upper edge reads `R` — the quantity the definition was always about — and the `hi` edge stays
    /// what it honestly is: a landmark an operator can compare `r` against, not the trigger.
    ///
    /// Ordering matters: a cell below the lower edge is an [`Aggregate`] even if its `R` is low, because
    /// there the self-model was lost to *concentration*, not to coupling, and shedding correlation is the
    /// wrong answer — that case is [`Alarm::Structure`](crate::window::Alarm)'s.
    ///
    /// [`Aggregate`]: crate::window::CollectiveState::Aggregate
    #[must_use]
    pub fn collective_state(&self) -> crate::window::CollectiveState {
        crate::window::classify_collective(
            self.mean_correlation(),
            self.diagonal_purity(),
            self.measures().reflection,
        )
    }
}

// --- Equicorrelated closed forms (spec §2.7, V15) ---

// `phi_equicorrelated(n, r) = (N−1)r²` was here. It is gone, and its absence is the point (UHM
// T-312/T-314/T-316): it was the `p = 1/N` case of [`phi_at`], and having it as its own function meant a
// caller could evaluate a stratum result without ever naming the stratum. Every former use is now
// `phi_at(r, 1.0 / n as f64)` — the flat diagonal is a call site, visible in the argument, rather than a
// second function that looks like the general one. `purity_equicorrelated` stays: it has a production
// caller (`minima::viability_is_integration`).


/// Closed-form purity on the equicorrelated stratum: `P = (1 + (N−1) r²) / N`.
#[must_use]
pub fn purity_equicorrelated(n: usize, r: f64) -> f64 {
    (1.0 + (n - 1) as f64 * r * r) / n as f64
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    /// The flat closed form is **wrong on a real cell**, by a margin big enough to mislead — which is why
    /// two docs that stated it as the definition were corrected (#219 follow-up, UHM T-316).
    ///
    /// `Φ = (N−1)r²` holds only where the diagonal is flat. `fanos-telemetry`'s operator-facing snapshot
    /// said `Φ = 6r²` outright, and the homeostat's shed doc named `(N−1)r²` as the thing it lowers. Neither
    /// named a stratum, so a reader on a lopsided cell would compute a number the cell does not have.
    ///
    /// This measures the gap rather than asserting the rule: a cell whose behavioural weight is
    /// concentrated on one node, with the correlation held fixed, and the two laws compared. It also shows
    /// the recovery path the corrected doc promises — `p = P/(1 + Φ)` — actually returns the diagonal
    /// purity, so a reader holding only the snapshot can still get the general law.
    #[test]
    fn the_flat_law_misreports_a_lopsided_cell_and_p_is_recoverable_from_the_snapshot() {
        // Sylvester–Hadamard rows: mutually orthogonal and zero-mean, so the correlation is exactly `r`
        // while node 0 carries twice the amplitude — same correlations, concentrated diagonal.
        let h = |i: usize, t: usize| if (i & t).count_ones().is_multiple_of(2) { 1.0f64 } else { -1.0f64 };
        let r: f64 = 0.45;
        let (a, b) = (sqrt(r), sqrt(1.0 - r));
        let signals: Vec<Vec<f64>> = (0..7)
            .map(|i| {
                let scale = if i == 0 { 2.0 } else { 1.0 };
                (0..16).map(|t| scale * (a * h(1, t) + b * h(i + 2, t))).collect()
            })
            .collect();
        let g = CoherenceMatrix::from_signals(&signals).expect("a well-formed matrix");
        let m = g.measures();
        let p = g.diagonal_purity();

        // The general law reproduces the measured Φ; the flat one does not, and the gap is not a rounding.
        let general = phi_at(g.mean_correlation(), p);
        let flat = 6.0 * g.mean_correlation() * g.mean_correlation();
        assert!(
            (general - m.phi).abs() < 1e-9,
            "the general law must reproduce the measured Φ: {general} vs {}",
            m.phi
        );
        // The harm, not merely a gap: the flat form reads 1.215 where the cell measures 0.718, so it
        // crosses `Φ ≥ 1` and calls an UNBOUND cell a bound subject. A wrong number that lands on the
        // right side of the verdict is a different defect from a wrong number.
        assert!(
            flat >= PHI_TH && m.phi < PHI_TH,
            "the flat form must cross the integration threshold while the measurement does not — that is \
             the harm the corrected docs exist to prevent: flat={flat}, measured={}, p={p}",
            m.phi
        );

        // And the snapshot's promise: `p = P/(1 + Φ)` recovers the diagonal purity from three fields.
        let recovered = m.purity / (1.0 + m.phi);
        assert!(
            (recovered - p).abs() < 1e-9,
            "P = p(1 + Φ) must invert: recovered {recovered} against measured {p}"
        );
    }


    /// **`Alarm::Integration` was unreachable from any matrix a node could build** — the detector the docs
    /// call the platform's earliest warning and its centralization sensor (#104).
    ///
    /// The proof is algebraic, not statistical. With a unit diagonal the old expressions were
    /// `P = ΣC_ij²/N²` and `Φ = (ΣC_ij² − N)/N`, so `P ≡ (1 + Φ)/N` **identically** — and therefore
    /// `P ≥ 2/N ⟺ Φ ≥ 1`. The alarm is `Φ < 1` **with** `P ≥ 2/N`: the empty set, on every input, forever.
    /// `minima.rs` reached it only by hand-writing a `Γ` with a heterogeneous diagonal, which
    /// `from_signals` could not produce, because normalising each node to unit variance is exactly what
    /// discards the heterogeneity.
    ///
    /// The fix is the general formula rather than a new one: `γ_ij = √(d_i d_j)·c_ij` with `d` the activity
    /// shares, collapsing to the old expressions at `d_i = 1/N`. So this test has two halves, and the second
    /// is what stops the first from being bought with a behaviour change: **uniform activity must still read
    /// exactly as before.**
    #[test]
    fn concentrated_activity_reaches_the_integration_alarm_and_uniform_activity_reads_as_before() {
        let n = 7usize;
        let len = 16usize;
        let sig = |i: usize, scale: f64| -> Vec<f64> {
            (0..len)
                .map(|t| scale * f64::from((t as u32).wrapping_mul(0x9E37_79B1 ^ i as u32) % 97))
                .collect()
        };
        // Uncorrelated activity with one node carrying almost all the variance: high `Tr(Γ²)` (the cell
        // looks structured, because its mass sits in one place) and no integration at all. A centralized
        // cell, which is what this alarm is named for.
        let concentrated: Vec<Vec<f64>> =
            (0..n).map(|i| sig(i, if i == 0 { 1000.0 } else { 1.0 })).collect();
        let got = CoherenceMatrix::from_signals(&concentrated).expect("a well-formed matrix").measures();
        assert!(got.phi < 1.0, "a centralized cell is not integrated: phi = {}", got.phi);
        assert!(
            got.purity >= 2.0 / n as f64,
            "and it still scores structured, which is what makes the pair an alarm: P = {} vs {}",
            got.purity,
            2.0 / n as f64
        );

        // Uniform activity means equal **variance**, which is a stronger thing than "no scale factor" and is
        // easy to get wrong: the first draft used the same generator with a per-node seed, whose variances
        // differ by a few percent, and the general formula correctly disagreed with the old one. A rotation
        // of one sequence is uniform exactly — same multiset per node, same variance, different correlations.
        let base: Vec<f64> = (0..len).map(|t| f64::from((t as u32).wrapping_mul(0x9E37_79B1) % 97)).collect();
        let uniform: Vec<Vec<f64>> = (0..n)
            .map(|i| (0..len).filter_map(|t| base.get((t + i) % len).copied()).collect())
            .collect();
        let um = CoherenceMatrix::from_signals(&uniform).expect("a well-formed matrix").measures();
        assert!(
            (um.purity - (1.0 + um.phi) / n as f64).abs() < 1e-12,
            "uniform activity must still give P = (1+phi)/N exactly: {} vs {}",
            um.purity,
            (1.0 + um.phi) / n as f64
        );
        // And there the alarm stays empty, which is correct rather than a residual gap: a cell whose members
        // are equally active has no concentration to report, so firing would be a false positive.
        assert_eq!(
            um.phi < 1.0,
            um.purity < 2.0 / n as f64,
            "the two crossings coincide under uniform activity, as the algebra says"
        );
    }

    use super::*;

    #[test]
    fn the_three_measures_are_bijections_of_one_scalar() {
        // The identity the module documents, asserted on matrices that are NOT equicorrelated — the point
        // being that this needs no stratum, only the unit diagonal `from_correlation` enforces. If it ever
        // stopped holding, `Measures` would have gained a third degree of freedom and every threshold
        // stated in one vocabulary would need re-reading in the others.
        let cases: [(usize, Vec<f64>); 3] = [
            (3, vec![1.0, 0.9, 0.1, 0.9, 1.0, 0.2, 0.1, 0.2, 1.0]),
            (3, vec![1.0, -0.4, 0.5, -0.4, 1.0, 0.0, 0.5, 0.0, 1.0]),
            (4, vec![
                1.0, 0.8, 0.0, 0.1, 0.8, 1.0, 0.1, 0.0, 0.0, 0.1, 1.0, 0.7, 0.1, 0.0, 0.7, 1.0,
            ]),
        ];
        for (n, c) in cases {
            let m = CoherenceMatrix::from_correlation(c, n).expect("a valid correlation matrix").measures();
            let nf = n as f64;
            assert!((m.purity - (1.0 + m.phi) / nf).abs() < 1e-12, "P = (1+Φ)/N");
            assert!((m.reflection - 1.0 / (1.0 + m.phi)).abs() < 1e-12, "R = 1/(1+Φ)");
            // …and therefore the two thresholds are one threshold, in either direction.
            assert_eq!(m.phi >= 1.0, m.purity >= p_crit(n), "Φ ≥ 1 ⟺ P ≥ 2/N, with no stratum assumed");
            assert_eq!(m.phi <= 2.0, m.reflection >= R_TH, "Φ ≤ 2 ⟺ R ≥ 1/3");
        }
    }

    /// **Three distinguishable cells no longer read identically** (#229).
    ///
    /// Measured before the fix, all four through the production constructor:
    ///
    /// ```text
    /// busy, genuinely independent   Φ=0  P=0.1429  p=0.1429  Structure
    /// silent, nothing happened      Φ=0  P=0.1429  p=0.1429  Structure
    /// steady equal load             Φ=0  P=0.1429  p=0.1429  Structure
    /// one node active, six silent   Φ=0  P=1.0000  p=1.0000  Integration
    /// ```
    ///
    /// The first three were bit-identical: real distributed work indistinguishable from total silence, all
    /// three raising the platform's most severe coherence alarm, and — through `Homeostat::control`'s
    /// purity gate — escalating a collapse to the parent. The one input that separates them is whether
    /// there was any variance at all, and the old fallback discarded it.
    ///
    /// A correlation needs variance. Two of the three have none, so their correlation is UNDEFINED, and
    /// `None` says that where a zero matrix asserted a measurement. The third does have variance and still
    /// reads `Structure` — that part is untouched here and is the arguable half of #229, because UHM T-319
    /// says a holon with no integration genuinely cannot self-recover.
    #[test]
    fn a_cell_with_no_variance_is_refused_rather_than_read_as_collapsed() {
        let h = |i: usize, t: usize| if (i & t).count_ones().is_multiple_of(2) { 1.0f64 } else { -1.0f64 };
        let silent: Vec<Vec<f64>> = (0..7).map(|_| vec![0.0f64; 16]).collect();
        let steady: Vec<Vec<f64>> = (0..7).map(|_| vec![5.0f64; 16]).collect();
        let independent: Vec<Vec<f64>> =
            (0..7).map(|i| (0..16).map(|t| h(i + 1, t)).collect()).collect();

        assert!(
            CoherenceMatrix::from_signals(&silent).is_none(),
            "a cell where nothing happened has no correlation to report"
        );
        assert!(
            CoherenceMatrix::from_signals(&steady).is_none(),
            "a cell at an unchanging load has no correlation to report either — same reason, and it used \
             to be the one that looked most like a real reading"
        );

        // The busy independent cell still reads, and still reads uncorrelated — which is the honest answer
        // for it. The point is that it is now DISTINGUISHABLE from the two above.
        let g = CoherenceMatrix::from_signals(&independent).expect("variance is present");
        assert!(g.phi() < 1e-9, "independent nodes are uncorrelated, Φ={}", g.phi());
        assert!(
            (g.diagonal_purity() - 1.0 / 7.0).abs() < 1e-9,
            "and evenly active, so p = 1/7 — the value that used to be shared with silence"
        );
    }

    /// **A cell that concentrates its behavioural weight is not a collective subject at the flat
    /// threshold** (UHM T-312/T-314) — the direction that was wrong, and it was wrong optimistically.
    ///
    /// The correlations are exact rather than sampled: seven signals built from mutually orthogonal
    /// Sylvester–Hadamard rows, each loading `√r` on one shared row and `√(1−r)` on a row of its own, so
    /// every pair correlates at exactly `r`. Scaling node 0's whole signal leaves every correlation
    /// untouched and moves only the variance shares — which is precisely the axis the flat closed form
    /// assumes away, isolated.
    ///
    /// The last assertion is the one that keeps this honest: it asserts the OLD reading disagrees. Without
    /// it the test would pass on a cell where both readings say `Aggregate` and would be pinning nothing.
    #[test]
    fn a_cell_that_concentrates_its_weight_is_not_called_a_subject_by_the_flat_threshold() {
        use crate::window::CollectiveState;

        // Sylvester–Hadamard: `H[i][j] = (−1)^popcount(i & j)`. Row 0 is constant (no variance after
        // centring, so unusable); rows 1.. are zero-mean and mutually orthogonal.
        let h = |i: usize, t: usize| if (i & t).count_ones().is_multiple_of(2) { 1.0f64 } else { -1.0f64 };
        let r: f64 = 0.45;
        let (a, b) = (sqrt(r), sqrt(1.0 - r));
        let signals: Vec<Vec<f64>> = (0..7)
            .map(|i| {
                // Node 0 carries twice the amplitude: same correlations, concentrated diagonal.
                let scale = if i == 0 { 2.0 } else { 1.0 };
                (0..16).map(|t| scale * (a * h(1, t) + b * h(i + 2, t))).collect()
            })
            .collect();
        let g = CoherenceMatrix::from_signals(&signals).expect("a well-formed matrix");

        let p = g.diagonal_purity();
        assert!(p > 1.0 / 7.0 + 1e-6, "the construction must concentrate the diagonal, got p={p}");
        assert!(
            (g.mean_correlation() - r).abs() < 1e-9,
            "the construction must hold the correlation at exactly r, got {}",
            g.mean_correlation()
        );

        // The exact measure says aggregate...
        assert!(g.phi() < 1.0, "Phi={} — this cell is below its own phase line", g.phi());
        // ...and the classifier now agrees with it.
        assert_eq!(
            g.collective_state(),
            CollectiveState::Aggregate,
            "p={p}, r={r}, Phi={}: a cell below its own phase line is an aggregate",
            g.phi()
        );
        // The disagreement this fixes, asserted so the test cannot go vacuous: the flat threshold, read off
        // the same cell, calls it a subject.
        assert_eq!(
            crate::window::classify_collective(g.mean_correlation(), 1.0 / 7.0, g.measures().reflection),
            CollectiveState::CollectiveSubject,
            "the flat threshold must still disagree, or this test is pinning nothing"
        );
    }

    #[test]
    fn dispersion_is_the_second_dimension_and_is_what_the_under_coupled_band_needs() {
        use crate::window::{CollectiveState, collective_subject_window};

        // Zero exactly on the equicorrelated stratum — where the three measures really do say everything.
        for &r in &[0.0, 0.3, 0.45, 0.8] {
            let g = CoherenceMatrix::equicorrelated(7, r);
            assert!(g.dispersion() < 1e-12, "an equicorrelated cell has no dispersion (r={r})");
        }

        // **The band that needs it.** A block of `k` perfectly-correlated nodes in a cell of 7 gives
        // `mean = C(k,2)/21` and `Φ = 2·C(k,2)/7`; `Bind` is `Φ > 1` with `mean ≤ lo`, which the arithmetic
        // satisfies only at `k = 4`. Built here rather than asserted about, so the claim is checked and not
        // merely restated.
        let block = |k: usize| {
            let n = 7;
            let mut c = vec![0.0; n * n];
            for i in 0..n {
                c[i * n + i] = 1.0;
                for j in 0..n {
                    if i != j && i < k && j < k {
                        c[i * n + j] = 1.0;
                    }
                }
            }
            CoherenceMatrix::from_correlation(c, n).expect("a block matrix is PSD")
        };
        let (lo, _) = collective_subject_window(7);
        for k in 2..=6usize {
            let g = block(k);
            let m = g.measures();
            let binds = m.phi > 1.0
                && g.collective_state() == CollectiveState::Aggregate;
            assert_eq!(
                binds,
                k == 4,
                "k={k}: Φ={:.3} mean={:.3} (lo={lo:.3}) — the under-coupled band is reachable at exactly \
                 one block size, and a cell in it necessarily has dispersion",
                m.phi,
                g.mean_correlation(),
            );
            if binds {
                assert!(m.dispersion > 0.0, "k={k}: `Bind` is unreachable at zero dispersion");
            }
        }
    }

    #[test]
    fn from_correlation_rejects_non_finite_out_of_range_and_non_psd_matrices() {
        // Valid correlation matrices (finite, |r| ≤ 1, symmetric, unit-diagonal, PSD) are accepted.
        assert!(CoherenceMatrix::from_correlation(vec![1.0, 0.3, 0.3, 1.0], 2).is_some());
        assert!(CoherenceMatrix::from_correlation(vec![1.0, 0.5, 0.5, 1.0], 2).is_some());
        // r = 0.9 equicorrelated 3×3 is PSD (eigenvalues {2.8, 0.1, 0.1}) — accepted.
        assert!(
            CoherenceMatrix::from_correlation(vec![1.0, 0.9, 0.9, 0.9, 1.0, 0.9, 0.9, 0.9, 1.0], 3)
                .is_some()
        );
        // NaN or ±∞ anywhere is rejected — they would silently pass the tolerance checks (every
        // comparison with NaN is false) and poison the self-model (D2).
        assert!(CoherenceMatrix::from_correlation(vec![1.0, f64::NAN, f64::NAN, 1.0], 2).is_none());
        assert!(CoherenceMatrix::from_correlation(vec![f64::INFINITY, 0.0, 0.0, 1.0], 2).is_none());
        assert!(
            CoherenceMatrix::from_correlation(vec![1.0, 0.3, 0.3, f64::NEG_INFINITY], 2).is_none()
        );
        // |c_ij| > 1 is not a correlation (Cauchy–Schwarz): rejected before it can inflate Φ.
        assert!(CoherenceMatrix::from_correlation(vec![1.0, 5.0, 5.0, 1.0], 2).is_none());
        // Symmetric, unit-diagonal, |r| ≤ 1, but indefinite (every off-diagonal = −0.9 ⇒ least
        // eigenvalue −0.8): the "spurious over-coupling" shape a garbage self-model takes. Rejected.
        assert!(
            CoherenceMatrix::from_correlation(
                vec![1.0, -0.9, -0.9, -0.9, 1.0, -0.9, -0.9, -0.9, 1.0],
                3
            )
            .is_none(),
            "an in-range but non-PSD matrix must be rejected"
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
                (g.phi() - phi_at(r, 1.0 / 7.0)).abs() < 1e-9,
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

    /// Wrap a raw symmetric matrix for the pure-algebra tests, bypassing the `from_correlation`
    /// PSD / |r| ≤ 1 ingestion guard. Those tests exercise the Frobenius identities (`phi`,
    /// `excise`, `phi_after_quarantine`, `quarantine_lowers_phi`), which hold for **any**
    /// symmetric unit-diagonal matrix — including the deliberately non-PSD Byzantine
    /// over-coupling case — so they must not be filtered by the ingestion boundary (which is
    /// tested separately in `from_correlation_rejects_non_finite_out_of_range_and_non_psd_matrices`).
    fn wrap_raw(c: Vec<f64>, n: usize) -> CoherenceMatrix {
        CoherenceMatrix { n, c, d: vec![1.0 / n.max(1) as f64; n] }
    }

    /// A random symmetric, unit-diagonal `n×n` matrix (not necessarily PSD — see [`wrap_raw`]).
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
        wrap_raw(c, n)
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
        // Non-PSD by construction (node 0's over-coupling is geometrically impossible) — this is
        // exactly what `from_correlation` now rejects, so build it raw to test the diagnosis algebra.
        let byz = wrap_raw(c, n);
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
        let silent = wrap_raw(c2, n);
        assert!(silent.coupling_energy(0) < silent.phi() / 2.0, "the silent node's coupling is below Φ/2");
        assert!(!silent.quarantine_lowers_phi(0), "quarantining a silent node is forbidden — it would raise Φ");
        assert!(silent.phi_after_quarantine(0).unwrap() > silent.phi(), "removing the silent node concentrates coupling");
    }
}
