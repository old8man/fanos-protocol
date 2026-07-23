//! The coherence matrix `Γ` — its flow-form constructor and the pure (unthresholded) measures.

use crate::aspect::{Aspect, FLOWS, N};

/// How much one aspect carries of each of the three flows — its column in the participation table.
/// A [`Gamma`] is built from one `Budget` per aspect; the numbers are relative weights (only their
/// ratios matter — each flow's column is L2-normalised into a mode).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Budget {
    /// Participation in the control flow.
    pub control: f64,
    /// Participation in the data flow.
    pub data: f64,
    /// Participation in the supply flow.
    pub supply: f64,
}

impl Budget {
    /// A budget from a `(control, data, supply)` triple.
    #[must_use]
    pub const fn new(control: f64, data: f64, supply: f64) -> Self {
        Self { control, data, supply }
    }

    /// This budget's weight in flow / mode `m` (`0=control, 1=data, 2=supply`).
    #[must_use]
    fn mode(&self, m: usize) -> f64 {
        match m {
            0 => self.control,
            1 => self.data,
            _ => self.supply,
        }
    }
}

/// A 7×7 trace-1 PSD coherence matrix over the seven [`Aspect`]s.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Gamma {
    m: [[f64; N]; N],
}

impl Gamma {
    /// The **flow-form constructor** (`holarch_lab.make_gamma_modes`): build `Γ` from a participation
    /// table, the flow weights `λ` (control, data, supply), and the background `ε`.
    ///
    /// Each flow `m` becomes a coherent mode `|ψ_m⟩` — its participation column, L2-normalised — and
    ///
    /// ```text
    /// Γ = (1−ε)·Σ_m λ_m |ψ_m⟩⟨ψ_m|  +  ε·I/7 ,
    /// ```
    ///
    /// which is PSD by construction with unit trace (the `λ` are renormalised to sum 1). Couplings are
    /// derived: `γ_ij = (1−ε)Σ_m λ_m ψ_mi ψ_mj`.
    #[must_use]
    pub fn from_modes(budgets: &[Budget; N], lambdas: [f64; FLOWS], eps: f64) -> Self {
        let lam_sum: f64 = lambdas.iter().sum();
        let mut m = [[0.0f64; N]; N];
        for (mode, &lam_raw) in lambdas.iter().enumerate() {
            let lam = lam_raw / lam_sum;
            // ψ = participation column `mode`, L2-normalised.
            let mut psi = [0.0f64; N];
            for (p, b) in psi.iter_mut().zip(budgets.iter()) {
                *p = b.mode(mode);
            }
            let norm = psi.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm > 0.0 {
                for x in &mut psi {
                    *x /= norm;
                }
            }
            // Γ += λ_m · ψψᵀ
            for (i, row) in m.iter_mut().enumerate() {
                for (j, cell) in row.iter_mut().enumerate() {
                    *cell += lam * psi[i] * psi[j];
                }
            }
        }
        // (1−ε)·Γ + ε·I/7
        let background = eps / N as f64;
        for (i, row) in m.iter_mut().enumerate() {
            for cell in row.iter_mut() {
                *cell *= 1.0 - eps;
            }
            row[i] += background;
        }
        Self { m }
    }

    /// A `Γ` from an explicit 7×7 matrix. The flow form ([`Gamma::from_modes`]) is the *canonical*
    /// constructor for a declared design, but the measures are general: this admits an arbitrary
    /// coherence matrix — e.g. one specified directly or estimated from telemetry — for the same
    /// verdict. Validity (symmetry, trace-1, PSD) is the caller's to check ([`Gamma::is_psd`] et al.).
    #[must_use]
    pub fn from_matrix(m: [[f64; N]; N]) -> Self {
        Self { m }
    }

    /// The maximally-formless reference: the grey matrix `I/7` (`P = 1/7`, `Φ = 0` — non-viable).
    #[must_use]
    pub fn grey() -> Self {
        let mut m = [[0.0f64; N]; N];
        let d = 1.0 / N as f64;
        for (i, row) in m.iter_mut().enumerate() {
            row[i] = d;
        }
        Self { m }
    }

    /// The maximally-concentrated reference: one aspect carries everything (`γ_aa = 1`). The `D = 7`,
    /// `Coh = 1` corner used in tests.
    #[must_use]
    pub fn pure_aspect(a: Aspect) -> Self {
        let mut m = [[0.0f64; N]; N];
        m[a.index()][a.index()] = 1.0;
        Self { m }
    }

    /// The entry `γ_ij`.
    #[must_use]
    pub fn entry(&self, i: usize, j: usize) -> f64 {
        self.m[i][j]
    }

    /// `Tr Γ = Σ_i γ_ii`. A valid coherence matrix is trace-1 (the flow constructor guarantees it); the
    /// whole P/Φ/D reading assumes it, so it is worth asserting.
    #[must_use]
    pub fn trace(&self) -> f64 {
        (0..N).map(|i| self.m[i][i]).sum()
    }

    /// Whether `Γ` is symmetric to `tol` (`γ_ij = γ_ji`) — couplings are undirected.
    #[must_use]
    pub fn is_symmetric(&self, tol: f64) -> bool {
        for i in 0..N {
            for j in (i + 1)..N {
                if (self.m[i][j] - self.m[j][i]).abs() > tol {
                    return false;
                }
            }
        }
        true
    }

    /// Whether `Γ` is **positive semidefinite** — i.e. a valid coherence / density operator — verified
    /// by a tolerant `LDLᵀ` factorisation: the decomposition exists with every pivot `≥ −tol`, and any
    /// (near-)zero pivot leaves a vanishing column (else the matrix is indefinite).
    ///
    /// PSD is guaranteed *by construction* ([`Gamma::from_modes`] is a non-negative combination of
    /// rank-1 projectors plus `εI/7`); this checks it numerically, so a future edit to the constructor
    /// that broke the property could not pass silently.
    #[must_use]
    pub fn is_psd(&self, tol: f64) -> bool {
        let mut l = [[0.0f64; N]; N];
        let mut d = [0.0f64; N];
        for j in 0..N {
            let mut pivot = self.m[j][j];
            for k in 0..j {
                pivot -= l[j][k] * l[j][k] * d[k];
            }
            if pivot < -tol {
                return false; // a negative pivot ⇒ an indefinite direction.
            }
            d[j] = pivot;
            l[j][j] = 1.0;
            for i in (j + 1)..N {
                let mut off = self.m[i][j];
                for k in 0..j {
                    off -= l[i][k] * l[j][k] * d[k];
                }
                if pivot.abs() <= tol {
                    // Zero pivot: PSD requires the rest of this column to vanish too.
                    if off.abs() > 1e-6 {
                        return false;
                    }
                    l[i][j] = 0.0;
                } else {
                    l[i][j] = off / pivot;
                }
            }
        }
        true
    }

    /// **P = Tr(Γ²) = Σ_ij γ_ij²** — structuredness / purity (V1).
    #[must_use]
    pub fn purity(&self) -> f64 {
        self.m.iter().flatten().map(|&x| x * x).sum()
    }

    /// Σ_i γ_ii² — the diagonal power (denominator of Φ and normaliser of Coh_E).
    #[must_use]
    fn diagonal_sq(&self) -> f64 {
        self.m.iter().enumerate().map(|(i, row)| row[i] * row[i]).sum()
    }

    /// Σ_{i≠j} γ_ij² — the off-diagonal power (the coupling energy).
    #[must_use]
    pub fn off_diagonal_sq(&self) -> f64 {
        self.purity() - self.diagonal_sq()
    }

    /// **Φ = Σ_{i≠j}γ_ij² / Σ_i γ_ii²** — integration (V3).
    #[must_use]
    pub fn phi(&self) -> f64 {
        self.off_diagonal_sq() / self.diagonal_sq()
    }

    /// **R = 1/(7P)** — the canonical reflexivity lower bound (V2); `R ≥ 1/3 ⇔ P ≤ 3/7`.
    #[must_use]
    pub fn reflection(&self) -> f64 {
        1.0 / (N as f64 * self.purity())
    }

    /// **Coh_E = (γ_EE² + 2Σ_{i≠E}γ_Ei²) / P** — how much of the total structure is bound up in
    /// interiority (`axiom-septicity`); `Coh_E ∈ [1/7, 1]`.
    #[must_use]
    pub fn coh_e(&self) -> f64 {
        let e = Aspect::E.index();
        let row = &self.m[e];
        let mut num = row[e] * row[e];
        for (j, &v) in row.iter().enumerate() {
            if j != e {
                num += 2.0 * v * v;
            }
        }
        num / self.purity()
    }

    /// **D = 1 + (N−1)·Coh_E** — differentiation (V4); the grey matrix gives `1 + 6/7 ≈ 1.857`, and
    /// pure-E gives `7`.
    #[must_use]
    pub fn differentiation(&self) -> f64 {
        1.0 + (N as f64 - 1.0) * self.coh_e()
    }
}
