//! Differentially-private telemetry export (audit C7 · `docs/design-telemetry.md` §5).
//!
//! A [`CoherenceFrame`](crate::CoherenceFrame) folds a cell's health into a minimal record, but that
//! record is **data-minimized, not anonymized**: it names the exact faulted point (the 3-bit syndrome)
//! and the cell's exact coherence scalars. An observer of an *exported* frame — a monitor feed, a
//! cross-cell roll-up, any shareable telemetry — could therefore read *which node is down* and correlate
//! a cell's health perturbations against traffic events to deanonymize flows. This module is the
//! anonymity floor for that export boundary.
//!
//! # Mechanism — the Laplace mechanism on the cell's sufficient statistic
//!
//! The privacy unit is **one flow** (equivalently one of the `C(7,2) = 21` node pairs of a Fano cell):
//! two cell-states are *adjacent* when they differ in a single flow's contribution. The mean off-diagonal
//! correlation `r = (1/21) Σ_{i<j} γ_ij` averages over exactly those 21 pairs, so one flow moves it by at
//! most `Δr = 1/21` (its correlation `γ ∈ [0,1]` changes by ≤ 1, spread across 21 terms). We release
//!
//! ```text
//! r̃ = clamp_[−1/(N−1), 1]( r + Laplace(Δr / ε) ),   Δr = 1/21,
//! ```
//!
//! which is **ε-differentially private** — the textbook Laplace mechanism at global sensitivity `Δr`.
//! Every other exported scalar is a deterministic function of `r̃`: rebuilding the equicorrelated matrix
//! from `r̃` yields `Φ = (N−1)r̃²`, `P = 1/N + (N−1)r̃²/N`, `R = 1/(1 + (N−1)r̃²)`, and the
//! regime/alarm/integrated verdict — the same equicorrelated identity the mandatory liveness fold already
//! uses ([`observe_liveness`](crate::observer::SelfObserver::observe_liveness)). By the **post-processing
//! theorem** they inherit the same ε with no extra budget, so a single Laplace draw privatizes the whole
//! scalar block.
//!
//! The fields **not** captured by `r` are **withheld** on export (the cell-granular floor): the exact
//! fault `syndrome` (which node is down), the spectral `gap`, the `heal_seq` event counter, and the
//! cascade `forecast` are never shared. Fault *presence* survives only through the DP-derived alarm level,
//! so it too is ε-DP. Clamping `r̃` into the PSD range of a correlation matrix is post-processing and
//! preserves ε.
//!
//! The full-resolution frame stays **internal** — self-diagnosis and self-healing use the exact syndrome
//! and scalars within the cell. Only [`CoherenceFrame::privatize`] crosses the export boundary.
//!
//! # What ε-DP does and does not promise here
//!
//! ε-DP bounds how much *one flow's* presence can shift the exported distribution — it hides any single
//! flow, which is the deanonymization unit. It does **not** hide a cell that is genuinely, deeply faulted
//! (a large true signal is not one flow), and it should not: that is legitimate cell-granular health, the
//! floor the design targets.

use rand_core::Rng;

use fanos_diakrisis::coherence::CoherenceMatrix;

use crate::frame::CoherenceFrame;
use crate::snapshot::CELL_N;

/// The number of unordered node pairs (candidate flows) in a Fano cell: `C(7,2) = 21`.
const CELL_PAIRS: f64 = (CELL_N * (CELL_N - 1) / 2) as f64;

/// Global L1 sensitivity of the mean correlation `r` to one flow: `Δr = 1/C(N,2) = 1/21`
/// (`docs/design-telemetry.md` §5). `r` is a mean over the 21 pairs, so one flow's full-range change
/// (`γ ∈ [0,1]`) moves it by at most this — the "favorable sensitivity" that lets a small ε budget hide a
/// single flow while preserving the cell signal.
pub const R_SENSITIVITY: f64 = 1.0 / CELL_PAIRS;

/// The most-negative off-diagonal correlation an `N`-node equicorrelated matrix can carry and stay
/// positive semidefinite: `−1/(N−1)`. `r̃` is clamped to `[R_MIN, 1]` so the rebuilt matrix — and every
/// scalar derived from it — remains physical.
const R_MIN: f64 = -1.0 / (CELL_N as f64 - 1.0);

/// The ε budget for one exported frame. Smaller ε ⇒ stronger privacy (more noise). Anonymity floors
/// typically use `ε ≤ 1`; [`PrivacyBudget::default`] is `ε = 0.5`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PrivacyBudget {
    epsilon: f64,
}

impl PrivacyBudget {
    /// A budget with total privacy loss `epsilon`. Values `≤ 0` are meaningless (they would demand
    /// infinite noise) and are treated by [`CoherenceFrame::privatize`] as the strongest floor the
    /// representation allows.
    #[must_use]
    pub const fn new(epsilon: f64) -> Self {
        Self { epsilon }
    }

    /// The ε value of this budget.
    #[must_use]
    pub const fn epsilon(self) -> f64 {
        self.epsilon
    }
}

impl Default for PrivacyBudget {
    /// `ε = 0.5` — a conservative anonymity floor. At `Δr = 1/21` the Laplace scale is `≈ 0.095`, so any
    /// single flow (marginal effect `1/21 ≈ 0.048`) is buried in noise, while the cell's mean signal
    /// — averaged over windows — survives.
    fn default() -> Self {
        Self { epsilon: 0.5 }
    }
}

#[cfg(feature = "std")]
#[inline]
fn ln(x: f64) -> f64 {
    x.ln()
}

#[cfg(all(not(feature = "std"), feature = "libm"))]
#[inline]
fn ln(x: f64) -> f64 {
    libm::log(x)
}

/// A uniform `f64` in `[0, 1)` from 53 random bits (an exactly-representable dyadic).
#[inline]
fn uniform01(rng: &mut impl Rng) -> f64 {
    (rng.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
}

/// One standard exponential `Exp(1)` via inverse-CDF. `uniform01 ∈ [0,1)` ⇒ `1 − u ∈ (0,1]`, so the `ln`
/// is always finite (never `ln 0`).
#[inline]
fn exp1(rng: &mut impl Rng) -> f64 {
    -ln(1.0 - uniform01(rng))
}

/// A zero-mean Laplace sample with scale `b`, drawn as the difference of two standard exponentials
/// (`Laplace(b) = b·(E₁ − E₂)`, `Eᵢ ~ Exp(1)`) — numerically robust, with no sign/branch handling and no
/// `ln 0`.
#[inline]
fn laplace(scale_b: f64, rng: &mut impl Rng) -> f64 {
    scale_b * (exp1(rng) - exp1(rng))
}

impl CoherenceFrame {
    /// Produce an ε-differentially-private copy of this frame, safe to **export** beyond the cell
    /// (cross-cell roll-up, the monitor feed, any shareable telemetry). See the [module docs](self) for
    /// the mechanism and the ε-DP guarantee: the mean correlation is Laplace-noised at sensitivity
    /// `1/21`, the coherence scalars and verdict are re-derived from it by post-processing, and the exact
    /// syndrome, spectral gap, heal-event counter, and forecast are withheld (the cell-granular floor).
    ///
    /// `rng` is the caller's entropy source — a node's CSPRNG in production, a seeded RNG in tests. The
    /// noise MUST be fresh per release: never reuse a deterministic draw across exports, or the guarantee
    /// is void.
    #[must_use]
    pub fn privatize(&self, budget: PrivacyBudget, rng: &mut impl Rng) -> Self {
        // ε ≤ 0 is meaningless; fall back to the strongest representable floor rather than divide by ≤ 0.
        let epsilon = if budget.epsilon > 0.0 {
            budget.epsilon
        } else {
            f64::MIN_POSITIVE
        };
        let noised = f64::from(self.mean_r) + laplace(R_SENSITIVITY / epsilon, rng);
        // Clamp into the PSD range so the rebuilt correlation matrix — and every scalar read from it —
        // stays physical. Clamping is post-processing and preserves ε.
        let r = noised.clamp(R_MIN, 1.0);
        let matrix = CoherenceMatrix::equicorrelated(CELL_N, r);
        // Reuse `observe` for the canonical packing: `degraded = 0` withholds the exact syndrome point;
        // `gap = 0.0` / `forecast = -1` / `heal_seq = 0` withhold the non-`r` fields. Φ/P/R and the
        // regime/alarm/integrated verdict come from the DP-noised equicorrelated matrix — all
        // post-processing of the single Laplace release, so the whole frame is ε-DP.
        Self::observe(self.cell_id, self.epoch, &matrix, 0, 0.0, -1, 0)
    }
}
