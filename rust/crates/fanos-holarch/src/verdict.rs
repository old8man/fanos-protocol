//! The thresholded judgment: the four-invariant [`Verdict`] and the [`Sigma`] stress panel.

use core::fmt;

use fanos_diakrisis::coherence::{PHI_TH, R_TH, p_crit};

use crate::aspect::{Aspect, N};
use crate::gamma::Gamma;

/// The differentiation threshold `D_th = 2` (V4). Interiority must carry enough of the structure that
/// the holon has a genuine inside; below 2 it is a thin public surface. (Differentiation is a
/// HOLARCH-specific measure, so its threshold lives here rather than in the shared coherence family.)
pub const D_TH: f64 = 2.0;

/// One of the four release invariants — enough to name the binding constraint or the target of an
/// [`crate::Ablation`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Invariant {
    /// V1 — Distinctness (`P > 2/7`).
    V1Distinctness,
    /// V2 — Reflection (`R ≥ 1/3` ⇔ `P ≤ 3/7`).
    V2Reflection,
    /// V3 — Integration (`Φ ≥ 1`).
    V3Integration,
    /// V4 — Differentiation (`D ≥ 2`).
    V4Differentiation,
}

impl Invariant {
    /// A short label (`V1`…`V4`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Invariant::V1Distinctness => "V1",
            Invariant::V2Reflection => "V2",
            Invariant::V3Integration => "V3",
            Invariant::V4Differentiation => "V4",
        }
    }

    /// Whether this invariant holds in a verdict.
    #[must_use]
    pub fn holds(self, v: &Verdict) -> bool {
        match self {
            Invariant::V1Distinctness => v.v1_distinctness,
            Invariant::V2Reflection => v.v2_reflection,
            Invariant::V3Integration => v.v3_integration,
            Invariant::V4Differentiation => v.v4_differentiation,
        }
    }
}

/// The four release invariants read off one `Γ`, each with its pass/fail.
// The four invariants V1–V4 are, by definition, four independent booleans; collapsing them into an
// enum would erase the point (a design can fail any subset). This is the report, not a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Verdict {
    /// `P = Tr(Γ²)`.
    pub purity: f64,
    /// `R = 1/(7P)`.
    pub reflection: f64,
    /// `Φ`.
    pub phi: f64,
    /// `D`.
    pub differentiation: f64,
    /// **V1** — `P > 2/7`.
    pub v1_distinctness: bool,
    /// **V2** — `R ≥ 1/3`.
    pub v2_reflection: bool,
    /// **V3** — `Φ ≥ 1`.
    pub v3_integration: bool,
    /// **V4** — `D ≥ 2`.
    pub v4_differentiation: bool,
}

impl Verdict {
    /// Whether the design sits in the viable window (all four invariants hold).
    #[must_use]
    pub fn viable(&self) -> bool {
        self.v1_distinctness && self.v2_reflection && self.v3_integration && self.v4_differentiation
    }

    /// The [`Margins`] — how far inside each boundary the design sits, so a robust pass is
    /// distinguishable from a knife-edge one.
    #[must_use]
    pub fn margins(&self) -> Margins {
        Margins {
            distinctness: (self.purity - p_crit(N)) / p_crit(N),
            // V2's boundary is the dominance *ceiling* P ≤ 3/7 (⇔ R ≥ 1/3); measure headroom below it.
            reflection: (3.0 / N as f64 - self.purity) / (3.0 / N as f64),
            integration: (self.phi - PHI_TH) / PHI_TH,
            differentiation: (self.differentiation - D_TH) / D_TH,
        }
    }
}

/// The per-invariant robustness margins — each the signed distance inside that boundary, *relative* to
/// the boundary (so they are comparable across the four different scales). Positive ⇒ inside; the
/// minimum is the headroom to the nearest wall, and the invariant achieving it is the binding one.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Margins {
    /// V1 relative margin `(P − 2/7)/(2/7)` — headroom above the noise floor.
    pub distinctness: f64,
    /// V2 relative margin `(3/7 − P)/(3/7)` — headroom below the dominance ceiling.
    pub reflection: f64,
    /// V3 relative margin `(Φ − 1)/1` — headroom above the integration floor.
    pub integration: f64,
    /// V4 relative margin `(D − 2)/2` — headroom above the differentiation floor.
    pub differentiation: f64,
}

impl Margins {
    /// The four margins paired with their invariants, in canonical order.
    #[must_use]
    fn all(&self) -> [(Invariant, f64); 4] {
        [
            (Invariant::V1Distinctness, self.distinctness),
            (Invariant::V2Reflection, self.reflection),
            (Invariant::V3Integration, self.integration),
            (Invariant::V4Differentiation, self.differentiation),
        ]
    }

    /// The headroom to the nearest boundary (the minimum relative margin). Negative ⇒ that boundary is
    /// violated; a small positive value ⇒ a fragile, near-boundary pass.
    #[must_use]
    pub fn headroom(&self) -> f64 {
        self.all().into_iter().map(|(_, m)| m).fold(f64::INFINITY, f64::min)
    }

    /// The **binding** invariant — the one with the least headroom (closest to failing).
    #[must_use]
    pub fn binding(&self) -> Invariant {
        self.all()
            .into_iter()
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .map_or(Invariant::V1Distinctness, |(inv, _)| inv)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flag = |b: bool| if b { '✓' } else { '✗' };
        write!(
            f,
            "P={:.3} R≥{:.3} Φ={:.2} D={:.2} [{}{}{}{}] {}",
            self.purity,
            self.reflection,
            self.phi,
            self.differentiation,
            flag(self.v1_distinctness),
            flag(self.v2_reflection),
            flag(self.v3_integration),
            flag(self.v4_differentiation),
            if self.viable() { "VIABLE" } else { "NOT VIABLE" },
        )
    }
}

/// The T-92 stress panel: a per-aspect stress `σ ∈ [0,1]` (how loaded each organ is), with the v1
/// errata — `σ_E = (7−D)/5`, `σ_U = 2/(1+Φ)`, and the other five the diagonal stress `1 − 7γ_kk`.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Sigma {
    s: [f64; N],
}

impl Sigma {
    /// The stress of one aspect.
    #[must_use]
    pub fn get(&self, a: Aspect) -> f64 {
        self.s[a.index()]
    }
}

impl fmt::Display for Sigma {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (k, a) in Aspect::ALL.iter().enumerate() {
            if k > 0 {
                write!(f, " ")?;
            }
            write!(f, "{}:{:.2}", a.glyph(), self.s[a.index()])?;
        }
        Ok(())
    }
}

impl Gamma {
    /// The four-invariant [`Verdict`], thresholds taken from the shared DIAKRISIS coherence family so
    /// the gate and the runtime plane can never disagree on where the window is.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        let purity = self.purity();
        let reflection = self.reflection();
        let phi = self.phi();
        let differentiation = self.differentiation();
        Verdict {
            purity,
            reflection,
            phi,
            differentiation,
            v1_distinctness: purity > p_crit(N),
            v2_reflection: reflection >= R_TH,
            v3_integration: phi >= PHI_TH,
            v4_differentiation: differentiation >= D_TH,
        }
    }

    /// The T-92 [`Sigma`] stress panel for this `Γ`.
    #[must_use]
    pub fn sigma(&self) -> Sigma {
        let mut s = [0.0f64; N];
        let n = N as f64;
        for a in Aspect::ALL {
            let i = a.index();
            s[i] = match a {
                Aspect::E => ((n - self.differentiation()) / (n - 2.0)).clamp(0.0, 1.0),
                Aspect::U => 2.0 / (1.0 + self.phi()),
                _ => (1.0 - n * self.entry(i, i)).clamp(0.0, 1.0),
            };
        }
        Sigma { s }
    }
}
