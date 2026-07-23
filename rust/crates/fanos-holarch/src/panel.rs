//! The release panel: run every gate check and render a PASS/FAIL report (the CI-checkable gate).

use core::fmt;

use crate::aspect::Aspect;
use crate::gamma::Gamma;
use crate::instance::{Ablation, agent_platform, blockchain, fanos_platform, mixnet};

/// The honesty class of a check (mirrors the ХОЛАРХ lab): a computed fact about the machinery, or the
/// self-consistency of an engineering instance (true by construction, demonstrated).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// A computed fact about the machinery (an arithmetic identity, a reference point).
    Verified,
    /// Self-consistency of an engineering instance (true by construction, demonstrated).
    Design,
}

impl Class {
    const fn label(self) -> &'static str {
        match self {
            Class::Verified => "VERIFIED",
            Class::Design => "DESIGN  ",
        }
    }
}

/// One line of the panel.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Check {
    /// The check id (`H1`…).
    pub id: &'static str,
    /// Its honesty class.
    pub class: Class,
    /// Whether it passed.
    pub pass: bool,
    /// A one-line detail.
    pub detail: String,
}

/// The full gate panel — every check, in order.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Panel {
    /// Every check, in order.
    pub checks: Vec<Check>,
}

impl Panel {
    fn push(&mut self, id: &'static str, class: Class, pass: bool, detail: String) {
        self.checks.push(Check { id, class, pass, detail });
    }

    /// Whether every check passed — the release gate's boolean (CI exit `0` iff `true`).
    #[must_use]
    pub fn all_pass(&self) -> bool {
        self.checks.iter().all(|c| c.pass)
    }

    /// Run the whole gate: reference points, the FANOS platform verdict, the Ω4 ablation calculus, and
    /// the sibling W1/W2/W3 instances (a cross-check that the constructor reproduces the reference lab).
    #[must_use]
    pub fn run() -> Self {
        let mut p = Panel::default();

        // H1 — reference points (VERIFIED arithmetic against the corpus).
        let grey = Gamma::grey();
        let grey_v = grey.verdict();
        let pure_e = Gamma::pure_aspect(Aspect::E);
        let h1 = (grey_v.purity - 1.0 / 7.0).abs() < 1e-12
            && grey_v.phi < 1e-12
            && !grey_v.viable()
            && (pure_e.coh_e() - 1.0).abs() < 1e-12
            && (pure_e.differentiation() - 7.0).abs() < 1e-12;
        p.push(
            "H1",
            Class::Verified,
            h1,
            format!(
                "grey I/7: P=1/7, Φ=0, D={:.3}, non-viable; pure-E: Coh_E=1, D=7 (T-124 corners)",
                grey.differentiation()
            ),
        );

        // H1b — the FANOS Γ is a *valid coherence operator* (trace-1, symmetric, PSD): the P/Φ/D
        // reading is only meaningful on such a matrix, so the gate verifies the object before judging it.
        let fanos = fanos_platform();
        let g = fanos.gamma();
        let structural = (g.trace() - 1.0).abs() < 1e-12 && g.is_symmetric(1e-12) && g.is_psd(1e-12);
        p.push(
            "H1b",
            Class::Verified,
            structural,
            format!("FANOS Γ: Tr={:.6}, symmetric, PSD (a valid density/coherence operator)", g.trace()),
        );

        // H2 — the FANOS platform sits in the viable window (THE GATE), reported with its robustness
        // margin: the headroom to the nearest release boundary and the invariant that binds.
        let v = g.verdict();
        let margins = v.margins();
        p.push(
            "H2",
            Class::Design,
            v.viable(),
            format!(
                "{}: {v}; headroom {:.1}% at {} (nearest boundary)",
                fanos.name,
                margins.headroom() * 100.0,
                margins.binding().label(),
            ),
        );

        // H3 — the Ω4 ablation calculus: each ablation breaks exactly the invariant it targets.
        let mut broke = Vec::new();
        let mut all_break = true;
        for a in Ablation::ALL {
            let target = a.target();
            let broken = !target.holds(&fanos.ablate(a).verdict());
            all_break &= broken;
            if broken {
                broke.push(format!("{}→{}", a.name(), target.label()));
            }
        }
        p.push(
            "H3",
            Class::Design,
            all_break,
            format!("FANOS ablations each break their own invariant: {}", broke.join(", ")),
        );

        // H4 — the sibling instances are viable too (constructor cross-check vs the reference lab).
        for (id, inst) in [("H4a", mixnet()), ("H4b", blockchain()), ("H4c", agent_platform())] {
            let vv = inst.gamma().verdict();
            p.push(id, Class::Design, vv.viable(), format!("{}: {vv}", inst.name));
        }

        p
    }
}

impl fmt::Display for Panel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ХОЛАРХ viability gate — FANOS platform (spec/platform.md §1)")?;
        for c in &self.checks {
            let mark = if c.pass { "PASS" } else { "FAIL" };
            writeln!(f, "  [{:<3}] {} {mark} — {}", c.id, c.class.label(), c.detail)?;
        }
        let total = self.checks.len();
        let passed = self.checks.iter().filter(|c| c.pass).count();
        writeln!(f, "  σ-stress (FANOS): {}", fanos_platform().gamma().sigma())?;
        write!(
            f,
            "  TOTAL: {passed}/{total} {}",
            if self.all_pass() { "PASS — PLATFORM VIABLE" } else { "FAIL" }
        )
    }
}
