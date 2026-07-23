//! Declared architecture instances (the `holarch.v1` budget vectors) and the Ω4 ablation calculus.

use crate::aspect::{Aspect, N};
use crate::gamma::{Budget, Gamma};
use crate::verdict::Invariant;

/// A targeted perturbation of an [`Instance`] — each must break *exactly* the one invariant it aims at
/// (T-124b): a design you cannot break on demand was never really constrained by that invariant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ablation {
    /// **Mud** — 80% of activity outside any flow: the unstructured background swamps the signal, so
    /// purity falls through the noise floor (breaks **V1**).
    Mud,
    /// **Monolith** — one global mode eats the system with no background to reflect in: purity spikes
    /// past the dominance ceiling (breaks **V2**).
    Monolith,
    /// **Fragmentation** — the flows lose their shared carriers and retreat to disjoint islands, so the
    /// parts stop cohering (breaks **V3**).
    Fragmentation,
    /// **Blind** — interiority is unplugged from every flow, so nothing differentiates inside (breaks
    /// **V4**).
    Blind,
}

impl Ablation {
    /// All four ablations.
    pub const ALL: [Ablation; 4] =
        [Ablation::Mud, Ablation::Monolith, Ablation::Fragmentation, Ablation::Blind];

    /// The invariant this ablation is designed to break.
    #[must_use]
    pub const fn target(self) -> Invariant {
        match self {
            Ablation::Mud => Invariant::V1Distinctness,
            Ablation::Monolith => Invariant::V2Reflection,
            Ablation::Fragmentation => Invariant::V3Integration,
            Ablation::Blind => Invariant::V4Differentiation,
        }
    }

    /// A short name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Ablation::Mud => "mud",
            Ablation::Monolith => "monolith",
            Ablation::Fragmentation => "fragmentation",
            Ablation::Blind => "blind",
        }
    }
}

/// A named architecture instance: a participation table (one [`Budget`] per aspect), the flow weights
/// `λ`, and the background `ε` — everything [`Gamma::from_modes`] needs.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Instance {
    /// A human name.
    pub name: &'static str,
    /// A one-line note on the design.
    pub note: &'static str,
    /// One participation budget per aspect (indexed by [`Aspect::index`]).
    pub budgets: [Budget; N],
    /// The flow weights `(control, data, supply)` (renormalised to sum 1).
    pub lambdas: [f64; 3],
    /// The unstructured background fraction `ε ∈ (0,1)`.
    pub eps: f64,
}

impl Instance {
    /// This instance's coherence matrix.
    #[must_use]
    pub fn gamma(&self) -> Gamma {
        Gamma::from_modes(&self.budgets, self.lambdas, self.eps)
    }

    /// The instance under one [`Ablation`] — the perturbed `Γ`.
    #[must_use]
    pub fn ablate(&self, a: Ablation) -> Gamma {
        match a {
            Ablation::Mud => Gamma::from_modes(&self.budgets, self.lambdas, 0.80),
            Ablation::Monolith => Gamma::from_modes(&self.budgets, [0.96, 0.02, 0.02], 0.04),
            Ablation::Fragmentation => {
                // control={L,U}, data={A,D}, supply={O,S}; E barely attached to the data island.
                let mut b = [Budget::new(0.0, 0.0, 0.0); N];
                b[Aspect::L.index()] = Budget::new(1.0, 0.0, 0.0);
                b[Aspect::U.index()] = Budget::new(1.0, 0.0, 0.0);
                b[Aspect::A.index()] = Budget::new(0.0, 1.0, 0.0);
                b[Aspect::D.index()] = Budget::new(0.0, 1.0, 0.0);
                b[Aspect::O.index()] = Budget::new(0.0, 0.0, 1.0);
                b[Aspect::S.index()] = Budget::new(0.0, 0.0, 1.0);
                b[Aspect::E.index()] = Budget::new(0.0, 0.35, 0.0);
                Gamma::from_modes(&b, self.lambdas, 0.10)
            }
            Ablation::Blind => {
                let mut b = self.budgets;
                b[Aspect::E.index()] = Budget::new(0.02, 0.02, 0.02);
                Gamma::from_modes(&b, self.lambdas, self.eps)
            }
        }
    }
}

/// **The FANOS platform** — the E∧L holonic synthesis (`spec/platform.md` §1.2).
///
/// Thick on both intEriority (the anonymity pool ∧ shielded-currency state, from the mixnet holon) and
/// Logic (mixnet routing / crypto law ∧ blockchain consensus, from the chain holon); the join lands
/// inside the viable window with margin on every invariant.
#[must_use]
pub fn fanos_platform() -> Instance {
    Instance {
        name: "FANOS platform (E∧L synthesis)",
        note: "E = anonymity + shielded interiority; L = routing-law ∧ consensus; the join of W1∧W2",
        budgets: [
            //                control  data  supply
            Budget::new(0.6, 1.5, 0.4), // A — ingress articulation on the data flow
            Budget::new(1.0, 1.2, 0.5), // S — uniform packet format ∧ ledger schema (law + data)
            Budget::new(1.0, 1.5, 0.8), // D — packet forwarding ∧ tx execution: data-heavy, metered
            Budget::new(1.7, 0.9, 0.7), // L — routing / crypto law ∧ consensus: L-dominant
            Budget::new(0.7, 1.5, 1.2), // E — anonymity pool ∧ shielded state: E-rich
            Budget::new(0.6, 0.8, 1.7), // O — transport, stake, cover budget, data availability
            Budget::new(1.6, 0.6, 0.9), // U — epoch topology ∧ canonical head: the control organ
        ],
        lambdas: [0.36, 0.36, 0.28],
        eps: 0.40,
    }
}

/// **W1 — mixnet node-holon** (FANOS / Nym class). Interiority is the anonymity resource; the data flow
/// runs ingress into the hidden pool, and supply carries stake, transport, and the cover budget. A
/// sibling reference instance that cross-checks the constructor against `holarch_lab.py`.
#[must_use]
pub fn mixnet() -> Instance {
    Instance {
        name: "W1 mixnet (FANOS/Nym class)",
        note: "E = anonymity as interiority; cover traffic = E–O immanence cost",
        budgets: [
            Budget::new(0.6, 1.5, 0.4), // A
            Budget::new(0.9, 1.1, 0.5), // S
            Budget::new(1.0, 1.5, 0.8), // D
            Budget::new(1.5, 0.9, 0.7), // L
            Budget::new(0.6, 1.5, 1.2), // E
            Budget::new(0.6, 0.7, 1.7), // O
            Budget::new(1.6, 0.5, 0.8), // U
        ],
        lambdas: [0.34, 0.38, 0.28],
        eps: 0.40,
    }
}

/// **W2 — public blockchain holon** (a modular stack as one organism). Law-machine: the control flow is
/// dominant (consensus), supply carries stake + DA, data carries transactions; E is deliberately lean
/// (public ledger) but non-empty (node-local state keeps `D ≥ 2`).
#[must_use]
pub fn blockchain() -> Instance {
    Instance {
        name: "W2 blockchain (modular L1)",
        note: "L-dominant by design: law-machine; U = one canonical head",
        budgets: [
            Budget::new(0.6, 1.5, 0.4), // A
            Budget::new(1.2, 1.2, 0.6), // S
            Budget::new(1.0, 1.4, 0.7), // D
            Budget::new(1.7, 0.8, 0.8), // L
            Budget::new(0.5, 1.2, 1.0), // E
            Budget::new(0.7, 0.8, 1.7), // O
            Budget::new(1.5, 0.7, 0.9), // U
        ],
        lambdas: [0.40, 0.33, 0.27],
        eps: 0.42,
    }
}

/// **W3 — LLM-agent platform holon** (orchestrator + workers, memory tiers, evals). E-rich: memory /
/// context is load-bearing; the data flow feeds apperception, control carries the planner, supply
/// carries compute / quota.
#[must_use]
pub fn agent_platform() -> Instance {
    Instance {
        name: "W3 LLM-agent platform",
        note: "E-rich: memory tiers are load-bearing; SYNARC = full realization",
        budgets: [
            Budget::new(0.7, 1.6, 0.4), // A
            Budget::new(1.0, 1.1, 0.5), // S
            Budget::new(1.1, 1.4, 0.8), // D
            Budget::new(1.5, 0.9, 0.6), // L
            Budget::new(0.7, 1.5, 1.1), // E
            Budget::new(0.6, 0.7, 1.7), // O
            Budget::new(1.6, 0.7, 0.8), // U
        ],
        lambdas: [0.36, 0.37, 0.27],
        eps: 0.40,
    }
}
