//! The HOLARCH release gate as a CI-checkable test: the FANOS platform must sit in the viable window,
//! the reference corners must hold, and every Ω4 ablation must break exactly the invariant it targets.
//! `cargo test -p fanos-holarch` failing == the platform failing its own definition of done.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use fanos_holarch::{
    Ablation, Aspect, Gamma, Invariant, N, Panel, agent_platform, blockchain, fanos_platform, mixnet,
};

/// The gate itself: the FANOS E∧L platform is viable, with margin on every invariant, and its numbers
/// match the locked construction (a regression guard on the declared budget vectors).
#[test]
fn fanos_platform_is_in_the_viable_window() {
    let v = fanos_platform().gamma().verdict();
    assert!(v.viable(), "FANOS platform must pass the HOLARCH gate: {v}");

    // In-window with genuine margin, not on a knife-edge (P strictly inside (2/7, 3/7]).
    assert!(v.purity > 2.0 / 7.0, "V1: P={} must exceed the 2/7 noise floor", v.purity);
    assert!(v.purity <= 3.0 / 7.0, "V2: P={} must not exceed the 3/7 dominance ceiling", v.purity);
    assert!(v.phi >= 1.0, "V3: Φ={} must reach the integration floor", v.phi);
    assert!(v.differentiation >= 2.0, "V4: D={} must reach the differentiation floor", v.differentiation);

    // Regression guard: the locked numbers (λ=(0.36,0.36,0.28), ε=0.40).
    assert!((v.purity - 0.3704).abs() < 5e-3, "P drifted: {}", v.purity);
    assert!((v.phi - 1.563).abs() < 5e-3, "Φ drifted: {}", v.phi);
    assert!((v.differentiation - 2.615).abs() < 5e-3, "D drifted: {}", v.differentiation);
}

/// The corpus reference corners (`holarch_lab.hl03`): the grey mesh is non-viable with `P=1/7, Φ=0`,
/// and a single pure aspect gives `Coh=1, D=7`.
#[test]
fn reference_corners_match_the_corpus() {
    let grey = Gamma::grey();
    assert!((grey.purity() - 1.0 / 7.0).abs() < 1e-12, "grey P must be 1/7");
    assert!(grey.phi() < 1e-12, "grey Φ must be 0 (no coupling)");
    assert!((grey.differentiation() - (1.0 + 6.0 / 7.0)).abs() < 1e-12, "grey D must be 1+6/7");
    assert!(!grey.verdict().viable(), "the formless mesh must be non-viable");

    let pure_e = Gamma::pure_aspect(Aspect::E);
    assert!((pure_e.coh_e() - 1.0).abs() < 1e-12, "pure-E Coh_E must be 1");
    assert!((pure_e.differentiation() - 7.0).abs() < 1e-12, "pure-E D must be 7");
}

/// The Ω4 ablation calculus: a design that cannot be broken on demand was never really constrained by
/// that invariant (T-124b). Every ablation must break its target — and, for the three that *can* be
/// selective, must leave the other three invariants standing.
///
/// The earlier form of this test asserted only that the target broke, while the doc beside it claimed
/// each broke "exactly" one. It did not: `monolith` also broke V4 and `fragmentation` also broke V4, so
/// neither showed its own invariant to be independently binding. Asserting the full break-set is what
/// caught that, and it is the whole point of the calculus — an ablation that breaks three invariants
/// demonstrates nothing about any of them.
#[test]
fn each_ablation_breaks_exactly_the_invariant_it_targets() {
    let f = fanos_platform();
    for a in Ablation::ALL {
        let v = f.ablate(a).verdict();
        let broken: Vec<Invariant> = ALL_INVARIANTS.into_iter().filter(|i| !i.holds(&v)).collect();
        assert!(
            broken.contains(&a.target()),
            "ablation {} must break {} but the verdict was {v}",
            a.name(),
            a.target().label(),
        );
        // `Mud` is the one exception, and it is forced by the model rather than by this design:
        // `P = (Σγ_ii²)(1 + Φ)` with `Σγ_ii² ≥ 1/7`, so V1 cannot fail unless V3 already has.
        let expected: &[Invariant] = if a == Ablation::Mud {
            &[Invariant::V1Distinctness, Invariant::V3Integration]
        } else {
            &[a.target()]
        };
        assert_eq!(
            broken.len(),
            expected.len(),
            "ablation {} broke {:?}, expected exactly {:?} — a perturbation that breaks extra invariants \
             shows none of them to be independently binding. Verdict: {v}",
            a.name(),
            broken.iter().map(|i| i.label()).collect::<Vec<_>>(),
            expected.iter().map(|i| i.label()).collect::<Vec<_>>(),
        );
        for want in expected {
            assert!(broken.contains(want), "ablation {} should have broken {}", a.name(), want.label());
        }
    }
}

/// The four invariants in canonical order, for tests that need the full break-set.
const ALL_INVARIANTS: [Invariant; 4] = [
    Invariant::V1Distinctness,
    Invariant::V2Reflection,
    Invariant::V3Integration,
    Invariant::V4Differentiation,
];

/// **V1 is implied by V3** — so the viable window has three independent walls, not four.
///
/// Purity decomposes exactly: `P = Σ_ij γ_ij² = Σ_i γ_ii² + Σ_{i≠j} γ_ij² = S(1 + Φ)` with `S = Σ_i γ_ii²`,
/// because `Φ` is *defined* as the ratio of those two sums. At trace 1, Cauchy–Schwarz gives
/// `S = Σ γ_ii² ≥ (Σ γ_ii)²/7 = 1/7`. Hence `Φ ≥ 1 ⇒ P ≥ 2S ≥ 2/7`, with equality only where `Φ = 1`
/// *and* the diagonal is exactly uniform — a single degenerate point.
///
/// This is why no ablation can exhibit V1 alone, and it is checked rather than argued: the identity holds
/// to floating-point on every declared instance and ablation, and a sweep over the model's own parameter
/// family finds no `Γ` that satisfies V3 and fails V1.
#[test]
fn v1_distinctness_is_implied_by_v3_integration() {
    let (mut checked, mut implied) = (0usize, 0usize);
    let mut check = |g: Gamma, what: &str| {
        let (p, phi) = (g.purity(), g.phi());
        let s = p - g.off_diagonal_sq(); // Σ_i γ_ii², by the definition of the off-diagonal power
        assert!((p - s * (1.0 + phi)).abs() < 1e-12, "{what}: P={p} ≠ S(1+Φ)={}", s * (1.0 + phi));
        assert!(s >= 1.0 / 7.0 - 1e-12, "{what}: Σγ_ii²={s} must be ≥ 1/7 at trace 1");
        if phi >= 1.0 {
            assert!(p > 2.0 / 7.0 - 1e-12, "{what}: Φ={phi} ≥ 1 must force P={p} ≥ 2/7");
            implied += 1;
        }
        checked += 1;
    };

    for inst in [fanos_platform(), mixnet(), blockchain(), agent_platform()] {
        check(inst.gamma(), inst.name);
        for a in Ablation::ALL {
            check(inst.ablate(a), a.name());
        }
    }
    check(Gamma::grey(), "grey");
    check(Gamma::pure_aspect(Aspect::E), "pure-E");

    // A sweep of the model's own family: the gate never sees a `Γ` built any other way.
    let mut lcg = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        lcg ^= lcg << 13;
        lcg ^= lcg >> 7;
        lcg ^= lcg << 17;
        (lcg >> 11) as f64 / (1u64 << 53) as f64
    };
    for k in 0..2000 {
        let mut budgets = [fanos_holarch::Budget::new(0.0, 0.0, 0.0); N];
        for b in &mut budgets {
            *b = fanos_holarch::Budget::new(2.0 * next(), 2.0 * next(), 2.0 * next());
        }
        let lambdas = [next() + 1e-6, next() + 1e-6, next() + 1e-6];
        let eps = 0.01 + 0.97 * next();
        check(Gamma::from_modes(&budgets, lambdas, eps), &format!("sweep #{k}"));
    }
    assert!(checked > 2000, "the sweep must actually have run: {checked} matrices");
    // Without this the test could pass while proving nothing: the implication is only exercised where the
    // antecedent holds, and a sweep that drifted to all-Φ<1 would assert nothing at all. Measured: 961.
    assert!(
        implied > checked / 4,
        "only {implied} of {checked} matrices satisfied Φ ≥ 1 — the implication under test was barely exercised"
    );
}

/// The sibling reference instances (W1 mixnet / W2 blockchain / W3 agent-platform) are also viable —
/// the Rust flow-constructor reproduces `holarch_lab.py`'s verdicts, not just the FANOS instance.
#[test]
fn sibling_instances_are_viable() {
    for inst in [mixnet(), blockchain(), agent_platform()] {
        assert!(inst.gamma().verdict().viable(), "{} must be viable: {}", inst.name, inst.gamma().verdict());
    }
}

/// The full panel — every check green — is what a CI step asserts.
#[test]
fn the_release_panel_passes() {
    let p = Panel::run();
    assert!(p.all_pass(), "release panel had failures:\n{p}");
    assert_eq!(p.checks.len(), 7, "H1, H1b, H2, H3, H4a-c");
}

/// Every declared instance (and every ablation) must be a *valid coherence operator* — trace-1,
/// symmetric, PSD — since the P/Φ/D reading is only meaningful on such a matrix. Also pins the checker
/// itself: the grey matrix is strictly PD, a pure aspect is PSD-but-singular, an indefinite matrix is
/// rejected.
#[test]
fn every_gamma_is_a_valid_coherence_operator() {
    for inst in [fanos_platform(), mixnet(), blockchain(), agent_platform()] {
        let g = inst.gamma();
        assert!((g.trace() - 1.0).abs() < 1e-12, "{}: Tr={} must be 1", inst.name, g.trace());
        assert!(g.is_symmetric(1e-12), "{}: Γ must be symmetric", inst.name);
        assert!(g.is_psd(1e-12), "{}: Γ must be PSD", inst.name);
        for a in Ablation::ALL {
            let ga = inst.ablate(a);
            assert!(ga.is_symmetric(1e-12) && ga.is_psd(1e-12), "{} under {} must stay PSD", inst.name, a.name());
        }
    }
    // The reference corners exercise both PSD branches.
    assert!(Gamma::grey().is_psd(1e-12), "grey I/7 is strictly PD");
    assert!(Gamma::pure_aspect(Aspect::E).is_psd(1e-12), "a rank-1 projector is PSD (singular)");
    // A genuinely indefinite symmetric matrix (eigenvalues ±1) must be rejected.
    let mut m = [[0.0f64; N]; N];
    m[0][1] = 1.0;
    m[1][0] = 1.0;
    assert!(!Gamma::from_matrix(m).is_psd(1e-9), "an indefinite matrix must fail the PSD check");
}

/// The gate is not a knife-edge: the FANOS platform clears its *tightest* release boundary with real
/// headroom, and that binding boundary is the anti-dominance ceiling V2 (as designed — an E∧L platform
/// pushes purity up toward, but safely under, 3/7).
#[test]
fn fanos_platform_clears_its_binding_boundary_with_margin() {
    let m = fanos_platform().gamma().verdict().margins();
    assert!(m.headroom() > 0.10, "headroom {:.3} must exceed 10% (robust, not knife-edge)", m.headroom());
    assert_eq!(m.binding(), Invariant::V2Reflection, "V2 (dominance ceiling) should bind for E∧L");
    // Every individual margin is positive (inside all four walls).
    assert!(m.distinctness > 0.0 && m.reflection > 0.0 && m.integration > 0.0 && m.differentiation > 0.0);
}

/// T-77 contract composition: coupling two holons (org ⊗ system, the Conway mirror) adds exactly
/// `2‖γ_cross‖²_F` of purity — the integration gain lives entirely in the cross-block, the identity
/// `spec/platform.md` §1.2 cites. Checked here on a concrete `2N×2N` block matrix.
#[test]
fn t77_composition_gain_is_twice_the_cross_block_energy() {
    const D: usize = 2 * N;
    // Two block-diagonal holons, each a probability diagonal scaled by 1/2 (joint trace 1).
    let mut diag = [[0.0f64; D]; D];
    for (k, w) in [0.30, 0.10, 0.05, 0.20, 0.15, 0.12, 0.08].iter().enumerate() {
        diag[k][k] = w / 2.0; // holon A
        diag[N + k][N + k] = w / 2.0; // holon B
    }
    let trace_sq = |m: &[[f64; D]; D]| -> f64 { m.iter().flatten().map(|&x| x * x).sum() };
    // Add a cross block γ_cross (top-right) and its transpose (bottom-left) — a few typed contracts.
    let mut paired = diag;
    let cross = [(0usize, 1usize, 0.04), (3, 4, 0.03), (2, 6, 0.02)];
    let mut cross_energy = 0.0;
    for &(i, j, c) in &cross {
        let half = c / 2.0;
        paired[i][N + j] = half;
        paired[N + j][i] = half;
        cross_energy += half * half; // ‖γ_cross‖²_F over the top-right block
    }
    let gain = trace_sq(&paired) - trace_sq(&diag);
    assert!((gain - 2.0 * cross_energy).abs() < 1e-15, "T-77: gain {gain} ≠ 2‖γ_cross‖² {}", 2.0 * cross_energy);
}

