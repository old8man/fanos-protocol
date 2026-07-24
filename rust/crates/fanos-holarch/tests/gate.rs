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

/// The Ω4 ablation calculus: each targeted perturbation breaks *exactly* the invariant it aims at — a
/// design that cannot be broken on demand was never really constrained by that invariant (T-124b).
#[test]
fn each_ablation_breaks_its_targeted_invariant() {
    let f = fanos_platform();
    for a in Ablation::ALL {
        let v = f.ablate(a).verdict();
        assert!(
            !a.target().holds(&v),
            "ablation {} must break {} but the verdict was {v}",
            a.name(),
            a.target().label(),
        );
    }
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
