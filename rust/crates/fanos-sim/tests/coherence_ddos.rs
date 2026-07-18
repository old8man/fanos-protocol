//! Coherence under a multi-target DDoS, on the real observatory — the #68 capstone validation.
//!
//! This connects the two homeostatic mechanisms to the simulator's coherence self-model. A *differential*
//! flood saturates a subset of nodes; a flooded node's behaviour diverges from the shared cell rhythm, so
//! its inter-node correlation drops — the cell slides toward a mere aggregate (`docs/ddos-homeostasis.md
//! §2`). The **projective load balancer** (`fanos_diakrisis::loadbalance`) spreads the excess toward the
//! global mean. Because, for a *fixed total load*, uniform coupling maximizes the pairwise-coherence sum
//! `Σ cᵢcⱼ = ((Σcᵢ)² − Σcᵢ²)/2` (minimizing `Σcᵢ²` — convexity), load balancing is *guaranteed* to raise
//! the cell's mean correlation, and here it restores it from Aggregate back into the collective-subject
//! band — as measured by the real `observatory::read`.
//!
//! The experiment is *controlled*: both the concentrated and the balanced case are generated from the
//! **same** shared/idiosyncratic noise realization, so the only difference is the load distribution.

use fanos_diakrisis::loadbalance::{self, N};
use fanos_diakrisis::window::CollectiveState;
use fanos_sim::read;

/// A deterministic centred noise source in `[-0.5, 0.5]` (a fixed LCG, so the test is reproducible without
/// touching the sim's RNG visibility).
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 11) as f64) / ((1u64 << 53) as f64) - 0.5
    }
}

const WINDOW: usize = 4000;
const CAP: f64 = 10.0;
const BASE_COUPLING: f64 = 0.6;
const DIVERGENCE_GAIN: f64 = 0.3;

/// Map an excess-load vector to per-node coupling to the shared cell rhythm: more excess ⇒ the node
/// diverges (lower coupling). Kept in the linear regime (no clamping) so that load balancing — which
/// conserves total load — conserves the total coupling `Σcᵢ`, isolating the *distribution* effect.
fn couplings(excess: &[f64; N]) -> [f64; N] {
    core::array::from_fn(|i| BASE_COUPLING - DIVERGENCE_GAIN * excess[i] / CAP)
}

/// Build per-node behavioural signals `sᵢ(t) = cᵢ·shared(t) + (1−cᵢ)·idioᵢ(t)` from a fixed noise
/// realization, so two coupling vectors can be compared under identical randomness.
fn signals(c: &[f64; N], shared: &[f64], idio: &[Vec<f64>]) -> Vec<Vec<f64>> {
    (0..N)
        .map(|i| {
            (0..WINDOW)
                .map(|t| c[i] * shared[t] + (1.0 - c[i]) * idio[i][t])
                .collect()
        })
        .collect()
}

#[test]
fn load_balancing_restores_coherence_under_a_differential_flood() {
    // One fixed noise realization shared by both scenarios (the controlled part of the experiment).
    let mut lcg = Lcg(0x00C0_FFEE_D15E_A5ED);
    let shared: Vec<f64> = (0..WINDOW).map(|_| lcg.next()).collect();
    let idio: Vec<Vec<f64>> = (0..N)
        .map(|_| (0..WINDOW).map(|_| lcg.next()).collect())
        .collect();

    // A differential flood: nodes 5 and 6 are saturated (excess 16 each); the rest idle.
    let excess_concentrated = [0.0, 0.0, 0.0, 0.0, 0.0, 16.0, 16.0];
    // The projective load balancer spreads the excess to the global mean (conserving the total).
    let (excess_balanced, rounds) = loadbalance::balance_to_uniform(&excess_concentrated, 1e-9, 100);
    assert!(rounds > 0 && rounds <= 20, "balancing converges in a few rounds, took {rounds}");

    let concentrated = read(&signals(&couplings(&excess_concentrated), &shared, &idio))
        .expect("well-formed signals");
    let balanced =
        read(&signals(&couplings(&excess_balanced), &shared, &idio)).expect("well-formed signals");

    // 1. Guaranteed by convexity: spreading the same total load raises the cell's mean coherence.
    assert!(
        balanced.mean_correlation > concentrated.mean_correlation + 0.02,
        "load balancing raises mean coherence: concentrated r={:.3} → balanced r={:.3}",
        concentrated.mean_correlation,
        balanced.mean_correlation
    );

    // 2. The qualitative jump: the concentrated flood leaves the cell a mere Aggregate (below r*), while
    //    balancing restores it into the collective-subject band — a healthy, self-modelling subject.
    assert_eq!(
        concentrated.collective,
        CollectiveState::Aggregate,
        "the concentrated flood disintegrates the cell (r={:.3})",
        concentrated.mean_correlation
    );
    assert_eq!(
        balanced.collective,
        CollectiveState::CollectiveSubject,
        "load balancing restores the collective subject (r={:.3})",
        balanced.mean_correlation
    );

    // 3. Total load is conserved by balancing (no work created or destroyed — pure redistribution).
    let total_before: f64 = excess_concentrated.iter().sum();
    let total_after: f64 = excess_balanced.iter().sum();
    assert!((total_before - total_after).abs() < 1e-6, "redistribution conserves total load");
}

#[test]
fn balancing_monotonically_improves_coherence_round_by_round() {
    // Each balancing round contracts the load deviation (λ₂ = 2/9), reducing Σcᵢ² and so raising the
    // pairwise-coherence sum — the mean correlation climbs monotonically toward the uniform maximum.
    let mut lcg = Lcg(0x5EED_1234_ABCD_0001);
    let shared: Vec<f64> = (0..WINDOW).map(|_| lcg.next()).collect();
    let idio: Vec<Vec<f64>> = (0..N)
        .map(|_| (0..WINDOW).map(|_| lcg.next()).collect())
        .collect();

    let mut excess = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 14.0];
    let mut prev_r = read(&signals(&couplings(&excess), &shared, &idio))
        .unwrap()
        .mean_correlation;
    let start_r = prev_r;
    for _ in 0..8 {
        excess = loadbalance::balance_step(&excess);
        let r = read(&signals(&couplings(&excess), &shared, &idio))
            .unwrap()
            .mean_correlation;
        // Monotone non-decreasing (small tolerance for finite-window sampling noise).
        assert!(r >= prev_r - 2e-3, "coherence does not regress while balancing: {prev_r:.4} → {r:.4}");
        prev_r = r;
    }
    assert!(prev_r > start_r + 0.02, "balancing raised coherence overall: {start_r:.3} → {prev_r:.3}");
}
