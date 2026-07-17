//! Property tests: coherence-measure identities and the diagnostic theorems over random data.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::float_cmp
)]

use fanos_diakrisis::coherence::{CoherenceMatrix, phi_equicorrelated, purity_equicorrelated};
use fanos_diakrisis::{healing, polar, window};
use proptest::prelude::*;

fn arr7() -> impl Strategy<Value = [f64; 7]> {
    proptest::array::uniform7(-2.0f64..2.0)
}

/// A random PSD `Γ` with `Tr = 1` from a few random rank-1 terms.
fn random_psd(vectors: &[[f64; 7]]) -> Vec<f64> {
    let mut g = vec![0.0f64; 49];
    for v in vectors {
        for i in 0..7 {
            for j in 0..7 {
                g[i * 7 + j] += v[i] * v[j];
            }
        }
    }
    let trace: f64 = (0..7).map(|i| g[i * 7 + i]).sum();
    if trace > 1e-12 {
        for x in &mut g {
            *x /= trace;
        }
    }
    g
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// The equicorrelated closed forms match the matrix measures, and `Φ = N·P − 1` (V15).
    #[test]
    fn equicorrelated_identities(r in -0.16f64..1.0) {
        let g = CoherenceMatrix::equicorrelated(7, r);
        prop_assert!((g.phi() - phi_equicorrelated(7, r)).abs() < 1e-9);
        prop_assert!((g.purity() - purity_equicorrelated(7, r)).abs() < 1e-9);
        prop_assert!((g.phi() - (7.0 * g.purity() - 1.0)).abs() < 1e-9);
    }

    /// Leading indicator (V17): on any PSD Γ with Tr=1, `P < 2/N ⇒ Φ < 1`.
    #[test]
    fn leading_indicator_containment(a in arr7(), b in arr7(), c in arr7()) {
        let g = random_psd(&[a, b, c]);
        let phi = window::phi_of_gamma(&g, 7);
        let p = window::purity_of_gamma(&g, 7);
        if p < 2.0 / 7.0 - 1e-9 {
            prop_assert!(phi < 1.0 + 1e-9, "P<2/7 but Φ={phi}");
        }
    }

    /// The 14 polar sum-rules hold for the rates produced by *any* line-rate vector (T-226).
    #[test]
    fn polar_sum_rules_hold_for_any_line_rates(gamma in proptest::array::uniform7(0.1f64..20.0)) {
        let rates = polar::line_rates_to_pair_rates(gamma);
        prop_assert!(polar::sum_rules_hold(&rates, 1e-9));
        // Tomography round-trips.
        let rho = polar::polar_values(&rates);
        let back = polar::polar_values_to_line_rates(rho);
        for i in 0..7 {
            prop_assert!((gamma[i] - back[i]).abs() < 1e-6);
        }
    }

    /// Forging one rate violates exactly the polar class of that pair's mediator.
    #[test]
    fn forging_a_rate_flags_one_class(gamma in proptest::array::uniform7(1.0f64..10.0), i in 0..7usize, j in 0..7usize) {
        prop_assume!(i != j);
        let mut rates = polar::line_rates_to_pair_rates(gamma);
        rates[i][j] += 50.0;
        rates[j][i] += 50.0;
        let k = fanos_geometry::fano::mediator(i, j).unwrap();
        prop_assert_eq!(polar::violated_classes(&rates, 1e-9), vec![k]);
    }

    /// The healing budget: `Φ → Φ/9^d` for any depth.
    #[test]
    fn healing_budget(phi in 1.0f64..1e6, d in 0u32..6) {
        let expected = phi / 9f64.powi(d as i32);
        prop_assert!((healing::phi_after_coarse_hops(phi, d) - expected).abs() <= expected.abs() * 1e-9 + 1e-12);
    }
}
