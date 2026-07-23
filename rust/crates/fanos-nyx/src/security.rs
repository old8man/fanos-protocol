//! The threshold-hop security curve (spec §5.2, V5).
//!
//! In NYX a hop is a **line**, peeled only by a threshold `t` of its `q+1` members. An
//! adversary owning a random fraction `f` of nodes breaks one hop with probability
//! `P_hop = P(Binomial(q+1, f) ≥ t)` — a binomial tail. Endpoint linkage (Tor's guard+exit)
//! needs the first *and* last hop, `P_link = P_hop²`, and full tracing of an `L`-hop path is
//! `P_hop^L`. Compared with Tor's `f²`, this is orders of magnitude smaller for `f ≤ 0.3`.
//!
//! [`hop_compromise`] is the *exact* tail; [`chernoff_break_bound`] is its closed-form **upper bound**
//! `exp(−(q+1)·D(τ‖f))` (the **Anytrust-escape**, design authority T4): exponentially small in the cell
//! size for any sub-threshold `f < τ = t/(q+1)`, so scaling `q` drives the break probability to zero and
//! the MIX lane runs at the honest-network frontier instead of the trilemma's Anytrust `√K` latency. The
//! tests verify the bound dominates the exact tail across a grid of cells — the computational content of T4.

/// `P(Binomial(n, f) ≥ t)` — the probability at least `t` of `n` line members are adversarial.
#[must_use]
pub fn hop_compromise(line_size: u32, threshold: u32, f: f64) -> f64 {
    if threshold == 0 {
        return 1.0;
    }
    if threshold > line_size {
        return 0.0;
    }
    let mut sum = 0.0;
    for k in threshold..=line_size {
        sum += binomial_pmf(line_size, k, f);
    }
    sum.clamp(0.0, 1.0)
}

/// Endpoint linkage probability `P_link = P_hop²` (breaking first and last hop, spec §5.2).
#[must_use]
pub fn endpoint_linkage(line_size: u32, threshold: u32, f: f64) -> f64 {
    let p = hop_compromise(line_size, threshold, f);
    p * p
}

/// Full-path tracing probability `P_hop^L` for an `L`-hop circuit.
#[must_use]
pub fn full_trace(line_size: u32, threshold: u32, f: f64, hops: u32) -> f64 {
    crate::mathfns::powi(hop_compromise(line_size, threshold, f), hops as i32)
}

/// Tor's endpoint-correlation baseline `f²` (owning a fraction `f` of relays).
#[must_use]
pub fn tor_baseline(f: f64) -> f64 {
    f * f
}

/// How many times smaller NYX endpoint linkage is than Tor's `f²` at the same `f`.
#[must_use]
pub fn advantage_over_tor(line_size: u32, threshold: u32, f: f64) -> f64 {
    let nyx = endpoint_linkage(line_size, threshold, f);
    if nyx <= 0.0 {
        f64::INFINITY
    } else {
        tor_baseline(f) / nyx
    }
}

/// The binary Kullback–Leibler divergence `D(τ‖f)` in nats — `τ·ln(τ/f) + (1−τ)·ln((1−τ)/(1−f))`, the
/// large-deviation rate of the Chernoff–Hoeffding tail. Uses the standard `0·ln0 = 0` convention, and is
/// `+∞` when `f = 0 < τ` (a corruption-free network never reaches the threshold).
#[must_use]
pub fn kl_divergence(tau: f64, f: f64) -> f64 {
    let term = |a: f64, b: f64| {
        if a <= 0.0 {
            0.0 // 0·ln0 := 0
        } else if b <= 0.0 {
            f64::INFINITY // a·ln(a/0) = +∞ for a > 0
        } else {
            a * crate::mathfns::ln(a / b)
        }
    };
    term(tau, f) + term(1.0 - tau, 1.0 - f)
}

/// The **Anytrust-escape Chernoff bound** on the hop-break probability (spec §5.2; design authority T4):
///
/// > `P(Binomial(q+1, f) ≥ t) ≤ exp(−(q+1)·D(τ‖f))`,  `τ = t/(q+1)`,  valid for `f < τ`.
///
/// It is an *upper bound* on the exact [`hop_compromise`] tail — verified in the tests to dominate it —
/// and it is **exponentially small in the line size** for any sub-threshold corruption fraction `f < τ`.
/// So growing the cell (`q`) drives the break probability to zero, and the MIX lane runs at the
/// honest-network frontier rather than paying the Anytrust `√K` latency the trilemma otherwise imposes:
/// a *node-level* corruption budget is converted into an exponentially-safer *line-level threshold*
/// budget. Returns the trivial `1.0` when `f ≥ τ` (the bound covers only the upper tail, above the mean).
#[must_use]
pub fn chernoff_break_bound(line_size: u32, threshold: u32, f: f64) -> f64 {
    if threshold == 0 || line_size == 0 {
        return 1.0;
    }
    if threshold > line_size {
        return 0.0;
    }
    let tau = f64::from(threshold) / f64::from(line_size);
    if f >= tau {
        return 1.0; // the mean already meets the threshold — no small-tail bound applies
    }
    crate::mathfns::exp(-f64::from(line_size) * kl_divergence(tau, f)).clamp(0.0, 1.0)
}

/// The binomial pmf `C(n,k) f^k (1-f)^(n-k)`, computed without overflowing the coefficient.
fn binomial_pmf(n: u32, k: u32, f: f64) -> f64 {
    let mut coeff = 1.0;
    for i in 0..k {
        coeff = coeff * f64::from(n - i) / f64::from(i + 1);
    }
    coeff * crate::mathfns::powi(f, k as i32) * crate::mathfns::powi(1.0 - f, (n - k) as i32)
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, rel: f64) -> bool {
        (a - b).abs() <= rel * b.abs().max(1e-300)
    }

    #[test]
    fn v5_endpoint_linkage_matches_spec() {
        // spec §5.2 / Appendix D: (q+1=8, t=6, f=0.2) → P_link ≈ 1.516e-6, ×26,381 over Tor.
        let p_link = endpoint_linkage(8, 6, 0.2);
        assert!(approx(p_link, 1.516e-6, 5e-3), "P_link = {p_link:e}");
        assert!(approx(advantage_over_tor(8, 6, 0.2), 26_381.0, 1e-2));
    }

    #[test]
    fn security_curve_table() {
        // A few cells from the spec §5.2 table (order-of-magnitude tolerance).
        assert!(endpoint_linkage(8, 6, 0.1) < 1e-8);
        assert!(endpoint_linkage(14, 10, 0.1) < 1e-13);
        assert!(endpoint_linkage(32, 22, 0.2) < 1e-15);
        // Degrades toward Tor as f → majority (a fundamental limit).
        assert!(endpoint_linkage(8, 6, 0.5) < tor_baseline(0.5));
    }

    #[test]
    fn tracing_is_steeper_than_linkage() {
        // Tracing all L hops is P_hop^L: for (8,6), f=0.2, L=3 → ~1.9e-9.
        let trace = full_trace(8, 6, 0.2, 3);
        assert!(trace < endpoint_linkage(8, 6, 0.2));
        assert!(approx(trace, 1.9e-9, 0.1));
    }

    #[test]
    fn edge_cases() {
        assert_eq!(hop_compromise(8, 0, 0.2), 1.0);
        assert_eq!(hop_compromise(8, 9, 0.2), 0.0);
        assert!((hop_compromise(8, 1, 1.0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn t4_the_chernoff_bound_dominates_the_exact_hop_break_probability() {
        // T4 (Anytrust-escape): for every sub-threshold corruption fraction f < τ = t/(q+1), the exact
        // binomial tail P(Bin(q+1,f) ≥ t) is dominated by exp(−(q+1)·D(τ‖f)). Verified across a grid of
        // cells (Fano q=2 through a large PG(2,7) committee) and corruption fractions — this is the
        // computational content of the stated theorem.
        for &(n, t) in &[(3u32, 2u32), (8, 6), (14, 10), (32, 22), (57, 30)] {
            let tau = f64::from(t) / f64::from(n);
            let mut f = 0.01;
            while f < tau - 1e-9 {
                let exact = hop_compromise(n, t, f);
                let bound = chernoff_break_bound(n, t, f);
                assert!(
                    exact <= bound * (1.0 + 1e-9),
                    "T4 violated at (n={n}, t={t}, f={f}): exact {exact:e} exceeds bound {bound:e}"
                );
                f += 0.02;
            }
        }
    }

    #[test]
    fn t4_the_break_bound_decays_exponentially_in_the_cell_size() {
        // The Anytrust-escape proper: fixing τ = 2/3 and f = 0.2 < τ, growing the line size drives the
        // break bound → 0 exponentially — larger cells are strictly safer, so FANOS never enters the √K
        // Anytrust regime.
        let f = 0.2;
        let mut prev = 1.0;
        for &(n, t) in &[(3u32, 2u32), (6, 4), (12, 8), (24, 16), (48, 32)] {
            let bound = chernoff_break_bound(n, t, f); // τ = t/n = 2/3 throughout
            assert!(
                bound < prev,
                "P_break must shrink as the cell grows: n={n} bound={bound:e} not < {prev:e}"
            );
            prev = bound;
        }
        assert!(
            chernoff_break_bound(48, 32, f) < 1e-6,
            "a large cell is overwhelmingly unbreakable below threshold"
        );
        // f ≥ τ carries no small-tail bound (trivial 1.0), matching the theorem's precondition.
        assert_eq!(chernoff_break_bound(8, 6, 0.8), 1.0);
        // The binary KL is non-negative and zero exactly at τ = f (Gibbs' inequality).
        assert!(kl_divergence(0.4, 0.4).abs() < 1e-12);
        assert!(kl_divergence(0.6, 0.2) > 0.0);
    }
}
