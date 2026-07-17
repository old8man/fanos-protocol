//! The threshold-hop security curve (spec §5.2, V5).
//!
//! In NYX a hop is a **line**, peeled only by a threshold `t` of its `q+1` members. An
//! adversary owning a random fraction `f` of nodes breaks one hop with probability
//! `P_hop = P(Binomial(q+1, f) ≥ t)` — a binomial tail. Endpoint linkage (Tor's guard+exit)
//! needs the first *and* last hop, `P_link = P_hop²`, and full tracing of an `L`-hop path is
//! `P_hop^L`. Compared with Tor's `f²`, this is orders of magnitude smaller for `f ≤ 0.3`.

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
}
