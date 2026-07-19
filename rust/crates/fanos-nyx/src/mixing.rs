//! Poisson mixing and structurally-balanced cover traffic (spec §5.5, V7/V8).
//!
//! Each mix hop applies an exponential delay of mean `1/μ` (Loopix-class). By Little's law the
//! anonymity set at a hop is the number of packets in its mixing window, `λ/μ` for arrival
//! rate `λ`, giving `log₂(λ/μ)` bits of entropy. The `μ` dial trades latency for anonymity
//! continuously — one substrate from "Tor-class" to "Nym+". Cover traffic is emitted at a
//! constant rate on each of a node's `q+1` lines; by point-regularity every node's total load
//! is identical, so there is **no volume fingerprint** (a theorem, not a policy).

/// Mean end-to-end latency of an `L`-hop path at mixing rate `μ` (per second): `L/μ` seconds.
#[must_use]
pub fn mean_path_latency(mu: f64, hops: u32) -> f64 {
    if mu <= 0.0 {
        return f64::INFINITY;
    }
    f64::from(hops) / mu
}

/// The anonymity-set size at a mix: packets in the window, `λ/μ` (Little's law, spec §5.5).
#[must_use]
pub fn anonymity_set(arrival_rate: f64, mu: f64) -> f64 {
    if mu <= 0.0 {
        return f64::INFINITY;
    }
    arrival_rate / mu
}

/// The anonymity entropy in bits: `log₂(anonymity_set)`.
///
/// **Informational only — never gate wire-visible behaviour on this value.** It is the sole caller of
/// [`crate::mathfns::log2`], whose result is *not* correctly-rounded and so may differ by an ULP
/// between a `std` node (hardware `f64::log2`) and a `no_std` node (`libm::log2`). That divergence is
/// harmless *because* this metric only ever feeds operator-facing reporting ([`DialPoint`]) and tests —
/// no route, `Effect`, or serialized byte depends on it, so two nodes can never disagree on the wire
/// over it. If this value is ever wired into a protocol decision it must first be quantized to a
/// backend-independent fixed-point form (see the determinism invariant, `docs/design-testing.md`).
#[must_use]
pub fn anonymity_entropy_bits(arrival_rate: f64, mu: f64) -> f64 {
    let set = anonymity_set(arrival_rate, mu);
    if set <= 1.0 {
        0.0
    } else {
        crate::mathfns::log2(set)
    }
}

/// A point on the λ (μ) dial: a mixing configuration and its resulting anonymity.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct DialPoint {
    /// Mixing rate `μ` (1/s).
    pub mu: f64,
    /// Path length `L`.
    pub hops: u32,
    /// System arrival rate `λ` (1/s).
    pub arrival_rate: f64,
    /// Mean end-to-end latency (s).
    pub latency_s: f64,
    /// Anonymity-set size.
    pub anonymity_set: f64,
    /// Anonymity entropy (bits).
    pub entropy_bits: f64,
}

impl DialPoint {
    /// Compute the anonymity metrics for a `(μ, L, λ)` operating point.
    #[must_use]
    pub fn new(mu: f64, hops: u32, arrival_rate: f64) -> Self {
        Self {
            mu,
            hops,
            arrival_rate,
            latency_s: mean_path_latency(mu, hops),
            anonymity_set: anonymity_set(arrival_rate, mu),
            entropy_bits: anonymity_entropy_bits(arrival_rate, mu),
        }
    }
}

/// A node's total cover-traffic load: a constant `per_line_rate` on each of its `q+1` lines.
/// Identical for every node by point-regularity — the zero-fingerprint property (spec §5.5).
#[must_use]
pub fn cover_load_per_node(q: u32, per_line_rate: f64) -> f64 {
    f64::from(q + 1) * per_line_rate
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, rel: f64) -> bool {
        (a - b).abs() <= rel * b.abs().max(1e-12)
    }

    #[test]
    fn v7_mixing_table() {
        // spec §5.5 table: (μ, L, λ) → (latency, anon set, entropy).
        let rows = [
            (2.0, 3, 50.0, 1.5, 25.0, 4.64),
            (1.0, 3, 50.0, 3.0, 50.0, 5.64),
            (0.5, 5, 200.0, 10.0, 400.0, 8.64),
            (0.2, 5, 1000.0, 25.0, 5000.0, 12.29),
        ];
        for (mu, hops, lambda, latency, set, entropy) in rows {
            let d = DialPoint::new(mu, hops, lambda);
            assert!(approx(d.latency_s, latency, 1e-6), "latency at μ={mu}");
            assert!(approx(d.anonymity_set, set, 1e-6), "anon set at μ={mu}");
            assert!(approx(d.entropy_bits, entropy, 1e-2), "entropy at μ={mu}");
        }
    }

    #[test]
    fn dial_trades_latency_for_anonymity() {
        // Lowering μ raises both latency and anonymity — the continuous dial.
        let fast = DialPoint::new(2.0, 3, 50.0);
        let slow = DialPoint::new(0.2, 5, 1000.0);
        assert!(slow.latency_s > fast.latency_s);
        assert!(slow.entropy_bits > fast.entropy_bits);
    }

    #[test]
    fn v8_cover_load_is_uniform_across_nodes() {
        // Every node emits the same total cover on its q+1 lines — no volume fingerprint.
        let q = 31;
        let load = cover_load_per_node(q, 10.0);
        assert_eq!(load, 320.0); // (31+1) × 10, identical for all N nodes
    }
}
