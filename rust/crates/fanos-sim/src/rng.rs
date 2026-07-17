//! A deterministic, seedable PRNG (SplitMix64) — the simulator's entropy port.
//!
//! Every source of randomness in a run (network jitter, loss draws, and any node entropy)
//! comes from here, seeded once, so a `(seed, scenario)` pair reproduces byte-identically on
//! every platform (see `docs/architecture.md`, the determinism contract).

/// SplitMix64 — a fast, well-distributed deterministic generator.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Seed the generator.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform `f64` in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        // 53 high bits → the mantissa, exactly representable.
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
    }

    /// A uniform integer in `0..n` (`n > 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0);
        self.next_u64() % n
    }

    /// Whether an event of probability `p` occurs.
    pub fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = Rng::new(1234);
        let mut b = Rng::new(1234);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn unit_is_in_range() {
        let mut r = Rng::new(9);
        for _ in 0..10_000 {
            let u = r.unit();
            assert!((0.0..1.0).contains(&u));
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }
}
