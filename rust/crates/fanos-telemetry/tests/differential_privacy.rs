//! C7 — the differentially-private telemetry export boundary (`fanos_telemetry::dp`).
//!
//! Validates `CoherenceFrame::privatize`: the **identity floor** (the exact faulted point and the
//! per-window event fields are withheld on export), the **ε-DP guarantee** (a raw frame is a
//! deanonymization oracle, while the private frame's optimal distinguishing advantage matches the
//! analytic Laplace total-variation bound `1 − e^{−ε/2}`), and **utility** (the noised statistic is
//! unbiased, so the cell signal survives).

// The withheld fields are set to *exactly* 0.0/0 on export, and the determinism check compares identical
// computations — so exact float equality is the correct assertion here, not an epsilon comparison.
#![allow(clippy::unwrap_used, clippy::float_cmp)]

use core::convert::Infallible;

use fanos_diakrisis::coherence::CoherenceMatrix;
use fanos_telemetry::{CellId, CoherenceFrame, PrivacyBudget, R_SENSITIVITY};
use rand_core::TryRng;

/// A tiny deterministic SplitMix64 — reproducible Monte-Carlo without pulling a full RNG crate. In
/// rand_core 0.10 an infallible generator implements [`TryRng`] with `Error = Infallible`; `Rng` then
/// comes from a blanket impl, so `privatize`'s `impl Rng` bound is satisfied.
struct SplitMix64(u64);

impl SplitMix64 {
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl TryRng for SplitMix64 {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok((self.step() >> 32) as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.step())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            for (slot, b) in chunk.iter_mut().zip(self.step().to_le_bytes()) {
                *slot = b;
            }
        }
        Ok(())
    }
}

/// The internal (full-resolution) coherence frame for an equicorrelated `N = 7` cell with the given
/// faulted-point mask, spectral gap, and healing counter.
fn internal_frame(r: f64, degraded: u8, gap: f64, heal_seq: u32) -> CoherenceFrame {
    let matrix = CoherenceMatrix::equicorrelated(7, r);
    CoherenceFrame::observe(CellId([0x5A; 16]), 7, &matrix, degraded, gap, 4, heal_seq)
}

#[test]
fn the_export_withholds_the_exact_syndrome_and_event_fields() {
    // An internal frame that localizes point 2 (mask bit 2), with a real gap, forecast, and heal count.
    let internal = internal_frame(0.5, 0b0000_0100, 0.42, 9);
    assert!(internal.is_faulted(), "the internal frame names the faulted point");
    assert_ne!(internal.gap, 0.0);
    assert_ne!(internal.heal_seq, 0);

    let exported = internal.privatize(PrivacyBudget::default(), &mut SplitMix64(1));

    // The cell-granular floor: exact point, gap, healing timeline, and forecast are all withheld.
    assert_eq!(exported.syndrome, 0, "the exact faulted point is withheld on export");
    assert!(!exported.is_faulted());
    assert_eq!(exported.gap, 0.0, "the spectral gap is withheld");
    assert_eq!(exported.heal_seq, 0, "the healing-event counter is withheld");
    assert_eq!(exported.forecast, -1, "the cascade forecast is withheld");

    // The cell identity and window survive (cell-granular, not per-node), and the frame is well-formed.
    assert_eq!(exported.cell_id, internal.cell_id);
    assert_eq!(exported.epoch, internal.epoch);
    assert_eq!(CoherenceFrame::decode(&exported.encode()), Some(exported));
    assert!(exported.phi.is_finite() && exported.mean_r.is_finite());
}

#[test]
fn privatize_is_deterministic_in_its_rng() {
    let internal = internal_frame(0.5, 0b0000_0001, 0.3, 2);
    let a = internal.privatize(PrivacyBudget::new(0.7), &mut SplitMix64(42));
    let b = internal.privatize(PrivacyBudget::new(0.7), &mut SplitMix64(42));
    assert_eq!(a, b, "same seed ⇒ same private frame (sans-I/O replay)");
    let c = internal.privatize(PrivacyBudget::new(0.7), &mut SplitMix64(43));
    assert_ne!(a.mean_r, c.mean_r, "a different seed draws different noise");
}

#[test]
fn a_raw_frame_is_an_oracle_but_the_private_frame_meets_the_dp_bound() {
    // Two flow-adjacent worlds: they differ by exactly one flow, so their mean correlation differs by the
    // sensitivity Δr = 1/21. A distinguisher that reads the exported mean_r guesses which world it came
    // from — the deanonymization primitive C7 must defeat.
    const TRIALS: u32 = 40_000;
    let r_a = 0.45;
    let r_b = r_a + R_SENSITIVITY;
    let world_a = internal_frame(r_a, 0, 0.0, 0);
    let world_b = internal_frame(r_b, 0, 0.0, 0);
    let midpoint = f64::midpoint(r_a, r_b);

    // Undefended: exporting the RAW frame. The exact mean_r reveals the world with certainty — advantage
    // = |P(guess A | A) − P(guess A | B)| = |1 − 0| = 1.
    let raw_a_guesses_a = f64::from(world_a.mean_r) < midpoint;
    let raw_b_guesses_a = f64::from(world_b.mean_r) < midpoint;
    let raw_adv =
        f64::from(u8::from(raw_a_guesses_a)) - f64::from(u8::from(raw_b_guesses_a));
    assert!(raw_adv > 0.99, "a raw frame is a deanonymization oracle (advantage ≈ 1): {raw_adv}");

    // Defended: the ε-DP export. The optimal threshold distinguisher's advantage must match the analytic
    // Laplace total-variation distance between the two worlds, TV = 1 − e^{−ε/2}.
    let epsilon = 0.5;
    let budget = PrivacyBudget::new(epsilon);
    let mut rng_a = SplitMix64(0x00A1_1CE5);
    let mut rng_b = SplitMix64(0x0000_0B0B);
    let mut a_guessed_a = 0u32;
    let mut b_guessed_a = 0u32;
    let mut sum_ra = 0.0f64;
    for _ in 0..TRIALS {
        let ea = world_a.privatize(budget, &mut rng_a);
        let eb = world_b.privatize(budget, &mut rng_b);
        if f64::from(ea.mean_r) < midpoint {
            a_guessed_a += 1;
        }
        if f64::from(eb.mean_r) < midpoint {
            b_guessed_a += 1;
        }
        sum_ra += f64::from(ea.mean_r);
    }
    let p_a = f64::from(a_guessed_a) / f64::from(TRIALS);
    let p_b = f64::from(b_guessed_a) / f64::from(TRIALS);
    let defended_adv = (p_a - p_b).abs();
    let analytic_tv = 1.0 - (-epsilon / 2.0).exp(); // ≈ 0.2212 for ε = 0.5

    assert!(
        (defended_adv - analytic_tv).abs() < 0.03,
        "the DP export's distinguishing advantage {defended_adv:.3} must match the analytic Laplace bound \
         1 − e^(−ε/2) = {analytic_tv:.3}"
    );
    assert!(
        defended_adv < raw_adv - 0.6,
        "DP collapses the deanonymization advantage from ≈1 to ≈{analytic_tv:.2} (got {defended_adv:.3})"
    );

    // Utility: the noised statistic is unbiased — its mean tracks the true r (Laplace is zero-mean), so
    // the cell health signal survives aggregation even as any single flow is hidden.
    let mean_ra = sum_ra / f64::from(TRIALS);
    assert!(
        (mean_ra - r_a).abs() < 0.01,
        "utility preserved: the mean exported r {mean_ra:.4} tracks the true r {r_a:.4}"
    );
}

#[test]
fn a_smaller_epsilon_hides_more() {
    // Stronger privacy (smaller ε) ⇒ more noise ⇒ a lower distinguishing advantage. Monotonicity is the
    // knob's contract: `1 − e^{−ε/2}` is increasing in ε.
    const TRIALS: u32 = 40_000;
    let world_a = internal_frame(0.45, 0, 0.0, 0);
    let world_b = internal_frame(0.45 + R_SENSITIVITY, 0, 0.0, 0);
    let midpoint = f64::midpoint(0.45, 0.45 + R_SENSITIVITY);

    let advantage_at = |epsilon: f64, seed: u64| -> f64 {
        let budget = PrivacyBudget::new(epsilon);
        let mut ra = SplitMix64(seed);
        let mut rb = SplitMix64(seed ^ 0xFFFF);
        let (mut a_a, mut b_a) = (0u32, 0u32);
        for _ in 0..TRIALS {
            if f64::from(world_a.privatize(budget, &mut ra).mean_r) < midpoint {
                a_a += 1;
            }
            if f64::from(world_b.privatize(budget, &mut rb).mean_r) < midpoint {
                b_a += 1;
            }
        }
        (f64::from(a_a) / f64::from(TRIALS) - f64::from(b_a) / f64::from(TRIALS)).abs()
    };

    let strong = advantage_at(0.2, 7);
    let weak = advantage_at(1.0, 7);
    assert!(
        strong < weak,
        "smaller ε hides more: adv(ε=0.2)={strong:.3} must be < adv(ε=1.0)={weak:.3}"
    );
}
