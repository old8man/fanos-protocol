//! Projective load balancing — spread load across the *whole* cell with **no local extrema** (the
//! metabolic complement to the coherence [`homeostat`](crate::homeostat)).
//!
//! A perennial failure of large distributed networks is hotspotting: load piles onto a few nodes (a local
//! extremum) while the rest idle, and naive local balancing can *stall* in such extrema. FANOS avoids it
//! by the geometry, not by tuning. Let each node relax its load toward the mean of the lines it lies on
//! (a Maekawa-quorum bus operation). Because any two points of `PG(2,q)` share exactly one line, the
//! point-line incidence matrix `A` satisfies
//!
//! ```text
//! A·Aᵀ = q·I + J        (diagonal q+1 = lines per point, off-diagonal 1 = the unique common line)
//! ```
//!
//! whose eigenvalues are `(q+1)²` (once, the all-ones/uniform mode) and `q` (multiplicity `N−1`). The
//! line-averaging diffusion `M = A·Aᵀ/(q+1)²` therefore has eigenvalue `1` on the uniform vector and
//! `λ₂ = q/(q+1)²` on **every** other mode. Two exact, load-bearing consequences:
//!
//! * **Convergence with no local extrema.** The uniform load is the *unique* fixed point (2-transitivity of
//!   `Aut(PG(2,q))` leaves no other invariant), and every deviation from it contracts by exactly `λ₂ < 1`
//!   per round — so the process cannot stall in a hotspot; the whole cell is driven to the global mean.
//! * **Closed-form step.** The projective identity collapses the diffusion to a per-node scalar update,
//!   `new[i] = (q·load[i] + S)/(q+1)²` with `S = Σ load` — O(N), total-conserving, no matrix. Minimalism by
//!   theorem: the balancer is one line, and its exact contraction rate `λ₂` is a closed form.
//!
//! For the Fano cell (`q = 2`, `N = 7`) this is `λ₂ = 2/9` (spectral gap `7/9`): a hotspot's excess is cut
//! to `2/9` of itself every round, `≈ 3.3×` per round, converging in a handful of rounds. This is exactly
//! the redistribution that dissolves a *differential*-DDoS hotspot (`docs/ddos-homeostasis.md §2`), so load
//! homeostasis and coherence homeostasis are two readings of the same projective structure.

// Dense fixed-size (7-node) kernel: every index is a Fano point/line in `0..7` (from the incidence tables
// or an `0..N` loop), so slice access is bounded by construction and reads most clearly as indexing.
#![allow(clippy::indexing_slicing)]

use fanos_geometry::fano;

/// Nodes per Fano cell (`q² + q + 1` at `q = 2`).
pub const N: usize = fano::N;

/// The Fano deviation-contraction factor `λ₂ = q/(q+1)²` at `q = 2`: one balancing round multiplies every
/// node's deviation from the global mean by exactly `2/9` (spectral gap `7/9`). This is the second
/// eigenvalue of the projective line-averaging diffusion — the guaranteed, tuning-free mixing rate.
pub const DEVIATION_CONTRACTION: f64 = 2.0 / 9.0;

/// One round of projective line-averaging load balancing: each node relaxes to the mean of the lines it
/// lies on. Total load is conserved and the deviation from the global mean contracts by exactly
/// [`DEVIATION_CONTRACTION`], so iterating converges geometrically to the unique uniform fixed point — the
/// whole cell is used, with no persistent hotspot. Implemented via the incidence (the realistic
/// bus-local operation); [`balance_step_closed_form`] is the algebraically-equal O(N) collapse.
#[must_use]
pub fn balance_step(loads: &[f64; N]) -> [f64; N] {
    let mut out = [0.0f64; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut acc = 0.0;
        let lines = fano::POINT_LINES[i];
        for &l in &lines {
            let pts = fano::LINE_POINTS[l as usize];
            let line_mean = pts.iter().map(|&p| loads[p as usize]).sum::<f64>() / pts.len() as f64;
            acc += line_mean;
        }
        *slot = acc / lines.len() as f64;
    }
    out
}

/// The closed-form projective balancing step `new[i] = (q·load[i] + S)/(q+1)²` (`q = 2`, `(q+1)² = 9`),
/// algebraically identical to [`balance_step`] but O(N) with no incidence walk — the minimal form the
/// projective identity `A·Aᵀ = q·I + J` guarantees.
#[must_use]
pub fn balance_step_closed_form(loads: &[f64; N]) -> [f64; N] {
    let s: f64 = loads.iter().sum();
    core::array::from_fn(|i| (2.0 * loads[i] + s) / 9.0)
}

/// Run [`balance_step`] until the peak-to-peak load spread is within `epsilon` of uniform, or `max_rounds`
/// is reached. Returns `(final_loads, rounds_used)`. Since the spread contracts by `λ₂ = 2/9` per round,
/// this terminates in `⌈log(ε/spread₀)/log(2/9)⌉` rounds — a few for any realistic imbalance.
#[must_use]
pub fn balance_to_uniform(loads: &[f64; N], epsilon: f64, max_rounds: u32) -> ([f64; N], u32) {
    let mut cur = *loads;
    let mut rounds = 0;
    while spread(&cur) > epsilon && rounds < max_rounds {
        cur = balance_step(&cur);
        rounds += 1;
    }
    (cur, rounds)
}

/// The peak-to-peak load spread `max − min` — zero exactly when the load is uniform (no hotspot).
#[must_use]
pub fn spread(loads: &[f64; N]) -> f64 {
    let mut lo = f64::INFINITY;
    let mut hi = f64::NEG_INFINITY;
    for &x in loads {
        lo = lo.min(x);
        hi = hi.max(x);
    }
    hi - lo
}

/// The L2 deviation from the global mean, `√Σ(load_i − mean)²` — the norm the diffusion contracts by
/// exactly `λ₂` each round (the projective spectral gap made measurable).
#[must_use]
pub fn deviation_from_mean(loads: &[f64; N]) -> f64 {
    let mean = loads.iter().sum::<f64>() / N as f64;
    crate::mathfns::sqrt(loads.iter().map(|&x| (x - mean) * (x - mean)).sum::<f64>())
}

#[cfg(test)]
#[allow(clippy::float_cmp, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn the_incidence_step_equals_the_closed_form() {
        // The realistic line-averaging operation collapses to (2·load[i] + S)/9 via A·Aᵀ = 2I + J.
        let loads = [3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0];
        let a = balance_step(&loads);
        let b = balance_step_closed_form(&loads);
        for i in 0..N {
            assert!(approx(a[i], b[i]), "node {i}: {} vs {}", a[i], b[i]);
        }
    }

    #[test]
    fn balancing_conserves_total_load() {
        let loads = [10.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let before: f64 = loads.iter().sum();
        let after: f64 = balance_step(&loads).iter().sum();
        assert!(approx(before, after), "total load is conserved: {before} vs {after}");
    }

    #[test]
    fn the_deviation_contracts_by_exactly_two_ninths_each_round() {
        // The projective spectral result made executable: every non-uniform load's L2 deviation from the
        // mean is multiplied by exactly λ₂ = 2/9 per round, whatever the pattern.
        for pattern in [
            [7.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0],
            [0.0, 0.0, 5.0, 0.0, 0.0, 5.0, 0.0],
        ] {
            let d0 = deviation_from_mean(&pattern);
            let d1 = deviation_from_mean(&balance_step(&pattern));
            assert!(d0 > 0.0);
            assert!(
                (d1 - DEVIATION_CONTRACTION * d0).abs() < 1e-9,
                "deviation contracts by exactly 2/9: {d0} → {d1}, expected {}",
                DEVIATION_CONTRACTION * d0
            );
        }
    }

    #[test]
    fn a_hotspot_spreads_to_the_whole_cell_with_no_local_extremum() {
        // A single flooded node (a differential-DDoS hotspot); the rest idle. Balancing drives every node
        // to the global mean S/N — the whole cell used — and it never stalls in a local extremum.
        let loads = [70.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let mean = 70.0 / N as f64;
        let (final_loads, rounds) = balance_to_uniform(&loads, 1e-9, 100);
        for (i, &x) in final_loads.iter().enumerate() {
            assert!((x - mean).abs() < 1e-9, "node {i} reached the global mean {mean}, got {x}");
        }
        // Geometric convergence at λ₂ = 2/9 ⇒ a handful of rounds, not a stall.
        assert!(rounds <= 20, "converges in a few rounds, took {rounds}");
        assert!(rounds > 0);
    }

    #[test]
    fn uniform_load_is_a_fixed_point_and_the_only_one() {
        // Uniform is fixed (no work to do), and any non-uniform load strictly decreases in deviation — so
        // there is no other fixed point, i.e. no local extremum the process could get trapped in.
        let uniform = [4.0; N];
        let stepped = balance_step(&uniform);
        for i in 0..N {
            assert!(approx(stepped[i], 4.0), "uniform is fixed");
        }
        // Every non-uniform pattern strictly contracts (deviation drops), so it cannot be a fixed point.
        for pattern in [
            [5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 0.0],
            [9.0, 0.0, 0.0, 9.0, 0.0, 0.0, 0.0],
        ] {
            let d0 = deviation_from_mean(&pattern);
            let d1 = deviation_from_mean(&balance_step(&pattern));
            assert!(d1 < d0, "non-uniform strictly contracts (no local extremum): {d0} → {d1}");
        }
    }

    #[test]
    fn balancing_is_symmetric_no_node_is_privileged() {
        // Vertex-transitivity: a hotspot on ANY node converges to the same uniform state in the same number
        // of rounds — no node is structurally a bottleneck or a privileged sink.
        let mut rounds_seen = None;
        for hot in 0..N {
            let mut loads = [0.0; N];
            loads[hot] = 42.0;
            let (final_loads, rounds) = balance_to_uniform(&loads, 1e-9, 100);
            let mean = 42.0 / N as f64;
            for &x in &final_loads {
                assert!((x - mean).abs() < 1e-9);
            }
            match rounds_seen {
                None => rounds_seen = Some(rounds),
                Some(r) => assert_eq!(r, rounds, "every node's hotspot converges identically"),
            }
        }
    }
}
