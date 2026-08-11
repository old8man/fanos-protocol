//! Is **healing the same lever as erasure**? (#139 condition 2, #272's residual)
//!
//! UHM's second condition on a lifter is a *personal anchor*: state that is not shareable at any coupling.
//! Without one, "feed this node" and "overwrite this node" are the same operation at different weights, and
//! a controller that can do the first can do the second by turning a dial it already holds.
//!
//! FANOS has the structural half — roles differ by coordinate, so nodes are not interchangeable by
//! construction. It does not have the second half: [`BehaviorMonitor`](fanos_diakrisis::monitor) keeps one
//! scalar sample per node, every sample enters `Γ`, and no component is reserved that never converges.
//!
//! This file does not argue that from the shape of the code. It drives the lifter's mixture to its limit
//! and reads what comes out, because "healing and erasure are one lever" is a claim about a reachable
//! state and belongs to a measurement.
//!
//! **It found one, in code I had shipped an hour earlier.** `lift::apply`'s first version mixed the
//! recipient's row toward the donor's with nothing reserved, and at full weight it produced `c = 1.000000`,
//! every other coupling equal to the donor's, and a smallest eigenvalue of `1.2e-16`. The lifter built to
//! feed a cell could erase a member, and the dial was already in its hand. `ANCHOR_SHARE` is now inside
//! the mixture, and the two tests below hold both halves: what the unanchored form does, and that the
//! shipped one cannot.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use fanos_diakrisis::coherence::CoherenceMatrix;
use fanos_diakrisis::lift::{Lift, apply};

const N: usize = 7;
const T: usize = 4096;

fn noise(seed: u64) -> Vec<f64> {
    let mut s = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..T)
        .map(|_| {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            f64::from((s >> 32) as u32) / f64::from(u32::MAX) * 2.0 - 1.0
        })
        .collect()
}

/// A plain cell at exchange strength `lambda` — nodes distinct, nothing anchored.
fn cell(lambda: f64) -> CoherenceMatrix {
    let shared = noise(0x00C0_FFEE);
    let signals: Vec<Vec<f64>> = (0..N)
        .map(|i| {
            let own = noise(0x5EED + i as u64);
            own.iter()
                .zip(&shared)
                .map(|(&o, &s)| (1.0 - lambda) * o + lambda * s)
                .collect()
        })
        .collect();
    CoherenceMatrix::from_signals(&signals).expect("real signals give a PSD correlation matrix")
}

/// **The erasure, measured — and that the shipped mixture cannot reach it.**
///
/// The first half computes the unanchored mixture directly, because it is no longer what [`apply`] does and
/// a claim about a mechanism nobody can run is not a measurement. The second half asserts the shipped one
/// refuses that state, so this is a guard rather than a museum piece: setting `ANCHOR_SHARE` to zero turns
/// it red.
#[test]
fn the_unanchored_mixture_erases_a_member_and_the_shipped_one_cannot() {
    let g = cell(0.30);
    let (recipient, donor) = (0usize, 3usize);

    // The unanchored mixture at full weight, written out: the recipient's row simply becomes the donor's.
    let mut raw = vec![0.0; N * N];
    for i in 0..N {
        for j in 0..N {
            raw[i * N + j] = g.pairwise(i, j).expect("a 7-node cell");
        }
    }
    for k in 0..N {
        if k == recipient {
            continue;
        }
        let v = if k == donor { 1.0 } else { g.pairwise(donor, k).expect("a 7-node cell") };
        raw[recipient * N + k] = v;
        raw[k * N + recipient] = v;
    }
    let smallest_raw = smallest_eigenvalue(&raw);
    println!(
        "unanchored, λ=1: c[{recipient}][{donor}] {:.6} → {:.6}, smallest eigenvalue {smallest_raw:.3e}",
        g.pairwise(recipient, donor).expect("a 7-node cell"),
        raw[recipient * N + donor]
    );
    assert!(
        (raw[recipient * N + donor] - 1.0).abs() < 1e-12 && smallest_raw.abs() < 1e-6,
        "the unanchored form must reach a perfectly correlated pair and a rank-deficient self-model, or \
         the harm this file is about does not exist as stated"
    );

    // And the shipped mixture, at the same full weight, must not.
    let after = apply(&g, Lift { recipient, donor, lambda: 1.0 }).expect("a full mixture is still a state");
    let coupling = after.pairwise(recipient, donor).expect("a 7-node cell");
    let a = fanos_diakrisis::lift::ANCHOR_SHARE;
    let ceiling = (1.0 - a) / (a * a + (1.0 - a) * (1.0 - a)).sqrt();
    let mut shipped = vec![0.0; N * N];
    for i in 0..N {
        for j in 0..N {
            shipped[i * N + j] = after.pairwise(i, j).expect("a 7-node cell");
        }
    }
    let smallest = smallest_eigenvalue(&shipped);
    println!(
        "anchored a={a:.2}, λ=1: c[{recipient}][{donor}] → {coupling:.6} (ceiling {ceiling:.6}), \
         smallest eigenvalue {smallest:.6}"
    );
    assert!(
        coupling <= ceiling + 1e-9,
        "a reserved share must cap the achievable coupling at (1−a)/√(a²+(1−a)²): {coupling} > {ceiling}"
    );
    assert!(
        smallest > 1e-3,
        "and the self-model must keep the dimension the anchor reserves: λ_min = {smallest}"
    );
}

/// The smallest eigenvalue of a symmetric matrix — how a lost dimension shows up in the measures.
fn smallest_eigenvalue(m: &[f64]) -> f64 {
    fanos_diakrisis::eig::eigenvalues_symmetric(m, N)
        .expect("the spectrum converges")
        .iter()
        .copied()
        .fold(f64::INFINITY, f64::min)
}
