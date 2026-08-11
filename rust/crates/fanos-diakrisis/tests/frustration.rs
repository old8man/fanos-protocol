//! The two instrument families the verdict summarises away, and what they can see that `Φ` cannot.
//! (#223, UHM T-306/T-311/T-317)
//!
//! T-317 counts the cell's self-model at **34 independent numbers** on a Fano cell: the 6 diagonal
//! activity shares, the 21 pairwise couplings, and the 7 line holonomies. The verdict — `Φ`, `P`, `R` —
//! is three of them, and it is not a fourth family: those three are *functions* of the other 34. So the
//! question this file asks is not "are there more numbers" but "does any of them decide something the
//! verdict decides differently".
//!
//! For the holonomies the answer is a theorem, T-311: `Φ` sums `c_ij²` and therefore **squares the sign
//! away**, so a frustrated loop — one where no assignment of "these two move together" is consistent
//! around the triple — is invisible to it. This file constructs the two worlds and checks that the verdict
//! genuinely cannot tell them apart, because a new reading whose answer is already implied by an old one is
//! not an instrument, it is a restatement.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use fanos_diakrisis::coherence::CoherenceMatrix;
use fanos_geometry::fano;

const N: usize = 7;

/// A cell whose couplings are `+r` everywhere except on the pairs of one Fano line, where the sign of one
/// pair is flipped to `-r`.
///
/// Flipping exactly one edge of a triangle is what makes it frustrated: the product of the three couplings
/// goes negative, and no assignment of directions to the three nodes satisfies all three pairs at once.
/// Every `|c_ij|` is unchanged, which is the whole point — `Φ` reads the squares.
fn cell(r: f64, flip: Option<(usize, usize)>) -> CoherenceMatrix {
    let mut c = vec![0.0; N * N];
    for i in 0..N {
        c[i * N + i] = 1.0;
        for j in (i + 1)..N {
            let flipped = flip == Some((i, j)) || flip == Some((j, i));
            let v = if flipped { -r } else { r };
            c[i * N + j] = v;
            c[j * N + i] = v;
        }
    }
    CoherenceMatrix::from_correlation(c, N).expect("a symmetric unit-diagonal matrix in range")
}

/// The frustration a Fano line carries is a fact the verdict cannot reach.
#[test]
fn a_frustrated_line_is_invisible_to_phi_and_visible_to_the_holonomy() {
    // `r` small enough that flipping one edge leaves the matrix positive semi-definite — a state the cell
    // can actually be in. `from_correlation` accepts any symmetric unit-diagonal matrix in range, so PSD is
    // this test's obligation, not the constructor's, and it is asserted below through the measures.
    let r = 0.30;
    let line = fano::LINE_POINTS[0];
    let (a, b) = (usize::from(line[0]), usize::from(line[1]));

    let plain = cell(r, None);
    let frustrated = cell(r, Some((a, b)));

    let (mp, mf) = (plain.measures(), frustrated.measures());
    println!(
        "plain:      Φ={:.9} P={:.9} R={:.9} r={:.9} holonomies={:?}",
        mp.phi,
        mp.purity,
        mp.reflection,
        plain.mean_correlation(),
        plain.line_holonomies().expect("a Fano cell")
    );
    println!(
        "frustrated: Φ={:.9} P={:.9} R={:.9} r={:.9} holonomies={:?}",
        mf.phi,
        mf.purity,
        mf.reflection,
        frustrated.mean_correlation(),
        frustrated.line_holonomies().expect("a Fano cell")
    );

    // Both cells must be reachable states, or the comparison is between a cell and a fiction.
    for (name, m) in [("plain", &mp), ("frustrated", &mf)] {
        assert!(
            m.purity > 0.0 && m.phi >= 0.0 && m.reflection > 0.0,
            "the {name} cell must be a real state: {m:?}"
        );
    }

    // THE BLINDNESS. `Φ` sums the squares, so a sign flip moves it by nothing at all.
    assert!(
        (mp.phi - mf.phi).abs() < 1e-12,
        "Φ separated the two cells ({} vs {}), so it is NOT blind to the sign and T-311's premise does not \
         transfer here — check the construction before concluding anything about the holonomy",
        mp.phi,
        mf.phi
    );
    assert!(
        (mp.purity - mf.purity).abs() < 1e-12 && (mp.reflection - mf.reflection).abs() < 1e-12,
        "P or R separated them, so the whole verdict is not blind after all"
    );
    assert_eq!(
        (plain.collective_state(), plain.alarm()),
        (frustrated.collective_state(), frustrated.alarm()),
        "the classifier reached a different verdict, which would make the holonomy redundant"
    );

    // THE READING. The mean correlation *does* move — flipping one of 21 pairs changes the average — so the
    // discriminator has to be the holonomy rather than "something differs".
    let hp = plain.line_holonomies().expect("a Fano cell");
    let hf = frustrated.line_holonomies().expect("a Fano cell");
    assert!(hp.iter().all(|&v| v > 0.0), "an all-positive cell frustrates nothing: {hp:?}");
    assert!(hf[0] < 0.0, "line 0 carries the flipped pair and must read frustrated: {hf:?}");
    assert_eq!(
        frustrated.frustrated_lines().count_ones(),
        1,
        "exactly one line contains that pair — the other two lines through each endpoint use its other \
         edges, whose signs are untouched: mask {:07b}",
        frustrated.frustrated_lines()
    );
    assert_eq!(plain.frustrated_lines(), 0, "and the plain cell reports none");
}

/// GF(2) rank by Gaussian elimination over bit-vectors.
fn rank(mut rows: Vec<u32>) -> usize {
    let mut r = 0usize;
    for bit in 0..32 {
        let Some(pivot) = rows.iter().skip(r).position(|v| v & (1 << bit) != 0) else {
            continue;
        };
        rows.swap(r, r + pivot);
        let p = rows[r];
        for row in rows.iter_mut().skip(r + 1) {
            if *row & (1 << bit) != 0 {
                *row ^= p;
            }
        }
        r += 1;
    }
    r
}

/// **Eight loop dimensions are dark, and this computes it rather than quoting it.**
///
/// The cell's loops live in the cycle space of `K₇`: subsets of the 21 edges with every vertex touched an
/// even number of times, a `GF(2)` vector space of dimension `E − V + 1 = 21 − 7 + 1 = 15`. Each triple
/// contributes the vector with ones on its three edges. The Fano plane draws seven of those triples, so the
/// question "how much of the cell's loop structure does the geometry name" is the `GF(2)` rank of those
/// seven vectors — and the dark part is the quotient.
///
/// This matters because [`CoherenceMatrix::line_holonomies`] reads exactly the seven. Anything the plane
/// does not draw is not merely unread; it is unreachable from that reading, and saying so with a number is
/// what stops the seven from being mistaken for a complete instrument.
#[test]
fn the_fano_lines_leave_exactly_eight_loop_dimensions_dark() {
    // Edge indexing: pair (i, j) with i < j maps to a bit position in a 21-bit word.
    let edge_bit = |i: usize, j: usize| -> u32 {
        let (a, b) = if i < j { (i, j) } else { (j, i) };
        // Offset of row `a` in the strictly-upper triangle, plus the offset within it.
        let start: usize = (0..a).map(|k| N - 1 - k).sum();
        u32::try_from(start + (b - a - 1)).expect("21 edges fit a u32")
    };
    let edges = N * (N - 1) / 2;
    assert_eq!(edges, 21, "K₇ has 21 edges");

    // A triangle as a GF(2) vector over the edge space.
    let triangle = |i: usize, j: usize, k: usize| -> u32 {
        (1 << edge_bit(i, j)) | (1 << edge_bit(j, k)) | (1 << edge_bit(k, i))
    };


    // The whole cycle space, spanned by every triangle in K₇ (true for any complete graph on ≥ 3 vertices).
    let all: Vec<u32> = (0..N)
        .flat_map(|i| ((i + 1)..N).flat_map(move |j| ((j + 1)..N).map(move |k| (i, j, k))))
        .map(|(i, j, k)| triangle(i, j, k))
        .collect();
    let cycle_dim = rank(all.clone());
    assert_eq!(
        cycle_dim,
        edges - N + 1,
        "the triangles must span the whole cycle space, or the denominator below is wrong: got \
         {cycle_dim}, expected {} from E − V + 1",
        edges - N + 1
    );

    // The seven the plane draws.
    let lines: Vec<u32> = fano::LINE_POINTS
        .iter()
        .map(|p| triangle(usize::from(p[0]), usize::from(p[1]), usize::from(p[2])))
        .collect();
    let lit = rank(lines);
    let dark = cycle_dim - lit;

    println!(
        "K₇ cycle space: {cycle_dim} dimensions from {} triangles; the Fano plane's 7 lines span {lit}; \
         dark = {dark}",
        all.len()
    );
    assert_eq!(
        (cycle_dim, lit, dark),
        (15, 7, 8),
        "the instrument-set arithmetic moved. `line_holonomies` reads the lit part; if `lit` fell, the \
         seven lines are dependent and the reading is narrower than its doc claims, and if `dark` fell, \
         more of the cell's loop structure is nameable by the geometry than the doc says"
    );
}

/// **A rank-one shared structure is never frustrated** — which is why the stratum's exculpation is true
/// there, and why a census built on one shared mode can only ever read zero (#221).
///
/// With a single common factor every coupling is `c_ij = s_i·s_j·|c|`, so a triple's product is
/// `(s_i s_j s_k)²·|c|³` — non-negative for **every** sign assignment. This is T-318's "balanced ⟺ pure
/// gauge" in the one case FANOS can check without leaving arithmetic, and it is worth pinning because it
/// cost three attempts at a census: a generator with one signed shared mode cannot produce a frustrated
/// cell at all, so its `0 %` was a statement about the fixture.
#[test]
fn one_shared_mode_can_never_frustrate_a_loop_whatever_the_signs() {
    for pattern in 0u8..128 {
        let signs: Vec<f64> = (0..N)
            .map(|i| if pattern & (1 << i) == 0 { 1.0 } else { -1.0 })
            .collect();
        let mut c = vec![0.0; N * N];
        for i in 0..N {
            c[i * N + i] = 1.0;
            for j in (i + 1)..N {
                let v = signs[i] * signs[j] * 0.4;
                c[i * N + j] = v;
                c[j * N + i] = v;
            }
        }
        let Some(g) = CoherenceMatrix::from_correlation(c, N) else {
            continue; // not every sign pattern at this magnitude is a reachable state
        };
        assert_eq!(
            g.frustrated_lines(),
            0,
            "sign pattern {pattern:07b} frustrated a line, which a rank-one structure cannot do — the \
             product around any triple is a perfect square times |c|³"
        );
    }
}
