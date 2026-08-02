//! **What a rendezvous costs**, measured across plane orders rather than argued at `q = 2`.
//!
//! `meeting_lines` used to derive its meeting-point count by pigeonhole — `f + 1` points against an adversary
//! holding `f` of the plane's `n = q² + q + 1`. Since `f = ⌊(n − 1)/3⌋` that count is **linear in `n`**, and a
//! host registers at every member of every meeting line, so the work was `≈ n(q+1)/3`: a third of the network,
//! times the line width. That is the opposite of the `√n` scaling the projective plane was adopted for, and
//! nobody had ever evaluated the formula past the Fano cell where `f + 1 = 3` looks harmless.
//!
//! This file measures both bounds side by side, so the growth is a table and not a reading
//! (`docs/design-rendezvous.md §5–§6`).

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::format_push_string)]

use fanos_calypso::{BeaconSeed, Epoch};
use fanos_field::{F2, F4, F7, F8, F13, F16, F31};
use fanos_geometry::Field;
use fanos_rendezvous::{CENSORSHIP_HORIZON_EPOCHS, meeting_lines, meeting_point_count};

/// One plane, both bounds, and the host registrations each implies.
struct Row {
    q: usize,
    n: usize,
    pigeonhole: usize,
    derived: usize,
    obtained: usize,
}

fn measure<F: Field>() -> Row {
    let q = F::Q as usize;
    let n = q * q + q + 1;
    Row {
        q,
        n,
        pigeonhole: (n - 1) / 3 + 1,
        derived: meeting_point_count(q),
        obtained: meeting_lines::<F>(b"a-service-key", Epoch::new(4), &BeaconSeed::GENESIS).len(),
    }
}

fn table() -> (Vec<Row>, String) {
    let rows =
        vec![measure::<F2>(), measure::<F4>(), measure::<F7>(), measure::<F8>(), measure::<F13>(), measure::<F16>(), measure::<F31>()];
    let mut report = String::from("\n  q     n   f+1   f+1 regs   m   m regs   regs/n\n");
    for r in &rows {
        let (old, new) = (r.pigeonhole * (r.q + 1), r.derived * (r.q + 1));
        report.push_str(&format!(
            "{:3} {:5} {:5} {:10} {:3} {:8} {:8.2}\n",
            r.q,
            r.n,
            r.pigeonhole,
            old,
            r.derived,
            new,
            new as f64 / r.n as f64
        ));
    }
    (rows, report)
}

/// The bound that was shipped grows with the network: the host's registration work is a **rising fraction of
/// the whole plane**, so it scales with `n` rather than with `√n`.
///
/// Asserted on the shape, not on a measured constant — a quorum-sized rendezvous would see this ratio fall.
#[test]
fn the_pigeonhole_bound_costs_a_growing_fraction_of_the_plane() {
    let (rows, report) = table();
    println!("{report}");

    let ratios: Vec<f64> =
        rows.iter().map(|r| (r.pigeonhole * (r.q + 1)) as f64 / r.n as f64).collect();
    for w in ratios.windows(2) {
        assert!(w[1] > w[0], "expected a rising per-node cost from f+1, got {ratios:?}{report}");
    }
    let last = rows.last().unwrap();
    assert!(
        last.pigeonhole * (last.q + 1) > 4 * last.n,
        "expected the largest plane to register >4n under f+1{report}"
    );
}

/// The derived bound does **not** grow: past the crossover it is flat in `n`, so a host's rendezvous cost
/// stops tracking the size of the network.
#[test]
fn the_derived_bound_is_constant_in_the_plane_size() {
    let (rows, report) = table();
    println!("{report}");

    // Every plane must reach the count its own derivation asks for. A short walk is a silent downgrade of the
    // censorship bound — the failure `combiner_of` once had at PG(2,7), where 14 distinct combiners out of 57
    // made the requested count literally unobtainable.
    for r in &rows {
        assert_eq!(r.obtained, r.derived, "q={}: the distinct-combiner walk came up short{report}", r.q);
    }

    // Flat past the crossover: every plane from q=7 up takes the same number of meeting points.
    let past: Vec<usize> = rows.iter().filter(|r| r.q >= 7).map(|r| r.derived).collect();
    assert!(past.windows(2).all(|w| w[0] == w[1]), "expected a flat count past q=7, got {past:?}{report}");

    // And it is a real cut, not a rounding: the largest plane measured drops by more than an order of
    // magnitude against the bound it replaces.
    let last = rows.last().unwrap();
    assert!(
        last.pigeonhole > 10 * last.derived,
        "q={}: expected >10x, got {} vs {}{report}",
        last.q,
        last.pigeonhole,
        last.derived
    );
}

/// **The shipped cell is untouched.** On `PG(2,2)` the pigeonhole bound is cheaper than the probabilistic one,
/// so the minimum keeps it — and with it the *strictly stronger* guarantee that censorship is impossible
/// rather than improbable. A change to the base cell's count would be a flag day for every live party.
#[test]
fn the_fano_cell_keeps_its_deterministic_bound() {
    assert_eq!(meeting_point_count(2), 3, "the Fano cell's meeting-point count must not move");
    assert_eq!(
        meeting_lines::<F2>(b"a-service-key", Epoch::new(4), &BeaconSeed::GENESIS).len(),
        3,
        "the Fano cell's derivation must still yield 3 meeting points"
    );
    // The minimum picked the pigeonhole side here, so the guarantee is the deterministic one.
    for q in [2usize, 3, 4, 5] {
        let n = q * q + q + 1;
        assert_eq!(meeting_point_count(q), (n - 1) / 3 + 1, "q={q} should still take the deterministic bound");
    }
}

/// The integer, division-truncating solve must agree with the closed form it implements, and must err *high*
/// where it disagrees. Client and host compute this count with no channel to compare it on, so it may not
/// depend on a platform's `libm`; this pins the integer path against the real logarithm.
#[test]
fn the_integer_solve_matches_the_closed_form_and_never_undershoots() {
    #[allow(clippy::cast_precision_loss)]
    for q in [2usize, 3, 4, 5, 7, 8, 9, 11, 13, 16, 17, 19, 23, 25, 27, 29, 31, 32, 37, 64, 127] {
        let n = q * q + q + 1;
        let f = (n - 1) / 3;
        let exact = (CENSORSHIP_HORIZON_EPOCHS as f64).ln() / (n as f64 / f as f64).ln();
        let closed = (exact.ceil() as usize).min(f + 1);
        let got = meeting_point_count(q);
        assert!(
            got >= closed && got <= closed + 1,
            "q={q}: integer solve gave {got}, closed form {closed} (exact {exact:.3}) — must match or err high"
        );
    }
}

/// The bound it claims must actually hold, and its deliberate conservatism must stay small.
///
/// The derivation solves `(f/n)^m ≤ 1/H`, but the meeting points are sampled *without* replacement, so the
/// true probability is the hypergeometric `C(f,m)/C(n,m) = Π (f−j)/(n−j)`, which is strictly smaller. This
/// checks the *claim* against that exact figure rather than against the algebra that produced it — and then
/// bounds the gap, because "conservative" must not become a licence to pad.
#[test]
#[allow(clippy::cast_precision_loss)]
fn the_censorship_probability_meets_the_horizon_it_solves_for() {
    let budget = 1.0 / CENSORSHIP_HORIZON_EPOCHS as f64;
    // Exact censorship probability with `m` distinct combiners drawn from `n` points against `f` adversarial.
    let exact = |n: usize, f: usize, m: usize| -> f64 {
        (0..m).map(|j| (f - j) as f64 / (n - j) as f64).product()
    };

    for q in [7usize, 8, 9, 11, 13, 16, 31] {
        let (n, f) = (q * q + q + 1, (q * q + q) / 3);
        let m = meeting_point_count(q);
        let p = exact(n, f, m);
        assert!(
            p <= budget,
            "q={q}: {m} meeting points give censorship probability {p:.3e}, over the {budget:.3e} budget"
        );

        // The smallest count the *exact* distribution would accept. The solve may exceed it — sampling
        // without replacement is what it declines to model — but only barely, or the saving it claims is
        // being spent on padding instead.
        let tight = (1..=f + 1).find(|&k| exact(n, f, k) <= budget).unwrap_or(f + 1);
        assert!(
            m >= tight && m <= tight + 2,
            "q={q}: solve gave {m}, the exact bound needs {tight} — the conservatism is over 2 points"
        );
    }
}
