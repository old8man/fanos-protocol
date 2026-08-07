//! **The PG(2,q) parameters this crate computes are the ones `conformance/vectors/algebra.json` specifies.**
//!
//! The vector existed and nothing compared it to the code (#160). It is the cheapest of the nine to check —
//! every quantity is a closed form — and the cheapest to get silently wrong, because `N`, `LINE_SIZE` and the
//! Fano incidence table are consumed by every layer above: a cell's size, a line's membership, the erasure
//! code's stopping sets, the anonymity floor's denominator.
//!
//! The closed forms are evaluated, not transcribed. `N = q² + q + 1` and `line_size = q + 1` are the vector's
//! own stated definitions, so computing them and comparing to the listed integers pins the DEFINITION; copying
//! the integers would pin only that the same arithmetic was done twice by hand.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use fanos_field::{F2, F7};
use fanos_geometry::{Line, Plane, Point};

/// The vector, read as text — see `fanos-diakrisis/tests/conformance.rs` for why there is no JSON dependency.
fn vector() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../conformance/vectors/algebra.json");
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Every `{ "q": _, "N": _, "line_size": _ }` row of `pg_parameters.cells`, in file order.
///
/// Parsed from the text rather than with a JSON crate, and deliberately strict: a row whose shape changes
/// stops being parsed and the count assertion below fails, rather than the row quietly dropping out of the
/// check. A scan that can silently return fewer rows is a scan that can pass by finding nothing.
fn cells(text: &str) -> Vec<(u32, u32, u32)> {
    let mut out = Vec::new();
    for row in text.split("{ \"q\":").skip(1) {
        let field = |key: &str| -> Option<u32> {
            let at = row.find(&format!("\"{key}\":"))?;
            let rest = &row[at + key.len() + 3..];
            let end = rest.find([',', '}'])?;
            rest[..end].trim().parse().ok()
        };
        let Some(q) = row.split(',').next().and_then(|t| t.trim().parse::<u32>().ok()) else {
            continue;
        };
        if let (Some(n), Some(line_size)) = (field("N"), field("line_size")) {
            out.push((q, n, line_size));
        }
    }
    out
}

#[test]
fn the_pg_parameters_match_their_closed_forms_for_every_listed_order() {
    let v = vector();
    let rows = cells(&v);
    assert_eq!(rows.len(), 5, "algebra.json lists five plane orders; the scan found {}", rows.len());

    for (q, n, line_size) in rows {
        assert_eq!(n, q * q + q + 1, "q={q}: the vector says N={n}, but q²+q+1 = {}", q * q + q + 1);
        assert_eq!(line_size, q + 1, "q={q}: the vector says line_size={line_size}, but q+1 = {}", q + 1);
    }
}

#[test]
fn the_shipped_planes_agree_with_the_vectors_rows_for_their_orders() {
    let v = vector();
    let rows = cells(&v);
    let row = |q: u32| rows.iter().find(|(qq, ..)| *qq == q).copied().unwrap_or_else(|| panic!("no q={q} row"));

    // The two orders this workspace instantiates. Checking the CODE's constants, not the formula again —
    // `the_pg_parameters_match_their_closed_forms…` already pinned the formula, and a plane whose `N` drifted
    // from `q²+q+1` would pass that test while failing this one.
    let (_, n2, ls2) = row(2);
    assert_eq!(Plane::<F2>::N, n2, "Fano: the crate says N={}, the vector says {n2}", Plane::<F2>::N);
    assert_eq!(Plane::<F2>::LINE_SIZE, ls2, "Fano: line size");

    let (_, n7, ls7) = row(7);
    assert_eq!(Plane::<F7>::N, n7, "q=7: the crate says N={}, the vector says {n7}", Plane::<F7>::N);
    assert_eq!(Plane::<F7>::LINE_SIZE, ls7, "q=7: line size");
}

#[test]
fn the_fano_incidence_table_is_the_vectors_line_points() {
    let v = vector();
    // `fano.line_points[l]` — the three point indices on line `l`, self-dual so also the lines through point l.
    let at = v.find("\"line_points\":").expect("algebra.json has fano.line_points");
    let rows: Vec<Vec<usize>> = v[at..]
        .split('[')
        .skip(2) // the outer array, then the first inner one
        .take(7)
        .map(|s| {
            s.split(']')
                .next()
                .expect("a closed inner array")
                .split(',')
                .map(|t| t.trim().parse().expect("a point index"))
                .collect()
        })
        .collect();
    assert_eq!(rows.len(), 7, "the Fano plane has seven lines; the scan found {}", rows.len());

    for (l, want) in rows.iter().enumerate() {
        let mut got: Vec<usize> =
            Plane::<F2>::points_on(Line::<F2>::at(l)).map(|p| p.index()).collect();
        got.sort_unstable();
        let mut want_sorted = want.clone();
        want_sorted.sort_unstable();
        assert_eq!(
            got, want_sorted,
            "line {l}: the crate says {got:?}, the vector says {want_sorted:?}"
        );
        assert_eq!(want.len(), 3, "every Fano line holds exactly q+1 = 3 points");
    }
}

#[test]
fn the_mediator_examples_are_the_third_point_of_the_line_through_the_pair() {
    let v = vector();
    // `fano.mediator_examples.pairs`: k*(i,j) = the third point of the line through i and j.
    let at = v.find("\"pairs\":").expect("algebra.json has mediator_examples.pairs");
    let mut checked = 0usize;
    for row in v[at..].split("{ \"i\":").skip(1).take(3) {
        let field = |key: &str| -> usize {
            let a = row.find(&format!("\"{key}\":")).unwrap_or_else(|| panic!("pair has no {key}"));
            let rest = &row[a + key.len() + 3..];
            let end = rest.find([',', '}']).expect("a delimited value");
            rest[..end].trim().parse().expect("an index")
        };
        let i: usize = row.split(',').next().expect("i").trim().parse().expect("i is an index");
        let (j, mediator) = (field("j"), field("mediator"));

        let pi = Point::<F2>::at(i);
        let pj = Point::<F2>::at(j);
        let line = pi.join(&pj).expect("two distinct points determine a line");
        let third: Vec<usize> = Plane::<F2>::points_on(line)
            .map(|p| p.index())
            .filter(|&p| p != i && p != j)
            .collect();
        assert_eq!(third, vec![mediator], "the third point on the line through {i} and {j}");
        checked += 1;
    }
    assert_eq!(checked, 3, "the vector lists three mediator pairs; a scan that checked fewer proves nothing");
}
