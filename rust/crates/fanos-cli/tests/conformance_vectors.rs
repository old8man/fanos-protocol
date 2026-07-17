//! The Rust reference reproduces the language-agnostic conformance vectors **exactly**. The files
//! `conformance/vectors/{algebra,diakrisis}.json` are the interop contract (README guarantees: the
//! wire is KAT-pinned and the mathematics is verifier-pinned). Rather than hard-code the expected
//! numbers, this test *parses the vectors* and re-derives every entry from the implementation — so
//! the published contract and the code cannot drift apart. Any clean-room implementation that
//! reproduces these same files interoperates with no shared code.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_cmp
)]

use fanos_code::syndrome::{Sector, index_of_address};
use fanos_core::Hierarchy;
use fanos_diakrisis::coherence::{CoherenceMatrix, systemic_correlation};
use fanos_diakrisis::regeneration::regeneration_rate;
use fanos_diakrisis::{blindness, healing, partition, window};
use fanos_field::{F2, F7, F31};
use fanos_geometry::{Plane, Point, fano, pgl3_order};
use serde_json::Value;

/// Load and parse a vector file relative to the repository root.
fn load(name: &str) -> Value {
    let path = format!(
        "{}/../../../conformance/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read conformance {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

/// Tight equality for the vectors' full-precision doubles.
fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= 1e-12 * b.abs().max(1.0)
}

fn arr3(v: &Value) -> [u32; 3] {
    let a = v.as_array().unwrap();
    [
        a[0].as_u64().unwrap() as u32,
        a[1].as_u64().unwrap() as u32,
        a[2].as_u64().unwrap() as u32,
    ]
}

#[test]
fn algebra_vectors_reproduced() {
    let v = load("algebra.json");

    // pg_parameters: N = q²+q+1 points/lines, q+1 per line, |PGL(3,q)| symmetries.
    for cell in v["pg_parameters"]["cells"].as_array().unwrap() {
        let q = u128::from(cell["q"].as_u64().unwrap());
        assert_eq!(
            q * q + q + 1,
            u128::from(cell["N"].as_u64().unwrap()),
            "N q={q}"
        );
        assert_eq!(
            q + 1,
            u128::from(cell["line_size"].as_u64().unwrap()),
            "line q={q}"
        );
        if let Some(order) = cell["pgl3_order"].as_u64() {
            assert_eq!(pgl3_order(q as u32), u128::from(order), "|PGL(3,{q})|");
        }
    }
    // Cross-check N against the concrete typed planes the code actually builds.
    assert_eq!(u128::from(Plane::<F2>::N), 7);
    assert_eq!(u128::from(Plane::<F7>::N), 57);
    assert_eq!(u128::from(Plane::<F31>::N), 993);

    // cross_product over GF(7): join = u × v, bridge = meet of two lines.
    for j in v["cross_product"]["join"].as_array().unwrap() {
        let u = Point::<F7>::new(arr3(&j["u"])).unwrap();
        let w = Point::<F7>::new(arr3(&j["v"])).unwrap();
        assert_eq!(u.join(&w).unwrap().coords(), arr3(&j["line"]), "join");
    }
    for b in v["cross_product"]["bridge"].as_array().unwrap() {
        let l1 = fanos_geometry::Line::<F7>::new(arr3(&b["l1"])).unwrap();
        let l2 = fanos_geometry::Line::<F7>::new(arr3(&b["l2"])).unwrap();
        assert_eq!(l1.meet(&l2).unwrap().coords(), arr3(&b["point"]), "bridge");
    }

    // fano: point i has these GF(2) coordinates.
    for (i, pc) in v["fano"]["point_coords"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(Point::<F2>::at(i).coords(), arr3(pc), "point_coords[{i}]");
    }
    // line_points: the three points of each line are mutual mediators (third-collinear).
    for lp in v["fano"]["line_points"].as_array().unwrap() {
        let p = lp.as_array().unwrap();
        let (a, b, c) = (
            p[0].as_u64().unwrap() as usize,
            p[1].as_u64().unwrap() as usize,
            p[2].as_u64().unwrap() as usize,
        );
        assert_eq!(fano::mediator(a, b), Some(c), "line {a},{b}→{c}");
        assert_eq!(fano::mediator(a, c), Some(b));
        assert_eq!(fano::mediator(b, c), Some(a));
    }
    for pair in v["fano"]["mediator_examples"]["pairs"].as_array().unwrap() {
        let i = pair["i"].as_u64().unwrap() as usize;
        let j = pair["j"].as_u64().unwrap() as usize;
        let m = pair["mediator"].as_u64().unwrap() as usize;
        assert_eq!(fano::mediator(i, j), Some(m), "mediator({i},{j})");
    }

    // syndrome: sector → address → LSB-first 3-bit σ.
    for row in v["syndrome"]["table"].as_array().unwrap() {
        let sector = sector_of(row["sector"].as_str().unwrap());
        let address = row["address"].as_u64().unwrap() as u8;
        assert_eq!(sector.address(), address, "address of {sector:?}");
        // Every address 1..=7 addresses some Fano point (the map is a permutation, not identity).
        assert!(
            index_of_address(address).is_some(),
            "address {address} locates a point"
        );
        let sigma: Vec<u8> = row["sigma"]
            .as_str()
            .unwrap()
            .chars()
            .map(|c| (c == '1') as u8)
            .collect();
        assert_eq!(sector.syndrome_lsb().to_vec(), sigma, "σ({sector:?})");
    }

    // hierarchy: total = N^k, per-node routing state = k·N.
    for ex in v["hierarchy"]["examples"].as_array().unwrap() {
        let q = ex["q"].as_u64().unwrap() as u32;
        let levels = ex["levels"].as_u64().unwrap() as u32;
        let h = Hierarchy::new(q, levels);
        assert_eq!(
            h.total_nodes(),
            u128::from(ex["total_nodes"].as_u64().unwrap()),
            "total q={q} k={levels}"
        );
        assert_eq!(
            h.routing_state(),
            u128::from(ex["routing_state"].as_u64().unwrap()),
            "state q={q} k={levels}"
        );
    }
}

fn sector_of(letter: &str) -> Sector {
    Sector::ALL
        .into_iter()
        .find(|s| s.label() == letter.chars().next().unwrap())
        .unwrap()
}

#[test]
fn diakrisis_vectors_reproduced() {
    let v = load("diakrisis.json");
    let n = 7usize;

    // thresholds.
    let th = &v["coherence_measures"]["thresholds"];
    assert!(
        close(2.0 / n as f64, th["p_crit_7"].as_f64().unwrap()),
        "p_crit"
    );
    assert!(close(1.0 / 3.0, th["r_th"].as_f64().unwrap()), "r_th");
    assert!(
        close(
            systemic_correlation(n),
            th["systemic_correlation_r_star_7"].as_f64().unwrap()
        ),
        "r*"
    );
    assert_eq!(th["phi_th"].as_f64().unwrap(), 1.0);
    // general form r* = 1/√(N−1) across cell sizes.
    for m in [7usize, 57, 183] {
        assert!(
            close(systemic_correlation(m), 1.0 / ((m - 1) as f64).sqrt()),
            "r*({m})"
        );
    }

    // equicorrelated closed forms at the critical point.
    let cp = &v["equicorrelated_stratum"]["critical_point"];
    let r = cp["r"].as_f64().unwrap();
    let g = CoherenceMatrix::equicorrelated(n, r);
    assert!(close(g.phi(), cp["phi"].as_f64().unwrap()), "Φ crit");
    assert!(close(g.purity(), cp["purity"].as_f64().unwrap()), "P crit");
    assert!(
        close(g.reflection(), cp["reflection"].as_f64().unwrap()),
        "R crit"
    );
    // identity Φ = N·P − 1.
    assert!(close(g.phi(), n as f64 * g.purity() - 1.0), "Φ = N·P − 1");
    // Φ = (N−1)·r² over the whole stratum.
    for i in 1..20 {
        let rr = f64::from(i) / 40.0;
        assert!(
            close(
                CoherenceMatrix::equicorrelated(n, rr).phi(),
                (n as f64 - 1.0) * rr * rr
            ),
            "Φ=(N−1)r² at r={rr}"
        );
    }

    // collective-subject window (1/√6, 1/√3].
    let win = &v["collective_subject_window"];
    let (lo, hi) = window::collective_subject_window(n);
    assert!(
        close(lo, win["lower_exclusive"].as_f64().unwrap()),
        "window lo"
    );
    assert!(
        close(hi, win["upper_inclusive"].as_f64().unwrap()),
        "window hi"
    );

    // first-order blindness spectrum {6:×1, −1:×6}.
    assert!(blindness::is_fano_blind());
    let spec = blindness::blindness_spectrum();
    let sixes = spec.iter().filter(|&&x| close(x, 6.0)).count();
    let negs = spec.iter().filter(|&&x| close(x, -1.0)).count();
    let fb = &v["first_order_blindness"]["spectrum"];
    assert_eq!(
        sixes,
        fb["6"].as_u64().unwrap() as usize,
        "eigenvalue 6 multiplicity"
    );
    assert_eq!(
        negs,
        fb["-1"].as_u64().unwrap() as usize,
        "eigenvalue −1 multiplicity"
    );

    // partition Fiedler values.
    let pf = &v["partition_fiedler"];
    assert!(close(
        partition::algebraic_connectivity(0x7F),
        pf["full_cell_lambda2"].as_f64().unwrap()
    ));
    assert!(close(
        partition::algebraic_connectivity(0x7F & !1),
        pf["one_line_down_lambda2"].as_f64().unwrap()
    ));

    // self-healing budget: coherence ×1/3 per coarse hop, Φ ×1/9; κ_bootstrap = ω₀/7.
    let sh = &v["self_healing"];
    assert!(close(
        healing::phi_after_coarse_hops(9.0, 1),
        9.0 * sh["phi_contraction_per_hop"].as_f64().unwrap()
    ));
    assert!(
        close(
            regeneration_rate(5.0, 0.0),
            sh["kappa_bootstrap"].as_f64().unwrap()
        ),
        "κ_bootstrap"
    );
    assert!(healing::reflection_sufficient(3.0 / 7.0, n));
    assert!(close(
        sh["self_observation_floor_r_th"].as_f64().unwrap(),
        1.0 / 3.0
    ));
}
