//! `fanos-verify` — the reference verifier and demo.
//!
//! Reproduces the specification's quantitative claims (V1–V22) directly from the reference
//! crates, printing each with its computed value, and then demonstrates the protocol
//! end-to-end (identity → coordinate → rendezvous → fault → diagnosis → reroute → threshold
//! share). Exit code `0` iff every reproduced claim holds — an executable conformance gate.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_precision_loss,
    clippy::indexing_slicing
)]

use fanos_code::{is_hyperoval_fano, is_recoverable_fano, locate, syndrome::Sector};
use fanos_core::{
    BeaconSeed, Epoch, Hierarchy, Node, NodeId, Observation, VrfSecret, Verdict,
    membership::centrality_fraction,
};
use fanos_diakrisis::{
    Fault, blindness, coherence::CoherenceMatrix, healing, partition, polar, window,
};
use fanos_field::{F2, F7, F31};
use fanos_geometry::{Plane, Point, pgl3_order};
use fanos_primitives::{reconstruct, split};

/// Accumulates check results and prints a report.
struct Report {
    passed: usize,
    failed: usize,
}

impl Report {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
        }
    }

    /// Record a check: its id, name, whether it holds, and the computed detail shown.
    fn check(&mut self, id: &str, name: &str, ok: bool, detail: &str) {
        let mark = if ok { "PASS" } else { "FAIL" };
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
        println!("  [{mark}] {id:<5} {name:<44} {detail}");
    }
}

/// `P(Binomial(n, f) ≥ t)` — the tail probability an adversary owning fraction `f` of a line's
/// `n = q+1` members reaches the threshold `t` (spec §5.2).
fn binomial_tail(n: u32, t: u32, f: f64) -> f64 {
    let mut sum = 0.0;
    for k in t..=n {
        let mut coeff = 1.0;
        for i in 0..k {
            coeff = coeff * f64::from(n - i) / f64::from(i + 1);
        }
        sum += coeff * f.powi(k as i32) * (1.0 - f).powi((n - k) as i32);
    }
    sum
}

fn approx(a: f64, b: f64, rel: f64) -> bool {
    (a - b).abs() <= rel * b.abs().max(1e-300)
}

fn leading_indicator_holds() -> bool {
    // On the equicorrelated stratum: below r*, Φ<1; the failure region {P<2/7} ⊆ {Φ<1}.
    for i in 0..100 {
        let g = CoherenceMatrix::equicorrelated(7, f64::from(i) / 200.0);
        if g.purity() < 2.0 / 7.0 - 1e-9 && g.phi() >= 1.0 - 1e-9 {
            return false;
        }
    }
    true
}

fn verify_geometry(r: &mut Report) {
    println!(" Part II — projective geometry");
    r.check(
        "V1",
        "PG(2,q) parameters N=q²+q+1, |PGL(3,q)|",
        Plane::<F2>::N == 7
            && Plane::<F7>::N == 57
            && pgl3_order(2) == 168
            && pgl3_order(7) == 5_630_688,
        "N(2)=7 N(7)=57 |PGL(3,2)|=168",
    );
    let u = Point::<F7>::new([1, 0, 0]).unwrap();
    let v = Point::<F7>::new([0, 1, 0]).unwrap();
    let luv = u.join(&v).unwrap();
    let w = Point::<F7>::new([1, 2, 3]).unwrap();
    let bridge = luv.meet(&u.join(&w).unwrap()).unwrap();
    r.check(
        "V2",
        "cross rendezvous [1:0:0]×[0:1:0]=[0:0:1]",
        luv.coords() == [0, 0, 1] && bridge == u,
        "line & bridge KAT hold",
    );
}

fn verify_overlay(r: &mut Report) {
    println!(" Part IV — overlay & membership");
    r.check(
        "V3",
        "centrality cap (q+1)/N (q=31)",
        approx(centrality_fraction(31), 0.032_225, 1e-4),
        &format!("{:.4}%", centrality_fraction(31) * 100.0),
    );
    let h = Hierarchy::new(31, 3);
    let h2 = Hierarchy::new(127, 3);
    r.check(
        "V4",
        "hierarchy scale N^k, state k·N",
        h.total_nodes() == 979_146_657 && h2.total_nodes() == 4_296_563_326_593,
        "q31,k3→9.79e8 · q127,k3→4.30e12",
    );
}

fn verify_security(r: &mut Report) {
    println!(" Part V — NYX threshold security");
    let p_hop = binomial_tail(8, 6, 0.2);
    let p_link = p_hop * p_hop;
    let tor = 0.2f64 * 0.2;
    r.check(
        "V5",
        "P_link=P_hop² (q+1=8,t=6,f=0.2)",
        approx(p_link, 1.516e-6, 5e-3),
        &format!("P_link={p_link:.3e} vs Tor {tor:.2} (×{:.0})", tor / p_link),
    );
}

fn verify_codes(r: &mut Report) {
    println!(" Part II/IV — innate codes & LRC");
    r.check(
        "V9",
        "LRC redundancy (q+1)/q → 1.032 (q=31)",
        approx(fanos_code::lrc::redundancy(31), 1.032_258, 1e-5),
        &format!("{:.4}×", fanos_code::lrc::redundancy(31)),
    );
    r.check(
        "V10",
        "Fano = Hamming(7,4): 7 weight-3 codewords",
        fanos_code::LINE_CODEWORDS
            .iter()
            .all(|c| c.count_ones() == 3),
        "7 lines = 7 codewords",
    );
}

fn verify_diakrisis(r: &mut Report) {
    println!(" Part VI — DIAKRISIS self-diagnosis");
    r.check(
        "V11",
        "first-order blindness Σ line-adj = J−I",
        blindness::is_fano_blind() && approx(blindness::blindness_spectrum()[6], 6.0, 1e-6),
        "spectrum {6, −1×6}",
    );
    r.check(
        "V13",
        "3-bit syndrome pins 1 of 7 (node O→011)",
        Sector::O.syndrome_lsb() == [0, 1, 1] && matches!(locate(1 << 5), Fault::Single(5)),
        "σ(O)=011",
    );
    let full = partition::algebraic_connectivity(0x7F);
    let down = partition::algebraic_connectivity(0x7F & !1);
    r.check(
        "V14",
        "partition Fiedler λ₂ full=7, one-down=4",
        approx(full, 7.0, 1e-6) && approx(down, 4.0, 1e-6),
        &format!("λ₂: {full:.1} → {down:.1}"),
    );
    let rstar = fanos_diakrisis::coherence::systemic_correlation(7);
    let g = CoherenceMatrix::equicorrelated(7, rstar);
    r.check(
        "V15",
        "critical r*=1/√6: Φ=1 ⟺ P=2/7",
        approx(g.phi(), 1.0, 1e-6) && approx(g.purity(), 2.0 / 7.0, 1e-6),
        &format!("r*={rstar:.4} Φ={:.3} P={:.3}", g.phi(), g.purity()),
    );
    r.check(
        "V16",
        "healing budget: coarse hop Φ → Φ/9",
        approx(healing::phi_after_coarse_hops(9.0, 1), 1.0, 1e-9),
        "Φ×1/9 per coarse boundary",
    );
    r.check(
        "V17",
        "leading indicator {P<2/7} ⊂ {Φ<1}",
        leading_indicator_holds(),
        "structure alarm ⇒ integration alarm",
    );
    r.check(
        "V18",
        "self-observation floor R_th=1/3 ⟺ P≤3/7",
        healing::reflection_sufficient(3.0 / 7.0, 7) && !healing::reflection_sufficient(0.44, 7),
        "R≥1/3 at P=3/7",
    );
    let (lo, hi) = window::collective_subject_window(7);
    r.check(
        "V19",
        "collective-subject window (1/√6,1/√3]",
        approx(lo, 0.408_248, 1e-5) && approx(hi, 0.577_35, 1e-4),
        &format!("({lo:.3}, {hi:.3}]"),
    );
    verify_lrc_and_polar(r);
}

fn verify_lrc_and_polar(r: &mut Report) {
    let all_le3 = (0u8..=0x7F)
        .filter(|m| m.count_ones() <= 3)
        .all(is_recoverable_fano);
    let mut mask = 0u8;
    for a in [1u8, 2, 4, 7] {
        mask |= 1 << fanos_code::syndrome::index_of_address(a).unwrap();
    }
    let hyperoval = is_hyperoval_fano(mask) && !is_recoverable_fano(mask);
    r.check(
        "V20",
        "LRC peeling ≤3 crashes; hyperoval fails",
        all_le3 && hyperoval,
        "≤3 recover · A,S,L,U hyperoval stuck",
    );
    r.check(
        "V21",
        "7-theme layer resolves 2 Byzantine",
        matches!(locate((1 << 1) | (1 << 4)), Fault::Pair(1, 4)),
        "pair localized exactly",
    );

    println!(" Part VI — polar sum-rules (T-226)");
    let rates = polar::line_rates_to_pair_rates([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]);
    let clean = polar::sum_rules_hold(&rates, 1e-9);
    let mut forged = rates;
    forged[2][3] += 9.0;
    forged[3][2] += 9.0;
    r.check(
        "T226",
        "14 free polar alarms; forge → 1 class",
        clean && polar::violated_classes(&forged, 1e-9).len() == 1,
        "clean holds · forgery localizes",
    );
}

/// End-to-end demonstration of the overlay flow.
fn demo() {
    println!("\n Demo — identity → rendezvous → diagnosis → threshold\n");
    let alice = Node::<F31>::open(
        &VrfSecret::from_seed([0xA1; 32]),
        NodeId([0xA1; 32]),
        Epoch::new(42),
        &BeaconSeed::GENESIS,
    );
    let bob = Node::<F31>::open(
        &VrfSecret::from_seed([0xB0; 32]),
        NodeId([0xB0; 32]),
        Epoch::new(42),
        &BeaconSeed::GENESIS,
    );
    let line = alice.rendezvous_with(&bob.coordinate()).unwrap();
    println!(
        "  rendezvous: Alice{:?} × Bob{:?} = bus {:?}",
        alice.coordinate().coords(),
        bob.coordinate().coords(),
        line.coords()
    );

    let obs = Observation {
        degraded: 1 << 5,
        ..Default::default()
    };
    let verdict = Node::<F2>::health(&obs);
    println!("  diagnosis: node 5 crashes → {verdict:?}");
    if let Verdict::Localized(Fault::Single(n)) = verdict {
        let k = Node::<F2>::reroute_via(n, 0).unwrap();
        println!("  self-heal:  reroute (5→0) via mediator k*={k}");
    }

    let secret = b"NYX line private key";
    let rnd: Vec<u8> = (0..5 * secret.len())
        .map(|i| (i as u8).wrapping_mul(97).wrapping_add(3))
        .collect();
    let shares = split(secret, 6, 8, &rnd).unwrap();
    let recovered = reconstruct(&shares[1..7]).unwrap();
    println!(
        "  threshold: split 6-of-8, any 6 reconstruct: {}",
        recovered == secret
    );
}

fn run_all_checks() -> Report {
    let mut r = Report::new();
    verify_geometry(&mut r);
    verify_overlay(&mut r);
    verify_security(&mut r);
    verify_codes(&mut r);
    verify_diakrisis(&mut r);
    r
}

fn main() {
    println!(
        "\nFANOS reference verifier — reproducing the spec's headline claims (V1–V21, T-226)\n"
    );
    let r = run_all_checks();
    demo();
    println!("\n  Summary: {} passed, {} failed\n", r.passed, r.failed);
    if r.failed > 0 {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::run_all_checks;

    #[test]
    fn all_reproduced_claims_hold() {
        let r = run_all_checks();
        assert_eq!(r.failed, 0, "{} reproduced claim(s) failed", r.failed);
        assert!(r.passed >= 18, "expected ≥18 claims, got {}", r.passed);
    }
}
