//! Polar rates and the fourteen free consistency alarms (spec §6.2, corpus T-226).
//!
//! On a Fano-wired cell the 21 pairwise decoherence/error rates are **not free**: they
//! collapse to 7 values indexed by the polar point (the mediator), so within each of the 7
//! polar classes the 3 rates coincide — **14 parameter-free linear identities**. This module
//! provides the polar partition, the forward rate model `r_ij = ρ_{π(i,j)}` with
//! `ρ_k = (G − T_k)/6`, its closed-form inverse (line tomography), and the sum-rule checker
//! that turns the identities into a free structural-anomaly detector.

// Dense fixed-size (7-node) numerical kernel: array indices are all bounded by the Fano
// enumeration 0..7, so slice indexing is safe by construction, and `(i,j)` matrix fills read
// most clearly as index loops.
#![allow(clippy::indexing_slicing, clippy::needless_range_loop)]

use alloc::vec::Vec;

use fanos_geometry::fano;

/// Number of nodes / lines / polar classes in a Fano cell.
pub const N: usize = 7;

/// The polar class of point `k`: the three pairs that complete the three lines through `k`
/// (spec §6.2). Every such pair has `k` as its mediator, and the seven classes partition all
/// 21 pairs.
#[must_use]
pub fn polar_class(k: usize) -> [(usize, usize); 3] {
    let mut out = [(0usize, 0usize); 3];
    let lines = fano::POINT_LINES[k];
    for (slot, &l) in out.iter_mut().zip(lines.iter()) {
        let pts = fano::LINE_POINTS[l as usize];
        // The two points of the line other than k.
        let mut others = [0usize; 2];
        let mut idx = 0;
        for &p in &pts {
            if p as usize != k {
                others[idx] = p as usize;
                idx += 1;
            }
        }
        *slot = (others[0], others[1]);
    }
    out
}

/// The forward polar rate model: from 7 per-line rates `γ`, produce the 21 pairwise rates
/// `r_ij = ρ_{π(i,j)}`, `ρ_k = (G − T_k)/6`, `T_k = Σ_{ℓ∋k} γ_ℓ`, `G = Σ γ` (corpus T-226).
/// Returned as a symmetric `7×7` matrix with zero diagonal.
#[must_use]
pub fn line_rates_to_pair_rates(gamma: [f64; N]) -> [[f64; N]; N] {
    let g: f64 = gamma.iter().sum();
    let mut t = [0.0f64; N];
    for (k, tk) in t.iter_mut().enumerate() {
        for &l in &fano::POINT_LINES[k] {
            *tk += gamma[l as usize];
        }
    }
    let rho = |k: usize| (g - t[k]) / 6.0;
    let mut r = [[0.0f64; N]; N];
    for i in 0..N {
        for j in 0..N {
            if i != j
                && let Some(k) = fano::mediator(i, j)
            {
                r[i][j] = rho(k);
            }
        }
    }
    r
}

/// Line tomography (spec §6.2(iii), corpus T-226): recover the 7 line rates `γ` from the 7
/// polar values `ρ`, in closed form `γ_p = 3(½ Σ_k ρ_k − Σ_{k∈ℓ_p} ρ_k)`.
#[must_use]
pub fn polar_values_to_line_rates(rho: [f64; N]) -> [f64; N] {
    let half_sum: f64 = 0.5 * rho.iter().sum::<f64>();
    let mut gamma = [0.0f64; N];
    for (p, gp) in gamma.iter_mut().enumerate() {
        let line_sum: f64 = fano::LINE_POINTS[p].iter().map(|&k| rho[k as usize]).sum();
        *gp = 3.0 * (half_sum - line_sum);
    }
    gamma
}

/// The seven polar values `ρ_k` extracted from a pairwise-rate matrix (one representative
/// rate per class). Used to run tomography backwards from measured rates.
#[must_use]
pub fn polar_values(rates: &[[f64; N]; N]) -> [f64; N] {
    let mut rho = [0.0f64; N];
    for (k, slot) in rho.iter_mut().enumerate() {
        let (a, b) = polar_class(k)[0];
        *slot = rates[a][b];
    }
    rho
}

/// The honest polar-class cross-attestation node `k` gossips (spec §6.4): the 3 rates for the 3
/// channels `k` mediates (`polar_class(k)`), derived from a cell-wide liveness snapshot
/// `degraded` (bit `p` set ⇔ Fano point `p` currently reads down) via the T-226 forward rate
/// model — each line's rate `γ_l` is its count of degraded points, and
/// [`line_rates_to_pair_rates`] turns that into the pairwise matrix (spec §6.2).
///
/// Because `ρ_k = (G − T_k)/6` depends only on the mediator `k`, never on which of its 3 pairs is
/// asked, **the 3 returned values are always mutually equal, for every possible `degraded`
/// pattern** (see `mediator_attestation_is_always_internally_consistent` below) — an
/// honestly-reporting mediator's own class can therefore never look inconsistent, however many
/// cell members are simultaneously down. This is what makes the live wiring
/// (`fanos_runtime::overlay::OverlayNode`) safe against ordinary crash/churn: only a node that
/// deviates from this formula when it actually gossips — an equivocator — can produce a class
/// whose 3 attested values disagree, and [`violated_classes`] then catches exactly that (spec
/// §6.4: "an equivocating node produces inconsistencies on all q+1 of its lines at once").
#[must_use]
pub fn mediator_attestation(k: usize, degraded: u8) -> [f64; 3] {
    let mut gamma = [0.0f64; N];
    for (l, rate) in gamma.iter_mut().enumerate() {
        *rate = (degraded & fano::INCIDENCE[l]).count_ones() as f64;
    }
    let matrix = line_rates_to_pair_rates(gamma);
    let mut out = [0.0f64; 3];
    for (slot, (a, b)) in out.iter_mut().zip(polar_class(k)) {
        *slot = matrix[a][b];
    }
    out
}

/// Check the fourteen polar equalities against a measured `7×7` rate matrix. Returns the list
/// of polar points `k` whose class violates the identity beyond `tol` — an empty list means
/// the wiring is a clean Fano plane (spec §6.2 selector T-226(vi)).
#[must_use]
pub fn violated_classes(rates: &[[f64; N]; N], tol: f64) -> Vec<usize> {
    let mut violated = Vec::new();
    for k in 0..N {
        let [(a, b), (c, d), (e, f)] = polar_class(k);
        let (r0, r1, r2) = (rates[a][b], rates[c][d], rates[e][f]);
        // A non-finite rate is a violation, not a pass: `(NaN − r).abs() > tol` is false, so an
        // unguarded check would let a Byzantine node reporting NaN/±∞ rates satisfy every polar
        // identity and evade detection. The organism treats a non-finite observable as inconsistent.
        if !r0.is_finite()
            || !r1.is_finite()
            || !r2.is_finite()
            || (r0 - r1).abs() > tol
            || (r0 - r2).abs() > tol
        {
            violated.push(k);
        }
    }
    violated
}

/// Whether all fourteen polar sum-rules hold (no violated class).
#[must_use]
pub fn sum_rules_hold(rates: &[[f64; N]; N], tol: f64) -> bool {
    violated_classes(rates, tol).is_empty()
}

/// A node's full **polar vector** `ρ` — its opinion of all 7 polar values — from its own liveness view
/// `degraded` (bit `p` set ⇔ point `p` reads down), via the T-226 forward model: each line's rate `γ_ℓ` is
/// its count of degraded points, and `ρ_k = (G − T_k)/6` with `G = Σγ`, `T_k = Σ_{ℓ∋k} γ_ℓ`. This is the
/// per-class value the [`mediator_attestation`] returns three (equal) copies of; here the whole vector, so
/// a node's opinion of a class it is an ENDPOINT of (not just the one it mediates) is available for the
/// §6.4 endpoint cross-attestation.
#[must_use]
pub fn rho_vector_from_degraded(degraded: u8) -> [f64; N] {
    let mut gamma = [0.0f64; N];
    for (l, g) in gamma.iter_mut().enumerate() {
        *g = f64::from((degraded & fano::INCIDENCE[l]).count_ones());
    }
    let total: f64 = gamma.iter().sum();
    core::array::from_fn(|k| {
        let t_k: f64 = fano::POINT_LINES[k]
            .iter()
            .map(|&l| gamma[l as usize])
            .sum();
        (total - t_k) / 6.0
    })
}

/// The **§6.4 endpoint cross-attestation closure**: catch a *consistent* liar — a Byzantine node whose
/// self-report is internally consistent (so [`violated_classes`] passes it) but uniformly FALSE.
///
/// `reports[w]` is witness `w`'s polar vector [`rho_vector_from_degraded`] reconstructed from the liveness
/// view `w` gossiped, or `None` if `w` has not gossiped a fresh view (ABSENT — excluded from both the vote
/// and any verdict, so a silent node is never mistaken for a liar). For each polar class `k`, the value
/// `ρ_k` is a single global scalar that EVERY node computes; the mediator `k` and both endpoints of each of
/// `k`'s channels are independent witnesses of it. So we majority-vote the present opinions of `ρ_k`: if a
/// stable majority of at least `min_agree` witnesses agree on a value (within `tol`), that is the truth —
/// the honest supermajority who share the corroborated liveness view — and any PRESENT witness deviating
/// from it (or reporting a non-finite value) is Byzantine on class `k`. If NO such majority exists (a churn
/// transient where honest views have not yet converged, or too few have reported), the class yields no
/// verdict — churn-safe. A node flagged on any class it witnesses is returned.
///
/// **Soundness.** With `min_agree = ⌈(N+1)/2⌉ = 4` on the Fano cell, the check tolerates up to 3 Byzantine
/// nodes: the ≥4 honest witnesses form the majority and fix `ρ_k` to the truth, so a liar's fabricated `ρ_k`
/// (whether it lies "consistently" or not — the vector format admits no per-channel equivocation) is
/// outvoted and caught. This complements the mediator model (which catches an equivocator via within-class
/// inconsistency) with the consistent-liar case it structurally cannot see.
#[must_use]
pub fn byzantine_by_endpoint_majority(
    reports: &[Option<[f64; N]>; N],
    tol: f64,
    min_agree: usize,
) -> Vec<usize> {
    let mut flagged = [false; N];
    for k in 0..N {
        let opinions: [Option<f64>; N] = core::array::from_fn(|w| reports[w].map(|r| r[k]));
        // The truth is a value at least `min_agree` PRESENT, finite opinions share within `tol`.
        let truth = opinions.iter().flatten().copied().find(|&v| {
            v.is_finite()
                && opinions
                    .iter()
                    .flatten()
                    .filter(|&&x| x.is_finite() && (x - v).abs() <= tol)
                    .count()
                    >= min_agree
        });
        if let Some(truth) = truth {
            for (w, op) in opinions.iter().enumerate() {
                // Only a node that ACTUALLY reported can be flagged; an absent witness is never a liar.
                if let Some(op) = op
                    && (!op.is_finite() || (op - truth).abs() > tol)
                {
                    flagged[w] = true;
                }
            }
        }
    }
    (0..N).filter(|&w| flagged[w]).collect()
}

/// The **§6.4 endpoint cross-attestation, live form** — the directional fabrication detector the simulator
/// research found and pinned (`fanos-sim/tests/endpoint_attestation_research.rs`). It supersedes
/// [`byzantine_by_endpoint_majority`] for *live* wiring: that one majority-votes the symmetric polar vector
/// `ρ`, which is only sound when every honest node shares one corroborated liveness view — and the naive live
/// reconstruction of `ρ` from raw gossip **false-positives**, because honest nodes have ASYMMETRIC direct
/// views (a lost ping / cut link) and `ρ` collapses two very different claims into one magnitude.
///
/// This detector keeps the two claims apart, which is what makes it sound on live, asymmetric data:
///   - **VOUCH** (bit `p` set ⇔ witness gossips point `p` *fresh*, `age < τ`) is a *positive, checkable*
///     assertion — a node's reported age is monotone between real `Pong`s (`OverlayNode::health_view` reads
///     `peers[p].last_seen`), so an honest node **cannot fabricate freshness** for a node it did not hear from.
///   - **DENY** (bit clear ⇔ stale / unseen) is the *absence* of an assertion — honest under any lost ping or
///     cut link, and already inert (every node trusts its own direct observation over gossip).
///
/// So only a **VOUCH a firm consensus denies** is a soundly-attributable lie. Given a window of gossip rounds
/// (`rounds[r][w] = Some(fresh_mask)` for witness `w`, or `None` if `w` was absent that round), a witness `w`
/// is a fabricator iff there is some subject `k ≠ w` that, **persistently across the whole window**, `w`
/// vouches fresh while a **firm consensus** — at least `min_stale_consensus` of the *other* present witnesses
/// (excluding `k`'s own self-vouch) — reports stale. Persistence filters churn transients (an honest lost-ping
/// recovers within a heartbeat and cannot hold a fake-fresh age); firmness tolerates colluders.
///
/// **Why it catches what the plain quorum cannot.** The corroboration quorum (`Config::corroboration_quorum`)
/// merely *counts* vouchers, so `quorum` colluding liars keep a dead node believed-alive. This cross-checks the
/// vouch against the firm *direction* of the honest consensus, so any minority of fabricators is caught however
/// they collude. With `min_stale_consensus = ⌈(N−1)/2⌉ = 3` on the Fano cell it tolerates up to 3 colluders:
/// the `6 − f` honest witnesses (of the 6 non-subject nodes) still reach 3 stale for `f ≤ 3`, fixing the truth.
/// The dual attack — denying a *live* node — is (soundly) never flagged: it is indistinguishable from honest
/// link failure, so acting on it would quarantine honest nodes, which must never ship.
///
/// `subjects` restricts which points are adjudicated (bit `k` set ⇔ class `k` is examined). A vouch and an
/// honest lone-observation of a node are *identical* at the gossip layer, so the caller passes only the
/// subjects it cannot itself directly confirm alive (`!own_fresh_mask` in the live wiring): "only
/// cross-examine testimony about nodes you can't see yourself." This closes the sole honest false-positive —
/// a node uniquely reachable to one honest witness — without weakening detection, since a truly dead node is
/// exactly one the honest judge cannot reach. Pass `0x7F` to adjudicate every class.
#[must_use]
pub fn fabricators_by_persistent_freshness(
    rounds: &[[Option<u8>; N]],
    min_stale_consensus: usize,
    subjects: u8,
) -> Vec<usize> {
    let mut flagged = Vec::new();
    if rounds.is_empty() {
        return flagged;
    }
    for w in 0..N {
        let caught = (0..N)
            .filter(|&k| k != w && subjects & (1u8 << k) != 0)
            .any(|k| {
                rounds.iter().all(|round| {
                    // `w` must be present and persistently VOUCH `k` fresh.
                    let Some(mask) = round[w] else {
                        return false;
                    };
                    if mask & (1u8 << k) == 0 {
                        return false;
                    }
                    // …while a firm consensus of the OTHER present witnesses (never `k` itself) reports `k` stale.
                    let stale = (0..N)
                        .filter(|&v| v != w && v != k)
                        .filter(|&v| round[v].is_some_and(|m| m & (1u8 << k) == 0))
                        .count();
                    stale >= min_stale_consensus
                })
            });
        if caught {
            flagged.push(w);
        }
    }
    flagged
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn violated_classes_flags_non_finite_rates() {
        // A uniform rate matrix satisfies every polar identity — no violations.
        let uniform = [[1.0f64; N]; N];
        assert!(violated_classes(&uniform, 1e-9).is_empty());
        // A single NaN rate must be reported as a violation, not silently satisfy the identity: an
        // unguarded (NaN − r).abs() > tol is false, which would let a Byzantine node evade the check
        // by reporting non-finite rates (D3).
        let mut poisoned = uniform;
        let (a, b) = polar_class(0)[0];
        poisoned[a][b] = f64::NAN;
        assert!(violated_classes(&poisoned, 1e-9).contains(&0));
        // ±∞ likewise.
        let mut inf = uniform;
        let (c, d) = polar_class(3)[0];
        inf[c][d] = f64::INFINITY;
        assert!(violated_classes(&inf, 1e-9).contains(&3));
    }

    #[test]
    fn polar_classes_partition_all_21_pairs() {
        use std::collections::HashSet;
        let mut pairs = HashSet::new();
        for k in 0..N {
            for (a, b) in polar_class(k) {
                let key = if a < b { (a, b) } else { (b, a) };
                assert!(pairs.insert(key), "pair {key:?} appears in two classes");
                // k is the mediator of the pair.
                assert_eq!(fano::mediator(a, b), Some(k));
            }
        }
        assert_eq!(pairs.len(), 21);
    }

    #[test]
    fn forward_model_satisfies_sum_rules() {
        // For any line rates, the produced pairwise rates satisfy the 14 identities.
        for seed in 0..20u32 {
            let gamma = std::array::from_fn(|i| ((seed * 7 + i as u32 * 3) % 11) as f64 + 0.5);
            let rates = line_rates_to_pair_rates(gamma);
            assert!(sum_rules_hold(&rates, 1e-9), "seed {seed}");
        }
    }

    #[test]
    fn tomography_round_trips() {
        // γ → (G,T,ρ) → γ recovers the line rates exactly (spec §6.2(iii)).
        let gamma = [1.0, 2.0, 3.5, 0.5, 4.0, 2.5, 1.5];
        let rates = line_rates_to_pair_rates(gamma);
        let rho = polar_values(&rates);
        let back = polar_values_to_line_rates(rho);
        for i in 0..N {
            assert!((gamma[i] - back[i]).abs() < 1e-9, "γ[{i}] mismatch");
        }
    }

    #[test]
    fn mediator_attestation_is_always_internally_consistent() {
        // The load-bearing false-positive guard for the live wiring
        // (`fanos_runtime::overlay::OverlayNode::attested_pairwise_rates`): for EVERY liveness
        // pattern (every degraded mask, any number of simultaneous crashes), an honestly-attesting
        // mediator's own 3 reported channel rates agree — so ordinary crash/churn can never trip
        // the structural (Byzantine) check.
        for degraded in 0u8..=0x7F {
            for k in 0..N {
                let [r0, r1, r2] = mediator_attestation(k, degraded);
                assert_eq!(r0, r1, "k={k} degraded={degraded:#09b}");
                assert_eq!(r0, r2, "k={k} degraded={degraded:#09b}");
            }
        }
    }

    #[test]
    fn mediator_attestation_assembles_into_a_clean_matrix() {
        // Assembling ALL 7 nodes' honest attestations into a full matrix — as the live engine does,
        // modulo its per-mediator fallback/override mechanics — satisfies every polar sum-rule.
        for degraded in [0u8, 1, 0b0101_0001, 0x7F] {
            let mut matrix = [[0.0f64; N]; N];
            for k in 0..N {
                let rates = mediator_attestation(k, degraded);
                for ((a, b), r) in polar_class(k).into_iter().zip(rates) {
                    matrix[a][b] = r;
                    matrix[b][a] = r;
                }
            }
            assert!(sum_rules_hold(&matrix, 1e-9), "degraded={degraded:#09b}");
        }
    }

    #[test]
    fn byzantine_forge_breaks_exactly_its_polar_class() {
        // A single forged rate violates only the polar class of that pair's mediator,
        // localizing the anomaly (spec §6.2).
        let gamma = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];
        let mut rates = line_rates_to_pair_rates(gamma);
        // Corrupt the (0,1) channel; its mediator is the violated class.
        let k = fano::mediator(0, 1).unwrap();
        rates[0][1] += 5.0;
        rates[1][0] += 5.0;
        let violated = violated_classes(&rates, 1e-9);
        assert_eq!(
            violated,
            std::vec![k],
            "only the mediator's class is flagged"
        );
    }

    #[test]
    fn rho_vector_agrees_with_the_mediator_attestation_for_every_liveness_pattern() {
        // The full polar vector's k-th entry IS the (single) value the mediator of class k attests — the
        // two derivations of ρ_k must coincide for every degraded mask, so the endpoint cross-check and the
        // mediator model speak of the same quantity.
        for degraded in 0u8..=0x7F {
            let rho = rho_vector_from_degraded(degraded);
            for k in 0..N {
                let [m0, _, _] = mediator_attestation(k, degraded);
                assert!((rho[k] - m0).abs() < 1e-9, "k={k} degraded={degraded:#09b}");
            }
        }
    }

    #[test]
    fn a_consistent_liar_is_caught_by_the_endpoint_majority() {
        // §6.4 closure: an honest cell shares one liveness view, so every node's reconstructed ρ vector is
        // identical — a supermajority. A CONSISTENT liar (self-consistent reports the mediator model passes)
        // fabricates a DIFFERENT view; its ρ vector deviates and is outvoted by the honest endpoints who
        // directly witness the channels. Six honest (view D), one liar (view D'): only the liar is flagged.
        let honest = rho_vector_from_degraded(0b000_0001); // point 0 down
        let liar = rho_vector_from_degraded(0b000_0110); // a fabricated, different view
        let mut reports = [Some(honest); N];
        reports[6] = Some(liar);
        assert_eq!(
            byzantine_by_endpoint_majority(&reports, 1e-9, 4),
            std::vec![6],
            "the lone consistent liar is caught; the honest majority is untouched"
        );
    }

    #[test]
    fn three_byzantine_liars_are_all_caught_while_four_honest_hold_the_truth() {
        // The tolerance bound on the Fano cell: with min_agree = ⌈(7+1)/2⌉ = 4, the check withstands up to
        // 3 Byzantine — the 4 honest witnesses fix ρ, and all 3 liars (each a distinct fabricated view) are
        // flagged, none of the honest.
        let honest = rho_vector_from_degraded(0b000_0001);
        let mut reports = [Some(honest); N];
        reports[4] = Some(rho_vector_from_degraded(0b000_0010));
        reports[5] = Some(rho_vector_from_degraded(0b000_0100));
        reports[6] = Some(rho_vector_from_degraded(0b000_1000));
        assert_eq!(
            byzantine_by_endpoint_majority(&reports, 1e-9, 4),
            std::vec![4, 5, 6],
            "all three liars caught, the four honest hold"
        );
    }

    #[test]
    fn no_stable_majority_yields_no_verdict_churn_safe() {
        // Churn-safety: below the majority (here only 3 witnesses reported a finite view, the rest have not
        // gossiped ⇒ non-finite), NO class reaches min_agree = 4, so there is NO truth to deviate from and
        // NOBODY is flagged — a transient, unconverged view never quarantines an honest node.
        let view = rho_vector_from_degraded(0b000_0001);
        let mut reports: [Option<[f64; N]>; N] = [None; N]; // most nodes have not gossiped yet
        reports[0] = Some(view);
        reports[1] = Some(view);
        reports[2] = Some(view); // only 3 agree — one short of the majority
        assert!(
            byzantine_by_endpoint_majority(&reports, 1e-9, 4).is_empty(),
            "no stable majority ⇒ no Byzantine verdict (churn-safe); absent nodes are never flagged"
        );
    }

    /// A full-fresh 7-point mask (every point vouched), from which stale points are cleared.
    const ALL_FRESH: u8 = 0x7F;

    /// A fresh-mask that vouches every point except the given stale ones.
    fn fresh_except(stale: &[usize]) -> u8 {
        let mut m = ALL_FRESH;
        for &k in stale {
            m &= !(1u8 << k);
        }
        m
    }

    #[test]
    fn persistent_vouch_fabricators_exceeding_the_quorum_are_caught() {
        // The live §6.4 closure, matching the sim's DETECTION metric: point 6 is dead; two colluders (1, 4)
        // — one more than corroboration_quorum = 2 tolerates — persistently vouch it fresh while the honest
        // remainder reports it stale. Both colluders are caught, no honest node is.
        let honest = fresh_except(&[6]); // stale on the dead node
        let liar = ALL_FRESH; // vouches the dead node fresh
        let round: [Option<u8>; N] = core::array::from_fn(|w| match w {
            6 => None,           // the dead node gossips nothing
            1 | 4 => Some(liar), // colluding vouch-fabricators
            _ => Some(honest),
        });
        let rounds = [round; 5];
        assert_eq!(
            fabricators_by_persistent_freshness(&rounds, 3, 0x7F),
            std::vec![1, 4],
            "exactly the two persistent vouch-fabricators are caught"
        );
    }

    #[test]
    fn a_transient_vouch_is_not_a_fabrication_churn_safe() {
        // The FALSE-POSITIVE guard, matching the sim's zero-FP metric: an honest node that vouches a
        // just-crashed node fresh for ONE round (before its own age crosses τ) is NOT flagged — the
        // persistence requirement filters the crash transient, so honest churn never quarantines.
        let honest_stale = fresh_except(&[6]);
        let honest_lagging = ALL_FRESH; // node 2 hasn't yet staled on 6 in the first round
        let first: [Option<u8>; N] = core::array::from_fn(|w| match w {
            6 => None,
            2 => Some(honest_lagging), // transiently still fresh on 6
            _ => Some(honest_stale),
        });
        // In every later round node 2 has caught up (its age crossed τ), so it no longer vouches 6.
        let settled: [Option<u8>; N] =
            core::array::from_fn(|w| if w == 6 { None } else { Some(honest_stale) });
        let rounds = [first, settled, settled, settled, settled];
        assert!(
            fabricators_by_persistent_freshness(&rounds, 3, 0x7F).is_empty(),
            "a one-round transient vouch is not persistent ⇒ no fabrication verdict"
        );
    }

    #[test]
    fn an_honestly_dead_node_flags_nobody() {
        // A genuine death with everyone honest: all present nodes report 6 stale, nobody vouches it — so
        // there is no VOUCH-vs-firm-STALE contradiction and nobody is flagged. A real crash is not a lie.
        let honest = fresh_except(&[6]);
        let round: [Option<u8>; N] =
            core::array::from_fn(|w| if w == 6 { None } else { Some(honest) });
        let rounds = [round; 5];
        assert!(
            fabricators_by_persistent_freshness(&rounds, 3, 0x7F).is_empty(),
            "an honestly-reported death is not a fabrication"
        );
    }

    #[test]
    fn deny_liars_are_never_flagged_soundness() {
        // The DIRECTIONALITY guard, matching the sim's abstention metric: colluders (1, 4) DENY a fully-live
        // node 6 (everyone else vouches it fresh). Denying is honest-omission-shaped — indistinguishable from
        // a cut link — so the detector must abstain; flagging here would quarantine honest nodes.
        let honest = ALL_FRESH; // vouches everyone, incl. the live node 6
        let denier = fresh_except(&[6]); // falsely denies 6
        let round: [Option<u8>; N] = core::array::from_fn(|w| match w {
            1 | 4 => Some(denier),
            _ => Some(honest),
        });
        let rounds = [round; 5];
        assert!(
            fabricators_by_persistent_freshness(&rounds, 3, 0x7F).is_empty(),
            "denying a live node is not a soundly-attributable lie ⇒ never flagged"
        );
    }

    #[test]
    fn tolerates_three_colluding_fabricators_at_the_boundary() {
        // The tolerance boundary: with min_stale_consensus = ⌈(N−1)/2⌉ = 3, three colluders (1, 3, 5) vouching
        // the dead node 6 are still all caught — the three honest witnesses (0, 2, 4) reach the firm-stale
        // threshold and fix the truth.
        let honest = fresh_except(&[6]);
        let liar = ALL_FRESH;
        let round: [Option<u8>; N] = core::array::from_fn(|w| match w {
            6 => None,
            1 | 3 | 5 => Some(liar),
            _ => Some(honest),
        });
        let rounds = [round; 5];
        assert_eq!(
            fabricators_by_persistent_freshness(&rounds, 3, 0x7F),
            std::vec![1, 3, 5],
            "all three colluders caught at the tolerance boundary"
        );
    }

    #[test]
    fn a_subject_the_judge_can_see_is_not_adjudicated() {
        // The soundness safeguard: even a textbook fabrication pattern about point 6 is IGNORED when 6 is
        // excluded from `subjects` — modelling the live judge that directly sees 6 alive (`!own_fresh_mask`
        // clears bit 6). A vouch is indistinguishable from an honest lone-observation, so the judge only
        // cross-examines nodes it cannot itself confirm; here it confirms 6, so nobody is flagged.
        let honest = fresh_except(&[6]);
        let liar = ALL_FRESH;
        let round: [Option<u8>; N] = core::array::from_fn(|w| match w {
            6 => None,
            1 | 4 => Some(liar),
            _ => Some(honest),
        });
        let rounds = [round; 5];
        let subjects = 0x7F & !(1u8 << 6); // the judge directly sees 6 ⇒ 6 is not adjudicated
        assert!(
            fabricators_by_persistent_freshness(&rounds, 3, subjects).is_empty(),
            "a subject the judge directly confirms alive is never adjudicated"
        );
        // …but with 6 in `subjects` (the judge cannot see 6), the very same data catches both colluders.
        assert_eq!(
            fabricators_by_persistent_freshness(&rounds, 3, 0x7F),
            std::vec![1, 4]
        );
    }

    #[test]
    fn an_empty_window_flags_nobody() {
        assert!(fabricators_by_persistent_freshness(&[], 3, 0x7F).is_empty());
    }
}
