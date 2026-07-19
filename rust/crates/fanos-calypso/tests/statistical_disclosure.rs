//! **C5 — statistical disclosure / intersection attack** (Danezis 2003, *Statistical Disclosure
//! Attacks*; Mathewson–Dingledine 2004, *Practical Traffic Analysis*). The canonical long-term
//! de-anonymization: a persistent target is observed over many epochs, and the adversary intersects
//! *which services were active* during the target's active epochs — the target's own service recurs
//! every time the target is active, while unrelated services wash out, so their difference converges
//! on the target's service.
//!
//! A subtlety specific to FANOS: the rendezvous line rotates every epoch (`rendezvous_line`, verified
//! uniform + cross-epoch-unlinkable in `entry_unlinkability.rs`). That gives *unlinkability of
//! appearances* to a passive observer — but it does **not**, by itself, stop an adversary who
//! *enumerates candidate services* and re-derives each candidate's rotating line per epoch (the line
//! derivation is public). Against that stronger adversary the real defense is **cover traffic + the
//! per-service anonymity set**: they make a service's line appear active *independently* of the target,
//! so the intersection carries no target-specific signal.
//!
//! This models the SDA estimator over the real `rendezvous_line` derivation and calibrates the two
//! regimes: with no cover and a lone target the attack recovers the service (the threat is real and the
//! model non-vacuous); with cover and a realistic co-client set it is defeated (the target's service is
//! indistinguishable from decoys). Deterministic (a fixed LCG), so the advantage is a fixed number.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use fanos_calypso::{BeaconSeed, Epoch, rendezvous_line};
use fanos_field::F7;
use fanos_geometry::{Line, Plane, Triple};

/// Lines in `PG(2,7)`.
const N_LINES: usize = Plane::<F7>::N as usize; // 57

/// A deterministic LCG (as in `early_warning.rs`) — the whole run is a pure function of the seed.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn chance(&mut self, p: f64) -> bool {
        ((self.next() >> 11) as f64) / ((1u64 << 53) as f64) < p
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The rendezvous (entry) line a service occupies at `epoch`. The beacon is held fixed across epochs
/// here (this test studies epoch rotation, not beacon unpredictability), so the line still rotates by
/// epoch exactly as in production where each epoch's beacon differs.
fn line_of(service: &[u8], epoch: u32) -> Triple {
    rendezvous_line::<F7>(
        service,
        Epoch::new(epoch.into()),
        &BeaconSeed::new([0xB7; 32]),
    )
    .coords()
}

/// Parameters of one SDA scenario.
struct Scenario {
    epochs: u32,
    /// Probability the target is active in a given epoch.
    p_active: f64,
    /// Other clients of the *same* service (the per-service anonymity set); each active with prob `q`.
    co_clients: usize,
    q: f64,
    /// Lines made active each epoch by cover + all other traffic (of `N_LINES`).
    background_active: usize,
    /// Decoy candidate services the adversary also scores.
    decoys: usize,
    seed: u64,
}

/// Run the SDA and return `(score_true, best_decoy_score, rank_of_true)`. The per-candidate score is
/// `P(candidate's line active | target active) − P(candidate's line active | target inactive)` — the
/// disclosure signal. `rank_of_true == 1` means the attack top-ranked the true service.
fn run_sda(s: &Scenario) -> (f64, f64, usize) {
    let target = b"target-service";
    let mut lcg = Lcg(s.seed);

    // Simulate the observable: per epoch, whether the target is active and which lines are active.
    let mut target_active = vec![false; s.epochs as usize];
    let mut observed: Vec<BTreeSet<Triple>> = Vec::with_capacity(s.epochs as usize);
    for e in 0..s.epochs {
        let ta = lcg.chance(s.p_active);
        target_active[e as usize] = ta;
        // The service is *used* this epoch if the target OR any co-client is active.
        let mut used = ta;
        for _ in 0..s.co_clients {
            used |= lcg.chance(s.q);
        }
        // Background: cover + all other services' traffic light up a random set of lines.
        let mut active = BTreeSet::new();
        for _ in 0..s.background_active {
            active.insert(Line::<F7>::at(lcg.below(N_LINES)).coords());
        }
        if used {
            active.insert(line_of(target, e));
        }
        observed.push(active);
    }

    // The adversary's per-candidate disclosure score.
    let score = |service: &[u8]| -> f64 {
        let (mut a_hit, mut a_tot, mut b_hit, mut b_tot) = (0u32, 0u32, 0u32, 0u32);
        for e in 0..s.epochs {
            let present = observed[e as usize].contains(&line_of(service, e));
            if target_active[e as usize] {
                a_tot += 1;
                a_hit += u32::from(present);
            } else {
                b_tot += 1;
                b_hit += u32::from(present);
            }
        }
        f64::from(a_hit) / f64::from(a_tot.max(1)) - f64::from(b_hit) / f64::from(b_tot.max(1))
    };

    let score_true = score(target);
    let mut best_decoy = f64::MIN;
    let mut rank = 1usize;
    for d in 0..s.decoys {
        let s_d = score(format!("decoy-{d}").as_bytes());
        best_decoy = best_decoy.max(s_d);
        if s_d >= score_true {
            rank += 1;
        }
    }
    (score_true, best_decoy, rank)
}

/// The threat is real (and the model non-vacuous): with no cover and the target the lone user of its
/// service, the SDA recovers the service — its disclosure score is far above every decoy, top-ranked.
#[test]
fn without_cover_or_an_anonymity_set_the_disclosure_attack_succeeds() {
    let (score_true, best_decoy, rank) = run_sda(&Scenario {
        epochs: 600,
        p_active: 0.3,
        co_clients: 0,
        q: 0.0,
        background_active: 3, // almost no cover
        decoys: 60,
        seed: 0xC5A,
    });
    eprintln!("[C5 no-defense] score_true={score_true:.3} best_decoy={best_decoy:.3} rank={rank}");
    assert_eq!(
        rank, 1,
        "the SDA must top-rank the true service when it is undefended"
    );
    assert!(
        score_true - best_decoy > 0.5,
        "the true service must stand out sharply (advantage {:.3})",
        score_true - best_decoy
    );
}

/// Cover + a realistic per-service anonymity set defeat the SDA: the target's service line is active
/// almost every epoch *regardless* of the target, so its disclosure score collapses to the decoy noise
/// floor — the adversary cannot tell it from a random service.
#[test]
fn cover_and_an_anonymity_set_defeat_the_disclosure_attack() {
    let (score_true, best_decoy, rank) = run_sda(&Scenario {
        epochs: 600,
        p_active: 0.3,
        co_clients: 8,
        q: 0.3,
        background_active: 45, // heavy cover: most of the 57 lines active each epoch
        decoys: 60,
        seed: 0xC5A,
    });
    eprintln!("[C5 defended] score_true={score_true:.3} best_decoy={best_decoy:.3} rank={rank}");
    // The target's disclosure signal is indistinguishable from the decoy noise floor: no exploitable
    // advantage, and it does not reliably top the ranking.
    assert!(
        score_true - best_decoy < 0.1,
        "cover + anonymity set must erase the disclosure signal (advantage {:.3})",
        score_true - best_decoy
    );
    assert!(
        rank > 1,
        "the true service must not be uniquely top-ranked under the defense (rank {rank})"
    );
}
