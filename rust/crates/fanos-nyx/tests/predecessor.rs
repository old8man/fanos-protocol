//! **C — the predecessor attack** (Wright–Adler–Levine–Shields, *An Analysis of the Degradation of
//! Anonymous Protocols*, NDSS 2002; *The Predecessor Attack*, ACM TISSEC 2004). When a client
//! repeatedly builds fresh circuits toward a recurring destination, an adversary controlling a fraction
//! of relays counts, over many rounds, which node precedes its earliest on-path relay. The true
//! initiator is the predecessor of the *first* hop on **every** circuit, so if the first hop rotates it
//! recurs above chance and is identified after ~`1/f` circuits. The classic defense is a **guard**: a
//! *fixed* first hop turns "exposed with probability `f` per circuit" into "exposed once, only if the
//! adversary controls the guard."
//!
//! This models the attack against the real [`build_circuit`] and calibrates the two regimes:
//!   * **guardless** (today: every intermediate hop is drawn from the per-circuit seed, so the first
//!     hop rotates) — the initiator is identified in essentially every adversary trial;
//!   * **guarded** (a stable per-client first hop) — the initiator is exposed only in the fraction of
//!     trials where the adversary happens to control the guard (≈ `f`), independent of the round count.
//!
//! Deterministic (a fixed LCG picks the adversary set), so the exposure rates are fixed numbers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use fanos_field::F7;
use fanos_geometry::{Point, Triple};
use fanos_nyx::{GuardSet, build_circuit};

const N: usize = 57; // points/relays in PG(2,7) = Plane::<F7>::N
const HOPS: usize = 4;

/// Deterministic LCG for adversary-set selection.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The client's per-circuit seed at counter `c` (mirroring `NyxNode::originate`).
fn circuit_seed(client_seed: &[u8], c: u32) -> Vec<u8> {
    let mut s = client_seed.to_vec();
    s.extend_from_slice(&c.to_be_bytes());
    s
}

/// The **guardless** relay sequence today: `build_circuit` derives every intermediate hop from the
/// per-circuit seed, so the first hop rotates with `c`.
fn guardless_relays(client: Point<F7>, dest: Point<F7>, client_seed: &[u8], c: u32) -> Vec<Triple> {
    build_circuit::<F7>(client, dest, HOPS, &circuit_seed(client_seed, c))
        .expect("circuit")
        .relays()
        .iter()
        .map(Point::coords)
        .collect()
}

/// A stable per-client **guard** — a first hop derived from the client seed *without* the circuit
/// counter, so it is the same on every circuit.
fn guard_of(client: Point<F7>, dest: Point<F7>, client_seed: &[u8]) -> Point<F7> {
    let mut s = client_seed.to_vec();
    s.extend_from_slice(b"/guard");
    build_circuit::<F7>(client, dest, 2, &s)
        .expect("guard circuit")
        .relays()[1]
}

/// The **guarded** relay sequence: the first hop is the stable guard; the remainder is derived per
/// circuit from the guard onward.
fn guarded_relays(client: Point<F7>, dest: Point<F7>, client_seed: &[u8], c: u32) -> Vec<Triple> {
    let guard = guard_of(client, dest, client_seed);
    let mut relays = vec![client.coords()];
    for p in build_circuit::<F7>(guard, dest, HOPS - 1, &circuit_seed(client_seed, c))
        .expect("sub-circuit")
        .relays()
    {
        relays.push(p.coords());
    }
    relays
}

/// Run the predecessor attack over `rounds` circuits produced by `route`, with the adversary
/// controlling `adversary`. Returns `true` if the true initiator (`client`) is the unique
/// most-frequent predecessor of the adversary's earliest on-path relay — i.e. identified.
fn initiator_is_identified(
    client: Triple,
    rounds: u32,
    adversary: &std::collections::BTreeSet<Triple>,
    mut route: impl FnMut(u32) -> Vec<Triple>,
) -> bool {
    let mut count: BTreeMap<Triple, u32> = BTreeMap::new();
    for c in 0..rounds {
        let relays = route(c);
        // The adversary's earliest on-path relay is at position ≥1; it observes its predecessor.
        if let Some(p) = (1..relays.len()).find(|&p| adversary.contains(&relays[p])) {
            *count.entry(relays[p - 1]).or_insert(0) += 1;
        }
    }
    // Identified iff the client is the unique argmax of the predecessor tally.
    let client_count = count.get(&client).copied().unwrap_or(0);
    client_count > 0 && count.iter().all(|(&n, &v)| n == client || v < client_count)
}

/// Build a random adversary set of `size` relays (never the client).
fn adversary_set(lcg: &mut Lcg, size: usize, client: Triple) -> std::collections::BTreeSet<Triple> {
    let mut set = std::collections::BTreeSet::new();
    while set.len() < size {
        let p = Point::<F7>::at(lcg.below(N)).coords();
        if p != client {
            set.insert(p);
        }
    }
    set
}

/// Over many adversary trials, the fraction in which the initiator is identified.
fn exposure_rate(guarded: bool, f: f64, trials: u32, rounds: u32, seed: u64) -> f64 {
    let client = Point::<F7>::at(0);
    let dest = Point::<F7>::at(30);
    let client_seed = b"initiator-secret-seed";
    let size = ((N as f64) * f) as usize;

    let mut lcg = Lcg(seed);
    let mut exposed = 0u32;
    for _ in 0..trials {
        let adv = adversary_set(&mut lcg, size, client.coords());
        let identified = initiator_is_identified(client.coords(), rounds, &adv, |c| {
            if guarded {
                guarded_relays(client, dest, client_seed, c)
            } else {
                guardless_relays(client, dest, client_seed, c)
            }
        });
        exposed += u32::from(identified);
    }
    f64::from(exposed) / f64::from(trials)
}

/// Exposure with the slowly-rotating **guard set** (`GuardSet`) as the entry policy: the circuit enters
/// through the highest-priority reachable guard. `primary_down` marks the primary unreachable, so the
/// entry falls back to a stable backup — the availability-under-churn case.
fn guard_set_exposure_rate(primary_down: bool, f: f64, trials: u32, rounds: u32, seed: u64) -> f64 {
    let client = Point::<F7>::at(0);
    let dest = Point::<F7>::at(30);
    let client_seed = b"initiator-secret-seed";
    let size = ((N as f64) * f) as usize;
    // One stable guard set (slow rotation: a long period, so it never re-draws over these rounds).
    let set = GuardSet::<F7>::derive(client_seed, 0, 1000, 3, client);
    let primary = set.primary().expect("guard set non-empty");

    let mut lcg = Lcg(seed);
    let mut exposed = 0u32;
    for _ in 0..trials {
        let adv = adversary_set(&mut lcg, size, client.coords());
        let identified = initiator_is_identified(client.coords(), rounds, &adv, |c| {
            set.build_circuit(client, dest, HOPS, &circuit_seed(client_seed, c), |g| {
                !(primary_down && g == primary)
            })
            .expect("guard-set circuit")
            .relays()
            .iter()
            .map(Point::coords)
            .collect()
        });
        exposed += u32::from(identified);
    }
    f64::from(exposed) / f64::from(trials)
}

/// The threat is real: without guards the rotating first hop lets the predecessor attack identify the
/// initiator in essentially every adversary trial — exposure does not depend on how few relays the
/// adversary holds, only on running enough rounds.
#[test]
fn without_guards_the_predecessor_attack_identifies_the_initiator() {
    let rate = exposure_rate(false, 0.2, 40, 300, 0x9E37);
    eprintln!("[predecessor] guardless exposure rate = {rate:.3}");
    assert!(
        rate > 0.9,
        "a rotating first hop must leave the initiator identifiable (exposure {rate:.3})"
    );
}

/// The guard is what makes that work: a fixed first hop across every circuit, while the interior still
/// rotates per circuit (so only the entry is pinned, not the whole path).
#[test]
fn the_guard_pins_a_stable_first_hop_while_the_interior_rotates() {
    let client = Point::<F7>::at(0);
    let dest = Point::<F7>::at(30);
    let seed = b"initiator-secret-seed";
    let first_hops: std::collections::BTreeSet<Triple> = (0..20)
        .map(|c| guarded_relays(client, dest, seed, c)[1])
        .collect();
    assert_eq!(
        first_hops.len(),
        1,
        "the guard is the same first hop on every circuit"
    );
    let interior: std::collections::BTreeSet<Triple> = (0..20)
        .map(|c| guarded_relays(client, dest, seed, c)[2])
        .collect();
    assert!(
        interior.len() > 1,
        "the interior hops still rotate per circuit (only the entry is pinned)"
    );
}

/// A stable guard bounds it: the initiator is exposed only in the fraction of trials where the
/// adversary controls the guard (≈ f), independent of the round count — the classic guard guarantee.
#[test]
fn a_stable_guard_bounds_predecessor_exposure_to_guard_compromise() {
    let f = 0.2;
    let rate = exposure_rate(true, f, 40, 300, 0x9E37);
    eprintln!("[predecessor] guarded exposure rate = {rate:.3}  (f = {f})");
    assert!(
        rate < 0.4,
        "a stable guard must bound exposure to ~f (got {rate:.3}), not the guardless ~1.0"
    );
}

/// A guard **set** used primary-first is no worse than a single guard: because the primary carries every
/// circuit while it is up, exposure stays ≈ `f` — it does **not** grow to the union bound
/// `1 − (1−f)^k ≈ 0.49` a naive "any of k guards" set would suffer.
#[test]
fn a_primary_first_guard_set_keeps_single_guard_exposure_not_the_union_bound() {
    let f = 0.2;
    let single = exposure_rate(true, f, 40, 300, 0x9E37);
    let set = guard_set_exposure_rate(false, f, 40, 300, 0x9E37);
    let union_bound = 1.0 - (1.0 - f).powi(3);
    eprintln!(
        "[predecessor] single-guard={single:.3}  guard-set={set:.3}  (union bound ≈ {union_bound:.3})"
    );
    assert!(
        set < 0.4,
        "a primary-first guard set stays in the ≈f regime (got {set:.3}), well below the union bound {union_bound:.3}"
    );
    assert!(
        (set - single).abs() < 0.2,
        "the guard set tracks the single-guard rate (set {set:.3} vs single {single:.3}), not the union bound"
    );
}

/// The set's payoff over a single guard is **availability**: when the primary goes down the entry falls to
/// a *stable* backup, so the predecessor bound survives guard churn — unlike a per-circuit re-pick, which
/// would rotate the entry back to the guardless ≈1.
#[test]
fn a_guard_set_survives_primary_churn_without_reopening_the_attack() {
    let f = 0.2;
    let churned = guard_set_exposure_rate(true, f, 40, 300, 0x9E37);
    let guardless = exposure_rate(false, f, 40, 300, 0x9E37);
    eprintln!("[predecessor] guard-set(primary down)={churned:.3}  guardless={guardless:.3}");
    assert!(
        churned < 0.4,
        "with the primary down the entry must stay pinned to a stable backup (exposure {churned:.3})"
    );
    assert!(
        churned < guardless - 0.4,
        "the churn-resilient set ({churned:.3}) stays far below the guardless rate ({guardless:.3})"
    );
}
