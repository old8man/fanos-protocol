//! Beacon leader election and line-committee selection (spec §10.1, `docs/design-taxis.md` §3).
//!
//! Leadership and the anti-MEV sealing committee are chosen from the **epoch beacon**, which is unbiasable
//! by construction (the pairing-free threshold-DVRF, §L3). Two structural consequences the spec sells fall
//! out for free:
//!
//! * **Unpredictable** — a proposer for a future `(height, round)` cannot be pre-computed until the epoch's
//!   `SEED` is revealed, so an adversary cannot pre-aim to lead a chosen height (the anti-grinding property
//!   of coordinate assignment, §8.4).
//! * **Cartel-proof** — leadership rotates over **lines** (committees); by the plane's point-regularity a
//!   validator sits on exactly `q + 1` of the `n` lines, so its share of leadership is the structural
//!   centrality cap `(q+1)/n` — a bound no coalition can buy (§8.4 "supernode capture"). For the Fano cell
//!   that is `3/7` chance of being *in* the elected committee, and `1/7` of leading, per round.
//!
//! This module is concrete to the base **Fano cell** (`q = 2`, `n = 7`), where the whole base-cell machinery
//! runs (DIAKRISIS, the LRC, the DA sampler); larger-`q` cells reuse the identical derivation over the
//! generic [`fanos_geometry::Plane`]. Validators are the Fano point indices `0..7`.

use fanos_geometry::fano;
use fanos_primitives::{BeaconSeed, Epoch, hash_labeled};

const LEADER_LINE_LABEL: &str = "FANOS-v1/taxis-leader-line";
const LEADER_MEMBER_LABEL: &str = "FANOS-v1/taxis-leader-member";
const SEAL_LINE_LABEL: &str = "FANOS-v1/taxis-seal-line";

/// The per-`(height, round)` election preimage: `SEED ‖ height ‖ round`. One source of truth so the leader
/// line and the leader member derive from the same bytes.
fn election_preimage(seed: &BeaconSeed, height: u64, round: u32) -> [u8; 32 + 8 + 4] {
    let mut buf = [0u8; 32 + 8 + 4];
    buf[..32].copy_from_slice(seed.as_bytes());
    buf[32..40].copy_from_slice(&height.to_be_bytes());
    buf[40..].copy_from_slice(&round.to_be_bytes());
    buf
}

/// The first 8 bytes of a digest as a big-endian `u64` — the uniform draw the reductions below use.
fn draw(digest: &[u8; 32]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(b)
}

/// The **committee line** elected to propose at `(height, round)`: `MapToLine` of the beacon election
/// preimage, a uniform choice among the `N = 7` Fano lines. Unpredictable before the epoch's `SEED`.
#[must_use]
pub fn leader_line(seed: &BeaconSeed, height: u64, round: u32) -> usize {
    let digest = hash_labeled(LEADER_LINE_LABEL, &election_preimage(seed, height, round));
    (draw(&digest) % fano::N as u64) as usize
}

/// The `q + 1 = 3` validator indices on Fano line `line` (its committee members), in canonical order.
#[must_use]
pub fn line_members(line: usize) -> [usize; fano::LINE_SIZE] {
    let pts = fano::LINE_POINTS.get(line).copied().unwrap_or([0, 0, 0]);
    [pts[0] as usize, pts[1] as usize, pts[2] as usize]
}

/// The elected **proposer** for `(height, round)`: the member of the elected [`leader_line`] whose
/// `H(SEED ‖ height ‖ round ‖ member)` is smallest — a uniform pick within the committee, so leadership is
/// beacon-random over validators yet always bound to the round's structural committee.
#[must_use]
pub fn leader(seed: &BeaconSeed, height: u64, round: u32) -> usize {
    let line = leader_line(seed, height, round);
    let preimage = election_preimage(seed, height, round);
    let member_key = |member: usize| {
        let mut buf = [0u8; 32 + 8 + 4 + 1];
        buf[..44].copy_from_slice(&preimage);
        buf[44] = member as u8;
        hash_labeled(LEADER_MEMBER_LABEL, &buf)
    };
    // The committee member with the smallest keyed digest — a uniform pick within the elected line.
    line_members(line)
        .into_iter()
        .min_by_key(|&m| member_key(m))
        .unwrap_or(0)
}

/// The **anti-MEV keyper line** for an epoch: `MapToLine(H(SEED(epoch) ‖ epoch))`, the single line committee
/// whose members threshold-seal every transaction of that epoch's mempool until each is finalized (spec
/// §10.1 "threshold encryption of a *line's* mempool", `docs/design-taxis.md` §5). Beacon-selected, so it is
/// unpredictable before the epoch and **not** choosable by any sender — a client cannot steer its transaction
/// to a committee it controls, and the committee rotates every epoch. This mirrors a Shutter/Ferveo keyper
/// set: one decryption committee per epoch, independent of the proposer, opening only after ordering.
#[must_use]
pub fn epoch_seal_line(seed: &BeaconSeed, epoch: Epoch) -> usize {
    let mut buf = [0u8; 32 + 8];
    buf[..32].copy_from_slice(seed.as_bytes());
    buf[32..].copy_from_slice(&epoch.to_be_bytes());
    let digest = hash_labeled(SEAL_LINE_LABEL, &buf);
    (draw(&digest) % fano::N as u64) as usize
}

/// The **cross-shard bridge** validator between two committee lines: the unique Maekawa intersection point
/// (any two Fano lines meet in exactly one point). A cross-shard transaction touching both committees is
/// witnessed by this shared validator, giving deterministic, balanced cross-shard coordination with no
/// extra overlay (spec §10.1 "cross-shard = bridge nodes", `docs/design-taxis.md` §7). `None` iff
/// `line_a == line_b` (a line does not bridge to itself).
#[must_use]
pub fn cross_shard_bridge(line_a: usize, line_b: usize) -> Option<usize> {
    if line_a == line_b || line_a >= fano::N || line_b >= fano::N {
        return None;
    }
    // The two lines' point sets share exactly one index (dual Steiner / Maekawa).
    let a = line_members(line_a);
    let b = line_members(line_b);
    a.into_iter().find(|p| b.contains(p))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const SEED: BeaconSeed = BeaconSeed::new([7u8; 32]);

    #[test]
    fn the_leader_is_deterministic_and_a_member_of_its_committee() {
        for height in 0..20u64 {
            for round in 0..4u32 {
                let line = leader_line(&SEED, height, round);
                let leader = leader(&SEED, height, round);
                assert!(line < fano::N);
                assert!(leader < fano::N);
                assert!(
                    line_members(line).contains(&leader),
                    "the proposer must sit on the elected committee line"
                );
                // Deterministic in (seed, height, round).
                assert_eq!(leader, super::leader(&SEED, height, round));
            }
        }
    }

    #[test]
    fn leadership_rotates_and_is_fair_across_validators() {
        // Over many heights every validator leads, and the distribution tracks the structural centrality
        // cap 1/7 — no validator can monopolize proposing (cartel resistance).
        let mut counts = [0u32; fano::N];
        let rounds = 7_000u64;
        for h in 0..rounds {
            counts[leader(&SEED, h, 0)] += 1;
        }
        assert!(counts.iter().all(|&c| c > 0), "every validator leads sometimes");
        let expected = rounds as f64 / fano::N as f64;
        for (v, &c) in counts.iter().enumerate() {
            let dev = (f64::from(c) - expected).abs() / expected;
            assert!(dev < 0.15, "validator {v} share {c} deviates too far from uniform 1/7 ({expected})");
        }
    }

    #[test]
    fn a_round_change_generally_re_elects_a_fresh_leader() {
        // Round advance (proposer timeout) must be able to move leadership off a stuck proposer — over
        // many heights the round-0 and round-1 leaders differ most of the time.
        let differ = (0..100u64).filter(|&h| leader(&SEED, h, 0) != leader(&SEED, h, 1)).count();
        assert!(differ > 70, "round change should usually re-elect a different leader, got {differ}/100");
    }

    #[test]
    fn a_different_beacon_seed_changes_the_schedule() {
        let other = BeaconSeed::new([9u8; 32]);
        let differ = (0..100u64).filter(|&h| leader(&SEED, h, 0) != leader(&other, h, 0)).count();
        assert!(differ > 70, "a fresh epoch beacon reshuffles the leader schedule, got {differ}/100");
    }

    #[test]
    fn the_keyper_line_rotates_with_the_epoch_and_is_not_sender_choosable() {
        // The epoch keyper line is deterministic within an epoch (members and combiner agree) and rotates
        // across epochs (unpredictable committee) — and it depends only on the beacon, not on any sender
        // input, so a client cannot steer its transaction to a committee it controls.
        let e0 = epoch_seal_line(&SEED, Epoch::new(0));
        assert_eq!(e0, epoch_seal_line(&SEED, Epoch::new(0)), "deterministic within an epoch");
        let rotations =
            (0..64u64).map(|e| epoch_seal_line(&SEED, Epoch::new(e))).collect::<alloc::collections::BTreeSet<_>>();
        assert!(rotations.len() >= 5, "the keyper committee rotates across epochs, saw {} distinct", rotations.len());
        // A different epoch beacon yields a different schedule of keyper lines.
        let other = BeaconSeed::new([0x5A; 32]);
        let differ = (0..40u64).filter(|&e| epoch_seal_line(&SEED, Epoch::new(e)) != epoch_seal_line(&other, Epoch::new(e))).count();
        assert!(differ > 25, "a fresh beacon reshuffles the keyper schedule, got {differ}/40");
    }

    #[test]
    fn cross_shard_bridge_is_the_unique_shared_validator() {
        // Any two distinct Fano lines meet in exactly one validator (Maekawa); it lies on both.
        for a in 0..fano::N {
            for b in 0..fano::N {
                let bridge = cross_shard_bridge(a, b);
                if a == b {
                    assert_eq!(bridge, None, "a line does not bridge to itself");
                } else {
                    let p = bridge.expect("distinct lines share a validator");
                    assert!(line_members(a).contains(&p) && line_members(b).contains(&p));
                    // Uniqueness: exactly one shared point.
                    let shared = line_members(a).into_iter().filter(|x| line_members(b).contains(x)).count();
                    assert_eq!(shared, 1, "lines {a},{b} share exactly one validator");
                }
            }
        }
    }
}
