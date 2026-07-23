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
use fanos_vrf::pqvrf::{self, MerkleProof, VrfOutput};

const LEADER_LINE_LABEL: &str = "FANOS-v1/taxis-leader-line";
const LEADER_MEMBER_LABEL: &str = "FANOS-v1/taxis-leader-member";
const SEAL_LINE_LABEL: &str = "FANOS-v1/taxis-seal-line";
/// Domain separation for the secret-leader sortition ticket (SSLE, spec §10.1).
const LEADER_TICKET_LABEL: &str = "FANOS-v1/taxis-leader-ticket";

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

// ===========================================================================================
// Secret-leader sortition (SSLE) — the min-ticket over the elected line (spec §10.1).
//
// The elected [`leader_line`] is PUBLIC (beacon-derived), so an adversary knows the `q + 1`
// candidate proposers. What it must NOT know until a member proposes is *which* member leads —
// otherwise it can pre-aim a DoS/bribe at the single upcoming proposer (the Heimbach et al.
// USENIX'25 deanonymization attack, whose fix at the consensus layer is exactly this). The
// derived-native answer (converged across three independent SSLE audits): every line member
// draws a **post-quantum VRF ticket**; all propose; the LOWEST ticket leads; a member reveals
// its VRF witness with its proposal, and replicas prepare the lowest verified ticket seen.
//
// The ticket MUST be a full-uniqueness VRF (RFC 9381) — here FANOS's Merkle-VRF (`pqvrf`, an
// iVRF whose output is Merkle-committed and therefore unique). It is emphatically NOT a hash of
// an ML-DSA signature: ML-DSA is Fiat-Shamir-with-aborts, so a signer can mint many valid
// signatures per message and GRIND the argmin — full rigging, not mere bias.
//
// Safety is untouched: leader selection lives entirely in the pacemaker (cf. HotStuff's theorem
// that safety holds under an adversarial Pacemaker). Ties/splits/withheld tickets can only waste
// a view; round ≥ 1 falls back to the public deterministic [`leader`]. See `docs/design-taxis.md`.
// ===========================================================================================

/// Whether `member` sits on the **proposer line** elected for `(height, round)` — the public
/// `q + 1`-member committee that runs the secret-leader sortition. Membership is beacon-derived
/// (public); *which* member leads is secret until it proposes.
#[must_use]
pub fn is_line_member(seed: &BeaconSeed, height: u64, round: u32, member: usize) -> bool {
    line_members(leader_line(seed, height, round)).contains(&member)
}

/// A line member's **secret-leader sortition ticket** for `(height, round)`:
/// `H(vrf_output ‖ SEED ‖ height ‖ round)`, where `vrf_output` is the member's post-quantum
/// Merkle-VRF value at index `height`. **Lowest ticket leads.**
///
/// Folding the unbiasable epoch beacon `seed` makes the ticket unpredictable before the beacon is
/// revealed (anti-grinding); folding `round` re-randomizes the order each view so a round change
/// re-sortitions among the *same* line without a fresh VRF evaluation. Because `vrf_output` is
/// Merkle-committed it is **unique** (RFC 9381 full uniqueness) — a Byzantine member cannot grind
/// it, unlike a hash of a (non-unique) lattice signature.
#[must_use]
pub fn leader_ticket(vrf_output: &VrfOutput, seed: &BeaconSeed, height: u64, round: u32) -> [u8; 32] {
    let mut buf = [0u8; 32 + 32 + 8 + 4];
    buf[..32].copy_from_slice(vrf_output);
    buf[32..64].copy_from_slice(seed.as_bytes());
    buf[64..72].copy_from_slice(&height.to_be_bytes());
    buf[72..].copy_from_slice(&round.to_be_bytes());
    hash_labeled(LEADER_TICKET_LABEL, &buf)
}

/// Verify a proposer's ticket **witness** and return its ticket value, or `None` if the witness is
/// invalid. The proposer presents its Merkle-VRF `output` + `proof` at `vrf_index`, checked against
/// its pre-registered `root` (`vrf_height` = the registered tree height). Only a verified witness
/// yields a ticket, so a min-over-verified-proposals comparison admits no forged or grindable ticket.
///
/// `vrf_index` is the **per-registration domain index** (e.g. `height − epoch_base`), kept distinct
/// from the absolute `height`/`round` the ticket hash binds: the VRF tree has `2^vrf_height` leaves,
/// so a long chain uses a *bounded* domain re-registered each epoch (the sound scaling — an absolute
/// height index would eventually exhaust `MAX_HEIGHT = 24` and OOM the tree). The hash still binds the
/// absolute `height` so tickets never collide across epochs that reuse a relative index.
#[must_use]
#[allow(clippy::too_many_arguments)] // eight distinct cryptographic inputs; bundling them would be artificial
pub fn verify_leader_ticket(
    root: &[u8; 32],
    vrf_height: u32,
    vrf_index: u64,
    seed: &BeaconSeed,
    height: u64,
    round: u32,
    vrf_output: &VrfOutput,
    proof: &MerkleProof,
) -> Option<[u8; 32]> {
    if !pqvrf::verify(root, vrf_height, vrf_index, vrf_output, proof) {
        return None;
    }
    Some(leader_ticket(vrf_output, seed, height, round))
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

    // ---- Secret-leader sortition (SSLE) -----------------------------------------------------

    #[test]
    fn a_line_member_is_recognized_and_the_fallback_leader_is_always_one() {
        for height in 0..12u64 {
            for round in 0..3u32 {
                let members = line_members(leader_line(&SEED, height, round));
                for m in 0..fano::N {
                    assert_eq!(is_line_member(&SEED, height, round, m), members.contains(&m));
                }
                // The round ≥ 1 public fallback proposer is always drawn from the same line.
                assert!(is_line_member(&SEED, height, round, leader(&SEED, height, round)));
            }
        }
    }

    #[test]
    fn a_ticket_witness_verifies_against_the_registered_root_and_yields_the_ticket() {
        let vrf_height = 6u32;
        let secret = pqvrf::MerkleVrfSecret::generate(&[3u8; 32], vrf_height).unwrap();
        let root = secret.root();
        let (height, round) = (5u64, 0u32);
        let (output, proof) = secret.prove(height).unwrap();
        // A valid witness (vrf_index = height here, base 0) yields exactly the direct ticket value.
        assert_eq!(
            verify_leader_ticket(&root, vrf_height, height, &SEED, height, round, &output, &proof),
            Some(leader_ticket(&output, &SEED, height, round)),
        );
        // A wrong registered root rejects (can't borrow another member's identity).
        assert_eq!(verify_leader_ticket(&[0u8; 32], vrf_height, height, &SEED, height, round, &output, &proof), None);
        // A witness proving a DIFFERENT index does not verify at this index (no index substitution).
        let (other_out, other_proof) = secret.prove(height + 1).unwrap();
        assert_eq!(verify_leader_ticket(&root, vrf_height, height, &SEED, height, round, &other_out, &other_proof), None);
    }

    #[test]
    fn the_ticket_binds_output_beacon_height_and_round() {
        let secret = pqvrf::MerkleVrfSecret::generate(&[4u8; 32], 6).unwrap();
        let (output, _) = secret.prove(3).unwrap();
        let base = leader_ticket(&output, &SEED, 3, 0);
        assert_eq!(base, leader_ticket(&output, &SEED, 3, 0), "deterministic");
        let other_seed = BeaconSeed::new([9u8; 32]);
        assert_ne!(base, leader_ticket(&output, &other_seed, 3, 0), "beacon-bound (anti-grinding)");
        assert_ne!(base, leader_ticket(&output, &SEED, 4, 0), "height-bound");
        assert_ne!(base, leader_ticket(&output, &SEED, 3, 1), "round-bound (re-sortition on view change)");
        let (other_out, _) = secret.prove(4).unwrap();
        assert_ne!(base, leader_ticket(&other_out, &SEED, 3, 0), "output-bound (per-member)");
    }

    #[test]
    fn min_ticket_sortition_elects_one_secret_leader_and_the_beacon_reshuffles_it() {
        // A q+1 = 3-member line, each member with its own registered Merkle-VRF. The winner is the
        // argmin ticket — a single well-defined leader per (height, round) — and it is unpredictable:
        // a fresh beacon reshuffles the winner, so no adversary can pre-aim before the beacon reveals.
        let vrf_height = 9u32; // domain 2^9 = 512 ≥ the 300 heights swept below
        let secrets = [
            pqvrf::MerkleVrfSecret::generate(&[10u8; 32], vrf_height).unwrap(),
            pqvrf::MerkleVrfSecret::generate(&[11u8; 32], vrf_height).unwrap(),
            pqvrf::MerkleVrfSecret::generate(&[12u8; 32], vrf_height).unwrap(),
        ];
        let winner = |seed: &BeaconSeed, height: u64| -> usize {
            (0..3usize)
                .min_by_key(|&i| {
                    let (out, _) = secrets[i].prove(height).unwrap();
                    leader_ticket(&out, seed, height, 0)
                })
                .unwrap()
        };
        // A single well-defined winner per height (deterministic given the VRF outputs + beacon).
        for h in 0..8u64 {
            assert_eq!(winner(&SEED, h), winner(&SEED, h));
        }
        // The beacon reshuffles the secret leader (unpredictable before the epoch beacon reveals).
        let other = BeaconSeed::new([0x5A; 32]);
        let differ = (0..64u64).filter(|&h| winner(&SEED, h) != winner(&other, h)).count();
        assert!(differ > 20, "the beacon must reshuffle the secret leader, got {differ}/64");
        // Fairness: over many heights every line member wins the sortition sometimes (no monopoly).
        let mut wins = [0u32; 3];
        for h in 0..300u64 {
            wins[winner(&SEED, h)] += 1;
        }
        assert!(wins.iter().all(|&w| w > 0), "every line member wins the sortition sometimes: {wins:?}");
    }
}
