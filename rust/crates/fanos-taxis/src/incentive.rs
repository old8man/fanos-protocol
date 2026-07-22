//! The TAXIS incentive equilibrium (spec §16, `docs/design-incentive-equilibrium.md`).
//!
//! Spec §16 leaves the *equilibrium guarantee* for validator incentives open ("L7 gives the mechanics, not
//! an equilibrium guarantee"). This module supplies it: a reward/slashing mechanism, and a machine-checked
//! proof that under it honest validation is a Nash equilibrium. The result is clean because TAXIS already
//! makes the **gain** of every profitable-looking deviation zero — the anti-MEV encrypted mempool
//! neutralizes MEV, BFT safety makes equivocation pointless, and DA gating makes data-withholding
//! unrewarded — so honesty is an equilibrium under the minimal conditions that rewards cover costs (C1) and
//! provable faults are slashed by any positive amount (C2). See the design note for the full derivation.
//!
//! Fees are the existing anonymous VOPRF credit ([`fanos_incentives`]), context-bound to the block so a fee
//! cannot be replayed or front-run; this module is the *accounting and game theory* on top of that token.

use alloc::vec::Vec;

use fanos_geometry::fano;
use fanos_incentives::{CreditIssuer, RedeemProof, Redemption};
use fanos_pqcrypto::HybridVerifier;
use fanos_primitives::Epoch;

use crate::committee::line_members;
use crate::params::CellParams;
use crate::vote::{Phase, SignedVote};

const FEE_CONTEXT_LABEL: &[u8] = b"FANOS-v1/taxis-fee";

/// The context a fee credit is bound to: `"taxis-fee" ‖ epoch ‖ height`. Binding the anonymous VOPRF credit
/// to the exact block it pays for (RFC-9578-style, `fanos_incentives` audit B8) means a fee credit shown for
/// one block cannot be replayed or front-run into another — the block-inclusion fee is single-use and
/// non-transferable across blocks, without deanonymising the payer.
#[must_use]
pub fn fee_context(epoch: Epoch, height: u64) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(FEE_CONTEXT_LABEL.len() + 16);
    ctx.extend_from_slice(FEE_CONTEXT_LABEL);
    ctx.extend_from_slice(&epoch.to_be_bytes());
    ctx.extend_from_slice(&height.to_be_bytes());
    ctx
}

/// Collect an anonymous VOPRF credit as this block's inclusion fee: redeem `proof` against the fee issuer,
/// **bound to `(epoch, height)`**. `true` iff the credit is valid and first-seen for this block; a replay,
/// a forgery, or a credit bound to a different block is rejected. The payer stays anonymous (the credit's
/// blinding unlinks issuance from redemption, `fanos_incentives`).
#[must_use]
pub fn collect_fee(
    issuer: &mut CreditIssuer,
    proof: &RedeemProof,
    epoch: Epoch,
    height: u64,
) -> bool {
    matches!(issuer.redeem(proof, &fee_context(epoch, height)), Redemption::Accepted)
}

/// The reward/penalty parameters of the per-block stage game.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RewardParams {
    /// `F` — the block's total transaction fee (in anonymous credits).
    pub fee: u64,
    /// `Q` — the finality quorum size (the reward is split among the commit-certificate signers).
    pub quorum: usize,
    /// `c` — a validator's honest cost per block (signing + bandwidth).
    pub vote_cost: u64,
    /// `S` — the slashing penalty for a *provable* fault (equivocation). Must be `> 0` (condition C2).
    pub slash: u64,
}

impl RewardParams {
    /// The per-participant reward `R = F / Q`.
    #[must_use]
    pub fn reward_per_participant(&self) -> u64 {
        if self.quorum == 0 {
            return 0;
        }
        self.fee / self.quorum as u64
    }

    /// Condition **C1**: the per-participant reward covers the honest cost (`R ≥ c`).
    #[must_use]
    pub fn covers_cost(&self) -> bool {
        self.reward_per_participant() >= self.vote_cost
    }

    /// Condition **C2**: provable faults are slashed by a positive amount (`S > 0`).
    #[must_use]
    pub fn slashing_deters(&self) -> bool {
        self.slash > 0
    }

    /// The equilibrium theorem's hypotheses: honest play is a Nash equilibrium iff **C1 ∧ C2**.
    #[must_use]
    pub fn honest_is_nash(&self) -> bool {
        self.covers_cost() && self.slashing_deters()
    }
}

/// Split a block's `fee` equally among the validators who both signed its commit certificate **and** revealed
/// their sealing share (reveal-gated payment). Returns `(validator, reward)` pairs; any remainder from
/// integer division is burned (deterministic, no rounding advantage). Empty if there are no eligible signers.
#[must_use]
pub fn distribute(fee: u64, eligible_signers: &[u8]) -> Vec<(u8, u64)> {
    if eligible_signers.is_empty() {
        return Vec::new();
    }
    let share = fee / eligible_signers.len() as u64;
    eligible_signers.iter().map(|&s| (s, share)).collect()
}

/// A self-contained cryptographic proof that a validator equivocated: two of its validly-signed votes at the
/// same `(height, round, phase)` for **different** blocks. Anyone can verify it and apply the slash — no
/// trusted party, no synchrony assumption.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SlashEvidence {
    /// The equivocating validator's index.
    pub validator: u8,
    /// The height both votes are cast at.
    pub height: u64,
    /// The round both votes are cast at.
    pub round: u32,
    /// The phase both votes are cast in.
    pub phase: Phase,
    /// The first conflicting vote.
    pub vote_a: SignedVote,
    /// The second conflicting vote.
    pub vote_b: SignedVote,
}

/// Detect equivocation: if `a` and `b` are two validly-signed votes from the **same** validator at the same
/// `(height, round, phase)` but for **different** blocks, return the slashable proof. Returns `None` if they
/// are not a genuine conflict (different slot, identical vote, or either signature fails to verify — a forged
/// "vote" is not evidence). `verifier` must be the voter's key.
#[must_use]
pub fn detect_equivocation(
    a: &SignedVote,
    b: &SignedVote,
    verifier: &HybridVerifier,
) -> Option<SlashEvidence> {
    let (va, vb) = (a.vote, b.vote);
    if va.voter != vb.voter
        || va.height != vb.height
        || va.round != vb.round
        || va.phase != vb.phase
    {
        return None; // not the same voting slot
    }
    if va.block_hash == vb.block_hash {
        return None; // the same vote, not a conflict
    }
    if !a.verify(verifier) || !b.verify(verifier) {
        return None; // an unsigned / forged "vote" cannot slash anyone
    }
    Some(SlashEvidence {
        validator: va.voter,
        height: va.height,
        round: va.round,
        phase: va.phase,
        vote_a: a.clone(),
        vote_b: b.clone(),
    })
}

/// A unilateral validator strategy for the stage game (`docs/design-incentive-equilibrium.md` §1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Strategy {
    /// Propose (if elected), vote in both phases, and reveal — the honest triple.
    Honest,
    /// Withhold the vote (free-ride, saving the cost).
    Abstain,
    /// Sign two conflicting votes (provable, slashable).
    Equivocate,
    /// As proposer, reorder for MEV (gain 0 under the encrypted mempool).
    MevReorder,
    /// As proposer, publish a header whose payload is unavailable (never finalizes).
    WithholdData,
    /// As a sealing member, refuse to reveal (forfeits the reveal-gated share).
    WithholdReveal,
    /// Withhold reveals to **censor** a targeted transaction for an external bribe. A lone validator cannot
    /// reach a keyper line's blocking threshold, so unilaterally this censors nothing (gain `0`); it becomes a
    /// coalitional deviation ([`coalition_payoff`]) that still fails below a covering coalition.
    Censor,
}

/// The payoff of a strategy for a validator, given all others honest — the model of
/// `docs/design-incentive-equilibrium.md` §2–§3. Signed (a slashed equivocator is negative).
///
/// The arms are kept separate on purpose even where they coincide numerically: that `MevReorder` equals
/// `Honest`, and that the three withholding/abstaining deviations equal `0`, is exactly the theorem's content
/// (anti-MEV zeroes the ordering gain; the gates zero the withholders' reward) — collapsing them would erase
/// the per-strategy derivation this function documents.
#[allow(clippy::match_same_arms)]
#[must_use]
pub fn payoff(params: &RewardParams, strategy: Strategy) -> i128 {
    let r = i128::from(params.reward_per_participant());
    let c = i128::from(params.vote_cost);
    let s = i128::from(params.slash);
    match strategy {
        // Earns the reward, pays the honest cost.
        Strategy::Honest => r - c,
        // Excluded from the certificate → no reward, but saves the cost.
        Strategy::Abstain => 0,
        // Gain 0 (BFT safety makes a fork impossible); detected and slashed, reward forfeited.
        Strategy::Equivocate => -s,
        // Gain 0 (encrypted mempool blinds ordering); still finalizes and earns the reward — same as honest.
        Strategy::MevReorder => r - c,
        // The block never finalizes (DA gating) → no reward.
        Strategy::WithholdData => 0,
        // Reveal-gated payment → forfeits the share; gain 0.
        Strategy::WithholdReveal => 0,
        // A lone validator cannot reach a keyper line's blocking threshold (≥ 2), so it censors nothing.
        Strategy::Censor => 0,
    }
}

/// Every unilateral deviation from a strategy set — the model's full deviation space.
pub const DEVIATIONS: [Strategy; 6] = [
    Strategy::Abstain,
    Strategy::Equivocate,
    Strategy::MevReorder,
    Strategy::WithholdData,
    Strategy::WithholdReveal,
    Strategy::Censor,
];

/// The equilibrium theorem, machine-checked: under **C1 ∧ C2** the honest payoff is `≥` every deviation's,
/// so honest validation is a best response (a Nash equilibrium). Returns `false` if the hypotheses fail.
#[must_use]
pub fn best_response_is_honest(params: &RewardParams) -> bool {
    if !params.honest_is_nash() {
        return false;
    }
    let honest = payoff(params, Strategy::Honest);
    DEVIATIONS.iter().all(|&d| honest >= payoff(params, d))
}

// ── Coalitional deviations & censorship resistance (`docs/design-incentive-equilibrium.md` §4) ──────────────
//
// The theorem above assumes a lone deviator. A stronger guarantee rules out a *coalition* of up to the BFT bound
// `f` jointly deviating — including the one deviation a coalition unlocks that no individual can: **censorship**
// of a targeted transaction by withholding a keyper line's reveals. The anti-MEV line is `t`-of-`(q+1)`, so
// blocking a transaction's decryption needs `(q+1) − t + 1` of *that line's* members to withhold. The line is
// chosen by the unbiasable epoch beacon and rotates every epoch (`crate::committee`), and a client re-seals each
// epoch — so *permanent* censorship demands the coalition block **every** line at once, a covering coalition far
// larger than `f`. The functions below make that precise; the tests machine-check it exhaustively over the cell.

/// The number of withholders needed to block a keyper line's `t`-of-`(q+1)` reveal reconstruction:
/// `(q+1) − t + 1`. Below this the honest remainder still reaches the threshold and the transaction decrypts.
#[must_use]
pub fn blocking_threshold(cell: CellParams) -> usize {
    cell.line_size().saturating_sub(usize::from(cell.seal_threshold())) + 1
}

/// Whether `coalition` holds a blocking subset (≥ [`blocking_threshold`]) of Fano line `line`'s seats — enough
/// of that line's keyper members to deny the `t` honest reveals a transaction sealed to it needs.
#[must_use]
fn blocks_line(coalition: &[u8], line: usize, cell: CellParams) -> bool {
    let held = line_members(line).into_iter().filter(|&m| coalition.contains(&(m as u8))).count();
    held >= blocking_threshold(cell)
}

/// Whether `coalition` can **permanently** censor a transaction: it blocks a reveal on *every* one of the `N`
/// keyper lines, so no epoch's beacon-chosen line escapes it and re-sealing never gets the transaction through.
/// (Reference Fano cell — the lines are `committee::line_members(0..N)`.) For a coalition within the BFT bound
/// `f` this is always `false` (machine-checked in the tests) — the censorship-resistance guarantee.
#[must_use]
pub fn can_permanently_censor(coalition: &[u8], cell: CellParams) -> bool {
    (0..fano::N).all(|l| blocks_line(coalition, l, cell))
}

/// The total payoff of a `coalition` jointly playing `strategy` while every non-member stays honest — the
/// coalitional extension of [`payoff`]. Each member earns/forfeits as in the unilateral game (so `k` members
/// scale the per-member payoff), and the coalition additionally collects the external `bribe` **iff** it can
/// permanently censor a targeted transaction (the [`Strategy::Censor`] arm gated by [`can_permanently_censor`]).
///
/// The point of the model: for any coalition within the fault bound `f`, `can_permanently_censor` is `false`, so
/// `Censor` collapses to honest cooperation — the bribe is uncollectable and adds no payoff.
#[allow(clippy::match_same_arms)]
#[must_use]
pub fn coalition_payoff(
    params: &RewardParams,
    cell: CellParams,
    coalition: &[u8],
    bribe: u64,
    strategy: Strategy,
) -> i128 {
    let k = i128::from(u64::try_from(coalition.len()).unwrap_or(u64::MAX));
    let r = i128::from(params.reward_per_participant());
    let c = i128::from(params.vote_cost);
    let s = i128::from(params.slash);
    match strategy {
        // Every member earns the reward and pays the cost; blind ordering leaves MEV-reordering identical.
        Strategy::Honest | Strategy::MevReorder => k * (r - c),
        // Excluded / unrewarded joint deviations: each member nets 0.
        Strategy::Abstain | Strategy::WithholdData | Strategy::WithholdReveal => 0,
        // Each member is individually slashed; safety is unbroken for `k ≤ f`, so there is no offsetting gain.
        Strategy::Equivocate => -k * s,
        // Members still validate honestly (earning `k(R−c)`) and withhold on the target line; the bribe is
        // collected only if the coalition blocks every line — impossible within the fault bound.
        Strategy::Censor => {
            k * (r - c) + if can_permanently_censor(coalition, cell) { i128::from(bribe) } else { 0 }
        }
    }
}

/// Every coalitional deviation — the unilateral space plus the coalition-only [`Strategy::Censor`].
pub const COALITION_DEVIATIONS: [Strategy; 6] = DEVIATIONS;

/// The **coalitional** equilibrium theorem, machine-checked: for the given `coalition`, under **C1 ∧ C2** the
/// honest cooperative payoff is `≥` every joint deviation's — censorship included. A caller proves
/// coalition-proofness up to the BFT bound by checking this for every coalition of size `≤ f` (the tests do so
/// exhaustively, together with the lemma that no such coalition can [`can_permanently_censor`]). Returns `false`
/// if the hypotheses fail.
#[must_use]
pub fn coalition_best_response_is_honest(
    params: &RewardParams,
    cell: CellParams,
    coalition: &[u8],
    bribe: u64,
) -> bool {
    if !params.honest_is_nash() {
        return false;
    }
    let honest = coalition_payoff(params, cell, coalition, bribe, Strategy::Honest);
    COALITION_DEVIATIONS.iter().all(|&d| honest >= coalition_payoff(params, cell, coalition, bribe, d))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use fanos_pqcrypto::{HybridSigSecret, SeedRng};

    use super::*;
    use crate::vote::Vote;

    /// The reference Fano-cell parameters: F=100, Q=5 (R=20), c=10, S=50 — satisfies C1 (20 ≥ 10) and C2.
    const P: RewardParams = RewardParams { fee: 100, quorum: 5, vote_cost: 10, slash: 50 };

    #[test]
    fn the_reference_parameters_satisfy_the_equilibrium_conditions() {
        assert_eq!(P.reward_per_participant(), 20);
        assert!(P.covers_cost(), "C1: R=20 ≥ c=10");
        assert!(P.slashing_deters(), "C2: S=50 > 0");
        assert!(P.honest_is_nash());
    }

    #[test]
    fn honest_is_a_best_response_and_strictly_beats_detectable_faults() {
        assert!(best_response_is_honest(&P), "honest ≥ every deviation");
        let honest = payoff(&P, Strategy::Honest); // 20 − 10 = 10
        assert_eq!(honest, 10);
        // Weakly dominates the zero-gain deviations, strictly beats the punished/unrewarded ones.
        assert!(honest >= payoff(&P, Strategy::MevReorder), "MEV gains nothing (blind ordering)");
        assert!(honest > payoff(&P, Strategy::Abstain), "free-riding forfeits the reward");
        assert!(honest > payoff(&P, Strategy::Equivocate), "equivocation is slashed");
        assert!(honest > payoff(&P, Strategy::WithholdData), "a withheld block earns nothing");
        assert!(honest > payoff(&P, Strategy::WithholdReveal), "a withheld reveal forfeits the share");
        // Equivocation is strictly negative (the slash bites).
        assert_eq!(payoff(&P, Strategy::Equivocate), -50);
    }

    #[test]
    fn the_equilibrium_breaks_exactly_when_rewards_stop_covering_costs() {
        // If the fee no longer covers the cost (C1 fails), abstaining ties or beats honesty — the mechanism
        // correctly reports that honest play is no longer guaranteed.
        let starved = RewardParams { fee: 20, quorum: 5, vote_cost: 10, slash: 50 }; // R=4 < c=10
        assert!(!starved.covers_cost());
        assert!(!best_response_is_honest(&starved), "under-funded fees break the equilibrium (honestly reported)");
        // And with no slashing (C2 fails), equivocation is no longer deterred.
        let unslashed = RewardParams { slash: 0, ..P };
        assert!(!unslashed.slashing_deters());
        assert!(!best_response_is_honest(&unslashed));
    }

    #[test]
    fn a_block_fee_splits_equally_among_the_eligible_signers() {
        let rewards = distribute(100, &[0, 1, 2, 3, 4]);
        assert_eq!(rewards.len(), 5);
        assert!(rewards.iter().all(|&(_, r)| r == 20), "each of the 5 signers gets 20");
        let total: u64 = rewards.iter().map(|&(_, r)| r).sum();
        assert_eq!(total, 100);
        // A non-dividing fee burns the remainder deterministically (no signer gains from rounding).
        let uneven = distribute(103, &[0, 1, 2, 3, 4]);
        assert!(uneven.iter().all(|&(_, r)| r == 20), "103/5 = 20 each, 3 burned");
        assert!(distribute(100, &[]).is_empty(), "no signers, no payout");
    }

    fn signer(tag: u8) -> (HybridSigSecret, HybridVerifier) {
        let mut rng = SeedRng::from_seed(&[0xF0, tag]);
        HybridSigSecret::generate(&mut rng)
    }

    #[test]
    fn equivocation_is_detected_and_turned_into_a_slashable_proof() {
        let (sk, vk) = signer(1);
        // Validator 3 signs two DIFFERENT blocks at the same (height, round, phase) — equivocation.
        let base = Vote { height: 5, round: 0, block_hash: [1u8; 32], phase: Phase::Commit, voter: 3 };
        let a = SignedVote::sign(base, &sk);
        let b = SignedVote::sign(Vote { block_hash: [2u8; 32], ..base }, &sk);
        let evidence = detect_equivocation(&a, &b, &vk).expect("a genuine equivocation is detected");
        assert_eq!(evidence.validator, 3);
        assert_eq!(evidence.height, 5);
    }

    #[test]
    fn a_fee_credit_is_bound_to_its_block() {
        // The fee context is deterministic and distinct per (epoch, height), so a credit paid for one block
        // is invalid for any other — the block-inclusion fee cannot be replayed or front-run across blocks.
        let a = fee_context(Epoch::new(3), 10);
        assert_eq!(a, fee_context(Epoch::new(3), 10), "deterministic");
        assert_ne!(a, fee_context(Epoch::new(3), 11), "distinct per height");
        assert_ne!(a, fee_context(Epoch::new(4), 10), "distinct per epoch");

        // A garbage / forged redemption proof is rejected (not a valid credit for this block). The
        // accepted path — issue → finalize → redeem — is exercised in `fanos-incentives`' own suite.
        let mut issuer = CreditIssuer::from_seed(b"taxis-fee-issuer");
        let forged = RedeemProof::from_bytes(&[0u8; 64]);
        assert!(!collect_fee(&mut issuer, &forged, Epoch::new(3), 10), "a forged fee credit is refused");
    }

    #[test]
    fn honest_voting_and_forgeries_are_not_slashable() {
        let (sk, vk) = signer(2);
        let (other_sk, _) = signer(9);
        let base = Vote { height: 1, round: 0, block_hash: [7u8; 32], phase: Phase::Prepare, voter: 4 };

        // The same vote twice (a re-broadcast) is not a conflict.
        let a = SignedVote::sign(base, &sk);
        assert!(detect_equivocation(&a, &a, &vk).is_none(), "an identical vote is not equivocation");

        // Two votes in DIFFERENT phases are not a conflict (prepare then commit is honest).
        let commit = SignedVote::sign(Vote { phase: Phase::Commit, ..base }, &sk);
        assert!(detect_equivocation(&a, &commit, &vk).is_none(), "different phases are not equivocation");

        // A "conflicting" pair where one vote is forged (wrong signer) is not evidence — you cannot frame an
        // honest validator by fabricating a second vote.
        let framed = SignedVote::sign(Vote { block_hash: [8u8; 32], ..base }, &other_sk);
        assert!(detect_equivocation(&a, &framed, &vk).is_none(), "a forged second vote cannot slash validator 4");
    }

    #[test]
    fn the_blocking_threshold_is_the_line_minority_that_denies_the_honest_reveal_quorum() {
        // The Fano keyper line is 2-of-3, so blocking its reconstruction needs (q+1) − t + 1 = 3 − 2 + 1 = 2
        // withholders — a majority of the 3-member line. A single withholder (< 2) is tolerated.
        let cell = CellParams::FANO;
        assert_eq!(cell.line_size(), 3);
        assert_eq!(cell.seal_threshold(), 2);
        assert_eq!(blocking_threshold(cell), 2);
        // One validator on a keyper line never blocks it (the theorem's unilateral base case).
        for line in 0..fano::N {
            let m = line_members(line);
            assert!(!blocks_line(&[m[0] as u8], line, cell), "a lone member cannot block line {line}");
            assert!(blocks_line(&[m[0] as u8, m[1] as u8], line, cell), "two members block line {line}");
        }
    }

    #[test]
    fn no_coalition_within_the_bft_bound_can_permanently_censor() {
        // Machine-checked censorship-resistance lemma: exhaustively over every coalition of the Fano cell, none
        // of size ≤ f can block a reveal on *every* keyper line (so re-sealing across epochs always gets through).
        let cell = CellParams::FANO; // f = 2
        for mask in 0u16..(1 << fano::N) {
            let c: Vec<u8> = (0..fano::N as u8).filter(|i| mask >> i & 1 == 1).collect();
            if c.len() <= cell.f {
                assert!(!can_permanently_censor(&c, cell), "coalition {c:?} (≤ f={}) must not censor every line", cell.f);
            }
        }
        // The smallest coalition that CAN permanently censor is n − 1 = 6 — its complement is the single point no
        // line can avoid — far beyond the tolerated f = 2.
        let min_censor = (0u16..(1 << fano::N))
            .filter_map(|mask| {
                let c: Vec<u8> = (0..fano::N as u8).filter(|i| mask >> i & 1 == 1).collect();
                can_permanently_censor(&c, cell).then_some(c.len())
            })
            .min()
            .expect("some coalition censors");
        assert_eq!(min_censor, fano::N - 1, "permanent censorship needs n−1 validators");
        assert!(min_censor > cell.f, "the censoring coalition exceeds the BFT fault bound f={}", cell.f);
    }

    #[test]
    fn honest_cooperation_beats_every_coalitional_deviation_up_to_f() {
        // The coalitional equilibrium: exhaustively over every non-empty coalition of size ≤ f, honest
        // cooperation is a best response to every joint deviation — censorship included, even against a large
        // external bribe, because no tolerated coalition can permanently censor (the lemma above).
        let cell = CellParams::FANO;
        let bribe = 1_000; // a large censorship bribe — still uncollectable within the fault bound
        for mask in 1u16..(1 << fano::N) {
            let c: Vec<u8> = (0..fano::N as u8).filter(|i| mask >> i & 1 == 1).collect();
            if c.len() <= cell.f {
                assert!(
                    coalition_best_response_is_honest(&P, cell, &c, bribe),
                    "coalition {c:?} (≤ f) cannot profit by any joint deviation"
                );
            }
        }
        // Beyond tolerance a covering coalition (n − 1) CAN collect the bribe: the model reports honestly that
        // censorship-resistance is a consequence of the BFT bound, not an unconditional guarantee.
        let covering: Vec<u8> = (0..(fano::N as u8 - 1)).collect();
        assert!(can_permanently_censor(&covering, cell), "n−1 validators block every line");
        assert!(
            coalition_payoff(&P, cell, &covering, bribe, Strategy::Censor)
                > coalition_payoff(&P, cell, &covering, bribe, Strategy::Honest),
            "a coalition exceeding f extracts censorship value — outside the BFT guarantee"
        );
        // A tolerated coalition's censor payoff, by contrast, is exactly its honest payoff (no bribe collected).
        let tolerated: Vec<u8> = alloc::vec![0, 1]; // size 2 = f, shares one line only
        assert_eq!(
            coalition_payoff(&P, cell, &tolerated, bribe, Strategy::Censor),
            coalition_payoff(&P, cell, &tolerated, bribe, Strategy::Honest),
            "within the fault bound, attempting censorship pays exactly what honest cooperation does"
        );
    }
}
