# The TAXIS incentive equilibrium (closing spec §16 / task A2)

> Spec §16 lists, honestly, an open problem: *"Incentives against free-riders in an open network are an open
> economic problem (L7 gives the mechanics, not an equilibrium guarantee)."* The L7 **mechanics** — anonymous
> VOPRF credits — already exist (`fanos-incentives`). This note supplies the missing **equilibrium
> guarantee**: a mechanism, and a proof that under it honest participation is a Nash equilibrium. The result
> is unusually clean because two properties TAXIS already has do the heavy lifting — the anti-MEV encrypted
> mempool and BFT safety make the *gain* from every profitable-looking deviation exactly **zero**, so honest
> play is an equilibrium under the minimal condition that rewards cover costs.

Everything here is derived, not tuned: the two mechanism constants (C1, C2 below) are the *equilibrium
conditions themselves*, not magic thresholds. Implemented and machine-checked in
`fanos-taxis::incentive`.

---

## 1. The stage game

One cell, `n` validators (the projective points), one block height as the stage. A validator's honest
strategy is the triple **(propose if elected, vote in both phases, reveal your sealing share post-commit)**,
at total cost `c > 0` (signature + bandwidth). Deviations available to a unilateral validator `i`:

| Deviation | What `i` does |
|---|---|
| **Abstain** | withhold its prepare/commit vote (free-ride, save `c`) |
| **Misvote** | vote for a different block than the honest one |
| **Equivocate** | sign two conflicting votes at the same `(height, round, phase)` |
| **MEV-reorder** | as proposer, order transactions to extract value (front-run / sandwich) |
| **Withhold-data** | as proposer, publish a header whose payload it does not make available |
| **Withhold-reveal** | as a sealing-committee member, refuse to release its share opening |

**Rewards.** A block's transaction fees `F` (paid by senders in anonymous VOPRF credits, context-bound to
`(cell, epoch, height)` so a fee cannot be replayed or front-run — `fanos_incentives::Credit::prove`) are
split **equally among the `Q` validators whose signatures form the commit certificate**, and payment of a
sealing member's share is **gated on that member's reveal**. So per-participant reward is `R = F / Q`. A
validator provably caught equivocating forfeits its reward and a stake `S > 0` (slashing); equivocation is
*provable* because a `(vote_a, vote_b)` pair with the same signer, height, round, and phase but different
block hashes, both valid signatures, is a self-contained cryptographic proof.

---

## 2. Why every deviation's *gain* is zero

This is the crux, and it is what a generic blockchain lacks:

- **MEV-reorder gains 0.** The mempool is threshold-encrypted to a beacon-selected keyper line; the proposer
  orders *commitments*, provably blind to contents (`docs/design-taxis.md` §5). There is no ordering it can
  choose that reveals or exploits transaction contents — the value it could extract is identically zero.
- **Equivocate gains 0.** BFT safety (the masking-quorum intersection, `CellParams::is_safe`) makes two
  conflicting commit certificates for one height *impossible*: any two `Q`-quorums share an honest validator
  who signs at most one block. So an equivocator cannot cause a double-spend or a fork — the outcome it could
  buy with equivocation does not exist.
- **Withhold-data gains 0 (and loses the reward).** PREPARE is gated on DA sampling; an unavailable payload
  gets no honest prepares, so the block never finalizes and the proposer earns `0` instead of its share.

So for the three "attacking" deviations the *benefit* term is `0`, while equivocation and data-withholding
additionally carry a *cost* (slashing / lost reward).

---

## 3. The equilibrium theorem

> **Theorem (honest Nash equilibrium).** Let
> **(C1)** `R = F/Q ≥ c` — the per-participant reward covers the honest cost; and
> **(C2)** `S > 0` — provable faults are slashed by any positive amount.
> Then the all-honest profile is a Nash equilibrium of the TAXIS stage game; it is a *strict* equilibrium
> against every **detectable** deviation (equivocate, withhold-data, withhold-reveal).

**Proof.** Fix all other validators honest and check each unilateral deviation of `i`:

1. **Abstain.** `i` leaves the commit certificate (the other `Q` honest validators still form one — liveness,
   `CellParams::is_live`), so it earns `0` and saves `c`: payoff `0` vs honest `R − c ≥ 0` by **C1**. Not
   profitable.
2. **Misvote.** A lone wrong vote cannot form a conflicting certificate (needs `Q−1` accomplices; the honest
   majority refuses), so it is simply excluded from the honest certificate → earns `0`. Not profitable.
3. **Equivocate.** Gain `0` (§2); detected and slashed → payoff `−S − ` (forfeited `R`) `< R − c`. Strictly
   worse (uses **C2**).
4. **MEV-reorder.** Gain `0` (§2); still finalizes and earns its proposer share `R`. Payoff unchanged — no
   incentive to deviate.
5. **Withhold-data.** Block does not finalize → proposer earns `0` vs `R`. Strictly worse.
6. **Withhold-reveal.** Reveal-gated payment → `i` forfeits its share; gain `0`. Strictly worse.

No unilateral deviation raises `i`'s payoff, so the honest profile is a Nash equilibrium; deviations 3, 5, 6
are detectable and strictly punished, giving strictness there. ∎

**Reading.** The mechanism does *not* rely on a large stake or a finely-tuned fee. It relies on TAXIS already
having removed the *reasons* to cheat: with MEV neutralized and safety structural, cheating buys nothing, so
the faintest incentive to participate (C1) and the faintest penalty for provable faults (C2) suffice. This is
the equilibrium guarantee §16 asked for, and it is a *consequence* of the anti-MEV + BFT design, not a bolted-on
economic assumption.

**Honest scope.** This is the single-cell stage game with a *unilateral* deviator and provable faults. It does
**not** claim collusion-proofness against a `≥ f+1` cartel (excluded by the anti-Sybil centrality cap and the
beacon committee rotation, but a coalition of that size breaks BFT itself — a separate, acknowledged limit),
nor does it model the credit *issuance* economy (who funds fees) — that remains the genuinely open
macro-economic question of §16. What is now closed is the micro-equilibrium: **given** fees exist, honest
validation is the rational strategy.

---

## 4. What is implemented (`fanos-taxis::incentive`)

- `RewardParams` and `reward_per_participant` (`R = F/Q`), with `covers_cost` (**C1**) and `honest_is_nash`
  checking the theorem's hypotheses.
- `distribute` — split a block's fee equally among its commit-certificate signers (reveal-gated).
- `detect_equivocation` — turn a conflicting signed-vote pair into a `SlashEvidence` proof; `slash` applies
  the penalty.
- `best_response_is_honest` — a machine-checked enumeration of §3: for the derived params, the honest payoff
  is `≥` every deviation payoff (and `>` for the detectable ones).
- Fees are the existing anonymous VOPRF credit (`fanos-incentives`), context-bound to `(cell, epoch, height)`.
