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

**Honest scope.** This is the single-cell stage game with a *unilateral* deviator and provable faults. §4
strengthens it to a *coalitional* guarantee up to the BFT bound `f` (including the censorship deviation a
coalition unlocks); beyond `f` a cartel breaks BFT itself, the acknowledged structural limit. It does not model
the credit *issuance* economy (who funds fees) — that remains the genuinely open macro-economic question of §16.
What is now closed is the micro-equilibrium: **given** fees exist, honest validation is the rational strategy,
individually and in coalition up to `f`.

---

## 4. Coalitional deviations and censorship resistance

The stage game of §1–§3 has a *unilateral* deviator. The natural strengthening is coalition-proofness: no group
of up to the BFT fault bound `f` can jointly deviate and come out ahead. Scaling the §3 deviations to a coalition
of size `k ≤ f` is immediate — each member's individual payoff is unchanged (the others are still honest), so a
`k`-coalition playing Abstain/Equivocate/MEV/Withhold earns `k` times the per-member payoff, and the sign of the
comparison against honest `k(R − c)` is exactly §3's. Safety is intact for `k ≤ f` (two `Q`-quorums still share
an honest validator, `CellParams::is_safe`), so the coalitional equivocation gain is still `0` — just `k` slashes.

**The one deviation a coalition unlocks is censorship.** No individual can prevent a transaction from being
decrypted, but a coalition holding enough of a keyper line can. A transaction is sealed `t`-of-`(q+1)` to the
epoch's keyper line (`docs/design-taxis.md` §5), so **denying** its decryption requires

> `block = (q + 1) − t + 1`

of *that line's* members to withhold their reveals — a line minority large enough that fewer than `t` honest
members remain. For the Fano line (`q+1 = 3`, `t = 2`) that is `block = 2`. A coalition that holds a blocking
subset of the epoch's keyper line can censor any transaction sealed in that epoch, for an external bribe `b`.

**Why the bribe is uncollectable within `f`.** The keyper line is chosen by the unbiasable epoch beacon and
**rotates every epoch** (`crate::committee::epoch_seal_line`), and a client simply re-seals in the next epoch.
So censoring a transaction *permanently* requires the coalition to hold a blocking subset of **every** line at
once. In `PG(2, 2)` a set that meets all seven lines in `≥ 2` points is the complement of a set meeting every
line in `≤ 1` point; but any two points already share a line, so that complement has at most one point — the
covering coalition has size `n − 1 = 6`. Permanent censorship therefore needs `6 ≫ f = 2` validators. More
generally the covering coalition exceeds `f` for the reference cell, so:

> **Censorship-resistance lemma.** No coalition of size `≤ f` can block a reveal on every keyper line; a
> re-sealing client's transaction is decrypted within `O(1)` expected epochs. *(Machine-checked exhaustively
> over all `2ⁿ` coalitions: `no_coalition_within_the_bft_bound_can_permanently_censor`.)*

**Theorem (coalitional equilibrium).** Under **C1 ∧ C2**, for every coalition of size `k ≤ f` the honest
cooperative payoff `k(R − c)` is `≥` every joint deviation's — Abstain, Equivocate, MEV-reorder, Withhold-data,
Withhold-reveal, **and Censor** — for any bribe `b`. The Censor arm pays `k(R − c) + [permanent] · b`, and by
the lemma `[permanent] = 0` for `k ≤ f`, so it collapses to honest cooperation: the bribe is never collected. ∎

This is verified by `coalition_best_response_is_honest`, checked exhaustively over every coalition of size `≤ f`
against a large bribe (`honest_cooperation_beats_every_coalitional_deviation_up_to_f`). The model also reports,
honestly, that a `> f` covering coalition *can* extract the bribe — censorship-resistance is a consequence of the
BFT bound, not an unconditional guarantee.

---

## 5. What is implemented (`fanos-taxis::incentive`)

- `RewardParams` and `reward_per_participant` (`R = F/Q`), with `covers_cost` (**C1**) and `honest_is_nash`
  checking the theorem's hypotheses.
- `distribute` — split a block's fee equally among its commit-certificate signers (reveal-gated).
- `detect_equivocation` — turn a conflicting signed-vote pair into a `SlashEvidence` proof; `slash` applies
  the penalty.
- `best_response_is_honest` — a machine-checked enumeration of §3: for the derived params, the honest payoff
  is `≥` every deviation payoff (and `>` for the detectable ones).
- `blocking_threshold` / `can_permanently_censor` — the §4 censorship geometry: the line minority `(q+1)−t+1`
  that denies a reveal, and whether a coalition blocks *every* keyper line (the covering condition).
- `coalition_payoff` / `coalition_best_response_is_honest` — the §4 coalitional stage game (with a `Censor` arm
  and an external bribe), machine-checked exhaustively over every coalition of size `≤ f`.
- Fees are the existing anonymous VOPRF credit (`fanos-incentives`), context-bound to `(cell, epoch, height)`.
