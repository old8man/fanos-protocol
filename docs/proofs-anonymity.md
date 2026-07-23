# Anonymity proofs — T1–T5 for the derived-native substrate

> Companion to `docs/design-anonymity-substrate.md`, which *states* the theorems; this note *proves*
> them, or — where a full formalization is genuinely open — gives the exact proof architecture (the
> reduction/hybrid structure, the lemmas it rests on, the assumptions, and the honest residual). Every
> game is the one the formal-defs audit (2026-07-23) transcribed from the primary sources; every cited
> lemma is named so a machine-checked pass could follow this skeleton. **T4 is fully proven in code**
> (`fanos-nyx::security`, commit `5806d34`); T2 is complete; T1 is complete modulo the standard
> committee-generalized-KHRS formalization; T3 and T5 have a proven core and a stated analytic residual.

## 0. Preliminaries — the game, the notions, the adversary

**The game (AnoA, Backes–Kate–Manoharan–Meiser–Mohammadi, *CSF 2013*).** A challenger `Ch(P, α, b)`
runs protocol `P` on the `b`-th of two adversary-chosen communication tables, forwarding every
`P↔A` message. `P` is `(ε,δ)`-`α`-IND-CDP iff for all PPT `A`,
`Pr[0 = A^{Ch(P,α,0)}] ≤ e^ε · Pr[0 = A^{Ch(P,α,1)}] + δ`. We fix `ε = 0` throughout; **strong
anonymity** is `δ = negl(η)`.

**The two notions we target.**
- `α_RA` (**receiver anonymity**): the challenge rows differ *only* in the recipient, `(u, R_0)` vs
  `(u, R_1)`; the sender `u` may be adversary-known or corrupt. This is exactly the NOSTOS threat: a
  peer that knows *who it is replying to as a pseudonym* must not learn *where*.
- `α_Rel` (**relationship anonymity**, the `M_SR` game, not the weaker `R_SR`): matched-vs-crossed
  sender–receiver pairs; identifying a single endpoint does not win.

We report the achieved rung in the Kuhn et al. (*PoPETs 2019*) hierarchy — receiver-side `RO̅`,
relationship-side `(SR)L̅` — to avoid the documented AnoA↔Kuhn naming trap (`α_SA ≡ SO̅`).

**The adversary class `C`.** A global passive network observer, plus *static* corruption of committee
members. **Corruption is counted in broken committees**, not nodes: a line hop is "broken" iff `≥ t`
of its `q+1` members are corrupt, which for corruption fraction `f < τ = t/(q+1)` happens with
probability `P_break ≤ exp(−(q+1)·D(τ‖f))` (T4). Write `c` for the number of broken committees on a
path; `c` is the honest-relay analogue that feeds the trilemma's compromise term.

**The new property `Sim_t` (below-threshold simulatability).** For every committee hop `C_i`
(`q+1` members, threshold `t`) and every coalition `S ⊂ C_i` with `|S| < t`, there is a simulator
`SimS` that, from public parameters alone, produces a distribution on `S`'s joint view (its members'
key material, the KEM-sealed shares it can open, the routed fragments, per-member timing) that is
indistinguishable from the real one. This is the object the packet-stratum hybrid substitutes for
"honest relay," and it is *not* a rung of the Kuhn hierarchy (which grades *what* is hidden) — it
widens the *adversary class* the guarantee holds against.

## 1. T1 — composite receiver anonymity, in three strata

### 1.1 Hop stratum — `Sim_t` for the FANOS threshold hop (information-theoretic core)

**Object.** A hop layer is a `ThresholdSealed` (`fanos-aphantos/threshold.rs`): the routing command
`m` (the next-hop line ‖ inner onion) is `AEAD(K, nonce, m)`; the key `K` is Shamir-shared
`t`-of-`(q+1)` as `{σ_1,…,σ_{q+1}}`; each `σ_j` is KEM-sealed to member `j`'s hybrid public key as
`Enc_j(σ_j)` (X25519 ‖ ML-KEM-768, IND-CCA).

**Lemma (Sim_t).** For any `S` with `|S| = s < t`, `S`'s joint view is simulable, with distinguishing
advantage `δ_hop ≤ (q+1−s)·Adv^{IND-CCA}_{KEM}(η)`.

*Proof.* `S`'s view is `({σ_j}_{j∈S}, {Enc_j(σ_j)}_{j∉S}, AEAD(K,nonce,m), nonce)`.
1. *(IT core — Shamir.)* The `s < t` shares `{σ_j}_{j∈S}` are, by Shamir's theorem, distributed
   **independently of `K`**: every value of `K` is consistent with exactly one degree-`(t−1)`
   polynomial through those `s` points. So `SimS` samples `{σ_j}_{j∈S}` as `s` uniform shares — a
   *perfect* simulation of this component, `δ = 0`.
2. *(Sealed honest shares.)* Replace each real `Enc_j(σ_j)` (`j ∉ S`) with `Enc_j(0)` by a standard
   hybrid over the `q+1−s` honest members; each step is bounded by `Adv^{IND-CCA}_{KEM}` (S cannot
   decapsulate `j ∉ S`'s slot, so it is a pure IND-CCA challenge). The simulator uses `Enc_j(0)`.
3. *(The AEAD command.)* Because step 1 fixed `S`'s shares independently of `K`, and step 2 removed
   the honest shares, `K` is now information-theoretically hidden from `S`; the simulator replaces
   `AEAD(K,nonce,m)` with `AEAD(K',nonce,0^{|m|})` for a fresh `K'` — indistinguishable by AEAD
   confidentiality, folded into the same `Adv^{IND-CCA}`-dominated bound (the AEAD key `K` is
   unrecoverable, so its ciphertext is pseudorandom).
The three hybrids compose to `δ_hop ≤ (q+1−s)·Adv^{IND-CCA}_{KEM}`. ∎

**Honest scope.** The *share-independence* is information-theoretic (Shamir); the *packet-level*
below-threshold secrecy is computational (IND-CCA), because the shares travel KEM-sealed, not in the
clear. This is exactly the design's stated scope — "per-hop below-threshold IT secrecy of the layer,
composed with computational onion security" — and is the honest reading of "no single-relay or
anytrust system offers this": no prior system has even the IT share-independence core at a *routing
hop*.

### 1.2 Packet stratum — forward and backward LU + TI over committee hops

**Target.** The Kuhn–Hofheinz–Rupp–Strufe (*ASIACRYPT 2021*, "Onion Routing with Replies") game-based
properties — forward and **backward** Layer-Unlinkability (LU) and Tail-Indistinguishability (TI) —
for the committee-generalized packet, which by the KHRS UC theorem imply the repliable-onion ideal
functionality.

**Reduction.** KHRS prove LU/TI by a hybrid that, at the *one honest relay* every path is assumed to
contain, replaces the real onion-crossing with an ideal (unlinkable) re-randomization. We substitute:
the "honest relay" hybrid step becomes a "committee with `< t` corrupt members" step, and `Sim_t`
(§1.1) supplies exactly the simulator that step needs — so each hybrid transition is bounded by
`δ_hop` instead of a single-relay CCA term. Every other part of the KHRS argument is untouched, so
their `games ⇒ ideal functionality` theorem carries over verbatim with `c` = broken committees in
place of corrupt relays.

**Two non-negotiable carry-overs.**
- *Implicit reply integrity.* An anonymous receiver cannot MAC a reply it does not yet know, and KHRS
  prove explicit MACs are insufficient — reply-payload malleability breaks anonymity (Kuhn–Beck–Strufe
  *S&P 2020*). NOSTOS's end-to-end AEAD *is* the implicit-integrity ingredient, and it lives **inside**
  this proof (a tampered dead-drop body fails the AEAD on open at `R`), not as a bolt-on lemma.
- *PQ assumption hygiene.* Scherer–Weis–Strufe (*PoPETs 2024*) proved DDH is insufficient for Sphinx
  (Gap-DH + a format fix required). The FANOS analogue is **IND-CCA + KEM anonymity/robustness** — the
  properties doing GDH's job — which the hybrid X25519 ‖ ML-KEM-768 KEM must (and, per the
  independent-crypto-audit, does) provide. We cite this, never an inherited DDH-era statement.

**Formalization status.** This is complete *modulo* writing the committee-generalized KHRS hybrids in
full — mechanical given §1.1, but not reproduced line-by-line here. Poly Onions (*TCC 2022*) supplies
the per-member CCA processing-oracle model and the single-run⇒multi-run composition lemma the write-up
uses.

### 1.3 End-to-end — `α_RA` and `α_Rel` IND-ANO

**Theorem T1.** The NOSTOS stack is `(0, δ)`-`α_RA` and `(0, δ)`-`α_Rel` IND-CDP with
`δ ≤ δ_stat(ℓ) + δ_comp(η) + δ_traffic`, where `δ_stat = Σ_{hops} 0` (Shamir-perfect share core),
`δ_comp = ℓ·(q+1)·Adv^{IND-CCA}_{KEM} + Adv_{AEAD}` (the packet stratum over `ℓ` hops), and
`δ_traffic` is the trilemma floor. Achieved rung: receiver-side `RO̅`, relationship-side `(SR)L̅`.

*Proof.* Compose §1.1 (each hop's below-threshold view is simulable) with §1.2 (the packet is LU+TI,
hence the ideal repliable-onion functionality) via the standard onion composition: an adversary
winning `α_RA` against the real stack wins against the ideal functionality with the same advantage up
to `δ_comp`, and against the ideal functionality the recipient bit `R_0`/`R_1` is hidden except for
the traffic term. The recipient's dead-drop delivery contributes only the `q+1` geometric anonymity
set (T2), which is `≥ 1` and folds into `δ_traffic`. ∎

**The trilemma budget is inside T1** so §1.1's IT core is never misread as beating it. `δ_traffic`
obeys Das et al. *S&P 2018* regardless of the strata above; for the **receiver leg** the constant is
**4** (`4ℓβ < 1 − ε`), the candidate window spanning `ℓ−1` rounds *both* sides of the challenge send.
So NOSTOS achieves strong `α_RA` only in a parameter regime with `4ℓβ ≥ 1` — i.e. the MIX lane must
actually spend cover `β` and delay `ℓ` (Loopix `λ/μ ≥ 2`, `≥ 3` layers). The FAST lane, which sets
`β = 0, ℓ = O(1)`, is *provably* not strongly anonymous — as designed. We budget `4ℓβ` and do not
architecturally depend on the Kuhn–Kitzing–Strufe (*WPES 2020*) conjecture that it tightens to `2ℓβ`.

## 2. T2 — blinded-rendezvous anonymity (complete)

**Setup.** The dead-drop line is `L = select_drop_line(R, s, epoch, beacon)`, the `i`-th of the `q+1`
lines through `R` with `i = H(s ‖ epoch ‖ beacon) mod (q+1)`; `R = MapToPoint(VRF(sk_R, id ‖ epoch ‖
beacon))`.

**Theorem T2.** Against an observer outside `L` who does not hold `s` or `sk_R`, the probability of
identifying `R` among `points_on(L)` in one epoch is `≤ 1/(q+1) + Adv_{VRF}(η)`, and deliveries in
distinct epochs are unlinkable up to `Adv_{VRF}(η)`.

*Proof.* An observer sees a delivery routed to `L`; `R ∈ points_on(L)`, a set of size `q+1`.
- *Within an epoch.* Without `s`, the index `i` is a fresh hash output; without `sk_R`, `R` itself is
  a VRF image. A distinguisher that identifies `R` among the `q+1` members with advantage `> 1/(q+1)`
  yields, by a standard reduction, a distinguisher against VRF pseudorandomness (predicting
  `MapToPoint(VRF(sk_R,·))` better than guessing) — bounding the advantage by `Adv_{VRF}`.
- *Across epochs.* `R` and `L` both rotate: `R_e = MapToPoint(VRF(sk_R, id ‖ e ‖ beacon_e))`. Linking
  two epochs' deliveries as the same receiver reduces to distinguishing two VRF output sequences from
  independent uniform ones — again `Adv_{VRF}`.
- *The Gnilke collusion caveat is discharged.* The unique-meet incidence that broke UPIR (*DCC 2019*)
  is defused because **two** rendezvous inputs are blinded — `R` (needs `sk_R`) and `i` (needs `s`) —
  so no party outside `{holder of s} ∩ {holder of sk_R}` can compute `L` from public data. This is the
  design's "at least one input beacon-blinded" precondition, met with margin. ∎

The `1/(q+1)` term is the honest geometric floor — the anonymity set is exactly the line's members,
and no cryptographic assumption shrinks it below `q+1`; scaling `q` grows it.

## 3. T3 — intersection resistance from threshold-gated rotation (core proven, bound residual)

**Claim.** Unbiasable per-epoch coordinate rotation *lowers*, not raises, the long-term `α_RA`
advantage — the non-trivial direction, because naive rotation is double-edged (predecessor attack,
*WPES 2012*; high-volume-flow fragility, *When Mixnets Fail*, *NDSS 2025*).

**Proven core (the §3a inequality).** The predecessor attack's per-epoch gain — the probability a
fresh adversarial draw both lands on the flow's current hop *and* compromises it — is, on a
single-relay moving target, the corruption fraction `f`. On a FANOS **threshold** hop the same fresh
draw compromises the hop only if it pushes the line to `≥ t` corrupt, i.e. with probability
`P_break = Pr[Bin(q+1,f) ≥ t] ≤ exp(−(q+1)·D(τ‖f))` (T4, proven in code). Therefore the threshold hop
**attenuates each rotation's predecessor gain by an exponential factor** `P_break / f`. This is exact
and machine-checked (`chernoff_break_bound`, `5806d34`).

**Residual (the statistical-disclosure benefit).** T3 is net-positive iff the *intersection benefit*
of rotation — the increase in the number of epochs an attacker must observe before the receiver's line
is pinned by a statistical-disclosure attack (SDA, Danezis) — exceeds the exponentially-attenuated
predecessor cost. Bounding the SDA sample complexity for the geometric dead-drop (how many epochs of
`points_on(L_e)` observations collapse the candidate identity set) is the open analytic step; the
mechanism is built and the predecessor side is proven, so the residual is a *quantitative* bound, not
a design question. We state it plainly rather than assert the inequality: **the tuning knob**, if it is
ever tight, is a bounded membership-churn cadence (rotate the coordinate, keep line membership
churn-limited within a community, à la Poly Onions' churn bound).

## 4. T4 — the Anytrust-escape (proven in code)

`P_break ≤ exp(−(q+1)·D(τ‖f))` for `f < τ`, and the exact tail is dominated by it, exponentially
small in `q`. **Proven and verified**: `fanos-nyx::security::{kl_divergence, chernoff_break_bound}`,
tested to dominate `hop_compromise` across a grid of cells and to decay exponentially in cell size
(commit `5806d34`). Consequence: `c_eff ≈ ℓ·P_break ≈ 0` w.h.p., so the compromise-degraded trilemma
bound `2(ℓ−c)β` collapses to the honest-network `2ℓβ` (sender) / `4ℓβ` (receiver), and FANOS never
enters the Anytrust `√K` regime. This does **not** repeal the trilemma — the MIX lane still spends
real `βℓ`; it converts a node-level corruption budget into an exponentially-safer line-level threshold
budget.

## 5. T5 — POROS sustainable-frontier ingress (core proven, censor-model residual)

**Claim.** The beacon-blinded, threshold-hosted ingress keeps the censorship burn rate
`β = λ_disc/λ_intro < 1` for a modeled censor (so, by Block-A-Mole's `A ≤ 1/β`, availability is not
forced below 1), subject to the Mahdian `Ω(t)` insider floor, with the residual localized to a single
out-of-band seed.

**Proven core.**
- *`λ_intro` (introduction rate).* The ingress line `f(beacon, community-secret, VRF-identity)` rotates
  **every epoch** (unbiasable beacon), so the defender introduces a fresh, unpredictable endpoint each
  epoch with no manual action — `λ_intro ≥ 1/epoch`, at zero marginal cost.
- *`λ_disc` (discovery rate) is threshold-priced.* To *serve-and-seize* an epoch's ingress a censor
  must obtain the descriptor, which is Shamir-`t`-of-`(q+1)`-hosted (POROS increment 1–2): seizing
  `< t` line members yields nothing (§1.1's Shamir core applies to the descriptor sharing verbatim), so
  discovery costs `≥ t` seizures **per epoch**, and any single enumeration is capped to one epoch by
  rotation. Non-transferable admission (the VRF-identity-bound PoW) prevents credential reuse from
  amortizing this.
- Hence `λ_disc ≤ (censor seizure rate)/t`, and for a censor whose per-epoch seizure budget is `< t`
  (the Mahdian regime where keeping `t` small is load-bearing), `λ_disc < λ_intro`, i.e. `β < 1`.

**Residual (stated plainly, as the frontier does).**
1. *The Mahdian `Ω(t)` floor.* Anyone admitted who can *compute* coordinates can block them at the
   `t·(1+⌈log(n/t)⌉)` rate (*FUN 2010*) — so keeping `t` small is mandatory, which is why the Sybil
   **cap** (not the PoW rate-limiter) is required: a fast-mixing trust graph (SybilLimit `O(log n)`/edge)
   or personhood. That anchor is designed but not yet built; without it, `β < 1` holds only against a
   *rate-limited*, not *capped*, adversary. This is the honest boundary of the current proof.
2. *The out-of-band seed.* A brand-new node with no beacon and no peer needs one unblockable carrier to
   receive the first beacon + community secret. This is information-theoretically irreducible for *any*
   circumvention system (SoK-Spectre, *PoPETs 2025*); POROS minimizes it (PROTEUS obfuscation, diverse
   high-collateral carriers), it does not eliminate it.

## 6. Summary — what is proven, what a full formalization still needs

| Theorem | Status |
|---|---|
| **T4** (Anytrust-escape) | **Proven in code** (`5806d34`), machine-verified against the exact tail. |
| **T2** (blinded rendezvous) | **Complete** — reduction to VRF pseudorandomness; `q+1` geometric floor; Gnilke caveat discharged by two blinds. |
| **T1** (receiver anonymity) | Hop stratum **proven** (`Sim_t`, Shamir IT core + IND-CCA). Packet + E2E **complete modulo** writing the committee-generalized KHRS hybrids in full. |
| **T3** (intersection resistance) | Predecessor side **proven** (exponential attenuation via T4). Net-positivity awaits an **SDA sample-complexity bound** — quantitative, not architectural. |
| **T5** (POROS frontier) | `λ_intro`/`λ_disc` threshold-pricing **proven**. `β < 1` holds against a rate-limited censor; the **capped**-censor case awaits the trust-graph/personhood Sybil anchor. |

The two genuine open items — the SDA bound (T3) and the Sybil-cap anchor (T5) — are the same two
implementation residuals recorded for POROS increment 3, so the theory and the code converge on
exactly the same frontier. Nothing here repeals the Anonymity Trilemma or the censorship residual;
each theorem places FANOS at the best point its governing impossibility allows, with a per-hop
below-threshold guarantee no single-relay or anytrust system provides.
