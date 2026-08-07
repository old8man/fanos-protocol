# The D6 quarantine theorem (closing the missing DIAKRISIS healing guarantee)

> The DIAKRISIS healing plan (`fanos-diakrisis::plan`) offers a **Quarantine** action — excise a structurally
> inconsistent member — but the corpus supplies **no theorem** for it (a documented correction: *"Decouple
> lowers Φ; no quarantine theorem"*). So quarantine was applied without a proven effect on coherence, unlike
> Reroute (`Φ → Φ/9` per hop, V16) and Decouple (sheds a correlation edge, lowers Φ). This note derives the
> missing theorem — an *exact* condition and closed form — and validates it by simulation
> (`coherence.rs::quarantine_experiment`).

## Setup

A cell of `N` nodes has a symmetric, unit-diagonal correlation matrix `C`; `Γ = C/N` with `Tr Γ = 1`.
Integration is `Φ = Σ_{i≠j} γ_ij² / Σ_i γ_ii²`, which the implementation computes as
`Φ = (frob − N)/N`, where `frob = Σ_{i,j} C_ij²` (so the off-diagonal energy is `OffDiag = frob − N = N·Φ`,
the diagonal being `N`). Define node `q`'s **coupling energy**

```
s_q = Σ_{j≠q} C_qj²      (its share of the off-diagonal energy).
```

Because each `C_ij²` (`i≠j`) appears in both `s_i` and `s_j`, `Σ_q s_q = OffDiag = N·Φ`, so the **mean coupling
energy is exactly `Φ`**.

## Theorem (quarantine effect on integration)

> **Theorem (D6).** Quarantining node `q` — excising its row and column — yields a cell of `N−1` nodes with
> integration
> ```
> Φ' = (N·Φ − 2·s_q) / (N − 1).
> ```
> Consequently `Φ' < Φ` **iff** `s_q > Φ/2`, `Φ' = Φ` iff `s_q = Φ/2`, and `Φ' > Φ` iff `s_q < Φ/2`.

**Proof.** Removing `q` drops from `frob` the diagonal `C_qq² = 1` and both off-diagonal legs `Σ_{j≠q}(C_qj² +
C_jq²) = 2 s_q` (symmetry), so `frob' = frob − 1 − 2 s_q` over `N' = N−1` nodes. Hence
```
Φ' = (frob' − N') / N' = (frob − 1 − 2 s_q − (N−1)) / (N−1) = (frob − N − 2 s_q)/(N−1) = (N·Φ − 2 s_q)/(N−1),
```
using `frob − N = N·Φ`. For the inequality, `Φ' < Φ ⇔ N·Φ − 2 s_q < (N−1)·Φ ⇔ Φ < 2 s_q ⇔ s_q > Φ/2`. ∎

## Reading — why this is the right guarantee

- **When quarantine heals.** `Φ' < Φ` exactly when `s_q > Φ/2`, i.e. when `q`'s coupling energy exceeds half
  the cell integration. A **structurally inconsistent / Byzantine** node — one whose behaviour spuriously
  tracks or mirrors the cell to appear live (the polar-inconsistency DIAKRISIS localizes, §6.4) — carries
  *high* coupling energy, so it satisfies `s_q > Φ/2` and quarantine provably reduces integration toward the
  healthy band. This is the theorem the Quarantine action needed.
- **When quarantine would harm.** An *under-coupled* node (a silent or isolated member, `s_q < Φ/2`) has `Φ'
  > Φ`: removing it concentrates the remaining correlation and **raises** integration. `quarantine_lowers_phi`
  is exactly the predicate `s_q > Φ/2`, and it is the condition a **coherence-motivated** excision must
  respect. Read §"What this theorem does *not* govern" before installing it anywhere.
- **Relation to Decouple.** Decouple removes a single edge (`one C_ij²`); quarantine removes a node — *all* its
  edges (`2 s_q` of off-diagonal energy) and one diagonal, over a shrunk `N`. Quarantine is thus a *structural
  Decouple*, and D6 is its quantitative law: the same "shed correlation to lower Φ" principle, now exact for
  whole-node excision, and — unlike Decouple — with a two-sided condition, because shrinking `N` can work
  against the removal when the node is weakly coupled.

## The experiment (`coherence.rs::quarantine_experiment`)

Deterministic, over many random symmetric unit-diagonal matrices and every node:
- **closed form = recompute** — `phi_after_quarantine(q)` equals `excise(q).phi()` to `1e-9` (the O(N) law
  matches the O(N²) full recompute);
- **condition is exact** — `quarantine_lowers_phi(q)` agrees with the sign of `excise(q).phi() − phi()` in
  every case, including the boundary;
- **Byzantine vs. silent** — a synthetic over-coupled ("Byzantine") node is confirmed to have `s_q > Φ/2` and
  its quarantine lowers Φ, while a synthetic isolated node has `s_q < Φ/2` and its quarantine raises Φ — the
  **predicate** keeps the first and rejects the second. (An earlier revision of this line said *"the planner's
  gate"*. The planner has no gate; the experiment exercises `quarantine_lowers_phi` directly, and the next
  section says why the planner is right not to call it.)

This closes the gap: Quarantine now has the same kind of proven, experimentally-validated coherence guarantee
that Reroute and Decouple already carry.

## What this theorem does *not* govern — and the hole that installing it would open

D6 is a law about **what excision does to integration**. It is therefore the right gate for a quarantine
chosen *in order to lower Φ*. **There is no such quarantine in FANOS.** Every emitter is a security action:

| site | driven by | kind |
|---|---|---|
| `plan.rs`, `Verdict::Structural` arm | a polar sum-rule violation — proven equivocation (§6.4) | security |
| `healer.rs`, `polar::fabricators_by_persistent_freshness` | a colluding vouch-fabricator keeping a dead node believed-alive | security |
| `overlay`, `Command::Quarantine` | the driver's identity-keyed distrust, re-applied across a reseat (audit R-M1) | security |

So `plan_healing` emitting `Quarantine` unconditionally is **correct**, and gating it on
`quarantine_lowers_phi` would be a defect. The bullet above assumes a Byzantine node *"spuriously tracks or
mirrors the cell to appear live"* and therefore carries high coupling energy — but that is a **modelling
assumption about the adversary, enforced nowhere**, and the two quantities come from independent inputs:

* `s_q` is read from the measured **relay-activity** correlation matrix (`BehaviorMonitor::coherence`);
* a `Verdict::Structural` is read from the **polar cross-attestation** sum rules, over gossiped `DiagAttest`
  reports.

An adversary that equivocates in its attestations *while relaying little traffic* is therefore simultaneously
**proven inconsistent** and **under-coupled**. With the gate installed the planner would refuse to quarantine
it — an evasion reachable by doing *less* work rather than more, and a coherence metric overruling proof.

**The rule.** A metric may decide *whether an excision helps*; it may never decide *whether evidence counts*.
When a coherence-motivated excision is finally built, gate that one on `quarantine_lowers_phi` — and say at
its call site that the security quarantines above are deliberately outside it.
