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
  > Φ`: removing it concentrates the remaining correlation and **raises** integration. The theorem forbids
  quarantining such a node — a genuine, non-obvious safety condition the healing planner must respect
  (`quarantine_lowers_phi` gates on exactly `s_q > Φ/2`).
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
  planner's gate keeps the first and rejects the second.

This closes the gap: Quarantine now has the same kind of proven, experimentally-validated coherence guarantee
that Reroute and Decouple already carry.
