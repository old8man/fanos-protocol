# Parent-observes-child DIAKRISIS recursion (closing the #95 deeper-recursion residual)

> The §6.5 partition sensor diagnoses *within* a cell. The residual (#95, hierarchy-vrf map) was the
> **parent side**: a parent cell running DIAKRISIS over its child cells recursively. This note closes it —
> the diagnosis is scale-invariant, so the identical machinery runs one level up with child cells as its
> "nodes" (`fanos-diakrisis::hierarchy`), validated by a two-level recursion experiment.

## The recursion

The base cell diagnoses `N = 7` **nodes** from (a) their **activity** signals → the coherence matrix `Γ`,
integration `Φ`, and the leading-indicator alarm; and (b) their **per-neighbour loss** → the §6.3 grey
endpoint that localizes a failing node. The recursion-of-cells (§L1) makes each node of a parent cell a
**child cell**, so at the parent level:

- **`parent_coherence(child_activity)`** builds `Γ` from the children's activity signals — the *same*
  `CoherenceMatrix::from_signals`. The parent's `Φ` measures how bound its sub-cells are; the leading-indicator
  alarm (`Φ < 1` before `P < 2/N`) recurses unchanged, so a parent's `Φ < 1` is its escalation trigger.
- **`inter_child_loss(child_losses)`** forms the parent's loss matrix, `loss(i,j) = max(loss_i, loss_j)` (a
  link is as lossy as its worse child), and **`localize_failing_child`** runs the *same* `grey_endpoint`: a
  failing child is lossy on all its links; an honest child keeps ≥ 1 low-loss link (to another honest child),
  so the grey child is unambiguous.
- **`cell_loss(children)`** aggregates a cell's loss as its worst member, so a fault **propagates up**: a
  parent carrying a failing grandchild reads high loss, which its own parent then localizes — the diagnosis
  composes to any depth (`diagnose_level`).

## Why scale-invariance holds — and the honest caveat

The projective structure is identical at every level (`S(2,3,7)` for `q = 2`), so the localization pyramid
`21 → 7 → 3 → 1`, the polar sum-rules, and the leading-indicator theorem apply verbatim to the parent's
7-child cell. The *arithmetic* (Φ, the grey endpoint, the sum-rules) is exact at every level.

The **one model assumption** — the same class as the existing `[И]` axis↔sector dictionary (§6.10) — is that a
child cell's *aggregate* loss is a faithful "node loss" for the parent (`cell_loss` = worst member). It is
**self-checking**: a wrong aggregation breaks the parent's polar sum-rules exactly as a wrong node-signal
breaks the base cell's, so a mis-modelled level is detectable. But it is a model, not a theorem — stated here
as honestly as the spec states the base-level dictionary caveat.

## Experiment (`hierarchy::tests`)

- A parent localizes its one failing child (loss 0.8 vs 0.05) by the grey endpoint; an all-healthy parent
  localizes none.
- **Two-level recursion**: a failing grandchild is localized by its parent; the parent's `cell_loss` rises;
  the grandparent, running the *same* `localize_failing_child`, localizes the faulty parent — the fault and
  its localization recurse verbatim.
- The **integration alarm recurses**: children whose activity moves together integrate the parent (`Φ ≥ 1`,
  no escalation); independent children leave it un-integrated (`Φ < 1`) and escalation tracks that leading
  indicator.

This closes #95's parent-observes-child recursion: DIAKRISIS now runs up the hierarchy, not only within a
cell, with the same proven arithmetic and one honestly-flagged aggregation model.
