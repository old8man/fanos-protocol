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

## What a "child cell" is, given that addressing builds a trie of **nodes** — DECIDED

This note and `fanos_geometry::hierarchy` describe two structures, and until they are read together the
recursion above has no input. Addressing builds a **trie of nodes**: `derive_address` keeps the shortest
prefix its identity-derived candidate finds free, *"never shadowing the occupant"*, so `[p]` is one node and
`[p, s]` are other nodes. Diagnosis, here and in `design-taxis.md` §7, expects a **tree of cells**: *"the
recursion-of-cells (§L1) makes each node of a parent cell a child cell"*. A trie is not a tree of cells, and
nothing in the code turns one into the other — which is why `federation::diagnose_cell`'s input side is
unfed and `crosscell_dir::spawn_health_publisher` has no callers.

**The decision: the trie is the structure, and a cell is a sibling-set.**

> A **cell** at prefix `P` is the set of nodes at `P ++ [s]` for the points `s` of the plane — at most seven
> at `q = 2`. Its **parent** is the single node holding `P` itself. So every node is both a *member* of the
> cell of its siblings and the *parent* of the cell of its children, and the base cell (`P` empty) is the
> plane's own occupants, which is the case that ships.

This needs no change to any covering: `diagnose_level` already takes `child_losses: &[f64; fano::N]`, and
under this reading those seven values are the seven siblings' subtree aggregates. It also matches how the
trie is actually built — the nodes at `[p, *]` are exactly the ones that wanted `p` and lost it, so "the
cell under `p`" is a set with a cause, not a labelling imposed on top.

**Why not the other way round.** Making a *cell* rather than a node occupy a parent's point would require
agreement on that cell's membership before any node could be placed — and placement is the one thing this
platform derives rather than negotiates (`derive_address`'s own summary: *"conflict-free, no
negotiation"*, and #145's `cell_of` for the same reason one layer down). It would trade the property that
makes descent work for a structure the covering does not need.

**The one obligation this creates, and it is the missing wire.** A node must report its **subtree's**
aggregate upward, not its own reading. `cell_loss(children)` — worst member — is already that function;
what has no caller is anything that feeds a node's own children's reports into it and publishes the result
at the level above. `OverlayNode::cell_liveness` returns this node's view of its seven *siblings*, which is
the right input for the level it sits at and the wrong one to send up.

**Why one representative is not a single point of trust.** The parent of a cell is one node, so it alone
speaks for its subtree — and it is not unchecked: it is itself one of its own parent's children, and a
representative that misreports is exactly a child whose loss is inconsistent with its links, which
`localize_failing_child` localizes by the same grey endpoint one level up. A lie about a subtree is
therefore the *same observable* as a failure in it, which is the property that lets the recursion stay
uniform instead of needing a committee signature per level.

**The honest limit, and it is the sparse-cell one.** The grey endpoint separates a failing child from
honest ones because *"an honest child keeps ≥ 1 low-loss link to another honest child"* — so localization
needs at least two honest siblings. A cell at the descent frontier is sparse by construction (a cell at
depth `d` receives `n / 7^d` nodes), and a cell with fewer than three occupied points cannot localize
anything, whatever the arithmetic says. So this decision fixes the *structure*; it does not make diagnosis
available everywhere in the tree, and a deployment should expect it at the levels that are full.

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
