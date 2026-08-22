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

### And here is what *names* one — `fanos_geometry::CellPath` (2026-08-21)

The decision above says what a cell **is**; nothing said what it is **called**, and every cross-cell surface was keyed by
a flat `cell: u32`. That is why `crosscell_dir`'s module doc recorded a design step nobody could take: `federation::CHILDREN`
is 7 while a plane holds `cells_in()` cells — 1 at `q = 2`, 3 at `q = 4`, **39** at `q = 16` — so *"at `q = 16` there are 39
and nothing says which seven"*.

**The seven are seats, not cells, and that dissolves it.** A cell is named by the pair

> `CellPath = (the parent's address, which Fano cell of the level below it)`

where the parent's address is a `HierAddr` path (empty for the base cell) and the second half is `fano::cell_of` of any
member's seat. So a parent at address `P` has `cells_in()` **child cells**, each with exactly `fano::N = 7` seats, and the
covering runs once per child cell: once at `q = 2`, three times at `q = 4`, thirty-nine times at `q = 16`. Nothing has to
pick seven of anything, and `diagnose_level`'s `[f64; 7]` is the shape of *one child cell*.

Three consequences, each of which was previously a blocker:

* **Enumeration needs no directory.** A parent's children are `P ++ [s]` over the seven seats `s`
  (`CellPath::member_address`), derived from its own address and the plane. `crosscell_dir::attest_children` had no caller
  because nothing could tell it *whose* certificates to read; now the answer is a pure function.
* **A child and a grandchild stop colliding.** Keyed by `u32`, a parent's child `0` and its grandchild `0` are one
  registry entry — a merge that ends with a certificate verified against the wrong committee. `CellPath::encode` is
  injective in both the prefix and the index (`a_prefix_separates_cells_a_flat_index_would_merge`).
* **#167 has its missing input.** `fanos_runtime`'s `cell_id` folds the genesis seed and the plane's points, and says so
  itself: *"two cells of the same deployment still collide, because the runtime has no identity above the base cell to
  fold in"*. This is that identity.

A plane that holds no Fano cell (`7 ∤ N`, so `q ∈ {7, 8, 31}`) names none, from both doors — the constructor and the
decoder — because a directory keyed by a name no member can claim is a directory nobody will ever read.

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

## Authenticating a sub-cell's records — the bridge is a recomputation, not a new envelope

`crosscell_dir::{resolve_committee, diagnose_children}` refused `cell.level() > 1` for a release: a seat's
record is opened by an `Entitlement` against *the seat's own coordinate*, and a descended node **keeps its
transport coordinate** (`on_descend`), so its entitlement proves a point unrelated to the seat it occupies.

That refusal's own note proposed carrying the §80 descriptor signature. That was half of what is needed, and
the other half needs no cryptography at all — which is why what shipped (`Entitlement::open_at_seat`) is
smaller than the note expected:

1. **Seat membership is RECOMPUTABLE.** `fanos_quic::identity::coordinate_at_level(cert_der, level)` is a
   pure function of the certificate (`fanos_primitives::address_point`). A reader holding the record's
   certificate re-derives the publisher's coordinate at *every* level and compares it against the `CellPath`
   prefix it is reading. If the identity hashes to this path, this path **is** its seat — no proof, no
   signature, no extra bytes.
2. **Key possession is what the entitlement already proves.** The VRF proof in the record is producible only
   by the holder of the secret, so a record is not forgeable by anyone who has merely *seen* the certificate
   — which matters precisely because the descent half is public. (The §80 descriptor signature the original
   note reached for binds a transport *address*; the seat never was a claim about the transport point, so it
   is not what this needed.)

**What this deliberately does not prove is the DEPTH.** `hierarchical_coordinate` descends while its
`occupied` predicate reports the level full — local knowledge, unverifiable remotely — so a node can publish
at a seat deeper than it occupies. That is a liveness claim about an absent node, and absence is already a
fault under the nesting model decided above, with the parent's sampling as its instrument. It is detected
rather than trusted, which is the same standing every other absence has here.

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
