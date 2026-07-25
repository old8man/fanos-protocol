# ERGON — the FANOS execution model

> ἔργον — *work, deed, that which is done.*
>
> A transaction is not a program. It is a **claim about a state transition, accompanied by evidence.** The evidence is
> either a bounded total term the validator re-executes, or a proof it verifies. There is one model and two evidence
> regimes, and that is the whole design.

Status discipline follows the SYNARC-Ω convention: **[D]** definition/contract, **[T]** theorem, **[C]** convention,
**[P]** deployment obligation or open refinement.

This document supersedes the fixed eight-tag dispatch in `fanos-dromos::hybrid`. It is written to be coherent with three
things at once: the FANOS protocol (`spec/protocol.md`, `spec/platform.md`), the DROMOS parallel executor
(`docs/design-dromos.md`), and the **SYNARC-Ω** specification the platform's ontology comes from
(`uhm-theory/holon/internal/synarc-omega/paper`). Where a design choice is *imported* from SYNARC-Ω rather than invented
here, the appendix and theorem are cited, because the point of the exercise is that the same ontology governs both.

---

## 0. The problem, stated honestly

The ledger today applies eight hardcoded transaction kinds (`TAG_TRANSPARENT` … `TAG_SLASH`). Each has its own decoder
and its own state-transition rule. This buys three real things:

1. **Exact access lists.** Every kind's footprint is known statically, which is what makes DROMOS's conflict-DAG
   scheduler work at all — a wave is conflict-free because footprints are known *before* execution.
2. **No gas economy and no halting problem.** Every rule is O(1) and total.
3. **No reentrancy class.** There is no call, so there is nothing to re-enter.

And it costs one thing that matters: **new application logic requires a new tag and a protocol release.** That is a trade
of programmability for verifiability, and stated that way it sounds unavoidable. It is not. The trade is an artefact of
assuming that programmability means *running programs*.

The rest of this document derives what programmability means when the ontology, not convenience, chooses.

---

## 1. Why not a VM — the analysis, not the prejudice

Four candidate models, evaluated against what FANOS already requires.

| model | expressiveness | access lists | termination | conflict class |
|---|---|---|---|---|
| EVM-style stack VM + gas | Turing-complete | **destroyed** (dynamic dispatch, `SLOAD` on computed keys) | metered, not proven | reentrancy |
| WASM + metering | Turing-complete | destroyed identically | metered | reentrancy |
| Move-style resources | Turing-complete | partial (dynamic borrows) | metered | narrowed, not removed |
| **effect term algebra** | see §5 | **exact, derived** | **structural** | none by construction |

The decisive column is the second, and the reason is not aesthetic. DROMOS's parallelism is the platform's headline
throughput claim, and it rests on a *statically computable* footprint per transaction. A VM whose storage keys are
computed at run time makes the footprint undecidable before execution, so the scheduler must either over-approximate
(everything conflicts → serial execution, the claim evaporates) or speculate and roll back (Block-STM: real, but it trades
determinism-by-construction for determinism-by-retry, and re-introduces the abort/retry economics that gas exists to
price). Adopting a VM does not *add* expressiveness to FANOS; it **spends** an existing structural property to buy a
familiar one.

The third column is the second reason. Gas is not a cost model — it is a *bound on a computation whose termination you
could not prove*. It exists because the halting problem does. A model whose terms are structurally finite needs no gas,
and §4 shows the platform's own ontology already fixes the bound.

---

## 2. What the ontology dictates

Six imports from SYNARC-Ω. These are not analogies; they are the same contracts read at the ledger level, and each one
answers a question the execution model must answer anyway.

### 2.1 Composition depth is bounded at three, and growth is horizontal [T]

**Theorem K.5 (T-Composition-Ceiling).** The order-`m` purity threshold scales as

```
P_crit^[m] = P_crit · 3^(m-1) / (m+1),        P_crit = 2/7
```

giving `P_crit^[1] = 1/7` (a first-order self-model is free), `P_crit^[2] = 2/7` (baseline), `P_crit^[3] = 9/14`, and

```
P_crit^[4] = (2/7)·(27/5) = 54/35 > 1
```

— exceeding the mathematical maximum. A fourth-order composite is **arithmetically foreclosed**. Unbounded growth is
available only *horizontally*: more blocks, more organisms, richer federation.

**What this settles.** The question "how deep may a composition nest?" has a derived answer — **three** — and it is not a
resource limit that could be raised by buying hardware. So ERGON caps *vertical* composition at 3 and makes
expressiveness *horizontal*: unbounded breadth of composed effects at a level, bounded nesting across levels. This is the
same shape as the certified-horizon bound of Corollary U.3 (plans of depth `k ≤ k* = ⌊r_stab/δ⌋` are sound; deeper is
uncertified, not forbidden), and it is why ERGON needs no gas: **the only unbounded axis is one where each additional unit
of work declares its own footprint and is therefore priceable in advance.**

### 2.2 Admission is a port predicate, checked before execution [D]

**Definition U.7** gives the goal write-port an admissibility predicate `Adm(C)`, checked *at the port*: "the agent cannot
be *tasked* into a nonviable target — assigning a dead state is rejected at the port, not discovered in operation."

**What this settles.** A transaction's declared post-state is checked for viability **before** it executes, not by running
it and observing failure. This inverts the gas model's epistemology: instead of *discovering* that a computation was
invalid after paying for it, ERGON *refuses* it at admission. §6 gives the predicate.

### 2.3 Composition is a gate, not a message; the parent dominates lexicographically [D]

**Definition U.14 (B1–B3)** for composed holons: (B1) each block owns its own preference — a parent's goal is *not*
written into children; inter-level influence passes **only through a gate**. (B2) children's proposed acts compose through
the *parent's* safety filter, so safety composes downward by construction. (B3) conflicts resolve **lexicographically** —
parent viability dominates child preference.

**What this settles.** Composition semantics. A composite effect does not *call* its parts and does not pass them state to
mutate; it **gates** them on a predicate over their own footprints, and the parent's invariants clamp the children's
effects. That is precisely why there is no reentrancy: a child never re-enters a parent, because influence flows only
downward and only through a gate. B3 gives conflict resolution inside a composite: the outer invariant wins.

### 2.4 Effects are hull-bounded [T]

**Lemma U.5 (hull-boundedness).** For *any* feedback sequence, including an adversarially corrupted one, the inferred goal
is a convex combination of *actually visited* states. "A corrupted reward channel can re-weight the agent's experience but
can never point the agent at a state outside its own history; no unbounded 'wirehead' gradient exists anywhere in the
architecture."

**What this settles.** The strongest available safety class for a hostile input: not "we check for bad transactions" but
"a bad transaction cannot express the dangerous thing." ERGON's primitive effects are chosen so that every well-typed term
maps reachable ledger states to reachable ledger states — value-conserving, supply-preserving, nullifier-monotone — so
adversarial *composition* can only reorder or reweight legitimate transitions. §7 states this as the closure theorem.

### 2.5 Effects are typed by what they touch [D]

**Definition U.8 (effector taxonomy).** *State-actuating* effectors are guarded by the mathematics; *symbol-emitting*
effectors have world-effects that are "semantic and invisible at Γ-granularity" and require a screen **outside** the
mathematical core — a deployment obligation [P], not a theorem.

**What this settles.** The type discipline, and an honest boundary. ERGON effects that mutate ledger state are fully
governed by the algebra. Effects whose consequence is *outside* the ledger — a storage-provider payout that triggers an
off-chain obligation, a cross-chain HTLC whose counterparty is another chain — are `Extern` effects, and the algebra
guards their *ledger* consequence only. That is recorded as [P], the same residual class the ASI spec assigns.

### 2.6 State identity is a hash-chained history, and eviction is by redundancy [D]

**Definition U.13:** identity "is its hash-chained `MeasureFrame` history, not its hardware", with a **single-activation
invariant** — at most one activation of a lineage at a time. **Definition U.12:** eviction is by *redundancy*, not
recency: an object may be evicted iff it is reconstructible from what remains, within tolerance.

**What this settles.** Two things ERGON would otherwise have had to invent. First, a stateful object's on-chain identity
is its history hash, and the single-activation invariant *is* the double-spend rule, generalised from value to arbitrary
state — OBOLOS's nullifier is the instance, not the concept. Second, the state-pruning rule: prune what is *re-derivable*
from what remains, never what is merely old.

---

## 3. The model

An ERGON transaction is a **term**:

```
Term ::= Effect                          -- a primitive
       | Seq   [Term]                    -- all, in order, atomically
       | Par   [Term]                    -- all, footprint-disjoint, order-irrelevant
       | Gate  Predicate Term            -- run the term iff the predicate holds of the pre-state
       | Alt   [(Predicate, Term)]       -- first predicate that holds; deterministic by order
       | Prove Claim Proof               -- an off-chain computation, verified not re-executed
```

with a **footprint** derived by structural induction, never declared:

```
fp(Effect e)        = (reads(e), writes(e))            -- from e's type
fp(Seq ts)          = ⋃ fp(t)                          -- union
fp(Par ts)          = ⋃ fp(t), well-typed iff pairwise disjoint on writes
fp(Gate p t)        = fp(t) ∪ (reads(p), ∅)
fp(Alt bs)          = ⋃ over branches (the union, not the taken branch — see below)
fp(Prove c _)       = (c.reads, c.writes)              -- declared in the claim AND proven
```

`fp(Alt)` unions over *all* branches rather than the taken one. That is deliberate and it is the one place ERGON pays for
determinism: the scheduler must know the footprint before it knows which branch runs, so a conditional's footprint is its
worst case. The alternative — schedule after evaluating the guard — would make the schedule depend on state the scheduler
has not yet reached, and the schedule must be a pure function of the ordered transactions (DROMOS's load-bearing
determinism property). Cost is over-approximated conflict for branchy terms; the mitigation is `Gate` (one branch, exact
footprint) wherever a two-sided `Alt` is not genuinely needed.

**Depth.** `depth(Effect) = 0`; `depth(Seq/Par/Gate/Alt) = 1 + max depth of children`; `depth(Prove) = 0` (the proof is
opaque — its internal depth is the prover's problem, not the verifier's). Well-typedness requires

```
depth(t) ≤ D_MAX = 3
```

by §2.1. Not a configuration knob: `P_crit^[4] > 1`.

---

## 4. Why this needs no gas [T]

**Proposition.** For any well-typed term `t`, the validator's execution cost is a pure function of `t` computable in time
linear in `|t|`, without executing it.

*Proof sketch.* Each primitive effect is O(1) in ledger operations by construction (they are the eight existing rules,
which are). `Seq`/`Par`/`Gate`/`Alt` add a bounded constant each, and depth is bounded by 3, so the term is a finite tree
whose node count is its own size. `Prove` costs one verification, whose cost is a function of the proof system and the
claim's declared size — both present in the term. Hence `cost(t) = Σ cost(node)` over a tree fully present in the
transaction. ∎

**Consequence.** The fee is priced from the term *before* admission, so a transaction cannot exhaust a budget mid-flight
and leave a partial state. There is no out-of-gas state, no refund rule, and no revert semantics to get wrong. This is the
structural form of the same insight as Corollary U.3: bound the work by *certifying the depth*, not by metering the run.

**The corner this does not cover [P].** A `Prove` whose verification cost is superlinear in a claim field the prover
chooses could grief the verifier. The bound must therefore be on the *claim*, not the proof: claim sizes are capped by the
same admission predicate that checks viability (§6), which is where every such bound belongs.

---

## 5. Where expressiveness actually comes from

Three sources, in increasing power, and the third is the one that makes the model unbounded.

**(a) Composition of existing primitives — available immediately.** The eight tags become eight *effects*, and any
well-typed term over them is a new transaction kind requiring no protocol release. Atomic multi-step transitions that are
currently impossible become expressible: *"pay a storage provider **and** register a name **and** shield the change, all
or nothing"* is `Seq [Storage, Name, Shield]`; *"transfer, but only if the recipient's name is registered"* is
`Gate (NameExists r) Transparent`. This is combinatorially larger than eight kinds while remaining exactly as
statically analysable — the footprint is *derived*, so DROMOS is not merely preserved but strengthened (a composite's
footprint is tighter than the union of separately-submitted transactions, because `Par` proves disjointness).

**(b) Horizontal breadth — the growth axis §2.1 licenses.** New primitive effects are added at level 0, not by deepening
nesting. Each carries its own footprint type, and §7's closure theorem means adding one cannot invalidate any existing
composition. This is the ecological growth K.5 leaves open, read at the ledger level.

**(c) `Prove` — Turing-complete expressiveness with O(1) on-chain cost.** An arbitrary off-chain computation, on-chain
reduced to verifying that *given this read-set, the write-set follows*. Expressiveness is unbounded; determinism is
trivial (verification is a pure function); and the footprint is not merely declared but **proven**, so the scheduler's
static analysis survives contact with arbitrary computation. This is the same "claim + evidence" shape OBOLOS already uses
for *value* — a shielded spend is exactly a `Prove` whose claim is "these nullifiers are fresh and value is conserved".
Generalising from value to arbitrary state is the natural closure of a mechanism the platform already ships.

**Honest gate on (c).** The PQ-ZK stack's proofs are currently far too large to gossip (`docs/design-obolos-zk.md`: 145
MiB at tree depth 1), and recursion is the sole blocker. So `Prove` is specified and type-checked now, and becomes
*practical* exactly when recursive compaction lands. Until then (a) and (b) carry the expressiveness, and `Prove` exists
in the algebra so that nothing has to be redesigned when the proof size falls. Stating this as a dated dependency rather
than an aspiration is the point.

---

## 6. Admission: the port predicate [D]

Mirroring `Adm(C)` (§2.2), a term is admitted iff — checked **before** execution, in this order, cheapest first:

```
Adm(t) ⟺ well_typed(t)                        -- depth ≤ 3, Par footprints disjoint, claims within size caps
       ∧ affordable(t, fee)                    -- cost(t) from §4, priced before admission
       ∧ footprint_bounded(t)                  -- |fp(t)| within the block's per-tx cap
       ∧ viable(post(t))                       -- the ledger-level analogue of P(C) > P_crit
```

`viable` is the ledger's own coherence condition, and it is where the SYNARC-Ω reading becomes concrete rather than
decorative. At minimum it is the conjunction of the invariants the current eight rules each maintain privately: supply
conservation, no negative balance, nullifier freshness, stake ≤ bonded, anchor known. ERGON's contribution is that these
stop being eight private post-conditions and become **one predicate on the post-state**, checked once, for any term. The
open refinement [P] is whether `viable` should additionally carry the DIAKRISIS coherence measure — the
`P(Γ_post) ≥ P(Γ_pre) − ε` form of the Proof-of-Coherence sketch — which would make block validity depend on network
health as well as ledger arithmetic. That is a consensus change, not an execution change, and is deliberately *not*
bundled here.

**Failure mode [D].** Admission failure is a *rejection*, never a partial application: the term never begins. This is the
property gas cannot offer and the reason §4 matters.

---

## 7. The closure theorem — why composition is safe by construction [T]

**Theorem (ERGON closure).** If every primitive effect preserves the ledger invariant set `I`, then every well-typed term
preserves `I`.

*Proof by structural induction.* `Effect`: by hypothesis. `Seq`: composition of `I`-preserving maps preserves `I`.
`Par`: children have disjoint write footprints, so their effects commute and the composite is any serialisation of them,
each `I`-preserving by induction. `Gate`: either the predicate fails (identity map, preserves `I`) or the child runs
(induction). `Alt`: exactly one branch runs, chosen deterministically by order; that branch preserves `I` by induction.
`Prove`: the verified claim asserts the write-set follows from the read-set, and admission (§6) checks `viable(post)`, so
the transition is `I`-preserving or rejected. ∎

This is the ledger-level reading of **Fractal Closure**: composition inherits the guarantees of its parts, so safety is
established once per primitive and never again per composition. It is the precise sense in which ERGON is *more*
verifiable than the eight-tag dispatch, not merely more expressive: today each tag's soundness is argued separately and
their *interactions* — two tags in one block touching one account — are argued by the scheduler. Under ERGON the
interaction argument is the induction above, discharged once.

Note what the theorem needs from B2 (§2.3): safety composes **downward**, because the parent's admission predicate is
checked on the composite's post-state, not on each child's. A child cannot pass through an intermediate state that
violates `I` and be rescued by a sibling — `Seq`'s atomicity means `I` is checked at the composite boundary, which is
strictly stronger.

---

## 8. Geometry: the second axis of parallelism

FANOS state is *placed*: `target = MapToPoint(H_storage(key))` (§L4). So a state key that does not carry its point is a
**lossy type**, and ERGON's `Key` carries it. That one decision unlocks an axis of parallelism the platform has so far
left on the table.

### 8.1 Locality — which machines need be involved at all

DROMOS answers *which transactions may run together*: given the committed order, non-conflicting transactions execute
concurrently, **within a cell, on one machine**. Locality is the orthogonal question, and it is answerable only once keys
carry placement:

| `Locality` | meaning | consequence |
|---|---|---|
| `Point(p)` | every key at one point | one node holds everything the term needs |
| `Line(l)` | all points on one line | executable **entirely inside that line's quorum** — the term is *shardable* |
| `PlaneWide` | points sharing no line | inherently cell-wide |

A `Line`-local term needs no cell-wide coordination, so throughput scales with the number of lines — `q² + q + 1` of them
— and not merely with a cell's cores. And terms are line-local far more often than plane-wide, because placement is
content-addressed: a transfer touches two accounts, a name registration one name and one account. The unlock is not that
this is *true* but that the algebra can now **prove** it, so a scheduler may act on it.

`Footprint::locality` takes an **incidence oracle** rather than importing a plane, so `fanos-ergon` stays a `no_std`
algebra with no `q` baked in and the same proofs hold for every plane. One closure is the entire coupling.

### 8.2 This is the shape modality, not an analogy to it

In SYNARC-Ω's operational semantics the shape modality `Π` *is* `decompose_fano_lines`: the path-connected components of a
holon "are precisely the set of seven Fano-line projections". Decomposing a footprint into its line components is not an
analogy to that operation — it is that operation applied to ledger state. Likewise the de Rham modality `Rh` *is*
`parallel_scan`, "integrating local data into global", which is what DROMOS's wave scheduler does.

Two correspondences, then, and stated as readings **[I]** rather than theorems. The wider temptation is refused
deliberately: mapping the eight ledger tags onto the seven modalities would be exactly the unfounded analogy the
math-grounded discipline forbids. The modalities are functors on a topos of holon states; a ledger effect is a transition
on placed key-value state. Where the operation is literally the same one, the correspondence is worth using; where it
would need forcing, it is worth refusing.

### 8.3 Why an effect should own points, not lines [T]

The plane's dual Steiner property — *any two distinct lines meet in exactly one point* — gives a sharp consequence:

> **A footprint the size of a line always conflicts with every other line-sized footprint.**

Point-sized footprints conflict only on equality; line-sized footprints conflict *always*. So footprint granularity is not
an implementation detail, it is the parallelism budget, and the design rule is derived rather than stylistic: **an ERGON
effect should own points, not lines.** A contract whose state is a whole line (a replica set, a quorum) serialises against
every other such contract structurally, not by bad luck. This is verified exhaustively over all seven Fano lines in
`plane_wide_footprints_always_conflict_which_is_why_effects_should_own_points`.

Where line-sized state is genuinely required — it is, for the LRC store's replica lines — the effect should be
`Extern`-typed (§2.5) and priced accordingly, not silently scheduled as though it were parallel.

### 8.4 Is `PG(2,q)` the right geometry? — the audit

Worth auditing rather than assuming, since every claim above rests on it. The result is stronger than expected: on the
axes FANOS actually uses, the plane is **extremal**, and the two costs that looked like defects dissolve on inspection.

**Extremal, three ways [T]:**

1. **Quorums meet the Maekawa bound.** A symmetric quorum system on `N` nodes requires quorums of size `≥ √N`. A line of
   `PG(2,q)` has `q + 1 ≈ √N` points for `N = q² + q + 1`. Not merely adequate — the theoretical minimum.
2. **No alternative design exists with these properties.** A symmetric BIBD with `λ = 1` *is* a projective plane (Fisher's
   inequality plus symmetry). "Any two blocks meet in exactly one point ∧ all blocks equal size ∧ all points equal
   replication" **uniquely characterises** projective planes, so the absence of a better structure with that property set
   is a theorem, not a preference.
3. **The incidence graph is a generalised 3-gon** — extremal in girth and diameter, and near-Ramanujan. For gossip and
   mixing that is best-available, not a compromise.

**The two apparent costs, re-examined:**

- **Capacity is a cost of *placement*, not of geometry.** `O(q)` occupancy instead of `q² + q + 1` follows from drawing
  coordinates uniformly into a finite point set — the birthday bound applies to *any* finite address space under random
  placement. Verifiable probing removes it entirely (7/7 at load factor 1.00) without touching the geometry.
- **The pessimal footprint class is the quorum guarantee, read from the other side.** "Any two line-sized footprints
  conflict" and "any two quorums intersect" are the *same statement*. One cannot have guaranteed quorum intersection
  without conflicting quorum-sized footprints. Not a defect — the price of the guarantee, and the guarantee is load-bearing.

**The one genuine geometric limitation [T].** Two lines meet in **exactly one** point, so the quorum-intersection guarantee
is *witnessed by a single node* — Byzantine or dead, and the witness is gone. A `λ = 2` design (a biplane) would give two
intersection points and a fault-tolerant witness, at a block size of `~√(2N)`. FANOS already compensates differently:
`fanos-core::routing` realises linearisability *more strongly* than a bare line quorum — a write erasure-codes across all
shard homes and a read fans out to all of them, reconstructing the highest recoverable version. Full fan-out instead of a
biplane; the compensation exists, and its price is the fan-out.

Secondary: `q` must be a prime power (no plane of order 6 or 10 — Bruck–Ryser, and order 10 by exhaustive search), so cell
sizes step 7, 13, 21, 31, 57, … and an arbitrary `N` is unreachable. §L1's recursion of cells already routes around this by
federating rather than resizing.

**Where a qualitative improvement is actually available: federation, not the cell.** A cell's geometry is derived and
extremal; the structure by which cells *compose* is derived far more weakly, and that is where the open problem in §10
("ecology dynamics") really lives. The UHM corpus already points at the answer — the **Golay federation** of T-228, i.e.
the Steiner system `S(5,8,24)`. That is a qualitatively different regime: 5-transitivity instead of 2, so block
intersections are redundant by construction, and the Golay code corrects three errors at the federation level where the
Fano structure detects at the cell level. Designing that is the next real geometric question; the cell's is settled.

---

## 9. Coherence with what exists

| existing | under ERGON |
|---|---|
| `TAG_TRANSPARENT` … `TAG_SLASH` | eight primitive `Effect`s at level 0; identical rules, now with typed footprints |
| `HybridLedger::apply` dispatch | one `Term` interpreter; the eight-way `match` becomes eight effect implementations |
| `AccessList` (derived by a second eight-way match) | **derived by `fp(t)`** from the same structure that defines the transition — one match instead of two that must agree |
| DROMOS conflict DAG | unchanged, and fed a tighter footprint |
| blind ordering / anti-MEV | unchanged: ordering is still fixed before reveal, and a term reveals nothing extra |
| OBOLOS shielded spend | the canonical `Prove`; the model generalises it rather than sitting beside it |
| HERMES HTLC | `Gate (HashLock h) (Seq [...])` — the lock becomes a *predicate*, not a bespoke tag |
| `fanos-holarch` Γ-gate | the natural home for `viable`'s coherence refinement [P] |

The `AccessList` row is the one worth pausing on, **and an earlier version of this document got it wrong.** It claimed
transactions *declare* their access lists and the scheduler trusts them, so ERGON would delete a trust assumption. That is
false about this codebase: `HybridLedger::access_of` already derives every access list by decoding the transaction. The
overclaim is recorded rather than quietly edited, because a design doc that flatters its own proposal is worth less than
one that can be checked.

The real benefit is narrower and better evidenced. Today `access_of` and `apply` are **two hand-maintained eight-way
matches over the same tags** — one computing what a transaction *touches*, the other what it *does* — and correctness
requires them to agree. Add a write to `apply` and forget it in `access_of`, and the scheduler places two genuinely
conflicting transactions in one wave and forks the state. That is not hypothetical: the shielded arm of `access_of` carries
a comment recording exactly that defect (a missing `TREASURY` write, audit §3.7) and the fork it would have caused.

Under ERGON the footprint is derived from the *same* structure that defines the transition, so there is one match to
maintain instead of two that must be kept in step. A smaller claim than "deletes a trust assumption", and unlike that one
it is true.

---

## 10. What is not settled

Recorded here rather than discovered later.

- **`Prove` is gated on ZK recursion** [P]. Specified, type-checked, unusable at current proof sizes (§5c).
- **`viable`'s coherence term** [P]. Whether block validity should depend on `P(Γ_post) ≥ P(Γ_pre) − ε` is a consensus
  decision, deliberately unbundled (§6).
- **`Alt` footprint over-approximation** [C]. Sound and deterministic, but branchy terms schedule pessimistically (§3).
  Whether a two-phase schedule (guard-evaluation wave, then body waves) recovers the precision without breaking schedule
  determinism is an open refinement.
- **`Extern` effects** [P]. The algebra guards their ledger consequence only; their outside-the-ledger consequence needs a
  guard of its own kind, exactly as Definition U.8 assigns for symbol-emitting effectors.
- **Ecology dynamics** [P]. §2.3's B1–B3 fix the interconnect's *types*; the collective dynamics of many composing
  contracts (emergent optimisation, collusion) is the same named open problem R4/S-14 the ASI spec declines to close, and
  no claim is made here either.

---

## 11. Implementation order

1. `fanos-ergon`: the sans-I/O term algebra — `Term`, `Effect`, `Footprint`, `fp`, `depth`, well-typedness, with the
   closure theorem's induction as the test suite. No ledger dependency; `no_std`.
2. The eight existing rules re-expressed as primitive effects, behind the same wire tags so no capability is lost.
3. `HybridLedger::apply` replaced by the term interpreter; the declared `AccessList` deleted and `fp` wired into DROMOS.
4. `Gate`/`Alt` predicates over ledger state; HERMES's HTLC migrated to `Gate` and `TAG_HTLC` retired.
5. `Prove` behind the OBOLOS verifier, inert until recursion lands.

Step 1 is pure and provable and is where this begins.
