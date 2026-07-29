# The evolution plan: from a network that diagnoses itself to one that governs itself

Written 2026-07-28, after a session in which every defect found lived in the same place. This is not a wish
list — each item names the evidence that motivates it and the **guarantee** it is expected to end in, because
"done" for this project means a theorem, a checkable invariant, or a measurement, never an opinion.

## The method

Work the phases in order, and at each step:

1. **Re-audit before building.** The last session's most valuable findings came from checking a premise rather
   than acting on it — three tests passed their own falsification, one experiment measured a cell that was
   never viable, and one "fix" was attributed to a cause that measurement then ruled out.
2. **State the guarantee first.** Every item below carries a `Guarantee:` line naming what kind of assurance is
   achievable. Three kinds are admissible, in descending strength:
   * **Theorem** — a proof, with the code asserting its hypotheses.
   * **Invariant** — a property a test checks mechanically over the whole tree, so it cannot regress silently.
   * **Measurement** — an interleaved A/B or a closed-loop simulation, reported with its conditions.
3. **Falsify every new test** by disabling the mechanism it covers, *in the file that actually holds it*.
4. **Update this plan** as findings change it. A plan that survives contact unchanged was not being tested.

Backward compatibility is not a constraint. Refactoring of any size is admissible where it buys architectural
coherence.

---

## Phase I — Composition

**Why first.** Every defect found in the 2026-07-28 session lived in a composition, not a component:
`read_coherence` with no caller; the observatory watching a simulated cell; `render_openmetrics` served by
nothing; a real DKG in the crate while the shipped bootstrap dealt 1-of-1; `FrameType::Error` **never
dispatched at all**; `AdmissionPolicy` never adaptive. The crates are strong and the seams between them are
thin. New control loops built on this foundation would inherit its blindness.

### I.1 — Every capability has a live consumer, or it is deleted

**Evidence.** `read_coherence` shipped with no caller. `render_openmetrics` exists and nothing serves it.
`fanos-angelos` and `fanos-ergon` are linked by nothing. The `vpn` datapath is exercised by nothing.

An unused capability is not neutral: it reads as a guarantee and is not one. The rule is **delete, not defer**.

**Guarantee: Invariant** — **half already held, and that is the finding.**

The symbol half is done and was done before this plan: `unreachable_pub = "warn"` is in `[workspace.lints.rust]`
and CI runs `-D warnings`, so every `pub` item unreachable from outside its crate is already a build failure.
A workspace build under the lint reports **zero**. The check I planned to write exists, in the compiler, which
is where it belongs — a hand-rolled reachability script would have been strictly worse and could not have been
right (a first pass of exactly that counted 554 "orphans", all of them public API a crate legitimately exposes).

What remains is the **crate** half, and it is a defect list rather than a lint: `fanos-angelos` (a complete
messenger — sessions, double ratchet, groups, media, call signalling, a bot SDK) and `fanos-ergon` are linked by
nothing shipped. `architecture.rs` now separates `EMBEDDING_SURFACE` (a C ABI or wasm entry point is *finished*
when nothing of ours links it) from `ORPHANS` (capability with no door), because one list conflated two opposite
meanings — and puts a **ratchet** on the orphan count: it may shrink and never grow, and resolving one requires
lowering the ratchet so the ground cannot be given back.

**`fanos-angelos` is wired** — `fanos message serve` hosts the messenger on the anonymous rendezvous, and the
orphan ratchet is down to one. What was missing was never the capability: `angelos_driver` is a composition, and
the whole of it is running ANGELOS's handshake over a stream the node already knows how to accept anonymously.

`fanos-ergon` remains. It is the last orphan, and the decision there is genuinely open — DROMOS executes without
it, so the question is whether the effect algebra replaces that execution path or is deleted.

### I.2 — Every frame that is sent is handled

**Evidence.** `FrameType::Error` was encoded and sent, and the overlay had no receive arm for it — so every
rejection the network ever sent arrived somewhere that did not read it. Found by accident while building
something else.

**Guarantee: Invariant.** — **DONE** (`fanos-cli/tests/frame_handling.rs`). Every `FrameType` variant must be
matched on somewhere, or declared with a reason.

**The suspicion was right, and larger than expected.** Eleven of thirty-one codes — `Goaway`, `Join`, `Bridge`,
`StreamOpen`, `StreamData`, `StreamFin`, `PartialDec`, `Cover`, `SvcAnnounce`, `DiagSyndrome`, `DiagVerdict` —
were defined and referenced *nowhere*. A third of the registry named a protocol the implementation does not
speak; every one had a working mechanism under another name. All eleven deleted, and the exception list is now
empty, which is its intended steady state.

### I.3 — The simulator runs the composed node, not the engines

**Evidence.** The standing directive is that the simulator differs from production only in transport. It does
not: it composes engines directly, while production composes them through `Node::start`. The measured gap is
that **node composition is never simulated** — and that is exactly where the defects are.

**Guarantee: Invariant** — **DONE**. `fanos_node::composition::compose_engine` is the one assembly point, and
both `Node::start` and `fanos_sim::spawn_cell` call it. The compiler confirmed the extraction was complete
rather than partial: `ThresholdRouter`, `BeaconNode`, `HybridKemSecret` and `OverlayNode` all became unused
imports in the files they moved out of.

Checked in the **source**, by `fanos-cli/tests/composition_seam.rs`, and that is the lesson of this item. The
first version asserted it at runtime — stand up a composed cell, crash a node, watch it localize the fault — and
passed just as well with the simulator put back to a bare overlay, because a bare overlay localizes that crash
identically. The property is not "a composed cell behaves differently"; it is "there is one assembly function
and both callers use it", which is a fact about the text.

Two simulator files are declared exempt with the reason: they build **topology fixtures** (gateways wired across
cells, hierarchical peers pinned per node) rather than nodes, and folding every `OverlayNode` builder into
`CellComposition` would turn it into a mirror of that type instead of a statement about what a node *is*.

### I.4 — TAXIS, rule by rule, against its source

**Evidence.** Round synchronization — "on `f+1` messages from a higher round, jump to it" — was **absent
entirely**. Not weakened, not subtly wrong: missing. Rounds advanced only on a node's own timeout, so validators
drifted apart on scheduling noise and had no mechanism to re-converge, while proposer entitlement is
round-dependent. The cell rejected its own proposals, hundreds of times per run.

A protocol built from a paper's happy path will have other such gaps.

**Guarantee: Theorem, per rule.** Enumerate the safety and liveness rules of the PBFT/Tendermint lineage that
TAXIS claims. For each: state its hypothesis, assert it in a test, and record where the implementation
establishes it. A rule that cannot be pointed at in the code is a rule that is not there.

### I.5 — Split the two numbers `admission_difficulty` holds

**Evidence.** One field is used both as "the price I demand of joiners" and "the difficulty I solved for
myself". Found when a scenario test had to *pay* 24 bits to *demand* 24 bits, taking 48 seconds.

**Guarantee: Invariant** — **DONE**. Two builders, `demanding(bits)` and `paying(bits)`, and the field is
`paid_difficulty`. The conflation was worse than untidy: a node's own proof must satisfy its *peers'* gates, so
its own gate has nothing to do with it — coupled, raising the price you charge forced you to pay it yourself for
nothing. Pinned by `what_a_node_demands_and_what_it_pays_are_independent`, falsified by re-coupling them.

---

## Phase II — Control

**Why this is the differentiator.** Tor has no `Φ`. FANOS's claim to be a living network rests on DIAKRISIS —
and the 2026-07-28 session found the sensing built and the acting **one loop deep**. The homeostat governs `κ`
and internal structure; the healing plan reroutes, repairs, quarantines. Against the *magnitude* of an external
disturbance, nothing acted at all until the admission price was derived, and T-104 is explicit that past a
large enough flood no amount of internal healing saves the cell.

**The rule for this phase:** every sensed quantity either gets a control law with a **derived** setpoint, or is
deleted as decoration. Half the readings a node computes go nowhere today.

Every loop must arrive with:
* a **setpoint derived from a theorem**, never a tuned constant;
* a **stability argument** — a contraction, a Lyapunov descent, or a fixed point;
* a **closed-loop simulation** showing it beats the open loop, on a fixture asserted to be viable first.

### II.1 — Admission price (IN PROGRESS)

Derived: `Δbits = −log₂(1 − s)` where `s = (‖h‖/κ)/r_stab`. Simulation-validated after three failures that each
taught the design something — a modelled load oscillates; the purity *level* lags; the disturbance is only
observable while it is admitted, so the controller must hold its estimate and release it at `κ`.

Remaining: the gate is installed; verify end-to-end on a live cell and record the measurement.

**Guarantee: Theorem + Measurement.** Done.

### II.2 — Route weight from measured load

Routing is currently pure geometry. The cell measures per-node load and does not use it. A derived law would
bias the choice among equally-valid geometric paths toward the less loaded, without breaking the diameter-2
guarantee — the constraint being that any deviation must preserve reachability, so the weight can only reorder
*equivalent* choices, never exclude one.

**Guarantee: Theorem** (reachability preserved by construction) **+ Measurement** (tail latency under skew).

### II.3 — Epoch pacing from the recovery constant

The epoch period is a configured constant. The cell knows its own recovery time `τ = 1/κ` (`regeneration`
already computes reintegration time). An epoch shorter than the cell's recovery time reshuffles a cell that has
not finished healing from the last reshuffle.

**Guarantee: Theorem.** The bound `epoch_period ≥ c·τ` follows from the reintegration-time result; `c` is
derived from how much of a heal must complete before the next disturbance.

### II.4 — Role assignment from measured deficit

The cell assigns roles, but not from a measurement of what it lacks. A cell short of storage should be
assigning storage.

**Guarantee: Theorem** (an assignment that is a fixed point of the deficit map) **+ Measurement**.

### II.5 — Storage placement under pressure

Placement is derived from the address, which is right for locating and blind to load.

**Guarantee: Theorem** (placement remains a deterministic function of the address, so lookup is unaffected)
**+ Measurement**.

---

## Phase III — Recursion

**Why last.** It builds on both prior phases, and it is where the elegance meets its real limit.

### III.1 — Federation as the primary structure

**Evidence.** A cell holds about `q` nodes, not `q²+q+1` — a birthday bound on VRF coordinate draws, measured
and recorded. So the plane's beauty operates at cell scale, and everything above it is the recursion of cells.
The hierarchy exists in part; it is not the primary structure.

**Guarantee: Theorem.** The capacity bound is already derived. What follows — how many levels for `N` nodes,
what the cross-cell diameter is, what a federation's own viability means — should be stated with the same
rigour.

### III.2 — Cross-cell coherence

Each cell diagnoses itself. Nothing notices that forty cells are simultaneously degraded — which is the first
question of any real incident.

**Guarantee: Theorem** (a federation-level `Γ` whose measures compose from its cells') **+ the aggregate
tier**, which also finally gives the published ε-private coherence frames a reader.

---

## Cross-cutting

* **Operator surface.** Hand-rolled argument parsing in a 1500-line binary while `clap` is already a workspace
  dependency. `fanos-quic/src/driver.rs` is 2125 lines.
* **Governance decisions, before any public launch** (`docs/design-governance.md`): run the DKG across the
  founding set rather than dealing 1-of-1, and settle the validator-committee change rule while there is no
  state to preserve.
* **Coverage.** `fanos-observatory` 0.16, `fanos-runtime` 0.29.
* **The one flaky live test** is a real liveness defect and stays in the per-push gate until it is zero, not
  moved to nightly.

---

## Current position

Phase I is not started. Phase II.1 is done and installed. That order is backwards, and deliberately so — II.1
was the answer to a direct question about incident response — but it is the last item to be taken out of order.
Phase I begins now.
