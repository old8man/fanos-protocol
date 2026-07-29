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

**First pass done. Two more rules were missing, and one is now implemented:**

| rule | status |
|---|---|
| round synchronization (`f+1` from a higher round ⇒ jump) | **was missing**; implemented earlier this session |
| **unlocking** (release a lock on a strictly-later PREPAREquorum) | **was missing**; implemented — the `pol` field carrying the proof existed and was checked only for *proposer entitlement*, never for *who may accept* |
| nil votes (prevote/precommit nil) | **absent, and deliberately recorded as a gap** — see below |
| the lock gate (refuse conflicting proposals) | present |
| `valid_value` (propose an observed polka) | present |
| per-phase timeouts | **absent** — TAXIS has one round timeout, not three |

**On the unlocking rule, an honest note about coverage.** It is correct, standard, and the safety boundary
(`pol.round > locked_round`, strictly) is pinned by five unit tests including a falsification. But **no scenario
in the current harness requires it**, and two attempts to build one both passed without the rule — because
`adopt_certified_parent` already frees a validator stranded at a height the cell *finalized*, and `valid_value`
covers the sub-quorum split where no conflicting quorum can form at all. The rule matters in the remaining
window: a polka formed, no commit followed. That is real, and it is not currently reachable in the simulator.
Recorded rather than claimed.

**On nil votes — DONE.** `vote::NIL` is a reserved sentinel (forging it would need a preimage of the all-zero
digest, an assumption already spent everywhere else), a validator whose round timeout expires with nothing
accepted says `nil` and **stays** in the round, and `round_failed_by_votes` ends the round once `2f+1` have
spoken and no value can still reach a quorum. Three attempts to build the test each corrected the design: a
validator that already prepared cannot also say nil without equivocating, so the scenario had to be one where
proposals never arrive; and the first implementation sent nil *while leaving*, announcing to a round everyone
had already left.

The safety half — a quorum of nils must never *lock* — is pinned through the probe, because it is invisible to
height and hashes (locking on nil never finalizes either, so both worlds look identical from outside).

**Stated limitation:** the latency gain is a production property and the simulator cannot exhibit it. There the
clock that would otherwise end the round doubles toward 24 s while votes cross in milliseconds; here the timeout
is injected by hand, so there is no wall clock to save.

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

### II.4 — Role assignment from measured deficit — DONE

**The mechanism was already excellent and one input was fiction.** Self-organizing assignment exists and is
provable: a node advertises only *capability*, and the cell assigns the epoch's roles as a deterministic
function of signed capabilities, the beacon, and the cell's **demand** — every node computes the same
assignment for every node with no coordination, no role can be forged without capability, and none can be aimed
at. A proportional controller (`Demand::rebalance`) already tracked a setpoint.

The demand handed to it was `one unit per role the node offered`. That measures **supply** and calls it need,
so the assignment tracked who volunteered rather than what the cell lacked. The code said so itself — "until a
telemetry-driven load sensor lands" — and `ROLE_CAPACITY_PER_NODE` was already documented as the denominator of
`⌈load / capacity⌉`, a formula whose numerator did not exist.

Now measured where a sensor exists: **relay** is relays carried since the last behavioural sample, **storage**
is keys held. The remaining three fall back to the offer, unchanged and **not disguised** — reporting a measured
relay count beside a fabricated service count in one vector would make the second look like the first. Safe to
mix because the controller steps each role toward its own setpoint independently; unsafe to present as one kind
of number, which is why the code says which is which. A measured zero also falls back to the offer, since a
demand of zero would retire a role the moment it went quiet.

**A design fault caught by the test:** the report was first emitted inside the branch that needs the coherence
matrix, so a fresh node reported nothing — the role controller's only real input made to wait on a quantity it
never needed. A node knows what it holds and what it carried whether or not `Γ_net` has samples yet.

### II.2 / II.5 — WITHDRAWN: there is no routing or placement choice to weight

**Both rested on a premise the audit disproved, and saying so is the finding.**

*Route weight.* The plane has diameter 2 and any two points lie on a **unique** line, so `routed_send` has no
alternatives to rank. Rerouting around a loss is likewise determined — the co-linear survivor is
`mediator(self, lost)`, one point, not a set.

*Placement under pressure.* `nearest_occupied` is the successor on the index ring, and it **must** stay a pure
function of the address: a reader recomputes it to find the data. Biasing placement by load would put a value
where the reader does not look, which is not a tuning question but a correctness one. This is the property that
removes the directory and the search, and it is bought precisely by leaving no choice.

*Read shard selection.* Also absent: `on_get` fans a `Lookup` to **every** peer at once and the erasure code
tolerates the silent ones, so the read already takes the fastest `K` rather than picking `K` in advance.

The geometry has removed the choice everywhere it could have existed. A control law needs a decision to make,
and inventing a place to apply one would have been the opposite of deriving it.

### II.2′ — Read fan-out width under pressure (replaces both)

The lever that *is* there, and it acts on a different load: [`admission_bits`] prices what others inflict on the
cell, and this governs what the cell inflicts **on itself**. A read that asks everyone costs `N` messages to
recover `K` shards — `N/K` ≈ 2.3× amplification on the Fano cell — spent, under pressure, on exactly the links
that are struggling.

```text
    width(s) = K + margin + (N − K − margin)·(1 − s)
```

Bounded below by the **code**, not by policy: fewer than `K` shards cannot reconstruct at all, and the practical
floor is `K + margin` because a silent holder at width exactly `K` turns every read into two rounds — more load
than the message it saved.

Linear, where the admission price and the epoch floor both go as `−log(1 − s)`. That is not an inconsistency:
those two price something that must **diverge** as the headroom vanishes, since an unbounded cost is what keeps
demand out. This one cannot diverge — the code floors it — so the honest shape is the one that spends the
remaining headroom evenly.

**Guarantee: Theorem + Invariant — DONE.** The floor is the code's; monotonicity and the hard `≥ K` bound are
pinned, and the law is wired into `on_get`. At rest a read asks every peer it knows; at full stress it narrows
and never below what the erasure code needs — a narrowing that went too far would not slow a read down, it
would make it impossible. Falsified by removing the truncation.

The margin above `K` is one, and derived rather than cautious: at width exactly `K` a single silent holder
turns the read into a second round, which costs more than the message the narrower fan-out saved. The second
non-responder is already much rarer than the first, so a larger margin buys less than it spends.

---

## Phase III — Recursion

**Re-audited, and the phase's premise was wrong.** Written from notes that lagged the code.

### III.1 — WITHDRAWN: the capacity bound was already solved

The plan said a cell holds about `q` nodes rather than `q²+q+1` — a birthday bound on VRF coordinate draws —
and concluded that federation is *forced*. That was true and has been fixed: `fanos_vrf::probe_point` gives each
node a **verifiable probe sequence**, so a node displaced from a contested point advances along its own
sequence and the cell recovers full occupancy. Measured over the real derivation rather than an urn model: 15 of
15 on `PG(2,4)`, 200 of 200 on `PG(2,31)`. Only the tiny Fano cell loses one in seven, because a line there
holds three points and a node fails to seat only when *every* point of its line is taken — probability
`~load^(q+1)`, negligible at real `q` and not at `q = 2`.

The design also already carries a sharp adversarial correction: the walk stays on **one line** rather than the
whole plane, because a whole-plane walk is a *steering* primitive — the sequence is a public function of a
public VRF output, so an attacker who grinds Sybils onto `p₀…p_{j−1}` lands the victim deterministically on
`p_j`, on a line the attacker occupies. Confining the walk trades a little capacity for the removal of that.

So federation is still wanted at internet scale — `fanos-core::hierarchy` computes the `O(log n)` routing-state
and rendezvous-depth figures — but it is driven by **total network size**, not by a per-cell ceiling. A cell of
`PG(2,31)` holds 993 nodes. The hierarchy's addressing, `RouteHier` routing, auto-seed and poisoning defences
are built; what remains there is cross-cell directory and rendezvous, which is a feature rather than a
structural correction.

### III.2 — Cross-cell coherence — DONE

Each cell diagnoses itself, and a fault that a cell cannot heal already escalates to its parent
(`escalate_to_parent`, bounded by a TTL so the recursion terminates). So **fault** propagation upward exists.

What does not exist is **health aggregation**. Nothing notices that forty cells are simultaneously degraded —
which is the first question of any real incident, and the one an operator asks before any other: *is this my
cell, or the network?*

The input is already on the wire and has never had a reader. Nodes publish ε-differentially-private coherence
frames (`telemetry_dir::publish_coherence`), and `read_coherence` has **no caller at all** — noted at the start
of this session and still true. The privacy shape is already right for this: exact locally, exact within a cell
that must act on it, noised in aggregate, so an observer sees weather rather than a target.

**Guarantee: Theorem + Invariant — the reader is DONE; the operator verb remains.**

And the theorem came out differently from the plan's guess, which is the finding. There is **no** federation-level
`Γ` to compose: a cell's coherence matrix is over its own points, and the cross-cell entries exist in nobody's
measurement. Synthesising a network-wide `Φ` from cells' `Φ`s would invent a quantity that then reads exactly
like a measured one.

The composition that *does* exist is already built and is a different mechanism entirely: a child cell is a
**point** of its parent, so an unhealable child becomes a degraded point and the parent's own reflex runs
unchanged (`ParentCell::observe` / `contains_escalation`). That is the **control** path, and it composes
properly because the parent is measuring its own points.

So the observability path reports a **census** — how many cells healthy, alarmed, silent, unreachable — with
silence kept strictly apart from health. A monitor that folds a quiet cell into the healthy count reports its
best news exactly when a partition is at its worst, which is the failure `read_coherence`'s three-valued result
exists to prevent and which one `unwrap_or_default` would undo. The network verdict is taken over the cells that
*answered*: counting silence as health hides a partition, counting it as sickness lets one unreachable cell
speak for the network, and neither is a reading.

`take_census` finally gives the published ε-private frames the reader they have never had, and `census` on the
control socket is the verb. Served **off** the node's loop: a census reads every cell coordinate out of the
overlay store, and serving it inline would stop the node driving its own engine for the duration — an operator's
question is not worth pausing the node it is about.

Exercised live on a fresh single-node cell with no ε configured: seven coordinates asked, seven silent, verdict
*"no reading — no cell answered"*. That is the property, demonstrated rather than asserted — the same setup
folded into a "healthy" count would have reported a perfectly well network.

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
