# Observability: the data-path plane, and why it is the afferent nerve rather than a debugging tool

**Status: §3–§5 implemented, §6–§7 open. Updated 2026-08-01.** The coherence plane (`fanos-telemetry`,
`fanos-observatory`) is built, live and mathematically grounded. The data-path plane derived here **now
exists in substrate form**: `fanos_telemetry::stations` supplies the derived `Station` enumeration and the
node-local, structure-keyed `Stations` counters (§3's R1–R4 and §5's geometric cardinality bound are
properties of the types), and the discard sites of two engines are instrumented:

* **`ThresholdRouter`** — gather expiry below threshold *and* completion (the denominator, without which the
  first is a bare number rather than a rate), cap-eviction, share-request-not-a-member, own-share-failed
  (key/epoch skew), share-for-unknown-request, forged share index, candidate flood cap, holonomy reject, and
  every frame-decode failure through a single `undecodable()` site;
* **`PorosHost`** — the four admission gates §4 names as the sharpest case, which previously returned the
  same silent `Vec::new()`, plus its own gather expiry and completion.

**What is NOT done**, and each is tracked: the remaining discard sites (`RendezvousRelay`,
`rendezvous_host`, per-tag frame-decode counts); §4.1's export of already-computed signals (`GatherClock`
now exposes `srtt`/`var`, but nothing reads them yet); §7's load sensor, which is this plane's acceptance
criterion; and §8's derivations, until which **counters stay local-only** — nothing here exports itself.

---

## §1. The gap, stated as an experiment rather than an opinion

FANOS already observes itself well, in one dimension. `fanos-telemetry` is *mandatory* per-node self-observation:
each window a node folds its state into a `CoherenceFrame` — a 3-bit Fano/Hamming syndrome naming the faulted
point, plus `Φ/P/R/Δ` — whose on-wire cost is `Θ(log N / N)` bits per node per window by the Minimal
Self-Observation Overhead theorem, and whose export is ε-differentially private at a **derived** sensitivity
`Δr = 1/21`. `fanos-observatory` renders it for a human and emits the same snapshot as JSON for an agent.

That plane answers **"is the organism healthy?"**. Nothing answers **"is the work getting done, and where does it
stop?"**

The gap is not hypothetical. Defect #55 — the `f + 1` meeting-point censorship spread failing because every hop
addressed one canonical combiner — was localized by hand-inserting eight `eprintln!("[s55] …")` probes into
`ThresholdRouter`, `RendezvousRelay`, `rendezvous_host` and the client bridge, running the scenario, grepping the
output, and deleting the probes. Eleven candidate causes were eliminated one at a time by that method.

**What the coherence plane would have said:** *"point 3 is faulted."* Which the operator already knew, having
stopped that node deliberately. It could not have said either of the two facts that actually solved it:

1. every circuit whose hop lines have that point as canonical addressee is dead — the *structural* consequence;
2. gathers are expiring at `1` of `t = 2` shares **by the hundreds per run** — which turned out to be a second,
   independent defect (a chosen 2000 ms deadline, `DEFAULT_GATHER_TIMEOUT`).

Both were sitting in the process's own control flow the whole time. Nothing recorded them.

---

## §2. Why this is not a tooling task

Three subsystems are open-loop today, and the same missing piece closes all three. Only the third is debugging.

### 2.1 Role self-organization runs on a fixed setpoint

`role_loop.rs` is live and derived, not heuristic: each beacon round it reads the cell's authenticated capability
directory and steps a `RoleController` — a UHM-grounded **Lyapunov-descent** demand rebalance plus role
assignment — then publishes this node's assigned roles on a `watch` channel. The controller is real.

Its own documentation states the gap: *"The setpoint — how much of each role the cell wants — is supplied on
another watch channel a load sensor drives; until that is wired the node holds a fixed target."*

A controller with no feedback is not a control system. **The load sensor needs data-path measurement, which does
not exist** — so "self-organizing" is presently a property of the code rather than of the running network.

### 2.2 Self-healing treats what it can see

`fanos-telemetry`'s own framing names this plane as half of a whole: *"Self-observation is the sensory half of
the organism: it feeds self-diagnosis, self-healing (the regenerator `ℛ`), and load optimization/balancing."*
The regenerator therefore acts on cell **health**. A hop line that has silently stopped peeling is not ill-health
in the `Φ/P/R/Δ` sense — every node is up, coherence is nominal, and no work is moving.

### 2.3 Debugging

Covered above. It is listed third deliberately: if the plane existed only for this, it would be worth building,
but it would not be architecture.

---

## §3. The hard constraint: observability is the adversary's goal

This is an anonymity network. **Per-circuit tracing is deanonymization**, so the usual answer — propagate a trace
id, correlate spans across hops — is not merely inadvisable here. It is an attack:

> A trace id carried through the onion and visible at successive hops is **exactly a tagging attack** — a
> recognizable modification that survives to a later hop and lets an observer confirm a flow. It is the channel
> per-hop AEAD exists to close, and that `tests/onion_tamper.rs` proves is closed ("no single-byte tag survives a
> hop"; the adversary's tag-and-trace channel has zero capacity). Adding a trace id would reopen, in plaintext,
> the exact channel the cryptography spends its budget closing.

So the design rule is not a caution, it is a prohibition with a proof behind it:

**R1. No cross-hop correlatable token, ever.** Not a trace id, not a request id, not a session id, not a hash of
one. If two observations at different hops can be linked, the plane is a deanonymization tool.

**R2. Counters are node-local aggregates keyed by STRUCTURE**, never by flow: `(station, line, epoch, role)`.
Structure is public — the geometry is a published function — so a counter keyed by it discloses nothing that the
plane's shape does not already disclose.

**R3. Per-session counters are forbidden even when the session id is not exported.** A count that varies with one
session's behaviour is a linkability channel by its variance alone. Aggregate over the window or do not collect.

**R4. Anything crossing a node boundary is privatized** through the existing `fanos-telemetry::dp` boundary. An
operator's own node may expose raw locals over its admin socket — it is theirs — but the export path must not
grow a second, unprivatized door beside the one whose sensitivity was derived.

---

## §4. The stations are derived, not invented

The temptation is to design a metrics taxonomy. That would be a chosen structure where a derived one exists.

**Every branch that discards work is already written in the code.** Each early return, each `None =>`, each
eviction and each expiry is a place where the system decided not to continue — and *that decision is the
observation*. The enumeration is therefore mechanical: instrument the discard sites, name each by what it
discards, and the taxonomy falls out of the control flow instead of out of a whiteboard.

`ThresholdRouter` alone has twenty such sites. Each corresponds to a question that was asked by hand during #55:

| station | what is discarded | the question it answers |
|---|---|---|
| `on_request` not-a-member | a share request for a line this node is not on | why a gather never reaches quorum |
| `on_request` partial-fail | the member's own share could not be computed | epoch/key skew between members |
| `on_reply` unknown request | a share for an already-peeled or foreign gather | are replies arriving after the deadline |
| share index out of range | a forged `x` outside real membership | **an attack**, distinguishable from noise |
| duplicate share | an exact `(x, y)` repeat | retransmission vs replay |
| `MAX_CANDIDATES` cap | share flood beyond what a real line needs | memory attack on the gather |
| holonomy reject | a delivery that traversed a different circuit | S1-M1 firing |
| **gather expiry at `k < t`** | **the entire hop** | ← this *was* defect #14, found by grepping |
| `pending` eviction at cap | a gather dropped for capacity | introduced with #14's count bound |
| frame decode failure, per tag | unparseable input | **version skew** — see §6 |
| combiner selection `None` | a degenerate line | plane misconfiguration |

`RendezvousRelay` adds host-registration refusals, tag misses, seal failures and both `BoundedMap` evictions.
`rendezvous_host` adds ingest failures, the intentional full-queue datagram drop (audit A4b), and session
spawn/evict/reap/sweep. **POROS is the sharpest case**: its four admission gates — identity binding, PoW, the
Sybil cap, and pending-full — today all return the same silent `Vec::new()`, so an operator cannot distinguish
"we are under a Sybil flood" from "our difficulty is set wrong". Four different worlds, one empty vector.

### 4.1 Export what is already computed

Some values exist, are used, and are then thrown away:

* **`GatherClock`'s `srtt`/`var`** (introduced by #14) is precisely the health of the gather path, already
  smoothed in RFC 6298 form. It is the load signal §2.1 needs, and it is currently private to the engine.
* `BoundedMap` eviction counts, holonomy rejects, peel failures, onion-epoch vs beacon-epoch skew, mix directory
  size and freshness.

Exporting these costs nothing and is where the plane should start.

---

## §5. Cardinality is bounded by the geometry

A metrics system usually needs a cap on label cardinality, because labels are user-supplied strings and an
attacker mints them. Here the key space is `(station, line, epoch, role)`, and **lines are a finite published set
of size `q² + q + 1`** — 7 on Fano, 57 on `PG(2,7)`. Stations are a compile-time enumeration. Roles are a fixed
set.

So the counter space is `O(stations × lines)` with no dynamic allocation and no attacker-chosen keys: the bound
is a fact about the plane rather than a cap someone chose. Epoch is a sliding window, retained by
`fanos-telemetry::history` at its existing depth.

This is a small, welcome consequence of building on a geometry rather than on a DHT.

---

## §6. What the same plane buys elsewhere

**Version skew becomes visible (#22).** Frame-decode failures counted per tag, per line, are exactly a skew
detector. This matters more here than in an ordinary network: a member on a different wire or derivation version
does not error — it produces a partial that does not reconstruct, or addresses a hop nobody is gathering, and the
hop simply never peels. #55 is the empirical proof of how that presents: a wholly dead data path indistinguishable
from eleven other causes, with a clock as the only signal. An upgrade architecture needs skew observable **per
line** before it can be survivable.

*Implemented in part:* `ThresholdRouter` now routes **every** decode-failure arm — and the unknown-tag arm —
through one `undecodable()` site recording `FrameDecodeFailed`, so the count cannot be half-instrumented by a
later arm being added without one. It is deliberately **unattributed** (`line: None`): a frame that failed to
parse has no readable line, and inventing one would put fabricated evidence against a line into the very plane
built to end diagnosis-by-thin-evidence. Per-*tag* counts and the other engines' decode sites remain open, and
`SharePartialFailed` — a member that cannot compute its own share, i.e. **key/epoch skew inside a line that is
otherwise agreeing** — is the sharper of the two skew signals and is instrumented.

**The founding operator's monitoring position becomes principled.** Running the founding nodes gives full local
visibility (§3 R4) with no privileged key and no anonymity cost — and that visibility **dilutes as others join**,
which is the correct shape: the privilege decays with decentralization instead of requiring anyone to relinquish
it. No mechanism is needed to revoke what arithmetic removes.

---

## §7. The load-sensor interface, stated as the point of the exercise

The deliverable that closes §2.1 is not a dashboard. It is a typed reading the `RoleController` can consume as its
setpoint: per-role demand derived from station rates the node already observes — gathers armed vs expired per
line, forward volume, session counts, storage and bandwidth service.

Until that interface exists, every claim about self-organization is a claim about `role_loop.rs` compiling, not
about a network organizing itself. **That is the acceptance criterion for this whole plane**, and it is stronger
than "the counters exist".

---

## §8. What is derived, what is chosen, and what is unproven

**Derived.** The station enumeration (it is the code's own discard sites). The cardinality bound (`q² + q + 1`
lines is the geometry). The prohibition on cross-hop tokens (it reopens the tagging channel `onion_tamper.rs`
proves closed). That the load sensor must read the data-path plane (the coherence plane measures health, and a
role setpoint is a function of demand).

**Chosen, and each needs a derivation before it ships.** The observation window length. The retention depth in
`history`. The DP `ε` for counter export — the *sensitivity* must be derived per counter family as `Δr = 1/21` was
for the coherence frame, and until it is, counter export stays local-only.

**Unproven, and the honest frontier.** That aggregate-by-structure counters leak nothing useful to an adversary
who also observes traffic. R1–R3 forbid the obvious channels, but a *rate* keyed by line is still a signal, and a
global passive adversary correlating published line-rates against observed traffic is a threat model this document
does not close. Until it is analysed, exported counters should be limited to what the coherence plane's DP budget
already covers, and per-line rates should be treated as local-only. **A plane built to find defects must not
become the defect.**
