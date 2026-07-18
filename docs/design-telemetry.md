# FANOS Telemetry & Self-Observation — distributed, provably minimal, at all scales

> The network scans itself for (almost) free. This document proves that FANOS's self-observation
> traffic is **information-theoretically minimal** — a vanishing fraction of useful traffic, with a
> per-node cost *independent of network size* — and specifies the **distributed collection** and the
> **monitor-mode WebSocket interface** a dashboard (or any tool) consumes at any scale, from one cell
> to the whole network. Provable efficiency, by construction.

Companion to [`design-platform.md`](design-platform.md) (§6 the coherence through-line, §8 DevEx) and
[`coherent-cybernetics.md`](coherent-cybernetics.md) (the theory). The user's requirement, made precise:
*control/service data must be the minimal possible fraction of total useful traffic when the network
scans itself* — here it is a theorem, not an aspiration.

---

## 0. The principle

A self-observing network faces an apparent paradox: to stay healthy it must *know itself* (a rich
self-model — the Good-Regulator theorem, `R ≥ 1/3`), yet every byte spent reporting status is a byte not
spent carrying payload. FANOS resolves the paradox with a single structural fact:

> **Rich self-model, minimal self-report.** The self-model is rich (each node spends `≥ 1/3` of its
> *internal* reflection budget modelling its cell). But **synchronizing that model across the cell costs
> only `Θ(log N)` bits per window** — because the projective geometry of a cell is *exactly* the
> parity-check structure of a perfect error-correcting code, so a `⌈log₂(N+1)⌉`-bit **syndrome** is a
> sufficient statistic for the cell's health. The compute is `Ω(1)`; the wire is `Θ(log N)`.

Everything below makes this precise and turns it into a shipping telemetry plane.

---

## 1. The Minimal Self-Observation Overhead theorem

### 1.1 The grounding identity — a Fano cell *is* a Hamming(7,4) parity check

The Fano plane `PG(2,2)` has 7 points whose homogeneous coordinates are the 7 non-zero vectors of
`GF(2)³`. Stack them as columns and you have the parity-check matrix `H` of the `[7,4,3]` **Hamming
code** — the canonical *perfect* single-error-correcting code. FANOS already carries this: `fanos-code`
computes `syndrome3`, `theme_flags`, `locate` over exactly this structure, and DIAKRISIS's `21 → 7 → 3 →
1` compression *is* the Hamming decode (21 pairwise readings → 7 line-parities → a 3-bit syndrome → the
1 faulted point). So the machinery below is not new code — it is the information theory of code already
shipped.

### 1.2 The theorem

> **Theorem (Minimal Self-Observation Overhead).** Let the network be organized as cells of
> `N = q²+q+1` nodes on `PG(2,q)` (the Fano cell: `q=2`, `N=7`), hierarchically to depth `k` (`N^k`
> nodes). Per observation window, to (a) detect a fault, (b) localize a single fault to one node, and
> (c) read the coherence regime, the self-observation traffic satisfies:
>
> 1. **Per-cell optimality.** Localizing one fault among `N` nodes requires **≥ `⌈log₂(N+1)⌉` bits per
>    cell per window** (the entropy of the fault location — `N` single-fault states plus "healthy"), and
>    the projective **syndrome achieves it exactly**: `3` bits for `N=7`. The bound is *tight* because
>    the Hamming code is **perfect** — its `2³ = 8` syndromes cover the `7` single-error patterns plus
>    zero with no waste (sphere-packing bound met with equality).
> 2. **Sightedness.** Any scheme reporting *below* third order — e.g. gossiping the `O(N²)` pairwise
>    liveness/correlations — is not merely wasteful but **Fano-blind**: the sum of the seven line-
>    adjacencies is `J − I` (spectrum `{6, −1×6}`, the complete graph `K₇`), so equal-weight pairwise
>    statistics are *provably indistinguishable from unstructured connectivity* (V11). The syndrome is
>    therefore the **minimal *sighted* report** — you cannot spend fewer bits *and* still see structure.
> 3. **Scale-invariance.** With hierarchical roll-up (a parent cell compresses its `N` child cells'
>    syndromes into its own `3`-bit syndrome — the `ParentCell` loop one tier up), the total control
>    traffic across all tiers of an `N^k` network is `((N^k − 1)/(N − 1)) · Θ(log N)` bits per window,
>    so the **per-node self-scan overhead is `Θ(log N / N)` bits per window — a constant, independent of
>    the total network size `N^k`.** The network does not pay more to watch itself as it grows.
> 4. **Vanishing fraction.** Let `B` be the mean useful payload a node carries per window. The control
>    fraction is `Θ(log N / N) / (B + Θ(log N / N)) → 0` as `B` grows, and is bounded above by
>    `Θ(log N / N) / B` — for a Fano cell, `≈ 0.4` bits/node/window of syndrome against arbitrary
>    payload. Self-observation is asymptotically **free**.

**Corollary (the reflection/report split).** The Good-Regulator budget `R ≥ 1/3` (a node must devote
`≥ 1/3` of its reflection capacity to a faithful self-model, spec §6.8) and the `Θ(log N / N)` wire
overhead are *complementary, not contradictory*: the projective code lets a rich `R ≥ 1/3` self-model be
**synchronized** across the cell with `log N` bits, because every node reconstructs the cell's coherence
from the shared syndrome plus its own local view. Requisite variety is met in *compute*; requisite
*communication* is `Θ(log N)`.

### 1.3 Why this is the strongest possible statement

Three lower bounds coincide on the same object. The **entropy** floor (you must distinguish `N+1`
states), the **coding** floor (a perfect code is the minimum redundancy to correct one error), and the
**sightedness** floor (below third order you are blind) all land on `⌈log₂(N+1)⌉` bits, and the Fano/
Hamming syndrome meets all three with equality. There is no scheme — with the same detection power — that
uses less. That is *provable efficiency*, not a tuned heuristic.

---

## 2. What is observed — the minimal sufficient statistic

The unit of telemetry is the **coherence frame** for a cell at a window, the minimal sufficient statistic
for health, and it is small by the theorem:

```
CoherenceFrame {
  cell_id:    CellId,          // which cell (or PID-scoped Γ_app cell, §5)
  epoch:      u64,
  syndrome:   u3,              // 3 bits — the Fano/Hamming fault localizer (Θ(log N))
  phi:        f32,             // Φ integration   (verifier-fixed threshold 1)
  purity:     f32,             // P structure     (2/N)
  reflection: f32,             // R self-model    (1/3)
  mean_r:     f32,             // r vs r* = 1/√6, upper 1/√3
  gap:        f32,             // Δ (recovery rate; τ = 1/Δ)
  verdict:    u8,              // Aggregate | CollectiveSubject | OverCoupled  + alarm bits
  forecast:   i16,            // cascade lead (windows to over-coupling; −1 = none)
  heal_seq:   u32,             // monotone counter of healing actions (event stream keyed off it)
}                              // ≈ 32 bytes; the load-bearing part (syndrome) is 3 bits
```

The `f32` scalars are a convenience for humans and cross-cell roll-up; the *load-bearing* health signal
is the `3`-bit syndrome (theorem §1.2.1). Healing **events** (reroute/repair/decouple/escalate/quarantine)
are a separate, sparse stream keyed by `heal_seq` — emitted only when something happens, so they cost
nothing in steady state. **No per-flow, per-node-raw, or payload-derived field ever appears** (the
anonymity floor, §5).

---

## 3. Distributed collection — push, pull, and roll-up

The network collects the frames with no central collector, three composable ways:

- **Push (gossip), for liveness.** The `3`-bit syndrome rides the existing heartbeat `DiagGossip` (spec
  §6.4) — already a fixed-size, constant-cadence frame. This is the `Θ(log N)` steady-state cost; it is
  the *only* always-on telemetry, and it is minimal.
- **Pull (DHT), for on-demand reads.** A cell publishes its `CoherenceFrame` at a rotating, access-gated
  DHT key `H("FANOS-v1/coherence" ‖ cell_id ‖ epoch)` (ONOMA-style unenumerable slot). Any node `Get`s it
  — so telemetry is *served distributedly* by the same LRC store that serves everything else, with LRC
  replication and read-repair for free. Rotation + access-gating keep it from becoming a public map of
  the network to an adversary (§5).
- **Roll-up (hierarchy), for scale.** A `ParentCell` treats its `N` child cells as its `N` points, folds
  their syndromes/scalars into *its* coherence matrix, and emits *its own* `CoherenceFrame` one tier up.
  So a monitor subscribing at tier `t` receives `N^(k−t)`-node-worth of health compressed to one frame
  per tier-`t` cell — **the same 3-bit-per-cell economy at every scale.** This is the telemetry
  realization of the `N^k` self-similar organism (coherent-cybernetics.md §2, Level 2).

The three modes are one mechanism (`H(label‖id‖epoch)` derivation) at three read patterns — consistent
with the platform's *derive-don't-negotiate* invariant.

---

## 4. The monitor-mode node & the WebSocket interface

A dashboard must not talk to the overlay directly (that would leak the observer and bypass the anonymity
floor). Instead, **the observer runs a local FANOS node in monitor mode**, which does the distributed
collection and exposes a *local* WebSocket the UI subscribes to. The UI (a server-side TypeScript app,
per the deployment plan) connects only to `ws://localhost` of its own monitor node.

### 4.1 `fanos node --monitor`

A node started with `--monitor [--scope SPEC] [--ws ADDR]` behaves as a normal overlay member (it joins,
heartbeats, self-observes) **and additionally**: subscribes to `CoherenceFrame`s over its scope (gossip
for its own cell/cluster; DHT pull for remote cells or the whole network), aggregates them into a live,
hierarchical coherence view, and serves that view over a WebSocket. It is the "special mode" the
dashboard connects to. Because it is itself a node, it collects *from inside* the network — no external
scraper, no privileged vantage.

### 4.2 The telemetry WebSocket protocol — expressive at every scale

A small, versioned, subscription protocol (JSON for tooling ergonomics; the same fields have a canonical
KAT-pinned binary form for cross-language monitors). The design goal is *one protocol that addresses any
scale* — a single cell, a cluster, the whole network, or a specific overlay's `Γ_app`.

```
// client → server
{ "v":1, "op":"subscribe",
  "scope":  { "kind":"cell"|"cluster"|"network"|"protocol",
              "id":"<cell/cluster id or PID>",         // omitted ⇒ the monitor's own cell
              "depth": 0..k },                          // roll-up tier: 0 = leaf cells, k = whole net
  "select": ["coherence","events","forecast","syndrome-map","topology"],
  "history": { "windows": 0..N },                       // backfill N windows on subscribe
  "rate_ms": 250                                        // stream cadence (server clamps to feed rate)
}
{ "v":1, "op":"unsubscribe", "sub":"<id>" }
{ "v":1, "op":"drill", "sub":"<id>", "into":"<cell_id>" }   // expand one cell to its children (zoom in)

// server → client
{ "v":1, "type":"hello", "node":"<coord>", "epoch":N, "scope_tree":{…}, "caps":[…] }
{ "v":1, "type":"frame", "sub":"<id>", "cells":[ CoherenceFrame, … ] }   // one per cell in scope
{ "v":1, "type":"event", "sub":"<id>", "cell":"<id>", "heal_seq":N,
         "action":"reroute"|"repair"|"decouple"|"escalate"|"quarantine", "detail":{…} }
{ "v":1, "type":"forecast", "sub":"<id>", "cell":"<id>", "lead_windows":N, "regime":"…" }
```

Expressiveness "at all scales" is the `scope × depth × drill` design: subscribe to the **network** at
`depth=k` for one whole-organism frame; **drill** into a hot cluster to `depth=t`; **drill** again to a
leaf cell to see its 7-node syndrome map; subscribe to a **protocol** PID to watch its `Γ_app` (the
application ecology, §5). One protocol, single cell to global, live + history, human-JSON or KAT-binary.
The `caps` field carries capability negotiation (versioned; new selectors are new capabilities, never a
fork).

### 4.3 The dashboard is a thin client

The server-side TypeScript dashboard opens the WebSocket, renders the coherence frames (Φ/P/R gauges, the
Fano syndrome map, the cascade forecast with `r* = 1/√6`, the healing timeline, the coherence history),
and offers `drill`/`scope` controls that map 1:1 to the protocol above. It holds *no* network state — the
monitor node is the source of truth — so it scales trivially and can be public (it reveals only what the
monitor node is permitted to aggregate, §5). The HTML reference panel already prototyped the visual
language on the exact coherence math; the production UI is this thin WebSocket client.

---

## 5. Anonymity-safe telemetry (the floor is structural, not procedural)

Telemetry must never become a deanonymization oracle. The floor is enforced by *what the coherence frame
can contain* (design-platform.md §5, invariant 14), and the theorem makes the safe choice also the
minimal one:

- **Cell-granularity floor (data minimization).** A frame is a *cell aggregate* — a `3`-bit syndrome plus
  scalars folded from a correlation matrix. Per-node raw signals never leave their node, and the monitor
  cannot emit (nor the WS carry) a per-flow or per-node-raw field. This is genuine **minimization** — but
  it is **not** anonymization: the syndrome still names the exact faulted point and the scalars are the
  cell's exact health, so any frame observer learns which node is down and how the cell is doing.
- **Third-order only.** By sightedness (§1.2.2), anything finer than the cell aggregate is *both* blind
  *and* forbidden — the minimal report is also the maximal safe one. The interests coincide.
- **DP-noised exports — DESIGN, not yet implemented (audit C7).** The intended floor for a *shareable*
  export is differential-privacy noise on the scalars, with favorable sensitivity (`r` is a mean over
  `21` pairs, one flow's marginal effect `O(1/21)`) so a small ε budget hides any single flow while
  preserving the cell signal — plus coarsening/withholding the exact syndrome. **The current
  `fanos-telemetry` build has no DP machinery** (no noise, no ε budget): an emitted `CoherenceFrame`
  carries the exact syndrome and scalars and must NOT be treated as anonymized until this is built.
- **Full-domain frames carry no timing.** For a `Full`-privacy cell, the frame excludes schedule-derived
  fields (constant-rate cover makes them information-free anyway); a `Direct` cell may expose more.
- **Per-PID `Γ_app`.** An overlay's own coherence is a first-class scope, so app developers watch *their*
  protocol's health (`Φ_app < 1` ⇒ "my messenger's cell is fragmenting") without ever seeing "user X sent
  Y" — the same anonymizing fold, applied per tenant.

---

## 6. Scale — from one cell to a self-observing planet

The `scope × depth` design and the scale-invariance theorem (§1.2.3) together mean the *same* tooling
serves a laptop devnet and a global deployment:

- **One cell (devnet / a single operator):** subscribe `scope=cell` — 7 nodes, one syndrome map.
- **A cluster (a datacenter / a community):** `scope=cluster, depth=t` — a rolled-up organ.
- **The whole network:** `scope=network, depth=k` — one whole-organism frame at `Θ(log N / N)` per-node
  cost, drillable on demand.
- **The application ecology:** `scope=protocol` — the coherence of the overlays the substrate hosts, the
  reflexive plane observing its symbionts.

This is also the on-ramp to **consensus-via-coherence** (roadmap Phase 6): a coherent-blockchain commit
rule "the cell agrees iff `Φ ≥ 1`" reads the *same* frames this telemetry plane already distributes — the
monitor is the ledger's sensor, one quantity end to end.

---

## 7. Implementation plan

Ordered, non-breaking, each independently valuable:

1. **`CoherenceFrame` + KAT** — the canonical (JSON + binary) frame, pinned in `conformance/vectors/`; the
   `3`-bit syndrome already comes from `fanos-code`/`fanos-diakrisis`. (Closes the "what is observed"
   contract.)
2. **Gossip carry** — publish the syndrome + scalars over the existing `DiagGossip` (push mode) — the
   always-on minimal telemetry.
3. **DHT publish/subscribe** — the rotating coherence slot `H("coherence"‖cell‖epoch)` (pull mode) +
   access-gating, reusing ONOMA derivations.
4. **Roll-up** — `ParentCell` emits a tier-`t` frame from its children (scale mode).
5. **`fanos node --monitor`** — the local aggregator + the WebSocket server (the dashboard backend).
6. **DP + Full-domain field masking** — the anonymity floor (§5), enforced at the WS boundary.
7. **The TS dashboard** — the thin WebSocket client (server-side framework), rendering the coherence
   frames at any scope/depth.

Every headline claim here is a theorem or a test: the overhead bound (§1) is provable and the frame is
KAT-pinned, so *"the network scans itself at the information-theoretic minimum"* is reproduce-then-verify,
not a slogan.
