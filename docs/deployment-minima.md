# Minimum deployment: how many nodes, and what hardware

Derived in closed form, **measured** on a running node, and **confirmed** by a simulator that was not told the
answer — 2026-07-29. Every figure below either follows from a theorem, follows from a constant in the tree, or
was read off a live process; where a number is an estimate rather than a measurement, it says so.

## Part 1 — How many nodes

The first version of this document answered by reading constants off the implementation. That is not an answer,
it is an inventory. A number worth trusting falls out of the dynamics and is then visible in a measurement that
did not consult it, so this part gives the derivation first and the measurement second.

### The scaling law

On the equicorrelated stratum (spec §2.7) the two closed forms

```
Φ(N, r) = (N − 1) r²        P(N, r) = (1 + (N − 1) r²) / N = (1 + Φ) / N
```

collapse every question about cell size onto one variable. Four consequences follow, all machine-checked in
`fanos_diakrisis::minima`:

**1. Viability and integration are one condition.** `P > 2/N ⟺ 1 + Φ > 2 ⟺ Φ > 1`. The septicity theorem
`P_crit = 2/N` and the integration threshold `Φ_th = 1` are the same requirement written twice.

**2. The collective-subject window does not depend on `N`.** Its edges in mean correlation do —
`(1/√(N−1), √(2/(N−1))]` — but in integration they are the constants `Φ ∈ (1, 2]`, equivalently
`P ∈ (2/N, 3/N]`. A cell grows by *diluting* correlation at exactly the rate that holds `Φ` still.

**3. The stability radius falls as the cell grows — and fault tolerance does not.** Since `r_stab = √(P − 2/N) = √((Φ − 1)/N)` and
`Φ ≤ 2`:

```
r_stab ≤ 1/√N
```

attained only at the top of the window. T-104 survives sustained noise `h` iff `h < κ·r_stab`, so the
disturbance an `N`-node cell can absorb is at most `κ/√N` — and with `κ_bootstrap = ω₀/N`, at most `ω₀·N^(−3/2)`.

**The tempting reading of that is wrong, and this document carried it for most of a day.** "A larger cell has a
smaller radius, so it is less robust" compares an absolute distance without asking what it is measured against
— and the disturbance scales too. One decorrelated node consumes **34.5 %** of a Fano cell's radius and
**0.2 %** of a `PG(2,31)` cell's. Both the capacity and the per-fault cost fall as `N^(−3/2)`, and they cancel.
What survives the cancellation is the fault count in the table further down, and that is what a deployment
feels.

One qualification before it. The condition is `Φ ≤ 2`, i.e. `P ≤ 3/N` — purity that *scales down* with the cell. Hold purity at an absolute
level instead and `r_stab = √(P − 2/N)` runs the **other way**, because the subtrahend `2/N` shrinks: at
`P = 0.75` the radius climbs from `0.699` at `N = 7` to `0.865` at `N = 993`, and integrating the reduced
dynamics there measures a critical attack that *grows* with the cell (`0.725` at `N = 7`, `3.875` at `N = 21`).

Only the first case describes a cell this platform would keep, and the reason is exact: `R = 1/(N·P)`, so the
self-model floor `R ≥ 1/3` **is** `P ≤ 3/N`. A cell at absolute purity `0.75` has `R = 0.19` on a Fano plane —
over-coupled, no longer self-observing, and what the homeostat answers with `Decouple`. Both statements are
pinned in `fanos_diakrisis::minima`.

| cell, held in-band | `r_stab ≤ 1/√N` | **node failures absorbed** | as a fraction |
|---|---|---|---|
| 7 (Fano) | 0.378 | **2** | 28.6 % |
| 21 | 0.218 | **6** | 28.6 % |
| 57 | 0.132 | **17** | 29.8 % |
| 993 | 0.032 | **291** | 29.3 % |

**The fraction is a constant, and it is derived.** Let `k` nodes decorrelate and `m = N − k` stay intact; only
intact pairs carry off-diagonal mass, so `P(k) = 1/N + m(m−1)r²/N²`, and at the top of the band the viability
condition `P > 2/N` reduces to `2m(m−1) > N(N−1)`:

```
k/N  →  1 − 1/√2  ≈  0.2929
```

independent of `N`. Compare the Byzantine tolerance `f/N → 1/3`: the coherence bound sits just inside it, and
two derivations from unrelated parts of the theory agreeing within four points is the best evidence either one
carries. **Cell size costs nothing in fault tolerance** — a `PG(2,31)` cell absorbs 291 simultaneous failures
where a Fano cell absorbs two.

**4. There is an absolute floor at `N = 3`.** The window in `r` is `(1/√(N−1), √(2/(N−1))]`, whose lower edge
reaches `1` at `N = 2` — and a correlation cannot exceed one, so the window is empty. Two nodes cannot form a
collective subject at any coupling whatsoever. This floor comes from the mathematics rather than from any
design choice, which is why every other floor sits above it.

### Four floors, four mechanisms

The minimum depends on which property you want, and the largest floor that matters to you is your minimum.

**Coherence — 3.** Result 4 above. Never binds in practice.

**Geometry — 7.** A cell is `PG(2, q)` and the smallest projective plane is Fano, `q = 2`, `n = q²+q+1 = 7`.
`CellParams::derive` refuses `q < 2`. Supported orders `q ∈ {2, 4, 7, 31}` give cells of **7, 21, 57, 993**.

**Consensus — 5 of 7 must be present.** With `f = ⌊(n−1)/3⌋` and quorum `Q = ⌈(n+f+1)/2⌉`:

| `q` | nodes `n` | faults tolerated `f` | quorum `Q` |
|---|---|---|---|
| 2 | 7 | 2 | 5 |
| 4 | 21 | 6 | 14 |
| 7 | 57 | 18 | 38 |
| 31 | 993 | 330 | 662 |

A Fano cell survives **two** faults and halts at three — the tightest possible PBFT system, not a weakness, but
it leaves no spare capacity for a third simultaneous failure.

**Storage — 4 survivors always, 3 usually.** This is where the earlier version of this document was wrong. It
read `[7,3,4]` as "any 3 shards reconstruct, so storage survives four losses". The code is a projective LRC and
not MDS: its guarantee is that peeling recovers any **≤3** losses, and among four-member losses the
irrecoverable patterns are **exactly the hyperovals** — four points no three of which are collinear, so every
line meets them in 0 or 2 points and peeling never finds a single exposed loss to start from. The Fano plane has
seven hyperovals out of 35 four-subsets.

### Measured, not assumed

`cargo run -p fanos-sim --example minima --release` disperses a value across a full cell, then enumerates
**every** loss pattern — not a sample, because at four losses the outcome depends on which four. Pinned as
tests in `crates/fanos-sim/tests/minima.rs`.

| members lost | survivors | patterns | reads still served |
|---|---|---|---|
| 0–3 | 7–4 | 64 | **all of them** |
| 4 | 3 | 35 | **28** — the 7 failures are exactly the hyperovals |
| 5 | 2 | 21 | none |
| 6 | 1 | 7 | none |

The failure set of the live storage stack equals the geometry's prediction exactly, in both directions. That is
a stronger statement than either the decoder's own tests or the network's: a layer that quietly replicated whole
values would pass every decoder test and read back from one survivor.

Two further findings from the same sweep, both corrections to what was believed:

* **A filling cell has no storage floor at all.** Shard homes are *points of the plane*, so in a small cell
  every shard lands on one of the few live members and a read reconstructs locally. The erasure floor bounds
  **shards, not nodes**, and cannot bind while a cell is still growing. It binds only in attrition.
* **A cell calls itself healthy only when the plane is complete.** Below seven members the absent points read
  as down, and the nodes are right to say so.

### The anonymity floor — and a defect found while measuring it

**The flow-matching floor.** An adversary's floor is `1/K` for `K` concurrent circuits, and `K` comes from the
plane. On a Fano cell that is `1/7` at best, so a 7-node network is a functional testbed, not an anonymity
system. That much was already known.

**What was not known: the hop threshold does not scale with the plane.** `MIX_THRESHOLD = 2` is a constant used
for every field, while a hop is a line of `q+1` points and the Byzantine tolerance `f = ⌊(n−1)/3⌋` grows with
the plane. Two points lie on exactly one line, so each corrupt *pair* captures one hop:

| `q` | nodes | line | tolerated `f` | **hops captured** | worst case |
|---|---|---|---|---|---|
| **2** | 7 | 3 | 2 | **0.143** — exactly 1 line of 7 | 0.143 |
| 4 | 21 | 5 | 6 | 0.450 | 0.714 |
| 7 | 57 | 8 | 18 | **0.795** | 1.000 |
| 31 | 993 | 32 | 330 | **≈1.000** | 1.000 |

At `q = 2` the tolerance equals the threshold, so exactly one line falls and one line cannot be both ends of a
circuit — **end-to-end deanonymization is impossible at the default plane**. Above Fano the tolerated corruption owns most or all
hops — 80 % at `q = 7`, effectively every one at `q = 31` — so **the MIX lane's guarantee is gone above the
default plane** under the platform's own fault assumption.

**This inverts the sizing advice.** Raising `q` buys a larger anonymity *set* and destroys hop strength, so
today the plane-order knob cannot be used for anonymity at all. The fix is derived and changes nothing at the
default — `t = ⌈2(q+1)/3⌉` evaluates to `2` at `q = 2` — and with it hop capture falls as the plane grows
instead of rising to certainty. Recorded as `docs/audit.md` E7 (HIGH, open); full working in
`docs/design-anonymity-substrate.md` §4a.

| cell | anonymity floor `1/K` | deanonymization at tolerated `f` | faults absorbed |
|---|---|---|---|
| 7 (Fano), `t = 2` | 1/7 — testbed only | **0** | 2 |
| 993 (`q = 31`), `t = 2` — the old constant | 1/993 | **≈1.0 — no anonymity** | 291 |
| 993, with `t = ⌈2(q+1)/3⌉ = 22` | 1/993 — credible | ~0 | 291 |

**Raising the plane order is free in fault tolerance** (result 3 above: the tolerated fraction is `1 − 1/√2` at
every size), so with the threshold fixed there is no reason not to. Its real prices are elsewhere and worth
naming:

* **Coordination.** A quorum of 662 of 993 rather than 5 of 7, and PBFT is quadratic in messages — a round on
  `PG(2,31)` costs roughly `(993/7)² ≈ 20 000×` a Fano round. This is the dominant cost of a large cell.
* **Hop liveness.** `t = 22` of a 32-point line: two thirds must be reachable to peel a layer. The same
  *ratio* Fano runs at, stricter in absolute terms.
* **Finding 993 operators**, which is not a technical cost but is a real one.

So the architecture separates anonymity from fragility and leaves an honest trade of *anonymity against
coordination* — the right one to be left with, since coordination can be engineered down and fragility cannot.

### So, in practice

| purpose | minimum | note |
|---|---|---|
| a working overlay: membership, storage, healing, self-diagnosis | **7** (one Fano cell) | also the most robust size, for a cell held inside the band |
| a blockchain cell (TAXIS) | **7 validators**, 5 present | quorum 5, survives 2 failures |
| serving reads after failures | **4 survivors** | 3 survivors work for 28 of 35 loss patterns |
| a mixnet relay path | 3 hops of 3 members | sound at `q = 2` (deanonymization impossible within `f = 2/7`) and **unsound above it** — `MIX_THRESHOLD` does not scale (E7) |
| **credible anonymity** | **not currently reachable** | `q = 31` gives the `1/K` set but zero hop strength until E7 is fixed |

The mixnet row is a statement of what is built, not a recommendation. Hop strength is sound *only* at the
default plane, and a wider plane — the obvious answer to the `1/K` set size — removes it. Both are needed
together, which is what E7 unblocks.

## Part 2 — Hardware

### Measured, on a release build

A single node, steady state, no traffic:

| | |
|---|---|
| resident memory | **7.6 MB** |
| CPU, idle | **~0%** |
| binary | **9.9 MB** (release; 55.7 MB debug) |

That is the floor, and it is small because the engine is sans-I/O and every collection in it is bounded.

### Bounded by construction, not by hope

The memory ceiling is a sum of explicit caps rather than an empirical guess. The load-bearing ones:

| cap | value | what it bounds |
|---|---|---|
| `MAX_STORE_ENTRIES` | 4096 keys | the overlay store |
| `MAX_VALUE_LEN` | 64 KiB | one stored value |
| `MAX_PENDING_GETS` | 1024 | reads in flight |
| `HELD_CAP` | 512 | own shards retained to serve peers |
| `PENDING_CAP` | 64 | skeletons awaiting reconstruction |
| `SEEN_TX_CAP` | 8192 | transaction dedup (validator) |
| `RECENT_BODY_CAP` | 64 | finalized bodies kept to help a lagging peer |

Worst-case store: `4096 × ⌈64 KiB / 3⌉ ≈ **85 MB**` of shards on a node holding one shard per key; a *sparse*
cell holds several shards per key and scales that up by the number of points it covers.

### Recommended, by role

Estimates from the measurements plus the caps — not measured under load, and marked as estimates:

| role | RAM | CPU | disk | network |
|---|---|---|---|---|
| **relay / storage** (the default) | 256 MB | 1 core | 1 GB | any stable link; cover traffic is constant-rate, so budget for it |
| **validator** (TAXIS) | 512 MB | 2 cores | 2 GB | consensus is chatty per round; latency matters more than bandwidth |
| **shielded-pool user** (OBOLOS) | 2 GB | 4 cores | — | **the heavy case**: a zero-knowledge proof at real parameters takes **~40 s on a release build**, and far longer unoptimised |

The three numbers that actually drive the recommendation:

1. **Admission proof-of-work.** Bounded at 30 bits by design — about a minute on one modest core — and the
   ceiling exists to protect the *newcomer*, not the cell. Any machine that can spend a minute of one core can
   join.
2. **The engine's own compute is negligible.** ~0% idle CPU, and the inline work is deliberately capped:
   `MAX_INLINE_ADMISSION_BITS = 20` (~0.1 s) so a solve cannot block an observation window.
3. **OBOLOS proofs dominate anything else.** If a deployment does not use the shielded pool, 256 MB and one
   core is genuinely enough; if it does, size for the proof.

### What was not measured

Under-load memory and CPU, disk I/O rates, and bandwidth per role. The caps give a hard ceiling on memory, so
the risk there is bounded; the CPU and bandwidth figures above are extrapolations from an idle node and should
be measured before a production sizing is published.
