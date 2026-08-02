# Coordination-free rendezvous: what the geometry buys, and what it does not (design)

> Status: **research finding + accepted correction.** Written in answer to a direct challenge — *"why has
> nobody used the Fano plane before us? maybe because it is not the most efficient option?"* — and to the
> follow-up demand that the architecture be re-derived from first principles rather than defended.
>
> The short answer, up front and without varnish:
>
> 1. **People have used it.** Maekawa used finite projective planes for distributed quorums in 1985, and the
>    plane is a *theorem*, not a taste: it is the provably minimum-size quorum system.
> 2. **That theorem does not apply to rendezvous.** Rendezvous is an *agreement* problem, not an
>    *intersection* problem, and the plane's defining property is idle in the rendezvous layer.
> 3. **The plane still earns its place**, but for a different reason than the one recorded — a
>    membership-independent address space with a routing structure, which no hash-based competitor provides.
> 4. **Auditing the layer found two real defects, and the second is the larger.** `meeting_lines` cost
>    `Θ(n)` host registrations (§5) — §6 replaces the count with a derived bound constant in `n`, leaving the
>    shipped Fano cell's *stronger* guarantee intact. And the client drew **one** meeting point and gave up
>    (§5.1), so the entire censorship derivation — old count and new alike — bought nothing: per-dial success
>    was `1 − f/n` regardless of how many points existed.

## 1. The problem, stated so it can be answered

A host `H` owns a service identity `sid` (a public key). A client `C` knows `sid`. Both know the epoch `e`
and its beacon `β` — public, and unpredictable before the epoch opens. They have never communicated, there
is no directory, and no third party may be asked.

Each independently computes a set of network locations:

```
R_H(sid, e, β) ⊆ Places      — where the host registers
R_C(sid, e, β) ⊆ Places      — where the client looks
```

The scheme **works** in epoch `e` iff `R_H ∩ R_C ⊄ A`, where `A` is the adversary's set.

## 2. The decision rule, fixed before anything is measured

| # | Requirement | Why it cannot be traded |
|---|---|---|
| **R1** | **Zero-membership.** `R` is computable from `(sid, e, β)` and the node's own coordinate — without knowing who else is in the network. | A membership roster *is* a directory. A directory is a coordination point, an enumeration target, and the standing criticism of Tor. A scheme that needs one is not coordination-free; it is coordination-deferred. |
| **R2** | **Survives `f` faults.** | Rendezvous must not be the single point of failure for every service. |
| **R3** | **Unpredictable.** `R` for a future epoch is not computable in advance. | Otherwise the adversary pre-positions. |
| **R4** | **Balanced.** No node is hot. | |
| **R5** | **Endpoint separation.** No single node learns both `C` and `H`. | This is the anonymity property; without it the rest is a CDN. |
| **R6** | **Churn-stable.** One node leaving does not relocate other services' rendezvous. | |

**The rule: failing R1 is disqualifying, whatever the other numbers say.** Among R1-passing schemes,
minimise (state, messages) subject to R2–R6.

## 3. Every candidate, and how it does

| Scheme | R1 zero-membership | Meeting size | State | Verdict |
|---|---|---|---|---|
| **Rendezvous hashing (HRW)** — `top-k by H(sid‖e‖β, node)` | ✗ **needs the roster** | `k`, sets identical | `O(n)` | **Disqualified by R1.** Optimal churn (1/n keys move) and the cheapest meeting there is — but you cannot take an `argmax` over a set you do not have. |
| **Consistent hashing / Kademlia DHT** | ✗ roster *and* an `O(log n)` lookup | `k` closest | `O(log n)` + lookup | **Disqualified twice.** The lookup is itself coordination, and it broadcasts the target to the path — fails R5 outright. |
| **Grid quorums (`√n × √n` row+column)** | ✗ needs the grid assignment | intersection ≥ 1 | `O(√n)` | Disqualified by R1; also `2√n − 1` vs the plane's `√n`. |
| **Random `k`-subset from a PRF seed** | ✗ needs the roster to draw *from* | probabilistic | `O(n)` | Disqualified by R1. Also strictly worse if it *were* an intersection problem: two independent `k`-draws meet with probability `1 − e^{−k²/n}`, so `k ≈ √(n·ln(1/ε))` — worse than the plane's `√n` *with certainty*. |
| **Stratified mixnets (Loopix, Nym)** | ✗ published directory + SURBs | — | `O(n)` | Not a rendezvous primitive at all: Nym rendezvous *is* a directory lookup. Excellent mixing bounds, which is a different layer (§7). |
| **Random-walk rendezvous** (search-theory classic) | ✓ | — | `O(1)` | Passes R1 and fails R2's latency: expected meeting time is `O(n)` steps with no useful tail bound. |
| **Cyclic difference set / Singer representation** | ✓ | `q+1` | **`O(1)`** | *This is the projective plane* — Singer's theorem says every `PG(2,q)` is cyclic, so a line is `{a + d mod n : d ∈ D}` for a fixed planar difference set `D`. Same design, cheaper representation. |
| **`PG(2,q)` lines (FANOS)** | ✓ | `q+1` | `O(1)` | The only survivor. |

**Exactly one family passes R1**, and the last two rows are the same family in two coordinate systems.

## 4. Why the plane survives — and why the usual justification is wrong

The recorded justification for `PG(2,q)` is Maekawa's optimality theorem:

> **Theorem (Maekawa 1985).** For a quorum system on `n` nodes in which (i) any two quorums intersect,
> (ii) every quorum has size `k`, and (iii) every node lies in equally many quorums — `n ≤ k² − k + 1`, with
> equality **iff** the system is a finite projective plane of order `k − 1`.

That theorem is real, it is the reason projective planes are textbook-optimal quorums, and it is a complete
answer to *"why has nobody used this before"* — [they did, in 1985](http://article.sapub.org/10.5923.j.ac.20120204.02.html),
and the grid alternative is [exactly twice as large](https://arxiv.org/pdf/2308.15000).

**It is also the wrong theorem for this layer.** Maekawa's setting is two quorums chosen *independently*,
which must be made to intersect. In rendezvous both parties evaluate *the same pure function of the same
public input*, so they can simply take `R_H = R_C`. Agreement is free; intersection is a cost you pay only
when you cannot agree. Read `meeting_lines` and this is plain — both sides run the identical loop and take
the identical list. **The plane's defining property, that any two lines meet in exactly one point, is never
invoked by rendezvous.**

So what is actually load-bearing?

- **A membership-independent address space (R1).** A projective *point* exists whether or not anyone
  occupies it. `H(sid‖e‖β)` lands on a coordinate, and the coordinate→node binding is the VRF seating
  (`design-coordinates.md`). This is the property HRW cannot have at any price, and it is the whole reason
  the geometry is here.
- **A place that is a *set*, with a threshold (R2).** A meeting point is a *line* — `q+1` nodes with a
  `t`-of-`q+1` combiner — so a place survives faults without a roster.
- **λ = 1, in the transport underneath (R5).** Consecutive onion hops are lines, and because any two lines
  meet in exactly one point, a hop always has a relay to hand off to *with no routing table*. This is where
  the plane's axiom does real work — carrying the client to the meeting point, not agreeing on it.

That is a narrower claim than the architecture has been making, and it is the true one. The plane is a
**routable, membership-free address space**; calling it an optimal quorum system is importing a guarantee
from a problem FANOS does not have.

## 5. The defect this exposes

`meeting_lines` derives its meeting-point count `m` by pigeonhole:

> an adversary holds `A` with `|A| = f = ⌊(n−1)/3⌋`; with `m ≤ f` combiners it covers them all; with
> `m = f + 1` at least one is left over.

The argument is valid. Its cost was never computed. Since `f = ⌊(n−1)/3⌋`:

```
m = f + 1 ≈ n/3          host registrations = m·(q+1) ≈ n(q+1)/3
```

**`m` is linear in `n`.** The host must touch a *third of the network*, and register at every member of each
line — which is `Θ(n√n)` work and, past the base cell, means registering at every node several times over.
That is the exact opposite of the `√n` scaling the plane was adopted for. Measured
(`fanos-rendezvous/tests/meeting_cost.rs`):

```
  q     n   f+1   f+1 regs   m   m regs   regs/n
  2     7     3          9   3        9     1.29
  4    21     7         35   7       35     1.67
  7    57    19        152  13      104     1.82
  8    73    25        225  13      117     1.60
 13   183    61        854  13      182     0.99
 16   273    91       1547  13      221     0.81
 31   993   331      10592  13      416     0.42
```

Read the `f+1 regs` column: at `q = 31` a single host registers **10,592 times on a 993-node plane** — it
touches every node ten times over to publish one service. The `m` column is §6's replacement, and `regs/n`
falls under it (1.82 → 0.42) exactly where the pigeonhole column keeps climbing.

### 5.1 A second defect, larger than the first: nothing walked

Auditing the count led to the client, and the client was worse. `meeting_lines` returns `m` points; the dialer
picked **one uniformly at random** and, if it failed, returned `Unreachable`. Nothing retried — a grep of the
whole dial path found `anonymous_dial` called exactly once per dial.

So the property *proved* was "an uncensored meeting point **exists**", and the property *implemented* was "a
uniformly-drawn meeting point works". Per-dial success was `1 − f/n ≈ 2/3` **no matter how large `m` was**.
Every meeting point past the first was dead weight, and the entire censorship derivation — the old `f + 1` and
the new `m` alike — bought nothing a single point would not have.

This is the recurring shape: a derivation establishes that a *set* contains a good element, and the code
samples one element and stops. Failure here is *observable*, so the fix is a **walk**, not a re-draw:

- **Start at a random point.** The randomness was never the point of the single pick — *unlinkability* was
  (two dials by one client must not share a first contact, or a node at that point links them). A random start
  keeps each dial's first contact uniform; the search supplies the coverage the derivation promised.
- **A liveness signal, because a byte stream cannot supply one.** Telling a *censored* meeting point from a
  merely *quiet* one is impossible from a `DuplexStream` — both are silent. The session driver knows, because
  it has a handshake, so it now returns one (`Ok` on establishment, `Err` on give-up).

### 5.2 The measurement that overturned the first fix

The obvious design — try a point, give it a deadline, move on — was implemented, measured, and **discarded**.
A deadline forces the question "censored, or slow?", and over this mixnet that question has no cheap answer.
Twelve healthy handshakes through a live meeting point, timed:

```
0.26  1.14  1.15  2.24  2.53  3.01  3.02  3.03  3.14  3.58  6.69  14.86   seconds
```

A median near 3 s with a tail past 14. **Any deadline short enough to catch a censor also abandons live
paths** — and abandoning a live path is worse than never walking at all. Measured directly: a 3.75 s
per-attempt deadline delivered **7 of 12** dials, below the 8 a single draw would be *expected* to manage.

So the deadline was replaced with **hedging** (Dean & Barroso, *The Tail at Scale*): attempts are *added*
every `HEDGE_DELAY` and never withdrawn, and the dial completes at the **minimum** over the points tried. The
asymmetry is the whole argument — hedging too early costs one extra onion, timing out too early costs the
dial — and it is what lets the delay be set from the measured distribution (3.75 s ≈ the third quartile, so
most dials never hedge) instead of argued from a worst case. The anonymity price is that a hedged dial tells
two meeting points that a dial happened rather than one; neither learns who dialled, nor that the two are one
client, and the key selecting them is public. That buys tail latency with bandwidth, not with linkability.

### 5.3 And the censorship test was not testing censorship

Falsifying the fix — reverting to a single draw — left `the_service_survives_one_meeting_point_going_silent`
**green**, which meant the test could not see the defect it was named for. Two reasons, both worth recording:

1. It looped up to eight times and passed on the first arrival. That measures "the service is not
   *permanently* censored" — which a client drawing one point already satisfies, since two of three points are
   live and eight tries will find one. It now asserts **every** dial arrives, with the attempt count set by
   falsification power (`(2/3)¹² < 1%`).
2. It silenced a meeting point's **canonical combiner**, and that does not silence the meeting point.
   Since #55 a launch draws a *salted* per-onion member of the line, so the line's `t`-of-`q+1` quorum absorbs
   the loss — which is the property `rendezvous_host.rs` already claims ("silencing a meeting point costs the
   adversary a `q + 2 − t` quorum of its line rather than one node") and which nothing had ever confirmed.
   The instrumented run confirms it: with the combiner down, **every** dial still landed on attempt 0.

That is a stronger result than the test was asking for, and it is now the thing the test should be pinning.

## 6. The correct derivation

The pigeonhole bound assumes the adversary can **aim** `A` at this service's meeting combiners. It cannot,
and the reason is already an axiom of the platform:

- **`A` is fixed before `β` is drawn.** Corruption takes time; the beacon rotates every epoch. The combiners
  are `H(sid‖i, e, β)` — unknowable when `A` was assembled.
- **The adversary cannot choose its coordinates.** `coord = MapToPoint(VRF(sk, node‖epoch‖beacon))` is
  identity-bound and HELLO-proven (`design-coordinates.md`, §3.2 assumption 1). So `A` is a *uniformly
  random* `f`-subset of the plane's points — the same assumption every other bound in the system already
  rests on.

Under that model, each meeting combiner is adversarial independently with probability `f/n`, and

```
Pr[service censored in one epoch] = Pr[all m combiners ∈ A]
                                  = C(f,m) / C(n,m)          (sampling without replacement)
                                  < (f/n)^m                   (a strict upper bound)
```

The target is stated as a **horizon** rather than a bare probability, because that is the form an operator can
argue about: `CENSORSHIP_HORIZON_EPOCHS = 2²⁰` is the number of epochs over which *at most one* censored epoch
is expected — ≈120 years at one epoch per hour. Solving `(f/n)^m ≤ 1/H`:

> **m ≥ log H / log(n/f)**, and with `f = ⌊(n−1)/3⌋` that is `log₃ H` — **constant in `n`**.

| horizon `H` | `m` |
|---|---|
| `2¹⁰` (≈6 weeks hourly) | 7 |
| `2²⁰` (≈120 years hourly) | 13 |
| `2³⁰` (≈120 000 years) | 19 |

The horizon is the *single* policy input; everything else is derived. It buys itself cheaply — a
thousand-fold longer horizon costs about six more meeting points — which is why it can be set generously
rather than tuned. Censorship is also not permanent: the next beacon redraws every combiner, so a service
censored with probability `3⁻ᵐ` in one epoch is reachable in `1 − 3⁻ᵐ` of them, each failure self-healing at
the next rotation.

The two bounds are not competing — take whichever is cheaper at each plane:

```
m = min( f + 1 ,  ⌈ log H / log(n/f) ⌉ )
```

- `q ≤ 5` → `f+1 ∈ {3,5,7,11}` wins, and the guarantee stays **deterministic**: censorship is *impossible*,
  not merely improbable. **The shipped Fano cell keeps `m = 3` and its stronger bound, unchanged.**
- `q ≥ 7` → the probabilistic bound wins and stops the growth. At `q = 31` it is 13 instead of 331.

The crossover falls exactly where the deterministic bound becomes unaffordable. That is not a coincidence
worth admiring — it is why a *minimum* of the two is the right shape.

The solve is **integer-only**. Client and host compute this count independently with no channel to compare it
on, so an `f64::ln` whose last bit differs between two platforms' libm would be a silent split; the
fixed-point iteration truncates *downward*, which biases `m` high — toward more meeting points than the bound
needs, never fewer. Against the exact hypergeometric the conservatism costs at most one point
(`tests/meeting_cost.rs` asserts the gap stays under two).

### 6.1 What the probabilistic bound depends on

Recording these because they are now load-bearing and were not before:

1. **The coordinate VRF** must keep `A` unaimable. Already assumption 1 of §3.2 — no new trust.
2. **A *static* adversary — and for a public service that is not a TODO, it is a limit.** If an adversary can
   watch registrations, identify which belong to the target, and corrupt those nodes *within* the epoch, it
   aims after the fact and only the pigeonhole bound holds. The obvious remedy is to blind the registration
   tag. **It cannot be done for a public service, and the reason is structural rather than unimplemented:**

   > The combiner routes a request to a registration by matching a tag. The client must compute that tag with
   > no contact with the host and no secret beyond the service's *public* key. Anything a client can compute
   > from public data, an adversary can compute from the same public data. So for a service anyone may dial,
   > the registration→service link is **inherently public**, whatever the tag's construction.

   Today's tag is `H(RDV_HOST, signing_key ‖ epoch)`, which is exactly that, and folding in the beacon would
   change nothing — the beacon is public too.

   **And in the shipped code the leak is blunter than that argument.** `HostRegister.identity` carries the
   service's canonical published identity bundle *verbatim*, so the combiner can recompute the tag rather than
   believe it — a sound anti-forgery check whose consequence had not been written down: a node at a meeting
   point is simply **handed** the list of services registered there. Blinding the tag while the identity
   travels beside it is a non-fix, which retires the "blinded, beacon-bound tag" of anonymity residual #49.

   It also sharpens the adversary model above. An adaptive adversary does not have to *infer* which
   registrations are the target's; holding any one combiner gives it the list. So the probabilistic bound
   rests on the adversary being unable to *act* on that list within the epoch, which is a weaker footing than
   "it cannot aim" — the honest reason `q ≥ 7` is a static-adversary claim.

   The real escape is **key blinding** (Tor v3's mechanism): register under `blinded_vk = Blind(vk, epoch,
   nonce)` and sign with the blinded key, so the combiner verifies the binding without ever seeing the
   unblinded identity. Anyone holding `vk` can still link — correct for a public service — while an
   **authorized-only** service folds the client-authorization secret into the blinding factor and becomes
   unlinkable to everyone else. The obstacle is real rather than clerical: FANOS signs with a hybrid ML-DSA
   construction and ML-DSA has no standard blinding, so this is research (task #39), not a patch. The two
   regimes therefore have genuinely different censorship guarantees:

   | service | adaptive-within-epoch adversary | static adversary |
   |---|---|---|
   | public | pigeonhole bound only (`m = f+1`) | the derived `m` holds |
   | client-authorized | the derived `m` holds | the derived `m` holds |

   `q ≥ 7` public deployments therefore hold the probabilistic bound against a static adversary, which is the
   model every other bound in this system already assumes (§3.2). Recording it as a *property of the regime*
   rather than as pending work is the point; task #16's authorization mode is what buys the stronger cell.
3. **The combiner map must cover the plane.** If `combiner_for` had a small image `S`, a random `A` would
   still meet `S` in `≈ f|S|/n` points and the `f/n` rate survives — but a *degenerate* image (as
   `PG(2,7)`'s 14-of-57 once was, before `combiner_of` was spread) breaks the distinctness walk first. The
   measurement in `meeting_cost.rs` asserts the walk reaches its requested count on every plane.

## 7. The layers this does not touch

Being honest about scope: this finding is confined to *how many meeting points a service takes*. Two
neighbouring layers were examined and are not implicated.

- **Mixing.** Stratified topologies (Loopix, Nym) have provable mixing bounds that a plane does not
  automatically inherit. FANOS's per-hop line quorum is a different mechanism, and comparing the two is a
  separate measurement — it is *not* settled by anything here.
- **Placement.** HRW's churn behaviour (1/n keys move per departure) is genuinely better than a re-seat,
  and it is unavailable only because of R1. If a future layer ever *does* have a roster in hand, HRW is the
  right tool there and the plane is not.

## 8. The ten advances

Checked at the user's request against
[OpenAI's ten advances](https://openai.com/index/ten-advances-in-mathematics/)
([formalizations](https://github.com/openai/ten-proofs)). Two touch FANOS; neither changes this design.

- **#7, hardness of approximating the Closest Vector Problem to polynomial factors, "with related
  consequences for decoding and lattice problems."** FANOS's post-quantum floor is lattice-based
  (ML-KEM/ML-DSA, the RLWE VRF backend, OBOLOS lattice commitments). A *strengthened* CVP hardness result is
  good news for that floor. It is asymptotic, so it moves no parameter set: **reassuring, not actionable.**
- **#2, exponentially stronger upper bounds for binary codes at every minimum distance.** FANOS's codes are
  Hamming(7,4) (the Fano syndrome) and the extended Golay `[24,12,8]` of the Turyn federation. Both sit at
  *exactly known* optima, by different routes: Hamming(7,4) is a **perfect** code, tiling the space with
  equality in the sphere-packing bound (and the perfect binary codes are completely classified); the extended
  Golay is not perfect — that is its `[23,12,7]` shortening — but it attains `A(24,8) = 4096`, an exact value,
  uniquely. A *stronger upper bound* is a statement about how large a code **can** be, so where the exact
  optimum is already known it can neither improve nor invalidate it. The result therefore **confirms both
  codes FANOS uses are the best possible at their parameters** — and confirming is all it can do.

The other eight (sphere packing, non-sofic groups, Connes rigidity, permanent lower bounds, quantum parallel
repetition, Ehrhart, multicolour Ramsey, extremal graph compactness) have no bearing here, and claiming
otherwise would be the kind of decoration this document exists to remove.

## 9. Verdict

The challenge was fair, and the audit it forced found more than the challenge did. The outcome is not a
rewrite:

- **Keep the plane.** It is the only candidate that satisfies R1, and the only one that gives a routable
  address space without a directory.
- **Correct the justification.** It is a membership-free routable address space, *not* an optimal quorum
  system. The optimality theorem is real and belongs to a different problem.
- **Fix the count.** `m = min(f+1, ⌈log H / log(n/f)⌉)` — derived, constant in `n`, an order of magnitude
  cheaper past `q = 5`, and leaving the base cell's stronger deterministic guarantee exactly as it was.
- **Make the count mean something.** The client now hedges across its meeting points instead of drawing one
  and giving up, so "an uncensored point exists" finally implies "a client reaches the service".
- **State the regime limit.** For a *public* service the registration→service link is inherently computable
  by anyone, so the strong bound holds against a static adversary and the pigeonhole bound against an
  adaptive one. Client authorization, not a better tag, is what closes that.

### What is not closed

Recorded here rather than left implicit:

- **An established session WEDGES when one cell member is down** — and that is stronger than the "2 dials in
  12 look flaky" it first appeared as. Giving each dial **4× the window** (192 s of *granted* time) recovers
  nothing: the failures land on the harness's `REFUTED` branch, which fires only when the poll ratio shows the
  runtime *was* being scheduled and the session still moved zero bytes. Not slowness, not contention. The dial
  and handshake succeed — hedging works — and the traffic afterwards stops forever, so some state bound *once
  per session* points at the dead node and never redraws. Data path, not rendezvous path (task #38).
- **The measurement that hid it.** The experiment wrapped the harness's own budgeted exchange in an outer 48 s
  timeout, which usually fired *first* and turned a loud wedge into a silent non-arrival. The earlier "control
  12/12, silenced 10/12" reading was therefore two **masked wedges**, not two slow dials — a reminder that an
  outer timer placed over an instrument replaces its verdict with a weaker one.
- **The censorship experiment's falsification power is only ≈82%** at its tolerance
  (`P(Bin(12, 2/3) ≥ 10) ≈ 18%`). Closing the wedge is what allows tightening it.
- **Mixing is not compared.** Stratified designs have provable mixing bounds a plane does not inherit, and
  nothing here measures FANOS's per-hop line quorum against them. That is a separate experiment, and this
  document does not settle it.
