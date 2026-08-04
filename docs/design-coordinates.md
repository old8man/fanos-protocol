# Coordinate assignment: the verifiable epoch coordinate (design)

> Status: **accepted, implementation in progress** (audit A7 + A2). This document is the recorded
> architectural decision the spec (§3.2, §L0, §L3, §7.3/7.6/7.8/7.10) and audit A2 call for.

## 1. The problem

A node's overlay address is its projective coordinate `[x:y:z] ∈ PG(2,q)`. The spec fixes exactly one
derivation for it (§L0, §7.6 step 3, §7.8 JOIN step 4):

```
coord = MapToPoint( VRF_beacon(pubkey, epoch) )
```

— a **verifiable random function** of the node's key and the epoch's beacon seed, carried with a
**proof-of-coordinate** in `HELLO` (§7.3) so any peer checks it without the secret. This single choice
is load-bearing for three of the protocol's headline guarantees:

- **§3.2 assumption 1** — coordinate assignment is *VRF-verifiable and not cheaply grindable*, so an
  adversary controlling a fraction *f* of nodes lands on ≈ *f* of every line (random placement), never a
  chosen one.
- **§3.2 assumption 2** — the epoch reshuffle is *unpredictable* (the coordinate folds the beacon, which
  is unknown until revealed), so an adversary cannot **pre-settle** onto a target's lines.
- **§L3 anti-eclipse / §7.10 attack table** — "coordinate grinding (pick your cell)" is defeated by
  exactly this: `coord = VRF(pubkey, epoch); beacon unpredictable → cannot pre-aim`.

The implementation had **diverged into three incompatible pieces** (audit A7, verified by a
workspace-wide caller map):

1. **Live path — static self-certifying.** Every live QUIC node derives `coord =
   MapToPoint(H(cert))` (`fanos-quic::coordinate_from_cert`). No VRF, no epoch, no beacon: the
   coordinate is **static for the identity's life** and, on the base cell, **trivially grindable** — the
   devnet harness `credentials_for_point` lands on *any chosen* Fano point in ≈ 7 mints. This satisfies
   *neither* assumption 1 (grindable) *nor* assumption 2 (never reshuffles).
2. **Reference path — a forgeable placeholder.** `fanos-core::membership::Member::assign` derives `coord
   = MapToPoint(H(node‖epoch))` (`fanos-primitives::coordinate_for`), whose own doc-comment admits it is
   "**not** unforgeable … standing in for `MapToPoint(VRF(pubkey, epoch))` until ECVRF is wired in." It
   is epoch-binding but keyless — anyone can compute anyone's coordinate. Used only by tests and the
   `fanos-cli` demo.
3. **The real primitive — dead.** `fanos-vrf::{prove,verify}_coordinate` — a ristretto255 RFC 9381-style
   VRF, the entire reason the coordinate half of `fanos-vrf` exists — has **zero non-test callers**, and
   its keypair `VrfSecret` has **no producer anywhere**: it is disconnected from node identity entirely.

Shipping the weaker of two same-named primitives (the forgeable `coordinate_for`) from the
more-depended-upon crate, while the strong one rots unused, is the "fundamentality hazard" A7 names. But
the deeper defect is that the **live** coordinate is the static self-certifying hash, which fails the
spec's security model on the base cell that actually ships.

> Note the DVRF/DKG/VSS core of `fanos-vrf` is **not** dead — it powers the live randomness beacon
> (`fanos-keygen`, audit E5/#94). Only the *coordinate* VRF was orphaned. The beacon this design folds
> into the coordinate is therefore already running.

## 2. Why self-certifying-static is not enough (and why VRF-epoch is)

Self-certification (coordinate earned by a certificate hash) *is* a real unforgeability property: you
cannot present a coordinate without the cert that hashes to it. It is why the live path is not
*trivially* forgeable. But it buys only assumption 1's *verifiability*, and only weakly:

- **Grindability (assumption 1).** `MapToPoint(H(cert))` is a public function of a self-minted cert.
  Minting is cheap, so landing on a target point costs ≈ *N* mints. On the base cell **N = 7** — the
  attacker picks any point essentially for free. Grind-cost only becomes a real barrier at large *q*
  (≈ *q²* mints), which the shipped q = 2 profile never reaches.
- **Reshuffle (assumption 2).** `H(cert)` has no epoch term. A coordinate, once grinded, is **held for
  the identity's life**. An adversary settles onto a victim's `q+1` lines once and stays. This is the
  precise attack §L3 and §7.10 exist to stop, and static self-certification cannot.

The VRF-epoch coordinate restores both, and does so *most* where the shipped profile is weakest:

- The coordinate is `MapToPoint(VRF(sk, epoch ‖ beacon))`. To aim it an adversary must grind **VRF
  keys** — but each key is a *whole identity* (§4) — and, decisively, the input folds the **beacon
  seed**, which is unpredictable until the threshold beacon reveals it. So the adversary cannot grind for
  a *future* epoch's placement: it does not yet know the mapping. On q = 2, where grind-cost is nil, this
  **unpredictable reshuffle is the entire defense** (assumption 2). On large *q*, grind-cost (assumption
  1) compounds it. The two assumptions cover the two ends of the *q* range; static self-certification
  covers neither end well.
- The coordinate is **VRF-verifiable**: the `HELLO` proof-of-coordinate lets a peer confirm `coord =
  MapToPoint(VRF(sk, epoch‖beacon))` for the claimed identity, so a forged or mis-placed coordinate is
  rejected at the handshake (error `2xx BAD_COORD`, §7.5), not trusted.

## 3. Operational feasibility of the reshuffle

The obvious objection to epoch-reshuffling coordinates is cost: if every node's address changes each
epoch, does the whole overlay have to re-key and migrate all content? In FANOS the answer is **no,
within a cell** — the design already absorbs it:

- **Content addressing is epoch-independent.** A key maps to a *point* by `MapToPoint(H(k))` (§L0), which
  has no epoch term. What an epoch changes is *which node occupies* that point, not which point owns the
  key.
- **Storage is full-line-replicated.** A point's data lives on the `q+1` nodes of the lines through it
  (projective LRC, §L4); in a single Fano cell that already spans the cell, and the live `OverlayNode`
  replicates a `Put` to every member (verified: `cell_e2e::a_stored_value_survives_losing_a_node`). So
  after a reshuffle the node newly at point *P* already holds *P*'s data — no migration, no gap.
- **Peers are re-derived by algebra, not discovery.** A Fano cell is fully connected; every node
  computes the other six from coordinates (no routing-table rebuild, `cell_e2e`). A reshuffle is a local
  re-computation, not a network-wide convergence.

So the reshuffle is a per-epoch *re-derivation and re-announcement*, not a data migration. The beacon
that drives it is already live (`fanos-keygen::BeaconNode`, #94), and its `Notification::BeaconReady`
is already the epoch clock other subsystems rotate on (E4 onion keys, E5 meeting lines).

## 4. The эталon architecture: one verifiable coordinate, bound to identity

The two live models (self-certifying identity, VRF-epoch coordinate) are **not rivals — they compose.**
Self-certification answers "*is this key really this node's?*"; the VRF answers "*is this the coordinate
that key earns this epoch?*". The unification binds them:

1. **The identity commits a VRF key.** The node's long-term public bundle gains a fourth component, a
   `VrfPublic` (ristretto255), alongside the Ed25519+ML-DSA signature and X25519+ML-KEM KEM keys. The
   long-term `NodeId = H(bundle)` therefore commits to the VRF key too: a coordinate proof can only be
   made with the VRF secret whose public is in the identity that hashes to that `NodeId`. The VRF secret
   is **derived deterministically from the same identity seed** (domain-separated), so an identity is one
   seed, as today — no extra key to store.
2. **The coordinate is the beacon-folded VRF.** `coord = MapToPoint(VRF(vrf_sk, coord_input(node_id,
   epoch, beacon_seed)))`, where the input is `node_id ‖ epoch_low32_be ‖ beacon_seed` (extending the
   existing `beacon_alpha` with the beacon term the spec's `VRF_beacon` names). At genesis (`epoch 0`,
   `beacon = BeaconSeed::GENESIS`) this is computable with no live beacon, so cold-start and tests need no
   beacon round.

   **That convenience is also a window, and the two halves of this document had never been put together.**
   §Reshuffle above states that on `q = 2`, where grind-cost is nil, *"this unpredictable reshuffle is the
   entire defense"*. At genesis there is no reshuffle yet — so on the base cell there is, for that window, no
   placement defence at all. `BeaconSeed::GENESIS` is a public constant, so an adversary computes credentials
   for every point of the plane offline (`fanos-quic::harness` measures the cost as ~7 mints per point, which
   is why it exists as a *test* facility) and joins wherever it chose. The window closes when the first beacon
   round assembles — `epoch_period`, 600 s by default.

   **Confirmed against the code, 2026-08-04**, because the conjunction alone would not have settled it:
   `on_join` and `on_announce` (`overlay/membership_ops.rs`) do not require an adopted beacon, and the only
   gate on the path is `require_admission` — which is **`false` in `Config::default()`**, with
   `admission_difficulty: None`. So on a default cell the genesis window is not merely undefended by the
   reshuffle; it is ungated entirely.

   This is the same primitive the announce path already documents defending against — its comment records
   *"grind ~20 identities until one collides with a chosen victim at a lower rank … reuse the victim's proof"*,
   and that attack was closed by binding the admission challenge to the identity. What was closed there is
   proof **replay**; what remains here is placement **choice** during the one window that has no reshuffle to
   undo it.

   **Not fixed here, because the fix is a deployment decision with a real cost.** Three shapes: refuse joins
   until the first beacon round (costs the cold-start ergonomics this bullet exists to provide, and the
   founding runbook would have to sequence the beacon first); price the join (`admission_difficulty` makes
   occupying seven points cost seven proofs — cheap to state, weak against a funded adversary); or accept it
   and require that a cell be founded privately and then opened, which is what a multi-operator ceremony does
   anyway. Picking one belongs with the founding choreography, not with this derivation.
3. **`HELLO` carries a proof-of-coordinate.** The handshake sends `(epoch, coord, vrf_output,
   vrf_proof)`; the peer runs `verify_coordinate(vrf_public, node_id, epoch, beacon, coord, proof)` and
   rejects a mismatch (`BAD_COORD`) or a stale epoch (`EPOCH_STALE` → `BEACON` sync). Zero extra round
   trips: it piggybacks the first flight (§7.3).
4. **`coordinate_from_cert` is retired as the coordinate authority.** The self-certifying cert continues
   to certify the *identity* (the TLS key), but the *coordinate* comes from the VRF. The devnet harness
   pins a node to a point by grinding the *identity seed* until `VRF(vrf_sk, point-for-genesis)` hits the
   target — the same retry-until-target loop, now over the primitive that actually guards placement.

This makes `fanos-vrf::prove_coordinate`/`verify_coordinate` the single coordinate authority, used on
the live path; demotes `coordinate_for` to what its doc already calls it — the no_std deterministic
*addressing reference* for tests, never a security primitive; and gives the coordinate the verifiability
(assumption 1) the shipped profile lacked.

### Delivery levels

- **Level A — the verifiable, identity-bound coordinate (this change).** Items 1–4 above at the genesis
  epoch, wired live: the VRF key is in the identity, the coordinate is `MapToPoint(VRF(sk, epoch‖beacon))`,
  `HELLO` proves it, `coordinate_from_cert` is retired. Satisfies assumption 1 (verifiable, forge-proof,
  grind-priced in the VRF key) and unifies the models. The coordinate is *provable and unforgeable*
  everywhere it is used.
- **Level B — the live per-epoch reshuffle + hierarchy unification (tracked follow-up).** Two pieces.
  (1) *Reshuffle:* nodes re-derive and re-announce their coordinate on each `BeaconReady`, with the
  JOIN-waits-for-beacon cold-start and the announce/withdraw choreography — satisfying assumption 2 in the
  running overlay. This is a deployment mechanism (operating a reshuffling membership), not a primitive;
  §3 shows it is cheap in FANOS, and it rides the beacon clock that already exists.
  (2) *Hierarchy unification:* today the multi-level **hierarchical address** is a proof-free hash-chain of
  the identity (`fanos_primitives::address_point`, the #79 poisoning defence — a *distinct* scheme from the
  VRF coordinate, so the no_std overlay verifies an announced address by recomputation). Level A makes a
  node's **top-level, base-cell** coordinate the VRF one; unifying the *descent* under the VRF — a
  VRF-seeded chain (`level 0 = MapToPoint(VRF output)`, deeper levels a hash of that output) with
  proof-carrying #79 verification — is Level B, since the descent only engages on collisions and interacts
  with the reshuffle. Until then the two coexist: the base cell (what ships, and what `cell_e2e` covers)
  uses the VRF coordinate consistently, and `subcell_descent` tests the hash-chain descent on its own terms.

Level A closes the A7 defect (forgeable/dead/unverified coordinate) completely and correctly; Level B is
the operational completion of the same design.

### Level B, resolved (#95, 2026-07-21)

The **placement scheme is settled** and matches the design above: a node's hierarchical address is
`level 0 = the live VRF transport coordinate` (§A7, reshuffling every epoch, anti-eclipse) then
`level ≥ 1 = address_point(id, level)` (identity-hash sub-cell points, epoch-stable). `on_reseat` already
preserves the hash-chain deep levels across the reshuffle (`a_reshuffle_preserves_the_hierarchical_descent_chain`),
and `address_matches_identity_from(min_level = 1)` verifies the descent while skipping the externally-proven
VRF level 0. **Anti-eclipse for deep levels is free**: because level 0 reshuffles, *which identities share a
level-0 point — hence the whole sub-cell membership — churns every epoch*, so no deep position can be
pre-settled and **no per-sub-cell beacon is needed**. (Resolves design decisions 1–2 of #95.)

The **missing live core** was not the placement math but a deterministic, occupancy-driven **descent
policy** — who yields when two identities contest a point — and that is now built and verified:
`fanos_primitives::derive_hierarchical_address(own_id, own_point, seated)` (commit `cc2f393`). Every node
runs the same pure function over the same membership; priority is the strict total order on identity bytes,
so of any identities contesting a position exactly one (the minimum id) keeps it and the rest descend,
recursively and conflict-free, with no negotiation. A 5-way contention converges to a distinct address per
node (proven by fixed-point iteration) and is order-independent.

**Remaining to make the hierarchy fully live (the large follow-on).** (a) **Transport addressing keyed by
the hierarchical address.** The base cell conflates the transport coordinate with the level-0 point; that
is correct only at depth 1, because two identities that VRF to the same level-0 point then collide on one
transport coordinate. A genuine multi-cell topology must reach a node by *routing to its sub-cell then its
leaf* (`RouteHier`, already built), so the physical/Directory key must be the full `HierAddr` (or a unique
flattening), not the level-0 point — this is the foundational change the deep hierarchy waits on. (b) A
**multi-cell simulator**: the sim is one node per transport `Triple` in a single plane; a real deep
hierarchy needs a multi-cell container that seats sub-cells and routes cell-to-cell (the descent policy +
`RouteHier` are ready; the harness is not). (c) **Live descent actuation**: wire
`derive_hierarchical_address` into `OverlayNode::on_announce` (re-derive on membership change, re-seat,
re-announce), which unblocks once (a) lands. (d) **Parent-observes-child**: route a child's
`Notification::Escalated` to a live `ParentCell` (today fed only by hand in `hierarchy.rs`). (e)
**Cross-cell content placement**: `MapToPoint(H(key))` is single-plane full-cell today; the hierarchy needs
a cross-cell key-placement rule. The descent policy is the verified keystone the rest of this composes on.

## 5. A2 — the large-`q` scaling decision (recorded)

Audit A2 asks for an explicit, recorded decision on the general-`q` story, because DIAKRISIS and the whole
live stack fix `q = 2` while `Plane::<F7/F13/F31>` generality is exercised only in geometry unit tests.
The decision:

- **`q = 2` + a recursion of cells is *the* deployment scaling model** (spec §L1 "Hierarchy", verified
  V4; the [[hierarchy-scaling]] work — addressing, live-overlay routing, self-seed, signed descriptors —
  is built). Internet scale is `k` levels of Fano cells (`O(log n)` state/depth, like Kademlia), **not** a
  single large-`q` plane. This design's coordinate is `MapToPoint` over the base cell at each level; the
  hierarchy composes it by domain-separated descent ([[crypto-identity-primitives]], `address.rs`).
- **Large-`q` `Plane` is spec-completeness, not a scaling lever.** The generic-`q` geometry is retained
  because the theorems are stated for general `q` and it keeps the algebra honest and testable at
  `q ∈ {7,13,31}`, but no large-`q` *cell* runs above geometry, and none is a deployment target. It must
  not be read as a shipping capability.
- **DIAKRISIS `N = 7` is base-cell proprioception, not a ceiling.** The 3-bit Hamming(7,4) syndrome is
  intrinsically a Fano-plane object (spec Part VI); self-diagnosis is defined on the base cell and the
  hierarchy diagnoses upward by escalation, not by a 993-element self-observation. The `N = 7` constant is
  therefore correct and honest — the coherence/window measures are properly general-`N`, and the `_fano`
  suffixes mark the specialization.

The coordinate authority (§4) is the same at every level and every `q`: `MapToPoint(VRF(sk,
epoch‖beacon))`. Nothing here forecloses a future large-`q` self-observation story; it records that the
shipped model is `q = 2` + hierarchy, so the capability is not mistaken for one that runs.

### 5.1 A challenge to this decision, on an axis it did not consider (2026-08-03)

The decision above is argued on **state and depth** — `O(log n)` like Kademlia — and on **proprioception**.
It is silent on **liveness**, and liveness is where the base cell is weakest.

A gather completes when `t = ⌈2(q+1)/3⌉` of `q+1` members answer in time, so a line can afford to lose
`⌊(q+1)/3⌋`. At `q = 2` that is **1** — the minimum for any non-trivial threshold. With each member answering
in time with probability `r = 0.9`, a gather succeeds with probability 0.972, and a session needing `N`
gathers survives with about `0.972^N`: **0.24 at `N = 50`**, 0.058 at `N = 100`. The measured wedge rate in
`anonymous_quic` (~1 dial in 8–10) sits comfortably inside that model.

**And the hierarchy makes it worse, not better.** `k` levels of Fano cells means a path crosses more lines,
every one of them with a spare of exactly 1, so `N` grows with depth while the per-gather margin does not.
The scaling model that fixes state and depth also multiplies the number of minimum-margin hops.

The natural remedy is `q = 5`: 31 points, spare **2**, per-gather 0.984 — still a small fixed cell, still
recursive, so every argument §5 actually makes survives. It is also in the `q ≡ 2 (mod 3)` family where the
threshold's ceiling is exact and no capacity is lost to rounding (`docs/design-constants.md` §5).

**What it would cost, stated honestly, because this is the load-bearing objection.** DIAKRISIS's `N = 7`
proprioception is not merely sized to the base cell — it *is* the Fano plane: the 7 non-zero vectors of `F₂³`
are simultaneously the points of `PG(2,2)` and the syndrome space of Hamming(7,4), which is why the 3-bit
syndrome localizes a fault at all. That coincidence does **not** reproduce at 31: `PG(2,5)`'s 31 points are a
plane over `F₅`, while the 31 non-zero vectors of `F₂⁵` are the points of `PG(4,2)` — a different object, so
`[31,26,3]` Hamming buys nothing here. Moving the base cell to `q = 5` costs self-diagnosis its algebra.

So the real decision is a **trade the original text does not name**: `q = 2` buys Hamming(7,4) proprioception
at the price of the minimum possible liveness margin, at every hop, at every level. That may still be the
right trade — the point is that it should be made knowingly, and it was not.

Tracked as #47. What would settle it is an experiment rather than more argument: run the rendezvous fixture at
`q = 5` and see whether the wedge thins as the model predicts.

### 5.2 Why the experiment cannot be run today, and the shape that would allow it

The plane order is a **type parameter**: `Field::Q` is an associated `const`, so `q` is fixed at compile time.
The engines are already generic — `ThresholdRouter<F>`, `RendezvousRelay<F>`, `RendezvousClient<F>`,
`RendezvousService<F>` — and it is only the **composition** that pins, `F2` appearing ~176 times in
`fanos-node`'s sources alone. The familiar shape: libraries ahead, wiring behind.

Three ways out, and the third is the one to build:

1. **Keep one order per binary** (today). Zero cost, and a node cannot join a cell of a different order
   without a rebuild — which also forecloses a hierarchy whose levels differ in order.
2. **Make `q` a runtime value.** Every field operation loses its compile-time modulus, const-generic
   specialization goes, and it touches everything. The arithmetic is the hot path of every onion; paying
   there to gain deployment flexibility is the wrong direction.
3. **Monomorphize a small enumerated set and dispatch once, at construction.** `Field` stays exactly as it
   is; the node composite becomes an enum over supported orders and picks from the cell's advertised order.
   Zero cost in the hot path, one branch at startup.

Option 3 needs a set of supported orders, and it should not be a taste. `docs/design-constants.md` §5 derives
one: the liveness tax is zero exactly when `3 | (q+1)`, so the supported set is `q ≡ 2 (mod 3)` — **`{2, 5, 8,
11}`** — smallest first. The enumeration is then a consequence of the threshold's algebra rather than a list
someone picked, which is the property that keeps it from rotting.

## 6. Impact

- **Wire/KAT.** Adding `VrfPublic` to the bundle changes `HybridPublicKey::encode()` length and every
  derived `NodeId`. No *external* conformance vector breaks (they key on opaque bytes / literal strings);
  two in-crate identity KATs are updated in lock-step (`keys.rs` bundle-length, `pqcrypto` node_id
  parity). `HELLO` gains the proof-of-coordinate fields (`fanos-wire`).
- **Coordinate-pinned tests.** Every test that pins a node to `Point::at(i)` via the cert grind now pins
  via the identity-seed grind; the assertion (node lands on the intended point) is unchanged.
- **Crates touched (Level A):** `fanos-vrf` (no_std + beacon-folded input), `fanos-primitives` (bundle +
  VRF key), `fanos-pqcrypto` (identity generation derives the VRF key), `fanos-core` (membership uses
  `prove_coordinate` + `verify`); and for the live path, `fanos-quic` — the cert embeds the VRF public
  (rcgen custom extension, read via `x509-parser`), the coordinate is the VRF one, and the driver's
  connection handshake exchanges + verifies a mutual proof-of-coordinate **HELLO** (the proof is bound to
  the certificate by `node_id = H(cert)`, so no live challenge is needed) — plus `fanos-node` (the
  identity coordinate helper).

---

## Collision resolution — verifiable coordinate probing

### The bound being escaped

A coordinate is `MapToPoint(VRF(sk, id ‖ epoch ‖ beacon))`: a **uniform draw** over the plane's `P = q² + q + 1` points.
Two nodes drawing the same point are *mutually unroutable* — the coordinate → address table holds one address per point —
so a cell can only see its own membership while the draw is injective, and

```text
P(injective) = P! / ((P − n)! · Pⁿ) ≈ exp(−n²/2P)
E[distinct]  = P · (1 − (1 − 1/P)ⁿ)
```

By the birthday bound injectivity survives only while `n = O(√P)`, and `√P ≈ q`. **Without resolution a PG(2,q) cell
supports on the order of `q` nodes, not `q² + q + 1`** — a factor-`q` capacity loss. Measured: seven nodes in PG(2,2)
occupied **four** distinct points, one held by three nodes (`docs/design-testing.md` §5.3.4a).

### The constraint that shapes the design

Placement security (§3.2 assumption 2) rests on a node being unable to **aim** its coordinate — at a victim's lines, at a
chosen storage neighbourhood. Any resolution rule that lets a node influence where it is displaced *to* trades that away:
a free choice among `K` destinations is exactly a factor-`K` gain in aiming power. So the design gives the node **none**.

### The construction

`fanos_vrf::probe_point` — **double hashing** over the canonical point index:

```text
p_k = Point::at((i₀ + k·s) mod P),   i₀ = index(MapToPoint(output)),   gcd(s, P) = 1
```

Both `i₀` and the stride `s` derive from the node's *own* VRF output, so the walk is verifiable and unchoosable, and a new
beacon reshuffles the entire sequence — assumption 2 extends to **every** probe index, not just `k = 0`. `gcd(s, P) = 1`
makes the walk a cyclic permutation of its **line's `q + 1` points**, so probing seats a node whenever any point of that
line is free. (This paragraph described a *plane-wide* walk until the steering analysis below replaced it with a
line-restricted one; the double-hashing construction is unchanged, only the domain it walks.)

Two details that are load-bearing rather than fussy:

- The stride is searched upward from a hashed start until coprime. `P = q² + q + 1` **need not be prime** (`21 = 3·7` at
  `q = 4`), so a bare `H mod P` could land on a divisor and silently confine the walk to a short orbit.
- The first construction, `p_k = MapToPoint(H(probe ‖ output ‖ k))`, was a random *function*, not a permutation: a node's
  own sequence repeated points and never enumerated the plane. It seated **5 of 7** at `n = P = 7` — better than the bare
  4.62, but the probing was re-colliding with itself. The simulator caught this on the first measurement.

### Rank, and why resolution needs no agreement

Rank is the VRF output itself, lowest wins: unforgeable, and unpredictable before the beacon. Both sides of a collision
compute the same verdict from public data, and the verdicts are **complementary** — an empty point is free, and so is one
held by a *higher*-ranked node, because that node is the one who must move. So exactly one party yields, and resolution is
a **local pairwise rule**: no negotiation, no round trip, and no dependency on agreed membership (which would be circular,
since membership is what collisions obstruct).

`settle_index` is the sans-I/O core a node runs: walk to the first index whose point no lower-ranked node holds. It is
monotone in information — a node that has seen fewer peers may settle early and later advance — which is a *convergence*
question, not a correctness one, since every intermediate position is a claim it can legitimately prove.

### The claim, and the one freedom it closes

The node cannot choose *where* its sequence goes, so the only thing left to misreport is *how far along* it sits.
`CoordinateClaim { proof, index, witnesses }` closes that: index `k` is accepted only with **exactly** `k` witnesses, the
`j`-th being a genuinely lower-ranked node whose *preference* is the claimant's `j`-th point. A lower-ranked node
preferring `p` displaces the claimant from `p`, so each step is a public fact rather than an assertion.

`verify_coordinate_claim` is the acceptance predicate a peer runs on a `HELLO`. Three properties worth stating:

- **Non-recursive.** A witness proves only its own preference, never where it settled, so a chain of length `k` costs `k`
  independent VRF verifications and never unfolds into the witnesses' own chains. The price is *phantom collisions* — a
  witness itself displaced from `p` still displaces the claimant — which costs occupancy efficiency, never correctness or
  security, and cannot be manufactured since the claimant does not choose which witnesses exist.
- **Witness distinctness is automatic.** A witness justifies index `j` only if its single preference *is* the claimant's
  `j`-th point, and distinct indices are distinct points on a permutation walk, so one witness can never justify two
  steps. No separate check, and one less thing to get wrong.
- **Exactly `k`, not at least `k`.** A longer chain is rejected too, which stops a claimant padding a chain and then
  asserting a lower index whose point it happens to prefer.

`probe_point(·, 0)` is the pre-existing derivation and `CoordinateClaim::direct` the pre-existing `HELLO` proof, so a node
that meets no collision presents and verifies exactly what it always did.

### Measured

Over the real derivation, not an urn model (`fanos-sim`):

| plane `P` | nodes | load | bare `E[distinct]` | globally-ordered seating | **local uncoordinated settling** |
|---|---|---|---|---|---|
| 7 | 7 | 1.00 | 4.62 | 7/7 (2.29 probes/node) | **7/7 in 4 sweeps** |
| 21 | 7 | 0.33 | 6.08 | 7/7 (1.00) | — |
| 21 | 15 | 0.71 | 10.90 | 15/15 (1.73) | **15/15 in 4 sweeps** |
| 993 | 200 | 0.20 | 181.23 | 200/200 (1.15) | **200/200 in 3 sweeps** |

The last column is the one that matters for deployability. The first measurement seated nodes in a globally-sorted rank
order, which **no node can compute** — it needs the whole membership. The local column instead has every node run
`settle_index` against only the occupancy it can see, in arbitrary arrival order, repeatedly, as a live node would: it
converges to the *same* full occupancy in a handful of sweeps, and provably terminates rather than oscillating.

Capacity therefore goes from `O(√P)` to the full `P`, at 1–2.3 probes per node.

### ⚠️ What rank arbitration does and does not buy — an adversarial correction

The section below claims rank arbitration works because "arrival order is attacker-controlled; rank is not". **Probing that
claim refuted half of it.** Rank is a VRF output over an identity the attacker *chooses*, so it is attacker-*influenced*
even though it is unforgeable for a fixed identity. Measured against the real VRF
(`fanos-vrf/examples/grind_probe.rs`): finding an identity that collides with a **chosen victim** at a **lower rank** took
**20 draws** on PG(2,2) and **8** on PG(2,4) — the analytic `~2P` — and each draw is a local, offline VRF evaluation.

It was worse than that, because the admission proof compounded it. The Sybil challenge was `(coord, epoch)` with **no
identity component**, so a solved proof was replayable by anyone claiming that point: the attacker could present the
*incumbent's own* proof. Evicting a chosen node therefore cost ~20 VRF evaluations and **zero** proof-of-work.

**Fixed:** `admission_challenge` now binds the identity, so a proof admits only the identity that solved it. Two honest
caveats, both recorded rather than glossed:

- A node carrying **no identity** (self-certification not in use) contributes an empty component and the challenge
  degenerates to the old form, replayable among all such nodes. The defence requires the self-certifying path.
- **Grinding itself remains cheap and cannot be priced.** Evaluating a VRF for a candidate identity is local and offline;
  no admission gate sees it. So rank arbitration between an honest node and a Sybil-capable adversary rests on identities
  being **scarce** — stake- or reputation-bound — not on the rank rule alone. The rank rule removes *arrival-order* control,
  which is a real improvement over what preceded it, and that is the whole of what it removes.

### Wiring: rank arbitration replaces arrival order

`Directory` now stores each entry's **rank** alongside its address (`insert_ranked`), and a contested point is decided by
the rank rather than by whoever bound last. That fixes a security bug, not merely a capacity one. The previous code
documented its own consequence — "the colliding node silently shadows another and one becomes unreachable" — and treated
it as a fault to be relocated out of. But it was **exploitable**: a node whose coordinate landed on a victim's point could
*evict* the victim simply by connecting after it, and arrival order is attacker-controlled. Rank is a VRF output: neither
party chooses it, and it cannot be forged without the node's secret.

The arbitration is deliberately asymmetric about missing ranks:

| newcomer | incumbent | outcome | why |
|---|---|---|---|
| ranked | ranked | lowest rank keeps the point | matches `settle_index`, so the displaced node's own local walk agrees with every peer's directory unprompted |
| ranked | unranked | newcomer wins | an unranked entry is a bootstrap seed or pinned fixture, not a proven claim |
| unranked | ranked | **rejected** | no evidence, no eviction — otherwise the arrival-order attack returns |
| unranked | unranked | last writer wins | unchanged pre-existing behaviour for seed entries |

`rank_at` is the occupancy oracle `settle_index` consumes, and returns `None` for both "unbound" and "bound but unranked"
— for settling those are the same answer, since an unranked occupant offers no evidence that it may keep the point.

Supplying the rank required returning what was already being computed and discarded: `prove_coordinate_ranked` and
`verify_coordinate_rank` yield the VRF output, with the pre-existing `prove_coordinate` / `verify_coordinate` defined in
terms of them so the two can never disagree about what a valid claim is. A node binds its own point ranked at genesis and
on every epoch reshuffle.

### ⚠️ What probing cost — displacement became steerable, and that is worse than what it replaced

An honest accounting of a feature I added, since the adversarial consequence was not considered when it was designed.

A node's probe walk is **public**: it is a deterministic function of its VRF output, which its own `HELLO` proof carries.
So anyone who knows a victim's identity can compute the victim's entire fallback sequence `p₀, p₁, p₂, …` as soon as the
epoch's beacon lands — at the same moment the victim can. Combined with grinding (threat model B1: ~`N` local hashes to
seat a Sybil at a *chosen* point), an attacker can therefore **steer** a victim:

1. compute the victim's sequence and pick the index `j` whose point it wants the victim on;
2. seat low-ranked Sybils at `p₀ … p_{j−1}` — about `j·N` grinding draws and `j` admissions;
3. the victim deterministically lands on `p_j`.

**The trade is not obviously favourable.** Before probing, an attacker who collided with a victim merely made it
*unroutable*: a denial of service, disruptive and **detectable**. After probing, the same spend lands the victim
*somewhere the attacker chose* — and steering a victim onto a line the attacker occupies is **eclipse**, which is quieter
and worse than denial of service. Probing bought capacity (`O(√P) → P`, measured) and sold a failure mode.

**A depth cap does not rescue it.** Bounding the walk at `K` limits the attacker to the victim's first `K` points, but the
victim's sequence is a permutation of arbitrary points, so what matters is whether *any* of them lies on the attacker's
target line — and that probability is not small:

| plane | `K = 4` | `K = 8` | `K = 16` | `K = 64` |
|---|---|---|---|---|
| `q = 31` (`N = 993`, line = 32) | 12.3% | 23.1% | 40.8% | 87.7% |
| `q = 127` (`N = 16257`, line = 128) | 3.1% | 6.1% | 11.9% | 39.7% |

A cap tight enough to matter (`K ≤ 4` at `q = 31`) starts costing real seating failures at any load worth having, so the
cap is a dial between two harms rather than a fix, and it is deliberately **not** applied.

**No cryptographic mitigation exists, and the reason is structural**: the walk must be *verifiable*, so it cannot be
secret, and it is computable from public data the moment the beacon is known, so it cannot be a race the victim wins.

**But a structural one does — and it is now the design.** Confine the walk to **one line through `p₀`**, the line chosen
by the node's *own* VRF output. The attacker can then only move a victim among points of a line **he did not choose**, and
to exploit that he must occupy that line — which is the `N·H_{q+1}` coupon-collector cost he already faced. Probing stops
being a lever: it gives him nothing he was not already buying.

The capacity given up is negligible where it matters, because a walk fails only if *every* point of the line is taken
(probability `≈ load^{q+1}`):

| plane | load 0.25 | load 0.5 | load 0.75 |
|---|---|---|---|
| `q = 7` (line 8) | 1.5e-5 | 3.9e-3 | 0.10 |
| `q = 31` (line 32) | 5.4e-20 | 2.3e-10 | 1.0e-4 |
| `q = 127` (line 128) | 8.6e-78 | 2.9e-39 | 1.0e-16 |

Measured against the simulator after the change: **7/7 at `P = 21`, 15/15 at load 0.71, 200/200 at `P = 993`** — unchanged
from the full-plane walk. The one regression is on `PG(2,2)` at load factor 1.00, which now seats **6 of 7** instead of 7,
because that plane's lines hold three points. That is the toy plane, and one more reason the base cell is a test fixture
rather than a deployment.

So the honest summary of the redesign: full-plane probing recovers marginally more capacity **on a toy plane** and hands a
resourced adversary a steering primitive **everywhere**; line-restricted probing gives that up and keeps the capacity that
exists at real `q`. The residual defence remains the same one everything here reduces to — **identities must be scarce**,
since every seat costs `~N` grinding *plus an admission*.

Recorded here rather than in a commit message because it is a standing property of the design, not an incident.

### Still not wired

The `HELLO` frame carries a bare proof, so a node cannot yet *present* a probed point (`index > 0`) to a peer: the claim
type, its codec and its acceptance predicate are verified, but the frame format and `verify_hello` still assume `k = 0`.
Two consequences worth stating plainly rather than leaving implicit:

- A node can *detect* that it should move (its own `settle_index` walk, against ranks it has recorded) but cannot yet
  announce the point it moved to.
- The inbound path deliberately does not insert peer coordinates into the directory — a connection *is* the reachability,
  and inventing an address from the source port would clobber the peer's real listen address — so in a production
  deployment `rank_at` is populated by this node's own binding plus hole-punch and bootstrap entries. Driving
  `settle_index` across a whole cell therefore wants the **membership** layer's occupancy set (`MemberJoined`, which
  already carries coordinates), not the transport directory alone. That is the next unit.


## The settling window — why a coordinate may not move mid-epoch, and what to do instead

*Added 2026-07-26, after the probe index reached the wire (`79bd9fc`) and live resolution did not follow.*

### The constraint

A coordinate is not merely an address. It is the key from which the cell derives **TAXIS committee membership**,
**erasure-shard placement**, and **every routing table** — and all three re-derive at an *epoch boundary*, where every node
moves at once by a beacon all of them can compute. That is what makes the reshuffle safe: the movement is simultaneous and
predictable-once-the-beacon-lands.

A single node moving *between* boundaries has no such property. It invalidates state the rest of the cell still holds, so
it stops being reachable at the position its peers committed to, while continuing to believe it holds a different one. So:

> **Invariant.** Within an epoch, a seated node's coordinate is constant.

Collisions, however, are only *discovered* by meeting peers, which happens during the epoch. A node cannot know at the
boundary that its point is contested, because a peer's coordinate for the new epoch is `VRF(their_sk, …‖beacon_e)` — it is
computable only by that peer, and the proof from the previous epoch says nothing about this one. Discovery is therefore
inherently mid-epoch, while movement must not be. That is the whole tension, and it is not an implementation gap.

### What the invariant costs if nothing else changes

A node that loses its point is simply not seated: the directory refuses its binding (`Directory::supersedes`), so it sits
out the epoch and re-draws at the next boundary. The cost is capacity, and it has a closed form. With `n` nodes on
`P = q² + q + 1` points at load `ρ = n/P`, the chance a given node shares its point with someone is

```
P(contested) = 1 − (1 − 1/P)^(n−1) ≈ 1 − e^(−ρ)
```

**independent of the plane order** — it depends on load alone:

| load `ρ` | nodes idle for the epoch |
|---|---|
| 0.25 | **22.1 %** |
| 0.50 | **39.3 %** |

(Checked at `q = 31` and `q = 127`; both match `1 − e^{−ρ}` to three digits, as the approximation requires.)

### The window, and the trade that justifies its size

Split each epoch into a **settling phase** `[T_e, T_e + W)` and a **committed phase** `[T_e + W, T_{e+1})`:

1. On the boundary every node re-derives its point for the new epoch and announces it at probe index 0 — which it already
   does today.
2. Through `W` it collects peers' claims (`fanos_quic::claims::ClaimBook`, already built and already recording) and may
   re-seat freely, because no coordinate-keyed layer has committed yet.
3. At `T_e + W` the placement is **committed**: the node re-announces its settled point, and the layers above derive from it.

This adds no new outage. The reshuffle *already* invalidates every routing table at the boundary, so a convergence period
already exists there; the window bounds and names it rather than introducing it. What is new is that the layers above need
to be told when placement is final — a `PlacementCommitted { epoch }` signal — instead of assuming the coordinate is usable
the moment the beacon lands.

The window is worth it exactly when its duty cost is below the capacity it buys back:

```
W / E  <  1 − e^(−ρ)        ⇒  W < E · (1 − e^(−ρ))
```

At `E = DEFAULT_EPOCH_PERIOD = 600 s` and `ρ = 0.5` that permits `W < 236 s`. The window only needs to span the discovery
timescale — `fanos_sim::fabric::FROZEN_SPAN = 2 × ROSTER_REFRESH = 30 s`, the same derived constant the harness uses to
decide a cell has stopped changing — for a duty cost of **5 %** against **39 %** of nodes recovered. Nearly an order of
magnitude of margin, so the choice is not delicate.

### Why not the alternatives

* **Move the node anyway.** Rejected on the invariant above. Whether it is *tolerable* is unverified rather than disproven:
  the measurement that appeared to show it breaking consensus was a load artefact the baseline refuted (HEAD failed
  identically). Even so, "not moving a running node" is the correct default while the question is open.
* **Pre-settle for the next epoch.** Impossible, and deliberately so: the next epoch's beacon is unknown until it lands,
  which is exactly the unpredictability that stops an adversary pre-aiming a placement (§3.2 assumption 2).
* **Let two nodes share a point.** Harmless for shard placement (it reads as redundancy) but not for routing or committee
  identity, both of which need one holder per point. It is also the status quo, and it is what costs the `1 − e^{−ρ}` above.
* **Settle only on join.** A strictly weaker version of the window that is safe *today*, because a node that has not yet
  announced has no coordinate-keyed state depending on it. Worth having as the first increment: it fixes the joining case,
  which is the whole of the cold-start and the whole of the simulator's fleet scenario, and it needs no new signal. It does
  not fix an established node whose point becomes contested by a later arrival.

### Status

Not implemented. The wire (`CoordinateClaim` on `HELLO`), the state (`ClaimBook`), and the decision procedure
(`fanos_vrf::settle_index` + `claims::settle`) are all in place and unit-verified; what is missing is the phase boundary and
the `PlacementCommitted` signal the layers above must respect. **Settle-on-join is the increment to build first** — safe
under the invariant, and it is what the failing simulator measurement is actually blocked on.
