# Self-organization and the L0 substrate — the network assigns position *and* function

> *Design note (spec §L0/§L3, Part X). Implements `fanos-core::roles`; composes the coordinate VRF
> (`fanos-core::membership`), the hierarchy (`fanos-core::hierarchy`), DIAKRISIS self-diagnosis, and TAXIS.*

FANOS's thesis is that structure the other networks *search* for, FANOS *computes*. The clearest expression of
that thesis is self-organization: a fresh node should need no human to slot it into the network. The base
infrastructure (a handful of bootstrap seeds) is prepared by hand once; after that, **anyone starts a node and
the network organizes it — position, role, quorum membership, and consensus duty — with controlled freedom.**
This note states the principle, the mathematics that makes it deterministic and verifiable, the homeostatic
loop that keeps it balanced, and why the same machinery makes FANOS an **L0 substrate** rather than a single
network with a blockchain bolted on.

## 1. The principle — the network computes both *where* and *what*

Two facts about a node are decided by the network, not the operator:

- **Position** — a node's cell coordinate is `coord = MapToPoint(VRF(sk, id ‖ epoch ‖ beacon))`
  (`membership::Member::assign`). The operator cannot choose it, cannot aim it at a target's lines (the beacon
  is unbiasable), and every peer can verify it (`verify_coordinate`). Placement is *earned by identity*, not
  declared. Sybils gain nothing: every node sits on exactly `q+1` of the `N` lines — the structural centrality
  cap `(q+1)/N`, identical for all.
- **Function** — a node's active roles for the epoch are `assign(capabilities, epoch, beacon, demand)`
  (`roles`, new). The operator declares only *capability* — what the node **can** do (relay, store, host,
  exit) and how much (a capacity `weight`) — and the network **assigns** what it **does**, by the same kind of
  beacon-bound, verifiable, unpredictable rule that fixes position.

Everything else a node needs — which quorums it belongs to (the `q+1` lines through its point), whether it is
this epoch's consensus leader or on the keyper line (beacon election, `fanos-taxis::committee`), which shards
it stores (the projective LRC's support) — is a **pure function of position + beacon**, so it too is computed,
not configured. The operator's entire surface is: *an identity, a set of capabilities, and a bootstrap seed.*

## 2. Zero-touch onboarding

The join flow (spec §7.8), start to serving, with no manual placement:

1. **Identity.** The node has (or generates) a self-certifying identity bundle — a hybrid-PQ signing key, a
   hybrid KEM key, and a VRF key, all committed under one `NodeId` (`fanos-pqcrypto`). No registrar, no
   certificate authority.
2. **Admission price.** It solves the epoch's proof-of-work admission puzzle (`fanos-core::admission`,
   difficulty `d`), paying `~2^d` hashes for the right to occupy a coordinate this epoch — re-paid each epoch
   as the coordinate reshuffles. This is FANOS's Sybil cost (see §5): identities are cheap to *mint* but
   priced to *place*, and placement is what buys influence.
3. **Placement.** It computes its coordinate from its VRF secret and the current beacon and announces it with
   the proof; peers admit it iff the proof verifies (`Member::verified`, `BAD_COORD` otherwise). It is now a
   point of the cell, a member of its `q+1` lines.
4. **Capability advertisement.** It publishes a signed capability descriptor (its offered `RoleSet` + capacity
   `weight`) — advertised through the overlay store, one epoch-tagged slot per node, exactly as the mix
   directory already advertises relay keys (`fanos-node::mixdir`).
5. **Role assignment.** Every node (including the newcomer) runs `assign` over the cell's published
   capabilities, the beacon, and the demand vector, and obtains the same assignment. The newcomer learns which
   roles it serves this epoch; its peers learn (and can verify) the same. It begins serving them.
6. **Re-organization.** At each beacon round the coordinate, the role assignment, the leader schedule, the
   keyper line, and the onion keys all rotate together (the moving-target defence, §L3/§7.6). A node that was a
   relay last epoch may store this epoch; the network continuously re-balances itself onto its current members.

No step requires an operator decision beyond "here is what I can offer." The base infrastructure prepared by
hand is only the bootstrap seed list that step 3's announcement first reaches.

## 3. Role assignment — the mathematics

`roles::assign` is the load-bearing new primitive. For each role `ρ` with demand `Dρ`:

- **Eligibility.** `Eρ = { i : capability(i) offers ρ }`. A node is only ever considered for a role it
  declared it can serve — so the network never assigns a duty a node cannot perform.
- **Priority key.** Each `i ∈ Eρ` draws `key_ρ(i) = min_{t < weight_i} H(ρ ‖ epoch ‖ beacon ‖ id_i ‖ t)` — the
  minimum of `weight_i` beacon-bound tickets. Smaller is higher priority.
- **Selection.** The `Dρ` nodes of `Eρ` with the smallest keys are assigned `ρ` (ties broken by `id` for total
  determinism). A node's assigned set is the union over roles; it may hold several at once.

Why this exact rule, and not a heuristic:

- **Deterministic & verifiable.** The inputs are public and identical for everyone (signed capabilities, the
  beacon, the demand), so every node reproduces the same assignment, with **no coordination**, and any node
  verifies a peer's claimed role with `roles::assigned` — recompute the keys; a role claimed without
  capability, or outside the top-`Dρ`, is rejected. This is the exact unforgeability the coordinate proof gives
  placement, now for function.
- **Capability-weighted, provably.** `key_ρ(i)` is the minimum of `weight_i` i.i.d. uniforms, with
  `P(key ≤ x) = 1 − (1 − x)^{weight}`. This distribution **stochastically decreases in weight**: a
  higher-capacity node's key is smaller in the usual stochastic order, so it is preferentially selected for
  scarce roles — while equal-weight nodes are selected uniformly at random. This is *weighted reservoir
  selection*, a standard, analyzable rule, not a tuned threshold. `weight` is clamped to `1..=MAX_WEIGHT`, so a
  node cannot buy unbounded priority by inflating its self-declared capacity.
  - *Exact-proportional refinement.* If selection probability must be **exactly** proportional to weight (not
    merely monotone), replace the min-of-tickets key with the Efraimidis–Spirakis key `u_i^{1/weight_i}` (pick
    the largest), compared exactly in integer arithmetic via `u_a^{w_b} ≷ u_b^{w_a}`. The current min-of-tickets
    realization is chosen for its `no_std`, bignum-free determinism; the ES key is a drop-in when exact
    proportionality is required.
- **Rotating — a moving target that spreads load.** The beacon enters every ticket, so the whole assignment
  reshuffles each epoch. No node holds a role forever (load spreads over time; the active-set is a moving
  target an adversary cannot pre-map), and — because the beacon is *unbiasable* (`fanos-vrf`) — a node cannot
  grind its identity to capture a chosen role, precisely as it cannot grind a chosen coordinate. Rotation and
  anti-grinding are the *same* property the coordinate VRF already provides, inherited for free.

## 4. Homeostatic self-balancing

Self-organization without self-balancing is brittle: a fixed demand vector cannot follow a changing cell. The
demand `Dρ` is therefore itself a controlled variable, driven by a **Lyapunov-descent controller grounded in the
UHM viability dynamics** (T-101 minimax under the T-104 ISS envelope — the same theory `fanos-diakrisis`'s DDoS
homeostat realizes).

- **The control law.** `Demand::rebalance` steps the current demand toward a telemetry-derived setpoint
  `sρ = ⌈observed_loadρ / per_node_capacity⌉` (the active count that would bring role `ρ` to capacity):
  `Dρ' = Dρ + κ·(sρ − Dρ)`, with the loop gain **`κ ∈ [κ_bootstrap = 1/7, 1]`** — the UHM viability floor
  (T-59/T-104) below which the pull toward health can vanish, up to the unit jump. Because `κ ≤ 1` the step
  never overshoots and lands strictly between `Dρ` and `sρ`, so the error `V = (Dρ − sρ)²` **contracts by
  `(1 − κ)²` each step** — a strict Lyapunov descent, the identical contraction as `stability::excursion_step`,
  and under a moving setpoint the ISS envelope `√V' ≤ (1−κ)√V + ‖drift‖`. This is *derived*, not tuned: the
  contraction is proved in code (`roles::tests::the_demand_controller_is_a_lyapunov_contraction`, verified from
  both above and below the setpoint at `κ ∈ {1/7, 3/7, 1}`), exactly as the UHM `calib.rs` battery asserts each
  viability law numerically.
- **The engine.** `RoleController` packages this as a **sans-I/O** loop: one per cell, it holds the demand
  state and, each beacon round, `step(members, epoch, beacon, setpoint)` rebalances the demand (Lyapunov) then
  re-assigns roles — touching no clock, socket, or RNG, so the identical controller runs under the simulator
  and a live node, like every other FANOS engine. A future learnable module may tune the setpoint or the gain
  *within* `[κ_bootstrap, 1]`, but — exactly as the UHM T-155 consciousness-preserving-learning bound requires —
  it can never move the attractor, leave the viability band, or break the T-104 contraction: the envelope is a
  hard invariant the reflex layer enforces around any cognitive tuning (the SYNARC node model).
- **The sensor.** The setpoint's load figures come from the cell's coherence self-scan (`fanos-telemetry`) and
  DIAKRISIS (`fanos-diakrisis`): the same third-order self-diagnosis that detects a failing node also measures
  whether a role is over- or under-provisioned. Self-diagnosis and self-provisioning are one loop.
- **A shortfall is never silent, and its terminus is the operator — not the parent cell.** The demand is *not*
  capped at the eligible supply: a setpoint above supply is a real, unmet want. When `Dρ > |Eρ|`,
  `roles::assign_report` surfaces the shortfall as a per-role **deficit** (assigning `min(Dρ, |Eρ|)` and
  reporting the rest), and `note_deficit` records `Station::RoleUnderProvisioned` with the role index. Since
  every role's capacity is now derived from the bound its own subsystem enforces, that number means what it
  says for all six.

  **This paragraph used to say the cell escalates the deficit to its parent, which "recruits a capable node
  from a sibling cell, or lowers the cell's advertised service level". Both branches are unbuildable here, and
  the reasons are worth keeping.**

  *There is nothing to lower.* Work reaches a node by **derivation**, not by lookup, for five of the six roles:
  a key lands on its responsible point by geometry; a hidden service's meeting line is
  `rendezvous_line(pubkey, epoch, beacon)`; a community's admission line is
  `ingress_line(community, epoch, beacon)`; a mix hop **is** a line and its gatherer is salted; a threshold
  service is keyed. A client derives what it needs from the epoch beacon, so **no party holds an advertisement
  that could be lowered**. Exit is the one directory-based role, and it needs no channel: fewer exits publish
  fewer descriptors and clients pick from what is there — the deficit is self-expressing.

  *Recruiting needs an authority §L3 exists to deny.* A node's coordinate is
  `MapToPoint(VRF(sk, id‖epoch‖beacon))` precisely so that no node can **aim itself** at a position. Granting a
  parent the power to place a node in a child cell hands that aim to the parent, which is a threat-model change
  (a hostile parent could pack a target cell), not a missing frame.

  *And the existing escalation transport is the wrong shape anyway.* `CellEscalate{child, residue, ttl}` carries
  a **node mask** and the parent spends a `⌊log₉Φ⌋` budget to install coarse reroutes around a failed child;
  `ChildSummary` has exactly two fields, both about faults. A per-role shortfall is neither a node set nor
  reroutable, and folding it in would make a parent route around a cell that is perfectly healthy.

  So the hierarchy remains the overflow path for **health** — the UHM holarchic recovery protocol (T-148),
  where a collapsed cell hands its residue up for external regeneration — and not for provisioning. The answer
  to "nobody here offers enough relay" is more nodes or broader capability declarations, which is an operator
  and incentive matter rather than a routing one.

## 5. Controlled freedom — the boundary between choice and control

The design deliberately splits what a node *chooses* from what the network *decides*:

| The node chooses (freedom) | The network decides (control) |
|---|---|
| its identity and keys | its coordinate (VRF) — cannot be aimed |
| which roles it *offers* (capability) | which offered roles are *active* (assignment) — see below: for four of six this is an **exclusion** right, not a selection |
| its declared capacity `weight` (bounded) | its priority, and whether it wins a scarce role |
| when to join / leave | its quorum membership, leader/keyper turns (position + beacon) |

### What "active" can mean, and it is not the same for every role

The row above reads as one power over six roles. It is not, and the difference is decided by a single
question: **what puts the work in front of a node?**

| role | how work arrives | what the assignment can decide |
|---|---|---|
| **exit** | a client reads the exit directory and picks one | **everything** — who publishes is who serves |
| **relay** | the mix hop *is* a line; its gatherer is salted from the cell | exclude at most `m − t` |
| **rendezvous** | `MapToLine(H(secret ‖ epoch ‖ beacon))` | exclude at most `m − t` |
| **ingress** | `ingress_line(community, epoch, beacon)` | exclude at most `m − t` |
| **storage** | the key's responsible point; shards go to the nearest *occupied* homes | **nothing** — a node cannot decline to be a shard's home without losing the shard |
| **service** | `ServiceParams::line`, fixed at the provisioning ceremony | **nothing** — the member set is not the assignment's to choose |

For the four **geometry-placed** roles the work lands at a derived address whatever the cell assigned, so
`⌈Σ load / capacity⌉` cannot be their law: raising the count moves no work and lowering it stops none. Their
demand is a **coverage** count — `N − (m − t)`, near-full plane occupancy — and what the assignment retains is
the right to withhold the role from `m − t` members, which is precisely the per-line fault budget the
threshold already buys. Ask for fewer and some line falls below its quorum; that is not a weaker guarantee but
an inverted one.

**And that budget is what makes the reputation price below a price rather than an ornament.** `select` ranks by
the minimum of `weight` beacon-bound tickets and the role loop scales `weight` by reputation, so the members a
demand leaves out are the lowest-weighted. At the coverage floor the cell leaves out exactly `m − t` — the
worst `m − t`. Measured over 40 000 draws of that rule, one member at `weight 1` against six at `weight 8`:
**0.748** probability of being the one excluded, against a `0.143` chance baseline — a **5.2×** discrimination.
Under a floor of `t` the cell left out five of seven instead, and an **honest** member was excluded `0.717` of
the time, chance to three digits: the lottery, not the conduct, decided who served.

Exit is the exception on both counts, and for the same reason: a client *chooses* it, so provisioning moves
real work. Its floor is therefore an availability one — `fault_budget(N) + 1`, three on the base cell and
nineteen at `q = 7` — because a service picked from a set survives the cell's stated tolerance only when the
set is larger than it, the adversary choosing whom to take after the assignment is public. A floor of one made
`discover_exit`'s "pick one at random, so a proxy restart spreads load across the available exits" a
randomisation over a set of size one, and put every clearnet destination the cell reaches in front of a single
node.

The control side is enforced *structurally*, not by policy: a node cannot forge a role it lacks capability for
(eligibility), cannot monopolize a role (beacon rotation), cannot aim at one (beacon unpredictability), and
cannot buy centrality (the `(q+1)/N` cap) or unbounded priority (`MAX_WEIGHT`). The freedom side is real: a
node offers exactly what it can, and honest capacity is rewarded (weighted selection).

The one place freedom must be *policed* is a node that **declares capability it does not have** — a role it
wins but cannot serve. This is caught by the same self-diagnosis loop: a non-performing assignee shows up as a
coherence deficit on its lines, DIAKRISIS attributes it, and the node's effective `weight` is slashed (a
reputation the assignment reads next epoch). Capability is declared freely but *priced by performance* — the
economic mirror of the PoW that prices placement. Sybil identities are cheap to mint, priced to place (PoW),
and worthless to over-declare (reputation) — three independent bounds on the same freedom.

## 6. FANOS as an L0 — the geometry *is* the shared substrate

Reaching a blockchain (TAXIS) forces the layering question. The fundamental answer: **FANOS is an L0**, and it
is a cleaner L0 than the hub-and-spoke designs because its shared substrate is a *mathematical structure*, not
a separate chain that must be secured and becomes a bottleneck.

- **What an L0 must provide** — shared addressing, shared randomness, committee selection, data availability,
  cross-shard messaging, and (ideally) shared security. In Cosmos these come from a hub chain + IBC; in
  Polkadot from a relay chain that re-validates parachains. Both put a *chain* underneath the chains — a thing
  to trust, to congest, to attack.
- **What FANOS provides instead** — the projective plane `PG(2,q)` and the epoch beacon supply *all* of these
  directly, with no underlying chain:
  - **Addressing** — the coordinate VRF (§1) places every node deterministically and verifiably.
  - **Shared randomness** — one unbiasable beacon (`fanos-vrf` DVRF), propagated down the hierarchy, anchors
    every cell's leader election, keyper line, coordinate reshuffle, and role assignment from a *single* source
    no cell can bias.
  - **Committee selection** — a cell *is* a Byzantine quorum system (`fanos-taxis::params`: `n=q²+q+1`,
    `f=⌊(n−1)/3⌋`, `Q=⌈(n+f+1)/2⌉`, proven safe+live); the committees are the plane's lines, chosen by the
    geometry, cartel-proof by the centrality cap.
  - **Data availability** — the projective LRC (`fanos-code`) erasure-codes each cell's payload with in-cell
    reconstruction and sampling-gated finality; the hierarchy provides fallback reconstruction (a parent cell
    peels a child's shards).
  - **Cross-shard messaging** — two cells' committees meet in a *unique* Maekawa bridge point
    (`committee::cross_shard_bridge`); a cross-cell transaction is witnessed by that shared validator, giving
    deterministic cross-shard coordination with **no extra overlay** — the geometry supplies the router.
- **The layering, precisely.**
  - **L0 = the geometry + beacon + overlay** — addressing, randomness, committees, DA, bridging, and the
    self-organization of §§1–5. It is not a chain; it is the substrate every cell inherits for free.
  - **L1 = a cell's TAXIS** — a sovereign BFT ledger with its own state and execution, running *inside* a cell,
    using the L0's committee, beacon, DA, and anti-MEV keyper line. Each cell is an L1-equivalent.
  - **The hierarchy composes them** — a parent cell provides shared randomness and DA fallback to its child
    cells and observes their health/finality (the parent-observes-child recursion, §L1), giving *shared
    security without a separate relay chain*: the parent **is** the relay, using the same geometry, and the
    recursion is unbounded rather than slot-limited.
- **Why this is the more fundamental solution.** Cosmos trades shared security for sovereignty (each chain
  secures itself); Polkadot buys shared security with a relay-chain bottleneck and a fixed parachain budget.
  FANOS gets *both* — sovereign per-cell execution **and** shared randomness/DA/committee-selection/security —
  because the shared layer is the plane's algebra, which costs no consensus and cannot be congested. The L0 is
  *derived*, not deployed. This is the "maximally generalized" positioning: one substrate underlies anonymity
  routing, hidden services, the VPN datapath, censorship-resistant transport, **and** an unbounded lattice of
  BFT ledgers, all from the same `PG(2,q)`.

## 7. Honest limits & what remains

- **Implemented now** — the deterministic, verifiable, capability-weighted, rotating role assignment
  (`roles::assign`), the **Lyapunov-descent `RoleController`** (sans-I/O, UHM-grounded, with the contraction
  proved in code), **a derived per-node capacity for every one of the six roles** — each read from the
  admission bound its own subsystem enforces, so the setpoint's denominator is never a chosen number — and the
  deficit signal (local, by §4's derivation); on the substrate side, the coordinate VRF, the beacon,
  the cell-as-BFT-quorum-system, the projective LRC + DA sampling, the Maekawa bridge selection, and the
  parent-observes-child coherence recursion. On the L0 side, the **executed-state checkpoint**
  (`fanos-taxis::checkpoint` — divergence is now a detectable fault, not a silent fork), **trust-minimized
  cross-cell messaging** (`fanos-taxis::crosscell` — a destination cell verifies a source cell's ExecCertificate
  + Merkle inclusion, no bridge trust), and **parent-attests-child-finality** (`fanos-taxis::hierarchy` — a
  parent anchors a child's finality, availability-gated, with child-equivocation detection) are all built and
  tested.
- **The live control loop is closed end to end, and this bullet now records how rather than what is left.**
  Three items stood here; all three are in code, and they are named rather than deleted because this list is
  what a reader consults for what is *outstanding*, and an item that silently vanishes reads as forgotten
  rather than finished.
  * *A signed capability-descriptor advertisement* — `fanos_node::capdir`. Each node publishes a **signed**
    record at its coordinate slot per epoch and `build_capability_directory` verifies both the signature and
    the coordinate binding, so a roster is evidence rather than hearsay.
  * *Per-role load metering to derive the setpoint* — **all six roles are measured now**, each against the
    admission bound its own subsystem enforces, so `⌈Σ load / capacity⌉` divides quantities that count the
    same objects. The last two arrived by correcting sensors rather than by adding them: relay's reading was
    frames the node *originated* (its work as a source, not the work it carries for others), and ingress's
    accessor existed and nothing read it.
  * *The performance-slash reputation feedback* — the role loop rebuilds `Reputation` from published
    diagnosis records each epoch and applies it to the members' weights, so a non-performer's weight decays
    without any node trusting another's word for it. §5 records what makes that a price rather than an
    ornament: at the coverage floor the cell excludes exactly the fault budget's worth of members, and they
    are the worst-reputed ones (measured **5.2×** discrimination against a chance baseline).

  What remains is **actuation for the three geometry-placed roles**: only Exit reads its assignment today (the
  per-epoch advertisement is withheld when the cell did not assign it). §5's table says why that ordering is
  not an accident — Exit is the one role where the assignment decides who serves.
- **L0 frontier** — a live *multi-cell* driver that runs cross-cell relay and parent attestation end-to-end
  across real cells (the primitives are built and unit-proven; the multi-cell orchestration is the residual),
  and folding an executed `state_root` history into the block header so a light client can follow finality
  without the full checkpoint stream. These are tracked with the hierarchy work (§L1).
- **The crowd caveat (inherited honestly).** Self-organization makes a node *join and serve* with zero touch;
  it does **not** manufacture the anonymity set. As every deployed peer network concedes, anonymity is a
  property of the live crowd, not of the routing mathematics — a self-organizing topology that is empty is
  still empty. FANOS's structural advantages (O(1) rendezvous, computed committees, PQ from day one, no
  plutocratic staking) are real and are *preconditions* for a strong network; they are not a substitute for
  adoption. See `docs/comparison.md`.
