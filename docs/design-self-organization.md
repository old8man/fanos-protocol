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
demand `Dρ` is therefore itself a controlled variable.

- **The control law.** `Demand::rebalance` is a proportional controller: from the cell's telemetry it reads,
  per role, a load ratio (observed load ÷ capacity of the currently-active nodes) and steps demand toward the
  eligible-supply ceiling when the role is congested, toward a floor when it is slack —
  `Dρ' = clamp(round(Dρ · load/capacity), floorρ, |Eρ|)`. This is the **same shape** as the DDoS dissipation
  law that answers a decoherence perturbation (`fanos-diakrisis`): a bounded, monotone response to a *measured*
  deficit, so it converges rather than oscillates. There is no magic constant — the target is "match provision
  to observed demand," and the gain is the one control parameter.
- **The sensor.** The load ratios come from the cell's coherence self-scan (`fanos-telemetry`) and DIAKRISIS
  (`fanos-diakrisis`): the same third-order self-diagnosis that detects a failing node also measures whether a
  role is over- or under-provisioned. Self-diagnosis and self-provisioning are one loop.
- **Escalation, never silent failure.** When `Dρ > |Eρ|` — the cell genuinely lacks enough capable nodes — the
  shortfall is surfaced by `roles::assign_report` as a per-role **deficit**, not swallowed. That deficit is the
  signal the cell escalates to its **parent cell** (`fanos-core::hierarchy`, the recursion-of-cells): the
  parent can recruit a capable node from a sibling cell, or lower the cell's advertised service level. A cell
  that cannot self-provision a role asks the level above, exactly as a node that cannot self-heal escalates its
  DIAKRISIS verdict upward. The hierarchy is the overflow path for both health and provisioning.

## 5. Controlled freedom — the boundary between choice and control

The design deliberately splits what a node *chooses* from what the network *decides*:

| The node chooses (freedom) | The network decides (control) |
|---|---|
| its identity and keys | its coordinate (VRF) — cannot be aimed |
| which roles it *offers* (capability) | which offered roles are *active* (assignment) |
| its declared capacity `weight` (bounded) | its priority, and whether it wins a scarce role |
| when to join / leave | its quorum membership, leader/keyper turns (position + beacon) |

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
  (`roles`), the homeostatic demand controller, and the deficit/escalation signal; on the substrate side, the
  coordinate VRF, the beacon, the cell-as-BFT-quorum-system, the projective LRC + DA sampling, the Maekawa
  bridge selection, and the parent-observes-child recursion all exist and are tested.
- **Design-complete, wiring outstanding** — the *live control loop* (telemetry load ratios → `rebalance` →
  `assign` each epoch) is specified and its pieces exist, but the end-to-end driver that runs it every beacon
  round is not yet wired into `fanos-node`; the capability descriptor is advertised but the performance-slash
  reputation feedback is described, not yet closed in code.
- **L0 primitives still to harden** — cross-cell transaction *proofs* (a destination cell verifying a source
  cell's finalized-header + Merkle inclusion via the bridge, rather than trusting the bridge node) and
  *parent-attests-child-finality* (the parent sampling a child's DA + checking its finality certificates to
  extend shared security) are designed but not fully built. These are the genuine frontier, tracked with the
  hierarchy work (§L1).
- **The crowd caveat (inherited honestly).** Self-organization makes a node *join and serve* with zero touch;
  it does **not** manufacture the anonymity set. As every deployed peer network concedes, anonymity is a
  property of the live crowd, not of the routing mathematics — a self-organizing topology that is empty is
  still empty. FANOS's structural advantages (O(1) rendezvous, computed committees, PQ from day one, no
  plutocratic staking) are real and are *preconditions* for a strong network; they are not a substitute for
  adoption. See `docs/comparison.md`.
