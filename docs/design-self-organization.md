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
- **Escalation, never silent failure.** The demand is *not* capped at the eligible supply — a setpoint above
  supply is a real, unmet want. When `Dρ > |Eρ|`, `roles::assign_report` surfaces the shortfall as a per-role
  **deficit** (assigning `min(Dρ, |Eρ|)` and reporting the rest), the signal the cell escalates to its **parent
  cell** (`fanos-core::hierarchy`): the parent recruits a capable node from a sibling cell, or lowers the cell's
  advertised service level. A cell that cannot self-provision a role asks the level above — precisely the UHM
  holarchic recovery protocol (T-148), where a collapsed cell that cannot self-heal hands its residue up for
  external regeneration. The hierarchy is the overflow path for both health and provisioning.

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
  (`roles::assign`), the **Lyapunov-descent `RoleController`** (sans-I/O, UHM-grounded, with the contraction
  proved in code), and the deficit/escalation signal; on the substrate side, the coordinate VRF, the beacon,
  the cell-as-BFT-quorum-system, the projective LRC + DA sampling, the Maekawa bridge selection, and the
  parent-observes-child coherence recursion. On the L0 side, the **executed-state checkpoint**
  (`fanos-taxis::checkpoint` — divergence is now a detectable fault, not a silent fork), **trust-minimized
  cross-cell messaging** (`fanos-taxis::crosscell` — a destination cell verifies a source cell's ExecCertificate
  + Merkle inclusion, no bridge trust), and **parent-attests-child-finality** (`fanos-taxis::hierarchy` — a
  parent anchors a child's finality, availability-gated, with child-equivocation detection) are all built and
  tested.
- **Design-complete, wiring outstanding** — the *live control loop*'s **core is now the sans-I/O
  `RoleController`**; what remains is the thin driver that feeds it each beacon round inside `fanos-node`: a
  signed capability-descriptor advertisement (a wire type over the overlay store, like the mix directory) and
  per-role **load metering** in `fanos-telemetry` to derive the setpoint. The performance-slash reputation
  feedback (a non-performing assignee's `weight` decays) is specified, not yet closed in code.
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
