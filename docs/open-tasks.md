# FANOS — open tasks (handoff)

**As of** `HEAD 6ad6fa7`, 2026-07-26. Every item below was **re-verified against the current tree** on this date by
reading the code, not by trusting the previous revision of this file — which had drifted badly (four entries were already
done or rested on a retracted measurement; see *Corrections* at the end). **No open CRITICAL/HIGH security item remains**
(all four audit passes are consolidated in `docs/audit.md`, every finding RESOLVED). What follows are the remaining
*capability*, *coherence*, and *quality* gaps.

**Verification rule for whoever picks this up:** check the claim before doing the work. A task list is a cache, and this
one has gone stale twice. Each item below names the file and symbol its claim rests on so the check is cheap.

**Already done — DO NOT redo** (each verified present): validator-in-the-binary (`fanos validator` / `taxis-deal`,
`ValidatorConfig`, `spawn_taxis`); the production anonymous host (`fanos host` + `spawn_rendezvous_host`, audit A5);
bonded-stake state + slashing (`fanos-dromos::stake` `StakeLedger`/`SlashTx`/`apply_stake`, T-H5); the adaptive round
timeout (`taxis_driver::next_round_timeout`, §5.B livelock); peer-sampled DA (`taxis_driver::try_reconstruct`, T-H4);
`#[derive(Wire)]` across 12 crates; `fanos-primitives::BoundedMap`; the ERGON execution-model algebra (`fanos-ergon`,
derived footprints — §3.7 access-list drift); OBOLOS spend-auth signatures (`derive_spend_auth (ask,ak)`, §5.D-2);
position-bound nullifier (O-M1); rolling anchor window (O-M2); **the Γ-viability gate (S5-C1 — see correction 1)**;
**the OBOLOS incoming-viewing key (O-M3 — see correction 2)**; **the configurable plane order** (`--plane-order`,
`Node::start_on_plane`, `8df2b08` — partially closes item 9).

---

## Tier A — headline frontiers (fundamental research + build)

### 1. OBOLOS diversified / stealth one-time addresses (O-M4)
- **Problem.** The key hierarchy is *half* built. `fanos-obolos/src/wallet.rs` has the full viewing hierarchy —
  `IncomingViewingKey{kem_seed, owner, auth}` with `scan()`, and `to_incoming()` downgrading from the full viewing key —
  so **O-M3 is done** and selective disclosure works. What does **not** exist is the one-time address: `lib.rs:17` and
  `tx.rs:42` both describe stealth addresses as "forthcoming" / "the next increment", and `ring_note.rs:23` notes `rho` is
  the ring-native form of the one-time key a stealth address *would* supply. So two payments to one recipient still reuse
  the same `owner`, and are linkable on-chain before either is spent.
- **Task.** Diversified one-time addresses (ML-KEM-derived per payment) on top of the existing `(ask, ak)` spend-auth and
  the `IncomingViewingKey`, so `scan()` still detects them with no spend authority while distinct payments share no key
  material. Compose with `note`/`nullifier`/`tx`/`note_cipher`/`state` and the §5.D-2 sighash signatures; reconcile the
  three docs above. (The ZK backend stays the separate `[P]` frontier; this is the key structure it inherits.)

### 2. Live coordinate resolution — WORKING; one residual in roster propagation
- **Placement: DONE.** A contested node advances along its probe walk and announces the point it reached. Measured with
  the collision *forced* (`NodeFleet::spawn_as_drawn`): **4 of 4 trials reach 7/7 distinct**, nodes visibly seated at probe
  index 1, 3 and 4. Runtime fell from ~700 s to ~1 s. The cause had been one line — `spawn_inner` bound the coordinate to
  the node's own address unranked, overwriting the bootstrap seed that was its only route to the incumbent, so it deleted
  the information it needed (`29e322b`).
- **Roster propagation after a move: 3 of 4.** Four links found and fixed, each measured:

  | | change | cell-wide scenario, collisions allowed |
  |---|---|---|
  | `29e322b` | live resolution moves the node | 1 pass in 3 |
  | `b17e5bb` | mover re-announces; peers re-key the live connection on the handshake's own check | 6 of 8 |
  | `4b53a9a` | mover republishes capability/load at the point it moved **to** (and on `Reseated`, not only on a beacon) | 4 of 6 |
  | `f09d9d6` | peers re-arm their roster refresh on `PeerMoved` — re-arm, **not** scan inline | 3 of 4 |

- **The residual is NOT about moving at all — it is a read that cannot fail visibly.** Two hypotheses were tried and both
  made convergence *worse*, which is what redirected the search: acting on `MemberJoined` gave 0 of 3 (scan inline) and
  1 of 4 (re-arm), because it fires per newly-learned member and holds every node at the refresh floor throughout
  discovery — and §5.3.5 already records that the steady-state scan then starves the critical path. **More scanning cannot
  be the fix when scanning is what starves convergence** (`24dc4fe`).
  - **The actual defect.** `capdir::resolve_capability` ends in `tokio::time::timeout(...).ok()??`, and
    `resolve::resolve_directory` keeps only the `Some`s — so a **timed-out read, a decode failure and a genuine absence are
    one value**. Under load a slow store read silently *shrinks* the roster; two short scans in a row look identical, so
    the role loop marks the assignment `stable`, grows its backoff, and the cell freezes short. That predicts every
    observation, including the ones that refuted the move-propagation story: rosters low across *all* nodes
    (`[2, 2, 1, 3, 2]`), worse under contention, and unimproved by scanning more (each scan is equally likely to time out,
    and concurrent scans raise the odds).
  - **The fix is today's own discipline, one layer down in production code.** A three-valued read — found / absent /
    unknown — and an assignment computed over an *incomplete* read must not count as evidence of stability: no `stable`
    increment, no backoff growth. Exactly the `Reached`/`Refuted`/`Inconclusive` distinction the simulator harness now
    makes (`fanos_sim::fabric::Settled`), for exactly the same reason: a measurement that did not finish is not a result.
  - Scope: `resolve_directory`'s resolver signature returns `Option<T>`, so this touches `capdir`, `loaddir` and the other
    callers plus the role loop's stability gate. A full cycle, not a patch.

- **`NodeFleet::spawn`'s injective draw is the honest indicator.** While it is there, this is not closed; it goes when the
  cell-wide scenario passes with collisions allowed. Its stated reason has been rewritten five times as the chain advanced,
  which is itself the record of where the boundary is.

---

## Tier B — platform capability (deliver a shipped headline claim)

### 3. Wire the DROMOS parallel scheduler into live execution
- **Problem.** `execute_block` (deterministic, serial-equivalent, double-spend-safe, stochastically tested) has **only
  `#[cfg(test)]` callers** — verified: every hit in `fanos-dromos/src/hybrid.rs` (1525, 1747, 1759, 1782) is inside the
  test module. Live consensus runs the serial `apply` loop, so the "high-speed L1 / vertical parallelism" throughput claim
  (`platform.md §3`) delivers zero real speedup.
- **Task.** Dispatch scheduler waves onto a real thread pool and wire `execute_block` into the consensus execute path
  (post-reveal; ordering stays serial/blind). Consume ERGON-derived footprints (`fanos-ergon::Term::footprint`) as the
  conflict source so the scheduler and the transition cannot drift. Benchmark the speedup; keep determinism KATs green.

### 4. Anonymity: the binding constraint is the plane, not the schedule
- **Status.** This replaces the previous "the GPA timing channel is essentially undefended" task, whose measurement was
  **retracted** (`c896d2d` retracting `18fce2e`) — see correction 3. What survives measurement:
  - **Closed.** The mix schedule was calibrated on a valid metric (linkability among *concurrent* flows vs the `1/K`
    chance floor): `DEFAULT_MIX_DELAY` 50 → 120 ms, `DEFAULT_COVER_INTERVAL` 1 s → 500 ms, on a knee sweep.
  - **Closed.** The plane is configurable and no longer silently caps anonymity (`--plane-order`, plus a warning when
    `--profile anonymous` runs on order 2, `8df2b08`).
  - **Open — deployment decision, not code.** `plane_order` still *defaults* to 2, where `PG(2,2)` has only 4 lines with
    distinct combiners ⇒ 2 concurrent circuits ⇒ a passive adversary's flow-matching floor is **0.50 regardless of the
    schedule**. Raising the default is a network-wide compatibility change (every node of a cell must agree), so it is
    deliberately warned about rather than changed unilaterally.
- **Task.** Decide the default. If it is to stay 2, say so in `spec/platform.md` next to the anonymity claim, because the
  profile's name currently promises more than order 2 can deliver. Any *further* timing work must first exhibit a metric an
  ideal mix passes — the retracted one penalised conservation, which an ideal exponential mix at 50 ms also fails
  (`r = 0.712`).

---

## Tier C — coherence & architecture quality

### 5. Telemetry differential-privacy export path (C7) — **DONE** (`f752495`)
`fanos-node::telemetry_dir` publishes the privatized `CoherenceFrame` to a coordinate-and-epoch store slot, driven off
`Notification::Observed` so the export cadence *is* the diagnosis cadence. Off by default
(`NodeConfig::telemetry_epsilon: Option<f64>`) with deliberately no default ε — picking one chooses a privacy/utility
trade-off on the operator's behalf. The entropy source is the subtle part: `privatize` requires an *infallible* RNG, so
`FreshEntropy` reads a 32-byte OS seed (returning `None`, and skipping the export, if that fails) then expands by
domain-separated XOF — because panicking would down a node and a predictable fallback would void the ε.

### 5-OLD. Telemetry differential-privacy export path (C7)
- **Problem.** Verified: `fanos-telemetry::dp::privatize` (the ε-DP mechanism) has **no caller anywhere outside its own
  crate**. The node has no telemetry *export* path at all, so the DP guarantee is decorative and no operator-facing
  metrics ship.
- **Task.** Build the node telemetry export surface and route every export through `privatize` with the configured
  `PrivacyBudget`. Build the export *first* — there is nothing to privatize today.

### 6. One Merkle tree in `fanos-primitives` — **DONE** (`bfe3fdd`)
`fanos_primitives::merkle` binds the leaf count into the root (killing the CVE-2012-2459 class by construction) and
demands an exact proof length. crosscell and thesauros adopted it; `CrossCellReceipt` gained a `count` field.
**`pqvrf` deliberately did not**: a perfect tree with a publicly fixed height is already unambiguous and already
length-bound, and adopting would change every root for no gain — so the "three divergent implementations" framing was
partly wrong, two of the three being sound by different appropriate mechanisms. The real defects were confined to the
unbounded proof fold (both crosscell and thesauros — 65 535 hashes from one receipt, and in thesauros the prover is an
untrusted storage provider), the `[0u8; 32]` empty root, thesauros carrying the sibling *side* on the wire, and a one-leaf
CID equalling a bare leaf hash. Conformance vectors regenerated.

### 7. Split `fanos-runtime/src/overlay.rs` (7b — the `ThresholdSealed` edge — is DONE)
- **7b DONE** (`a23ed82`). `fanos-taxis` no longer depends on `fanos-aphantos` at all: the KEM **seal** is its own `no_std`
  crate `fanos-threshold` (two low-layer deps), while the **circuit** layer — `seal_onion`, `HopLine`,
  `circuit_line_holonomy`, needing geometry and NYX's ratchet — stays in aphantos as `threshold_onion`. Splitting the file
  rather than moving it was forced by the code: moving the whole thing would have recreated the inversion one hop over
  (`taxis → threshold → nyx`). A facade keeps `fanos_aphantos::threshold::{…}` resolving to both halves, so no caller
  churned. `sealed.rs` deliberately stayed put — it needs `fanos-nyx` and `fanos-wire`, whatever the task doc guessed.
  - *Method note worth carrying:* reading a module's `use` lines is **not** its dependency list. Half of `threshold.rs`'s
    references were fully-qualified paths the imports never mentioned, and the first attempt at the move compiled the new
    crate against deps it did not declare.
- **7a: 4,048 → 2,900 lines (−28%), in four slices, zero API change.** `overlay.rs` is now `overlay/` with
  `healer` (`9cb113c`), `store`/`router`/`membership` (`cad9eb5`), `frames` (`3942199`) and `overlay/hier.rs`
  (`1ef497b`) — 1,344 lines in six modules named for what they do.
  - **What the slices taught, in order.** Cut by **items** (doc/attr block → brace match), never by line offsets: the
    first slice landed mid-doc-comment and orphaned half of `ContentPoint`'s documentation. Start each new module with an
    **empty** import list and let the compiler name what it needs; copying the facade's `use` block dragged in a dozen
    unused imports. Never blanket-rewrite visibility — a `pub(crate) fn` sweep silently demoted two *public* functions
    (`descriptor_message`, `admission_challenge`) that `fanos-sim` reaches by path.
  - **Splitting an impl is CHEAPER than lifting a type**, which is the opposite of what it looks like. A **child** module
    reaches its parent's private items, so `overlay/hier.rs` widened no field at all, where extracting whole types needed
    five `pub(crate)`. The rule is one-way: a parent cannot see a child's privates, so the four methods the facade
    dispatches to are `pub(super)` — which names one module, not the crate.
  - **Remaining, and it is a decision rather than a next step.** `overlay/mod.rs` is `OverlayNode`, its ~1,400-line impl,
    and `impl Engine`. The natural further cuts are `storage` (`on_put`/`on_get`/`on_sample`/`on_publish`/`on_lookup`/
    `on_value`/`distribute_shards`), `membership` (`flood`/`on_join`/`on_announce`/`on_reseat`/epoch), and `liveness`
    (`on_heartbeat`/`health_view`/`loss_view`/`sweep_pending_gets`) — each a child module on the pattern `hier` now
    establishes. Worth doing deliberately; not worth drifting into.

### 8. Coherence / meta-holon reconciliation (E→L / L→O / Ω2 / Ω9)
- **Problem.** The cross-block coherence contracts (`platform.md §1.2`, §9) are asserted but not reconciled in one place:
  the per-subsystem aspect budgets (Ω2 — every tier names all seven aspects), the CALM class on each consistency contract
  (Ω9), and the E→L / L→O typed channels. Also "stake read literally" (§1.2 L→O) versus the historical "forbids capital
  staking" (§7), now that bonded stake exists.
- **Task.** Produce the declared budget/contract table and reconcile it against `fanos-holarch::instance::fanos_platform`
  — which already encodes a budget set and is what the gate scores, so any table that disagrees with it is a real
  divergence, not a documentation gap. Reconcile the staking framing against the shipped `StakeLedger`; add
  `SUBJECT_DEPTH_MAX` / CALM annotations where a live enforcement point exists.

---

## Tier D — lower-severity anonymity residuals (documented in `docs/audit.md`)

- **9b. NYX transparent-sheaf footgun — DONE** (`decc4d8`). `sheaf`/`tessera` are behind a non-default
  `transparent-onion` feature; `NyxError` moved to its own module so gating the construction did not gate the crate's
  error vocabulary. (Was item 12.)
- **9. 3-member anonymity set at F2** — *partially closed* by `8df2b08` (the order is now selectable and under-delivery is
  loud). Residual: document per-cell set size as first-class, and settle the default (item 4).
- **10. S1-M3 + capdir's residual — DONE** (`46f9bc9` for `mixdir`, and the `capdir` half + shared authority after it). The
  two were one gap and are closed by one mechanism, `fanos_node::bound::Entitlement`: a record carries the credential its
  coordinate is *derived from* (identity bytes ‖ VRF public ‖ VRF proof) and the reader checks that the slot's coordinate lies
  on that publisher's own probe walk.
  - **`mixdir`** published its onion key unsigned, so anyone who could write to the store could plant a key at every point of
    the plane and *be* the mixnet. Now bound: on PG(2,7) a lifted record is refused at 49 of the other 56 points, and it is
    tied to its epoch and beacon so a past epoch's record cannot be replayed forward.
  - **`capdir`** *did* sign, and signing was never the missing piece — a signature proves *someone* holding that key signed
    those bytes, so a forger with a fresh key at another node's slot joined the roster as that member. Now bound the same way,
    with the descriptor authenticated against **the very key just proven entitled** (two copies of one key would be a
    cross-check waiting to be forgotten).
  - **One extra half, found while writing it:** a coordinate binding alone still lets an *entitled* publisher advertise under
    another member's id — owning a point says nothing about which name you claim while sitting there. A node's
    role-assignment id **is** its coordinate-VRF public key (`node.rs`'s `SelfOrgConfig`), so `parse_bound_advertisement`
    requires `desc.node_id == entitled.public`, and the name inside the slot is unforgeable too. Pinned by
    `an_entitled_publisher_cannot_advertise_under_another_members_id`.
  - **The mode question the reverted attempt raised, settled.** `Option<BeaconSeed>` at every reader and
    `Option<CoordinateProver>` at every publisher: having a beacon *is* the VRF mode, and its absence is an **absent
    mechanism**, not a disabled check — nothing in a pinned cell can supply one, so `verify: bool` (which reads as "disable
    the security check here") never appears.
  - **⚠️ The trap that cost the most, and is now documented in `bound.rs` and asserted in the suite: the mode cannot be
    inferred from below.** Deriving it from `NodeHandle::claims` — a claim book exists iff the node has a self-certifying
    identity — looks like the same predicate and is not one: **a pinned harness gives its nodes identities while seating none
    of them on a point it could prove.** An assertion added to the pinned QUIC suite reported `true` there and killed the
    derivation immediately. It is a deployment property of the cell, stated by whoever configured it.
  - Threading the mode through the hidden-service host driver hit eight positional arguments, three of them
    `(Vec<u8>, u8, bool)`; `HostedService` now groups what is hosted and under which regime.
  - Superseded, as the earlier revision predicted: a storage-layer write ACL would police *who wrote*, while what matters is
    whether a **reader** can tell a genuine record from a forged one. The check belongs at the read.
- **10b. TAXIS consensus liveness — defect A FIXED, one residual. The root cause was DA sampling with no retry.**
  - **The real defect, and it caused both symptoms.** A replica requests a missing shard the instant a skeleton arrives,
    but the proposer emits skeleton-then-shard peer by peer, so the request routinely reaches peer `p` **before** `p` has
    been dispersed its own shard. `p` holds nothing, answers nothing, and **there was no retry** — the requester waited
    forever for a shard its peer had held all along. One proposal in flight loses that race *sometimes*; under SSLE
    all-propose there are N proposals racing at once and it loses reliably. Fixed by `resample_pending` on each driver
    tick (idempotent: a `Request` for a held shard is answered, for an unheld one dropped, so it converges the moment the
    peer is dispersed).
  - **A second, independent defect fixed on the way: the SSLE lottery was gated on the body it does not rank.**
    `on_propose` ran the DA gate before computing the ticket, and the driver admitted a proposal only after
    reconstruction — so ranking a *losing* proposal required its whole payload. Now `Input::Skeleton` ranks from the
    witness (which `Block::skeleton` already carries) and availability is required only for the block actually prepared.
    Happy-path DA work drops from N proposals to 1, and replicas rank the same set because skeletons need no sampling.
  - **Measured:** `taxis_quic` went from **no block in 240 s** to green in **6.5–10.7 s**. `dromos_quic`'s
    network-submission test also went green — same root cause.
  - **Residual: `dromos_quic::a_private_transfer_executes_over_live_consensus_end_to_end`.** Still refutes. What is now
    *established*, all measured on the live path:
    - Only the **proposer** finalizes (`6:h1`, everyone else `h0`); the others hold the commit certificate and wedge
      waiting for a body. So it is DA availability, **not** the anti-MEV reveal as the previous revision guessed.
    - Rounds do advance — five distinct blocks sit pending at height 0, one per rotated leader.
    - Dispersal is **accepted and answered**: every proposer `Emit` returns `true`, shard `Request`s arrive at their
      target with `held=true`, and the target responds.
    - Yet a replica's shard bitmap sits at `1......` (its own shard only) for 48 s of per-tick retries, occasionally
      reaching `11....1`. Shards are requested, answered, and largely do not land.
    - Recovery is **pattern**-dependent, not count-dependent: `erasure::reconstruct` gates on
      `lrc::is_recoverable_fano(mask)` with `K = 3, N = 7`, so *which* shards are present decides it.
    - **REFUTED — frame size.** A shielded block's shard frame is **6203 bytes** against 43 for a plain-transfer block,
      which looked like the whole explanation for "every small-payload suite passes, the shielded one wedges". It is not:
      a new transport test fans both sizes out to all six peers and both arrive, in 0.62 s. `MAX_FRAME` is 1 MiB and the
      overlay maps `Emit` straight to `Effect::Send`.
    - **The pattern is stable across runs and it is unanimity that fails, not consensus.** A quorum finalizes and
      executes; one or two validators sit at genesis forever holding the commit certificate without a body. Measured
      thrice: `1:h0` alone stuck (6 of 7 executed), then `0,4,5:h0` (4 of 7), and the private-transfer test consistently
      at only the proposer. So the sibling's single green run after the resample fix was luck, not a fix — corrected here.
    - **`fanos_taxis::da::Sampler` extracted (sans-I/O), which is the structural half of the fix.** The sampling decision
      procedure was inline in the driver, which is exactly why the simulator could not exercise it and why a total
      liveness failure was invisible: the sim cannot "differ only in transport" while the logic under test *is* tangled
      into the transport. The driver now owns only the I/O, and its `DaState`/`PendingDa`/`try_reconstruct` are gone.
      Five unit tests, including one that asserts the fixture block genuinely needs more than one shard — without it an
      empty payload reconstructs from a single shard and every exchange test would be vacuous.
    - **`consensus_sim` now drives the real `Sampler`** — one per validator, ONE shard dispersed to each, gathered by
      request/response over the bus, with dispersal *staggered* per (validator, block) so a request can reach a peer that
      holds nothing yet. The lookalike `shards_for`-hands-you-everything model is gone.
    - **And it does NOT reproduce the residual, which is itself the finding.** Both shapes pass, including the exact
      `dromos` shape — `sortition: None`, one proposer, dispersed bodies, **unanimity** asserted on both finalization and
      `Sampler::in_flight() == 0` (`every_validator_recovers_a_dispersed_block_not_merely_a_quorum`, verified to fail
      0-of-7 when sampling is disabled). So the sampling *logic* is sound and the divergence is in the live message path,
      not the decision procedure.
    - **⚠️ DA IS NOT THE CAUSE OF THIS FAILURE. Two iterations were spent on the wrong subsystem; here is the measurement
      that ends it.** With the sampler instrumented, at the frozen fixed point **every one of the seven validators reports
      `pending=0, backlog=0`** — no node is waiting for a body and no node has an unprocessed queue. Availability is
      *clear* while the cell is wedged.
    - The per-pair questions raised in the previous revision are all answered, and all negative: requests **do** arrive
      (534 of them), they **are** served (576 of 580, only 4 misses), all seven coordinates appear as requesters in
      roughly equal numbers, and every ordered pair of cell points delivers a 6203-byte frame in 0.71 s
      (`cell_e2e::every_ordered_pair_of_cell_points_can_deliver`). There is no directional gap.
    - **What is actually happening:** two validators finalize height 0, five never do, and the shielded transfer executes
      **nowhere** — including on the two that finalized. Since nothing is pending, the transaction-carrying block is not
      being *awaited*; it is being proposed and then not prepared. Both an empty 43-byte block and a 6203-byte
      payload-carrying block are dispersed each round, so the payload block is reaching the cell and failing a gate in
      `on_propose` (or failing to gather PREPAREs), after which the round times out and the cycle repeats forever.
    - **This also reverses a correction I made in `eab901e`.** I had discarded the reveal/execution hypothesis on the
      reasoning that "blocks commit without executing ⇒ DA". `pending=0` shows that inference was invalid. Both the
      admission gates (`valid_seal`, `verify_structure`, `valid_last_commit`) and the anti-MEV reveal gather are live
      candidates again.
    - Next observable: instrument `on_propose`'s reject reasons directly — which gate drops the payload block, on how many
      validators. That is one measurement and it decides between "rejected on admission" and "accepted but never
      prepared", which have nothing in common as fixes.
  - **Two of my own errors on the way, both caught by the instrument rather than by reading:**
    - `rank_round0` first called `prepare_round0_min()` unconditionally, which prepares on *first sight* — precisely the
      PREPARE-splitting the collection window exists to prevent. Two engine tests went red immediately.
    - I added an eviction timer for a winner whose body never arrives, keyed off the collection window. The window is one
      tick and sampling takes several, so it evicted **every honest proposer in turn** until the lottery was empty.
      Removed: the round timeout is already the correct backstop, and it is the one a withheld public proposal has always
      used. An eviction timer here would have to be derived from sampling latency, which a sans-I/O engine cannot see.
- **11. ct_len hop-position leak (S1-M6)** — a *peeling* relay learns its hop position, because the threshold-onion layer
  is variable-sized by depth. **Two findings that change the task, so do not implement the fix as previously written:**
  - **Encrypting `ct_len` achieves nothing.** The layer is `nonce(12) ‖ members(2) ‖ ct_len(4) ‖ ciphertext ‖ share*`, so
    `ct_len = total − 18 − members × SEALED_SHARE_LEN` — and `members` is cleartext while `total` is the layer the relay is
    holding. The field is **redundant**; hiding it hides nothing. The leak is that layers *shrink with depth*, not that a
    number names the size.
  - **The real fix is already paid for.** The honest construction is a Sphinx-shape fixed slot array — a constant-size
    header of `D` per-hop slots, each hop decrypting its slot, shifting, and re-padding — which leaks no depth by
    construction. The objection is normally bandwidth, and here it is void: `pad_onion` already pads **every** onion to
    `THRESHOLD_ONION_LEN` = 20 480 B on every hop, and a fixed slot array costs the same bytes. At `q = 2` that width holds
    5 hops, at `q = 4` three, at `q = 7` two — which also makes explicit a max-depth the current design leaves implicit.
  - So this is a contained redesign of the layer layout at unchanged wire cost, not an optional expensive extra. Worth
    doing; worth doing deliberately.
- **12. NYX transparent-sheaf footgun** — `fanos-nyx` `sheaf.rs`/`tessera.rs` (cleartext-Shamir transparent onions,
  superseded on the live path) are still `pub` (`lib.rs:33-34`): gate behind a sim feature or rename so an integrator
  cannot pick the lower-assurance variant.

---

## Simulator hardening (the standing directive, applied to the harness itself)

**App-frame fan-out is now asserted at the transport level** (`fanos-quic/tests/cell_e2e.rs`,
`a_large_app_frame_fans_out_to_every_cell_point`). `Command::Emit` is fire-and-forget and reports only whether the *local*
input queue accepted the frame, so anything lost past that point was silently gone and nothing in the suite noticed —
the only caller that did was a consensus cell that stopped finalizing. Both live sizes are pinned: 43 bytes (a
plain-transfer block's DA shard) and 6203 bytes (a shielded block's). It earns its place by having **refuted** a
plausible hypothesis rather than confirming one.

**The sim now models DA dispersal, because not modelling it hid a total consensus liveness failure**
(`consensus_sim::Cluster::da_delay`). `shards_for` handed every replica the complete shard set instantly, so the sim
delivered proposals whole while production disperses one shard and samples the rest — a violation of the standing
"differ only in transport" rule, and it let every engine-level SSLE test pass while the cell finalized nothing over QUIC.
- Skeletons land immediately (they need no sampling); bodies land `sampling_latency(validator, block)` ticks later.
- **The latency must be per (validator, block), and that is the whole fidelity of the model.** Written with a *uniform*
  delay first, the test passed with the defect fully present — every replica then ranks the identical complete set at the
  identical tick and the lottery cannot split. Independent per-replica sampling is what produces the divergence.
- Verified it can fail: with skeleton ranking removed, `ssle_finalizes_when_bodies_arrive_by_da_sampling_rather_than_whole`
  reports 0 of 7 finalizing. **0.59 s to reproduce what took 240 s over QUIC.**

**A third verdict for the real-socket suites (`tests/common::converge`).** `HANG_CEILING` separated "expected latency" from
"liveness backstop" — a real fix — but left a state neither expresses: **the system has stopped changing.** A wait that ends
at the ceiling can only ever say "too slow", so a wedged cell and a loaded one produce the same message, and the wedged one
was twice answered with more headroom. `converge` reports **Reached / Refuted / Inconclusive**: refuted the moment the
observation has been unchanged for `FROZEN_SPAN`, with the frozen trace attached.
- `FROZEN_SPAN` is **derived**: `2 × fanos_node::taxis_driver::ROUND_TIMEOUT_MAX` (now `pub` for exactly this). A driver
  between round attempts shows no change for just under one round timeout, so one period cannot tell "between attempts"
  from "stopped" — two can. Same argument and same factor of two as `fanos_sim::fabric::FROZEN_SPAN`, which was derived as a
  *single* period first and refuted by the simulator.
- The trace is **per validator**, because the first defect it exposed was one validator out of seven — a cell-wide "not yet"
  cannot say that.
- Measured: a wedged cell now fails in 51 s naming the stuck node, against 241 s saying only "did not converge".

Each defect class found this session is now an **assertion in the simulator**, not a one-off measurement — and two of them
were defects *in the instrument*:

- **A blind observable manufactures defects.** `Node::health().address` was a field captured at spawn while the engine
  reseated every epoch, so every layer named the node's birth position forever. Three "collided draws never resolve"
  measurements were taken through it and are void. Pinned by
  `fabric::a_reseat_moves_the_coordinate_every_layer_reports`, which failed at 245 s against the old code and passes in
  0.11 s (`4bb60f3`). `Notification::Reseated` had existed with no consumer — the engine always announced its re-seats and
  nothing listened.
- **A symptom that cannot be localised is a measurement, not a test.** `Health::verified_claims` separates "never heard of
  the rival" from "heard and did not move", two defects with one symptom. Pinned by
  `fabric::a_node_records_the_claims_of_peers_it_meets`; it refuted a hypothesis immediately (`4bb60f3`).
- **A timeout is not a refutation.** `NodeFleet::until_settled` is three-valued — `Reached` / `Refuted` / `Inconclusive` —
  discriminating on the trajectory rather than on load average, so a contended host reports "still converging" instead of
  red. Pinned by `fabric::the_harness_tells_a_refutation_apart_from_an_unfinished_measurement`, all three branches
  (`ef18e81`). Its `FROZEN_SPAN` is derived from `role_loop::ROSTER_REFRESH` × **2**, the factor being the content: a
  process firing every `T` is unchanged for just under `T` between firings, so `T` alone cannot tell "between firings" from
  "stopped". The sim proved that by refuting my first derivation.
- **Establish the baseline before attributing a failure.** `git stash push -- <own paths only>`, run, pop. Two hypotheses
  died to this in one session; both would otherwise have shipped as findings.

## Two test defects found while doing the above — both mine, both from the same gap

Recorded because the cause was one habit, not two accidents: **every gate I ran was `cargo test -p <crate> --lib`, which
does not run `tests/*.rs`.** Running `cargo test --workspace --tests` (78 suites) surfaced both immediately.

1. **`fanos-quic/tests/self_certifying.rs::an_impostor_at_the_resolved_address_is_rejected`** had been failing
   deterministically (0.02 s) since `fdf3075` earlier the same session. It poisoned the directory with the *unranked*
   `Directory::insert` over a binding the driver had made *with* a rank — which rank arbitration correctly refuses, so the
   poisoning silently stopped working and the test's premise evaporated. A test whose **setup** depends on behaviour you
   just changed fails by becoming vacuous, not by asserting something false. Fixed by modelling a stale entry the way one
   actually arises (B vacates, C rebinds) and asserting *both* halves.
2. **`fanos-sim::fabric::the_whole_cell_resolves_every_member`** failed in **40.2%** of runs, and the comment above the
   assertion claimed it was draw-independent. Comparing rosters against *occupied* coordinates fixes the target number but
   not the fact that the node losing a collision's arbitration is unroutable and can never see the whole cell.
   `NodeFleet::spawn` now draws injectively (`e243ac4`).

**Standing rule from both:** gate with `cargo test -p <crate>` (all targets), never `--lib`. And a deterministic
sub-second failure is never a load flake, however high the load average.

## Corrections to the previous revision of this file

Recorded rather than silently edited, because the pattern matters more than the entries: **a handoff doc drifts exactly
the way the code it describes does**, and a task list that flatters its own currency wastes an implementer's day.

1. **"Γ-viability gate does not exist (no `architecture/` dir)" — false.** `fanos-holarch` exists and delivers it:
   `aspect`/`gamma`/`instance`/`panel`/`verdict` + `ablate`, with `instance::fanos_platform()` scoring the platform's
   declared budgets. `tests/gate.rs` asserts V1–V4, reproduces the `platform.md §1.2` estimate to 5e-3 (P = 0.3704,
   Φ = 1.563, D = 2.615), checks the corpus reference corners, requires each ablation to break its targeted invariant, and
   asserts all 7 σ-panel checks. It gates CI through the `cargo test --workspace` step. The one residual is cosmetic:
   §1.2 prints `P ≈ 0.36` where the calculator computes 0.3704.
2. **"OBOLOS has no incoming-viewing key (O-M3)" — false.** `wallet.rs` has `IncomingViewingKey` with `scan()` and a
   `to_incoming()` downgrade. Only O-M4 (stealth/diversified addresses) is open, and it is now Tier A item 1.
3. **"The GPA timing channel is essentially undefended" — retracted.** `c896d2d` retracted `18fce2e`. The metric
   (per-hop in/out rate correlation) penalised **conservation**: a relay neither drops nor manufactures real cells, so over
   a window ≫ the mix delay cells-out must equal cells-in, and an ideal independent-exponential mix at 50 ms scores
   `r = 0.712` on it. Two invalid variants are kept `#[ignore]`d in `fanos-sim/tests/traffic_analysis.rs` as labelled
   counter-examples. The lesson is a standing rule: **compute the ideal reference before reporting a defect**.
4. **"3,870-line `overlay.rs`"** — it is 4,048.

*Notes for the implementer.* A **concurrent teammate** is active in `fanos-keygen/src/recovery.rs` and `fanos-obolos`
(`lib.rs`, `ring_tx.rs`, `ring_output.rs`) — never stage those. `fanos-vrf` is no longer contended. Every change must keep
`cargo clippy --workspace --all-targets --features validator -- -D warnings` and `cargo test --workspace` green (42
crates, 1,600+ tests); the repo is hand-formatted, so **never run `cargo fmt`**. Standing directives apply: math-grounded
(derive, no magic thresholds), maximal crate reuse, no deferring — implement in full, then verify.
