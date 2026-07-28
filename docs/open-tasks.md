# FANOS — open tasks

**Only open items live here.** A closed task is deleted, not annotated: its rationale is in the commit that closed it, and any
durable finding belongs in the design or audit doc it concerns (`docs/audit.md`, `docs/design-testing.md`,
`docs/design-anonymity-substrate.md`, `docs/design-coordinates.md`).

**Check the claim before doing the work.** A task list is a cache; this one has gone stale twice. Each item names the file and
symbol its claim rests on so the check is cheap.

No open CRITICAL/HIGH *security* item remains (`docs/audit.md`, all four passes RESOLVED). The 2026-07-27 architecture audit
(`docs/audit-2026-07-27-architecture.md`) adds the items below marked **[A]**.

---

## Tier A — headline frontiers

### [A] Close the "libraries ahead of wiring" gap — four items, measured and guarded
The list is now computed, not remembered: `fanos-cli/tests/architecture.rs` takes the closure over the manifests and fails
if a crate is linked by nothing (or if a listed orphan gets wired). 34 of 43 crates sit in the node's closure, 38 of 43 are
reachable from some shipped binary. The earlier prose version of this item was wrong in two thirds of its list — see
`docs/audit-2026-07-27-architecture.md` §2.1 — because it grepped for crate names where the crate is reached through an
intermediary. What genuinely remains:

| crate | claim it carries | gap |
|---|---|---|
| `fanos-angelos` | L11 messenger, a headline product | **orphan** — linked by nothing at all |
| `fanos-ergon` | the effect-algebra "no gas, derived footprints" model | **orphan** — DROMOS executes without it |
| `fanos-vpn` | the full-tunnel datapath | CI now compiles `--features vpn`; **the datapath itself is still exercised by nothing** |

Each needs one live test or an honest downgrade of the claim. `fanos-bench`/`fanos-ffi`/`fanos-wasm` are embedding
surfaces and are exempt by construction.

### [A] Decide whether `InsufficientFunds` is premature — the one case left, and it is a trade-off
The sweep is otherwise done. `ExecOutcome::Deferred` now covers every order-dependent case in
`HybridLedger::apply_with_verdict` that has an **identifiable pending prerequisite**: a transparent nonce ahead of its
account, an HTLC claim/refund ahead of its lock, a storage prove/close ahead of its open, and the funding transfer of a
shield, a name operation, an HTLC lock and a storage open (`TokenLedger::is_premature`). The shielded path needs nothing —
its rolling anchor window accepts any recent root and no wallet can prove membership against a root that does not exist.

What is left is deliberately undone: a transaction that fails on **balance** has no identifiable prerequisite, so
deferring it re-consumes block space for `REVEAL_WINDOW` blocks and multiplies a spam flood by that factor, with no fee to
price it (ERGON is gasless). Deciding it needs the spam-cost model, not more of this pattern.

Two rules the sweep established, both worth keeping:
- A rejection is premature **iff re-executing the transaction unchanged against a later state could succeed.** Replay,
  double-spend, bad signature, malformed bytes never can; a missing prerequisite can.
- **Deferral is a last resort, not a first check.** The check must run *after* everything a handler can judge on its own,
  or a transaction that is both malformed and premature gets deferred — wasting `REVEAL_WINDOW` blocks before being
  dropped anyway. The first version had it backwards and the existing storage suite caught it; the ordering is now pinned
  by `a_transaction_that_is_both_malformed_and_premature_is_rejected_not_deferred`.

### [A] A sub-quorum lock split still stalls a live cell about 1 run in 8
**Largely fixed; this is the residual.** Originally 2 of 4 runs of `cargo test -p fanos-node --test dromos_quic
--features validator a_hash_locked` failed on an **idle** host (load average 3.75), every failure with all seven
validators at `next_height() == 1` and the HTLC still `Locked`. The proof-of-lock (`docs/design-taxis.md` §4.1) took that
to **1 in 8**. Starvation was ruled out throughout by the verdict's own evidence: 295 ms for the slowest of 321 completed
observations, on a machine doing nothing else.

It also subsumes an earlier item, now deleted: "a quiescent chain leaves a straggler behind" was the same lock split seen
from the other side (5 of 7 executing a second transaction while 2 sat at the previous height). A quiescent cell in fact
advances perfectly well — measured reaching height 9 with no transactions at all, and 14 with one.

**Why nothing caught it.** No other real-QUIC suite requires a *second* finalized block. `dromos_quic`'s two siblings, both
`taxis_quic` tests, and `anonymous_quic` all reach their fixed point at height 1 — one transaction, one block, assert. The
HERMES contract suite is the first that needs two rounds of consensus (lock, then claim), and it is where this appears.
The deterministic simulator reaches height 24+ reliably in the same shape, so the defect is in the live driver or its
transport, not in the engine's logic.

**Root cause located, 2026-07-28: a lock split that never heals, because the majority never obtains the locked block.**
Instrumenting every `ProposalRejects` counter on a failing run gives exactly one reason and nothing else:

    15 rejects, all `locked`, all at height 1 — 5 each from validators 0, 2 and 3. The other four reject nothing.

So three validators received the height-1 proposal, locked on it, and refuse every later one; the other four never
received it, so they have nothing to reject and go on proposing alternatives. Quorum is 5: neither side can reach it.
Crucially **no `unavailable` reject appears** — the four are not refusing the block for want of its body, they never saw
the proposal at all.

`awaited_body` is now widened to that third case — a block peers are voting for and this validator does not hold — and it
is kept because its trigger is real. But instrumentation says it is **not** what the four validators were missing:
`WANT-VOTED` fires 41 times on a failing run while the driver's `ASK` fires **zero** times, because the guard
`!da.is_sampling(&want)` is already true. The four *did* receive the skeleton and *are* sampling; they simply never
complete the shard set.

**Two fixes for that were tried and both are measured regressions — do not retry them.** Baseline: the suite fails in
~55 s, passing runs take 10–13 s.
| change | result |
|---|---|
| request each missing shard from **every** peer, not just its custodian | **0 of 3 passed**, every run exhausting the 240 s ceiling |
| additionally ask the block's **proposer** (which provably holds it whole) | **0 of 4 passed**, 150–167 s each |

Both results stand as evidence that **adding request traffic to this recovery path measurably hurts**, which is worth
knowing before anyone proposes more of it. The conclusion drawn from them at the time — that transport capacity was the
binding constraint — did not survive: the binding constraint is the lock split below. The single custodian per shard
remains a genuine structural weakness, and `ConsensusEngine::shard_of` lets any holder answer for an index it can produce,
but it is not what stalls the cell.
**Size is refuted, and the real obstacle is structural.** Measured sealed transaction sizes: the *shielded* transfer whose
suite passes reliably is **18 473 bytes**, twice the HTLC lock (**9 101**) whose suite stalls. Size is not the variable, so
every size-derived hypothesis above is dead.

What `reprepare_lock`'s own doc requires is the answer: *"liveness follows because a **quorum** locked on the same block
re-prepares it together."* With three of seven locked and five needed, no number of rounds can re-form the PREPARE quorum.
The standard remedy is Tendermint's **valid-value rule** — a proposer re-proposes the value it is locked on instead of
building a fresh one — and it is **not expressible in this design as it stands**:

- a block header commits to `proposer`, and `on_propose` requires `leader(seed, height, round) == header.proposer` outside
  SSLE round 0. So a validator cannot re-propose *another* validator's locked block: the header would name the wrong
  proposer and be refused on `rejects.proposer`. Only the original proposer can re-offer it byte-identically, which the
  `reprepare_lock` doc already notes, and it may not be entitled in the later round.
- Attempted and reverted: re-proposing the locked block from `maybe_propose`. It cannot work for that reason, and the
  attempt is what surfaced it.

**The proof-of-lock is implemented and it cuts the failure rate roughly threefold, but does not close it.** `Block::pol`
carries a `Phase::Prepare` quorum certificate over the block, `on_propose` admits *any* proposer whose block comes with a
valid one, and a locked validator holding its block may re-offer it regardless of the round's rota. Measured across
`a_hash_locked` runs: **1 of 8 failing** with the fix, against **3 of 6** before (and one further failure in a
full-`dromos_quic` run). No regression elsewhere: `taxis_quic` 2/2, `anonymous_quic` 5/5, `mix_directory_quic` 3/3,
`consensus_sim` 31/31, taxis unit 86/86.

The order the two halves went in is worth keeping, because the first alone did nothing: with only the receiver relaxed,
`maybe_propose` still returned early for a non-entitled validator, so a locked validator could re-offer its block only in
the rounds where the rota happened to reach it — 3 in 7, while the round timeout doubles toward 24 s. The receiver
accepted a justified re-proposal that nobody was ever entitled to send. Rate unchanged at 3 of 6 until the sender side
was made symmetric.

**Residual.** Something still stalls occasionally, and the surviving failures run 90–110 s where a healthy run is 10–25 s,
so the cell is converging *slowly* rather than never — which is a different shape from the original permanent freeze.
Next: instrument how many rounds a failing run burns and which validator finally re-offers, and check whether the
doubling round timeout (`ROUND_TIMEOUT_MAX` 24 s) is what makes the remaining window too tight, since a re-offer can only
happen on a round entry.

Size is what makes it *likely* rather than what makes it happen: a 9 KB block is slower to disperse, so the window in
which only some validators hold it is wider.

**Superseded reading, kept so it is not re-derived** — three probes first suggested DA availability:

| cell | driven with | 40 s of heights |
|---|---|---|
| `Accounts` | one small transfer | reaches **14**, no stall over ~5 s |
| `HybridLedger` | nothing at all | reaches **9**, pauses ≤ 10 s |
| `HybridLedger` | one **9 101-byte** HTLC lock | reaches 6–7 and **stalls 25 s+** |

So a quiescent cell advances fine and the state machine is not the variable: what stalls it is a block carrying a large
transaction. The stalled sample is split — `[7, 6, 6, 7, 6, 6, 6]` — which is the signature of **body availability**, not
of agreement: some validators hold the block and some do not. A 9 KB transaction is dispersed as erasure shards and must
be sampled back; `resample_pending` and `NeedSkeleton` retry exist in the driver, and are evidently not enough at this
size.
- The deterministic simulator models dispersal (`sampling_latency`, `Sampler`) and reaches height 24+ in the same shape,
  so the fidelity gap is in *what it models about size* — its shards are exchanged by construction rather than raced.
- Next: instrument `Sampler` occupancy on the live path, and check whether a 9 KB block's shard set is ever completed by
  the validators that lag. Compare against the ~1 KB shielded transfer, which does not stall.

### [A] The verification gate itself is load-sensitive — one flake per full-workspace run
Measured 2026-07-28 on the current tree: `cargo test --workspace --features validator` → 43 suites, **756 tests, one
failure**. The failing one was the HERMES contract suite, with all seven validators frozen at the lock height; in
isolation the same suite passes in 20–30 s, repeatedly.

The verdict now carries the evidence to judge it, which is the point of the progress-bounded waits: **321 observations
completed inside the frozen window, the slowest taking 269 ms** against single-digit milliseconds idle. So the host was
answering, roughly 30× slower than idle, and the cell still made no progress in that window.

- That suite is structurally more exposed than its two siblings: it needs *two* rounds of consensus (lock, then claim), so
  it spends twice as long in the contended window. A one-transaction test's fixed point is reached before contention
  matters.
- **Do not fix it by widening a timeout** — the frozen span is already counted in observations rather than wall clock, and
  it still refuted. The binding constraint is that `cargo test` runs several real-QUIC cell fixtures against one loopback
  and one scheduler. The decision is how the harness bounds concurrency for *transport-bound* suites: `serial_cell`
  already does this within a binary, but nothing coordinates across binaries.
- CI runs exactly this command on a 2-core runner, i.e. permanently in the contended regime. A gate that flakes teaches
  people to ignore it — which is how this repository acquired a formatter gate nobody looked at (§2.0).

### [A] Combiner-forwarded anonymous sessions stall under host contention — and only those
Isolated 2026-07-27 by the progress-bounded waits in `fanos-node/tests/common/mod.rs`, which report *what the bytes did*
instead of "did not finish in 240 s". On a host loaded by an unrelated build, one run of `anonymous_quic`:

| test | path | result |
|---|---|---|
| `an_onion_reaches_the_meeting_line_over_real_quic` | direct | ok |
| `a_full_anonymous_session_completes_over_real_quic` | direct | ok |
| `a_fresh_anonymous_session_completes_over_a_cell_of_composites` | direct | ok |
| `a_service_hosted_off_its_meeting_combiner_is_reached_via_forwarding` | **combiner-forwarded** | **0 bytes / 48 s** |
| `the_spawn_rendezvous_host_driver_serves_a_dialer_over_real_quic` | **combiner-forwarded** | **0 bytes / 48 s** |

The split was by path, not by cost, and the *same process* delivered 23 and 46 bytes on the direct flows while the
forwarded ones moved none. These are also the two tests that failed the first full `cargo test --workspace --features
validator` run. Idle, all five pass in ~2–5 s, repeatedly.

**Held as unconfirmed, deliberately.** The observation above is a *single* run, and this host cannot support a controlled
one: an unrelated project's test binary was measured at **1202 % CPU** (12 of 16 cores) during the follow-ups, so every
"N× oversubscription" experiment here was really N× plus an unknown, time-varying neighbour. Under load I could add, all
four exchange-driven tests starve alike and report INCONCLUSIVE — the path split did not reproduce. One candidate cause
was removed on the way (both forwarded tests were the only ones synchronising on a fixed sleep; those are now waits on
`Notification::HostRegistered` and on the mix directory actually being readable), but removing the sleeps entirely does
*not* fail idle, so the sleep is not shown to have been the cause either.
- **What would settle it:** a quiet host, or a way to apply load to the cell without loading the observer. Until then this
  is one observation, not a defect.
- **Do not "fix" with longer timeouts.** A wait that ends without bytes is not a slow wait, and 240 s already failed to be
  a principled multiplier.
- Residual instrument gap: a host that starves only *midway* still reads as a wedge, because the discriminator asks
  whether the process has *ever* delivered.

### [A] Verify the nightly `heavy` job's class selection actually runs
`ci.yml`'s `heavy` job now selects cost-gated assertions by class rather than by package:
`cargo test --workspace --features validator --release -- --ignored --skip measure_ --skip probe_ --skip sweep_
--test-threads 1`, and `fanos-cli/tests/ignored_tests.rs` guarantees the `--skip` set selects exactly the assertions.
Unverified as written, because it needs a full **release** build of the workspace plus the twelve assertions serially —
minutes of compute this host could not spare while other work was measured. What is known: the OBOLOS proofs pass in 38 s
release/serial, the two C ABI end-to-end paths in 0.17 s, and `the_fabric_seam_carries_real_node_traffic` and the two
randomized no-fork searches have never been run in that configuration. Run it once with `workflow_dispatch` (or locally)
before trusting the nightly.

### [A] No machine-checked formatting convention
`cargo fmt --all --check` was removed from CI (2 650 hunks: the source is deliberately hand-wrapped denser than rustfmt's
100-column default, and as the *first* gate step it hid every gate below it — see `docs/audit-2026-07-27-architecture.md` §2.0).
Nothing now enforces any width. The house style is ~120 columns: **15 768** lines exceed 100, **1 395** exceed 120, but only
**84** exceed 140 — and that tail concentrates in six files (22 in `fanos-obolos/tests/scenarios.rs`, 10 in
`fanos-observatory/src/bin/lab.rs`, 9 in `fanos-dromos/src/naming.rs`). So a 140-column ceiling costs 84 rewraps and is
enforceable today; a 120-column one costs 1 395 and is the mechanical reformat that was rejected. Decide the bound, fix the
tail, add the check.

### [A] Split `fanos-quic/src/driver.rs` — 2 125 production lines, eight concerns
The workspace's largest production file, larger than `overlay/mod.rs` is *after* its split, and never split. Concerns:
PROTEUS shaping; identity/self-certification; coordinate placement & reseating; handle/client API; the spawn surface;
connection & frame plumbing; NAT traversal; the custom UDP fabric. Cleanest first cuts, none needing an API change: `placement`
(reseating), `fabric` (`impl quinn::AsyncUdpSocket`), `holepunch`, `shaping`. Method: `docs/design-testing.md`
§"Refactoring a large module".

### [A] Make node readiness explicit — `Node::start` is correct only if nothing yields at spawn
**Blocks the builder below.** Two opposing, undocumented startup-ordering sensitivities, satisfied today only by an accident:
`spawn_self_certifying_persistent_over` (used by `Node::start` and the simulator) is synchronous, while the other four
self-certifying variants are `async` awaiting nothing. So the deployed node never yields at spawn and every harness does.
Measured in isolation with one unified `spawn()`:

| `spawn()` | node role-loop test | live `anonymous_quic` |
|---|---|---|
| sync | passes 2.1 s | **fails 4 of 5** |
| async + one `yield_now()` | **fails 10.6 s** | passes |

Do **not** fix by choosing a yield placement — that re-encodes the race in a second accident. Make readiness explicit:
`spawn` returns a handle whose tasks are spawned but not running, and a caller needing a peer to serve awaits evidence (a
notification, a successful dial), as `establish_membership` already does for membership. Detail in
`docs/audit-2026-07-27-architecture.md` §6.

### [A] Collapse seven `spawn*` entry points into one builder
`spawn`, `spawn_shaped`, and five `spawn_self_certifying{,_with_capabilities,_persistent,_persistent_on,_persistent_over}` —
the latter five all funnel into `self_certifying_inner` and differ only in which of `{bind, credentials, capabilities, proteus,
fabric}` they take. The names encode the parameter list, so each new axis has meant a new public function. Also re-read the 25
remaining `allow(clippy::too_many_arguments)` the same way: twice this session such a lint was pointing at a missing *type*.
- **Written once and reverted** (clippy clean, `fanos-quic` 6 suites + `fanos-node` 114 green) because it flips the live tests
  red until the readiness item above is done. Four of the five variants are `async` awaiting nothing, which is what the
  `allow(clippy::unused_async)` suppressions cover — the lint is right, but removing them is what exposes the race.

### [A] Thin unit coverage — in two crates, not three
`fanos-observatory` 2 394 lines / **0.16** ratio / 17 tests. `fanos-runtime` 3 433 / 0.29 / 29 — the overlay engine;
mitigated by `fanos-sim` (267) and `fanos-quic` (68) but the thinnest own-coverage of any core crate.

`fanos-holarch` is **struck from this list**: its tests turned out to be dense, not thin, and the real defect there was an
assertion weaker than its own doc claim — invisible to a ratio. Fixed (`docs/audit-2026-07-27-architecture.md` §2.3), and
it produced a theorem: V1 is implied by V3, so the viability window has three independent walls, not four. Treat the
remaining two rows the same way — look for claims that no assertion checks, not for a line count.

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

### 2. Roster never converges when a coordinate collision has to be resolved
- **Reproduce:** `fanos_sim::fabric` → `measure_roster_convergence_with_collisions_allowed` (`#[ignore]`d; forces a colliding
  draw). Rosters stall (e.g. `[6,4,4,5,5,6,6]`) and `agreed` is `None`; the injective control reaches `[7; 7]` in 24 s.
- **Not the cause** (each measured, do not re-test): placement — trials reach 7 of 7 distinct with nodes visibly advanced along
  their probe walks; claim propagation — 3–7 peers' claims verified per node; the three-valued read fix — already in
  (`Scan<T>`, `role_loop::may_relax`), and it is what made the injective case converge.
- **Not established:** `known_peers` is `Directory::len()` (the dial book, seeded in spawn order — a staircase even when
  converged), so it cannot carry the conclusion. **Prerequisite: an observable meaning "this node can reach coordinate X".**
- `NodeFleet::spawn`'s injective draw stays until a forced-collision run reaches `agreed`.

---

## Tier B — platform capability

### 4. Settle the default plane order — now constrained by the onion payload floor
- `plane_order` defaults to **2**, where `PG(2,2)` has 4 lines with distinct combiners ⇒ 2 concurrent circuits ⇒ a passive
  adversary's flow-matching floor is **0.50 regardless of the mix schedule** (`8df2b08` made the order selectable and warns on
  under-delivery; the schedule itself is calibrated and closed).
- **New hard constraint:** the fixed-slot onion reserves one nested threshold seal of payload, so circuit depth falls as the
  plane widens — `slots::depth_for`: **3 hops at q=2 and q=3, 2 at q=4, 1 at q=7**. Raising the default to 4 buys a larger
  anonymity set and costs a hop; q=7 cannot carry a circuit at all inside `THRESHOLD_ONION_LEN`.
- **Task:** decide (2, 3 or 4), and if it stays 2 say so in `spec/platform.md` beside the anonymity claim, because
  `--profile anonymous` currently promises more than order 2 delivers. Document per-cell anonymity-set size as first-class
  (absorbs the old item 9). If a wide plane is wanted, `THRESHOLD_ONION_LEN` must grow with it — a wider cell buys more slots,
  not more payload, so the budget is the knob, not the depth.
- Any further timing work must first exhibit a metric an *ideal* mix passes; the previous one penalised conservation and was
  retracted.

---

## Tier C — coherence & architecture quality

### 7a. Decompose `fanos-runtime/src/overlay/mod.rs`
`overlay.rs` is now `overlay/` (six modules, −28%, zero API change). What remains is `OverlayNode`, its ~1,400-line impl and
`impl Engine`. Natural cuts, each a child module on the pattern `hier` established: `storage`
(`on_put`/`on_get`/`on_sample`/`on_publish`/`on_lookup`/`on_value`/`distribute_shards`), `membership`
(`flood`/`on_join`/`on_announce`/`on_reseat`/epoch), `liveness`
(`on_heartbeat`/`health_view`/`loss_view`/`sweep_pending_gets`). A decision to take deliberately, not to drift into. Method
notes: `docs/design-testing.md` §"Refactoring a large module".

### 8. Coherence / meta-holon reconciliation (E→L / L→O / Ω2 / Ω9)
- **Problem.** The cross-block coherence contracts (`platform.md §1.2`, §9) are asserted but not reconciled in one place:
  the per-subsystem aspect budgets (Ω2 — every tier names all seven aspects), the CALM class on each consistency contract
  (Ω9), and the E→L / L→O typed channels. Also "stake read literally" (§1.2 L→O) versus the historical "forbids capital
  staking" (§7), now that bonded stake exists.
- **Task.** Produce the declared budget/contract table and reconcile it against `fanos-holarch::instance::fanos_platform`
  — which already encodes a budget set and is what the gate scores, so any table that disagrees with it is a real
  divergence, not a documentation gap. Reconcile the staking framing against the shipped `StakeLedger`; add
  `SUBJECT_DEPTH_MAX` / CALM annotations where a live enforcement point exists.
