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

### [A] A ~1-in-8 test sits in the per-push CI gate, and it should not be hidden
`a_hash_locked_contract_is_funded_and_claimed_over_live_consensus` is **not** `#[ignore]`d, so it runs in the `gate`
job on every push, where it fails both under full-workspace loopback saturation and — at a lower rate — in isolation.
A gate that fails one push in eight blocks merges at random and trains people to re-run rather than read.

The repo's own convention would move it: two sibling real-QUIC tests are `#[ignore]`d into the nightly `heavy` job for
exactly this reason, with the rationale written down. **Deliberately not doing that yet.** Ignoring it would convert a
known liveness defect into an unobserved one, and the defect is real — it is the thread that produced the sampler
eviction fix below. The honest options, in preference order:
1. keep hunting until the isolated rate is zero, then the saturation question is CI tuning rather than cover;
2. if it must move, move it *with* a recorded isolated failure rate, so nobody later reads `#[ignore]` as "flaky, safe".

Whichever way it goes, it is a decision to make explicitly rather than by attrition.

**Process note for the next investigator:** the failure message carries the whole `ConsensusProbe` trace, which is the
diagnosis. Do not filter test output through `grep -E "FAILED|^---- "` — that drops exactly the line worth reading.

### [A] The adaptive admission gate is built and tested but DELIBERATELY NOT INSTALLED
`fanos_core::AdaptivePowAdmission` reads its difficulty from a `LiveDifficulty` the coherence controller drives,
so a cell under attack prices entry within one observation window. It never charges below the operator's floor —
a stuck sensor or a compromised controller can only *raise* the price, never open a network its operator chose to
close. `SYBIL_REJECT` now carries the required difficulty in the reason field its `ErrorBody` always had.

**It is not installed in `Node::start`, and that is a safety decision, not an unfinished one.** The overlay has
**no receive path for `Error` frames at all** — nothing dispatches `FrameType::Error`, so a rejected joiner
already gets a frame nothing reads. Under a *static* difficulty that costs only a diagnostic. Under an adaptive
one it is fatal to the honest: a joiner whose proof was minted a moment before the price rose is refused, is told
the new number, and has nothing that reads it — a permanent unexplained refusal, which is the attacker's goal
reached through the defence.

To install it, in order:
1. ~~dispatch `FrameType::Error` and surface the refusal~~ — **DONE**: the overlay now decodes `Error`, and a
   `SybilReject` becomes `Notification::AdmissionRefused { required }`. Only that error is surfaced; the rest are
   diagnostics a sans-I/O engine has nowhere to write and no business waking a driver for.
2. ~~re-solve at that difficulty, bounded~~ — **DONE**, and in the engine rather than the driver, following the
   precedent already there: `reseat` re-mints the proof inline when the coordinate moves. Three guards, each
   answering a way the mechanism could be turned against the joiner — never below what the operator configured
   (a peer cannot talk a node into a weaker proof); never above `MAX_INLINE_ADMISSION_BITS` (derived from the
   engine's own 500 ms window, so a solve cannot block the cell — without it "solve harder" on demand is a
   remote CPU-exhaustion primitive); and monotone, so a crowd all demanding the maximum costs one solve, not one
   each.
3. only then install `AdaptivePowAdmission` and drive `LiveDifficulty` from the healer's
   `AdmissionController::observe`. **The remaining question is what the healer should do with a stress reading
   from a cell it is itself part of** — a node under attack raises its own price, which is right; a node that
   *mis*-measures raises it too, and nothing yet cross-checks one node's reading against its cell's.

Weighed and rejected as a *substitute*: carrying the price in the pre-announce exchange. It is a fine
optimization — the joiner solves right the first time — but the price can change between learning it and
announcing, so the retry path is needed for correctness regardless. An optimization on top, not instead.

### [A] Operator surface — the control socket closes the read half; the monitor is still next
`fanos status` now asks the **running node** over a local Unix socket (`admin.sock`, mode 0600 in the state
directory) and reports what the node itself sees: coordinate, peers, verified claims, probe index. Verbs are
`ping | health | roles | shutdown`. Filesystem permissions are the authentication — the control plane is not
addressable from the network at all, which is the property that matters for a process whose job is accepting
traffic from strangers.

Remaining, in order:
1. **`OverlayCoherenceSource`** — the observatory still watches a *simulated* cell. `read_coherence` has no caller,
   so nodes publish ε-private coherence frames that nothing consumes. The same `SnapshotSource` trait the live
   source implements is the seam; this is the last thing between the panel and a real deployment.
2. **`fanos node --metrics-listen`** — `render_openmetrics` exists and nothing serves it, so a deployment cannot be
   scraped. The control socket could carry it as a fifth verb, which needs no new listener.
3. **Coherence in `status`** — Φ/P/R belongs beside the peer count, and needs (1).

### [A] ROOT CAUSE: TAXIS had no round synchronization — FIXED
The defect the whole live-stall investigation was circling. `self.round` advanced by exactly one thing — this
validator's own timeout firing. **Nothing** ever moved a validator toward the round its peers were on. Local timers are
independent and the round timeout doubles toward 24 s, so validators drift apart on ordinary scheduling noise and then
have no mechanism to re-converge.

That is not cosmetic, because proposer entitlement is round-dependent: `on_propose` judges a proposal against
`leader(seed, height, self.round)` using the **receiver's** round, and the block header deliberately carries no round
(it must not — a header committing to the round would make a re-proposal differ byte for byte, and a locked validator
could never accept one). A proposer legitimate at its own round is therefore an impostor to a peer one round ahead, and
the proposal is not merely ignored: it is counted as a proposer-entitlement violation and discarded. **A drifted cell
rejects the proposals it makes to itself.**

Every symptom of this investigation follows: hundreds of `rejects.proposer` in every frozen trace; rounds climbing to
13; validators sitting at different rounds in one snapshot (`v0` at 12 while six peers were at 13); and validators
watching three different blocks, because each admitted a different subset of proposals according to its own round.

Fixed with the standard rule: on seeing `f + 1` validators voting at a round above ours, jump to the highest round
`f + 1` of them have reached. `f + 1` guarantees at least one honest validator genuinely got there. Jumping forward is
safe by the same argument as a timeout — locks and committed state persist across rounds, and votes are round-tagged,
so no certificate can be assembled from a round we skipped. Both randomized no-fork searches still pass.

Pinned by `a_validator_left_behind_in_the_round_rejoins_the_round_its_peers_reached`, verified load-bearing.

### [A] CORRECTION: the eviction fix is a latent-defect fix, not the demonstrated live cause
Checked my own arithmetic after committing, and it does not support the attribution. `Sampler::reconstruct` **removes**
the entry, so `pending` holds only skeletons that never reconstructed — not every skeleton ever seen. And under SSLE
only round 0 is all-propose; rounds ≥ 1 contribute one proposal each. So a height burning 13 rounds produces on the
order of twenty skeletons, of which only the failures accumulate — nowhere near the 64-entry cap.

The eviction is real, the fix is correct, and the class is worth closing (see below). But the live symptom it was
committed against — seven of seven validators reporting `await` at round 13 — was **not shown** to be eviction, and I
wrote the commit as though it had been.

Made falsifiable rather than argued: `DriverProbe` now reports `sampling=N/CAP`. The next live failure settles it — a
validator stalled with the queue in single digits provably is not losing skeletons to eviction, and one stalled near the
cap is.

### [A] The sampler eviction — FIXED (latent)
The strongest finding of this investigation, and it explains the `await` that appears in **every** frozen trace.
`Sampler::pending` is bounded (`PENDING_CAP = 64`) because its key is a remote-chosen block hash, and `BoundedMap`
evicts in **insertion order**. Under SSLE all-propose a height costs one skeleton per validator per round, so a
seven-validator cell overruns the map in nine rounds — and the first entry discarded is the earliest, which is round 0's
min-ticket winner: the block the cell converged on. Later proposals that will never be chosen evict the one that was.

The consequence is a loop, not a delay: once evicted the block leaves `outstanding()`, so no shard is ever requested for
it again; the driver sees the validator still waiting and re-fetches the skeleton; the next round's proposals evict it
again. Measured live as seven of seven validators at round 13 reporting `await` for a body none of them held.

Fixed by an invariant rather than a bigger number: `Sampler::pin` protects exactly the one skeleton the engine has
already committed to needing (`awaited_body`), and the driver pins it every tick. The flood defence the cap exists for is
untouched — pinned by `pinning_protects_exactly_one_entry_and_not_the_cap`, and the defect itself by
`the_awaited_skeleton_survives_a_flood_of_later_proposals`; both verified load-bearing by disabling the pin.

### [A] Also closed on the way: a shard was only ever asked of its custodian
`request_shards` addressed shard `i` solely to validator `i`. Correct while dispersal worked — but a validator reaches
that recovery path *because* it did not, and then every custodian is as empty as the requester. Now the block's
**proposer** is asked too: the one peer that built the block and can regenerate any index, a deterministic address
rather than the blind rotation that preceded it (which itself replaced a whole-cell broadcast measured strictly worse,
0 of 3 against 7 of 8).

### [A] Superseded: the residual stall is ONE straggler that knows it is behind
The probe changed the picture completely. The current residual failure reads:

```
v0..v5 : 1000/None      h8r3                    ← six validators succeeded: recipient paid, contract resolved, height 8
v6     : 0/Some(Locked)  h1r13 behind(2) await   ← one stuck at height 1
```

Six of seven complete the whole scenario. The failure is a **single straggler**, and it is not confused: `behind(2)`
means its own `max_seen_height` exceeds its height, so it knows the cell moved on, and `await` means it is waiting on a
body. So the question is no longer "why does consensus not progress" — it does — but **why catch-up does not run for a
validator that has already detected it is behind**. Candidates, in order:
- **its `max_seen_height` is 2 while the cell is at 8** — and this is almost certainly the answer. `note_height` fires
  from proposals, votes, skeletons and exec-votes alike, so a validator receiving *any* current cell traffic would
  record 8. Recording 2 means it heard nothing above height 2 for the remaining ~200 s. It is not failing to ask; it
  cannot hear the answer. That points at the overlay/transport — a node that stops receiving — not at consensus, and
  not at the catch-up protocol, which asked exactly as designed. Ruled out along the way: the `SyncResp` snapshot
  exceeding a frame (`MAX_FRAME` is 1 MiB, the test ledger is orders of magnitude smaller).
- `certified[1]` is pruned on every peer once a checkpoint forms above it (`prune_sync_retention`), so the
  `CommitCert` answer is unavailable and only `SyncResp` can serve it;
- `awaited_body` may be occupying the validator ahead of the sync path.

### [A] Superseded: the residual stall is *not* the lock split — both healing changes measured neutral or worse
The lock-split mechanism is now fully addressed and **neither half moved the live rate**, which is the finding:

| change | interleaved A/B | verdict |
|---|---|---|
| `Block::pol` — a locked validator may re-offer its value, any proposer carrying the certificate is heard | 3 of 6 failing → 1 of 8, but measured sequentially | improvement plausible, not A/B-confirmed |
| `valid_value` — a polka is recorded on *observation*, so an unlocked proposer offers the prepared value | **5 of 6 vs 4 of 6** | neutral; kept on correctness grounds, not performance |
| suppressing the round-timeout backoff while a re-offer is held | **0 of 4 vs 2 of 3** | **regression, reverted** |

So after both healing changes the failure rate is where it was, and the cause must be re-established rather than assumed.
The `rejects.locked`-only signature that motivated all of this was captured *before* them; nothing since has re-read the
counters on a current failure.
- **Done, and the counters had moved.** On a current failing run: **501 `proposer`**, 3 `locked`, 3 `link` — where before
  the fixes it was `locked` and nothing else. All seven validators at height 1; 130 proposals carrying a PREPARE proof for
  height **0**. The residual was a *proposal storm of my own making*: `can_reoffer` let a validator that had not yet
  advanced re-offer its value once per round forever, and every peer past that height refused it as a proposer-entitlement
  violation. Fixed by the guard the lag signal already made available — a re-offer is sound only while no peer is known to
  be ahead (`max_seen_height <= height`), since past that point the refusal is by construction. Side effect: the
  consensus simulator's own runtime fell from 92 s to 39 s, the same storm.
- The investigation also surfaced a genuine gap, now closed and pinned: a validator short of a height's COMMIT quorum
  could be rescued only by a **newer block** (`adopt_certified_parent`) or an execution **checkpoint** (`SyncResp`), and
  neither reaches a validator whose proposal deliveries fail in a cell too young to have checkpointed. `ConsensusMsg::CommitCert`
  answers its catch-up request with the quorum certificate itself — the retransmissible form of the votes TAXIS never
  retransmits. This required `finalize` to *retain* the certificate it collects rather than consume it, because
  `collect_cert` filters by the current round and height: finalization is the only moment at which it can be captured.
- Keep the two changes regardless: both are standard consensus rules that closed real gaps (a locked value that only its
  original proposer could re-offer; an observed polka that no unlocked proposer could act on), and neither regressed.

### [A] The lock-split healing, for the record
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

### [A] Store placement is a successor rule over a *per-node, time-varying* occupancy set
A value written before a membership change can become **unreachable**, not merely slower to find. Located 2026-07-28 while
chasing the C ABI flake, and it explains a class rather than one test.

`OverlayNode::responsible_point(key)` is `nearest_occupied(ideal_index)` — the first *occupied* point at or after the key's
ideal index, wrapping around. And `occupied_points()` is **this node's current view**: itself, peers it has heard from, and
announced members. So:

- A hosts a service and publishes its descriptor while its view is `{A}`. A is therefore responsible for every key, and
  stores it locally; no shard goes anywhere else, because there is nowhere else it knows of.
- B joins. Both views become `{A, B}`. A key whose ideal index falls between them now resolves to **B**, which never
  received it.
- B's `Get` asks the point its own view names, finds nothing, and reports `NOTFOUND` — for the full 30 s of the C ABI
  test's retries. Measured: 1 run in 10.

The design accepts view-dependence deliberately (`occupied_points`' own doc: "a never-occupied point is simply absent; a
heard-then-crashed occupant is handled downstream by `routed_send`'s reroute"), and on a converged cell every view agrees
so the rule is consistent. The gap is the *formation* window, and a sparse cell is permanently in it — the C ABI example
is two nodes on seven points, which is what an embedder following that example gets.

- **Erasure shards do not cover it.** They are placed at per-point homes *as the writer understands them*, so a write made
  under a one-node view leaves nothing to reconstruct from.
- **The bounded fix is a read fan-out**, not a re-placement: a `Get` that misses at the computed home tries the next
  occupied successors, bounded by the cell size. That is how a DHT normally absorbs view skew, it needs no write-side
  bookkeeping, and it is cheap on a cell of seven. Re-placing on every membership change is the alternative and is much
  more invasive.
- Worth checking whether this is also behind the mix-directory and rendezvous-descriptor flakes seen elsewhere in this
  list — all three are "a value published by one node, read by another, intermittently absent".

### [A] The verification gate itself is load-sensitive — one flake per full-workspace run
Measured twice on the current tree with `cargo test --workspace --features validator`:
- 43 suites, **756 tests, one failure** — the HERMES contract, all seven validators frozen at the lock height.
- 45 suites, **759 tests, two failures in one suite** — the HERMES contract *and* `a_private_transfer_executes_over_live_
  consensus_end_to_end`, which had never failed before. Immediately afterwards, `dromos_quic` alone passed **3 of 3
  twice** (53 s, 38 s).

- 45 suites, **761 tests, one failure** — the HERMES contract only, *after* `anonymous_quic`'s five cell fixtures were
  serialized. That suite failed **4 of 5** in the first run and passes inside the workspace run here for the first time.

So the count grows with what else shares the machine, and the suite that fails is whichever real-QUIC one the contention
lands on. The one intra-binary cause that *was* fixable is fixed: `anonymous_quic` was standing up to thirty-five real
QUIC nodes concurrently, and serializing them cost nothing in wall time. The remaining failure is the sub-quorum
lock-split residual at its known ~1-in-8 rate, so a single occurrence in one run is expected rather than informative.
- What is left is genuinely external: this host's load is set by a neighbouring project's build and moves by an order of
  magnitude within minutes. The lighter two-node fixtures (`diaulos_quic`, `exit_quic`, `proxy`) still run concurrently by
  design — a two-node setup is not a cell — and no measurement implicates them.

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

### [A] The C ABI example is the most contention-sensitive path — folded into the load item below
**Not a separate defect.** Every layer under it has been exonerated, each by measurement rather than inspection:

| layer | how it was cleared |
|---|---|
| descriptor publication | the readiness point (`fanos_join`) removed those failures entirely |
| store lookup | bounded by `STORE_TIMEOUT`; the unbounded await *was* the 34-minute stall, and is fixed |
| `offer` dropping a payload | the counter it now exposes reads **0** on every failure |
| session + reliable stream | `a_sub_segment_write_is_never_lost_across_the_session_pair` — 200 clean in-process rounds |
| interactive streaming over QUIC | `an_interactive_write_without_half_close_reaches_the_peer` — 8 of 8, a shape nothing covered before |
| the accept-queue indirection | `an_accepted_stream_taken_from_a_queue_receives_an_interactive_write` — 8 of 8, same queue-and-guard shape, one runtime |
| runtime worker count | refuted by interleaved A/B (2 → 6/8, 4 → 8/8 under identical load); only the single-worker case was real, and is fixed by a floor of two |

What remains is that the example runs **two full node stacks, two multi-threaded runtimes, and a parked caller thread in one
process** — the most contention-sensitive arrangement in the repository — and its failure rate tracks host load exactly as
the workspace suites' does. In the last interleaved batch, at load 13–19, it passed 8 of 8. Treat it as an instance of the
load item, not as its own mystery: the same fix (bounding concurrency for transport-bound suites) covers it, and no
layer-specific hypothesis has survived a controlled comparison.

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
