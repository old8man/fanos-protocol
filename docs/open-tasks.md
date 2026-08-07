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

### [A] The homeostat has a derived setpoint and does not steer to it
`Homeostat::control` (`homeostat.rs`) returns `Hold` for any mean correlation inside `collective_subject_window`, i.e. any
`Φ ∈ (1, 2]` — a range across which the stability radius varies **8.58×** (`0.0171` at `Φ = 1.1` against `0.1466` at
`Φ = 2` on a Fano cell, in the exact metric; `8.49×` and `0.1450` in the runtime one). A cell can sit a hair above the
collapse boundary, be told it is healthy, and absorb an eighth of the disturbance it could. In the runtime form the
ratio is exactly `(√2 − 1)/(√1.1 − 1)` and therefore **the same on every plane** — the scale factor `K/√N` cancels in
it, as it does in the setpoint below.

The setpoint is **derived** (`fanos_diakrisis::minima::OPTIMAL_INTEGRATION`), and in band coordinates the derivation is
one line. The runtime radius is `r_stab = K(N)·(√Φ − 1)/√N` with `K(N) = √N·⁴√(N−1)/(2√(N−2))`, so the distance down to
collapse is `∝ √Φ − 1` and the distance up to the ceiling is `∝ √2 − √Φ`. **The scale factor `K/√N` divides out**, so the
max-min point equalises the two brackets and is the same on every plane:

```
√Φ − 1 = √2 − √Φ   ⟹   √Φ* = (1 + √2)/2   ⟹   Φ* = (3 + 2√2)/4 = 1.4571067811865475
```

Notably **not** the midpoint `Φ = 3/2` — but only just, and the reason matters (below). One clean consequence worth
asserting: since the setpoint equalises the two distances and they sum to the ceiling, `r_stab(Φ*)` is **exactly half**
`max_stability_radius` — `0.0725` against `0.1450` on a Fano cell, and at every `N`. That identity is exact in the
**runtime** metric, which is the one Φ\* is the max-min point of; against the exact metric it holds to `0.9 %`
(`0.0726` against half of `0.1466`), inside the runtime form's stated ≤1.13 % budget.

> **Corrected 2026-08-07 (#183).** This section derived `Φ* = 5/4`, `P* = (9/4)/N`, `r_stab* = 1/(2√N)` from
> `r_stab = √(P − 2/N)` and a metric `ds = dP/(2√(P − 2/N))`, and quoted a **3.16×** spread across the band. That radius
> formula was refuted — it overstates the margin by up to 81.7× at the viability wall. The old derivation's load-bearing
> sentence was that the metric is *singular at the lower boundary*, so equal distance in `Φ` is not equal distance in the
> geometry. **That singularity was an artefact of the surd**: the true radius is linear in `ε = P − 2/N` near the wall, so
> `ds` is constant there. The conclusion survives in weakened form — `1.4571` is still not `1.5` — but the singularity was
> doing most of the work, and the setpoint moves up by `0.207`.
>
> The cost of having held the old value: at `Φ = 5/4` the true margin is `0.0413` against `0.1466` available at `Φ = 2`,
> so the homeostat was aiming at **28 % of the robustness the band affords** while believing it was at the max-min point.

The closed form above is exact; `OPTIMAL_INTEGRATION` should be *computed* from it rather than typed as a decimal, since
the hand-written literal is 2 ULP off the true value.

**What remains is the control change, and it should be evidence-gated.** Teaching `control` to nudge toward `Φ*` inside
the band replaces a dead zone with a proportional term, which can oscillate; it needs a closed-loop experiment showing a
cell held at `Φ*` survives a flood that one left at `Φ = 1.1` does not, before it goes in.

**Check before working:** `control` should still return `BandControl::Hold` unconditionally for
`CollectiveState::CollectiveSubject`, and `OPTIMAL_INTEGRATION` should still have no caller outside its own tests.

### [A] Anonymity cannot leave its cell, and that is what forces the robustness trade-off
`fanos-aphantos` is parameterized by a single field `F` throughout. The threshold onion routes over hop **lines of one
plane** (`threshold_onion.rs`, `hop_lines: &[Triple]`), NOSTOS picks a dead-drop from the `q+1` lines through a point of
that same plane (`nostos.rs::select_drop_line`), and `HierAddr` — the hierarchical address that would name a coordinate in
another cell — appears **nowhere in the crate**. So an anonymous circuit is confined to its cell and the anonymity set is
the cell, not the federation.

**The cost of not having it is smaller than this item once claimed.** An earlier version priced raising the plane order at
"a 12× robustness cost", from `r_stab = 0.378` at `N = 7` down to `0.032` at `N = 993`. That compared absolute radii
without normalizing by the disturbance, which scales the same way: `fanos_diakrisis::minima` result 6 derives that the
tolerated fault fraction is `1 − 1/√2 ≈ 29.3 %` **at every cell size**, so a `PG(2,31)` cell absorbs 291 simultaneous
failures where Fano absorbs 2. Raising `q` for anonymity is free in fault tolerance; its real price is coordination
(a quorum of 662 of 993, quadratic in messages).

So federation is not needed to escape a robustness penalty — there isn't one. What it would buy is an anonymity set at the
union rather than per cell, and graceful degradation past the fault threshold (`f = 3/7`: one cell 11.4 %, three federated
cells 1.6 %). Worth having, not urgent.

**Check before working:** `grep -rn "HierAddr" crates/fanos-aphantos/` should still return nothing, and
`threshold_onion.rs`'s hop unit should still be a flat `Triple`. Design authority: `docs/design-anonymity-substrate.md`,
numbers in `docs/deployment-minima.md`.

### [A] Close the "libraries ahead of wiring" gap — four items, measured and guarded
The list is now computed, not remembered: `fanos-cli/tests/architecture.rs` takes the closure over the manifests and fails
if a crate is linked by nothing (or if a listed orphan gets wired). **36 of 43** crates sit in the node's closure and
**40 of 43** are reachable from some shipped binary (2026-07-30; the test holds these numbers and is the authority — the
figures written here had already drifted to 34/38). The earlier prose version of this item was wrong in two thirds of its list — see
`docs/audit-2026-07-27-architecture.md` §2.1 — because it grepped for crate names where the crate is reached through an
intermediary. What genuinely remains:

**The orphan half of this item is closed.** `ORPHANS` in that test is now **empty** and its ratchet is at 0:
`fanos-angelos` is a dependency of `fanos-node` (`fanos message serve`) and `fanos-ergon` became reachable through
`fanos_dromos::ergon_host` + `TAG_ERGON` on 2026-07-30. Both rows that used to stand here were stale — the angelos one
said "linked by nothing at all" while the crate sat in the node's manifest, which is the second time this table has
outlived its subject.

**And the coverage half is closed too — 2026-07-30.** `fanos-vpn/tests/datapath.rs` exercises `run_fulltunnel` end to
end with no TUN and no root: it is generic over both edges, so a `tokio::io::duplex` stands in for the device and a
recording dialer for the exit, and a real IPv4/UDP datagram written to the device arrives at the exit **addressed to its
own destination** — the property that distinguishes a tunnel from a proxy. Falsified two ways: dialing a fixed address
instead of the flow's, and dropping UDP flows at the accept loop.

What is left is `device.rs` alone — the TUN **syscalls**, which genuinely need root and a device. The crate's feature
comment used to lump the syscalls and the stack together as "runtime-verified only", which is how the full-tunnel claim
came to rest on untested code; it now says which half is which.

The distinction this item turned on is worth keeping: a **linkage** gap is computable from the manifests and the
architecture test catches it, while a **coverage** gap — "is this code ever run" — is not visible to it at all.
`fanos-bench`/`fanos-ffi`/`fanos-wasm` are embedding surfaces and exempt by construction.

### [A] ~~Decide whether `InsufficientFunds` is premature~~ — DECIDED: it is not
The sweep is otherwise done. `ExecOutcome::Deferred` now covers every order-dependent case in
`HybridLedger::apply_with_verdict` that has an **identifiable pending prerequisite**: a transparent nonce ahead of its
account, an HTLC claim/refund ahead of its lock, a storage prove/close ahead of its open, and the funding transfer of a
shield, a name operation, an HTLC lock and a storage open (`TokenLedger::is_premature`). The shielded path needs nothing —
its rolling anchor window accepts any recent root and no wallet can prove membership against a root that does not exist.

**DECIDED 2026-07-30: do not defer on balance.** The item said this needed the spam-cost model; it does not, because the
decision turns on **agency** rather than on the cost's magnitude, and that is settled by one fact in the code.

`TokenLedger::apply_with_verdict` returns `InsufficientFunds` *before* the nonce bump, so a rejected transaction **does
not consume its sender's nonce**. The identical bytes can therefore be resubmitted the moment funds arrive. Compare the
nonce-ahead case, where deferral is load-bearing: that transaction is waiting on the sender's **own earlier**
transaction, already in flight, and resubmitting cannot help because the prerequisite is temporal rather than the
sender's to supply.

So the two cases differ in exactly the respect that matters. Deferring a balance failure buys convenience the sender can
supply themselves; it costs re-consumed block space for up to `REVEAL_WINDOW = 4` blocks — a 5× amplification of a spam
flood — with no fee to price it, since ERGON is gasless.

**And this sharpens the project's own rule.** "Premature iff re-executing unchanged against a later state could succeed"
is *necessary* and not sufficient: a balance failure satisfies it too. The criterion that separates them is

> **Defer iff the prerequisite is one the sender cannot supply by resubmitting.**

which keeps every case the sweep already deferred (a nonce ahead of its account, a claim ahead of its lock, a prove ahead
of its open, a funding transfer) and excludes this one. Worth having as the rule, because the weaker version would have
argued for deferring here.

Two rules the sweep established, both worth keeping:
- A rejection is premature **iff re-executing the transaction unchanged against a later state could succeed.** Replay,
  double-spend, bad signature, malformed bytes never can; a missing prerequisite can.
- **Deferral is a last resort, not a first check.** The check must run *after* everything a handler can judge on its own,
  or a transaction that is both malformed and premature gets deferred — wasting `REVEAL_WINDOW` blocks before being
  dropped anyway. The first version had it backwards and the existing storage suite caught it; the ordering is now pinned
  by `a_transaction_that_is_both_malformed_and_premature_is_rejected_not_deferred`.

### [A] Convergence for the two-round HTLC scenario spans 35 s to >300 s — the "flaky test" is that tail cut by a 240 s ceiling

**Re-titled 2026-07-30, and the reframing is the finding.** Twelve single-test runs were measured with their durations,
and the durations settle what a year of rate-counting could not:

| | seconds |
|---|---|
| passes | 35.3 · 35.5 · 89.5 · 168.6 · 228.2 |
| failures | 245.4 · 247.2 · 263.0 · 300.8 |

**There is no gap.** The pass distribution runs continuously to 228 s and the failures begin at 245 s — which is the
harness's own 240 s ceiling. So the failures are the right tail of one continuous distribution, cut by the clock, not a
distinct wedge. The harness has been saying so in its own verdict string all along: *"INCONCLUSIVE — still changing at the
240 s ceiling, so this is latency rather than a wedge."*

**And load does not drive it**, which had been the standing hypothesis: pass loads mean 10.30, failure loads mean 11.45,
the **lowest-load run of the batch failed** (6.87) and the highest-load pass was at 15.23. Failures and passes interleave
across the whole range.

Two consequences, and the second is why the title changed:

1. **Every previous "root cause" was real and none of them was the cause of the *rate*.** Round synchronization, the
   unlocking rule, nil votes, custodian targeting, the proof-of-lock, the body-recovery rung — each shaved latency off a
   long tail rather than removing a wedge, which is exactly what a tail predicts and what the measurements showed (a rate
   that never clearly moved).
2. **Raising the ceiling would make the test pass and hide the real problem.** An HTLC claim on a seven-node loopback cell
   taking four minutes is bad regardless of any test, and 35 s → 300 s is an **8× spread** with no adversary, no
   partition and no crash. That spread is the defect; the red test is a messenger.

**The 8× is the round-timeout ladder, quantitatively — 2026-07-30.** `ROUND_TIMEOUT_BASE` is 1.5 s doubling to a
`ROUND_TIMEOUT_MAX` of 24 s, so the cumulative wait for `r` rounds at one height is 1.5, 4.5, 10.5, 22.5, 46.5, then
+24 s each. The observed durations land on that ladder:

| observed | verdict | nearest cumulative | off by |
|---|---|---|---|
| 89.5 s | pass | r7 = 94.5 s | 6 % |
| 168.6 s | pass | r10 = 166.5 s | **1 %** |
| 228.2 s | pass | r13 = 238.5 s | 4 % |
| 245.4 s · 247.2 s | fail | r13 = 238.5 s | 3–4 % |
| 263.0 s | fail | r14 = 262.5 s | **0 %** |

The two 35 s runs sit below r5 and are better read as a couple of rounds spread over the scenario's two heights. Every
slow run matches within a few percent, and the failing traces' round numbers agree independently — `h1r13`, `h2r12`,
`h1r8`, `h3r9`.

So the time is spent **waiting on a clock, not on the network**: each failed round past the fourth costs 24 s of pure
idling while the transport is loopback with sub-millisecond latency. The cap is tuned for a WAN. The 8× spread is
therefore 1–2 rounds against 12–14, at 24 s apiece.

That splits the item into two questions, and the second is the one that was hiding:

1. **Why does a height sometimes need twelve rounds?** The traces are the instrument for it, and this is what task #27
   captures.
2. **Should one failed round cost 24 s on a sub-millisecond transport?** Tendermint-style backoff exists to adapt to real
   latency, and here it adapts to none: the ladder is a fixed schedule that ignores the observed round-trip time entirely.
   A cap derived from measured latency rather than assumed WAN conditions would turn a four-minute recovery into a
   sub-second one **without touching consensus logic** — and would leave the r12 question exactly as visible, since the
   round count is what the probe reports.

**The twelve-round mechanism, from a fresh trace — 2026-07-30.** Captured post-`270aef8`, so the old
`PARKED@1 ccrej[park=1963]` wedge is closed and this is the current cause. All seven validators at height 1, in **four
different rounds** (r9, r9, r10, r11, r12, r12, r12), each awaiting a **different** body (`7736f246` ×3, `49d97a60`,
`e2a409d3`, `60410e05`, `892121ac`). Nobody locked, no `PARKED@`, no `sync=` (nobody thinks itself behind), DA healthy
(shard serve 96–100 %, `took` in the thousands). One reject kind only: `rej[prop=36…155]` per validator, and zero
`link`/`structure`/`lock`/`last_commit`.

`ConsensusProbe::awaiting_body`'s own documentation reads that for us: *"A cell in which every validator awaits the same
block is one whose body never reached anyone — a dispersal failure. A cell in which each awaits a different one is not
stuck on a body at all; it is failing to converge."* Four distinct hashes ⇒ convergence, not availability.

**And the gate explains it.** `on_propose`'s check is

```rust
let proposer_ok = pol_ok
    || if sortition_round0 { is_line_member(seed, height, 0, proposer) }
       else { leader(seed, height, self.round) == block.header.proposer };
```

`sortition_round0` is true only while `self.round == 0`. So: under SSLE every line member proposes at round 0; ranking
picks a min-ticket winner but its **body must be recovered** through DA, which takes seconds; if round 0's quorum has not
formed in `ROUND_TIMEOUT_BASE` = 1.5 s everyone advances; and a round-0 body arriving at a validator now in r5 is checked
against *r5's* leader, which it is not. Refused, `rejects.proposer`. A `pol` cannot rescue it either — a POL is attached
when a proposer **re-offers a locked block**, and the trace shows nobody locked.

So round-0 proposals become permanently inadmissible the moment round 0 ends, and the cell must wait for a round whose
leader both proposes *and* gets its body distributed inside that round's window. At 24 s per round past the fourth, that is
the r9–r13 tail and the minutes.

**This is the theory withdrawn earlier — and it was withdrawn for the wrong reason.** The withdrawal was right that
skeletons route to `on_skeleton` and never reach `on_propose`. It was wrong to conclude the gate is never consulted:
**recovered bodies** reach `on_propose` through `admit`, and that is where it bites. The trace's 36–155 proposer rejects
with no other kind is the evidence that was missing then.

**Candidate fix, stated as a hypothesis because a plausible one here already passed 132 tests and was still wrong:** the
round-0 winner is chosen by *ticket ranking*, not by the leader rota, so asking `leader(seed, h, self.round)` about it is
the wrong question. Keeping the ranked round-0 winner admissible at later rounds is the targeted change. The experiment
that would confirm it is not "the test passes": it is that the **round spread collapses** and `rej[prop]` falls to near
zero in the probe. Anything less could be the ladder's own variance.

So the question to work is *why the two-round scenario's convergence varies 8×*, not *why a test is flaky*. The
`ccrej[h/v/park]` and `PARKED@` counters are in place for it, and the next capture must keep the trace — the batch above
grepped only `test result` and threw away the instrument's output, which is the second time that mistake has cost a run.

**Process note kept from the old title:** the gate question is separate and already decided below — `#[ignore]` is the
wrong instrument, because that class is defined by cost and this is not a cost problem.

### [A] ~~A ~1-in-4 test sits in the per-push CI gate~~ — the gate half
`a_hash_locked_contract_is_funded_and_claimed_over_live_consensus` is **not** `#[ignore]`d, so it runs in the `gate`
job on every push, where it fails both under full-workspace loopback saturation and — at a lower rate — in isolation.
A gate that fails this often blocks merges at random and trains people to re-run rather than read.

**Re-measured across 15 isolated runs, 2026-07-29 and 07-30:** 4 failures, so roughly **1 in 4**. The two
batches disagree — 3 of 6 on 07-29 at host load 6–9, then 1 of 9 on 07-30 at load 4.7–9.6 — and Fisher's exact
gives `p ≈ 0.11`, so **neither "the rate fell" nor "load drives it" is established**. The single 07-30 failure
did land at the highest load observed (9.56), which makes load-sensitivity plausible and not more than that.

**`#[ignore]` is the WRONG instrument here, and that is a decision — 2026-07-30.** The obvious remedy is to mark it
`#[ignore]` so the nightly `heavy` job takes it, and three multi-node real-QUIC tests already live there. But
`fanos-cli/tests/ignored_tests.rs` defines the class precisely and holds the workspace to it: `#[ignore]` means either a
**measurement** (prefixed `measure_`/`probe_`/`sweep_`, never gates) or a **cost-gated assertion** listed in `COST_GATED`,
whose stated criterion is *"reliable in isolation, unreliable when a full-workspace run saturates the loopback"*.

This test fails **3 of 7 single-test runs**. It is not reliable in isolation, so it does not meet the criterion — the class
is defined by *cost*, not by flakiness. Moving it there would make a nightly gate fail a quarter of its nights and would
corrupt a check that currently proves something exact. A well-defined policy is worth more than the convenience of
reusing its attribute.

So the options are the two real ones: **fix it**, or **add a quarantine class** — distinct from cost-gating, with its own
list and its own meta-test, for a test that must run and whose failure must not block. The second is a policy change and
should not be smuggled in as an `#[ignore]`.

**Also corrected:** `.github/workflows/ci.yml`'s comment read as though every multi-node real-QUIC path is `#[ignore]`d.
Three are; the whole `fanos-node` e2e suite (`dromos_quic`, `taxis_quic`, `anonymous_quic`, `exit_quic`,
`mix_directory_quic`, `diaulos_quic`) is not, and runs per push. Verified by counting the attributes rather than reading
the comment.

**That figure measures a tree that no longer exists**, and the distinction matters more than the number: every run
above predates `270aef8` (the body-recovery rung — a validator holding a certified decision now asks a certificate
voter for the block, where before it parked the decision forever) and `1fa8edc`. A rate is a property of a
particular tree, so quoting it against the current one would be quoting a measurement of something else. The
post-fix sample so far is **6 passes and 1 failure in 7 runs** — too small to distinguish from either 1-in-4 or
from fixed, which is exactly why it is written as a count and not as a rate.
The earlier "1 in 8" and the intermediate "1 in 3" were both over-precise for their samples; quote the run count
with the rate or do not quote it.

**Original 07-29 measurement** (`cargo test -p fanos-node --test dromos_quic a_hash_locked --features
validator`, one test alone, host load 6–9): **pass / pass / fail at HEAD**, and fail / pass / fail with an unrelated
observational change applied — statistically indistinguishable, which is how that change was cleared. The rate is
therefore around **one in three, not one in eight**; the older figure is stale and was the reason a single passing
baseline run looked like exoneration. Two conclusions follow: a lone HEAD run proves nothing about this test, and the
underlying data-availability defect has not been improving.

The repo's own convention would move it: two sibling real-QUIC tests are `#[ignore]`d into the nightly `heavy` job for
exactly this reason, with the rationale written down. **Deliberately not doing that yet.** Ignoring it would convert a
known liveness defect into an unobserved one, and the defect is real — it is the thread that produced the sampler
eviction fix below. The honest options, in preference order:
1. keep hunting until the isolated rate is zero, then the saturation question is CI tuning rather than cover;
2. if it must move, move it *with* a recorded isolated failure rate, so nobody later reads `#[ignore]` as "flaky, safe".

Whichever way it goes, it is a decision to make explicitly rather than by attrition.

**Process note for the next investigator:** the failure message carries the whole `ConsensusProbe` trace, which is the
diagnosis. Do not filter test output through `grep -E "FAILED|^---- "` — that drops exactly the line worth reading.

The probe now also carries `skel=served/asked` (`ConsensusEngine::note_skeleton_ask`), which separates two failures the
trace could not otherwise tell apart: a cell whose skeleton requests never arrive, and one where they arrive and nobody
holds the block. `await:<hash>` looks identical in both and they need opposite investigations.

**And `shard=served/asked took=N sent=M` one layer down (2026-07-30),** because the skeleton counter answered its own
question and pointed past itself: requests arrive in thousands and are served (one validator answered 3461 of 3461), so
what is missing is the *shards*, which `skel=` cannot see. Three counters rather than one, because a single number
conflates three different investigations — `asked = 0` is a request-side failure, `served = 0` a holder-side one, and
`asked > 0, served > 0, took = 0` means replies are produced and then lost or refused.

Two things the instrument settled immediately, before any failing run:

- **`sampling=x/64` is not a sample fraction.** It is `Sampler::in_flight()` against `PENDING_CAP` — blocks being
  reassembled, not shards gathered. `sampling=1/64` is *healthy*, and a healthy passing run shows three of seven
  validators ending on `await:<hash>` with `sampling=1/64`. Neither `await` nor a low `sampling` is a failure signature;
  earlier readings that treated them as one were reading a capacity as a shortfall.
- **The healthy shape**, from a passing `a_private_transfer` run: `shard=402/402 took=1052`, every validator nonzero,
  serve rates 97–100 %. That is what the counters read when nothing is wrong, which is the only way a failing trace means
  anything.

Validated before use, per the rule this test taught: each clause of the new assertion in
`a_private_transfer_executes_over_live_consensus_end_to_end` was falsified by disabling the mechanism it claims.
`shard_asks` dies when `request_shards` is a no-op; `shards_sent` dies when the dispersal `Emit` is removed. But
`shards_taken` does **not** die when dispersal is removed — the test stays green — so it counts *any* accepted delivery,
dispersed or sampled, and the assertion no longer claims otherwise. The first draft's comment did claim it, which is the
whole reason to falsify clause by clause rather than run the suite once and believe it.

A side measurement worth keeping: with dispersal removed the cell still commits, once in 9.4 s and once failing at
94.9 s. So proposer dispersal is not load-bearing for correctness at q = 2 — sampling recovers what it did not send — and
its absence shows up as *flakiness*, exactly the shape being chased. Nothing tested dispersal at all before this.

**And never let a pipeline decide whether the gate passed.** `cargo test … | grep …` reports *grep's* exit status, so a
run ending `error: test failed` was reported as exit 0 and nearly shipped. Run the gate bare, `echo $?` on its own, then
read the detail in a separate call.

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
   `AdmissionController::observe`.

**The open question is answered, and the answer is that no machinery is needed.** "What stops a node that
mis-measures its stress from closing the network?" — the shape already does. Admission is decided by *each peer
for itself*: `members` is one node's own view and `Announce` is flooded to all of them, so a peer whose sensor is
wrong, or which is simply hostile, shuts its own door and no one else's. A joiner refused by one is admitted by
the rest. Pinned by `one_peer_pricing_a_joiner_out_does_not_exclude_it_from_the_cell`.

A quorum on the admission price would have bought that property at the cost of a new consensus to reach, a new
thing to capture, and a new way for the cell to stall.

Weighed and rejected as a *substitute*: carrying the price in the pre-announce exchange. It is a fine
optimization — the joiner solves right the first time — but the price can change between learning it and
announcing, so the retry path is needed for correctness regardless. An optimization on top, not instead.

### [A] Operator surface — the control socket closes the read half; the monitor is still next
`fanos status` now asks the **running node** over a local Unix socket (`admin.sock`, mode 0600 in the state
directory) and reports what the node itself sees: coordinate, peers, verified claims, probe index. Verbs are
`ping | health | roles | shutdown`. Filesystem permissions are the authentication — the control plane is not
addressable from the network at all, which is the property that matters for a process whose job is accepting
traffic from strangers.

**But the socket belongs to one subcommand, not to the node** (found 2026-07-30 while looking for somewhere to surface
the consensus probe; the first reading of it was "the validator lacks a verb", the second "the validator lacks a
socket", and both were too small). Counted across every command in `bin/fanos.rs` that runs until ctrl-c:

```
cmd_node       long-running   admin::serve = 1
cmd_proxy      long-running   admin::serve = 0
cmd_host       long-running   admin::serve = 0
cmd_vpn        long-running   admin::serve = 0
cmd_validator  long-running   admin::serve = 0
```

Four of the five roles anyone actually deploys — the anonymous proxy, the hidden-service host, the VPN datapath and the
consensus validator — expose **no control channel at all**: no `ping`, `health`, `roles`, `census`, and no clean
`shutdown` except a signal. `fanos status` against any of them always takes the "fall back to the config" branch its own
startup message describes as the failure case. The one command that *does* have the socket is the one that runs no
chain, hosts nothing and carries no datapath.

The fix is not to paste the socket into four more `select!` blocks. Each command rolls its own run-until-shutdown loop,
which is *why* the socket sits in only one of them; copying it would put the duplication in five places and guarantee
the next role forgets. Extract the loop — bind, drain `admin_rx`, notifications, ctrl-c, unlink on exit — with a
per-role answer callback. Same seam as "collapse seven `spawn*` entry points into one builder" below; decide whether
that work absorbs this rather than landing twice.

Remaining, in order:
1. **The validator's control socket** — bind and drain it in `cmd_validator` exactly as `cmd_node` does, including
   the non-fatal stance (a node that cannot open a control channel is still a working node) and the unlink on exit.
2. **A `consensus` verb** — `TaxisHandle::probe()` has two callers and both are in `dromos_quic.rs`, so every field of
   `ConsensusProbe` is reachable only from a test binary. Each of those fields exists *because* a live cell was stuck
   and its state could not be read, which makes the operator of a stuck validator precisely the person who cannot get
   them. `probe()` is async ⇒ answer off the loop like `census` does; render with the existing `Display` rather than
   inventing a second format.
3. **`OverlayCoherenceSource`** — the observatory still watches a *simulated* cell. `read_coherence` has no caller,
   so nodes publish ε-private coherence frames that nothing consumes. The same `SnapshotSource` trait the live
   source implements is the seam; this is the last thing between the panel and a real deployment.
4. **`fanos node --metrics-listen`** — `render_openmetrics` exists and nothing serves it, so a deployment cannot be
   scraped. The control socket could carry it as a further verb, which needs no new listener.
5. **Coherence in `status`** — Φ/P/R belongs beside the peer count, and needs (3).

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

### [A] …and the rule works. The residual round split is a DELIVERY failure — 2026-07-30
The fix above is real, and the next trace showed the cell split across rounds anyway:

```
v0 h1r9 lock await:ec97cba9   v1 h1r8 lock await:fe9dbb89   v2 h1r9 lock await:fe9dbb89
v3 h1r8 lock await:fe9dbb89 jumped=1/1 above=0              v4 h1r8 lock await:ec97cba9
v5 h1r8 lock await:fe9dbb89   v6 h1r9 lock await:fe9dbb89
```

Four at r8, three at r9, every validator locked and **holding** its body, `rej[prop]` in single or low double digits
(3–18, against 19–257 in the pre-fix traces), no `rej[lock]`, no `rej[unavail]`, and 240 s with nothing finalized.
Neither group can finalize alone: `collect_cert` reads the votes of **one** round, so 4 < 5 and 3 < 5.

The decisive number is `above=0` on every validator. Reproduced deterministically
(`a_cell_whose_rounds_split_four_three_still_finalizes`): nothing dropped, crashed or partitioned — the only deviation
from a healthy cell is one extra timer firing on three of seven, which is not a fault. `timeout_some` is what makes it
expressible; cell-wide `timeout` held every validator in one round by construction, the one arrangement in which drift
cannot occur.

**The offset does not survive the drain.** The three that advanced re-prepare their lock at the new round, those
PREPAREs reach the four that stayed, `f + 1 = 3` peers are visible above, and `maybe_advance_round` closes the gap
inside the same delivery. Falsifying it — disabling the rule — freezes the sim into the live shape exactly, with the one
difference that is the finding:

```
sim, rule disabled:   v3 h0r0 lock votes=0<6=3> above=3    ← the evidence is present, the rule is not acting
live, 240 s stall:    v3 h1r8 lock              above=0    ← the evidence never arrived
```

A genuine 4/3 split **must** show `above=3` on the laggards. The live cell shows 0, so the votes that close the gap are
not being delivered, and the engine is not the defect. That is a transport claim and only a counter can make it, so the
vote path now has one: `votes=<below>‹<equal>=<above>› oh=<other height>`, counted after authentication and before
storage, peers only (our own votes are echoed back through the same path and would guarantee a non-zero). Paired with
`voters_above` it separates "never arrived" from "arrived and lost before the buffer" — three readings of this path
deduced the answer and all three were wrong.

**CORRECTED by the very counter that was built to test it.** The capture came back and the delivery reading is wrong:

```
v0 r10  votes=31<27=0> oh=0  rej[prop=71]  skel=   3/1749
v1 r10  votes=32<31=0> oh=6  rej[prop=31]  skel=1061/2388
v2 r9   votes=31<33=0> oh=6  rej[prop=48]  skel=1191/2391
v3 r9   votes=30<37=0> oh=5  rej[prop= 6]  skel=2561/2561
v4 r8   votes=30<18=0> oh=6  rej[prop=28]  skel= 282/1340
v5 r9   votes=31<26=4> oh=6  rej[prop=24]  skel= 977/2117
v6 r8   votes=21<18=0> oh=9  rej[prop= 5]  skel= 362/ 909
```

Votes arrive in the tens in both the below- and equal-round buckets, so nothing is dropping them. `above = 0` means the
cell advances rounds in near-lockstep — every vote lands at a peer that has already left that round — not that anyone is
unreachable. A one-sided reading of a single field cost a wrong headline; the second field is what corrected it.

**The real defect is upstream of rounds.** No validator prints `lock` in this trace: no value ever held a PREPARE quorum
at height 1, and the seven were chasing **four different bodies**. The correlation names the cause — `rejects.proposer`
against skeletons this validator could serve: 71 → 3 of 1749 (0.2 %), and 6 → 2561 of 2561 (100 %).

Entitlement is judged against the **receiver's** round, because the header carries none by design. Round
synchronization pulls a validator *forward* to its peers' round; nothing pulls one that has run *ahead* back. So the
validator furthest ahead refuses the most proposals — and it threw away their **bodies** too, which is a second decision
the first was never entitled to make. It then broadcast `NeedSkeleton` for the body it had just discarded, every tick,
to peers in the same state. Fixed by splitting the gate: validity gates admission, entitlement gates only the vote, and
`pending_finalize` resolves before either (a COMMIT quorum outranks the right to propose). Growth is bounded with no
chosen constant — an unentitled proposal is stored only if that proposer has no body at this height yet, so at most one
entry per validator per height. Pinned by `a_validator_that_ran_ahead_still_keeps_the_body_it_refuses_to_prepare` and
falsified by restoring the fused gate, whose failure prints the defect in one line: `await:1c350fe0 … rej[prop=1]`.

The confirming experiment for the admission fix was stated as **not** "the test passes" but "the round spread collapses
and `rej[prop]` falls to near zero", and that is what happened: `h1 r8–r10, rej[prop] 5…71` became `h3 r0–r2,
rej[prop] 6…11`, with above-round votes going from 0 on six of seven to 4…10 on all seven and the round-sync rule
visibly firing (`jumped=2/2 above=0`). 8/8 green against 4 failures in the previous 9 — P ≈ 0.5 % under the old rate.

### [A] The DA resample is a schedule, not a list — FIXED
`resample_pending` re-requested **every** missing shard of **every** pending block on **every** 150 ms tick, with no
backoff and no give-up; a `Sampler` entry leaves `pending` only by reconstruction, `prune_below`, or cap eviction, so a
block that cannot be completed at a stalled height was retried for the whole stall — `shard=7130/7130 took=5366` at one
height. The admission fix above shrank it at the source, but the retry policy was unbounded on its own terms.

Derived rather than tuned. A repeat is worth sending only if the answer could have changed, and exactly two things
change it: the proposer's dispersal finally reaching the peer we asked (the race retry exists for — bounded by one
dispersal sweep, so it resolves in the first attempts), or that peer obtaining the block another way (unbounded in time,
its probability decaying with every attempt already failed). Early dense, late sparse, which is **doubling**, with no
parameter to pick: `O(log t)` requests instead of `t` for a block that completes, completion delayed by under 2×, and
1600 sweeps turned into 17 for a block that never does.

That bound is why there is deliberately **no give-up rule** — at logarithmic cost an abandoned entry is not worth an
invented horizon, and `prune_below` plus `PENDING_CAP` already bound the map. The *gap* is capped instead, because
obtainability is not monotone: a peer that could answer nothing can answer **any** index the moment it reconstructs the
block itself. The cap is the cell's own progress unit — one round timeout in ticks — and the relation is asserted in
`fanos-node`, the only crate that can see both constants, because a derived constant with no link back to its
derivation is a magic number with a nice comment. Progress resets the schedule and only *real* progress does: a fresh
shard resets, a duplicate must not, or the interval sticks at 1 and the storm returns.

Live, five consecutive runs, against the scenario that was failing at the 240 s ceiling three commits earlier — the
columns are before the entitlement split, after it, and after this:

```
shard asks     1340…10435  →  626…2444  →  139…529
shards taken   1644…5855   →  667…1326  →  125…353
skeleton asks   909…2561   →    2…30    →  0 in most runs
convergence    240 s FAIL  →     44 s   →  7.1–8.9 s   (5/5)
```

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

The consequence is a loop, not a delay: once evicted the block leaves the sampler's request schedule (`Sampler::due`,
then named `outstanding`), so no shard is ever requested for it again; the driver sees the validator still waiting and
re-fetches the skeleton; the next round's proposals evict it again. Measured live as seven of seven validators at round
13 reporting `await` for a body none of them held.

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
validator that has already detected it is behind**.

**The leading candidate — "it cannot hear the answer" — is REFUTED, 2026-07-30.** The shard counters caught the same
failure with the traffic visible:

```
v0,v1,v2,v4 : 1000/None       h4r2                shard=8463/8779 … took=3390  sent=60
v5,v6       : 1000/None       h4r2 await:3de7398e shard=4112/4284 … took=7909  sent=48
v3          : 0/Some(Locked)  h2r12 behind(3) lock await:3a4474d5
              skel=0/564   shard=2012/2354  took=4773  sent=42  sampling=4/64
```

The straggler answered 2012 of 2354 shard requests, was asked for 564 skeletons, **accepted 4773 delivered shards** and
dispersed 42 of its own. It is in dense two-way traffic, so "a node that stops receiving" is not what this is. Note also
that six of seven finish while two of the six sit on `await:<hash>` — waiting on a body is normal and not a failure
signature, the same correction the `sampling=x/64` reading needed.

**What the code says, read against that trace.** The wedge is `finalize`: it requires the block *body*
(`self.proposals.get(&block_hash)`), and without it records the decision in `pending_finalize` and returns. Its comment
claims this "never wedge[s] permanently at this height (audit fix, HIGH 3)" **on the assumption that `on_propose`
eventually delivers the body** — which for a straggler two heights back is exactly what may never happen. So:

- the `CommitCert` answer hands the straggler the *decision* and not the body, and cannot free it on its own;
- `prune_sync_retention` drops `certified[h]` below the checkpoint height, so even that answer expires;
- `SyncResp` is the only mechanism that skips the body — it transfers executed state — and it is gated on an
  `ExecCertificate`, i.e. on a quorum of execution votes. Those are emitted on **every** executed block, and
  `capture_sync_snapshot` retains `(root, head)` per height, so at `h4` a peer should hold a checkpoint at `h3` and be
  able to answer a `have_height = 2` request.
- Everything is wired on the live path: `step_msg` maps `SyncReq`/`SyncResp`/`CommitCert`/`ExecVote`
  (`taxis_driver.rs:500–505`), the generic `TaxisApp::Consensus(msg)` arm routes them, `Output::SendTo` is emitted to the
  one peer, and `Input::Tick` calls `maybe_request_sync`. So this is not the unwired-capability pattern.

One asymmetry found while reading, which may or may not matter: `on_skeleton` returns before `note_height` whenever
`self.round != 0`, so a straggler that has timed out into a high round stops learning the cell's height *from
skeletons*. In this trace it learned `3` and never `4` while receiving thousands of DA frames — DA messages are a
separate app type and never touch `note_height`.

**That counter was built, and it found a wedge — `322bbaf`.** `sync=<asks>a/<snapshots>s/<certs>c
ans=<snap>/<cert>/<none>`, plus `PARKED@<height>` for a COMMIT decision held but unappliable for want of the body.

`on_sync_resp` cleared `sync_heads`/`sync_states` and *then* installed the certificate it had just adopted — discarding,
at the one moment it certainly held all three, exactly the three things a `SyncResp` is made of: the certified state, its
root, and the head it sits on. So a validator whose checkpoint sits above a peer's height took the snapshot branch of
`on_sync_req`, found nothing retained, and returned an **empty vector**; and it could not fall back to a commit
certificate either, because it *jumped over* the requester's height and never finalized it. Empty is indistinguishable
from a lost packet, so the requester re-asks every tick and is met with silence again.

A node that has just been rescued is the peer most likely to be asked next — it was behind for the same reason its
neighbours are, and it holds precisely the state they need. It answered every one of them with nothing. Measured:
`h9r1 sync=1a/1s/0c ans=0/0/2`. Fixed by retaining the adopted snapshot, pinned by
`a_freshly_synced_validator_still_answers_a_laggard_instead_of_going_silent`, and the two silent `return Vec::new()`
paths now fall through to the certificate — holding a checkpoint is not the same as being able to serve it, and the two
were conflated.

**The first draft of that test asserted something false**, and the counter is what showed it: keyed on
`latest_checkpoint().is_some()`, it fired while the laggard was still at genesis, because a validator forms a checkpoint
from a **quorum of peers' exec votes** at a height it never executed itself. A validator that far behind genuinely has
nothing to offer anyone, and answering nothing is correct there — the defect is answering nothing while *ahead*. Keyed on
the height having moved instead.

Whether this moves the live `a_hash_locked` rate is a separate question and is **not** established: 1 pass and 1 failure
in the two runs completed before the batch was stopped to chase what those runs revealed. Two wrong diagnoses this
session came from reasoning one step past the last measurement.

### [A] The snapshot rescue needs a peer TWO heights ahead — and the stall guarantees none exists

The second trace, with the catch-up counters, is a different failure from the first and it closes out by arithmetic:

```
v0: 0/Locked h2r5             skel=0/2231   sync=0a/0s/1c   ans=0/4248/0
v1: 0/Locked h1r13 behind(2)  skel=602/1532 sync=908a/0s/1c ans=0/0/3775
… v2–v5 the same shape, 817–876 asks each, 0 snapshots adopted, 1 certificate
v6: 0/Locked h2r6             skel=19/2255  sync=0a/0s/0c   ans=0/4266/0
```

**Nobody ever serves a snapshot** — `ans=0/…` on every validator in both traces — and that is structural, not luck. A
validator at height `P` has executed at most `P−1`, so its checkpoint is `C ≤ P−1`; `on_sync_req` serves the snapshot
branch only when `C > have_height`. A peer must therefore be **at least two heights ahead** of the requester to serve
one. Here `P = 2` against `L = 1`, so it cannot.

And the cell can never open that gap: five of seven are stuck at height 1, `Q = 5`, so height 2 can never assemble a
quorum. The two validators that did finalize height 1 (with the laggards' COMMIT votes, which the laggards themselves
never collected — votes are not retransmitted) stay exactly *one* ahead forever. The snapshot rescue is therefore
unavailable **precisely in the configuration that needs it**, and the only remaining path is the commit certificate,
which requires the body.

**The serving guard and the adopting guard do disagree by one**, and it is worth recording that it is *not* the cause.
`on_sync_resp` rejects on `cert.height < self.height()`, so it accepts `C == L`; `on_sync_req` falls through to the
certificate on `cert.height <= have_height`, so it never sends that case. Adopting `C == L` would be sound and is what a
laggard needs — a `Q`-quorum attests the state *after* `L`, `chain.restore` sets `base_height = L + 1`, and a
quorum-certified root cannot fork.

**But serving `C >= have_height` would not have rescued this cell, and the arithmetic says why.** A checkpoint at height
`h` needs a `Q`-quorum of *execution* votes for `h`, and a validator votes only after executing it. The five laggards
never finalized height 1, so they never executed it and never voted: height 1 has 2 exec votes against `Q = 5` and **no
checkpoint at height 1 exists anywhere**. The two ahead validators are therefore checkpointed at height **0** — *below*
the laggards' height — so `C >= L` reads `0 >= 1` and fails too.

That closes the question without a guard bug: **the execution checkpoint cannot advance past a stuck majority, by
construction**, because the stuck majority is what a quorum of execution votes requires. The snapshot rescue is not
merely unavailable here, it is structurally impossible, and the whole burden falls on the commit certificate — which is
offered ~8500 times and advances nobody.

So the live question is unchanged and one measurement away: `ccrej[h/v/park]` will name the guard that refuses those
certificates. Everything above is arithmetic on the trace; the refusal is not, and three attempts at deriving it have
already been wrong.

Ruled out along the way and still ruled out: the `SyncResp` snapshot exceeding a frame (`MAX_FRAME` is 1 MiB, the test
ledger is orders of magnitude smaller).

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
