# FANOS — architecture & code audit, 2026-07-27

A measured audit rather than a reading. Every number below is reproducible from the commands in
`docs/design-testing.md` or restated inline; where a metric could not carry the conclusion it is marked as such, because a
previous pass in this repo was misled three times by observables that meant something other than assumed.

Scope: 43 crates, **73 370 lines of production code**, 56 546 lines of test (**ratio 0.77**), **1 922 tests**.

---

## 1. What genuinely justifies "new generation"

These are structural properties, not aspirations — each is enforced by the build rather than by convention.

**Panics are effectively absent from production paths: 13 sites in 73 370 lines.** Counting only code *before* the
`#[cfg(test)]` boundary in every `src` file: 11 `unwrap()` + 2 `expect()`, of which **11 are in one CLI binary**
(`fanos-cli/src/main.rs`). The remaining two are one each in `fanos-vrf` and `fanos-sim`. **Zero** in every network-facing
engine — `fanos-node`, `fanos-quic`, `fanos-runtime`, `fanos-taxis`, `fanos-obolos`, `fanos-aphantos`. The 954 raw `unwrap()`
hits a naive grep reports are almost entirely inside test modules, which is what the 278 `#![allow(clippy::unwrap_used)]`
headers cover.

**`unsafe` is contained to exactly one crate.** `#![allow(unsafe_code)]` appears once, in `fanos-ffi` — the C ABI surface,
where it is unavoidable. The only match elsewhere is the word "Byzantine-unsafe" in a comment. Every other crate is under the
workspace `unsafe_code` denial.

**23 of 43 crates are `no_std`**, including the whole crypto/math core (`primitives`, `field`, `geometry`, `code`, `vrf`,
`pqcrypto`, `obolos`, `ergon`) *and* `fanos-runtime` — the overlay engine itself. The sans-I/O discipline the design claims is
therefore structural: the engine cannot perform I/O because it cannot link to it.

**The dependency graph is a clean pyramid, no cycles.** Fan-in: `primitives` 27, `field` 24, `geometry` 23, `pqcrypto` 15,
`wire` 13. Layers depend downward only.

**Lint bar is uniform.** `cargo clippy --workspace --all-targets --features validator -- -D warnings` is clean, and it covers
test targets, so test code is held to the same bar as shipping code.

---

## 2. Findings

### 2.0 CRITICAL — every CI job failed before it verified anything (fixed)

Measured, not read. All three jobs in `.github/workflows/ci.yml` died on their own arguments:

- **`gate` died at its first step.** `cargo fmt --all --check` exits 1 with **2 650 diff hunks** across the workspace — the
  source is hand-wrapped denser than rustfmt's 100-column default (15 768 lines exceed 100 columns; the house width is ~120,
  with only 84 lines past 140). Everything after that step — clippy, the entire test suite, the V1–V22 reference verifier,
  three simulator scenarios, the benchmark compile — **never ran**.
- **`portability` and `miri` both named `fanos-crypto`, a package that does not exist** (cargo: *"a workspace member with a
  similar name exists: `fanos-pqcrypto`"*). Both failed at package resolution.

So the platform had **no working continuous verification of any kind**, while every quality claim in this repository rests on
the word "verified". This is the finding that precedes the others: it is why §2.2 and §2.4 below could be true unnoticed.

Three further defects, each of which would have kept a job red after the obvious name fix:

1. `cargo build -p fanos-runtime --no-default-features --features libm` **does not build for wasm32** — the overlay engine
   imports `fanos_code::{da, erasure}`, which are `alloc`-gated. The CI line contradicted the embedded build
   (`--features alloc,libm`) that the crate's own manifest documents.
2. Clippy and the tests ran **without `--features validator`**, so the ledger/consensus paths were neither linted nor tested —
   including the five consensus liveness defects fixed earlier the same day. Neither configuration is a superset: three
   `cfg(not(feature = "validator"))` fallbacks are visible only to the default build, so both must run.
3. **Miri was pointed away from the only `unsafe` in the workspace.** `fanos-ffi` is the sole crate containing any (57 sites —
   it is the C ABI); the other 42 deny or forbid it via `[workspace.lints]`, 36 escalating to `forbid`. The job checked
   `fanos-diakrisis`, `fanos-field` and the nonexistent crate — code that *cannot* contain the bug the tool looks for.

**Resolution.** The formatter step is deleted rather than satisfied: reformatting 2 650 hunks would overwrite deliberately
hand-wrapped source, and a gate that has never passed catches nothing while hiding every gate below it. Both feature
configurations are now linted and tested; every portability line is verified to build with exactly the features listed; a
nightly `heavy` job runs the real-parameter ZK proofs (§2.2) and the real-QUIC end-to-end paths (§2.4), closing both.

Miri was made load-bearing rather than merely re-aimed. Its target crate's raw-pointer contracts were only reachable through a
live node — and Miri cannot drive a reactor (`kqueue`/`epoll` are unsupported foreign calls), so it saw none of them. The
runtime-free half of the ABI is now factored out (borrowing caller buffers, the size-probe copy-out, the C-string terminator),
the handle paths are `cfg_attr(miri, ignore)`d, and Miri executes 11 tests over the actual `unsafe` in 1.7 s.

That the job *can fail* was verified by injecting defects, not argued: an off-by-one in the copy-out capacity check and a
terminator written one byte late are both reported as out-of-bounds writes. The first attempt at this proof **failed** — the
suite passed with the injected off-by-one, because no test probed the `value.len() == out_cap + 1` boundary. A boundary test
now closes that gap. A third injection (deleting the empty-value guard, so a zero-count copy takes a null `dst`) is *not*
caught by Miri; `core::ptr`'s rule is that only a **non-null** pointer is valid even for zero-sized accesses, so the guard
stands on the documented contract, and the test comment now says that instead of claiming a tool would catch its removal.

### 2.1 HIGH — "libraries ahead of wiring" persists, and is now quantified

Past passes named this as a meta-pattern without a number. It has one.

**Corrected 2026-07-27, and now a checked number rather than a remembered one** (`fanos-cli/tests/architecture.rs`
computes the closure over the manifests; `cargo test -p fanos-cli --test architecture`). The figures below stand — 34 of 43
crates in the node's closure, 38 of 43 reachable from *some* shipped binary — but two thirds of the *list* did not, and
every error had the same cause: grepping for a crate's name where it is reached through an intermediary, which is the
exact trap this section's own method note warns about.

- `fanos-holarch` and `fanos-observatory` were listed as "not in the binary at all". Both are reachable: holarch through
  `fanos-cli`'s `fanos-verify` (the V1–V22 verifier CI runs), and observatory owns two binaries of its own.
- Of the six listed as "never exercised over any transport", **three are**: `fanos-session` is used by
  `fanos-node/src/{diaulos,rendezvous,rendezvous_host}.rs`, `fanos-stream` through `fanos-diaulos`, and `fanos-threshold`
  through `fanos-aphantos`'s sealing — all driven end-to-end by `diaulos_quic` and `anonymous_quic`.

**What genuinely remains, after measurement:** two orphans linked by *nothing* — `fanos-angelos` (the L11 messenger, a
headline product) and `fanos-ergon` (the effect-algebra execution model; DROMOS executes without it) — and two crates that
ship inside the node with no transport-level test: `fanos-hermes` (reached via `fanos-dromos/src/hermes.rs`, but no QUIC
suite submits an HTLC) and `fanos-vpn` (feature-gated, and CI does not build the feature). `fanos-bench`, `fanos-ffi` and
`fanos-wasm` are embedding surfaces whose lack of an internal consumer is correct, not a gap.

Original text, kept for the record:

**34 of 43 crates are reachable from the shipped node.** Not in the binary at all, excluding legitimate tooling
(`cli`, `bench`, `sim`) and embedding surfaces (`ffi`, `wasm`):

| crate | what it claims | status |
|---|---|---|
| `fanos-angelos` | L11 — the Discord-class anonymous PQ messenger, a headline product | built, tested in isolation, **not in the node** |
| `fanos-ergon` | the effect-algebra execution model — the "no gas, derived footprints" claim | **not in the node** |
| `fanos-holarch` | the Γ viability gate that *scores the platform* | **not in the node**, and 8 tests for 987 lines |
| `fanos-observatory` | operator/measurement surface | **not in the node**, 17 tests for 2 394 lines |

**In the binary but never exercised over any transport** (absent from both `fanos-node/tests` and `fanos-sim/tests`), excluding
trait/macro crates (`ports`, `wire-derive`):

`fanos-hermes` (cross-chain HTLC — the "live on the ledger" claim), `fanos-proteus` (traffic morphing — the
censorship-resistance claim), `fanos-vpn`, `fanos-session`, `fanos-stream`, `fanos-threshold`.

Both lists are *claims the platform makes in prose* that no transport-level test covers. That is the exact shape of defect
this session found five times in TAXIS consensus and twice in the anonymity substrate: code that is correct in isolation and
unreachable, mis-wired, or starved on the live path.

**Method note for whoever acts on this:** the first version of this measurement checked only `fanos-node/src` and reported
`fanos-proteus` as unwired — false, it is reached via `fanos-quic`'s shaper. Reachability must be computed transitively over
`Cargo.toml`, which is what the table above does.

### 2.2 MEDIUM — the ZK proof stack is sound at real parameters, but nothing runs it on a schedule

**Verified in this audit, not assumed:** `cargo test -p fanos-obolos --release -- --ignored` → **7 passed, 0 failed, 84 s.**
That covers the note-validity proof, sound membership with a position-bound nullifier, the full per-input spend, and a
1-in/1-out whole-transaction shielded transfer — each at real `bits = LOG_BASE = 16`, plus the ledger-application path. So the
severity is lower than the `#[ignore]` count suggests: the proofs work, and they are cost-gated rather than unverified, exactly
as their attributes document.

The residual is process, not soundness: the default `cargo test` covers the state machine and codecs but **not** the proofs, so
nothing re-checks the currency's real-parameter soundness after a change unless someone remembers. 84 s in release is cheap
enough for a nightly or pre-release job, and the finding is that it does not have one.

**Closed** by the nightly `heavy` job (§2.0) — `cargo test -p fanos-obolos --release -- --ignored`, plus a manual
`workflow_dispatch` trigger for pre-release runs.

### 2.3 MEDIUM — thin unit coverage where it matters most

| crate | prod lines | ratio | tests | note |
|---|---|---|---|---|
| `fanos-holarch` | 987 | **0.14** | 9 | see below — the ratio misjudged this one |
| `fanos-observatory` | 2 394 | **0.16** | 17 | |
| `fanos-runtime` | 3 433 | **0.29** | 29 | the overlay engine — mitigated by `fanos-sim` (267 tests) and `fanos-quic` (68), but its own unit coverage is the thinnest of any core crate |

Everything else sits at 0.4–1.9. `fanos-ports` (368 lines, 0 tests) is pure trait/type declaration and needs none.

**Correction, 2026-07-27: the ratio was the wrong instrument for `fanos-holarch`.** Its tests are dense rather than thin —
the gate with margin, the corpus reference corners, PSD validity for every instance *and* every ablation including a
rejection case, the binding-boundary headroom, and the T-77 composition identity. What was actually wrong was narrower and
would not have shown up as a ratio at all: `each_ablation_breaks_its_targeted_invariant` asserted only that the target
broke, while the doc beside it claimed each ablation breaks *exactly* one invariant. Asserting the full break-set showed
that **three of the four did not** — `mud` also broke V3, `monolith` also broke V4, `fragmentation` also broke V4 — so
none of those three demonstrated its invariant to be independently binding, which is the entire purpose of the Ω4
calculus. `monolith` and `fragmentation` are now selective (the monolith eats the *data* flow, which is E-rich, instead of
the L/U-dominant control flow; fragmentation keeps interiority thick inside its island instead of thinning it along with
the coupling). `mud` cannot be, and the reason is a theorem rather than a defect: `P = (Σγ_ii²)(1 + Φ)` and
`Σγ_ii² ≥ 1/7` at trace 1, so `Φ ≥ 1 ⇒ P ≥ 2/7` — **V1 is implied by V3**, and the viable window has three independent
walls, not four. Recorded in `spec/platform.md` §1.3 and pinned over 2 000 matrices of the model's own family. Lesson for
the rest of this table: a test-to-code ratio cannot see an assertion that is weaker than the claim it is labelled with.

### 2.4 MEDIUM — 34 `#[ignore]`d tests are a second, invisible test suite

15 in `fanos-sim` (measurements and probes — legitimate, they print rather than assert), 13 in `fanos-obolos` (§2.2), 2 each in
`taxis`, `quic`, `ffi`. Nothing runs them on a schedule. Two categories are conflated under one attribute — *measurements*,
which should never gate, and *cost-gated assertions*, which must gate somewhere. They should be distinguishable.

**Partly closed** by the nightly `heavy` job (§2.0): the cost-gated assertions in `fanos-obolos` (13) and `fanos-ffi` (2) now
gate nightly. The residual is the conflation itself — `fanos-sim`'s 15 measurements share one attribute with assertions that
must gate, so "run the ignored tests" cannot mean one thing.

### 2.5 LOW — suppressed-lint inventory

278 `allow(clippy::unwrap_used)` and 77 `allow(clippy::indexing_slicing)`, concentrated in test modules (per §1 the production
panic count is 13, so the suppressions are doing what they claim). Worth a periodic re-check that none has migrated to a
production block: the check is the `#[cfg(test)]`-boundary count in §1, which is cheap to re-run.

`25 allow(clippy::too_many_arguments)` is worth a second look for a different reason: this session found that such a lint was
twice pointing at a **missing type** rather than a missing suppression (`HostedService`, and the `(Vec<u8>, u8, bool)` triple).

### 2.6 CRITICAL — blind ordering met drop-on-inclusion, and a sender's later transactions were lost (fixed)

Found after this audit was written, by following a live symptom into the deterministic simulator. Two individually-correct
behaviours composed into losing user transactions outright:

- **Anti-MEV ordering is blind.** A proposer sees only commitments, so it *cannot* order a sender's transactions by nonce,
  and a block routinely carries nonce 2 ahead of nonce 1. Execution rejected the premature one — rightly.
- **`on_finalize` dropped every *included* commitment from the mempool**, keyed on inclusion rather than outcome, and it
  ran *before* the execution that would have re-queued anything.

Measured: four transfers of 100 from one account, submitted together and driven to height 24, executed **one**. Live over
QUIC the same shape lost one of four. This is not a stress case — it is what happens whenever a wallet sends a second
transaction before the first is included.

The conflation lived in the outcome type: `ExecOutcome::Rejected` documented "bad nonce, insufficient balance, …" as one
terminal verdict, when a nonce *ahead* of an account is not invalid but **premature** — it becomes valid the moment its
predecessor lands. `ExecOutcome::Deferred` now names that, `Accounts` and `TokenLedger` return it
(`TokenError::NonceAhead`, split out of `BadNonce`, which now means only a replay), and the engine returns those
transactions to the mempool.

Three things are worth carrying forward from the fix:

1. **The class is wider than the instance.** The same shape held for an HTLC claim ordered ahead of its lock
   (`[claim, lock]` → `[Rejected, Applied]`, recipient paid nothing, escrow stranded until the timeout) and a storage
   proof ahead of its deal. Both now defer. The shielded path was checked and is safe by construction — its rolling anchor
   window accepts any recent root, and no wallet can prove membership against a root that does not exist yet.
2. **The general rule**: a rejection is premature iff *re-executing the transaction unchanged against a later state could
   succeed*. Replay, double-spend, bad signature and malformed bytes never can; a missing prerequisite can. `TAG_SHIELD`
   and `TAG_NAME` remain to be decided against it, and one of them is a genuine trade-off rather than an oversight —
   deferring on insufficient funds has no identifiable pending prerequisite, so it re-consumes block space for
   `REVEAL_WINDOW` blocks with no fee to price it (ERGON is gasless).
3. **A one-transaction test cannot see any of this.** Both sibling `dromos_quic` suites submit exactly one transaction, so
   "every validator reached height 1" is their fixed point. The defect needed a *second* transaction from the same sender
   to exist at all — which is the ordinary case in production and was absent from every test in the repository.

---

## 3. What this audit does not cover

Stated so it is not mistaken for completeness: no formal review of the cryptographic constructions themselves (that is
`docs/crypto-audit-readiness.md` and the independent pass recorded in `docs/audit.md`), no performance/throughput
characterisation beyond the DROMOS wave metric, and no review of the spec documents against each other — only spec-vs-code
where a claim was measurable.

---

# Part 2 — code architecture

## 4. What is well-factored

**Error discipline is uniform: one error enum per crate, no duplication.** 14 distinct `*Error` types (`WireError`,
`QuicError`, `NodeError`, `ThresholdError`, …), each defined once, each with `Display` + `std::error::Error` and `From`
conversions at the boundaries. No crate leaks another's error type as its own.

**The abstraction seams are real and small: 21 traits for 43 crates.** `Engine` and `StateMachine` (the two sans-I/O cores),
`Wire` (codec), `Dialer`/`UdpDialer`/`OverlayTransport` (transport substitution — this is what lets the simulator differ only
in transport), `MorphCodec` + `AdmissionPolicy` (pluggable policy SPIs), `SystemProbe`/`Scenario` (measurement),
`ShieldedProof`/`ReRandomizable`/`ProofSize` (the ZK surface), `TunReader`/`TunWriter` (VPN datapath). Each names a
substitution point that is actually substituted somewhere — none is speculative.

**`overlay.rs` stayed split.** 4 048 → `overlay/` with `mod.rs` at 1 061 production lines and five siblings. The method notes
that came out of it are in `docs/design-testing.md`.

## 5. Findings

### 5.1 MEDIUM — `fanos-quic/src/driver.rs` is the workspace's god-object: 2 125 production lines, eight concerns

It is now the largest production file in the repo — larger than `overlay/mod.rs` is *after* being split, and it has never been
split. Eight separable concerns, with natural boundaries already visible in its own section comments:

| concern | representative items |
|---|---|
| PROTEUS shaping | `ProteusConfig`, `shape_out`/`shape_in`, `apply_outcome`, `MorphController` |
| identity / self-certification | `SelfCert`, `HelloVerifier`, `CoordinateProver`, `hello_exchange`, `read_verified_hello` |
| coordinate placement & reseating | `BeaconWindow`, `Placement`, `Reseater`, `reshuffle_loop`, `announce_moves`, `verified_move` |
| handle & client API | `NodeHandle`, `Client`, `Control`, `GetWaiters`/`PutWaiters`, `router_loop` |
| spawn surface | `spawn`, five `spawn_self_certifying*`, `self_certifying_inner`, `spawn_shaped` |
| connection & frame plumbing | `Transport`, `accept_loop`, `read_frames`, `send_framed`, `ConnMap` |
| NAT traversal | `broker_holepunch`, `accept_holepunch`, `encode_punch`/`decode_punch`, `Reflexive` |
| custom UDP fabric | `Fabric`, `PassThroughFabric`, `impl quinn::AsyncUdpSocket`, `WritablePoller` |

The precedent and the method exist (the overlay split, `docs/design-testing.md` §"Refactoring a large module"): cut by items,
child modules see the parent's privates so splitting an impl is cheaper than lifting a type. `placement` (reseating), `fabric`
(the UDP socket impl), `holepunch` and `shaping` are the four cleanest first cuts and none of them needs an API change.

### 5.2 MEDIUM — seven `spawn*` entry points where one builder belongs

`spawn`, `spawn_shaped`, and five `spawn_self_certifying{,_with_capabilities,_persistent,_persistent_on,_persistent_over}` —
all five of the latter funnel into one `self_certifying_inner` and differ only in which of `{bind, credentials, capabilities,
proteus, fabric}` they accept. **The names encode the parameter list, which is the tell.** Each new axis has so far meant a new
public function, so the surface grows multiplicatively with options.

This is the same lint-shaped signal this session hit twice elsewhere: a `too_many_arguments` warning pointing at a missing
*type* rather than a missing suppression (resolved as `HostedService` in one case, and the `(Vec<u8>, u8, bool)` triple in
another). 25 `allow(clippy::too_many_arguments)` remain in the workspace and are worth reading the same way.

### 5.3 LOW — `fanos-node/src/bin/fanos.rs` at 1 226 production lines

A CLI binary that size is carrying logic that belongs in the library, which also puts it outside most of the test surface
(binaries are harder to test than libs). It is where the 11 of 13 production panic sites live — not a coincidence.

### 5.4 Observation — `fanos-obolos` exposes 357 public items

The largest public surface in the workspace (next is `fanos-node` at 255, `fanos-taxis` at 232). For the currency crate this
may be inherent — the ZK statement types, the ring/SIS parameters and the note algebra are all legitimately public — but it is
worth one pass asking which of the 357 are load-bearing for callers versus incidental. A narrower surface is a smaller
compatibility obligation for the crate that most needs to stay stable.

---

# Part 3 — a latent fragility found by attempting a refactor

## 6. HIGH — `Node::start` is correct only in the absence of a suspension point at spawn

Attempting §5.2 (collapse the seven `spawn*` entry points into one builder) surfaced something the audit's static
measurements could not: **two opposing, undocumented startup-ordering sensitivities, which the current code satisfies only by
accident.**

The accident is the async/sync split of the five functions. `spawn_self_certifying_persistent_over` — the one `Node::start`
and the simulator use — is **synchronous**. The other four, used by the test harness and the QUIC suites, are **`async` while
awaiting nothing**. So the deployed node never yields at spawn, and every harness does.

Measured, each in isolation, with a single builder replacing all five:

| `spawn()` shape | `fanos-node` role-loop test | live `anonymous_quic` |
|---|---|---|
| synchronous (honest — the inner call awaits nothing) | **passes**, 2.1 s | **fails**, 4 of 5 |
| `async` + one `yield_now()` (matches the four old async variants) | **fails**, 10.6 s | passes |

Both failures reproduce in isolation, so neither is the contention artefact this suite is prone to. Baselined at HEAD: both
green.

**What this means.** `Node::start`'s role assignment depends on the driver tasks *not* being polled between `spawn` and the
rest of its own setup, while a multi-node live cell depends on them *being* polled before it is used. Neither is written down,
neither is asserted, and any innocuous refactor that adds or removes an `await` on that path silently breaks one of them. That
is a latent bug in the shipped node, not merely a refactoring obstacle.

**Not fixed by choosing a yield placement.** Tuning which caller yields would be exactly "compromising around a known
defect": it leaves the race in place and re-encodes it in a second accident. The fix is to make readiness *explicit* — `spawn`
returns a handle whose tasks are spawned but not necessarily running, and a caller that needs a peer serving awaits evidence of
that (a notification, a successful dial), which is what the harness's `establish_membership` already does for membership. Then
neither behaviour depends on suspension-point placement.

**Status:** the builder was written, all 8 call sites ported, clippy clean workspace-wide, `fanos-quic` 6 suites and
`fanos-node` 114 lib tests green — then **reverted**, because it cannot ship while it flips live tests red, and shipping it
would have meant tuning a race. The finding is the deliverable; §5.2 stays open behind it.

**Method note.** I first attributed the live failure to the fake `async` being "accidentally load-bearing" — an appealing
explanation, built on a *contended* flake, which an isolated run refuted (the fully synchronous configuration passes the
three-node capability test 3/3 in 2.0 s on its own). Only the second, isolated round produced the table above. Third time this
session that a contended real-socket suite produced a false attribution; the rule stands — **baseline in isolation before
explaining anything.**
