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

### 2.1 HIGH — "libraries ahead of wiring" persists, and is now quantified

Past passes named this as a meta-pattern without a number. It has one.

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

### 2.3 MEDIUM — thin unit coverage where it matters most

| crate | prod lines | ratio | tests | note |
|---|---|---|---|---|
| `fanos-holarch` | 987 | **0.14** | 8 | this is the *viability gate*; a gate with 8 tests cannot be trusted to gate |
| `fanos-observatory` | 2 394 | **0.16** | 17 | |
| `fanos-runtime` | 3 433 | **0.29** | 29 | the overlay engine — mitigated by `fanos-sim` (267 tests) and `fanos-quic` (68), but its own unit coverage is the thinnest of any core crate |

Everything else sits at 0.4–1.9. `fanos-ports` (368 lines, 0 tests) is pure trait/type declaration and needs none.

### 2.4 MEDIUM — 34 `#[ignore]`d tests are a second, invisible test suite

15 in `fanos-sim` (measurements and probes — legitimate, they print rather than assert), 13 in `fanos-obolos` (§2.2), 2 each in
`taxis`, `quic`, `ffi`. Nothing runs them on a schedule. Two categories are conflated under one attribute — *measurements*,
which should never gate, and *cost-gated assertions*, which must gate somewhere. They should be distinguishable.

### 2.5 LOW — suppressed-lint inventory

278 `allow(clippy::unwrap_used)` and 77 `allow(clippy::indexing_slicing)`, concentrated in test modules (per §1 the production
panic count is 13, so the suppressions are doing what they claim). Worth a periodic re-check that none has migrated to a
production block: the check is the `#[cfg(test)]`-boundary count in §1, which is cheap to re-run.

`25 allow(clippy::too_many_arguments)` is worth a second look for a different reason: this session found that such a lint was
twice pointing at a **missing type** rather than a missing suppression (`HostedService`, and the `(Vec<u8>, u8, bool)` triple).

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
