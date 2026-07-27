# FANOS — open tasks

**This file lists only what is still open.** Closed work is not kept here — its rationale lives in the commit that closed
it, and any durable engineering finding is written into the design or audit doc it belongs to (`docs/audit.md`,
`docs/design-testing.md`, `docs/design-coordinates.md`, …). A task list that accumulates completed items stops being
readable as a task list, which is what happened to the previous revision of this file.

**Verification rule for whoever picks this up:** check the claim before doing the work. A task list is a cache, and this
one has gone stale twice. Each item names the file and symbol its claim rests on, so the check is cheap.

No open CRITICAL/HIGH security item remains; all four audit passes are consolidated in `docs/audit.md` with every finding
RESOLVED. What follows are the remaining *capability*, *coherence*, and *quality* gaps.

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

### 2. Roster propagation after a within-epoch coordinate move — 3 of 4 links
Live coordinate resolution itself is done and measured (see `docs/design-coordinates.md` and `29e322b`). What remains is
the last propagation link.

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

## Tier B — platform capability


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

### 7a. Decompose `fanos-runtime/src/overlay/mod.rs`
`overlay.rs` is now `overlay/` — six modules, 4,048 → 2,900 lines, zero API change (`9cb113c`, `cad9eb5`, `3942199`,
`1ef497b`, `998470f`), and the `ThresholdSealed` dependency edge is gone (`a23ed82`).

- **Remaining, and it is a decision rather than a next step.** `overlay/mod.rs` is `OverlayNode`, its ~1,400-line impl, and
  `impl Engine`. The natural further cuts are `storage` (`on_put`/`on_get`/`on_sample`/`on_publish`/`on_lookup`/`on_value`/
  `distribute_shards`), `membership` (`flood`/`on_join`/`on_announce`/`on_reseat`/epoch), and `liveness`
  (`on_heartbeat`/`health_view`/`loss_view`/`sweep_pending_gets`) — each a child module on the pattern `hier` established.
  Worth doing deliberately; not worth drifting into.
- The method notes earned by the completed slices (cut by items not offsets; start each module with an empty import list;
  never blanket-rewrite visibility; splitting an impl is cheaper than lifting a type) are recorded in
  `docs/design-testing.md` §"Refactoring a large module".

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

- **9. 3-member anonymity set at F2** — *partially closed* by `8df2b08` (the order is now selectable and under-delivery is
  loud). Residual: document per-cell set size as first-class, and settle the default (item 4).

- **11. Hop-position leak (S1-M6) — the layout is BUILT and unit-verified; wiring it in is the open part.**
  - **The leak, measured** (`threshold_onion::a_peeling_relay_can_currently_infer_its_hop_position_s1_m6`, a deliberate
    characterization test asserting the defect is still present, so a fix cannot land silently): per-hop sizes
    `[20480, 10689, 7135, 3581]` on a 4-hop circuit over 3-member lines. Only the outermost onion is padded, so **exactly one
    hop is protected**; from hop 1 on the size falls by a constant 3554 B and `round(size / 3554)` gives a relay its position.
  - **`fanos_aphantos::slots` is the fix, and it is done and tested** — constant-width packet, per-hop slot shift, `D`
    derived per plane (5 hops at `q = 2`, 3 at `q = 4`, 2 at `q = 7`), size-preserving payload layers. See
    `docs/design-anonymity-substrate.md` for the construction and why it is simpler than textbook Sphinx.
  - **A second-order leak found while building it, and fixed:** framing. A relay holds the whole header, so if an unused slot
    fails to *parse* as a sealed layer while a real one succeeds, the relay counts the parseable slots and recovers the
    remaining depth — the original leak through the back door. Measured: **2 of 5 slots parsed on a 2-hop circuit**, exactly
    the real hop count. Pure keystream filler is therefore wrong; filler must reproduce `members`/`ct_len` and randomize only
    what is genuinely opaque. This is the kind of thing a constant-*width* test cannot see, and it is now its own test.
  - **⚠️ Wiring it into `seal_onion`/`peel_onion` was attempted and WITHDRAWN.** All 43 `fanos-aphantos` unit tests passed,
    including the constant-width and filler-framing assertions — and four live tests in `anonymous_quic` then failed by
    timing out with no session completing. Not shipped in that state.
  - **Ruled out by measurement, so do not re-try these:**
    - *Payload capacity.* Doubling `THRESHOLD_ONION_LEN` to 40 960 did **not** fix it. (The budget question below is real
      and separate — it just is not this failure.)
    - *Ragged hop lines.* `fanos_rendezvous::create_forward` builds every hop from `line_member_coords` and requires all
      `q + 1` keys present, so hop member counts are uniform and the new equal-width precondition holds.
    - *The peel paths.* Instrumented `member_partial` and the peel to print on every failure: **zero** hits.
  - **Also ruled out — and this is the sharpest narrowing, so start here.** With the wiring applied:
    - `fanos-rendezvous` **17/17 pass**, including `seal_forward_to_host::<F2>` — an end-to-end seal of the very structure the
      live dialer sends. So the seal path itself is fine.
    - `fanos-sim` passes, **including `anonymous_rendezvous` (4 tests)**, and `fanos-calypso` 44. The sim differs from
      production only in transport, so the whole anonymous composition works over the in-memory transport.
    - No length guard anywhere on the live path: every `THRESHOLD_ONION_LEN` reference in `fanos-node`/`fanos-aphantos`
      outside tests is the re-export itself.
    - Live circuit depth is `(1, 1)` — 2 hops, against a 5-hop ceiling at `q = 2`. Not depth.
  - So the failure is **specific to the real-QUIC composition** and is not in the onion construction. The remaining suspects
    are the parts only `anonymous_quic` exercises: the NOSTOS dead-drop reply path over QUIC, the per-epoch onion-key ratchet
    on live `MixRelay`s, and `ThresholdRouter` cover traffic. Instrument at the **router**, not the onion: log every
    peel/forward decision in `ThresholdRouter` for one `anonymous_quic` run. The onion-level instrumentation already came
    back with **zero** failures across a full 240 s run, which is why the next probe has to move up a layer.
  - *The gap that cost the most this iteration:* I instrumented only the peel side, while `create_forward` swallows a seal
    error with `.ok()?` — so "no output" was ambiguous between "no failures" and "not reached". Instrument both ends of a
    path before reading silence as evidence.
  - **A real budget constraint to settle regardless.** A fixed array reserves all `D` slots even for a one-hop circuit, so
    payload capacity falls to `THRESHOLD_ONION_LEN − PREAMBLE_LEN − D × slot_len` = 2 704 B at `q = 2`. Some structures this
    protocol nests *inside* an onion payload are larger (sealing to a 3-member line is 3 507 B alone), so wiring needs either
    a wider cell or fragmentation above a fixed cell — which is the trade Sphinx makes and answers the same way.
