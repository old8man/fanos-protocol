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

- **11. Hop-position leak (S1-M6) — CLOSED.** `fanos_aphantos::slots` is live: `seal_onion`/`peel_onion` build and peel a
  constant-width packet, so every hop at every depth is handed identical bytes. `anonymous_quic` 5/5 over real QUIC.
  Construction, the two forced design decisions, and the payload trade are in `docs/design-anonymity-substrate.md`.
