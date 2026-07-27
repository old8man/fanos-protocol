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

### 2. A node that loses a coordinate collision can stay permanently unbound
Live coordinate resolution is done (`docs/design-coordinates.md`, `29e322b`), and so is the read-triage fix this item used to
prescribe — `resolve_directory` returns `Scan<T>`, reads are three-valued (`Read::{Found,Absent,Unknown}`), and
`role_loop::may_relax` refuses to treat an *incomplete* scan as evidence of stability (`2e088a4`, `416b4f7`, `24dc4fe`). That
worked: at full occupancy with an injective draw, rosters now reach **`[7; 7]`, agreed in 24–116 s**, where they previously
froze at `[4, 4, 3, 4, 2]`.

**What remains is one measured failure, and it is not about propagation.** `measure_roster_convergence_with_collisions_allowed`
(fabric, `#[ignore]`d measurement) runs `spawn_as_drawn` — collisions permitted — and reports:

| trial | distinct | probe index | final rosters | agreed |
|---|---|---|---|---|
| 0 | 7 of 7 | all `Some(0)` — *no collision occurred* | `[7, 7, 7, 7, 7, 7, 7]` | 24 s |
| 1 | **6 of 7** | `[0, 0, 0, **None**, 0, **2**, 0]` | `[3, 5, 5, 4, 1, 5, 6]` | **never** |

- **The primary defect: `probe_index = None` — a node that lost the arbitration holds no directory entry at all.** It should
  advance its own probe walk and bind at the next point it can prove, which `settle_index` exists to do and which node 5
  visibly did (index 2). Node 3 did neither and stayed unbound.
- Everything else follows from that. **A node with no coordinate cannot publish**, so no scan can ever see it and the roster
  cannot complete — which is why `agreed` is `None` rather than late. The roster numbers are a *symptom*; chasing them is
  chasing the wrong layer, exactly as this item's earlier revisions did.
- **Trial 0 is the control and it is essential**: an injective draw over the same code converges in 24 s. So the collision
  path is the whole of the residual.
- **The instrument needs one improvement before the next attempt:** `spawn_as_drawn` takes the draw as it comes, so trial 0
  spent 160 s measuring a case with nothing to resolve. Force the condition — retry the draw until `distinct < n` — or the
  measurement is half wasted and can silently pass by never colliding.
- `NodeFleet::spawn`'s injective draw stays until trial-1-shaped runs converge; it is the honest indicator of exactly this.

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
