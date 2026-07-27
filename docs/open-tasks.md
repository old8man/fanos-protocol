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

### [A] Close the "libraries ahead of wiring" gap — measured, 2026-07-27
34 of 43 crates are reachable from the shipped node. These make claims in prose that no transport-level test covers:
- **Not in the binary at all:** `fanos-angelos` (L11 messenger — a headline product), `fanos-ergon` (the effect-algebra "no
  gas" claim), `fanos-holarch` (the Γ gate that *scores* the platform), `fanos-observatory`.
- **In the binary, never exercised over a transport** (absent from `fanos-node/tests` and `fanos-sim/tests`): `fanos-hermes`
  (cross-chain HTLC, claimed "live on the ledger"), `fanos-proteus` (traffic morphing — censorship resistance), `fanos-vpn`,
  `fanos-session`, `fanos-stream`, `fanos-threshold`.
- This is the shape of every defect found this session: correct in isolation, then unreachable, mis-wired or starved live.
  Each entry needs one live test or an honest downgrade of the claim.
- *Measure reachability transitively over `Cargo.toml`* — checking only `fanos-node/src` falsely reports `fanos-proteus` as
  unwired (it is reached via `fanos-quic`'s shaper).

### [A] `#[ignore]` conflates two incompatible things
34 ignored tests carry one attribute for two purposes: *measurements* (15 in `fanos-sim`) that print rather than assert and must
**never** gate, and *cost-gated assertions* (13 in `fanos-obolos`, 2 each in `taxis`/`quic`/`ffi`) that must gate **somewhere**.
So "run the ignored tests" cannot mean one thing, and the nightly `heavy` job has to name packages instead of selecting a
category. Distinguish them — a `measure_` name convention plus a required-vs-optional split, or a cargo feature per class.

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

### [A] Thin unit coverage in three crates
`fanos-holarch` 987 lines / **0.14** ratio / 8 tests — and it is the viability gate, so a gate that cannot be trusted to gate.
`fanos-observatory` 2 394 / 0.16 / 17. `fanos-runtime` 3 433 / 0.29 / 29 — the overlay engine; mitigated by `fanos-sim` (267)
and `fanos-quic` (68) but the thinnest own-coverage of any core crate.

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
