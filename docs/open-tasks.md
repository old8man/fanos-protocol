# FANOS — open tasks (handoff)

**As of** `HEAD afc253b`, 2026-07-26. Every item below was **re-verified against the current tree** on this date by
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

### 2. Wire the probe index onto the HELLO frame
- **Problem.** The coordinate-resolution primitive is complete and now internally consistent (`afc253b`: one
  lexicographic claim order shared by `settle_index`, `displacement_is_forced`, and `Directory::supersedes`), with
  `CoordinateClaim`/`DisplacementWitness`/`verify_coordinate_claim` and a canonical encoding. But **the wire carries only
  `k = 0`**: `fanos-quic/src/identity.rs:28` fixes `HELLO_BODY_LEN` at `version(2) ‖ caps(4) ‖ field_q(4) ‖ epoch(8) ‖
  coord(12) ‖ proof(80)`, and `verify_hello` calls the single-proof `verify_peer_coordinate`. So a node can *detect* it
  must move but cannot *announce* the point it moved to, `CoordinateClaim` has no consumer outside `fanos-vrf`, and the
  measured capacity (200/200 at `P=993` vs the bare draw's 181) is reachable **only from the simulator**. The shipping
  cell still seats ~`q` nodes.
- **Task.** Carry the claim instead of the bare proof: a direct claim encodes as `proof(80) ‖ index(2)`, so the common
  case costs two bytes and the first 80 are byte-identical to what is there now. `verify_hello` runs
  `verify_coordinate_claim`; the driver runs `settle_index` against `Directory::claim_at` and binds via
  `insert_claimed`. Bound the claim body **before** decoding (peek the index at its fixed offset and reject
  `index >= probe_bound::<F>()`) — an attacker-chosen `u16` index otherwise sizes a witness vector. Version-gate the
  format change through the existing `negotiate_version`.

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

### 5. Telemetry differential-privacy export path (C7)
- **Problem.** Verified: `fanos-telemetry::dp::privatize` (the ε-DP mechanism) has **no caller anywhere outside its own
  crate**. The node has no telemetry *export* path at all, so the DP guarantee is decorative and no operator-facing
  metrics ship.
- **Task.** Build the node telemetry export surface and route every export through `privatize` with the configured
  `PrivacyBudget`. Build the export *first* — there is nothing to privatize today.

### 6. One Merkle tree in `fanos-primitives`
- **Problem.** Verified: no `fanos-primitives/src/merkle.rs`, and three divergent implementations with incompatible
  odd-node rules and proof formats — `fanos-thesauros/src/content.rs:88` (odd node promoted; `MerkleStep` proofs),
  `fanos-taxis/src/crosscell.rs:96` (odd tail **duplicated**, the **CVE-2012-2459** ambiguity class unless the leaf count
  is externally bound; index-parity proofs), `fanos-vrf/src/pqvrf.rs:61` (perfect tree).
- **Task.** One domain-separated `merkle` module in `fanos-primitives` (`hash_labeled`, one odd rule, one proof type, leaf
  count bound into the root); thesauros + crosscell adopt it; pqvrf reuses it as the perfect-tree case.
  (`obolos/tree.rs` is a genuinely different incremental-frontier structure — leave it.)

### 7. Split `fanos-runtime/src/overlay.rs` + extract `ThresholdSealed`
- **Problem (a).** `overlay.rs` is **4,048 lines** (it has grown since this file last claimed 3,870). The `OverlayNode`
  decomposition already exists at the type level (`Config`/`Store`/`Router`/`Membership`/`Healer`) — only the module split
  never happened.
- **Problem (b).** Verified: `fanos-taxis` (consensus) imports `ThresholdSealed`/`ThresholdError` from `fanos-aphantos`
  (the onion router) — `keyper.rs:30`, `tx.rs:15` — the one bad edge in an otherwise clean 5-layer dependency DAG.
- **Task.** Mechanical split of `overlay.rs` into `store/router/membership/healer/hier/node.rs` (lib.rs re-exports, zero
  API change); extract `aphantos/{threshold,sealed}.rs` into a low-layer crate both aphantos and taxis import.

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
- **10. S1-M3** — mix-key store slots are unauthenticated (`fanos-node/src/mixdir.rs`, `mix_key_slot` keys a slot by
  `coord ‖ epoch` with no writer check): bind a published mix key to its cert-derived coord, rejecting a `put` unless the
  writer identity hashes to `coord`. Liveness-DoS, not deanonymization.
- **11. ct_len hop-position leak (S1-M6)** — the threshold-onion per-layer length header is cleartext
  (`fanos-aphantos/src/threshold.rs:234`, already documented there as a residual), so a *peeling* relay learns its hop
  position. Optional: flat-header Sphinx-style per-layer length encryption (the `sealed.rs` path already AEAD-encrypts the
  length).
- **12. NYX transparent-sheaf footgun** — `fanos-nyx` `sheaf.rs`/`tessera.rs` (cleartext-Shamir transparent onions,
  superseded on the live path) are still `pub` (`lib.rs:33-34`): gate behind a sim feature or rename so an integrator
  cannot pick the lower-assurance variant.

---

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
