# FANOS — the Platform Reference Design

> The synthesized reference architecture: FANOS is not a Tor-analog but a **self-observing coherent
> substrate** — a platform on which anyone builds optionally-anonymous overlay networks (messengers,
> blockchains, web infrastructure) through an SDK, with per-segment privacy, native monitoring, and a
> deterministic developer loop. This document unifies eight parallel deep-research tracks (streams,
> control surface, connection protocol, anonymity integration, platform/SDK, heterogeneous privacy,
> developer platform, and an adversarial critique) into one coherent design at all levels.

It extends [`design.md`](design.md) (invariants, incidents), [`design-names.md`](design-names.md)
(ONOMA), and [`roadmap.md`](roadmap.md) (phases). Where those describe the *substrate as shipped*, this
describes the substrate *as a platform*.

---

## 0. Thesis — one quantity, one move, recursively

Eight independent design tracks converged on the **same** primitives. That convergence is the strongest
evidence the architecture is right, and it crystallizes into three unifying statements:

**(T1) One quantity runs the whole stack — coherence.** The coherence measures `Φ/P/R` and the spectral
gap `Δ` of the network's dissipative dynamics are not just the *healing* signal. They are simultaneously:
monitoring, admission pricing (Lindblad), transport congestion/RTO, node readiness (`Φ≥1 ∧ R≥1/3`),
reputation, (Phase 6) consensus, **and** privacy-isolation health. Every controller in FANOS reads the
same `(Φ, P, R, Δ)` at a different tier. "Go faster," "hide better," "stay healthy," "price the flood,"
and "is this node ready" are one dial read at several time-scales — the *derive-don't-tune* invariant
taken to its limit.

**(T2) One move creates every boundary — `H(label ‖ id ‖ …)` domain-separation.** A self-certifying
identity is a hash-commitment: an ONOMA address is `H(bundle)`, a Protocol-Id is `H(manifest)`, a DHT
key is `H(STORAGE‖PID‖key)`, a rendezvous line is `MapToLine(H(pubkey‖epoch))`, an epoch slot is
`H(addr‖epoch)`. The *same* move gives naming, tenancy isolation, unenumerability, and rotation. Nothing
is negotiated that can be *derived* — this is why FANOS has no directory, no registrar, no
multistream-select handshake.

**(T3) One structure recurs at every tier — the reflexive cell.** DIAKRISIS observes a coherence matrix
`Γ` over 7 nodes and heals; `ParentCell` runs the same loop over 7 child cells; the platform runs it over
a *cell of protocols* (`Γ_app`); privacy runs it over *isolation* (`isolation-coherence`). The network's
two adaptation clocks — fast homeostasis (DIAKRISIS) and slow selection (capability negotiation) — range
over **nodes, protocols, and privacy domains alike.** "Self-observing" means every tier is a citizen of
the reflexive loop.

The single load-bearing insight that makes anonymity and everything else *compatible*: a **constant-size
onion cell is simultaneously the unit of unlinkability, the unit of reliable delivery, and the unit of
observation** — and observation is forced to **third order** (cell-aggregate) by a theorem (Fano-blindness,
V11), which is *exactly* the aggregation floor anonymity requires. The geometry reconciles self-observation
with anonymity for free.

---

## 1. The layered reference architecture

One process, `fanos node`, is a stack of sans-I/O engines behind one driver. Reading top-down (what an
app author touches) to bottom (the wire):

```
  ┌── Apps ────────────────────────────────────────────────────────────────────────────────┐
  │  fanos.tunnel (.fanos + SOCKS5/VPN, the reference tenant) · messengers · ledgers · …     │
  ├── SDK (fanos-sdk) ──────────────────────────────────────────────────────────────────────┤
  │  Protocol trait · PortCtx syscalls · #[derive(Wire)] codegen+KAT · C-ABI/wasm bindings    │
  ├── Kernel (fanos-kernel) — the OS split ─────────────────────────────────────────────────┤
  │  PID demux (port = H(manifest)[..4]) · per-PID DHT/sub-plane/sub-epoch · per-PID Lindblad │
  ├── Privacy composition kernel ──────────────────────────────────────────────────────────┤
  │  segments · per-domain lanes · reserved constant-rate cover · non-interference (I1–I9)    │
  ├── Transport: DIAULOS (fanos-diaulos) ───────────────────────────────────────────────────┤
  │  reliable multiplexed byte streams · end-to-end AEAD cells · threshold rendezvous-meeting │
  ├── Control surface (in fanos-quic driver) ───────────────────────────────────────────────┤
  │  Router actor · cloneable Client · FanosStream(AsyncRead+AsyncWrite) · FanosListener       │
  ├── Anonymity dial (APHANTOS) ────────────────────────────────────────────────────────────┤
  │  Direct · Lite (NyxNode onion+mix) · Full (ThresholdRouter line-onion + Poisson + cover)   │
  ├── Substrate (OverlaySubstrate + DIAKRISIS) ─────────────────────────────────────────────┤
  │  PG(2,q) membership · liveness · beacon · L4 DHT · self-observation Φ/P/R · self-healing   │
  ├── Driver (fanos-quic / fanos-sim) ──────────────────────────────────────────────────────┤
  │  QUIC/TLS-1.3 socket + PROTEUS shaping   ‖   deterministic virtual-time simulator          │
  └─────────────────────────────────────────────────────────────────────────────────────────┘
```

Each layer below is the synthesis of the relevant research track. Named components: the connection layer
is **DIAULOS** (δίαυλος, "the double conduit"); the platform split is the **Kernel/Protocol** model; the
reply path is the **threshold rendezvous-meeting**.

---

## 2. The Kernel/Protocol model — FANOS as an operating system

The load-bearing platform decision: **`OverlayNode` becomes a `Kernel` that offers *syscalls*; overlays
become *processes* (`Protocol`s) the Kernel multiplexes.** This costs the wire exactly **one new frame
type** (`App = 0x70`, in the unused `0x7*` group; unknown types are already length-skipped, so every KAT
is preserved).

- **A Protocol is a self-certifying, sans-I/O tenant.** `PID = H(label::PROTOCOL ‖ canonical(Manifest))`,
  a hash-commitment to `{name, MAJOR version, wire-KAT digest, capabilities, grants}` — exactly the ONOMA
  address move (T2). A minor-compatible upgrade keeps the PID (links survive); a breaking change is a new
  PID (a new overlay); migration is ONOMA dual-publish.
- **The port is *computed*, never negotiated:** `PortTag = PID[0..4]`. This beats libp2p's
  multistream-select round-trip — *derive, don't negotiate* (T2), the same move as computed rendezvous.
- **Six primitives + the dial-as-policy** (naming, datagram, DHT, epoch/beacon, groups/threshold,
  self-observation feed) + four **derived** (streams=DIAULOS, pub/sub, RPC, rendezvous/hidden-service).
  The split is principled: a primitive needs the Kernel to *own the coordinate, transport, and cell*; a
  derived primitive is pure logic over syscalls (streams are already standalone in `runtime::stream` —
  proof they belong above the syscall line).
- **`PortCtx` is the capability-scoped syscall surface** — each method pushes a `KernelOp` the Kernel
  lowers to an `Effect`, auto-scoped to the caller's PID and gated by `manifest().grants` (object-capability
  security borrowed from Cap'n-Proto). Determinism is intact: still "collect effects, driver performs them."

**Tenancy = uniform PID-domain-separation (T2), and it is the make-or-break commitment.** *Every*
app-visible mapping is `H(label ‖ PID ‖ …)`: the wire port, the DHT keyspace, the coordinate sub-plane,
the sub-epoch phase, the admission bucket (a `LindbladLoadController` **per PID**), and — decisively — the
coherence sample. Only if tenancy is uniform can DIAKRISIS observe a *protocol* as a first-class object
(§12). If tenancy were bolted on per-primitive, the platform would stall permanently at "multiplexer."

**Non-breaking refactor:** `OverlayNode<F>` splits into `OverlaySubstrate<F>` (membership, liveness,
beacon, DIAKRISIS, shared DHT+datagram) + a built-in **system Protocol on port 0**. Every current test and
the `fanos-proxy` path becomes "the tenant on port 0"; Phase-1 behavior is preserved bit-for-bit while
external overlays get PID-derived ports.

---

## 3. DIAULOS — the connection & stream layer

A connection-oriented, multiplexed, bidirectional byte-stream that runs **inside** the constant-size onion
(its cells are onion `DELIVER` payloads) but keys **end-to-end** (the onion gives anonymity + per-hop KEM,
never a client↔service session). It fills the already-reserved `STREAM_*` / `RDV_*` wire codes.

- **Reuse, don't reinvent.** DIAULOS reuses `runtime::stream`'s selective-repeat + SACK state machine and
  `(stream_id, seq, fin)` / `Ack{cumulative, sack}` vocabulary *verbatim* as the per-stream reliability
  core — three tracks independently reached this conclusion. Three surgical, purity-preserving extensions
  to `stream.rs`: `push()` (open-ended writes, not one-shot payloads), a receiver-advertised `rwnd`
  (backpressure + a bound on the reorder buffer, killing the memory-DoS), and a cell-padding `len`.
- **The cell is the atom** (T-insight). Fixed `CELL_LEN`; one cell = one onion `DELIVER` = one datagram.
  `cnonce(8) ‖ AEAD_{K_dir}(ver ‖ frame ‖ [ack] ‖ pad)` — **per-cell explicit-nonce AEAD** so a lost or
  reordered cell never stalls decryption of the next (no crypto HOL). The multiplex `stream_id` and the
  real `len` live *inside* the end-to-end AEAD — never a cleartext cross-hop correlator (the same reasoning
  that keeps the holonomy tag out of any cleartext header).
- **No head-of-line blocking, the QUIC way.** Independent `StreamSender`/`Receiver` per `stream_id`
  (independent seq/SACK/FIN/`rwnd`); a cell lost for stream A leaves a gap only in A. FANOS gets this for
  free because the overlay is a datagram bus with no substrate-level ordering — a property Tor structurally
  cannot have.
- **Handshake:** a 1-RTT hybrid-KEM (Noise-IK / hs-ntor class) **piggybacked on `RDV_INTRO`/`RDV_REPLY`**
  (zero extra round trips over the computed rendezvous). Service authenticated by `H(bundle)==addr` (ONOMA)
  *plus* a long-term-key possession proof; forward-secret via ephemerals; **re-keyed per epoch** (bounding
  FS in time for long streams).
- **Flow control decoupled from schedule** (§5/§6): `rwnd` is correctness (encrypted, private); the *cell
  schedule* is anonymity. In Full, retransmissions **displace cover cells rather than raise the rate** — so
  even loss is invisible, closing the timing side channel adaptive congestion control fundamentally cannot.

---

## 4. The concurrent control surface — Router · Client · FanosStream

The precondition for a proxy (or any multi-connection app): the single `next_notification` stream cannot
serve concurrent work. The synthesis, with **no change to the pure engine**:

- **A new Router actor** owns the notification stream and the correlation registry; it is the *sole writer*
  (single-writer-by-message, matching the driver's lock-free ethos — no `Arc<Mutex>`).
- **Correlation is derived from content, not invented:** `Get`/`Put` correlate by the public digest
  `hash_labeled(STORAGE, key)` (client-computable, zero engine change); streams correlate by
  `(peer, stream_id)`, the `stream_id` already inside the payload. So **no new `Command`/`Notification`
  variants** — content-addressing is self-correlating (two `Get`s of one key legitimately coalesce).
- **A cloneable `Client`** many tasks share: `get/put` (concurrency-safe, register-before-issue),
  `open_stream → FanosStream`, `listen → FanosListener`, `subscribe → broadcast events`.
- **`FanosStream: AsyncRead + AsyncWrite + Unpin + Send`** — backed by a per-stream *session task* driving
  the (extended) `runtime::stream`. It satisfies the existing `fanos_proxy::Dialer::Stream` bound
  **verbatim**, so `FanosDialer` is a ~15-line adapter and the SOCKS5 proxy consumes it via
  `copy_bidirectional` unchanged.
- **Hot-path invariant:** the Router never `.await`s a client-controlled resource (per-stream forwarding is
  `try_send`), so one saturated stream can never stall another stream, a `Get`, or an event. Leaked waiters
  are reclaimed by a `DelayQueue`; `PeerDown` sweeps a peer's streams; `Drop` deregisters.

`Node::resolve` changes `&mut self → &self` over `client.get(...)`, becoming concurrency-safe in one line.

---

## 5. The privacy composition kernel — heterogeneous privacy done soundly

The user's requirement — different segments anonymous or not, mixed coherently, an *engineering
masterpiece* — is precisely a **non-interference** problem (Goguen–Meseguer) with a **bounded
declassification** channel (DIAKRISIS). The substrate has the anonymity primitives but not yet the
isolation kernel; this is the exact gap between *possible* and *sound*.

**The one defect, nine faces.** Today a node has *no privacy domain*: one input queue, one egress path, one
cover budget, one KEM secret, one reroute/quarantine table, one epoch phase, one DHT namespace — all shared
across flows. Each is a leakage channel (a Direct/plaintext segment B can correlate/deanonymize a Full
segment A via shared timing, cover-starvation, healing-as-oracle, lockstep epoch, or store contention).

**The isolation kernel (the Supervisor is the only enforcer)** partitions per **segment** (a named privacy
domain `{level, isolation_class, key_context, epoch_phase, reserved_rate}`), enforcing testable
non-interference invariants:

| Invariant | Enforcement |
|---|---|
| **I1 constant-rate egress** | a Full domain's emission depends only on its key/epoch/clock, never on another domain's load — *split the single input queue + egress into per-domain lanes* (highest-leverage change) |
| **I2 reserved, non-starvable cover** | Full cover+mix bandwidth reserved, priority ≥ Direct — **add cover to the Full path (ThresholdRouter has none today — a real gap: Full's GPA-resistance is currently *not* what the threat model claims)** |
| **I3 per-domain admission** | a `LindbladLoadController` per domain; a flood in B can't raise cost/latency in A |
| **I4 key/line/epoch domain separation** | a `key_context` label in every KDF; per-segment epoch offset (fixes lockstep rotation) |
| **I5 observe container not contents** | DIAKRISIS ingests only payload-independent signals (liveness, schedule-adherence, threshold-success, report-consistency) for Full domains; exports DP-noised (§6) |
| **I7 line-granular non-leaking healing** | reroute happens *inside* the encrypted line-hop (pick another live line member), never a cleartext coordinate rewrite an observer can confirm |
| **I8 fail-closed admission** | a Full segment runs on a node only if the node *proves* it provides I1–I7 (signed capability), else refuses — never silently downgrades |
| **I9 semantic independence is the app's obligation** | the substrate secures side channels + *covers the level-crossing*; same-principal cross-level temporal correlation is **fundamentally unsafe** (the Zcash round-trip leak) and must be declared |

**Composition theorem (target).** With I1–I7, for every adversary in the Full threat model,
`|AnonSet_eff(A) − AnonSet(A)| ≤ ε = ε_DP + ε_active`, and **ε is independent of B's level, load, and
behavior** — the adversary's view of A is simulatable without B's inputs. Corollary (the boundary): if the
same principal is correlated across levels, no substrate invariant suffices — hence *cover the crossing*
(constant-rate, amount-hidden) and force declaration. Hierarchically ε composes like `ε → ε·9^d` — **the
same `1/9` constant that bounds healing depth bounds privacy-composition depth** (T1).

**Counterintuitive, correct result:** co-residency with enforced I1–I7 yields a *larger* anonymity set than
physical separation (a Full-only node set is small and its membership is itself a leak). Isolation, not
separation.

---

## 6. The coherence through-line — and the honest answer to "is the Lindbladian real?"

This section makes T1 concrete and settles the sharpest question: is "Lindbladian control" a real mechanism
or a rudiment imitating dynamics?

**It is a real mechanism — with one wiring gap to close.**

- **The dissipative operator is genuinely computed, not tuned.** DIAKRISIS builds a real coherence matrix
  `Γ_net = C/N` (`Tr Γ = 1`, a bona-fide density) from actual node correlations, and computes the **exact
  spectral gap** `Δ = (G − max_k T_k)/6` (theorem T-226(v)) from the cell's seven measurable Fano-line
  rates — the relaxation rate of the slowest polar mode. `τ = 1/Δ` is the healing time. `Φ/P/R` are
  verifier-pinned (V15–V18). This is the opposite of imitation: the network measures its own density and
  computes its own relaxation rate from its own structure.
- **The load controller is the honest classical shadow of that operator.** The leaky integrator
  `x_{n+1} = (1−Δ)x_n + max(0, arrived−target)` *is* the equation of motion of one observable under
  dissipative relaxation to a steady state at rate `Δ` (the diagonal/single-mode limit) — the *form* is
  load-bearing: it yields the bounded fixed point (no runaway) and the `∝C³` attacker cost, both proven and
  tested.
- **The gap:** in the code today `Δ` (`dissipation`) is a *constructor parameter*, not fed from
  `regeneration::spectral_gap`. So the claim "the same `Δ` as healing" currently holds by *convention*, not
  by *wiring*. **The fix** (a real, high-value change): feed the rendezvous line's cell spectral gap into
  the controller, discretized `dissipation = 1 − e^{−Δ·Δt_window}`. Then admission-relaxation and healing
  time are two observables of **one** Lindbladian relaxation at **one** computed gap — not two controllers
  with two tuned constants. This is *derive-don't-tune*, closed.

**The same `Δ`/`Φ`/`R` then run the whole stack** (T1): per-domain admission pricing (§5 I3); DIAULOS's
retransmit **RTO as a public, epoch-derived constant `k·L/μ`** (not a per-flow RTT measurement — closing
the last timing side channel, §3); node **readiness `Φ≥1 ∧ R≥1/3`** (an integrated, self-observing subject
— a proof, not a tuned threshold); coherence **reputation**; (Phase 6) **consensus-via-coherence**; and
**isolation-coherence** (§5 made homeostatic). One quantity, every tier.

**Self-observation stays anonymity-preserving** because the observable is *third order* by theorem: a
pairwise heartbeat mesh is **Fano-blind** (the 7 line-adjacencies sum to `J−I`, `K₇` spectrum {6, −1×6},
V11), so structure first appears at cell-aggregate — which is exactly the anonymity aggregation floor. The
exporter enforces a **cell-granularity floor** (per-node signals never leave the node; the fold into `Γ` is
the anonymization) and **DP-noises** exports (favorable: one flow's effect on `r` is `O(1/21)`, low
sensitivity). Healing telemetry is **self-blinding** (constant-rate, content-independent, encrypted). The
one honest residual — an active adversary perturbing a flow and reading the aggregate — is *bounded* (not
zeroed) by sub-threshold margin + DP noise + heal-action rate-limiting.

---

## 7. The SDK — Protocol, wire codegen, bindings

- **The `Protocol` trait** desugars to `Engine` (inheriting determinism, replay, the simulator): typed
  `Message/Command/Event`, `on_message/on_command/on_timer`, and one optional hook —
  `activity_signal() → Option<f64>` — that folds the protocol into `Γ_net`, unlocking native observability
  for *any* app. `Cx` gives `send/rendezvous/line_members/arm_timer/emit/profile`.
- **Schema-driven wire codegen — the interop killer.** A `.fanos` IDL + `#[derive(Wire)]` emits, from one
  source: the Rust canonical codec (reproducing the KAT rules), **the KAT vectors themselves**
  (`conformance/vectors/<proto>.json`), and optional cross-language stubs. Beats protobuf/Cap'n-Proto:
  interop is *"pass the KATs,"* machine-checked, not *"trust the .proto."* This makes the design.md §12 law
  — *interoperation = selection* — turnkey.
- **Bindings via sans-I/O:** `fanos-ffi` (the stable C ABI, spec §11.2) → UniFFI auto-generates
  Swift/Kotlin/Python/Ruby; a wasm component model hosts **untrusted third-party overlays** in a memory-safe
  membrane (strictly stronger than in-process; a capability libp2p/IPFS lack). The wasm build of `fanos-sim`
  is an in-browser deterministic playground.

Deployment tiers by trust: in-process (first-party, max-perf) · wasm component (untrusted) · C-ABI sidecar
(any language, the I2P-SAM position).

---

## 8. The developer platform — determinism × self-observation

Three products collapse into the two native assets: **the devnet is production** (`fanos-sim` drives the
byte-for-byte `Engine`), **observability is intrinsic** (DIAKRISIS already computes the network's health),
and **time-travel debugging is a determinism contract** (`(seed, inputs) → byte-identical run`).

- **`fanos dev`** — a deterministic local devnet + live Coherence Observatory + reified fault vocabulary
  (`Scenario::{CATASTROPHE, BYZANTINE, CASCADE}` reusing the shipped suites; Byzantine faults are *raw
  forged frames*). A third-party protocol inherits the catastrophe/Byzantine suites and the cascade
  **forecast** for free — *"your protocol will cascade in N ticks"* is a number no other devnet can produce
  (none carries a coherence matrix).
- **The Coherence Observatory** (a self-contained dashboard/Artifact): `Φ/P/R` gauges with theorem-fixed
  bands, the cascade meter with the `r* = 1/√6` early-warning line, the Fano-cell syndrome heat-map, the
  healing timeline. OpenTelemetry is the *export syntax* (Grafana/Tempo/Datadog day one); the third-order
  self-model is the *source of truth* — external pairwise monitoring is provably weaker (Fano-blind) and
  redundant.
- **Incident forensics by replay:** journal each node's `(seed, ordered Inputs)`; `fanos replay` reproduces
  the bug **bit-identically** (including DIAKRISIS verdicts) — Temporal/rr replay *for free* from sans-I/O,
  and forecast-gated postmortems ("the alert fired 40 ticks before the outage").
- **Observability-driven development:** your `fanos test` assertions (`Φ≥1`, `forecast.lead()>0`) *are* your
  Kubernetes readiness gate and your production SLOs — the same self-model grades the test and monitors prod.
  CI can fail a merge that *shortens the network's cascade warning horizon*.

---

## 9. The extended invariant set

The nine invariants of `design.md §3` stand; the platform adds five (each testable, per invariant 9):

10. **Coherence is the one quantity.** Monitoring, admission, transport RTO, readiness, reputation,
    consensus, and isolation-health all read `(Φ, P, R, Δ)` at some tier. New controllers derive their
    constants from the computed spectral gap, never a tuned one.
11. **Derive, don't negotiate.** Any mapping computable by `H(label ‖ id ‖ …)` — port, key, coordinate,
    epoch, rendezvous — is *derived*, not handshaked. Negotiation (capability §12) is only for
    versions/features/privacy-floor, never addressing.
12. **Uniform PID-domain-separation is the only tenancy mechanism.** Every app-visible boundary is the same
    hash-scoping move, so the reflexive plane can observe protocols as objects.
13. **Non-interference across privacy levels.** A lower-privacy segment cannot lower a higher one's
    anonymity beyond ε; the substrate secures side channels and covers the level-crossing; semantic
    independence is the app's declared obligation.
14. **Observe the container, not the contents.** Telemetry is cell-aggregate (third order), payload-
    independent, DP-noised, and self-blinding — monitoring is never a deanonymization oracle.

---

## 10. Honest gap register & the evaluation rubric

The adversarial track surfaced concrete defects in the *current* code — recorded here so the design is
falsifiable, not decorative:

- **Epoch type skew** — `u32` (rendezvous/balance) vs `u64` (descriptor/onoma/resolve). A live correctness
  landmine: rendezvous line and descriptor slot rotate on different-width counters. *Reconcile to one type.*
- **Full has no cover** — `ThresholdRouter` emits no cover traffic, so Full's global-passive resistance is
  currently *not* what §6 claims. *Add reserved constant-rate cover (I2).*
- **Lindblad unwired** — `LindbladLoadController` exists but isn't fed real load or the computed `Δ` (§6).
- **`stream.rs` is one-shot** — needs `push`/`rwnd`/`len` before it is a socket (§3).
- **Single notification stream** — no concurrency; needs the Router/Client refactor (§4).
- **Telemetry plaintext** — no auth, DP, or cell-floor (§6); the observatory's raw-volume `Γ` input is
  forbidden for Full nodes.
- **No segment/tenancy concept** — the privacy kernel and Kernel/Protocol split are green-field (§2, §5).
- **Residual (documented, not a defect):** the threshold-splice combiner and on-path relay learn their own
  layer length (Sphinx-filler gap); a re-randomizing splice is the `[P]` frontier.

**Evaluation rubric** (score competing designs; a `0` on any **gate** rejects regardless of total):
endpoint-unlinkability-through-the-data-plane `[gate]`, bidirectional-without-deanonymization `[gate]`,
flow-shape-resistance-for-Full `[gate]`, epoch-straddle-correctness `[gate]`, bounded-server-state-under-flood
`[gate]`, sans-I/O-determinism `[gate]`, honest-dial `[gate]`; then incremental-streaming, congestion+fairness,
HOL-isolation, cell-occupancy, reliability-at-one-layer, forward-secrecy-bounded. Each is an executable test.

---

## 11. Phased implementation plan (non-breaking)

Ordered so each step is independently valuable, gated, and preserves shipping behavior:

1. **Reconcile the epoch type** (u64 everywhere) + **wire `Δ` from `spectral_gap` into the Lindblad
   controller** (§6). Small, closes a real bug + the "rudiment" gap.
2. **Extend `runtime::stream`** with `push`/`rwnd`/`len` (pure, in-place; simulator unaffected).
3. **The control surface** — Router actor + cloneable `Client` + `FanosStream`/`FanosListener` in the QUIC
   driver; `Node::resolve → &self` (§4). Unblocks all concurrency.
4. **DIAULOS** — new sans-I/O `fanos-diaulos` engine: cells, 1-RTT handshake, the threshold
   rendezvous-meeting reply path; `FanosDialer` slots into `fanos-proxy` unchanged (§3). *SOCKS5 → `.fanos`
   works end-to-end here.*
5. **The Kernel/Protocol split** — `OverlaySubstrate` + system-Protocol-on-port-0 + the `App = 0x70`
   envelope + PID demux + per-PID DHT/epoch/Lindblad; `fanos-sdk` (`Protocol`/`Manifest`/`PortCtx`) (§2, §7).
6. **The privacy kernel** — per-domain lanes (split the queue), reserved Full cover, reroute-inside-hop,
   key/epoch/store domain separation, segment manifest + capability negotiation + fail-closed (§5).
7. **Telemetry** — authenticate + encrypt + DP + cell-floor; `fanos-telemetry` OTel export; the Observatory
   (§6, §8).
8. **DevEx** — `fanos-harness`, `fanos dev`, `#[derive(Wire)]` codegen + KAT gen, `fanos replay`, bindings
   (§7, §8).
9. **The multi-node cell test harness** *(delivered)* — a driver seam to pin coordinates so a full 7-node
   F2 cell runs over real QUIC (self-certifying coords are random today), enabling e2e store/rendezvous
   tests. Implemented as `fanos-quic::spawn_cell` (rejection-sampled self-certifying credentials, not a
   backdoor) with `tests/cell_e2e.rs`; the full verification ladder and the byte-identical-replay
   contract are documented in [`design-testing.md`](design-testing.md).

The reference tenant `fanos.tunnel` (SOCKS5/`.fanos`, then VPN, then exit) rides on top and special-cases
nothing.

---

## 12. The recursive apex — предельное идейное масштабирование

At its logical limit FANOS is a **universal coherent substrate** where every networked artifact — a name, a
message, a stream, a store, a group, a ledger, *and another overlay* — is a `Protocol` on one self-observing
plane, **and the plane observes the protocols the way it observes nodes.**

The recursion is exact and already latent: DIAKRISIS reads `Γ_net` over 7 nodes and heals; `ParentCell`
runs the same loop over 7 child cells; apply the dimension shift once more and run it over a `PortTag`-indexed
coherence matrix `Γ_app` of inter-overlay correlations. Then an overlay inducing cross-tenant correlation is
**Decoupled** exactly as an over-coupled node is; an incoherent overlay is **Escalated**; admission,
reputation, and (Phase 6) consensus read the *same* `Φ/P/R` over overlays that they read over nodes. The two
adaptation clocks — fast homeostasis and slow selection — range over the **application ecology** itself: the
network evolves which overlays thrive by the same reflexive selection it uses for wire features and node
health.

**The one decision that determines whether it gets there** is invariant 12: that PID-uniform
domain-separation is the *only* tenancy mechanism, so a protocol is a uniformly-measurable object. Everything
in this document is built from that one move on purpose.

**The one-sentence differentiator:** every other platform bolts a stack, an anonymity layer, an
observability system, and a devnet *onto* a network that cannot see itself; FANOS *is* a network that sees
itself — so its transport, its privacy composition, its tenancy, its monitor, its debugger, its readiness
gate, its reputation, and its consensus are **one coherence quantity measured at every tier**, deterministic,
theorem-fixed, and anonymity-preserving by the geometry.
