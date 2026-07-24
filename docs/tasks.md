# FANOS — task list

> **STATUS (2026-07-22): the protocol reference implementation is COMPLETE, verified, and hardened.**
> Every roadmap milestone **M0–M10** (Part XV) is implemented across the 33 crates; the full workspace test
> suite is green and every crate is clippy `--all-targets -D warnings` clean; a subsequent hardening pass
> bounded all per-flow maps, closed a C-ABI UB edge, de-flaked the gate, and audited to correct code.
> **What remains below is by design** — optional application layers, research-gated `[P]` theory, and an
> OS-syscall shell that can't run in CI. None of it is a protocol gap; each needs a decision or research, not
> autonomous grind. Full landed history: this file's lower section + `git log`.

> Note: the **Claude Code todo panel** (`◼/◻`) is a separate list; this session's toolset has **no**
> todo-editing tool, so **this file is the accurate status**. There are **no** in-code `TODO`/`unimplemented!`
> markers anywhere in `rust/crates` (verified) — the source carries no deferred work.

---

## 🏛 PLATFORM TRANSFORMATION — IN PROGRESS (2026-07-22, user directive)

**FANOS is now a holonic PLATFORM, not just a protocol** — a maximal-anonymity mixnet (E-machine) composed
with a high-speed private post-quantum L1 blockchain (L-machine) into one meta-holon, grounded in HOLARCH.
Design authority: **`spec/platform.md`** (the E∧L synthesis, the 4 viability invariants as release gates, the
subsystem specs). `protocol.md` reframed; all docs made consistent (FANOS=platform).

Roadmap (`spec/platform.md` §8), sequential + verified:
- [x] **T1 · TAXIS live (L8)** — consensus over real QUIC, App-overlay receive seam, live checkpoint publishing
      (this session). Residual: two-cell parent-attests-child loop; `Node::start` config.
- [~] **T2 · OBOLOS (L10) — the untraceable PQ currency (crown jewel)** — crate `fanos-obolos` (crate 36):
      - [x] Untraceability accounting — commitment tree (whole-pool membership) + nullifiers (`fb0…`/tree+nf).
      - [x] Confidentiality — BDLOP-style homomorphic lattice value commitment (balance without revealing amounts).
      - [x] Shielded tx + verified state machine — `ShieldedProof` interface ([P] ZK seam) + `TransparentProof`
            reference; `ShieldedState::apply` gates (anchor/double-spend/proof); mint issuance.
      - [x] Wallet `build_transfer` + **SecOps scenario suite** (conservation, tampering sweep, wraparound
            inflation, cross-tx double-spend, consolidation, whole-pool anonymity set).
      - [x] Canonical wire codec (ShieldedTx + proof + submission payload) — unblocks the chain integration.
      - [x] **Unlinkable delivery** (`note_cipher`): ML-KEM note ciphertexts, on-chain (`OutputNote.cipher`) +
            `build_transfer_delivering` + `scan`. All THREE privacy properties now hold: confidentiality
            (homomorphic commitment) ∧ untraceability (whole-pool + nullifiers) ∧ unlinkability (hidden-owner
            commitments + fresh-KEM delivery — no key-blinding needed, Zcash-Sapling model).
      - [x] **Bidirectional shield/unshield bridge** (`dromos::bridge`, `ShieldedTx.public_value`) — value flows
            both ways between the public token ledger and the private pool (a keyless POOL_SINK backs the pool;
            shield = signed transfer→sink + mint; unshield = shielded spend with a public output → system move
            from sink). Shield for privacy, unshield to pay public fees.
      - [ ] Residual: the PQ **zero-knowledge** proof backend (the one frontier [P]/[H]); calibrate the lattice
            params + external audit.
- [~] **T3 · DROMOS (L9)** — crate `fanos-dromos` (crate 37):
      - [x] `ShieldedLedger` — the OBOLOS pool as a TAXIS `StateMachine` (shielded transfers execute on-chain).
      - [x] `HybridLedger` — transparent accounts + shielded pool under ONE `state_root` (tagged txs dispatch to
            each half). **Public value and private value coexist on one chain.**
      - [x] **FULL-PLATFORM e2e** (`fanos-node/tests/dromos_quic.rs`) — a PRIVATE OBOLOS transfer executes over
            live TAXIS BFT consensus over real QUIC (7 nodes converge: note nullified + created, ~2.2s). The
            E∧L composition proven runnable end-to-end.
      - [ ] Residual: the parallel post-reveal scheduler (proven-deterministic serialization) for Solana-class
            throughput; transparent-tx wallet/CLI ergonomics.
- [~] **T4 · ONOMA-domains + ANGELOS (L11)**:
      - [x] **Authenticated token ledger** (`dromos::token`) — signed transfers, key-bound accounts (the
            payment substrate the reference Accounts omits). A `begin_block` clock hook was added to the TAXIS
            `StateMachine` (default no-op) to give height-dependent rules a canonical clock.
      - [x] **Currency-bought naming** (`dromos::naming`) — `NameRegistry`: register/renew/update/transfer,
            each a signed fee-paying op to a treasury; length-tiered price + expiry = anti-squatting.
      - [x] **Full hybrid ledger** — `HybridLedger` now carries tokens + shielded pool + names under one
            `state_root`, names buyable over LIVE consensus (dromos_quic e2e). Public + private + naming on one chain.
      - [ ] Residual: ANGELOS (anonymous PQ messenger — compose NYX/CALYPSO/DIAULOS/ONOMA); name→descriptor
            resolution wired to CALYPSO/OBOLOS/ANGELOS endpoints.
- [ ] **T5 · HERMES (L12)** — PQ threshold cross-chain (atomic-swap mode first, custody second).
- [ ] **HOLARCH gate** — a Γ-calculator that CI-checks the platform's P/R/Φ/D viability verdict.

---

## ⬜ What's left (anonymity substrate)

### 0 · Fundamental deepening pass — IN PROGRESS (2026-07-22, grounded in UHM/holon theory)
Post independent-crypto-audit + honest-landscape-comparison. Implementing the best fundamental solution at
every level, verified against the UHM coherence/viability/holarchy theory. Sequential:
- [x] **Self-organizing role assignment** — `fanos-core::roles` (network assigns *function*, not just position).
- [x] **Live role loop** — sans-I/O `RoleController` with a UHM-grounded Lyapunov-descent demand controller
      (κ ∈ [1/7, 1], V=(D−setpoint)² contracts (1−κ)² per step, proved in code) + deficit→parent escalation.
      Residual: the thin `fanos-node` driver (capability-descriptor advertisement + per-role load metering).
- [x] **Executed-state checkpoint** — `fanos-taxis::checkpoint`: Q-quorum ExecCertificate over (height,
      state_root); divergence is now detectable (`conflicting`), not a silent fork.
- [x] **Cross-cell transaction proofs** (L0) — `fanos-taxis::crosscell`: destination verifies source
      ExecCertificate + state_root opening + Merkle inclusion; no bridge trust.
- [x] **Parent-attests-child-finality** (L0 shared security) — `fanos-taxis::hierarchy`: verify + anchor child
      ExecCertificates, DA-gated, with child-equivocation detection.
- [x] **TAXIS residuals** — equivocation-detection → `Output::Slash` wired into `accept_vote` (the S>0 the
      Nash proof assumes is now operational); deterministic anti-MEV execution via a finalized-height-keyed
      `REVEAL_WINDOW` drop (undecryptable/withheld tx dropped uniformly, checkpoint catches any divergence).
- [x] **WASM/mobile client surface** — new `fanos-wasm` crate (35th): compute + verify a node's self-organizing
      coordinate in the browser; native-tested + builds to wasm32-unknown-unknown warning-free.

**Deepening pass COMPLETE (2026-07-22).** All items above ✅, plus proven end-to-end in the simulator:
- [x] **Self-organization end-to-end sim** (`fanos-core/tests/self_organization.rs`) — a 13-node cell where
      every node runs its own controller in LOCKSTEP (deterministic role consensus, no coordination),
      homeostatic convergence, rotation, capability-honesty, and deficit→parent escalation.
- [x] **Multi-cell L0 end-to-end sim** (`fanos-taxis/tests/multicell.rs`) — a burn-and-mint cross-cell transfer
      through REAL consensus: cell A certifies + emits, cell B verifies the receipt (no bridge trust) + mints,
      a parent anchors both finalities.
- [x] **Signed capability descriptor** (`roles::CapabilityDescriptor`) — the authenticated self-org loop input
      (VRF-signed), so a node cannot forge another's capabilities.

### 1 · Full open-task programme (sequential, 2026-07-22)

**A · Self-organization live wiring — ✅ DONE.**
- [x] A1 `fanos-node::capdir` — publish/read signed `CapabilityDescriptor` over the overlay store (mirror mixdir).
- [x] A2 `fanos-node::role_loop` — the live driver: each beacon, gather directory + step controller + assign.
- [x] A3 `fanos-core::roles::{LoadMeter, cell_setpoint}` + `fanos-node::loaddir` — per-role load → agreed setpoint.
- [x] A4 `fanos-core::roles::Reputation` — performance-decay of a non-performer's effective weight, wired in.
- [x] `spawn_self_organization` — the single Node::start entry point (3 tasks + assigned-roles watch).
- [ ] Residual: dynamic actuation — Node::start behaviors react to the assigned `RoleSet` (start/stop as it
      rotates), replacing the fixed `config.roles` gating; feed reputation from the diagnosis.

**B · L0 live multi-cell orchestration — live single-cell DONE (2026-07-22); multi-cell residual.**
- [x] **Live TAXIS over real QUIC** (`3ac8cfc`) — `fanos_node::spawn_taxis`: side-car driver bridging the
      sans-I/O `ConsensusEngine` to a node's `Client` (App-`0x70`-frame receive via the new `Notification::App`
      seam `b7fb4e9`; broadcast fan-out + self-delivery; Tick/Timeout; ledger snapshot). A crypto-free drainer
      task makes the lossy `subscribe()` broadcast lossless for the engine (fixed finality stalls). Real 7-node
      QUIC test: seal→propose→prepare→commit→reveal→execute an anti-MEV tx to unanimous ledger agreement, ~2s.
- [x] **Live checkpoint publishing** (`c97ddc6`) — `spawn_checkpoint_publisher` publishes each new
      `ExecCertificate` to the cell's `crosscell_dir` slot; the test resolves + verifies it (cross-cell producer).
- [ ] Residual: the full multi-cell loop (two real TAXIS cells, parent `attest_children` over live children);
      `Node::start` config wiring (a runnable `fanos` consensus node); executed-`state_root` history in the header
      for light clients; per-epoch committee rotation (the driver runs a fixed epoch — beacon sub is wired).
**C · TAXIS residuals — ✅ DONE (2026-07-22).**
- [x] Wire fee/reward distribution (`564c789`) — `Output::Reward`, `distribute` among commit-cert signers.
- [x] In-engine DA sampling (`c9e5c63`) — `Input::Propose` carries sampled `DaShards`; `on_propose` verifies
      availability by `reconstruct_payload` vs `da_commit` instead of trusting a driver bit.
- [x] On-chain decryption-key commitment (`3757192`) — `keyper::{KeyperKeyCert, KeyperRegistry,
      seal_to_keyper_line}`: self-certified KEM keys, `commit()` (agreed genesis constant), engine
      `accepts_keyper_registry`; the Shutter/Ferveo on-chain key, PQ-native (authority, not pre-open verifiability).
- [x] Extend the equilibrium model (`fd56942`) — coalitional (≤ f) + censorship: `blocking_threshold`,
      `can_permanently_censor`, `coalition_best_response_is_honest`; machine-checked exhaustively; design §4.
**D · PQ shuffle** — splitting-ring NIZK (eprint 2025/658) or a re-parameterized worst-case-sound RLWE backend.
**E · WASM/mobile** — wasm-pack build + browser demo; extend the wasm surface; a real client (WebSocket/WebRTC).
**F · Architecture refactor** (#73) — split fanos-runtime; decompose OverlayNode; typed StorageAddress; secret-field encapsulation.
**G · Deployment & audit** — live multi-machine deployment; real-NAT harness; external crypto audit; E4∩E5 live driver (#54).

### A · Optional application layers — ✅ DONE (2026-07-22)
- **Part X.1 — the blockchain application on FANOS** — ✅ **DONE**: new crate **`fanos-taxis`** (`854feef`),
  the FANOS-native BFT blockchain. Projective-cell PBFT consensus (proved a masking-quorum system: `n=q²+q+1`,
  `f=⌊(n−1)/3⌋`, `Q=⌈(n+f+1)/2⌉`; tight `n=3f+1` for `q≢1 mod 3`, incl. the Fano cell 7/2/5), beacon leader
  election (cartel-proof by the `(q+1)/n` centrality cap), **anti-MEV** threshold-encrypted mempool (reuses
  `ThresholdSealed`; proposer orders blind, keyper line reveals post-commit), **DA-sampled** blocks (projective
  LRC + line sampling gates finality), sans-I/O engine, App-overlay wire. Verified by a 7-node BFT sim
  (finality+execution, `f=2` crash-liveness, DA-withholding rejection, Byzantine safety). `docs/design-taxis.md`.
- **L7 incentive equilibrium** — ✅ **DONE** (`a60ab73`): `fanos-taxis::incentive` + `docs/design-incentive-
  equilibrium.md` close the §16 open problem — a machine-checked proof that honest validation is a Nash
  equilibrium under C1 (`R=F/Q≥c`) ∧ C2 (`S>0`), clean because anti-MEV + BFT-safety + DA-gating zero the gain
  of every deviation. Reward distribution, equivocation-slashing proofs, and context-bound VOPRF fee credits.

### B · Research-gated — ✅ fundamental theory closure DONE (2026-07-22); residuals noted
- **Holonomic ratchet + Tessera security** — ✅ **DONE** (`08e07dd`): the ratchet was a front-keyed cascade
  (length-extendable); added a length-binding NMAC finalization → a provable keyed MAC, EUF-CMA reducing to
  BLAKE3-PRF, with a deterministic attack experiment over every tamper class (`docs/design-holonomy-security.md`).
  Tessera onion confidentiality/integrity reduced to hybrid-KEM-IND-CCA + AEAD + BLAKE3 (`docs/design-tessera-
  security.md`). Residual: only the *machine-checked mechanization* (proof-assistant artifact) — the reductions
  are its spec.
- **PQ-VRF / PQ beacon / PQ shuffle** — ✅ **DONE** (`fca1aad`, `1050711`, `bb429f0` Hand-roll-full): (1)
  Merkle-VRF — PQ, unique, unbiasable — + full-reveal beacon (`pqvrf`); (2) **reconstruction-unique** threshold
  beacon (`pqvss`): committed Shamir + all-`t`-subsets consistency, novel/unaudited; (3) **verifiable shuffle**
  (`shuffle`): Sako–Kilian cut-and-choose **generic over a `ReRandomizable` trait** (hash-only proven
  impossible), with TWO backends — `ElGamal` (ristretto, classical) and **`rlwe::Rlwe` (Ring-LWE,
  post-quantum)**; the same proof runs over either. Novel/unaudited. `docs/design-pq-vrf.md`.
- **D6 quarantine theorem** — ✅ **DONE** (`653a9c3`): derived `Φ' = (N·Φ − 2s_q)/(N−1)`, so quarantine lowers
  Φ iff `s_q > Φ/2`; implemented the gate + simulation experiment (`docs/design-quarantine-theorem.md`).
- **GF(2^m) constant-time** — ✅ **DONE** (`b563f9a`): mul is branchless, inv is fixed-exponent Fermat →
  secret-independent; deterministic op-count experiment proves it (`docs/design-constant-time.md`).
- **Parent-observes-child hierarchy recursion (#95)** — ✅ **DONE** (`2b66064`): DIAKRISIS recurses up the
  cell hierarchy (child cells as the parent's nodes) — `fanos-diakrisis::hierarchy` localizes a failing child
  by the same §6.3 grey endpoint, the fault propagates up (`cell_loss`), the integration alarm recurses; a
  2-level recursion experiment validates it. `docs/design-hierarchy-recursion.md`.
- **Residual open pieces are now ONLY external processes, not design/implementation**: `pqvss`/`shuffle`/`rlwe`
  external cryptanalysis and calibrating/adopting a *vetted, hardened* RLWE backend (the built one uses
  illustrative params). Everything is built + reduced + tested; the RLWE proof is noise-agnostic so only the
  backend needs hardening. External audit is, by definition, not an in-house task.

### C · Honest fundamental limits (Part XVI) — not defects, not closeable
- `f→0.5` endpoint-majority limit; single-cell DIAKRISIS localization stratification (crashes ≤3, Byzantine
  ≤2); the coherence `[И]` axis↔sector dictionary is a self-checking *model*; third-order statistics are
  data-hungrier; threshold↔availability is a calibration trade-off. All correctly stated in the spec; nothing
  to "fix" — they are the honest boundaries of the design.

### C · Runtime-only verification — built + compiles/lints clean, but the OS-syscall shell can't run in CI
- **TUN device I/O** (`fanos-vpn`, feature `device`; `fulltunnel.rs` + `device.rs`) — the datapath/engine/mux
  are unit-tested with mocks; the real `tun` syscalls are verified on a host, not in the gate.
- **Real-NAT socket-filter test harness** — the NAT-traversal logic (#119) is complete and tested against
  simulated NATs; a harness exercising real OS NAT/firewall filters is the only residual.

> **Two former "frontier" items were phantom gaps — already realized + tested, kept here as the record:**
> **Maekawa W∩R quorum** is the erasure store's versioned full-fan-out read (a superset of any line-quorum →
> trivial `W∩R≠∅`, plus LRC durability; `sim/tests/storage.rs`), founded on `fanos-geometry::
> dual_any_two_lines_intersect` (V1) — strict multi-writer linearisability is unneeded (keys are
> single-writer). **VOPRF credit settlement** is the ristretto255 primitive (`fanos-incentives`:
> blind→DLEQ→unblind, B8 context binding, B4 nonce, double-spend) paying for a CALYPSO introduction exactly
> once (`sim/tests/paid_intro.rs`); mix-relay forwarding payment is the L7-opt economically-open part above.

## ✅ Landed (recent frontier history — full record in `git log`)

**`fanos vpn` FULL-TUNNEL (TCP + UDP) — the VPN is complete** (Phase 5, §11.4) — `fulltunnel::run_fulltunnel`
(feature `device`): a userspace TCP/IP stack (`ipstack`) terminates every TCP/UDP flow at the TUN and bridges
it to a FANOS exit — TCP over `Dialer::dial` + `copy_bidirectional`, UDP over `dial_udp` — reusing the exact
`Dialer`/`UdpDialer` seams the SOCKS5 proxy uses (same `FanosDialer`-with-exit). The `fanos vpn` CLI now runs
full-tunnel; `--features vpn`. ipstack does the TCP state machine, so the bridge is thin glue; clean clippy
both with and without the feature, default 13 tests unchanged. The hand-rolled UDP datapath stays as the
stack-free lightweight alternative. Full-tunnel completes Phase 5. ·
**VPN datapath engine — the UDP/DNS mode** (Phase 5, §11.4) — NEW crate `fanos-vpn`: the sans-I/O routing
brain of `fanos vpn`, following the node's engine/driver split. An IPv4/UDP packet codec (`packet.rs`:
parse + build with valid IPv4-header and pseudo-header UDP checksums, index-free parsing) and the flow
engine (`engine.rs`: `classify` an inbound TUN packet → `VpnAction::RelayUdp{flow,payload,is_dns}` keyed on
the 4-tuple, or `Drop` for TCP/IPv6/malformed; `response_packet` rebuilds an exit response into a TUN packet
with endpoints swapped). "UDP mode" (design.md §11) needs no userspace TCP stack — this tunnels DNS + UDP
(QUIC/…). Verified with synthetic packets: checksums verify, build↔parse round-trips, classify/drop, and a
swapped-endpoint response round-trip. **Runnable end to end**: a real `tun` device adapter (feature `device`)
+ the `fanos vpn` CLI (feature `vpn`, wiring device ↔ `run_vpn` ↔ a `FanosDialer`-with-exit) — the OS device
I/O is runtime-only-verified, the rest compiles/lints clean both with and without the feature. Plus the
**multiplexer** (`mux.rs`, `run_udp_datapath`) — the driver's
stateful core: relay each flow over a per-destination exit tunnel via the **shared `UdpDialer`/`UdpTunnel`
seam** the SOCKS5 UDP-ASSOCIATE relay uses (so VPN + proxy share one exit-UDP abstraction, same `FanosDialer`
impl), and pump responses back as TUN packets. Verified with a mock dialer: a DNS query and a QUIC flow each
relay out and round-trip back as TUN packets; TCP drops. The thin TUN device driver + TCP mode remain. ·
**C ABI — service hosting → the §11.2 surface is COMPLETE** (#113, M9) — `fanos_service_host(node, seed,
addr_out, cap)` derives a stable service identity from a seed, hosts it (forwarding each accepted DIAULOS
session onto an accept queue over the closure-based `serve`), publishes its descriptor, and returns the
`.fanos` name; `fanos_service_accept` blocks for the next incoming `FanosStream*`; `fanos_service_free`.
Verified over **real QUIC**: A hosts a service through the C ABI, B dials it by name, and a payload
round-trips client→host→client entirely across the FFI. The C ABI now covers all §11.2 operations
(lifecycle, storage, health, client streams, service hosting). ·
**C ABI — hidden-service client streams** (#113, M9, §11.2) — `fanos_service_connect(node, "<addr>.fanos")`
resolves the name over the overlay (`NodeResolver`) and dials a DIAULOS byte stream, returning an opaque
owning `FanosStream*`; `fanos_stream_read`/`_write` (blocking, driving the async stream on the node's
runtime via a cloned `Handle`) / `_free`. The dial runs inside the runtime context (`Runtime::enter`) so its
`tokio::spawn` bridge lands correctly. Verified over **real QUIC**: node B resolves + dials node A's
published echo service by name and a payload round-trips through the C-ABI stream (2-node, serialized +
retry-bounded). Header + null-safety extended. Service *hosting* is the last surface. ·
**C ABI — the embedding foundation** (#113, M9, spec §11.2) — NEW crate `fanos-ffi`: a stable `extern "C"`
surface (`crate-type = staticlib/cdylib/rlib`, hand-synced `include/fanos.h`) over the node so any language
reuses the core. Slice 1: lifecycle (`fanos_open` from a config string / `fanos_join` / `fanos_free` — an
owning tokio-runtime+node handle), storage (`fanos_publish`/`fanos_lookup` with the buffer-too-small
retry convention), and `fanos_diagnose` health. Every deref is null-guarded with a `# Safety` contract.
Verified: a publish→lookup value round-trips through the C ABI (+ short-buffer path), bad config → null,
null handles rejected, all off-network. Streams/services are the next slice. ·
**PROTEUS pluggable-transport SPI** (§13.3 `pluggable`, M10) — `MorphCodec` trait: an embedder's custom
codec fully replaces the built-in transform (`ProteusShaper::with_codec`, `ProteusConfig::pluggable`), the
honest home for real cover-protocol tunnels (tls-tunnel/masque/fronted need external stacks, §13.8 — never
faked). `set_morph` back to a built-in morph restores the built-in codec. Verified at the crate level (a
mock codec round-trips, the built-in decode rejects it) and over **real QUIC** (two nodes deliver under a
pluggable codec). This completes the PROTEUS morph catalogue (codec + traffic-shaper + auto-fallback + SPI). ·
**PROTEUS morph auto-fallback — live** (§13.7) — `MorphController` circuit breaker (K consecutive connect
failures trip a rotation through the environment chain, a success resets it) + `ProteusShaper::set_morph`
(runtime profile swap; the codec-using morphs share a codec, so rotation is decode-compatible and local —
no peer renegotiation). Wired into the fanos-quic driver: `ProteusConfig::auto(secret, env)`, connect
outcomes recorded in `get_or_connect` (a censored morph surfaces as connect timeouts), rotation installs
the new morph on the live shaper (`apply_outcome`, unit-tested off the network). Node knob
`proteus_environment` / `--proteus-environment` (open, dpi-corporate, sni-filter, deep-censorship). ·
**PROTEUS traffic-shaping morph transforms** (§13.3/§13.7) — a morph is "codec + traffic-shaper", but only
the polymorph codec existed and ran for every morph. Added `profile::ShapingProfile` — the per-morph,
θ_epoch-derived traffic-shaper: packet-SIZE (pad up to a sampled band) + inter-packet TIMING (exponential
`−mean·ln u`, the Poisson model, sender-local so float divergence is wire-harmless), both rotating per epoch
and per packet, bands/means cited to the real protocol (TLS/MASQUE MTU-fill, WebRTC ~50 pkt/s). Wired the
`Morph` through the shaper (`with_morph`, `shape()->Shaped{wire,delay}`, `Plain`=identity), the fanos-quic
driver (`ProteusConfig{secret,morph}`, `send_uni` paces the timing directive — clock stays in the driver),
and node config/CLI (`proteus_morph` / `--proteus-morph`). Polymorph default stays zero-cost (codec-only);
shaping morphs add size+timing. Verified: profile math (size band, exponential mean, tail-cap, rotation),
morph name round-trip, config parse, and a **real-QUIC** delivery under the TLS-tunnel size+timing morph. ·
**DNS-over-FANOS · SOCKS5 UDP ASSOCIATE** (Phase 2 app surface, RFC 1928 §7) — the proxy now speaks the
whole SOCKS5 protocol, not just CONNECT. Exit side: a `udp:host:port` target opens a connected UDP relay
(`relay_udp`) carrying length-framed datagrams over the DIAULOS stream. Proxy side: `UdpDialer`/`UdpTunnel`
seam + a full UDP ASSOCIATE relay (`fanos-proxy::udp`) — binds the relay socket, parses per-datagram SOCKS5
headers, multiplexes one exit tunnel per destination, latches the client source, drops fragments; DNS falls
out for free (a query is a datagram to `resolver:53`). `FanosDialer` implements `UdpDialer` through the
configured exit. Verified: header parse/encode round-trips, an echo-dialer associate E2E (two destinations),
fragment-drop, and a **real-QUIC** `dial_udp → dial_exit_udp → serve_exit → UDP socket` round-trip. ·
C10 guard-set LIVE actuation — `NyxNode::next_circuit` now enters through the guard SET (sealable-guard
failover: a down/unknown primary falls to a stable backup, not guardless); validated with a partial mix
directory. (Residual: slow rotation inert — the standalone engine has no epoch source) ·
DoS-via-healing cost bound (`healing.rs`: a flapping node keeps reroutes/repairs linear in churn — the
`⌊log₉Φ⌋` blast-radius budget — no cascade; bounded transient escalations; reconverges to health) ·
C9 onion-replay over the running mixnet (`sim/tests/replay.rs`: a captured forwarded onion re-injected to
the hop that saw it is dropped by the replay cache — no path confirmation; distinct onion still routes) ·
Tier-2 hardening: DIAULOS `serve` session-map bounded (audit A4) — `MAX_SESSIONS` LRU-evicted + idle sweep
aborting wedged handler tasks; a flood of client coords / a never-finishing handler can't grow it ·
**PRODUCTION Blocker 3 — PoW Sybil admission live-wired** (`NodeConfig.admission_difficulty` →
`OverlayNode::with_admission_pow`: prices every join, rejects proof-less announces with SYBIL_REJECT, and
re-solves the `(coord,epoch)` proof each epoch on reshuffle — the Blocker-1 coupling; verified incl. a
reshuffled joiner staying admitted) ·
**PRODUCTION Blocker 2 — QUIC connection-pinning bounded** (`fanos-quic` accept loop: per-source-IP inbound
cap + handshake deadline; established links never reclaimed for silence — #69/A6; unit-tested + real-QUIC
suite unaffected) ·
**PRODUCTION Blocker 1 — the live epoch clock now ticks** (`Node` spawns `spawn_epoch_driver` issuing the
wall-clock `AdvanceEpoch`; `NodeConfig.epoch_period`) — the whole moving-target defence (VRF coord / PROTEUS
shape / onion-key rotation) was inert/genesis-pinned in a deployed node; verified E2E that the beacon
advances across epochs (`tests/epoch_clock.rs`) ·
C8 tagging over the running mixnet (`sim/tests/tagging.rs`: AEAD drops tampered onions, tagging can't trace) ·
beacon active-anchor adversary (`sim/tests/beacon_adversary.rs`: forged biased-σ partial DLEQ-rejected,
silent anchor can't block — beacon integrity proven over the running cell, not just unit-level) ·
C10 predecessor guard-SET (`fanos-nyx::GuardSet`: primary-first, slow-rotation window, backup failover —
proven ≈f not the union bound; live NyxNode actuation is the residual) ·
C7 telemetry differential-privacy export (ε-DP `CoherenceFrame::privatize`, Laplace at Δr=1/21, exact
syndrome withheld — verified vs the analytic `1−e^{−ε/2}` bound) ·
spec↔impl reconciliation (protocol.md, 4-agent audit: beacon-DVRF, per-member-sealed onion, hash-to-line
rendezvous, [7,3,4] LRC, node-keyed coord-VRF, NAT stack, field_q+CORE caps, DIAKRISIS 3-verdict split) ·
NAT reachability complete (relay fallback) · exit discovery (auto) · proxy→exit clearnet path · clearnet
exit role · DIAULOS interactive-streaming fix · threshold-CALYPSO `service` role · #129 DHT durability
