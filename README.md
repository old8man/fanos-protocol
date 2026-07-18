# FANOS

> *"Structure lives not in pairs but in triples. A network that knows this does not search — it computes."*

**FANOS** is a next-generation distributed overlay protocol built on the finite projective
plane `PG(2, q)`. Addressing a node as a *point* and a quorum as a *line* turns the hard
problems of peer-to-peer networking into single algebraic operations:

| Problem in Kademlia / Tor / Nym | FANOS answer |
|---|---|
| iterative `O(log n)` lookup, many round trips | **O(1) rendezvous** — the line through two points is their cross product `u × v` |
| no guaranteed intersection of quorums | **Maekawa quorums** — any two lines meet in exactly one point |
| a hop is a single node (point of compromise) | **a hop is a line** — a threshold `t`-of-`q+1` group; below threshold, zero knowledge |
| supernodes, Sybil-bought centrality | **structural centrality cap** `(q+1)/N`, identical for every node |
| health = pairwise heartbeats (structure-blind) | **DIAKRISIS** — third-order self-diagnosis on the cell's coherence matrix |
| classical crypto, harvest-now-decrypt-later | **post-quantum hybrid** from day one |

This repository hosts the **specification** and **implementations in every language**, starting
with the Rust reference implementation.

## Repository layout

```
fanos-protocol/
├── spec/            The protocol specification (spec/protocol.md) — the source of truth
├── rust/            Reference implementation (Rust) — a Cargo workspace, see rust/README.md
├── conformance/     Language-agnostic known-answer test vectors (KATs) — the interop contract
├── docs/            Supplementary documentation (see docs/roadmap.md for the strategic vision)
└── <lang>/          Future implementations (go/, python/, …) slot in as siblings
```

Every implementation is bound by two interoperability guarantees (spec Part VII §7.9):

1. **The wire is canonical and KAT-pinned.** There is exactly one valid byte encoding of every
   object; any language that reproduces the vectors in `conformance/` interoperates with no
   shared code.
2. **The mathematics is verifier-pinned.** Every quantitative claim (V1–V22) is reproduced by
   an executable verifier; a clean-room implementation passes the same numbers.

## Rust reference implementation

A `#![no_std]`-friendly Cargo workspace whose crates mirror the protocol's module structure
(spec Part XI). The algebraic core, the diagnosis plane (now with a **DDoS-stabilizing coherence
homeostat**), the wire, the addressing/crypto surface, the NYX/APHANTOS anonymity layer, CALYPSO
services, ONOMA naming, the DIAULOS reliable-stream layer, a real QUIC transport, and a
**deterministic network simulator** that runs the real node code are implemented and verified:

| Crate | Layer | What it provides | Status |
|---|---|---|---|
| `fanos-field` | — | `GF(2^m)` + `GF(p)` arithmetic, zero-dep, `no_std` | ✅ verified |
| `fanos-geometry` | L1 | `PG(2,q)` points/lines, cross rendezvous, incidence, the Fano cell | ✅ verified |
| `fanos-code` | L4 | Hamming(7,4) syndrome, projective LRC, hyperoval peeling | ✅ verified |
| `fanos-diakrisis` | ⟂ | coherence matrix Φ/P/R, polar sum-rules, partition, the **active healing controller** (reroute/repair/quarantine/escalate) and regeneration dynamics (`κ(Γ)`, `τ=1/Δ`), plus the **coherence homeostat** — T-104 ISS/Lyapunov `stability`, purity `dynamics`, a **Control-Barrier-Function** safety seam (`cbf`), projective load-balancing (`loadbalance::balance_exact`), and `vitals`/`monitor` | ✅ verified |
| `fanos-wire` | VII | canonical varints, point/line encoding, frames, Tessera layout | ✅ verified |
| `fanos-crypto` | L0/L6 | domain-separated BLAKE3, MapToPoint, Shamir threshold, hybrid keys (secrets zeroized on drop, audit A6) | ✅ verified |
| `fanos-core` | L0/L1/L3 | coordinates, rendezvous, Maekawa quorums, the `Node` API, and **stratified diagnosis** — the parent-cell tier that *consumes* escalation (self-similar `ParentCell`) | ✅ verified |
| `fanos-onoma` | L5 | **ONOMA** self-certifying `.fanos` names — bech32m codec, unenumerable per-epoch derivations, readable names & subdomains | ✅ verified |
| `fanos-nyx` | L5 | threshold-sheaf onion: geometric flag paths, `t`-of-`q+1` hops, holonomic ratchet, mixing | ✅ verified |
| `fanos-pqcrypto` | L6 | **real** hybrid post-quantum crypto: Ed25519+ML-DSA-65 signatures, X25519+ML-KEM-768 KEM, node identity | ✅ verified |
| `fanos-vrf` | L6 | **real** verifiable random function (ristretto255 ECVRF) → self-certifying epoch coordinates, **Feldman VSS**, and **interactive multi-dealer DKG** (a joint key no party holds) | ✅ verified |
| `fanos-incentives` | L7 | **anonymous relay credits** — a ristretto255 VOPRF (blind tokens + DLEQ proof) so payment can't deanonymise (Privacy-Pass class) | ✅ verified |
| `fanos-keygen` | L6 | **distributed key generation as a running engine** — a cell runs a `t`-of-`n` DKG over the overlay and agrees on a joint key | ✅ verified |
| `fanos-aphantos` | L5 | KEM-sealed onion + the `NyxNode` routing engine, with **Poisson mixing** and **cover traffic** | ✅ verified |
| `fanos-calypso` | services | self-certifying `.fanos` addresses, epoch-rotating rendezvous, hashcash PoW, threshold hosting — plus the running hidden-service flow over the overlay | ✅ verified |
| `fanos-proteus` | XIII | polymorphic transport: beacon-rotating shape, moving-target bridges, morphs, and the `ProteusShaper` driver wrapper | ✅ verified |
| `fanos-diaulos` | L2/L3 | **DIAULOS** reliable, multiplexed, end-to-end-encrypted byte streams over constant-size cells — two-level flow control, stream cap/retire, RST/abort (`Frame::Reset`), and AEAD nonce hard-kill | ✅ verified |
| `fanos-telemetry` | ⟂ | the mandatory per-node **CoherenceFrame** (a minimal cell self-scan) and its canonical KAT-pinned encoding | ✅ verified |
| `fanos-runtime` | — | the node as a **sans-I/O** state machine (`OverlayNode`) — witness-corroborated liveness, rendezvous, the **sense→act** healing loop and live **coherence homeostat**, **L4 storage**, reliable **streams**, and **membership/JOIN + epoch beacon** (flooded key distribution, adopt-max consensus) | ✅ verified |
| `fanos-sim` | — | deterministic in-process **simulator** driving the real engines (faults, traces, metrics) + the **coherence observatory** that forecasts cascades (early-warning `CriticalSlowingDown` detector; Sybil-cost & eclipse threat-model scenarios) | ✅ verified |
| `fanos-quic` | L2 | the **second sans-I/O driver** — the *same* engine over real UDP + QUIC (TLS 1.3), optionally PROTEUS-shaped, with **cert-bound self-certifying identity** (mutual TLS), **persistent credentials** (durable coordinate), keep-alive/idle tuning, and `tracing` | ✅ verified |
| `fanos-rendezvous` | — | anonymous rendezvous — carry a session over APHANTOS threshold onions to a computed CALYPSO meeting line, so neither party learns the other's location | ✅ verified |
| `fanos-session` | — | async DIAULOS byte streams — a sans-I/O `ClientSession` as a tokio `AsyncRead`+`AsyncWrite` (the bridge a SOCKS5 proxy uses) | ✅ verified |
| `fanos-node` | — | the unified **`fanos` daemon** (supervisor): durable self-certifying identity, config, bootstrap, and engine composition behind the QUIC driver | 🟡 landed, in-process tested |
| `fanos-proxy` | — | SOCKS5 CONNECT front-end over a pluggable `Dialer`, with DNS-leak-free `.fanos` target handling | 🟡 landed, in-process tested |
| `fanos-cli` / `fanos-bench` | — | `fanos-verify` reproduces V1–V22; `fanos-bench` benchmarks the hot paths (rendezvous ≈ 5 ns) | ✅ verified |

### Status at a glance

Every crate in the table above is implemented **and** tested (`✅ verified`); the tiers below track
the *product* surface built on them — honest about what is proven vs. still integrating vs. designed-only.

- **✅ implemented + tested** — the algebraic substrate; DIAKRISIS self-diagnosis, self-healing, and
  the **coherence homeostat** (Lyapunov stability, a CBF safety seam, projective load-balancing); the
  canonical wire; hybrid post-quantum crypto, ECVRF, and networked DKG; the NYX/APHANTOS threshold
  onion with mixing + cover; CALYPSO services; ONOMA naming; DIAULOS reliable streams; the sans-I/O
  `OverlayNode` engine under **two drivers** (the `fanos-sim` simulator and the `fanos-quic`
  real-socket transport); the observatory's early-warning detector; and the Sybil-cost / eclipse
  threat-model verifications.
- **🟡 partial / integrating** — the unified `fanos` node daemon and the SOCKS5 proxy (crates and a
  `fanos` binary have landed and pass in-process tests; a live multi-machine deployment is not
  demonstrated here); the Direct/Lite/Full anonymity dial (engines exist; per-stream selection is
  still being wired at the node layer).
- **📐 designed-only** — the full-tunnel VPN (`fanos vpn`); clearnet DNS-over-FANOS and UDP-ASSOCIATE
  at the proxy (leak-free `.fanos` handling already ships, but clearnet resolution over an exit does
  not); and the research-horizon *coherent blockchain* (consensus-via-coherence). See
  [`docs/roadmap.md`](docs/roadmap.md).

The node logic is written **sans-I/O** (see [`docs/architecture.md`](docs/architecture.md)): it
reacts to inputs and returns effects, touching no clock, socket, or RNG. The simulator and the
`fanos-quic` transport are **two drivers of one engine** — the byte-for-byte `OverlayNode` that
`fanos-sim` fault-tests is what `fanos-quic` runs over a real socket, proven by a loopback e2e
suite (delivery, connection reuse, live-peer death detection). This is how the protocol is
debugged "as if in production" on one host, then shipped unchanged.

**Self-healing.** DIAKRISIS does not merely *diagnose* — it *acts* (spec §6.9). A verdict becomes
a bounded, corpus-grounded `HealingPlan`: reroute around a loss along the projective LRC (the
co-linear survivor `mediator(self, lost)`), regenerate lost shards by peeling, escalate a
hyperoval stopping-set to the parent, or shed correlation on a cascade early-warning. The
simulator confirms the operational payoff: traffic addressed to a crashed node **still delivers**
via the reroute, and a cell that saturates its syndrome decoder at ≥3 faults still heals locally.

**Forecasting.** The simulator's coherence observatory reconstructs `Γ_net` from behavioural
signals and calls a cascade a full regime **before any node fails** (spec §2.7, V15) — the mean
correlation crosses `r* = 1/√6` with a measurable lead time ahead of the first liveness failure.
Run `cargo run -p fanos-sim --example forecast` to watch it.

**Coherent cybernetics — stabilization by dynamics, not filters.** FANOS treats a DDoS not as traffic
to filter but as a **perturbation of the network's coherence**, answered by dissipation with a provable
spectral gap. A multi-target flood is the canonical `h^(D)` noise attack on a cell's coherence matrix;
by the T-104 stability theorem the organism returns exponentially to its healthy attractor as long as
the aggregate decoherence stays under `κ_bootstrap/2 = 1/14`, and two provably-relaxing controllers —
admission (load) and the coherence homeostat (self-model) — hold it there. This is implemented in
`fanos-diakrisis` (`homeostat`, `stability`, `dynamics`, `cbf`, `loadbalance`), wired live into the
`OverlayNode` engine, and validated on the simulator; a **Control-Barrier-Function** seam guarantees
that even a future *learnable* controller cannot steer the cell out of viability.

- [`docs/ddos-homeostasis.md`](docs/ddos-homeostasis.md) — the math-verified derivation (T-104, the `1/14` survival bound, the homeostat)
- [`docs/coherent-cybernetics.md`](docs/coherent-cybernetics.md) — the organism theory FANOS instantiates
- [`docs/network-threat-model.md`](docs/network-threat-model.md) — the systematic threat sweep (Sybil-cost & eclipse verified in `fanos-sim`)
- [`docs/frontier-synthesis.md`](docs/frontier-synthesis.md) — the research frontier, measured against what FANOS already derives

Two simulation-driven investigations produced protocol improvements. (1) Naive per-link liveness
times out spuriously under packet loss (5→84 false positives as loss climbs 10→50%), so liveness is
**corroborated across a node's line-witnesses** (spec §6.4). (2) That fix, taken as "any witness
rescues liveness", is then vulnerable to a *single Byzantine liar* vouching for a dead node — so
corroboration is **quorum-based**: own observation is trusted, otherwise `≥ quorum` distinct
witnesses must agree, outvoting up to `quorum − 1` liars. The Byzantine-safe default (quorum 2)
holds the false-positive rate at **zero through ~40% loss** with true-death detection preserved; a
loss-optimized deployment can set quorum 1 (zero through 50%, but fooled by one liar). Both regimes,
and the garbage-flood drop path, are pinned by adversary scenarios (`tests/byzantine.rs`).

A deep audit pass hardened several layers and, in the spirit of the status tags below, documents
what remains a deliberate simplification. Fixed: the APHANTOS onion no longer carries a
**circuit-constant holonomy tag** in cleartext (it was a perfect cross-hop correlator) — the
authenticator now rides *inside* the innermost encrypted layer (`tests/`-pinned); the DIAKRISIS
controller now **decouples only when over-coupled** (`r > 1/√3`, `R < 1/3`), never inside the
healthy collective-subject band; wire length fields are `usize::try_from`-checked so a 64-bit and a
`wasm32` node cannot disagree; membership rejects non-canonical/zero coordinates and never lets a
repeat announce overwrite a member's keys; the hybrid node-ID is pinned byte-for-byte to the
canonical hashing rule; and a VRF key derives from *any* seed (a hash-to-scalar, not a 1-in-16
canonical-bytes gate). L4 reads now **repair across the replica line** — a `Get`
queries the responsible primary, then falls back through the co-linear replicas on a miss or a
silent-replica timeout, so any survivor answers even when the primary recovered empty after churn.
The networked **DKG is Byzantine-robust via a complaint round** — a node finalizes as soon as every
member qualifies, or (past a collection deadline) on the qualified set reaching the threshold, so an
offline dealer cannot stall the majority; and a node missing or holding an *invalid* share complains,
the dealer must publicly justify (reveal) the complainer's share against its commitment, and a dealer
with an unanswered complaint is disqualified. Because commitments, complaints, and justifications are
reliably broadcast, every honest node computes the same qualified set even against a dealer that
*equivocates* (valid share to some, invalid to others), so they still agree on one key.
The APHANTOS onion is **constant-size on the wire** — every hop's packet is
padded to a fixed bucket with the real layer length carried in an *encrypted* field, so a passive
observer cannot link entry to exit by the shrinking size a naive nested onion leaks. PROTEUS junk
is now **per-packet**: a random-looking nonce seeds each packet's junk/padding keystream, so even
two sends of the identical frame shape to different bytes (no fixed intra-epoch prefix, cf.
AmneziaWG). NYX **cover traffic is now byte-indistinguishable from real onions** — a cover cell is
the same `Tessera` frame type and the same constant onion size, and it simply fails to peel (the
drop path a wrong-relay onion takes), so an observer cannot tell an idle node from a busy one.
Documented as a known limitation with a fix path (see the module docs): the onion's processing relay
still learns its own layer length (full position-hiding is the Sphinx filler construction; a passive
network observer already learns nothing from size).

### Build, verify, and simulate

```console
$ cd rust
$ cargo run -p fanos-cli                          # reference verifier — 18 headline claims (V1–V22, T-226)
$ cargo run -p fanos-sim --bin fanos-sim-demo     # drive a real cell: crash, partition, rendezvous
$ cargo run -p fanos-sim --example forecast       # forecast a cascade before it collapses
$ cargo run -p fanos-sim --example catastrophe    # loss/churn/scale robustness probe
$ cargo bench -p fanos-bench                       # hot-path micro-benchmarks
$ cargo test --workspace                          # ~700 tests across 27 crates
$ cargo clippy --all-targets -- -D warnings       # pedantic lints, zero warnings (CI gate)
```

The verifier reproduces the specification's headline numbers exactly, e.g. the NYX endpoint
linkage `P_link = 1.516·10⁻⁶` at `(q+1=8, t=6, f=0.2)` — a **×26,381** improvement over Tor's
`f²`.

## Engineering standards

The implementation is held to a strict, CI-enforced bar (see `.github/workflows/ci.yml`):

- **nightly Rust, edition 2024** — pinned for reproducibility (`rust/rust-toolchain.toml`).
- **`#![forbid(unsafe_code)]`** across the math core; memory-safe by construction.
- **`cargo clippy --all-targets -- -D warnings`** with pedantic lints — zero warnings.
- **`cargo fmt --check`** — canonical formatting.
- **`no_std` cross-builds to `wasm32`** — proving portability down to embedded (spec §11.5).
- **Every V1–V22 claim reproduced as a test** — the code is provably faithful to the spec.

## License

Code is MIT-licensed (see [`LICENSE`](LICENSE)). The specification is a reference architecture;
status tags `[T]`/`[C]`/`[H]`/`[P]` mark what is proven, conditional, hypothesized, or a
research direction — the cryptographic novelty is the *composition* of vetted post-quantum
primitives, not new hardness assumptions.
