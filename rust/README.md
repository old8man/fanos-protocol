# FANOS — Rust reference implementation

A Cargo workspace implementing the FANOS protocol (`../spec/protocol.md`). The crates mirror
the protocol's module structure (spec Part XI) so a build selects exactly what it needs and
stays wire-compatible with the others.

## Crates

The workspace is **41 crates** spanning `L0–L12 + the DIAKRISIS plane`, so a build selects exactly
what it needs (a bare DHT, DHT+VPN, the full mixnet + anonymous services, or the whole platform —
blockchain, private currency, messenger) and stays wire-compatible with the rest via the canonical
encoding. All are implemented and tested; the single active frontier (`[P]`) is marked inline.

**Algebraic core, wire & sans-I/O contract**

| Crate | Provides |
|---|---|
| [`fanos-field`](crates/fanos-field) | `GF(2^m)` (carry-less) and `GF(p)` arithmetic; zero-dependency, `no_std` |
| [`fanos-geometry`](crates/fanos-geometry) | `PG(2,q)` points/lines, `u×v` rendezvous, incidence, flags, const Fano tables |
| [`fanos-code`](crates/fanos-code) | Hamming(7,4) syndrome, projective LRC peeling + erasure coding, hyperoval detection |
| [`fanos-primitives`](crates/fanos-primitives) | the crypto surface — domain-separated BLAKE3, MapToPoint, Shamir threshold, hybrid keys, bounded collections; `no_std` |
| [`fanos-wire`](crates/fanos-wire) | canonical varints, point/line encoding, frame registry, Tessera layout, capability negotiation |
| [`fanos-wire-derive`](crates/fanos-wire-derive) | `#[derive(Wire)]` — a canonical codec generated from one type definition |
| [`fanos-ports`](crates/fanos-ports) | the sans-I/O contract — the `Command`/`Input`/`Effect`/`Notification` vocabulary + the `Engine` trait every node engine speaks |
| [`fanos-stream`](crates/fanos-stream) | reliable, ordered, multiplexed sans-I/O byte streams (selective-repeat/SACK, two-level flow control) — a transport-agnostic leaf |

**DIAKRISIS — diagnosis, healing & viability**

| Crate | Provides |
|---|---|
| [`fanos-diakrisis`](crates/fanos-diakrisis) | coherence matrix Φ/P/R, polar sum-rules, Fiedler partition, self-healing, **and the coherence homeostat** — T-104 Lyapunov `stability`, purity `dynamics`, a Control-Barrier-Function safety seam (`cbf`), projective load-balancing (`loadbalance::balance_exact`), `vitals`/`monitor` |
| [`fanos-telemetry`](crates/fanos-telemetry) | the mandatory per-node `CoherenceFrame` self-scan, its canonical KAT-pinned encoding, and ε-differential-privacy export |
| [`fanos-observatory`](crates/fanos-observatory) | `fanos-monitor` — the terminal Coherence Observatory TUI reading the network's self-model (`--json` for agents) |
| [`fanos-holarch`](crates/fanos-holarch) | the architecture viability gate — the platform's Γ-matrix, the release invariants, the σ-stress panel, the Ω4 ablation calculus |

**Crypto, identity & naming**

| Crate | Provides |
|---|---|
| [`fanos-pqcrypto`](crates/fanos-pqcrypto) | hybrid PQ: Ed25519+ML-DSA-65 signatures, X25519+ML-KEM-768 KEM, node identity (secrets zeroized on drop) |
| [`fanos-vrf`](crates/fanos-vrf) | ristretto255 ECVRF → self-certifying epoch coordinates, Feldman VSS, interactive multi-dealer DKG |
| [`fanos-keygen`](crates/fanos-keygen) | distributed key generation as a running engine — a Byzantine-robust `t`-of-`n` DKG over the overlay |
| [`fanos-onoma`](crates/fanos-onoma) | ONOMA self-certifying `.fanos` names — bech32m codec, unenumerable epoch derivations, subdomains |

**Overlay core, privacy & anonymous services**

| Crate | Provides |
|---|---|
| [`fanos-core`](crates/fanos-core) | coordinates, O(1) rendezvous, Maekawa quorums, hierarchy, stratified diagnosis, PoW admission, the `Node` API |
| [`fanos-nyx`](crates/fanos-nyx) | threshold-sheaf onion: flag paths, `t`-of-`q+1` hops, holonomic ratchet, mixing |
| [`fanos-aphantos`](crates/fanos-aphantos) | KEM-sealed constant-size onion + the `NyxNode` engine, Poisson mixing, constant-rate cover, the NOSTOS reply substrate |
| [`fanos-incentives`](crates/fanos-incentives) | anonymous VOPRF relay credits (blind tokens + DLEQ; Privacy-Pass class) |
| [`fanos-calypso`](crates/fanos-calypso) | self-certifying `.fanos` services, computed rendezvous, hashcash PoW, threshold hosting, CALYPSO-Balance, Lindbladian anti-DDoS |
| [`fanos-proteus`](crates/fanos-proteus) | polymorphic transport: per-packet junk, beacon-rotating shape, moving-target bridges |
| [`fanos-rendezvous`](crates/fanos-rendezvous) | anonymous rendezvous — APHANTOS onions to a computed CALYPSO meeting line, so neither party learns the other's location |

**Streams, runtime, drivers & node**

| Crate | Provides |
|---|---|
| [`fanos-diaulos`](crates/fanos-diaulos) | the DIAULOS connection layer over constant-size cells — session multiplexing, stream cap/retire, RST/abort, nonce hard-kill |
| [`fanos-runtime`](crates/fanos-runtime) | the sans-I/O `OverlayNode` engine — liveness, erasure storage, membership/beacon, streams, the live sense→act healing loop and coherence homeostat |
| [`fanos-quic`](crates/fanos-quic) | the QUIC/TLS-1.3 driver over real UDP — cert-bound self-certifying identity, per-epoch coordinate reshuffle, PROTEUS-shapeable |
| [`fanos-sim`](crates/fanos-sim) | deterministic in-process simulator driving the real engines + the coherence observatory (early-warning, threat-model scenarios) |
| [`fanos-session`](crates/fanos-session) | async DIAULOS streams — a `ClientSession` as a tokio `AsyncRead`+`AsyncWrite` over a bounded datagram transport |
| [`fanos-node`](crates/fanos-node) | the unified `fanos` daemon (supervisor: identity, config, bootstrap, engine composition; validator + anonymous-host roles) |
| [`fanos-proxy`](crates/fanos-proxy) | SOCKS5 CONNECT front-end with DNS-leak-free `.fanos` handling over a pluggable `Dialer` |

**Platform (L8–L12): consensus, execution, currency & apps**

| Crate | Provides |
|---|---|
| [`fanos-taxis`](crates/fanos-taxis) | TAXIS — the FANOS-native BFT blockchain: projective-cell PBFT, secret-leader election, threshold-encrypted anti-MEV mempool, DA-sampled blocks, durable state-sync |
| [`fanos-dromos`](crates/fanos-dromos) | DROMOS — the parallel execution fabric: a deterministic conflict-DAG scheduler wiring the OBOLOS pool onto TAXIS consensus |
| [`fanos-obolos`](crates/fanos-obolos) | OBOLOS — the private, untraceable PQ currency: a shielded note pool with lattice value commitments, a Merkle tree + nullifiers; the PQ zero-knowledge spend proof is the active frontier (`[P]`) |
| [`fanos-hermes`](crates/fanos-hermes) | HERMES — PQ threshold cross-chain: hash-locked atomic swaps and threshold-attested custody |
| [`fanos-angelos`](crates/fanos-angelos) | ANGELOS — the anonymous PQ messenger: forward-secret double-ratchet 1:1, groups, media & call signaling over the mixnet |
| [`fanos-thesauros`](crates/fanos-thesauros) | THESAUROS — the content-storage platform: content-addressed objects, proof of retrievability, a capacity market over the L4 erasure store |

**Embedding & tooling**

| Crate | Provides |
|---|---|
| [`fanos-ffi`](crates/fanos-ffi) | the stable C ABI — an `extern "C"` embedding surface over the node (lifecycle, storage, health, streams, service hosting) |
| [`fanos-vpn`](crates/fanos-vpn) | the VPN datapath — a sans-I/O IPv4/UDP flow engine tunneling through a FANOS exit; a TUN driver + userspace-TCP mode layer on top |
| [`fanos-wasm`](crates/fanos-wasm) | the browser/mobile client surface (WebAssembly): compute + verify a node's self-organizing coordinate, no directory, no authority |
| [`fanos-cli`](crates/fanos-cli) | `fanos-verify` — reproduces V1–V22 and demos the protocol |
| [`fanos-bench`](crates/fanos-bench) | hot-path micro-benchmarks (rendezvous ≈ 5 ns) |

For the cybernetics behind the DIAKRISIS plane — the DDoS-stabilizing homeostat and the systematic
threat model — see [`../docs/ddos-homeostasis.md`](../docs/ddos-homeostasis.md),
[`../docs/coherent-cybernetics.md`](../docs/coherent-cybernetics.md), and
[`../docs/network-threat-model.md`](../docs/network-threat-model.md).

## Quick start

```console
$ cargo run -p fanos-cli        # the reference verifier — reproduces V1–V22
$ cargo test --workspace        # 1,600+ tests across all 41 crates
$ cargo doc --no-deps --open    # API docs
```

## Toolchain

Pinned to **nightly, edition 2024** via [`rust-toolchain.toml`](rust-toolchain.toml). Nightly
unlocks `portable_simd` (the coherence-matrix kernels) and advanced const generics (the
projective geometry); edition 2024 is the latest stable edition. The pin is deliberate and for
reproducibility — bump it explicitly.

## The verification gate

Every crate is held to the same bar (run locally, and enforced in CI):

```console
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets -- -D warnings   # pedantic lints, zero warnings
$ cargo test --workspace
$ cargo build -p fanos-field --target wasm32-unknown-unknown --no-default-features   # no_std
```

- The math crates are **`#![forbid(unsafe_code)]`** — memory-safe by construction.
- Restriction lints (`unwrap_used`, `indexing_slicing`, …) apply to production code; test
  modules opt out locally.
- Every numeric claim of the specification (V1–V22) is reproduced as a test, so the code is
  provably faithful to the spec, and the CLI verifier is itself a test.

## Build profiles

- `release` — `lto = "thin"`, fast to compile.
- `maxperf` — `lto = "fat"`, `codegen-units = 1`, `panic = "abort"` (the ship/benchmark
  profile): `cargo build --profile maxperf`.

## Using the library

```rust
use fanos_core::{BeaconSeed, Epoch, Node, NodeId, VrfSecret};
use fanos_field::F31;

// Each node derives a verifiable, identity-bound coordinate — a VRF of (identity, epoch, beacon),
// so placement reshuffles unpredictably each epoch — then both compute the same rendezvous line
// with no coordination.
let beacon = BeaconSeed::GENESIS;
let alice = Node::<F31>::open(&VrfSecret::from_seed([1; 32]), NodeId([1; 32]), Epoch::new(42), &beacon);
let bob = Node::<F31>::open(&VrfSecret::from_seed([2; 32]), NodeId([2; 32]), Epoch::new(42), &beacon);
let bus = alice.rendezvous_with(&bob.coordinate()).unwrap(); // the line u × v
assert!(alice.coordinate().is_on(&bus) && bob.coordinate().is_on(&bus));
```
