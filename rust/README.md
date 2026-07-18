# FANOS — Rust reference implementation

A Cargo workspace implementing the FANOS protocol (`../spec/protocol.md`). The crates mirror
the protocol's module structure (spec Part XI) so a build selects exactly what it needs and
stays wire-compatible with the others.

## Crates

The workspace is **27 crates** mirroring `L0–L7 + DIAKRISIS`, so a build selects exactly what it
needs ("DHT only", "DHT+VPN", or the full mixnet+services stack) and stays wire-compatible with the
rest via the canonical encoding. All are implemented and tested unless tagged otherwise.

**Algebraic core & wire**

| Crate | Provides |
|---|---|
| [`fanos-field`](crates/fanos-field) | `GF(2^m)` (carry-less) and `GF(p)` arithmetic; zero-dependency, `no_std` |
| [`fanos-geometry`](crates/fanos-geometry) | `PG(2,q)` points/lines, `u×v` rendezvous, incidence, flags, const Fano tables |
| [`fanos-code`](crates/fanos-code) | Hamming(7,4) syndrome, projective LRC peeling, hyperoval detection |
| [`fanos-wire`](crates/fanos-wire) | canonical varints, point/line encoding, frame registry, Tessera layout |

**Diagnosis, healing & stabilization (the DIAKRISIS plane)**

| Crate | Provides |
|---|---|
| [`fanos-diakrisis`](crates/fanos-diakrisis) | coherence matrix Φ/P/R, polar sum-rules, Fiedler partition, self-healing, **and the coherence homeostat** — T-104 Lyapunov `stability`, purity `dynamics`, a Control-Barrier-Function safety seam (`cbf`), projective load-balancing (`loadbalance::balance_exact`), `vitals`/`monitor` |
| [`fanos-telemetry`](crates/fanos-telemetry) | the mandatory per-node `CoherenceFrame` self-scan and its canonical KAT-pinned encoding |

**Crypto, identity & naming**

| Crate | Provides |
|---|---|
| [`fanos-crypto`](crates/fanos-crypto) | domain-separated BLAKE3, MapToPoint, Shamir threshold, hybrid keys (secrets zeroized on drop) |
| [`fanos-pqcrypto`](crates/fanos-pqcrypto) | hybrid PQ: Ed25519+ML-DSA-65 signatures, X25519+ML-KEM-768 KEM, node identity |
| [`fanos-vrf`](crates/fanos-vrf) | ristretto255 ECVRF → self-certifying epoch coordinates, Feldman VSS, interactive multi-dealer DKG |
| [`fanos-keygen`](crates/fanos-keygen) | distributed key generation as a running engine — a Byzantine-robust `t`-of-`n` DKG over the overlay |
| [`fanos-onoma`](crates/fanos-onoma) | ONOMA self-certifying `.fanos` names — bech32m codec, unenumerable epoch derivations, subdomains |

**Core, privacy & services**

| Crate | Provides |
|---|---|
| [`fanos-core`](crates/fanos-core) | coordinates, rendezvous, Maekawa quorums, hierarchy, stratified diagnosis, the `Node` API |
| [`fanos-nyx`](crates/fanos-nyx) | threshold-sheaf onion: flag paths, `t`-of-`q+1` hops, holonomic ratchet, mixing |
| [`fanos-aphantos`](crates/fanos-aphantos) | KEM-sealed constant-size onion + the `NyxNode` engine, Poisson mixing, cover traffic |
| [`fanos-incentives`](crates/fanos-incentives) | anonymous VOPRF relay credits (blind tokens + DLEQ; Privacy-Pass class) |
| [`fanos-calypso`](crates/fanos-calypso) | self-certifying `.fanos` services, computed rendezvous, hashcash PoW, threshold hosting, CALYPSO-Balance, Lindbladian anti-DDoS |
| [`fanos-proteus`](crates/fanos-proteus) | polymorphic transport: per-packet junk, beacon-rotating shape, moving-target bridges |

**Streams, runtime, drivers & node**

| Crate | Provides |
|---|---|
| [`fanos-diaulos`](crates/fanos-diaulos) | DIAULOS reliable, multiplexed, encrypted byte streams over constant-size cells (flow control, stream cap/retire, RST/abort, nonce hard-kill) |
| [`fanos-runtime`](crates/fanos-runtime) | the sans-I/O `OverlayNode` engine — liveness, storage, membership/beacon, streams, the live sense→act healing loop and coherence homeostat |
| [`fanos-quic`](crates/fanos-quic) | the QUIC/TLS-1.3 driver over real UDP — cert-bound self-certifying identity, persistent credentials, PROTEUS-shapeable |
| [`fanos-sim`](crates/fanos-sim) | deterministic in-process simulator driving the real engines + the coherence observatory (early-warning, threat-model scenarios) |
| [`fanos-session`](crates/fanos-session) | async DIAULOS streams — a `ClientSession` as a tokio `AsyncRead`+`AsyncWrite` |
| [`fanos-rendezvous`](crates/fanos-rendezvous) | anonymous rendezvous — APHANTOS onions to a computed CALYPSO meeting line |
| [`fanos-node`](crates/fanos-node) | 🟡 the unified `fanos` daemon (supervisor: identity, config, bootstrap, engine composition) — landed, in-process tested |
| [`fanos-proxy`](crates/fanos-proxy) | 🟡 SOCKS5 CONNECT front-end with DNS-leak-free `.fanos` handling — landed, in-process tested |

**Tooling**

| Crate | Provides |
|---|---|
| [`fanos-cli`](crates/fanos-cli) | `fanos-verify` — reproduces V1–V22 and demos the protocol |
| [`fanos-bench`](crates/fanos-bench) | hot-path micro-benchmarks (rendezvous ≈ 5 ns) |

For the cybernetics behind the DIAKRISIS plane — the DDoS-stabilizing homeostat and the systematic
threat model — see [`../docs/ddos-homeostasis.md`](../docs/ddos-homeostasis.md),
[`../docs/coherent-cybernetics.md`](../docs/coherent-cybernetics.md), and
[`../docs/network-threat-model.md`](../docs/network-threat-model.md).

## Quick start

```console
$ cargo run -p fanos-cli        # the reference verifier — reproduces V1–V22
$ cargo test --workspace        # ~700 tests across 27 crates
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
use fanos_core::{Node, NodeId, Field};
use fanos_field::F31;

// Two nodes derive their coordinates and a shared rendezvous line — no coordination.
let alice = Node::<F31>::open(NodeId([1; 32]), /* epoch */ 42);
let bob = Node::<F31>::open(NodeId([2; 32]), 42);
let bus = alice.rendezvous_with(&bob.coordinate()).unwrap(); // the line u × v
assert!(alice.coordinate().is_on(&bus) && bob.coordinate().is_on(&bus));
```
