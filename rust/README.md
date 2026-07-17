# FANOS — Rust reference implementation

A Cargo workspace implementing the FANOS protocol (`../spec/protocol.md`). The crates mirror
the protocol's module structure (spec Part XI) so a build selects exactly what it needs and
stays wire-compatible with the others.

## Crates

| Crate | Depends on | Provides |
|---|---|---|
| [`fanos-field`](crates/fanos-field) | — | `GF(2^m)` (carry-less) and `GF(p)` arithmetic; zero-dependency, `no_std` |
| [`fanos-geometry`](crates/fanos-geometry) | field | `PG(2,q)` points/lines, `u×v` rendezvous, incidence, flags, const Fano tables |
| [`fanos-code`](crates/fanos-code) | geometry | Hamming(7,4) syndrome, projective LRC peeling, hyperoval detection |
| [`fanos-diakrisis`](crates/fanos-diakrisis) | geometry, code | coherence matrix Φ/P/R, polar sum-rules, Fiedler partition, self-healing |
| [`fanos-wire`](crates/fanos-wire) | geometry | canonical varints, point/line encoding, frame registry, Tessera layout |
| [`fanos-crypto`](crates/fanos-crypto) | geometry | domain-separated BLAKE3, MapToPoint, Shamir threshold, hybrid keys, VRF surface |
| [`fanos-core`](crates/fanos-core) | all above | coordinates, rendezvous, Maekawa quorums, hierarchy, the `Node` API |
| [`fanos-cli`](crates/fanos-cli) | all above | `fanos-verify` — reproduces V1–V22 and demos the protocol |

## Quick start

```console
$ cargo run -p fanos-cli        # the reference verifier — reproduces V1–V22
$ cargo test --workspace        # 119 tests
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
