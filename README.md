# FANOS

> *"Structure lives not in pairs but in triples. A network that knows this does not search — it computes."*

**FANOS is a post-quantum anonymity network** — Tor / Nym / I2P class — that replaces the search-based
plumbing of peer-to-peer systems with **geometry**. Nodes are *points* of a finite projective plane
`PG(2, q)`; quorums are its *lines*. Because the plane's algebra is fixed and total, the operations that cost
other networks round trips and routing tables cost FANOS a **single arithmetic step**:

| The hard problem in Kademlia / Tor / Nym | The FANOS answer |
|---|---|
| iterative `O(log n)` lookup, many round trips | **O(1) rendezvous** — the line through two points *is* their cross product `u × v` (nanoseconds, no search) |
| quorums that may not intersect | **Maekawa quorums** — any two lines meet in exactly one point, guaranteed |
| a hop is one node — one point of compromise | **a hop is a line** — a threshold `t`-of-`q+1` group; below the threshold, provable zero knowledge |
| supernodes, Sybil-bought centrality | **structural centrality cap** `(q+1)/N`, identical for every node — you cannot buy influence |
| health = pairwise heartbeats (structure-blind) | **DIAKRISIS** — third-order self-diagnosis on the cell's coherence matrix, seeing failures a regime early |
| classical crypto, "harvest now, decrypt later" | **hybrid post-quantum from day one** (Ed25519 + ML-DSA-65, X25519 + ML-KEM-768) |

One substrate, one codebase. From it we build a whole stack — and it is **built and tested**, not sketched.

---

## What you can do with it

FANOS is not a single app; it is a foundation that already carries five product surfaces, each a real,
tested crate — not a roadmap bullet:

- 🕵️ **Browse and communicate anonymously.** The **APHANTOS / NYX** mixnet routes through threshold-sheaf
  onions (a hop is a `t`-of-`q+1` line, so `P_link = P_hop²`), with Poisson mixing and structurally-balanced
  cover traffic. A `λ` dial trades latency for anonymity per task — "Tor-fast" to "Nym-strong" on one engine.
- 🧅 **Host a hidden service.** **CALYPSO** gives self-certifying `.fanos` addresses, a rendezvous point that
  is *computed* (no directory to enumerate, rotating each epoch), threshold hosting (seize `< t` hosts and
  learn nothing), and PoW / anonymous-credit DoS defence.
- 🛡️ **Run it as a VPN.** `fanos vpn` is a full-tunnel TCP + UDP datapath (a userspace IP stack over a real
  TUN device), bridging every flow to an exit — WireGuard-class shape, onion-class privacy, PQ from day one.
- 🌐 **Use it as a proxy.** A SOCKS5 front-end (CONNECT + UDP-ASSOCIATE) with leak-free `.fanos` handling and
  DNS-over-FANOS.
- ⛓️ **Build a blockchain on it.** **TAXIS** is a BFT ledger *derived from the geometry itself*: the projective
  cell is a proven PBFT quorum system, leaders are beacon-elected (cartel-proof by the centrality cap), and an
  **anti-MEV encrypted mempool** (the proposer orders blind, a keyper line reveals only after ordering) comes
  essentially for free from the same threshold primitive the onion uses.
- 🧩 **Embed it anywhere.** A stable **C ABI** (`fanos-ffi`) exposes the whole node — lifecycle, storage,
  streams, hidden-service hosting — to any language, on any platform down to `no_std` embedded.

Add **PROTEUS**, a polymorphic transport that removes the wire's fingerprint (the "Parrot is Dead" principle —
it looks like *nothing*, and different at every deployment) and rotates its shape with the epoch beacon, and
the stack spans anonymity, services, VPN, censorship-resistance, and a ledger — all on the projective core.

---

## Why it is different

**It heals itself.** DIAKRISIS does not just diagnose — it *acts*. A verdict becomes a bounded healing plan:
reroute around a lost node along the projective code (the co-linear survivor), regenerate lost shards by
peeling, or escalate an unrecoverable pattern to the parent cell. A DDoS is treated not as traffic to filter
but as a **perturbation of the network's coherence**, answered by dissipation with a provable spectral gap: by
the stability theorem the cell returns exponentially to its healthy attractor as long as the aggregate
decoherence stays under `1/14`. This recurses *up the hierarchy* — a parent cell diagnoses its child cells by
the same math.

**One engine, two drivers.** Every node behaviour is written **sans-I/O** — it reacts to inputs and returns
effects, touching no clock, socket, or RNG. A **deterministic simulator** fault-tests the *byte-for-byte* same
engine that a **real QUIC transport** runs over a socket. FANOS is debugged "as if in production" on one host,
then shipped unchanged.

**It is proven, not asserted.** Every headline number in the spec (V1–V22) is reproduced by an executable
verifier, and the wire is pinned to language-agnostic known-answer vectors — a clean-room implementation in any
language reproduces the same bytes and the same numbers. Example, checkable today: the NYX endpoint linkage
`P_link = 1.516·10⁻⁶` at `(q+1=8, t=6, f=0.2)` — a **×26,381** improvement over Tor's `f²`.

**Post-quantum from day one.** Not a migration plan — hybrid signatures and KEM are the default wire, so
"harvest now, decrypt later" fails against traffic recorded today.

---

## The theory, closed

FANOS's novelty is the *composition* of vetted primitives, and the load-bearing math is worked out in the
open (`docs/design-*.md`), each with a derivation and a reproducible experiment:

- **Holonomic-ratchet path authentication** — hardened to a length-bound MAC with an EUF-CMA reduction to
  BLAKE3 and an attack experiment over every tamper class.
- **A DIAKRISIS quarantine theorem** — `Φ' = (N·Φ − 2·s_q)/(N−1)`: quarantining a node lowers integration iff
  its coupling energy exceeds `Φ/2` (Byzantine nodes qualify; a silent node does not) — derived and simulated.
- **Constant-time `GF(2^m)`** — mask-based multiply, fixed-exponent Fermat inverse; a deterministic op-count
  experiment proves the inversion ladder is secret-independent.
- **Post-quantum VRF, beacon, and verifiable shuffle** — a hash-based Merkle-VRF (unbiasable epoch randomness),
  a reconstruction-unique threshold beacon (binding the sharing *polynomial*, so no dealer can bias it), and a
  verifiable mixnet shuffle that is unconditionally sound over its classical ristretto backend, with an
  experimental Ring-LWE (NewHope-512) backend and a noise-budget + Monte-Carlo analysis.
  *These are novel constructions; they have had an adversarial internal cryptographer review (which found and
  fixed real breaks) but no external audit — see their design notes and the honest-status section.*

---

## The Rust reference implementation

A `#![no_std]`-friendly Cargo workspace of **34 crates** mirroring the protocol's layers. Grouped by theme:

**Foundation** — `fanos-field` (`GF(2^m)`/`GF(p)`, zero-dep), `fanos-geometry` (`PG(2,q)` points/lines, cross
rendezvous, the Fano cell), `fanos-code` (projective LRC, hyperoval peeling, data-availability sampling),
`fanos-wire` + `fanos-wire-derive` (canonical, KAT-pinned encoding), `fanos-primitives` (BLAKE3, MapToPoint,
Shamir), `fanos-ports` (the sans-I/O contract).

**Crypto** — `fanos-pqcrypto` (real hybrid Ed25519+ML-DSA-65 / X25519+ML-KEM-768), `fanos-vrf` (ristretto
ECVRF + Feldman VSS + DKG — *and* the post-quantum Merkle-VRF, threshold beacon, and verifiable shuffle),
`fanos-incentives` (anonymous VOPRF relay credits), `fanos-keygen` (networked DKG engine).

**Self-diagnosis** — `fanos-diakrisis` (the coherence matrix Φ/P/R, polar sum-rules, the active healing
controller, the DDoS homeostat with a Control-Barrier-Function safety seam, and the parent-observes-child
recursion), `fanos-telemetry` (the per-node coherence self-scan), `fanos-observatory` (an operator TUI).

**Anonymity & services** — `fanos-nyx` (threshold-sheaf onion, holonomic ratchet, mixing), `fanos-aphantos`
(the KEM-sealed onion + routing engine, cover traffic), `fanos-proteus` (polymorphic censorship-resistant
transport), `fanos-rendezvous` (anonymous meeting), `fanos-calypso` (hidden services), `fanos-onoma`
(self-certifying `.fanos` names).

**Transport & streams** — `fanos-diaulos` (reliable, multiplexed, encrypted byte streams over constant-size
cells), `fanos-stream` (the reliability layer), `fanos-session` (async `AsyncRead`/`AsyncWrite`), `fanos-quic`
(the real UDP+QUIC/TLS-1.3 driver with cert-bound self-certifying identity).

**Node, runtime & apps** — `fanos-core` (coordinates, quorums, the `Node` API), `fanos-runtime` (the sans-I/O
`OverlayNode`), `fanos-sim` (the deterministic simulator + cascade-forecasting observatory), `fanos-node` (the
`fanos` daemon), `fanos-proxy` (SOCKS5), `fanos-vpn` (the TUN datapath), `fanos-ffi` (the C ABI), **`fanos-taxis`
(the BFT blockchain)**, `fanos-cli` / `fanos-bench` (the verifier and benchmarks).

### Build, verify, and simulate

```console
$ cd rust
$ cargo run -p fanos-cli --bin fanos-verify   # reference verifier — the headline claims (V1–V22, T-226)
$ cargo run -p fanos-sim --bin demo           # drive a real cell: crash, partition, rendezvous
$ cargo run -p fanos-sim --example forecast   # forecast a cascade a regime before it collapses
$ cargo test --workspace                      # 1,100+ tests across 34 crates
$ cargo clippy --all-targets -- -D warnings   # pedantic lints, zero warnings (CI gate)
```

Interoperability is guaranteed two ways (spec Part VII §7.9): the **wire is canonical and KAT-pinned** (one
valid byte encoding per object; reproduce `conformance/` and you interoperate with no shared code), and the
**mathematics is verifier-pinned** (every V-claim is an executable test).

---

## Engineering standards

Held to a strict, CI-enforced bar:

- **nightly Rust, edition 2024**, pinned for reproducibility.
- **`#![forbid(unsafe_code)]`** across the math core — memory-safe by construction.
- **`cargo clippy --all-targets -- -D warnings`** with pedantic lints — zero warnings.
- **`no_std` cross-builds to `wasm32`** — portability down to embedded (spec §11.5).
- **1,100+ tests**, including every V1–V22 claim and adversarial threat-model scenarios.

---

## Honest status

FANOS is a **reference implementation of a research architecture**, and it is precise about what that means.
The spec's status tags — `[T]` proven, `[C]` conditional, `[H]` hypothesized, `[P]` research direction — carry
into the code, and we would rather under-claim than oversell:

- **✅ Implemented and tested** — the algebraic substrate; DIAKRISIS diagnosis, self-healing, and the DDoS
  homeostat; the canonical wire; hybrid post-quantum crypto and networked DKG; the NYX/APHANTOS mixnet with
  mixing and cover; CALYPSO services; ONOMA naming; DIAULOS streams; the TAXIS blockchain; the C ABI; and the
  sans-I/O engine under **two drivers** (the simulator and the real QUIC transport), proven byte-identical by
  a loopback end-to-end suite.
- **🟡 Landed, in-process tested** — the unified `fanos` daemon, the SOCKS5 proxy, and the VPN's OS-level TUN
  syscalls are verified on a host but **a live multi-machine deployment is not demonstrated here**.
- **⚠️ Novel, internally-reviewed, not externally audited** — the post-quantum threshold beacon (`pqvss`), the
  verifiable shuffle (`shuffle`/`rlwe`), the anti-MEV encrypted-mempool execution path (`taxis`), and the
  hardened path-authentication MAC are hand-rolled constructions with written security reductions and extensive
  tests. They have had an **adversarial internal cryptographer review** — which found and fixed genuine breaks
  (a beacon a malicious dealer could bias; a lattice re-randomization check that was a tautology; unauthenticated
  anti-MEV reveals that let anyone censor or fork executed state) and left honest, documented scope limits (the
  RLWE shuffle backend is an experimental research scaffold, **not** worst-case-sound at NewHope-512 — rely on
  the classical backend; the encrypted-mempool needs on-chain key commitment for full robustness). But they have
  had **no external cryptanalysis** and must not be deployed as sole security without one; each design note states
  its status plainly.

The cryptographic claim is the *composition* of vetted post-quantum primitives, not new hardness assumptions.

## License

Code is MIT-licensed (see [`LICENSE`](LICENSE)). The specification (`spec/protocol.md`) is the source of truth;
the strategic vision is in [`docs/roadmap.md`](docs/roadmap.md), the architecture in
[`docs/architecture.md`](docs/architecture.md), and the load-bearing derivations in `docs/design-*.md`.
