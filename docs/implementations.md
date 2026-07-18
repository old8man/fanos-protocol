# FANOS implementations

FANOS is designed to be re-implemented in any language. Interoperability is guaranteed by the
canonical wire (`../conformance/`) and the verifier-pinned mathematics — not by shared code
(spec Part VII §7.9, Part XI).

## Status

| Language | Location | Status | Notes |
|---|---|---|---|
| **Rust** | [`../rust/`](../rust/) | reference — the full stack: algebraic core, DIAKRISIS (self-healing + coherence homeostat), wire, crypto/PQ/VRF/DKG, NYX/APHANTOS privacy, CALYPSO services, ONOMA naming, DIAULOS streams, the sans-I/O runtime + QUIC transport, simulator, and the `fanos` node/proxy | the source of truth for the KATs |
| Go | `../go/` | planned | clean-room from the spec + conformance vectors |
| Python | `../python/` | planned | verifier port + bindings |
| C / C ABI | `../c/` | planned | the portable core with the stable C ABI (spec §11.2) |

To add a language, create a sibling top-level directory and make it reproduce
`../conformance/vectors/*.json`. It will interoperate with every other implementation with no
shared code.

## What "the reference implementation" covers today

Implemented and verified across 27 crates and ~700 tests:

- **L0/L1 addressing & routing** — projective coordinates, O(1) cross-product rendezvous,
  bridges, multipath, content addressing.
- **L3 membership** — epoch-bound coordinate derivation, the structural centrality cap.
- **L4 storage** — Maekawa quorums, projective LRC parameters and peeling/line repair.
- **DIAKRISIS** — the full self-diagnosis plane (coherence matrix, syndrome localization, polar
  sum-rules, partition resistance, self-healing budgets) **and the coherence homeostat**: Lyapunov
  stability, a Control-Barrier-Function safety seam, and projective load-balancing (`docs/ddos-homeostasis.md`).
- **L6 crypto & identity** — domain-separated BLAKE3, MapToPoint/MapToLine, Shamir threshold sharing,
  hybrid-key identity, **real hybrid post-quantum** signatures/KEM, ECVRF coordinates, and networked
  DKG (secrets zeroized on drop).
- **L5 privacy** — the NYX/APHANTOS threshold-sheaf onion (constant-size), Poisson mixing,
  byte-indistinguishable cover traffic, and anonymous VOPRF relay credits.
- **Services, naming & censorship** — CALYPSO computed-rendezvous threshold-hosted `.fanos` services,
  ONOMA self-certifying names, and PROTEUS polymorphic anti-DPI transport.
- **L2 transport & streams** — a real QUIC/TLS-1.3 driver and DIAULOS reliable multiplexed encrypted
  streams (flow control, RST/abort, nonce hard-kill).
- **Runtime & simulation** — the sans-I/O `OverlayNode` engine and a deterministic simulator with a
  coherence observatory (cascade early-warning; Sybil-cost & eclipse threat-model scenarios).
- **Part VII wire** — canonical encoding, frame registry, error taxonomy, Tessera layout.

## What is next

The privacy, service, transport, and stream layers listed above have **landed** since this doc's
first draft; the reference implementation's remaining frontier is integration and reach, not new
primitives:

- **Multi-machine bring-up** — take the `fanos` node/proxy from in-process tests to a live network
  over the wire (roadmap Phase 1).
- **The anonymity dial & app surface** — per-stream Direct/Lite/Full selection, and DNS-over-FANOS +
  UDP-ASSOCIATE at the SOCKS5 proxy (no local-resolver leak), roadmap Phase 2.
- **Scale** — the cell hierarchy (`N^k`), gossip membership, and DHT storage at `10⁶–10⁹` nodes.
- **The C ABI + bindings** and the TUN/VPN integration surface (spec §11.2–§11.4).
- **Other-language implementations** — Go / Python / C, clean-room from the spec + conformance vectors.
