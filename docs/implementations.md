# FANOS implementations

FANOS is designed to be re-implemented in any language. Interoperability is guaranteed by the
canonical wire (`../conformance/`) and the verifier-pinned mathematics — not by shared code
(spec Part VII §7.9, Part XI).

## Status

| Language | Location | Status | Notes |
|---|---|---|---|
| **Rust** | [`../rust/`](../rust/) | reference — algebraic core, DIAKRISIS, wire, crypto, overlay core | the source of truth for the KATs |
| Go | `../go/` | planned | clean-room from the spec + conformance vectors |
| Python | `../python/` | planned | verifier port + bindings |
| C / C ABI | `../c/` | planned | the portable core with the stable C ABI (spec §11.2) |

To add a language, create a sibling top-level directory and make it reproduce
`../conformance/vectors/*.json`. It will interoperate with every other implementation with no
shared code.

## What "the reference implementation" covers today

Implemented and verified (roadmap M0–M1, plus the DIAKRISIS math of M3+ and the wire of Part
VII):

- **L0/L1 addressing & routing** — projective coordinates, O(1) cross-product rendezvous,
  bridges, multipath, content addressing.
- **L3 membership** — epoch-bound coordinate derivation, the structural centrality cap.
- **L4 storage** — Maekawa quorums, projective LRC parameters and peeling repair.
- **DIAKRISIS** — the full self-diagnosis plane (coherence matrix, syndrome localization,
  polar sum-rules, partition resistance, self-healing budgets).
- **L6 crypto surface** — domain-separated BLAKE3, MapToPoint/MapToLine, Shamir threshold
  sharing, hybrid-key identity.
- **Part VII wire** — canonical encoding, frame registry, error taxonomy, Tessera layout.

## What is next (spec roadmap M2, M4–M10)

The networked and privacy layers, whose algebra is already implementable and whose interfaces
are scaffolded:

- **L2 transport** — QUIC (RFC 9000/9001), multipath, MASQUE NAT traversal.
- **L5 NYX / APHANTOS** — the threshold-sheaf onion (DKG per line, threshold decryption),
  Poisson mixing, structurally-balanced cover, the holonomic ratchet.
- **CALYPSO** — computed-rendezvous threshold-hosted hidden services.
- **PROTEUS** — polymorphic anti-DPI transport and moving-target bridges.
- **The C ABI + bindings** and the SOCKS5 / TUN integration surfaces (spec §11.2–§11.4).
