# FANOS — active task list

> **▶ RIGHT NOW: exit discovery** — publish an exit's descriptor to the overlay + resolve it, so
> `fanos proxy` finds an exit **automatically** (no hand-written `--exit-via`). Mirrors the mix directory.

This file is kept current: the task above is committed **before** I start it and marked done (then pruned)
when it lands. Completed tasks are removed — full history is in `git log`. Legend: ⬜ next up.

---

## ⬜ Next up (frontier, roughly by priority)

- **PROTEUS morph transforms** (§13.7) — real TLS / MASQUE-H3 / fronted traffic shaping (only `Polymorph`
  is live today).
- **NYX-Lite dialer wiring** — the low-latency (Tor-class) anonymity profile (`NyxNode` built, unwired).
- **DNS-over-FANOS · UDP-ASSOCIATE** (Phase 2 app surface) — complete the proxy beyond TCP CONNECT.
- **Maekawa W∩R quorum** — strict linearizability over the L4 store (optional polish; LWW already gives
  consistent reads).
- **VOPRF credit settlement** (Phase 4) — anonymous relay payment.
- **`fanos vpn` / TUN** (Phase 5) — full-tunnel TCP+UDP.
- **C ABI** (#113) — embedding surface.

## ✅ Landed this session (2026-07-21) — pruned as they age

proxy→exit clearnet path · clearnet exit role · DIAULOS interactive-streaming fix · threshold-CALYPSO
`service` role · NAT hole-punch · #129 DHT durability over QUIC
