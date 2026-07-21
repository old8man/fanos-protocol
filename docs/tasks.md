# FANOS — active task list

> **▶ RIGHT NOW: NYX-Lite dialer wiring** — expose the low-latency (Tor-class) anonymity profile in the
> proxy: `NyxNode` (single-relay onion + mixing + cover) is built but unwired. Rounds out the anonymity
> "dial" between `direct` (fast, no anonymity) and `anonymous` (Nym-class, full mixing).

This file is kept current: the task above is committed **before** I start it and marked done (then pruned)
when it lands. Completed tasks are removed — full history is in `git log`. Legend: ⬜ next up.

---

## ⬜ Next up (frontier, roughly by priority)

- **PROTEUS morph transforms** (§13.7) — real TLS / MASQUE-H3 / fronted traffic shaping (only `Polymorph`
  is live today).
- **DNS-over-FANOS · UDP-ASSOCIATE** (Phase 2 app surface) — complete the proxy beyond TCP CONNECT.
- **Maekawa W∩R quorum** — strict linearizability over the L4 store (optional polish; LWW already gives
  consistent reads).
- **VOPRF credit settlement** (Phase 4) — anonymous relay payment.
- **`fanos vpn` / TUN** (Phase 5) — full-tunnel TCP+UDP.
- **C ABI** (#113) — embedding surface.

## ✅ Landed this session (2026-07-21) — pruned as they age

exit discovery (auto) · proxy→exit clearnet path · clearnet exit role · DIAULOS interactive-streaming fix ·
threshold-CALYPSO `service` role · NAT hole-punch · #129 DHT durability over QUIC
