# FANOS — active task list

> **▶ RIGHT NOW: NAT reachability — symmetric-NAT relay fallback.** The reachability core is DONE (reflexive
> address discovery, hub hole-punch, reverse-reachability). The residual: when a direct connection / punch
> can't be made (symmetric NAT), relay the traffic through a common hub — so nodes behind ANY NAT can talk.
> This is what finishes "NAT traversal / reachability for real-internet nodes".

This file is kept current: the task above is committed **before** I start it and marked done (then pruned)
when it lands. Completed tasks are removed — full history is in `git log`. Legend: ⬜ next up.

> Note: a separate **GitHub Project board** also tracks tasks; I can't read/edit it without the
> `read:project`/`project` gh scope. If you run `gh auth refresh -s project`, I can sync it directly;
> otherwise this file is the source of truth for what I'm doing.

---

## ⬜ Next up (frontier, roughly by priority)

- **NYX-Lite dialer wiring** — the low-latency (Tor-class) anonymity profile (`NyxNode` built, unwired;
  needs a design call on single-node Sphinx hops vs the proxy's threshold rendezvous).
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
