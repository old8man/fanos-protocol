# FANOS — active task list

A living tracker of what is being worked on right now. Completed tasks are **pruned** from here as they
age (the full history is in `git log`); this file stays short so it is obvious what is in flight.

Legend: 🔨 in progress · ⬜ next up · ✅ just landed (kept briefly for context, then removed).

---

## 🔨 In progress

- **proxy → exit clearnet path** — make `fanos proxy` reach the ordinary internet: a non-`.fanos`
  (clearnet) SOCKS5 / HTTP-CONNECT target is dialed through a configured **exit** node (`dial_exit`) and
  spliced, instead of being refused. Completes "any app reaches the internet through FANOS".

## ⬜ Next up (frontier, roughly by priority)

- **exit discovery** — a descriptor so a client/proxy learns an exit's `(coord, service key)` (today the
  exit must be configured by hand); the discovery half of the exit story.
- **PROTEUS morph transforms** (§13.7) — real TLS / MASQUE-H3 / fronted traffic shaping (only `Polymorph`
  is live today).
- **NYX-Lite dialer wiring** — the low-latency (Tor-class) anonymity profile (`NyxNode` is built, unwired).
- **Maekawa W∩R quorum** — strict linearizability over the L4 store (optional polish; LWW already gives
  consistent reads).
- **VOPRF credit settlement** (Phase 4) — anonymous relay payment.
- **`fanos vpn` / TUN** (Phase 5) — full-tunnel TCP+UDP.
- **DNS-over-FANOS · UDP-ASSOCIATE** (Phase 2 app surface).
- **C ABI** (#113) — embedding surface.

## ✅ Just landed (2026-07-21)

- clearnet **exit role** — relay `serve_exit`/`dial_exit` + `Node::start` wiring + `fanos node --exit`
- **DIAULOS interactive-streaming fix** — `StreamSender` never sent sub-segment writes without a close
- threshold-CALYPSO **`service` role** — `ServiceNode` composite + `Node::start` + `fanos node --service`
- **NAT hole-punch** — hub-brokered `ConnectReq`/`PunchTo`
- **#129 DHT durability** — a stored value now survives node loss over real QUIC
