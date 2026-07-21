# FANOS — active task list

A living tracker of what is being worked on right now. Completed tasks are **pruned** from here as they
age (the full history is in `git log`); this file stays short so it is obvious what is in flight.

Legend: 🔨 in progress · ⬜ next up · ✅ just landed (kept briefly for context, then removed).

---

## 🔨 In progress

- **exit discovery** — publish an exit's descriptor `(coord, service key)` to the overlay and resolve it,
  so `fanos proxy` finds an exit **automatically** instead of a hand-written `--exit-via` file. Mirrors the
  `.fanos` service resolution (ONOMA descriptors). The discovery half of the exit story.

## ⬜ Next up (frontier, roughly by priority)

- **PROTEUS morph transforms** (§13.7) — real TLS / MASQUE-H3 / fronted traffic shaping (only `Polymorph`
  is live today).
- **NYX-Lite dialer wiring** — the low-latency (Tor-class) anonymity profile (`NyxNode` is built, unwired).
- **DNS-over-FANOS · UDP-ASSOCIATE** (Phase 2 app surface) — complete the proxy beyond TCP CONNECT.
- **Maekawa W∩R quorum** — strict linearizability over the L4 store (optional polish; LWW already gives
  consistent reads).
- **VOPRF credit settlement** (Phase 4) — anonymous relay payment.
- **`fanos vpn` / TUN** (Phase 5) — full-tunnel TCP+UDP.
- **C ABI** (#113) — embedding surface.

## ✅ Just landed (2026-07-21)

- **proxy → exit clearnet path** — `FanosDialer::with_exit` routes non-`.fanos` targets through an exit;
  `fanos proxy --exit-via`; exit logs its descriptor at startup. "Any app → the internet through FANOS".
- clearnet **exit role** — relay `serve_exit`/`dial_exit` + `Node::start` wiring + `fanos node --exit`
- **DIAULOS interactive-streaming fix** — `StreamSender` never sent sub-segment writes without a close
- threshold-CALYPSO **`service` role** — `ServiceNode` composite + `Node::start` + `fanos node --service`
