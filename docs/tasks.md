# FANOS — active task list

> **▶ RIGHT NOW: NYX-Lite dialer wiring** — expose the low-latency (Tor-class) anonymity profile in the
> proxy. `NyxNode` (single-node Sphinx onion hops) is built + sim-tested but unwired into the proxy dialer,
> which today offers only `direct` (fast, no anonymity) and `anonymous` (Nym-class threshold mixing). This
> needs a design call: bridge the NyxNode Sphinx path, or a Lite preset over the existing rendezvous.

This file is kept current: the task above is committed **before** I start it and marked done (then pruned)
when it lands. Completed tasks are removed — full history is in `git log`. Legend: ⬜ next up.

> Note: a separate **GitHub Project board** also tracks tasks; I can't read/edit it without the
> `read:project`/`project` gh scope. If you run `gh auth refresh -s project`, I can sync it directly;
> otherwise this file is the source of truth for what I'm doing. **NAT traversal / reachability is now
> fully DONE** (relay fallback landed) — it can be marked done on the board.

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

spec↔impl reconciliation (protocol.md, 4-agent audit: beacon-DVRF, per-member-sealed onion, hash-to-line
rendezvous, [7,3,4] LRC, node-keyed coord-VRF, NAT stack, field_q+CORE caps, DIAKRISIS 3-verdict split) ·
NAT reachability complete (relay fallback) · exit discovery (auto) · proxy→exit clearnet path · clearnet
exit role · DIAULOS interactive-streaming fix · threshold-CALYPSO `service` role · #129 DHT durability
