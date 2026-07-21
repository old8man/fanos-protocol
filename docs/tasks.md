# FANOS — active task list

> **▶ RIGHT NOW: THREAT catalog — industrial attack-class modeling in the simulator.** Model every
> real-world attack class (calibrated to industrial grade) against the live engine in `fanos-sim`, per the
> standing threat-modeling directive; `docs/network-threat-model.md` is the living catalog. Survey current
> coverage → implement each missing class as a sim adversary affordance + a test that asserts the defence
> holds (or documents the residual). Closing the fundamental layers sequentially.

This file is kept current: the task above is committed **before** I start it and marked done (then pruned)
when it lands. Completed tasks are removed — full history is in `git log`. Legend: ⬜ next up.

> Note: the **Claude Code todo panel** in the terminal (`◼/◻`, "N completed") is a *separate* list from
> this file. This session's toolset does **not** include the todo-editing tool (confirmed by search), so I
> can't rewrite that panel — it froze showing tasks that are already done. Treat **this file as the accurate
> status**. Stale-but-DONE on the panel: **NAT traversal** (`6de9760`), **L4 storage** (#115).

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

C7 telemetry differential-privacy export (ε-DP `CoherenceFrame::privatize`, Laplace at Δr=1/21, exact
syndrome withheld — verified vs the analytic `1−e^{−ε/2}` bound) ·
spec↔impl reconciliation (protocol.md, 4-agent audit: beacon-DVRF, per-member-sealed onion, hash-to-line
rendezvous, [7,3,4] LRC, node-keyed coord-VRF, NAT stack, field_q+CORE caps, DIAKRISIS 3-verdict split) ·
NAT reachability complete (relay fallback) · exit discovery (auto) · proxy→exit clearnet path · clearnet
exit role · DIAULOS interactive-streaming fix · threshold-CALYPSO `service` role · #129 DHT durability
