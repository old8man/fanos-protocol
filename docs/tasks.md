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

Tier-2 hardening: DIAULOS `serve` session-map bounded (audit A4) — `MAX_SESSIONS` LRU-evicted + idle sweep
aborting wedged handler tasks; a flood of client coords / a never-finishing handler can't grow it ·
**PRODUCTION Blocker 3 — PoW Sybil admission live-wired** (`NodeConfig.admission_difficulty` →
`OverlayNode::with_admission_pow`: prices every join, rejects proof-less announces with SYBIL_REJECT, and
re-solves the `(coord,epoch)` proof each epoch on reshuffle — the Blocker-1 coupling; verified incl. a
reshuffled joiner staying admitted) ·
**PRODUCTION Blocker 2 — QUIC connection-pinning bounded** (`fanos-quic` accept loop: per-source-IP inbound
cap + handshake deadline; established links never reclaimed for silence — #69/A6; unit-tested + real-QUIC
suite unaffected) ·
**PRODUCTION Blocker 1 — the live epoch clock now ticks** (`Node` spawns `spawn_epoch_driver` issuing the
wall-clock `AdvanceEpoch`; `NodeConfig.epoch_period`) — the whole moving-target defence (VRF coord / PROTEUS
shape / onion-key rotation) was inert/genesis-pinned in a deployed node; verified E2E that the beacon
advances across epochs (`tests/epoch_clock.rs`) ·
C8 tagging over the running mixnet (`sim/tests/tagging.rs`: AEAD drops tampered onions, tagging can't trace) ·
beacon active-anchor adversary (`sim/tests/beacon_adversary.rs`: forged biased-σ partial DLEQ-rejected,
silent anchor can't block — beacon integrity proven over the running cell, not just unit-level) ·
C10 predecessor guard-SET (`fanos-nyx::GuardSet`: primary-first, slow-rotation window, backup failover —
proven ≈f not the union bound; live NyxNode actuation is the residual) ·
C7 telemetry differential-privacy export (ε-DP `CoherenceFrame::privatize`, Laplace at Δr=1/21, exact
syndrome withheld — verified vs the analytic `1−e^{−ε/2}` bound) ·
spec↔impl reconciliation (protocol.md, 4-agent audit: beacon-DVRF, per-member-sealed onion, hash-to-line
rendezvous, [7,3,4] LRC, node-keyed coord-VRF, NAT stack, field_q+CORE caps, DIAKRISIS 3-verdict split) ·
NAT reachability complete (relay fallback) · exit discovery (auto) · proxy→exit clearnet path · clearnet
exit role · DIAULOS interactive-streaming fix · threshold-CALYPSO `service` role · #129 DHT durability
