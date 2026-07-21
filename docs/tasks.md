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

- **`fanos vpn` / TUN** (Phase 5) — full-tunnel TCP+UDP (OS TUN device; verification needs a TUN harness).
- **Maekawa W∩R quorum** — strict linearizability over the L4 store (optional polish; LWW already gives
  consistent reads).

> **VOPRF credit settlement** (Phase 4) is **already implemented + tested**, not a gap: the ristretto255
> VOPRF primitive (`fanos-incentives`: blind→DLEQ→unblind, context-bound redemption B8, deterministic nonce
> B4, double-spend) and its concrete settlement use — anonymous credits paying for a CALYPSO introduction
> exactly once (`sim/tests/paid_intro.rs`). Mix-relay *forwarding* payment is the L7-opt / economically-open
> part (§16 "L7 gives the mechanics, not an equilibrium guarantee"), deliberately not invented (no magic
> pricing).

## ✅ Landed this session (2026-07-21) — pruned as they age

**C ABI — service hosting → the §11.2 surface is COMPLETE** (#113, M9) — `fanos_service_host(node, seed,
addr_out, cap)` derives a stable service identity from a seed, hosts it (forwarding each accepted DIAULOS
session onto an accept queue over the closure-based `serve`), publishes its descriptor, and returns the
`.fanos` name; `fanos_service_accept` blocks for the next incoming `FanosStream*`; `fanos_service_free`.
Verified over **real QUIC**: A hosts a service through the C ABI, B dials it by name, and a payload
round-trips client→host→client entirely across the FFI. The C ABI now covers all §11.2 operations
(lifecycle, storage, health, client streams, service hosting). ·
**C ABI — hidden-service client streams** (#113, M9, §11.2) — `fanos_service_connect(node, "<addr>.fanos")`
resolves the name over the overlay (`NodeResolver`) and dials a DIAULOS byte stream, returning an opaque
owning `FanosStream*`; `fanos_stream_read`/`_write` (blocking, driving the async stream on the node's
runtime via a cloned `Handle`) / `_free`. The dial runs inside the runtime context (`Runtime::enter`) so its
`tokio::spawn` bridge lands correctly. Verified over **real QUIC**: node B resolves + dials node A's
published echo service by name and a payload round-trips through the C-ABI stream (2-node, serialized +
retry-bounded). Header + null-safety extended. Service *hosting* is the last surface. ·
**C ABI — the embedding foundation** (#113, M9, spec §11.2) — NEW crate `fanos-ffi`: a stable `extern "C"`
surface (`crate-type = staticlib/cdylib/rlib`, hand-synced `include/fanos.h`) over the node so any language
reuses the core. Slice 1: lifecycle (`fanos_open` from a config string / `fanos_join` / `fanos_free` — an
owning tokio-runtime+node handle), storage (`fanos_publish`/`fanos_lookup` with the buffer-too-small
retry convention), and `fanos_diagnose` health. Every deref is null-guarded with a `# Safety` contract.
Verified: a publish→lookup value round-trips through the C ABI (+ short-buffer path), bad config → null,
null handles rejected, all off-network. Streams/services are the next slice. ·
**PROTEUS pluggable-transport SPI** (§13.3 `pluggable`, M10) — `MorphCodec` trait: an embedder's custom
codec fully replaces the built-in transform (`ProteusShaper::with_codec`, `ProteusConfig::pluggable`), the
honest home for real cover-protocol tunnels (tls-tunnel/masque/fronted need external stacks, §13.8 — never
faked). `set_morph` back to a built-in morph restores the built-in codec. Verified at the crate level (a
mock codec round-trips, the built-in decode rejects it) and over **real QUIC** (two nodes deliver under a
pluggable codec). This completes the PROTEUS morph catalogue (codec + traffic-shaper + auto-fallback + SPI). ·
**PROTEUS morph auto-fallback — live** (§13.7) — `MorphController` circuit breaker (K consecutive connect
failures trip a rotation through the environment chain, a success resets it) + `ProteusShaper::set_morph`
(runtime profile swap; the codec-using morphs share a codec, so rotation is decode-compatible and local —
no peer renegotiation). Wired into the fanos-quic driver: `ProteusConfig::auto(secret, env)`, connect
outcomes recorded in `get_or_connect` (a censored morph surfaces as connect timeouts), rotation installs
the new morph on the live shaper (`apply_outcome`, unit-tested off the network). Node knob
`proteus_environment` / `--proteus-environment` (open, dpi-corporate, sni-filter, deep-censorship). ·
**PROTEUS traffic-shaping morph transforms** (§13.3/§13.7) — a morph is "codec + traffic-shaper", but only
the polymorph codec existed and ran for every morph. Added `profile::ShapingProfile` — the per-morph,
θ_epoch-derived traffic-shaper: packet-SIZE (pad up to a sampled band) + inter-packet TIMING (exponential
`−mean·ln u`, the Poisson model, sender-local so float divergence is wire-harmless), both rotating per epoch
and per packet, bands/means cited to the real protocol (TLS/MASQUE MTU-fill, WebRTC ~50 pkt/s). Wired the
`Morph` through the shaper (`with_morph`, `shape()->Shaped{wire,delay}`, `Plain`=identity), the fanos-quic
driver (`ProteusConfig{secret,morph}`, `send_uni` paces the timing directive — clock stays in the driver),
and node config/CLI (`proteus_morph` / `--proteus-morph`). Polymorph default stays zero-cost (codec-only);
shaping morphs add size+timing. Verified: profile math (size band, exponential mean, tail-cap, rotation),
morph name round-trip, config parse, and a **real-QUIC** delivery under the TLS-tunnel size+timing morph. ·
**DNS-over-FANOS · SOCKS5 UDP ASSOCIATE** (Phase 2 app surface, RFC 1928 §7) — the proxy now speaks the
whole SOCKS5 protocol, not just CONNECT. Exit side: a `udp:host:port` target opens a connected UDP relay
(`relay_udp`) carrying length-framed datagrams over the DIAULOS stream. Proxy side: `UdpDialer`/`UdpTunnel`
seam + a full UDP ASSOCIATE relay (`fanos-proxy::udp`) — binds the relay socket, parses per-datagram SOCKS5
headers, multiplexes one exit tunnel per destination, latches the client source, drops fragments; DNS falls
out for free (a query is a datagram to `resolver:53`). `FanosDialer` implements `UdpDialer` through the
configured exit. Verified: header parse/encode round-trips, an echo-dialer associate E2E (two destinations),
fragment-drop, and a **real-QUIC** `dial_udp → dial_exit_udp → serve_exit → UDP socket` round-trip. ·
C10 guard-set LIVE actuation — `NyxNode::next_circuit` now enters through the guard SET (sealable-guard
failover: a down/unknown primary falls to a stable backup, not guardless); validated with a partial mix
directory. (Residual: slow rotation inert — the standalone engine has no epoch source) ·
DoS-via-healing cost bound (`healing.rs`: a flapping node keeps reroutes/repairs linear in churn — the
`⌊log₉Φ⌋` blast-radius budget — no cascade; bounded transient escalations; reconverges to health) ·
C9 onion-replay over the running mixnet (`sim/tests/replay.rs`: a captured forwarded onion re-injected to
the hop that saw it is dropped by the replay cache — no path confirmation; distinct onion still routes) ·
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
