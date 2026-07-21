# FANOS — Roadmap & Architecture Vision

> *A living transport network: self-observing, self-healing, post-quantum — the substrate on which
> anonymity, VPN, hidden services, and a coherent ledger are built.*

This document is the **strategic** companion to [`spec/protocol.md`](../spec/protocol.md) (the protocol
reference) and [`architecture.md`](architecture.md) (the sans-I/O engineering thesis). The spec says
*what the protocol is*; this says *where the project goes, why, and in what order* — grounded in a
fundamental analysis of the field and in the UHM (УГМ) ontology that gives FANOS its cybernetics.

Status tags follow the spec: **[T]** proven / built, **[C]** conditional / integration work, **[P]**
research direction. Nothing here is overstated.

---

## 0. Thesis — the network is alive

Every anonymity network to date is a *mechanism*: a fixed pipeline of relays that forwards packets and
hopes no one correlates the ends. FANOS is a **self-observing dissipative system**. Its substrate is a
finite projective plane `PG(2, q)`, so a hop is a *line* (a threshold quorum), addressing is algebra,
and the topology needs no directory authority. Over that substrate runs **DIAKRISIS** — a reflexive
plane by which the network measures its *own* coherence (`Φ / P / R`) and heals itself under the same
Lindbladian dynamics that govern an open quantum system: perturbations (faults, floods) relax back to
the healthy steady state `ρ*` at the dynamics' spectral gap `Δ`.

The consequence is a single network that:

- **dials** its own latency↔anonymity trade-off (Tor-class *or* Nym-class, per request);
- **observes and repairs** itself (reroute, regenerate, decouple, escalate) with no operator;
- **stabilizes** under attack by formal dissipation, not bolt-on filters;
- is **post-quantum** end to end from day one; and
- is a **platform** — anyone can run a VPN, hidden service, web backend, or (future) a *coherent
  blockchain* on top, because FANOS is a high-level transport, not a single application.

The end state is one binary — `fanos` — that runs nodes, exactly as `tor` does, but for a network that
is coherent cybernetics made real.

---

## 1. The landscape — a fundamental analysis

| Axis | **Tor** (onion routing) | **Nym** (Loopix mixnet) | **I2P** (garlic) | **FANOS** |
|---|---|---|---|---|
| Topology | circuit, 3 relays | stratified mix layers | packet-switched DHT | **algebraic `PG(2,q)`** — geometry *is* the directory |
| The hop | one relay | one mix | one router | **a line: `t`-of-`(q+1)`; below `t` = zero knowledge** |
| Directory | 9–10 authorities (chokepoint) | blockchain | netDb (floodfill) | **none — computed** |
| Adversary resisted | local; weak vs global correlation | **global passive** (Poisson mixing) | local | **dial:** Lite ≈ Tor · Full ≈ Nym (threshold + mixing) |
| Latency | low | high | medium | **configurable per call** |
| Self-diagnosis | ✗ | ✗ | ✗ | **DIAKRISIS — network self-observation & healing** |
| Post-quantum | retrofitting | retrofitting | ✗ | **hybrid PQ from day one** |
| Hidden services | v3 onion + HSDir | — | eepsites | **CALYPSO — computed rendezvous, threshold-hosted, HA** |
| DoS defence | onion-service PoW (bolt-on) | cover traffic | limited | **Lindbladian stabilization (formal) + threshold + PoW** |
| Censorship | pluggable transports, bridges | — | — | **PROTEUS — polymorphic, moving-target bridges** |
| Incentives | none (volunteers) | token + mixmining | none | **anonymous VOPRF credits + coherence reputation** |
| Anti-Sybil | bandwidth-weighted | stake | — | **structural centrality cap `(q+1)/N`** |

**What each gets right, and its ceiling.** Tor's genius is low-latency usability, but its directory
authorities are a trust/censorship chokepoint, its single-relay hops fall to a global correlator, and
it has no incentives (a capacity ceiling) and, until 2023, no DoS answer. Nym's genius is *provable*
anonymity against a global adversary via verifiable Poisson mixing, but at interactive-latency cost,
with a hard economic/token dependency and single-mix hops. I2P is strong in-network but weak on exit
and enumeration-resistant naming. Loopix is the sound academic core Nym productized.

**None of them observes itself.** They are open-loop. The moment a relay degrades, a hop is flooded, or
the topology partitions, a human or a coarse heuristic must intervene. That is the gap FANOS is built
to close, and it is why the substrate had to be algebraic and the plane had to be reflexive.

---

## 2. The FANOS synthesis — inherit the best, innovate the rest

FANOS is not "a better Tor" or "a faster Nym." It is the synthesis that keeps their proven ideas and
adds the two things neither can: a **structural** substrate and a **reflexive** one.

**Inherited (and hardened):**

- *From Tor* — onion routing, low-latency usability, the SOCKS proxy integration path, self-certifying
  hidden-service addresses, pluggable-transport censorship resistance. → FANOS: constant-size PQ
  onions, `.fanos` addresses, PROTEUS.
- *From Nym / Loopix* — Poisson mixing and cover traffic for global-adversary resistance, decentralized
  topology, anonymous credentials, incentives. → FANOS: mixing + cover on the *Full* profile,
  VOPRF credits, no token *required* (credits are optional and unlinkable).

**Innovated (FANOS-native, not in either):**

1. **A hop is a line.** Maekawa quorums: any two lines meet in one point, so rendezvous is `O(1)`
   algebra and each hop is a `t`-of-`(q+1)` threshold group — compromising a hop needs `t` colluding
   members, and below `t` the layer is information-theoretically dark. *(Built: `fanos-aphantos::threshold`,
   routed by `ThresholdRouter`.)*
2. **The network self-observes.** DIAKRISIS reads `Γ_net`'s coherence and heals — reroute along the
   projective LRC, regenerate shards by peeling, decouple an over-coupled cell, escalate a stopping
   set to the parent tier. *(Built: `fanos-diakrisis`, `fanos-core::stratum`.)*
3. **One dial, two networks.** Direct / Lite / Full unify Tor-class and Nym-class anonymity in one
   overlay, chosen per stream. *(Engines built; the dial is wired at the node layer — Phase 1–2.)*
4. **Lindbladian stability.** DDoS is a perturbation; the answer is dissipation with a provable
   spectral gap and super-linear attacker cost. *(Built: the `fanos-diakrisis` coherence homeostat —
   `homeostat`/`stability`/`dynamics`/`cbf`/`loadbalance` — wired live into `OverlayNode`, plus the
   `fanos-calypso::stabilize` load channel; derived in [`ddos-homeostasis.md`](ddos-homeostasis.md).)*
5. **Directory-free by geometry.** No authority to seize or censor — the plane *is* the map, epochs
   rotate it, VRF makes positions self-certifying. *(Substrate built; VRF primitive built.)*
6. **Post-quantum, structurally anti-Sybil, evolvable.** Hybrid PQ throughout; `(q+1)/N` centrality
   cap; capability negotiation so the wire evolves without a hard fork.

---

## 3. Target architecture — the coherent transport network

### 3.1 The substrate (Phase 0 — **[T]** built)

Twenty-seven `no_std`-friendly crates mirror `L0–L7 + DIAKRISIS`. Node logic is **sans-I/O**: a pure
`Engine::step(now, Input) → [Effect]`, driven identically by `fanos-sim` (deterministic, fault-testable)
and `fanos-quic` (real UDP + QUIC/TLS 1.3). Four engines exist — `OverlayNode` (membership, liveness,
storage, healing, now with a live **coherence homeostat**), `NyxNode` (single-relay onion + mixing + cover),
`ThresholdRouter` (line-hop threshold onion), `DkgNode` (distributed key generation) — plus the **DIAULOS**
reliable-stream layer, composed by the `fanos-node` supervisor. ~700 tests, the V1–V22 verifier, wasm cross-builds.

### 3.2 The node — one `fanos` binary (Phase 1)

The product is a single daemon, like `tor`:

```
fanos node        # run a relay/storage/healing node; join a cell; participate
fanos proxy       # local SOCKS5/HTTP-CONNECT + DNS, tunnelling apps through the overlay
fanos service     # host a .fanos hidden service (single or CALYPSO-Balance fleet)
fanos vpn         # full-tunnel VPN over FANOS transport
fanos health      # live DIAKRISIS readout (Φ, P, syndrome, verdict)
fanos verify      # the reference verifier (today's fanos-cli)
```

One process composes the engines behind the `fanos-quic` driver: cert-bound self-certifying identity
(`coord = MapToPoint(H(cert))`, built), a config file, durable `NodeCredentials`, and a supervisor that
feeds `Input`s and performs `Effect`s. **This phase turns a proven protocol into a runnable network.**

### 3.3 The anonymity dial (Phase 2)

`profile ∈ { Direct, Lite, Full }`, selected per stream:

- **Direct** — plain QUIC, no anonymity (LAN / trusted).
- **Lite** — single-relay PQ onion, low latency (≈ Tor + PQ), `fanos-aphantos::sealed`.
- **Full** — threshold line-hops + Poisson mixing + cover (> Nym), `ThresholdRouter`.

The node runs all three; the app picks. This is the concrete Tor↔Nym synthesis in one binary.

*Status (#54): the **Full-class anonymous profile is now wired end-to-end** — `fanos proxy --profile
anonymous` draws a FRESH, unlinkable threshold-onion rendezvous route per dial, and deployed `fanos node
--role relay` nodes run the mixnet (a `CellNode` composite: overlay + beacon + mix router + rendezvous
relay) and publish their onion keys. Client and service stay location-hidden; the reply returns via a
cookie-registered rendezvous relay. Verified unit + sim + real-QUIC (`anonymous_quic.rs`).*

### 3.4 The application surface — SOCKS5, DNS, UDP (Phase 2)

`fanos proxy` is the "use it from anything" surface (spec §11.3):

- **SOCKS5 / HTTP-CONNECT** — every `CONNECT host:port` becomes a FANOS stream at the listener's
  profile. Any browser, `curl`, SSH, messenger works with a one-line config.
- **`.fanos` names** — routed to CALYPSO (self-certifying, no directory), the `.onion` analogue.
- **DNS without leaks** — the single largest deanonymization vector. `.fanos` is answered locally;
  clearnet DNS is resolved **over the overlay** through an exit, never via the local resolver. DNS is a
  first-class network feature, not an afterthought.
- **UDP** — `UDP ASSOCIATE` onto QUIC datagrams: the foundation for the VPN and for QUIC-native apps.

### 3.5 Names & rendezvous (**[T]** built · integration Phase 2)

CALYPSO: self-certifying `<b32(H(pubkey))>.fanos`, per-epoch **computed** rendezvous (no HSDir to
enumerate), **threshold hosting** (no single host to raid), **CALYPSO-Balance** (offline-root →
epoch-signing-key hierarchy, weighted-rendezvous-hashing load balancing, HA fleets), and **Lindbladian
anti-DDoS**. A petname/naming layer sits on top, deliberately out of protocol scope.

*Status (#99): the threshold-hosting core is now **live-wired** — a production `ThresholdService` engine
(`fanos-node`) threshold-decrypts each intro across the service-line (`t`-of-`(q+1)` PartialDec gather over
the `RdvIntro`/`SvcShareReq`/`SvcPartial` wire frames), so no single host reads an intro and `< t` seized
hosts learn nothing, and a client discovers the line through a wire-serialized `ServiceLine` roster
(`fanos-calypso::hosting`) and seals its intro to it — the full discover → seal → serve loop, verified over
the sim (`threshold_service_live.rs`). Remaining integration: composition with the anonymous transport
(§12.4, so the intro rides the rendezvous onion and the reply returns over the client's reply circuit) and
LRC-replicated service state.*

### 3.6 Censorship resistance & evolution (**[T]** core · Phase 3)

- **PROTEUS** — polymorphic transport: per-packet junk (built), beacon-rotating shape, moving-target
  bridges (no static list to block), morph auto-fallback.
- **No authority to capture** — the geometry is the directory; there is nothing to seize or coerce.
- **Capability negotiation** — versioned min-version + capability intersection, so the protocol
  *evolves continuously* (new morphs, ciphers, cell sizes) without a hard fork. Censorship is an arms
  race; the platform is built to keep moving.

### 3.7 Incentives & sustainability (**[C]** primitive built · Phase 4)

Anonymous **VOPRF relay credits** (built: blind, unlinkable, double-spend-proof) let relaying be paid
without deanonymizing — Privacy-Pass class, no token *required*. **Coherence reputation**: DIAKRISIS
already measures each node's contribution to its cell's coherence, a native, sybil-resistant reputation
signal. Together these target the free-rider problem the spec honestly marks open (§XVI).

---

## 4. Products on the platform

FANOS is a transport; products ride it.

- **VPN (flagship, Phase 5).** Full-tunnel `fanos vpn` (TUN): all traffic — TCP *and* UDP — through
  Lite/Full onions, PROTEUS-obfuscated, provably anonymous. WireGuard-class UX, mixnet-class privacy,
  post-quantum, censorship-resistant. The first consumer face of the network.
- **Hidden services (built + Phase 2).** `.onion`-class, but computed-rendezvous, threshold-hosted,
  DDoS-stabilized, and horizontally scalable via CALYPSO-Balance — for high-load services Tor cannot serve.
- **General overlay / web infra (Phase 3+).** Any app dials FANOS via SOCKS5, the C ABI, or the native
  `dial/host/connect` API — a censorship-resistant, self-healing substrate for messaging, storage, CDNs.
- **The coherent blockchain (Phase 6, [P]).** The frontier: a ledger native to the coherent network.
  Line committees are natural threshold validators; **consensus-via-coherence** (a cell commits when its
  integration `Φ ≥ 1` — an *integrated subject*, spec §18) is a genuinely UHM-grounded alternative to
  PoW/PoS; data-availability sampling maps onto the projective incidence structure; the
  threshold/mixing layers give anti-MEV by construction.

---

## 5. The UHM grounding — coherent cybernetics on every level

FANOS is the network realization of the UHM (УГМ) ontology, and this is *why* it can self-observe:

- **The reflexive plane.** DIAKRISIS is the network's self-model: a cell of seven reads its own
  coherence matrix `Γ_net`, the third-order statistic `Φ / P / R`. A network that measures itself can
  correct itself. *(Built; V11–V21 verified.)*
- **Lindbladian healing.** Faults and floods are perturbations; the healing dynamics (`κ` regeneration,
  `τ = 1/Δ` reintegration, the `Φ→Φ/9` coarse-hop budget) are the dissipative terms of a Lindblad
  master equation, relaxing the system to `ρ*`. *(Built; §6.7, T-226(v).)*
- **The collective-subject window.** A cell is a genuine integrated subject exactly when its mean
  inter-node correlation lies in `(1/√6, 1/√3]` — integrated yet still self-modelling (spec §18.2). This
  is the formal boundary the future consensus layer will commit on.
- **Coherence as the universal currency.** Health, reputation, admission pricing, and (future)
  consensus all read the *same* coherence measures — one cybernetic quantity across the stack.

The design rule: **every level — routing, healing, admission, naming, consensus — is derived from the
UHM dynamics, not tuned.** That is what keeps the platform coherent as it evolves.

---

## 6. The phased roadmap

| Phase | Deliverable | State | Proves |
|---|---|---|---|
| **0 — Coherent core** | 27 crates, 4 engines + DIAULOS streams, sim + quic drivers, verifier, ~700 tests | **[T] done** | the protocol works in simulation & loopback |
| **1 — The `fanos` node** | single daemon: `fanos node` over QUIC, identity, cell join, membership/beacon, storage, healing, config, bootstrap | **[C] in progress** — supervisor crate + `fanos` binary landed & in-process tested | a real multi-machine network runs |
| **2 — Application surface** | `fanos proxy`: SOCKS5/HTTP-CONNECT, `.fanos` resolution, DNS-over-FANOS (no leak), UDP-ASSOCIATE; the Direct/Lite/Full dial | **[C]** | any unmodified app tunnels through FANOS |
| **3 — Scale & anti-censorship** | cell hierarchy (`N^k`), gossip membership at scale, DHT storage, exit policy, PROTEUS moving-target bridges, capability-negotiated evolution | **[C]** | censored bootstrap, `10⁶–10⁹` scale |
| **4 — Incentives & sustainability** | VOPRF credit settlement, coherence reputation, mixmining-style rewards | **[C]/[P]** | relays are paid without deanonymization |
| **5 — The VPN** | `fanos vpn` (TUN), full-tunnel TCP+UDP, PROTEUS-obfuscated, provably anonymous | **[C]** | the flagship consumer product |
| **6 — Coherent blockchain** | consensus-via-coherence, DA sampling over lines, anti-MEV | **[P]** | a UHM-native ledger on the living network |

**Cross-cutting, every phase:** security audits and the `[P] → [T]` formalization program (machine-checked
proofs of Tessera, the ratchet, PQ-VRF/beacon/shuffle); performance hardening (constant-time `GF(2^m)`,
hot-path benches); the C ABI + language bindings; mobile/embedded profiles; and continuous
reproduce-then-verify (every headline claim stays an executable test).

**Immediate next step (Phase 1):** the `fanos-node` crate — a supervisor binding `OverlayNode`
(+ optional relay/service engines) to the `fanos-quic` driver with a config file and bootstrap — **has
landed** with the `fanos` binary and passes in-process tests; a `fanos-proxy` SOCKS5 front-end and the
`fanos-session`/`fanos-rendezvous` stream surfaces have landed alongside it. The open part of Phase 1 is
the live **multi-machine** bring-up (proven engines leaving the simulator to form a real network); the
proxy, VPN, and scale work composes on that one runnable node.

---

## 7. Positioning

Position FANOS, today, as **the provably-anonymous, censorship-circumventing transport network** —
Tor's usability and Nym's global-adversary resistance in one post-quantum overlay that *heals itself*.
The first product is the **VPN** (fanos as transport): absolute anonymity with proofs, obfuscated
against DPI and blocking, self-stabilizing under attack. Hidden services and the general overlay follow
for builders. The coherent blockchain is the long horizon — but it is a *consequence* of the substrate,
not a bolt-on, because the network was coherent cybernetics from the first line of code.

> *"Structure lives not in pairs but in triples. A network that knows this does not search — it
> computes. A network that observes itself does not fail — it heals."*
