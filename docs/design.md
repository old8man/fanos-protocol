# FANOS — Architectural Design & Principles

> The reference design: derived from a fundamental analysis of the field and its **incidents**, it
> fixes the invariants that make FANOS both *outstanding today* and *evolvable forever* — an
> architecture that adapts like a living organism, because it observes and repairs itself.

This document is the **HOW and WHY** behind [`roadmap.md`](roadmap.md) (the what/when) and
[`spec/protocol.md`](../spec/protocol.md) (the protocol). It states the architectural invariants, the
incident analysis they answer, and the evolvability model — so every future decision is traceable to a
principle, and the platform can grow without losing coherence.

> **Naming note.** The name is **FANOS** (Φανός, "beacon"), retained for now. A three-letter successor
> in the `tor` / `i2p` / `nym` lineage is catalogued in §8 as a future brand option; the architecture
> below is name-independent and can be re-prefixed mechanically if ever renamed.

---

## 1. Method — analysis → synthesis → invariants

Great anonymity systems were not designed on a whiteboard; they were forged by *incidents*. Tor's guard
nodes exist because of predecessor attacks; its onion-service PoW exists because of years of DDoS; its
pluggable transports exist because of the GFW. A reference architecture must therefore be derived
**backwards from the failure modes of the field**, not forwards from a feature list.

So the method is: (1) enumerate the real incidents and structural weaknesses of deployed systems;
(2) extract the *root cause* of each; (3) require the architecture to answer each root cause
**structurally** (by construction, not by patch); (4) crystallize the answers into a small set of
**invariants**; (5) verify every future component against them. The result is §2 → §3, and the
evolvability that falls out is §4.

---

## 2. Incident analysis — learning from the field

Each row is a real failure mode of a deployed system, its root cause, and the FANOS structural response
(built `[T]`, integration `[C]`, or research `[P]`). This is the evidence base for the invariants.

| Incident / weakness (field) | Root cause | FANOS structural response |
|---|---|---|
| **Directory-authority pressure** (Tor's 9–10 authorities: legal coercion, the 2014 Heartbleed key exposure) | a *global point of trust* that must be operated and can be compelled | **No authority.** The `PG(2,q)` geometry *is* the directory; membership is computed and gossiped, positions are VRF-self-certifying. Nothing to seize or coerce. `[T]` substrate / `[C]` at scale |
| **End-to-end traffic correlation** (low-latency onion routing is defeated by a global passive adversary; NSA/academic timing attacks) | latency-optimal routing preserves timing signatures | **The dial.** *Full* profile adds Poisson mixing + cover (Nym-class, global-adversary-resistant); *Lite* is honestly labelled low-latency. Constant-size onions kill the size channel. `[T]` |
| **Onion-service DDoS** (2022–23 sustained intro floods forced Tor to bolt on PoW) | admission is a *fixed, unpriced* resource with no feedback | **Lindbladian stabilization** — load is a mode relaxed to `ρ*` at spectral gap `Δ`; admission cost is super-linear in excitation; driven by *valid* load so garbage drops free. `[T]` |
| **Sybil / bad-relay campaigns** (KAX17: thousands of malicious Tor relays, 2017–21) | influence scales with the number of nodes an actor runs | **Anti-Sybil by geometry.** Structural centrality cap `(q+1)/N` (identical for every node) + threshold hops (below `t` = zero knowledge) + coherence reputation. Running many nodes buys no centrality. `[T]` |
| **Active probing & DPI blocking** (GFW fingerprints bridges and probes to confirm them) | the wire has a *static signature* and bridges are a *static list* | **PROTEUS** — polymorphic per-packet junk, beacon-rotating shape, **moving-target bridges** (derived from the beacon, no static list). Nothing static to fingerprint or enumerate. `[T]` core / `[C]` bridges |
| **DNS deanonymization** (DNS leaks are a top real-world deanon vector) | name resolution escapes the tunnel to the local resolver | **DNS is in-network.** `.fanos` is self-certifying (no DNS); clearnet DNS is resolved *over the overlay* via an exit, never locally. `[C]` (Phase 2) |
| **Incentive fragility** (Tor: no incentives → capacity ceiling; Nym: hard token dependency) | sustainability tied to either volunteerism or a mandatory token | **Optional, unlinkable credits.** VOPRF relay credits pay without deanonymizing and are *not required*; coherence reputation is a non-economic quality signal. `[T]` primitive / `[C]` settlement |
| **Protocol ossification** (Tor is slow to evolve; the network can't adapt quickly) | no negotiated extension path; upgrades are near-hard-forks | **Capability negotiation.** Versioned `min-version` + capability-intersection over a canonical KAT-pinned wire, so morphs, ciphers, and cell sizes are added *without a fork*. `[C]` |
| **Harvest-now-decrypt-later** (recorded traffic decrypted once a quantum computer exists) | classical-only crypto with no forward secrecy margin | **Hybrid PQ from day one** (Ed25519‖ML-DSA, X25519‖ML-KEM) + per-hop KEM forward secrecy. Breaking a hop needs a *relay's* long-term secret, not the sender's. `[T]` |
| **Silent degradation** (a failing/partitioning network has no self-view; humans must notice) | the network is *open-loop* — it cannot see its own state | **DIAKRISIS** — the reflexive plane reads `Γ_net`'s coherence and heals (reroute/repair/decouple/escalate). Closed-loop by construction. `[T]` |
| **Single-host seizure** (raid the machine, seize the service) | a service lives at *one* physical host | **Threshold hosting** (CALYPSO): the key is `t`-of-`(q+1)` shared; `< t` seized hosts learn nothing; CALYPSO-Balance spreads a fleet. `[T]` |

The pattern is deliberate: **every incident's root cause is a *point* — a point of trust, a point of
failure, a static point on the wire, a point of unpriced load.** The projective substrate answers all of
them with the same move: replace the point with a *line* (a quorum), the authority with *geometry*, the
static with the *rotating*, and the open loop with a *reflexive* one.

---

## 3. Architectural invariants

These nine invariants are load-bearing. Every crate, engine, and future feature is reviewed against
them (§7 traces each invariant back to the incidents it answers).

1. **Sans-I/O core.** All logic is a pure `Engine::step(now, Input) → [Effect]`; clocks, sockets, and
   RNG live only in drivers. → testable, deterministic, driver-portable. `[T]`
2. **No point of trust or coercion.** No directory authority, no privileged node. The geometry is the
   map; consensus is local and structural. `[T]`
3. **A hop / host / key is a *group*, not a node.** Maekawa line-hops (`t`-of-`(q+1)`), threshold
   hosting, DKG'd keys — below threshold, zero knowledge. `[T]`
4. **The network is reflexive.** It measures its own coherence and heals — homeostasis, not operator
   babysitting. This is the *evolution engine* (§4). `[T]`
5. **Post-quantum + crypto-agile.** Hybrid classical+PQ everywhere, and the cipher suite is negotiable,
   not baked. `[T]` hybrid / `[C]` agility
6. **Evolvability is a first-class invariant.** A canonical, KAT-pinned wire *plus* capability
   negotiation, so the protocol extends without forking. Ossification is a design bug. `[C]`
7. **The anonymity dial is honest.** Direct / Lite / Full, chosen per stream, each with a *stated*
   threat model — no silent over- or under-claiming. `[T]` engines / `[C]` wiring
8. **Derive, don't tune.** Every threshold, budget, and controller constant comes from the UHM dynamics
   (`r* = 1/√6`, `Φ→Φ/9`, `τ=1/Δ`, the coherence measures), not from hand-picked magic numbers. `[T]`
9. **Reproduce-then-verify.** Every headline claim is an executable test/verifier; the wire is
   KAT-pinned; the math is verifier-pinned. `[T]`

---

## 4. Evolvability — the architecture as a living organism

The user's requirement is a network that *evolves like a living organism*. That is not a metaphor here
— it is the direct consequence of invariant 4 (reflexivity) composed with invariant 6 (negotiated
extension). The mapping is exact:

| Organism | FANOS mechanism | Built? |
|---|---|---|
| **Homeostasis** — sense deviation, correct it | DIAKRISIS reads `Φ/P/R`, heals (reroute/repair/decouple/escalate) at rate `Δ`; the Lindbladian relaxation *is* the corrective reflex | `[T]` |
| **Genome / gene expression** — a stable code that expresses variable traits | Capability negotiation: a canonical wire (the "genome") expresses optional traits (morphs, ciphers, cell sizes) per peer, without mutating the core | `[C]` |
| **Adaptive camouflage** — change appearance to evade predators | PROTEUS: the wire polymorphs per packet and per epoch; bridges move | `[T]` core |
| **Self-similar growth** — tissues of the same cell type | The `N^k` cell hierarchy: a parent cell treats seven child cells as its own seven points, running the *same* reflexive loop one tier up | `[T]` (stratum) |
| **Vital signs** — one set of measurements across the body | The coherence measures (`Φ/P/R`, mean correlation `r`) drive health, admission pricing, reputation, and (future) consensus — one quantity, whole-stack | `[T]` |
| **Metabolism / energy** — sustainable resourcing | Optional VOPRF credits + coherence reputation (no mandatory token) | `[C]` |
| **Evolutionary selection** — keep what interoperates | New capabilities that reproduce the KATs and negotiate cleanly survive; the rest never propagate — natural selection over the capability space | `[C]` |

The crucial design decision that unlocks all of this: **the self-observing loop and the extension
mechanism are the *same architecture, one tier apart*.** DIAKRISIS lets the network adapt its *behaviour*
(routing, healing, admission) in real time; capability negotiation lets it adapt its *form* (features,
crypto, transport) across releases. A living system needs both — fast homeostasis and slow evolution —
and FANOS has both, derived from one substrate.

**Design rule for every future feature:** it must (a) be expressible as a negotiated capability over the
canonical wire (so it never forks the network), (b) expose its health to DIAKRISIS (so the network can
observe it), and (c) derive its constants from the UHM dynamics (so it stays coherent). A feature that
cannot do all three does not belong in the core — it belongs in an application on top.

---

## 5. The reference node — detailed design

One process, `fanos node`, composes engines behind one driver.

```
                    ┌──────────────────────── fanos node (one process) ────────────────────────┐
   config ─────────▶│  Supervisor: owns identity, clock, RNG, config, connections               │
   .fanos/DNS ──────▶│    ├─ OverlayNode  — membership · liveness · storage · DIAKRISIS healing   │  ← always
   SOCKS5/UDP ──────▶│    ├─ NyxNode        — Lite: single-relay PQ onion + mixing + cover         │  ← relay opt
   TUN (vpn) ───────▶│    ├─ ThresholdRouter— Full: line-hop threshold onion + mixing              │  ← relay opt
                     │    ├─ DkgNode         — line-committee distributed key generation            │  ← host opt
                     │    └─ CalypsoHost     — .fanos service (single or Balance fleet)             │  ← service opt
                     │  Driver: fanos-quic (UDP + QUIC/TLS 1.3, PROTEUS-shaped)                      │
                     └────────────────────────────────────────────────────────────────────────────┘
```

- **Supervisor.** The only stateful I/O owner: reads config, holds the cert-bound self-certifying
  identity (`coord = MapToPoint(H(cert))`, built), persists `NodeCredentials`, opens QUIC connections,
  and runs the `Input → Effect` loop that fans events to the engines and performs their effects. This is
  the *only* new code Phase 1 needs — everything below it is built and tested.
- **Engine composition.** A node advertises a **role set** (relay, storage, service, exit) and a
  **capability set** (profiles, morphs, ciphers) via JOIN; peers negotiate the intersection. A minimal
  node runs only `OverlayNode`; a full node runs all engines. Capability negotiation keeps them wire-compatible.
- **The dial** is realized here: a stream request carries `profile ∈ {Direct, Lite, Full}`; the
  supervisor routes it through the plain path, `NyxNode`, or `ThresholdRouter` accordingly.
- **Surfaces** (Phase 2) are thin adapters over the node: `fanos proxy` (SOCKS5/HTTP-CONNECT + DNS),
  `fanos vpn` (TUN), the C ABI, and the native `dial/host/connect` API — all speaking to the same node.

---

## 6. Threat model, per profile (honest)

Anonymity claims are only meaningful against a stated adversary. The dial makes this explicit:

| Adversary | Direct | Lite | Full |
|---|:-:|:-:|:-:|
| Local/ISP observer | ✗ | ✓ | ✓ |
| Malicious relay (single) | — | ✓ (needs the whole path) | ✓✓ (needs `t`-of-line per hop) |
| **Global passive** (timing correlation) | ✗ | ✗ (low-latency, honest) | ✓ (Poisson mixing + cover) |
| DPI / active-probing censor | with PROTEUS | with PROTEUS | with PROTEUS |
| Quantum adversary (future) | ✓ (PQ transport) | ✓ | ✓ |
| DoS flood on a service | Lindbladian stabilization + threshold admission | — | — |

The honest limit, shared by *all* anonymity networks, holds: as the fraction `f` of adversary-controlled
relays → 0.5, endpoint unlinkability degrades. FANOS pushes the constant hard (line-hops make
`P_link = P_hop^L` with `P_hop` a *threshold* tail, spec §5.2) but does not claim to repeal it.

---

## 7. Traceability — invariants answer incidents

Every invariant exists to neutralize specific field failures — the design is falsifiable, not decorative:

- **No point of trust (2)** ⟵ directory pressure, single-host seizure.
- **Group-not-node (3)** ⟵ bad-relay/Sybil campaigns, single-host seizure, relay compromise.
- **Reflexive (4)** ⟵ silent degradation, load floods (with 8).
- **PQ + agile (5)** ⟵ harvest-now-decrypt-later, cipher breaks.
- **Evolvable (6)** ⟵ protocol ossification, the censorship arms race.
- **Honest dial (7)** ⟵ traffic-correlation over-claiming.
- **Derive-don't-tune (8)** ⟵ DDoS (formal stabilization vs. magic thresholds), and coherence of the whole.
- **Sans-I/O (1)** and **reproduce-then-verify (9)** are the meta-invariants that keep the other seven
  correct as the system grows.

A new feature review asks: *which incident does this prevent, and which invariant does it uphold?* If it
answers neither, it is scope creep.

---

## 8. The name — a three-letter successor (catalogued, deferred)

**FANOS is retained for now.** Should a three-letter successor in the `tor` / `i2p` / `nym` lineage be
wanted later — to carry the project's essence, a network that *knows and heals itself* — the candidates
are catalogued here. The leading option:

- **`NOS`** — from Greek **νόος / νοῦς** ("mind, intellect, self-awareness"): *the network that observes
  itself*. It is literally the tail of FANOS (heritage preserved), three letters, pronounceable, and
  exactly names the reflexive core (DIAKRISIS is the net's *nous*). Backronym-friendly: *Noetic Overlay
  System*.

Alternatives, if a fresher root is preferred:

- **`AXO`** — from *axon*, the living network's transmitting fibre (organism/evolution connotation).
- **`ORB`** — the all-seeing orb (self-observation) over the projective sphere; evocative and memorable.
- **`NUS`** — the cleaner Latin spelling of *nous* (same meaning as NOS).

The subsystem names (NYX, APHANTOS, CALYPSO, PROTEUS, DIAKRISIS) already form a coherent mythic register
and can stay regardless of the top-level rename. **This is a brand decision — the architecture above is
name-independent** and every crate can be re-prefixed mechanically once chosen.

---

## 9. Component design — censorship-resistant bootstrap

The hardest problem a real deployment faces is not routing but **entry**: a new node must reach *one*
live peer, and that is exactly the choke a censor attacks (the GFW blocks known entry IPs and probes
suspected bridges). Tor answers with directory authorities plus a bridge database — both enumerable and
blockable. FANOS bootstraps by **derivation, not enumeration**, over three composable paths:

1. **Open path** — a shipped seed set of well-known nodes, for the un-censored network. Simplest, blockable.
2. **Moving-target bridges** — the censored path. A community shares a `bridge_secret` out of band (a
   contact, a QR, a mesh); the current entry is `bridge = f(bridge_secret, epoch)` (built:
   `fanos-proteus::bridge_line`), rotating every epoch. A user with the secret computes *today's* bridge;
   a censor **without** the secret cannot enumerate the space, and yesterday's bridge is already stale.
   There is no static list to block. The connection rides a PROTEUS morph, so the wire looks like nothing.
3. **Peer exchange** — once inside, a node learns more peers by gossip (spec §L3 membership flood), so a
   single successful entry seeds a full view. Bootstrap fragility decays to zero after the first contact.

`fanos node --bridge <secret>` selects path 2. **Design invariants honoured:** no authority (2), nothing
static to block (6), reflexive recovery if a bridge dies (4, the node re-derives and retries).
**Open residual `[P]`:** the *first* out-of-band `bridge_secret` distribution is a human/social channel,
not a protocol one — the universal bootstrap-trust problem, which no network solves purely in-band.

---

## 10. Component design — the exit / clearnet gateway

Exits are where deanonymization and legal liability concentrate: an exit sees the cleartext destination
(inherently — *someone* must speak to the clearnet), can sniff or inject, and its operator bears abuse
complaints. The design contains, not eliminates, this:

- **Exit is an opt-in role** advertised as a capability, with an **exit policy** (allowed
  ports/host-patterns) negotiated like any other. Most nodes are not exits.
- **What an exit learns and doesn't.** It learns the *destination* (must, to connect) and the *content*
  if unencrypted (use TLS end-to-end — the exit is untrusted, exactly as a Tor exit). It does **not**
  learn the *origin*: the stream arrives onion-routed, so the exit sees only the last hop. Origin↔exit
  unlinkability is the whole point and is preserved.
- **DNS through the exit** (see §11) so the client never resolves locally.
- **Accountability without linkability.** The exit's cert-bound identity makes it accountable for policy
  and reputation (DIAKRISIS coherence + abuse signals), while clients stay unlinkable — the two
  properties do not conflict because identity binds the *exit*, not the *stream's origin*.
- **`[P]` frontier — threshold exit.** A genuinely FANOS-native improvement is to make the *line*, not a
  node, the exit: `t`-of-`(q+1)` members jointly authorize (and rate-limit) the clearnet connection, so no
  single exit operator sees all a client's destinations and none can unilaterally inject. The connection
  itself is still made by one member (TCP is point-to-point), but *authorization and logging are
  threshold-shared* — spreading liability and trust the way threshold hosting does for services. Deferred
  as research; the single-exit design ships first.

---

## 11. Component design — DNS without leaks

DNS is the most common real-world deanonymizer: even a perfect tunnel is defeated if the browser resolves
`example.com` via the local ISP resolver. The rule is absolute — **resolution never escapes the tunnel**:

- **`.fanos` names** resolve locally with *no DNS at all*: the address self-certifies the service key, and
  CALYPSO computes the rendezvous (built). Zero network resolution, zero leak.
- **Clearnet names** are resolved **at the exit, over the circuit**: the client hands the *name* (not an
  IP) into the onion; the exit resolves it (its resolver, or DoH for integrity) and connects. SOCKS5's
  domain-address mode makes this native — the proxy forwards names, never pre-resolving.
- **VPN / UDP mode** captures port-53 traffic at the TUN and tunnels it the same way, so even apps that
  bypass SOCKS cannot leak.
- **Caching is a fingerprint** and is therefore bound to the *session/circuit* (evicted on rotation),
  trading a little circuit load for unlinkability — an explicit, honest trade (invariant 7).

**Design invariant honoured:** close every side channel by construction (the incident-2 family). DNS is a
first-class network feature here, not a proxy afterthought.

---

## 12. Component design — capability negotiation, the evolvability genome

This is the mechanism that makes invariant 6 real: the protocol must *evolve continuously* (new morphs,
ciphers, cell sizes, roles) without a hard fork, because censorship is a perpetual arms race and a
network that cannot change is a network that will be blocked.

- **Advertisement.** Each node's `HELLO`/`JOIN` carries a monotone `version` and a `capability` bitfield
  (profiles `{Direct,Lite,Full}`, morphs, cipher suites, cell size `q`, roles `{relay,storage,exit,service}`),
  spec §7.4. Old bits keep their meaning forever; new features are new bits.
- **Negotiation.** Two peers operate at `min(version)` and the **intersection** of capabilities. A
  minimal DHT-only node interoperates with a full mixnet+service node — the full node simply does not
  offer it NYX/CALYPSO frames. Unknown bits are ignored (forward-compatible).
- **Extension = mutation; interoperation = selection.** A new capability propagates only if nodes adopt
  it *and* it reproduces the canonical KAT vectors (§7.9); one that cannot interoperate never spreads.
  This is literally natural selection over the capability space — the "genome" (the KAT-pinned wire)
  expresses variable "traits" (capabilities), and the network keeps what survives contact.
- **Deprecation** is passive: nodes stop advertising a capability, and the intersection drops it — no
  coordinated flag day.
- **Security — no silent downgrade.** The capability set is bound to the node's identity in the signed
  `HELLO`, and each side enforces a *policy floor* (e.g. "refuse below Lite for this stream"), so an
  active attacker cannot strip a peer down to a weaker profile or cipher. Downgrade resistance is part of
  the negotiation, not an add-on.

This is the slow, structural counterpart to DIAKRISIS's fast, behavioural adaptation (§4): together they
are why the platform can *keep evolving as part of its architecture* — homeostasis within a release,
selection across releases — the living-organism property the project is built to have.

