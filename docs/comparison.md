# FANOS in the landscape — an honest comparison (Tor · Nym · I2P · Lokinet · Veilid)

This document compares FANOS to the anonymity networks it is closest to. It is written to be *useful*, which
means it leads with the concessions, not the wins. Where a rival is ahead, it says so plainly.

## 0. The meta-caveat — read this first

**FANOS has no users, no deployment, and no external audit.** It is a reference implementation of a research
architecture. Every network below has *shipped*: Tor for ~20 years to millions of daily users; I2P and Nym for
years; Lokinet powers Session's ~1.7M monthly users; Veilid ships a mobile app. FANOS powers a test harness.

That gap matters more than any feature, because of a fact both of the newest rivals concede about themselves:
**anonymity is a property of the live crowd, not of the routing mathematics.** Lokinet has cleaner primitives
than most and still delivers weak practical anonymity because ~2,000 relays and a near-empty hidden-service
ecosystem is a tiny anonymity set. Veilid's own first independent study (IEEE CSR 2024) is descriptive and
critical, and its anonymity is *asserted, not proven*. FANOS proves its *math* (the V1–V22 claims are executable
tests) but cannot prove an *anonymity set it does not have*. A provably-better topology is a precondition for a
strong network, never a substitute for adoption. Everything below is "how FANOS is designed to compare *if it
earns a crowd*."

## 1. At a glance

| | **Tor** | **I2P** | **Nym** | **Lokinet** | **Veilid** | **FANOS** |
|---|---|---|---|---|---|---|
| **Model** | onion, TCP/SOCKS | garlic, packet, all-IP | **mixnet** (timing defence) | onion, **layer-3 all-IP** | onion-derived routes over a DHT | onion + **threshold-sheaf** (a hop is a *line*), Poisson mix dial |
| **Topology / position** | directory-listed relays | netDB (DHT) | directory + mixmining | blockchain-listed service nodes | **random** 256-bit pubkey (XOR) | **computed** coordinate `MapToPoint(VRF(sk,id‖epoch‖beacon))` |
| **Rendezvous** | HSDir descriptors | leaseSets (DHT) | — | introset (DHT) | private/safety routes (DHT) | **O(1) computed** — the line through two points is their cross product |
| **Self-organization** | manual relay config + DAs | manual + netDB | staked mixnodes | staked, multi-role | **zero-touch**, opt-in capability flags + detected reachability (VICE) | zero-touch, **capability-*assigned*** roles (`roles::assign`) + computed position |
| **Sybil resistance** | trusted directory authorities | none (open) | **stake** (NYM) | **stake** (SESH/OXEN) | **none** (free keypairs) | **structural** centrality cap `(q+1)/N` + **PoW-priced placement** + performance reputation |
| **Blockchain / economics** | none | none | token (mixmining rewards) | CryptoNote→Arbitrum chain, staking | **none, by design** | **derived** BFT chain (TAXIS) + anonymous VOPRF credits — geometry-native, not bolted on |
| **Post-quantum** | classical (some PQ handshakes landing) | classical | classical | **classical** | **classical** (crypto-agile, no PQ) | **hybrid PQ from day one** (Ed25519+ML-DSA-65, X25519+ML-KEM-768) |
| **Formal analysis** | extensive academic | some | mixnet literature | thin (LLARP under-studied) | one descriptive/critical paper; anonymity *asserted* | V1–V22 executable proofs of the *math*; anonymity of a live net *unbuilt* |
| **Maturity** | ~20 yrs, millions | years | live | live, ~2k nodes, 1.7M via Session | pre-1.0 (~3 yrs), early-alpha app | **pre-everything** (reference impl) |
| **Mobile / reachability** | Orbot | limited | — | Session (mobile) | **mobile-first**, WASM, VICE NAT traversal | designed (NAT traversal done); **no mobile/browser client yet** |

## 2. Network by network — the honest read

**Tor.** The incumbent, and the standard FANOS must be measured against. Its structural weaknesses are real: a
handful of **directory authorities** are a centralization and censorship chokepoint, a hop is a single node
(one point of compromise), and rendezvous/HSDir lookups are search-based. FANOS removes all three — no
authorities (position is computed and self-certifying), a hop is a *line* (a `t`-of-`q+1` threshold group, so
endpoint linkage drops to `P_hop²`), and rendezvous is O(1) arithmetic. But Tor has two decades of academic
scrutiny and a crowd of millions; FANOS has neither. Tor's crypto is mostly classical (PQ handshakes are
landing); FANOS is hybrid-PQ throughout. Net: FANOS is *architecturally* ahead and *empirically* nowhere.

**Nym.** The closest prior art for FANOS's ambition of a *verifiable, incentivized mixnet*. Nym adds real timing
defences (a Poisson mixnet) and a token-incentivized mixnode set with "mixmining." FANOS's mixing (Poisson +
structurally-balanced cover, a `λ` latency dial) and its incentive equilibrium are the same family; the
difference is that FANOS derives committees and randomness from geometry rather than a token, and its verifiable
*shuffle* is designed, not deployed (and its post-quantum shuffle backend is, honestly, an experimental research
scaffold — see `docs/design-pq-vrf.md`). Nym ships; FANOS's mixnet runs in a simulator and a loopback transport.

**I2P.** Shares FANOS's packet-switched, all-IP, exit-averse philosophy (garlic routing, in-net services). I2P's
netDB is a DHT with the usual eventual-consistency and Sybil concerns; FANOS replaces the DHT with computed
placement. I2P is mature and self-organizing in practice; FANOS's self-organization is more principled on paper
and unproven in the field.

**Lokinet.** The closest prior art for FANOS's *whole stack*: onion routing **plus** a blockchain **plus**
incentivized, multi-role nodes. Lokinet is genuinely strong where it counts — **layer-3 any-protocol** anonymity
(UDP/ICMP, which Tor lacks), **economic Sybil resistance** via staking (making cheap Sybil floods expensive), no
directory authorities, and a real 1.7M-user downstream (Session). Its honest weaknesses are exactly the ones
FANOS is designed to avoid — and one it must heed:
- *Staking = plutocracy.* Routing capacity and consensus weight accrue to whoever holds the most tokens;
  security scales with **market cap**, not with any anonymity metric. FANOS's centrality is the *structural*
  `(q+1)/N` cap — identical for every node, **not purchasable** — and its Sybil cost is PoW-priced *placement*,
  not stake. This is a real, fundamental difference in the right direction.
- *A separate chain.* Lokinet's membership/naming/trust hard-depends on a CryptoNote fork now re-platformed onto
  Arbitrum (an L2 with its own sequencer trust). FANOS's chain (TAXIS) is **derived from the same geometry** that
  does routing — no separate chain to secure or congest (see §4).
- *Classical crypto, thin scrutiny.* Lokinet is entirely classical; LLARP has had little independent analysis.
  FANOS is hybrid-PQ and its math is executable-proof-pinned.
- **The lesson FANOS must concede:** Lokinet's globally-enumerable staked registry is superb for coordination
  *and* is simultaneously a deanonymization/targeting surface. FANOS's geometric membership map is *also*
  globally computable — a targeting surface, and a *farming* surface if occupying a point/line were ever cheap.
  FANOS answers this exactly as it should (VRF-rotated coordinates + beacon unpredictability + PoW placement so
  points can't be cheaply farmed), but the concern is permanent, and elegance is not anonymity.

**Veilid.** The closest prior art for FANOS's *self-organization* ambition, and the sharpest mirror. Veilid is a
no-blockchain P2P **framework** (not an app) that onboards a node behind NAT, on cellular, or in a browser with a
**single DNS query and zero configuration** — by *detecting what each node can do* (VICE reachability → a
`NetworkClass`) and letting it *opt into* capability flags (ROUT/RLAY/DHTV/…), with volunteer relays covering the
unreachable. What it deliberately does **not** do is the two things FANOS is built for:
- *Structured placement.* A Veilid node's position is its **random 256-bit public key** (XOR distance) — not
  computed, not structured. FANOS's is a computed projective coordinate.
- *Capability-aware role assignment.* Veilid roles are **opt-in flags plus detected reachability only** — there
  is **no** assignment by measured bandwidth, uptime, or latency. FANOS's `roles::assign` deterministically and
  verifiably *assigns* active roles by capability weight, rotating each epoch. FANOS is strictly more principled
  here.
- Veilid also has **no Sybil resistance at all** (free keypairs, no PoW/stake/reputation) and **no post-quantum**
  — the exact territory FANOS's structural cap + PoW + hybrid-PQ claims.
- **The lesson FANOS must concede:** Veilid *ships* precisely because its self-organization is invisible and
  reachability-robust, in code the user never sees. FANOS's computed-coordinate + capability-assignment is more
  principled **only if it is as zero-touch, NAT-robust, and mobile-capable as VICE.** Veilid chose ergonomic
  minimalism *over* Sybil resistance and formal anonymity; FANOS chooses the opposite — but if it trades away
  Veilid's usability for elegance, the elegance is worthless. FANOS has the NAT traversal (done) but **no mobile
  or browser client yet** — a concrete, honest gap.

## 3. What FANOS genuinely does differently

Setting deployment aside (§0), these are real architectural distinctions, not marketing:

1. **Computed, not searched.** Position, quorum membership, rendezvous, committees, and now *roles* are
   arithmetic on `PG(2,q)` — O(1), verifiable, coordination-free — where the others iterate a DHT or consult a
   directory/registry.
2. **A hop is a line, not a node.** Threshold-sheaf onions make the unit of trust a `t`-of-`q+1` group, dropping
   endpoint linkage to `P_hop²` rather than `f²`. None of the others thresholds a hop.
3. **Hybrid post-quantum from day one.** Alone in this table. Tor, I2P, Nym, Lokinet, and Veilid are classical
   (Veilid is crypto-agile but ships no PQ). "Harvest now, decrypt later" fails against traffic recorded today.
4. **Non-plutocratic Sybil resistance.** The centrality cap `(q+1)/N` is structural and identical for all;
   placement is PoW-priced, not stake-bought. Influence cannot be purchased (contra Lokinet), and Sybil floods
   are priced (contra Veilid).
5. **Self-organization *by capability*.** Roles are assigned to the fittest capable nodes and rotate each epoch
   (`roles`), where Veilid only lets nodes opt into flags and Lokinet gates on stake.
6. **An L0 substrate derived from geometry** (§4) — one structure underlies routing, services, VPN, transport,
   *and* an unbounded lattice of BFT ledgers, with no separate hub/relay chain.
7. **The math is proven.** V1–V22 are executable tests; the wire is KAT-pinned. The novel crypto has had an
   adversarial internal review that found and fixed real breaks (see the honest-status section of the README).
   This is more formal grounding than Veilid (asserted) or Lokinet (thin) — *for the math*, not the live net.

## 4. The blockchain: L0, not L1-bolted-on

Lokinet bolts a CryptoNote/Arbitrum chain beneath its overlay; Veilid rejects a chain entirely. FANOS takes a
third path: **the geometry itself is the L0 substrate**, and each cell's TAXIS is an L1-equivalent BFT ledger
running inside it. The plane + beacon supply shared addressing, randomness, committee selection, data
availability, and cross-shard bridging (the unique Maekawa intersection point) with **no underlying chain to
secure or congest**; the hierarchy of cells composes them, a parent cell giving child cells shared randomness and
DA fallback — *shared security without a separate relay chain*. This is a cleaner L0 than Cosmos (which trades
shared security for sovereignty) or Polkadot (which buys it with a relay-chain bottleneck): FANOS gets sovereign
per-cell execution *and* a shared substrate, because the substrate is algebra, not a chain. The full design is in
`docs/design-self-organization.md` §6 and `docs/design-taxis.md`.

## 5. The honest scorecard

- **Where FANOS leads (by design):** post-quantum, computed O(1) structure, threshold-per-hop trust, non-
  plutocratic Sybil resistance, capability-based self-organization, a geometry-derived L0, executable-proof math.
- **Where FANOS is even (on paper):** exit-averse all-IP ambition (I2P/Lokinet), mixing + incentives (Nym),
  zero-touch onboarding intent (Veilid).
- **Where FANOS is behind (today, and it matters most):** **no crowd, no deployment, no external audit, no
  mobile/browser client.** Tor has scale and scrutiny; Lokinet and Session have real users and staked reliability;
  Veilid has mobile reach and shipping ergonomics. FANOS has a simulator, a reference implementation, and a set
  of proofs. Until it earns a crowd and clears the usability bar those rivals have already cleared, its
  advantages are potential, not realized — and this document would rather say that than oversell.
