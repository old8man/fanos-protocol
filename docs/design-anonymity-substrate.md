# The FANOS anonymity substrate — a derived-native design (NOSTOS · POROS · the two-lane substrate)

> This note replaces the earlier Tor/Sphinx *ports* (the single-relay reply block, the fixed-bridge bootstrap)
> with mechanisms **derived from FANOS's own structure** — the projective plane `PG(2,q)`, the below-threshold
> zero-knowledge line hop, the unbiasable DVRF beacon, and the VRF-rotated coordinates. It is grounded in an
> external audit of the 2013–2026 research frontier (arXiv / IACR / PoPETs / USENIX Sec / IEEE S&P / NSDI /
> SOSP-OSDI); every load-bearing claim is either a cited result or a stated **theorem to prove**. Where a
> mechanism is, to the surveyed frontier, a genuine gap, that is said plainly — and so is every precondition its
> security rests on. The Tor vocabulary ("SURB", "bridge", "rendezvous") is retired for the pantheon.

## 0. The one theorem everything obeys — and why there must be two lanes

**The Anonymity Trilemma** (Das, Meiser, Mohammadi, Kate, *IEEE S&P 2018*, ePrint 2017/954; strengthened for
coordinated users in *Comprehensive Anonymity Trilemma*, PoPETs 2020): against a global passive adversary, no
protocol achieves strong anonymity when `2ℓβ < 1 − negl`, where `ℓ` = latency overhead (rounds a message may be
delayed) and `β` = bandwidth overhead (per-user cover rate/round). The **low-latency ∧ low-overhead ∧
strong-anonymity** corner is *provably empty*; you escape only by paying `ℓ` (mixing delay) **or** `β` (cover).

FANOS is simultaneously a **maximal-anonymity network** and a **high-throughput L1 + platform for an app
hierarchy**. The trilemma proves these cannot be one tunable pipe. So the architecture is **two lanes over one
substrate**, selected by a **per-flow mode bit** (default FAST, opt-in MIX) — the design NymVPN validates in
production (one-click 5-hop Sphinx-mixnet "Anonymous" vs 2-hop WireGuard "Fast"). The lanes **share** the
substrate and **diverge** only at the transport. This is not a compromise of the algebra; it is the algebra
serving two masters the theorem says must be served separately.

## 1. The shared substrate (both lanes)

1. **`PG(2,q)` point/line incidence + `O(1)` algebraic routing.** `q²+q+1` points and lines; any two points lie
   on exactly one line; any two lines meet in exactly one point — the meet is a **cross-product over `GF(q)³`**,
   no lookup. Diameter-2 routing (any two points share a line ⇒ ≤2 structural hops). Load is `≈1/√N`-optimal
   (Maekawa quorums, *ACM TOCS 1985*; Naor–Wool; the RP2 datacenter topology) — textbook for *coordination*,
   never before fused with an anonymity fast path.
2. **DVRF beacon + VRF-rotated coordinates.** Unbiasable epoch randomness assigns each node's point via
   `coord = MapToPoint(VRF(sk, id ‖ epoch ‖ beacon))` (already built, [[coordinate-vrf-architecture]]). No fixed
   positions; the adversary cannot *choose* which line to pack, and membership rotates each epoch.
3. **The line as a `t`-of-`(q+1)` threshold committee**, below-threshold zero-knowledge (`t−1` shares reveal
   nothing — Shamir perfect secrecy). One structure, two uses: a **mixing/ZK hop** (MIX lane) and a
   **BFT/erasure/broadcast committee** (FAST lane).
4. **PQ identity + placement-priced admission** (the existing PoW-placement + reputation, [[self-organization-and-comparison]]).

## 2. The FAST lane — maximum throughput (and, correctly, no strong anonymity)

The trilemma says a low-latency low-overhead lane *cannot* be strongly anonymous; that is acceptable, because
this lane carries TAXIS/DROMOS and the app hierarchy, whose threat model is integrity/liveness, not
unobservability. It gets its throughput from the three moves every fast blockchain plane uses (Narwhal/Tusk
*EuroSys 2022*; Solana Turbine; Kadcast *AFT 2019*):
- **Decouple dissemination from ordering** — a Narwhal-style DAG mempool spreads payloads in parallel; TAXIS
  orders only tiny certificates (→ 130K–600K tx/s in the literature).
- **Structured fanout, not flat gossip** — erasure-coded shreds propagated down the **line-incidence tree**
  (the beacon supplies the unbiasable tree shuffle), à la Turbine; the geometry gives the tree for free.
- **FEC over QUIC**, not retransmission.
- Then **DROMOS** parallel execution ([[dromos-parallel-execution]]).

`β=0, ℓ=O(1)`. **Required addition — role-privacy in-protocol.** USENIX Security 2025 deanonymized >15% of
Ethereum validators from 4 vantage nodes via gossip-timing; the field's answer is *not* network anonymity
(Tor-push costs +614 ms, impossible at DAG-BFT tempo) but **secret leader election** (Whisk/SSLE — hide *who* in
the committee, zero network latency). TAXIS's leader/keyper is already **beacon-VRF-elected**; making that
election *secret* (SSLE-grade) gives the fast lane the only anonymity a fast lane can afford. **Theorem to
state:** the beacon-VRF committee election is a single-secret-leader election under the DVRF's unpredictability.

## 3. NOSTOS (νόστος, "the homecoming") — receiver anonymity, derived not ported

**What it replaces.** Sphinx single-use reply blocks route the reply through *single relays* to a *coordinate a
delivery node learns*; Kuhn et al. (*IEEE S&P 2020*) proved reply-payload tampering on single-relay reply paths
can break whole-protocol anonymity. The sealed single-relay reply block built earlier is exactly that fragile
2009-era construction. It is retired.

**The construction.** The reply comes home on the receiver's **own line** — one of the `q+1` lines through its
point — computed by cross-product from a shared secret + the beacon. The receiver is a *member* of that line,
hidden inside its **`q+1`-node anonymity set**. There is no "delivery node" and no coordinate to leak. Each
return hop **is a line**, threshold-peeled `t`-of-`(q+1)`; below `t`, a corrupt subset learns **zero**. The
innermost is E2E-sealed (PQ AEAD), so the combiner delivers *ciphertext to the line* — a **geometric
dead-drop** — and only the receiver decrypts. Header/payload split (the responder inserts only the payload),
but over threshold lines, not single relays.

**Why it is genuinely new (audit verdict).** The receiver-anonymity frontier splits two ways and NOSTOS heals
both weaknesses: mixnet reply (Loopix/Nym) needs a **semi-trusted provider that knows the receiver** with
single-relay hops; private dead-drops (Pung, Talek, Express, Riposte, Spectrum — the strongest cryptographic
receiver guarantee) need a **fixed mailbox host** and an **anytrust (`1`-of-`n` global)** model. The audit's
words: *"no prior construction makes a reply hop a threshold `t`-of-`(q+1)` set with below-threshold
information-theoretic routing privacy,"* and *"the composite — reply landing on the receiver's own line as a
`q+1` dead-drop, threshold-peeled, E2E-sealed, over VRF-rotated coordinates — is, to the frontier surveyed,
novel."* It **removes the semi-trusted mailbox every strong receiver system needs**.

**The precondition that makes it sound — not optional.** The *only* prior finite-geometry anonymity system
(UPIR over projective planes) was **broken by a single colluding user, precisely because any two users share
exactly one point** (Gnilke et al., *DCC 2019*). The unique-meet incidence that makes rendezvous `O(1)` is,
unguarded, a *deanonymization primitive*: anyone who knows or shares one input line computes the meet. NOSTOS
therefore rests on **at least one input coordinate being VRF-beacon-blinded and epoch-rotated** (the FANOS
coordinate-VRF — the geometric analog of Tor v3's blinded keys). The design **must characterize the anonymity
set explicitly** — which observers, which inputs secret — or it is rendezvous-efficiency, not anonymity.

**Theorems to prove (open problems the audit flags as FANOS's to claim):**
- **T1 (below-threshold IT receiver anonymity).** Extend the repliable-onion UC functionality (Ando–Lysyanskaya
  *TCC 2021*; Kuhn et al. *ASIACRYPT 2021*) so a hop is a `t`-of-`(q+1)` set; prove backward (receiver)
  anonymity holds information-theoretically against any `< t`-per-line corruption. *No such theorem exists.*
- **T2 (blinded-rendezvous anonymity).** With one input VRF-blinded, the meet point is unpredictable and
  unlinkable to a computationally-bounded observer outside the receiver's line; state the anonymity set as the
  `q+1` line members and prove non-linkability across epochs.
- **T3 (intersection resistance from rotation).** Prove unbiasable per-epoch coordinate rotation raises the
  sample complexity / cost of the long-term statistical-disclosure (intersection) attack that defeats
  Loopix-class systems over time — the unsolved receiver-anonymity threat.

## 4. The MIX lane — ultimate anonymity, and the Anytrust-escape it buys

A hop **is a line**, threshold-encrypted `t`-of-`(q+1)`, below-threshold ZK; Sphinx-uniform packets; Loopix
Poisson per-hop delay + loop cover to pay the mandatory `βℓ=Ω(1)`; VRF-random independent per-packet routes.
Optional **latency-aware routing bias** (LARMix/LAMP, *NDSS 2024/25*: 7–8× lower latency for 1–2 bits of
entropy) over the algebraic routing gives a *graduated* anonymity dial within the lane.

**The provable efficiency win (theorem to prove — T4).** The trilemma's cost is driven by `c` (compromised
parties); its Anytrust regime forces latency `~√K`. A FANOS hop is broken only if `≥ t` of its `q+1` members are
corrupt. Under corruption fraction `f`, threshold ratio `τ = t/(q+1)`:

> `P_break = Pr[Binomial(q+1, f) ≥ t] ≤ exp(−(q+1)·D(τ‖f))` — **exponentially small in `q` for any `f < τ`**.

So `c_eff ≈ ℓ·P_break ≈ 0` w.h.p.; the degraded bound `2(ℓ−c)β` **collapses to the honest-network bound**
`2ℓβ ≥ 1−negl` even under Byzantine *node* corruption up to `τ`; FANOS **never enters the Anytrust regime**,
never pays the `√K` latency. The DVRF beacon + VRF-rotated coordinates make this hold against *adaptive*
corruption (the adversary cannot pre-select and pack a target line). **Honest bound:** this does *not* repeal
the trilemma — the MIX lane still spends real `βℓ`. It converts a *node-level* corruption budget into an
exponentially-safer *line-level threshold* budget, letting the anonymity lane run at the **non-compromised
frontier** (minimum latency the pure `βℓ` bound allows) instead of the inflated Anytrust penalty. This is a
Chernoff design derivation, not yet a published theorem; T4 is to formalize it.

## 5. The per-flow mode bit — fingerprint-safe by construction

Tor *refuses* a path-length knob because a per-user anonymity setting (path length, delay profile) becomes a
fingerprint. FANOS answers architecturally: **uniform packet format across both lanes** (Sphinx-shaped cells
whether MIX or FAST), the mode carried where it does not leak, and both lanes riding the *same* `PG(2,q)`
substrate — so lane membership is not an observable per-user identifier. The MIX-lane delay profile is drawn
from the shared Poisson parameters, not per-application (Nym's own admitted app-distinguishability caveat).

## 6. POROS (πόρος, "the way through") — censorship-resistant ingress

> *Pending the unblockable-bootstrap audit; this section states the derived design, to be reconciled with the
> audit's prior-art and theory findings when they land.*

A censor's goal is *aporia* — no way through. POROS guarantees a **way through** without fixed, enumerable
bridges. Because coordinates are VRF-rotated there are **no fixed endpoints** to enumerate. The entry for an
epoch **is a beacon-derived line**, **threshold-hosted** (`t`-of-`(q+1)` — reuse the CALYPSO ThresholdService,
[[threshold-calypso-hosting]]) so no single node holds the entry set; anti-enumeration is intrinsic (a censor
must predict the unbiasable beacon *and* break a threshold, vs scrape a bucketed list); Sybil-cost comes from
the **holonic coherence/placement** structure, not wasteful hashing. The unique-meet blinding precondition of §3
applies: the ingress line must fold a community secret into the beacon derivation so it is unpredictable to a
censor outside the community. **The irreducible residual** (stated honestly, as the frontier does): a brand-new
node with no beacon and no peer needs **one** out-of-band unblockable carrier to receive the first beacon/secret
— minimized, not eliminated, by PROTEUS obfuscation ([[proteus-morph-transforms]]) and diverse carriers.

## 7. Novelty, stated for the record

To the 2013–2026 frontier surveyed: (i) the **threshold-line below-ZK reply hop** is a literature gap; (ii) the
**geometric line-dead-drop with no fixed host** removes the semi-trusted mailbox every strong receiver system
needs; (iii) **rendezvous as an element of the routing geometry** (`O(1)` cross-product of identity-bound,
beacon-blinded coordinates) is unmatched — and *lookup-free*, which kills the DHT-lookup-leak attack class that
broke NISAN/Torsk/Octopus; (iv) a **single algebraic substrate whose lines serve as both threshold-mix/ZK hops
and BFT/erasure committees, toggled per-flow**, has no prior art. The components each have precedent; the
*synthesis* is ours. None of this repeals the trilemma — it moves FANOS to the best point the trilemma allows,
with an information-theoretic per-hop guarantee no single-relay or anytrust system provides.

## 8. Sources

Anonymity Trilemma (ePrint 2017/954; PoPETs 2020) · Loopix (USENIX Sec 2017) · Nym whitepaper · NymVPN
Fast/Anonymous · Cryptographic Shallots (TCC 2021) · Kuhn "Onion Routing with Replies" (ePrint 2021/1178) ·
Kuhn et al. reply-tampering (IEEE S&P 2020) · Pung (OSDI 2016) · Talek (ACSAC 2020) · Express (USENIX Sec 2021)
· Riposte (IEEE S&P 2015) · Vuvuzela/Karaoke (SOSP'15/OSDI'18) · UPIR + Gnilke et al. finite-geometry collusion
(DCC 2019; arXiv 1707.01551) · Camtepe–Yener PG-keying (ESORICS 2004) · Maekawa quorums (ACM TOCS 1985) ·
Naor–Wool; RP2 · Narwhal/Tusk (EuroSys 2022); Bullshark (CCS 2022); Mysticeti (NDSS 2025) · Turbine · Kadcast
(AFT 2019) · Dandelion++ (SIGMETRICS 2018) · Ethereum validator deanonymization (USENIX Sec 2025) · Whisk/SSLE
(EIP-7441) · LARMix/LAMP (NDSS 2024/25) · HORNET/TARANET (CCS'15/EuroS&P'18). Full per-claim URLs in the session
audit reports (2026-07-23).
