# The FANOS anonymity substrate — a derived-native design (NOSTOS · POROS · the two-lane substrate)

> This note replaces the earlier Tor/Sphinx *ports* (the single-relay reply block, the fixed-bridge bootstrap)
> with mechanisms **derived from FANOS's own structure** — the projective plane `PG(2,q)`, the below-threshold
> zero-knowledge line hop, the unbiasable DVRF beacon, and the VRF-rotated coordinates. It is grounded in a
> completed external audit of the 2004–2026 research frontier (arXiv / IACR / PoPETs / USENIX Sec / IEEE S&P /
> NDSS / SOSP-OSDI / EUROCRYPT-CRYPTO-ASIACRYPT-TCC), delivered as four adversarially-verified reports
> (2026-07-23): the anonymity-trilemma formal spine, threshold/MPC-onion prior-art, VRF-placement + rendezvous
> SOTA, and the censorship-bootstrap frontier. Every load-bearing claim is either a cited result or a stated
> **theorem to prove**. Where a mechanism is, to the surveyed frontier, a genuine gap, that is said plainly — and
> so is every precondition its security rests on, and every honest scope limit. The Tor vocabulary ("SURB",
> "bridge", "rendezvous") is retired for the pantheon.

## 0. The one theorem everything obeys — and why there must be two lanes

**The Anonymity Trilemma** (Das, Meiser, Mohammadi, Kate, *IEEE S&P 2018*, ePrint 2017/954; strengthened for
coordinated users in *Comprehensive Anonymity Trilemma*, PoPETs 2020(3)): against a global passive adversary, no
protocol achieves strong anonymity when `2ℓβ < 1 − ε`, where `ℓ` = latency overhead (rounds a message may be
delayed) and `β` = bandwidth overhead (per-user cover rate/round). The **low-latency ∧ low-overhead ∧
strong-anonymity** corner is *provably empty*; you escape only by paying `ℓ` (mixing delay) **or** `β` (cover).

The bound tightens by regime, and the exact forms are load-bearing for what follows (audit angle-1 report,
theorem numbers read from the primary PDFs):
- **Sender** anonymity fails at `2ℓβ < 1 − ε` (2018, Thm 2). The **receiver-anonymity** variant NOSTOS lives in
  fails at the *stricter* `4ℓβ < 1 − ε` (2018, §IX) — receivers are quantifiably harder to hide, which is
  *precisely why* NOSTOS is the delicate lane and gets the algebraic machinery.
- Passive compromise of `c` parties degrades the budget to `2(ℓ−c)β` (2018, Thm 5), and forces `ℓ ∉ O(1)` —
  **constant latency is fatal once the adversary holds a constant fraction of a short path.**
- **User coordination does not escape it.** Even DC-net-style secret sharing obeys the unified law
  `ℓ̂(p'+β) < 1 − ε` (PoPETs 2020, Thms 1–2). The Anytrust regime (all-but-`γ` compromised) additionally forces
  path length `ℓ ≳ √K`. The **one** unconditional escape is full-DC-net bandwidth `B ≥ N−1` — every user emits a
  share for every message — which a platform L1 cannot afford. So it is off the table, and the two-lane split is
  forced, not chosen.
- Every line of this theory — computational (`2βℓ`), coordinated (`ℓ̂(p'+β)`), Poisson-mix (Loopix `λ/μ ≥ 2`,
  ≥3 layers), information-theoretic (Venkitasubramaniam–Anantharam `λT`, ISIT 2008) — places the threshold on the
  same **(traffic-rate × delay-budget) product**. That invariant, not any single inequality, is the law the
  architecture obeys. No published work refutes it (2019–2026); the closest critique (Kuhn–Kitzing–Strufe, *SoK
  on Performance Bounds*, WPES 2020) only flags that the models' *assumptions* (synchrony, global adversary,
  always-online) limit real-world tightness — the impossibility itself stands.

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
   (Maekawa quorums, *ACM TOCS 1985*; Naor–Wool load-optimality `L(S) ≥ 1/√n`, *SIAM J. Comput. 1998*; the RP2
   datacenter topology) — textbook for *coordination*, never before fused with an anonymity fast path.
2. **DVRF beacon + VRF-rotated coordinates.** Unbiasable epoch randomness assigns each node's point via
   `coord = MapToPoint(VRF(sk, id ‖ epoch ‖ beacon))` (already built, [[coordinate-vrf-architecture]]). No fixed
   positions; the adversary cannot *choose* which line to pack, and membership rotates each epoch. Prior art
   places nodes by VRF+beacon per epoch (Nym `VRF(beacon,sk) mod L`; VeraSel, arXiv 2301.09207; Tor HSDir
   hash-ring rotation via the daily Shared-Random-Value) — but for *load-balancing / sybil-dilution /
   anti-trawling*, at *layer or directory* granularity. Using an unbiasable DVRF to rotate **every node's
   coordinate every epoch as an anti-intersection moving target** is, per the audit, **unmatched in the
   literature** (closest kin: Nym/VeraSel placement + Tor-HSDir beacon-rotated positions, differentiated on
   motive and granularity). Its safety is *not* free — see §3a (the rotation double-edge). Our beacon is a
   **pairing-free DVRF** (HydRand/SPURT/Scrape/PVSS family, *not* drand-style pairing BLS; anchor against SoK-DRB
   *IEEE S&P 2023*), unbiasable under its threshold and strictly stronger than Tor v3's commit-reveal SRV, whose
   last revealer can bias the beacon.
3. **The line as a `t`-of-`(q+1)` threshold committee**, below-threshold zero-knowledge (`t−1` shares reveal
   nothing — Shamir perfect secrecy). One structure, three uses: a **mixing/ZK hop** (MIX lane), a
   **BFT/erasure/broadcast committee** (FAST lane), and a **threshold-hosted ingress** (POROS).
4. **Algebraic recoverability (LRC).** In `PG(2,q)` each point lies on `q+1` lines and each line is a recovery
   set ⇒ **locality `r = q` with `q+1` disjoint recovery sets** — a locally-repairable code with `q+1` repair
   alternatives (this follows from the projective-plane **incidence axioms**, framed by Gopalan et al. *IEEE
   Trans. IT 58(11), 2012* and the multiple-disjoint-recovery-set notion of Pámies-Juárez–Hollmann–Oggier, *ISIT
   2013*; **do not** mis-cite it to the generalised-quadrangles result arXiv:1912.06372 — a projective plane is a
   generalised *triangle*, and that theorem does not specialise to it). This gives POROS availability under
   partial seizure for free.
5. **PQ identity + placement-priced admission** (the existing PoW-placement + reputation,
   [[self-organization-and-comparison]]), with the Sybil-anchoring caveat of §6.

## 2. The FAST lane — maximum throughput (and, correctly, no strong anonymity)

The trilemma says a low-latency low-overhead lane *cannot* be strongly anonymous; that is acceptable, because
this lane carries TAXIS/DROMOS and the app hierarchy, whose threat model is integrity/liveness, not
unobservability. It gets its throughput from the three moves every fast blockchain plane uses (Narwhal/Tusk
*EuroSys 2022*; Bullshark *CCS 2022*; Mysticeti *NDSS 2025*; Solana Turbine; Kadcast *AFT 2019*):
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
election *secret* (SSLE-grade — re-randomizable commitments per Whisk/EIP-7441, or a ring-VRF/Sassafras
continuation, ePrint 2023/002, or the PQ-SSLE of AFT 2023 to stay lattice-native) gives the fast lane the only
anonymity a fast lane can afford. **Theorem to state:** the beacon-VRF committee election is a single-secret-
leader election under the DVRF's unpredictability (empirical DoS/censorship rigor per arXiv 2509.24955).

## 3. NOSTOS (νόστος, "the homecoming") — receiver anonymity, derived not ported

**What it replaces.** Sphinx single-use reply blocks route the reply through *single relays* to a *coordinate a
delivery node learns*; Kuhn et al. (*IEEE S&P 2020*) proved reply-payload tampering on single-relay reply paths
can break whole-protocol anonymity, and the Sphinx reply format itself was only fully proven (under Gap-DH, with
a patch closing a sender-privacy attack) in *PoPETs 2024*. The sealed single-relay reply block built earlier is
exactly that fragile 2009-era construction. It is retired.

**The construction.** The reply comes home on the receiver's **own line** — one of the `q+1` lines through its
point — computed by cross-product from a shared secret + the beacon. The receiver is a *member* of that line,
hidden inside its **`q+1`-node anonymity set**. There is no "delivery node" and no coordinate to leak. Each
return hop **is a line**, threshold-peeled `t`-of-`(q+1)`; below `t`, a corrupt subset learns **nothing about
that layer's next hop**. The innermost is E2E-sealed (PQ AEAD), so the combiner delivers *ciphertext to the
line* — a **geometric dead-drop** — and only the receiver decrypts. Header/payload split (the responder inserts
only the payload), but over threshold lines, not single relays.

**Why threshold hops at all — the compulsion argument (Danezis–Clulow, *IH 2005*).** A single-relay reply layer
is peeled by one key; an adversary who can legally or physically *compel* one node at a time traces the entire
reply path with `ℓ` sequential subpoenas, each against one machine — and a seized Sphinx relay key retroactively
peels every recorded packet of its epoch. A threshold hop raises that to **`t` simultaneous compromises per hop**
(`t·ℓ` total), and below `t` the seized material is *by construction* statistically independent of the routing.
This is the compulsion-resistance guarantee the literature has wanted since 2005 and no onion format has
delivered.

**Why it is genuinely new (audit verdict, threshold-onion report).** After a systematic sweep of the provable-OR
line (Camenisch–Lysyanskaya *CRYPTO 2005* through Scherer et al. STIR *PoPETs 2024*), the MPC-mix line (MCMix,
AsynchroMix, Blinder, Clarion), the committee-hop line (Duo/Hydra Onions *CMS 2004*, Poly Onions *TCC 2022*,
Atom/Stadium/XRD/Trellis), and the threshold-decryption mixnets (Sako–Kilian, Abe, Wikström): *"no published
construction peels each onion layer by `t`-of-`n` threshold decryption such that a below-threshold subset of the
hop's members learns information-theoretically nothing about the routing."* NOSTOS occupies the **empty cell** in
`{per-hop committee} × {IT below threshold}`. The four nearest neighbours each miss it: Poly Onions gates only
the *backup* path (the primary candidate peels unilaterally) and is computational, for churn not privacy;
Duo/Hydra are `1`-of-`k` (the dual — *any* member peels); Atom/Trellis are anytrust groups (`≥1` honest,
computational, a fully-corrupt group learns its permutation); MPC-mixes are a genuine `t`-of-`n` committee but
**one** committee — no multi-hop path. The only prior IT-below-threshold *receiver-reply* guarantee anywhere is
Pynchon Gate's multi-server IT-PIR **retrieval** (*WPES 2005*) — a mailbox pickup, not an in-network path.
NOSTOS brings that guarantee to a routed path for the first time, and **removes the semi-trusted mailbox every
strong receiver system needs** (Pung/Talek/Express/Riposte/Spectrum all require a fixed host + anytrust).

**The honest scope — per-hop IT, composed with computational end-to-end.** The information-theoretic claim covers
exactly the **per-hop routing secret and peel state**: below `t` members of a line, the joint view is
statistically independent of that layer's next hop (Shamir-perfect). The onion *body* transiting between hops is
a ciphertext, so end-to-end unlinkability remains *computational* unless payloads are themselves IT-shared
(DC-net/MPC-mix style, which the trilemma prices at `B ≥ N−1`). The correct, defensible formal claim — the one
the theorems target — is therefore **"per-hop, below-threshold, information-theoretic secrecy of the layer,
composed with computational onion security across hops,"** stated in the Kuhn et al. privacy-notions hierarchy
(*PoPETs 2019*) within the Scherer et al. STIR variant framework (*PoPETs 2024*). Overclaiming "IT end-to-end"
would be false; this is the precise statement, and it is still a guarantee **no single-relay or anytrust system
offers**.

**Situated against the SOTA (vrf-rendezvous report).** For *discovery/handshake*, the strongest current systems
are Arke (unlinkable ID-NIKE over an untrusted store, consensus-free, Byzantine, *CCS 2024*) and Pudding
(username discovery on Loopix, `<1/3` malicious, *IEEE S&P 2024*); NOSTOS's rendezvous is **lookup-free** (an
`O(1)` cross-product, not a store/PIR query), a different and stronger anti-enumeration posture — and it kills
the DHT-lookup-leak class that broke NISAN/Torsk/Octopus/I2P-netDB. For the *reply-notification* sub-problem the
frontier is Oblivious Message Retrieval (PerfOMR, lattice/PQ, *USENIX Sec 2024*; Group-OMR; HomeRun *CCS 2024*),
Myco (2-server polylog, *IEEE S&P 2025*), and Private Signaling (*USENIX Sec 2022*) — all needing a semi-trusted
server pair or TEE; NOSTOS's geometric dead-drop provides the "recipient privately learns a slot is theirs"
property **in-network, with no mailbox host**. The reply *format* is positioned against Sphinx SURBs and the
asynchronous-onion theory (Bruisable Onions *TCC 2024*; Peony *ePrint 2025/1067*) that closes the sync-model gap.

**The precondition that makes it sound — not optional.** The *only* prior finite-geometry anonymity system
(UPIR over projective planes) was **broken by a single colluding user, precisely because any two users share
exactly one point** (Gnilke et al., *DCC 2019*). The unique-meet incidence that makes rendezvous `O(1)` is,
unguarded, a *deanonymization primitive*: anyone who knows or shares one input line computes the meet. NOSTOS
therefore rests on **at least one input coordinate being VRF-beacon-blinded and epoch-rotated** (the FANOS
coordinate-VRF — the geometric analog of Tor v3's blinded keys). The design **must characterize the anonymity
set explicitly** — which observers, which inputs secret — or it is rendezvous-efficiency, not anonymity.

**Theorems to prove — the formal targets, with exact games (formal-defs report).** The guarantee is proven in
the **AnoA** challenge game (Backes et al. *CSF 2013* — cleanest challenger; `(ε,δ)`-IND-CDP with `ε=0`, "strong"
iff `δ=negl`), with the achieved rung *named* in the Kuhn et al. notions (*PoPETs 2019*) to dodge the documented
**AnoA↔Kuhn naming trap** (AnoA's `α_SA ≡` Kuhn `SO̅` *unobservability*; Loopix-style "receiver unobservability"
`≡` the strictly-weaker `RO̅`).

- **T1 — composite receiver anonymity, three strata.**
  - *(i) Hop stratum (information-theoretic).* **Below-threshold simulatability `Sim_t`:** for every committee
    hop `C_i` (`q+1` members, threshold `t`) and every coalition `S ⊂ C_i` with `|S| < t`, a simulator produces
    `S`'s joint view (keys, KEM-sealed shares, routed fragments, per-member timing) from public parameters alone,
    statistical distance `≤ 2^{-s}` (`0` for perfect Shamir sharing). This is **not** a new rung of the Kuhn
    hierarchy — that grades *what* is hidden; `Sim_t` widens the *adversary class* the guarantee holds against.
    The KEM-sealed-share object in `threshold.rs` is exactly what `Sim_t` is proven over.
  - *(ii) Packet stratum (computational).* Forward **and backward** Layer-Unlinkability + Tail-Indistinguishability
    (Kuhn–Hofheinz–Rupp–Strufe, *ASIACRYPT 2021*) for the committee-generalized packet: in each LU/TI hybrid,
    substitute *"committee with `< t` corrupted members"* for *"honest relay"*; `Sim_t` makes that hybrid step
    **statistical**, and the KHRS UC theorem (games ⇒ ideal functionality) carries over untouched. **Reply
    integrity lives *inside* this proof** as implicit payload authentication (an anonymous receiver cannot MAC an
    unknown reply, and MAC-style explicit auth is provably insufficient — KHRS) — the NOSTOS end-to-end AEAD is
    that ingredient, not a separate lemma. **Assumption hygiene:** Scherer–Weis–Strufe (*PoPETs 2024*) proved DDH
    is *insufficient* for Sphinx (Gap-DH + a format fix required, else a concrete sender-privacy attack), so
    NOSTOS's PQ KEM must supply **IND-CCA + KEM anonymity/robustness** (the property doing GDH's job), cited
    explicitly — never an inherited DDH-era statement.
  - *(iii) End-to-end stratum.* `(0,δ)`-`α_RA` **and** `(0,δ)`-`α_Rel` IND-ANO. `α_RA` challenges two
    adversary-chosen reply-receivers `R_0,R_1` with identical sender (*possibly corrupt* — that is the point),
    payload, length, and timing template; `α_Rel` challenges **matched-vs-crossed** sender–receiver pairs (the
    `M_SR` game — identifying *one* endpoint does not win, unlike the weaker `R_SR`). `δ ≤ δ_stat(hops) +
    δ_comp(η) + δ_traffic`; achieved rung, named in Kuhn terms: receiver-side `RO̅` (or a stated leak-variant),
    relationship-side `(SR)L̅`.
  - **The trilemma budget lives inside T1** so stratum (i) is never misread as beating it: `δ_traffic` obeys Das
    et al. *S&P 2018* regardless of the IT hop stratum, and the **receiver leg's constant is 4** (`4ℓβ < 1−ε`,
    the candidate window spanning `ℓ−1` rounds *both* sides of the challenge send) — budget `4ℓβ`, though
    Kuhn–Kitzing–Strufe *WPES 2020* conjecture it tightens to the sender's `2ℓβ`; **do not architecturally depend
    on the gap.** With committee hops the compromise count `c` is **broken committees** (`≥ t` corrupted, prob.
    `P_break`, §4-T4), *not* corrupted relays — the honest-majority-per-hop analogue of the honest-relay term.
- **T2 (blinded-rendezvous anonymity).** With one rendezvous input VRF-beacon-blinded, the meet is unpredictable
  and unlinkable to any bounded observer outside the receiver's line; the anonymity set is exactly `points_on(L)`
  (the `q+1` members), proven non-linkable across epochs. (`c` = broken committees, as in T1.)
- **T3 (intersection resistance from rotation).** Prove per-epoch coordinate rotation *lowers* the long-term
  `α_RA`-advantage — the non-trivial direction — because the threshold hop's `P_break` (T4) attenuates each
  rotation's predecessor gain below the intersection-attack's sampling gain (§3a). The receiver-side
  statistical-disclosure threat, stated in the `α_RA` game across epochs.
- **Cost honesty.** Ando–Lysyanskaya–Upfal (*ITC 2021*): anonymity against an active adversary needs a
  *superlogarithmic* onion count per participant; NOSTOS's cover/route budget is reported against that floor.

## 3a. The rotation double-edge — and why the threshold hop is what makes moving-target safe

Per-epoch coordinate rotation is presented across the moving-target literature as unambiguously good; the audit
(vrf-rendezvous report) flags that it is **not**, and the design must *earn* it. Two results:
- **The predecessor / guard-rotation tradeoff** (Elahi et al., "Changing of the Guards", *WPES 2012*; Tor
  Vanguards / Prop-292). A node that re-randomizes its relations every epoch presents a *persistent* adversary a
  fresh draw each epoch to land adjacent to the target; over many epochs the probability the adversary has *ever*
  been your neighbour rises. Naive rotation can therefore **increase** long-run compromise — the opposite of the
  intent.
- **High-volume-flow fragility** (*When Mixnets Fail*, *NDSS 2025*). With 5–10% corrupt mixnodes, high-volume
  flows are deanonymized regardless of mixing — and a **receiver's reply stream is high-volume**, precisely
  NOSTOS's traffic.

**Why FANOS is on the right side of the tradeoff — the derivation.** The predecessor attack's per-epoch gain is
the probability a fresh adversarial draw both lands on the flow's hop *and* compromises it. On a single-relay
moving target that gain is the corruption fraction `f`. On a **threshold line** the fresh draw compromises the
hop only if it pushes that line to `≥ t` corrupt members — probability
`P_break = Pr[Binomial(q+1,f) ≥ t] ≤ exp(−(q+1)·D(τ‖f))` (T4), *exponentially smaller than `f`* for any
`f < τ = t/(q+1)`. The threshold hop therefore **attenuates each rotation's predecessor gain by an exponential
factor**, while rotation's benefit against the statistical-disclosure/intersection attack (raising the samples an
adversary must collect before the receiver's line is pinned) is undiminished. The design point: **rotation is
safe precisely because the hop is a threshold committee, not a single relay** — the two mechanisms are
co-designed, and **T3 is the theorem that the net is positive** (rotation benefit > exponentially-attenuated
predecessor cost). If the inequality is ever tight, the tuning knob is a **bounded membership-churn** cadence
(rotate the coordinate, keep line membership churn-limited within a community, à la Poly Onions' churn bound).
This is also why the FAST lane, needing no unobservability, may rotate freely, while the MIX/NOSTOS lane's
rotation is threshold-gated.

## 3b. The service is a receiver too — production hidden-service hosting via symmetric NOSTOS

NOSTOS (§3) hides the *client* that dials a service. The mirror problem — hosting a service so clients reach it
**without the network ever learning the service's coordinate** — is not a second mechanism: it is NOSTOS applied
to the *other* endpoint. The client already rides a forward onion to the service's **meeting line**
`L_rdv = MapToLine(H(svc_pub ‖ epoch ‖ beacon))` and names its own dead-drop line as the reply circuit (§3). The
gap this closes is that a meeting line's *combiner* `m = combiner_for(L_rdv)` is a function of the **service key**,
not of any node's coordinate — and a node's coordinate is VRF-beacon-blinded and epoch-rotated (§3, the T2
precondition). So the operator hosting `svc_pub` is, save by luck, **not** the node at `m`, and `m` rotates every
epoch with the beacon. A production host therefore cannot "listen at its meeting combiner"; something at `m` must
relay to it, and that relay must not learn where "it" is.

**The construction — both endpoints are dead-drop receivers; the combiner is a pure rendezvous.** The service
operator `O` is treated exactly as a NOSTOS receiver:

1. **Anonymous host-registration** (`O → m`, the `RdvHostRegister` frame, wire `0x5B`). Each epoch, `O` computes
   `m = combiner_for(L_rdv(svc_pub, epoch, beacon))`, draws a fresh dead-drop line `L_O = select_drop_line(c_O, …)`
   through its own point, and rides a **forward onion to `m`** carrying `{ service_tag, reply_pub_O, forward_route_O }`
   — where `service_tag = H("FANOS-v1/rdv-host" ‖ svc_pub ‖ epoch)` disambiguates services co-located at one
   combiner (Fano has only 4), `reply_pub_O` is a fresh NOSTOS reply key, and `forward_route_O` is a threshold
   circuit ending at `L_O`. The registration is itself an onion, so `m` learns only `O`'s **line** `L_O` (`O` hidden
   `1`-of-`(q+1)`), never `c_O`. `O` **re-registers each epoch**, because `m` and `L_O` both rotate with the beacon.
2. **Combiner-side forwarding** (`m → O`). When a client request peels out at `m` as an anonymous delivery, `m`
   looks up the request's `service_tag`; if a host is registered, it **re-seals the entire client `Request` as a
   NOSTOS onion to `forward_route_O`** (`seal_nostos_reply` — the same primitive that seals a client reply, §3) and
   emits it. `O`, a member of `L_O`, receives the dead-drop, opens it with `reply_pub_O`'s secret, and now holds the
   client's `Request` verbatim: cookie, the client's own reply circuit, and the DIAULOS `ClientHello` sealed to
   `svc_pub`. A request whose tag matches no registered host falls through to a **local** delivery (unchanged), so a
   node that genuinely *is* its own combiner still serves directly — the rule is additive.
3. **Reply** (`O → client`). `O` ingests the request into a `RendezvousService`, drives the DIAULOS `ServerSession`
   (only `O` holds the service secret, so only `O` completes the handshake — `m` cannot), and seals each response
   back through the **client's** dead-drop line via ordinary NOSTOS (`RendezvousService::seal_reply`). The reply
   goes `O → client` directly; `m` is **out of the reply path entirely**.

**What each party learns — the anonymity claim.** The meeting combiner `m` sees a public `service_tag` (already
implied by `L_rdv`, itself `H(svc_pub‖…)`), the client's dead-drop **line**, the service's dead-drop **line**, and
ciphertext bodies — **neither endpoint's coordinate**. The forward and return legs are each threshold onions, so
below `t` members of any hop learn information-theoretically nothing (`Sim_t`, §3-T1). The service is hidden
`1`-of-`(q+1)` on `L_O`; the client `1`-of-`(q+1)` on its own line; the two are **symmetric**, and the relationship
`α_Rel` (§3-T1(iii)) is protected because `m` never holds a (client-coord, service-coord) pair — it holds a
(client-line, service-line) pair, each a `q+1` set, refreshed every epoch. This is the strict generalization of §3's
T2 to *both* endpoints, and it is **strictly stronger than Tor's rendezvous model**, where the rendezvous point
learns the service's introduction circuit and the intro point is chosen by (hence linkable to) the service; here the
combiner is a beacon-derived coordinate no party selects, and the service is a blinded line member.

**The bare-host fallback (stated for honesty, as with the client's bare-proxy §3-relay).** An operator that cannot
be a line member — a pure-overlay egress with no router — may instead register its **coordinate** (an
`RdvHostRegister` naming `c_O` with an empty `forward_route`), and `m` forwards the request by a direct `Send`. This
leaks `c_O` to the one node `m` (exactly Tor's posture, no worse), and is the residual path for a host that cannot
peel a dead-drop; the **primary** path is the coordinate-hiding onion registration above. The two are the same frame
with/without a `forward_route`, mirroring the client's NOSTOS-vs-relay split precisely.

**Why re-seal at the combiner rather than anchor the service at `m`.** Anchoring (dealing `svc`'s secret to the
`q+1` members of `L_rdv` so a threshold *jointly* serves) is a genuinely different primitive — threshold-custodied
hosting (CALYPSO/`ThresholdService`), reshared to the rotating line by POROS (§6) — and it is correct for a service
that is *meant* to be threshold-operated (a naming oracle). It is **wrong** for a private single-operator service or
a **clearnet exit**: you cannot Shamir-deal clearnet egress or a private key you are unwilling to expose to a
threshold of rotating strangers. Symmetric-NOSTOS hosting keeps the secret with the operator and hides the operator;
threshold-anchoring shares the secret and needs no operator. FANOS offers both; this section is the former, and it
is what makes the exit and the generic `.fanos` service reachable.

**Cost.** Three threshold-onion legs (client→meeting, meeting→service dead-drop, service→client dead-drop) instead of
NOSTOS's two — the price of hiding the *second* endpoint. It obeys the same trilemma budget (§0): a hidden service is
receiver-anonymous traffic and pays the receiver leg's constant on each blinded endpoint.

## 4. The MIX lane — ultimate anonymity, and the Anytrust-escape it buys

A hop **is a line**, threshold-encrypted `t`-of-`(q+1)`, below-threshold ZK; Sphinx-uniform packets; Loopix
Poisson per-hop delay (`λ/μ ≥ 2`, ≥3 layers — the literature's endorsed sweet spot) + loop cover to pay the
mandatory `βℓ = Ω(1)`; VRF-random independent per-packet routes. Optional **latency-aware routing bias**
(LARMix/LAMP, *NDSS 2024/25*: 7–8× lower latency for 1–2 bits of entropy) over the algebraic routing gives a
*graduated* anonymity dial within the lane.

**The provable efficiency win (theorem to prove — T4).** The trilemma's cost is driven by `c` (compromised
parties); its Anytrust regime forces latency `~√K`. A FANOS hop is broken only if `≥ t` of its `q+1` members are
corrupt. Under corruption fraction `f`, threshold ratio `τ = t/(q+1)`:

> `P_break = Pr[Binomial(q+1, f) ≥ t] ≤ exp(−(q+1)·D(τ‖f))` — **exponentially small in `q` for any `f < τ`**.

So `c_eff ≈ ℓ·P_break ≈ 0` w.h.p.; the degraded bound `2(ℓ−c)β` **collapses to the honest-network bound**
`2ℓβ ≥ 1−ε` even under Byzantine *node* corruption up to `τ`; FANOS **never enters the Anytrust regime**, never
pays the `√K` latency. The DVRF beacon + VRF-rotated coordinates make this hold against *adaptive* corruption
(the adversary cannot pre-select and pack a target line). **Honest bound:** this does *not* repeal the
trilemma — the MIX lane still spends real `βℓ`. It converts a *node-level* corruption budget into an
exponentially-safer *line-level threshold* budget, letting the anonymity lane run at the **non-compromised
frontier** (minimum latency the pure `βℓ` bound allows) instead of the inflated Anytrust penalty. This is a
Chernoff design derivation, not yet a published theorem; T4 is to formalize it.

## 5. The per-flow mode bit — fingerprint-safe by construction

Tor *refuses* a path-length knob because a per-user anonymity setting (path length, delay profile) becomes a
fingerprint. FANOS answers architecturally: **uniform packet format across both lanes** (Sphinx-shaped cells
whether MIX or FAST), the mode carried where it does not leak, and both lanes riding the *same* `PG(2,q)`
substrate — so lane membership is not an observable per-user identifier. The MIX-lane delay profile is drawn from
the shared Poisson parameters, not per-application (Nym's own admitted app-distinguishability caveat).

## 6. POROS (πόρος, "the way through") — censorship-resistant ingress

**Framing (POROS bootstrap report).** Every circumvention system splits into *establishment* (proxy distribution
+ rendezvous) and *conversation* (the data channel), with different limits per phase (Khattak et al., *SoK:
Making Sense of Censorship Resistance*, PoPETs 2016). Achievability is **not cryptographic but economic**: real
censors act only when collateral/economic damage is low (Tschantz et al., *SoK: Grounding Censorship
Circumvention in Empiricism*, IEEE S&P 2016). POROS is therefore designed to *shift the censor's cost*, and its
residual is stated as an economic inequality, not hidden behind a cryptographic gloss.

**What no protocol escapes — the four-layer residual:**
- **Algorithmic (distribution).** To keep proxies alive against `t` known insiders while serving `n` users,
  `t·(1+⌈log(n/t)⌉)` proxies suffice with a matching lower bound (Mahdian, *FUN 2010*): the **insider count `t`,
  not the user count `n`, is the linear cost driver.** Distribution can be decentralized only to the Byzantine
  `⌊m/3⌋` (Zamani–Saia–Crandall, *TorBricks*, SSS 2017).
- **Statistical (endpoint).** *No single endpoint or protocol is unblockable* — probe-resistant proxies are
  identified by their *reaction* to probes (Frolov et al., *NDSS 2020*); active probing is the GFW's dominant
  enumeration primitive (Ensafi et al., *IMC 2015*; *IMC 2020*).
- **Economic (the equilibrium).** Unblockability is a *rate*. Define the **burn rate `β = λ_disc/λ_intro`**
  (censor discovery ÷ defender introduction); for `β > 1`, time-average availability `A ≤ 1/β < 1` regardless of
  rotation speed or endpoint count (Maiti, *Block-A-Mole*, arXiv 2606.08886, Thm 2 — *preprint, full-text
  verified*). Agility cannot win once the censor out-discovers you on the scarce rendezvous resource.
- **Irreducible.** Every deployed system roots first contact in an out-of-band / trust-on-first-use channel it
  *assumes* reachable (SoK-Spectre, *PoPETs 2025 Issue 2*, arXiv 2401.15828). This is the mathematical
  restatement of "you must seed one unblockable channel."

**The POROS construction — one derivation from the substrate.** Set the ingress as
`ingress = f( unbiasable-DVRF-beacon , community-secret , VRF-identity-binding )`, where each input supplies
exactly one property (the same three-input blinding NOSTOS's §3 precondition demands — the mechanisms converge):
the **beacon** → per-epoch unpredictable rotation (caps any enumeration to one epoch and *raises `λ_intro`*, so
`β < 1` is cheap to sustain); the **community-secret** → enumeration-resistance (a censor with only the *public*
beacon + a target identity still cannot compute the meet); the **VRF identity-binding** → Sybil/seed-extraction
resistance (a captured client leaks nothing usable against others — unlike a DGA seed, which is extractable). The
entry for an epoch is a beacon-derived **line**, `t`-of-`(q+1)` **threshold-hosted** (reuse the CALYPSO
ThresholdService, [[threshold-calypso-hosting]] — seize `< t` ⇒ learn nothing, per CALYPSO *VLDB 2021*), and
**LRC-recoverable from any of the `q+1` lines** (§1.4). This composite — DVRF beacon + identity-bound VRF
coordinates + `t`-of-`(q+1)` threshold hosting + projective-LRC recoverability — is, per the audit, **absent from
the 2015–2026 literature**; the nearest neighbours each miss ≥2 of the properties (Tor v3 SRV→HSDir: biasable
beacon, unauthenticated derivation, descriptor replicated-not-shared, no LRC; G-Lox: directory-mediated not
beacon-global, 2 servers not `t`-of-`(q+1)`; CALYPSO: ledger secret, no VRF coordinates, no rotation, no LRC;
Snowflake: central broker, no threshold). It is **provably better than fixed-bridge distribution on four
measurable axes**: (i) seizure (`< t` reveals nothing vs one bridge = total compromise); (ii) per-epoch
enumeration (rotation caps a single enumeration's value to one epoch); (iii) availability under partial blocking
(LRC recovery from any of `q+1` lines); (iv) unbiasable rotation (DVRF strictly dominates commit-reveal SRV).

**The Sybil gate is load-bearing, and must be anchored correctly.** Mahdian's `Ω(t)` floor binds POROS too:
anyone admitted who can *compute* coordinates can block them at the same `t·log` rate — so **keeping `t` small is
the whole game**, which makes the admission gate not optional. But the FANOS holonic *coherence* signal has the
**same guarantee shape as a VDF** (Boneh et al., *CRYPTO 2018*): it raises per-identity-per-epoch cost yet does
**not cap total identities** unless *anchored* to a scarce resource. The strongest non-PoW bounds are
proof-of-personhood (1 identity/human, *IEEE S&B 2017*) and fast-mixing trust graphs (SybilLimit `O(log n)`
Sybils/attack-edge, within a `log n` factor of the `Ω(1)` lower bound, *IEEE S&P 2008*; routing-integrated via
Whānau *NSDI 2010* / X-Vine *NDSS 2012*). **Design decision:** use coherence as the *rate-limiting / expulsion*
layer — its natural strength, converting Mahdian's `t` into a smaller *effective* insider budget exactly as
Salmon's trust-tiering (*PoPETs 2016*) does — and compose it with a graph- or credential-based *admission* anchor
(the Lox unlinkable-credential tree, *PoPETs 2023*, is the deployed privacy-preserving instance) for the actual
Sybil cap. Coherence anchored to nothing is a rate limiter only; a patient adversary accrues coherence on many
identities.

**Theorem to prove — T5 (sustainable-frontier ingress).** Prove the beacon-blinded threshold-rotating ingress
keeps the burn rate `β < 1` for a *modeled* censor (unpredictable rotation boosts `λ_intro`; seizure needs `≥ t`;
enumeration is capped to one epoch), **subject to** the Mahdian `Ω(t)` floor and the Block-A-Mole `A ≤ 1/β`
ceiling — i.e. that POROS sits on the sustainable side of the frontier — and formally **localize the residual to
a single out-of-band seed** (DVRF params + `PG(2,q)` params + ≥1 reachable transport, TOFU once). Two **open
field gaps** POROS is positioned to close, flagged by the audit as genuinely unclaimed: (a) a **differential-
privacy formulation** of bridge distribution (the guarantee of record is *unlinkable credentials*, not
calibrated noise); (b) a **standalone information-theoretic "unblockable-channel-required" impossibility** (the
residual is currently argued *economically*, via collateral damage, not information-theoretically).

**The irreducible residual, stated honestly.** POROS does not escape the seed: a brand-new node with no beacon
and no peer needs **one** out-of-band unblockable carrier to receive the first beacon/community-secret —
minimized, not eliminated, by PROTEUS obfuscation ([[proteus-morph-transforms]]) and diverse high-collateral
carriers (domain fronting / refraction / a high-value CDN — "collateral freedom", *PoPETs 2015*).

## 7. Novelty, stated for the record

To the 2004–2026 frontier surveyed: (i) the **threshold-line below-ZK reply hop** occupies the empty cell in
`{per-hop committee} × {IT below threshold}` — a literature gap (threshold-onion report); (ii) the **geometric
line-dead-drop with no fixed host** removes the semi-trusted mailbox every strong receiver system needs, and
brings Pynchon-Gate-class IT-below-threshold receiver privacy to an in-network *path* for the first time; (iii)
**rendezvous as an element of the routing geometry** (`O(1)` cross-product of identity-bound, beacon-blinded
coordinates) is unmatched — and *lookup-free*, killing the DHT-lookup-leak class that broke NISAN/Torsk/Octopus;
(iv) a **single algebraic substrate whose lines serve as threshold-mix/ZK hops, BFT/erasure committees, and
threshold-hosted ingress, toggled per-flow**, has no prior art; (v) the **POROS composite** (DVRF beacon +
identity-bound VRF coordinates + `t`-of-`(q+1)` threshold hosting + projective-LRC) is a novel composition absent
from the censorship-resistance literature. The components each have precedent; the *synthesis* is ours. None of
this repeals the trilemma or the censorship residual — it moves FANOS to the best point each theory allows, with
an information-theoretic per-hop guarantee no single-relay or anytrust system provides.

**One open novelty check (stated honestly).** A low-tier 2024 paper (Jambha et al., Amrita, *"Securing Layers:
The Synergy of Mix Networks and Shamir's Secret Sharing in Onion Routing"*) is title-adjacent to NOSTOS; its full
text was not retrievable in the audit sweep, and nothing in its visible metadata suggests a below-threshold IT
theorem — but it **must be read and distinguished before any novelty claim is made in print.** Novelty here is a
literature-gap *finding*, reported as such, not a proof of absence.

## 8. Sources

*Full per-claim URLs are in the four session audit reports (2026-07-23): trilemma spine, threshold/MPC-onion
prior-art, VRF-placement + rendezvous SOTA, censorship-bootstrap frontier.*

**Trilemma & bounds.** Das et al. Anonymity Trilemma (IEEE S&P 2018, ePrint 2017/954); Comprehensive Anonymity
Trilemma (PoPETs 2020); Beyond Mix-Nets (Purdue TR); Ando–Lysyanskaya–Upfal onion-complexity (ITC 2021, ICALP
2018); Venkitasubramaniam–Anantharam (ISIT 2008); Kuhn–Kitzing–Strufe SoK performance bounds (WPES 2020);
Divide-and-Funnel (CSF 2024).
**Onion theory & replies.** Camenisch–Lysyanskaya (CRYPTO 2005); Backes et al. UC-OR (CSF 2012); AnoA (CSF 2013);
Kuhn et al. privacy notions (PoPETs 2019); Kuhn–Beck–Strufe breaking provable OR (IEEE S&P 2020); Scherer–Weis–
Strufe STIR + Sphinx proof (PoPETs 2024); Sphinx (IEEE S&P 2009); Kuhn–Hofheinz–Rupp–Strufe Onion Routing with
Replies (ASIACRYPT 2021); Ando–Lysyanskaya Cryptographic Shallots (TCC 2021); EROR (ePrint 2024/020); Bruisable
Onions (TCC 2024); Peony (ePrint 2025/1067); KEM-Sphinx (ePrint 2023/1960); Outfox (WPES 2025); Danezis–Clulow
compulsion resistance (IH 2005); Mixminion (IEEE S&P 2003); HORNET/TARANET (CCS'15/EuroS&P'18).
**Threshold / committee / MPC hops.** Duo/Hydra Onions (CMS 2004); Poly Onions (TCC 2022); Atom (SOSP 2017);
Stadium (SOSP 2017); XRD (NSDI 2020); Trellis (NDSS 2023); MCMix (USENIX Sec 2017); AsynchroMix/HoneyBadgerMPC
(CCS 2019); Blinder (CCS 2020); Clarion (NDSS 2022); Riffle (PoPETs 2016); cMix (ACNS 2017); Sako–Kilian
(EUROCRYPT 1995); Abe (EUROCRYPT 1998); Wikström UC mixnet (TCC 2004); Pynchon Gate (WPES 2005).
**Receiver / metadata-private SOTA.** SoK Metadata-Protecting (Sasy–Goldberg, PoPETs 2024); Arke (CCS 2024);
Pudding (IEEE S&P 2024); OMR/PerfOMR (CRYPTO 2022 / USENIX Sec 2024); Group-OMR; HomeRun (CCS 2024); Myco (IEEE
S&P 2025); Private Signaling (USENIX Sec 2022); FMD + critique (CCS 2021 / FC 2022); DP5 (PoPETs 2015); Loopix
(USENIX Sec 2017); Echomix/Katzenpost (arXiv 2501.02933); Pung/Talek/Express/Riposte/Spectrum/Sabre/Pepper;
Vuvuzela/Karaoke (SOSP'15/OSDI'18); LARMix/LAMP + When Mixnets Fail (NDSS 2024/25).
**Beacons, VRF placement, SSLE.** SoK Distributed Randomness Beacons (IEEE S&P 2023); RandHound/RandHerd (IEEE
S&P 2017); SPURT (IEEE S&P 2022); HydRand (IEEE S&P 2020); GRandLine (CCS 2024); drand; Galindo et al. DVRF
(EuroS&P 2021); Giunta–Stewart unbiasable VRFs (EUROCRYPT 2024); Algorand sortition (SOSP 2017); VeraSel (arXiv
2301.09207); Nym whitepaper + NymVPN Fast/Anonymous; Katzenpost/Echomix PKI; Whisk/SSLE (EIP-7441); ring-VRF /
Sassafras (ePrint 2023/002); PQ-SSLE (AFT 2023); Ethereum validator deanonymization (USENIX Sec 2025, arXiv
2509.24955); guard rotation "Changing of the Guards" (WPES 2012) + Vanguards; Trawling for Tor HS (IEEE S&P
2013).
**Geometry & codes.** UPIR + Gnilke et al. finite-geometry collusion (DCC 2019, arXiv 1707.01551); Camtepe–Yener
PG-keying (ESORICS 2004); Maekawa quorums (ACM TOCS 1985); Naor–Wool (SIAM J. Comput. 1998); RP2; Gopalan et al.
locality of codeword symbols (IEEE Trans. IT 2012); Pámies-Juárez–Hollmann–Oggier multiple recovery sets (ISIT
2013).
**Censorship bootstrap & Sybil.** Khattak SoK censorship (PoPETs 2016); Tschantz SoK empiricism (IEEE S&P 2016);
Mahdian (FUN 2010); TorBricks (SSS 2017); Frolov et al. probe-resistant proxies (NDSS 2020); Ensafi et al. (IMC
2015 / IMC 2020); Elahi game-theoretic framework + Nasr Enemy at the Gateways (PoPETs 2016 / NDSS 2019); Maiti
Block-A-Mole (arXiv 2606.08886, *preprint*); G-Lox (arXiv 2606.19620, *preprint*); SoK-Spectre (PoPETs 2025 Iss.
2, arXiv 2401.15828); collateral freedom / domain fronting (PoPETs 2015); Salmon (PoPETs 2016); Lox (PoPETs
2023); Snowflake (USENIX Sec 2024); Conjure (CCS 2019); ECH (draft-ietf-tls-esni); S/Kademlia (ICPADS 2007);
CALYPSO (VLDB 2021); Briar BRP; SybilGuard (SIGCOMM 2006) / SybilLimit (IEEE S&P 2008) / Alvisi SoK (IEEE S&P
2013) / Whānau (NSDI 2010) / X-Vine (NDSS 2012); proof-of-personhood (IEEE S&B 2017; arXiv 2408.07892); VDFs
(CRYPTO 2018 / EUROCRYPT 2018).
**Substrate.** Narwhal/Tusk (EuroSys 2022); Bullshark (CCS 2022); Mysticeti (NDSS 2025); Turbine; Kadcast (AFT
2019); Dandelion++ (SIGMETRICS 2018).

**One honest-caveat check outstanding:** Jambha et al. (Amrita 2024) — title-adjacent, full text unretrieved,
must be read before printing a NOSTOS novelty claim (§7).
