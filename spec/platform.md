---
sidebar_position: 1
title: "FANOS Platform — the holonic synthesis (E∧L meta-holon)"
description: "The transformation of FANOS from an anonymity overlay into a full holonic platform: natively both a maximal-anonymity mixnet (E-machine) and a high-speed private post-quantum L1 blockchain (L-machine), with an untraceable currency (OBOLOS), a swift parallel execution fabric (DROMOS), currency-bought private naming (ONOMA), an anonymous PQ messenger (ANGELOS), a monetized content-storage platform (THESAUROS), and a threshold cross-chain (HERMES) — grounded in the HOLARCH meta-specification and validated against its four viability invariants."
---

# FANOS Platform — the holonic synthesis

> *"A mixnet hides who; a blockchain agrees what. Compose the two above the integration threshold and a third thing is born that neither is: a platform where value moves with the untraceability of light through night and the finality of law."*

:::info Document status
**Version 0.1** (platform reference architecture — the revision of [`protocol.md`](./protocol.md) for the blockchain-platform era). This document is the **design authority** for the transformation; it is grounded in the corpus **HOLARCH** meta-specification (`applied/research/holarch.md`) and inherits its status discipline — every nontrivial claim carries **[T]** theorem / **[C]** construction (self-consistent by design) / **[H]** hypothesis (needs proof or audit) / **[P]** program (a direction of work) / **[И]** interpretation (a structured, arguable dictionary reading, never a fact). Cryptographic honesty is unchanged from `protocol.md`: **the novelty is architectural composition of vetted primitives, not new hardness assumptions.** Where a subsystem genuinely needs frontier cryptography (the post-quantum shielded pool, §4), the frontier component is isolated behind a typed interface and tagged **[P]**; the surrounding accounting is fully implementable and verified.
:::

---

## §0. The thesis, in one paragraph {#thesis}

`protocol.md` specifies FANOS as an **E-machine**: an anonymity overlay whose product is its unobservable interior (the hidden pool, the ratchet keys, the cover traffic) — the HOLARCH mixnet worked example W1 (`holarch.md` §15), re-derived on `PG(2,q)`. This document composes that E-machine with an **L-machine** — a Byzantine-agreement blockchain whose product is forced consistency between strangers (the HOLARCH blockchain worked example W2, §16) — already present in seed form as `fanos-taxis`. By the HOLARCH cooperation theorem (T-77, §9), composing two holons whose cross-block coherence exceeds the integration threshold **founds a new meta-holon** — a platform that is neither parent alone. The FANOS Platform is that meta-holon: **the first system that is simultaneously anonymity-native (strong E) and consensus-native (strong L)**, and therefore the natural home for a currency that is at once *untraceable* (an E property — value hidden in interiority) and *sound* (an L property — no double-spend, enforced by agreement). Monero and Zcash are L-machines with a bolted-on shielded pool; Nym is an E-machine with no L1. FANOS is the composition done at the root.

---

## §1. HOLARCH grounding: the platform as a validated meta-holon {#holarch}

### 1.1 The seven aspects, at platform scale {#aspects}

HOLARCH fixes the alphabet of concerns at **seven** (A/S/D/L/E/O/U) by the uniqueness theorem T-224 [T] — the same Fano-plane rigidity that FANOS already builds its *network* on, now read one level up as the platform's own budget vector. The platform's aspect profile (its Γ-diagonal — the [И] reading of `holarch.md` §4):

| Aspect | Platform reading — what lives here |
|---|---|
| **A** Articulation | transaction/message ingestion: the mempool intake, wire parsing, the SOCKS/API surface, the messenger's inbound |
| **S** Structure | the ledger schema, note/UTXO commitments, address & name formats, the wire registry, epoch topology descriptors |
| **D** Dynamics | execution: the DROMOS parallel VM, transfer application, packet forwarding, message delivery — *what moves* |
| **L** Logic | **consensus law (TAXIS), the cryptographic laws — routing, shielding, nullifiers, range proofs, cross-chain attestation** — what must cohere without contradiction (the blockchain's dominant axis) |
| **E** Interiority | **anonymity and untraceability: the mixnet hidden pool, the OBOLOS shielded notes, viewing keys, the messenger's sealed state** — what is visible only from inside (the mixnet's *and* the private currency's dominant axis) |
| **O** Foundation | transport (QUIC), the L4 erasure store, **stake**, data availability, the cover-traffic budget, energy |
| **U** Unity | identity and orchestration: the canonical head (fork-choice), the epoch beacon, the directory, ONOMA naming — what makes the parts one platform |

The load-bearing observation: **the mixnet dominant aspect (E) and the blockchain dominant aspect (L) are different axes.** A pure blockchain (W2) has thin E (`D_diff` barely reaches 2 — `holarch.md` §16: "transparent-by-design systems structurally live with thin interiority"); a pure mixnet (W1) has thin L. Their composition is not a compromise between two thin profiles — it is a holon **thick on both E and L at once**, which no mainstream system in either lineage achieves. This is the platform's породная сигнатура (species signature), and §1.3 shows it lands inside the viability window precisely *because* the two axes reinforce rather than compete.

### 1.2 The cross-block: where the integration lives {#crossblock}

By T-77 (`holarch.md` §9), the integration gain of a composition is `2‖γ_cross‖²_F` — it lives **entirely in the contract between the sub-holons**, never inside either. The FANOS meta-holon's cross-block (the coherence channels binding the E-machine to the L-machine) is not thin, and that is the whole point:

- **E→L (the mempool is a mixnet):** OBOLOS/TAXIS transactions propagate through the APHANTOS mixnet and enter the anti-MEV *encrypted* mempool. Sender-unlinkability (E) is delivered to the ledger's intake (A) as a first-class property, not a gateway afterthought. Channel: **AE** (Apperception) + **DE** (Affection) — the network's interiority writes the ledger's intake.
- **L→O (consensus secures the substrate):** TAXIS finality + stake (proof-of-stake is the HOLARCH **LO — Foundation** channel read literally, §5) provide the Sybil-resistant node registry, the naming ownership, and the beacon the *mixnet* needs for its epoch topology and Sybil admission. The blockchain pays the mixnet's foundation. Channel: **LO** + **OU** (Wholeness — the DA layer feeds the whole).
- **L↔E (agreement over hidden state):** the currency's soundness (no double-spend: an **LU — Consistency** invariant) is enforced over *shielded* notes (E). The nullifier set is public (L/S) while the notes are private (E) — the exact E↔L seam. Channel: **LE** (Evidence — logic inside interiority: the ZK proof attests a hidden fact) + **LU**.

Because this cross-block is thick and typed, the composition **founds a platform** rather than staying a federation of two peers (`holarch.md` §9: "composition with mutual information above the integration threshold founds a new whole; below — remain federated peers"). The composed verdict (a [C] construction, now computed by the `fanos-holarch` Γ-calculator over the declared platform budgets, §8): `P = 0.370`, `R = 0.386 ≥ 1/3`, `Φ = 1.563` (higher than either parent — the composition's integration exceeds both W1's 1.53 and W2's 1.49), `D = 2.615` (E restored above the blockchain's thin `2.06` by the mixnet's hidden pool). **In the agentic window on all four invariants, with 13.6% headroom to the nearest wall (V2, the anti-dominance ceiling).** The honest note stands: the numbers are a construction over declared budgets, not a measurement, exactly the HOLARCH [C] class — but the construction is now mechanical and CI-checked, not asserted.

### 1.3 The four viability invariants as platform release gates {#invariants}

HOLARCH's four invariants (`holarch.md` §6, all [T]) become the platform's architectural release gates — computed, not asserted:

| Invariant | Threshold | The platform pathology it forbids |
|---|---|---|
| **V1 Distinctness** `P = Tr(Γ²)` | `> 2/7` [T] | *mud* — the platform smears into an undifferentiated "does everything" blob with no legible module boundaries |
| **V2 Reflection** `R ≥ 1/3` [T] | `≥ 1/3` | *monolith* — one subsystem (e.g. consensus) eats the whole; anonymity and currency become afterthoughts |
| **V3 Integration** `Φ ≥ 1` [T] | `≥ 1` | *fragmentation* — the subsystems are an archipelago with thin interfaces; the currency doesn't actually ride the mixnet, the naming doesn't actually bind the ledger |
| **V4 Differentiation** `D ≥ 2` [T] | `≥ 2` | *rigidity* — no degraded mode; if the shielded pool or a cell fails there is no transparent/federated fallback to retreat to |

The anti-domination ceiling (V2 ≤ ~3/7) is the same *облик* (shape) of law that BFT already imposes on TAXIS (`f < n/3`) — `holarch.md` §6 marks this KOНСОНАНС [И]: one fraction, two bases (validator weight vs pattern purity), a structural rhyme, never an identity. FANOS is the rare system where the anti-domination law is enforced at **both** levels — the network's quorums *and* the platform's architecture.

### 1.4 The depth ceiling governs L1/L2 scaling {#depth}

HOLARCH's depth-3 ceiling (T-142, §10) — with its external КОНСОНАНС to Buterin's "L3 does not compound" (§16) — is a *derived* constraint on how FANOS scales, not a fashion:

- **Depth 0–1:** the single `PG(2,q)` cell (TAXIS) — an L1 shard.
- **Depth 2 (L2):** the **recursion of cells** already specified in `protocol.md` §L1 and built in `fanos-taxis::hierarchy` — a parent cell whose "nodes" are child cells, attesting their finality (the checkpoints published live in the transformation so far). This is the *legitimate* one compounding of the scaling trick: L2 scales L1.
- **Depth ≥ 3:** **forbidden as a scaling mechanism** — a third recursive tier does *not* compound (the compression does not stack twice). Beyond depth 2, FANOS **federates** (HERMES cross-chain, §8) rather than stacking another tier. The platform's shape obeys the theorem: *scale to depth 2, then federate.*

---

## §2. The platform stack {#stack}

The `protocol.md` layer map (L0–L7) is preserved and extended; the platform adds a **value/application tier (L8–L13)** that composes onto the anonymity substrate. Every new tier names all seven aspects (HOLARCH Ω2 gate: a zero is a decision, not an omission).

| Layer | Name | HOLARCH породная сигнатура | Status |
|---|---|---|---|
| L0–L7 | FANOS anonymity substrate (identity, overlay, transport, membership/beacon, L4 store, APHANTOS/NYX, crypto, incentives) | **E-machine** (W1) | shipped (`protocol.md`) |
| **L8** | **TAXIS** — projective-cell BFT consensus + the cell hierarchy (L1+L2) | **L-machine** (W2), LU/LO dominant | live over QUIC (this transformation) |
| **L9** | **DROMOS** — the swift parallel execution fabric (the high-speed VM + the multi-cell parallel-shard scheduler) | D-dominant, DL/DU channels | **[P]** §3 |
| **L10** | **OBOLOS** — the private untraceable post-quantum currency (the SKIA shielded pool) | **E∧L** — the composition made concrete | **[P]/[H]** §4 |
| **L11** | **ONOMA-domains** (currency-bought private naming) · **ANGELOS** (anonymous PQ messenger) | U (naming) · A/E (messaging) | **[P]** §5, §6 |
| **L12** | **HERMES** — post-quantum threshold cross-chain (federation, not a deeper tier) | O/L, cross-holon T-77 | **[C]** §8 (atomic swaps built; custody [P]) |
| **L13** | **THESAUROS** — the content-storage platform & capacity market (elevates the L4 store) | **O**-dominant, SD/SU/OU/SE channels | **[C]** §7 |

The rest of this document specifies L9–L13. TAXIS (L8) is specified in `protocol.md` Part X.1 and `docs/design-taxis.md`; its live wiring is the current transformation.

---

## §3. DROMOS — the high-speed L1 {#dromos}

*Name:* Greek **δρόμος** (dromos) — a running-course, a racetrack. The engine that makes the ledger *swift*.

### 3.1 The speed thesis: parallelism is already in the geometry {#dromos-thesis}

Solana-class throughput comes from two independent moves, and FANOS's projective structure natively supports both:

1. **Horizontal (inter-cell) parallelism [C].** Each `PG(2,q)` cell is a BFT shard running TAXIS in parallel. Throughput scales with the number of cells; cross-cell atomicity is the `fanos-taxis::crosscell` receipt + the parent-attested checkpoint (already built). This is *sharding by construction* — the plane's `q²+q+1` points partition the validator set, and the incidence geometry gives a deterministic, uniform cross-shard routing (Maekawa `O(√n)` quorums, `protocol.md` §L1). Unlike ad-hoc sharding, cross-shard communication is **algebraic** (two cells meet in exactly one line — the Fano incidence), not a gossip search.
2. **Vertical (intra-cell) parallelism [C] — the scheduler is built.** Within one cell, non-conflicting transactions execute concurrently (the Sealevel insight). The anti-MEV *encrypted* mempool means contents are hidden until the post-commit reveal — so DROMOS parallelizes **post-reveal**, on the revealed access-lists, after ordering is fixed. Ordering (consensus) stays serial and blind (anti-MEV preserved); *execution* fans out. Access-list conflicts are resolved by the HOLARCH **DL — Regulation** channel (`fanos-dromos::scheduler`): a deterministic level assignment on the conflict DAG (each transaction to `1 + max(wave of any earlier conflicting one)`) that provably yields conflict-free waves whose wave-by-wave execution equals the serial result, producing the identical serialization on every validator (`HybridLedger::execute_block`; determinism + serial-equivalence stochastically proven). What remains is running a wave across a real thread pool (the reference executes it in-order) and the cross-cell case below.

### 3.2 Pipelining: finality and execution are already decoupled {#dromos-pipeline}

TAXIS already separates **finality** (the commit certificate fixes order) from **execution** (post-reveal, within the `REVEAL_WINDOW`). DROMOS exploits this: height `h+1` is proposed and finalized while height `h` is still executing — a pipeline whose depth is the reveal window. Execution never blocks consensus; consensus never waits on execution. This is the HOLARCH **SD — Persistence** channel (durable state flowing through the process) plus **DU — Teleology** (the fork-choice reconciling to the desired head) running as a pipeline, not a lockstep.

### 3.3 State model {#dromos-state}

DROMOS runs a **hybrid state machine**: a transparent account tree (for public smart contracts, staking, naming — the `Accounts` model, generalized) **and** the OBOLOS shielded note pool (§4), unified under one `state_root`. A transaction declares its access list (for parallel scheduling) in the clear for *public* state, and only a nullifier + commitment set for *shielded* state (the access list of a shielded spend is the whole pool — so shielded spends serialize against the nullifier set but parallelize against each other via the disjoint-nullifier check). The `StateMachine` trait (already the TAXIS execution seam) is the plug point; DROMOS is a `StateMachine` implementation with a parallel scheduler.

### 3.4 Honest limits {#dromos-limits}

- Intra-cell parallel execution: the scheduler + conflict model are **built and proven** (`fanos-dromos::scheduler`/`HybridLedger::execute_block`, determinism + serial-equivalence stochastically tested); the residual is **[C]** — dispatching a wave onto an actual thread pool (the reference runs it in index order) and a fuller access-list model as contract state grows.
- The anti-MEV encrypted mempool caps *pre-execution* parallelism: DROMOS cannot speculate on hidden contents, so its parallelism begins at reveal. This is a deliberate privacy/throughput trade (`holarch.md` anonymity trilemma, §15): FANOS spends some latency to keep ordering blind. The pipeline hides most of that latency; the residual is the honest cost of anti-MEV.
- Cross-cell atomic composability (a transaction touching two cells atomically) is the classic sharding hard problem; FANOS's algebraic incidence *simplifies routing* but the two-phase atomic-commit across cells is **[P]** and its liveness under a Byzantine cell is bounded by the parent's attestation window.

---

## §4. OBOLOS — the private, untraceable, post-quantum currency {#obolos}

*Name:* Greek **ὀβολός** (obolos) — an ancient coin. Its privacy machinery is **SKIA** (σκιά, shadow) — the shielded pool where value hides.

This is the crown jewel and the hardest subsystem. The requirement (from the platform brief): **untraceability and unlinkability no weaker than Monero, made post-quantum, and stronger where the design allows.** The design below chooses a **shielded-pool** model (a whole-pool anonymity set) over Monero's fixed-size ring signatures — a strictly larger anonymity set — and instantiates every primitive post-quantum.

### 4.1 The three privacy properties and their PQ instantiation {#obolos-props}

A private currency must deliver three orthogonal properties. The [И] mapping to HOLARCH aspects makes the design legible: all three are **E** (interiority) properties enforced by **L** (logic — a zero-knowledge proof):

| Property | What it hides | Classical (Monero/Zcash) | FANOS post-quantum instantiation |
|---|---|---|---|
| **Confidentiality** | the amount | Pedersen commitment (ristretto) + Bulletproofs range proof | **lattice (Module-LWE, BDLOP-style) additively-homomorphic commitment** to the amount + a **lattice range proof** (the Esgin–Nguyen–Seiler / LNP line) — [P] |
| **Unlinkability** | the recipient | Ed25519 stealth addresses | **hybrid-KEM (ML-KEM) one-time note keys** — a fresh note public per payment, detectable only by the recipient's viewing key (reuses `fanos-pqcrypto::kem`) — [C] for the derivation, [P] for the note-scan optimisation |
| **Untraceability** | the sender / the spent note | CLSAG ring signature over a small ring | **whole-pool membership proof**: a ZK proof that the spent note is *some* leaf of the public commitment tree, revealing only a **nullifier** — a Zcash-Orchard/Lelantus-Spark-class design, PQ-instantiated (lattice or hash-based STARK membership proof) — [P]/[H] |

The untraceability upgrade over Monero is structural: Monero's anonymity set is the ring size (≈16); OBOLOS's is **the entire shielded pool**. And it compounds with the platform's E-machine: the *transaction itself* also travels the mixnet and enters the *encrypted* mempool, so the network-level linkage (who broadcast it, in what order) is hidden by APHANTOS + anti-MEV — a second, independent anonymity layer Monero and Zcash lack.

### 4.2 The note, the commitment tree, and the nullifier {#obolos-note}

The model is a **shielded UTXO** (a "note"), the Zcash Sapling/Orchard lineage, made PQ:

- **A note** `n = (v, pk_d, ρ)` — an amount `v`, a diversified one-time recipient key `pk_d` (from the recipient's stealth address via ML-KEM), and a random `ρ`.
- **The note commitment** `cm = Commit_lat(v; r) ‖ H("obolos-note", pk_d ‖ ρ)` — the value under a lattice additively-homomorphic commitment (so balance is checkable homomorphically), bound to the recipient and randomness by a PQ hash (BLAKE3, already in `fanos-primitives`). Binding + hiding.
- **The commitment tree** `T` — an append-only Merkle tree (PQ-safe hash) of all `cm` ever created; its root is part of the `state_root`. Public.
- **The nullifier** `nf = PRF(nsk, position(cm))` — a pseudo-random function of the note's spending secret and the note's tree position, revealed when the note is spent. Deterministic (so the *same* note always yields the *same* nullifier → double-spend is detectable) yet **unlinkable** to `cm` (the PRF hides which note it nullifies). The nullifier set is public (L/S); a spend that repeats a nullifier is rejected. PQ PRF: a keyed BLAKE3 / lattice PRF — [C].

### 4.3 The shielded transaction and the balance law {#obolos-tx}

A shielded transaction spends `m` input notes and creates `k` output notes, revealing only: the `m` nullifiers, the `k` output commitments, an encrypted note-ciphertext per output (for the recipient, sealed with ML-KEM), a fee `f` (public, in the clear, so validators can be paid), and **one zero-knowledge proof** `π` attesting:

1. **membership** — each input `cm_i` is a leaf of the tree at root `rt` (whole-pool untraceability);
2. **ownership + nullifier correctness** — the spender knows each `nsk_i` and `nf_i = PRF(nsk_i, pos_i)` is computed correctly (no forged nullifiers, no framing);
3. **balance** — `Σ v_i (inputs) = Σ v_j (outputs) + f`, checked **homomorphically** on the lattice value-commitments (confidential amounts never revealed);
4. **range** — every output `v_j ∈ [0, 2^64)` (no negative-value inflation attack).

This `π` is the single frontier component. It is isolated behind a typed interface `trait ShieldedProof { fn prove(...); fn verify(...); }` so the accounting (tree, nullifier set, commitments, balance homomorphism, ledger integration) is fully implementable and **verified now**, while the proof backend is a pluggable, honestly-tagged **[P]** — the target backend is a lattice ZK system (LNP-class); a transparent hash-based (STARK) backend is the conservative fallback (larger proofs, only symmetric-crypto assumptions). **No new hardness is invented** — both backends compose published PQ ZK constructions (HOLARCH Ω0 honesty).

### 4.4 Integration with TAXIS and the mixnet — the composition realized {#obolos-integration}

OBOLOS is a `StateMachine` on TAXIS (L8): shielded transactions are ordered by the anti-MEV encrypted mempool (contents blind to the proposer — MEV-free by construction, `docs/design-taxis.md` §5), then executed post-reveal by DROMOS, which verifies `π`, checks nullifiers against the set, and appends output commitments to the tree. The two anonymity layers **compose**: SKIA hides the *ledger-level* linkage (which note paid which), APHANTOS + the encrypted mempool hide the *network-level* linkage (who submitted, in what order). This is the E∧L cross-block of §1.2 delivering a currency neither an E-machine nor an L-machine could deliver alone — the platform thesis, made spendable.

### 4.5 Honest limits and open problems {#obolos-limits}

- The PQ shielded-transaction proof `π` is **[P]/[H]**: practical post-quantum ZK for the full membership+range+balance statement is at the research frontier. Lattice ZK (LNP) is the target; proof size/verification time and a formal security reduction are open until built + audited. **This is the single most load-bearing [P] in the platform** and is scoped, isolated, and honestly flagged — never hidden.
- Amount confidentiality via lattice commitments requires the additively-homomorphic property to survive the chosen parameters; the balance check's soundness reduces to the commitment's binding — a [C] to prove per parameter set.
- Regulatory / viewing-key disclosure (selective transparency for a consenting user) is a design option (Zcash viewing keys), specified as optional and off by default — untraceability is the default, disclosure is opt-in.
- Quantitative anonymity: the anonymity set is the shielded pool size; a freshly-launched pool is small (the classic "anonymity loves company" bootstrap). Mitigations (mandatory shielded fees, dummy notes as an EO — Immanence cover-traffic budget, exactly the mixnet's cover-traffic idea imported to the ledger) are [P].

---

## §5. ONOMA-domains — currency-bought private naming {#onoma}

*Name:* Greek **ὄνομα** (onoma) — a name. Already present as `fanos-onoma` (self-certifying `.fanos` addresses + a registry); the platform makes names **ownable, purchasable, and private**.

- **Ownership on the ledger [C].** A name → owner binding lives in the transparent state (TAXIS/DROMOS). Registration and renewal are transactions **paid in OBOLOS**; the name→descriptor mapping is public (so anyone can resolve), but the *owner* may be a shielded identity (payment from the pool), so ownership is public while the human behind it is not — the E∧L seam again (public binding, private owner).
- **What a name resolves to.** A CALYPSO service descriptor (an anonymous hidden service, `protocol.md` Part XII), an OBOLOS payment address (a stealth meta-address), and/or an ANGELOS messaging identity (§6) — one human-memorable name, three private endpoints.
- **Governance [P].** Auctions/pricing (Harberger-style or fixed) to prevent squatting; a demand-controlled price is the HOLARCH **DL — Regulation** channel (the same Lyapunov demand controller the network's `roles::assign` already uses — reuse, not reinvention).
- **Anti-squatting via the mixnet [C]:** registration is submitted anonymously, so front-running a pending registration is defeated by the same anti-MEV encrypted mempool that protects OBOLOS transfers — naming inherits MEV-resistance for free.

---

## §6. ANGELOS — the anonymous post-quantum messenger {#angelos}

*Name:* Greek **ἄγγελος** (angelos) — a messenger. The goal: **more advanced than Session**, by composing FANOS primitives that already individually beat Session's (Lokinet onion routing + Oxen service nodes + Signal double-ratchet).

FANOS already has every organ Session assembles, each stronger:

| Session (Oxen) | FANOS organ | Why stronger |
|---|---|---|
| Lokinet onion routing | **NYX** threshold-sheaf onion (`protocol.md` §V) | threshold groups per hop (not single relays) + structurally-balanced cover traffic — mixnet-class, not just onion |
| Oxen service-node registry | **TAXIS** stake registry (L8) | a real BFT L1, not a separate chain bolted on |
| directory of swarms | **CALYPSO** computed rendezvous (`protocol.md` §XII) | *no directory* — the meeting point is computed, `O(1)`, unlinkable |
| Session ID (X25519) | **ONOMA** name → PQ identity | human-memorable, ledger-owned, post-quantum |
| Signal double-ratchet | **DIAULOS** sessions + a **PQ double-ratchet** (hybrid X25519+ML-KEM, reusing `onion_ratchet`) | post-quantum forward secrecy |
| — (online-ish) | **L4 store mailboxes** | store-and-forward offline delivery in the erasure-coded DHT, retrieved anonymously |

ANGELOS is therefore an **application composition [C]**, not new cryptography: the anonymity is inherited from the substrate; the new pieces are the session crypto and the product model. But the goal is larger than a 1:1 Session clone — it is a **Discord-class communications platform** (text *and* audio/video, communities and channels, presence and roles), carried over the *whole network*, at a performance the mixnet alone cannot give. That forces the one non-obvious architectural decision, and the rest follows from it.

### §6.1 The two transport modes — the latency↔anonymity dial {#angelos-modes}

The mixnet (NYX/APHANTOS) is deliberately **high-latency**: Poisson mixing and cover traffic are *why* metadata vanishes (the anonymity trilemma, `holarch.md` §15 — you pay latency or bandwidth for unlinkability). Real-time audio/video needs the opposite: **sub-150 ms** mouth-to-ear. A messenger that must do both cannot pick one transport. FANOS already resolves this with the **Direct / Lite / Full anonymity dial** (`docs/roadmap.md`, `docs/design.md` §6): the *same* engine offers a spectrum from a low-latency near-direct path to full mixnet mixing. ANGELOS makes the dial **per-flow**:

- **Async / control plane — Full mixnet.** Text messages, mailbox delivery, presence, and signaling ride NYX-over-CALYPSO at full mixing: metadata-private, store-and-forward through L4 mailboxes (`OU — Wholeness`: the DHT feeds the offline recipient). This is where ANGELOS beats Discord *and* Signal — the network cannot see who talks to whom.
- **Real-time media plane — Lite/Direct.** A call's audio/video rides a low-latency path (Lite: a short mixed route; Direct: a rendezvous-established near-direct path, still onion-wrapped for content secrecy). The user (or a room policy) sets the dial: a whistleblower's call pays latency for anonymity; a team standup takes Direct. The trade-off is **declared, not hidden** — the HOLARCH **EO — Immanence** channel (the cover-traffic/latency budget, felt from inside).

Both planes share one **coordinate/identity fabric** (the platform's `U — Unity`), so a call is *set up* over the anonymous control plane (exchanging the media session's keys and a rendezvous coordinate) and then *flows* over the media plane — SIP/WebRTC's "signaling vs. media" split, re-derived on the FANOS substrate.

### §6.2 The session crypto — three ratchets {#angelos-crypto}

- **1:1 text** — a **forward-secret PQ session** (`fanos-angelos::session`, built): hybrid-ML-KEM handshake → BLAKE3 symmetric ratchet, a fresh key per message. Post-compromise security (the asymmetric KEM ratchet) and skipped-key handling compose on top.
- **Groups / channels** — a **sender-key group session**: each member derives a per-sender chain, so a channel of `k` members is `k` ratchets, and posting is `O(1)` (encrypt once to the channel key), not `O(k)` pairwise. Membership changes rekey. This is the crypto under a Discord *text channel*.
- **Real-time media** — a **media session**: a per-call symmetric key (agreed over the control plane) keys an SRTP-like frame cipher (per-packet AEAD, sequence-numbered, loss-tolerant — you cannot ratchet per-packet at 50 packets/s, so media uses a periodically-rekeyed key, forward-secret across epochs not packets). Voice and video are just typed media streams over it.

### §6.3 The Discord-class model {#angelos-product}

Everything Discord assembles maps onto organs FANOS already has, made private and post-quantum:

| Discord | ANGELOS |
|---|---|
| account / user id | **ONOMA** name → PQ identity (ledger-owned, human-memorable) |
| servers (guilds) & channels | a **community**: a signed roster + channel set; ownership/roles on the ledger (a `dromos::naming` descriptor points a name at a community), so a community is *self-certifying*, not host-owned |
| roles / permissions | capability tokens signed by the community key (post-quantum), checked at the channel boundary |
| voice/video rooms | a media session (§6.2) over the Lite/Direct plane; the room's coordinate is CALYPSO-computed, so **no central media server** — an SFU role (selective forwarding) is a *cell* function, not a company's datacenter |
| presence / typing | control-plane events over the mixnet (rate-shaped so presence itself leaks nothing) |
| file / screen share | typed media/blob streams; large blobs land in the L4 erasure store, retrieved anonymously |
| Nitro (paid features) | **OBOLOS**-payable premium (storage, larger uploads, priority) — private payment for a private service |

The decisive difference from Discord: **there is no company in the middle.** Communities are self-certifying (ledger-owned identity + roles), media is forwarded by cell nodes (an SFU is a *role* the network assigns, `fanos-core::roles`), and metadata is mixnet-hidden. It is *no worse than Discord* on features and strictly better on sovereignty and privacy.

### §6.4 Status {#angelos-status}

**[C]** for the composition (the transport dial, rendezvous, identity, storage all exist and are strong). **Built:** the 1:1 forward-secret session. **[P]:** the group and media sessions, the community/role model, the signaling↔media call flow, and the product surface. The performance target (Discord-class real-time at scale) rides on the Lite/Direct plane + cell-forwarded media — the substrate supports it; delivering it at scale is the program.

---

## §7. THESAUROS — the content-storage platform {#thesauros}

*Name:* Greek **θησαυρός** (thesauros) — "storehouse, treasury"; the store that is also a market. It captures both duties at once, in the OBOLOS economic register.

THESAUROS makes the **O — Foundation** store first-class: an advanced, monetized, post-quantum IPFS analog built *on top of* the L4 projective-LRC erasure store (`protocol.md` §L4), not beside it. It is the messenger's first tenant — "large blobs land in the L4 erasure store, retrieved anonymously" (§6.3) becomes a real subsystem — and the platform's capacity market: nodes **earn** OBOLOS by serving the `Storage` role, users **pay** for durability. It adds exactly three things the substrate lacks, all else being composition (Ω0):

- **Immutable content addressing:** a chunk's `CID = MerkleRoot(leaves)` (BLAKE3, domain-separated) is content-addressed-by-value *and* the storage commitment at once; large objects are UnixFS-style Merkle-DAG manifests; a `DescriptorKind::Storage` name (`fanos-dromos::naming`) maps a mutable name → immutable CID. Content is **sealed at the edge** — the store holds only ciphertext (the E/privacy tint).
- **Proof of retrievability [T]:** a cheap, *derived* audit — the PQ-VRF beacon seeds `k` unpredictable leaf challenges (reusing the `da` sampler), the provider returns leaves + Merkle paths against the committed CID. Soundness is not a constant: to catch any provider missing a fraction `f_tol` with `λ` bits, `k ≥ λ·ln2 / (−ln(1−f_tol))` — computed, not chosen. Storj/Sia-class spot-checks, *not* Filecoin's proving treadmill (the erasure layer already gives durability).
- **The capacity market:** carried as a new `HybridLedger` tag `TAG_STORAGE`, a `Deal` state machine whose escrow releases the epoch slice **only when a proof verifies** — the exact `apply_shielded` "keyless sink released by a proof" idiom, via `move_system`. Enforcement is **pay-per-proof in arrears + reputation decay**, *not* bond-slashing: FANOS forbids capital staking (it deanonymizes), so a non-proving provider simply earns nothing and loses future assignments (`Reputation::observe`), the consumer is refunded, and honest storage strictly dominates whenever the slice `p` clears the cost `c` (the reused `covers_cost` condition). Price is derived (a utilization bonding curve; a double auction is the evolution), never a knob.

*Породная сигнатура:* **O**-dominant, thick on **SD** (Persistence), **SU** (Symmetry / LRC replication), **OU** (Wholeness / data availability), **SE** (Representation / manifest index), with an **E/EO** tint (sealed, anonymously-retrieved content). It reuses the `[7,3,4]` codec, coordinate placement, DA sampler, `Role::Storage`/reputation, and the DROMOS payment rails verbatim; the one greenfield primitive is the proof of retrievability. Full design: `docs/design-storage.md`.

**Status: [C]** for the composition (substrate, payments, roles, DA all built and strong); **[T]** for the PoR soundness bound; the content model + market state machine are the near-term build; shielded-payment deals inherit OBOLOS's **[P]** frontier (transparent-token deals work today).

---

## §8. HERMES — post-quantum threshold cross-chain {#hermes}

*Name:* Greek **Ἑρμῆς** (Hermes) — god of boundaries, travel, commerce, and messengers; the crosser of thresholds.

Cross-chain is a **federation** (HOLARCH §10: beyond depth 2, federate — do not stack a third tier), realized by FANOS's own threshold cells as the trust-minimized bridge validators. The idea-storm, synthesized to a decision:

- **Rejected — light-client bridges:** verifying a foreign chain's consensus inside FANOS requires that chain's (often non-PQ) signatures, importing its trust assumptions and its quantum-fragility. A PQ platform must not anchor its bridge on classical ECDSA.
- **Chosen — threshold-attested custody + HTLC atomic swaps:** a FANOS cell (its BFT quorum + a threshold signature, both already built: `fanos-vrf` DKG, `fanos-aphantos` threshold) acts as a decentralized notary/custodian. Two modes: (1) **atomic swaps [C] — built** via PQ hash-locked contracts (`fanos-hermes` — a hash-preimage lock, post-quantum with no shortcut past Grover; trustless, no custody, for chains that support hashlocks) and **live on the ledger** (`fanos-dromos` `TAG_HTLC`: lock escrows into a keyless sink, a revealed preimage before the timeout releases it to the recipient, a timed-out contract refunds the sender — the timeout measured by the block-height clock; the two-chain atomicity is unit-proven on both the reveal and the refund paths); (2) **threshold custody [P]** for chains without hashlocks — the cell's quorum jointly controls a foreign address, and a cross-chain transfer is a TAXIS-attested event (the `crosscell` receipt machinery, generalized to a foreign endpoint). Byzantine safety of the bridge = the cell's BFT bound (`f < n/3`), the same guarantee as consensus.
- **The synthesis:** FANOS's cells are *already* threshold-signing BFT committees with an unbiasable beacon and cross-cell receipts. HERMES is the smallest possible new surface: point that machinery at a foreign endpoint. Cross-chain becomes an instance of cross-*cell*, where the far cell is another chain. **[P]** — the foreign adapters and the economic security (bonding, slashing on equivocated attestations, reusing `fanos-taxis::incentive`) are the work.

---

## §9. The transformation roadmap — sequential, verified, exemplary {#roadmap}

The transformation proceeds in verified increments; each lands green (workspace tests + `clippy --all-targets -D warnings`) before the next, per the standing discipline. Ordered by *foundational leverage* (what the most other things need):

1. **T1 · TAXIS live (L8)** — ✅ substantially done this cycle: consensus over real QUIC, the App-overlay receive seam, live checkpoint publishing. Residual: full two-cell parent-attests-child loop; `Node::start` config.
2. **T2 · The value tier foundation** — the OBOLOS accounting core (note, commitment tree, nullifier set, lattice value-commitment, balance homomorphism) as a new crate `fanos-obolos`, with `ShieldedProof` as a typed interface and a first verifiable backend. *The crown-jewel foundation, fully verified; the frontier proof isolated and tagged.*
3. **T3 · DROMOS (L9)** — the hybrid state machine (transparent accounts + shielded pool under one `state_root`) as a TAXIS `StateMachine`, then the parallel scheduler with a proven-deterministic serialization.
4. **T4 · ONOMA-domains + ANGELOS (L11)** — currency-bought naming on the ledger; the messenger composition over the existing anonymity organs.
5. **T5 · HERMES (L12)** — the threshold cross-chain, atomic-swap mode first (trustless), custody mode second.
6. **Throughout · the HOLARCH gate** — the `fanos-holarch` Γ-calculator (the `architecture/` companion, built) that, given the declared platform budgets, verifies `Γ` is a valid trace-1 PSD coherence operator and then computes `P/R/Φ/D`, the σ-panel, the robustness margin, and the four Ω4 ablations — so "the platform is in the viability window" is a CI-checked number (its own `cargo test` gate plus a section in `fanos-verify`), not a claim (HOLARCH Ω4/Ω7). Its release thresholds are imported from the runtime DIAKRISIS coherence plane, so the gate and the plane cannot drift. This is the platform's release gate, the way `fanos-verify` is the network's.

Every subsystem names all seven aspects (Ω2), declares its typed cross-block contracts (Ω9, with a CALM class on each consistency contract), and carries a formal representation on its heavy L-contracts (the shielded-proof soundness, the consensus safety — Ω5).

---

## §10. Honest limits, falsifiers, and the single largest risk {#limits}

Following HOLARCH §19 — a specification that declares itself perfect refutes itself. The load-bearing honesty:

- **The post-quantum shielded proof (§4.3) is the single largest [P]/[H].** Practical PQ zero-knowledge for the full shielded statement is frontier work; the platform's *untraceability guarantee* rests on it. It is scoped behind one interface, has a conservative transparent-STARK fallback, and is never claimed as done. If PQ ZK for this statement proves impractical at platform scale, the fallback is a Monero-class **PQ ring signature** over a bounded ring (a strictly weaker but still-PQ anonymity set) — a documented retreat, the HOLARCH V4 *differentiation* (a second mode to fall back to) applied to the crypto itself.
- **"High-speed L1" is a program, not a benchmark yet.** The parallel-execution determinism and cross-shard atomicity (§3.4) must be built and measured; the geometry *enables* Solana-class scaling but does not deliver it for free.
- **The Γ-profile numbers (§1.2) are a [C] construction over declared budgets**, not a measurement of a running platform — exactly the HOLARCH honesty class. The viability *thresholds* are theorems; that the platform's budgets deserve them is validated by coherence-of-consequences until there is field data.
- **Aspect attributions are judgments [И].** Whether the OBOLOS proof is L-work or E-work, whether DROMOS's scheduler is D or DL, are arguable model decisions; the vocabulary makes them arguable, not certain.
- **Falsifiers, as targets:** (1) exhibit a platform dependency no aspect-pair types (breaks §1); (2) exhibit a bona-fide Γ-assembly of the platform that is viable yet violates the four-invariant conjunction (breaks the gate); (3) demonstrate the PQ shielded pool is unrealizable at parameters giving both soundness and platform-scale performance (forces the §10 retreat, honestly).

**What this document does not claim:** it does not claim the platform is built (it is the blueprint); it does not claim new cryptographic hardness (it composes vetted PQ primitives and isolates the one frontier proof); and it does not claim the HOLARCH verdict is a measurement (it is a construction over declared budgets, to be recomputed as the code lands). The transformation is sequential, verified, and honest at every step — the standing discipline, applied to a platform.
