---
sidebar_position: 1
title: "FANOS Platform — the holonic synthesis (E∧L meta-holon)"
description: "The transformation of FANOS from an anonymity overlay into a full holonic platform: natively both a maximal-anonymity mixnet (E-machine) and a high-speed private post-quantum L1 blockchain (L-machine), with an untraceable currency (OBOLOS), a swift parallel execution fabric (DROMOS), currency-bought private naming (ONOMA), an anonymous PQ messenger (ANGELOS), and a threshold cross-chain (HERMES) — grounded in the ХОЛАРХ meta-specification and validated against its four viability invariants."
---

# FANOS Platform — the holonic synthesis

> *"A mixnet hides who; a blockchain agrees what. Compose the two above the integration threshold and a third thing is born that neither is: a platform where value moves with the untraceability of light through night and the finality of law."*

:::info Document status
**Version 0.1** (platform reference architecture — the revision of [`protocol.md`](./protocol.md) for the blockchain-platform era). This document is the **design authority** for the transformation; it is grounded in the corpus **ХОЛАРХ** meta-specification (`applied/research/holarch.md`) and inherits its status discipline — every nontrivial claim carries **[T]** theorem / **[C]** construction (self-consistent by design) / **[H]** hypothesis (needs proof or audit) / **[P]** program (a direction of work) / **[И]** interpretation (a structured, arguable dictionary reading, never a fact). Cryptographic honesty is unchanged from `protocol.md`: **the novelty is architectural composition of vetted primitives, not new hardness assumptions.** Where a subsystem genuinely needs frontier cryptography (the post-quantum shielded pool, §4), the frontier component is isolated behind a typed interface and tagged **[P]**; the surrounding accounting is fully implementable and verified.
:::

---

## §0. The thesis, in one paragraph {#thesis}

`protocol.md` specifies FANOS as an **E-machine**: an anonymity overlay whose product is its unobservable interior (the hidden pool, the ratchet keys, the cover traffic) — the ХОЛАРХ mixnet worked example W1 (`holarch.md` §15), re-derived on `PG(2,q)`. This document composes that E-machine with an **L-machine** — a Byzantine-agreement blockchain whose product is forced consistency between strangers (the ХОЛАРХ blockchain worked example W2, §16) — already present in seed form as `fanos-taxis`. By the ХОЛАРХ cooperation theorem (T-77, §9), composing two holons whose cross-block coherence exceeds the integration threshold **founds a new meta-holon** — a platform that is neither parent alone. The FANOS Platform is that meta-holon: **the first system that is simultaneously anonymity-native (strong E) and consensus-native (strong L)**, and therefore the natural home for a currency that is at once *untraceable* (an E property — value hidden in interiority) and *sound* (an L property — no double-spend, enforced by agreement). Monero and Zcash are L-machines with a bolted-on shielded pool; Nym is an E-machine with no L1. FANOS is the composition done at the root.

---

## §1. ХОЛАРХ grounding: the platform as a validated meta-holon {#holarch}

### 1.1 The seven aspects, at platform scale {#aspects}

ХОЛАРХ fixes the alphabet of concerns at **seven** (A/S/D/L/E/O/U) by the uniqueness theorem T-224 [T] — the same Fano-plane rigidity that FANOS already builds its *network* on, now read one level up as the platform's own budget vector. The platform's aspect profile (its Γ-diagonal — the [И] reading of `holarch.md` §4):

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
- **L→O (consensus secures the substrate):** TAXIS finality + stake (proof-of-stake is the ХОЛАРХ **LO — Foundation** channel read literally, §5) provide the Sybil-resistant node registry, the naming ownership, and the beacon the *mixnet* needs for its epoch topology and Sybil admission. The blockchain pays the mixnet's foundation. Channel: **LO** + **OU** (Wholeness — the DA layer feeds the whole).
- **L↔E (agreement over hidden state):** the currency's soundness (no double-spend: an **LU — Consistency** invariant) is enforced over *shielded* notes (E). The nullifier set is public (L/S) while the notes are private (E) — the exact E↔L seam. Channel: **LE** (Evidence — logic inside interiority: the ZK proof attests a hidden fact) + **LU**.

Because this cross-block is thick and typed, the composition **founds a platform** rather than staying a federation of two peers (`holarch.md` §9: "composition with mutual information above the integration threshold founds a new whole; below — remain federated peers"). The estimated composed verdict (a [C] construction, to be reproduced by a Γ-calculator over the declared platform budgets, §8): `P ≈ 0.36`, `R ≥ 1/3`, `Φ ≈ 1.6` (higher than either parent — the composition's integration exceeds both W1's 1.53 and W2's 1.49), `D ≥ 2.3` (E restored above the blockchain's thin `2.06` by the mixnet's hidden pool). **In the agentic window on all four invariants** — and the honest note: the numbers are a construction over declared budgets, not a measurement, exactly the ХОЛАРХ [C] class.

### 1.3 The four viability invariants as platform release gates {#invariants}

ХОЛАРХ's four invariants (`holarch.md` §6, all [T]) become the platform's architectural release gates — computed, not asserted:

| Invariant | Threshold | The platform pathology it forbids |
|---|---|---|
| **V1 Distinctness** `P = Tr(Γ²)` | `> 2/7` [T] | *mud* — the platform smears into an undifferentiated "does everything" blob with no legible module boundaries |
| **V2 Reflection** `R ≥ 1/3` [T] | `≥ 1/3` | *monolith* — one subsystem (e.g. consensus) eats the whole; anonymity and currency become afterthoughts |
| **V3 Integration** `Φ ≥ 1` [T] | `≥ 1` | *fragmentation* — the subsystems are an archipelago with thin interfaces; the currency doesn't actually ride the mixnet, the naming doesn't actually bind the ledger |
| **V4 Differentiation** `D ≥ 2` [T] | `≥ 2` | *rigidity* — no degraded mode; if the shielded pool or a cell fails there is no transparent/federated fallback to retreat to |

The anti-domination ceiling (V2 ≤ ~3/7) is the same *облик* (shape) of law that BFT already imposes on TAXIS (`f < n/3`) — `holarch.md` §6 marks this KOНСОНАНС [И]: one fraction, two bases (validator weight vs pattern purity), a structural rhyme, never an identity. FANOS is the rare system where the anti-domination law is enforced at **both** levels — the network's quorums *and* the platform's architecture.

### 1.4 The depth ceiling governs L1/L2 scaling {#depth}

ХОЛАРХ's depth-3 ceiling (T-142, §10) — with its external КОНСОНАНС to Buterin's "L3 does not compound" (§16) — is a *derived* constraint on how FANOS scales, not a fashion:

- **Depth 0–1:** the single `PG(2,q)` cell (TAXIS) — an L1 shard.
- **Depth 2 (L2):** the **recursion of cells** already specified in `protocol.md` §L1 and built in `fanos-taxis::hierarchy` — a parent cell whose "nodes" are child cells, attesting their finality (the checkpoints published live in the transformation so far). This is the *legitimate* one compounding of the scaling trick: L2 scales L1.
- **Depth ≥ 3:** **forbidden as a scaling mechanism** — a third recursive tier does *not* compound (the compression does not stack twice). Beyond depth 2, FANOS **federates** (HERMES cross-chain, §7) rather than stacking another tier. The platform's shape obeys the theorem: *scale to depth 2, then federate.*

---

## §2. The platform stack {#stack}

The `protocol.md` layer map (L0–L7) is preserved and extended; the platform adds a **value/application tier (L8–L12)** that composes onto the anonymity substrate. Every new tier names all seven aspects (ХОЛАРХ Ω2 gate: a zero is a decision, not an omission).

| Layer | Name | ХОЛАРХ породная сигнатура | Status |
|---|---|---|---|
| L0–L7 | FANOS anonymity substrate (identity, overlay, transport, membership/beacon, L4 store, APHANTOS/NYX, crypto, incentives) | **E-machine** (W1) | shipped (`protocol.md`) |
| **L8** | **TAXIS** — projective-cell BFT consensus + the cell hierarchy (L1+L2) | **L-machine** (W2), LU/LO dominant | live over QUIC (this transformation) |
| **L9** | **DROMOS** — the swift parallel execution fabric (the high-speed VM + the multi-cell parallel-shard scheduler) | D-dominant, DL/DU channels | **[P]** §3 |
| **L10** | **OBOLOS** — the private untraceable post-quantum currency (the SKIA shielded pool) | **E∧L** — the composition made concrete | **[P]/[H]** §4 |
| **L11** | **ONOMA-domains** (currency-bought private naming) · **ANGELOS** (anonymous PQ messenger) | U (naming) · A/E (messaging) | **[P]** §5, §6 |
| **L12** | **HERMES** — post-quantum threshold cross-chain (federation, not a deeper tier) | O/L, cross-holon T-77 | **[P]** §7 |

The rest of this document specifies L9–L12. TAXIS (L8) is specified in `protocol.md` Part X.1 and `docs/design-taxis.md`; its live wiring is the current transformation.

---

## §3. DROMOS — the high-speed L1 {#dromos}

*Name:* Greek **δρόμος** (dromos) — a running-course, a racetrack. The engine that makes the ledger *swift*.

### 3.1 The speed thesis: parallelism is already in the geometry {#dromos-thesis}

Solana-class throughput comes from two independent moves, and FANOS's projective structure natively supports both:

1. **Horizontal (inter-cell) parallelism [C].** Each `PG(2,q)` cell is a BFT shard running TAXIS in parallel. Throughput scales with the number of cells; cross-cell atomicity is the `fanos-taxis::crosscell` receipt + the parent-attested checkpoint (already built). This is *sharding by construction* — the plane's `q²+q+1` points partition the validator set, and the incidence geometry gives a deterministic, uniform cross-shard routing (Maekawa `O(√n)` quorums, `protocol.md` §L1). Unlike ad-hoc sharding, cross-shard communication is **algebraic** (two cells meet in exactly one line — the Fano incidence), not a gossip search.
2. **Vertical (intra-cell) parallelism [P].** Within one cell, non-conflicting transactions execute concurrently (the Sealevel insight). The anti-MEV *encrypted* mempool means contents are hidden until the post-commit reveal — so DROMOS parallelizes **post-reveal**, on the revealed access-lists, after ordering is fixed. Ordering (consensus) stays serial and blind (anti-MEV preserved); *execution* fans out. Access-list conflicts are resolved by the ХОЛАРХ **DL — Regulation** channel (a deterministic scheduler), producing the identical serialization on every validator.

### 3.2 Pipelining: finality and execution are already decoupled {#dromos-pipeline}

TAXIS already separates **finality** (the commit certificate fixes order) from **execution** (post-reveal, within the `REVEAL_WINDOW`). DROMOS exploits this: height `h+1` is proposed and finalized while height `h` is still executing — a pipeline whose depth is the reveal window. Execution never blocks consensus; consensus never waits on execution. This is the ХОЛАРХ **SD — Persistence** channel (durable state flowing through the process) plus **DU — Teleology** (the fork-choice reconciling to the desired head) running as a pipeline, not a lockstep.

### 3.3 State model {#dromos-state}

DROMOS runs a **hybrid state machine**: a transparent account tree (for public smart contracts, staking, naming — the `Accounts` model, generalized) **and** the OBOLOS shielded note pool (§4), unified under one `state_root`. A transaction declares its access list (for parallel scheduling) in the clear for *public* state, and only a nullifier + commitment set for *shielded* state (the access list of a shielded spend is the whole pool — so shielded spends serialize against the nullifier set but parallelize against each other via the disjoint-nullifier check). The `StateMachine` trait (already the TAXIS execution seam) is the plug point; DROMOS is a `StateMachine` implementation with a parallel scheduler.

### 3.4 Honest limits {#dromos-limits}

- Intra-cell parallel execution is **[P]** — the scheduler + the conflict model must be built and the determinism proven (the same serialization on every validator, exhaustively tested).
- The anti-MEV encrypted mempool caps *pre-execution* parallelism: DROMOS cannot speculate on hidden contents, so its parallelism begins at reveal. This is a deliberate privacy/throughput trade (`holarch.md` anonymity trilemma, §15): FANOS spends some latency to keep ordering blind. The pipeline hides most of that latency; the residual is the honest cost of anti-MEV.
- Cross-cell atomic composability (a transaction touching two cells atomically) is the classic sharding hard problem; FANOS's algebraic incidence *simplifies routing* but the two-phase atomic-commit across cells is **[P]** and its liveness under a Byzantine cell is bounded by the parent's attestation window.

---

## §4. OBOLOS — the private, untraceable, post-quantum currency {#obolos}

*Name:* Greek **ὀβολός** (obolos) — an ancient coin. Its privacy machinery is **SKIA** (σκιά, shadow) — the shielded pool where value hides.

This is the crown jewel and the hardest subsystem. The requirement (from the platform brief): **untraceability and unlinkability no weaker than Monero, made post-quantum, and stronger where the design allows.** The design below chooses a **shielded-pool** model (a whole-pool anonymity set) over Monero's fixed-size ring signatures — a strictly larger anonymity set — and instantiates every primitive post-quantum.

### 4.1 The three privacy properties and their PQ instantiation {#obolos-props}

A private currency must deliver three orthogonal properties. The [И] mapping to ХОЛАРХ aspects makes the design legible: all three are **E** (interiority) properties enforced by **L** (logic — a zero-knowledge proof):

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

This `π` is the single frontier component. It is isolated behind a typed interface `trait ShieldedProof { fn prove(...); fn verify(...); }` so the accounting (tree, nullifier set, commitments, balance homomorphism, ledger integration) is fully implementable and **verified now**, while the proof backend is a pluggable, honestly-tagged **[P]** — the target backend is a lattice ZK system (LNP-class); a transparent hash-based (STARK) backend is the conservative fallback (larger proofs, only symmetric-crypto assumptions). **No new hardness is invented** — both backends compose published PQ ZK constructions (ХОЛАРХ Ω0 honesty).

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
- **Governance [P].** Auctions/pricing (Harberger-style or fixed) to prevent squatting; a demand-controlled price is the ХОЛАРХ **DL — Regulation** channel (the same Lyapunov demand controller the network's `roles::assign` already uses — reuse, not reinvention).
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

ANGELOS is therefore an **application composition [C]**, not new cryptography: a PQ double-ratchet (A/E aspects — articulation of messages into sealed interiority, the **AE — Apperception** channel) carried over DIAULOS-over-NYX to a CALYPSO-computed rendezvous, addressed by an ONOMA name, with offline messages parked in L4 mailboxes and OBOLOS-payable premium features (storage, priority). Metadata privacy — the property Session most struggles with — is delivered by the mixnet substrate, not patched on. **[P]** is only the messenger *product* (UX, group messaging, the mailbox protocol); the anonymity is inherited.

---

## §7. HERMES — post-quantum threshold cross-chain {#hermes}

*Name:* Greek **Ἑρμῆς** (Hermes) — god of boundaries, travel, commerce, and messengers; the crosser of thresholds.

Cross-chain is a **federation** (ХОЛАРХ §10: beyond depth 2, federate — do not stack a third tier), realized by FANOS's own threshold cells as the trust-minimized bridge validators. The idea-storm, synthesized to a decision:

- **Rejected — light-client bridges:** verifying a foreign chain's consensus inside FANOS requires that chain's (often non-PQ) signatures, importing its trust assumptions and its quantum-fragility. A PQ platform must not anchor its bridge on classical ECDSA.
- **Chosen — threshold-attested custody + HTLC atomic swaps [P]:** a FANOS cell (its BFT quorum + a threshold signature, both already built: `fanos-vrf` DKG, `fanos-aphantos` threshold) acts as a decentralized notary/custodian. Two modes: (1) **atomic swaps** via PQ hash-locked contracts (HTLCs with a PQ hash — trustless, no custody, for chains that support hashlocks); (2) **threshold custody** for chains that don't — the cell's quorum jointly controls a foreign address, and a cross-chain transfer is a TAXIS-attested event (the `crosscell` receipt machinery, generalized to a foreign endpoint). Byzantine safety of the bridge = the cell's BFT bound (`f < n/3`), the same guarantee as consensus.
- **The synthesis:** FANOS's cells are *already* threshold-signing BFT committees with an unbiasable beacon and cross-cell receipts. HERMES is the smallest possible new surface: point that machinery at a foreign endpoint. Cross-chain becomes an instance of cross-*cell*, where the far cell is another chain. **[P]** — the foreign adapters and the economic security (bonding, slashing on equivocated attestations, reusing `fanos-taxis::incentive`) are the work.

---

## §8. The transformation roadmap — sequential, verified, exemplary {#roadmap}

The transformation proceeds in verified increments; each lands green (workspace tests + `clippy --all-targets -D warnings`) before the next, per the standing discipline. Ordered by *foundational leverage* (what the most other things need):

1. **T1 · TAXIS live (L8)** — ✅ substantially done this cycle: consensus over real QUIC, the App-overlay receive seam, live checkpoint publishing. Residual: full two-cell parent-attests-child loop; `Node::start` config.
2. **T2 · The value tier foundation** — the OBOLOS accounting core (note, commitment tree, nullifier set, lattice value-commitment, balance homomorphism) as a new crate `fanos-obolos`, with `ShieldedProof` as a typed interface and a first verifiable backend. *The crown-jewel foundation, fully verified; the frontier proof isolated and tagged.*
3. **T3 · DROMOS (L9)** — the hybrid state machine (transparent accounts + shielded pool under one `state_root`) as a TAXIS `StateMachine`, then the parallel scheduler with a proven-deterministic serialization.
4. **T4 · ONOMA-domains + ANGELOS (L11)** — currency-bought naming on the ledger; the messenger composition over the existing anonymity organs.
5. **T5 · HERMES (L12)** — the threshold cross-chain, atomic-swap mode first (trustless), custody mode second.
6. **Throughout · the ХОЛАРХ gate** — a Γ-calculator (`architecture/` companion) that, given the declared platform budgets, computes `P/R/Φ/D` and the σ-panel, so "the platform is in the viability window" is a CI-checked number, not a claim (ХОЛАРХ Ω4/Ω7). This is the platform's release gate, the way `fanos_verify.py` is the network's.

Every subsystem names all seven aspects (Ω2), declares its typed cross-block contracts (Ω9, with a CALM class on each consistency contract), and carries a formal representation on its heavy L-contracts (the shielded-proof soundness, the consensus safety — Ω5).

---

## §9. Honest limits, falsifiers, and the single largest risk {#limits}

Following ХОЛАРХ §19 — a specification that declares itself perfect refutes itself. The load-bearing honesty:

- **The post-quantum shielded proof (§4.3) is the single largest [P]/[H].** Practical PQ zero-knowledge for the full shielded statement is frontier work; the platform's *untraceability guarantee* rests on it. It is scoped behind one interface, has a conservative transparent-STARK fallback, and is never claimed as done. If PQ ZK for this statement proves impractical at platform scale, the fallback is a Monero-class **PQ ring signature** over a bounded ring (a strictly weaker but still-PQ anonymity set) — a documented retreat, the ХОЛАРХ V4 *differentiation* (a second mode to fall back to) applied to the crypto itself.
- **"High-speed L1" is a program, not a benchmark yet.** The parallel-execution determinism and cross-shard atomicity (§3.4) must be built and measured; the geometry *enables* Solana-class scaling but does not deliver it for free.
- **The Γ-profile numbers (§1.2) are a [C] construction over declared budgets**, not a measurement of a running platform — exactly the ХОЛАРХ honesty class. The viability *thresholds* are theorems; that the platform's budgets deserve them is validated by coherence-of-consequences until there is field data.
- **Aspect attributions are judgments [И].** Whether the OBOLOS proof is L-work or E-work, whether DROMOS's scheduler is D or DL, are arguable model decisions; the vocabulary makes them arguable, not certain.
- **Falsifiers, as targets:** (1) exhibit a platform dependency no aspect-pair types (breaks §1); (2) exhibit a bona-fide Γ-assembly of the platform that is viable yet violates the four-invariant conjunction (breaks the gate); (3) demonstrate the PQ shielded pool is unrealizable at parameters giving both soundness and platform-scale performance (forces the §9 retreat, honestly).

**What this document does not claim:** it does not claim the platform is built (it is the blueprint); it does not claim new cryptographic hardness (it composes vetted PQ primitives and isolates the one frontier proof); and it does not claim the ХОЛАРХ verdict is a measurement (it is a construction over declared budgets, to be recomputed as the code lands). The transformation is sequential, verified, and honest at every step — the standing discipline, applied to a platform.
