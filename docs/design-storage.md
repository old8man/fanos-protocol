# THESAUROS — the FANOS content-storage platform (design)

> **THESAUROS** (Greek θησαυρός, "storehouse, treasury") is the platform's content-storage organ: an
> advanced, post-quantum, monetized IPFS analog built *on top of* the existing L4 projective-LRC erasure
> store, not beside it. It adds three things the substrate lacks — **immutable content addressing**
> (content-addressed-by-value objects and Merkle manifests), a **proof of retrievability** (a cheap,
> derived, beacon-driven audit that a provider still holds what it was paid to hold), and a **capacity
> market** (providers earn OBOLOS currency by serving the `Storage` role; consumers pay to store) — and
> wires them to the messenger, whose attachments and mailboxes are its first tenant.
>
> Status: **built and verified** (`fanos-thesauros` + the DROMOS `TAG_STORAGE` arm), the crate's wire formats
> pinned in `conformance/vectors/thesauros.json` and the market's audit/incentive dynamics exercised in
> `fanos-sim/tests/thesauros_market.rs`. The L4 substrate it builds on is `[T]` (`spec/protocol.md` §L4); the
> content model, proof-of-retrievability, and market state machine are **built** (the PoR soundness is `[T]`, a
> derived bound, §5); the transparent-token market is live on the ledger; **shielded-payment** deals inherit
> OBOLOS's `[P]` frontier. Ontologically an **O — Foundation** organ, per `spec/platform.md` §1.1. Residual
> hardening is called out in §10 (the scheduled-audit policy against prover inclusion-timing is the one that
> touches soundness).

## 1. The problem and the goals

The messenger (ANGELOS) must store file attachments, media, and offline mailboxes somewhere; the spec
already says "large blobs land in the L4 erasure store, retrieved anonymously" (`spec/platform.md` §6.3)
but there is no first-class subsystem, no immutable addressing, and — critically — **no economic layer**:
nothing lets a node *earn* by supplying capacity or a user *pay* for durability beyond best-effort
self-healing. THESAUROS closes that. Goals, in priority order:

1. **Solve content storage for the messenger** — content-addressed, encrypted, chunked objects with
   anonymous retrieval; mailboxes as a special case.
2. **Monetize capacity** — a two-sided market: providers earn currency for *proven* storage, consumers
   pay for durability/replication/duration, with payment released *only against a verifiable proof*.
3. **Stay on the platform's grain** — reuse the vetted primitives (§3), honor the ontology (§2), derive
   every threshold (§5), keep content opaque to providers (privacy), and **avoid capital staking** — it
   deanonymizes (`fanos-incentives/src/lib.rs:1`), so enforcement is *pay-per-proof + reputation*, not
   bond-slashing (§6).

Non-goals (v1): a global order-book matching engine (a derived posted price suffices, §6.4); a paid
third-party *retrieval* market (retrieval of content you hold a capability for is served by the LRC line,
§8); reinventing erasure/placement/DA (all inherited, §3).

## 2. Ontological placement (HOLARCH Ω2 — every aspect named)

Persistence is the **O — Foundation** ("Основание": substrate and supply — runtime, transport, **storage**,
stake, budget) aspect at platform scale (`spec/platform.md` §1.1 already files "the L4 erasure store" under
O). THESAUROS is that aspect made first-class. Its typed cross-block (the Ω9 contract) is dominated by four
channels, each a real corpus channel:

- **SD — Persistence** ("форма сквозь процесс: durable-состояние"): the object outlives the write process —
  the Merkle manifest is the durable form.
- **SU — Symmetry** ("репликация… согласованное хэширование"): the `[7,3,4]` LRC replication over the
  projective coordinate ring — inherited verbatim.
- **OU — Wholeness** ("доступность данных"): data availability — the DA sampler is the availability oracle
  and the audit's engine.
- **SE — Representation** ("индексы, кэши"): the manifest/index that resolves a name to a CID to shards.
- **EO — Immanence** ("data locality") / **E — Interiority**: content is **sealed before it enters the
  store**, so providers hold opaque ciphertext and retrieval is anonymous — the privacy tint.

The seven-aspect budget (Ω2: a zero is a decision, not an omission):

| Aspect | THESAUROS content |
|---|---|
| **A** Articulation | the `Put`/`Get`/`OpenDeal`/`Prove` intake; challenge ingestion |
| **S** Structure | the CID, the Merkle manifest DAG, the `Deal` and `ShardCommitment` records |
| **D** Dynamics | the chunk→encode→place pipeline; the challenge→response→settle audit loop |
| **L** Logic | the storage law: escrow releases **iff** a retrievability proof verifies; a missed proof pays nothing and decays reputation — anti-domination (§6): the market accounting must not eat anonymity (V2) |
| **E** Interiority | content is encrypted at the edge; the store never sees plaintext |
| **O** Foundation *(dominant)* | the erasure substrate, capacity, the escrow, data availability |
| **U** Unity | the deal registry + name→CID resolution (a `DescriptorKind::Storage`) |

This budget (O-dominant, four strong S/O/E cross-channels) keeps the subsystem inside the viability window
(distinct, not a mud-ball V1; not consensus-dominated V2; integrated V3; degradable V4 — the LRC's local
repair is the degraded mode).

## 3. What THESAUROS inherits (and must not reinvent)

The L4 substrate is `[T]` and exhaustively tested; THESAUROS calls it, never re-implements it.

| Inherited primitive | Where | THESAUROS use |
|---|---|---|
| `[7,3,4]` Fano-XOR erasure codec (N=7, K=3, 2.33× redundancy, ≤3-loss tolerance) | `fanos-code::erasure` | shard every chunk |
| Coordinate placement `MapToPoint(H_storage(key))` → q+1 replica lines (Maekawa quorums) | `fanos-primitives::maptopoint`, `fanos-core::routing` | where each shard lives |
| DA sampling — each Fano line a sample, `(1/7)^k` soundness, unpredictable `splitmix64` seeding | `fanos-code::da` | the audit's sampling engine |
| Mutable LWW-by-version key→value store (`on_put`/`on_get`/`on_sample`/`distribute_shards`) | `fanos-runtime::overlay::Store` | the raw put/get transport |
| `Role::Storage`, VRF `CapabilityDescriptor{offered, weight}`, `assign`, `Reputation::observe` | `fanos-core::roles` | provider identity + selection + the enforcement signal |
| Weighted-HRW provider selection over a signed roster | `fanos-calypso::balance` | pick a provider ∝ advertised capacity |
| `TokenLedger` (`apply`/`credit`/`move_system`), keyless-sink proof-gated release | `fanos-dromos::token`, `hybrid::apply_shielded` | the escrow + pay-per-proof rails |
| `HybridLedger` tag dispatch + `StateMachine` | `fanos-dromos::hybrid`, `fanos-taxis::state` | carry the market as `TAG_STORAGE` |
| PQ-VRF epoch beacon | (coordinate/beacon layer) | drive unpredictable audit challenges |

The one genuinely greenfield cryptographic component is the **proof of retrievability** (§5) — the research
confirmed none exists. Everything else is composition, per the platform's Ω0 ("novelty in composition, not
hardness").

## 4. The content model — immutable, content-addressed, encrypted

The substrate is a *mutable* key→value store; IPFS-class content addressing is an *immutable* discipline
layered on top, at zero engine cost (the store key is arbitrary bytes).

**Leaves, chunks, CIDs.** An object's ciphertext is split into fixed-size **leaves** (`LEAF = 4 KiB`) and a
BLAKE3 **Merkle tree** is built over them; the **content id** `CID = MerkleRoot` (32 bytes,
domain-separated leaf/node labels `FANOS-v1/thesauros-leaf`, `…-node`). This single object is load-bearing
twice over: it is the **content address** (fetch by CID, recompute the root, verify — self-certifying) *and*
the **storage commitment** the proof-of-retrievability challenges (§5). One Merkle root, two duties.

**Chunks and manifests.** Objects larger than one chunk (`CHUNK = 256 KiB`) are split into chunks, each
stored under its own CID; a **manifest** lists `(chunk CID, length)` in order, is itself an object, and its
CID is the object handle — an IPFS-UnixFS-style Merkle DAG, but every node is a PoR-checkable Merkle root.

**Encrypt-then-store.** The caller seals the object under a fresh symmetric key `K` (the shared
ChaCha20-Poly1305 AEAD) *before* chunking, so the store holds only ciphertext — providers cannot read
content, and the E/privacy budget is honored. `K` travels out-of-band (inside an E2E-encrypted ANGELOS
message, §8). Default is a fresh `K` (private, no cross-user dedup); an opt-in **convergent** mode
(`K = H(content)`) is offered for public content where dedup is wanted — the caller's explicit trade of
privacy for dedup.

**Mutable names over immutable content.** Immutable CIDs + a mutable pointer is the clean split: a
`DescriptorKind::Storage` in the DROMOS name registry (`fanos-dromos::naming`) maps a stable name → current
CID (LWW, owner-key-updated), bought/renewed in currency like any name.

**Placement** is inherited unchanged: a chunk at CID lives on the q+1 line-nodes through
`MapToPoint(H_storage(CID))`, `[7,3,4]`-coded — computable by any party from `(CID, membership view)`,
which is exactly what an auditor needs to know *who* owes a shard.

## 5. Proof of retrievability — the derived audit `[T]`

The market must convince the network that a paid provider still holds a chunk, cheaply, without the verifier
holding the chunk. THESAUROS uses **Merkle spot-checks** (Storj/Sia-class), reusing the DA sampler's
unpredictable seeding and the `pow`-style challenge/verify shape — *not* Filecoin PoRep/PoSt (no global
proving treadmill; the erasure layer already gives durability, the proof only needs to detect deletion).

**Commitment.** At deal open the chunk's `CID = MerkleRoot(leaves)` (from §4) is recorded on-ledger — no
extra commitment; the content address *is* the commitment.

**Challenge.** At audit epoch `t`, the public PQ-VRF beacon yields an unpredictable seed; expand it (the
`da::sample_lines` construction) to `k` distinct leaf indices `i₁…i_k ∈ [0, m)` where `m = CHUNK/LEAF = 64`.
Unpredictable ⇒ a provider cannot pre-retain only the queried leaves.

**Response & verify.** The provider returns the `k` leaves and their Merkle authentication paths; the
verifier (any node, or the on-ledger `apply` arm) checks every path against the committed `CID`. Pass ⇔ all
`k` verify.

**Soundness (derived — no magic constant).** Suppose a cheating provider retains only a fraction `ρ` of the
`m` leaves. Each independent random challenge lands on a retained leaf with probability `ρ`, so it passes all
`k` with probability at most `ρ^k` (with-replacement bound; sampling without replacement is tighter). To
catch any provider missing at least a tolerated fraction `f_tol` (i.e. `ρ ≤ ρ_min = 1 − f_tol`) with
audit-soundness `λ` bits (escape probability `≤ 2^−λ` per audit):

```
ρ_min^k ≤ 2^−λ   ⟹   k ≥  λ · ln 2 / ( − ln ρ_min )  =  λ·ln2 / ( −ln(1 − f_tol) )
```

`k` is a **function of the security parameters `(λ, f_tol)`**, computed, not chosen. Worked points (leaf
count `k`):

| `f_tol` | `λ = 20` | `λ = 30` | `λ = 40` |
|---|---|---|---|
| 10 % | 132 | 198 | 264 |
| 1 % | 1 380 | 2 070 | 2 759 |
| 0.1 % | 13 857 | 20 785 | 27 713 |

**Two-tier audit (cost control).** Returning `k` full 4 KiB leaves is large (`k=198` ⇒ ~0.8 MiB). So audits
are two-tier, both beacon-driven: frequent cheap **possession** checks return only leaf *hashes* + paths
(catches wholesale deletion — the common failure), and rare **retrieval** checks pull full leaves (or the
whole chunk) to prove the bytes are actually served. Retrievability of the *object* rests on the erasure
layer: `f_tol` is set so a passing provider set keeps ≥ K=3 good shards per chunk with the target margin, so
the audit's job is to keep the LRC's loss budget from silently eroding, not to re-prove reconstruction.

## 6. The market — escrowed, pay-per-proof, reputation-enforced

Carried as a new `HybridLedger` tag `TAG_STORAGE = 0x04` (the fifth alongside transparent/shielded/name/
shield), with a `StorageMarket` sub-state whose root folds into the hybrid `state_root` — no consensus
change, the identical shape the four existing tags follow.

### 6.1 Deal lifecycle (a sans-I/O state machine)

```
Open ──fund escrow + provider accepts──▶ Active ──each epoch: audit──▶ (pass ⇒ pay slice)
                                            │                          (fail/timeout ⇒ pay nothing, decay rep)
                                            └── D epochs of passes ──▶ Completed (escrow drained, name resolvable)
                                            └── faulted / expired ───▶ Closed (unproven escrow refunded, re-provision)
```

1. **Open.** The consumer submits `OpenDeal{ CID, size, duration D, replication r, λ, f_tol, price P,
   providers }` and funds `P` into a keyless `STORAGE_ESCROW` sink via a `SignedTransfer` (settled by
   `TokenLedger::apply`, using the name-registry's validate→settle→commit ordering so a rejected open never
   moves money). Providers are drawn from the `Role::Storage` roster by weighted HRW (§7).
2. **Active / audit.** Each epoch the beacon drives a challenge (§5); the provider's `ProveStorage` response
   is verified inside the `apply` arm. **On pass**, the epoch's slice `P/D` is released to the provider via
   the keyless `move_system` — the exact `apply_shielded` idiom ("value leaves a keyless sink only when a
   proof verifies"). **On fail/timeout**, nothing is released and `Reputation::observe(provider, false)` is
   fed to the role layer.
3. **Close.** After `D` passing epochs the deal is `Completed`. If faulted or expired, unproven escrow is
   refunded to the consumer and the shard is re-provisioned to a fresh provider (self-healing already
   regenerates the bytes via the LRC; the market just re-lets the deal).

Payment **in arrears** (release *after* each passing audit) is the crux: a provider that never proves earns
nothing, so no up-front trust and no bond are needed.

### 6.2 Incentive compatibility without staking (the platform-grain correction)

FANOS deliberately forbids capital staking (it binds identity to capital and deanonymizes). So THESAUROS
does **not** slash a bond; enforcement is three aligned forces:

- **Pay-per-proof in arrears** — a non-proving provider's payoff is `0`.
- **Reputation decay** — a failed audit multiplicatively decays the provider's `effective_weight`
  (`Reputation::observe`, fast decay / slow recovery), costing it *future* assignments and income.
- **Consumer refund** — unproven epochs are refunded, so the consumer never overpays.

Honest per-epoch payoff is `p − c` with `p = P/D` the slice and `c` the true storage+bandwidth cost;
cheating (store nothing) yields `0` payment minus the reputation loss. Honest strictly dominates iff
`p > c` — exactly the `covers_cost` condition `R ≥ c` the TAXIS incentive layer already formalizes
(`fanos-taxis::incentive::RewardParams::covers_cost`), reused here with the storage reward in place of the
validator fee. No capital is ever at risk, so anonymity is preserved. (Partial cheating — retain `ρ < 1` to
save cost — is caught because §5 sets `k` so `1 − ρ^k ≈ 1` for any `ρ ≤ ρ_min`, so the expected lost income
exceeds the saved cost.)

### 6.3 Anonymity of the deal (the V2 anti-domination guard)

The deal record is public ledger accounting, a linkage surface. Three mitigations keep the market from
eating anonymity: content is **opaque ciphertext** (providers/observers learn nothing of it); the deal
payment can be a **shielded** OBOLOS unshield into the escrow (consumer unlinkable) or paid in anonymous
credits; and the consumer account in a deal may be a **fresh throwaway** derived per deal. The honest limit
(§10): un-shielded deal metadata (size, timing, provider set) remains an analysis surface — shielding the
payment is recommended, and bulk-content confidentiality is the guarantee, not deal-graph privacy.

### 6.4 Pricing — derived, not a knob

v1 uses a **utilization bonding curve**: the unit price per byte-epoch rises convexly with the provider
set's utilization `U ∈ [0,1)`, `price(U) = c_floor / (1 − U)` — it rations scarce capacity and → ∞ as the
set fills, with `c_floor` the marginal cost anchor (the same `covers_cost` floor). The consumer's offered
`P` must clear `price(U)·size·D`; providers accept deals at or above their own cost. A uniform-price
**double auction** (providers post asks, consumers bids, clear at the marginal price) is the documented
evolution when liquidity warrants — tied to the same TAXIS L7 equilibrium so storage and consensus rewards
share one economic model. Price is an *output* of supply and demand, never a hardcoded constant.

## 7. Provider selection and roles

No new identity machinery: a storage provider already advertises
`Capability{ offered: Role::Storage, weight }` via a VRF-signed `CapabilityDescriptor`, is chosen by the
beacon-weighted `assign`, and is reputation-weighted. THESAUROS adds only the **reward loop**: feed each
audit's pass/fail into `Reputation::observe`, and select the deal's provider set by weighted HRW over the
`Storage`-role roster (∝ advertised capacity, with health-aware failover) — the exact `balance::
select_instance` pattern. A provider's `weight` (capacity class) sets its share of assignments and thus of
market income.

## 8. ANGELOS integration (the first tenant)

- **Attachment send:** seal the file under a fresh `K` → `thesauros.put(ciphertext)` → `CID`; send a
  message carrying `{ CID, K, size, media-type }` (a typed content descriptor, itself E2E-encrypted).
  **Receive:** `thesauros.get(CID)` → decrypt with `K`. Large media chunked; the manifest CID is the handle.
- **Mailboxes unified:** offline store-and-forward messages are already L4 objects; a mailbox message *is* a
  THESAUROS object under a short-TTL deal — one storage model for attachments and mailboxes.
- **Community/channel files:** a `CID` plus a capability token signed by the community key gates retrieval at
  the channel boundary (the §6.3 Discord-class capability model), so a file shared in a channel is fetched
  by members only.

## 9. Crate plan — `fanos-thesauros`

A `no_std` core crate, sans-I/O like `ConsensusEngine`/`HybridLedger`:

- `content` — leaf/chunk splitting, the BLAKE3 Merkle tree, `Cid`, manifest encode/decode.
- `por` — `commit` (= the CID), `challenge(cid, beacon_seed, k)`, `prove(chunk, indices)`,
  `verify(cid, challenge, response)`; the derived `k(λ, f_tol)`.
- `market` — the `Deal` record, the `StorageMarket` sub-state and its `StateMachine` semantics (a
  `TAG_STORAGE` arm folded into `HybridLedger`), the escrow/`move_system` settlement, the pricing curve.
- Payments via `fanos-dromos`; placement/erasure/DA via `fanos-code`/`fanos-runtime`; roles/reputation via
  `fanos-core`; the beacon via the coordinate layer.
- **Conformance vectors** (`conformance/vectors/thesauros.json`): the CID/Merkle construction, the manifest
  layout, and a worked PoR challenge/response — language-agnostic, so other implementations interoperate.
- **Simulator scenarios** (`fanos-sim`, per the SecOps directive): provider churn → LRC repair; a cheating
  provider failing audits → reputation decay + re-provision; market price under load; retrieval latency;
  an adversary withholding the lone external DA line.

## 10. Honest limits, falsifiers, status

- **PoR proves possession of committed bytes, not global retrievability** `[T→C]`: the `k(λ,f_tol)` bound is
  exact for the spot-check (and holds empirically — `fanos-sim/tests/thesauros_market.rs` measures a
  >10%-missing provider caught >95% of the time, on the hypergeometric theory), but end-to-end "the object can
  be reconstructed" rests on the inherited LRC loss budget; `f_tol` must be set against the LRC's ≤3-loss
  tolerance (the redundancy-headline caveat in `erasure.rs` must be reconciled first).
- **Scheduled audits vs prover inclusion-timing** `[C]` — the one built-path soundness residual: the audit beacon
  is now the consensus-committed parent hash (ungrindable by the proposer, wired through
  `StateMachine::set_audit_beacon`), but a *provider* still chooses when to submit its `Prove`, so it could wait
  for a beacon that happens to challenge only leaves it kept. Closing it fully means binding each epoch to a
  **scheduled height** and requiring the proof for that height's beacon (a market-policy layer over the built
  arm), so the provider cannot choose the challenge.
- **Deal-graph privacy is weaker than content privacy** `[C]` (§6.3): shield the payment; bulk content is
  the strong guarantee.
- **Shielded payment inherits OBOLOS's `[P]` frontier**: transparent-token deals work today; shielded deals
  wait on the PQ-ZK proof backend.
- **q=2-only codec** `[C]`: the erasure codec is Fano-specific; larger-`q` LRC is spec-`[T]` but not yet in
  the byte codec — THESAUROS large objects scale by *sharding across many base cells*, not a bigger single
  code.
- **Falsifiers, as targets:** (1) exhibit a provider that passes the audit with soundness `λ` while holding
  fewer than `ρ_min·m` leaves (breaks §5); (2) exhibit a profitable cheating strategy under pay-per-proof +
  reputation with `p > c` (breaks §6.2); (3) show the deal metadata deanonymizes a consumer whose payment
  was shielded (breaks §6.3).

## References

- `spec/protocol.md` §L4 (the inherited store), §2 (content addressing); `spec/platform.md` §1.1 (O-Foundation),
  §6.3 (messenger files), §4 (OBOLOS).
- `holarch.md` §4–§6 (aspects, channels, viability), §16 (the L-machine).
- Crates: `fanos-code` (erasure/DA), `fanos-runtime::overlay` (the store), `fanos-core::roles`,
  `fanos-dromos::{token,hybrid,naming}`, `fanos-calypso::balance`, `fanos-taxis::incentive`.
- Landscape synthesized from IPFS/libp2p (content addressing, DAG), Filecoin (PoRep/PoSt — rejected as too
  heavy), Storj/Sia (Merkle audit — adopted), Arweave (endowment — noted for permanent-storage deals).
