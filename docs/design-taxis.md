# TAXIS — the FANOS-native BFT blockchain (spec Part X.1)

> **TAXIS** (τάξις, "order / arrangement") is FANOS's consensus-ordering and ledger layer — the concrete
> realization of spec **§10.1 "A next-generation blockchain"** and roadmap milestone **M7**. It does **not**
> invent a new consensus; it *derives* one from the projective geometry already load-bearing everywhere else
> in FANOS, and composes the primitives that already exist (DA sampling, projective-LRC erasure, the epoch
> beacon, threshold sealing, VOPRF credits, hybrid-PQ signatures, the wire codec). This document is the
> derivation — written **before** the code, per the standing "crystallize before implementing" directive.

Everything here is math-grounded: no magic thresholds, no ad-hoc quorum sizes. Each parameter is either forced
by a theorem below or is the honest tunable it is labelled as.

---

## 1. What the spec fixes (§10.1) — and what we must derive

The spec pins five structural identities and leaves the protocol to the implementation:

1. **Validator committees = quorum-lines [T].** Any two committees intersect (Maekawa) ⇒ BFT with structural
   committee selection; rotation by the beacon; no validator cartels (the centrality cap `(q+1)/N`).
2. **Sharding = cells; cross-shard = bridge nodes** (line intersections) — deterministic, balanced.
3. **Data-availability sampling = checks along lines** (Steiner coverage); erasure code = the projective LRC.
4. **Innate randomness beacon (L3)** — honest leader election / lotteries.
5. **Anti-MEV = threshold encryption of a line's mempool (t-of-(q+1))** — tx contents hidden until inclusion.

The open questions the implementation must answer rigorously: *what is the finality quorum and how many
Byzantine validators does a cell tolerate?* *How exactly does "committees = lines" become a safe+live BFT?*
*How does the encrypted mempool prevent MEV without breaking liveness?* *How does DA sampling gate finality?*

---

## 2. The consensus domain is one projective cell — and it is a PBFT quorum system

The consensus runs **inside a cell** = the finite projective plane `PG(2,q)`, with `n = q² + q + 1` nodes
(validators), `n` lines, each line carrying `q+1` points, each point on `q+1` lines, any two lines meeting in
exactly one point (the dual incidence, `fanos-geometry::dual_any_two_lines_intersect`, V1). The reference cell
is the Fano plane `q = 2`: `n = 7`, lines of `3`, the Steiner system `S(2,3,7)`.

### 2.1 Theorem (a cell is a Byzantine quorum system).

Model the `n` validators with a PBFT-class **quorum system**: a *quorum* is any set of
`Q = ⌈(n + f + 1)/2⌉` validators, tolerating `f = ⌊(n−1)/3⌋` Byzantine faults. This is a *masking quorum
system* — it satisfies the two properties consensus needs:

- **Safety (consistency).** Any two quorums intersect in `2Q − n ≥ f + 1` validators, so their intersection
  contains **at least one honest** validator. An honest validator never double-votes within a round, so two
  conflicting blocks can never both gather a quorum certificate. *(Proof: `2Q−n ≥ (n+f+1)−n = f+1`.)*
- **Liveness (availability).** `n − f ≥ Q`, so the honest validators alone always contain a full quorum;
  progress never requires a Byzantine node's vote. *(Proof: `n − f ≥ Q ⇔ n − f ≥ ⌈(n+f+1)/2⌉`, which holds
  for all `f ≤ ⌊(n−1)/3⌋`.)*

Both are verified for every prime-power cell `q ∈ {2,3,4,5,7,8,9,11,13,…}` in `consensus::tests`.

### 2.2 Corollary (tight cells). For `q ≢ 1 (mod 3)`, `n = q²+q+1 ≡ 1 (mod 3)`, so **`n = 3f + 1` exactly**:
the cell is an *optimal, tight* PBFT system with `f = (q²+q)/3` and quorum `Q = 2f + 1`. The reference Fano
cell (`q = 2`) is tight: **`n = 7`, `f = 2`, `Q = 5`** — a genuine BFT tolerating two malicious validators out
of seven. Cells with `q ≡ 1 (mod 3)` (`q = 4, 7, 13, …`, so `n ≡ 0 mod 3`) are still valid quorum systems via
the general `Q = ⌈(n+f+1)/2⌉`; they are simply not tight. *(The identity `n ≡ 1 (mod 3) ⇔ q ≢ 1 (mod 3)` is
proved in the tests.)*

> **Why this is faithful to "committees = quorum-lines".** The *lines* are the structural committee, sampling,
> and sealing units (§3–§5); the **finality quorum is the `Q`-node BFT threshold**, which is precisely "any
> two committees intersect in an honest validator" lifted from a single pair of lines (which meet in one node —
> a *crash*-tolerant witness) to the Byzantine-robust `f+1`-honest intersection a malicious-validator threat
> model demands. At `q = 2` a bare line-quorum (3 nodes, pairwise intersection 1) is exactly the crash-fault
> special case; TAXIS defaults to the Byzantine `Q`-quorum because a blockchain's validators are adversarial.

---

## 3. Leader election — beacon-driven, cartel-proof

For height `h` (round `r` within it), the proposer is elected from the epoch beacon, which is unbiasable by
construction (the pairing-free threshold-DVRF, §L3):

```
seed(h, r)   = H( "taxis-leader" ‖ SEED(epoch) ‖ h ‖ r )
committee    = MapToLine(seed(h,r))          # a line = the round's structural committee
proposer     = member of `committee` with the smallest H(seed(h,r) ‖ member_coord)
```

Because `SEED(epoch)` is unpredictable until the epoch opens, no validator can pre-aim to be leader at a
chosen height (the same anti-grinding property as coordinate assignment, §8.4). Because leadership rotates over
lines and the plane's point-regularity caps any node's incidence at `(q+1)/N`, **no validator or coalition can
monopolize proposing** — the structural centrality cap *is* the anti-cartel guarantee, not a policy. On
proposer timeout the round increments `r` and re-elects (a fresh line), giving round-robin liveness.

### 3.1 Secret-leader election (SSLE) — the `who` is hidden until it proposes

The election above is *cartel-proof* but not *secret*: within an epoch the `proposer` is a public function of
`SEED(epoch)`, `h`, `r`, so anyone can compute who leads each upcoming height. That is a live attack surface —
Heimbach et al. (USENIX Security 2025) located >15 % of Ethereum validators in the P2P layer with 4 nodes in 3
days; knowing the *single* next proposer lets an adversary pre-position a targeted DoS or bribe against it. The
fix is **secret leader election**: keep the round-0 leader unknown until it actually proposes.

**The derived design — "min-ticket PBFT with a public fallback"** (converged, independently, across three SSLE
research audits: constructions, BFT-liveness, PQ-native-derivation). Round 0 of every height becomes a lottery
over the *same* beacon-elected line `L = MapToLine(seed(h,0))` (its membership is public — the anonymity set is
at most `q+1`):

```
ticket_i(h) = H( "taxis-leader-ticket" ‖ VRF_i(idx) ‖ SEED(epoch) ‖ h ‖ 0 )     # lowest ticket leads
```

where `VRF_i` is validator `i`'s **post-quantum Merkle-VRF** (`fanos-vrf::pqvrf`, an iVRF) at domain index
`idx = h − base`. Every member of `L` proposes (**all-propose**, `p = 1`), attaching its `(VRF output, Merkle
proof)` as a `LeaderWitness` *outside* the hashed header. A replica verifies each witness against the
proposer's **pre-registered** root, ranks the valid proposals by ticket, and after a short collection window
PREPAREs the **lowest**. Rounds `r ≥ 1` fall back to the public deterministic `proposer` of §3 — the pre-SSLE
protocol verbatim — reached by the ordinary view-change on timeout.

**Theorem (SSLE properties).** Under the epoch DVRF beacon's unbiasability and Merkle-VRF full uniqueness:

* **Secrecy / unpredictability.** `ticket_i` is a function of `VRF_i`, whose output no other party can predict
  before member `i` reveals it, and of the beacon, unpredictable before the epoch opens. So before any
  proposal is broadcast the winner is uniform over `L` to every outside observer — an adversary cannot pre-aim
  at *the* next proposer. The anonymity set is exactly `L` (`|L| = q+1`), and this is optimal: the line is
  public, so no consensus-layer scheme can hide the winner in a larger set. The guaranteed benefit is the
  Boneh–Eskandarian–Hanzlik–Greco robustness bound — attacking an `α`-fraction of `L` disrupts a round with
  probability `≤ α`, i.e. targeted-DoS cost is multiplied by `q+1` (a surgical single-proposer strike becomes
  impossible). With all-propose, per-round traffic is symmetric across `L`, removing the who-is-about-to-lead
  timing tell at the protocol layer.
* **Safety (unconditional, unchanged).** Leader selection lives entirely in the *pacemaker*; the vote logic is
  byte-for-byte §4. HotStuff's theorem — safety holds even under a Pacemaker that proposes arbitrarily — applies
  verbatim. Two commit certificates at one height still force two `Q`-quorums to intersect in an honest
  validator who prepared ≤ 1 value per view (§2.1), so no two blocks commit. Min-ticket, ties, vote-splits, and
  withheld/late tickets can therefore only *waste a view*, never fork. A member cannot grind its ticket (see
  PQ-soundness) and cannot double-prepare (the equivocation slash, §8, still bites), so it PREPAREs exactly the
  one min per round 0.
* **Liveness.** All-propose makes empty rounds **structurally impossible** (`q+1 ≥ 3` tickets always exist),
  eliminating the 30–37 % empty-slot residue that thresholded (`p<1`) sortition suffers at small committees. The
  collection window converges honest replicas on a common min: with the early-exit (all `q+1` proposals seen)
  the happy path prepares with no added wait, and its tick-bounded expiry (`Δ_prio`, one tick — *not* a full
  round timeout) covers a slow/down member. Post-GST every honest replica holds the identical ticket set, hence
  the identical min, hence a `Q`-quorum on the winner whenever it is honest (probability `≥ (n−f)/n`). Otherwise
  one timeout drops to the public-leader ladder, live by the classical argument. So liveness never degrades
  *below* today's baseline; SSLE only adds a fast secret-leader path on top of it.

**PQ-soundness — why the ticket is a Merkle-VRF and never `H(signature)`.** The min-ticket rule is sound only
if the ticket satisfies RFC 9381 *full uniqueness* (no party, even with malicious keygen, can produce two
verifying outputs for one input). A hash of the validator's hybrid signature does **not**: ML-DSA (FIPS 204) is
Fiat–Shamir-with-aborts, its verifier accepts many signatures per message, and its "deterministic" mode is an
unverifiable signer-side convention — so a Byzantine member *grinds* signatures offline and submits the one
minimizing `H(σ)`, winning the argmin with probability `≈ k/(k+n−1)` (~96 % at `k=100`, `n=5`). This is full
rigging, not bias, and it also sinks Falcon (randomized) and even XMSS (X-VRF's uniqueness proof was broken at
FC 2024). The Merkle-VRF sidesteps all of it: its output is *committed* by the pre-registered Merkle root, so
exactly one output verifies per index — uniqueness by construction, from symmetric-hash assumptions only.

**Bounded domain, per-epoch re-registration.** The Merkle-VRF domain is `2^height` leaves (`height ≤ 24`), so
the index is **relative** (`h − base`) and the roots are re-registered each epoch over a fresh bounded domain —
an absolute-height index would eventually exhaust the tree (OOM). Re-registration doubles as the anti-grinding
*fence*: a validator's root is fixed strictly before the beacon it is used with, so it cannot choose a key to
bias its ticket. The ticket hash still binds the absolute `h`, so tickets never collide across epochs that
reuse a relative index.

**Honest scope.** This is *secret-until-proposal-broadcast* within a public `q+1` line — not whole-validator-set
SSLE. Whole-set schemes (Whisk shuffles, Sassafras ring-VRFs) are non-PQ; PQ true-SSLE (Qelect, BPR23) needs
MB-scale multi-round shuffles or `G`-out-of-`G` synchronous tFHE whose single-crash abort is a *worse* liveness
cliff than the empty-slot residue it removes — strictly dominated at `q+1 ≤ 8`, where the line is public anyway.
The engine keeps a clean seam (`enable_sortition`; `None` ⇒ the public leader) so a future PQ batch ring-VRF
ticket layer can replace the per-view lottery without touching the BFT core. Implementation: `committee.rs`
(`leader_ticket` / `verify_leader_ticket`), `block.rs` (`LeaderWitness`), `consensus.rs`
(`maybe_propose` / `on_propose` / the collection window), driven end-to-end in `tests/consensus_sim.rs` and over
real QUIC in `taxis_quic.rs`.

---

## 4. The round protocol (PBFT-class, three phases + reveal)

A height commits one block. Votes are hybrid-PQ-signed (Ed25519 + ML-DSA-65) and carry `(height, round,
block_hash)`. A **certificate** is a set of `Q` distinct valid signatures over the same tuple.

1. **PROPOSE** — the elected proposer assembles a block from the encrypted mempool (§5), erasure-codes the
   payload with the projective LRC and attaches the DA commitment (§6), links `parent_hash`, and broadcasts a
   signed `Propose{header, sealed_txs, da_commit}`.
2. **PREPARE** — each validator checks: parent is the current head, the proposer is entitled (the correct
   beacon-elected leader; or, under SSLE round 0, any line member whose sortition witness verifies — §3.1), the
   block is well-formed, and **the payload is available** by DA-sampling (§6). If all hold it broadcasts
   `Prepare{h,r,block_hash}` — under SSLE round 0, for the **lowest-ticket** proposal collected in the window.
   A `Q`-quorum of prepares is a **prepared certificate** (`PC`) — the block is *locked*.
3. **COMMIT** — on seeing a `PC`, a validator broadcasts `Commit{h,r,block_hash}`. A `Q`-quorum of commits is a
   **commit certificate** (`CC`) — the block is **final** (irreversible; safety by §2.1).
4. **REVEAL** — once a `CC` exists the block's order is fixed, so the sealing committees release their share
   openings (§5); every node reconstructs the plaintext txs and the state machine applies them **in the
   committed order**.

View-change / round advance follows Tendermint's locking rule: a validator that holds a `PC` for a block only
prepares a conflicting block at a higher round if shown a newer `PC`, which §2.1 makes impossible for two
different blocks at the same height — so safety holds across rounds, and the beacon re-election gives liveness.

---

## 5. Anti-MEV — the threshold-encrypted mempool

MEV (front-running, sandwiching, censorship-for-profit) is possible only if the party choosing *order* can see
tx *contents*. TAXIS removes that visibility, reusing the exact threshold primitive every NYX onion layer uses
(`fanos-aphantos::threshold`: Shamir `t`-of-`(q+1)` with each share sealed under a fresh per-member hybrid KEM
— dealt-and-sealed, no line DKG, §5.2).

- **Submit.** A client seals a tx to the line `L_tx = MapToLine(H(tx_commit ‖ epoch))` — `t`-of-`(q+1)` shares,
  one KEM-sealed to each member of `L_tx`. Into the mempool goes only the **commitment** `tx_commit =
  H(ciphertext)` and the sealed shares. The line is beacon-folded, so the sealing committee is unpredictable
  and rotates each epoch; the sender cannot choose a committee it controls.
- **Order.** The proposer orders blocks over **commitments** — it provably cannot read contents, so it cannot
  front-run, sandwich, or content-censor. (It can only censor *blindly* by omission, which the beacon leader
  rotation and round-robin re-election bound, and which is externally detectable.)
- **Open.** A sealing member releases its opening **only** upon seeing a valid `CC` that includes `tx_commit`
  (order already final ⇒ releasing is MEV-safe) and **never** before (releasing early would leak contents to
  the next proposer). `t` honest members suffice to reconstruct (liveness); `< t` ⇒ the tx is undecryptable,
  dropped, and the sender retries (safe: no partial leak, no stuck chain).

This is a threshold-encrypted mempool (Shutter/Ferveo-class) obtained *for free* from a primitive already in
the tree, with the sealing committee chosen by the plane instead of a bespoke committee protocol.

**Security argument (sketch).** Contents are IND-CPA-hidden until `t` members open; a proposer holds `< t`
openings for any line it does not `t`-dominate; the anti-Sybil centrality cap bounds how many of a line's
`q+1` members any coalition holds; therefore ordering is content-blind whenever the sealing line has `< t`
adversarial members — the same `t`-of-`(q+1)` trust already assumed for onion layers. Formalized in §5 tests.

### 5.1 Audit hardening & honest limits (execution layer)

An adversarial review found the *ordering* core sound but the *execution* (REVEAL) path broken; the fixes and
remaining honest limits:

- **Authenticated reveals (fixed CRITICAL).** A `REVEAL` was unauthenticated — anyone could inject a garbage
  share for any `tx_commit`, and reconstruction interpolated through *all* collected shares, so one bad share
  produced a wrong key: an attacker could **censor** a finalized tx (drop it from execution everywhere) or
  **fork executed state** (race which share wins a slot; undetected, since the header carries no state root).
  Now each reveal is **hybrid-PQ-signed** by the member; a receiver verifies the signature, pins the sender to
  the tx's keyper line and its share `x` to the member's committee position, records first-writer-wins per
  member, and **opens from a `t`-subset whose AEAD tag authenticates** — so a lone Byzantine member's
  validly-signed garbage share cannot poison decryption, and a tx is only skipped once *every* member has
  revealed and none opens.
- **Enforced keyper line (fixed CRITICAL).** "The sender cannot choose a committee it controls" was *described*
  but not *checked*: a tx sealed to the wrong line (or no real committee) could be ordered and then never
  decrypt, stalling execution. Admission now **enforces** `epoch == current`, `line == epoch_seal_line`, and a
  full committee size at both `submit` and `on_propose`.
- **No finalization wedge (fixed HIGH).** A validator that gathered a commit certificate but not the block body
  (async delivery) previously wedged at that height forever. It now records the pending decision and finalizes
  the instant the body arrives.
- **Honest limit — undecryptable-tx liveness.** A tx sealed to the right line but to *garbage* KEM slots yields
  no honest shares (the slots aren't ciphertext-verifiable without opening), so its block's execution pends.
  Ordering/consensus is unaffected; fully-robust deterministic execution under adversarial reveal-withholding
  needs **on-chain decryption-key commitment** (Shutter/Ferveo-style) — a planned upgrade, not yet built. The
  keyper line also tolerates only `t−1` faulty members for anti-MEV *liveness* (2-of-3 ⇒ ≤ 1 on the Fano cell),
  narrower than the cell's `f`.
- **Honest limit — no executed state root.** Consensus commits to block *order*, not to executed *state* (the
  vote/header carry no `state_root`). Adding an executed-state commitment to a later header — so any execution
  divergence becomes a consensus fault rather than a silent fork — is the highest-value structural hardening and
  is future work.

---

## 6. Data availability — sampling gates finality

A proposer must not be able to finalize a block whose data it withholds (else state is unrecoverable). The
block payload is erasure-coded with the **projective LRC** (`[7,3,4]` on the Fano cell) across the cell's
nodes, and **PREPARE is gated on DA sampling** (`fanos-code::da`): before preparing, a validator samples `k`
lines chosen unpredictably from `H(block_hash ‖ SEED(epoch))` and checks each is fully present. By the DA
theorem (`da.rs`): an unavailable value has **≤ 1 external line**, so **two distinct samples detect any
withheld block with certainty**, and `k` independent samples bound the false-available probability by `(1/7)^k`.
A block that fails sampling gets no PREPARE from honest validators ⇒ cannot reach a `PC` ⇒ cannot finalize.
Availability is thus a *precondition of finality*, proven at the cell, not an afterthought.

**Audit note (assurance gap).** In the reference engine the availability bit-mask is supplied by the *driver*
(`on_propose(block, present)`); the engine gates on it but does not itself sample, and the reference wire ships
the whole payload inside the proposal, so real withholding is not yet modelled end-to-end. The header↔payload
binding via the DA commitment is sound (a proposer cannot swap payloads), but the *gating* currently reduces to
"the driver sampled honestly." Making the engine perform/verify sampling itself (or verify a signed
DA-attestation quorum) and shipping headers + sampled shards rather than the whole payload is required to make
withholding a real, in-engine-defeated threat.

---

## 7. Sharding & cross-shard — cells as shards, Maekawa nodes as bridges

Each cell maintains its own shard (chain + state). A transaction touching two shards is carried by a **bridge
node** in both cells — in the hierarchy a node belongs to a parent and a child cell, and any two lines within a
cell meet in one node (Maekawa), giving a deterministic, balanced set of cross-shard coordinators with no
extra overlay. Cross-shard atomicity is a two-phase commit anchored by the bridge: `prepare` (lock + `PC`) in
the source shard, then an inclusion proof (the source `CC`) admitted by the destination shard, `commit` in
both. The reference implementation lands single-cell consensus fully and the cross-shard 2-phase protocol over
two cells in the simulator; deeper hierarchical sharding rides the existing cell-recursion (§L1).

---

## 8. Incentives (ties to L7 / task A2)

Block inclusion is paid with an **anonymous VOPRF credit** (`fanos-incentives`), context-bound to
`(epoch, cell)` so a credit cannot be replayed across shards or epochs (RFC-9578-style binding, already
implemented). The **incentive *equilibrium*** — proving honest proposing/voting is a Nash equilibrium given
the anti-MEV design removes the MEV profit term — is derived and implemented in the companion note
`docs/design-incentive-equilibrium.md` (task A2). TAXIS exposes the fee/credit hook; A2 supplies the game.

**Audit note (wiring & model scope).** The incentive module is currently an accounting/detection **library**,
not yet wired into the consensus loop: `detect_equivocation`→`SlashEvidence` is sound and unforgeable (you
cannot frame an honest validator), and `collect_fee`/`distribute` are reveal-gated, but the engine's
`accept_vote` does not yet scan stored votes for equivocation, emit slash evidence, or apply fees — so the
slashing the Nash proof assumes (`S>0`) is provable-but-not-operational until wired. The equilibrium model also
scores only *unilateral* deviations against an honest majority; it does not yet cover the `≤ f` **coalition**
the fault model tolerates, nor a **blind censorship-for-profit** term (accepting a bribe to omit a competitor's
tx by omission, which §5's "Order" bullet acknowledges). Both are noted extensions, bounded in practice by
beacon leader rotation and (future) force-inclusion / inclusion-list mechanisms.

---

## 9. Crate layout — `fanos-taxis`

A new leaf crate composing the primitives above (no new crypto, no new geometry):

| Module | Responsibility |
|---|---|
| `params.rs` | cell → `(n, f, Q)` BFT parameters + the §2 theorem tests |
| `committee.rs` | beacon leader election, line-committee selection, the Maekawa cross-shard witness |
| `tx.rs` | `Transaction`, `SealedTx` (threshold-sealed), `tx_commit` |
| `mempool.rs` | the anti-MEV encrypted mempool: seal-on-submit, order-over-commitments, open-on-`CC` |
| `block.rs` | `BlockHeader` / `Block`, hash-linking, the DA commitment |
| `vote.rs` | signed `Vote`, quorum `Certificate` aggregation + verification |
| `consensus.rs` | the sans-I/O `Engine::step` PBFT state machine (propose/prepare/commit/reveal, round advance) |
| `state.rs` | the `StateMachine` trait + a reference account/KV instantiation |
| `chain.rs` | finalized-chain state, head, state root |
| `wire.rs` | `Propose` / `Prepare` / `Commit` / `Reveal` / `DaSample` wire messages (derive the codec) |
| `lib.rs` | assembly + module docs |

**Verification plan (sim):** happy-path single-cell finality; `f`-Byzantine safety (equivocating proposer,
conflicting votes, forged certificate) — no two conflicting `CC`s; liveness under `f` crashes and under proposer
timeout (round advance); anti-MEV (a proposer with `< t` openings cannot read contents / cannot reorder for
profit); DA (a withheld block never finalizes); cross-shard atomic commit over two cells. Everything runs on
the existing sans-I/O engine + sim harness (deterministic), then over real QUIC for a 7-node cell.
