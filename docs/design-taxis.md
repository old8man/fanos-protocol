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

---

## 4. The round protocol (PBFT-class, three phases + reveal)

A height commits one block. Votes are hybrid-PQ-signed (Ed25519 + ML-DSA-65) and carry `(height, round,
block_hash)`. A **certificate** is a set of `Q` distinct valid signatures over the same tuple.

1. **PROPOSE** — the elected proposer assembles a block from the encrypted mempool (§5), erasure-codes the
   payload with the projective LRC and attaches the DA commitment (§6), links `parent_hash`, and broadcasts a
   signed `Propose{header, sealed_txs, da_commit}`.
2. **PREPARE** — each validator checks: parent is the current head, the proposer is the correct beacon-elected
   leader, the block is well-formed, and **the payload is available** by DA-sampling (§6). If all hold it
   broadcasts `Prepare{h,r,block_hash}`. A `Q`-quorum of prepares is a **prepared certificate** (`PC`) — the
   block is *locked*.
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
