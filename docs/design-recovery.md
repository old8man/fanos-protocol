# Below-threshold recovery — partition-safe re-genesis without stake

> Closes audit §4 R-C1 (the instantaneous mass-loss cliff): a Fano cell that loses more than `n − t`
> beacon anchors *at once* freezes its epoch clock permanently, because a `(t, n)` threshold secret is
> **information-theoretically gone** below `t` survivors — no resharing, proactive VSS, CHURP, or DPSS can
> resurrect it (all require ≥ `t` honest current shares to carry the secret forward). This note specifies the
> recovery that *is* possible: a fresh key under a **fencing rule that makes exactly one restart canonical**.

## 0. The impossibility, stated precisely

A FANOS cell's rendezvous/epoch beacon is a pairing-free threshold DVRF over a Shamir/Feldman `(t, n)` sharing
of a group secret `x` (`n = 7`, `t = 4 > n/2`, `fanos-vrf::beacon`). Any `≤ t − 1 = 3` shares reveal **zero
information** about `x` (Shamir perfect secrecy). Therefore:

- **Above threshold (`≥ t` survivors):** the secret is still alive; it can be *proactively reshared* to a new
  roster (`fanos-vrf::reshare`, key-preserving via Lagrange interpolation at 0). This is **partition-safe by
  quorum intersection**: with `t > n/2`, at most one side of any partition can hold `≥ t` shares, so a
  partitioned `≤ 3` minority *cannot* reshare — no competing key can ever exist.
- **Below threshold (`≤ t − 1` survivors):** `x` is unrecoverable. Recovery is **never key-recovery**; it is a
  **fresh DKG** producing a new key `x'`, plus a rule that guarantees **at most one** fresh key becomes
  canonical — otherwise two minority partitions each re-key and the cell forks.

The whole design is the second bullet made safe.

## 1. What the field does (comparative analysis)

| Mechanism | Anti-fork (partition-safety) condition | Liveness cost | FANOS fit |
|---|---|---|---|
| Ethereum inactivity-leak + Casper FFG | accountable safety: two conflicting finalizations ⇒ **≥ 1/3 stake** slashable | no finality while > 1/3 offline; leak drains offline stake ~weeks | anti-fork *is* slashable capital stake — **FANOS forbids staking**; only the "penalize the absent" idea transfers, as reputation |
| Tendermint / CometBFT halt + governance restart | never forks with ≤ 1/3 Byzantine (CP: halts, not forks); restart safety = **social consensus on one `genesis.json`** | halts > 1/3 offline; hours–days of off-chain coordination | the **root-of-hierarchy fallback**; its one weakness (no cryptographic uniqueness) is exactly what generation-fencing fixes |
| Herzberg proactive VSS | mobile adversary < `t` per epoch; a lost share re-issued **only by interpolation from ≥ t holders** | per-epoch refresh; **no recovery below t** | confirms the impossibility; useful *above* `t` to rotate/repair shares |
| CHURP / dynamic-committee DPSS (eprint 2019/017) | hands `(n,t) → (n',t')` via dimension-switching; needs **≥ t honest old members** at handoff | one handoff per churn event; halts below t | best tool for **planned churn** while `≥ t` survive; not a below-t rescue |
| drand / Ferveo epoch re-DKG | beacon round needs `t`-of-`n`; resharing needs a threshold of the *old* group | below t ⇒ beacon halts; old-honest < t ⇒ **fresh DKG, new public key** | same DVRF shape — confirms below `t` the only path is a **fresh DKG under a new generation** |
| **Dfinity IC subnet recovery (CUP + NNS, eprint 2021/339)** | a stalled subnet restarts via an **NNS proposal pinning a state-certified height (Catch-Up Package)** as the single canonical point, then re-keys | subnet halted until the single-writer authority acts | **the deployed analog of this design**: CUP ≙ our **ExecCertificate**, NNS ≙ the **parent cell** |
| Vertical Paxos / etcd `force-new-cluster` | a **single-writer reconfiguration master** stops the old config then starts one successor; etcd *explicitly splits-brain if old members stay alive* ⇒ must be fenced | operator in the loop; unavailability window | this **is** the re-genesis primitive: parent = reconfiguration master, one successor per generation |
| Fencing tokens (Kleppmann) | authority issues **strictly monotonic** tokens; every resource **rejects a writer with token < max-seen** | free; needs a monotonic counter + universal stale-rejection | the mechanism that makes a returning partition **subordinate, not forking** |

**CAP framing (Gilbert–Lynch).** Under partition you get Consistency *or* Availability. The **money/state**
layer (OBOLOS notes, TAXIS `ExecCertificate`s) must be **CP** — a double-spend is irreversible, so it *halts*
rather than fork. The **randomness/beacon** layer has no persistent value and may be
**AP-with-deterministic-reconciliation**. The anti-fork engine on the CP side is **quorum intersection**: any
two `2f+1 = 5`-of-`7` quorums overlap in `≥ 3` nodes (`≥ f+1 = 3` honest), so two conflicting
`ExecCertificate`s are impossible and a `≤ 3` minority *cannot sign one* — the ledger halts safely by
construction, no stake required.

## 2. The FANOS design — single-canonical-generation re-genesis

**Invariant (the linchpin).** For each cell `C` and a strictly-monotonic **generation** `g ∈ ℕ`, **at most one**
re-genesis certificate `RGC(C, g, ·)` is ever validly signed, and every node **rejects any artifact — beacon
round, block, ExecCert — that is tagged, or keyed under a commitment, from a generation `< its highest-seen g`**.
(Vertical-Paxos stop-then-start ∧ Kleppmann fencing ∧ Raft-term monotonicity.) This yields **no fork across a
re-genesis, with no stake.**

Two thresholds, two regimes:

### Regime A — survivors ≥ t (autonomous, partition-safe by quorum intersection)
The auto-trigger (below) fires a **proactive reshare** (`fanos-vrf::reshare`, key-preserving) to the live
survivor roster *before* the set crosses `t`, and reactively while `≥ t` remain. Safe because a partitioned
`≤ 3` group is below `t` and cannot reshare — no competing key can arise. The generation counter (`reshare_gen`)
bumps on each reshare; the beacon value is byte-identical across the handoff (continuity, proven in
`fanos-keygen::beacon` tests).

### Regime B — survivors ≤ t − 1 (authority-gated fresh re-genesis)
1. **Detect + safe-stall.** The auto-trigger sees `< t` live anchors (membership − corroborated `PeerDown`) or a
   stall (no `BeaconReady` for `D` epochs). The `BeaconWindow` (`DEPTH = 3`, `fanos-quic`) keeps the cell
   *joinable* at the last good epoch while frozen — the passive half of R-C1. The active half emits
   `RecoveryNeeded { cell, generation g, epoch, survivors S, last_exec_cert }`.
2. **Authorize.** The **RecoveryAuthority** issues, over the survivors' request,
   `RGC(C, g+1, S, t', anchor = H(last ExecCertificate), epoch_fence e', sig)` — enforcing `g+1 > g`
   (monotone, one per generation) and that `anchor` matches a certificate it accepts. The authority is, in
   priority order:
   - the **parent cell** (a BFT quorum — itself fork-safe by quorum intersection, so it cannot sign two
     conflicting `RGC`s); this is the holarchic recovery path (design-self-organization §4, "a collapsed cell
     hands its residue up for external regeneration", UHM T-148).
   - for the **root cell** (no parent): a **founder/constitution quorum** of long-term PQ identities — a
     weak-subjectivity checkpoint. Recovery at the root cannot be made trustless; it can only be made *fenced
     and single-canonical*. Even a Tendermint-style social restart embeds the monotonic `g` so it is one-per-
     generation.
3. **Re-key.** The named survivors run a **fresh DKG** (`fanos-keygen::DkgNode`, full GJKR with complaint/
   justify) → a new `(t', |S|)` DVRF key. Each survivor installs it at `epoch_fence e'`, generation `g+1`
   (`BeaconNode::rebootstrap`). The old key is abandoned (it is gone anyway).
4. **Fence.** The new commitment *is* the fence: a returning "lost" node's rounds are signed under the old
   commitment and **fail verification against the new one**, so they are rejected automatically; the node
   adopts `RGC(C, g+1, ·)` on receipt and rejoins **subordinated, not forked**. A consumer confirms the new
   commitment when the **first beacon round at `e'` self-authenticates against it** (`verify_and_seed`) — only
   the real survivors, holding shares of the new key, can produce that round, so a replayed authorization paired
   with a forged commitment never commits.

**The anchor unifies with state-sync.** `RGC.anchor = H(last ExecCertificate)` reuses the quorum-signed
executed-state checkpoint built for [state-sync](./design-taxis.md): a survivor proves its provenance (it was
part of the last agreed state) with the same portable, unforgeable object, and a recovering node adopts the
re-genesis and the certified state together.

**Layer split (what is autonomous vs authority-gated):**

| Layer | CAP | Autonomous? | Rule |
|---|---|---|---|
| DVRF beacon / epoch clock | AP + deterministic reconciliation, generation-fenced | **yes** if survivors `≥ t`; below `t` the authority picks the one generation | competing fresh beacons converge to **highest generation**, tie-break = smallest beacon-round hash — at most one per generation |
| Money/state ledger (OBOLOS, TAXIS) | strictly **CP** | **no** | halts below quorum `5` (safe by quorum intersection); resumes **only** under an authority `RGC` anchored on the last `ExecCertificate` |

## 2a. Deployed-system corroboration & refinements (research 2026-07-23)

A five-angle primary-source review (CAP/fencing, proactive/dynamic secret sharing, deployed DKG, censorship)
confirmed the design and sharpened three points:

- **Structural impossibility, not policy (CAP).** Gilbert–Lynch: with `≥ n/2` crash failures the *original*
  configuration "can never again decide anything — only reconfiguration from outside can restore progress." So
  a `≤ 3`-of-7 minority re-keying is Raft's Figure-10 disjoint-majorities fork (3+4 both act). Regime B must
  therefore be *structurally* gated: no valid re-genesis certificate can form without the authority.
  `BeaconNode::rebootstrap` enforces exactly this — it returns `false` unless a configured authority key verifies
  the `RGC`, and the survivors do not hold that key, so they cannot self-authorize.
- **IC CUP + NNS `RecoverSubnet` is the ~1:1 deployed reference.** A Catch-Up Package is a `(n−f)`-of-`n`
  threshold-signed, unique-per-epoch checkpoint carrying "everything a replica needs to begin working, without
  knowing anything about previous epochs" (state-root + beacon material + config). Recovery is an NNS proposal
  pinning `(height, state_hash)` + optional `replacement_nodes`, which triggers `setup_initial_dkg` — a *fresh*
  key on the certified state, never a recovery of the lost shares. FANOS's `ExecCertificate` ≙ CUP and the parent
  `RGC` ≙ `RecoverSubnet`; we adopt the two CUP guarantees explicitly: **uniqueness per height** (the quorum
  signature) and **self-contained resume** (a joiner needs zero history — provided by state-sync).
- **`OldThreshold` downgrade guard (drand).** A resharing config must carry the *old* threshold "to avoid a
  downgrade attack where the number of deals required is less than it should be." FANOS's reshare carries the
  generation + the `contributors.len() ≥ threshold` gate + the `MIN_REGENESIS_THRESHOLD` floor (§3.1), which
  closes the same class.

Two refinements folded into the roadmap (not yet built — the mechanism is correct without them):

1. **Delegation-chain re-keying (the hierarchy extension).** The IC lets a subnet swap 100 % of its nodes *and*
   its key without breaking a client, because verifiers pin only the never-changing *root* key and every subnet
   key is certified inside the root's state tree. FANOS should certify a child cell's new group key inside the
   *parent's* certified state, recursively — so external verifiers pin only an ancestor key and re-genesis is
   free for them. Today the `RGC` authority is a fixed key; the delegation chain is the `R-C2` parent-transport
   work.
2. **Explicit receiver-side generation fencing (defense-in-depth).** Today a returning old-generation node is
   fenced *implicitly* — its rounds are signed under the old commitment and fail `verify_and_seed` against the
   new one. That is sound (the commitment *is* generation-specific), but an explicit generation tag on every
   beacon round/partial (rejected receiver-side when `< g`, per Kleppmann/Raft-term) would harden it. And the
   **order of operations is load-bearing** (IC subnet-splitting ops): halt at the *next* `ExecCertificate` so the
   re-genesis state is quorum-signed, *then* the authority references that exact `(height, state_root)`, then
   nodes restart and state-sync — never re-genesis on an unsigned mid-flight state.

## 3. Censorship-resistant bootstrap (recovering/new nodes when seeds are state-blocked)

A re-genesis is worthless if a recovered cell is unreachable. Fixed seed lists die to enumeration+blocking;
five principles make bootstrap enumeration-resistant (Tor BridgeDB/Salmon, Snowflake, Conjure, ECH): no client
learns the full set; endpoints are ephemeral/rotating (moving target); the rendezvous carrier is unblockable
(collateral-damage blocking); distribution is Sybil-costly; and legitimate peers **compute** the meeting point
from a shared secret. FANOS realizes these by **reusing its own primitives**:

- **Moving-target rendezvous from the beacon:** `rendezvous(epoch) = MapToLine(H(shared_seed ‖ epoch ‖
  SEED(epoch)))` — the existing NYX derivation (§5, `protocol.md`) doubles as an unpredictable, unenumerable
  bootstrap meeting point that rotates each epoch.
- **Wire obfuscation:** PROTEUS polymorph as the obfs4 analog (look-like-nothing), under the Parrot-is-Dead rule
  (no faked TLS/MASQUE handshakes) — see [[proteus-morph-transforms]].
- **Entry broker:** hands out a *few* rotating, PoW-gated, Sybil-bucketed entry descriptors — the
  Snowflake-broker + Tor **rdsys** model (BridgeDB was retired in Oct 2024 for exactly this: hand out `k` per
  requester, rate-limited and bucketed, never the full set). Cap enumeration the way **Lox** (PETS 2023) does —
  open-entry buckets of 1, invite-only buckets of 3, with anonymous credentials that *hide* the inviter/invitee
  graph — so one enumerator learns `O(k)`, never `O(N)`. For hard-blocking regimes, an ECH-fronted or
  Conjure/refraction entry with no fixed IP to list, and **diversify the ECH outer SNI**: a static public name
  (e.g. `cloudflare-ech.com`) is itself the fingerprint Russia's TSPU began blocking in Nov 2024.
- **Peer-exchange after first contact:** once one peer is reached, the rest bootstrap via signed-descriptor
  gossip over the overlay (existing poisoning defence, [[hierarchy-scaling]]).
- **Irreducible residual (stated honestly):** a brand-new node with *no* peer and *no* seed needs **one**
  out-of-band unblockable channel (CDN/ECH front, refraction station, or a Salmon-style social bundle). This
  cannot be eliminated — only made cheap to rotate and expensive to enumerate.

## 4. Implementation map

- `fanos-keygen::RecoveryAuthorization` — the `RGC`: `{ generation, epoch_fence, survivors, threshold, anchor,
  sig }`, PQ-signed (`fanos-pqcrypto::HybridSignature`), `verify(authority)`.
- `fanos-keygen::BeaconNode` — an optional `authority: HybridVerifier` (the recovery trust root) and
  `rebootstrap(auth, new_commitment, new_share)`: verify the `RGC` against the authority + `generation >
  reshare_gen`, then install the fresh key at `epoch_fence`, generation-fenced. Consumers adopt via the flooded
  authorization + a self-authenticating first round.
- **Auto-trigger** (`fanos-node`) — a `client.subscribe()` task beside the epoch driver: Regime A fires
  `reshare_trigger` on predicted thinning; Regime B emits `RecoveryNeeded` and, on an `RGC`, drives the survivor
  `DkgNode` and reseats the beacon. Pure decision fn `recovery_decision(live_anchors, t, stall) → Action` for
  deterministic testing.
- **Simulator** — `mass_event` + the extended R-C1 test: crash `n − t + 1` anchors → clock frozen → `RGC`
  (founder-signed) → survivor DKG → reseat → **`tick_epoch()` resumes** at `epoch_fence`, generation `g+1`.

## 5. Sources

Shamir below-threshold secrecy (perfect); Ethereum Gasper/inactivity-leak + Casper FFG accountable safety;
Ethereum weak subjectivity; Tendermint BFT (>1/3 halt); Herzberg proactive VSS; CHURP eprint 2019/017; drand;
Ferveo eprint 2022/898; Dfinity NIDKG eprint 2021/339 (CUP+NNS); Gilbert–Lynch CAP; Kleppmann fencing tokens;
Vertical Paxos; etcd `force-new-cluster`; Tor obfs4 / Snowflake (USENIX Sec '24) / Conjure (CCS '19); ECH
(draft-ietf-tls-esni). (URLs in the recovery-research synthesis, session 2026-07-23.)
