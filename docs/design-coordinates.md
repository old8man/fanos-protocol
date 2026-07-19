# Coordinate assignment: the verifiable epoch coordinate (design)

> Status: **accepted, implementation in progress** (audit A7 + A2). This document is the recorded
> architectural decision the spec (§3.2, §L0, §L3, §7.3/7.6/7.8/7.10) and audit A2 call for.

## 1. The problem

A node's overlay address is its projective coordinate `[x:y:z] ∈ PG(2,q)`. The spec fixes exactly one
derivation for it (§L0, §7.6 step 3, §7.8 JOIN step 4):

```
coord = MapToPoint( VRF_beacon(pubkey, epoch) )
```

— a **verifiable random function** of the node's key and the epoch's beacon seed, carried with a
**proof-of-coordinate** in `HELLO` (§7.3) so any peer checks it without the secret. This single choice
is load-bearing for three of the protocol's headline guarantees:

- **§3.2 assumption 1** — coordinate assignment is *VRF-verifiable and not cheaply grindable*, so an
  adversary controlling a fraction *f* of nodes lands on ≈ *f* of every line (random placement), never a
  chosen one.
- **§3.2 assumption 2** — the epoch reshuffle is *unpredictable* (the coordinate folds the beacon, which
  is unknown until revealed), so an adversary cannot **pre-settle** onto a target's lines.
- **§L3 anti-eclipse / §7.10 attack table** — "coordinate grinding (pick your cell)" is defeated by
  exactly this: `coord = VRF(pubkey, epoch); beacon unpredictable → cannot pre-aim`.

The implementation had **diverged into three incompatible pieces** (audit A7, verified by a
workspace-wide caller map):

1. **Live path — static self-certifying.** Every live QUIC node derives `coord =
   MapToPoint(H(cert))` (`fanos-quic::coordinate_from_cert`). No VRF, no epoch, no beacon: the
   coordinate is **static for the identity's life** and, on the base cell, **trivially grindable** — the
   devnet harness `credentials_for_point` lands on *any chosen* Fano point in ≈ 7 mints. This satisfies
   *neither* assumption 1 (grindable) *nor* assumption 2 (never reshuffles).
2. **Reference path — a forgeable placeholder.** `fanos-core::membership::Member::assign` derives `coord
   = MapToPoint(H(node‖epoch))` (`fanos-primitives::coordinate_for`), whose own doc-comment admits it is
   "**not** unforgeable … standing in for `MapToPoint(VRF(pubkey, epoch))` until ECVRF is wired in." It
   is epoch-binding but keyless — anyone can compute anyone's coordinate. Used only by tests and the
   `fanos-cli` demo.
3. **The real primitive — dead.** `fanos-vrf::{prove,verify}_coordinate` — a ristretto255 RFC 9381-style
   VRF, the entire reason the coordinate half of `fanos-vrf` exists — has **zero non-test callers**, and
   its keypair `VrfSecret` has **no producer anywhere**: it is disconnected from node identity entirely.

Shipping the weaker of two same-named primitives (the forgeable `coordinate_for`) from the
more-depended-upon crate, while the strong one rots unused, is the "fundamentality hazard" A7 names. But
the deeper defect is that the **live** coordinate is the static self-certifying hash, which fails the
spec's security model on the base cell that actually ships.

> Note the DVRF/DKG/VSS core of `fanos-vrf` is **not** dead — it powers the live randomness beacon
> (`fanos-keygen`, audit E5/#94). Only the *coordinate* VRF was orphaned. The beacon this design folds
> into the coordinate is therefore already running.

## 2. Why self-certifying-static is not enough (and why VRF-epoch is)

Self-certification (coordinate earned by a certificate hash) *is* a real unforgeability property: you
cannot present a coordinate without the cert that hashes to it. It is why the live path is not
*trivially* forgeable. But it buys only assumption 1's *verifiability*, and only weakly:

- **Grindability (assumption 1).** `MapToPoint(H(cert))` is a public function of a self-minted cert.
  Minting is cheap, so landing on a target point costs ≈ *N* mints. On the base cell **N = 7** — the
  attacker picks any point essentially for free. Grind-cost only becomes a real barrier at large *q*
  (≈ *q²* mints), which the shipped q = 2 profile never reaches.
- **Reshuffle (assumption 2).** `H(cert)` has no epoch term. A coordinate, once grinded, is **held for
  the identity's life**. An adversary settles onto a victim's `q+1` lines once and stays. This is the
  precise attack §L3 and §7.10 exist to stop, and static self-certification cannot.

The VRF-epoch coordinate restores both, and does so *most* where the shipped profile is weakest:

- The coordinate is `MapToPoint(VRF(sk, epoch ‖ beacon))`. To aim it an adversary must grind **VRF
  keys** — but each key is a *whole identity* (§4) — and, decisively, the input folds the **beacon
  seed**, which is unpredictable until the threshold beacon reveals it. So the adversary cannot grind for
  a *future* epoch's placement: it does not yet know the mapping. On q = 2, where grind-cost is nil, this
  **unpredictable reshuffle is the entire defense** (assumption 2). On large *q*, grind-cost (assumption
  1) compounds it. The two assumptions cover the two ends of the *q* range; static self-certification
  covers neither end well.
- The coordinate is **VRF-verifiable**: the `HELLO` proof-of-coordinate lets a peer confirm `coord =
  MapToPoint(VRF(sk, epoch‖beacon))` for the claimed identity, so a forged or mis-placed coordinate is
  rejected at the handshake (error `2xx BAD_COORD`, §7.5), not trusted.

## 3. Operational feasibility of the reshuffle

The obvious objection to epoch-reshuffling coordinates is cost: if every node's address changes each
epoch, does the whole overlay have to re-key and migrate all content? In FANOS the answer is **no,
within a cell** — the design already absorbs it:

- **Content addressing is epoch-independent.** A key maps to a *point* by `MapToPoint(H(k))` (§L0), which
  has no epoch term. What an epoch changes is *which node occupies* that point, not which point owns the
  key.
- **Storage is full-line-replicated.** A point's data lives on the `q+1` nodes of the lines through it
  (projective LRC, §L4); in a single Fano cell that already spans the cell, and the live `OverlayNode`
  replicates a `Put` to every member (verified: `cell_e2e::a_stored_value_survives_losing_a_node`). So
  after a reshuffle the node newly at point *P* already holds *P*'s data — no migration, no gap.
- **Peers are re-derived by algebra, not discovery.** A Fano cell is fully connected; every node
  computes the other six from coordinates (no routing-table rebuild, `cell_e2e`). A reshuffle is a local
  re-computation, not a network-wide convergence.

So the reshuffle is a per-epoch *re-derivation and re-announcement*, not a data migration. The beacon
that drives it is already live (`fanos-keygen::BeaconNode`, #94), and its `Notification::BeaconReady`
is already the epoch clock other subsystems rotate on (E4 onion keys, E5 meeting lines).

## 4. The эталon architecture: one verifiable coordinate, bound to identity

The two live models (self-certifying identity, VRF-epoch coordinate) are **not rivals — they compose.**
Self-certification answers "*is this key really this node's?*"; the VRF answers "*is this the coordinate
that key earns this epoch?*". The unification binds them:

1. **The identity commits a VRF key.** The node's long-term public bundle gains a fourth component, a
   `VrfPublic` (ristretto255), alongside the Ed25519+ML-DSA signature and X25519+ML-KEM KEM keys. The
   long-term `NodeId = H(bundle)` therefore commits to the VRF key too: a coordinate proof can only be
   made with the VRF secret whose public is in the identity that hashes to that `NodeId`. The VRF secret
   is **derived deterministically from the same identity seed** (domain-separated), so an identity is one
   seed, as today — no extra key to store.
2. **The coordinate is the beacon-folded VRF.** `coord = MapToPoint(VRF(vrf_sk, coord_input(node_id,
   epoch, beacon_seed)))`, where the input is `node_id ‖ epoch_low32_be ‖ beacon_seed` (extending the
   existing `beacon_alpha` with the beacon term the spec's `VRF_beacon` names). At genesis (`epoch 0`,
   `beacon = BeaconSeed::GENESIS`) this is computable with no live beacon, so cold-start and tests need no
   beacon round.
3. **`HELLO` carries a proof-of-coordinate.** The handshake sends `(epoch, coord, vrf_output,
   vrf_proof)`; the peer runs `verify_coordinate(vrf_public, node_id, epoch, beacon, coord, proof)` and
   rejects a mismatch (`BAD_COORD`) or a stale epoch (`EPOCH_STALE` → `BEACON` sync). Zero extra round
   trips: it piggybacks the first flight (§7.3).
4. **`coordinate_from_cert` is retired as the coordinate authority.** The self-certifying cert continues
   to certify the *identity* (the TLS key), but the *coordinate* comes from the VRF. The devnet harness
   pins a node to a point by grinding the *identity seed* until `VRF(vrf_sk, point-for-genesis)` hits the
   target — the same retry-until-target loop, now over the primitive that actually guards placement.

This makes `fanos-vrf::prove_coordinate`/`verify_coordinate` the single coordinate authority, used on
the live path; demotes `coordinate_for` to what its doc already calls it — the no_std deterministic
*addressing reference* for tests, never a security primitive; and gives the coordinate the verifiability
(assumption 1) the shipped profile lacked.

### Delivery levels

- **Level A — the verifiable, identity-bound coordinate (this change).** Items 1–4 above at the genesis
  epoch, wired live: the VRF key is in the identity, the coordinate is `MapToPoint(VRF(sk, epoch‖beacon))`,
  `HELLO` proves it, `coordinate_from_cert` is retired. Satisfies assumption 1 (verifiable, forge-proof,
  grind-priced in the VRF key) and unifies the models. The coordinate is *provable and unforgeable*
  everywhere it is used.
- **Level B — the live per-epoch reshuffle (tracked follow-up).** Nodes re-derive and re-announce their
  coordinate on each `BeaconReady`, with the JOIN-waits-for-beacon cold-start and the announce/withdraw
  choreography. Satisfies assumption 2 in the running overlay. This is a deployment mechanism (operating a
  reshuffling membership), not a primitive; §3 shows it is cheap in FANOS, and it rides the beacon clock
  that already exists. It is specified here and tracked as its own task so it is delivered against this
  design, not improvised.

Level A closes the A7 defect (forgeable/dead/unverified coordinate) completely and correctly; Level B is
the operational completion of the same design.

## 5. A2 — the large-`q` scaling decision (recorded)

Audit A2 asks for an explicit, recorded decision on the general-`q` story, because DIAKRISIS and the whole
live stack fix `q = 2` while `Plane::<F7/F13/F31>` generality is exercised only in geometry unit tests.
The decision:

- **`q = 2` + a recursion of cells is *the* deployment scaling model** (spec §L1 "Hierarchy", verified
  V4; the [[hierarchy-scaling]] work — addressing, live-overlay routing, self-seed, signed descriptors —
  is built). Internet scale is `k` levels of Fano cells (`O(log n)` state/depth, like Kademlia), **not** a
  single large-`q` plane. This design's coordinate is `MapToPoint` over the base cell at each level; the
  hierarchy composes it by domain-separated descent ([[crypto-identity-primitives]], `address.rs`).
- **Large-`q` `Plane` is spec-completeness, not a scaling lever.** The generic-`q` geometry is retained
  because the theorems are stated for general `q` and it keeps the algebra honest and testable at
  `q ∈ {7,13,31}`, but no large-`q` *cell* runs above geometry, and none is a deployment target. It must
  not be read as a shipping capability.
- **DIAKRISIS `N = 7` is base-cell proprioception, not a ceiling.** The 3-bit Hamming(7,4) syndrome is
  intrinsically a Fano-plane object (spec Part VI); self-diagnosis is defined on the base cell and the
  hierarchy diagnoses upward by escalation, not by a 993-element self-observation. The `N = 7` constant is
  therefore correct and honest — the coherence/window measures are properly general-`N`, and the `_fano`
  suffixes mark the specialization.

The coordinate authority (§4) is the same at every level and every `q`: `MapToPoint(VRF(sk,
epoch‖beacon))`. Nothing here forecloses a future large-`q` self-observation story; it records that the
shipped model is `q = 2` + hierarchy, so the capability is not mistaken for one that runs.

## 6. Impact

- **Wire/KAT.** Adding `VrfPublic` to the bundle changes `HybridPublicKey::encode()` length and every
  derived `NodeId`. No *external* conformance vector breaks (they key on opaque bytes / literal strings);
  two in-crate identity KATs are updated in lock-step (`keys.rs` bundle-length, `pqcrypto` node_id
  parity). `HELLO` gains the proof-of-coordinate fields (`fanos-wire`).
- **Coordinate-pinned tests.** Every test that pins a node to `Point::at(i)` via the cert grind now pins
  via the identity-seed grind; the assertion (node lands on the intended point) is unchanged.
- **Crates touched (Level A):** `fanos-vrf` (beacon-folded input), `fanos-primitives` (bundle + VRF key +
  seed-derivation), `fanos-pqcrypto` (identity generation derives the VRF key), `fanos-quic` (coordinate
  from VRF, harness grind), `fanos-core` (membership uses `prove_coordinate` + `verify`), `fanos-wire` +
  `fanos-diaulos` (HELLO proof-of-coordinate).
