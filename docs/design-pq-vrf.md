# Post-quantum VRF, beacon, and verifiable shuffle (addressing spec §16 `[P]`)

> Spec §16: *"PQ-VRF, PQ beacon, PQ verifiable shuffle are `[P]`. Active crypto directions; we use classical
> variants as an interim, honestly marked."* This note advances all three, from **BLAKE3 alone** (no new
> hardness, quantum-resistant): a fully-implemented-and-tested PQ **VRF** and a PQ **beacon** built on it, and
> a rigorous **design + honest status** for the PQ verifiable **shuffle**. The unifying idea is to exploit the
> structure of FANOS's actual need rather than chase a general-purpose lattice VRF.

## 1. The PQ-VRF — a Merkle-committed PRF over the epoch domain (`fanos-vrf::pqvrf`, implemented)

FANOS's VRF input is the **epoch counter** — a bounded, increasing integer, not an arbitrary string. That
changes the problem: over a bounded pre-committable domain a **Merkle-committed PRF tree** is a complete VRF
from symmetric primitives.

```
leaf(e) = H("pqvrf-leaf", seed ‖ e)       one PRF value per epoch e ∈ [0, 2^height)
root    = Merkle root of { leaf(e) }        the public key, published at setup
VRF(e)  = ( output = leaf(e) , proof = Merkle authentication path )
verify  : recompute the path from `output` and check it reaches `root`
```

**Security, reduced to BLAKE3.**
- **Uniqueness** — the root binds exactly one leaf per epoch; a second valid output for the same epoch is a
  Merkle 2nd-preimage, `≤ 2^-256`. So a prover cannot equivocate on its randomness.
- **Pseudorandomness / unpredictability** — `leaf(e) = PRF(seed, e)`; without `seed` a future epoch's output
  is indistinguishable from random even given all earlier outputs (PRF security of keyed BLAKE3).
- **Unbiasability** — every leaf is fixed by `seed` and *committed in `root` at setup*. At reveal time an
  adversary cannot grind its contribution: the RANDAO last-actor bias is structurally impossible. This is the
  property a beacon most needs, and here it is free.

**Cost, stated honestly.** The domain is bounded to `2^height` pre-committed epochs, and setup materializes the
tree (`O(2^height)`). A deployment picks a modest `height` (e.g. `20` ≈ 1M epochs) and **rotates to a fresh
root** periodically — a natural re-key, cheaper than it sounds because the tree is built once per rotation.
For unbounded domains without rotation a stateless hash-based VRF (e.g. an XMSS/SPHINCS-style few-time VRF, or
a Picnic-ZK-of-PRF) is the heavier general answer; the Merkle construction is the right one for the
bounded-epoch use, which is *all* the FANOS beacon requires.

*Experiments (`pqvrf::tests`).* prove/verify round-trips over an entire domain; a forged output, tampered
path, wrong epoch, or wrong root are all rejected; outputs are distinct and deterministic (unbiasable) across
the domain; proofs round-trip through bytes.

## 2. The PQ beacon — combined anchor shares (`pqvrf::beacon_seed`, implemented)

`T` anchors each publish a Merkle root at setup. For epoch `e`, each reveals a verified `BeaconShare`
`(root_i, output_i, proof_i)`, and the beacon seed is `H("pqvrf-beacon", e ‖ sorted_i(root_i ‖ output_i))`.

- **Unbiasable** — each `output_i` is pre-committed in `root_i`, so no anchor (even the last to reveal) can
  grind; this is strictly stronger than a RANDAO commit-reveal beacon.
- **Unpredictable** — as long as one honest anchor's `seed_i` is secret, its `output_i` is unpredictable, so
  the combined seed is (a "one honest anchor suffices" unpredictability).
- **Verifiable** — every share is checked against its published root before combining.

*Honest status vs. the classical DVRF.* The interim beacon (`fanos-vrf::beacon`) is a threshold DVRF whose
output is **unique under reconstruction**: any `t` of `n` shares recover the *same* value, so a `< t`
withholding minority cannot stop or fork it. The PQ beacon here is a **full-reveal** composition — it combines
the shares that appear, so a withholding anchor changes the value (a liveness/agreement dependency on all
declared anchors for a given round). Recovering DVRF-style *reconstruction uniqueness* post-quantum needs a PQ
threshold primitive (a lattice threshold PRF, or a hash-based threshold with a fixed reveal set) and is the
residual open piece — but the per-anchor PQ-VRF and the unbiasable full-reveal beacon are concrete, tested
advances over "classical only", and suffice for a synchronous anchor set.

## 3. The PQ verifiable shuffle — design and honest status (designed, not implemented)

A verifiable shuffle proves that an output list is a secret permutation (+ re-randomization) of an input list.
FANOS has **no classical shuffle implementation** either: its anonymity comes from the **threshold sheaf**
onion + structurally-balanced cover + Poisson mixing (§5.2–§5.5), *not* from a Neff/Groth verifiable-mix proof,
so this item is a spec *aspiration* for an alternative verifiable-mixnet profile, not a live dependency.

**Recommended sound PQ construction (cut-and-choose permutation argument).** Commit each input with a
hash commitment `c_i = H(m_i ‖ r_i)`. The mixer outputs re-committed values in permuted order and proves
correctness by a `k`-round cut-and-choose: in each round it commits a fresh "shadow" permutation `σ_j` and its
blinders; the verifier's challenge bit reveals either (a) `σ_j` and the input→shadow blinders, or (b) the
shadow→output blinders — never both, so the permutation stays hidden while each round has soundness error
`1/2`; `k` rounds give `2^-k`. Everything is hash commitments ⇒ post-quantum. Proof size is `O(k·n)`.
(A lattice-based shuffle — RLWE re-encryption with a norm/permutation proof — is the smaller-proof alternative
but a much larger implementation surface.)

**Status.** Designed here with a soundness argument; **not implemented**, because (i) it has no live consumer
in FANOS's current anonymity stack and (ii) a sound cut-and-choose implementation is a substantial standalone
artifact whose value is a *different* mixnet profile than the one FANOS ships. It is recorded as the concrete
next construction should a verifiable-mixnet profile be prioritized.

## Summary

| Item | Status |
|---|---|
| PQ-VRF (Merkle-committed PRF over epochs) | **Implemented + tested** (`pqvrf`), reduction to BLAKE3 |
| PQ beacon (full-reveal anchor combination) | **Implemented + tested**, unbiasable; threshold-uniqueness residual noted |
| PQ verifiable shuffle | **Designed** (cut-and-choose, sound, PQ); not implemented — no live consumer |
