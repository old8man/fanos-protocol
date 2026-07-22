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
withholding minority cannot stop or fork it. The `pqvrf` beacon is a **full-reveal** composition. **The
reconstruction-unique variant is now implemented** in [`fanos-vrf::pqvss`] (Hand-roll full): a threshold beacon
from **plain Shamir over `GF(256)`** ([`fanos_primitives::shamir`], the existing threshold substrate), whose
reconstruction is *information-theoretic* — hence PQ — and unique by interpolation. Malicious-dealer
consistency, which Feldman/Pedersen buy with non-PQ homomorphic commitments, is instead enforced at reveal by
a complete **all-`t`-subsets-agree** check (accept a dealing iff every `t`-subset reconstructs the identical
secret ⇔ the shares lie on one degree-`t−1` polynomial); an inconsistent dealer is detected and excluded.
Unbiasability comes from a binding hash commitment to all shares published before the epoch. This is
**novel/unaudited** and detectable-abort (a malicious dealer can only get its own contribution rejected, never
bias the honest sum), reduced in `pqvss`'s module docs.

## 3. The PQ verifiable shuffle — implemented ([`fanos-vrf::shuffle`], Hand-roll full)

A verifiable shuffle proves an output list is a secret permutation (+ re-randomization) of the inputs, so no
output links to its submitter, *without revealing the permutation*. **Audit correction:** an earlier draft of
this note claimed a *hash-only* cut-and-choose shuffle is sound — **it is not**. Proving a shadow re-commits
the inputs forces opening the input commitments, which leaks the submitter↔value link; genuine unlinkability
needs **re-randomization**, which needs a *homomorphic* cryptosystem (so a verifier checks `ct' = ReRand(ct,r)`
from `r` without the plaintext). Hash commitments cannot re-randomize — so no sound hash-only linkage-hiding
shuffle exists.

The implemented construction is therefore a **Sako–Kilian cut-and-choose over a re-randomizable encryption**,
with the proof logic **generic over the cryptosystem** (the sound, novel part) and the re-randomization
isolated to one seam. It is instantiated over **ristretto ElGamal** (the group FANOS's VRF/DKG/VOPRF already
use — architecturally coherent), giving a complete, tested verifiable mixnet proof. *Soundness* `1 − 2^-k`
(each shadow is committed before the Fiat–Shamir challenge; a wrong output multiset fails one branch).
*Hiding*: only re-randomization factors are ever revealed (checked homomorphically), one branch per shadow, so
`π` stays hidden. Over ristretto it is **classical** (discrete log); **swapping the seam for a lattice/RLWE
ElGamal makes the identical proof post-quantum** — the cut-and-choose soundness is unconditional. The PQ `[P]`
thus reduces to "a PQ re-randomizable encryption" (a known lattice primitive), and the construction is ready
for it. **Novel/unaudited.** (FANOS's live anonymity remains the threshold sheaf + cover + Poisson mixing; this
is the verifiable-mixnet profile the spec aspires to, now built.)

## Summary

| Item | Status |
|---|---|
| PQ-VRF (Merkle-committed PRF over epochs) | **Implemented + tested** (`pqvrf`), reduction to BLAKE3 |
| PQ beacon — full-reveal | **Implemented + tested** (`pqvrf`), unbiasable |
| PQ beacon — **reconstruction-unique** | **Implemented + tested** (`pqvss`): committed Shamir + all-`t`-subsets consistency. Novel/unaudited |
| PQ verifiable shuffle | **Implemented + tested** (`shuffle`): Sako–Kilian over ristretto ElGamal, PQ via a lattice seam-swap. Novel/unaudited |
