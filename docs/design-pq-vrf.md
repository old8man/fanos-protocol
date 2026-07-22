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
with the proof logic **generic over the cryptosystem** ([`shuffle::ReRandomizable`]) — the sound, novel part —
and the re-randomization isolated to one seam. **Two backends are implemented**: ristretto ElGamal
([`shuffle::ElGamal`], *classical*/discrete-log, coherent with FANOS's VRF/DKG/VOPRF group) and **Ring-LWE
ElGamal** ([`rlwe::Rlwe`], *post-quantum*). The *same* `prove`/`verify` run over either — `the_same_shuffle_
proof_runs_post_quantum_over_rlwe` exercises it end-to-end. *Soundness* `1 − 2^-k` (each shadow is committed
before the Fiat–Shamir challenge; a wrong output multiset fails one branch); the cut-and-choose is
unconditional, so the shuffle is post-quantum **iff its backend is** — and now it can be. **Novel/unaudited.**
(FANOS's live anonymity remains the threshold sheaf + cover + Poisson mixing; this is the verifiable-mixnet
profile the spec aspires to, now built and PQ-capable.)

## 4. Self-cryptanalysis and honest limits

The strongest verification achievable in-house (external cryptanalysis is, by definition, external):

- **`pqvss`** — reconstruction-uniqueness and unbiasability reduce to *information-theoretic* Shamir + BLAKE3
  binding, both standard; the all-`t`-subsets check is a complete decision procedure for collinearity (no
  probabilistic gap). The honest limit is the **detectable-abort** model: a malicious *dealer* can get its own
  contribution rejected (a liveness nuisance), never bias the honest sum — sound only under an honest majority
  of *dealers*. Adversarial tests cover forged shares, an inconsistent (off-polynomial) but self-consistently
  committed dealing, and below-threshold reveals.
- **`shuffle`** — soundness is unconditional (combinatorial cut-and-choose, `1 − 2^-k`); hiding reveals only
  re-randomization factors (checked homomorphically), one branch per shadow.

### 4.1 RLWE parameter calibration (rigorous)

The `rlwe` backend is calibrated to **NewHope-512** (Alkim–Ducas–Pöppelmann–Schwabe): single ring
`R_q = Z_q[X]/(X^n+1)`, `n = 512`, `q = 12289` (`≡ 1 mod 2n`, NTT-friendly), centered-binomial noise `η = 8`
(variance `η/2 = 4`, `σ = 2`). NewHope-512 is estimated at **≈ 101-bit post-quantum** core-SVP (NIST level 1)
by the lattice estimator; a higher level is the drop-in **NewHope-1024** (`n = 1024`, `≈ 233-bit`).

**Decryption-noise budget (why re-randomization is safe).** With `b = a·s + e`, `Dec = v − s·u = e·r + e2 − s·e1
+ m·⌊q/2⌋`. Each product coefficient (e.g. `e·r`) is a sum of `n` independent `σ²`-variance terms, so
`Var ≈ n·σ⁴`; the encryption noise has `Var(E_enc) ≈ 2n·σ⁴ + σ²`, i.e. `σ_enc ≈ σ²√(2n)`. A **re-randomization
adds a fresh `Enc(0)`**, doubling the variance: `σ_tot ≈ 2σ²√n = 2·4·√512 ≈ 181`. Decryption fails only if a
coefficient exceeds `q/4 = 3072 ≈ 17·σ_tot`, a `> 17σ` Gaussian tail — so the analytic decryption-failure rate
is `≈ n·2·Φ(−17) < 2^-100`, comfortably below any epoch count. The **experiment** (`rlwe::noise_experiment`,
100 keys × 512 coefficients) confirms the model: the empirical stddev lands at `≈ 181` and every observed
coefficient is far below `q/4` (max `< 7σ` over ~51k samples), with correct decryption on every trial. The
shuffle **proof** is noise-agnostic (it checks *exact* ciphertext equality), so noise bounds bear only on
decryption, never on soundness.

### 4.2 Soundness in a splitting ring — why the cut-and-choose is the safe choice

The lattice-shuffle literature (Costa–Martínez–Morillo, *Proof of a Shuffle for Lattice-Based Cryptography*,
2017; Aranha et al., CCS 2023; and **eprint 2025/658, *Efficient Verifiable Mixnets from Lattices, Revisited***,
which *corrects a soundness gap* in prior work) shows that the *efficient, algebraic* (Neff/Bayer–Groth-style)
shuffle proofs are subtle over `R_q`: because `q ≡ 1 (mod 2n)` makes `X^n+1` split completely, `R_q` has
**zero-divisors**, so the Schwartz–Zippel argument those proofs rely on (a nonzero low-degree polynomial has
few roots) **fails**, and soundness must be recovered with splitting-ring-aware machinery. Our **combinatorial
cut-and-choose relies on no algebraic identity** — a wrong shuffle fails one of two challenge branches with
probability `≥ 1/2` regardless of the ring — so it is **unconditionally sound over `R_q` for free**, sidestepping
that entire subtlety. The honest cost is proof size: `O(k·n)` (with `k = 128` for `2^-128`) versus the
algebraic `O(n)`. We trade succinctness for a soundness that needs no delicate ring analysis — the right default
for a first, un-audited PQ construction.

### 4.3 Honest limits

- **`pqvss`** — reconstruction-uniqueness and unbiasability reduce to *information-theoretic* Shamir + BLAKE3
  binding. Consistency is the **`O(n·t²)` interpolate-and-evaluate** collinearity check (interpolate `P` from
  `t` verified shares over `GF(256)`, require all shares to lie on `P`) — a *complete* decision (no
  probabilistic gap) that is robust to a forgery *inside* the interpolation basis and correct at any cell size
  (the earlier `all-t-subsets` scan was exponential and mis-rejected large cells). Limit: the
  **detectable-abort** model (a malicious dealer can only exclude itself, never bias the honest sum) under an
  honest dealer-majority. Tests cover forged shares, an off-polynomial (in-basis and out-of-basis) dealing,
  sub-threshold reveals, and a 20-node cell.
- **`rlwe`** — the implementation is **not constant-time / NTT-hardened** (schoolbook `O(n²)` multiply, data-
  dependent nothing-special) and the security rests on the standard Ring-LWE assumption at the cited level.

**What genuinely remains is not design or implementation** but two *external* processes: independent
cryptanalysis of `pqvss`/`shuffle`, and swapping the reference `rlwe` for a **vetted, constant-time, NTT** RLWE
implementation at a deployment's target level (the calibration and the proof are done; only the backend crate
is external).

Sources: [NewHope / lattice-estimator (malb)](https://github.com/malb/lattice-estimator),
[CRYSTALS-Kyber spec](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf),
[Costa–Martínez–Morillo, Proof of a Shuffle (eprint 2017/900)](https://eprint.iacr.org/2017/900),
[Verifiable Mix-Nets from Lattices, CCS 2023 (eprint 2022/422)](https://eprint.iacr.org/2022/422),
[Efficient Verifiable Mixnets from Lattices, Revisited (eprint 2025/658)](https://eprint.iacr.org/2025/658).

## Summary

| Item | Status |
|---|---|
| PQ-VRF (Merkle-committed PRF over epochs) | **Implemented + tested** (`pqvrf`), reduction to BLAKE3 |
| PQ beacon — full-reveal | **Implemented + tested** (`pqvrf`), unbiasable |
| PQ beacon — **reconstruction-unique** | **Implemented + tested** (`pqvss`): committed Shamir + all-`t`-subsets consistency. Novel/unaudited |
| PQ verifiable shuffle (proof) | **Implemented + tested** (`shuffle`): Sako–Kilian, generic over the cryptosystem. Novel/unaudited |
| — classical backend (ristretto ElGamal) | **Implemented + tested** (`shuffle::ElGamal`) |
| — **post-quantum backend (Ring-LWE)** | **Implemented + tested** (`rlwe::Rlwe`) — same proof runs PQ. **NewHope-512** params (≈101-bit PQ), noise budget analyzed + Monte-Carlo-validated (§4.1). Needs a CT/NTT-hardened vetted crate |
