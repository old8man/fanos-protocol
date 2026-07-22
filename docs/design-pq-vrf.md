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
reconstruction is *information-theoretic* — hence PQ — and unique by interpolation.

Malicious-dealer consistency, which Feldman/Pedersen buy with non-PQ homomorphic commitments, is instead
enforced by **binding the sharing polynomial** (audit fix). An earlier design bound each share to itself with a
per-share hash and checked, at reveal, that the *revealed* `t`-subset was self-consistent — but at exactly `t`
shares that check is **vacuous** (interpolation is trivially self-consistent at `t` points), so a dealer could
deal shares off any single degree-`t−1` polynomial and have different `t`-subsets reconstruct *different*
secrets; per-share hash commitments fundamentally cannot give both withholding-tolerance and dealer-consistency.
The fix: the dealer publishes, before the epoch, a commitment to the **polynomial itself** —
`H(epoch ‖ dealer ‖ t ‖ P(0) ‖ … ‖ P(t−1))`, whose `t` canonical values uniquely determine the degree-`t−1`
polynomial. At reveal, any `t` shares are interpolated, the reconstructed polynomial's canonical values are
hashed, and compared to the commitment: a `t`-subset that reconstructs a *different* polynomial fails and is
rejected, so **at most one secret is ever accepted** — reconstruction-unique *and* withholding-tolerant, with
`t`, `epoch`, and `dealer` all bound (no wrong-`t` or cross-epoch/dealer replay). This is **novel/unaudited** and
detectable-abort (a malicious dealer can only get its own contribution rejected, never bias the honest sum),
reduced in `pqvss`'s module docs.

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
ElGamal** ([`rlwe::Rlwe`], *post-quantum*). The *same* `prove`/`verify` run over either. *Soundness* `1 − 2^-k`
with `k ≥ 128` enforced (each shadow is committed before the Fiat–Shamir challenge, which is a single joint hash
over the public key, `(n, k)`, and all shadows; a wrong output multiset fails one branch).

**Audit correction — soundness is not backend-agnostic (see §4.2).** The reduction is exact **only when the
backend's re-randomization is plaintext-preserving *and* `verify_rerandomization` enforces that.** The **ElGamal
backend meets this unconditionally** (one scalar ties both ciphertext components — no free translation), so the
classical shuffle is genuinely `1 − 2^-k` sound and is the backend to rely on. The **Ring-LWE backend does not**
at `n = 512`: an independent review broke it (its check was a tautology admitting a plaintext-changing
translation factor); a shortness gate now closes the trivial forgery, but a norm bound alone cannot give
worst-case soundness there. Treat the RLWE backend as an **experimental research scaffold** (§4.2), not a sound
PQ shuffle. **Novel/unaudited.** (FANOS's live anonymity remains the threshold sheaf + cover + Poisson mixing;
this is the verifiable-mixnet profile the spec aspires to.)

## 4. Self-cryptanalysis and honest limits

The strongest verification achievable in-house (external cryptanalysis is, by definition, external):

- **`pqvss`** — reconstruction-uniqueness and unbiasability reduce to *information-theoretic* Shamir + a BLAKE3
  **polynomial commitment** (the `t` canonical values `P(0..t−1)` bind the whole degree-`t−1` polynomial before
  the epoch). The honest limit is the **detectable-abort** model: a malicious *dealer* can get its own
  contribution rejected (a liveness nuisance), never bias the honest sum — sound only under an honest majority
  of *dealers*. Adversarial tests cover forged shares, an inconsistent (off-polynomial) dealing that yields two
  different `t`-subset secrets (the attack an internal review used to break the earlier per-share-commitment
  design — now rejected), wrong-`t`/epoch/dealer replays, and below-threshold reveals.
- **`shuffle`** — the ElGamal backend's soundness is unconditional (combinatorial cut-and-choose, `1 − 2^-k`,
  the plaintext-preserving factor is one scalar); the RLWE backend is not worst-case sound at `n = 512` (§4.2).
  Hiding reveals only re-randomization factors (checked homomorphically), one branch per shadow, and requires a
  secret high-entropy `seed`.

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

### 4.2 Soundness in a splitting ring — and why a naive cut-and-choose does **not** sidestep it (audit)

The lattice-shuffle literature (Costa–Martínez–Morillo, *Proof of a Shuffle for Lattice-Based Cryptography*,
2017; Aranha et al., CCS 2023; and **eprint 2025/658, *Efficient Verifiable Mixnets from Lattices, Revisited***,
which *corrects a soundness gap* in prior work) shows that the *efficient, algebraic* (Neff/Bayer–Groth-style)
shuffle proofs are subtle over `R_q`: because `q ≡ 1 (mod 2n)` makes `X^n+1` split completely, `R_q` has
**zero-divisors**, so the Schwartz–Zippel argument those proofs rely on **fails**, and soundness must be
recovered with splitting-ring-aware machinery.

**An earlier draft of this note claimed our combinatorial cut-and-choose "relies on no algebraic identity" and
is therefore "unconditionally sound over `R_q` for free," sidestepping the subtlety. An independent review
proved that false.** The cut-and-choose's per-shadow trap — that a shadow cannot be *both* a re-randomization of
the inputs (`b=0`) *and* have the outputs be a re-randomization of it (`b=1`) — holds **only if re-randomization
preserves the plaintext**. The RLWE re-randomization opens its factor `(r', e1', e2')` in the clear, and if the
verifier does not bound it, a factor with `r'=0` and an arbitrary `(e1', e2')` is a *free additive translation*
that changes the plaintext, so a cheater answers whichever branch the challenge demands — a total soundness
break (which the review demonstrated with a working forged shuffle). Enforcing a **shortness bound** on the
opened factor closes that trivial forgery. But at NewHope-512 a norm bound alone is *not* enough for worst-case
soundness: the decryption shift includes `s·e1'` with the **secret** `s` unknown to the verifier, and the only
bound it can enforce, `‖s·e1'‖∞ ≤ n·η·B = 512·8·B`, exceeds `q/4 = 3072` for any `B` large enough to admit
honest factors (`‖ρ−s‖∞ ≤ 2η = 16`). This is exactly the splitting-ring subtlety, and the naive cut-and-choose
does not escape it — the dimension is too large relative to `q` for a clean opened-factor bound.

**Honest resolution.** The **ElGamal (classical) backend is unconditionally sound** — its factor is a single
scalar tying both ciphertext components, leaving no free translation — and is the shuffle to rely on. The
**RLWE backend is an experimental research scaffold**: the shortness gate removes the trivial break, but a
production-sound PQ shuffle needs the splitting-ring-aware NIZK of eprint 2025/658 / Aranha et al., or a
re-parameterization to a regime (much larger `q`, or a gadget/rounding re-randomization) where opened-factor
norm bounds provably keep the shift `< q/4`. This is the honest state after review, not a claim of PQ soundness.

### 4.3 Honest limits

- **`pqvss`** — reconstruction-uniqueness and unbiasability reduce to *information-theoretic* Shamir + a BLAKE3
  **polynomial commitment**. Consistency is decided by re-deriving the reconstructed polynomial's `t` canonical
  values from any `t` verified shares and hashing them against the pre-epoch commitment `H(epoch ‖ dealer ‖ t ‖
  P(0..t−1))` — `O(n·t²)`, and a *complete* decision that (unlike the earlier per-share-commitment / revealed-
  subset check, which was **vacuous at exactly `t` shares** and let a dealer bias the beacon) binds the whole
  polynomial before the epoch, so it is correct even when only a withholding minority's `t` shares are revealed.
  Limit: the **detectable-abort** model (a malicious dealer can only exclude itself, never bias the honest sum)
  under an honest dealer-majority. Tests cover forged shares, an off-polynomial dealing that would otherwise give
  two different `t`-subset secrets, wrong-`t`/epoch/dealer replays, sub-threshold reveals, and a 20-node cell.
- **`rlwe`** — the polynomial multiply is **branch-free / data-independent** (the secret-dependent zero-skip
  that would leak the secret's Hamming weight was removed), but the backend is **not fully constant-time /
  NTT-hardened** (the modular reduction uses `%`; sampling is not rejection-free); security rests on the
  standard Ring-LWE assumption at the cited level.

**What genuinely remains** after the internal review: external cryptanalysis of `pqvss` and the ElGamal
`shuffle`; and, for a *sound* PQ shuffle, replacing the experimental RLWE cut-and-choose with a splitting-ring-
aware NIZK (eprint 2025/658) or a re-parameterized, vetted constant-time NTT RLWE backend (§4.2). The classical
shuffle and the `pqvss` polynomial-commitment beacon are complete and sound up to their stated models.

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
| PQ beacon — **reconstruction-unique** | **Implemented + tested** (`pqvss`): Shamir + **polynomial commitment** (binds `P(0..t−1)`), reconstruction-unique + withholding-tolerant. Novel/unaudited |
| PQ verifiable shuffle (proof) | **Implemented + tested** (`shuffle`): Sako–Kilian, generic over the cryptosystem, `k ≥ 128`, key/`(n,k)`-bound FS. Novel/unaudited |
| — classical backend (ristretto ElGamal) | **Implemented + tested** (`shuffle::ElGamal`) — **unconditionally `1−2^-k` sound**; the backend to rely on |
| — post-quantum backend (Ring-LWE) | **Experimental research scaffold** (`rlwe::Rlwe`) — mechanism runs PQ; a shortness gate closes the trivial forgery but it is **not worst-case sound at NewHope-512** (§4.2). Needs a splitting-ring NIZK or re-parameterization + a vetted CT/NTT crate |
