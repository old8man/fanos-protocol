# OBOLOS's proof size — is LaBRADOR/Greyhound the fix, and what would adopting it cost?

> Answers the question `docs/reference-solutions.md` §5 opened and left as a survey verdict: OBOLOS's shielded-spend
> proof is **145 MiB**, four to five orders of magnitude too large to gossip, against Halo2's low-KB proofs live in
> Zcash Orchard since 2022 — so the crown-jewel private-currency tier ships **zero** privacy today, not degraded
> privacy. The survey named LaBRADOR (Beullens & Seiler, CRYPTO 2023, IACR eprint 2022/1341) with Greyhound-style
> polynomial commitments (IACR eprint 2024/1293) as the fix. This document is the engineering decision behind that
> verdict: is it right, and precisely what would it cost — in bytes, in files, and in which invariants move.
>
> Method: (1) measure where the 145 MiB actually goes, from the code, not the docs; (2) establish what LaBRADOR and
> Greyhound actually deliver, from the papers, including where they *don't* help; (3) do the crossover arithmetic —
> is OBOLOS's statement large enough to be in LaBRADOR's regime; (4) compare honestly against the alternatives,
> including "change nothing but the parameters"; (5) cost the adoption in FANOS's own files and invariants.

## 1. The measurement — where the 145 MiB actually goes

`docs/design-obolos-zk.md` §6 already publishes a sizing table, produced by [`ring_size::ProofSize`](../rust/crates/fanos-obolos/src/ring_size.rs) — an exact count of the `R_q` ring elements each proof consists of, checked against the constructions in the crate's own tests. Rather than take that table on faith, it was reproduced three independent ways for this document, and all three agree to the byte:

1. **Hand-derivation** from the `ProofSize` formulas in the source (below).
2. **A fresh execution.** A standalone harness was built against `fanos-obolos`'s own public API (`RingParams`, `SpendScheme`, `prove_input`/`prove_output`/`prove_amounts`/`prove_shielded_tx`, and the `ring_size::ProofSize` trait) — no crate file was modified — reproducing exactly the scenario the crate's own `#[ignore]`d test (`ring_tx.rs`, `a_one_in_one_out_shielded_transfer_proves_and_verifies`) builds: a 1-in/1-out shielded transfer at Merkle depth 1 (the shallowest a tree path can be). Run at HEAD `e3ca7ad` (2026-08-04), release profile:

   ```text
   one hash step (ring_linear, n=12):            1440 elements      2.8125 MiB
   node shortness (ELL_H=4 limbs, bits=16):      4468 elements      8.7266 MiB
   one input's spend proof (depth 1):           61877 elements    120.8535 MiB
   one output's creation proof:                 12176 elements     23.7812 MiB
   confidential amounts (1 out, RANGE_BITS):      196 elements      0.3828 MiB

   TOTAL 1-in/1-out shielded tx (depth 1):      74249 elements    145.0176 MiB  (152061952 bytes)
   ```

3. **The crate's own `#[ignore]`d test**, run with `--include-ignored` in release mode, passes unmodified and asserts `proof_bytes > 8 << 20` (a floor, not the exact figure — the exact figure came from (2)).

All three agree with `docs/design-obolos-zk.md` §6 to four decimal places. **The 145 MiB figure is current, not stale, and is not an estimate** — it is `74,249` ring elements at `D=256` coefficients each, one `u64` per coefficient (`BYTES_PER_ELEMENT = 2048` bytes/element, [`ring_size.rs:35`](../rust/crates/fanos-obolos/src/ring_size.rs)).

**This is the theoretical floor, not the deployment number.** Depth 1 is the shallowest a Merkle path can be; the production tree is fixed-depth **32** ([`tree.rs:22`](../rust/crates/fanos-obolos/src/tree.rs), `TREE_DEPTH`, the Zcash Sapling convention). At depth 32 the same accounting gives **875 MiB** per transaction (design-obolos-zk.md §6). Every figure below uses the depth-1 floor, because it is the strongest form of the argument: even the cheapest possible spend proof this construction can produce is hopeless to gossip.

### 1.1 The dominant term, exactly

Walking the composition (`ring_input::prove_input` = `ring_note::prove_note` + `ring_value_tie::prove_value_tie` + `ring_untraceable::prove_untraceable` = `ring_membership::prove_path_sound` + `ring_nullifier::prove_nullifier` + a position-tie `ring_linear` proof; `ring_output::prove_output` mirrors the note+value-tie half), a 1-in/1-out transaction pays a [`ring_shortness::prove_short`](../rust/crates/fanos-obolos/src/ring_shortness.rs) proof (an `ELL_H`-limbed node's shortness, 4,468 elements each) on exactly these node values:

| From | Nodes proven short |
|---|---|
| `ring_note` (the note's validity) | `nsk`, `value_node`, `rho`, `tag`, `note_owner` — **5** |
| `ring_membership` (the path, depth 1) | `cm` (the leaf), the one sibling — **2** |
| `ring_nullifier` | `nsk` (again), `cm` (again), `pos_node`, `slot` — **4** |
| `ring_output` (the created note) | `value_node`, `note_owner` — **2** |

**13 shortness-proof instances**, over **11 distinct witness values** — `nsk` and `cm` are each proven short *twice*, once inside `ring_note`/`ring_membership` and once again inside `ring_nullifier`, because those sub-proofs are composed independently and each re-establishes its own input's shortness precondition rather than sharing an already-proven fact. `13 × 4,468 = 58,084` elements — **78.2% of the entire 74,249-element proof** is this one repeated argument: "this 4-limb node's coefficients are `< 2^16`," proved from scratch 13 times with no sharing of commitments, challenges, or randomness across instances (deduplicating the two redundant re-proofs would save `2 × 4,468 = 8,936` elements, 12.0% — a real but minor same-construction saving, see §5.3).

### 1.2 The witness this is actually protecting, and the resulting blow-up ratio

The **true secret** a 1-in/1-out spend needs to attest to is small. Enumerating every distinct short vector that functions as a witness (not a proof artifact): 11 SIS-hash nodes (`nsk`, `value_node_in`, `rho`, `tag`, `note_owner_in`, `cm`, `sibling`, `pos_node`, `slot`, `value_node_out`, `note_owner_out`), each `ELL_H = 4` ring elements; two value-commitment openings (`rv_in`, `rv_out`), each `ELL = 4` ring elements; one direction bit. In `Z_q` coefficients (`D = 256` each):

```text
11 nodes × 4 × 256   = 11,264
 2 openings × 4 × 256 =  2,048
 1 direction bit × 256 =    256
                        ────────
 true witness  N  ≈    13,568  Z_q coefficients
```

The delivered proof is `74,249 × 256 = 19,007,744` `Z_q`-coefficient-equivalents. **The proof is ≈1,401× the size of its own witness.** That ratio is not inherent to the relation — it is what an *unamortized* Σ-protocol costs: every one of the ~13 small relations pays its own independent commit-challenge-respond round, repeated `REPETITIONS = 16` times (monomial-challenge proofs — [`ring_product.rs:74`](../rust/crates/fanos-obolos/src/ring_product.rs), pinned by the ring's `2D = 512`-element guaranteed-unit challenge set, [§2](#2-what-obolos-actually-proves-and-why-it-composes-the-way-it-does)) or `SCALAR_ROUNDS = 9` times (scalar-challenge proofs, `⌈128/(CHALLENGE_BITS−1)⌉` at `CHALLENGE_BITS=16` — [`ring_range_agg.rs:58`](../rust/crates/fanos-obolos/src/ring_range_agg.rs)), with **zero sharing** of commitment or challenge machinery *across* the 13 instances or across repetitions within one instance. This is exactly the shape that amortized/aggregated lattice proof systems — LaBRADOR chief among them — exist to remove: not by shrinking any one relation, but by paying the `O(√N)`-ish aggregation cost **once** for the whole witness instead of `13 × (9\text{-or-}16)` times for its pieces.

## 2. What OBOLOS actually proves, and why it composes the way it does

Every sub-proof in the stack is already stated in a form a lattice amortization scheme could plausibly consume directly, without an R1CS or circuit front-end:

- [`ring_linear`](../rust/crates/fanos-obolos/src/ring_linear.rs) — `Σᵢ cᵢ·mᵢ = 0` over committed short `mᵢ`, with public coefficients `cᵢ` that may be **huge** (SIS matrix rows). This is the SIS hash step (`parent = hash(left, right)`, [`ring_hash.rs`](../rust/crates/fanos-obolos/src/ring_hash.rs)) and the value-tie, restated directly.
- [`ring_product`](../rust/crates/fanos-obolos/src/ring_product.rs) — a Baum–BDLOP argument for `z = x·y` over committed short vectors, using **monomial** challenges `{X^m : 0 ≤ m < 2D}` because the ring `R_q = Z_q[X]/(X^{256}+1)` over the Goldilocks prime **fully splits** (every element factors into 256 linear pieces mod `q`), so a random short difference is not guaranteed invertible — only monomial differences are ([`ring.rs`](../rust/crates/fanos-obolos/src/ring.rs), `monomial_challenge_differences_are_units`). This is the conditional-swap gadget that hides a Merkle path's direction bits.
- [`ring_binary`](../rust/crates/fanos-obolos/src/ring_binary.rs) / [`ring_range_agg`](../rust/crates/fanos-obolos/src/ring_range_agg.rs) — a Bulletproofs-style scalar-challenge aggregated binarity/range argument.
- [`ring_shortness`](../rust/crates/fanos-obolos/src/ring_shortness.rs) — bit-plane decomposition into `t = LOG_BASE = 16` planes, each proven binary (via `ring_binary`), plus a reconstruction opening-to-zero. This is the dominant term (§1.1) — and it is dominant *because* it is a bit-by-bit decomposition proof, the classical way to bound a norm in a Σ-protocol without native norm-checking machinery.

All of it reduces to Module-SIS (the commitment binding, the SIS hash collision resistance) and Module-LWE (the commitment hiding) over this one ring — no new hardness anywhere in the stack (`docs/design-obolos-zk.md` §0–§4). The parameters in play: `D = 256`, `q = 2^{64} − 2^{32} + 1` (Goldilocks), commitment ranks `K = 1`, `ELL = 4`, hash ranks `K_H = 1`, `ELL_H = 4`, gadget base `LOG_BASE = 16` (`DIGITS = 4`), `REPETITIONS = 16`, `SCALAR_ROUNDS = 9`.

---

## 3. What LaBRADOR delivers, and the two places it does not

Sourcing note, stated once so every figure below can be weighed: the eprint PDFs (2022/1341, 2024/1293, 2024/1846, 2026/1289) refuse direct fetch (HTTP 403), as does the ACM DL copy; the RWC slides are unparseable and the Wayback Machine is unreachable from here. So the numbers come from abstract pages read directly, corroborated by a technical review series that quotes the papers' formalism verbatim and by two independent implementation write-ups. Where no source produced a number, this document says **not established** rather than estimating, and §8 tables every claim by its basis. That distinction is load-bearing in §3.3 and it is what caught a circulating benchmark figure that no primary page contains (§6).

### 3.1 The relation is already OBOLOS's shape — this is the finding that matters

LaBRADOR's *principal relation* is: given `r` short vectors `s₁…s_r ∈ R_q^n`, prove

```
f(s₁,…,s_r) = Σᵢⱼ aᵢⱼ⟨sᵢ,sⱼ⟩ + Σᵢ⟨φᵢ,sᵢ⟩ − b = 0
```

— a **system of bilinear dot-product constraints over short ring vectors**, with linear relations as the `aᵢⱼ = 0` special case. Compare §2: [`ring_linear`](../rust/crates/fanos-obolos/src/ring_linear.rs) is `Σ cᵢmᵢ = 0` over committed short `mᵢ` (the second sum, verbatim) and [`ring_product`](../rust/crates/fanos-obolos/src/ring_product.rs) is `z = x·y` over committed short vectors (the first sum, verbatim). **OBOLOS's relations are already written in LaBRADOR's native input language.**

That is not a small coincidence, and it is worth being precise about why it matters. The usual cost of adopting a SNARK is the *front end*: flattening a hand-built relation into R1CS or an AIR, which is where correctness is lost and where a constant-factor blow-up hides. Here there is no front end. Two independent sources confirm the language is native rather than R1CS-only — the Nethermind implementation notes state "the underlying mathematical framework operates on general dot-product constraints," with R1CS translation being merely the common on-ramp, and IBM's **LaZer** library (eprint 2024/1846, CCS 2024) exists precisely so users "specify the lattice relations and norm bounds they would like to prove" directly.

### 3.2 Proof size: flat at ≈50 KB, and flat is the important word

| statement size | LaBRADOR proof |
|---|---|
| 2²⁰ R1CS constraints, mod 2⁶⁴+1 | **58 KB** (the paper's headline) |
| 2¹⁰ constraints | **47 KB** |

A **1000× increase in statement size costs 23% more proof**. Sources disagree on the clean asymptotic label — some say `O(√N)` per amortization step, others `O(log N)` after recursion — and that disagreement does not matter here, because the *measured* behaviour across the range OBOLOS lives in is "approximately constant, near 50 KB". Below 2¹⁰ constraints no figure was found: **not established**, and irrelevant, since §3.3 puts OBOLOS well above it.

### 3.3 The crossover: is OBOLOS's statement big enough to be in that regime?

Counting from the construction rather than guessing. The dominant term is binarity: [`ring_shortness`](../rust/crates/fanos-obolos/src/ring_shortness.rs) decomposes each `ELL_H = 4`-element node into `LOG_BASE = 16` bit-planes and proves each plane binary, i.e. one `b(b−1) = 0` constraint per coefficient:

```
per node:      4 elements × 256 coefficients × 16 planes  =  16,384 binarity constraints
11 distinct nodes:                          11 × 16,384   = 180,224
+ SIS hash steps, value ties, products, range aggregation      ~ 10³–10⁴
                                                            ──────────
statement                                                    ≈ 2 × 10⁵  ≈  2¹⁷·⁵
```

That sits **inside the 2¹⁰–2²⁰ band the paper measured**, not at its edge and not beyond it. So the expected proof is the band's value, ≈50–58 KB:

| | today | with LaBRADOR |
|---|---|---|
| 1-in/1-out, Merkle depth 1 | 145 MiB | ≈50 KB — **≈3,000×** |
| 1-in/1-out, production depth 32 | 875 MiB | ≈50–58 KB — **≈18,000×** |

The second row is the one that decides this. **Merkle depth stops mattering.** Today each level of the tree adds two shortness proofs at 8.7 MiB each, which is why depth 32 costs 875 MiB; under LaBRADOR depth 32 multiplies the *constraint count* by ~30 and the proof size by roughly the 23%-per-1000× figure above. The construction's worst scaling axis becomes its flattest.

### 3.4 Where it does *not* help — verifier time

This is the finding that changes the shape of the recommendation, and it is confirmed by two independent sources quoting the paper: LaBRADOR is "transparent, with **linear prover and verifier time**, and achieves sublinear proof size." Sublinearity is in **bytes only**.

So a validator's per-transaction verification work stays proportional to ≈2×10⁵ constraints. Whether that is 10 ms or 10 s is **not established** — no source produced a prover- or verifier-time figure in seconds, and this is exactly the number a chain needs. For comparison, Zcash Orchard's Halo2 verification is on the order of milliseconds, and that is the bar a shielded pool is measured against in practice.

**Greyhound is not the answer to this**, and the reason is structural rather than a matter of effort. Greyhound (eprint 2024/1293) is a polynomial-commitment scheme: it proves *evaluations of one committed polynomial of bounded degree N* with `O(√N)` verifier time, and it reaches succinctness by **restating its own checks as an instance of LaBRADOR's principal relation** — LaBRADOR is a subroutine *inside* Greyhound, not a competing choice. To use it, OBOLOS would first have to arithmetize the whole spend relation into a single polynomial IOP — a PLONKish/AIR front end the crate does not have and whose absence is precisely what makes §3.1 favourable. Adopting Greyhound would mean *acquiring* the front end this analysis just showed is unnecessary.

**Therefore the recommendation is LaBRADOR alone, and Greyhound is explicitly rejected** — which reverses the pairing `docs/reference-solutions.md` §5 proposed, on the grounds that the two solve different problems and only one of them is OBOLOS's.

### 3.5 The zero-knowledge question — settled, and it is a maturity risk rather than a crypto one

For OBOLOS, witness-hiding is not a feature — it is the entire product; a shielded pool whose proof leaks the witness is a public ledger with extra steps. So the first reading of eprint 2026/1289, *A Toolkit for Succinct Lattice-Based Zero Knowledge Proofs*, was alarming: it calls itself "the first concrete construction and implementation that adds **zero-knowledge** proofs to LaBRADOR", which from the abstract alone could mean the 2023 construction has no witness-hiding treatment at all.

**It does not mean that, and the paper says so in the same paragraph:**

> "Achieving [witness privacy] can, in theory, be done by combining LaBRADOR with a linear-size zero-knowledge proof. **While such a combination has already been described in the LaBRADOR paper itself**, as well as in the works of Albrecht et al. (Eurocrypt 2024) and del Pino et al. (Crypto 2025), **its concrete costs remained unexplored**. In this work, we provide the first concrete construction and implementation…"

So the theory has been in place since 2023 and has been engaged with by two further papers since. What was missing was **an implementation and a number**, supplied in June 2026 by integrating Lyubashevsky–Nguyen–Plançon's linear-size zero-knowledge proof (CRYPTO 2022, eprint 2022/284) into the protocol. That technique is separately published and well established, and its shape — only the final masked opening `z` scales with the witness, the inner messages staying sublinear — is the same mask-then-reveal structure OBOLOS's own [`ring_zk`](../rust/crates/fanos-obolos/src/ring_zk.rs) already uses. *(That last sentence is a structural observation about the technique in general; whether the "linear" term stays small once grafted onto LaBRADOR's recursion is **inference, not confirmed** — see §8.)*

**The residual risk is therefore maturity, not correctness**, and it should be stated as exactly that:

* the only concrete, benchmarked, witness-hiding LaBRADOR is **about six weeks old** (approved 2026-06-22);
* it has **one implementation** — LaZer, whose repository tracks both this paper and the CCS 2024 one and ships the scripts that reproduce its tables;
* **its cost is not established.** No source reachable — paper (the PDF 403s, and at six weeks old it has not propagated to any mirror), repository README, or secondary coverage — states a KB or millisecond figure for the ZK variant against the bare 47–58 KB. The abstract's "under 100 KB for arbitrarily large statements" is context about the LaBRADOR family stated *before* the ZK contribution is introduced, and reading it as a bound on the hiding variant would be an overreach.

**And this residual is measurable rather than research-blocked**, which is what makes it a work item instead of an open question: LaZer ships `benchmark_*.py` scripts that reproduce the paper's own tables. Running them is the cheapest way to get the number, and it does not require the PDF.

One note on the other implementation: **condor-rs is not a second ZK implementation.** Its own README scopes it to "Falcon signature aggregation with LaBRADOR in Rust", with no mention of witness-hiding — signature aggregation is a use case where hiding the witness is not the point. Read LaZer as carrying the ZK variant and condor-rs as the bare argument of knowledge. (A third library, **Lattirust** — "arkworks for lattice-based constructions" — surfaced during this and has not been investigated.)

## 4. The alternatives, compared honestly

### 4.1 Change nothing but the parameters

Two levers exist inside the current construction, and neither is a fix:

* **Deduplicate the two redundant shortness re-proofs** (§1.1: `nsk` and `cm` are each proven short twice). Saves 8,936 elements, **12.0%** → 128 MiB. Real, cheap, and irrelevant to the verdict.
* **Reduce `REPETITIONS = 16`.** This one is a genuine, named lever rather than a knob, and it is worth stating correctly because it looks like a tuning constant and is not. Lyubashevsky–Seiler (EUROCRYPT 2018, eprint 2017/523 — Seiler is also a LaBRADOR/Greyhound co-author) show that a lattice ZK challenge set must be large (~2²⁵⁶), small-normed, and have **all pairwise differences invertible**; on a **fully splitting** ring — which OBOLOS's Goldilocks `X²⁵⁶+1` is, splitting into 256 linear factors — only an `O(d)`-sized subset can guarantee that, which is exactly the `2D = 512` monomials [`ring.rs`](../rust/crates/fanos-obolos/src/ring.rs) uses, and the shortfall is made up by repetition. A **partially splitting** ring admits a far larger population of short elements with invertible differences, which is how Dilithium/Falcon-style schemes reach target soundness in close to one round.

  So the 16 is *derived*, not chosen — and it could plausibly fall by an order of magnitude. But it is a **ring redesign, not a parameter change**: every extractor argument in the crate currently leans on Goldilocks's slot-wise inverse, which full splitting provides for free and a partially splitting ring does not. (That last connection is inference from the general mechanism, not a claim any source makes about OBOLOS.)

  And the arithmetic settles it anyway: 16× on 145 MiB is **9 MiB**. Still three orders of magnitude from gossipable. **The repetition lever is a multiplier on the right answer, not a substitute for it** — and pursuing it now would spend a ring redesign to reach a number that is still hopeless.

### 4.2 The lattice-folding line — LatticeFold, LatticeFold+, Neo

* **LatticeFold** (Boneh–Chen, eprint 2024/257) folds R1CS/CCS instances under Module-SIS. Its base construction carries a restriction on `q` that a technical review states plainly: it "does not work with certain finite fields such as **Goldilocks** or Mersenne61." **That is OBOLOS's exact prime**, and Neo's own abstract names the cause rather than just the symptom — "the required ring structure places restrictions on the choice of primes (e.g., LatticeFold is not compatible with the Goldilocks field)", i.e. the ring structure constrains the modulus. Worth keeping in view because it is the named failure mode of this whole literature, and it is the frame in which §5.3's degree question should be read. A modification for wider moduli exists (§3.3 of the paper) whose details are not established here, but as published this is not a drop-in.
* **LatticeFold+** (CRYPTO 2025, eprint 2025/247) claims a 5–10× faster prover and, notably, "a new purely algebraic range proof" replacing bit-decomposition — which is precisely OBOLOS's 78.2% dominant term (§1.1). No concrete figures were obtainable. This is the most interesting item in the field for OBOLOS specifically, and it is too new to build on.
* **Neo** (eprint 2025/294) and **SuperNeo** (eprint 2026/242) adapt HyperNova-style folding to lattices *without* the cyclotomic restriction, explicitly **Goldilocks-compatible**, with a "pay-per-bit" Ajtai commitment. This is the closest field-match alternative and is genuinely live.

The structural argument for preferring LaBRADOR over all three: **folding is for an unbounded or streaming sequence of instances**, combined incrementally and wrapped in a final SNARK. OBOLOS's per-spend instance count is **fixed and known up front** — 13 shortness proofs, a handful of hash steps, two openings — which is LaBRADOR's one-shot amortization regime, not folding's. Folding becomes the right tool at the *block* level (§5.2), not the transaction level.

### 4.3 STARKs (Plonky3-class)

Calibration only: Plonky2-class proofs run ~45 KB small, ~250–300 KB at ~300K constraints; Plonky3 reports >2M Poseidon hashes/sec on an M3 Max. Post-quantum, transparent, mature tooling, and **fast verification** — which is the one thing §3.4 says LaBRADOR lacks.

The reason it is still not the recommendation: those figures assume a circuit built around a STARK-friendly hash in a STARK-native field. OBOLOS's relation is a *lattice* relation — SIS hashing, module commitments, norm bounds — and re-expressing it as an arithmetic circuit over a different field with a different hash means **rebuilding the entire crate's cryptographic content**, not porting its proofs. It would also fork the platform's hardness base: every other primitive in FANOS reduces to Module-SIS/Module-LWE or a hash, and a STARK'd OBOLOS would still be PQ but would no longer share OBOLOS's own commitment algebra with its own hash. That is a strictly larger rearchitecture for a benefit (verifier speed) that §6's gate might show is unnecessary.

### 4.4 "Lattice Bulletproofs"

No such distinct construction exists; where sources call LaBRADOR "a lattice analogue of Bulletproofs," that is descriptive of LaBRADOR itself. The genuine ancestor is Lyubashevsky–Nguyen–Plançon (CRYPTO 2019, eprint 2019/445) for degree-2 relations, which LaBRADOR generalizes. For calibration on the narrow range-proof case, a 2024 SoK (AFT 2024) puts lattice range proofs at **10–200 KB** against classical Bulletproofs' sub-1 KB — confirming the expected direction and confirming that ≈50 KB for a *whole spend* is a good number by lattice standards, not a disappointing one.

## 5. What adopting LaBRADOR actually changes in this repository

### 5.1 The seam is already in the right place

OBOLOS separates *what is proven* from *how it is proven*, one module per relation. That separation is what makes this a replacement rather than a rewrite:

| keeps | replaced |
|---|---|
| `ring.rs` (ring arithmetic), `commit.rs`, `ring_hash.rs` | `ring_linear`, `ring_product`, `ring_binary`, `ring_range_agg`, `ring_shortness` — the Σ-protocol layer |
| `tree.rs`, `nullifier.rs`, `note.rs`, `note_cipher.rs` | the composition proofs (`ring_note`, `ring_membership`, `ring_nullifier`, `ring_untraceable`, `ring_value_tie`, `ring_input`, `ring_output`, `ring_confidential`, `ring_balance`, `ring_tx`) — restated as one constraint system instead of composed proofs |
| `state.rs`, `tx.rs`, `wallet.rs`, `codec.rs` | `ring_size::ProofSize` — becomes a measurement of one proof, not a sum over thirteen |

The *statements* are unchanged. What changes is that they stop each carrying their own commit–challenge–respond machinery and become rows of one dot-product system. The hardness assumptions do not move: Module-SIS binding and Module-LWE hiding, over a power-of-two cyclotomic, is what both constructions already use.

### 5.2 What stays open even after adoption

**Per-transaction, not per-block.** ≈50 KB per shielded spend puts 100 spends at 5 MB of block, which is a real TAXIS capacity question rather than a solved one. And the obvious fix does not work: LaBRADOR amortizes over relations **with their witnesses**, and a block proposer does not hold the senders' witnesses, so it cannot aggregate their proofs. Compressing a block's spends into one proof requires *recursive verification* — proving "I checked these k proofs" — which is what the folding line (§4.2) is for and which is not available on Goldilocks today outside Neo/SuperNeo. This is the honest limit of the recommendation, and it belongs in the record rather than in a footnote.

### 5.3 The ring-degree mismatch — probably incidental, not confirmed

LaBRADOR's practical instantiation uses `d = 64` and `q ≈ 2⁶⁴+1`; OBOLOS uses `D = 256` and Goldilocks `q = 2⁶⁴ − 2³² + 1`. Same assumption family, same power-of-two cyclotomic shape, same modulus magnitude — but a **4× ring-degree difference**. Third-party implementations already use different moduli again (Ingonyama's is a CRT pair of ~31-bit NTT primes rather than one 64-bit prime), so `q` is implementation-dependent rather than fixed by the construction.

The best evidence reachable says the **degree is the same kind of choice**. Two independent technical write-ups present `d = 64` as a performance convention rather than a soundness requirement — one states "in practice, LaBRADOR uses d=64" alongside NTT efficiency as "pretty standard practice in lattice-based cryptography", and the Greyhound companion tells readers outright that the concrete degree "is not important to understand the protocol". Neither implementation pins it: condor-rs's documented ring is the general `Z_q[x]/(x^d + 1)` with `d` symbolic.

Two caveats, because "probably" is not "yes":

* **The paper's own parameter-selection section is unread** (the PDF 403s), and that is where a degree constraint would live if there is one. So this is the better-supported reading, not a closed question.
* **No source reports running LaBRADOR at `d = 256`** — neither working nor broken. Genuinely not established either way.

One piece of standard lattice reasoning, flagged as **inference** because no LaBRADOR-specific source states it: Module-SIS hardness conventionally depends on the *total* lattice dimension — module rank × ring degree — rather than the degree alone, so a 4× larger degree generically permits a *smaller* module rank at the same security level rather than breaking anything. That is precisely what reading the parameter section would confirm or refute.

## 6. Recommendation

**Adopt LaBRADOR as the argument system for OBOLOS's existing relations. Reject Greyhound. Leave the ring alone.**

That is the strictly-better option on the evidence: it is the only candidate whose native input language is what OBOLOS already writes (§3.1), it lands the proof in the ≈50 KB band at OBOLOS's measured statement size (§3.3), it makes Merkle depth almost free (§3.3), and it keeps the platform on one hardness base. Greyhound is rejected because it solves polynomial-evaluation succinctness and would require acquiring the front end §3.1 shows is unnecessary. STARKs are rejected because the migration is a rebuild of the crate's cryptographic content, not a change of proof system. The parameter levers are rejected because 16× on 145 MiB is still 9 MiB (§4.1).

**Three gates were named before committing engineering effort. All three have now been worked, and none of them blocks — but what they returned changes what the work is.**

**Gate 1 — zero-knowledge (§3.5): PASSED, with a maturity caveat.** The alarming reading was wrong: the ZK combination has been described since the 2023 LaBRADOR paper itself and engaged with by Albrecht et al. (Eurocrypt 2024) and del Pino et al. (Crypto 2025); what 2026/1289 contributes is the first *implementation and concrete cost*. So this is not "the crypto might not exist". It is "the only benchmarked, witness-hiding instantiation is six weeks old and has one implementation, and its cost is unquantified".

**Gate 2 — verifier time (§3.4): NOT ESTABLISHED, and it will not be settled by reading.** Every avenue was tried and each is blocked or empty: the eprint PDFs 403 (2022/1341, 2024/1846), the ACM DL copy 403s, the RWC slides are unparseable, the Wayback Machine is unreachable, and every abstract page that *does* load contains no benchmarks — confirmed by fetching them, not assumed. The two technical deep-dives are explicitly asymptotic-only. **A trap worth recording rather than repeating:** a search summary asserted a specific figure ("verification 45–72 ms, proof size 32–48 KB, memory 512–645 MB, median of 100 runs") attributed to LaZer, and direct fetches of both pages it could plausibly have come from show no such numbers. It is a lead for someone with PDF access, **not a citable fact**, and it must not enter this document as one.

**Gate 3 — ring degree (§5.3): probably incidental, not confirmed.** Two independent write-ups present `d = 64` as an NTT/performance convention rather than a soundness requirement, and neither implementation pins it. The paper's own parameter-selection section is unread, so this stays open rather than closed.

### What the gates turned the work into

The two unresolved items are **measurements, not research questions**, and both are cheap:

1. **Run LaZer's own benchmarks.** Its repository ships `benchmark_expansion.py`, `benchmark_compression.py`, `benchmark_membership_proof.py` and `benchmark_blind_sign.py`, which reproduce the paper's Tables 1–4 (reported on a single Tiger Lake-H core). That gets gate 1's missing ZK cost *and* gate 2's verifier time from runnable code, without the PDF. **This is the single highest-value next step on #65** and it needs no FANOS work at all.
2. **Read the parameter-selection section** once any copy of 2022/1341 becomes reachable, to close gate 3.

Neither is a reason to delay the architectural decision, because neither can change *which* system is the right one — gate 2 can only change whether a linear verifier is affordable, and if it is not, §4.2's Neo/SuperNeo is the alternative for the same reasons LaBRADOR was chosen over the rest.

Reference implementations to read rather than depend on: **LaZer** (IBM, C+Python, eprint 2024/1846 and 2026/1289 — it carries the zero-knowledge variant) for the relation-specification front end, and **condor-rs** (Nethermind, Rust) for the construction, noting it is scoped to Falcon signature aggregation and is the bare argument-of-knowledge variant, not a second ZK implementation. FANOS's own rule applies — a proof system this load-bearing is implemented in-tree against the papers, with the references used as an oracle for test vectors, not linked.

## 7. What would have to be true for this to be wrong

* **If witness-hiding is materially more expensive than the argument of knowledge** — gate 1's unquantified half — the ≈50 KB figure is not OBOLOS's figure, and every number in §3.3 needs redoing against the zero-knowledge variant. The theory is no longer in doubt; the constant factor is.
* **If the verifier is too slow** — a linear verifier at 2×10⁵ constraints costing more than a validator can spend — then proof *size* was never the binding constraint and this whole analysis optimized the wrong axis. The measurement in §1 would still stand; the conclusion would not.
* **If the ring degree turns out to be load-bearing** after all, `ring.rs` / `commit.rs` / `ring_hash.rs` are not "kept" as §5.1 claims and the adoption is substantially larger than costed.
* **If the field settles elsewhere.** LatticeFold+, Neo and SuperNeo all postdate Greyhound, and the lattice-SNARK race is visibly unfinished. Committing to LaBRADOR should be a deliberate choice made knowing that Neo/SuperNeo is a live, actively developed, same-field alternative — not a belief that the question is closed.
* **A methodological one, because it nearly happened.** Two of the three gates were nearly answered by a search-engine summary rather than a source: gate 1 by an abstract fragment that read as "ZK did not exist before 2026", and gate 2 by a fabricated-looking benchmark line. Both were caught by fetching the primary page and finding the claim absent. Any future number entering this document needs the same treatment — §8 exists so that a reader can see which ones had it.

## 8. Status of the claims in this document

| claim | basis |
|---|---|
| 145 MiB / 875 MiB, and the 78.2% shortness term | **measured**, three independent ways, at HEAD (§1) |
| LaBRADOR's relation matches OBOLOS's | paper abstract + two implementation write-ups, corroborated (§3.1) |
| 47–58 KB across 2¹⁰–2²⁰ | paper abstract (headline figure) + secondary sources (§3.2) |
| OBOLOS's statement ≈2¹⁷·⁵ constraints | **derived here** from the construction (§3.3) |
| linear verifier | two independent sources quoting the paper (§3.4) |
| Greyhound uses LaBRADOR internally | Greyhound abstract + a technical analysis of the composition (§3.4) |
| the ZK combination predates 2026; 2026/1289 supplies the first implementation | **quoted from 2026/1289's own abstract**, fetched directly (§3.5) |
| the ZK variant's size/time cost | **not established** — no source reachable states one; measurable by running LaZer's own benchmark scripts (§6) |
| LaZer carries the ZK variant, condor-rs does not | repository contents + condor-rs's own scoping statement (§3.5) |
| the ZK technique's linear term stays small on LaBRADOR's recursion | **inference**, explicitly not confirmed (§3.5) |
| `d = 64` is a convention, not a soundness requirement | two independent write-ups; the paper's parameter section is **unread** (§5.3) |
| a larger degree permits a smaller module rank | **inference** from standard Module-SIS reasoning, no LaBRADOR source (§5.3) |
| LatticeFold's Goldilocks incompatibility is a ring-structure/prime coupling | Neo's abstract, quoted (§4.2) |
| REPETITIONS = 16 traces to full splitting | eprint 2017/523 abstract; the OBOLOS-specific consequence is **inference** (§4.1) |
| prover/verifier times in seconds; full benchmark table | **not established** — every avenue tried and blocked; one circulating figure is a **lead, not a fact** (§6) |
