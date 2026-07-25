# The Turyn federation — FANOS's perfect three-fault integrity grammar

> A single cell detects and locates **one** faulty axis. A federation of exactly three cells locates **three**, anywhere,
> perfectly — including all three inside one member, which that member's own code could never do.

Implements UHM **T-228** (`uhm-theory/.../applied/research/syndrome-calculus.md` §8a). Code: `fanos_code::golay`.
Status markers follow the corpus: **[T]** theorem, **[D]** definition/contract, **[I]** reading, **[P]** open.

---

## 0. Why this was the right place to look

`docs/design-ergon.md` §8.4 audited the *cell's* geometry and found it extremal: `PG(2,q)` lines meet the Maekawa `√N`
quorum bound exactly, a symmetric `λ=1` BIBD **is** a projective plane (Fisher + symmetry, so no better structure with
those properties exists as a theorem), and the incidence graph is a generalised 3-gon. The cell is settled.

What was *not* settled is how cells **compose**. That asymmetry is the finding: a derived, extremal structure at one level
and a weakly-derived one at the next. This document closes it, and the answer was already in the corpus.

---

## 1. What a lone cell can and cannot do [T]

A FANOS cell's geometry *is* the Hamming(7,4) code — the Fano incidence matrix is that code's parity-check matrix
(`fanos_code::hamming`). So one faulty axis out of seven is detected and located, and by Theorem Σ (T-224) the length-7
perfect code is **unique**, so there is nothing better to reach for within a cell.

The limit matters more than the capability. At two faults Hamming(7,4) does not fail loudly — it aliases onto a *confident
wrong single-fault verdict*, which is worse than no verdict, because a self-healing controller will act on it. Extending
fault tolerance therefore cannot be done by improving the cell. It has to come from composition.

---

## 2. The construction [T]

Let `A = Ĥ` be the extended Hamming code `[8,4,4]` — a cell's **seven axes plus its parity bus** — and `B = Ĥ^mir` the
same code over the *mirror* orientation of the same Fano plane. Then `A ∩ B = {0, 1}`, and the **Turyn sum**

```
G = { (a ⊕ x, b ⊕ x, a ⊕ b ⊕ x) : a, b ∈ A, x ∈ B }
```

is the extended binary Golay code `[24,12,8]`.

Verified exhaustively in `fanos_code::golay`, not cited:

| property | expected | verified |
|---|---|---|
| codewords | `2¹² = 4096` | the Turyn map is injective |
| weight enumerator | `1 + 759x⁸ + 2576x¹² + 759x¹⁶ + x²⁴` | exact, and nothing at any other weight |
| minimum distance | `8` ⟹ `t = ⌊(8−1)/2⌋ = 3` | `T` is *derived* from `d`, not chosen |
| block parity (T-228 ii) | every block even | so the 8th coordinate **is** the bus |
| dimension / duality | `12`, self-dual | each block's own basis is its check matrix |
| punctured `[23,12,7]` | `4096·(1+23+253+1771) = 2²³` | perfect: radius-3 balls tile the cube |
| coordinate arithmetic | `23 = 3·7 + 2` | three frames plus the two surviving buses |

The coordinate geometry is therefore *exactly* three cells of seven axes each with its own bus — the layout is not imposed
on the code, it is read off it.

---

## 3. Three is forced, and forced twice [T]

By **van Lint–Tietäväinen** the only perfect binary codes with more than two words are the Hamming family (`t = 1`) and
the Golay code (`t = 3`, `n = 23`). So **no federation of four or more cells admits a perfect multi-fault grammar of any
order.** Certified-perfect integrity caps at three members — not as a design budget but as a classification theorem.

And the composition tower caps at three for a completely unrelated reason: the purity ladder
`P_crit^[m] = P_crit·3^(m-1)/(m+1)` gives `P_crit^[4] = 54/35 > 1`, past the mathematical maximum
(`fanos_ergon::D_MAX`, `docs/design-ergon.md` §2.1).

**Two independent derivations — sphere packing and purity arithmetic — cap the same quantity at the same value.** The
corpus notes this and §8b of the syndrome calculus gives the coincidence a shared skeleton via the tower ladder
`U(m) = 8m − 1`: at `m = 3`, `U(3) = 23`, the binary Golay's length, decomposing as `3·7 + 2` — three organisms plus **two
couplings**. Where the horizontal federation needs one bus punctured, the vertical 3-tower has exactly two inter-level
couplings and needs no puncture at all. **The vertical tower and the horizontal federation carry the same grammar.** [T]+[I]

That is a strong coherence result for the platform: the bound on how deep ERGON terms may nest and the bound on how many
cells may federate are the same number for two reasons that do not reference each other.

---

## 4. The mirror is the other quadratic-residue class — and the naive reading is wrong [T]

"The reversed orientation of the same plane" reads naturally as *reverse the coordinate order*. That reading is **false**,
and it was caught by construction rather than by inspection: in the binary/XOR presentation `hamming` uses (position `p`
carries address `p`), the extended Hamming code is **self-reverse**, so bit-reversal gives `A ∩ B = A` — all sixteen words
instead of two — and the Turyn sum collapses without producing Golay. `bit_reversal_would_have_been_the_wrong_mirror`
pins this so the distinction cannot be quietly re-broken.

The corpus's phrase *"reciprocal-generator frame"* is load-bearing, and in the cyclic presentation it is exact and fully
derived:

```
lines of the plane        = translates of QR(7)  = {1, 2, 4}
lines of the mirror plane = translates of NQR(7) = {3, 5, 6} = −QR(7) mod 7
```

**The mirror is literally the negation of the residue set** — the two enantiomorphic labelings of one plane, which
Theorem Σ identifies only abstractly and the federation exhibits concretely: one as member grammar, one as glue. With that
derivation `A ∩ B = {0, 1}` holds exactly, and **no generator polynomial is ever written down** — the codes are built by
closing the plane's own line-incidence vectors under XOR, so the correspondence "the incidence structure *is* the code" is
the implementation rather than a remark about it.

---

## 5. Membership is the construction read backwards [D]

No parity-check matrix is needed. Summing the three components of a Turyn triple gives `w₁ ⊕ w₂ ⊕ w₃ = x`, after which
`a = w₁ ⊕ x` and `b = w₂ ⊕ x` are forced. So

```
w ∈ G  ⟺  a ∈ A ∧ b ∈ A ∧ x ∈ B
```

— O(1), and it *is* T-228's structure rather than a re-derivation of it. The 12-bit syndrome follows the same
decomposition (three 4-bit block syndromes), and since `A` and `B` are self-dual each block's own basis serves as its
check matrix, so there is no second matrix that could drift out of step with the first.

**Decoding** searches the `1 + 24 + 276 + 2024 = 2325` patterns of weight ≤ 3 for the one whose syndrome matches. A coset
table would be O(1) and is deliberately not used: `d = 8` makes radius-3 balls disjoint, so the first match is *the*
answer (verified exhaustively — all 2325 patterns have distinct syndromes, occupying 2325 of the 4096 syndromes with the
remaining 1771 being the weight-4 cosets), and 2325 evaluations of a few XORs run once per federation epoch. No 16 KiB
table, no `alloc`, and no second derivation to keep in step.

---

## 6. The operator surface [D]

```rust
Report { axes: u8, bus_fault: bool }   // a member's observation
diagnose([Report; 3]) -> Verdict        // Healthy | Localized(Faults) | Ambiguous
```

Three contracts worth stating, each of which was a mistake first:

**The bus is a coordinate, not a checksum.** T-228(ii) says every codeword has even weight on each block, so the eighth
coordinate is the parity bus **of the codeword** — and like any coordinate it can itself be damaged. A member *observes*
its bus; it does not compute one. A constructor that derived the bus from the fault report turned three faulty axes into a
weight-4 block, pushing a correctable pattern out of range and making the federation answer `Ambiguous` for exactly the
case it exists to handle. Parity is a property of the codeword, never of the error.

**Byzantine self-reporting needs no separate path.** Every codeword's block is even, so an odd-weight observation cannot be
a codeword and lands in the syndrome as an ordinary fault coordinate. A lying member and a broken member are diagnosed by
the *same* mechanism — which is why there is no trust assumption here to get wrong, and why a member cannot make itself
look healthy by adjusting one number.

**Four faults are `Ambiguous`, not guessed.** `d = 8` gives `t = 3` and covering radius 4, so a weight-4 pattern is
detected and *not* localizable. Reporting "detected but ambiguous" is the true state, and a controller that acts on a
guess is the failure mode §1 identifies in the lone cell.

`Faults::axes()` yields in **member** order, not bit order. `bits()` is ascending in bit position, and since the least
significant block is the *last* member that would hand a caller its members backwards — a footgun removed by a
three-element sort rather than documented.

---

## 7. What this buys FANOS

| | lone cell | three-cell federation |
|---|---|---|
| faults located | 1 | **3, anywhere** |
| 3 faults in one cell | aliases to a wrong single-fault verdict | **located exactly, member and axis named** |
| Byzantine self-report | trusted | caught by the grammar |
| over-capacity behaviour | silent wrong answer | `Ambiguous`, explicitly |
| syndrome waste | none (perfect) | none (perfect) |

The middle row is the one that matters. A self-healing controller acting on a confident wrong verdict is worse than one
acting on no verdict, and that is precisely what a lone cell produces at two faults. The federation removes the failure
mode rather than lowering its probability.

---

## 8. Not yet wired [P]

- **The live federation driver.** `fanos_code::golay` is sans-I/O and complete; nothing yet gathers three cells' `Report`s
  each epoch and acts on the `Verdict`. That belongs beside DIAKRISIS's per-cell diagnosis (`fanos-diakrisis`), which today
  stops at the cell boundary.
- **Which three cells.** A federation is exactly three members, so a deployment with more cells must *partition* into
  triples, and which triples is an open design question — the natural candidate is the hierarchy's own parent-cell
  grouping (§L1), so that the federation triple is a structural fact rather than a configuration.
- **The `U(m) = 8m − 1` vertical reading.** §3 records that the vertical 3-tower carries the same grammar with two
  couplings and no puncture. Whether FANOS's hierarchy should be diagnosed *as* that tower — inter-level couplings as
  coordinates — is a genuine and attractive open question, and is the same [P] item ERGON §10 lists as "ecology dynamics".
