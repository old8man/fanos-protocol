# OBOLOS zero-knowledge backend — compact lattice proofs on the cyclotomic ring

> The value tier's crown-jewel component (`spec/platform.md` §4.3): the post-quantum, zero-knowledge proof
> backend that makes OBOLOS's two privacy properties — **confidentiality** (amounts hidden yet sound) and
> **untraceability** (which note was spent hidden) — provable without revealing the witness. It is built entirely
> on a compact **ring-BDLOP** substrate over the Goldilocks cyclotomic ring, composing vetted lattice hardness
> (Module-SIS / Module-LWE) — **no new hardness is invented**. Every module is **[P]/[H] correctness-first**: the
> constructions and their soundness/ZK arguments are the security spec and are empirically tested (completeness,
> soundness, binding, ZK re-randomisation), while the parameters `(D, q, K, ℓ, REPETITIONS, CHALLENGE_BITS)` are
> illustrative — bit-security calibration, constant-time arithmetic, and external cryptanalysis are the
> documented heavy-artillery follow-ups.

## 0. What must be proven

A shielded spend reveals on the ledger only: the tree `anchor`, one **nullifier** per input, one re-randomised
**value commitment** per input and output, the output note commitments, the public fee, and one spend-auth
signature per input. A single proof `π` must attest, in zero knowledge, the relation binding these — the two
orthogonal privacy properties:

| Property | hides | reduces to (this backend) |
|---|---|---|
| **Confidentiality** | the amount | balance (`Σin = Σout + fee`) **and** range (`0 ≤ v < 2⁵¹`) on the value commitments |
| **Untraceability** | which note | Merkle **membership** of the note commitment under `anchor` + nullifier correctness + ownership |

The transparent [`TransparentProof`](../rust/crates/fanos-obolos/src/tx.rs) proves exactly this relation *in the
clear* — it is the accounting oracle every adversarial scenario checks against. This backend is its
zero-knowledge successor.

## 1. The ring substrate, and the load-bearing insight

Everything sits on `R_q = Z_q[X]/(X^D + 1)`, `D = 256`, `q = 2⁶⁴ − 2³² + 1` (the **Goldilocks** prime;
[`ring.rs`](../rust/crates/fanos-obolos/src/ring.rs)). Goldilocks is chosen for a fast NTT (`2³² | q − 1`, so a
`2D`-th root of unity exists) — ring multiplication is `O(D log D)`. A verified drop-in **fast reduction** (the
Plonky2 `2⁶⁴ ≡ 2³² − 1` folding) replaces `x % q` on the hot path, checked equal to the modulo over 2M random
inputs.

The value commitment ([`ring_commit.rs`](../rust/crates/fanos-obolos/src/ring_commit.rs)) is ring-BDLOP:
`com(v; r) = (A₁·r, ⟨a₂, r⟩ + v)` with short (ternary) `r` — binding ← Module-SIS on `[A₁; a₂]`, hiding ←
Module-LWE, additively homomorphic (the amount lives in the constant coefficient, `q ≫ MAX_VALUE`, so message
terms add as integers).

**The subtlety that shapes the whole design.** Every compact lattice proof of a quadratic/product relation needs
a challenge set whose *pairwise differences are units* — the special-soundness extractor divides by a challenge
difference. But Goldilocks **fully splits** `X^D + 1`, so a random short (ternary) difference is *not* guaranteed
invertible. The resolution turns the liability into an asset:

- **Monomial challenges** `{X^m : 0 ≤ m < 2D}` — every element is short (`‖·‖∞ = 1`), and every difference
  `X^i − X^j` (`i ≠ j`) is **always** a unit, because `2D` is a power of two so `X^{i−j} − 1` shares no root with
  `X^D + 1`. Multiplying an opening by a monomial only permutes its coefficients, so the *revealed openings stay
  short* (binding survives) while the challenge space stays large.
- **Exact inversion** is then free: on the fully-splitting ring `R_q ≅ (Z_q)^D` slot-wise, so `a⁻¹ = INTT(slotᵢ⁻¹)`
  ([`Poly::inverse`](../rust/crates/fanos-obolos/src/ring.rs)).

This monomial-challenge / exact-inversion pair is what makes the product, range, and membership proofs sound on
this ring.

## 2. Confidentiality — balance and range

| Module | Proves | Construction |
|---|---|---|
| [`ring_zk`](../rust/crates/fanos-obolos/src/ring_zk.rs) | knowledge of a short opening `M·r = u` | single-round Fiat–Shamir with aborts; challenge is a ternary `R_q` element (`3^D ≫ 2¹²⁸`, so **one** round) |
| [`ring_balance`](../rust/crates/fanos-obolos/src/ring_balance.rs) | `Σin = Σout + fee` | the residual `Σin − Σout − com(fee)` **opens to zero** under the hidden balance randomness — an opening-to-zero proof, so the linkage-leaking randomness the transparent check reveals stays hidden |
| [`ring_product`](../rust/crates/fanos-obolos/src/ring_product.rs) | a committed `z = x·y` | Baum–BDLOP: `z₁z₂ = γ²z + γt + u`; monomial `γ` keeps openings short; `REPETITIONS` rounds under one FS seed |
| [`ring_range_agg`](../rust/crates/fanos-obolos/src/ring_range_agg.rs) | `v ∈ [0, 2^bits)` | **aggregated** (size independent of `bits`): pack bits into one poly, small scalar challenge, binarity via the Hadamard `f∘(x−f)` computed by the verifier — a Bulletproofs-style argument in the lattice setting |
| [`ring_confidential`](../rust/crates/fanos-obolos/src/ring_confidential.rs) | a whole transfer's amounts | a range proof per output + one balance proof (inputs' range holds by induction over the pool) |

The range proof is why balance is *sound*: balance alone holds only modulo `q`, so without a range bound an output
could commit a near-`q` "negative" amount and forge money (audit O-C1). The **aggregation** (`ring_range_agg`
superseding the per-bit first cut) is what makes it affordable — ~13× faster on the confidential-amount tests,
and the prerequisite for the untraceability shortness proofs below.

### 2.2 Three bounds, not one — closing wraparound completely

A range proof alone is *not* enough, and each of the following was a live inflation path found by auditing the ring
path against what the transparent one enforces:

| Bound | Why it is load-bearing |
|---|---|
| the range width is the **verifier's demand** (`RANGE_BITS`, pinned by consensus — never a per-call argument) | the aggregated proof carries its own width, so trusting that field lets the *prover* choose the bound: four outputs each just under `2⁶²` sum to `q + ε ≡ ε`, balancing against an input worth `ε` while being worth `≈2⁶⁴` in the pool |
| the cleartext **fee** `< MAX_VALUE` | the fee has no range proof, so an unbounded `fee ≈ q` makes `Σin ≡ Σout + fee` satisfiable with an output *larger* than its input — a "negative" fee |
| the **note count** `≤ MAX_NOTES_PER_TX` | even with every amount below `MAX_VALUE`, enough terms reach `q`; the constant is derived as `⌊q / MAX_VALUE⌋ − 2` so no side of the law can |

The bounds are checked *before* any proof verification, so an oversized claim cannot force wasted work. Each has a
test that constructs the forging transaction and shows it refused — the range-width test additionally verifies the
attack proof is internally consistent at the prover's own width, so the pinned width is demonstrably what stops it.

### 2.1 The aggregation, precisely

Pack the bits `b(X) = Σ bᵢXⁱ`, commit `C_b` once. Per round, for a **small scalar** `x` reveal one masked
polynomial `f = x·b + a` and check three homomorphic openings:

```text
opening:        com(f)          = x·C_b + C_a
binarity:       com(f ∘ (x−f))  = x·C_d + C_e     (d = a∘(1−2b),  e = −a∘a)
reconstruction: com(⟨f, 2^vec⟩) = x·C_v + C_w     (w = ⟨a, 2^vec⟩)
```

`x` scalar makes `f∘(x−f)` a Hadamard product the *verifier* forms from the revealed `f`; its `x²` coefficient is
`b∘(1−b)`, forced to zero → `b` binary. A non-binary `b` survives only at a degree-2 root of a random `x`
(`≤ 2/2^{CHALLENGE_BITS}` per round → `2⁻¹²⁸` over `REPETITIONS`). Only the openings that hide *witness* randomness
need wide masking; `f`'s masking is uniform.

## 3. Untraceability — zero-knowledge Merkle membership

A spend must prove its note commitment is a leaf under the public `anchor` *without revealing which leaf*. A ZK
proof of the BLAKE3 tree hash is intractable (a whole SNARK circuit). The escape (Libert–Ling–Nguyen–Wang) is a
tree hash whose relation is **linear over `R_q`**.

### 3.1 The SIS hash ([`ring_hash.rs`](../rust/crates/fanos-obolos/src/ring_hash.rs))

A node is a **short** vector `x ∈ R_q^ℓ` (coefficients `< 2^{LOG_BASE}`). For public `A₀, A₁`:

```text
hash(l, r) = G⁻¹(A₀·l + A₁·r)
```

`G⁻¹` is the gadget decomposition (split each coefficient of the `k`-element image into base-`2^{LOG_BASE}`
digits) — a bijection, so the node stays short and re-hashable and the tree compresses `2ℓ → ℓ`. Collision
resistance ← Module-SIS on `[A₀ | A₁]`. The load-bearing property: `G(hash(l,r)) = A₀·l + A₁·r` is `R_q`-**linear**
in the short `(l, r)`.

### 3.2 The proof primitives

| Module | Proves |
|---|---|
| [`ring_linear`](../rust/crates/fanos-obolos/src/ring_linear.rs) | `Σ cᵢ·mᵢ = 0` for committed `mᵢ`, coefficients `cᵢ` that may be **huge** (matrix entries) with *no `Σcᵢrᵢ` blow-up* — the `cᵢ` touch only revealed messages |
| [`ring_binary`](../rust/crates/fanos-obolos/src/ring_binary.rs) | a committed polynomial is `{0,1}`-valued (the aggregated-range binarity half, standalone) |
| [`ring_shortness`](../rust/crates/fanos-obolos/src/ring_shortness.rs) | `‖p‖∞ < 2^t` via bit-planes `p = Σ 2ʲp_j` — each `p_j` binary + a linear reconstruction |
| [`ring_membership`](../rust/crates/fanos-obolos/src/ring_membership.rs) | **hash step** (`parent = hash(left, right)` = one `ring_linear` proof), **conditional swap**, and the **path** |

The **hash step** is one `ring_linear` proof over `left ‖ right ‖ parent` with coefficients `[A₀, A₁, −gadget]`.
The **conditional swap** hides the position: a hidden bit `d` selects `left = child + d·(sibling − child)` (a
`ring_product` per limb, `d` a constant polynomial so the ring product is coefficient-wise scalar multiplication),
with `right = child + sibling − left` derived homomorphically. The **path** chains swap + hash step up the tree —
the parent commitment of level `j` is the child of level `j+1` — and ties the top node to the public root; the
leaf and every intermediate node stay hidden, and the per-level swap hides the direction bits (hence the position,
hence the note identity).

### 3.3 Swap subtlety

`d` must act as a *scalar* consistently across limbs. A per-limb `{left, right} = {child, sibling}` sum+product
check would let limbs swap independently (invalid); and a non-constant `d` makes `d·(sibling − child)` a
convolution whose result is generally *not short*, so the node **shortness** proofs reject it — the swap relies on
that rather than proving `d` constant directly.

### 3.4 Membership soundness — the sound path

`prove_path` chains the linear relations and ties leaf → root, but that alone is not sound: a prover could satisfy
the linear system with **non-short** "nodes" and forge a path (and the swap's constant-`d` guarantee rests on
shortness too). `prove_path_sound` adds a shortness proof for every *hidden* node — leaf, every sibling, every
intermediate — and checks the public root's digits directly. That is `O(depth · ℓ · LOG_BASE · REPETITIONS)`
binarity proofs: the known, inherent cost of lattice ZK Merkle membership, with recursive-SNARK compaction the
future optimisation.

## 4. The ring-native note, and how a whole spend composes

The BLAKE3 note ([`note.rs`](../rust/crates/fanos-obolos/src/note.rs)) is unusable inside a ZK proof, so the note
is rebuilt out of the *same* SIS hash as the tree — domain-separated instances, so every note relation is a chain
of linear hash steps ([`ring_note.rs`](../rust/crates/fanos-obolos/src/ring_note.rs), `NoteScheme`):

```text
tag        = hash_owner(nsk, nsk)          — the owner tag: one-way in the secret nullifier key (ownership)
note_owner = hash_rho(tag, rho)            — the ONE-TIME note key: fresh per note
cm         = hash_note(value_node, note_owner)   — the note commitment / tree leaf
value_node = ⟨digits of v base 2^LOG_BASE⟩ — one digit per limb, so ℓ = 4 limbs cover 2⁵¹
```

### 4.1 Why `rho` is load-bearing

Without it the leaf is `hash(value_node, tag)` — deterministic in *(amount, recipient)* — so two payments of the
same amount to the same recipient produce the **identical leaf**, and two independent failures follow:

- **privacy**: leaf equality is public on the tree, so an observer reads "same amount, same recipient" off
  commitments that are meant to leak nothing;
- **spendability**: an identical `cm` gives an identical nullifier `nf = hash(nsk, cm)`, so the second note is
  rejected as a double-spend — value silently destroyed.

A fresh per-note `rho` (the ring-native form of the BLAKE3 note's `rho`, and of a stealth address's one-time key)
closes both. It reaches the recipient out of band with the note's opening, since spending requires it.

`rho` makes *honest* collisions impossible by freshness — but a malicious sender could deliberately reuse it across
two outputs to the same recipient, leaving the recipient able to spend only one (griefing, no inflation). §4.2's
position-bound nullifier removes that hazard structurally.

### 4.1b The position-bound nullifier

A nullifier of `(nsk, cm)` alone is a function of the note's *contents*, so any two notes sharing a commitment share
a nullifier and only one is ever spendable. Binding the leaf's **tree position** fixes this at the root — every slot
is unique, so distinct leaves always nullify distinctly whatever their contents (the ring form of
[`nullifier.rs`](../rust/crates/fanos-obolos/src/nullifier.rs)'s audit O-M1 property):

```text
slot = hash_slot(cm, pos_node)   the position-bound note identity (hidden)
nf   = hash_nf(nsk, slot)        the public nullifier
```

The position never becomes public. The elegance is that the membership path **already commits** the leaf's index:
its per-level direction bits *are* the index in binary, and each is already proven binary by its level's swap proof.
So one [`ring_linear`](../rust/crates/fanos-obolos/src/ring_linear.rs) relation over commitments the two halves
share closes the loop:

```text
Σ_d 2^{LOG_BASE·d}·pos_d − Σ_j 2ʲ·d_j = 0
```

Without that tie the position node would be free and the binding would buy nothing — a prover could nullify one slot
while proving membership of another. With it, the nullified slot *is* the slot proven a member. (Note the bound on
`slot`: it is a *hash output*, so its shortness is always at the gadget base `LOG_BASE`, never at a caller's smaller
`bits` — that shortness is what makes the outer hash step binding.)

### 4.2 Per-input spend proof ([`ring_input`](../rust/crates/fanos-obolos/src/ring_input.rs))

Three sub-proofs over **one** note, bound by *shared commitments* (the binding is the soundness — otherwise a
spender could balance one note's amount while spending another's):

| Sub-proof | Proves | Shares |
|---|---|---|
| [`ring_note`](../rust/crates/fanos-obolos/src/ring_note.rs) | `cm = hash(value_node, hash(hash(nsk,nsk), rho))` | verified against untraceability's `cm`/`nsk` commitments |
| [`ring_value_tie`](../rust/crates/fanos-obolos/src/ring_value_tie.rs) | `value_node` encodes the amount in `Cv` | the same `value_node` commitment |
| [`ring_untraceable`](../rust/crates/fanos-obolos/src/ring_untraceable.rs) | `cm` is a tree member under the root **and** its position-bound `nf` is correct | the shared `cm`, `nsk`, and the path's own direction bits (§4.1b) |

The nullifier's outer step is a hash step with a **public output**: the verifier ties the committed hash output to
the public `nf` via a revealed randomness, exactly as the path ties its top node to the public root.

### 4.3 Per-output creation proof ([`ring_output`](../rust/crates/fanos-obolos/src/ring_output.rs))

The mirror on the output side, and a soundness gap the value commitment alone leaves open: a transaction appends
one new leaf per output and publishes one `Cv` per output, and **nothing tied them together**. A sender could
balance an output at a small amount while appending a leaf encoding a larger one, then spend that leaf for the
larger amount — value conjured, every other check satisfied. (The transparent reference has the same shape: it
checks each output `Cv` opens to a claimed amount but never binds the appended leaf to it.) With `cm` and `Cv` both
public, over hidden `value_node`, `note_owner`:

```text
cm = hash(value_node, note_owner)   public-output hash step
value_node ↔ Cv                     the value-tie
value_node, note_owner short        so cm's SIS opening is unique
```

Shortness makes the opening unique, the step binds `cm` to the committed `value_node`, the tie binds that same
`value_node` to `Cv` — so the amount extractable from the leaf *is* the amount balanced for it. It deliberately does
not constrain how `note_owner` was derived (the sender does not know the recipient's `nsk`); a sender who fixes it
wrongly only makes its own output unspendable, never anyone else's and never any extra value.

### 4.4 The whole transaction ([`ring_tx`](../rust/crates/fanos-obolos/src/ring_tx.rs))

One `prove_input` per input, one `prove_output` per output, one `ring_confidential` amount proof — sharing each
input's and output's `Cv` with the balance proof:

| Property | proven by |
|---|---|
| confidentiality (amounts hidden, sound) | balance + range over the `Cv`s |
| untraceability (which note) | membership + nullifier, per input |
| ownership | `nf` derivable only with `nsk` (and `rho`), per input |
| no spend-lock | `nf` bound to the leaf's proven tree slot, per input (§4.1b) |
| integrity (spend the note you balance) | shared `Cv`: input proof ↔ balance |
| conservation (create only what you balance) | shared `Cv`: output proof ↔ balance, per output |

`prove_shielded_tx` returns a `ProvenTx` — input leaves, **output leaves to append**, nullifiers, proof — which
[`RingShieldedTx`](../rust/crates/fanos-obolos/src/ring_tx.rs) assembles with the public value commitments into the
object consensus orders.

Note what that object does *not* carry: **spend-auth signatures**. In the BLAKE3 design a spend reveals the
nullifier key, so a separate signing key was needed to stop a broadcast transaction being re-authorised to another
recipient (audit §5.D-2). Here `nsk` is never revealed — it stays inside the proof — so the proof *is* the spend
authorization. (An unshield's public recipient must still be bound into the proof statement when that path is
ported; a pure shielded transfer has no such field.)

## 4a. The ledger — the ring-native state machine

[`ring_state`](../rust/crates/fanos-obolos/src/ring_state.rs) is where the stack stops being a library: `apply`
verifies a real `ShieldedTxProof` — no witness revealed, no transparent oracle. It keeps [`state.rs`](../rust/crates/fanos-obolos/src/state.rs)'s
gate order exactly, and is atomic (on any failure the state is untouched):

**known anchor → fresh nullifiers → capacity → valid proof → commit.**

The verdict is split out (`apply_with_verdict`) so a block verifies every proof in parallel and then commits serially
in consensus order, with an identical result — proof verification reads no ledger state.

**Why the node digest.** A ring nullifier or root is a `HashNode` — kilobytes of ring coefficients. Keying the
nullifier set and anchor window on nodes would grow executed state by kilobytes per spent note, and the block
`state_root` is 32 bytes. So the *sets* key on `HashNode::digest` (injective under the same BLAKE3 assumption the
BLAKE3-side ledger already makes), while every **soundness** check is stated over the full node inside the proof.
That lets the nullifier set and the rolling-anchor policy (`MAX_ANCHORS`, audit O-M2) be *literally the same code* as
`state.rs`'s, not a second divergent implementation of the same rules.

**The tree.** [`ring_tree`](../rust/crates/fanos-obolos/src/ring_tree.rs) is a Merkle tree over the SIS hash with
canonical empty-subtree padding, yielding the root (anchor) and the auth paths (siblings + direction bits) that
`prove_path_sound` and the §4.1b position tie consume. It maintains an **incremental frontier** — `pending[h]` is the
complete height-`h` subtree awaiting a right sibling, and appending carries upward exactly as binary addition carries
— so `append` and `root` are `O(depth)`, independent of pool size. That is not a micro-optimisation: recomputing the
root per append is `O(n)`, making a block of `k` notes `O(n·k)`, which no ledger can carry. It stays a *reference*
tree in retaining every leaf so it can produce any note's `auth_path` in `O(n)` — a wallet operation, replaced in
production by per-note incremental witnesses, with byte-identical roots and paths.

## 5. Integration roadmap

The proof stack is complete and verified; wiring it into the ledger is the "libraries-ahead → wired" step
(`docs/audit.md`). In order:

1. **Migrate the value commitment and note model** in `tx` / `build` / `wallet` / `codec` and downstream
   `fanos-dromos` from the flat-vector [`commit`](../rust/crates/fanos-obolos/src/commit.rs) to
   [`ring_commit`](../rust/crates/fanos-obolos/src/ring_commit.rs) + SIS notes.
2. **Wire `ring_tx` as `ShieldedProof`** — replacing the transparent proof as the consensus relation, with
   `TransparentProof` retained as the degraded-mode oracle.
3. **Calibrate** `REPETITIONS`, `CHALLENGE_BITS`, and `(K, ℓ, D, q)` to a bit-security target; add constant-time
   arithmetic and the merged-butterfly NTT; commission external cryptanalysis. Until then the backend stays
   **[P]/[H]** and is never claimed as production-audited.
4. **Compact the proof** — a whole-transaction proof is *minutes* to produce and, more decisively, **gigabytes** to
   transmit at a realistic tree depth. §6 measures this and derives the ladder; recursive compaction is the only route
   to a shippable spend proof, and it gates any wire codec (encoding a multi-gigabyte object is not the problem worth
   solving first).

## 6. Cost — measured, not asserted

Lattice-ZK cost is usually reported as proving *time*. For this stack **size** is the harder half, and it had been
described only qualitatively. [`ring_size`](../rust/crates/fanos-obolos/src/ring_size.rs) makes it exact: every proof
counts the `R_q` elements it consists of, and the counts are checked against the constructions in test, so they are
auditable rather than estimated. At `D = 256`, `K = 1`, `ℓ = 4`, `ℓ_H = 4`, `LOG_BASE = 16`, `REPETITIONS = 16`, with
one `u64` per coefficient (2 KiB per element):

| Component | elements | size |
|---|---|---|
| one binarity proof | 240 | 0.47 MiB |
| one hash step (linear proof, `n = 12`) | 1 440 | 2.81 MiB |
| **shortness at `t = LOG_BASE`, per limb** | 5 872 | **11.5 MiB** |
| **node shortness (`ℓ_H` limbs)** | 23 488 | **45.9 MiB** |
| node shortness in a depth-1 path (3 nodes) | | 138 MiB |
| node shortness in a depth-32 path (65 nodes) | | **2.9 GiB** |

So the dominant term is unambiguous, and it is not the hash steps or the amount proofs — it is **node shortness**,
`(2d+1) · ℓ_H · LOG_BASE` binarity proofs for a depth-`d` spend. Everything else is rounding error beside it.

### 6.1 The compaction ladder, and its ceiling

Each step below is derived, and the factor is arithmetic from the table — no guesswork:

1. **Aggregate the bit-plane binarity checks.** Rather than `t` separate proofs, commit the `t` planes and prove the
   single relation `Σ_j y^j·(p_j ∘ (p_j − 1)) = 0` for a challenge `y`: a non-binary plane leaves a nonzero degree-`<t`
   polynomial in `y`, which a random `y` kills with probability `≤ (t−1)/|challenge|`. Per round this drops the
   per-plane `c_d, c_e, z_de` (8 of 15 elements), keeping the irreducible `c_a, f, z_ba` — **≈2×**, or **≈3×** when
   aggregated across a whole node's `ℓ_H · t` planes at once.
2. **Widen the challenge to shorten the repetitions.** `CHALLENGE_BITS = 9` forces 16 rounds for `2⁻¹²⁸`. The width is
   bounded only by the masking having room above it (`MASK_WIDE` must dominate `x·witness`, and `2⁵⁷ < q` leaves
   plenty), so a `2³²` challenge needs ~4 rounds — **≈4×**.
3. **Encode short elements at their true width.** Most revealed elements are *openings* bounded by `ACCEPT_*`, not
   general elements mod `q`; ternary randomness is 2 bits per coefficient, not 64 — **≈2×** on the remainder.

Together ≈10–25×: a depth-32 spend falls from ~3 GiB to a few hundred MiB. That is the honest ceiling of
constant-factor work, and it is **still impractical** — which is precisely why production lattice systems wrap
membership in a recursive/succinct proof rather than paying for it directly. Recursive compaction is therefore not a
nice-to-have on this stack's roadmap; it is the only route to a shippable spend proof, and the numbers above are why.
The construction is sound and complete today, and it will stay `[P]` until that route is built.

## 7. Verification status

The whole backend is empirically verified — completeness, soundness (a false statement has no accepting proof),
binding, and zero-knowledge re-randomisation on every primitive — under the workspace clippy gate. It composes
vetted post-quantum hardness only; the honest frontier is calibration + external audit, isolated behind the
typed proof interfaces and never overstated.
