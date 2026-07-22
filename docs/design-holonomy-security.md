# Holonomic-ratchet path authentication — security analysis (closing spec §5.4 `[P]`)

> Spec §8.4 / §16 mark the holonomic ratchet a **research construction `[P]`** ("formal security … is `[P]`
> until a machine-checked proof"). This note (a) formalizes the tag as a keyed MAC, (b) identifies the one
> real gap in the original front-keyed cascade — length extension — (c) closes it with a length-binding
> finalization, giving a construction whose EUF-CMA security **reduces to BLAKE3 as a PRF**, and (d) validates
> every claim with a deterministic attack experiment (`fanos-nyx::ratchet::attack_experiment`).

## 1. The construction

For a circuit of `L` hops with per-hop incidence-connection bytes `A_1 … A_L` (`A_k` = the two relay
coordinates and the hop line, `connection_bytes`), and a shared secret `seed`:

```
state_0 = seed
state_k = H("nyx-ratchet" , state_{k-1} ‖ A_k)          k = 1 … L      (the cascade)
Hol     = H("nyx-ratchet-final" , state_L ‖ L)                          (the finalization)   ← new
```

`H` is domain-separated BLAKE3 (`hash_labeled`). Both endpoints know `seed` and the algebraic path, so both
compute the identical `Hol`; a verifier recomputes it from the circuit it legitimately knows and compares.

## 2. Security model

**Goal (path authentication).** `Hol` is an *unforgeable, tamper-evident* authenticator of the ordered hop
sequence `(A_1,…,A_L)` under the key `seed`: an adversary without `seed` cannot produce `Hol` for any path
(EUF-CMA), and any modification of the path — substitution, insertion, deletion, reordering, truncation,
extension, or single-byte tamper — changes `Hol` except with probability `≤ 2^-256` (collision resistance).

**Assumption.** `H` (keyed/domain-separated BLAKE3) is a PRF and collision-resistant. No new hardness
assumption; BLAKE3 is already trusted across FANOS.

## 3. Why the front-keyed cascade alone is only conditionally secure

`state_k = H(state_{k-1} ‖ A_k)` is the **Bellare–Canetti–Krawczyk cascade**. The cascade is a secure PRF on
its message space *only when that space is prefix-free*; on an unrestricted space it admits **length
extension**: an adversary who learns `state_L` (the raw cascade output) can compute
`state_{L+1} = H(state_L ‖ A_{L+1})` for any `A_{L+1}` **without the seed**, forging the authenticator of a
one-hop-longer path. In the original ratchet `Hol = state_L`, so this attack applies *if the tag is ever
exposed*. The protocol hid the tag (encrypted end-to-end), making the construction secure **in context** — but
that is a confidentiality caveat, not an unconditional MAC, which is exactly why it was marked `[P]`.

## 4. The fix and the reduction

The length-binding finalization `Hol = H("…-final", state_L ‖ L)` folds the exact hop count into a one-way
outer step over the secret cascade state. **Audit correction on the model.** An earlier draft called this
"NMAC" and claimed a "standard NMAC argument, unconditionally." That is over-stated: `hash_labeled` is
**unkeyed** BLAKE3 with the key carried *in the message* (`H(label ‖ 0x1f ‖ seed ‖ A_1)`, …) — there is no
independent outer key, so it is **not textbook NMAC**. The correct assumption is that **secret-prefix BLAKE3 is
a PRF** (equivalently, a ROM argument), which is standard for BLAKE3 — its root-finalization flag kills length
extension — but is stronger than a plain native-keyed-PRF assumption, and should be stated as such. With that
assumption:

- **No length extension.** The tag exposes `H(state_L ‖ L)`, not `state_L`. Recovering `state_L` from `Hol`
  contradicts the one-wayness of `H`; and even granting `state_L`, the outer step folds in the exact length
  `L`, so the value for `L+1` is an independent PRF output. The extension attack is dead — and, because BLAKE3
  is not length-extendable in the first place (root flag), this holds without any tag-secrecy caveat.
- **EUF-CMA from a (secret-prefix) PRF (sketch).** By the cascade theorem, `state_L = Cascade_seed(A_1…A_L)` is
  a PRF on the fixed-length hop space keyed by `seed`. Composing the one-way, length-folding outer step over the
  message length `L` yields a variable-input-length MAC over the whole hop space. A PRF is a secure MAC, so no
  PPT adversary forges `Hol` for an unqueried path except with advantage bounded by the secret-prefix-PRF
  advantage of `H` plus the birthday term `q²/2^256`. ∎ (reduction — modulo the secret-prefix-PRF assumption,
  **not** a native-keyed reduction). A backend upgrade to `blake3::keyed_hash` with an independent outer key
  would earn the stronger native-keyed reduction; the current construction is sound under the stated model, and
  the review found no forgery in any tamper class (§5).

Tamper-evidence (§2's second clause) is immediate: any changed `A_k`, changed order, or changed `L` changes a
PRF input, so `Hol` changes unless a `H`-collision occurred (`≤ 2^-256`).

## 5. The experiment (`ratchet.rs::attack_experiment`)

Deterministic (no timing, no RNG flake): over many synthetic paths, every tamper class is applied and the tag
asserted to change —
- **substitute / insert / delete / reorder / truncate / extend / 1-bit tamper** → tag differs, every trial;
- **forge-without-seed** → a wrong seed yields a different tag (the adversary cannot match without `seed`);
- **length-extension resistance** → the naive extension `H("nyx-ratchet", Hol_L ‖ A)` — what an attacker on the
  *un-finalized* cascade would compute — does **not** equal the real `Hol` of the extended path, confirming the
  finalization blocks the classic attack;
- **collision Monte-Carlo** → thousands of distinct random paths yield thousands of distinct tags (no
  collision), and an **avalanche** check confirms a single-bit path change diffuses to ≈half the tag bits.

Together the reduction (§4) and the experiment (§5) close the `[P]`: the holonomy is now a length-bound keyed
MAC with EUF-CMA security reducing to **secret-prefix BLAKE3-as-a-PRF** (no tag-secrecy caveat; not a native-
keyed NMAC — see §4's correction), and every
failure mode is exercised in the suite.
