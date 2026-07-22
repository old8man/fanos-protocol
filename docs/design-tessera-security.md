# Tessera packet security (closing the confidentiality half of spec §5.4 `[P]`)

> Spec §8.4/§16 mark *"Tessera and the holonomic ratchet"* as `[P]`. The ratchet — the *novel* construction —
> is closed in `docs/design-holonomy-security.md` (a length-bound MAC with a reduction + attack experiment).
> This note closes the other half, the Tessera **onion**, by reducing its confidentiality, unlinkability, and
> integrity to standard primitives already trusted in FANOS. Unlike the ratchet, the onion is *not* a novel
> construction — it is a Sphinx/onion-class packet — so the appropriate closure is a rigorous reduction to
> established assumptions plus the existing test coverage, not a new proof of a new object.

## The packet (`fanos-aphantos::sealed`, wire in `fanos-wire::tessera`)

A Tessera is a nested-AEAD onion: for a circuit `r_1 … r_L`, layer `k` is
`AEAD(hopkey_k , nonce_k , cmd_k ‖ inner_{k+1})`, where `hopkey_k` is derived from a **hybrid-KEM
encapsulation** (`X25519 ‖ ML-KEM-768`) to relay `r_k`'s public key, `cmd_k` is `NEXT ‖ next_coord` or the
innermost `DELIVER ‖ holonomy`, the real per-layer length rides in an **encrypted** `len` field, and every
packet is padded with hop-keyed keystream to a **constant** `TOTAL_LEN`.

## Reductions

- **Layer confidentiality (only `r_k` peels layer `k`).** `hopkey_k` is the KEM shared secret of an
  encapsulation to `r_k`; recovering it requires `r_k`'s KEM secret. Under the **IND-CCA security of the
  hybrid KEM** (X25519 ⊕ ML-KEM-768, combined with SHAKE256 — post-quantum by the ML-KEM leg, classically
  hedged by X25519) no other party derives `hopkey_k`, and under **AEAD confidentiality** the layer plaintext
  (hence `next_coord` and all inner layers) is hidden from everyone but `r_k`. A relay therefore learns only
  its own next hop — never the origin, the destination, or the payload.
- **Integrity / tamper-evidence.** Each layer is AEAD-authenticated: any modification of a layer's ciphertext
  fails the Poly1305 tag at the peeling relay (forgery probability `≤ 2^-103` per the AEAD). End-to-end **path**
  integrity is the holonomy authenticator (`design-holonomy-security.md`), now an EUF-CMA MAC.
- **Length/size unlinkability (passive observer).** Every packet on every hop is exactly `TOTAL_LEN`
  (oversized inputs are *rejected at build*, never truncated), the true length is in an encrypted field, and
  the padding is hop-keyed keystream indistinguishable from ciphertext and sharing no bytes hop-to-hop. So a
  passive network observer sees identically-sized, unlinkable packets and cannot correlate entry to exit by
  size — reducing to AEAD/keystream pseudorandomness. (The documented residual: a *processing* relay learns
  its own layer's length; full position-hiding is the flat-header Sphinx filler, a noted refinement.)
- **Endpoint unlinkability.** Combined with the **threshold sheaf** (a hop is a `t`-of-`(q+1)` line, so a
  single compromised relay cannot peel — §5.2) endpoint linkage drops to `P_hop²`, the §5.2 result; the onion
  layer above contributes the per-hop confidentiality the sheaf composes over.

## Assumptions and status

Confidentiality and integrity rest only on: **hybrid-KEM IND-CCA**, **AEAD (ChaCha20-Poly1305) security**, and
**BLAKE3 as a PRF/KDF** — all already assumed across FANOS, all with the ML-KEM leg post-quantum. No new
hardness. The construction is the standard nested-onion composition of these, and its properties are exercised
by the existing suite (`sealed.rs`: routes through every relay at constant size; a wrong relay cannot peel;
the holonomy never appears in cleartext at any hop; oversized packets rejected not truncated;
`tests/holonomy_verification.rs`: honest delivery verifies, a substituted hop is caught).

Together with the ratchet closure, this discharges the confidentiality/integrity content of the Tessera `[P]`:
what remains genuinely open is only the *machine-checked* mechanization (a proof-assistant artifact), for which
the reductions above are the specification.
