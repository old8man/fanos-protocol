# Cryptographic audit readiness package

> Status: **package for an external cryptographic review**, prepared against the reference
> specification (`spec/protocol.md`, v0.1) and the Rust reference implementation (`rust/crates/`)
> as of this writing. Every claim below is cited to a spec section (`§`) or a `crate/file.rs`
> path so the auditor — and this project — can check it directly against source. Claims that
> could not be independently verified in this pass are marked **TODO: verify** rather than
> asserted.

This document is the entry point for an external cryptographer or audit firm engaged before
FANOS is deployed on the real internet. It does not re-derive the protocol; it tells the auditor
**where to look, what is claimed, and what specifically needs scrutiny**, and it separates
"vetted primitive, composed" from "novel construction, unproven" — because those two classes of
code need entirely different review effort.

---

## 1. Purpose and scope

FANOS is a projective-plane-addressed (`PG(2,q)`) overlay network in the Tor/Nym/I2P anonymity
class, with an optional privacy layer (APHANTOS/NYX), hidden-service layer (CALYPSO), and
censorship-resistance layer (PROTEUS). The full architecture is `spec/protocol.md`; this package
concerns only its **cryptographic surface**.

### The project's own cryptographic-honesty stance

The spec states its position explicitly, and this package inherits it as the review frame
(`spec/protocol.md` line 56, restated in Part VIII and the closing note):

> "Cryptographic honesty: **the novelty of FANOS is the architectural composition of vetted
> primitives, not new hardness assumptions.** The single genuinely new construction (the NYX
> threshold-sheaf Tessera packet, §V) is tagged **[P]** — it needs formal cryptanalysis before
> production. We do NOT invent new mathematical hardness 'from scratch.'"

Concretely: every discrete-log-family operation in the codebase (VRF, threshold beacon, VOPRF
credits, Shamir/Feldman VSS, DKG) rests on the **ristretto255** group — the same group and the
same decisional Diffie–Hellman-family assumption already relied on for nothing new; every KEM/AEAD
operation rests on vetted RustCrypto implementations of standardized primitives (X25519, ML-KEM-768,
Ed25519, ML-DSA-65, ChaCha20-Poly1305, BLAKE3/SHAKE256). What is genuinely novel, and therefore
what an audit should spend the most time on, is **how these primitives are composed** — nested
per-hop AEAD keyed by Shamir-shared, individually KEM-sealed secrets over a threshold *line* rather
than a single node. Section 2 is the priority list for that review.

### Document status of the spec being reviewed

The spec (`spec/protocol.md`) tags every nontrivial claim **[T]** (theorem, proven/computed),
**[C]** (conditional on a named assumption), **[H]** (hypothesis, needs proof), or **[P]** (program
— a direction of work, not yet audited). This package preserves that tagging because it is exactly
the signal an auditor needs: **[T]/[C]** items are combinatorial/algebraic claims verified by the
project's own test suite and conformance vectors (in scope for spot-checking, not for
cryptanalysis); **[H]/[P]** items are the ones that need a cryptographer's judgment.

### In scope

- The hybrid KEM and signature primitives and their combiner (`fanos-pqcrypto`).
- The coordinate VRF and the threshold randomness beacon (`fanos-vrf`, `fanos-keygen`).
- Threshold secret sharing / VSS / DKG (`fanos-primitives::shamir`, `fanos-vrf::vss`,
  `fanos-vrf::dkg`, `fanos-keygen`).
- The NYX Tessera packet and the threshold-sheaf onion, in both its reference (`fanos-nyx`) and
  production KEM-sealed (`fanos-aphantos`) forms.
- The holonomic ratchet / path-authenticator (`fanos-nyx::ratchet`).
- CALYPSO threshold-hosted service identity and rendezvous derivation (`fanos-calypso`).
- The ONOMA self-certifying naming layer's address commitment (`fanos-onoma::address`).
- Anonymous relay credits (VOPRF, `fanos-incentives`).
- The canonical wire encoding of all of the above (`fanos-wire`) and its known-answer test (KAT)
  vectors (`conformance/vectors/`).

### Out of scope for this package

- **DIAKRISIS** (Part VI of the spec) — the self-diagnosis/health-monitoring plane. Its "coherence
  matrix" mathematics is linear algebra over health-signal correlations, not cryptography; it has
  no bearing on confidentiality or unlinkability guarantees. (`docs/design-testing.md`,
  `docs/network-threat-model.md` cover it.)
- **Hierarchy/routing** (`fanos-core`, `fanos-runtime`, overlay engine logic) except where it
  touches identity/coordinate binding (covered under the VRF item above).
- **PROTEUS** morph/obfuscation logic (Part XIII) beyond the beacon-rotated shaping KDF, which is
  a straightforward domain-separated `hash_xof` call, not a novel construction — flagged in §3 for
  completeness, not because it needs cryptanalysis.
- **DIAKRISIS/consensus/performance** numeric claims (the V1–V22 verifier, `fanos_verify.py`) —
  these are projective-geometry and combinatorics claims, reproducible independently of
  cryptographic review.
- Non-cryptographic engineering defects (flow control, backpressure, timeouts) tracked in
  `docs/audit.md` Part C — out of scope for a cryptographer, in scope for a systems reviewer.

---

## 2. Priority list — constructions needing formal cryptanalysis

These are every construction the spec itself tags **[P]** ("needs formal cryptanalysis before
production") or that composes vetted primitives in a way novel enough to warrant the same
scrutiny. Ordered by priority.

### 2.1 The Tessera packet (headline item)

**What it is.** A fixed-size, nested onion packet in which each layer is not addressed to a single
relay's key but to a **line** of `q+1` members: the sender AEAD-encrypts the routing command under
a fresh symmetric key `K`, Shamir-splits `K` into `q+1` shares (threshold `t`), and individually
hybrid-KEM-seals each share to its member's public key. Peeling a layer needs `t` cooperating
members; below `t`, `K` is information-theoretically unrecoverable even to a party holding the
entire packet and every sealed share (the shares are ciphertext, not plaintext-split-among-holders).

**Claimed security property.** Endpoint linkage (the Tor guard+exit analogue) drops from `f²` to
`P_hop²` where `P_hop = P(Binomial(q+1, f) ≥ t)` — many orders of magnitude smaller for realistic
adversary fractions `f ≤ 0.3` (spec §5.2, worked numerically in `fanos-nyx/src/security.rs`).

**Where implemented** (two forms — an auditor should review both and understand why they
coexist):

| Form | Crate/file | Hop unit | Shares | Notes |
|---|---|---|---|---|
| Reference (`no_std`) sheaf | `fanos-nyx/src/sheaf.rs`, `fanos-nyx/src/tessera.rs` | single relay's AEAD layer, `q+1`-way Shamir split | **carried in the clear** in the packet | Explicitly documented as the transparent form: "the shares are carried in the clear, so its below-threshold guarantee holds only when each share is delivered privately to its member" (`sheaf.rs` module doc). This is a test/simulation form, not the production wire format. |
| Production KEM-sealed | `fanos-aphantos/src/threshold.rs` (`ThresholdSealed`, `seal_onion`/`peel_onion`) | a **line**: each Shamir share is individually hybrid-KEM-sealed (`X25519+ML-KEM-768`) to its member's public key before transmission | never in the clear | This is the construction that actually delivers the spec's "genuine zero-knowledge below threshold, not merely information-theoretic secrecy among cooperating members" claim (spec §5.2). Fixed wire bucket `THRESHOLD_ONION_LEN = 20480` bytes. |
| Single-relay hybrid-KEM onion | `fanos-aphantos/src/sealed.rs` | one relay per hop (APHANTOS-Lite, Sphinx-class — not the threshold sheaf) | n/a | Constant `ONION_LEN = 8192` bytes, matches spec §7.7 exactly. This is the wire format currently in the KAT set (`conformance/vectors/wire.json`'s `tessera_layout`); see §6 for the corresponding gap in the KAT set for the threshold-line form. |

**What an auditor should focus on:**

1. **The sender-dealt, no-line-DKG design decision.** The spec is explicit that this is a
   *deliberate divergence* from a single joint `PK_L` per line (§5.2 note "Interop deviation — no
   line DKG, no single `PK_L`"): each Tessera build is a fresh Shamir dealing sealed with fresh KEM
   encapsulations, so there is no long-lived line secret to compromise and no DKG liveness
   dependency. The claimed benefit is real (no line-wide secret, forward secrecy per encapsulation)
   but it means **the sender learns and momentarily holds the plaintext key `K` and constructs
   every member's share** — the sender is a trusted dealer for that one packet. An auditor should
   verify this trust placement is consistent with the anonymity goals (the sender is, definitionally,
   the party who already knows the packet's contents, so this is likely sound — but it should be
   checked against the "genuine zero-knowledge... not merely information-theoretic" claim, which is
   about a *third party* holding the packet, not the sender).
2. **Nonce and key derivation determinism.** Per-hop keys, nonces, and Shamir/KEM randomness are
   all derived by `hash_labeled`/`hash_xof` from a single `seed` (`fanos-aphantos/src/threshold.rs`
   lines ~309–325, `fanos-nyx/src/tessera.rs` lines ~116–124). In production this `seed` must be
   fresh CSPRNG output per packet; verify there is no path by which a stale or predictable seed
   reaches this code (the deterministic-seed pattern is intentional for the simulator and tests —
   confirm production callers never share it with the test harness's fixed seeds).
3. **The fixed-bucket padding.** Both onion forms pad to a constant size (`8192` B / `20480` B)
   with keystream-derived filler so a passive observer cannot link hops by shrinking size. The
   `fanos-aphantos/src/threshold.rs` module doc records a known **residual**: "the per-layer
   `ct_len` in the header is cleartext, so a party holding the *decrypted* packet... can read the
   layer size" — this is explicitly *not* hidden from an on-path relay that has already decrypted
   its own layer, only from a passive network observer. Confirm this residual is acceptable for the
   threat model in §4.
4. **The holonomy is never a cleartext header field.** An earlier revision apparently carried a
   cleartext `holonomy_tag` for cross-hop path verification; the current wire format
   (`fanos-wire/src/tessera.rs`, `fanos-aphantos/src/sealed.rs`) moves it **inside** the innermost
   `DELIVER` command, AEAD-encrypted end-to-end, specifically because a constant per-circuit
   cleartext tag would be a perfect cross-hop correlator (spec §7.7's own warning; regression test
   `the_holonomy_is_not_a_cleartext_cross_hop_correlator` in `fanos-aphantos/src/sealed.rs`). Worth
   independent confirmation that no other field (nonce, `kem_ct`, padding-derivation input) leaks
   an equivalent correlator by construction.
5. **Replay / path-confirmation defense.** `fanos-aphantos/src/sealed.rs::replay_tag` derives a tag
   from the KEM ciphertext to let a relay reject a replayed cell cheaply before decapsulating.
   Confirm the tag itself does not leak linkage information and that the "bounded set of forwarded
   tags" retention policy (implementation-dependent, not shown in this file) is sized correctly
   against the intended replay window.

### 2.2 The holonomic ratchet (path authenticator)

**What it is.** A one-way KDF chain over the "incidence connection" of each hop
(`fanos-nyx/src/ratchet.rs`): `β_k = KDF(state ‖ A(p_{k-1}, p_k))`, `state ← β_k`. The final `state`
(`Hol`) is carried inside the encrypted `DELIVER` command as a 32-byte tag.

**Claimed security property.** Two things, tagged differently by the spec and worth separating:

- **Forward secrecy [C], not from this ratchet.** The code's own doc corrects a possible
  misreading of the spec: "*Forward secrecy* of the routed onion comes from the per-hop **hybrid
  KEM**... not from this ratchet (whose chain is entirely sender-derived)" (`ratchet.rs` module
  doc). The ratchet by itself provides no forward secrecy; that property is carried entirely by the
  hybrid-KEM sealing described in §2.1.
- **Path/tamper authentication [H], the ratchet's actual claimed job.** Spec §5.4: "A compact path
  authenticator **[H]**... inserting/substituting a hop breaks the holonomy." This is a hypothesis,
  not a proven property. §8.4's red-team table restates it as "holonomy tag breaks on any hop
  insertion/substitution — **[H] (formal audit [P])**."

**Where implemented.** `fanos-nyx/src/ratchet.rs` (`Ratchet::advance`, `circuit_holonomy`,
`verify_holonomy`); consumed by `fanos-aphantos/src/sealed.rs::{build, verify_delivery}`.

**What an auditor should focus on:**

1. **This is a MAC-like construction built from a plain hash chain, not a proven MAC.** `advance`
   is `hash_labeled(RATCHET_LABEL, state ‖ connection_bytes)`. There is no keyed authentication
   against a third party who does not already know `seed` — verification
   (`verify_holonomy`/`verify_delivery`) is explicitly documented as "meaningful only for a verifier
   who already has legitimate knowledge of `circuit`" (the code's own doc, `ratchet.rs` and
   `sealed.rs::verify_delivery`), i.e., it authenticates the path to someone who built or was told
   the circuit end-to-end — it is not a public verifiability mechanism. Confirm this scoping is
   correctly enforced everywhere `verify_delivery` is called (a caller checking an *assumed* rather
   than *known* circuit would defeat the anonymity property the code's own comment warns about).
2. **No formal model.** The spec is explicit (§5.4 warning box): "a rigorous cryptographic
   formalisation (model, reduction, a PQ version of the blinding) is **[P]**... we honestly mark
   this as a research construction, not as ready-proven security." A Tamarin/ProVerif-style
   symbolic model, or a game-based reduction, is the concrete deliverable an auditor should scope.
3. **Collision/substitution resistance rests entirely on the underlying hash** (BLAKE3 via
   `hash_labeled`) and on `connection_bytes` actually being injective enough in the two relay
   coordinates and the hop line (`fanos-nyx/src/ratchet.rs::connection_bytes`, a 36-byte
   big-endian encoding of three projective triples). Worth checking whether a crafted alternate
   circuit could produce colliding `connection_bytes` sequences within the small field sizes FANOS
   uses in practice (`GF(31)`, `GF(127)`, etc. — small enough that an exhaustive-search argument,
   not just an asymptotic hash-collision argument, may be warranted).

### 2.3 PQ-VRF (post-quantum upgrade of the coordinate VRF)

**What it is today.** `vrf-r255`: an RFC 9381-*style* VRF over ristretto255 (classical, not
post-quantum — security rests on the ristretto255 discrete-log/DDH assumption). See §3 for the
exact instantiation; it is a vetted, deployed construction, not itself [P].

**The [P] item.** The spec (§L6 table) tags a **future post-quantum VRF** "standard / [P]", and §L3
separately notes "A post-quantum variant is [P] (hash/lattice VRF beacons — an active direction)."
**No PQ-VRF is implemented in the current codebase** — confirmed by inspection of
`fanos-vrf/src/lib.rs`, which implements only the classical ristretto255 construction. An auditor
should treat this as: the *current* VRF is a vetted classical construction (in scope for normal
review, not novel-construction review); the *future* PQ-VRF does not yet exist to audit.

### 2.4 PQ threshold beacon (post-quantum upgrade of the DVRF beacon)

**What it is today.** A pairing-free threshold DVRF over ristretto255 with Chaum–Pedersen DLEQ
proofs (`fanos-vrf/src/beacon.rs`) — see §3 for the exact instantiation. Also a vetted, deployed
classical construction.

**The [P] item.** Same pattern as §2.3: the spec tags a future **post-quantum beacon** "standard /
[P]." Not implemented. The beacon's unpredictability today rests on ristretto255 DDH, the same
assumption as everywhere else in the suite — **not** on pairing-based BLS (a deliberate deviation,
covered in §3).

### 2.5 PQ verifiable shuffle (unimplemented)

**What it is.** The spec's L6 table lists "Verifiable shuffle | Bayer–Groth argument (classical); PQ
shuffle | standard / [P]" and §8.3 says the interim plan is "a classical shuffle proof over PQ
transport." **Neither the classical Bayer–Groth argument nor any PQ shuffle is implemented in the
codebase** — a repository-wide search for shuffle-proof constructions turns up no hits outside of
unrelated uses of the word "shuffle" (epoch/coordinate reshuffling, an entirely different concept).
APHANTOS-Full's "verifiable mixing" (spec §L5 profile table, echoed in doc comments in
`fanos-nyx/src/profile.rs`) is, in the current implementation, **Poisson-delay statistical mixing**
(`fanos-nyx/src/mixing.rs`) plus the threshold-sheaf hop construction of §2.1 — there is no
zero-knowledge shuffle-correctness proof backing the word "verifiable" in that phrase yet. An
auditor evaluating APHANTOS-Full's mixing-integrity claim should know this gap exists rather than
assume a Bayer–Groth-style proof is present. **TODO: verify** whether this is tracked as a known
gap elsewhere in the project's own issue tracking; it is not called out as a resolved item in
`docs/audit.md`.

### 2.6 Out of the priority list, but worth a note: the naming/petname layer

Spec §12.8 tags a human-readable petname layer atop CALYPSO's self-certifying addresses "**[P] and
out of protocol scope**" — deliberately, so CALYPSO needs no naming authority. The project has since
built `fanos-onoma` (see §3), which is considerably more developed than "out of scope" suggests: it
includes a full self-certifying address commitment, a GNS/DNS-style signed-zone layer, and an
optional registry interface (`fanos-onoma/src/lib.rs` module doc). Its core address commitment
(`fanos-onoma::address`) is in scope for this audit as a vetted-primitive composition (§3); its
zone/registry layers are a naming-system design question, not primarily a cryptanalysis target, and
are not covered further here.

---

## 3. Vetted primitives and their exact instantiation

| Purpose | Primitive | Standard / reference | FANOS instantiation | Code location |
|---|---|---|---|---|
| Signature | Ed25519 ‖ ML-DSA-65 (hybrid, both must verify) | Ed25519 (RFC 8032); ML-DSA-65 (FIPS 204) | `HybridSignature` = `Ed25519(64B)` ‖ `ML-DSA-65(3309B)`; `HybridVerifier::verify` requires **both** components to verify | `fanos-pqcrypto/src/sig.rs` |
| KEM | X25519 ‖ ML-KEM-768 (hybrid) | X25519 (RFC 7748); ML-KEM-768 (FIPS 203) | See combiner detail below | `fanos-pqcrypto/src/kem.rs` |
| AEAD | ChaCha20-Poly1305 | RFC 8439 | One shared `seal`/`open` (32B key, 12B nonce, 16B tag) used by every layer/cell/descriptor seal in the stack | `fanos-primitives/src/aead.rs` |
| Hash / XOF | BLAKE3 (general hashing, domain-separated); SHAKE256 (PQ-KDF, hybrid-KEM combiner) | BLAKE3; SHA-3/SHAKE (FIPS 202) | All hashing goes through one `hash_labeled`/`hash_xof` with a constant ASCII domain label prefixed before a `0x1f` unit separator | `fanos-primitives/src/hash.rs`; SHAKE256 combiner in `fanos-pqcrypto/src/kem.rs` |
| Coordinate VRF | `vrf-r255` (RFC-9381-*style*, ristretto255) | RFC 9381 as a *style* reference, not a conformance target (see deviation below) | `coord = MapToPoint(VRF(vrf_sk, node_id ‖ epoch_low32 ‖ beacon_seed))`; total (seed always yields a valid key via wide mod-order reduction) | `fanos-vrf/src/lib.rs` |
| Threshold randomness beacon | Pairing-free threshold DVRF: ristretto255 partials `σ_i = s_i·M(epoch)` + Chaum–Pedersen DLEQ, Lagrange-combined in the exponent | drand-class threshold beacon design, re-based on ristretto255 (not BLS — see deviation below) | `SEED(epoch) = H("beacon-seed" ‖ epoch ‖ σ)`, `σ = x·M(epoch)`, unique per `(Y, epoch)`, subset-independent | `fanos-vrf/src/beacon.rs` |
| Threshold sharing | Shamir SSS (`GF(256)` byte-wise) + **Feldman** VSS (ristretto255 commitments `C_j = a_j·G`) | Shamir (1979); Feldman VSS (1987) | `fanos-primitives::shamir` (raw Shamir, used for onion-layer keys and CALYPSO identity shards); `fanos-vrf::vss` (Feldman-verifiable, used for the beacon/DKG group secret) — **two separate sharing primitives for two separate trust models**, see note below | `fanos-primitives/src/shamir.rs`; `fanos-vrf/src/vss.rs` |
| DKG | Interactive multi-dealer Feldman-VSS DKG with a complaint/justification round (GJKR-style) | Gennaro–Jarecki–Krawczyk–Rabin | Algebraic core in `fanos-vrf::dkg` (deal/ingest/qualify); the live, Byzantine-robust networked protocol engine (authenticated commit/complaint/justify frames, `QUAL` computation) is `fanos-keygen::DkgNode` | `fanos-vrf/src/dkg.rs`; `fanos-keygen/src/lib.rs` |
| Threshold decryption / combination | Non-interactive Lagrange-at-zero combination in the exponent (beacon) and of reconstructed keys (Shamir/CALYPSO) | — | `fanos_vrf::vss::lagrange_coeffs_at_zero`; `shamir::reconstruct` | `fanos-vrf/src/vss.rs`; `fanos-primitives/src/shamir.rs` |
| Verifiable shuffle | — | Bayer–Groth (spec-named); PQ shuffle | **Not implemented** — see §2.5 | — |
| Anonymous credits | Bespoke VOPRF on ristretto255: BLAKE3-XOF hash-to-curve, Chaum–Pedersen DLEQ issuance proof, context-bound redemption authenticator | Privacy Pass *in spirit* (not RFC 9497/9578 wire-compatible — see deviation below) | `N = k·H(x)`; redemption presents `(x, H(N ‖ context))`, never `N` itself, so cross-context replay is impossible; double-spend detected on `x` | `fanos-incentives/src/lib.rs` |
| CALYPSO / self-certifying address commitment | `BLAKE3-256` commitment to the hybrid PQ key bundle, bech32m + BCH-checksum + version-byte encoded | — | `addr = version(1) ‖ BLAKE3-256(bundle)`; second-preimage resistance ⇒ forging a different key under the same name needs `2^128` work even against a quantum adversary | `fanos-onoma/src/address.rs` (supersedes the spec §12.1 literal `base32(BLAKE3(pubkey))` text — see note below) |
| Node identity / long-term ID | `BLAKE3` of the canonical `sig ‖ kem ‖ vrf` public-key bundle | — | `NodeId = hash_labeled(NODE_ID_LABEL, sig.encode() ‖ kem.encode() ‖ vrf.to_bytes())` — commits to the VRF key too, so a coordinate proof cannot be transplanted onto a different identity | `fanos-pqcrypto/src/identity.rs`; byte-model mirrored in `fanos-primitives/src/keys.rs` |

### 3.1 The hybrid KEM combiner — exact construction

This is a specific, load-bearing detail the spec calls out and the auditor should verify against
the code directly (`fanos-pqcrypto/src/kem.rs`, function `combine`, lines ~86–103):

```
session_key = SHAKE256( LABEL ‖ x25519_ss ‖ mlkem_ss ‖ x25519_ephemeral ‖ mlkem_ct ‖ x25519_recipient_pk )
```

i.e., SHAKE256 over the **full transcript** — both raw shared secrets, the X25519 ephemeral public
key, the ML-KEM-768 ciphertext, and the recipient's static X25519 public key — not a bare
concatenation of the two shared secrets alone. This matches X-Wing/MAL-BIND-K,PK,CT combiner
guidance: binding the ciphertext and recipient key into the KDF input prevents a re-encapsulation
or key-reuse attack from binding one derived key to two different contexts. The ML-KEM encapsulation
key itself is bound transitively, since `mlkem_ss = decap(dk, ct)` and `ct = encap(ek)`.

A second, related check both `encapsulate` and `decapsulate` perform: the X25519 leg's
Diffie–Hellman output is checked for **contributory behavior**
(`x_ss.was_contributory()`, `curve25519-dalek`'s constant-time check) and the ciphertext/recipient
key is **rejected outright** — not silently downgraded to ML-KEM-only security — if the X25519 leg
is the low-order/all-zero degenerate point. Both directions are covered by dedicated tests
(`a_low_order_x25519_ephemeral_is_rejected_on_decapsulate`,
`encapsulating_to_a_low_order_x25519_recipient_key_is_rejected`, `fanos-pqcrypto/src/kem.rs`).

> **Note for the audit-package curator:** `docs/audit.md`'s own entry for this issue (B5,
> `fanos-pqcrypto/src/kem.rs`) currently reads "the contributory... check remains open" as a
> residual. That text is **stale relative to the current source** — the check is present in both
> `encapsulate` and `decapsulate` with passing regression tests, as cited above. Refresh
> `docs/audit.md`'s B5 entry before handing this package to an external auditor, so audit time is
> not spent re-confirming an already-fixed issue. The transcript-binding half of B5 (the SHAKE256
> full-transcript combiner) is correctly marked resolved in that same document.

### 3.2 Interop deviations — deliberate, single-curve choices

The spec is explicit (§L6 note, "Interop deviations — one pairing-free curve, not two trust
bases") that three rows above are **intentional** departures from the literally-named RFC/protocol,
made to keep the whole suite on one pairing-free curve (ristretto255 — the same group the
X25519/Ed25519 hybrid already uses) instead of introducing a second, pairing-friendly trust base
for BLS alone. An auditor should evaluate these as *what they are* — bespoke constructions on a
well-studied group — not penalize them for failing to match a differently-named RFC's exact
ciphersuite:

- **VRF.** `vrf-r255` is RFC-9381-*style* on ristretto255, **not** the RFC's own
  `ECVRF-EDWARDS25519-SHA512` ciphersuite, and not byte-compatible with it. Confirmed in code: the
  crate doc for `fanos-vrf` states this directly ("it is *not* the `ECVRF-EDWARDS25519-SHA512`
  ciphersuite of RFC 9381 and is not wire-compatible with it, so the RFC is a reference, not a
  conformance claim").
- **Beacon.** A pairing-free threshold DVRF (ristretto255 Diffie–Hellman partials + Chaum–Pedersen
  DLEQ), **not** threshold-BLS. Confirmed in code: `fanos-vrf/src/beacon.rs` module doc states the
  unpredictability rests on "the ristretto255 discrete-log/DDH assumption — the same assumption the
  X25519/Ed25519 hybrid already rests on, so no new hardness is introduced," and explicitly
  contrasts this with "the spec's nominal threshold-BLS."
- **Anonymous credits.** A bespoke VOPRF on ristretto255 (BLAKE3-XOF hash-to-curve, bespoke
  Chaum–Pedersen DLEQ) — Privacy Pass *in spirit* but **not** RFC 9497/9578 wire-compatible.
  Confirmed in code: `fanos-incentives/src/lib.rs` module doc states this directly, including that
  an earlier version of the same doc overclaimed RFC conformance and was corrected
  (`docs/audit.md` B8).

**A conformant implementation MUST use these three ristretto255-based constructions for wire
interoperability** — a clean-room implementation coded to the literal RFC 9381 /
threshold-BLS / RFC 9497-9578 citations will not interoperate with FANOS. This is a wire-format
fact, not a security concern, but an auditor benchmarking FANOS's VRF/beacon/credits against
published RFC 9381/9497 test vectors should know upfront that a mismatch is expected and correct.

### 3.3 Two Shamir/VSS constructions, deliberately not unified

FANOS uses **plain Shamir sharing** (`fanos-primitives::shamir`, no commitments, dealer trusted) in
two places — NYX onion-layer keys (§2.1) and CALYPSO service-identity shards
(`fanos-calypso::hosting::shard_service_key`) — and **Feldman-VSS** (`fanos-vrf::vss`, dealer's
polynomial coefficients committed as `C_j = a_j·G` so a bad share is caught by the recipient) for
the beacon/DKG group secret (`fanos-vrf::dkg`, `fanos-keygen`). This is a deliberate, documented
trust-model distinction, not an inconsistency: `fanos-calypso/src/hosting.rs`'s module doc explains
that a CALYPSO operator legitimately holds its own service secret in full before any sharing
happens (there is no adversarial dealer to defend against at deal time), so Feldman's extra
verifiability buys nothing there, whereas the beacon/DKG's `q+1` parties are **mutually
distrusting**, where a cheating dealer is a real threat GJKR-style disqualification defends against.
An auditor should confirm this trust-model separation is sound and that no code path accidentally
uses the unverified Shamir primitive in a context with an untrusted dealer.

**Note on "Feldman/Pedersen VSS":** the spec's L6 table lists "Shamir SSS + Feldman/Pedersen VSS."
The implementation is **Feldman VSS only** — single-generator commitments `C_j = a_j·G`, which are
*binding* but not *hiding* (a verifier who can solve discrete log, or who is given enough shares,
learns information about the coefficients from the commitments themselves). **Pedersen VSS**
(two-generator, `C_j = a_j·G + b_j·H`, unconditionally hiding) is not implemented. For the current
use cases (a beacon/DKG group secret that is not itself meant to stay hidden from the group, only
reconstructed by a threshold) Feldman's guarantees appear sufficient, but an auditor should confirm
no downstream use case needs Pedersen's hiding property that Feldman does not provide.

### 3.4 Spec-named primitives not (yet) present in code

Two rows of the spec's L6 table name an alternative that the current Rust implementation does not
build:

- **AEAD.** Spec: "ChaCha20-Poly1305 (portability) / AES-256-GCM (HW)." Only ChaCha20-Poly1305 is
  implemented (`fanos-primitives/src/aead.rs`); no AES-256-GCM path exists anywhere in
  `rust/crates/*/src/`.
- **Signature.** Spec: "Ed25519 + ML-DSA-65; conservative opt. SLH-DSA (SPHINCS+)." Only the
  two-primitive hybrid is implemented (`fanos-pqcrypto/src/sig.rs`); no SLH-DSA/SPHINCS+ path
  exists anywhere in the workspace.

Neither is a security defect — the shipped primitives (ChaCha20-Poly1305, Ed25519+ML-DSA-65) are
each independently sufficient per the spec's own reasoning — but an auditor should not expect to
find these optional/alternative paths in code.

### 3.5 A spec-vs-code drift worth flagging: CALYPSO address encoding

Spec §12.1 literally describes a CALYPSO address as
`` `<base32(BLAKE3(service_pubkey))>.fanos` ``. The current implementation has moved this
construction into the more general `fanos-onoma` naming layer (§2.6, §3): the commitment hash is
still `BLAKE3-256` over the canonical key bundle (same primitive, same security argument), but the
encoding is now bech32m with a BCH checksum and a leading version byte
(`fanos-onoma/src/address.rs`), not base32, and the known-answer vectors for it live in
`conformance/vectors/names.json`, not `services.json` (`services.json` itself now carries a comment
pointing to this: "CALYPSO service addresses are now ONOMA addresses... strictly superseding the
earlier base32(BLAKE3(pubkey)) scheme"). An auditor reviewing address-commitment security should
review `fanos-onoma::address`, cross-checked against `names.json`, rather than the spec's literal
§12.1 text.

---

## 4. Threat model and trust assumptions

### 4.1 Adversary profiles (spec §3.2)

| Profile | Description | FANOS's structural answer |
|---|---|---|
| T1 | Passive local observer (ISP sniffer) | PQ-hybrid TLS/QUIC |
| T2 | Global passive adversary (sees all traffic) | APHANTOS-Full mixing + structurally-balanced cover traffic |
| T3 | Active adversary controlling a fraction `f` of nodes (insert/drop/timing) | NYX threshold `t` of `q+1` per hop |
| T4 | Sybil (mass of fake nodes) | Geometric centrality cap `(q+1)/N` + pluggable Sybil admission |
| T5 | Quantum (future cryptanalytically-relevant quantum computer) | ML-KEM + ML-DSA hybrid; hash-based signatures as a further-conservative option (not yet built, §3.4) |
| T6 | Coercive (seizure of one node) | Below-threshold knowledge is zero (Shamir/KEM-sealed threshold construction, §2.1) |

### 4.2 Key security assumptions (spec §3.2, verbatim, numbered)

These three assumptions are what the entire quantitative security curve in spec §8 (and the
`fanos-nyx/src/security.rs` binomial-tail computation) is conditioned on. If any fails, the
corresponding numeric guarantee does not hold — an auditor should treat verifying these as
foundational, prior to reviewing any single construction in §2.

1. **"Coordinate assignment is VRF-verifiable and not cheaply grindable... an adversary with a
   fraction `f` of nodes ends up as ≈ a fraction `f` of every line (random placement)."** Tagged
   **[C]** "under a working Sybil admission." **What breaks if it fails:** the entire binomial-tail
   security curve (§2.1's `P_hop`) assumes uniform-random adversary placement into lines; a
   grindable coordinate lets an adversary concentrate its `f` fraction into chosen lines, which can
   push `P_hop` for those lines to 1 regardless of the network-wide `f`. **Implementation status:**
   the verifiable, identity-bound coordinate VRF is implemented and is the live coordinate
   authority for the base cell (`fanos-vrf::{prove_coordinate, verify_coordinate}`, wired into
   `fanos-core::membership` and proven in `HELLO` per `docs/design-coordinates.md` §4, "Level A" —
   confirmed done). A non-VRF, non-verifiable placeholder derivation
   (`fanos_primitives::vrf::coordinate_for`) still exists in the codebase but is explicitly
   documented as "**not** unforgeable... the no_std addressing reference," not the live security
   primitive (module doc, `fanos-primitives/src/vrf.rs`).
2. **"The adversary cannot predict the epoch reshuffle (the beacon is unpredictable) ⇒ cannot
   'pre-settle' into a target line."** **What breaks if it fails:** an adversary that can predict a
   future epoch's beacon (or coordinate/rendezvous-line derivation) can pre-position nodes onto a
   target's future lines, defeating the anti-eclipse and rendezvous-unpredictability guarantees
   throughout Parts V/XII/XIII. **Implementation status:** the unpredictability primitive itself
   (the threshold DVRF beacon, §2.4/§3) is implemented and verifiably unbiasable/unpredictable
   below threshold. Per `docs/design-coordinates.md` §4 ("Delivery levels"), the *live per-epoch
   reshuffle operation* — nodes re-deriving and re-announcing coordinates on every `BeaconReady`
   event in a running network — is recorded as **"Level B (tracked follow-up)"**, distinct from the
   already-delivered "Level A" (the VRF/beacon primitives themselves). An auditor should confirm
   the current state of Level B before relying on assumption 2 holding in a live deployment, as
   opposed to holding for the primitives in isolation. **TODO: verify** current Level B completion
   status at audit time — this document reflects the state recorded in
   `docs/design-coordinates.md` as of this pass, and the project's own working notes describe it
   as still in progress.
3. **"The threshold `t` is chosen so that it cannot be broken without owning ≥ `t` members of a
   line."** This is a deployment-parameter-choice assumption, not a code-correctness one: it holds
   automatically given the Shamir/KEM-sealed construction of §2.1 as long as an operator picks `t`
   appropriately for their target `f` (spec §5.2's table gives worked `(q+1, t)` choices against `f`
   up to 0.5). No code defect can violate this; a misconfigured deployment can.

### 4.3 Conditional [C] thresholds — a consolidated inventory

Several of the guarantees above and in §2 are **[C]**-tagged — true conditional on an honest
threshold, not unconditionally. An auditor should treat each as a distinct trust boundary to state
explicitly in the final report:

| Construction | Honest-threshold condition | What breaks below it |
|---|---|---|
| NYX Tessera hop (§2.1) | Fewer than `t` of a line's `q+1` members are adversarial | Below `t` colluding members recover the layer key and can peel/tamper that hop; endpoint linkage degrades toward the `P_hop` curve at the adversary's actual local concentration |
| Threshold randomness beacon (§2.4) | Fewer than `t` beacon-committee shareholders are adversarial | A `≥ t` adversarial coalition can compute the seed early (breaking unpredictability, assumption 2) or, if it controls dealing, bias it (mitigated by the GJKR complaint/disqualification round, §3, but see the DKG note below) |
| CALYPSO threshold-hosted service (§2.6, spec §12.3) | Fewer than `t` service-line members are seized/colluding | `≥ t` seized hosts reconstruct the service identity secret and/or the intro-decryption key — full compromise |
| DIAKRISIS Byzantine cross-attestation (spec §6.4, out of scope for this package but load-bearing for the trust picture) | Fewer than the line's threshold of members collude on the same line | Above threshold, a coalition can produce a globally-consistent lie; below, geometry pins the liar |

### 4.4 A resolved-but-worth-restating trust finding: the live DKG

`docs/audit.md` records that the one place FANOS wrote its own multi-party cryptographic protocol
end-to-end — the live, networked GJKR-style DKG engine (`fanos-keygen::DkgNode`, distinct from the
algebraic core in `fanos-vrf::dkg` it wraps) — previously had **unauthenticated** commit/complaint/
justify control frames (audit items B1–B3, tagged CRITICAL), letting a single Byzantine member
forge complaints and evict every honest dealer from the qualified set. The document records these
as **RESOLVED**: `from` is now authenticated against the claimed dealer/complainer for every control
frame, and dedicated adversary tests pin the fix (`fanos-keygen/src/lib.rs`, module doc lines 1–31
describes the current authenticated design; see `docs/audit.md` §B1–B3 for the fix commit history).
**This is exactly the kind of finding an external audit should independently re-derive** — the DKG
protocol logic is bespoke (not a call into a vetted library), so it is the single highest-priority
item in the "vetted primitives" table to treat as if it were a [P] item despite the spec calling
DKG "standard." Recommend the auditor re-run the specific attack B1–B3 describe (forged complaint
frame) against the current `fanos-keygen` source independently of trusting the resolution note.

---

## 5. [H] hypotheses

Two claims in the spec are explicitly tagged **[H]** — formulated, not yet proven. Both concern the
NYX privacy layer and are closely related to the §2.1/§2.2 priority items; they are separated out
here because "hypothesis, needs proof" is a distinct ask from "needs formal cryptanalysis of an
implemented construction."

### 5.1 The holonomy as a compact path authenticator (spec §5.4)

> "A compact path authenticator **[H]**: both endpoints, knowing the algebraic description of the
> path, compute the same `Hol`; intermediate nodes see only the local `β_k`. `Hol` serves as a
> self-verifying 'route signature' — inserting/substituting a hop breaks the holonomy."

This is the same construction reviewed for implementation-level concerns in §2.2. As a
**hypothesis**, what remains unproven is the authenticator's actual unforgeability/binding
property under a formal adversary model — not merely "the test suite shows tampering changes the
output," which the implementation does demonstrate
(`fanos-nyx/src/ratchet.rs::tampering_a_hop_breaks_the_tag`,
`fanos-aphantos/src/sealed.rs::a_substituted_hop_fails_verification_and_must_be_rejected`), but
which is not the same as a proof that no adversary can *forge* a valid `Hol` for a path it did not
actually traverse. The spec's own red-team table (§8.4) restates this row's status as "**[H]**
(formal audit **[P]**)" — i.e., both an unproven hypothesis and, separately, a formal-audit
work item, which this package's §2.2 addresses on the implementation side.

### 5.2 Algebraic private rendezvous (spec §5.6)

> "**The NYX solution [H→C]:** two parties sharing a secret `s`... deterministically derive a common
> meeting line `L_rdv = MapToLine(VRF_beacon(s, epoch))` and meet on it — with no directory, no
> introduction points."

The `[H→C]` notation itself signals the spec's own view: a hypothesis maturing toward a conditional
claim as the construction gets built out. This is the direct foundation of CALYPSO's rendezvous
derivation (spec §12.2, implemented in `fanos-calypso/src/rendezvous.rs::rendezvous_line`, folding
in the service pubkey, epoch, and threshold-beacon seed — confirmed matching the described
construction by direct code inspection). What remains a hypothesis rather than a proven property is
the **unlinkability** of the derived rendezvous line across epochs and across distinct
service/client pairs under an adversary that observes many rendezvous events — the implementation
gives determinism and beacon-unpredictability (both testable and tested, e.g.
`the_line_depends_on_the_beacon`, `distinct_services_meet_on_distinct_lines` in
`fanos-calypso/src/rendezvous.rs`), but a formal unlinkability argument (e.g., that
`MapToLine(H(pubkey ‖ epoch ‖ beacon))` outputs are indistinguishable from independent uniform
draws to a computationally bounded adversary without knowledge of `pubkey`) is not made in the spec
and was not found elsewhere in the repository. **TODO: verify** whether such an argument exists
outside the reviewed materials (e.g., in the UHM corpus math references the spec points to for
`MapToPoint`/`MapToLine` uniformity) — this package did not locate one.

---

## 6. Audit package manifest

What to hand the auditor, concretely, grouped by review track.

### 6.1 Specification

- `spec/protocol.md` — the whole document for context, but direct the auditor's attention to:
  - **§L6** (Cryptographic suite, line ~377–405) — the primitive table and interop-deviations note.
  - **§3.2** (Threat model, line ~258–281) — adversary profiles and the three key security
    assumptions.
  - **§5** (Part V, NYX, line ~414–509) — the Tessera packet, threshold sheaf, holonomic ratchet,
    cover traffic, and algebraic rendezvous.
  - **§7.7, §7.9** (Tessera wire format and conformance) — the canonical byte layout and the KAT
    discipline.
  - **§8** (Part VIII, Security analysis) — the quantitative security curve and the honest
    residual-vectors and red-team tables.
  - **§12** (Part XII, CALYPSO) — threshold-hosted services and the rendezvous derivation.
  - The `[T]`/`[C]`/`[H]`/`[P]` tagging convention (line ~56) — necessary to read every other
    section correctly.

### 6.2 Code, grouped by review track

| Track | Crates | What to look for |
|---|---|---|
| Core hybrid primitives | `fanos-pqcrypto` (`kem.rs`, `sig.rs`, `identity.rs`, `onion_ratchet.rs`, `rng.rs`) | The combiner, contributory checks, hybrid signature composition, the forward-secure onion-key ratchet (distinct from the holonomic *path* ratchet — do not conflate the two "ratchet" concepts; `onion_ratchet.rs` rotates a relay's own decap key per epoch for forward secrecy, `fanos-nyx/src/ratchet.rs` computes a path authenticator) |
| VRF / threshold beacon / DKG | `fanos-vrf` (`lib.rs`, `beacon.rs`, `dkg.rs`, `vss.rs`), `fanos-keygen` (`lib.rs`, `beacon.rs`) | The DLEQ proofs, Lagrange combination, GJKR complaint/disqualification robustness (§4.4) |
| Light math core | `fanos-primitives` (`hash.rs`, `maptopoint.rs`, `shamir.rs`, `aead.rs`, `keys.rs`, `vrf.rs`, `address.rs`) | Domain separation discipline, `MapToPoint`/`MapToLine` rejection-sampling uniformity, Shamir zeroize-on-drop |
| NYX / threshold privacy | `fanos-nyx` (`tessera.rs`, `sheaf.rs`, `ratchet.rs`, `security.rs`, `mixing.rs`, `path.rs`, `profile.rs`), `fanos-aphantos` (`sealed.rs`, `threshold.rs`, `threshold_router.rs`, `node.rs`) | The two onion forms (§2.1), the fixed-bucket padding, the holonomy-never-cleartext invariant |
| CALYPSO | `fanos-calypso` (`rendezvous.rs`, `hosting.rs`, `descriptor.rs`, `balance.rs`, `pow.rs`, `stabilize.rs`) | Threshold identity custody, sealed-share/sealed-intro constructions |
| Naming | `fanos-onoma` (`address.rs`, `derive.rs`, `bech32.rs`) | Address commitment, unenumerable per-epoch descriptor derivation |
| Incentives | `fanos-incentives` (`lib.rs`) | VOPRF issuance/redemption, context-binding, double-spend detection |
| Wire codec | `fanos-wire` (`tessera.rs`, `frame.rs`, `element.rs`, `varint.rs`, `capability.rs`) | Canonical encoding, the pinned Tessera byte layout |

### 6.3 Conformance vectors and known-answer tests

`conformance/vectors/` is the language-agnostic interop contract (spec §7.9); every value is
asserted by the Rust reference suite so it cannot drift silently (`conformance/README.md`). Hand
over the whole directory, but the cryptographically relevant files are:

- `conformance/vectors/wire.json` — canonical varints, field-element widths, point/line encodings,
  frame types, capability negotiation, the HELLO handshake transcript, and the **Tessera single-relay
  packet layout** (`tessera_layout` key), plus the non-canonical inputs a conformant decoder must
  reject (`reject` key). Reproduced and cross-checked against the live codec by
  `rust/crates/fanos-wire/tests/wire_kat.rs`, which parses the JSON and re-derives every entry from
  the actual encoder/decoder rather than hard-coding expected bytes — so the vector file and the
  implementation cannot silently drift apart.
- `conformance/vectors/names.json` — the ONOMA address commitment vectors (current CALYPSO/service
  addressing, §3.5), pinned by `rust/crates/fanos-onoma/tests/conformance.rs` (confirmed present).
- `conformance/vectors/algebra.json` — `PG(2,q)` parameters and the cross-product/mediator
  computations the coordinate/rendezvous derivations build on (geometry, not cryptography, but
  foundational to every `MapToPoint`/`MapToLine` call cited throughout this package).

**Gap to flag explicitly:** as of this pass, `wire.json` contains a `tessera_layout` entry for the
**single-relay** hybrid-KEM onion (`fanos-aphantos::sealed`, 8192-byte bucket) but **no
corresponding pinned KAT entry for the threshold-line onion** (`fanos-aphantos::threshold`,
20480-byte bucket) — confirmed by a direct text search of `wire.json` for "threshold", which finds
no matches. The threshold-line form is the one that actually realizes the spec §5.2 "hop is a line"
Tessera construction (§2.1 of this package); the pinned KAT today only covers the simpler
single-relay form. An auditor validating wire-level interoperability of the *headline* [P]
construction should be aware the byte-level conformance contract for it is not yet locked down the
same way the single-relay form is.

### 6.4 Test suites to run, not just read

- `cargo test -p fanos-pqcrypto -p fanos-vrf -p fanos-keygen -p fanos-primitives -p fanos-nyx
  -p fanos-aphantos -p fanos-calypso -p fanos-onoma -p fanos-incentives -p fanos-wire` — unit and
  property tests for every crate in §6.2's table (property tests via `proptest`, per each crate's
  `dev-dependencies`).
- `rust/crates/fanos-aphantos/tests/{flow_correlation,holonomy_verification,onion_tamper,replay_attack}.rs`
  — adversarial/attack-scenario integration tests specifically for the onion construction.
  `holonomy_verification.rs` and `onion_tamper.rs` are the most directly relevant to §2.1/§2.2/§5.1.
- `rust/crates/fanos-calypso/tests/{entry_unlinkability,statistical_disclosure,conformance}.rs` —
  CALYPSO-specific adversarial tests.
- `rust/crates/fanos-wire/tests/wire_kat.rs` — regenerates and checks every wire KAT against the
  live codec (§6.3).
- `python3 fanos_verify.py` (referenced by the spec, site-hosted) — reproduces the V1–V22
  quantitative claims. Out of scope for a cryptographer per §1, but worth a smoke-run to confirm
  the security-curve numbers cited throughout this package (e.g., `P_link` at `f=0.2`) are
  reproducible independently of the Rust test suite.

### 6.5 Audit history to hand over, with a caveat

`docs/audit.md` is the project's own prior internal audit pass (defect-level, not a formal
cryptographic review) and is worth including so the external auditor does not re-discover
already-fixed issues — but hand it over with the caveat this package found directly: **at least two
entries in its Part B (Cryptography) section are stale relative to the current source**, both
favorably (the code is more fixed than the doc states):

1. **B5** (hybrid KEM combiner) — the doc's "contributory... check remains open" residual note is
   outdated; the check is implemented and tested (§3.1 of this package).
2. **A6** ("No secret-material hygiene... no workspace crate depends on zeroize or subtle") — also
   outdated: `fanos-primitives/src/shamir.rs`'s `Share` type explicitly zeroizes on drop
   (`impl Drop`/`ZeroizeOnDrop`), `zeroize` is a direct (non-transitive) workspace dependency
   (`rust/Cargo.toml`), `ed25519-dalek`/`x25519-dalek` are built with their `zeroize` feature
   enabled (`fanos-pqcrypto/Cargo.toml`), `subtle` is a direct workspace dependency used for
   constant-time comparison in credit redemption (`fanos-incentives/src/lib.rs`,
   `use subtle::ConstantTimeEq`), and `VrfSecret` derives only `Clone` (not `Copy`) with a
   hand-written redacted `Debug` impl that never prints key material
   (`fanos-vrf/src/lib.rs`) — the opposite of what A6 describes. **TODO: verify** whether
   `ml-kem`/`ml-dsa` (the two RustCrypto crates without an explicit `zeroize` feature flag in
   `fanos-pqcrypto/Cargo.toml`, unlike `ed25519-dalek`/`x25519-dalek`) zeroize their secret key
   types on drop by default upstream — this package did not independently confirm that specific
   point and it is the one place the A6 concern could still have partial merit.

Recommend refreshing `docs/audit.md`'s Part B before or alongside this package's delivery, so the
external auditor's time is spent on what is actually still open.

### 6.6 Suggested audit sequencing

1. **Foundational assumptions first** (§4.2) — confirm the coordinate VRF and threshold beacon
   deliver the unforgeability/unpredictability the entire security curve is conditioned on.
2. **The bespoke DKG** (§4.4) — the one hand-rolled multi-party protocol; independently re-derive
   the B1–B3 finding and its fix.
3. **The Tessera packet, both forms** (§2.1) — the headline [P] item; focus on the KEM-sealed
   production form (`fanos-aphantos::threshold`) over the transparent reference form
   (`fanos-nyx::sheaf`), and flag the missing KAT coverage (§6.3) as a process gap alongside any
   cryptographic findings.
4. **The holonomic ratchet** (§2.2, §5.1) — scope a formal model as the spec itself requests.
5. **The vetted-primitive composition table** (§3) — spot-check the combiner and the interop
   deviations; this track needs less time per item than 1–4 but should confirm no primitive is
   mis-parameterized (e.g., correct ML-KEM-768/ML-DSA-65 parameter sets, not a smaller variant).
6. **CALYPSO and ONOMA** (§2.6, §3.5, §5.2) — threshold identity custody and the rendezvous/address
   unlinkability hypotheses.
7. **Everything else in §3** as time allows — the VOPRF credits and remaining wire-encoding surface
   are lower-novelty, vetted-primitive compositions.
