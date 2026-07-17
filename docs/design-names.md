# ONOMA — the FANOS name system (design)

> **ONOMA** (Greek ὄνομα, "name") is the FANOS self-certifying naming layer — the equivalent of
> `.onion` / `.i2p` / `.loki`, redesigned from first principles to be **post-quantum secure,
> unenumerable, leak-free, and format-agile** (the TLD and encoding can change without breaking the
> network). It sits atop CALYPSO (rendezvous + descriptors) and reuses the built substrate:
> self-certifying identities, the offline-root→epoch-signing hierarchy, the projective LRC store, and
> geometry routing.

This is a component design under [`design.md`](design.md) (it realizes §11 "DNS without leaks" and
invariants 2/5/6). The working TLD is **`.fanos`**, deliberately provisional — §8 makes changing it a
one-line, network-negotiated operation, never a fork.

---

## 1. The problem — Zooko's Triangle

A name binds a *memorable string* to a *cryptographic identity*. Zooko's Triangle states you can natively
get at most **two** of three properties:

- **Human-meaningful** — a person can read, remember, and type it.
- **Secure** — the binding is unforgeable and collision-free (no MITM, no squatting-into-impersonation).
- **Decentralized** — no trusted authority (no CA, no DNS root, no registrar).

Every deployed system picks a corner and pays for the third. The reference design does **not** pretend to
repeal the triangle — it **stratifies** it (§3): a secure+decentralized machine layer, a
human+decentralized petname layer, and an optional human+secure global registry. Each layer is honest
about which corner it sacrifices, and the layers compose.

---

## 2. Field analysis — what the deployed systems teach

| System | Corner taken | Address = | PQ? | Enumerable? | Human names | Cost / weakness |
|---|---|---|:-:|:-:|---|---|
| **Tor onion v2** | secure + decentralized | `base32(H(RSA1024)[:80])` (16 ch) | ✗ | **yes** (HSDir harvest) | none | short hash → enumeration + weak key; deprecated |
| **Tor onion v3** | secure + decentralized | `base32(ed25519_pk ‖ ck ‖ v)` (56 ch) | ✗ | no (key-blinding) | none | **embeds the key → not PQ**; long |
| **I2P b32** | secure + decentralized | `base32(H(dest))` (52 ch) | ✗ | no | none | hash-based (like ONOMA), but not PQ |
| **I2P addressbook** | human + decentralized | subscription "jump" lists | ✗ | — | first-come, per-list | inconsistent across subscriptions; no global truth |
| **Lokinet LNS** | human + secure | name on Oxen chain → key | ✗ | no | yes, registered | needs a **blockchain + fee**; renewal |
| **ENS / Namecoin / Handshake** | human + secure | name on a chain → record | ✗ | yes (public ledger) | yes | consensus cost, **front-running**, public zone, fees |
| **GNUnet GNS** | human + decentralized | petname → zone delegation | ✓-ish | no | yes, **relative** | not globally unique (by design) |

**Lessons extracted (the synthesis inputs):**

1. **Onion v3's self-certification is right, its cryptographic basis is obsolete.** Embedding the public
   key in the address makes the name *its own certificate* — no lookup-trust. But it only works because
   ed25519 keys are 32 bytes; **PQ keys (ML-DSA ≈ 2 KB) cannot be embedded**. A PQ address must
   *hash-commit* the key bundle and verify after a fetch (the I2P-b32 / onion-v2 shape) — but with a
   full 256-bit hash, not v2's truncated-80-bit one.
2. **Key-blinding (onion v3) defeats enumeration** — HSDirs index by a per-epoch *blinded* key they
   cannot invert to the identity. We must preserve unenumerability, but our anti-enumeration cannot rely
   on blinding a *client-known* key (the client only knows the hash). The fix (§5): move authority to the
   **client**, make the store a dumb, unenumerable, PoW-rate-limited blob-holder.
3. **Blockchain registries buy global human names at the price of consensus, fees, front-running, and a
   public zone** (everyone sees every name). Good as an *opt-in* top layer, wrong as the *base*.
4. **GNS petnames escape the triangle by giving up global uniqueness** — names are relative to a root you
   choose. This is the correct decentralized human layer, and it needs **no consensus at all**.

ONOMA = **onion-v3 self-certification, upgraded to PQ hash-commitment (L-key)** + **GNS petnames
(L-pet)** + **an optional coherence-chain registry for those who need global names (L-global)**.

---

## 3. Design — stratified naming

Escape the triangle by layering, not by magic. Each layer targets a different corner and they compose
top-down (human → machine):

```
  L-global   human + secure     coherent-chain registry (opt-in, Phase 6)   alice.fanos  (globally unique)
      │  optional; only when a globally-unique human name is required
  L-pet      human + decentral  GNS-style petnames / signed zones (Phase 2) blog.alice   (relative to a root)
      │  no consensus; names are relative to a trust root you choose
  L-key      secure + decentral self-certifying PQ address (base, built*)   fanos1q9x…8f.fanos
             the cryptographic ground truth — everything above resolves *to* an L-key address
```

`*` L-key reuses built CALYPSO primitives (self-certifying identity, descriptor store, epoch hierarchy);
Phase 2 adds the address codec + resolver. L-pet is Phase 2. L-global is Phase 6 (rides the coherent
blockchain). **The base is always self-certifying and consensus-free**; higher layers are conveniences
that ultimately resolve down to an L-key address whose binding is unforgeable.

---

## 4. The L-key address format (versioned, PQ, human-checksummed)

```
   fanos1 q9x2…（bech32m data: version ‖ H₂₅₆(bundle)）…8f
   └─hrp─┘└──────────────── bech32m(payload) + BCH checksum ────────────────┘   .fanos
     ▲                              ▲                                            ▲
   context tag                 33-byte payload                          TLD (config, changeable)
```

- **Payload** = `version(1 byte) ‖ BLAKE3-256(hybrid_bundle)(32 bytes)`. The `hybrid_bundle` is the
  service's canonical-encoded long-term public keys — Ed25519‖ML-DSA-65 (sig) and X25519‖ML-KEM-768
  (KEM). The address is a **256-bit commitment** to the *whole PQ bundle*: 2nd-preimage resistance
  ≈ `2¹²⁸` even under a quantum adversary (Grover), so no attacker can find a *different* key bundle with
  the same address. This is the security anchor.
- **Encoding = bech32m** (the Bitcoin-taproot checksum, BCH-code based): guarantees detection of up to 4
  transcription errors and has no mixed-case ambiguity — strictly stronger typo protection than onion's
  truncated-SHA3 checksum. Length ≈ 59–65 chars, comparable to onion v3.
- **`version` byte** selects `{hash, bundle-layout, blinding scheme}` — the whole cryptographic recipe.
  New PQ primitives ⇒ new version; old addresses keep resolving (the resolver dispatches on version).
  **This is what makes ONOMA changeable (§8).**
- **`hrp` + TLD** are configuration, not hardcoded crypto — `.fanos` today, negotiable later (§8).
- **Mnemonic rendering (advanced, optional).** The same 33-byte payload also renders as a short
  **word sequence** (a fixed 2048-word list, BIP-39-style) for *verbal* comparison ("read me your
  service's four words"). Humans compare words far more reliably than base32 — a usability *and*
  anti-homograph win that onion/i2p lack.

Why hash-commit instead of embedding the key (onion v3)? Because a PQ bundle is ~3 KB — unembeddable.
The cost is one descriptor fetch to *learn* the keys, which resolution does anyway to get intro points.
The benefit is full post-quantum binding. This is the single most important design decision in ONOMA.

---

## 5. Security properties & how they are achieved

| Property | Mechanism |
|---|---|
| **Self-authenticating** (no CA/DNS-root/MITM) | `addr = H(bundle)`; client fetches the descriptor, checks `H(bundle) == addr`, then the offline-root→epoch cert chain. The **client is the authority** — it holds the commitment. |
| **Post-quantum** | The commitment covers the *hybrid* bundle (ML-DSA + ML-KEM); the hash is 256-bit (quantum 2nd-preimage `2¹²⁸`). No small classical key is load-bearing (unlike onion v3's embedded ed25519). |
| **Unenumerable** | The store indexes descriptors by a **rotating lookup key** `L = H(addr ‖ epoch ‖ "onoma-lookup")`. Without the address, `L` is unguessable and `H` is one-way, so storage nodes cannot enumerate services or even confirm which they hold. Descriptor payload is encrypted to `K = H(addr ‖ epoch ‖ "onoma-enc")` — only address-holders decrypt. |
| **Publish-authorization without a trusted store** | The store cannot check authorization (it must not learn `addr`). Instead: **client-side selection** — several blobs may sit at `L`; the client fetches and keeps the one whose inner root-cert-chain verifies *and* `H(bundle)==addr`. Impersonation is therefore impossible regardless of what the store holds. |
| **Squat-DoS bounded** | Publishing at `L` costs **adaptive PoW** (built: `pow::AdaptiveDifficulty`) and is LRC-replicated + Lindbladian-rate-limited, so flooding `L` with junk is expensive and self-throttling; the real service (holding the root key) always re-publishes a valid descriptor the client will select. |
| **No DNS leak** | `.fanos` never touches clearnet DNS — resolution is 100 % in-CALYPSO over the overlay (design.md §11). |
| **Key rotation / revocation** | `addr` commits to the *root* bundle; the root delegates **epoch signing keys** (built: `SigningKeyCert`, CALYPSO-Balance). Rotate/replace epoch keys freely without changing the address; revoke the root via a signed tombstone descriptor. |
| **Forward-secure descriptors** | `L` and `K` rotate per epoch, so compromising one epoch's descriptor material reveals nothing about other epochs. |
| **Homograph / typo resistance** | bech32m BCH checksum (≤4-error detection) + no mixed case + optional word-list rendering for human comparison. |
| **Downgrade resistance** | The `version` (crypto recipe) is inside the checksummed payload; an attacker cannot silently present a weaker-version address for a service without producing a different, non-matching string. |

**The synthesis in one line:** where onion v3 makes the *HSDir* verify a blinded key, ONOMA makes the
*client* verify a hash commitment — which is what unlocks post-quantum names, because the client already
holds the address and needs no small embeddable key.

---

## 6. Resolution flow (over the built substrate)

Resolving `fanos1…​.fanos` (or a petname that resolves to it), all in-network, no DNS, no CA:

1. **Decode & check** the bech32m address → `(version, H(bundle))`; reject on checksum failure.
2. **Epoch lookup key** `L = H(addr ‖ epoch ‖ "onoma-lookup")`; the descriptor lives on the LRC replica
   line at coordinate `MapToPoint(L)` — **geometry-routed, directory-free** (built `points_on` / LRC).
3. **Fetch** the descriptor blob(s) at `L` from the replica line (read-repair across the line on miss —
   built: L4 read repair).
4. **Decrypt** with `K = H(addr ‖ epoch ‖ "onoma-enc")` — proves the fetcher holds the address.
5. **Verify (client is the authority):** `H(bundle) == addr` **and** the offline-root→epoch-signing cert
   chain (built). Discard any blob that fails; select the valid one (squat-resistance).
6. The descriptor yields the **hybrid pubkey bundle** + **intro-point line coordinates** + signing certs.
7. **Rendezvous** via CALYPSO intro/rendezvous (built), establishing the PQ onion to the service.

Every step reuses shipped machinery; Phase 2 adds only the codec (step 1), the lookup/enc key derivation
(steps 2/4), and the resolver glue.

---

## 7. L-pet — petnames & zones (GNS/SDSI, no consensus)

Memorable names without a blockchain, by giving up *global* uniqueness (the honest Zooko trade):

- A **zone** is a signed record set `{ label → target }`, `target ∈ { L-key address, another zone key }`.
  Your zone's root key is your identity; you publish the zone (encrypted, in the LRC store, keyed like a
  descriptor) or hand it out of band.
- **Delegation:** `blog.alice.fanos` resolves by starting at *your* chosen root → `alice` delegates to
  Alice's zone key (a signed record) → look up `blog` in Alice's zone → an L-key address. Every hop is
  self-certifying (each delegation record is signed by the delegating zone).
- **Petnames are relative** — "alice" means whoever *your* root says it is; there is no global "alice".
  That is the correct, honest decentralized-human design (GNS's insight), and it needs **zero
  consensus**. Import someone's zone to adopt their names.
- **Security:** a zone compromise affects only that zone's sub-names; the L-key addresses they point to
  are still self-certifying, so a bad zone can misdirect *which* service you reach but cannot forge *a*
  service's identity (you would rendezvous to a different, still-authenticated key — detectable, and
  scoped to that zone's trust).

---

## 8. Changeability — the explicit requirement

The user's constraint: **`.fanos` now, but the network must be able to change it later.** ONOMA is built
so that the TLD *and* the entire address recipe are data, not baked-in assumptions:

- **TLD is configuration.** `.fanos` is a single negotiated constant (`hrp` + suffix). Changing it is a
  config/roadmap decision, not a code fork; addresses are stored and routed by their *payload hash*, not
  their text suffix, so the suffix is purely a display/parse convention.
- **Version-dispatched crypto.** The `version` byte selects the hash, bundle layout, and blinding scheme.
  A future migration (new hash, new PQ primitive, shorter/longer payload) is a **new version** that old
  nodes ignore and new nodes prefer — resolved through **capability negotiation** (design.md §12,
  invariant 6). Both old and new addresses resolve during the overlap; no flag day.
- **Dual-publish migration.** A service migrating versions publishes descriptors under *both* its old and
  new addresses for a transition window (the epoch hierarchy makes this a routine re-sign), so links keep
  working while the ecosystem moves — exactly how a living system grows a new organ before retiring the
  old one.

Concretely: renaming `.fanos → .xyz` or upgrading the hash is *"advertise codec vN+1, dual-publish, drop
vN when adoption crosses threshold"* — a negotiated evolution, never a break.

---

## 9. Threat model & attacks addressed

| Attack | Defence |
|---|---|
| **MITM / fake service** | `H(bundle)==addr` + root-cert chain, checked client-side — cryptographically impossible to forge without a 2nd-preimage (`2¹²⁸` quantum). |
| **Service enumeration / harvesting** (onion v2's flaw) | rotating `L=H(addr‖epoch)`; store holds opaque, address-gated blobs; cannot invert or confirm. |
| **Squatting / lookup-slot DoS** | adaptive PoW to publish + LRC replication + Lindbladian rate limit; client-side selection ignores junk blobs. |
| **Front-running** (ENS/Namecoin flaw) | L-key has no registration to front-run (the address *is* the key). L-global (Phase 6) uses commit-reveal + PoW on the coherent chain. |
| **Homograph / typo phishing** | bech32m error-detecting checksum, no mixed case, optional word-list verbal comparison. |
| **Harvest-now-decrypt-later** | PQ commitment + PQ descriptor encryption; the address binding survives a quantum adversary. |
| **Key compromise** | epoch-key rotation under an offline root (built); root tombstone for revocation. |
| **Public-zone privacy leak** (blockchain registries expose all names) | L-key/L-pet publish nothing globally; only address-holders can find/decrypt a descriptor. |

The honest residual: **L-global human names still require consensus and are enumerable** (any global
registry is) — which is precisely why global human naming is an *opt-in top layer*, never the base. Users
who need unlinkability use L-key/L-pet, which leak nothing.

---

## 10. Implementation status & what remains

**Reused substrate:** self-certifying identity (`coord = MapToPoint(H(cert))`), the offline-root→epoch
`SigningKeyCert` hierarchy (CALYPSO-Balance), the projective **LRC descriptor store** with L4 read-repair,
geometry routing (`points_on` / `MapToPoint`), CALYPSO intro/rendezvous, adaptive PoW, Lindbladian rate
limiting, hybrid PQ keys, BLAKE3.

**Built now — the `fanos-onoma` crate (`no_std` + alloc, 30 tests, KAT-pinned):**

- **L-key** — `address` (the versioned PQ-commitment `Address`, `verifies`, `.fanos` display + parse,
  version dispatch), `bech32` (a from-scratch BIP-350 codec, pinned against BIP-350 vectors incl. the
  bech32-vs-bech32m discriminator), `mnemonic` (dictionary-free proquint rendering).
- **Derivations** — `derive` (`lookup_key` / `descriptor_key` / `lookup_point`): the rotating,
  unenumerable, address-gated per-epoch material.
- **L-pet readable names & subdomains** — `name` (strict LDH, homograph-safe), `zone` (signed
  `Zone`/`Record`/`Target`, apex `@`, signature-agnostic `verify`, and `resolve` walking delegations for
  subdomains), `registry` (`Registry` trait, `LocalRegistry`, and `MemoryNamespace` implementing
  `ZoneSource` for a complete in-memory readable-name + subdomain resolver).
- **L-global issuance seam** — `registry::Registration` (a signed, canonical, verifiable claim binding a
  top-level label to a target) behind the `Registry` trait, so a chain backend drops in without touching
  resolution.
- KAT-pinned in `conformance/vectors/names.json` so every implementation produces byte-identical
  addresses, mnemonics, and derivations.

**Remaining (integration, next):**

1. A sans-I/O `Resolver` engine binding `derive` + the descriptor store: address → epoch lookup → fetch →
   client-side verify+select → keys+intro points (client-is-the-authority), with a local `MemoryNamespace`
   cache for readable names.
2. Integration into `fanos proxy` / `fanos vpn` (design.md §5/§11): `.fanos` short-circuits to the
   resolver; clearnet names go over the exit.
3. Sim tests over the network: unenumerability (store cannot derive addr), squat-DoS (junk blobs ignored,
   PoW throttles), rotation (epoch key change, address stable), migration (dual-version dual-publish),
   multi-hop delegation chains.
4. **L-global settlement backend** (Phase 6): a coherent-chain `Registry` implementation with
   commit-reveal issuance — the only piece needing consensus, kept strictly optional so the base name
   system never depends on it.
