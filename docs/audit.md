# FANOS Rust reference implementation — architectural audit

**Date:** 2026-07-18
**Scope:** the entire `rust/` workspace — 27 crates, ~31 k LoC.
**Baseline health at audit time:** `cargo test --workspace` green; `cargo clippy --workspace --all-targets -D warnings` green; CI runs fmt + clippy + tests + no_std/wasm cross-builds + `cargo miri`. The working tree is mid-change (the DIAULOS anonymous-rendezvous WIP) and currently **fails `cargo fmt --check`** at `fanos-rendezvous/src/lib.rs:214`.
**Method:** whole-workspace read, dependency-graph and determinism analysis, and five parallel adversarial per-cluster reviews. Every CRITICAL/HIGH claim in Parts A–C was re-verified by hand against the source before inclusion.

---

## 1. Executive summary

FANOS is, at its foundation, an unusually principled codebase. The sans-I/O discipline is **real and holds** — the engine is a pure state machine and only the drivers touch entropy, wall-clock, or sockets, exactly as `architecture.md` claims. The projective-geometry substrate is genuinely generic over `q`. The post-quantum primitives are real (audited `ed25519-dalek` / `ml-dsa` / `x25519-dalek` / `ml-kem` / `vrf-r255` / `curve25519-dalek`), domain separation is correct and consistently applied, and the DIAULOS handshake is a textbook-quality hybrid KDF with transcript binding and directional key separation. The dependency graph is a clean DAG with leaf-shaped math crates. This is not a prototype pretending to be a protocol; it is a protocol implementation with a real spine.

The deficiencies are therefore **not in the primitives but in the composition and at the edges**, and they cluster into a recognizable shape:

1. ~~**The canonical layer is no longer canonical.** `fanos-wire` is a well-built, KAT-covered, "one valid encoding, reject non-canonical" codec — but only 5 of 27 crates use it. Every subsystem that grew after the spec froze (DIAULOS, threshold onions, rendezvous, ONOMA, CALYPSO-Balance, VRF proofs, PROTEUS) hand-rolls its own byte layout. The single-source-of-truth wire contract has bifurcated.~~ **RESOLVED (#82).** `#[derive(Wire)]` now exists and `fanos-wire` is the codec substrate for 12 crates (including DIAULOS, rendezvous, and CALYPSO); the remaining hand-written byte code is signing transcripts, layered onion/AEAD crypto, and group-validated foreign-crypto wrappers — not a bypass. See A1.
2. ~~**The one place FANOS wrote its own cryptographic protocol instead of calling a vetted crate — the `fanos-keygen` DKG — is Byzantine-broken and has zero tests.** Unauthenticated complaint frames let a single malicious node evict every honest dealer.~~ **RESOLVED.** Commit/complaint frames are now authenticated against the claimed dealer/complainer, the QUAL/share atomicity gap is closed (a dealer's commitment reaches the joint key only if its share actually folded), and justification is checked against the qualified commitment, not the frame's own; `fanos-keygen` now carries dedicated adversary tests for all three. See B1–B3.
3. **The "living, self-observing, provably-anonymous" headline capabilities are stranded below the shipping surface.** Self-healing's `Decouple` is a no-op, ~~the real verifiable-coordinate VRF is dead code~~ **(RESOLVED #66 — the VRF is now the live, HELLO-proven coordinate authority; see A7)**, the anonymous rendezvous path is not wired into the node binary, and ~~the general-`q` scaling story cannot run above the geometry layer~~ **(decision recorded #66 — `q=2`+hierarchy is the scaling model by design, not a stranded capability; see A2)**.
4. **A systemic robustness gap: unbounded state and absent back-pressure.** Waiter maps, session maps, rendezvous route tables, and every driver channel are unbounded; receiver flow control is advertised but not enforced. A single connected peer can OOM a node.
5. **Best-in-class hygiene the mandate demands is missing workspace-wide:** no `zeroize`, no `subtle`; several secret types even derive `Copy`/`Debug`.

None of these is fatal, and none contradicts the architecture — they are the gap between an excellent skeleton and the "flawless, fully-fundamental" bar the project sets for itself. The remainder of this document enumerates them with file/line anchors and a prioritized remediation path (§11).

**Overall grade:** foundations A; composition and productionization C+. The distance between the two is the subject of this audit.

---

## 2. Severity summary

| # | Finding | Severity | Where |
|---|---|---|---|
| B1 | ~~DKG complaint/commit/justify frames unauthenticated — one node evicts any honest dealer~~ **RESOLVED** — `from` authenticated against the claimed dealer/complainer | **CRITICAL** | `fanos-keygen/src/lib.rs:281-328` |
| B2 | ~~DKG `ingest_share` result discarded — joint key can include a rejected dealer (`x·G ≠ Y`)~~ **RESOLVED** — commitment pushed to the joint key only when the Feldman check passes | **CRITICAL** | `fanos-keygen/src/lib.rs:415-429` |
| B3 | ~~DKG justification checked against the frame's own commitment, not the qualified one~~ **RESOLVED** — verified against `self.commitments[d]`, the frame's own commitment ignored | **CRITICAL** | `fanos-keygen/src/lib.rs:337-362` |
| B4 | ~~DLEQ nonce drawn from a caller RNG — deterministic seed ⇒ issuer-key recovery~~ **RESOLVED** — synthetic RFC-6979-style nonce `s = H(k‖K‖B‖Z)` | **HIGH** | `fanos-incentives/src/lib.rs:89` |
| A6 | No `zeroize`/`subtle` anywhere; `VrfSecret` derives `Copy`+`Debug` | **HIGH** | workspace-wide |
| C1 | `Client::get`/`put` have no timeout; waiter maps leak unboundedly; no put-ack timeout | **HIGH** | `fanos-quic/src/driver.rs:210-243`; `fanos-runtime/.../overlay.rs:415` |
| C2 | Unbounded driver channels + single-task transport ⇒ no back-pressure, remote OOM DoS | **HIGH** | `fanos-quic/src/driver.rs:469-472,553-575` |
| C3 | Receiver `rwnd` advisory, not enforced on the in-order path ⇒ receiver OOM | **HIGH** | `fanos-runtime/src/stream.rs:288-289` |
| A1 | ~~Wire-codec bifurcation — canonical `fanos-wire` bypassed by ~10 subsystems~~ **RESOLVED (#82)** — `#[derive(Wire)]` built; `fanos-wire` is now the codec substrate for 12 crates (calypso, telemetry, rendezvous, quic, diaulos, node, keygen, aphantos, runtime, sim, primitives + itself) | **HIGH (arch)** | workspace-wide |
| A4 | Unbounded rendezvous route table + node session map (no eviction) | **HIGH** | `fanos-rendezvous/src/transport.rs:149`; `fanos-node/src/diaulos.rs:93` |
| A5 | Anonymous rendezvous path not wired into the node binary (sim-only) | **HIGH (arch)** | `fanos-node` deps |
| A2 | ~~General-`q` stranded below a `q=2`-only DIAKRISIS/runtime/node ceiling~~ **RESOLVED (#66)** — decision recorded, `docs/design-coordinates.md` §5 | **MEDIUM (arch)** | `fanos-diakrisis/*` |
| A3 | ~~"epoch" is three different quantities; frame epoch not cross-node comparable; no `Epoch` type~~ **RESOLVED (#90)** — one `Epoch(u64)` newtype threaded through every protocol-epoch seam | **MEDIUM** | see A3 |
| A7 | ~~Real VRF is dead code; live membership uses a self-declared-forgeable placeholder~~ **RESOLVED (#66, Level A)** — VRF is the coordinate authority, live + HELLO-proven; Level B tracked (#95) | **MEDIUM** | `fanos-core/src/membership.rs:32` |
| B5 | ~~Hybrid KEM combiner omits transcript (ephemeral pk + ct) — X-Wing binding not met~~ **PARTIAL (#63)** — full-transcript SHAKE256 combiner now binds ephemeral pk + ct + recipient key; **residual open:** no contributory-behaviour (all-zero/low-order X25519) rejection | **MEDIUM** | `fanos-pqcrypto/src/kem.rs:80-103` |
| B6 | ~~DKG polynomial randomness seeded solely by the long-term secret (reproducible shares)~~ **RESOLVED** — a fresh per-instance `session_nonce` is folded into the polynomial seed | **MEDIUM** | `fanos-keygen/src/lib.rs:87,181-187` |
| B7 | ~~Non-constant-time GF(256) multiply on secret Shamir shares~~ **RESOLVED (#63)** — branchless mask-based `clmul`, no data-dependent branches | **MEDIUM** | `fanos-field/src/gf2m.rs:60-85` |
| B8 | ~~Overstated RFC conformance (9497/9578/9381) and bearer credits with no redemption binding~~ **RESOLVED (#63)** — RFCs downgraded to "reference, not conformance"; redemption is context-bound and constant-time | **MEDIUM** | `fanos-incentives`, `fanos-vrf` |
| C4 | Content-digest correlation not request-scoped — stale/replayed `Value` resolves a newer get | **MEDIUM** | `fanos-runtime/.../overlay.rs:509-523` |
| C5 | Quarantine is permanent (no un-quarantine) and driven by local-only diagnosis | **MEDIUM** | `fanos-runtime/.../overlay.rs:746` |
| C6 | `Decouple` healing action is a no-op beyond a notification — the loop cannot lower Φ | **MEDIUM** | `fanos-runtime/.../overlay.rs:750-752` |
| C7 | Telemetry "self-observation is anonymization" is false — exact syndrome deanonymizes | **MEDIUM** | `fanos-telemetry/src/frame.rs:58-72` |
| A4b | `fanos-session` uses unbounded channels between the async stream and the datagram transport | **MEDIUM** | `fanos-session/src/lib.rs:73-74` |
| G1 | `rust/README.md` stale — "119 tests", documents 8 of 27 crates | **MEDIUM (docs)** | `rust/README.md` |
| G2 | `#[derive(Wire)]` "codec+KATs from one definition" (design-platform.md) is unbuilt | **LOW (docs)** | — |
| — | ~~Service side is one-shot RPC while the client gets a full duplex stream~~ **RESOLVED (#66)** — `serve` is a full-duplex per-client stream; `serve_rpc` keeps request/response ergonomic | **MEDIUM** | `fanos-node/src/diaulos.rs` |
| — | ~~AEAD nonce counter uses `wrapping_add`~~ **RESOLVED** — `next_nonce` uses `checked_add` and returns `None` at 2⁶⁴, so the connection hard-kills rather than reuse a nonce (pinned by `conn::tests::the_connection_hard_kills_at_nonce_exhaustion_rather_than_reusing_a_nonce`) | ~~LOW~~ | `fanos-diaulos/src/conn.rs:189` |
| E1 | ~~Full/threshold profile emits no cover traffic — GPA resistance below the Lite profile's~~ **RESOLVED (#61)** — constant-size cover cells, exponential-gap armed | **HIGH** | `fanos-aphantos/src/threshold_router.rs` |
| E2 | ~~Threshold mix delays seeded from the node's public coordinate — GPA can predict/relink~~ **RESOLVED (#61)** — delays now seeded from a secret KEM-derived subkey | **HIGH** | `fanos-aphantos/src/threshold_router.rs:122-136` |
| E3 | ~~Descriptor deterministic AEAD nonce — keystream+MAC reuse on mid-epoch republish~~ **RESOLVED** — SIV-style per-publish salt bound to the plaintext | **MEDIUM** | `fanos-calypso/src/descriptor.rs:180-192` |
| E4 | ~~Forward secrecy is sender-side only; relays use non-rotated long-term keys~~ **RESOLVED on the Full/threshold path (#61)** — forward-secure per-epoch onion ratchet | **MEDIUM** | `fanos-pqcrypto/src/kem.rs:88-105` |
| E5 | ~~Rendezvous "VRF beacon" is a predictable hash — meeting lines computable far ahead~~ **RESOLVED (#61)** — pairing-free distributed VRF beacon folded into the derivation | **MEDIUM** | `fanos-calypso/src/rendezvous.rs` |
| E6 | ~~Cover traffic additive, not constant-rate — real load still shows a volume fingerprint~~ **RESOLVED on the Full/threshold path (#61)** — real forwards displace cover at a constant slot rate | **MEDIUM** | `fanos-aphantos/src/node.rs:164-197` |
| F2 | No concurrent-stream cap; streams never retired (honest proxy use grows unbounded too) | **HIGH** | `fanos-diaulos/src/conn.rs:170-182` |
| F3 | Sender never reclaims acked segments — cannot stream a transfer larger than RAM | **HIGH** | `fanos-runtime/src/stream.rs:103` |
| F4 | No RTO (re-emits whole window/tick); sender `sacked` set grows from crafted ACKs | **MEDIUM** | `fanos-runtime/src/stream.rs:198-232` |
| D1 | `max_reroute_depth` infinite-loops on a non-finite Φ (live-confirmed DoS hang) | **HIGH** | `fanos-diakrisis/src/healing.rs:39-50` |
| D2 | `from_correlation` accepts NaN/Inf/non-PSD ⇒ misdiagnosis + reachability root of D1 | **HIGH** | `fanos-diakrisis/src/coherence.rs:86-101` |
| D3 | `violated_classes` treats non-finite rates as consistent ⇒ Byzantine detector evadable | **MEDIUM-HIGH** | `fanos-diakrisis/src/polar.rs:100-110` |

(F1 is C3 seen from the stream layer.) Lower-severity privacy/reliability/math items are detailed in Parts D–F.

---

## 3. What is fundamentally sound (calibration — do not regress these)

- **Sans-I/O determinism is real.** Engine crates (`fanos-runtime`, `fanos-core`, `fanos-diaulos`, `fanos-diakrisis`) take `now`/`rng` as inputs; the only entropy/clock calls in the workspace are in the drivers (`fanos-node`, `fanos-quic`, `fanos-session`) via `getrandom`/`Instant::now`. Every engine collection is `BTreeMap`/`BTreeSet`, so map iteration never leaks into output. This is the load-bearing invariant and it holds.
- **Clean layered DAG.** `fanos-field` has no dependencies; `geometry → field`; `code`/`wire`/`diakrisis` sit just above. No cycles, no upward dependencies. Foundational crates are `no_std` + `unsafe`-forbidden and cross-build to `wasm32`.
- **Geometry/field are genuinely general over `q`.** `Plane::<F2/F7/F13/F31>` compute `N`, line size, and `|PGL(3,q)|` correctly; the cross-product rendezvous and incidence are Field-generic. The O(1)-rendezvous claim is real at this layer.
- **PQ primitives are real, not placeholders.** True hybrid Ed25519+ML-DSA-65 (both-must-verify) and X25519+ML-KEM-768 with a SHAKE256 combiner; ristretto255 VOPRF+DLEQ and `vrf-r255` VRF are real constructions. Domain separation (`label ‖ 0x1f ‖ data`) is prefix-free, correct, and cross-crate parity-tested.
- **The DIAULOS handshake is excellent.** Separate `key_c2s`/`key_s2c` (no cross-direction nonce reuse), a proper hybrid combiner (`ss_static ‖ ss_ephemeral ‖ H(transcript)` through a domain-separated XOF, not naive concatenation), transcript binding of the service identity (MitM/downgrade resistance), forward secrecy from the ephemeral KEM, and a redacted `Debug` for key material. The AEAD cell uses an explicit monotonic per-cell nonce that is fresh on every retransmit — no nonce reuse.
- **Constant-size onions are real.** `ONION_LEN = 8192` with an encrypted length field and keystream padding (`fanos-aphantos/src/sealed.rs`); a passive observer cannot link by size.
- **Genuine robustness already present in the engine:** anti-poisoning membership (canonical-coordinate validation, first-write-wins, bounded by plane size), Byzantine-aware liveness (distinct-witness quorum, not naive per-link), uniformly bounds-checked wire decoders, saturating ACK arithmetic, bounded RRD metric history, and an enforced Φ-budget at the parent tier.
- **CI is strong:** fmt, clippy `-D warnings`, the full test suite, `no_std`/`wasm` cross-builds, and `cargo miri` for UB on the math/crypto core.

---

## 4. Part A — Cross-cutting architectural findings

These are the "lack of fundamentality" items: each is a foundational contract that exists but is not upheld across the system.

### A1 — The canonical wire codec is bypassed by most of the protocol *(HIGH, architectural)*

`fanos-wire` is a proper canonical-encoding crate: minimal-length QUIC varints, field/point/line element codecs, a frame-type registry, the fixed Tessera packet, and a documented invariant — *"exactly one valid byte sequence for every object; a conformant decoder rejects every non-canonical input."* That discipline is exactly what makes cross-language interop and signature/hash agreement possible.

**But only `fanos-aphantos`, `fanos-keygen`, `fanos-nyx`, `fanos-runtime`, and `fanos-sim` depend on it.** Every subsystem added after the spec froze hand-rolls its own big-endian layout with bespoke `to_be_bytes`/`split_at_checked` and its own truncation checks:

- `fanos-diaulos` does not depend on `fanos-wire` at all; its frame/cell/handshake formats are pinned in its own `tests/conformance.rs`.
- `fanos-calypso` (5 files), `fanos-onoma` (3), `fanos-proteus` (4), `fanos-aphantos` onions (8192/20480-byte, not the registry's Tessera), `fanos-rendezvous` (the `Request` wrapper) each maintain a private codec and a private KAT file.

Consequences:

1. **Two frame-type numbering authorities.** The `FrameType` registry (`fanos-wire/src/frame.rs`) enumerates `Hello`/`StreamOpen`/`Tessera`/`RdvIntro`/… but the live DIAULOS layer uses a private `ftype(1)` namespace and the design doc's promised `App = 0x70` frame is unregistered. The registry describes the *spec-era* protocol; the *running* protocol lives outside it.
2. **The "reject non-canonical" guarantee is enforced only inside `fanos-wire`'s five clients.** The hand-rolled decoders vary in whether they reject trailing bytes, non-minimal lengths, or out-of-range coordinates — the property that makes canonical hashing sound is no longer uniform.
3. **The canonical `Tessera` layout is stale and now *unsafe as a reference*.** It still carries a cleartext `HOLONOMY_TAG` header field (`fanos-wire/src/tessera.rs`) — the exact cross-hop correlator a prior audit removed from the live `aphantos` onion. Anyone re-implementing FANOS from the canonical packet would reintroduce the leak. The real onions are 8192/20480 bytes; the canonical one is 4096. The canonical artifact and the implementation have diverged.
4. **`#[derive(Wire)]` — the design's answer to exactly this (one type definition emitting codec + KAT) — does not exist** (see G2). The manual approach is duplicative and multiplies the number of hand-written decoders that can panic or disagree.

**Recommendation.** Treat `fanos-wire` as the mandatory substrate: (a) build the `#[derive(Wire)]` proc-macro so every framed type derives its codec and emits its KAT from one definition; (b) migrate DIAULOS/rendezvous/ONOMA/CALYPSO/PROTEUS frames onto it, registering their type codes in the one registry; (c) regenerate the canonical `Tessera`/onion layout from the real `aphantos` format and delete the stale cleartext-holonomy packet. This is the single highest-leverage structural fix in the audit.

**Progress (ARCH-1 / #82).** `#[derive(Wire)]` **exists** (`fanos-wire-derive`; consequence 4 above is stale) and is now the substrate for the migratable surface:

- **Enablers added** so composite types derive: `Wire` for `f64`, `Vec<T>`, `VecDeque<T>`, `Option<T>`, the field-erased `Triple` (`[u32;3]`, 12-byte), typed `Point<F>`/`Line<F>` (field-optimal, validated), and `Epoch` (8-byte BE, behind `fanos-primitives/wire`).
- **Struct families migrated to the derive** (each re-canonicalized to §7.1 BE+varint, KATs held or absent, hand-rolled decoders deleted): calypso `Descriptor`/`SealedDescriptor` (was LE + u32-prefix), telemetry `Bucket`/`Series`/`Tier`/`Snapshot` history persistence (deleted 13 helpers), rendezvous `Request` (also fixed a latent >255-hop `u8` truncation), quic `NodeCredentials`, plus the pre-existing telemetry `CoherenceFrame` and runtime `LookupBody`. Signing transcripts that could canonicalize did (calypso descriptor `signing_bytes` now uses `encode_bytes` + BE epoch).
- **Justified must-stay-custom** (a change would lose a real property, not reduce drift):
  - *Signing/hash transcripts* (Tier 3): onoma `signing_bytes` (epoch LE is **names.json-KAT-pinned**), calypso-balance `signing_message`/`delegation_message`/`body_bytes` (encode **shares** `body_bytes` with signing — a separate codec would *create* drift), runtime `descriptor_message` (§80 sig), diaulos handshake, kem `combine`, incentives DLEQ.
  - *Onion / AEAD / traffic-shape layouts* (Tier 4, several KAT-pinned): aphantos `sealed`/`threshold`, nyx `tessera`, diaulos `frame`/`cell`, proteus `obfuscate`.
  - *Foreign-crypto fixed wrappers* (Tier 5): pqcrypto kem/sig, vrf `VssShare`/`VssCommitment` (Ristretto **group-validation** on decode), the node-ID key bundle.
  - `geometry::HierAddr` already is a single validated codec (its `u8` depth equals a varint for all `depth < 64 = MAX_DEPTH`, so migrating buys no canonicity and would only risk the `Point::new` validation).

Net: the drift-prone hand-rolled **struct (de)serializers** are gone; what remains hand-written is transcripts, layered crypto, and group-validated foreign types — where a single explicit codec is the correct engineering, not a bypass. **All four consequences are now resolved:**

- *(1) Two frame-type authorities* → **resolved.** `fanos-wire` now owns both registries: the outer `FrameType` **and** a new `SessionFrameType` (the inner encrypted-cell session frames — a deliberately distinct layer, like QUIC frames inside a packet). `fanos-diaulos` derives its `ftype` bytes from `SessionFrameType`, and the designed application-overlay frame is registered as `FrameType::App = 0x70`.
- *(2) Non-uniform "reject non-canonical"* → **resolved for every wire object.** Each migrated struct decodes through `Wire::from_wire` (rejects trailing/non-minimal/out-of-range uniformly). No crate hand-rolls a duplicate integer/`Cursor` decoder any longer — diaulos's frame decoder and calypso-balance's `Cursor`/`put_bytes` were the last two, both eliminated.
- *(3) Stale cleartext `Tessera`* → **already resolved** (`tessera.rs`: `TOTAL_LEN = 8192`, path authenticator encrypted inside `body_ct`, cleartext `holonomy_tag` removed).
- *(4) `#[derive(Wire)]` absent* → **stale/false**: it exists (`fanos-wire-derive`) and is the substrate for the whole migration.

The remaining hand-written byte code is **not** a wire-codec bypass: it is either a hash preimage / signing transcript (domain-specific, some KAT-pinned — e.g. onoma's names.json LE family), an onion/AEAD/traffic-shape crypto layer (aphantos, nyx, diaulos cell, proteus — KAT-pinned), or a group-validated foreign-crypto wrapper (kem/sig/vss). Each is one explicit codec with a real invariant to enforce, which `#[derive(Wire)]` cannot express — so keeping it custom is the correct engineering, and A1 is closed.

### A2 — General-`q` capability is stranded below a `q=2` ceiling *(MEDIUM, architectural)*

The addressing substrate is generic over `q`, but **DIAKRISIS is hardcoded to `N = 7`** in every module (`blindness.rs`, `polar.rs`, `partition.rs`, `coherence.rs`, `healing.rs`, `regeneration.rs`: `pub const N: usize = 7`, fixed `[[f64; 7]; 7]` kernels, `1.0/7.0` constants). This is *theoretically correct* — the 3-bit Hamming(7,4) syndrome is intrinsically a Fano-plane object — but its architectural consequence is under-acknowledged: the entire live stack above geometry (self-diagnosis, healing, the runtime, the node binary, which fixes `F = F2`) is **`q=2`-only**. The `Plane::<F7/F13/F31>` generality is exercised only in geometry unit tests; nothing above geometry can run a large-`q` cell.

So the headline "scale via large-`q`, O(1) rendezvous over `q²+q+1` nodes" is real as algebra but **unreachable as a running system** — scaling is available only through the `q=2` self-similar hierarchy. This needs an explicit decision, recorded in the design:

- If large-`q` cells are a genuine deployment target, DIAKRISIS and the runtime need a general-`q` self-observation story (how a 993-node cell is diagnosed by 7-element structures), or
- If `q=2` + hierarchy is *the* model, document the large-`q` `Plane` as spec-completeness — not a scaling lever — so the capability is not mistaken for a shipping one.

**Resolved (#66).** Decision recorded in `docs/design-coordinates.md` §5: `q = 2` + a recursion of cells is *the* deployment scaling model (spec §L1 Hierarchy, verified V4 — internet scale is `k` levels of Fano cells, `O(log n)` state/depth); the large-`q` `Plane` is retained as **spec-completeness** (the theorems are general-`q`, and it keeps the algebra testable at `q ∈ {7,13,31}`), **not** a scaling lever — no large-`q` cell runs above geometry; and DIAKRISIS `N = 7` is **base-cell proprioception** (the 3-bit Hamming(7,4) syndrome is intrinsically a Fano-plane object, spec Part VI), diagnosing upward by escalation, not a ceiling to be lifted.

### A3 — "epoch" is three different quantities with no unifying type *(MEDIUM)*

Epoch is a raw integer with divergent widths and, worse, divergent *semantics*:

- **`u32` beacon/coordinate epoch:** `fanos-crypto` VRF, `fanos-core` membership, `fanos-calypso` balance + `lib`, `fanos-proteus`, `fanos-quic`.
- **`u64` naming/descriptor epoch:** `fanos-onoma`, `fanos-calypso` *descriptor* (!), `fanos-node`.
- **`u64` telemetry frame epoch** = `now_nanos / window`, where under the QUIC driver `now = origin.elapsed()` is measured from **each node's own start**, so two nodes emit *different* epoch values for the same wall-clock window.

`fanos-calypso` is internally inconsistent — `balance.rs`/`lib.rs` use `u32` while `descriptor.rs` uses `u64` for the same descriptor concept. There is no `Epoch` newtype, so the compiler cannot catch a mismatch, and the telemetry frame epoch's premise that "nodes agree on which window they describe" is false off the simulator's shared virtual clock: any `(cell_id, epoch)`-keyed cross-node roll-up mis-buckets in production.

**Recommendation.** Introduce one `Epoch(u64)` newtype in a foundational crate. Where a KAT pins a 32-bit encoding (the VRF `coord_input`), encode only the low 32 bits with a documented comment so the wire stays stable while the *type* unifies. Derive the telemetry frame epoch from the consensus beacon, not from per-node local elapsed time, and rename it if it stays a distinct concept.

**Resolved (ARCH-9 / #90).** `fanos_primitives::Epoch(u64)` is the one canonical newtype (`epoch.rs`), threaded through every protocol-epoch seam — VRF/coordinate (`primitives::vrf`, `fanos-vrf`), membership (`fanos-core`), naming/descriptor (`fanos-onoma`, `fanos-calypso` *descriptor + balance + lib + rendezvous*), proteus, the runtime beacon (`overlay.rs`) and its `Notification::EpochAdvanced(Epoch)`, and `fanos-node`. The compiler now forbids mixing an epoch with any other integer, and the calypso `u32`/`u64` descriptor split is gone. Wire stability is preserved per-site by three documented codecs — `to_le_bytes`/`to_be_bytes` (8-byte, the onoma-descriptor and telemetry families) and `low32_be_bytes`/`from_low32_be_bytes` (the KAT-pinned 4-byte coordinate/beacon/proteus/balance family) — and every KAT (names.json, services.json, L4 storage, coordinate derivation) still passes byte-for-byte. The telemetry **frame** epoch stays a distinct `u64` observation-window counter (as this note anticipated); the runtime now feeds it the *agreed flooded-beacon* `Epoch` via an explicit `self.epoch.get()` at `overlay.rs`'s `observe_liveness` call, so the cross-node `(cell_id, epoch)` roll-up buckets on the beacon, not per-node local time.

### A4 — Unbounded state and absent back-pressure (systemic DoS class) *(HIGH)*

The same shape recurs everywhere state is keyed by a peer- or attacker-chosen value with no eviction:

- **`fanos-rendezvous/src/transport.rs:149`** — `RendezvousService::routes` inserts a reply circuit per distinct cookie and never evicts. A client sending many cookies grows it without bound.
- **`fanos-node/src/diaulos.rs:93`** — the `serve` loop's `sessions` map is keyed by peer coordinate with no idle GC; a half-open session lingers forever.
- **`fanos-session/src/lib.rs:73-74`** (A4b) — `dial_over_transport` wires the async stream to the datagram transport through **unbounded** channels; there is no flow-control coupling, so a fast writer or slow network grows memory unbounded.
- The transport-layer instances of this are C1/C2/C3 (waiter maps, driver channels, receiver buffer).

**Recommendation.** Every peer-/attacker-keyed map needs a cap and a TTL/LRU reaper; every driver/session channel needs a bound with await-based back-pressure so the engine's own flow control is honored rather than discarded at the boundary.

### A5 — The anonymous path is not wired into the shipping node *(HIGH, architectural)*

`fanos-rendezvous` (the anonymous DIAULOS meeting-line transport) is a complete sans-I/O core and is e2e-tested — **but only in `fanos-sim`** (`tests/anonymous_rendezvous.rs`). **`fanos-node` does not depend on `fanos-rendezvous`.** The shipping `fanos` binary therefore offers only the *Direct* profile, which addresses services by coordinate and reveals *where* each party is. The project's headline positioning — "provably-anonymous, censorship-circumventing VPN" — is not reachable through the binary today; it exists as a simulated capability. This is an honest in-progress state, but it should be named as such in the roadmap and README rather than implied to be shipping.

### A6 — No secret-material hygiene (`zeroize`/`subtle`) *(HIGH)*

No workspace crate depends on `zeroize` or `subtle` (both appear only transitively in `Cargo.lock`). Consequently:

- **No secret is wiped on drop.** `HybridSigSecret`, `HybridKemSecret`, `VrfSecret`, `StaticKeypair`, `DkgNode.secret`, `CreditIssuer.k`, DIAULOS session keys, and Shamir shares all linger in freed memory.
- **`VrfSecret` derives `Copy` + `Debug`** (`fanos-vrf/src/lib.rs:42-43`): `Debug` can print the raw key, and `Copy` scatters unwipeable stack copies.
- FANOS-level secret comparisons have no constant-time path available. (AEAD tag verification itself *is* constant-time — delegated to `chacha20poly1305` — so this is latent rather than currently-exploited, but the mandate's "best-in-class" bar is not met.)

**Recommendation.** Add `zeroize`; wrap secrets in `Zeroizing`/`#[derive(ZeroizeOnDrop)]`; drop `Copy`/`Debug` on key types; add `subtle` for any future secret/tag comparison.

### A7 — Real primitive built, insecure placeholder shipped *(MEDIUM)*

`fanos-core/src/membership.rs:32` derives every live node coordinate with `fanos_crypto::coordinate_for`, whose own doc-comment reads *"**not** unforgeable … standing in for `MapToPoint(VRF(pubkey, epoch))` until ECVRF is wired in."* Meanwhile the real `fanos_vrf::{prove,verify}_coordinate` — the entire reason `fanos-vrf` exists — has **zero non-test callers**. Live coordinate placement is thus forgeable by anyone (a deterministic hash, not a VRF), so the anti-grinding / Sybil-placement resistance the VRF was designed for is not enforced anywhere in the running system. Either wire `fanos-vrf` into membership/beacon or delete the placeholder and make the gap explicit; shipping the weaker of two same-named primitives from the more-depended-upon crate is a fundamentality hazard.

**Resolved (#66, commits `b90e35d` foundation + `6b6c2f2` live path — Level A).** The real VRF is now the coordinate authority, beacon-folded and identity-bound: `coord = MapToPoint(VRF(vrf_sk, id ‖ epoch ‖ beacon))`. `fanos-vrf` was made `no_std` so the identity core can depend on it; the node identity commits the VRF key (`HybridPublicKey`/cert gain a VRF public, so `NodeId = H(bundle)` / `H(cert)` commits it — a proof cannot be transplanted onto another identity); `fanos-core::membership::Member::{assign,verified}` prove + check it; and the live QUIC node's coordinate is the VRF one, exchanged and verified in a mutual proof-of-coordinate **HELLO** (spec §7.3) at connection time — replacing the pure cert→coord derivation. The forgeable `coordinate_for` is demoted to the documented no_std addressing reference. Full design + the security/operational analysis: `docs/design-coordinates.md`. **Remaining (tracked, #95 — Level B):** the live per-epoch reshuffle *operation* and unifying the multi-level #79 hash-chain hierarchy address under the VRF — the base cell uses the VRF coordinate consistently today.

---

## 5. Part B — Cryptography & key management

### B1 — DKG complaint/commit/justify frames are unauthenticated *(CRITICAL)* — **RESOLVED**

~~`fanos-keygen/src/lib.rs:397-402` dispatches inbound frames and passes only `f.body` to `on_commit`/`on_complaint`/`on_justify` — the transport sender `from` is discarded (contrast `on_deal`, which does receive `from`). `complaint_frame` (`:434-437`) is literally `[complainer, dealer]` with no signature. A single Byzantine member can therefore broadcast `DkgComplaint{complainer = d, dealer = d}` against any honest dealer `d`; the accused's self-justify guard (`c != self.index`, `:263`) prevents `d` from answering its own "complaint," and because complaints are reliably echoed, every honest node drops `d` from `QUAL` consistently at `finalize`. An adversary can evict every honest dealer, force `|QUAL| < t` (DoS), or reduce `QUAL` to attacker dealers. `on_commit` is likewise unauthenticated and first-writer-wins, so a bogus commitment can be pre-registered for a silent dealer. This voids the "Byzantine-robust GJKR" claim, and it is entirely untested.~~ **Done.** `on_commit` (`fanos-keygen/src/lib.rs:281-293`) now requires `self.dealer_of(from) == Some(d)` — a commitment is accepted only direct from its own dealer. `on_complaint` (`:302-328`) now requires `self.dealer_of(from) == Some(c)` — a complaint is accepted only direct from its own complainer, closing the forged-eviction path. Pinned by `a_forged_complaint_cannot_evict_an_honest_dealer` and `a_commitment_is_only_accepted_from_its_own_dealer` (`:604,648`).

### B2 — DKG `ingest_share` result discarded *(CRITICAL)* — **RESOLVED**

~~`fanos-keygen/src/lib.rs:358-364` calls `self.participant.ingest_share(share, commitment)` (which folds the share only if the Feldman check passes) but pushes `commitment` into `refs` **unconditionally**. A dealer can thus end up in `QUAL` with its `C₀` summed into the joint key `Y` while its share is *not* folded into the final secret share, so `x·G ≠ Y` and any `t` final shares reconstruct a secret that does not match the published key.~~ **Done.** `finalize` (`fanos-keygen/src/lib.rs:415-429`) now gates the push — `if self.participant.ingest_share(share, commitment) { refs.push(commitment); }` — so a dealer's commitment reaches the joint key `Y` only if its share actually folded into the final secret share; `Y` and the final share are folded over the identical `QUAL` set.

### B3 — DKG justification verified against the wrong commitment *(CRITICAL)* — **RESOLVED**

~~`on_justify` (`:286`) verifies the revealed share against the commitment carried *in the justify frame*, not the commitment everyone qualified on (`note_commitment` is a no-op once one is stored). An equivocating dealer answers a complaint with an internally-consistent `(share', commitment')` unrelated to the qualified `C`, clearing the complaint without revealing a share consistent with `QUAL` — the mechanism that makes B2 exploitable.~~ **Done.** `on_justify` (`fanos-keygen/src/lib.rs:337-362`) now verifies against `self.commitments.get(&d)` — the commitment the node already qualified on — ignoring any commitment carried in the justify frame's body. Pinned by `a_justification_is_checked_against_the_qualified_commitment` (`:681`).

> **Resolved.** B1–B3 together were the reason the DKG — the one bespoke cryptographic protocol in the workspace — was not Byzantine-robust and was untested. All three are fixed, and `fanos-keygen` now carries dedicated adversary tests (forged-complaint eviction, foreign-dealer commitment injection, wrong-commitment justification), plus a session-nonce-freshness test (B6) and a beacon-material-consistency test. This was the highest-priority cluster in the audit and is now closed.

### B4 — DLEQ proof nonce comes from a caller RNG *(HIGH)* — **RESOLVED**

~~`fanos-incentives/src/lib.rs:64-77` draws the Chaum–Pedersen nonce `s = Scalar::random(rng)`. Every RNG in this repo is a deterministic BLAKE3 PRG (`SeedRng`/`DeterministicRng`/`TestRng`). Two issuances under the same seed reuse `s`; with `z = s + c·k` and distinct challenges, `k = (z₁−z₂)/(c₁−c₂)` — full issuer-key recovery.~~ **Done.** `synthetic_dleq_nonce` (`fanos-incentives/src/lib.rs:89-103`) now derives the nonce deterministically as `s = H(k ‖ K ‖ B ‖ Z)` (RFC-6979-style, over the issuer secret and the full DLEQ transcript) — no caller RNG involved, so a weak/reused/deterministic RNG can no longer leak `k`. Pinned by `the_dleq_proof_is_deterministic_so_a_bad_rng_cannot_leak_the_key` (`:494`). The beacon's analogous Chaum–Pedersen proof (`fanos-vrf/src/beacon.rs`) uses the same synthetic-nonce discipline.

### B5 — Hybrid KEM combiner does not bind the transcript *(MEDIUM)* — **PARTIAL (#63)**

~~`fanos-pqcrypto/src/kem.rs:78-86` hashes only `label ‖ x25519_ss ‖ mlkem_ss`, omitting the X25519 ephemeral public key and the ML-KEM ciphertext, so it does not meet the X-Wing / CFRG hybrid binding guidance (MAL-BIND-K,PK/CT), and there is no low-order/all-zero check on the X25519 shared secret. IND-CCA survives on the ML-KEM half, but binding does not.~~ **Transcript binding done.** `combine` (`fanos-pqcrypto/src/kem.rs:80-103`) now hashes `label ‖ x25519_ss ‖ mlkem_ss ‖ x25519_ephemeral ‖ mlkem_ct ‖ x25519_recipient_pk` — the full transcript, X-Wing/MAL-BIND-K,PK/CT-style. Pinned by `the_combiner_binds_every_transcript_element`. **Residual still open:** neither `encapsulate` (`:128`) nor `decapsulate` (`:188`) checks the X25519 `diffie_hellman` output for a low-order/all-zero (non-contributory) result before it enters the combiner — grep for `contributory`/`is_identity` in the crate is empty. **Fix (remaining):** reject a non-contributory X25519 shared secret before combining.

### B6 — DKG polynomial randomness seeded solely by the long-term secret *(MEDIUM)* — **RESOLVED**

~~`fanos-keygen/src/lib.rs:147` builds `DeterministicRng::new(&self.secret)`, making all VSS coefficients a deterministic function of the static secret — re-running DKG reproduces identical shares, with no per-run entropy.~~ **Done.** `DkgNode` now carries a `session_nonce: [u8; 32]` (`fanos-keygen/src/lib.rs:87`), fresh per DKG instance, folded with the long-term secret into the polynomial seed (`secret ‖ session_nonce`, `:181-187`) and zeroized on drop (`:478`). Re-running DKG with the same secret but a different session nonce now yields different dealings; the same `(secret, nonce)` stays deterministic (the sans-I/O replay property is preserved). Pinned by `a_fresh_session_nonce_makes_the_dealing_fresh` (`:730`).

### B7 — Non-constant-time GF(256) multiply on secret shares *(MEDIUM)* — **RESOLVED (#63)**

~~`fanos-field/src/gf2m.rs:72-86` branches on operand bits (`if b & 1`, `if overflow != 0`); `fanos-crypto/src/shamir.rs:110-125` runs this multiply on secret shares → data-dependent timing on secret material. The module comment claims a "sound basis for a constant-time build," but the shipped code is branchy.~~ **Done.** `clmul` (`fanos-field/src/gf2m.rs:60-85`) is now branchless: both the per-bit accumulation and the reduction step use a `0u32.wrapping_sub(bit)` all-ones/all-zeros mask instead of an `if`, so the multiply runs in data-independent time. The function's own doc comment now cites this fix directly ("used on secret Shamir shares (audit B7)").

### B8 — Overstated standards conformance; bearer credits without redemption binding *(MEDIUM)* — **RESOLVED (#63)**

~~The VOPRF advertised RFC 9497/9578 and the VRF advertised RFC 9381 while both use bespoke/ristretto constructions wire-incompatible with those ciphersuites; and relay credits were bearer tokens with no redemption context, so a credit shown for redemption could be replayed/front-run in flight.~~ **Done.** The conformance overclaims were corrected in-doc (the RFCs are cited as *reference, not conformance* — see the crate docs, d204b87). **Redemption is now context-bound** (`fanos-incentives`, 0932ec5): a client presents `Credit::prove(context) → RedeemProof { x, authenticator = H(N ‖ context) }` instead of the raw credit — it holds `N` and computes the authenticator; `CreditIssuer::redeem(proof, context)` recomputes `N = k·H(x)`, checks the authenticator **in constant time**, then double-spends on `x`. `N` never travels, so an in-flight observer (seeing only `(x, authenticator)`) cannot forge a proof for a *different* context — no cross-context replay/front-run — while one credit still redeems exactly once. `paid_intro` binds the proof to the descriptor key (its natural per-`(service, epoch)` context). Pinned by `a_credit_redemption_is_bound_to_its_context`.

**Lower-severity crypto items:** `fanos-vrf/src/lib.rs:87-88` `prove` self-verify falls back to an all-zero output on an (unreachable) failure rather than erroring; `fanos-crypto/src/maptopoint.rs:94,102` has a `Point::at(0)`/`Line::at(0)` dead fallback that would bias to a fixed element if reached; `fanos-keygen/src/lib.rs:97-99` defaults an unknown coordinate to `index = 1`, colliding with node 1; `fanos-crypto/src/shamir.rs:94` `reconstruct` carries no threshold metadata and silently returns a plausible wrong secret given `< t` shares.

---

## 6. Part C — Engine, transport & control surface

The engine is pure and deterministic (Part 3). The **control surface** (`fanos-quic` Router/`Client`) and the reflexive-healing loop are where productionization is incomplete.

### C1 — No request timeouts; waiter maps leak *(HIGH)*

`fanos-quic/src/driver.rs:210-243` — `Client::get`/`put` do `rx.await` with no timeout. The waiter is inserted into the router's `gets`/`puts` map and removed only when a matching digest returns. There is **no put-ack timeout or retry anywhere in the engine** (`overlay.rs:415,560-565`), so a down primary means `Stored` never fires, `put()` awaits forever, and the map entry leaks; the `get` path leaks whenever the heartbeat sweep is off. A SOCKS5 proxy resolving many unreachable `.fanos` names accumulates orphaned waiters with no eviction. **Fix:** `tokio::time::timeout` around the await, request-id correlation so the specific waiter can be evicted, a TTL reaper, and an engine-level put-completion timeout emitting a negative notification.

### C2 — Unbounded channels + single-task transport = no back-pressure *(HIGH)*

All four driver channels are `mpsc::unbounded_channel` (`driver.rs:469-472`), and `transport_loop` (`:553-575`) is a single task that awaits each peer's full QUIC `connect` inline before writing. One slow/unreachable peer blocks **all** overlay sends while the engine keeps pushing `Effect::Send` into an unbounded queue; inbound, `read_frames` accepts up to 1 MiB per uni-stream, so an authenticated peer opening many streams floods the engine's input queue faster than the single engine actor drains it. **A connected peer can OOM the node, and one slow peer stalls all traffic.** **Fix:** bounded channels with await-based back-pressure, per-peer send tasks / a dial pool, and caps on concurrent inbound connections and in-flight frames.

### C3 — Receiver flow control is advisory, not enforced *(HIGH)*

`fanos-runtime/src/stream.rs:288-289` admits a segment when `seq >= delivered && seq < next + recv_window`. Because the upper bound is anchored at `next` (which advances on contiguous *receipt*, `:297-299`) rather than at `delivered` (which advances only on `take()`, `:325-334`), the next in-order segment is **always** admitted regardless of how far the application's drain lags. A peer streaming in-order data that the app does not `take()` — or a peer ignoring an advertised `rwnd = 0` — grows the `received` buffer without bound. The module's "the receive buffer is bounded" guarantee is false on the in-order path. *(Verified by hand.)* **Fix:** anchor admission at `delivered + recv_window`, or hard-cap `received.len()`.

### C4 — Content-digest correlation is not request-scoped *(MEDIUM)*

`overlay.rs:509-523` emits `Retrieved` on **any** `found = true` Value, even with no in-flight get, and the driver correlates purely by storage digest (coalescing same-key waiters). Because the store is mutable, a delayed or replayed Value from a prior get can drain a later same-key get's waiter with an **old** value (a read-your-writes violation); symmetrically, two concurrent puts of the same key with different values both report success though only one persists. **Fix:** emit `Retrieved` only when a matching pending get exists; carry a per-request nonce end-to-end and correlate on it.

### C5 — Quarantine is permanent and locally-decided *(MEDIUM)*

`overlay.rs:746` inserts a quarantined coordinate and never removes it (contrast reroute/repaired, cleared on Pong/gossip), and the verdict is driven by **local liveness-only** diagnosis whose own comment concedes that partition/cascade verdicts need the global view. A transient or mis-diagnosed Byzantine verdict permanently partitions a node — and there is no restoration theorem behind it. **Fix:** expire quarantine on a timer or on parental re-provisioning, and require multi-witness corroboration before quarantining.

### C6 — `Decouple` is a no-op; the reflexive loop cannot lower Φ *(MEDIUM)*

`overlay.rs:750-752` — `Decouple` only pushes a `Notification::Decoupled`; `healthy_correlation` is an immutable `Config` value and Φ is recomputed from it each round, so nothing actually sheds correlation. The spec's "shed correlation to restore headroom" (§2.7/§6.5) is therefore cosmetic — the self-healing loop's marquee cascade response does not change the quantity it targets. (`Decouple`/`Escalate` also re-notify on every `Diagnose`, unlike the deduplicated Reroute/Repair/Quarantine, so a persistent fault spams notifications.) **Fix:** give the engine mutable decoupling state that reduces effective correlation and feeds back into `phi_equicorrelated`; dedup the notifications.

### C7 — Telemetry "self-observation is anonymization" is false *(MEDIUM)*

`fanos-telemetry` claims "the fold *is* the anonymization," but the crate contains no differential-privacy machinery (no noise, no ε budget). The `CoherenceFrame` carries the **exact** 3-bit syndrome naming the faulted point plus exact Φ/P/R/mean-r/gap scalars (`frame.rs:58-72`), emitted as `Notification::Observed` and gossip-able. Any frame observer learns which node is down and the cell's exact health each window. (Self-observation being *mandatory and embedded* is correct and sound — only the anonymization claim is false; local history is properly bounded via RRD ring buffers.) **Fix:** add calibrated noise, coarsen/withhold the syndrome, track an ε budget — or drop the anonymization claim.

**Lower-severity:** a connection-cache check-then-insert race with no inbound-connection cap (`driver.rs:579-620,642-670`, connection-flood surface); lossy notification delivery under load (`next_notification`/`subscribe` skip on lag past a 4096 ring — no lossless path for `Delivered` payloads); two content-address domains (`routing::content_address` uses `label::COORD` while the engine/driver use `label::STORAGE`) that look interchangeable but resolve to different points; and a `u128→u64` driver-clock truncation (~584 years, noted for completeness).

---

## 7. Part D — Math core

The algebra is the **most fundamentally sound part of the workspace**, and this was cross-validated hard (two independent derivations — const Fano tables vs. generic `Plane<F>` — plus exhaustive and property tests, plus external verification of every field polynomial). The defects are **not in the mathematics** but in its **numerical hygiene at the trust boundary**: the diagnostic plane assumes finite, well-formed `f64` telemetry and neither sanitizes nor defends against `NaN`/`Inf`/non-PSD input. Because DIAKRISIS consumes **gossiped** health reports (`DiagGossip`), these are not merely library-surface issues — a malicious node can gossip non-finite scalars into a victim's diagnosis.

**Verified correct (load-bearing, do not regress):** all core measures reduce to the spec exactly — `Φ = (frob − N)/N`, `P = frob/N²`, `R = N/frob`, with equicorrelated `Φ = (N−1)r²`, `P = (1+(N−1)r²)/N`, `r* = 1/√(N−1)`, `P_crit = 2/N`; every `GF(2^m)` reduction polynomial is irreducible **and** primitive (externally checked), `clmul` shift-and-reduce is correct, and prime-field arithmetic is overflow-safe; geometry cross/dot/canonicalize and `points_on` are brute-force-verified for F2/F7/F13/F31 and `pgl3_order` is exact in `u128`; Hamming(7,4) syndrome masks and the LRC `peel_fano`/`is_hyperoval_fano` are exhaustively correct over all 128 masks (exactly 7 hyperovals); and `fanos-wire` is genuinely canonical and panic-free on truncated/adversarial input (non-minimal varints, out-of-range elements, and non-canonical coords are all rejected; lengths use `usize::try_from` + `checked_add`, wasm-safe). The `N = 7` hardcoding is **intentional and honest** — DIAKRISIS is defined on the base Fano cell `PG(2,2)` (spec Part VI), the coherence/window measures are properly general-`N`, and the `_fano` suffixes make the specialization explicit. (Its *architectural* consequence is A2, not a correctness bug.)

### D1 — `max_reroute_depth` never terminates on a non-finite Φ *(HIGH — live-confirmed DoS)*

`fanos-diakrisis/src/healing.rs:39-50` — the loop `while current * (1/9) >= 1.0 { current *= 1/9; depth += 1 }` never exits when `current = +Inf` (`Inf · 1/9 = Inf ≥ 1` forever), and `depth: u32` overflows — an **infinite loop in release, an overflow panic in debug**. Confirmed live: the call did not return within 2 s. It is reachable because `plan_healing` takes the cell's measured `Φ`, and `Φ = Inf` is producible via D2. A crafted/garbage coherence reading hangs or crashes the healing controller. **Fix:** `if !phi.is_finite() { return 0 }` and cap the loop at a constant (`Φ/9^d` needs ≤ ~40 iterations for any finite `f64`).

### D2 — `from_correlation` accepts non-finite / non-PSD / out-of-range matrices *(HIGH)*

`fanos-diakrisis/src/coherence.rs:86-101` — validation uses `(x−1.0).abs() > 1e-9` and `(a−b).abs() > 1e-9`, both defeated by `NaN` (all `NaN` comparisons are false), with no PSD or `|r| ≤ 1` check. Confirmed live: symmetric `NaN` off-diagonals are accepted → `Φ = NaN`, `is_overcoupled() = true` → `diagnose` returns `Verdict::Systemic` on garbage; an `Inf` entry → `Φ = Inf` (feeds D1); `|r| = 5` non-PSD → `Φ = 50`, `purity = 17`. This causes spurious `Decouple`/`Systemic` misdiagnosis, can violate the V17 leading-indicator ordering, and is the reachability root of D1. **Fix:** reject any non-finite entry; enforce `|c_ij| ≤ 1` and a cheap PSD/diagonal-dominance guard.

### D3 — `violated_classes` treats non-finite rates as consistent — the Byzantine detector is evadable *(MEDIUM-HIGH)*

`fanos-diakrisis/src/polar.rs:100-110` — `(r0−r1).abs() > tol` is `false` when the rates are `NaN`, so an all-`NaN` (or NaN-injected) `pairwise_rates` matrix reports **zero** violated classes. Confirmed live: `diagnose(NaN rates) = Healthy`. The polar-sum-rule Byzantine structural detector (spec §6.2) can be evaded by a node emitting non-finite rate reports. **Fix:** treat any non-finite entry in a class as a violation, or reject the observation up front.

### D4 — Jacobi eigen-solver has no convergence/robustness signal *(MEDIUM, latent)*

`fanos-diakrisis/src/eig.rs:28-70` runs a fixed 100 sweeps with an *absolute*, non-norm-scaled off-diagonal threshold and silently returns the diagonal; `NaN`/`Inf` propagate silently, and a `NaN` Laplacian yields `fiedler_value = NaN` → `is_connected = false` → spurious `Partition`. For the actual partition path the Laplacian is built from a `u8` line mask (always finite), so this is **not currently reachable** — hence latent — but it is a sharp edge on the library surface. **Fix:** scale the threshold by the Frobenius norm, add an early non-finite check, and expose a "did not converge" signal.

**Test-coverage gaps (LOW-MEDIUM):** the `Gf2m<M>` table for `M ∈ {6,7,9..16}` is never instantiated by any test (the auditor externally verified all 16 are irreducible and primitive — no bug, but unguarded against future edits); the `from_correlation` rejection paths and the non-finite/non-PSD acceptance are untested; `eig.rs` edge cases (`n = 0/1`, the length-mismatch panic, non-convergence, non-finite input) are untested; and `fanos-wire` decoders have no proptest over arbitrary/truncated byte slices (the code is defensive, so this is hygiene, not a known defect).

## 8. Part E — Privacy & anonymity

The cryptographic core of the mixnet is real and well-built. The gap is between that core and the **system-level GPA claims for the strongest (Full) profile**: the very profile advertised as exceeding Nym is, on the traffic-analysis axis, currently *weaker* than the Lite profile it supposedly surpasses.

**Verified sound (do not regress):** the hybrid KEM is real (`ml_kem::MlKem768` ‖ `x25519-dalek`, SHAKE256-combined, `CIPHERTEXT_LEN = 1120`); threshold soundness on the live path is genuine — `fanos-aphantos/src/threshold.rs` KEM-seals each Shamir share to its member's public key, a member decapsulates only its own slot, and `shares_are_not_in_the_clear` confirms no cleartext shares (below-threshold ⇒ wrong key ⇒ AEAD fail); Shamir is textbook-correct GF(256), fails closed; onion-path AEAD nonces are distinct per hop with no cross-layer reuse; holonomy is encrypted end-to-end (not a cleartext correlator — test-verified); onions are constant-size on the wire; bech32m is BIP-350-correct and `Address` is a BLAKE3-256 commitment to the whole PQ bundle (2¹²⁸ second-preimage); CALYPSO-Balance HRW + the root→signing-key→delegation chain and the Lindblad stability math are correct.

### E1 — Full/threshold profile emits no cover traffic *(HIGH)* — **RESOLVED (#61)**

~~`fanos-aphantos/src/threshold_router.rs` … no cover-cell emission …~~ **Done.** `ThresholdRouter` now has `with_cover`/`arm_cover`/`start_cover`/`emit_cover` (constant-size cover cells via `hash_xof("FANOS-v1/threshold-cover-body")`, armed on an exponential gap keyed by `cover_prf_unit`). Pinned by `threshold_router::tests::cover_traffic_emits_indistinguishable_constant_size_cells_at_a_uniform_rate`.

### E2 — Threshold mix delays are a public, predictable function *(HIGH)* — **RESOLVED (#61)**

~~`threshold_router.rs` — `sample_delay` seeds the exponential from the node's public coordinate …~~ **Done.** `sample_delay` now seeds from `self.mix_seed = kem_secret.derive_subkey("FANOS-v1/threshold-mix-seed")` — a **secret** subkey, not the public coordinate — so the delay sequence is unpredictable to a GPA. Pinned by `threshold_router::tests::the_mixing_delay_is_secret_keyed_not_a_public_function_of_the_coordinate`.

### E3 — Descriptor uses a deterministic AEAD nonce with catastrophic reuse on republish *(MEDIUM, sharpest latent correctness bug)* — **RESOLVED**

~~`nonce = H(addr‖epoch)[..12]` was fixed per `(addr, epoch)`, so a service refreshing its descriptor mid-epoch reused the exact `(key, nonce)` on different plaintext → ChaCha20 keystream reuse + Poly1305 forgeries.~~ **Done.** `fanos-calypso/src/descriptor.rs` now derives a **SIV-style per-publish salt** bound to the plaintext — `nonce_salt = H(NONCE_SALT_LABEL ‖ plaintext)`, folded into `nonce = H(addr ‖ epoch ‖ salt)` — carried in `SealedDescriptor.nonce_salt` and authenticated by the AEAD tag. A *changed* body yields a *fresh* nonce (no reuse); an *identical* body yields an identical nonce (safe — same message), so it is misuse-resistant with no entropy required. Pinned by `descriptor::tests::a_mid_epoch_republish_of_a_changed_body_uses_a_fresh_nonce` (+ the salt round-trips through the wire form and a swapped salt fails AEAD). **The related latent instance is also fixed:** the onion nonce counter resets to 0 on reboot, so `NyxNode::new` now mixes a fresh **`boot_nonce`** into the node seed (every circuit/cover/delay PRF derives from it), so a restart never re-derives the same per-hop onion key/AEAD nonce — pinned by `node::tests::a_fresh_boot_nonce_freshens_the_seed_so_reboots_dont_reuse_onion_nonces`.

### E4 — Forward secrecy is sender-side only; no relay-key rotation *(MEDIUM)* — **RESOLVED on the Full/threshold path (#61)**

~~The KEM encapsulated to relays' **long-term** hybrid keys, so a GPA that records onion `kem_ct` and later compromises a relay's long-term secret decrypts all past hops through it — the standard mixnet FS threat.~~ **Done on `ThresholdRouter`.** Each relay now peels with a **separate, forward-secure per-epoch onion keypair** (`fanos-pqcrypto/src/onion_ratchet.rs::OnionKeyRatchet`), distinct from the long-term identity KEM in its node-ID bundle (rotating that would change `node_id`). Advancing overwrites the seed with a one-way hash `H(seed)`, so a relay compromise yields the current and future keys but **never a past one**: an onion recorded at epoch `e` is unpeelable once the relay ratchets more than the grace window past `e`. The genesis seed is fresh entropy in production (never derived from the identity key, or the FS would be illusory). The relay advances on `Command::AdvanceEpoch` and peels with `onion.secrets()` — the current epoch plus a bounded `retain`-epoch **grace window** (default 1), so onions in flight across a rotation still peel while FS exposure stays bounded to `retain` epochs (fail-closed at `retain = 0`; a multi-epoch catch-up jump retains no stale key). Discovery is epoch-scoped: `fanos-node/src/mixdir.rs` publishes/resolves each relay's onion public at a `(coord, epoch)`-tagged store slot, so a client seals to the current epoch's key. Pinned by `onion_ratchet::tests::{a_ratchet_that_advances_cannot_decrypt_a_past_epochs_onion, the_grace_window_peels_across_one_rotation_then_forward_secrecy_takes_over, retain_zero_is_fail_closed_with_no_grace_window, a_multi_epoch_catch_up_jump_retains_no_stale_key}` and `threshold_router::tests::a_recorded_onion_survives_one_rotation_then_becomes_unpeelable`, and end-to-end in the sim and over real QUIC. The epoch clock that issues `AdvanceEpoch` and triggers the per-epoch key republish is the E5 rendezvous beacon, now built as the `fanos-keygen::BeaconNode` engine + the `fanos-node::EpochDriver` rotation core (#94, E4∩E5) — the clock is defined once, not re-invented; `EpochDriver` is proven to republish exactly the key the router peels with. (The Lite `NyxNode`/`sealed.rs` path still uses long-term keys; that engine is the lower-assurance profile.)

### E5 — Rendezvous "VRF beacon" is a predictable hash *(MEDIUM)* — **RESOLVED (#61)**

~~`rendezvous_line = MapToLine(H("FANOS-v1/calypso" ‖ pubkey ‖ epoch))` was a plain deterministic hash, so every future meeting line was computable arbitrarily far ahead and an adversary could pre-position on a service's rendezvous line.~~ **Done.** A per-epoch **distributed randomness beacon** now supplies an unpredictable seed folded into the derivation: `L_rdv = MapToLine(H(pubkey ‖ epoch ‖ beacon))`.

- **Beacon (`fanos-vrf/src/beacon.rs`) — pairing-free distributed VRF over the existing ristretto255 DKG.** `M(epoch)` is a public hash-to-curve point; each shareholder emits `σ_i = s_i·M` with a Chaum–Pedersen DLEQ proof binding it to its public share `Y_i` (from the aggregate VSS commitment, `VssCommitment::aggregate`); any `t` verified partials Lagrange-combine *in the exponent* to the **unique** `σ = x·M`, seed `= H(σ)`. **Unpredictable** below `t` (DDH on ristretto255 — no new hardness beyond the existing hybrid), **unbiasable** (`x·M` is unique — nothing to grind, no subset steers it), **verifiable** (`BeaconRound::verify_and_seed` checks every partial's DLEQ, so a client trusts algebra not a beacon operator), and **curve-coherent** (reuses the coordinate VRF's curve rather than adding the spec's nominal — non-PQ — threshold-BLS pairing base; a PQ beacon stays the spec's `[P]` direction).
- **Consumption (Layer B).** `BeaconSeed` (`fanos-primitives`) is threaded through *every* meeting-point derivation — `rendezvous_line` / `meeting_line` / `HiddenService::rendezvous_line` / `client_meeting_line` / `descriptor_key` / `client_descriptor_key` / `master_descriptor_key` / `primitives::vrf::rendezvous_line` — and into `RendezvousRoute`.
- **DKG integration.** `DkgNode::aggregate_commitment()` / `final_share()` expose exactly the material a beacon partial needs; every honest node folds the same `QUAL`, so all agree on the group commitment.

Pinned by `beacon::tests::{any_threshold_subset_yields_the_same_unbiasable_seed, a_forged_or_tampered_partial_is_rejected, fewer_than_threshold_partials_cannot_form_the_beacon, a_beacon_round_self_verifies_and_round_trips, a_dkg_group_produces_a_verifiable_beacon}`, `keygen …a_completed_dkg_exposes_consistent_beacon_material`, and end-to-end in `fanos-sim/tests/beacon_rendezvous.rs` (`a_beacon_derived_meeting_line_delivers_over_the_mixnet`, `a_future_epochs_line_is_unpredictable_without_that_epochs_beacon`, `a_sub_threshold_coalition_cannot_form_the_beacon`).

**E4∩E5 driver (#94) — built + sim-proven; deployment last-mile remains.** The live epoch clock is now a networked engine: `fanos-keygen::BeaconNode` (a sans-I/O engine, sibling to `DkgNode`) — anchors flood `BeaconPartial` frames (`0x18`) on `AdvanceEpoch`, verify each DLEQ against the group commitment, assemble + adopt the `BeaconRound` (flooded on `Beacon` `0x13`), and announce `Notification::BeaconReady { epoch, seed }`; monotone, subset-independent, forgery-rejecting. `fanos-node::EpochDriver` is the rotation core — on each beacon epoch it advances a ratchet parallel to the hosted `ThresholdRouter`'s and reports the router step count + the onion public to republish, **proven to publish byte-for-byte the key the router peels with** (`epoch_driver::tests::the_driver_publishes_exactly_the_key_the_router_peels_with`). End-to-end: `fanos-sim/tests/beacon_node_e2e.rs` shows the networked cell's seed equals the canonical DVRF output and drives a working anonymous rendezvous. **Remaining:** the async multi-role mix-relay node runtime that hosts a `BeaconNode` + a `ThresholdRouter` over real QUIC and runs the documented loop (`BeaconReady → EpochDriver.advance_to → router `AdvanceEpoch`×steps → `publish_mix_key``) — thin glue whose every component is tested; the multi-role QUIC hosting is deployment work (→ #94/#54). (The coordinate-assignment VRF shares the predictability issue but reshuffles node placement — membership A7/#66 — and will consume the same beacon.)

### E6 — Cover traffic is additive, not constant-rate *(MEDIUM)* — **RESOLVED on the Full/threshold path (#61)**

~~cover sent *on top of* real forwards, so send volume rises with real load …~~ **Done on `ThresholdRouter`.** `forward_send` queues a real forward into the constant-rate `outbox`; each send slot emits exactly one cell — a queued real forward (which **displaces** a cover cell) if any, else cover — so emitted volume is the fixed slot count, independent of real traffic. Pinned by `threshold_router::tests::a_queued_real_forward_displaces_a_cover_slot_at_a_constant_rate`. (The Lite `NyxNode` path remains additive; that engine is the lower-assurance profile.)

**Lower-severity anonymity items:** `fanos-nyx` `sheaf.rs`/`tessera.rs` "transparent" threshold onions carry Shamir shares in cleartext yet cite the §5.2 ZK-below-threshold property — superseded on the live path but still `pub` re-exported (integrator footgun; gate behind a sim feature or rename); the Lindblad anti-DDoS gate is implemented and tested only in `fanos-sim/tests/calypso_ddos.rs`, unintegrated into any shipping service, and `stabilize.rs:34-36` asserts a "quarantine per T-226" backstop that (per the corpus) has no theorem; the threshold layer's `ct_len` is cleartext (a peeling node learns its path position — a documented Sphinx-filler residual that `sealed.rs` avoids by AEAD-encrypting the length); and ONOMA global-name issuance is interface-only with `LocalRegistry::insert` silently overwriting (no first-come settlement).

**Verdict.** The **entire E-series anonymity floor is now resolved** — E1 (constant-rate cover), E2 (secret-keyed mix delays), E3 (SIV-salt descriptor nonce + per-boot onion-nonce freshening), E4 (forward-secure relay onion keys with a grace window), E5 (unpredictable distributed-beacon rendezvous), E6 (constant-rate cover displacement) — all implemented and verified above (#61). The marketing verbs ("verifiable mixing," "forward secrecy," "unpredictable epochs," "no volume fingerprint") now match the shipping Full engine. The only remaining anonymity work is the live-network **deployment transport** of the beacon and the single E4∩E5 epoch driver (→ #54). The lower-severity items below are documented-in-code residuals, none a fabrication.

## 9. Part F — DIAULOS stream reliability

The selective-repeat/SACK **delivery** core is correct and carefully sized. What is not sound is **resource-boundedness** under an adversarial or merely slow peer — the very thing the flow-control machinery exists to provide. (Handshake and AEAD nonce management are already verified sound — Part 3.)

**Verified sound (do not regress):** cumulative+selective ACK interaction is monotone and clamped (`acked = acked.max(cumulative).min(len)`); retransmission is genuinely selective (skips `sacked`, resends only the gap); the SACK bitmap exactly covers the window (bit 0 = cumulative gap, bits 1..63 = 63 out-of-order holds, `recv_window` clamped to `1..=64` — **no "segment lost outside the bitmap" bug**); duplicates are first-write-wins; out-of-order segments beyond the window are dropped (the sparse-high-seq attack is bounded); padding (`Frame::Padding`, ftype `0x00`) decodes distinctly from DATA and routes to a no-op, so cover cells can never be mis-delivered as data; and per-stream independence gives real multiplexing with no cross-stream head-of-line blocking.

### F1 — Receiver buffer unbounded under a stalled reader (the C3 bug, from the stream side) *(HIGH)*

Confirmed independently: `fanos-runtime/src/stream.rs:288-289` anchors admission on `next` (the contiguous frontier) while the buffered byte count is governed by `delivered` (what the app drained), so an in-order `seq == next` is accepted whenever `recv_window > 0` — **always**. A stalled local reader (a SOCKS client whose TCP socket is blocked) or a flooding peer drives unbounded `received` growth at line rate. Even a *fully compliant* sender leaks: its zero-window probe (`seq == acked == next`) is accepted as in-order every round, ~1 segment/RTT forever. **Fix:** anchor on the drain low-water mark — `seq < delivered + recv_window` — which also correctly drops the probe until `take()` frees credit, consistent with the existing `rwnd = recv_window − held` computation.

### F2 — No concurrent-stream cap; streams are never retired *(HIGH)*

`fanos-diaulos/src/conn.rs:170-182` — a DATA frame for an unknown `stream_id` unconditionally allocates a new `Stream`, and **no code path anywhere removes a stream from `self.streams`**, not even after `is_stream_done`. Two failure modes:

- *Adversarial:* an authenticated peer sends DATA with distinct ids `0,1,2,…` — one `Stream` (with its maps/vecs) per cell, plus an unbounded `accept_queue` if the app doesn't `accept()`.
- *Honest, arguably worse:* the SOCKS proxy opens one stream per client connection; over a long-lived `Connection`, completed streams accumulate forever, and `outbound()` emits **one ACK cell per stream every tick** for every dead stream — O(total-streams-ever) cells/tick.

The initiator-even/responder-odd parity is also not enforced on implicit open, so a peer can pollute the local id space and a later `open_stream()` can silently overwrite an injected stream. **Fix:** a live-stream cap that rejects/limits implicit opens; retire streams on `is_stream_done` (and stop ACKing retired streams); bound `accept_queue`; enforce parity on implicit opens.

### F3 — Sender never reclaims acknowledged segments *(HIGH)*

`fanos-runtime/src/stream.rs:103` — `StreamSender.segments: Vec<Vec<u8>>` is append-only; `on_ack` advances `acked` but never truncates, and `outbound()` indexes `segments.get(seq as usize)`. Acknowledged data is never freed, so **sender memory equals the total bytes ever sent**, not the in-flight window. A proxied large download buffers the entire file in RAM even though it is fully acked — the layer cannot stream anything larger than memory. **Fix:** reclaim below the cumulative ack with a `base_seq` offset + `VecDeque` (translate `seq → seq − base_seq`), dropping entries `< acked`.

### F4 — No RTO; sender `sacked` set grows from crafted ACKs *(MEDIUM)*

`outbound()` (`stream.rs:198-214`) re-emits the *entire* unacked in-window set every call, with no per-segment timer, dup-ack threshold, or backoff — the driver's tick is the de-facto RTO, so a fast tick spuriously retransmits and (under the constant-rate shaper) crowds out cover budget. Correctness holds (fresh nonce per emit). Separately (`stream.rs:222-224,232`), `on_ack` inserts `cumulative + i` for each SACK bit keyed off the *peer-supplied* `cumulative` and prunes only below `acked`, so an authenticated peer sending ACKs with `cumulative` near `u32::MAX` accumulates surviving entries indefinitely — unbounded `BTreeSet` growth. **Fix:** RTT-estimated RTO + fast-retransmit; ignore SACK bits whose absolute sequence is `≥ segments.len()`.

**Lower-severity:** there is no RST/abort frame — a stream can only close via FIN, so a peer that opens and never FINs pins it forever (compounding F2); `fin_seq` (`stream.rs:291-293`) accepts a FIN on any in-window segment and overwrites, letting a peer truncate the stream so `deliver()` and `take()` disagree; and `u32` sequence / stream-id wraparound is unguarded with a couple of non-saturating adds (`stream.rs:202,310`) that are unreachable given memory bounds but unasserted. The AEAD nonce counter's `wrapping_add` (`conn.rs:115-117`) should likewise become a hard connection-kill at the limit.

**Test-coverage gaps behind these:** there is no stalled-reader test, no zero-window-probe test, no stream-retirement/cap test, no sender-reclaim test, and — critically — no *valid-but-malicious-peer* test (the existing `robustness.rs` feeds only random blobs that fail AEAD and are dropped, so F1/F2/F4 all go unexercised). These are the tests that would have caught the HIGH findings.

**Verdict.** The delivery logic would ship; the flow-control and lifecycle accounting (F1–F3) need fixing before this layer can safely face a real network or a malicious counterparty.

---

## 10. Part G — Documentation integrity

- **G1 (MEDIUM).** `rust/README.md` — the front door of the reference implementation — claims "119 tests" and documents only 8 of 27 crates (field/geometry/code/diakrisis/wire/crypto/core/cli), omitting the entire privacy, DIAULOS, node, and proxy stack. It reflects an early snapshot; the workspace is now ~700 tests across 27 crates.
- **G2 (LOW).** `docs/design-platform.md` presents `#[derive(Wire)]` ("emits codec + KATs from one type definition") as part of the architecture; it is unbuilt. Either build it (it is the right fix for A1) or mark it as a proposal.
- The design corpus (`design.md`, `design-platform.md`, `roadmap.md`) is otherwise unusually thorough and honest, and already records several of the gaps above as known — this audit sharpens them with file/line anchors and severity, and adds the DKG, flow-control, and wire-bifurcation findings that were not previously called out.

---

## 11. Part H — Prioritized remediation roadmap

**Tier 0 — correctness/security, do first**
1. ~~**Authenticate the DKG (B1) and fix the QUAL/share atomicity (B2, B3).** Bind `from` to the claimed index or sign every DKG frame; gate `refs.push` on the Feldman result; verify justifications against the qualified commitment. Add the adversary tests that should have caught these.~~ **DONE.** `from` is authenticated against the claimed dealer/complainer (B1); the Feldman-gated push closes the `x·G ≠ Y` atomicity gap (B2); justifications verify against the qualified commitment (B3); all three are pinned by dedicated adversary tests. See the B1–B3 §resolutions.
2. ~~**Make DLEQ nonces synthetic (B4)** and **fix the descriptor nonce reuse (E3)** — both are seed/nonce-reuse correctness bugs that leak secrets or keystream. Deterministic-from-`(k, transcript)` for DLEQ; salt/counter in the descriptor nonce.~~ **DONE.** B4's DLEQ nonce is now synthetic (RFC-6979-style, over the issuer secret + transcript); E3's descriptor nonce now carries a SIV-style per-publish salt bound to the plaintext. See the B4/E3 §resolutions.
3. **Close the reachable OOM/hang cluster:** enforce receiver flow control (C3/F1, anchor admission on `delivered`); cap and retire streams (F2); reclaim acked sender segments (F3); add request timeouts + waiter eviction (C1).
4. **Sanitize DIAKRISIS telemetry inputs (D1, D2, D3).** Reject non-finite/non-PSD coherence and rate readings at the boundary and cap the reroute-depth loop — otherwise a single gossiped `NaN`/`Inf` hangs a peer's healing controller or evades the Byzantine detector.

**Tier 1 — robustness, hygiene, anonymity floor**
4. **Bound and back-pressure everything (A4, A4b, C2):** cap + TTL every peer-keyed map (rendezvous routes, node sessions, waiter maps); bound every driver/session channel; per-peer send concurrency.
5. ~~**Restore the Full-profile anonymity floor (E1, E2):** port constant-rate cover into `ThresholdRouter`, key its mix delays off a secret.~~ **DONE (#61).** E1/E2/E3/E4/E5/E6 all resolved on the Full/threshold path (constant-rate cover, secret-keyed mix delays, SIV-salted descriptor nonce, forward-secure onion ratchet, distributed rendezvous beacon); see the E-section resolutions. Remaining anonymity work: the beacon's live-network deployment transport (→ #54).
6. **Adopt `zeroize`/`subtle` (A6);** drop `Copy`/`Debug` on key types.
7. ~~**Bind the KEM transcript (B5); seed DKG per-run (B6); constant-time Shamir (B7);**~~ **B6/B7 DONE, B5 PARTIAL (#63).** B6: DKG now folds a fresh per-instance `session_nonce` into the polynomial seed. B7: `clmul` is now branchless (mask-based, no data-dependent branches). B5: the SHAKE256 combiner now binds the full transcript (ephemeral pk + ct + recipient key); the contributory-behaviour (all-zero/low-order X25519) check remains open — see the B5 §resolution. ~~rotate relay KEM keys per epoch or scope the FS claim (E4).~~ **E4 DONE (#61)** — forward-secure per-epoch onion ratchet (`OnionKeyRatchet`) with a bounded grace window, wired into `ThresholdRouter` (peels via `onion.secrets()`, advances on `AdvanceEpoch`) and epoch-scoped mix-key discovery; see the E4 §resolution.

**Tier 2 — fundamentality / architecture**
7. ~~**Re-canonicalize the wire (A1).**~~ **DONE (#82).** `#[derive(Wire)]` (exists) is the substrate; every migratable struct serializer is on it (calypso `Descriptor`/`SealedDescriptor` + balance `MasterDescriptor`, telemetry history, rendezvous `Request`, quic creds); `fanos-wire` is the single frame-code authority (`FrameType` + `SessionFrameType`, `App=0x70` registered); the duplicate integer/`Cursor` decoders (diaulos frame, calypso-balance) are eliminated; the `Tessera` layout was already regenerated (encrypted holonomy, 8192). The rest is justified must-stay (transcripts / layered crypto / group-validated foreign types). All four A1 consequences resolved — see the A1 §Progress note.
8. ~~**Introduce the `Epoch` newtype and fix the telemetry frame epoch (A3).**~~ **DONE (#90):** `fanos_primitives::Epoch(u64)` threaded through every protocol-epoch seam (calypso u32/u64 split closed); telemetry frame epoch fed the agreed beacon `Epoch` via `observe_liveness`. All KATs byte-identical; clippy/fmt clean. See the A3 §resolution.
9. ~~**Resolve the placeholder/real split (A7):** wire `fanos-vrf` into membership, or delete the placeholder and document the gap.~~ **DONE (#66, Level A):** the real VRF is the coordinate authority — beacon-folded, identity-committed, live + HELLO-proven (commits `b90e35d` + `6b6c2f2`); Level B (reshuffle + hierarchy unification) tracked (#95). See the A7 §resolution + `docs/design-coordinates.md`.
10. **Make `Decouple` real or remove it (C6); give quarantine an exit + multi-witness gate (C5); make telemetry DP-safe or drop the anonymization claim (C7).**

**Tier 3 — capability completion**
11. **Wire the anonymous rendezvous path into the node binary (A5)**; ~~give the service side a full duplex stream to match the client (currently one-shot RPC).~~ **Service duplex DONE (#66):** `serve` is a full-duplex per-client stream (`serve_rpc` keeps request/response a one-liner); a unified `SessionStream` driver serves both directions. See the service-duplex row.
12. ~~**Decide and document the large-`q` scaling story (A2).**~~ **DONE (#66):** recorded in `docs/design-coordinates.md` §5 — `q = 2` + hierarchy is the scaling model; large-`q` `Plane` is spec-completeness, not a scaling lever.
13. **Refresh the README and reconcile the design docs with the shipping surface (G1, G2).**

---

## 12. Appendix — verification baseline

- `cargo test --workspace`: pass (exit 0). `cargo clippy --workspace --all-targets -- -D warnings`: pass (exit 0). `cargo fmt --all --check`: **fails** on the uncommitted WIP (`fanos-rendezvous/src/lib.rs:214`).
- Dependency graph: acyclic; `fanos-field` is a true leaf; math/privacy core cross-builds to `wasm32-unknown-unknown` `no_std`.
- CI (`.github/workflows/ci.yml`): fmt + clippy `-D warnings` + tests + cli/sim demos + `no_std`/wasm cross-builds + `cargo miri test` on field/crypto/diakrisis.
- Per-crate `#[test]` inventory highlights the coverage gaps behind several findings: `fanos-session` **2**, `fanos-incentives` **6**, `fanos-proxy`/`fanos-cli` **3–6**, against `fanos-sim` **90** and `fanos-diakrisis` **45**. (`fanos-keygen` — cited above at the audit's original 0 — now carries **5** adversary/regression tests, including the ones pinning the B1/B2/B3/B6 fixes.)

---

## 2026-07 gap-map addendum (drive to 100%)

A follow-up spec-vs-implementation audit (driving toward #97) re-swept the spec against the current tree. It confirmed the Tier-0/1 resolutions above and found the workspace has grown **ahead** of the spec in several places (NYX's threshold-sheaf construction, the Tessera wire format, the pairing-free ciphersuite choices), reconciled into `spec/protocol.md` this session. The residual open P0/P1 frontier — in progress now, not yet done — is:

- **§6.4 live Byzantine self-healing.** Closure cross-attestation (mediator witnesses) and the healing actions are implemented as pure functions/formulas but not fully wired into the live engine's diagnose→heal loop (cf. C5/C6 above). *(#98, in progress.)*
- **§12.3 threshold-hosted CALYPSO.** The Shamir split/reconstruct primitive for service-key hosting exists (`fanos-calypso/src/hosting.rs`) but its only caller is its own unit test; the live `RendezvousService` (`fanos-rendezvous/src/transport.rs`) is a single host, not a `t`-of-`q+1` threshold service — the "no single host to raid" headline is not yet realized end-to-end. *(#99, pending.)*
- **§7.4 wire version/capability negotiation.** No `PROTOCOL_VERSION`/version byte and no capability-intersection handshake exist yet; `HELLO` does not carry them. *(#100, pending.)*
- **§7.9 wire-KAT conformance harness.** `conformance/vectors/wire.json` exists but no test loads or verifies it — the interop contract is unenforced and can silently drift. *(#101, pending.)*
- **L3.2 live per-epoch coordinate reshuffle.** The VRF coordinate authority is live (A7 above), but the live-network *reshuffle operation* driven by the real DVRF seed each epoch is not yet wired. *(#95/#102, pending.)*
- **L3.3 Sybil admission gate.** No pluggable `AdmissionPolicy` (PoW / stake-bond / web-of-trust) is wired into JOIN yet — only the structural centrality cap is enforced. *(#103, pending.)*
- **L4.1 real erasure coding.** The storage engine still replicates a full copy to every cell member (redundancy ≈ N) rather than erasure-coding across the `q+1` lines the spec's LRC claims; a projective erasure codec is under active development. *(#104, in progress.)*
- **§5.4 holonomy verification.** The path-authenticator `Hol` is computed and carried encrypted end-to-end, but no live code path recomputes and compares it — `WireError::HolonomyFail` is defined but never produced, so the path-integrity property is not yet enforced at runtime.
- **PROTEUS enablement.** The flagship `polymorph` codec is genuinely wired into the live QUIC driver (`fanos-quic::spawn_shaped`), but no shipping node/CLI ever calls it — there is no config surface, auto-detect/fallback loop, or capability advertisement to turn PROTEUS on.

None of these is a regression — each is a tracked frontier item, several already in progress. This addendum records where the "drive to 100%" effort stands; it does not supersede the Tier-0/1 resolutions above.
