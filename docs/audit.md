# FANOS Rust reference implementation — architectural audit

**Date:** 2026-07-18
**Scope:** the entire `rust/` workspace — 27 crates, ~31 k LoC.
**Baseline health at audit time:** `cargo test --workspace` green; `cargo clippy --workspace --all-targets -D warnings` green; CI runs fmt + clippy + tests + no_std/wasm cross-builds + `cargo miri`. The working tree is mid-change (the DIAULOS anonymous-rendezvous WIP) and currently **fails `cargo fmt --check`** at `fanos-rendezvous/src/lib.rs:214`.
**Method:** whole-workspace read, dependency-graph and determinism analysis, and five parallel adversarial per-cluster reviews. Every CRITICAL/HIGH claim in Parts A–C was re-verified by hand against the source before inclusion.

> **Resolution status — refreshed 2026-07-24: every finding in this document is RESOLVED.** Each was re-verified against the current source in a full per-finding closure re-audit; the last open items (D2, D4, A4/A4b, A6, C4, G1) were closed on 2026-07-24, and the rest were confirmed already fixed. The workspace has since grown to 41 crates and passes `cargo clippy --workspace --all-targets -D warnings` and `cargo test --workspace` green (the mid-change `cargo fmt` failure noted above is long gone). Resolutions are annotated inline (`— **RESOLVED**`) and summarised in the §2 table. This document is deliberately **retained** as the project's internal defect-audit record and external-audit deliverable (`crypto-audit-readiness.md` §6.5), not deleted.

> **Consolidation status — this file is now the single FANOS audit record (consolidated 2026-07-24).** It gathers **four chronological audit passes** into one document (the separate `docs/audit-2026-07-2*.md` files were merged in and removed). Read it as a timeline — each later pass independently re-verified and **supersedes** the earlier one:
>
> | Pass | Date | Scope | Status of its own findings |
> |---|---|---|---|
> | **Audit I** — this document, above | 2026-07-18 | the original whole-workspace architectural audit | **fully resolved** — every finding closed and re-verified (the `— RESOLVED` tags + §2 table) |
> | **Audit II** — below | 2026-07-22 | first adversarial review of the crown-jewel subsystems (OBOLOS/DROMOS/THESAUROS/ANGELOS/live TAXIS): 9 CRITICAL + ~18 HIGH | superseded by III–IV + subsequent work |
> | **Audit III** — below | 2026-07-23 | re-audit of II: 13 fixes confirmed, plus new *unauthenticated/unbounded recovery-wiring* findings (§3.1–§3.9) | superseded by IV + subsequent work |
> | **Audit IV** — below | 2026-07-23 (deep) | re-verified III at `file:line`; reframed the frontier as *"no driver"* | the most recent frontier snapshot |
>
> **Current status of Audits II–IV (2026-07-24), checked against the current tree.** Each pass closed most of the prior pass's frontier, and substantial subsequent work has closed most of what Audit IV named:
> - **Shipped-binary chain** (Audit IV's "no driver"): **CLOSED** — `fanos taxis-deal` + `fanos validator` provision and run the TAXIS blockchain, with genesis token allocation and Tendermint-style round-timeout backoff (the §5.B `dromos_quic` livelock).
> - **Anonymous hidden-service reachability** (Audit III §5 / IV): **CLOSED** — `fanos host` serves and `fanos proxy --profile anonymous` dials a symmetric-NOSTOS hidden service over real QUIC, neither coordinate revealed; the S1-M2 epoch-follow break is closed.
> - **Mass-loss recovery** (R-C1 cliff, Audit II/III §4): **CLOSED** — partition-safe below-threshold re-genesis (RGC + `BeaconNode::rebootstrap` + generation fencing) + an auto-trigger (recovery-decision ladder + stall detector) replaces the permanent freeze; durable state-sync + secret-leader election are built and proven over real QUIC.
> - **The Audit III §3 DoS/overflow cluster:** §3.2 (OBOLOS ternary-randomness reject), §3.3 (storage `decode_response` bound), §3.5 (audit-cadence), §3.4 (market floors + prune), §3.7 (TREASURY access-list), §3.8/§3.9 (CI green): **CLOSED** per Audit IV's re-verification + subsequent commits.
> - **Γ-viability gate** (Audit II CRITICAL-ARCH): **CLOSED** — built as the `fanos-holarch` crate (`gamma`/`verdict`/`panel`/`Sigma` + the Ω4 ablations); the E∧L verdict is now a CI number.
> - **Beacon-reshare key-secrecy** (Audit IV §2.1, CRITICAL, **RESOLVED 2026-07-24**): the last live CRITICAL across all four audits is now closed. The `BeaconReshareTrigger` is **authenticated** — it carries a `HybridSignature` by the beacon's recovery `authority`, and `on_reshare_trigger` refuses any unsigned/foreign-signed/tampered trigger before any anchor deals a sub-share; `node.rs::actuate_recovery` escalates a proactive reshare to that authority (as re-genesis already is) rather than a node self-issuing one. The 2-anchor-coalition master-key exfiltration is closed, while legitimate threshold-lowering recovery still works (the authority signs it). The in-flux `recovery.rs` was not touched. Full detail at Audit IV §2.1 below. **With this, no open CRITICAL/HIGH security item remains across the four audits** — the residual is the coherence/MEDIUM-LOW tail noted next.
> - **Remaining:** the coherence/meta-holon tail (E→L / L→O / Ω2 / Ω9 reconciliation) and the per-subsystem MEDIUM/LOW items are preserved in the dated sections below and tracked in ongoing work. Where an archived section says "unbuilt/open," verify against the current tree — it has advanced hundreds of commits since each snapshot.
>
> Inter-audit references in the archived sections (e.g. "`docs/audit-2026-07-23.md`", "pass 1") now point to the correspondingly-dated section **within this file**.

---

## 1. Executive summary

FANOS is, at its foundation, an unusually principled codebase. The sans-I/O discipline is **real and holds** — the engine is a pure state machine and only the drivers touch entropy, wall-clock, or sockets, exactly as `architecture.md` claims. The projective-geometry substrate is genuinely generic over `q`. The post-quantum primitives are real (audited `ed25519-dalek` / `ml-dsa` / `x25519-dalek` / `ml-kem` / `vrf-r255` / `curve25519-dalek`), domain separation is correct and consistently applied, and the DIAULOS handshake is a textbook-quality hybrid KDF with transcript binding and directional key separation. The dependency graph is a clean DAG with leaf-shaped math crates. This is not a prototype pretending to be a protocol; it is a protocol implementation with a real spine.

The deficiencies are therefore **not in the primitives but in the composition and at the edges**, and they cluster into a recognizable shape:

1. ~~**The canonical layer is no longer canonical.** `fanos-wire` is a well-built, KAT-covered, "one valid encoding, reject non-canonical" codec — but only 5 of 27 crates use it. Every subsystem that grew after the spec froze (DIAULOS, threshold onions, rendezvous, ONOMA, CALYPSO-Balance, VRF proofs, PROTEUS) hand-rolls its own byte layout. The single-source-of-truth wire contract has bifurcated.~~ **RESOLVED (#82).** `#[derive(Wire)]` now exists and `fanos-wire` is the codec substrate for 12 crates (including DIAULOS, rendezvous, and CALYPSO); the remaining hand-written byte code is signing transcripts, layered onion/AEAD crypto, and group-validated foreign-crypto wrappers — not a bypass. See A1.
2. ~~**The one place FANOS wrote its own cryptographic protocol instead of calling a vetted crate — the `fanos-keygen` DKG — is Byzantine-broken and has zero tests.** Unauthenticated complaint frames let a single malicious node evict every honest dealer.~~ **RESOLVED.** Commit/complaint frames are now authenticated against the claimed dealer/complainer, the QUAL/share atomicity gap is closed (a dealer's commitment reaches the joint key only if its share actually folded), and justification is checked against the qualified commitment, not the frame's own; `fanos-keygen` now carries dedicated adversary tests for all three. See B1–B3.
3. ~~**The "living, self-observing, provably-anonymous" headline capabilities are stranded below the shipping surface.** Self-healing's `Decouple` is a no-op, the real verifiable-coordinate VRF is dead code, the anonymous rendezvous path is not wired into the node binary, and the general-`q` scaling story cannot run above the geometry layer.~~ **ALL RESOLVED.** `Decouple` now mutates a shed factor that lowers the effective correlation feeding `Φ` (C6); the VRF is the live, HELLO-proven coordinate authority (#66, A7); the anonymous rendezvous path is wired into the binary — `fanos host` serves and `fanos proxy --profile anonymous` dials a hidden service without revealing either coordinate (A5); and `q=2`+hierarchy is the recorded scaling model (#66, A2).
4. ~~**A systemic robustness gap: unbounded state and absent back-pressure.** Waiter maps, session maps, rendezvous route tables, and every driver channel are unbounded; receiver flow control is advertised but not enforced. A single connected peer can OOM a node.~~ **RESOLVED.** Every peer-keyed map is capped+TTL'd (`BoundedMap`, `MAX_SESSIONS`+idle-GC, `MAX_ROUTES`, `MAX_PENDING_GETS`); the QUIC ingress and the datagram-transport channels are bounded with back-pressure/drop-on-full; receiver admission is enforced on the drained low-water mark (C1–C4, A4/A4b, F1).
5. ~~**Best-in-class hygiene the mandate demands is missing workspace-wide:** no `zeroize`, no `subtle`; several secret types even derive `Copy`/`Debug`.~~ **RESOLVED.** `zeroize`/`subtle` are direct workspace dependencies; no secret type derives `Copy`, secret material zeroizes on drop, and `VrfSecret`/`Ratchet` carry redacted `Debug` (A6).

None of these is fatal, and none contradicts the architecture — they are the gap between an excellent skeleton and the "flawless, fully-fundamental" bar the project sets for itself. The remainder of this document enumerates them with file/line anchors and a prioritized remediation path (§11).

**Overall grade (at audit time, 2026-07-18):** foundations A; composition and productionization C+. The distance between the two was the subject of this audit. **As of the 2026-07-24 refresh that distance is closed:** every finding is resolved and re-verified against the shipping source, so composition/productionization now meets the same bar as the foundations.

---

## 2. Severity summary

| # | Finding | Severity | Where |
|---|---|---|---|
| B1 | ~~DKG complaint/commit/justify frames unauthenticated — one node evicts any honest dealer~~ **RESOLVED** — `from` authenticated against the claimed dealer/complainer | **CRITICAL** | `fanos-keygen/src/lib.rs:281-328` |
| B2 | ~~DKG `ingest_share` result discarded — joint key can include a rejected dealer (`x·G ≠ Y`)~~ **RESOLVED** — commitment pushed to the joint key only when the Feldman check passes | **CRITICAL** | `fanos-keygen/src/lib.rs:415-429` |
| B3 | ~~DKG justification checked against the frame's own commitment, not the qualified one~~ **RESOLVED** — verified against `self.commitments[d]`, the frame's own commitment ignored | **CRITICAL** | `fanos-keygen/src/lib.rs:337-362` |
| B4 | ~~DLEQ nonce drawn from a caller RNG — deterministic seed ⇒ issuer-key recovery~~ **RESOLVED** — synthetic RFC-6979-style nonce `s = H(k‖K‖B‖Z)` | **HIGH** | `fanos-incentives/src/lib.rs:89` |
| A6 | ~~No `zeroize`/`subtle` anywhere; `VrfSecret` derives `Copy`+`Debug`~~ **RESOLVED** — `zeroize`/`subtle` are direct workspace deps; no secret type derives `Copy`; `VrfSecret`/`Ratchet` carry redacted `Debug`; secret material zeroizes on drop (incl. OBOLOS wallet keys, NYX `Ratchet`, VSS share) | **HIGH** | workspace-wide |
| C1 | ~~`Client::get`/`put` have no timeout; waiter maps leak unboundedly; no put-ack timeout~~ **RESOLVED** — `REQUEST_TIMEOUT`=10 s wraps get/put + `evict_stale` waiter sweep; overlay `pending` capped (`MAX_PENDING_GETS`) + TTL-swept; node `RESOLVE_TIMEOUT`=5 s | **HIGH** | `fanos-quic/src/driver.rs`; `fanos-runtime/.../overlay.rs` |
| C2 | ~~Unbounded driver channels + single-task transport ⇒ no back-pressure, remote OOM DoS~~ **RESOLVED** — QUIC ingress bounded (`INPUT_CAP`, awaits on full ⇒ QUIC flow control) + per-peer send workers + connection caps; datagram-transport channels bounded (A4b) | **HIGH** | `fanos-quic/src/driver.rs` |
| C3 | ~~Receiver `rwnd` advisory, not enforced on the in-order path ⇒ receiver OOM~~ **RESOLVED** — admission anchored on the drained low-water mark (`seq < delivered + recv_window`) | **HIGH** | `fanos-stream/src/lib.rs` |
| A1 | ~~Wire-codec bifurcation — canonical `fanos-wire` bypassed by ~10 subsystems~~ **RESOLVED (#82)** — `#[derive(Wire)]` built; `fanos-wire` is now the codec substrate for 12 crates (calypso, telemetry, rendezvous, quic, diaulos, node, keygen, aphantos, runtime, sim, primitives + itself) | **HIGH (arch)** | workspace-wide |
| A4 | ~~Unbounded rendezvous route table + node session map (no eviction)~~ **RESOLVED** — route table is a `BoundedMap` (`MAX_ROUTES`); session maps are `MAX_SESSIONS`+LRU-evict+idle-GC/abort; every peer-keyed map is capped+TTL'd | **HIGH** | `fanos-rendezvous/src/transport.rs`; `fanos-node/src/{diaulos,rendezvous_relay}.rs` |
| A5 | ~~Anonymous rendezvous path not wired into the node binary (sim-only)~~ **RESOLVED** — `fanos-node` depends on `fanos-rendezvous`; `fanos host` serves and `fanos proxy --profile anonymous` dials a hidden service, neither coordinate revealed | **HIGH (arch)** | `fanos-node/src/{bin/fanos,rendezvous_host,rendezvous}.rs` |
| A2 | ~~General-`q` stranded below a `q=2`-only DIAKRISIS/runtime/node ceiling~~ **RESOLVED (#66)** — decision recorded, `docs/design-coordinates.md` §5 | **MEDIUM (arch)** | `fanos-diakrisis/*` |
| A3 | ~~"epoch" is three different quantities; frame epoch not cross-node comparable; no `Epoch` type~~ **RESOLVED (#90)** — one `Epoch(u64)` newtype threaded through every protocol-epoch seam | **MEDIUM** | see A3 |
| A7 | ~~Real VRF is dead code; live membership uses a self-declared-forgeable placeholder~~ **RESOLVED (#66, Level A)** — VRF is the coordinate authority, live + HELLO-proven; Level B tracked (#95) | **MEDIUM** | `fanos-core/src/membership.rs:32` |
| B5 | ~~Hybrid KEM combiner omits transcript (ephemeral pk + ct) — X-Wing binding not met~~ **RESOLVED (#63)** — full-transcript SHAKE256 combiner binds ephemeral pk + ct + recipient key, **and** the contributory-behaviour check (`x_ss.was_contributory()`, fail-closed) is present in both `encapsulate` and `decapsulate` — the prior residual is closed | **MEDIUM** | `fanos-pqcrypto/src/kem.rs` |
| B6 | ~~DKG polynomial randomness seeded solely by the long-term secret (reproducible shares)~~ **RESOLVED** — a fresh per-instance `session_nonce` is folded into the polynomial seed | **MEDIUM** | `fanos-keygen/src/lib.rs:87,181-187` |
| B7 | ~~Non-constant-time GF(256) multiply on secret Shamir shares~~ **RESOLVED (#63)** — branchless mask-based `clmul`, no data-dependent branches | **MEDIUM** | `fanos-field/src/gf2m.rs:60-85` |
| B8 | ~~Overstated RFC conformance (9497/9578/9381) and bearer credits with no redemption binding~~ **RESOLVED (#63)** — RFCs downgraded to "reference, not conformance"; redemption is context-bound and constant-time | **MEDIUM** | `fanos-incentives`, `fanos-vrf` |
| C4 | ~~Content-digest correlation not request-scoped — stale/replayed `Value` resolves a newer get~~ **RESOLVED** — per-request nonce carried end-to-end; a `Value` resolves only a matching in-flight get whose nonce it echoes (put-side by version-LWW) | **MEDIUM** | `fanos-runtime/.../overlay.rs:2149-2231` |
| C5 | ~~Quarantine is permanent (no un-quarantine) and driven by local-only diagnosis~~ **RESOLVED** — `QUARANTINE_TTL`=60 s with removal on expiry + parental `Escalate`; multi-witness gates (corroboration quorum, mediator attestation, persistent endpoint consensus) | **MEDIUM** | `fanos-runtime/.../overlay.rs` |
| C6 | ~~`Decouple` healing action is a no-op beyond a notification — the loop cannot lower Φ~~ **RESOLVED** — `Decouple` raises a shed factor ⇒ `effective_correlation = healthy·(1−decoupling)` ⇒ lowers `phi_equicorrelated`; deduped, decays on Bind/Hold | **MEDIUM** | `fanos-runtime/.../overlay.rs` |
| C7 | ~~Telemetry "self-observation is anonymization" is false — exact syndrome deanonymizes~~ **RESOLVED** — false claim corrected ("data minimization, not anonymization; do not export a raw frame") + real ε-DP export `CoherenceFrame::privatize`; no raw frame auto-exported | **MEDIUM** | `fanos-telemetry/src/{frame,dp}.rs` |
| A4b | ~~`fanos-session` uses unbounded channels between the async stream and the datagram transport~~ **RESOLVED** — `ChannelTransport` channels are bounded (`CAP`=1024, `try_send` drop-on-full; DIAULOS retransmits) across the session + all node dial/serve loops | **MEDIUM** | `fanos-session/src/lib.rs` |
| G1 | ~~`rust/README.md` stale — "119 tests", documents 8 of 27 crates~~ **RESOLVED** — README refreshed to all 41 crates with accurate counts, the phantom `fanos-crypto` row replaced by `fanos-primitives`, and the `Node::open` example updated to the current VRF/beacon API | **MEDIUM (docs)** | `rust/README.md` |
| G2 | ~~`#[derive(Wire)]` "codec+KATs from one definition" (design-platform.md) is unbuilt~~ **RESOLVED** — `fanos-wire-derive` is a built proc-macro used at 25 sites | **LOW (docs)** | `fanos-wire-derive` |
| — | ~~Service side is one-shot RPC while the client gets a full duplex stream~~ **RESOLVED (#66)** — `serve` is a full-duplex per-client stream; `serve_rpc` keeps request/response ergonomic | **MEDIUM** | `fanos-node/src/diaulos.rs` |
| — | ~~AEAD nonce counter uses `wrapping_add`~~ **RESOLVED** — `next_nonce` uses `checked_add` and returns `None` at 2⁶⁴, so the connection hard-kills rather than reuse a nonce (pinned by `conn::tests::the_connection_hard_kills_at_nonce_exhaustion_rather_than_reusing_a_nonce`) | ~~LOW~~ | `fanos-diaulos/src/conn.rs:189` |
| E1 | ~~Full/threshold profile emits no cover traffic — GPA resistance below the Lite profile's~~ **RESOLVED (#61)** — constant-size cover cells, exponential-gap armed | **HIGH** | `fanos-aphantos/src/threshold_router.rs` |
| E2 | ~~Threshold mix delays seeded from the node's public coordinate — GPA can predict/relink~~ **RESOLVED (#61)** — delays now seeded from a secret KEM-derived subkey | **HIGH** | `fanos-aphantos/src/threshold_router.rs:122-136` |
| E3 | ~~Descriptor deterministic AEAD nonce — keystream+MAC reuse on mid-epoch republish~~ **RESOLVED** — SIV-style per-publish salt bound to the plaintext | **MEDIUM** | `fanos-calypso/src/descriptor.rs:180-192` |
| E4 | ~~Forward secrecy is sender-side only; relays use non-rotated long-term keys~~ **RESOLVED on the Full/threshold path (#61)** — forward-secure per-epoch onion ratchet | **MEDIUM** | `fanos-pqcrypto/src/kem.rs:88-105` |
| E5 | ~~Rendezvous "VRF beacon" is a predictable hash — meeting lines computable far ahead~~ **RESOLVED (#61)** — pairing-free distributed VRF beacon folded into the derivation | **MEDIUM** | `fanos-calypso/src/rendezvous.rs` |
| E6 | ~~Cover traffic additive, not constant-rate — real load still shows a volume fingerprint~~ **RESOLVED on the Full/threshold path (#61)** — real forwards displace cover at a constant slot rate | **MEDIUM** | `fanos-aphantos/src/node.rs:164-197` |
| F2 | ~~No concurrent-stream cap; streams never retired (honest proxy use grows unbounded too)~~ **RESOLVED** — `MAX_CONCURRENT_STREAMS`=256 caps implicit opens; streams retire on `is_stream_done` (and stop being ACKed); accept_queue bounded; parity enforced; `Reset`/abort frame added | **HIGH** | `fanos-diaulos/src/conn.rs` |
| F3 | ~~Sender never reclaims acked segments — cannot stream a transfer larger than RAM~~ **RESOLVED** — `segments` is a `VecDeque` with a `base` offset, reclaimed below the cumulative ack (timing maps pruned in lock-step) | **HIGH** | `fanos-stream/src/lib.rs` |
| F4 | ~~No RTO (re-emits whole window/tick); sender `sacked` set grows from crafted ACKs~~ **RESOLVED** — RFC-6298 RTT-estimated RTO + 3-dup-ack fast retransmit; SACK bits beyond the sealed segment count are ignored | **MEDIUM** | `fanos-stream/src/lib.rs` |
| D1 | ~~`max_reroute_depth` infinite-loops on a non-finite Φ (live-confirmed DoS hang)~~ **RESOLVED** — a non-finite / `Φ<1` guard returns 0 early, plus a `MAX_REROUTE_DEPTH`=64 iteration cap | **HIGH** | `fanos-diakrisis/src/healing.rs` |
| D2 | ~~`from_correlation` accepts NaN/Inf/non-PSD ⇒ misdiagnosis + reachability root of D1~~ **RESOLVED** — rejects non-finite, `|c_ij|>1`, and non-PSD (least eigenvalue ≥ −ε·n via the crate eigensolver) | **HIGH** | `fanos-diakrisis/src/coherence.rs` |
| D3 | ~~`violated_classes` treats non-finite rates as consistent ⇒ Byzantine detector evadable~~ **RESOLVED** — any non-finite rate in a class is treated as a violation | **MEDIUM-HIGH** | `fanos-diakrisis/src/polar.rs` |

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

### A1 — The canonical wire codec is bypassed by most of the protocol *(HIGH, architectural)* — **RESOLVED (#82)**

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

### A2 — General-`q` capability is stranded below a `q=2` ceiling *(MEDIUM, architectural)* — **RESOLVED (#66)**

The addressing substrate is generic over `q`, but **DIAKRISIS is hardcoded to `N = 7`** in every module (`blindness.rs`, `polar.rs`, `partition.rs`, `coherence.rs`, `healing.rs`, `regeneration.rs`: `pub const N: usize = 7`, fixed `[[f64; 7]; 7]` kernels, `1.0/7.0` constants). This is *theoretically correct* — the 3-bit Hamming(7,4) syndrome is intrinsically a Fano-plane object — but its architectural consequence is under-acknowledged: the entire live stack above geometry (self-diagnosis, healing, the runtime, the node binary, which fixes `F = F2`) is **`q=2`-only**. The `Plane::<F7/F13/F31>` generality is exercised only in geometry unit tests; nothing above geometry can run a large-`q` cell.

So the headline "scale via large-`q`, O(1) rendezvous over `q²+q+1` nodes" is real as algebra but **unreachable as a running system** — scaling is available only through the `q=2` self-similar hierarchy. This needs an explicit decision, recorded in the design:

- If large-`q` cells are a genuine deployment target, DIAKRISIS and the runtime need a general-`q` self-observation story (how a 993-node cell is diagnosed by 7-element structures), or
- If `q=2` + hierarchy is *the* model, document the large-`q` `Plane` as spec-completeness — not a scaling lever — so the capability is not mistaken for a shipping one.

**Resolved (#66).** Decision recorded in `docs/design-coordinates.md` §5: `q = 2` + a recursion of cells is *the* deployment scaling model (spec §L1 Hierarchy, verified V4 — internet scale is `k` levels of Fano cells, `O(log n)` state/depth); the large-`q` `Plane` is retained as **spec-completeness** (the theorems are general-`q`, and it keeps the algebra testable at `q ∈ {7,13,31}`), **not** a scaling lever — no large-`q` cell runs above geometry; and DIAKRISIS `N = 7` is **base-cell proprioception** (the 3-bit Hamming(7,4) syndrome is intrinsically a Fano-plane object, spec Part VI), diagnosing upward by escalation, not a ceiling to be lifted.

### A3 — "epoch" is three different quantities with no unifying type *(MEDIUM)* — **RESOLVED (#90)**

Epoch is a raw integer with divergent widths and, worse, divergent *semantics*:

- **`u32` beacon/coordinate epoch:** `fanos-crypto` VRF, `fanos-core` membership, `fanos-calypso` balance + `lib`, `fanos-proteus`, `fanos-quic`.
- **`u64` naming/descriptor epoch:** `fanos-onoma`, `fanos-calypso` *descriptor* (!), `fanos-node`.
- **`u64` telemetry frame epoch** = `now_nanos / window`, where under the QUIC driver `now = origin.elapsed()` is measured from **each node's own start**, so two nodes emit *different* epoch values for the same wall-clock window.

`fanos-calypso` is internally inconsistent — `balance.rs`/`lib.rs` use `u32` while `descriptor.rs` uses `u64` for the same descriptor concept. There is no `Epoch` newtype, so the compiler cannot catch a mismatch, and the telemetry frame epoch's premise that "nodes agree on which window they describe" is false off the simulator's shared virtual clock: any `(cell_id, epoch)`-keyed cross-node roll-up mis-buckets in production.

**Recommendation.** Introduce one `Epoch(u64)` newtype in a foundational crate. Where a KAT pins a 32-bit encoding (the VRF `coord_input`), encode only the low 32 bits with a documented comment so the wire stays stable while the *type* unifies. Derive the telemetry frame epoch from the consensus beacon, not from per-node local elapsed time, and rename it if it stays a distinct concept.

**Resolved (ARCH-9 / #90).** `fanos_primitives::Epoch(u64)` is the one canonical newtype (`epoch.rs`), threaded through every protocol-epoch seam — VRF/coordinate (`primitives::vrf`, `fanos-vrf`), membership (`fanos-core`), naming/descriptor (`fanos-onoma`, `fanos-calypso` *descriptor + balance + lib + rendezvous*), proteus, the runtime beacon (`overlay.rs`) and its `Notification::EpochAdvanced(Epoch)`, and `fanos-node`. The compiler now forbids mixing an epoch with any other integer, and the calypso `u32`/`u64` descriptor split is gone. Wire stability is preserved per-site by three documented codecs — `to_le_bytes`/`to_be_bytes` (8-byte, the onoma-descriptor and telemetry families) and `low32_be_bytes`/`from_low32_be_bytes` (the KAT-pinned 4-byte coordinate/beacon/proteus/balance family) — and every KAT (names.json, services.json, L4 storage, coordinate derivation) still passes byte-for-byte. The telemetry **frame** epoch stays a distinct `u64` observation-window counter (as this note anticipated); the runtime now feeds it the *agreed flooded-beacon* `Epoch` via an explicit `self.epoch.get()` at `overlay.rs`'s `observe_liveness` call, so the cross-node `(cell_id, epoch)` roll-up buckets on the beacon, not per-node local time.

### A4 — Unbounded state and absent back-pressure (systemic DoS class) *(HIGH)* — **RESOLVED**

The same shape recurs everywhere state is keyed by a peer- or attacker-chosen value with no eviction:

- **`fanos-rendezvous/src/transport.rs:149`** — `RendezvousService::routes` inserts a reply circuit per distinct cookie and never evicts. A client sending many cookies grows it without bound.
- **`fanos-node/src/diaulos.rs:93`** — the `serve` loop's `sessions` map is keyed by peer coordinate with no idle GC; a half-open session lingers forever.
- **`fanos-session/src/lib.rs:73-74`** (A4b) — `dial_over_transport` wires the async stream to the datagram transport through **unbounded** channels; there is no flow-control coupling, so a fast writer or slow network grows memory unbounded.
- The transport-layer instances of this are C1/C2/C3 (waiter maps, driver channels, receiver buffer).

**Recommendation.** Every peer-/attacker-keyed map needs a cap and a TTL/LRU reaper; every driver/session channel needs a bound with await-based back-pressure so the engine's own flow control is honored rather than discarded at the boundary.

**Resolved.** Every peer-/attacker-keyed map is now capped: `RendezvousService::routes` is a `BoundedMap` (`MAX_ROUTES`, this session); the `serve`/host session maps are `MAX_SESSIONS` with LRU eviction + a 120 s idle sweep that aborts the task (`fanos-node/src/{diaulos,rendezvous_host}.rs`); `rendezvous_relay` registrations/hosts are `BoundedMap`s; overlay `pending`/`pending_samples` are `MAX_PENDING_GETS`-capped and TTL-swept. The `fanos-session` datagram-transport channels (A4b) are bounded with `try_send` drop-on-full (DIAULOS retransmits). The transport-layer instances C1/C2/C3 are closed with them (see Part C).

### A5 — The anonymous path is not wired into the shipping node *(HIGH, architectural)* — **RESOLVED**

`fanos-rendezvous` (the anonymous DIAULOS meeting-line transport) is a complete sans-I/O core and is e2e-tested — **but only in `fanos-sim`** (`tests/anonymous_rendezvous.rs`). **`fanos-node` does not depend on `fanos-rendezvous`.** The shipping `fanos` binary therefore offers only the *Direct* profile, which addresses services by coordinate and reveals *where* each party is. The project's headline positioning — "provably-anonymous, censorship-circumventing VPN" — is not reachable through the binary today; it exists as a simulated capability. This is an honest in-progress state, but it should be named as such in the roadmap and README rather than implied to be shipping.

**Resolved.** `fanos-node` now depends on `fanos-rendezvous`, and the anonymous profile is reachable through the binary end to end: `fanos host --forward …` registers an anonymous forward-route and serves a hidden service at its beacon-blinded dead-drop (the §3b symmetric-NOSTOS host, `rendezvous_host.rs`), and `fanos proxy --profile anonymous` dials it via `anonymous_dial` (`rendezvous.rs`) — the client's coordinate never leaves the node and the service's coordinate is never published. Proven over real QUIC.

### A6 — No secret-material hygiene (`zeroize`/`subtle`) *(HIGH)* — **RESOLVED**

No workspace crate depends on `zeroize` or `subtle` (both appear only transitively in `Cargo.lock`). Consequently:

- **No secret is wiped on drop.** `HybridSigSecret`, `HybridKemSecret`, `VrfSecret`, `StaticKeypair`, `DkgNode.secret`, `CreditIssuer.k`, DIAULOS session keys, and Shamir shares all linger in freed memory.
- **`VrfSecret` derives `Copy` + `Debug`** (`fanos-vrf/src/lib.rs:42-43`): `Debug` can print the raw key, and `Copy` scatters unwipeable stack copies.
- FANOS-level secret comparisons have no constant-time path available. (AEAD tag verification itself *is* constant-time — delegated to `chacha20poly1305` — so this is latent rather than currently-exploited, but the mandate's "best-in-class" bar is not met.)

**Recommendation.** Add `zeroize`; wrap secrets in `Zeroizing`/`#[derive(ZeroizeOnDrop)]`; drop `Copy`/`Debug` on key types; add `subtle` for any future secret/tag comparison.

**Resolved.** `zeroize` and `subtle` are direct workspace dependencies. No secret type derives `Copy`; `VrfSecret` and the NYX `Ratchet` carry hand-written redacted `Debug` impls; and secret material zeroizes on drop across the workspace — Shamir `Share`, `HybridKemSecret`/`HybridSigSecret`, `DkgNode`, the onion ratchet, DIAULOS/ANGELOS session keys, and (2026-07-24) the OBOLOS wallet keys (`SpendingKey`/`FullViewingKey`/`IncomingViewingKey`), the NYX `Ratchet`, and the VSS share `Scalar`. `subtle::ConstantTimeEq` guards the credit-redemption authenticator.

### A7 — Real primitive built, insecure placeholder shipped *(MEDIUM)* — **RESOLVED (#66, Level A)**

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

### B5 — Hybrid KEM combiner does not bind the transcript *(MEDIUM)* — **RESOLVED (#63)**

~~`fanos-pqcrypto/src/kem.rs:78-86` hashes only `label ‖ x25519_ss ‖ mlkem_ss`, omitting the X25519 ephemeral public key and the ML-KEM ciphertext, so it does not meet the X-Wing / CFRG hybrid binding guidance (MAL-BIND-K,PK/CT), and there is no low-order/all-zero check on the X25519 shared secret. IND-CCA survives on the ML-KEM half, but binding does not.~~ **Transcript binding done.** `combine` (`fanos-pqcrypto/src/kem.rs:80-103`) now hashes `label ‖ x25519_ss ‖ mlkem_ss ‖ x25519_ephemeral ‖ mlkem_ct ‖ x25519_recipient_pk` — the full transcript, X-Wing/MAL-BIND-K,PK/CT-style. Pinned by `the_combiner_binds_every_transcript_element`. ~~**Residual still open:** neither `encapsulate` (`:128`) nor `decapsulate` (`:188`) checks the X25519 `diffie_hellman` output for a low-order/all-zero (non-contributory) result before it enters the combiner.~~ **Residual now closed.** Both `encapsulate` and `decapsulate` guard the X25519 `diffie_hellman` output with `x_ss.was_contributory()` and **fail closed** (`return None`) on a low-order/all-zero result before it reaches the combiner. Pinned by `a_low_order_x25519_ephemeral_is_rejected_on_decapsulate` and `encapsulating_to_a_low_order_x25519_recipient_key_is_rejected`. B5 is fully closed.

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

### C1 — No request timeouts; waiter maps leak *(HIGH)* — **RESOLVED**

`fanos-quic/src/driver.rs:210-243` — `Client::get`/`put` do `rx.await` with no timeout. The waiter is inserted into the router's `gets`/`puts` map and removed only when a matching digest returns. There is **no put-ack timeout or retry anywhere in the engine** (`overlay.rs:415,560-565`), so a down primary means `Stored` never fires, `put()` awaits forever, and the map entry leaks; the `get` path leaks whenever the heartbeat sweep is off. A SOCKS5 proxy resolving many unreachable `.fanos` names accumulates orphaned waiters with no eviction. **Fix:** `tokio::time::timeout` around the await, request-id correlation so the specific waiter can be evicted, a TTL reaper, and an engine-level put-completion timeout emitting a negative notification.

**Resolved.** `REQUEST_TIMEOUT`=10 s wraps `Client::get`/`put`; `router_loop`'s `evict_stale` sweep drops closed/stale waiters and empty digest buckets; the overlay `pending` map is `MAX_PENDING_GETS`-capped and TTL-swept (`sweep_pending_gets`); node resolve/directory paths use `RESOLVE_TIMEOUT`=5 s.

### C2 — Unbounded channels + single-task transport = no back-pressure *(HIGH)* — **RESOLVED**

All four driver channels are `mpsc::unbounded_channel` (`driver.rs:469-472`), and `transport_loop` (`:553-575`) is a single task that awaits each peer's full QUIC `connect` inline before writing. One slow/unreachable peer blocks **all** overlay sends while the engine keeps pushing `Effect::Send` into an unbounded queue; inbound, `read_frames` accepts up to 1 MiB per uni-stream, so an authenticated peer opening many streams floods the engine's input queue faster than the single engine actor drains it. **A connected peer can OOM the node, and one slow peer stalls all traffic.** **Fix:** bounded channels with await-based back-pressure, per-peer send tasks / a dial pool, and caps on concurrent inbound connections and in-flight frames.

**Resolved.** The QUIC ingress channel is bounded (`INPUT_CAP`; the per-connection frame reader `await`s on full, so a flood back-pressures through QUIC flow control); one `peer_send_worker` per destination isolates a slow/dead peer; inbound connections are capped globally (`MAX_INBOUND_CONNECTIONS`) and per source IP (`MAX_INBOUND_PER_SOURCE`). The datagram-transport channels (A4b) are bounded with drop-on-full.

### C3 — Receiver flow control is advisory, not enforced *(HIGH)* — **RESOLVED**

`fanos-runtime/src/stream.rs:288-289` admits a segment when `seq >= delivered && seq < next + recv_window`. Because the upper bound is anchored at `next` (which advances on contiguous *receipt*, `:297-299`) rather than at `delivered` (which advances only on `take()`, `:325-334`), the next in-order segment is **always** admitted regardless of how far the application's drain lags. A peer streaming in-order data that the app does not `take()` — or a peer ignoring an advertised `rwnd = 0` — grows the `received` buffer without bound. The module's "the receive buffer is bounded" guarantee is false on the in-order path. *(Verified by hand.)* **Fix:** anchor admission at `delivered + recv_window`, or hard-cap `received.len()`.

**Resolved.** Admission now anchors on the drain low-water mark — `seq < delivered + recv_window` (`fanos-stream/src/lib.rs`), so the receive buffer is bounded by `recv_window` and a zero-window probe is dropped until `take()` frees credit. (Same fix as F1.)

### C4 — Content-digest correlation is not request-scoped *(MEDIUM)* — **RESOLVED**

`overlay.rs:509-523` emits `Retrieved` on **any** `found = true` Value, even with no in-flight get, and the driver correlates purely by storage digest (coalescing same-key waiters). Because the store is mutable, a delayed or replayed Value from a prior get can drain a later same-key get's waiter with an **old** value (a read-your-writes violation); symmetrically, two concurrent puts of the same key with different values both report success though only one persists. **Fix:** emit `Retrieved` only when a matching pending get exists; carry a per-request nonce end-to-end and correlate on it.

**Resolved.** A monotone per-request nonce is carried end-to-end (`encode_lookup(digest, nonce)`); `on_value` (`overlay.rs:2149-2231`) resolves only a matching in-flight `pending` get whose nonce the reply echoes — a stale/replayed `Value`, or one with no in-flight read, is ignored (put-side ordered by version-LWW). Pinned by `a_stale_value_reply_cannot_resolve_a_read_it_does_not_belong_to`.

### C5 — Quarantine is permanent and locally-decided *(MEDIUM)* — **RESOLVED**

`overlay.rs:746` inserts a quarantined coordinate and never removes it (contrast reroute/repaired, cleared on Pong/gossip), and the verdict is driven by **local liveness-only** diagnosis whose own comment concedes that partition/cascade verdicts need the global view. A transient or mis-diagnosed Byzantine verdict permanently partitions a node — and there is no restoration theorem behind it. **Fix:** expire quarantine on a timer or on parental re-provisioning, and require multi-witness corroboration before quarantining.

**Resolved.** `QUARANTINE_TTL`=60 s expires quarantine (re-diagnosis re-quarantines if still bad), and `Verdict::Structural` co-emits `Escalate` for parental re-provisioning. Entry now requires multi-witness corroboration — a corroboration quorum on liveness, mediator polar attestation, and a persistent ≥3-witness endpoint-fabrication consensus — so no single observer can quarantine.

### C6 — `Decouple` is a no-op; the reflexive loop cannot lower Φ *(MEDIUM)* — **RESOLVED**

`overlay.rs:750-752` — `Decouple` only pushes a `Notification::Decoupled`; `healthy_correlation` is an immutable `Config` value and Φ is recomputed from it each round, so nothing actually sheds correlation. The spec's "shed correlation to restore headroom" (§2.7/§6.5) is therefore cosmetic — the self-healing loop's marquee cascade response does not change the quantity it targets. (`Decouple`/`Escalate` also re-notify on every `Diagnose`, unlike the deduplicated Reroute/Repair/Quarantine, so a persistent fault spams notifications.) **Fix:** give the engine mutable decoupling state that reduces effective correlation and feeds back into `phi_equicorrelated`; dedup the notifications.

**Resolved.** `Decouple` raises a mutable `decoupling` shed factor (capped, dwell-gated); `effective_correlation = healthy·(1 − decoupling)` feeds `phi_equicorrelated`, so a shed genuinely lowers measured Φ the next round, and it decays back on Bind/Hold. The notification is deduped by a `decoupled` latch. Pinned by `decouple_genuinely_sheds_correlation_and_is_deduped`.

### C7 — Telemetry "self-observation is anonymization" is false *(MEDIUM)* — **RESOLVED**

`fanos-telemetry` claims "the fold *is* the anonymization," but the crate contains no differential-privacy machinery (no noise, no ε budget). The `CoherenceFrame` carries the **exact** 3-bit syndrome naming the faulted point plus exact Φ/P/R/mean-r/gap scalars (`frame.rs:58-72`), emitted as `Notification::Observed` and gossip-able. Any frame observer learns which node is down and the cell's exact health each window. (Self-observation being *mandatory and embedded* is correct and sound — only the anonymization claim is false; local history is properly bounded via RRD ring buffers.) **Fix:** add calibrated noise, coarsen/withhold the syndrome, track an ε budget — or drop the anonymization claim.

**Resolved (both branches).** The false claim is corrected in-code (`frame.rs`: "data minimization, not anonymization … **Do not export a raw frame**"), and `CoherenceFrame::privatize` (`dp.rs`) provides a genuine ε-DP export — a zero-mean Laplace mechanism at L1 sensitivity Δr=1/21, ε-budgeted, with the exact syndrome/gap/heal-seq withheld. No raw frame is auto-exported cross-node.

**Lower-severity:** a connection-cache check-then-insert race with no inbound-connection cap (`driver.rs:579-620,642-670`, connection-flood surface); lossy notification delivery under load (`next_notification`/`subscribe` skip on lag past a 4096 ring — no lossless path for `Delivered` payloads); two content-address domains (`routing::content_address` uses `label::COORD` while the engine/driver use `label::STORAGE`) that look interchangeable but resolve to different points; and a `u128→u64` driver-clock truncation (~584 years, noted for completeness).

---

## 7. Part D — Math core

The algebra is the **most fundamentally sound part of the workspace**, and this was cross-validated hard (two independent derivations — const Fano tables vs. generic `Plane<F>` — plus exhaustive and property tests, plus external verification of every field polynomial). The defects are **not in the mathematics** but in its **numerical hygiene at the trust boundary**: the diagnostic plane assumes finite, well-formed `f64` telemetry and neither sanitizes nor defends against `NaN`/`Inf`/non-PSD input. Because DIAKRISIS consumes **gossiped** health reports (`DiagGossip`), these are not merely library-surface issues — a malicious node can gossip non-finite scalars into a victim's diagnosis.

**Verified correct (load-bearing, do not regress):** all core measures reduce to the spec exactly — `Φ = (frob − N)/N`, `P = frob/N²`, `R = N/frob`, with equicorrelated `Φ = (N−1)r²`, `P = (1+(N−1)r²)/N`, `r* = 1/√(N−1)`, `P_crit = 2/N`; every `GF(2^m)` reduction polynomial is irreducible **and** primitive (externally checked), `clmul` shift-and-reduce is correct, and prime-field arithmetic is overflow-safe; geometry cross/dot/canonicalize and `points_on` are brute-force-verified for F2/F7/F13/F31 and `pgl3_order` is exact in `u128`; Hamming(7,4) syndrome masks and the LRC `peel_fano`/`is_hyperoval_fano` are exhaustively correct over all 128 masks (exactly 7 hyperovals); and `fanos-wire` is genuinely canonical and panic-free on truncated/adversarial input (non-minimal varints, out-of-range elements, and non-canonical coords are all rejected; lengths use `usize::try_from` + `checked_add`, wasm-safe). The `N = 7` hardcoding is **intentional and honest** — DIAKRISIS is defined on the base Fano cell `PG(2,2)` (spec Part VI), the coherence/window measures are properly general-`N`, and the `_fano` suffixes make the specialization explicit. (Its *architectural* consequence is A2, not a correctness bug.)

### D1 — `max_reroute_depth` never terminates on a non-finite Φ *(HIGH — live-confirmed DoS)* — **RESOLVED**

`fanos-diakrisis/src/healing.rs:39-50` — the loop `while current * (1/9) >= 1.0 { current *= 1/9; depth += 1 }` never exits when `current = +Inf` (`Inf · 1/9 = Inf ≥ 1` forever), and `depth: u32` overflows — an **infinite loop in release, an overflow panic in debug**. Confirmed live: the call did not return within 2 s. It is reachable because `plan_healing` takes the cell's measured `Φ`, and `Φ = Inf` is producible via D2. A crafted/garbage coherence reading hangs or crashes the healing controller. **Fix:** `if !phi.is_finite() { return 0 }` and cap the loop at a constant (`Φ/9^d` needs ≤ ~40 iterations for any finite `f64`).

**Resolved.** `max_reroute_depth` returns 0 early on `!phi.is_finite() || phi < 1.0` and caps the loop at `MAX_REROUTE_DEPTH`=64 (which also forecloses the `u32` overflow). Pinned by `max_reroute_depth_is_total_and_terminates_on_non_finite_phi`.

### D2 — `from_correlation` accepts non-finite / non-PSD / out-of-range matrices *(HIGH)* — **RESOLVED (2026-07-24)**

`fanos-diakrisis/src/coherence.rs:86-101` — validation uses `(x−1.0).abs() > 1e-9` and `(a−b).abs() > 1e-9`, both defeated by `NaN` (all `NaN` comparisons are false), with no PSD or `|r| ≤ 1` check. Confirmed live: symmetric `NaN` off-diagonals are accepted → `Φ = NaN`, `is_overcoupled() = true` → `diagnose` returns `Verdict::Systemic` on garbage; an `Inf` entry → `Φ = Inf` (feeds D1); `|r| = 5` non-PSD → `Φ = 50`, `purity = 17`. This causes spurious `Decouple`/`Systemic` misdiagnosis, can violate the V17 leading-indicator ordering, and is the reachability root of D1. **Fix:** reject any non-finite entry; enforce `|c_ij| ≤ 1` and a cheap PSD/diagonal-dominance guard.

**Resolved (2026-07-24).** `from_correlation` now rejects any non-finite entry, any `|c_ij| > 1` (Cauchy–Schwarz), and any non-PSD matrix (least eigenvalue < −ε·n, computed via the crate's own symmetric eigensolver — exact for symmetric input). Diagonal-dominance was deliberately *not* used as the PSD proxy (it would reject valid equicorrelated matrices). Pinned by `from_correlation_rejects_non_finite_out_of_range_and_non_psd_matrices`.

### D3 — `violated_classes` treats non-finite rates as consistent — the Byzantine detector is evadable *(MEDIUM-HIGH)* — **RESOLVED**

`fanos-diakrisis/src/polar.rs:100-110` — `(r0−r1).abs() > tol` is `false` when the rates are `NaN`, so an all-`NaN` (or NaN-injected) `pairwise_rates` matrix reports **zero** violated classes. Confirmed live: `diagnose(NaN rates) = Healthy`. The polar-sum-rule Byzantine structural detector (spec §6.2) can be evaded by a node emitting non-finite rate reports. **Fix:** treat any non-finite entry in a class as a violation, or reject the observation up front.

**Resolved.** `violated_classes` now treats any non-finite rate in a class as a violation, so an all-`NaN` `pairwise_rates` flags all 7 classes instead of zero. Pinned by `violated_classes_flags_non_finite_rates`.

### D4 — Jacobi eigen-solver has no convergence/robustness signal *(MEDIUM, latent)* — **RESOLVED (2026-07-24)**

`fanos-diakrisis/src/eig.rs:28-70` runs a fixed 100 sweeps with an *absolute*, non-norm-scaled off-diagonal threshold and silently returns the diagonal; `NaN`/`Inf` propagate silently, and a `NaN` Laplacian yields `fiedler_value = NaN` → `is_connected = false` → spurious `Partition`. For the actual partition path the Laplacian is built from a `u8` line mask (always finite), so this is **not currently reachable** — hence latent — but it is a sharp edge on the library surface. **Fix:** scale the threshold by the Frobenius norm, add an early non-finite check, and expose a "did not converge" signal.

**Resolved (2026-07-24).** `eigenvalues_symmetric` now returns `Option`: `None` on any non-finite input **and** on non-convergence (the explicit did-not-converge signal), with a Frobenius-norm-relative convergence test (scale-invariant). `fiedler_value` fails safe to 0 rather than propagating a `NaN`. This hardening also underpins D2's PSD check on untrusted input. Pinned by the new `eig::tests`.

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

### F1 — Receiver buffer unbounded under a stalled reader (the C3 bug, from the stream side) *(HIGH)* — **RESOLVED**

Confirmed independently: `fanos-runtime/src/stream.rs:288-289` anchors admission on `next` (the contiguous frontier) while the buffered byte count is governed by `delivered` (what the app drained), so an in-order `seq == next` is accepted whenever `recv_window > 0` — **always**. A stalled local reader (a SOCKS client whose TCP socket is blocked) or a flooding peer drives unbounded `received` growth at line rate. Even a *fully compliant* sender leaks: its zero-window probe (`seq == acked == next`) is accepted as in-order every round, ~1 segment/RTT forever. **Fix:** anchor on the drain low-water mark — `seq < delivered + recv_window` — which also correctly drops the probe until `take()` frees credit, consistent with the existing `rwnd = recv_window − held` computation.

**Resolved.** `on_segment` now admits on `segment.seq >= delivered && segment.seq < delivered + recv_window` (`fanos-stream/src/lib.rs`, the reliability state machine having moved there from `fanos-runtime`), bounding the buffer by `recv_window` and dropping the zero-window probe until `take()` frees credit. Pinned by `the_receive_buffer_is_bounded_by_recv_window_under_a_flood`.

### F2 — No concurrent-stream cap; streams are never retired *(HIGH)* — **RESOLVED**

`fanos-diaulos/src/conn.rs:170-182` — a DATA frame for an unknown `stream_id` unconditionally allocates a new `Stream`, and **no code path anywhere removes a stream from `self.streams`**, not even after `is_stream_done`. Two failure modes:

- *Adversarial:* an authenticated peer sends DATA with distinct ids `0,1,2,…` — one `Stream` (with its maps/vecs) per cell, plus an unbounded `accept_queue` if the app doesn't `accept()`.
- *Honest, arguably worse:* the SOCKS proxy opens one stream per client connection; over a long-lived `Connection`, completed streams accumulate forever, and `outbound()` emits **one ACK cell per stream every tick** for every dead stream — O(total-streams-ever) cells/tick.

The initiator-even/responder-odd parity is also not enforced on implicit open, so a peer can pollute the local id space and a later `open_stream()` can silently overwrite an injected stream. **Fix:** a live-stream cap that rejects/limits implicit opens; retire streams on `is_stream_done` (and stop ACKing retired streams); bound `accept_queue`; enforce parity on implicit opens.

**Resolved.** `MAX_CONCURRENT_STREAMS`=256 caps implicit opens; `retire_stream` removes a stream once `is_stream_done` (and the outbound iterator no longer ACKs it); `accept_queue` is bounded by the same cap; parity is enforced on implicit open; and a `Reset`/abort frame was added. Pinned by `implicit_opens_are_capped_to_bound_stream_memory`, `a_wrong_parity_implicit_open_cannot_seize_a_local_id`, and `reset_aborts_a_stream_both_ways_and_blocks_reopen`.

### F3 — Sender never reclaims acknowledged segments *(HIGH)* — **RESOLVED**

`fanos-runtime/src/stream.rs:103` — `StreamSender.segments: Vec<Vec<u8>>` is append-only; `on_ack` advances `acked` but never truncates, and `outbound()` indexes `segments.get(seq as usize)`. Acknowledged data is never freed, so **sender memory equals the total bytes ever sent**, not the in-flight window. A proxied large download buffers the entire file in RAM even though it is fully acked — the layer cannot stream anything larger than memory. **Fix:** reclaim below the cumulative ack with a `base_seq` offset + `VecDeque` (translate `seq → seq − base_seq`), dropping entries `< acked`.

**Resolved.** `StreamSender.segments` is a `VecDeque` with a `base` offset; `on_ack` reclaims below the cumulative ack (`while base < acked { pop_front }`) and `outbound` indexes with `seq − base`; the per-seq timing maps are pruned in lock-step, so sender memory tracks the in-flight window, not total bytes ever sent. Pinned by `the_sender_reclaims_acked_segments` + `timing_state_stays_bounded_by_the_window_over_a_long_transfer`.

### F4 — No RTO; sender `sacked` set grows from crafted ACKs *(MEDIUM)* — **RESOLVED**

`outbound()` (`stream.rs:198-214`) re-emits the *entire* unacked in-window set every call, with no per-segment timer, dup-ack threshold, or backoff — the driver's tick is the de-facto RTO, so a fast tick spuriously retransmits and (under the constant-rate shaper) crowds out cover budget. Correctness holds (fresh nonce per emit). Separately (`stream.rs:222-224,232`), `on_ack` inserts `cumulative + i` for each SACK bit keyed off the *peer-supplied* `cumulative` and prunes only below `acked`, so an authenticated peer sending ACKs with `cumulative` near `u32::MAX` accumulates surviving entries indefinitely — unbounded `BTreeSet` growth. **Fix:** RTT-estimated RTO + fast-retransmit; ignore SACK bits whose absolute sequence is `≥ segments.len()`.

**Resolved.** An `RttEstimator` (RFC-6298 SRTT/RTTVAR/RTO) drives a per-segment `due_at`; `outbound` re-sends only first-sends and past-RTO segments, with a 3-dup-ack fast retransmit; and `on_ack` ignores SACK bits whose absolute sequence is `≥ total`, so a crafted far-future `cumulative` cannot grow `sacked`. Pinned by the RTT / fast-retransmit tests + `on_ack_is_robust_to_stale_and_hostile_cumulative`.

**Lower-severity:** there is no RST/abort frame — a stream can only close via FIN, so a peer that opens and never FINs pins it forever (compounding F2); `fin_seq` (`stream.rs:291-293`) accepts a FIN on any in-window segment and overwrites, letting a peer truncate the stream so `deliver()` and `take()` disagree; and `u32` sequence / stream-id wraparound is unguarded with a couple of non-saturating adds (`stream.rs:202,310`) that are unreachable given memory bounds but unasserted. The AEAD nonce counter's `wrapping_add` (`conn.rs:115-117`) should likewise become a hard connection-kill at the limit.

**Resolved.** A `Frame::Reset`/abort frame exists (minted by `reset_stream`, honored in `on_cell` — drops state, unqueues the accept, blocks re-open); `fin_seq` is guarded against a peer truncating or contradicting an established FIN; and the AEAD nonce counter now `checked_add`s and hard-kills the connection at 2⁶⁴ rather than wrapping (pinned by `the_connection_hard_kills_at_nonce_exhaustion_rather_than_reusing_a_nonce`). The `u32` seq/stream-id wraparound remains unreachable by memory bound.

**Test-coverage gaps behind these:** there is no stalled-reader test, no zero-window-probe test, no stream-retirement/cap test, no sender-reclaim test, and — critically — no *valid-but-malicious-peer* test (the existing `robustness.rs` feeds only random blobs that fail AEAD and are dropped, so F1/F2/F4 all go unexercised). These are the tests that would have caught the HIGH findings.

**Verdict (updated 2026-07-24).** The delivery logic was already ship-quality; the flow-control and lifecycle accounting (F1–F4, plus RST / FIN-guard / nonce-kill) are now fixed and adversary-tested, so the layer is safe to face a real network or a malicious counterparty. The reliability state machine now lives in `fanos-stream`; F2 / RST / nonce-kill are in `fanos-diaulos/src/conn.rs`.

---

## 10. Part G — Documentation integrity

- **G1 (MEDIUM) — RESOLVED.** ~~`rust/README.md` … claims "119 tests" and documents only 8 of 27 crates …, omitting the entire privacy, DIAULOS, node, and proxy stack.~~ The README is refreshed (2026-07-24) to all **41** crates in seven layer groups, each with an accurate one-liner; the counts are corrected (1,600+ tests), the phantom `fanos-crypto` row is replaced by `fanos-primitives`, the L8–L12 platform layer is documented, and the "Using the library" example is updated to the current VRF/beacon `Node::open` signature.
- **G2 (LOW) — RESOLVED.** ~~`docs/design-platform.md` presents `#[derive(Wire)]` ("emits codec + KATs from one type definition") as part of the architecture; it is unbuilt.~~ Built: `fanos-wire-derive` is a proc-macro used at 25 sites — the substrate for the A1 wire re-canonicalization.
- The design corpus (`design.md`, `design-platform.md`, `roadmap.md`) is otherwise unusually thorough and honest, and already records several of the gaps above as known — this audit sharpens them with file/line anchors and severity, and adds the DKG, flow-control, and wire-bifurcation findings that were not previously called out.

---

## 11. Part H — Prioritized remediation roadmap

**Tier 0 — correctness/security, do first**
1. ~~**Authenticate the DKG (B1) and fix the QUAL/share atomicity (B2, B3).** Bind `from` to the claimed index or sign every DKG frame; gate `refs.push` on the Feldman result; verify justifications against the qualified commitment. Add the adversary tests that should have caught these.~~ **DONE.** `from` is authenticated against the claimed dealer/complainer (B1); the Feldman-gated push closes the `x·G ≠ Y` atomicity gap (B2); justifications verify against the qualified commitment (B3); all three are pinned by dedicated adversary tests. See the B1–B3 §resolutions.
2. ~~**Make DLEQ nonces synthetic (B4)** and **fix the descriptor nonce reuse (E3)** — both are seed/nonce-reuse correctness bugs that leak secrets or keystream. Deterministic-from-`(k, transcript)` for DLEQ; salt/counter in the descriptor nonce.~~ **DONE.** B4's DLEQ nonce is now synthetic (RFC-6979-style, over the issuer secret + transcript); E3's descriptor nonce now carries a SIV-style per-publish salt bound to the plaintext. See the B4/E3 §resolutions.
3. ~~**Close the reachable OOM/hang cluster:** enforce receiver flow control (C3/F1, anchor admission on `delivered`); cap and retire streams (F2); reclaim acked sender segments (F3); add request timeouts + waiter eviction (C1).~~ **DONE.** Admission anchors on `delivered` (C3/F1); `MAX_CONCURRENT_STREAMS`+retire (F2); `VecDeque`+`base` reclaim (F3); `REQUEST_TIMEOUT`+`evict_stale` (C1). See the C/F §resolutions.
4. ~~**Sanitize DIAKRISIS telemetry inputs (D1, D2, D3).** Reject non-finite/non-PSD coherence and rate readings at the boundary and cap the reroute-depth loop — otherwise a single gossiped `NaN`/`Inf` hangs a peer's healing controller or evades the Byzantine detector.~~ **DONE (2026-07-24).** `from_correlation` rejects non-finite / `|r|>1` / non-PSD (D2), `violated_classes` treats non-finite as a violation (D3), and `max_reroute_depth` guards non-finite + caps iterations (D1); the eigensolver was hardened (D4) so the PSD check is safe on untrusted input.

**Tier 1 — robustness, hygiene, anonymity floor**
4. ~~**Bound and back-pressure everything (A4, A4b, C2):** cap + TTL every peer-keyed map (rendezvous routes, node sessions, waiter maps); bound every driver/session channel; per-peer send concurrency.~~ **DONE.** Every peer-keyed map is a `BoundedMap` / cap+TTL (A4); the QUIC ingress and the datagram-transport channels are bounded with back-pressure or drop-on-full (C2/A4b); per-peer send workers isolate a slow peer.
5. ~~**Restore the Full-profile anonymity floor (E1, E2):** port constant-rate cover into `ThresholdRouter`, key its mix delays off a secret.~~ **DONE (#61).** E1/E2/E3/E4/E5/E6 all resolved on the Full/threshold path (constant-rate cover, secret-keyed mix delays, SIV-salted descriptor nonce, forward-secure onion ratchet, distributed rendezvous beacon); see the E-section resolutions. Remaining anonymity work: the beacon's live-network deployment transport (→ #54).
6. ~~**Adopt `zeroize`/`subtle` (A6);** drop `Copy`/`Debug` on key types.~~ **DONE.** `zeroize`/`subtle` are direct deps; no secret derives `Copy`; secret material zeroizes on drop and key types carry redacted `Debug`.
7. ~~**Bind the KEM transcript (B5); seed DKG per-run (B6); constant-time Shamir (B7);**~~ **B6/B7 DONE, B5 PARTIAL (#63).** B6: DKG now folds a fresh per-instance `session_nonce` into the polynomial seed. B7: `clmul` is now branchless (mask-based, no data-dependent branches). B5 is **now fully DONE:** the SHAKE256 combiner binds the full transcript (ephemeral pk + ct + recipient key) **and** the contributory-behaviour check (`x_ss.was_contributory()`, fail-closed) is present in both `encapsulate` and `decapsulate` — see the B5 §resolution. ~~rotate relay KEM keys per epoch or scope the FS claim (E4).~~ **E4 DONE (#61)** — forward-secure per-epoch onion ratchet (`OnionKeyRatchet`) with a bounded grace window, wired into `ThresholdRouter` (peels via `onion.secrets()`, advances on `AdvanceEpoch`) and epoch-scoped mix-key discovery; see the E4 §resolution.

**Tier 2 — fundamentality / architecture**
7. ~~**Re-canonicalize the wire (A1).**~~ **DONE (#82).** `#[derive(Wire)]` (exists) is the substrate; every migratable struct serializer is on it (calypso `Descriptor`/`SealedDescriptor` + balance `MasterDescriptor`, telemetry history, rendezvous `Request`, quic creds); `fanos-wire` is the single frame-code authority (`FrameType` + `SessionFrameType`, `App=0x70` registered); the duplicate integer/`Cursor` decoders (diaulos frame, calypso-balance) are eliminated; the `Tessera` layout was already regenerated (encrypted holonomy, 8192). The rest is justified must-stay (transcripts / layered crypto / group-validated foreign types). All four A1 consequences resolved — see the A1 §Progress note.
8. ~~**Introduce the `Epoch` newtype and fix the telemetry frame epoch (A3).**~~ **DONE (#90):** `fanos_primitives::Epoch(u64)` threaded through every protocol-epoch seam (calypso u32/u64 split closed); telemetry frame epoch fed the agreed beacon `Epoch` via `observe_liveness`. All KATs byte-identical; clippy/fmt clean. See the A3 §resolution.
9. ~~**Resolve the placeholder/real split (A7):** wire `fanos-vrf` into membership, or delete the placeholder and document the gap.~~ **DONE (#66, Level A):** the real VRF is the coordinate authority — beacon-folded, identity-committed, live + HELLO-proven (commits `b90e35d` + `6b6c2f2`); Level B (reshuffle + hierarchy unification) tracked (#95). See the A7 §resolution + `docs/design-coordinates.md`.
10. ~~**Make `Decouple` real or remove it (C6); give quarantine an exit + multi-witness gate (C5); make telemetry DP-safe or drop the anonymization claim (C7).**~~ **DONE.** `Decouple` sheds real correlation that lowers Φ (C6); quarantine has a TTL exit + multi-witness gate (C5); telemetry dropped the false claim and added an ε-DP export (C7). See the C5/C6/C7 §resolutions.

**Tier 3 — capability completion**
11. ~~**Wire the anonymous rendezvous path into the node binary (A5)**~~ **DONE** — `fanos host` serves and `fanos proxy --profile anonymous` dials a hidden service, neither coordinate revealed; ~~give the service side a full duplex stream to match the client (currently one-shot RPC).~~ **Service duplex DONE (#66):** `serve` is a full-duplex per-client stream (`serve_rpc` keeps request/response a one-liner); a unified `SessionStream` driver serves both directions. See A5 + the service-duplex row.
12. ~~**Decide and document the large-`q` scaling story (A2).**~~ **DONE (#66):** recorded in `docs/design-coordinates.md` §5 — `q = 2` + hierarchy is the scaling model; large-`q` `Plane` is spec-completeness, not a scaling lever.
13. ~~**Refresh the README and reconcile the design docs with the shipping surface (G1, G2).**~~ **DONE (2026-07-24).** README refreshed to all 41 crates with accurate counts and a current `Node::open` example; `#[derive(Wire)]` is built (G2). See the G1/G2 rows.

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

**Update — 2026-07-24: all nine addendum items are now resolved.** A per-item re-audit against the current tree confirmed each is implemented: §6.4 live diagnose→heal (`on_diagnose` runs every heartbeat), §12.3 threshold-hosted CALYPSO (`ServiceNode`+`ThresholdService` wired into `Node::start`), §7.4 capability negotiation (`fanos-wire::capability`, folded into HELLO), §7.9 wire-KAT harness (`fanos-wire/tests/wire_kat.rs` loads + verifies `conformance/vectors/wire.json`), L3.2 per-epoch reshuffle (`reshuffle_loop` on `BeaconReady`), L3.3 Sybil admission (`PowAdmission` wired into JOIN via `with_admission_pow`), L4.1 erasure coding (`fanos-code::{erasure,lrc}` replaces full replication), §5.4 holonomy verification (`verify_delivery` produces `WireError::HolonomyFail` on the live peel path), and PROTEUS enablement (config/CLI surface + auto-fallback + capability advertisement). The deeper residuals surfaced afterwards — cross-cell erasure placement, full hidden-service reachability, censored-bootstrap bridges — are carried forward and tracked in the consolidated later-audit sections that follow (Audits II–IV).


---

<!-- ═══════════════════ AUDIT II of IV ═══════════════════ -->

> **Audit II of IV — consolidated into `docs/audit.md` on 2026-07-24** (formerly `docs/audit-2026-07-22.md`). The first adversarial review of the crown-jewel subsystems built after Audit I (OBOLOS / DROMOS / THESAUROS / ANGELOS / live TAXIS). Preserved verbatim as a dated snapshot; for the **current** status of its findings see the *Consolidation status* note near the top of this file — most were closed by Audits III–IV and the subsequent recovery / anonymity / validator work.

# FANOS platform deep audit — 2026-07-22

**Scope:** the whole `rust/` workspace (39 crates, ~88.5k LoC) + `spec/protocol.md`, `spec/platform.md`, and the HOLARCH meta-spec (`uhm-theory/.../applied/research/holarch.md`), with special focus on (1) end-to-end anonymity for `.fanos` and clearnet surfing, (2) survival + self-organization under mass destruction and heterogeneous recovery, (3) holonic-architecture compliance and cross-level coherence, and (4) the simulator.

**Baseline at audit time:** the tree is **332 commits past** the prior audit (`docs/audit.md`, 2026-07-18); the whole workspace **compiles green under `--all-targets`**; **1408** `#[test]`/`#[tokio::test]` annotations. Full `cargo test --workspace` + `clippy --all-targets -D warnings` result: **see §0**.

**Method:** eight parallel adversarial audit streams (anonymity, OBOLOS, TAXIS/DROMOS, ANGELOS/THESAUROS, HOLARCH coherence, simulator, systemic robustness, mass-failure self-organization), each grounded in the specs above and told to verify *current* code (not the prior audit's snapshot). Every CRITICAL/HIGH below was read at `file:line` by the responsible stream; findings are tagged **CONFIRMED** (read and definite) or **LIKELY** (inferred, needs a second look). This document is written to be executed from — the sibling dev-agent should treat §10 as the work queue.

---

## §0. Verification baseline

- `cargo build --workspace --all-targets`: **PASS** (exit 0, verified this session).
- `cargo clippy --workspace --all-targets -- -D warnings`: **PASS** (clean, verified this session — the CI gate holds).
- `cargo test --workspace`: **green** (verified this session — exit 0, **1414 passed / 0 failed** across 181 test binaries).
- No `TODO`/`unimplemented!` markers in `rust/crates` (per `docs/tasks.md`, re-confirmed by the robustness stream: all new crates `forbid(unsafe_code)`, no `unwrap`/`expect`/`panic`/OOB-indexing in non-test code for obolos/dromos/thesauros/angelos).

The important caveat this audit establishes: **green tests do not cover the findings below.** Nearly every CRITICAL/HIGH lives in a code path the existing tests do not exercise adversarially (media seals one-direction-only; `settle_epoch` is fed a bool directly; the sim broadcasts every reveal to all validators; the sim moves reshuffled nodes to unoccupied coordinates; etc.). The green suite is real, but it is a *conformance/regression* suite, not an *adversarial* one.

---

## §1. Executive summary

FANOS is, as the prior audit found, an unusually principled and honest codebase — the cryptographic cores are real (audited PQ primitives, a correct 1:1 double ratchet with genuine FS+PCS, a sound projective-LRC store, exact DIAKRISIS invariant math, BFT ordering safety verified to `q=1000`), the status discipline is candid, and the transport/stream DoS cluster that dominated the last audit is **genuinely fixed**. The team has closed an enormous amount in four days.

But this audit surfaces one dominant, systemic theme and a cluster of load-bearing defects inside it.

### The meta-pattern (present in 6 of 8 streams): **libraries/engines/proofs ahead, live-wiring behind**

The cryptographic cores, accounting math, invariant formulas, controllers, and healing actuators are built, unit-proven, and tested. What is missing, over and over, is the layer *around* them:

- **the guards** — replay/epoch binding, sender authentication, direction separation, input validation before buffering;
- **the enablement** — cover traffic + mixing, beacon provisioning, self-organization actuation, differential-privacy export, holonomy verification;
- **the recovery wiring** — beacon resharing, parent escalation transport, cross-cell erasure.

Nearly every CRITICAL and HIGH below is an instance of this pattern. It is not sloppiness; it is the gap between an excellent skeleton and a live, adversary-facing, self-healing platform — the same "excellent foundations, incomplete productionization" shape the prior audit named, now extended into the crown-jewel subsystems (OBOLOS, DROMOS, THESAUROS, ANGELOS, live TAXIS) that were built *after* that audit and had never been reviewed.

### Severity tally

| Severity | Count | Where |
|---|---|---|
| **CRITICAL** (security/liveness/funds) | **9** | OBOLOS inflation (C1) + untraceability break (C2); THESAUROS escrow drain (S4-C1); ANGELOS media nonce-reuse (S4-C2) + group forgery (S4-C3); anonymity clearnet-not-anonymized (S1-C1); resilience beacon-stall (R-C1) + escalation-unwired (R-C2) + erasure-loss (R-C3) |
| **CRITICAL-ARCH** | **1** | HOLARCH Γ-viability gate unbuilt while gated tiers ship |
| **HIGH / HIGH-ARCH** | **~18** | TAXIS exec-divergence (borderline critical), round-lock liveness wedge, keyper censorship, DA-not-wired, slashing-not-applied; anonymity cover/mixing-off, beacon-unreachable, cookie-correlator; resilience membership-lockout, self-org-not-live, zero-reintegration-budget; robustness B1 taxis-pending-reveals; OBOLOS fee-drift + note-cipher-nonce; THESAUROS PoR-not-provider-bound + reputation-not-wired; ANGELOS media-replay; HOLARCH E→L/L→O/self-org/Ω2 |
| **MEDIUM / LOW** | ~40 | per-subsystem, §5–§7 |

### The three answers the user asked for, up front

1. **Ultimate anonymity (`.fanos` + clearnet):** the cryptographic core is strong and the anonymous `.fanos` path is now genuinely live over real QUIC (a real advance over the prior "sim-only"), **but the shipping node delivers threshold-onion unlinkability *without* the GPA defenses, forward secrecy, moving-target rotation, or clearnet anonymization the spec advertises** — cover traffic and mixing are off, the beacon is unreachable so epochs never advance, `--profile anonymous` sends clearnet *direct*, and the session cookie is a cleartext cross-correlator. **§3.** The guarantee is real in the engine and inert in deployment. *Not yet defensible as "ultimate."*
2. **Mass-destruction → heterogeneous recovery self-organization:** **not flawless — three CRITICAL cliffs**, all on the *unwired* recovery path: the beacon permanently stalls below threshold with no re-DKG (a network-wide liveness SPOF), escalation-to-parent is a log line, and erasure loss past `[7,3,4]` is silent permanent data loss. The self-organizing role loop is *never called by `Node::start`*. **§2.** The proofs exist; the network that would survive its own destruction does not run.
3. **Holonic coherence:** the network-cell layer is genuinely holonic in code; the *platform* layer is holonic in prose and conventional in code — the Γ-viability gate the platform calls its release criterion is **unbuilt**, and the meta-holon's cross-block is ~1/3 wired (L↔E live, E→L absent, L→O reversed). **§4.**

---

## §2. Mass destruction → heterogeneous recovery (the self-organization scenario) — PRIORITY

*This is the user's most-emphasized dimension: nodes go offline en masse, then recover heterogeneously — some identical (rebooted server, same identity/coordinate), some changed, some never, and new nodes appear. The self-organization model must be flawless. It is not.* The scenario's survival depends **almost entirely on the unwired half** of the codebase (`roles.rs`, `hierarchy.rs`, `partition.rs`, `regeneration.rs`, `derive_hierarchical_address`, `LiveRoleController` — all built, unit-proven, and **not driven in `Node::start`**).

### [CRITICAL] R-C1 — Beacon liveness cliff: sub-threshold anchor loss permanently stalls the epoch clock; no re-DKG / resharing
*Anchors:* `fanos-vrf/src/beacon.rs:283` (`assemble`), `:235` (`combine`), `:313` (`verify_and_seed`) — all return `None` below threshold; `fanos-keygen/src/beacon.rs:135` (`try_assemble`); `fanos-quic/src/driver.rs:829` (`reshuffle_loop` blocks on `BeaconReady`); `fanos-node/src/overlay_beacon.rs:107` (`drive_overlay` only advances on `BeaconReady`); `fanos-node/src/config.rs:31-36` (static shares, no re-DKG).

**Trajectory:** losing `n−t+1` anchors → no round assembles → no `BeaconReady` → the epoch clock **and** the coordinate reshuffle both freeze forever → recovering/new nodes cannot compute current placement, cannot pull-sync the beacon (no synced peer to answer), and land at genesis in a different coordinate space than the survivors → HELLO `EPOCH_STALE` rejects them → **the cell is frozen and unjoinable.** There is **no anchor-reconstitution / proactive-resharing / re-DKG path anywhere** (grep for `reshare`/`proactive`/`refresh`/`redeal` = none; the DKG is one-shot, dead shares are gone). Because the design propagates *one* beacon down the hierarchy (`design-self-organization.md §6`), this is a **network-wide randomness-liveness single point of failure**, not a local one. For a Fano cell (`n=7`, `t∈{3,4,5}`), the ">3 losses/cell" boundary the whole fault model is built around is *exactly* this cliff.

**Fix (fundamental, painful, correct):** proactive **verifiable secret resharing** (periodic re-DKG / Herzberg-style proactive VSS) so a depleted anchor set below `t` is reconstituted from ≥`t` survivors without revealing the secret; plus a **beacon re-bootstrap protocol** (on `<t` live anchors for `D` epochs, run a fresh DKG among current members and publish a new commitment via the parent, or an operator-signed rollover at the genesis root); plus **safe-stall semantics** — when the beacon is down, freeze coordinates *and* freeze `EPOCH_STALE` rejection, so a lagging node can still attach to the last good epoch instead of deadlocking.

### [CRITICAL] R-C2 — Escalation / parent-recovery is not wired: the recovery-of-last-resort is a log line
*Anchors:* `fanos-node/src/bin/fanos.rs:543` (the **only** `Notification::Escalated` consumer — an `info!` log); `fanos-diakrisis/src/hierarchy.rs` (pure function, no live parent cell, "fed by hand" per `design-coordinates.md §4(d)`); `fanos-runtime/src/overlay.rs:911` (`HealingAction::Escalate`), `:813` (`BandControl::Escalate → Escalated(0)`); `fanos-core/src/roles.rs:620` (`assign_report` deficit — also no live parent).

**Trajectory:** every design doc names escalation as the authoritative fix for a collapsed cell (`ddos-homeostasis.md §5`: `P<2/7 ⇒ g_V=0 ⇒` regeneration off `⇒` external help required; `design-self-organization.md §4`: deficit → parent recruits/relaxes). In the running system, a collapsed or under-provisioned cell emits `Escalated` and **nothing receives it** — no parent recruits a sibling node, no cross-cell reconstruction, no service-level relaxation. The mass-recovery scenario's entire "hand the residue up" branch is unimplemented.

**Fix:** build the live `ParentCell` transport — route child `Notification::Escalated{mask}` and role `deficit` to a parent committee (the Maekawa bridge point is already computed geometrically), with a real re-provisioning action (recruit a capable sibling into the child roster, or authoritatively lower the child's advertised service level) and a **bounded, terminating** escalation contract. This is the keystone R-C1, R-C3, and H-3 all depend on for recovery.

### [CRITICAL] R-C3 — Erasure repair past the `[7,3,4]` bound is silent permanent data loss
*Anchors:* `fanos-runtime/src/overlay.rs:32,1851` (one shard per Fano point); `fanos-code/src/erasure.rs:83` (`K=3`); `fanos-code/src/lrc.rs` (`is_recoverable_fano`/`is_hyperoval_fano`); `overlay.rs:250` (`reconstruct_highest` returns `None` if unrecoverable).

**Trajectory:** mass loss dropping `>3` point-occupants (or exactly a 4-point hyperoval) → the key is unrecoverable → the read returns a miss and the node emits `Escalated`, but content placement is **single-plane** (`design-coordinates.md §4(e)`: "MapToPoint(H(key)) is single-plane full-cell today; the hierarchy needs a cross-cell key-placement rule"), so **there is no parent peel** to reconstruct from. Data is silently, permanently gone; the "honest accounting" is a counter and a log line.

**Fix:** a genuine **hierarchical erasure layer** — cross-cell shard placement (spread a key's shards across sibling cells so a whole-cell loss is still a ≤tolerance loss at the parent) + a parent-driven reconstruction path. Short of that, at minimum a **durable loss ledger** (which keys became unrecoverable, at which epoch) so loss is accounted, not swallowed.

### [HIGH] R-H1 — Membership is first-write-wins keyed by *coordinate*: returning/new identities are locked out; rosters diverge across reshuffle
*Anchors:* `fanos-runtime/src/overlay.rs:2109` (a repeat at an occupied coord is dropped whole), `:2059` (`on_announce` — no epoch check on the announced coord), `:2233` (`on_reseat` removes **only self's** old entry — other members' stale coords are never evicted); `derive_hierarchical_address` descent tie-break is unwired into `on_announce`.

**Trajectory:** (a) a rebooted-identical node reclaiming its point loses to whoever holds it in each peer's view; (b) a new 8th identity on the 7-point base cell collides and is rejected with no descent; (c) after a reshuffle, node B moving onto a point still holding A's stale entry has its announce dropped, so B goes missing from A's roster until A also churns. Under mass reshuffle+churn the roster diverges node-to-node — the `members` map is effectively append-until-self-moves.

**Fix:** key membership by **`NodeId` with an `(epoch, coord)` stamp**; admit the **highest-epoch** announcement (last-writer-wins on epoch, first-writer-wins only within an epoch); evict stale-epoch entries on reseat; wire the deterministic descent policy (min-id tie-break) into `on_announce` so base-cell collisions resolve instead of silently locking out.

### [HIGH] R-H2 — Self-organizing re-roling is not live; even the library diverges under churn (split-brain of function)
*Anchors:* `fanos-node/src/role_loop.rs` (`spawn_self_organization` is **never called by `Node::start`**); `fanos-node/src/node.rs:322` (static `config.roles` via `Command::Join`); `fanos-core/src/roles.rs:373` (`cell_setpoint` sums `node_loads`), `:572` (`assign` is deterministic **only** given identical members/epoch/beacon/demand), `:453` (`Reputation.observe` halves score on a "did-not-perform" observation).

**Trajectory:** (a) in production, roles never re-assign under churn — a cell that loses all its exits/storage nodes does not promote survivors; (b) if the loop *were* wired, `members`/`node_loads` come from an eventually-consistent store, so mid-churn nodes hold different rosters/loads → different `cell_setpoint` → different `demand` → different `assign` — two honest nodes deterministically disagree on who holds which role; (c) a node knocked offline by the mass event while holding a role is scored non-performing and decayed toward `REP_FLOOR` (1/8) — **punished for an outage that was not its fault.**

**Fix:** wire `spawn_self_organization` into `Node::start` (this is also HOLARCH finding §4-H3 — the self-org brain is disconnected from the hands); make the setpoint/roster inputs **epoch-snapshotted and quorum-agreed** (assign off a committed membership snapshot per epoch, not the live mutable store) so the determinism precondition actually holds under churn; gate reputation decay on **reachability-corroborated** non-performance (a corroborated-down node is excused, not slashed).

### [HIGH] R-H3 — Reintegration budget is zero for near-healthy cells: deep repair is structurally forbidden, forcing (unwired) escalation
*Anchors:* `fanos-diakrisis/src/healing.rs:39` (`max_reroute_depth = ⌊log₉ Φ⌋`), `:19` (Φ→Φ/9 per coarse hop); `fanos-diakrisis/src/regeneration.rs:64` (`recovery_time = 1/Δ`, → ∞ as the gap closes).

**Trajectory:** a healthy cell sits at `Φ∈(1,2]`, so `max_reroute_depth(Φ<9)=0` — it cannot afford **even one** coarse cross-segment hop without dropping below `Φ=1`. Mass recovery needing deep reroutes (large `d`, whole segments gone) is therefore budget-forbidden and must escalate — but escalation is R-C2 (unwired). So deep-repair scenarios cannot reintegrate above `Φ=1` from inside, and the outside help does not run: a stuck-fragmented cell. (The containment theorem is working exactly as designed; combined with R-C2 it produces the stall.)

**Fix:** primarily R-C2 (make escalation real so the `⌊log₉Φ⌋` floor hands off correctly); secondarily, expose the depth-0 condition as an explicit "must escalate for any cross-segment repair" signal rather than an implicit reroute that silently no-ops.

### [MEDIUM] R-M1 — Quarantine keyed by coordinate not identity (C5 residual)
*Anchors:* `overlay.rs:919` (`quarantine` by `Triple`), `:587` (`is_quarantined` by `Triple`), `:121` (`QUARANTINE_TTL = 60s`). **The prior audit's C5 permanence is FIXED** (`:592` re-admits after the TTL, pinned by `quarantine_is_bounded_and_re_admits_a_member_after_the_ttl` `:3483`). Residual: coordinates reshuffle every epoch, so a quarantine tag on epoch-N's coordinate is meaningless at N+1 — a Byzantine identity sheds it by the epoch turning, and an innocent identity reshuffling onto that point *inherits* it. Diagnosis remains **local-only** (each node quarantines independently), so under chaos different nodes drop different members → inconsistent frame-acceptance. **Fix:** key quarantine by `NodeId` (follow the identity across reshuffle) and make the distrust verdict cell-corroborated (the polar cross-attestation already gathers the evidence).

### [MEDIUM] R-M2 — Bootstrap under mass failure: static seed list + genesis fallback → epoch split-brain
*Anchors:* `node.rs:198` (static bootstrap seeds), `fanos-keygen/src/beacon.rs:209` (`BeaconReq` only answered by a *synced* peer). If the configured seeds are among the dead, a recovering/new node has no discovery; if it reaches a live-but-stalled cell it cannot advance past genesis. **Fix:** a self-healing seed/rendezvous (the DVRF rendezvous beacon already exists) plus the R-C1 safe-stall join semantics.

### Simulator cannot model this scenario today — see §7 (S-P0.0). This is itself a required improvement.

---

## §3. End-to-end anonymity (`.fanos` + clearnet) — PRIORITY

**Headline:** the anonymous `.fanos` datapath is now genuinely live over real QUIC (`fanos-node/tests/anonymous_quic.rs:101,232` — forward + full request/response), a real advance over the prior audit's "sim-only (A5/#54)". The threshold-onion crypto is genuine (KEM-sealed Shamir shares, below-`t` zero-knowledge, forged/out-of-range shares neither block nor kill an honest peel). **But the anonymity *properties* the spec sells on top of that datapath are largely inert in the shipping node.** The meta-pattern again.

### [CRITICAL] S1-C1 — `--profile anonymous` does NOT anonymize clearnet/exit traffic
*Anchors:* `fanos-node/src/diaulos.rs:414-433` (`FanosDialer::dial` handles a non-`.fanos` target in an early branch → `exit::dial_exit` → `dial_service`, the **Direct** by-coordinate transport `:104-112,424`, **never consulting `self.profile`**); `exit.rs:97-108` (exit demuxes clients by `Notification::Delivered{from}` = the client's real overlay coordinate); banner at `bin/fanos.rs:248-262`.

**Attack:** a user runs `fanos proxy --profile anonymous` to browse the web anonymously; the CLI prints `Profile: anonymous` and `Clearnet: via exit x:y:z`, implying the clearnet is anonymized. It is not — every clearnet dial is a Direct DIAULOS session addressed to the exit by coordinate, so the exit (a Tor-exit-equivalent, often adversarial) and any relay on the path learn the client's coordinate for **every** clearnet site, and because the coordinate is a stable pseudonym this is durable, cross-session linkage. This silently defeats one of the two headline use-cases.

**Fix:** route clearnet through the anonymous rendezvous to the exit's service key (the exit already advertises one, `exit.rs:280-317`) exactly like a `.fanos` service; until then, `--profile anonymous` must **refuse** clearnet targets rather than silently downgrade, and the banner must not claim anonymity for the exit path.

### [HIGH] S1-H1 — The shipping mixnet runs with cover traffic AND Poisson mixing OFF: no GPA (T2) defense
*Anchors:* `fanos-node/src/node.rs:263-268` builds `ThresholdRouter::new(...)` with **neither** `.with_cover(...)` **nor** `.with_mixing(...)` — the only setters for `cover_interval`/`mean_delay` (`threshold_router.rs:184-197`), called **only in aphantos/sim tests**, never on any shipping path. `NodeConfig` has no cover/mixing knob. With `mean_delay=0` every hop forwards immediately (`:286`) and `cover_interval=0` makes `StartHeartbeat` a no-op (`:221`). A global passive adversary — the T2 threat the Full profile claims to defend "strong (cover+mixing)" (spec §8.2, §5.5) — sees real timing and volume with no cover and no reordering, and performs standard end-to-end correlation. **E1/E2/E6 "RESOLVED (#61)" is true for the *engine*, not the *shipping node*.** **Fix:** enable cover+mixing on the deployed `CellNode` router (a `NodeConfig` λ/μ dial per §5.5), on by default for Full; add an integration test asserting a running cell emits constant-rate indistinguishable cells.

### [HIGH] S1-H2 — The distributed beacon is unreachable from the shipping binary → epoch never advances → E4 forward-secrecy and E5 rotation are both inert
*Anchors:* `fanos-node/src/config.rs:392` (`NodeConfig::beacon` defaults `None`), `:410-411` (`from_config_str` has no key — "provisioned out-of-band"); `bin/fanos.rs` has no `--beacon-share`/anchor flag; `node.rs:310-314` (`epoch_driver`/`mix_publisher` gated off when `beacon=None`). Consequences (all CONFIRMED): the onion ratchet never advances (`threshold_router.rs:562` never invoked) → a relay uses one static onion key forever → **a later relay compromise decrypts every onion ever routed through it** (the exact threat E4/`OnionKeyRatchet` was built to stop); meeting lines and coordinates never rotate (fixed SEED) → long-term rendezvous surveillance and path targeting become possible; PROTEUS per-epoch shape rotation (§13.4) never fires. The engines are real and proven in `epoch_clock.rs` (which provisions `BeaconParams` programmatically) — a **library** embedder can set `config.beacon`, the **CLI** cannot. **Fix:** expose beacon genesis provisioning through the CLI/config (anchor share + group-commitment file) and a genesis tool; make `fanos node` advance epochs.

### [HIGH] S1-H3 — The session cookie is a cleartext cross-correlator, and the reply-relay learns the client's real coordinate
*Anchors:* `fanos-node/src/rendezvous.rs:111-118` (client sends `RdvRegister` **directly from its own coordinate** to the reply relay), `rendezvous_relay.rs:122` (relay records `cookie → client_coordinate`); the **same 16-byte cookie** is delivered in cleartext in the `Request` at the service's meeting-line combiner (`fanos-rendezvous/src/transport.rs:100-116,149`) and prefixes every reply (`:173`); the `Request` also carries the full `reply_circuit`, so the service learns the reply-relay's coordinate.

**Attack:** (a) a malicious hidden service reads `reply_circuit` → identifies the exact relay holding the client's coordinate → colludes with/compromises that one cell node → learns the client (breaks §12.4 "neither side learns the other's coordinate"; very feasible on a 7-node cell). (b) A GPA (undefended per S1-H1) links `client_coord ↔ cookie ↔ service` with **no compromise at all**, because the `RdvRegister` is an un-onion-wrapped overlay send from the client's real coordinate. **Fix:** the client must reach its reply rendezvous **through an onion circuit** (never a raw `Emit` from its own coordinate), and the cookie must not be a single value visible in cleartext at both ends — use independent, per-direction, unlinkable tags.

### MEDIUM/LOW (anonymity)
- **S1-M1** — holonomy path-authenticator (§5.4/§5.7) is **absent on the shipping Full/threshold path** (`verify_holonomy`/`circuit_holonomy` only in `sealed.rs:180,252`, the sim-only Lite `NyxNode`; `ThresholdRouter`+`fanos-rendezvous` have none). Per-hop AEAD still catches tampering, but the end-to-end path authenticator both endpoints were to verify is missing. (Same finding as robustness "holonomy still open".) **Fix:** carry+verify `Hol` on the threshold path, or scope §5.4 to the Lite engine in the spec.
- **S1-M2** — anonymous proxy defaults to a predictable genesis beacon/epoch 0 with no live sync (`bin/fanos.rs:188-194`; `Node` exposes no beacon/epoch accessor) → the meeting line is static and computable, defeating E5's "unpredictable in advance" in deployment; once S1-H2 is fixed, dials fail if relays rotate past epoch 0.
- **S1-M3** [LIKELY] — mix-key store slots are unauthenticated (`mixdir.rs:16-19,50-59`, self-flagged "not self-certifying") → an attacker overwrites honest members' slots with garbage keys, steering path selection toward the attacker's relays and undermining the random-placement assumption `P_hop`/`P_link` rests on. **Fix:** sign `(coord, epoch, onion_pub)`, reject foreign writes.
- **S1-M4** — the shipping node is Fano `F2` (`q=2`): 7-node cell, 3-member lines, 2-of-3 threshold → per-hop anonymity set ≤3, only 3 of 7 points are combiners. Combined with S1-H1/H2 a 1–2-node adversary in the cell likely sits on both the entry and the meeting/reply combiner. The spec's `P_link` tables assume `q+1 ∈ [8,32]`, not 3. **Fix:** document that base-cell anonymity is weak; require hierarchy/larger `q` (or a minimum live-relay count well above threshold) before advertising Full-profile guarantees.
- **S1-M5** — censored bootstrap (PROTEUS moving-target bridges, §13.6) is not wired (`fanos-proteus::bridge` referenced nowhere in node/quic) → a cold-start user under censorship cannot get in. (PROTEUS frame-shaping and morph auto-fallback *are* wired and enable-able.)
- **S1-M6** — threshold-onion `ct_len` is cleartext (`threshold.rs:79-93`) → an on-path relay reads the remaining layer count → learns its path position (size is constant 20480B, but the per-layer length is plaintext; `sealed.rs` AEAD-encrypts it). **Fix:** flat-header Sphinx-style length hiding.
- **S1-L1** onion size 20480B ≠ spec §5.7's 8192B (constant, so not an anonymity bug — conformance). **S1-L2** PROTEUS epoch rotation inert without the beacon. **S1-L3** the transparent-share `fanos_nyx::sheaf`/`tessera` onions remain `pub` re-exported alongside the real KEM-sealed module (integrator footgun).

**Verified SOUND (do-not-regress):** threshold-onion crypto; the live anonymous `.fanos` path over QUIC; fresh unlinkable per-dial routes; **no client DNS leak** (`.fanos` answered in-network, exit does remote resolution → with `socks5h` the client never resolves clearnet DNS); E3 descriptor nonce (SIV salt bound to plaintext); the onion FS + cover/mixing engines are *correct* (the defect is that they are not enabled); DIAULOS E2E encryption; PROTEUS obfuscation + auto-fallback.

---

## §4. HOLARCH holonic coherence + cross-level composition

### [CRITICAL-ARCH] S5-C1 — the Γ-viability release gate is UNBUILT while gated tiers ship
*Evidence (exhaustive):* no `architecture/` directory (`find` = 0); **zero Python in the repo** (`fanos_verify.py`, the model §9.6 cites, lives only in the *other* uhm-theory repo); CI (`.github/workflows/ci.yml`) computes no architectural P/R/Φ/D; no Rust computes an architecture-Γ from declared budgets (grep `holarch`/`viable_window`/`sigma_panel`/`AspectBudget` → two *comment* mentions only); **V4 differentiation `D=1+6·Coh_E` is computed nowhere**; the **σ-panel exists nowhere**; the platform's own composed verdict (`platform.md:49`: `P≈0.36, R≥1/3, Φ≈1.6, D≥2.3`) was **never reproduced** by any code (`holarch_lab.py` has W1/W2/W3 but no FANOS-platform E∧L instance, and is not run by this CI). Honestly tracked open at `docs/tasks.md:65`.

`platform.md §1.3` declares the four invariants "the platform's **architectural release gates** — computed, not asserted," and §9.6 makes the calculator the *throughout* roadmap item — yet TAXIS, DROMOS, OBOLOS, and THESAUROS have materially shipped through no such gate. The central epistemic differentiator the platform claims over conventional architecture — that its viability window is a CI-checked number — is currently prose. This is exactly the failure mode HOLARCH itself names ("конституция, которую нечем вычислить, — совет, а не закон").

**Fix (high-leverage, self-contained):** build the calculator as specified — a small `architecture/` companion (Python matching `holarch_lab.py`'s flow-constructor, or a `fanos-cli` subcommand) holding the declared per-tier `holarch.v1` budget vectors, computing P/R/Φ/D + the σ-panel + the four Ω4 ablations, added as a CI step; recompute §1.2's numbers and replace "≈" with the computed values. This single act closes the CRITICAL-ARCH finding, gives Ω2/Ω9 (below) a place to be machine-checked, and converts the platform's own definition of done into a gate.

### [HIGH-ARCH] the meta-holon's cross-block is ~1/3 wired (composition ahead of the wiring)
- **S5-H1 — E→L "the mempool is a mixnet" has no wire.** The anti-MEV encrypted mempool is real and strong (`keyper.rs`), but nothing propagates a transaction through APHANTOS to reach it: `ConsensusMsg = {Propose,Vote,Reveal,ExecVote}` (`consensus.rs:202-211`) — **there is no transaction-submission wire variant at all**; the only ingress is the in-process `TaxisHandle::submit` mpsc (`taxis_driver.rs:102-110`). `platform.md:45` states in present tense that transactions "propagate through the APHANTOS mixnet" — prose. Per T-77 the integration gain lives *entirely* in this cross-block. **Fix:** add a client tx-submission App-frame and route it over the existing mixnet path (`Command::Emit`/CellNode from #54).
- **S5-H2 — L→O "the blockchain pays the mixnet's foundation" is directionally reversed.** Sybil admission is PoW-only (`admission.rs:9-13`, stake is an unimplemented trait slot); the beacon is produced by the standalone DVRF and TAXIS *consumes* it (`TaxisParams.seed` pinned at construction, rotation unwired) — today **O feeds L, not L→O**. What *is* real: ledger-owned naming and the consensus-fed storage-audit beacon. **Fix:** implement the stake `AdmissionPolicy` against the ledger, and either wire consensus into beacon generation/rotation or amend §1.2 to the actual direction.
- **S5-H3 — self-organization computes but does not actuate** (= R-H2; the highest cross-cutting overlap). The Lyapunov controller and the live directory loop are wired, but `spawn_self_organization`/`assigned` have **zero consumers** outside `role_loop.rs`, and `Node::start` actuates from static `config.roles`. "The network assigns function" is true of a computation the node ignores. **Fix:** subscribe the node to `assigned` and start/stop relay/store/service/exit engines from it.
- **S5-H4 — Ω2 "every tier names all seven aspects" is fulfilled by exactly one tier of six.** Only THESAUROS has the full seven-aspect budget table (`design-storage.md:38-66`); TAXIS/DROMOS/OBOLOS/ONOMA/ANGELOS/HERMES carry only dominant-aspect signatures, and `design-taxis.md`/`design-platform.md` have zero aspect mentions. Nothing records or enforces the gate. **Fix:** add the seven-row budget table to each tier's design section (it also feeds the calculator its vectors).

### MEDIUM/LOW (coherence)
- **S5-M1** — Ω9 CALM classes are absent everywhere (the only "CALM" in the repo is the promise itself); the engineering facts exist (TAXIS coordinated, L4 LWW monotonic) but are undeclared. **Fix:** one line per LU/consistency contract.
- **S5-M2** — the depth-3 subjecthood ceiling is respected by construction but enforced nowhere (no `SAD_MAX` constant; `geometry MAX_DEPTH=8` is *addressing* depth, legitimately distinct). **Fix:** a named `SUBJECT_DEPTH_MAX = 3` in `fanos-core` with the T-142 citation, consulted by the taxis hierarchy/crosscell layer.
- **S5-M3** — internal contradiction on staking: `platform.md:46` grounds the platform on "stake (the LO channel read literally)" and plans HERMES bonding/slashing, while `platform.md:243`/`design-storage.md:196-199` declare "FANOS forbids capital staking (it deanonymizes)". The reconciliation (validators are public infra; storage/relay roles stay anonymous) is plausible but unstated. **Fix:** one delimiting paragraph in §1.2.
- **S5-M4** [MED→LOW] — the storage-audit beacon doc says "PQ-VRF beacon" but the wiring feeds the parent block hash (`consensus.rs:878-880`), giving the previous proposer bounded grinding over the next challenge; reconcile the doc / derive from the epoch PQ-VRF beacon + height.
- **S5-L1** stale refs (`platform.md:49` "§8" should be §9; `fanos_verify.py` cited but absent from this repo — the real verifier is `fanos-cli`). **S5-L2** ANGELOS is a library, not yet a node tenant (tracked `tasks.md:62-63`).

**Verified SOUND:** DIAKRISIS invariant math is **exact to spec and CI-verified** (`coherence.rs`: `P=frob/N²`, `Φ=(frob−N)/N`, `R=1/(N·P)`, `r*=1/√(N−1)`, `P_crit=2/N`, `R_TH=1/3`, `PHI_TH=1`, equicorrelated forms — all match §2.7, re-proved by `fanos-cli` on every CI run + miri + wasm; D6 quarantine cross-validated over 800 matrices). L↔E is a real, live composition (obolos → `HybridLedger impl StateMachine` → live TAXIS over QUIC in `dromos_quic.rs`). THESAUROS is the Ω2/Ω9 exemplar. Depth-2 recursion is done right (parent-attests-child + parent-observes-child + live checkpoints; HERMES correctly framed as federation beyond it). **The network cell layer is genuinely holonic in code; the platform layer is holonic in prose and conventional in code.**

---

## §5. Crown-jewel subsystem findings (first-ever audit coverage)

### 5.1 OBOLOS — the private currency (2 CRITICAL, in the pinned *relation* → a future ZK backend inherits them)

- **[CRITICAL] O-C1 — modular-wraparound inflation.** `commit.rs:253-262` (`verify_balance`) is a mod-`q` identity (`Q=2⁶¹−1`, `MAX_VALUE=2⁵¹`, ratio 1023); the range guard `tx.rs:144` is per-output and outputs-only (inputs never range-checked), and there is **no bound on the number/sum of outputs** (`state.rs:133` only caps at 2³² outputs). **Confirmed numerically:** input `v=1000`; 1025 in-range outputs summing to `Q+1000 ≡ 1000 (mod Q)` → balance passes, each output `< MAX_VALUE` → range passes → **1025 notes ≈2⁶¹ minted from a 1000-value input (×2.3e15)**. Reachable end-to-end via DROMOS `TAG_SHIELDED` (`hybrid.rs:287-290`). The existing test `scenarios.rs:117` only exercises a single out-of-range output. **Fix:** hard-cap `#inputs+#outputs ≤ ⌊Q/MAX_VALUE⌋`, range-check inputs, bound `Σv_out < q` — the pinned relation must carry the bounded-sum constraint the ZK circuit will enforce. (Contributing: `state.rs:112-116` mint + `hybrid.rs:140-152` shield append notes with no `value<MAX_VALUE` check; `public_value` `tx.rs:64` unbounded before the mod-`q` balance.)
- **[CRITICAL] O-C2 — untraceability defeated.** `tx.rs:53-55` publishes `pub input_values: Vec<Commitment>` as cleartext on the public `ShieldedTx`; `build.rs:45` sets them to the note's own `value_commitment` **with its original randomness**, and `tx.rs:137` requires equality — but that same `com(v; value_r)` was already public in the note's creating `OutputNote.value_commitment` (`tx.rs:39`), paired there with its tree leaf. **Attack (public chain data only):** build the map `value_commitment → (note_commitment, leaf)`; any spend's `input_values[i]` is a byte-for-byte match → the exact spent note and leaf are identified → the whole-pool anonymity set collapses to one note, for **every** note created via a shielded output. Persists under the real ZK backend (the leak is in the public tx body, not the swappable proof). **Fix (Zcash-Orchard pattern):** reveal a freshly re-randomized `cv_in = com(v; r_fresh)` per spend and prove in `π` it commits to the same `v`; never republish the note's creation commitment at spend time.
- **[HIGH] O-H1 — the shielded fee is never collected + pool invariant drift** (`hybrid.rs:159-170`): the fee reduces `Σv_out` but is credited to no one, breaking §4.3's "public fee so validators can be paid" and the claimed `POOL_SINK == Σ unspent note values` invariant. Not fund loss (stranded), but incentive + invariant. **Fix:** debit `POOL_SINK` by the fee, credit the proposer/treasury.
- **[HIGH] O-H2 — note-cipher key AND nonce both from the KEM session → reuse is catastrophic + linkable** (`note_cipher.rs:60-67,94-100`): reusing `rng_seed` to the same recipient reuses the ChaCha20-Poly1305 nonce (keystream + Poly1305 forgery) and produces identical `kem_ct` (linkable). **Fix:** `nonce = H(session ‖ kem_ct)` or a counter; generate coins internally from a CSPRNG.
- **MEDIUM:** O-M1 nullifier `nf=H(nsk‖cm)` diverges from spec's `PRF(nsk, position)` (sound, but duplicate-`cm` notes share a nullifier → spend-lock); O-M2 anchor set is insert-only unbounded (`state.rs:49,65,116,146` — no rolling window); O-M3 collapsed key hierarchy (one `nsk` = owner + nullifier key; `TransparentProof` reveals it → no viewing-key-only capability, so §4.5 disclosure is impossible without full spend authority); O-M4 stealth address unimplemented (`note_cipher.rs:34-48` static `Address.owner`; unlinkability is delivered by the hiding commitment, not the advertised one-time keys — reconcile the wording).
- **Honesty note:** the `ShieldedProof` seam is genuinely isolated (a real trait, only `TransparentProof` does real checks, **no accept-all/`todo!`/`return true` stub** — grep-confirmed), and the lattice params are honestly tagged `[P]/[H]`. But the overclaim at `lib.rs:19-31`/`tx.rs:16-21` ("the accounting is fully verified now"; "`TransparentProof` proves exactly what the ZK backend must") is **false given O-C1/O-C2** — the pinned relation is inflatable and traceable. **Retract that claim until O-C1/O-C2 are fixed.**
- **SOUND:** commitment tree, nullifier double-spend guard (atomic), lattice commitment (genuinely additively-homomorphic + binding), `state_root` consistency, shield/unshield conservation (gated + atomic + replay-protected), note delivery (fresh ML-KEM, `scan` re-verifies), codecs.

### 5.2 TAXIS / DROMOS — consensus + execution (ordering safety SOUND; execution-layer HIGHs)

*No confirmed CRITICAL: ordering agreement is sound and Monte-Carlo-verified (no two conflicting blocks finalizable). The findings are in the execution layer TAXIS deliberately decouples from ordering.*

- **[HIGH, borderline CRITICAL] T-H1 — reveal-driven execution-state divergence (nondeterminism).** `consensus.rs:835-888` (`try_execute`): the reveal window drops an undecryptable tx based on `self.reveals` = shares **this validator locally collected** (per-validator, async). The window boundary is deterministic, but the *share set at that boundary is not agreed*. **Scenario:** on a Fano keyper line (3 members, `t=2`, `f=2`), 2 Byzantine members reveal valid signed shares only to validators {0,1,2} → {0,1,2} execute tx X, {3,4,5,6} drop it after the window → **honest validators hold permanently different state roots** (a late share never re-executes; the block already left `exec_queue`). Also reachable with honest keypers under a slow/partitioned link delaying a share past 4 heights. The comment at `:862` claiming "the drop is identical on every validator" is **false**. The `ExecCertificate` *detects* it (no `Q`-quorum root forms) so it is not a silent cross-cell theft, but honest nodes fork intra-cell state and checkpoint liveness is lost. **Uncovered by tests** (the sim broadcasts every reveal; Byzantine nodes only equivocate on prepare votes; no test asserts state-root equality across validators). **Fix:** gate execution on *agreed* data — the on-chain decryption-key commitment (Shutter/Ferveo, already in `design-taxis.md §5.1`) or a `Q`-quorum "undecryptable" certificate.
- **[HIGH, LIKELY] T-H2 — the round lock has no unlock / re-propose rule → partial-lock liveness wedge.** `consensus.rs:547-551` refuses any block ≠ `locked_block`; `:494-510` always assembles a *fresh* block, never re-proposing the locked value; `:945` only bumps the round on timeout. The code implements the *refuse-conflicting* half of Tendermint but not the *unlock-on-newer-PC / re-propose-locked-value* half. A partial lock (3 validators lock B, `<Q` commits) + fresh proposals forever → the height wedges permanently (safety preserved, liveness not). **Fix:** implement `lockedValue`/`validRound` — the proposer re-proposes its locked value with a PC justification; validators unlock when shown a PC for a round ≥ their lockedRound.
- **[HIGH, disclosed] T-H3 — a within-`f` keyper majority can transiently censor a targeted tx** (`consensus.rs:835-888` + `incentive.rs:247-266`): 2-of-3 keyper line, 2 Byzantine withhold reveals → tx dropped after the reveal window; only *permanent* censorship is proven impossible; per-epoch, per-tx censorship is operational and unpriced, with no force-inclusion/inclusion-list. Compounds with T-H1.
- **[HIGH, disclosed [P]] T-H4 — DA dispersal is not wired.** `taxis_driver.rs:228` derives the DA shards from the proposer's own block, so `reconstruct_payload` always sees the full set → the whole payload rides in the proposal, real withholding is never modeled, and erasure-coded dispersal gives no scalability. **Fix:** ship headers + sampled shards and verify a signed DA-attestation quorum in-engine.
- **[HIGH, disclosed] T-H5 — slashing is detected but never applied; rewards are non-canonical and never minted.** `taxis_driver.rs:268-273` maps `Output::Slash`/`Reward` to events that **never touch ledger state**; `consensus.rs:717-730` computes the reward split from the *local* commit view (non-canonical, would fork the root if folded). The Nash equilibrium's `S>0`/`R` conditions are provable-but-not-live. **Fix:** apply slashing/rewards to a real balance canonically.
- **MEDIUM:** T-M1 cross-cell is one-way emission-proof, not two-phase atomic, and not wired into any shipped `StateMachine` (replay-dedup by `(source,nonce)` is delegated and implemented nowhere → a naive wiring double-applies); T-M2 live parent attestation never calls `conflict()` → silently anchors the first-seen child fork; T-M3 `pending_finalize` body admission is gated by the current-round leader → a CC-without-body can re-wedge after a timeout; T-M4 cross-cell verifier trust-root is assumed, not established for peer cells.
- **LOW:** duplicate tx not rejected structurally; `open_from_subset` combinatorial cap at 4096; well-sealed-but-undecryptable tx wastes a block slot.
- **Not built (honest `[P]`, not flaws):** intra-cell parallel execution / deterministic scheduler is **absent** (no rayon/threads/access-lists; execution is strictly sequential → trivially deterministic → *no* parallel-nondeterminism because there is no parallelism); dispersed DA datapath; two-phase cross-cell; operational slashing; mid-chain keyper/committee rotation.
- **SOUND:** BFT ordering safety (`f=⌊(n−1)/3⌋`, `Q=⌈(n+f+1)/2⌉`, exhaustive to `q=1000`; certificate/vote validation; randomized async Monte-Carlo no-fork); anti-MEV blind ordering; executed-state checkpoint; cross-cell receipt primitive; `state_root` determinism (all sub-ledgers sorted-BTreeMap under domain-separated BLAKE3); VOPRF fee-credit binding.

### 5.3 ANGELOS / THESAUROS — messenger + storage market (3 CRITICAL)

- **[CRITICAL] AT-C1 — storage escrow drained by proof-replay within one audit epoch.** `hybrid.rs:200-219` (`prove_deal`) has no "already-proven-at-this-beacon/epoch" guard, the deal epoch advances **per proof submitted** (not per block/time), and the audit response is **order-malleable** (`por::verify` matches indices order-independently while `encode_response` serializes in slice order). So a provider proves once then submits many byte-distinct leaf-order-permuted copies for the same `(deal, beacon)`; the mempool dedups by exact commitment (permuted variants pass), and block `apply` never dedups. **Scenario:** `duration=100`, prove once, submit 99 permuted copies in one block → each `settle_epoch(true)` releases `price/duration` → the **full escrow is drained for a single proof-of-holding**; `close()` refunds 0. Direct consumer fund loss; the pay-per-proof guarantee collapses. **Fix:** bind each proof to the epoch/height (store `last_audited_height` per deal; reject a second settle for the same period) and make the response canonical (ascending indices, `verify` rejecting non-canonical/duplicate ordering).
- **[CRITICAL] AT-C2 — the media plane reuses (key, nonce) across both call directions.** `media.rs:62-67` (`MediaSession::new`) derives `key = H(EPOCH0_LABEL, secret)` with **no role/direction split** and starts `send_seq=0`; both caller and callee build from the *same* `media_secret` (`call.rs:80-95`). Caller frame `seq=0` and callee frame `seq=0` are both `AEAD(K, nonce(0), …)` over different plaintexts → **ChaCha20-Poly1305 nonce reuse** → two-time-pad keystream recovery (XOR of the two live media streams) + Poly1305 forgery. The 1:1 `Session` splits `a2b`/`b2a` correctly; the media session forgot it. (Group/SFU → N-way reuse.) Not caught because every test seals one direction only. **Fix:** per-sender/per-direction keys (mix role/identity/SSRC into the KDF) or partition the nonce space by a sender id in the frame header.
- **[CRITICAL] AT-C3 — group sender-keys have no sender authentication.** `group.rs:41-101`: a member's chain is `H("group-sender", group_key ‖ member_id)`; every member knows `group_key` and every `member_id`, so **every member can derive every other member's message keys**, and `recv` "authenticates" only by decrypting under a key the receiver itself can compute. There is **no per-sender signature** — any member can seal a message under another member's chain and attribute it to them; `Message.sender` is cryptographically unbacked inside a group. Below the Signal Sender-Keys baseline the spec invokes; severe for a "Discord-class" platform (moderation, roles, accountability). **Fix:** a per-sender signature key; sign each post; distribute only the public half.
- **[HIGH] AT-H1 — PoR is not provider-bound** (`storage.rs:58-64` `Prove` carries no signature/prover identity; `hybrid.rs:200-219` pays a fixed `params.provider`): the leaves are public ciphertext bytes any replica/cache can produce (the `[7,3,4]` code replicates them), so the designated provider can delete its copy and still be paid whenever any other party submits a valid proof. **Fix:** require the `Prove` tx to be signed by `params.provider`, bind the proof to that identity.
- **[HIGH] AT-H2 — reputation decay + timeout/miss path are not wired** (grep `observe`/`Reputation`/`Settlement::Miss` in dromos = nothing): only pay-per-proof exists; `settle_epoch(false)` is never called, there is no audit deadline, a non-proving deal sits `Active` forever, and the consumer refund only happens on a *manual* `Close`. Two of the three forces the no-staking incentive model depends on are absent from the running system. **Fix:** drive a per-epoch audit deadline off the height clock; on a miss, call the miss path + `Reputation::observe(false)` + auto-refund.
- **[HIGH] AT-H3 — media plane has no replay protection** (`media.rs:103-113` `open_frame(&self)` is stateless): any captured frame re-opens while its epoch is current; SRTP mandates a replay window. **Fix:** a sliding replay window per epoch.
- **MEDIUM:** AT-M1 no key zeroization anywhere in ANGELOS (no `zeroize` dep, no `Drop`/`Zeroize`); AT-M2 the group session drops all out-of-order messages while channel text rides the reordering Full mixnet (permanent loss); AT-M3 per-chunk PoR soundness is capped at the leaf count (`0.9^64 ≈ 9.7` bits, not the advertised λ=20/30/40 — the market treats one chunk pass as the epoch's proof); AT-M4 `close_deal` accepts any consumer signature unbound to `(deal_id, close, height)` → replay a historical `SignedTransfer` to force-close deals early (griefing); AT-M5 session/ratchet randomness is caller-seeded (`SeedRng` satisfies the `CryptoRng` bound) → a weak/reused seed silently breaks FS+PCS.
- **LOW:** media cleartext `epoch‖seq` flow-fingerprint; `unwrap_or_default` masks AEAD-seal failure; unbounded Merkle-path length; pre-auth skip-key derivation (bounded ~µs); `audit_beacon` inits to zero (latent).
- **SOUND:** the **1:1 double ratchet reaches Signal parity** — FS *and* PCS are both real (traced: one-way BLAKE3 chains overwrite the prior key; after compromise the peer's fresh ratchet key + ratchet-on-top heals the root; replays/tampers refused; skipped-key storage bounded); the 1:1 session direction split; PoR challenge unpredictability + Merkle verification + the exact `k` formula; edge encryption (no plaintext to the store); deal accounting arithmetic (conserved); canonical KAT-pinned codecs. **Baselines:** 1:1 = Signal parity minus zeroization + enforced-CSPRNG; groups behind Signal (no sender auth, no reordering); media below SRTP (nonce reuse, no replay); storage crypto Storj/Sia-class but the market wiring behind all three.

### 5.4 Systemic robustness — prior cluster fixed; bug-class migrated to new wiring

**Prior-audit robustness cluster (re-verified against current code): C1, C2, C3/F1, F2, F3, F4 — all FIXED** (largely via the `fanos-stream` extraction and the per-peer driver rework: `REQUEST_TIMEOUT=10s` + waiter eviction; bounded `INPUT_CAP=1024` with back-pressure + per-peer workers + `MAX_INBOUND_CONNECTIONS=512`/`_PER_SOURCE=32`; admission anchored on `delivered`; `MAX_CONCURRENT_STREAMS=256` + retire/reset; `VecDeque`+`base` reclaim; RFC-6298 RTO). **C5 (quarantine expiry), C6 (Decouple made real), #100 (version/capability negotiation), #101 (wire-KAT harness loads+verifies `wire.json`), #103 (PoW admission) — all FIXED.** **C7 (telemetry DP) — PARTIAL:** `dp.rs` machinery exists and is tested, but `.privatize(` has **no live caller** — the observer still emits the exact syndrome + scalars un-privatized. **Holonomy verification — STILL OPEN** (function exists, live peel path never recomputes/compares, `HolonomyFail` never produced).

**New findings (bug-class = unbounded attacker-keyed map + missing validation, migrated to the newest live wiring):**
- **[HIGH] B1 — unauthenticated, uncapped `pending_reveals` in TAXIS consensus → single-peer remote OOM.** `consensus.rs:777-784` (`on_reveal`): the `else` branch buffers a raw `RevealMsg` whose `commit` is not a known finalized tx **without `validate_and_record`, so the signature is never verified**, keyed by the attacker-chosen 32-byte `r.commit`; `drain_pending_reveals` only evicts commits that become finalized txs → garbage is never evicted. A single connected peer streams reveals with distinct random commits (each carrying a `share`+`sig` Vec) and grows the map without bound. **Fix:** verify `r.verify(verifiers[r.member])` eagerly before buffering (the verifier is already available) + bound `pending_reveals` with LRU/TTL.
- **[MEDIUM] B2 — unbounded `RendezvousRelay.registrations` on the live anonymous-relay role** (`rendezvous_relay.rs:43,122`, live in `mix_relay.rs:48` + `cell_node.rs:75`): `registrations.insert(cookie, from)` per inbound `RdvRegister`, attacker-chosen 16-byte cookie, no cap/TTL. The live successor to the prior A4. **Fix:** LRU+TTL like `MAX_SESSIONS`.
- **[MEDIUM, LIKELY] B3 — unauthenticated block proposals inflate `proposals` within a height** (`consensus.rs:513-540`): a block is not authenticated by a leader signature (only a `proposer:u8` index), so any peer can craft a structurally-valid block claiming `proposer = elected-leader-index` and grow the map with distinct forged payloads (bounded per height; a within-height memory-amplification DoS, not a safety break). **Fix:** require + verify a leader signature over the block hash.
- **LOW:** TAXIS mempool has no size cap (but is fed only from the local bounded mpsc, not the network); `exec_votes` keyed by height is never pruned (verifies the signature first → permissioned/slashable). **Clean:** obolos/dromos/thesauros/angelos have no `unwrap`/`expect`/`panic`/OOB-indexing in non-test code; all new crates `forbid(unsafe_code)`.

---

## §6. Painful-but-correct architectural improvements

*Per the directive "everything that can be improved must be improved, especially painful architectural moments." These are the structural changes the findings converge on — larger than a single fix, worth doing once, correctly.*

1. **Wire the self-organization loop into `Node::start` and make it churn-safe** (R-H2 / S5-H3). Replace static `config.roles` with the live `assigned` `RoleSet`; snapshot the roster/setpoint per epoch off a committed membership set (not the live mutable store) so `assign` is deterministic under churn; gate reputation on reachability-corroborated non-performance. *This is the single change that most directly serves "flawless self-organization."*
2. **Give the beacon a resharing + re-bootstrap contract, and the epoch clock safe-stall semantics** (R-C1). A one-shot DKG with static shares is a network-wide liveness SPOF; proactive VSS / periodic re-DKG + a below-threshold re-bootstrap + freeze-don't-deadlock is the fundamental fix.
3. **Build the live `ParentCell` escalation transport** (R-C2). Escalation is the documented recovery-of-last-resort across the whole design; it must be a real cross-cell action (recruit/relax), not a log line — with a bounded, terminating contract.
4. **Make placement identity-first, epoch-stamped, collision-resolving** (R-H1, R-M1). Key membership *and* quarantine by `NodeId` with `(epoch, coord)`, admit highest-epoch, evict stale on reseat, and wire the deterministic descent tie-break — so returning and new identities are never silently locked out and quarantine follows the identity across reshuffle.
5. **Hierarchical erasure placement** (R-C3). Cross-cell shard placement + parent-driven reconstruction so a whole-cell loss is recoverable; short of that, a durable loss ledger so loss is accounted.
6. **Close the shielded-relation soundness/privacy holes in the *statement*, not the backend** (O-C1, O-C2). The bounded-sum constraint and per-spend re-randomized value commitments must be part of the pinned relation, so the eventual ZK circuit enforces them.
7. **Build the HOLARCH Γ-calculator gate** (S5-C1). It is the platform's own definition of done, it is self-contained, and it gives Ω2/Ω9 and the depth constant a place to be machine-checked. High leverage, low blast radius.
8. **Enable the anonymity properties in the shipping node** (S1-H1, S1-H2). Cover+mixing on by default for Full; beacon provisioning via CLI so epochs advance (forward secrecy + rotation depend on it). The engines exist — this is a config/wiring surface, not new crypto.
9. **Authenticate-before-buffer, everywhere** (B1, B3, T-H1's share agreement). The recurring remote-DoS/nondeterminism class is "buffer attacker-keyed data before validating"; make eager validation + bounded, evicting maps the standing pattern for every network-fed map.
10. *(Already tracked, endorse:)* the `#73` architecture refactor — split `fanos-runtime`, decompose `OverlayNode`, typed `StorageAddress`, secret-field encapsulation — is the right home for several of the above seams.

---

## §7. Simulator improvement backlog

`fanos-sim` is a **real** deterministic simulator (drives the actual sans-I/O engines, real wire encode/decode round-trips, virtual-time DES, seeded determinism, a genuine coherence observatory + Monte-Carlo layer) — not a test suite masquerading as one. Its self-balancing/homeostasis coverage is a genuine strength. Three gaps, and the user's scenario needs the first two:

- **S-P0.0 (new, top priority) — model mass-destruction + heterogeneous recovery.** Today the sim **cannot express** the user's scenario: `spawn_cell` builds bare overlays (not `OverlayBeaconNode`s), `reshuffle.rs` injects `Reseat` directly (never driving `beacon → BeaconReady → reshuffle`), so you cannot crash an anchor batch and *observe the epoch clock stall* (the R-C1 experiment); `recover` restores the *exact* prior engine, so "returns changed" is inexpressible; and `step` moves reshuffled nodes to unoccupied coordinates, so the R-H1 placement-collision/lockout class *cannot occur*. **Build:** `spawn_beacon_cell::<F>(sim, t, anchors)` + `Sim::tick_epoch()` driving the real `BeaconReady→Reseat` loop; `Sim::recover_as(node, engine)` + `Sim::mass_event({crash, recover_identical, recover_changed, add_fresh, leave_dead})` applied atomically; a **multi-occupant coordinate model** (the hardest lift — it touches the sim's core one-occupant invariant) so lockout/descent is testable; and survival assertions (beacon advances iff ≥`t` anchors survive; survivor rosters converge; a `Put` before the event is `Get`-recoverable iff ≤3 shard-points died; `Escalated` was *acted on*, not merely counted).
- **S-P0.1–P0.5 — adversarial scenarios for the crown jewels** (confirmed: **zero** obolos/dromos/taxis/angelos/thesauros coverage in `fanos-sim`; TAXIS/OBOLOS have strong-but-*siloed* per-crate harnesses, THESAUROS/ANGELOS/DROMOS are thin even locally). In deficit order: **DROMOS determinism under adversarial scheduling** (random conflicting tx set × N permuted schedules → identical state root); **ANGELOS ratchet-under-compromise** (state-exfil at t → assert PCS heals within one KEM step; adversary reorder/drop/replay; GPA metadata non-fingerprint); **THESAUROS cheating-provider** (withhold/forge-PoR/adaptive-to-audit strategy knob × audit-frequency sweep → cheating dominated) — *note this would have caught AT-C1*; **TAXIS-in-sim over a partition** (port `never_fork` onto seeded loss+partition — the split-brain condition T-H1/T-H2 live in); **OBOLOS networked double-spend race** (conflicting spends to different validators under partition → heal → exactly one nullifier wins).
- **S-P1.1 (the enabler) — a `SubsystemEngine` adapter** so a non-`fanos_ports::Engine` state machine can be driven by `Sim`, converting the five fragmented per-crate harnesses into clients of the one platform (shared network model, determinism trace, GPA tape, observatory). Then **S-P1.2** a richer `Transport` trait (per-link/asymmetric latency, bandwidth/queueing, Gilbert-Elliott bursty loss, reorder, clock skew — the file already anticipates it) and **S-P1.3** an active/adaptive network adversary (strategic delay/reorder/selective-drop; a rushing adversary for BFT/DKG).
- **S-P2 (SecOps usability)** — an `Experiment` abstraction (parameter grid → seeded runs → JSON/CSV artifact) + a `fanos-sim` CLI (`--param k=v --seeds N --out file`) generalizing `endpoint_attestation_research.rs`, with an extensible `Metrics` side-channel. This is what turns "what `f` deanonymizes at Full?" from a recompile into a command — and is the foundation for the `fanos evolve` genetic-search harness `coherent-cybernetics.md §6` envisions.
- **S-P3** — extend `network-threat-model.md` with crown-jewel rows (it is stale: F3 is marked ⬜ but `consensus_sim.rs` covers Byzantine agreement); add a PROTEUS DPI/probing sim (G1/G2 are design-only); add a self-org role-loop-under-churn scenario (folds into S-P0.0).

---

## §8. Prioritized remediation roadmap (the dev-agent work queue)

**Tier 0 — security/liveness/funds; do first**
1. **OBOLOS O-C1 (inflation) + O-C2 (untraceability)** — fix the pinned relation (bounded-sum constraint + range-check inputs; per-spend re-randomized value commitments). Retract the "verified now" claim until done.
2. **THESAUROS AT-C1 (escrow drain)** — per-deal epoch/height binding + canonical audit response.
3. **ANGELOS AT-C2 (media nonce reuse) + AT-C3 (group forgery)** — per-direction media keys; per-sender group signatures.
4. **Anonymity S1-C1 (clearnet direct)** — refuse-or-route; fix the banner. **S1-H3 (cookie correlator)** — onion-wrap the reply registration; per-direction tags.
5. **TAXIS T-H1 (execution divergence)** — gate execution on agreed reveal data. **Robustness B1 (pending_reveals OOM)** — validate-before-buffer + bound.

**Tier 1 — self-organization / recovery (the user's priority) + anonymity enablement**
6. **R-C1 beacon resharing + safe-stall; R-C2 live parent escalation; R-C3 hierarchical erasure** (the three recovery cliffs). 
7. **R-H1 identity-first epoch-stamped membership; R-H2 wire + churn-harden self-organization; R-M1 identity-keyed quarantine.**
8. **S1-H1 cover+mixing on in the shipping node; S1-H2 CLI beacon provisioning** (turns forward secrecy + rotation on).
9. **TAXIS T-H2 (round-lock liveness), T-H5 (apply slashing/rewards); O-H1/O-H2, AT-H1/H2/H3.**

**Tier 2 — coherence / architecture**
10. **Build the HOLARCH Γ-calculator gate (S5-C1)**; wire E→L tx submission (S5-H1); implement the stake `AdmissionPolicy` (S5-H2); add the seven-aspect budget tables (S5-H4) + CALM classes (S5-M1) + `SUBJECT_DEPTH_MAX` (S5-M2); reconcile the staking contradiction (S5-M3).
11. **Wire C7 telemetry DP onto the export path; wire holonomy verification (S1-M1) onto the threshold peel path** — the two remaining "built-but-unwired" residuals.
12. **Robustness B2/B3; TAXIS T-M1..M4; the `#73` refactor.**

**Tier 3 — simulator + hardening**
13. **S-P0.0 (mass-failure/recovery scenario modeling)** + **S-P1.1 (SubsystemEngine adapter)** + the crown-jewel adversarial scenarios (S-P0.1–P0.5) — several of which would have caught the Tier-0 findings.
14. **S-P2 experiment-runner CLI + metrics export** (foundation for `fanos evolve`); S-P1.2/1.3 transport + active-adversary fidelity; the anonymity MEDIUMs (S1-M2..M6) and OBOLOS/ANGELOS/THESAUROS MEDIUMs.

---

## §9. What is verified SOUND (do-not-regress)

- **Cryptographic cores:** audited PQ primitives; the hybrid KEM combiner (full transcript); the DIAULOS handshake; the **1:1 double ratchet (FS+PCS both real)**; the threshold-onion (KEM-sealed Shamir, below-`t` zero-knowledge); OBOLOS's commitment tree / nullifier guard / additively-homomorphic lattice commitment; the PoR challenge unpredictability + Merkle verification + exact `k` formula; edge encryption (no plaintext to the store).
- **Consensus:** BFT ordering safety (exhaustive to `q=1000`, randomized async no-fork); anti-MEV blind ordering; the executed-state checkpoint; `state_root` determinism (no HashMap/float/iteration-order nondeterminism reaches any root).
- **Invariant math:** DIAKRISIS Φ/P/R/r*/thresholds exact to spec, CI-verified + miri + wasm.
- **Robustness:** the entire transport/stream DoS cluster (C1/C2/C3/F1/F2/F3/F4) is genuinely closed; version/capability negotiation; the wire-KAT harness; PoW admission; quarantine expiry; a real `Decouple`.
- **Anonymity:** the live anonymous `.fanos` path over real QUIC; fresh unlinkable per-dial routes; no client DNS leak; the SIV descriptor nonce.
- **Determinism:** sans-I/O purity holds; the simulator drives the real engines with trace-strength reproducibility.
- **Honesty:** the status discipline is candid — the ZK proof is `[P]` everywhere, the Γ-gate and ANGELOS composition are tracked open, the `ShieldedProof` seam has no accept-all stub. The gaps this audit sharpens are, overwhelmingly, *unfinished wiring*, not *wrong foundations*.

---

## §10. Appendix — coverage and method

Eight parallel adversarial streams, each reading current code at `file:line`: (1) end-to-end anonymity, (2) OBOLOS, (3) TAXIS/DROMOS, (4) ANGELOS/THESAUROS, (5) HOLARCH coherence, (6) simulator, (7) systemic robustness, (8) mass-failure self-organization. Working notes with the full per-stream detail (every anchor, every fix) are preserved. Findings are tagged CONFIRMED (read and definite) vs LIKELY (inferred). This audit did **not** modify code — it is assessment only, written for the sibling dev-agent to execute from §8.

*The bar the project sets for itself is "verified-or-it-doesn't-ship" and "no compromise around a known defect." Measured against that bar, the foundations pass and the wiring does not yet — and the distance between the two, subsystem by subsystem, is the subject of this document.*


---

<!-- ═══════════════════ AUDIT III of IV ═══════════════════ -->

> **Audit III of IV — consolidated 2026-07-24** (formerly `docs/audit-2026-07-23.md`). A re-audit that independently re-verified Audit II's remediation and surfaced new wiring-layer findings (unauthenticated/unbounded recovery wiring). Preserved verbatim; current status in the *Consolidation status* note at top.

# FANOS platform re-audit — 2026-07-23

**Scope:** a full re-audit after the dev-agent's remediation of `docs/audit-2026-07-22.md` (**41 commits, ~4,140 insertions across 57 files, + the new `fanos-hermes` crate**). Same requirements as the prior audit: architectural compliance, ultimate anonymity (`.fanos` + clearnet), cross-level coherence, most-advanced mechanisms, continuous-improvement, the simulator — with the user's priority focus on **survival + self-organization under mass destruction → heterogeneous recovery**, and on **painful architectural moments**.

**Method:** eight parallel streams (OBOLOS, ANGELOS/THESAUROS, TAXIS + new DROMOS scheduler, anonymity, mass-failure resilience, robustness/new-code sweep, coherence + HERMES + simulator). **The discipline this pass: independently verify every claimed fix in current code — do not trust the fix claims — and hunt for incomplete fixes and NEW bugs the fixes introduced,** plus audit the two new subsystems cold and re-sweep everything still open. Every verdict was read at `file:line`; two arithmetic-critical OBOLOS claims and the beacon-reshare crypto were re-derived by hand; several were executed. Findings are **CONFIRMED** (read/ran, definite) or **LIKELY** (inferred). No code was modified.

**Baseline:** the tree compiles green `--all-targets`; `cargo test --workspace` + `clippy --all-targets -D warnings`: **see §0**.

---

## §0. Verification baseline
- `cargo build --workspace --all-targets`: **PASS** (exit 0, verified this session).
- `cargo clippy --workspace --all-targets -- -D warnings`: **FAILS (exit 101)** — see §3.9. One denied `expect_used` lint at `crates/fanos-aphantos/src/threshold.rs:686:24` (`delivered.expect("the onion is delivered")` in a `#[cfg(test)]` block). The CI gate is **currently red**; the dev-agent's "clippy clean" claim does not hold under `--all-targets`.
- `cargo test --workspace`: **one failure, reproduces 2/2 in isolation** — `a_private_transfer_executes_over_live_consensus_end_to_end` (`fanos-node/tests/dromos_quic.rs:137`) hits its **60 s deadline** waiting for the private transfer to converge across the live 7-node cell; **39+ other binaries pass**. This is **NOT a load flake** (see §3.9): the test's own sanity check at `:120` — the built transfer applies to a fresh genesis ledger with `ExecOutcome::Applied` — **passes**, so the transaction is valid and the stall is in the *live consensus/execute path* (the test's own comment: "a live-path failure is a consensus/transport issue"). The platform's headline "E∧L composition proven runnable end-to-end" test is **currently red**. This contradicts the "green suite" claim.
- **Coverage caveat (repeats and sharpens the prior audit's):** the green suite does **not** exercise the findings below. Several fixes are pinned by tests that assert the *narrow* property (media seals one direction; `settle_epoch` refused at the same height) while the *residual* attack (cross-direction is now safe but SFU is unbuilt; cross-height settlement is unbounded) is untested. **Two coverage regressions were introduced this cycle:** the strongest BFT no-fork Monte-Carlo test is now `#[ignore]`d (§3.7), and the OBOLOS overflow panic (§3.2) is reachable in the default overflow-checked test profile yet unguarded.

---

## §1. Executive summary

**The dev-agent did substantial, largely-honest work, and the core cryptographic and arithmetic fixes are genuinely sound.** Independent verification confirms **13 fixes correct**: O-C1 (inflation cap — bound math re-derived), O-C2 (untraceability — the re-randomized commitment is correctly *bound to the note's value*, the hard part), O-H1 (fee conservation), O-H2 (fresh randomness), AT-C2 (per-direction media keys), AT-C3 (group sender signatures — Signal Sender-Keys parity), AT-M4 (close bound to deal), B1 (auth-before-buffer + bound), S1-H2 (beacon reachable — executed green over real QUIC), and the new **HERMES** HTLC subsystem is built, sound, and holonically correct (respects the depth-3 federation ceiling). The reshare *crypto* (Desmedt–Jajodia continuity + binding) is mathematically correct, the DROMOS parallel scheduler is provably deterministic + serial-equivalent, and the simulator has genuinely crossed toward an experimentation tool (a real `fanos-sim-experiment` CLI now exists). The four items the dev-agent flagged deferred (Γ-gate, E→L, L→O stake, self-org actuation) are genuinely still open exactly as described — the honesty holds up.

**But the re-audit's core value is what independent verification found that the fixes introduced or left — and it is serious.** The remediation pattern this cycle was to *add recovery and guard wiring*, and several of those additions were **added without authentication or without bounds**, re-instantiating the project's own meta-pattern in a sharper form:

> **New meta-pattern this cycle: recovery/guard wiring was added, but often *unauthenticated* or *unbounded* — so the fix opened a new attack surface.**

### The new problems (introduced or left by the fixes)

| # | Severity | Finding | Origin |
|---|---|---|---|
| §3.1 | **CRITICAL** | **Unauthenticated `BeaconReshareTrigger` = beacon master-key exfiltration oracle** — one malicious cell member reshares to `threshold=1` at its own index and reconstructs the beacon secret in the clear | the **R-C1 recovery fix** opened it |
| §3.2 | **HIGH → potentially CRITICAL** | **OBOLOS unbounded-randomness overflow on the consensus verify path** — a single crafted shielded tx panics every overflow-checked validator (consensus halt) or, in release, wraps and voids O-C1's mod-Q inflation proof | the **O-C2 fix** added the reachable instance |
| §3.3 | **HIGH** | **Storage-audit `decode_response`/`challenge` unbounded** — a free crafted `Prove` tx allocates ~240 GB and aborts every validator identically → cell-wide consensus halt | new THESAUROS wiring |
| §3.4 | **HIGH** | **Unbounded `deals`/`htlcs` maps + free zero-value txs** → per-block O(all-deals-ever) sweep + unbounded memory | new storage/HERMES ledger wiring |
| §3.5 | **HIGH** | **AT-C1 residual — audit cadence unenforced**: a provider front-loads all `duration` proofs into consecutive blocks, collects 100% of escrow, then deletes the data | AT-C1 fix incomplete |
| §3.6 | **HIGH** | **AT-H1 residual — PoR still proves access, not possession**: the provider binding is a static replayable transfer and the leaves are public ciphertext any replica can prove → delete your copy, keep getting paid | AT-H1 fix incomplete |
| §3.7 | **MEDIUM (latent → fork)** | **DROMOS `TREASURY` access-list omission** — safe today (scheduler unwired + TREASURY additive) but a consensus fork the moment the scheduler goes live *and* TREASURY gains a read/debit | new scheduler |
| §3.8 | **MEDIUM (CI)** | **The strongest BFT no-fork Monte-Carlo test is now `#[ignore]`d** — the safety property the prior audit cited as the baseline is now opt-in | test change |
| §3.9 | **HIGH (CI red)** | **The suite is NOT green:** clippy `--all-targets` fails (`expect_used` in a fanos-aphantos test) **and** the headline full-platform e2e test (`dromos_quic`) fails 2/2 in isolation — a real live-consensus/execute regression (the tx is provably valid). The "green suite" claim that gated this batch is currently false | lint + consensus-layer change |

### The two priority questions, re-answered

1. **Mass-destruction → heterogeneous-recovery self-organization (user #1): STILL NOT flawless.** The reshare crypto is correct, but (a) the fix only works **proactively, before** the loss — the actual **instantaneous mass-loss case still freezes the epoch clock permanently** (`recovery.rs` honestly asserts this), with no below-threshold re-bootstrap and no auto-trigger; (b) the reshare trigger is the **CRITICAL key-leak** above; (c) parent escalation (R-C2) is a **no-op on the flat depth-1 cell** that the scenario actually runs on; (d) membership lockout (R-H1) and self-org actuation (R-H2) remain open, so returning/new nodes are still dropped and survivors are never re-roled. **§4.**
2. **Ultimate anonymity: STILL NOT defensible.** Only S1-H2 (beacon reachable) is fully correct. S1-C1 is incomplete — **UDP clearnet still leaks the client's coordinate to the exit**, and **anonymous clearnet TCP is non-functional by construction** (no node role hosts an anonymous rendezvous service, so it fails closed). S1-H1's cover traffic is **dead from startup** (the `StartHeartbeat` is swallowed by `CellNode`), so the GPA onset defense is not proactive. And S1-H2's correct fix **aggravates S1-M2** (the proxy can't follow the now-advancing epoch clock → dials break after epoch 0). **§5.**

**Net security-critical delta:** 5 of the prior 9 security CRITICALs are correctly fixed (O-C1, O-C2, AT-C1-literal, AT-C2, AT-C3, S1-C1-TCP-leg — with residuals on the storage ones), but **+1 new CRITICAL** (reshare key-leak) **+1 new HIGH-maybe-CRITICAL** (OBOLOS overflow) **+2 new HIGH** (storage halt, unbounded deals) were introduced. The absolute count of shipping-blocking issues did not drop as much as the commit log suggests, because the fixes traded old bugs for new ones in the wiring layer.

---

## §2. Fix-verification scorecard

| Finding | Claimed fix | **Verdict** | Note |
|---|---|---|---|
| **O-C1** inflation | cap `≤1021` notes + range-check inputs + bound fee/public | **FIXED-CORRECTLY** | math re-derived; `D∈(−Q,Q)⟹D=0`. But depends on randomness being short — see §3.2 |
| **O-C2** untraceability | fresh re-randomised `cv_in` bound to note value | **FIXED-CORRECTLY** | value-binding verified (`tx.rs:157`); no soundness hole, no residual leak |
| **O-H1** fee never collected | debit POOL_SINK, credit TREASURY | **FIXED-CORRECTLY** | conservation exact; invariant restored |
| **O-H2** note-cipher reuse | `seal` takes `CryptoRng` | **FIXED-CORRECTLY** | fresh per seal; no fixed-seed caller |
| **AT-C2** media nonce reuse | per-direction `MediaRole` keys | **FIXED-CORRECTLY** (1:1) | SFU/N-way is *unbuilt*, not "safe" — needs SSRC keying when built |
| **AT-C3** group forgery | per-sender signatures, verify-before-chain | **FIXED-CORRECTLY** | Signal Sender-Keys parity; bind `group_id‖epoch` for defense-in-depth |
| **AT-M4** close-replay | bind close auth to `deal_id` | **FIXED-CORRECTLY** | idempotent-safe |
| **B1** pending_reveals OOM | auth-before-buffer + cap 4096 | **FIXED-CORRECTLY** | eviction is min-key not LRU (minor) |
| **S1-H2** beacon reachable | `--beacon-params` + `beacon-deal` | **FIXED-CORRECTLY** | executed green; but aggravates S1-M2 (§5) |
| **R-C3** loss ledger | account, don't swallow | **FIXED-CORRECTLY** (as scoped) | accounts loss; data still gone (no cross-cell reconstruction) |
| **R-H2** reputation | excuse corroborated-down | **library FIXED / actuation ARCH-BLOCKED** | `spawn_self_organization` still unwired |
| **HERMES** (new) | PQ HTLC atomic swaps | **BUILT, SOUND, holonically correct** | strongest new work; foreign adapter/custody honestly `[P]` |
| **DROMOS scheduler** (new) | deterministic parallel exec | **CORRECT but NOT WIRED** + latent bug | serial-equivalent + double-spend-safe; TREASURY access-list gap (§3.7); zero live benefit today |
| **S-P0.0 sim** | tick_epoch + recovery.rs | **REAL** (cliff + proactive fix demonstrated) | heterogeneous-recovery/collision half not built |
| **S-P2 sim CLI** | experiment-runner | **BUILT** (genuine) | one scenario registered; foundation real |
| **AT-C1** escrow drain | height-binding + canonical response | **INCOMPLETE** | literal replay closed; **cadence unenforced** → §3.5 |
| **AT-H1** PoR provider-bind | `prover_auth` signed transfer | **INCOMPLETE** | static/replayable + proves access not possession → §3.6 |
| **AT-H2** reputation/refund | deadline + auto-refund + reputation | **INCOMPLETE** | refund correct; **reputation half unwired** + new unbounded-deals HIGH (§3.4) |
| **T-H1** exec divergence | reveal re-gossip | **INCOMPLETE** | defeats selective-delivery under partial synchrony; async residual + untested |
| **R-C1** beacon cliff | proactive reshare (Desmedt–Jajodia) | **INCOMPLETE + NEW CRITICAL** | crypto sound; but proactive-only (mass loss still freezes) + §3.1 key-leak |
| **R-C2** parent escalation | `CellEscalate` recursion | **INCOMPLETE** | terminates correctly; but observational-only + **no-op on flat cells** |
| **S1-C1** clearnet-direct | route clearnet through profile | **INCOMPLETE** | TCP forward fixed; **UDP leaks (§5), TCP non-functional (§5)** |
| **S1-H1** cover/mixing | on-by-default | **INCOMPLETE** | **cover-from-startup dead** — `StartHeartbeat` swallowed (§5) |

---

## §3. New / residual findings (the re-audit's core)

### §3.1 [CRITICAL] Unauthenticated `BeaconReshareTrigger` — beacon master-key exfiltration oracle
`fanos-keygen/src/beacon.rs:323` (`on_reshare_trigger`). The only guard (`:327-333`) checks `new_threshold != 0`, `new_threshold ≤ new_indices.len()`, `contributors.len() ≥ threshold` — **no authentication of the trigger and no lower bound** on `new_threshold`/`new_indices`. The frame is routed straight in (`overlay_beacon.rs:82` includes `BeaconReshareTrigger` in `is_beacon_frame`).

**Exploit (single malicious admitted cell member, CONFIRMED by trace):** send `BeaconReshareTrigger{gen > cur, new_threshold = 1, contributors = [the t honest anchors], new_indices = [attacker's own point index]}`. The guard passes. Each honest anchor calls `deal_reshare` (`:354`) **without validating the trigger's legitimacy**; with `new_threshold = 1`, `deal_scalar` builds a **degree-0** polynomial (`vss.rs:264-285`), so `gᵢ(j) = sᵢ` for every `j` — and `:387-395` **sends that sub-share (= the anchor's real secret share `sᵢ`) to the attacker's coordinate.** The attacker collects `{sᵢ}` from ≥`t` contributors and `combine_reshare_share` yields `Σ λᵢ(0)·sᵢ = x` — **the beacon master secret in the clear.** It can then predict every future beacon, coordinate, and rendezvous line. The doc's claimed "authenticated over the parent link" mitigation is **not implemented**. This is precisely the "wrong reshare leaks the key" failure the recovery fix needed to avoid. (Also a liveness-DoS from the same root — a trigger flood evicts the legitimate coordinator's in-progress generation, defeating recovery; robustness stream N3.)

**Fix:** authenticate the trigger (coordinator/parent/operator signature, or a designated-coordinator role check); enforce a security floor — `new_threshold ≥ current t`, `new_indices` must be the full anchor set, reject any shrink-to-attacker; bound `generation ∈ (reshare_gen, reshare_gen + K]`.

### §3.2 [HIGH → potentially CRITICAL] OBOLOS unbounded-randomness overflow on the consensus verify path
`codec.rs:157-167` (`Randomness::from_bytes` reads `L` raw `i64` with **no shortness/bound check**); `commit.rs:179,181` (the `i128` dot-product); reached from `tx.rs:141` (`note.value_r`, pre-existing) **and `tx.rs:157` (`value_r_in` — added by the O-C2 fix, reachable with no mint)**; consensus path `state.rs:136` `apply → proof.verify ← hybrid.rs:243 apply_shielded ← hybrid.rs:567`. The commitment assumes short/ternary randomness (`commit.rs:10,101`) but the verifier never enforces it: `A₁·r` sums `L=256` products of `a ∈ [0,2⁶¹)` and attacker-chosen `x ∈ [i64::MIN, i64::MAX]`, reaching `≈2¹³²` past `i128::MAX (2¹²⁷)`.

**CONFIRMED end-to-end** (standalone reproducer, three ways incl. a no-mint submission overflowing at `tx.rs:141` *before* the membership check): **debug / overflow-checks-on** (the default dev/test/CI profile, and any overflow-hardened production node) → `panic "attempt to add with overflow"` → a **single decodable `TAG_SHIELDED` submission crashes every overflow-checked validator → network-wide liveness event.** **Default release** (overflow-checks off) → silent two's-complement wrap, deterministic (no fork) **but voids the clean mod-`Q` argument O-C1's fix relies on** → a crafted-coefficient inflation is **LIKELY but unproven** (129 mixed-modulus constraints, ~512 `i64` DOF; could not be ruled out). If realizable → CRITICAL supply inflation. **Fix:** reject any `Randomness` coefficient outside `{−1,0,1}` in `from_bytes` and assert it in `TransparentProof::verify`; add randomness-shortness to the relation text (`tx.rs:11-17` lists value-range but omits it) — the "TransparentProof proves exactly what the ZK backend must" claim is still slightly overclaimed until this lands.

### §3.3 [HIGH] Storage-audit execution path — remote OOM/abort via attacker-controlled counts
`fanos-thesauros/src/por.rs`, reached from `HybridLedger::prove_deal` (`hybrid.rs:288-316`) during **deterministic block execution** (so every validator aborts identically → cell-wide halt). (a) `decode_response` (`por.rs:182-185`) reads `count` from a 4-byte attacker prefix and calls `Vec::with_capacity(count)` **with no check against `bytes.len()`** — `[0xFF;4]` ⇒ ~240 GB reservation ⇒ `handle_alloc_error` abort. The correct guard is **present elsewhere in the same codebase** (`content.rs:229` `Manifest::decode` checks `body.len() == count*36` first). (b) `challenge` (`por.rs:66-80`) takes unbounded `params.k` / `size` (validated nowhere at `open_deal`); `k = u32::MAX` ⇒ `(0..leaves).collect()` (~34 GB) or a billions-entry `BTreeSet`. Attacker cost: two zero-value txs (§3.4). **Fix:** bound `count ≤ (bytes.len()-4)/MIN_LEAFPROOF_LEN` before `with_capacity`; reject `k`/`size` above protocol maxima at `open_deal`; clamp `challenge` work.

### §3.4 [HIGH] Unbounded `deals`/`htlcs` maps + free zero-value transactions
`token.rs:179` (`balance < amount` is false for `amount == 0`) ⇒ `open_deal(price=0)` and `lock_htlc(amount=0)` cost only a signature from a funds-less fresh keypair. `StorageMarket::deals` (`storage.rs:139`) and `HtlcBook::htlcs` (`hermes.rs:112`) are **never pruned** (Completed/Closed/Claimed/Refunded persist forever); `begin_block → finalize_lapsed_deals` (`hybrid.rs:343-356`) and both `state_root`s iterate **every** entry each block. A single peer streams distinct-id zero-value Opens/Locks → unbounded validator memory **and** a monotonically-growing per-block CPU tax. **Fix:** a minimum fee / non-zero escrow floor; prune terminal deals/htlcs; a deadline-indexed lapse sweep (the code comment at `hybrid.rs:341` already flags the linear scan). (Also the AT-H2 "reputation half": `grep` for `Reputation`/`Settlement::Miss` in `fanos-dromos` = nothing — the miss/decay path is unwired on-ledger.)

### §3.5 [HIGH] AT-C1 residual — audit cadence unenforced
The same-block permutation replay is correctly closed (canonical-ascending `por::verify` + strictly-increasing height). **But `AUDIT_PERIOD=64` is enforced nowhere on the pay path** (it gates only the lapse deadline, `storage.rs:29-33`). `set_audit_beacon(block.header.parent)` (`consensus.rs:930`) changes the beacon **every block**, and `settle_epoch` requires only `height > last`. So a provider submits a fresh valid `Prove` **every block**, advances one epoch/block, and **collects the entire escrow in `duration` blocks** instead of over `duration·64` — same number of proofs, no extra cost, strictly rational — then the deal `Completed`s and the provider deletes the data. The consumer paid for `64·duration` blocks of durability and got `duration`. **Fix:** require `height ≥ last_height + AUDIT_PERIOD` in `settle_epoch`.

### §3.6 [HIGH] AT-H1 residual — PoR proves access, not possession
`prover_auth` (`hybrid.rs:296`) binds identity + deal, but it is a **static, replayable `SignedTransfer`** (`token.rs:47-57` signs `LABEL‖from‖to‖amount‖nonce` — not the beacon/height/response; "verified, never applied," so the nonce/replay machinery never runs). One provider signature is byte-identical every epoch and replayable forever, and the outer `Prove` tx is itself unauthenticated (the audit's B3). Combined with the untouched root cause — the PoR leaves are **public edge-ciphertext replicated across the `[7,3,4]` cell**, so any replica can compute a valid response — a provider can **sign `prover_auth` once, delete its copy, and keep collecting** (itself or via any confederate). With §3.5 this is 100% escrow in `duration` blocks storing nothing. **Fix:** make `prover_auth` a signature over a fresh per-epoch challenge (`deal_id‖audit_beacon‖height‖H(response)`); ideally encode leaves under a provider-unique key so the response demonstrates *possession*.

### §3.7 [MEDIUM, latent → fork] DROMOS scheduler `TREASURY` access-list omission
`apply_shielded` credits `TREASURY` when `fee > 0` (`hybrid.rs:252-254`), but the `TAG_SHIELDED` access list (`:424-428`) declares only `{SHIELDED_MARKER, POOL_SINK, [recipient]}` — **not `TREASURY`** (a name tx *does* declare it, `:435`). So a shielded-fee tx and a name tx are "non-conflicting" per declaration yet both write `TREASURY` at runtime, violating the "conservative superset" contract (`:407`). Benign today only because `TREASURY` is credit-only/additive (order-independent) **and** the scheduler is off the live path (`execute_block` has zero non-test callers; consensus runs a serial `apply` loop, `consensus.rs:931-933`). It becomes a **consensus fork** the moment the scheduler is wired live *and* `TREASURY` gains a read/debit (governance, treasury-funded rewards, a cap check), or the same omission recurs on a non-commutative key. Untested. **Fix:** declare `TREASURY` in the shielded-fee access list; audit every access list for runtime-write completeness before wiring the scheduler live.

### §3.8 [MEDIUM, CI] Strongest BFT no-fork test now `#[ignore]`d
`consensus_sim.rs:491-493` — the randomized-async + Byzantine-equivocation "never fork" Monte-Carlo test (the strongest safety property, ~140 s) is now `#[ignore]`, so it does not run in the default `cargo test`. The prior audit cited the green suite as the safety baseline; that guarantee is now opt-in. **Fix:** restore it to a CI lane (nightly/heavy) so the no-fork property stays gated. (Also: the partition test `consensus_sim.rs:454` is correct but its docstring mislabels it as covering T-H1/T-H2, which it does not exercise.)

### §3.9 [HIGH — the CI gate is currently RED] clippy fails + the full-platform e2e test fails
The prior audit's §0 (and the dev-agent's notes) cite a green suite as the safety baseline. **Running it this session, it is not green:**

- **clippy `--all-targets -D warnings` FAILS** at `crates/fanos-aphantos/src/threshold.rs:686:24` — `let holonomy = delivered.expect("the onion is delivered");` inside a `#[cfg(test)]` block trips the denied `expect_used` lint. This is the classic `--lib`-vs-`--all-targets` trap (a plain `clippy --lib` or `cargo build` does not surface it — which is why it slipped through). A one-line fix (`let Some(holonomy) = delivered else { panic!(...) }` or a scoped `#[allow]`), but the workspace CI gate is red until it lands. **Fix:** replace the test `expect` per the workspace lint policy; run `clippy --all-targets -D warnings` in CI (not `--lib`).
- **`dromos_quic::a_private_transfer_executes_over_live_consensus_end_to_end` FAILS, reproducing 2/2 in isolation** (each a 60 s deadline stall, not a load flake). The test's in-body sanity check (`:117-122`) proves the *transaction is valid* (`local.apply(&dromos_tx) == ExecOutcome::Applied` against a fresh genesis ledger) — so the failure is in the **live consensus/execute path**: across the real 7-node QUIC cell, the shielded transfer never reaches `spent_count==1 ∧ note_count==2` on all nodes within 60 s. This is the platform's headline "the E∧L composition proven runnable end-to-end" test (`docs/tasks.md` T3), and it is currently red. **Prime suspects are this cycle's consensus-layer changes** — the **T-H1 reveal re-gossip** (`consensus.rs` on_reveal/validate_and_record, which altered reveal handling) and/or the **B1 reveal-auth-before-buffer** (`consensus.rs:791`, which now *drops* a reveal whose signature does not verify against `verifiers[member]` — if the live keyper/verifier wiring in this path does not satisfy that check, legitimate reveals are dropped → the anti-MEV tx is never decrypted → never executes → 60 s timeout). *Not root-caused here* (git-bisecting against the pre-remediation commit would require a checkout that could disrupt the parallel dev branch), but it reproduces deterministically and the transaction is provably valid, so it is a **real regression, not an environmental flake** — the dev-agent should reproduce with `RUST_LOG` on the reveal/execute path and bisect T-H1/B1. This is the single most urgent verification-integrity finding: **a headline correctness test regressed and the "green suite" claim that gated this batch is currently false.**

---

## §4. Mass-destruction → heterogeneous recovery (user priority #1) — current verdict: STILL NOT FLAWLESS

The reshare **crypto** is correct and continuity is real (verified algebraically: `combine_reshare_commitment` preserves the group key; the DVRF output is byte-identical, `beacon.rs:612`), and the **safe-stall** admission window is sound (`quic/identity.rs`, `driver.rs:822` — bounded, VRF/epoch-bound, no admission bypass). But the recovery is not flawless:

1. **The instantaneous mass-loss case still freezes permanently.** `recovery.rs:66` (`the_epoch_clock_freezes_below_threshold_the_r_c1_cliff`) crashes `n−t+1 = 4` anchors and asserts `tick_epoch() == None` **twice** — the reactive cliff is unfixed. The reshare needs `contributors.len() ≥ threshold` (`keygen/beacon.rs:330`), i.e. **≥ t live anchors** — once already below `t`, you cannot reshare. The audit's prescribed **below-threshold re-bootstrap / re-DKG is absent** (grep confirms), and there is **no auto-trigger** (`reshare_trigger` has zero production callers; `spawn_epoch_driver` only sends `AdvanceEpoch`). So R-C1 is **proactive-scheduled-churn-only** — it survives only if operators reshared *before* the loss (which `recovery.rs:95` does, with all 7 anchors up).
2. **That proactive path is the §3.1 CRITICAL key-leak.**
3. **R-C2 parent escalation is a no-op on the flat cell.** It terminates correctly (`ESCALATE_TTL=3` + depth bound, self-send filtered) but the parent action is observational only (`Rerouted`/`Repaired` → `info!` logs, no recruit/relax), and on the common **depth-1 Fano cell** `escalate_up` returns empty (`overlay.rs:1668`). The mass-recovery scenario runs on exactly that flat cell.
4. **Membership still locks out returning/new identities (R-H1, correctly deferred).** `members: BTreeMap<Triple, …>` keyed by coordinate, first-write-wins (`overlay.rs:2258`), no `(epoch,coord)` stamp. A rebooted-identical node whose stale entry lingers, and any colliding new/returning identity on the 7-point cell, is silently dropped → rosters diverge under churn. The deferral is sound (a naive id-key without an authenticated epoch opens a coord-hijack), but it means reintegration at the membership layer is still broken.
5. **Self-org still does not actuate (R-H2, arch-blocked).** The reputation excusal is correct, but `spawn_self_organization` has zero callers; `Node::start` composes roles once from static `config.roles` (`node.rs:236-293`) → survivors are never promoted.
6. **R-C3 accounts loss correctly but does not recover it** (no cross-cell reconstruction); **R-H3** (depth-0 reroute budget) is unaddressed.

**End-to-end:** instantaneous ≥`n−t+1` loss → permanent freeze (dominant break); if proactively reshared → key-leak; returning/new nodes → locked out; re-roling → doesn't happen; data past `[7,3,4]` → accounted but gone.

**Painful-but-correct fixes (priority):** (1) **authenticate + bound + auto-trigger the reshare** (closes §3.1 *and* half the cliff) **+ a below-threshold re-DKG re-bootstrap** for the already-sub-threshold case; (2) **wire `spawn_self_organization` into `Node::start`** off an epoch-snapshotted, corroboration-gated membership; (3) **identity-first, authenticated-`(epoch,coord)` membership**; (4) **real parent re-provisioning + a hierarchy that actually nests + cross-cell erasure placement** so a whole-cell loss is recoverable, not merely accounted.

**Simulator:** S-P0.0 genuinely reproduces the cliff and the proactive fix (5/5 `recovery.rs` green), but the heterogeneous-recovery half is missing — no `recover_as`/`mass_event`, and the one-occupant coordinate model means the R-H1 lockout class *still cannot occur in the sim*. Build the multi-occupant model + `mass_event` so the scenario is fully expressible.

---

## §5. Anonymity — current verdict: STILL NOT "ultimate"

Only **S1-H2 (beacon reachable)** is fully correct (executed green: a provisioned node advances ≥2 epochs over real QUIC; the onion ratchet + coordinates rotate). The rest:

- **S1-C1 clearnet — INCOMPLETE.** The TCP *forward* leg is fixed (onion to `meeting_line(exit_key)`, no coordinate leak). But **(a) UDP clearnet still goes Direct** — `dial_udp` (`diaulos.rs:483-504`) never consults `self.profile`, so `proxy --profile anonymous` sends **every SOCKS5 UDP datagram (DNS, QUIC/HTTP-3, WebRTC) Direct to the exit by coordinate** (live path `socks5.rs:134 → udp.rs:111`). **(b) Anonymous clearnet TCP is non-functional** — the onion targets the exit's meeting line, but the exit listens at its own coordinate via the Direct `serve` loop and **no node role hosts an anonymous `RendezvousService`** (grep: only tests/reply-forwarder/calypso), so onions aimed at the exit are never served; `dial()` has no Direct fallback → it fails closed (no leak, but browsing doesn't work). The banner (`bin/fanos.rs:280`) overclaims for both.
- **S1-H1 cover traffic — INCOMPLETE (dead from startup).** `CellNode::step` routes all commands to `step_obn`, which **never forwards `StartHeartbeat` to the relay** (`cell_node.rs:133-154`), so the router's cover flag is never set at startup. Cover self-starts *lazily* on the first real forward — so the silence→cover transition **coincides with and reveals** the relay's first real traffic, defeating the E1/E6 "uniform whether or not carrying real traffic" property. An idle or line-member-only relay emits **zero cover**. **Fix:** forward `StartHeartbeat` to the relay in `step_obn` (or start cover on role activation).
- **S1-H3 cookie correlator — STILL OPEN (deferral sound), now worse.** The client still `Emit`s the registration from its real coordinate; the reply combiner learns `cookie→client_coord`. Because S1-C1 now routes *clearnet* through the same machinery, **the reply-relay leak now applies to clearnet too** — exit + reply-relay collusion re-links client↔target, undercutting S1-C1's forward-path win. Needs a SURB-style encrypted single-use reply tag + onion-wrapped registration.
- **S1-M2 — OPEN + aggravated by S1-H2.** The proxy is pinned at static `--epoch`/`--beacon` (default genesis) and `Node` exposes no accessor to sync the live value; now that relays *advance* epochs (S1-H2), a proxy at epoch 0 draws its mix directory / meeting lines for epoch 0 while relays rotated to epoch N → **dials fail after the first epoch turn.** **Fix:** expose the current `(epoch,beacon)` on `Node`; the proxy consumes it.
- **Still open (unchanged):** S1-M1 (holonomy absent on the threshold path), S1-M3 (unauthenticated mix-key slots → circuit steering toward attacker-peelable relays), S1-M4 (3-node Fano anonymity set), S1-M5 (censored-bootstrap bridges not wired), S1-M6 (`ct_len` cleartext hop-position leak).

**A bare `fanos node` delivers zero anonymity** (empty `RoleSet`, `beacon: None`); the whole stack requires deliberate provisioning, and even fully provisioned the residuals above break both headline paths. Not defensible as "ultimate."

---

## §6. Coherence, HERMES, DROMOS, simulator

- **Γ-viability gate — STILL UNBUILT (highest-weight arch gap).** No `architecture/` dir, no Python, no Rust computes an architecture-Γ P/R/Φ/D from budgets, no CI step; V4 + σ-panel + the Ω4 ablations exist nowhere; `platform.md:49`'s verdict is still an unreproduced estimate while every gated tier has shipped. The platform's "computed, not asserted" release gate remains prose.
- **E→L / L→O / Ω2 / Ω9 / depth-const / staking contradiction — all STILL OPEN** exactly as the prior audit found (no `SubmitTx` wire; PoW-only admission; Ω2 THESAUROS-only; CALM absent; no `SUBJECT_DEPTH_MAX`; the "stake read literally" vs "forbids capital staking" contradiction unreconciled).
- **Self-org actuation (R-H2) — STILL ARCH-BLOCKED** (see §4).
- **HERMES (new) — BUILT, SOUND, holonically correct.** The HTLC state machine is correct (BLAKE3-preimage PQ hashlock; claim requires `Locked ∧ height < timeout ∧ hash(preimage)==hashlock`, refund requires `Locked ∧ height ≥ timeout`; the boundary is exact and gap-free → exactly one fires). The cross-chain `T_B < T_A` asymmetry is correct and unit-proven (happy + abort). Ledger integration is coherent (`TAG_HTLC`, `HTLC_ESCROW` keyless sink, validate-then-settle, unique `htlc_id`, block-height clock). No griefing beyond the inherent hashlock free-option. It **respects the depth-3 federation ceiling** (federation, not a third tier) and realizes the T-77 cross-holon framing. Honestly scoped (foreign adapters/custody/bonding `[P]`). The strongest new work. Minor nit: `claim/refund` discard the `move_system` result (`let _ =`, `hermes.rs:153/163`).
- **DROMOS parallel execution — scheduler built + proven-deterministic + serial-equivalent + double-spend-safe, but NOT wired live** (§3.7) — a real correctness/safety advance (the hard part is done and proven), zero throughput benefit today, with the latent `TREASURY` access-list bug.
- **Simulator — crossed toward an experimentation tool.** `S-P2` is genuinely built (a real `fanos-sim-experiment` CLI: `--param` grid, `--seeds`, `--out`, CSV/JSON, a real `Experiment` abstraction) — the operator-facing capability the prior audit flagged missing. `S-P0.0` genuinely reproduces the R-C1 cliff and the fix. The crown-jewel adversarial scenarios (S-P0.1–0.5) are **real and passing but siloed in per-crate harnesses** — the `S-P1.1` `SubsystemEngine` adapter that would make them sim-native was not built, so they don't share the network model / determinism trace / GPA tape / observatory. `S-P1.2` transport is still a single global model (soft-partition added). Foundation real, breadth nascent.

---

## §7. Still-open from the prior audit (unchanged — confirmed)

OBOLOS O-M1/M2/M3/M4; ANGELOS AT-M1 (no zeroize), AT-M2 (group out-of-order drop), AT-M3 (per-chunk PoR < λ), AT-M5 (caller-seeded ratchet randomness), AT-H3 (media replay window); TAXIS T-H2 (round-lock liveness wedge), T-H3 (keyper censorship), T-H4 (DA dispersal — engine gained in-engine verification but the driver still feeds the proposer's own full shard set), T-H5 (slashing/rewards emitted but never applied to state), T-M1-M4 (cross-cell); C7 (telemetry-DP built-but-unwired — zero `.privatize` callers), holonomy verification (absent from the threshold/rendezvous peel path). None regressed; each remains as characterized.

---

## §8. Prioritized remediation roadmap (dev-agent work queue)

**Tier 0 — new security-critical, do first**
0. **§3.9 Get the CI gate green first** — fix the `expect_used` lint at `threshold.rs:686`; root-cause and fix the `dromos_quic` e2e regression (reproduce with `RUST_LOG`, bisect T-H1 re-gossip / B1 reveal-auth). A red headline test invalidates the "verified" status of everything else this batch. Run `clippy --all-targets -D warnings` + the un-`#[ignore]`d Monte-Carlo test in CI.
1. **§3.1 Authenticate + bound the `BeaconReshareTrigger`** (the key-leak) — sign the trigger, enforce `new_threshold ≥ t` + full-anchor `new_indices`, bound `generation`. This is the most severe finding of the re-audit.
2. **§3.2 Enforce OBOLOS randomness-shortness on the verify path** — reject coefficients outside `{−1,0,1}` in `from_bytes` + `TransparentProof::verify`; add it to the relation text. (Closes the consensus-halt panic and the release-wrap inflation risk.)
3. **§3.3 Bound the storage-audit `decode_response`/`challenge`** (mirror `Manifest::decode`; cap `k`/`size` at `open_deal`) — closes the cell-wide OOM halt.
4. **§3.4 + §3.5 + §3.6 Storage market hardening** — reject `price==0` / min escrow; prune terminal deals/htlcs; enforce `AUDIT_PERIOD` cadence in `settle_epoch`; make `prover_auth` a fresh per-epoch challenge (possession, not access); wire the reputation/miss path.

**Tier 1 — the user's #1 (recovery) + anonymity**
5. **§4: below-threshold re-DKG re-bootstrap + auto-trigger** for the instantaneous-mass-loss case (the cliff is not yet closed); **wire self-org actuation** (R-H2); **identity-first authenticated `(epoch,coord)` membership** (R-H1); **real parent re-provisioning + cross-cell erasure** (R-C2/R-C3 fundamentals).
6. **§5: route `dial_udp` through the profile (or refuse UDP)**; **host an anonymous `RendezvousService` in the exit role** (make clearnet TCP actually work); **forward `StartHeartbeat` to the relay** (proactive cover); **expose `(epoch,beacon)` on `Node`** so the proxy follows the clock (S1-M2); then S1-H3 (SURB), S1-M1/M3/M6.

**Tier 2 — coherence / correctness-latent**
7. **§3.7 Declare `TREASURY` in the shielded-fee access list** + audit all access lists before wiring the scheduler live. **§3.8 Restore the Monte-Carlo no-fork test to CI.**
8. **Build the Γ-viability gate** (§6); wire E→L tx submission; implement the stake `AdmissionPolicy`; add the Ω2 budgets + Ω9 CALM classes + `SUBJECT_DEPTH_MAX`; reconcile the staking contradiction; wire C7 telemetry-DP + holonomy on the threshold path.

**Tier 3 — simulator + remaining MEDIUM/LOW**
9. **Build the `S-P1.1 SubsystemEngine` adapter** (unifies the siloed crown-jewel scenarios) + the multi-occupant coordinate model + `mass_event` (so the R-H1 lockout and heterogeneous recovery are expressible); **`S-P1.2` richer transport**; the remaining MEDIUM/LOW across OBOLOS/ANGELOS/THESAUROS/TAXIS.

---

## §9. Verified SOUND this cycle (do-not-regress)

The 13 correct fixes in §2 (O-C1/O-C2/O-H1/O-H2, AT-C2/AT-C3/AT-M4, B1, S1-H2, R-C3, HERMES, the DROMOS scheduler's determinism/serial-equivalence/double-spend-safety, the reshare crypto's continuity+binding, the safe-stall window, the S-P0.0 sim, the S-P2 CLI); plus everything the prior audit marked sound and that did not regress (BFT ordering safety, the 1:1 double ratchet FS+PCS, DIAKRISIS invariant math, the transport/stream DoS cluster, the threshold-onion crypto, no-client-DNS-leak). The dev-agent's status discipline remained honest — the four deferred items are genuinely still open exactly as flagged.

---

## §10. Appendix — method and confidence

Eight parallel streams, current code read at `file:line`; the OBOLOS bound math + value-binding and the reshare Lagrange algebra were re-derived by hand; S1-H2, HERMES, the crown-jewel scenarios, and the OBOLOS overflow were executed. Working notes with every anchor and fix are preserved. The re-audit's central lesson: **the remediation was real and the cryptographic cores are sound, but adding recovery and guard wiring without authentication or bounds re-created the platform's meta-pattern in a sharper form — the beacon reshare, the storage-audit path, the escalation frame, and the deals map were all added as new *unauthenticated or unbounded* network-fed surfaces.** Authenticate-before-act and bound-every-map must be the standing discipline for the next cycle, and the two priority dimensions — flawless mass-recovery self-organization and ultimate anonymity — are **not yet met.**


---

<!-- ═══════════════════ AUDIT IV of IV ═══════════════════ -->

> **Audit IV of IV — consolidated 2026-07-24** (formerly `docs/audit-2026-07-23-deep.md`, previously untracked). The deepest architecture→implementation pass; re-verified Audit III at `file:line` and reframed the frontier as *"no driver"* (engines built, production actuation last-mile behind). Preserved verbatim; current status in the *Consolidation status* note at top.

# FANOS deep architecture + implementation audit — 2026-07-23 (pass 2)

**Auditor:** independent read-only pass (a *separate* agent performs the fixes; this document is written to be
directly actionable by that agent — every finding carries an exact `file:line`, a concrete trigger, and the fix).

**Scope.** A full-stack audit *from architecture to implementation* with the user's headline priority foregrounded:
**the code architecture must be flawless and code across all 39 crates must be maximally reused** ("blockchain of the
future"). Grounded in `spec/protocol.md` + `spec/platform.md` and the subsystem design docs in `docs/`. Covers: build/CI
health, independent re-verification of every prior-audit finding (`docs/audit-2026-07-23.md`) against *current* code,
new findings, cross-crate DRY/reuse, dependency-graph hygiene, spec-compliance, and empirical simulator experiments.

**Method.** Four parallel read-only streams (architecture/DRY, blockchain-core, crypto/keygen/POROS, anonymity/storage)
plus the auditor's own verification at `file:line`, hand re-derivation of the load-bearing bounds, and **live simulator
experiments** driven through `fanos-sim` (the deterministic driver over the real node engines). No code was modified by
the audit. Findings are **CONFIRMED** (read/ran, definite) or **LIKELY** (inferred).

**Pinned baseline.** `HEAD = 25b0a6f` ("poros: engine-level line rotation …"), Fri 2026-07-23 17:53.

> ⚠️ **Live-tree caveat.** The repository is under **active concurrent development** by the fixing agent: during this
> audit `HEAD` advanced **`274a0f2 → 25b0a6f → 6d81506`** (and `recovery.rs` / `threshold_service.rs` / `Cargo.lock`
> carry uncommitted WIP). Findings are pinned to `25b0a6f` unless noted; load-bearing items were re-verified at
> `file:line`. Line numbers drift as the tree moves.
>
> 🚨 **§5.D-1 is transitioning latent → live during finalization.** The newest commit `6d81506`
> ("IngressNode rotation API — `emit_reshares` + `arm_rotation`") adds the **driver-facing rotation API** that §7.1
> flagged as missing — but a grep of the current `poros.rs` confirms `on_reshare` (`:583`) **still takes no `from` and
> performs no commitment verification.** So the fixing agent is wiring the POROS rotation driver **without** the §5.D-1
> receive-path verification — exactly the "wiring the driver converts a latent HIGH into a live ingress-DoS" transition
> this report warns of. **§5.D-1 + Tier-0 #3 must land with (or before) the driver.**
>
> 🔒 **The audit modified no production code.** All four read-only streams confirmed zero `Edit`/`Write` calls to
> tracked files; the auditor's temporary `fanos-sim` experiment and chain-core's two throwaway diagnostic tests were all
> removed. The transient `poros.rs`/`ingress_node.rs`/`frame.rs`/`threshold_service.rs` modifications observed mid-audit
> were the **concurrent fixing agent's** work (committed as `25b0a6f`/`6d81506` + WIP), not the auditors'. Final tree
> handed back exactly as found: `M Cargo.lock`, `M recovery.rs`, `M threshold_service.rs` (all the fixing agent's), plus
> this report.

---

## §0. Verification baseline (CI health) — GREEN

Independently run this session on the pinned tree:

- `cargo build --workspace --all-targets` → **PASS** (exit 0, 2m40s).
- `cargo clippy --workspace --all-targets -- -D warnings` → **PASS** (exit 0, 2m58s, no warnings).
- `cargo test -p fanos-sim --test recovery` → **5/5 PASS**; auditor's two custom sim experiments → PASS (§6).

**This flips the prior audit's §0/§3.9 red-CI finding.** The `expect_used` clippy failure at
`fanos-aphantos/src/threshold.rs` is resolved, and `--all-targets` is clean. The dev-agent's "green suite" claim now
holds for build + clippy. **And the pass-1 §3.9 `dromos_quic` stall is now root-caused** (chain-core, §5.B): it **passes
in isolation (8.56 s)** and only stalls **under CPU load** — a wall-clock round-timeout livelock in the *ordering* path,
**not** the reveal-race the pass-1 audit hypothesized (that hypothesis was wrong; the reveal fixes work). So the headline
e2e test is green on an unloaded CI runner but has a real performance cliff (§5.B HIGH-1).

---

## §1. Executive summary

**The remediation since `docs/audit-2026-07-23.md` (pass 1) is substantial and genuine — but incomplete on the most
severe item.** Independent re-verification confirms **§3.2, §3.3, §3.5, and §3.9-clippy fully fixed** (several with
defense-in-depth + tests), **§3.6 fixed-or-partial**, and **§3.1 only *half* fixed**: the single-member key-exfil is
closed, but re-verification uncovered that the *same* surface still admits a **2-anchor coalition** master-key exfil
(the fix floored the threshold at 2 instead of at `t`, and left the trigger unauthenticated). So the security ledger is
**net-positive but not clean** — the worst DoS (§3.2) is gone, yet a CRITICAL key-secrecy break persists:

| Pass-1 finding | Severity | **Re-verified verdict** | Evidence |
|---|---|---|---|
| §3.1 beacon reshare key-exfil (single-member) | CRITICAL | **single-member FIXED; 2-coalition still LIVE (CRITICAL)** | `beacon.rs:386` floors at `2`, **not `self.threshold`**, and the trigger is unauthenticated → §2.1 |
| §3.2 OBOLOS randomness overflow | HIGH→CRIT | **FIXED** (defense-in-depth + tests) | `codec.rs:166-172` ternary reject at decode **and** `tx.rs:143-145` in the verify relation |
| §3.3 storage `decode_response` OOM | HIGH | **FIXED** | `por.rs:201-203` bounds `count ≤ (len-4)/MIN_LEAFPROOF_LEN` |
| §3.5 storage audit-cadence drain | HIGH | **FIXED** | `market.rs:269` `settle_epoch` enforces `height ≥ last + AUDIT_PERIOD` |
| §3.6 PoR proves-access-not-possession | HIGH | **PARTIAL** | fresh `ProverAuth` over `deal_id‖H(response)` (`hybrid.rs:325`); residual = public replicated leaves |
| §3.9 clippy `--all-targets` red | HIGH (CI) | **FIXED** | §0 above |

**The meta-pattern persists, one layer up.** The project's signature failure mode — *"libraries ahead, live-wiring
behind"* — recurs, but the remediation has pushed the frontier from "crypto exists" to "engine exists": the primitives
and even the sans-I/O engines are built and unit-tested, while the **production driver / actuation last-mile** is still
missing. This is now the dominant architectural gap and the core of the user's two priorities:

> **New framing: the gap is no longer "no library" but "no driver."** Recovery, POROS rotation, DROMOS parallelism, and
> telemetry-DP all have a *complete, tested engine* and *no production caller that drives it end-to-end*.

**The apex of that pattern (arch-dry, HIGH):** the **shipped `fanos` binary runs no blockchain at all.** `fanos-dromos`
and `fanos-obolos` are `[dev-dependencies]` of `fanos-node`, `spawn_taxis` has **zero production callers**, and
`bin/fanos.rs` / `fanos-ffi` / `fanos-cli` contain no ledger wiring — the entire L-machine (TAXIS/DROMOS/OBOLOS) is
exercised only by `tests/dromos_quic.rs`. And when that test path *is* driven under CPU load, chain-core found it
**livelocks** (a wall-clock round timeout that a large block cannot beat under contention — §5.B). So both the *product*
wiring and the *performance* of the value tier are pre-production. Two further latent-but-serious correctness landmines
sit in the value tier awaiting their drivers: the **`public_recipient` fund-redirection** hole (§5.D-2, live the moment
unshield-crediting is wired) and the **POROS reshare corruption** (§5.D-1, live the moment rotation is triggered).

### The priority verdicts

1. **Mass-destruction → recovery (user #1): NOT yet flawless — the auto-trigger detects but does not recover.**
   The new `StallDetector` + `RecoveryWatcher` (`node.rs:106-216`) is honest new infrastructure, but as wired it
   **cannot recover a mass-loss freeze**: (a) Regime A (proactive reshare) is stall-gated into unreachability (§4.1);
   (b) Regime B only emits a `tracing::warn!` — **`BeaconNode::rebootstrap` has zero production callers** and no code
   issues/consumes a re-genesis certificate automatically (§4.2). Empirically (§6): the clock **does** self-heal on
   *churn-rejoin* (returning anchors), but stays frozen for permanent loss. **The recovery loop's last mile is open.**
2. **Ultimate anonymity: delegated to the anonymity stream (§5.C).** Prior-audit §5 residuals (UDP-profile clearnet
   leak, cover-from-startup, proxy epoch-pinning, no hosted anonymous rendezvous, SSLE) are re-verified there.

### Net delta since pass 1
Security posture improved on the arithmetic/DoS axis (§3.2 consensus-halt and §3.3/§3.5 storage closed; §3.2 was the
worst DoS). **But two live security defects remain, both in the threshold-resharing surface:**
- **[CRITICAL] §2.1** — the beacon reshare trigger is unauthenticated and floors `new_threshold` at 2 not `t`, so a
  **2-anchor coalition reconstructs the beacon master secret** (a confirmed threshold-downgrade exfil, live in the test
  suite), and the now-live recovery auto-trigger makes reshares routine cover.
- **[HIGH] §5.D-1** — the POROS descriptor-reshare receive path accepts **forged, unverified** contributions, so **one
  remote node corrupts a new-line member's rotated share** → ingress DoS the moment the rotation driver is wired.

The same root cause underlies both: **resharing without an authenticated trigger and without receiver-side binding
verification.** The dominant *architectural* debt is the driver-wiring last-mile (§4, §7) and cross-crate reuse (§3).

---

## §2. Independent fix-verification detail

### §2.1 [CRITICAL — live] §3.1 beacon `BeaconReshareTrigger` — single-member exfil FIXED, but a 2-coalition threshold-downgrade exfil REMAINS — CONFIRMED — **RESOLVED 2026-07-24**

> **Current status — 2026-07-24: RESOLVED.** The `BeaconReshareTrigger` is now **authenticated**: it carries a `HybridSignature` by the beacon's recovery `authority` (the same trust root that authorizes re-genesis) over its parameters, and `on_reshare_trigger` rejects any trigger that is unsigned, foreign-signed, or tampered **before any anchor deals a sub-share** (`fanos-keygen/src/beacon.rs`). Because a node holds no authority secret, it can no longer self-issue a reshare: `node.rs::actuate_recovery` now **escalates** a proactive reshare to the authority (exactly as Regime B already escalates re-genesis) instead of emitting an unauthenticated trigger. The 2-anchor-coalition key-exfiltration is closed — a coalition cannot forge the authority signature — while legitimate threshold-lowering recovery still works (the authority signs it, so a 4-of-7 → 3-of-4 survivor reshare is honored). The threshold-value floor (`MIN_RESHARE_THRESHOLD`) is retained only as defence-in-depth against a degree-0 reshare. Pinned by `beacon::tests::a_key_exfiltration_reshare_trigger_is_rejected` (foreign-signed **and** tampered triggers refused, authority-signed honored) + `a_reshare_moves_the_beacon_to_a_survivor_set`, and the sim `proactive_resharing_survives_the_r_c1_cliff` drives an authenticated reshare end-to-end. The in-flux `recovery.rs` was not touched. **This was the platform's single top open security item; it is now closed.**

`fanos-keygen/src/beacon.rs`. The receive path `on_reshare_trigger` (`:368`, guard `:384-393`) now enforces, before dealing:
```
generation > reshare_gen  ∧  generation ≤ reshare_gen + MAX_RESHARE_GEN_ADVANCE
new_threshold ≥ MIN_RESHARE_THRESHOLD (=2)      // :386 — floors at 2, NOT at self.threshold
new_threshold ≤ new_indices.len()
contributors.len() ≥ self.threshold
distinct_in_range(contributors) ∧ distinct_in_range(new_indices)
```
and `on_reshare_commit` (`:468`) rejects any contribution that fails `verify_reshare_commit` against the *current*
commitment (binding). The prior CRITICAL — a **single** member naming `new_threshold=1` at its own index — is **closed**;
with `t' ≥ 2` a single identity holds only one evaluation of a degree-≥1 polynomial. Empirically confirmed in the
simulator (§6, P2): the `t'=1` trigger is silently dropped and the clock advances undisturbed.

**But the core hole is still live and is CRITICAL, not merely a residual** (crypto/keygen stream; the code's own note at
`beacon.rs:380-383` labels it a "Tier-1 follow-up"). The floor is `MIN_RESHARE_THRESHOLD = 2`, **not `self.threshold`**,
and the trigger carries **no authentication** (`reshare_trigger_frame`/`parse_reshare_trigger`, `:706-727`, have no
signature field; dispatch `overlay_beacon.rs:82 → beacon.rs:655` performs no sender/authority check).

> **Exploit (CONFIRMED, reproducible).** Cell `n=7`, threshold `t=4` (BFT tolerates `f ≤ 2` Byzantine). **Two** colluding
> anchors sit at Fano indices 5 and 6. Anchor 5 broadcasts (no signature needed)
> `reshare_trigger_frame(generation=1, new_threshold=2, contributors=[1,2,3,4], new_indices=[5,6])`. Every guard clause
> passes (`gen 1∈(0,8]`; `t'=2 ≥ 2` and `≤ |{5,6}|`; `|contributors|=4 ≥ t`; both sets distinct/in-range). Honest anchors
> 1..4 each run `deal_reshare` (`:414`): deal a fresh degree-1 `gᵢ` with `gᵢ(0)=sᵢ` and **send `gᵢ(5)→coord(5)` and
> `gᵢ(6)→coord(6)`** (`:447-454`). The coalition collects `{gᵢ(5)}` and `{gᵢ(6)}`, computes `H(5)=Σλᵢgᵢ(5)`,
> `H(6)=Σλᵢgᵢ(6)`; `H` has degree `t'−1 = 1`, so **two points interpolate `H(0)=S` = the beacon master secret.** Two
> Byzantine anchors — *within* the tolerated `f ≤ 2` — reconstruct a secret that the `(4,7)` design says needs 4
> shareholders. The key-secrecy threshold is downgraded from `t` to `2`.

**Smoking gun in the test suite:** `beacon.rs:1251` asserts that a threshold-*lowering* reshare
(`new_threshold=3, new_indices=[4,5,6,7]` against a victim at `t=4`) is **honored** (`!is_empty()`, "a legitimate reshare
is still dealt") — i.e. the downgrade path is deliberately live. With the beacon now emitting reshare triggers
automatically (§4), this attack has routine cover, and it works for any `t ≥ 3`.

**Fix (reuses existing infra; from the crypto/keygen stream):**
1. **Authenticate** — `BeaconNode` already holds `self.authority: Option<HybridVerifier>` (`beacon.rs:607`, used by
   `rebootstrap`). Add a `HybridSignature` field to the trigger wire (`:706-727`) over a domain-separated
   `signable(generation, new_threshold, contributors, new_indices, self.lineage_anchor())` — mirror
   `RecoveryAuthorization::signable` (`recovery.rs:52-63`; `HybridVerifier::verify` checks Ed25519 **and** ML-DSA-65,
   `sig.rs:104-105`). Require a valid authority sig in `on_reshare_trigger` before the guard; make `actuate_recovery`
   (`node.rs:126`) sign with the authority secret — making Regime A authority-authorized like Regime B re-genesis.
2. **Fallback if no authority is configured** — change `beacon.rs:386` from `new_threshold < MIN_RESHARE_THRESHOLD` to
   `new_threshold < self.threshold`: an unauthenticated reshare may **preserve/raise** the threshold (always
   confidentiality-safe) but never **lower** it. (A threshold-preserving reshare needs a coalition of `≥ t` new coords =
   `≥ t` identities = outside the trust model.) **Note:** this fix requires updating the `beacon.rs:1251` test, which
   currently asserts the downgrade is honored.
3. **Minimal stopgap** if the signature work is deferred: apply the `:386` change **and** make `node.rs` Regime A
   escalate-and-log like Regime B (`:135-139`) rather than emit a downgrade trigger — closes the exfil now, at the cost
   of autonomous proactive resharing until the signed path lands.

This is the **top security item** of the audit.

### §2.2 [FIXED] §3.2 OBOLOS randomness overflow — CONFIRMED (defense-in-depth)
`fanos-obolos`. Two independent guards now enforce ternary (`{−1,0,1}`) commitment randomness:
- **Decode:** `codec.rs:157-172` — `Randomness::from_bytes` returns `rand.is_ternary().then_some(rand)`; a full-range
  `i64` *or even a coefficient of 2* is refused (tests `:350-353`).
- **Relation:** `tx.rs:143-145` — `TransparentProof::verify` re-asserts `short(r) = r.is_ternary()` over every input and
  output opening, and the relation text (`tx.rs:15,78-82`) now *lists* randomness-shortness (closing the pass-1
  "overclaimed relation" nit).
The `A₁·r` dot-product can no longer reach `2¹³²`; the consensus-halt panic and the release-wrap inflation risk are both
closed. **Re-derived by hand: bounded.**

### §2.3 [FIXED] §3.3 storage `decode_response` — CONFIRMED
`fanos-thesauros/src/por.rs:201-203` now bounds `count > (bytes.len()-4)/MIN_LEAFPROOF_LEN → None`, mirroring
`Manifest::decode`. (It still *hand-rolls* the bound — see the DRY finding §3.1 below.) The `challenge`/`k`/`size` arm
of pass-1 §3.3 is delegated to the anonymity/storage stream (§5.C) to confirm the `open_deal` caps.

### §2.4 [FIXED] §3.5 storage audit cadence — CONFIRMED
`fanos-thesauros/src/market.rs:269` `settle_epoch` now computes `floor = last_height.unwrap_or(open) + min_interval`
(`= AUDIT_PERIOD`) and returns `None` if `height < floor` on the ledger path. A provider can advance a deal at most once
per `AUDIT_PERIOD` blocks; the front-loading escrow-drain is closed. Called with `AUDIT_PERIOD` from
`hybrid.rs:338`.

### §2.5 [FIXED for the replay class; residual LOW for possession] §3.6 PoR — CONFIRMED (both storage + crypto streams)
`hybrid.rs:315-345` `prove_deal` now requires a dedicated `ProverAuth` (not the old static `SignedTransfer`) that
`verify(id, response_bytes, provider)` binds to `deal_id ‖ H(response)` (`hybrid.rs:325`), beacon-bound via
`por::verify(cid, audit_beacon, …)` (`:332`). A third party lacking the provider key cannot forge it, and a captured auth
cannot be replayed across epochs — the **replay/forgery class is closed.** **Residual CONFIRMED (downgraded to LOW):** the
leaf *encoding* did **not** become provider-unique — `seal_object` (`object.rs:41`) seals under the *object's* fresh key,
and leaves stay content-addressed ciphertext replicated across the `[7,3,4]` cell. `ProverAuth` binds the **payee**, not
the **holder**, so a provider that deleted its copy can fetch the leaves from a sibling replica and still prove — *access,
not possession.* Because the data remains retrievable cell-wide, this is an **intra-cell free-rider nuance (LOW)**, not a
durability break. **Full fix (optional):** encode leaves under a provider-unique key so only the designated holder can
answer. (Storage `challenge`/`open_deal` caps the pass-1 §3.3 `k`/`size` arm flagged are also present — §5.C.)

---

## §3. Architecture & code-reuse (the user's headline) — DRY findings

> The remaining sub-findings (crypto-wrapper duplication, Merkle/accumulator duplication, epoch-math duplication,
> per-crate reuse census) are produced by the **architecture/DRY stream** and integrated in §5.A. The auditor's own
> confirmed reuse findings:

### §3.1 [HIGH — reuse] The canonical bounded reader exists but is inconsistently adopted — CONFIRMED
`fanos-primitives::codec` provides the *correct, reusable* bounded decoder: `Reader::seq(min_elem, f)` bounds
pre-allocation against the bytes actually present and refuses `min_elem = 0` (`codec.rs:77-83`); `read_map` likewise;
tests reject over-counts (`:179-192`). **Yet at least four incompatible bounding strategies coexist across crates:**

| Strategy | Site(s) | Problem |
|---|---|---|
| `Reader::seq` (the shared, correct one) | `fanos-primitives`, parts of ledger codecs | ✅ the target |
| manual `count > (len-4)/MIN → None` + hand loop | `thesauros/por.rs:201` | secure *now*, but was the §3.3 vuln until pass 1 patched it by hand |
| manual `body.len() == count*stride` pre-check | `thesauros/content.rs:229` | different idiom, same intent |
| `count.min(1024)` cap | `obolos/codec.rs:308` | a magic cap, not bytes-bounded |
| **no bound** on `with_capacity(<wire count>)` | `vrf/beacon.rs:348`, `vrf/pqvrf.rs:115,119,164`, `vrf/shuffle.rs:291-312`, `taxis/checkpoint.rs:174`, `taxis/crosscell.rs:322`, `dromos/hybrid.rs:1397`, `node/rendezvous.rs:220`, `nyx/tessera.rs:119-127`, `nyx/guard.rs:65`, `aphantos/node.rs:326` | each is a place a bound can be *forgotten* (as `por.rs` originally was) |

**This is the cleanest illustration of the DRY thesis in the codebase:** the *same* safety invariant is re-implemented
by hand in ≥4 ways, and the one time it was omitted it was a cell-wide-halt HIGH. **Fix:** route every length-prefixed
wire decode through `Reader::seq`/`read_map`, and delete the hand-rolled variants. This simultaneously (a) removes the
duplication, (b) makes the unbounded-alloc DoS class *structurally impossible* rather than whack-a-mole, and (c) is
exactly the "maximal reuse" the user demands. Each `with_capacity(<wire count>)` site above must be audited: some have
a *protocol-fixed* count (safe) but should still adopt the shared reader for uniformity; the VRF/taxis ones read the
count from the wire and need the bound.

### §3.2 [MED — architecture] `fanos-node` is a god-crate — CONFIRMED
`fanos-node` = **19 internal `fanos-*` dependencies, ~11.1k LOC** (the widest fan-out in the workspace by far; next is
`fanos-runtime` at 11). It composes essentially every subsystem (aphantos, calypso, diaulos, keygen, proxy, quic,
rendezvous, session, taxis, vpn, vrf, obolos-via-dromos, …). This is the known `OverlayNode`-decompose / `fanos-runtime`
-split backlog. Some breadth is inherent to an integration crate, but 11k LOC + 19 deps is a decomposition target: the
`Node::start` role-composition, the driver tasks (epoch, recovery, exit, service, poros), and the engine composites
(`OverlayBeaconNode`, `CellNode`, `IngressNode`) are separable into role-scoped modules/crates. *Architecture stream to
propose the split boundary.*

### §3.3 [OK — do not regress] Dependency-graph hygiene is otherwise good
The internal graph is cleanly layered (`fanos-field` (0 deps) → `geometry` → `wire`/`primitives`/`vrf`/`pqcrypto` →
mid-tier → `runtime`/`node`); **no cycles** observed. The one apparent inversion — `fanos-observatory → fanos-sim` — is
**deliberately feature-gated** (`optional = true`, feature `sim`; the Cargo.toml cites audit ARCH-10 D8 and offers
`--no-default-features` for a sim-free shipping monitor). Good hygiene; the only nit is `sim` being on by *default*, so
the shipped monitor bundles the simulator unless explicitly slimmed. Keep this handled.

---

## §4. Mass-destruction → recovery (user priority #1) — the driver last-mile is open

The recovery **crypto and engine** are real and correct (reshare continuity + binding: §2.1; `RecoveryAuthorization` is
a hybrid-PQ signed, floored, generation-fenced cert: `recovery.rs:31-133`; `rebootstrap` exists on `BeaconNode`; the
committed sim tests pass 5/5 incl. `proactive_resharing_survives_the_r_c1_cliff`). The gap is **actuation**.

### §4.1 [HIGH] Regime A (proactive reshare) is stall-gated into unreachability — CONFIRMED
`node.rs` `RecoveryWatcher::on_tick` (`:205-215`) gates **all** actuation behind
`if !self.detector.observe(self.last_epoch) { return; }` — the `StallDetector` fires only after `RECOVERY_PATIENCE = 4`
consecutive **non-advancing** epochs, i.e. *after the clock has already frozen*. But a clock freeze from anchor loss
means `live_anchors < threshold`, at which point `recovery_decision` (`recovery.rs:176-186`) returns **`RequestRegenesis`
(Regime B)**, never `ProactiveReshare` (Regime A). Regime A requires `live ≥ threshold` (clock still advancing) — and
while the clock advances, `on_note` bumps `last_epoch`, the detector resets, and `on_tick` never actuates.
**Consequence:** the proactive reshare that is *supposed to lower the threshold ahead of a loss and prevent the freeze*
is effectively **dead code in production** — reachable only in the pathological corner of a transient-loss stall at
*exactly*-`threshold` membership. The headroom-buying mechanism never auto-fires on the monotonic-loss path the mass-
destruction scenario actually runs.
**Fix:** drive Regime A off a **membership-thinning** signal (corroborated `PeerDown` count vs `threshold`) that is
*independent of* the stall detector, so a cell reshares to a lower threshold *while still live*; keep the stall detector
only for Regime B.

**The `StallDetector` logic itself is correct** (crypto/keygen stream, verified at `recovery.rs:191-223`): an advancing
(even every-other-period) clock never fires (`observe` resets `missed=0` on any advance); only `patience` *consecutive*
non-advances fire, exactly once at the boundary, re-fire blocked; genesis all-zero never fires; and
`patience = RECOVERY_PATIENCE = 4 > BeaconWindow::DEPTH = 3`, so a lagging-but-live cell is not mistaken for frozen. No
false-positive, no missed sustained freeze. The reachability defect in §4.1 is therefore **not** a detector bug — it is
the `on_tick` gate composing a correct detector with a decision function that routes the frozen state to Regime B. **The
`BeaconReady → on_note` delivery is confirmed wired** (crypto stream traced the full path
`beacon.rs:330 → driver.rs:1039,546,499 → node.rs:252,260,182`; the only caveat is an unrealistic >4096-deep broadcast
backlog), so there is no false-fire risk either. The defect is purely the gate.

### §4.2 [HIGH] Regime B escalates correctly-by-design, but the RGC issue/consume loop is not wired — CONFIRMED
Two things are true and must be held together:
- **The escalate-not-auto-rekey behavior is correct.** `actuate_recovery` (`node.rs:135-139`) handles
  `RequestRegenesis` by emitting a `tracing::warn!` and escalating — it does **not** auto-rekey. This is *right*: a
  `(t,n)` secret with `< t` shares is information-theoretically gone, and two partitioned minorities each re-keying would
  **fork**. `recovery.rs:1-11` argues this correctly — below-threshold recovery *must* be fenced by a single-writer
  authority (a signed `RecoveryAuthorization` with a strictly-monotonic generation), never trustless. And the crypto is
  sound: `RecoveryAuthorization` is a floored (`MIN_REGENESIS_THRESHOLD`), generation-fenced, hybrid-PQ-signed cert
  (`recovery.rs:31-133`), and `BeaconNode::rebootstrap` (`beacon.rs:601-628`) adopts it. **The pass-1 "reactive cliff" is
  closed at the crypto layer.**
- **But the loop is not automated.** `BeaconNode::rebootstrap` has **no non-test caller**, and **no production code
  issues *or consumes* a `RecoveryAuthorization`** (`RecoveryAuthorization::issue` appears only in `recovery.rs` tests;
  the `fanos-incentives` `issue(...)` hits are an unrelated blind-signature method). There is no frame handler that, on
  receiving an RGC, calls `rebootstrap`. So on a real below-threshold freeze: `StallDetector` confirms → coordinator logs
  → **and there it stops** — the clock stays frozen until a human operator (a) reads the log, (b) obtains the authority
  key, (c) issues an RGC, and (d) delivers it to a survivor that manually calls `rebootstrap`. None of (a)–(d) is wired.
**Fix:** wire the two missing legs — (1) an operator/authority control-plane that *receives* the escalation and issues a
`RecoveryAuthorization` (the authority key already configurable via `with_recovery_authority`, `beacon.rs:150`), and (2)
a production frame handler that *consumes* a delivered RGC via `rebootstrap`. Until both land, below-threshold "recovery"
is detection + logging + a manual operator runbook — not autonomous recovery. (This is a *narrower, fairer* framing than
"recovery is broken": the design deliberately keeps a human/authority in the below-threshold loop for fork-safety; the
gap is that the two ends of that loop have no production wiring.)

### §4.3 [Context] Empirical result — the freeze is survivable for *transient* loss (§6, P1)
The simulator experiment (§6) shows that when the crashed anchors **return** (churn-rejoin, shares intact), the beacon
engine **does resume** the clock (`None,None → Epoch 3,4`). So the freeze is permanent only for *permanent* loss; a
transient mass-outage self-heals at the engine level once `≥ threshold` anchors are back. **Caveat (R-H1):** the sim
models one occupant per coordinate, so a returning identity always reclaims its exact slot+share; on a real network the
membership/identity layer (stale entries, coordinate collisions, VRF reshuffle to a new coord, lost shares) may block
the right nodes from returning to the right slots. That membership-reintegration layer remains the open reliability
question for the returning-node case.

### §4.4 Net #1-priority verdict
Instantaneous permanent ≥`n−t+1` loss → **still a permanent freeze** (no auto-recovery); transient loss → self-heals at
the engine level (good, empirically shown), *if* membership lets nodes return; the auto-trigger is **detect-and-log**,
not recover. **The four painful-but-correct fixes:** (1) authenticate the reshare trigger (also closes §2.1 residual);
(2) drive Regime A off membership-thinning, not stall; (3) wire the RGC issue/consume loop for Regime B; (4) close the
membership-reintegration (R-H1) so returning/new identities reclaim slots safely.

---

## §5. Stream findings (integrated as the parallel streams report)

> The four read-only streams (architecture/DRY, blockchain-core, crypto/keygen/POROS, anonymity/storage) are running.
> Their detailed `file:line` findings are integrated into the subsections below as each completes. The auditor has
> pre-verified the load-bearing items above; the streams supply breadth (OBOLOS `O-M*`, SSLE safety, the full anonymity
> §5 residual set, storage `challenge`/deals-map bounds, and the per-crate DRY census).

### §5.A Architecture / DRY (stream: arch-dry) — INTEGRATED

**[HIGH] The shipped binary runs no blockchain — the whole L-machine is test-only wiring.** `spawn_taxis`
(`taxis_driver.rs:151`) has **zero production callers** (only the `lib.rs:72` re-export); **`fanos-dromos` and
`fanos-obolos` are `[dev-dependencies]` of `fanos-node`**, pulled in solely by `tests/dromos_quic.rs`; and the single
`fanos` binary (`bin/fanos.rs`), `fanos-ffi`, and `fanos-cli` contain **no TAXIS/ledger wiring at all**. So the entire
platform value-tier (TAXIS/DROMOS/OBOLOS) is exercised only by integration tests — a running `fanos` node cannot be a
validator. This is the single loudest structural signal of the whole audit and the root of the "engine-ahead,
driver-behind" pattern at the *product* level. **Fix:** promote `dromos`/`obolos` to real deps, add a config-gated
validator role in `bin/fanos.rs` that instantiates `spawn_taxis::<F, HybridLedger>`, and expose it through `fanos-ffi`.

**[HIGH] Three divergent Merkle implementations with incompatible rules + proof formats.** `thesauros/content.rs:88-113`
(lone odd node **promoted** unchanged; proofs = `MerkleStep{sibling, sibling_on_right}`), `taxis/crosscell.rs:96-158`
(odd tail **duplicated**; proofs = index-parity `Vec<[u8;32]>`), `vrf/pqvrf.rs:61-140` (perfect `2^h` tree). Same abstract
structure, three dialects — and `crosscell`'s duplicate-last rule is the **CVE-2012-2459** ambiguity class unless the leaf
count is externally bound (flagged to the correctness stream). `obolos/tree.rs` (incremental frontier) is a genuinely
different structure — rightly separate. Positive: `taxis/committee.rs`+`block.rs` already **reuse** `pqvrf::MerkleProof`
for the SSLE ticket path — that seam is clean. **Fix:** one `merkle` module in `fanos-primitives` (domain-separated via
`hash_labeled`, one odd-rule, one proof type); thesauros + crosscell adopt; pqvrf reuses as the perfect-tree case.

**[HIGH] Wire bifurcation — three serialization dialects; the ledger layer bypasses `fanos-wire` entirely.**
`#[derive(Wire)]` is used in only **9** crates; **21 crates hand-roll big-endian, 20 little-endian, 12 mix both** (taxis
alone: 10 BE files + 1 LE + 3 derive). **Zero `fanos-wire` usage** in the consensus-critical app crates: `obolos/codec`,
`dromos/{naming,token,storage,hermes}`, `hermes/htlc`, `thesauros/{por,content,market}`, `angelos` (8 files),
`incentives`, `onoma`. This contradicts `primitives/epoch.rs`'s own "one canonical wire width" doctrine (audit A3). The
encodings **aren't consensus-frozen yet — the window to unify is now.** **Fix:** `#[derive(Wire)]` across the ledger
crates, or at minimum the shared `Reader` + one endianness. (This is the same root as the §3.1 bounded-reader finding,
at larger scale.)

**[HIGH] `fanos-runtime` is one 3,870-line file.** The crate is `lib.rs` + `overlay.rs`, and the `OverlayNode`
decomposition **already exists at the type level** (`Config`, `Store`, `Router`, `Membership`, `Healer`, the 15-field
`OverlayNode` struct, the `Engine` impl — all in that one file); only the module split never happened. **Fix:**
mechanical split into `store/router/membership/healer/hier/node.rs`, `lib.rs` re-exports, **zero API change**. Next-worst
cohesive-but-big files: `quic/driver.rs` (1936), `dromos/hybrid.rs` (1530), `taxis/consensus.rs` (1432),
`aphantos/threshold_router.rs` (1317), `keygen/beacon.rs` (1254). (`fanos-sim`'s 13.5k = 2.1k src + 11.2k *test
scenarios* — intended per the SecOps directive, not a smell — which revises my earlier "god-crate" note on sim; the
real god-object is `runtime/overlay.rs` and `fanos-node`.)

**[MED] Threshold KEM-seal hosted in the anonymity crate ⇒ consensus depends on the onion router.** `taxis/tx.rs:15` +
`keyper.rs:30` import `ThresholdSealed`/`ThresholdError` from `fanos-aphantos` (whose `threshold.rs` 858 ln + `sealed.rs`
523 ln are general threshold-KEM machinery inside the 4.5k routing crate). **This is the one questionable edge in an
otherwise clean graph.** **Fix:** extract `threshold.rs`+`sealed.rs` into a low-layer crate (`fanos-threshold`, or into
`fanos-pqcrypto`); aphantos and taxis both import it.

**[MED] POROS protocol engine lives inside the integrator crate.** `node/poros.rs` (1,039 ln) is a full sans-I/O ingress
engine + 11 hand-rolled codec fns *inside `fanos-node`*, while every sibling engine has its own crate (`keygen::BeaconNode`,
calypso hosting, aphantos). **Fix:** move engine+codec to a protocol crate; node keeps only the tokio driver.

**[MED] No shared bounded-collection type — every subsystem hand-rolls cap+eviction.** `keygen/beacon.rs:45,50,254,634`,
`taxis/consensus.rs:48,56,1195`, plus maps in `dromos/hybrid.rs`, `quic/driver.rs`, `diaulos/conn.rs`. The historical
"OOM cluster" is exactly missed instances of this. **Fix:** one `BoundedMap` with explicit insert policies
(reject-new / evict-oldest / evict-terminal) — makes the OOM bug class unconstructible.

**[MED] Additional dead/unwired public APIs (beyond DROMOS/telemetry/POROS-driver already logged):**
- **Hierarchy SEND API is test-only** — `runtime/overlay.rs:1584-1608` (`learn_hier_peer`/`hier_next_hop`/`send_hier`):
  RouteHier *forwarding* is wired engine-internally, but the only *initiators* are `sim/tests/hier_poisoning.rs`.
- **`fanos-angelos` (2,290 ln) has zero consumers outside its own tests** — no node driver, no FFI surface. A product
  with no socket. (Matches memory [[angelos-messenger]]: the crypto is done; the wiring isn't.)
- **`spawn_self_organization`** (`node/role_loop.rs:165`) — **zero callers anywhere** (R-H2 actuation still unwired).
- **`CoherenceFrame::privatize`** — test-only callers; telemetry leaves via `DiagGossip` without crossing the DP export
  boundary, so the ε-guarantee is decorative (corroborates §7.3).
- **Stale backlog:** `StorageAddress` matches nothing in the workspace — storage addressing is thesauros `Cid`
  end-to-end; the backlog item names a non-existent type (drop it).

**[LOW] Four identical copies of `fn encode(ty: FrameType, body: &[u8])`** (`keygen/beacon.rs:685`,
`runtime/overlay.rs:2689`, `node/poros.rs`, `node/threshold_service.rs`) → a `FrameType`-accepting `encode_frame` in
`fanos-wire`, delete all four. **[LOW] `SplitMix64` ×7** (2 legit no_std/sim, 5 test copies) → expose once from
primitives/testkit. **[LOW] `generation` is a bare `u64`** across keygen/node recovery frames while `epoch` got the A3
newtype — same truncation-risk class → a `Generation` newtype beside `Epoch`.

**Crypto-wrapper verdict — mostly EXEMPLARY (do-not-regress):** `hash_labeled` (one home, ~40 consumers, zero re-wraps),
AEAD (primitives `aead` feature is the *only* AEAD dep), Shamir (primitives only), Lagrange-at-zero (`vrf/vss.rs:302`),
`NodeId` (pqcrypto imports from primitives — the don't-duplicate directive **holds**), KEM/sig (pqcrypto only). The
VRF/beacon three-layer split (primitives no_std reference → fanos-vrf ristretto production → keygen networked engine) is
**deliberate and documented, not duplication**. The Epoch newtype is the model A3 closure. **The only crypto-reuse
defects are the Merkle triplication + the `ThresholdSealed` placement above.**

**Dependency-graph shape:** a clean **5-layer DAG, no cycles**. High fan-in on `field/geometry/wire/primitives/pqcrypto`
is an appropriate platform base. Apparent inversions dissolve on inspection (`quic→runtime` is the sans-I/O host pattern;
`primitives→wire` is optional+feature-gated; `observatory→sim` is feature-gated §3.3). **Exactly one bad edge:**
`taxis→aphantos` (above). The loudest signal is `dromos`/`obolos` as **dev-deps** of `fanos-node` (the test-only chain,
finding #1).

**Top 5 DRY wins (arch-dry):** (1) unify ledger serialization on `Wire`/`derive(Wire)` — ~25 files of bespoke
length-prefix logic deleted; (2) one Merkle in primitives — kills the thesauros/crosscell divergence + an ambiguity
class; (3) one `BoundedMap` — makes the OOM class unconstructible; (4) fold the three allocation-bound variants
(`obolos:308`, `checkpoint:171`, `por:201`) into the shared `Reader`; (5) `encode(ty,body)` ×4 + `SplitMix64` ×5 →
one wire helper + one primitives home.

### §5.B Blockchain core: TAXIS / DROMOS / ledger / SSLE (stream: chain-core) — INTEGRATED

**[HIGH] Round-timeout livelock on large blocks under CPU load (resolves the pass-1 §3.9 mystery, with the correct root
cause).** `taxis_driver.rs:46-50,266` + the consensus ordering path. Chain-core **ran `dromos_quic`**: it **passes in
isolation (8.56 s)** but **livelocks under CPU load** — reproduced deterministically via a block-size sweep (empty→h13,
3.5KB→h10, 7KB→h4, 10.6KB→h1, 13KB→h0 in 19 s): per-height latency is **superlinear in block bytes**. Root cause:
`TIMEOUT_PERIOD=1500 ms` is **wall-clock**, and under `(cores+2)` contention the per-height cost — erasure `da_shards()`
(~4.4 ms) **recomputed per-propose at `taxis_driver.rs:266` *and again* in `verify_structure`**, `reconstruct_payload`
(~5.8 ms), plus the ML-DSA cascade over propose + ~6 prepares + ~6 commits + reveals — **exceeds 1500 ms**, so every round
times out and re-proposes → livelock, total cell halt, no self-recovery while load persists. **Safety is never violated
(no fork).** **The pass-1 §3.9 root-cause hypothesis (T-H1 reveal re-gossip / B1 reveal-auth) was WRONG** — the reveal
fixes work; the stall is in **ordering under load, before any reveal**. **Fix:** cache `da_shards` on the `Block`
(the proposer already computed them — don't re-encode on receive) + an adaptive/larger round timeout + cap block payload
bytes.

**[MED] Slashing & rewards emitted but never applied (T-H5).** `taxis_driver.rs:321-326`: `Output::Slash`/`Reward`
become `TaxisEvent`s only — **no stake/balance mutation**, and there is **no bonded-stake state anywhere** in
TAXIS/DROMOS to slash (`storage.rs:8` "No bond, no staking"; `HybridLedger` has no stake map). Equivocation costs the
attacker nothing on-chain; the Nash equilibrium (`incentive.rs`) is proven abstractly but **unenforced**. **This connects
to the spec-coherence "staking contradiction" (§7.5):** the platform simultaneously says stake secures the substrate
(`platform.md §1.2 L→O`) and forbids capital staking (`§7`), and the code lands on "no stake state at all" — so slashing
has nothing to bite. **Fix:** add a bonded-stake sub-ledger + apply Slash/Reward into executed state (and reconcile the
spec).

**[MED] DA not independently sampled (T-H4).** `taxis_driver.rs:266`: the driver feeds the engine the **proposer's own
full shard set** (`b.da_shards().map(Some)`), so `reconstruct_payload` checks proposer-supplied data, not network
samples. A proposer that gossips a full block to its target validator defeats DA sampling (acknowledged in-code at
`:20-22`). The §6.3/§L4.3 DA guarantee is not live on the consensus path. **Fix:** sample shards from peers, not from the
proposer's attachment.

**[LOW] T-H2 no explicit unlock rule** (`consensus.rs:1028,1423`): `locked_block` clears only on finalize/sync, no
unlock-on-higher-prepared-cert; advances via re-lock on each new prepared cert, so not currently wedge-able (partition MC
passes) — theoretical residual. **T-H3 keyper censorship: bounded/OK** (`incentive::can_permanently_censor` false within
`f`; machine-checked).

**SSLE secret-leader election — SAFE & live, does NOT break BFT (CONFIRMED, corroborating the auditor's preliminary
read).** No two leaders can both drive a commit at one height/view: the min-ticket only changes **which** block an honest
validator PREPAREs; each still sends **≤1 PREPARE per `(height,round)`** (`sent_prepare` idempotence,
`consensus.rs:900,912`), so quorum-intersection is untouched — two conflicting prepared certs would need >7 prepares from
7 validators. Split round-0 prepares only waste a view → round-1 public fallback (a **liveness** cost, not a fork); the
`ssle_..._never_fork` Monte-Carlo (24 Byzantine + async trials) passes. The ticket is **unpredictable & non-grindable**:
`H(vrf_output‖SEED‖height‖round)` with `vrf_output` a **Merkle-VRF/iVRF (RFC-9381 full uniqueness)**, root pre-registered
before the beacon (`pqvrf.rs:16` — one leaf per epoch, no argmin grind, unlike `H(ML-DSA-sig)`), the unbiasable SEED
blocking pre-aiming; `verify_witness` pins `index = height − base` and `root = roots[proposer]`
(`consensus.rs:795-802`). The collection window is bounded (`COLLECT_WINDOW_TICKS=1` + all-members early-exit +
never-empty-when-open + an independent round-timeout backstop) → no wedge of its own (it shares only the HIGH-1 load
fragility). **Verdict: the SSLE addition is architecturally sound and does not regress consensus safety.**

**§3.4 — FIXED.** Non-zero floors are present at the right layer (`hybrid.rs`, the open/lock sites, not `token.rs`):
`lock_htlc` rejects `amount==0` (`:133`); `open_deal` rejects `price==0` and requires `payment.amount==price`
(`:276-294`). Terminal-state pruning is present + deterministic: `finalize_lapsed_deals` retains only `Active` (`:390`),
`begin_block` retains only `Locked` HTLCs (`:593`). Map growth now costs refundable locked capital, self-pruned on lapse.

**§3.7 — FIXED (access lists complete).** Chain-core audited **every** `hybrid.rs` access list against the keys each tag
actually writes — all are conservative supersets, and **`TREASURY` is now declared for the shielded-fee case**
(`hybrid.rs:468`, the pass-1 fix). TAG_TRANSPARENT/SHIELDED/NAME/SHIELD/STORAGE(Open/Prove/Close)/HTLC(Lock/Claim/Refund)
all check out; conditional party keys are omitted only when the op fails and writes nothing; same-block pending
deals/htlcs are tracked in the `access_lists` forward pass. Scheduler determinism (BTreeMap/BTreeSet, no clock/thread
leak) + serial-equivalence verified. **So the §3.7 latent-fork risk is closed at the declaration level** — the DROMOS
scheduler is still unwired (§7.2), but wiring it live no longer forks on the TREASURY omission.

**T-M1..M4 cross-cell:** not deep-dived by chain-core (surface read only) — flagged as **not covered** this pass.

### §5.C Anonymity + storage (stream: anon-storage) — INTEGRATED

**Anonymity headline-path verdict: `.fanos` NO, clearnet TCP NO, clearnet UDP NO** — end-to-end anonymity does not work
today, but **not because of a client-side leak** (those are fixed): because **nothing hosts the service side of the
rendezvous**. The Direct profile works but reveals the client coordinate (the CLI says so honestly).

**Major good news — the prior-audit §5 client-side leaks are ALL fixed** (verified by the stream at `file:line`):
- **S1-C1(a) UDP clearnet — FIXED:** `dial_udp` now routes through `establish` (`diaulos.rs:512`), shared with TCP.
- **S1-H1 cover-from-startup — FIXED:** `cell_node.rs:181-185` forwards `StartHeartbeat` to the relay router, and
  production builds it `.with_cover(cover_interval)` (`node.rs:480`).
- **S1-M2 proxy epoch-pinning — FIXED:** `Node::live_beacon()` (`node.rs:553`) exposes `(epoch,beacon)`, consumed by
  `build_proxy_dialer` (`fanos.rs:401-403`).
- **S1-H3 cookie correlator — SUPERSEDED by NOSTOS:** production dial uses a dead-drop reply (`reply_keys.open` +
  `select_drop_line`), no relay registration, no SURB; the client coordinate never leaves the node.
- **S1-M1 holonomy on the peel path — FIXED:** `circuit_line_holonomy` keyed MAC verified on `Deliver`
  (`threshold.rs:295,322-325`).

**[CRITICAL — anonymity] No production node completes an anonymous session end-to-end.** The client-side stack is
correct and fully wired (§5.C good-news above) — `FanosDialer::anonymous_dial` computes `meeting = meeting_line(exit_public)`
(`rendezvous.rs:261`) and rides threshold onions there via `Command::Emit` (`rendezvous.rs:122`) — **but there is no
anonymous endpoint to answer it, so the dial hangs to timeout.** Three disjoint host situations, none of which serves the
anonymous client (exact chain, confirmed by the anonymity stream):
1. **The clearnet exit is Direct-served, not anonymous.** `spawn_exit_role` → `serve_exit` (`node.rs:301` → `exit.rs:102`)
   runs the **Direct `serve` loop**, which dispatches on `Notification::Delivered{from}` at the node's **own coordinate**
   (`diaulos.rs:143-144`); neither `exit.rs` nor the exit role references `meeting_line`/`RendezvousService` — the exit
   publishes its key and is **dialed by coordinate** (`spawn_exit_publisher`, `exit.rs:331`). So onions aimed at
   `meeting_line(exit_public)` reach no endpoint.
2. **The generic anonymous `.fanos` rendezvous has no production host** — `RendezvousService::new` exists only in
   `tests/anonymous_quic.rs:264,370` + a calypso TODO.
3. **The hosted CALYPSO `ThresholdService` (`node.rs:498`) is a *different, client-less, reply-unwired* protocol** and
   does **not** rescue it: (a) it ingests `FrameType::RdvIntro` carrying a `SealedIntro` (CALYPSO threshold-decrypt,
   `threshold_service.rs:245`, `service_node.rs:72`) — a **disjoint frame vocabulary** from the client's DIAULOS
   `ClientSession`-over-onions, so it can't answer it; (b) **no production client** builds a `SealedIntro`/`RdvIntro`
   (`intro_frame` `threshold_service.rs:268` + `SealedIntro::seal` have **zero production callers**); (c) **no reply
   last-mile** — `ThresholdService` only surfaces the request as `Notification::Delivered{from: ANONYMOUS}`
   (`threshold_service.rs:217-220`) and its docs say "reply sealing is the application's" (`:28-30`); that application
   loop (consume → drive session → `seal_reply`) is the **test-only** `anonymous_service` (`tests/anonymous_quic.rs:169-229`).

So the client-side anonymity machinery is entirely wasted for lack of a server. **Design decision required:** the meeting
combiner `combiner_for(meeting_line(service_public))` is a function of the **key, not the node's coordinate**, so a
service is generally **not** at its own meeting combiner (the test cheats by placing the node at `nodes[l_index]`).
Production needs either a `RendezvousRelay` at the meeting-combiner coord that forwards peeled `Deliver` payloads to a
registered service, **or** service anchoring at that coord, re-registered each epoch (the meeting line rotates with the
beacon). **Fix:** port `tests/anonymous_quic.rs::anonymous_service` (169-229) into `src` as a production `serve_anonymous`
+ an anonymous `serve_exit`, wire into `spawn_exit_role` (`node.rs:301`), and add a hidden-service CLI verb
(`bin/fanos.rs` has only node/proxy/vpn/id/beacon-deal/resolve).

**[HIGH] POROS ingress: identity-binding `from == req.requester` unenforced.** `on_request` (`poros.rs:625`) checks
PoW+Sybil on `req.requester` (a frame-body field) but never against the arriving transport `from`; `IngressNode::step`
(`ingress_node.rs:104-111`) routes by frame-type only and drops `from` (the host's own doc at `poros.rs:161-163` says the
caller MUST check). **Trigger:** anyone sends a `PorosRequest` claiming an arbitrary requester coord with a self-ground
PoW (PoW is public) → amplified DoS (each forged request opens a gather, fans `PorosShareReq` to all `q+1`, fills the
`pending` cap of 256) + breaks the "non-transferable identity-bound" property censorship-resistance rests on.
**Bounded:** the response is sent `to: requester` (`:690`), **not** to the forger, so the descriptor bucket is **not
disclosed** — DoS + invariant break, not leakage. POROS is **not deployed** (only tests construct it), so latent — but
must be fixed before the ingress role ships. **Fix:** decode `PorosRequest` in `ingress_node.rs:104` and drop unless
`req.requester == from`.

**[MED] 3-member anonymity set in the F2 base cell (S1-M4).** `nostos.rs:78` + all rendezvous pinned to `F2` (q=2) →
receiver hidden 1-of-3, meeting line 3 members. Not a leak (the construction is sound) but weak vs a cell-local
adversary. Fix is **compositional** (multi-cell / larger planes for sensitive traffic), not a point patch; document
per-cell anonymity-set size as first-class.

**[MED] Unauthenticated mix-key store slots → liveness-fault DoS (S1-M3).** `publish_mix_key` (`mixdir.rs:50`) writes
onion keys to `mix-key/coord/epoch` without slot-owner authentication (`mixdir.rs:16-19` admits it), and
`require_self_certified_membership` (`overlay.rs:166`) is false-by-default + gates membership not slot ownership.
**Trigger:** overwrite the 7 cell coords' key slots each epoch. **Not deanonymization** (a forged key only makes that
member unable to peel → the circuit re-draws with `t` genuine members) but **perpetual forced liveness faults** degrade
the anon path. **Fix:** bind the published mix key to its cert-derived coord (reject the `put` unless the writer identity
hashes to `coord`), the hardening `mixdir.rs:19` already names.

**[LOW/MED] Threshold-onion `ct_len` hop-position leak (S1-M6).** Documented + transport-mitigated (`threshold.rs:83-104`);
packet size is constant (`THRESHOLD_ONION_LEN=20480`) so a passive net observer sees nothing, but the per-layer
`ct_len`/`members` header is cleartext (`threshold.rs:234,255`), so a **peeling relay** learns its hop position/depth
(a traffic-analysis aid, not next-hop identity — below-threshold ZK + holonomy still hold). Relies entirely on QUIC for
observer-hiding. **Optional fix:** flat-header Sphinx-style per-layer length encryption.

**NOSTOS / POROS / T4 are in CODE with tests, not docs-only** (verified): NOSTOS (`nostos.rs` — `select_drop_line`,
`seal_to_receiver`/`ReplyKeys`, `seal_reply`, tested for receiver-only open + below-threshold ZK + the pairwise-meet
trap); POROS (ingress line, identity-bound non-transferable PoW, threshold-sharded descriptor + sealed resharing, Sybil
cap composed with PoW); T4 Anytrust-escape (`nyx/security.rs` — `chernoff_break_bound` + `kl_divergence`, tested that the
bound dominates the exact combinatorial tail). These are analysis/claim-validating functions of the right shape, not
runtime mechanisms.

**Storage:** §3.3 **FIXED** (the `challenge`/`open_deal` caps the auditor deferred are present: `challenge` clamps
leaves+`k` to `MAX_AUDIT_LEAVES=1<<20` at `por.rs:74-75`; `open_deal` bounds `size≤MAX_DEAL_SIZE`, `k≠0`,
`duration≤MAX_DEAL_DURATION`, `price≠0` at `hybrid.rs:276-284`). §3.5 **FIXED**. **§3.6 residual CONFIRMED (the auditor's
instinct was right):** the leaf encoding did **not** become provider-unique — `seal_object` (`object.rs:41`) seals under
the *object's* fresh key, and leaves are content-addressed ciphertext replicated across the `[7,3,4]` cell. The only
change was the fresh per-epoch `ProverAuth`, which binds the **payee** (provider key) + response but **not the holder**.
So a provider that deleted its copy can still fetch the leaves from a sibling replica, produce the response, sign, and
collect — **proving access, not possession.** Because the data stays retrievable cell-wide, this is an **intra-cell
free-rider nuance (downgrade to LOW)**, not a durability/possession break — but the property is genuinely still open.
**Full fix:** encode leaves under a provider-unique key so only the designated holder can answer.

### §5.D Crypto / keygen / POROS (stream: crypto-keygen) — INTEGRATED
Stream corroborated §2.1 (§3.1 CRITICAL, with the 2-coalition exploit + `beacon.rs:1251` test evidence — now folded into
§2.1), §2.2 (§3.2 fixed, with a hand re-derivation: ternary `r` ⇒ `A₁·r ≤ 2⁶⁹ ≪ i128`, and the recomputed
`r_balance ∈ [−1021,1021] ⇒ ≤ 2⁷⁹`), and §4 (StallDetector correct; RGC path sound). Tests run green: `fanos-obolos`
37/37, `fanos-keygen` 19/19, `fanos-primitives::shamir` 9/9. New finding:

**[HIGH → live-when-the-driver-lands] §5.D-1 — POROS descriptor-reshare accepts forged, unverified contributions.**
The POROS/CALYPSO reshare is raw Shamir over GF(256) with **no commitment/verifiability** and the wired receive path
authenticates nothing. Three compounding gaps:
- **(a) forged sender/`old_x`:** dispatch `poros.rs:727-728` decodes `(epoch, old_x, sealed)` and calls
  `self.on_reshare(epoch, old_x, &sealed)` **without the transport `from`**; `on_reshare` (`:583`) never checks that
  `from` is the old-line member at `old_x`, and `old_x` is pure wire data (`decode_reshare`, `:760`).
- **(b) no binding verification:** `on_reshare` opens the sealed sub-share (`:594`) and combines via
  `combine_descriptor_reshares → combine_reshares → shamir::combine_contributions` (`shamir.rs:204`) — a blind Lagrange
  sum with **zero check** that each contribution is a correct re-split of old member `old_x`'s real share. No
  Feldman/Pedersen anywhere in `fanos-primitives::shamir` or `fanos-calypso::hosting`. (Contrast: the *beacon* reshare
  *does* verify — `verify_reshare_commit` + `verify_share` + self-check — and would refuse to adopt.)
- **(c) first-writer-wins gather:** `ctx.gather.entry(old_x).or_insert(sub)` (`:597`).

> **Trigger:** a new-line member `V` publishes its KEM key in the roster (`hosting.rs:352`). After `V` calls
> `begin_rotation` (`:574`), any unprivileged remote node (need **not** be an old-line member) seals garbage to `V`'s
> published key and floods `PorosReshare` frames for `old_x ∈ {1..threshold}`, beating the honest members
> (`PorosReshare` has no PoW/rate-limit, unlike `PorosRequest` at `:627`). `open_service_share` succeeds (genuinely
> sealed to `V`), garbage is gathered, and once `gather.len() ≥ threshold` `V` combines and **adopts** a share on a
> polynomial `H′` with `H′(0) ≠ descriptor` (`:606-609`). **Consequence:** one remote node corrupts any new-line
> member's rotated share → the new line cannot reconstruct the ingress descriptor → **POROS ingress DoS** for that epoch,
> defeating the `t`-of-`(q+1)` fault tolerance the design claims (confidentiality is preserved — sealing holds — so this
> is a *DoS/integrity* break, not exfil).

**This is latent only because the rotation *trigger* driver is unwired (§7.1) — but the receive/dispatch path IS wired,
so it becomes live the instant §7.1 lands.** The engine test (`poros.rs:1185`) covers only the honest path + a stale-epoch
drop; forged-`old_x` / garbage-sub-share / first-writer poisoning are untested. **Fix:** (1) pass `from` into
`on_reshare` and require `from == old_line_coord_for(old_x)` (the beacon-derived `ingress_line(community, prev_epoch,
beacon)`, same derivation `begin_rotation` uses); (2) add verifiable resharing — a hash-based vector commitment over the
evaluations (there is no group in GF(256)) or lift descriptor custody to the Ristretto VSS the beacon already uses, and
verify each opened sub-share against it before combining; (3) floor `new_threshold ≥ 2` in `emit_reshare`/
`shard_service_key` (`poros.rs:544`, `hosting.rs:62`) — `shamir::split` only rejects 0, so `threshold=1` gives degree-0
= every new member reconstructs the descriptor alone (same class as the beacon exfil).

**POROS resharing verdict: NOT production-safe.** The CHURP continuity *algebra* is correct
(`H(0)=Σλₖ·f(old_xₖ)=f(0)=S`) and KEM-sealing correctly protects sub-share **confidentiality** in transit — but it is
"CHURP-style" in name only: it **omits CHURP's entire verification layer** (unauthenticated trigger + unverified
contributions). The `hosting.rs:20-34` "dealt-and-sealed not DKG" justification holds for *bootstrap* (one trusted
operator-dealer) but **explicitly does not cover resharing**, whose dealers are the mutually-distrusting old-line members
— exactly the adversarial-dealer case that needs verifiability. Proactive-security refresh holds only if old shares are
erased each epoch: `Share` is `ZeroizeOnDrop` (`shamir.rs:64-70`), but the (unbuilt) driver must actually drop old shares
on rotation — **a driver requirement to flag.**

**[HIGH — NEW, latent] §5.D-2 — the ShieldedProof relation omits `public_recipient` → fund-redirection landmine.**
`fanos-obolos/src/tx.rs`: `TransparentProof::verify` (`:124-191`) **never references `tx.public_recipient`** (field at
`:70`). It binds `public_value` in the balance term (`:190`) but **not who receives it**. `public_recipient` is
transmitted (`codec.rs:208,234`) and committed into the tx, but the *proof relation* — the statement the ZK backend must
mirror — omits it. **Trigger:** for an unshield (`public_value > 0`), an attacker copies the victim's public tx fields +
proof, swaps `public_recipient` to its own account, and rebroadcasts; `verify` still passes (recomputed `balance_r` is
unchanged; `public_recipient` isn't in the relation). Both txs share the nullifiers → whichever consensus orders first
wins, the victim's original is rejected as a double-spend, and **the unshielded funds are redirected to the attacker
(theft).** **Not exploitable today** — unshield-crediting is unbuilt (`fanos-dromos/src/bridge.rs:17` "every (future)
unshield debits"), but it becomes **live theft the instant the ledger reads `tx.public_recipient` to credit an unshield.**
**Fix:** fold `public_recipient` into the proof relation (a bound message in `verify` + the pinned ZK statement), or bind
it under an outer sender signature over the full tx before any crediting. **Must be closed before unshield-crediting is
wired.**

**[MED — NEW] §5.D-3 — the O-H2 nonce-hygiene fix was not propagated to the calypso sealing layer.**
`fanos-calypso/src/hosting.rs:164-183` `seal_share_to_member` derives **both** the KEM-encapsulation RNG
(`SeedRng::from_seed(member_seed)`) **and** the AEAD nonce (`derive_nonce(label, member_seed)`) deterministically from
`member_seed`, and the AEAD key `= H(label‖session)` is likewise a deterministic function of it — so `(key, nonce)` is a
pure function of `(label, member_seed)`, with `member_seed = kem_seed ‖ i`. **If a caller reuses `kem_seed`** across two
seals of different plaintexts (two deals, a retried reshare, or `seal_reshare_contribution` `poros.rs:281` with a
repeated seed), member `i` gets identical `(key, nonce)` over different data → **ChaCha20-Poly1305 two-time-pad** (leaks
the XOR of two Shamir sub-shares) + Poly1305 forgery. The O-H2 fix switched `fanos-obolos/note_cipher.rs:98` to a live
`&mut CryptoRng`; **the same pattern persists un-hardened in every calypso sealer** (`deal_service_key`,
`SealedIntro::seal`, `seal_reshare_contribution`), enforced only by caller discipline. **Fix:** mirror O-H2 — take a live
`CryptoRng` for the KEM encapsulation (fresh per seal), or bind a fresh per-seal salt into `member_seed`; add a
debug-assert / doc contract that `kem_seed` is single-use.

**[MED ×4] O-M1–O-M4 — all STILL OPEN (verified unchanged):**
- **O-M1** — nullifier `= H(nsk‖cm)`, **not** `PRF(nsk, position)` (`nullifier.rs:37-42`, `note.rs:72-73`): two leaves
  with identical `cm` share one nullifier ⇒ only one is spendable (spend-lock), bound solely to `rho` uniqueness. **Fix:**
  bind the nullifier to the note's tree position (Zcash-Orchard).
- **O-M2** — the anchor set is **insert-only unbounded** (`state.rs:54,197`), folded into `state_root` ⇒ grows forever =
  state-bloat DoS. **Fix:** a rolling window of the last N roots.
- **O-M3** — **collapsed key hierarchy**: one `nsk` is both owner-authority and nullifier key, and the proof **reveals
  `nsk`** (`tx.rs:95`) ⇒ no viewing-key-only capability, so the `platform.md §4.5` selective-disclosure option is
  impossible without full spend authority. **Fix:** split into (spend, nullifier, incoming-viewing) keys (Sapling/Orchard).
- **O-M4** — **stealth addresses unimplemented**: `derive_owner_pk` is a *static* per-recipient owner (`note.rs:22-25`);
  the advertised one-time keys don't exist. On-chain unlinkability still holds (hiding commitment + fresh KEM ct), but two
  spends by one recipient reveal the same `nsk` in the transparent proof ⇒ **linkable-on-spend**. **Fix:** implement the
  KEM-derived per-payment owner key, or stop advertising it in the docs.

**StallDetector wiring — CONFIRMED sound (this closes the §4.1 open question).** The crypto stream traced the full path:
beacon emits `Effect::Notify(BeaconReady)` (`beacon.rs:330`) → effect pump `notify_tx.send` (`driver.rs:1039-1040`) →
forwarder `events_tx.send` (`:546`) → `client.subscribe()` (`:499`) → watcher `on_note` (`node.rs:252,260,182`). **So
`BeaconReady` does reach `on_note`; there is no delivery gap** (the only caveat is a >4096-deep broadcast backlog →
`Lagged`, unrealistic). Therefore §4.1 is purely the `on_tick` **gate** composing a correct detector with a decision
function that routes the frozen state to Regime B — the architectural defect stands, and it is *not* a detector bug.

**OBOLOS still-sound (do-not-regress), re-verified by the stream:** O-C1 inflation cap (`MAX_NOTES_PER_TX=1021`, the
`D∈(−Q,Q) ∧ D≡0 ⇒ D=0` integer argument, enforced on the apply path `state.rs:187`); O-C2 value-bound re-randomization;
O-H1 fee conservation (`verify_balance`, `tx.rs:190`); O-H2 fresh seal key+nonce *in obolos*; hybrid signature checks
Ed25519 **and** ML-DSA-65 (no PQ downgrade); the ShieldedProof seam binds every field **except** `public_recipient`
(§5.D-2); the *beacon* reshare sub-share verifiability (`verify_reshare_commit`/`verify_share`, `vss.rs`) that the POROS
path lacks.

---

## §6. Simulator experiments (auditor-run, empirical)

Two experiments were driven through `fanos-sim` on the pinned tree (temporary test, since removed; results reproduced
2/2). They validate the #1-priority claims *empirically*, not just by code-reading.

**P1 — returning-node recovery.** A `4-of-7` beacon cell; crash 4 anchors (below threshold), then `recover()` them.
```
after mass-loss:  tick = None, None          # R-C1 freeze reproduced
after return:     tick = Some(Epoch 3), Some(Epoch 4)   # clock RESTARTS
```
→ the beacon engine **self-heals on churn-rejoin**; the freeze is permanent only for permanent loss (see §4.3 caveat).

**P2 — malicious `t'=1` reshare (the §3.1 shape).** Inject
`reshare_trigger(gen=1, new_threshold=1, contributors=[1,2,3,4], new_indices=[7])`:
```
after malicious reshare:  tick = Some(Epoch 3), Some(Epoch 4)   # clock UNDISTURBED
```
→ the `MIN_RESHARE_THRESHOLD=2` floor **rejects** the exfiltration-shaped trigger; the beacon is unaffected —
empirical confirmation of the §2.1 fix.

**Simulator-as-platform note.** The `fanos-sim-experiment` CLI is real but registers **only one** scenario
(`diakrisis-resilience`, `bin/experiment.rs:76`); the crown-jewel adversarial scenarios remain siloed in per-crate
`tests/*.rs`. The `Sim` API is capable (`tick_epoch` drives the real DVRF clock; `observe_frames` gives a GPA tape;
`crash`/`recover`/`partition`/`heal`), but the R-H1 membership-lockout class **cannot be expressed** (one occupant per
coordinate), which is exactly why P1's returning-node result is optimistic. **Recommendation:** add a multi-occupant
coordinate model + a `mass_event`/`recover_as` affordance and register the recovery + anonymity-GPA scenarios into the
experiment CLI, so the #1-priority story is a repeatable experiment, not a bespoke test.

---

## §7. Persistent "engine-ahead, driver-behind" gaps (the meta-pattern, current)

Each item below has a **complete, tested engine/library** and **no production driver** — the recurring pattern, verified
at `25b0a6f`:

1. **[HIGH] POROS proactive line-rotation — receive path wired *and unverified* (§5.D-1), trigger driver unwired.** The
   rotation crypto + sans-I/O engine are built and unit-tested, and the **receive/dispatch path is wired** (`IngressNode`
   routes `PorosReshare=0x5A` → `on_reshare` → gather → adopt). But the **trigger** side —
   `emit_reshare`/`begin_rotation` — has **only `#[cfg(test)]` callers** (`poros.rs:1189-1251`): no production driver
   triggers rotation at an epoch boundary or discovers the new line's KEM keys (the commit message's own residual:
   *"the remaining reshare work is now only the driver loop"*). So a live ingress line **does not rotate its descriptor
   per epoch** and the CHURP proactive-security property is not achieved end-to-end. **Critically, the wired-but-unverified
   receive path is the §5.D-1 [HIGH] DoS surface** — so the driver loop **must not** be added without first adding the
   requester-binding + contribution-verification of §5.D-1, or wiring it converts a latent finding into a live one.
   **Fix:** add §5.D-1's verification, *then* the epoch-boundary driver loop (+ erase old shares on rotation).
2. **[MED] DROMOS parallel scheduler — proven, unwired (access lists now complete).** `execute_block` (deterministic +
   serial-equivalent + double-spend-safe, stochastically tested) has **only test callers**; consensus runs serial
   `execute → apply` (`consensus.rs:1332`, `chain.rs:106`). Zero throughput benefit today. **The pass-1 §3.7 latent-fork
   risk is now closed:** chain-core audited **every** `hybrid.rs` access list and confirms all are conservative supersets,
   with **`TREASURY` now declared** for the shielded-fee case (`hybrid.rs:468`). So wiring the scheduler live no longer
   forks on that omission — the remaining work is purely dispatching waves onto a thread pool (the reference runs them
   in index order). **Fix:** wire the scheduler to gain the throughput the "high-speed L1" claim (`platform.md §3`)
   promises; keep the access-list-completeness discipline as new tags are added.
3. **[MED] Telemetry differential privacy — built, unwired.** `dp.rs:142 privatize(...)` has **no production caller**
   (only `tests/`). The DP export path (C7) is not on any live telemetry surface. **Fix:** call `privatize` on the
   telemetry egress with the configured `PrivacyBudget`.
4. **[HIGH — spec release-gate] The Γ-viability gate is unbuilt.** `spec/platform.md §9(6)` and §1.3 name a
   Γ-calculator (`architecture/` companion) computing `P/R/Φ/D` as *the platform's CI-checked release gate* — the
   analogue of the network's `fanos_verify.py`. **No `architecture/` dir, no calculator, no CI step exists.** The
   platform's viability verdict (`P≈0.36, R≥1/3, Φ≈1.6, D≥2.3`) remains an honest `[C]` construction over declared
   budgets (`platform.md:49,284`), never a measurement. This is spec-acknowledged `[P]`, but it is the single largest
   *architectural-completeness* gap and the only way to make "in the viability window" reproducible.
5. **[MED] Coherence-layer gaps (re-confirmed, sharpened):** the "staking contradiction" is now concrete — chain-core
   confirms **there is no bonded-stake state anywhere** (`storage.rs:8` "No bond, no staking"; `HybridLedger` has no stake
   map), so **slashing/rewards are emitted but have nothing to bite** (T-H5, §5.B), and the "stake read literally"
   (`platform.md §1.2 L→O`) vs "FANOS forbids capital staking" (`§7`) tension is unresolved *by omission* (no stake at
   all). Admission is PoW/Sybil-cap only. Also unbuilt: the Ω2 aspect-budgets / Ω9 CALM classes / `SUBJECT_DEPTH_MAX`
   remain design-only. **Fix:** decide the staking model (add a bonded-stake sub-ledger, or excise slashing and state the
   PoW-only security budget), then reconcile the spec.

---

## §8. Spec-compliance assessment (`spec/protocol.md`, `spec/platform.md`)

The spec is **exemplary in honesty** — every nontrivial claim carries a `[T]/[C]/[H]/[P]/[И]` tag, and the platform doc
explicitly flags its own load-bearing risks (§10: the PQ shielded proof `[P]/[H]`, the Γ-numbers as `[C]`, the
"high-speed L1" as a program). **The implementation does not contradict the spec** — the wiring gaps in §4/§7 are all
consistent with the spec's `[C]` ("built, not fully live") / `[P]` ("program") tags. The audit's value here is the
tension between the spec's *permitted staging* and the project's *standing engineering discipline*
(`no-deferring-implement-fully`, `verified-or-it-doesn't-ship`, `pursue-ultimate-best`): the `[C]→live` and `[P]→built`
transitions in §4/§7 are precisely the deferred last-miles the discipline says must close.

- `platform.md §9`: *"each lands green (workspace tests + clippy --all-targets -D warnings) before the next."* — **holds
  at HEAD** (§0). Good.
- `platform.md §4.3`: the OBOLOS accounting around the `[P]` shielded proof is claimed "verified now" — consistent with
  the confirmed soundness of O-C1/O-C2 (pass 1) + §3.2 (this pass); the ZK backend is the honest isolated `[P]`.
- `platform.md §7` THESAUROS PoR `[T]` soundness bound `k ≥ λ·ln2/(−ln(1−f_tol))` — the storage stream should confirm
  the `challenge` implementation matches this derived `k` (and enforces it as an upper *and* lower bound — pass-1 §3.3's
  unbounded-`k` arm).

---

## §9. Prioritized remediation queue (for the fixing agent)

**Tier 0 — security: one live CRITICAL + two latent landmines to close before their enabling driver lands**
1. **§2.1 [CRITICAL] Authenticate the `BeaconReshareTrigger`** (sign it via the existing `HybridVerifier` authority;
   `beacon.rs:706-727` + `on_reshare_trigger`), and as an unauthenticated fallback change `beacon.rs:386` to
   `new_threshold < self.threshold` (a reshare may raise/preserve, never lower). Update the `beacon.rs:1251` test. Closes
   the 2-coalition master-key exfil; the now-live auto-trigger makes it urgent.
2. **§5.D-2 [HIGH → theft-when-wired] Bind `public_recipient` into the ShieldedProof relation** (`tx.rs` `verify` + the
   pinned ZK statement) **before** unshield-crediting is wired (`dromos/bridge.rs`). Otherwise the first unshield-credit
   is redirectable theft.
3. **§5.D-1 [HIGH → DoS-when-wired] Verify + bind the POROS reshare receive path** *before* wiring its driver (§7.1):
   pass `from` into `on_reshare` and require `from == old_line_coord_for(old_x)`; add a hash-based commitment check on
   each contribution; floor `new_threshold ≥ 2`; erase old shares on adopt.

**Tier 1 — user priority #1 (recovery last-mile) + anonymity headline**
4. **§4.1** Drive Regime A (proactive reshare) off membership-thinning, independent of the (correct) stall detector.
5. **§4.2** Wire the two RGC legs (authority issues on escalation; a frame handler consumes via `rebootstrap`) so
   below-threshold recovery is autonomous, not a manual operator runbook. (The crypto + fork-safety design are correct.)
6. **§4.3 / R-H1** Close membership-reintegration so returning/new identities reclaim slots safely (and make it
   expressible in the multi-occupant sim, §6).
7. **§5.C [CRITICAL-anonymity] Host a production anonymous `RendezvousService`** at the meeting-combiner coord (make the
   design decision: a `RendezvousRelay` at `combiner_for(meeting_line(key))` that forwards to a registered service, vs
   service anchoring; re-register each epoch), wire into `spawn_exit_role`, add a hidden-service CLI verb. Also bind
   `from == req.requester` in POROS ingress (`ingress_node.rs:104`).

**Tier 2 — make the platform actually run, and perform**
8. **arch-dry #1 [HIGH] Wire a validator role into the shipped binary** — promote `fanos-dromos`/`fanos-obolos` from
   dev-deps to real deps, add a config-gated role in `bin/fanos.rs` calling `spawn_taxis::<F, HybridLedger>`, expose via
   FFI. Today the `fanos` binary runs no blockchain.
9. **§5.B HIGH-1 [HIGH] Fix the round-timeout livelock** — cache `da_shards` on the `Block` (don't re-encode on receive),
   adopt an adaptive/larger round timeout, cap block payload bytes.
10. **§7.1** POROS epoch-boundary rotation driver (after Tier-0 #3). **§7.2** Wire the DROMOS scheduler (access lists are
    now complete — §5.B). **§7.3** Wire telemetry `privatize` on the egress. **§7.4** Build the Γ-viability gate
    (`architecture/` + CI). **§5.D-3** propagate the O-H2 live-RNG nonce fix to the calypso sealers. **§5.C S1-M3**
    authenticate mix-key store slots.

**Tier 3 — correctness tail + the reuse mandate + breadth**
11. **Value-tier correctness:** O-M1 (position-bound nullifier), O-M2 (bounded anchor window), O-M3 (split key
    hierarchy + viewing keys), O-M4 (stealth addresses); T-H4 (sample DA from peers, not the proposer); T-H5 (add
    bonded-stake state or excise slashing + reconcile the spec).
12. **The reuse mandate (user headline):** adopt `Reader::seq`/`read_map` everywhere (§3.1); **one Merkle in
    `fanos-primitives`** (kills the thesauros/crosscell divergence *and* the CVE-2012-2459 ambiguity class); unify ledger
    serialization on `derive(Wire)`; introduce `BoundedMap`; extract `ThresholdSealed` into a low-layer crate; split
    `runtime/overlay.rs` (mechanical) and decompose `fanos-node`; delete the `encode()`×4 / `SplitMix64`×5 copies; add a
    `Generation` newtype.
13. **Anonymity depth:** S1-M4 (per-cell set size / multi-cell composition), S1-M6 (flat-header per-layer length
    encryption).

---

## §10. Verified-sound this pass (do-not-regress)
**Fixes confirmed:** §3.2 ternary defense-in-depth; §3.3 `decode_response` + `challenge`/`open_deal` caps; §3.4 non-zero
floors + terminal-state pruning; §3.5 `settle_epoch` cadence; **§3.7 all access lists complete (TREASURY declared)**;
§3.9 `--all-targets` build+clippy green; the §3.1 *single-member* exfil floor + binding + generation-windowing (the
2-coalition variant remains — §2.1); the entire **client-side anonymity leak set** (S1-C1a UDP profile, S1-H1 cover,
S1-M2 epoch, S1-H3 via NOSTOS, S1-M1 holonomy). **Sound designs:** SSLE secret-leader election (safety preserved, MC-
proven — §5.B); the reshare continuity crypto + `verify_reshare_commit`/`verify_share` binding; `RecoveryAuthorization`
PQ cert (floored + fenced) and `rebootstrap`; the `StallDetector` logic *and* its `BeaconReady` wiring; the OBOLOS
accounting core (O-C1/O-C2/O-H1/O-H2, hybrid sig no-downgrade) except the `public_recipient` relation gap (§5.D-2); the
shared `Reader`/`read_map` bounded codec; the crypto-wrapper reuse (`hash_labeled`/AEAD/Shamir/NodeId/VRF-layering all
single-homed — §5.A); the clean 5-layer dependency DAG; the deliberately-feature-gated `observatory → sim` coupling; the
POROS + DROMOS **engine** correctness (sound — only their drivers are missing). NOSTOS/POROS/T4 and the crown-jewel
scenarios are real code with tests, not docs. The committed recovery sim suite (5/5) and the auditor's two sim
experiments pass; `fanos-obolos` 37/37, `fanos-keygen` 19/19, `fanos-primitives::shamir` 9/9 green.

---

*Method appendix.* Pinned to `25b0a6f`. The auditor ran build / clippy `--all-targets` / the recovery suite / two live
`fanos-sim` experiments this session, and re-verified §0, §2.1–§2.5, §3.1–§3.3, §4, §6, §7 at `file:line` (with hand
re-derivation of the §2.1 Lagrange/degree-0 exfil and the §2.2 `i128` overflow bound). §5.A–D breadth is from four
independent **read-only** streams (architecture/DRY, blockchain-core, crypto/keygen/POROS, anonymity/storage), each of
which ran targeted tests and returned `file:line` findings; the streams **corroborated** every auditor finding they
overlapped and **added** the `public_recipient` landmine (§5.D-2), the round-timeout livelock root-cause (§5.B), the
test-only chain wiring (§5.A), the O-M residuals, and the precise anonymity-host scope (§5.C). The four streams and the
auditor independently confirm the audit modified no production code.

**The central lesson of this pass:** the remediation since pass 1 was real — the worst DoS (§3.2) and the storage/access-
list/§3.4/§3.7 classes are genuinely closed, the client-side anonymity leaks are fixed, and SSLE is safe — **but the
frontier has moved from "missing library" to "missing driver," and that shift hides three sharp edges:** (1) one live
CRITICAL (the 2-coalition beacon exfil) that the partial §3.1 fix left open; (2) two latent correctness landmines
(`public_recipient` theft, POROS reshare corruption) that go live the instant their drivers land — and one of those
drivers (`6d81506`) landed *during this audit* without its guard; (3) an entire value tier and anonymity host that are
test-only, so the platform's headline claims ("high-speed private L1", "ultimate anonymity") are not yet runnable
end-to-end. **The two user priorities turn on closing those production last-miles *with* their security guards, and on
authenticating the one remaining reshare surface — not on new cryptography.**
