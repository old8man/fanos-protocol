# Large distributed anonymity networks — the complete threat & challenge model

> The systematic sweep the project demands: enumerate **every** class of problem and attack surface that
> large distributed / anonymity networks face, and for each state FANOS's **fundamental** answer, its
> **verification status**, and where the work lives. This is the master index for iterative hardening —
> "gather all problems, surface all attack surfaces, iteratively find the best verified solution." Rows are
> honest: ✅ = derived + verified (test/theorem), 🟡 = partial / in progress, ⬜ = gap with an owning task.

Companion to [`audit.md`](audit.md) (the code-level defect audit), [`ddos-homeostasis.md`](ddos-homeostasis.md)
(the worked availability derivation), and [`coherent-cybernetics.md`](coherent-cybernetics.md) (the organism
theory). The discipline: **no speculative solutions** — every ✅ points at a theorem or a test; every 🟡/⬜
points at a task, not a hope.

---

## The stance — why a projective organism answers these at the root

Most of the surfaces below are, in classical designs, patched independently. FANOS collapses many into *one*
structure, which is why the answers compose instead of conflicting:

- **Verifiable self-certifying geometry.** A node's coordinate is `MapToPoint(VRF(vrf_sk, id ‖ epoch ‖ beacon))`
  (A7/#66 Level A, base cell) — identity *is* position, the VRF key is committed in the identity so the
  coordinate is unforgeable, and folding the epoch beacon makes it unpredictable-until-revealed so it cannot
  be **pre-settled** onto a target's lines. Sybil, eclipse, and coordinate-hijack reduce to grinding a keyed
  VRF against an unpredictable reshuffle, which is priced. (Multi-level hierarchy addressing is still the #79
  hash-chain pending Level B — see `docs/design-coordinates.md`.)
- **`PG(2,q)` incidence.** Any two points meet in one line ⇒ `O(1)` rendezvous, quorum-by-line, LRC repair,
  and load diffusion with no local extrema — one identity behind routing, availability, and healing.
- **The coherence self-model (DIAKRISIS).** The network observes its own `Γ`, so DoS, Byzantine faults, and
  partitions surface as *coherence* signals with theorem-fixed thresholds and a leading indicator that fires
  a regime before failure.
- **One dissipative dynamics.** Availability (homeostasis), integrity (immune response), and healing
  (regeneration) are the three terms of one generator (T-258), so defence-in-depth is structural, not bolted.

---

## A. Availability, DoS, and resource exhaustion

| # | Threat / attack surface | FANOS fundamental answer | Status | Verified / owned by |
|---|---|---|---|---|
| A1 | **Volumetric DDoS** (valid-but-excessive load) | Lindblad admission controller: super-linear PoW pricing, excitation relaxes at the derived spectral gap `Δ`; attacker aggregate cost `∝ C³` | ✅ | `fanos-calypso::stabilize`, 10 sim scenarios |
| A2 | **Coherence/self-model DDoS** (`h^(D)` noise) | The T-104 coherence homeostat: survive iff `‖δΓ₂‖ < κ_bootstrap/2 = 1/14`; ISS + exponential return | ✅ | `fanos-diakrisis::homeostat` + `dynamics` sim; `ddos-homeostasis.md` |
| A3 | **Load hotspots / local extrema** (whole net unused) | Projective line-averaging diffusion: unique uniform fixed point, exact `λ₂ = q/(q+1)²` contraction, no stall | ✅ | `fanos-diakrisis::loadbalance` |
| A4 | **State-exhaustion DoS** (memory: streams, buffers, waiters) | Receiver flow control anchored on `delivered`; stream cap + retire; sender reclaim; request timeouts | ✅ 🟡 | #60 ✅ (streams); #62 🟡 (waiter maps, backpressure) |
| A5 | **Algorithmic-complexity DoS** (non-finite `Φ` → hang) | Reject non-finite coherence at the boundary; bounded reroute-depth loop | ✅ | #59, `coherence`/`healing`/`polar` |
| A6 | **Slowloris / connection pinning** (open, never finish) | Stream concurrency cap bounds memory; and at the QUIC **connection** layer a **per-source-IP inbound cap** (one host holds ≤ `1/16` of the 512 slots, so monopolizing takes many hard-to-spoof source IPs) **+ a handshake deadline** (a connection that stalls before proving a coordinate is dropped). An *established* link is never reclaimed for silence — it may back the #119 reverse-reachability path | ✅ | #60 ✅ (stream cap); **#69 ✅** — `fanos-quic::driver` `admit_source` / `SourceGuard` (per-source cap, unit-tested) + `HELLO_DEADLINE` timeout wrapping establishment in `accept_loop`; the real-QUIC suite (loopback / hole-punch / self-certifying) is unaffected |
| A7 | **Amplification** (small request → large response/broadcast) | Constant-size cells; reliable-broadcast echo bounded; response ≤ request by protocol; the `Announce` flood is bounded by two structural gates — a member coordinate must be a **canonical projective point** (so `members` ≤ plane size `N`) and the **monotone guard** re-floods only on first sight | ✅ | `sim/tests/amplification.rs`: a **replayed** announcement re-amplifies **zero** frames (monotone guard), **forged non-canonical** coordinates are dropped before any re-flood (20 injects → ≤20 delivered, no fan-out), and a flood of announcements for every point stays a bounded `O(N)` epidemic — no super-unit / unbounded fan-out |
| A8 | **Retransmission storms / spurious retransmit** | An RTT-estimated RTO (Jacobson/Karels `srtt`/`rttvar`, bounded exponential backoff) replaces tick-as-RTO, and fast-retransmit resends a gap on the dup-ACK threshold without waiting for the RTO | ✅ | `runtime/stream.rs`: `the_rtt_estimator_converges_to_a_stable_rto`, `an_in_flight_segment_is_not_resent_before_its_rto`, `back_off_is_bounded_by_a_multiple_of_the_base_rto`, `fast_retransmit_resends_the_gap_without_waiting_for_the_rto` |

## B. Routing & topology attacks

| # | Threat / attack surface | FANOS fundamental answer | Status | Verified / owned by |
|---|---|---|---|---|
| B1 | **Sybil** (flood fake identities) | Coordinate = `MapToPoint(VRF(sk, epoch‖beacon))` (A7) → placement is keyed-VRF-priced, lands uniformly, and **reshuffles unpredictably each epoch** so a grinded seat cannot be *maintained* (no pre-settling); cell membership is `q+1`-bounded per line | ✅ | `sim/tests/sybil_cost.rs`: `E[T]=N` per seat, coupon-collector `N·(H_s−H_{s−t})`, χ²-uniformity (uniformity holds for the VRF output too) — per-epoch placement cost is `Θ(N·log)`, so real Sybil resistance still needs a per-admission cost on top. **The cross-epoch "no pre-settling" property (spec §3.2 assumption 2, the load-bearing anti-eclipse premise) is now measured over the real VRF machinery — `sim/tests/anti_eclipse_reshuffle.rs`**: seat-retention across an epoch reshuffle collapses to chance (a grinded seat is NOT maintained — nearly every identity moves), the placement stays χ²-uniform (no seat easier to pre-aim), and seizing a chosen coordinate costs a full ~N regrind that must be re-paid every epoch (no amortization). **The beacon underpinning that reshuffle now resists an active *anchor* adversary over the running cell — `sim/tests/beacon_adversary.rs`**: a forged (biased-`σ`) partial is DLEQ-rejected and cannot steer the seed, and a silent/withholding anchor cannot block it (threshold liveness + subset-independence `σ = x·M`), so the reshuffle's unpredictability holds against a Byzantine anchor, not just a passive observer |
| B2 | **Eclipse** (surround a node with adversarial peers) | Neighbours are *derived* from the plane (`lines_through(coord)`), not discovered — an attacker cannot choose a victim's peers without owning those exact coordinates | ✅ | `sim/tests/eclipse.rs`: neighbour-set invariant under forged floods; eclipse ⇒ B1 coordinate-seizure (only crashing the witness's coordinate severs it) |
| B3 | **Routing/DHT poisoning** (false routes/records) | Self-certifying records; responsible-point routing is algebraic (`u×v`), not gossiped. The **hierarchical routing table** learned from flooded announces is guarded by self-certified membership on TWO axes: (a) an address is seeded only if it is the announcer identity's own derived chain (`address_matches_identity`) — **attraction** costs `≈ N^k` grinding, not one announce; (b) the descriptor `coord ‖ hier ‖ id` carries a **hybrid signature** (Ed25519 ‖ ML-DSA-65) the identity produced, so a peer cannot re-announce another identity's address at its own coordinate — closing the **transport hijack** without that identity's private key | ✅ | `fanos-quic::directory` collision-detect ✅; `sim/tests/hier_poisoning.rs` (live engine rejects address-poison AND a signed-descriptor hijack; ungated both succeed in one announce; attraction forge-cost calibrated to the `N^k` wall — 0 full forges, ≤8 two-level near-forges in 3000 grinds at `N=57`); DHT-record poisoning D7 ✅ |
| B4 | **Partition / netsplit** | Fiedler `λ₂ = 0` detected (`Verdict::Partition`); fragment operates degraded, escalates the cut to the parent for cross-cell repair | 🟡 | `partition.rs` ✅; live cross-cell repair path 🟡 |
| B5 | **Coordinate hijack / seizing** | Not possible without a cert hashing to that point (self-certifying); a collision relocates the newcomer by sub-cell descent into a coordinate it derives from its *own* cert, never shadowing the occupant | ✅ | `geometry::hierarchy` + `quic::hierarchical_coordinate` (`tests/subcell_descent.rs`: real cert collision → descent); overlay `RouteHier` routing over hierarchical addresses ✅ (`runtime::overlay` greedy longest-prefix + self-organizing JOIN auto-seed; `sim/tests/hierarchical_routing.rs`: multi-level descent, fail-closed hole, auto-seed) |
| B6 | **Churn / high turnover** | LRC repair + regeneration heal departures within the `Φ→Φ/9` budget; quorum-by-line tolerates `≤ t` losses | ✅ 🟡 | `plan.rs`/`healing.rs` ✅; churn-rate sim 🟡 (#47) |
| B7 | **Congestion collapse** (goodput → 0 under load) | Admission backpressure whose relaxation rate is **derived from the cell's own spectral gap `Δ`** (the `LindbladLoadController`, `τ = 1/Δ` shared with healing) prices entry up under load without collapsing, plus stream-level flow control | ✅ | `sim/tests/calypso_ddos.rs`: a determined flood stabilizes at a ceiling without runaway, legit clients are still served *through* the flood if they pay, a distributed flood is stabilized the same, and the line relaxes to the floor after the flood ends |

## C. Anonymity & traffic analysis

| # | Threat / attack surface | FANOS fundamental answer | Status | Verified / owned by |
|---|---|---|---|---|
| C1 | **Timing / traffic-confirmation (flow correlation)** | **Constant-rate** cover: a real forward *displaces* a cover cell (audit E6) so emitted volume is independent of real traffic; secret-keyed mix delays; anonymity set `λ/μ` | ✅ | `aphantos/tests/flow_correlation.rs` (leak slope dE/dN: 0.667 additive → **0.000** constant-rate); **now also over the running network — `sim/tests/traffic_analysis.rs`**: a **global passive adversary** taps every frame's metadata `(t,from,to,len)` on the simulated wire (`Sim::observe_frames`/`FrameObs`) and runs the volume leak-slope attack over the real routed+mixed+cover cell — undefended interior relay slope > 0.5, constant-rate cover collapses it to < 0.25 (the C1/§8.2 GPA claim, no longer only a crate-local harness) |
| C2 | **Content-length / digest correlation** | Constant-size cells; padding indistinguishable from data | ✅ 🟡 | cells ✅; C4 content-digest gap 🟡 (#65) |
| C3 | **Predictable beacons / mix from public coord** | The mix-delay and cover-tick schedules derive from a **secret** `mix_seed = kem_secret.derive_subkey(…)`, never the public coordinate — so a global passive adversary who knows a relay's coordinate cannot recompute its `D(1), D(2), …` sequence to relink a hop's in/out flows (audit E2) | ✅ | `aphantos/threshold_router.rs::the_mixing_delay_is_secret_keyed_not_a_public_function_of_the_coordinate` (same coord + two different secrets → different schedules; deterministic per secret for sans-I/O replay) |
| C4 | **Sender/recipient linkability** | Threshold onions (APHANTOS), computed meeting line (CALYPSO), symmetric-forward routing, cookie demux | ✅ 🟡 | anonymous path ✅ (wired); forward-secrecy both directions 🟡 (#61 E4) |
| C5 | **Statistical disclosure / intersection over epochs** | Epoch rotation unlinks *appearances*; against an enumerating adversary, **cover + the per-service anonymity set** make a service's line active independently of the target, erasing the disclosure signal | ✅ | `calypso/tests/statistical_disclosure.rs` (SDA advantage 0.904 undefended → −0.058 defended) |
| C6 | **Guard discovery / entry enumeration** | Membership is geometric, not a public list; entry set per-client | ✅ | `calypso/tests/entry_unlinkability.rs` (uniform, unguessable, epoch-unlinkable, avalanche) |
| C7 | **Telemetry deanonymization** (self-observation leaks) | The export boundary is ε-**differentially private**: the cell's sufficient statistic `r` is Laplace-noised at the *derived* sensitivity `Δr = 1/21` (one flow is one of the 21 cell pairs), Φ/P/R and the verdict are re-derived from the noised `r` by post-processing (no extra ε), and the exact syndrome / spectral gap / heal-event / forecast fields are **withheld** (the cell-granular floor). The full-resolution frame stays internal for self-healing | ✅ | `fanos-telemetry::dp` (`CoherenceFrame::privatize`); `telemetry/tests/differential_privacy.rs` — a raw frame is a deanonymization oracle (advantage ≈ 1), the private frame's optimal distinguishing advantage collapses to the **analytic Laplace bound `1 − e^{−ε/2}`** (matched to ±0.03 over 40 k trials), the syndrome/event fields are withheld, and the noised statistic is unbiased (utility preserved) |
| C8 | **Active tagging / tamper-and-trace** (flip bits to mark a flow) | Per-hop ChaCha20-Poly1305 AEAD: any tamper fails the tag at the first relay and is dropped; padding is regenerated per hop | ✅ | `aphantos/tests/onion_tamper.rs` (0 surviving tags over every core byte-flip) + **`sim/tests/tagging.rs`** over the running mixnet: with every interior relay tampering each forwarded onion, the tampered cell is AEAD-rejected downstream and never reaches the service (control: the honest cell delivers), so tagging cannot link a circuit's in/out sides |
| C9 | **Replay path-confirmation** (re-inject a captured cell to confirm a relay is on-path) | Bounded per-relay replay cache keyed on `sealed::replay_tag` (drops a recurring cell before decap); relay-key rotation (E4) is the second line | ✅ | `aphantos/tests/replay_attack.rs` (replay dropped, distinct cells forwarded); **E4 rotation ✅ (#61)** — `fanos-pqcrypto::OnionKeyRatchet` per-epoch forward-secure onion keys (bounded grace window) wired into `ThresholdRouter`, so a recorded cell is unpeelable once the relay ratchets past its epoch |
| C10 | **Predecessor attack** (identify the initiator by counting predecessors over repeated circuits) | A stable per-client **guard**, generalized to a slowly-rotating **guard set** (`fanos-nyx::GuardSet`): an ordered, **primary-first** set keeps exposure ≈`f` (the primary carries every circuit while up — *not* the `1−(1−f)^k` union bound a naive "any of k" set suffers), falls back to a **stable backup** under churn (availability without reopening the attack), and re-draws only on a coarse `epoch/rotation_period` **window** (slow rotation bounds lifetime exposure) | ✅ 🟡 | `nyx/tests/predecessor.rs` (guardless 1.000 → single-guard/guard-set ≈ f; the primary-first set matches single-guard exposure, **not** the union bound; survives primary churn) + `nyx::guard` unit tests (distinct/ordered set, window-stable slow rotation, primary-first failover). **Live `NyxNode` still enters through the single `guard()`** — actuating the set needs an epoch (rotation) + guard-liveness (failover) threaded through the node (residual) |

## D. Byzantine faults & integrity

| # | Threat / attack surface | FANOS fundamental answer | Status | Verified / owned by |
|---|---|---|---|---|
| D1 | **Byzantine lying about state** | Polar sum-rules `r_ij = ρ_{π(i,j)}` hold iff the wiring is Fano — a liar *localizes* to a polar class (T-226) | ✅ | `polar.rs` (14 free alarms), tests |
| D2 | **Non-finite / poisoned observables** (evade detection) | Non-finite rates treated as violations, not passes; rejected at the coherence boundary | ✅ | #59 |
| D3 | **DKG Byzantine breaks** (keygen) | Signed frames + reliable-broadcast with originator auth; verifiable shares | ✅ | `sim/tests/dkg.rs::a_byzantine_equivocating_dealer_is_disqualified_and_honest_nodes_still_agree` (a Byzantine equivocating dealer is disqualified over the sim; honest nodes still agree the key). Residual hardening (Feldman→Pedersen rushing-adversary) tracked in #57 |
| D4 | **Equivocation** (two faces to two peers) | Quorum-corroborated liveness: a peer is believed alive on gossip only when `quorum` **distinct** witnesses vouch, so an attacker must control `quorum` separate line identities (each a B1-priced coordinate) to forge a liveness face | ✅ | `sim/tests/byzantine.rs`: single liar outvoted (quorum 2) vs the any-witness rule fooled (quorum 1) — AND the exact tolerance boundary `byzantine_tolerance_is_exactly_quorum_minus_one_distinct_witnesses` (2 distinct liars defeated at quorum 3, 3 succeed), so safety holds iff #liars < quorum |
| D5 | **Selective forwarding / data withholding** | Redundancy on `q+1` lines (any hop reachable via a co-linear survivor); a read consults the responsible node and, on its silence, **read-repairs through the replica line** | ✅ | `plan.rs` LRC ✅; **`sim/tests/withholding.rs` ✅** — a heartbeat-green Byzantine node at the responsible coordinate withholds its `Value` responses (control: it dropped ≥1), yet the read is served by a co-linear replica via the silent-replica line-fallback, and the withholder is **never diagnosed as a crash** (D5 is invisible to first-order liveness monitoring — only read redundancy defeats it) |
| D6 | **Quarantine correctness** (permanent exile / no-op decouple) | Quarantine + escalate (corpus does not prove exclusion restores wiring); decouple must lower `Φ` | 🟡 | #65 (C5/C6) |
| D7 | **DHT poisoning** (overwrite/forge a stored record) | The overlay store is mutable, so integrity is at the record: descriptors are address-gated **AEAD-encrypted**, **self-certifying** (`H(bundle)==addr`), epoch-bound, and stored at an unenumerable rotating slot `H(addr‖epoch)` — a poisoned/forged/tampered/replayed blob is rejected on `open` | ✅ | `calypso/descriptor.rs` (tamper→Aead, forge→NotCertified, wrong-addr→Aead, cross-epoch→Aead, PoW) |

## E. Cryptography

| # | Threat / attack surface | FANOS fundamental answer | Status | Verified / owned by |
|---|---|---|---|---|
| E1 | **Harvest-now-decrypt-later (quantum)** | Hybrid `X25519 + ML-KEM-768` handshake, transcript-bound combiner | ✅ | handshake ✅; transcript-bound combiner ✅ (`pqcrypto::kem::combine` folds both shared secrets ‖ X25519 ephemeral ‖ ML-KEM ct ‖ recipient static pk — MAL-BIND-K,PK,CT; `kem::tests::the_combiner_binds_every_transcript_element` flips one byte of each field in place → key must move, closing audit B5 #63) |
| E2 | **Nonce / seed reuse** (leaks secrets) | Per-cell explicit monotone nonce (fresh per retransmit); synthetic DLEQ nonce | ✅ | cells ✅; **B4 DLEQ nonce ✅ (#63)** — `fanos-incentives::synthetic_dleq_nonce` derives `s = H(k ‖ K ‖ B ‖ Z)` deterministically from the issuer secret + transcript (RFC 6979-style), never a caller RNG, so two issuances can't reuse `s` and leak the key |
| E3 | **Side channels** (non-constant-time on secrets) | Constant-time `GF(256)` on secret shares; `subtle`/`zeroize` | ✅ 🟡 | **#63:** constant-time Shamir (B7), `subtle::ConstantTimeEq` on credit redemption (B8), `zeroize` on onion-ratchet + Shamir secrets (A6); **#73:** `VrfSecret` dropped `Copy` + redacted `Debug`. 🟡 residual: `pub` secret fields (encapsulation — a tracked #73 review item) |
| E4 | **Downgrade / MitM** | Transcript binds service identity; ephemeral-KEM forward secrecy | ✅ | handshake (audit "excellent") |
| E5 | **Nonce-counter wrap** | Hard connection-kill at the AEAD nonce limit | ✅ | **#66:** `fanos-diaulos::conn` `next_nonce` uses `checked_add` — at 2⁶⁴ constant-size cells the connection refuses to mint any further cell rather than wrap the nonce (a hard kill), so no `(key, nonce)` pair is ever reused |

## F. Consensus & consistency

| # | Threat / attack surface | FANOS fundamental answer | Status | Verified / owned by |
|---|---|---|---|---|
| F1 | **Split-brain / CAP** | Partition detection + degraded operation + escalation; no global lock on the hot path | 🟡 | `partition.rs`; consensus phase later |
| F2 | **Convergence without a rate bound** (CRDT-style) | Relaxation with a *derived* spectral gap `Δ` (bounded convergence time `τ = 1/Δ`) | ✅ | `regeneration::spectral_gap`, `loadbalance` λ₂ |
| F3 | **Agreement under Byzantine** | Consensus-via-coherence: agreement = `Φ ≥ 1`; Byzantine exclusion = polar quarantine | ⬜ | consensus phase (roadmap) |

## G. Censorship & blocking resistance

| # | Threat / attack surface | FANOS fundamental answer | Status | Verified / owned by |
|---|---|---|---|---|
| G1 | **Active probing / DPI fingerprinting** | PROTEUS adaptive camouflage; indistinguishable cover cells | 🟡 | design; morph-negotiation impl later |
| G2 | **Entry-point enumeration & blocking** | Geometric membership (no public bridge list); capability-negotiated morphs | 🟡 | design |
| G3 | **Total-control / global adversary** | Bounded blast radius: per-cell ISS + `⌊log₉Φ⌋` containment; no operator, no seizable center | ✅ | `ddos-homeostasis.md §7`; `sim/tests/global_adversary.rs` (local footprint, finite tier depth, `⌊log₉Φ⌋` gate) |

---

## Cross-cutting guarantees (the invariants every solution must preserve)

1. **Bounded resources** — every buffer/queue/state map has a proven cap (no OOM under any peer behaviour).
2. **ISS under bounded attack** — coherence returns to the band; the excursion is `O(D/κ)` (T-104).
3. **Blast-radius containment** — a perturbation cannot ripple past `⌊log₉Φ⌋` tiers (the `1/9` budget).
4. **No forced analogy** — symmetric cells use symmetric invariants; asymmetric (SYNARC agent) structure is
   kept separate (`synarc-node-architecture`).
5. **Derive-don't-tune** — one spectral gap `Δ` sets admission relaxation, healing time, and the death clock.
6. **Verified or it doesn't ship** — a mechanism lands with a theorem *and* a deterministic sim/test.

## Gaps → owned tasks (the iteration queue)

Existing audit tasks cover most code-level gaps (#57–#69). This model surfaces **network-science** gaps that
deserve their own verified treatment, tracked as new tasks:

- ~~**Sybil-cost bound (B1):**~~ **done** — `sim/tests/sybil_cost.rs` derives + measures `E[T]=N` per seat
  (coupon-collector for thresholds), grounded in `MapToPoint` uniformity.
- ~~**Eclipse resistance (B2):**~~ **done** — `sim/tests/eclipse.rs` proves the derived-neighbour invariant
  and reduces eclipse to B1 coordinate-seizure on the sim.
- ~~**Guard discovery / entry enumeration (C6):**~~ **done** — `calypso/tests/entry_unlinkability.rs`
  quantifies the entry (rendezvous) line derivation as un-enumerable and unlinkable: uniform over the
  whole line space (no small guard set), unguessable beyond `1/N` without the identity, epoch-rotating
  with no cross-epoch correlation, and avalanche (a near-miss identity reveals nothing).
- ~~**Global-adversary / total-control (G3):**~~ **done** — `sim/tests/global_adversary.rs` measures, on
  the real engine + stratum, that an attack's footprint stays local (the syndrome never blames an honest
  node; a tier reroutes only around attacked cells), the escalation depth is finite (one tier for a
  within-decoder attack, one more for an irrecoverable stopping set, no further), and the reroute budget
  gate is exactly the analytic `⌊log₉Φ⌋`.

Each follows the same discipline: derive the bound, implement the minimal mechanism, validate on
`fanos-sim`, and only then mark it ✅.
