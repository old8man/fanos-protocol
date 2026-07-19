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

- **Self-certifying geometry.** A node's coordinate is `MapToPoint(H(cert))` — identity *is* position, so an
  address cannot be forged or seized without breaking the hash. Sybil, eclipse, and coordinate-hijack all
  reduce to "grind a hash," which is priced.
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
| A6 | **Slowloris / connection pinning** (open, never finish) | Stream concurrency cap bounds memory; explicit RST/abort + idle-retire to reclaim slots | 🟡 | #60 ✅ (cap); #69 ⬜ (RST/idle-timeout) |
| A7 | **Amplification** (small request → large response/broadcast) | Constant-size cells; reliable-broadcast echo bounded; response ≤ request by protocol | 🟡 | audit — verify no super-unit fan-out remains |
| A8 | **Retransmission storms / spurious retransmit** | RTT-estimated RTO + fast-retransmit (replace tick-as-RTO) | ⬜ | #69 |

## B. Routing & topology attacks

| # | Threat / attack surface | FANOS fundamental answer | Status | Verified / owned by |
|---|---|---|---|---|
| B1 | **Sybil** (flood fake identities) | Coordinate = `H(cert)` → identities are hash-grinding-priced and land uniformly; cell membership is `q+1`-bounded per line | ✅ | `sim/tests/sybil_cost.rs`: `E[T]=N` per seat, coupon-collector `N·(H_s−H_{s−t})`, χ²-uniformity — cost is `Θ(N·log)`, so real Sybil resistance needs a per-admission cost |
| B2 | **Eclipse** (surround a node with adversarial peers) | Neighbours are *derived* from the plane (`lines_through(coord)`), not discovered — an attacker cannot choose a victim's peers without owning those exact coordinates | ✅ | `sim/tests/eclipse.rs`: neighbour-set invariant under forged floods; eclipse ⇒ B1 coordinate-seizure (only crashing the witness's coordinate severs it) |
| B3 | **Routing/DHT poisoning** (false routes/records) | Self-certifying records; responsible-point routing is algebraic (`u×v`), not gossiped. The **hierarchical routing table** learned from flooded announces is guarded by self-certified membership on TWO axes: (a) an address is seeded only if it is the announcer identity's own derived chain (`address_matches_identity`) — **attraction** costs `≈ N^k` grinding, not one announce; (b) the descriptor `coord ‖ hier ‖ id` carries a **hybrid signature** (Ed25519 ‖ ML-DSA-65) the identity produced, so a peer cannot re-announce another identity's address at its own coordinate — closing the **transport hijack** without that identity's private key | ✅ | `fanos-quic::directory` collision-detect ✅; `sim/tests/hier_poisoning.rs` (live engine rejects address-poison AND a signed-descriptor hijack; ungated both succeed in one announce; attraction forge-cost calibrated to the `N^k` wall — 0 full forges, ≤8 two-level near-forges in 3000 grinds at `N=57`); DHT-record poisoning D7 ✅ |
| B4 | **Partition / netsplit** | Fiedler `λ₂ = 0` detected (`Verdict::Partition`); fragment operates degraded, escalates the cut to the parent for cross-cell repair | 🟡 | `partition.rs` ✅; live cross-cell repair path 🟡 |
| B5 | **Coordinate hijack / seizing** | Not possible without a cert hashing to that point (self-certifying); a collision relocates the newcomer by sub-cell descent into a coordinate it derives from its *own* cert, never shadowing the occupant | ✅ | `geometry::hierarchy` + `quic::hierarchical_coordinate` (`tests/subcell_descent.rs`: real cert collision → descent); overlay `RouteHier` routing over hierarchical addresses ✅ (`runtime::overlay` greedy longest-prefix + self-organizing JOIN auto-seed; `sim/tests/hierarchical_routing.rs`: multi-level descent, fail-closed hole, auto-seed) |
| B6 | **Churn / high turnover** | LRC repair + regeneration heal departures within the `Φ→Φ/9` budget; quorum-by-line tolerates `≤ t` losses | ✅ 🟡 | `plan.rs`/`healing.rs` ✅; churn-rate sim 🟡 (#47) |
| B7 | **Congestion collapse** (goodput → 0 under load) | Backpressure at admission (`Δ`) + flow control; the whole cell load-balances (A3) | 🟡 | #62 |

## C. Anonymity & traffic analysis

| # | Threat / attack surface | FANOS fundamental answer | Status | Verified / owned by |
|---|---|---|---|---|
| C1 | **Timing / traffic-confirmation (flow correlation)** | **Constant-rate** cover: a real forward *displaces* a cover cell (audit E6) so emitted volume is independent of real traffic; secret-keyed mix delays; anonymity set `λ/μ` | ✅ | `aphantos/tests/flow_correlation.rs` (leak slope dE/dN: 0.667 additive → **0.000** constant-rate) |
| C2 | **Content-length / digest correlation** | Constant-size cells; padding indistinguishable from data | ✅ 🟡 | cells ✅; C4 content-digest gap 🟡 (#65) |
| C3 | **Predictable beacons / mix from public coord** | Mix schedule/delays must not derive from the public coordinate | ⬜ | #61 (E5/E6) |
| C4 | **Sender/recipient linkability** | Threshold onions (APHANTOS), computed meeting line (CALYPSO), symmetric-forward routing, cookie demux | ✅ 🟡 | anonymous path ✅ (wired); forward-secrecy both directions 🟡 (#61 E4) |
| C5 | **Statistical disclosure / intersection over epochs** | Epoch rotation unlinks *appearances*; against an enumerating adversary, **cover + the per-service anonymity set** make a service's line active independently of the target, erasing the disclosure signal | ✅ | `calypso/tests/statistical_disclosure.rs` (SDA advantage 0.904 undefended → −0.058 defended) |
| C6 | **Guard discovery / entry enumeration** | Membership is geometric, not a public list; entry set per-client | ✅ | `calypso/tests/entry_unlinkability.rs` (uniform, unguessable, epoch-unlinkable, avalanche) |
| C7 | **Telemetry deanonymization** (self-observation leaks) | Cell-granular floor; differential-privacy on exported coherence | ⬜ | #65 (C7) |
| C8 | **Active tagging / tamper-and-trace** (flip bits to mark a flow) | Per-hop ChaCha20-Poly1305 AEAD: any tamper fails the tag at the first relay and is dropped; padding is regenerated per hop | ✅ | `aphantos/tests/onion_tamper.rs` (0 surviving tags over every core byte-flip) |
| C9 | **Replay path-confirmation** (re-inject a captured cell to confirm a relay is on-path) | Bounded per-relay replay cache keyed on `sealed::replay_tag` (drops a recurring cell before decap); relay-key rotation (E4) is the second line | ✅ 🟡 | `aphantos/tests/replay_attack.rs` (replay dropped, distinct cells forwarded); E4 rotation ⬜ (#61) |
| C10 | **Predecessor attack** (identify the initiator by counting predecessors over repeated circuits) | A stable per-client **guard** (`build_circuit_via_guard`): a fixed first hop pins exposure to guard-compromise (~`f`, once) instead of ~`f` per circuit; the interior still rotates | ✅ 🟡 | `nyx/tests/predecessor.rs` (guardless exposure 1.000 → guarded 0.325 ≈ f); guard-set + slow rotation ⬜ |

## D. Byzantine faults & integrity

| # | Threat / attack surface | FANOS fundamental answer | Status | Verified / owned by |
|---|---|---|---|---|
| D1 | **Byzantine lying about state** | Polar sum-rules `r_ij = ρ_{π(i,j)}` hold iff the wiring is Fano — a liar *localizes* to a polar class (T-226) | ✅ | `polar.rs` (14 free alarms), tests |
| D2 | **Non-finite / poisoned observables** (evade detection) | Non-finite rates treated as violations, not passes; rejected at the coherence boundary | ✅ | #59 |
| D3 | **DKG Byzantine breaks** (keygen) | Signed frames + reliable-broadcast with originator auth; verifiable shares | ⬜ | #57 (B1-B3,B6; sim-only path today) |
| D4 | **Equivocation** (two faces to two peers) | Quorum-corroborated liveness: a peer is believed alive on gossip only when `quorum` **distinct** witnesses vouch, so an attacker must control `quorum` separate line identities (each a B1-priced coordinate) to forge a liveness face | ✅ | `sim/tests/byzantine.rs`: single liar outvoted (quorum 2) vs the any-witness rule fooled (quorum 1) — AND the exact tolerance boundary `byzantine_tolerance_is_exactly_quorum_minus_one_distinct_witnesses` (2 distinct liars defeated at quorum 3, 3 succeed), so safety holds iff #liars < quorum |
| D5 | **Selective forwarding / data withholding** | Redundancy on `q+1` lines (any hop reachable via a co-linear survivor); repair by peeling | ✅ 🟡 | `plan.rs` LRC ✅; withholding-detection sim 🟡 |
| D6 | **Quarantine correctness** (permanent exile / no-op decouple) | Quarantine + escalate (corpus does not prove exclusion restores wiring); decouple must lower `Φ` | 🟡 | #65 (C5/C6) |
| D7 | **DHT poisoning** (overwrite/forge a stored record) | The overlay store is mutable, so integrity is at the record: descriptors are address-gated **AEAD-encrypted**, **self-certifying** (`H(bundle)==addr`), epoch-bound, and stored at an unenumerable rotating slot `H(addr‖epoch)` — a poisoned/forged/tampered/replayed blob is rejected on `open` | ✅ | `calypso/descriptor.rs` (tamper→Aead, forge→NotCertified, wrong-addr→Aead, cross-epoch→Aead, PoW) |

## E. Cryptography

| # | Threat / attack surface | FANOS fundamental answer | Status | Verified / owned by |
|---|---|---|---|---|
| E1 | **Harvest-now-decrypt-later (quantum)** | Hybrid `X25519 + ML-KEM-768` handshake, transcript-bound combiner | ✅ 🟡 | handshake ✅; combiner-transcript B5 🟡 (#63) |
| E2 | **Nonce / seed reuse** (leaks secrets) | Per-cell explicit monotone nonce (fresh per retransmit); synthetic DLEQ nonce | ✅ ⬜ | cells ✅; B4 DLEQ + E3 descriptor-nonce ⬜ (#58) |
| E3 | **Side channels** (non-constant-time on secrets) | Constant-time `GF(256)` on secret shares; `subtle`/`zeroize` | ⬜ | #63 (A6/B7) |
| E4 | **Downgrade / MitM** | Transcript binds service identity; ephemeral-KEM forward secrecy | ✅ | handshake (audit "excellent") |
| E5 | **Nonce-counter wrap** | Hard connection-kill at the AEAD nonce limit | ⬜ | #66 |

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
