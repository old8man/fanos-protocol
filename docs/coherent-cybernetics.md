# Coherence Cybernetics in FANOS — the theory of self-observing networks

> The meta-theory beneath FANOS is **Coherence Cybernetics (CC)** — "the only complete cybernetics
> strictly derivable from Unitary Holonomic Monism (UHM)" (CC corpus, `introduction.md`), in which a
> system's *dynamics*, *structural integrity*, and *interiority* are "different projections of one and
> the same object — the coherence matrix `Γ`." A system regulates itself *through its own coherence*:
> the regulator and the regulated are one object. This document instantiates CC for anonymous networks
> — its **three-level organismic model**, and why UHM's elegance lets it *discover* optimal
> architectures rather than merely describe one — and is **reconciled to the canonical CC corpus in §9**,
> with FANOS-original extensions marked as such.

Companion to [`design.md`](design.md) (invariants), [`design-platform.md`](design-platform.md)
(architecture), [`design-telemetry.md`](design-telemetry.md) (the minimal-overhead observation theorem),
[`roadmap.md`](roadmap.md) (phases). Where those engineer the network, this names the *discipline* the
engineering instantiates. **Notation.** FANOS writes the coherence density `ρ`/`Γ_net`; the canon writes
`Γ` and reserves `ρ*` for the *self-model target* `φ(Γ)`. Read them as the same object (§9).

---

## 0. The herald — one sentence

**A network should not be *managed*; it should *metabolize* — sense its own coherence and relax back to
health by the same dynamics that make it work.** Coherence Cybernetics is the study of systems for which
"operate," "observe," "heal," "price," "grow," and "evolve" are not separate machineries bolted together
but **one dissipative dynamics read at different time-scales.** FANOS is its first full instantiation.

---

## 1. From cybernetics to Coherence Cybernetics

Classical cybernetics (Wiener, Ashby, von Foerster) gave load-bearing *principles*; CC promotes each to
a *theorem* by giving it a coherence carrier. The canon positions CC as a **metatheory** "from which all
particular cybernetics … are derived as projections onto a subset of dimensions" (`cybernetics-history.md`).

| Cybernetics (classical) | CC carrier (canonical) | In FANOS |
|---|---|---|
| **Negative feedback / homeostasis** | **Regeneration, not decay.** The generator has *three* terms, `dΓ/dτ = −i[H,Γ] + 𝒟[Γ] + ℛ[Γ,E]` (T-258): unitary *work*, the dissipator 𝒟 (*heat* — drains order toward `I/7`, i.e. death), and the **regenerator ℛ** (*matter* — the only term that imports order, relaxing toward the self-model `ρ* = φ(Γ)`). **Healing is ℛ, not 𝒟.** | DIAKRISIS heals a cell back to `ρ*` via regeneration `κ = κ_bootstrap + κ₀·Coh_E`; `τ = 1/λ_gap` is the recovery time (FANOS's `Δ` is the equicorrelated instance of `λ_gap`, `stabilize::from_line_rates`) |
| **Second-order / the observer is in the system** (von Foerster) — *asserted* | **Necessity of Self-Reference (T-7.1) — *proved*:** a viable open system *must* contain `φ` with `‖Γ − φ(Γ)‖ < ε` ("part of `Γ` must model the whole"). Sharpened by **No-Zombie (T-8.1):** `Coh_E ≥ Coh_min > 1/7`, a *derived* minimum self-observation signal that grows with environmental noise. | DIAKRISIS reads `Γ_net` and its verdict *is* a healing input — observer and observed share one `Γ`; a node that stops self-observing stops being viable (T-8.1) |
| **Requisite variety** (Ashby) | **Dimensional:** requisite variety ↔ `dim ℋ = 7` (the minimum for autopoiesis + phenomenology + a quantum base, from `G₂` minimality). *Separately*, the regulation **bandwidth** is the spectral gap `λ_gap` (relaxation `τ = 1/λ_gap`; critical slowing `λ_min → 0 ⇒ τ → ∞`). | the cell is `N = 7`; the admission controller relaxes at the *derived* gap so it out-paces exactly the floods that gap can damp — a FANOS *bandwidth* reading of `λ_gap`, distinct from requisite variety proper |
| **The Good Regulator theorem** (Conant–Ashby) — *"every good regulator must be a model"* | The canon proves this as **T-7.1 + T-113** (learning needs a replacement channel with `R > 0`, else `n* = ∞`); "Good Regulator/Conant–Ashby" is FANOS's *naming* for the CC self-reference results. | `R = 1/(7P) ≥ 1/3` is the readiness gate; equivalently `P ≤ 3/7` — a reflexivity **ceiling** on purity ("dissipation protects reflexivity against an over-rigid ideal"), the *dual* of "afford to know yourself" |

The decisive upgrade is that **von Foerster's and Ashby's intuitions become theorems.** Where classical
cybernetics *asserted* the observer belongs in the system, CC *proves* a viable system must model itself
(T-7.1) and must carry a minimum interiority signal (T-8.1, `Coh_E > 1/7`). The FANOS readiness gate
`Φ ≥ 1 ∧ R ≥ 1/3` is the canon's **L2 viability gate** (which also asks `P > 2/7` and `D_diff ≥ 2`);
`R ≥ 1/3 ⟺ P ∈ (2/7, 3/7]` is the **Goldilocks window** — integrated enough to be a subject, dissipative
enough to stay adaptable. "An integrated subject that can afford to know itself — and not so rigid it
cannot revise itself."

---

## 2. The three-level organismic model

FANOS is an organism in the exact, non-metaphorical sense: **three nested levels of coherence
organization, each a reflexive system running the same dissipative dynamics one tier up, on its own
time-scale, carried by its own coherence density.** The levels are the biological hierarchy —
*cell → organ → organism* — and they are literally the network's `N¹ → N^k → ecology` structure.

### Level 1 — the Cell (metabolism & immunity)

The unit is the projective cell of `N = q²+q+1` nodes (the Fano cell at `q=2`, `N=7`).

- **Density (state):** the coherence matrix `Γ_net = C/N` (`Tr Γ = 1`) — a bona-fide density built from
  the nodes' behavioural correlations (`fanos-diakrisis::coherence`).
- **Dynamics:** the CC master equation `dΓ/dτ = −i[H,Γ] + 𝒟[Γ] + ℛ[Γ,E]` (three terms, T-258). The
  **unitary** `−i[H,Γ]` is normal reversible operation (routing, storage, rendezvous — *work*); the
  **dissipator** `𝒟` is entropy-producing decay toward `I/7` (*heat* — the death the cell resists); the
  **regenerator** `ℛ` is **healing** — the only term that imports order, relaxing toward the self-model
  `ρ* = φ(Γ)` at rate `κ = κ_bootstrap + κ₀·Coh_E`, with recovery time `τ = 1/λ_gap` (FANOS's
  `Δ = (G − max_k T_k)/6` is the equicorrelated instance of `λ_gap`). *DIAKRISIS is `ℛ`, not `𝒟`* — it
  opposes decay, it is not decay.
- **Vital signs:** integration `Φ` (cross-node binding, threshold 1), structure `P = Tr(Γ²)` (purity),
  reflection `R = 1/(N·P)` (self-model), mean correlation `r`, and the recovery time `τ = 1/Δ`.
- **Homeostasis (the immune/metabolic reflex):** DIAKRISIS *sense → act* — reroute (project around a dead
  node along a co-linear survivor), repair (regenerate a shard by peeling), **decouple** (shed correlation
  when over-integrated, `r > 1/√3`), quarantine (excise a structurally-inconsistent liar via the polar
  sum-rules), escalate (hand up what it cannot fix). The **fever line** is `r* = 1/√6 ≈ 0.408`: above it
  the cell enters the cascade regime, and the leading indicator `{P < 2/N} ⊂ {Φ < 1}` fires a *full regime
  before any node fails* (V17) — the cell runs a temperature it can read before it is sick.

This is metabolism (maintain coherence against decay) plus an immune system (detect and excise the
non-self). It is complete and shipping.

### Level 2 — the Organ (self-similar growth & containment)

The unit is a **super-cell**: a `ParentCell` whose `N` points are themselves child cells, recursively to
`N^k` (`fanos-core::stratum`, `hierarchy`).

- **Density:** `Γ` over cells — a coherence matrix whose entries are *inter-cell* correlations. The same
  object, one tier up.
- **Dynamics:** the identical Lindbladian form. **Escalation is the coupling between tiers:** a Level-1
  cell that cannot heal within its budget emits `Escalated(mask)` — an *input* to Level 2's dynamics.
- **Containment is the developmental invariant.** Healing spends a coarse-grained budget that **contracts
  by `1/9` per tier** (`PHI_CONTRACTION`, T-226): a perturbation cannot ripple past a bounded depth. This
  is exactly an organ containing damage — a bruise does not become systemic. It is *also* the
  privacy-composition bound (`ε → ε·9^d`) and the anonymity-locality bound: **one constant governs
  developmental containment, healing locality, and privacy locality** — because they are one dynamics.
- **Specialization:** roles (relay / storage / service / exit) are cell differentiation; a super-cell is
  tissue of differentiated cells.

This is organ/tissue organization — self-similar (fractal) growth where the whole has the same reflexive
architecture as the part. `ParentCell` is built and consumes escalation; the deeper strata are the scale
phase.

### Level 3 — the Organism (identity, nervous system, evolution, ecology)

The unit is the **whole network as one self-observing subject**, plus the **ecology of applications** it
hosts.

- **The genome (identity):** every name, key, coordinate, and protocol-id is a self-certifying
  hash-commitment `H(label ‖ … )` (ONOMA addresses, PIDs). This is DNA: a stable, self-verifying code from
  which the organism's expressed traits are derived. It cannot be forged or seized — the organism *is* its
  genome.
- **The nervous system:** the DIAKRISIS reflexive plane spanning all tiers — the substrate through which
  the organism feels itself and acts. Its signal is coherence; its reflexes are the healing actions.
- **Two adaptation clocks** (this is the organism's aliveness):
  - **Fast — homeostasis:** DIAKRISIS regulates behaviour in real time (route, heal, price admission,
    shed correlation). Milliseconds to epochs.
  - **Slow — evolution:** capability negotiation is the genome *expressing variable traits* (morphs,
    ciphers, cell sizes, protocols) that propagate only if they interoperate (reproduce the KAT vectors).
    *Extension = mutation, interoperation = natural selection.* Releases to eras.
- **Behavioural plasticity:** the anonymity dial (Direct/Lite/Full) is the organism choosing how much to
  hide per act; PROTEUS is adaptive camouflage evading predators (censors).
- **The application ecology:** overlays (messengers, ledgers, web infra) are **symbionts** — hosted as
  `Protocol`s the organism *observes as citizens* of the reflexive loop (a `Γ_app` coherence matrix over
  protocols). The organism regulates its symbionts by the same coherence it uses on its own cells:
  a protocol inducing cross-tenant correlation is *decoupled* exactly as an over-coupled node is.

This is the organism level: a stable identity (genome), a nervous system (reflexive plane), plasticity
(dial, PROTEUS), evolution (selection over capabilities), and a hosted ecology (symbiotic overlays).
Levels 1–2 are built; Level 3's genome and reflexes are built, its ecology and slow clock are the platform
phase.

### The three-fold correspondence (why it is exactly three)

The three levels are not a chosen number — they are the three irreducible aspects of one dynamics:

| Level | Biology | Time-scale | UHM operator | FANOS structure |
|---|---|---|---|---|
| **1 Cell** | metabolism, immunity | ms – s (homeostatic) | the density `ρ` (state) and its dissipator `D` | the Fano cell, DIAKRISIS |
| **2 Organ** | tissue, development, containment | epochs (developmental) | the spectral gap `Δ` (rate, locality `1/9`) | `N^k` stratum, ParentCell |
| **3 Organism** | identity, nervous system, evolution | releases – eras (evolutionary) | the full Lindbladian `L = −i[H,·] + D` (the whole operator) and its genome | the network + capability negotiation + application ecology |

`ρ` (what it is now) · `Δ` (how fast it returns and how far damage spreads) · `L` (the whole law of its
evolution, unitary + dissipative). State, rate, law — three, and only three, because a dissipative system
*is* a state evolving under a law at a rate.

---

## 2A. The self-modeling node — monism at the architecture level

The canon proves (T-7.1) that a viable system **must** contain a self-model `φ` with `‖Γ − φ(Γ)‖ < ε`.
FANOS realizes this not with an *approximate* model bolted on, but with an exact one that falls out of an
architectural fact already true: **`fanos-sim` runs the byte-for-byte same sans-I/O engine as production**
(the determinism contract, `architecture.md`). So a node can embed an instance of *its own engine* as its
self-model — the map is literally a copy of the territory's code. This is **monism at the architecture and
implementation level**: the model and the modeled are one object, so the self-model has **zero structural
mismatch** — `φ(Γ)` is exact, and the Good-Regulator requirement is met not approximately but *with
equality* (the regulator is an *instance* of the system, not a sketch of it). Classical control fights
model-mismatch; here there is none to fight.

Made scalable and provable by **two fidelities** — a pragmatic digital-twin + model-predictive design:

- **The exact twin (deep, occasional).** The node runs its own engine forward on a hypothesis — *what if I
  decouple? what if node k dies? what if this line is flooded?* — a literal deterministic what-if. Zero
  mismatch, reproducible (so a plan is *verifiable*), but `O(engine-step)`, so it drives deliberation, not
  the hot loop. Bounded: one cell, `N = 7`.
- **The reduced-order predictor (cheap, per-tick).** The hot loop forecasts via the *coherence dynamics*
  alone — the linearized CC relaxation of `Γ` in `(Φ, P, R, r)` around the operating point (`τ = 1/λ_gap`).
  `O(1)` per window, error bounded by the linearization near `ρ*`; this is the `forecast_cascade` the
  observatory already computes.

Together they close a **model-predictive sensorimotor loop** — and this is where the sensorimotor idea
grounds *maturely*, not speculatively:

1. **Sense** — read coherence (the 3-bit syndrome + scalars; minimal, `design-telemetry.md`).
2. **Predict** — the reduced model forecasts the trajectory; the exact twin scores candidate actions.
3. **Plan** — choose the action minimizing the stress `‖σ_sys‖_∞` (the canonical minimax, T-11.2 — a
   *ready-made objective with no engineered reward*): decouple / reroute / raise admission `Δ` / escalate.
4. **Act** — the motor outputs are the node's syscalls (emit, reroute, decouple, adjust difficulty).
5. **Learn** — tune only the model's *parameters* (operating point, gap estimate) from prediction error —
   active-inference / free-energy in the CC sense (minimize surprise between model and observation). The
   *structure* stays exact (the engine); only the parameters adapt.

A **SYNARC / neural module** plugs in here as an *optional* planner (step 3) that learns a policy over the
same sense/act interface (sense = coherence feed; motor = datagram/broadcast/reroute; proprioception = the
node's own `Γ`) — sandboxed as a capability-scoped `Protocol`, never a core dependency. The default planner
is the provable MPC minimax; SYNARC is the innovative option on a mature core (the pragmatic split the
architecture demands). This makes each node a small **anticipatory agent** — it does not merely react to
damage, it *foresees* it (leading indicator `{P<2/N}⊂{Φ<1}`, a regime before failure) and acts on a
verifiable plan — and it is the substrate on which many such agents compose into the larger organism
(§2, §12): cells that model themselves, forming an organism that models itself.

---

## 3. Unitary architectures

Why call the derived architectures **Unitary**? Two senses, and they are the same sense.

1. **Operator-theoretic.** The CC generator is **metriplectic** (T-262): "one frictionless rotation plus
   two slides downhill" — the **unitary** `−i[H,Γ]` is a reversible isometry (the network *working*), the
   **dissipator** `𝒟` slides down to `I/7` (*heat*), and the **regenerator** `ℛ` slides toward the
   self-model `ρ*` (*matter* — the network *healing*). A *Unitary architecture* is one whose normal
   operation is the unitary rotation and whose only irreversibility is the deliberate `ℛ`-climb that
   opposes the `𝒟`-decay — no ad-hoc, off-model machinery leaks entropy. The architecture evolves as
   **one operator** with exactly these three channels (a fourth is impossible, T-11.3).
2. **Compositional.** *Unitary* = *a single coherent whole*, not a federation of modules that negotiate.
   Every component is derived from the same three primitives — the coherence quantity `(Φ,P,R,Δ)`, the
   commitment move `H(label‖id‖…)`, and the reflexive cell — so the transport, the privacy composition,
   the tenancy, the monitor, the admission controller, the readiness gate, the reputation, and the
   consensus are *the same quantity measured at different tiers*. Unity is not an aesthetic; it is the
   theorem that these are one dynamics.

The two senses coincide because **coherence is unity**: `Φ` literally measures how much the parts bind
into a whole. A Unitary architecture is one that maximizes its own `Φ` — an integrated subject — which is
precisely the readiness condition `Φ ≥ 1`. *The architecture is Unitary iff it is an integrated subject of
its own coherence.*

This is the sense in which Coherence-Cybernetic architectures "lead to a Cyberpunk epoch" not by aesthetic
but by capability: a self-owning, self-healing, self-observing, censorship-resistant substrate that no
authority operates is the material precondition of that world.

---

## 4. UHM as an architecture-discovery meta-theory

The strongest claim, and the one the user asks us to press: **UHM is not just a description of FANOS; its
mathematical structure is expressive enough to *generate* optimal architectures and to *classify* other
theories as friendly or orthogonal.** The evidence is that FANOS's hardest properties were **derived, not
invented:**

- **O(1) rendezvous** from the projective cross-product `u×v` (any two points determine one line) — not a
  DHT search someone chose, a geometric identity.
- **Threshold-by-geometry:** a hop is a *line* (a Maekawa quorum) because any two lines of `PG(2,q)` meet
  in exactly one point — the quorum-intersection property is the geometry, not a protocol.
- **The cascade threshold `r* = 1/√(N−1)`** from the eigenstructure of the equicorrelated coherence
  matrix — the fever line is an eigenvalue crossing, not a tuned alarm.
- **The healing locality `1/9`** and recovery time `τ = 1/Δ` from the polar sum-rules (T-226) — the
  containment budget is a theorem.
- **The Fano-blindness of pairwise monitoring** from `K₇`'s spectrum `{6, −1×6}` — *why* observation must
  be third-order is forced, not a design taste.
- **The Good-Regulator threshold `R ≥ 1/3`** — the self-model cost is derived.

A theory with this reach is **generative**: hand it the constraints (self-healing, anonymity, scale,
post-quantum, no-authority) and the coherence dynamics + projective geometry *yield* the architecture —
the rendezvous, the quorum, the thresholds, the budgets, the monitoring order. That is what
"mathematically-grounded optimal architecture" means, and it is testable: every such claim is a verifier
(V1–V22, and the new derivations).

**Classifying other theories.** Because UHM carries a coherence functional, it induces a relation on
theories: a theory `T` is **friendly** to UHM if its objects reduce to coherence dynamics (its state is a
density, its optimum a steady state, its stability a spectral gap), and **orthogonal** if they are
independent of coherence. Worked examples the platform will meet:

- **BFT consensus** → *friendly*: agreement is `Φ ≥ 1` on a proposal (an integrated subject commits),
  Byzantine exclusion is the polar-sum-rule quarantine, liveness is `τ = 1/Δ`. FANOS's "consensus-via-
  coherence" is the reduction. (Phase 6.)
- **LRC / erasure coding** → *friendly*: the projective LRC *is* the geometry; regeneration is the
  dissipative repair channel.
- **Mixnets (Loopix/Nym)** → *friendly*: the anonymity set is `λ/μ` (Little's law), a coherence-entropy;
  constant-rate cover is a purity constraint.
- **Proof-of-work / tokenomics** → *orthogonal*: economic scarcity is independent of coherence, hence
  *optional* in FANOS (VOPRF credits are a plug-in, not load-bearing) — the meta-theory tells us where the
  economics can be removed without loss.
- **CRDTs / eventual consistency** → *partially friendly*: convergence is a relaxation, but without a
  spectral gap the rate is unbounded — UHM would *add* the gap the CRDT lacks.

This classification is itself an engineering tool: it tells us which imported ideas fuse into the one
dynamics and which stay modular — so the architecture stays Unitary.

---

## 5. The instrument panel — vital signs of a living network

A living organism deployed on real servers needs a **clinical monitor**, not a log tail. Because FANOS is
self-observing, the instrument panel *reads the organism's own self-model*, at cell granularity (the
anonymity-safe floor, §14 of the platform design). The panel's dials are the vital signs of §2:

- **`Φ` (integration)** — the ECG: is the cell one bound subject (`Φ ≥ 1`) or fragmenting?
- **`r` vs `r* = 1/√6`** — the thermometer with the fever line; the cascade forecast prints *"systemic in
  N ticks"* from the leading indicator, before any node dies.
- **`R` vs `1/3`** — the reflexivity gauge: can the cell still afford to know itself (the Good-Regulator
  budget)?
- **`P` vs `2/N`** — the structure gauge: distance from a formless mesh.
- **`τ = 1/Δ`** — the recovery clock: how fast the cell heals, *derived from its own spectral gap*.
- **The Fano syndrome map** — the 3-bit localization (21→7→3→1 pyramid) highlighting *which* node is
  faulted — a picture no pairwise dashboard can draw (it would be Fano-blind).
- **The healing timeline** — reroute / repair / decouple / escalate events with the `Φ→Φ/9` budget
  depletion, and the coherence history (state over time, the organism's medical record).

This is designed and specified (`design-platform.md §8`); the reference dashboard is a self-contained
Coherence Observatory that consumes `fanos monitor --json` (or OTLP) and renders these dials with
theorem-fixed bands — so an operator reads *coherence*, not CPU, and sees the disease a regime before the
symptom. It is the difference between watching a body's temperature and self-model versus tailing its
syscalls.

---

## 6. Evolutionary modeling — finding the strongest genetics

The organism should be bred, not guessed. Because `fanos-sim` runs the *production* engine
deterministically, we can model the network's future evolution across its architecture space **many
times** and select the strongest genetics — with UHM predicting *why* a genotype is strong:

- **The genotype** is the derivable-parameter vector: field size `q` (cell size `N`), mixing rate `μ` and
  hop count `L`, cover ratio, the spectral gap `Δ` band, the reflection budget, the LRC replication, the
  admission `over_ceil`, the escalation depth.
- **The fitness** is a coherence-grounded score, not an ad-hoc metric: sustained `Φ ≥ 1` and `R ≥ 1/3`
  under the catastrophe/Byzantine/DDoS suites; **cascade lead-time** `forecast.lead()` (larger = more
  warning); anonymity-set entropy `log₂(λ/μ)`; healing recovery `τ`; throughput at a fixed anonymity
  floor. Multi-objective → a **Pareto front**, because privacy/latency/resilience genuinely trade.
- **The search** is an evolutionary loop over seeds and genotypes (mutate the vector, run the suites,
  select the Pareto-strongest, repeat) — an actual genetic algorithm whose *reproduction* is the sim and
  whose *selection pressure* is coherence-under-stress. Run repeatedly across seed sweeps, the
  distribution of survivors *is* the network's strongest genetics.
- **The UHM prediction** closes the loop: theory says the strongest genotypes maximize the spectral gap
  `Δ` (fast healing) subject to `r < r*` (below cascade) and `Φ ≥ 1` (integrated) at the target anonymity
  entropy — so the search is *guided*, not blind, and where the empirical Pareto front and the UHM
  prediction disagree, we have found either a bug or a **new theorem** (an orthogonal/friendly effect UHM
  did not yet see — exactly the "discover theories" the meta-theory promises).

This is the concrete plan for `fanos evolve` (a harness over the sim, roadmap DevEx phase): breed the
architecture, read the winners, and let disagreements with UHM surface new mathematics.

---

## 7. Deployment reality — Coherence Cybernetics on real servers

The theory is not ornamental; it is what makes tomorrow's real-server launch *operable*:

- **Operate by coherence:** `fanos health --readiness` returns `Φ ≥ 1 ∧ R ≥ 1/3 ∧ joined` — a Kubernetes/
  systemd readiness grounded in a proof, not a hand-picked latency threshold.
- **Alert before failure:** the cascade forecast fires a regime early; the panel shows the fever line
  crossed before a node dies — the operator acts on `r → r*`, not on a post-mortem.
- **Heal without operators:** DIAKRISIS reroutes/repairs/decouples autonomically; the operator's job
  shrinks to *watching the self-model and provisioning capacity*, because the organism runs its own
  homeostasis.
- **Upgrade without flag-days:** capability negotiation rolls new traits through the fleet by intersection;
  `fanos upgrade --canary` watches the canary cell's `Φ` stay ≥ 1 before continuing.
- **Reproduce every incident:** the deterministic journal replays a field bug bit-for-bit — a
  post-mortem is a settled fact ("the forecast fired 40 ticks early; the alert existed").

The instruments and mechanisms this requires — `fanos monitor`, the Observatory, `fanos evolve`,
readiness/liveness, journaled replay, OTel export — are specified (`design-platform.md §8`) and are the
DevEx implementation phase.

---

## 8. Positioning — the herald of a Cyberpunk epoch

Coherence Cybernetics is the banner because it names what makes the substrate *unlike everything before it*:
a network that is a self-owning, self-observing, self-healing, censorship-resistant coherent subject —
operated by no authority, understood through one quantity, and evolvable like life. Its architectures are
**Unitary** because they are one dissipative dynamics; its platform hosts an ecology of anonymous overlays
as symbionts; its math is expressive enough to *derive* the optimal and to *recognize* the new. That is the
material substrate of a Cyberpunk epoch — not the aesthetic, the infrastructure: **coherence as the
currency of a networked world that governs itself.**

*Engineering maturity, viability, and the most advanced solutions are the drivers; Coherence Cybernetics is
the theory that keeps them one thing.*

---

## 9. Canonical alignment (the CC corpus)

This document instantiates the canonical **Coherence Cybernetics** corpus (`.../applied/coherence-cybernetics/`)
for anonymous networks. Fidelity notes, so FANOS-original synthesis is never mistaken for canonical result:

**Faithful (direct instances of the canon).** The measures `Φ` (int., `Φ_th=1`), `P = Tr(Γ²)` (`P_crit=2/7`),
`R = 1/(7P)` (`R_th=1/3`); the readiness gate `Φ≥1 ∧ R≥1/3` = the canon's **L2 viability gate**; fractal
self-similarity (**T-9.1/9.2**, "a cell is a holon, an organ is a holon…", invariants preserved under scale
aggregation); the metatheory-as-projection stance (**T-82** `G₂`-rigidity uniqueness); the Fano/Hamming
syndrome decoder (`gap-algebra §3.5`) that FANOS's telemetry theorem uses.

**Corrections applied here (were wrong in an earlier draft).** (a) The generator is **three-term**
`−i[H,Γ] + 𝒟 + ℛ` (T-258), and **DIAKRISIS healing is the regenerator `ℛ` (matter), not the dissipator `𝒟`
(heat, → `I/7` = death)** — the single most important fix. (b) "Good Regulator / Conant–Ashby" is *absent*
from the canon; the self-model requirement is **T-7.1** (Necessity of Self-Reference) + **T-113** (learning
needs `R>0`), and `R≥1/3 ⟺ P∈(2/7,3/7]` is a reflexivity **ceiling/Goldilocks window**, not a duty-cycle
floor. (c) Requisite variety is **`dim ℋ=7`** (dimensional); `Δ` carries the *bandwidth/relaxation rate*
`λ_gap`, a separate role.

**Glossary delta to adopt going forward.** the regenerator `ℛ` + rate `κ=κ_bootstrap+κ₀·Coh_E`; **E-coherence
`Coh_E`** + the **No-Zombie floor `Coh_E>1/7`** (T-8.1) — a *derived* minimum self-observation signal that
grows with environmental noise; the **stress tensor `σ_sys∈ℝ⁷`**, viability `‖σ_sys‖_∞<1` (T-92) — a richer
diagnostic than one scalar, mapping onto per-node syndromes; **effective temperature `T_eff=(Γ₂/κ₀)k_BT`** —
the fever quantity; **stability radius `r_stab=√(P−2/7)`** + Lyapunov contraction (T-104), with T-69 "sudden
death is impossible for small perturbations" underwriting the leading indicator; the **learning/observation
bounds** T-109 (info), T-111 (measurement back-action `ε≤r_stab`), T-113, and the **`Γ`-tomography sample
bound `N ≥ (2c²/Δ²)·ln(1/δ)`** — the canonical "cost of scanning yourself" that grounds `design-telemetry.md`;
**`G₂`-Noether**: 14 charges / 14 Ward identities / 14 sum-rules on the 21 pairwise rates, gauge torus
`U(1)⁷⋊PSL(2,7)` (order 168) — the same `Aut(PG(2,2))` FANOS already uses; the **metriplectic** structure
(T-262) "one rotation + two slides"; the attractor hierarchy `I/7 → ρ*_Ω → Γ*_coh`.

**FANOS-original extensions (consistent with, but not stated in, the canon).** The projective-network results
— `O(1)` cross-product rendezvous, quorum-by-line-intersection, the cascade line `r*=1/√(N−1)`, the healing
locality `1/9`, the `K₇` Fano-blindness of pairwise monitoring, and the **Minimal Self-Observation Overhead
theorem** (`design-telemetry.md`) — are FANOS's own projective-geometry contributions, grounded in the
canon's Fano/`PG(2,2)`/Hamming machinery and its measurement bounds, and presented as extensions, not as
canonical theorems.
