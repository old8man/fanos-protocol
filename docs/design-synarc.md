# FANOS × SYNARC-Ω — the sensorimotor / agentic interface (design)

> How FANOS nodes host **learning sensorimotor agents** — cells that sense their own coherence, act
> by emitting/broadcasting packets, and learn through full closed-loop feedback — and how that
> composes into the larger organism. Designed **pragmatically**: it is the *learning generalization of
> a controller FANOS already has*, built almost entirely from primitives already shipped, with
> **provable safety rails** and clearly-marked keep-out lines. The speculative cognitive-architecture
> machinery stays out of the networking layer by design.

Grounded in the canonical SYNARC-Ω spec (`uhm-theory/.../synarc-omega/paper`) and its coherence-
cybernetics substrate, reconciled with [`coherent-cybernetics.md`](coherent-cybernetics.md) (§2A the
self-modeling node), [`design-platform.md`](design-platform.md) (the Protocol/SDK), and
[`design-telemetry.md`](design-telemetry.md) (the coherence feed).

---

## 0. The finding — FANOS *is* the Ω-organism's distributed deployment

The SYNARC-Ω paper is explicit: **"FANOS is not an analogy over the organism but its distributed
deployment … the substrate for distributed cognition is the organism's own physics one scale up, with
FANOS as its wire"** (Appendix K), including *distributed embodiment* — "an agent's seven sectors may be
threshold-hosted across a FANOS line … an agent with no single physical substrate … whose interoception
is the line's own DIAKRISIS loop." So this is not a bolt-on: the anonymity substrate and the cognitive
architecture share one physics (UHM), and FANOS already ships the substrate the agent needs.

**Decisive corollary:** FANOS already implements SYNARC's mathematical substrate — the *identical*
coherence observables — so a "SYNARC agent" is not a foreign body but the point where a controller FANOS
*already runs* (DIAKRISIS sense→act) is allowed to *learn*.

---

## 0.5. The applied payoff — capabilities other architectures *cannot* have

This is not ornament. The self-model + intrinsic-reward + projective substrate give FANOS a class of
capabilities that competitors cannot bolt on, *because each requires a coherence self-model, sans-I/O
determinism, and the projective structure — which Tor, Nym, I2P, and libp2p structurally lack.* That is
why they would obsolesce, not merely lose a feature race:

1. **Self-tuning healing & admission that is provably safe.** A FANOS cell *learns* the optimal
   reroute / decouple / admission policy for its *actual* traffic — from its own coherence, under a hard
   viability barrier (§5) that guarantees a learner can never harm the cell. Tor and Nym run *fixed,
   hand-tuned heuristics*; they cannot learn safely because they have no self-model and no viability
   certificate to bound a learner. → **obsoletes hand-tuning.**
2. **Anticipatory defense — act a regime *before* failure.** The leading indicator `{P<2/N} ⊂ {Φ<1}`
   plus the cascade forecast give provable warning *before* any node fails or a DDoS lands; the node acts
   ahead of the event. Every reactive system (i.e. everyone else) acts *after* the symptom. → **obsoletes
   reactive defense.**
3. **Zero-parameter, zero-reward self-optimization.** The reward is intrinsic — `dP/dτ`, the approach to
   the self-model — so the network optimizes with *no operator knobs and no external reward field*. This
   is *impossible* without a self-model to differentiate. → **obsoletes ops-tuning.**
4. **An exact digital twin per node (monism).** Every node can simulate itself forward with *zero
   model-mismatch* (§2A) — verifiable what-if planning and bit-exact incident replay. Competitors model
   themselves only approximately (or not at all), so their forecasts and postmortems are guesses. →
   **obsoletes ops-by-guesswork.**
5. **Adaptive distributed mechanisms.** Sensorimotor cells compose into *self-reconfiguring* mechanisms
   (the "proteins → machine" the user names) — a class of adaptive distributed computation a static
   overlay cannot express: the network can grow and re-wire application structure by learning, not by
   redeployment.
6. **One quantity across the whole stack.** Because monitoring = healing = admission = learning =
   reputation = consensus are the *same* coherence quantity at different tiers, the system evolves as a
   coherent unit. A competitor's bolt-on stack — a separate monitoring product, transport, and consensus,
   each maintained apart — *cannot* reach this integration and ossifies under its own seams.

The through-line: capabilities 1–6 are all corollaries of *"the network has an exact, differentiable model
of itself."* No architecture without that can imitate them — which is the practical, not aesthetic, reason
this design matters.

---

## 1. What already exists — the shared substrate

| SYNARC-Ω | FANOS today (crate/file) | Status |
|---|---|---|
| `Γ ∈ 𝒟(ℂ⁷)` coherence state = working memory | `CoherenceMatrix` (`Γ_net = C/N`), `fanos-diakrisis/coherence.rs` | present (real correlation vs complex density) |
| `Φ`, `P`, `R` + thresholds `1`, `2/7`, `1/3` | `phi`/`purity`/`reflection`, `PHI_TH`/`p_crit`/`R_TH` | **identical** |
| `σ_k` channel stress; viability certificate | `Observation.degraded`, `alarm()`, `diagnose()→Verdict` | present |
| generator `−i[H,·]+𝒟+ℛ`; regeneration `κ`, `φ=(1−k)Γ+kρ*`, `k=1−R` | `regeneration.rs` (`regeneration_rate`, `regenerate_toward`, `replacement_fraction`), `healing.rs` (`Φ→Φ/9`) | **identical formulas** |
| spectral gap / recovery `Δ`, `τ=1/Δ` | `spectral_gap()`, `recovery_time()` | **identical** |
| collective-subject window `r ∈ (1/√6, 1/√3]` | `collective_state()` {Aggregate, CollectiveSubject, OverCoupled} | present |
| Sense = Input; Act = Effect; tick = `Instant` | `Engine::step(now, Input) → Vec<Effect>`, `fanos-runtime/ports.rs` | present (the loop) |
| **`V_hed` reward `= dP/dτ`; a *learning* target `ρ*`** | — | **the thin layer a SYNARC module adds** |

The gap between "FANOS node" and "SYNARC agent" is exactly one thing: today the node's healing target and
policy are *fixed theorems* (`regenerate_toward` toward a fixed `ρ*`, `plan_healing` by rule); a SYNARC
module makes the **target `ρ*` and the action policy learned**, by relaxing them with the *same* Bures/
regeneration operator — so learning and healing are literally one mechanism, sharing code and guarantees.

---

## 2. The sensorimotor loop *is* the Engine loop

The paper's closed loop `Γ --Act--> a --Env--> e --Sense--> s --π_Γ--> h --L--> Γ'` is, one-to-one, the
sans-I/O loop FANOS already runs:

- **Sense** = the node's `Input` (exteroception: inbound datagrams/timers) **+** its coherence `Measures`
  (interoception/proprioception: `Φ/P/R`, the `Verdict`).
- **Act** = the node's `Effect::Send{to, frame}` (a motor command is a frame to emit); a **Fano-line
  multicast** — send to the `q+1` co-linear peers — is the native *broadcast* motor primitive (the cell
  is 7 co-linear peers).
- **The three dials** the world writes to (the paper's unique decomposition `h = h^H ⊕ h^D ⊕ h^R`) map to
  concrete node actions: `h^H` = *which peers to bias toward / route to* (attention), `h^D` = *drop /
  decorrelate / shed* (the decouple reflex), `h^R` = *heal / replicate / regenerate* (repair). An agent's
  action space is a bounded menu over these three.
- **Tick** = a virtual-time step; the engine "never calls a clock — it receives Inputs and returns
  Effects," which is *already* the sans-I/O contract. Determinism ⇒ the agent is simulator-reproducible.

Adding a learner is therefore a **role, not a rewrite.**

---

## 3. The `SynarcModule` interface

A learning agent hosted on a node — belief is the node's coherence, action is frames, reward is intrinsic.
It is a capability-scoped `Protocol` (design-platform.md), so it is sandboxed and optional.

```rust
/// A learning sensorimotor agent hosted on a FANOS node.
pub trait SynarcModule {
    /// Fold one tick of sensation into belief Γ (exteroception + interoception).
    fn sense(&mut self, now: Instant, s: Sensation);
    /// Choose actions from the current belief (the Act functor → node syscalls).
    /// Motor output is frames: Effect::Send (unicast) or a Fano-line fan-out (broadcast).
    fn act(&mut self, now: Instant) -> Vec<Effect>;
    /// Fold intrinsic reward into the self-model target ρ* (Bures flow = regeneration).
    fn reward(&mut self, r: f64);
    /// Proprioception: the belief the agent holds about itself.
    fn belief(&self) -> &CoherenceMatrix;
}

pub struct Sensation {
    pub inbound:  Option<Input>,   // Message / Timer / Command  — exteroception
    pub measures: Measures,        // Φ / P / R feed             — interoception
    pub verdict:  Option<Verdict>, // DIAKRISIS self-diagnosis   — proprioceptive fault sense
}
```

The **host computes reward; the agent never receives an external scalar** (§4). A `sensorimotor` node role
in `fanos-node` drives it: subscribe to the cell's `Measures` as the interoceptive feed, run the module,
compute reward from consecutive `Measures`, and gate every action by the feedback-stability invariant (§5).

---

## 4. Intrinsic reward & learning = healing (one mechanism)

There is **no external reward field.** Every feedback signal is a functional of `Γ` the host already
computes — the crux for a networking agent (no reward-engineering, no wireheading surface):

- **Reward / valence** `V_hed = dP/dτ|_ℛ = 2κ·g_V·[Tr(Γρ*) − P]` — the *rate of approach to the
  self-model*. Operationally `r ≈ (P(t) − P(t−1))/Δτ` from consecutive `Measures`. "Nobody rewards an
  amoeba for finding glucose — `dP/dτ` arises automatically when `Γ` shifts toward `ρ*`."
- **Per-channel error** `σ_k = 1 − 7γ_kk` (motor form `σ_motor_k = 1 − γ_kk/ρ*_kk`); the greedy policy is
  `argmin_a max_k σ_motor_k` — "reward = −(viability deficit)."
- **Learning = Bures isometric flow** `dΓ/dt = Γ_target − Γ` — CPTP-preserving by construction (a convex
  mixing line stays a legal state), and it is *the same operator as regeneration* (`regenerate_toward`).
  So a learned reintegration policy and the existing self-healing **share code and guarantees**; extending
  learning is extending `regenerate_toward` from a fixed target to a learned `ρ*`.
- **Sparse/terminal reward** is credited backprop-free by eligibility replay `r_t = λ^{T−t}R` into a
  running weighted-mean goal estimator `ρ̂* = Π(Σ r_t Γ_t / Σ r_t)` — "the centre of mass of what worked."
- **Few-shot optimality:** `E[Bures²] ≤ C/k = O(1/k)` at the quantum Cramér–Rao limit (vs `O(1/√k)` for
  SGD); overfitting is auto-regularized because the analogue of Rademacher complexity is the channel
  capacity `≤ log₂7` — the same `log₂7` per-observation bound that floors the telemetry theorem.

**Interaction with the self-model (monism, §2A).** The node's *structural* self-model is **exact** (a copy
of its own engine — zero mismatch). SYNARC does **not** replace it; it learns the **target `ρ*`** (the
homeostatic set-point) and the **policy** on top of that exact model. So: exact structural twin (monism) +
learned set-point/policy (SYNARC) = the full active-inference agent. And the two planners coincide at the
limit — the SYNARC expected-free-energy action `argmin_a[Bures²(ŝ(a),C) − β·IG(a)]` reduces at `β=0,
C=ρ*` to "pure homeostatic return to `ρ*`," which *is* the MPC minimax `argmin_a‖σ_sys‖_∞` of §2A. The MPC
minimax is the provable default; SYNARC is the learned exploration-adding option — same objective family.

---

## 5. Safety by construction — the theorems, for free

A learning agent that can emit packets is dangerous unless bounded. SYNARC-Ω's structure supplies three
guarantees FANOS inherits, and they are *theorems*, not policies:

1. **Feedback-stability barrier (the load-bearing rail).** If the state is in the Bures ball
   `B(ρ*, r_stab)` with `r_stab = √(P − 2/7)`, and every injected perturbation obeys
   `‖h^ext‖·dt ≤ κ_fb·r_stab`, the trajectory stays in the ball *forever* → viability `P > 2/7` is
   preserved. The host **gates every action** by `verify_feedback_stability`, so a learning agent
   *provably cannot drive its own cell below viability*. This is a Control-Barrier-Function guarantee — a
   hard safety rail obtained from the substrate, not bolted on.
2. **Bounded subjecthood — `SAD_max = 3`.** A unified subject composes to at most **three levels**
   (node → cell → cell-of-cells); the Fano contraction `α = 2/3` caps the reflexive tower. Above three
   levels there is *no* unified agency — only **ecology/administration**. This is exactly FANOS's `N^k`
   stratification with `Verdict::Escalate` / `Notification::Escalated` between tiers, and it is an
   **anti-singleton guarantee**: the network is a horizontally-unbounded ecology of depth-bounded
   organisms, never one super-mind.
3. **Goldilocks operating band.** A sensorimotor cell targets `r ∈ (1/√6, 1/√3]` and the purity ceiling
   `P ∈ (2/7, 3/7]`: integrated enough to coordinate, dissipative enough to stay adaptable — below the
   band it is a formless aggregate, above it an "over-coupled, reflexionless mob" that the **decouple
   reflex** already sheds (`is_overcoupled()` → `Decoupled`). The agent's set-point is *inside* what
   DIAKRISIS already keeps.

Together: an agent that can never kill its cell (1), can never become a singleton (2), and self-sheds
over-coupling (3) — all from mechanisms already in `fanos-diakrisis`.

---

## 6. How it interacts with the rest of the architecture

The whole point of the user's ask — "everything must architecturally interact." It does, through one
quantity and one loop:

- **↔ the coherence self-model (§2A monism):** the module's *belief* IS the node's exact self-model
  `Γ_net`; the module learns its *target* `ρ*`; the exact engine-twin scores its candidate actions. Model,
  learner, and controller share one `Γ`.
- **↔ the MPC loop (§2A):** SYNARC is the *learned planner* option in step 3 (plan); the provable minimax
  is the default. They are one objective family (§4), so swapping in a learner never leaves the safety set.
- **↔ the platform (design-platform.md):** a `SynarcModule` is a **capability-scoped `Protocol`** (PID-
  isolated, `grants`-gated, wasm-sandboxable) — so a learning agent is a first-class, isolated tenant, and
  the platform can *observe it* (its `Γ_app`) exactly as it observes any overlay. The reflexive plane
  watches its learning symbionts.
- **↔ telemetry (design-telemetry.md):** the module's proprioception is the minimal coherence feed (3-bit
  syndrome + scalars); its learning consumes the same `log₂7`-bounded observation the telemetry theorem
  minimizes. No extra sensing traffic.
- **↔ the anonymity dial:** motor actions honor the segment's privacy profile; a `Full`-cell agent's
  actions are constant-rate/cover-padded (no timing leak) — the agent cannot learn a policy that leaks,
  because the dial shapes its emissions below it.
- **↔ alignment (honest boundary):** coherence gives **viability and boundedness, not alignment**. Two
  agents are aligned iff their value sets coincide as `G₂`-orbits; for FANOS this is a **shared, epoch-
  anchored target `ρ*` invariant** distributed like any other epoch parameter — an explicit design choice,
  not something the `Φ/P/R` feed enforces on its own. We state this openly (like the `f→0.5` limit).

---

## 7. Scaling & evolution modes (the network as a builder of mechanisms)

The user's "cells/proteins building a larger mechanism" and "modes of scaling and evolution" resolve into
four composable modes, now including the agentic one — each a real, bounded mechanism:

| Mode | Mechanism | Bound |
|---|---|---|
| **Structural** | the `N^k` fractal holon: `FractalHolon = νX. 𝒟 × Multiset(X)` — a cell is a `Γ` plus a bag of sub-cells; growth is `spawn_child` (one per Fano line), i.e. neurogenesis *into the failing sector* | self-similar; healing locality `1/9` per tier |
| **Capability** | the genome — capability negotiation expresses new traits; interoperation = selection | no fork; KAT-gated |
| **Ecological** | symbiont overlays (`Protocol`s) hosted + observed as `Γ_app` citizens | PID-isolated |
| **Agentic (SYNARC)** | learning sensorimotor cells; "super-intelligence is not one mind but an *ecology* of seven-channel organisms, each perfectly diagnosable, cooperating" | `SAD_max=3` unified subjecthood; above = ecology |

The two clocks (fast homeostasis, slow selection) now range over agents too: a learning agent adapts its
policy fast (Bures flow) and the ecology selects which policies thrive slowly (coherence reputation). The
`SAD_max=3` cap is the crucial engineering discipline: **keep unified agency to ≤ 3 levels (node → cell →
cell-of-cells); everything above is ecology, not a larger mind** — exactly how FANOS stratification already
behaves, and the guarantee that scaling never produces a singleton.

---

## 8. Keep-out lines (mature scoping — what NOT to import)

Pragmatism demands hard boundaries; the networking layer takes the *observables and control law*, not the
metaphysics or the heavy machinery:

- **No phenomenology.** "Consciousness," qualia, suffering, moral patienthood are `[I]`-status
  interpretations. A node crossing `P>2/7 ∧ Φ≥1 ∧ R≥1/3` is a *coordinated, self-modelling cell* — not a
  sentient one. Use the numbers, drop the metaphysics.
- **No wholesale `ℂ⁷/G₂/topos/PEPS/Kan-complex` machinery.** FANOS uses a *real symmetric* correlation
  matrix, not a complex density matrix with `G₂` gauge, HoTT, or a coskeletal meta-tower. The three-dial
  action model (`h^H/h^D/h^R`) is worth prototyping; the full Strang integrator and simplicial tower are
  not inherited.
- **No AGI/ASI claims.** A packet-emitting node needs at most L0/L1 ("which frame to send"), never the
  `ω^ω` mentalization tower. `SAD_max=3` is a *design constraint*, not an aspiration.
- **No alignment-from-coherence claim.** Stated in §6: viability ≠ alignment.

These are the difference between a mature engineering interface and over-reach.

---

## 9. Phased plan (optional, capability-gated)

Everything here is a *future capability*, built when the core transport/platform is done, and entirely from
existing primitives:

1. **`SynarcModule` trait + `Sensation`** in a new `fanos-synarc` crate (no_std core: pure sense/act/learn
   over `CoherenceMatrix`), reusing `fanos-diakrisis` verbatim.
2. **Intrinsic reward + Bures learning** = extend `regenerate_toward` to a learned `ρ*`; reward from
   consecutive `Measures`.
3. **The feedback-stability gate** (`verify_feedback_stability`) around every emitted action — the safety
   rail, first-class.
4. **A `sensorimotor` node role** in `fanos-node`: a bounded `Effect::Send` action menu (unicast + Fano-
   line broadcast), driven by the coherence feed; runs as a capability-scoped `Protocol`.
5. **Deterministic training in the sim** — because the agent is sans-I/O, `fanos-sim` trains and
   reproduces it bit-for-bit (the digital-twin, §2A); fitness = coherence-under-stress, the same
   `fanos evolve` harness.
6. **(Research) distributed embodiment across a line** — a threshold-hosted agent whose seven sectors are
   the `q+1` line members and whose interoception is the line's DIAKRISIS loop (Appendix K) — the deepest,
   latest step.

The first four are small and built from shipped primitives; the safety rails are theorems. That is the
mature core; the learned policy and distributed embodiment are the innovative frontier — kept optional,
sandboxed, and bounded, so the anonymity substrate's guarantees are never at the mercy of a learner.
