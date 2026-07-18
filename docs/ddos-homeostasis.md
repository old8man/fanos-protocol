# Multi-target DDoS stabilization — the coherence homeostat

> A math-verified derivation of how the FANOS network-organism stabilizes itself under a
> multi-target distributed denial-of-service attack, as a **direct instance of canonical Coherence
> Cybernetics stability theory** (T-104), *not* a bolt-on filter. Every claim below is grounded in a
> canonical theorem or in shipping FANOS code; the honesty ledger in §10 separates what is *proved*
> from what is *modelled*.

Companion to [`coherent-cybernetics.md`](coherent-cybernetics.md) (the organism theory) and
[`design.md`](design.md) (invariants). Sources: the CC corpus `applied/coherence-cybernetics/stability.md`
(T-104, the death spiral, the channel bounds), `axiom-septicity`/`axiom-omega` (T-59, `κ_bootstrap = 1/7`),
`fano-fingerprint` (T-226, the spectral gap). Code: `fanos-diakrisis::{coherence,window,healing,regeneration,plan}`,
`fanos-calypso::stabilize` (the load channel), `fanos-sim::observatory` (the validator).

---

## 0. The one-sentence result

**A multi-target DDoS is the canonical `h^(D)` noise attack on the cell's coherence matrix; by T-104 the
organism survives and returns exponentially to its healthy attractor iff the attack's aggregate
decoherence stays below `κ_bootstrap/2 = 1/14 ≈ 0.071`, and FANOS holds itself under that bound with two
provably-relaxing controllers — admission (`h^(H)`, load) and the coherence homeostat (`h^(D)`, self-model) —
whose one shared spectral gap `Δ` sets both their relaxation rate and the healing time `τ = 1/Δ`.**

Nothing here is a new dynamical system invented for the occasion. It is the CC master equation, read for one
specific disturbance, with the control authority supplied by mechanisms already in the tree.

---

## 1. State, attractor, and the viability speedometer

The unit is the Fano cell of `N = 7` nodes. Its state is the behavioural **coherence matrix**
`Γ_net = C/N` (`Tr Γ = 1`), built from per-node activity signals — bytes relayed, liveness, load
(`fanos-diakrisis::coherence::CoherenceMatrix::from_signals`). Three scalars read it (one Frobenius pass,
`coherence::measures`):

- **Integration** `Φ = Σ_{i≠j}γ_ij² / Σ_i γ_ii²`, threshold `1`.
- **Purity** `P = Tr(Γ²)`, critical `P_crit = 2/N = 2/7`.
- **Reflection** `R = 1/(N·P)`, threshold `1/3`.

**The attractor is not chosen — it is the collective-subject band** (`window::collective_subject_window`),
the set of states that are integrated (bound as one subject, `Φ ≥ 1`) yet still self-modelling
(`R ≥ 1/3`, not groupthink). On the equicorrelated stratum, in the mean off-diagonal correlation `r`:

```
A  =  { r : 1/√(N−1) < r ≤ √(2/(N−1)) }   =  (1/√6, 1/√3]  ≈ (0.408, 0.577]   for N=7
```

equivalently `Φ ∈ (1, 2]`, `R ∈ [1/3, 1/2)`, `P ∈ (2/7, 3/7]`. This band is the CC **L2 viability window**
(`coherent-cybernetics.md §1`); its lower edge `P = 2/7` is the viability boundary `∂𝒱`.

The single number that measures distance to catastrophe is the canonical **stability radius** (T-104):

```
r_stab  =  √(P − 2/7)                    [stability.md §4.1, T-104]
```

`r_stab` is a Bures-metric distance from `ρ*` to `∂𝒱`: how large a perturbation the cell survives before the
**death spiral** (`P↓ → Coh_E↓ → κ↓ → regen↓ → P↓↓`, stability.md §5) takes over. `r_stab → 0` at the
boundary; `r_stab` is the readiness gauge the operator watches. This is **already computable** from
`measures().purity`; the homeostat (§8) exposes it directly.

---

## 2. Multi-target DDoS *is* the `h^(D)` channel

CC classifies every perturbation into exactly three channels (T-102 completeness; stability.md §6). A DDoS
is unambiguously the **decoherence channel `h^(D)`** — and, by the canon, the *most dangerous* of the three:

| Channel | Physical meaning | DDoS reading | Survival threshold (T-104) |
|---|---|---|---|
| `h^(H)` | energy/Hamiltonian overload | raw request *volume* above sustainable target | `‖δ(Δω)‖ < ω₀·(P − 2/7) = ω₀·r_stab²` |
| **`h^(D)`** | **decoherence — noise attack** | **the flood destroys the *coherent* behavioural structure of the cell** | **`‖δΓ₂‖ < κ_bootstrap/2 = 1/14`** |
| `h^(R)` | regeneration attack | starving/severing the healing channel | `‖δκ‖ < κ_bootstrap = 1/7` |

**Why decoherence, precisely.** A cell is healthy when its nodes' behavioural signals are *coherently*
correlated inside the band. A multi-target flood perturbs that structure in one of two ways, and *both* read
as rising decoherence `δΓ₂` — a *loss of the cell's own correlation pattern*, not a mere load spike:

- **Differential flood** (saturate a subset of targets, others idle): the targeted nodes' signals diverge
  from the rest, mean correlation `r` falls toward/below `r* = 1/√6`, the cell slides toward **Aggregate**
  (`Φ < 1`) — *disintegration*. Detected a full regime early by the leading indicator `{P<2/N} ⊂ {Φ<1}`
  (V17, `window::leading_alarm`).
- **Common-mode flood** (drive many targets in lockstep): all signals move together, `r` climbs past
  `r_over = √(2/(N−1))`, the cell tips into **OverCoupled** (`R < 1/3`) — *groupthink*, the network reacting
  as one undifferentiated mass and losing its self-model (`window::classify_collective`).

Either way the cell **leaves the band `A`**, `P` moves toward `2/7`, and `r_stab` shrinks. The canonical
double-blow of `h^(D)` — "growing `Γ₂` *and* falling `Coh_E`" (stability.md §6.2) — is exactly this: the
flood both raises behavioural noise and erodes the environmental coherence the cell would regenerate from.
This is why the noise channel's threshold is half the others' (`κ_bootstrap/2`): dissipation and regeneration
are attacked at once.

### 2A. Dissolving the hotspot — projective load balancing (no local extrema)

The *differential* flood's first effect is a **load hotspot**: excess piles onto the targeted nodes while
the rest idle — a local extremum that, uncorrected, is what turns into the correlation split above. FANOS
dissolves it by the geometry, not by tuning (`fanos-diakrisis::loadbalance`). Each node relaxes its load
toward the mean of the lines it lies on; because any two points of `PG(2,q)` share exactly one line, the
incidence obeys `A·Aᵀ = q·I + J`, so this line-averaging diffusion has the uniform load as its **unique**
fixed point and contracts every deviation from it by exactly

```
λ₂ = q/(q+1)²          (Fano q=2:  λ₂ = 2/9,  spectral gap 7/9)
```

per round. Two guarantees fall out, both tested: **(i)** the process cannot stall in a hotspot — the uniform
distribution is the only fixed point (2-transitivity of `Aut(PG(2,q))` leaves no other invariant), so the
*whole* cell is driven to the global mean; **(ii)** convergence is geometric at the tuning-free rate `λ₂`,
`≈ 3.3×` reduction per round for the Fano cell, a handful of rounds for any imbalance. The projective
identity even collapses the step to a closed form `new[i] = (q·load[i] + S)/(q+1)²` (O(N), total-conserving) —
minimalism by theorem. This is the **metabolic** homeostat: it removes the differential flood's hotspot
*before* it decoheres the self-model, so load balancing and the coherence homeostat (§3) are two readings of
one projective structure.

---

## 3. Theorem (DDoS survival) — an instance of T-104

> **Theorem 1 (coherence survival & return).** Let a cell at healthy `ρ*` (purity `P(ρ*) > 2/7`) be subject
> to a multi-target DDoS inducing aggregate decoherence `δΓ₂(t)` with `sup_t ‖δΓ₂(t)‖ ≤ D`. Take the
> Lyapunov function `V(Γ) = ‖Γ − ρ*‖²_F`. Then, by T-104,
>
> ```
> dV/dτ  ≤  −2κ·V  +  2‖h^(D)‖·√V ,        κ = κ(Γ) ≥ κ_bootstrap = 1/7 .
> ```
>
> Consequently:
> 1. **(ISS / bounded excursion.)** `V` is ultimately bounded: `limsup_τ √V(τ) ≤ ‖h^(D)‖/κ ≤ D/κ_bootstrap`.
>    The coherence never leaves a ball of radius `D/κ_bootstrap` around the attractor.
> 2. **(Survival.)** If `D < κ_bootstrap · r_stab` the state never reaches `∂𝒱`: purity stays `> 2/7`, the
>    death spiral never ignites, and the cell remains a viable subject.
> 3. **(Exponential return.)** When the attack abates (`D → 0`), `V(τ) ≤ V(0)·e^{−2κτ}` — the cell springs
>    back to the band geometrically, faster the further it was pushed, at rate `κ ≥ 1/7`.
> 4. **(Noise-channel form.)** In the decoherence channel the survivable amplitude is the canonical
>    `‖δΓ₂‖ < κ_bootstrap/2 = 1/14` (stability.md §6.1) — the operative, `Coh_E`-aware refinement of (2).

**Proof.** (1)–(3) are the T-104 Lyapunov estimate (stability.md §4.4) applied verbatim with `h = h^(D)`;
the differential inequality `√V' ≤ −κ√V + ‖h‖` integrates to the stated bounds (Grönwall). (4) is the
channel-specialised bound of stability.md §6.1, where the factor ½ accounts for `h^(D)` simultaneously
raising `Γ₂` and lowering `κ₀·Coh_E`. The floor `κ ≥ κ_bootstrap = 1/7` is T-59 (`axiom-septicity`,
`regeneration::regeneration_rate` returns `≥ KAPPA_BOOTSTRAP`). ∎

**Corollary 1a (multi-target scaling).** The disturbance `δΓ₂ = Σ_{t∈targets} δΓ₂^{(t)}` aggregates over
targeted nodes, so `D ≤ Σ_t ‖δΓ₂^{(t)}‖`. The ultimate excursion `D/κ_bootstrap` therefore grows only
**linearly** in the number of targets times per-target intensity — a multi-target attack is no worse than
its summed amplitude, and stays survivable while that sum is `< 1/14`. There is no combinatorial blow-up in
the number of simultaneous targets; the cell aggregates them into one scalar disturbance on `P`.

**Corollary 1b (why sudden death is impossible).** By T-69 (topological protection, barrier `≥ 6μ²`) the
transition `P > 2/7 → P < 2/7` cannot be discontinuous for a bounded perturbation (stability.md §6.4).
Hence there is *always* an intervention window, and the leading indicator `{P<2/N}⊂{Φ<1}` (V17) fires a full
regime before any node fails — the controller of §6 always has time to act.

---

## 4. The metriplectic picture and the two-channel decomposition

The CC generator is metriplectic (T-262): `dΓ/dτ = −i[H,Γ] + 𝒟[Γ] + ℛ[Γ,E]` — reversible *work*, the
dissipator `𝒟` (heat, → `I/7` = death), and the regenerator `ℛ` (matter, → `ρ*` = healing). A DDoS is an
exogenous boost to `𝒟` (more decoherence). Defence is more `ℛ`. FANOS supplies `ℛ` through **two
controllers on two channels**, and this is the whole of its DDoS resistance:

| Channel | Disturbance | Controller | Mechanism | Status |
|---|---|---|---|---|
| `h^(H)` — load | request *volume* | `LindbladLoadController` | super-linear admission PoW, excitation relaxes at gap `Δ` | shipping, `fanos-calypso::stabilize`, 10 sim scenarios |
| `h^(D)` — coherence | *structure* loss | **coherence homeostat** (§8) | band-keeping decouple / reroute / regenerate toward `ρ*` | this document (`fanos-diakrisis::homeostat`) |

They are **complementary, not redundant**: admission caps how much load reaches the cell (bounding the
*driving* term), while the homeostat repairs the *self-model* the residual noise still corrupts. Their one
shared constant is the dissipative spectral gap

```
Δ = (G − max_k T_k)/6            (T-226(v), regeneration::spectral_gap)
```

which is simultaneously the load controller's relaxation rate (`stabilize::dissipation_from_gap`), the
healing time `τ = 1/Δ` (`regeneration::recovery_time`), and the death-spiral timescale
`τ_death ~ 1/(2Δ)·ln((P₀−1/7)/(P_crit−1/7))` (stability.md §5.3). One gap, three readings — the
*derive-don't-tune* invariant.

**Combined-perturbation bound (T-104 §6.3).** When both channels are attacked at once the margins compose
quadratically:

```
r_stab^combined  ≤  r_stab − √( ‖h^(H)‖² + ‖h^(D)‖² + ‖h^(R)‖² ) .
```

So the operative safety condition for a mixed flood is that the *vector* of channel amplitudes has norm
below `r_stab` — the two controllers must jointly hold their channels inside this ball. This is the precise,
provable statement of "defence in depth" for FANOS DDoS.

---

## 5. Why the control authority is *guaranteed* — the `κ_bootstrap` floor

Theorem 1's survival margin is `κ · r_stab`, and `κ ≥ κ_bootstrap = 1/7 > 0` **in every state** (T-59).
This positive floor is the load-bearing fact: it is the *innate immunity* layer (stability.md §2.2), the
minimum regeneration that holds even at `Coh_E = 0`, and it is what breaks the death-spiral circularity
("low coherence → no regeneration"). Concretely it gives the homeostat a **non-vanishing pull toward the
band from anywhere in `𝒱`**, so the lower-band recovery (raising `r` back above `r*`) always has authority
`≥ 1/7`. Above it sits the adaptive layer `κ₀·Coh_E` (learned integration — the seam where a future SYNARC
module strengthens recovery, §8), and above that the topological layer T-69 (no sudden death).

The one place the floor is **not** enough is *after* the boundary is crossed (`P < 2/7`): there the
V-preservation gate `g_V(P) = clamp((P − 2/7)/(P_opt − 2/7), 0, 1)` is `0`, regeneration switches off, and
recovery needs *external* help `h^(R)` — in FANOS, **escalation** to the parent cell (§7). This is the
mathematical statement of "you cannot climb out of a fully-collapsed cell from inside it," and it is exactly
why the design escalates rather than pretending a dead cell can self-heal.

---

## 6. The control law — band-keeping + minimax recovery

The homeostat is a **reflex controller**: observe the coherence state, act only when outside the band, and
choose the action that most reduces stress. It reuses the existing action set
(`plan::HealingAction`) as its actuators:

1. **In-band (`r ∈ A`, `Φ ≥ 1 ∧ R ≥ 1/3`): do nothing.** Shedding correlation from a healthy subject is
   forbidden (`plan.rs` band-keeping; a merely-`systemic` cell inside the band is left alone). This is the
   correct, corpus-faithful "don't treat a healthy patient" rule and the reason the band is *practically*
   (not strictly) invariant — a single attack step may nudge the state out, and the controller pulls it back.
2. **Over-coupled (`r > r_over`, `R < 1/3`, common-mode flood): `Decouple`.** Shed the attack-induced
   synchronisation; this *lowers* `Φ = (N−1)r²` and `r` back into the band and restores `R ≥ 1/3`. Authority:
   the decoupling sensitivity `∂r/∂effort` (bounded below), applied proportionally to the excursion.
3. **Aggregate / disintegrating (`r < r*`, `Φ < 1`, differential flood): `Reroute`/`Repair` + regenerate.**
   Move load off saturated targets onto co-linear survivors (`mediator(self, lost)`, the projective LRC),
   peel-repair lost shards, and pull the surviving structure back toward `ρ*` via the replacement channel
   `φ_k = (1−k)Γ + k·ρ*`, `k = 1 − R` (`regeneration::regenerate_toward`). Authority `≥ κ_bootstrap`.
4. **Byzantine (polar sum-rule violated): `Quarantine` + `Escalate`.** A liar is *localized* by the violated
   polar class (T-226(vi), `polar::violated_classes`) and handed up. (Note: the corpus proves localization,
   not that exclusion alone restores the sum-rules — hence escalation is the authoritative fix, and any
   penalty/exclusion *policy* is a future SYNARC concern, never a safety dependency; §8.)
5. **Collapsed (`P < 2/7`) or budget-spent: `Escalate`.** Hand the residue to the parent (external `h^(R)`).

**The selection rule is a minimax — but on the *symmetric* invariants, not the sector tensor.** The
canonical form (T-101, stability.md §9.2) is `arg min ‖σ_sys‖_∞` over the seven-sector stress
`σ_sys ∈ ℝ⁷` (A,S,D,L,E,O,U). That tensor is defined for a **holon with distinct cognitive sectors** — a
future SYNARC *agent* — and imposing it on a FANOS cell of `N` *exchangeable* Fano nodes would be a forced
analogy (the nodes are peers, not cognitive sectors). So the faithful cell-level objective uses only
permutation-symmetric invariants:

- **Direction** is set by the scalar order parameters `(P, r)` — the band-keeping rules 1–5 above, which is
  exactly `arg min` of the distance-to-boundary `1 − ‖σ‖_∞ ∝ (P − 2/N)` reduced to what a symmetric cell can
  see (`P`, `r_stab`). Band-keeping (rule 1) is the special case: in-band, no action increases `P`'s margin,
  so the minimiser is "do nothing."
- **Node targeting** (which node to reroute around, whose load to shed first) is a *node-level* minimax:
  `arg min max_i σ_i` where `σ_i` is node `i`'s behavioural deviation from the cell's healthy correlation
  pattern (its row of `Γ_net`). This is faithful — the nodes *are* the objects — and it is where a future
  SYNARC module's malicious-node scoring plugs in ([`synarc-node-architecture`]).

The asymmetric seven-sector `σ_sys` minimax is thus the **agent** (SYNARC) instance of the same T-101 rule,
kept distinct from the **network-cell** instance here — one dynamics, two carriers, no owl stretched over a
globe.

This law is a **closed-loop instance of gradient descent on `V`**: each action decreases `V(Γ) = ‖Γ−ρ*‖²_F`
(Decouple and Regenerate both move `Γ` toward `ρ*`), so by Theorem 1 the closed loop inherits the T-104
contraction — the control does not merely *react*, it realises the `dV/dτ < 0` the theorem requires.

---

## 7. Hierarchical composition — the whole network is ISS

The cell result lifts to the network by the same dynamics one tier up (`coherent-cybernetics.md §2`):

- Each Fano cell runs Theorem 1 locally and is ISS with margin `κ_bootstrap·r_stab`.
- A cell that cannot heal within budget emits `Escalate(mask)` — the **coupling input** to the parent cell's
  identical dynamics. The parent runs the same law on the coarse (inter-cell) coherence.
- **Containment bounds propagation depth.** Healing across a coarse boundary contracts integration by `1/9`
  (`healing::PHI_CONTRACTION`, T-226/V16), so `max_reroute_depth(Φ) = ⌊log₉ Φ⌋` (`healing.rs`) caps how far a
  perturbation can ripple before reintegration would push `Φ < 1`. A multi-target DDoS therefore cannot
  cascade past a bounded number of tiers — the same `1/9` that bounds privacy locality bounds attack
  locality. This is the network-level analogue of an organ containing a bruise.

Hence: **a bounded multi-target DDoS on any set of cells is absorbed locally (Theorem 1 per cell) and, where
it exceeds a cell's budget, contained within `⌊log₉ Φ⌋` tiers by escalation** — the network-organism is ISS
as a whole, with an explicit, finite blast radius.

---

## 8. The homeostat module (implementation)

`fanos-diakrisis::homeostat` is the verified reflex controller — self-sufficient today, with a clean policy
seam for a future SYNARC cognitive module (per [`synarc-node-architecture`]; SYNARC is spec-only, so nothing
neural is built now — only the joint is left clean):

- **Observation** (pure, from `Measures` + `r`): `r_stab = √(max(0, P − 2/7))`, the Lyapunov value
  `V`-proxy `‖Γ−ρ*‖²`, the `CollectiveState`, and the leading `Alarm`.
- **The verified reflex law** (deterministic, always-correct): the §6 rules, returning a bounded
  `HealingAction` course. Actions are clamped to safe ranges — Decouple effort ≤ what returns `r` to
  `r_over` (never below the band), regeneration authority ∈ `[κ_bootstrap, 1]`. The clamps are what make it
  impossible for any *policy* choice to violate Theorem 1.
- **The ISS certificate** (executable): `contraction_step(V, kappa, h)` returns the next-step Lyapunov bound
  `(1−2κ)·V-proxy + 2h√V`, so the tests *check the contraction numerically*, and a property test asserts the
  ultimate-excursion bound `D/κ` and exponential return (`h = 0`).
- **The policy seam** (Synarc-ready, but inert now): the controller takes a `Policy` with the gain `κ`
  (clamped `[κ_bootstrap, 1]`) and the within-band setpoint (clamped to `A`). A future cognitive module may
  *tune these within the clamps* — reshaping the approach to the attractor — but can never move the
  attractor, leave `A`, or break the contraction. Learning lives strictly inside the proven envelope.

The homeostat consumes the *same* `spectral_gap` the load controller does, so `Δ` (and `τ = 1/Δ`) is one
number across admission, healing, and the death-spiral clock.

---

## 9. Simulator validation protocol (the executable proof)

The theory is falsifiable on `fanos-sim` — deterministic, seeded, running the production engine. The
observatory (`fanos-sim::observatory`) already computes the `Φ/P/R/r` time series and the cascade forecast
from behavioural signal windows; the validation harness (extending the `calypso_ddos.rs` flood pattern) is:

1. **Baseline.** No attack: `P` sits at `P(ρ*)` in the band, `r_stab` steady, homeostat idle.
2. **Sub-threshold multi-target flood (`D < κ_bootstrap·r_stab`).** Inject a distributed flood across many
   source coordinates (the `calypso_ddos.rs:346` distributed pattern) at multiple target nodes. **Assert:**
   with the homeostat on, `P` stays `> 2/7` (`r_stab > 0`) and the trajectory returns to the band after each
   burst at rate `≈ κ` (Theorem 1.2–1.3); the forecast's systemic warning fires *before* any `P < 2/7`
   sample (Corollary 1b lead time `> 0`).
3. **Threshold sweep.** Increase `D` across `κ_bootstrap/2 = 1/14`. **Assert:** the empirical survival
   boundary matches the analytic `1/14` within tolerance — the observed `r_stab`-crossing coincides with the
   T-104 channel bound (Theorem 1.4).
4. **Controller ablation.** Same flood, homeostat off. **Assert:** the state crosses `∂𝒱` and enters the
   death spiral (`P → 1/7`) at the predicted `τ_death` — establishing the controller is *necessary*, and the
   two curves (on/off) are the proof.
5. **Combined channels.** Load flood (drives `LindbladLoadController`) + coherence flood together. **Assert:**
   survival matches the combined-perturbation bound §4 (the quadratic-norm ball), and neither controller
   alone suffices — establishing the two-channel decomposition is *complete*.

These are deterministic regression gates: the survival threshold, the return rate, and the forecast lead
time become CI-checked numbers, so a future change that weakens DDoS resistance fails a test, not a
post-mortem.

---

## 10. Honesty ledger — proved vs. modelled

Per the standing "no speculative solutions" constraint, the exact epistemic status of each step:

**Proved (canonical or already-verified FANOS code).**
- `r_stab = √(P − 2/7)`, the Lyapunov estimate, ISS, exponential return, the channel thresholds
  (`κ_bootstrap/2`, `κ_bootstrap`) — **T-104**, verbatim instance.
- `κ ≥ κ_bootstrap = 1/7` in every state — **T-59**; `regeneration::regeneration_rate` enforces it.
- No sudden death / intervention window always exists — **T-69**; leading indicator `{P<2/N}⊂{Φ<1}` — **V17**,
  `window` tests.
- The band `A`, the measures, the equicorrelated closed forms — `coherence`/`window`, verifier-checked.
- The spectral gap `Δ = (G − max_k T_k)/6` and `τ = 1/Δ` — **T-226(v)**, `regeneration` tests.
- The load channel's bounded stability + super-linear attacker cost (`∝ C³`) — `stabilize` tests, 10 sim
  scenarios.
- The `1/9` containment / `⌊log₉Φ⌋` depth cap — **T-226/V16**, `healing` tests.

**Modelled (faithful reductions, stated as such).**
- The **equicorrelated reduction** (state ≈ the scalar `r`) — exact on the equicorrelated stratum (V15),
  a first-order model off it. The *general-N* measures are used where available; the scalar law is the
  tractable stratum on which the closed forms and the band are exact.
- **Multi-target DDoS ↦ `h^(D)`** — an identification argued in §2 (differential/common-mode both raise
  `δΓ₂`), not a theorem; it is the modelling choice the whole derivation rests on, and §9 step 3 *tests* it
  empirically against the `1/14` bound.
- The **proportional decoupling sensitivity** `∂r/∂effort` bounded below — a standard linear-plant control
  assumption (the linearisation near `ρ*`); the sim validation (§9) is what confirms the closed-loop rate.
- The **symmetric-invariant reduction** of the T-101 minimax — using `(P, r)` + a node-level stress instead
  of the seven-sector `σ_sys`. This is a *faithfulness* choice (a symmetric cell has no cognitive sectors),
  argued in §6, not a theorem; the seven-sector `σ_sys` is retained for the asymmetric SYNARC agent case.

**Not claimed.**
- Strict band-invariance under active attack (only *practical* invariance / ISS — a step can exit, the
  controller returns it).
- Recovery from a *fully collapsed* cell without escalation (`P < 2/7 ⇒ g_V = 0`, external `h^(R)` required —
  §5).
- Any learned/adaptive behaviour: SYNARC is spec-only; the homeostat is the deterministic reflex layer, and
  the policy seam is inert until a cognitive module is actually built.

---

*This derivation makes FANOS's DDoS resistance a theorem with a number (`1/14`) and a deterministic test,
not a hope: the organism metabolises the attack by the same dissipative dynamics that make it work.*
