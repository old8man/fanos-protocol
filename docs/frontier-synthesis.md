# Frontier synthesis — self-balancing & self-healing networks vs. FANOS

> A survey of the arXiv/top-venue frontier on (a) distributed self-balancing (load balancing
> without local extrema) and (b) self-healing / self-stabilizing / resilient distributed systems,
> read **against what FANOS already derives**, synthesised in UHM / Coherence-Cybernetics (CC) +
> SYNARC terms, and turned into a ranked list of **derivable, verifiable** candidate improvements.
>
> Companion to [`ddos-homeostasis.md`](ddos-homeostasis.md) (the T-104 homeostat derivation),
> [`coherent-cybernetics.md`](coherent-cybernetics.md) (the organism theory) and
> [`design-synarc.md`](design-synarc.md) (the reflex/learnable seam). This document is **research +
> synthesis only** — it proposes, it does not change any FANOS mechanism. Nothing here ships until
> it is derived and validated on `fanos-sim`; every speculative step is marked **[hypothesis]**.

**Epistemic legend.** `[T]` theorem (canonical or already-verified FANOS code) · `[D]` derived here
from FANOS's own proven structure (elementary, checkable) · `[E]` established external result
(peer-reviewed / arXiv) · `[H]` hypothesis to be verified on the simulator before it is believed.

---

## 0. Orientation — the FANOS baseline the frontier is measured against

The frontier is only useful relative to what FANOS *already* derives, so recommendations do not
re-invent shipped mechanisms. The load-bearing inventory:

| FANOS mechanism | Exact result | Status | Code |
|---|---|---|---|
| **Projective load balancing** | `A·Aᵀ = qI + J` ⇒ line-averaging diffusion `M` has eigenvalues `{1, λ₂=q/(q+1)²}`; unique uniform fixed point, **no local extrema**, deviation contracts by exactly `λ₂ = 2/9` (Fano), closed form `new[i]=(q·load[i]+S)/(q+1)²` | `[T]` | `fanos-diakrisis::loadbalance` |
| **T-104 ISS/Lyapunov homeostat** | `V=‖Γ−ρ*‖²`, `√V' ≤ −κ√V + ‖h‖`, ultimate excursion `h/κ`, exponential return | `[T]` | `stability`, `homeostat` |
| **Guaranteed authority floor** | `κ ≥ κ_bootstrap = 1/7 > 0` in **every** state (T-59) | `[T]` | `healing::KAPPA_BOOTSTRAP` |
| **Viability gate / death spiral** | `g_V(P)=clamp((P−2/N)/(3/N−2/N))`; `g_V=0` at `P≤2/N` ⇒ regeneration off = **saddle-node** collapse (`κ/Γ₂=1`) | `[T]` | `stability::v_preservation_gate`, `dynamics` |
| **Band-keeping control** | Hold / Decouple / Bind / Escalate on `(P, r)`; collective-subject band `r∈(1/√6,1/√3]` | `[T]` | `homeostat`, `window` |
| **Survival threshold** | decoherence channel `‖δΓ₂‖ < κ_bootstrap/2 = 1/14` | `[T]` | `stability::NOISE_SURVIVAL_THRESHOLD` |
| **Leading indicator** | `{P<2/N} ⊂ {Φ<1}` — integration alarm fires no later than structure alarm | `[T]` | `window::leading_alarm` |
| **Fano-channel containment** | `Φ→Φ/9` per coarse hop ⇒ blast radius `⌊log₉Φ⌋` tiers | `[T]` | `healing`, `regeneration` |
| **Spectral gap (one number)** | `Δ=(G−max_k T_k)/6` sets admission relaxation, healing time `τ=1/Δ`, death-spiral clock | `[T]` | `regeneration::spectral_gap`, `calypso::stabilize` |
| **Byzantine localization** | polar sum-rule violation (T-226) localizes the liar to a polar class, then escalate | `[T]` | `polar`, `plan` |
| **Basin of attraction** | viability set `𝒱={P>2/7}`, analytic basin volume `≈(2/7)²¹`, valley/potential landscape | `[T]` | corpus `stability.md §3` |
| **Two-channel decomposition** | load `h^(H)` (Lindblad leaky integrator, cost `∝C³`) + coherence `h^(D)` (homeostat) | `[T]` | `calypso::stabilize`, `homeostat` |
| **SYNARC seam** | reflex layer verified; learnable module tunes **within** clamps (`κ∈[κ_bootstrap,1]`, band setpoint), never moves `ρ*` | design | `design-synarc.md` |

The headline: **FANOS already instantiates a large slice of the ISS/Lyapunov, basin/bifurcation,
and spectral-gap frontier — as theorems, from the projective geometry and the CC master equation.**
The frontier's value is therefore concentrated in a few genuinely *complementary* directions
(finite-time balancing, Byzantine-robust averaging, control-barrier safety, dynamical early-warning),
mapped out below.

---

## 1. The frontier map (annotated)

Grouped A–I. Each entry: citation · **key result** · *relevance to FANOS*. arXiv ids / DOIs were
verified against search results or fetched abstract pages; a few pre-arXiv classics are cited by
venue.

### A. Distributed load balancing via diffusion & the graph spectral gap

- **Cybenko (1989), "Dynamic Load Balancing for Distributed Memory Multiprocessors."** *J. Parallel
  Distrib. Comput.* 7(2):279–301. **Key:** diffusion load-balancing convergence is governed by the
  **eigenstructure of the iteration matrix**; on a `d`-hypercube the work distribution is guaranteed
  uniform after **`d+1` iterations** (a *finite-time* result tied to the number of distinct
  eigenvalues); dimension-exchange beats plain diffusion there. *Relevance:* the direct ancestor of
  FANOS's line-averaging diffusion — and its "finite iterations = #distinct eigenvalues" insight is
  exactly what makes FANOS's 2-eigenvalue balancer a **one-round exact** averager (Candidate 1).
- **Boyd, Diaconis, Xiao (2004), "Fastest Mixing Markov Chain on a Graph."** *SIAM Review*
  46(4):667–689. **Key:** minimising the second-largest eigenvalue modulus of a reversible transition
  matrix (⇔ maximising the spectral gap ⇔ fastest averaging) is a **convex SDP**. *Relevance:* FANOS
  does not need to *optimise* weights — `PG(2,q)` hands it the extreme two-eigenvalue spectrum for
  free; its balancer is already "fastest-mixing" in the strongest sense.
- **Xiao & Boyd (2004), "Fast Linear Iterations for Distributed Averaging."** *Systems & Control
  Letters* 53:65–78. **Key:** average-consensus convergence rate = asymptotic spectral radius of
  `W − 11ᵀ/n`; optimal symmetric weights via SDP. *Relevance:* the general form of FANOS's exact
  `λ₂` contraction; FANOS is the closed-form special case.
- **Sundaram & Hadjicostis (2007), "Finite-Time Distributed Consensus in Graphs with Time-Invariant
  Topologies."** *ACC 2007* (and later *IEEE TAC*). **Key:** each node computes the **exact** consensus
  value in `D` steps, `D` = degree of the **minimal polynomial** of the weight matrix (≤ #distinct
  eigenvalues), by a local linear combination of its own past values. *Relevance:* the theorem behind
  Candidate 1 — FANOS's `M` has **two** distinct eigenvalues, so `D=2` and one deflation gives the
  exact mean.
- **Nguyen, Jiang, Ying, Uribe (2023), "On Graphs with Finite-Time Consensus and Their Use in Gradient
  Tracking."** arXiv:2311.01317 (*SIAM J. Optim.*). **Key:** characterises weight-matrix sequences with
  `W^(τ−1)···W^(0) = (1/n)11ᵀ` **exactly** after `τ` steps — exact, not geometric `|λ₂|ᵗ`, convergence
  — and asks which topologies (automorphism/line structure) admit them. *Relevance:* the modern framing
  of Candidate 1; `PG(2,q)`'s two-eigenvalue structure *is* such a topology, with `τ=1` deflation.
- **Rabani, Sinclair, Wanka (1998), "Local Divergence of Markov Chains and the Analysis of Iterative
  Load-Balancing Schemes."** *FOCS 1998*. **Key:** diffusion/dimension-exchange drives discrepancy below
  `x` in `O(μ⁻¹·log(Kn²/x))` rounds, `μ=1−|λ₂|` the spectral gap. *Relevance:* the rigorous
  "rounds ∝ (1/gap)·log(1/error)" shape for the *approximate* projective balancer's proof (the exact
  one-round result of Cand 1 is the two-eigenvalue special case).
- **Azar, Broder, Karlin, Upfal (1999), "Balanced Allocations" (power of two choices).** *SIAM J.
  Comput.* 29(1):180. **Key:** with `d≥2` random bin choices, max load is `log_d log n + O(1)`. *Relevance:*
  a memoryless randomized alternative to deterministic diffusion — a contrast case, not a replacement,
  for the "no stalling" property FANOS gets deterministically.
- **Becchetti, Clementi, Natale, Pasquale, Posta (2019), "Self-Stabilizing Repeated Balls-into-Bins."**
  arXiv:1501.04822 (*Distrib. Comput.*). **Key:** from an arbitrary/adversarial start the process reaches
  `O(log n)` max load in `O(n)` rounds and *stays* legitimate over poly(n) windows w.h.p. *Relevance:*
  the closest *randomized* literature match to FANOS's deterministic "no local extrema / self-healing
  balance" guarantee.
- **Berenbrink, Elsässer, Friedetzky, et al. (2025), "(Almost) Perfect Discrete Iterative Load
  Balancing."** arXiv:2510.15473. **Key:** an indivisible-token scheme reaches discrepancy `≤3` w.h.p. in
  round-count matching the continuous spectral bound `Θ(Δ·log(Kn)/(1−λ))`. *Relevance:* the tight
  discrete-vs-continuous bound to cite if FANOS load becomes integer request-tokens (Cand 1's rounding
  clause).
- **Montijano, Montijano, Sagüés (2011/2013), "Chebyshev Polynomials in Distributed Consensus
  Applications."** *IEEE TSP*; see also Kokiopoulou & Frossard, "Polynomial Filtering for Fast
  Convergence in Distributed Consensus," arXiv:0802.3992. **Key:** a degree-`K` Chebyshev matrix
  polynomial cuts a gossip matrix's condition number `χ` to `O(1)` using `K=⌈√χ⌉` rounds (factor-`N`
  speedup on chains, `√N` on grids). *Relevance:* the acceleration to fall back on when a *damaged*
  cell's incidence loses the clean two-eigenvalue spectrum (Candidate 1, degradation clause).
- **Muthukrishnan, Ghosh, Schultz (1998), "First- and Second-Order Diffusive Methods for Rapid,
  Coarse, Distributed Load Balancing."** *Theory Comput. Syst.* 31:331–354. **Key:** second-order
  ("momentum") diffusion `x^{(t+1)} = β M x^{(t)} + (1−β) x^{(t−1)}` accelerates first-order diffusion
  toward the optimal `β` set by `λ₂`. *Relevance:* the two-tap accelerated form of `balance_step`;
  again a degraded-topology option.

### B. Expander / Ramanujan / projective topologies for robustness

- **Hoory, Linial, Wigderson (2006), "Expander Graphs and Their Applications."** *Bull. AMS*
  43(4):439–561. **Key:** spectral gap ⇔ edge/vertex expansion (Cheeger); large gap ⇒ fast mixing,
  robust connectivity, few-cut fault tolerance. *Relevance:* the canonical dictionary translating
  FANOS's `λ₂` into robustness statements.
- **Lubotzky, Phillips, Sarnak (1988), "Ramanujan Graphs."** *Combinatorica* 8(3):261–277. **Key:**
  explicit `(p+1)`-regular Cayley graphs with **every** nontrivial `|λ| ≤ 2√(k−1)` (the Alon–Boppana
  optimum) and girth `≥ (4/3)log_{k−1}|X|`. *Relevance:* the gold-standard benchmark for "optimal `λ₂`
  ⇒ optimal mixing/robustness" against which FANOS's incidence spectrum is measured.
- **Alon–Boppana (1986) / Nilli (1991), "On the Second Eigenvalue of a Graph."** *Discrete Math.*
  91(2):207. **Key:** every `d`-regular family has `λ₂ ≥ 2√(d−1) − o(1)` — the Ramanujan bound is a
  provable **ceiling**, not just a target. *Relevance:* makes FANOS's `λ₂=√q` a *near-optimal* gap in an
  absolute sense (Candidate 4b), not merely "good."
- **Marcus, Spielman, Srivastava (2015), "Interlacing Families I: Bipartite Ramanujan Graphs of All
  Degrees."** *Annals of Math* 182(1):307–325, arXiv:1304.4132 (and IV, "…of All Sizes,"
  arXiv:1505.08010, *SIAM J. Comput.*). **Key:** biregular bipartite Ramanujan graphs (nontrivial
  eigenvalue `≤ √(c−1)+√(d−1)`) exist for every degree/size, via interlacing polynomials. *Relevance:*
  the **incidence (Levi) graph of `PG(2,q)`** is `(q+1)`-regular bipartite with nontrivial eigenvalue
  `√q`, i.e. it satisfies the bipartite Ramanujan bound — FANOS's topology is (near-)spectrally optimal
  *by construction*, a robustness certificate it can simply state (Candidate 4b).
- **Lakhotia, Besta, Monroe, Isham, Iff, Hoefler, Petrini (2022), "PolarFly: A Cost-Effective and
  Flexible Low-Diameter Topology."** *SC'22*, arXiv:2208.01695. **Key:** a diameter-2 interconnect built
  **directly from an Erdős–Rényi polarity graph — a polarity of a finite projective plane** — reaching
  `>96%` of the Moore-bound node count. *Relevance:* **the single closest precedent in the literature to
  `PG(2,q)` incidence geometry deployed as a real network fabric** — independent, strong external
  validation of FANOS's topology choice (see also PolarStar, *SPAA'24*, arXiv:2302.07217).
- **Young et al. (2021), "SpectralFly: Ramanujan Graphs as Flexible and Efficient Interconnection
  Networks,"** arXiv:2104.11725; **Camarero, Martínez, Beivide (2016), "Projective Networks,"**
  arXiv:1512.07574; **Besta & Hoefler (2014), "Slim Fly,"** *SC'14*, arXiv:1912.08968; **Kashefi et al.
  (2017), "RP2: A DCN Using Projective Planes,"** *Cluster Comput.* 20(4):3499 (paywalled — quantitative
  claims unverified). **Key:** Ramanujan/MMS/projective-plane graphs are diameter-2/3, near-Moore-bound,
  cost- and failure-resilient interconnects. *Relevance:* a converging body of HPC/datacenter work
  showing incidence-geometry topologies buy robustness cheaply — the applied backdrop for FANOS's fabric.
- **Olesker-Taylor, Sauerwald, Sylvester (2024), "Time-Biased Random Walks and Robustness of
  Expanders,"** arXiv:2412.13109; **Harsh, Jyothi, Godfrey (2018), "Expander Datacenters,"**
  arXiv:1811.00212. **Key:** an expander's spectral gap quantifies how much adversarial edge perturbation
  its mixing can absorb; expander DCNs degrade gracefully under load/failure. *Relevance:* directly
  frames the `λ₂`↔DDoS-robustness link FANOS wants to state.

### C. Self-stabilization (Dijkstra lineage → modern)

- **Dijkstra (1974), "Self-Stabilizing Systems in Spite of Distributed Control."** *CACM*
  17(11):643–644. **Key:** founding definition — from **any** initial state, converge to a legitimate
  configuration in finite time and stay. *Relevance:* the qualitative ancestor of FANOS's reflex layer;
  `κ_bootstrap>0` is a **stronger, quantitative** floor (authority never even transiently hits zero),
  not merely "eventual" legitimacy.
- **Ghosh, Gupta, Herman, Pemmaraju (1996/2007), "Fault-Containing Self-Stabilizing Protocols."**
  *Distrib. Comput.* 20(1):53–73. **Key:** for a bounded number of faults, both recovery time and the
  set of processors that change state are bounded **independent of `n`**. *Relevance:* the exact
  classical analogue of FANOS's `⌊log₉Φ⌋` containment radius — names the property FANOS proves
  geometrically.
- **Dolev & Herman (1997), "Superstabilizing Protocols for Dynamic Distributed Systems."** *Chicago J.
  Theor. CS.* **Key:** after a single topology change, a **"passage predicate"** (safety invariant)
  holds continuously throughout reconvergence. *Relevance:* the framing FANOS's healing should adopt —
  "the viability invariant `P>2/7` is never violated mid-repair," which is exactly what
  `κ_bootstrap` + the V-gate guarantee (Candidate 3 makes it a barrier certificate).
- **Nesterenko & Arora (2002), "Tolerance to Unbounded Byzantine Faults."** *IEEE SRDS.* **Key:**
  correct processes outside a bounded **containment radius** of a Byzantine node are immune to it.
  *Relevance:* classical ancestor of "a liar's blast radius is bounded" — pairs with FANOS's polar
  localization + escalation.
- **Duvignau, Raynal, Schiller (2021–2023), self-stabilizing Byzantine consensus trilogy.**
  arXiv:2110.08592, arXiv:2201.12880, arXiv:2311.09075. **Key:** self-stabilizing, signature-free
  intrusion-tolerant consensus/broadcast tolerating `t<n/3` Byzantine processes *and* arbitrary
  transient corruption, with `O(t)` stabilization time. *Relevance:* the live research thread that
  fuses "heal from any state" with "tolerate liars" — the same union FANOS wants at the inter-cell tier.
- **Altisen, Devismes, Dubois, Petit (2019), *Introduction to Distributed Self-Stabilizing
  Algorithms.*** Morgan & Claypool. **Key:** modern taxonomy (daemons, silent/snap/super-stabilization,
  round/move complexity). *Relevance:* the reference for stating FANOS's reflex-layer convergence
  under an adversarial scheduler precisely.

### D. Resilient / Byzantine-robust consensus (MSR family and beyond)

- **LeBlanc, Zhang, Koutsoukos, Sundaram (2013), "Resilient Asymptotic Consensus in Robust Networks."**
  *IEEE JSAC* 31(4):766–781. **Key:** defines **`r`-/`(r,s)`-robustness**; under W-MSR with an
  `F`-total malicious model, **`(F+1,F+1)`-robustness is necessary and sufficient**; `(2F+1)`-robustness
  is sufficient for the `F`-local model. Connectivity/min-degree alone are *insufficient* to
  characterise this. *Relevance:* the foundational resilient-averaging result — the missing
  **quantified** convergence guarantee for FANOS's averaging iterations (Candidate 2). (The fourth
  author is **Koutsoukos**.)
- **Vaidya, Tseng, Liang (2012), "Iterative Approximate Byzantine Consensus in Arbitrary Directed
  Graphs."** *PODC*, arXiv:1201.4183. **Key:** exact necessary-and-sufficient topological condition
  (via "source components" of the reduced graph) for iterative approximate Byzantine consensus on
  sparse digraphs. *Relevance:* tells FANOS how much line-redundancy `PG(2,q)` must retain (after
  losses) to keep resilient averaging feasible.
- **Usevitch & Panagou (2019), "Determining r- and (r,s)-Robustness of Digraphs Using MILP."**
  arXiv:1901.11000. **Key:** exact computation of a graph's robustness from its Laplacian via MILP.
  *Relevance:* the tool to *certify* the `r`-robustness value of the `PG(2,q)` incidence/collinearity
  graph (Candidate 2's proof obligation).
- **Abbas, Shabbir, Li, Koutsoukos (2022), "Resilient Distributed Vector Consensus Using Centerpoints."**
  arXiv:2003.05497, *Automatica* 136:110046. **Key:** replaces the NP-hard Tverberg safe point with a
  **centerpoint**; resilient vector consensus holds iff the adversarial-neighbour fraction is **below
  `1/(d+1)`** in `d` dimensions. *Relevance:* the way to robustly aggregate a *vector/matrix* self-model
  (`Γ`, coarse coherence) across nodes (Candidate 7).
- **Blanchard, El Mhamdi, Guerraoui, Stainer (2017), "Byzantine-Tolerant Machine Learning" (Krum).**
  *NeurIPS*, arXiv:1703.02757. **Key:** **linear/averaging aggregation tolerates zero Byzantine
  workers**; Krum (distance-to-nearest-neighbours selection) tolerates `f<(n−2)/2`. *Relevance:* the
  precise reason FANOS's *plain* line-averaging balancer needs a robust variant (Candidate 2) — one
  liar suffices to bias a mean.
- **Yemini, Nedić, Goldsmith, Gil (2021), "Characterizing Trust and Resilience in Distributed
  Consensus for Cyberphysical Systems."** arXiv:2103.05464 (+ follow-ups arXiv:2403.17907,
  arXiv:2404.07838). **Key:** with stochastic per-edge **trust** observations, almost-sure convergence
  and finite-time liar classification hold even when malicious agents exceed half of connectivity.
  *Relevance:* a statistical complement to FANOS's *deterministic algebraic* liar localization — a
  model for the future SYNARC malicious-node scorer.
- **Lee & Panagou (2024), "Maintaining Strong r-Robustness … using Control Barrier Functions."**
  arXiv:2409.14675 (*ICRA'25*). **Key:** a CBF whose superlevel set keeps graph `r`-robustness **above
  a threshold at all times** during reconfiguration. *Relevance:* fuses robustness-floor maintenance
  with the CBF machinery FANOS should adopt for its safety seam (Candidate 3).

### E. ISS / Lyapunov / contraction / control-barrier network control

- **Sontag (1989), "Smooth Stabilization Implies Coprime Factorization"** (origin of **ISS**), and
  **Sontag & Wang (1995), "Characterizations of the ISS Property."** *IEEE TAC* / *SIAM J. Control
  Optim.* **Key:** ISS ⟺ ∃ ISS-Lyapunov function `V` with `V̇ ≤ −α₃(‖x‖) + γ(‖u‖)`; state ultimately
  bounded by `γ(‖u‖∞)`. *Relevance:* the general theorem FANOS's T-104 estimate `√V'≤−κ√V+‖h‖`
  (⇒ bound `h/κ`) instantiates — FANOS *is* an ISS system with an explicit gain.
- **Dashkovskiy, Rüffer, Wirth (2007/2010), "ISS Small-Gain Theorem for General Networks" /
  "…Construction of ISS-Lyapunov Functions."** arXiv:math/0506434, arXiv:0901.1842. **Key:** `n`
  interconnected ISS subsystems are ISS as a whole iff a **small-gain condition** (spectral-radius-type)
  on the nonlinear gain matrix holds; a network ISS-Lyapunov function is built by scaling the
  per-subsystem ones. *Relevance:* the exact machinery to *prove* FANOS's hierarchical composition
  (`ddos-homeostasis §7`) rigorous — the inter-cell escalation coupling must satisfy this small-gain
  condition (Candidate refinement).
- **Kolathaya & Ames (2019), "Input-to-State Safety With Control Barrier Functions."** *IEEE L-CSS*
  3(1):108–113, arXiv:1803.03035. **Key:** under bounded disturbance, an ISSf-CBF renders a *slightly
  enlarged* safe set forward-invariant, with the enlargement bounded by a class-`𝒦` function of the
  disturbance. *Relevance:* the single closest match to FANOS's combined claim — an ISS ultimate bound
  `h/κ` **coupled to** a hard viability boundary `P>2/7` that must never be crossed (Candidate 3).
- **Ames, Xu, Grizzle, Tabuada (2017), "Control Barrier Function Based Quadratic Programs for Safety
  Critical Systems."** *IEEE TAC*, arXiv:1609.06408 (+ survey Ames et al., ECC'19). **Key:** a CBF `h`
  makes `C={h≥0}` forward-invariant iff `sup_u[ḣ+α(h)]≥0`; safety (CBF) + performance (CLF) unify in a
  single real-time **QP**. *Relevance:* the principled replacement for FANOS's ad-hoc clamps in the
  homeostat / SYNARC seam (Candidate 3).
- **Kelly, Maulloo, Tan (1998), "Rate Control for Communication Networks."** *J. Oper. Res. Soc.*
  49(3):237–252 (and Low & Lapsley 1999). **Key:** network rate control is utility-maximisation whose
  objective is a global **Lyapunov function** ⇒ stable at the fair operating point. *Relevance:* the
  seminal "congestion control *is* a Lyapunov-stabilised system," structurally FANOS's admission `h^(H)`.
- **Tassiulas & Ephremides (1992), "Stability Properties … Max Throughput,"** and **Neely (2010),
  *Stochastic Network Optimization* (drift-plus-penalty).** *IEEE TAC* / Morgan & Claypool. **Key:**
  backpressure/max-weight is throughput-optimal via a quadratic **Lyapunov drift**; drift-plus-penalty
  gives an `[O(V),O(1/V)]` backlog/utility tradeoff. *Relevance:* FANOS's Lindblad leaky-integrator
  admission controller is a Lyapunov-drift controller; the `V`-knob mirrors tuning `κ` vs. responsiveness.
- **Lohmiller & Slotine (1998), "On Contraction Analysis,"** updated by **Tsukamoto, Chung, Slotine
  (2021)** (arXiv:2110.00675); **Russo, di Bernardo, Sontag (2013)** contraction of networks. **Key:**
  a contraction metric `M` with negative generalized Jacobian gives **incremental** (trajectory-to-
  trajectory) stability that composes across networks. *Relevance:* a stronger, metric-based reading of
  FANOS's `λ₂` and `κ` contraction — potentially a cleaner multi-cell composition than a single global `V`.

### F. Attractor / basin / bifurcation / early-warning

- **Menck, Heitzig, Marwan, Kurths (2013), "How Basin Stability Complements the Linear-Stability
  Paradigm."** *Nature Physics* 9:89–92. **Key:** **basin stability** = normalised volume (return
  probability under a reference measure) of a state's basin, estimated by Monte-Carlo — captures *how
  large* a perturbation a state tolerates, unlike a linearization exponent. *Relevance:* the empirical
  complement to FANOS's analytic basin volume `(2/7)²¹` — measures the basin of the **controlled** cell
  (Candidate 5).
- **Scheffer et al. (2009), "Early-Warning Signals for Critical Transitions,"** and **Scheffer et al.
  (2012), "Anticipating Critical Transitions."** *Nature* 461:53–59; *Science* 338:344–348. **Key:**
  near a **saddle-node/fold**, the dominant eigenvalue → 0 ⇒ **critical slowing down**: rising variance,
  rising lag-1 autocorrelation, spectral reddening *before* the transition — generic, model-independent
  leading indicators. *Relevance:* FANOS's death spiral **is** a saddle-node (`stability.md §7.2`); CSD
  gives a *dynamical* early-warning that fires while the mean is still in-band (Candidate 4).
- **Dobson & Chiang (1989), "Towards a Theory of Voltage Collapse in Electric Power Systems."**
  *Syst. Control Lett.* 13(3):253–262. **Key:** voltage collapse is a **saddle-node bifurcation** — a
  stable and unstable equilibrium coalesce and vanish, with characterised post-collapse escape
  dynamics. *Relevance:* the founding real-network account of exactly FANOS's "gate closes ⇒ death
  spiral" mechanism.
- **Gao, Barzel, Barabási (2016), "Universal Resilience Patterns in Complex Networks."** *Nature*
  530:307–312. **Key:** reduces an arbitrary multi-node network to a **single effective 1-D equation**
  for a resilience parameter `β_eff(topology)` whose bifurcation predicts collapse. *Relevance:*
  FANOS's equicorrelated **scalar-`r`/scalar-`P` reduction** is exactly this move — the frontier
  supplies the general-topology justification for it.
- **Ashwin, Wieczorek, Vitolo, Cox (2012), "Tipping Points in Open Systems."** *Phil. Trans. R. Soc. A*
  370:1166–1184, arXiv:1103.0169. **Key:** three tipping mechanisms — **B**-tipping (bifurcation),
  **N**-tipping (noise-induced), **R**-tipping (**rate**-induced: a fast-enough ramp tips even with no
  bifurcation). *Relevance:* an important **caveat** — FANOS's saddle-node analysis covers B-tipping; a
  *fast* attack ramp could R-tip below the static threshold (Honesty ledger; a `[H]` to test).
- **Motter & Lai (2002), "Cascade-Based Attacks on Complex Networks"** (arXiv:cond-mat/0301086); **Watts
  (2002), "A Simple Model of Global Cascades"** (*PNAS*); **Buldyrev et al. (2010), interdependent
  networks** (arXiv:0907.1182). **Key:** load-redistribution and threshold-contagion cascades exhibit
  percolation/first-order collapse; interdependency makes collapse abrupt. *Relevance:* alternative
  collapse mechanisms to check FANOS's cascade against; the `1/9` containment is FANOS's structural
  defense against exactly this.

### G. Homeostatic / allostatic / immune-inspired resilience

- **Ashby (1952/1960), *Design for a Brain* — ultrastability & the homeostat.** **Key:** a system with
  a set of essential variables held in viable bounds by feedback that reconfigures when a variable
  leaves its bound. *Relevance:* the direct cybernetic ancestor of FANOS's band-keeping homeostat and
  the CC viability window; FANOS is a formal, quantitative ultrastable system.
- **Kephart & Chess (2003), "The Vision of Autonomic Computing."** *IEEE Computer* 36(1):41–50. **Key:**
  self-configuring/healing/optimising/protecting systems via a **MAPE-K** (monitor–analyse–plan–execute
  over shared knowledge) loop. *Relevance:* FANOS's DIAKRISIS sense→diagnose→plan→act *is* a MAPE-K
  loop with a *proven* analyse/plan stage — the numbers (`Φ/P/R`, `V`) are the shared knowledge.
- **Forrest, Hofmeyr, Somayaji — Artificial Immune Systems** (negative selection, danger theory,
  dendritic-cell algorithm), 1990s–2000s. **Key:** anomaly detection by self/non-self discrimination.
  *Relevance:* **honest appraisal** — AIS is mostly metaphor with weak guarantees; FANOS deliberately
  does **not** import it. The CC corpus instead *derives* a three-layer "immune" reading (basal
  `κ_bootstrap` = innate; adaptive `κ₀·Coh_E` = acquired; topological `6μ²` = anatomical) from the
  math (`stability.md §2.2`). FANOS's immunity is a *consequence of theorems*, not an analogy — keep it
  that way (the "don't stretch the owl over the globe" directive).

### H. Epidemic / gossip and control-of-epidemics

- **Van Mieghem, Omic, Kooij (2009), "Virus Spread in Networks" (N-intertwined mean-field),** and
  **Chakrabarti, Wang, Wang, Leskovec, Faloutsos (2008) / Prakash et al. (2012).** *IEEE/ACM ToN* /
  *ACM TISSEC*. **Key:** the SIS **epidemic threshold** is `τ_c = 1/λ_max(A)` — a contagion dies out iff
  the effective infection/curing ratio `β/δ < 1/λ_max` of the adjacency matrix. *Relevance:* a
  **spectral** containment certificate: a node-to-node flood on the inter-cell topology self-extinguishes
  iff below `1/λ_max` — complements FANOS's `⌊log₉Φ⌋` topological blast radius (Candidate 6).
- **Preciado, Zargham, Enyioha, Jadbabaie, Pappas (2014), "Optimal Resource Allocation for Network
  Protection Against Spreading Processes."** *IEEE TCNS* 1(1):99–108; CDC'13, arXiv:1303.3984. **Key:**
  allocating curing/vaccination resources to push the spectral condition below threshold at minimum
  cost is a **geometric program** (convex). *Relevance:* the optimal way to allocate the homeostat's
  finite regeneration authority `κ` across nodes to keep `β·λ_max < δ` (Candidate 6, control side).
- **Demers et al. (1987), "Epidemic Algorithms for Replicated Database Maintenance" (anti-entropy /
  gossip),** and **Karp, Schindelhofer, Shenker, Vöcking (2000), "Randomized Rumor Spreading."**
  *PODC* / *FOCS*. **Key:** gossip disseminates/aggregates in `O(log n)` rounds with high robustness to
  node failure. *Relevance:* the robust-dissemination baseline for FANOS's gossiped coherence readings;
  the `log n` rounds are the cost the projective one-round balancer (Candidate 1) undercuts for the
  *averaging* sub-problem.

### I. Predictive (MPC) & active-inference / free-energy control

- **Mayne, Rawlings, Rao, Scokaert (2000), "Constrained Model Predictive Control: Stability and
  Optimality."** *Automatica* 36:789–814. **Key:** MPC with a terminal cost/constraint is stabilising;
  optimise over a receding horizon subject to state/input constraints. *Relevance:* the provable
  planner FANOS's minimax band-keeping approximates; a receding-horizon homeostat is the natural
  predictive upgrade — with the CBF as its safety constraint.
- **Da Costa, Lanillos, Sajid, Friston, et al. (2022), "Active Inference in Robotics and Artificial
  Agents: Survey and Challenges."** arXiv:2112.01871 (+ Friston's free-energy principle corpus).
  **Key:** action = minimising **expected free energy** `G(a) = risk (goal divergence) + ambiguity
  (uncertainty)`; unifies estimation, control, planning under one objective. *Relevance:* precisely the
  SYNARC "learned planner" option — `design-synarc.md §4` shows the EFE action
  `argmin_a[Bures²(ŝ(a),C) − β·IG(a)]` **reduces at `β=0, C=ρ*` to the MPC minimax** `argmin_a‖σ‖_∞`.
  Keep it as the optional exploration layer (`[H]`), never a safety dependency.
- **Cheng, Orosz, Murray, Burdick (2019), "End-to-End Safe RL through Barrier Functions."** *AAAI*,
  arXiv:1903.08792. **Key:** a CBF layer guarantees safety of a learning policy by projecting its
  actions into the safe set. *Relevance:* the template for the SYNARC seam — a learner proposes, a CBF
  filters (Candidate 3); safety is a theorem regardless of what is learned.

---

## 2. Rigorous comparison — what FANOS subsumes/derives vs. where the frontier is stronger

| Frontier cluster | FANOS status | Verdict |
|---|---|---|
| A. Diffusion balancing / spectral gap (Cybenko, Boyd–Xiao) | `λ₂=q/(q+1)²` contraction, unique fixed point, closed form — **derived** | **Subsumed & extremal.** FANOS gets the optimal two-eigenvalue spectrum from geometry; no weight-optimisation needed. *Gap:* FANOS iterates geometrically but the two-eigenvalue structure permits **one-round exact** averaging (Cand 1). |
| A. Finite-time consensus (Sundaram–Hadjicostis) | not exploited | **Complementary, high value.** Directly yields Cand 1. |
| B. Expander / Ramanujan / projective topologies | `PG(2,q)` incidence graph is (near-)Ramanujan (`λ₂=√q`) — **true but unstated** | **Subsumed, worth certifying.** FANOS should *state* the Ramanujan/robustness certificate (Cand 4b); external precedent (Slim Fly, Projective Networks) validates the topology choice. |
| C. Self-stabilization (Dijkstra; fault-containment; superstabilization) | reflex layer + `κ_bootstrap` floor + `⌊log₉Φ⌋` containment — **derived** | **Subsumed & stronger** (quantitative floor vs. eventual legitimacy; geometric containment vs. protocol-specific). *Adopt:* the "passage predicate never violated mid-repair" framing (Cand 3). |
| D. MSR / W-MSR resilient averaging (LeBlanc) | polar liar **localization** + escalate — **derived, and stronger in kind** (identifies *who*) | **Complementary.** FANOS localizes but has **no quantified resilient-convergence bound for its averaging** (load balancer, coherence aggregation). W-MSR + an `r`-robustness certificate supplies the number (Cand 2, 7). |
| E. ISS / Lyapunov / small-gain / drift (Sontag; Dashkovskiy; Tassiulas; Neely) | T-104 = ISS with bound `h/κ`; Lindblad admission = Lyapunov drift — **derived/instantiated** | **Subsumed.** *Refinement:* prove the inter-cell composition meets the **ISS small-gain** condition explicitly. |
| E. Control Barrier Functions (Ames; Kolathaya–Ames ISSf-CBF) | safety via **clamps** — sound but ad hoc | **Complementary, high value.** CBF-QP / ISSf-CBF is the principled, less-conservative, provably forward-invariant replacement (Cand 3). |
| E. Contraction theory (Lohmiller–Slotine) | single global `V` | **Complementary (optional).** A contraction metric may compose multi-cell more cleanly; a research option, not a need. |
| F. Basin of attraction / saddle-node / 1-D reduction (Menck; Dobson; Gao–Barzel) | basin `𝒱`, basin volume `(2/7)²¹`, saddle-node `κ/Γ₂=1`, scalar reduction — **derived** | **Subsumed at theory level.** *Gaps:* empirical basin of the **controlled** cell (Cand 5); the analytic volume is for a *random uncontrolled* state and understates real robustness. |
| F. Critical slowing down / early-warning (Scheffer) | threshold indicator `{P<2/N}⊂{Φ<1}` — **derived** | **Complementary, high value.** CSD is a *variance/autocorrelation* precursor that fires while the mean is still in-band — extra lead time (Cand 4). |
| F. R-tipping (Ashwin) | not modelled | **Complementary caveat.** Fast attack ramps could tip below the static saddle-node — test on sim (`[H]`). |
| G. Homeostasis / ultrastability / MAPE-K (Ashby; Kephart) | band-keeping homeostat, DIAKRISIS loop — **derived** | **Subsumed & formalised.** FANOS is a quantitative ultrastable/MAPE-K system with a *proven* analyse/plan stage. |
| G. Artificial immune systems | corpus derives a 3-layer immune *reading* from the math | **Correctly avoided.** AIS-as-metaphor adds no guarantees; do not import. |
| H. Epidemic threshold `1/λ_max` (Van Mieghem; Preciado) | `⌊log₉Φ⌋` topological containment — **derived** | **Complementary.** A *spectral* ignition certificate + GP curing-allocation, distinct from the topological depth bound (Cand 6). |
| H. Gossip / anti-entropy | gossiped readings | **Subsumed baseline.** Cand 1 undercuts gossip's `log n` for the averaging sub-problem. |
| I. MPC / active inference (Mayne; Friston) | minimax band-keeping; EFE↔minimax shown | **Complementary, future.** Predictive/EFE planner is the SYNARC learned option, reducing to the reflex minimax — optional, sandboxed (`[H]`). |

**Bottom line.** FANOS genuinely *subsumes or instantiates* clusters A (rate), B, C, E (ISS/drift),
F (theory), G. The frontier is genuinely **stronger or complementary** in exactly five places, which
become the top candidates: **finite-time balancing (A)**, **CBF safety seam (E)**, **CSD early-warning
(F)**, **W-MSR robust averaging (D)**, **spectral epidemic containment (H)** — plus lower-ranked
instrumentation (basin telemetry) and future (robust vector aggregation, EFE planner).

---

## 3. Synthesis in UHM / CC + SYNARC terms

Every promising idea lands on one of three CC objects. The organising picture is the **metriplectic
generator** (`T-262`):

```
dΓ/dτ  =  −i[H,Γ]        +     𝒟[Γ]           +      ℛ[Γ,E]
         (reversible work)   (dissipation → I/7)   (regeneration → ρ*)
```

with the sense→act loop `Γ --measure--> (Φ,P,R,r) --plan--> action --actuate--> Γ'` around it, and the
reflex/learnable seam wrapping the whole.

**(i) The dissipator / mixing side `𝒟` — self-balancing.**
Load balancing *is* the mixing sub-generator: line-averaging homogenises load, which minimises `Σcᵢ²`
and so **raises** the cell's mean coherence `r` (convexity — proven in `coherence_ddos.rs`). The
spectral gap `λ₂` is the mixing rate. Frontier ideas here (finite-time deflation, Chebyshev,
second-order diffusion, W-MSR) all reshape **how** `𝒟` mixes — faster, exactly, or Byzantine-robustly —
without touching the fixed point (uniform load) or the attractor `ρ*`. This is the safe place to be
aggressive: mixing has a unique fixed point by 2-transitivity, so no acceleration can create a spurious
extremum.

**(ii) The regenerator `ℛ` and the viability barrier — self-healing.**
`ℛ[Γ,E] = κ·g_V(P)·(ρ*−Γ)` is CC's control input; its rate `κ` and gate `g_V` are the homeostat's
authority. The whole ISS/Lyapunov/CBF cluster lives here: `V=‖Γ−ρ*‖²` is the **control-Lyapunov
function** (performance = descent via `ℛ`), and `h(P)=P−2/7` is the **control-barrier function**
(safety = forward-invariance of `𝒱`). ISSf-CBF (Kolathaya–Ames) is the exact formal union of FANOS's
two guarantees — bounded excursion `h/κ` **and** never crossing `∂𝒱`. The `κ_bootstrap` floor is the
"innate immunity" layer that keeps `ℛ` non-vanishing; the topological barrier `6μ²` (T-69) is why the
saddle-node crossing is continuous (no sudden death) — which is *precisely the regime where CSD
early-warning theory applies*.

**(iii) The attractor geometry — basin, saddle-node, early-warning.**
`ρ*`, the band `𝒜`, and the boundary `∂𝒱` are fixed by theorems, not chosen. Basin stability, CSD, and
the 1-D reduction all *describe* this geometry: CSD reads the approach to the saddle-node; basin
stability measures the size of `𝒱` under control; Gao–Barzel justifies the scalar reduction FANOS
already uses. None of them *moves* the attractor — they instrument it.

**(iv) The reflex/learnable seam — where SYNARC plugs in, and its hard rails.**
The seam is a **projection**: the reflex layer exposes observations `(Φ,P,R,r,r_stab,V)` and accepts a
*bounded* action from a policy; today that policy is a fixed theorem, tomorrow a SYNARC module. The
frontier makes this seam rigorous:

- **Sense** is hardened by robust consensus (W-MSR scalar, centerpoint vector) and enriched by CSD —
  the module receives a *clean, early* self-model.
- **Plan** is the MPC/EFE layer; EFE reduces to the reflex minimax at `β=0`, so the learner only *adds
  exploration*, never a new objective.
- **Act** is filtered by a **CBF-QP**: whatever the module proposes, the QP returns the nearest action
  that keeps `ḣ+α(h)≥0`, i.e. `P>2/7` for all time, with `κ∈[κ_bootstrap,1]`.

The single invariant across all of this: **the SYNARC module may reshape the *approach* to the
attractor — gains, action ordering, which liar to isolate first, how much to explore — but the CBF, the
`κ_bootstrap` floor, the band `𝒜`, and the fixed `ρ*` are theorems it can never move.** Learning lives
strictly inside the proven envelope; every frontier idea above either hardens that envelope (robust
sense, CBF act) or instruments it (CSD, basin), and none is allowed to become a safety dependency.

---

## 4. Ranked, derivable, verifiable candidate improvements

Each: **Claim · Why better · Derivation · Validation on `fanos-sim` · Status.** Ranked by
value × derivability × verifiability × fit to FANOS priorities. **Report-back top 3 = #1, #2, #3.**

### 1. Finite-time (one-round) *exact* projective load balancing  `[D]`, high confidence

**Claim.** The projective balancer reaches the **exact** uniform load in **one** communication round
plus a local affine combine — not the ~8–12 geometric rounds `balance_to_uniform` uses. Because
`A·Aᵀ = qI+J` gives `M = A·Aᵀ/(q+1)²` exactly **two** eigenvalues `{1, λ₂=q/(q+1)²}`, the spectral
projector onto the uniform mode is `P₁ = (M − λ₂I)/(1 − λ₂)`, so

```
mean = P₁·load = (M·load − λ₂·load)/(1 − λ₂).
```

For the Fano cell (`q=2, λ₂=2/9`): `meanᵢ = (9·balance_step(load)ᵢ − 2·loadᵢ)/7`, and substituting the
closed form `balance_step(load)ᵢ = (2·loadᵢ + S)/9` gives `meanᵢ = (2loadᵢ + S − 2loadᵢ)/7 = S/7`
**exactly**.

**Why better.** Exact (not `ε`-approximate); **one** line-averaging round vs. `⌈log(ε/spread)/log(2/9)⌉`.
Each round is a real Maekawa-quorum bus operation with latency, so this is a ~10× cut in *communication
rounds* for the balancing sub-problem — while remaining total-conserving, extremum-free, and
vertex-symmetric. It is the projective instance of Sundaram–Hadjicostis finite-time consensus, of
Nguyen et al.'s finite-time-consensus graphs (arXiv:2311.01317), and of Cybenko's "finite iterations =
#distinct eigenvalues." The geometric magic: `PG(2,q)`'s 2-transitivity
means one line-average already carries the global sum `S` into every node's value, so a single deflation
extracts the exact mean.

**Derivation.** (1) Eigen-structure `[T]`: `J` has eigenvalues `{N, 0^{N−1}}`, so `A·Aᵀ=qI+J` has
`{(q+1)², q^{N−1}}` and `M` has `{1, λ₂^{N−1}}` — proven already. (2) Spectral projector `P₁=(M−λ₂I)/
(1−λ₂)` maps eigenvalue 1→1, λ₂→0, so `P₁ = 11ᵀ/N` (the exact averaging operator). (3) The Fano
substitution above verifies `= S/N`. **Holds for all `q`** (always two eigenvalues) — a general FANOS
theorem, not a Fano coincidence.

**Validation.** Extend `crates/fanos-diakrisis/src/loadbalance.rs` tests + `calypso_balance` /
`coherence_ddos`: (a) property test — for random `[f64;N]`, `deflate(balance_step(load))` equals
`[S/N; N]` to `1e-12`; (b) assert the deflated balancer restores `CollectiveSubject` in **one** round
where `balance_to_uniform` took several (reuse `coherence_ddos.rs` differential-flood harness); (c)
count bus-ops vs. the geometric version.

**Degradation clause `[D]/[H]`.** On a *damaged* cell (node/line down) `M` loses the clean two-eigenvalue
spectrum. `partition.rs`/`spec-math` already give the one-line-down Laplacian spectrum `{0,4,4,7,7,7,7}`
(3 distinct nonzero), so exact finite-time takes `#distinct − 1` rounds (Sundaram–Hadjicostis) or use
Chebyshev/second-order acceleration (Montijano; Muthukrishnan). Compute the damaged-`M` spectrum
numerically and pick the minimal-polynomial degree — a small, verifiable fallback, not a new mechanism.

### 2. Control-Barrier-Function safety seam (ISSf-CBF) for the homeostat / SYNARC  `[E]+[H]`, high value

**Claim.** Recast the homeostat's safety from *clamps* to a **CBF quadratic program**. With CLF `V=‖Γ−ρ*‖²`
(performance: descent via `ℛ`) and CBF `h(P)=P−2/7` (safety: forward-invariance of `𝒱`), any proposed
action `u_prop` (reflex or SYNARC-learned) is projected by

```
u* = argmin_u ‖u − u_prop‖²   s.t.   ḣ(P,u) + α(h) ≥ 0,   κ ∈ [κ_bootstrap, 1],
```

so `P>2/7` holds **for all time**, not merely in expectation. Under a bounded disturbance use the
**ISSf-CBF** form (Kolathaya–Ames): forward-invariance of a slightly enlarged set with enlargement
bounded by a class-`𝒦` function of `‖h‖` — the exact union of FANOS's ISS bound `h/κ` and its hard
viability boundary.

**Why better.** FANOS's clamps are sound but ad hoc and *conservative* — they inner-approximate the true
safe set. A CBF-QP is the standard, **pointwise-optimal** ("smallest deviation from the intended
action") forward-invariance filter, and it is precisely the rigorous form of `design-synarc.md`'s
informal `verify_feedback_stability`. It gives the reflex/learnable seam a single certified operator:
*the learner proposes, the CBF disposes.*

**Derivation.** From `dynamics.rs`, `dP/dτ = −2(λ+a)(P−1/N) + 2κ·g_V(P)(P_ideal−P)`; hence
`ḣ = dP/dτ`. The CBF condition `ḣ + α(h) ≥ 0` (choose `α(h)=γh`, `γ>0`) is linear in the control
authority `κ·g_V`, so the QP is scalar and closed-form. Show the existing clamp
`κ∈[κ_bootstrap,1]` is a conservative subset of the CBF-feasible set (so the CBF is never *less* safe,
sometimes *more* permissive).

**Validation.** `homeostat.rs`+`dynamics.rs`: (a) property test — over adversarial/random `u_prop`, the
CBF-filtered trajectory keeps `P>2/7` across the `empirical_threshold` sweep already in `dynamics.rs`;
(b) show the CBF tolerates an attack strictly larger than the clamp version reaches, *without* crossing
`∂𝒱` (less conservative, still safe); (c) confirm reduction — at `u_prop = reflex action`, `u* = u_prop`
in-band (the CBF is inactive when safe).

**Status.** CBF-QP / ISSf-CBF are `[E]` (proven machinery); the mapping is `[D]`; "less conservative
than clamps while still safe" is `[H]` to verify on sim. Hardens the exact seam the project prioritises.

### 3. Critical-slowing-down early-warning as a second, dynamical leading indicator  `[E]+[H]`, high value, low risk

**Claim.** Add a CSD detector to the observatory: on a sliding window of the `P` (or `r`) time series,
estimate **lag-1 autocorrelation** and **variance**; a monotone rise signals the approaching
saddle-node **before** the mean leaves the band — earlier and more robustly than the threshold-crossing
`{P<2/N}⊂{Φ<1}`.

**Why better.** FANOS's current leading indicator triggers when the *mean* crosses a threshold; CSD is a
*fluctuation* precursor that rises while the mean is still healthy (Scheffer). It is pure observation —
**it changes no control**, so it cannot harm the proven envelope — and it strengthens FANOS's
"anticipatory defense, act a regime before failure" claim (`design-synarc.md §0.5`).

**Derivation.** Linearise the reduced `dP/dτ` near the fold: the recovery rate = `|dominant eigenvalue|
→ 0` at `κ/Γ₂→1`, so under additive noise `P` is Ornstein–Uhlenbeck with AR(1) coefficient `→ 1` and
stationary variance `→ ∞` as `a → a*`. Estimate both on the observatory window; the saddle-node is
`[T]` (corpus), CSD-near-fold is `[E]`.

**Validation.** Extend `observatory.rs` + `coherence_ddos.rs`: in the attack sweep, assert windowed
variance and lag-1 autocorrelation of `P` rise monotonically and cross a detector threshold at
`progress < a*`-crossing (positive CSD lead time — mirror the existing `CascadeForecast::lead()` test);
assert a diversified (non-cascading) field shows *no* CSD rise (no false alarm).

**Status.** `[H]` on the exact lead-time; near-zero risk (observation only), high operational value.

### 4. Quantified topology-robustness certificates  `[D]/[H]`, medium-high

Two cheap, statable certificates FANOS's geometry *already earns* but does not claim:

**4a. Byzantine-robust averaging via W-MSR + `r`-robustness.** The line-averaging balancer and any
coherence-aggregation are **linear** iterations — one Byzantine node biases the mean (Blanchard et al.:
linear tolerates zero liars). Replace each line-average with a **W-MSR** trim (drop the `F` highest/
lowest reported values before averaging) and prove the `PG(2,q)` collinearity/incidence graph is
`(F+1,F+1)`-robust for an explicit `F(q)` (compute via Usevitch–Panagou MILP, or analytically from
`(q+1)`-regularity + 2-transitivity). Then LeBlanc et al. gives resilient convergence despite `F` liars
per neighbourhood — a **number** for the balancer's Byzantine tolerance, complementing polar
localization (which says *who* lied). *Validate:* `byzantine.rs` — plain balancer biases under a false-
load node, W-MSR stays within `ε` up to `F`, fails at `F+1`. *Status:* W-MSR is `[E]`; the `r`-value for
`PG(2,q)` is `[H]` to compute/prove.

**4b. Ramanujan/expander certificate.** State the fact FANOS gets for free: the `PG(2,q)` incidence
graph is `(q+1)`-regular bipartite with nontrivial eigenvalue `√q`, i.e. it meets the bipartite
**Ramanujan** bound (Marcus–Spielman–Srivastava), and by the **Alon–Boppana** ceiling `2√(d−1)` no
regular family can do asymptotically better — so FANOS's mixing and fault-tolerance are spectrally
near-optimal *by construction*, not by tuning. The deployed precedents **PolarFly** (arXiv:2208.01695)
and **SpectralFly** (arXiv:2104.11725) show incidence/Ramanujan topologies are real, robust interconnects.
*Validate:* `eig.rs`/`partition.rs` — assert the incidence spectrum equals `{±(q+1), ±√q}`. *Status:*
`[D]` (elementary from `A·Aᵀ=qI+J`), a low-effort documentation/verification win.

### 5. Spectral epidemic-threshold containment certificate  `[E]+[H]`, medium

**Claim.** Model a flood that propagates *between cells* as an SIS process on the inter-cell topology; by
the `τ_c=1/λ_max` threshold it self-extinguishes iff the effective per-hop gain/curing ratio
`β/δ < 1/λ_max(A)`. This is a **spectral** ignition certificate complementing the **topological**
`⌊log₉Φ⌋` depth bound, and it maps the regeneration authority to curing: keep `β·λ_max < δ` with `δ↔κ`.
Preciado et al.'s geometric program then allocates finite `κ` across nodes at minimum cost.

**Why better.** `⌊log₉Φ⌋` bounds how *far* an over-budget perturbation ripples; the epidemic threshold
says whether a node-to-node contagion **ignites at all** — a sharper, different condition tied to
`λ_max`. It also unifies "the spectral gap that balances load" with "the spectral radius that contains
contagion."

**Validation.** New harness extending `calypso_ddos.rs`: propagate a cross-cell flood, sweep `β/δ`,
assert die-out iff below `1/λ_max`; check GP-allocated `κ` beats uniform `κ` at equal budget.

**Status.** Threshold is `[E]`; the identification (flood↔SIS, `κ↔δ`, chosen topology/`λ_max`) is a
**modelling `[H]`** — frame as a complementary certificate, not a replacement, and validate before
claiming.

### 6. Empirical basin-stability telemetry for the *controlled* cell  `[E]`, medium (instrumentation)

**Claim.** Add a Menck-style Monte-Carlo basin-stability estimate `S_B(κ)` = fraction of random initial
`Γ` (and random sustained attacks) that return to the band with the homeostat on. **Why better:** the
analytic `(2/7)²¹` is for a *random uncontrolled* state and drastically understates real robustness; the
homeostat's `ℛ` reshapes the flow and enlarges the basin. `S_B(κ)` is the honest operational resilience
metric and makes the SYNARC gain objective concrete ("maximise `S_B` within the envelope").
**Validation:** sample initial conditions over `dynamics.rs`/the full Lindblad, controller on/off,
report `S_B` with a confidence interval; assert `S_B(on) ≫ S_B(off)` and `S_B` increasing in `κ`.
**Status:** `[E]` method, FANOS numbers `[E→measured]`; a telemetry/observatory upgrade.

### 7. Resilient vector consensus (centerpoint) for cross-cell `Γ` aggregation  `[E]+[H]`, lower

**Claim.** When cells aggregate a coarse coherence/self-model vector, use centerpoint-based resilient
vector consensus (Abbas et al.): the safe aggregate exists and is Byzantine-robust when the adversarial
fraction `< 1/(d+1)`. **Why better:** complements polar localization with a robust *estimator* — the
aggregated self-model stays in the convex hull of honest views even before a liar is escalated.
**Status:** `[E]` method; mapping to FANOS `Γ`-aggregation is a design `[H]`; bites mainly at the
inter-cell tier (intra-cell readings are local).

### 8. Predictive / active-inference planner as the SYNARC exploration layer  `[H]`, future/optional

**Claim.** Offer a receding-horizon MPC (Mayne et al.) / expected-free-energy (active inference)
*planner* as the SYNARC learned option, with the CBF (Cand 2) as its hard constraint. `design-synarc.md
§4` already shows EFE reduces to the reflex minimax at `β=0, C=ρ*`, so this only *adds exploration*.
**Status:** explicitly `[H]`/future, sandboxed, never a safety dependency — the reflex minimax remains
the provable default. Listed for completeness of the frontier map, not for near-term build.

---

## 5. Honesty ledger

**Derived here from FANOS's own proven structure `[D]` (checkable now).**
- Finite-time one-round exact balancing (Cand 1) — elementary consequence of the two-eigenvalue spectrum
  already proven; verifiable to machine precision.
- The Ramanujan/expander certificate (Cand 4b) — direct from `A·Aᵀ=qI+J`.
- The CBF construction `h(P)=P−2/7`, `ḣ=dP/dτ` (Cand 2 derivation) — from the shipped reduced dynamics.

**Established external results `[E]` FANOS can adopt/instantiate.**
- ISSf-CBF, CBF-QP, W-MSR + `r`-robustness, Menck basin stability, Scheffer CSD, `τ_c=1/λ_max`,
  Sundaram–Hadjicostis finite-time, Chebyshev/second-order diffusion, ISS small-gain. Each is
  peer-reviewed; the *mapping* to FANOS is what must be validated.

**Hypotheses `[H]` — must pass a `fanos-sim` gate before they are believed or shipped.**
- Cand 2's "less conservative than clamps while still safe"; Cand 3's exact CSD lead-time on FANOS's
  dynamics; Cand 4a's `r`-robustness *value* for `PG(2,q)`; Cand 5's flood↔SIS identification and the
  right `λ_max`; the **R-tipping caveat** (a fast attack ramp may tip below the static saddle-node —
  Ashwin) is an open risk to test, not a claim.

**Explicitly *not* claimed / not to import.**
- No artificial-immune-system machinery (metaphor, no guarantees) — FANOS's immunity is *derived*
  (basal/adaptive/topological), keep it that way.
- No claim that any candidate moves the attractor `ρ*`, widens the band `𝒜`, lowers `κ_bootstrap`, or
  weakens the viability barrier — by construction none of them may. The SYNARC layer tunes the
  *approach*, never the envelope.
- No learned behaviour ships as a safety dependency: SYNARC is spec-only; the CBF filter and the reflex
  minimax are what guarantee safety regardless of what (if anything) is learned.

---

## References (arXiv ids / URLs)

*Load balancing & consensus (A).* Cybenko, *JPDC* 7(2):279–301 (1989) · Boyd–Diaconis–Xiao,
[SIAM Rev. 46(4):667](https://epubs.siam.org/doi/10.1137/S0036144503423264) (2004) · Xiao–Boyd,
*Syst. Control Lett.* 53:65 (2004) · Boyd–Ghosh–Prabhakar–Shah, "Randomized Gossip," *IEEE T-IT*
52(6):2508 (2006) · Sundaram–Hadjicostis, *ACC* (2007) · Nguyen–Jiang–Ying–Uribe
[arXiv:2311.01317](https://arxiv.org/abs/2311.01317) · Rabani–Sinclair–Wanka, *FOCS* (1998) ·
Montijano et al., *IEEE TSP* (2013); Kokiopoulou–Frossard
[arXiv:0802.3992](https://arxiv.org/abs/0802.3992) · Muthukrishnan–Ghosh–Schultz, *Theory Comput.
Syst.* 31:331 (1998) · Azar–Broder–Karlin–Upfal, *SIAM J. Comput.* 29(1):180 (1999) · Becchetti et al.
[arXiv:1501.04822](https://arxiv.org/abs/1501.04822) · Berenbrink et al.
[arXiv:2510.15473](https://arxiv.org/abs/2510.15473).
*Topologies (B).* Hoory–Linial–Wigderson, *Bull. AMS* 43:439 (2006) · Lubotzky–Phillips–Sarnak,
*Combinatorica* 8(3):261 (1988) · Alon–Boppana / Nilli, *Discrete Math.* 91:207 (1991) ·
Marcus–Spielman–Srivastava [arXiv:1304.4132](https://arxiv.org/abs/1304.4132),
[arXiv:1505.08010](https://arxiv.org/abs/1505.08010) (*Annals* 2015) · Lakhotia et al. "PolarFly"
[arXiv:2208.01695](https://arxiv.org/abs/2208.01695) (*SC'22*), "PolarStar"
[arXiv:2302.07217](https://arxiv.org/abs/2302.07217) · Young et al. "SpectralFly"
[arXiv:2104.11725](https://arxiv.org/abs/2104.11725) · Camarero–Martínez–Beivide
[arXiv:1512.07574](https://arxiv.org/abs/1512.07574) · Besta–Hoefler
[arXiv:1912.08968](https://arxiv.org/abs/1912.08968) (*SC'14*) · Olesker-Taylor et al.
[arXiv:2412.13109](https://arxiv.org/abs/2412.13109) · Harsh et al.
[arXiv:1811.00212](https://arxiv.org/abs/1811.00212).
*Self-stabilization (C).* Dijkstra, *CACM* 17(11):643 (1974) · Ghosh et al., *Distrib. Comput.*
20(1):53 (2007) · Dolev–Herman, *Chicago J. TCS* (1997) · Nesterenko–Arora, *SRDS* (2002) ·
Duvignau–Raynal–Schiller [arXiv:2110.08592](https://arxiv.org/abs/2110.08592),
[arXiv:2201.12880](https://arxiv.org/abs/2201.12880),
[arXiv:2311.09075](https://arxiv.org/abs/2311.09075) · Altisen et al., Morgan & Claypool (2019).
*Resilient consensus (D).* LeBlanc–Zhang–Koutsoukos–Sundaram, *IEEE JSAC* 31(4):766 (2013) ·
Vaidya–Tseng–Liang [arXiv:1201.4183](https://arxiv.org/abs/1201.4183) · Usevitch–Panagou
[arXiv:1901.11000](https://arxiv.org/abs/1901.11000) · Abbas et al.
[arXiv:2003.05497](https://arxiv.org/abs/2003.05497) (*Automatica* 2022) · Blanchard et al.
[arXiv:1703.02757](https://arxiv.org/abs/1703.02757) · Yemini et al.
[arXiv:2103.05464](https://arxiv.org/abs/2103.05464) · Lee–Panagou
[arXiv:2409.14675](https://arxiv.org/abs/2409.14675).
*ISS / Lyapunov / CBF (E).* Sontag, *IEEE TAC* 34:435 (1989); Sontag–Wang, *SIAM JCO* (1995) ·
Dashkovskiy–Rüffer–Wirth [arXiv:math/0506434](https://arxiv.org/abs/math/0506434),
[arXiv:0901.1842](https://arxiv.org/abs/0901.1842) · Kolathaya–Ames
[arXiv:1803.03035](https://arxiv.org/abs/1803.03035) · Ames et al.
[arXiv:1609.06408](https://arxiv.org/abs/1609.06408) · Kelly–Maulloo–Tan, *JORS* 49:237 (1998) ·
Tassiulas–Ephremides, *IEEE TAC* 37:1936 (1992); Neely, Morgan & Claypool (2010) ·
Tsukamoto–Chung–Slotine [arXiv:2110.00675](https://arxiv.org/abs/2110.00675).
*Basin / bifurcation / early-warning (F).* Menck et al., *Nature Physics* 9:89 (2013) · Scheffer et al.,
*Nature* 461:53 (2009); *Science* 338:344 (2012) · Dobson–Chiang, *Syst. Control Lett.* 13:253 (1989) ·
Gao–Barzel–Barabási, *Nature* 530:307 (2016) · Ashwin et al.
[arXiv:1103.0169](https://arxiv.org/abs/1103.0169) · Motter–Lai
[arXiv:cond-mat/0301086](https://arxiv.org/abs/cond-mat/0301086) · Buldyrev et al.
[arXiv:0907.1182](https://arxiv.org/abs/0907.1182).
*Homeostasis / immune (G).* Ashby, *Design for a Brain* (1952) · Kephart–Chess, *IEEE Computer* 36:41
(2003) · Forrest–Hofmeyr–Somayaji, AIS (1990s–2000s, metaphorical — appraised, not adopted).
*Epidemics (H).* Van Mieghem–Omic–Kooij, *IEEE/ACM ToN* (2009); Chakrabarti et al., *ACM TISSEC* (2008) ·
Preciado et al. [arXiv:1303.3984](https://arxiv.org/abs/1303.3984) (*IEEE TCNS* 2014) · Demers et al.,
*PODC* (1987); Karp et al., *FOCS* (2000).
*Predictive / active inference (I).* Mayne et al., *Automatica* 36:789 (2000) · Da Costa–Lanillos et al.
[arXiv:2112.01871](https://arxiv.org/abs/2112.01871) · Cheng et al.
[arXiv:1903.08792](https://arxiv.org/abs/1903.08792).

*This survey recommends nothing FANOS has not already earned the right to prove: every candidate either
makes a shipped guarantee sharper (finite-time balancing, CBF safety, robustness certificates) or adds a
new eye that cannot harm the organism (CSD, basin telemetry) — and each carries a simulator gate it must
pass before it is believed.*
