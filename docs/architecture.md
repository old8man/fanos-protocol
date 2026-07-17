# FANOS implementation architecture — sans-I/O core, swappable environment

## The requirement

We cannot test on a real fleet, so we need to run the **real production node code** in a
single process, as if every node were real, with the *environment and transport substituted*.
The simulator must not be a second, simplified model of the protocol — it must be a different
**driver** of the exact same logic that ships.

## The principle: sans-I/O

The node's protocol logic is written **without any I/O, wall-clock, or OS-randomness calls**.
It is a pure state machine:

```
step(now: Instant, input: Input) -> Vec<Effect>
```

* **Inputs** are the only things that reach it: a received frame, a fired timer, an
  application command.
* **Effects** are the only things it can cause: send a frame, arm a timer, notify the
  application.

The engine never touches a socket, `std::time`, or an RNG. Everything external is named in
`Input`/`Effect` and performed by whatever **driver** owns the engine. This is the pattern
proven by `quinn`, `rustls`, and `str0m`: the protocol is a value, the world is injected.

```
        ┌─────────────────────────────────────────────────────────┐
        │  Engine (production code, sans-I/O, deterministic)        │
        │    OverlayNode<F> : step(now, Input) -> [Effect]          │
        │    uses fanos-core / -diakrisis / -wire (all pure)        │
        └───────────────▲───────────────────────┬──────────────────┘
                 Input  │                        │  Effect
        ┌───────────────┴───────────────────────▼──────────────────┐
        │  Driver — provides Time · Transport · Entropy             │
        │                                                           │
        │   fanos-sim  (in-process, virtual clock, in-memory net)   │  ← driver A
        │   fanos-quic (QUIC/TLS-1.3 over UDP, system clock)        │  ← driver B, SAME engine
        └───────────────────────────────────────────────────────────┘
```

Because the engine only ever sees its own local inputs, a thousand engines in one process are
**genuinely independent nodes** — there is no global oracle, no shared mutable state, no way
for one node's logic to see another's. That is what makes the simulation faithful.

## The three environment ports

Everything the outside world provides is one of three ports, all injected via `Input`/`Effect`
rather than called directly:

| Port | Production driver | Simulator driver |
|---|---|---|
| **Time** | monotonic system clock, OS timers | a virtual `u64` nanosecond clock + an event queue |
| **Transport** | QUIC frames over UDP | an in-memory queue routing frames between inboxes |
| **Entropy** | OS CSPRNG | a seeded deterministic RNG, so every run is reproducible |

The engine receives time as the `now` argument, randomness as a seed handed in at construction
(all per-node randomness is a PRF of that seed + context), and transport purely through
`Input::Message` / `Effect::Send`. Swap the driver, keep the engine.

## Layering

```
fanos-field / -geometry / -code / -diakrisis / -wire / -crypto / -core   pure algebra & logic (no I/O)
        │
fanos-nyx                                                                 privacy behaviour (still pure)
        │
fanos-runtime   Input/Effect/Instant + the OverlayNode engine            THE production node, sans-I/O
        │
fanos-sim       virtual clock · in-memory net · faults · metrics         driver A (research)
fanos-quic      QUIC/TLS-1.3 · system clock · tokio timers               driver B (deployment)
```

The lower crates were already pure functions, so they satisfy the discipline for free. The
runtime turns them into a state machine; the drivers turn the state machine into a running
network. Both drivers exist today: `fanos-quic` runs the byte-for-byte `OverlayNode` that
`fanos-sim` fault-tests over a real loopback socket (delivery, connection reuse, live-peer
death detection), which is the sans-I/O thesis discharged, not merely asserted.

## The reflexive loop: sense → act (self-healing)

DIAKRISIS is not a passive monitor. Each diagnostic round (`Command::Diagnose`) produces a
[`Verdict`], and — because the reflexive loop *acts* (spec §6.9) — a bounded `HealingPlan`
derived from it: reroute around a loss along the projective LRC, regenerate lost shards by
peeling, escalate an irrecoverable hyperoval to the parent, quarantine a Byzantine member, or
shed correlation on a cascade early-warning. Every action is fixed by the geometry and the
corpus healing theory (`Φ→Φ/9` reroute budget, `mediator` reroute, `τ=1/Δ` cooldown), never
tuned. The node applies the plan to its own reroute/repair/quarantine state and emits it as
notifications, so the simulator can assert service continuity (traffic to a crashed node still
delivers via its co-linear survivor) as an emergent property.

## What the simulator buys us (why simulate)

A deterministic, single-host simulator of the real code lets us **research** the protocol's
claims as *emergent behaviour of independent nodes*, not just as unit-tested formulas:

1. **Fault modelling** — crash, grey/slow, Byzantine (drop / corrupt / equivocate), eclipse,
   partition, churn, each injected at the driver so the engine code is unchanged. We watch
   DIAKRISIS localize and heal them end to end.
2. **Reproducibility** — a seed fixes the whole run (network order, latencies, RNG), so any
   observed bug replays exactly. This is testing that CI can gate on.
3. **Adversary experiments** — vary the adversary fraction `f` and threshold `t` and measure
   the *actual* endpoint-linkage rate against the `P_hop²` curve (V5); vary mixing `μ` and
   measure the *actual* anonymity-set entropy (V7).
4. **Scale & phase behaviour** — drive inter-node behavioural correlation toward `r* = 1/√6`
   and watch the cascade early-warning fire before any node has failed (V15/§6.5).
5. **Regression & conformance** — the same scenarios run in CI; a change that breaks
   quorum intersection, syndrome localization, or partition resistance fails a test.
6. **Confidence before deployment** — the code that passes the simulator is the code that
   ships; only the driver changes.

## Determinism contract

* No `std::time`, `Instant::now`, `SystemTime`, or `Date` in engine or driver logic — virtual
  time only.
* No `rand::thread_rng` — all randomness derives from the run seed via a splittable PRF.
* Event ties (same timestamp) break by a total order (`(time, node, sequence)`), so scheduling
  is deterministic regardless of map iteration order.

Given a seed and a scenario, the simulator produces byte-identical metrics on every run and
every platform.
