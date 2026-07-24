# FANOS — the Simulation Lab (operator console + scale-out fleet)

> One engine, many drivers — and now, one **lens** over a whole fleet of them. The `fanos-sim` engine
> that powers the T2 test tier (`design-testing.md`) also powers an interactive operator console:
> launch 1 → 10 000 nodes, watch their state live, drive edge-case experiments at any scale, and read
> the platform's own viability gate. Everything an operator sees is the *real* production self-model,
> under the *deterministic* simulator — the "the devnet is production" claim, made operable.

This extends [`design-testing.md`](design-testing.md) (the verification-tier taxonomy; the lab is the
human-facing face of tier **T2**) and [`design-telemetry.md`](design-telemetry.md) (the per-node
self-model the lab aggregates). Where those state *how the suite is layered* and *what a node observes*,
this states *how an operator runs and reads a fleet at scale*.

---

## 0. Thesis — the coherence self-model is per base cell, so scale is a *recursion of cells*

The load-bearing fact that shapes the whole lab: the DIAKRISIS coherence self-model is defined **per base
7-node Fano cell** (`overlay.rs::cell_liveness` senses a 3-bit syndrome over exactly the seven points
`Point::at(0..7)`, gated on `self_index`). A single large projective plane is therefore **not** one big
coherent cell — its nodes report *no* per-node self-model at all (empirically: `spawn_cell::<F31>` = 993
nodes, **zero** reporting). Genuine coherence at scale is what the network itself does: a **recursion of
small coherent cells** (spec §L1). The lab is built on that truth — a *federation* of base cells, each a
real, deterministically-seeded, coherent 7-node `F2` cell — rather than the mirage of a single 10 000-node
plane. A base cell's `O(N²)` heartbeat is bounded to `N = 7`, so the fleet scales by *count of cheap cells*,
which is exactly why 10 000 nodes stay tractable.

---

## 1. The stack, bottom to top

### `Sim::fleet_snapshot` — cross-node state inspection (`fanos-sim/src/fleet.rs`)

The `Engine` trait is deliberately minimal (`step` + `address`), so a node's internals are not queryable.
But every node already **publishes** its coherence self-model each telemetry window as
`Notification::Observed(CoherenceFrame)` (the reflex runs every heartbeat since audit #122), and its
diagnostic `Notification::Verdict`. `Sim` banks the latest of each per node (`latest_observed`,
`latest_verdict` — `O(1)` per emission, read-only w.r.t. the run, so the **determinism contract is
untouched**), and `fleet_snapshot()` folds them — with ground-truth liveness and the run's `Metrics` — into
a `FleetSnapshot`:

- one `NodeState` per node: `coord`, `alive`, decoded `CoherenceSnapshot` (Φ/P/R/regime/alarm/syndrome),
  and the diagnostic `Verdict` (`Partition`/`Localized`/`Escalate`/`Structural`/`Systemic`);
- the cluster rollup `ClusterStats`: alive / reporting / faulted / ready / **partitioned** / **diagnosed**
  counts, mean & min Φ, mean P/R, and the regime + alarm histograms.

`refresh_telemetry()` forces a sense-only `Command::Observe` round — the `O(N)` inspection path used at
large scale (no `O(N²)` heartbeat).

### `Cluster` — the scale-out fleet (`fanos-sim/src/cluster.rs`)

A federation of base cells presented as one addressable fleet. `Cluster::with_node_target(seed, cfg, n)`
gives smooth 1 → N scaling (a single growing cell up to 7, then more cells; the last partial). `run_for` /
`refresh_telemetry` step every cell; `cell_mut(i)` reaches in for a targeted experiment; `snapshot()`
returns a `ClusterSnapshot` (each cell's `FleetSnapshot`, the cross-cell `ClusterStats` total, summed
`Metrics`, and `troubled_cells()` — the drill-down list when the fleet is too big to render node-by-node).
Cells are independent coherence domains (the real recursion), so a fault is contained to its cell.

### `fanos-observatory::cluster_dashboard` — the ratatui view

A pure, `TestBackend`-testable `render_cluster(frame, &ClusterDashboard)`: cluster vitals gauges
(alive / reporting / mean Φ / healthy), the regime + alarm distributions, a **diagnosis line**
(partitioned / diagnosed / faulted), a run-metrics line, and a **cell-health heatmap** — one glyph per
cell, coloured by its worst state, so a single degraded cell among a thousand pops out. Drilling into a
cell (`←→`, or `t` to jump to the next troubled one) shows that cell's **instrument panel**: Φ/P/R, the
collective-subject regime, the Fano syndrome, a partition banner, and the per-node roster. The operator
path is *fleet overview → cell instrument → per-node state* — the single-cell observatory, scaled.

### `fanos-lab` — the console (`fanos-observatory/src/bin/lab.rs`, clap)

```text
fanos-lab run   --nodes N [--seed S] [--run-ms MS] [--json]   # run, print cluster state
fanos-lab watch --nodes N [--experiment X] [--fraction F]     # live dashboard (chaos optional)
fanos-lab sweep [--experiment X] [--max-nodes N]              # state (& resilience) 7 → 10003, one table
fanos-lab experiment <name> --nodes N [--fraction F] [--json] # run one edge case, report the response
fanos-lab scenarios                                           # list experiments
fanos-lab gate                                                # the HOLARCH viability panel (fanos-holarch)
```

Watch keys: `q` quit · `space` pause · `f` fault a cell · `h` heal · `t` next issue · `←→` inspect a cell.

---

## 2. The stress catalog — `fanos_sim::stress` (chaos-engineering the fleet)

The 50+ single-cell scenarios in `crates/fanos-sim/tests/` pin named adversarial *properties* on one cell;
this is the complementary axis — parametric perturbations of a whole `Cluster`, each with the fleet's
homeostatic response captured in an `ExperimentReport` (peak troubled cells, peak diagnosed / partitioned,
decouples, deepest mean-Φ dip, ended-healthy). Every target is chosen **by index** (never a clock or RNG),
so a run reproduces exactly — the determinism contract, lifted to the fleet. The signatures are **distinct**,
which is the point: the same fleet answers different insults differently.

| experiment | insult | homeostatic signature |
|---|---|---|
| `mass-crash` | crash a fraction of nodes (whole cells first), one-shot | degradation contained per cell; no resurrection |
| `churn` | crash + later recover a few nodes each tick | bounded, never cascading (diversified failure) |
| `cascade` | crash one more of a target cell each tick | that cell collapses alone; **localizable** diagnoses |
| `partition` | hard 4\|3 network cut on a fraction of cells, then heal | cells degrade + recover; nodes stay alive |
| `soft-partition` | *lossy* cut (§6.5 incipient split), then heal | trips the **`Partition` verdict** — the Fiedler sensor catching what liveness cannot (every node alive) |
| `flood` | common-mode routed load (DDoS) into a fraction of cells | the T-104 homeostat **sheds** correlation (Decouple) — availability by shedding, not crashing |

The trigger discipline is preserved from the single-cell tests: a flood sheds because of *correlation*,
not *volume*; a soft partition is *detected* though *liveness* misses it. The lab makes these visible at
fleet scale.

---

## 3. What the lab does *not* do (honest limits)

- **Coherence and routing are two lenses, deliberately separate.** The federated `Cluster` is the
  *coherence* lens — cells are independent coherence domains (which is *why* coherence works at scale), so
  it cannot express cross-cell message routing. The complementary *routing* lens now exists as
  `Hierarchy` (`fanos-sim/src/hierarchy.rs`): a connected two-level tree on one transport plane with
  partial routing tables, exercising genuine §L1 up-and-over **descent** and **fault containment** (crash a
  gateway → its sub-cell is severed, the others untouched — B4/G3). It does *not* model coherence (that is
  per base cell, transport points `0..6`), and it is a routing-**correctness** substrate at cell-tree scale
  (transport is one flat plane, so `Join`/heartbeat still flood `O(N²)`), not a 10k-node load test. What
  remains: deeper trees, partition-**escalation** to a parent, wiring the routing lens into `fanos-lab` as
  its own command + experiments, and — the one hard change — generalising `cell_liveness` off its `0..6`
  coupling so a *single* topology could carry both lenses at once.
- **Fleet-snapshot observability fits availability, not integrity or anonymity.** The snapshot reads
  liveness + coherence + diagnostic verdict, which the availability / partition / DDoS experiments move.
  Byzantine (lying about state) and anonymity (traffic analysis) are about *specific diagnoses* and
  *metadata correlation* — better served by their single-cell tests (`byzantine.rs`, `traffic_analysis.rs`,
  …), whose observables are exact assertions, not fleet aggregates.
- **`f64` in the lab is fine — it is a host tool.** The lab evaluates on the operator's machine to *show*
  state; it carries no determinism or DoS obligation on any network path (unlike the runtime DIAKRISIS
  diagnostics, which stay off `f64` on the hot path).

---

## 4. Running it

```text
cargo run -p fanos-observatory --bin fanos-lab -- sweep                 # coherence at every scale
cargo run -p fanos-observatory --bin fanos-lab -- watch --nodes 350 --experiment soft-partition
cargo run -p fanos-observatory --bin fanos-lab -- experiment flood --nodes 1001 --fraction 0.5
cargo test -p fanos-sim --test fleet --test cluster --test stress       # the lab's own regression guards
```

The lab shares the T2 determinism keystone: same `(seed, inputs)` → byte-identical run, so any experiment
is a permanent, replayable regression guard, not an anecdote.
