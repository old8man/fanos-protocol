# Minimum deployment: how many nodes, and what hardware

Derived from the code and **measured** on a running node, 2026-07-29. Every figure below either follows from a
constant in the tree or was read off a live process; where a number is an estimate rather than a measurement,
it says so.

## Part 1 — How many nodes

There is no single answer, because the minimum depends on which property you want. Four different mechanisms
impose four different floors, and the largest one that matters to you is your minimum.

### The structural floor: 7

A cell is a projective plane `PG(2, q)`, and the smallest projective plane is the **Fano plane**, `q = 2`, with
`n = q² + q + 1 = 7` points. There is nothing below it — `CellParams::derive` refuses `q < 2` outright. Seven is
therefore the floor for *any* FANOS cell.

The supported orders are `q ∈ {2, 4, 7, 31}`, giving cells of **7, 21, 57 and 993** nodes.

### The consensus floor: 7 nodes, tolerating 2 faults

For a cell of `n` points, `f = ⌊(n−1)/3⌋` and quorum `Q = ⌈(n + f + 1)/2⌉`:

| `q` | nodes `n` | faults tolerated `f` | quorum `Q` |
|---|---|---|---|
| 2 | 7 | 2 | 5 |
| 4 | 21 | 6 | 14 |
| 7 | 57 | 18 | 38 |
| 31 | 993 | 330 | 662 |

A Fano cell survives **two** Byzantine or crashed validators and halts at three. That is the tightest
(optimal) PBFT system, not a weakness — but it means a 7-node deployment has no spare capacity for a third
simultaneous failure, planned or otherwise.

### The storage floor: 3 reachable holders

Values are erasure-coded `[7, 3, 4]`: one shard per point, any **3** reconstruct. So storage survives four
simultaneous losses of the seven, which is a *looser* bound than consensus — a cell that has halted may still be
serving reads.

### The anonymity floor: this is the real constraint

The plane order bounds anonymity directly. An adversary's flow-matching floor is `1/K` for `K` concurrent
circuits, and `K` comes from the plane rather than from the mix schedule. On a Fano cell that is `1/7` at best —
**weak**, and a 7-node network should be treated as a functional testbed, not as an anonymity system.

For meaningful anonymity, the cell order is what to raise, and `q = 31` (993 nodes) is where the floor becomes
comparable to a real mix network.

### So, in practice

| purpose | minimum | note |
|---|---|---|
| a working overlay: membership, storage, healing, self-diagnosis | **7** (one Fano cell) | on `PG(2,2)` one node in seven may fail to seat — a line holds three points, so a node fails only when its whole line is taken; probability `~load^(q+1)`, negligible at real `q` |
| a blockchain cell (TAXIS) | **7 validators** | quorum 5, survives 2 failures |
| a mixnet relay path | 3 per hop | `MIX_THRESHOLD = 2`, i.e. 2-of-3 peeling |
| **credible anonymity** | **hundreds** | `q = 31`, 993 points; below that the `1/K` floor is the binding limit |

More than one cell is not required for correctness at any of these scales — a cell of `PG(2,31)` holds 993
nodes, and the birthday-bound capacity loss that once forced federation was solved by verifiable probe
sequences (`fanos_vrf::probe_point`, measured at 200/200 seats on `PG(2,31)`). Federation is driven by total
network size, not by a per-cell ceiling.

## Part 2 — Hardware

### Measured, on a release build

A single node, steady state, no traffic:

| | |
|---|---|
| resident memory | **7.6 MB** |
| CPU, idle | **~0%** |
| binary | **9.9 MB** (release; 55.7 MB debug) |

That is the floor, and it is small because the engine is sans-I/O and every collection in it is bounded.

### Bounded by construction, not by hope

The memory ceiling is a sum of explicit caps rather than an empirical guess. The load-bearing ones:

| cap | value | what it bounds |
|---|---|---|
| `MAX_STORE_ENTRIES` | 4096 keys | the overlay store |
| `MAX_VALUE_LEN` | 64 KiB | one stored value |
| `MAX_PENDING_GETS` | 1024 | reads in flight |
| `HELD_CAP` | 512 | own shards retained to serve peers |
| `PENDING_CAP` | 64 | skeletons awaiting reconstruction |
| `SEEN_TX_CAP` | 8192 | transaction dedup (validator) |
| `RECENT_BODY_CAP` | 64 | finalized bodies kept to help a lagging peer |

Worst-case store: `4096 × ⌈64 KiB / 3⌉ ≈ **85 MB**` of shards on a node holding one shard per key; a *sparse*
cell holds several shards per key and scales that up by the number of points it covers.

### Recommended, by role

Estimates from the measurements plus the caps — not measured under load, and marked as estimates:

| role | RAM | CPU | disk | network |
|---|---|---|---|---|
| **relay / storage** (the default) | 256 MB | 1 core | 1 GB | any stable link; cover traffic is constant-rate, so budget for it |
| **validator** (TAXIS) | 512 MB | 2 cores | 2 GB | consensus is chatty per round; latency matters more than bandwidth |
| **shielded-pool user** (OBOLOS) | 2 GB | 4 cores | — | **the heavy case**: a zero-knowledge proof at real parameters takes **~40 s on a release build**, and far longer unoptimised |

The three numbers that actually drive the recommendation:

1. **Admission proof-of-work.** Bounded at 30 bits by design — about a minute on one modest core — and the
   ceiling exists to protect the *newcomer*, not the cell. Any machine that can spend a minute of one core can
   join.
2. **The engine's own compute is negligible.** ~0% idle CPU, and the inline work is deliberately capped:
   `MAX_INLINE_ADMISSION_BITS = 20` (~0.1 s) so a solve cannot block an observation window.
3. **OBOLOS proofs dominate anything else.** If a deployment does not use the shielded pool, 256 MB and one
   core is genuinely enough; if it does, size for the proof.

### What was not measured

Under-load memory and CPU, disk I/O rates, and bandwidth per role. The caps give a hard ceiling on memory, so
the risk there is bounded; the CPU and bandwidth figures above are extrapolations from an idle node and should
be measured before a production sizing is published.
