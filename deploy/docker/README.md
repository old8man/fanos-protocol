# FANOS multi-node integration cell (Docker)

Real **inter-container QUIC** integration testing: each FANOS node runs as its own container with its own
network namespace on a shared bridge, so the overlay forms over genuine inter-host UDP/QUIC — the tier the
in-process [`cell_e2e`](../../rust/crates/fanos-quic/tests/cell_e2e.rs) tests structurally cannot reach
(those run many QUIC endpoints in **one** process on loopback).

This complements, not replaces, the [T0–T5 test ladder](../../docs/design-testing.md):

| Tier | What | Where |
|------|------|-------|
| T0–T3 | Field/geometry/engine unit + property tests | `cargo test` across the workspace |
| T4 | Real QUIC, **one process**, loopback (a 7-node Fano cell) | `crates/fanos-quic/tests/cell_e2e.rs` |
| **T5** | Real QUIC, **many containers**, real namespaces (+ optional netem) | **this harness** |

## Run

```sh
./run-cell.sh                 # build the image if needed, form a 4-node cell, assert convergence, tear down
./run-cell.sh --keep          # leave the cell running afterwards for inspection
NETEM=100ms ./run-cell.sh     # add 100ms egress delay to every node (self-healing under real latency)
CONVERGE_TIMEOUT=120 ./run-cell.sh
PROFILE=release ./run-cell.sh # build the actual production (release) image instead of the fast debug one
```

The integration image builds with the **debug** profile by default (far faster to compile; startup speed
and binary size are irrelevant for a test). `PROFILE=release` exercises the real production build. An
already-built `fanos-node:integration` image is reused as-is — `docker rmi fanos-node:integration` to force
a rebuild at a different profile.

The script exits non-zero if the cell does not form; `[ ok ] INTEGRATION PASS …` on success.

## What it proves

A four-node cell forms over real inter-container QUIC: each node **discovers the other three**
(membership converges) through the full production path — bootstrap address-book seeding, `Command::Join`
Announce flooding, and self-certifying **HELLO proof-of-coordinate handshakes** exchanged between separate
containers. That exercises the transport, wire codec, VRF-coordinate verification, and membership layers
across a real network boundary, not a loopback shortcut.

## How it works

A node's coordinate is `MapToPoint(VRF(identity, epoch, beacon))` — it exists only once the node has minted
its identity, and a full-mesh bootstrap needs every node's coordinate up front. So `run-cell.sh`:

1. **Mints** one identity per node (`fanos id`, persisted into the compose named volume), re-minting any
   node that collides onto an already-used Fano point (distinct-points is a cell invariant; a `1/7`
   collision per fresh identity).
2. Builds each node's **full-mesh `--bootstrap`** list (`coord@host:9000` for every other node) and starts
   the cell with those injected per-service.
3. Polls each container's logs until it has logged `member joined` for its three peers, or fails on timeout.

## Known scope / limitations

- **Full-mesh bootstrap is deliberate.** The driver has no directory-based *reverse* peer discovery yet —
  reachability rides cached QUIC connections, so a node that only knew the genesis seed would form a **star**
  (peers reach genesis but not each other), and peer↔peer DHT storage would drop. Automatic discovery
  (coordinate → address via the DHT, spec §L1) is tracked as **#119**; until then the harness seeds the full
  mesh so the cell is genuinely complete.
- **Membership convergence is the current assertion.** Driving application traffic (DHT `put`/`get`,
  payload `Send`) end-to-end from outside a container needs a client CLI surface the node binary does not yet
  expose (only `node` / `id` / `resolve`); extending this harness to a cross-container store→retrieve and a
  node-loss survival check is the natural follow-on (**#117**), and `NETEM=` already lets it run under real
  delay/loss for the self-healing layer.
- Requires Docker with the Compose v2 plugin (or legacy `docker-compose`). `NETEM=` additionally needs the
  container to allow `tc` (NET_ADMIN); it is skipped with a notice if unavailable.
