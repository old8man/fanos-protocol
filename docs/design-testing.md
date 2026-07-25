# FANOS — the Verification Tier Taxonomy

> One engine, many drivers. Because a FANOS node is a pure sans-I/O state machine, the *same* engine
> bytes run under a deterministic in-memory driver and under a real UDP+QUIC+TLS driver. That single
> fact organizes the entire test suite into a **ladder**: each tier runs the same engine through one
> more layer of reality, and catches exactly the class of defect the tier below it abstracts away. A
> bug's regression test belongs at the cheapest tier that can reproduce it; a higher tier earns its
> cost only by covering a boundary the lower tier cannot.

This extends [`architecture.md`](architecture.md) (the sans-I/O monism) and [`design-platform.md`](design-platform.md)
§8 (determinism × self-observation). Where those state *why* the architecture is testable, this states
*how the suite is layered* and *where a new test goes*.

---

## 0. Thesis — the boundary a tier abstracts is the bug class it cannot see

A FANOS node is `Engine::step(now, Input) -> Vec<Effect>` (`fanos-runtime`): it touches no clock, no
socket, no RNG. Every environmental fact — time, packet delivery, loss, randomness, the wire — is
supplied by a *driver*. The protocol has two production-grade drivers:

- **`fanos-sim`** — deterministic virtual time, in-memory transport, seeded RNG.
- **`fanos-quic`** — a real epoll/UDP socket, QUIC, TLS 1.3, mutual-auth certificates.

The engine is byte-identical across both; that equivalence is the whole point of the architecture. It
means a test can pin down engine logic *without* a socket (fast, deterministic, adversary-controllable)
and, separately, pin down the socket-and-serialization layer *around* an engine already known-correct.
Each layer a tier abstracts (the socket, the RNG, the second language) is precisely the class of bug it
is blind to — so the suite is a ladder, not a heap:

| Tier | Driver / medium | Location | Proves | Blind to |
|---|---|---|---|---|
| **T0 Engine unit** | none (pure `step`) | `crates/*/src` `#[cfg(test)]` (114 modules) | state-machine logic, pure math | wire bytes, transport, cross-node emergence |
| **T1 Conformance KAT** | fixed byte vectors | `conformance/vectors/*.json` + `*/tests/conformance.rs` | byte-exact formats across *all* language impls | dynamics (vectors are static) |
| **T2 Simulator scenario** | `fanos-sim` (virtual time) | `crates/fanos-sim/tests` (30 files) | multi-node protocol behaviour, adversaries, healing, coherence — enumerated *and* Monte-Carlo | real sockets, real TLS, real concurrency |
| **T3 Real-QUIC transport** | `fanos-quic` (UDP+TLS) | `crates/fanos-quic/tests/{loopback,proteus,self_certifying}.rs` | driver, serialization, handshake, self-certifying identity, PROTEUS shaping | cell-scale integration |
| **T4 Real-QUIC full cell** | `fanos-quic` (7 nodes) | `crates/fanos-quic/tests/cell_e2e.rs` | cross-node DHT / replication / read-repair / availability over real links | application stack above the overlay |
| **T5 Application e2e** | `fanos-node` / `fanos-proxy` | `crates/fanos-node/tests`, `crates/fanos-proxy/tests/socks5.rs` | the user path: SOCKS5 → DIAULOS session → overlay → service; anonymous rendezvous | — (the top of the stack) |

The rungs below are each detailed with *what defect they exist to catch*.

---

## 1. The ladder, rung by rung

### T0 — Engine unit tests (sans-I/O)

The 114 in-crate `#[cfg(test)]` modules drive the engine and pure functions directly:
`node.step(Instant(t), Input::Command(..))` and assert over the returned `Vec<Effect>`, or check a
formula against its closed form. No time passes that the test does not pass in; no frame is delivered
that the test does not hand over. This is the fastest tier (a full crate's unit suite runs in
milliseconds) and the correct home for any bug expressible as "given this state and this input, the
engine must emit this effect" — the vast majority of logic defects. DIAKRISIS decoders, the RTO/jitter
schedule, DoS-cap predicates, the DHT address arithmetic, the coherence math: all are T0.

**Catches:** logic, arithmetic, boundary conditions, decoder validation.
**Cannot catch:** anything requiring bytes on a wire or two engines interacting.

### T1 — Cross-language conformance vectors (KAT)

`conformance/vectors/*.json` (`wire`, `algebra`, `diaulos`, `names`, `diakrisis`, `telemetry`,
`services`) are known-answer vectors: fixed inputs paired with their canonical output bytes. Every
language implementation (see [`implementations.md`](implementations.md)) must reproduce them exactly, so
they are the contract that keeps the Rust, and any sibling, impls on the *same wire*. In-repo they are
checked by `*/tests/conformance.rs` (calypso, diaulos, onoma, proteus) and the `fanos-cli`
`conformance_vectors` test. When a codec changes intentionally, the vector is regenerated in the same
commit — a diff to a `.json` vector is a wire-format change under review, never an accident.

**Catches:** wire/format drift, endianness, framing, cross-impl divergence.
**Cannot catch:** dynamic behaviour — a vector is a single frozen step.

### T2 — Deterministic simulator scenarios

`fanos-sim` swaps the driver for virtual time + in-memory transport + a seeded RNG, so a whole network
of engines runs in-process, reproducibly, at thousands of virtual seconds per wall-clock second. The 28
scenario files are the protocol's behavioural spec: `healing`, `catastrophe`, `byzantine`, `eclipse`,
`sybil_cost`, `coherence_ddos`, `storage`, `membership`, `rendezvous_robustness`, `mixnet`,
`early_warning`, and more. Adversaries are first-class — Byzantine faults are *raw forged frames*
(`inject_frame`), losses are a tunable `NetworkModel`, crashes and recoveries are `sim.crash`/`recover`.
This is where emergent, multi-node, adversarial properties are proven, and where a regression that needs
a *network* (not a single engine) to appear is pinned.

T2 has two faces. The **enumerated** scenarios pin named situations (the ones above). The **Monte-Carlo**
layer instead samples a *distribution* of situations and asserts invariants across the whole sample —
this is where "predict and model stochastic scenarios" and "maximal coverage of every attack surface"
live:

- `stochastic_invariants.rs` sweeps 160 seeds per invariant (≈ 960 randomized adversarial scenarios):
  random loss, random timed fault sets, random DHT floods, random forged frames — and asserts the
  load-bearing safety/liveness invariants hold on *every* draw (determinism, syndrome soundness — never
  blame a live node, saturation → escalation, replicated availability under minority loss,
  malformed-input safety, no spurious quarantine). Each scenario is *seed-derived*, so a violation is a
  seed that reproduces the counterexample forever — property-based testing with the determinism contract
  as its backstop.
- `cascade_forecast_stochastic.rs` characterizes the critical-slowing-down predictor over an *ensemble*
  of random cell parameterizations, not one: it measures **sensitivity** (fraction of random cascades
  warned before the viability crossing) and **specificity** (fraction of stable cells that falsely
  alarm) as deterministic pass/fail rates — the honest operating point of the early-warning system.

The tier's own correctness rests on a contract — see §2.

**Catches:** protocol logic across nodes, healing/coherence dynamics, adversary resistance, timing/order, and — via the Monte-Carlo layer — invariant violations and predictor blind spots anywhere in a distribution of scenarios.
**Cannot catch:** real-socket faults, TLS handshake, OS concurrency, serialization at the driver seam.

### T3 — Real-QUIC transport (loopback, identity, shaping)

The same engine, now under `fanos-quic` on a real loopback UDP socket with QUIC and TLS 1.3.
`loopback.rs` proves a datagram survives the real transport round-trip; `self_certifying.rs` proves the
overlay coordinate `MapToPoint(H(cert))` is authenticated by the mutual-TLS handshake (an impostor at a
resolved address is rejected) and is stable across restarts from persisted credentials; `proteus.rs`
proves PROTEUS frame-shaping interoperates below the engine boundary. These catch everything the
in-memory transport abstracts: the actual serialization at the driver seam, the handshake, connection
lifecycle, address resolution.

**Catches:** driver/serialization bugs, TLS/QUIC handshake, self-certifying identity, transport lifecycle.
**Cannot catch:** whole-cell integration (loopback is a pair).

### T4 — Real-QUIC full cell (this tier's enabling seam is new)

`cell_e2e.rs` stands up all **seven** nodes of a Fano (`F2`) cell over real QUIC and exercises the DHT
end-to-end: a `Put` at one member is read back by a *different* member (content-addressed routing +
replication across genuine mutual-TLS links), and a stored value survives losing a node (LRC
availability, spec §L4). This tier was previously impossible — self-certifying coordinates are random,
so one could not seat specific nodes on the specific points a cell needs. The **coordinate-pinning
seam** (§3) closes that gap.

**Catches:** cross-node integration at cell scale over real links — routing, replication, read-repair, availability.
**Cannot catch:** the application protocols riding on the overlay.

### T5 — Application end-to-end

The top of the stack, over real QUIC: `fanos-node/tests/diaulos_quic.rs` drives a reliable, encrypted,
hybrid-PQ DIAULOS session between nodes; `anonymous_quic.rs` drives the anonymous rendezvous path; and
`fanos-proxy/tests/socks5.rs` drives a SOCKS5 client through the `.fanos` dialer. This is the user's
actual path — a TCP payload entering a SOCKS5 proxy and arriving at a `.fanos` service — and it catches
integration defects that only appear once the full session/stream/overlay stack is composed (the
duplex-deadlock class, for one).

**Catches:** the composed user path, session/stream integration, the proxy surface.

---

## 2. The determinism keystone — `(seed, inputs) → byte-identical run`

T2 is only trustworthy if it is *reproducible*: an adversary experiment that cannot be replayed is an
anecdote. `design-platform.md` §8 states the contract — same seed and same inputs yield a byte-identical
run — and `crates/fanos-sim/tests/determinism.rs` proves it at **trace strength**: not just that the
aggregate counters match (which can hold while event *order* silently diverges), but that the full
ordered causal trace (`Trace::dump()` — every dispatched event and performed effect, including DIAKRISIS
verdicts) reproduces byte-for-byte, under packet loss and churn. Non-vacuity is proven alongside it: two
distinct seeds *must* produce distinct traces under loss, so the byte-identity is a real property of the
run and not of an empty log.

This contract is what upgrades the simulator from a test harness into a **platform asset**: incident
forensics by replay, time-travel debugging, and the "the devnet is production" claim all reduce to it.
It is enforced structurally — `fanos-sim` uses only ordered collections (`BTreeMap`/`BTreeSet`), never a
`HashMap`, so iteration order never leaks the allocator's nondeterminism into the run. A change that
introduced a `HashMap` on a trace-affecting path would fail `determinism.rs` immediately.

---

## 3. The coordinate-pinning seam — honest, not a backdoor

A cell test needs node *A* on point 0, *B* on point 1, and so on. But a self-certifying node's
coordinate is `MapToPoint(H(cert))`, so a fresh identity lands on a *random* Fano point — you cannot ask
for point 3. The seam (`fanos-quic/src/harness.rs`) closes this by **grinding**: it mints credentials
until one hashes to the wanted point (`credentials_for_point`), then brings the node up through the
*ordinary* persistent self-certifying path (`spawn_pinned` → `spawn_self_certifying_persistent`).

This is deliberately **not** a bypass of self-certification, and the distinction is load-bearing:

- Every node produced is a *genuine* self-certifying node — real certificate, real key, real
  `MapToPoint` — indistinguishable on the wire from any other. Only *which* coordinate it landed on was
  chosen, by discarding mints that missed.
- It is exactly the retry-until-**distinct** loop the identity tests already run
  (`self_certifying.rs::spawn_distinct`), generalized to retry-until-**target**.
- It is tractable *only* because a cell has `N = 7` points (≈ 7 mints per point). Grinding a large plane
  is deliberately impractical — the very asymmetry that keeps a coordinate unforgeable in production. The
  seam does not weaken that asymmetry; it rides the cheap end of it, and `spawn_cell` bounds the grind
  (`DEFAULT_GRIND_LIMIT`) so a mis-parameterized call fails cleanly (`QuicError::Grind`) rather than
  looping.

Because the Fano plane is fully connected (any two points share a line), each pinned node derives all
six others as peers at construction (`derive, don't negotiate`), so a freshly assembled cell replicates
and read-repairs with **no discovery walk** — the cell is live the instant it is spawned.

---

## 4. Where does a new test go?

The decision procedure, cheapest-first:

1. **Can a single engine reproduce it?** → **T0.** Most logic bugs. Write `node.step(...)` and assert
   the `Effect`s. Do not reach for the simulator to test a decoder.
2. **Is it a wire/format fact that other language impls must share?** → **T1.** Add or regenerate a
   vector; the change to the `.json` *is* the reviewable artifact.
3. **Does it need several engines, an adversary, loss, or churn to appear?** → **T2.** A seeded
   `fanos-sim` scenario. Deterministic, so it is a permanent regression guard, not a flaky one. If the
   property should hold across a *class* of situations rather than one — an invariant, or a predictor's
   operating point — add it to the **Monte-Carlo** layer (`stochastic_invariants.rs` /
   `cascade_forecast_stochastic.rs`) as a seed sweep with a fixed pass/fail rate, not a single case.
4. **Is it a fault of the real socket, TLS, serialization, or identity handshake?** → **T3.** A
   loopback/self-certifying test — the only tier that exercises the driver seam.
5. **Does it only appear with a whole cell of real nodes interacting?** → **T4.** `spawn_cell` + the
   assertion. Reserve for genuinely cell-scale integration; a pair belongs at T3.
6. **Is it on the composed user path (proxy → session → service)?** → **T5.**

The rule is **push down**: reproduce a bug at the lowest tier that still exhibits it, and put the
regression test there. A higher tier is justified only when the bug lives at a boundary the lower tier
abstracts — a serialization bug is invisible to T2 (in-memory transport carries typed values, not
bytes), so it *must* be T3; a cross-node race is invisible to T0, so it *must* be T2 or above. Adding a
slow high-tier test for a bug a fast low-tier test already catches is waste, and it dilutes the signal
of the high tiers (whose job is to fail *only* on integration faults).

---

## 5. Honest limits

- **T1 vectors are static.** They freeze a step, not a trajectory; a codec that is byte-correct per
  vector but mis-sequenced across steps is a T2/T3 concern.
- **T2 abstracts the socket.** Its transport hands typed values between engines; it will never surface a
  serialization, MTU, or handshake fault. That is by design (it buys determinism), and it is exactly why
  T3/T4 exist.
- **T3/T4/T5 are wall-clock and concurrent**, so they use bounded timeouts, not virtual time — and are
  therefore not bit-reproducible the way T2 is. Their assertions are written to be robust to timing
  (await-until-delivered with a generous deadline), never to a fixed tick. The flake hunt of #77 was a
  timeout tuned too tight for concurrent load; the lesson is encoded in the loopback liveness windows.
- **Grinding cost scales with the plane.** The pinning seam is a *cell* tool (`N = 7`). It is not a
  mechanism for occupying a chosen coordinate in a production-sized overlay, and must not be presented as
  one — its whole safety argument is that the grind is cheap only at cell scale.

### 5.1 The boundary no rung crosses — the deployed node's *composition*

By this document's own thesis, the boundary a tier abstracts is the bug class it cannot see. Applied to the ladder
as a whole, there is one boundary **every** rung abstracts:

| rung | what it runs |
|---|---|
| T0 | one engine, sans-I/O |
| T2 | `fanos_runtime::OverlayNode` — the overlay **engine** — over virtual time |
| T3/T4 | `fanos_quic` — the **transport** and a cell of it |
| T5 | the application above the overlay |

None of them runs **`fanos_node::Node`** — the deployed node, which composes the overlay engine *plus* around a
dozen driver tasks: the self-organizing role loop, the capability/load/mix publishers, the epoch driver, the beacon
tracker, the recovery trigger, the exit role, the rendezvous host. `fanos-sim` does not reference `fanos_node::` at
all (it carries the crate only as a dev-dependency for one scenario). So the ladder is faithful about *protocol*
and *transport*, and silent about **wiring** — whether those tasks are started, in what order, and whether their
inputs are ready when they run.

That is not a hypothetical class. Wiring the role loop into `Node::start` immediately surfaced four defects that
every rung above was structurally unable to see, because none of them ran the composition:

1. `spawn_self_organization` **had no callers** — the whole self-organizing subsystem was proven-but-unreachable,
   so a deployed node's roles came from its config file and the cell had no say;
2. the genesis assignment **raced its own publishers**, which write from sibling tasks;
3. it needed **both** the capability and the load report, and waiting on one still produced an empty assignment;
4. every cell-wide directory scan was **sequential**, so an unoccupied slot cost the full `RESOLVE_TIMEOUT` and one
   epoch's assignment took `N × 5s` — unfinishable on a production-sized plane.

Each is a composition fault, invisible to a rung that instantiates the engine directly. The fix is not another
scenario at an existing rung: it is to make the simulator drive the **real node composition**, with only the
transport virtualised — which is what "differs from production only in transport" has to mean if it is to carry
weight.

### 5.2 T2f — real nodes over a modelled carrier

That rung now exists. [`fanos_quic::Fabric`](../rust/crates/fanos-quic/src/driver.rs) chooses where a node's QUIC
endpoint gets its datagrams — a bound UDP socket, or a caller-supplied `AsyncUdpSocket` — and
[`fanos_sim::fabric`](../rust/crates/fanos-sim/src/fabric.rs) is a modelled carrier implementing the latter. A node
spawned over it *is* the production node: real QUIC state machine, real TLS, real driver actors, real composition.
Only reachability, one-way latency with jitter, independent loss, and partition are modelled.

Two properties differ from the tiers around it and are worth stating:

- **It is wall-clock, deliberately.** Delays are real `tokio` sleeps, so a scenario is *not* bit-reproducible the way
  T2 is. T2 buys determinism by abstracting the socket, which is exactly why it cannot see composition faults; this
  rung buys composition fidelity by giving that up. They are complements, not substitutes.
- **Partition is directional.** A one-way cut is both a real failure mode (asymmetric routing, a middlebox filtering
  one direction) and a strictly sharper test: a protocol that assumes reachability is symmetric passes a symmetric
  partition and fails this one.

It costs almost nothing — the fabric's tests spawn real self-certifying nodes, exchange traffic, cut one direction and
heal it, in ~0.2 s with no OS sockets — so a large fleet of *composed* nodes is affordable where a real-UDP tier is
not.

> **Two lessons from building it, recorded because both were mine and both looked like framework faults.**
>
> `poll_recv` **must register the caller's waker** when it has nothing to return. A bare `Poll::Pending` compiles,
> type-checks, and then silently never receives another datagram — nothing will ever wake the task. The first
> pass-through fabric did exactly that and the node hung.
>
> And **do not assert carrier properties through overlay operations.** Two attempts asserted a put/get round-trip; a
> key routes to its *responsible point*, which with two of seven points occupied exists only depending on where random
> credentials landed — so the test was intermittently asserting a property of the overlay's addressing while claiming
> to test the transport. `Command::Send` names its destination, which is the property actually under test.

### 5.3 First finding from the new rung — the assignment converges on a roster of one

Using the fleet as an instrument rather than a regression test (`probe_loss_tolerance_of_the_composition`) produced a
result that no prior rung could have shown. Across loss from 0% to 90%:

```
loss= 0%  all-assigned=true  elapsed=4.11s  delivered=956  dropped=  0  known_peers=[1, 2, 3]
loss=50%  all-assigned=true  elapsed=4.13s  delivered= 14  dropped= 43  known_peers=[1, 2, 2]
loss=90%  all-assigned=true  elapsed=4.12s  delivered=  4  dropped= 32  known_peers=[1, 2, 2]
```

Two invariants across the sweep give it away. `known_peers` is exactly the *bootstrap* count (node `i` is seeded with
`i` peers), identical at 0% and 90% — network discovery contributed nothing within the window. And convergence time is
flat at ~4.1 s regardless of how much the carrier dropped.

The mechanism: **a node's own capability and load slots are local store reads.** `build_capability_directory` therefore
resolves the node itself with zero peer contact, and the genesis assignment proceeds over a **roster of one**. At 90%
loss, with four datagrams delivered in total, every node still reported a complete assignment.

Nothing here is unsafe in isolation — a node never assigns itself a role it did not offer. What is missing is that the
determinism argument the design rests on is *conditional*: `role_loop` states it is "deterministic across nodes given
the same live set", and in a lossy or partitioned cell the live sets are **not** the same. Each node then steps an
identical controller over a *different* roster, so the cell disagrees about who serves what while every member believes
it agreed. Consequences: every role is over-provisioned (each node assigns itself), and for
[`Role::Rendezvous`](../rust/crates/fanos-core/src/roles.rs) the cell's estimate of line coverage — which *is* the
anonymity set a hidden service hides in — is wrong in the direction of overconfidence.

Worth noting honestly: the genesis-ordering fix in §5.1 (wait for this node's own publishes to signal) made the
roster-of-one path *reliable* rather than racy. It fixed a real bug and sharpened this one.

The remedy is observability before policy, and deliberately not a quorum threshold — a fresh or genuinely small cell
must still be able to start. An assignment should carry **the roster it was computed over**, so a node can tell a
cell-agreed assignment from a solitary guess, and so a subsystem whose safety depends on cell-wide agreement
(rendezvous coverage above all) can decline to rely on a provisional one.

---

## 6. Running the tiers

```
# T0 — engine unit tests (fast; every crate)
cargo test --workspace --lib

# T1 — conformance vectors
cargo test --workspace --test conformance          # per-crate conformance.rs
cargo test -p fanos-cli --test conformance_vectors

# T2 — deterministic scenarios, the determinism contract, and the Monte-Carlo invariant/predictor sweeps
cargo test -p fanos-sim
cargo test -p fanos-sim --test determinism
cargo test -p fanos-sim --test stochastic_invariants
cargo test -p fanos-sim --test cascade_forecast_stochastic

# T3/T4 — real-QUIC transport and the full cell
cargo test -p fanos-quic                            # loopback, proteus, self_certifying, cell_e2e

# T5 — application end-to-end
cargo test -p fanos-node -p fanos-proxy
```

All tiers gate CI together via `cargo test --workspace`, and `cargo clippy --all-targets -- -D warnings`
holds test modules to the same lint bar as shipping code (the `#![allow(...)]` headers on test files are
the audited, deliberate exceptions).
