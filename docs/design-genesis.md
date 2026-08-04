# The genesis window — why it is open, why proof-of-work does not close it, and the one-line fix that does

> **Status.** Analysis, and the change is **implemented** (2026-08-04). The window itself is established and
> measured (`docs/design-coordinates.md` §2, confirmed against `on_join` / `on_announce`). This note is the
> synthesis the founding choreography needed before it could pick a defence, and it reaches a different answer
> than the three options originally listed — one of those options is provably useless here. §5 is rewritten
> against what was actually built, including a defect the first half of the wiring introduced.

## 1. The window, stated once

`docs/design-coordinates.md` says two things in different sections, and their conjunction is the problem:

* on `q = 2`, where grind-cost is nil, *"this unpredictable reshuffle is the entire defense"*;
* at genesis the coordinate is computable with no live beacon, *"so cold-start and tests need no beacon
  round"*.

At genesis there is no reshuffle yet. So on the base cell, for that window, there is **no placement defence at
all**. `BeaconSeed::GENESIS` is a public constant, so an adversary computes credentials for every point of the
plane offline — `fanos-quic::harness` measures the cost at roughly seven mints per point, which is precisely
why it exists as a *test* facility — and joins wherever it chose. The window closes when the first beacon
round assembles: `epoch_period`, 600 s by default.

Confirmed against the code rather than inferred: `on_join` and `on_announce`
(`overlay/membership_ops.rs`) do not require an adopted beacon, and the only gate on that path is
`require_admission`, which is `false` in `Config::default()`.

## 2. Why proof-of-work does not close it — the derivation that kills the obvious option

The obvious answer is "turn admission on": make each JOIN cost work, so occupying seven points costs seven
proofs. It looks especially good here because FANOS's admission challenge is **better than most**: it binds

```
admission_challenge(id, coord, epoch)          — fanos-runtime/src/frames.rs
```

so a proof is bound to a *specific point*, not merely to entry. Work cannot be solved once and spent
everywhere; taking seven points costs seven distinct solves. That is a real property and it is why the
neighbouring replay attack is closed.

**It does not help at genesis, and the reason is precise.** Every term of that challenge is known to the
adversary in advance:

| term | at genesis | in steady state |
|---|---|---|
| `epoch` | `0`, by definition | known |
| `coord` | `MapToPoint(VRF(sk, id ‖ 0 ‖ GENESIS))` — the adversary controls `sk` and `id`, and `GENESIS` is a **public constant** | derived from a beacon that does not exist yet |
| `id` | chosen by the adversary | chosen by the adversary |

In steady state the adversary cannot precompute, because it cannot know its own *future* coordinate — the VRF
runs over a beacon that is unpredictable until the threshold reveals it. That unpredictability, not the work,
is what makes the price bite.

At genesis the entire challenge is available offline, with unlimited time and no interaction with anyone. The
adversary grinds identities until it holds one per point, then solves the seven proofs at its leisure, then
joins. **Proof-of-work converts the attack from free to slow-and-offline, and offline cost is exactly what an
adversary with time already has.**

So the option "price the join" is not a weaker defence for genesis. It is not a defence for genesis.

## 3. What is actually missing, named correctly

Not a gate. **Unpredictability.** In steady state the beacon supplies it; at genesis nothing does, because the
seed is a compile-time constant shared by every FANOS network that has ever existed.

That last clause is worth pausing on, because it is a second and independent defect hiding in the same line:

> With `BeaconSeed::GENESIS` a public constant, one grinding effort works against **every FANOS deployment**.
> An adversary that computes the seven credentials once holds a chosen genesis placement on every network
> anyone will ever found — a testnet, a private cell, a production launch — without repeating the work.

A per-deployment genesis value fixes both at once, and it does not need inventing: **the network already has a
per-deployment random value that every node must hold before it can participate.**

## 4. The recommended solution

```
genesis_seed = H("FANOS-v1/genesis-beacon" ‖ VssCommitment::to_bytes)
```

The beacon commitment is the DKG-or-dealing output. It is random, it is per-network, it is public *within* the
network, and it is already carried in every provisioning file (`anchor-i.beacon`, `consumer.beacon`) because
no node can verify a beacon round without it. Hashing it into the genesis seed costs:

* **no new field** in any provisioning file, and so no format change and no new distribution channel;
* **no new operational step** — the founding ceremony already draws this entropy;
* **no change to the derivation** — the coordinate is still `MapToPoint(VRF(sk, id ‖ epoch ‖ beacon))`, with a
  different value in the last argument at epoch 0;
* **no loss of the cold-start property** that the genesis bullet exists to provide: a node still computes its
  coordinate with no live beacon round, because it holds the commitment before it starts.

### What it buys, stated precisely

Grinding a chosen genesis placement now requires the network's commitment first. That converts the attack from

> *grindable by anyone, for every network, before any network exists*

to

> *grindable only after obtaining that network's provisioning material, and only until its first beacon round*

— which is the same trust boundary the bootstrap seed already assumes, and the same window the steady state
already tolerates. The defence is not bolted on; it is the steady-state property extended backwards to cover
the one epoch that lacked it.

### What it does not buy, stated equally precisely

It does **not** make genesis grinding impossible for a party inside the trust boundary. A founder, or anyone
handed `consumer.beacon`, can grind between receiving it and the first beacon round. A network that publishes
its `consumer.beacon` openly — which a public testnet might reasonably do — reopens the original window
against anyone who reads it.

So the second half of the recommendation is operational and belongs in the founding runbook, not in the code:
**produce the first beacon round before opening joins.** The founding set is provisioned with explicit
coordinates and does not need to join, so there is no circularity — the cell can reach its first `BeaconReady`
with no joiner present, and only then publish its bootstrap seeds. Each half is cheap, and each covers the
other's residual.

## 5. Where the cost actually is — rewritten after building it

The derivation costs nothing; **the seam does**. Two shapes were tried before the right one, and the first
half of the wiring shipped a defect into the genesis epoch, which is the part most worth recording.

### 5.1 Two dead ends

The seed is needed where a node computes its own genesis coordinate (`driver.rs`,
`verifiable_coordinate_ranked(creds, Epoch::ZERO, …)`) and where *peers'* epoch-0 claims are checked
(`BeaconWindow::genesis`). Both sit in `fanos-quic`, the transport, which does not know what a
`VssCommitment` is — that is `fanos-vrf`'s, held in `fanos-node`'s config.

**Hanging it on `NodeCredentials`** is the shortcut anyone would try, since credentials already reach both
sites. It is wrong twice: `NodeCredentials` derives `Wire` and is *persisted*, so a field there changes a
stored format for every existing node; and it is the wrong home semantically, because the seed is
per-**network** while credentials are per-**node** and are exactly the thing that should exist independently
of any particular network.

**Adding a spawn parameter** was the second answer, and it is merely expensive: 16 external call sites.

### 5.2 What was built

`Directory` already *is* the per-network object — it is created once per network, threaded to every spawn site
in the family, and carries the peer addresses that only make sense on one network. So the seed rides there:

```rust
Directory::new().for_network(genesis_seed(&params.commitment))   // fanos-node, at Directory creation
directory.genesis()                                              // fanos-quic, at both sites above
```

Zero signature changes, and the value cannot arrive at one of the two sites and not the other, because both
read the same object.

### 5.3 The defect that half the wiring introduced

Deriving the seed **moves the seat**. Everything that computes an epoch-0 coordinate has to move with it, and
the ones that do not are silent: a producer on the old constant still agrees with a verifier on the old
constant, so nothing errors, no log line appears — they simply describe a network no node is on.

Measured, with the transport wired and nothing else: **the cell's mix directory was empty for the whole
genesis epoch on every network with a beacon.** The relay published its onion key bound to the constant-seed
coordinate; the reader verified it against the constant-seed coordinate; the node sat somewhere else. Caught
by one library test (`a_relay_node_publishes_its_mix_key_to_the_directory`), not by review, and only because
the whole workspace was run rather than the crate being edited.

The full set that had to move — a *family*, not a site:

| where | what it does at epoch 0 |
|---|---|
| `mixdir::spawn_mix_publisher` | publishes this relay's onion key, coordinate-bound |
| `mixdir::spawn_mix_directory_feeder` | builds the directory a combiner seals through |
| `capdir::spawn_capability_publisher` | publishes this node's bound capability advertisement |
| `role_loop::genesis_assign` + the loop's seed | reads the roster the role assignment runs on |
| `composition::compose_engine` | seats a POROS ingress host on its community's line |
| `driver`'s initial `Placement.beacon` | what the reshuffle compares the first beacon against |
| four CLI verbs (`host`, `proxy --anonymous`, `message serve`, `taxis-deal`) | default when `--beacon` is absent |

The fix that makes it not recur is to remove the *opportunity*: the seed is now readable from `Client::genesis()`
inside any spawned task, from `NodeConfig::genesis_seed()` / `CellComposition::genesis_seed()` in
provisioning, and from `beacon_arg()` in the CLI. A task added next year gets it by asking, not by
remembering — and `fanos-cli/tests/genesis_seed.rs` fails if anything in `fanos-node` names the constant
outside the derivation's own fallback.

## 6. The operator-visible cost

One real consequence, and it is a *correction* rather than a regression: **a coordinate is now a function of
the identity and the network.** `fanos id` used to print a point computed from the credentials alone, the same
on every FANOS network in existence; its last line is a bootstrap address, and bootstrap pins are
coordinate-checked, so on a network with a beacon that address was one no node would match.

It now reads the same configuration the daemon reads, from the same default path (`--config` to override), and
says which network the answer is for:

```
coordinate: 1:0:1
network: 9f3ac7b2 (from /etc/fanos/node.conf)
bootstrap seed (add host:port): 1:0:1@HOST:PORT
```

With no beacon configured it prints the constant-seed coordinate and says so, rather than implying a network.
`fanos status` gained the same `network` line, and `fanos init` computes the coordinate **after** the beacon
ceremony rather than before it — it printed, and then advertised, a pre-beacon placement otherwise.

The fingerprint is the first four bytes of the genesis seed. It exists because "are we even on the same
network?" is the first question when two hosts disagree, and nothing else printed can answer it: coordinates
differ between identities *and* between networks, so comparing them separates neither case.

## 7. What would have to be true for this to be wrong

* If a deployment genuinely has no beacon — no commitment at all — this has nothing to hash and must fall back
  to the constant. Such a deployment has no epoch clock and no reshuffle either, so it has no placement
  defence at any epoch; the honest answer there is that it is a test fixture, not a network.
* If the commitment were ever *published outside* the set of participants as a matter of course, the value
  would be public again and the change would buy only the per-deployment separation, not the unpredictability.
  Nothing in the current design publishes it, but a directory or explorer that did would silently undo half of
  this.
* The **fingerprint** (§6) is four bytes of `H(label ‖ commitment)`. It does not help grinding — that needs the
  whole seed, and this is a preimage-resistant hash of it — but it is a *confirmation* oracle: someone holding
  a candidate commitment can check it against a published fingerprint and learn that a given host runs that
  network. It is printed by local operator commands and is not put on the wire; a future surface that
  published it would be making a network-membership statement, and should say so.

## 8. What was adopted

The derived genesis seed, wired through `Directory` (§5.2), with the runbook step recorded: **produce the
first beacon round before opening joins.** Do **not** rely on admission proof-of-work for this window — §2
shows it does not apply — though admission remains correct and valuable for what it does address, which is the
steady-state and Sybil cases.

The lesson worth carrying past this note is §5.3's: a value that moves *where a node sits* has as many
consumers as there are things that name a position, and the ones that fail do so by finding nothing rather
than by erroring. Finding them needed the whole suite, not the crate being edited.
