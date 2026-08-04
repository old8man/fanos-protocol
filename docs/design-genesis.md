# The genesis window — why it is open, why proof-of-work does not close it, and the one-line fix that does

> **Status.** Analysis and a recommended change; the change is **not yet implemented**. The window itself is
> established and measured (`docs/design-coordinates.md` §2, confirmed against `on_join` / `on_announce`).
> This note is the synthesis the founding choreography needs before it can pick a defence, and it reaches a
> different answer than the three options originally listed — one of those options is provably useless here.

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

## 5. The cost, honestly

One real consequence, and it is a *correction* rather than a regression: **`fanos id` becomes
network-specific.** Today it prints a coordinate computed from the credentials alone, and that coordinate is
the same on every FANOS network in existence. After this change it needs the network's commitment
(`--beacon-params`) to print a meaningful point, and printing one without it would be printing a placement the
node will not have.

That is the right shape — an identity's placement *should* depend on which network it is joining — but it
changes a command's signature and the runbook's step 2, so it is a deliberate break rather than a silent one.

Three call sites compute the genesis coordinate for display (`bin/fanos.rs`), plus the live path through
`spawn_self_certifying_persistent_over`, where the commitment is already in hand.

## 6. What would have to be true for this to be wrong

* If a deployment genuinely has no beacon — no commitment at all — this has nothing to hash and must fall back
  to the constant. Such a deployment has no epoch clock and no reshuffle either, so it has no placement
  defence at any epoch; the honest answer there is that it is a test fixture, not a network.
* If the commitment were ever *published outside* the set of participants as a matter of course, the value
  would be public again and the change would buy only the per-deployment separation, not the unpredictability.
  Nothing in the current design publishes it, but a directory or explorer that did would silently undo half of
  this.

## 7. Recommendation

Adopt the derived genesis seed, and record the runbook step. Do **not** rely on admission proof-of-work for
this window — §2 shows it does not apply — though admission remains correct and valuable for what it does
address, which is the steady-state and Sybil cases.
