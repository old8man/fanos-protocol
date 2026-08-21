# Upgrading a live FANOS network: epoch-aligned activation, because derivation skew is invisible

**Status: design, 2026-08-01.** The wire layer's versioning is built and sound for the classes it covers. The
class it does *not* cover — a change to a **derivation** rather than to a frame type — has no protection today,
and `#55` is the empirical proof of how that class presents. This document derives the mechanism for it.

---

## §1. Three kinds of change, and only two of them are visible

`fanos-wire` is the single frame-numbering authority, and spec §7.4 already versions the registry with IANA-style
allocation. That gives two well-behaved classes:

| class | what happens on a mixed-version network | verdict |
|---|---|---|
| **A. Additive frame type** | unknown types on a stream are skipped by `length` | safe, already handled |
| **B. Critical frame type** | unknown critical types abort the connection with `UNSUPPORTED` (§7.5) | safe *because it is loud* |
| **C. Changed derivation** | **nothing** | **unprotected** |

Class B deserves note: aborting looks worse than skipping, but it is the better failure. A node that cannot
speak the required protocol says so, at once, at the connection. Loud is the property you want.

**Class C is the problem, and it is not hypothetical — it is what this codebase shipped today.** Changing
`combiner_of(line)` to `combiner_of_salted(line, onion)` altered *where an onion is addressed*. No frame type
changed. No field was added. Both versions emit a perfectly well-formed `TAG_ONION` to a perfectly valid
coordinate. They simply disagree about **which member of the line is gathering**, so:

* the old-version sender addresses the canonical member; a new-version member is gathering elsewhere;
* the hop produces no error, no `UNSUPPORTED`, no malformed frame;
* it simply never peels.

The same shape covers any change to: a coordinate or line derivation, a key-derivation label, a threshold, a
padding bucket, a hash domain separator, or a serialization order that both sides still parse. **All of them are
silent by construction**, because agreement on a derivation is not something a wire format can check.

### 1.1 Why silence is worse here than in an ordinary network

`#55` measured the presentation. A dead data path was indistinguishable from **eleven** other hypotheses, took a
full working session to localize, and its only failure signal was a clock — which, in an anonymity network, is
the one signal an adversary also controls. A version-skew incident would present *identically*. An operator
would see dials timing out and no error anywhere.

So the requirement is not "make skew survivable". It is, in order:

1. **make skew observable**, before
2. **make skew impossible**, and only then
3. make the rollout fast.

Fast rollout without (1) and (2) is not a fix pipeline; it is a way to cause the next `#55` across the whole
fleet at once.

---

## §2. Canary deployment does not map onto this network

The universal playbook — "ship to 10% of nodes, watch, widen" — assumes a stable addressable subset. FANOS has
none: a node's coordinate is `MapToPoint(VRF(sk, node ‖ epoch ‖ beacon))` and **rotates every epoch**, by design,
so "the nodes at these addresses" is not a set that persists across the observation window.

Worse, a coordinate-range canary would be actively harmful: it would select a *geometrically clustered* subset,
and clustering is exactly what the plane's fault model assumes away.

Canarying must therefore be expressed in the platform's own units:

* **by cell** — cells federate and are the natural blast-radius boundary (a cell is where a threshold, a beacon
  and a fault bound all live);
* **by role** — `roles.rs` already has the network assign function, so "upgrade the relays first" is expressible;
* **by opt-in flag** in the node descriptor — an operator volunteers, which is honest for a public network where
  nobody can be conscripted into a canary anyway.

Never by coordinate.

---

## §3. Activation is epoch-aligned, because the beacon is already the shared clock

The mechanism follows from what exists. Every node already agrees on an **epoch ordinal** (`EPOCH_AGREE`,
distinct from the `BEACON` randomness round) and on the beacon that seeds each epoch. That is a shared,
Byzantine-agreed clock — which is precisely, and only, what a coordinated switch needs.

**So a derivation change activates at an epoch height, not at process start.**

```
  feature F is active for epoch e   iff   e ≥ activation_height(F)
```

Consequences, each of which is the reason to do it this way rather than a nice property:

* **A whole line flips together.** A threshold gather needs `t` of `q+1` members to agree on the derivation. Any
  switch granularity coarser than "all members at once" leaves a window where a line cannot reach quorum — which
  is class C's silent death, self-inflicted.
* **Restart order stops mattering.** Nodes may deploy the new binary over hours; none of them *behaves*
  differently until the height arrives. Deployment and activation become separate events, and only the second
  one is consensus-critical.
* **It reuses the registry rather than adding a mechanism.** Spec §7.4 already versions frame types; an
  activation height is the same idea applied to derivations, and belongs in the same authority (`fanos-wire`)
  rather than in a second, parallel scheme that could disagree with the first.

### 3.0 Where it lives, and the dependency fact that decides the type

§3 argues the activation registry "belongs in the same authority (`fanos-wire`) rather than in a second,
parallel scheme that could disagree with the first". Checked against the crate graph, that placement holds —
but it fixes the *type*, and not the way one would first reach for:

**`fanos-wire` cannot use `Epoch`.** `Epoch` lives in `fanos-primitives`, and `fanos-primitives` already
carries an optional dependency **on `fanos-wire`**. A `fanos-wire → fanos-primitives` edge would close a
cycle. So the registry takes a bare **epoch ordinal (`u64`)**, or a newtype `fanos-wire` defines itself.

That is the better shape anyway, and worth stating as a rule rather than a workaround: the frame-numbering
authority is *below* the geometry and identity vocabulary in the graph, and should stay there. An activation
height is a number two nodes must agree on — it needs no plane, no coordinate, and no key material to mean
what it means. Reaching for `Epoch` would have coupled the wire's version authority to the whole geometry
stack to gain nothing but a nicer signature.

The shape, then:

```text
  ActivationHeight(u64)                    // the epoch ordinal a feature becomes active at
  Derivation                               // the enumeration of derivation-versioned behaviours
  fn active_at(d: Derivation, epoch: u64) -> bool     // e >= activation_height(d)
```

with each call site selecting between its two implementations on `active_at`, and the epoch supplied by the
caller that already holds one (the node driver) rather than read from a clock inside the registry — the same
sans-I/O discipline every other engine follows. **First consumer: `combiner_of` vs `combiner_of_salted`**,
the change that motivated this document.

### 3.1 Both derivations must be linked into the binary

A node that has not yet reached the activation height must still speak the *old* derivation, and after it, the
*new* one. So a release carries both and selects by epoch — which is the real cost of this design, and it is
worth naming: **derivation changes accumulate as code that cannot be deleted until every supported epoch is
past.** A retirement policy ("derivations older than `N` epochs are dropped in release `X`") must exist from the
start, or the codebase silently becomes an archive of every wire it ever spoke.

**Status: the registry exists (`fanos_wire::activation`), the dual implementations do not.** `Derivation`,
`activation_height`, and `Activation::is_active(derivation, epoch)` are built and tested, so the *schedule*
now has a single authority and a place for the next change to go. What is deliberately **not** built is the
second half — no call site yet selects between two implementations on `is_active`, because there is currently
nothing to select *between*: `combiner_of_salted` shipped before the registry existed, so it is registered at
height `0` (honestly "active for every epoch this build has seen") rather than back-dated to a switch that
never happened. Registering it at all is what gives the mechanism a worked example and the next derivation
change a home. **The first real exercise of this design will be the first derivation changed after it** —
and that change, not this commit, is what will prove the dual-implementation and retirement discipline.

---

## §4. Skew must be observable per line, not per node

"Is anyone running an old version?" is the wrong question; the network tolerates that by construction until the
activation height. The operational question is:

> **Does any hop line hold fewer than `t` members that agree on the current derivation?**

Because that — not the count of stale nodes — is the condition under which a hop dies. A cell can be 90 %
upgraded and still have one line below quorum, and *that line's traffic is what silently stops*.

This is a direct dependency on the observability work (`docs/design-observability.md`, tasks #16–#19), and it is
where two designs meet rather than merely coexist:

* **frame-decode failures counted per tag, per line** are the skew detector (§4 of the observability design lists
  exactly this station);
* a **feature/derivation vector** in the coherence plane's health frame makes agreement per line legible;
* the same DP export boundary applies — a version vector is node-identifying metadata and must not cross a node
  boundary unprivatized.

**Until skew is observable per line, an upgrade is not a controlled operation.** That ordering is the doc's main
operational claim.

---

## §5. Rollback, including the case the activation height creates

An epoch-aligned flip is also an epoch-aligned *break*: if a defect is only visible after activation, the whole
network entered it together. That is the price of coordination and it must be paid deliberately.

* **Before the height** — trivial. Deployment and activation are separate (§3), so pulling a release before its
  height is an ordinary redeploy.
* **After the height** — the honest statement is that rolling *back* a derivation is itself a derivation change,
  and therefore needs its own activation height. There is no instant revert. What can be shortened is the gap:
  a **second, pre-agreed abort height** shipped with the feature (`if a defect is found before epoch e+k, revert
  at e+k`) turns a rollback from a new consensus decision into an already-agreed one.
* **The stronger answer is to not need it**: an activation height gives a *scheduled* window in which the change
  can be exercised on a canary cell (§2) at the real epoch boundary before the fleet-wide height arrives.

---

## §6. The release key is the power that does not dilute

`docs/design-governance.md` §2.3 states it plainly: *"Open source does not decentralize the binary. Whoever
publishes builds can change all of the above by shipping a new one."*

Every other founding advantage decays as the network grows — bootstrap visibility dilutes, monitoring share
shrinks, the beacon becomes DKG-held. **The signing key does not.** An operator who can ship a binary can change
any derivation, any threshold, any bound in this document, and — since §1 established that derivation changes are
silent — can do so without an observable wire event.

So the release pipeline is a governance surface, not a build detail:

* **reproducible builds**, so a published binary is checkable against its source by anyone — **built**
  (`.github/workflows/ci.yml`, job `reproducible`: two builds from different source paths *and* different target
  directories, compared byte for byte, with the comparison shown to be live by perturbing a printed string);
* **signed releases**, so the artefact is bound to something — **built**, and deliberately not to a *key*
  (`.github/workflows/release.yml`): a keyless provenance attestation binds the archive to the repository, the
  commit and the workflow that produced it, checkable with `gh attestation verify`;
* **multi-party release signing** eventually, so the durable power is at least a threshold rather than a person —
  the same reasoning that moves the beacon from dealt to DKG. **Still open**, and the attestation does not close
  it: it mints no private key, which is a real improvement over a founder holding one, but whoever controls the
  repository can still run the workflow. The power moved from a key to an account; it did not dilute.

**Why the order of those three is not arbitrary.** A signature binds an artefact to a signer and says nothing
about what is *in* it; only reproducibility lets a third party rebuild the source and confirm the artefact is that
source. So the signature is worth what the reproducibility gate is worth, and an operator who distrusts the
attestation has a strictly stronger check available: run the recipe in the archive's `BUILD.txt` and compare
`shasum -a 256`. `docs/testnet.md` §8 gives both commands.

Without these, the rest of this document describes a mechanism that a single key can bypass.

---

## §7. What is derived, what is chosen, and what is unproven

**Derived.** That activation must be epoch-aligned (a threshold gather needs all `t` members to agree at once,
and the beacon epoch is the only clock they already share). That canarying cannot be coordinate-based
(coordinates rotate every epoch by design). That skew must be measured **per line**, since a line below `t`
agreeing members is the exact death condition. That derivation changes are invisible to a frame registry (a
registry types messages; it cannot type an agreement about how a value was computed).

**Chosen, and each needs a derivation before it ships.** The activation lead time (how many epochs between
publishing a height and reaching it) — should follow from measured fleet-update latency, not a guess. The
retirement window `N` in §3.1. The abort-height offset `k` in §5.

**Unproven, and the honest frontier.** That an epoch-aligned flip is *atomic enough* in practice: nodes agree on
the epoch ordinal, but a node whose clock lags, or which is mid-reconnect at the boundary, spends a brief window
on the wrong side. The size of that window and whether it can drop below the retransmission budget (so a session
merely stutters rather than dies) has not been measured. Until it is, an activation should be scheduled where a
brief per-line quorum dip is survivable — and that, too, is a claim the observability plane will be able to check
rather than assume.
