# Governance: who controls a FANOS network, and how

Written because the question has a real answer in the code, and because two of the three answers are
uncomfortable enough that they should be decided deliberately rather than inherited from whatever the first
deployment happened to do.

The short form: **membership is ungoverned by construction; the epoch clock and the validator set are governed
by whoever was present at genesis.** Everything below is that sentence, in detail, with the evidence.

## 1. What no one controls, and cannot

These are properties of the construction, not policies a configuration can relax.

**Position.** A node's coordinate is `MapToPoint(VRF(sk, node‖epoch‖beacon))` — bound to its identity and proven
at HELLO. A node cannot choose where it sits, and no one can place it. This removes, structurally, the power
that in most overlays belongs to whoever operates the directory: the ability to seat an adversary next to a
target. See `docs/design-coordinates.md`.

**Rendezvous.** Two lines of the projective plane meet in exactly one point, found in O(1) with no search. The
meeting point is a computation, not a lookup, so "rendezvous operator" is not a role that exists.

**Storage placement.** Derived from the address. There is no allocator to petition or capture.

**Enforcement.** Slashing is permissionless: an equivocation proof is two conflicting signed votes, it is
self-contained, execution re-verifies it, and the account it debits is derived from the verifying key inside the
proof — so **the evidence names its own target** and no validator registry is consulted. Anyone can submit one.
See `fanos-dromos/src/stake.rs`.

**Scale.** A cell holds about `q` nodes, not `q²+q+1` — a birthday bound on VRF coordinate draws. The network
therefore *must* federate into many cells rather than growing one large one, so there is no single cell whose
capture is capture of the network.

## 2. What is controlled, by whom, today

### 2.1 The epoch beacon — the load-bearing one

Coordinates derive from the beacon. Whoever holds a reconstruction threshold of its shares influences where
every joining node lands. That is the most consequential power in the system, and it is worth stating plainly
that it is a *governance* position and not an operational detail.

Two paths exist, and only one is safe for a public network:

* **Dealt** (`fanos beacon-deal`, and `fanos init` when starting a cell): one party generates the secret and
  splits it. That party held the whole key at the moment of dealing. Correct for a private or test cell, where
  the dealer is the only operator. **Wrong for a network opened to others**, where it makes the founder the
  permanent holder of everyone else's addressing randomness.
* **Distributed** (`fanos-keygen`): a real Byzantine-robust DKG — Feldman/Pedersen sharing with a
  Gennaro–Jarecki–Krawczyk–Rabin complaint round, dealer disqualification, and a `QUAL` set over which the joint
  key and every share agree. Every control frame is bound to its origin, so a malicious member cannot speak for
  an honest one. **No party ever sees the whole key.**

`fanos init` now asks which of the two situations it is in rather than assuming, and says what the answer costs.
It cannot run the DKG itself — that needs the founding nodes to be running and talking to each other — which is
precisely why the dealt path must not be the one a public launch walks into by default.

**Decision required before a public launch:** run the DKG across the founding set. The code is there; what is
missing is only the operational choreography.

### 2.1b The POROS ingress descriptor — a dealt secret with a *published* half

A community's ingress descriptor names the entry peers a censored newcomer bootstraps from. It is dealt
(`fanos ingress-deal`) rather than distributed, and unlike the beacon that is defensible: the descriptor is a
*community's* list of its own entry points, so the party that compiles it necessarily knows it, and the
threshold sharing exists to stop a **seizure** of `< t` members from disclosing it, not to stop the dealer from
knowing what they themselves wrote down.

What the ceremony must not get wrong is the other half. Every member's file carries the dealing's public
**binding** alongside its secret share, and a host refuses to start without one. That is not belt-and-braces:
a POROS line reconstructs a *plaintext*, so it has no AEAD tag to fail on a wrong reconstruction the way every
other threshold secret in the platform does, and Lagrange interpolation is linear — a single member could
otherwise contribute an offset share and make every other combiner serve a descriptor of its choosing, which is
to say choose the entry peers the whole community bootstraps from. Confidentiality below threshold and
integrity at any threshold are different properties, and only the first one comes free from Shamir.

**Operationally:** hand each member exactly one file and no more. A second file gives its holder a second
share, and two of three is the threshold.

### 2.2 The validator committee

TAXIS verifies against a fixed committee established at genesis (`fanos taxis-deal`). Share *resharing* exists
at the VSS layer (`fanos_vrf::vss::reshare` / `verify_reshare`) and the beacon uses it, but there is no live
protocol for changing the TAXIS committee itself. So **who orders transactions is decided once, when the chain
is created.**

**Decision required before a public launch:** the rule by which the committee changes — and it is far cheaper to
answer now than after there is state to preserve. Stake is already in committed state
(`StakeTx::Bond`/`Unbond`), which is the natural basis for such a rule; nothing currently reads it for
membership.

### 2.3 Entry points and builds

Whoever runs the first nodes appears in everyone's initial `bootstrap`, and therefore sees who arrives. The power
decays quickly — knowing any peer is enough, and the overlay is structural rather than directory-based — but at
launch it is real.

Open source does not decentralize the *binary*. Whoever publishes builds can change all of the above by shipping
a new one. Reproducible builds and signed releases are what make the rest of this document meaningful rather
than aspirational.

## 3. What limits joining

* **Proof of work** at admission (`admission_difficulty`) — a per-join cost, which is anti-Sybil at the margin
  rather than absolutely.
* **Unchoosable position** — a Sybil fleet can be large but cannot aim.
* **Cell capacity** — cells stay small and federate.
* **Role assignment** — the configuration *offers* roles; the cell *assigns* them (`Node::assigned_roles`).
* **Bonded stake and slashing** for validators.

## 4. The honest summary

Nobody governs who may join, and nothing in the design gives that power to anyone. Two things *are* governed —
the epoch clock and the validator set — and today both belong to whoever performs genesis. The architecture
already contains the trust-minimized alternative for the first (a working DKG) and the raw material for the
second (on-ledger stake). Neither is yet the default path, and defaults are what a public network inherits.
