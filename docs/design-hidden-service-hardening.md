# Hidden-service hardening — accountable anonymity, attack resistance, load distribution

**Status: partly implemented — §6 is real, §2–§5 are design.** Written 2026-07-31, updated 2026-08-01. What has
landed: the registration binding is authenticated (`9e34d4c`), the combiner map covers the plane instead of
concentrating below the fault bound (`a7c7699`), `m = f + 1` is derived and proven (`32a4248`), and a host
registers at all `m` (`edcf845`). What has NOT: **the client still always takes meeting point 0**, so the
censorship bound of §6 does not bind yet — the registrations cost traffic and buy nothing until clients spread.
Everything in §2–§5 (the client tag, the admission ladder, the filtering surface, replica load-spreading) is
design only, and §8's frontier — whether the lattice ZK stack can carry the §2 proof at a per-request cost — is
unmeasured.

Written in answer to a direct requirement: hidden-service anonymity and security at the highest level reachable,
protocol-level resistance to DDoS and related attacks, **client identifiers a conventional backend (nginx, haproxy)
can filter on** while the chain of hops is unchanged, and load distribution.

The organising claim is that FANOS does not need to import these mechanisms. Every one of them falls out of parts
the platform already has — the SIS Merkle tree and nullifiers OBOLOS just built, Shamir sharing from the keyper
reveals, the epoch beacon, the projective plane, and a private currency. Where a mechanism is borrowed in spirit
(Tor's onion-PoW, Privacy Pass, RLN), the derivation is redone from FANOS structure rather than the construction
copied, because the structure is stronger than what those systems could assume.

---

## §0. The three gaps this closes, and one it does not

Today a service registers a forward route at one combiner and answers whatever arrives.

1. **No accountability at all.** Every client is perfectly unlinkable, so the service cannot distinguish one
   attacker sending a million requests from a million clients sending one. Nothing can be rate-limited, and the
   backend behind `fanos host --forward` sees every request as coming from the same place.
2. **One meeting point per epoch.** `meeting_line(service_pubkey, epoch, beacon)` yields a single line, so a single
   node holds the whole of a service's inbound traffic for an epoch. It cannot read requests, but it can drop them.
   **This is a censorship single point of failure and is filed separately as a defect, not a design gap** — Tor has
   had multiple introduction points since v2, and the fix here is smaller than Tor's because the plane supplies the
   spread for free (§6).
3. **One route per tag.** `hosts: BoundedMap<[u8;32], HostRegister>` maps a service to exactly one forward route,
   so a service is one process on one machine. There is no way to run a second replica (§5).

**What this design does not attempt:** hiding *that a service exists* from a party who already knows its address.
An address holder can always compute the epoch tag and probe. §7 narrows the window; it does not close it, and a
design that claimed to would be lying.

---

## §1. The trilemma, and the only escape

Rate limiting needs to know that two requests came from the same party. Anonymity is precisely the property that
you cannot know that. So **anonymity ∧ per-client accountability ∧ no trusted authority** cannot all hold in the
naive sense, and every real system gives one up:

| System | Gives up |
|---|---|
| Tor onion services (pre-0.4.8) | accountability — no per-client notion at all |
| Tor onion-PoW | accountability, replaced by *cost*: no identity, only work |
| Privacy Pass / anonymous tokens | the authority — an issuer must exist and be trusted not to link |
| Plain IP rate limiting | anonymity |

The escape is to notice that accountability does **not** require identity. It requires a **stable pseudonym scoped
to one service and one epoch, provably rate-bounded**. That object is already in this codebase under another name:
a **nullifier**. OBOLOS publishes, per shielded spend, a value that is deterministic in a secret, unlinkable to the
note it spends, and detectably repeated. Retarget it from "this note is spent" to "this client has spoken", and the
accountability problem is solved without an authority and without identity.

---

## §2. The client tag — a post-quantum rate-limiting nullifier

### 2.1 The object

A client holds a long-term secret `csk` whose commitment `Comm(csk)` sits in a **membership set** (§2.4). For a
service `S`, epoch `e`, and message index `i`, define

```
  tag   = PRF(csk, S ‖ e ‖ i)                    the pseudonym the service sees
  share = (x, y)  where  x = H(request ‖ S ‖ e),   y = a_0 + a_1·x   over the field
                          a_0 = csk,  a_1 = PRF(csk, S ‖ e ‖ i ‖ "slope")
```

and a proof `π` that, in zero knowledge:

1. `Comm(csk)` is a leaf of the membership tree with root `R` — a **SIS Merkle tree**, the one built for OBOLOS's
   ring-native spend proof;
2. `tag` is that exact PRF evaluation on that exact `csk`;
3. `i < K`, the per-epoch quota;
4. `share` lies on the line whose intercept is `csk` and whose slope is the derived `a_1`.

The service accepts `(tag, share, π)` and keeps `(tag → count, shares)` for the epoch.

### 2.2 What each clause buys

* **(1) is the anonymity set.** Unlinkability is exactly the size of the membership set, and it is public, so a
  client can *check* its own anonymity before speaking rather than trusting an operator's claim.
* **(2) makes the tag a stable identifier within `(S, e, i)` and an unlinkable one across services and epochs.**
  Binding `S` is what stops two services from correlating a client; binding `e` is what stops a permanent profile.
* **(3) is the rate limit itself, enforced by arithmetic rather than by the service's bookkeeping.** A client
  cannot mint a `K+1`-th distinct tag, so exceeding the quota is not "unpoliced", it is *impossible without reusing
  a tag*.
* **(4) is what makes reuse expensive rather than merely visible** — the RLN idea, and the reason this is not just
  "a nullifier with a counter". Each message carries one Shamir share of `csk` at a point derived from the message.
  One share reveals nothing. **Two messages under the same tag are two points on the same line, so `csk` is
  recovered by interpolation** — by anyone, from public data. The credential is then burned, its stake slashable
  through the existing TAXIS incentive path, and the client's whole history under that `csk` becomes linkable to
  itself (never to a person).

That last property is the design's centre of gravity: **a flood is not blocked, it is self-incriminating.** An
attacker who wants `n·K` requests in an epoch must hold `n` credentials, because the `n+1`-th request from any one
of them destroys it.

### 2.3 Why this is not just RLN

RLN as deployed (Semaphore, Waku) is a Groth16 circuit over BN254 with Poseidon — pairing-based, and dead the day a
CRQC exists. FANOS cannot use it: the whole platform is post-quantum by construction. The substitution is not
cosmetic:

* the Merkle tree is **SIS-based** (already built for OBOLOS), so membership is lattice-hard;
* the proof system is the **lattice ZK stack OBOLOS already carries**, not a pairing SNARK;
* the PRF and commitment are the platform's BLAKE3-based labelled hashes and SIS commitments.

To the best of what this design's author can establish, a **post-quantum rate-limiting nullifier** is not deployed
anywhere. It is claimed here as a construction, not as a proven scheme: the proof sizes and verification cost of
the lattice stack are the open engineering question, and §8 says so plainly.

### 2.4 Who is in the membership set — three modes, one mechanism

The tree's contents are policy, and the same circuit serves all three:

* **Open** — anyone may insert a commitment by burning a small OBOLOS amount. Sybils are priced, not forbidden.
* **Staked** — insertion locks stake; clause (4)'s recovery makes it slashable. Attack cost becomes explicit.
* **Authorised** — the service (or a federation) admits commitments. This is *client authorization* in Tor's
  sense, and it arrives for free rather than as a separate feature.

A service names the roots it accepts in its descriptor, so it may accept several sets at once with different
quotas — e.g. a large open set at `K = 8` and a small staked set at `K = 512`.

---

## §3. The admission ladder as a control law, not three features

Requiring a credential for every request would be wrong: it costs the client a proof and the service a
verification, and most traffic is benign. The service therefore publishes a **per-epoch triple** in its descriptor,

```
  (d, K, p)   =   PoW difficulty,  per-epoch quota,  price per request
```

and each request satisfies **one** tier:

| Tier | Cost to a client | What the service learns | When it binds |
|---|---|---|---|
| **0 — work** | a PoW over `(tag_S, e, beacon, request)` at difficulty `d` | nothing; no pseudonym | always available; the free path |
| **1 — credential** | one proof `π` (§2) | a stable per-epoch pseudonym + remaining quota | when filtering or fairness is wanted |
| **2 — payment** | a shielded OBOLOS transfer of `p` | nothing beyond "paid" | under sustained attack |

Two things make this a ladder rather than a menu. First, **tier 0's puzzle is bound to the epoch beacon**, so it
cannot be precomputed beyond the current epoch — a strictly stronger position than Tor's onion-PoW, whose seed is
service-chosen and whose freshness is therefore the service's problem. Second, **the triple is driven by a
controller, not set by hand.**

### 3.1 The controller

Let `u` be measured utilisation (admitted requests per epoch ÷ service capacity) and `u*` the target. The service
adjusts along the gradient of a single cost functional rather than by three independent knobs, because three
independent thresholds is precisely the "magic constant" failure this platform forbids:

```
  Φ(d, K, p)  =  (u − u*)²  +  λ·(honest cost)
```

with honest cost the expected work/quota/fee paid by a compliant client. Descent on Φ raises `d` first (it costs
attackers most per unit of honest pain, because honest clients are few relative to a flood), then lowers `K`, then
raises `p` — the ordering falls out of the relative gradients rather than being decreed. Under no load the
controller returns to `(0, K_max, 0)`, i.e. an unauthenticated service, which is the correct resting state.

This is the same shape as the platform's homeostasis argument — Lyapunov descent to a coherence attractor — applied
to admission rather than to topology, and it should be simulated the same way.

---

## §4. The filtering surface — how the tag reaches nginx

The host driver already terminates the anonymous session and forwards each stream to a local address
(`fanos host --forward HOST:PORT`). That is exactly the right seam, because it is the only place where an
identifier can be attached *after* the anonymity layer has done its work.

**HTTP backends.** The host injects, per forwarded request:

```
  X-Fanos-Client:     <tag, 32 bytes hex>     stable for this (client, service, epoch)
  X-Fanos-Epoch:      <epoch>
  X-Fanos-Tier:       work | credential | payment
  X-Fanos-Quota-Left: <K − i>                 credential tier only
  X-Fanos-Set:        <membership root, short id>
```

so an operator writes ordinary nginx:

```nginx
  limit_req_zone $http_x_fanos_client zone=perclient:32m rate=10r/s;
  map $http_x_fanos_tier $burst { work 2; credential 20; payment 100; }
```

**Non-HTTP backends.** The same values ride **PROXY protocol v2 TLVs** (the spec reserves a custom TLV range), so
`haproxy`, nginx `stream`, and anything PROXY-aware receives them without parsing application data.

**The trap, stated because it is the classic way this fails:** the host **must strip every inbound `X-Fanos-*`
header before injecting its own**. A client that can set `X-Fanos-Client` chooses its own rate-limit bucket and the
entire mechanism inverts into an attacker-controlled bypass. The stripping must be unconditional and tested by a
scenario that sends the header deliberately.

**What the backend must not conclude.** The tag is not an IP and not a person: it is stable for one epoch, it
changes at the boundary by construction, and two tags may be the same human. Persisting it as a user key would
create the profile the design exists to prevent. Documented as such, with the epoch in the header so a backend
cannot accidentally treat it as durable.

---

## §5. Load distribution — the tag is also the balancing key

### 5.1 Several routes per tag

`hosts` becomes `service_tag → {HostRegister}` — a set, each entry a distinct replica with its own dead-drop line
and reply key, each independently signed under the same identity (§45's binding). The combiner selects

```
  replica = registrations[ H(tag_S ‖ client_tag) mod n ]
```

Consistent hashing on the **client tag from §2** gives **sticky sessions with no shared state**: the same client
lands on the same replica for the whole epoch, which is what a real application needs (caches, in-flight uploads,
WebSocket affinity), and the mapping reshuffles at the epoch boundary along with everything else. One primitive,
two uses — the identifier that makes filtering possible is the identifier that makes affinity possible.

Tier-0 traffic has no client tag; it hashes on the request digest instead, which spreads without affinity. That is
the correct trade: unaccountable traffic gets no session guarantees.

### 5.2 Spread over the line, not over one node

A replica registers at the meeting **line**, which has `q + 1` points. Registering one replica per line member
means no single node sees the whole request stream — an availability gain *and* an anonymity gain, since traffic
analysis at one combiner sees a `1/(q+1)` sample.

---

## §6. Censorship resistance — `m` meeting points, not one

**This is the largest availability gap in the current design and is filed as a defect.** A service's meeting line
is `meeting_line(service_pubkey, epoch, beacon)`, a single line, so the `q + 1` nodes on it — in practice the one
combiner a client reaches — hold the whole of that service's inbound traffic for an epoch. They cannot read it.
They can drop it.

The fix is a one-parameter generalisation the geometry already supports:

```
  meeting_line_i(pk, e, beacon, i)   for  i ∈ 0..m
```

A client picks `i` uniformly (or walks `i` on failure); the service registers at all `m`. A censor must hold every
one of the `m` lines simultaneously, and since line membership is beacon-driven and re-drawn each epoch, holding
them requires controlling a growing fraction of the plane rather than a fixed few nodes. Tor reaches the same place
with 3 introduction points chosen by the service; FANOS gets a *verifiable* spread instead of a chosen one, because
the lines are a public function of the key and the beacon.

### 6.1 `m = f + 1`, derived and proven

`m` is not a free constant and it is now settled. Model the censor as the fault model already does: an adversary
holds a set `A` of points with `|A| = f`, where `f = ⌊(n − 1)/3⌋` — the same tolerance every other bound here
assumes. A service is censored exactly when every one of its meeting **combiners** lies in `A`. With `m ≤ f`
distinct combiners the adversary picks `A` to cover them and censorship is deterministic *within the budget the
platform already grants it*; with `m = f + 1`, pigeonhole leaves one combiner outside `A` for every admissible `A`.

So **`m = f + 1`** — on the Fano plane, 3, which is the number Tor picked by convention and here follows from the
geometry. Distinct *combiners*, not distinct lines: two lines can share one, and `f + 1` lines with `f` distinct
combiners is the censored case again.

Implemented as `fanos_rendezvous::meeting_lines`, with a two-plane test. That test is also what found the defect
underneath: the combiner map used to cover only 14 of 57 points on `PG(2,7)` against `f = 18`, which made `f + 1`
distinct combiners *unobtainable* — and a Fano-only test would have stayed green at 4 combiners and shipped it.

### 6.2 The consequence: the at-combiner mode cannot survive `m > 1`

Wiring `m` surfaced a structural incompatibility rather than a bug. **A service that is its own combiner sits at
`combiner_for(meeting)` — one point.** With `m` meeting points a client may pick any of them, and one node cannot
occupy `m` combiners. So `m = f + 1` and the at-combiner mode cannot both hold, and no amount of test rewriting
changes that.

Three ways out, and the costs are what decide it:

* **(a) Hosting becomes mandatory.** Every service registers a forward route at all `m` (the §3b path, authenticated
  by the identity binding). The at-combiner shortcut is deleted. Costs registration traffic ×`(f + 1)` — 3 on Fano,
  19 on `PG(2,7)` — and every service runs the host driver.
* **(b) The client walks the points**, trying one and moving on. But a censoring combiner black-holes rather than
  refuses, so "failure" is a timeout — the one signal the adversary controls — and a dial under censorship costs
  `m` round trips.
* **(c) `m` applies only to hosted services**, leaving at-combiner services with their single point of censorship —
  which puts the weakest mode in the path an operator reaches for first.

**(a) is chosen.** The at-combiner mode is a test-and-demo convenience that already cannot survive a real plane: it
needs the service to land by luck on one of only four Fano combiners, and its coordinate is then the very thing the
substrate exists to hide. Option (b) hands the adversary the failure signal, which is the wrong direction on
principle. The registration cost is real and bounded, and §5's replica set already needs a host driver.

### 6.3 The bound is claimed by construction and NOT yet demonstrated

The mechanism is in place — hosts register at all `m`, clients pick among them — and the eight anonymous e2e tests
pass. **That is not the same as surviving censorship, and the difference has been measured rather than assumed.**

With meeting point 0's combiner stopped and points 1 and 2 alive, dials fail far more often than the pick
distribution can account for: 0 of 8 arrived in one run, while a run differing only in an instrumentation probe
passed. Three candidate causes were each ruled out by their own experiment — a route/meeting mismatch in the Fresh
profile (a real defect, since fixed, but not this), impatience (per-attempt deadline raised fourfold, no change),
and missing bindings (probed directly: all three meeting points bind the same service tag). What remains is
unexplained and nondeterministic.

Two properties of the setting were established on the way, and both belong here rather than in a test comment:

* **A silenced combiner does not refuse, it swallows.** A dial still *succeeds* — it only seals and emits — and
  the exchange then wedges indefinitely. So the only failure signal available to a client is a clock, which is
  the one signal an adversary controls. This is the concrete form of the objection §6.2 raised against letting
  the client walk the points as the primary mechanism.
* **The property to prove is "remains reachable", not "every dial completes".** Since a dial does not retry, a
  fraction of picks landing on a censored point *should* fail; a test asserting otherwise cannot pass and would
  be measuring a mechanism that does not exist yet.

Until a scenario demonstrates reachability under a silenced meeting point — falsified by collapsing `m` to 1 —
§6's bound stands as a derivation whose implementation is unverified.

---

## §7. Anonymity hardening — four residuals

1. **Bind the service tag to the beacon.** `service_tag = H(bundle ‖ epoch)` today, so an adversary holding a list
   of candidate addresses can precompute every future epoch's tags and watch for them. Adding the epoch beacon —
   unpredictable until the epoch opens — reduces that to the current epoch only. Cheap, already available, strictly
   better.
2. **Client authorization as a first-class mode.** §2.4's authorised set already expresses it; what is missing is
   that an unauthorised client should be unable to *locate* the service at all, not merely be refused by it. That
   means deriving the meeting line from a shared secret for private services, which is a different derivation, not
   a flag.
3. **The guard tension, stated because it is real and unresolved.** FANOS re-draws coordinates every epoch, which
   maximises unlinkability — and *minimises* entry-guard stability, the property Tor's guard design exists to
   protect. A client that draws fresh first hops every epoch will, over enough epochs, eventually draw a hostile
   one; a client with a sticky first hop is either safe or compromised from the start, which is the strictly better
   risk profile against a long-running observer. The resolution is a **first hop derived from a long-term client
   secret and rotated on a slow schedule** (every `N` epochs, `N` derived from the desired compromise probability),
   while every *subsequent* hop keeps per-epoch rotation. This trades a little unlinkability at the edge for a
   large reduction in eventual-compromise probability, and the trade should be quantified in the simulator before
   it is chosen.
4. **Shape the reply path.** PROTEUS already provides per-morph size and timing shaping; the hidden-service reply
   dead-drop is a distinctive pattern (a burst to a line the client is a member of) and should be explicitly
   covered by a morph rather than inheriting whatever the transport does.

---

## §8. What is derived, what is chosen, and what is unproven

Stated explicitly, because the platform's standing rule is that a chosen constant where a derivation is possible is
a defect.

**Derived.** The tier ordering in §3 (from the gradients of Φ). The replica selection in §5 (consistent hashing on
an identifier that must exist anyway). The spread in §5.2 (`q + 1` line members). The requirement that `m` in §6
follow from the plane's fault tolerance.

**Chosen, and each needs a derivation before it ships.** `K` (per-epoch quota) — should follow from the honest
client's actual request profile, measured, not guessed. `u*` and `λ` in the controller. The rotation period `N` in
§7.3 — derivable from a target compromise probability, and that derivation should be done rather than a number
picked.

**Unproven, and the honest frontier.** The §2 construction assumes the lattice ZK stack can carry a membership
proof plus a PRF evaluation plus a range check at a per-request cost a client can pay. OBOLOS's whole-transaction
shielded-spend proof is the closest existing evidence and it is *not* the same circuit. Until that is measured —
proof size, prove time, verify time, on real hardware — §2 is a design and not a plan. The correct first step is a
benchmark of the three clauses against the existing SIS stack, and if the cost is prohibitive the fallback is tier
0 plus tier 2, which need no ZK at all and still give cost-based DDoS resistance and payment-based load shedding —
losing only the filterable identifier, which is the one thing that genuinely requires the proof.
