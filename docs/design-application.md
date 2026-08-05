# The application — one surface over the whole platform

**Status: design, 2026-08-05. Nothing here is built.** It names what the platform already has, what it does
not, and which parts of the product are blocked on which open work. Where a mechanism does not exist, this
says so rather than describing it in the present tense.

The goal the platform states for itself is a network that cannot be controlled or censored and on which every
user exercises privacy. An application is where that is either delivered or quietly given away, because a
product surface is what decides *which* privacy class a user actually gets, and users do not read protocols.

---

## 1. The two categories are one object

Social products divide into what look like two families:

| | examples | unit | recipient set | author |
|---|---|---|---|---|
| **broadcast** | x.com, Bluesky | a post | everyone | public |
| **rooms** | Telegram, Discord, Matrix | a message | a group | known to the server |

They are the same object. **Both are an authenticated append-only log with a recipient set.** A post is a log
whose recipient set is everyone; a DM is a log whose recipient set is one; a room is a log whose recipient
set is a group. Nothing else differs — not the storage, not the ordering, not the authentication.

What actually varies is two independent axes, and conflating them is why every existing product is weak in
one direction:

1. **the recipient set** — who may read;
2. **the observability of that set** — who may learn who reads, and who wrote.

Telegram gets (1) roughly right and (2) badly wrong: the server knows every membership and every timing.
x.com gets (1) trivially right — everyone — and (2) is not even attempted. Matrix federates (1) and leaks
(2) to every participating homeserver.

**So the application has exactly one primitive, and two orthogonal parameters on it.** Everything the user
asked for — feeds, rooms, DMs, communities, shops, calls — is that primitive at a different point in the
two-dimensional space. This is not a simplification for elegance; it is what makes a single privacy argument
cover the whole product instead of one argument per feature.

---

## 2. The recipient lattice is the plane, and it is already built

FANOS addresses nodes as points of `PG(2, q)`. That geometry *is* the lattice of addressable sets, and its
two structural theorems are exactly the two operations a social graph needs:

| set | size at `q` | what it is in the product | operation |
|---|---|---|---|
| **point** | 1 | a direct message | — |
| **line** | `q + 1` | a room, **and** a threshold quorum | `Point::join` |
| **plane** | `q² + q + 1` | a cell-wide broadcast | — |
| **subtree** | recursive | a community / federation | `HierAddr` prefix (§L1) |
| **network** | all | the global feed | root |

Two facts make this more than a naming scheme, and both are single field operations with no search
(`fanos-geometry`):

* **Any two points lie on exactly one line** (Steiner). So *any two users have a canonical shared room*,
  derivable by both without negotiation, handshake, or a broker that learns they spoke. A DM channel is a
  computation, not an allocation.
* **Any two lines meet in exactly one point** (dual Steiner / Maekawa). So *any two rooms have a canonical
  bridge member*. Federation between communities needs no directory and no agreed relay: the bridge is
  determined by the pair.

That second property is the one nothing else in this space has. Matrix federates by having servers talk;
here the bridge is a point of the plane, and the two rooms cannot disagree about which one it is.

**A room is hosted by a line, and that is why a room is not a server.** A line is `q + 1` members with a
threshold `t = ⌈2(q+1)/3⌉` (`fanos-node::mix_threshold`), so a room's state is threshold-held: no member can
serve a forged history, and `t` must collude to censor a message. The hosting mechanism exists —
`fanos-calypso` threshold hosting, dealt-and-sealed — and is what the product calls "a room stays up while
you sleep."

---

## 3. A room is a shared execution context, not a log with attachments

This is where "any interactivity" becomes a derivation rather than a wish.

Every product in category 2 bolts interactivity on: Discord has bots with a webhook, Telegram has a bot API
and inline keyboards, Matrix has widgets that are iframes to somebody's server. In all three the interactive
object lives *outside* the room's trust model, which is why every one of them is a deanonymisation surface.

FANOS has an execution model that fits inside it. **ERGON is an effect algebra with derived footprints and no
gas** (`docs/design-ergon.md`): a term declares which state it touches, the footprint is computed rather than
metered, and depth is bounded at `D_MAX = 3` by construction. Combined with DROMOS's conflict-DAG scheduler
(`fanos-dromos`, proven serial-equivalent and deterministic), that gives:

> **A room is a state machine. A message is an effect. Ordering is the line's own quorum.**

Then the whole product is one mechanism:

| what the user sees | the effect | why it is not special-cased |
|---|---|---|
| a chat message | `Say(body)` | appends to room state |
| an edit / delete | `Amend(id)` / `Retract(id)` | an effect on a prior effect |
| a reaction, a thread | `React(id, k)` / `Reply(id)` | effects addressed to an id |
| a poll | `Open`, `Vote`, `Close` | three effects and a tally |
| a shop listing | `List(item, price)` | an effect carrying an OBOLOS term |
| a purchase | `Bid` → `Settle` | two effects, atomic by the scheduler |
| a game move | any effect the object declares | footprint-typed like every other |
| a call | `Offer` / `Answer` — signalling only | media rides DIAULOS, not the log |

Two consequences worth stating because they are the difference between a design and a feature list:

* **Parallelism is free where the footprints are disjoint.** Ten thousand people reacting to different
  messages touch disjoint state, so DROMOS runs them in one wave. A room does not serialise on its own
  popularity — which is the actual scaling wall Discord hits.
* **An interactive object cannot exceed its declared footprint.** There is no sandbox to escape because there
  is no ambient authority to escape *to*: an effect that did not declare a piece of state cannot touch it,
  and the scheduler is what enforces it. That is a stronger statement than "we sandbox widgets."

**Not built.** ERGON has no live caller — `docs/audit.md` records that no running node constructs or
serialises a term (task #17 closed the library, not the wiring). The room state machine is the first real
consumer and would be the thing that finally exercises it.

---

## 4. Two dials, not one — and encryption is never on a dial

Before the classes, the structure they sit in, because conflating these two is the mistake that makes people
believe "fast" must mean "exposed":

* **Confidentiality is not negotiable and is not a setting.** End-to-end encryption, forward secrecy and PQ
  hybrid key exchange are on at *every* point of the speed dial, including the fastest. There is no mode in
  which the network reads your content. Turning that into an option would be the single worst decision this
  design could make, because an option is a thing that gets defaulted off, mis-set, or asked for by a
  government.
* **Network anonymity is a dial, and it costs latency and cover traffic.** What varies is who can learn
  *that you spoke, to whom, and when* — not what you said.

So the lane is a **hop count `h` plus a cover rate**, and the honest table is:

| `h` | what stands between | who could link the pair | latency | fits |
|---|---|---|---|---|
| **0** | nothing | the two parties themselves | best possible | media, bulk transfer, public feeds |
| **1** | one line (`q+1`, threshold `t`) | `t` colluding members of *that* line | one relay | calls, live streams |
| **2** | two lines | `t` on **each** of two specific lines | two gathers | messaging, most of the product |
| **3+** | three lines | as `h = 2`, plus resistance to walking the path | three gathers | the strongest setting |

**A hop here is a line, not a node, and that changes the arithmetic.** Tor needs three hops because a hop is
one machine that knows both its neighbours. Here a hop falls only when `t = ⌈2(q+1)/3⌉` of its members
collude — and on the base cell the platform already proves something stronger: *two points lie on exactly one
line*, so within the tolerated fault budget **at most one hop can ever be captured**, and one hop cannot be
both ends of a circuit. First-and-last correlation is structurally impossible there, at any `h ≥ 2`.

**Which makes the shipped depth a chosen constant, and it should not be.** `TARGET_DEPTH = 3` is documented
as "the depth that actually buys anonymity (**it is what Tor uses**)" — a value justified by citing a system
whose hop is a different object. The platform's own standing rule is that a chosen constant where a
derivation is possible is a defect, and a derivation is possible here: the required depth is a function of
`q`, `t` and `f`, and it should be computed rather than inherited. Filed; see the task register.

Each of the four classes below then names *what is hidden*; the dial above names *what is paid for it*. They
are orthogonal, and a product that offers only one of them is the reason people believe privacy and speed
are opposed.

## 4a. Privacy is a class per log, declared once, and it is the honest part

Here is where a product either tells the truth or sells a feeling. There is no configuration in which
everything is free: the platform's own substrate document derives the trilemma, and the costs are real.

**Four classes. Each log declares exactly one, at creation.**

| class | content | author | recipient set | what it costs | mechanism |
|---|---|---|---|---|---|
| **Ω0 open** | public | public | public | nothing | direct lane |
| **Ω1 veiled** | public | **hidden** | public | MIX latency + cover traffic | APHANTOS threshold onion |
| **Ω2 sealed** | private | known to the room | known to the hosting line | key management | ANGELOS + CALYPSO |
| **Ω3 occluded** | private | **hidden from the host** | **hidden from the host** | dead-drop + threshold + bandwidth | NOSTOS + POROS |

The four are ordered, and the ordering is what the UI must make impossible to mistake. A public feed post
under a persistent name is Ω0 and calling it anything else is a lie. A room where the hosting line can see
who is a member is Ω2 — which is *better than every product in category 2* and is still not anonymity.

**The invariant that most products get wrong: a log's class can never be raised in place.** Telegram has
"secret chats" beside normal ones and lets you keep both with the same person; Discord has no such notion at
all. But history already exists at the old class — moving a room from Ω2 to Ω3 does not un-leak the
membership the host already recorded. So:

> **Raising a class creates a new log with a new identity. The old one is retired, not converted.**

That is a derived rule, not a policy: the leak is in the past, and no future mechanism reaches it. The UI
consequence is that "make this private" is an explicit act with a visible discontinuity, which is honest,
where a silent toggle would not be.

### What the platform can and cannot deliver today

* **Ω0, Ω2 — available.** The hidden-service hosting path is proven end to end over real QUIC.
* **Ω1, Ω3 — available in mechanism, NOT at the default plane.** The anonymity set is `1/K` for `K`
  concurrent circuits, and on a Fano cell (`q = 2`, 7 points) that is a testbed, not an anonymity system.
  `docs/deployment-minima.md` says so and the application must say so too: **a client on a 7-node network
  must not display an anonymity claim.** Above Fano, since E7 closed, a wider plane buys both a larger set
  and a stronger hop — so the class is real at deployment scale and not at demo scale.
* **The wallet's shielded path — blocked.** OBOLOS's spend proof is ~145 MiB (task #65), four orders of
  magnitude too large to gossip. The wallet therefore ships **transparent** transfers, and the UI must say
  "this transfer is visible on the ledger," because a private-looking wallet that is not private is worse
  than an honest transparent one.
* **Anonymous credentials — partially blocked.** PQ signature blinding is behind field-wide (task #67), so
  "prove you are a member without saying which member" is limited to what threshold constructions give.

---

## 5. Identity: many accounts, and the isolation that makes them real

A FANOS identity is a key; the coordinate is `MapToPoint(VRF(sk, node‖epoch‖beacon))`, so an account **is** a
keypair and a seat is derived from it. Multiple accounts are therefore free to create — and that is exactly
where products go wrong, because creation is not the hard part.

> **Two accounts are unlinkable only if they never share a circuit, a guard, a timing pattern, or a
> reconnection.** Unlinkability is a transport property, not a UI property.

So the application enforces isolation *below* the account switcher:

* each active account gets **its own circuit set and its own cover schedule** — the honest cost is that `N`
  simultaneously-online accounts cost `N ×` cover traffic, and the UI states it;
* accounts are **never online simultaneously by default**, because simultaneity is the strongest correlator
  there is; going multi-online is an explicit choice with the cost shown;
* an account is **ephemeral by default** — no ONOMA name, no persistent coordinate beyond the epoch. Taking a
  `.fanos` name is the moment linkability is accepted, and it is a purchase, so it is already a deliberate
  act.

**The mobile problem, and the derived answer.** No mobile OS will run a node continuously in the background,
so a phone cannot be a full cell member. The answer already exists as a subsystem: **the phone leases a
threshold hosting line** (`fanos-calypso`) — `t`-of-`q+1`, dealt and sealed — which holds its dead-drop while
the device sleeps. That is presence without a trusted server, and it is the one architecturally honest answer
to a problem every competitor solves with a company.

**Push notifications are refused.** APNs and FCM see every notification's timing and its recipient; routing
through them would hand the strongest metadata channel in the product to two companies. Instead the client
polls its leased dead-drop **on a constant-rate cover schedule**, so polling reveals nothing — the traffic is
the same whether there is mail or not. The cost is battery, it is measurable, and it is stated. This is the
single most consequential UX-versus-privacy trade in the whole design and it should be decided explicitly
rather than by default.

---

## 6. Names, value, and shops are the same room mechanism

* **Names** — ONOMA (`.fanos`, labels ≤ 63 bytes, ≤ 32 labels) with zone delegation. A name is a
  registration signed by its owner; buying one is an effect.
* **Value** — OBOLOS, with the shielded path gated as above. HERMES gives PQ hash-locked atomic swaps for
  cross-chain, already live on the ledger.
* **Storage** — THESAUROS deals: a provider is paid per passing audit, and a silent provider now releases the
  consumer's escrow after `λ` silent periods (`abandonment_threshold`) rather than at term end.
* **Shops** — *not a separate surface*. A shop is a room whose state machine holds listings; a purchase is
  `Bid` → `Settle` and the scheduler makes it atomic. Unifying the shop with the room is what stops the
  marketplace from becoming the one centralised, censorable, KYC-shaped part of the product.

---

## 7. The client stack

Requirements, in the order they constrain the choice:

1. embed the existing Rust node (the C ABI exists: `fanos-ffi`, full lifecycle/storage/streams/hosting);
2. one rendering pipeline, or the "unified design" is aspirational;
3. desktop **and** mobile from one codebase, without an Electron-class footprint;
4. no third-party push, no third-party analytics, no remote config — every one is a metadata channel.

| option | verdict |
|---|---|
| native per platform (SwiftUI / Compose / GTK) | best fidelity, ~3× the UI work, and three chances for the privacy rules to diverge |
| Tauri | good desktop story; mobile is young, and the webview is a fingerprinting surface |
| React Native / Electron | the bridge to a Rust node is the worst of the options, and Electron's footprint contradicts running a node beside it |
| **Rust core + Flutter** | **recommended** |

**Rust core + Flutter**, because it is the only option that satisfies (2) and (3) together: one Impeller
pipeline on all five targets, `flutter_rust_bridge` for typed async FFI onto the ABI that already exists, and
no webview to fingerprint. The cost is honest — Dart is a second language in the tree, and the FFI boundary
must be treated as a real seam with its own conformance vectors, exactly as `fanos-ffi` already does for C.

**The rule that matters more than the framework:** the privacy classes of §4 live in the **Rust core**, not in
the UI. The shell may only *display* a class it was given. A UI that could compute a class could get it
wrong, and a UI that could override one would eventually be asked to.

---

## 8. What to build first, and why in this order

1. **The room state machine over ERGON** (§3) — it is the primitive everything else is a case of, and it is
   the first live consumer of an execution model that currently has none.
2. **Ω0 and Ω2 end to end** — feed and rooms, on mechanisms already proven over real QUIC.
3. **The class discontinuity** (§4) — the retire-and-recreate rule, before there is history to mis-migrate.
4. **Account isolation** (§5) — circuits and cover, before multi-account exists to be linked.
5. **Wallet, transparent only** — with the ledger-visible warning in the UI, not in a document.
6. **Ω1 and Ω3** — gated on a deployment above the default plane, and refused with an explanation below it.

Everything in 1–5 is buildable on what exists. Item 6 is buildable but must not be *claimed* at demo scale,
and the strongest thing this design can do for the platform's honesty is make that refusal a feature of the
client rather than a footnote in a document.
