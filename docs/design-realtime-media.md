# Real-time media, and the network beneath it

**Status: design, 2026-08-05. Nothing here is built.** Companion to `docs/design-application.md`, which
defines the hop dial (§4) and the privacy classes (§4a) this document is organised around.

Controlling every layer is the reason this can be done well — the codec, the transport, the placement and the
anonymity substrate are normally four organisations with four incentives. It is also the reason it must be
done honestly, because there is no vendor to blame for a trade-off that was made here.

---

## 1. The derivation that constrains everything else

**Conversational latency is a fixed human constant, and threshold anonymity is a quorum round per hop. They
do not compose.**

ITU-T G.114 is the reference: one-way mouth-to-ear ≤ **150 ms** preserves natural conversation, 150–400 ms is
tolerable with visible turn-taking damage, and beyond 400 ms speakers begin to collide. That budget is not
negotiable by engineering; it is a property of people.

Now count what a full-anonymity path costs. A threshold onion hop is **not a forward** — it is a gather: the packet
reaches a line, `t = ⌈2(q+1)/3⌉` of its `q+1` members compute partial decryptions, and a combiner waits for
`t` of them before anything moves. So each hop is at least one intra-line round trip, and the hop completes
on the **slowest of `t` responders**, not the average.

That second part is what kills it, and it is worth being precise: the per-hop delay is an order statistic,
so its *tail* grows with `t` even when its mean does not. A jitter buffer must be sized to the tail. Three
hops of `max`-of-`t` compose into a distribution whose 99th percentile is far above three times the median —
and audio is judged at the tail, because one late frame is an audible gap.

> **Therefore: conversational voice and video cannot ride the threshold mixnet.** Not "is slow on" —
> cannot. Any design that claims otherwise is either not using the mixnet or not conversational.

**This must be measured, not asserted.** The platform has the instrument: `fanos-sim` is a high-fidelity
simulator whose only difference from production is the transport, and the gather deadline is already measured
there (RFC 6298 over completed gathers). The number to obtain is the per-hop delay *distribution* at each
plane order, and the deliverable is a table of `(q, hops) → p50 / p99 one-way`, against the 150 ms line. Until
that exists this section states a structural argument, and structural arguments have been wrong here before.

---

## 2. What is actually possible, per setting

Read this against the hop dial of `design-application.md` §4: **encryption is on at every row**, including
the fastest. What the rows differ in is who can learn that a call happened.

| `h` | signalling | media | conversational? | what the user is told |
|---|---|---|---|---|
| **0** | open | direct peer-to-peer | yes | "encrypted; the other party sees your address" |
| **1** | mixnet | **relayed by a rotating line** | yes | "encrypted; neither of you learns the other's address" |
| **2+** | mixnet | — | **no** | "anonymous voice is asynchronous, not a call" |

The middle row is the one that matters, and note what it is: **the signalling is dialled all the way up while
the media is dialled down.** They are separate channels with opposite requirements, so they get separate
settings — which is only expressible because the dial is per-channel rather than per-app.

### The `h = 1` design, which is the one that matters

The interesting case is the middle, and it decomposes because **signalling and media have opposite
requirements**: signalling is small, rare, and latency-tolerant; media is large, continuous, and latency-bound.
Treating them as one channel is why existing products leak.

* **The introduction is anonymous.** `Offer` / `Answer` are effects on the room's log (§3 of the application
  design), so they ride whatever setting the room has — including the deepest. *Who called whom, and when,* is the
  metadata that matters most, it is small, and it is exactly what the mixnet is good at.
* **The stream is relayed by a line, not a node.** The relay is `q + 1` members chosen by the geometry, and
  it rotates with the epoch. So no single machine sees a whole call, and none of them holds a long-term
  identity for either endpoint — coordinates are VRF-derived per epoch.
* **Neither endpoint learns the other's address.** That is the property Signal buys with a company's TURN
  servers and Matrix does not buy at all.

What this is **not**: it is not sender anonymity. The relay line sees that *some* coordinate is streaming to
*some* coordinate. Calling that anonymity would be the exact dishonesty this design is trying to avoid. It is
**unlinkability to the network and address-privacy between the parties**, which is a real and strong property,
and it should be named as such in the UI.

### Full anonymity without lying: asynchronous voice

Anonymous *conversation* is impossible; anonymous *voice* is not. A recorded 30-second voice note is
latency-tolerant by construction, so it rides the mixnet as ordinary content. This is not a consolation
prize — asynchronous voice is what a large fraction of messenger audio already is, and it is the only form
of it that can be genuinely anonymous. **Push-to-talk** at ~1 s one-way sits between the two and is worth
offering explicitly, because half-duplex tolerates latency that full-duplex cannot.

---

## 3. Codecs

### Audio: Opus is the floor, and a neural codec earns its place for a reason specific to this architecture

**Opus (RFC 6716) is the mandatory baseline** and every endpoint must implement it. 6–510 kbps, frames of
2.5–60 ms, speech and music in one codec, in-band FEC and packet-loss concealment. There is no serious
competitor in the classical regime and there has not been for a decade.

Neural codecs — Lyra v2 (~3.2 kbps), EnCodec, SoundStream — reach intelligible speech at bitrates an order
below Opus's practical floor. In an ordinary messenger they buy little: bandwidth is cheap and the model
costs battery and binary size.

**Here they buy something else, and this is the architecture-specific argument.** Media on a privacy-bearing
path rides inside a **constant-rate cover envelope** — the traffic shape must not vary with what is being
said, or the shape is the message. Cover is paid whether or not it is used. So a codec at 3 kbps instead of
32 kbps does not save bandwidth; it **buys headroom inside a fixed envelope** — more redundancy, more
concealment, or a smaller envelope for the same quality. That is a real reason, and it does not exist for a
product that does not pad.

So: **Opus mandatory; a neural codec negotiated, optional, and never required for interop.** Ship the
baseline that always works, and let the constrained path opt into the model.

### Video: AV1, with an honest fallback

* **AV1** — royalty-free, roughly 30 % better than VP9 and 50 % better than H.264 at equal quality.
  `dav1d` decodes very fast; `SVT-AV1` has viable realtime presets. Hardware **decode** is now common
  (recent Apple, Intel, AMD, Qualcomm); hardware **encode** is still rare.
* **VP9** — the compatibility fallback, widely hardware-accelerated.
* **H.265/HEVC** — refused. Patent-encumbered, and a royalty-bearing codec in a censorship-resistant network
  is a control point by another name.

The honest trade: **mobile encode may fall back** to hardware VP9/H.264 for battery, even though AV1 is the
better codec, because a call that drains a phone is a call nobody makes. State it in the client rather than
pretending the encoder ladder is uniform.

### Scalable coding, mapped onto the geometry

This is where controlling every layer pays. **SVC** (a base layer plus enhancement layers) is normally
selected by a server-side SFU deciding who gets which quality — a single point of both failure and
observation.

Here the relay is a **line**, so layer selection is a threshold decision: no single member decides who sees
what, and no single member can silently degrade one participant. The mapping is direct:

* the **base layer** is replicated to more points — it is what everyone must receive;
* **enhancement layers** go to fewer — they degrade first under loss, by construction rather than by policy.

That is graceful degradation derived from the placement structure rather than implemented as a heuristic.

### Loss: use the erasure code that is already there

The platform's L4 store uses a `[7, 3, 4]` erasure code over the Fano plane. Media loss tolerance wants the
same shape — recover the frame from a subset of what was sent — and using **one mechanism for two purposes**
is worth more than a bespoke media FEC that has to be reasoned about separately. Opus's in-band FEC handles
the ordinary case; the erasure structure handles the bursty case the anonymous path produces.

---

## 4. The transport finding: DIAULOS is the wrong pipe for media, and its window is a hard ceiling

Two things, and the first is a category error worth naming before anyone builds on it.

**(a) Real-time media must not use a reliable ordered stream.** DIAULOS is reliable and ordered. For media
that is precisely wrong: a lost packet blocks everything behind it (head-of-line), and by the time a
retransmission arrives the frame it belongs to is already too late to play. Every serious real-time stack
uses unreliable datagrams with its own concealment for this reason. **The platform needs a datagram path for
media** — QUIC's DATAGRAM extension (RFC 9221) is the natural fit and rides the transport already in use.

**(b) The existing stream window bounds throughput, and the number is small.** `fanos-stream` ships
`DEFAULT_WINDOW = 32` segments of `MAX_SEGMENT = 1024` bytes — **32 KiB in flight**. Throughput on a windowed
protocol is bandwidth-delay-limited at `window / RTT`:

| RTT | ceiling | what fits |
|---|---|---|
| 50 ms | 5.2 Mbps | 1080p30 AV1 realtime, just |
| 100 ms | 2.6 Mbps | 720p30 |
| 200 ms | 1.3 Mbps | 360p, or audio only |
| 400 ms | 0.65 Mbps | audio only |

The window was sized for interactive request/response, where 32 KiB is generous. It is the binding constraint
on video above ~50 ms RTT, and it is a constant with no derivation attached — the same shape `docs/audit.md`
keeps finding. **It should be derived from a stated bandwidth-delay target, exactly as `MAX_STORE_ENTRIES` is
now derived from a memory budget**, rather than raised to whatever makes a demo work.

---

## 5. Caching and placement

### The placement problem is already solved, and should not be re-solved

A key's shard homes **are** its digest's points. There is no cache-placement algorithm to choose, no
consistent-hashing ring to tune, no rendezvous-hashing comparison to run — the geometry assigns it. The
comparison against HRW and stratified topologies has been run (`docs/audit.md`), so this is measured rather
than assumed.

### Cache admission is a function of the privacy class, and that is a rule, not a policy

A CDN caches everything it relays. Here that is a leak: **what a relay retains is evidence of what passed
through it.**

| class | cacheable by a relay? | why |
|---|---|---|
| **Ω0** | yes, aggressively | the content is public; retaining it reveals nothing that reading it did not |
| **Ω1** | content yes, **provenance no** | the content is public, the author is not — a cache entry must not record where it came from |
| **Ω2** | no | a relay caching room content becomes an offline-searchable record of the room |
| **Ω3** | never | the whole class is that the host learns nothing; a cache is learning |

This is derived rather than chosen: the class *states* what the host may learn, and a cache is a thing the
host learns. It should be enforced at admission — a relay that cannot tell the class of what it holds will
cache it — which means the class must travel with the object, not with the request.

### Multicast is free, and this is the one place the geometry is simply better

A live stream to many receivers is normally a tree-building problem: ALM, application-layer multicast,
overlay trees, and a protocol to maintain them under churn.

`PG(2, q)` has **diameter 2** — any two points lie on a common line — so a cell-wide broadcast is **two hops**
with no tree to build and no state to maintain. A publisher sends to its `q + 1` lines; each member forwards
along its own. Under churn there is nothing to repair, because there was never a tree: the structure *is* the
routing.

At `q = 31` that is 993 receivers in two hops. It is the strongest throughput property the architecture has,
and it is worth building the live-streaming path around rather than treating streams as large files.

---

## 6. What to measure before building

In this order, because each answer changes the next design:

1. **The per-hop threshold-gather delay distribution**, per plane order, in `fanos-sim` — `p50` and `p99`
   one-way against the 150 ms line. This decides §1 as a measurement rather than an argument.
2. **The window/RTT ceiling against a real encoder ladder** — confirm the table in §4 with SVT-AV1 realtime
   output rather than nominal bitrates.
3. **Cover-envelope headroom** — how much redundancy a 3 kbps neural codec actually buys inside a fixed
   envelope versus Opus at 32 kbps. This decides whether the neural path is worth its battery and binary.
4. **Two-hop multicast fan-out under churn** at `q = 7` and `q = 31` — the claim in §5 is structural and the
   loss behaviour is not.

Nothing in §§2–5 should be built before (1), because if the gather tail is worse than this document assumes,
the Ω2 relay design is the *only* call design and the effort belongs there entirely.
