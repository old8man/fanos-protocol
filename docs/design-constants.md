# Every constant declares its kind (design)

> Status: **standing rule.** A number with no recorded reason is a number nobody can safely change — not the
> author six months on, not a reviewer, not an operator tuning a deployment. This file says what a constant
> must carry to exist in FANOS.
>
> Measured 2026-08-03: **811 numeric `const` declarations across the workspace, roughly 121 with any
> derivation recorded near them.**

## 1. Why "remove the hardcodes" is the wrong instruction

Most of those 811 are correct and should stay. A wire tag is a number; so is a field length, a domain label's
size, the order of a field. Demanding a derivation for `TAG_ONION = 0x03` produces ceremony, not safety.

The failures this codebase has actually suffered came from a different place: a number that *looked*
definitional while being an environmental guess. `ATTEMPT_PATIENCE` abandoned live paths because 3.75 s was a
reasonable-sounding figure for a distribution whose tail reaches 15 s. The gather deadline could not widen
because its estimator only ever saw samples that beat it. `MIX_THRESHOLD` was `2` on every plane until it was
made `⌈2(q+1)/3⌉`. In each case the defect was not that a number existed — it was that **nobody could tell
what kind of number it was**.

So the rule is not "derive everything". It is: **declare the kind, and meet that kind's obligation.**

## 2. The four kinds

| Kind | What it is | Obligation |
|---|---|---|
| **Definitional** | A name for a fixed fact: a wire tag, a field length, a label, an array size fixed by a format. | None beyond a doc line saying what it names. Changing it is a format change, and that is obvious from the name. |
| **Derived** | Follows from a theorem, a structure, or another constant. | **Show the derivation** in the doc comment, in enough detail that a reader can check it. A derived constant whose derivation is not written is an undeclared guess. |
| **Measured** | Its correct value depends on the environment it runs in. | **It must not be a constant.** It must be an estimator over observation; a constant may survive only as a *bound* on that estimator, and the bound needs its own derivation. |
| **Policy** | A genuine operator input — a target, a horizon, a budget. | Named as policy, documented in the form an operator can reason about, and **few**. If there are many, most are misclassified. |

**A constant that cannot be classified is itself the finding.** That is the useful output of applying this
rule: not the reclassification, but the ones that resist it.

## 3. Worked examples, from this repo

- **Definitional.** `HYBRID_VK_LEN`, `TAG_ONION`, `MAX_SKEW_TAG`. Nothing to derive.
- **Derived, well.** `t = ⌈2(q+1)/3⌉` — the mixing threshold from the plane's own BFT ratio, evaluating to the
  shipped `2` at `q = 2` with a test that also fails at `t − 1`. `m = min(f+1, ⌈log H / log(n/f)⌉)` — meeting
  points, the cheaper of a pigeonhole and an unpredictability bound. `REPLAY_WINDOW = 64` — widening never
  admits a replay and state cost is flat to the machine word, so the width belongs at the structural limit;
  RFC 3711 agreeing is corroboration, not the reason.
- **Measured, done right.** `GatherClock::deadline()` — `SRTT + 4·RTTVAR`, RFC 6298, from completed gathers
  *and* (since the censored-sampling fix) from shares that arrive after the deadline. `MIN_/MAX_GATHER_DEADLINE`
  survive as bounds.
- **Policy.** `CENSORSHIP_HORIZON_EPOCHS = 2²⁰` — "at most one censored epoch in this many", ≈120 years hourly.
  One input, in a form an operator can argue about, everything else derived from it.
- **Still wrong.** `HANDSHAKE_GIVE_UP = 180 s`, `STORE_TIMEOUT = 5 s`, `RENDEZVOUS_TICK = 250 ms`. All kind 3
  wearing kind 1's clothes.

## 4. The roots problem

Deriving one constant from another is only as good as what the chain bottoms out in. FANOS's timing constants
form a tidy tree — `ROSTER_REFRESH = 3 × STORE_TIMEOUT`, `FROZEN_SPAN = 2 × ROSTER_REFRESH`,
`HEDGE_DELAY = RENDEZVOUS_TICK × GIVE_UP_ATTEMPTS` — standing on about six roots that are bare numbers.

**Fix roots, not leaves.** A derived leaf inherits its root's error and hides it behind arithmetic that looks
principled.

The sharpest instance is tracked as task #46. `RENDEZVOUS_TICK = 250 ms` is documented as "paced to the
mixnet's effective round trip" — and that round trip is no longer unknown, because `GatherClock` measures it:
25 ms on an idle host, **4.0 s under load**. Under load the client therefore retransmits ~16× faster than a
gather completes, and every retransmit arms a fresh gather. That is a multiplying flood at exactly the moment
the mixnet cannot absorb it, and it fits every symptom of the wedge in #38.

## 5. What the rule found, applied to `t`

`t = ⌈2(q+1)/3⌉` is a **derived** constant and its derivation is written down: the BFT safety ratio. Applying
the rule properly means asking *what else that number decides* — and it decides liveness too, silently.

A gather completes when `t` of `q+1` members answer in time, so what it can afford to lose is
`(q+1) − t = ⌊(q+1)/3⌋`. The ceiling's **rounding** is a liveness tax, and it falls unevenly. Per-gather
success with each member answering in time with probability `r = 0.90`:

```
 q=2   3 members, spare 1   0.9720
 q=3   4 members, spare 1   0.9477   ← worse than Fano
 q=4   5 members, spare 1   0.9185   ← worse still
 q=5   6 members, spare 2   0.9842
 q=8   9 members, spare 3   0.9917
 q=31 32 members, spare 10  0.9998
```

More members with the same spare is strictly worse: more ways to lose, no more slack. The tax is zero exactly
when `3 | (q+1)`, i.e. **`q ≡ 2 (mod 3)`** — the family `2, 5, 8, 11, 14, …`. The shipped Fano cell is its
smallest member, so the base cell is defensible on liveness grounds and not only on tradition, and the
sensible step up is `q = 5` or `q = 8`, never `q = 3` or `q = 4`.

That inverts the naive reading of the geometry ("a bigger plane is more robust"), which is why it is an
asserted test (`node.rs`) and not a paragraph. It is also the clearest example of what this rule is *for*: the
constant was already derived, already documented, already correct — and still had an unexamined consequence
that changes which planes we would deploy.

## 6. Applying it

Highest risk first; do not sweep 811 entries blindly.

1. **Consensus-critical** — anything two nodes must agree on. Divergence here is a fork, not a slowdown.
2. **Security bounds** — difficulty, window widths, quorum sizes, key lifetimes.
3. **Timing and capacity** — every `Duration`, every `MAX_*`. The default expectation is kind 3; a `Duration`
   that is *not* backed by an estimator owes a reason why not.
4. **The rest**, which should be almost entirely kind 1.

Tracked as #45.
