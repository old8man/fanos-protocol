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

Policy splits once more, and the split has teeth. A **published contract** — policy that third parties have
been told and now depend on — carries an obligation the others do not: it must be *honoured*, not merely
justified, and it therefore **cannot adapt**. `STORE_TIMEOUT` is one: its own doc says "public because it is a
contract an embedder needs; the C ABI's `fanos_lookup`/`fanos_publish` bound themselves by it, and a foreign
caller has no other way to know that a store call returns." A measured estimator in its place would be a
better *number* and a broken *promise*.

The consequence worth knowing before deriving anything from one: **a contract bounds the worst supported
deployment, an estimator tracks the typical one.** So a contract is the right base for a *duty-cycle* bound and
the wrong base for a *latency-tracking* one. `ROSTER_REFRESH = 3 × STORE_TIMEOUT` is the right use, and says
so — "one assignment costs up to one `STORE_TIMEOUT`, so a 3× period bounds the refresh at a 1/3 duty cycle."
Reading that as "three times how long a store read takes" would be the category error, and would make the
constant look absurdly conservative rather than exactly right.

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

The sharpest instance is #46, and it is worth reading for how it turned out rather than only for the finding.
`RENDEZVOUS_TICK = 250 ms` is documented as "paced to the mixnet's effective round trip" — a round trip
`GatherClock` now measures at 25 ms idle and **4.0 s under load**. Chasing that turned up a real defect one
layer down: `ClientSession::poll_payloads` resent the `ClientHello` on *every* poll with no backoff, so a dial
put ~16 hello onions into the mixnet per actual round trip, each arming a fresh gather. Fixed, with an
exponential backoff.

**But I predicted it would explain the wedge in #38, and it did not** — the autopsy still wedges with the
backoff in. Recorded here because the roots problem is real *and* a plausible chain from a plucked root to an
observed symptom is not evidence: the flood existed, was worth fixing, and was a different defect. Deriving
`RENDEZVOUS_TICK` from the clock remains right, but as a tuning improvement to be measured, not as a suspect.

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

## 6. Pass A, completed 2026-08-03 — the unbounded-collection sweep

Pass A asks which constants are consensus-critical. Following one that **admitted it could not be derived**
turned it into a different and more productive question. `DEFERRAL_CAP`'s doc says: *"the natural derivation is
'as many transactions as can be pending at once', and that quantity is currently unbounded because the mempool
has no cap of its own."* So the question became: **which collections fed by remote input have no bound?**

Three found, each a remote memory exhaustion by an *authenticated* peer — audit B1's shape, which had been
fixed in one place and not looked for elsewhere:

| Collection | Defect | Rule adopted |
|---|---|---|
| TAXIS `mempool` | No cap at all; dedup was a linear scan, so `N` admissions cost `O(N²)`. `valid_seal` cannot help — the keyper line's keys are public, so anyone can mint distinct valid seals. | **Refuse** at the bound |
| TAXIS `exec_votes` | Never pruned — a leak with **no adversary**, growing with chain height forever; and `on_exec_vote` applies no height bound, so a Byzantine member forges heights. | Evict the **lowest** height |
| Beacon `pending` | Each bucket capped, the **number of buckets** unbounded; a share holder can evaluate at any epoch, so a member floods with valid partials. | Evict the **highest** epoch |

**The three eviction rules are different, and that is the finding.** A single house policy would have been wrong
twice:

- the mempool is *encrypted* — fee and sender are invisible before reveal, so every candidate ordering
  (arrival, the commitment) is attacker-controlled and there is **no honest ordering to evict by**. Refusing
  has no victim to choose wrongly.
- `exec_votes` is ordered by a **monotone** checkpoint, so low heights stop mattering first and a far-ahead
  certificate is exactly what a lagging validator needs.
- beacon epochs are adopted **in order**, so the *nearest* future epoch is the only one that can assemble next
  and far-future buckets are precisely what an attacker fills memory with.

**The rule follows from the ordering the data actually has.** That is the reusable lesson, not the caps.

### What the sweep found already correct

Recorded so the pass is re-runnable and its coverage is legible, not just its findings:

- **`fanos-runtime`** — every map (`peers`, `attested`, `witnessed`, `reroute`, `activity`, `loss_reports`) is
  keyed by *coordinate*, so the plane's `q²+q+1` points bound them structurally. The nicest kind of bound:
  nothing to enforce.
- **`fanos-angelos`** — the double ratchet is properly capped in all three places a skipped-key DoS lives:
  `MAX_SKIP_PER_MESSAGE`, `MAX_SKIPPED_STORED`, `MAX_PAST_EPOCHS`, and the doc cites Signal's `MAX_SKIP`.
- **`fanos-aphantos`** — `MAX_PENDING`, `MAX_CANDIDATES`, `MAX_RESOLVED`.
- **`fanos-keygen`** reshare generations — `MAX_RESHARE_GENS`, oldest evicted.
- **`fanos-node`** relay — `registrations` and `hosts` are `BoundedMap`.
- **Not attack surfaces** — `fanos-onoma`'s registries are operator-populated, `fanos-thesauros`'s chunk
  vectors are per-object.

## 7. Pass C's first slice — and a naming hazard

Two constants named **`FROZEN_SPAN`** exist, in two harnesses, derived from different roots and meaning
different things:

- `fanos-node/tests/common` — `2 × ROUND_TIMEOUT_MAX` (48 s), the patience for a *consensus*-driven wait;
- `fanos-sim/fabric` — `2 × ROSTER_REFRESH` (30 s), the patience for a *role-assignment* wait.

Both are individually well derived. Together they are a trap: a reader who learns one and meets the other will
carry the wrong number, and neither name says which span it is. Same name, different quantity, no way to tell
from the call site. Worth renaming to what each actually bounds.

## 8. Pass C, 2026-08-03 — timing, and a shape that is not a wrong number

Pass C found almost no wrong values. It found **relationships that were described rather than held**, which
is the failure mode a timing tree is actually prone to: every constant correct today, and nothing keeping them
correct together.

| Was | Now |
|---|---|
| `ROUND_TIMEOUT_BASE = 1_500` ms, doc: "comfortably longer than a tick" | `TICK_PERIOD × ROUND_TIMEOUT_TICKS` — same value, and doubling the tick can no longer turn "comfortably" into "marginally" while the prose still says otherwise |
| `ROUND_TIMEOUT_MAX = 24` s, doc: "doubles up to this ceiling" | `ROUND_TIMEOUT_BASE << ROUND_TIMEOUT_DOUBLINGS` — the ladder lands on its ceiling exactly, instead of a final step shorter than the one before it |
| `ROUND_TIMEOUT_TICKS = 10`, chosen | `ROUND_PHASES + ROUND_TIMEOUT_SLACK` — the part the protocol requires, plus the part that is judgement, so a reader can tell which is which |
| Backoff doc: "~22 attempts inside a 180 s give-up" | **27** at the anonymous tick, **286** at the Direct one, both measured by driving the real session |

Three lessons, and they are the transferable part:

1. **A relationship a doc describes is one that drifts; one it computes cannot.** Prose asserting "comfortably
   longer" survives exactly until someone edits the other constant.
2. **A number a comment works out by hand is a number nobody re-works out.** The "~22" was wrong, and the
   spread between profiles — tenfold — was not merely unknown but unsuspected.
3. **Assert the reason, not the value.** The ladder's test caught *me* demanding the ceiling clear
   `ROUND_TIMEOUT_TICKS × 4 s` when a round's cost is proportional to `ROUND_PHASES`, not to the tick count
   that already carries margin. The constant was right and my reasoning was not; only naming the two
   quantities apart made the error visible.

And one refinement to the taxonomy, from `STORE_TIMEOUT`: a **published contract** is policy that third
parties depend on, so it must be *honoured* rather than merely justified, and it cannot adapt. It bounds the
worst supported deployment where an estimator tracks the typical one — which makes it the right base for a
duty-cycle derivation (`ROSTER_REFRESH = 3 × STORE_TIMEOUT`, correctly) and the wrong base for a
latency-tracking one.

**Still open in Pass C:** `TICK` (20 ms) and `TICK_PERIOD` (150 ms) remain roots with descriptions but no
derivation, and `RENDEZVOUS_TICK` (250 ms) is the one the `GatherClock` could plausibly derive (#46).

## 9. Applying it

Highest risk first; do not sweep 811 entries blindly.

1. **Consensus-critical** — anything two nodes must agree on. Divergence here is a fork, not a slowdown.
2. **Security bounds** — difficulty, window widths, quorum sizes, key lifetimes.
3. **Timing and capacity** — every `Duration`, every `MAX_*`. The default expectation is kind 3; a `Duration`
   that is *not* backed by an estimator owes a reason why not.
4. **The rest**, which should be almost entirely kind 1.

Tracked as #45.
