# Where Verum changes FANOS's architecture, not just its front end

**Status:** exploration, 2026-07-30. Four proposals, each with an honest scope and a first slice small enough to be an
experiment rather than a commitment. Two of them change what the platform *is*; two are alignments worth knowing about.

The brief was to take Verum's architecture seriously and look for a qualitative rethink. The most useful thing I found is
not a feature to adopt — it is a **conflation in our own design docs** that Verum's existence exposes (§1).

---

## 1. `Prove` is blocked on ZK recursion — but only for privacy. Correctness needs a *proof*, not a ZK proof.

`docs/design-ergon.md` §5c states the honest gate on unbounded expressiveness:

> The PQ-ZK stack's proofs are currently far too large to gossip (`docs/design-obolos-zk.md`: 145 MiB at tree depth 1),
> and recursion is the sole blocker. So `Prove` is specified and type-checked now, and becomes *practical* exactly when
> recursive compaction lands.

That sentence is true about **privacy** and false about **correctness**, and the difference has been invisible because
OBOLOS needed both at once. A shielded spend must prove "value is conserved" *without revealing which note* — that is
zero-knowledge, and ZK is what costs 145 MiB. A public contract asserting "given this read-set, these writes follow" needs
no secrecy at all. It needs a **checkable proof**, and a proof term is one.

Verum already produces those and already ships a checker: `crates/verum_kernel` is an LCF-style kernel that is the *sole
trusted checker* in its stack — the elaborator, the 22 tactics, the SMT backends and the cubical evaluator all emit terms
in the kernel's `CoreTerm` language and the kernel validates them. So the architecture ERGON's §5 wants exists today for
the non-private half of the problem:

- **Two evidence regimes, both live.** §0 of the design already says a transaction is "a claim about a state transition,
  accompanied by evidence — either a bounded total term a validator re-executes, or a proof it verifies." The second
  regime has been inert. It need not be: `Claim { kind: PROOF_TERM }` verified by a kernel is that regime, available now.
- **Unbounded expressiveness at O(check) cost.** A contract whose logic is too heavy to re-execute — a large sort, an
  optimisation, an iteration over a big structure — ships the proof instead. This is exactly §5c's promise, arriving
  years before recursive ZK.
- **ZK remains for privacy only**, which is what it is uniquely good at, and OBOLOS keeps it.

**What it costs, stated plainly, because this is the part that decides it.** The chain's trusted computing base grows by
the kernel. That is a real and well-understood trade — it is how Coq and HOL are trusted, and everything expensive stays
outside: a hostile compiler, a wrong tactic and a buggy SMT solver all produce terms the kernel rejects. But the price is
the kernel's *size*, and here the measurement matters:

| | lines |
|---|---|
| the kernel's own stated target ("audit-able by a single reviewer in one session") | **< 5 000** |
| `crates/verum_kernel/src`, all `.rs` | 70 614 |
| same, excluding comments and blank lines | **≈ 44 405** (79 files) |

Nine times its own budget. A 5 000-line checker inside a consensus TCB is a proportionate price for unbounded verified
expressiveness; a 44 000-line one is not obviously so, and "auditable in one session" is the property that would make it
so. This is not a reason to abandon the idea — it is the idea's **gating condition**, and it converts a vague aspiration
("the kernel should be small") into a concrete deliverable with a customer. Filed as G9 in
`docs/verum-contract-requirements.md`.

**MEASURED THE SAME DAY, AND IT MOVES THE GATING CONDITION.** The first slice was to measure a certificate's size and
check time. There is nothing to measure: **no certificate can be produced today.**

`verum elaborate-proof` runs and emits only `verification-surface.json` — zero `.vproof` files — for every input tried:

| input | result |
|---|---|
| four FANOS-shaped theorems (value conservation, no-debt, the Fano quorum, quorum intersection), `proof by auto` | `skipped — unsupported tactic form: Auto` ×4 |
| `proof by rfl` | `skipped — unsupported tactic form: Named` |
| `proof by reflexivity` | `skipped — Reflexivity in empty context — needs a DefinitionalEquality witness` |
| **Verum's own kernel-bootstrap lemma** `core/verify/kernel_v0/lemmas/beta.vr` | `skipped — apply target mathlib4.lambda.ChurchRosser is neither a local binder nor a registered axiom` |

The reason is exact and sits at `crates/verum_kernel/src/tactic_elaborator.rs:583-653`. The elaborator handles `Apply`,
`Reflexivity`, `Exact`, `Intro`, `Seq` — explicit proof terms — and rejects **all** of the automation: `Auto`, `Smt`,
`Omega`, `Ring`, `Field`, `Simp`, `Rewrite`, `Blast`, `Split`, `Trivial`, `Assumption`. And `Reflexivity` is a "stand-in"
by its own comment, which is why it fails even on `k == k`.

So the real gating condition is **SMT proof reconstruction**, not the kernel's size. A contract's obligations are
arithmetic — conservation, no-underflow, a bound — and arithmetic is exactly what `Smt`/`Auto` discharge and exactly what
does not become a certificate. Bridging "the solver says true" to "the kernel has a term" is the well-known hard problem
(SMTCoq, veriT proof output), and it is a piece of work in Verum, not a configuration we were missing.

**This corrects the paragraph above, one turn after writing it.** The kernel's 9×-over-budget size (G9) is a real finding
and still the price of the trade — but it is the *second* obstacle, and I ranked it first because I reasoned about the
architecture instead of running it. The order of the two matters: shrinking the kernel would not produce a single
certificate, while making one tactic elaborate would produce the first.

**Revised first slice**, and it is now Verum's rather than ours: make **one** arithmetic obligation elaborate end to end —
`verum elaborate-proof` emitting a `.vproof` that `verum check-proof` accepts. Then the measurement I wanted (size, check
time) becomes possible, and §1 either lives or dies on data. Filed as G10.

Kept as the standing discipline, because it worked here within the hour: **measure before believing.** The 145 MiB number
is what that bought last time; this is what it bought today.

---

## 2. One artefact for the simulator and for production

**The standing directive** is that the simulator must differ from production *only in transport*, and the measured gap has
always been the same one: node **composition** is never simulated. This session paid for that gap three times — the DA
body wedge reproduced only over real QUIC; the majority-short scenario passes deterministically in the simulator and fails
live; and a sim-green test needed `deaf_propose` added before it exercised the mechanism it was written for.

The gap is structural: sim and prod are **two Rust code paths** kept in step by discipline. Discipline is exactly what
fails silently.

Verum's headline runtime property is *"a single bytecode IR that runs under both interpreter and AOT native"*. If node
logic were Verum, the simulator would run the identical compiled artefact under the interpreter — deterministic, virtual
clock, single-threaded, adversarial scheduler — and production would run it AOT native. The sim/prod gap would then be
closed **by construction** rather than by review, and "the simulator does not reproduce production" would become a
statement about the transport only, which is what the directive says it should be.

**Honest scope.** Porting the node to Verum is enormous and not proposed. But the platform's engines are *already*
sans-I/O pure state machines — `ConsensusEngine`, `Sampler`, `fanos-ergon` — which is precisely what an interpreter can
run deterministically.

**First slice:** port **one** engine (`Sampler` is the smallest with real behaviour) to Verum, run it under the
interpreter inside `fanos-sim` and AOT in the node, and answer one question: *does a defect injected into the engine show
up identically in both?* If yes, the approach is proven on a small surface and the question becomes how far to take it. If
no, we learn why for the price of one small crate.

This is the highest-leverage idea in this document, because the sim/prod gap is the single largest recurring cost in the
project's own history.

---

## 3. Derived constants as refinement types, so drift is a compile error

The platform is built on derived constants: `f = ⌊(n−1)/3⌋`, `Q = ⌈(n+f+1)/2⌉`, `t = ⌈2(q+1)/3⌉`, `D_MAX = 3`,
`MIN_SHARDS = N − 3`, the equicorrelated closed forms in `fanos-diakrisis::minima`. Each is *proved* in a document and
*re-stated* in Rust, and nothing but a test connects the two.

That gap has already cost a HIGH. Audit E7: `MIX_THRESHOLD` was a derived quantity written down as `const … = 2`, correct
at `q = 2` and silently wrong at every larger plane — for months, found by accident. `t = ⌈2(q+1)/3⌉` *evaluates* to 2 at
`q = 2`, so the constant was not wrong when written; it was wrong the moment the plane order became a variable and nothing
noticed, because a `usize` has no relationship to its derivation.

A refinement type has one. `CellParams { n: Int, f: Int { self == (n-1)/3 }, quorum: Int { self == (n+f+1)/2 } }` cannot
hold a drifted value: the SMT obligation fails and the build fails. The class of defect becomes unrepresentable rather
than tested-for.

**First slice:** port `minima.rs`'s closed forms and `CellParams::derive` to Verum as the **reference**, and have CI check
the Rust constants against the Verum artefact. The Rust stays as the implementation; the Verum becomes the specification
that can *fail*. That is strictly better than a doc, and cheaper than a rewrite.

---

## 4. Two structural alignments worth knowing, not yet worth building

**Supervision trees are the recursion of cells.** Verum ships OTP-style supervision —
`OneForOne` / `OneForAll` / `RestForOne`, `Permanent` / `Transient` / `Temporary`, `RestartIntensity`, and **escalation to
the parent supervisor**. FANOS's recovery ladder is hand-rolled (stall detector → `recovery_decision` → `rebootstrap` →
escalate), and §L1's hierarchy escalates a cell's failure *to its parent cell*. Escalation-to-parent-supervisor and
escalation-to-parent-cell are the same shape at two scales, and `RestartIntensity` is the missing piece of our ladder —
we have thresholds for *when* to recover and none for *how often before giving up*, which is exactly the flapping case an
intensity limit exists for. Worth stealing the concept even without adopting the runtime.

**CBGR capabilities and ERGON footprints are the same idea at different granularities.** Verum's eight capability bits
(`READ`/`WRITE`/`EXECUTE`/`DELEGATE`/`REVOKE`/`BORROWED`/`MUTABLE`/`NO_ESCAPE`) with generation-based use-after-free
detection, and `fanos_ergon::Confined` refusing an access outside a derived footprint, are both "authority is what you
hold, not what you claim". Aligning the vocabulary would make the emitter's lowering read as a translation rather than an
invention. Low cost, modest payoff — do it when the emitter lands, not before.

---

## 5. What I would do in what order

1. ~~**§1's first slice** — measure a proof term's size and check time.~~ **Done, and it returned "not yet possible"**
   (§1). The measurement is now blocked on G10, which is Verum's work: one arithmetic obligation elaborating to a
   certificate the kernel accepts. Nothing on our side to do until then, which is exactly the value of having measured it
   first — we would otherwise have designed `Claim` kinds around a pipeline with an empty success path.
2. **§3's first slice** — the derivation as a failing specification. Small, and it retires a class of defect that has
   already cost a HIGH.
3. **§2's first slice** — one engine under both runtimes. Larger, and the payoff is the project's most persistent cost.
4. **§4** — take `RestartIntensity` into the recovery ladder now; leave the rest.

And the discipline that applies to all four, learned the hard way this session: **a mechanism that cannot fail in a test
has not been tested.** Every slice above must come with the negative case — a proof that does not check, a drifted
constant, an injected defect the interpreter must also see — or it will report success without having been exercised.
