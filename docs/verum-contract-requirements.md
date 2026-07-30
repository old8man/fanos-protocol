# Verum → ERGON: what FANOS needs from the language, and the gaps found

**Audience:** whoever works on Verum next. This is a request list with evidence, not a critique — every gap below is
something FANOS depends on, with a file:line for what exists today and an acceptance criterion for what "done" means.

**Author's disclosure of scope.** I read `grammar/verum.ebnf` selectively (top-level productions, capabilities, contexts,
loop annotations, verification strategies), `README.md`, the docs index, and grepped the 26 crates for the specific
mechanisms below. I did **not** run the compiler, read the docs site pages, or inspect the SMT encodings. So every claim
here is either quoted with a location or marked as an open question. Where I say "not wired", it is because the code says
so in a comment — see G1.

**Companion document:** `docs/design-ergon.md` §10a–§10c in the FANOS repo carries the derivation this rests on.

---

## 0. The single most important constraint: the chain does not trust the compiler

Verum is the **front end**, outside the trusted computing base. The chain receives an artefact — a canonically encoded
ERGON term, plus a proof where one is used — and independently:

1. decodes it,
2. type-checks it (`fanos_ergon::well_typed`: depth ≤ `D_MAX = 3`, `Par` branches footprint-disjoint, no empty
   combinators, claims and footprint width within admission limits),
3. **derives the footprint itself** (`Term::footprint`, by structural induction — never read from a declaration),
4. and confines execution to that footprint, faulting on any access outside it.

So a buggy or hostile Verum can produce an artefact the chain **rejects**; it cannot produce one the chain
**mis-schedules**. This is deliberate and it is what lets the front end be arbitrarily sophisticated — SMT, dependent
types, cubical paths, a 22-tactic proof DSL — without any of it entering the chain's TCB. Two consequences for whoever
implements the requests below:

- **You do not need to be trusted, and should not try to be.** Emitting a term the chain will accept is the whole job.
  Nothing you assert about the term is believed.
- **But you must be *reproducible*.** See G8: two compilations of the same source must be byte-identical, or the chain's
  audit trail from source to on-chain code breaks.

FANOS takes **no cargo dependency** on the Verum crates. The `verum` binary emits the artefact; `fanos-ergon` decodes it.
Same shape as our proof system: prover outside, verifier inside.

---

## 1. The target: what an artefact must contain

The IR is `fanos_ergon::Term`, currently:

```text
Term ::= Do(Effect) | Seq([Term]) | Par([Term]) | Gate(Predicate, Term) | Alt([(Predicate, Term)]) | Prove(Claim)
Effect    ::= { kind: u16, footprint: Footprint, external: bool }        -- args being added, see §2
Predicate ::= { kind: u16, reads: [Key] }                                -- expression forms being added, see §2
Claim     ::= { kind: u16, footprint: Footprint, proof_bytes: u32 }
Key       ::= { point: PointId, slot: [u8; 32] }
Footprint ::= { reads: [Key], writes: [Key] }                            -- sorted, deduplicated
```

Hard constraints, none of them negotiable because each is load-bearing somewhere else in the platform:

- **Nesting depth ≤ 3.** Not a resource limit — it is derived (`P_crit^[4] > 1` forecloses a fourth order arithmetically;
  `docs/design-ergon.md` §2). A term nested four deep is *ill-typed*, not expensive.
- **No loops, no recursion.** The term must be bounded and total. This is why G1 and G3 matter: Verum's `decreases`
  measures are how a loop becomes a bounded `Seq`.
- **`Par` branches must be provably footprint-disjoint.** The chain checks this. Emit `Par` only where you can show it;
  `Seq` is always safe.
- **Every state access must be a key known at compile time.** This is the reason FANOS has no VM (`design-ergon.md` §1):
  DROMOS's conflict-DAG scheduler needs footprints *before* execution. A construct whose storage key is computed from
  runtime state cannot be compiled to ERGON at all — it must be rejected in the front end with a clear diagnostic, not
  lowered into something that looks like it works.

**Please do not add a "declared footprint" to the artefact format.** It would be ignored: the chain derives it. Emitting
one would create a second source of truth that can silently disagree.

---

## 2. FANOS-side work in flight (so you can target the right shape)

We are adding to `fanos-ergon`, and the artefact format will include these. Design is settled; implementation is ours.

- `Value` — fixed-width: `Int(u128)` and `Bytes32([u8; 32])`. `u128` for arithmetic headroom over the ledger's `u64`
  quantities (`fanos_dromos::token::TokenLedger::balance -> u64`), with an explicit narrowing fault at the host boundary
  rather than a silent wrap. Anything wider than 32 bytes is addressed by digest, which is what ledger keys already are.
- `Expr` — a **total, depth-bounded** expression layer: literals, `Load(Key)`, instantiation arguments, and checked
  arithmetic / min / max. No recursion, no iteration, no division-by-zero panic (it is a fault). This is what lets an
  author write `transfer(to, balance(from) / 2)` — the smallest thing that turns composition into programming.
- `Effect` and `Predicate` gain **computed arguments** (`Vec<Expr>`), and predicates gain comparison / and / or / not
  forms so a `Gate` can be a real condition rather than an opaque host kind.
- **Footprints absorb expression reads.** `Effect::footprint()` will return the declared footprint **∪** the keys its
  argument expressions load. There is deliberately no "expression read outside the footprint" error, because there is no
  outside — the footprint is derived from the whole effect, arguments included. (This is a correction to an earlier draft
  of `design-ergon.md` §10b which specified a check; deriving is strictly better, since a check can be forgotten.)
- `trait State` / `trait Host`, and `eval` with a `Confined` state wrapper that **enforces** the footprint at run time.

**What this means for you:** target `Expr` for anything computed. If a Verum expression cannot be lowered into a total,
key-static `Expr`, that is a front-end rejection with a diagnostic — never a lowering that defers the problem.

---

## 3. What Verum already has that we are relying on

Verified by inspection, with locations. If any of this is more aspirational than the code suggests, that is itself the
most valuable correction you can send back.

| FANOS precondition | Verum mechanism | Evidence |
|---|---|---|
| Bounded totality | `decreases` measures on loops | `grammar/verum.ebnf:1687` — `loop_annotation = 'invariant' expr \| 'decreases' expr` |
| Termination obligations exist as a concept | `ObligationKind::Termination`; total-correctness VCs | `crates/verum_verification/src/context.rs:487-488`; `crates/verum_verification/src/hoare_logic.rs:214-217, 456-462, 511` |
| Static footprint | capability-restricted types, attenuating subtyping | `grammar/verum.ebnf:1257-1264`; **implemented** in `crates/verum_types/src/capability.rs` (attenuation, intersection, propagation through calls); AST nodes `Capability`/`CapabilitySet` at `crates/verum_ast/src/expr.rs:120-134` |
| Effects separated from pure computation | `pure` modifier; `@effect(<kind>)` | `grammar/verum.ebnf:104, 671, 431` |
| Declared context per contract | `using` clauses, DI as a language feature | `grammar/verum.ebnf:732-733, 1092-1148` |
| `Prove` claims | `@verify(certified)`, proof export to Coq / Lean / Dedukti / Metamath | `README.md`; `crates/verum_codegen/src/proof_export.rs` |
| A place to put contract annotations | `contract#` tagged literal | `grammar/verum.ebnf:330`, `format_tag_code` includes `'contract'` |

This lines up feature-for-precondition, which is why we are not designing a new language. It is also why the gaps below
are worth closing: each one is the difference between a mechanism existing and it being usable as a gate.

---

## 4. Gaps, in dependency order

### G1 — `@verify(thorough)` and `@verify(certified)` are not wired *(blocking)*

`crates/verum_verification/src/ladder_dispatch.rs:53-55` says so directly:

> `//  are not yet wired (ComplexityTyped, Thorough, Reliable, Certified, CoherentStatic, CoherentRuntime, Coherent, Synthesize) — annotated with the existing infrastructure`

**Why FANOS needs it.** Our contract-dialect gate is "compiles at `@verify(thorough)` or above", precisely because
`thorough` is documented as *"formal + **mandatory** invariant / frame / **termination** obligations"*
(`grammar/verum.ebnf:478-479`). That mandatory termination obligation is what discharges ERGON's bounded-totality
precondition. Without dispatch, the gate is a comment.

**Acceptance.** `verum build --verify=thorough` fails a function with an unproven loop measure, and succeeds on the same
function with a valid `decreases`. A test asserting *both* directions — the negative case is the one that matters, since a
strategy that always passes is indistinguishable from one that is not wired.

### G2 — no ERGON codegen target *(blocking)*

`crates/verum_codegen/src/` contains `llvm/`, `mlir/`, `passes/`, `proof_export.rs`, `link.rs`. VBC is a separate crate.
There is no extension point for a third-party IR that I could find (no `trait Backend`/`Target`/`Emit` in
`verum_codegen` or `verum_vbc`).

**Why FANOS needs it.** The artefact is an ERGON term, not VBC and not native code. Lowering VBC → ERGON on our side is
possible but wrong: VBC is a stack/bytecode IR, so storage keys are already dynamic by the time it exists, and recovering
static footprints from it is exactly the analysis §1 of `design-ergon.md` refuses to rely on.

**What we would like.** Either (a) a documented backend trait so an `ergon` target can live outside the Verum tree, or
(b) an `ergon` target inside it. (a) is better for both repos — it keeps FANOS's IR out of Verum's release cycle — but
(b) is fine and simpler. Lowering must happen from the **typed AST / HIR**, where capability types and `decreases` bounds
are still present, not from VBC.

**Acceptance.** `verum build --target=ergon contract.vr -o contract.ergon` emits a canonical byte string that
`fanos_ergon::Term::decode` accepts and `well_typed` passes.

### G3 — a proved `decreases` bound is not exposed as a compile-time constant *(blocking for loops)*

`decreases` reaches the CFG (`crates/verum_compiler/src/phases/cfg_constructor.rs:600-649`) and termination VCs exist
(G1's evidence), but I found no API that answers the question a lowering needs: **"what is the proved upper bound on this
loop's iteration count, as a constant?"**

**Why FANOS needs it.** ERGON has no loops. A loop whose measure is bounded by a compile-time constant `k` lowers to
`Seq` of `k` unrollings; a loop whose bound is only *finite* cannot lower at all. Without the constant, every loop is a
rejection and the dialect becomes straight-line-only — a large expressiveness loss for no reason, since the prover already
knows the measure.

**Acceptance.** Given `while c { … } decreases n - i;` with `n` a compile-time constant, an API surfaces the bound `n`, and
given `n` a runtime value it surfaces "finite, not constant". The diagnostic for the second case should say so plainly —
"loop bound is not a compile-time constant, so this cannot compile to a contract" — because that message is what an author
will act on.

### G4 — capabilities are coarse; FANOS needs **key-level** footprints *(blocking)*

`Read` / `Write` / `ReadWrite` / `Admin` / `Transaction` (`grammar/verum.ebnf:1260-1263`) say *what kind* of access, not
*to which key*. ERGON's `Footprint` is a set of 32-byte-slotted keys at projective points.

**Why FANOS needs it.** `Ledger with [Write]` tells the scheduler nothing: two transactions both holding it would appear
to conflict, and DROMOS's parallelism — the platform's throughput claim — evaporates. We need the key set.

**What we would like — a design question rather than a request**, because you know the language and I do not:

- **Option A: custom capabilities carry a key.** The grammar already allows custom capability names
  (`capability_item = capability_name | capability_or_expr`, with `identifier` for custom). If a capability can be
  parameterised — `Ledger with [Write(account_of(sender))]` — the key set falls out of the type.
- **Option B: an attribute on the state handle.** `@state_key(account, sender)` on the parameter, checked against the
  capability and collected by the lowering.
- **Option C: a FANOS-provided stdlib module** whose functions are the eight primitive effects, each with a signature
  whose types name the keys. Then no language change is needed at all — the lowering reads the call graph. **This is the
  option I would start with**, because it requires nothing from Verum but G1–G3, and it is how a contract author would
  naturally write anyway (`ledger.transfer(to, amount)` rather than key arithmetic).

If Option C is workable, G4 stops being a Verum gap and becomes ours. Please say which of these fits the language's grain
— that answer is worth more than an implementation.

### G5 — the contract dialect needs a determinism switch *(blocking)*

A contract must be a pure function of its inputs and the pre-state on **every** validator. So the dialect must forbid, at
compile time: floating point, ambient time, randomness, FFI, I/O, threads/`spawn`/`async`, and anything whose result can
differ between machines. Verum has all of these features legitimately — a systems language should — so this is a
restriction, not a fix.

**Acceptance.** A single flag (`--dialect=contract`, or the `contract#` literal implying it) under which each forbidden
construct is a *compile error naming the construct*, plus a test per construct. A denylist that silently allows one
construct is worse than none, because the artefact will look valid and diverge in production.

### G6 — total arithmetic in the dialect *(blocking)*

ERGON's evaluator treats overflow and division by zero as **faults**, deterministically. Verum needs the same in the
dialect: no wrapping, no panic-on-overflow-in-debug/wrap-in-release split, no UB. Refinement types can express the
side conditions (`Int { self != 0 }` on a divisor) and that is the nicest form — the author gets a proof obligation rather
than a runtime fault.

**Acceptance.** In `--dialect=contract`, `a / b` without a proof that `b != 0` is a compile error; `a + b` over a bounded
type without a proof of no-overflow is a compile error. Both with a test.

### G7 — proof export → `Prove(Claim)` *(not blocking; sequenced behind our ZK work)*

`Prove` is specified and type-checked in ERGON but **inert**: our PQ-ZK proofs are far too large to gossip
(`docs/design-obolos-zk.md`: 145 MiB at tree depth 1) and recursive compaction is the sole blocker. So exporting Coq/Lean
terms is not yet useful to us — an on-chain verifier must verify a *succinct* proof, not a proof script.

**What would help now**, cheaply: a statement of which proof-term formats are stable, and whether a machine-checkable
*certificate* (as opposed to a script requiring a proof assistant) is on the roadmap. We will design the `Claim` kinds
around that answer when recursion lands. **Please do not build anything here for FANOS's sake yet.**

### G8 — reproducibility of the artefact *(blocking)*

Two compilations of the same source, on different machines, must produce **byte-identical** artefacts.

**Why FANOS needs it.** A deployed contract is identified on chain by the hash of its term. If the compiler is not
reproducible, nobody can verify that a deployed contract is the source it claims to be, and the entire audit story from
source to chain collapses — reviewers would be auditing text with no binding to the code that runs.

The repo has `repro/` and a `Makefile`, so this may already hold; I did not test it.

**Acceptance.** `verum build --target=ergon` twice, on two machines, byte-identical output, asserted in CI. Any
non-determinism (hash-map iteration order, timestamps, absolute paths, parallel-codegen ordering) named and removed rather
than tolerated.

### G9 — the kernel is nine times its own audit budget *(gating a much bigger opportunity)*

`crates/verum_kernel/src/lib.rs` states the property that makes an LCF kernel trustworthy:

> Target size: **under 5000 lines of Rust, audit-able by a single reviewer in one session**.

Measured 2026-07-30: **79 files, 70 614 lines, ≈44 405 excluding comments and blank lines.** The largest are
`arch_anti_pattern.rs` (3 712), `soundness/expr_translate.rs` (2 977), `soundness/proof_body_translate.rs` (2 787),
`proof_checker.rs` (2 669), `support.rs` (2 248).

**Why FANOS cares, and it is not a style complaint.** A blockchain can put a proof *checker* in its trusted computing base
and gain something large: unbounded verified expressiveness at the cost of one check, without waiting for recursive ZK.
`docs/design-verum-frontier.md` §1 works this through — our own design doc conflates privacy with correctness, and a
kernel-checked proof term serves the correctness half today. ZK's 145 MiB is the price of *secrecy*, which a public
contract does not need.

That trade is proportionate at 5 000 lines and not obviously so at 44 000, because "auditable by one reviewer in one
session" is the entire property being bought. So the kernel's stated target is, for us, the gating condition on the largest
opportunity in the integration — which turns "the kernel should stay small" from an aspiration into a deliverable with a
named customer.

**Acceptance.** The non-comment line count of everything the kernel *trusts* is under 5 000, with a CI assertion so it
cannot drift back, and anything not strictly required for checking terms moved out (the crate doc already says that is the
intent). If some of the 44 000 is already untrusted support code that merely lives in the same crate, then the fix is
mostly to **say which lines are the TCB** — a manifest we can point an auditor at is worth nearly as much as the reduction.

---

## 5. Open questions I could not answer from the outside

1. **Is `--dialect` a concept the compiler has?** G5 and G6 assume one. If not, is a `#![dialect(contract)]` module
   attribute the idiomatic route?
2. **Does the capability system already propagate through the standard library**, so Option C in G4 would inherit key
   information from a FANOS-provided module's signatures?
3. **`core/meta/diakrisis_attrs.vr`** — the meta-system references DIAKRISIS, which is also the name of FANOS's math core.
   Is that a deliberate shared lineage (VVA Part B)? If the two are the same theory, there may be more alignment available
   here than a compiler target, and it would be worth a conversation before either side builds much.
4. **Is there prior art in the tree for a non-LLVM target** (some MLIR dialect, a serialisation backend) whose shape an
   `ergon` target should follow?

---

## 6. The conformance suite we will run

So the interface is pinned by a test rather than by this document. FANOS will ship a suite that, for each fixture:

1. compiles `fixture.vr` with `verum build --target=ergon --dialect=contract --verify=thorough`;
2. decodes the artefact with `fanos_ergon::Term::decode` — a decode failure is a hard error, never a skip;
3. runs the chain's own `well_typed` and compares `Term::footprint` against a hand-written expected footprint;
4. evaluates it against a fixture pre-state and compares the post-state;
5. re-compiles and asserts byte-identical output (G8).

Step 3 is the one that keeps the trust boundary honest: it must fail loudly if the compiler's intent and the chain's
derivation ever disagree. And every fixture will have a **negative twin** — a contract that must be *rejected* (dynamic
storage key, unbounded loop, float, unproven divisor) — because a gate that only ever accepts is indistinguishable from
one that is not wired, which is exactly the defect G1 documents.
