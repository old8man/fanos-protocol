# Verum → ERGON integration design (FANOS side)

**Status:** accepted 2026-07-30. Companion to `verum-contract-requirements.md` (G1–G8).
**Ownership note:** Verum deliberately knows nothing about ERGON. Everything
ERGON-specific — this document, the emitter, the conformance suite — lives here.
Verum's side is a set of *general* language/toolchain features, documented in the
Verum repo at `docs/architecture/deterministic-profile-and-typed-export.md`:

| Requirements gap | General Verum feature (Verum repo task) | ERGON use (ours) |
|---|---|---|
| G1 verify wiring | Thorough/Certified mandatoriness (T0671) | the dialect gate "compiles at thorough" |
| G5 determinism | `--profile deterministic` / `@profile(deterministic)` (T0672) | the contract dialect IS this profile |
| G6 total arithmetic | profile-scoped divisor/overflow obligations (T0673) | ERGON fault semantics discharged at compile time |
| G3 loop bounds | per-loop `ConstantBound(k)` API in the typed export (T0674) | loop → `Seq` of `k` unrollings; `FiniteNotConstant` → reject |
| G2 codegen target | canonical **typed-IR export** (T0675) — the documented seam, option (a) of our own G2 | the `ergon-emitter` crate (ours) lowers typed-IR → `Term` |
| G4 key-level footprints | capability propagation verified (T0676) | **Option C**: our stdlib-shaped module of eight effect fns |
| G8 reproducibility | byte-identical exports, CI-asserted (T0677) | artefact hash = on-chain identity |

## The emitter (ours to build)

A crate in this repo, `rust/crates/ergon-emitter` (name TBD), that:

1. reads a Verum typed-IR artefact (schema-versioned; pin the schema version),
2. accepts only items carrying `@profile(deterministic)` provenance + a
   Thorough verification record — otherwise reject with the artefact's own
   diagnostics,
3. lowers structured bodies to the `Term` algebra:
   - straight-line statements → `Seq`
   - calls to our effect module's fns (identified by their `@effect(<kind>)`
     attribute, carried verbatim in the export) → `Do(Effect)`
   - `if`/`else` → `Gate`; `match`/else-if chains → `Alt` (declaration order)
   - loops → `Seq` of `k` unrollings where the export says `ConstantBound(k)`;
     anything else → rejection quoting the export's "not a compile-time
     constant" diagnostic
   - anything outside the lowerable subset → rejection naming the construct
4. computes nothing the chain derives: no declared footprints, ever (§1 of the
   requirements). `Par` is emitted only where key-disjointness is provable from
   the effect-module signatures (Option C); `Seq` otherwise.
5. encodes canonically once the codec lands in `fanos-ergon` (encode/decode do
   not exist yet as of 2026-07-30 — the emitter targets the in-memory algebra
   until the wire format is pinned).

## The effect module (Option C, ours)

A Verum library module, shipped by FANOS, whose eight primitive effect
functions carry `@effect(<kind>)` and capability-typed signatures naming the
keys. Contract authors mount it and write `ledger.transfer(to, amount)`;
the emitter reads the call graph. No Verum change is required beyond
T0671–T0677; if capability information turns out not to survive the
archive round-trip (T0676's test), that is a Verum bug to file with a repro,
not a reason to add ERGON knowledge to Verum.

## Answers to the requirements doc's §5

1. **`--dialect`:** no such concept existed; the general mechanism is the
   profile (flag + attribute). Our "contract dialect" = `deterministic` profile
   + Thorough + the emitter's lowerable-subset check.
2. **Capability propagation through stdlib:** mechanism implemented in
   `verum_types/src/capability.rs`; archive-round-trip fidelity is exactly what
   T0676 tests before we rely on it.
3. **DIAKRISIS lineage:** flagged to the humans; nothing in the integration
   depends on it.
4. **Prior art for a non-LLVM target:** Verum's `proof_export.rs` and the VBC
   archive writer; the typed-IR export follows their shape. Our emitter is the
   third-party backend that seam exists for.

## Conformance suite (§6 of the requirements) — updated commands

1. `verum build --profile deterministic --verify=thorough fixture.vr` — gate;
2. `verum export --typed-ir fixture.vr -o fixture.tir` — artefact;
3. `ergon-emitter fixture.tir -o fixture.ergon` + `Term::decode` (once codec
   lands) — decode failure is a hard error, never a skip;
4. chain-side `well_typed` + `Term::footprint` vs hand-written expectation;
5. evaluate against fixture pre-state, compare post-state;
6. re-run steps 1–3, assert byte-identical artefacts (G8) — both the `.tir`
   and the `.ergon`.

Every fixture keeps its **negative twin** (dynamic key, unbounded loop, float,
unproven divisor) — a gate that only accepts is indistinguishable from one that
is not wired.
