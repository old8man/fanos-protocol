# Constant-time GF(2^m) arithmetic (closing spec §16 side-channel concern)

> Spec §16 flags: *"GF(2^m) for large q needs careful field-arithmetic implementation (constant time against
> side-channels)."* This note establishes — by analysis **and** experiment — that `fanos-field`'s binary-field
> arithmetic is constant-time in its secret operands, so the field operations that touch secret material
> (Shamir shares over `GF(256)`, audit B7) leak nothing through timing.

**Constant-time, defined.** An operation is constant-time (CT) if its control flow and memory-access pattern —
hence its execution time on a fixed platform — depend only on **public** inputs, never on secret ones. It is
*not* required to run in the same time for different *fields* or different *public exponents*; it is required
that, holding those public, the time not vary with the secret operand.

## The four operations (`crates/fanos-field/src/gf2m.rs`)

- **`add` / `sub` / `neg`** — a single `XOR` (and a mask). No branch, no table, no secret-indexed access.
  Trivially CT.

- **`mul` (`clmul`)** — carry-less multiply-and-reduce. The inner loop runs **exactly `M` iterations** (a
  `const` bound, no early exit), and each step is **branchless**: the conditional "add a shifted copy of `a`"
  and "reduce by the polynomial" are done with arithmetic masks —
  ```
  add_mask    = 0u32.wrapping_sub(b & 1);            // all-ones iff the bit is set
  acc        ^= a & add_mask;
  reduce_mask = 0u32.wrapping_sub((a >> (M-1)) & 1);
  a           = ((a << 1) ^ (POLY & reduce_mask)) & MASK;
  ```
  — never a data-dependent branch. So `mul` executes an identical instruction sequence for every operand
  pair: CT by construction. (On CPUs with a carry-less multiply instruction — `PCLMULQDQ`/`PMULL` — this loop
  is the portable fallback; a hardware path is itself CT and drops in without changing callers.)

- **`inv` (`a^(q−2)` by Fermat)** — the multiplicative inverse is a fixed power. Crucially the exponent
  `q − 2` is a **public constant** of the field, so the square-and-multiply ladder in `pow` branches only on
  the bits of `q − 2` — *never on the secret base `a`*. The number and order of squarings and multiplications
  is therefore identical for every secret `a`, and each of those field multiplies is itself CT (above). Hence
  `inv` is CT in the secret. `div = a · inv(b)` inherits this.

The one branch in `pow` (`if e & 1 == 1`) is on the public exponent, which is the standard, sound Fermat-based
CT-inversion for binary fields (the same reason a fixed-window exponentiation with a public exponent is CT).

## The experiment (`gf2m.rs::ct_experiment`)

Timing measurements are noisy and flaky in CI, so the property is validated **deterministically**: a wrapper
field over `GF(256)` counts every field multiplication, and `inv` is run over **all 255 non-zero secrets**.
The test asserts the multiply-count is **identical** for every secret — a non-flaky, reproducible proxy that
the inversion ladder's control flow does not depend on the secret operand. (The count is the fixed `15` for
`e = 254`: 8 squarings + 7 conditional multiplies, the same for all inputs.) Correctness is checked alongside
(`a · a⁻¹ = 1`) so the counting wrapper is exercising the real algorithm.

This closes the §16 concern: the binary-field arithmetic is CT in secrets by construction, documented here and
guarded by a deterministic experiment in the test suite.
