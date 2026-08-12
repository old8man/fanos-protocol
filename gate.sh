#!/usr/bin/env bash
# The local mirror of `.github/workflows/ci.yml`, with the exit codes read from cargo.
#
# WHY THIS EXISTS. Every local gate in this project has been assembled by hand at the prompt, and the same
# two mistakes kept being paid for:
#
#   1. `cargo … | grep … | head` reports **head's** status, not cargo's. An "exit 0" recorded that way once
#      cost a false all-clear and an hour chasing a regression that was neither mine nor new — and it
#      recurred after being written into a memory, which is why the answer is a script and not a note.
#   2. Two gates sharing one log file give you the rc of whichever finished last.
#
# So: every step runs cargo **directly** into its own log, its status is captured on the next line, and the
# summary prints what cargo said. Greps read the log afterwards, where they cannot launder a status.
#
# WHAT IT DOES NOT RUN, said out loud rather than quietly omitted — a gate that skips in silence reads as a
# gate that passed:
#   * the reproducible-build job (two source paths + a byte compare; it wants a clean second checkout);
#   * the wasm32 target builds (they need `rustup target add wasm32-unknown-unknown`).
# Both are in ci.yml. Run them there, or add them here when the setup is a given.
#
# USAGE
#   ./gate.sh              # everything below
#   ./gate.sh clippy       # one group: clippy | guards | tests | run | docs | nostd | prune
#   ./gate.sh clippy tests
#
# Costs, measured on this project: a no-op test target is ~0.2 s, `clippy --all-targets` on fanos-node ~76 s,
# on fanos-sim ~587 s. The full run is tens of minutes. Gate once per work item, not once per edit.

set -u

cd "$(dirname "$0")/rust" || exit 2

# MEASURED, 2026-08-12 (#286). One full `tests` run grows `target` by ~44 GB: `debug/deps` +37 GB and
# `debug/incremental` +6.7 GB. The gate compiles each crate exactly ONCE per run, so the incremental cache buys
# it nothing — that cache pays off in the edit-run-edit loop, which is not what this script does. Turning it off
# is 6.7 GB per run for free.
#
# It is NOT the fix for the accumulation, and saying so would be lying by a factor of five. Cargo never removes
# a superseded artefact: every fingerprint change leaves the old `.rlib` in `deps` forever, which is where the
# other 37 GB goes. That needs pruning by age (`cargo-sweep`), and until it exists the floor below is what
# stands between this repo and the failure it already caused once.
export CARGO_INCREMENTAL=0

# A run needs ~44 GB of headroom, so refuse below 50. Derived from the measurement above plus one run's slack,
# not chosen: at 0 bytes free the harness cannot even create a file, `bash` stops working entirely, and the
# session that discovers this cannot run the `rm` that would fix it. Failing loudly here costs one message;
# failing there cost an hour and a hand-written instruction to the operator.
free_mb() { df -m . 2>/dev/null | awk 'NR==2 {print $4}'; }
FREE_MB=$(free_mb)
FREE_AT_START=$FREE_MB
if [ -n "${FREE_MB:-}" ] && [ "$FREE_MB" -lt 51200 ]; then
  echo "REFUSING TO START: $((FREE_MB / 1024)) GB free, a full run needs ~44 GB (measured #286)." >&2
  echo "  du -h -d 1 $(pwd)/target   # then prune debug/incremental (safe) or debug/deps (costs a rebuild)" >&2
  exit 4
fi

FAILED=0
SUMMARY=()

# run <name> <cargo args...> — one log, one status, no pipeline between cargo and `$?`.
run() {
  local name="$1"; shift
  local log="$LOGS/$name.log"
  printf '  %-46s ' "$name"
  cargo "$@" >"$log" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    printf 'ok\n'
    SUMMARY+=("ok    $name")
  else
    printf 'FAILED (rc=%d)\n' "$rc"
    SUMMARY+=("FAIL  $name  →  $log")
    FAILED=1
    # The first lines that say why, so a failure is actionable without opening the log.
    grep -E '^(error|warning: unused|test result: FAILED|failures:)' "$log" | head -8 | sed 's/^/        /'
  fi
}

# want <group> [selected...] — true when nothing was selected, or when this group was.
#
# The selection array is NOT called `GROUPS`: that is a bash built-in holding the caller's group IDs, so the
# assignment silently did nothing and the first run of this script matched no group at all. A name that means
# something else to the reader — and the reader here is the shell.
#
# `${A[@]+"${A[@]}"}` and not `"${A[@]}"`: under `set -u`, bash 3.2 (what macOS ships) treats an empty array
# expansion as an unbound variable, so a full run would have died before its first step.
#
# **The emptiness that matters is the SELECTION's, not this function's**, and the check was on the wrong one
# — one line above where it belonged. Every call passes the group name, so `$#` here is never 0 and the guard
# never fired: `./gate.sh` with no arguments, the form this file's own USAGE calls "everything below",
# matched nothing and gated nothing. Shift the name off first, and what remains IS the selection.
#
# Note the shape, because the comment above describes the *same* defect one fix earlier: `GROUPS` was a bash
# built-in, the assignment did nothing, and a bare run matched no group. That fix renamed the array and left
# this half standing — the guarded path and its unguarded twin, inside six lines.
want() {
  local g="$1"; shift
  [ "$#" -eq 0 ] && return 0
  for a in "$@"; do [ "$a" = "$g" ] && return 0; done
  return 1
}

SELECT=("$@")

# The log directory is named for WHAT WAS ASKED, not for the PID.
#
# It used to be `fanos-gate-$$`, and that address is computable only from inside the running gate. When a run
# returned `GATE_TESTS_EXIT=1` alongside `no space left on device` in the same output, there was no way to tell
# a real test failure from a disk artefact: the per-step logs existed and were unfindable. A gate whose
# evidence outlives it only in principle reports nothing at the one moment it is needed — after it died.
#
# Naming it for the selection keeps it findable AND keeps #217's rule that overlapping gates must not share
# paths: `./gate.sh clippy` and `./gate.sh tests` land in different directories, and the only collision left
# is two runs of the SAME groups, which the lock below refuses outright rather than letting them interleave
# their statuses.
TAG=all
if [ "${#SELECT[@]}" -gt 0 ]; then
  TAG=$(printf '%s-' ${SELECT[@]+"${SELECT[@]}"})
  TAG="${TAG%-}"
fi
LOGS="${GATE_LOGS:-${TMPDIR:-/tmp}/fanos-gate-$TAG}"

if [ -f "$LOGS/pid" ] && kill -0 "$(cat "$LOGS/pid" 2>/dev/null)" 2>/dev/null; then
  echo "gate '$TAG' is already running (pid $(cat "$LOGS/pid")) — its logs are in $LOGS" >&2
  echo "refusing to start a second one: they would overwrite each other's statuses" >&2
  exit 3
fi
mkdir -p "$LOGS" || exit 2
echo $$ >"$LOGS/pid"
trap 'rm -f "$LOGS/pid"' EXIT

echo "gate — logs in $LOGS"

# `./gate.sh prune` — the only removal this script performs, and it is deliberately the safe half.
#
# `debug/incremental` is pure cache: deleting it costs compile time and nothing else, and since
# CARGO_INCREMENTAL=0 above it is not even being written any more — whatever is there is left over from before
# that line existed. Measured: one full `tests` run used to deposit 6.7 GB here.
#
# `debug/deps` is NOT touched, and that omission is the finding rather than laziness. It grows 37 GB per run
# because cargo keeps every superseded `.rlib` for ever, but from the outside a stale artefact and a current
# one look identical — only cargo's fingerprints know which is which. Deleting by age would eventually throw
# away something current; that costs only a rebuild, never correctness, but it also would not be a policy, it
# would be a guess wearing a number. The honest tool is `cargo-sweep`, which reads the fingerprints. Until it
# is available this step reports the size and names the command, and refuses to pretend it has pruned.
# NAMED ONLY. `want` is true when nothing was selected, so a bare `./gate.sh` would have run this too — a
# destructive step reached by the path that means "check everything". Removal must be asked for by name.
if [ "${#SELECT[@]}" -gt 0 ] && want prune ${SELECT[@]+"${SELECT[@]}"}; then
  RAN_GROUP=1
  echo "prune"
  before=$(free_mb)
  rm -rf target/debug/incremental
  after=$(free_mb)
  echo "  incremental cache removed — $((after - before)) MB reclaimed"
  echo "  deps NOT pruned: only cargo's fingerprints can tell a stale .rlib from a live one."
  echo "  install cargo-sweep and run: cargo sweep --installed   # or cargo clean, at one full rebuild"
fi

if want clippy ${SELECT[@]+"${SELECT[@]}"}; then
  RAN_GROUP=1
  echo "clippy"
  run clippy-default   clippy --workspace --all-targets -- -D warnings
  run clippy-validator clippy --workspace --all-targets --features validator -- -D warnings
  run clippy-vpn       clippy -p fanos-node --features vpn --all-targets -- -D warnings
  # The three feature surfaces no other job compiles. `observatory/sim` gates a target behind
  # `required-features`, so `cargo test --workspace` SKIPS it rather than failing — the quietest form of
  # the same gap, which is why it gets its own step here too.
  run clippy-sim       clippy -p fanos-observatory --features sim --all-targets -- -D warnings
  run clippy-sysinfo   clippy -p fanos-telemetry --features sysinfo --all-targets -- -D warnings
  run clippy-wasm      clippy -p fanos-wasm --features wasm --all-targets -- -D warnings
fi

# **The cross-crate guards, split out because the full `tests` run is too slow to be a per-change gate.**
#
# MEASURED, 2026-08-12: one `tests` run took 2 h 40 min and was still going, which means its verdict is about
# whatever the tree was when it STARTED. A gate that cannot finish inside the life of a working tree does not
# verify that tree — and this is not hypothetical: today a real regression (`no_new_public_capability_arrives_
# unwired`, fanos-sim 40 > 37) reached three commits deep because everything in between was checked with
# `clippy -p <crate>` and targeted tests, neither of which runs a guard that lives in fanos-cli and reads the
# whole workspace.
#
# These guards are the part that catches exactly that class. Their cost has TWO components and quoting only
# the friendly one would repeat the mistake this whole group exists to fix:
#   * running them, once built: `--test architecture` measured 2.04 s;
#   * BUILDING them, which dominates and is shared with whatever else the tree has compiled. Measured here:
#     a `guards` run started while `tests` was mid-flight recompiled the dependency chain from `fanos-field`
#     up and had not finished in 10 minutes. It was not blocked on cargo's lock — the log shows `Compiling`.
# So: seconds when the tree is warm, a full dependency build when it is not. Run this after every change
# that touches a public surface; run `tests` when there is time for it.
if want guards ${SELECT[@]+"${SELECT[@]}"}; then
  RAN_GROUP=1
  echo "guards"
  # The whole fanos-cli test directory: architecture ratchets, the composition seam, the frame registry, the
  # conformance vectors, the skew windows. Every one of them reads ACROSS crates, which is why no per-crate
  # invocation can substitute.
  run guards-crosscrate test -p fanos-cli --no-fail-fast
fi

if want tests ${SELECT[@]+"${SELECT[@]}"}; then
  RAN_GROUP=1
  echo "tests"
  # `--no-fail-fast` everywhere, and it is not a style preference: `cargo test` stops at the first failing
  # TARGET, so one red target hides every target after it.
  #
  # fanos-quic and fanos-node run ALONE. Their real-QUIC liveness assertions are load-sensitive; measured
  # 221 green / 9 inconclusive under a parallel workspace run, and 9-of-9 green with the runner to
  # themselves. The guard is right; a shared runner is what is wrong.
  run test-workspace   test --workspace --no-fail-fast --exclude fanos-node --exclude fanos-quic
  run test-quic        test -p fanos-quic --no-fail-fast
  run test-node        test -p fanos-node --no-fail-fast
  run test-validator   test -p fanos-node --features validator --no-fail-fast
  # The `vpn` surface had a clippy phase and no test phase, and the gap was exactly one test:
  # `cargo test -p fanos-vpn -- --list` yields 17 by default and 18 with `device`, the extra one being
  # `fulltunnel::tests::a_flow_buffer_is_one_mtu_of_the_stack_this_build_configures` — #247's proof that the
  # per-flow buffer is the MTU read back from the stack rather than a declared constant (268 MB -> 5.1 MB,
  # 51x). `clippy-vpn --all-targets` COMPILED it all along; compiling a test says it exists and nothing
  # about whether it passes.
  #
  # Deliberately `-p fanos-vpn` and not the `-p fanos-node --features vpn` form `test-validator` uses. The
  # measured delta decides it: fanos-vpn's device tests cost ~1 s, while re-running fanos-node's suite under
  # the feature cost 131 s + 93 s of integration time for a delta that is one subcommand's wiring, already
  # linted. If that wiring grows real logic, this phase should grow with it.
  run test-vpn         test -p fanos-vpn --features device --no-fail-fast
  # Same shape, second member. `--list` measures it: fanos-telemetry has 45 tests by default and 46 with
  # `sysinfo`, the extra one being `sysmetrics::tests::sysinfo_probe_reads_real_vitals_in_range` — the only
  # check that the REAL host probe returns plausible numbers rather than the fixture's. The other two
  # single-clippy features are clean and were checked the same way: `fanos-observatory --features sim` is
  # 22/22 (the feature gates the `fanos-lab` BINARY via required-features, adding no tests) and
  # `fanos-wasm --features wasm` is 3/3.
  run test-sysinfo     test -p fanos-telemetry --features sysinfo --no-fail-fast
fi

if want run ${SELECT[@]+"${SELECT[@]}"}; then
  RAN_GROUP=1
  echo "run"
  run verifier         run -p fanos-cli
  run sim-demo         run -p fanos-sim --bin fanos-sim-demo
  run forecast         run -p fanos-sim --example forecast
  run catastrophe      run -p fanos-sim --example catastrophe
  run bench-compile    bench -p fanos-bench --no-run
fi

if want docs ${SELECT[@]+"${SELECT[@]}"}; then
  RAN_GROUP=1
  echo "docs"
  RUSTDOCFLAGS="-D warnings" run doc doc --workspace --no-deps
fi

if want nostd ${SELECT[@]+"${SELECT[@]}"}; then
  RAN_GROUP=1
  echo "no_std on the HOST target"
  # On the host, not wasm: wasm has native f64.ceil/f64.nearest, so a wasm-only check supplies the very
  # facility `libm` exists to replace and cannot fail on a std call that slipped in.
  # These verify the LIBRARY builds without std, and NOT its tests — `check` without `--all-targets` never
  # compiles test code. That limit is worth stating because the six lines look uniform and are not:
  # measured with `--list`, fanos-nyx (42) and fanos-runtime (65) keep every test std-free and would compile
  # under this configuration, while fanos-diakrisis, fanos-telemetry and fanos-ports use `std`, `println!`
  # and `String` in theirs and fail to build here. Neither is a defect — a no_std guarantee is about what
  # ships, and a test harness needs a runner these targets do not have — but a reader must not take six
  # identical-looking lines as identical coverage.
  #
  # Deliberately NOT upgraded to `check --all-targets` for the two that would pass it. That would enforce a
  # property nobody in this tree has decided to hold, and the first std-using test added to fanos-nyx would
  # redden the gate for something that is not a defect. If the tree ever decides test code stays std-free,
  # this is the line to change and the measurement above is the evidence to change it against.
  run nostd-diakrisis-libm  check -p fanos-diakrisis --no-default-features --features libm
  run nostd-diakrisis-alloc check -p fanos-diakrisis --no-default-features --features "alloc libm"
  run nostd-telemetry       check -p fanos-telemetry --no-default-features --features "alloc libm"
  run nostd-ports           check -p fanos-ports     --no-default-features --features "alloc libm"
  run nostd-nyx             check -p fanos-nyx       --no-default-features --features "alloc libm"
  run nostd-runtime         check -p fanos-runtime   --no-default-features --features "alloc libm"
fi

echo
echo "summary"
printf '  %s\n' ${SUMMARY[@]+"${SUMMARY[@]}"}
echo
# The path is printed again HERE, not only at the top. A caller that keeps the tail of a long run — which is
# every caller — otherwise ends up holding the verdict without the evidence.
# What this run COST the disk, printed whether it passed or failed.
#
# The accumulation was invisible until it stopped the machine: `target` reached 188 GB, and at zero bytes free
# the harness could not create a file, so `bash` itself stopped working. Nothing in the tree measured the
# growth, and nothing removes it — cargo keeps every superseded `.rlib` in `deps` forever. A floor alone only
# reports the last moment before the wall; this reports the rate that walks you there.
#
# `df`, not `du`: reading 128 GB of directory entries takes minutes, and an instrument that expensive gets
# switched off. This is two syscalls and is exact for the question asked — how much less room is there now.
FREE_AT_END=$(free_mb)
if [ -n "${FREE_AT_START:-}" ] && [ -n "${FREE_AT_END:-}" ]; then
  delta=$((FREE_AT_START - FREE_AT_END))
  if [ "$delta" -lt 0 ]; then
    echo "disk — $((FREE_AT_START / 1024)) GB free before, $((FREE_AT_END / 1024)) GB after (reclaimed $((-delta)) MB)"
  else
    echo "disk — $((FREE_AT_START / 1024)) GB free before, $((FREE_AT_END / 1024)) GB after (this run cost $delta MB)"
  fi
fi
# "GREEN" with nothing gated is the same lie as a skipped step reported as a pass: `prune` runs no cargo at
# all, so it must not borrow the word.
if [ "${RAN_GROUP:-0}" -eq 0 ]; then
  echo "NO GATE GROUP MATCHED — logs in $LOGS"
  # **And say it in the exit code too.** The line above was already honest; `exit 0` was not, and a caller
  # that reads `$?` — CI, a shell `&&`, a wrapper script — saw a pass. `./gate.sh guardz` (a typo for a real
  # group) gated nothing and reported success: the human-readable half told the truth and the
  # machine-readable half did not.
  #
  # Keyed on whether a GROUP ran, not on whether cargo ran, and that distinction is not pedantry — the first
  # version keyed on the step count and broke `prune`, which is a real group that deliberately invokes no
  # cargo at all. Caught by running both arms: a typo must fail, and every real group must not.
  exit 1
elif [ "$FAILED" -eq 0 ]; then
  echo "GATE GREEN — ${#SUMMARY[@]} steps, every status read from cargo — logs in $LOGS"
else
  echo "GATE RED — logs in $LOGS"
fi
exit "$FAILED"
