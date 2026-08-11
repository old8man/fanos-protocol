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
#   ./gate.sh clippy       # one group: clippy | tests | run | docs | nostd
#   ./gate.sh clippy tests
#
# Costs, measured on this project: a no-op test target is ~0.2 s, `clippy --all-targets` on fanos-node ~76 s,
# on fanos-sim ~587 s. The full run is tens of minutes. Gate once per work item, not once per edit.

set -u

cd "$(dirname "$0")/rust" || exit 2

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
want() {
  [ "$#" -eq 0 ] && return 0
  local g="$1"; shift
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

if want clippy ${SELECT[@]+"${SELECT[@]}"}; then
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

if want tests ${SELECT[@]+"${SELECT[@]}"}; then
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
fi

if want run ${SELECT[@]+"${SELECT[@]}"}; then
  echo "run"
  run verifier         run -p fanos-cli
  run sim-demo         run -p fanos-sim --bin fanos-sim-demo
  run forecast         run -p fanos-sim --example forecast
  run catastrophe      run -p fanos-sim --example catastrophe
  run bench-compile    bench -p fanos-bench --no-run
fi

if want docs ${SELECT[@]+"${SELECT[@]}"}; then
  echo "docs"
  RUSTDOCFLAGS="-D warnings" run doc doc --workspace --no-deps
fi

if want nostd ${SELECT[@]+"${SELECT[@]}"}; then
  echo "no_std on the HOST target"
  # On the host, not wasm: wasm has native f64.ceil/f64.nearest, so a wasm-only check supplies the very
  # facility `libm` exists to replace and cannot fail on a std call that slipped in.
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
if [ "$FAILED" -eq 0 ]; then
  echo "GATE GREEN — ${#SUMMARY[@]} steps, every status read from cargo — logs in $LOGS"
else
  echo "GATE RED — logs in $LOGS"
fi
exit "$FAILED"
