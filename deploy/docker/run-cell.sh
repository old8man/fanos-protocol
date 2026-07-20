#!/usr/bin/env bash
# FANOS multi-node integration test over real inter-container QUIC (#117/#119, T5 tier).
#
# Brings up a four-node cell where every node is its own container with its own network namespace, then
# asserts the cell FORMS over genuine inter-host QUIC: each node discovers the other three (membership
# converges) via bootstrap + JOIN/Announce flooding + self-certifying HELLO handshakes between containers.
# This is the tier the in-process `cell_e2e` tests structurally cannot reach — real sockets across real
# namespaces, not many endpoints in one process on loopback.
#
# Why an orchestration script and not plain `docker compose up`: a node's coordinate is
# MapToPoint(VRF(identity, …)), so it only exists AFTER the node mints its identity — and a full-mesh
# bootstrap needs every node's coordinate up front. So we mint all four identities first (persisted into
# the compose named volumes), resolve the four coordinates onto distinct Fano points, then start the cell
# with each node's full-mesh `--bootstrap` list.
#
# Usage:  ./run-cell.sh            # build (if needed), form the cell, assert, tear down
#         ./run-cell.sh --keep     # leave the cell running for inspection after asserting
#         KEEP=1 ./run-cell.sh     # same
#         NETEM=100ms ./run-cell.sh   # add 100ms egress latency to every node (self-healing under delay)
set -euo pipefail

cd "$(dirname "$0")"

PROJECT="fanos-cell"
IMAGE="fanos-node:integration"
NODES="genesis node2 node3 node4"
NPEERS=3                 # each node should discover the other three
PORT=9000
CONVERGE_TIMEOUT="${CONVERGE_TIMEOUT:-90}"   # seconds to wait for membership convergence
KEEP="${KEEP:-}"
[ "${1:-}" = "--keep" ] && KEEP=1
NETEM="${NETEM:-}"

# Resolve a docker compose invocation (v2 plugin `docker compose`, or legacy `docker-compose`).
if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi
compose() { $DC -p "$PROJECT" "$@"; }

log()  { printf '\033[1;36m[cell]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ ok ]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; dump_logs; teardown; exit 1; }

dump_logs() {
  printf '\n=== container logs ===\n' >&2
  compose logs --no-color 2>&1 | tail -120 >&2 || true
}

teardown() {
  [ -n "$KEEP" ] && { log "leaving the cell up (--keep); tear down with: $DC -p $PROJECT down -v"; return; }
  log "tearing down"
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}

# --- 0. image ------------------------------------------------------------------------------------
# An integration image builds with the `debug` profile by default (far faster to compile than release,
# and startup speed / binary size are irrelevant here); override with `PROFILE=release ./run-cell.sh` to
# exercise the actual production build. A pre-existing `$IMAGE` is reused as-is.
PROFILE="${PROFILE:-debug}"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "building $IMAGE (PROFILE=$PROFILE) from the repo-root Dockerfile"
  ( cd ../.. && docker build --build-arg "PROFILE=$PROFILE" -t "$IMAGE" . )
fi

# --- 1. clean slate ------------------------------------------------------------------------------
compose down -v --remove-orphans >/dev/null 2>&1 || true

# --- 2. mint one identity per node onto a distinct Fano point ------------------------------------
# `fanos id` mints+persists the identity to the volume and prints `coordinate: x:y:z`. Two fresh
# identities land on the same Fano point 1/7 of the time; a cell requires distinct points, so re-mint any
# node that collides with an already-accepted coordinate (removing its volume forces a fresh identity).
mint() { # $1 = service; echoes its coordinate
  compose run --rm --no-deps --entrypoint /usr/local/bin/fanos "$1" \
    id --identity /var/lib/fanos/id.bin 2>/dev/null | awk -F': ' '/^coordinate:/ {print $2; exit}'
}

log "minting four identities onto distinct Fano points"
USED=""            # space-delimited accepted coordinates
SEEDS=""           # space-delimited "service=coord" pairs
for n in $NODES; do
  tries=0
  while :; do
    tries=$((tries + 1))
    [ "$tries" -gt 25 ] && die "could not mint a distinct coordinate for $n after 25 tries"
    coord="$(mint "$n")"
    [ -z "$coord" ] && die "minting $n produced no coordinate (is the image built correctly?)"
    case " $USED " in
      *" $coord "*) docker volume rm -f "${PROJECT}_${n}-id" >/dev/null 2>&1 || true; continue ;;
      *) break ;;
    esac
  done
  USED="$USED $coord"
  SEEDS="$SEEDS $n=$coord"
  ok "$n → $coord"
done

# --- 3. full-mesh bootstrap: each node seeds the other three (coord@host:port) --------------------
seed_of() { for kv in $SEEDS; do case "$kv" in "$1="*) echo "${kv#*=}"; return ;; esac; done; }
bootstrap_for() { # $1 = this service; echoes comma-joined seeds of all OTHER nodes
  local me="$1" out="" other c
  for other in $NODES; do
    [ "$other" = "$me" ] && continue
    c="$(seed_of "$other")"
    out="${out:+$out,}${c}@${other}:${PORT}"
  done
  echo "$out"
}

export BOOTSTRAP_GENESIS="$(bootstrap_for genesis)"
export BOOTSTRAP_NODE2="$(bootstrap_for node2)"
export BOOTSTRAP_NODE3="$(bootstrap_for node3)"
export BOOTSTRAP_NODE4="$(bootstrap_for node4)"

# --- 4. bring the cell up --------------------------------------------------------------------------
log "starting the four-node cell over the bridge network"
compose up -d

# The node floods its membership Announce ONCE at startup (no periodic re-announce / anti-entropy yet — a
# real gap tracked under #119). So a node only learns peers whose Announce arrived while it was already
# listening; with staggered container startup a late joiner would miss earlier members. Synchronise
# deterministically with a ROLLING RESTART once every endpoint is up: each node then re-announces into a
# fully-listening cell, and — because every OTHER node stays up throughout its restart — every node both
# learns and is learned by all three peers. (A rolling restart is a routine ops procedure; this is exactly
# the anti-entropy that #119's discovery layer will make automatic.)
nodeup_count() { compose logs --no-color "$1" 2>/dev/null | grep -c "fanos node up" || true; }
wait_nodeup() { # $1 = service, $2 = minimum "node up" occurrences to wait for
  local n="$1" want="$2" end=$(( $(date +%s) + 45 ))
  while [ "$(nodeup_count "$n")" -lt "$want" ]; do
    [ "$(date +%s)" -ge "$end" ] && die "$n did not bind its endpoint (no 'fanos node up') in time"
    sleep 1
  done
}

log "waiting for every endpoint to bind"
for n in $NODES; do wait_nodeup "$n" 1; done

log "rolling-restart to synchronise the one-shot membership announces"
for n in $NODES; do
  before="$(nodeup_count "$n")"
  compose restart "$n" >/dev/null
  wait_nodeup "$n" $((before + 1))
done

# Optional: shape every node's egress with netem, to watch the cell stay coherent under real delay/loss.
if [ -n "$NETEM" ]; then
  log "applying netem delay=$NETEM to each node's egress (best-effort; needs NET_ADMIN)"
  for n in $NODES; do
    cid="$(compose ps -q "$n")"
    docker exec --user 0 "$cid" sh -c "tc qdisc add dev eth0 root netem delay $NETEM" 2>/dev/null \
      || log "netem on $n skipped (tc/NET_ADMIN unavailable in the image — informational)"
  done
fi

# --- 5. assert membership convergence from the logs -----------------------------------------------
# Each node logs `member joined` (with the peer's `coord=[x, y, z]`) on first sight of a peer. We count
# the DISTINCT peer coordinates a node has logged over its lifetime: the rolling restart above guarantees
# every node both announces to, and receives an announce from, all three peers while they are up — so a
# converged node has discovered three distinct peers. (Distinct-count, not raw lines, so a peer re-learned
# after a restart is not double-counted.)
joined_count() {
  # `|| true` neutralises the pipefail exit when `grep` finds no matches yet (early in the wait) — `wc`
  # still prints 0, so the count is correct; without it, `set -e` would abort the poll on the first tick.
  { compose logs --no-color "$1" 2>/dev/null \
      | grep "member joined" \
      | grep -oE '\[[0-9]+, [0-9]+, [0-9]+\]' \
      | sort -u | wc -l | tr -d ' '; } || true
}

log "waiting up to ${CONVERGE_TIMEOUT}s for every node to discover its three peers"
deadline=$(( $(date +%s) + CONVERGE_TIMEOUT ))
while :; do
  converged=1
  summary=""
  for n in $NODES; do
    c="$(joined_count "$n")"
    summary="$summary $n=$c"
    [ "$c" -ge "$NPEERS" ] || converged=0
  done
  if [ "$converged" -eq 1 ]; then
    ok "cell converged — every node discovered $NPEERS peers:$summary"
    break
  fi
  [ "$(date +%s)" -ge "$deadline" ] && die "cell did not converge within ${CONVERGE_TIMEOUT}s (member-joined counts:$summary)"
  sleep 2
done

# Secondary signal: a converged cell should not be flapping. Report (do not fail on) peer-down churn.
downs=0
for n in $NODES; do downs=$(( downs + $(compose logs --no-color "$n" 2>/dev/null | grep -c "peer down" || true) )); done
log "liveness: $downs total peer-down events across the cell during formation (transient startup churn is normal)"

ok "INTEGRATION PASS — a four-node FANOS cell formed over real inter-container QUIC"
teardown
