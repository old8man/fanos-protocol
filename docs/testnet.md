# Running a FANOS testnet

A **testnet** here means several independent operators, on separate machines, forming one cell together —
as opposed to `docs/deployment.md`, which is written from one operator's point of view and assumes someone
else already started the network they're joining. This document is the missing piece: how a *founding set*
comes into existence in the first place, and what a multi-operator launch can and cannot do today.

Everything below was read out of the code that ships (`crates/fanos-node/src/bin/fanos.rs`,
`crates/fanos-node/src/config.rs`, `crates/fanos-node/src/setup.rs`, `crates/fanos-keygen/`) and, where
cheap, run against a debug build. Where a step is not something the CLI can do yet, this document says so
by name rather than describing a path that doesn't exist.

---

## At a glance

| | |
|---|---|
| **Minimum viable cell** | 7 operators (one Fano plane, `q = 2` — the shipped default) |
| **Governance today** | the epoch beacon is **dealt**: one founder briefly holds the whole secret |
| **Governance available, not wired** | a real Byzantine-robust DKG exists (`fanos-keygen`) but has no CLI verb — see §7 |
| **Roles a cell should cover** | relay, storage, rendezvous (cheap, offer broadly); exit, service, ingress (opt-in, see §2) |
| **Convergence check** | `fanos status census` + `fanos status coherence` — see §5 |
| **Binary** | `fanos`, built from `crates/fanos-node`; `--features validator` adds the TAXIS chain, `--features vpn` the full-tunnel datapath |

---

## 1. How many nodes, and why

`docs/deployment-minima.md` derives this in closed form and measures it against a running node; this
section only applies its numbers to the founding question.

A FANOS cell is `PG(2, q)`, a projective plane with `q² + q + 1` points — one node per point. The smallest
one, `q = 2` (**Fano**), has **7** points, and `q = 2` is also what every node runs unless every operator
in the cell agrees to raise it (`NodeConfig::plane_order`, a cell-wide constant — see the caution in §3.5).
So the founding question is really "how many of the 7 seats do we fill", and the answer depends on what you
want from the cell:

| purpose | minimum | why |
|---|---|---|
| a working overlay (membership, storage, self-healing) | 7 | below 7 points, the cell reports itself unhealthy **by construction** — "a cell calls itself healthy only when the plane is complete" (deployment-minima §1) |
| TAXIS consensus, if you deal one (§3.6) | 5 of 7 present | quorum `Q = ⌈(n+f+1)/2⌉ = 5`; a Fano validator set survives 2 simultaneous failures and halts at 3 |
| serving storage reads after losses | 4 survivors | 3 survivors still serve 28 of the 35 four-loss patterns |
| a mixnet hop | 3 members of a line | sound at `q = 2` — see the anonymity caveat below |

**Fill all 7.** A cell smaller than 7 is not "a smaller testnet", it is an incomplete Fano plane that never
reports healthy, and every founding-operator step below assumes 7 people showed up. If fewer than 7 are
available, wait — there is no smaller valid cell above the coherence floor of 3 (deployment-minima §1,
Result 4), and 3–6 nodes sit in a regime this platform doesn't consider viable.

**One honesty check before you build on top of this:** `q = 2` is a **test fixture**, not an anonymity
system. `config.rs`'s own doc comment on `plane_order` and `deployment-minima.md` both derive the same
number: a passive adversary's flow-matching floor on the default plane is **0.50 — a coin flip**, because
only 4 of Fano's 7 lines have distinct combiners and that supports exactly 2 concurrent circuits. If the
testnet's purpose includes exercising the anonymity properties (not just connectivity, storage and
consensus), raise `--plane-order` — see §3.5's caution before you do, since it isn't free and it isn't
exposed by the `fanos init` wizard.

---

## 2. Roles a testnet must cover

A node's `--role` (or config file `role =`) is an **offer**, not a guarantee of duty: `RoleController`
(`fanos-core/src/roles.rs`) assigns who is *actually* doing what each epoch, as a deterministic,
beacon-seeded function of who offered what and how much the cell currently needs. So "covering a role"
means at least one — ideally several, for the controller to rotate across — of the 7 founding nodes offer
it.

| role | what it needs beyond `--role` | what breaks if nobody offers it |
|---|---|---|
| **relay** | a beacon (`--beacon-params`) — `Node::start` **refuses to start** a relay without one | no mixnet hops exist at all; `fanos proxy --profile anonymous` and `fanos host` have nothing to route through and refuse to start ("needs at least threshold+1 live mix relays") |
| **storage** | nothing extra | the overlay's L4 store has nowhere to place shards; every directory the platform rides on top of it (service descriptors, mix keys, exit listings, ingress keys, census) degrades with it |
| **rendezvous** | nothing extra | hidden-service hosting (`fanos host`) has no line to seat a service on — receiver anonymity for `.fanos` services is unavailable |
| **exit** | its own local secret (§3.5) — no coordination with anyone | `fanos proxy`'s clearnet path has no exit to discover and refuses non-`.fanos` targets; `fanos vpn` cannot start at all |
| **service** | a hand-assembled roster (§3.5) — no CLI ceremony exists for this one | threshold-hosted (CALYPSO) services have nowhere to be hosted |
| **ingress** | a per-community dealing (`fanos ingress-deal`, §3.5) | nothing breaks for the cell itself — ingress is the censorship-resistant *bootstrap* path for newcomers who can't reach the cell directly. Skip it unless the testnet is specifically exercising POROS |

Every founding node can safely offer `relay,storage,rendezvous` — none of the three need per-node secret
material beyond the shared beacon, so there's no reason not to spread that coverage across all 7. `exit`,
`service` and `ingress` are opt-in per §3.5.

---

## 3. Founding a cell, step by step

This is the **dealt** path — the only one `fanos` can drive today. §7 covers exactly what a DKG-based
founding would need instead, and why it isn't this section.

### 3.1 One founder deals the epoch beacon

Coordinates are `MapToPoint(VRF(sk, node ‖ epoch ‖ beacon))`, so whoever holds a reconstruction threshold
of the beacon's shares has real influence over where every future node lands (`docs/design-governance.md`
§2.1). One person has to go first; §6 states exactly what that costs.

```sh
fanos beacon-deal 7 5 --out ./ceremony/beacon
```

This draws a fresh secret from OS entropy, Shamir-splits it 5-of-7 (illustrative — any `1 ≤ t ≤ n` works;
5-of-7 tolerates 2 anchors being down or malicious before the epoch clock stalls, echoing TAXIS's own
5-of-7 consensus quorum), and writes:

* `anchor-1.beacon` … `anchor-7.beacon` — one per founding node, each carrying that node's secret share
* `consumer.beacon` — the public commitment and threshold only, for a node that should track the live
  epoch without being an anchor (a joining node later, §4)
* `recovery-authority.key` — **the most sensitive file in the ceremony.** It authorizes a future reshare
  or re-genesis of the beacon (the way out of an anchor-loss freeze). It is *not* split — the founder keeps
  this one file, offline, and never puts it on a running node. Its public half travels automatically inside
  every `.beacon` file above (`authority = …`), so nothing further needs distributing for it.

Hand `anchor-<i>.beacon` to founding operator `i` over a channel you trust (SSH, an encrypted messenger —
the tool doesn't specify one, and that gap is real; see §6). Each file carries that operator's secret
share: treat it like a private key, because a `VssShare` is exactly that.

### 3.2 Each founding operator generates a persistent identity

Independently, and in any order — a node's coordinate is VRF-derived from its identity key at *start*
time, not from which beacon share it holds, so there's no sequencing constraint between §3.1 and this step.

```sh
mkdir -p ~/.config/fanos            # see the path table below for your platform
fanos id --identity ~/.config/fanos/identity.key
```

```
coordinate: 4:1:0
identity file: /home/op/.config/fanos/identity.key
bootstrap seed (add host:port): 4:1:0@HOST:PORT
```

Replace `HOST:PORT` with your real, publicly reachable address and a port you intend to keep stable (this
runbook uses `9931`, the wizard's own default — `fanos-node/src/setup.rs::DEFAULT_PORT`). Open it in your
firewall; `docs/deployment.md` §5 covers NAT/port-forwarding and is not repeated here.

| install | config & identity | data |
|---|---|---|
| root (any OS) | `/etc/fanos/` | `/var/lib/fanos` |
| unprivileged Linux | `~/.config/fanos/` | `~/.local/share/fanos` |
| unprivileged macOS | `~/Library/Application Support/fanos/` | same |

(`fanos node --data DIR` / `fanos status --data DIR` override the data directory independently, if you'd
rather not use the platform default.)

### 3.3 Exchange seed addresses

All 7 operators post their `x:y:z@host:port` line from the previous step to each other — a shared
document, a group chat, whatever's convenient. These are **public**; nothing here is secret.

### 3.4 Start the founding nodes

A first foreground check, per operator, bootstrapped to two or three of the other six (not necessarily
all — the overlay discovers the rest by gossip, same as `docs/deployment.md` §6):

```sh
RUST_LOG=info fanos node \
  --listen 0.0.0.0:9931 \
  --identity ~/.config/fanos/identity.key \
  --beacon-params ~/.config/fanos/anchor-3.beacon \
  --role relay,storage,rendezvous \
  --bootstrap 1:0:0@peer1.example:9931,2:0:0@peer2.example:9931
```

The very first operator to actually start has zero live peers for a moment — expected, and the same
genesis behaviour `docs/deployment.md` §6 describes for a single-operator launch.

**Give every founding node a beacon file, not just the ones offering `relay`.** `Node::start` only *hard
requires* `--beacon-params` for `relay` — `storage` and `rendezvous` will start without one — but a node
with no beacon params runs a bare overlay pinned at genesis (epoch 0) forever, even while its beacon-tracking
peers advance. A cell where some members never advance is a cell that's only partly converged, so hand out
`consumer.beacon` (or, since you dealt exactly 7 anchor files for exactly 7 founders, everyone already got
an anchor file in §3.1 — use it) to all 7, whether or not each is a relay.

Once the foreground run looks right (§5), install it under supervision the way `docs/deployment.md` §4
describes (`fanos init`'s generated unit, or `deploy/fanos-node.service` by hand). Two things don't carry
over cleanly from that single-operator doc, and are worth stating precisely:

* The generated config *file* supports `role = …` and `beacon_params = <path>` directly
  (`node.conf.example` shows the format) — both are fine to put in a supervised unit's config.
* `--service`, `--exit` and `--ingress-params` have **no config-file key** — `NodeConfig::from_config_str`
  doesn't recognise them. They must be passed on the command line on every start, so a service/exit/ingress
  founding node's systemd `ExecStart=` needs hand-editing to add the flag; `fanos init` doesn't do this for
  you.

### 3.5 Optional: exit, service, and ingress coverage

These three are independent of each other and of the base founding step above — add any of them to any
subset of the 7 founding operators.

**Exit** — no ceremony, no coordination with anyone. Each operator who wants to bridge to the clear
internet under their own IP generates their own local identity seed:

```sh
printf 'seed = %s\nports = 80,443\n' "$(openssl rand -hex 32)" > exit.params
fanos node … --exit exit.params        # implies --role exit
```

Omit `ports =` to relay any destination port — an open relay, opted into explicitly. This is a real legal
decision (traffic other people send leaves under this host's address, and complaints arrive here); the
`fanos init` wizard prints the same warning if you take this role interactively.

**Service** (threshold CALYPSO hosting) — **there is no `fanos service-deal` tool.** Unlike the beacon and
ingress, a service line's members hold *independent* keys rather than shares of one split secret
(`fanos-calypso`'s hosting doc: "the operator generates each member's seed"), so assembling one is simpler
but entirely manual today:

1. Pick `M` of the 7 founders to host one service line and agree a threshold `T` (`1 ≤ T ≤ M`).
2. Each of the `M` independently runs `openssl rand -hex 32` for their own seed and reports their node's
   coordinate (from `fanos id`, once they've generated an identity — §3.2).
3. Each writes the **same** roster and threshold into their own file, differing only in `seed`:
   ```
   seed = <their own 64 hex chars>
   line = 4:1:0, 2:3:0, 0:0:1
   threshold = 2
   ```
4. `fanos node … --service service.params` (implies `--role service`).

**Ingress** (POROS censorship-resistant bootstrap, `docs/design-anonymity-substrate.md` §6) — for a
community that wants a moving-target set of entry peers a censored newcomer can bootstrap from without
already knowing the cell:

```sh
fanos ingress-deal my-testnet-community \
  1:0:0@relay1.example:9931 2:0:0@relay2.example:9931 3:0:0@relay3.example:9931 \
  --out ./ceremony/ingress
```

The peers listed are the *entry peers* newcomers land on — any reachable nodes of the cell, not necessarily
the line's own hosts. This writes one `ingress-<i>.poros` per line member (defaulting to a 3-member line —
the plane's own first 3 points — at 2-of-3, both overridable with `--line`/`--threshold`; the default line
assumes the Fano plane, so pass `--line` explicitly if the testnet runs at a higher `--plane-order`).

```sh
fanos node … --role ingress --ingress-params ingress-2.poros
```

**Both flags are required, and the failure modes are asymmetric — this is worth knowing before you hit
it.** `--role ingress` alone fails loudly at start ("needs ingress parameters… run `fanos ingress-deal`").
`--ingress-params` alone does *nothing* and **fails silently** — the file loads, the node starts clean, and
`ingress_params()` in `node.rs` simply returns `Ok(None)` because the role wasn't offered, so no
`IngressNode` is ever composed. Unlike `--service`/`--exit`, providing `--ingress-params` does not imply
the role. Pass both.

Once both are given, rotation is automatic: `Node::start` spawns `spawn_ingress_rotation` for any node
configured this way, so the line reshares itself to the next epoch's roster on its own — no separate driver
process to run. (This landed recently; older notes describing ingress as non-rotating are stale.)

### 3.6 Optional: a TAXIS validator cell

The blockchain is a **separate process and a separate network** from everything above — `fanos validator`
seats at a fixed consensus point (`Point::at(me)`, ground for that exact coordinate, not the VRF-derived
identity `fanos node` uses) and runs *only* consensus over the DROMOS ledger; it does not relay, store, or
host anything, and shares no state with a `fanos node` an operator might also be running. An operator who
wants both runs two independent processes on two ports. Needs a binary built with `--features validator`.

```sh
fanos taxis-deal --out ./ceremony/taxis --supply 1000000000
```

Writes `validator-0.taxis` … `validator-6.taxis`, `chain-info.taxis` (public — every future `fanos pay`
client needs it), and `founder.key` (secret — funds the genesis account; hand it to whoever should be able
to spend the initial supply). Each of the 7 operators:

```sh
fanos validator --config ./validator-3.taxis --listen 0.0.0.0:9932 \
  --bootstrap 1:0:0@peer1.example:9932,2:0:0@peer2.example:9932,…
```

using the *other six* validators' `--bootstrap` coordinates (all fixed, printed by `taxis-deal`), on a
different port from the overlay node if both run on the same host.

---

## 4. Joining an existing testnet

A joining operator needs, from any existing member: two or three bootstrap seeds, and — if they intend to
relay — the cell's beacon material. Since they aren't one of the original anchors, they get the founder's
`consumer.beacon` (public commitment + threshold, no share): enough to verify and adopt the live epoch,
not to contribute a partial. If the testnet runs a non-default `--plane-order`, they need that too, and it
must match exactly.

```sh
fanos init --role relay,storage --bootstrap 1:0:0@peer1.example:9931,2:0:0@peer2.example:9931
```

Because `--bootstrap` is non-empty, the wizard knows this is a join, not a genesis: it asks (or, with
`--yes`, requires) a path to the cell's beacon file rather than dealing its own. Or, the fully explicit
form that skips the wizard entirely (also the only option if the cell runs a non-default plane order —
`fanos init` doesn't expose `--plane-order`):

```sh
fanos node --listen 0.0.0.0:9931 --identity ~/.config/fanos/identity.key \
  --beacon-params ./consumer.beacon --role relay,storage \
  --bootstrap 1:0:0@peer1.example:9931,2:0:0@peer2.example:9931
```

Then supervise it exactly as `docs/deployment.md` §4 describes — nothing about running under systemd or
Docker differs for a joining node.

---

## 5. Verifying convergence — and telling it apart from merely started

A bound port and a `fanos node up` line prove one process is alive. They don't prove the cell holds
together. Right after several nodes start, query any one of them:

```sh
fanos status census
fanos status coherence
```

**Just started** looks like this: `census`'s `healthy` count is low, with nonzero `silent` or
`unreachable` (nobody has published a coherence reading yet); `coherence` times out with "this node cannot
yet see its cell (too few peers, or no heartbeats have completed a window)"; `fanos status roles` shows
roles *offered* but nothing *assigned* yet, because the self-organizing role loop needs a beacon round
before it assigns anything.

**Converged** looks like this:

* `fanos status census` — `healthy` ≈ 7 (your founding count), `silent = 0`, `unreachable = 0`, verdict
  *"not network-wide — most answering cells are healthy."*
* `fanos status coherence` — a real Φ / purity / alarm reading, not a timeout.
* `fanos status roles` — assigned roles actually filled in, not just offered.
* `fanos status stations` (on a relay or rendezvous node) — real gather-station numbers, not "no answer
  within the probe timeout."
* Logs (`RUST_LOG=info`) show `member joined` for every founding peer, and — only if every node was given
  beacon params per §3.4's caution — periodic `epoch advanced` lines roughly every `epoch_period` (default
  600 s). A cell that never logs `epoch advanced` is pinned at genesis, even if every peer shows connected.
* All **7** of the Fano plane's points are occupied, not "most nodes are up" — deployment-minima.md's own
  finding is that a cell reports healthy only when the plane is complete.

**The most convincing proof is end-to-end**, not a status readout: have one founding operator host a toy
service, and another dial it anonymously.

```sh
head -c 32 /dev/urandom > svc.key
fanos host --forward 127.0.0.1:8000 --host-key svc.key --threshold 2
#  … prints:  address: <name>.fanos
```

From a different node:

```sh
fanos proxy --profile anonymous --threshold 2 --bootstrap 1:0:0@peer1.example:9931
curl --socks5-hostname 127.0.0.1:1080 http://<name>.fanos/
```

A successful fetch means the mixnet drew a fresh threshold-onion route, a rendezvous line combined it, and
the host's forward reached a real local port — the cell's substance, not just its bookkeeping.

---

## 6. What the dealt beacon costs

Say this plainly, because it's a governance position and not an implementation detail
(`docs/design-governance.md` §2.1 makes the same point): **from the moment `fanos beacon-deal` runs until
that process exits, the operator who ran it holds the entire cell's epoch-beacon secret — the value every
future node's coordinate is derived from.** Splitting it into shares happens in the same breath, but for
that moment, one person had the whole thing. This is exactly what `fanos beacon-deal`'s own doc comment
says about itself: "a single-operator convenience… a trust-minimized deployment runs the networked DKG
instead, so no one party ever holds it."

That is a defensible choice for a testnet — the founding operators presumably already trust each other more
than they trust an unbuilt tool — but it is not free, and it does not become free just because the secret
was split a moment later:

* The founder briefly saw randomness that determines where every node — including ones that join months
  later — lands on the plane.
* The channel used to hand out `anchor-<i>.beacon` in §3.1 is unspecified by the tooling. Whoever
  transmits a share insecurely is the actual leak, and the code has no opinion on how you do that part.
* `recovery-authority.key` is a standing, ongoing trust root, not a one-time cost: whoever holds it can
  authorize a reshare or re-genesis for the life of the cell, by design (it's what recovers a cell that
  loses too many anchors). Keeping it "offline" is a promise the tooling cannot enforce.

None of this is a reason not to launch. It is a reason to say, in whatever the testnet's own operator
documentation is, who dealt it and what they promise to do with `recovery-authority.key` — the same
reasoning `docs/design-governance.md` §2.1 already applies to a public launch, at smaller scale.

---

## 7. The DKG choreography, as far as the code supports it

`docs/design-governance.md` §2.1 says a distributed alternative exists and names only what's missing as
"the operational choreography." Here is exactly what that means, read from `crates/fanos-keygen/`.

### What exists

`DkgNode<F>` (`fanos-keygen/src/lib.rs`) is a sans-I/O `Engine` — the same kind of thing `OverlayNode`,
`BeaconNode` and every other production engine in this tree is — running the classic Feldman/Pedersen DKG
with a Gennaro–Jarecki–Krawczyk–Rabin complaint round:

1. **Sharing.** Each of the `n` participants deals a Feldman VSS of a secret *it alone chose* (drawn from
   OS entropy locally — never transmitted whole): broadcasts a public commitment, privately sends every
   other participant its share.
2. **Complaint.** A participant missing or holding an invalid share from some dealer broadcasts a
   complaint against it.
3. **Justification.** The accused dealer answers by revealing the complainer's correct share, checked
   against the *commitment everyone already qualified on* — not one carried in the justify frame itself
   (this exact substitution was audit finding B3, CRITICAL, now closed).
4. **Finalize.** The qualified set `QUAL` (dealers with a commitment and no unanswered complaint) must
   reach the threshold; each participant folds exactly `QUAL`'s shares into its own final share and sums
   their commitments into the joint public key, so every honest node ends up agreeing on the same aggregate
   even against a Byzantine dealer that deals validly to some members and not others.

Every control frame is authenticated to its claimed origin (a forged complaint or commitment is rejected
and *counted* — `DkgRejects` — not merely dropped), so a minority of malicious participants cannot evict an
honest dealer or forge disagreement. `fanos-sim/tests/dkg.rs` drives 7 real `DkgNode`s — including one
deliberately equivocating — to completion and checks that all 7 land on an identical aggregate commitment
and that each one's own final share verifies against it: **the cryptography and the protocol logic are
built and tested.**

The output maps directly onto what a node needs to run the live epoch clock: `aggregate_commitment()` is
`BeaconParams::commitment`, `final_share()` is `BeaconParams::share`, and the threshold is whatever was
agreed going in — the same three fields `fanos beacon-deal` writes today, just arrived at without anyone
ever holding the whole secret.

### What does not exist

* **No CLI verb.** `bin/fanos.rs`'s dispatch table has `node`, `proxy`, `host`, `message`, `validator`,
  `pay`, `vpn`, `init`, `start`/`stop`/`restart`, `uninstall`, `status`, `id`, `beacon-deal`,
  `ingress-deal`, `taxis-deal`, `resolve`, `help` — nothing named `keygen` or `dkg`. `DkgNode` has never
  been instantiated outside `fanos-sim`'s test harness: never run as its own OS process, never sent a real
  frame over real QUIC between two machines. It has never been wired the way `spawn_taxis` or
  `spawn_rendezvous_host` wire their engines onto a real transport.
* **No provisioning-file writer for a DKG run's output.** `BeaconParams::to_config_string()` — the format
  every anchor file uses — already exists and needs no changes; nothing currently calls it from a
  `DkgNode`'s `final_share()` / `aggregate_commitment()`.
* **The recovery authority is untouched by the DKG entirely**, and this is worth stating precisely because
  it's easy to assume the DKG closes the whole governance gap in §2.1 and it does not: `DkgNode` has no
  concept of a recovery-authority keypair. Even a fully-wired `fanos keygen` would still need the exact
  manual step `beacon-deal` uses today — one party generates a `HybridSigSecret`, keeps the seed offline,
  and distributes only the public verifier. The DKG removes single-party trust from the *beacon secret*; it
  does nothing for the *recovery authority* unless a second ceremony is designed for that too.
* **No discovery/transport step** for "these `n` operators, each on their own machine, are all in the same
  run." `fanos-sim`'s test wires every `DkgNode` directly in one process over a hand-rolled bus; a real
  multi-operator run needs the participants reachable by network address first.

### What building it would concretely require

Naming this precisely, so it's a scoped piece of work rather than an open question:

1. A CLI verb — e.g. `fanos keygen --n 7 --t 5 --index <1..7> --listen ADDR --bootstrap <other peers>
   --out DIR` — that draws this operator's own secret and session nonce from OS entropy, seats a
   `DkgNode::<F>::new(Point::at(index-1), t, secret, nonce)` on a real transport reaching the other `n-1`
   participants (very likely `spawn_self_certifying_persistent_on`/`_over` at a *fixed* point, the same
   pattern `fanos validator` already uses to seat at `Point::at(me)` — `DkgNode` already addresses peers by
   `coord_of(index)`, a fixed point, so this is closer to `taxis-deal`'s ceremony shape than to a normal
   VRF-seated node), waits for `Notification::DkgComplete`, and writes this participant's own
   `anchor-<index>.beacon`-equivalent file from `final_share()` + `aggregate_commitment()` + `t` — in the
   same `BeaconParams::to_config_string()` format already in use, so nothing downstream of this document's
   §3.4 needs to change once the file exists.
2. The recovery-authority step above, run separately and manually, exactly as today.
3. All `n` founding operators running step 1 at roughly the same time — the library's sharing/complaint
   deadlines default to 1.5 s each (`DEFAULT_SHARE_DEADLINE`/`DEFAULT_COMPLAINT_DEADLINE`), tuned for a
   simulated bus, not real network latency plus human coordination across operators in different locations.
   What deadline a real multi-operator ceremony needs is itself unmeasured.

Until this exists, **the dealt path in §3.1 is the only one `fanos` can drive**, and §6's costs apply to
every testnet founded from this document today.

---

## 8. What this testnet still cannot do

Verified against the code, not copied from an earlier claim:

**Trust in the binary.** Releases are unsigned — `docs/design-upgrade.md` §6 names "signed releases" as
still needed, and nothing in `.github/workflows/ci.yml` signs a build artifact. Every operator in the
testnet is building from source, which means every operator is also a point where the source could differ
from what everyone else built. `docs/design-governance.md` §2.3: "open source does not decentralize the
binary."

**No running node builds an ERGON term.** `fanos-ergon` is a workspace member, but neither `fanos-node` nor
any binary depends on it (`crates/fanos-node/Cargo.toml` has no such dependency; only `fanos-sim` and
`fanos-dromos` do). Whatever ERGON's execution model proves on paper, no process this testnet runs
constructs or serializes one.

**A hole-punch that fails has never been exercised against a real NAT.** Direct hole-punch initiation is
now wired (`docs/deployment.md` §5), but every test of it runs over loopback or a simulated fabric, neither
of which can produce a punch that genuinely fails the way a symmetric NAT does — which is the exact case
the relay fallback exists for. On home connections, whether that fallback actually engages when it needs to
is untested. No harness for it exists yet.

**A hidden service's reachability across a live epoch turn is unmeasured.** `fanos host`
(`spawn_rendezvous_host`) does follow the beacon and re-registers at each new meeting line as epochs
advance — it is not pinned. But every anonymous end-to-end test in the tree pins a fixed epoch instead of
turning one under a running host and then dialing (`crates/fanos-node/tests/anonymous_quic.rs` uses
`Epoch::new(4)`, `Epoch::new(5)`, and `Epoch::ZERO` as constants throughout, including in the one test that
exercises the full `spawn_rendezvous_host` driver). A client and a host derive their meeting line from
`(epoch, beacon)` independently, so if either computes it a moment before the other during a turn, whether
the old registration covers that window is unverified. If a hidden service on this testnet goes briefly
unreachable once per `epoch_period` (default 600 s), that is this gap, not a bug report waiting to happen —
it just hasn't been measured either way.

**POROS ingress lines do now rotate** — `Node::start` spawns `spawn_ingress_rotation` automatically for any
node given `--role ingress --ingress-params FILE` (§3.5), landed after the receive half was built. Listed
here only because earlier notes described ingress as non-rotating, and that's now stale.

**Two CLI sharp edges worth knowing before they cost you an hour:**

* `fanos <verb> --help` does not print that verb's usage. Only bare `fanos help` (or no arguments) does —
  the dispatch table checks for `help`/`--help`/`-h` at the *top level* only. `fanos node --help` silently
  starts a real node, with `--help` treated as an unrecognized, ignored argument (verified by running it).
* `--service`, `--exit` and `--ingress-params` have no config-file key — see §3.4's callout — and
  `--ingress-params` alone silently does nothing without `--role ingress` alongside it, while every other
  parameterized role (`service`, `exit`) auto-enables its own role flag — see §3.5.

---

## Quick command reference

| do this | run this |
|---|---|
| deal the cell's epoch beacon | `fanos beacon-deal <n> <t> --out DIR` |
| generate/show an identity | `fanos id --identity PATH` |
| run a node, foreground | `fanos node --listen ADDR --identity PATH --beacon-params FILE --role LIST --bootstrap SEED,…` |
| single-operator setup wizard | `fanos init [--yes] [--role LIST] [--bootstrap SEED,…]` |
| check setup + ask a running node | `fanos status [health\|roles\|coherence\|census\|stations\|consensus]` |
| host a hidden service | `fanos host --forward HOST:PORT --host-key FILE --threshold T` |
| dial anonymously | `fanos proxy --profile anonymous --threshold T --bootstrap SEED,…` |
| deal a community's ingress line | `fanos ingress-deal COMMUNITY PEER… --out DIR` |
| deal a TAXIS validator cell | `fanos taxis-deal --out DIR` (needs `--features validator`) |
| run a validator | `fanos validator --config validator-<i>.taxis --listen ADDR --bootstrap COORD@HOST:PORT,…` |

See also: `docs/deployment.md` (single-node operations, systemd/Docker, upgrades), `docs/deployment-minima.md`
(the derivations behind every number in §1), `docs/design-governance.md` (the power question this document
only operationalizes).
