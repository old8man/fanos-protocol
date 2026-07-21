# Deploying a FANOS node

This is the operator guide for running a FANOS node on a real internet-facing server. A node joins
the anonymity overlay, relays and stores for its cell, and (optionally) hosts services or bridges to
the clear net. There is **no central infrastructure** to stand up — a node bootstraps from a handful
of peers you already know and derives everything else. See `docs/design.md` for the protocol itself;
this document is only about running the binary.

At a glance:

| | |
|---|---|
| **Binary** | `fanos` (built from `crates/fanos-node`) |
| **Transport** | QUIC over **UDP** — one listen port (default example: `9000/udp`) |
| **State** | one identity file (`id.bin`) that *is* the node's overlay coordinate |
| **Config** | a `key = value` file (`deploy/node.conf.example`) and/or CLI flags |
| **Privileges** | none — a plain unprivileged user and one UDP socket |

---

## 1. Build

### From source

The toolchain is pinned in `rust/rust-toolchain.toml` (a specific nightly); `rustup` installs it
automatically the first time you build.

```sh
cd rust
cargo build --release -p fanos-node --bin fanos
# → target/release/fanos
```

### As a container

The repository ships a multi-stage `Dockerfile` (build → slim runtime):

```sh
docker build -t fanos-node .
```

The image pins the same toolchain via `rust-toolchain.toml`, runs as an unprivileged user, and
persists the identity in the `/var/lib/fanos` volume.

---

## 2. Generate a persistent identity

A node's identity file is its overlay coordinate — self-certifying, so it needs no registration.
Generate it once and keep it:

```sh
fanos id --identity /var/lib/fanos/id.bin
# coordinate: 3:1:0
# identity file: /var/lib/fanos/id.bin
# bootstrap seed (add host:port): 3:1:0@HOST:PORT
```

The last line is the **bootstrap seed** other operators add to reach you — replace `HOST:PORT` with
your public address (see §5). Keep `id.bin` at mode `0600` and back it up: losing it means a new
coordinate; leaking it lets someone impersonate the node.

> An identity is optional. Omit `identity` and the node runs ephemerally with a fresh coordinate each
> start — useful for a throwaway client, wrong for a server you want peers to keep reaching.

---

## 3. Configure

Copy the example and edit it:

```sh
install -Dm644 deploy/node.conf.example /etc/fanos/node.conf
$EDITOR /etc/fanos/node.conf
```

The keys (`listen`, `identity`, `bootstrap`, `role`, `heartbeat`) are documented inline in the
example. An unrecognised key is a hard error, so a typo fails fast at start instead of silently
running with a wrong setting. Every key has an equivalent CLI flag that overrides the file, so you
can keep one config and tweak a single value on the command line:

```sh
fanos node --config /etc/fanos/node.conf --listen 0.0.0.0:9100
```

---

## 4. Run

### Under systemd (recommended for a server)

```sh
install -Dm755 target/release/fanos      /usr/local/bin/fanos
install -Dm644 deploy/fanos-node.service /etc/systemd/system/fanos-node.service
systemctl daemon-reload
systemctl enable --now fanos-node
journalctl -u fanos-node -f
```

The shipped unit (`deploy/fanos-node.service`) runs under a transient `DynamicUser`, keeps the
identity in a systemd-managed `StateDirectory` (`/var/lib/fanos`), restarts on failure, and is
sandboxed (no capabilities, read-only system, INET sockets only).

### Under Docker

```sh
docker run -d --name fanos \
  -p 9000:9000/udp \
  -v fanos-state:/var/lib/fanos \
  -v /etc/fanos/node.conf:/etc/fanos/node.conf:ro \
  fanos-node
```

Publish the port as **`/udp`** — QUIC is UDP, and a `-p 9000:9000` (TCP) mapping silently carries no
traffic. Keep the `fanos-state` volume across restarts and upgrades to keep the identity.

### In the foreground (for a quick check)

```sh
RUST_LOG=info fanos node --config /etc/fanos/node.conf
# fanos node up — coordinate 3:1:0 on 0.0.0.0:9000 (2 bootstrap peers)
```

---

## 5. Networking

* **Open the UDP port.** The `listen` port must be reachable from the internet. Example firewall
  rule: `ufw allow 9000/udp`.
* **NAT / port-forward.** Behind NAT, forward the same UDP port to the host and advertise the
  *public* `host:port` in your bootstrap seed. A node now **auto-discovers** the public address its
  peers observe it at (reflexive / STUN-like: peers report it, and a node trusts it once a quorum
  agree — `fanos_quic::ReflexiveAddr`, NAT traversal #119). Direct **hole-punching** for
  non-forwarded nodes is the remaining piece; until it lands a server still needs a reachable UDP
  port (forwarded or firewall-opened).
* **Pin the port.** Set `listen` to a fixed port (not `:0`) so the seed you hand out stays valid.

---

## 6. Join the network

FANOS has no central directory; you seed from peers you already know.

* **Joining an existing network** — get one or more seeds (`x:y:z@host:port`) from operators you
  trust and list them under `bootstrap`. Two or three independent seeds is plenty; the node discovers
  the rest of its cell from there.
* **Starting a new network (genesis)** — run the first node with no `bootstrap`. Its `fanos id`
  seed is what the second node bootstraps from, and so on.

Beacon/epoch parameters (the DVRF group commitment that drives the live epoch clock) are genesis
material provisioned out-of-band, not set in this file — a node without them runs correctly, pinned
at the genesis epoch.

---

## 7. Verify

* `systemctl status fanos-node` — running, not restart-looping.
* The startup line `fanos node up — coordinate X:Y:Z on <addr> (N bootstrap peers)` shows the
  coordinate and that the socket bound.
* Watch `journalctl -u fanos-node -f` for `member joined`, `epoch advanced`, and self-heal events
  (`rerouted`, `shard repaired`). Raise detail with `RUST_LOG=debug`.
* From another host, point a client's `--bootstrap` at your seed and confirm it reaches the cell.

---

## 8. Upgrades

1. Build/pull the new `fanos` binary.
2. Replace `/usr/local/bin/fanos` (or the image tag).
3. `systemctl restart fanos-node` (or recreate the container **with the same state volume**).

The identity file is forward-compatible; keeping `/var/lib/fanos` across the upgrade preserves the
node's coordinate and its place in the overlay.
