//! The node's **local control socket** — how an operator asks a *running* node anything.
//!
//! Before this, a live node was opaque from outside its own log. `fanos status` could report what the host was
//! *configured* to be and whether something held the port, which is the difference between reading a plan and
//! reading a system; and the observatory, whose whole purpose is watching a cell, could only watch a simulated
//! one. Both had the same missing piece: no way to ask the process.
//!
//! ## Why a Unix socket, and why no authentication
//!
//! The socket is created inside the node's own state directory at mode `0600`, so the filesystem *is* the
//! authorization — the same mechanism that already protects the identity key sitting beside it. That is not a
//! shortcut around auth; it is the correct auth for this boundary, and it is strictly stronger than the
//! alternatives. A TCP port would need a credential to be safe, and a credential needs provisioning, rotation and
//! a place to live — every one of which is a new way for an operator to lock themselves out of their own node, in
//! exchange for guarding a boundary the kernel already guards.
//!
//! It also means the control plane cannot be reached from the network at all, which is the property that matters:
//! a node whose whole job is accepting traffic from strangers must not have an administrative surface those
//! strangers can address.
//!
//! ## The protocol
//!
//! One request word per connection, one response, close. Line-oriented text, because the thing on the other end is
//! as often a person with `socat` as it is this binary, and a format a human can read without a tool is a format
//! that gets used when something is wrong.

use core::fmt::Write as _;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

use fanos_runtime::ports::stations::{GatherHealth, Observation};
use fanos_telemetry::CoherenceFrame;
use fanos_wire::activation::Derivation;

use crate::node::Health;

/// The socket's name inside the node's state directory.
pub const SOCKET_FILE: &str = "admin.sock";

/// The longest `sun_path` a Unix socket address can hold, minus slack for the terminator.
///
/// A hard kernel limit, not a convention: `sockaddr_un.sun_path` is 104 bytes on macOS and BSD, 108 on Linux.
/// Bind past it and the call fails with a message about `SUN_LEN` that says nothing about which path was too
/// long. 100 is the smaller platform's limit with room to spare, so the same node has the same socket everywhere.
const MAX_SOCKET_PATH: usize = 100;

/// The control socket's path for a node whose state lives in `data`.
///
/// Beside the state, where it belongs and where an operator will look for it — **unless** that path would exceed
/// what a socket address can hold, in which case it moves to a short name in the temporary directory, derived
/// from the data directory so both the node and `fanos status` compute the same one with no pointer file between
/// them to go stale.
///
/// The fallback is not hypothetical. It fires for a container mount a few levels deep, a long user name under an
/// XDG home, or any of the paths a packaging system picks — and found here by running a node from a scratch
/// directory, where it failed with nothing but `path must be shorter than SUN_LEN`.
#[must_use]
pub fn socket_path(data: &Path) -> PathBuf {
    let natural = data.join(SOCKET_FILE);
    if natural.as_os_str().len() <= MAX_SOCKET_PATH {
        return natural;
    }
    let digest = fanos_primitives::hash_labeled("FANOS-v1/admin-socket", data.as_os_str().as_encoded_bytes());
    let mut name = String::from("fanos-");
    for byte in digest.iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    name.push_str(".sock");
    std::env::temp_dir().join(name)
}

/// What an operator can ask a running node.
///
/// Deliberately small. Every verb here is either a question or a shutdown, and that is the whole surface a control
/// socket needs to justify existing: an administrative channel that can *reconfigure* a node is a channel that can
/// misconfigure it, and the configuration file is already the place where such changes are reviewable and survive
/// a restart.
#[derive(Debug)]
pub enum Request {
    /// Liveness only — the cheapest possible "is it there".
    Ping,
    /// The node's current [`Health`].
    Health,
    /// The roles the **cell** has assigned this node, which is not always what its config offered.
    Roles,
    /// A **census** of the cells this node can see — the answer to "is this my cell, or the network?".
    ///
    /// Reads every cell coordinate's published ε-private coherence frame for the current epoch and reports the
    /// distribution: healthy, alarmed, silent, unreachable. Slower than the other verbs by design — it goes to
    /// the overlay store rather than to local state — and issued serially, since a monitor that fans out over a
    /// federation at once is a load spike on a network it may be asking about because it is under load.
    Census,
    /// **Why this validator sits where it does** — the consensus engine's own position and the counters behind it.
    ///
    /// Everything `ConsensusProbe` carries: height and round, whether it is locked and on what, the body it is
    /// waiting for, proposals refused *by cause*, the skeleton/shard/body/sync exchange counts, the vote arrivals
    /// bucketed against our own round, and any parked decision. Rendered by the probe's own `Display`, which is the
    /// dense one-validator-per-line form these are read in.
    ///
    /// It exists because every one of those counters was added while a live cell was stuck and its state could not
    /// be read — from a test harness. The operator of a stuck validator is exactly who needs them, and was exactly
    /// who could not get them. A role that runs no chain answers so rather than inventing a reading.
    Consensus,
    /// **The data-path plane** — where work is stopping, and how healthy the gather path is.
    ///
    /// The station counters and the measured gather deadline (`docs/design-observability.md` §4.1). Every one
    /// of these was computed and thrown away: #55 was localized by hand-inserting eight `eprintln!` probes and
    /// eliminating eleven candidate causes one at a time, while the two facts that actually solved it — every
    /// circuit through a point dead, gathers expiring at `1` of `t = 2` by the hundreds — were sitting in the
    /// process's own control flow and nothing recorded them. This is the verb that reads them from a running
    /// node, which is exactly the position that could not.
    ///
    /// It is also the **first production caller of `Command::Observe`**. The sense-only read had existed with
    /// only the simulator issuing it, so the whole passive-observation path — the coherence frame included —
    /// was exercised nowhere a deployed node runs.
    ///
    /// Answered off the loop, like `census`: it round-trips a command through the engine, and an operator's
    /// question is not worth pausing the node it is about.
    Stations,
    /// **This node's own coherence frame** — Φ, purity, reflection, the Fano syndrome, the forecast.
    ///
    /// The coherence plane, where `stations` is the data-path plane: "is the organism healthy?" beside "is the
    /// work getting done, and where does it stop?". `docs/design-observability.md` §1 is about needing both,
    /// and the socket served only the second.
    ///
    /// It also closes the gap `fanos-observatory` names in its own module doc — "a **remote** source,
    /// subscribing to a running node's telemetry stream, implements the same `SnapshotSource` and drops in
    /// behind this one". The monitor could render a scripted scenario or a simulated cell and never a deployed
    /// node, because a deployed node had no way to say what it saw. This is that way.
    ///
    /// Distinct from `census`, which reads every *peer's* published ε-private frame out of the overlay store:
    /// this is the node's own reading, unprivatized, local, and immediate — the operator asking their own node,
    /// which §3's R4 is explicit costs no anonymity.
    Coherence,
    /// Ask the node to shut down cleanly.
    Shutdown,
}

impl Request {
    /// Parse a request word, case-insensitively.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word.trim().to_ascii_lowercase().as_str() {
            "ping" => Some(Self::Ping),
            "health" => Some(Self::Health),
            "roles" => Some(Self::Roles),
            "census" => Some(Self::Census),
            "consensus" => Some(Self::Consensus),
            "stations" => Some(Self::Stations),
            "coherence" => Some(Self::Coherence),
            "shutdown" => Some(Self::Shutdown),
            _ => None,
        }
    }

    /// Every verb, for the error message a wrong one gets.
    #[must_use]
    pub const fn all() -> &'static str {
        "ping | health | roles | census | consensus | stations | coherence | shutdown"
    }
}

/// A request paired with the channel its answer goes back on.
pub type Envelope = (Request, oneshot::Sender<String>);

/// [`ask`], without a runtime — write a verb, read the answer, on the calling thread.
///
/// The async form is right for the CLI, which is already inside tokio. It is wrong for a caller that is not:
/// `fanos-monitor` is a terminal UI whose `SnapshotSource::tick` is synchronous, and making it carry a runtime
/// to send nine bytes down a Unix socket would be a dependency chosen by an accident of the client's colour.
///
/// The two share the protocol by being read together — write the verb, a newline, then read to EOF — and share
/// [`socket_path`], which is the part that must not drift: its `SUN_LEN` fallback is derived, and a second
/// implementation of *that* is how a monitor ends up looking in a different place from the node it monitors.
///
/// `Ok(None)` means "not running", the same distinction [`ask`] draws: no socket, or a stale one nobody is
/// accepting on. Collapsing that into an error would make a monitor unable to tell a stopped node from a
/// broken one, which is the first thing its operator needs to know.
///
/// # Errors
/// Any I/O failure other than a missing or refused socket.
pub fn ask_blocking(path: &Path, request: &str) -> std::io::Result<Option<String>> {
    use std::io::{Read as _, Write as _};
    let mut stream = match std::os::unix::net::UnixStream::connect(path) {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    stream.write_all(request.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut body = String::new();
    stream.read_to_string(&mut body)?;
    Ok(Some(body))
}

/// Render a [`Health`] as the socket's response body.
///
/// `key: value` lines, aligned, one fact per line — parseable with `cut` and readable without anything. The
/// `verified_claims` and `probe_index` fields are carried through rather than summarized, because their whole
/// reason for existing is telling apart two failures that look identical from outside.
#[must_use]
pub fn render_health(health: &Health) -> String {
    use std::fmt::Write as _;
    let [x, y, z] = health.address;
    let mut s = String::new();
    // **First, because it qualifies every line below it** (#165). `reflexive: false` is not a degraded
    // reading, it is an *absent instrument*: on a plane above `q = 2` nothing tells a node which seven peers
    // are its cell, so there is no coherence self-model, no liveness diagnosis and no §6.7 healing — and every
    // other field here still reads healthy, because the component that would say otherwise is the one that is
    // missing. It was added to `Health` so an operator would be told, and then was not printed, which left the
    // warning one hop from the person it was written for.
    if health.reflexive {
        let _ = writeln!(s, "reflexive: yes");
    } else {
        let _ = writeln!(
            s,
            "reflexive: NO — no coherence self-model, no liveness diagnosis, no §6.7 healing on this plane; \
             the readings below describe transport only"
        );
    }
    let _ = writeln!(s, "coordinate: {x}:{y}:{z}");
    let _ = writeln!(s, "listen: {}", health.local_addr);
    let _ = writeln!(s, "known_peers: {}", health.known_peers);
    // Reported unconditionally, including the zero. A counter that appears only when non-zero teaches an
    // operator that its absence means "not measured" — and this is a health signal about the *cell*, since a
    // peer that stops draining is what makes it move (#89).
    let _ = writeln!(s, "send_drops: {}", health.send_drops);
    // The same rule, applied to the two detectors #149 gave a reader and this renderer then did not print.
    // `collisions` is documented as the signal a node *reacts* to by relocating instead of silently shadowing
    // a peer, and `unresolved_drops` as the difference between a quiet cell and one this node cannot address
    // — neither of which it can be, from a field nothing renders. Zeros included, for the reason above.
    let _ = writeln!(s, "collisions: {}", health.collisions);
    let _ = writeln!(s, "unresolved_drops: {}", health.unresolved_drops);
    match health.verified_claims {
        Some(n) => {
            let _ = writeln!(s, "verified_claims: {n}");
        }
        None => {
            let _ = writeln!(s, "verified_claims: none (no self-certifying identity)");
        }
    }
    match health.probe_index {
        Some(i) => {
            let _ = writeln!(s, "probe_index: {i}");
        }
        None => {
            let _ = writeln!(s, "probe_index: unclaimed");
        }
    }
    let _ = writeln!(s, "roles_offered: {:?}", health.roles);
    s
}

/// This build's **derivation vector**, as a digest: one hash over every registered derivation's
/// `(name, activation_height)`, in `Derivation::ALL` order.
///
/// `docs/design-upgrade.md` §4 wants agreement to be *legible* rather than inferred. Two operators comparing
/// this one value know their nodes agree on every registered height; different values mean the schedules
/// differ, and that is knowable **before** an activation rather than after a line has gone quiet — which is the
/// operational claim, since "the schedule *is* the build" and a node that disagrees about heights is a node
/// running a different release.
///
/// A **digest, not the vector**, and the difference is a privacy one. Every node on a release yields the same
/// digest, so it distinguishes releases without enumerating which features a particular node does and does not
/// carry — §4 is explicit that a version vector is node-identifying metadata. It is still a build fingerprint,
/// so like the station counters it stays **local**: read off an operator's own control socket, never exported
/// across a node boundary until the DP sensitivity for it is derived the way `Δr = 1/21` was for the coherence
/// frame.
///
/// The name is hashed alongside the height so that *renaming* a derivation — which changes what a height means
/// — changes the digest; hashing heights alone would call two different schedules identical.
///
/// It lives here rather than beside the registry because `fanos-wire` has no hash to reach for:
/// `fanos-primitives` depends **on** it, which is the same dependency fact that made `is_active_at` take a
/// bare `u64` instead of an `Epoch`.
#[must_use]
pub fn derivation_digest() -> [u8; 32] {
    digest_of(Derivation::ALL.iter().map(|d| (d.name(), d.activation_height(), d.abort_height())))
}

/// The digest of an arbitrary schedule — the body of [`derivation_digest`], taken as input.
///
/// Factored so a test can vary **one dimension at a time** against the real hashing. The first version of that
/// test built a comparison vector by hand and asserted it differed; it passed with the abort height removed
/// from the digest entirely, because the two inputs differed in *length* whatever the function did. Isolating a
/// dimension means feeding the same function two schedules that differ only in it.
fn digest_of<'a>(entries: impl Iterator<Item = (&'a str, u64, Option<u64>)>) -> [u8; 32] {
    let mut input = Vec::new();
    for (name, activation, abort) in entries {
        input.extend_from_slice(name.as_bytes());
        input.push(0);
        input.extend_from_slice(&activation.to_be_bytes());
        // The **abort** height too. Arming one is a change to the schedule — a build that intends to withdraw
        // a derivation is not on the same schedule as one that does not — and a digest that ignored it would
        // report the two as agreeing. That is the silent derivation change §1 exists to make visible,
        // reintroduced inside the instrument built to reveal it. `u64::MAX` stands for "no abort" so an absent
        // height and a real one at 0 cannot hash alike.
        input.extend_from_slice(&abort.unwrap_or(u64::MAX).to_be_bytes());
    }
    fanos_primitives::hash::hash_labeled("FANOS-v1/derivation-vector", &input)
}

/// Render the data-path plane as the socket's response body.
///
/// One station per line, **only where the count is non-zero**: a node reports `stations × lines` counters and
/// printing them all at zero buries the two that moved, which is the diagnosis-by-thin-evidence this plane
/// exists to end rather than reproduce. A wholly quiet plane says so in words, because an empty response and a
/// broken verb look identical.
///
/// Lines are named by coordinate where the site knew one. An unattributed count is printed as such rather than
/// folded into a bucket: a frame that failed to parse has no readable line, and inventing one would put
/// fabricated evidence against a line into the plane built to end exactly that.
#[must_use]
pub fn render_data_path(stations: &[Observation], gather: GatherHealth, epoch: u64) -> String {
    let mut out = String::new();
    let mut moved = 0usize;
    for o in stations.iter().filter(|o| o.count > 0) {
        moved += 1;
        // The tag is printed only where a site recorded one, which is only the skew station — an operator
        // reading `frame.type_unknown  line 1:0:1  tag 47  312` has the whole of §4's question in one line:
        // what disagrees, where, and how much.
        let tag = o.tag.map_or_else(String::new, |t| format!("  tag {t}"));
        match o.line {
            Some([x, y, z]) => {
                let _ = writeln!(out, "{:<24} line {x}:{y}:{z}{tag}  {}", o.station.name(), o.count);
            }
            None => {
                let _ = writeln!(out, "{:<24} unattributed{tag}   {}", o.station.name(), o.count);
            }
        }
    }
    if moved == 0 {
        out.push_str("no station has fired: nothing has been discarded, expired or refused\n");
    }
    // The derivation vector rides with the data-path plane rather than getting its own verb: an operator
    // reading "where is work stopping" is one question away from "and is this node on the same schedule as the
    // line that is stopping" — §4's two halves, which are only useful together.
    let digest = derivation_digest();
    let _ = writeln!(
        out,
        "derivation_vector        {}",
        digest.iter().take(8).fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    );
    // The digest answers "do two nodes agree"; this answers "on what". An operator whose digests differ needs
    // the second question immediately, and a hash cannot be diffed.
    for d in Derivation::ALL {
        let status = d.status_at(epoch);
        // The scope is on this line because it is what an operator needs before planning a rollout: it says
        // which canary units are admissible at all, and getting that wrong is not a slower rollout but a dead
        // line (§2 ∧ §3).
        // The scope is printed as its **consequence**, not its label. "line-scoped" is a fact about the
        // derivation; "canary by cell only" is what the operator has to do about it, and getting that wrong
        // is not a slower rollout but a dead line (§2 ∧ §3).
        let canary = if d.scope().allows_node_canary() {
            "canary per node ok"
        } else {
            "canary by cell only"
        };
        let _ = write!(
            out,
            "  {:<22} {} at {} ({}-scoped, {canary})",
            d.name(),
            status.name(),
            d.activation_height(),
            d.scope().name()
        );
        match d.abort_height() {
            // Named even when far off: a scheduled withdrawal is the single most important thing on this
            // line, and an operator should never learn of one by watching a derivation stop working.
            Some(h) => {
                let _ = writeln!(out, ", withdrawn at {h}");
            }
            None => {
                let _ = writeln!(out, ", permanent");
            }
        }
    }
    match gather {
        // Milliseconds: the deadline lives in the 1 ms .. 10 s band its bounds define, and nanoseconds there
        // are six digits of noise in front of the one an operator reads.
        GatherHealth::Measured { srtt, var } => {
            let _ = writeln!(
                out,
                "gather_deadline          srtt {} ms  var {} ms",
                srtt.as_nanos() / 1_000_000,
                var.as_nanos() / 1_000_000
            );
        }
        // A finding, not a shrug: there is a gather path and nothing has completed on it, so the engine is
        // running on its initial estimate rather than on anything it observed.
        GatherHealth::Unmeasured => {
            out.push_str("gather_deadline          unmeasured — no gather has completed\n");
        }
        // Not a finding at all, and printed differently for that reason: this engine has no threshold gather,
        // so there is no deadline to be right or wrong about.
        GatherHealth::NoGatherPath => {
            out.push_str("gather_deadline          n/a — this node runs no threshold gather\n");
        }
    }
    out
}

/// Render a [`CoherenceFrame`] as the socket's response body.
///
/// `key: value` lines like [`render_health`], so the two read alike and both parse with `cut`. The measures are
/// printed to three decimals: they are `f32` ratios in `[0, 1]`, and more digits would suggest a precision the
/// estimator does not have.
///
/// The **verdict and syndrome are printed as their numbers as well as their meanings**, because an operator
/// comparing two nodes needs a value that compares, and a reader diagnosing one needs a word that explains.
#[must_use]
pub fn render_coherence(frame: &CoherenceFrame, degraded: u8, alive: u16) -> String {
    let mut out = String::new();
    // `wire` first and on one line: the canonical `Wire` bytes of the frame, hex. A monitor decodes this and
    // gets exactly what the node holds; everything below it is the same data rendered for a person. Serving
    // both is what lets the human form stay readable — it does not have to double as a parsing target, which
    // is how a rendering ends up frozen by a scraper that depends on its column widths.
    let _ = writeln!(out, "wire           : {}", frame.encode().iter().fold(String::new(), |mut a, b| {
        let _ = write!(a, "{b:02x}");
        a
    }));
    let down: Vec<String> = (0..8).filter(|i| degraded & (1u8 << i) != 0).map(|i| i.to_string()).collect();
    let _ = writeln!(out, "alive          : {alive}");
    // As the SET of points, not the mask value: the frame's syndrome localizes one fault, and this exists
    // precisely because there may be several — a number the reader has to convert to binary hides that.
    let _ = writeln!(
        out,
        "degraded       : {}",
        if down.is_empty() { "none — every point fresh".to_owned() } else { format!("points {}", down.join(", ")) }
    );
    let _ = writeln!(out, "epoch          : {}", frame.epoch);
    let _ = writeln!(out, "phi            : {:.3}", frame.phi);
    let _ = writeln!(out, "purity         : {:.3}", frame.purity);
    let _ = writeln!(out, "reflection     : {:.3}", frame.reflection);
    let _ = writeln!(out, "mean_r         : {:.3}", frame.mean_r);
    let _ = writeln!(out, "spectral_gap   : {:.3}", frame.gap);
    // The syndrome is a 3-bit Hamming code over the seven Fano points: 0 means no localized fault, and any
    // other value NAMES the point. Printing only the number would make the operator do the decode.
    let _ = writeln!(
        out,
        "syndrome       : {} ({})",
        frame.syndrome,
        if frame.syndrome == 0 { "no localized fault".to_owned() } else { format!("point {}", frame.syndrome - 1) }
    );
    let _ = writeln!(out, "verdict        : {}", frame.verdict);
    let _ = writeln!(out, "forecast       : {}", frame.forecast);
    let _ = writeln!(out, "heal_seq       : {}", frame.heal_seq);
    out
}

/// Serve one connection: read a verb, forward it, write the answer.
async fn serve_one(stream: UnixStream, tx: &mpsc::Sender<Envelope>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let body = match Request::parse(&line) {
        Some(req) => {
            let (reply_tx, reply_rx) = oneshot::channel();
            if tx.send((req, reply_tx)).await.is_err() {
                // The node is gone; say so rather than hanging a client that is waiting on a corpse.
                "error: node is shutting down\n".to_owned()
            } else {
                reply_rx.await.unwrap_or_else(|_| "error: no answer\n".to_owned())
            }
        }
        None => format!("error: unknown request (expected {})\n", Request::all()),
    };
    let mut stream = reader.into_inner();
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Bind the control socket at `path` and serve it until the node stops.
///
/// A stale socket file from a previous run is removed first: a node that crashed left the path behind, and
/// `bind` fails on an existing path — so without this a hard restart silently loses its control plane, which is
/// exactly when an operator most wants it.
///
/// # Errors
/// Propagates the bind failure, which is the operator's to see: a node running without the socket it was asked
/// for should say so rather than pretend.
pub fn serve(path: &Path, tx: mpsc::Sender<Envelope>) -> std::io::Result<tokio::task::JoinHandle<()>> {
    // Owner-only, and it is what closes the bind→chmod window below rather than merely narrowing it: a Unix
    // socket's permission check happens at `connect()`, so an unrestricted parent lets a local account reach
    // the socket during the microseconds it exists at the umask. See `durable::create_private_dir`.
    if let Some(parent) = path.parent() {
        crate::durable::create_private_dir(parent)?;
    }
    // Only if it is actually a socket. Removing whatever happens to sit at the path would let a mistyped data
    // directory delete a real file.
    if path.exists() {
        use std::os::unix::fs::FileTypeExt as _;
        if std::fs::metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
            std::fs::remove_file(path)?;
        }
    }
    let listener = UnixListener::bind(path)?;
    restrict(path)?;
    let owned = path.to_path_buf();
    Ok(tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let tx = tx.clone();
            tokio::spawn(async move { serve_one(stream, &tx).await });
        }
        // The listener is dropped here; take the path with it so the next start binds cleanly.
        let _ = std::fs::remove_file(&owned);
    }))
}

/// Restrict the socket to its owner.
///
/// Applied immediately after `bind`, and it is the whole of this channel's access control — see the module note.
/// A socket left at the umask is an administrative channel open to every account on the host.
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Ask a running node one question over its control socket.
///
/// `Ok(None)` means *no node is listening* — a distinct answer from an error, and the distinction is the point:
/// "nothing is running here" is the normal state of a host that has been set up and not started, while a failure
/// to talk to a socket that does exist is a fault.
///
/// # Errors
/// I/O failures against a socket that exists.
pub async fn ask(path: &Path, request: &str) -> std::io::Result<Option<String>> {
    let stream = match UnixStream::connect(path).await {
        Ok(s) => s,
        // Both mean "not running": no socket file at all, or a stale one nobody is accepting on.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let mut stream = stream;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    let mut body = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_to_string(&mut body).await?;
    Ok(Some(body))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use fanos_runtime::ports::Duration;
    use fanos_runtime::ports::stations::Station;

    /// **Every field of `Health` reaches the operator** (#165) — a ratchet, not a smoke test.
    ///
    /// `render_health` printed **7 of 10**, and the three it dropped were precisely the ones added by audit
    /// work *so that an operator could see them*: `collisions` and `unresolved_drops` (#149, whose title was
    /// "the three unread detectors now have readers" — they got their reader and the reader printed nothing)
    /// and `reflexive` (#145, "so an operator is told the reflex is absent"). `reflexive` was the sharpest
    /// loss, because its only job is to say that **every other line here is uninformative**.
    ///
    /// A field is added to `Health` by whoever needs it in a test, in a different file from this one, so the
    /// omission is the default outcome rather than an oversight. This test makes it a red build: every field
    /// is set to a value that cannot occur by accident, and each must appear in the output.
    #[test]
    fn render_health_prints_every_field_it_is_given() {
        let health = Health {
            address: [1, 2, 3],
            local_addr: "127.0.0.1:65001".parse().expect("addr"),
            known_peers: 41,
            reflexive: false,
            send_drops: 43,
            collisions: 44,
            unresolved_drops: 45,
            verified_claims: Some(46),
            probe_index: Some(47),
            roles: crate::config::RoleSet::default(),
        };
        let out = render_health(&health);
        // Values, not key names: a renderer that prints `collisions: 0` for a `Health` carrying 44 is exactly
        // the failure this is for, and a key-only check would pass it.
        for (what, needle) in [
            ("coordinate", "1:2:3"),
            ("listen", "65001"),
            ("known_peers", "41"),
            ("send_drops", "43"),
            ("collisions", "44"),
            ("unresolved_drops", "45"),
            ("verified_claims", "46"),
            ("probe_index", "47"),
        ] {
            assert!(out.contains(needle), "`{what}` is in Health and not in the rendering:\n{out}");
        }
        assert!(out.contains("reflexive: NO"), "an absent reflex must be stated, loudly:\n{out}");
        assert!(out.contains("roles"), "the offered roles are part of the answer:\n{out}");

        // And the other direction, so the line above is a discriminator rather than a constant.
        let reflexive = render_health(&Health { reflexive: true, ..health });
        assert!(reflexive.contains("reflexive: yes"), "a present reflex says so too:\n{reflexive}");
        assert!(!reflexive.contains("reflexive: NO"));
    }

    #[test]
    fn every_documented_verb_parses_and_nothing_else_does() {
        // Derived from the help string rather than a hand-written list. The literal it used to iterate had
        // already drifted — `consensus` was documented, parsed, and silently unchecked — because a list that
        // must be edited alongside two other places gets edited in two.
        for word in Request::all().split('|').map(str::trim) {
            assert!(Request::parse(word).is_some(), "`{word}` is offered in help but does not parse");
        }
        assert!(Request::parse("PING").is_some(), "verbs are case-insensitive");
        assert!(Request::parse(" health \n").is_some(), "a line from a socket carries its newline");
        assert!(Request::parse("reconfigure").is_none(), "an unknown verb must not be silently accepted");
        assert!(Request::parse("").is_none());
    }

    #[test]
    fn every_variant_is_reachable_over_the_socket() {
        // The direction the help string cannot give: a verb the enum has and the parser does not is a feature
        // nobody can invoke. The `match` is exhaustive, so a new variant does not compile until someone states
        // its word here — which is the only check that survives someone forgetting this file exists.
        let every = [
            Request::Ping,
            Request::Health,
            Request::Roles,
            Request::Census,
            Request::Consensus,
            Request::Stations,
            Request::Coherence,
            Request::Shutdown,
        ];
        for request in &every {
            let word = match request {
                Request::Ping => "ping",
                Request::Health => "health",
                Request::Roles => "roles",
                Request::Census => "census",
                Request::Consensus => "consensus",
                Request::Stations => "stations",
                Request::Coherence => "coherence",
                Request::Shutdown => "shutdown",
            };
            assert!(Request::all().contains(word), "`{word}` is a variant but is not offered in help");
            let parsed = Request::parse(word).expect("a variant's own word must parse");
            assert_eq!(
                core::mem::discriminant(&parsed),
                core::mem::discriminant(request),
                "`{word}` parses to a different verb than the one it names"
            );
        }
        assert_eq!(
            Request::all().split('|').count(),
            every.len(),
            "the help string and the variant list disagree on how many verbs there are"
        );
    }

    #[test]
    fn the_coherence_render_decodes_the_syndrome_instead_of_leaving_the_arithmetic_to_the_reader() {
        // The syndrome is a 3-bit Hamming code over the seven Fano points, so `4` does not mean "four of
        // something" — it names a point, and the off-by-one is the kind of decode an operator should never be
        // asked to do at 3am. Both the number and its meaning are printed: the number compares between nodes,
        // the word explains one.
        let healthy = CoherenceFrame {
            cell_id: fanos_telemetry::CellId([0; 16]),
            epoch: 12,
            syndrome: 0,
            verdict: 0,
            phi: 0.875,
            purity: 0.5,
            reflection: 0.25,
            mean_r: 0.5,
            gap: 0.125,
            forecast: -3,
            heal_seq: 7,
        };
        let body = render_coherence(&healthy, 0, 7);
        assert!(body.contains("no localized fault"), "a zero syndrome is not point zero: {body}");
        assert!(body.contains("phi            : 0.875"), "measures print to three decimals: {body}");
        assert!(body.contains("epoch          : 12"), "and the epoch they were taken at: {body}");

        let faulted = CoherenceFrame { syndrome: 4, ..healthy };
        let body = render_coherence(&faulted, 0b0000_1000, 6);
        assert!(body.contains("point 3"), "syndrome 4 names point 3, not point 4: {body}");
        assert!(body.contains("points 3"), "and the footprint lists the point as a member of a SET: {body}");
        assert!(
            body.contains("wire           : "),
            "a monitor needs the canonical bytes, not the human render, to reconstruct the frame: {body}"
        );
        assert!(body.contains("syndrome       : 4"), "and the raw value is still there to compare: {body}");
    }

    #[test]
    fn the_derivation_digest_changes_with_the_schedule_and_not_with_anything_else() {
        // §4 wants agreement legible rather than inferred: two operators comparing this one value know their
        // nodes agree on every registered height. That is only true if the digest actually depends on the
        // schedule — a constant would compare equal between two genuinely different releases and report
        // agreement that does not exist, which is worse than reporting nothing.
        let digest = derivation_digest();
        assert_eq!(digest, derivation_digest(), "same build, same value — or comparison means nothing");
        assert_ne!(digest, [0u8; 32], "a digest that is all zeros is a constant wearing a hash's clothes");

        // Each dimension isolated against the REAL hashing: two schedules identical but for one field. The
        // earlier version of this built a comparison vector by hand and passed even with the abort height
        // dropped from the digest, because the two inputs differed in length whatever the function did.
        let base = [("onion.gather_member", 4u64, None)];
        let armed = [("onion.gather_member", 4u64, Some(9u64))];
        let renamed = [("onion.gather_member!", 4u64, None)];
        let moved = [("onion.gather_member", 5u64, None)];
        assert_ne!(
            digest_of(base.into_iter()),
            digest_of(armed.into_iter()),
            "arming an abort must move the digest, or a scheduled withdrawal is invisible to comparison"
        );
        assert_ne!(
            digest_of(base.into_iter()),
            digest_of(moved.into_iter()),
            "moving an activation must move the digest"
        );
        // The name is hashed beside the heights so that RENAMING a derivation — which changes what its height
        // means — changes the digest; hashing heights alone would call two different schedules identical.
        assert_ne!(
            digest_of(base.into_iter()),
            digest_of(renamed.into_iter()),
            "renaming a derivation must move the digest — the height it names would otherwise be unanchored"
        );

        // The name is hashed beside the height on purpose: renaming a derivation changes what its height
        // *means*, and a digest over heights alone would call two different schedules identical. Recomputed
        // here with one name perturbed — it must differ.
        // And it reaches the operator, which is the point of computing it.
        let plane = render_data_path(&[], GatherHealth::NoGatherPath, 0);
        assert!(plane.contains("derivation_vector"), "the schedule must be readable beside the plane: {plane}");
        // And the digest alone is not enough: it answers "do two nodes agree", and an operator whose digests
        // differ needs "on what" immediately — a hash cannot be diffed.
        for d in Derivation::ALL {
            assert!(plane.contains(d.name()), "{} is missing from the listed schedule: {plane}", d.name());
        }
        assert!(
            plane.contains("permanent") || plane.contains("withdrawn at"),
            "every entry states whether it is provisional: {plane}"
        );
        // And what an operator may actually do with it. The shipped entry is line-scoped, so the answer is
        // "by cell only" — the constraint §2 ∧ §3 impose, stated where a rollout is planned rather than left
        // for someone to re-derive from the scope's name.
        assert!(
            plane.contains("canary by cell only"),
            "a line-scoped derivation must say that a per-node canary is inadmissible: {plane}"
        );
    }

    #[test]
    fn the_data_path_render_shows_what_moved_and_says_when_nothing_did() {
        // A node reports `stations × lines` counters. Printing them all buries the two that moved, which is the
        // diagnosis-by-thin-evidence the plane exists to end rather than reproduce — so only non-zero counts
        // appear, and a quiet plane says so in words, because an empty body and a broken verb look identical.
        let quiet = render_data_path(&[], GatherHealth::Unmeasured, 0);
        assert!(quiet.contains("no station has fired"), "silence must be stated, not implied: {quiet}");
        assert!(
            quiet.contains("unmeasured"),
            "an unmeasured deadline is not a fast one — the engine is on its initial estimate: {quiet}"
        );

        // And the third state, which an `Option` could not carry: a node with no gather at all must not be told
        // its deadline is unmeasured, or every overlay-only node reports a finding it cannot act on.
        let no_gather = render_data_path(&[], GatherHealth::NoGatherPath, 0);
        assert!(no_gather.contains("n/a"), "no gather path is not an unmeasured one: {no_gather}");
        assert!(
            !no_gather.contains("unmeasured"),
            "an engine with no gather must not report an unmeasured deadline: {no_gather}"
        );

        let obs = [
            Observation { station: Station::GatherExpired, line: Some([1, 0, 1]), tag: None, count: 412 },
            Observation { station: Station::GatherCompleted, line: Some([1, 0, 1]), tag: None, count: 0 },
            Observation { station: Station::FrameDecodeFailed, line: None, tag: None, count: 7 },
            Observation {
                station: Station::FrameTypeUnknown,
                line: Some([1, 0, 1]),
                tag: Some(47),
                count: 312,
            },
        ];
        let body = render_data_path(
            &obs,
            GatherHealth::Measured { srtt: Duration::from_millis(180), var: Duration::from_millis(40) },
            0,
        );
        assert!(body.contains("412") && body.contains("line 1:0:1"), "a hot station names its line: {body}");
        assert!(body.contains("unattributed"), "an unattributable count says so, not a fabricated line: {body}");
        // Via `name()`, not a literal. Written as `"gather_completed"` this assertion could never fail — the
        // names are dotted — so the filter it exists to pin was unguarded, and the falsification pass that
        // removed the filter passed clean.
        assert!(
            !body.contains(Station::GatherCompleted.name()),
            "a station that never fired is not printed: {body}"
        );
        assert!(body.contains("srtt 180 ms") && body.contains("var 40 ms"), "the measured deadline: {body}");
    }

    #[test]
    fn a_long_data_directory_still_gets_a_bindable_socket_path() {
        // `sockaddr_un.sun_path` is 104 bytes on macOS. A node whose state sits a few levels deep — a container
        // mount, a long user name, a packaging layout — cannot put its socket beside its state, and the failure
        // is a bind error naming `SUN_LEN` and not the path. Found by running one.
        let deep = PathBuf::from(format!("/tmp/{}", "verylongsegment/".repeat(12)));
        assert!(deep.join(SOCKET_FILE).as_os_str().len() > MAX_SOCKET_PATH, "the fixture must be too long");
        let path = socket_path(&deep);
        assert!(
            path.as_os_str().len() <= MAX_SOCKET_PATH,
            "the fallback is still unbindable at {} bytes: {}",
            path.as_os_str().len(),
            path.display()
        );
        // Deterministic: the node and `fanos status` derive it independently, so it must not depend on anything
        // but the data directory — otherwise they would disagree and the socket would be unreachable.
        assert_eq!(path, socket_path(&deep), "the derivation must be stable across calls");
        let other = PathBuf::from(format!("/tmp/{}x", "verylongsegment/".repeat(12)));
        assert_ne!(socket_path(&other), path, "two nodes must not be handed the same socket");
    }

    #[test]
    fn a_short_data_directory_keeps_the_socket_beside_the_state() {
        // The fallback must stay a fallback: on a normal install the socket belongs where an operator looks.
        let path = socket_path(Path::new("/var/lib/fanos"));
        assert_eq!(path, Path::new("/var/lib/fanos").join(SOCKET_FILE));
    }

    #[tokio::test]
    async fn asking_a_path_with_no_socket_is_not_running_rather_than_an_error() {
        // The distinction the operator's first question depends on: "set up but not started" is normal, a broken
        // socket is a fault, and collapsing them makes `fanos status` unable to tell them apart.
        let missing = std::env::temp_dir().join(format!("fanos-absent-{}.sock", std::process::id()));
        let answer = ask(&missing, "ping").await.expect("an absent socket is not an error");
        assert!(answer.is_none(), "a path with no socket must read as `not running`");
    }

    #[tokio::test]
    async fn a_request_reaches_the_node_and_its_answer_comes_back() {
        let dir = std::env::temp_dir().join(format!("fanos-admin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = socket_path(&dir);
        let (tx, mut rx) = mpsc::channel::<Envelope>(4);
        let _server = serve(&path, tx).expect("bind the control socket");

        // Stand in for the node's main loop.
        tokio::spawn(async move {
            while let Some((req, reply)) = rx.recv().await {
                let body = match req {
                    Request::Ping => "pong\n".to_owned(),
                    Request::Roles => "relay,storage\n".to_owned(),
                    _ => "…\n".to_owned(),
                };
                let _ = reply.send(body);
            }
        });

        assert_eq!(ask(&path, "ping").await.unwrap().as_deref(), Some("pong\n"));
        assert_eq!(ask(&path, "roles").await.unwrap().as_deref(), Some("relay,storage\n"));
        let unknown = ask(&path, "reconfigure").await.unwrap().unwrap_or_default();
        assert!(unknown.starts_with("error: unknown request"), "got {unknown:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn every_verb_the_error_message_advertises_is_a_verb_the_parser_accepts() {
        // The two drifted apart the moment a verb was added: `all()` is what an operator is told to type after a
        // mistake, so a verb listed there and unparsed is a lie told at exactly the wrong moment, and a verb
        // parsed but unlisted is a capability nobody can discover. Checked against each other rather than against
        // a hand-written list, so adding a verb cannot satisfy this test without wiring both sides.
        for verb in Request::all().split('|').map(str::trim) {
            assert!(Request::parse(verb).is_some(), "`{verb}` is advertised by all() and the parser refuses it");
        }
        // …and the reverse direction, for the verbs this build knows about.
        for verb in ["ping", "health", "roles", "census", "consensus", "shutdown"] {
            assert!(Request::parse(verb).is_some(), "`{verb}` must parse");
            assert!(Request::all().contains(verb), "`{verb}` parses but is not advertised, so nobody can find it");
        }
        // Case-insensitively, as the parser promises.
        assert!(Request::parse("  CONSENSUS \n").is_some(), "verbs are parsed case-insensitively and trimmed");
    }

    #[tokio::test]
    async fn the_socket_is_readable_only_by_its_owner() {
        // This permission *is* the channel's authentication. At the umask it would be an administrative surface
        // open to every account on the host.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("fanos-admin-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = socket_path(&dir);
        let (tx, _rx) = mpsc::channel::<Envelope>(1);
        let _server = serve(&path, tx).expect("bind");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the control socket must not be reachable by other accounts");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_stale_socket_from_a_crashed_node_does_not_block_the_next_start() {
        // `bind` fails on an existing path, so without clearing it a hard restart comes up with no control plane
        // — precisely when an operator most needs to ask the node anything.
        let dir = std::env::temp_dir().join(format!("fanos-admin-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = socket_path(&dir);
        {
            let (tx, _rx) = mpsc::channel::<Envelope>(1);
            let first = serve(&path, tx).expect("first bind");
            first.abort();
        }
        assert!(path.exists(), "the aborted server left its socket behind, as a crash would");
        let (tx, _rx) = mpsc::channel::<Envelope>(1);
        assert!(serve(&path, tx).is_ok(), "a stale socket must not prevent the node from restarting");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_non_socket_at_the_path_is_never_deleted() {
        // The guard against a mistyped data directory: clearing "whatever is in the way" would make a typo
        // destroy a real file.
        let dir = std::env::temp_dir().join(format!("fanos-admin-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = socket_path(&dir);
        std::fs::write(&path, b"precious").unwrap();
        let (tx, _rx) = mpsc::channel::<Envelope>(1);
        assert!(serve(&path, tx).is_err(), "binding over a regular file must fail rather than remove it");
        assert_eq!(std::fs::read(&path).unwrap(), b"precious", "the file was destroyed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
