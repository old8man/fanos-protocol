//! First-run setup: turn a freshly-installed binary into a running node.
//!
//! The target experience is one command on a bare server. Everything this module can *determine* it determines —
//! where configuration belongs on this operating system, which port is actually free, whether there is an init
//! system and whether we may write to it — and the operator is asked only what genuinely cannot be derived: what
//! this node should offer the network, and whose cell it is joining.
//!
//! ## Why this is a library module and not a block of the binary
//!
//! Two of the three things here are pure functions over data — the per-OS path layout, the rendered service unit,
//! and the rendered configuration — and each is a place where a silent mistake produces a node that looks
//! installed and is not. A unit file with the wrong `ExecStart` fails at boot, weeks later, on a machine nobody is
//! watching. So they are written where they can be asserted, and only the parts that genuinely need a human — the
//! prompts — stay in the binary.
//!
//! ## The round-trip that matters
//!
//! [`render_config`] is the inverse of [`NodeConfig::from_config_str`], and that is a property, not an aspiration:
//! the wizard's whole output is a file the daemon must later read back. A field this renderer forgets is a setting
//! that silently reverts to its default on the next restart — which is precisely the failure an operator cannot
//! see. The round-trip is asserted in this module's tests, field by field.

use std::fmt::Write as _;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};

use crate::config::{NodeConfig, RoleSet};

/// Where this node's files belong on this operating system, and under this user.
///
/// Two layouts, chosen by privilege rather than by flag: a root install is a machine-wide service and belongs in
/// the system directories; an unprivileged install belongs in the user's own. Deciding by `--system` instead would
/// let an operator ask for a layout they cannot write to, and the failure would arrive at first boot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    /// The configuration file the daemon reads.
    pub config: PathBuf,
    /// The node's long-term identity key. Must be readable only by its owner.
    pub identity: PathBuf,
    /// Durable state (the overlay store).
    pub data: PathBuf,
}

impl Paths {
    /// The layout for a machine-wide (root) install: `/etc/fanos` and `/var/lib/fanos`.
    #[must_use]
    pub fn system() -> Self {
        Self {
            config: PathBuf::from("/etc/fanos/fanos.conf"),
            identity: PathBuf::from("/etc/fanos/identity.key"),
            data: PathBuf::from("/var/lib/fanos"),
        }
    }

    /// The layout for an unprivileged install, rooted at `home`.
    ///
    /// XDG on Linux, `Library/Application Support` on macOS — the convention each platform's own tooling expects,
    /// so an operator's backup and packaging scripts find it where they look.
    #[must_use]
    pub fn user_in(home: &Path, macos: bool) -> Self {
        let (cfg_root, data_root) = if macos {
            let app = home.join("Library/Application Support/fanos");
            (app.clone(), app)
        } else {
            (home.join(".config/fanos"), home.join(".local/share/fanos"))
        };
        Self {
            config: cfg_root.join("fanos.conf"),
            identity: cfg_root.join("identity.key"),
            data: data_root,
        }
    }

    /// The layout for this process: system when running as root, otherwise the invoking user's.
    ///
    /// Fallible on exactly one input, and that is the whole point of the signature: the root branch is
    /// determined (it asks `/etc` directly), the user branch needs a home directory, and a home directory is
    /// something the environment may simply not name. See [`home_dir`] for why the previous `"."` answer was
    /// the worst of the three possible ones.
    pub fn detect() -> Result<Self, HomeUnknown> {
        if is_root() {
            return Ok(Self::system());
        }
        Ok(Self::user_in(&home_dir()?, cfg!(target_os = "macos")))
    }
}

/// Why this host's home directory could not be determined — the two ways `HOME` fails to name one.
///
/// Kept apart because the operator's fix differs: one is "give the process an environment", the other is
/// "the environment it has is wrong".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HomeUnknown {
    /// `HOME` is unset, or set to the empty string. What a service manager's minimal environment looks like
    /// from inside the process it started.
    Unset,
    /// `HOME` names a **relative** path, so everything under it would depend on the directory this process
    /// happened to start in — the same defect as no home at all, one indirection further away.
    NotAbsolute(PathBuf),
}

impl core::fmt::Display for HomeUnknown {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unset => f.write_str(
                "HOME is not set, so this host's FANOS layout has no home directory to sit under — start the \
                 process with HOME set (a service manager gives a daemon a minimal environment, and this is \
                 what that looks like from inside), or name the paths explicitly with --config and --data",
            ),
            Self::NotAbsolute(p) => write!(
                f,
                "HOME is '{}', which is a relative path — every file under it would then depend on the \
                 directory this process was started from, which is not a property a node's identity may \
                 have. Set HOME to an absolute path, or name the paths explicitly with --config and --data",
                p.display()
            ),
        }
    }
}

impl std::error::Error for HomeUnknown {}

/// **The one reader of `HOME` in this workspace**, and the reason it is one (#312).
///
/// Four sites used to answer this question, each with `map_or_else(|| PathBuf::from("."), …)` — an unset
/// `HOME` silently became the *current working directory*. That is not a mild fallback. The user layout puts
/// this node's identity key, its configuration and its durable store under the home directory, so the answer
/// `"."` puts a node's **identity** wherever the process happened to be started: a `cd` between two starts
/// gives the cell two different nodes, and neither operator nor cell can see why. Service managers routinely
/// start daemons with no `HOME` at all, so this is the deployed case rather than an exotic one.
///
/// The three candidate answers, and why this is the one:
///
/// * **`"."`** — silently wrong, above.
/// * **the system layout** — worse than wrong: an unprivileged process cannot write `/etc/fanos`, and if it
///   could, it would be reading *another* installation's files.
/// * **refuse, and say which of the two things is missing** — the caller then either sets `HOME` or names the
///   paths, both of which it can do. A refusal an operator can act on beats a default nobody chose.
///
/// An empty `HOME` counts as unset: `HOME=` is what an environment that meant to clear it produces, and
/// `PathBuf::from("")` would join to a relative path. A relative `HOME` is refused for the same reason `"."`
/// is — POSIX requires an absolute pathname here, and accepting a relative one reintroduces exactly the
/// defect this function exists to remove.
///
/// # Errors
///
/// [`HomeUnknown::Unset`] if `HOME` is absent or empty, [`HomeUnknown::NotAbsolute`] if it is relative.
pub fn home_dir() -> Result<PathBuf, HomeUnknown> {
    classify_home(std::env::var_os("HOME"))
}

/// The decision [`home_dir`] makes, as a pure function of the variable's value.
///
/// Split out so the classification is testable without mutating the process environment — an env var is
/// global state shared by every test in the binary, and a test that sets it is a test that decides another
/// test's answer.
fn classify_home(raw: Option<std::ffi::OsString>) -> Result<PathBuf, HomeUnknown> {
    let raw = raw.filter(|v| !v.is_empty()).ok_or(HomeUnknown::Unset)?;
    let path = PathBuf::from(raw);
    if path.is_absolute() { Ok(path) } else { Err(HomeUnknown::NotAbsolute(path)) }
}

/// Whether this process may install to the system paths — asked, and now answered, as a **capability**.
///
/// The previous version compared `/etc`'s owner against a uid it learned by writing
/// `<temp>/fanos-uid-probe-<pid>` and reading the owner back. Two defects followed from that shape, and the
/// comment above it had already described the right check without implementing it (#174):
///
/// 1. `fs::write` is `O_WRONLY|O_CREAT|O_TRUNC` and **follows symlinks**, at a fully predictable path in a
///    shared directory. No race was needed — pre-create the plausible PID range as symlinks and the name is
///    already there — so it truncated whatever the link pointed at, with our privileges.
/// 2. `metadata()` follows the link too, so the uid returned was the **target's** owner. Pointing it at a file
///    the attacker owns made `is_root()` false for an actual root operator, and `fanos setup` then provisioned
///    to the user paths silently.
///
/// Neither was escalation — destruction within our own authority, and misprovisioning — and on a default
/// Linux `fs.protected_symlinks=1` blocks both, while macOS gives each user a `0700` `TMPDIR`. It was still
/// the wrong shape: the question is *"may I write to a root-only place?"* and it was answered by a uid
/// comparison that a shared directory could influence.
///
/// So ask it directly. `create_new` is `O_EXCL|O_CREAT`: it refuses if the path exists **at all**, symlink or
/// not, so there is no link to follow and nothing to truncate. `/etc` is root-owned and not world-writable on
/// every platform this ships to, so an attacker who could plant a name there is already root and the question
/// is moot.
///
/// Fails **closed**: any error reads as "not root", which provisions to the user paths — visible to the
/// operator and recoverable, where the opposite would attempt a system install and fail midway.
#[must_use]
pub fn is_root() -> bool {
    // A dot-name with the pid, created and removed immediately. Not `/etc/fanos` — the probe must not collide
    // with anything an install would later create.
    let probe = Path::new("/etc").join(format!(".fanos-root-probe-{}", std::process::id()));
    let created = std::fs::OpenOptions::new().write(true).create_new(true).open(&probe).is_ok();
    if created {
        let _ = std::fs::remove_file(&probe);
    }
    created
}

/// The port a fresh install listens on unless the operator says otherwise.
///
/// A *stable* number, and that is the point. `NodeConfig::default()` binds port 0 — an ephemeral port, correct
/// for a test that only needs some socket, and wrong for an installed node: it would take a different port at
/// every restart, so the seed address it prints for peers to dial is stale the moment it is restarted. A daemon
/// needs an address others can write down. 9931 is in the unassigned range and not claimed by IANA.
pub const DEFAULT_PORT: u16 = 9931;

/// Find a UDP port this node can actually bind, starting from `preferred`.
///
/// Probed rather than assumed. A default port that is already taken is the single most common reason a
/// freshly-installed daemon fails to start, and it fails *after* the operator has walked away. Returns `None` if
/// the whole scanned window is occupied, which is a real answer and not a port to try anyway.
#[must_use]
pub fn free_udp_port(preferred: u16, window: u16) -> Option<u16> {
    (0..window).find_map(|i| {
        let port = preferred.checked_add(i)?;
        UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))).ok().map(|_| port)
    })
}

/// The service manager this host actually has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceManager {
    /// systemd, as a machine-wide unit (root).
    SystemdSystem,
    /// systemd, as a per-user unit — the correct target for an unprivileged install.
    SystemdUser,
    /// launchd (macOS), per-user.
    Launchd,
    /// No supervisor found: the operator runs the node in the foreground or wires their own.
    None,
}

impl ServiceManager {
    /// Detect the supervisor available to *this* process, privilege included.
    ///
    /// Presence is checked on the filesystem rather than by running the tool: a machine can have `systemctl` on
    /// `PATH` inside a container where systemd is not the running init, and installing a unit there produces a
    /// service that is never started and never reports why.
    #[must_use]
    pub fn detect() -> Self {
        if cfg!(target_os = "macos") {
            return if Path::new("/bin/launchctl").exists() { Self::Launchd } else { Self::None };
        }
        // `/run/systemd/system` exists only when systemd is the running init — the check systemd itself documents.
        if !Path::new("/run/systemd/system").exists() {
            return Self::None;
        }
        if is_root() { Self::SystemdSystem } else { Self::SystemdUser }
    }

    /// Where this manager's unit file for FANOS belongs, given the user's home.
    ///
    /// The **pure** half, kept public because the per-OS layout is exactly the kind of thing a test must be
    /// able to state without an environment. Production wants [`unit_path_here`](Self::unit_path_here), which
    /// resolves the home itself — and only on the arms that read one.
    #[must_use]
    pub fn unit_path(self, home: &Path) -> Option<PathBuf> {
        match self {
            Self::SystemdSystem => Some(PathBuf::from(SYSTEM_UNIT_PATH)),
            Self::SystemdUser => Some(home.join(".config/systemd/user/fanos.service")),
            Self::Launchd => Some(home.join("Library/LaunchAgents/network.fanos.node.plist")),
            Self::None => None,
        }
    }

    /// Where this manager's unit file belongs **on this host** — the home resolved only where it is read.
    ///
    /// The distinction is not decoration (#312). `SystemdSystem`'s path is a constant, so resolving the home
    /// first and passing it in would refuse a *root* install for want of a `HOME` that arm never looks at —
    /// a guard wider than the thing it guards. Each arm therefore asks only for what it uses.
    ///
    /// # Errors
    ///
    /// [`HomeUnknown`] on the two per-user managers, when the environment does not name a home directory.
    pub fn unit_path_here(self) -> Result<Option<PathBuf>, HomeUnknown> {
        match self {
            Self::SystemdSystem => Ok(Some(PathBuf::from(SYSTEM_UNIT_PATH))),
            Self::None => Ok(None),
            Self::SystemdUser | Self::Launchd => Ok(self.unit_path(&home_dir()?)),
        }
    }

    /// The `systemctl` invocation for this manager: system-wide, or with `--user`.
    fn systemctl(self) -> Vec<String> {
        match self {
            Self::SystemdUser => vec!["systemctl".to_owned(), "--user".to_owned()],
            _ => vec!["systemctl".to_owned()],
        }
    }

    /// The commands that enable and start the installed unit, in order — as **argv lists**, so a caller runs
    /// them directly rather than through a shell.
    ///
    /// Structured rather than printed because these are meant to be *executed*: an operator who has just asked
    /// for a node installed does not want a list of commands to copy, and a string handed to a shell is an
    /// injection surface for every path in it.
    #[must_use]
    pub fn activation(self, unit: &Path) -> Vec<Vec<String>> {
        match self {
            Self::SystemdSystem | Self::SystemdUser => {
                let sc = self.systemctl();
                let mut out = vec![
                    [sc.clone(), vec!["daemon-reload".to_owned()]].concat(),
                    [sc, vec!["enable".to_owned(), "--now".to_owned(), UNIT_NAME.to_owned()]].concat(),
                ];
                if self == Self::SystemdUser {
                    // Without lingering, a user unit stops at logout — which on a server is "it worked until I
                    // closed the terminal", the most confusing failure this could ship.
                    out.push(vec!["loginctl".to_owned(), "enable-linger".to_owned()]);
                }
                out
            }
            Self::Launchd => {
                vec![vec![
                    "launchctl".to_owned(),
                    "load".to_owned(),
                    "-w".to_owned(),
                    unit.display().to_string(),
                ]]
            }
            Self::None => Vec::new(),
        }
    }

    /// Stop the running service without uninstalling it.
    #[must_use]
    pub fn stop(self, unit: &Path) -> Vec<Vec<String>> {
        match self {
            Self::SystemdSystem | Self::SystemdUser => {
                vec![[self.systemctl(), vec!["stop".to_owned(), UNIT_NAME.to_owned()]].concat()]
            }
            Self::Launchd => vec![vec![
                "launchctl".to_owned(),
                "unload".to_owned(),
                unit.display().to_string(),
            ]],
            Self::None => Vec::new(),
        }
    }

    /// Start an already-installed service.
    #[must_use]
    pub fn start(self, unit: &Path) -> Vec<Vec<String>> {
        match self {
            Self::SystemdSystem | Self::SystemdUser => {
                vec![[self.systemctl(), vec!["start".to_owned(), UNIT_NAME.to_owned()]].concat()]
            }
            Self::Launchd => vec![vec![
                "launchctl".to_owned(),
                "load".to_owned(),
                "-w".to_owned(),
                unit.display().to_string(),
            ]],
            Self::None => Vec::new(),
        }
    }

    /// Stop **and** disable the service, so it does not come back at the next boot.
    ///
    /// Both, and in that order: stopping alone leaves a unit that returns on reboot, which is the removal an
    /// operator thinks they performed and did not.
    #[must_use]
    pub fn deactivation(self, unit: &Path) -> Vec<Vec<String>> {
        match self {
            Self::SystemdSystem | Self::SystemdUser => {
                let sc = self.systemctl();
                vec![
                    [sc.clone(), vec!["disable".to_owned(), "--now".to_owned(), UNIT_NAME.to_owned()]].concat(),
                    [sc, vec!["daemon-reload".to_owned()]].concat(),
                ]
            }
            Self::Launchd => vec![vec![
                "launchctl".to_owned(),
                "unload".to_owned(),
                "-w".to_owned(),
                unit.display().to_string(),
            ]],
            Self::None => Vec::new(),
        }
    }
}

/// The systemd unit's name — one constant, because a name that disagrees between install and removal leaves a
/// service an operator cannot get rid of with this tool.
pub const UNIT_NAME: &str = "fanos.service";

/// Where a machine-wide systemd unit belongs. Named once so the two functions that answer "where is the unit"
/// cannot drift apart — the second would be a copy, and a copy is the defect one edit away.
const SYSTEM_UNIT_PATH: &str = "/etc/systemd/system/fanos.service";

/// The node's **steady-state** memory ceiling: every named share, plus the measured resident cost of the
/// process outside them.
///
/// This is `MemoryHigh=` — the figure past which the node is holding more than its own design accounts for,
/// and systemd should apply reclaim pressure rather than kill. Nothing above this is planned: the shares are
/// each derived against their subsystem's own admission rule (`fanos_primitives::budget`), and residency is
/// measured. A node steadily above it has a leak or an unnamed consumer, and either is a thing to look at
/// rather than a thing to die of.
///
/// **It is above `NODE_MEMORY_BUDGET`, and that is the accounting speaking, not a slack factor.** The shares
/// sum to 320 MiB against a 256 MiB recommendation; `budget::overcommit()` is that 109 MiB gap and exists to
/// be reported, not hidden. Writing 256M here would put the throttle below what the code's own bounds
/// permit at rest — systemd squeezing a node that is doing exactly what it was designed to do.
#[must_use]
pub fn memory_high_bytes() -> usize {
    fanos_primitives::budget::allocated() + fanos_primitives::budget::PROCESS_RESIDENT
}

/// The node's **worst-case** memory ceiling: the steady one, plus every byte of inbound QUIC receive credit
/// a hostile set of peers can make this node hold at once.
///
/// This is `MemoryMax=` — the figure past which the node is definitely leaking and should die. The two
/// directives answer different questions and a single number cannot answer both: throttling at the
/// contingent ceiling would never fire, and killing at the steady one would kill the node under **exactly
/// the flood its caps exist to survive**, which is the failure mode #207 was opened to avoid.
///
/// **The margin between them is derived, not chosen.** It is
/// `fanos_quic::inbound_credit_ceiling()` = `MAX_INBOUND_CONNECTIONS × MAX_PEER_UNI_STREAMS × max_wire()`,
/// every factor of which is itself derived (#245 for the first two, #190 for the third). Measured today at
/// **2.00 GiB**, which is 6.4× the whole named-share total.
///
/// **This figure was not the whole worst case, and the first version of this doc claimed it was.** It
/// called the QUIC credit "the largest quantity in the node's memory picture, and the only one an adversary
/// picks the size of". Continuing the enumeration found the SOCKS5 UDP tunnel map at **8.6 GB per
/// association** — 3.6× this whole `MemoryMax` — held by a *local* runaway application rather than a remote
/// peer.
///
/// **#300 took the decision, and it was neither of the two this doc offered.** "Join the sum" and "bound it
/// down to fit the proxy's share" both assume the term must be sized against its worst case; the arithmetic
/// says no share can buy that one — the entire node budget funds depth 26 of the declared 64. So the queues
/// are **metered** instead: each datagram debits `fanos_primitives::budget::TUNNEL_BACKLOG_SHARE` for its
/// actual bytes and repays on consumption. That share is inside `allocated()`, so it reaches this figure
/// through `memory_high_bytes()` without a term of its own here, and the 8.6 GB is now a ratchet on what
/// the queues COULD hold rather than a hole this ceiling has to cover.
///
/// The ceiling was **not** raised to cover the unmetered figure while it stood, and that was the right
/// call: raising it would have ratified a number nobody derived, and the derivation, when it came, said
/// the number should not exist.
///
/// Two things this figure honestly is not:
///
/// - **A recommendation.** `NODE_MEMORY_BUDGET` says a node is documented to run in 256 MiB; this says a
///   node under a full inbound flood may reach ~2.4 GiB before systemd is right to conclude it is broken.
///   Those are different claims and the gap between them is a fact about the bounds, not about the doc.
/// - **A reason to raise the shares.** Nothing here allocates anything. It is the enforcement figure that
///   admits what the existing bounds already permit.
#[must_use]
pub fn memory_max_bytes() -> usize {
    memory_high_bytes() + fanos_quic::inbound_credit_ceiling()
}

/// The file descriptors a node can have open at once, summed from what actually consumes them (#207).
///
/// **The sum, not a guess.** This task's first note proposed "2× the session count"; the enumeration says
/// something else, because the terms are not all sessions:
///
/// | consumer | count | why |
/// |---|---|---|
/// | QUIC endpoint | 1 | quinn is **one UDP socket** regardless of peer count — the overlay's 512 inbound connections cost one descriptor between them |
/// | exit outbound TCP | `MAX_SESSIONS` | one socket per relayed clear-net session |
/// | exit outbound UDP | `MAX_UDP_DATAGRAM_SESSIONS` | one socket per relayed datagram session |
/// | local proxy clients | `MAX_CONNECTIONS` | one accepted socket per relayed connection… |
/// | proxy UDP associations | `MAX_ASSOCIATIONS` | …and one relay socket per association |
/// | listeners + control socket + tun | 4 | SOCKS5, HTTP, the admin `UnixListener`, the VPN device |
/// | stdio | 3 | |
///
/// The two proxy terms are *both* counted although one memory share buys them, because a descriptor is not
/// memory: the share makes them mutually exclusive in **bytes**, not in count, and the file table has to
/// hold whichever mix the client asks for. Summing them is the conservative reading and the only one that
/// cannot be wrong.
///
/// **This could not be written until the proxy accept loops had a bound at all** (#207): three of them
/// spawned per accepted connection with no counter, and no sum over an unbounded term is a sum.
///
/// Measured today the terms are `1 + 246 + 256 + 4096 + 128 + 4 + 3 = 4734`, and the limit is the next power
/// of two above it — **8192**. Rounding up rather than writing 4734 leaves the store's own file work (a
/// snapshot writes one temp file and renames it) and the allocator's mappings inside the limit without
/// giving either its own term, and a power of two is what an operator comparing this against `ulimit -n`
/// expects to see. The rounding is the only chosen part; every term under it is a bound derived elsewhere.
#[must_use]
pub fn open_files_limit() -> usize {
    let derived = 1                                                    // quinn's single UDP socket
        + fanos_diaulos::budget::MAX_SESSIONS                          // exit TCP
        + crate::exit::MAX_UDP_DATAGRAM_SESSIONS                       // exit UDP
        + fanos_proxy::budget::MAX_CONNECTIONS                         // proxy clients
        + fanos_proxy::budget::MAX_ASSOCIATIONS                        // proxy associations
        + 4                                                            // listeners, control socket, tun
        + 3; // stdio
    derived.next_power_of_two()
}

/// Render a systemd unit that runs `exe` against `config`.
///
/// The hardening directives are not decoration. A relay node's whole job is to accept traffic from strangers, so
/// it is exactly the process that should not be able to write outside its own state directory, gain privileges, or
/// see the rest of the filesystem. Every one of these has a cost of zero when the node behaves.
#[must_use]
pub fn render_systemd_unit(exe: &Path, config: &Path, data: &Path, user_unit: bool) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "[Unit]");
    let _ = writeln!(s, "Description=FANOS node");
    let _ = writeln!(s, "Documentation=https://github.com/fanos-protocol/fanos");
    let _ = writeln!(s, "After=network-online.target");
    let _ = writeln!(s, "Wants=network-online.target");
    let _ = writeln!(s);
    let _ = writeln!(s, "[Service]");
    let _ = writeln!(s, "Type=simple");
    let _ = writeln!(s, "ExecStart={} node --config {}", exe.display(), config.display());
    let _ = writeln!(s, "Restart=on-failure");
    let _ = writeln!(s, "RestartSec=5");
    // **Stated, not defaulted.** systemd's default stop signal is SIGTERM either way, but writing it makes
    // the supervisor's half of the contract readable — and a guard asserts it is one the binary actually
    // handles (`fanos_node::shutdown::HANDLED_STOP_SIGNALS`). The two halves are each plausible alone and
    // only wrong together: a unit sending a signal nobody catches, or a binary catching one nobody sends.
    let _ = writeln!(s, "KillSignal=SIGTERM");
    // The node persists its store before closing its endpoint. systemd's default 90 s is generous for that,
    // but stating it keeps the drain's budget beside the signal that starts it, rather than in a manual.
    let _ = writeln!(s, "TimeoutStopSec=30");
    // A node that cannot reach the overlay retries forever by design; without this, systemd gives up on it.
    let _ = writeln!(s, "StartLimitIntervalSec=0");
    // **Two ceilings, because "beyond my design" and "definitely broken" are different questions** (#207).
    // Computed, never typed: both come from `fanos_primitives::budget`'s summed shares and — for the gap
    // between them — from `fanos_quic::inbound_credit_ceiling()`. Writing either as a literal here would
    // put a memory decision in a unit file, one indirection away from every derivation that justifies it.
    let _ = writeln!(s, "MemoryHigh={}", memory_high_bytes());
    let _ = writeln!(s, "MemoryMax={}", memory_max_bytes());
    // Derived from what consumes descriptors, not from a habit — `open_files_limit` has the enumeration.
    let _ = writeln!(s, "LimitNOFILE={}", open_files_limit());
    let _ = writeln!(s, "StateDirectory=fanos");
    let _ = writeln!(s, "WorkingDirectory={}", data.display());
    if !user_unit {
        let _ = writeln!(s, "DynamicUser=yes");
    }
    let _ = writeln!(s, "NoNewPrivileges=yes");
    let _ = writeln!(s, "PrivateTmp=yes");
    let _ = writeln!(s, "PrivateDevices=yes");
    let _ = writeln!(s, "ProtectSystem=strict");
    let _ = writeln!(s, "ProtectHome=yes");
    let _ = writeln!(s, "ProtectKernelTunables=yes");
    let _ = writeln!(s, "ProtectControlGroups=yes");
    let _ = writeln!(s, "RestrictAddressFamilies=AF_INET AF_INET6");
    let _ = writeln!(s, "MemoryDenyWriteExecute=yes");
    let _ = writeln!(s, "LockPersonality=yes");
    let _ = writeln!(s);
    let _ = writeln!(s, "[Install]");
    let _ = writeln!(s, "WantedBy={}", if user_unit { "default.target" } else { "multi-user.target" });
    s
}

/// Render a launchd agent that runs `exe` against `config`.
#[must_use]
pub fn render_launchd_plist(exe: &Path, config: &Path, data: &Path, log: &Path) -> String {
    let mut s = String::new();
    let _ = writeln!(s, r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    let _ = writeln!(
        s,
        r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">"#
    );
    let _ = writeln!(s, r#"<plist version="1.0">"#);
    let _ = writeln!(s, "<dict>");
    let _ = writeln!(s, "  <key>Label</key><string>network.fanos.node</string>");
    let _ = writeln!(s, "  <key>ProgramArguments</key>");
    let _ = writeln!(s, "  <array>");
    let _ = writeln!(s, "    <string>{}</string>", exe.display());
    let _ = writeln!(s, "    <string>node</string>");
    let _ = writeln!(s, "    <string>--config</string>");
    let _ = writeln!(s, "    <string>{}</string>", config.display());
    let _ = writeln!(s, "  </array>");
    let _ = writeln!(s, "  <key>RunAtLoad</key><true/>");
    let _ = writeln!(s, "  <key>KeepAlive</key><true/>");
    let _ = writeln!(s, "  <key>WorkingDirectory</key><string>{}</string>", data.display());
    let _ = writeln!(s, "  <key>StandardOutPath</key><string>{}</string>", log.display());
    let _ = writeln!(s, "  <key>StandardErrorPath</key><string>{}</string>", log.display());
    let _ = writeln!(s, "</dict>");
    let _ = writeln!(s, "</plist>");
    s
}

/// Render `config` as the file [`NodeConfig::from_config_str`] reads back.
///
/// The inverse of the parser, and asserted as one. This is what the wizard writes, so a field omitted here is a
/// setting that reverts to its default at the next restart with nothing to show for it — the class of failure an
/// operator has no way to notice. Values equal to the default are written anyway, commented, so the file doubles
/// as documentation of what *can* be set.
#[must_use]
pub fn render_config(config: &NodeConfig, identity: &Path) -> String {
    let d = NodeConfig::default();
    let mut s = String::new();
    let _ = writeln!(s, "# FANOS node configuration — written by `fanos init`.");
    let _ = writeln!(s, "# Every key here is also a `fanos node` flag; the file is what the daemon reads.");
    let _ = writeln!(s);
    let _ = writeln!(s, "listen = {}", config.listen);
    let _ = writeln!(s, "identity = {}", identity.display());
    // The durable store (#77). Written when the caller named one — the wizard always does, so an installed
    // node keeps its shards across a restart; a config assembled in a test or by a client that wants an
    // ephemeral node leaves it unset and keeps nothing, which is what ephemeral means.
    match &config.state_path {
        Some(dir) => {
            let _ = writeln!(s, "state = {}", dir.display());
        }
        None => {
            let _ = writeln!(s, "# state = /var/lib/fanos   (unset: this node keeps nothing across a restart)");
        }
    }
    let _ = writeln!(s, "role = {}", config.roles);
    // The three role provisioning files (#90). Written when configured, so a supervised unit no longer needs
    // them on its `ExecStart=` line and the round-trip assertion below can see them at all.
    for (key, path) in [
        ("service", config.service_path.as_ref()),
        ("exit", config.exit_path.as_ref()),
        ("ingress_params", config.ingress_path.as_ref()),
    ] {
        match path {
            Some(p) => {
                let _ = writeln!(s, "{key} = {}", p.display());
            }
            None => {
                let _ = writeln!(s, "# {key} = /etc/fanos/{key}.conf   (unset: this node does not serve it)");
            }
        }
    }
    if let Some(dir) = identity.parent() {
        let beacon = dir.join(BEACON_FILE);
        if beacon.exists() {
            let _ = writeln!(s, "beacon_params = {}", beacon.display());
        }
    }
    let _ = writeln!(s, "plane_order = {}", config.plane_order);
    let _ = writeln!(s);
    if config.bootstrap.is_empty() {
        let _ = writeln!(s, "# bootstrap = x:y:z@host:port,…   (empty: this node starts a new cell)");
    } else {
        let peers: Vec<String> = config.bootstrap.iter().map(ToString::to_string).collect();
        let _ = writeln!(s, "bootstrap = {}", peers.join(","));
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "# --- timing ---");
    let _ = writeln!(s, "epoch_period = {}", config.epoch_period.as_secs());
    // **Say what the operator pays, not just what the knob is.** These two carry a value the file otherwise
    // renders as a bare number, and a number with no stated cost gets tuned for the thing it visibly affects
    // — latency — by someone who cannot see what it buys. `mix_mean_delay` IS the mixing: lowering it makes
    // the node faster and narrows the window in which its traffic is indistinguishable from anyone else's.
    let _ = writeln!(s, "# mix_mean_delay is the anonymity/latency trade itself: lower is faster AND less mixed.");
    let _ = writeln!(s, "mix_mean_delay = {}", config.mix_mean_delay.as_millis());
    let _ = writeln!(s, "cover_interval = {}", config.cover_interval.as_millis());
    render_overlay_choices(&mut s, config.overlay, d.overlay);
    if config.start_heartbeat != d.start_heartbeat {
        let _ = writeln!(s, "heartbeat = {}", config.start_heartbeat);
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "# --- admission ---");
    match config.admission_difficulty {
        Some(bits) => {
            let _ = writeln!(s, "admission_difficulty = {bits}");
        }
        None => {
            let _ = writeln!(s, "# admission_difficulty = 16   (proof-of-work bits demanded of a joiner)");
        }
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "# --- health telemetry (opt-in, differentially private) ---");
    // The differential-privacy budget, and the file said only its name. ε is not a quality setting: it is how
    // much a reading is allowed to reveal about this node, and it does not reset — repeated publications
    // compose, so a larger ε spends the budget faster as well as deeper. Stated here because the operator
    // edits this file, and a bare `telemetry_epsilon = 1.0` invites tuning for signal quality.
    let _ = writeln!(s, "# telemetry_epsilon is a PRIVACY BUDGET (smaller = less revealed), not a precision dial;");
    let _ = writeln!(s, "# repeated publications compose, so it is spent over time rather than set once.");
    match config.telemetry_epsilon {
        Some(eps) => {
            let _ = writeln!(s, "telemetry_epsilon = {eps}");
        }
        None => {
            let _ = writeln!(s, "# telemetry_epsilon = 1.0   (omitted: this node publishes no readings)");
        }
    }
    let _ = writeln!(s);
    render_transport_shaping(&mut s, config);
    s
}

/// Write the **transport shaping** section — the PROTEUS morph, its environment, and the community
/// secret's absence (#352 extraction).
///
/// A section of the rendered file and therefore a seam of the renderer, not a cut to satisfy a line count:
/// this block is the one whose comments carry an operator PROCEDURE — the umask recipe and why the secret is
/// never written here — and it changes when §13.4 changes, while the keys above it change with the node's
/// own configuration. `render_config` names the sections; this owns one of them.
fn render_transport_shaping(s: &mut String, config: &NodeConfig) {
    let _ = writeln!(s, "# --- transport shaping ---");
    let _ = writeln!(s, "proteus_morph = {}", config.proteus_morph.name());
    if let Some(env) = config.proteus_environment {
        let _ = writeln!(s, "proteus_environment = {}", env.name());
    } else {
        let _ = writeln!(s, "# proteus_environment = open|dpi-corporate|sni-filter|deep-censorship");
    }
    if config.proteus_secret.is_some() {
        let _ = writeln!(s, "# proteus_secret is set out-of-band — a shared community secret does not belong in a");
        let _ = writeln!(s, "# generated file that gets copied between hosts.");
    } else {
        // **The line above says `proteus_morph = polymorph`, and without this one that reads as "obfuscation
        // is on".** It is not: `proteus_morph`'s own doc says it "only takes effect when `proteus_secret` is
        // set", and a fresh config sets none. So the generated file displayed a security setting in its
        // enabled-looking form while the thing that activates it was invisible — the operator had no way to
        // learn the key exists, because the branch above only mentions it once it is already configured.
        //
        // Stated here rather than left to the docs for the same reason `proteus_environment` states its
        // values here: the file an operator edits is the surface they read. The secret itself still is not
        // written — that part was right, and the comment above says why.
        let _ = writeln!(s, "# proteus_morph above does NOTHING until a shared community secret is set. It is");
        let _ = writeln!(s, "# supplied out-of-band (never in this file, which gets copied between hosts), and");
        let _ = writeln!(s, "# until then this node speaks unshaped FANOS on the wire. Supply it by file:");
        // **Naming the mechanism, not just the policy.** "Out of band" told the operator where the secret
        // must not go and not how to supply it, and the flag that used to be the obvious answer took the
        // secret as an argv value — readable by every local account from `ps` (#13). That flag now refuses,
        // so the file recipe is written out here, umask included: the default umask writes the secret
        // world-readable and the node refuses to read such a file at all.
        let _ = writeln!(s, "#   (umask 077; printf %s 'YOUR-COMMUNITY-SECRET' > proteus.secret)");
        let _ = writeln!(s, "#   fanos node --proteus-secret-file proteus.secret");
    }
    // **Mentioned in EVERY fresh config, set or not** (#13), and for the reason the block above records one
    // field over: a mechanism an operator cannot discover from the file they edit does not exist to them. This
    // one has to be discovered BEFORE it is needed — a community secret is rotated by a procedure, and an
    // operator who learns of the procedure only when the rotation has already gone wrong has learnt it too
    // late. The value is never written for the same reason `proteus_secret`'s never is.
    let _ = writeln!(s, "# proteus_accept_secrets = <a secret to ACCEPT but not emit under>  (repeat per secret)");
    let _ = writeln!(s, "#   Rotating the community secret has no flag day, and this key is how. Phase 1: every");
    let _ = writeln!(s, "#   node ACCEPTS the new secret here — nothing on the wire changes. Phase 2, once every");
    let _ = writeln!(s, "#   node has done phase 1: move the new one to proteus_secret and put the old one here.");
    let _ = writeln!(s, "#   Phase 3: drop the old one. Doing phase 2 early makes this node unreadable to every");
    let _ = writeln!(s, "#   peer still on the old secret."); 
}

/// Write the overlay choices that differ from their defaults (#352).
///
/// Called as one line from [`render_config`] rather than three blocks inline, because they are one group and
/// that function sits at its line bound — a renderer grows one block per key, so a group of keys that move
/// together should cost one call. Written only on a difference, like every key there: a rendered config that
/// restates every default is a config whose diff stops meaning anything.
///
/// Split from [`render_config`] for the same reason its own arms are split: a renderer grows one block per
/// key, and a group of keys that move together should cost one call rather than three. `s` is the buffer the
/// caller is building; each writes only on a difference, so a default-valued config renders none of them.
fn render_overlay_choices(s: &mut String, c: crate::config::OverlayChoices, d: crate::config::OverlayChoices) {
    // **Mentioned in every fresh config, set or not**, for the reason this file states one field over: a
    // mechanism an operator cannot discover from the file they edit does not exist to them. #352 made these
    // three choices expressible and that is only half the fix — a key nobody can find is barely better than
    // a key that does not exist, and it is the same defect one step further out.
    let _ = writeln!(s);
    let _ = writeln!(s, "# --- overlay behaviour (defaults shown; each is a deployment choice) ---");
    if c.self_healing == d.self_healing {
        let _ = writeln!(s, "# self_healing = {}   (false: sense and diagnose, never act)", c.self_healing);
    } else {
        let _ = writeln!(s, "self_healing = {}", c.self_healing);
    }
    if c.require_self_certified_membership == d.require_self_certified_membership {
        let _ = writeln!(
            s,
            "# require_self_certified_membership = {}   (the signed descriptor it checks is produced now, but what a cell does with this ON has not been measured)",
            c.require_self_certified_membership
        );
    } else {
        let _ = writeln!(s, "require_self_certified_membership = {}", c.require_self_certified_membership);
    }
    if c.require_admission == d.require_admission {
        let _ = writeln!(
            s,
            "# require_admission = {}   (true needs an admission policy installed; without one it rejects every peer)",
            c.require_admission
        );
    } else {
        let _ = writeln!(s, "require_admission = {}", c.require_admission);
    }
}

/// The file a node's beacon provisioning is written to inside its config directory.
pub const BEACON_FILE: &str = "beacon.params";

/// The roles a node offers by default when the operator expresses no preference.
///
/// Relay and storage: the two that make a fresh node useful to the network the moment it starts, and the two whose
/// cost is bounded by configuration rather than by what strangers ask of it. `exit` is deliberately absent — an
/// exit carries other people's traffic to the clear internet under this host's address, which is a decision with
/// legal weight and must be typed, never defaulted into.
#[must_use]
pub fn default_roles() -> RoleSet {
    RoleSet { relay: true, storage: true, service: false, exit: false, rendezvous: false, ingress: false }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use crate::config::SeatSource;
    use super::*;

    /// **An environment that does not name a home directory is refused, not answered with the cwd** (#312).
    ///
    /// The three refusable inputs are each a `HOME` a real deployment produces: unset is what a service
    /// manager hands a daemon, empty is what a script that meant to clear it produces, and relative is what a
    /// `HOME=fanos` in a container image produces. All three used to yield `PathBuf::from(".")`, which puts
    /// the node's **identity key** wherever the process was started — so two starts from two directories are
    /// two different nodes on the cell, with nothing anywhere saying why.
    ///
    /// Falsified by restoring the old body (`map_or_else(|| PathBuf::from("."), PathBuf::from)`): the first
    /// three assertions fail, each naming the value it got. The fourth is the control — an ordinary absolute
    /// `HOME` must still pass, or the guard would be green for the trivial reason that it refuses everything.
    #[test]
    fn a_home_that_would_make_the_layout_depend_on_the_working_directory_is_refused() {
        use std::ffi::OsString;

        assert_eq!(classify_home(None), Err(HomeUnknown::Unset), "an unset HOME must not become a path");
        assert_eq!(
            classify_home(Some(OsString::from(""))),
            Err(HomeUnknown::Unset),
            "an empty HOME is an unset HOME — `PathBuf::from(\"\")` joins to a relative path",
        );
        assert_eq!(
            classify_home(Some(OsString::from("fanos/home"))),
            Err(HomeUnknown::NotAbsolute(PathBuf::from("fanos/home"))),
            "a relative HOME is the same defect one indirection away: the layout would follow the cwd",
        );
        // CONTROL: the ordinary case must pass, or every assertion above is satisfied by a guard that
        // refuses unconditionally and says nothing about the classification.
        assert_eq!(
            classify_home(Some(OsString::from("/home/op"))),
            Ok(PathBuf::from("/home/op")),
            "an absolute HOME is the whole point of the layout and must be accepted",
        );
    }

    /// A machine-wide install is not refused for want of a `HOME` its unit path never reads (#312).
    ///
    /// The guard against a fix that is wider than its defect. `unit_path_here` resolves the home per arm,
    /// so `SystemdSystem` — whose answer is a constant — is reachable in any environment. Falsified by
    /// hoisting `home_dir()?` above the `match`: this fails whenever the test process has no `HOME`, which
    /// is exactly the deployment the hoisted version would have broken.
    #[test]
    fn the_machine_wide_unit_path_needs_no_home_directory() {
        let system = ServiceManager::SystemdSystem
            .unit_path_here()
            .expect("a machine-wide unit path is a constant and cannot depend on the environment");
        assert_eq!(
            system.as_deref(),
            Some(Path::new(SYSTEM_UNIT_PATH)),
            "the root install's unit path must be the same constant `unit_path` returns",
        );
        // And the arm with no unit at all answers without consulting the environment either.
        assert_eq!(ServiceManager::None.unit_path_here().expect("no manager, no question to ask"), None);
    }

    /// **A fresh config names every deployment choice, set or not** (#352).
    ///
    /// This file already states the rule one field over — *"a mechanism an operator cannot discover from the
    /// file they edit does not exist to them"* — and applies it to `state`, `bootstrap`,
    /// `admission_difficulty`, `telemetry_epsilon`, `proteus_environment` and `proteus_accept_secrets`, each
    /// written as a commented default when unset.
    ///
    /// The three overlay choices were first rendered only when they DIFFERED from the default, which meant a
    /// wizard-written config never mentioned them. That is the same defect #352 set out to fix, one step
    /// further out: making a choice expressible and leaving it undiscoverable is barely better than not
    /// offering it. Asserted on a DEFAULT config, because that is the only case where the omission was
    /// possible — a non-default value was always written.
    #[test]
    fn a_fresh_config_mentions_every_overlay_choice() {
        let text = render_config(&NodeConfig::default(), Path::new("/etc/fanos/node.key"));
        for key in ["self_healing", "require_self_certified_membership", "require_admission"] {
            // **The COMMENTED form specifically**, and that is not pedantry. Asserting only that the key
            // appears is satisfiable by writing it as a live setting, which is a different act: a default
            // written as a setting is PINNED in the file, so the day the default changes every config the
            // wizard ever wrote keeps the old value and nothing says so. Checking the `#` is what separates
            // documenting a choice from making one.
            //
            // The first version of this asserted the parse instead — that reading the rendered text back
            // yields the default overlay — and that assertion **could not fail**: hints are only written when
            // the value already equals the default, so the comparison holds whether or not the `#` is there.
            // Found by falsifying it, not by reading it.
            let commented = format!("# {key} = ");
            assert!(
                text.contains(&commented),
                "a config rendered from defaults does not carry `{commented}…`, so either the choice is \
                 invisible to an operator reading the file the wizard wrote, or it is written as a live \
                 setting and the default is pinned into every generated config.\n--- rendered ---\n{text}"
            );
        }
        // The file the wizard writes must still parse, and the hints must leave the overlay at its default —
        // weaker than the check above and kept as the round-trip half rather than as the discriminator.
        let back = NodeConfig::from_config_str(&text).expect("the wizard's own output must parse");
        assert_eq!(back.overlay, NodeConfig::default().overlay, "a hint changed the parsed configuration");
    }


    #[test]
    fn the_rendered_config_reads_back_field_for_field() {
        // The property the wizard rests on: what it writes, the daemon reads. A renderer that drops a field
        // produces a node that silently reverts it at the next restart, and nothing in the running system says so.
        let c = NodeConfig {
            listen: "0.0.0.0:9931".parse().expect("a valid listen address"),
            plane_order: 7,
            roles: RoleSet { relay: true, storage: true, service: true, exit: false, rendezvous: true, ingress: true },
            telemetry_epsilon: Some(0.75),
            admission_difficulty: Some(18),
            epoch_period: std::time::Duration::from_secs(120),
            mix_mean_delay: std::time::Duration::from_millis(45),
            cover_interval: std::time::Duration::from_millis(900),
            start_heartbeat: false,
            state_path: Some(PathBuf::from("/var/lib/fanos")),
            ..NodeConfig::default()
        };

        let text = render_config(&c, Path::new("/etc/fanos/identity.key"));
        let back = NodeConfig::from_config_str(&text).expect("the wizard's own output must parse");

        assert_eq!(back.listen, c.listen, "listen");
        assert_eq!(back.plane_order, c.plane_order, "plane_order");
        assert_eq!(back.roles.to_string(), c.roles.to_string(), "roles");
        assert_eq!(back.telemetry_epsilon, c.telemetry_epsilon, "telemetry_epsilon");
        assert_eq!(back.admission_difficulty, c.admission_difficulty, "admission_difficulty");
        assert_eq!(back.epoch_period, c.epoch_period, "epoch_period");
        assert_eq!(back.mix_mean_delay, c.mix_mean_delay, "mix_mean_delay");
        assert_eq!(back.cover_interval, c.cover_interval, "cover_interval");
        assert_eq!(back.start_heartbeat, c.start_heartbeat, "heartbeat");
        assert_eq!(back.overlay, c.overlay, "overlay choices");
        assert_eq!(back.identity_path.as_deref(), Some(Path::new("/etc/fanos/identity.key")), "identity");
        assert_eq!(back.state_path, c.state_path, "state");
        assert_eq!(back.service_path, c.service_path, "service");
        assert_eq!(back.exit_path, c.exit_path, "exit");
        assert_eq!(back.ingress_path, c.ingress_path, "ingress_params");
    }

    /// **Every field of `NodeConfig` is accounted for — by the compiler, not by a list someone maintains.**
    ///
    /// The two tests above assert the round trip field by field, which is the right property and the wrong
    /// mechanism: whether the list is COMPLETE is exactly what a hand-written list cannot say. Measured when
    /// this landed: 22 `pub` fields, 17 named across both tests, and the two never checked were
    /// `proteus_morph` and `proteus_environment` — the settings #113 showed are worth two hops of censorship
    /// chain depth. A renderer that dropped either would leave a node reverting to the default morph at its
    /// next restart, with this suite green.
    ///
    /// The `let NodeConfig { … } = &c;` below has **no `..`**, so adding a field to the struct stops this
    /// test compiling. That is the same shape #165 gave `render_health`, and it is stronger than a runtime
    /// count: the reminder arrives at the moment the field is added rather than at the next full test run.
    ///
    /// Three fields are deliberately not compared to a round-tripped value, and each says why below. The
    /// bindings still exist, so the exemptions are visible here rather than implied by absence.
    #[test]
    fn the_round_trip_covers_every_field_the_compiler_knows_about() {
        let c = NodeConfig {
            // Deliberately the PERMISSIVE value, so the assertion below is about the render/parse
            // path resetting it rather than about the fixture already holding the default.
            bootstrap_source: SeatSource::Observed,
            listen: "127.0.0.1:9977".parse().expect("a valid listen address"),
            plane_order: 4,
            telemetry_epsilon: Some(0.5),
            state_path: Some(PathBuf::from("/var/lib/fanos-ratchet")),
            roles: RoleSet { relay: false, storage: true, service: false, exit: true, rendezvous: true, ingress: false },
            mix_mean_delay: std::time::Duration::from_millis(31),
            cover_interval: std::time::Duration::from_millis(777),
            start_heartbeat: false,
            // All three flipped away from their defaults, so a writer that skips one is caught by the
            // comparison below rather than by the destructure alone.
            overlay: crate::config::OverlayChoices {
                self_healing: false,
                require_self_certified_membership: true,
                require_admission: true,
            },
            epoch_period: std::time::Duration::from_secs(301),
            admission_difficulty: Some(11),
            // The two the hand-written list never reached, set to something no default would produce.
            proteus_morph: fanos_quic::Morph::TlsTunnel,
            proteus_environment: Some(fanos_quic::Environment::DeepCensorship),
            ..NodeConfig::default()
        };
        let text = render_config(&c, Path::new("/etc/fanos/ratchet.key"));
        let back = NodeConfig::from_config_str(&text).expect("the wizard's own output must parse");

        // No `..`: a new field is a compile error here, which is the whole point of the test.
        let NodeConfig {
            listen,
            plane_order,
            telemetry_epsilon,
            identity_path,
            service_path,
            exit_path,
            ingress_path,
            state_path,
            bootstrap,
            bootstrap_source,
            roles,
            mix_mean_delay,
            cover_interval,
            start_heartbeat,
            overlay,
            beacon,
            epoch_period,
            admission_difficulty,
            service,
            exit,
            ingress,
            proteus_secret,
            proteus_morph,
            proteus_environment,
            proteus_accept_secrets,
        } = &c;

        assert_eq!(&back.listen, listen, "listen");
        assert_eq!(&back.plane_order, plane_order, "plane_order");
        assert_eq!(&back.telemetry_epsilon, telemetry_epsilon, "telemetry_epsilon");
        assert_eq!(&back.state_path, state_path, "state_path");
        assert_eq!(&back.bootstrap, bootstrap, "bootstrap");
        assert_eq!(back.roles.to_string(), roles.to_string(), "roles");
        assert_eq!(&back.mix_mean_delay, mix_mean_delay, "mix_mean_delay");
        assert_eq!(&back.cover_interval, cover_interval, "cover_interval");
        assert_eq!(&back.start_heartbeat, start_heartbeat, "start_heartbeat");
        assert_eq!(&back.overlay, overlay, "overlay choices");
        assert_eq!(&back.epoch_period, epoch_period, "epoch_period");
        assert_eq!(&back.admission_difficulty, admission_difficulty, "admission_difficulty");
        assert_eq!(&back.proteus_morph, proteus_morph, "proteus_morph — the censorship transform (#113)");
        assert_eq!(&back.proteus_environment, proteus_environment, "proteus_environment");
        // The identity is an ARGUMENT to the renderer rather than a field it reads, so the round trip is from
        // that argument into the parsed config — which is what a caller of `render_config` actually relies on.
        assert_eq!(
            back.identity_path.as_deref(),
            Some(Path::new("/etc/fanos/ratchet.key")),
            "identity_path comes from the renderer's argument, not from `c`"
        );
        assert_eq!(identity_path, &None, "and the fixture deliberately leaves the field unset");

        // --- deliberately not round-tripped, each for its own reason ---

        // `bootstrap_source` is a CONSTRUCTOR ARGUMENT, not a setting, and the round trip must not create
        // one: it says whether a repeated coordinate in `bootstrap` is an operator's typo (refuse) or a
        // live collision among running peers (admit). Rendering it would let a provisioning file declare
        // its own duplicate acceptable, which is the exact hole `seed_directory` exists to close. So the
        // property asserted here is the OPPOSITE of a round trip — the parse must come back at the
        // fail-closed default whatever the fixture was built with (#186).
        assert_eq!(bootstrap_source, &SeatSource::Observed, "the fixture sets the permissive value");
        assert_eq!(
            back.bootstrap_source,
            SeatSource::Provisioned,
            "a rendered-and-reparsed config must come back refusing duplicates, or a file could relax it"
        );

        // A shared community secret does not belong in a file an operator copies between hosts, so the
        // renderer writes a comment naming it instead of the value. The property worth asserting is
        // therefore the OPPOSITE one: that the comment does not parse back as a setting.
        assert_eq!(proteus_secret, &None, "the fixture sets no secret");
        assert!(back.proteus_secret.is_none(), "a rendered `# proteus_secret` comment must stay a comment");
        // **Not-round-tripped is not the same as not-mentioned, and this is the half that was missing.** The
        // destructure above makes a NEW field a compile error, but a field the renderer never writes is
        // invisible to it — the round trip has nothing to compare. So `proteus_secret` was absent from a
        // fresh config entirely, while `proteus_morph = polymorph` sat one line up reading as "obfuscation is
        // on". Its own doc says the morph "only takes effect when `proteus_secret` is set".
        //
        // Asserted on the UNSET branch specifically: the `is_some()` branch already mentioned the key, so a
        // test that only checked "the word appears somewhere" would have passed all along.
        assert!(
            text.contains("does NOTHING until a shared community secret is set"),
            "a config with no secret must say that the morph it displays is inert:\n{text}"
        );

        // The rollover's receive-only secrets are secrets, so the same rule as `proteus_secret` applies and
        // the same OPPOSITE property is what is worth asserting: the rendered comment must not parse back as
        // a setting. What is NOT the same is discoverability — this key is mentioned in every fresh config,
        // set or not, because a rotation procedure has to be known before the rotation, and the branch that
        // only speaks once the key is configured would tell an operator about it exactly too late.
        assert!(proteus_accept_secrets.is_empty(), "the fixture sets no rollover");
        assert!(
            back.proteus_accept_secrets.is_empty(),
            "a rendered `# proteus_accept_secrets` comment must stay a comment"
        );
        assert!(
            text.contains("Rotating the community secret has no flag day"),
            "every fresh config must name the rollover procedure, set or not:\n{text}"
        );

        // The four provisioning bundles are loaded from FILES the config names. Rendering writes the paths;
        // parsing re-reads them, and in this fixture no such file exists, so the parsed side is `None` by
        // construction. `the_rendered_config_reads_back_field_for_field` covers the three paths; the beacon
        // has no path field at all because the renderer derives it from the config directory
        // (`dir.join(BEACON_FILE)`, emitted only if the file is there) — a different design from the other
        // three and a deliberate one, since `ensure_beacon` creates that file at a fixed name.
        assert!(
            beacon.is_none() && service.is_none() && exit.is_none() && ingress.is_none(),
            "no provisioning bundles in this fixture"
        );
        assert_eq!(
            (&back.service_path, &back.exit_path, &back.ingress_path),
            (service_path, exit_path, ingress_path),
            "the three provisioning PATHS round-trip; their loaded contents are files, not config"
        );
    }

    #[test]
    fn a_defaulted_config_also_round_trips() {
        // The commented-out lines must be comments, not settings. A renderer that writes its own documentation as
        // live keys would turn "unset" into "explicitly set to the default" — which reads identically until a
        // default changes underneath a deployed node.
        let c = NodeConfig::default();
        let text = render_config(&c, Path::new("/tmp/id.key"));
        let back = NodeConfig::from_config_str(&text).expect("a default config must round-trip too");
        assert_eq!(back.telemetry_epsilon, None, "an omitted ε must stay omitted, not become a number");
        assert_eq!(back.admission_difficulty, None, "an omitted PoW must stay omitted");
        assert!(back.bootstrap.is_empty(), "the bootstrap comment must not parse as a peer");
        assert!(back.state_path.is_none(), "the state comment must not parse as a directory");
        assert!(back.service_path.is_none(), "the service comment must not parse as a path");
        assert!(back.exit_path.is_none(), "the exit comment must not parse as a path");
        assert!(back.ingress_path.is_none(), "the ingress comment must not parse as a path");
    }

    #[test]
    fn the_default_port_is_stable_rather_than_ephemeral() {
        // The wizard prints a seed address for other operators to dial. Built on `NodeConfig::default()`, which
        // binds port 0, that address would name a port the node abandons at its next restart — so the whole
        // point of publishing it is lost. Caught by running `fanos init` and reading `listen = 0.0.0.0:0`.
        assert_ne!(DEFAULT_PORT, 0, "an installed node must not take an ephemeral port");
        assert_eq!(
            NodeConfig::default().listen.port(),
            0,
            "if the library default stops being ephemeral, this constant's reason for existing has changed"
        );
    }

    #[test]
    fn a_free_port_is_actually_bindable() {
        let port = free_udp_port(41_000, 64).expect("some port in a 64-wide window is free");
        let bound = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port)));
        assert!(bound.is_ok(), "free_udp_port returned {port}, which does not bind");
    }

    #[test]
    fn an_occupied_port_is_skipped() {
        // The whole reason this probes rather than assumes.
        let held = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).expect("bind an ephemeral port");
        let taken = held.local_addr().expect("its address").port();
        let found = free_udp_port(taken, 16).expect("a later port is free");
        assert_ne!(found, taken, "the probe handed back a port it could not have bound");
    }

    /// **The kill ceiling must sit above the worst case the node's own bounds permit** (#207).
    ///
    /// The whole reason this pair exists rather than one number: `MemoryMax` is where systemd concludes the
    /// process is broken, and a peer filling its QUIC receive windows is not the process being broken — it
    /// is the caps doing their job. Set the kill at the steady ceiling and a flood becomes a kill, which is
    /// the failure this task was opened to avoid rather than to ship.
    ///
    /// Read back out of the **rendered text**, not from the functions, and compared against the three
    /// derivations independently. A guard that called `memory_max_bytes()` on both sides would be an
    /// identity, green the day someone writes a literal into the unit.
    #[test]
    fn the_units_kill_ceiling_admits_a_full_inbound_flood() {
        let unit = render_systemd_unit(
            Path::new("/usr/local/bin/fanos"),
            Path::new("/etc/fanos/fanos.conf"),
            Path::new("/var/lib/fanos"),
            false,
        );
        let read = |key: &str| -> usize {
            unit.lines()
                .find_map(|l| l.strip_prefix(key))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or_else(|| panic!("the unit must state {key} as a byte count:\n{unit}"))
        };
        let (high, max) = (read("MemoryHigh="), read("MemoryMax="));

        let steady =
            fanos_primitives::budget::allocated() + fanos_primitives::budget::PROCESS_RESIDENT;
        let flood = fanos_quic::inbound_credit_ceiling();
        println!(
            "MemoryHigh={} MiB  MemoryMax={} MiB  (steady {} MiB + inbound credit {} MiB)",
            high >> 20,
            max >> 20,
            steady >> 20,
            flood >> 20
        );

        assert_eq!(
            high, steady,
            "MemoryHigh is the *steady* ceiling: every named share plus measured residency. It reads \
             {high} and the shares sum to {steady} — either a share moved and the unit did not follow, or \
             a number was typed here instead of computed."
        );
        assert!(
            max >= steady + flood,
            "MemoryMax is {max}, below the {} bytes a full inbound flood can reach ({steady} steady + \
             {flood} of QUIC receive credit). systemd would kill the node under exactly the load \
             MAX_INBOUND_CONNECTIONS and the per-connection window exist to survive (#207, #245).",
            steady + flood
        );
        // And the descriptor limit, which is only derivable because every accept loop now has a bound.
        let nofile = read("LimitNOFILE=");
        println!("LimitNOFILE={nofile}");
        let consumers = 1
            + fanos_diaulos::budget::MAX_SESSIONS
            + crate::exit::MAX_UDP_DATAGRAM_SESSIONS
            + fanos_proxy::budget::MAX_CONNECTIONS
            + fanos_proxy::budget::MAX_ASSOCIATIONS
            + 4
            + 3;
        assert!(
            nofile >= consumers,
            "LimitNOFILE is {nofile}, below the {consumers} descriptors this node's own bounds permit at \
             once. A node that hits the OS limit fails in whichever subsystem asks next, not in the one \
             that overspent (#207)."
        );

        assert!(
            max > high,
            "MemoryMax ({max}) must sit strictly above MemoryHigh ({high}), or the kill fires before the \
             throttle and the two directives answer one question instead of two"
        );
    }

    #[test]
    fn the_signal_the_unit_sends_is_one_the_binary_handles() {
        // **A guard on the join, not on either half.** "The unit stops the node with SIGTERM" and "the node
        // handles SIGINT" are both defensible sentences; together they mean every `systemctl stop` kills the
        // process before it persists. Neither file can see the mismatch, so the check has to read both — the
        // rendered unit for what will be *sent*, and the binary's own list for what is *caught*.
        let unit = render_systemd_unit(
            Path::new("/usr/local/bin/fanos"),
            Path::new("/etc/fanos/fanos.conf"),
            Path::new("/var/lib/fanos"),
            false,
        );
        // systemd's default when the key is absent is SIGTERM, so an omitted key is not a pass — it is the
        // same obligation, unstated. Read the value if present and fall back to what systemd would do.
        let sent = unit
            .lines()
            .find_map(|l| l.strip_prefix("KillSignal="))
            .unwrap_or("SIGTERM")
            .trim();
        assert!(
            crate::shutdown::HANDLED_STOP_SIGNALS.contains(&sent),
            "the unit stops the node with {sent}, which is not in {:?} — an orchestrated stop would \
             terminate it before the store is persisted",
            crate::shutdown::HANDLED_STOP_SIGNALS
        );
        // The drain needs a budget on the supervisor's side too, or systemd SIGKILLs mid-write.
        assert!(
            unit.lines().any(|l| l.starts_with("TimeoutStopSec=")),
            "the unit must give the drain a stated budget:\n{unit}"
        );
    }

    #[test]
    fn the_systemd_unit_starts_the_binary_against_the_written_config() {
        // A unit whose ExecStart is wrong fails at boot, on a machine nobody is watching, weeks later.
        let unit = render_systemd_unit(
            Path::new("/usr/local/bin/fanos"),
            Path::new("/etc/fanos/fanos.conf"),
            Path::new("/var/lib/fanos"),
            false,
        );
        assert!(
            unit.contains("ExecStart=/usr/local/bin/fanos node --config /etc/fanos/fanos.conf"),
            "the unit must launch the node against the generated config:\n{unit}"
        );
        assert!(unit.contains("Restart=on-failure"), "a node that dies must come back");
        assert!(unit.contains("StartLimitIntervalSec=0"), "retrying forever is by design; systemd must not give up");
        assert!(unit.contains("NoNewPrivileges=yes"), "a process that talks to strangers must not gain privileges");
        assert!(unit.contains("WantedBy=multi-user.target"), "a system unit belongs to multi-user.target");
    }

    #[test]
    fn a_user_unit_differs_where_it_must_and_only_there() {
        let user = render_systemd_unit(Path::new("/u/fanos"), Path::new("/c/f.conf"), Path::new("/d"), true);
        assert!(user.contains("WantedBy=default.target"), "a user unit belongs to default.target");
        assert!(
            !user.contains("DynamicUser=yes"),
            "DynamicUser is a system-manager facility; in a user unit it fails the unit rather than hardening it"
        );
    }

    #[test]
    fn the_launchd_plist_is_well_formed_and_points_at_the_config() {
        let plist = render_launchd_plist(
            Path::new("/usr/local/bin/fanos"),
            Path::new("/Users/x/cfg/fanos.conf"),
            Path::new("/Users/x/data"),
            Path::new("/Users/x/fanos.log"),
        );
        assert!(plist.starts_with("<?xml"), "a plist must be XML");
        assert!(plist.contains("<key>Label</key><string>network.fanos.node</string>"));
        assert!(plist.contains("<string>/Users/x/cfg/fanos.conf</string>"), "it must name the generated config");
        assert!(plist.contains("<key>RunAtLoad</key><true/>"), "it must start at load");
        assert_eq!(plist.matches("<dict>").count(), plist.matches("</dict>").count(), "balanced dicts");
    }

    #[test]
    fn the_two_path_layouts_never_collide() {
        let system = Paths::system();
        let user = Paths::user_in(Path::new("/home/op"), false);
        assert_ne!(system.config, user.config);
        assert_ne!(system.identity, user.identity);
        assert!(user.config.starts_with("/home/op"), "an unprivileged install stays inside the user's home");
        assert!(system.config.starts_with("/etc"), "a root install is machine-wide");
    }

    #[test]
    fn the_macos_layout_follows_apples_convention_not_xdg() {
        let mac = Paths::user_in(Path::new("/Users/op"), true);
        assert!(
            mac.config.starts_with("/Users/op/Library/Application Support/fanos"),
            "macOS tooling looks in Application Support, not .config: {}",
            mac.config.display()
        );
    }

    #[test]
    fn the_default_roles_are_useful_and_never_include_exit() {
        let r = default_roles();
        assert!(r.relay && r.storage, "a fresh node should be useful to the network immediately");
        assert!(
            !r.exit,
            "an exit carries strangers' traffic to the clear internet under this host's address — that is typed, \
             never defaulted into"
        );
    }

    #[test]
    fn every_manager_that_has_a_unit_path_can_be_installed_started_stopped_and_removed() {
        // A supervisor this tool can install into but not remove from is a supervisor it should not touch: the
        // operator would be left with a service only manual surgery gets rid of.
        for m in [ServiceManager::SystemdSystem, ServiceManager::SystemdUser, ServiceManager::Launchd] {
            let path = m.unit_path(Path::new("/home/op")).expect("a real manager has a unit path");
            assert!(!m.activation(&path).is_empty(), "{m:?} installs a unit but cannot start it");
            assert!(!m.stop(&path).is_empty(), "{m:?} can start but not stop");
            assert!(!m.start(&path).is_empty(), "{m:?} can stop but not start again");
            assert!(!m.deactivation(&path).is_empty(), "{m:?} can install but not remove");
        }
        assert!(ServiceManager::None.unit_path(Path::new("/home/op")).is_none());
        assert!(ServiceManager::None.activation(Path::new("/x")).is_empty());
        assert!(ServiceManager::None.deactivation(Path::new("/x")).is_empty());
    }

    #[test]
    fn a_user_systemd_install_enables_lingering() {
        // Without it the unit stops at logout, which on a server presents as "it worked until I closed the
        // terminal" — the most confusing failure this wizard could ship.
        let acts = ServiceManager::SystemdUser.activation(Path::new("/home/op/.config/systemd/user/fanos.service"));
        assert!(
            acts.iter().any(|a| a.iter().any(|w| w == "enable-linger")),
            "a user unit must survive logout: {acts:?}"
        );
    }

    #[test]
    fn removal_disables_and_does_not_merely_stop() {
        // Stopping alone leaves a unit that returns at the next boot — the removal an operator believes they
        // performed and did not.
        for m in [ServiceManager::SystemdSystem, ServiceManager::SystemdUser] {
            let cmds = m.deactivation(Path::new("/x"));
            let flat: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
            assert!(flat.iter().any(|c| c.contains("disable")), "{m:?} removal must disable: {flat:?}");
        }
        let mac = ServiceManager::Launchd.deactivation(Path::new("/x"));
        assert!(
            mac.iter().any(|c| c.iter().any(|w| w == "-w")),
            "launchctl unload without -w leaves the agent enabled: {mac:?}"
        );
    }

    #[test]
    fn a_user_manager_always_carries_the_user_flag() {
        // A `--user` unit addressed with a system-wide systemctl silently operates on a different (empty)
        // manager, so every command reports success and nothing happens.
        for cmds in [
            ServiceManager::SystemdUser.activation(Path::new("/x")),
            ServiceManager::SystemdUser.stop(Path::new("/x")),
            ServiceManager::SystemdUser.start(Path::new("/x")),
            ServiceManager::SystemdUser.deactivation(Path::new("/x")),
        ] {
            for cmd in cmds.iter().filter(|c| c.first().is_some_and(|p| p == "systemctl")) {
                assert!(cmd.contains(&"--user".to_owned()), "user-manager command without --user: {cmd:?}");
            }
        }
    }

    /// **The three role files survive the round trip, with real files on disk.**
    ///
    /// The round-trip test above compares `None` to `None` for these, which is no test at all: the parser has
    /// to *read* each file to accept the key, so the only honest fixture is real provisioning. Written because
    /// the whole reason these keys exist (#90) is that a configured role used to vanish between restarts, and
    /// an assertion that cannot fail would have shipped the same defect with a green tick over it.
    #[test]
    fn a_configured_service_and_exit_survive_the_round_trip() {
        let dir = std::env::temp_dir().join(format!("fanos-roles-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let (svc, exit) = (dir.join("service.conf"), dir.join("exit.conf"));
        std::fs::write(&svc, format!("seed = {}\nline = 1:0:0, 0:1:0\nthreshold = 1\n", "ab".repeat(32)))
            .expect("write service params");
        std::fs::write(&exit, format!("seed = {}\nports = 80, 443\n", "cd".repeat(32)))
            .expect("write exit params");

        let c = NodeConfig {
            service_path: Some(svc.clone()),
            exit_path: Some(exit.clone()),
            ..NodeConfig::default()
        };
        let text = render_config(&c, Path::new("/etc/fanos/identity.key"));
        let back = NodeConfig::from_config_str(&text).expect("the wizard's own output must parse");

        assert_eq!(back.service_path.as_deref(), Some(svc.as_path()), "the service path survives");
        assert_eq!(back.exit_path.as_deref(), Some(exit.as_path()), "the exit path survives");
        // And the *effect* of the setting, not only its text: reading the file is what makes the key mean
        // something, and implying the role is what makes it usable without a second setting.
        assert!(back.roles.service, "a configured service file implies the service role");
        assert!(back.roles.exit, "a configured exit file implies the exit role");
        assert_eq!(back.service.expect("service params were read").threshold, 1);
        assert_eq!(back.exit.expect("exit params were read").allowed_ports, vec![80, 443]);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}