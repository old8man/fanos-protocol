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
    #[must_use]
    pub fn detect() -> Self {
        if is_root() {
            return Self::system();
        }
        let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
        Self::user_in(&home, cfg!(target_os = "macos"))
    }
}

/// Whether this process is running with uid 0.
#[must_use]
pub fn is_root() -> bool {
    // No libc dependency for one number: the effective uid is what `id -u` reports, and on the platforms this
    // binary targets `/proc` and `id` are not both guaranteed — but `USER`/`LOGNAME` are spoofable, so neither is
    // used. `geteuid` via the standard library is unavailable, so the honest check is the one filesystem fact that
    // cannot be faked: whether we can write to a root-only location.
    Path::new("/etc").metadata().is_ok_and(|m| {
        use std::os::unix::fs::MetadataExt as _;
        m.uid() == current_uid()
    })
}

/// This process's effective uid, read without a libc dependency.
fn current_uid() -> u32 {
    // A file we certainly own: our own temporary marker is overkill, and `/proc/self` is Linux-only. The portable
    // fact is that a file we create is owned by us.
    std::env::temp_dir().metadata().map_or(u32::MAX, |_| {
        use std::os::unix::fs::MetadataExt as _;
        // `std::env::temp_dir()` is shared, so read our own uid off a file we made rather than off the directory.
        let probe = std::env::temp_dir().join(format!("fanos-uid-probe-{}", std::process::id()));
        let uid = std::fs::write(&probe, b"")
            .ok()
            .and_then(|()| probe.metadata().ok())
            .map_or(u32::MAX, |m| m.uid());
        let _ = std::fs::remove_file(&probe);
        uid
    })
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
    #[must_use]
    pub fn unit_path(self, home: &Path) -> Option<PathBuf> {
        match self {
            Self::SystemdSystem => Some(PathBuf::from("/etc/systemd/system/fanos.service")),
            Self::SystemdUser => Some(home.join(".config/systemd/user/fanos.service")),
            Self::Launchd => Some(home.join("Library/LaunchAgents/network.fanos.node.plist")),
            Self::None => None,
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
    // A node that cannot reach the overlay retries forever by design; without this, systemd gives up on it.
    let _ = writeln!(s, "StartLimitIntervalSec=0");
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
    let _ = writeln!(s, "role = {}", config.roles);
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
    let _ = writeln!(s, "mix_mean_delay = {}", config.mix_mean_delay.as_millis());
    let _ = writeln!(s, "cover_interval = {}", config.cover_interval.as_millis());
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
    match config.telemetry_epsilon {
        Some(eps) => {
            let _ = writeln!(s, "telemetry_epsilon = {eps}");
        }
        None => {
            let _ = writeln!(s, "# telemetry_epsilon = 1.0   (omitted: this node publishes no readings)");
        }
    }
    let _ = writeln!(s);
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
    }
    s
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
    RoleSet { relay: true, storage: true, service: false, exit: false, rendezvous: false }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_rendered_config_reads_back_field_for_field() {
        // The property the wizard rests on: what it writes, the daemon reads. A renderer that drops a field
        // produces a node that silently reverts it at the next restart, and nothing in the running system says so.
        let c = NodeConfig {
            listen: "0.0.0.0:9931".parse().expect("a valid listen address"),
            plane_order: 7,
            roles: RoleSet { relay: true, storage: true, service: true, exit: false, rendezvous: true },
            telemetry_epsilon: Some(0.75),
            admission_difficulty: Some(18),
            epoch_period: std::time::Duration::from_secs(120),
            mix_mean_delay: std::time::Duration::from_millis(45),
            cover_interval: std::time::Duration::from_millis(900),
            start_heartbeat: false,
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
        assert_eq!(back.identity_path.as_deref(), Some(Path::new("/etc/fanos/identity.key")), "identity");
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
}
