//! Node configuration: listen address, persistent identity, bootstrap peers, and roles.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fanos_geometry::Triple;
use fanos_vrf::vss::{VssCommitment, VssShare};

use crate::error::NodeError;

/// The default beacon epoch period (§7.6). Ten minutes is a conservative moving-target cadence: long
/// enough that per-epoch coordinate reshuffle + re-handshake churn is modest, short enough that a
/// grinded seat or a censor's traffic-shape classifier is invalidated well within an attack window.
/// A deployment tunes it via [`NodeConfig::epoch_period`]; all nodes on a network should share it so
/// their epochs stay aligned.
pub const DEFAULT_EPOCH_PERIOD: Duration = Duration::from_secs(600);

/// The distributed-beacon parameters a node needs to run the live epoch clock (§7.6, #108). With
/// `beacon = Some(..)` the node composes an [`OverlayBeaconNode`](crate::OverlayBeaconNode): it
/// verifies and adopts the threshold-DVRF rounds the anchors flood — needing only the public
/// `commitment` and `threshold` — and advances its epoch as the network beacon advances (which in turn
/// rotates rendezvous lines, cover schedules, and the coordinate reshuffle). `share = Some(..)`
/// additionally makes it an **anchor** that contributes partials; `None` is a pure **consumer**. With
/// `beacon = None` the node runs a bare [`OverlayNode`](fanos_runtime::OverlayNode), pinned at genesis
/// (the pre-beacon behaviour), so this is fully backward-compatible.
#[derive(Clone, Debug)]
pub struct BeaconParams {
    /// The beacon group's public commitment — a genesis parameter shared across the network.
    pub commitment: VssCommitment,
    /// The DVRF reconstruction threshold `t`.
    pub threshold: usize,
    /// This node's beacon share if it is an anchor; `None` for a pure consumer.
    pub share: Option<VssShare>,
}

/// The threshold-hosting parameters a node needs to serve a CALYPSO service line (spec §12.3, #99). With
/// `service = Some(..)` **and** the `service` role, the node composes a [`ServiceNode`](crate::ServiceNode):
/// it holds one member key of the service line, joins the line's threshold gather on each intro, and
/// surfaces the recovered request — no single host reads an intro alone.
///
/// The member key is carried as a **seed**, not the secret itself: a member's hybrid KEM secret is
/// deliberately non-serializable (it must not be spilled un-zeroized to a `Vec`; audit #124), so the node
/// regenerates it in memory from this seed via
/// [`HybridKemSecret::generate`](fanos_pqcrypto::HybridKemSecret::generate) — deterministically, so the
/// member's published public key stays stable across restarts (unlike a relay's forward-secure onion key,
/// which is fresh per run). Provisioned out-of-band, exactly like the beacon share: the operator generates
/// each member's seed, collects the derived publics into the published [`ServiceLine`], and hands each
/// member its own seed. Set programmatically, not from the config file.
#[derive(Clone)]
pub struct ServiceParams {
    /// The seed this node regenerates its service-line member KEM keypair from. Secret material.
    pub seed: [u8; 32],
    /// The service line's member coordinates, in the client's seal order.
    pub line: Vec<Triple>,
    /// The reconstruction threshold `t` — how many members must cooperate to serve an intro.
    pub threshold: usize,
}

// The seed regenerates the member secret, so it is itself key material — redacted from `Debug` (which
// `NodeConfig` derives) so a config can be logged without leaking a service's hosting key.
impl fmt::Debug for ServiceParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceParams")
            .field("seed", &"<redacted>")
            .field("line", &self.line)
            .field("threshold", &self.threshold)
            .finish()
    }
}

/// The clearnet-exit parameters a node needs to run the `exit` role (roadmap §3): the DIAULOS service
/// identity clients dial the exit at, plus the [`ExitPolicy`](crate::ExitPolicy) bounding what it relays
/// to. Like a service member's key ([`ServiceParams`]) the identity is carried as a **seed** — the exit
/// regenerates its `StaticKeypair` in memory from it, deterministically, so its published public stays
/// stable across restarts (clients dial a fixed identity). `allowed_ports` empty means any port — an open
/// relay, which the operator opts into explicitly rather than by default.
#[derive(Clone)]
pub struct ExitParams {
    /// The seed the exit regenerates its DIAULOS service `StaticKeypair` from. Secret material.
    pub seed: [u8; 32],
    /// The destination ports this exit will relay to; empty = any port.
    pub allowed_ports: Vec<u16>,
}

// The seed regenerates the exit's service key, so it is redacted from `Debug` (which `NodeConfig` derives).
impl fmt::Debug for ExitParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExitParams")
            .field("seed", &"<redacted>")
            .field("allowed_ports", &self.allowed_ports)
            .finish()
    }
}

impl ExitParams {
    /// Parse exit parameters from a `key = value` text file: `seed` (64 hex chars, the service-key seed)
    /// and `ports` (comma-separated destination ports; omitted or empty = any port).
    ///
    /// # Errors
    /// [`NodeError::Config`] on a malformed line, an unknown key, or a bad value.
    pub fn from_config_str(text: &str) -> Result<Self, NodeError> {
        let mut seed: Option<[u8; 32]> = None;
        let mut allowed_ports: Vec<u16> = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let l = raw.split('#').next().unwrap_or("").trim();
            if l.is_empty() {
                continue;
            }
            let (key, value) = l.split_once('=').ok_or_else(|| {
                NodeError::Config(format!("exit config line {}: expected `key = value`", n + 1))
            })?;
            match key.trim() {
                "seed" => seed = Some(parse_seed_hex(value.trim())?),
                "ports" => {
                    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                        allowed_ports.push(part.parse().map_err(|_| {
                            NodeError::Config(format!("bad exit port '{part}'"))
                        })?);
                    }
                }
                other => {
                    return Err(NodeError::Config(format!("unknown exit config key '{other}'")));
                }
            }
        }
        let seed = seed.ok_or_else(|| NodeError::Config("exit config missing `seed`".to_owned()))?;
        Ok(Self {
            seed,
            allowed_ports,
        })
    }
}

impl ServiceParams {
    /// Parse service parameters from a `key = value` text file — the out-of-band provisioning a service
    /// operator hands each line member. Recognised keys: `seed` (64 hex chars: the 32-byte member-key
    /// seed), `line` (comma-separated `x:y:z` member coordinates, in the client's seal order), and
    /// `threshold` (the reconstruction `t`). All three are required; an unrecognised key is an error.
    ///
    /// # Errors
    /// [`NodeError::Config`] on a malformed line, an unknown key, a bad value, or a missing key.
    pub fn from_config_str(text: &str) -> Result<Self, NodeError> {
        let mut seed: Option<[u8; 32]> = None;
        let mut line: Vec<Triple> = Vec::new();
        let mut threshold: Option<usize> = None;
        for (n, raw) in text.lines().enumerate() {
            let l = raw.split('#').next().unwrap_or("").trim();
            if l.is_empty() {
                continue;
            }
            let (key, value) = l.split_once('=').ok_or_else(|| {
                NodeError::Config(format!("service config line {}: expected `key = value`", n + 1))
            })?;
            match key.trim() {
                "seed" => seed = Some(parse_seed_hex(value.trim())?),
                "line" => {
                    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                        line.push(parse_coord(part)?);
                    }
                }
                "threshold" => {
                    threshold = Some(value.trim().parse().map_err(|_| {
                        NodeError::Config(format!("bad service threshold '{}'", value.trim()))
                    })?);
                }
                other => {
                    return Err(NodeError::Config(format!(
                        "unknown service config key '{other}'"
                    )));
                }
            }
        }
        let seed = seed.ok_or_else(|| NodeError::Config("service config missing `seed`".to_owned()))?;
        let threshold =
            threshold.ok_or_else(|| NodeError::Config("service config missing `threshold`".to_owned()))?;
        if line.is_empty() {
            return Err(NodeError::Config(
                "service config `line` must list at least one member coordinate".to_owned(),
            ));
        }
        Ok(Self {
            seed,
            line,
            threshold,
        })
    }
}

/// Parse a `x:y:z` projective coordinate into a [`Triple`].
fn parse_coord(s: &str) -> Result<Triple, NodeError> {
    let mut it = s.split(':');
    let mut next = || {
        it.next()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .ok_or_else(|| NodeError::Config(format!("bad coordinate '{s}' (expected x:y:z)")))
    };
    let coord = [next()?, next()?, next()?];
    if it.next().is_some() {
        return Err(NodeError::Config(format!(
            "coordinate '{s}' must be exactly x:y:z"
        )));
    }
    Ok(coord)
}

/// Decode exactly 64 hex characters into a 32-byte seed.
fn parse_seed_hex(s: &str) -> Result<[u8; 32], NodeError> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(NodeError::Config(format!(
            "service seed must be 64 hex characters (got {})",
            bytes.len()
        )));
    }
    let nibble = |c: u8| -> Result<u8, NodeError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(NodeError::Config(
                "service seed contains a non-hex character".to_owned(),
            )),
        }
    };
    let mut seed = [0u8; 32];
    // 64 even bytes → exactly 32 two-byte chunks, zipped 1:1 with the 32 seed slots. The slice pattern
    // binds each pair without indexing; the `_` arm is unreachable given the length check.
    for (slot, pair) in seed.iter_mut().zip(bytes.chunks(2)) {
        match pair {
            [hi, lo] => *slot = (nibble(*hi)? << 4) | nibble(*lo)?,
            _ => return Err(NodeError::Config("service seed has an odd length".to_owned())),
        }
    }
    Ok(seed)
}

/// A bootstrap peer: a known overlay coordinate bound to a network address. The overlay routes on
/// coordinates; a fresh node seeds its address book with these so it can dial into the network
/// (`docs/design.md` §9 — derivation/seed, not a central directory).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Peer {
    /// The peer's overlay coordinate.
    pub coord: Triple,
    /// The peer's network address.
    pub addr: SocketAddr,
}

impl Peer {
    /// Parse a `x:y:z@host:port` seed string.
    ///
    /// # Errors
    /// [`NodeError::Config`] if the coordinate or address is malformed.
    pub fn parse(s: &str) -> Result<Self, NodeError> {
        let (coord_str, addr_str) = s
            .split_once('@')
            .ok_or_else(|| NodeError::Config(format!("peer '{s}' must be 'x:y:z@host:port'")))?;
        let mut it = coord_str.split(':');
        let mut next = || {
            it.next()
                .and_then(|v| v.parse::<u32>().ok())
                .ok_or_else(|| NodeError::Config(format!("bad coordinate in peer '{s}'")))
        };
        let coord = [next()?, next()?, next()?];
        if it.next().is_some() {
            return Err(NodeError::Config(format!(
                "coordinate in peer '{s}' must be x:y:z"
            )));
        }
        let addr = addr_str
            .parse::<SocketAddr>()
            .map_err(|_| NodeError::Config(format!("bad address in peer '{s}'")))?;
        Ok(Self { coord, addr })
    }
}

/// The roles a node advertises (a capability set; spec §7.4 / `docs/design.md` §12). In Phase 1 all
/// roles are served by the overlay engine; the set is advertised via JOIN so the cell learns it.
// Four independent role flags are the natural shape of a capability set (they map 1:1 to the JOIN
// bitfield); a struct here reads better than an opaque bitmask at the call sites.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct RoleSet {
    /// Relays application traffic for others.
    pub relay: bool,
    /// Stores DHT (L4) shards for the cell.
    pub storage: bool,
    /// Hosts hidden services (CALYPSO).
    pub service: bool,
    /// Bridges to the clear net (an exit).
    pub exit: bool,
}

impl RoleSet {
    /// Whether any role is advertised.
    #[must_use]
    pub fn any(self) -> bool {
        self.relay || self.storage || self.service || self.exit
    }

    /// A compact one-byte encoding for the JOIN announcement.
    #[must_use]
    pub fn encode(self) -> u8 {
        u8::from(self.relay)
            | (u8::from(self.storage) << 1)
            | (u8::from(self.service) << 2)
            | (u8::from(self.exit) << 3)
    }

    /// Parse a comma-separated role list (`relay,storage,service,exit`).
    ///
    /// # Errors
    /// [`NodeError::Config`] on an unknown role name.
    pub fn parse(s: &str) -> Result<Self, NodeError> {
        let mut roles = Self::default();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part {
                "relay" => roles.relay = true,
                "storage" => roles.storage = true,
                "service" => roles.service = true,
                "exit" => roles.exit = true,
                other => return Err(NodeError::Config(format!("unknown role '{other}'"))),
            }
        }
        Ok(roles)
    }
}

/// A node's runtime configuration.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// The address to bind the QUIC endpoint to (e.g. `0.0.0.0:9000`).
    pub listen: SocketAddr,
    /// Where to persist the self-certifying identity; `None` = ephemeral (new identity each run).
    pub identity_path: Option<PathBuf>,
    /// Bootstrap peers seeded into the address book.
    pub bootstrap: Vec<Peer>,
    /// The advertised role set.
    pub roles: RoleSet,
    /// Whether to begin liveness heartbeats on start.
    pub start_heartbeat: bool,
    /// The distributed-beacon parameters. `Some(..)` runs the live epoch clock (§7.6); `None` (the
    /// default) runs a bare overlay pinned at genesis — see [`BeaconParams`].
    pub beacon: Option<BeaconParams>,
    /// How often the node issues the root `AdvanceEpoch` tick that drives the live epoch clock: each
    /// period the beacon advances a round, rotating the VRF coordinate, the PROTEUS wire shape, and the
    /// forward-secure onion keys (the moving-target defence, §L3/§7.6). Only used when `beacon` is
    /// `Some` (a bare overlay has no clock to drive). Network-wide — all nodes should share it so their
    /// epochs stay aligned. Default: [`DEFAULT_EPOCH_PERIOD`].
    pub epoch_period: Duration,
    /// The threshold-hosting parameters. Required by (and only used with) the `service` role: `Some(..)`
    /// composes a [`ServiceNode`](crate::ServiceNode) hosting one member of a service line — see
    /// [`ServiceParams`]. `None` (the default) hosts no service.
    pub service: Option<ServiceParams>,
    /// The clearnet-exit parameters. Required by (and only used with) the `exit` role: `Some(..)` runs a
    /// [`serve_exit`](crate::serve_exit) relay under a stable service identity — see [`ExitParams`]. `None`
    /// (the default) runs no exit.
    pub exit: Option<ExitParams>,
    /// PROTEUS censorship-resistance (§13.4). `Some(secret)` shapes every wire frame with the shared
    /// community secret so the transport carries no static FANOS signature, and the shape **rotates each
    /// epoch** (the moving-target defence); `None` (the default) is plaintext QUIC. All peers that must
    /// interoperate share the same secret — it is a bridge/community password, not a per-node key.
    pub proteus_secret: Option<Vec<u8>>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 0)),
            identity_path: None,
            bootstrap: Vec::new(),
            roles: RoleSet::default(),
            start_heartbeat: true,
            beacon: None,
            epoch_period: DEFAULT_EPOCH_PERIOD,
            service: None,
            exit: None,
            proteus_secret: None,
        }
    }
}

impl NodeConfig {
    /// Parse a node config from a simple `key = value` text file — one setting per line, `#` starts a
    /// comment — the operator-facing alternative to a long CLI-flag line (§11). Recognised keys:
    /// `listen`, `identity`, `bootstrap` (comma-separated `coord@addr` peers), `role` (comma-separated
    /// roles), `heartbeat` (`true`/`false`). An unrecognised key is an ERROR, not silently ignored — a
    /// typo on a production node must fail loudly rather than leave a setting unexpectedly at its
    /// default. Beacon parameters (the DVRF group commitment) are genesis material provisioned
    /// out-of-band, not from this file, so `beacon` stays `None` here.
    ///
    /// # Errors
    /// [`NodeError::Config`] on a line without `=`, an unrecognised key, or an unparseable value.
    pub fn from_config_str(text: &str) -> Result<Self, NodeError> {
        let mut config = Self::default();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                NodeError::Config(format!("config line {}: expected `key = value`", n + 1))
            })?;
            let (key, value) = (key.trim(), value.trim());
            match key {
                "listen" => {
                    config.listen = value
                        .parse()
                        .map_err(|_| NodeError::Config(format!("bad listen '{value}'")))?;
                }
                "identity" => config.identity_path = Some(PathBuf::from(value)),
                "bootstrap" => {
                    for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                        config.bootstrap.push(Peer::parse(part)?);
                    }
                }
                "role" => config.roles = RoleSet::parse(value)?,
                "heartbeat" => {
                    config.start_heartbeat = value.parse().map_err(|_| {
                        NodeError::Config(format!("bad heartbeat '{value}' (expected true/false)"))
                    })?;
                }
                "proteus_secret" => {
                    if value.is_empty() {
                        return Err(NodeError::Config(
                            "proteus_secret must be non-empty (a shared community secret)".to_owned(),
                        ));
                    }
                    config.proteus_secret = Some(value.as_bytes().to_vec());
                }
                other => {
                    return Err(NodeError::Config(format!(
                        "config line {}: unknown key '{other}'",
                        n + 1
                    )));
                }
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_peer_seed() {
        let p = Peer::parse("1:2:3@127.0.0.1:9000").unwrap();
        assert_eq!(p.coord, [1, 2, 3]);
        assert_eq!(p.addr, "127.0.0.1:9000".parse().unwrap());
    }

    #[test]
    fn rejects_malformed_peers() {
        assert!(Peer::parse("1:2:3").is_err()); // no '@addr'
        assert!(Peer::parse("1:2@127.0.0.1:9000").is_err()); // 2-coord
        assert!(Peer::parse("a:b:c@127.0.0.1:9000").is_err()); // non-numeric
        assert!(Peer::parse("1:2:3@not-an-addr").is_err());
    }

    #[test]
    fn parses_and_encodes_roles() {
        let r = RoleSet::parse("relay,exit").unwrap();
        assert!(r.relay && r.exit && !r.storage && !r.service);
        assert_eq!(r.encode(), 0b1001);
        assert!(r.any());
        assert!(RoleSet::parse("bogus").is_err());
        assert!(!RoleSet::default().any());
    }

    #[test]
    fn parses_service_params_from_a_config() {
        let p = ServiceParams::from_config_str(
            "# a 3-of-3 service line\n\
             seed = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
             line = 1:0:0, 0:1:0, 0:0:1\n\
             threshold = 2\n",
        )
        .unwrap();
        assert_eq!(p.seed[0], 0x00);
        assert_eq!(p.seed[1], 0x11);
        assert_eq!(p.seed[31], 0xff);
        assert_eq!(p.line, vec![[1, 0, 0], [0, 1, 0], [0, 0, 1]]);
        assert_eq!(p.threshold, 2);
        // The seed is redacted from Debug (it regenerates the member secret).
        assert!(format!("{p:?}").contains("<redacted>"));
        assert!(!format!("{p:?}").contains("0011"));
    }

    #[test]
    fn parses_exit_params_from_a_config() {
        let p = ExitParams::from_config_str(&format!(
            "# a web-only exit\nseed = {}\nports = 80, 443\n",
            "cd".repeat(32)
        ))
        .unwrap();
        assert_eq!(p.seed[0], 0xcd);
        assert_eq!(p.allowed_ports, vec![80, 443]);
        assert!(format!("{p:?}").contains("<redacted>"));
        // `ports` omitted = any port (empty list).
        let open = ExitParams::from_config_str(&format!("seed = {}", "ab".repeat(32))).unwrap();
        assert!(open.allowed_ports.is_empty());
        // Missing seed / bad port / unknown key rejected.
        assert!(ExitParams::from_config_str("ports = 80").is_err());
        assert!(
            ExitParams::from_config_str(&format!("seed = {}\nports = notaport", "ab".repeat(32)))
                .is_err()
        );
        assert!(
            ExitParams::from_config_str(&format!("seed = {}\nbogus = 1", "ab".repeat(32))).is_err()
        );
    }

    #[test]
    fn rejects_malformed_service_params() {
        // Missing keys.
        assert!(ServiceParams::from_config_str("line = 1:0:0\nthreshold = 1").is_err()); // no seed
        assert!(
            ServiceParams::from_config_str(&format!("seed = {}\nthreshold = 1", "ab".repeat(32)))
                .is_err(),
            "empty line rejected"
        );
        // Bad seed length / hex.
        assert!(ServiceParams::from_config_str("seed = abcd\nline = 1:0:0\nthreshold = 1").is_err());
        assert!(
            ServiceParams::from_config_str(&format!(
                "seed = {}\nline = 1:0:0\nthreshold = 1",
                "zz".repeat(32)
            ))
            .is_err(),
            "non-hex seed rejected"
        );
        // Unknown key and bad coordinate.
        assert!(
            ServiceParams::from_config_str(&format!(
                "seed = {}\nline = 1:0:0\nthreshold = 1\nbogus = 1",
                "ab".repeat(32)
            ))
            .is_err()
        );
        assert!(
            ServiceParams::from_config_str(&format!(
                "seed = {}\nline = 1:0\nthreshold = 1",
                "ab".repeat(32)
            ))
            .is_err(),
            "two-component coordinate rejected"
        );
    }

    #[test]
    fn parses_a_config_file() {
        let cfg = NodeConfig::from_config_str(
            "# a relay node\nlisten = 127.0.0.1:9000\nrole = relay,storage\nbootstrap = 1:2:3@10.0.0.1:9000, 4:5:6@10.0.0.2:9000\nheartbeat = false\n",
        )
        .unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:9000".parse().unwrap());
        assert!(cfg.roles.relay && cfg.roles.storage && !cfg.roles.exit);
        assert_eq!(cfg.bootstrap.len(), 2);
        assert!(!cfg.start_heartbeat);
        assert!(cfg.beacon.is_none());
    }

    #[test]
    fn config_file_rejects_unknown_keys_and_malformed_values() {
        assert!(NodeConfig::from_config_str("bogus = 1").is_err()); // unknown key fails loudly
        assert!(NodeConfig::from_config_str("listen 127.0.0.1:9000").is_err()); // no '='
        assert!(NodeConfig::from_config_str("listen = not-an-addr").is_err());
        assert!(NodeConfig::from_config_str("heartbeat = maybe").is_err());
    }

    #[test]
    fn config_file_comments_and_blanks_keep_defaults() {
        let cfg = NodeConfig::from_config_str("\n  # only a comment\n\n").unwrap();
        assert!(cfg.start_heartbeat); // the default is preserved
        assert!(cfg.bootstrap.is_empty());
        assert!(cfg.identity_path.is_none());
    }

    #[test]
    fn proteus_secret_enables_shaping_and_is_off_by_default() {
        // PROTEUS (§13.4) is opt-in: default off (plaintext QUIC), enabled by a non-empty shared secret.
        assert!(NodeConfig::default().proteus_secret.is_none(), "off by default");
        let cfg = NodeConfig::from_config_str("proteus_secret = a-shared-bridge-secret").unwrap();
        assert_eq!(cfg.proteus_secret.as_deref(), Some(&b"a-shared-bridge-secret"[..]));
        // An empty secret is a configuration error, not a silent no-op.
        assert!(NodeConfig::from_config_str("proteus_secret =").is_err());
    }
}
