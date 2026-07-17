//! Node configuration: listen address, persistent identity, bootstrap peers, and roles.

use std::net::SocketAddr;
use std::path::PathBuf;

use fanos_geometry::Triple;

use crate::error::NodeError;

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
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 0)),
            identity_path: None,
            bootstrap: Vec::new(),
            roles: RoleSet::default(),
            start_heartbeat: true,
        }
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
}
