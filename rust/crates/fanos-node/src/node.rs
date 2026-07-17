//! The running node: composes the sans-I/O engine behind the QUIC driver.
//!
//! Phase 1 runs the [`OverlayNode`] engine (membership, liveness, L4 storage, DIAKRISIS healing)
//! behind the production QUIC transport. Relay / service / exit engines compose in later phases; the
//! node advertises its role set via JOIN so the cell learns what it offers. The heavy lifting —
//! endpoint, connection pool, event loop — lives in the driver; this type is the supervisor that
//! wires identity, bootstrap, and the engine together and exposes control.

use std::net::SocketAddr;

use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_quic::{Directory, NodeHandle, spawn_self_certifying_persistent_on};
use fanos_runtime::{Command, Config as OverlayConfig, Notification, OverlayNode};

use crate::config::{NodeConfig, RoleSet};
use crate::error::NodeError;
use crate::identity;

/// A running FANOS node.
pub struct Node {
    handle: NodeHandle,
    directory: Directory,
    address: Triple,
    local_addr: SocketAddr,
    roles: RoleSet,
}

/// A point-in-time health snapshot of a node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Health {
    /// The node's overlay coordinate.
    pub address: Triple,
    /// The bound network address.
    pub local_addr: SocketAddr,
    /// The number of peers currently in the address book.
    pub known_peers: usize,
    /// The advertised roles.
    pub roles: RoleSet,
}

impl Node {
    /// Start a node over the deployment field `F`, using `config` (identity, bootstrap, roles).
    ///
    /// # Errors
    /// [`NodeError`] if the identity cannot be loaded or the QUIC endpoint cannot be bound.
    pub async fn start<F: Field + 'static>(config: NodeConfig) -> Result<Self, NodeError> {
        let credentials = identity::load_or_generate(config.identity_path.as_deref())?;

        // Seed the address book so a fresh node can dial into the network (design.md §9).
        let directory = Directory::new();
        for peer in &config.bootstrap {
            directory.insert(peer.coord, peer.addr);
        }

        let handle = spawn_self_certifying_persistent_on::<F>(
            config.listen,
            &credentials,
            move |coord| Box::new(OverlayNode::<F>::new(coord, OverlayConfig::default())),
            directory.clone(),
        )
        .await?;

        let address = handle.address();
        let local_addr = handle.local_addr();

        if config.start_heartbeat {
            handle.command(Command::StartHeartbeat);
        }
        if config.roles.any() {
            // Announce the role set so the cell learns what this node offers (spec §7.8 JOIN).
            handle.command(Command::Join {
                info: vec![config.roles.encode()],
            });
        }

        Ok(Self {
            handle,
            directory,
            address,
            local_addr,
            roles: config.roles,
        })
    }

    /// The node's overlay coordinate.
    #[must_use]
    pub fn address(&self) -> Triple {
        self.address
    }

    /// The bound network address (useful when the config requested an ephemeral port).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The shared address book (the discovery seam).
    #[must_use]
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// A current health snapshot.
    #[must_use]
    pub fn health(&self) -> Health {
        Health {
            address: self.address,
            local_addr: self.local_addr,
            known_peers: self.directory.len(),
            roles: self.roles,
        }
    }

    /// Submit a command to the engine. Returns `false` if the node has shut down.
    pub fn command(&self, cmd: Command) -> bool {
        self.handle.command(cmd)
    }

    /// Await the next engine notification (`None` once the node has shut down).
    pub async fn next_notification(&mut self) -> Option<Notification> {
        self.handle.next_notification().await
    }

    /// Shut the node down (closes the endpoint; the notification stream then ends).
    pub fn shutdown(&self) {
        self.handle.shutdown();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use fanos_field::F2;

    #[tokio::test]
    async fn a_node_starts_and_reports_health() {
        let node = Node::start::<F2>(NodeConfig::default()).await.unwrap();
        let health = node.health();
        assert_eq!(health.address, node.address());
        assert!(
            health.local_addr.port() > 0,
            "endpoint bound to a real port"
        );
        node.shutdown();
    }

    #[tokio::test]
    async fn two_nodes_bootstrap_and_exchange_a_payload() {
        // Loopback so the bound address is directly dialable in-test (a public node would bind
        // 0.0.0.0 and advertise its reachable address — a Phase-2 concern).
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));

        // Bring up a first node; a second seeds its address book with the first and sends to it.
        let a = Node::start::<F2>(NodeConfig {
            listen: loopback,
            ..NodeConfig::default()
        })
        .await
        .unwrap();
        let a_addr = a.address();
        let a_net = a.local_addr();

        let b = Node::start::<F2>(NodeConfig {
            listen: loopback,
            bootstrap: vec![crate::config::Peer {
                coord: a_addr,
                addr: a_net,
            }],
            ..NodeConfig::default()
        })
        .await
        .unwrap();
        // b learned a via bootstrap; a learns b's address when b dials (the driver registers it).
        a.directory().insert(b.address(), b.local_addr());

        b.command(Command::Send {
            to: a_addr,
            payload: b"hello over quic".to_vec(),
        });

        // a should observe the delivery.
        let mut a = a;
        let delivered = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match a.next_notification().await {
                    Some(Notification::Delivered { payload, .. }) => break Some(payload),
                    Some(_) => {}
                    None => break None,
                }
            }
        })
        .await
        .expect("timed out waiting for delivery");
        assert_eq!(delivered.as_deref(), Some(b"hello over quic".as_slice()));

        a.shutdown();
        b.shutdown();
    }
}
