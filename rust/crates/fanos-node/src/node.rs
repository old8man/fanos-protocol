//! The running node: composes the sans-I/O engine behind the QUIC driver.
//!
//! Phase 1 runs the [`OverlayNode`] engine (membership, liveness, L4 storage, DIAKRISIS healing)
//! behind the production QUIC transport. Relay / service / exit engines compose in later phases; the
//! node advertises its role set via JOIN so the cell learns what it offers. The heavy lifting —
//! endpoint, connection pool, event loop — lives in the driver; this type is the supervisor that
//! wires identity, bootstrap, and the engine together and exposes control.

use std::net::SocketAddr;

use fanos_aphantos::ThresholdRouter;
use fanos_field::Field;
use fanos_geometry::Triple;
use fanos_onoma::{Address, Epoch, lookup_key};
use fanos_pqcrypto::{HybridKemSecret, SeedRng};
use fanos_quic::{Client, Directory, NodeHandle, spawn_self_certifying_persistent_on};
use fanos_keygen::BeaconNode;
use fanos_runtime::{Command, Config as OverlayConfig, Engine, Notification, OverlayNode};
use tokio::task::JoinHandle;

use crate::{CellNode, OverlayBeaconNode, ServiceNode, ThresholdService, spawn_mix_publisher};

use crate::config::{NodeConfig, RoleSet};
use crate::error::NodeError;
use crate::identity;
use crate::resolve::{ResolvedService, verify_descriptor};

/// The mixnet's per-hop cooperation threshold — how many of a Fano line's three members must combine to
/// peel one onion layer (2-of-3). A relay's [`ThresholdRouter`] gathers this many partials; an anonymous
/// client's `--threshold` MUST match, since it seals each layer for exactly this many members.
const MIX_THRESHOLD: usize = 2;

/// 32 fresh bytes of OS entropy — the mix router's per-run key seeds (a relay node only).
fn os_entropy_32() -> Result<[u8; 32], NodeError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| NodeError::Config(format!("OS entropy failed: {e}")))?;
    Ok(bytes)
}

/// Validate the `service` role's parameters, returning the member-key seed, line roster, and threshold to
/// compose into a [`ServiceNode`] — or `None` when the role is off. The role requires its parameters (there
/// is no line to serve without them) and a threshold in `1..=line.len()` (zero would serve every intro from
/// a single host; above the line size can never be met). Validated here so bad provisioning fails
/// [`Node::start`] rather than the infallible engine builder.
#[allow(clippy::type_complexity)]
fn service_params(config: &NodeConfig) -> Result<Option<([u8; 32], Vec<Triple>, usize)>, NodeError> {
    if !config.roles.service {
        return Ok(None);
    }
    let params = config.service.as_ref().ok_or_else(|| {
        NodeError::Config(
            "the service role hosts a threshold CALYPSO line and needs service parameters (the line \
             roster, threshold, and this node's member key seed)"
                .to_owned(),
        )
    })?;
    if params.threshold == 0 || params.threshold > params.line.len() {
        return Err(NodeError::Config(format!(
            "the service threshold {} must be in 1..={} (the line has {} members)",
            params.threshold,
            params.line.len(),
            params.line.len(),
        )));
    }
    Ok(Some((params.seed, params.line.clone(), params.threshold)))
}

/// A running FANOS node.
pub struct Node {
    handle: NodeHandle,
    directory: Directory,
    address: Triple,
    local_addr: SocketAddr,
    roles: RoleSet,
    /// The background task republishing this node's mix onion key each epoch — present only for a relay
    /// node (which runs the mixnet role). Held so it lives as long as the node; it ends when the node's
    /// notification stream closes on shutdown.
    _mix_publisher: Option<JoinHandle<()>>,
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

        // Compose the engine per coordinate: a bare overlay by default, or — when beacon params are
        // configured — an `OverlayBeaconNode` that runs the live threshold-DVRF epoch clock (§7.6). A
        // pure consumer (`share = None`) only needs the group commitment + threshold to verify and adopt
        // the rounds anchors flood; an anchor also contributes partials.
        let beacon = config.beacon.clone();
        // A relay node also runs the anonymity mixnet: its engine is a [`CellNode`] (overlay + beacon +
        // threshold-onion router), and it republishes its onion key each epoch so anonymous clients can
        // seal to it. The router's key material is fresh OS entropy per run — forward-secure, since a
        // restart cannot peel onions sealed to the old key. A relay needs the beacon to lock its onion-key
        // rotation to the cell epoch (E4∩E5), so require beacon parameters for the role.
        let relay = config.roles.relay;
        if relay && beacon.is_none() {
            return Err(NodeError::Config(
                "the relay role runs the anonymity mixnet and needs beacon parameters (configure the \
                 beacon commitment and threshold)"
                    .to_owned(),
            ));
        }
        let (onion_seed, kem_seed) = if relay {
            (os_entropy_32()?, os_entropy_32()?)
        } else {
            ([0u8; 32], [0u8; 32])
        };
        // The service role hosts one member of a threshold CALYPSO line. Validate its parameters up front so
        // bad provisioning fails `start` here rather than inside the infallible engine builder; the member
        // key seed is then carried into the builder (the secret is regenerated there, in memory).
        let service = service_params(&config)?;
        let handle = spawn_self_certifying_persistent_on::<F>(
            config.listen,
            &credentials,
            move |coord| -> Box<dyn Engine + Send> {
                // A deployed node is seated by its VRF beacon coordinate (`spawn_self_certifying…` →
                // `verifiable_coordinate`), so its level-0 point is NOT the hash `address_point(id, 0)`.
                // Tell the overlay, so if a deployment turns on self-certified membership the check verifies
                // level 0 by the proof-of-coordinate HELLO + descriptor signature rather than the hash chain
                // (which would reject every legitimate VRF announcement, audit C3).
                let overlay_config = OverlayConfig { vrf_coordinates: true, ..OverlayConfig::default() };
                let overlay = OverlayNode::<F>::new(coord, overlay_config);
                let base: Box<dyn Engine + Send> = match beacon {
                    Some(bp) => {
                        let obn = OverlayBeaconNode::new(
                            overlay,
                            BeaconNode::<F>::new(coord, bp.share, bp.commitment, bp.threshold),
                        );
                        if relay {
                            // Compose the mixnet router at the same coordinate → a full cell participant.
                            let (router_secret, _identity) =
                                HybridKemSecret::generate(&mut SeedRng::from_seed(&kem_seed));
                            let router = ThresholdRouter::<F>::new(
                                coord,
                                &router_secret,
                                MIX_THRESHOLD,
                                onion_seed,
                            );
                            Box::new(CellNode::new(obn, router))
                        } else {
                            Box::new(obn)
                        }
                    }
                    None => Box::new(overlay),
                };
                // The service role composes a threshold-hosting engine OVER whatever cell engine the other
                // roles produced (overlay, beacon, and/or the mixnet relay), so the one coordinate also
                // serves its CALYPSO line — an intro reaching it is dispatched to the service, everything
                // else to the cell engine (see [`ServiceNode`]).
                match service {
                    Some((seed, line, threshold)) => {
                        // Regenerate the member secret in memory from its seed (never serialized, audit
                        // #124); its public is the one the operator collected into the published line.
                        let (secret, _public) =
                            HybridKemSecret::generate(&mut SeedRng::from_seed(&seed));
                        Box::new(ServiceNode::new(
                            base,
                            ThresholdService::new(coord.coords(), secret, line, threshold),
                        ))
                    }
                    None => base,
                }
            },
            directory.clone(),
            // PROTEUS (§13.4): when a community secret is configured, every frame is polymorph-shaped and the
            // shape rotates each epoch (driven by the same beacon that reshuffles the coordinate).
            config.proteus_secret.clone(),
        )
        .await?;

        let address = handle.address();
        let local_addr = handle.local_addr();
        // Keep the relay's onion key live in the mix directory for as long as it runs: publish the genesis
        // key at once, then republish each epoch the beacon advances to (audit #54; E4∩E5).
        let mix_publisher = relay.then(|| spawn_mix_publisher(handle.client(), address, onion_seed));

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
            _mix_publisher: mix_publisher,
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

    /// A cloneable, concurrency-safe [`Client`] for this node — issue `get`/`put`/commands and await
    /// correlated replies from many tasks at once (the surface a proxy or resolver builds on).
    #[must_use]
    pub fn client(&self) -> Client {
        self.handle.client()
    }

    /// Resolve a `.fanos` `name` to its authenticated service descriptor at `epoch`, requiring at
    /// least `min_pow` proof-of-work on the published descriptor.
    ///
    /// Fetches the descriptor from the rotating epoch slot via a **correlated** `get` (so many
    /// resolves run concurrently without stealing each other's replies) and verifies it
    /// **client-side** (`H(bundle) == addr`), so a malicious store can never induce impersonation.
    ///
    /// # Errors
    /// [`NodeError::Resolve`] if the name is malformed, no descriptor is published, or the fetched
    /// descriptor fails verification.
    pub async fn resolve(
        &self,
        name: &str,
        epoch: Epoch,
        min_pow: u32,
    ) -> Result<ResolvedService, NodeError> {
        let address = Address::parse(name)
            .map_err(|e| NodeError::Resolve(format!("invalid .fanos name '{name}': {e}")))?;
        let slot = lookup_key(&address, epoch).to_vec();
        let value = self.client().get(slot).await.ok_or_else(|| {
            NodeError::Resolve(format!(
                "no descriptor published for '{name}' at epoch {epoch}"
            ))
        })?;
        verify_descriptor(&address, epoch, &value, min_pow)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::{BeaconParams, NodeConfig, ServiceParams};
    use fanos_field::F2;

    #[tokio::test]
    async fn resolve_rejects_a_malformed_name_without_touching_the_network() {
        // A name that is not a valid `.fanos` address fails at parse time, before any Get — so the
        // happy path (which needs a full cell) is covered by the resolve unit tests and the sim
        // `onoma_resolve` scenario, while this stays fast and deterministic.
        let node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..NodeConfig::default()
        })
        .await
        .unwrap();
        // Concurrency-safe: two resolves run at once without stealing each other's replies (both
        // fail at parse here, before any network I/O — deterministic).
        let (a, b) = tokio::join!(
            node.resolve("definitely not a .fanos name", Epoch::new(0), 0),
            node.resolve("also-not-valid", Epoch::new(7), 0),
        );
        assert!(matches!(a, Err(NodeError::Resolve(_))));
        assert!(matches!(b, Err(NodeError::Resolve(_))));
        node.shutdown();
    }

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
    async fn a_node_starts_with_a_beacon_consumer_and_self_certifies_a_coordinate() {
        // A consumer-mode beacon (share = None) needs only the group commitment + threshold; the node
        // composes an OverlayBeaconNode, binds real QUIC, and self-certifies a coordinate. With no
        // anchors flooding rounds it simply sits at genesis — the epoch-advance behaviour is unit-tested
        // in overlay_beacon. This proves the Node::start wiring spawns the composite end-to-end (§7.6).
        use fanos_vrf::vss::{DeterministicRng, deal};
        let (_shares, commitment) =
            deal(&[0xB5; 32], 2, 3, &mut DeterministicRng::new(b"node-beacon")).unwrap();
        let node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            beacon: Some(BeaconParams {
                commitment,
                threshold: 2,
                share: None,
            }),
            ..NodeConfig::default()
        })
        .await
        .unwrap();
        let health = node.health();
        assert_eq!(health.address, node.address());
        assert!(health.local_addr.port() > 0, "endpoint bound");
        node.shutdown();
    }

    #[tokio::test]
    async fn a_relay_role_requires_beacon_parameters() {
        // A relay runs the anonymity mixnet, whose onion-key rotation locks to the beacon epoch — so the
        // role is refused without beacon parameters rather than silently running an un-rotating mixnet.
        let started = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            roles: RoleSet {
                relay: true,
                ..RoleSet::default()
            },
            ..NodeConfig::default()
        })
        .await;
        assert!(
            matches!(started, Err(NodeError::Config(_))),
            "the relay role without beacon parameters is refused"
        );
    }

    #[tokio::test]
    async fn a_service_role_requires_service_parameters() {
        // The service role hosts a threshold CALYPSO line; without the line roster + member key there is
        // nothing to serve, so the role is refused rather than silently running as a bare overlay.
        let started = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            roles: RoleSet {
                service: true,
                ..RoleSet::default()
            },
            ..NodeConfig::default()
        })
        .await;
        assert!(
            matches!(started, Err(NodeError::Config(_))),
            "the service role without service parameters is refused"
        );
    }

    #[tokio::test]
    async fn a_service_role_rejects_an_out_of_range_threshold() {
        // A threshold above the line size can never be met, and zero would serve every intro from a single
        // host — both defeat the hosting guarantee, so provisioning is rejected at start.
        for threshold in [0usize, 3] {
            let started = Node::start::<F2>(NodeConfig {
                listen: SocketAddr::from(([127, 0, 0, 1], 0)),
                roles: RoleSet {
                    service: true,
                    ..RoleSet::default()
                },
                service: Some(ServiceParams {
                    seed: [0x5e; 32],
                    line: vec![[1, 0, 0], [0, 1, 0]],
                    threshold,
                }),
                ..NodeConfig::default()
            })
            .await;
            assert!(
                matches!(started, Err(NodeError::Config(_))),
                "threshold {threshold} (line size 2) is refused"
            );
        }
    }

    #[tokio::test]
    async fn a_service_node_starts_and_composes_the_hosting_engine() {
        // Valid service parameters compose a ServiceNode over the overlay and bind real QUIC — the wiring
        // path the intro-serving behaviour (unit-tested in `service_node`, sim-tested in
        // `threshold_service_live`) then runs on.
        let node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            roles: RoleSet {
                service: true,
                ..RoleSet::default()
            },
            service: Some(ServiceParams {
                seed: [0x5e; 32],
                line: vec![[1, 0, 0], [0, 1, 0], [0, 0, 1]],
                threshold: 2,
            }),
            ..NodeConfig::default()
        })
        .await
        .expect("a service node with valid parameters starts");
        assert!(node.health().local_addr.port() > 0, "endpoint bound");
        node.shutdown();
    }

    #[tokio::test]
    async fn a_relay_node_publishes_its_mix_key_to_the_directory() {
        // The Node::start relay wiring end-to-end: a relay composes a CellNode (overlay + beacon + mix
        // router) AND spawns the publisher that keeps its onion key live in the cell directory — so a
        // client's `build_cell_mix_directory` surfaces it, i.e. the anonymity mixnet is actually reachable.
        use std::time::Duration;

        use fanos_vrf::vss::{DeterministicRng, deal};

        use crate::build_cell_mix_directory;

        let (_shares, commitment) =
            deal(&[0xB6; 32], 2, 3, &mut DeterministicRng::new(b"relay-mix")).unwrap();
        let mut node = Node::start::<F2>(NodeConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            beacon: Some(BeaconParams {
                commitment,
                threshold: 2,
                share: None,
            }),
            roles: RoleSet {
                relay: true,
                ..RoleSet::default()
            },
            start_heartbeat: true,
            ..NodeConfig::default()
        })
        .await
        .unwrap();

        // The publisher republishes asynchronously; poll the directory (draining notifications so the
        // engine makes progress) until the relay's own onion key appears.
        let client = node.client();
        let mut dir = build_cell_mix_directory::<F2>(&client, Epoch::ZERO).await;
        for _ in 0..30 {
            if !dir.is_empty() {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(100), node.next_notification()).await;
            dir = build_cell_mix_directory::<F2>(&client, Epoch::ZERO).await;
        }
        assert!(
            !dir.is_empty(),
            "the relay published its mix onion key to the cell directory"
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

        // A node's coordinate is derived from its (fresh, random) identity, so two nodes collide on
        // the same Fano point 1/7 of the time — which would make the coordinate→node mapping
        // ambiguous and break routing. Start B until it lands on a point distinct from A (the cell
        // invariant that members occupy distinct points).
        let make_b = || {
            Node::start::<F2>(NodeConfig {
                listen: loopback,
                bootstrap: vec![crate::config::Peer {
                    coord: a_addr,
                    addr: a_net,
                }],
                ..NodeConfig::default()
            })
        };
        let mut b = make_b().await.unwrap();
        while b.address() == a_addr {
            b.shutdown();
            b = make_b().await.unwrap();
        }

        b.command(Command::Send {
            to: a_addr,
            payload: b"hello over quic".to_vec(),
        });

        // a should observe the delivery. (No manual directory insert of b: b dialed in, and under
        // self-certification a's accept loop registered b's proven coordinate → source address itself.)
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

    #[tokio::test]
    async fn a_dialed_in_peer_is_routable_in_reverse_via_self_certifying_discovery() {
        // The reachability property (#119): a node that only ever *received* a connection can originate
        // traffic BACK to that peer, because under self-certification its accept loop registers the peer's
        // VRF-proven coordinate → source address (no shared directory, no manual insert). Without that
        // reverse discovery a real deployment forms a star — a dialled-in peer is unreachable in reverse.
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut a = Node::start::<F2>(NodeConfig { listen: loopback, ..NodeConfig::default() })
            .await
            .unwrap();
        let a_addr = a.address();
        let a_net = a.local_addr();

        // b bootstraps ONLY a; a is given nothing about b.
        let make_b = || {
            Node::start::<F2>(NodeConfig {
                listen: loopback,
                bootstrap: vec![crate::config::Peer { coord: a_addr, addr: a_net }],
                ..NodeConfig::default()
            })
        };
        let mut b = make_b().await.unwrap();
        while b.address() == a_addr {
            b.shutdown();
            b = make_b().await.unwrap();
        }
        let b_addr = b.address();

        // b dials in (its first Send establishes the connection a learns it on). Drain a's notification of
        // that inbound payload so we know the connection — and thus the reverse registration — is in place.
        b.command(Command::Send { to: a_addr, payload: b"knock".to_vec() });
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match a.next_notification().await {
                    Some(Notification::Delivered { .. }) | None => break,
                    Some(_) => {}
                }
            }
        })
        .await
        .expect("a received b's inbound knock");

        // Now the reverse direction: a originates to b. a never bootstrapped b — it can only route there
        // if it learned b's address from the inbound connection.
        a.command(Command::Send { to: b_addr, payload: b"reply over quic".to_vec() });
        let mut b = b;
        let got = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match b.next_notification().await {
                    Some(Notification::Delivered { payload, .. }) => break Some(payload),
                    Some(_) => {}
                    None => break None,
                }
            }
        })
        .await
        .expect("timed out waiting for the reverse delivery");
        assert_eq!(
            got.as_deref(),
            Some(b"reply over quic".as_slice()),
            "a routed back to a peer it only ever received a connection from (self-certifying reverse discovery)"
        );

        a.shutdown();
        b.shutdown();
    }
}
