//! The **in-memory datagram fabric** — a modelled carrier that real nodes run over.
//!
//! This is the concrete answer to the fidelity gap `docs/design-testing.md` §5.1 names: every existing test rung
//! abstracts the deployed node's *composition*, because each instantiates an engine (or a transport) directly. A node
//! spawned over this fabric instead runs the **whole production path** — real QUIC state machine, real TLS, real
//! driver actors, real `fanos-node` driver tasks — with datagrams carried by a queue this module models rather than a
//! UDP socket. It plugs into [`fanos_quic::Fabric::Abstract`], the seam that exists for exactly this.
//!
//! ## What is and is not simulated
//!
//! Simulated: **the carrier only** — reachability, one-way latency with jitter, independent loss, and partition. Not
//! simulated: anything above it. Packets are the real serialized QUIC datagrams, congestion control and loss recovery
//! are quinn's own, and the node composition is whatever `fanos-node` actually spawns.
//!
//! **This is a wall-clock tier, deliberately.** Delays are real `tokio` sleeps, so a scenario here is *not*
//! bit-reproducible the way the deterministic simulator ([`crate::sim`]) is — that one buys determinism by abstracting
//! the socket, which is precisely why it cannot see composition faults. The two are complements: [`crate::sim`] for
//! reproducible protocol behaviour at scale, this for faithful wiring under adverse transport. Assertions here follow
//! the T3/T4 discipline — poll until observed with a generous deadline, never a fixed tick.
//!
//! ## The contract a fabric owes quinn
//!
//! `poll_recv` **must register the caller's waker** when it has nothing to hand back. Returning a bare
//! `Poll::Pending` compiles and then silently never receives another datagram, because nothing wakes the task. Here
//! that is discharged by `UnboundedReceiver::poll_recv`, which registers on the channel.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

use crate::rng::Rng;

/// How the fabric carries datagrams — the only thing this tier simulates.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Link {
    /// One-way base latency.
    pub latency: Duration,
    /// Extra uniform jitter added per datagram, in `[0, jitter]`.
    pub jitter: Duration,
    /// Independent per-datagram loss probability, in percent (`0` = lossless).
    pub loss_percent: u8,
}

impl Default for Link {
    /// A plausible wide-area link: 20 ms one-way with 10 ms jitter and no loss — the same shape
    /// [`crate::network`] uses for the deterministic tier, so a scenario reads the same in both.
    fn default() -> Self {
        Self { latency: Duration::from_millis(20), jitter: Duration::from_millis(10), loss_percent: 0 }
    }
}

impl Link {
    /// A perfect link — no latency, no jitter, no loss. For tests isolating composition from transport.
    #[must_use]
    pub const fn ideal() -> Self {
        Self { latency: Duration::ZERO, jitter: Duration::ZERO, loss_percent: 0 }
    }

    /// A lossy link at `loss_percent`, otherwise as `self`.
    #[must_use]
    pub const fn with_loss(mut self, loss_percent: u8) -> Self {
        self.loss_percent = loss_percent;
        self
    }
}

/// One endpoint's inbox: the queue its socket polls.
type Inbox = mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>;

/// The shared state every socket on a fabric reads — the routing table and the partition set.
#[derive(Debug, Default)]
struct Shared {
    inboxes: HashMap<SocketAddr, Inbox>,
    /// Ordered pairs `(from, to)` whose datagrams are dropped — a **directional** partition, since real censorship
    /// and real routing failures are frequently one-way and a symmetric-only model cannot express that.
    blocked: HashSet<(SocketAddr, SocketAddr)>,
}

/// A modelled datagram fabric that real nodes bind sockets on.
///
/// Cheap to clone (every clone shares one network). Addresses are synthetic loopback `SocketAddr`s handed out by
/// [`bind`](Self::bind) — quinn treats them as opaque endpoint identities, so nothing is bound on the host.
#[derive(Clone, Debug)]
pub struct Fabric {
    shared: Arc<Mutex<Shared>>,
    link: Link,
    next_port: Arc<AtomicU64>,
    /// Datagrams accepted for delivery and datagrams dropped — the fabric's own observability, so a scenario can
    /// assert on what the transport did rather than inferring it from node behaviour.
    sent: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl Default for Fabric {
    fn default() -> Self {
        Self::new(Link::default())
    }
}

impl Fabric {
    /// A fresh fabric whose links all behave as `link`.
    #[must_use]
    pub fn new(link: Link) -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared::default())),
            link,
            next_port: Arc::new(AtomicU64::new(1)),
            sent: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Bind a new endpoint, returning the socket to hand to [`fanos_quic::Fabric::Abstract`].
    ///
    /// The synthetic address is `127.0.0.1:<n>` for a fresh `n`. Nothing is bound on the host — these are identities
    /// within the fabric, which is what makes tens of thousands of endpoints cost nothing.
    pub fn bind(&self) -> Arc<FabricSocket> {
        let port = self.next_port.fetch_add(1, Ordering::Relaxed);
        // Ports are 16-bit; wrap above the reserved range so a very large fleet keeps producing distinct identities.
        let port = u16::try_from(1024 + (port % 60_000)).unwrap_or(1024);
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut shared) = self.shared.lock() {
            shared.inboxes.insert(addr, tx);
        }
        Arc::new(FabricSocket { fabric: self.clone(), addr, inbox: Mutex::new(rx) })
    }

    /// **Partition** `from → to`: every datagram in that direction is dropped until [`heal`](Self::heal).
    ///
    /// Directional on purpose. A one-way block is both a real failure mode (asymmetric routing, a middlebox filtering
    /// one direction) and a sharper test: a protocol that assumes reachability is symmetric will pass a symmetric
    /// partition and fail here.
    pub fn partition(&self, from: SocketAddr, to: SocketAddr) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.blocked.insert((from, to));
        }
    }

    /// Remove a [`partition`](Self::partition).
    pub fn heal(&self, from: SocketAddr, to: SocketAddr) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.blocked.remove(&(from, to));
        }
    }

    /// Datagrams the fabric accepted for delivery.
    #[must_use]
    pub fn delivered(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Datagrams the fabric dropped — to loss or to a partition.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Whether `from → to` is currently partitioned.
    fn is_blocked(&self, from: SocketAddr, to: SocketAddr) -> bool {
        self.shared.lock().is_ok_and(|shared| shared.blocked.contains(&(from, to)))
    }

    /// The destination's inbox, if that endpoint exists on this fabric.
    fn inbox_of(&self, to: SocketAddr) -> Option<Inbox> {
        self.shared.lock().ok().and_then(|shared| shared.inboxes.get(&to).cloned())
    }
}

/// One endpoint's socket on a [`Fabric`] — a `quinn` [`AsyncUdpSocket`] over the modelled carrier.
#[derive(Debug)]
pub struct FabricSocket {
    fabric: Fabric,
    addr: SocketAddr,
    /// Behind a `Mutex` because `poll_recv` needs `&mut` on the receiver while the trait gives `&self`. Uncontended
    /// in practice: exactly one driver task polls a given socket.
    inbox: Mutex<mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>,
}

impl FabricSocket {
    /// This endpoint's synthetic address on the fabric.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl AsyncUdpSocket for FabricSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // The fabric's queues are unbounded, so the socket is always writable — there is no backpressure to report.
        // A future bandwidth model would gate here, and would then owe the same waker registration `poll_recv` does.
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let (from, to) = (self.addr, transmit.destination);
        let Some(inbox) = self.fabric.inbox_of(to) else {
            // No such endpoint: silently dropped, exactly as a datagram to an unreachable host is. Reporting an error
            // here would tell the sender something UDP would not.
            self.fabric.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };
        if self.fabric.is_blocked(from, to) {
            self.fabric.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let link = self.fabric.link;
        // Loss and jitter are drawn from a seed bound to this datagram's endpoints and sequence, so a run is
        // reproducible for a fixed schedule even though the tier is wall-clock.
        let seq = self.fabric.sent.load(Ordering::Relaxed);
        let mut rng = Rng::new(seq ^ u64::from(to.port()) << 16 ^ u64::from(from.port()));
        if link.loss_percent > 0 && rng.below(100) < u64::from(link.loss_percent) {
            self.fabric.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.fabric.sent.fetch_add(1, Ordering::Relaxed);
        let jitter = if link.jitter.is_zero() {
            Duration::ZERO
        } else {
            let span = u64::try_from(link.jitter.as_micros()).unwrap_or(u64::MAX);
            Duration::from_micros(rng.below(span.max(1)))
        };
        let delay = link.latency + jitter;
        let datagram = transmit.contents.to_vec();
        if delay.is_zero() {
            let _ = inbox.send((from, datagram));
        } else {
            // A delayed delivery is its own task, so datagrams may reorder — which a real network does and a
            // deliver-in-order model would hide.
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = inbox.send((from, datagram));
            });
        }
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [io::IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let (Some(buf), Some(slot)) = (bufs.first_mut(), meta.first_mut()) else {
            return Poll::Ready(Ok(0));
        };
        let Ok(mut inbox) = self.inbox.lock() else {
            return Poll::Ready(Err(io::Error::other("fabric inbox poisoned")));
        };
        // `poll_recv` registers the waker on the channel — the contract a fabric owes quinn (module docs).
        let Some((from, datagram)) = ready!(inbox.poll_recv(cx)) else {
            return Poll::Ready(Err(io::Error::other("fabric endpoint closed")));
        };
        let len = datagram.len().min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..len), datagram.get(..len)) {
            dst.copy_from_slice(src);
        }
        *slot = RecvMeta { addr: from, len, stride: len, ecn: None, dst_ip: None };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

/// The fabric has no backpressure, so writability is immediate.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}


/// A fleet of **real deployed nodes** on one modelled fabric — the composed-node facility a scenario drives.
///
/// Every member is a genuine [`fanos_node::Node`]: the overlay engine *plus* every driver task it composes. That is
/// what distinguishes this from [`crate::fleet`], which models node state directly, and from [`crate::sim`], which
/// steps engines — neither can observe wiring, and wiring is where composition faults live
/// (`docs/design-testing.md` §5.1).
///
/// Nodes bootstrap exactly as a deployment does: the first member's fabric address is handed to the rest as a
/// [`Peer`], so discovery is the real path rather than a pre-populated table.
pub struct NodeFleet {
    /// The carrier every member shares — partition and inspect it here.
    pub fabric: Fabric,
    nodes: Vec<fanos_node::Node>,
    addrs: Vec<SocketAddr>,
}

impl NodeFleet {
    /// Spawn `count` real nodes on a fresh fabric with `link` behaviour, each offering `roles`.
    ///
    /// The first node carries the beacon parameters (a cell needs one beacon authority) and the rest bootstrap from
    /// it. `count` must be at least 1.
    ///
    /// # Errors
    /// Propagates the first node-start failure.
    pub async fn spawn<F: fanos_field::Field + 'static>(
        count: usize,
        link: Link,
        roles: fanos_node::RoleSet,
    ) -> Result<Self, fanos_node::NodeError> {
        let fabric = Fabric::new(link);
        let (_shares, commitment) = fanos_vrf::vss::deal(
            &[0xF1; 32],
            2,
            3,
            &mut fanos_vrf::vss::DeterministicRng::new(b"fabric-fleet"),
        )
        .ok_or(fanos_node::NodeError::Identity)?;
        let mut nodes: Vec<fanos_node::Node> = Vec::with_capacity(count);
        let mut addrs = Vec::with_capacity(count);
        for _ in 0..count {
            let socket = fabric.bind();
            let addr = socket.addr();
            // Bootstrap from whoever is already up — the real discovery path, not a seeded table.
            let bootstrap = nodes
                .iter()
                .zip(&addrs)
                .map(|(node, &addr)| fanos_node::Peer { coord: node.health().address, addr })
                .collect();
            let node = fanos_node::Node::start_over::<F>(
                fanos_node::NodeConfig {
                    beacon: Some(fanos_node::BeaconParams { commitment: commitment.clone(), threshold: 2, share: None }),
                    roles,
                    bootstrap,
                    ..fanos_node::NodeConfig::default()
                },
                fanos_quic::Fabric::Abstract(socket),
            )
            .await?;
            nodes.push(node);
            addrs.push(addr);
        }
        Ok(Self { fabric, nodes, addrs })
    }

    /// The fleet's nodes.
    #[must_use]
    pub fn nodes(&self) -> &[fanos_node::Node] {
        &self.nodes
    }

    /// Member `index`, if it exists.
    #[must_use]
    pub fn node(&self, index: usize) -> Option<&fanos_node::Node> {
        self.nodes.get(index)
    }

    /// Cut `from → to` by member index — **directional**, so a scenario can model the asymmetric reachability real
    /// censorship produces. Silently ignores an out-of-range index.
    pub fn partition(&self, from: usize, to: usize) {
        if let (Some(&a), Some(&b)) = (self.addrs.get(from), self.addrs.get(to)) {
            self.fabric.partition(a, b);
        }
    }

    /// Cut both directions between two members.
    pub fn isolate(&self, a: usize, b: usize) {
        self.partition(a, b);
        self.partition(b, a);
    }

    /// Restore `from → to`.
    pub fn heal(&self, from: usize, to: usize) {
        if let (Some(&a), Some(&b)) = (self.addrs.get(from), self.addrs.get(to)) {
            self.fabric.heal(a, b);
        }
    }

    /// Poll `predicate` until it holds, or give up after a deliberately generous deadline.
    ///
    /// This tier is wall-clock, so an assertion must never be written against a fixed tick — a budget that merely
    /// looks generous is the documented flake shape (`docs/design-testing.md` §5). Returns whether it held.
    pub async fn until(&self, mut predicate: impl FnMut(&Self) -> bool) -> bool {
        for _ in 0..600 {
            if predicate(self) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    /// Stop every member.
    pub fn shutdown(self) {
        for node in self.nodes {
            node.shutdown();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use fanos_field::F2;
    use fanos_quic::{Directory, NodeCredentials, spawn_self_certifying_persistent_over};
    use fanos_runtime::{Config, OverlayNode};

    /// Spawn a real self-certifying node on `fabric` — the whole production path, carrier excepted.
    fn node(fabric: &Fabric, directory: &Directory) -> (Arc<FabricSocket>, fanos_quic::NodeHandle) {
        let credentials = NodeCredentials::generate().expect("credentials");
        let socket = fabric.bind();
        let handle = spawn_self_certifying_persistent_over::<F2>(
            fanos_quic::Fabric::Abstract(socket.clone()),
            &credentials,
            |point| Box::new(OverlayNode::<F2>::new(point, Config::default())),
            directory.clone(),
            None,
        )
        .expect("a node spawns over the modelled fabric");
        (socket, handle)
    }

    /// Poll until `f` holds, or give up — the T3/T4 discipline (never a fixed tick).
    ///
    /// The deadline is deliberately far larger than the ~0.1 s these tests take in isolation. They share a process
    /// with CPU-heavy Monte-Carlo scenarios, and a budget that merely *looks* generous produced exactly the flake §5
    /// of `docs/design-testing.md` records — alternating failures under concurrent load. A long deadline costs nothing
    /// when the condition holds on the first poll, which is the normal case.
    async fn until(mut f: impl FnMut() -> bool) -> bool {
        for _ in 0..600 {
            if f() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    #[tokio::test]
    async fn real_nodes_exchange_traffic_over_the_modelled_carrier() {
        // The point of this tier: nothing above the socket is simulated. These are real self-certifying nodes with
        // real QUIC and real TLS, and the datagrams between them are carried by this module.
        let fabric = Fabric::new(Link::ideal());
        let directory = Directory::new();
        let (a_sock, a) = node(&fabric, &directory);
        let (b_sock, b) = node(&fabric, &directory);
        assert_ne!(a_sock.addr(), b_sock.addr(), "each endpoint gets its own fabric identity");
        assert_eq!(a.local_addr(), a_sock.addr(), "the node reports the fabric address as its own");

        // Send A → B *directly*. Deliberately not a store operation: a key routes to its responsible point, and with
        // two of seven points occupied whether that point exists depends on where the random credentials landed — so a
        // put/get here asserts a property of the overlay's addressing, not of the carrier. `Command::Send` names the
        // destination, which is exactly the carrier property under test.
        assert!(
            a.client().command(fanos_runtime::Command::Send { to: b.address(), payload: b"over the fabric".to_vec() }),
            "the engine accepted the send"
        );
        assert!(until(|| fabric.delivered() > 0).await, "real node traffic crossed the fabric");
        a.shutdown();
        b.shutdown();
    }

    #[tokio::test]
    async fn a_directional_partition_drops_only_the_blocked_direction() {
        // Directional partition is the sharper model: a protocol that assumes reachability is symmetric passes a
        // symmetric cut and fails this one.
        let fabric = Fabric::new(Link::ideal());
        let directory = Directory::new();
        let (a_sock, a) = node(&fabric, &directory);
        let (b_sock, b) = node(&fabric, &directory);

        fabric.partition(a_sock.addr(), b_sock.addr());
        let before = fabric.dropped();
        assert!(a.client().command(fanos_runtime::Command::Send { to: b.address(), payload: b"blocked".to_vec() }));
        assert!(until(|| fabric.dropped() > before).await, "a → b datagrams are dropped while partitioned");

        // The reverse direction was never cut, so b → a still carries.
        let delivered = fabric.delivered();
        assert!(b.client().command(fanos_runtime::Command::Send { to: a.address(), payload: b"reverse".to_vec() }));
        assert!(until(|| fabric.delivered() > delivered).await, "b → a is unaffected by the a → b cut");

        // And healing restores it.
        fabric.heal(a_sock.addr(), b_sock.addr());
        assert!(!fabric.is_blocked(a_sock.addr(), b_sock.addr()), "the partition is healed");
        a.shutdown();
        b.shutdown();
    }

    #[tokio::test]
    async fn a_whole_deployed_node_runs_on_the_fabric_and_self_organizes() {
        // The rung this tier exists for. `Node::start_over` is the DEPLOYED node — every driver task it composes:
        // capability publisher, load publisher, role loop, beacon tracker, epoch driver, recovery trigger, mix
        // publisher. None of that is reachable from a rung that instantiates an engine, which is exactly why four
        // wiring bugs survived until the role loop was connected (docs/design-testing.md §5.1).
        //
        // Asserting on the ASSIGNMENT is the sharp end: it is produced by the composition, not by any one component —
        // capability advertisement + load report + directory scan + controller, each over the fabric.
        use fanos_core::roles::Role;
        use fanos_field::F2;
        use fanos_node::{Node, NodeConfig, RoleSet};
        use fanos_vrf::vss::{DeterministicRng, deal};

        let fabric = Fabric::new(Link::ideal());
        let (_shares, commitment) =
            deal(&[0xF4; 32], 2, 3, &mut DeterministicRng::new(b"fabric-node")).expect("deal");
        let offered = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        let node = Node::start_over::<F2>(
            NodeConfig {
                beacon: Some(fanos_node::BeaconParams { commitment, threshold: 2, share: None }),
                roles: offered,
                ..NodeConfig::default()
            },
            fanos_quic::Fabric::Abstract(fabric.bind()),
        )
        .await
        .expect("a whole node starts on the fabric");

        // The cell assigned from the offer — which only happens if the publishers, the directory scan and the
        // controller all completed over the modelled carrier.
        let assigned = until(|| node.assigned_roles().any()).await;
        assert!(assigned, "the deployed node's composition ran and produced an assignment");
        assert!(node.serves(Role::Rendezvous), "including the role it offered");
        assert!(!node.serves(Role::Exit), "and not one it did not");
        node.shutdown();
    }

    #[tokio::test]
    async fn a_fleet_of_composed_nodes_self_organizes_over_the_carrier() {
        // A fleet of REAL deployed nodes, bootstrapping off each other over the modelled carrier. The assertion is
        // that every member's composition completes — each must publish a capability, publish a load report, scan the
        // cell-wide directory and step its controller, all over the fabric.
        use fanos_core::roles::Role;
        use fanos_field::F2;
        use fanos_node::RoleSet;

        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        let fleet = NodeFleet::spawn::<F2>(5, Link::default(), roles).await.expect("a fleet starts");
        assert_eq!(fleet.nodes().len(), 5);
        let all_assigned = fleet
            .until(|f| f.nodes().iter().all(|n| n.assigned_roles().any()))
            .await;
        assert!(all_assigned, "every member's composition produced an assignment over the carrier");
        // Every member offered rendezvous, so the cell should be serving it — the property NOSTOS hosting coverage
        // depends on, now observable end to end rather than asserted of a controller in isolation.
        assert!(
            fleet.nodes().iter().any(|n| n.serves(Role::Rendezvous)),
            "the cell provisioned the anonymous rendezvous role"
        );
        assert!(fleet.fabric.delivered() > 0, "the fleet's traffic crossed the modelled carrier");
        fleet.shutdown();
    }

    #[tokio::test]
    async fn a_node_that_can_reach_nobody_reports_a_solitary_assignment() {
        // The §5.3 finding, now detectable. A node's own capability and load slots are LOCAL reads, so an isolated
        // node still computes a valid-looking assignment — over a roster of one. Before `Assignment::roster` existed
        // that was indistinguishable from a cell-agreed decision, which is what made it dangerous: every member of a
        // partitioned cell assigns itself every role it offers and believes the cell agreed.
        use fanos_field::F2;
        use fanos_node::RoleSet;

        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        // Total loss: nothing whatsoever crosses the carrier.
        let fleet = NodeFleet::spawn::<F2>(2, Link::ideal().with_loss(100), roles).await.expect("fleet starts");
        let assigned = fleet.until(|f| f.nodes().iter().all(|n| n.assigned_roles().any())).await;
        assert!(assigned, "an unreachable node still assigns itself — the behaviour §5.3 measured");
        for node in fleet.nodes() {
            let assignment = node.assignment();
            assert!(
                assignment.is_solitary(),
                "…and now says so: roster={} for a node that reached nobody",
                assignment.roster
            );
        }
        assert_eq!(fleet.fabric.delivered(), 0, "nothing crossed the carrier, confirming the isolation");
        fleet.shutdown();
    }

    #[tokio::test]
    async fn a_reachable_fleet_reports_a_cell_agreed_roster() {
        // The contrapositive, which is what makes the signal worth anything: on a healthy carrier the roster grows
        // past one, so `is_solitary` genuinely discriminates rather than always being true.
        use fanos_field::F2;
        use fanos_node::RoleSet;

        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        let fleet = NodeFleet::spawn::<F2>(3, Link::ideal(), roles).await.expect("fleet starts");
        let agreed = fleet.until(|f| f.nodes().iter().any(|n| !n.assignment().is_solitary())).await;
        let rosters: Vec<usize> = fleet.nodes().iter().map(|n| n.assignment().roster).collect();
        assert!(agreed, "a healthy fleet reaches a roster beyond one (rosters = {rosters:?})");
        fleet.shutdown();
    }

    #[tokio::test]
    #[ignore = "probe, not an assertion — run with --ignored --nocapture"]
    async fn probe_loss_tolerance_of_the_composition() {
        use fanos_field::F2;
        use fanos_node::RoleSet;
        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        for loss in [0u8, 10, 25, 50, 75, 90] {
            let started = std::time::Instant::now();
            let fleet = NodeFleet::spawn::<F2>(3, Link::default().with_loss(loss), roles)
                .await
                .expect("fleet starts");
            let ok = fleet.until(|f| f.nodes().iter().all(|n| n.assigned_roles().any())).await;
            // Does each node's peer count agree? `known_peers` is the address book — a proxy for whether discovery
            // completed, i.e. whether the rosters the controllers agreed over were the same set.
            let peers: Vec<usize> = fleet.nodes().iter().map(|n| n.health().known_peers).collect();
            let rosters: Vec<usize> = fleet.nodes().iter().map(|n| n.assignment().roster).collect();
            println!(
                "loss={loss:>2}%  all-assigned={ok:<5}  {:>7.2?}  delivered={:>5} dropped={:>5}  peers={peers:?} rosters={rosters:?}",
                started.elapsed(),
                fleet.fabric.delivered(),
                fleet.fabric.dropped()
            );
            fleet.shutdown();
        }
    }

    #[test]
    fn an_unreachable_destination_is_dropped_not_an_error() {
        // A datagram to an endpoint that does not exist must behave as UDP does: dropped, with nothing reported to
        // the sender. Returning an error here would hand the sender reachability information a real socket withholds.
        let fabric = Fabric::new(Link::ideal());
        let socket = fabric.bind();
        let nowhere = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 65_000));
        let transmit = Transmit {
            destination: nowhere,
            ecn: None,
            contents: b"into the void",
            segment_size: None,
            src_ip: None,
        };
        assert!(socket.try_send(&transmit).is_ok(), "an unreachable destination is not an error");
        assert_eq!(fabric.dropped(), 1, "…it is a drop");
        assert_eq!(fabric.delivered(), 0, "and nothing was delivered");
    }
}
