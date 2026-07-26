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

use crate::observe::Timeline;
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

/// The number of **distinct** plane points `n` nodes are expected to occupy, out of `points`.
///
/// A node's coordinate is `MapToPoint(VRF(sk, node‖epoch‖beacon))` — a uniform draw over the plane's
/// `P = q² + q + 1` points — so this is the classic occupancy-problem expectation:
///
/// ```text
/// E[distinct] = P · (1 − (1 − 1/P)ⁿ)
/// ```
#[must_use]
pub fn expected_distinct(points: usize, n: u32) -> f64 {
    let p = points as f64;
    if p <= 0.0 { return 0.0 }
    p * (1.0 - (1.0 - 1.0 / p).powi(i32::try_from(n).unwrap_or(i32::MAX)))
}

/// The probability that `n` nodes draw **pairwise distinct** coordinates from `points` — `P! / ((P − n)! · Pⁿ)`.
///
/// Two nodes sharing a point are *mutually unroutable*: the coordinate → address table holds one address per point. So
/// any property requiring a cell to see its own membership needs this close to 1, and by the birthday bound
/// (`≈ exp(−n²/2P)`) that holds only while `n = O(√P)`. **A PG(2,q) cell therefore supports on the order of `q` nodes,
/// not `q² + q + 1`** — a factor-`q` reduction against the naive reading, and a property of the coordinate *draw* rather
/// than of any subsystem above it.
///
/// ## Measured, and why it matters for every cell-wide test here
///
/// | plane | points | nodes | `injective_probability` | observed distinct |
/// |---|---|---|---|---|
/// | PG(2,2) | 7 | 3 | 0.612 | 3, sometimes 2 |
/// | PG(2,2) | 7 | 7 | 0.0061 | **4** (one point held by three nodes; E[distinct] = 4.62) |
/// | PG(2,4) | 21 | 7 | 0.325 | **7**, then **6** on the next run (E[distinct] = 6.08) |
///
/// Several cell-wide tests here were intermittent for exactly this reason: a collision splits the roster in a way that
/// is indistinguishable from a resolution defect, and it was diagnosed as one until the plane was enlarged with
/// everything else held fixed. The lasting fix is not a bigger plane — at 7 nodes even PG(2,4) is a coin flip — but
/// assertions that do not depend on the draw: compare each node's roster against the number of *occupied* coordinates,
/// never against the node count.
///
/// Resolving collisions rather than tolerating them belongs to the coordinate-VRF Level B reshuffle
/// (`docs/design-coordinates.md`); `Directory` already *counts* collisions, so they were anticipated but not resolved.
#[must_use]
pub fn injective_probability(points: usize, n: u32) -> f64 {
    let p = points as f64;
    if points == 0 || (n as usize) > points { return 0.0 }
    (0..n).map(|k| (p - f64::from(k)) / p).product()
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
        let mut taken: HashSet<fanos_geometry::Triple> = HashSet::new();
        // Retries until the whole draw is INJECTIVE. A coordinate is `MapToPoint(VRF(sk, …))`, i.e. a uniform draw over
        // the plane's `q² + q + 1` points, so a fleet collides with probability `1 - P!/((P-n)!·Pⁿ)` — at 5 nodes on
        // `PG(2,4)`'s 21 points that is **40.2% of runs**. Two nodes sharing a point are mutually unroutable: the one
        // that loses the directory arbitration receives nothing, so it can never see the whole cell however long it
        // waits. A fixture that lets that happen turns every cell-wide assertion into a coin flip on the draw — and a
        // frozen, split roster is indistinguishable from a resolution defect, which is a diagnosis this file has already
        // paid for once (§5.3.4a).
        //
        // Resolving a collision *live* is `fanos_vrf::settle_index`, which is complete and consistent but not yet
        // reachable from the wire (the `HELLO` frame carries only probe index 0 — `docs/open-tasks.md` Tier A). Until it
        // is, an injective fixture is what isolates resolution from the draw; the same construction is used by
        // `fanos-quic/tests/self_certifying.rs::spawn_distinct`, for the same reason.
        // An injective draw is impossible past the plane's point count, and a retry loop must never be the thing that
        // discovers that. `attempts` additionally bounds the pathological tail: the expected number of draws is
        // `n·H_P/(P-n)`-ish, and 64 per seat is orders of magnitude past it for every fixture here.
        if count > fanos_geometry::Plane::<F>::N as usize {
            return Err(fanos_node::NodeError::Identity);
        }
        let mut attempts = 0usize;
        while nodes.len() < count {
            attempts += 1;
            if attempts > 64 * count.max(1) {
                return Err(fanos_node::NodeError::Identity);
            }
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
            if !taken.insert(node.health().address) {
                // A collided draw: drop this node and try again with fresh credentials. The socket is abandoned with it,
                // which costs nothing on a modelled fabric.
                node.shutdown();
                continue;
            }
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
    /// Poll `predicate` until it holds, up to ~240 s; `false` if it never did.
    ///
    /// The ceiling is a **liveness backstop, not a latency budget** — its only job is to turn a never-converging fleet
    /// into a failure. It was 60 s, which is the mistake `docs/design-testing.md` §5.3.4 removes from the real-socket
    /// suites: a fleet measured converging at 76 s on an idle machine would fail against it for no reason. The healthy
    /// path pays nothing, since it returns as soon as the predicate holds.
    pub async fn until(&self, mut predicate: impl FnMut(&Self) -> bool) -> bool {
        for _ in 0..2_400 {
            if predicate(self) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    /// Record a [`Timeline`] of `observe` across every node: `samples` samples spaced `every` apart, starting
    /// immediately. Blocks for `samples * every`.
    ///
    /// This is the I/O half of the observatory ([`crate::observe`] holds the analysis). It exists because the properties
    /// that matter for a self-organizing cell — converged / frozen / oscillating — are properties of a *trajectory*, and
    /// a fleet inspected once can only report its final state. A single observation pass feeds every question, so
    /// different observables are always compared at the same instants (see [`Timeline::map`]).
    pub async fn observe<T, O>(&self, samples: usize, every: Duration, observe: O) -> Timeline<T>
    where
        O: Fn(&fanos_node::Node) -> T,
    {
        let mut recorded = Vec::with_capacity(samples);
        for k in 0..samples {
            recorded.push((every * u32::try_from(k).unwrap_or(u32::MAX), self.nodes.iter().map(&observe).collect()));
            tokio::time::sleep(every).await;
        }
        Timeline::new(recorded)
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
        for _ in 0..2_400 {
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
        use fanos_field::F4;
        use fanos_node::RoleSet;

        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        // F4, per `SAFE_LOAD_FACTOR`: five nodes in PG(2,2)'s seven points is load factor 0.71, where collisions are
        // near-certain and two nodes on one coordinate would confound what this asserts.
        let fleet = NodeFleet::spawn::<F4>(5, Link::default(), roles).await.expect("a fleet starts");
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
    async fn the_cell_converges_without_freezing_or_oscillating() {
        // The observatory applied to the subsystem that motivated it — three defect classes in one pass, each invisible
        // to an assertion over the final state alone:
        //
        //   frozen     → a missing trigger. This is how `[1, 1, 2]` survived a green suite for so long.
        //   never agreed → permanent disagreement, which breaks the deterministic cell-wide assignment outright.
        //   flapping   → roles oscillating instead of settling. UNTESTED UNTIL NOW, and the most costly of the three
        //                for this protocol: a role set that churns churns the anonymity set with it.
        const N: usize = 3;
        /// Two-thirds through the observation window: roles and roster must both be settled past this point. Sized off
        /// the loop's own refresh period rather than a guess — convergence needs a few refreshes, and the window has to
        /// outlast them or the assertion measures discovery latency instead of settling.
        const WINDOW: u64 = 40;
        // F4 (21 points), not F2 (7): at three nodes in PG(2,2) roughly two runs in five draw a coordinate collision,
        // and a split roster from a collision is indistinguishable from one caused by the defects asserted here. See
        // `SAFE_LOAD_FACTOR` — a cell-wide assertion at a high load factor tests the birthday bound, not the cell.
        use fanos_field::F4;
        use fanos_node::RoleSet;

        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        let fleet = NodeFleet::spawn::<F4>(N, Link::ideal(), roles).await.expect("fleet starts");
        let trace = fleet.observe(30, Duration::from_secs(2), fanos_node::Node::assignment).await;
        fleet.shutdown();

        let roster = trace.map(|a| a.roster);
        let assigned = trace.map(|a| a.roles);
        let shape = roster.render();

        // Not frozen: the roster must move off its genesis value, or no re-assign trigger is firing at all.
        assert!(!roster.frozen(), "a frozen roster means no re-assign trigger fires\n{shape}");
        // Not oscillating: whatever it converges on, it must stop moving. Asserted over the window's second half so the
        // property is about *settling*, not about how long discovery took.
        let settle_by = Duration::from_secs(WINDOW);
        assert_eq!(
            assigned.changes_after(settle_by),
            0,
            "roles must settle, not oscillate: churn here is churn in the anonymity set\n{}",
            assigned.render()
        );
        assert_eq!(
            roster.changes_after(settle_by),
            0,
            "the roster must settle too — a value still moving late in the window has not converged\n{shape}"
        );
        assert!(roster.last().iter().all(|&r| r >= 1) && roster.last().len() == N, "every node reports a roster");
    }

    #[test]
    fn probing_recovers_the_capacity_the_birthday_bound_costs() {
        // The measurement that decides whether `fanos_vrf::probe_point` is worth its verification cost: with resolution,
        // does a cell of n nodes actually occupy n distinct points where a bare draw occupies only ~√P?
        //
        // Simulated over the real derivation (`probe_point` + `outranks`) rather than an abstract urn model, applying the
        // exact rule a node applies locally: lowest rank keeps a contested point, everyone else advances along its own
        // sequence. Phantom collisions are included, since the non-recursive witness rule permits them.
        use fanos_field::{F2, F4, F31};
        use fanos_primitives::{BeaconSeed, Epoch};
        use fanos_vrf::{VrfSecret, probe_point};

        for &(points, n) in &[(7usize, 7u32), (21, 7), (21, 15), (993, 200)] {
            let epoch = Epoch::new(4);
            let beacon = BeaconSeed::GENESIS;
            let outputs: Vec<_> = (0..n)
                .map(|i| {
                    let sk = VrfSecret::from_seed([u8::try_from(i % 251).unwrap_or(0); 32]);
                    let id = i.to_be_bytes();
                    let mut alpha = id.to_vec();
                    alpha.extend_from_slice(&epoch.low32_be_bytes());
                    alpha.extend_from_slice(beacon.as_bytes());
                    sk.prove(&alpha).1
                })
                .collect();

            // Seat everyone by ascending rank: a node takes the first point in its own sequence not already held by a
            // lower-ranked node. That is exactly the fixed point the local pairwise rule converges to.
            let mut order: Vec<usize> = (0..outputs.len()).collect();
            order.sort_by_key(|&i| outputs.get(i).copied().unwrap_or([0xff; 64]));
            let mut held: HashSet<fanos_geometry::Triple> = HashSet::new();
            let mut probes = 0u32;
            for out in order.iter().filter_map(|&i| outputs.get(i)) {
                for k in 0..u16::try_from(points).unwrap_or(u16::MAX) {
                    let candidate = match points {
                        7 => probe_point::<F2>(out, k).coords(),
                        21 => probe_point::<F4>(out, k).coords(),
                        _ => probe_point::<F31>(out, k).coords(),
                    };
                    probes += 1;
                    if held.insert(candidate) { break }
                }
            }
            let bare = expected_distinct(points, n);
            println!(
                "P={points:>4} n={n:>3} load={:.2}  probed occupancy {:>3}/{n}  bare E[distinct]={bare:.2}  probes/node={:.2}",
                f64::from(n) / points as f64, held.len(), f64::from(probes) / f64::from(n)
            );
            // The walk is confined to ONE LINE through the preferred point (`fanos_vrf::probe_point`), which denies an
            // attacker a steering primitive at the cost of a little capacity: a node fails to seat only when every point
            // of its line is taken, with probability ~ load^(q+1). That is negligible at real `q` and NOT negligible on
            // PG(2,2), whose lines hold three points — so the assertion is stated per plane rather than as one slogan.
            let expected = if points == 7 { 6 } else { n as usize };
            assert_eq!(
                held.len(),
                expected,
                "line-restricted probing seats {expected} of {n} at P={points} (lines hold {} points)",
                match points { 7 => 3, 21 => 5, _ => 32 }
            );
            assert!(
                (held.len() as f64) > bare || f64::from(n) <= bare + 0.01,
                "and it still beats the bare draw wherever the bare draw loses points"
            );
        }
    }

    /// The **best claim held on each point** by the first `arrived` nodes, keyed by point.
    ///
    /// This is the table a directory maintains as HELLOs land, and the only input `fanos_vrf::settle_index` takes: a claim
    /// to `p` is `(where the claimant's own walk reaches p, its rank)`, ordered by `fanos_vrf::claim_beats`. Building it
    /// once per peer set is the point — a directory that instead recomputes a peer's walk per query turns an O(q) lookup
    /// into an O(P) rebuild, which measured as a 77× slowdown on the `P=993` fixture below.
    fn best_claim_table(
        walks: &[Vec<fanos_geometry::Triple>],
        outputs: &[fanos_vrf::VrfOutput],
        arrived: usize,
    ) -> HashMap<fanos_geometry::Triple, (u16, fanos_vrf::VrfOutput)> {
        let mut table = HashMap::new();
        for (j, w) in walks.iter().enumerate().take(arrived) {
            let Some(out) = outputs.get(j) else { continue };
            for (k, t) in w.iter().enumerate() {
                let Ok(k) = u16::try_from(k) else { continue };
                let entry = table.entry(*t).or_insert((k, *out));
                if fanos_vrf::claim_beats((k, out), (entry.0, &entry.1)) {
                    *entry = (k, *out);
                }
            }
        }
        table
    }

    #[test]
    fn uncoordinated_local_settling_is_monotone_one_shot_and_injective() {
        // The property that decides whether the rule is *usable* rather than merely sound. A node can only run it against
        // the peers it has actually seen, in whatever order they appear, so the questions are: does a node's answer ever
        // have to be taken back, and do independent local answers agree?
        //
        // Under the lexicographic claim rule (`fanos_vrf::claim_beats`) a claim to a point is a function of the claimant's
        // VRF output alone — not of where anyone settled — which buys three things the old occupancy rule lacked and this
        // measures directly: settling is ONE-SHOT (no iteration to a fixed point), MONOTONE under arrival (an index only
        // ever advances as peers appear, so a node never retracts a position it already proved), and INJECTIVE (no two
        // nodes settle on one point, since the order is total).
        use fanos_field::{F2, F4, F31};
        use fanos_primitives::{BeaconSeed, Epoch};
        use fanos_vrf::{VrfSecret, probe_point, settle_index};

        for &(points, n) in &[(7usize, 7u32), (21, 15), (993, 200)] {
            let epoch = Epoch::new(11);
            let beacon = BeaconSeed::GENESIS;
            let outputs: Vec<_> = (0..n)
                .map(|i| {
                    let sk = VrfSecret::from_seed([u8::try_from(i % 251).unwrap_or(0); 32]);
                    let mut alpha = i.to_be_bytes().to_vec();
                    alpha.extend_from_slice(&epoch.low32_be_bytes());
                    alpha.extend_from_slice(beacon.as_bytes());
                    sk.prove(&alpha).1
                })
                .collect();

            // Each node's walk, once. A claim to a point is `(where my walk reaches it, my rank)`, so indexing the walks by
            // point gives the *best claim per point* — which is exactly the table a directory maintains from the HELLOs it
            // has collected, and the only input the rule takes. Recomputing a peer's walk per query instead is what a
            // directory must not do: it turns an O(q) lookup into an O(P) rebuild.
            macro_rules! walk_of {
                ($F:ty, $out:expr) => {
                    (0..fanos_vrf::probe_bound::<$F>())
                        .map(|k| probe_point::<$F>($out, k).coords())
                        .collect::<Vec<_>>()
                };
            }
            let walks: Vec<Vec<fanos_geometry::Triple>> = outputs
                .iter()
                .map(|o| match points {
                    7 => walk_of!(F2, o),
                    21 => walk_of!(F4, o),
                    _ => walk_of!(F31, o),
                })
                .collect();
            let best_claims = |arrived: usize| best_claim_table(&walks, &outputs, arrived);
            macro_rules! settle_on {
                ($F:ty, $mine:expr, $table:expr) => {
                    settle_index::<$F>($mine, |p: &fanos_geometry::Point<$F>| {
                        $table.get(&p.coords()).copied().filter(|(_, o)| o != $mine)
                    })
                };
            }
            macro_rules! per_plane {
                ($mine:expr, $table:expr) => {
                    match points {
                        7 => settle_on!(F2, $mine, $table),
                        21 => settle_on!(F4, $mine, $table),
                        _ => settle_on!(F31, $mine, $table),
                    }
                };
            }

            // Peers arrive one at a time; after each arrival every node re-evaluates against what it can see.
            let mut prev: Vec<Option<u16>> = vec![None; outputs.len()];
            for arrived in 1..=outputs.len() {
                let table = best_claims(arrived);
                for (i, mine) in outputs.iter().enumerate().take(arrived) {
                    let now = per_plane!(mine, table);
                    // MONOTONE: more peers can only make more points contested, so an index never retreats. This is what
                    // makes an intermediate answer safe to act on — a node that has already announced index `k` is never
                    // asked to un-announce it.
                    if let (Some(before), Some(after)) = (prev.get(i).copied().flatten(), now) {
                        assert!(
                            after >= before,
                            "index went backwards at P={points} node {i}: {before} → {after} on arrival {arrived}"
                        );
                    }
                    // ONE-SHOT: re-running against the same peer set is a no-op, so there is nothing to converge to.
                    assert_eq!(now, per_plane!(mine, table), "settling is not a function of the peer set alone");
                    if let Some(slot) = prev.get_mut(i) {
                        *slot = now;
                    }
                }
            }

            let seats = prev;
            let held: HashSet<fanos_geometry::Triple> = seats
                .iter()
                .enumerate()
                .filter_map(|(j, s)| {
                    let k = (*s)?;
                    let out = outputs.get(j)?;
                    Some(match points {
                        7 => probe_point::<F2>(out, k).coords(),
                        21 => probe_point::<F4>(out, k).coords(),
                        _ => probe_point::<F31>(out, k).coords(),
                    })
                })
                .collect();
            let seated = seats.iter().filter(|s| s.is_some()).count();
            println!(
                "P={points:>4} n={n:>3}  local settling → {seated:>3}/{n} seated, {:>3} distinct  (bare E={:.2})",
                held.len(),
                expected_distinct(points, n)
            );
            // INJECTIVE: every seated node holds a point of its own. This is the capacity claim, and unlike the old rule
            // it is structural rather than an outcome of iterating.
            assert_eq!(held.len(), seated, "two nodes settled on one point at P={points}");
            let expected = if points == 7 { 5 } else { n as usize };
            assert_eq!(
                seated,
                expected,
                "local settling seats {expected} of {n} at P={points} — line-restricted, see probing_recovers"
            );
        }
    }

    #[test]
    fn the_occupancy_formulas_match_their_closed_forms() {
        // The measured cases from `injective_probability`'s table, checked against hand-computed values — the constants
        // that justify running cell-wide tests at one load factor and not another must themselves be right.
        assert!((injective_probability(7, 3) - 210.0 / 343.0).abs() < 1e-12, "7·6·5 / 7³");
        assert!((injective_probability(7, 7) - 5040.0 / 823_543.0).abs() < 1e-12, "7! / 7⁷");
        assert!((injective_probability(21, 7) - 0.325_387_2).abs() < 1e-6, "21·20·…·15 / 21⁷");
        assert!((injective_probability(7, 1) - 1.0).abs() < 1e-12, "one node never collides");
        assert!(injective_probability(7, 8).abs() < f64::EPSILON, "more nodes than points cannot be injective");
        assert!(injective_probability(0, 1).abs() < f64::EPSILON, "an empty plane has nowhere to land");

        // E[distinct] = P(1 − (1 − 1/P)ⁿ): one draw always occupies exactly one point, and the 7-in-7 case is the
        // ≈4.6 figure that predicted the measured 4.
        assert!((expected_distinct(7, 1) - 1.0).abs() < 1e-12);
        assert!((expected_distinct(7, 7) - 4.620_583).abs() < 1e-5);
        assert!((expected_distinct(21, 7) - 6.075_692).abs() < 1e-5);
        assert!(expected_distinct(21, 7) < 7.0, "collisions are the norm, not the exception");
        assert!(expected_distinct(0, 5).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn the_whole_cell_resolves_every_member() {
        // The property the deterministic cell-wide assignment REQUIRES: every node resolves every member, so all compute
        // over the same roster.
        //
        // This was briefly recorded as an open finding against directory resolution. That framing was WRONG, and the
        // instrument corrected it: resolution is sound, and the failures were **coordinate collisions**. A coordinate is
        // a uniform draw into the plane's `q² + q + 1` points, so at 7 nodes in PG(2,2) — load factor 1 — the measured
        // occupancy was 4 distinct points of 7, with one point claimed by three nodes. Two nodes sharing a point are
        // mutually unroutable, so no node can ever see the whole cell. Enlarging the plane, with everything else held
        // fixed, is decisive: PG(2,4) at the same 7 nodes gives 7 distinct coordinates and rosters [7; 7].
        //
        // The assertion compares each node's roster against the number of **occupied** coordinates rather than the node
        // count. That was not enough on its own: comparing against `occupied` fixes the target NUMBER but not the fact
        // that the node which loses a collision's arbitration is unroutable and therefore cannot see the whole cell
        // however long it waits. Measured, this failed in ~40% of runs at `N = 5` on `PG(2,4)`'s 21 points, while the
        // comment here claimed it was draw-independent. `NodeFleet::spawn` now draws INJECTIVELY, which is what actually
        // isolates resolution from the draw; the `occupied` comparison stays because it keeps the assertion honest if
        // that ever changes.
        // Five, not seven. The assertion is draw-independent (roster vs *occupied* points), so it does not need a
        // full plane's worth of nodes — and seven real composed nodes is the most expensive fixture in this file, which
        // on a contended host is the difference between a signal and a timeout.
        const N: usize = 5;
        use fanos_field::F4;
        use fanos_node::RoleSet;

        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        let fleet = NodeFleet::spawn::<F4>(N, Link::ideal(), roles).await.expect("fleet starts");
        let coords: HashSet<fanos_geometry::Triple> =
            fleet.nodes().iter().map(|node| node.health().address).collect();
        let occupied = coords.len();
        // Convergence is *polled* rather than measured inside a fixed window: a window long enough to survive machine
        // contention makes every run pay for the worst case, and one sized for an idle machine is a false red — the same
        // mistake §5.3.4 removed from the real-socket suites. Settling is then checked over a short window afterwards.
        let converged = fleet.until(|f| f.nodes().iter().all(|n| n.assignment().roster == occupied)).await;
        let trace = fleet.observe(8, Duration::from_secs(2), fanos_node::Node::assignment).await;
        fleet.shutdown();
        let roster = trace.map(|a| a.roster);
        assert!(occupied > 1, "the premise: the draw left more than one point occupied ({occupied} of {N})");
        assert!(
            converged,
            "every node resolves every OCCUPIED coordinate ({occupied} of {N} nodes drew distinct points)\n{}",
            roster.render()
        );
        assert_eq!(roster.changes_after(Duration::ZERO), 0, "and it holds\n{}", roster.render());
    }

    #[tokio::test]
    #[ignore = "measurement — run with --ignored --nocapture"]
    async fn measure_whether_a_collided_draw_now_resolves_itself() {
        // The claim to check: with the probe index on the wire (`fanos_quic::claims`), a fleet whose coordinate draw
        // COLLIDES should now resolve to distinct points by itself, retiring the injective-draw workaround in
        // `NodeFleet::spawn`. At 7 nodes on `PG(2,4)`'s 21 points the draw collides in ~67% of runs, so a handful of trials
        // exercises it. Reports the *preferred* points (what the draw gave) against the *held* points (where the nodes
        // ended up): resolution shows as held > preferred.
        use fanos_field::F4;
        use fanos_node::RoleSet;

        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        for trial in 0..4 {
            let fleet = NodeFleet::spawn::<F4>(7, Link::ideal(), roles).await.expect("fleet starts");
            let settled = fleet.until(|f| {
                let held: HashSet<_> = f.nodes().iter().map(|n| n.health().address).collect();
                held.len() == f.nodes().len()
            }).await;
            let held: HashSet<_> = fleet.nodes().iter().map(|n| n.health().address).collect();
            let rosters: Vec<_> = fleet.nodes().iter().map(|n| n.assignment().roster).collect();
            fleet.shutdown();
            println!("trial {trial}: held {}/7 distinct, all-distinct reached: {settled}, rosters {rosters:?}", held.len());
        }
    }

    #[tokio::test]
    #[ignore = "probe, not an assertion — run with --ignored --nocapture"]
    async fn probe_roster_convergence_against_cell_occupancy() {
        // Hypothesis for the open finding: the capability/load directories ride the erasure-coded L4 store, whose
        // [7,3,4] LRC needs FOUR of seven shard homes to reconstruct, and sends to unoccupied coordinates are dropped.
        // If so, a three-node cell is simply BELOW the store's threshold and cannot resolve its own directory at all —
        // which would make this a configuration floor, not a resolution defect. Occupancy is the independent variable.
        use fanos_field::F4;
        use fanos_node::RoleSet;

        for n in [7usize] {
            let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
            let fleet = NodeFleet::spawn::<F4>(n, Link::ideal(), roles).await.expect("fleet starts");
            let trace = fleet.observe(30, Duration::from_secs(4), fanos_node::Node::assignment).await;
            let peers: Vec<usize> = fleet.nodes().iter().map(|node| node.health().known_peers).collect();
            let coords: Vec<fanos_geometry::Triple> = fleet.nodes().iter().map(|node| node.health().address).collect();
            let distinct: HashSet<fanos_geometry::Triple> = coords.iter().copied().collect();
            println!("  coords {coords:?} → {} distinct of {n}", distinct.len());
            fleet.shutdown();
            let roster = trace.map(|a| a.roster);
            println!(
                "occupancy {n}/7: final rosters {:?}  agreed={:?}  known_peers={peers:?}",
                roster.last(),
                roster.stable_agreement_at().map(|d| d.as_secs())
            );
        }
    }

    #[tokio::test]
    #[ignore = "probe, not an assertion — run with --ignored --nocapture"]
    async fn probe_does_the_roster_grow_at_later_epochs() {
        // Verifying a claim I made in docs §5.3 rather than trusting it: that cell-wide agreement is a property of
        // LATER epochs, once the beacon advances and the loop re-assigns over a fuller directory. If the roster never
        // grows, that sentence is wrong and the situation is worse than described — agreement would never be reached.
        use fanos_field::F4;
        use fanos_node::RoleSet;

        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        // F4 for the same reason as the assertions: the original F2 timeline that motivated this probe was partly a
        // collision artifact. The frozen *epoch* it revealed was real and independent of that.
        let fleet = NodeFleet::spawn::<F4>(3, Link::ideal(), roles).await.expect("fleet starts");
        for tick in 0..12 {
            let rosters: Vec<usize> = fleet.nodes().iter().map(|n| n.assignment().roster).collect();
            let epochs: Vec<String> =
                fleet.nodes().iter().map(|n| format!("{:?}", n.assignment().epoch)).collect();
            let peers: Vec<usize> = fleet.nodes().iter().map(|n| n.health().known_peers).collect();
            println!("t={:>4}s  rosters={rosters:?}  epochs={epochs:?}  known_peers={peers:?}", tick * 5);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
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
