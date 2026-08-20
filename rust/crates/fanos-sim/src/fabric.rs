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
//! bit-reproducible the way the deterministic simulator (`crate::sim`) is — that one buys determinism by abstracting
//! the socket, which is precisely why it cannot see composition faults. The two are complements: `crate::sim` for
//! reproducible protocol behaviour at scale, this for faithful wiring under adverse transport. Assertions here follow
//! the T3/T4 discipline — poll until observed with a generous deadline, never a fixed tick.
//!
//! ## The contract a fabric owes quinn
//!
//! `poll_recv` **must register the caller's waker** when it has nothing to hand back. Returning a bare
//! `Poll::Pending` compiles and then silently never receives another datagram, because nothing wakes the task. Here
//! that is discharged by `UnboundedReceiver::poll_recv`, which registers on the channel.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
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

/// How long an observable must sit unchanged before a failing property counts as **refuted** rather than unmeasured.
///
/// Derived, not chosen: **twice** the cell's own discovery timescale, `fanos_node::role_loop::ROSTER_REFRESH`
/// (`3 × RESOLVE_TIMEOUT`), which is the period on which a converging node re-runs the assignment that changes what a
/// scenario observes.
///
/// The factor of two is the whole content of the constant. A process that fires every `T` sits unchanged for just under
/// `T` *between* firings, so a window of `T` cannot distinguish "between firings" from "stopped" — it must span one full
/// period to catch a firing and a second to confirm none came. This was measured the hard way: at `T` the cell-wide
/// scenario reported `Refuted { frozen_for: 15s, last: [1, 2, 3, 4, 5] }` while the trace taken two seconds later read
/// `[5, 5, 5, 5, 5]`. The system had converged; the window was one period short of being able to say so.
///
/// Residual, stated because it bounds the claim: the role loop backs off as far as `DEFAULT_EPOCH_PERIOD`, so a node deep
/// in backoff could still move later. [`Settled::Refuted`] therefore means "frozen across two discovery periods", which is
/// the strongest claim a bounded observation can support.
pub const FROZEN_SPAN: Duration = fanos_node::role_loop::ROSTER_REFRESH.saturating_mul(2);

/// Default patience for [`NodeFleet::until_settled`] — the same 240 s ceiling [`NodeFleet::until`] uses, sized for a
/// loaded host running seven composed real-QUIC nodes.
pub const SETTLE_DEADLINE: Duration = Duration::from_secs(240);

/// The outcome of [`NodeFleet::until_settled`] — three-valued on purpose.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Settled<T> {
    /// The predicate held, after this long.
    Reached {
        /// Time from the first poll.
        after: Duration,
    },
    /// The observable stopped changing for [`FROZEN_SPAN`] and the predicate is still false: a real refutation.
    Refuted {
        /// How long nothing changed.
        frozen_for: Duration,
        /// The observable at the fixed point — what to print in the failure.
        last: T,
    },
    /// The deadline arrived while the observable was still changing. **Not** a refutation: the measurement failed, not
    /// the property, and reading it as failure is what makes a contended host produce red.
    Inconclusive {
        /// When the observable last changed.
        last_change: Duration,
        /// The observable when the deadline arrived.
        last: T,
    },
}

impl<T> Settled<T> {
    /// Whether the property was genuinely refuted — the only outcome a scenario should fail on.
    #[must_use]
    pub const fn is_refuted(&self) -> bool {
        matches!(self, Self::Refuted { .. })
    }

    /// Whether the predicate held.
    #[must_use]
    pub const fn is_reached(&self) -> bool {
        matches!(self, Self::Reached { .. })
    }
}

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
    /// `crate::network` uses for the deterministic tier, so a scenario reads the same in both.
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
/// what distinguishes this from `crate::fleet`, which models node state directly, and from `crate::sim`, which
/// steps engines — neither can observe wiring, and wiring is where composition faults live
/// (`docs/design-testing.md` §5.1).
///
/// Nodes bootstrap exactly as a deployment does: the first member's fabric address is handed to the rest as a
/// `Peer`, so discovery is the real path rather than a pre-populated table.
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
/// E\[distinct\] = P · (1 − (1 − 1/P)ⁿ)
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
/// | PG(2,2) | 7 | 7 | 0.0061 | **4** (one point held by three nodes; E\[distinct\] = 4.62) |
/// | PG(2,4) | 21 | 7 | 0.325 | **7**, then **6** on the next run (E\[distinct\] = 6.08) |
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
        Self::spawn_inner_fleet::<F>(count, link, roles, true, None, fanos_node::config::OverlayChoices::default()).await
    }

    /// As [`spawn`](Self::spawn), with an explicit **epoch period** — the one thing a fleet could not say.
    ///
    /// Every scenario here has run against `DEFAULT_EPOCH_PERIOD` (600 s) while lasting tens of seconds, so
    /// the whole of what an epoch drives — the coordinate reshuffle, the onion-key ratchet, per-epoch
    /// re-assignment, directory-slot expiry — has never been exercised at the multi-node tier. The node tier
    /// has always been able to say it (`cell_diagnosis.rs`, `role_roster.rs` pass `ROSTER_REFRESH * 2`); this
    /// one could not, and two `#[ignore]`d probes ask questions about later epochs they cannot reach.
    ///
    /// Additive on purpose: the existing constructors pass `None` and keep their behaviour exactly, so a
    /// scenario that changes is one that asked to.
    ///
    /// # Errors
    /// Propagates the first node-start failure.
    /// Test-only, and the declaration says so: its callers are this file's own measurement
    /// harnesses, exactly as `widest_withheld_scan` is.
    #[cfg(test)]
    pub(crate) async fn spawn_with_epoch<F: fanos_field::Field + 'static>(
        count: usize,
        link: Link,
        roles: fanos_node::RoleSet,
        epoch_period: Duration,
    ) -> Result<Self, fanos_node::NodeError> {
        Self::spawn_inner_fleet::<F>(count, link, roles, true, Some(epoch_period), fanos_node::config::OverlayChoices::default()).await
    }

    /// [`spawn_as_drawn`](Self::spawn_as_drawn) with an explicit epoch period — the collision half of
    /// [`spawn_with_epoch`](Self::spawn_with_epoch).
    ///
    /// Both halves exist because a collision scenario and an epoch-crossing scenario are different questions
    /// and a constructor that changed the draw *and* the clock would make any comparison between them
    /// uninterpretable.
    ///
    /// # Errors
    /// Propagates the first node-start failure.
    /// Test-only, and the declaration says so: its callers are this file's own measurement
    /// harnesses, exactly as `widest_withheld_scan` is.
    #[cfg(test)]
    pub(crate) async fn spawn_as_drawn_with_epoch<F: fanos_field::Field + 'static>(
        count: usize,
        link: Link,
        roles: fanos_node::RoleSet,
        epoch_period: Duration,
    ) -> Result<Self, fanos_node::NodeError> {
        Self::spawn_inner_fleet::<F>(count, link, roles, false, Some(epoch_period), fanos_node::config::OverlayChoices::default()).await
    }

    /// As [`spawn`](Self::spawn), but taking the coordinate draw **as it comes** — collisions included.
    ///
    /// The condition must be reproducible on demand, not waited for: a scenario that hopes to meet a collision measures
    /// whatever the draw happened to give, and four consecutive passes of a cell-wide test looked like success while being a
    /// 13% coincidence. This is how a collided draw is *forced*, which is what turned live coordinate resolution from
    /// "seems fine" into a measurement.
    pub async fn spawn_as_drawn<F: fanos_field::Field + 'static>(
        count: usize,
        link: Link,
        roles: fanos_node::RoleSet,
    ) -> Result<Self, fanos_node::NodeError> {
        Self::spawn_inner_fleet::<F>(count, link, roles, false, None, fanos_node::config::OverlayChoices::default()).await
    }

    /// A fleet running an **overlay configuration a deployment can choose**, so a scenario can exercise a
    /// switch rather than argue about it.
    ///
    /// The one that needed it: `require_self_certified_membership` verifies a signed descriptor, and the
    /// producer for that descriptor is the *driver* — it re-signs at every reseat, because the message binds
    /// the transport coordinate and the reshuffle re-draws it. So the sans-I/O simulator cannot reach the
    /// property at all: only a fleet, which runs the real QUIC transport and the real reshuffle loop, puts
    /// the signer and the verifier in the same run.
    ///
    /// # Errors
    /// Propagates the first node-start failure.
    #[cfg(test)]
    pub(crate) async fn spawn_with_overlay<F: fanos_field::Field + 'static>(
        count: usize,
        link: Link,
        roles: fanos_node::RoleSet,
        epoch_period: Duration,
        overlay: fanos_node::config::OverlayChoices,
    ) -> Result<Self, fanos_node::NodeError> {
        Self::spawn_inner_fleet::<F>(count, link, roles, true, Some(epoch_period), overlay).await
    }

    async fn spawn_inner_fleet<F: fanos_field::Field + 'static>(
        count: usize,
        link: Link,
        roles: fanos_node::RoleSet,
        injective: bool,
        epoch_period: Option<Duration>,
        overlay: fanos_node::config::OverlayChoices,
    ) -> Result<Self, fanos_node::NodeError> {
        let fabric = Fabric::new(link);
        // **The shares are dealt and kept.** They used to be `_shares`, and that one underscore cost this tier every
        // epoch-driven behaviour it has: `share = Some(..)` is what makes a node an *anchor* that contributes partials,
        // `None` a pure consumer. Every fleet node was a consumer of a group whose anchors did not exist, so no
        // threshold round could ever assemble, `BeaconReady` never fired, and the epoch stood at genesis for the life of
        // every scenario — measured as `live beacons [None, None, None]` after twelve periods at a 2.1 s epoch.
        //
        // Two consequences worth stating because both were recorded as facts about the protocol: no fleet node ever
        // reaches `Station::SeatCommitted`, so settle-on-join was silently at full strength in every collision
        // measurement; and the experiment that varied `epoch_period` and found no effect was comparing two arms that
        // both stood still. The sibling fixture one directory over (`tests/common/mod.rs`) always dealt them properly.
        let (shares, commitment) = fanos_vrf::vss::deal(
            &[0xF1; 32],
            2,
            3,
            &mut fanos_vrf::vss::DeterministicRng::new(b"fabric-fleet"),
        )
        .ok_or(fanos_node::NodeError::Identity)?;
        let mut nodes: Vec<fanos_node::Node> = Vec::with_capacity(count);
        let mut addrs = Vec::with_capacity(count);
        // An injective draw, retried until achieved — and the reason has CHANGED, which is why it is spelled out.
        //
        // It used to exist because a collided node stayed unroutable forever, making every cell-wide assertion a coin flip
        // on the draw (40.2% collide at 5 nodes on `PG(2,4)`'s 21 points). That is fixed: live resolution now moves a
        // contested node along its probe walk and it announces the point it reached, measured at 7/7 distinct across four
        // forced-collision trials with nodes visibly seated at probe index 1 and 4 (`fanos_quic::claims`).
        //
        // What it guards now is **roster** convergence after a move, one layer above placement. Two links of that chain are
        // fixed and each measurably helped, with collisions allowed:
        //
        //   1 pass in 3   → live resolution moves the node (`29e322b`)
        //   6 of 8        → the mover re-announces, peers re-key the live connection (`b17e5bb`)
        //   4 of 6        → the mover republishes its capability/load descriptors at the point it moved TO
        //
        //   3 of 4        → a peer that learns of a move re-arms its roster refresh at the floor
        //
        // The residual is now precise, and it is a reachability limit rather than a missing signal: `PeerMoved` only reaches
        // nodes holding a **live connection** to the mover. A node that never met it gets no signal and stays in whatever
        // backoff it had relaxed to — up to `ROSTER_REFRESH_MAX` — so it learns only from its own directory scan. That is why
        // the last failure reads `Refuted { frozen_for: 30s, last: [5, 3, 5, 4, 4] }`: two readers correct, three still on a
        // long cadence, and genuinely no change across two discovery periods. Closing it needs the mover to be discoverable
        // by nodes it has no connection to — the store-published descriptor is now correct, so what remains is the scan
        // cadence. Remove this guard when the cell-wide scenario passes with collisions allowed.
        let mut taken: HashSet<fanos_geometry::Triple> = HashSet::new();
        let mut attempts = 0usize;
        while nodes.len() < count {
            attempts += 1;
            // **The plane's size bounds an INJECTIVE draw, not a fleet.** `count > N` cannot be satisfied
            // when every node must land on a point of its own, so refusing early is right there — a retry
            // loop that cannot terminate is worse than an error. `spawn_as_drawn` makes no such promise:
            // taking the draw as it comes is the whole point of it, and a fleet larger than the plane is
            // exactly the regime the design answers with sub-cell descent. Guarding both alike made the one
            // load factor that matters unmeasurable — the plane is covered at `n/N ≈ 1.5`
            // (`measure_how_many_nodes_a_plane_needs_before_its_lines_work`), and every attempt to reach it
            // came back `NodeError::Identity` from a condition about a draw it was not using.
            if attempts > 64 * count.max(1)
                || (injective && count > fanos_geometry::Plane::<F>::N as usize)
            {
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
                    beacon: Some(fanos_node::BeaconParams {
                        network_id: fanos_node::NetworkId::from_seed(b"test-network"),
                        commitment: commitment.clone(),
                        threshold: 2,
                        // The dealing is three wide against a threshold of two, so the first three nodes are the
                        // cell's anchors and the rest are consumers — the production shape, where anchoring is a
                        // subset rather than the whole cell. A one-node fleet therefore still stands at genesis, and
                        // honestly so: two partials cannot come from one anchor.
                        share: shares.get(nodes.len()).cloned(),
                        authority: None,
                    }),
                    roles,
                    // A fleet that never crosses an epoch cannot exercise anything an epoch drives, and the
                    // production default is 600 s against scenarios that run for tens. `None` keeps exactly
                    // today's behaviour; a caller that needs a boundary asks for one, the way the node-tier
                    // tests already do (`cell_diagnosis.rs`, `role_roster.rs`: `ROSTER_REFRESH * 2`).
                    epoch_period: epoch_period.unwrap_or(fanos_node::config::DEFAULT_EPOCH_PERIOD),
                    // Derived from the role rather than taken as a parameter, because without them
                    // `exit_params` refuses the node outright: offering `exit` to this fleet used to be a
                    // *start error*, so no scenario could ever exercise the one role whose capacity is
                    // derived AND whose activity is advertised. A per-node seed, since the seed regenerates
                    // the exit's DIAULOS service key and one key at several coordinates is a different
                    // fixture from the one any caller means. Empty ports = any, which is what a scenario
                    // that never relays wants.
                    exit: roles.exit.then(|| fanos_node::ExitParams {
                        seed: [u8::try_from(nodes.len()).unwrap_or(0xE0); 32],
                        allowed_ports: Vec::new(),
                    }),
                    bootstrap,
                    // OBSERVED, not provisioned: this list is the coordinates the running nodes are
                    // actually at, read from their own `health()`. When the draw collides — which is the
                    // whole subject of `spawn_as_drawn` and of the two measurements that use it — the list
                    // repeats a coordinate, and treating that as an operator's typo made both of them
                    // impossible to run at all (#186).
                    bootstrap_source: fanos_node::config::SeatSource::Observed,
                    overlay,
                    ..fanos_node::NodeConfig::default()
                },
                fanos_quic::Fabric::Abstract(socket),
            )
            .await?;
            if injective && !taken.insert(node.health().address) {
                node.shutdown().await; // collided draw: retry with fresh credentials
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

    /// Every member's non-zero driver stations, as one line per node — for a failure message.
    ///
    /// **A counter, deliberately, rather than a log.** Chasing #250 I ran the failing test under
    /// `RUST_LOG=fanos_quic=debug` and read three zeroes as "those events did not happen". This crate has
    /// no `tracing` dependency at all and installs no subscriber, so the zeroes were the *absence of a
    /// sink*, not the absence of events — and two conclusions had already been drawn on them. A station is
    /// data the test reads directly: no subscriber, no `RUST_LOG`, no `--nocapture`, and "nothing was
    /// discarded" becomes an observation instead of an empty buffer.
    ///
    /// Empty output therefore means exactly one thing: every node discarded nothing that carries a
    /// station. If a frame is going missing, it is going missing somewhere that does not count — which is
    /// itself the finding, and the reason this renders *all* nodes rather than a total.
    #[must_use]
    pub fn stations(&self) -> String {
        let mut out = String::new();
        for (i, node) in self.nodes.iter().enumerate() {
            let seen = node.client().driver_stations();
            let _ = write!(out, "\n  node {i}: ");
            if seen.is_empty() {
                out.push_str("(nothing discarded)");
                continue;
            }
            for o in seen {
                // **`line` and `tag`, not just the count — they are part of the key, not decoration.**
                // The counter map is `(station, line, tag) → count`, so two observations of one station
                // that differ only in line or tag are distinct rows; printing `name=count` collapsed them
                // into indistinguishable pairs. Measured cost: four `conns.surplus_read` entries on one node
                // are four *peers*, and this report could not say which — while
                // `Station::ConnSurplusRead` exists precisely to separate "sending into a corpse is a
                // bounded transient" from "the list is a graveyard whose head is permanently dead", and it
                // separates them **by tag** ("how many entries that read removed"). The discriminator was
                // collected and dropped one line before it was printed.
                //
                // Raw values rather than `admin.rs`'s resolved `tag N (name)` form: that surface serves an
                // operator and owns a vocabulary; this one serves a failure message, where the number is
                // what a reader correlates across nodes.
                let line = o.line.map_or_else(String::new, |[x, y, z]| format!("@{x}:{y}:{z}"));
                let tag = o.tag.map_or_else(String::new, |t| format!("#{t}"));
                let _ = write!(out, "{}{line}{tag}={} ", o.station.name(), o.count);
            }
        }
        out
    }

    /// The **engine's** data-path plane, one line per node — the counterpart to [`stations`], which reads the
    /// driver's map.
    ///
    /// **Two planes, and a failure message that prints one of them can mistake a blind spot for evidence.**
    /// The driver's counters see frames: a send that found no rung (`directory.entry_fallback`), a
    /// connection reused or pruned. The engine's see decisions: a read that did not conclude and *why*
    /// (`read.inconclusive`, tagged with a `ReadStall`), a gather that expired, a share that arrived late.
    /// A read that never reaches the store and a read that reaches it and starves look identical on the
    /// transport plane and are opposite on this one.
    ///
    /// Paid for once, honestly: this **asks** each node (`Command::Observe`) and awaits its answer, where
    /// `stations` reads a map already in hand. It is a diagnosis, not a sample, so it belongs in a failure
    /// message rather than in a loop.
    /// `#[cfg(test)]`, and that is the honest description rather than a concession. Every caller is a test
    /// scenario in this file; a `pub` diagnostic with no reader outside the crate is exactly the shape
    /// `no_new_public_capability_arrives_unwired` exists to catch, and a `pub(crate)` one with no
    /// non-test reader is the same claim one step quieter. Promote it the day a shipping binary asks a node
    /// for its engine plane — `bin/demo.rs` and `bin/experiment.rs` print neither plane today.
    #[cfg(test)]
    async fn engine_stations(&self) -> String {
        let mut out = String::new();
        for (i, node) in self.nodes.iter().enumerate() {
            let mut events = node.client().subscribe();
            let _ = write!(out, "\n  node {i}: ");
            if !node.client().command(fanos_runtime::Command::Observe) {
                out.push_str("(engine did not accept Observe)");
                continue;
            }
            // This crate's own deadline rather than the testkit's backstop — the same 240 s, derived from the
            // same measurement, and `engine_stations` is library code that a dev-dependency cannot reach.
            let seen = tokio::time::timeout(SETTLE_DEADLINE, async {
                loop {
                    match events.recv().await {
                        Ok(fanos_runtime::Notification::DataPath { stations, .. }) => {
                            return Some(stations);
                        }
                        Ok(_) => {}
                        Err(_) => return None,
                    }
                }
            })
            .await;
            match seen.ok().flatten() {
                None => out.push_str("(no answer)"),
                Some(obs) if obs.is_empty() => out.push_str("(nothing recorded)"),
                Some(obs) => {
                    for o in obs {
                        // Same key as `stations` renders — `(station, line, tag)` — for the same reason: two
                        // rows differing only in tag are different findings, and `read.inconclusive` carries
                        // its `ReadStall` reason *in* the tag.
                        let line = o.line.map_or_else(String::new, |[x, y, z]| format!("@{x}:{y}:{z}"));
                        let tag = o.tag.map_or_else(String::new, |t| format!("#{t}"));
                        let _ = write!(out, "{}{line}{tag}={} ", o.station.name(), o.count);
                    }
                }
            }
        }
        out
    }

    /// **The widest directory scan any member has withheld at** — a second term in a settling trajectory,
    /// carried for what it *tells you when the trajectory freezes* (#159).
    ///
    /// [`Station::AssignmentWithheld`](fanos_runtime::ports::stations::Station::AssignmentWithheld) documents
    /// that `Observation::tag` carries the roster size the scan produced (#199), so the maximum rises while
    /// members are still appearing and stands still when a cell cannot improve its read. The *count* would
    /// have been the wrong quantity: it rises for a fleet that is merely spinning, and a permanently broken
    /// composition would then report `Inconclusive` instead of `Refuted` — which every call site treats as a
    /// pass. Adding it would have made those assertions unable to fail for the failure they exist to catch.
    ///
    /// **It is here as an instrument, not as a repair, and the distinction is the finding.** The hypothesis
    /// it was written for — that the roster vector freezes in the gap between discovery finishing and the
    /// first assignment, and `withhold` fills that gap silently — is REFUTED by what it printed:
    /// `Refuted { frozen_for: 30s, last: ([3, 4, 2, 4, 4], 0) }`. The rosters never completed, and the
    /// maximum is `0`, so `withhold` was never reached at all. The stall is upstream of the assignment
    /// decision, in discovery or publication, and the same fleet size and plane converge under
    /// [`Link::ideal`] — the failing case differs only by 20 ms of latency and 10 ms of jitter, with no loss
    /// on either. That is a real convergence defect, not a trajectory artefact, and it belongs to the frozen
    /// roster already tracked separately.
    ///
    /// Across members, not per node: one member still scanning while the others are settled is the cell
    /// working, and a per-node reading would let its progress hide behind four still ones.
    ///
    /// `#[cfg(test)]`, and the two rejected alternatives are worth naming. As `pub` it entered fanos-sim's
    /// public census as a capability no production code calls — the shape #227's guard exists to catch, and
    /// which it caught here on its next full run. As `pub(crate)` it was dead code in the non-test build,
    /// which is the compiler saying the same thing more precisely: every caller is a predicate in this
    /// file's own test module, so this is a test instrument and the declaration should say so.
    #[cfg(test)]
    #[must_use]
    fn widest_withheld_scan(&self) -> u64 {
        self.nodes
            .iter()
            .flat_map(|n| n.client().driver_stations())
            .filter(|o| o.station == fanos_runtime::ports::stations::Station::AssignmentWithheld)
            .filter_map(|o| o.tag)
            .max()
            .unwrap_or(0)
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

    /// Poll until `predicate` holds, distinguishing **refuted** from **not measured**.
    ///
    /// [`until`](Self::until) answers `bool`, which conflates two different outcomes: the system reached a fixed point
    /// that fails the property, and the deadline arrived while the system was still moving. On a contended machine the
    /// second is common, and reading it as the first is how a wall-clock suite converts contention into a false red —
    /// which this session paid for three times over, including one "confirmed decisively" that the baseline refuted.
    ///
    /// The discriminator is the **trajectory**, not the machine: `observe` is sampled alongside the predicate, and
    ///
    /// * the predicate holding ⇒ [`Settled::Reached`];
    /// * `observe` unchanged for [`FROZEN_SPAN`] with the predicate still false ⇒ [`Settled::Refuted`]. Nothing further
    ///   is coming at the timescale the system converges on, so the property is genuinely false;
    /// * the deadline arriving while `observe` is still changing ⇒ [`Settled::Inconclusive`]. Neither shown nor refuted.
    ///
    /// Deliberately *not* keyed on load average or elapsed time: those would be heuristics about the host, while whether
    /// a system has stopped moving is a property of the observation itself.
    pub async fn until_settled<T, O>(
        &self,
        predicate: impl FnMut(&Self) -> bool,
        observe: O,
    ) -> Settled<T>
    where
        O: FnMut(&Self) -> T,
        T: PartialEq + core::fmt::Debug,
    {
        self.until_settled_within(SETTLE_DEADLINE, predicate, observe).await
    }

    /// As [`until_settled`](Self::until_settled), with an explicit patience budget.
    ///
    /// Worth exposing rather than fixing internally: [`Settled::Inconclusive`] can only be reached by *exhausting* the
    /// deadline, so a scenario checking that branch pays it in full. The default is sized for a loaded host running seven
    /// composed nodes; a scenario that knows its own timescale should say so.
    ///
    /// `deadline` must exceed [`FROZEN_SPAN`] for [`Settled::Refuted`] to be reachable at all — below it, a genuinely
    /// frozen failure reports as `Inconclusive`, which is conservative but uninformative.
    pub async fn until_settled_within<T, O>(
        &self,
        deadline: Duration,
        mut predicate: impl FnMut(&Self) -> bool,
        mut observe: O,
    ) -> Settled<T>
    where
        O: FnMut(&Self) -> T,
        T: PartialEq + core::fmt::Debug,
    {
        // The polling granularity of this wait. Not a deadline — the deadline is the caller's — but the
        // resolution at which it is checked, so it only has to be fine enough that `FROZEN_SPAN` spans
        // several samples (the quiet-run count below divides by it). 100 ms gives tens of samples across
        // any span this harness uses, at a cost of ten wakeups a second on an idle wait.
        const STEP: Duration = Duration::from_millis(100);
        let polls = (deadline.as_millis() / STEP.as_millis().max(1)).max(1) as u32;
        // How many unchanged samples span `FROZEN_SPAN`; at least one, whatever the step.
        let quiet_needed = (FROZEN_SPAN.as_millis() / STEP.as_millis().max(1)).max(1) as u32;
        let mut last = observe(self);
        let mut quiet = 0u32;
        let mut elapsed = Duration::ZERO;
        let mut last_change = Duration::ZERO;
        for _ in 0..polls {
            if predicate(self) {
                return Settled::Reached { after: elapsed };
            }
            let now = observe(self);
            if now == last {
                quiet += 1;
                if quiet >= quiet_needed {
                    return Settled::Refuted { frozen_for: STEP * quiet, last: now };
                }
            } else {
                quiet = 0;
                last_change = elapsed;
                last = now;
            }
            tokio::time::sleep(STEP).await;
            elapsed += STEP;
        }
        Settled::Inconclusive { last_change, last }
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

    /// Stop every member — **awaiting each one's durable stop** (#178).
    ///
    /// Async because `Node::shutdown` is: a clean stop persists the store before closing the endpoint, and a
    /// fabric that dropped those futures would tear its cell down without writing, which is exactly the
    /// pre-#178 behaviour one layer up.
    pub async fn shutdown(self) {
        for node in self.nodes {
            node.shutdown().await;
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
            // The same derivation the deployed node runs, over the same default roles — the simulator differs
            // from production in the transport and only the transport, and an announced capability set is not
            // transport (#284).
            fanos_node::config::RoleSet::default().advertised_capabilities(2),
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
                beacon: Some(fanos_node::BeaconParams { network_id: fanos_node::NetworkId::from_seed(b"test-network"), commitment, threshold: 2, share: None, authority: None }),
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
        node.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
        // Three-valued, not `until` — this call site is why. Under the whole `--lib` binary it exhausted the
        // 240 s budget and reported `false`, which reads as "the composition does not assign" and is what a
        // red gate then accuses the last commit of. Run alone on the same loaded host it settles in 68 s. The
        // discriminator is the trajectory: while any member is still completing its composition the count
        // moves, and a fleet that has stopped moving for `FROZEN_SPAN` with members unassigned has genuinely
        // failed. `Inconclusive` is then a measurement that did not finish, which is the honest verdict for a
        // contended host and the one `until` cannot express.
        // The observable is the ROSTER VECTOR, not the assigned count, and the difference is not cosmetic:
        // the count changes at most five times in the whole run, so between two of those steps it is
        // indistinguishable from a frozen fleet and `FROZEN_SPAN` expires against a system that is still
        // working. Measured — with the count it reported `Refuted { frozen_for: 30s, last: 4 }` on a fleet
        // that reaches 5/5. A trajectory has to move while the thing being waited on is still happening, and
        // the roster does: it grows with every peer each member learns, which is the very scan the
        // composition is blocked on. Same observable the two fleet assertions below already use.
        let assigned = fleet
            .until_settled(
                |f| f.nodes().iter().all(|n| n.assigned_roles().any()),
                // Roster AND withheld count. The roster alone stops moving when discovery finishes, which is
                // BEFORE the first assignment; the gap is filled by `withhold`, which sends nothing and so
                // freezes every other observable for exactly `FROZEN_SPAN` (#159).
                |f| (f.nodes().iter().map(|n| n.assignment().roster).collect::<Vec<_>>(), f.widest_withheld_scan()),
            )
            .await;
        // Both planes, and the second one is what a reader of this message could not reconstruct. The
        // driver's counters say whether a frame found a rung; only the engine's say whether a *read* reached
        // the store and how it ended — and an assignment that never arrives is a scan that did not conclude,
        // which is a read fact end to end. Asked before the assertion because it awaits each node.
        let engine = fleet.engine_stations().await;
        assert!(
            !assigned.is_refuted(),
            "every member's composition must produce an assignment over the carrier: {assigned:?}\
             \nassignment epochs: {:?}\nlive beacons: {:?}\nknown peers: {:?}\ndriver plane:{}\n\
             engine plane:{engine}",
            fleet.nodes().iter().map(|n| n.assignment().epoch.get()).collect::<Vec<_>>(),
            fleet.nodes().iter().map(|n| n.live_beacon().map(|(e, _)| e.get())).collect::<Vec<_>>(),
            fleet.nodes().iter().map(|n| n.health().known_peers).collect::<Vec<_>>(),
            fleet.stations()
        );
        // Every member offered rendezvous, so the cell should be serving it — the property NOSTOS hosting coverage
        // depends on, now observable end to end rather than asserted of a controller in isolation.
        assert!(
            fleet.nodes().iter().any(|n| n.serves(Role::Rendezvous)),
            "the cell provisioned the anonymous rendezvous role"
        );
        assert!(fleet.fabric.delivered() > 0, "the fleet's traffic crossed the modelled carrier");
        fleet.shutdown().await;
    }

    /// **A tripwire on the assignment that actuates nothing.**
    ///
    /// `docs/design-self-organization.md` §5 puts "which roles it *offers*" on the node's side of the table
    /// and "which offered roles are **active**" on the network's. The tree does not do the second: every role
    /// behaviour is started once, at boot, from `config.roles`, and no shipping branch reads the assignment —
    /// see `SelfOrganization::assigned`'s doc, which used to claim the opposite.
    ///
    /// **Exit is the only role where that is observable, and the reasons the other two are not are worth
    /// keeping.** The hazard needs a role with a *derived* capacity, so the assignment can be a strict subset
    /// of the offer, AND a wired activity advertisement to watch. Relay has the advertisement (its mix key)
    /// but the placeholder capacity, so it saturates and assignment equals offer. Rendezvous has the derived
    /// capacity but no advertisement — `spawn_rendezvous_host` is not called from `Node::start` at all. Exit
    /// has both: `diaulos::MAX_SESSIONS` as its denominator and `spawn_exit_publisher` as its record.
    ///
    /// So on an idle cell the setpoint is `⌈0 / MAX_SESSIONS⌉ = 0`, the demand falls to the observability
    /// floor of one, and exactly one member is assigned Exit — while **all five publish an exit descriptor**,
    /// because `exit_params` consults `config.roles.exit`, the offer, and nothing consults the assignment.
    ///
    /// ⚠️ **AND IT CANNOT CERTIFY THAT, which was found by landing the actuation and watching this stay
    /// green.** The witness is `advertised && !serves(Exit)` read at one instant, and those two quantities
    /// live on different clocks: a descriptor is written per **epoch** and stands for it, while the role
    /// loop re-assigns on the much shorter `ROSTER_REFRESH` cadence. A node that published while assigned
    /// and lost the role thirty seconds later is a witness by this definition and a *correct* publisher by
    /// the design's — "withholding a record drains a node gracefully" says the record outlives the
    /// assignment that produced it, on purpose.
    ///
    /// So the condition is satisfiable by ordinary churn, and green here means "not proven either way"
    /// rather than "no actuation". The sharper observable is a node that was **never** assigned Exit and
    /// advertises anyway — which needs the assignment sampled *at publication time*, not at read time.
    ///
    /// ⛔ **RETIRED AS AN ASSERTION 2026-08-16, in both directions, and the reason is not that it stopped
    /// mattering.** With the actuation landed (`ff9a361`) neither colour proves anything here. Red is
    /// reachable from load alone — the claim is *existential*, so a busy host on which fewer nodes publish
    /// at all removes the witnesses and fails a healthy cell; measured, it failed once inside a full-suite
    /// run and passed three times standalone minutes later. Green is reachable from the clock mismatch
    /// above. A test that can go either way for reasons unrelated to its subject is a measurement, and it is
    /// one now.
    ///
    /// **The question moved to an instrument that can answer it**:
    /// `measure_whether_the_cell_withholds_an_unassigned_exit_advertisement` records the *withholding* at
    /// publication time — `exit.advertisement_withheld`, tagged for "decided, not assigned" against
    /// "decision is for an earlier epoch" — which has no clock gap because nothing is compared afterwards.
    ///
    /// **The original text, kept because it is the derivation:** when this test fails, actuation has landed.
    /// That is the point of it: read
    /// `SelfOrganization::assigned` for the shape that was proposed (withhold the *advertisement*, do not stop
    /// the task) and check the two things that gap touches — the viability floor, and a node's mix key
    /// outliving its assignment. (A third was listed here, `Escalation::Deficit`. It is **not** to be built:
    /// five of the six roles are addressed by geometry rather than by a directory, so there is no
    /// advertisement a parent could lower, and recruiting across cells would hand a parent the placement aim
    /// §L3 exists to deny. `docs/design-self-organization.md` §4 carries the derivation.)
    ///
    /// **Measured before shipping, three consecutive runs: two measured the witness (2.8 s, 31.1 s), one
    /// skipped on the saturated precondition (4 published, 4 assigned), none red.** The variance is the
    /// fixture's, not the assertion's — see the note at the precondition — so the outcomes are exactly two:
    /// *measured* and *not measured*, never a false red. A tripwire that fires on two runs in three is enough
    /// to be noticed on the day it starts firing, which is all this is for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement — run with --ignored --nocapture; see the note on why it is no longer an assertion"]
    async fn measure_whether_an_exit_advertises_a_role_the_cell_did_not_assign() {
        use fanos_field::F2;
        use fanos_core::roles::Role;
        use fanos_node::{RoleSet, resolve_exit_key};
        use fanos_primitives::Epoch;

        const N: usize = 5;
        // **The plane is F2 because the exit floor is now `fault_budget(N) + 1`.** This probe needs the
        // assignment to be a strict subset of the offer, and on `F4` that floor is `fault_budget(21) + 1 = 7`
        // against five offering nodes — saturated, so the probe would skip for ever. On `F2` it is
        // `fault_budget(7) + 1 = 3`, leaving two of five withholding with the plane still slack (7 points,
        // 5 nodes), which is the same regime this fixture was written in.
        let roles = RoleSet { relay: true, exit: true, ..RoleSet::default() };
        let fleet = NodeFleet::spawn::<F2>(N, Link::default(), roles).await.expect("a fleet starts");
        // `until_settled`, not `until`, and the difference is the whole reason the first version of this
        // test went red on a quiet machine: a `bool` conflates "the fleet reached a fixed point that fails
        // the predicate" with "the deadline arrived while it was still converging". Measured here — one run
        // settled in 3.4 s and the next was still moving at 240 s — because `spawn` allows coordinate
        // collisions, so how long the draw takes is not a property this test is about. Refuted is red;
        // inconclusive means the question below cannot be asked, and is reported rather than asserted away.
        let settled = fleet
            .until_settled(
                |f| f.nodes().iter().all(|n| n.assigned_roles().any()),
                |f| {
                    (
                        f.nodes().iter().map(|n| n.assignment().roster).collect::<Vec<_>>(),
                        f.widest_withheld_scan(),
                    )
                },
            )
            .await;
        // **Anything but `Reached` is "not measured", INCLUDING `Refuted` — and that is a correction.**
        // This test first asserted `!is_refuted()`, copying the neighbouring scenario, and I shipped it after
        // three runs that never showed the difference. Running it more turned up
        // `Refuted { frozen_for: 30s, last: ([3, 3, 3, 4, 4], 0) }`: the fleet reached a fixed point with a
        // member holding no role, and the rosters never completed. That is a real property of the fixture —
        // measured across an epoch turn, on a lossless link, with and without the exit role — but it is *not
        // this test's subject*, and asserting it here turns a convergence failure into a red about actuation.
        // The neighbour is entitled to assert it, because convergence IS its subject. Recorded separately.
        //
        // Not a quiet pass either: a run that skips its own subject and reports `ok` cannot be told from one
        // that checked, so the outcome is printed with the verdict that produced it.
        if !matches!(settled, Settled::Reached { .. }) {
            // The stations too, not only the verdict: the verdict says *what* did not settle (the rosters),
            // and the counters say *why* — which is the half a reader cannot reconstruct afterwards, because
            // the fleet is about to be shut down.
            eprintln!(
                "SKIPPED {}: the fleet had not settled — {settled:?}\ndriver plane:{}\nengine plane:{}",
                module_path!(),
                fleet.stations(),
                // The half the sentence above promises and the driver's map cannot give: "why" for a fleet
                // that did not settle is almost always a read that did not conclude, and that station lives
                // only on the engine's plane.
                fleet.engine_stations().await
            );
            fleet.shutdown().await;
            return;
        }

        // Read from one member's view, because that is the view a client gets: the descriptors have to have
        // travelled, not merely been written locally.
        let Some(reader) = fleet.nodes().first() else {
            unreachable!("a fleet that started has members")
        };
        let client = reader.client();
        let genesis = client.genesis();
        // Ask about the coordinates the fleet actually occupies, not the whole plane.
        // `build_cell_exit_directory` sweeps all `Plane::<F2>::N = 7` points and each miss waits out
        // `resolve::STORE_TIMEOUT` (5 s), so one sweep of a five-node fleet costs up to eighty seconds —
        // polling it in a loop is what made the first version of this test exceed a 500 s timeout without
        // ever reaching an assertion. Five targeted reads, all of which should hit, cost nothing by
        // comparison, and they assert *which* nodes published rather than a count that could be made up by
        // any five slots.
        // Per node, aligned with `fleet.nodes()`: did it publish, and was it assigned?
        //
        // **The claim is existential and the first version asserted it universally**, which is what made that
        // version fragile against something it is not about: coordinates move (`directory.moved_peer_retained`
        // in the stations below), the exit publisher writes at the node's *live* coordinate, and a node that
        // moved between publishing and this read has its descriptor at the point it left. Measured: 4 of 5
        // resolved. "Some node advertises a role the cell did not assign it" needs one witness, not five.
        let mut advertised = vec![false; fleet.nodes().len()];
        for _ in 0..5 {
            for (i, node) in fleet.nodes().iter().enumerate() {
                if advertised.get(i).copied() == Some(true) {
                    continue;
                }
                let coord = node.health().address; // re-read each round: the coordinate is what moves
                if resolve_exit_key::<F2>(&client, coord, Epoch::ZERO, Some(genesis)).await.is_some()
                    && let Some(slot) = advertised.get_mut(i)
                {
                    *slot = true;
                }
            }
            if advertised.iter().all(|&a| a) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let serving: Vec<bool> = fleet.nodes().iter().map(|n| n.serves(Role::Exit)).collect();
        let witnesses = advertised.iter().zip(&serving).filter(|&(&a, &s)| a && !s).count();
        let published = advertised.iter().filter(|&&a| a).count();
        let assigned = serving.iter().filter(|&&s| s).count();
        let stations = fleet.stations();
        fleet.shutdown().await;

        // Setup first, so a witness cannot be manufactured by a scan that found nothing: something must have
        // been published, and the controller must have assigned the role to somebody.
        assert!(
            published >= 1,
            "no member's exit descriptor resolved at all, so nothing here is about the assignment.{stations}"
        );
        assert!(
            assigned >= 1,
            "the viability floor asks for one exit even on an idle cell ({N} offer it), so the controller \
             must assign at least one — {assigned} were assigned, i.e. the setpoint path is not running"
        );
        // **The precondition, and it does not always hold.** Measured across runs of this very test: with
        // every member's Exit slot *sensed* the cell total is zero, the setpoint is zero, the viability floor
        // asks for one, and one of five is assigned — a strict subset. With it *unsensed* the node publishes
        // `capacity` instead (`RoleReading::to_load`: an offered-but-unsensed role presumes itself at
        // capacity), the total is `5 × capacity`, the setpoint comes back as exactly five, and every member is
        // assigned. Both were observed, in runs seconds apart, and **why the sensed/unsensed state differs is
        // not yet explained** — `spawn_exit_role` opens the gauge synchronously and before the load publisher
        // exists, so the obvious ordering answer is wrong.
        //
        // Until that is understood, saturation is *not measured* rather than a failure: the question below is
        // about a strict subset and cannot be asked of a saturated cell. Said out loud for the same reason the
        // settle is.
        if assigned >= published {
            eprintln!(
                "SKIPPED {}: the cell assigned Exit to every publisher ({published} published, \
                 {assigned} assigned) — no strict subset, so the question does not arise.{stations}",
                module_path!()
            );
            return;
        }
        // The finding. When this fails, actuation has landed — read `SelfOrganization::assigned`.
        assert!(
            witnesses >= 1,
            "every member that published an exit descriptor was also assigned the Exit role \
             ({published} published, {assigned} assigned, {witnesses} advertise unassigned). Either the \
             assignment now gates the advertisement — in which case this tripwire has done its job, see \
             `SelfOrganization::assigned` for what else that touches — or Exit's capacity or floor moved and \
             this cell no longer produces a strict subset."
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
        fleet.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
        fleet.shutdown().await;

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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

        // **A liveness assertion, so it declines rather than guesses** — and the price of not doing so is
        // measured rather than argued. This test waits on convergence against `FROZEN_SPAN`, which is exactly
        // what `require_quiet_host` exists for ("counts arrivals or waits on a deadline"). On 2026-08-15 it
        // came back `Refuted { last: [5, 4, 3, 5, 4] }` inside a whole-workspace run that took 6 h 56 min
        // against a recorded baseline of 3 h 14 min — a box under 2.14× contention. Bisected 3 runs per arm,
        // it failed 1-in-3 identically at HEAD and HEAD~1: flaky, not a regression. Diagnosing that cost a
        // bisect and several hours of wrong hypotheses, all of which one INCONCLUSIVE line would have
        // replaced. The comment above already rejects the two alternatives — a window sized for a contended
        // host makes every run pay for the worst case, and one sized for an idle host is a false red.
        //
        // Applied here and NOT swept across this file, following `self_certifying.rs`'s practice of guarding
        // one test of three and saying why: the fleet's other assertions are structural (an isolated node
        // reports solitary, a crash localizes) and a starved box cannot make those wrongly pass, so guarding
        // them would weaken a test for no reason. The sibling fleet-convergence tests qualify by the same
        // criterion and have no evidence of flaking yet; they are candidates, not oversights.
        fanos_testkit::require_quiet_host("whether every node resolves every occupied coordinate");
        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        let fleet = NodeFleet::spawn::<F4>(N, Link::ideal(), roles).await.expect("fleet starts");
        // Let the PLACEMENT settle before counting occupied points. This used to sample immediately after spawn, which was
        // correct only while a collided node stayed put: now that live resolution moves it along its probe walk
        // (`fanos_quic::claims`), an early sample counts the *pre-resolution* draw and asserts rosters against a target the
        // cell is in the middle of leaving behind. Measured as `Refuted { last: [2, 4, 3, 4, 4] }` against `occupied = 4`
        // while the cell was converging on 5.
        let placed = fleet
            .until_settled(
                |f| {
                    let held: HashSet<_> = f.nodes().iter().map(|n| n.health().address).collect();
                    held.len() == f.nodes().len()
                },
                |f| f.nodes().iter().map(|n| n.health().address).collect::<Vec<_>>(),
            )
            .await;
        let coords: HashSet<fanos_geometry::Triple> =
            fleet.nodes().iter().map(|node| node.health().address).collect();
        let occupied = coords.len();
        assert!(
            !placed.is_refuted() || occupied > 1,
            "the draw must leave more than one point occupied once placement settles: {placed:?}"
        );
        // Convergence is *polled* rather than measured inside a fixed window: a window long enough to survive machine
        // contention makes every run pay for the worst case, and one sized for an idle machine is a false red — the same
        // mistake §5.3.4 removed from the real-socket suites. Settling is then checked over a short window afterwards.
        // Three-valued, so a contended host cannot turn "still converging" into "does not converge". The observable is the
        // roster vector: while any node is still learning peers it changes, and a cell that has stopped learning for
        // `FROZEN_SPAN` has genuinely stopped.
        let verdict = fleet
            .until_settled(
                |f| f.nodes().iter().all(|n| n.assignment().roster == occupied),
                |f| f.nodes().iter().map(|n| n.assignment().roster).collect::<Vec<_>>(),
            )
            .await;
        // **A joint trajectory, because a final snapshot cannot answer the question the readings raised.**
        // Across four reproductions `deliver` came out `[5,5,5,5,5]` beside rosters of `[5,3,3,3,5]` twice —
        // full reach, short roster — and once exactly equal to the roster, `[4,4,5,5,3]`. Two readings, two
        // stories. But `deliver` is sampled at diagnosis time while the roster is the last value the loop
        // *computed*, so the difference may be nothing but recovery: reach lost while the roster was derived
        // and regained before anyone looked. Sampling both on one clock is what separates "reach was never
        // the problem" from "reach came back and nothing re-derived".
        let trace = fleet
            .observe(8, Duration::from_secs(2), |n| (n.assignment(), n.health().deliverable_points))
            .await;
        let reach = trace.map(|(_, d)| *d);
        // **The epoch each roster was computed FOR, because a capability slot is keyed by it.**
        // `cap_slot(coord, epoch)` hashes the epoch into the key, so a node reading epoch `E` cannot see a
        // record its neighbour published at `E-1` — the slot is a different one, and the read succeeds by
        // finding nothing. That failure mode raises nothing: the scan concluded, `Coverage::unresolved` is
        // zero, `complete` is *true*, and the loop climbs its stability ladder and goes quiet while holding a
        // roster short of the cell. Measured on 2026-08-17: two nodes reporting `complete` with a roster of 3
        // against 5 occupied coordinates and reach to all 5 — a short roster that no station and no flag
        // contradicts. Without this column the two causes of a short roster are indistinguishable, and only
        // one of them is a read problem.
        let epoch = trace.map(|(a, _)| a.epoch.get());
        // **Read the reach metrics BEFORE the shutdown, so an intermittent failure diagnoses itself.**
        // This assertion fires rarely and its message used to carry the roster vector alone — which says the
        // cell froze short without saying whether the missing members were *unreachable* or merely
        // *unpublished*. Those want opposite repairs, and five earlier readings could not separate them
        // because the two metrics available were wrong in opposite directions: `peers` counts the dial book
        // including unconfirmed seeds, `route` counts proven bindings only and is blind to a peer that
        // dialled **in**. `deliver` is the union that answers it (`Health::deliverable_points`).
        //
        // Captured unconditionally rather than inside the failure arm: `shutdown` consumes the fleet, so by
        // the time the assertion runs there is nothing left to ask.
        let deliver: Vec<usize> = fleet.nodes().iter().map(|n| n.health().deliverable_points).collect();
        let route: Vec<usize> = fleet.nodes().iter().map(|n| n.health().routable_points).collect();
        let peers: Vec<usize> = fleet.nodes().iter().map(|n| n.health().known_peers).collect();
        let complete: Vec<bool> = fleet.nodes().iter().map(|n| n.assignment().complete).collect();
        // **And the reason a read did not conclude, which the store already records and nothing printed.**
        // `Station::ReadInconclusive` is tagged with a `ReadStall`: `TimedOut` says the cell did not assemble
        // a reconstructable shard-set inside `read_timeout`, `TableFull` says the read was never issued. On a
        // lossless link with full reach those are very different accusations, and the pair
        // (`complete = false`, reason) is what turns "a scan did not conclude" into a mechanism.
        let plane = fleet.stations();
        // Both planes: the driver's says whether a frame found a rung, the engine's says whether a read
        // reached the store and how it ended. An earlier pass read the *absence* of `read.inconclusive` off
        // the driver's plane alone and concluded the reads never reached the store — an absence that plane
        // structurally cannot report. See `engine_stations`.
        let engine = fleet.engine_stations().await;
        // **Which coordinates each reader could resolve, not how many** — the reading two refuted hypotheses
        // showed was missing. A short roster has two very different causes: a writer whose record never
        // became retrievable (then every reader misses the *same* points) and a reader that cannot see what
        // others can (then the masks differ). The count cannot tell them apart and the rosters observed —
        // `[3, 2, 3, 2, 3]`, `[1, 3, 3, 3, 1]` — already disagree, which is the second shape.
        //
        // Re-scanned here with the same public entry point the role loop uses, rather than plumbed out of
        // it: the loop keeps no seating a fixture could read, and a second reader is exactly what is wanted
        // when the question is whether two readers see the same cell.
        let mut resolved: Vec<String> = Vec::new();
        for (i, node) in fleet.nodes().iter().enumerate() {
            let client = node.client();
            let mut seen: Vec<String> = Vec::new();
            let at_epoch = node.assignment().epoch;
            // The **bound** reader, which is what the role loop uses: under VRF coordinates every record
            // carries an `Entitlement`, so the unbound parser answers `None` at every point — including the
            // node's own — and that reads as an empty cell rather than as the wrong question. Measured that
            // way once before this line said so.
            // …and at the SAME seed the record was written against. `live_beacon()` is `None` before the
            // first round, and `read_capability(.., None)` is the unbound path again — the same wrong
            // question one layer down. The publisher falls back to `client.genesis()`, so this must too.
            let seed = Some(node.live_beacon().map_or_else(|| client.genesis(), |(_, s)| fanos_primitives::BeaconSeed::new(s)));
            // The **occupied** points only. Scanning the whole plane costs `N` store reads per node — 105
            // here, at the store's read timeout each — and every vacant point can only answer `Absent`,
            // which is not the question. The question is whether two readers see the same *members*.
            for c in coords.iter().copied() {
                seen.push(match fanos_node::capdir::read_capability::<F4>(&client, c, at_epoch, seed).await {
                    fanos_node::resolve::Read::Found(_) => format!("{}=found", crate::fmt_coord(c)),
                    fanos_node::resolve::Read::Absent => continue,
                    fanos_node::resolve::Read::Unknown => format!("{}=UNKNOWN", crate::fmt_coord(c)),
                });
            }
            resolved.push(format!("  node {i} @{} resolved {}: {}", crate::fmt_coord(node.health().address), seen.len(), seen.join(" ")));
        }
        let resolved = resolved.join("\n");
        fleet.shutdown().await;
        let roster = trace.map(|(a, _)| a.roster);
        assert!(occupied > 1, "the premise: the draw left more than one point occupied ({occupied} of {N})");
        assert!(
            !verdict.is_refuted(),
            "every node must resolve every OCCUPIED coordinate ({occupied} of {N}); the cell froze short of it: \
             {verdict:?}\n  deliver {deliver:?}  route {route:?}  peers {peers:?}  complete {complete:?}\n\
             (deliver ≈ occupied − 1 everywhere means reach is NOT the cause and the missing members were \
             unpublished at read time; a low deliver means the opposite)\n\
             roster over the observation clock:\n{}\n\
             reach over the SAME clock — if this rises while the roster stands still, reach was never the \
             binding constraint and nothing re-derived once it returned:\n{}\n\
             which coordinates each reader could resolve — same points everywhere means a writer never \
             landed, differing masks mean a reader cannot see what others can:\n{resolved}\n\
             driver plane — did a frame find a rung:{plane}\n\
             epoch each roster was computed for — a capability slot is keyed by it, so nodes reading \
             different epochs read different slots and each finds the other absent while concluding:\n{}\n\
             engine plane — did a read reach the store, and how did it end:{engine}",
            roster.render(),
            reach.render(),
            epoch.render()
        );
        // Role-assignment churn is measured in `a_lossy_cell_does_not_churn_its_role_assignment`, not here.
        // It was briefly asserted in this test and passed — and then passed just as green with the fix under
        // it reverted, because this fleet runs a **lossless** link, so a load read never times out and the
        // noise source never fires. A gate that cannot fail is not a gate.

        // Stability, three-valued like the verdict above it and for the same reason. This used to be a bare
        // `assert_eq!(changes_after(..), 0)` sitting one line below a comment explaining that a contended host
        // must not turn "still converging" into "does not converge" — so the file argued the point and then
        // did the opposite. A cell that was still converging when the deadline arrived changes during the
        // window *by definition*, and reading that as instability is the same false red, one layer up.
        if verdict.is_reached() {
            // Converged first, so anything moving now is the system, not the measurement. `revisits`, not
            // `changes_after`: a roster shrinking monotonically under load is churn the host caused, while one
            // returning to a value it already left is a controller chasing its own tail — and only the second
            // is a claim about FANOS. That distinction matters now that the role setpoint is genuinely
            // telemetry-driven and can oscillate for real.
            assert_eq!(
                roster.revisits(),
                0,
                "the assignment oscillates: a node returned to a roster it had already left\n{}",
                roster.render()
            );
            if roster.changes_after(Duration::ZERO) > 0 {
                // Drift without revisits. Reported rather than asserted: it is churn, and this observation
                // cannot tell churn the host caused from churn the cell did.
                println!(
                    "PG(2,4) N={N}: converged, then drifted without oscillating ({} transitions)\n{}",
                    roster.transitions(),
                    roster.render()
                );
            }
        } else {
            // Not a failure: the measurement did not finish. Saying so beats a red that means nothing.
            println!("PG(2,4) N={N}: inconclusive — still converging at the deadline: {verdict:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_isolated_member_does_not_make_the_cell_retire_a_role() {
        // The condition the hold rule was written for, found by asking what actually produces `Read::Unknown`.
        // Loss does not: a lossy read still concludes inside `STORE_TIMEOUT` (5 s), which is why
        // `a_lossy_cell_does_not_churn_its_role_assignment` passes with the rule reverted. An **unreachable**
        // member does — `Client::get` bounds itself at 10 s, so the outer 5 s fires first and the read reports
        // "did not conclude" rather than "definitely nothing".
        //
        // Without the rule that member's load counts as zero demand, the cell shrinks a role nobody stopped
        // needing, and the next epoch that resolves grows it back. With it, a partial read holds.
        let roles = fanos_node::RoleSet { relay: true, storage: true, ..fanos_node::RoleSet::default() };
        let fleet = NodeFleet::spawn::<F2>(4, Link::default(), roles).await.expect("fleet starts");

        // Let the cell settle before cutting anything, so what follows is the isolation's doing and not
        // start-up. Three-valued: on a contended host this may not finish, and that is not a refutation.
        let settled = fleet
            .until_settled(
                |f| f.nodes().iter().all(|n| n.assigned_roles().any()),
                // The sharper case of #159: this observable WAS the predicate — the roles vector changes only
                // when an assignment lands, so while the predicate is false it can sit perfectly still. The
                // withheld count moves in exactly that state.
                |f| (f.nodes().iter().map(|n| n.assignment().roles).collect::<Vec<_>>(), f.widest_withheld_scan()),
            )
            .await;

        // Cut member 3 off from everyone: its load slot now takes longer than STORE_TIMEOUT to read.
        for peer in 0..3 {
            fleet.isolate(peer, 3);
        }
        let trace = fleet.observe(10, Duration::from_secs(3), fanos_node::Node::assignment).await;
        fleet.shutdown().await;

        if !settled.is_reached() {
            println!("isolated-member churn: inconclusive — cell had not settled before the cut: {settled:?}");
            return;
        }
        let assigned = trace.map(|a| a.roles);
        // **Is this measurement capable of a result?** Measured: it is not, on this fleet. Every node offers
        // relay and storage and receives both for the whole window, so the observable never moves and no
        // setpoint change could show in it however wrong the setpoint was. Reported rather than passed off as
        // a green tick — a saturated assignment is the seventh kind of blindness, an instrument that agrees
        // with everything.
        //
        // Making it capable means a fleet where demand falls *below* eligible supply, so the assignment
        // selects a subset. With the shipped per-node capacity of 1 an unsensed offered role publishes one
        // node's worth per offering node, so the setpoint equals the supply by construction — which is why
        // this needs a deliberate configuration rather than a bigger cell.
        if assigned.transitions() == 0 {
            println!(
                "isolated-member churn: inconclusive — the assignment never moved, so this fleet cannot \
                 detect churn\n{}",
                assigned.render()
            );
            return;
        }
        assert_eq!(
            assigned.revisits(),
            0,
            "a member going unreachable made the cell retire and reinstate a role — an unresolved read \
             counted as a member demanding nothing\n{}",
            assigned.render()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_lossy_cell_does_not_churn_its_role_assignment() {
        // The question the setpoint work left open, measured where it can actually be answered. Until the load
        // sensors went live the setpoint was supply standing in for demand and could not oscillate; now it can.
        // The dominant noise source was never load jitter — it was the *measurement*: a load read that timed
        // out counted as a member demanding nothing, so the role shrank and the next successful read grew it
        // back. With κ = 1 the assignment tracks that in one step.
        //
        // **Loss is the point of this fleet** — the lossless one cannot exercise the path at all.
        //
        // ⚠️ **This test has NOT been shown to fail without the hold rule.** Reverting `99b7207` and running
        // this at 25% loss still passes, so it is a general regression guard on assignment stability and it is
        // *not* evidence for that rule. Recorded here so the next reader does not mistake it for one — a test
        // that passes with and without the mechanism under it proves nothing about the mechanism, whatever its
        // name suggests.
        //
        // Two reasons, both since established. Loss does not produce `Read::Unknown` at all: a lossy read
        // still concludes inside `STORE_TIMEOUT`, and the third value fires only when `Client::get` runs past
        // it — which needs an *unreachable* member, not a lossy link. And this fleet's assignment is saturated
        // anyway, so it could not have shown churn either way; the guard below now says so out loud.
        let roles = fanos_node::RoleSet { relay: true, storage: true, ..fanos_node::RoleSet::default() };
        let fleet = NodeFleet::spawn::<F2>(5, Link::default().with_loss(25), roles)
            .await
            .expect("fleet starts");
        let trace = fleet.observe(12, Duration::from_secs(2), fanos_node::Node::assignment).await;
        fleet.shutdown().await;

        // `revisits`, not `transitions`: a cell still discovering members legitimately assigns more roles as
        // it finds them, which is progress. Only a node returning to a role set it had already left is the
        // controller chasing its own tail.
        let assigned = trace.map(|a| a.roles);
        // **Is this measurement capable of a result?** Measured: it is not, on this fleet. Every node offers
        // relay and storage and receives both for the whole window, so the observable never moves and no
        // setpoint change could show in it however wrong the setpoint was. Reported rather than passed off as
        // a green tick — a saturated assignment is the seventh kind of blindness, an instrument that agrees
        // with everything.
        //
        // Making it capable means a fleet where demand falls *below* eligible supply, so the assignment
        // selects a subset. With the shipped per-node capacity of 1 an unsensed offered role publishes one
        // node's worth per offering node, so the setpoint equals the supply by construction — which is why
        // this needs a deliberate configuration rather than a bigger cell.
        if assigned.transitions() == 0 {
            println!(
                "lossy-cell churn: inconclusive — the assignment never moved, so this fleet cannot detect \
                 churn\n{}",
                assigned.render()
            );
            return;
        }
        assert_eq!(
            assigned.revisits(),
            0,
            "the role assignment oscillates under lossy reads — a node returned to a role set it had already \
             left, which is churn in the anonymity set\n{}",
            assigned.render()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_harness_tells_a_refutation_apart_from_an_unfinished_measurement() {
        // The harness asserting about ITSELF, and the reason it exists: a two-valued `until` reports "the property is
        // false" and "I could not tell" identically, and on a contended host the second is the common one. That cost three
        // false results in one session — including a "confirmed decisively" that the baseline then refuted — so the
        // discrimination is pinned here rather than trusted.
        //
        // One node, so the fleet is cheap; the observables are synthetic because what is under test is the *verdict logic*,
        // not any node behaviour.
        use fanos_node::RoleSet;
        let fleet = NodeFleet::spawn::<fanos_field::F4>(1, Link::ideal(), RoleSet::default())
            .await
            .expect("one node starts");

        // Predicate true immediately ⇒ Reached, whatever the observable does.
        let reached = fleet.until_settled(|_| true, |_| 0u32).await;
        assert!(reached.is_reached(), "a satisfied predicate must be Reached, got {reached:?}");
        assert!(!reached.is_refuted());

        // Predicate false, observable frozen ⇒ Refuted. This is the only outcome a scenario may fail on, and it must
        // arrive after FROZEN_SPAN rather than after the full deadline — otherwise a genuine failure costs 240 s.
        let started = tokio::time::Instant::now();
        let refuted = fleet.until_settled(|_| false, |_| 7u32).await;
        let took = started.elapsed();
        assert!(refuted.is_refuted(), "a frozen failing observable must be Refuted, got {refuted:?}");
        assert!(
            matches!(refuted, Settled::Refuted { last: 7, .. }),
            "and it reports the fixed point it froze at: {refuted:?}"
        );
        assert!(
            took < FROZEN_SPAN * 3,
            "a refutation must cost about FROZEN_SPAN ({FROZEN_SPAN:?}), not the whole deadline — took {took:?}"
        );

        // Predicate false, observable STILL CHANGING at the deadline ⇒ Inconclusive, never Refuted. A counter that moves
        // every poll is exactly a system that has not settled, which is what contention looks like from inside.
        let mut tick = 0u32;
        // A short budget: reaching `Inconclusive` means exhausting the deadline, and paying the 240 s default to check a
        // branch of the verdict logic would make this test the slowest thing in the suite.
        let inconclusive = fleet
            .until_settled_within(
                Duration::from_secs(2),
                |_| false,
                |_| {
                    tick += 1;
                    tick
                },
            )
            .await;
        fleet.shutdown().await;
        assert!(
            !inconclusive.is_refuted(),
            "a system still moving has NOT been measured and must not be reported as a failure: {inconclusive:?}"
        );
        assert!(matches!(inconclusive, Settled::Inconclusive { .. }), "{inconclusive:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_reseat_moves_the_coordinate_every_layer_reports() {
        // The instrument check, and it is not hypothetical: `Node::health().address` was a field captured at spawn while
        // the engine reseated underneath it, so from the first epoch reshuffle onward every layer reported the GENESIS
        // coordinate forever. Three "collided draws never resolve" measurements were taken through that frozen field before
        // the cause was noticed — a blind instrument does not merely fail to find defects, it manufactures them.
        //
        // So: drive a re-seat and assert the reported coordinate follows. A simulator whose observables can go stale
        // silently cannot be trusted about anything it reports.
        use fanos_field::F4;
        use fanos_node::RoleSet;
        use fanos_runtime::Command;

        let fleet = NodeFleet::spawn::<F4>(1, Link::ideal(), RoleSet::default()).await.expect("one node starts");
        let node = fleet.node(0).expect("the node");
        let before = node.health().address;
        // Any free point of the plane that is not the current one.
        let target = (0..fanos_geometry::Plane::<F4>::N as usize)
            .map(|i| fanos_geometry::Point::<F4>::at(i).coords())
            .find(|&p| p != before)
            .expect("a plane has more than one point");
        assert!(node.command(Command::Reseat { coord: target }), "the engine accepts a re-seat");

        let moved = fleet.until(|f| f.nodes().first().is_some_and(|n| n.health().address == target)).await;
        let after = node.health().address;
        fleet.shutdown().await;
        assert!(moved, "a re-seat must move the reported coordinate: {before:?} → {target:?}, still reads {after:?}");
        assert_eq!(after, target, "and every layer reads the same live value");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_node_records_the_claims_of_peers_it_meets() {
        // The observable that makes a resolution failure *localisable*: `verified_claims` counts peers whose coordinate
        // claim this node has checked, which is the input `fanos_vrf::settle_index` runs on. A node stuck on a contested
        // point with a low count never heard of its rival; one with a high count heard and did not move. Same symptom, two
        // different defects — and before this metric existed they were indistinguishable from outside, which is why the
        // live-resolution investigation could only report the symptom.
        use fanos_field::F4;
        use fanos_node::RoleSet;

        let fleet = NodeFleet::spawn::<F4>(3, Link::ideal(), RoleSet::default()).await.expect("fleet starts");
        // Every node is self-certifying here, so every node has a book.
        for (i, n) in fleet.nodes().iter().enumerate() {
            assert!(n.health().verified_claims.is_some(), "node {i} is self-certifying and must have a claim book");
        }
        let recorded = fleet
            .until(|f| f.nodes().iter().any(|n| n.health().verified_claims.is_some_and(|c| c > 0)))
            .await;
        let counts: Vec<_> = fleet.nodes().iter().map(|n| n.health().verified_claims).collect();
        fleet.shutdown().await;
        assert!(recorded, "a node that completes a handshake must record the peer's verified claim, saw {counts:?}");
    }






    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement — run with --ignored --nocapture"]
    async fn measure_whether_the_cell_withholds_an_unassigned_exit_advertisement() {
        // **The direct evidence that the assignment actuates, sampled where the decision is made.** The
        // neighbouring tripwire compares the directory against the assignment at one instant and cannot
        // separate "never assigned" from "assigned, then not" — a descriptor stands for its epoch while the
        // role loop re-assigns on the much shorter roster cadence. `exit.advertisement_withheld` has no such
        // gap: it fires exactly when a node that OFFERS Exit is not assigned it and therefore publishes
        // nothing for that epoch.
        //
        // Needs epoch boundaries to be observable at all, so the fleet runs at the derived floor rather than
        // the shipped 600 s — at which the withholding branch is simply never reached inside a scenario.
        //
        // Read against the offer: five nodes offer Exit on an idle cell, the setpoint is `⌈0/capacity⌉ = 0`,
        // and demand falls to the observability floor of one. A zero here would say the record is still
        // being written by the OFFER rather than by the decision.
        //
        // **Measured 2026-08-16.** First run after the actuation landed, before the publisher waited for the
        // decision to reach its epoch: `[9, 3, 6, 4, 8]` over nine epochs, every one tagged "stale" — the
        // publisher and the role loop wake on the same beacon and the publisher always wins, so the record
        // for epoch E was written against the decision for E−1. After the wait: `[0, 0, 1, 0, 0]`, the one
        // withholding tagged "decided, not assigned", and no stale tag at all. Far fewer withholdings, which
        // says the previous-epoch decision was systematically naming different holders.
        //
        // The older reading, kept because it is what the actuation itself proved: `[9, 3, 6, 4, 8]`.
        // Every node withheld in some epochs and published in others, which is the assignment rotating —
        // `priority_key` re-draws the holders against each beacon — and it is the direct evidence the
        // neighbouring tripwire structurally cannot give. Before the change all five published every epoch,
        // unconditionally.
        use fanos_field::F2;
        use fanos_node::RoleSet;

        let floor = Duration::from_nanos(Config::default().minimum_epoch_period().0);
        // **The plane is F2 because the exit floor is now `fault_budget(N) + 1`.** This probe needs the
        // assignment to be a strict subset of the offer, and on `F4` that floor is `fault_budget(21) + 1 = 7`
        // against five offering nodes — saturated, so the probe would skip for ever. On `F2` it is
        // `fault_budget(7) + 1 = 3`, leaving two of five withholding with the plane still slack (7 points,
        // 5 nodes), which is the same regime this fixture was written in.
        let roles = RoleSet { relay: true, exit: true, ..RoleSet::default() };
        let fleet = NodeFleet::spawn_with_epoch::<F2>(5, Link::ideal(), roles, floor).await.expect("fleet starts");
        tokio::time::sleep(8 * floor).await;
        let withheld: Vec<Vec<(u64, u64)>> = fleet
            .nodes()
            .iter()
            .map(|n| {
                n.client()
                    .driver_stations()
                    .iter()
                    .filter(|o| o.station == fanos_runtime::ports::stations::Station::ExitAdvertisementWithheld)
                    .map(|o| (o.tag.unwrap_or(0), o.count))
                    .collect::<Vec<_>>()
            })
            .collect();
        let assigned: Vec<bool> = fleet.nodes().iter().map(|n| n.serves(fanos_core::roles::Role::Exit)).collect();
        let epochs: Vec<_> = fleet.nodes().iter().map(|n| n.live_beacon().map(|(e, _)| e.get())).collect();
        fleet.shutdown().await;
        println!(
            "MEASURED exit.advertisement_withheld per node as (tag, count), tag 0 = decided-not-assigned, 1 = assignment stale for this epoch: {withheld:?}, assigned now {assigned:?}, epochs \
             {epochs:?} — all five offer Exit, so a nonzero count is the assignment acting"
        );
    }


    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement — run with --ignored --nocapture"]
    async fn measure_whether_membership_locks_out_after_an_epoch_boundary() {
        // **The consequence of keying membership by a position whose occupant changes.** `on_announce` ends
        // at "first sight only" — `members.contains_key(&coord)` refuses a repeat, which protects a member's
        // key bundle from being overwritten by any peer. But the beacon re-draws every node's VRF coordinate
        // each epoch while `members` is keyed by position and is **not** cleared at the boundary, so after a
        // turn an announcement can land on a point some *previous* occupant still holds and be dropped.
        //
        // **The repeat counter turned out to be the wrong observable, and this measurement is what showed
        // it.** It conflates a benign repeat while a join flood drains with a genuine lock-out, and after the
        // boundary clear landed it went *up* (75–122 against 52–107) while the actual behaviour improved,
        // because every node now re-announces every epoch. It is still printed, as the symptom it is.
        //
        // **What decides is `membership.size`** — one row per epoch end, tagged with the size the epoch
        // closed with, which measures the *consequence* rather than the symptom. Measured on a five-node
        // fleet at the derived floor epoch:
        //
        //   without the boundary clear:  0, 4, 5, 7, 8, 9, 10, 10   ← monotone, to TWICE the cell size
        //   with it:                     0, 4, 4, 4, 4, 4,  5,  5   ← steady at the cell size
        //
        // Without clearing, every node re-announces at a *new* coordinate each epoch and nothing removes the
        // old entry, so a five-node cell's view grows toward the plane's 21 points — and as it fills, more
        // and more announcements land on an occupied coordinate and are refused. That is the lock-out, and
        // the growth curve is the proof the repeat count could not give.
        use fanos_field::F4;
        use fanos_node::RoleSet;
        use fanos_runtime::ports::stations::Station;

        async fn ignored(fleet: &NodeFleet) -> (Vec<u64>, Vec<Vec<(u64, u64)>>) {
            let mut out = Vec::new();
            let mut sizes = Vec::new();
            for n in fleet.nodes() {
                let mut events = n.client().subscribe();
                if !n.client().command(fanos_runtime::Command::Observe) {
                    out.push(0);
                    continue;
                }
                let seen = tokio::time::timeout(fanos_testkit::LIVENESS_BACKSTOP, async {
                    loop {
                        match events.recv().await {
                            Ok(fanos_runtime::Notification::DataPath { stations, .. }) => return Some(stations),
                            Ok(_) => {}
                            Err(_) => return None,
                        }
                    }
                })
                .await
                .ok()
                .flatten()
                .unwrap_or_default();
                out.push(
                    seen.iter().filter(|o| o.station == Station::MembershipRepeatIgnored).map(|o| o.count).sum(),
                );
                // The series that decides it: one row per epoch end, tagged with the size the epoch closed
                // with. A view refilling to the cell's size every boundary is healthy; one decaying epoch by
                // epoch is the lock-out, and no reading of a repeat count is needed to tell them apart.
                sizes.push(
                    seen.iter()
                        .filter(|o| o.station == Station::MembershipSize)
                        .map(|o| (o.tag.unwrap_or(0), o.count))
                        .collect::<Vec<_>>(),
                );
            }
            (out, sizes)
        }

        let floor = Duration::from_nanos(Config::default().minimum_epoch_period().0);
        let fleet = NodeFleet::spawn_with_epoch::<F4>(5, Link::ideal(), RoleSet::default(), floor)
            .await
            .expect("fleet starts");
        // Before any boundary: whatever the join flood produced, and nothing else.
        tokio::time::sleep(floor / 2).await;
        let (at_genesis, _) = ignored(&fleet).await;
        let epochs_before: Vec<_> = fleet.nodes().iter().map(|n| n.live_beacon().map(|(e, _)| e.get())).collect();
        // Several boundaries later.
        tokio::time::sleep(8 * floor).await;
        let (after, sizes) = ignored(&fleet).await;
        let epochs_after: Vec<_> = fleet.nodes().iter().map(|n| n.live_beacon().map(|(e, _)| e.get())).collect();
        let addrs: Vec<_> = fleet.nodes().iter().map(|n| n.health().address).collect();
        fleet.shutdown().await;

        let growth: Vec<i64> = after
            .iter()
            .zip(&at_genesis)
            .map(|(a, b)| i64::try_from(*a).unwrap_or(0) - i64::try_from(*b).unwrap_or(0))
            .collect();
        println!(
            "MEASURED membership.repeat_ignored: at genesis {at_genesis:?} (epochs {epochs_before:?}), after \
             {after:?} (epochs {epochs_after:?}), growth {growth:?}; membership.size per node as \
             (size, epochs-ending-at-that-size) {sizes:?}; addresses {addrs:?}"
        );
    }


    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement — run with --ignored --nocapture"]
    async fn measure_what_fraction_of_beacon_rounds_assemble() {
        // **The beacon's liveness is a delivery probability, and nothing had ever measured it.** A round needs
        // `threshold` partials, and `BeaconNode::broadcast` addresses each one to a *plane point*, so every partial
        // rides the coordinate send ladder and its last rung drops the frame. The epoch therefore advances at
        // `tick rate x P(threshold partials arrive)`, not at the tick rate the operator configured.
        //
        // Measured 2026-08-16, 3 nodes on `Link::ideal()`, `epoch_period` at the derived floor, over a window of ten
        // periods (the driver skips its first tick, so nine rounds are on offer). Cell-max epoch reached across five
        // runs: **3, 3, 9, 5, 3** — an assembly fraction of about a third, with one run at nominal. On an ideal link,
        // in a three-node cell, at a threshold of two.
        //
        // **This instrument is load-dominated, and that is a property of the quantity, not a flaw to tune out.** The
        // window is wall-clock and the epoch driver's ticks are wall-clock, so a busy host offers the same nine rounds
        // while delivering fewer of them. Readings taken the same afternoon: `0.67, 0.78, 0.89` at host load ≈ 5, and
        // `0.22, 0.33` at load ≈ 10, with no code change between the two groups. **Any before/after comparison across
        // different host loads is therefore worthless** — the beacon pull-sync trigger added the same day looked like
        // a large improvement until the loaded samples arrived and the bands overlapped. Use this to measure the *rate
        // itself* on a quiet box, and use a presence observable (did the pull fire? did a laggard catch up?) for
        // anything that has to survive a shared machine.
        //
        // Two readings this cannot give, deliberately. It cannot say *why* a round failed: `Station::BeaconRefused`
        // rides `Notification::DataPath`, which is emitted only in answer to `Command::Observe`, so `fleet.stations()`
        // — the driver's map — cannot see refusals at all, and their absence there means nothing. And it cannot
        // separate "the partial was dropped" from "it arrived and was refused" until that surface is reachable here.
        use fanos_field::F4;
        use fanos_node::RoleSet;

        let floor = Duration::from_nanos(Config::default().minimum_epoch_period().0);
        let periods = 10;
        let fleet = NodeFleet::spawn_with_epoch::<F4>(3, Link::ideal(), RoleSet::default(), floor)
            .await
            .expect("fleet starts");
        tokio::time::sleep(u32::try_from(periods).map_or(floor, |p| p * floor)).await;
        let epochs: Vec<_> = fleet.nodes().iter().map(|n| n.live_beacon().map(|(e, _)| e.get())).collect();
        // **Why a round failed, asked of the one surface that can answer it.** `Station::BeaconRefused` never appears
        // in `fleet.stations()` — that reads the driver's map, while a refusal rides `Notification::DataPath`, which
        // the engine emits only in answer to `Command::Observe`. Reading the absence off the wrong surface is how the
        // first account of this freeze went wrong, so the right surface is asked here explicitly. A tag names the
        // class (`fanos_keygen::BeaconRefusal::ALL`): a partial for an already-adopted epoch is benign and expected
        // to be nonzero, while a DLEQ failure or an own-share mismatch is a provisioning fault, and a future-epoch
        // discard means this node is behind rather than deaf. Nothing at all means the partials never arrived.
        let mut refusals = Vec::new();
        for (i, n) in fleet.nodes().iter().enumerate() {
            let mut events = n.client().subscribe();
            if !n.client().command(fanos_runtime::Command::Observe) {
                continue;
            }
            let seen = tokio::time::timeout(fanos_testkit::LIVENESS_BACKSTOP, async {
                loop {
                    match events.recv().await {
                        Ok(fanos_runtime::Notification::DataPath { stations, .. }) => return Some(stations),
                        Ok(_) => {}
                        Err(_) => return None,
                    }
                }
            })
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
            for o in seen.iter().filter(|o| o.station == fanos_runtime::ports::stations::Station::BeaconRefused) {
                let name = o
                    .tag
                    .and_then(|t| usize::try_from(t).ok())
                    .and_then(|t| fanos_keygen::BeaconRefusal::ALL.get(t))
                    .map_or("unknown", |r| r.name());
                refusals.push(format!("node {i} {name}={}", o.count));
            }
        }
        // Printed beside the epochs because a coordinate collision is the mechanism most likely to explain a node
        // that stops: the directory serves a contested point as ONE address, so a partial addressed to that point
        // reaches the incumbent and never the co-located claimant. Measured live here — two of three nodes reporting
        // the same address is not rare.
        let addrs: Vec<_> = fleet.nodes().iter().map(|n| n.health().address).collect();
        // **The load-robust observable, and the one that decides whether coordinate addressing is the defect.**
        // `directory.entry_fallback` fires per coordinate on the send ladder's last rung, and *drops the frame*. Most
        // of those are the plane's empty points — 21 points against 3 nodes leaves 18 that nobody occupies, and a
        // broadcast to the cell dutifully tries every one. What matters is the intersection with the **occupied**
        // points: each of those is a real peer this node could not address, so a partial aimed at it was thrown away.
        // Unlike the assembly fraction above, this number does not move with host load — a coordinate either resolves
        // or it does not — which is what makes it usable on a shared machine.
        let occupied: HashSet<_> = addrs.iter().copied().collect();
        let occupied_hits = |i: usize, station: fanos_runtime::ports::stations::Station| {
            fleet
                .nodes()
                .get(i)
                .map(|n| n.client().driver_stations())
                .unwrap_or_default()
                .iter()
                .filter(|o| o.station == station)
                .filter_map(|o| o.line)
                .filter(|c| occupied.contains(c) && addrs.get(i).copied() != Some(*c))
                .collect::<HashSet<_>>()
                .len()
        };
        let unreachable: Vec<usize> = (0..fleet.nodes().len())
            .map(|i| occupied_hits(i, fanos_runtime::ports::stations::Station::DirectoryEntryFallback))
            .collect();
        // **Which rung failed, not merely that the ladder ran out.** `conns.cache_miss` is the second rung's
        // own outcome, so an occupied point appearing here says this node had no live connection to a real
        // peer at the moment it tried to send. Compare with `unreachable` above: equal counts mean the cache
        // is the binding constraint (the directory had nothing either, and the ladder went all the way down),
        // while a cache miss without a fallback means some later rung caught it.
        let cache_missed: Vec<usize> = (0..fleet.nodes().len())
            .map(|i| occupied_hits(i, fanos_runtime::ports::stations::Station::ConnCacheMiss))
            .collect();
        let stations = fleet.stations();
        fleet.shutdown().await;
        let reached = epochs.iter().flatten().copied().max().unwrap_or(0);
        // The driver skips its first tick, so `periods` of wall clock offer `periods - 1` rounds.
        // **Rounds per period, not a fraction of an exact offer.** The nodes are spawned in sequence, so their epoch
        // drivers tick out of phase and the number of ticks inside the window is not `periods - 1` on the nose — an
        // early draft divided by that and printed `1.11`, which is the denominator confessing. One is nominal; below
        // one is rounds the cell failed to assemble.
        println!(
            "MEASURED beacon rounds: cell reached epoch {reached} in {periods} periods of {floor:?} ({:.2} per \
             period), per node {epochs:?}, addresses {addrs:?}, occupied points this node could NOT address \
             {unreachable:?}, of which the connection cache missed {cache_missed:?}, refusals {refusals:?}, \
             stations{stations}",
            f64::from(u32::try_from(reached).unwrap_or(u32::MAX)) / f64::from(periods),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_node_of_a_fleet_leaves_the_genesis_epoch() {
        // **The premise underneath the premise.** The test below asserts that a boundary is what ends a node's freedom
        // to re-seat; this one asserts that a boundary happens at all. It did not: `NodeFleet` dealt a VSS sharing and
        // bound it to `_shares`, so every node was a beacon *consumer* of a group with no anchors, no threshold round
        // could assemble, and `live_beacon()` read `None` on every node for the whole life of every scenario. A fleet
        // pinned at genesis exercises no coordinate reshuffle, no onion ratchet, no per-epoch re-assignment and no
        // directory-slot expiry — and reports nothing, because nothing was watching this.
        //
        // **This asserts the floor only — every node leaves genesis — and the reason is a defect it must not hide.**
        // Nine runs of three nodes at a 2.1 s epoch: `[9,9,1]`, `[1,12,12]`, `[9,1,9]`, `[5,5,4]`, `[6,5,7]`, `[4,3,4]`,
        // `[3,5,4]`, `[4,4,3]`, `[4,9,9]`. In roughly two runs of five **one node adopts epoch 1 and then stands still
        // for ever** while the cell advances — and it is a *different* node each time, so it is a property of the cell's
        // reachability graph, not of any position in it.
        //
        // **And the freeze is the tail of something continuous, not a state of its own** — the correction that matters
        // most here. `measure_what_fraction_of_beacon_rounds_assemble` puts the cell at epoch 3–9 of nine on offer,
        // about a third to a half, on an ideal link. Rounds fail *routinely*; "stuck at 1" is simply the run where a
        // node's share of them was zero. Read the freeze as the extreme of a distribution, not as a switch.
        //
        // What is established about the mechanism: `BeaconNode::broadcast` addresses its partial to **every point of
        // the plane** (`Point::at(i)`), so every partial rides the ordinary coordinate send ladder — directory binding
        // → cached connection → hub → `directory.entry_fallback`, whose last rung *drops the frame*. The beacon's
        // liveness is therefore a delivery probability over coordinate resolution, and the epoch advances at
        // `tick rate × P(threshold partials arrive)` rather than at the configured rate.
        //
        // **Two explanations died, and one of them was mine, shipped in this doc.**
        //
        //   * *One-directional discovery* — refuted at the source: the accept path files an inbound connection under
        //     the peer's **proven** coordinate (`file_conn(&mut map, from, conn)`), precisely so the transport can
        //     originate back over it. Reverse reachability exists by design; what is deliberately withheld is only the
        //     *directory* entry, because the source port is ephemeral. "Nobody can address it" was the right symptom
        //     attached to the wrong cause.
        //   * *Silence proves no refusals* — invalid evidence: `Station::BeaconRefused` rides
        //     `Notification::DataPath`, emitted only in answer to `Command::Observe`, while `fleet.stations()` reads
        //     the **driver's** map. That surface cannot carry a beacon refusal, so its absence there says nothing at
        //     all. A diagnostic surface stops at its crate.
        //
        // The live candidate, observed rather than argued: two of three nodes reporting the **same address** is not
        // rare here, and a contested point resolves to one holder, so a partial addressed to it reaches the incumbent
        // and never the co-located claimant (`transport.self_connection`, 68 in one reading). If that is the mechanism
        // it is circular and self-sealing — the collision costs the node the very epoch clock whose next draw would
        // clear the collision — which would explain why forced collisions do not resolve and why the epoch length
        // never mattered.
        //
        // What still stands, and is the reason for the assertion below: the alarm cannot fire. `RECOVERY_PATIENCE = 4`
        // periods confirm the stall, but `RecoveryWatcher::live_anchors` counts an anchor live unless a `PeerDown`
        // arrived, and a starved node's connections are *healthy* — it is deaf, not disconnected. The detector
        // confirms a stall and the decision then classifies it as nothing wrong.
        //
        // Asserting the floor pins what dealing the anchors bought without pinning the freeze as if it were correct.
        use fanos_field::F4;
        use fanos_node::RoleSet;

        let floor = Duration::from_nanos(Config::default().minimum_epoch_period().0);
        let fleet =
            NodeFleet::spawn_with_epoch::<F4>(3, Link::ideal(), RoleSet::default(), floor).await.expect("fleet starts");
        let advanced = fleet
            .until(|f| f.nodes().iter().all(|n| n.live_beacon().is_some_and(|(e, _)| e > fanos_primitives::Epoch::ZERO)))
            .await;
        let epochs: Vec<_> = fleet.nodes().iter().map(|n| n.live_beacon().map(|(e, _)| e.get())).collect();
        fleet.shutdown().await;
        assert!(
            advanced,
            "a {floor:?} epoch and a dealt beacon must carry every node past genesis, read {epochs:?} — `None` means no \
             threshold round ever assembled, which is the anchors being absent rather than the period being long"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_settling_window_re_opens_at_every_boundary_and_closes_when_the_seat_is_read() {
        // **The premise every collision measurement in this file is read through, and nothing pinned it.**
        // Settle-on-join (`docs/design-coordinates.md`; `Wake::Resettle if at.joining`) lets a node re-seat on a
        // peer's better claim only until it has lived through an epoch boundary. So whether a harness is observing
        // free nodes or committed ones is not a detail — it decides which of the two designs is under test — and it
        // is set by a constant three crates away: `at.joining` clears only in the `Wake::Beacon` arm, that arm wakes
        // only on `BeaconReady`, and only `spawn_epoch_driver` produces one, whose **first tick is deliberately
        // skipped** "so the node has a full period to connect and sync". At `DEFAULT_EPOCH_PERIOD = 600 s` against
        // runs of 60–160 s, no fleet node has ever committed a seat, and the numbers those runs produced were
        // therefore measuring settle-on-join at full strength rather than its absence.
        //
        // That inference cost this investigation three wrong explanations, so it is asserted here rather than
        // re-derived. Both states are produced, one variable apart — the epoch period — because an absence with
        // nothing to contrast it against cannot tell "never commits" from "the station never fires at all".
        use fanos_field::F4;
        use fanos_node::RoleSet;
        use fanos_runtime::ports::stations::Station;

        // The **count**, not the presence. Under the rule this test was written for, a node committed its
        // seat exactly once and never again, so a boolean said everything there was to say. It no longer
        // does: the window is re-entered at every boundary, and how many times a node has closed one is the
        // whole difference between the two designs.
        fn commits(fleet: &NodeFleet) -> Vec<u64> {
            fleet
                .nodes()
                .iter()
                .map(|n| {
                    n.client()
                        .driver_stations()
                        .iter()
                        .filter(|o| o.station == Station::SeatCommitted)
                        .map(|o| o.count)
                        .sum()
                })
                .collect()
        }

        fn committed(fleet: &NodeFleet) -> usize {
            fleet
                .nodes()
                .iter()
                .filter(|n| n.client().driver_stations().iter().any(|o| o.station == Station::SeatCommitted))
                .count()
        }

        // Derived, not chosen: the shortest epoch the runtime's own arithmetic admits, `read_timeout + heartbeat`.
        // `Node::start` deliberately does not enforce it on fixtures ("test fixtures compress the clock on purpose"),
        // and this is exactly that case — the quantity under test is the boundary, not the period.
        let floor = Duration::from_nanos(Config::default().minimum_epoch_period().0);

        let short =
            NodeFleet::spawn_with_epoch::<F4>(3, Link::ideal(), RoleSet::default(), floor).await.expect("fleet starts");
        let began = std::time::Instant::now();
        let all_committed = short.until(|f| committed(f) == f.nodes().len()).await;
        let took = began.elapsed();
        let seen = committed(&short);
        short.shutdown().await;
        assert!(all_committed, "at a {floor:?} epoch every node must cross a boundary and commit its seat; {seen} of 3 did");
        println!("MEASURED all three seats committed after {took:?} at a {floor:?} epoch (backstop, not a latency claim)");

        // **The control, re-stated — because the thing it controlled for stopped being true, and that is
        // the finding rather than a maintenance chore.**
        //
        // It used to be: at the default 600 s epoch a node cannot reach a boundary in a few seconds, so
        // every node must still be free to re-seat. That held only while a boundary was the *only* thing
        // that ended freedom — and `at.joining` was then cleared at the first boundary and never restored,
        // so a node resolved collisions once in its life and every later epoch re-derived every placement at
        // once with nobody permitted to move. Measured at `n = 31` on `PG(2,4)`: the joining phase reaches
        // **21 of 21** servable lines, the first boundary drops it to 13, and six boundaries do not recover
        // it (`measure_whether_shadowing_clears_at_the_epoch_or_is_stationary`).
        //
        // So freedom now ends where the invariant always said it did — when the cell has read this placement
        // (`Client::commit_seat`, called by the role loop, which already computes that) or when the walk is
        // spent (`may_walk`, bounded by `probe_bound = q + 1`) — and the window **re-opens at every
        // boundary**. What the harness needs is unchanged: it must be able to tell a free node from a
        // committed one, and produce both. The producer is what moved, and this asserts the new one, which
        // the old rule could not satisfy at all: over several boundaries a node commits **more than once**.
        let rounds = 6 * floor;
        let many = NodeFleet::spawn_with_epoch::<F4>(3, Link::ideal(), RoleSet::default(), floor)
            .await
            .expect("fleet starts");
        let reopened = many.until(|f| commits(f).iter().all(|&c| c >= 2)).await;
        let counts = commits(&many);
        let stations = many.stations();
        many.shutdown().await;
        assert!(
            reopened,
            "the settling window must re-open at every boundary: after {rounds:?} of {floor:?} epochs every \
             node should have closed at least two windows, and the counts are {counts:?}. Exactly one apiece \
             is the old rule — a node that resolved collisions once and was frozen for every epoch after. \
             Stations:{stations}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement — run with --ignored --nocapture"]
    async fn measure_whether_a_collided_draw_now_resolves_itself() {
        // Forces the condition with `spawn_as_drawn` — at 7 nodes on `PG(2,4)`'s 21 points a draw collides in ~67% of runs,
        // and hoping to meet one is how a 13% coincidence passed for success.
        //
        // **RESOLVED 2026-07-26. Four trials, every one reaching 7/7 distinct:**
        //
        //   trial 0: held 7/7, all-distinct: true, index [0, 0, 1, 0, 0, 0, 0]
        //   trial 1: held 7/7, all-distinct: true, index [0, 0, 0, 0, 1, 0, None]
        //   trial 2: held 7/7, all-distinct: true, index [0, 0, 0, 0, 0, 1, 4]
        //   trial 3: held 7/7, all-distinct: true  (injective draw — nothing to resolve)
        //
        // Nodes are visibly seated at probe index 1 and 4: they advanced along their own walks and announced where they
        // landed. Runtime fell from ~700 s (waiting out the deadline) to 1.13 s.
        //
        // Three wrong hypotheses preceded it, each killed by adding an observable rather than by argument, and the cause was
        // one line: **`spawn_inner` bound our coordinate to our own address unranked, overwriting the bootstrap seed** — the
        // only route to whoever already held that point. The node then had no contender in its claim book, `settle_index`
        // saw nothing to move for, and both members of a colliding pair sat at index 0 each believing it held the point.
        // The first attempt at the fix read the directory *after* `spawn_inner` and so always answered "us", doing nothing.
        //
        // Dead hypotheses, kept because each was instructively wrong: reachability (refuted — every node, stuck ones
        // included, had verified several peers' claims) and settle-on-join (changed nothing — the fleet never crosses an
        // epoch boundary, so every node was already free to move).
        //
        // **The next defect is one layer up:** after a node moves, peers keep the stale binding, since `Reseater::apply`
        // clears the vacated point from the mover's own directory and nothing tells the rest of the cell. With placement
        // fully resolved (`occupied = 5 of 5`) roster convergence still froze at
        // `Refuted { frozen_for: 30s, last: [4, 4, 3, 4, 2] }`. That is what `NodeFleet::spawn`'s injective draw now guards.
        use fanos_field::F4;
        use fanos_node::RoleSet;

        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        println!("{}", fanos_testkit::measurement_conditions());
        // **Two arms, one run, because the comparison IS the measurement.** The production question is
        // "does a collided draw resolve itself" at the shipped `DEFAULT_EPOCH_PERIOD`; the diagnostic
        // question is whether the epoch turn is what resolves it, which #260 predicts ("both then hold one
        // point until the epoch turns"). Answering them in separate runs would put a host and an hour
        // between the two numbers; answering them here does not, and a reader gets a pair rather than a
        // single figure they might mistake for behaviour.
        //
        // Measured 2026-08-16, eight forced collisions per arm: **4/8 at 600 s, 5/8 at 30 s** (Fisher exact
        // `p = 1.0`). So the epoch turn is NOT the resolving event, and #260's deadlock — real, and the
        // reason the seated loser cannot walk — is not what the missing half is about. Two caveats the
        // numbers do not carry: at eight per arm even 4/8 vs 8/8 is only `p ≈ 0.08`, so this design can
        // conclude from a total effect or from none; and under a short epoch "resolved" is a **transient**
        // property, since the wait below and the re-read after it can straddle a boundary.
        for (label, epoch) in [
            ("epoch 600s (shipped)", fanos_node::config::DEFAULT_EPOCH_PERIOD),
            ("epoch  30s (probe)  ", fanos_node::role_loop::ROSTER_REFRESH * 2),
        ] {
        let mut resolved = 0usize;
        for trial in 0..8 {
            // **Force the collision, and count more trials — the certification above was taken without
            // either.** `spawn_as_drawn` takes the draw as it comes, so a trial can spend itself on an
            // injective draw with nothing to resolve; re-running this on 2026-08-16 produced exactly that as
            // trial 0 (`claims` all zero). The sibling measurement one function over states the rule and
            // follows it — "a measurement that can silently pass by never exercising its path is not a
            // measurement" — and this one did not, so "four trials, every one reaching 7/7" was three real
            // trials and a vacuous one.
            //
            // It matters because the re-run reached 7/7 in **one of the three** that actually collided, with
            // the original fingerprint (`index` all `0`: nobody advanced). Whether that is a regression or a
            // sample too small to have shown it in July is exactly what a larger forced sample answers, and
            // it is one constant.
            let fleet = loop {
                let fleet = NodeFleet::spawn_as_drawn_with_epoch::<F4>(7, Link::ideal(), roles, epoch)
                    .await
                    .expect("fleet starts");
                let drawn: HashSet<_> = fleet.nodes().iter().map(|n| n.health().address).collect();
                if drawn.len() < fleet.nodes().len() {
                    break fleet;
                }
                fleet.shutdown().await;
            };
            let settled = fleet.until(|f| {
                let held: HashSet<_> = f.nodes().iter().map(|n| n.health().address).collect();
                held.len() == f.nodes().len()
            }).await;
            let held: HashSet<_> = fleet.nodes().iter().map(|n| n.health().address).collect();
            // The localising observable: whose claims did each node actually verify? A node still on a contested point with
            // a low count never heard of its rival; a high count means it heard and did not move.
            let claims: Vec<_> = fleet.nodes().iter().map(|n| n.health().verified_claims).collect();
            // **The pairwise reading, and the one the columns beside it cannot give.** `claims` is a total:
            // a node stuck on a contested point can have verified six peers and still not the one contesting
            // *its* seat. This asks `ClaimBook::outranked_at` — `claim_beats` applied against the very order
            // `settle_index` walks — whether a peer has proved a **better** claim to the point this node
            // sits on.
            //
            // **Not "is there a contender", which the first version asked and which is nearly vacuous.** That
            // read `true` on all seven nodes, because a peer's claim to a point is scored by
            // `probe_index_of`, which answers for every point on that peer's walk, and a walk covers its
            // whole line. Being *outranked* is the question that decides a contest.
            //
            // Read it against `index`: the order is total, so of a colliding pair exactly one must be
            // outranked and therefore able to advance. A node reading `true` here while its index stays at 0
            // is one the rule should have moved and did not.
            //
            // **Measured 2026-08-16 with this column: `false` almost everywhere, including every unresolved
            // trial.** Two nodes share a point and *neither* considers itself outranked — impossible under a
            // total order if both held the other's claim, since exactly one of a colliding pair must be
            // beaten. So `contender` is not returning the rival at all: the best claim it finds there is a
            // third node whose walk merely passes through, which loses to the incumbent. The rival's claim to
            // the contested point is **absent from the book**, which closes the chain on the mechanism this
            // harness already measured — `transport.self_connection`, the directory serving the contested
            // point as one address, so the pair cannot reach each other to exchange claims.
            //
            // **Epoch arms, four runs, with the outlier kept.** Baseline 7/8, 4/8, 1/8, 3/8 against treatment
            // 6/8, 8/8, 8/8, 8/8. Runs 2–4 are a paired within-run contrast of 8/24 vs 24/24 and each run is
            // its own control, so the epoch turn probably does help; run 1 contradicts it and nothing in the
            // executed path differed. Report the outlier rather than averaging it away.
            let contended: Vec<_> =
                fleet.nodes().iter().map(|n| n.health().seat_outranked).collect();
            // Did each node *decide* to move? `0` = stayed at its preferred point, `> 0` = advanced its probe walk,
            // `None` = not bound at all (it lost the arbitration and holds no directory entry).
            let idx: Vec<_> = fleet.nodes().iter().map(|n| n.health().probe_index).collect();
            // **The stations, because one of them is the discriminator this measurement lacked.**
            // `directory.seat_outranked` fires when a node holds the winning claim to its own point and is
            // forbidden to act on it (#260), keyed by the contested coordinate — and its own doc gives the
            // reading rule: "a nonzero count that does not clear at the next epoch is the settling window
            // (`docs/design-coordinates.md`) being needed rather than one unlucky draw". The short-epoch arm
            // spans several boundaries, so its persistence there tests the DESIGN's prediction rather than
            // any story told about the numbers afterwards.
            let stations = fleet.stations();
            fleet.shutdown().await;
            // Deliberately NOT reporting rosters here. The `until` predicate waits for distinct *addresses*, so a roster
            // sampled at that instant is read before the role loop has assigned anything — it prints `[0, 0, …]` and looks
            // like broken propagation when it is only an early read. Roster convergence has its own probe
            // (`probe_roster_convergence_against_cell_occupancy`), which waits for it.
            // Both readings, because under a short epoch they are different facts: `settled` is what the
            // wait observed, `held` is what a re-read found afterwards, and a boundary can fall between them.
            // Equal ⇒ placement is stable; different ⇒ the epoch re-draws faster than placement settles,
            // which would make the epoch period a quantity bounded below by the resolution time rather than
            // a chosen one.
            if settled {
                resolved += 1;
            }
            println!(
                "  {label} trial {trial}: held {}/7, all-distinct: {settled}, claims {claims:?}, outranked-here \
                 {contended:?}, index {idx:?}{stations}",
                held.len()
            );
        }
        println!("{label}: resolved {resolved}/8");
        }
    }

    /// **How many nodes does a cell need before its plane is covered?** — the sizing number the geometry
    /// implies, measured against the shipping placement rather than a model of it.
    ///
    /// A cell is sized in **nodes**; a plane is counted in **points**; and line viability is a statement
    /// about points (`fanos_geometry::points_serving_every_line`, `servable_lines`). Nothing connects the
    /// two, so a deployment has no way to answer "how many members before my lines work". This measures it
    /// end to end: real coordinate draws, the real line-confined probe walk (`fanos_vrf::probe_walk`), real
    /// claim ranking and displacement.
    ///
    /// **Pre-registered, so the run can refute rather than confirm.** Simulating the same walk in isolation
    /// predicted, for `PG(2,4)` (`N = 21`, floor `20`): at `n = 21` about `18.9` distinct points and `2.1`
    /// nodes unbound, clearing the floor a quarter of the time; at `n = 31` about `20.8` distinct and `10.2`
    /// unbound, clearing it almost always. The prediction that matters is the SHAPE — distinct must fall
    /// visibly below `n`, and `unbound ≈ n − distinct`. If distinct tracks `n`, the model is wrong and the
    /// placement is doing something the walk alone does not explain.
    ///
    /// `servable_now` is the quantity the cell actually cares about, and it is a step function of the other
    /// two: below the floor it collapses, and the collapse is what `role.under_provisioned` reports.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement — run with --ignored --nocapture"]
    async fn measure_how_many_nodes_a_plane_needs_before_its_lines_work() {
        use std::collections::HashSet;
        let roles = fanos_node::RoleSet {
                relay: true,
                rendezvous: true,
                ..fanos_node::RoleSet::default()
            };
        let n_points = fanos_geometry::Plane::<fanos_field::F4>::N as usize;
        let floor = fanos_geometry::points_serving_every_line(
            fanos_geometry::Plane::<fanos_field::F4>::LINE_SIZE as usize,
        );
        println!("PG(2,4): {n_points} points, viability floor {floor}");
        for count in [11usize, 16, 21, 26, 31] {
            // The error, not just its absence. The first run printed "fleet did not start" for `n = 26`
            // and `31` and threw the reason away, which turned the one regime this measurement exists to
            // reach — `n/N ≈ 1.5` — into an unexplained blank.
            let fleet =
                match NodeFleet::spawn_as_drawn::<fanos_field::F4>(count, Link::ideal(), roles).await {
                    Ok(f) => f,
                    Err(e) => {
                        println!("n={count}: fleet did not start — {e:?}");
                        continue;
                    }
                };
            // **The same settling budget the neighbouring collision measurement uses**, and it is not
            // generosity. A coordinate read before displacement resolves counts a point that is about to be
            // vacated: the first run gave `10 × 2s` and saw 19 bound nodes on 16 points with every
            // `probe_index` still at `0` — nobody had moved yet, so the reading was of a cell mid-settle
            // rather than of a settled one. `40 × 4s` is what the collision scenario one screen down found
            // sufficient for resolution to complete.
            let _ = fleet.observe(40, Duration::from_secs(4), fanos_node::Node::assignment).await;
            // **Bound nodes only.** An unbound node still reports an `address` — its preferred point — so
            // folding it into the occupancy counts a seat nobody holds. The first run of this measurement
            // did exactly that and produced `distinct + unbound > n`, which is the arithmetic saying so.
            let seats: Vec<(fanos_geometry::Triple, Option<u16>)> =
                fleet.nodes().iter().map(|n| (n.health().address, n.health().probe_index)).collect();
            let coords: HashSet<fanos_geometry::Triple> =
                seats.iter().filter(|(_, i)| i.is_some()).map(|(a, _)| *a).collect();
            let unbound = seats.iter().filter(|(_, i)| i.is_none()).count();
            // Two BOUND nodes on one point is shadowing, which §L0 forbids outright — so it is reported as
            // the finding it would be rather than averaged into the occupancy.
            let bound = seats.len() - unbound;
            if bound != coords.len() {
                println!(
                    "  !! {} bound nodes hold {} distinct points — shadowing, or `Health::address` is the \
                     PREFERRED point rather than the settled one. seats {seats:?}",
                    bound,
                    coords.len()
                );
            }
            let servable =
                fanos_geometry::servable_lines::<fanos_field::F4>(|p| coords.contains(&p.coords()));
            // **Does the built-in repair fire at all?** `apply` reacts to a contested seat by dialling the
            // other party — `Displaced` (we took the point) and `Superseded` (a better claim holds it) —
            // precisely so the two books exchange the claim neither has. But it can only react to a conflict
            // its OWN directory already knows about: a node that has never heard of the incumbent gets
            // `WriteOutcome::Bound`, seats on top of it, and tells nobody. These two counts separate "the
            // conflict was never detected" from "it was detected and the repair did not converge", which are
            // opposite defects and look identical in the seat table.
            let station_total = |st| -> u64 {
                fleet
                    .nodes()
                    .iter()
                    .flat_map(|n| n.client().driver_stations())
                    .filter(|o| o.station == st)
                    .map(|o| o.count)
                    .sum()
            };
            let taken = station_total(fanos_runtime::ports::stations::Station::DirectoryPointTaken);
            let superseded =
                station_total(fanos_runtime::ports::stations::Station::DirectorySeatSuperseded);
            let self_conn =
                station_total(fanos_runtime::ports::stations::Station::TransportSelfConnection);
            println!(
                "      repair: point_taken={taken} seat_superseded={superseded} self_connection={self_conn}"
            );
            println!(
                "n={count:>3}  n/N={:.2}  distinct={:>3} of {n_points}  unbound={unbound:>3}  \
                 servable_now={servable:>3} of {n_points}  {}",
                count as f64 / n_points as f64,
                coords.len(),
                if coords.len() >= floor { "AT OR ABOVE FLOOR" } else { "below floor" }
            );
            fleet.shutdown().await;
        }
    }

    /// **Does shadowing clear at the epoch, or is its PREVALENCE stationary?** — the question the
    /// within-epoch reading cannot answer and the design's own bound turns on.
    ///
    /// `driver`'s resettle arm accepts two nodes on one point deliberately: an established node must not
    /// move mid-epoch, so *"both then hold one point until the epoch turns"*. That bounds the life of any
    /// one collision. It says nothing about how many exist at once — and placement is **re-derived** from a
    /// fresh beacon each epoch, so every turn that clears a collision also mints a new draw that can make
    /// one. If the prevalence is stationary, "bounded by the epoch" describes each pair while the cell
    /// carries a steady population of doubly-held points, every one of them a routing fault at that point.
    ///
    /// The sibling measurement could not see this: it runs at `DEFAULT_EPOCH_PERIOD = 600 s` and observes
    /// `160 s`, so **no epoch turns at all** and every number it reports is within one. This one shortens
    /// the period so turns actually happen, and samples across them.
    ///
    /// Read `excess` (bound nodes minus the points they hold). Falling to `0` after each `epoch` step and
    /// staying there is the design working; oscillating about a level is a stationary fault population, and
    /// the level is the number the settling phase — designed, not built — would have to remove.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement — run with --ignored --nocapture"]
    async fn measure_whether_shadowing_clears_at_the_epoch_or_is_stationary() {
        use std::collections::{BTreeSet, HashSet};
        let roles = fanos_node::RoleSet {
            relay: true,
            rendezvous: true,
            ..fanos_node::RoleSet::default()
        };
        // **Long enough for the machinery that RESPONDS to a turn, and that bound is not the beacon's.**
        // The first version used `8 s`, which fits twenty turns into the run and is a measurement of the
        // wrong thing: `ROSTER_REFRESH = 15 s` and a roster needs `STABLE_BEFORE_BACKOFF = 3` looks to
        // settle, so placement was being re-derived about six times faster than anything could follow it.
        // The excess it reported (11–14 of 30) is what an out-of-spec period produces, and the contrast
        // proves it — the same fleet at the 600 s default sits at 1–6. A period must exceed the settling
        // cadence or the reading is about the fixture.
        //
        // `60 s` is four times the refresh floor and above the `3 × 15 s` a roster takes to settle, while
        // still fitting six turns into the run — which is what makes "did it clear at the turn" answerable
        // at all. The production default is `600 s`; nothing here claims a shorter one is safe, only that
        // the response has room.
        let period = Duration::from_secs(60);
        // **Two loads, because only one of them can show a repair.** At `n = 31` on 21 points the excess is
        // arithmetic: thirty-one nodes cannot hold twenty-one points without sharing, and the measured
        // excess of 12–14 is exactly `31 − points`. A mechanism that moves a loser onto a free point has no
        // free point to move it to, and the remainder belongs in sub-cells production cannot reach. At
        // `n = 16` five points are spare, so shadowing is *reducible* there and its level says whether the
        // repair works rather than whether the plane is full.
        for count in [16usize, 31] {
        let fleet =
            match NodeFleet::spawn_as_drawn_with_epoch::<fanos_field::F4>(count, Link::ideal(), roles, period)
                .await
            {
                Ok(f) => f,
                Err(e) => {
                    println!("fleet did not start — {e:?}");
                    return;
                }
            };
        println!("\n=== PG(2,4): 21 points, n={count} (n/N={:.2}), epoch period {period:?}", count as f64 / 21.0);
        for tick in 0..18u32 {
            tokio::time::sleep(Duration::from_secs(20)).await;
            let seats: Vec<(fanos_geometry::Triple, Option<u16>)> =
                fleet.nodes().iter().map(|n| (n.health().address, n.health().probe_index)).collect();
            let bound: Vec<fanos_geometry::Triple> =
                seats.iter().filter(|(_, i)| i.is_some()).map(|(a, _)| *a).collect();
            let points: HashSet<fanos_geometry::Triple> = bound.iter().copied().collect();
            let epochs: BTreeSet<u64> =
                fleet.nodes().iter().map(|n| n.assignment().epoch.get()).collect();
            let beacons: BTreeSet<u64> =
                fleet.nodes().iter().filter_map(|n| n.live_beacon().map(|(e, _)| e.get())).collect();
            println!(
                "t={:>3}s  bound={:>2}  points={:>2}  excess={:>2}  servable={:>2}  epochs={epochs:?}  \
                 beacons={beacons:?}",
                tick * 20,
                bound.len(),
                points.len(),
                bound.len() - points.len(),
                fanos_geometry::servable_lines::<fanos_field::F4>(|p| points.contains(&p.coords())),
            );
        }

        // **The correlation the sets above cannot show.** Two facts came out of this run: the excess never
        // reaches zero across twenty beacon turns, and the cell never agrees on an epoch — `{0, 1, 2}`
        // persists beside `19`. If the SAME nodes are both stuck and shadowed, the two are one loop rather
        // than two faults: a node sharing its point is unaddressable there, so it misses the beacon that
        // would re-derive its placement, so it keeps the point it is sharing. The design's remedy for
        // shadowing is "wait for the epoch"; that remedy would then be disabled by the very fault it
        // answers, for exactly the nodes that need it.
        let final_seats: Vec<(fanos_geometry::Triple, Option<u16>, u64, Option<u64>)> = fleet
            .nodes()
            .iter()
            .map(|n| {
                let h = n.health();
                (h.address, h.probe_index, n.assignment().epoch.get(), n.live_beacon().map(|(e, _)| e.get()))
            })
            .collect();
        let mut held: std::collections::BTreeMap<fanos_geometry::Triple, usize> =
            std::collections::BTreeMap::new();
        for (a, i, _, _) in &final_seats {
            if i.is_some() {
                *held.entry(*a).or_default() += 1;
            }
        }
        let newest = final_seats.iter().filter_map(|(_, _, _, b)| *b).max().unwrap_or(0);
        let (mut shad_stuck, mut shad_ok, mut solo_stuck, mut solo_ok) = (0u32, 0u32, 0u32, 0u32);
        for (a, i, _, b) in &final_seats {
            if i.is_none() {
                continue;
            }
            let shadowed = held.get(a).copied().unwrap_or(0) > 1;
            let stuck = b.unwrap_or(0) + 2 < newest;
            match (shadowed, stuck) {
                (true, true) => shad_stuck += 1,
                (true, false) => shad_ok += 1,
                (false, true) => solo_stuck += 1,
                (false, false) => solo_ok += 1,
            }
        }
        println!(
            "\ncorrelation at the end of the run (newest beacon {newest}; `stuck` = more than two epochs behind):\n  \
             shadowed & stuck {shad_stuck:>3}   shadowed & current {shad_ok:>3}\n  \
             alone    & stuck {solo_stuck:>3}   alone    & current {solo_ok:>3}"
        );
        fleet.shutdown().await;
        }
    }


    /// **What does verifying membership descriptors COST a real cell?** — the question a default turns on,
    /// and the one the simulator cannot answer.
    ///
    /// `require_self_certified_membership` refused 100 % of honest announcements until the producer landed.
    /// The instrument that measured that runs on the sans-I/O simulator, and it cannot reach this property:
    /// the producer is the **driver**, which re-signs at every reseat because the descriptor binds the
    /// *transport* coordinate and the reshuffle re-draws it. Only a fleet — real QUIC, the real reshuffle
    /// loop, a real beacon — puts the signer and the verifier in one run.
    ///
    /// **Both arms, read after a real boundary.** A cell that learns its membership at genesis and is never
    /// asked again would prove only that `compose_engine` installs the first descriptor; what has never been
    /// exercised is `Command::Descriptor` from the reshuffle loop, and that fires once per boundary. So each
    /// arm waits for the beacon to turn twice before it is read.
    ///
    /// The assertion is a **comparison**, not a threshold: this fixture's membership view is partial even
    /// ungated (five nodes on seven points, a 20 s epoch, and `known_peers` counts what a node has actually
    /// heard), so an absolute floor would be a number about the fixture. What a default needs to know is
    /// whether the check *takes* anything, and that is the difference between the arms.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement — run with --ignored --nocapture"]
    async fn measure_what_verifying_membership_descriptors_costs_a_real_cell() {
        use fanos_field::F2;
        let roles = fanos_node::RoleSet { relay: true, ..fanos_node::RoleSet::default() };
        // Short enough that two boundaries arrive inside the run, and the fixture's clock rather than the
        // production floor — `NodeFleet` does not enforce the latter, and this measures the reshuffle.
        let period = Duration::from_secs(20);
        let n = 5usize;
        let mut readings = Vec::new();
        for (label, require) in [("ungated", false), ("guarded", true)] {
            let overlay = fanos_node::config::OverlayChoices {
                require_self_certified_membership: require,
                ..fanos_node::config::OverlayChoices::default()
            };
            let fleet = match NodeFleet::spawn_with_overlay::<F2>(
                n,
                Link::ideal(),
                roles,
                period,
                overlay,
            )
            .await
            {
                Ok(f) => f,
                Err(e) => panic!("a fleet must start ({label}): {e:?}"),
            };
            // Two rounds, so the reading is of a cell that has re-signed rather than of one still on its
            // composition-time descriptor.
            let turned = fleet
                .until(|f| {
                    f.nodes()
                        .iter()
                        .filter_map(|x| x.live_beacon().map(|(e, _)| e.get()))
                        .min()
                        .unwrap_or(0)
                        >= 2
                })
                .await;
            let known: Vec<usize> = fleet.nodes().iter().map(|x| x.health().known_peers).collect();
            let claims: Vec<i64> =
                fleet.nodes().iter().map(|x| x.health().verified_claims.map_or(-1, |c| c as i64)).collect();
            let total: usize = known.iter().sum();
            println!(
                "{label:>8}: turned={turned}  known_peers={known:?} (sum {total} of {})  claims={claims:?}",
                n * (n - 1)
            );
            readings.push(total);
            fleet.shutdown().await;
        }
        let [ungated, guarded] = readings[..] else {
            panic!("both arms must have run — the loop above has exactly two");
        };
        assert!(ungated > 0, "the ungated arm learned nothing — the measurement has no baseline");
        assert!(
            guarded > 0,
            "verifying descriptors still costs the cell ALL of its membership ({guarded} learned edges \
             against {ungated} ungated). Either nothing produces the signed descriptor, or what it produces \
             is not what the engine rebuilds to check it — and after a boundary that also means the \
             re-signing path is not running."
        );
    }

    /// **Is the plane below its line floor because placement is broken, or because the FIXTURE's epoch is
    /// tight?** — the question that decides whether the numbers in `docs/testnet.md` are about a deployment.
    ///
    /// `Node::start` warns when a walk does not fit inside a period, and states the arithmetic: a contested
    /// node takes up to `q + 1` steps and a step cannot be faster than a new seat becomes known, so
    /// `PG(2,2)` needs `3 × 15 s = 45 s`. The neighbouring measurement runs a **60 s** epoch — valid, and
    /// only **1.33×** the walk. Production's default is **600 s**, or 13×. A cell whose walk barely fits is
    /// a cell that re-derives placement almost as fast as it can resolve it, and every below-floor sample
    /// this fixture reports would then be a property of the fixture.
    ///
    /// So: one load — `n = 10`, the sized one a deployment is told to run — at two epochs, everything else
    /// identical. If the below-floor share collapses at the longer period, the operator-facing number is the
    /// long one and the fixture has been measuring its own clock.
    ///
    /// ## Result, 2026-08-19 — REFUTED, and the refutation is what makes the other numbers usable
    ///
    /// | epoch | margin over the walk | below floor | mean points |
    /// |---|---|---|---|
    /// | 60 s | 1.3× | **25 %** (10/40) | 6.0 |
    /// | 180 s | 4.0× | **28 %** (11/40) | 5.7 |
    ///
    /// **Three times the margin buys nothing.** So the below-floor share is not an artefact of a fixture
    /// whose epoch barely fits its walk, and the 25 % that `docs/testnet.md` gives an operator is about
    /// placement rather than about this clock. It also reproduces the neighbouring measurement's 25 % at a
    /// different sampling interval (15 s here against 10 s there), which rules out the sampling phase too.
    ///
    /// **What it leaves.** Time is not the constraint, and neither is knowledge (the claim book is complete
    /// at genesis and refills every epoch) nor permission (a contested seat is no longer frozen). What has
    /// not been ruled out is the **geometry of the walk itself**: `probe_point` confines a node to the
    /// `q + 1` points of one line — 3 of 7 here — and `probe_point`'s own doc records that plane-wide
    /// probing was built, measured and reverted for a stated security reason. Whether ten line-confined
    /// walks can cover six of seven points is a question about the draw, answerable by enumerating the real
    /// walk rather than by simulating a cell.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement — run with --ignored --nocapture"]
    async fn measure_whether_the_epochs_margin_over_the_walk_is_what_holds_the_plane_short() {
        use fanos_field::F2;
        use std::collections::HashSet;
        let roles = fanos_node::RoleSet {
            relay: true,
            rendezvous: true,
            ..fanos_node::RoleSet::default()
        };
        let n_points = fanos_geometry::Plane::<F2>::N as usize;
        let floor = fanos_geometry::points_serving_every_line(
            fanos_geometry::Plane::<F2>::LINE_SIZE as usize,
        );
        let sized = fanos_geometry::members_for_a_covered_plane(
            fanos_geometry::Plane::<F2>::LINE_SIZE as usize,
        );
        // The walk this plane owes, from the same terms the node's own warning uses.
        let walk = (fanos_geometry::Plane::<F2>::LINE_SIZE as u64) * 15;
        for period_s in [60u64, 180] {
            let period = Duration::from_secs(period_s);
            let fleet = match NodeFleet::spawn_as_drawn_with_epoch::<F2>(
                sized,
                Link::ideal(),
                roles,
                period,
            )
            .await
            {
                Ok(f) => f,
                Err(e) => {
                    println!("epoch {period_s}s: fleet did not start — {e:?}");
                    continue;
                }
            };
            println!(
                "\n=== n={sized} on {n_points} points, epoch {period_s}s = {:.1}x the {walk}s walk",
                period_s as f64 / walk as f64
            );
            let (mut below, mut samples, mut pts_total) = (0usize, 0usize, 0usize);
            for tick in 0..40u32 {
                tokio::time::sleep(Duration::from_secs(15)).await;
                let health: Vec<_> = fleet.nodes().iter().map(fanos_node::Node::health).collect();
                let points: HashSet<fanos_geometry::Triple> = health
                    .iter()
                    .filter(|h| h.probe_index.is_some())
                    .map(|h| h.address)
                    .collect();
                samples += 1;
                pts_total += points.len();
                if points.len() < floor {
                    below += 1;
                }
                if tick % 8 == 0 {
                    println!(
                        "  t={:>4}s  points={:>2}  {}",
                        tick * 15,
                        points.len(),
                        if points.len() >= floor { "AT/ABOVE FLOOR" } else { "BELOW FLOOR" }
                    );
                }
            }
            println!(
                "  epoch {period_s}s: below floor in {below}/{samples} samples ({:.0}%), mean points {:.1}",
                100.0 * below as f64 / samples as f64,
                pts_total as f64 / samples as f64
            );
            fleet.shutdown().await;
        }
    }

    /// **Does the SHIPPED plane stay packed across an epoch boundary?** — the same question the two
    /// measurements above ask, asked on the plane a deployment actually runs.
    ///
    /// Both of them run `PG(2,4)`, and `NodeConfig::plane_order`'s default is **2**. That is not a detail:
    /// a Fano line holds `q + 1 = 3` points, so a node's whole probe walk is three long and
    /// `probe_bound` gives it three rounds before `commit_seat` freezes it where it stands. The `PG(2,4)`
    /// results (genesis packs 11 on 11, the first boundary leaves 8 points and an excess of 6) are
    /// therefore a measurement of a *five*-point walk with five spare seats, and neither number transfers.
    /// Every deployment this project documents — `docs/testnet.md`'s seven founding operators — is the
    /// configuration nobody has measured.
    ///
    /// ## Pre-registered, so the run can refute
    ///
    /// * `N = 7` points, `LINE_SIZE = 3`, viability floor `points_serving_every_line(3) = 6`. The mixnet
    ///   needs **6 of 7** points occupied and consensus **5 of 7** (`CellParams::FANO` quorum over the
    ///   point count), so on this plane a single doubly-held point is one step from switching the mixnet
    ///   off and two from stalling the chain. There is no margin to average over.
    /// ⚠️ **The second load was 10 when every table below was measured, and the constant now says 16.**
    /// `members_for_a_covered_plane` was corrected on 2026-08-19 (its `3/2` was applied to the point count
    /// rather than to the coupon-collector expectation), so a fresh run of this fixture measures a *larger*
    /// cell than the numbers recorded here and they are not comparable to it. Re-run before quoting.
    ///
    /// * `n = 7` (`n/N = 1.0`) and `n = 10` — the second **read from
    ///   `fanos_geometry::members_for_a_covered_plane`** rather than chosen, since a load factor picked by
    ///   hand is exactly the kind of constant this project refuses. At that load three nodes cannot be
    ///   seated at all — there are seven points — so `unbound ≈ 3` is arithmetic, not a fault, and the
    ///   number to read is `excess` among the **bound**.
    /// * **The prediction**: genesis packs (sequential arrival resolves against a settled state), and every
    ///   boundary unpacks, as it does at `q = 4`. If instead `excess` returns to `0` within an epoch, the
    ///   `PG(2,4)` result does not generalise downward and the shipped default is not affected by it.
    ///
    /// ## The discriminating observable, and why it is this one
    ///
    /// `Health::verified_claims` is the size of the driver's claim book — *the input coordinate resolution
    /// runs on*. `fanos_vrf::settle_index` is **one-shot and order-independent given the contending
    /// claims**: a claim to `p` is `(probe_index_of(their_output, p), their_output)`, a function of the
    /// peer's VRF output alone, so with complete knowledge every node computes the same assignment with no
    /// negotiation and no iteration. The book is cleared at every boundary by design (a claim proves a
    /// placement for one epoch only) and refills **only from peers this node has actually met**.
    ///
    /// So the two candidate explanations separate cleanly, and nothing else in the seat table can tell them
    /// apart:
    ///
    /// | if after a turn | then |
    /// |---|---|
    /// | `claims → n−1` quickly **and** `excess > 0` | the rule is wrong, or the walk budget is too short |
    /// | `claims` stays low **and** `excess > 0` | the rule is starved of its input — a propagation defect |
    ///
    /// Sampled every `10 s` against a `60 s` period, so six samples fall inside each epoch: "did it clear
    /// before the next turn" is a question about the shape within one epoch and a per-epoch reading cannot
    /// answer it.
    ///
    /// ## Result, 2026-08-18 — 36 samples per load, `Link::ideal()`
    ///
    /// | | `n = 7` (`n/N = 1.00`) | `n = 10` (`n/N = 1.43`) |
    /// |---|---|---|
    /// | excess | mean **1.7**, zero in 5 of 36 | mean **4.2**, zero in **0** of 36 |
    /// | occupied points | mean 5.1 of 7 | mean 5.5 of 7 |
    /// | servable lines | mean 6.5 of 7 | mean 6.2 of 7 |
    /// | **below the viability floor** | **50 % of samples** | **53 %** |
    /// | claim book | mean 3.0 of 6 peers | mean 6.0 of 9 |
    ///
    /// **The shipped default plane sits below its own line-viability floor about half the time**, and
    /// sizing the cell up does not fix it — `n = 10` is no better and never once reaches `excess = 0`.
    ///
    /// **Genesis does not pack here.** The very first sample at `n = 7` reads 5 points and `excess = 2`,
    /// where `PG(2,4)` reaches a perfect packing before its first boundary. So the `PG(2,4)` result does not
    /// transfer downward — it is *optimistic* about the plane a deployment actually runs — and the two
    /// planes differ in the direction that matters: a Fano line is three points, so a node's whole probe
    /// walk is three long and `probe_bound` gives it three rounds before `commit_seat` freezes it.
    ///
    /// **The discriminator answered the question it was built for — and then refuted the answer.** The claim
    /// book never reached `n − 1` at either load: half the contenders at `n = 7`, two thirds at `n = 10`,
    /// 14 % of readings at *zero*. That is the starved-input arm of the table above, so three
    /// one-directional claim losses were found and fixed (a node whose new point equalled its old one never
    /// re-announced; a claim from a peer ahead of this node's beacon was verified-as-unjudgeable and
    /// dropped; the claim book adopted an epoch *after* the beacon window did).
    ///
    /// **The book filled — samples of 8–9 of 9 — and every node still read `probe_index = 0` while ten of
    /// them shared four points.** Knowledge was never the binding constraint *at that moment*, and making it
    /// complete made the plane *worse*, which is only possible if knowledge itself was ending something. It
    /// was: this loop wakes on **every recorded claim** and spent a round on each, while `may_walk`'s bound
    /// is derived for **steps** along the walk. A node with nine peers burned its whole budget on the first
    /// three claims to arrive and committed its seat before it had a reason to move.
    ///
    /// ⛔ **And the claim column in the tables below is a MEAN over a cycle that resets, so read the
    /// plateaus instead.** The book is cleared at every boundary and refills within one 10 s tick, then does
    /// not change for the rest of the epoch — five identical readings, then a step. Grouping the run into
    /// those plateaus says something the mean hides completely:
    ///
    /// | | genesis plateau | later plateaus |
    /// |---|---|---|
    /// | `n = 7`, 6 peers | 6.0 / 6.6 / 6.0 — **complete** | 4.0, 5.9, 3.4, 1.3 · 4.6, 5.1, 4.7, 4.6, 2.3 · 4.4, 5.3, 2.6, 3.9, 2.1 |
    /// | `n = 10`, 9 peers | 8.9 / 9.2 / 9.0 — **complete** | 7.9, 5.4, 3.4, 2.0, **0.3** · 6.1, 5.8, 6.3, 7.1, 5.5 · 6.8, 7.2, 5.4, 6.5, 4.3 |
    ///
    /// **Every node knows every peer's claim at genesis and never again.** After the first boundary the book
    /// refills to somewhere between a half and three quarters, and in one of three runs it **ratchets down**
    /// — 8.9 → 7.9 → 5.4 → 3.4 → 2.0 → 0.3 — until placement is running on no knowledge at all. That is not
    /// a static cost: the same rotation that orphans the connection cache (139 k misses a run) removes a
    /// little more reach each epoch, and the ask on `MemberJoined` can only reach peers this node can still
    /// address. **This is the open half of the placement problem**, and it is a decay rather than a floor.
    ///
    /// ## Three runs, same fixture
    ///
    /// | | `n = 7` below floor | walked | `n = 10` below floor | walked | `n = 10` points |
    /// |---|---|---|---|---|---|
    /// | as shipped | 50 % | 17/252 | 53 % | 6/360 | 5.5 |
    /// | + the three claim fixes | 100 % | 24/252 | 67 % | 1/360 | 5.2 |
    /// | + the budget spent on steps | 86 % | 10/252 | **19 %** | **49/360** | **6.1** |
    ///
    /// ⛔ **CORRECTION — the outcome column is not reproducible, and the box was not quiet.** A fourth run of
    /// the **identical** build read `n = 10` at **69 %** below floor against the third run's 19 %, and
    /// `n = 7` at 67 % against 86 %. The difference between those two runs is not the code: the fourth was
    /// taken while a `cargo build` and a `cargo test` competed for the same four cores this fixture asks for
    /// (`worker_threads = 4`). That is this project's own recorded lesson — *measure on a quiet box or not
    /// at all* — paid for again.
    ///
    /// **What survives the variance is the mechanism, and it survives cleanly.** `walked` — samples in which
    /// any node sat at a probe index above zero — reads **6 and 1** before the budget fix and **49 and 66**
    /// after it, across two independent runs each. An order of magnitude, in the same direction, twice. The
    /// budget fix is justified by *that*, not by the packing column.
    ///
    /// **Answered on an idle machine, and it does separate the arms.** Two paired runs of one build, with
    /// nothing else running, plus a third of the preceding build:
    ///
    /// | | `n = 7` below floor | points | `n = 10` below floor | points |
    /// |---|---|---|---|---|
    /// | run 5 (pre-descriptor) | 86 % | 5.1 | 44 % | 5.6 |
    /// | quiet A | 86 % | 4.5 | **25 %** | 5.9 |
    /// | quiet B | 86 % | 5.1 | **25 %** | 6.1 |
    ///
    /// `n = 7` reads **86 %** in all three; `n = 10` reads **25 %** in both paired runs. Those are the
    /// numbers an operator can be given. The earlier 19 %-against-69 % spread was the contended box, not the
    /// distribution.
    ///
    /// **`outranked` came back with the signed descriptor, and asking for the claim removed it again.** It
    /// read 0 at both loads before the descriptor, then 914 and 3 251 at `n = 10` with it — a node can commit
    /// while uncontested and be outranked *afterwards*, so the contested-seat rule was intact and the window
    /// it leaves open had widened. Wiring `Wake::Meet` — a member learned by announcement is asked for its
    /// claim when the book holds none for that point — closes it: **0 in both paired runs**.
    ///
    /// | | `n = 7` below | `n = 10` below | `n = 10` book | `outranked` |
    /// |---|---|---|---|---|
    /// | baseline A / B | 86 % / 86 % | 25 % / 25 % | 5.1 / 5.3 of 9 | 914 / 3 251 |
    /// | + ask C / D | 100 % / 75 % | 31 % / 17 % | 4.4 / 6.3 of 9 | **0 / 0** |
    ///
    /// **And nothing else moved.** Occupancy and the book size are unchanged within the spread — 24 % mean
    /// against 25 %, a book that goes both ways — so the change is justified by the window it closes, not by
    /// the packing column. Said explicitly because the temptation with a cheap change is to credit it with
    /// the run it happened to land in.
    ///
    /// ## The third layer, and the instrument is what found it
    ///
    /// Adding the station line above answered in one run what the seat table could not answer in three.
    /// At genesis, with claim books **complete** (6 of 6 peers), it read `committed = 7` and
    /// `DirectorySeatOutranked = 386`: every node had closed its settling window, every node knew a better
    /// claim held its point, and not one of them was permitted to move. Over a whole run the outranked count
    /// reached **12 421** at `n = 7` and **21 469** at `n = 10`.
    ///
    /// The cause is two facts kept apart. `Client::commit_seat` closes the window on *"I can read my own
    /// record"*, which proves the cell **can** read this node and says nothing about whether another node is
    /// standing on its point — and two contenders share one `cap_slot` by construction, so each of them
    /// transiently reads *itself* there and both commit. After that the established-node rule forbids the
    /// very move that would resolve the contest. **A commit is now refused while a better claim holds the
    /// seat**, which costs the rule nothing: a node another node also sits on is one nothing above it can
    /// have derived anything from — its record is the one being overwritten.
    ///
    /// | | `outranked` | `self_connection` | `committed` |
    /// |---|---|---|---|
    /// | before, `n = 7` / `n = 10` | 12 421 / 21 469 | 2 075 / 1 030 | 32 / 43 |
    /// | after | **0 / 0** | 703 / 477 | 26 / 21 |
    ///
    /// Zero is categorical, not a shift within the noise: the frozen-and-outranked state is **gone**, and
    /// self-connections — two nodes each resolving one point to themselves — are halved with it. The
    /// occupancy column moved 5.3 → 5.6 at `n = 10` and 5.2 → 5.1 at `n = 7`, i.e. inside the variance above,
    /// and is **not** claimed.
    ///
    /// ### How to use this fixture, so the next reader does not pay for it again
    ///
    /// 1. **Nothing else may run.** It asks for four worker threads and drives real timers — `HELLO_DEADLINE`,
    ///    the roster refresh, the epoch period — so a competing `cargo` build does not slow it down evenly,
    ///    it changes what the cell does.
    /// 2. **Two runs per arm, minimum**, and report both. One run of this fixture is a sample of one from a
    ///    distribution wide enough to swallow any change worth making.
    /// ### What the station line said about the transport, measured 2026-08-19
    ///
    /// | | `conns.cache_miss` | `directory.entry_fallback` (frame **dropped**) | `stale_coordinate` | `repeat_ignored` |
    /// |---|---|---|---|---|
    /// | `n = 7` | **139 269** | **77** | 10 | 0 |
    /// | `n = 10` | **45 217** | **71** | 17 | 0 |
    ///
    /// The send ladder asks for a coordinate it has no connection filed under **tens of thousands of times
    /// per run**, and frames actually lost are ~75 — so the ladder's lower rungs recover almost everything.
    ///
    /// ⛔ **`cache_miss` is NOT a measure of orphaning, and reading it as one was a mistake.** A miss fires
    /// whenever nothing is filed at the coordinate asked for, and on a 7-point plane with 5 occupied that
    /// includes every send to a point *this node has never met anyone at* — which
    /// [[transport-state-keyed-by-a-rotating-value]] names as the competing explanation and says the
    /// discriminator is the station's `line` (the coordinate refused), a field this fixture does not print.
    /// Keying the cache by identity did **not** move the count (139 k / 298 k before, 306 k / 216 k after),
    /// which is what a counter measuring something else looks like.
    ///
    /// ⛔ **And identity-keying was BUILT, MEASURED and REVERTED — it regresses the sized load.** Two runs
    /// per arm, idle machine, `n = 10` below the floor: **17 % / 17 %** with the coordinate key against
    /// **56 % / 36 %** with the identity key. The arms do not overlap.
    ///
    /// The mechanism is the direction each key fails in. A coordinate key fails **safe**: a peer that moved
    /// leaves nothing filed at its old point, so the lookup misses, the ladder falls through to a dial, and
    /// the dial reaches whoever is actually there. An identity key with a coordinate index fails **unsafe**:
    /// `seat[old_point]` still names the departed peer until something removes it, so the lookup *hits* and
    /// the frame goes to the wrong node. **A wrong hit is worse than a miss**, and the orphaning the key was
    /// meant to prevent is what kept the old index honest for free.
    ///
    /// So the remedy `transport-state-keyed-by-a-rotating-value` recommends needs a third piece it does not
    /// name: the seat index has to be **invalidated when it goes stale** — the coordinate is only meaningful
    /// within an epoch, and nothing in the transport expires it at a boundary. Do not re-attempt the key
    /// without that.
    ///
    /// `repeat_ignored = 0` settles a neighbouring question in passing: `members` is cleared at every
    /// boundary, so an announcement really does repeat each epoch and the flood is not being suppressed.
    ///
    /// 3. **Read `walked` and the station line first.** They say whether the mechanism under test is running
    ///    at all — `outranked` says nodes know they lost, `committed` says whether their window closed,
    ///    `rejudged` says whether the retention path is yielding — and each of those is a count of events
    ///    rather than a state sampled at an instant, so none of them is at the mercy of *when* the tick fell.
    ///
    /// **`n = N` exactly is under-sized, and the argument for that is the derivation rather than this
    /// fixture.** Seven nodes on seven points have **no spare seat**: a node that walks off its preferred
    /// point takes one another node prefers, so resolution cascades with nowhere to end.
    /// `members_for_a_covered_plane`'s own table used to price it at 87 % against 99.7 %, and **that table
    /// was refuted on 2026-08-19**: enumerating the shipping arbitration at complete knowledge gives 32.7 %
    /// at `M = N` and 74.5 % at `M = 1.5N` on this plane. The live 25 %-below-floor reading at `n = 10` is
    /// the *same number* as that ceiling's 74.5 % clearing — so this fixture is not falling short of the
    /// geometry, it is sitting on it.
    ///
    /// What is still open at 19 %: claims reach only direct connection partners, and in a projective plane
    /// every two lines meet, so every node contends for exactly one point of every other node's line.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement — run with --ignored --nocapture"]
    async fn measure_whether_the_shipped_fano_plane_stays_packed_across_a_boundary() {
        use std::collections::{BTreeSet, HashSet};
        use fanos_field::F2;
        let roles = fanos_node::RoleSet {
            relay: true,
            rendezvous: true,
            ..fanos_node::RoleSet::default()
        };
        let n_points = fanos_geometry::Plane::<F2>::N as usize;
        let floor = fanos_geometry::points_serving_every_line(
            fanos_geometry::Plane::<F2>::LINE_SIZE as usize,
        );
        // The same period the `PG(2,4)` measurement justified: above `ROSTER_REFRESH * STABLE_BEFORE_BACKOFF`
        // so the machinery that responds to a turn has room, and short enough that turns actually happen.
        let period = Duration::from_secs(60);
        println!("PG(2,2): {n_points} points, line size {}, viability floor {floor}", fanos_geometry::Plane::<F2>::LINE_SIZE);
        // Read, not chosen: the sizing constant the geometry crate derives for this plane.
        let sized = fanos_geometry::members_for_a_covered_plane(
            fanos_geometry::Plane::<F2>::LINE_SIZE as usize,
        );
        for count in [n_points, sized] {
            let fleet = match NodeFleet::spawn_as_drawn_with_epoch::<F2>(count, Link::ideal(), roles, period).await {
                Ok(f) => f,
                Err(e) => {
                    println!("n={count}: fleet did not start — {e:?}");
                    continue;
                }
            };
            println!(
                "\n=== PG(2,2): {n_points} points, n={count} (n/N={:.2}), epoch period {period:?}",
                count as f64 / n_points as f64
            );
            for tick in 0..36u32 {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let health: Vec<_> = fleet.nodes().iter().map(fanos_node::Node::health).collect();
                let bound: Vec<fanos_geometry::Triple> =
                    health.iter().filter(|h| h.probe_index.is_some()).map(|h| h.address).collect();
                let points: HashSet<fanos_geometry::Triple> = bound.iter().copied().collect();
                // **`assigned` is the epoch of each node's last ROLE ASSIGNMENT, not its engine epoch**, and
                // the difference is worth the longer name. `Node::assignment` reads `self_org.assigned`, which
                // the role loop writes only when it does **not** withhold — and it withholds precisely while
                // it cannot find its own advertisement in the roster it scanned, which is what a shadowed seat
                // looks like from inside. So a spread here is a **shadowing** reading, not a disagreement
                // about the clock; `beacons` is the clock, and it is usually a single value while this is not.
                // Read as "epochs" it says the cell cannot agree on the time, which is a different and much
                // larger claim, and one this field cannot support.
                let assigned: BTreeSet<u64> =
                    fleet.nodes().iter().map(|n| n.assignment().epoch.get()).collect();
                let beacons: BTreeSet<u64> =
                    fleet.nodes().iter().filter_map(|n| n.live_beacon().map(|(e, _)| e.get())).collect();
                // The discriminator. `None` means the node has no self-certifying identity and so no book at
                // all, which is a different statement from an empty one and is printed as such.
                let claims: Vec<i64> =
                    health.iter().map(|h| h.verified_claims.map_or(-1, |c| c as i64)).collect();
                let indices: Vec<i64> =
                    health.iter().map(|h| h.probe_index.map_or(-1, i64::from)).collect();
                let servable = fanos_geometry::servable_lines::<F2>(|p| points.contains(&p.coords()));
                // **The second discriminator, and it separates the two ways a node stops walking.** A node
                // that has not moved is either uninformed (its book lacks the claim that beats it) or
                // *forbidden* — `DirectorySeatOutranked` is raised exactly when the winning claim IS in its
                // own book and the established-node rule refuses the move, and `SeatCommitted` counts the
                // windows that closed. Without these two the seat table cannot tell "nobody told it" from
                // "it was told and may not act", which are opposite defects with opposite fixes — and the
                // first round of fixes here was spent on the wrong one of them.
                let station = |st: fanos_runtime::ports::stations::Station| -> u64 {
                    fleet
                        .nodes()
                        .iter()
                        .flat_map(|n| n.client().driver_stations())
                        .filter(|o| o.station == st)
                        .map(|o| o.count)
                        .sum()
                };
                println!(
                    "          committed={} outranked={} taken={} superseded={} self_conn={} rejudged={} \
                     withheld={} cache_miss={} stale_coord={} repeat_ignored={} dropped={}",
                    station(fanos_runtime::ports::stations::Station::SeatCommitted),
                    station(fanos_runtime::ports::stations::Station::DirectorySeatOutranked),
                    station(fanos_runtime::ports::stations::Station::DirectoryPointTaken),
                    station(fanos_runtime::ports::stations::Station::DirectorySeatSuperseded),
                    station(fanos_runtime::ports::stations::Station::TransportSelfConnection),
                    station(fanos_runtime::ports::stations::Station::HelloRejudged),
                    // **What shadowing costs one layer up.** The role loop withholds while it cannot find
                    // its own advertisement, which is exactly a shadowed seat seen from inside — and a node
                    // shadowed since genesis has *never* been assigned, so it holds the default assignment
                    // and serves nothing. One shadowed later keeps its previous roles, which is a different
                    // cost (stale) from the same cause. Counted here because the transport-level tables
                    // above cannot price either.
                    station(fanos_runtime::ports::stations::Station::AssignmentWithheld),
                    // **Why a claim this node ASKED for did not arrive.** `Wake::Meet` emits a frame at the
                    // coordinate an announcement named, and every address this node holds is keyed by that
                    // same rotating coordinate — so the ask can only reach a peer whose *current* seat is
                    // already in the local tables. These two separate the outcomes: `cache_miss` is "no
                    // connection was filed there at all", `stale_coord` is "we dialled and the peer that
                    // answered proved a different seat", i.e. our entry rotated out from under us.
                    station(fanos_runtime::ports::stations::Station::ConnCacheMiss),
                    station(fanos_runtime::ports::stations::Station::DirectoryStaleCoordinate),
                    // And whether an announcement is even repeated each epoch — `members` is cleared at the
                    // boundary, so it should be, and a high count here would mean it is not.
                    station(fanos_runtime::ports::stations::Station::MembershipRepeatIgnored),
                    // **And whether a miss costs delivery.** A cache miss falls to the next rung, which
                    // usually dials; this is the LAST rung — no address, no cached connection, no hub — and
                    // its own doc says it is *"zero on a healthy node"* because the frame is dropped. The
                    // two together separate "the ladder works harder" from "the cell loses frames", which
                    // is the difference between tidying the key and having to.
                    station(fanos_runtime::ports::stations::Station::DirectoryEntryFallback),
                );
                println!(
                    "t={:>3}s  bound={:>2}  points={:>2}  excess={:>2}  servable={:>2}/{n_points}  {}  \
                     assigned={assigned:?} beacons={beacons:?}\n          claims={claims:?} probe_index={indices:?}",
                    tick * 10,
                    bound.len(),
                    points.len(),
                    bound.len() - points.len(),
                    servable,
                    if points.len() >= floor { "AT/ABOVE FLOOR" } else { "BELOW FLOOR" },
                );
            }
            fleet.shutdown().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "measurement — run with --ignored --nocapture"]
    async fn measure_roster_convergence_with_collisions_allowed() {
        // THE COMBINATION ITEM 2 TURNS ON, and which no other test covered: a draw that is allowed to **collide**, plus
        // roster convergence. Two separate measurements each answered half of it — `spawn_as_drawn` reaches 7/7 distinct
        // addresses, and `spawn` (injective draw) reaches full rosters `[7; 7]` — but a cell that has to *resolve* a
        // collision and *then* propagate its roster is the case the injective draw in `NodeFleet::spawn` exists to avoid.
        //
        // While that guard is there, item 2 is not closed. It goes when this passes.
        use fanos_field::F4;
        use fanos_node::RoleSet;

        let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
        for trial in 0..2 {
            // Force the condition rather than hope for it. `spawn_as_drawn` takes the draw as it comes, so a trial can spend
            // its whole budget on an injective draw with nothing to resolve — which is exactly what trial 0 did on the first
            // run, and a measurement that can silently pass by never exercising its path is not a measurement.
            let fleet = loop {
                let fleet = NodeFleet::spawn_as_drawn::<F4>(7, Link::ideal(), roles).await.expect("fleet starts");
                let drawn: HashSet<_> = fleet.nodes().iter().map(|n| n.health().address).collect();
                if drawn.len() < fleet.nodes().len() {
                    break fleet; // at least two nodes drew the same point
                }
                fleet.shutdown().await;
            };
            let trace = fleet.observe(40, Duration::from_secs(4), fanos_node::Node::assignment).await;
            let coords: Vec<fanos_geometry::Triple> = fleet.nodes().iter().map(|n| n.health().address).collect();
            let distinct: HashSet<fanos_geometry::Triple> = coords.iter().copied().collect();
            let idx: Vec<_> = fleet.nodes().iter().map(|n| n.health().probe_index).collect();
            // The observables that separate the candidate causes for an unbound node (`index = None`), because "it never
            // heard of its rival" and "it heard and had nowhere to go" look identical in the index alone:
            //   * `claims` — how many peers' coordinate claims this node verified. Low ⇒ it never learned of the contender.
            //   * `peers`  — how many peers it knows at all, which bounds the above.
            //   * `route`  — how many points it can actually route to (#249): ranked bindings in its dial table.
            // A node with high `claims` and `index = None` heard everything and still failed to place, which is the
            // line-restricted walk being exhausted (or the settle path declining to bind at all).
            //
            // `route` is the third reading because the first two cannot separate the case that matters most here.
            // `claims` counts what the CLAIM BOOK verified; `route` counts what the DIAL TABLE will resolve, and the
            // arbitration rule can refuse a write whose claim verified fine (`WriteOutcome::Superseded`).
            //
            // **The reading this comment used to carry was stronger than its metrics.** It said a node with
            // `claims` high and `route` low "heard its rivals and cannot reach them", and neither number can
            // say that: `route` counts *ranked* bindings while the send ladder resolves without consulting
            // rank, so it under-counts reach; `peers` counts the dial book including seeds no handshake
            // confirmed, so it over-counts. The gap between two numbers that are wrong in opposite
            // directions cannot mean "cannot reach".
            //
            // `deliver` is the quantity that can: a ranked binding **or** a live connection, the union. Its
            // decisive case is this fixture's own bootstrap node, which dialled nobody — `peers` and `route`
            // both read zero while every other node holds a connection to it and it answers each one.
            let claims: Vec<_> = fleet.nodes().iter().map(|n| n.health().verified_claims).collect();
            let peers: Vec<_> = fleet.nodes().iter().map(|n| n.health().known_peers).collect();
            let route: Vec<_> = fleet.nodes().iter().map(|n| n.health().routable_points).collect();
            let deliver: Vec<_> = fleet.nodes().iter().map(|n| n.health().deliverable_points).collect();
            // The FIFTH reading, and it says what the fourth is worth (#289): a roster count from an incomplete
            // scan is a race the next epoch settles; the same count from a complete one is the cell deciding on
            // an input its members do not share. Without it `agreed=None` names no cause.
            let complete: Vec<_> = fleet.nodes().iter().map(|n| n.assignment().complete).collect();
            fleet.shutdown().await;
            let roster = trace.map(|a| a.roster);
            println!(
                "trial {trial}: {} distinct of 7, index {idx:?} claims {claims:?} route {route:?} deliver {deliver:?} peers {peers:?} complete {complete:?} → final rosters {:?} agreed={:?}",
                distinct.len(),
                roster.last(),
                roster.stable_agreement_at().map(|d| d.as_secs())
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
            fleet.shutdown().await;
            let roster = trace.map(|a| a.roster);
            println!(
                "occupancy {n}/7: final rosters {:?}  agreed={:?}  known_peers={peers:?}",
                roster.last(),
                roster.stable_agreement_at().map(|d| d.as_secs())
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
        // **A short epoch, or this probe cannot ask its own question.** It exists to see whether the roster
        // grows at LATER epochs, and it observed 60 s against `DEFAULT_EPOCH_PERIOD = 600 s` — zero epoch
        // boundaries, so the answer was never in the window. `ROSTER_REFRESH * 2` is the node tier's own
        // choice (`cell_diagnosis.rs`, `role_roster.rs`) and sits well above `minimum_epoch_period`.
        let fleet = NodeFleet::spawn_with_epoch::<F4>(3, Link::ideal(), roles, fanos_node::role_loop::ROSTER_REFRESH * 2)
            .await
            .expect("fleet starts");
        for tick in 0..12 {
            let rosters: Vec<usize> = fleet.nodes().iter().map(|n| n.assignment().roster).collect();
            let epochs: Vec<String> =
                fleet.nodes().iter().map(|n| format!("{:?}", n.assignment().epoch)).collect();
            let peers: Vec<usize> = fleet.nodes().iter().map(|n| n.health().known_peers).collect();
            println!("t={:>4}s  rosters={rosters:?}  epochs={epochs:?}  known_peers={peers:?}", tick * 5);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        fleet.shutdown().await;
    }

    /// **What a five-node cell actually assigns, under latency and without it** (#250).
    ///
    /// Both worlds in one run, because the question is a comparison and two separate test runs are two
    /// separate hosts an hour apart. `Link::ideal()` is all zeroes; `Link::default()` is 20 ms of latency and
    /// 10 ms of jitter, with **no loss on either side**.
    ///
    /// It exists because three stories about the fleet assertion died here, each to one run:
    ///
    /// * *the trajectory freezes in the gap before the first assignment* — refuted: the withheld scan is `0`,
    ///   so `withhold` is never reached;
    /// * *the address book is the frozen thing* — refuted: under `ideal` the book stands at `[1, 2, 5, 5, 5]`
    ///   from five seconds in and never moves again, and four of five nodes are assigned anyway. A frozen
    ///   book is the healthy case too, so it cannot be the cause. An earlier run of this very probe on the
    ///   WRONG world (`F2`, `relay + storage`) had both links converge, which is what exposed the mistake;
    /// * *epoch skew mismatches the slot-keyed records* — refuted: every epoch is `0` and no node has a
    ///   beacon.
    ///
    /// What it reports instead, on the real world (`F4`, `relay + rendezvous`, five nodes):
    ///
    /// ```text
    /// ideal    roster=[4, 4, 5, 5, 5]  has_role=[false, true, true, true, true]   roles: 4×RoleSet(17), 1×0
    /// default  roster=[4, 3, 4, 2, 4]  has_role=[false, false, false, false, false]  roles: 5×RoleSet(0)
    /// ```
    ///
    /// Two things worth separating. Under `ideal` one member is assigned **nothing**, stably, on a roster of
    /// four — so "every member has a role" is not a property this cell has even at zero latency. Under
    /// `default` **no member is assigned anything at all** for a full minute, while assignments are being
    /// produced (the roster moves, and it even shrinks: 5 → 4 on one node). Nothing reports either: the
    /// stations plane is empty, `AssignmentWithheld` never fires, and neither does `RoleUnderProvisioned`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "probe, not an assertion — run with --ignored --nocapture"]
    async fn probe_what_a_five_node_cell_assigns_under_latency() {
        // The SAME world as the assertion under investigation: `F4` and `relay + rendezvous`. The first two
        // runs of this probe used `F2` with `relay + storage` and converged under BOTH links — which refuted
        // the address-book story rather than confirming it, and only because the worlds differed.
        use fanos_field::F4;
        use fanos_node::RoleSet;

        const NODES: usize = 5;
        const SAMPLES: usize = 12;
        const EVERY: Duration = Duration::from_secs(5);

        // Host-sensitive by construction — it is about wall-clock convergence — so it says what it is worth
        // even though no clock is read directly (#255).
        println!("{}", fanos_testkit::measurement_conditions());

        for (label, link) in [("ideal   ", Link::ideal()), ("default ", Link::default())] {
            let roles = RoleSet { relay: true, rendezvous: true, ..RoleSet::default() };
            let Ok(fleet) = NodeFleet::spawn::<F4>(NODES, link, roles).await else {
                println!("PROBE {label}: fleet did not start");
                continue;
            };
            // Roles beside the book, because the predicate is "every member has SOME role" and the controller
            // is free to assign fewer roles than there are members. A node stably without a role on a
            // COMPLETE roster is a different finding from a node that never learned the cell.
            let book = fleet
                .observe(SAMPLES, EVERY, |n| {
                    (n.health().known_peers, n.assignment().roster, n.assigned_roles().any())
                })
                .await;
            for (t, seen) in book.samples() {
                let peers: Vec<usize> = seen.iter().map(|(p, _, _)| *p).collect();
                let roster: Vec<usize> = seen.iter().map(|(_, r, _)| *r).collect();
                let served: Vec<bool> = seen.iter().map(|(_, _, a)| *a).collect();
                println!(
                    "PROBE {label} t={:>3}s  known_peers={peers:?}  roster={roster:?}  has_role={served:?}",
                    t.as_secs()
                );
            }
            println!(
                "PROBE {label} final roles={:?}  widest withheld scan={}",
                fleet.nodes().iter().map(|n| format!("{:?}", n.assignment().roles)).collect::<Vec<_>>(),
                fleet.widest_withheld_scan()
            );
            fleet.shutdown().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "probe, not an assertion — run with --ignored --nocapture"]
    async fn probe_loss_tolerance_of_the_composition() {
        use fanos_field::F2;
        use fanos_node::RoleSet;
        // This probe prints `started.elapsed()`, so it is a wall-clock reading like the two in
        // fanos-rendezvous and fanos-aphantos — and it owes the same statement of conditions (#255).
        println!("{}", fanos_testkit::measurement_conditions());
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
            fleet.shutdown().await;
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
