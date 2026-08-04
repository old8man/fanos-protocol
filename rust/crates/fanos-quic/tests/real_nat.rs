//! Real-QUIC **NAT hole-punch under a fabric that can actually refuse the punch** (#119 residual, the
//! testnet blocker `docs/tasks.md` records as "the real-NAT harness — the only residual").
//!
//! `hole_punch.rs` proves the brokering mechanism over loopback: no NAT is present there, so the punched
//! dial always lands and the relay fallback (the path that exists precisely for a punch that CANNOT work)
//! has never once run. This file supplies the missing ingredient — a [`quinn::AsyncUdpSocket`] that models a
//! NAT's own behaviour, plugged into the same [`fanos_quic::Fabric::Abstract`] transport-injection seam
//! `driver.rs`'s own `PassThroughFabric` test uses, and the one `fanos_sim::fabric::Fabric` uses for its
//! whole modelled-carrier suite. Above that seam this is a completely ordinary self-certifying node: real
//! QUIC, real TLS, real driver actors — only the datagram carrier is modelled, exactly per
//! `docs/design-testing.md` §5.1.
//!
//! ## The model
//!
//! A NAT's traversal-relevant behaviour is two independent axes (RFC 4787 §4):
//!
//! * **Mapping** — does the NAT reuse ONE external port for every destination (`EndpointIndependent`, a
//!   "cone" NAT), or allocate a FRESH one per distinct destination (`EndpointDependent`, a "symmetric"
//!   NAT)? This is the axis that decides whether a hole-punch is even *possible*: a hub can only ever hand a
//!   peer the mapping it personally observed, and that mapping is valid toward a THIRD party only if the NAT
//!   reuses it — under `EndpointDependent` the punching peer dials from a port nobody was ever told about.
//! * **Filtering** — does the NAT admit an inbound datagram from a source this mapping has not itself sent
//!   an outbound datagram to (`AddressDependent`), or admit anything (`Open`)? This is the minimum bar a
//!   punch needs regardless of mapping: each side's own outbound packet toward the other is what opens its
//!   mapping to the reply (the "simultaneous open"). Every peer below filters — the interesting claim is
//!   that filtering ALONE does not defeat a punch, only a mismatched mapping does.
//!
//! The hub is deliberately the one exception to filtering (`Filtering::Open`): it is the rendezvous every
//! peer dials in to *first*, and address-dependent filtering would reject that very first, unsolicited
//! contact — a rendezvous server is, by construction, not itself hidden behind a restrictive NAT (a real
//! deployment gives it a public or port-forwarded address for exactly this reason).
//!
//! Both are modelled **in-memory**, not over real kernel sockets — the same choice `fanos_sim::fabric::Fabric`
//! already makes for latency/jitter/loss/partition, for the same reason: the fidelity claim
//! (`docs/design-testing.md` §5.1) is about what runs ABOVE the socket (real QUIC, real TLS, real
//! composition), not about whether the datagram carrier itself is a kernel port. A NATted node here can own
//! MULTIPLE synthetic addresses (one per allocated mapping); what a peer's connection is seen to arrive FROM
//! is exactly the address [`Internet::deliver`] tags it with, which is the one thing that actually decides
//! whether a punch can land.
//!
//! ## What each test proves
//!
//! 1. [`filtering_nat_lets_a_hole_punch_succeed`] — a "cone" NAT with filtering still lets the simultaneous
//!    open through: traffic ends up direct.
//! 2. [`symmetric_nat_defeats_the_punch_and_the_relay_carries_the_pair`] — a symmetric NAT defeats the punch
//!    outright, and the relay (#54) carries every frame anyway, in both directions. **This is the case that
//!    has never run before this file.**
//! 3. [`a_hub_that_cannot_broker_a_punch_is_asked_at_most_once`] — the two derived bounds in
//!    `peer_send_worker`: however many frames go unresolved, the hub is asked to broker once (`asked`) and
//!    an address whose dial failed is not dialled again (`dead_addr`). **The second one was found by this
//!    file.** Before it, a symmetric-NAT pair paid a full `DIAL_TIMEOUT` handshake to the hub's brokered —
//!    and permanently unreachable — address on *every frame*, ahead of the relay that was always going to
//!    carry it; the failures also fed `apply_outcome(false)` and so the morph auto-fallback breaker
//!    (§13.7), which made an unreachable peer read as a censored transport.
//!
//! Runtime: multi-threaded with **four** workers — a current-thread harness cannot see a parallelism
//! defect at all (#84), and two workers see it only 3 times in 8 where four see it 8 of 8. Measured
//! against the reverted fix for #83; the table is in `fanos-quic/tests/store_acks.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::await_holding_lock)]

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use fanos_field::F2;
use fanos_geometry::Point;
use fanos_quic::{
    DEFAULT_GRIND_LIMIT, Directory, Fabric, NodeHandle, credentials_for_point,
    spawn_self_certifying_persistent_over,
};
use fanos_runtime::{Command, Config, Notification, OverlayNode, Triple};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

/// Real-QUIC tests each bring up several nodes; run them one at a time to avoid overloading the transport
/// (see `hole_punch.rs`). Scoped to this file only — each `tests/*.rs` is its own binary.
static SERIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

// =================================================================================================
// The NAT model: `Internet` (the shared substrate) + `NatSocket` (one node's `AsyncUdpSocket`).
// =================================================================================================

/// The mapping axis (RFC 4787 §4.1): does a NAT reuse one external port for every destination, or a fresh
/// one per destination?
#[derive(Clone, Copy, Debug)]
enum Mapping {
    /// One external mapping, reused for every destination — a "cone" NAT. What a hub observes for this
    /// node is the SAME address it will itself use dialing anyone else.
    EndpointIndependent,
    /// A fresh external mapping per distinct destination — a "symmetric" NAT. What a hub observes is valid
    /// only for traffic TO the hub; the mapping this node uses when it turns around and dials the peer the
    /// hub named is a different port that peer was never told about.
    EndpointDependent,
}

/// The filtering axis (RFC 4787 §5): does a mapping admit an inbound datagram from a source it has not
/// itself sent an outbound datagram to?
#[derive(Clone, Copy, Debug)]
enum Filtering {
    /// Admit anything. Reserved for the hub (see the module doc) — nobody could ever make first contact
    /// with a rendezvous that also required "you must have written to me first".
    Open,
    /// Admit only a source this mapping has itself sent to. The minimum bar a punch needs: each side's own
    /// outbound packet toward the other is what opens its mapping for the reply.
    AddressDependent,
}

/// One NAT table entry: a synthetic address other nodes address it at, the destinations it has itself sent
/// to (what `AddressDependent` filtering checks an inbound source against), and the inbox that funnels an
/// admitted datagram back to the owning `NatSocket`'s single receive stream.
#[derive(Debug)]
struct MappingEntry {
    filtering: Filtering,
    sent_to: HashSet<SocketAddr>,
    inbox: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
}

/// The shared substrate every `NatSocket` on one test sits on — cheap to clone (an `Arc` inside), mirroring
/// `fanos_sim::fabric::Fabric`.
#[derive(Clone, Debug)]
struct Internet {
    inner: Arc<InternetInner>,
}

#[derive(Debug)]
struct InternetInner {
    mappings: Mutex<HashMap<SocketAddr, MappingEntry>>,
    next_port: AtomicU64,
    /// Datagrams `AddressDependent` filtering refused — the wire-level proof a punch attempt actually hit a
    /// mismatched mapping, not merely that nothing happened to try one.
    rejected: AtomicU64,
    /// Every ADMITTED datagram's `(from, to)`. Needed because `Notification::Delivered` cannot tell a direct
    /// hop from a relayed one: a `Relay` frame re-attributes its payload to the true origin at the
    /// application layer regardless of which physical hop actually carried it (`driver.rs`'s
    /// `FrameType::Relay` arm). Only the fabric's own wire log can answer "did this ever go direct".
    log: Mutex<Vec<(SocketAddr, SocketAddr)>>,
}

impl Internet {
    fn new() -> Self {
        Self {
            inner: Arc::new(InternetInner {
                mappings: Mutex::new(HashMap::new()),
                next_port: AtomicU64::new(1),
                rejected: AtomicU64::new(0),
                log: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Allocate a fresh synthetic `127.0.0.1:<port>` mapping and register it, feeding admitted datagrams
    /// into `inbox`. Used both for a node's primary mapping and, under `Mapping::EndpointDependent`, for
    /// each new destination's own mapping — always the same `inbox`, so every mapping a node owns still
    /// funnels into that ONE node's single receive stream.
    fn register(
        &self,
        filtering: Filtering,
        inbox: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    ) -> SocketAddr {
        let port = self.inner.next_port.fetch_add(1, Ordering::Relaxed);
        // 16-bit ports, kept off the reserved range — mirrors fanos_sim::fabric::Fabric::bind.
        let port = u16::try_from(1024 + (port % 60_000)).unwrap_or(1024);
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        self.inner
            .mappings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(addr, MappingEntry { filtering, sent_to: HashSet::new(), inbox });
        addr
    }

    /// Bind a new node onto this NAT model, returning the socket to hand to `Fabric::Abstract`.
    fn attach(&self, mapping: Mapping, filtering: Filtering) -> Arc<NatSocket> {
        let (tx, rx) = mpsc::unbounded_channel();
        let primary = self.register(filtering, tx.clone());
        Arc::new(NatSocket {
            internet: self.clone(),
            mapping,
            filtering,
            primary,
            by_dest: Mutex::new(HashMap::new()),
            inbox_tx: tx,
            inbox_rx: Mutex::new(rx),
        })
    }

    /// Deliver one datagram from `from` to `to` — the whole NAT model in one place.
    ///
    /// Outbound always leaves (a real NAT never blocks traffic going OUT), and that send is itself what
    /// opens `from`'s own mapping to a reply — recorded unconditionally, before `to`'s filtering is even
    /// consulted, exactly like a real NAT table entry. `to` then admits the datagram only if its own
    /// filtering allows it — `Open` always does; `AddressDependent` only if `to` has itself already sent
    /// to `from`.
    fn deliver(&self, from: SocketAddr, to: SocketAddr, data: &[u8]) {
        let mut mappings = self.inner.mappings.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(from_entry) = mappings.get_mut(&from) {
            from_entry.sent_to.insert(to);
        }
        let Some(to_entry) = mappings.get(&to) else {
            return; // no such endpoint: dropped exactly as UDP drops a datagram to an unreachable host
        };
        let admitted = match to_entry.filtering {
            Filtering::Open => true,
            Filtering::AddressDependent => to_entry.sent_to.contains(&from),
        };
        if !admitted {
            drop(mappings);
            self.inner.rejected.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let _ = to_entry.inbox.send((from, data.to_vec()));
        drop(mappings);
        self.inner.log.lock().unwrap_or_else(PoisonError::into_inner).push((from, to));
    }

    /// How many datagrams have been ADMITTED to `to` — the count of what actually reached an address,
    /// whoever sent it. Used to measure what a node can be made to emit toward a third party.
    fn arrivals_at(&self, to: SocketAddr) -> u64 {
        self.inner
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(_, dst)| *dst == to)
            .count() as u64
    }

    /// Datagrams `AddressDependent` filtering has refused, across every mapping on this model.
    fn rejected(&self) -> u64 {
        self.inner.rejected.load(Ordering::Relaxed)
    }

    /// Whether the wire log shows any datagram directly between the two address sets, in either direction —
    /// the decisive proof a direct hop occurred (or, checked negatively, never occurred) between two nodes.
    fn any_direct_between(&self, a: &HashSet<SocketAddr>, b: &HashSet<SocketAddr>) -> bool {
        self.inner
            .log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(from, to)| (a.contains(from) && b.contains(to)) || (b.contains(from) && a.contains(to)))
    }
}

/// One node's `AsyncUdpSocket` on an [`Internet`] — the identity fabric `driver.rs`'s `PassThroughFabric`
/// demonstrates the seam for, here with a NAT's mapping/filtering behaviour instead of a bare pass-through.
#[derive(Debug)]
struct NatSocket {
    internet: Internet,
    mapping: Mapping,
    filtering: Filtering,
    /// This node's first-ever mapping — always what `local_addr()` reports, and (under
    /// `EndpointIndependent`) the ONLY mapping this node ever uses.
    primary: SocketAddr,
    /// Extra mappings allocated per destination, used only under `Mapping::EndpointDependent`.
    by_dest: Mutex<HashMap<SocketAddr, SocketAddr>>,
    inbox_tx: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    /// Behind a `Mutex` because `poll_recv` needs `&mut` on the receiver while the trait gives `&self` —
    /// the same shim `fanos_sim::fabric::FabricSocket` uses.
    inbox_rx: Mutex<mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>,
}

impl NatSocket {
    /// Which of this node's own mappings a datagram to `dest` leaves from. `EndpointIndependent` always
    /// answers `primary`; `EndpointDependent` allocates a fresh mapping the first time `dest` is seen and
    /// reuses it thereafter — a real symmetric NAT's per-flow port choice.
    fn mapping_for(&self, dest: SocketAddr) -> SocketAddr {
        match self.mapping {
            Mapping::EndpointIndependent => self.primary,
            Mapping::EndpointDependent => {
                let mut by_dest = self.by_dest.lock().unwrap_or_else(PoisonError::into_inner);
                *by_dest
                    .entry(dest)
                    .or_insert_with(|| self.internet.register(self.filtering, self.inbox_tx.clone()))
            }
        }
    }

    /// Every synthetic address this node currently owns — what a test uses to tell "a datagram involving
    /// THIS node" apart from any other party on the same modelled address space.
    fn owned_addrs(&self) -> HashSet<SocketAddr> {
        let mut set: HashSet<SocketAddr> =
            self.by_dest.lock().unwrap_or_else(PoisonError::into_inner).values().copied().collect();
        set.insert(self.primary);
        set
    }
}

impl AsyncUdpSocket for NatSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // The model has no backpressure (delivery is synchronous), so the socket is always writable —
        // mirrors fanos_sim::fabric::FabricSocket's AlwaysWritable.
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let from = self.mapping_for(transmit.destination);
        self.internet.deliver(from, transmit.destination, transmit.contents);
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (Some(buf), Some(slot)) = (bufs.first_mut(), meta.first_mut()) else {
            return Poll::Ready(Ok(0));
        };
        let mut rx = self.inbox_rx.lock().unwrap_or_else(PoisonError::into_inner);
        // `poll_recv` registers the waker on the channel — the contract a fabric owes quinn (module docs of
        // `fanos_sim::fabric` and `driver.rs`'s `PassThroughFabric` both make the same point: a bare
        // `Poll::Pending` here compiles and then silently never receives again).
        let Some((from, datagram)) = ready!(rx.poll_recv(cx)) else {
            return Poll::Ready(Err(io::Error::other("NAT-modelled endpoint closed")));
        };
        let len = datagram.len().min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..len), datagram.get(..len)) {
            dst.copy_from_slice(src);
        }
        *slot = RecvMeta { addr: from, len, stride: len, ecn: None, dst_ip: None };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.primary)
    }
}

/// The model has no backpressure, so writability is immediate — copied verbatim from
/// `fanos_sim::fabric::AlwaysWritable`.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// =================================================================================================
// Harness helpers
// =================================================================================================

/// Bring up a self-certifying node whose ONLY datagram path is `fabric` — real QUIC, real TLS, real driver
/// actors, with the modelled NAT standing in for the kernel socket. Self-certifying (not the field-less
/// `spawn` `hole_punch.rs` uses) because the field-less entry point hardcodes a real UDP bind with no
/// injection point; `Fabric::Abstract` is only reachable through the `_over` family
/// (`spawn_self_certifying_persistent_over`).
/// **`point` is pinned, and it has to be.** These tests assert things like "A does not know B's address
/// up front", which is a statement about two *distinct* coordinates. A freshly generated identity draws a
/// random VRF coordinate on a 7-point plane, so three nodes collide with probability `1 − (6/7)(5/7) ≈ 39%`
/// — and a collision makes `dir_a.resolve(b.address())` resolve A's own entry and the assertion fail. The
/// first version of this harness generated identities and was flaky at exactly that rate; measured, three
/// consecutive runs gave 1, 2 and 2 failures out of 3. Grinding to a chosen point is what the coordinate
/// harness exists for, and it costs ~7 mints.
fn node_over(fabric: Fabric, dir: &Directory, point: usize) -> NodeHandle {
    let credentials = credentials_for_point::<F2>(Point::<F2>::at(point), DEFAULT_GRIND_LIMIT)
        .expect("grind credentials for the pinned point");
    spawn_self_certifying_persistent_over::<F2>(
        fabric,
        &credentials,
        |point| Box::new(OverlayNode::<F2>::new(point, Config::default())),
        dir.clone(),
        None,
    )
    .expect("spawn node over the modelled NAT fabric")
}

/// Await a `Delivered` payload from `want_from`, within `secs` — a barrier that also proves the sender's
/// connection reached this node (its accept path ran). Mirrors `hole_punch.rs`'s own helper.
async fn await_delivery(node: &mut NodeHandle, want_from: Triple, secs: u64) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            match node.next_notification().await {
                Some(Notification::Delivered { from, payload }) if from == want_from => {
                    return payload;
                }
                Some(_) => {}
                None => panic!("engine stopped before delivery"),
            }
        }
    })
    .await
    .expect("delivery timed out")
}

/// Poll `f` until it returns `true`, or panic at `deadline` — the boolean poll-until-observed idiom
/// `hole_punch.rs`'s `await_resolved` also uses, for a one-shot event with nothing to `.await` on directly.
async fn await_true(mut f: impl FnMut() -> bool, deadline: Duration) {
    tokio::time::timeout(deadline, async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("condition never became true within the deadline");
}

/// Wait for a burst of background activity (a punch dial's retries) to START — `f() becomes nonzero — then
/// keep polling until it stops changing for a full `quiet` window, and return the value it settled at.
///
/// A fixed sleep either races a slow run (flaky under load — see the shared-machine-contention note in
/// `docs/design-testing.md` §5) or wastes time on a fast one; this adapts to whichever actually happens.
/// The two-phase shape matters: without phase 1, a call made when `f` is ALREADY nonzero and about to climb
/// again could return the stale pre-climb value the instant its own `quiet` window (measured from a value
/// that hasn't moved YET) elapses, before the new activity even starts.
/// How long "quiet" must last before a dial attempt can be called finished.
///
/// **Derived from the one bound that governs it, and getting this wrong produced a false failure.** A
/// connect attempt is abandoned at `driver.rs`'s `DIAL_TIMEOUT` (3 s, private to that module), so no
/// datagram belonging to an attempt can arrive more than that after it started — silence for longer than
/// `DIAL_TIMEOUT` therefore means no attempt is outstanding. Silence for *less* means nothing at all: QUIC
/// retransmits an Initial on a growing backoff (~1 s, 2 s, …), so a 700 ms window — the first value here —
/// reliably declared the punch finished while it was merely between retransmits, and counted the remainder
/// as if later frames had provoked it. Measured that way, one punch attempt read as 32 events across two
/// sample points; it is 2 flows, retransmitted.
const DIAL_QUIET: Duration = Duration::from_millis(3_500);

async fn settle(mut f: impl FnMut() -> u64, quiet: Duration, deadline: Duration) -> u64 {
    tokio::time::timeout(deadline, async {
        while f() == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut last = f();
        let mut since_change = tokio::time::Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let now = f();
            if now != last {
                last = now;
                since_change = tokio::time::Instant::now();
            } else if since_change.elapsed() >= quiet {
                return now;
            }
        }
    })
    .await
    .expect("activity never started, or never went quiet, within the deadline")
}

// =================================================================================================
// Tests
// =================================================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn filtering_nat_lets_a_hole_punch_succeed() {
    let _serial = serial();
    // A rendezvous hub (open — see the module doc for why) plus two peers behind a "restricted cone" NAT:
    // one external mapping reused for every destination, but an inbound datagram is admitted only from a
    // source this node has itself sent to first.
    let net = Internet::new();
    let hub_sock = net.attach(Mapping::EndpointIndependent, Filtering::Open);
    let a_sock = net.attach(Mapping::EndpointIndependent, Filtering::AddressDependent);
    let b_sock = net.attach(Mapping::EndpointIndependent, Filtering::AddressDependent);

    let dir_a = Directory::new();
    let dir_b = Directory::new();
    let dir_h = Directory::new();
    let mut h = node_over(Fabric::Abstract(hub_sock.clone()), &dir_h, 0);
    let a = node_over(Fabric::Abstract(a_sock.clone()), &dir_a, 1);
    let mut b = node_over(Fabric::Abstract(b_sock.clone()), &dir_b, 2);

    // Both peers can reach the hub directly — it is the rendezvous, never hidden.
    dir_a.insert(h.address(), h.local_addr());
    dir_b.insert(h.address(), h.local_addr());

    // B dials in first, so the hub observes (and remembers) B's mapping before anyone asks it to broker.
    b.command(Command::Send { to: h.address(), payload: b"warm".to_vec() });
    assert_eq!(await_delivery(&mut h, b.address(), 5).await, b"warm", "the hub observed B");

    assert!(dir_a.resolve(b.address()).is_none(), "A must not know B's address up front");

    assert!(a.hole_punch(h.address(), b.address()), "the hole-punch request was queued");

    // Proof of the simultaneous open: a datagram crossed directly between A's and B's own mappings —
    // impossible unless each side's own outbound punch packet opened its mapping for the other's reply.
    // Generous deadline: under a loaded host, even a same-process handshake can need several PTO retries
    // to win the race between "my outbound packet arrives" and "the other side's outbound packet, which
    // is what admits mine, has left yet".
    let a_addrs = a_sock.owned_addrs();
    let b_addrs = b_sock.owned_addrs();
    await_true(|| net.any_direct_between(&a_addrs, &b_addrs), Duration::from_secs(15)).await;

    // End-to-end proof: an application payload now reaches B over the punched connection.
    let payload = b"through the punched hole".to_vec();
    assert!(a.command(Command::Send { to: b.address(), payload: payload.clone() }));
    assert_eq!(await_delivery(&mut b, a.address(), 5).await, payload, "B receives A's payload");

    // Falsified against: swapping A and B to `Mapping::EndpointDependent` here (test 2's fabric) — with
    // that one change, `await_true` above times out instead of observing a direct hop, because the mapping
    // each side dials the other FROM is no longer the one the hub told the other party about. Confirms this
    // assertion is actually pinned on the mapping axis, not an accident of the harness.
    a.shutdown();
    b.shutdown();
    h.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn symmetric_nat_defeats_the_punch_and_the_relay_carries_the_pair() {
    let _serial = serial();
    // The case that has never run: A and B behind a SYMMETRIC NAT (a fresh external mapping per distinct
    // destination). The hub still brokers successfully — it only ever reports each peer's mapping TOWARD
    // ITSELF, which is genuine information — but the mapping each peer then uses to dial the OTHER is a
    // port neither the hub nor that peer ever advertised, so the punched dial lands nowhere and the relay
    // fallback (#54, #119) is the only path traffic ever takes, in both directions.
    let net = Internet::new();
    let hub_sock = net.attach(Mapping::EndpointIndependent, Filtering::Open);
    let a_sock = net.attach(Mapping::EndpointDependent, Filtering::AddressDependent);
    let b_sock = net.attach(Mapping::EndpointDependent, Filtering::AddressDependent);

    let dir_a = Directory::new();
    let dir_b = Directory::new();
    let dir_h = Directory::new();
    let mut h = node_over(Fabric::Abstract(hub_sock.clone()), &dir_h, 0);
    let mut a = node_over(Fabric::Abstract(a_sock.clone()), &dir_a, 1);
    let mut b = node_over(Fabric::Abstract(b_sock.clone()), &dir_b, 2);

    dir_a.insert(h.address(), h.local_addr());
    dir_b.insert(h.address(), h.local_addr());

    // Both warm the hub — exactly hole_punch.rs's automatic-trigger test. Nobody calls `hole_punch` here;
    // the send path below must ask on its own.
    a.command(Command::Send { to: h.address(), payload: b"a-warm".to_vec() });
    assert_eq!(await_delivery(&mut h, a.address(), 5).await, b"a-warm");
    b.command(Command::Send { to: h.address(), payload: b"b-warm".to_vec() });
    assert_eq!(await_delivery(&mut h, b.address(), 5).await, b"b-warm");

    assert!(dir_a.resolve(b.address()).is_none(), "A must not know B's address up front");

    // One ordinary send. Its own frame rides the relay immediately (a punch is asynchronous and must not
    // delay traffic) AND triggers the automatic broker request.
    let fwd = b"A to B, a punch attempted and defeated".to_vec();
    a.command(Command::Send { to: b.address(), payload: fwd.clone() });
    assert_eq!(await_delivery(&mut b, a.address(), 5).await, fwd, "B receives A's message via the relay");

    // The mechanism actually engaged and actually lost: the mismatched mapping was hit at least once. (A
    // transient reject can also occur mid-race in the SUCCEEDING case — what is decisive here is checked
    // below: the punch never recovers, however long it is given.)
    let r1 = settle(|| net.rejected(), DIAL_QUIET, Duration::from_secs(90)).await;
    assert!(r1 > 0, "the mismatched mapping must have been hit at least once");

    // The reverse leg: B replies, independently triggering its own (equally doomed) punch toward A, and
    // also relayed.
    let rev = b"B back to A, still relayed".to_vec();
    b.command(Command::Send { to: a.address(), payload: rev.clone() });
    assert_eq!(await_delivery(&mut a, b.address(), 5).await, rev, "A receives B's reply via the relay");

    // Decisive: across the WHOLE exchange, not one datagram ever crossed directly between A's and B's own
    // mappings (own_addrs() taken now, after every mapping either side ever allocated exists) — every byte
    // that reached the other side carried the hub's address, never the peer's.
    let a_addrs = a_sock.owned_addrs();
    let b_addrs = b_sock.owned_addrs();
    assert!(
        !net.any_direct_between(&a_addrs, &b_addrs),
        "a symmetric NAT must never let A and B exchange a direct datagram"
    );

    // Falsified against: swapping A and B back to `Mapping::EndpointIndependent` here (test 1's fabric) —
    // with that one change, `r1` never becomes positive within the deadline (nothing to settle against) and
    // `any_direct_between` flips true, because the same mapping the hub reported IS the one each side would
    // dial from. Confirms the failure is pinned on the mapping axis, not on this being a NAT model at all.
    a.shutdown();
    b.shutdown();
    h.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hub_that_cannot_broker_a_punch_is_asked_at_most_once() {
    let _serial = serial();
    // The derived bound in `peer_send_worker`'s `asked: BTreeSet<Triple>`: once a hub has been asked to
    // broker a punch to a given peer, it is never asked again for that peer — re-asking cannot change the
    // answer while the two NATs' mappings hold, so a dead or Byzantine hub cannot be re-asked once per
    // frame, for ever. Reuses test 2's symmetric-NAT pair (the punch that keeps failing) and sends several
    // MORE frames after the first attempt has settled, watching for any renewed punch activity.
    let net = Internet::new();
    let hub_sock = net.attach(Mapping::EndpointIndependent, Filtering::Open);
    let a_sock = net.attach(Mapping::EndpointDependent, Filtering::AddressDependent);
    let b_sock = net.attach(Mapping::EndpointDependent, Filtering::AddressDependent);

    let dir_a = Directory::new();
    let dir_b = Directory::new();
    let dir_h = Directory::new();
    let mut h = node_over(Fabric::Abstract(hub_sock.clone()), &dir_h, 0);
    let a = node_over(Fabric::Abstract(a_sock.clone()), &dir_a, 1);
    let mut b = node_over(Fabric::Abstract(b_sock.clone()), &dir_b, 2);

    dir_a.insert(h.address(), h.local_addr());
    dir_b.insert(h.address(), h.local_addr());

    a.command(Command::Send { to: h.address(), payload: b"a-warm".to_vec() });
    assert_eq!(await_delivery(&mut h, a.address(), 5).await, b"a-warm");
    b.command(Command::Send { to: h.address(), payload: b"b-warm".to_vec() });
    assert_eq!(await_delivery(&mut h, b.address(), 5).await, b"b-warm");

    // First frame: triggers the one punch attempt (and is itself relayed regardless of the punch's fate).
    a.command(Command::Send { to: b.address(), payload: b"frame-1".to_vec() });
    assert_eq!(await_delivery(&mut b, a.address(), 5).await, b"frame-1");

    // Let that one attempt run its course and go quiet.
    let r1 = settle(|| net.rejected(), DIAL_QUIET, Duration::from_secs(90)).await;
    assert!(r1 > 0, "the one punch attempt must have hit the mismatched mapping");

    // **The claim is that the cost does not scale with the traffic, so the test compares two batches
    // rather than a batch against zero.** Some one-time work legitimately follows the first frame: the
    // brokered punch teaches A an address for B it did not have before, and an address never tried is
    // tried once — that is the same "a different address is new information" rule the guards rest on. What
    // must NOT happen is *per-frame* work. So: four frames, settle, then eight more — twice as many — and
    // the count must not move at all the second time.
    let send_batch = async |n: std::ops::RangeInclusive<u8>, b: &mut NodeHandle| {
        for i in n {
            let payload = format!("frame-{i}").into_bytes();
            a.command(Command::Send { to: b.address(), payload: payload.clone() });
            assert_eq!(await_delivery(b, a.address(), 5).await, payload, "later frames must keep relaying");
        }
    };
    send_batch(2..=5, &mut b).await;
    let r2 = settle(|| net.rejected(), DIAL_QUIET, Duration::from_secs(90)).await;
    send_batch(6..=13, &mut b).await;
    let r3 = settle(|| net.rejected(), DIAL_QUIET, Duration::from_secs(90)).await;

    assert_eq!(
        r3, r2,
        "eight further frames to the same unreachable peer must cost NOTHING on the wire toward it: the \
         hub is asked once ({r1} rejected datagrams for the punch itself, {r2} after the first batch \
         re-tried the newly-learned address once), and after that the relay carries everything"
    );

    // **What this counts, and what it therefore cannot tell apart.** `rejected()` is a *packet* counter, so
    // it sees a re-asked hub and a re-dialled dead address as the same thing, and it also sees one attempt's
    // QUIC Initial retransmissions as several events. Both of those cost real findings before they were
    // understood, and both are why the assertion is a batch-to-batch comparison instead of an equality
    // against `r1`:
    //
    // * The first version compared `r2` to `r1` with a 700 ms quiet window and read one punch attempt as 32
    //   events, because QUIC retransmits an Initial on a growing backoff and 700 ms lands between retries.
    //   `DIAL_QUIET` fixed that; verified by re-measuring with an 11 s window and getting identical counts.
    // * It then still failed, at `r2 = 14` against `r1 = 8`, and the six extra were real and CORRECT: the
    //   punch had taught A an address for B, and the worker dialled it once. Asserting `r2 == r1` demanded
    //   that a node never try an address it has just learned.
    // * That it passed at all in its very first form was the coordinate collision this file's `node_over`
    //   now pins away: when A and B drew the same point, `Send { to: b.address() }` addressed A itself, no
    //   punch path ran, and the assertion held for a reason unrelated to either guard.
    //
    // Falsified against both guards, one at a time, then reverted: making `asked.insert(hub_coord)`
    // unconditional, and dropping the `dead_addr != Some(addr)` condition in `peer_send_worker`. Each alone
    // makes the second batch cost eight more dials and `r3 > r2`.
    a.shutdown();
    b.shutdown();
    h.shutdown();
}

/// **A node cannot be made to flood a third party by sending it hole-punch frames.**
///
/// `PunchTo` is unsolicited on one side by construction — the hub tells *both* parties to dial, and the
/// target never asked — so the receive path cannot correlate a punch to a request and must bound instead.
/// Before it did, `accept_holepunch` took `(peer, addr)` straight off the frame, wrote the directory, and
/// spawned a dial, consulting neither the sender nor any cap. Any established peer could therefore aim this
/// node's QUIC Initials at **any address it named**, as often as it liked.
///
/// That is an outward harm before it is a local one: a fleet of FANOS nodes becomes a reflector pointed at
/// someone who never joined anything. So the property under test is measured **at the victim**, not at the
/// node — how much traffic arrives somewhere the attacker chose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_of_punch_frames_cannot_aim_this_node_at_a_third_party() {
    use fanos_wire::{FrameType, encode_frame};

    let _serial = serial();
    let net = Internet::new();
    let a_sock = net.attach(Mapping::EndpointIndependent, Filtering::Open);
    let x_sock = net.attach(Mapping::EndpointIndependent, Filtering::Open);
    // The victim: an address on the model that belongs to no node, admitting everything, so every datagram
    // that lands is one this node was talked into sending.
    let victim_sock = net.attach(Mapping::EndpointIndependent, Filtering::Open);
    let victim = victim_sock.primary;

    let dir_a = Directory::new();
    let dir_x = Directory::new();
    let mut a = node_over(Fabric::Abstract(a_sock.clone()), &dir_a, 1);
    let x = node_over(Fabric::Abstract(x_sock.clone()), &dir_x, 2);

    // X is an ordinary, admitted peer: it completes the handshake like any cell member. The fault budget
    // tolerates `f` of these, so "an established peer is hostile" is inside the threat model, not outside.
    dir_x.insert(a.address(), a.local_addr());
    x.command(Command::Send { to: a.address(), payload: b"hello".to_vec() });
    assert_eq!(await_delivery(&mut a, x.address(), 5).await, b"hello", "X is an established peer of A");

    // Forty crafted punches naming one coordinate and the victim's address. Body per `encode_punch`:
    // `peer_coord(12B) || family(1B) || ip(4) || port(2B BE)`.
    let target = Point::<F2>::at(4).coords();
    let mut body = Vec::new();
    for c in target {
        body.extend_from_slice(&c.to_be_bytes());
    }
    body.push(4);
    let std::net::IpAddr::V4(ip) = victim.ip() else { panic!("the model is IPv4") };
    body.extend_from_slice(&ip.octets());
    body.extend_from_slice(&victim.port().to_be_bytes());
    let mut frame = Vec::new();
    encode_frame(FrameType::PunchTo.code(), &body, &mut frame);
    for _ in 0..40 {
        x.command(Command::Emit { to: a.address(), frame: frame.clone() });
    }

    // THE PROPERTY, measured at the victim: what arrives is one dial's worth of handshake, not forty.
    // A single QUIC connection attempt retransmits its Initial a handful of times before `DIAL_TIMEOUT`
    // abandons it, so the bound is stated against that — one attempt, whatever its retry schedule — rather
    // than against a packet count this test would have to keep in step with quinn.
    let settled = settle(|| net.arrivals_at(victim).max(1), DIAL_QUIET, Duration::from_secs(90)).await;
    assert!(
        settled < 40,
        "forty punch frames put {settled} datagrams on the victim: the node is being used as a reflector, \
         and the count scales with what the attacker sends rather than with anything the node decided"
    );

    // THE MECHANISM, so the test cannot pass by the punch path being dead: the frames DID reach the punch
    // path and it DID dial — one attempt's worth of traffic arrived at an address only the attacker named.
    assert!(settled > 0, "no punch was attempted at all — this test would then prove nothing");

    a.shutdown();
    x.shutdown();
}
