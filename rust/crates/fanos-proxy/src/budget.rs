//! The local proxy's memory share, and the **one pool both transports draw from** (#207).
//!
//! # Why a pool of bytes rather than two counts
//!
//! This crate holds per-client buffers of two shapes: a UDP association's 64 KiB receive buffer, and a
//! relayed TCP connection's two staging buffers. #254 named the share and derived a count for the first
//! —`MAX_ASSOCIATIONS = share / MAX_UDP` — which is the tree's usual idiom (`STORE_SHARE →
//! MAX_STORE_ENTRIES`, `SESSION_MEMORY_BUDGET → MAX_SESSIONS`). It works when a share buys **one** kind of
//! thing.
//!
//! It does not work here, and the reason is not bookkeeping: the two are **not mutually exclusive**. A
//! client can hold 128 associations *and* a thousand relayed connections at once, so two independently
//! derived counts would each be honest about its own item and together spend the share twice. The router's
//! two send queues (#294) got one share precisely because they *are* exclusive — `forward_send` branches and
//! only one can fill. The opposite fact demands the opposite structure.
//!
//! So the admission rule is on **bytes**: one process-wide semaphore whose permits are bytes, from which an
//! association takes [`ASSOCIATION_COST`] and a connection takes [`CONNECTION_COST`]. The per-kind ceilings
//! below are then *readings* of what the share buys when only that kind is live — useful to an operator, and
//! never the thing enforced.
//!
//! # Why the TCP side had no bound at all
//!
//! `MAX_ASSOCIATIONS`'s own doc named both unguarded doors — *"Neither accept loop — `crate::serve` nor
//! `fanos_node::proxy::serve_proxy` — limits concurrency"* — and #254 closed only the UDP one. Three accept
//! loops (`socks5::serve`, `http::serve`, `fanos_node::proxy::serve_proxy`) spawned a task per accepted TCP
//! connection with no counter, so a looping application could grow this process without limit. The
//! qualification "the client is local and trusted" is the same one #254 rejected for the UDP path, one file
//! over.
//!
//! Finding it was not an audit: `LimitNOFILE=` cannot be derived over an unbounded accept loop, so #207's
//! descriptor half walked into it.

use tokio::sync::Semaphore;

/// The largest datagram the relay socket reads — the SOCKS5 header plus payload. A UDP datagram carries at
/// most 65535 bytes total, so this bounds the whole wrapped frame.
///
/// One of these is allocated **per live association**, which is why the pool charges [`ASSOCIATION_COST`].
pub const MAX_UDP: usize = 65535;

/// This process's share of memory for the local proxy's per-client buffers — taken from
/// `fanos_primitives::budget`, never restated here (#213's direction, #254's term).
pub const PROXY_MEMORY_BUDGET: usize = fanos_primitives::budget::PROXY_SHARE;

/// One direction's staging buffer while relaying a TCP connection.
///
/// **Derived, and the derivation is the whole reason this constant exists rather than tokio's default.**
/// `copy_bidirectional` allocates two buffers of a size tokio keeps private (8 KiB today); a bound computed
/// against a dependency's unexported default is a bound that can move under it without a build error, and
/// there is nothing to import ([[the-guard-becomes-the-defect]]). `copy_bidirectional_with_sizes` takes the
/// number, so the number becomes ours.
///
/// Its value is **one downstream write unit**. The proxy stages bytes between a TCP socket and a
/// `Dialer`-produced stream, and that stream ships them a segment at a time; a buffer larger than one
/// segment does not travel faster, it only holds more bytes waiting for the same drain. That is #247's
/// lesson exactly — a buffer sized for something the stack below cannot produce — and it cost 51× there.
///
/// `fanos-stream` is a leaf crate with no dependencies of its own, so importing the real number costs this
/// crate nothing in coupling and removes the copy that would otherwise need a cross-crate guard.
pub const RELAY_BUF: usize = fanos_stream::MAX_SEGMENT;

/// What one relayed TCP connection charges the pool: a staging buffer in each direction.
pub const CONNECTION_COST: usize = 2 * RELAY_BUF;

/// What one live UDP association charges the pool: its single receive buffer.
pub const ASSOCIATION_COST: usize = MAX_UDP;

/// Datagrams a [`UdpTunnel`](crate::dialer::UdpTunnel) buffers **per direction** before UDP's lossy drop
/// takes over — a few in flight smooth a burst without letting a stalled peer grow memory without bound.
///
/// **It lives here, beside the share it spends, and it used to live in a consumer.** `fanos-node` declared
/// it privately next to the one call that passes it to `UdpTunnel::pair`, so the depth of *this crate's*
/// channel was invisible to this crate — and therefore to the arithmetic below. That is the same direction
/// problem `fanos_primitives::budget`'s header describes, one level down, and it is why the product went
/// unsummed until #300.
///
/// 64 is not derived. It is "slack to smooth a burst", which is a scheduling claim nobody measured — the
/// same honest position `fanos_diaulos::budget::QUEUE_DEPTH` states about itself and leaves at a floor.
pub const UDP_TUNNEL_BUFFER: usize = 64;

/// **The pool a tunnel queue debits, one datagram's ACTUAL bytes at a time** (#300).
///
/// Separate from [`PROXY_MEMORY`] because it funds a different thing: that one buys a per-client buffer
/// that exists for as long as the client does, this one buys transient backlog. Sizing is
/// `fanos_primitives::budget::TUNNEL_BACKLOG_SHARE`, derived there as a FLOOR — enough for every admitted
/// flow to hold one datagram each way — because the arithmetic in `fanos-vpn` shows no ceiling is
/// purchasable at any price the node can pay.
///
/// **A process-wide static rather than a constructor argument, and the reason is the derivation.** An
/// earlier design made the pool a `pair()` parameter so each crate could name its own share; that was
/// right while the VPN looked like it would need one of its own. It does not: `fanos-proxy` and
/// `fanos-vpn` queue through this one mechanism and never in one process, so they get one share for it,
/// and a share for a mechanism belongs with the mechanism. The parameter would only have offered callers
/// a way to pass the wrong pool.
pub static TUNNEL_MEMORY: Semaphore = Semaphore::const_new(TUNNEL_BACKLOG_MEMORY_BUDGET);

/// This crate's name for the share `fanos_primitives::budget` grants the relayed-UDP tunnel queues.
///
/// **It exists because the register's guard requires it**, and the requirement is right: every share in
/// `SHARES` must have a `*_MEMORY_BUDGET` a consumer declares, "or the sum is over a subset nobody chose".
/// A share named only on the register's side is a number with no crate answering for it — the same
/// direction problem `UDP_TUNNEL_BUFFER` had before #300 moved it here, one level up.
pub const TUNNEL_BACKLOG_MEMORY_BUDGET: usize = fanos_primitives::budget::TUNNEL_BACKLOG_SHARE;

/// Charge `bytes` to [`TUNNEL_MEMORY`], or refuse. The permit rides with the datagram and returns itself
/// when the datagram is consumed or dropped — see [`crate::dialer::Datagram`] for why RAII and not a
/// counter.
pub(crate) fn charge_tunnel(bytes: usize) -> Option<tokio::sync::SemaphorePermit<'static>> {
    let want = u32::try_from(bytes).ok()?;
    TUNNEL_MEMORY.try_acquire_many(want).ok()
}

/// The awaiting form: used where the producer reads a byte-stream and back-pressure is the right answer,
/// rather than a socket where UDP's own lossiness is.
pub(crate) async fn charge_tunnel_waiting(bytes: usize) -> Option<tokio::sync::SemaphorePermit<'static>> {
    let want = u32::try_from(bytes).ok()?;
    TUNNEL_MEMORY.acquire_many(want).await.ok()
}


/// **What the tunnel queues COULD hold if nothing debited them** (#300) — kept as the figure the ratchet
/// below pins, not as a quantity anything reserves.
///
/// A relayed UDP flow's queue is `2 directions × UDP_TUNNEL_BUFFER × the datagram ceiling`, and every
/// flow map multiplies it again. Pinned as a number rather than left to a task note, because a quantity
/// with no name is invisible to the register that is supposed to sum it.
///
/// Behind `testing` because it is a RATCHET helper: it computes what the queues could hold if nothing
/// debited them, and nothing reserves that — a production caller would be reserving a number this crate
/// deliberately stopped honouring. `fanos-vpn` reaches it as a dev-dependency, the same way it reaches
/// `EchoDialer`.
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub const fn tunnel_queue_ceiling(flows: usize, datagram_ceiling: usize) -> usize {
    flows.saturating_mul(2).saturating_mul(UDP_TUNNEL_BUFFER).saturating_mul(datagram_ceiling)
}

/// How many UDP associations the share buys **when nothing else is live**.
///
/// A reading, not the enforced bound — [`PROXY_MEMORY`] is what admits. Kept because it is the number an
/// operator reads in a refusal message and the one they would change.
pub const MAX_ASSOCIATIONS: usize = PROXY_MEMORY_BUDGET / ASSOCIATION_COST;

/// How many relayed TCP connections the share buys **when nothing else is live**. Same status as
/// [`MAX_ASSOCIATIONS`]: a reading of the pool, not a second bound beside it.
pub const MAX_CONNECTIONS: usize = PROXY_MEMORY_BUDGET / CONNECTION_COST;

/// **Every charge is a whole number of buffers, and the two ceilings spend the share without exceeding it.**
///
/// `const` asserts rather than a test, following #205: the quantities are constants, so a violation is a
/// build error on the author who changed one. The second half of each pair matters as much as the first — a
/// ceiling far under what the share buys would have the budget counting bytes no deployment can use, which
/// understates what is left for every other subsystem.
const _: () = assert!(
    MAX_ASSOCIATIONS * ASSOCIATION_COST <= PROXY_MEMORY_BUDGET,
    "the association ceiling needs more memory than the share this crate was granted"
);
const _: () = assert!(
    (MAX_ASSOCIATIONS + 1) * ASSOCIATION_COST > PROXY_MEMORY_BUDGET,
    "the share buys more associations than the ceiling states, so the budget reserves memory nothing uses"
);
const _: () = assert!(
    MAX_CONNECTIONS * CONNECTION_COST <= PROXY_MEMORY_BUDGET,
    "the connection ceiling needs more memory than the share this crate was granted"
);
const _: () = assert!(
    (MAX_CONNECTIONS + 1) * CONNECTION_COST > PROXY_MEMORY_BUDGET,
    "the share buys more connections than the ceiling states, so the budget reserves memory nothing uses"
);

/// A permit is one byte, so the pool must be expressible in `Semaphore`'s own currency.
const _: () = assert!(
    PROXY_MEMORY_BUDGET <= Semaphore::MAX_PERMITS,
    "the proxy share exceeds what one Semaphore can hold; the pool would silently admit everything"
);

/// The bytes this process's local proxy may hold in per-client buffers, as permits.
///
/// **Process-wide on purpose, and this is the opposite call from the one `stations.rs` makes.** A station
/// counter must never be a global, because `fanos-sim` runs many nodes in one process and a shared counter
/// would blend their data paths into one unreadable sum. A memory limit is the reverse: the memory really is
/// shared by everything in the process, so a bound that is *not* global would let N in-process proxies
/// allocate N times the share this crate was granted. The quantity decides the scope, not the convention.
pub static PROXY_MEMORY: Semaphore = Semaphore::const_new(PROXY_MEMORY_BUDGET);

/// Take `bytes` from [`PROXY_MEMORY`], or `None` if the pool cannot spare them **right now**.
///
/// The non-waiting half of the pair, so a caller can tell an operator it is *about* to wait before it does
/// — the `warn!` at every call site is the only way "the proxy is at its share" reaches a human, and a
/// silent stall is the dead end #199 and #243 exist to prevent. [`reserve`] is what then waits.
///
/// The returned permit releases on drop, so a task that panics or is cancelled returns its bytes.
#[must_use = "dropping the permit immediately returns the bytes, so the buffer is unaccounted"]
pub fn try_reserve(bytes: usize) -> Option<tokio::sync::SemaphorePermit<'static>> {
    let want = u32::try_from(bytes).ok()?;
    PROXY_MEMORY.try_acquire_many(want).ok()
}

/// Wait for `bytes` in [`PROXY_MEMORY`]. Pairs with [`try_reserve`] for the caller that has already
/// decided to wait and wants to say so first.
///
/// **An accept loop should stop accepting rather than accept-and-refuse, and finding that out cost two
/// wrong designs.** The first wrote a protocol refusal (`503`, SOCKS5 `0xFF`) and closed. It arrives as a
/// TCP **reset**: closing a socket with unread bytes in its receive buffer sends `RST`, which discards
/// whatever was queued the other way, so the client reports "connection reset" and never sees the reason.
/// The second drained the pending request first — and `accept` returns on the SYN, before the request has
/// arrived, so there is usually nothing to drain and the reset happens anyway.
///
/// The fix is not a better refusal, it is **not accepting**: leave the client in the kernel's accept queue
/// until a connection ends. That needs no task, no buffer and no write, which matters because every one of
/// those is the resource that just ran out — and a backlog that overflows is refused by the OS, which is
/// the answer a TCP client is built to understand. The `warn!` at the call site is what an operator gets;
/// the client gets back-pressure.
pub async fn reserve(bytes: usize) -> Option<tokio::sync::SemaphorePermit<'static>> {
    let want = u32::try_from(bytes).ok()?;
    PROXY_MEMORY.acquire_many(want).await.ok()
}

/// **A process-global budget makes this crate's own tests tests over shared state, and that is a real cost
/// of the design rather than a test-harness detail.**
///
/// Tests in one binary run concurrently by default. A test that drains [`PROXY_MEMORY`] therefore makes
/// every *other* test that goes through an accept loop see a refusal — which is the mechanism working, and
/// indistinguishable from a bug when it lands on `a_non_connect_method_gets_400`. It did, on the first run
/// after the pool landed: three `http` tests failed with `ConnectionReset`, because `serve` had correctly
/// answered `503` and closed.
///
/// So every test that *takes* permits holds this, not only the ones that drain. Half a lock is worse than
/// none: it would serialise the draining tests against each other and leave exactly the collision above.
#[cfg(test)]
pub(crate) static POOL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The readings the docs and the refusal messages quote, pinned so they cannot drift silently.
    #[test]
    fn the_share_buys_what_the_ceilings_say() {
        println!(
            "share {PROXY_MEMORY_BUDGET} bytes: {MAX_ASSOCIATIONS} associations at {ASSOCIATION_COST} \
             B, or {MAX_CONNECTIONS} connections at {CONNECTION_COST} B"
        );
        assert_eq!(MAX_ASSOCIATIONS, 128);
        assert_eq!(MAX_CONNECTIONS, 4096);
        assert_eq!(RELAY_BUF, 1024, "the relay buffer is one downstream segment");
    }

    /// **The debit works in both directions: it refuses when the pool is spent, and ordinary traffic is
    /// not refused.** The second half is the one that matters — a bound that refuses normal work is not a
    /// bound, it is an outage, and #300's whole argument is that byte-accurate accounting buys the flow cap
    /// and the depth that a product-of-ceilings share could not.
    ///
    /// Serialised on [`POOL`] because these arms move the process-wide semaphore. Cross-crate users of the
    /// same mechanism (`fanos-vpn`) cannot collide with it: each crate's tests are a separate binary, so
    /// each has its own copy of the static.
    #[tokio::test]
    async fn the_debit_refuses_a_spent_pool_and_admits_ordinary_traffic() {
        let _serial = POOL.lock().await;
        let (tunnel, _in_tx, _out_rx) = crate::dialer::UdpTunnel::pair(UDP_TUNNEL_BUFFER);

        // ORDINARY TRAFFIC, first and deliberately: a full channel's worth of MTU-sized datagrams is
        // admitted without one refusal. This is the direction a wrong bound breaks.
        let ordinary = 1252;
        for i in 0..UDP_TUNNEL_BUFFER {
            assert_eq!(
                tunnel.outbound.try_send(vec![0u8; ordinary]),
                Ok(()),
                "datagram {i} of an ordinary burst was refused; the share does not fund what the channel \
                 depth admits, which is the failure mode #300 exists to avoid"
            );
        }
        assert!(
            TUNNEL_MEMORY.available_permits() >= PROXY_MEMORY_BUDGET,
            "a full channel of ordinary datagrams should leave most of the share unspent; it left \
             {} B",
            TUNNEL_MEMORY.available_permits()
        );

        // SPENT POOL: hold everything that is left, and the next datagram is refused for the pool's
        // reason, not the channel's — the two are different events and the caller can tell them apart.
        let held = TUNNEL_MEMORY
            .try_acquire_many(u32::try_from(TUNNEL_MEMORY.available_permits()).unwrap_or(u32::MAX));
        assert!(held.is_ok(), "nothing else should be holding the pool inside this lock");
        let (spare, _in2, _out2) = crate::dialer::UdpTunnel::pair(UDP_TUNNEL_BUFFER);
        assert_eq!(
            spare.outbound.try_send(vec![0u8; ordinary]),
            Err(crate::dialer::Refused::NoBudget),
            "with the pool spent the refusal must name the POOL; QueueFull here would send an operator to \
             look at one destination for a node-wide condition"
        );
        drop(held);
        assert_eq!(
            spare.outbound.try_send(vec![0u8; ordinary]),
            Ok(()),
            "releasing the pool must let traffic through again — a permit that does not come back is the \
             counter bug this design chose RAII to avoid"
        );
    }

    /// **What the tunnel queues can hold, pinned so the figure moves visibly** (#300).
    ///
    /// This is a RATCHET, not a pass: the number it records eats the entire share, and recording it is the
    /// point. `PROXY_SHARE` covers an association's receive buffer and a connection's relay buffers; it
    /// does not cover the queues, and the register that is supposed to sum every byte had no name for them
    /// until this test gave them one.
    ///
    /// The remedy is decided and not yet built (#300): debit the pool with the datagram's **actual** bytes
    /// at enqueue — the channel item becomes `(Vec<u8>, SemaphorePermit)` — so the bound is exact instead
    /// of worst-case and `MAX_UDP_FLOWS` goes back to being a map cap. Reserving the ceiling is not an
    /// option and the arithmetic here is why: the share buys ONE tunnel at this depth.
    ///
    /// **RAII rather than a counter, and the reason is drop.** A shared `AtomicUsize` incremented on send
    /// and decremented on receive is smaller and wrong: a tunnel dropped with items still queued never
    /// decrements, so the counter leaks by exactly the traffic that was in flight when a client went away —
    /// which is every client. A permit travelling with the datagram returns itself.
    #[test]
    fn the_tunnel_queues_are_larger_than_the_share_and_that_is_the_finding() {
        let per_tunnel = tunnel_queue_ceiling(1, MAX_UDP);
        let per_association = tunnel_queue_ceiling(crate::udp::MAX_UDP_FLOWS, MAX_UDP);
        println!(
            "one tunnel {per_tunnel} B ({} MiB); one association {per_association} B ({} GB);              the share is {PROXY_MEMORY_BUDGET} B",
            per_tunnel >> 20,
            per_association / 1_000_000_000
        );

        let permille = per_tunnel * 1000 / PROXY_MEMORY_BUDGET;
        assert_eq!(
            permille, 999,
            "one tunnel's queue is {permille}‰ of the whole share ({per_tunnel} B against \
             {PROXY_MEMORY_BUDGET} B). If #300's byte debit landed, delete this ratchet and assert the \
             debit instead; if a constant merely moved, say by how much and re-derive"
        );
        assert_eq!(
            PROXY_MEMORY_BUDGET - per_tunnel,
            128,
            "the share misses covering one tunnel's queue by 128 B — 2 × 64 × 65535 against \
             2 × 64 × 65536 — so \"the share buys ONE tunnel\" is exact arithmetic and not a rounded \
             phrase. The two numbers have unrelated provenance: nobody chose the depth to make this come \
             out even, which is why the near-identity is worth pinning rather than tidying away"
        );
        assert_eq!(
            per_association, 8_589_803_520,
            "the per-association queue ceiling moved. It is MAX_UDP_FLOWS × 2 × UDP_TUNNEL_BUFFER × \
             MAX_UDP, and every factor is a decision someone took — re-derive rather than re-pin (#300)"
        );
    }

    /// **The property the pool exists for: the two kinds cannot spend the share twice.**
    ///
    /// Two independently derived counts would each admit its own maximum, so a client holding every
    /// association *and* every connection would take `128 × 64 KiB + 4096 × 2 KiB` — twice the share. The
    /// pool is what makes that unreachable, and this asserts it by exhausting one kind and demanding the
    /// other be refused.
    #[tokio::test]
    async fn associations_and_connections_cannot_both_reach_their_ceiling() {
        let _serial = POOL.lock().await;
        // Control FIRST: on an untouched pool a connection is admitted, or the refusal below proves nothing.
        let probe = try_reserve(CONNECTION_COST);
        assert!(probe.is_some(), "an idle pool must admit a connection, or this test cannot fail");
        drop(probe);

        let mut held = Vec::new();
        for _ in 0..MAX_ASSOCIATIONS {
            held.push(try_reserve(ASSOCIATION_COST).expect("the share buys this many associations"));
        }
        assert!(
            try_reserve(ASSOCIATION_COST).is_none(),
            "the {MAX_ASSOCIATIONS}th association must exhaust the pool"
        );
        assert!(
            try_reserve(CONNECTION_COST).is_none(),
            "with the share spent on associations there is nothing left for a connection — two separate \
             counts would have admitted {MAX_CONNECTIONS} of them on top"
        );

        // And the pool recovers: a permit returns its bytes on drop, so capacity is a level and not a tally.
        drop(held.pop());
        assert!(try_reserve(CONNECTION_COST).is_some(), "freeing an association must free its bytes");
        drop(held);
    }
}
