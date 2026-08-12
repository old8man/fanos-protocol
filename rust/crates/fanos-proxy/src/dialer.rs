//! The [`Dialer`] seam — how a target is actually reached.
//!
//! The proxy is generic over a `Dialer`, so the reachability policy (resolve a `.fanos` service
//! over the overlay, refuse the clear net until an exit exists) is entirely pluggable and testable
//! in isolation. The in-process loopback fixtures live behind the `testing` feature (#194), so a shipped
//! build has no dialer that answers a client with the client's own bytes.

use std::future::Future;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::target::Target;

/// Why a dial failed — mapped to the corresponding SOCKS5 reply code.
#[derive(Debug)]
pub enum DialError {
    /// The connection is not allowed by policy (e.g. clear net with no exit configured).
    Refused,
    /// The target could not be reached (service not found / unreachable).
    Unreachable,
    /// This kind of target is not supported (e.g. an address type the dialer won't handle).
    Unsupported(String),
    /// An underlying I/O error.
    Io(std::io::Error),
}

impl DialError {
    /// The SOCKS5 reply code for this failure (RFC 1928 §6).
    #[must_use]
    pub fn socks5_reply_code(&self) -> u8 {
        match self {
            Self::Refused => 0x02,        // connection not allowed by ruleset
            Self::Unreachable => 0x04,    // host unreachable
            Self::Unsupported(_) => 0x08, // address type not supported
            Self::Io(_) => 0x01,          // general SOCKS server failure
        }
    }
}

impl core::fmt::Display for DialError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Refused => f.write_str("connection refused by policy"),
            Self::Unreachable => f.write_str("target unreachable"),
            Self::Unsupported(what) => write!(f, "unsupported target: {what}"),
            Self::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for DialError {}

impl From<std::io::Error> for DialError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Establishes a byte stream to a SOCKS5 [`Target`]. Implementors decide reachability policy.
pub trait Dialer {
    /// The duplex byte stream returned on a successful dial.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Attempt to reach `target`, returning a connected duplex stream.
    fn dial(&self, target: &Target)
    -> impl Future<Output = Result<Self::Stream, DialError>> + Send;
}

/// A bidirectional datagram channel to one fixed destination — the UDP analogue of a dialed byte stream.
///
/// A [`UdpDialer`] owns the underlying transport and its pump tasks; the proxy simply pushes outbound
/// datagrams onto [`outbound`](Self::outbound) and pulls inbound ones from [`inbound`](Self::inbound).
/// Dropping either end tears the tunnel down. A single SOCKS5 UDP association multiplexes many of these —
/// one per distinct destination the client addresses (so DNS to `resolver:53` and QUIC to a web host each
/// get their own tunnel).
pub struct UdpTunnel {
    /// Datagrams to transmit toward the destination (the payloads, unframed).
    pub outbound: ChargedSender,
    /// Datagrams the destination sent back; yields `None` once the tunnel closes.
    pub inbound: mpsc::Receiver<Datagram>,
}

/// A datagram sitting in a tunnel queue, carrying the pool permit that paid for its bytes (#300).
///
/// **RAII rather than a counter, and the reason is drop.** A shared `AtomicUsize` bumped on send and cut
/// on receive is smaller and wrong: a tunnel dropped with items still queued never decrements, so the
/// counter leaks by exactly the traffic in flight when a client went away — which is every client. A
/// permit travelling with the bytes returns itself, whichever way the datagram leaves.
///
/// Derefs to its bytes, so a consumer writes `&datagram` exactly as it did when this was a `Vec<u8>`.
pub struct Datagram {
    bytes: Vec<u8>,
    _permit: tokio::sync::SemaphorePermit<'static>,
}

impl std::ops::Deref for Datagram {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// Prints the LENGTH and not the bytes. A queued datagram is relayed user traffic, so a `Debug` that
/// rendered its contents would put a client's payload into any log line that formatted a tunnel — the
/// cheapest possible way to undo the thing this crate exists to provide.
#[expect(clippy::missing_fields_in_debug, reason = "the omitted field IS the point: see the doc above")]
impl std::fmt::Debug for Datagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Datagram").field("len", &self.bytes.len()).finish()
    }
}

/// Compares the bytes; the permit is bookkeeping, not identity.
impl PartialEq for Datagram {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Datagram {}

impl PartialEq<[u8]> for Datagram {
    fn eq(&self, other: &[u8]) -> bool {
        self.bytes == other
    }
}

impl PartialEq<Vec<u8>> for Datagram {
    fn eq(&self, other: &Vec<u8>) -> bool {
        &self.bytes == other
    }
}

impl PartialEq<&[u8]> for Datagram {
    fn eq(&self, other: &&[u8]) -> bool {
        self.bytes == *other
    }
}

impl Datagram {
    /// Take the bytes, releasing the permit.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Why a datagram did not make it into a tunnel queue. Every arm is a drop — UDP's own failure model —
/// but they are different events and an operator reading a count of them wants them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The pool had no bytes left: the node's total tunnel backlog is at its share.
    NoBudget,
    /// This tunnel's own queue is full, though the pool had room: one destination is not draining.
    Full,
    /// The far end of the tunnel is gone.
    Closed,
}

/// The send half of one tunnel direction: **charges the pool before it queues**, so the bound is on bytes
/// actually held rather than on a product of ceilings nobody can afford (#300).
#[derive(Clone)]
pub struct ChargedSender {
    tx: mpsc::Sender<Datagram>,
}

impl ChargedSender {
    /// Queue `bytes`, dropping rather than waiting — the right answer where the producer is a socket and
    /// UDP's lossiness already is the contract.
    pub fn try_send(&self, bytes: Vec<u8>) -> Result<(), Refused> {
        let Some(permit) = crate::budget::charge_tunnel(bytes.len()) else {
            return Err(Refused::NoBudget);
        };
        self.tx.try_send(Datagram { bytes, _permit: permit }).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => Refused::Full,
            mpsc::error::TrySendError::Closed(_) => Refused::Closed,
        })
    }

    /// Queue `bytes`, waiting for pool room and queue room — the right answer where the producer is a
    /// byte-stream that can be back-pressured instead of dropped.
    pub async fn send(&self, bytes: Vec<u8>) -> Result<(), Refused> {
        let Some(permit) = crate::budget::charge_tunnel_waiting(bytes.len()).await else {
            return Err(Refused::NoBudget);
        };
        self.tx.send(Datagram { bytes, _permit: permit }).await.map_err(|_| Refused::Closed)
    }

    /// Move an already-charged datagram to another queue: the permit rides along, so nothing is charged
    /// twice and nothing is released early.
    pub async fn forward(&self, datagram: Datagram) -> Result<(), Refused> {
        self.tx.send(datagram).await.map_err(|_| Refused::Closed)
    }

    /// Whether the receiving half is gone.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

impl UdpTunnel {
    /// Build a tunnel together with the transport-side channel ends a [`UdpDialer`] pumps: returns
    /// `(tunnel, inbound_tx, outbound_rx)`. The dialer pushes datagrams it receives from the destination
    /// into `inbound_tx`, and reads datagrams to transmit from `outbound_rx`; the proxy holds `tunnel`.
    /// `buffer` bounds each direction's in-flight backlog (UDP is lossy: a full channel drops, never
    /// blocks the association).
    #[must_use]
    pub fn pair(buffer: usize) -> (Self, ChargedSender, mpsc::Receiver<Datagram>) {
        let (outbound, outbound_rx) = mpsc::channel(buffer);
        let (inbound_tx, inbound) = mpsc::channel(buffer);
        (
            Self { outbound: ChargedSender { tx: outbound }, inbound },
            ChargedSender { tx: inbound_tx },
            outbound_rx,
        )
    }
}

/// Establishes a [`UdpTunnel`] to a UDP [`Target`] — the datagram analogue of [`Dialer`]. Implementors
/// decide reachability policy (e.g. relay only through a configured clearnet exit; refuse `.fanos`, which
/// names byte-stream services). A dialer that cannot serve a target returns [`DialError`], and the SOCKS5
/// UDP relay silently drops datagrams to it (UDP's own failure model).
pub trait UdpDialer {
    /// Open a datagram tunnel to `target`.
    fn dial_udp(&self, target: &Target)
    -> impl Future<Output = Result<UdpTunnel, DialError>> + Send;
}

/// A loopback dialer whose stream echoes everything written to it — the SOCKS5 test fixture.
#[derive(Clone, Copy, Default, Debug)]
#[cfg(any(test, feature = "testing"))]
pub struct EchoDialer;

#[cfg(any(test, feature = "testing"))]
impl Dialer for EchoDialer {
    type Stream = tokio::io::DuplexStream;

    fn dial(
        &self,
        _target: &Target,
    ) -> impl Future<Output = Result<Self::Stream, DialError>> + Send {
        let (client_side, server_side) = tokio::io::duplex(8192);
        // Echo: copy the server side's reads back to its writes (what the client reads).
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(server_side);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        std::future::ready(Ok(client_side))
    }
}

#[cfg(any(test, feature = "testing"))]
impl UdpDialer for EchoDialer {
    fn dial_udp(
        &self,
        _target: &Target,
    ) -> impl Future<Output = Result<UdpTunnel, DialError>> + Send {
        let (tunnel, inbound_tx, mut outbound_rx) = UdpTunnel::pair(crate::budget::UDP_TUNNEL_BUFFER);
        // Echo: every datagram sent toward the "destination" comes straight back.
        tokio::spawn(async move {
            while let Some(datagram) = outbound_rx.recv().await {
                // The permit rides along: an echo re-queues the same bytes, it does not buy them twice.
                if inbound_tx.forward(datagram).await.is_err() {
                    break;
                }
            }
        });
        std::future::ready(Ok(tunnel))
    }
}

/// A dialer that refuses every target — a safe default before any transport is wired.
#[derive(Clone, Copy, Default, Debug)]
#[cfg(any(test, feature = "testing"))]
pub struct RefuseDialer;

#[cfg(any(test, feature = "testing"))]
impl Dialer for RefuseDialer {
    type Stream = tokio::io::DuplexStream;

    fn dial(
        &self,
        _target: &Target,
    ) -> impl Future<Output = Result<Self::Stream, DialError>> + Send {
        std::future::ready(Err(DialError::Refused))
    }
}

#[cfg(any(test, feature = "testing"))]
impl UdpDialer for RefuseDialer {
    fn dial_udp(
        &self,
        _target: &Target,
    ) -> impl Future<Output = Result<UdpTunnel, DialError>> + Send {
        std::future::ready(Err(DialError::Refused))
    }
}
