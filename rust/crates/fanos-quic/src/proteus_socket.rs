//! The PROTEUS envelope **under** QUIC — an [`AsyncUdpSocket`] decorator (spec §13.3, §13.5).
//!
//! Every datagram this node sends is sealed with
//! [`fanos_proteus::datagram`](fanos_proteus::datagram); every datagram it receives must open, or it is
//! dropped before quinn ever parses it. The handshake travels inside the envelope like everything else, so
//! there is no plaintext ALPN, SNI or version list on the wire and an unauthenticated prober gets silence
//! instead of a Version Negotiation packet.
//!
//! ## Why a decorator, and not a change inside the driver
//!
//! The seam already existed for the simulator: [`Fabric::Abstract`](crate::Fabric) hands quinn any
//! `AsyncUdpSocket`. Putting the envelope there means the *same* code path carries it in production, in the
//! simulator and in the tests — the simulator-fidelity rule (differ in the transport, and only there) is
//! kept rather than spent.
//!
//! ## The envelope is configuration, not a dial — and that is derived, not preference
//!
//! A morph rotation (§13.7 auto-fallback) is explicitly a **local** decision: every codec-using morph
//! shares one wire codec, so a node walks the chain without renegotiating. Sealing is not like that. It is
//! a property both ends must agree on before the first packet, so it cannot be flipped by a local breaker
//! mid-flight without cutting every live connection. It is therefore decided **once**, at socket
//! construction, from the configured morph, and a later rotation does not move it.
//!
//! [`Morph::Plain`] is the one morph that does not seal: it exists to be indistinguishable from ordinary
//! QUIC on an uncensored network at zero overhead, and an envelope would be exactly the overhead it
//! declines.
//!
//! ## Batching
//!
//! GSO/GRO are off ([`max_transmit_segments`] and [`max_receive_segments`] pinned to 1). A segmented
//! `Transmit` is *N* datagrams in one buffer that the kernel splits on a fixed stride; sealing changes each
//! one's length, so the stride no longer describes them. Stated here rather than left to the trait default,
//! because the default silently being 1 is not the same as the value being load-bearing.
//!
//! [`max_transmit_segments`]: AsyncUdpSocket::max_transmit_segments
//! [`max_receive_segments`]: AsyncUdpSocket::max_receive_segments

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::{Context, Poll};
use std::time::Instant;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use fanos_runtime::ports::stations::{Station, Stations};
use fanos_proteus::obfuscate::NONCE_LEN;
use fanos_primitives::collections::BoundedMap;
use fanos_proteus::shaper::OpenedUnder;
use fanos_proteus::{Morph, ProteusShaper};

use crate::driver::{DIAL_TIMEOUT, MAX_INBOUND_CONNECTIONS};

/// A socket that seals every outbound datagram and opens every inbound one, dropping what does not open.
pub(crate) struct ProteusSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    /// The same shaper the frame layer uses, so the datagram envelope rotates on the same epoch turn and
    /// accepts the same grace window — one shape authority, not two that can disagree at a boundary.
    shaper: Arc<RwLock<ProteusShaper>>,
    /// The driver's station plane. A drop here is *invisible by design* — no reply, no error, nothing
    /// downstream — so if it is not counted at this exact spot, a node under active probing reads as idle on
    /// every surface it has. This is the outermost gate; there is no later one to catch it.
    stations: Arc<Mutex<Stations>>,
    /// Addresses whose last datagram opened under the **genesis** shape, with when it did (#234).
    ///
    /// A joining node cannot know the cell's live epoch — nothing in `BeaconParams` carries a time or an
    /// epoch number, and `BeaconWindow::genesis` starts at zero — so it necessarily speaks epoch 0 while the
    /// cell is at `N`. Past `N = 2` that is outside the cell's `{N−1, N, N+1}` window in both directions and
    /// the handshake cannot start. The shaper answers half of it by accepting the genesis shape as a fourth
    /// candidate; this map answers the other half, because a reply sealed at `N` is one the joiner's own
    /// window `{0, 0, 1}` cannot open. **The reply goes out in the shape the request arrived in.**
    ///
    /// Both bounds are read off constants that already exist rather than chosen here. Capacity is
    /// [`MAX_INBOUND_CONNECTIONS`]: an entry past it is a handshake this node would refuse anyway. An entry
    /// expires after [`DIAL_TIMEOUT`], the window a handshake is given — past it the exchange has either
    /// completed or failed, and in both cases the peer now knows the live epoch and speaks it.
    ///
    /// The eviction hazard this class usually carries does not apply, and the reason is worth stating: an
    /// entry is only created by a datagram that **opened** under the genesis shape, which takes the community
    /// secret. A stranger cannot flood the map to evict a real joiner, because a stranger's datagram never
    /// opens at all.
    genesis_speakers: GenesisSpeakers,
}

/// The joining-peer map, shared between the datagram envelope that *learns* it and the frame layer that
/// must *act* on it (#234).
///
/// Shared rather than socket-private, and the reason is an ordering the code makes plain: both sides call
/// `send_hello` **before** they read one, so by the time the frame layer sees a genesis-shaped HELLO its own
/// HELLO is already on the wire in the live shape — unreadable to the joiner, and the exchange dies there.
/// The envelope, one layer down, knew the peer was mid-join before the driver wrote a byte. This handle is
/// how that answer reaches the layer that needs it in time.
pub(crate) type GenesisSpeakers = Arc<Mutex<BoundedMap<SocketAddr, Instant>>>;

/// A fresh map, sized and expiring as [`ProteusSocket::genesis_speakers`] documents.
pub(crate) fn genesis_speakers() -> GenesisSpeakers {
    Arc::new(Mutex::new(BoundedMap::new(MAX_INBOUND_CONNECTIONS)))
}

/// Whether the next frame or datagram to `dst` must go out under the genesis shape.
///
/// Free rather than a method, because the socket and the driver ask it of the same handle.
pub(crate) fn speaks_genesis(map: &GenesisSpeakers, dst: SocketAddr) -> bool {
    let map = map.lock().unwrap_or_else(PoisonError::into_inner);
    map.get(&dst).is_some_and(|at| at.elapsed() < DIAL_TIMEOUT)
}

impl ProteusSocket {
    /// Wrap `inner` iff `shaper`'s morph seals. Returns the bare socket for [`Morph::Plain`], so the
    /// zero-overhead open-network path stays byte-for-byte native QUIC.
    ///
    /// Reading the morph here — once — is what makes the envelope configuration rather than a dial; see
    /// this module's header.
    pub(crate) fn wrap(
        inner: Arc<dyn AsyncUdpSocket>,
        shaper: &Arc<RwLock<ProteusShaper>>,
        stations: &Arc<Mutex<Stations>>,
        speakers: &GenesisSpeakers,
    ) -> Arc<dyn AsyncUdpSocket> {
        let seals = shaper
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .morph()
            != Morph::Plain;
        if !seals {
            return inner;
        }
        Arc::new(Self {
            genesis_speakers: Arc::clone(speakers),
            inner,
            shaper: Arc::clone(shaper),
            stations: Arc::clone(stations),
        })
    }

    /// A fresh per-datagram nonce from the OS CSPRNG.
    ///
    /// **Not a counter, and the reason is that two peers share `θ`.** Both ends of a community derive the
    /// same epoch shape, so two nodes whose counters both start at zero would produce the same keystream
    /// for their first datagram — and a QUIC Initial is *structured*, so the XOR of two of them leaks the
    /// header. Drawing at random makes a repeat a birthday event over 2⁶⁴, re-based every epoch.
    fn nonce() -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        // A failure here would mean the OS entropy source is gone. Falling back to a counter would silently
        // reintroduce exactly the collision above, so the datagram is dropped instead: loud, and recovered
        // by QUIC's own retransmission if entropy returns.
        if getrandom::fill(&mut n).is_err() {
            return [0u8; NONCE_LEN];
        }
        n
    }
}

/// Hand-written rather than derived, for one reason: `genesis_speakers` is keyed by peer address, and a
/// derived `Debug` would print the address of every node currently mid-join into whatever log the socket is
/// formatted into. The count answers the operational question ("is anyone joining?") without naming who.
impl std::fmt::Debug for ProteusSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let joining = self.genesis_speakers.lock().unwrap_or_else(PoisonError::into_inner).len();
        f.debug_struct("ProteusSocket").field("joining", &joining).finish_non_exhaustive()
    }
}

impl ProteusSocket {
    /// Whether the next datagram to `dst` must be sealed under the genesis shape.
    ///
    /// Expiry is read here rather than swept on a timer: the answer is only ever needed at send time, so a
    /// stale row costs nothing until it is asked about, and asking is where it is cheapest to discard.
    /// Remember that these addresses reached us under the genesis shape, and drop rows past their window.
    fn note_genesis_speakers(&self, addrs: &[SocketAddr]) {
        let now = Instant::now();
        let mut map = self.genesis_speakers.lock().unwrap_or_else(PoisonError::into_inner);
        map.retain(|_, at: &Instant| now.duration_since(*at) < DIAL_TIMEOUT);
        for addr in addrs {
            map.insert(*addr, now);
        }
    }
}

impl AsyncUdpSocket for ProteusSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let nonce = Self::nonce();
        if nonce == [0u8; NONCE_LEN] {
            return Err(io::Error::other("no OS entropy for a PROTEUS datagram nonce"));
        }
        // Answer in the shape the question arrived in. A peer that reached us under the genesis shape is
        // mid-join and holds the window `{0, 0, 1}`; sealing the reply at the live epoch would leave it
        // unreadable and the handshake would fail from the other side — the asymmetry #235 measured.
        let shaper = self.shaper.read().unwrap_or_else(PoisonError::into_inner);
        let sealed = if speaks_genesis(&self.genesis_speakers, transmit.destination) {
            shaper.seal_datagram_at_genesis(transmit.contents, &nonce)
        } else {
            shaper.seal_datagram(transmit.contents, &nonce)
        };
        drop(shaper);
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &sealed,
            // Pinned to `None` by `max_transmit_segments` above; restated so a future quinn that stops
            // asking cannot turn this into a silent stride mismatch.
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let n = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
            let shaper = self.shaper.read().unwrap_or_else(PoisonError::into_inner);

            // Compact in place: datagram `i` that opens moves to slot `kept`. A stranger's datagram is
            // simply not carried forward — no reply, no error, no trace on the wire, which is §13.5.
            let mut kept = 0usize;
            let mut refused = 0u64;
            let mut joining: Vec<SocketAddr> = Vec::new();
            for i in 0..n {
                let (Some(buf), Some(m)) = (bufs.get_mut(i), meta.get(i).copied()) else {
                    continue;
                };
                let Some((len, under)) = shaper.open_datagram(buf.get_mut(..m.len).unwrap_or(&mut [])) else {
                    refused += 1;
                    continue;
                };
                if under == OpenedUnder::Genesis {
                    joining.push(m.addr);
                }
                if kept != i {
                    let (left, right) = bufs.split_at_mut(i);
                    let (Some(dst), Some(src)) = (left.get_mut(kept), right.first()) else {
                        continue;
                    };
                    let Some(dst) = dst.get_mut(..len) else { continue };
                    let Some(src) = src.get(..len) else { continue };
                    dst.copy_from_slice(src);
                }
                if let Some(slot) = meta.get_mut(kept) {
                    *slot = RecvMeta { len, stride: len, ..m };
                }
                kept += 1;
            }
            if refused > 0 {
                self.stations
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .record_n(Station::WireForeignDatagram, None, refused);
            }
            if !joining.is_empty() {
                // Counted before the map is written, so the number is "genesis datagrams that arrived",
                // not "distinct peers currently mid-join" — a repeat from one address is a retry an
                // operator wants to see, and the map would swallow it.
                self.stations.lock().unwrap_or_else(PoisonError::into_inner).record_n(
                    Station::WireGenesisShaped,
                    None,
                    joining.len() as u64,
                );
                self.note_genesis_speakers(&joining);
            }
            // Every datagram in this batch was a stranger's. Returning `Ok(0)` would tell quinn a readiness
            // event produced nothing and risks a spin; go back to the socket instead, which either yields
            // more datagrams or registers the waker and parks.
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// See the module header: sealing changes each datagram's length, so a segmented `Transmit`'s fixed
    /// stride would no longer describe the wire.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    /// The receive side of the same argument: a GRO batch arrives as one buffer with a fixed stride, and
    /// the sealed datagrams in it do not share one.
    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
